"""The two LSM trees that place volume bytes: ``data_map`` and ``segment_map``.

- ``data_map`` (TLV[1], 31-byte key / 10-byte value) maps ``(volume_id, source byte
  offset)`` to a segment id for every stored extent.
- ``segment_map`` (TLV[2], 8-byte key / 32-byte value) maps a segment id to the page
  where the segment's header lives.

The data_map's lexicographic key order equals ``(volume_id, source_offset)`` order, so
sorted extents are binary-searchable. Overlapping extents (incremental/differential
backups, dedup) are resolved downstream by :mod:`dissect.archive.tibx.tibx`.

Ported from ``acronis-tib-reader`` (MIT License, Copyright (c) 2026 the tibread
contributors, https://github.com/TreadingTheTiber/acronis-tib-reader), with the mem-tree
merge from ``acronis-tibx`` (MIT License, Copyright (c) 2026 mniedermaier).
"""

from __future__ import annotations

import struct
from array import array
from bisect import bisect_left, bisect_right
from collections.abc import Mapping, Sequence
from itertools import compress, islice, repeat
from operator import eq, itemgetter, le, lshift, lt, or_
from typing import TYPE_CHECKING, NamedTuple, overload

from dissect.archive.tibx.c_tibx import (
    LSM_CELL_GROUP_HEADER_SIZE,
    LSM_CELL_GROUP_MAX,
    SEGMENT_MAP_VALUE_SIZE,
    TLV_DATA_MAP,
    TLV_SEGMENT_MAP,
)
from dissect.archive.tibx.exception import CorruptArchiveError
from dissect.archive.tibx.lsm import iter_memtree_cells, iter_tree_leaf_streams

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from dissect.archive.tibx.lsm import ArchiveHeader, LsmSuperBlock
    from dissect.archive.tibx.page import PageStore

# RECORD PARSING -- data_map and segment_map records are the one place that does not go
# through c_tibx, deliberately. An archive of a few hundred GB holds about a million of each,
# and c_tibx costs ~10.7 us per record against ~0.6 us for these precompiled structs. Worse,
# cstruct returns its own int subclasses (60 bytes each, tracked by the cyclic GC): seven of
# them per extent made a 720k-extent index take ~775 MiB and every full GC a ~0.8 s pause.
#
# The layouts mirror c_tibx.data_map_key/_value and segment_map_key/_value (a test keeps
# them in step). The 24-bit extent_length is split into its high byte and low 16 bits, and
# the segment_map page_count, the record's one little-endian field, is left as bytes.
_DATA_MAP_KEY = struct.Struct(">QQBHIQ")
_DATA_MAP_RECORD = struct.Struct(">QQBHIQQH")
# Array typecodes for the fields of _DATA_MAP_RECORD, and for those of Extent
_DATA_MAP_TYPECODES = "QQBHIQQH"
_EXTENT_TYPECODES = "QQQIQQH"
_SEGMENT_MAP_KEY = struct.Struct(">Q")
_SEGMENT_MAP_RECORD = struct.Struct(">Q4sI24x")
# The same record with the page_count as a big-endian int, to unpack in bulk and byteswap after
_SEGMENT_MAP_COLUMNS = struct.Struct(">QII24x")

# A record as decoded from a compact cell stream: the key and value fields of a live record,
# the key fields alone of a tombstone
Record = tuple[bool, tuple]


class Extent(NamedTuple):
    """One data_map record: where ``extent_length`` bytes of a volume are stored."""

    volume_id: int
    source_offset: int
    extent_length: int
    slice_id: int
    extent_id: int
    segment_id: int
    extent_index: int

    @property
    def end_offset(self) -> int:
        """Exclusive end offset of this extent within its volume."""
        return self.source_offset + self.extent_length


class ExtentTable(Sequence[Extent]):
    """Extents as columns: an array for each field of :class:`Extent`, a row per extent.

    Loaded from the data_map, the rows are in ``(volume_id, source_offset)`` order. A real
    archive holds a million extents and more. As :class:`Extent` tuples they took some 250
    bytes each, and the cyclic GC went through all of them in every full collection: up to
    a third of the time to load the index. These arrays hold the same in under 50 bytes an
    extent, as seven objects for the GC however many extents there are; an :class:`Extent`
    is only built for whoever asks for one.
    """

    __slots__ = (
        "extent_ids",
        "extent_indexes",
        "extent_lengths",
        "segment_ids",
        "slice_ids",
        "source_offsets",
        "volume_ids",
    )

    def __init__(self, columns: Sequence[array] | None = None):
        if columns is None:
            columns = [array(typecode) for typecode in _EXTENT_TYPECODES]
        (
            self.volume_ids,
            self.source_offsets,
            self.extent_lengths,
            self.slice_ids,
            self.extent_ids,
            self.segment_ids,
            self.extent_indexes,
        ) = columns

    @classmethod
    def from_extents(cls, extents: Iterable[Extent]) -> ExtentTable:
        """A table of ``extents`` in ``(volume_id, source_offset)`` order, as the data_map holds them."""
        table = cls()
        for extent in sorted(extents, key=lambda extent: (extent.volume_id, extent.source_offset)):
            for column, value in zip(table.columns, extent, strict=True):
                column.append(value)
        return table

    @property
    def columns(self) -> tuple[array, ...]:
        """The arrays, in the order of the fields of :class:`Extent`."""
        return (
            self.volume_ids,
            self.source_offsets,
            self.extent_lengths,
            self.slice_ids,
            self.extent_ids,
            self.segment_ids,
            self.extent_indexes,
        )

    def __len__(self) -> int:
        return len(self.volume_ids)

    @overload
    def __getitem__(self, index: int) -> Extent: ...

    @overload
    def __getitem__(self, index: slice) -> ExtentTable: ...

    def __getitem__(self, index: int | slice) -> Extent | ExtentTable:
        if isinstance(index, slice):
            return ExtentTable([column[index] for column in self.columns])
        return Extent(*(column[index] for column in self.columns))

    def __iter__(self) -> Iterator[Extent]:
        return map(Extent, *self.columns)

    def select(self, keep: Iterable[bool]) -> ExtentTable:
        """The rows for which ``keep`` is true, in their order."""
        keep = list(keep)
        return ExtentTable([array(column.typecode, compress(column, keep)) for column in self.columns])

    def volume_ranges(self) -> Iterator[tuple[int, int, int]]:
        """``(volume_id, start, stop)`` for each volume: rows ``start`` up to ``stop`` hold its extents."""
        volume_ids = self.volume_ids
        start = 0
        while start < len(volume_ids):
            volume_id = volume_ids[start]
            stop = bisect_right(volume_ids, volume_id, start)
            yield volume_id, start, stop
            start = stop


class SegmentLocator(NamedTuple):
    """Where one segment lives in the archive (from its segment_map value)."""

    segment_id: int
    page_count: int
    page_offset: int


def decode_extent(raw_key: bytes, raw_value: bytes) -> Extent:
    """Decode one raw data_map (key, value) record."""
    return _extent(_DATA_MAP_RECORD.unpack(raw_key + raw_value))


def _extent(fields: tuple) -> Extent:
    volume_id, source_offset, length_high, length_low, slice_id, extent_id, segment_id, extent_index = fields
    return Extent(
        volume_id, source_offset, length_high << 16 | length_low, slice_id, extent_id, segment_id, extent_index
    )


def decode_segment_locator(raw_key: bytes, raw_value: bytes) -> SegmentLocator:
    """Decode one raw segment_map (key, value) record."""
    segment_id, page_count, page_offset = _SEGMENT_MAP_RECORD.unpack(raw_key + raw_value[:SEGMENT_MAP_VALUE_SIZE])
    return SegmentLocator(segment_id, int.from_bytes(page_count, "little"), page_offset)


def _iter_compact_groups(raw: bytes, count: int, key: struct.Struct, record: struct.Struct) -> Iterator[bytes | Record]:
    """Decode a compact cell stream of fixed-size records, a group of cells at a time.

    The same layout :func:`dissect.archive.tibx.lsm.decode_cells_compact` decodes. A group
    whose cells are all alive -- nearly all of them -- comes out as the bytes of its
    records, for the caller to unpack in bulk; the cells of any other group as Records.
    """
    pos = 0
    decoded = 0
    try:
        while decoded < count:
            # c_tibx.lsm_cell_group_header, indexed directly: there is one per 24 records
            group = raw[pos]
            alive = int.from_bytes(raw[pos + 1 : pos + LSM_CELL_GROUP_HEADER_SIZE], "big")
            if group == 0 or group > LSM_CELL_GROUP_MAX or pos + LSM_CELL_GROUP_HEADER_SIZE > len(raw):
                raise CorruptArchiveError(f"compact cells: bad group header at {pos}")
            pos += LSM_CELL_GROUP_HEADER_SIZE
            group = min(group, count - decoded)
            mask = (1 << group) - 1
            if alive & mask == mask:
                end = pos + group * record.size
                if end > len(raw):
                    raise CorruptArchiveError(f"compact cells: short group at {pos}")
                yield raw[pos:end]
                pos = end
            else:
                for index in range(group):
                    if alive >> index & 1:
                        yield True, record.unpack_from(raw, pos)
                        pos += record.size
                    else:
                        yield False, key.unpack_from(raw, pos)
                        pos += key.size
            decoded += group
    except (IndexError, struct.error) as e:
        raise CorruptArchiveError(f"compact cells: truncated stream at {pos}") from e


def _run_items(
    store: PageStore, sb: LsmSuperBlock, key: struct.Struct, record: struct.Struct
) -> list[Iterable[bytes | Record]]:
    """The runs of a fixed-layout LSM tree, newest first: mem-tree, then ctrees.

    Each run comes as the items of :func:`_iter_compact_groups`: the bytes of a group of
    live records, or a Record.
    """
    if sb.key_length != key.size or sb.value_length != record.size - key.size:
        # Not the layout this tree is known by: there is nothing to decode it as
        return []

    runs: list[Iterable[bytes | Record]] = []
    memtree = [
        (cell.alive, record.unpack(cell.key + cell.value) if cell.alive else key.unpack(cell.key))
        for cell in iter_memtree_cells(sb)
        if len(cell.key) == key.size and (not cell.alive or len(cell.value) == record.size - key.size)
    ]
    if memtree:
        runs.append(memtree)
    runs.extend(_leaf_groups(leaves, key, record) for leaves in iter_tree_leaf_streams(store, sb))
    return runs


def _leaf_groups(
    leaves: Iterable[tuple[bytes, int]], key: struct.Struct, record: struct.Struct
) -> Iterator[bytes | Record]:
    for raw, count in leaves:
        yield from _iter_compact_groups(raw, count, key, record)


def _record_runs(
    store: PageStore, sb: LsmSuperBlock, key: struct.Struct, record: struct.Struct
) -> list[Iterable[Record]]:
    """The runs of a fixed-layout LSM tree as records, newest first: mem-tree, then ctrees."""
    return [_records(items, record) for items in _run_items(store, sb, key, record)]


def _records(items: Iterable[bytes | Record], record: struct.Struct) -> Iterator[Record]:
    for item in items:
        if type(item) is bytes:
            for fields in record.iter_unpack(item):
                yield True, fields
        else:
            yield item


def _decode_extent_run(items: Iterable[bytes | Record]) -> tuple[list[array], list[tuple]]:
    """One data_map run as the columns of an ExtentTable, in its key order, and the keys of its tombstones."""
    fields = [array(typecode) for typecode in _DATA_MAP_TYPECODES]
    deleted = []
    for item in items:
        if type(item) is bytes:
            for column, values in zip(fields, zip(*_DATA_MAP_RECORD.iter_unpack(item), strict=True), strict=True):
                column.extend(values)
        else:
            alive, values = item
            if alive:
                for column, value in zip(fields, values, strict=True):
                    column.append(value)
            else:
                volume_id, source_offset, length_high, length_low, slice_id, extent_id = values
                deleted.append((volume_id, source_offset, length_high << 16 | length_low, slice_id, extent_id))
    volume_ids, source_offsets, length_high, length_low, slice_ids, extent_ids, segment_ids, extent_indexes = fields
    extent_lengths = array("Q", map(or_, map(lshift, length_high, repeat(16)), length_low))
    return [volume_ids, source_offsets, extent_lengths, slice_ids, extent_ids, segment_ids, extent_indexes], deleted


def _keep_first(columns: list[array], bounds: list[int], deleted: list[list[tuple]]) -> list[array]:
    """Merge data_map runs with LSM keep-first semantics.

    ``columns`` holds the runs one after the other, newest first, run ``i`` ending at row
    ``bounds[i]`` with the tombstones ``deleted[i]``. The newest record for a key wins, and
    a tombstone keeps masking the older records of its key (seen in the wild after a
    "single version scheme" cleanup deletes a backup version). Keys are unique within a
    run, so only the keys of the runs before the last one need remembering.
    """
    merged = [array(typecode) for typecode in _EXTENT_TYPECODES]
    seen: set[tuple] = set()
    start = 0
    for number, (stop, run_deleted) in enumerate(zip(bounds, deleted, strict=True)):
        run = [column[start:stop] for column in columns]
        # The key of a record: everything up to the segment it points at
        identities = list(zip(*run[:5], strict=True))
        for identity, row in zip(identities, zip(*run, strict=True), strict=True):
            if identity not in seen:
                for column, value in zip(merged, row, strict=True):
                    column.append(value)
        if number < len(bounds) - 1:
            seen.update(identities)
            seen.update(run_deleted)
        start = stop
    return merged


def _offset_order(columns: list[array]) -> tuple[list[int] | None, list[int]]:
    """The rows of ``columns`` in ``(volume_id, source_offset)`` order, rows with equal ones in their current order.

    Returns ``(order, ties)``: ``order`` is ``None`` if the rows are in that order already,
    and ``ties`` lists the positions in the order whose row has the same volume and offset
    as the row before.
    """
    volume_ids, source_offsets = columns[0], columns[1]
    positions = list(map(or_, map(lshift, volume_ids, repeat(64)), source_offsets))
    if all(map(le, positions, islice(positions, 1, None))):
        order = None
    else:
        order = sorted(range(len(positions)), key=positions.__getitem__)
        positions = [positions[row] for row in order]
    ties = list(compress(range(1, len(positions)), map(eq, islice(positions, 1, None), positions)))
    return order, ties


def _shares_a_key(columns: list[array], order: list[int] | None, ties: list[int]) -> bool:
    """Whether two rows among ``ties`` (from :func:`_offset_order`) have the same data_map key."""
    keys: set[tuple] = set()
    previous = -2
    for position in ties:
        if position != previous + 1:
            # A new group of rows at one volume offset, starting at the row before
            keys = {tuple(column[order[position - 1] if order else position - 1] for column in columns[:5])}
        key = tuple(column[order[position] if order else position] for column in columns[:5])
        if key in keys:
            return True
        keys.add(key)
        previous = position
    return False


def _gather(columns: list[array], order: list[int]) -> None:
    """Put the rows of ``columns`` in ``order``, a column at a time to keep a single copy at hand."""
    take = itemgetter(*order) if len(order) > 1 else lambda column: [column[row] for row in order]
    for number, column in enumerate(columns):
        columns[number] = array(column.typecode, take(column))


def load_extents(store: PageStore, header: ArchiveHeader) -> ExtentTable:
    """Walk the data_map tree of ``header`` and return all extents.

    In ``(volume_id, source_offset)`` order. Tombstones and malformed records are skipped.
    Returns an empty table if the header has no data_map.

    The runs of the tree (the mem-tree, then the ctrees, newest first) are merged with LSM
    keep-first semantics. Real archives have one to four runs without a single key in more
    than one of them, nor a tombstone, so the runs are only put in order: then no record
    can shadow another.
    """
    sb = header.tree(TLV_DATA_MAP)
    if sb is None:
        return ExtentTable()
    # The runs one after the other, newest first, each run decoded and then let go of
    columns = [array(typecode) for typecode in _EXTENT_TYPECODES]
    bounds: list[int] = []
    deleted: list[list[tuple]] = []
    for items in _run_items(store, sb, _DATA_MAP_KEY, _DATA_MAP_RECORD):
        run_columns, run_deleted = _decode_extent_run(items)
        if len(run_columns[0]) or run_deleted:
            if bounds:
                for column, part in zip(columns, run_columns, strict=True):
                    column.extend(part)
            else:
                columns = run_columns
            bounds.append(len(columns[0]))
            deleted.append(run_deleted)
        del run_columns

    # The tombstones of the oldest run mask nothing
    if len(bounds) > 1 and any(deleted[:-1]):
        columns = _keep_first(columns, bounds, deleted)
    order, ties = _offset_order(columns)
    if len(bounds) > 1 and ties and _shares_a_key(columns, order, ties):
        columns = _keep_first(columns, bounds, deleted)
        order, _ = _offset_order(columns)
    if order is not None:
        _gather(columns, order)
    return ExtentTable(columns)


class SegmentIndex(Mapping[int, SegmentLocator]):
    """``{segment_id: SegmentLocator}`` for a whole segment_map, in about 16 bytes a segment.

    A dict of locators costs ~200 bytes a segment, and real archives hold a million
    segments. This keeps the runs of the tree apart, newest first, each as sorted parallel
    arrays, and looks a segment id up in one run after the other: the first run with a
    record for it decides, which is LSM keep-first. A locator is built on lookup.

    Merging the runs instead took up to a second on a large archive, for nothing: real
    archives have two to five runs whose segment ids overlap, newer runs holding rewritten
    locations of older segments, and a read looks up a few segments at most.
    """

    def __init__(self, runs: list[_SegmentRun]):
        self._runs = runs
        self._ids: array | None = None

    def _find(self, segment_id: object) -> tuple[_SegmentRun, int] | None:
        if not isinstance(segment_id, int):
            return None
        for run in self._runs:
            index = bisect_left(run.ids, segment_id)
            if index < len(run.ids) and run.ids[index] == segment_id:
                return run, index
            index = bisect_left(run.deleted, segment_id)
            if index < len(run.deleted) and run.deleted[index] == segment_id:
                # A tombstone: the segment is gone, whatever older runs say
                return None
        return None

    def __getitem__(self, segment_id: int) -> SegmentLocator:
        found = self._find(segment_id)
        if found is None:
            raise KeyError(segment_id)
        run, index = found
        return SegmentLocator(segment_id, run.page_counts[index], run.page_offsets[index])

    def __contains__(self, segment_id: object) -> bool:
        return self._find(segment_id) is not None

    def _live_ids(self) -> array:
        # Only iterating needs the runs merged, so they are merged when it does
        if self._ids is None:
            live: set[int] = set()
            decided: set[int] = set()
            for run in self._runs:
                live.update(set(run.ids).difference(decided))
                decided.update(run.ids)
                decided.update(run.deleted)
            self._ids = array("Q", sorted(live))
        return self._ids

    def __iter__(self) -> Iterator[int]:
        return iter(self._live_ids())

    def __len__(self) -> int:
        return len(self._live_ids())


class _SegmentRun(NamedTuple):
    """One run of the segment_map, decoded: its live records as arrays, its tombstones apart, in segment id order."""

    ids: array
    page_counts: array
    page_offsets: array
    deleted: array


def _decode_segment_run(items: Iterable[bytes | Record], record: struct.Struct) -> _SegmentRun:
    """One segment_map run from the items of :func:`_run_items`, unpacked with ``record``.

    ``record`` reads the page_count as a big-endian int, like :data:`_SEGMENT_MAP_COLUMNS`.
    """
    ids, page_counts, page_offsets, deleted = array("Q"), array("I"), array("I"), array("Q")
    for item in items:
        if type(item) is bytes:
            for column, values in zip(
                (ids, page_counts, page_offsets), zip(*record.iter_unpack(item), strict=True), strict=True
            ):
                column.extend(values)
        else:
            alive, fields = item
            if alive:
                ids.append(fields[0])
                page_counts.append(fields[1])
                page_offsets.append(fields[2])
            else:
                deleted.append(fields[0])
    # The page_count is the record's one little-endian field
    page_counts.byteswap()
    if not all(map(lt, ids, islice(ids, 1, None))):
        # Out of id order, as in a damaged tree: the lookups bisect
        order = sorted(range(len(ids)), key=ids.__getitem__)
        ids, page_counts, page_offsets = (
            array(column.typecode, map(column.__getitem__, order)) for column in (ids, page_counts, page_offsets)
        )
    return _SegmentRun(ids, page_counts, page_offsets, array("Q", sorted(deleted)))


def load_segment_index(store: PageStore, header: ArchiveHeader) -> SegmentIndex:
    """Walk the segment_map tree of ``header`` and index it by segment id.

    The runs of the tree (the mem-tree, then the ctrees, newest first) keep LSM keep-first
    semantics: the newest record for a segment id wins, and a tombstone masks it. See
    :class:`SegmentIndex`.
    """
    sb = header.tree(TLV_SEGMENT_MAP)
    runs: list[_SegmentRun] = []
    if sb is not None and sb.value_length >= SEGMENT_MAP_VALUE_SIZE:
        # Only the leading fields of the value are known; a longer value just pads further
        record = struct.Struct(f"{_SEGMENT_MAP_COLUMNS.format}{sb.value_length - SEGMENT_MAP_VALUE_SIZE}x")
        runs = [_decode_segment_run(items, record) for items in _run_items(store, sb, _SEGMENT_MAP_KEY, record)]
    return SegmentIndex([run for run in runs if run.ids or run.deleted])
