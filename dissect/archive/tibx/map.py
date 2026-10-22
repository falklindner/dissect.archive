"""The two LSM trees that place volume bytes: ``data_map`` and ``segment_map``.

- ``data_map`` (TLV[1], 31-byte key / 10-byte value) maps ``(volume_id, source byte
  offset)`` to a segment id for every stored extent.
- ``segment_map`` (TLV[2], 8-byte key / 32-byte value) maps a segment id to the page
  where the segment's header lives.

The data_map's lexicographic key order equals ``(volume_id, source_offset)`` order, so
sorted extents are binary-searchable. Overlapping extents (incremental/differential
backups, dedup) are resolved downstream by :mod:`dissect.archive.tibx.tibx`.

Ported from the MIT-licensed ``acronis-tib-reader``, with the mem-tree merge from
``acronis-tibx``. See ``THIRD_PARTY_NOTICES.md``.
"""

from __future__ import annotations

import struct
from array import array
from bisect import bisect_left
from collections.abc import Mapping
from itertools import pairwise
from typing import TYPE_CHECKING, NamedTuple

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
_DATA_MAP_KEY_FIELDS = 6
_DATA_MAP_RECORD = struct.Struct(">QQBHIQQH")
_SEGMENT_MAP_KEY = struct.Struct(">Q")
_SEGMENT_MAP_RECORD = struct.Struct(">Q4sI24x")

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


def _iter_compact_records(raw: bytes, count: int, key: struct.Struct, record: struct.Struct) -> Iterator[Record]:
    """Decode a compact cell stream of fixed-size records in bulk.

    The same layout :func:`dissect.archive.tibx.lsm.decode_cells_compact` decodes, but a
    group whose cells are all alive -- nearly all of them -- is unpacked in one call.
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
                for fields in record.iter_unpack(raw[pos:end]):
                    yield True, fields
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


def _record_runs(
    store: PageStore, sb: LsmSuperBlock, key: struct.Struct, record: struct.Struct
) -> list[Iterable[Record]]:
    """The runs of a fixed-layout LSM tree as records, newest first: mem-tree, then ctrees."""
    if sb.key_length != key.size or sb.value_length != record.size - key.size:
        # Not the layout this tree is known by: there is nothing to decode it as
        return []

    runs: list[Iterable[Record]] = []
    memtree = [
        (cell.alive, record.unpack(cell.key + cell.value) if cell.alive else key.unpack(cell.key))
        for cell in iter_memtree_cells(sb)
        if len(cell.key) == key.size and (not cell.alive or len(cell.value) == record.size - key.size)
    ]
    if memtree:
        runs.append(memtree)
    runs.extend(_leaf_records(leaves, key, record) for leaves in iter_tree_leaf_streams(store, sb))
    return runs


def _leaf_records(leaves: Iterable[tuple[bytes, int]], key: struct.Struct, record: struct.Struct) -> Iterator[Record]:
    for raw, count in leaves:
        yield from _iter_compact_records(raw, count, key, record)


def _keep_first(runs: list[Iterable[Record]], key_fields: int) -> Iterator[Record]:
    """Merge LSM runs (newest first) with keep-first semantics, tombstones included.

    Keys are unique within a run, so only the keys of the runs before the last one need
    remembering: an archive written by a single full backup has one run and no set at all,
    and otherwise the set holds the (small) newer runs rather than the big base.
    """
    seen: set[tuple] = set()
    for index, run in enumerate(runs):
        last = index == len(runs) - 1
        if last and not seen:
            yield from run
            return
        for alive, fields in run:
            identity = fields[:key_fields]
            if identity in seen:
                # LSM keep-first: the newest record for this key already decided its fate --
                # in particular a tombstone must keep masking an older alive record (seen in
                # the wild after a "single version scheme" cleanup deletes a backup version)
                continue
            if not last:
                seen.add(identity)
            yield alive, fields


def load_extents(store: PageStore, header: ArchiveHeader) -> list[Extent]:
    """Walk the data_map tree of ``header`` and return all extents.

    Sorted by ``(volume_id, source_offset)``. Tombstones and malformed records are
    skipped. Returns an empty list if the header has no data_map.
    """
    sb = header.tree(TLV_DATA_MAP)
    if sb is None:
        return []
    runs = _record_runs(store, sb, _DATA_MAP_KEY, _DATA_MAP_RECORD)
    extents = [_extent(fields) for alive, fields in _keep_first(runs, _DATA_MAP_KEY_FIELDS) if alive]
    # A single run comes out of the tree in key order, which this sort then only confirms
    extents.sort(key=lambda extent: (extent.volume_id, extent.source_offset))
    return extents


class SegmentIndex(Mapping[int, SegmentLocator]):
    """``{segment_id: SegmentLocator}`` for a whole segment_map, in about 24 bytes a segment.

    A dict of locators costs ~200 bytes a segment, and real archives hold a million
    segments. This keeps sorted parallel arrays instead and builds a locator on lookup.
    """

    def __init__(self, segment_ids: array, page_counts: array, page_offsets: array):
        self._ids = segment_ids
        self._counts = page_counts
        self._offsets = page_offsets

    def _find(self, segment_id: object) -> int:
        if not isinstance(segment_id, int):
            return -1
        index = bisect_left(self._ids, segment_id)
        return index if index < len(self._ids) and self._ids[index] == segment_id else -1

    def __getitem__(self, segment_id: int) -> SegmentLocator:
        index = self._find(segment_id)
        if index < 0:
            raise KeyError(segment_id)
        return SegmentLocator(segment_id, self._counts[index], self._offsets[index])

    def __contains__(self, segment_id: object) -> bool:
        return self._find(segment_id) >= 0

    def __iter__(self) -> Iterator[int]:
        return iter(self._ids)

    def __len__(self) -> int:
        return len(self._ids)


class _SegmentRun(NamedTuple):
    """One run of the segment_map, decoded: its live records as arrays, its tombstones apart."""

    ids: array
    page_counts: array
    page_offsets: array
    deleted: list[int]

    def id_range(self) -> tuple[int, int]:
        """The lowest and highest segment id the run mentions, for runs whose ids are sorted."""
        mentioned = [*self.ids[:1], *self.ids[-1:], *self.deleted]
        return min(mentioned), max(mentioned)


def _decode_segment_run(records: Iterable[Record]) -> _SegmentRun:
    run = _SegmentRun(array("Q"), array("L"), array("L"), [])
    for alive, fields in records:
        if alive:
            segment_id, page_count, page_offset = fields
            run.ids.append(segment_id)
            run.page_counts.append(int.from_bytes(page_count, "little"))
            run.page_offsets.append(page_offset)
        else:
            run.deleted.append(fields[0])
    return run


def load_segment_index(store: PageStore, header: ArchiveHeader) -> SegmentIndex:
    """Walk the segment_map tree of ``header`` and index it by segment id.

    The runs of the tree (the mem-tree, then the ctrees, newest first) are merged with LSM
    keep-first semantics: the newest record for a segment id wins, and a tombstone masks
    it. Segment ids are handed out in increasing order, so each run normally covers an id
    range of its own, and real archives have two to four runs. Then no record can shadow
    another, and the runs only need putting in id order.
    """
    sb = header.tree(TLV_SEGMENT_MAP)
    runs: list[_SegmentRun] = []
    if sb is not None and sb.value_length >= SEGMENT_MAP_VALUE_SIZE:
        # Only the leading fields of the value are known; a longer value just pads further
        record = struct.Struct(f"{_SEGMENT_MAP_RECORD.format}{sb.value_length - SEGMENT_MAP_VALUE_SIZE}x")
        runs = [_decode_segment_run(records) for records in _record_runs(store, sb, _SEGMENT_MAP_KEY, record)]

    ids = array("Q")
    page_counts = array("L")
    page_offsets = array("L")
    nonempty = [run for run in runs if run.ids or run.deleted]
    if all(left < right for run in nonempty for left, right in pairwise(run.ids)):
        nonempty.sort(key=_SegmentRun.id_range)
        bounds = [run.id_range() for run in nonempty]
        if all(left[1] < right[0] for left, right in pairwise(bounds)):
            for run in nonempty:
                ids.extend(run.ids)
                page_counts.extend(run.page_counts)
                page_offsets.extend(run.page_offsets)
            return SegmentIndex(ids, page_counts, page_offsets)

    # Runs that share segment ids: the first record seen for an id, newest run first, wins.
    # Ids are unique within a run, so only those of the runs before the last need remembering.
    seen: set[int] = set()
    for number, run in enumerate(runs):
        for segment_id, page_count, page_offset in zip(run.ids, run.page_counts, run.page_offsets, strict=True):
            if segment_id not in seen:
                ids.append(segment_id)
                page_counts.append(page_count)
                page_offsets.append(page_offset)
        if number < len(runs) - 1:
            seen.update(run.ids)
            seen.update(run.deleted)
    order = sorted(range(len(ids)), key=ids.__getitem__)
    return SegmentIndex(
        array("Q", (ids[index] for index in order)),
        array("L", (page_counts[index] for index in order)),
        array("L", (page_offsets[index] for index in order)),
    )
