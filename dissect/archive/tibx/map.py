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
from typing import TYPE_CHECKING, NamedTuple

from dissect.archive.tibx.c_tibx import (
    DATA_MAP_KEY_SIZE,
    DATA_MAP_VALUE_SIZE,
    TLV_DATA_MAP,
    TLV_SEGMENT_MAP,
    c_tibx,
)
from dissect.archive.tibx.lsm import iter_tree_cells

if TYPE_CHECKING:
    from dissect.archive.tibx.lsm import ArchiveHeader
    from dissect.archive.tibx.page import PageStore


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
    key = c_tibx.data_map_key(raw_key)
    value = c_tibx.data_map_value(raw_value)
    return Extent(
        volume_id=key.volume_id,
        source_offset=key.source_offset,
        extent_length=key.extent_length,
        slice_id=key.slice_id,
        extent_id=key.extent_id,
        segment_id=value.segment_id,
        extent_index=value.extent_index,
    )


def load_extents(store: PageStore, header: ArchiveHeader) -> list[Extent]:
    """Walk the data_map tree of ``header`` and return all extents.

    Sorted by ``(volume_id, source_offset)``. Tombstones and malformed records are
    skipped. Returns an empty list if the header has no data_map.
    """
    sb = header.tree(TLV_DATA_MAP)
    if sb is None:
        return []
    extents = []
    seen: set[bytes] = set()
    for cell in iter_tree_cells(store, sb):
        if len(cell.key) != DATA_MAP_KEY_SIZE:
            continue
        key = bytes(cell.key)
        if key in seen:
            # LSM keep-first: the newest record for this key already decided its fate --
            # in particular a tombstone must keep masking an older alive record (seen in
            # the wild after a "single version scheme" cleanup deletes a backup version)
            continue
        seen.add(key)
        if not cell.alive or len(cell.value) != DATA_MAP_VALUE_SIZE:
            continue
        extents.append(decode_extent(cell.key, cell.value))
    extents.sort(key=lambda extent: (extent.volume_id, extent.source_offset))
    return extents


def load_segment_index(store: PageStore, header: ArchiveHeader) -> dict[int, SegmentLocator]:
    """Walk the segment_map tree of ``header`` and return ``{segment_id: locator}``.

    The mem-tree is yielded before the ctrees, so keep-first implements LSM merge
    semantics (the newest record for a segment id wins).
    """
    sb = header.tree(TLV_SEGMENT_MAP)
    if sb is None:
        return {}
    index: dict[int, SegmentLocator] = {}
    dead: set[int] = set()
    for cell in iter_tree_cells(store, sb):
        if len(cell.key) != 8:
            continue
        segment_id = struct.unpack(">Q", cell.key)[0]
        if segment_id in index or segment_id in dead:
            continue
        if not cell.alive or len(cell.value) < 8:
            # Keep-first as above: a tombstone masks older records for this segment
            dead.add(segment_id)
            continue
        # Empirically mixed endianness: page_count is LE, page_offset is BE
        page_count = struct.unpack_from("<I", cell.value, 0)[0]
        page_offset = struct.unpack_from(">I", cell.value, 4)[0]
        index[segment_id] = SegmentLocator(segment_id=segment_id, page_count=page_count, page_offset=page_offset)
    return index
