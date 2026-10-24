from __future__ import annotations

import gc
import hashlib
import io
import random
import struct
import weakref
from itertools import pairwise
from typing import TYPE_CHECKING

import pytest

from dissect.archive.tibx.map import Extent, ExtentTable, load_extents, load_segment_index
from dissect.archive.tibx.tibx import MIN_VOLUME_SIZE, TIBX, resolve_extents
from tests._synth import (
    PAGE,
    Cell,
    CountingIO,
    ExtentSpec,
    arch_header_page,
    build_exfat_image,
    build_fat32_image,
    build_lsm_archive,
    build_version_set,
    data_map_key,
    data_map_value,
    lsb,
    lsm_page,
    segment_map_key,
    segment_map_value,
    segment_pages,
    sparse_extents,
)

if TYPE_CHECKING:
    from pathlib import Path


def _open(archive: bytes) -> TIBX:
    return TIBX(io.BytesIO(archive))


def _expected_image(extents: list[ExtentSpec], size: int) -> bytes:
    # Paint the extents oldest-to-newest into a zeroed buffer (slice_id = recency)
    image = bytearray(size)
    for spec in sorted(extents, key=lambda s: s.slice_id):
        image[spec.source_offset : spec.source_offset + len(spec.data)] = spec.data
    return bytes(image)


@pytest.mark.parametrize("use_ctree", [False, True], ids=["memtree", "ctree"])
def test_volume_reconstruction_with_holes(use_ctree: bool) -> None:
    extents = [
        ExtentSpec(10, 0x0000, b"A" * 0x8000),
        ExtentSpec(10, 0xC000, b"B" * 0x4000),  # sparse hole at [0x8000, 0xC000)
    ]
    tibx = _open(build_lsm_archive(extents, use_ctree=use_ctree))
    volumes = tibx.streams()
    assert len(volumes) == 1
    volume = volumes[0]
    assert volume.volume_id == 10
    assert volume.size == 0x10000

    image = volume.read(0, volume.size)
    assert image == _expected_image(extents, 0x10000)
    # The hole reads as zeros
    assert volume.read(0x8000, 0x4000) == b"\x00" * 0x4000
    # Reads spanning an extent boundary
    assert volume.read(0x7FF0, 0x20) == b"A" * 0x10 + b"\x00" * 0x10


def test_overlapping_extents_newest_slice_wins() -> None:
    base = ExtentSpec(10, 0x0000, b"A" * 0x8000, slice_id=2, extent_id=10)
    # A newer, shorter extent from a later backup overlays the middle of the base.
    # Note it carries a LOWER extent_id — only the slice id signals recency.
    patch = ExtentSpec(10, 0x2000, b"X" * 0x1000, slice_id=3, extent_id=1)
    tibx = _open(build_lsm_archive([base, patch]))
    volume = tibx.streams()[0]

    assert volume.read(0x2000, 0x1000) == b"X" * 0x1000
    # The tail of the longer base extent is NOT masked by the shorter newer one
    assert volume.read(0x3000, 0x1000) == b"A" * 0x1000
    assert volume.read(0, volume.size) == _expected_image([base, patch], 0x8000)


def test_multiple_volumes_ranked_by_span() -> None:
    extents = [
        ExtentSpec(6, 0, b"small" * 100),
        ExtentSpec(10, 0, b"L" * 0x20000),
    ]
    tibx = _open(build_lsm_archive(extents))
    volumes = tibx.streams()
    assert [v.volume_id for v in volumes] == [10, 6]


def test_multi_page_segment_in_volume() -> None:
    data = random.Random(1).randbytes(4 * PAGE)  # incompressible, spans pages
    tibx = _open(build_lsm_archive([ExtentSpec(10, 0, data)]))
    assert tibx.streams()[0].read(0, len(data)) == data


def test_segment_read_in_one_io() -> None:
    # The segment_map's page count lets a segment come in one read: one round trip per
    # segment over SMB instead of two
    first, second = random.Random(3).randbytes(3 * PAGE), random.Random(4).randbytes(3 * PAGE)
    fh = CountingIO(build_lsm_archive([ExtentSpec(10, 0, first), ExtentSpec(10, len(first), second)]))
    volume = TIBX(fh).streams()[0]
    assert volume.read(0, len(first)) == first  # also loads the segment index

    fh.reads = 0
    assert volume.read(len(first), len(second)) == second
    assert fh.reads == 1


def test_stream_matches_direct_reads() -> None:
    extents = [
        ExtentSpec(10, 0x0000, b"A" * 0x5000),
        ExtentSpec(10, 0x9000, b"B" * 0x3000),
    ]
    tibx = _open(build_lsm_archive(extents))
    volume = tibx.streams()[0]
    stream = volume.open()

    assert stream.size == volume.size
    direct = volume.read(0, volume.size)
    assert stream.read() == direct
    assert hashlib.sha256(direct).hexdigest() == hashlib.sha256(_expected_image(extents, 0xC000)).hexdigest()

    stream.seek(0x4FF0)
    assert stream.read(0x20) == direct[0x4FF0 : 0x4FF0 + 0x20]


def test_volume_size_from_ntfs_boot_sector() -> None:
    # A fake NTFS boot sector claiming 100 sectors; the data_map span is only 4 KiB
    boot = bytearray(0x1000)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<H", boot, 0x0B, 512)
    struct.pack_into("<Q", boot, 0x28, 100)
    tibx = _open(build_lsm_archive([ExtentSpec(10, 0, bytes(boot))]))
    volume = tibx.streams()[0]
    assert volume.size == 100 * 512
    # The tail past the last extent reads as zeros
    assert volume.read(0x1000, volume.size - 0x1000) == b"\x00" * (volume.size - 0x1000)


def test_volume_size_from_fat32_boot_sector() -> None:
    # FAT32 needs 65525+ clusters, so the image is ~32 MiB virtual with a sparse body
    image = build_fat32_image(b"fat32 file content")
    tibx = _open(build_lsm_archive(sparse_extents(10, image)))
    volume = tibx.streams()[0]
    assert volume.size == len(image)
    assert volume.read(0, 512) == image[:512]


def test_volume_size_from_exfat_boot_sector() -> None:
    image = build_exfat_image(b"exfat file content")
    # Pad the data_map span past the filesystem: the boot-sector size must win
    tibx = _open(build_lsm_archive([ExtentSpec(10, 0, image), ExtentSpec(10, len(image), b"\x00" * 512)]))
    volume = tibx.streams()[0]
    assert volume.size == len(image)


def test_maps_load_directly() -> None:
    extents = [ExtentSpec(10, 0, b"A" * 100, slice_id=2, extent_id=7)]
    tibx = _open(build_lsm_archive(extents))
    loaded = load_extents(tibx.store, tibx.header)
    assert len(loaded) == 1
    assert loaded[0].volume_id == 10
    assert loaded[0].extent_length == 100
    assert loaded[0].slice_id == 2
    assert loaded[0].extent_id == 7

    index = load_segment_index(tibx.store, tibx.header)
    assert loaded[0].segment_id in index
    assert index[loaded[0].segment_id].page_offset == 1


def test_record_layouts_match_c_tibx() -> None:
    # map.py decodes these records with struct for speed; c_tibx stays the definition
    from dissect.archive.tibx import map as tibx_map
    from dissect.archive.tibx.c_tibx import c_tibx

    key = data_map_key(0x1122334455667788, 0x0102030405060708, 0xABCDEF, 0x0A0B0C0D, 0x99)
    value = data_map_value(0xDEADBEEF, 0x1234)
    extent = tibx_map.decode_extent(key, value)
    parsed_key, parsed_value = c_tibx.data_map_key(key), c_tibx.data_map_value(value)
    assert extent == (
        parsed_key.volume_id,
        parsed_key.source_offset,
        parsed_key.extent_length,
        parsed_key.slice_id,
        parsed_key.extent_id,
        parsed_value.segment_id,
        parsed_value.extent_index,
    )
    # Plain ints: cstruct's int subclasses are tracked by the GC, at a million records a tree
    assert all(type(field) is int for field in extent)

    raw = segment_map_value(0x01020304, 0x0A0B0C0D, slice_id=7)
    locator = tibx_map.decode_segment_locator(segment_map_key(42), raw)
    assert locator == (42, 0x01020304, c_tibx.segment_map_value(raw).page_offset)


def test_extent_table() -> None:
    extents = [
        Extent(11, 0x2000, 0x1000, 2, 3, 103, 0xFFFF),
        Extent(10, 0x1000, 0x1000, 1, 2, 102, 0xFFFF),
        Extent(10, 0x0000, 0x1000, 1, 1, 101, 0xFFFF),
    ]
    table = ExtentTable.from_extents(extents)

    assert len(table) == 3
    assert list(table) == sorted(extents)
    assert table[0] == extents[2]
    assert table[-1] == extents[0]
    assert list(table[1:]) == [extents[1], extents[0]]
    assert list(table.volume_ranges()) == [(10, 0, 2), (11, 2, 3)]
    assert list(table.select([True, False, True])) == [extents[2], extents[0]]
    assert len(ExtentTable()) == 0
    assert list(ExtentTable().volume_ranges()) == []

    # Columns, not an object per extent for the GC to traverse
    many = [Extent(10, index * 0x1000, 0x1000, 1, index, index + 100, 0xFFFF) for index in range(1000)]
    gc.collect()
    tracked = len(gc.get_objects())
    table = ExtentTable.from_extents(many)
    gc.collect()
    assert len(gc.get_objects()) - tracked < 10
    assert list(table) == many


@pytest.mark.parametrize("mode", ["own-keys", "shared-keys", "tombstones"])
@pytest.mark.parametrize("seed", range(10))
def test_load_extents_matches_keep_first_reference(seed: int, mode: str) -> None:
    # The mem-tree and two ctrees, newest first, their keys interleaving in offset order as in
    # real archives. Runs that share keys (rewrites, tombstones) must merge keep-first
    rng = random.Random(seed)
    runs = []
    records = {}
    for number in range(3):
        cells = []
        for _ in range(rng.randrange(1, 30)):
            volume_id = rng.choice((10, 11))
            offset = rng.randrange(0, 24) * 0x1000
            # Own keys: each run another slice, so runs only share volume offsets, not keys
            key = (volume_id, offset, 0x1000, number + 1 if mode == "own-keys" else 1, 1)
            if any(key == cell_key for cell_key, _ in cells):
                continue
            if mode == "tombstones" and rng.random() < 0.2:
                cells.append((key, None))
            else:
                cells.append((key, rng.randrange(1, 1000)))
        cells.sort()
        runs.append(cells)
        for key, segment_id in cells:
            records.setdefault(key, segment_id)

    def to_cells(cells: list) -> list[Cell]:
        return [
            Cell(
                data_map_key(*key),
                b"" if segment_id is None else data_map_value(segment_id),
                alive=segment_id is not None,
            )
            for key, segment_id in cells
        ]

    dm_sb = lsb(31, 10, memtree_cells=to_cells(runs[0]), ctrees=[(PAGE, len(runs[1])), (2 * PAGE, len(runs[2]))])
    leaves = b"".join(lsm_page(0x03, b"LEAF", to_cells(cells), key_length=31, compact=True) for cells in runs[1:])
    tibx = _open(arch_header_page({1: dm_sb}) + leaves)

    expected = [
        Extent(volume_id, offset, length, slice_id, extent_id, segment_id, 0xFFFF)
        for (volume_id, offset, length, slice_id, extent_id), segment_id in sorted(records.items())
        if segment_id is not None
    ]
    loaded = load_extents(tibx.store, tibx.header)
    assert sorted(loaded) == expected
    assert [(extent.volume_id, extent.source_offset) for extent in loaded] == sorted(
        (extent.volume_id, extent.source_offset) for extent in expected
    )


def test_segment_index_merges_runs() -> None:
    # A newer run (the mem-tree) holding a higher segment id than the older ctree comes
    # out of the tree walk unsorted; the index must still look every id up
    sm_sb = lsb(8, 32, memtree_cells=[Cell(segment_map_key(300), segment_map_value(3, 30))], ctrees=[(PAGE, 2)])
    leaf = lsm_page(
        0x03,
        b"LEAF",
        [Cell(segment_map_key(100), segment_map_value(1, 10)), Cell(segment_map_key(200), segment_map_value(2, 20))],
        key_length=8,
        compact=True,
    )
    tibx = _open(arch_header_page({2: sm_sb}) + leaf)
    index = load_segment_index(tibx.store, tibx.header)

    assert list(index) == [100, 200, 300]
    assert len(index) == 3
    assert index[300].page_offset == 30
    assert index[100].page_count == 1
    assert 200 in index
    assert 250 not in index
    assert "200" not in index
    assert index.get(250) is None
    assert dict(index.items())[200] == (200, 2, 20)
    with pytest.raises(KeyError):
        index[250]


def test_segment_index_sorts_a_run_out_of_order() -> None:
    # A run out of id order, as in a damaged tree, must not break the lookups by bisection
    cells = [Cell(segment_map_key(segment_id), segment_map_value(1, segment_id)) for segment_id in (300, 100, 200)]
    leaf = lsm_page(0x03, b"LEAF", cells, key_length=8, compact=True)
    tibx = _open(arch_header_page({2: lsb(8, 32, ctrees=[(PAGE, len(cells))])}) + leaf)

    index = load_segment_index(tibx.store, tibx.header)
    assert list(index) == [100, 200, 300]
    assert [index[segment_id].page_offset for segment_id in (100, 200, 300)] == [100, 200, 300]


@pytest.mark.parametrize("overlapping", [True, False], ids=["overlapping", "disjoint"])
@pytest.mark.parametrize("seed", range(10))
def test_segment_index_matches_keep_first_reference(seed: int, overlapping: bool) -> None:
    # The mem-tree and two ctrees, newest first. Written as ids are handed out, each run holds
    # an id range of its own; runs that share ids (rewrites, tombstones) must merge keep-first
    rng = random.Random(seed)
    runs = []
    locations = {}
    for number in range(3):
        low = 0 if overlapping else (2 - number) * 1000
        segment_ids = sorted(rng.sample(range(low, low + (60 if overlapping else 1000)), rng.randrange(1, 30)))
        cells = []
        for segment_id in segment_ids:
            if rng.random() < 0.2:
                cells.append(Cell(segment_map_key(segment_id), b"", alive=False))
            else:
                location = (rng.randrange(1, 9), rng.randrange(1, 1 << 20))
                locations[number, segment_id] = location
                cells.append(Cell(segment_map_key(segment_id), segment_map_value(*location)))
        runs.append(cells)
    sm_sb = lsb(8, 32, memtree_cells=runs[0], ctrees=[(PAGE, len(runs[1])), (2 * PAGE, len(runs[2]))])
    leaves = b"".join(lsm_page(0x03, b"LEAF", cells, key_length=8, compact=True) for cells in runs[1:])
    tibx = _open(arch_header_page({2: sm_sb}) + leaves)

    expected = {}
    for number, cells in enumerate(runs):
        for cell in cells:
            segment_id = int.from_bytes(cell.key, "big")
            expected.setdefault(segment_id, locations.get((number, segment_id)))
    expected = {segment_id: location for segment_id, location in sorted(expected.items()) if location is not None}

    index = load_segment_index(tibx.store, tibx.header)
    assert list(index) == list(expected)
    assert [(locator.page_count, locator.page_offset) for locator in index.values()] == list(expected.values())


def test_resolve_extents_empty() -> None:
    assert tuple(map(list, resolve_extents(ExtentTable()))) == ([], [], [])


def _resolve_by_boundary(extents: list[Extent]) -> list[tuple[int, int, Extent]]:
    # Reference for resolve_extents: between two boundaries, the most recent covering extent
    # wins, and a run of the same extent is one interval
    points = sorted({offset for extent in extents for offset in (extent.source_offset, extent.end_offset)})
    intervals = []
    for start, end in pairwise(points):
        covering = [extent for extent in extents if extent.source_offset <= start < extent.end_offset]
        if not covering:
            continue
        winner = max(covering, key=lambda extent: (extent.slice_id, extent.extent_id, extent.segment_id))
        if intervals and intervals[-1][2] is winner and intervals[-1][1] == start:
            intervals[-1] = (intervals[-1][0], end, winner)
        else:
            intervals.append((start, end, winner))
    return intervals


@pytest.mark.parametrize("overlapping", [True, False], ids=["overlapping", "disjoint"])
@pytest.mark.parametrize("seed", range(25))
def test_resolve_extents_matches_reference(seed: int, overlapping: bool) -> None:
    rng = random.Random(seed)
    extents = []
    offset = 0
    for extent_id in range(1, rng.randrange(2, 80)):
        length = rng.randrange(0, 16) * 0x1000
        if overlapping:
            offset = rng.randrange(0, 64) * 0x1000
        extents.append(Extent(10, offset, length, rng.randrange(1, 6), extent_id, rng.randrange(1, 100), 0xFFFF))
        if not overlapping:
            offset += length + rng.randrange(0, 3) * 0x1000
    rng.shuffle(extents)
    # Another volume's extents around them: only the rows given are resolved
    table = ExtentTable.from_extents(
        [*extents, Extent(9, 0, 0x1000, 9, 1, 1, 0xFFFF), Extent(11, 0, 0x1000, 9, 1, 1, 0xFFFF)]
    )

    starts, stops, covering = resolve_extents(table, 1, len(table) - 1)
    resolved = [(start, stop, table[1 + row]) for start, stop, row in zip(starts, stops, covering, strict=True)]
    assert resolved == _resolve_by_boundary(extents)


def test_resolve_extents_full_backup_creates_no_object_per_interval() -> None:
    # Extents that do not overlap are their own intervals: plain arrays, no object per interval
    # for the GC to traverse
    extents = [Extent(10, index * 0x1000, 0x1000, 1, index, index + 100, 0xFFFF) for index in range(1000)]
    table = ExtentTable.from_extents(extents[::-1])
    gc.collect()
    tracked = len(gc.get_objects())

    starts, stops, covering = resolve_extents(table)

    assert len(gc.get_objects()) - tracked < 10
    assert list(covering) == list(range(1000))
    assert list(starts) == [extent.source_offset for extent in extents]
    assert list(stops) == [extent.end_offset for extent in extents]


def test_multi_extent_shared_segment() -> None:
    # Two volumes share one segment (16-byte-aligned concatenation, as observed in
    # real True Image metadata streams); a third extent joins with unaligned length
    first = b"0123456"  # 7 bytes -> padded to 16 before the next chunk
    second = b"B" * 112
    third = b"C" * 100
    extents = [
        ExtentSpec(6, 0, first, segment_group=1),
        ExtentSpec(6, 7, second, segment_group=1),
        ExtentSpec(8, 0, third, segment_group=1),
    ]
    tibx = _open(build_lsm_archive(extents))
    volumes = {v.volume_id: v for v in tibx.streams()}

    assert volumes[6].read(0, 119) == first + second
    assert volumes[8].read(0, 100) == third
    # The shared segment holds all three chunks: 16 + 112 -> aligned 128, + 100
    assert len(tibx.read_segment(100)) == 16 + 112 + 100


def test_discard_extent_masks_older_data() -> None:
    # A newer slice marks part of an older extent as unallocated (segment_id 0, as
    # written by real incrementals when files are deleted): reads as zeros on top
    base = ExtentSpec(10, 0, b"A" * 0x4000, slice_id=2, extent_id=1)
    tibx = _open(build_lsm_archive([base]))
    # Inject the discard extent directly (the builder always allocates segments)
    from dissect.archive.tibx.map import Extent

    discard = Extent(
        volume_id=10, source_offset=0x1000, extent_length=0x1000, slice_id=3, extent_id=2, segment_id=0, extent_index=0
    )
    tibx._extents = ExtentTable.from_extents([*tibx.extents, discard])
    tibx._volumes = None

    volume = tibx.streams()[0]
    assert volume.read(0, 0x1000) == b"A" * 0x1000
    assert volume.read(0x1000, 0x1000) == b"\x00" * 0x1000  # masked by the discard
    assert volume.read(0x2000, 0x1000) == b"A" * 0x1000  # older data past the marker


def test_segment_shorter_than_its_extent_reads_zeros() -> None:
    # Damaged archive: the data_map maps more bytes than the segment holds
    tibx = _open(build_lsm_archive([ExtentSpec(10, 0, b"A" * 0x1000)]))
    tibx._extents = ExtentTable.from_extents([tibx.extents[0]._replace(extent_length=0x3000)])
    volume = tibx.streams()[0]

    assert volume.read(0, 0x3000) == b"A" * 0x1000 + b"\x00" * 0x2000
    assert volume.read(0xF00, 0x200) == b"A" * 0x100 + b"\x00" * 0x100
    assert volume.read(0x2F00, 0x200) == b"\x00" * 0x200  # and on past the end
    assert volume.read(0x100, 0) == b""


def test_tombstone_masks_older_records() -> None:
    # A backup-version cleanup writes tombstones into the mem-tree (newest LSM layer)
    # that must mask the deleted version's records still present in the on-disk ctree
    payload_a, payload_b = b"A" * 64, b"B" * 64
    key_a = data_map_key(10, 0, 64, 2, 1)
    key_b = data_map_key(10, 0x1000, 64, 2, 2)
    dm_cells = [Cell(key_a, data_map_value(100)), Cell(key_b, data_map_value(101))]
    sm_cells = [
        Cell(segment_map_key(100), segment_map_value(1, 1)),
        Cell(segment_map_key(101), segment_map_value(1, 2)),
    ]
    dm_sb = lsb(31, 10, memtree_cells=[Cell(key_a, b"", alive=False)], ctrees=[(3 * PAGE, len(dm_cells))])
    sm_sb = lsb(8, 32, memtree_cells=[Cell(segment_map_key(100), b"", alive=False)], ctrees=[(4 * PAGE, 2)])
    archive = (
        arch_header_page({1: dm_sb, 2: sm_sb})
        + segment_pages(payload_a)[0]
        + segment_pages(payload_b)[0]
        + lsm_page(0x03, b"LEAF", dm_cells, key_length=31, compact=True)
        + lsm_page(0x03, b"LEAF", sm_cells, key_length=8, compact=True)
    )

    tibx = _open(archive)
    volume = tibx.streams()[0]
    assert [extent.source_offset for extent in volume.extents] == [0x1000]
    assert volume.read(0x1000, 64) == payload_b
    # The masked extent's range reads as a sparse hole, not the old data
    assert volume.read(0, 64) == b"\x00" * 64

    index = load_segment_index(tibx.store, tibx.header)
    assert 100 not in index
    assert 101 in index


@pytest.mark.parametrize("use_ctree", [False, True], ids=["memtree", "ctree"])
def test_version_set_file_table(tmp_path: Path, use_ctree: bool) -> None:
    # Version set: base compacted to one physical page but logically spanning 8 pages;
    # the version file maps at page 8 via the TLV[18] file table, all offsets global
    data = b"version-file volume content" * 100
    stub, version = build_version_set([ExtentSpec(10, 0, data)], stub_logical_pages=8, use_ctree=use_ctree)
    (tmp_path / "Ver.tibx").write_bytes(stub)
    (tmp_path / "Ver-0001.tibx").write_bytes(version)

    with TIBX.open(tmp_path / "Ver.tibx") as tibx:
        assert tibx.store.page_count == 8 + len(version) // PAGE
        volume = tibx.streams()[0]
        assert volume.read(0, len(data)) == data
        result = tibx.store.verify()
        assert result["bad"] == 0
        assert result["holes"] == 7  # the compacted logical range of the base file


@pytest.mark.parametrize("compression", [0x0002, 0x0003], ids=["variant2", "variant3"])
def test_comp_stored_variants(compression: int) -> None:
    # Metadata-stream variants observed in real archives, only ever stored verbatim
    data = b"metadata stream content" * 5
    tibx = _open(build_lsm_archive([ExtentSpec(10, 0, data)], compression=compression))
    assert tibx.streams()[0].read(0, len(data)) == data


def _ntfs_boot(total_sectors: int, sector_size: int = 512) -> bytes:
    """A boot sector just complete enough for _boot_sector_size to size the volume."""
    boot = bytearray(512)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<H", boot, 0x0B, sector_size)
    struct.pack_into("<Q", boot, 0x28, total_sectors)
    return bytes(boot)


def _mbr(*partitions: tuple[int, int, int, int]) -> bytes:
    """A disk's MBR with the given ``(boot_flag, type, lba_start, sectors)`` entries."""
    mbr = bytearray(512)
    for index, (boot_flag, partition_type, lba_start, sectors) in enumerate(partitions):
        struct.pack_into("<B3xB3xII", mbr, 0x1BE + index * 16, boot_flag, partition_type, lba_start, sectors)
    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr)


def test_metadata_streams_are_not_volumes() -> None:
    # Acronis keys its own metadata by volume id exactly like a partition: the metainfo
    # XML, allocation bitmaps, small index tables, the disk's MBR region. Reporting those
    # as volumes made a one-partition backup look like eight.
    archive = build_lsm_archive(
        [
            ExtentSpec(4, 0, _ntfs_boot(0x18000) + b"\x00" * 512),  # a real 48 MB volume
            ExtentSpec(8, 0, b'\xef\xbb\xbf<?xml version="1.0"?><metainfo/>'),
            ExtentSpec(5, 0, b"\xff" * 520),
            ExtentSpec(2, 0, b"\x00" * 16),
        ]
    )
    tibx = TIBX(io.BytesIO(archive))

    assert [v.volume_id for v in tibx.volumes()] == [4]
    assert len(tibx.streams()) == 4  # nothing is lost, just classified


def test_unformatted_partition_is_still_a_volume() -> None:
    # A partition Acronis cannot identify is reported by "acrocmd list content" as a
    # partition of type None, so size has to carry it -- a filesystem check alone would
    # silently drop it.
    archive = build_lsm_archive(
        [
            ExtentSpec(4, 0, _ntfs_boot(0x18000) + b"\x00" * 512),
            ExtentSpec(9, MIN_VOLUME_SIZE, b"unformatted tail".ljust(512, b"\x00")),  # partition-sized
            ExtentSpec(3, 0, b"\x02\x00\x02\x00" * 8),
        ]
    )
    tibx = TIBX(io.BytesIO(archive))

    assert sorted(v.volume_id for v in tibx.volumes()) == [4, 9]


def test_allocation_bitmap_is_not_a_volume() -> None:
    # A volume's allocation bitmap is a bit per cluster, so on a real disk it passes
    # MIN_VOLUME_SIZE (one was 2.9 MB). Its span is no whole number of sectors.
    archive = build_lsm_archive(
        [
            ExtentSpec(4, 0, _ntfs_boot(0x18000) + b"\x00" * 512),
            ExtentSpec(5, 0, b"\xff" * (MIN_VOLUME_SIZE + 0x2C5)),
        ]
    )
    tibx = TIBX(io.BytesIO(archive))

    assert [v.volume_id for v in tibx.volumes()] == [4]


def test_sector_aligned_allocation_bitmap_is_not_a_volume() -> None:
    # The bitmap of a 100 GiB volume with 4 KiB clusters is 3,276,800 bytes, a whole number
    # of sectors (seen in a real archive). It starts with set bits, as no partition does.
    bitmap = b"\xff" * 0x3000 + b"\x0f" + b"\x00" * 0xFFF
    archive = build_lsm_archive(
        [
            ExtentSpec(4, 0, _ntfs_boot(0x18000) + b"\x00" * 512),
            ExtentSpec(9, 0, bitmap),
            ExtentSpec(9, 3_276_800 - 512, b"\x00" * 512),
        ]
    )
    tibx = TIBX(io.BytesIO(archive))

    assert [v.volume_id for v in tibx.volumes()] == [4]
    assert {stream.volume_id: stream.span for stream in tibx.streams()}[9] == 3_276_800


def test_allocation_bitmap_is_told_by_its_span() -> None:
    # Seen in a real archive: the bitmap of a volume of 41,943,039 clusters of 4 KiB is
    # 5,242,880 bytes, a whole number of sectors, and has clear bits in its first sector
    volume_span = 41_943_039 * 0x1000
    bitmap = b"\xff" * 16 + b"\x7f" + b"\xff" * 0x1EF
    archive = build_lsm_archive(
        [
            ExtentSpec(6, 0, _ntfs_boot(volume_span // 512) + b"\x00" * 512),
            ExtentSpec(6, volume_span - 512, b"\x00" * 512),
            ExtentSpec(8, 0, bitmap),
            ExtentSpec(8, 5_242_880 - 512, b"\x00" * 512),
        ]
    )
    tibx = TIBX(io.BytesIO(archive))

    assert [v.volume_id for v in tibx.volumes()] == [6]
    assert {stream.volume_id: stream.span for stream in tibx.streams()}[8] == 5_242_880


def test_filesystem_with_the_span_of_a_bitmap_is_a_volume() -> None:
    # A recognised filesystem is a volume whatever its span: this one happens to have the
    # span of the other's bitmap for 4 KiB clusters
    volume_span = 41_943_039 * 0x1000
    archive = build_lsm_archive(
        [
            ExtentSpec(6, 0, _ntfs_boot(volume_span // 512) + b"\x00" * 512),
            ExtentSpec(6, volume_span - 512, b"\x00" * 512),
            ExtentSpec(8, 0, _ntfs_boot(5_242_880 // 512) + b"\x00" * 512),
            ExtentSpec(8, 5_242_880 - 512, b"\x00" * 512),
        ]
    )
    tibx = TIBX(io.BytesIO(archive))

    assert sorted(v.volume_id for v in tibx.volumes()) == [6, 8]


@pytest.mark.parametrize(
    "mbr", [_mbr((0x80, 0x07, 2048, 0x18000)), _mbr((0x00, 0xEE, 1, 0xFFFFFFFF))], ids=["mbr", "gpt"]
)
def test_disk_bootstrap_region_is_not_a_volume(mbr: bytes) -> None:
    # The region before a disk's first partition is a whole 1 MiB on a disk partitioned
    # the Windows way, and starts with its partition table: an MBR whose partitions all
    # start past the region, or the protective MBR of a GPT disk.
    archive = build_lsm_archive(
        [
            ExtentSpec(4, 0, _ntfs_boot(0x18000) + b"\x00" * 512),
            ExtentSpec(1, 0, mbr),
            ExtentSpec(1, MIN_VOLUME_SIZE - 512, b"\x00" * 512),
        ]
    )
    tibx = TIBX(io.BytesIO(archive))

    assert [v.volume_id for v in tibx.volumes()] == [4]


def test_partition_with_unrecognised_boot_sector_is_a_volume() -> None:
    # A boot sector that ends in 55 AA, as BitLocker's does, is no partition table unless
    # its entries say so
    boot = bytearray(512)
    boot[:11] = b"\xeb\x58\x90-FVE-FS-"
    boot[510:512] = b"\x55\xaa"
    archive = build_lsm_archive([ExtentSpec(9, 0, bytes(boot)), ExtentSpec(9, MIN_VOLUME_SIZE, b"\x00" * 512)])
    tibx = TIBX(io.BytesIO(archive))

    assert [v.volume_id for v in tibx.volumes()] == [9]


def test_small_recognised_filesystem_is_a_volume() -> None:
    # Below the size threshold, but it says NTFS, so it is a volume.
    archive = build_lsm_archive([ExtentSpec(4, 0, _ntfs_boot(0x40) + b"\x00" * 512)])
    tibx = TIBX(io.BytesIO(archive))

    assert [v.volume_id for v in tibx.volumes()] == [4]


def test_close_releases_the_index() -> None:
    # Volumes refer back to their archive. close() drops the archive's side of that cycle,
    # so the index is freed by reference counting rather than whenever the cyclic GC runs.
    tibx = _open(build_lsm_archive([ExtentSpec(10, 0, b"A" * 0x1000)]))
    volume = weakref.ref(tibx.streams()[0])
    assert volume().read(0, 4) == b"AAAA"

    gc.disable()
    try:
        tibx.close()
        assert volume() is None
        assert not tibx._segment_cache
    finally:
        gc.enable()
