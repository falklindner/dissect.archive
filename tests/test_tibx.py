from __future__ import annotations

import hashlib
import io
import random
import struct
from typing import TYPE_CHECKING

import pytest

from dissect.archive.tibx.map import load_extents, load_segment_index
from dissect.archive.tibx.tibx import TIBX, resolve_extents
from tests._synth import (
    PAGE,
    Cell,
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
    volumes = tibx.volumes()
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
    volume = tibx.volumes()[0]

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
    volumes = tibx.volumes()
    assert [v.volume_id for v in volumes] == [10, 6]


def test_multi_page_segment_in_volume() -> None:
    data = random.Random(1).randbytes(4 * PAGE)  # incompressible, spans pages
    tibx = _open(build_lsm_archive([ExtentSpec(10, 0, data)]))
    assert tibx.volumes()[0].read(0, len(data)) == data


def test_stream_matches_direct_reads() -> None:
    extents = [
        ExtentSpec(10, 0x0000, b"A" * 0x5000),
        ExtentSpec(10, 0x9000, b"B" * 0x3000),
    ]
    tibx = _open(build_lsm_archive(extents))
    volume = tibx.volumes()[0]
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
    volume = tibx.volumes()[0]
    assert volume.size == 100 * 512
    # The tail past the last extent reads as zeros
    assert volume.read(0x1000, volume.size - 0x1000) == b"\x00" * (volume.size - 0x1000)


def test_volume_size_from_fat32_boot_sector() -> None:
    # FAT32 needs 65525+ clusters, so the image is ~32 MiB virtual with a sparse body
    image = build_fat32_image(b"fat32 file content")
    tibx = _open(build_lsm_archive(sparse_extents(10, image)))
    volume = tibx.volumes()[0]
    assert volume.size == len(image)
    assert volume.read(0, 512) == image[:512]


def test_volume_size_from_exfat_boot_sector() -> None:
    image = build_exfat_image(b"exfat file content")
    # Pad the data_map span past the filesystem: the boot-sector size must win
    tibx = _open(build_lsm_archive([ExtentSpec(10, 0, image), ExtentSpec(10, len(image), b"\x00" * 512)]))
    volume = tibx.volumes()[0]
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


def test_resolve_extents_empty() -> None:
    assert resolve_extents([]) == ([], [])


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
    volumes = {v.volume_id: v for v in tibx.volumes()}

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
    tibx._extents = [*tibx.extents, discard]
    tibx._volumes = None

    volume = tibx.volumes()[0]
    assert volume.read(0, 0x1000) == b"A" * 0x1000
    assert volume.read(0x1000, 0x1000) == b"\x00" * 0x1000  # masked by the discard
    assert volume.read(0x2000, 0x1000) == b"A" * 0x1000  # older data past the marker


def test_tombstone_masks_older_records() -> None:
    # A backup-version cleanup writes tombstones into the mem-tree (newest LSM layer)
    # that must mask the deleted version's records still present in the on-disk ctree
    payload_a, payload_b = b"A" * 64, b"B" * 64
    key_a = data_map_key(10, 0, 64, 2, 1)
    key_b = data_map_key(10, 0x1000, 64, 2, 2)
    dm_cells = [Cell(key_a, data_map_value(100)), Cell(key_b, data_map_value(101))]
    sm_cells = [
        Cell(struct.pack(">Q", 100), segment_map_value(1, 1)),
        Cell(struct.pack(">Q", 101), segment_map_value(1, 2)),
    ]
    dm_sb = lsb(31, 10, memtree_cells=[Cell(key_a, b"", alive=False)], ctrees=[(3 * PAGE, len(dm_cells))])
    sm_sb = lsb(8, 32, memtree_cells=[Cell(struct.pack(">Q", 100), b"", alive=False)], ctrees=[(4 * PAGE, 2)])
    archive = (
        arch_header_page({1: dm_sb, 2: sm_sb})
        + segment_pages(payload_a)[0]
        + segment_pages(payload_b)[0]
        + lsm_page(0x03, b"LEAF", dm_cells, key_length=31, compact=True)
        + lsm_page(0x03, b"LEAF", sm_cells, key_length=8, compact=True)
    )

    tibx = _open(archive)
    volume = tibx.volumes()[0]
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
        volume = tibx.volumes()[0]
        assert volume.read(0, len(data)) == data
        result = tibx.store.verify()
        assert result["bad"] == 0
        assert result["holes"] == 7  # the compacted logical range of the base file


@pytest.mark.parametrize("compression", [0x0002, 0x0003], ids=["variant2", "variant3"])
def test_comp_stored_variants(compression: int) -> None:
    # Metadata-stream variants observed in real archives, only ever stored verbatim
    data = b"metadata stream content" * 5
    tibx = _open(build_lsm_archive([ExtentSpec(10, 0, data)], compression=compression))
    assert tibx.volumes()[0].read(0, len(data)) == data
