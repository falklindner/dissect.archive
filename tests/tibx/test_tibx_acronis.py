"""TIBX archives written by Acronis.

``t1_*`` are written by Acronis Cyber Protect 15 (build 37414) and identity-scrubbed: host,
account and SID values are replaced by same-length placeholders. Their expected backup GUIDs
are the ones ``acrocmd list backups`` prints for each archive.

``ati_2020_*`` are written by Acronis True Image 2020, with LZ4 forced: neither the GUI nor
the command line offers compression level low, so the level in the ARCH header was patched
to 1 (low) and its CRC32 fixed, and the backups made after that are LZ4. The first backup in
``ati_2020_disk_enc_lz4_compr`` was made before the patch and is zstd.
"""

from __future__ import annotations

import hashlib
import io

import pytest

from dissect.archive.tibx.c_tibx import PAGE_SIZE, TLV_SEGMENT_MAP, c_tibx
from dissect.archive.tibx.exception import CorruptArchiveError, InvalidPasswordError
from dissect.archive.tibx.lsm import iter_tree_cells
from dissect.archive.tibx.map import load_segment_index
from dissect.archive.tibx.page import (
    ARCI_CRC64_OFFSET,
    FIRST_CI_OFFSET,
    SCAN_CHUNK_MIN_PAGES,
    PageStore,
    arci_crc64,
    page_crc32c,
)
from dissect.archive.tibx.segment import Segment
from dissect.archive.tibx.tibx import TIBX
from tests._tools.tibx._synth import CountingIO
from tests._util import absolute_path

PASSWORD = "dissect"

# Incompressible segments are stored at every compression level
STORED_AND_ZSTD = {c_tibx.ComprAlg.NONE, c_tibx.ComprAlg.ZSTD}
STORED_AND_LZ4 = {c_tibx.ComprAlg.NONE, c_tibx.ComprAlg.LZ4}

ARCHIVES = [
    "t1_simple_ntfs",
    "t1_empty_ntfs",
    "t1_stored",
    "t1_enc_aes",
    "t1_disk_mbr",
    "t1_disk_gpt",
    "t1_multivol",
    "t1_chain_inc",
    "t1_chain_diff",
    "t1_legacy_tib",
    "ati_2020_disk_lz4_compr",
    "ati_2020_disk_enc_lz4_compr",
]


def _open(name: str) -> TIBX:
    return TIBX.open(absolute_path(f"_data/tibx/{name}.tibx"))


def _sample(name: str, corrupt: tuple[int, ...] = (), trailing: int = 0) -> bytes:
    """A single-file sample with a byte flipped in the page at each ``corrupt`` offset, and
    ``trailing`` zero pages appended, as a backup that failed after the last commit leaves.
    """
    data = bytearray(absolute_path(f"_data/tibx/{name}.tibx").read_bytes())
    for offset in corrupt:
        data[offset + 0x100] ^= 0xFF
    return bytes(data) + b"\x00" * PAGE_SIZE * trailing


def _rewrite_commit_info(data: bytearray, offset: int, **fields: int) -> None:
    """Set ``fields`` of the commit info page at ``offset`` in ``data``, and fix up both its CRCs."""
    page = data[offset : offset + PAGE_SIZE]
    for field, value in fields.items():
        start = len(c_tibx.page_header) + c_tibx.arci_header.fields[field].offset
        page[start : start + 8] = value.to_bytes(8, "big")
    page[ARCI_CRC64_OFFSET : ARCI_CRC64_OFFSET + 8] = arci_crc64(bytes(page)).to_bytes(8, "big")
    page[4:8] = page_crc32c(bytes(page)).to_bytes(4, "big")
    data[offset : offset + PAGE_SIZE] = page


def _sha256(tibx: TIBX, volume_id: int) -> str:
    volume = next(volume for volume in tibx.volumes() if volume.volume_id == volume_id)
    return hashlib.sha256(volume.open().read()).hexdigest()


def _segments(tibx: TIBX) -> dict[int, Segment]:
    """Every segment header of ``tibx``, by segment id."""
    index = load_segment_index(tibx.store, tibx.header)
    segments = {}
    for segment_id in index:
        page_index = index[segment_id].page_offset
        segments[segment_id] = Segment(tibx.store.read_run(page_index, 1)[0], page_index)
    return segments


@pytest.mark.parametrize(
    ("name", "backups", "volumes"),
    [
        ("t1_simple_ntfs", ["0179ab2a"], 1),
        ("t1_empty_ntfs", ["a7432cb3"], 1),
        ("t1_stored", ["9f993b4b"], 1),
        ("t1_enc_aes", ["96ab6f64"], 1),
        ("t1_disk_mbr", ["9652499c"], 2),
        ("t1_disk_gpt", ["17fb9899"], 8),
        ("t1_multivol", ["3c92193a"], 3),
        ("t1_chain_inc", ["f660caf0", "54425f75", "4b7e07ce"], 1),
        ("t1_chain_diff", ["5ad78378", "48ae4b88"], 1),
        ("t1_legacy_tib", ["77b21cde"], 0),  # file-level backup: no volumes
        ("ati_2020_disk_lz4_compr", ["7642df97", "982cebc8", "d82d0cde", "4d84d50e"], 1),
        ("ati_2020_disk_enc_lz4_compr", ["7ae8e0cc", "c1fdd51f"], 1),
    ],
)
def test_acronis_archive(name: str, backups: list[str], volumes: int) -> None:
    with _open(name) as tibx:
        assert tibx.store.verify()["bad"] == 0
        assert [str(point.guid)[:8] for point in tibx.recovery_points()] == backups
        # Listing must not need the password, only reading does
        assert len(tibx.volumes()) == volumes


@pytest.mark.parametrize(
    ("name", "volume_id", "digest"),
    [
        ("t1_simple_ntfs", 0x4, "2f37a8c006003a77723338f740e61ecec223095ab43852c132e10d1af3829fa0"),
        ("t1_stored", 0x4, "acf750441e2c47f8fcc7448e3bfd15bf99c6818cd2c737ae81f1a5ca0143d0d6"),
        ("ati_2020_disk_lz4_compr", 0xE, "d29989304fc63657dfdab3fd7fb0a804a747b93580b7abb622a29f3d55ae33e7"),
    ],
)
def test_acronis_volume_content(name: str, volume_id: int, digest: str) -> None:
    with _open(name) as tibx:
        assert _sha256(tibx, volume_id) == digest


@pytest.mark.parametrize(
    ("name", "level", "codecs"),
    [
        ("t1_simple_ntfs", c_tibx.ComprLvl.HIGH, STORED_AND_ZSTD),
        ("t1_empty_ntfs", c_tibx.ComprLvl.NORMAL, STORED_AND_ZSTD),
        ("t1_stored", c_tibx.ComprLvl.NONE, {c_tibx.ComprAlg.NONE}),
        ("t1_enc_aes", c_tibx.ComprLvl.NORMAL, STORED_AND_ZSTD),
        ("t1_disk_mbr", c_tibx.ComprLvl.NORMAL, STORED_AND_ZSTD),
        ("t1_disk_gpt", c_tibx.ComprLvl.NORMAL, STORED_AND_ZSTD),
        ("t1_multivol", c_tibx.ComprLvl.NORMAL, STORED_AND_ZSTD),
        ("t1_chain_inc", c_tibx.ComprLvl.NORMAL, STORED_AND_ZSTD),
        ("t1_chain_diff", c_tibx.ComprLvl.NORMAL, STORED_AND_ZSTD),
        ("ati_2020_disk_lz4_compr", c_tibx.ComprLvl.LOW, STORED_AND_LZ4),
        ("ati_2020_disk_enc_lz4_compr", c_tibx.ComprLvl.LOW, {c_tibx.ComprAlg.LZ4, c_tibx.ComprAlg.ZSTD}),
    ],
)
def test_acronis_segments(name: str, level: c_tibx.ComprLvl, codecs: set[c_tibx.ComprAlg]) -> None:
    # Every segment decodes to the length its header records
    with _open(name) as tibx:
        if tibx.encrypted:
            tibx.unlock(PASSWORD)
        assert tibx.root.compr_lvl == level

        seen = set()
        for segment_id, segment in _segments(tibx).items():
            assert len(tibx.read_segment(segment_id)) == segment.length
            seen.add(segment.compression)
        assert seen == codecs


def test_acronis_codec_per_backup() -> None:
    # The compression level was patched to low between the two backups: each segment is
    # written in the codec of the backup that first stored it
    with _open("ati_2020_disk_enc_lz4_compr") as tibx:
        first_slice = {}
        for extent in tibx.extents:
            first_slice[extent.segment_id] = min(extent.slice_id, first_slice.get(extent.segment_id, extent.slice_id))

        codecs = {}
        for segment_id, segment in _segments(tibx).items():
            codecs.setdefault(first_slice[segment_id], set()).add(segment.compression)
        assert codecs == {2: {c_tibx.ComprAlg.ZSTD}, 3: {c_tibx.ComprAlg.LZ4}}


@pytest.mark.parametrize(
    ("name", "alg", "volume_id", "digest"),
    [
        (
            "t1_enc_aes",
            c_tibx.EncrAlg.AES_256_GCM,
            0x4,
            "d13f328efd801ac02dfb847a83bb1c0432182273619cf3b7121558f2bb177ea0",
        ),
        (
            "ati_2020_disk_enc_lz4_compr",
            c_tibx.EncrAlg.AES_256_CBC,
            0x6,
            "122fd1031eec87f138c2c8607fb858bb81ec3d9041115344a5b8a52e1f2251c0",
        ),
    ],
)
def test_acronis_encrypted(name: str, alg: c_tibx.EncrAlg, volume_id: int, digest: str) -> None:
    with _open(name) as tibx:
        assert tibx.encrypted
        assert tibx.password_protected
        assert tibx.root.encr_alg == alg
        with pytest.raises(InvalidPasswordError):
            tibx.unlock("wrong")

        tibx.unlock(PASSWORD)
        assert _sha256(tibx, volume_id) == digest


@pytest.mark.parametrize(
    ("name", "volume_id", "expected"),
    [
        (
            "t1_chain_inc",
            0x4,
            [
                "14601f43adb0681ddf24a630acc050d00d1448627d5d0e810f925786efb5b8fb",
                "ed9dfc11d43d84d2a88acfb094ca80cd6859966cfafd2d740a22c4b42225025a",
                "e7e893d56c2ca997fbf4c86864927bcdf3b498205f46ada0fd4c3d6f2488f4df",
            ],
        ),
        (
            # A zstd backup, then an LZ4 one on top of it
            "ati_2020_disk_enc_lz4_compr",
            0x6,
            [
                "0a2702360cdb9902aa64f59f072402736b4f0f57be4fc1e83a5884900e226084",
                "122fd1031eec87f138c2c8607fb858bb81ec3d9041115344a5b8a52e1f2251c0",
            ],
        ),
    ],
)
def test_acronis_recovery_points(name: str, volume_id: int, expected: list[str]) -> None:
    with _open(name) as tibx:
        if tibx.encrypted:
            tibx.unlock(PASSWORD)
        for index, digest in enumerate(expected):
            tibx.use_recovery_point(index)
            assert _sha256(tibx, volume_id) == digest

        tibx.use_recovery_point("latest")
        assert _sha256(tibx, volume_id) == expected[-1]


@pytest.mark.parametrize(
    ("name", "types"),
    [
        ("t1_simple_ntfs", ["FULL"]),
        ("t1_chain_inc", ["FULL", "INCREMENTAL", "INCREMENTAL"]),
        ("t1_chain_diff", ["FULL", "DIFFERENTIAL"]),
        ("ati_2020_disk_lz4_compr", ["FULL", "INCREMENTAL", "INCREMENTAL", "INCREMENTAL"]),
    ],
)
def test_acronis_recovery_point_types(name: str, types: list[str]) -> None:
    with _open(name) as tibx:
        assert [point.type for point in tibx.recovery_points()] == types


def test_acronis_unformatted_partition() -> None:
    # Imaged sector by sector; its index is the one that needs LZ4 dictionary blocks
    with _open("t1_disk_gpt") as tibx:
        assert _sha256(tibx, 0x19) == "18fdb2a2fbfda6a212c8c82d848835dc863e905a481ad400c0ba0c084d80fce7"


@pytest.mark.parametrize(
    ("name", "recovery_point", "sizes"),
    [
        # NTFS leaves the partition's last sector out of the volume size in its boot sector
        ("t1_simple_ntfs", "latest", {0x4: 50331648}),
        ("t1_disk_mbr", "latest", {0x4: 50331648, 0x7: 41943040}),
        # The boot sector size is more than 64 times what this sparse volume stores
        ("ati_2020_disk_lz4_compr", 2, {0xE: 2097152}),
        # Unformatted partitions have no boot sector
        ("t1_disk_gpt", "latest", {0x11: 33554432, 0x15: 33554432, 0x19: 33554432}),
        # The imap is encrypted
        ("ati_2020_disk_enc_lz4_compr", "latest", {0x6: 3145728}),
    ],
)
def test_acronis_volume_size(name: str, recovery_point: int | str, sizes: dict[int, int]) -> None:
    # The partition's size, as the imap records it and as Acronis's tibxread reads it
    with _open(name) as tibx:
        if tibx.encrypted:
            tibx.unlock(PASSWORD)
        tibx.use_recovery_point(recovery_point)
        volumes = {volume.volume_id: volume for volume in tibx.volumes()}
        assert {volume_id: volumes[volume_id].size for volume_id in sizes} == sizes


@pytest.mark.parametrize(
    ("recovery_point", "volume_id", "digest"),
    [
        # Before it was formatted, the partition stores no data at all, and reads as zeros
        (0, 0x6, "5647f05ec18958947d32874eeb788fa396a05d0bab7c1b71f112ceb7e9b31eee"),
        (1, 0x6, "5647f05ec18958947d32874eeb788fa396a05d0bab7c1b71f112ceb7e9b31eee"),
        # A freshly formatted FAT16, which stores 20 KiB of its 2 MiB
        (2, 0xE, "b69c98b5ac590d9173bd06df0388cbdd18ad0a12acf5963bcd6607254ac8ff36"),
        (3, 0xE, "d29989304fc63657dfdab3fd7fb0a804a747b93580b7abb622a29f3d55ae33e7"),
    ],
)
def test_acronis_sparse_volume(recovery_point: int, volume_id: int, digest: str) -> None:
    # What ``tibxread calculate hash --volume 1-1`` gives (verified for recovery points 0 and 2)
    with _open("ati_2020_disk_lz4_compr") as tibx:
        tibx.use_recovery_point(recovery_point)
        assert [volume.volume_id for volume in tibx.volumes()] == [volume_id]
        assert _sha256(tibx, volume_id) == digest


@pytest.mark.parametrize("name", ["ati_2020_disk_lz4_compr", "ati_2020_disk_enc_lz4_compr"])
def test_acronis_segment_hash(name: str) -> None:
    # The segment_map holds the SHA-1 of each decompressed segment. Not in the t1_* samples,
    # whose metainfo segments were scrubbed after Acronis hashed them.
    with _open(name) as tibx:
        if tibx.encrypted:
            tibx.unlock(PASSWORD)
        for cell in iter_tree_cells(tibx.store, tibx.header.tree(TLV_SEGMENT_MAP)):
            segment_id = c_tibx.segment_map_key(cell.key).segment_id
            digest = hashlib.sha1(tibx.read_segment(segment_id)).digest()
            assert digest == c_tibx.segment_map_value(cell.value).hash


@pytest.mark.parametrize("name", ARCHIVES)
def test_acronis_commit_info(name: str) -> None:
    # In an intact archive CI0, the last commit info and the last header all name the same root
    with _open(name) as tibx:
        store = tibx.store
        assert store.live_root().offset == store._last_ci().arch_offset == store._last_arch().offset


def test_acronis_commit_info_rewritten_ci0() -> None:
    # Cyber Protect 15 rewrites CI0 after each commit: it describes the newest commit, and
    # is the last commit info written
    with _open("t1_chain_inc") as tibx:
        store = tibx.store
        ci0 = store._ci0()
        newest = store._commit_info_at(store.live_root().ci_offset)
        assert ci0.flags == c_tibx.ArciFlags.REWRITE | c_tibx.ArciFlags.CI0
        assert newest.flags == c_tibx.ArciFlags.REWRITE
        assert ci0.commit_seq == newest.commit_seq == 5
        assert (ci0.ci_seq, newest.ci_seq) == (10, 9)
        assert ci0.arch_offset == newest.arch_offset == store.live_root().offset


def test_acronis_commit_info_split_archive() -> None:
    # CI0 is only in the first file of a split archive, and names the newest commit in the
    # last, in offsets of the whole archive
    with _open("t1_chain_diff") as tibx:
        store = tibx.store
        assert store._ci0().arch_offset == store.live_root().offset == 0xBC000

        # Commit info offsets are in the whole archive, volume offsets in the page's own file
        newest = store._commit_info_at(store.live_root().ci_offset)
        assert (newest.offset, newest.volume_offset) == (0xBE000, 0x42000)


@pytest.mark.parametrize("name", ["t1_chain_inc", "ati_2020_disk_lz4_compr"])
def test_acronis_live_root_three_reads(name: str) -> None:
    # CI0 and the commit info and header it names, where there is a CI0; otherwise page 2,
    # the last pages of the archive, which end in its newest commit info, and the header that
    # commit info names
    fh = CountingIO(_sample(name))
    store = PageStore(fh)
    fh.reads = 0
    root = store.live_root()
    assert fh.reads == 3
    assert root.offset == store._last_ci().arch_offset


def test_acronis_live_root_trusts_ci0() -> None:
    # As Acronis does, a valid CI0 decides the live root, even with a newer commit after the
    # one it names: here a commit torn after its commit info was written, but before CI0 was
    # rewritten to name it
    data = bytearray(_sample("t1_chain_inc"))
    _rewrite_commit_info(data, FIRST_CI_OFFSET, arch_offset=0xB6000, commit_seq=4, ci_seq=8, prev_ci_offset=0xB8000)

    store = PageStore(io.BytesIO(bytes(data)))
    assert store._last_ci().arch_offset == 0xF3000
    assert store.live_root().offset == 0xB6000


def test_acronis_commit_info_ci0_after_failed_backup() -> None:
    # Data after the last commit pushes the newest commit out of the last pages, but Cyber
    # Protect keeps CI0 up to date: it names the newest commit, however much data follows it
    fh = CountingIO(_sample("t1_chain_inc", trailing=5000))
    store = PageStore(fh)
    fh.reads = 0

    assert store.live_root().offset == 0xF3000
    assert fh.reads == 3  # CI0, the commit info it names and its header


def test_acronis_commit_info_without_ci0() -> None:
    # True Image 2020 has no CI0, its first commit info page stays the first commit's: the
    # backward scan finds the newest commit, however much data follows it
    store = PageStore(io.BytesIO(_sample("ati_2020_disk_lz4_compr", trailing=2 * SCAN_CHUNK_MIN_PAGES)))
    assert store._ci0() is None
    assert store._commit_info_at(FIRST_CI_OFFSET) is not None
    assert store.live_root().offset == 0x53000


def test_acronis_commit_info_damaged_ci0_and_end() -> None:
    data = _sample("t1_chain_inc", corrupt=(FIRST_CI_OFFSET,), trailing=2 * SCAN_CHUNK_MIN_PAGES)
    store = PageStore(io.BytesIO(data))
    assert store._ci0() is None
    assert store.live_root().offset == 0xF3000


def test_acronis_live_root_without_commit_info() -> None:
    # With every commit info page damaged, the last CRC-valid ARCH header is the live root
    store = PageStore(io.BytesIO(_sample("t1_chain_inc")))
    offsets = tuple(
        index * PAGE_SIZE for index in range(store.page_count) if store.page(index)[1] == c_tibx.PageType.ARCI
    )
    store = PageStore(io.BytesIO(_sample("t1_chain_inc", corrupt=offsets)))
    assert store._ci0() is None
    assert store._last_ci() is None
    assert store.live_root().offset == 0xF3000


@pytest.mark.parametrize(
    ("name", "torn", "previous"),
    [
        ("t1_chain_inc", 0xF6000, 0xB6000),
        ("ati_2020_disk_lz4_compr", 0x55000, 0x1D000),
    ],
)
def test_acronis_torn_commit(name: str, torn: int, previous: int) -> None:
    # A commit is complete only once its commit info has been written: a valid ARCH header
    # whose commit info is damaged, or missing from a truncated archive, is skipped
    damaged = PageStore(io.BytesIO(_sample(name, corrupt=(torn,))))
    assert damaged.live_root().offset == previous

    truncated = PageStore(io.BytesIO(_sample(name)[:torn]))
    assert truncated.live_root().offset == previous


@pytest.mark.parametrize("name", ARCHIVES)
def test_acronis_commit_info_crc64(name: str) -> None:
    # Each commit info page carries a CRC-64 (Redis) of its first 512 bytes, besides the
    # CRC-32C every page has
    with _open(name) as tibx:
        store = tibx.store
        pages = [store.page(index) for index in range(store.page_count)]
        commit_info = [page for page in pages if page[1] == c_tibx.PageType.ARCI]
        assert commit_info
        assert all(c_tibx.arci_page(page).commit_info.crc64 == arci_crc64(page) for page in commit_info)


def test_acronis_commit_info_crc64_mismatch() -> None:
    # A commit info page whose CRC-32C holds but whose CRC-64 does not is no commit info: its
    # commit is skipped, as a torn one is
    data = bytearray(_sample("t1_chain_inc"))
    page = data[0xF6000 : 0xF6000 + PAGE_SIZE]
    page[ARCI_CRC64_OFFSET] ^= 0xFF
    page[4:8] = page_crc32c(bytes(page)).to_bytes(4, "big")
    data[0xF6000 : 0xF6000 + PAGE_SIZE] = page

    store = PageStore(io.BytesIO(bytes(data)))
    assert store._commit_info_at(0xF6000) is None
    assert store.live_root().offset == 0xB6000


def test_acronis_truncated_header() -> None:
    # Cut off after its first page, the archive holds only part of its two-page ARCH header
    with pytest.raises(CorruptArchiveError, match="L-SB truncated"):
        TIBX(io.BytesIO(_sample("t1_chain_inc")[:PAGE_SIZE]))
