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

from dissect.archive.tibx.c_tibx import PAGE_SIZE, c_tibx
from dissect.archive.tibx.exception import InvalidPasswordError
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
from tests.conftest import absolute_path

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
    return TIBX.open(absolute_path(f"_data/acronis/tibx/{name}.tibx"))


def _sample(name: str, corrupt: tuple[int, ...] = (), trailing: int = 0) -> bytes:
    """A single-file sample with a byte flipped in the page at each ``corrupt`` offset, and
    ``trailing`` zero pages appended, as a backup that failed after the last commit leaves.
    """
    data = bytearray(absolute_path(f"_data/acronis/tibx/{name}.tibx").read_bytes())
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
        ("t1_simple_ntfs", 0x4, "16c90fb48eedab726037df2cfc59d0d1b8140cf320e3fac57b33087848781676"),
        ("t1_stored", 0x4, "aa55f3a300f8f687d3023d4df03b4c84264f55df7c1519b8bffdd166aa74cb68"),
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
            "4d71863bceccc3b8b3d8ce0d3bdf1926b479775926c588f014f3b51c45de0320",
        ),
        (
            "ati_2020_disk_enc_lz4_compr",
            c_tibx.EncrAlg.AES_256_CBC,
            0x6,
            "134a9b44bdf6c383dae8c863a6fcbba254b805c4c49ae12a02367bf3d081aad6",
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
                "76cb61ecc47f9ced80d80270b2e32bf457ebf69bbd0a7b671890ea3e13e01596",
                "4d8189da83582ac549918ba85131c51d5bd4543f5b739a8b984d4369a904591e",
                "2c388dfbc8d3446f5d7f36bb7d62a46234a0ceb49aad99defbe202822bc34e07",
            ],
        ),
        (
            # A zstd backup, then an LZ4 one on top of it
            "ati_2020_disk_enc_lz4_compr",
            0x6,
            [
                "32da7e79b4787c254e3b4ba74b73a6633f4d17b49d2a1c82a7c711acce1dd94b",
                "134a9b44bdf6c383dae8c863a6fcbba254b805c4c49ae12a02367bf3d081aad6",
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


def test_acronis_unformatted_partition() -> None:
    # Imaged sector by sector; its index is the one that needs LZ4 dictionary blocks
    with _open("t1_disk_gpt") as tibx:
        assert _sha256(tibx, 0x19) == "18fdb2a2fbfda6a212c8c82d848835dc863e905a481ad400c0ba0c084d80fce7"


@pytest.mark.parametrize("name", ARCHIVES)
def test_acronis_commit_info(name: str) -> None:
    # The commit info chain finds what a page scan finds, without one
    with _open(name) as tibx:
        store = tibx.store
        assert store.live_root().offset == store._last_ci().arch_offset == store._last_arch().offset

        chained = store._chained_roots()
        assert chained is not None
        assert sorted(root.offset for root in chained) == sorted(root.offset for root in store._scan_commit_roots())


@pytest.mark.parametrize("name", ARCHIVES)
def test_acronis_commit_infos(name: str) -> None:
    # One commit info page per commit, page 2's first, found along the chain as the page scan
    # finds them
    with _open(name) as tibx:
        store = tibx.store
        infos = store.commit_infos()
        assert store._chained_commit_infos(store.live_root()) is not None
        assert [ci.offset for ci in infos] == [ci.offset for ci in store._scan_commit_infos()]
        assert infos[0].offset == FIRST_CI_OFFSET
        assert len(infos) == len(store.commit_roots())
        assert {ci.archive_uuid for ci in infos} == {store.live_root().archive_uuid}


def test_acronis_commit_infos_rewritten_ci0() -> None:
    # Cyber Protect 15 rewrites CI0 after each commit: it describes the newest commit, and
    # is the last commit info written
    with _open("t1_chain_inc") as tibx:
        infos = tibx.store.commit_infos()
        assert [ci.commit_seq for ci in infos] == [5, 1, 2, 3, 4, 5]
        assert [ci.ci_seq for ci in infos] == [10, 1, 3, 5, 7, 9]
        assert infos[0].flags == c_tibx.ArciFlags.REWRITE | c_tibx.ArciFlags.CI0
        assert all(ci.flags == c_tibx.ArciFlags.REWRITE for ci in infos[1:])
        assert infos[0].arch_offset == infos[-1].arch_offset == tibx.store.live_root().offset


def test_acronis_commit_info_split_archive() -> None:
    # CI0 is only in the first file of a split archive, and names the newest commit in the
    # last; the commit info chain runs across both files, in offsets of the whole archive
    with _open("t1_chain_diff") as tibx:
        store = tibx.store
        assert store._ci0().arch_offset == store.live_root().offset == 0xBC000
        chained = store._chained_roots()
        assert [root.offset for root in chained] == [0xBC000, 0xB9000, 0xB6000, 0x79000, 0x76000, 0x3000, 0]

        # Commit info offsets are in the whole archive, volume offsets in the page's own file
        infos = store.commit_infos()
        assert [ci.offset for ci in infos] == [0x2000, 0x5000, 0x78000, 0x7B000, 0xB8000, 0xBB000, 0xBE000]
        assert [ci.volume_offset for ci in infos] == [0x2000, 0x5000, 0x78000, 0x7B000, 0x3C000, 0x3F000, 0x42000]


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
    assert [root.offset for root in store.commit_roots()][-1] == 0xB6000


def test_acronis_commit_info_ci0_after_failed_backup() -> None:
    # Data after the last commit pushes the newest commit out of the last pages, but Cyber
    # Protect keeps CI0 up to date: it names the newest commit, however much data follows it
    fh = CountingIO(_sample("t1_chain_inc", trailing=5000))
    store = PageStore(fh)
    fh.reads = 0

    assert store.live_root().offset == 0xF3000
    assert fh.reads == 3  # CI0, the commit info it names and its header
    assert store._chained_roots() is not None
    assert len(store.commit_roots()) == 6


def test_acronis_commit_info_without_ci0() -> None:
    # True Image 2020 has no CI0, its first commit info page stays the first commit's: the
    # backward scan finds the newest commit, however much data follows it, and the commit
    # info chain the rest
    store = PageStore(io.BytesIO(_sample("ati_2020_disk_lz4_compr", trailing=2 * SCAN_CHUNK_MIN_PAGES)))
    assert store._ci0() is None
    assert store._commit_info_at(FIRST_CI_OFFSET) is not None
    assert store.live_root().offset == 0x53000
    chained = store._chained_roots()
    assert chained is not None
    assert len(chained) == len(store.commit_roots()) == 7


def test_acronis_commit_info_damaged_ci0_and_end() -> None:
    data = _sample("t1_chain_inc", corrupt=(FIRST_CI_OFFSET,), trailing=2 * SCAN_CHUNK_MIN_PAGES)
    store = PageStore(io.BytesIO(data))
    assert store._ci0() is None
    assert store.live_root().offset == 0xF3000
    # Without page 2 the commit info chain has no end, but the page scan finds every root
    assert store._chained_roots() is None
    assert len(store.commit_roots()) == 6
    assert [ci.offset for ci in store.commit_infos()] == [0x5000, 0x79000, 0x7C000, 0xB8000, 0xF6000]


def test_acronis_commit_info_broken_chain_falls_back() -> None:
    # A damaged commit info page halfway down the chain: the page scan still finds every root
    intact = [root.offset for root in PageStore(io.BytesIO(_sample("t1_chain_inc"))).commit_roots()]
    store = PageStore(io.BytesIO(_sample("t1_chain_inc", corrupt=(0x79000,))))
    assert store._chained_roots() is None
    assert [root.offset for root in store.commit_roots()] == intact
    assert store.live_root().offset == 0xF3000


def test_acronis_live_root_without_commit_info() -> None:
    # With every commit info page damaged, the last CRC-valid ARCH header is the live root
    store = PageStore(io.BytesIO(_sample("t1_chain_inc")))
    offsets = tuple(ci.offset for ci in store.commit_infos())
    store = PageStore(io.BytesIO(_sample("t1_chain_inc", corrupt=offsets)))
    assert store._ci0() is None
    assert store._last_ci() is None
    assert store.live_root().offset == 0xF3000


@pytest.mark.parametrize("prev_ci_offset", [0xF6000, 0x79000])
def test_acronis_commit_info_cyclic_chain_falls_back(prev_ci_offset: int) -> None:
    # A commit info page pointing back to the newest one, or at itself -- damaged or crafted,
    # with both CRCs intact: its ci_seq does not count down, so the walk stops rather than
    # loops, and the page scan finds every root
    intact = [root.offset for root in PageStore(io.BytesIO(_sample("t1_chain_inc"))).commit_roots()]
    data = bytearray(_sample("t1_chain_inc"))
    _rewrite_commit_info(data, 0x79000, prev_ci_offset=prev_ci_offset)

    store = PageStore(io.BytesIO(bytes(data)))
    assert store._commit_info_at(0x79000) is not None
    assert store._chained_roots() is None
    assert [root.offset for root in store.commit_roots()] == intact
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
