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

import pytest

from dissect.archive.tibx.c_tibx import c_tibx
from dissect.archive.tibx.exception import InvalidPasswordError
from dissect.archive.tibx.map import load_segment_index
from dissect.archive.tibx.segment import Segment
from dissect.archive.tibx.tibx import TIBX
from tests.conftest import absolute_path

PASSWORD = "dissect"

# Incompressible segments are stored at every compression level
STORED_AND_ZSTD = {c_tibx.ComprAlg.NONE, c_tibx.ComprAlg.ZSTD}
STORED_AND_LZ4 = {c_tibx.ComprAlg.NONE, c_tibx.ComprAlg.LZ4}


def _open(name: str) -> TIBX:
    return TIBX.open(absolute_path(f"_data/acronis/tibx/{name}.tibx"))


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
