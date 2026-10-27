"""TIBX archives written by Acronis Cyber Protect 15 (build 37414).

Identity-scrubbed: host, account and SID values are replaced by same-length placeholders.
The expected backup GUIDs are the ones ``acrocmd list backups`` prints for each archive.
"""

from __future__ import annotations

import hashlib

import pytest

from dissect.archive.tibx.exception import InvalidPasswordError
from dissect.archive.tibx.tibx import TIBX
from tests.conftest import absolute_path

PASSWORD = "dissect"


def _open(name: str) -> TIBX:
    return TIBX.open(absolute_path(f"_data/acronis/tibx/{name}.tibx"))


def _sha256(tibx: TIBX, volume_id: int) -> str:
    volume = next(volume for volume in tibx.volumes() if volume.volume_id == volume_id)
    return hashlib.sha256(volume.open().read()).hexdigest()


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
    ],
)
def test_acronis_archive(name: str, backups: list[str], volumes: int) -> None:
    with _open(name) as tibx:
        assert tibx.store.verify()["bad"] == 0
        assert [str(point.guid)[:8] for point in tibx.recovery_points()] == backups
        # Listing must not need the password, only reading does
        assert len(tibx.volumes()) == volumes


@pytest.mark.parametrize(
    ("name", "digest"),
    [
        ("t1_simple_ntfs", "16c90fb48eedab726037df2cfc59d0d1b8140cf320e3fac57b33087848781676"),
        ("t1_stored", "aa55f3a300f8f687d3023d4df03b4c84264f55df7c1519b8bffdd166aa74cb68"),
    ],
)
def test_acronis_volume_content(name: str, digest: str) -> None:
    with _open(name) as tibx:
        assert _sha256(tibx, 0x4) == digest


def test_acronis_encrypted() -> None:
    with _open("t1_enc_aes") as tibx:
        assert tibx.encrypted
        assert tibx.password_protected
        with pytest.raises(InvalidPasswordError):
            tibx.unlock("wrong")

        tibx.unlock(PASSWORD)
        assert _sha256(tibx, 0x4) == "4d71863bceccc3b8b3d8ce0d3bdf1926b479775926c588f014f3b51c45de0320"


def test_acronis_recovery_points() -> None:
    expected = [
        "76cb61ecc47f9ced80d80270b2e32bf457ebf69bbd0a7b671890ea3e13e01596",
        "4d8189da83582ac549918ba85131c51d5bd4543f5b739a8b984d4369a904591e",
        "2c388dfbc8d3446f5d7f36bb7d62a46234a0ceb49aad99defbe202822bc34e07",
    ]
    with _open("t1_chain_inc") as tibx:
        for index, digest in enumerate(expected):
            tibx.use_recovery_point(index)
            assert _sha256(tibx, 0x4) == digest

        tibx.use_recovery_point("latest")
        assert _sha256(tibx, 0x4) == expected[-1]


def test_acronis_unformatted_partition() -> None:
    # Imaged sector by sector; its index is the one that needs LZ4 dictionary blocks
    with _open("t1_disk_gpt") as tibx:
        assert _sha256(tibx, 0x19) == "18fdb2a2fbfda6a212c8c82d848835dc863e905a481ad400c0ba0c084d80fce7"
