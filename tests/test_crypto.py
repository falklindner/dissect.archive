from __future__ import annotations

import io
from typing import TYPE_CHECKING

import pytest

from dissect.archive.tibx.crypto import DataKey, decrypt_segment, unwrap_data_key
from dissect.archive.tibx.exceptions import InvalidPasswordError, UnsupportedFormatError
from dissect.archive.tibx.lsm import read_archive_header
from dissect.archive.tibx.page import PageStore
from dissect.archive.tibx.tibx import TIBX
from tests._synth import COMP_NONE, ExtentSpec, build_lsm_archive

if TYPE_CHECKING:
    from dissect.archive.tibx.lsm import ArchiveHeader

PASSWORD = b"dissect"
DATA_KEY = bytes(range(32))


def _header(archive: bytes) -> ArchiveHeader:
    store = PageStore(io.BytesIO(archive))
    return read_archive_header(store)


def test_unwrap_data_key_roundtrip() -> None:
    archive = build_lsm_archive([ExtentSpec(10, 0, b"encrypted content" * 100)], password=PASSWORD)
    key = unwrap_data_key(_header(archive), PASSWORD)
    assert isinstance(key, DataKey)
    assert key.alg == 3
    assert key.key == DATA_KEY


def test_unwrap_accepts_str_password() -> None:
    archive = build_lsm_archive([ExtentSpec(10, 0, b"x" * 64)], password=PASSWORD)
    assert unwrap_data_key(_header(archive), "dissect").key == DATA_KEY


def test_unwrap_wrong_password() -> None:
    archive = build_lsm_archive([ExtentSpec(10, 0, b"x" * 64)], password=PASSWORD)
    with pytest.raises(InvalidPasswordError):
        unwrap_data_key(_header(archive), b"wrong")


def test_unwrap_no_keymap() -> None:
    archive = build_lsm_archive([ExtentSpec(10, 0, b"x" * 64)])  # not encrypted
    with pytest.raises(InvalidPasswordError, match="no keymap"):
        unwrap_data_key(_header(archive), PASSWORD)


def test_gcm_alg_rejected() -> None:
    # Rebuild the keymap tree of an encrypted archive with the alg byte flipped to a
    # GCM id (5), then confirm unwrap refuses it
    from tests._synth import Cell, arch_header_page, lsb

    base = build_lsm_archive([ExtentSpec(10, 0, b"x" * 64)], password=PASSWORD)
    header = _header(base)
    blob = bytearray(header.tree(7).memtree_payload)
    idx = blob.index(bytes([0x01, 0x03]))
    blob[idx + 1] = 5  # AES_128_GCM

    keymap = lsb(0, 0, memtree_cells=[Cell(b"", b"")], memtree_blob=bytes(blob), memtree_encoding=0)
    slots = {i: header.tlv[i].payload for i in (1, 2)}
    slots[7] = keymap
    archive = arch_header_page(slots) + base[0x1000:]
    with pytest.raises(UnsupportedFormatError, match="GCM"):
        unwrap_data_key(_header(archive), PASSWORD)


def test_decrypt_segment_padding_stripped_by_caller() -> None:
    from Crypto.Cipher import AES

    plaintext = b"the quick brown fox" * 4
    padded = plaintext + bytes([16 - len(plaintext) % 16]) * (16 - len(plaintext) % 16)
    iv = bytes(range(16))
    payload = iv + AES.new(DATA_KEY, AES.MODE_CBC, iv).encrypt(padded)
    out = decrypt_segment(payload, DataKey(alg=3, key=DATA_KEY))
    assert out.startswith(plaintext)


@pytest.mark.parametrize("compression", [0x0300, COMP_NONE], ids=["zstd", "stored"])
def test_encrypted_archive_end_to_end(compression: int) -> None:
    content = b"secret volume payload, needs a password" * 200
    archive = build_lsm_archive([ExtentSpec(10, 0, content)], compression=compression, password=PASSWORD)
    tibx = TIBX(io.BytesIO(archive))
    assert tibx.encrypted

    volume = tibx.volumes()[0]
    with pytest.raises(InvalidPasswordError):
        volume.read(0, len(content))  # locked

    tibx.unlock(PASSWORD)
    assert volume.read(0, len(content)) == content
