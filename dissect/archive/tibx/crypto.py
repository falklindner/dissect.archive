"""Encrypted-archive support: recover the data key from a password, decrypt segments.

The LSM index is always plaintext; only data segments are encrypted (page tag ``SE``).
The data key is wrapped with a password-derived key-encryption key (KEK) and stored in
the keymap tree (TLV[7]) superblock mem-tree. A wrapped-key blob is:

    [format=0x01][alg][iter_log2][reserved][salt||16][wrapped key, PKCS#7-padded||16n]

    KEK      = PBKDF2-HMAC-SHA256(password, salt, 1 << iter_log2, 32 bytes)
    data key = PKCS#7-unpad(AES-256-CBC-decrypt(wrapped, KEK, IV=0))

The blob sits at an offset inside the (linked-LZ4) keymap mem-tree; its exact framing is
opaque, so we scan for a candidate format byte that unwraps to a valid AES key -- verified
against real Acronis Cyber Protect / True Image 2026 output.

Each ``SE`` segment payload is ``IV||16 || AES-256-CBC ciphertext``; the plaintext is a
zstd frame (or stored bytes when the segment's compression is NONE).
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, NamedTuple

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

from dissect.archive.tibx.c_tibx import TLV_KEYMAP
from dissect.archive.tibx.codecs import decompress_linked_lz4
from dissect.archive.tibx.exceptions import InvalidPasswordError, UnsupportedFormatError

if TYPE_CHECKING:
    from dissect.archive.tibx.lsm import ArchiveHeader

FORMAT_PASSWORD = 0x01
FORMAT_PUBKEY = 0x02

# alg id -> AES key length in bytes (CBC variants); GCM variants are unsupported
CBC_KEY_LENGTH = {1: 16, 2: 24, 3: 32}
GCM_ALG_IDS = {5, 6, 7}

MIN_ITER_LOG2 = 10
MAX_ITER_LOG2 = 24
SALT_SIZE = 16
# Bound the keymap scan: the mem-tree is tiny in practice
MAX_KEYMAP_BLOB = 1 << 20


class DataKey(NamedTuple):
    """A recovered plaintext data key."""

    alg: int
    key: bytes


def _pkcs7_unpad(data: bytes) -> bytes | None:
    if not data or len(data) % 16:
        return None
    pad = data[-1]
    if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return None


def _try_unwrap(blob: bytes, offset: int, password: bytes) -> DataKey | None:
    alg = blob[offset + 1]
    iter_log2 = blob[offset + 2]
    if alg in GCM_ALG_IDS:
        raise UnsupportedFormatError("AES-GCM encrypted TIBX archives are not supported")
    if alg not in CBC_KEY_LENGTH or not MIN_ITER_LOG2 <= iter_log2 <= MAX_ITER_LOG2:
        return None
    salt = blob[offset + 4 : offset + 4 + SALT_SIZE]
    wrapped = blob[offset + 4 + SALT_SIZE :]
    if len(salt) != SALT_SIZE or len(wrapped) < 16 or len(wrapped) % 16:
        return None
    kek = PBKDF2(password, salt, dkLen=32, count=1 << iter_log2, hmac_hash_module=SHA256)
    key = _pkcs7_unpad(AES.new(kek, AES.MODE_CBC, b"\x00" * 16).decrypt(wrapped))
    if key is None or len(key) != CBC_KEY_LENGTH[alg]:
        return None
    return DataKey(alg=alg, key=key)


def unwrap_data_key(header: ArchiveHeader, password: str | bytes) -> DataKey:
    """Recover the archive's data key from ``password`` via the keymap tree.

    Raises:
        InvalidPasswordError: If no wrapped key unwraps with this password.
        UnsupportedFormatError: If the archive uses AES-GCM (write-side only).
    """
    if isinstance(password, str):
        password = password.encode("utf-8")

    keymap = header.tree(TLV_KEYMAP)
    if keymap is None:
        raise InvalidPasswordError("archive has no keymap tree")

    blob = keymap.memtree_payload
    if keymap.memtree_encoding & 0x7F == 1 and len(blob) >= 8:
        uncompressed = struct.unpack_from(">I", blob, 4)[0]
        blob = decompress_linked_lz4(blob, min(uncompressed + 64, MAX_KEYMAP_BLOB), strict=False)
    if len(blob) > MAX_KEYMAP_BLOB:
        raise InvalidPasswordError("keymap blob implausibly large")

    for offset in range(len(blob) - (4 + SALT_SIZE)):
        if blob[offset] != FORMAT_PASSWORD:
            continue
        data_key = _try_unwrap(blob, offset, password)
        if data_key is not None:
            return data_key
    raise InvalidPasswordError("wrong password, or no password-wrapped key in the keymap")


def decrypt_segment(payload: bytes, data_key: DataKey) -> bytes:
    """Decrypt an ``SE`` segment payload (``IV||16 || ciphertext``) to its stored bytes.

    Returns the still-compressed (or stored) plaintext; the caller decompresses per the
    segment's compression field. CBC padding is left intact -- the caller truncates to the
    segment's declared length.
    """
    if len(payload) < 32:
        raise InvalidPasswordError(f"encrypted segment payload too short: {len(payload)} bytes")
    iv = payload[:16]
    ciphertext = payload[16:]
    ciphertext = ciphertext[: len(ciphertext) // 16 * 16]
    return AES.new(data_key.key, AES.MODE_CBC, iv).decrypt(ciphertext)
