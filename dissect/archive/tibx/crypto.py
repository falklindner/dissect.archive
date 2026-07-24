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

# pycryptodome is only needed to actually derive/apply keys, not to *detect* encryption
# (see has_password_wrapped_key), so it is imported where it is used rather than at module
# import time -- the detection path runs on every archive open.
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


def _blob_is_well_formed(blob: bytes, offset: int, *, cbc_only: bool) -> bool:
    """Whether a wrapped-key blob at ``offset`` parses structurally -- no password needed.

    Checks only what the format fixes: a known algorithm id, a plausible PBKDF2 iteration
    exponent, a full salt, and a wrapped key that is a non-empty AES block multiple.

    ``cbc_only`` restricts this to algorithms we can actually unwrap; the detection path
    passes ``False`` so a GCM archive is still reported as *encrypted* (it is), and fails
    later with a clear "not supported" rather than being mistaken for plaintext.
    """
    alg = blob[offset + 1]
    iter_log2 = blob[offset + 2]
    known = CBC_KEY_LENGTH if cbc_only else {**CBC_KEY_LENGTH, **dict.fromkeys(GCM_ALG_IDS, 0)}
    if alg not in known or not MIN_ITER_LOG2 <= iter_log2 <= MAX_ITER_LOG2:
        return False
    salt = blob[offset + 4 : offset + 4 + SALT_SIZE]
    wrapped = blob[offset + 4 + SALT_SIZE :]
    return len(salt) == SALT_SIZE and len(wrapped) >= 16 and not len(wrapped) % 16


def _keymap_blob(header: ArchiveHeader) -> bytes | None:
    """The decompressed keymap (TLV[7]) mem-tree region, or ``None`` if there is no keymap.

    Raises:
        InvalidPasswordError: If the region is implausibly large for a keymap.
    """
    keymap = header.tree(TLV_KEYMAP)
    if keymap is None:
        return None

    blob = keymap.memtree_payload
    if keymap.memtree_encoding & 0x7F == 1 and len(blob) >= 8:
        uncompressed = struct.unpack_from(">I", blob, 4)[0]
        blob = decompress_linked_lz4(blob, min(uncompressed + 64, MAX_KEYMAP_BLOB), strict=False)
    if len(blob) > MAX_KEYMAP_BLOB:
        raise InvalidPasswordError("keymap blob implausibly large")
    return blob


def has_password_wrapped_key(header: ArchiveHeader) -> bool:
    """Whether the keymap carries a password-wrapped data key -- i.e. reading data segments
    needs a password.

    Locate-only: scans the keymap region for an offset where a wrapped-key blob parses
    structurally. No password is involved and no key is derived, so this is cheap enough to
    run on every open. It is strictly more precise than "a keymap tree exists": an archive
    whose keymap holds no password-wrapped key (a public-key-wrapped one, say) is correctly
    reported as not password-protected instead of prompting for a password that cannot work.

    Detection must never stop an unusual-but-valid archive from opening, so any failure
    answers ``False`` -- a missed detection still surfaces later as an explicit
    :class:`InvalidPasswordError` from the segment reader, not a silent misread.
    """
    try:
        blob = _keymap_blob(header)
        if not blob:
            return False
        return any(
            blob[offset] == FORMAT_PASSWORD and _blob_is_well_formed(blob, offset, cbc_only=False)
            for offset in range(len(blob) - (4 + SALT_SIZE))
        )
    except Exception:
        return False


def _try_unwrap(blob: bytes, offset: int, password: bytes) -> DataKey | None:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import PBKDF2

    alg = blob[offset + 1]
    iter_log2 = blob[offset + 2]
    if alg in GCM_ALG_IDS:
        raise UnsupportedFormatError("AES-GCM encrypted TIBX archives are not supported")
    if not _blob_is_well_formed(blob, offset, cbc_only=True):
        return None
    salt = blob[offset + 4 : offset + 4 + SALT_SIZE]
    wrapped = blob[offset + 4 + SALT_SIZE :]
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

    blob = _keymap_blob(header)
    if blob is None:
        raise InvalidPasswordError("archive has no keymap tree")

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
    from Crypto.Cipher import AES

    if len(payload) < 32:
        raise InvalidPasswordError(f"encrypted segment payload too short: {len(payload)} bytes")
    iv = payload[:16]
    ciphertext = payload[16:]
    ciphertext = ciphertext[: len(ciphertext) // 16 * 16]
    return AES.new(data_key.key, AES.MODE_CBC, iv).decrypt(ciphertext)
