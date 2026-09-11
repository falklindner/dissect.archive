"""Encrypted-archive support: recover the data key from a password, decrypt segments.

The LSM index is always plaintext; only data segments are encrypted (page tag ``SE``).
The data key is wrapped with a password-derived key-encryption key (KEK) and stored in
the keymap tree (TLV[7]) superblock mem-tree, as a :class:`c_tibx.wrapped_key` header
followed by the PKCS#7-padded key itself::

    KEK      = PBKDF2-HMAC-SHA256(password, salt, 1 << iter_log2, 32 bytes)
    data key = PKCS#7-unpad(AES-256-CBC-decrypt(wrapped, KEK, IV=0))

The blob sits at an offset inside the (linked-LZ4) keymap mem-tree; its exact framing is
opaque, so we scan for a candidate format byte that unwraps to a valid AES key -- verified
against real Acronis Cyber Protect / True Image 2026 output.

``alg`` selects the cipher for the *data segments* only -- the data key itself is always
CBC-wrapped as above, whichever variant the segments use. Each ``SE`` payload opens with
the prefix that variant calls for, a :class:`c_tibx.segment_cbc_header` or a
:class:`c_tibx.segment_gcm_header`, and the ciphertext follows it. CBC pads the ciphertext
to a block boundary; GCM leaves it exactly as long as the plaintext, so a GCM segment's
``zlength`` is its ``length`` plus that prefix.

Either way the plaintext is a zstd frame (or stored bytes when the segment's compression
is NONE).

Ported from the MIT-licensed ``acronis-tib-reader`` and ``acronis-tibx``. See
``THIRD_PARTY_NOTICES.md``.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, NamedTuple

# pycryptodome is only needed to actually derive/apply keys, not to *detect* encryption
# (see has_password_wrapped_key), so it is imported where it is used rather than at module
# import time -- the detection path runs on every archive open.
from dissect.archive.tibx.c_tibx import (
    SEGMENT_CBC_HEADER_SIZE,
    SEGMENT_GCM_HEADER_SIZE,
    TLV_KEYMAP,
    WRAPPED_KEY_FORMAT_PASSWORD,
    WRAPPED_KEY_FORMAT_PUBKEY,
    WRAPPED_KEY_HEADER_SIZE,
    c_tibx,
)
from dissect.archive.tibx.codec import decompress_linked_lz4
from dissect.archive.tibx.exception import CorruptArchiveError, InvalidPasswordError

if TYPE_CHECKING:
    from dissect.archive.tibx.lsm import ArchiveHeader

# alg id -> AES key length in bytes, per segment cipher. GOST2015 (4) stays unsupported.
CBC_KEY_LENGTH = {1: 16, 2: 24, 3: 32}
GCM_KEY_LENGTH = {5: 16, 6: 24, 7: 32}
KEY_LENGTH = {**CBC_KEY_LENGTH, **GCM_KEY_LENGTH}

MIN_ITER_LOG2 = 10
MAX_ITER_LOG2 = 24
# Bound the keymap scan: the mem-tree is tiny in practice
MAX_KEYMAP_BLOB = 1 << 20


class DataKey(NamedTuple):
    """A recovered plaintext data key."""

    alg: int
    key: bytes

    @property
    def gcm(self) -> bool:
        """Whether segments are AES-GCM.

        GCM plaintext is exactly as long as the ciphertext, where CBC leaves PKCS#7 padding
        for the caller to strip -- so this also says whether a segment's decrypted bytes may
        be truncated to the declared length as they are, or need unpadding first.
        """
        return self.alg in GCM_KEY_LENGTH


def _pkcs7_unpad(data: bytes) -> bytes | None:
    if not data or len(data) % 16:
        return None
    pad = data[-1]
    if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return None


def _scan_offsets(blob: bytes) -> range:
    """The offsets in ``blob`` at which a complete wrapped key could still begin.

    The blob's framing inside the keymap mem-tree is opaque, so the key is found by
    scanning; anything closer to the end than a header plus one AES block cannot be one.
    """
    return range(len(blob) - (WRAPPED_KEY_HEADER_SIZE + 16))


def _parse_wrapped_key(blob: bytes, offset: int) -> tuple[c_tibx.wrapped_key, bytes] | None:
    """Parse the wrapped-key header at ``offset`` and the padded key that follows it.

    Returns ``None`` if there are not enough bytes left for a complete header plus at
    least one AES block of wrapped key.
    """
    if len(blob) - offset < WRAPPED_KEY_HEADER_SIZE + 16:
        return None
    return c_tibx.wrapped_key(blob[offset:]), blob[offset + WRAPPED_KEY_HEADER_SIZE :]


def _blob_is_well_formed(blob: bytes, offset: int) -> bool:
    """Whether a wrapped-key blob at ``offset`` parses structurally -- no password needed.

    Checks only what the format fixes: a known algorithm id, a plausible PBKDF2 iteration
    exponent, and a wrapped key that is a non-empty AES block multiple. The salt is fixed
    width, so parsing the header at all already proves it is complete.
    """
    parsed = _parse_wrapped_key(blob, offset)
    if parsed is None:
        return False
    header, wrapped = parsed
    if header.alg not in KEY_LENGTH or not MIN_ITER_LOG2 <= header.iter_log2 <= MAX_ITER_LOG2:
        return False
    return not len(wrapped) % 16


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
    return _has_wrapped_key(header, WRAPPED_KEY_FORMAT_PASSWORD)


def has_certificate_wrapped_key(header: ArchiveHeader) -> bool:
    """Whether the keymap carries a certificate-wrapped data key.

    Acronis can wrap the data key to a certificate instead of a password. Such an archive
    is genuinely encrypted, but no password can open it -- telling the two apart is what
    lets :meth:`TIBX.unlock` fail with something better than "wrong password".
    """
    return _has_wrapped_key(header, WRAPPED_KEY_FORMAT_PUBKEY)


def _has_wrapped_key(header: ArchiveHeader, wrap_format: int) -> bool:
    """Whether the keymap holds a structurally valid wrapped key of ``wrap_format``."""
    try:
        blob = _keymap_blob(header)
        if not blob:
            return False
        return any(blob[offset] == wrap_format and _blob_is_well_formed(blob, offset) for offset in _scan_offsets(blob))
    except Exception:
        return False


def _try_unwrap(blob: bytes, offset: int, password: bytes) -> DataKey | None:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import PBKDF2

    parsed = _parse_wrapped_key(blob, offset)
    if parsed is None:
        return None
    header, wrapped = parsed

    if not _blob_is_well_formed(blob, offset):
        return None

    kek = PBKDF2(password, header.salt, dkLen=32, count=1 << header.iter_log2, hmac_hash_module=SHA256)
    key = _pkcs7_unpad(AES.new(kek, AES.MODE_CBC, b"\x00" * 16).decrypt(wrapped))
    if key is None or len(key) != KEY_LENGTH[header.alg]:
        return None
    return DataKey(alg=header.alg, key=key)


def unwrap_data_key(header: ArchiveHeader, password: str | bytes) -> DataKey:
    """Recover the archive's data key from ``password`` via the keymap tree.

    Raises:
        InvalidPasswordError: If no wrapped key unwraps with this password.
    """
    if isinstance(password, str):
        password = password.encode("utf-8")

    blob = _keymap_blob(header)
    if blob is None:
        raise InvalidPasswordError("archive has no keymap tree")

    for offset in _scan_offsets(blob):
        if blob[offset] != WRAPPED_KEY_FORMAT_PASSWORD:
            continue
        data_key = _try_unwrap(blob, offset, password)
        if data_key is not None:
            return data_key
    raise InvalidPasswordError("wrong password, or no password-wrapped key in the keymap")


def decrypt_segment(payload: bytes, data_key: DataKey) -> bytes:
    """Decrypt an ``SE`` segment payload to its stored bytes.

    Returns the still-compressed (or stored) plaintext; the caller decompresses per the
    segment's compression field. For CBC the padding is left intact -- the caller truncates
    to the segment's declared length; GCM plaintext is already exact.

    Raises:
        CorruptArchiveError: If the payload is too short for its framing, or a GCM tag does
            not authenticate.
    """
    from Crypto.Cipher import AES

    if data_key.gcm:
        if len(payload) < SEGMENT_GCM_HEADER_SIZE:
            raise CorruptArchiveError(f"encrypted segment payload too short: {len(payload)} bytes")
        header = c_tibx.segment_gcm_header(payload)
        try:
            return AES.new(data_key.key, AES.MODE_GCM, nonce=header.iv).decrypt_and_verify(
                payload[SEGMENT_GCM_HEADER_SIZE:], header.tag
            )
        except ValueError as e:
            # The data key is confirmed by its PKCS#7 unwrap, so a failing tag is damage
            # to the archive rather than a wrong password.
            raise CorruptArchiveError(f"segment failed AES-GCM authentication: {e}")

    if len(payload) < SEGMENT_CBC_HEADER_SIZE + 16:
        raise CorruptArchiveError(f"encrypted segment payload too short: {len(payload)} bytes")
    ciphertext = payload[SEGMENT_CBC_HEADER_SIZE:]
    ciphertext = ciphertext[: len(ciphertext) // 16 * 16]
    return AES.new(data_key.key, AES.MODE_CBC, c_tibx.segment_cbc_header(payload).iv).decrypt(ciphertext)
