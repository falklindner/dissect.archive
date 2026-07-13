"""CRC-32C (Castagnoli) for TIBX page verification.

Every 4 KiB TIBX page stores a CRC-32C of itself big-endian at offset ``0x04``, computed
with the four checksum bytes zeroed.

The table implementation is ported from the MIT-licensed ``acronis-tib-reader`` project
(see THIRD_PARTY_NOTICES.md).
"""

from __future__ import annotations

_POLY_REFLECTED = 0x82F63B78


def _make_table() -> tuple[int, ...]:
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ (_POLY_REFLECTED if crc & 1 else 0)
        table.append(crc & 0xFFFFFFFF)
    return tuple(table)


_TABLE = _make_table()


def crc32c(data: bytes) -> int:
    """Return the unsigned 32-bit CRC-32C of ``data``."""
    crc = 0xFFFFFFFF
    table = _TABLE
    for byte in data:
        crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
    return crc ^ 0xFFFFFFFF


def page_crc32c(page: bytes) -> int:
    """Return the CRC-32C of a page with the four checksum bytes at ``[4:8]`` zeroed."""
    return crc32c(page[:4] + b"\x00\x00\x00\x00" + page[8:])
