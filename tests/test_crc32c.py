from __future__ import annotations

from dissect.archive.tibx.crc32c import crc32c, page_crc32c


def test_known_answer_vectors() -> None:
    # Standard CRC-32C check values (RFC 3720 appendix B.4 / Castagnoli)
    assert crc32c(b"") == 0
    assert crc32c(b"123456789") == 0xE3069283
    assert crc32c(b"\x00" * 32) == 0x8A9136AA
    assert crc32c(b"\xff" * 32) == 0x62A8AB43


def test_page_crc_ignores_checksum_field() -> None:
    page = bytearray(0x1000)
    page[0], page[1] = 0x41, 0x01
    page[8:12] = b"ARCH"
    base = page_crc32c(bytes(page))

    # Whatever is stored in the CRC field must not affect the page CRC itself
    page[4:8] = b"\xde\xad\xbe\xef"
    assert page_crc32c(bytes(page)) == base

    # But any body change must
    page[0x80] ^= 0xFF
    assert page_crc32c(bytes(page)) != base
