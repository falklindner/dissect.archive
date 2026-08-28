"""Data segments: the unit of bulk storage in a TIBX archive.

A segment is a 0x2C-byte header (``SG`` plaintext / ``SE`` encrypted, at page offset
+0x08) followed by the compressed payload. Payloads larger than the segment's first
page (4052 bytes) spill onto continuation DATA pages, each contributing its 4088-byte
body.

Ported from the MIT-licensed ``acronis-tib-reader``, with the ``comp=0x0001`` variant
from ``acronis-tibx``. See ``THIRD_PARTY_NOTICES.md``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.archive.tibx.c_tibx import (
    COMP_LZ4,
    COMP_NONE,
    COMP_STORED_VARIANTS,
    COMP_ZSTD,
    ENVELOPE_SIZE,
    PAGE_BODY_SIZE,
    SEGMENT_FIRST_PAGE_PAYLOAD,
    SEGMENT_HEADER_OFFSET,
    SEGMENT_MAGIC,
    SEGMENT_MAGIC_ENCRYPTED,
    SEGMENT_PAYLOAD_OFFSET,
    c_tibx,
)
from dissect.archive.tibx.codec import decompress_zstd, lz4_block_decompress
from dissect.archive.tibx.exception import (
    CorruptArchiveError,
    InvalidPasswordError,
    UnsupportedFormatError,
)

if TYPE_CHECKING:
    from dissect.archive.tibx.crypto import DataKey
    from dissect.archive.tibx.page import PageStore


class Segment:
    """One parsed segment header at ``page_index``."""

    def __init__(self, page: bytes, page_index: int):
        if page[1] != c_tibx.PageType.DATA:
            raise CorruptArchiveError(f"page {page_index} is not a DATA page")
        magic = page[SEGMENT_HEADER_OFFSET : SEGMENT_HEADER_OFFSET + 2]
        if magic not in (SEGMENT_MAGIC, SEGMENT_MAGIC_ENCRYPTED):
            raise CorruptArchiveError(f"page {page_index} carries no segment header")
        self.page_index = page_index
        self.page = page  # retained so read_compressed need not re-read the header page
        self.header = c_tibx.segment_header(page[SEGMENT_HEADER_OFFSET:])
        self.encrypted = magic == SEGMENT_MAGIC_ENCRYPTED
        self.length = self.header.length
        self.zlength = self.header.zlength
        self.key_id = self.header.key_id
        self.compression = self.header.compression

    def __repr__(self) -> str:
        return (
            f"<Segment page={self.page_index} length={self.length} zlength={self.zlength} "
            f"compression={self.compression:#06x}{' encrypted' if self.encrypted else ''}>"
        )


def _pkcs7_unpad(data: bytes) -> bytes:
    """Strip PKCS#7 padding if present, else return the data unchanged."""
    if data and len(data) % 16 == 0:
        pad = data[-1]
        if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
            return data[:-pad]
    return data


def read_compressed(store: PageStore, segment: Segment) -> bytes:
    """Read exactly ``segment.zlength`` still-compressed bytes.

    Walks the segment's page plus as many continuation DATA pages as needed, stripping
    each page's 8-byte envelope. The physically-contiguous continuation pages are read in
    a single batched I/O (one ``read`` instead of one per page), which matters most over a
    network share.
    """
    remaining = segment.zlength
    first_take = min(SEGMENT_FIRST_PAGE_PAYLOAD, remaining)
    parts = [segment.page[SEGMENT_PAYLOAD_OFFSET : SEGMENT_PAYLOAD_OFFSET + first_take]]
    remaining -= first_take

    if remaining > 0:
        cont_count = (remaining + PAGE_BODY_SIZE - 1) // PAGE_BODY_SIZE
        start = segment.page_index + 1
        if start + cont_count > store.page_count:
            raise CorruptArchiveError(f"segment at page {segment.page_index} runs off the end of the archive")
        for offset, page in enumerate(store.read_run(start, cont_count)):
            if page[1] != c_tibx.PageType.DATA:
                raise CorruptArchiveError(
                    f"unexpected non-data page {start + offset} inside segment at page {segment.page_index}"
                )
            # The segment's byte length is authoritative for where it ends; we deliberately
            # do not treat an SG/SE magic on a continuation page as a new segment, because
            # compressed and encrypted payload bytes can coincidentally match that magic.
            body = page[ENVELOPE_SIZE:]
            take = min(len(body), remaining)
            parts.append(body[:take])
            remaining -= take

    return b"".join(parts)


def decompress(raw: bytes, segment: Segment) -> bytes:
    """Decompress a segment's raw payload to exactly ``segment.length`` plaintext bytes."""
    if segment.compression == COMP_NONE:
        if len(raw) != segment.length:
            raise CorruptArchiveError(
                f"stored segment at page {segment.page_index} has zlength {len(raw)} != length {segment.length}"
            )
        return raw

    if segment.compression == COMP_LZ4 or segment.compression in COMP_STORED_VARIANTS:
        # Stored verbatim when there was no compression gain; the metadata variants
        # have only ever been observed stored
        if segment.zlength == segment.length:
            return raw
        if segment.compression in COMP_STORED_VARIANTS:
            raise UnsupportedFormatError(
                f"segment at page {segment.page_index} uses compression variant "
                f"{segment.compression:#06x} in compressed form, which has not been observed before"
            )
        out = lz4_block_decompress(raw, segment.length)
        if len(out) != segment.length:
            raise CorruptArchiveError(
                f"LZ4 segment at page {segment.page_index} decoded {len(out)} bytes, expected {segment.length}"
            )
        return out

    if segment.compression not in COMP_ZSTD:
        raise UnsupportedFormatError(
            f"segment at page {segment.page_index} uses unknown compression {segment.compression:#06x}"
        )

    out = decompress_zstd(raw, segment.length)
    if len(out) != segment.length:
        raise CorruptArchiveError(
            f"zstd segment at page {segment.page_index} decoded {len(out)} bytes, expected {segment.length}"
        )
    return out


def read_plaintext(store: PageStore, page_index: int, data_key: DataKey | None = None) -> bytes:
    """Read and decompress the segment whose header is at ``page_index``.

    Encrypted (``SE``) segments are decrypted with ``data_key`` before decompression.

    Raises:
        InvalidPasswordError: If the segment is encrypted but no data key was provided.
    """
    segment = Segment(store.page(page_index), page_index)
    if segment.encrypted or segment.key_id != 0:
        if data_key is None:
            raise InvalidPasswordError(f"segment at page {page_index} is encrypted and no data key is available")
        from dissect.archive.tibx.crypto import decrypt_segment

        plaintext = decrypt_segment(read_compressed(store, segment), data_key)
        if segment.compression in COMP_ZSTD:
            # zstd frame parsing ignores the trailing CBC/PKCS#7 padding
            return decompress_zstd(plaintext, segment.length)
        # Stored or LZ4: recover the exact payload length by removing PKCS#7 padding
        payload = _pkcs7_unpad(plaintext)
        if segment.compression == COMP_LZ4 and len(payload) != segment.length:
            return lz4_block_decompress(payload, segment.length)
        if segment.compression in (COMP_NONE, COMP_LZ4) or segment.compression in COMP_STORED_VARIANTS:
            return payload[: segment.length]
        raise UnsupportedFormatError(
            f"encrypted segment at page {page_index} uses compression {segment.compression:#06x}"
        )
    return decompress(read_compressed(store, segment), segment)
