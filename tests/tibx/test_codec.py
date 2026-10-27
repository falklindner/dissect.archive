from __future__ import annotations

import struct
import sys

import pytest

from dissect.archive.tibx import codec
from dissect.archive.tibx.c_tibx import LZ4_BLOCK_HEADER_SIZE, c_tibx
from dissect.archive.tibx.codec import (
    decompress_cell_stream,
    decompress_linked_lz4,
    decompress_zstd,
    lz4_block_decompress,
)
from dissect.archive.tibx.exception import CorruptArchiveError

if sys.version_info >= (3, 14):
    from compression import zstd  # novermin
else:
    from backports import zstd

PLAIN = b"The data_map maps (volume_id, offset) to segments. " * 40
DICTIONARY = PLAIN[:51]


def _lz4_length(length: int) -> tuple[int, bytes]:
    """Split an LZ4 length into its token nibble and extension bytes."""
    if length < 15:
        return length, b""
    length -= 15
    return 15, b"\xff" * (length // 255) + bytes([length % 255])


def _lz4_block(*sequences: tuple[bytes, int, int], tail: bytes) -> bytes:
    """Encode a raw LZ4 block from ``(literals, offset, match_len)`` sequences and the trailing literals."""
    block = bytearray()
    for literals, offset, match_len in sequences:
        literal_nibble, literal_extra = _lz4_length(len(literals))
        match_nibble, match_extra = _lz4_length(match_len - 4)
        block += bytes([literal_nibble << 4 | match_nibble]) + literal_extra + literals
        block += struct.pack("<H", offset) + match_extra
    literal_nibble, literal_extra = _lz4_length(len(tail))
    block += bytes([literal_nibble << 4]) + literal_extra + tail
    return bytes(block)


# Starts with literals, then copies DICTIONARY[4:40] from 54 bytes back: 7 into the output and 47 into the dictionary
DICTIONARY_BLOCK = _lz4_block((b"Index: ", 54, 36), tail=b" -- end.")
DICTIONARY_BLOCK_OUTPUT = b"Index: " + DICTIONARY[4:40] + b" -- end."


def test_zstd_roundtrip_with_trailing_padding() -> None:
    frame = zstd.compress(PLAIN)
    assert decompress_zstd(frame + b"\x00" * 100, len(PLAIN)) == PLAIN


def test_zstd_bound_enforced() -> None:
    frame = zstd.compress(PLAIN)
    with pytest.raises(CorruptArchiveError):
        decompress_zstd(frame, len(PLAIN) - 1)


def test_zstd_garbage_rejected() -> None:
    with pytest.raises(CorruptArchiveError):
        decompress_zstd(b"\x00" * 64, 1024)


def test_lz4_block_with_dictionary() -> None:
    assert lz4_block_decompress(DICTIONARY_BLOCK, len(DICTIONARY_BLOCK_OUTPUT), DICTIONARY) == DICTIONARY_BLOCK_OUTPUT


def test_lz4_block_without_its_dictionary() -> None:
    # dissect.util's two backends raise different types; both must surface as ours
    with pytest.raises(CorruptArchiveError):
        lz4_block_decompress(DICTIONARY_BLOCK, len(DICTIONARY_BLOCK_OUTPUT))


def test_lz4_block_bound_enforced() -> None:
    block = _lz4_block(tail=PLAIN[:100])
    assert lz4_block_decompress(block, 100) == PLAIN[:100]
    with pytest.raises(CorruptArchiveError):
        lz4_block_decompress(block, 99)
    with pytest.raises(CorruptArchiveError):
        lz4_block_decompress(block, 0)


def test_lz4_block_garbage_rejected() -> None:
    with pytest.raises(CorruptArchiveError):
        lz4_block_decompress(b"\xff" * 64, 4096)


def _linked_chain(*blocks: tuple[bytes, int]) -> bytes:
    return b"".join(struct.pack(">II", len(block), uncompressed) + block for block, uncompressed in blocks)


def test_linked_lz4_chain() -> None:
    # Each block after the first copies from the output of the blocks before it
    first = DICTIONARY
    second = b"Again: " + first[:20] + b" and more."
    third = second + b" Done."
    body = _linked_chain(
        (_lz4_block(tail=first), len(first)),
        (_lz4_block((b"Again: ", len(first) + 7, 20), tail=b" and more."), len(second)),
        (_lz4_block((b"", len(second), len(second)), tail=b" Done."), len(third)),
    )
    assert decompress_linked_lz4(body, len(first + second + third)) == first + second + third


def test_lz4_block_header_struct_matches_c_tibx() -> None:
    header = c_tibx.lz4_block_header(compressed_size=0x01020304, uncompressed_size=0x05060708).dumps()
    assert codec._LZ4_BLOCK_HEADER.size == LZ4_BLOCK_HEADER_SIZE == len(header)
    assert codec._LZ4_BLOCK_HEADER.unpack(header) == (0x01020304, 0x05060708)


def test_linked_lz4_chain_longer_than_a_dictionary() -> None:
    # Only the last 64 KiB of the output can be referenced, so that is all that is passed on;
    # the second block copies from the farthest byte it can reach
    first = bytes(range(256)) * 300  # 75 KiB
    second = first[-codec.LZ4_MAX_DISTANCE :][:20000] + b" Done."
    body = _linked_chain(
        (_lz4_block(tail=first), len(first)),
        (_lz4_block((b"", codec.LZ4_MAX_DISTANCE, 20000), tail=b" Done."), len(second)),
    )
    assert decompress_linked_lz4(body, len(first + second)) == first + second


def test_linked_lz4_strict_overflow() -> None:
    body = _linked_chain((_lz4_block(tail=PLAIN[:1000]), 1000))
    with pytest.raises(CorruptArchiveError):
        decompress_linked_lz4(body, 100, strict=True)
    # Non-strict stops cleanly at the offending block
    assert decompress_linked_lz4(body, 100, strict=False) == b""


def test_cell_stream_raw_and_lz4() -> None:
    assert decompress_cell_stream(PLAIN, 0, 512) == PLAIN[:512]
    body = _linked_chain((_lz4_block(tail=PLAIN[:512]), 512))
    assert decompress_cell_stream(body, 1, 512) == PLAIN[:512]
    with pytest.raises(CorruptArchiveError):
        decompress_cell_stream(PLAIN, 7, 512)
