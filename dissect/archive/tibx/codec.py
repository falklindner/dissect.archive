"""Decompression codecs used by TIBX.

- Data segments: a single zstd frame (or LZ4 / stored, per the segment header).
- LSM cell streams and mem-tree blobs: **linked-LZ4** -- a chain of blocks
  ``[compressed BE u32][uncompressed BE u32][payload]`` where each block may
  back-reference previously decompressed output as its LZ4 dictionary
  (``LZ4_decompress_safe_continue`` semantics).

A ``.tibx`` is untrusted input: every decode is bounded by the caller-supplied output
size so malformed on-disk sizes can't drive unbounded allocations.

The linked-LZ4 chain framing is ported from ``acronis-tibx`` (MIT License, Copyright (c)
2026 mniedermaier).
"""

from __future__ import annotations

import struct
import sys

from dissect.util.compression import lz4
from dissect.util.exceptions import CorruptDataError

from dissect.archive.tibx.c_tibx import LZ4_BLOCK_HEADER_SIZE
from dissect.archive.tibx.exception import CorruptArchiveError

# Generous ceiling for a single decompressed unit; real segments are a few MiB
MAX_DECOMPRESSED = 2 << 30

# LZ4 back-references reach at most this far, so a longer dictionary is never read
LZ4_MAX_DISTANCE = 0xFFFF

# c_tibx.lz4_block_header as a precompiled struct (a test keeps the two in step): an index
# page chains six to eight blocks, and cstruct's ~3 us a header was a quarter of the time
# spent decoding the index's LZ4 with dissect.util's native module
_LZ4_BLOCK_HEADER = struct.Struct(">II")


def decompress_zstd(data: bytes, max_output: int) -> bytes:
    """Decompress one zstd frame, ignoring trailing padding, bounded by ``max_output``.

    zstd is imported here, as :mod:`dissect.archive.tibx.crypto` imports pycryptodome: below
    Python 3.14 it comes from ``backports.zstd``, which only the ``full`` extra installs, and
    opening an archive and listing what it holds needs no zstd.
    """
    if sys.version_info >= (3, 14):
        from compression import zstd  # novermin
    else:
        from backports import zstd

    try:
        decompressor = zstd.ZstdDecompressor()
        out = decompressor.decompress(data, max_output + 1)
    except zstd.ZstdError as e:
        raise CorruptArchiveError(f"zstd: {e}")
    if len(out) > max_output:
        raise CorruptArchiveError(f"zstd output exceeds {max_output}-byte cap (malformed frame?)")
    return out


def lz4_block_decompress(src: bytes, uncompressed_size: int, dictionary: bytes = b"") -> bytes:
    """Decompress one raw LZ4 block whose matches may reach back into ``dictionary``."""
    if uncompressed_size <= 0:
        # Every TIBX LZ4 block records its size; without one the output would be unbounded
        raise CorruptArchiveError(f"LZ4: invalid uncompressed size {uncompressed_size}")
    try:
        return lz4.decompress(src, uncompressed_size, dictionary=dictionary)
    except (CorruptDataError, ValueError) as e:
        # The Rust backend raises ValueError, the pure-Python one CorruptDataError, which is not a ValueError
        raise CorruptArchiveError(f"LZ4: {e}")


def decompress_linked_lz4(body: bytes, max_output: int, *, strict: bool = True) -> bytes:
    """Decompress a linked-LZ4 block chain, bounded by ``max_output``.

    ``strict=True`` raises :class:`CorruptArchiveError` on a block that overflows the
    target or fails to decode; ``strict=False`` (best-effort scans over untrusted input)
    stops at the first malformed block and returns what decoded cleanly.
    """
    out = bytearray()
    pos = 0
    body_len = len(body)
    while pos + LZ4_BLOCK_HEADER_SIZE <= body_len and len(out) < max_output:
        compressed, uncompressed = _LZ4_BLOCK_HEADER.unpack_from(body, pos)
        pos += LZ4_BLOCK_HEADER_SIZE
        if compressed == 0 or compressed > body_len - pos:
            break
        if uncompressed > max_output - len(out):
            if not strict:
                break
            raise CorruptArchiveError(
                f"linked-LZ4 block claims {uncompressed} bytes; "
                f"only {max_output - len(out)} remain of the {max_output}-byte target"
            )
        try:
            dictionary = bytes(out[-LZ4_MAX_DISTANCE:])
            out += lz4_block_decompress(body[pos : pos + compressed], uncompressed, dictionary=dictionary)
        except CorruptArchiveError:
            if not strict:
                break
            raise
        pos += compressed
    return bytes(out)


def decompress_cell_stream(body: bytes, codec: int, uncompressed_size: int) -> bytes:
    """Decompress a LEAF/LDIR cell stream or mem-tree blob (codec 0 = raw, 1 = linked-LZ4)."""
    if codec == 0:
        if len(body) < uncompressed_size:
            raise CorruptArchiveError(f"raw cell stream is {len(body)} bytes, expected {uncompressed_size}")
        return bytes(body[:uncompressed_size])
    if codec != 1:
        raise CorruptArchiveError(f"unknown LSM cell codec {codec}")
    out = decompress_linked_lz4(body, uncompressed_size, strict=True)
    if len(out) != uncompressed_size:
        raise CorruptArchiveError(f"cell stream decoded {len(out)} bytes, expected {uncompressed_size}")
    return out
