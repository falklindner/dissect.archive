"""Decompression codecs used by TIBX.

- Data segments: a single zstd frame (or LZ4 / stored, per the segment header).
- LSM cell streams and mem-tree blobs: **linked-LZ4** -- a chain of blocks
  ``[compressed BE u32][uncompressed BE u32][payload]`` where each block may
  back-reference previously decompressed output as its LZ4 dictionary
  (``LZ4_decompress_safe_continue`` semantics).

``dissect.util``'s LZ4 has no dictionary parameter, so the raw block decoder here is
adapted from ``dissect.util.compression.lz4_python`` with a dictionary seed added.
A ``.tibx`` is untrusted input: every decode is bounded by the caller-supplied output
size so malformed on-disk sizes can't drive unbounded allocations.

The linked-LZ4 chain framing is ported from the MIT-licensed ``acronis-tibx``. See
``THIRD_PARTY_NOTICES.md``.
"""

from __future__ import annotations

import io
import struct
import sys

if sys.version_info >= (3, 14):
    from compression import zstd  # novermin
else:
    from backports import zstd

from dissect.archive.tibx.exceptions import CorruptArchiveError

# Generous ceiling for a single decompressed unit; real segments are a few MiB
MAX_DECOMPRESSED = 2 << 30

# Optional C-accelerated LZ4 block decoder. The pure-Python decoder below is always the
# fallback (``lz4`` is not a hard dependency), so nothing breaks without it; when present
# it is orders of magnitude faster and, per a capability probe, produces byte-identical
# output including the growing-dictionary (``LZ4_decompress_safe_continue``) semantics the
# linked-LZ4 chains rely on.
try:
    import lz4.block as _lz4_block

    _probe = _lz4_block.compress(b"tibx-lz4-capability-probe", store_size=False)
    if (
        _lz4_block.decompress(_probe, uncompressed_size=25) != b"tibx-lz4-capability-probe"
        or _lz4_block.decompress(_probe, uncompressed_size=25, dict=b"") != b"tibx-lz4-capability-probe"
    ):
        _lz4_block = None
except Exception:
    _lz4_block = None


def decompress_zstd(data: bytes, max_output: int) -> bytes:
    """Decompress one zstd frame, ignoring trailing padding, bounded by ``max_output``."""
    try:
        decompressor = zstd.ZstdDecompressor()
        out = decompressor.decompress(data, max_output + 1)
    except zstd.ZstdError as e:
        raise CorruptArchiveError(f"zstd: {e}")
    if len(out) > max_output:
        raise CorruptArchiveError(f"zstd output exceeds {max_output}-byte cap (malformed frame?)")
    return out


def lz4_block_decompress(src: bytes, uncompressed_size: int, dictionary: bytes = b"") -> bytes:
    """Raw LZ4 block decode with dictionary support.

    Adapted from ``dissect.util.compression.lz4_python.decompress``, extended with a
    ``dictionary`` seed: output starts as the dictionary so matches may reach back into
    it; the seed is stripped from the returned data.

    Uses the C ``lz4`` library when available (byte-identical, far faster), falling back
    to the pure-Python decoder otherwise.
    """
    if _lz4_block is not None and uncompressed_size > 0:
        try:
            return _lz4_block.decompress(src, uncompressed_size=uncompressed_size, dict=dictionary)
        except Exception as e:
            # Malformed on-disk block on untrusted input -- normalise to our error type
            raise CorruptArchiveError(f"LZ4: {e}")

    reader = io.BytesIO(src)
    dst = bytearray(dictionary)
    base = len(dictionary)
    min_match_len = 4

    def _get_length(token_len: int) -> int:
        length = token_len
        if token_len == 0xF:
            while True:
                byte = reader.read(1)
                if not byte:
                    raise CorruptArchiveError("LZ4: EOF while reading length")
                length += byte[0]
                if byte[0] != 0xFF:
                    break
        return length

    while True:
        read_buf = reader.read(1)
        if not read_buf:
            raise CorruptArchiveError("LZ4: EOF at reading literal-len")
        token = read_buf[0]

        literal_len = _get_length((token >> 4) & 0xF)
        if len(dst) - base + literal_len > uncompressed_size > 0:
            raise CorruptArchiveError("LZ4: decompressed size exceeds uncompressed_size")

        read_buf = reader.read(literal_len)
        if len(read_buf) != literal_len:
            raise CorruptArchiveError("LZ4: not enough literal data")
        dst.extend(read_buf)
        if len(dst) - base >= uncompressed_size > 0:
            break

        read_buf = reader.read(2)
        if len(read_buf) == 0:
            if token & 0xF != 0:
                raise CorruptArchiveError("LZ4: EOF, but match-len > 0")
            break
        if len(read_buf) != 2:
            raise CorruptArchiveError("LZ4: premature EOF")

        offset = struct.unpack("<H", read_buf)[0]
        if offset == 0 or offset > len(dst):
            raise CorruptArchiveError(f"LZ4: invalid match offset {offset} (output length {len(dst)})")
        match_len = _get_length(token & 0xF) + min_match_len

        # LZ4 allows overlapping matches: copy byte-wise from len(dst) - offset
        start = len(dst) - offset
        for index in range(match_len):
            dst.append(dst[start + index])

    return bytes(dst[base:])


def decompress_linked_lz4(body: bytes, max_output: int, *, strict: bool = True) -> bytes:
    """Decompress a linked-LZ4 block chain, bounded by ``max_output``.

    ``strict=True`` raises :class:`CorruptArchiveError` on a block that overflows the
    target or fails to decode; ``strict=False`` (best-effort scans over untrusted input)
    stops at the first malformed block and returns what decoded cleanly.
    """
    out = bytearray()
    pos = 0
    body_len = len(body)
    while pos + 8 <= body_len and len(out) < max_output:
        compressed, uncompressed = struct.unpack_from(">II", body, pos)
        pos += 8
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
            out += lz4_block_decompress(body[pos : pos + compressed], uncompressed, dictionary=bytes(out))
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
