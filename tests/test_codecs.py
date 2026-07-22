from __future__ import annotations

import struct
import sys

import pytest

from dissect.archive.tibx import codecs
from dissect.archive.tibx.codecs import (
    decompress_cell_stream,
    decompress_linked_lz4,
    decompress_zstd,
    lz4_block_decompress,
)
from dissect.archive.tibx.exceptions import CorruptArchiveError

if sys.version_info >= (3, 14):
    from compression import zstd  # novermin
else:
    from backports import zstd

lz4 = pytest.importorskip("lz4.block", reason="the C lz4 package is used as a test-only compressor")

PLAIN = b"The data_map maps (volume_id, offset) to segments. " * 40


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
    dictionary = PLAIN[:1000]
    chunk = PLAIN[500:1800]
    compressed = lz4.compress(chunk, mode="high_compression", store_size=False, dict=dictionary)
    assert lz4_block_decompress(compressed, len(chunk), dictionary) == chunk


def test_lz4_pure_python_fallback_matches_accelerator(monkeypatch: pytest.MonkeyPatch) -> None:
    # The C accelerator is optional; the pure-Python decoder is the no-dependency fallback.
    # Both must produce byte-identical output, including the growing-dictionary case.
    if codecs._lz4_block is None:
        pytest.skip("C lz4 accelerator not loaded; only the fallback path is available")
    dictionary = PLAIN[:1000]
    chunk = PLAIN[500:1800]
    compressed = lz4.compress(chunk, mode="high_compression", store_size=False, dict=dictionary)

    accelerated = lz4_block_decompress(compressed, len(chunk), dictionary)
    monkeypatch.setattr(codecs, "_lz4_block", None)
    fallback = lz4_block_decompress(compressed, len(chunk), dictionary)
    assert accelerated == fallback == chunk


def _linked_chain(chunks: list[bytes]) -> bytes:
    body = bytearray()
    history = b""
    for chunk in chunks:
        compressed = lz4.compress(chunk, mode="high_compression", store_size=False, dict=history)
        body += struct.pack(">II", len(compressed), len(chunk))
        body += compressed
        history += chunk
    return bytes(body)


def test_linked_lz4_chain() -> None:
    chunks = [PLAIN[:1000], PLAIN[500:1800], PLAIN[200:1500]]
    body = _linked_chain(chunks)
    assert decompress_linked_lz4(body, sum(map(len, chunks))) == b"".join(chunks)


def test_linked_lz4_strict_overflow() -> None:
    body = _linked_chain([PLAIN[:1000]])
    with pytest.raises(CorruptArchiveError):
        decompress_linked_lz4(body, 100, strict=True)
    # Non-strict stops cleanly at the offending block
    assert decompress_linked_lz4(body, 100, strict=False) == b""


def test_cell_stream_raw_and_lz4() -> None:
    assert decompress_cell_stream(PLAIN, 0, 512) == PLAIN[:512]
    body = _linked_chain([PLAIN[:512]])
    assert decompress_cell_stream(body, 1, 512) == PLAIN[:512]
    with pytest.raises(CorruptArchiveError):
        decompress_cell_stream(PLAIN, 7, 512)
