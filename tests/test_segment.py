from __future__ import annotations

import io
import random

import pytest

from dissect.archive.tibx.exception import CorruptArchiveError, InvalidPasswordError
from dissect.archive.tibx.page import PageStore
from dissect.archive.tibx.segment import Segment, read_plaintext
from tests._synth import COMP_NONE, PAGE, CountingIO, arch_page, segment_pages


def _store(*pages: bytes) -> PageStore:
    return PageStore(io.BytesIO(arch_page(1000, 2000, b"\xab" * 16) + b"".join(pages)))


def test_single_page_segment() -> None:
    payload = b"hello segment" * 10
    store = _store(*segment_pages(payload))
    assert read_plaintext(store, 1) == payload


def test_multi_page_segment_continuation() -> None:
    # Incompressible payload much larger than one page forces continuation pages
    payload = random.Random(0).randbytes(3 * PAGE)
    pages = segment_pages(payload)
    assert len(pages) > 1
    store = _store(*pages)
    assert read_plaintext(store, 1) == payload


def test_segment_read_in_one_io() -> None:
    # Given the segment_map's page count, the header and the continuation pages come in
    # one read instead of two
    payload = random.Random(0).randbytes(3 * PAGE)
    pages = segment_pages(payload)
    fh = CountingIO(arch_page(1000, 2000, b"\xab" * 16) + b"".join(pages))
    store = PageStore(fh)

    fh.reads = 0
    assert read_plaintext(store, 1, page_count=len(pages)) == payload
    assert fh.reads == 1
    fh.reads = 0
    assert read_plaintext(store, 1) == payload
    assert fh.reads == 2


@pytest.mark.parametrize("page_count", [0, 2, 1000], ids=["zero", "short", "past-eof"])
def test_segment_page_count_only_sizes_the_read(page_count: int) -> None:
    # The count comes from the archive: too small costs a second read, too large stops at
    # EOF, and the header decides where the segment ends either way
    payload = random.Random(0).randbytes(3 * PAGE)
    store = _store(*segment_pages(payload), *segment_pages(b"next segment"))
    assert read_plaintext(store, 1, page_count=page_count) == payload


def test_stored_segment() -> None:
    payload = b"\x01\x02\x03\x04" * 100
    store = _store(*segment_pages(payload, compression=COMP_NONE))
    assert read_plaintext(store, 1) == payload


def test_segment_header_fields() -> None:
    payload = b"x" * 100
    pages = segment_pages(payload)
    segment = Segment(pages[0], 1)
    assert segment.length == 100
    assert segment.key_id == 0
    assert not segment.encrypted
    assert segment.compression == 0x0300


def test_non_segment_page_rejected() -> None:
    store = _store()
    with pytest.raises(CorruptArchiveError):
        read_plaintext(store, 0)  # the ARCH page is not a segment


def test_truncated_continuation() -> None:
    payload = random.Random(0).randbytes(3 * PAGE)
    pages = segment_pages(payload)
    assert len(pages) > 1
    store = _store(*pages[:-1])  # drop the last continuation page
    with pytest.raises(CorruptArchiveError):
        read_plaintext(store, 1)


def test_encrypted_segment_needs_key() -> None:
    payload = b"secret" * 50
    pages = segment_pages(payload, data_key=bytes(range(32)))
    store = _store(*pages)
    with pytest.raises(InvalidPasswordError):
        read_plaintext(store, 1)
