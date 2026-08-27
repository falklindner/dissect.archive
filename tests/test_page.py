from __future__ import annotations

import io

import pytest
from dissect.util import ts

from dissect.archive.tibx.c_tibx import PAGE_MARKER, PAGE_SIZE, c_tibx
from dissect.archive.tibx.exceptions import CorruptArchiveError, InvalidArchiveError
from dissect.archive.tibx.page import PageStore, SuperBlock, page_crc32c
from tests._synth import SEG_PAYLOAD, arch_page, build_archive, data_page


def test_rejects_non_tibx() -> None:
    with pytest.raises(InvalidArchiveError):
        PageStore(io.BytesIO(b"\x00" * PAGE_SIZE))


def test_rejects_short_file() -> None:
    with pytest.raises(InvalidArchiveError):
        PageStore(io.BytesIO(b"\x41\x01"))


def test_page_access_and_types() -> None:
    store = PageStore(io.BytesIO(build_archive()))
    assert store.page_count == 2
    assert store.size == 2 * PAGE_SIZE
    assert store.page_type(0) == c_tibx.PageType.ARCH
    assert store.page_type(1) == c_tibx.PageType.DATA
    assert store.page_type_name(0) == "ARCH"
    assert store.page_type_name(1) == "DATA"
    assert [i for i, _ in store.pages()] == [0, 1]
    assert store.page(0)[8:12] == b"ARCH"


def test_superblock_fields() -> None:
    uuid = bytes(range(16))
    sb = SuperBlock(arch_page(1_720_000_000_123, 1_720_000_555_999, uuid), offset=0)
    assert sb.archive_uuid == uuid
    assert sb.created_ms == 1_720_000_000_123
    assert sb.modified_ms == 1_720_000_555_999
    assert sb.created == ts.from_unix_ms(1_720_000_000_123)
    assert sb.modified == ts.from_unix_ms(1_720_000_555_999)


def test_superblock_rejects_non_arch() -> None:
    with pytest.raises(InvalidArchiveError):
        SuperBlock(data_page(SEG_PAYLOAD), offset=0)


def test_verify_all_pages_ok() -> None:
    result = PageStore(io.BytesIO(build_archive())).verify()
    assert result["bad"] == 0
    assert result["ok"] == 2
    assert result["by_type"] == {"ARCH": 1, "DATA": 1}


def test_verify_detects_corruption() -> None:
    data = bytearray(build_archive())
    data[PAGE_SIZE + 0x40] ^= 0xFF  # flip a byte in the DATA page body
    result = PageStore(io.BytesIO(bytes(data))).verify()
    assert result["bad"] == 1
    assert result["bad_pages"] == [1]


def test_live_root_is_highest_offset_arch() -> None:
    # Two ARCH roots; the live root must be the higher-offset (newer) one
    data = arch_page(1000, 2000, b"\x01" * 16) + arch_page(3000, 5000, b"\x02" * 16)
    root = PageStore(io.BytesIO(data)).live_root()
    assert root.offset == PAGE_SIZE
    assert root.archive_uuid == b"\x02" * 16
    assert root.modified_ms == 5000


def test_live_root_skips_torn_final_commit() -> None:
    # The newest ARCH has a bad CRC (torn commit, e.g. power loss); transactional
    # recovery must fall back to the newest complete (CRC-valid) root.
    good = arch_page(1000, 2000, b"\x11" * 16)
    torn = bytearray(arch_page(3000, 5000, b"\x22" * 16))
    torn[0x80] ^= 0xFF
    root = PageStore(io.BytesIO(good + bytes(torn))).live_root()
    assert root.offset == 0
    assert root.modified_ms == 2000


def test_live_root_all_roots_torn() -> None:
    torn = bytearray(arch_page(1000, 2000, b"\x11" * 16))
    torn[0x80] ^= 0xFF
    store = PageStore(io.BytesIO(bytes(torn)))
    with pytest.raises(CorruptArchiveError):
        store.live_root()


def test_commit_roots_ordered_by_commit_time() -> None:
    # Three roots written out of timestamp order; enumeration sorts oldest -> newest
    data = (
        arch_page(1000, 7000, b"\x03" * 16)
        + data_page(SEG_PAYLOAD)
        + arch_page(1000, 2000, b"\x01" * 16)
        + arch_page(1000, 5000, b"\x02" * 16)
    )
    roots = PageStore(io.BytesIO(data)).commit_roots()
    assert [sb.modified_ms for sb in roots] == [2000, 5000, 7000]
    assert [sb.offset for sb in roots] == [2 * PAGE_SIZE, 3 * PAGE_SIZE, 0]


def test_page_crc_ignores_checksum_field() -> None:
    page = bytearray(PAGE_SIZE)
    page[0], page[1] = PAGE_MARKER, c_tibx.PageType.ARCH
    page[8:12] = b"ARCH"
    base = page_crc32c(bytes(page))

    # Whatever is stored in the CRC field must not affect the page CRC itself
    page[4:8] = b"\xde\xad\xbe\xef"
    assert page_crc32c(bytes(page)) == base

    # But any body change must
    page[0x80] ^= 0xFF
    assert page_crc32c(bytes(page)) != base


def test_superblock_rejects_truncated_page() -> None:
    # cstruct raises EOFError on a short buffer; callers should only ever see the parser's
    # own exception type.
    with pytest.raises(InvalidArchiveError):
        SuperBlock(b"\x41\x01\x00\x00\x00\x00\x00\x00ARCH", offset=0)
