from __future__ import annotations

import io
import struct

import pytest

from dissect.archive.tibx.exception import CorruptArchiveError
from dissect.archive.tibx.lsm import (
    LsmSuperBlock,
    decode_cells_compact,
    decode_cells_variable,
    decode_page_cells,
    iter_memtree_cells,
    read_archive_header,
    walk_tree,
)
from dissect.archive.tibx.page import PageStore
from tests._synth import PAGE, Cell, arch_header_page, arch_page, compact_cells, lsb, lsm_page


def test_compact_cells_roundtrip_with_tombstone() -> None:
    cells = [
        Cell(b"k" * 8, b"v" * 4),
        Cell(b"t" * 8, b"", alive=False),
        Cell(b"m" * 8, b"w" * 4),
    ]
    decoded = decode_cells_compact(compact_cells(cells), 3, key_length=8, value_length=4)
    assert [(c.key, c.value, c.alive) for c in decoded] == [
        (b"k" * 8, b"v" * 4, True),
        (b"t" * 8, b"", False),
        (b"m" * 8, b"w" * 4, True),
    ]


def test_compact_cells_multiple_groups() -> None:
    cells = [Cell(struct.pack(">Q", i), struct.pack(">I", i)) for i in range(30)]
    decoded = decode_cells_compact(compact_cells(cells), 30, key_length=8, value_length=4)
    assert len(decoded) == 30
    assert decoded[29].key == struct.pack(">Q", 29)


def test_variable_cells_leb128() -> None:
    # leb128 key_len | leb128 val_len | key | val, with a >127 length
    key = b"K" * 200
    buf = bytes([200 & 0x7F | 0x80, 200 >> 7]) + bytes([3]) + key + b"abc"
    decoded = decode_cells_variable(buf, 1)
    assert decoded[0].key == key
    assert decoded[0].value == b"abc"


def test_variable_cells_truncated() -> None:
    with pytest.raises(CorruptArchiveError):
        decode_cells_variable(b"", 1)


def test_lsb_parse_memtree_and_ctrees() -> None:
    cells = [Cell(b"a" * 8, b"1" * 4), Cell(b"b" * 8, b"2" * 4)]
    sb = LsmSuperBlock(lsb(8, 4, memtree_cells=cells), tlv_index=1)
    assert sb.key_length == 8
    assert sb.value_length == 4
    assert sb.memtree_node_count == 2
    assert sb.has_records
    assert all(c.offset is None for c in sb.ctrees)
    assert [(c.key, c.value) for c in iter_memtree_cells(sb)] == [(b"a" * 8, b"1" * 4), (b"b" * 8, b"2" * 4)]

    sb = LsmSuperBlock(lsb(8, 4, ctrees=[(3 * PAGE, 5)]), tlv_index=1)
    assert sb.ctrees[0].root_page == 3
    assert sb.has_records
    assert iter_memtree_cells(sb) == []

    assert not LsmSuperBlock(lsb(8, 4), tlv_index=1).has_records


def test_leaf_page_cells() -> None:
    cells = [Cell(b"k" * 8, b"v" * 4)]
    page = lsm_page(0x03, b"LEAF", cells, key_length=8, compact=True)
    decoded = decode_page_cells(page[8:], key_length=8, value_length=4)
    assert [(c.key, c.value) for c in decoded] == [(b"k" * 8, b"v" * 4)]


def test_walk_tree_through_ldir() -> None:
    # page 0: ARCH; page 1: LDIR -> pages 2 and 3 (LEAF)
    leaf_a = [Cell(b"a" * 8, b"1" * 4), Cell(b"b" * 8, b"2" * 4)]
    leaf_b = [Cell(b"c" * 8, b"3" * 4)]
    ldir = [
        Cell(b"a" * 8, struct.pack(">Q", 2 * PAGE)),
        Cell(b"c" * 8, struct.pack(">Q", 3 * PAGE)),
    ]
    archive = (
        arch_page(1000, 2000, b"\xab" * 16)
        + lsm_page(0x04, b"LDIR", ldir, key_length=8, compact=False)
        + lsm_page(0x03, b"LEAF", leaf_a, key_length=8, compact=True)
        + lsm_page(0x03, b"LEAF", leaf_b, key_length=8, compact=True)
    )
    store = PageStore(io.BytesIO(archive))
    cells = list(walk_tree(store, 1, key_length=8, value_length=4))
    assert [(c.key, c.value) for c in cells] == [
        (b"a" * 8, b"1" * 4),
        (b"b" * 8, b"2" * 4),
        (b"c" * 8, b"3" * 4),
    ]


def test_archive_header_tlv_and_trees() -> None:
    dm = lsb(31, 10, memtree_cells=[Cell(b"\x00" * 31, b"\x01" * 10)])
    sm = lsb(8, 32, memtree_cells=[Cell(b"\x00" * 8, b"\x02" * 32)])
    store = PageStore(io.BytesIO(arch_header_page({1: dm, 2: sm})))
    header = read_archive_header(store)
    assert header.version == 8
    assert len(header.tlv) == 19
    assert header.tree(1) is not None
    assert header.tree(1).key_length == 31
    assert header.tree(2).value_length == 32
    assert header.tree(3) is None
