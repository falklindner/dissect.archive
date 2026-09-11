"""LSM index layer: the ARCH header's TLV directory, L-SB superblocks and tree walking.

The ARCH header body carries a 19-slot TLV directory (at body offset ``0x400``); slots
0-8 hold **L-SB** superblocks, one per LSM tree (slot 1 = ``data_map``, slot 2 =
``segment_map``, slot 5 = ``slices``, slot 7 = ``keymap``, slot 18 = volume table).
Each L-SB describes the tree's on-disk ctree runs (B-tree roots of LEAF/LDIR pages)
plus a residual **mem-tree** holding not-yet-compacted records -- small archives keep
*all* records in the mem-tree with empty ctrees.

Ported from the LSM engine of the MIT-licensed ``acronis-tib-reader``, with the mem-tree
(C0) layer from ``acronis-tibx``. See ``THIRD_PARTY_NOTICES.md``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from dissect.archive.tibx.c_tibx import (
    CTREE_EMPTY_SENTINEL,
    ENVELOPE_SIZE,
    LDIR_VALUE_SIZE,
    LSB_CTREE_OFFSET,
    LSB_FIXED_SIZE,
    LSB_MEMTREE_OFFSET,
    LSM_CELL_GROUP_HEADER_SIZE,
    LSM_CELL_GROUP_MAX,
    LSM_CELL_STREAM_OFFSET,
    LSM_MAGIC_LDIR,
    LSM_MAGIC_LEAF,
    LSM_MAGIC_SUPERBLOCK,
    LZ4_BLOCK_HEADER_SIZE,
    PAGE_SIZE,
    TLV_DIRECTORY_OFFSET,
    TLV_HEADER_SIZE,
    TLV_SLOT_COUNT,
    c_tibx,
)
from dissect.archive.tibx.codec import decompress_cell_stream, decompress_linked_lz4
from dissect.archive.tibx.exception import CorruptArchiveError, UnsupportedFormatError
from dissect.archive.tibx.page import ARCH_MAGIC

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.archive.tibx.page import PageStore, SuperBlock

# Sanity bound on pages visited per tree walk (matches the reference engine)
MAX_TREE_PAGES = 8192


class CTreeRef(NamedTuple):
    """One on-disk ctree (frozen LSM run) slot from an L-SB. ``offset`` is None if empty."""

    offset: int | None
    num_pages: int
    item_count: int

    @property
    def root_page(self) -> int | None:
        return None if self.offset is None else self.offset // PAGE_SIZE


class LsmCell(NamedTuple):
    """One decoded LSM record. ``alive`` is False for tombstones (deletes)."""

    key: bytes
    value: bytes
    alive: bool


class TlvSlot(NamedTuple):
    """One TLV directory entry from the ARCH header body."""

    index: int
    payload: bytes


class LsmSuperBlock:
    """One LSM tree's superblock (an ``L-SB`` TLV payload from the ARCH header)."""

    def __init__(self, payload: bytes, tlv_index: int = -1):
        if payload[:4] != LSM_MAGIC_SUPERBLOCK:
            raise CorruptArchiveError(f"L-SB magic missing in TLV slot {tlv_index}")
        self.tlv_index = tlv_index
        self.sb = c_tibx.lsm_superblock(payload)
        self.seq = self.sb.seq
        self.key_length = self.sb.key_length
        self.value_length = self.sb.value_length

        ctree_count = self.sb.ctree_count_minus_2 + 2
        self.ctrees: list[CTreeRef] = []
        for index in range(ctree_count):
            slot_offset = LSB_CTREE_OFFSET + index * len(c_tibx.ctree_ref)
            if slot_offset + len(c_tibx.ctree_ref) > len(payload):
                break
            ref = c_tibx.ctree_ref(payload[slot_offset:])
            empty = ref.offset == CTREE_EMPTY_SENTINEL or (
                ref.offset == 0 and ref.num_pages == 0 and ref.item_count == 0
            )
            self.ctrees.append(
                CTreeRef(
                    offset=None if empty else ref.offset,
                    num_pages=ref.num_pages,
                    item_count=ref.item_count,
                )
            )

        # Residual mem-tree: header after the ctree slots, blob after the fixed L-SB record
        self.memtree_encoding = 0
        self.memtree_node_count = 0
        self.memtree_payload = b""
        if len(payload) >= LSB_FIXED_SIZE:
            memtree = c_tibx.lsm_memtree_header(payload[LSB_MEMTREE_OFFSET:])
            self.memtree_encoding = memtree.encoding
            self.memtree_node_count = memtree.node_count
            self.memtree_payload = bytes(payload[LSB_FIXED_SIZE:])

    def __repr__(self) -> str:
        return (
            f"<LsmSuperBlock tlv={self.tlv_index} key_length={self.key_length} "
            f"value_length={self.value_length} ctrees={sum(1 for ctree in self.ctrees if ctree.offset is not None)} "
            f"memtree_nodes={self.memtree_node_count}>"
        )

    @property
    def has_records(self) -> bool:
        """Whether this tree holds any records (mem-tree or on-disk ctrees)."""
        return self.memtree_node_count > 0 or any(
            ctree.offset is not None and ctree.item_count > 0 for ctree in self.ctrees
        )


def _arch_header(body: bytes) -> c_tibx.arch_header:
    """Parse the fixed fields at the start of an ARCH header body."""
    try:
        return c_tibx.arch_header(body)
    except EOFError:
        raise CorruptArchiveError(f"ARCH header body too short: {len(body)} bytes")


class ArchiveHeader:
    """The decoded ARCH header of one commit root: TLV directory + LSM superblocks."""

    def __init__(self, body: bytes):
        if body[:4] != ARCH_MAGIC:
            raise CorruptArchiveError("ARCH magic missing in header body")
        self.body = body
        header = _arch_header(body)
        self.size = header.header_size
        self.version = header.header_version
        self.tlv = parse_tlv_directory(body)
        self.lsm_trees: dict[int, LsmSuperBlock] = {}
        for slot in self.tlv:
            if slot.index <= 8 and slot.payload[:4] == LSM_MAGIC_SUPERBLOCK:
                self.lsm_trees[slot.index] = LsmSuperBlock(slot.payload, slot.index)

    def tree(self, tlv_index: int) -> LsmSuperBlock | None:
        """Return the LSM superblock in TLV slot ``tlv_index``, or None."""
        return self.lsm_trees.get(tlv_index)


def parse_tlv_directory(body: bytes) -> list[TlvSlot]:
    """Walk the 19-entry TLV directory at ``body[0x400:header_size]``.

    Header versions below 8 zero-skip some slots; version 8+ parses all 19.
    """
    if len(body) < TLV_DIRECTORY_OFFSET + 8:
        raise CorruptArchiveError(f"ARCH body too short for TLV directory: {len(body)} bytes")
    header = _arch_header(body)
    if header.header_version < 7:
        skip = {8, 12, 13, 14, 15, 16}
    elif header.header_version < 8:
        skip = {12, 13, 14, 15, 16}
    else:
        skip = set()

    pos = TLV_DIRECTORY_OFFSET
    end = min(header.header_size, len(body))
    slots = []
    for index in range(TLV_SLOT_COUNT):
        if index in skip or pos + TLV_HEADER_SIZE > end:
            slots.append(TlvSlot(index=index, payload=b""))
            continue
        length = c_tibx.tlv_header(body[pos : pos + TLV_HEADER_SIZE]).length
        start = pos + TLV_HEADER_SIZE
        slots.append(TlvSlot(index=index, payload=bytes(body[start : start + length])))
        # The next entry starts at the next 4-byte boundary
        pos = (start + length + 3) & ~3
    return slots


def read_header_body(store: PageStore, root: SuperBlock) -> bytes:
    """Assemble the full ARCH header body of the commit root at ``root``.

    The header may span multiple pages: continuation pages are also type ARCH but carry
    raw header bytes (no inner magic). Bodies are the pages' content after the 8-byte
    envelope.
    """
    page_index = root.offset // PAGE_SIZE
    first = store.page(page_index)
    header_size = c_tibx.arch_superblock(first).body.header_size
    body = bytearray(first[ENVELOPE_SIZE:])
    next_index = page_index + 1
    while len(body) < header_size and next_index < store.page_count:
        page = store.page(next_index)
        if c_tibx.page_header(page).type != c_tibx.PageType.ARCH:
            break
        body.extend(page[ENVELOPE_SIZE:])
        next_index += 1
    return bytes(body[:header_size]) if header_size <= len(body) else bytes(body)


def read_archive_header(store: PageStore, root: SuperBlock | None = None) -> ArchiveHeader:
    """Read and decode the archive header of ``root`` (default: the live commit root)."""
    if root is None:
        root = store.live_root()
    return ArchiveHeader(read_header_body(store, root))


# --- cell streams ---------------------------------------------------------


def _read_leb128(buf: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise CorruptArchiveError("LEB128 ran off end of buffer")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos
        shift += 7
        if shift > 28:
            raise CorruptArchiveError("LEB128 too long (max 4 bytes)")


def decode_cells_variable(buf: bytes, count: int, key_length: int = 0, value_length: int = 0) -> list[LsmCell]:
    """Decode ``count`` cells from a non-compact buffer (LDIR pages, variable-key trees).

    ``key_length == 0`` selects variable-length records (``leb128 key_len | leb128
    val_len | key | val``); otherwise cells are fixed ``key || value`` back-to-back.
    """
    cells = []
    pos = 0
    for _ in range(count):
        if key_length == 0:
            if pos >= len(buf):
                raise CorruptArchiveError("ran out of buffer mid-cell (variable mode)")
            key_len, pos = _read_leb128(buf, pos)
            val_len, pos = _read_leb128(buf, pos)
            if key_len > 0x8000 or val_len > 0x8000:
                raise CorruptArchiveError(f"cell sizes too large: {key_len}, {val_len}")
        else:
            key_len, val_len = key_length, value_length
        key = bytes(buf[pos : pos + key_len])
        pos += key_len
        value = bytes(buf[pos : pos + val_len])
        pos += val_len
        cells.append(LsmCell(key=key, value=value, alive=True))
    return cells


def decode_cells_compact(buf: bytes, count: int, key_length: int, value_length: int) -> list[LsmCell]:
    """Decode ``count`` cells from a compact (LEAF, fixed-size) buffer.

    Cells come in groups of up to 24, each preceded by a :class:`c_tibx.lsm_cell_group_header`
    whose ``alive`` bitmap has bit ``i`` set when cell ``i`` carries a value; tombstones store
    only the key.
    """
    cells = []
    pos = 0
    decoded = 0
    while decoded < count:
        if pos + LSM_CELL_GROUP_HEADER_SIZE > len(buf):
            raise CorruptArchiveError(f"compact cells: short group header at {pos}")
        group = c_tibx.lsm_cell_group_header(buf[pos : pos + LSM_CELL_GROUP_HEADER_SIZE])
        if group.count == 0 or group.count > LSM_CELL_GROUP_MAX:
            raise CorruptArchiveError(f"compact cells: bad group count {group.count} at {pos}")
        pos += LSM_CELL_GROUP_HEADER_SIZE
        for index in range(group.count):
            if decoded >= count:
                break
            alive = bool((group.alive >> index) & 1)
            key = bytes(buf[pos : pos + key_length])
            pos += key_length
            value = b""
            if alive:
                value = bytes(buf[pos : pos + value_length])
                pos += value_length
            cells.append(LsmCell(key=key, value=value, alive=alive))
            decoded += 1
    return cells


def decode_page_cells(body: bytes, key_length: int, value_length: int) -> list[LsmCell]:
    """Decode every cell in a LEAF or LDIR page body (envelope already stripped)."""
    if body[:4] not in (LSM_MAGIC_LEAF, LSM_MAGIC_LDIR):
        raise CorruptArchiveError(f"not a LEAF/LDIR page: magic={bytes(body[:4])!r}")
    header = c_tibx.lsm_page_header(body)
    if header.encoding & 0x80:
        raise UnsupportedFormatError("encrypted LSM pages are not supported")

    is_ldir = bytes(header.magic) == LSM_MAGIC_LDIR
    if is_ldir:
        value_length = LDIR_VALUE_SIZE

    stream = body[LSM_CELL_STREAM_OFFSET : LSM_CELL_STREAM_OFFSET + header.on_disk_size]
    raw = decompress_cell_stream(stream, header.encoding & 0x7F, header.uncompressed_size)

    # Compact mode applies to LEAF pages of fixed-key trees only
    if not is_ldir and key_length != 0:
        return decode_cells_compact(raw, header.cell_count, key_length, value_length)
    return decode_cells_variable(raw, header.cell_count, key_length, value_length)


def iter_memtree_cells(sb: LsmSuperBlock) -> list[LsmCell]:
    """Decode an L-SB's residual mem-tree into cells.

    Small archives keep all of a tree's records here rather than in on-disk ctrees.
    The blob is a compact cell stream, raw or wrapped in a single linked-LZ4 block.
    """
    payload = sb.memtree_payload
    if not payload or sb.memtree_node_count == 0 or sb.key_length == 0:
        return []
    encoding = sb.memtree_encoding
    if encoding & 0x80:
        raise UnsupportedFormatError("encrypted mem-tree blobs are not supported")
    codec = encoding & 0x7F
    if codec == 0:
        decoded = bytes(payload)
    elif codec == 1:
        if len(payload) < LZ4_BLOCK_HEADER_SIZE:
            return []
        uncompressed = c_tibx.lz4_block_header(payload[:LZ4_BLOCK_HEADER_SIZE]).uncompressed_size
        decoded = decompress_linked_lz4(payload, uncompressed, strict=True)
        if len(decoded) != uncompressed:
            raise CorruptArchiveError(f"mem-tree blob decoded {len(decoded)} bytes, expected {uncompressed}")
    else:
        raise UnsupportedFormatError(f"unknown mem-tree encoding {encoding}")
    return decode_cells_compact(decoded, sb.memtree_node_count, sb.key_length, sb.value_length)


def walk_tree(store: PageStore, root_page: int, key_length: int, value_length: int) -> Iterator[LsmCell]:
    """Yield every cell of every LEAF reachable from ``root_page``, depth-first."""
    pages_walked = 0

    def _visit(page_index: int) -> Iterator[LsmCell]:
        nonlocal pages_walked
        if pages_walked >= MAX_TREE_PAGES or not 0 <= page_index < store.page_count:
            return
        pages_walked += 1
        page = store.page(page_index)
        page_type = c_tibx.page_header(page).type
        body = page[ENVELOPE_SIZE:]
        if page_type == c_tibx.PageType.LDIR:
            for cell in decode_page_cells(body, key_length, value_length):
                if len(cell.value) != LDIR_VALUE_SIZE:
                    continue
                yield from _visit(c_tibx.ldir_value(cell.value).child_offset // PAGE_SIZE)
        elif page_type == c_tibx.PageType.LEAF:
            yield from decode_page_cells(body, key_length, value_length)
        # other page types are silently skipped

    yield from _visit(root_page)


def iter_tree_cells(store: PageStore, sb: LsmSuperBlock) -> Iterator[LsmCell]:
    """Yield every record of an LSM tree: the mem-tree first (newest), then the ctrees.

    LSM merge semantics: for duplicate keys the first-yielded (newest) record wins;
    callers implement keep-first.
    """
    yield from iter_memtree_cells(sb)
    for ctree in sb.ctrees:
        if ctree.root_page is not None:
            yield from walk_tree(store, ctree.root_page, sb.key_length, sb.value_length)
