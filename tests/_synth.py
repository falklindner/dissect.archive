"""Synthetic, CRC-correct TIBX archive builders for hermetic tests.

Real archives can't be committed for every edge case (and corruption cases can't be
produced by Acronis at all), so structural tests build minimal valid page stores from
scratch — up to and including complete archives with a TLV directory, data_map /
segment_map LSM superblocks (mem-tree or on-disk LEAF/LDIR ctrees) and SG data
segments.

The fixtures are derived from those of ``acronis-tibx``, a private research project by mniedermaier that is no longer
publicly available, and extended here with the LSM layer. They are
cross-checked against archives produced by Acronis Cyber Protect / True Image 2026 -- a
synthetic page store is only useful for as long as a real parser would accept it.
"""

from __future__ import annotations

import struct
import sys
from typing import TYPE_CHECKING, NamedTuple

from dissect.archive.tibx.c_tibx import c_tibx
from dissect.archive.tibx.page import page_crc32c

if TYPE_CHECKING:
    from pathlib import Path

if sys.version_info >= (3, 14):
    from compression import zstd  # novermin
else:
    from backports import zstd

PAGE = 0x1000
BODY = PAGE - 8

SEG_PAYLOAD = b"hello synthetic volume" * 8

COMP_NONE = 0x0000
COMP_STORED_VARIANTS = (0x0002, 0x0003)
COMP_ZSTD = 0x0300

FORMAT_PASSWORD = 0x01


def finalize(pg: bytearray) -> bytes:
    """Stamp the page CRC-32C (big-endian at +0x04) and freeze the page."""
    pg[4:8] = struct.pack(">I", page_crc32c(bytes(pg)))
    return bytes(pg)


def arch_page(created_ms: int, modified_ms: int, uuid: bytes) -> bytes:
    """Build a minimal valid ARCH superblock page (no TLV directory)."""
    pg = bytearray(PAGE)
    pg[0], pg[1] = 0x41, 0x01
    pg[8:12] = b"ARCH"
    pg[0x18:0x20] = created_ms.to_bytes(8, "big")
    pg[0x20:0x28] = modified_ms.to_bytes(8, "big")
    pg[0x28:0x38] = uuid
    return finalize(pg)


def data_page(payload: bytes) -> bytes:
    """Build a single DATA page holding ``payload`` as one zstd SG segment."""
    pages = segment_pages(payload)
    if len(pages) != 1:
        raise ValueError("payload does not fit a single synthetic DATA page")
    return pages[0]


def segment_pages(payload: bytes, compression: int = COMP_ZSTD, data_key: bytes | None = None) -> list[bytes]:
    """Build the DATA page(s) of one segment: header page + continuation pages.

    With ``data_key`` set, an encrypted ``SE`` segment is produced: the compressed blob is
    AES-256-CBC encrypted (random IV prepended, PKCS#7 padded) and the key id is 1.
    """
    if compression == COMP_ZSTD:
        blob = zstd.compress(payload)
    elif compression == COMP_NONE or compression in COMP_STORED_VARIANTS:
        blob = payload  # all stored verbatim (the variants are only ever observed stored)
    else:
        raise ValueError(f"unsupported synthetic compression {compression:#06x}")

    if data_key is not None:
        from Crypto.Cipher import AES

        iv = bytes(range(16))
        padded = blob + bytes([16 - len(blob) % 16]) * (16 - len(blob) % 16)
        blob = iv + AES.new(data_key, AES.MODE_CBC, iv).encrypt(padded)
        magic, key_id = b"SE\x00\x00", 1
    else:
        magic, key_id = b"SG\x00\x01", 0

    first = bytearray(PAGE)
    first[0], first[1] = 0x41, 0xFF
    first[8:12] = magic
    struct.pack_into(">III", first, 0x0C, len(payload), len(blob), key_id)
    struct.pack_into(">HH", first, 0x18, compression, 0)
    first_take = min(len(blob), PAGE - 0x2C)
    first[0x2C : 0x2C + first_take] = blob[:first_take]
    pages = [finalize(first)]

    position = first_take
    while position < len(blob):
        cont = bytearray(PAGE)
        cont[0], cont[1] = 0x41, 0xFF
        chunk = blob[position : position + BODY]
        cont[8 : 8 + len(chunk)] = chunk
        pages.append(finalize(cont))
        position += len(chunk)
    return pages


def wrap_data_key(data_key: bytes, password: bytes, iter_log2: int = 12) -> bytes:
    """Build a keymap mem-tree blob wrapping ``data_key`` with ``password``.

    Mirrors the real layout ``[format=1][alg=3][iter_log2][reserved][salt·16][wrapped]``,
    preceded by a short opaque preamble like real archives carry. Raw-encoded (no LZ4).
    """
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import PBKDF2

    salt = bytes(range(100, 116))
    kek = PBKDF2(password, salt, dkLen=32, count=1 << iter_log2, hmac_hash_module=SHA256)
    padded = data_key + bytes([16]) * 16  # 32-byte key -> full padding block
    wrapped = AES.new(kek, AES.MODE_CBC, b"\x00" * 16).encrypt(padded)
    header = c_tibx.wrapped_key(format=FORMAT_PASSWORD, alg=3, iter_log2=iter_log2, _reserved=0, salt=salt)
    # Two leading bytes so the blob does not start on the format byte -- the parser locates
    # the wrapped key by scanning, and a blob at offset 0 would not exercise that.
    return b"\x00\x00" + header.dumps() + wrapped


def build_archive(uuid: bytes = b"\xab" * 16) -> bytes:
    """Build the minimal two-page archive: one ARCH root + one DATA page."""
    return arch_page(1000, 2000, uuid) + data_page(SEG_PAYLOAD)


def build_fat12_image(content: bytes, filename: bytes = b"HELLO   TXT") -> bytes:
    """A 64-sector FAT12 image with one 8.3 root file (cluster 2) holding ``content``.

    Small enough to embed in a synthetic archive, real enough for dissect.fat.
    """
    bps, spc, reserved, nfats, root_entries, fat_sectors, total = 512, 1, 1, 1, 16, 1, 64
    img = bytearray(total * bps)
    img[0:3] = b"\xeb\x3c\x90"
    img[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", img, 0x0B, bps)
    img[0x0D] = spc
    struct.pack_into("<H", img, 0x0E, reserved)
    img[0x10] = nfats
    struct.pack_into("<H", img, 0x11, root_entries)
    struct.pack_into("<H", img, 0x13, total)
    img[0x15] = 0xF8  # media descriptor
    struct.pack_into("<H", img, 0x16, fat_sectors)
    img[0x36:0x3E] = b"FAT12   "
    img[0x1FE:0x200] = b"\x55\xaa"
    fat_offset = reserved * bps
    img[fat_offset : fat_offset + 6] = bytes([0xF8, 0xFF, 0xFF, 0xFF, 0x0F, 0x00])
    root_offset = (reserved + nfats * fat_sectors) * bps
    entry = bytearray(32)
    entry[0:11] = filename
    entry[0x0B] = 0x20  # archive attribute
    struct.pack_into("<H", entry, 0x1A, 2)  # first cluster
    struct.pack_into("<I", entry, 0x1C, len(content))
    img[root_offset : root_offset + 32] = entry
    first_data = reserved + nfats * fat_sectors + (root_entries * 32 + bps - 1) // bps
    img[first_data * bps : first_data * bps + len(content)] = content
    return bytes(img)


def build_fat32_image(content: bytes, filename: bytes = b"HELLO   TXT") -> bytes:
    """A minimal FAT32 image with one 8.3 root file (cluster 3) holding ``content``.

    FAT type is decided by cluster count (65525+ clusters means FAT32, per the spec and
    dissect.fat), so the image is ~32 MiB *virtually* -- but nearly all of it is zeros.
    Pair it with :func:`sparse_extents` so only the boot sector, the head of the FAT and
    the two used data clusters are materialized in the archive, like Acronis would.
    """
    bps, spc, reserved, nfats = 512, 1, 1, 1
    clusters = 65552  # just past the FAT32 threshold
    fat_sectors = ((clusters + 2) * 4 + bps - 1) // bps
    first_data = reserved + nfats * fat_sectors
    total = first_data + clusters * spc

    img = bytearray(total * bps)
    img[0:3] = b"\xeb\x58\x90"
    img[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", img, 0x0B, bps)
    img[0x0D] = spc
    struct.pack_into("<H", img, 0x0E, reserved)
    img[0x10] = nfats
    img[0x15] = 0xF8  # media descriptor
    struct.pack_into("<I", img, 0x20, total)
    struct.pack_into("<I", img, 0x24, fat_sectors)
    struct.pack_into("<I", img, 0x2C, 2)  # root directory cluster
    img[0x52:0x5A] = b"FAT32   "
    img[0x1FE:0x200] = b"\x55\xaa"

    # Media/EOC reserved entries, then EOC-terminated chains: root dir (2), file (3)
    fat_offset = reserved * bps
    struct.pack_into("<IIII", img, fat_offset, 0x0FFFFFF8, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF)

    root_offset = first_data * bps  # cluster 2
    entry = bytearray(32)
    entry[0:11] = filename
    entry[0x0B] = 0x20  # archive attribute
    struct.pack_into("<H", entry, 0x14, 0)  # first cluster, high word
    struct.pack_into("<H", entry, 0x1A, 3)  # first cluster, low word
    struct.pack_into("<I", entry, 0x1C, len(content))
    img[root_offset : root_offset + 32] = entry
    file_offset = (first_data + spc) * bps  # cluster 3
    img[file_offset : file_offset + len(content)] = content
    return bytes(img)


# MS-DOS timestamp 2026-07-12 10:00:00 (a zero timestamp has month 0 and cannot parse)
DOS_TIMESTAMP = (46 << 25) | (7 << 21) | (12 << 16) | (10 << 11)


def build_exfat_image(content: bytes, filename: str = "hello.txt") -> bytes:
    """A 20-sector exFAT image with one root file (cluster 5) holding ``content``.

    Carries the mandatory volume label, allocation bitmap and up-case table directory
    entries; the file's clusters are flagged not-fragmented so no FAT chain is needed.

    Deliberately 1 sector per cluster: dissect.target's exFAT entry reads currently use
    the wrong RunlistStream block size for multi-sector clusters (see UPSTREAM.md), so a
    real-world 32 KiB-cluster image cannot pass a loader-level read test until that
    upstream fix lands.
    """
    sector = 512
    fat_sector, heap_sector, cluster_count = 2, 4, 16
    root_cluster, bitmap_cluster, upcase_cluster, file_cluster = 2, 3, 4, 5
    total = heap_sector + cluster_count

    img = bytearray(total * sector)
    img[0:3] = b"\xeb\x76\x90"
    img[3:11] = b"EXFAT   "
    struct.pack_into("<QQ", img, 0x40, 0, total)  # partition offset, volume sector count
    struct.pack_into("<IIIII", img, 0x50, fat_sector, 1, heap_sector, cluster_count, root_cluster)
    struct.pack_into("<I", img, 0x64, 0x1234ABCD)  # volume serial
    img[0x69] = 1  # filesystem revision 1.0
    img[0x6C] = 9  # 512-byte sectors (1 << 9)
    img[0x6D] = 0  # 1 sector per cluster
    img[0x6E] = 1  # number of FATs
    img[0x6F] = 0x80  # drive select
    img[0x1FE:0x200] = b"\x55\xaa"

    # FAT: media/reserved markers, then every used cluster is a single-cluster EOC chain
    struct.pack_into("<6I", img, fat_sector * sector, 0xFFFFFFF8, *([0xFFFFFFFF] * 5))

    def heap(cluster: int) -> int:
        return (heap_sector + cluster - 2) * sector

    name_utf16 = filename.encode("utf-16-le")
    entries = [
        # Volume label (mandatory for dissect.fat)
        bytes([0x83, 4]) + "TIBX".encode("utf-16-le").ljust(30, b"\x00"),
        # Allocation bitmap
        bytes([0x81, 0]) + b"\x00" * 18 + struct.pack("<IQ", bitmap_cluster, (cluster_count + 7) // 8),
        # Up-case table
        bytes([0x82])
        + b"\x00" * 3
        + struct.pack("<I", 0xE619D30D)
        + b"\x00" * 12
        + struct.pack("<IQ", upcase_cluster, 128),
        # File set: file entry + stream extension (not_fragmented) + one filename entry
        struct.pack("<BBHHH3I", 0x85, 2, 0, 0x20, 0, DOS_TIMESTAMP, DOS_TIMESTAMP, DOS_TIMESTAMP) + b"\x00" * 12,
        struct.pack("<BBBBHHQ", 0xC0, 0x03, 0, len(filename), 0, 0, len(content))
        + b"\x00" * 4
        + struct.pack("<IQ", file_cluster, len(content)),
        bytes([0xC1, 0]) + name_utf16.ljust(30, b"\x00"),
    ]
    img[heap(root_cluster) : heap(root_cluster) + 32 * len(entries)] = b"".join(entries)
    img[heap(bitmap_cluster) : heap(bitmap_cluster) + 2] = b"\x0f\x00"  # clusters 2-5 allocated
    img[heap(file_cluster) : heap(file_cluster) + len(content)] = content
    return bytes(img)


def sparse_extents(volume_id: int, image: bytes, granularity: int = 0x1000) -> list[ExtentSpec]:
    """Split ``image`` into one extent per non-zero ``granularity``-sized chunk.

    Mirrors how Acronis stores only allocated ranges. The final chunk is always kept,
    zero or not, so the reconstructed volume spans the full image size.
    """
    zero_chunk = bytes(granularity)
    extents = []
    for offset in range(0, len(image), granularity):
        chunk = image[offset : offset + granularity]
        is_last = offset + granularity >= len(image)
        if chunk != zero_chunk[: len(chunk)] or is_last:
            extents.append(ExtentSpec(volume_id, offset, chunk))
    return extents


def write_split_parts(archive: bytes, directory: Path, name: str, split_points: tuple[int, ...]) -> list[Path]:
    """Write ``archive`` as a split set (``Name.tibx`` + ``Name-0001.tibx`` + ...)."""
    bounds = [0, *split_points, len(archive)]
    parts = []
    for i in range(len(bounds) - 1):
        part_name = f"{name}.tibx" if i == 0 else f"{name}-{i:04d}.tibx"
        part = directory / part_name
        part.write_bytes(archive[bounds[i] : bounds[i + 1]])
        parts.append(part)
    return parts


# --- LSM layer builders ----------------------------------------------------


class Cell(NamedTuple):
    key: bytes
    value: bytes
    alive: bool = True


def compact_cells(cells: list[Cell]) -> bytes:
    """Encode cells as a compact cell stream (groups of up to 24 with alive-bitmaps)."""
    out = bytearray()
    for group_start in range(0, len(cells), 24):
        group = cells[group_start : group_start + 24]
        bitmap = 0
        for i, cell in enumerate(group):
            if cell.alive:
                bitmap |= 1 << i
        b3 = bitmap & 0xFF
        b2 = (bitmap >> 8) & 0xFF
        b1 = (bitmap >> 16) & 0xFF
        out += struct.pack("<I", len(group) | (b1 << 8) | (b2 << 16) | (b3 << 24))
        for cell in group:
            out += cell.key
            if cell.alive:
                out += cell.value
    return bytes(out)


def lsb(
    key_length: int,
    value_length: int,
    memtree_cells: list[Cell] | None = None,
    ctrees: list[tuple[int, int]] | None = None,
    seq: int = 1,
    memtree_blob: bytes | None = None,
    memtree_encoding: int = 0,
) -> bytes:
    """Build one L-SB TLV payload.

    ``memtree_cells`` go into the residual mem-tree (raw compact stream unless an
    explicit pre-encoded ``memtree_blob`` + ``memtree_encoding`` is given);
    ``ctrees`` is a list of ``(root_byte_offset, item_count)`` on-disk run slots.
    """
    memtree_cells = memtree_cells or []
    ctrees = ctrees or []
    if memtree_blob is None:
        memtree_blob = compact_cells(memtree_cells) if memtree_cells else b""

    record = bytearray(0x178)
    record[0:4] = b"L-SB"
    ctree_count = max(2, len(ctrees))
    record[4] = 1  # format version
    record[5] = ctree_count - 2
    record[6] = 10 - 2  # ctree_max
    struct.pack_into(">IIII", record, 8, seq, 0, key_length, value_length)
    for i, (root_offset, item_count) in enumerate(ctrees):
        slot = 0x18 + i * 32
        struct.pack_into(">QQI", record, slot, root_offset, PAGE, item_count)
    # mem-tree header at +0x158: encoding, pad, node_count, extra_len, pages_total
    record[0x158] = memtree_encoding
    struct.pack_into(">H", record, 0x15A, len(memtree_cells))
    struct.pack_into(">II", record, 0x15C, len(memtree_blob), 0)
    return bytes(record) + memtree_blob


def tlv_directory(slots: dict[int, bytes]) -> bytes:
    """Encode a 19-slot TLV directory (missing slots are zero-length)."""
    out = bytearray()
    for index in range(19):
        payload = slots.get(index, b"")
        out += struct.pack(">I", len(payload))
        out += payload
        stride = (len(payload) + 7) & ~3
        out += b"\x00" * (stride - 4 - len(payload))
    return bytes(out)


def arch_header_page(
    slots: dict[int, bytes],
    seq: int = 1,
    created_ms: int = 1000,
    modified_ms: int = 2000,
    uuid: bytes = b"\xab" * 16,
) -> bytes:
    """Build a full ARCH commit-root page with a TLV directory (single page)."""
    directory = tlv_directory(slots)
    header_size = 0x400 + len(directory)
    if 8 + header_size > PAGE:
        raise ValueError("synthetic ARCH header does not fit a single page")

    pg = bytearray(PAGE)
    pg[0], pg[1] = 0x41, 0x01
    pg[8:12] = b"ARCH"
    struct.pack_into(">I", pg, 0x0C, header_size)  # body+4: header size
    struct.pack_into(">H", pg, 0x10, 8)  # body+8: header version
    pg[0x18:0x20] = created_ms.to_bytes(8, "big")
    pg[0x20:0x28] = modified_ms.to_bytes(8, "big")
    pg[0x28:0x38] = uuid
    struct.pack_into(">Q", pg, 8 + 0x188, seq)  # body+0x188: commit sequence
    pg[8 + 0x400 : 8 + 0x400 + len(directory)] = directory
    return finalize(pg)


def lsm_page(page_type: int, magic: bytes, cells: list[Cell], key_length: int, compact: bool) -> bytes:
    """Build a LEAF (compact) or LDIR (plain ``key || value``) page, raw encoding."""
    stream = compact_cells(cells) if compact else b"".join(cell.key + cell.value for cell in cells)
    if 8 + 0x34 + len(stream) > PAGE:
        raise ValueError("synthetic LSM page overflow")

    pg = bytearray(PAGE)
    pg[0], pg[1] = 0x41, page_type
    body = 8
    pg[body : body + 4] = magic
    pg[body + 4] = 1  # version
    pg[body + 5] = 0  # encoding: raw
    struct.pack_into(">H", pg, body + 6, len(cells))
    struct.pack_into(">II", pg, body + 8, len(stream), len(stream))
    struct.pack_into(">I", pg, body + 16, key_length)
    pg[body + 0x34 : body + 0x34 + len(stream)] = stream
    return finalize(pg)


def data_map_key(volume_id: int, source_offset: int, length: int, slice_id: int, extent_id: int) -> bytes:
    return (
        struct.pack(">QQ", volume_id, source_offset)
        + length.to_bytes(3, "big")
        + struct.pack(">IQ", slice_id, extent_id)
    )


def data_map_value(segment_id: int, extent_index: int = 0xFFFF) -> bytes:
    return struct.pack(">QH", segment_id, extent_index)


def segment_map_value(page_count: int, page_offset: int, slice_id: int = 2) -> bytes:
    # Mixed endianness: page_count LE, page_offset and slice_id BE, then a 20-byte hash
    return struct.pack("<I", page_count) + struct.pack(">II", page_offset, slice_id) + b"\x00" * 20


class ExtentSpec(NamedTuple):
    """One extent for :func:`build_lsm_archive`: ``data`` placed at ``source_offset``.

    Extents with the same (non-None) ``segment_group`` share one segment: their data
    is concatenated in list order, each chunk aligned up to 16 bytes, and their
    data_map values carry sequential extent indexes instead of the whole-segment
    sentinel — mirroring real Acronis metadata streams.
    """

    volume_id: int
    source_offset: int
    data: bytes
    slice_id: int = 2
    extent_id: int = 0  # 0 = auto-assign in build order
    segment_group: int | None = None


def build_lsm_archive(
    extents: list[ExtentSpec],
    *,
    use_ctree: bool = False,
    compression: int = COMP_ZSTD,
    uuid: bytes = b"\xab" * 16,
    password: bytes | None = None,
    page_base: int = 0,
    extra_slots: dict[int, bytes] | None = None,
) -> bytes:
    """Build a complete synthetic archive: ARCH header + LSM maps + SG segments.

    Each extent (or shared segment group) becomes one segment. The data_map /
    segment_map records live in the L-SB mem-trees by default, or in on-disk LEAF
    ctrees when ``use_ctree`` is set. With ``password`` set, segments are AES-256-CBC
    encrypted and a keymap tree wraps the data key.

    ``page_base`` makes all absolute page/byte offsets (segment_map, ctrees) global
    for a *version file* mapped at that logical page offset of a version set;
    ``extra_slots`` adds raw TLV payloads (e.g. slot 18, the file table).
    """
    data_key = bytes(range(32)) if password is not None else None
    pages, dm_cells, sm_cells, _ = _segments_and_maps(
        extents, start_page=page_base + 1, compression=compression, data_key=data_key
    )

    if use_ctree:
        next_page = page_base + 1 + len(pages)
        dm_leaf_page, sm_leaf_page = next_page, next_page + 1
        pages.append(lsm_page(0x03, b"LEAF", dm_cells, key_length=31, compact=True))
        pages.append(lsm_page(0x03, b"LEAF", sm_cells, key_length=8, compact=True))
        dm_sb = lsb(31, 10, ctrees=[(dm_leaf_page * PAGE, len(dm_cells))])
        sm_sb = lsb(8, 32, ctrees=[(sm_leaf_page * PAGE, len(sm_cells))])
    else:
        dm_sb = lsb(31, 10, memtree_cells=dm_cells)
        sm_sb = lsb(8, 32, memtree_cells=sm_cells)

    slots = {1: dm_sb, 2: sm_sb}
    if password is not None:
        keymap_blob = wrap_data_key(data_key, password)
        slots[7] = lsb(0, 0, memtree_cells=[Cell(b"", b"")], memtree_blob=keymap_blob, memtree_encoding=0)
    if extra_slots:
        slots.update(extra_slots)

    header = arch_header_page(slots, uuid=uuid)
    return header + b"".join(pages)


def file_table(offsets: list[int]) -> bytes:
    """Encode a TLV[18] file table: the logical byte offset of each archive file."""
    return b"".join(struct.pack(">IQ", index, offset) for index, offset in enumerate(offsets))


def build_version_set(
    extents: list[ExtentSpec], stub_logical_pages: int = 8, use_ctree: bool = False
) -> tuple[bytes, bytes]:
    """Build a two-file version set: a compacted base stub + one version file.

    Mirrors a "single version scheme" cleanup: the base file physically holds only an
    empty initial root but logically spans ``stub_logical_pages`` (the removed pages of
    the deleted old version), and the version file, mapped at that logical offset by
    the TLV[18] file table, carries the live backup with global absolute offsets.
    """
    table = file_table([0, stub_logical_pages * PAGE])
    stub = arch_header_page({1: lsb(31, 10), 2: lsb(8, 32), 18: table}, modified_ms=1, uuid=b"\xaa" * 16)
    version = build_lsm_archive(extents, use_ctree=use_ctree, page_base=stub_logical_pages, extra_slots={18: table})
    return stub, version


def _segments_and_maps(
    extents: list[ExtentSpec],
    *,
    start_page: int,
    compression: int,
    data_key: bytes | None,
) -> tuple[list[bytes], list[Cell], list[Cell], int]:
    """Build the SG segment pages plus the data_map/segment_map cells for ``extents``.

    Segment pages are placed starting at absolute page ``start_page``; returns
    ``(pages, dm_cells, sm_cells, next_page)``.
    """
    pages: list[bytes] = []
    next_page = start_page
    dm_cells: list[Cell] = []
    sm_cells: list[Cell] = []

    # Group shared-segment extents, preserving list order within a group
    groups: dict[object, list[tuple[int, ExtentSpec]]] = {}
    for i, spec in enumerate(extents):
        key = ("shared", spec.segment_group) if spec.segment_group is not None else ("own", i)
        groups.setdefault(key, []).append((i, spec))

    for group_index, members in enumerate(groups.values()):
        segment_id = 100 + group_index
        shared = len(members) > 1 or members[0][1].segment_group is not None

        payload = bytearray()
        for position, (i, spec) in enumerate(members):
            if position > 0:
                payload += b"\x00" * (-len(payload) % 16)  # chunks align up to 16 bytes
            extent_id = spec.extent_id or (i + 1)
            extent_index = position if shared else 0xFFFF
            dm_cells.append(
                Cell(
                    data_map_key(spec.volume_id, spec.source_offset, len(spec.data), spec.slice_id, extent_id),
                    data_map_value(segment_id, extent_index),
                )
            )
            payload += spec.data

        seg_pages = segment_pages(bytes(payload), compression=compression, data_key=data_key)
        sm_cells.append(Cell(struct.pack(">Q", segment_id), segment_map_value(len(seg_pages), next_page)))
        pages.extend(seg_pages)
        next_page += len(seg_pages)

    # data_map keys must be in lexicographic (volume, offset) order for realism
    dm_cells.sort(key=lambda c: c.key)
    sm_cells.sort(key=lambda c: c.key)
    return pages, dm_cells, sm_cells, next_page


def build_multiroot_archive(roots: list[list[ExtentSpec]], *, compression: int = COMP_ZSTD) -> bytes:
    """Build an archive with several ARCH commit roots (a synthetic backup chain).

    Each entry in ``roots`` is the extent set of one recovery point, oldest first; each
    becomes its own ARCH header + segments in one page store. The live root is the last
    (highest-offset). An empty initial root is prepended, as real archives carry one.
    """
    out = bytearray()
    page_cursor = 0

    # Empty initial root (freshly-created archive, before any data)
    empty = arch_header_page({1: lsb(31, 10), 2: lsb(8, 32)}, modified_ms=1, uuid=b"\xaa" * 16)
    out += empty
    page_cursor += 1

    for root_index, extents in enumerate(roots):
        pages, dm_cells, sm_cells, next_page = _segments_and_maps(
            extents, start_page=page_cursor + 1, compression=compression, data_key=None
        )
        dm_sb = lsb(31, 10, memtree_cells=dm_cells)
        sm_sb = lsb(8, 32, memtree_cells=sm_cells)
        header = arch_header_page({1: dm_sb, 2: sm_sb}, modified_ms=1000 * (root_index + 1), uuid=b"\xab" * 16)
        out += header + b"".join(pages)
        page_cursor = next_page

    return bytes(out)
