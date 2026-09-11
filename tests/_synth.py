"""Synthetic, CRC-correct TIBX archive builders for hermetic tests.

Real archives can't be committed for every edge case (and corruption cases can't be
produced by Acronis at all), so structural tests build minimal valid page stores from
scratch — up to and including complete archives with a TLV directory, data_map /
segment_map LSM superblocks (mem-tree or on-disk LEAF/LDIR ctrees) and SG data
segments.

Every TIBX record is built from the same :mod:`c_tibx` structure the parser reads it
with, so a builder cannot drift from the parser's idea of the layout. Only the foreign
filesystem images (FAT, exFAT) are assembled by hand.

The fixtures are derived from those of the MIT-licensed ``acronis-tibx`` (see
``THIRD_PARTY_NOTICES.md``) and extended here with the LSM layer. They are cross-checked
against archives produced by Acronis Cyber Protect / True Image 2026 -- a synthetic page
store is only useful for as long as a real parser would accept it.
"""

from __future__ import annotations

import struct
import sys
from typing import TYPE_CHECKING, NamedTuple

from dissect.archive.tibx.c_tibx import (
    ENVELOPE_SIZE,
    LSB_CTREE_OFFSET,
    LSB_FIXED_SIZE,
    LSB_MEMTREE_OFFSET,
    LSM_CELL_GROUP_MAX,
    LSM_CELL_STREAM_OFFSET,
    PAGE_MARKER,
    SEGMENT_HEADER_OFFSET,
    SEGMENT_PAYLOAD_OFFSET,
    TLV_DIRECTORY_OFFSET,
    TLV_SLOT_COUNT,
    c_tibx,
)
from dissect.archive.tibx.page import page_crc32c

if TYPE_CHECKING:
    from pathlib import Path

if sys.version_info >= (3, 14):
    from compression import zstd  # novermin
else:
    from backports import zstd

PAGE = 0x1000
BODY = PAGE - ENVELOPE_SIZE

SEG_PAYLOAD = b"hello synthetic volume" * 8

COMP_NONE = 0x0000
COMP_STORED_VARIANTS = (0x0002, 0x0003)
COMP_ZSTD = 0x0300

FORMAT_PASSWORD = 0x01

# Segment cipher ids, as carried in the wrapped-key header -> AES key length in bytes
GCM_ALGS = (5, 6, 7)
KEY_LENGTH = {1: 16, 2: 24, 3: 32, 5: 16, 6: 24, 7: 32}

# The ARCH header body offset of the commit sequence. Not modelled in c_tibx: the parser
# never reads it, but real archives carry one, so the synthetic ones do too.
ARCH_COMMIT_SEQUENCE_OFFSET = 0x188


def blank_page(page_type: int) -> bytearray:
    """A zeroed page carrying just the envelope marker and ``page_type``."""
    page = bytearray(PAGE)
    page[:ENVELOPE_SIZE] = c_tibx.page_header(marker=PAGE_MARKER, type=c_tibx.PageType(page_type)).dumps()
    return page


def finalize(pg: bytearray) -> bytes:
    """Stamp the page CRC-32C into the envelope and freeze the page."""
    header = c_tibx.page_header(bytes(pg[:ENVELOPE_SIZE]))
    header.crc32c = page_crc32c(bytes(pg))
    pg[:ENVELOPE_SIZE] = header.dumps()
    return bytes(pg)


def arch_page(created_ms: int, modified_ms: int, uuid: bytes) -> bytes:
    """Build a minimal valid ARCH superblock page (no TLV directory)."""
    pg = blank_page(c_tibx.PageType.ARCH)
    body = c_tibx.arch_header(magic=b"ARCH", created_ms=created_ms, modified_ms=modified_ms, archive_uuid=uuid)
    pg[ENVELOPE_SIZE : ENVELOPE_SIZE + len(c_tibx.arch_header)] = body.dumps()
    return finalize(pg)


def data_page(payload: bytes) -> bytes:
    """Build a single DATA page holding ``payload`` as one zstd SG segment."""
    pages = segment_pages(payload)
    if len(pages) != 1:
        raise ValueError("payload does not fit a single synthetic DATA page")
    return pages[0]


def segment_pages(
    payload: bytes, compression: int = COMP_ZSTD, data_key: bytes | None = None, alg: int = 3
) -> list[bytes]:
    """Build the DATA page(s) of one segment: header page + continuation pages.

    With ``data_key`` set, an encrypted ``SE`` segment is produced and the key id is 1.
    ``alg`` selects the framing, mirroring what Acronis writes: a CBC id (1-3) prepends a
    random IV and PKCS#7-pads, a GCM id (5-7) prepends the IV and the tag and leaves the
    ciphertext exactly as long as the plaintext.
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
        if alg in GCM_ALGS:
            ciphertext, tag = AES.new(data_key, AES.MODE_GCM, nonce=iv).encrypt_and_digest(blob)
            blob = c_tibx.segment_gcm_header(iv=iv, tag=tag).dumps() + ciphertext
        else:
            padded = blob + bytes([16 - len(blob) % 16]) * (16 - len(blob) % 16)
            ciphertext = AES.new(data_key, AES.MODE_CBC, iv).encrypt(padded)
            blob = c_tibx.segment_cbc_header(iv=iv).dumps() + ciphertext
        magic, version, key_id = b"SE", 0, 1
    else:
        magic, version, key_id = b"SG", 1, 0

    first = blank_page(c_tibx.PageType.DATA)
    header = c_tibx.segment_header(
        magic=magic, version=version, length=len(payload), zlength=len(blob), key_id=key_id, compression=compression
    )
    first[SEGMENT_HEADER_OFFSET : SEGMENT_HEADER_OFFSET + len(c_tibx.segment_header)] = header.dumps()
    first_take = min(len(blob), PAGE - SEGMENT_PAYLOAD_OFFSET)
    first[SEGMENT_PAYLOAD_OFFSET : SEGMENT_PAYLOAD_OFFSET + first_take] = blob[:first_take]
    pages = [finalize(first)]

    position = first_take
    while position < len(blob):
        cont = blank_page(c_tibx.PageType.DATA)
        chunk = blob[position : position + BODY]
        cont[ENVELOPE_SIZE : ENVELOPE_SIZE + len(chunk)] = chunk
        pages.append(finalize(cont))
        position += len(chunk)
    return pages


def wrap_data_key(data_key: bytes, password: bytes, iter_log2: int = 12, alg: int = 3) -> bytes:
    """Build a keymap mem-tree blob wrapping ``data_key`` with ``password``.

    Mirrors the real layout ``[format=1][alg][iter_log2][reserved][salt·16][wrapped]``,
    preceded by a short opaque preamble like real archives carry. Raw-encoded (no LZ4).

    The wrap is AES-256-CBC whatever ``alg`` says, because ``alg`` names the cipher used
    for the *data segments* -- Acronis wraps the key the same way for CBC and GCM alike.
    """
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import PBKDF2

    salt = bytes(range(100, 116))
    kek = PBKDF2(password, salt, dkLen=32, count=1 << iter_log2, hmac_hash_module=SHA256)
    pad = 16 - len(data_key) % 16
    padded = data_key + bytes([pad]) * pad
    wrapped = AES.new(kek, AES.MODE_CBC, b"\x00" * 16).encrypt(padded)
    header = c_tibx.wrapped_key(format=FORMAT_PASSWORD, alg=alg, iter_log2=iter_log2, _reserved=0, salt=salt)
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
    for group_start in range(0, len(cells), LSM_CELL_GROUP_MAX):
        group = cells[group_start : group_start + LSM_CELL_GROUP_MAX]
        alive = 0
        for i, cell in enumerate(group):
            if cell.alive:
                alive |= 1 << i
        out += c_tibx.lsm_cell_group_header(count=len(group), alive=alive).dumps()
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

    record = bytearray(LSB_FIXED_SIZE)
    superblock = c_tibx.lsm_superblock(
        magic=b"L-SB",
        format_version=1,
        ctree_count_minus_2=max(2, len(ctrees)) - 2,
        ctree_max_minus_2=10 - 2,
        seq=seq,
        key_length=key_length,
        value_length=value_length,
    )
    record[: len(c_tibx.lsm_superblock)] = superblock.dumps()
    for i, (root_offset, item_count) in enumerate(ctrees):
        slot = LSB_CTREE_OFFSET + i * len(c_tibx.ctree_ref)
        ref = c_tibx.ctree_ref(offset=root_offset, num_pages=PAGE, item_count=item_count)
        record[slot : slot + len(c_tibx.ctree_ref)] = ref.dumps()
    memtree = c_tibx.lsm_memtree_header(
        encoding=memtree_encoding, node_count=len(memtree_cells), extra_len=len(memtree_blob)
    )
    record[LSB_MEMTREE_OFFSET : LSB_MEMTREE_OFFSET + len(c_tibx.lsm_memtree_header)] = memtree.dumps()
    return bytes(record) + memtree_blob


def tlv_directory(slots: dict[int, bytes]) -> bytes:
    """Encode a 19-slot TLV directory (missing slots are zero-length)."""
    out = bytearray()
    for index in range(TLV_SLOT_COUNT):
        payload = slots.get(index, b"")
        out += c_tibx.tlv_header(length=len(payload)).dumps()
        out += payload
        out += b"\x00" * (-len(out) % 4)  # the next entry starts on a 4-byte boundary
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
    header_size = TLV_DIRECTORY_OFFSET + len(directory)
    if ENVELOPE_SIZE + header_size > PAGE:
        raise ValueError("synthetic ARCH header does not fit a single page")

    pg = blank_page(c_tibx.PageType.ARCH)
    body = c_tibx.arch_header(
        magic=b"ARCH",
        header_size=header_size,
        header_version=8,
        created_ms=created_ms,
        modified_ms=modified_ms,
        archive_uuid=uuid,
    )
    pg[ENVELOPE_SIZE : ENVELOPE_SIZE + len(c_tibx.arch_header)] = body.dumps()
    sequence = ENVELOPE_SIZE + ARCH_COMMIT_SEQUENCE_OFFSET
    pg[sequence : sequence + 8] = c_tibx.uint64.dumps(seq)
    pg[ENVELOPE_SIZE + TLV_DIRECTORY_OFFSET : ENVELOPE_SIZE + header_size] = directory
    return finalize(pg)


def lsm_page(page_type: int, magic: bytes, cells: list[Cell], key_length: int, compact: bool) -> bytes:
    """Build a LEAF (compact) or LDIR (plain ``key || value``) page, raw encoding."""
    stream = compact_cells(cells) if compact else b"".join(cell.key + cell.value for cell in cells)
    if ENVELOPE_SIZE + LSM_CELL_STREAM_OFFSET + len(stream) > PAGE:
        raise ValueError("synthetic LSM page overflow")

    pg = blank_page(page_type)
    header = c_tibx.lsm_page_header(
        magic=magic,
        version=1,
        encoding=0,  # raw
        cell_count=len(cells),
        uncompressed_size=len(stream),
        on_disk_size=len(stream),
        key_size_param=key_length,
    )
    pg[ENVELOPE_SIZE : ENVELOPE_SIZE + len(c_tibx.lsm_page_header)] = header.dumps()
    start = ENVELOPE_SIZE + LSM_CELL_STREAM_OFFSET
    pg[start : start + len(stream)] = stream
    return finalize(pg)


def data_map_key(volume_id: int, source_offset: int, length: int, slice_id: int, extent_id: int) -> bytes:
    return c_tibx.data_map_key(
        volume_id=volume_id,
        source_offset=source_offset,
        extent_length=length,
        slice_id=slice_id,
        extent_id=extent_id,
    ).dumps()


def data_map_value(segment_id: int, extent_index: int = 0xFFFF) -> bytes:
    return c_tibx.data_map_value(segment_id=segment_id, extent_index=extent_index).dumps()


def segment_map_key(segment_id: int) -> bytes:
    return c_tibx.segment_map_key(segment_id=segment_id).dumps()


def segment_map_value(page_count: int, page_offset: int, slice_id: int = 2) -> bytes:
    return c_tibx.segment_map_value(
        page_count=page_count.to_bytes(4, "little"), page_offset=page_offset, slice_id=slice_id
    ).dumps()


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


# TLV[5] slices records are fixed width; only the leading fields are understood, and real
# archives pad the rest out to this length.
SLICE_VALUE_LENGTH = 132


def slice_record(guid: bytes, created_ms: int, modified_ms: int) -> bytes:
    """One TLV[5] slices record value: a backup's GUID and its start/finish times."""
    body = c_tibx.slice_record(guid=guid, created_ms=created_ms, modified_ms=modified_ms).dumps()
    return body + b"\x00" * (SLICE_VALUE_LENGTH - len(body))


def build_lsm_archive(
    extents: list[ExtentSpec],
    *,
    use_ctree: bool = False,
    compression: int = COMP_ZSTD,
    uuid: bytes = b"\xab" * 16,
    password: bytes | None = None,
    alg: int = 3,
    page_base: int = 0,
    slices: list[int] | None = None,
    extra_slots: dict[int, bytes] | None = None,
) -> bytes:
    """Build a complete synthetic archive: ARCH header + LSM maps + SG segments.

    Each extent (or shared segment group) becomes one segment. The data_map /
    segment_map records live in the L-SB mem-trees by default, or in on-disk LEAF
    ctrees when ``use_ctree`` is set. With ``password`` set, segments are encrypted
    under ``alg`` (AES-256-CBC by default) and a keymap tree wraps the data key.

    ``page_base`` makes all absolute page/byte offsets (segment_map, ctrees) global
    for a *version file* mapped at that logical page offset of a version set;
    ``extra_slots`` adds raw TLV payloads (e.g. slot 18, the file table).
    """
    data_key = bytes(range(KEY_LENGTH[alg])) if password is not None else None
    pages, dm_cells, sm_cells, _ = _segments_and_maps(
        extents, start_page=page_base + 1, compression=compression, data_key=data_key, alg=alg
    )

    if use_ctree:
        next_page = page_base + 1 + len(pages)
        dm_leaf_page, sm_leaf_page = next_page, next_page + 1
        pages.append(lsm_page(c_tibx.PageType.LEAF, b"LEAF", dm_cells, key_length=31, compact=True))
        pages.append(lsm_page(c_tibx.PageType.LEAF, b"LEAF", sm_cells, key_length=8, compact=True))
        dm_sb = lsb(31, 10, ctrees=[(dm_leaf_page * PAGE, len(dm_cells))])
        sm_sb = lsb(8, 32, ctrees=[(sm_leaf_page * PAGE, len(sm_cells))])
    else:
        dm_sb = lsb(31, 10, memtree_cells=dm_cells)
        sm_sb = lsb(8, 32, memtree_cells=sm_cells)

    slots = {1: dm_sb, 2: sm_sb}
    if slices:
        # One record per backup, keyed by slice id, exactly as the extents reference them.
        # GUIDs and times are derived from the slice id so a test can predict them.
        slots[5] = lsb(
            4,
            SLICE_VALUE_LENGTH,
            memtree_cells=[
                Cell(
                    c_tibx.slice_key(slice_id=slice_id).dumps(),
                    slice_record(bytes([slice_id]) * 16, 1000 * slice_id, 1000 * slice_id + 10),
                )
                for slice_id in slices
            ],
        )
    if password is not None:
        keymap_blob = wrap_data_key(data_key, password, alg=alg)
        slots[7] = lsb(0, 0, memtree_cells=[Cell(b"", b"")], memtree_blob=keymap_blob, memtree_encoding=0)
    if extra_slots:
        slots.update(extra_slots)

    header = arch_header_page(slots, uuid=uuid)
    return header + b"".join(pages)


def file_table(offsets: list[int]) -> bytes:
    """Encode a TLV[18] file table: the logical byte offset of each archive file."""
    return b"".join(
        c_tibx.file_table_entry(index=index, byte_offset=offset).dumps() for index, offset in enumerate(offsets)
    )


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
    alg: int = 3,
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

        seg_pages = segment_pages(bytes(payload), compression=compression, data_key=data_key, alg=alg)
        sm_cells.append(Cell(segment_map_key(segment_id), segment_map_value(len(seg_pages), next_page)))
        pages.extend(seg_pages)
        next_page += len(seg_pages)

    # data_map keys must be in lexicographic (volume, offset) order for realism
    dm_cells.sort(key=lambda c: c.key)
    sm_cells.sort(key=lambda c: c.key)
    return pages, dm_cells, sm_cells, next_page
