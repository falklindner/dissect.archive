"""Structure definitions for the Acronis TIBX ("archive3") file format.

A ``.tibx`` is a flat sequence of 4096-byte pages. Byte 0 of every page is the marker
``0x41`` (``'A'``), byte 1 the page type, and a CRC-32C of the page (checksum bytes
zeroed) is stored at ``+0x04``. The page content ("body") starts after this 8-byte
envelope.

Most multi-byte fields are big-endian, so the definitions are loaded into a big-endian
cstruct instance. cstruct applies one byte order per instance, so the one little-endian
field of a TIBX record -- the segment_map ``page_count`` -- is declared as raw bytes and
decoded where it is used; the LEAF sequence id is little-endian too, but unused. The LSM
cell-group header only looks little-endian: it is a count byte followed by a big-endian
24-bit bitmap.

:data:`c_boot` holds the few filesystem boot-sector fields the parser reads to size a
volume. Those formats are not TIBX's and are little-endian, so they get their own instance.

The format is not documented by Acronis. These definitions encode the format findings of
the MIT-licensed ``acronis-tibx`` (see ``THIRD_PARTY_NOTICES.md``) and were confirmed
against archives written by Acronis Cyber Protect / True Image 2026; fields still marked
``_reserved`` or ``_pad`` are ones whose meaning is not yet established.
"""

from __future__ import annotations

from dissect.cstruct import cstruct

tibx_def = """
#define PAGE_SIZE 0x1000

enum PageType : uint8 {
    ARCH    = 0x01,     /* superblock / commit root (+ continuation pages) */
    ARCI    = 0x02,     /* commit info */
    LEAF    = 0x03,     /* LSM tree leaf */
    LDIR    = 0x04,     /* LSM tree directory */
    GOLOMB  = 0x05,     /* dedup_map Golomb filter */
    DATA    = 0xFF      /* data segment (SG header or continuation) */
};

enum EncrAlg : uint8 {
    NONE            = 0,    // none
    AES_128_CBC     = 1,    // aes-128-cbc
    AES_192_CBC     = 2,    // aes-192-cbc
    AES_256_CBC     = 3,    // aes-256-cbc
    GOST2015        = 4,    // gost2015
    AES_128_GCM     = 5,    // aes-128-gcm
    AES_192_GCM     = 6,    // aes-192-gcm
    AES_256_GCM     = 7     // aes-256-gcm
};

enum ComprLvl : uint8 {
  NONE   = 0,  // "none"
  LOW    = 1,  // "low"
  NORMAL = 2,  // "normal"
  HIGH   = 3   // "high"
};

struct page_header {
    uint8       marker;                 /* always 0x41 'A' */
    PageType    type;
    uint16      _pad;
    uint32      crc32c;                 /* CRC-32C of the page, checksum bytes zeroed */
};

/* Start of an ARCH header body, i.e. of an ARCH page after its envelope. The TLV
 * directory follows at TLV_DIRECTORY_OFFSET into the body. */
struct arch_header {
    char        magic[4];               /* "ARCH" */
    uint32      header_size;            /* total header body size, may span pages */
    uint16      header_version;         /* 8 in current archives */
    ComprLvl    compr_lvl;
    EncrAlg     encr_alg;
    uint8_t     dedup;                  /* 0 = "off", 1 = "on" */
    uint8_t     hash_alg;
    uint8_t     chunking_alg;
    uint8_t     hash_window_width;
    uint64      created_ms;             /* creation time, ms since Unix epoch */
    uint64      modified_ms;            /* commit time, ms since Unix epoch */
    char        archive_uuid[16];
};

struct arch_superblock {
    page_header header;
    arch_header body;
};

/* One TLV directory entry: the payload follows, and the next entry starts at the next
 * 4-byte boundary after it */
struct tlv_header {
    uint32      length;
};

/* Data segment header, at page offset +0x08 of a DATA page */
struct segment_header {
    char        magic[2];               /* "SG" plaintext / "SE" encrypted */
    uint16      version;                /* 0x0001 */
    uint32      length;                 /* uncompressed payload size */
    uint32      zlength;                /* compressed payload size */
    uint32      key_id;                 /* encryption key id, 0 = plaintext */
    uint16      compression;            /* see COMP_* */
    uint16      cache;                  /* cache hint flags */
};

/* Prefix of an encrypted ("SE") segment payload, ahead of the ciphertext. Which one
 * applies is decided by the wrapped key's alg: a CBC variant carries the IV alone and
 * pads the ciphertext, a GCM variant follows the IV with the tag over that ciphertext. */
struct segment_cbc_header {
    char        iv[16];
};

struct segment_gcm_header {
    char        iv[16];
    char        tag[16];                /* AES-GCM tag, computed with no additional data */
};

/* Header of one block of a linked-LZ4 chain (LSM cell streams, mem-tree blobs); the
 * compressed block follows */
struct lz4_block_header {
    uint32      compressed_size;
    uint32      uncompressed_size;
};

/* LSM superblock (L-SB), carried as a TLV payload in the ARCH header body */
struct lsm_superblock {
    char        magic[4];               /* "L-SB" */
    uint8       format_version;
    uint8       ctree_count_minus_2;
    uint8       ctree_max_minus_2;
    uint8       _reserved0;
    uint32      seq;                    /* commit sequence */
    uint32      ctree_size_hint;
    uint32      key_length;             /* per-record key bytes (0 = variable) */
    uint32      value_length;           /* per-record value bytes */
    /* followed by LSB_CTREE_SLOTS x ctree_ref, then the mem-tree header */
};

struct ctree_ref {
    uint64      offset;                 /* root page byte offset; 0xFF..FF / 0 = empty */
    uint64      num_pages;              /* bytes occupied by this ctree */
    uint32      item_count;             /* number of leaf entries */
    uint32      _reserved;
    uint64      max_key_or_size;
};

struct lsm_memtree_header {
    uint8       encoding;               /* low 7 bits codec (0 raw, 1 LZ4), bit 7 encrypted */
    uint8       _reserved;
    uint16      node_count;             /* entries in the residual mem-tree */
    uint32      extra_len;              /* extra payload bytes after the fixed L-SB */
    uint32      pages_total;
};

/* Inner header of a LEAF / LDIR page (at the start of the page body) */
struct lsm_page_header {
    char        magic[4];               /* "LEAF" or "LDIR" */
    uint8       version;                /* < 2 */
    uint8       encoding;               /* low 7 bits codec, bit 7 encrypted */
    uint16      cell_count;
    uint32      uncompressed_size;      /* size of the decoded cell stream */
    uint32      on_disk_size;           /* size of the stored cell stream */
    uint32      key_size_param;
    char        _sequence_id[4];        /* LE u32, unused here */
    /* zero pad up to LSM_CELL_STREAM_OFFSET, where the cell stream starts */
};

/* Precedes each group of cells in a compact cell stream */
struct lsm_cell_group_header {
    uint8       count;                  /* cells in this group, 1-24 */
    uint24      alive;                  /* bit i set: cell i carries a value; a tombstone only its key */
};

/* LDIR record value: where the child page is */
struct ldir_value {
    uint64      child_offset;           /* byte offset of the child LEAF / LDIR page */
};

/* data_map (TLV[1]) record: 31-byte key + 10-byte value */
struct data_map_key {
    uint64      volume_id;
    uint64      source_offset;          /* byte offset within the volume */
    uint24      extent_length;
    uint32      slice_id;               /* backup slice that wrote this extent ("field3") */
    uint64      extent_id;
};

struct data_map_value {
    uint64      segment_id;
    uint16      extent_index;           /* 0xFFFF = extent fills the whole segment */
};

/* segment_map (TLV[2]) record: 8-byte key + 32-byte value */
struct segment_map_key {
    uint64      segment_id;
};

struct segment_map_value {
    char        page_count[4];          /* little-endian, unlike the rest of the record */
    uint32      page_offset;            /* page index of the segment's header page */
    uint32      slice_id;
    char        hash[20];
};

/* TLV[5] "slices" record: one backup of the archive. Every data_map extent carries this
 * key's slice id in its own slice_id, to say which backup wrote it. The record is longer
 * than the value struct below; only the leading fields are understood. The guid is the one
 * "acrocmd list backups" prints for the backup, and is stored mixed-endian. */
struct slice_key {
    uint32      slice_id;
};

struct slice_record {
    char        guid[16];
    uint64      created_ms;             /* ms since the Unix epoch */
    uint64      modified_ms;
};

/* Password-wrapped data key, stored in the keymap tree (TLV[7]) mem-tree. The wrapped
 * key itself follows this header and runs to the end of the blob: its length is not
 * carried in the format, only its PKCS#7 padding is. */
struct wrapped_key {
    uint8       format;                 /* 0x01 password-wrapped, 0x02 certificate-wrapped */
    uint8       alg;                    /* segment cipher, see KEY_LENGTH; the wrap is always CBC */
    uint8       iter_log2;              /* PBKDF2 iterations = 1 << iter_log2 */
    uint8       _reserved;
    char        salt[16];               /* PBKDF2 salt */
};

/* TLV[18] file table record: where each physical file of the archive set begins in
 * the logical page store. One entry per version file; a "single version scheme"
 * cleanup compacts (physically truncates) older files but keeps their logical range. */
struct file_table_entry {
    uint32      index;
    uint64      byte_offset;            /* logical page-store offset of file[index] */
};
"""

c_tibx = cstruct(endian=">").load(tibx_def)

# Only the fields needed to tell a volume's filesystem apart and read its size
boot_def = """
struct ntfs_boot_sector {
    char        jump[3];
    char        oem_id[8];              /* "NTFS    " */
    uint16      bytes_per_sector;
    char        _unused[27];
    uint64      total_sectors;          /* +0x28 */
};

struct exfat_boot_sector {
    char        jump[3];
    char        fs_name[8];             /* "EXFAT   " */
    char        _must_be_zero[53];
    uint64      partition_offset;       /* +0x40 */
    uint64      volume_length;          /* +0x48, in sectors */
    char        _unused[28];
    uint8       bytes_per_sector_shift; /* +0x6C */
};

struct fat_boot_sector {
    char        jump[3];
    char        oem_id[8];
    uint16      bytes_per_sector;       /* +0x0B */
    uint8       sectors_per_cluster;
    uint16      reserved_sectors;
    uint8       fat_count;
    uint16      root_entries;
    uint16      total_sectors_16;       /* +0x13, 0 if the volume needs total_sectors_32 */
    uint8       media;
    uint16      fat_size_16;
    uint16      sectors_per_track;
    uint16      heads;
    uint32      hidden_sectors;
    uint32      total_sectors_32;       /* +0x20 */
    char        _fat16_ext[18];
    char        fs_type_16[8];          /* +0x36, "FAT12   " / "FAT16   " */
    char        _fat32_ext[20];
    char        fs_type_32[8];          /* +0x52, "FAT32   " */
};

/* ext2/3/4 superblock, EXT_SUPERBLOCK_OFFSET bytes into the volume */
struct ext_superblock {
    uint32      inodes_count;
    uint32      blocks_count;           /* +0x04, low 32 bits */
    char        _unused0[16];
    uint32      log_block_size;         /* +0x18, block size is 1024 << log_block_size */
    char        _unused1[28];
    uint16      magic;                  /* +0x38, EXT_MAGIC */
};
"""

c_boot = cstruct(endian="<").load(boot_def)

PAGE_SIZE: int = c_tibx.PAGE_SIZE
ENVELOPE_SIZE = len(c_tibx.page_header)
PAGE_BODY_SIZE = PAGE_SIZE - ENVELOPE_SIZE

PAGE_MARKER = 0x41

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

SEGMENT_MAGIC = b"SG"
SEGMENT_MAGIC_ENCRYPTED = b"SE"
SEGMENT_HEADER_OFFSET = ENVELOPE_SIZE
SEGMENT_PAYLOAD_OFFSET = 0x2C
# Compressed bytes on the segment's first page; the rest spills onto continuation pages
SEGMENT_FIRST_PAGE_PAYLOAD = PAGE_SIZE - SEGMENT_PAYLOAD_OFFSET

SEGMENT_CBC_HEADER_SIZE = len(c_tibx.segment_cbc_header)
SEGMENT_GCM_HEADER_SIZE = len(c_tibx.segment_gcm_header)

# segment_header.compression variants
COMP_NONE = 0x0000
COMP_LZ4 = 0x0001
# Observed in True Image 2026 metadata streams (2 in partition backups, 3 in device
# metadata of USB sources), only ever stored (zlength == length); compressed forms of
# these variants have not been seen in the wild
COMP_STORED_VARIANTS = frozenset({0x0002, 0x0003})
COMP_ZSTD = frozenset({0x0300, 0x0301, 0x0302, 0x0303})

# Extents sharing a segment (extent_index != 0xFFFF) are concatenated in index order,
# each aligned up to this boundary (empirical: exact fit on all observed segments)
EXTENT_ALIGNMENT = 16

LZ4_BLOCK_HEADER_SIZE = len(c_tibx.lz4_block_header)

LSM_MAGIC_SUPERBLOCK = b"L-SB"
LSM_MAGIC_LEAF = b"LEAF"
LSM_MAGIC_LDIR = b"LDIR"
# Cell stream starts this many bytes into a LEAF/LDIR page body
LSM_CELL_STREAM_OFFSET = 0x34
LSM_CELL_GROUP_HEADER_SIZE = len(c_tibx.lsm_cell_group_header)
LSM_CELL_GROUP_MAX = 24
LDIR_VALUE_SIZE = len(c_tibx.ldir_value)
# L-SB fixed layout: the lsm_superblock fields, a fixed number of ctree_ref slots, the
# mem-tree header, then reserved space up to LSB_FIXED_SIZE; the mem-tree blob follows
LSB_CTREE_SLOTS = 10
LSB_CTREE_OFFSET = len(c_tibx.lsm_superblock)
LSB_MEMTREE_OFFSET = LSB_CTREE_OFFSET + LSB_CTREE_SLOTS * len(c_tibx.ctree_ref)
LSB_FIXED_SIZE = 0x178

CTREE_EMPTY_SENTINEL = 0xFFFFFFFFFFFFFFFF

# ARCH header body: TLV directory location and slot count
TLV_DIRECTORY_OFFSET = 0x400
TLV_HEADER_SIZE = len(c_tibx.tlv_header)
TLV_SLOT_COUNT = 19

TLV_DATA_MAP = 1
TLV_SEGMENT_MAP = 2
TLV_SLICES = 5
TLV_KEYMAP = 7
TLV_FILE_TABLE = 18

# Wrapped-key blob: the fixed header above, then the padded key to the end of the blob
WRAPPED_KEY_HEADER_SIZE = len(c_tibx.wrapped_key)
WRAPPED_KEY_SALT_SIZE = 16
WRAPPED_KEY_FORMAT_PASSWORD = 0x01
WRAPPED_KEY_FORMAT_PUBKEY = 0x02

DATA_MAP_KEY_SIZE = len(c_tibx.data_map_key)
DATA_MAP_VALUE_SIZE = len(c_tibx.data_map_value)
# data_map_value.extent_index for "extent fills its segment"
EXTENT_INDEX_WHOLE_SEGMENT = 0xFFFF

SEGMENT_MAP_KEY_SIZE = len(c_tibx.segment_map_key)
SEGMENT_MAP_VALUE_SIZE = len(c_tibx.segment_map_value)

EXT_SUPERBLOCK_OFFSET = 0x400
EXT_MAGIC = 0xEF53
