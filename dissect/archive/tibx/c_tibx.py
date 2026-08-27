"""Structure definitions for the Acronis TIBX ("archive3") file format.

A ``.tibx`` is a flat sequence of 4096-byte pages. Byte 0 of every page is the marker
``0x41`` (``'A'``), byte 1 the page type, and a CRC-32C of the page (checksum bytes
zeroed) is stored at ``+0x04``. The page content ("body") starts after this 8-byte
envelope.

Most multi-byte fields are big-endian, so the definitions are loaded into a big-endian
cstruct instance. The few little-endian fields (the LSM cell-group header, the LEAF
sequence id and the segment_map ``page_count``) are decoded manually at their use sites.

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

struct arch_superblock {
    page_header header;
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
    /* +0x18: ctree_count x ctree_ref slots, then mem-tree fields at +0x158 */
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
    /* zero pad up to +0x34, where the cell stream starts */
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

/* Password-wrapped data key, stored in the keymap tree (TLV[7]) mem-tree. The wrapped
 * key itself follows this header and runs to the end of the blob: its length is not
 * carried in the format, only its PKCS#7 padding is. */
struct wrapped_key {
    uint8       format;                 /* 0x01 password-wrapped, 0x02 certificate-wrapped */
    uint8       alg;                    /* AES variant, see CBC_KEY_LENGTH / GCM_ALG_IDS */
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

PAGE_SIZE: int = c_tibx.PAGE_SIZE
ENVELOPE_SIZE = 8
PAGE_BODY_SIZE = PAGE_SIZE - ENVELOPE_SIZE

PAGE_MARKER = 0x41

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

SEGMENT_MAGIC = b"SG"
SEGMENT_MAGIC_ENCRYPTED = b"SE"
SEGMENT_HEADER_OFFSET = 8
SEGMENT_PAYLOAD_OFFSET = 0x2C
# Compressed bytes on the segment's first page; the rest spills onto continuation pages
SEGMENT_FIRST_PAGE_PAYLOAD = PAGE_SIZE - SEGMENT_PAYLOAD_OFFSET

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

LSM_MAGIC_SUPERBLOCK = b"L-SB"
LSM_MAGIC_LEAF = b"LEAF"
LSM_MAGIC_LDIR = b"LDIR"
# Cell stream starts this many bytes into a LEAF/LDIR page body
LSM_CELL_STREAM_OFFSET = 0x34
# L-SB fixed layout: ctree slots at +0x18, mem-tree header at +0x158, extra payload at +0x178
LSB_CTREE_OFFSET = 0x18
LSB_MEMTREE_OFFSET = 0x158
LSB_FIXED_SIZE = 0x178

CTREE_EMPTY_SENTINEL = 0xFFFFFFFFFFFFFFFF

# ARCH header body: TLV directory location and slot count
TLV_DIRECTORY_OFFSET = 0x400
TLV_SLOT_COUNT = 19

TLV_DATA_MAP = 1
TLV_SEGMENT_MAP = 2
TLV_SLICES = 5
TLV_KEYMAP = 7
TLV_FILE_TABLE = 18

# Wrapped-key blob: the fixed header above, then the padded key to the end of the blob
WRAPPED_KEY_HEADER_SIZE = 20
WRAPPED_KEY_SALT_SIZE = 16
WRAPPED_KEY_FORMAT_PASSWORD = 0x01
WRAPPED_KEY_FORMAT_PUBKEY = 0x02

DATA_MAP_KEY_SIZE = 31
DATA_MAP_VALUE_SIZE = 10
# data_map_value.extent_index for "extent fills its segment"
EXTENT_INDEX_WHOLE_SEGMENT = 0xFFFF
