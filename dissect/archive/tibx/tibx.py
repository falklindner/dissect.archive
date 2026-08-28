"""TIBX archive facade: volume enumeration and lazy, recency-resolved volume reads.

A backed-up volume is reconstructed from the data_map: possibly-overlapping extents
(incremental/differential backups append new extents over older ones; the base extents
stay in the tree) are flattened per byte into a non-overlapping interval list, keeping
the newest extent -- keyed by the slice id that wrote it, which is the only reliable
global recency signal. Sparse gaps between intervals are genuine unallocated space and
read back as zeros. Only the segments backing a requested range are fetched and
decompressed, so reads are fully lazy.
"""

from __future__ import annotations

import re
import struct
from bisect import bisect_right
from collections import OrderedDict, defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import AlignedStream, MappingStream

from dissect.archive.tibx.c_tibx import (
    EXTENT_ALIGNMENT,
    EXTENT_INDEX_WHOLE_SEGMENT,
    PAGE_SIZE,
    TLV_DATA_MAP,
    TLV_FILE_TABLE,
    TLV_KEYMAP,
    c_tibx,
)
from dissect.archive.tibx.exception import (
    CorruptArchiveError,
    Error,
    InvalidArchiveError,
    UnsupportedFormatError,
)
from dissect.archive.tibx.lsm import read_archive_header
from dissect.archive.tibx.map import load_extents, load_segment_index
from dissect.archive.tibx.page import PageStore
from dissect.archive.tibx.segment import read_plaintext
from dissect.archive.tibx.stream import TibxVolumeStream

if TYPE_CHECKING:
    import datetime

    from typing_extensions import Self

    from dissect.archive.tibx.lsm import ArchiveHeader
    from dissect.archive.tibx.map import Extent
    from dissect.archive.tibx.page import SuperBlock

# Decompressed segments are cached per archive under a memory budget rather than a fixed
# count: random-access workloads (MFT, registry hives) touch thousands of distinct
# segments, and a count of ~32 thrashed to a near-100% miss rate. A byte budget keeps many
# more small segments resident while still bounding memory for large ones.
SEGMENT_CACHE_BUDGET = 256 * 1024 * 1024

SPLIT_PART_RE = re.compile(r"^(?P<stem>.+?)-(?P<num>\d{4})\.tibx$", re.IGNORECASE)

Interval = tuple[int, int, "Extent"]


class RecoveryPoint:
    """One selectable point-in-time snapshot (a non-empty ARCH commit root).

    Each backup operation appends a commit root carrying its own copy-on-write
    data_map/segment_map, so any recovery point reconstructs the exact volume state at
    that time. Points are indexed oldest-to-newest by commit time.
    """

    def __init__(self, index: int, root: SuperBlock, header: ArchiveHeader):
        self.index = index
        self.root = root
        self.header = header

    def __repr__(self) -> str:
        return f"<RecoveryPoint index={self.index} offset={self.root.offset:#x} modified={self.modified}>"

    @property
    def modified(self) -> datetime.datetime:
        """The commit time of this recovery point."""
        return self.root.modified


class TIBX:
    """An Acronis TIBX ("archive3") backup archive.

    Opens at the latest recovery point (the live commit root). Use
    :meth:`recovery_points` to enumerate and :meth:`use_recovery_point` to select
    another point in a backup chain.

    Args:
        fh: A file-like object of the archive, or the ordered file-like objects of a
            split archive's parts (a raw byte-split of one logical page store).
    """

    def __init__(self, fh: BinaryIO | list[BinaryIO]):
        self._handles: list[BinaryIO] = []
        if isinstance(fh, list):
            fh = _stitch(fh)
        self.fh = fh
        self.store = PageStore(fh)
        self.root = self.store.live_root()
        self.header = read_archive_header(self.store, self.root)

        self._recovery_points: list[RecoveryPoint] | None = None
        self._data_key = None
        self._reset_snapshot_caches()

    def _reset_snapshot_caches(self) -> None:
        # Everything derived from the currently-selected commit root (not the data key)
        self._extents: list[Extent] | None = None
        self._segment_index = None
        self._segment_cache: OrderedDict[int, bytes] = OrderedDict()
        self._segment_cache_bytes = 0
        self._segment_layout: dict[tuple[int, int], int] | None = None
        self._volumes: list[TibxVolume] | None = None

    @classmethod
    def open(cls, path: str | Path) -> TIBX:
        """Open an archive from a path, auto-discovering split parts.

        The returned instance owns the file handles; call :meth:`close` (or use it as a
        context manager) to release them.
        """
        parts = find_split_parts(Path(path))
        handles = []
        try:
            # Open one by one so a failure mid-list doesn't leak already-opened handles
            for part in parts:
                handles.append(part.open("rb"))  # noqa: PERF401
            tibx = cls(handles if len(handles) > 1 else handles[0])
        except Exception:
            for handle in handles:
                handle.close()
            raise
        tibx._handles = handles
        return tibx

    def close(self) -> None:
        """Close the file handles owned by this instance (opened via :meth:`open`)."""
        for handle in self._handles:
            try:
                handle.close()
            except OSError:  # noqa: PERF203
                pass
        self._handles = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @property
    def encrypted(self) -> bool:
        """Whether this archive's data segments are encrypted.

        The superblock's ``encr_alg`` is the archive-level signal and costs nothing, but it
        has only been verified for ``header_version`` 8, so a keymap carrying a wrapped data
        key is accepted as evidence too. Use :attr:`password_protected` to find out whether a
        *password* can open it -- an archive wrapped to a certificate is encrypted all the
        same, and no password will help.
        """
        if self.root.encr_alg != c_tibx.EncrAlg.NONE:
            return True
        return self.password_protected or self._certificate_protected

    @property
    def password_protected(self) -> bool:
        """Whether a password can unlock this archive.

        A keymap tree with records is the cheap precondition; it is then confirmed by
        structurally locating the password-wrapped data key, so a keymap that carries no
        such key does not prompt for a password that could never work.
        """
        keymap = self.header.tree(TLV_KEYMAP)
        if keymap is None or not keymap.has_records:
            return False

        from dissect.archive.tibx.crypto import has_password_wrapped_key

        return has_password_wrapped_key(self.header)

    @property
    def _certificate_protected(self) -> bool:
        """Whether the keymap wraps the data key to a certificate rather than a password."""
        keymap = self.header.tree(TLV_KEYMAP)
        if keymap is None or not keymap.has_records:
            return False

        from dissect.archive.tibx.crypto import has_certificate_wrapped_key

        return has_certificate_wrapped_key(self.header)

    def unlock(self, password: str | bytes) -> None:
        """Derive the data key from ``password`` to read encrypted segments.

        Raises:
            InvalidPasswordError: If the password is wrong.
            UnsupportedFormatError: If the archive is encrypted but wrapped to a
                certificate, which no password can open.
        """
        from dissect.archive.tibx.crypto import unwrap_data_key

        if not self.password_protected and self._certificate_protected:
            raise UnsupportedFormatError(
                "archive is encrypted, but not password-protected: its data key is wrapped "
                "to a certificate, which this parser cannot use"
            )

        self._data_key = unwrap_data_key(self.header, password)
        self._segment_cache.clear()

    def recovery_points(self) -> list[RecoveryPoint]:
        """The selectable recovery points, oldest to newest by commit time.

        These are the non-empty commit roots (the empty initial root of a freshly
        created archive is skipped). A single full backup has one; incremental and
        differential chains have several.
        """
        if self._recovery_points is None:
            points = []
            for root in self.store.commit_roots():  # sorted oldest -> newest
                header = read_archive_header(self.store, root)
                data_map = header.tree(TLV_DATA_MAP)
                if data_map is not None and data_map.has_records:
                    points.append(RecoveryPoint(len(points), root, header))
            self._recovery_points = points
        return self._recovery_points

    def use_recovery_point(self, recovery_point: int | str = "latest") -> None:
        """Select which recovery point volumes and reads reflect.

        Args:
            recovery_point: ``"latest"`` (the live root, default), ``"oldest"``, or an
                integer index into :meth:`recovery_points`.

        Raises:
            InvalidArchiveError: If an integer index is out of range.
        """
        if recovery_point == "latest":
            self.root = self.store.live_root()
            self.header = read_archive_header(self.store, self.root)
        else:
            points = self.recovery_points()
            if recovery_point == "oldest":
                chosen = points[0]
            else:
                try:
                    index = int(recovery_point)
                except (TypeError, ValueError):
                    raise InvalidArchiveError(f"invalid recovery point {recovery_point!r}")
                if not 0 <= index < len(points):
                    raise InvalidArchiveError(f"recovery point {index} out of range (0..{len(points) - 1})")
                chosen = points[index]
            self.root = chosen.root
            self.header = chosen.header
        self._reset_snapshot_caches()

    def disks(self) -> list:
        """Whole-disk views of this archive.

        Not implemented yet: TIBX stores one data stream per partition, and the disk
        bootstrap layout (MBR/GPT region) is not reconstructed. Backed-up partitions are
        exposed through :meth:`volumes` instead, which loses only the partition-table
        context, not any filesystem content.
        """
        return []

    @property
    def extents(self) -> list[Extent]:
        """All data_map extents of the live commit root."""
        if self._extents is None:
            self._extents = load_extents(self.store, self.header)
        return self._extents

    def volumes(self) -> list[TibxVolume]:
        """The backed-up volumes: newest backup generation first, then largest first.

        A differential backup opens *new* volume streams for the updated state while
        the base generation's streams stay in the data_map (incrementals overlay the
        existing stream instead). Ranking by the newest slice that touched a stream
        puts the current generation first, so "latest by default" holds for both.
        """
        if self._volumes is None:
            by_volume: dict[int, list[Extent]] = defaultdict(list)
            for extent in self.extents:
                by_volume[extent.volume_id].append(extent)
            ranked = sorted(
                by_volume,
                key=lambda vid: (
                    max(extent.slice_id for extent in by_volume[vid]),
                    max(extent.end_offset for extent in by_volume[vid]),
                ),
                reverse=True,
            )
            self._volumes = [TibxVolume(self, vid, by_volume[vid]) for vid in ranked]
        return self._volumes

    def extent_base(self, extent: Extent) -> int:
        """The within-segment byte offset where ``extent``'s data starts.

        Whole-segment extents (index ``0xFFFF``) start at 0. Extents *sharing* a
        segment are concatenated in ``extent_index`` order, each aligned up to 16
        bytes (empirical rule, exact fit on every observed multi-extent segment --
        including sparse index sequences).
        """
        if extent.extent_index == EXTENT_INDEX_WHOLE_SEGMENT:
            return 0
        if self._segment_layout is None:
            layout: dict[tuple[int, int], int] = {}
            shared: dict[int, list[Extent]] = defaultdict(list)
            for entry in self.extents:
                if entry.extent_index != EXTENT_INDEX_WHOLE_SEGMENT:
                    shared[entry.segment_id].append(entry)
            for segment_id, entries in shared.items():
                offset = 0
                for entry in sorted(entries, key=lambda item: item.extent_index):
                    layout[(segment_id, entry.extent_index)] = offset
                    offset += entry.extent_length
                    offset = (offset + EXTENT_ALIGNMENT - 1) & ~(EXTENT_ALIGNMENT - 1)
            self._segment_layout = layout
        return self._segment_layout.get((extent.segment_id, extent.extent_index), 0)

    def read_segment(self, segment_id: int) -> bytes:
        """Return the (cached) decompressed plaintext of segment ``segment_id``."""
        cached = self._segment_cache.get(segment_id)
        if cached is not None:
            self._segment_cache.move_to_end(segment_id)
            return cached

        if self._segment_index is None:
            self._segment_index = load_segment_index(self.store, self.header)
        locator = self._segment_index.get(segment_id)
        if locator is None:
            raise CorruptArchiveError(f"segment id {segment_id} not in segment_map")

        plain = read_plaintext(self.store, locator.page_offset, self._data_key)
        self._segment_cache[segment_id] = plain
        self._segment_cache_bytes += len(plain)
        # Evict oldest until under budget, but always keep the just-added entry so a single
        # segment larger than the budget is still returned (and simply evicted next insert).
        while self._segment_cache_bytes > SEGMENT_CACHE_BUDGET and len(self._segment_cache) > 1:
            _, evicted = self._segment_cache.popitem(last=False)
            self._segment_cache_bytes -= len(evicted)
        return plain


class TibxVolume:
    """One backed-up volume (a data_map volume stream) inside a TIBX archive."""

    def __init__(self, tibx: TIBX, volume_id: int, extents: list[Extent]):
        self.tibx = tibx
        self.volume_id = volume_id
        self.extents = extents
        self._starts, self._intervals = resolve_extents(extents)
        self._size: int | None = None

    def __repr__(self) -> str:
        return f"<TibxVolume volume_id={self.volume_id:#x} size={self.size}>"

    @property
    def size(self) -> int:
        """The volume size in bytes, from its boot sector, capped by the data_map span."""
        if self._size is None:
            span = max((extent.end_offset for extent in self.extents), default=0)
            size = _boot_sector_size(self.read(0, 2048))
            # An absent or absurd boot-sector size means this is not a filesystem
            # volume (or the BPB was misread) -- trust the data_map span instead
            if size <= 0 or size > span * 64:
                size = span
            self._size = size
        return self._size

    def open(self) -> TibxVolumeStream:
        """Open a lazy, seekable stream over the reconstructed volume bytes."""
        return TibxVolumeStream(self)

    def read(self, offset: int, length: int) -> bytes:
        """Read ``length`` bytes at volume offset ``offset`` (sparse gaps read as zeros)."""
        if length <= 0:
            return b""
        result = bytearray()
        cursor = offset
        end = offset + length
        while cursor < end:
            index = bisect_right(self._starts, cursor) - 1
            interval = self._intervals[index] if index >= 0 else None
            if interval is not None and interval[0] <= cursor < interval[1]:
                extent = interval[2]
                take = min(end, interval[1])
                if extent.segment_id == 0:
                    # Discard marker: a newer slice recorded this range as unallocated
                    # (e.g. a file deleted between incrementals) -- it reads as zeros
                    # and must keep masking the older data underneath
                    result.extend(b"\x00" * (take - cursor))
                    cursor = take
                    continue
                segment = self.tibx.read_segment(extent.segment_id)
                segment_offset = self.tibx.extent_base(extent) + (cursor - extent.source_offset)
                chunk = segment[segment_offset : segment_offset + (take - cursor)]
                if len(chunk) < take - cursor:
                    # Damaged archive: segment shorter than its mapped extent -- zero-fill
                    chunk = chunk + b"\x00" * ((take - cursor) - len(chunk))
                result.extend(chunk)
                cursor = take
            else:
                # Sparse hole: zero-fill up to the next interval (or the requested end)
                index = bisect_right(self._starts, cursor)
                until = min(end, self._starts[index]) if index < len(self._starts) else end
                result.extend(b"\x00" * (until - cursor))
                cursor = until
        return bytes(result)


def resolve_extents(extents: list[Extent]) -> tuple[list[int], list[Interval]]:
    """Flatten possibly-overlapping extents into a recency-resolved interval list.

    Interval painting: at every extent boundary, the covering extent is the one with the
    highest ``(slice_id, extent_id, segment_id)`` -- the slice id (the backup in the
    chain that wrote the extent) is the primary recency signal, because a differential
    backup can reuse or even lower extent and segment ids of the base it supersedes.
    Resolving per byte rather than per start offset matters: a newer *shorter* extent
    must not mask the tail of an older *longer* one at the same offset.

    Returns ``(starts, intervals)``: a sorted non-overlapping list of
    ``(start, end, extent)`` plus the parallel list of starts for bisect.
    """
    if not extents:
        return [], []

    by_start: dict[int, list[Extent]] = defaultdict(list)
    by_end: dict[int, list[Extent]] = defaultdict(list)
    for extent in extents:
        by_start[extent.source_offset].append(extent)
        by_end[extent.end_offset].append(extent)
    points = sorted(set(by_start) | set(by_end))

    def _recency(extent: Extent) -> tuple[int, int, int]:
        return (extent.slice_id, extent.extent_id, extent.segment_id)

    def _identity(extent: Extent) -> tuple:
        return (extent.source_offset, extent.end_offset, *_recency(extent))

    active: dict[tuple, Extent] = {}
    intervals: list[Interval] = []
    for index in range(len(points) - 1):
        point = points[index]
        for extent in by_end.get(point, []):  # half-open: extents ending here stop covering
            active.pop(_identity(extent), None)
        for extent in by_start.get(point, []):
            active[_identity(extent)] = extent
        if not active:
            continue
        winner = max(active.values(), key=_recency)
        next_point = points[index + 1]
        if intervals and intervals[-1][2] is winner and intervals[-1][1] == point:
            # Coalesce contiguous runs of the same extent
            intervals[-1] = (intervals[-1][0], next_point, winner)
        else:
            intervals.append((point, next_point, winner))
    return [interval[0] for interval in intervals], intervals


def find_split_parts(path: Path) -> list[Path]:
    """Return the ordered files making up the archive at ``path``.

    Acronis splits large backups at a size boundary into ``Name.tibx`` +
    ``Name-0001.tibx`` + ... -- a raw byte-split of one logical page store. Given any
    member of such a set, the full ordered set is returned; otherwise ``[path]``.
    """
    match = SPLIT_PART_RE.match(path.name)
    stem = match.group("stem") if match else (path.stem if path.suffix.lower() == ".tibx" else path.name)
    parts = sorted(path.parent.glob(f"{stem}-[0-9][0-9][0-9][0-9].tibx"), key=lambda part: part.name)
    main = path.parent / f"{stem}.tibx"
    if parts and main.exists():
        return [main, *parts]
    return [path]


class _ZeroStream(AlignedStream):
    """Zero-filled backing for logical ranges whose physical pages were compacted away."""

    def _read(self, offset: int, length: int) -> bytes:
        return b"\x00" * length


def _file_table_offsets(handle: BinaryIO, expected: int) -> list[int] | None:
    """The logical byte offset of every file of an archive set, from ``handle``'s TLV[18].

    Version files carry the archive's newest commit roots, so the *last* file's live
    root has the authoritative file table. Returns None when the file carries no
    plausible table for ``expected`` files -- notably for raw byte-split parts, which
    are page-misaligned fragments without their own roots.
    """
    entry_size = len(c_tibx.file_table_entry)
    try:
        store = PageStore(handle)
        header = read_archive_header(store, store.live_root())
    except Error:
        return None
    payload = header.tlv[TLV_FILE_TABLE].payload if len(header.tlv) > TLV_FILE_TABLE else b""
    if len(payload) // entry_size != expected:
        return None
    offsets = []
    for index in range(expected):
        entry = c_tibx.file_table_entry(payload[index * entry_size :])
        if entry.index != index:
            return None
        offsets.append(entry.byte_offset)
    if offsets[0] != 0 or offsets != sorted(set(offsets)):
        return None
    return offsets


def _stitch(handles: list[BinaryIO]) -> MappingStream:
    """Map the files of a multi-file archive into one logical page store.

    Split archives are raw byte-splits of one page store: the parts concatenate.
    Version sets (each backup version appended as ``Name-0001.tibx``, ...) instead
    record every file's logical start offset in the TLV[18] file table: after a
    "single version scheme" cleanup the base file is compacted -- physically
    truncated, its data pages tombstoned -- while retaining its logical address
    range, so concatenation would misplace every absolute offset in the maps.
    Compacted ranges are mapped as zeros; nothing alive references them.
    """
    sizes = []
    for handle in handles:
        handle.seek(0, 2)
        sizes.append(handle.tell())

    offsets = _file_table_offsets(handles[-1], expected=len(handles)) if len(handles) > 1 else None
    if offsets is not None:
        # A trustworthy table never maps a file below the previous file's end
        position = 0
        for offset, size in zip(offsets, sizes, strict=False):
            if offset < position:
                offsets = None
                break
            position = offset + size
    if offsets is None:
        offsets = []
        position = 0
        for size in sizes:
            offsets.append(position)
            position += size

    stream = MappingStream(align=PAGE_SIZE)
    position = 0
    for handle, size, offset in zip(handles, sizes, offsets, strict=False):
        if offset > position:
            stream.add(position, offset - position, _ZeroStream(offset - position), 0)
        stream.add(offset, size, handle, 0)
        position = offset + size
    return stream


def _boot_sector_size(boot: bytes) -> int:
    """Parse the volume size from a boot sector, or 0 if it is not a known filesystem.

    The total-sectors field differs per filesystem, so the filesystem must be sniffed
    first -- reading the wrong offset yields garbage sizes.
    """
    if len(boot) < 512:
        return 0
    try:
        if boot[3:11] == b"NTFS    ":
            bytes_per_sector = struct.unpack_from("<H", boot, 0x0B)[0] or 512
            return bytes_per_sector * struct.unpack_from("<Q", boot, 0x28)[0]
        if boot[3:11] == b"EXFAT   ":
            return struct.unpack_from("<Q", boot, 0x48)[0] << boot[0x6C]
        if boot[0x52:0x57] == b"FAT32" or boot[0x36:0x39] == b"FAT":
            bytes_per_sector = struct.unpack_from("<H", boot, 0x0B)[0] or 512
            total = struct.unpack_from("<H", boot, 0x13)[0] or struct.unpack_from("<I", boot, 0x20)[0]
            return bytes_per_sector * total
        if len(boot) >= 1024 + 0x5C and boot[1024 + 0x38 : 1024 + 0x3A] == b"\x53\xef":
            superblock = boot[1024:]
            blocks = struct.unpack_from("<I", superblock, 0x04)[0]
            return blocks << (10 + struct.unpack_from("<I", superblock, 0x18)[0])
    except struct.error:
        return 0
    return 0
