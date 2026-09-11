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

import datetime
import re
import uuid
from bisect import bisect_right
from collections import OrderedDict, defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import AlignedStream, MappingStream

from dissect.archive.tibx.c_tibx import (
    EXT_MAGIC,
    EXT_SUPERBLOCK_OFFSET,
    EXTENT_ALIGNMENT,
    EXTENT_INDEX_WHOLE_SEGMENT,
    PAGE_SIZE,
    TLV_FILE_TABLE,
    TLV_KEYMAP,
    TLV_SLICES,
    c_boot,
    c_tibx,
)
from dissect.archive.tibx.exception import (
    CorruptArchiveError,
    Error,
    InvalidArchiveError,
    UnsupportedFormatError,
)
from dissect.archive.tibx.lsm import iter_memtree_cells, read_archive_header
from dissect.archive.tibx.map import load_extents, load_segment_index
from dissect.archive.tibx.page import PageStore
from dissect.archive.tibx.segment import read_plaintext
from dissect.archive.tibx.stream import TibxVolumeStream

if TYPE_CHECKING:
    from typing_extensions import Self

    from dissect.archive.tibx.map import Extent

# Decompressed segments are cached per archive under a memory budget rather than a fixed
# count: random-access workloads (MFT, registry hives) touch thousands of distinct
# segments, and a count of ~32 thrashed to a near-100% miss rate. A byte budget keeps many
# more small segments resident while still bounding memory for large ones.
SEGMENT_CACHE_BUDGET = 256 * 1024 * 1024

SPLIT_PART_RE = re.compile(r"^(?P<stem>.+?)-(?P<num>\d{4})\.tibx$", re.IGNORECASE)

# Smallest stream taken to be a partition rather than Acronis metadata, for a stream whose
# filesystem this parser does not recognise. The two populations are far apart in practice:
# across the sample corpora the largest metadata stream is ~2.6 KB and the smallest real
# partition is 16 MB, so this sits in the middle of a gap of some four orders of magnitude.
MIN_VOLUME_SIZE = 1 << 20

Interval = tuple[int, int, "Extent"]


class RecoveryPoint:
    """One backup in the archive: a *slice*, in the format's own terms.

    A slice is what Acronis calls a backup and what ``acrocmd list backups`` lists; its
    :attr:`guid` is the id printed there. Every data_map extent records the slice that
    wrote it, so selecting a recovery point means taking the extents up to and including
    that slice -- which is how an incremental chain reconstructs an earlier state.

    Slice ids are not contiguous: a differential chain here numbered its two backups 2 and
    4. Address a point by its list index, and let :attr:`slice_id` stay whatever the
    archive says it is.
    """

    def __init__(self, index: int, slice_id: int, record: c_tibx.slice_record):
        self.index = index
        self.slice_id = slice_id
        self.guid = uuid.UUID(bytes_le=record.guid)
        self._record = record

    def __repr__(self) -> str:
        return f"<RecoveryPoint index={self.index} slice={self.slice_id} guid={self.guid} modified={self.modified}>"

    @property
    def created(self) -> datetime.datetime:
        """When this backup started."""
        return datetime.datetime.fromtimestamp(self._record.created_ms / 1000, datetime.timezone.utc)

    @property
    def modified(self) -> datetime.datetime:
        """When this backup finished."""
        return datetime.datetime.fromtimestamp(self._record.modified_ms / 1000, datetime.timezone.utc)


class TIBX:
    """An Acronis TIBX ("archive3") backup archive.

    Opens at the latest recovery point. Use :meth:`recovery_points` to enumerate the
    backups the archive records and :meth:`use_recovery_point` to select an earlier one
    in a chain.

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
        self._slice_limit: int | None = None
        self._data_key = None
        self._reset_snapshot_caches()

    def _reset_snapshot_caches(self) -> None:
        # Everything derived from the currently-selected commit root (not the data key)
        self._extents: list[Extent] | None = None
        self._segment_index = None
        self._segment_cache: OrderedDict[int, bytes] = OrderedDict()
        self._segment_cache_bytes = 0
        self._segment_layout: dict[tuple[int, int], int] | None = None
        self._streams: list[TibxVolume] | None = None
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
        """The backups in this archive, oldest first.

        Read from the slices tree (TLV[5]), which is the archive's own record of its
        backups: one record per backup, keyed by slice id, carrying the same GUID that
        ``acrocmd list backups`` prints.

        This deliberately does not enumerate ARCH commit roots. A commit root is a
        transactional checkpoint, not a backup, and Acronis writes a varying number of
        them per backup -- two for a single full backup here, four for a file-level one --
        so counting roots reports recovery points that were never taken.
        """
        if self._recovery_points is None:
            points: list[RecoveryPoint] = []
            slices = self.header.tree(TLV_SLICES)
            if slices is not None and slices.has_records:
                for cell in iter_memtree_cells(slices):
                    # The tree opens with an empty placeholder record; a real backup has a value.
                    if len(cell.value) < len(c_tibx.slice_record) or len(cell.key) < len(c_tibx.slice_key):
                        continue
                    key = c_tibx.slice_key(cell.key)
                    points.append(RecoveryPoint(len(points), key.slice_id, c_tibx.slice_record(cell.value)))
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
            self._slice_limit = None
        else:
            points = self.recovery_points()
            if not points:
                raise InvalidArchiveError("archive records no backups to select from")
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
            # Extents carry the slice that wrote them, and resolve_extents already treats
            # slice_id as the primary recency signal -- so dropping everything newer than
            # the chosen slice is exactly the archive as it stood after that backup.
            self._slice_limit = chosen.slice_id
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
        """The data_map extents in view: all of them, or those up to the selected slice."""
        if self._extents is None:
            extents = load_extents(self.store, self.header)
            if self._slice_limit is not None:
                extents = [extent for extent in extents if extent.slice_id <= self._slice_limit]
            self._extents = extents
        return self._extents

    def streams(self) -> list[TibxVolume]:
        """Every data_map stream, backed-up volumes and Acronis's own metadata alike.

        Ordered newest backup generation first, then largest first. A differential backup
        opens *new* streams for the updated state while the base generation's streams stay
        in the data_map (incrementals overlay the existing stream instead). Ranking by the
        newest slice that touched a stream puts the current generation first, so "latest by
        default" holds for both.

        Most callers want :meth:`volumes`; this is here for inspecting an archive's
        internals without having to reach into the data_map.
        """
        if self._streams is None:
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
            self._streams = [TibxVolume(self, vid, by_volume[vid]) for vid in ranked]
        return self._streams

    def volumes(self) -> list[TibxVolume]:
        """The backed-up volumes, newest backup generation first, then largest first.

        An archive's data_map holds more streams than it holds volumes: alongside each
        partition, Acronis stores its own metadata -- the ``metainfo`` XML, allocation
        bitmaps, small index tables -- and the disk's MBR/GPT bootstrap region, all keyed
        by volume id exactly like a partition. Returning those as volumes made a
        single-partition backup look like eight, and a file-level backup like forty-five.

        A stream counts as a volume if its content starts with a filesystem this parser
        recognises, or if it is at least :data:`MIN_VOLUME_SIZE` -- which keeps an
        unformatted or unrecognised partition, something ``acrocmd list content`` reports
        as a partition of type ``None``. Use :meth:`streams` for the unfiltered list.
        """
        if self._volumes is None:
            self._volumes = [stream for stream in self.streams() if self._is_volume(stream)]
        return self._volumes

    @staticmethod
    def _is_volume(stream: TibxVolume) -> bool:
        """Whether a data_map stream is a backed-up volume rather than Acronis metadata.

        The size test runs on :attr:`TibxVolume.span`, which comes from the data_map and
        needs no read. That matters for an encrypted archive that has not been unlocked:
        listing what a locked archive contains must not require the password, and reading
        the boot sector would.
        """
        if stream.span >= MIN_VOLUME_SIZE:
            return True
        try:
            return bool(_boot_sector_size(stream.open().read(2048)))
        except Error:
            # Locked, or unreadable for any other reason -- the span said no, so leave it.
            return False

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
    def span(self) -> int:
        """How far this stream reaches, straight from the data_map.

        Unlike :attr:`size` this needs no read, so it is available for an encrypted
        archive that has not been unlocked.
        """
        return max((extent.end_offset for extent in self.extents), default=0)

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
        ntfs = c_boot.ntfs_boot_sector(boot)
        if ntfs.oem_id == b"NTFS    ":
            return (ntfs.bytes_per_sector or 512) * ntfs.total_sectors
        exfat = c_boot.exfat_boot_sector(boot)
        if exfat.fs_name == b"EXFAT   ":
            return exfat.volume_length << exfat.bytes_per_sector_shift
        fat = c_boot.fat_boot_sector(boot)
        if fat.fs_type_32.startswith(b"FAT32") or fat.fs_type_16.startswith(b"FAT"):
            return (fat.bytes_per_sector or 512) * (fat.total_sectors_16 or fat.total_sectors_32)
        if len(boot) >= EXT_SUPERBLOCK_OFFSET + len(c_boot.ext_superblock):
            ext = c_boot.ext_superblock(boot[EXT_SUPERBLOCK_OFFSET:])
            if ext.magic == EXT_MAGIC:
                return ext.blocks_count << (10 + ext.log_block_size)
    except EOFError:
        return 0
    return 0
