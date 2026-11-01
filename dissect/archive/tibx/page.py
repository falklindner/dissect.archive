"""TIBX page store: 4 KiB pages, ARCH superblocks, transactional commit-root selection.

A ``.tibx`` is transactional: every commit writes a new ARCH superblock carrying its own
copy-on-write LSM trees, so each ARCH page is a complete point-in-time snapshot of the
archive. That is a commit, not a backup: a backup takes several commits, and the backups
are recorded in the archive header (see :meth:`TIBX.recovery_points`).

Each commit also writes a commit info (ARCI) page after its ARCH header, and those pages
chain back to the first one, at page 2. An archive keeps track of its newest commit in one
of two ways. Either its commits are appended, so the newest one is at the end, or page 2 is
CI0: a commit info page that names the newest commit, from which the whole chain can be
walked.

The live root is found the way Acronis opens an archive: from CI0 if there is one, taking
its commit as it stands. Otherwise -- no CI0, or a damaged one -- the live root is the
commit of the last commit info page written, found scanning backward from EOF. The commit
info is written after the ARCH header, so a commit torn in between (power loss) has none
yet and is skipped in favor of the newest complete one. Only an archive without usable
commit info falls back to its last CRC-valid ARCH page. Following the chain back from the
newest commit finds every commit root in a few reads more.

Ported from the page store of ``acronis-tibx`` (MIT License, Copyright (c) 2026
mniedermaier).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from dissect.util import ts
from dissect.util.hash import crc32c, crc64_redis

from dissect.archive.tibx.c_tibx import PAGE_MARKER, PAGE_SIZE, c_tibx
from dissect.archive.tibx.exception import CorruptArchiveError, InvalidArchiveError

if TYPE_CHECKING:
    import datetime
    from collections.abc import Iterator

ARCH_MAGIC = b"ARCH"
ARCI_MAGIC = b"ARCI"

# The first commit info is at page 2 (offset 0x2000), after the first commit's two-page ARCH header
FIRST_CI_OFFSET = 2 * PAGE_SIZE

# arci_header.crc64 covers the first 512 bytes of an ARCI page, envelope included
ARCI_CRC64_SIZE = 512
ARCI_CRC64_OFFSET = len(c_tibx.page_header) + c_tibx.arci_header.fields["crc64"].offset

# Pages read per step of the backward scan for the live root: 64 KiB growing to 4 MiB.
# Acronis's own scan doubles the same way, from 256 KiB to 4 MiB; the newest commit is
# nearly always in the last few pages, so this starts smaller.
SCAN_CHUNK_MIN_PAGES = 16
SCAN_CHUNK_MAX_PAGES = 1024

# ENVELOPE PARSING -- page envelopes go through :class:`c_tibx.page_header` everywhere
# except the page sweeps -- :func:`_is_valid_page`, :meth:`PageStore._last_ci`,
# :meth:`PageStore._scan_commit_roots` and :meth:`PageStore._scan_commit_infos` -- which
# index the envelope bytes directly.
#
# cstruct costs ~3.6 us per envelope against ~0.33 us for the indexing, but that ratio is
# not the one that matters; measured end to end on a 949 MiB archive (242,977 pages):
#
#   verify()               1.06x  -- dominated by CRC-32C (13.1 s of the 13.9 s)
#   _scan_commit_roots()   1.92x  -- 859 ms vs 1644 ms
#
# and on an archive whose live root is 84k pages before EOF, as in one real archive (most
# have it within the last 3 pages, where the choice is unmeasurable):
#
#   _last_arch()           2.8x   -- 291 ms vs 801 ms
#
# So only the sweeps -- whose per-page work is otherwise just a marker comparison -- index
# directly, and the offsets are mirrored in those places. Random access never touches this
# path at all.

# NO PAGE CACHE -- ``page()`` reads straight through, deliberately. A 512-page LRU used to
# sit here, on the theory that tree walks and segment headers get revisited. Measured on
# real archives it never once hit: :class:`TIBX`'s 256 MiB segment cache absorbs the
# repeats, and segment payloads go through :meth:`read_run`, which does not consult it. What
# reached ``page()`` was one header page per distinct segment, read once -- 40 to 500
# calls for 3000 scattered 4 KiB reads -- and now the header comes with the payload too.
# The LRU only earned hits with the segment cache shrunk to 256 KiB, which is not a
# configuration anyone runs.


def page_crc32c(page: bytes) -> int:
    """Return the CRC-32C of a page with the four checksum bytes at ``[4:8]`` zeroed.

    The three runs are chained through ``crc32c``'s ``value`` argument rather than CRCing a
    zeroed 4 KiB copy. Both measure the same (77.7 vs 77.5 MB/s over 30k pages) -- the
    chained form is just the one that does not allocate.

    Note the import: ``dissect.util.hash`` rebinds its ``crc32c`` attribute to the native
    (Rust) implementation when available, so it has to be reached through the package.
    ``from dissect.util.hash.crc32c import crc32c`` resolves through ``sys.modules`` to the
    pure-Python submodule instead and is ~14x slower for identical output.
    """
    return crc32c.crc32c(page[8:], crc32c.crc32c(b"\x00\x00\x00\x00", crc32c.crc32c(page[:4])))


def arci_crc64(page: bytes) -> int:
    """Return the CRC-64 (Redis) of an ARCI page's first 512 bytes, both checksums zeroed.

    Chained like :func:`page_crc32c`, and reached through the package for the same reason.
    """
    value = crc64_redis.crc64_redis(page[:4])
    value = crc64_redis.crc64_redis(b"\x00\x00\x00\x00", value)
    value = crc64_redis.crc64_redis(page[8:ARCI_CRC64_OFFSET], value)
    value = crc64_redis.crc64_redis(b"\x00" * 8, value)
    return crc64_redis.crc64_redis(page[ARCI_CRC64_OFFSET + 8 : ARCI_CRC64_SIZE], value)


def _is_valid_page(page: bytes, page_type: int, magic: bytes) -> bool:
    """Whether ``page`` is a CRC-valid page of ``page_type`` that opens with ``magic``."""
    # Envelope indexed directly -- see the ENVELOPE PARSING note at the top
    return (
        page[0] == PAGE_MARKER
        and page[1] == page_type
        and page[8:12] == magic
        and c_tibx.page_header(page).crc32c == page_crc32c(page)
    )


def _type_name(value: int) -> str:
    try:
        return c_tibx.PageType(value).name
    except ValueError:
        return f"{value:#04x}"


class SuperBlock:
    """An ARCH superblock (commit root) at a given byte offset in the page store."""

    def __init__(self, page: bytes, offset: int):
        self.offset = offset
        try:
            self.sb = c_tibx.arch_superblock(page)
        except EOFError:
            # A buffer too short to hold a superblock is not one; report it in the parser's
            # own vocabulary rather than letting cstruct's EOFError escape.
            raise InvalidArchiveError(f"Truncated ARCH superblock at offset {offset:#x}")
        header = self.sb.body
        if header.magic != ARCH_MAGIC:
            raise InvalidArchiveError(f"Not an ARCH superblock at offset {offset:#x}")
        self.header_size = header.header_size
        self.ci_offset: int = header.ci_offset
        self.archive_uuid: bytes = bytes(header.archive_uuid)
        self.created_ms: int = header.created_ms
        self.modified_ms: int = header.modified_ms
        self.compr_lvl: c_tibx.ComprLvl = header.compr_lvl
        self.encr_alg: c_tibx.EncrAlg = header.encr_alg
        self.hash_alg: int = header.hash_alg
        self.dedup: bool = bool(header.dedup)

    def __repr__(self) -> str:
        return f"<SuperBlock offset={self.offset:#x} modified_ms={self.modified_ms}>"

    @property
    def created(self) -> datetime.datetime:
        """The archive creation time."""
        return ts.from_unix_ms(self.created_ms)

    @property
    def modified(self) -> datetime.datetime:
        """The commit time of this root."""
        return ts.from_unix_ms(self.modified_ms)


class CommitInfo:
    """An ARCI commit info page at a given byte offset in the page store.

    ``volume_offset`` is where the page is within its own file of a split archive;
    ``offset`` and the offsets it points at are in the archive as a whole.
    """

    def __init__(self, page: bytes, offset: int):
        self.offset = offset
        self.header = c_tibx.arci_page(page).commit_info
        self.flags: c_tibx.ArciFlags = self.header.flags
        self.arch_offset: int = self.header.arch_offset
        self.arch_size: int = self.header.arch_size
        self.commit_seq: int = self.header.commit_seq
        self.ci_seq: int = self.header.ci_seq
        self.first_ci_offset: int = self.header.first_ci_offset
        self.prev_ci_offset: int = self.header.prev_ci_offset
        self.volume_offset: int = self.header.volume_offset
        self.archive_uuid: bytes = self.header.uuid.to_bytes(16, "big")

    def __repr__(self) -> str:
        return f"<CommitInfo offset={self.offset:#x} commit_seq={self.commit_seq} ci_seq={self.ci_seq}>"


def _commit_info(page: bytes, offset: int) -> CommitInfo | None:
    """The commit info ``page`` at byte ``offset`` holds, if its CRC-32C and CRC-64 hold."""
    if not _is_valid_page(page, c_tibx.PageType.ARCI, ARCI_MAGIC):
        return None
    commit_info = CommitInfo(page, offset)
    return commit_info if commit_info.header.crc64 == arci_crc64(page) else None


class PageStore:
    """Random access to the 4 KiB pages of a ``.tibx`` archive.

    Args:
        fh: A file-like object of the (stitched, in case of split archives) page store.

    Raises:
        ~dissect.archive.tibx.exception.InvalidArchiveError: If page 0 is not an ARCH superblock.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        fh.seek(0, 2)
        self.size = fh.tell()
        self.page_count = self.size // PAGE_SIZE

        if self.size < PAGE_SIZE or c_tibx.arch_superblock(self.page(0)).body.magic != ARCH_MAGIC:
            raise InvalidArchiveError("Missing ARCH magic at page 0")

    def _read_at(self, offset: int, size: int) -> bytes:
        """Read ``size`` bytes at ``offset``, or fewer only at EOF.

        :meth:`TIBX.open` opens a single-file archive unbuffered, and a raw file may return
        a read in parts.
        """
        self.fh.seek(offset)
        data = self.fh.read(size)
        if len(data) == size or not data:
            return data
        parts = [data]
        remaining = size - len(data)
        while remaining > 0 and (data := self.fh.read(remaining)):
            parts.append(data)
            remaining -= len(data)
        return b"".join(parts)

    def page(self, index: int) -> bytes:
        """Read the page at ``index``.

        Raises:
            ~dissect.archive.tibx.exception.CorruptArchiveError: If the page does not exist or is truncated.
        """
        if not 0 <= index < self.page_count:
            raise CorruptArchiveError(f"page {index} is out of bounds (archive has {self.page_count} pages)")
        page = self._read_at(index * PAGE_SIZE, PAGE_SIZE)
        if len(page) != PAGE_SIZE:
            raise CorruptArchiveError(f"short read on page {index}")
        return page

    def read_run(self, start: int, count: int) -> list[bytes]:
        """Read ``count`` consecutive pages beginning at ``start`` in a single I/O.

        Collapses what would otherwise be ``count`` separate ``seek``+``read`` calls into
        one -- the pages of a multi-page segment are physically contiguous, so this is the
        batch read path for :func:`segment.read_plaintext`, and for the backward scan of
        :meth:`_pages_backward`.

        Raises:
            ~dissect.archive.tibx.exception.CorruptArchiveError: If the run extends past the end of the archive or is
                truncated.
        """
        if count <= 0:
            return []
        if start < 0 or start + count > self.page_count:
            raise CorruptArchiveError(f"page run {start}..{start + count} is out of bounds ({self.page_count} pages)")
        blob = self._read_at(start * PAGE_SIZE, count * PAGE_SIZE)
        if len(blob) != count * PAGE_SIZE:
            raise CorruptArchiveError(f"short read on page run {start}..{start + count}")
        return [blob[i * PAGE_SIZE : (i + 1) * PAGE_SIZE] for i in range(count)]

    def page_type(self, index: int) -> int:
        """Return the type byte of the page at ``index``."""
        return c_tibx.page_header(self.page(index)).type

    def page_type_name(self, index: int) -> str:
        """Return the type of the page at ``index`` as a name, or hex for unknown types."""
        return _type_name(self.page_type(index))

    def pages(self) -> Iterator[tuple[int, bytes]]:
        """Iterate over all ``(index, page)`` pairs."""
        for index in range(self.page_count):
            yield index, self.page(index)

    def _page_at(self, offset: int) -> bytes | None:
        """The page at byte ``offset``, or None if no page starts there."""
        index, rest = divmod(offset, PAGE_SIZE)
        if rest or not 0 <= index < self.page_count:
            return None
        return self.page(index)

    def _commit_info_at(self, offset: int) -> CommitInfo | None:
        """The commit info at byte ``offset``, if an ARCI page is there whose CRC-32C and CRC-64 hold."""
        page = self._page_at(offset)
        return None if page is None else _commit_info(page, offset)

    def _root_at(self, offset: int, ci_offset: int) -> SuperBlock | None:
        """The CRC-valid ARCH root at byte ``offset``, if its commit info is at ``ci_offset``."""
        page = self._page_at(offset)
        if page is None or not _is_valid_page(page, c_tibx.PageType.ARCH, ARCH_MAGIC):
            return None
        root = SuperBlock(page, offset)
        return root if root.ci_offset == ci_offset else None

    def _pages_backward(self) -> Iterator[tuple[int, bytes]]:
        """Iterate over all ``(index, page)`` pairs from EOF backward.

        What is looked for this way is usually within the last few pages, but not always:
        one real archive had 84k pages after its newest commit, and reading those one by one
        took 71 s over SMB. So the pages are read in chunks, small first, doubling up to
        :data:`SCAN_CHUNK_MAX_PAGES`.
        """
        end = self.page_count
        count = SCAN_CHUNK_MIN_PAGES
        while end > 0:
            start = max(0, end - count)
            pages = self.read_run(start, end - start)
            for index in range(end - 1, start - 1, -1):
                yield index, pages[index - start]
            end = start
            count = min(count * 2, SCAN_CHUNK_MAX_PAGES)

    def _ci0(self) -> CommitInfo | None:
        """CI0, if the archive has a valid one.

        CI0 is the first commit info page (page 2) of an archive written in "rewrite" mode,
        rewritten after each commit to describe the newest one, and marked as such by
        ``ArciFlags.CI0``. In "append" mode the first commit info page is just the first
        commit's.
        """
        ci = self._commit_info_at(FIRST_CI_OFFSET)
        return ci if ci is not None and ci.flags & c_tibx.ArciFlags.CI0 else None

    def _last_ci(self) -> CommitInfo | None:
        """The last commit info page written, by scanning backward from EOF.

        That is the highest-offset one, which is the newest only in "append" mode. In
        "rewrite" mode CI0 names the newest, and this comes in only when CI0 is damaged:
        should the archive have reused space, an older commit may then be taken for the
        newest.
        """
        for index, page in self._pages_backward():
            # Envelope indexed directly -- see the ENVELOPE PARSING note at the top
            if page[1] == c_tibx.PageType.ARCI and (ci := _commit_info(page, index * PAGE_SIZE)):
                return ci
        return None

    def _last_arch(self) -> SuperBlock | None:
        """The last CRC-valid ARCH header, by scanning backward from EOF.

        Whether its commit was completed or not: this does not look at commit info at all.
        """
        for index, page in self._pages_backward():
            if _is_valid_page(page, c_tibx.PageType.ARCH, ARCH_MAGIC):
                return SuperBlock(page, index * PAGE_SIZE)
        return None

    def live_root(self) -> SuperBlock:
        """Return the live (newest complete) commit root.

        Uses the commit that CI0 (the commit info page at offset 0x2000) points to, the same
        way Acronis does. If there is no valid CI0, as in archives written in "append" mode,
        it uses the commit of the last commit info page, found by scanning backward from the
        end of the file. Only if no commit info can be used at all does it fall back to the
        last CRC-valid ARCH header.

        Raises:
            ~dissect.archive.tibx.exception.CorruptArchiveError: If no ARCH superblock exists.
        """
        if (ci0 := self._ci0()) is not None:
            # CI0 names the newest commit info, which must describe the same root
            ci = self._commit_info_at(ci0.prev_ci_offset)
            if ci is not None and ci.arch_offset == ci0.arch_offset:
                root = self._root_at(ci.arch_offset, ci.offset)
                if root is not None:
                    return root
        if (ci := self._last_ci()) is not None and (root := self._root_at(ci.arch_offset, ci.offset)) is not None:
            return root
        if (root := self._last_arch()) is not None:
            return root
        raise CorruptArchiveError("No ARCH superblock found")

    def commit_roots(self) -> list[SuperBlock]:
        """Return all ARCH commit roots, oldest to newest (by commit time).

        Each commit root is a complete copy-on-write snapshot of the archive, at a commit
        rather than a backup: a backup takes several commits (see
        :meth:`TIBX.recovery_points`). They are found by following the commit info chain back
        from the :meth:`live_root`, and by a full page scan if the chain does not check out.
        """
        roots = self._chained_roots()
        if roots is None:
            roots = self._scan_commit_roots()
        roots.sort(key=lambda sb: sb.modified_ms)
        return roots

    def _chained_roots(self) -> list[SuperBlock] | None:
        """Every commit root along the commit info chain, newest first, or None if it breaks."""
        try:
            root = self.live_root()
        except CorruptArchiveError:
            return None
        if (chain := self._chained_commit_infos(root)) is None:
            return None
        roots = [root]
        for ci in chain[1:]:
            # The first commit's header is page 0. Where CI0 is kept up to date it describes
            # the newest commit instead, so page 0 is checked against CI0's place rather
            # than against CI0's contents.
            offset = 0 if ci.offset == FIRST_CI_OFFSET else ci.arch_offset
            if (root := self._root_at(offset, ci.offset)) is None:
                return None
            roots.append(root)
        return roots

    def _scan_commit_roots(self) -> list[SuperBlock]:
        """Every page that carries the ARCH magic, by a full page scan."""
        roots = []
        for i, page in self.pages():
            # Envelope indexed directly -- see the ENVELOPE PARSING note at the top
            if page[0] == PAGE_MARKER and page[1] == c_tibx.PageType.ARCH and page[8:12] == ARCH_MAGIC:
                roots.append(SuperBlock(page, i * PAGE_SIZE))
        return roots

    def commit_infos(self) -> list[CommitInfo]:
        """Return all commit info pages, oldest to newest.

        The first is the one at page 2: the first commit's, or CI0 (see :meth:`_ci0`), which
        describes the newest commit instead. They are found by following the commit info chain back
        from the :meth:`live_root`, and by a full page scan if the chain does not check out.
        """
        try:
            chain = self._chained_commit_infos(self.live_root())
        except CorruptArchiveError:
            chain = None
        return self._scan_commit_infos() if chain is None else chain[::-1]

    def _chained_commit_infos(self, root: SuperBlock) -> list[CommitInfo] | None:
        """The commit info chain back from ``root``'s, newest first and page 2's last, or None if it breaks."""
        chain = []
        ci = self._commit_info_at(root.ci_offset)
        while ci is not None:
            chain.append(ci)
            if ci.offset == FIRST_CI_OFFSET:
                return chain
            previous = self._commit_info_at(ci.prev_ci_offset)
            # Each commit info is written after the one before it, so ci_seq counts down
            # along the chain wherever "rewrite" mode put the pages; that also ends a chain
            # that loops. Only a CI0, which ends the chain, was written after them all.
            if previous is not None and previous.offset != FIRST_CI_OFFSET and previous.ci_seq >= ci.ci_seq:
                return None
            ci = previous
        return None

    def _scan_commit_infos(self) -> list[CommitInfo]:
        """Every commit info page whose CRC-32C and CRC-64 hold, by a full page scan."""
        infos = []
        for i, page in self.pages():
            # Envelope indexed directly -- see the ENVELOPE PARSING note at the top
            if page[1] == c_tibx.PageType.ARCI and (ci := _commit_info(page, i * PAGE_SIZE)):
                infos.append(ci)
        return infos

    def verify(self) -> dict:
        """CRC-32C every page and return a summary.

        All-zero pages are counted as ``holes``, not corruption: in a version set whose
        base file was compacted by a backup cleanup, the removed page ranges legitimately
        read back as zeros (nothing alive references them).

        Returns:
            A dict with ``ok``/``bad``/``holes`` page counts, the ``bad_pages`` indices
            and an ``ok``-page count per type name in ``by_type``.
        """
        zero_page = b"\x00" * PAGE_SIZE
        ok = bad = holes = 0
        by_type: dict[str, int] = {}
        bad_pages: list[int] = []
        for index, page in self.pages():
            if page == zero_page:
                holes += 1
                continue
            header = c_tibx.page_header(page)
            if header.crc32c == page_crc32c(page):
                ok += 1
                name = _type_name(header.type)
                by_type[name] = by_type.get(name, 0) + 1
            else:
                bad += 1
                bad_pages.append(index)
        return {"ok": ok, "bad": bad, "holes": holes, "bad_pages": bad_pages, "by_type": by_type}
