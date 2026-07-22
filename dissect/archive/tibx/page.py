"""TIBX page store: 4 KiB pages, ARCH superblocks, transactional commit-root selection.

A ``.tibx`` is append-only transactional: every commit appends a new ARCH superblock
carrying its own copy-on-write LSM trees, so each ARCH page is a complete point-in-time
snapshot (a recovery point). The highest-offset ARCH page whose CRC validates is the live
root; a torn final commit (power loss) is skipped in favor of the newest complete root.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING, BinaryIO

from dissect.util import ts

from dissect.archive.tibx.c_tibx import PAGE_MARKER, PAGE_SIZE, c_tibx
from dissect.archive.tibx.crc32c import page_crc32c
from dissect.archive.tibx.exceptions import CorruptArchiveError, InvalidArchiveError

if TYPE_CHECKING:
    import datetime
    from collections.abc import Iterator

ARCH_MAGIC = b"ARCH"

# Pages recently returned by ``page()`` are kept in a small LRU so repeated single-page
# reads -- LSM directory pages revisited during tree walks, a segment header page read to
# parse the ``Segment`` then again to read its payload -- do not each re-hit the backing
# file (which may be a network share). 512 pages == 2 MiB.
PAGE_CACHE_SIZE = 512


def _type_name(value: int) -> str:
    try:
        return c_tibx.PageType(value).name
    except ValueError:
        return f"{value:#04x}"


class SuperBlock:
    """An ARCH superblock (commit root) at a given byte offset in the page store."""

    def __init__(self, page: bytes, offset: int):
        if page[8:12] != ARCH_MAGIC:
            raise InvalidArchiveError(f"Not an ARCH superblock at offset {offset:#x}")
        self.offset = offset
        self.sb = c_tibx.arch_superblock(page)
        self.header_size = self.sb.header_size
        self.archive_uuid: bytes = bytes(self.sb.archive_uuid)
        self.created_ms: int = self.sb.created_ms
        self.modified_ms: int = self.sb.modified_ms
        self.compr_lvl: c_tibx.ComprLvl = self.sb.compr_lvl
        self.encr_alg: c_tibx.EncrAlg = self.sb.encr_alg
        self.hash_alg: int = self.sb.hash_alg
        self.dedup: bool = bool(self.sb.dedup)

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


class PageStore:
    """Random access to the 4 KiB pages of a ``.tibx`` archive.

    Args:
        fh: A file-like object of the (stitched, in case of split archives) page store.

    Raises:
        InvalidArchiveError: If page 0 is not an ARCH superblock.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        fh.seek(0, 2)
        self.size = fh.tell()
        self.page_count = self.size // PAGE_SIZE
        self._page_cache: OrderedDict[int, bytes] = OrderedDict()

        if self.size < PAGE_SIZE or self.page(0)[8:12] != ARCH_MAGIC:
            raise InvalidArchiveError("Missing ARCH magic at page 0")

    def page(self, index: int) -> bytes:
        """Read the page at ``index`` (LRU-cached).

        Raises:
            CorruptArchiveError: If the page does not exist or is truncated.
        """
        cached = self._page_cache.get(index)
        if cached is not None:
            self._page_cache.move_to_end(index)
            return cached
        if not 0 <= index < self.page_count:
            raise CorruptArchiveError(f"page {index} is out of bounds (archive has {self.page_count} pages)")
        self.fh.seek(index * PAGE_SIZE)
        page = self.fh.read(PAGE_SIZE)
        if len(page) != PAGE_SIZE:
            raise CorruptArchiveError(f"short read on page {index}")
        self._page_cache[index] = page
        if len(self._page_cache) > PAGE_CACHE_SIZE:
            self._page_cache.popitem(last=False)
        return page

    def read_run(self, start: int, count: int) -> list[bytes]:
        """Read ``count`` consecutive pages beginning at ``start`` in a single I/O.

        Collapses what would otherwise be ``count`` separate ``seek``+``read`` calls into
        one -- the pages of a multi-page segment are physically contiguous, so this is the
        batch read path for :func:`segment.read_compressed`. Unlike :meth:`page` it does not
        populate the LRU (segment payload pages are read once), but it does honour pages
        already resident there.

        Raises:
            CorruptArchiveError: If the run extends past the end of the archive or is truncated.
        """
        if count <= 0:
            return []
        if start < 0 or start + count > self.page_count:
            raise CorruptArchiveError(f"page run {start}..{start + count} is out of bounds ({self.page_count} pages)")
        self.fh.seek(start * PAGE_SIZE)
        blob = self.fh.read(count * PAGE_SIZE)
        if len(blob) != count * PAGE_SIZE:
            raise CorruptArchiveError(f"short read on page run {start}..{start + count}")
        return [blob[i * PAGE_SIZE : (i + 1) * PAGE_SIZE] for i in range(count)]

    def page_type(self, index: int) -> int:
        """Return the type byte of the page at ``index``."""
        return self.page(index)[1]

    def page_type_name(self, index: int) -> str:
        """Return the type of the page at ``index`` as a name, or hex for unknown types."""
        return _type_name(self.page_type(index))

    def pages(self) -> Iterator[tuple[int, bytes]]:
        """Iterate over all ``(index, page)`` pairs."""
        for index in range(self.page_count):
            yield index, self.page(index)

    def live_root(self) -> SuperBlock:
        """Return the live (newest complete) commit root.

        Scans backward from EOF and returns the first ARCH page whose CRC validates --
        the highest-offset ARCH is the newest commit, and skipping CRC-invalid ones
        recovers from a torn final commit.

        Raises:
            CorruptArchiveError: If no CRC-valid ARCH superblock exists.
        """
        for index in range(self.page_count - 1, -1, -1):
            page = self.page(index)
            if (
                page[1] == c_tibx.PageType.ARCH
                and page[8:12] == ARCH_MAGIC
                and int.from_bytes(page[4:8], "big") == page_crc32c(page)
            ):
                return SuperBlock(page, index * PAGE_SIZE)
        raise CorruptArchiveError("No CRC-valid ARCH superblock found")

    def commit_roots(self) -> list[SuperBlock]:
        """Return all ARCH commit roots, oldest to newest (by commit time).

        Each commit root is a complete copy-on-write snapshot -- a selectable recovery
        point. This is a full page scan; use :meth:`live_root` for just the newest.
        """
        roots = []
        for i, page in self.pages():
            if page[0] == PAGE_MARKER and page[1] == c_tibx.PageType.ARCH and page[8:12] == ARCH_MAGIC:
                roots.append(SuperBlock(page, i * PAGE_SIZE))
        roots.sort(key=lambda sb: sb.modified_ms)
        return roots

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
            elif int.from_bytes(page[4:8], "big") == page_crc32c(page):
                ok += 1
                name = _type_name(page[1])
                by_type[name] = by_type.get(name, 0) + 1
            else:
                bad += 1
                bad_pages.append(index)
        return {"ok": ok, "bad": bad, "holes": holes, "bad_pages": bad_pages, "by_type": by_type}
