"""A lazy, seekable stream over a reconstructed TIBX volume."""

from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.util.stream import AlignedStream

from dissect.archive.tibx.c_tibx import PAGE_SIZE

if TYPE_CHECKING:
    from dissect.archive.tibx.tibx import TibxVolume


class TibxVolumeStream(AlignedStream):
    """The raw byte space of one backed-up volume.

    Reads are lazy -- only the segments backing the requested range are fetched and
    decompressed -- and sparse regions read back as zeros.
    """

    def __init__(self, volume: TibxVolume):
        self.volume = volume
        super().__init__(size=volume.size, align=PAGE_SIZE)

    def _read(self, offset: int, length: int) -> bytes:
        length = max(0, min(length, self.size - offset))
        return self.volume.read(offset, length)
