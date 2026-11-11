"""Exceptions raised by the TIBX parser."""

from __future__ import annotations

from dissect.archive.exception import Error


class TibxError(Error):
    """Base exception for TIBX parsing errors."""


class InvalidArchiveError(TibxError):
    """The file is not a TIBX archive."""


class CorruptArchiveError(TibxError):
    """The archive is a TIBX archive but its structure is damaged."""


class MissingVolumeError(CorruptArchiveError):
    """One or more volumes of an archive that consists of several are missing.

    Acronis calls the files of an archive its volumes; they have nothing to do with the
    backed-up volumes of :meth:`~dissect.archive.tibx.tibx.TIBX.volumes`.
    """


class UnsupportedFormatError(TibxError):
    """The archive uses a TIBX feature this parser does not (yet) support."""


class InvalidPasswordError(TibxError):
    """The archive is encrypted and the supplied password is missing or wrong."""
