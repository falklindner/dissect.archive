"""Exceptions raised by the TIBX parser."""

from __future__ import annotations

from dissect.archive.exception import Error


class TibxError(Error):
    """Base exception for TIBX parsing errors."""


class InvalidArchiveError(TibxError):
    """The file is not a TIBX archive."""


class CorruptArchiveError(TibxError):
    """The archive is a TIBX archive but its structure is damaged."""


class UnsupportedFormatError(TibxError):
    """The archive uses a TIBX feature this parser does not (yet) support."""


class InvalidPasswordError(TibxError):
    """The archive is encrypted and the supplied password is missing or wrong."""
