"""Exceptions raised by the TIBX parser."""

from __future__ import annotations


class Error(Exception):
    """Base exception for TIBX parsing errors."""


class InvalidArchiveError(Error):
    """The file is not a TIBX archive."""


class CorruptArchiveError(Error):
    """The archive is a TIBX archive but its structure is damaged."""


class UnsupportedFormatError(Error):
    """The archive uses a TIBX feature this parser does not (yet) support."""


class InvalidPasswordError(Error):
    """The archive is encrypted and the supplied password is missing or wrong."""
