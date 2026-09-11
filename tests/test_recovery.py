from __future__ import annotations

import io
import uuid

import pytest

from dissect.archive.tibx.exception import InvalidArchiveError
from dissect.archive.tibx.tibx import TIBX
from tests._synth import ExtentSpec, build_lsm_archive

# A chain lives in one archive: each backup writes its extents under its own slice id, and
# the slices tree (TLV[5]) records the backups. Slice ids are not contiguous in the wild --
# a real differential chain numbered its two backups 2 and 4 -- so this uses 2, 3, 5.
SLICES = [2, 3, 5]


def _chain() -> TIBX:
    archive = build_lsm_archive(
        [
            ExtentSpec(10, 0, b"base state" + b"\x00" * 54, slice_id=2),
            ExtentSpec(10, 0, b"after first backup" + b"\x00" * 46, slice_id=3),
            ExtentSpec(10, 0, b"after second backup" + b"\x00" * 45, slice_id=5),
        ],
        slices=SLICES,
    )
    return TIBX(io.BytesIO(archive))


def test_recovery_points_are_backups_not_commit_roots() -> None:
    # Acronis writes a varying number of ARCH commit roots per backup, so counting roots
    # invents recovery points that were never taken. The slices tree is the archive's own
    # record of its backups, and matches what "acrocmd list backups" lists.
    tibx = _chain()
    points = tibx.recovery_points()

    assert len(points) == 3
    assert [p.index for p in points] == [0, 1, 2]
    assert [p.slice_id for p in points] == SLICES


def test_recovery_point_carries_guid_and_times() -> None:
    point = _chain().recovery_points()[1]

    assert point.guid == uuid.UUID(bytes_le=bytes([3]) * 16)
    assert point.created.timestamp() == pytest.approx(3.0)
    assert point.modified.timestamp() == pytest.approx(3.01)


def test_latest_is_default() -> None:
    tibx = _chain()
    assert tibx.streams()[0].read(0, 19) == b"after second backup"


def test_select_by_index() -> None:
    tibx = _chain()
    tibx.use_recovery_point(0)
    assert tibx.streams()[0].read(0, 10) == b"base state"

    tibx.use_recovery_point(1)
    assert tibx.streams()[0].read(0, 18) == b"after first backup"

    tibx.use_recovery_point(2)
    assert tibx.streams()[0].read(0, 19) == b"after second backup"


def test_selection_is_by_slice_not_position() -> None:
    # Selecting a point takes every extent up to and including its slice id. Picking the
    # middle backup of a chain whose ids are 2, 3, 5 must not be read as "slice <= 1".
    tibx = _chain()
    tibx.use_recovery_point(1)

    assert {extent.slice_id for extent in tibx.extents} == {2, 3}


def test_select_oldest_and_latest() -> None:
    tibx = _chain()
    tibx.use_recovery_point("oldest")
    assert tibx.streams()[0].read(0, 10) == b"base state"
    tibx.use_recovery_point("latest")
    assert tibx.streams()[0].read(0, 19) == b"after second backup"


def test_index_out_of_range() -> None:
    tibx = _chain()
    with pytest.raises(InvalidArchiveError, match="out of range"):
        tibx.use_recovery_point(5)


def test_invalid_selector() -> None:
    tibx = _chain()
    with pytest.raises(InvalidArchiveError, match="invalid recovery point"):
        tibx.use_recovery_point("bogus")


def test_archive_without_slices_reports_no_recovery_points() -> None:
    # An archive whose slices tree is absent records no backups. Reporting none is right;
    # the previous behaviour counted commit roots and reported points that never existed.
    archive = build_lsm_archive([ExtentSpec(10, 0, b"x" * 64)])
    tibx = TIBX(io.BytesIO(archive))

    assert tibx.recovery_points() == []
    with pytest.raises(InvalidArchiveError, match="records no backups"):
        tibx.use_recovery_point(0)
