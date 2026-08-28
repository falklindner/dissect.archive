from __future__ import annotations

import io

import pytest

from dissect.archive.tibx.exception import InvalidArchiveError
from dissect.archive.tibx.tibx import TIBX
from tests._synth import ExtentSpec, build_multiroot_archive


def _chain() -> TIBX:
    # Three recovery points: base, then a changed file, then another change
    archive = build_multiroot_archive(
        [
            [ExtentSpec(10, 0, b"base state" + b"\x00" * 54)],
            [ExtentSpec(10, 0, b"after first backup" + b"\x00" * 46)],
            [ExtentSpec(10, 0, b"after second backup" + b"\x00" * 45)],
        ]
    )
    return TIBX(io.BytesIO(archive))


def test_recovery_points_enumerated() -> None:
    tibx = _chain()
    points = tibx.recovery_points()
    assert len(points) == 3  # the empty initial root is excluded
    assert [p.index for p in points] == [0, 1, 2]
    # oldest -> newest by commit time
    assert [p.root.modified_ms for p in points] == [1000, 2000, 3000]


def test_latest_is_default() -> None:
    tibx = _chain()
    assert tibx.volumes()[0].read(0, 19) == b"after second backup"


def test_select_by_index() -> None:
    tibx = _chain()
    tibx.use_recovery_point(0)
    assert tibx.volumes()[0].read(0, 10) == b"base state"

    tibx.use_recovery_point(1)
    assert tibx.volumes()[0].read(0, 18) == b"after first backup"

    tibx.use_recovery_point(2)
    assert tibx.volumes()[0].read(0, 19) == b"after second backup"


def test_select_oldest_and_latest() -> None:
    tibx = _chain()
    tibx.use_recovery_point("oldest")
    assert tibx.volumes()[0].read(0, 10) == b"base state"
    tibx.use_recovery_point("latest")
    assert tibx.volumes()[0].read(0, 19) == b"after second backup"


def test_index_out_of_range() -> None:
    tibx = _chain()
    with pytest.raises(InvalidArchiveError, match="out of range"):
        tibx.use_recovery_point(5)


def test_invalid_selector() -> None:
    tibx = _chain()
    with pytest.raises(InvalidArchiveError, match="invalid recovery point"):
        tibx.use_recovery_point("bogus")
