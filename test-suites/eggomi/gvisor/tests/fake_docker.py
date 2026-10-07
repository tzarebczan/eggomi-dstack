#!/usr/bin/env python3
"""A stand-in for the docker CLI, enough for gv-ckpt's unit tests.

State lives in the JSON file ``$FAKE_DOCKER_DB``: containers by name, with
an id, ``StartedAt``, ``Created``, and a running flag. Checkpoints are
directories under ``$FAKE_DOCKER_ROOT``; a restore stages a copy in
``$FAKE_DOCKER_STAGE``, as containerd does, and leaves it there.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

DB = Path(os.environ["FAKE_DOCKER_DB"])
ROOT = Path(os.environ["FAKE_DOCKER_ROOT"])
STAGE = Path(os.environ["FAKE_DOCKER_STAGE"])


def stamp() -> str:
    """Return an RFC 3339 timestamp with nanoseconds, as Docker prints it."""
    now = time.time()
    return (
        time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
        + f".{int(now % 1 * 1e9):09d}Z"
    )


def main(argv: list) -> int:
    """Run one fake docker command."""
    db = json.loads(DB.read_text())
    ctrs = db["containers"]

    def find(ref: str) -> dict:
        for name, c in ctrs.items():
            if ref in (name, c["id"]):
                return c
        sys.stderr.write(f"No such container: {ref}\n")
        raise SystemExit(1)

    time.sleep(float(os.environ.get("FAKE_DOCKER_HANG", "0")))
    if os.environ.get("FAKE_DOCKER_DOWN"):
        sys.stderr.write(
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
            "Is the docker daemon running?\n"
        )
        return 1
    if argv[:3] == ["inspect", "--type", "container"]:
        c = find(argv[3])
        out = {
            "Id": c["id"],
            "Created": c["created"],
            "State": {"StartedAt": c["started"], "Running": c["running"]},
        }
        print(json.dumps([out]))
        return 0
    if argv[:2] == ["checkpoint", "create"]:
        args = [a for a in argv[2:] if a != "--leave-running"]
        c = find(args[0])
        d = ROOT / "containers" / c["id"] / "checkpoints" / args[1]
        d.mkdir(parents=True)
        (d / "pages.img").write_bytes(b"memory image " + args[1].encode())
        # A checkpoint whose image is on disk but whose docker call has not
        # returned yet (dockerd slow or hung).
        time.sleep(float(os.environ.get("FAKE_DOCKER_CREATE_AFTER", "0")))
        if "--leave-running" not in argv:
            c["running"] = False
    elif argv[:2] == ["checkpoint", "rm"]:
        c = find(argv[2])
        shutil.rmtree(
            ROOT / "containers" / c["id"] / "checkpoints" / argv[3], ignore_errors=True
        )
    elif argv[:2] == ["start", "--checkpoint"]:
        time.sleep(float(os.environ.get("FAKE_DOCKER_RESTORE_DELAY", "0")))
        c = find(argv[3])
        src = ROOT / "containers" / c["id"] / "checkpoints" / argv[2]
        if not src.is_dir():
            sys.stderr.write("checkpoint not found\n")
            return 1
        stage = Path(tempfile.mkdtemp(prefix="ctrd-checkpoint", dir=STAGE))
        shutil.copytree(src, stage / "image")
        # Staged, not yet returned: a slow restore.
        time.sleep(float(os.environ.get("FAKE_DOCKER_RESTORE_AFTER", "0")))
        c["running"] = True
        c["started"] = stamp()
    else:
        sys.stderr.write(f"fake docker: unsupported {argv}\n")
        return 2
    DB.write_text(json.dumps(db))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
