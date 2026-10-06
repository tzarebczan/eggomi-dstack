"""Hide keeper authority from a compartment process.

The launcher runs this module inside ``unshare --user --map-root-user
--mount``. Mounts exist only in that namespace. The parent keeps the real
files. A child that can see its own role directory still cannot open the
authority directory or rewrite the admission registry.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


def popen_confined(
    command: Sequence[str],
    *,
    hide_dirs: Sequence[Path],
    keep_dirs: Sequence[Path],
    ro_files: Sequence[Path],
    env: Mapping[str, str],
    stdin: Any,
    stdout: Any,
    stderr: Any,
) -> subprocess.Popen[bytes]:
    """Run ``command`` in a user and mount namespace that hides authority."""
    wrapper = [
        "unshare",
        "--user",
        "--map-root-user",
        "--mount",
        sys.executable,
        "-m",
        "cah.confine",
    ]
    for path in hide_dirs:
        wrapper.extend(["--hide-dir", str(path)])
    for path in keep_dirs:
        wrapper.extend(["--keep-dir", str(path)])
    for path in ro_files:
        wrapper.extend(["--ro-file", str(path)])
    wrapper.append("--")
    wrapper.extend(command)
    return subprocess.Popen(
        wrapper,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        env=dict(env),
    )


def main(argv: list[str] | None = None) -> int:
    """Apply hides and then exec the compartment command."""
    args = list(sys.argv[1:] if argv is None else argv)
    if "--" not in args:
        print("error: confine command is missing", file=sys.stderr)
        return 1
    split = args.index("--")
    options = args[:split]
    command = args[split + 1 :]
    if not command:
        print("error: confine command is missing", file=sys.stderr)
        return 1
    hides: list[str] = []
    keeps: list[str] = []
    read_only: list[str] = []
    index = 0
    while index < len(options):
        flag = options[index]
        if index + 1 >= len(options):
            print("error: confine option needs a path", file=sys.stderr)
            return 1
        value = options[index + 1]
        if flag == "--hide-dir":
            hides.append(value)
        elif flag == "--keep-dir":
            keeps.append(value)
        elif flag == "--ro-file":
            read_only.append(value)
        else:
            print(f"error: unknown confine option {flag}", file=sys.stderr)
            return 1
        index += 2
    try:
        _apply(hides, keeps, read_only)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"error: confine mount failed: {exc}", file=sys.stderr)
        return 1
    os.execv(command[0], command)
    return 1


def _apply(hides: list[str], keeps: list[str], read_only: list[str]) -> None:
    staged: list[tuple[str, str]] = []
    for index, path in enumerate(keeps):
        stage = f"/tmp/cah-keep-{os.getpid()}-{index}"
        os.mkdir(stage)
        _mount(["mount", "--bind", path, stage])
        staged.append((path, stage))
    for path in hides:
        if not os.path.isdir(path):
            raise OSError(f"hide path is not a directory: {path}")
        _mount(["mount", "-t", "tmpfs", "tmpfs", path])
    for path, stage in staged:
        os.makedirs(path, exist_ok=True)
        _mount(["mount", "--bind", stage, path])
    for path in read_only:
        if not os.path.isfile(path):
            raise OSError(f"read-only path is not a file: {path}")
        _mount(["mount", "--bind", path, path])
        _mount(["mount", "-o", "remount,bind,ro", path])


def _mount(argv: list[str]) -> None:
    subprocess.run(argv, check=True, capture_output=True, text=True)


if __name__ == "__main__":
    raise SystemExit(main())
