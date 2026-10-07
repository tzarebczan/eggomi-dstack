"""What one sandbox can see of the others (stdlib only; prints one JSON object).

Runs inside a sandbox with ``docker exec`` (as root, the strongest position a
compromised process there could reach) or, for the escape check, in the CVM
under nsenter. The request is JSON on stdin, so its marker strings appear in
no command line, and it never carries a secret: file searches look for a
non-secret canary.

    {"markers": ["keeper_svc"], "pids": [123], "paths": ["/x"],
     "connect": ["10.0.0.1:7011"], "canary": "...", "roots": ["/"],
     "chromium": true}
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import errno
import json
import os
import platform
import socket
import sys
from typing import Any, Dict, List

SKIP_DIRS = ("/proc", "/sys", "/dev")


def _cmdline(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as handle:
            return handle.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return ""


def _status(pid: str) -> Dict[str, str]:
    out = {}
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as handle:
            for line in handle:
                key, _, value = line.partition(":")
                out[key] = value.strip()
    except OSError:
        pass
    return out


def _ns(pid: str, kind: str) -> str:
    try:
        return os.readlink(f"/proc/{pid}/ns/{kind}")
    except OSError as exc:
        return errno.errorcode.get(exc.errno, str(exc.errno))


def processes() -> Dict[str, str]:
    """Every other pid this view of /proc lists, with its command line."""
    me = str(os.getpid())
    return {p: _cmdline(p) for p in os.listdir("/proc") if p.isdigit() and p != me}


def open_mem(pid: int) -> str:
    """Try to read another process's memory by its number."""
    try:
        with open(f"/proc/{pid}/mem", "rb") as handle:
            handle.read(1)
        return "readable"
    except OSError as exc:
        return errno.errorcode.get(exc.errno, str(exc.errno))


def connect(address: str) -> str:
    """TCP connect with a short timeout; the outcome as a word."""
    host, _, port = address.rpartition(":")
    try:
        with socket.create_connection((host, int(port)), timeout=2):
            return "connected"
    except socket.timeout:
        return "timeout"
    except OSError as exc:
        return errno.errorcode.get(exc.errno, str(exc.errno))


def grep(canary: bytes, roots: List[str]) -> Dict[str, Any]:
    """Every readable regular file under ``roots`` that holds ``canary``."""
    hits, scanned, errors = [], 0, 0
    for root in roots:
        for top, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if os.path.join(top, d) not in SKIP_DIRS]
            for name in files:
                path = os.path.join(top, name)
                try:
                    if not os.path.isfile(path) or os.path.islink(path):
                        continue
                    with open(path, "rb") as handle:
                        tail = b""
                        while True:
                            block = handle.read(1 << 20)
                            if not block:
                                break
                            if canary in tail + block:
                                hits.append(path)
                                break
                            tail = block[-len(canary) :]
                    scanned += 1
                except OSError:
                    errors += 1
    return {"hits": hits, "files_scanned": scanned, "unreadable": errors}


def chromium() -> Dict[str, Any]:
    """Chromium's own sandbox, as its renderers show it."""
    procs = processes()
    main_pid = next(
        (
            p
            for p, c in procs.items()
            if "chromium" in c and "--type=" not in c and "crashpad" not in c
        ),
        None,
    )
    renderers = [p for p, c in procs.items() if "--type=renderer" in c]
    if main_pid is None or not renderers:
        return {"browser": main_pid, "renderers": 0}
    rows = []
    for pid in renderers:
        status = _status(pid)
        rows.append(
            {
                "pid": pid,
                "seccomp": status.get("Seccomp"),
                "own_user_ns": _ns(pid, "user") != _ns(main_pid, "user"),
                "own_pid_ns": _ns(pid, "pid") != _ns(main_pid, "pid"),
                "own_net_ns": _ns(pid, "net") != _ns(main_pid, "net"),
                "uid": status.get("Uid", "").split()[:1],
            }
        )
    return {
        "browser": main_pid,
        "browser_uid": _status(main_pid).get("Uid", "").split()[:1],
        "renderers": len(rows),
        "all_seccomp_filter": all(r["seccomp"] == "2" for r in rows),
        "all_own_namespaces": all(
            r["own_user_ns"] and r["own_pid_ns"] and r["own_net_ns"] for r in rows
        ),
        "rows": rows,
    }


def main() -> int:
    """Run the requested checks."""
    request = json.loads(sys.stdin.read() or "{}")
    procs = processes()
    out: Dict[str, Any] = {
        "kernel": platform.release(),
        "uid": os.getuid(),
        "pid_count": len(procs),
        "markers": {
            m: sorted(p for p, c in procs.items() if m in c)
            for m in request.get("markers", [])
        },
        "mem": {str(p): open_mem(p) for p in request.get("pids", [])},
        "kcore": os.path.exists("/proc/kcore"),
        "dev_mem": os.path.exists("/dev/mem"),
        "paths": {p: os.path.exists(p) for p in request.get("paths", [])},
        "connect": {a: connect(a) for a in request.get("connect", [])},
    }
    if request.get("canary"):
        out["grep"] = grep(
            request["canary"].encode("utf-8"), request.get("roots", ["/"])
        )
    if request.get("chromium"):
        out["chromium"] = chromium()
    json.dump(out, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
