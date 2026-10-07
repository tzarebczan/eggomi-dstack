"""CVM-side measurements for the L1 gVisor suites (root in the CVM, stdlib only).

Each subcommand prints one JSON object.

    cgroup CID             memory of one sandbox's cgroup and its host processes
    reclaim CID BYTES      write memory.reclaim; what memory.current gave back
    meminfo                the CVM's own MemTotal/MemAvailable
    sentries CID...        each sandbox's Sentry process: its host namespaces,
                           seccomp mode, capabilities, root, and the bridges
                           its network namespace attaches to
    timed CMD...           run CMD; seconds and exit code
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import ctypes
import errno
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

CGROOT = Path("/sys/fs/cgroup")
SYS_KCMP = 312  # x86_64
KCMP_VM = 1
_libc = ctypes.CDLL(None, use_errno=True)


def cgroup_dir(cid: str) -> Path:
    """Return the systemd scope dockerd made for container ``cid`` (full id)."""
    path = CGROOT / "system.slice" / f"docker-{cid}.scope"
    if not path.is_dir():
        raise FileNotFoundError(f"no cgroup for container {cid}")
    return path


def _kv(path: Path) -> Dict[str, int]:
    out = {}
    for line in path.read_text("utf-8").splitlines():
        key, _, value = line.partition(" ")
        if value.strip().lstrip("-").isdigit():
            out[key] = int(value)
    return out


def _proc_kb(pid: str, name: str, field: str) -> int:
    try:
        for line in Path(f"/proc/{pid}/{name}").read_text("utf-8").splitlines():
            if line.startswith(field + ":"):
                return int(line.split()[1]) * 1024
    except OSError:
        pass
    return 0


def _same_mm(a: str, b: str) -> bool:
    return _libc.syscall(SYS_KCMP, int(a), int(b), KCMP_VM, 0, 0) == 0


def address_spaces(pids: List[str]) -> List[str]:
    """One pid per distinct address space.

    systrap runs each application address space in stub processes that share
    one mm (CLONE_VM without a thread group), so per-process PSS repeats.
    """
    leaders: List[str] = []
    for pid in pids:
        if not any(_same_mm(pid, other) for other in leaders):
            leaders.append(pid)
    return leaders


def cgroup(cid: str) -> Dict[str, Any]:
    """memory.current and the host processes' RSS and PSS, in bytes.

    ``pss`` is summed once per address space (``address_spaces``) and splits
    pages shared with other address spaces: gVisor's memory file, which the
    Sentry and the stubs both map, and binaries other sandboxes also map.
    ``memory_current`` is what the role's cgroup is charged, page cache
    included; page cache first charged to another cgroup is not in it.
    """
    path = cgroup_dir(cid)
    pids = path.joinpath("cgroup.procs").read_text("utf-8").split()
    spaces = address_spaces(pids)
    stat = _kv(path / "memory.stat")
    names: Dict[str, int] = {}
    for pid in pids:
        try:
            comm = Path(f"/proc/{pid}/comm").read_text("utf-8").strip()
        except OSError:
            continue
        names[comm] = names.get(comm, 0) + 1
    return {
        "memory_current": int(path.joinpath("memory.current").read_text().strip()),
        "memory_max": path.joinpath("memory.max").read_text().strip(),
        "cpu_max": path.joinpath("cpu.max").read_text().strip(),
        "anon": stat.get("anon", 0),
        "file": stat.get("file", 0),
        "shmem": stat.get("shmem", 0),
        "rss": sum(_proc_kb(p, "status", "VmRSS") for p in spaces),
        "pss": sum(_proc_kb(p, "smaps_rollup", "Pss") for p in spaces),
        "procs": len(pids),
        "address_spaces": len(spaces),
        "comms": names,
    }


def reclaim(cid: str, amount: int) -> Dict[str, Any]:
    """Ask the kernel to reclaim ``amount`` bytes from one sandbox's cgroup."""
    path = cgroup_dir(cid)
    before = int(path.joinpath("memory.current").read_text().strip())
    started = time.monotonic()
    error = None
    try:
        with open(path / "memory.reclaim", "w", encoding="ascii") as handle:
            handle.write(f"{amount}\n")
    except OSError as exc:
        # EAGAIN: the kernel reclaimed less than asked. That is a result.
        error = errno.errorcode.get(exc.errno, str(exc.errno))
    seconds = time.monotonic() - started
    after = int(path.joinpath("memory.current").read_text().strip())
    return {
        "before": before,
        "after": after,
        "reclaimed": before - after,
        "requested": amount,
        "seconds": round(seconds, 3),
        "error": error,
    }


def meminfo() -> Dict[str, int]:
    """Return the CVM's MemTotal, MemAvailable, used, and ZFS ARC, in bytes.

    dstack's data disk is ZFS. Its ARC is not page cache, so MemAvailable
    counts it as used; checkpoint images written or read there grow it.
    """
    fields = {}
    for line in Path("/proc/meminfo").read_text("utf-8").splitlines():
        key, _, value = line.partition(":")
        fields[key] = int(value.split()[0]) * 1024
    arc = 0
    try:
        for line in (
            Path("/proc/spl/kstat/zfs/arcstats").read_text("utf-8").splitlines()
        ):
            parts = line.split()
            if parts[:1] == ["size"]:
                arc = int(parts[2])
    except OSError:
        pass
    return {
        "total": fields["MemTotal"],
        "available": fields["MemAvailable"],
        "used": fields["MemTotal"] - fields["MemAvailable"],
        "zfs_arc": arc,
        "shmem": fields.get("Shmem", 0),
    }


SENTRY_COMMS = ("gvisor_sentry", "runsc-sandbox")


def _comm(pid: str) -> str:
    try:
        return Path(f"/proc/{pid}/comm").read_text("utf-8").strip()
    except OSError:
        return ""


def _ppid(pid: str) -> str:
    try:
        return Path(f"/proc/{pid}/stat").read_text("utf-8").rsplit(")", 1)[1].split()[1]
    except (OSError, IndexError):
        return ""


def _sentry_pid(cid: str) -> str:
    """Return the Sentry: a sentry process whose parent is not one (stubs are its children)."""
    for pid in cgroup_dir(cid).joinpath("cgroup.procs").read_text("utf-8").split():
        if _comm(pid) in SENTRY_COMMS and _comm(_ppid(pid)) not in SENTRY_COMMS:
            return pid
    raise LookupError(f"no Sentry process in container {cid}")


def bridges(pid: str) -> List[str]:
    """Return the CVM bridges that ``pid``'s network namespace attaches to.

    Inside the namespace each interface is a veth whose peer (``@ifN``) sits
    in the CVM's namespace with a ``master`` bridge. An escapee there can put
    frames on those bridges and nowhere else.
    """
    inner = subprocess.run(
        ["nsenter", "-t", pid, "-n", "ip", "-o", "link"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    peers = {m.group(1) for m in re.finditer(r"@if(\d+):", inner)}
    outer = subprocess.run(
        ["ip", "-o", "link"], capture_output=True, text=True, check=True
    ).stdout
    out = []
    for line in outer.splitlines():
        index = line.split(":", 1)[0].strip()
        master = re.search(r" master (\S+) ", line)
        if index in peers:
            out.append(master.group(1) if master else "none")
    return sorted(out)


def sentries(cids: List[str]) -> Dict[str, Any]:
    """Host-side view of each Sentry: what escaping into it would reach."""
    out = {}
    for cid in cids:
        pid = _sentry_pid(cid)
        status = {}
        for line in Path(f"/proc/{pid}/status").read_text("utf-8").splitlines():
            key, _, value = line.partition(":")
            status[key] = value.strip()
        ns = {}
        for kind in ("pid", "net", "mnt", "ipc", "uts", "user", "cgroup"):
            try:
                ns[kind] = os.readlink(f"/proc/{pid}/ns/{kind}")
            except OSError as exc:
                ns[kind] = errno.errorcode.get(exc.errno, "?")
        try:
            root = sorted(os.listdir(f"/proc/{pid}/root"))
        except OSError as exc:
            root = [errno.errorcode.get(exc.errno, "?")]
        out[cid] = {
            "pid": int(pid),
            "seccomp": status.get("Seccomp"),
            "no_new_privs": status.get("NoNewPrivs"),
            "cap_eff": status.get("CapEff"),
            "uid": status.get("Uid", "").split()[:1],
            "ns": ns,
            "root_entries": root,
            "bridges": bridges(pid),
        }
    return out


def timed(cmd: List[str]) -> Dict[str, Any]:
    """Run ``cmd`` and time it."""
    started = time.monotonic()
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False
    )
    return {
        "seconds": round(time.monotonic() - started, 3),
        "rc": proc.returncode,
        "output": proc.stdout.decode("utf-8", "replace")[-2000:],
    }


def main(argv: List[str]) -> int:
    """Dispatch one subcommand."""
    cmd, args = argv[0], argv[1:]
    if cmd == "cgroup":
        result: Any = cgroup(args[0])
    elif cmd == "reclaim":
        result = reclaim(args[0], int(args[1]))
    elif cmd == "meminfo":
        result = meminfo()
    elif cmd == "sentries":
        result = sentries(args)
    elif cmd == "timed":
        result = timed(args)
    else:
        print(__doc__, file=sys.stderr)
        return 2
    json.dump(result, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
