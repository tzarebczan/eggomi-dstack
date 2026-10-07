#!/usr/bin/env python3
"""gv-ckpt: the CVM's checkpoint policy for gVisor browser sandboxes.

init-gvisor.sh installs this file as ``/run/eggomi/bin/gv-ckpt`` and starts
``gv-ckpt reap --loop``, so the policy is part of the measured app compose.
Every browser checkpoint and restore goes through it:

``arm CTR``
    The browser started from its image. It is pristine until its first fill.
    Refused for a container that ever filled, or one created before this boot
    (the policy state lives in tmpfs and does not know its history).
``filled CTR EXPIRES_MS``
    Called before a fill. The browser is no longer pristine, and every
    checkpoint taken from now on is a post-fill image that must be gone by
    the latest filled session's expiry (epoch milliseconds).
``create CTR NAME [--reuse] [--leave-running]``
    ``docker checkpoint create``. ``--reuse`` (an image to start later
    sessions from) is refused unless the browser is pristine. Without it, a
    post-fill image is a suspend of the same session only, and it carries
    the session's deadline.
``restore CTR NAME``
    ``docker start --checkpoint``, and in the same step the removal of the
    copy containerd stages in ``/tmp`` (RAM in the CVM) and never removes. A
    post-fill image past its deadline is deleted and refused, as is any
    image this tool did not create.
``reap [--loop SECONDS]``
    Delete post-fill images whose deadline passed, any checkpoint of a
    tracked browser that this tool did not record, and staged restore copies
    that a restore outside this tool left behind.

Output is one JSON object on stdout. Exit 0 on success, 3 when the policy
refuses, 1 on an error. Lab harness: test-suites/eggomi/gvisor/incvm-s*.sh.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

STATE_DIR = Path(os.environ.get("EGGOMI_GV_CKPT_STATE", "/run/eggomi/gv-ckpt"))
DOCKER = os.environ.get("EGGOMI_GV_CKPT_DOCKER", "docker")
DOCKER_ROOT = Path(os.environ.get("EGGOMI_GV_CKPT_DOCKER_ROOT", "/var/lib/docker"))
STAGE_DIR = Path(os.environ.get("EGGOMI_GV_CKPT_STAGE", "/tmp"))
STAGE_PREFIX = "ctrd-checkpoint"
# A staged restore copy older than this, outside a restore by this tool, is
# residue: containerd never removes it.
STALE_STAGE_SECONDS = 60
# The longest session a fill may declare. A post-fill image lives at most
# this long.
MAX_FILL_TTL_MS = 3_600_000
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

OK, REFUSED, ERROR = 0, 3, 1


class Refused(Exception):
    """The policy refuses the request; ``code`` names the rule."""

    def __init__(self, code: str, **detail: Any) -> None:
        """Keep the refusal code and its detail for the JSON reply."""
        super().__init__(code)
        self.code = code
        self.detail = detail


def now_ms() -> int:
    """Wall-clock time in epoch milliseconds."""
    return int(time.time() * 1000)


# A docker call that hangs (dockerd restarting) must not stall the policy.
DOCKER_TIMEOUT_SECONDS = 120


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run the docker CLI, capturing its output. A timeout reads as exit 124."""
    try:
        proc = subprocess.run(
            [DOCKER, *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        proc = subprocess.CompletedProcess([DOCKER, *args], 124, "", "docker timed out")
    if check and proc.returncode != 0:
        raise RuntimeError(f"docker {args[0]} failed: {proc.stderr.strip()[:400]}")
    return proc


def container_gone(cid: str) -> Optional[bool]:
    """Whether dockerd says the container does not exist.

    True only on a definite "No such container" (or "No such object") from
    the daemon, False when the container exists, and None when the answer is
    unknown: dockerd restarting, unreachable, or timing out.
    """
    proc = docker("inspect", "--type", "container", cid, check=False)
    if proc.returncode == 0:
        return False
    if re.search(r"No such (container|object)", proc.stderr):
        return True
    return None


def parse_time(value: str) -> float:
    """Parse Docker's RFC 3339 timestamps (nanosecond fractions) to epoch."""
    m = re.match(
        r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$", value
    )
    if not m:
        raise ValueError(f"unparsed timestamp {value!r}")
    zone = "+00:00" if m.group(3) == "Z" else m.group(3)
    base = datetime.fromisoformat(m.group(1) + zone).astimezone(timezone.utc)
    return base.timestamp() + float("0." + (m.group(2) or "0"))


def boot_time() -> float:
    """Return the CVM's boot time, from /proc/stat."""
    for line in Path("/proc/stat").read_text("ascii").splitlines():
        if line.startswith("btime "):
            return float(line.split()[1])
    raise RuntimeError("/proc/stat has no btime")


def inspect(ctr: str) -> Dict[str, Any]:
    """Return the container's id, run (StartedAt), running flag, and creation."""
    proc = docker("inspect", "--type", "container", ctr, check=False)
    if proc.returncode != 0:
        raise Refused("no_such_container", container=ctr)
    info = json.loads(proc.stdout)[0]
    return {
        "cid": info["Id"],
        "run": info["State"]["StartedAt"],
        "running": bool(info["State"]["Running"]),
        "created": parse_time(info["Created"]),
    }


@contextlib.contextmanager
def locked() -> Iterator[None]:
    """Serialise every policy step, so a fill cannot land mid-checkpoint."""
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(STATE_DIR / ".lock", "a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def load(cid: str) -> Optional[Dict[str, Any]]:
    """Return the policy state of one container, or ``None``."""
    path = STATE_DIR / f"{cid}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text("utf-8"))


def save(state: Dict[str, Any]) -> None:
    """Write one container's state whole (tmp + rename)."""
    path = STATE_DIR / f"{state['cid']}.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, sort_keys=True), "utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def checkpoint_dir(cid: str, name: str) -> Path:
    """Where dockerd keeps a container's checkpoint."""
    return DOCKER_ROOT / "containers" / cid / "checkpoints" / name


def staged_copies() -> List[Path]:
    """Restore copies containerd staged in the CVM's tmpfs."""
    if not STAGE_DIR.is_dir():
        return []
    return sorted(
        p for p in STAGE_DIR.iterdir() if p.name.startswith(STAGE_PREFIX) and p.is_dir()
    )


def tree_bytes(path: Path) -> int:
    """Apparent size of a directory tree."""
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            with contextlib.suppress(OSError):
                total += os.lstat(os.path.join(root, name)).st_size
    return total


def delete_checkpoint(ctr: str, cid: str, name: str) -> bool:
    """Remove a checkpoint through dockerd, then from disk. True if gone."""
    docker("checkpoint", "rm", ctr, name, check=False)
    target = checkpoint_dir(cid, name)
    shutil.rmtree(target, ignore_errors=True)
    return not target.exists()


def check_name(name: str) -> None:
    """Checkpoint names are plain path components."""
    if not NAME_RE.match(name):
        raise Refused("bad_name", name=name)


def current_state(info: Dict[str, Any]) -> Dict[str, Any]:
    """Return the state for the container's current run, or refuse."""
    state = load(info["cid"])
    if state is None or state.get("run") != info["run"]:
        raise Refused("unarmed", detail="this run was not armed or restored by gv-ckpt")
    return state


def cmd_arm(ctr: str) -> Dict[str, Any]:
    """Mark a browser freshly started from its image as pristine."""
    info = inspect(ctr)
    if not info["running"]:
        raise Refused("not_running")
    state = load(info["cid"])
    if state is None and info["created"] < boot_time():
        raise Refused("stale_container", detail="created before this boot; recreate it")
    if state is not None and state.get("ever_filled"):
        raise Refused(
            "not_pristine", detail="this container filled before; recreate it"
        )
    state = state or {"cid": info["cid"], "checkpoints": {}, "ever_filled": False}
    state.update(run=info["run"], pristine=True, fill_deadline_ms=None)
    save(state)
    return {"code": "ok", "pristine": True}


def cmd_filled(ctr: str, expires_ms: int) -> Dict[str, Any]:
    """Record a fill before it happens; the browser is no longer pristine."""
    if expires_ms > now_ms() + MAX_FILL_TTL_MS:
        raise Refused("ttl_too_long", max_ms=MAX_FILL_TTL_MS)
    info = inspect(ctr)
    state = load(info["cid"]) or {"cid": info["cid"], "checkpoints": {}}
    deadline = max(expires_ms, state.get("fill_deadline_ms") or 0)
    if state.get("run") != info["run"]:
        deadline = expires_ms
    state.update(
        run=info["run"], pristine=False, ever_filled=True, fill_deadline_ms=deadline
    )
    save(state)
    return {"code": "ok", "deadline_ms": deadline}


def cmd_create(ctr: str, name: str, reuse: bool, leave_running: bool) -> Dict[str, Any]:
    """Checkpoint under the pristine rule."""
    check_name(name)
    info = inspect(ctr)
    state = current_state(info)
    kind = "pristine" if state.get("pristine") else "post_fill"
    if reuse and kind != "pristine":
        raise Refused(
            "not_pristine",
            detail="a browser that filled may not be checkpointed for reuse",
        )
    deadline = None if kind == "pristine" else state.get("fill_deadline_ms")
    if kind == "post_fill" and (deadline is None or deadline <= now_ms()):
        raise Refused("expired", detail="the filled session already expired")
    if name in state["checkpoints"] or checkpoint_dir(info["cid"], name).exists():
        raise Refused("exists", name=name)
    args = (
        ["checkpoint", "create"]
        + (["--leave-running"] if leave_running else [])
        + [ctr, name]
    )
    start = time.monotonic()
    proc = docker(*args, check=False)
    if proc.returncode != 0:
        delete_checkpoint(ctr, info["cid"], name)
        raise RuntimeError(
            f"docker checkpoint create failed: {proc.stderr.strip()[:400]}"
        )
    state["checkpoints"][name] = {
        "kind": kind,
        "deadline_ms": deadline,
        "created_ms": now_ms(),
    }
    save(state)
    return {
        "code": "ok",
        "kind": kind,
        "deadline_ms": deadline,
        "seconds": round(time.monotonic() - start, 3),
    }


def cmd_restore(ctr: str, name: str) -> Dict[str, Any]:
    """Restore and remove containerd's staged copy in the same step."""
    check_name(name)
    info = inspect(ctr)
    if info["running"]:
        raise Refused("running")
    state = load(info["cid"])
    record = (state or {}).get("checkpoints", {}).get(name)
    if state is None or record is None:
        raise Refused(
            "unknown_checkpoint", detail="not created by gv-ckpt; never restored"
        )
    if record["kind"] == "post_fill" and record["deadline_ms"] <= now_ms():
        gone = delete_checkpoint(ctr, info["cid"], name)
        del state["checkpoints"][name]
        save(state)
        raise Refused("expired", deleted=gone)
    before = set(staged_copies())
    start = time.monotonic()
    proc = docker("start", "--checkpoint", name, ctr, check=False)
    seconds = round(time.monotonic() - start, 3)
    new = [p for p in staged_copies() if p not in before]
    staged_bytes = sum(tree_bytes(p) for p in new)
    for path in new:
        shutil.rmtree(path, ignore_errors=True)
    residue = sum(1 for p in new if p.exists())
    if proc.returncode != 0:
        raise RuntimeError(
            f"docker start --checkpoint failed: {proc.stderr.strip()[:400]}"
        )
    after = inspect(ctr)
    if record["kind"] == "pristine":
        state.update(run=after["run"], pristine=True, fill_deadline_ms=None)
    else:
        state.update(
            run=after["run"], pristine=False, fill_deadline_ms=record["deadline_ms"]
        )
    save(state)
    if residue:
        raise RuntimeError(f"{residue} staged restore copies could not be removed")
    return {
        "code": "ok",
        "kind": record["kind"],
        "seconds": seconds,
        "staged_copies_removed": len(new),
        "staged_bytes": staged_bytes,
        "residue": residue,
    }


def cmd_rm(ctr: str, name: str) -> Dict[str, Any]:
    """Delete one checkpoint and its record."""
    check_name(name)
    info = inspect(ctr)
    state = load(info["cid"])
    gone = delete_checkpoint(ctr, info["cid"], name)
    if state is not None and state["checkpoints"].pop(name, None) is not None:
        save(state)
    return {"code": "ok" if gone else "not_removed"}


def reap_once() -> Dict[str, Any]:
    """Delete expired post-fill images and stale staged restore copies.

    A checkpoint of a tracked browser that this tool did not record was
    made outside the policy (a raw ``docker checkpoint create``), so its
    contents are unknown: it is deleted too.
    """
    reaped: List[Dict[str, Any]] = []
    unknown: List[str] = []
    now = now_ms()
    for path in sorted(STATE_DIR.glob("*.json")):
        state = json.loads(path.read_text("utf-8"))
        cid = state["cid"]
        gone = container_gone(cid)
        if gone:
            # The container's directory, checkpoints included, went with it.
            path.unlink(missing_ok=True)
            continue
        if gone is None:
            # dockerd did not answer: keep the state and retry next pass.
            # Deadlines are still enforced below, on the files themselves.
            unknown.append(cid[:12])
        changed = False
        ckpts = DOCKER_ROOT / "containers" / cid / "checkpoints"
        if ckpts.is_dir():
            for entry in sorted(ckpts.iterdir()):
                if entry.name not in state["checkpoints"]:
                    gone = delete_checkpoint(cid, cid, entry.name)
                    reaped.append(
                        {
                            "cid": cid[:12],
                            "name": entry.name,
                            "deleted": gone,
                            "unrecorded": True,
                        }
                    )
        for name, record in list(state["checkpoints"].items()):
            if record["kind"] == "post_fill" and record["deadline_ms"] <= now:
                gone = delete_checkpoint(cid, cid, name)
                reaped.append({"cid": cid[:12], "name": name, "deleted": gone})
                if gone:
                    del state["checkpoints"][name]
                    changed = True
        if changed:
            save(state)
    stale = 0
    for copy in staged_copies():
        with contextlib.suppress(OSError):
            if time.time() - copy.stat().st_mtime > STALE_STAGE_SECONDS:
                shutil.rmtree(copy, ignore_errors=True)
                stale += 1
    return {
        "code": "ok",
        "reaped": reaped,
        "stale_stage_removed": stale,
        "docker_unanswered": unknown,
    }


def after_deadline_check(out: Dict[str, Any], ctr: str, name: str) -> Dict[str, Any]:
    """Reap once more before the lock is released.

    A checkpoint or restore holds the lock for seconds, and a post-fill
    deadline can pass meanwhile (the reaper waits on the lock). Whatever
    expired, this step's own image included, is deleted before anyone else
    can use it. A checkpoint whose own image expired that way is refused.
    """
    reaped = reap_once()["reaped"]
    out["reaped"] = reaped
    cid = inspect(ctr)["cid"][:12]
    own = any(r["cid"] == cid and r["name"] == name and r["deleted"] for r in reaped)
    if own and out.get("code") == "ok":
        if "staged_copies_removed" in out:
            # The browser is restored; its session is past its TTL.
            out["image_deleted_at_deadline"] = True
        else:
            raise Refused("expired", detail="the session expired while checkpointing")
    return out


def next_deadline_s() -> Optional[float]:
    """Seconds until the nearest post-fill deadline, if any."""
    deadlines = []
    for path in STATE_DIR.glob("*.json"):
        with contextlib.suppress(OSError, ValueError, KeyError):
            for record in json.loads(path.read_text("utf-8"))["checkpoints"].values():
                if record["kind"] == "post_fill":
                    deadlines.append(record["deadline_ms"])
    if not deadlines:
        return None
    return max(0.0, (min(deadlines) - now_ms()) / 1000)


# How often the sleeping reaper rereads the deadlines (state files only, no
# docker call), so a deadline added while it sleeps is not missed.
DEADLINE_POLL_SECONDS = 0.2


def reap_loop(interval: float, stop: Optional[threading.Event] = None) -> None:
    """Reap until killed: at each deadline, and every INTERVAL otherwise.

    The sleep is cut into short slices that reread the deadlines, so a
    post-fill image created while the reaper sleeps is reaped on time.
    ``stop`` ends the loop (tests); the CVM's reaper runs until killed.
    """
    stop = stop or threading.Event()
    while not stop.is_set():
        try:
            with locked():
                out = reap_once()
            if out["reaped"] or out["stale_stage_removed"] or out["docker_unanswered"]:
                print(json.dumps(out), flush=True)
        except Exception as exc:  # noqa: BLE001 - the reaper must keep running
            print(json.dumps({"code": "error", "message": str(exc)[:400]}), flush=True)
        slept = 0.0
        while slept < interval and not stop.is_set():
            nearest = None
            with contextlib.suppress(OSError):
                nearest = next_deadline_s()
            if nearest is not None and nearest <= 0:
                break
            step = DEADLINE_POLL_SECONDS
            if nearest is not None:
                step = min(step, nearest + 0.01)
            time.sleep(step)
            slept += step


def main(argv: Optional[List[str]] = None) -> int:
    """Parse the command, run it under the lock, and print one JSON reply."""
    parser = argparse.ArgumentParser(
        prog="gv-ckpt", description=__doc__.split("\n\n")[0]
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("arm").add_argument("container")
    p = sub.add_parser("filled")
    p.add_argument("container")
    p.add_argument("expires_ms", type=int)
    p = sub.add_parser("create")
    p.add_argument("container")
    p.add_argument("name")
    p.add_argument("--reuse", action="store_true")
    p.add_argument("--leave-running", action="store_true")
    for name in ("restore", "rm"):
        p = sub.add_parser(name)
        p.add_argument("container")
        p.add_argument("name")
    p = sub.add_parser("reap")
    p.add_argument("--loop", type=float, metavar="SECONDS")
    sub.add_parser("ls")
    args = parser.parse_args(argv)

    if args.cmd == "reap" and args.loop:
        reap_loop(args.loop)
        return OK
    try:
        with locked():
            if args.cmd == "arm":
                out = cmd_arm(args.container)
            elif args.cmd == "filled":
                out = cmd_filled(args.container, args.expires_ms)
            elif args.cmd == "create":
                out = cmd_create(
                    args.container, args.name, args.reuse, args.leave_running
                )
                out = after_deadline_check(out, args.container, args.name)
            elif args.cmd == "restore":
                out = cmd_restore(args.container, args.name)
                out = after_deadline_check(out, args.container, args.name)
            elif args.cmd == "rm":
                out = cmd_rm(args.container, args.name)
            elif args.cmd == "reap":
                out = reap_once()
            else:
                out = {
                    "code": "ok",
                    "states": [
                        json.loads(p.read_text("utf-8"))
                        for p in sorted(STATE_DIR.glob("*.json"))
                    ],
                }
    except Refused as exc:
        print(json.dumps({"code": exc.code, **exc.detail}))
        return REFUSED
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        print(json.dumps({"code": "error", "message": str(exc)[:400]}))
        return ERROR
    print(json.dumps(out))
    return OK


if __name__ == "__main__":
    sys.exit(main())
