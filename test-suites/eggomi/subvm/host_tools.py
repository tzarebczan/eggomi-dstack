"""Host-side helpers for the smolvm S3/S4 suites.

In L2 the host plays the outer CVM: it is the launcher that installs keys,
the relay that forwards the keeper channel, and the observer that measures
memory and searches disks and checkpoints.

Subcommands (each prints one JSON object unless noted):

    keygen DIR                 keeper, browser, and probe channel keys
    ping ADDR DIR              one keeper Ping with the probe key
    probe ADDR DIR LOG STOP    Ping every --interval until STOP exists (JSONL)
    probe-summary LOG          totals, failures, and the longest gap
    rss PID                    host memory of one VMM process, in bytes
    balloon SOCK TARGET_MIB    inflate the balloon, wait, deflate
    scan NEEDLE_FILE PATH...   count needle encodings in files, dirs, checkpoints
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import BinaryIO, Dict, Iterable, Iterator, List

CHUNK = 8 << 20
FOOTER = struct.Struct("<8sIQQQQQI")
FOOTER_SIZE = 64
MAGIC = b"SMOLPACK"


# --- keys and keeper calls -------------------------------------------------


def keygen(out: Path) -> Dict[str, str]:
    """Write one channel key per compartment and the keeper's peer table."""
    from cah.crypto_lab import generate_private, public_key

    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    publics = {}
    for role in ("keeper", "browser", "probe"):
        private = generate_private()
        path = out / f"{role}.key"
        path.write_bytes(private)
        os.chmod(path, 0o600)
        publics[role] = public_key(private).hex()
    (out / "keeper.pub").write_text(publics["keeper"] + "\n", encoding="utf-8")
    (out / "peers.json").write_text(
        json.dumps({"browser": publics["browser"], "probe": publics["probe"]}) + "\n",
        encoding="utf-8",
    )
    return publics


def ping(address: str, keys: Path, timeout: float = 2.0) -> Dict[str, object]:
    """Ping the keeper as the probe compartment."""
    from cah.channel import parse_public
    from kkrpc import call, parse_address

    started = time.monotonic()
    try:
        reply = call(
            parse_address(address),
            (keys / "probe.key").read_bytes(),
            parse_public((keys / "keeper.pub").read_text("utf-8").strip()),
            "Ping",
            {},
            timeout=timeout,
        )
        ok = "result" in reply
        code = "ok" if ok else reply["error"]["code"]
    except Exception as exc:  # noqa: BLE001 - every failure is a probe miss
        ok, code = False, type(exc).__name__
    return {"ok": ok, "code": code, "ms": round((time.monotonic() - started) * 1000, 2)}


def probe(address: str, keys: Path, log: Path, stop: Path, interval: float) -> None:
    """Ping until ``stop`` exists, one JSON line per attempt."""
    with log.open("a", encoding="utf-8") as handle:
        while not stop.exists():
            row = {"t": round(time.time(), 3), **ping(address, keys)}
            handle.write(json.dumps(row) + "\n")
            handle.flush()
            time.sleep(interval)


def probe_summary(log: Path) -> Dict[str, object]:
    """Summarize a probe log: attempts, failures, and the longest success gap."""
    rows = [json.loads(line) for line in log.read_text("utf-8").splitlines() if line]
    ok_times = [row["t"] for row in rows if row["ok"]]
    gaps = [b - a for a, b in zip(ok_times, ok_times[1:])]
    latencies = sorted(row["ms"] for row in rows if row["ok"])
    return {
        "attempts": len(rows),
        "failures": sum(1 for row in rows if not row["ok"]),
        "failure_codes": sorted({row["code"] for row in rows if not row["ok"]}),
        "max_gap_seconds": round(max(gaps), 3) if gaps else None,
        "p50_ms": latencies[len(latencies) // 2] if latencies else None,
        "p99_ms": latencies[min(len(latencies) - 1, int(len(latencies) * 0.99))]
        if latencies
        else None,
        "first": rows[0]["t"] if rows else None,
        "last": rows[-1]["t"] if rows else None,
    }


# --- memory -----------------------------------------------------------------


def rss(pid: int) -> Dict[str, int]:
    """Return VmRSS and its anon/file/shmem parts for ``pid``, in bytes."""
    fields = {"VmRSS": "rss", "RssAnon": "anon", "RssFile": "file", "RssShmem": "shmem"}
    out = {}
    for line in Path(f"/proc/{pid}/status").read_text("utf-8").splitlines():
        key, _, value = line.partition(":")
        if key in fields:
            out[fields[key]] = int(value.split()[0]) * 1024
    return out


def control(sock: Path, command: str, timeout: float = 60) -> str:
    """Send one line to a smolvm per-VM control socket and return the reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout)
        conn.connect(str(sock))
        conn.sendall(command.encode("ascii") + b"\n")
        reply = bytearray()
        while not reply.endswith(b"\n"):
            part = conn.recv(256)
            if not part:
                break
            reply.extend(part)
    return reply.decode("ascii", "replace").strip()


def balloon(sock: Path, target_mib: int, wait: float) -> Dict[str, object]:
    """Pulse the balloon the way smolvm's idle reclaim does, on demand.

    Inflate to ``target_mib`` so the guest drops page cache and frees pages,
    wait until the guest reports that size (or ``wait`` expires), then deflate
    to zero so the guest keeps its full ceiling.
    """
    started = time.monotonic()
    inflate = control(sock, f"BALLOON {target_mib}")
    reached = False
    status = ""
    deadline = time.monotonic() + wait
    while inflate.startswith("OK") and time.monotonic() < deadline:
        status = control(sock, "BALLOON")
        if f"actual={target_mib}" in status:
            reached = True
            break
        time.sleep(0.5)
    deflate = control(sock, "BALLOON 0")
    return {
        "inflate": inflate,
        "reached": reached,
        "status": status,
        "deflate": deflate,
        "seconds": round(time.monotonic() - started, 3),
    }


# --- needle search ----------------------------------------------------------


def encodings(needle: bytes) -> Dict[str, bytes]:
    """Return the forms a leaked secret is likely to take in memory or on disk."""
    text = needle.decode("utf-8")
    return {
        "raw": needle,
        "utf16le": text.encode("utf-16-le"),
        "hex": needle.hex().encode("ascii"),
    }


def count_stream(chunks: Iterable[bytes], needles: Dict[str, bytes]) -> Dict[str, int]:
    """Count every needle in a byte stream, including across chunk edges."""
    counts = {name: 0 for name in needles}
    keep = max(len(value) for value in needles.values()) - 1
    tail = b""
    for chunk in chunks:
        window = tail + chunk
        for name, value in needles.items():
            start = 0
            while True:
                hit = window.find(value, start)
                if hit < 0:
                    break
                # A match wholly inside the carried tail was counted last round.
                if hit + len(value) > len(tail):
                    counts[name] += 1
                start = hit + 1
        tail = window[-keep:] if keep else b""
    return counts


def sparse_chunks(handle: BinaryIO) -> Iterator[bytes]:
    """Yield only the allocated extents of a sparse file."""
    fd = handle.fileno()
    size = os.fstat(fd).st_size
    offset = 0
    while offset < size:
        try:
            data = os.lseek(fd, offset, os.SEEK_DATA)
        except OSError:
            return
        hole = os.lseek(fd, data, os.SEEK_HOLE)
        os.lseek(fd, data, os.SEEK_SET)
        remaining = hole - data
        while remaining > 0:
            block = os.read(fd, min(CHUNK, remaining))
            if not block:
                return
            remaining -= len(block)
            yield block
        # A hole splits two extents; a needle cannot straddle zeros it lacks.
        yield b"\0"
        offset = hole


def checkpoint_payload(handle: BinaryIO) -> Iterator[bytes]:
    """Yield the decompressed payload (a tar stream) of a smolvm checkpoint."""
    handle.seek(-FOOTER_SIZE, os.SEEK_END)
    magic, _version, _stub, offset, size, _moff, _msize, _crc = FOOTER.unpack(
        handle.read(FOOTER.size)
    )
    if magic != MAGIC:
        raise ValueError("not a smolvm checkpoint container")
    handle.seek(offset)
    try:
        from compression import zstd  # Python 3.14+
    except ImportError:
        zstd = None
    if zstd is not None:
        decompressor = zstd.ZstdDecompressor()
        remaining = size
        while remaining > 0 and not decompressor.eof:
            block = handle.read(min(CHUNK, remaining))
            if not block:
                break
            remaining -= len(block)
            out = decompressor.decompress(block)
            if out:
                yield out
        return
    proc = subprocess.Popen(
        ["zstd", "-dc"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    assert proc.stdin is not None and proc.stdout is not None

    def feed() -> None:
        remaining = size
        while remaining > 0:
            block = handle.read(min(CHUNK, remaining))
            if not block:
                break
            remaining -= len(block)
            proc.stdin.write(block)
        proc.stdin.close()

    import threading

    writer = threading.Thread(target=feed, daemon=True)
    writer.start()
    while True:
        out = proc.stdout.read(CHUNK)
        if not out:
            break
        yield out
    writer.join()
    if proc.wait() != 0:
        raise ValueError("zstd failed to decompress the checkpoint payload")


def is_checkpoint(path: Path) -> bool:
    """Return whether ``path`` ends with a SMOLPACK footer."""
    try:
        with path.open("rb") as handle:
            handle.seek(-FOOTER_SIZE, os.SEEK_END)
            return handle.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def scan(needle: bytes, paths: List[Path]) -> Dict[str, object]:
    """Count the needle's encodings in every regular file under ``paths``."""
    needles = encodings(needle)
    files: Dict[str, Dict[str, object]] = {}
    total = {name: 0 for name in needles}
    scanned = 0
    for root in paths:
        candidates = [root] if root.is_file() else sorted(p for p in root.rglob("*"))
        for path in candidates:
            if not path.is_file() or path.is_symlink():
                continue
            with path.open("rb") as handle:
                if is_checkpoint(path):
                    kind = "checkpoint"
                    counts = count_stream(checkpoint_payload(handle), needles)
                else:
                    kind = "file"
                    counts = count_stream(sparse_chunks(handle), needles)
            scanned += 1
            if any(counts.values()):
                files[str(path)] = {"kind": kind, **counts}
            for name, value in counts.items():
                total[name] += value
    return {"files_scanned": scanned, "hits": total, "files_with_hits": files}


def main(argv: List[str] | None = None) -> int:
    """Dispatch one subcommand."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("keygen")
    p.add_argument("dir", type=Path)
    p = sub.add_parser("ping")
    p.add_argument("address")
    p.add_argument("keys", type=Path)
    p = sub.add_parser("probe")
    p.add_argument("address")
    p.add_argument("keys", type=Path)
    p.add_argument("log", type=Path)
    p.add_argument("stop", type=Path)
    p.add_argument("--interval", type=float, default=0.1)
    p = sub.add_parser("probe-summary")
    p.add_argument("log", type=Path)
    p = sub.add_parser("rss")
    p.add_argument("pid", type=int)
    p = sub.add_parser("balloon")
    p.add_argument("sock", type=Path)
    p.add_argument("target_mib", type=int)
    p.add_argument("--wait", type=float, default=30)
    p = sub.add_parser("scan")
    p.add_argument("needle_file", type=Path)
    p.add_argument("paths", type=Path, nargs="+")
    args = parser.parse_args(argv)

    if args.cmd == "keygen":
        keygen(args.dir)
        result: object = {"ok": True}
    elif args.cmd == "ping":
        result = ping(args.address, args.keys)
    elif args.cmd == "probe":
        probe(args.address, args.keys, args.log, args.stop, args.interval)
        return 0
    elif args.cmd == "probe-summary":
        result = probe_summary(args.log)
    elif args.cmd == "rss":
        result = rss(args.pid)
    elif args.cmd == "balloon":
        result = balloon(args.sock, args.target_mib, args.wait)
    else:
        result = scan(args.needle_file.read_bytes().strip(), args.paths)
    json.dump(result, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
