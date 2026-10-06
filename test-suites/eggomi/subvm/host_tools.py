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
import errno
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import zlib
from pathlib import Path
from typing import BinaryIO, Dict, Iterable, Iterator, List, Optional

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
    """Yield the allocated extents of a file, or all of it without SEEK_DATA.

    Only ``ENXIO`` (no data past this offset) ends the walk early. A file
    system without SEEK_DATA is read sequentially; any other error raises, so
    a failed read can never pass as a clean search.
    """
    fd = handle.fileno()
    size = os.fstat(fd).st_size
    offset = 0
    while offset < size:
        try:
            data = os.lseek(fd, offset, os.SEEK_DATA)
            hole = os.lseek(fd, data, os.SEEK_HOLE)
        except OSError as exc:
            if exc.errno == errno.ENXIO:
                return
            if exc.errno in (errno.EINVAL, errno.EOPNOTSUPP):
                data, hole = offset, size
            else:
                raise
        os.lseek(fd, data, os.SEEK_SET)
        remaining = hole - data
        while remaining > 0:
            block = os.read(fd, min(CHUNK, remaining))
            if not block:
                raise OSError(errno.EIO, f"short read at offset {hole - remaining}")
            remaining -= len(block)
            yield block
        # A hole splits two extents; a needle cannot straddle zeros it lacks.
        yield b"\0"
        offset = hole


def checkpoint_payload(handle: BinaryIO) -> Iterator[bytes]:
    """Yield the decompressed payload (a tar stream) of a smolvm checkpoint.

    Every zstd frame in the payload is decoded, and a payload that ends inside
    a frame raises: a truncated decode must not look like a clean search.
    """
    handle.seek(-FOOTER_SIZE, os.SEEK_END)
    magic, _version, _stub, offset, size, _moff, _msize, _crc = FOOTER.unpack(
        handle.read(FOOTER.size)
    )
    if magic != MAGIC:
        raise ValueError("not a smolvm checkpoint container")
    if offset + size > os.fstat(handle.fileno()).st_size - FOOTER_SIZE:
        raise ValueError("checkpoint payload extends past the container")
    handle.seek(offset)
    try:
        from compression import zstd  # Python 3.14+
    except ImportError:
        zstd = None
    if zstd is not None:
        decompressor = zstd.ZstdDecompressor()
        remaining = size
        data = b""
        while True:
            if decompressor.eof:
                data = decompressor.unused_data
                if not data and remaining == 0:
                    return
                decompressor = zstd.ZstdDecompressor()
            if not data and decompressor.needs_input:
                if remaining == 0:
                    raise ValueError("checkpoint payload ends inside a zstd frame")
                data = handle.read(min(CHUNK, remaining))
                if not data:
                    raise ValueError("checkpoint payload is shorter than its footer says")
                remaining -= len(data)
            out = decompressor.decompress(data, max_length=CHUNK)
            data = b""
            if out:
                yield out
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


QCOW2_MAGIC = b"QFI\xfb"


class Qcow2:
    """Read-only logical view of a qcow2 image and its backing chain.

    A secret written by the guest is contiguous in the disk's logical address
    space, but qcow2 may store logically adjacent clusters far apart, compress
    them, or leave them in a backing file. Searching the image file alone can
    therefore miss it. Unallocated and zero clusters read as ``None``.
    """

    def __init__(self, path: Path, depth: int = 0) -> None:
        """Parse the header and L1 table; open the backing image if any."""
        if depth > 32:
            raise ValueError("qcow2 backing chain is deeper than 32")
        self.path = path
        self.handle = path.open("rb")
        header = self.handle.read(112)
        (magic, version, backing_offset, backing_size, cluster_bits, size,
         crypt, l1_size, l1_offset) = struct.unpack(">4sIQIIQIIQ", header[:48])
        if magic != QCOW2_MAGIC:
            raise ValueError(f"{path} is not qcow2")
        if crypt:
            raise ValueError(f"{path}: encrypted qcow2 is not supported")
        self.compression = 0
        if version >= 3:
            incompatible = struct.unpack(">Q", header[72:80])[0]
            if incompatible & ~0b11:  # only dirty and corrupt are understood
                raise ValueError(f"{path}: unsupported qcow2 features {incompatible:#x}")
            header_length = struct.unpack(">I", header[100:104])[0]
            if header_length > 104:
                self.compression = header[104]
        self.cluster_bits = cluster_bits
        self.cluster_size = 1 << cluster_bits
        self.size = size
        self.handle.seek(l1_offset)
        self.l1 = struct.unpack(f">{l1_size}Q", self.handle.read(8 * l1_size))
        self.l2_entries = self.cluster_size // 8
        self._l2_cache: Dict[int, tuple] = {}
        self.backing: "Optional[object]" = None
        if backing_offset and backing_size:
            self.handle.seek(backing_offset)
            name = self.handle.read(backing_size).decode("utf-8")
            backing_path = (path.parent / name).resolve()
            with backing_path.open("rb") as probe:
                is_qcow2 = probe.read(4) == QCOW2_MAGIC
            self.backing = Qcow2(backing_path, depth + 1) if is_qcow2 else RawImage(backing_path)

    def close(self) -> None:
        """Close this image and its backing chain."""
        self.handle.close()
        if self.backing is not None:
            self.backing.close()

    def _l2(self, index: int) -> Optional[tuple]:
        l1_index = index // self.l2_entries
        if l1_index >= len(self.l1):
            return None
        offset = self.l1[l1_index] & 0x00FFFFFFFFFFFE00
        if not offset:
            return None
        table = self._l2_cache.get(offset)
        if table is None:
            self.handle.seek(offset)
            table = struct.unpack(f">{self.l2_entries}Q", self.handle.read(self.cluster_size))
            self._l2_cache = {offset: table}
        return table

    def _cluster(self, index: int) -> Optional[bytes]:
        """Return this layer's bytes for cluster ``index``; fall through to backing."""
        table = self._l2(index)
        entry = table[index % self.l2_entries] if table is not None else 0
        # Bit 63 is the COPIED flag (refcount 1); bit 62 marks compression.
        if entry & (1 << 62):
            return self._compressed(entry)
        if entry & 1:
            return None  # reads as zeros, hides any backing data
        host = entry & 0x00FFFFFFFFFFFE00
        if host:
            self.handle.seek(host)
            return self.handle.read(self.cluster_size)
        if self.backing is None:
            return None
        return self.backing.read(index * self.cluster_size, self.cluster_size)

    def _compressed(self, entry: int) -> bytes:
        x = 62 - (self.cluster_bits - 8)
        host = entry & ((1 << x) - 1)
        sectors = ((entry >> x) & ((1 << (self.cluster_bits - 8)) - 1)) + 1
        length = sectors * 512 - (host & 511)
        self.handle.seek(host)
        raw = self.handle.read(length)
        if self.compression == 0:
            return zlib.decompressobj(-12).decompress(raw, self.cluster_size)
        try:
            from compression import zstd
        except ImportError as exc:
            raise ValueError("zstd-compressed qcow2 clusters need Python 3.14") from exc
        return zstd.ZstdDecompressor().decompress(raw, self.cluster_size)

    def read(self, offset: int, length: int) -> Optional[bytes]:
        """Return logical bytes, or ``None`` when the whole range is unallocated."""
        parts = []
        any_data = False
        end = min(offset + length, self.size)
        while offset < end:
            index = offset >> self.cluster_bits
            within = offset - (index << self.cluster_bits)
            take = min(self.cluster_size - within, end - offset)
            data = self._cluster(index)
            if data is None:
                parts.append(bytes(take))
            else:
                any_data = True
                parts.append(data[within : within + take].ljust(take, b"\0"))
            offset += take
        return b"".join(parts) if any_data else None

    def chunks(self) -> Iterator[bytes]:
        """Yield the disk's allocated logical content, in logical order."""
        gap = False
        for index in range((self.size + self.cluster_size - 1) >> self.cluster_bits):
            data = self.read(index << self.cluster_bits, self.cluster_size)
            if data is None:
                if not gap:
                    yield b"\0"
                    gap = True
                continue
            gap = False
            yield data


class RawImage:
    """A raw backing file, read with holes as ``None``."""

    def __init__(self, path: Path) -> None:
        """Open ``path``."""
        self.handle = path.open("rb")
        self.size = os.fstat(self.handle.fileno()).st_size

    def close(self) -> None:
        """Close the file."""
        self.handle.close()

    def read(self, offset: int, length: int) -> Optional[bytes]:
        """Return the bytes at ``offset``; ``None`` past the end or in a hole."""
        if offset >= self.size:
            return None
        try:
            data = os.lseek(self.handle.fileno(), offset, os.SEEK_DATA)
        except OSError as exc:
            if exc.errno != errno.ENXIO:
                if exc.errno not in (errno.EINVAL, errno.EOPNOTSUPP):
                    raise
                data = offset
            else:
                return None
        if data >= offset + length:
            return None
        self.handle.seek(offset)
        return self.handle.read(min(length, self.size - offset))


def file_kind(path: Path) -> str:
    """Classify a file as a smolvm checkpoint, a qcow2 image, or plain bytes."""
    with path.open("rb") as handle:
        if handle.read(4) == QCOW2_MAGIC:
            return "qcow2"
        try:
            handle.seek(-FOOTER_SIZE, os.SEEK_END)
        except OSError:
            return "file"
        if handle.read(len(MAGIC)) == MAGIC:
            return "checkpoint"
    return "file"


def is_checkpoint(path: Path) -> bool:
    """Return whether ``path`` ends with a SMOLPACK footer."""
    try:
        return file_kind(path) == "checkpoint"
    except OSError:
        return False


def _targets(roots: List[Path]) -> List[Path]:
    """Every regular file under ``roots``, symlinks resolved, without repeats.

    A missing root raises: a typo must not become a clean search.
    """
    seen: Dict[Path, None] = {}
    for root in roots:
        if not root.exists():
            raise FileNotFoundError(f"scan target does not exist: {root}")
        candidates = [root] if not root.is_dir() else sorted(root.rglob("*"))
        for path in candidates:
            if path.is_file():
                seen.setdefault(path.resolve(), None)
    return list(seen)


def scan(needle: bytes, paths: List[Path]) -> Dict[str, object]:
    """Count the needle's encodings in every regular file under ``paths``.

    Every file is searched as stored. A checkpoint is also searched decoded,
    and a qcow2 image also through its logical view and backing chain.
    """
    needles = encodings(needle)
    files: Dict[str, Dict[str, object]] = {}
    total = {name: 0 for name in needles}
    kinds: Dict[str, int] = {}
    for path in _targets(paths):
        kind = file_kind(path)
        kinds[kind] = kinds.get(kind, 0) + 1
        with path.open("rb") as handle:
            passes = {"stored": count_stream(sparse_chunks(handle), needles)}
            if kind == "checkpoint":
                passes["decoded"] = count_stream(checkpoint_payload(handle), needles)
        if kind == "qcow2":
            image = Qcow2(path)
            try:
                passes["logical"] = count_stream(image.chunks(), needles)
            finally:
                image.close()
        for counts in passes.values():
            for name, value in counts.items():
                total[name] += value
        if any(any(counts.values()) for counts in passes.values()):
            files[str(path)] = {"kind": kind, **passes}
    return {
        "files_scanned": sum(kinds.values()),
        "kinds": kinds,
        "hits": total,
        "files_with_hits": files,
    }


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
