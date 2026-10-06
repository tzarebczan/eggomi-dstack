"""Browser-guard service inside the browser subVM.

The guard is the browser subVM's only holder of a keeper-channel key. It runs
next to Chromium and owns:

- the channel private key, installed by the launcher into tmpfs and then
  wrapped (``cah.crypto_lab.wrap_private``) to a fence that also lives in
  tmpfs; the wrapped copy is the only one on the browser disk;
- ``cah.guard.GuardStore``: the sealed answer is opened at most once per
  grant, and refused with ``grant_expired`` once its offset has elapsed on
  the guard's monotonic clock;
- the session material it received, in memory only.

``serve`` runs the daemon. Every other subcommand is a local control client
that the harness runs with ``smolvm machine exec``; it talks to the daemon
over ``/run/eggomi-guard/ctl.sock`` and prints one JSON object. No control
reply carries a secret. ``held`` returns the session token so the host can
use it as a positive control when it scans a browser checkpoint.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from cah.channel import ChannelError, GateDenial, parse_public
from cah.crypto_lab import generate_private, wrap_private
from cah.guard import GuardStore
from cah.seal import LiveBinding
from kkrpc import call, parse_address
from session_material import binding

ROLE = "browser"
RUN = Path("/run/eggomi-guard")
DISK = Path("/var/lib/eggomi-guard")


class Guard:
    """Keeper client state for one browser compartment."""

    def __init__(self, run: Path, disk: Path, keeper: str) -> None:
        """Consume the installed key and build the fence."""
        self.keeper = parse_address(keeper)
        self.keeper_public = parse_public(
            (run / "keeper.pub").read_text("utf-8").strip()
        )
        key_path = run / "guard.key"
        private = key_path.read_bytes()
        if len(private) != 32:
            raise ValueError("guard.key must be 32 bytes")
        fence = run / "fence"
        fence.mkdir(mode=0o700, exist_ok=True)
        fence_secret = secrets.token_bytes(32)
        (fence / "secret").write_bytes(fence_secret)
        (fence / "epoch").write_text("1\n", encoding="utf-8")
        disk.mkdir(mode=0o700, parents=True, exist_ok=True)
        wrapped = disk / "lease.wrapped"
        wrapped.write_bytes(wrap_private(fence_secret, 1, private))
        key_path.unlink()
        self._private = private
        self.store = GuardStore(fence, wrapped)
        self.keeper_epoch = 0
        self.held: Optional[Dict[str, Any]] = None
        self.last_blob: Optional[Dict[str, Any]] = None
        self.last_live: Optional[LiveBinding] = None
        self._lock = threading.Lock()

    def _call(self, method: str, params: Dict[str, Any], key: Optional[bytes] = None):
        try:
            reply = call(self.keeper, key or self._private, self.keeper_public, method, params)
        except GateDenial as exc:
            return {"error": {"code": exc.code}}
        except ChannelError:
            return {"error": {"code": "handshake_refused"}}
        except OSError as exc:
            return {"error": {"code": "unreachable", "message": str(exc)}}
        return reply

    def ping(self) -> Dict[str, Any]:
        """Ping the keeper and learn its boot epoch."""
        reply = self._call("Ping", {})
        if "result" in reply:
            self.keeper_epoch = int(reply["result"]["keeper_epoch"])
            return {"code": "ok", "keeper_epoch": self.keeper_epoch}
        return {"code": reply["error"]["code"]}

    def session(
        self, purpose: str, ttl_ms: int, accept_delay_ms: int, redeem: bool, redeem_delay_ms: int
    ) -> Dict[str, Any]:
        """Mint, open, and optionally redeem one session."""
        if not self.keeper_epoch:
            pinged = self.ping()
            if pinged["code"] != "ok":
                return {"mint": pinged["code"]}
        challenge = secrets.token_bytes(32)
        challenge_mono = time.monotonic()
        operation_id = secrets.token_hex(8)
        reply = self._call(
            "MintSession",
            {
                "purpose": purpose,
                "ttl_ms": ttl_ms,
                "challenge": challenge.hex(),
                "operation_id": operation_id,
            },
        )
        if "error" in reply:
            return {"mint": reply["error"]["code"]}
        result = reply["result"]
        sealed = result["sealed"]
        time.sleep(accept_delay_ms / 1000)
        live = LiveBinding(
            challenge=challenge,
            challenge_mono=challenge_mono,
            keeper_public=self.keeper_public,
            **binding(
                role=ROLE,
                purpose=purpose,
                operation_id=operation_id,
                keeper_epoch=self.keeper_epoch,
            ),
        )
        accepted = self.store.accept(sealed, live)
        self.last_blob, self.last_live = sealed, live
        out: Dict[str, Any] = {
            "mint": "ok",
            "grant_ref": result["grant_ref"],
            "accept": accepted["code"],
        }
        if not accepted.get("ok") or accepted.get("repeat"):
            return out
        with self._lock:
            self.held = {
                "grant_ref": result["grant_ref"],
                "token": accepted["fill"],
                "expires_ms": result["expires_ms"],
            }
        if redeem:
            time.sleep(redeem_delay_ms / 1000)
            out["redeem"] = self.redeem_held()["code"]
        return out

    def redeem_held(self) -> Dict[str, Any]:
        """Present the held token to the keeper's origin stand-in."""
        with self._lock:
            held = dict(self.held) if self.held else None
        if held is None:
            return {"code": "nothing_held"}
        reply = self._call("Redeem", {"grant_ref": held["grant_ref"], "token": held["token"]})
        if "error" in reply:
            return {"code": reply["error"]["code"]}
        return {"code": "ok"}

    def reaccept_last(self) -> Dict[str, Any]:
        """Open the last sealed answer again. CAH returns the recorded outcome."""
        if self.last_blob is None or self.last_live is None:
            return {"code": "nothing_held"}
        accepted = self.store.accept(self.last_blob, self.last_live)
        return {"code": accepted["code"], "repeat": bool(accepted.get("repeat")),
                "plaintext_returned": "fill" in accepted}

    def raw(self, method: str, params: Dict[str, Any], stranger: bool) -> Dict[str, Any]:
        """Call any method, optionally with an unregistered key."""
        key = generate_private() if stranger else None
        reply = self._call(method, params, key)
        if "error" in reply:
            return {"code": reply["error"]["code"]}
        return {"code": "ok", "keys": sorted(reply["result"])}

    def dispatch(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Run one control command."""
        cmd = request.get("cmd")
        if cmd == "ping":
            return self.ping()
        if cmd == "session":
            return self.session(
                str(request.get("purpose", "")),
                int(request.get("ttl_ms", 5000)),
                int(request.get("accept_delay_ms", 0)),
                bool(request.get("redeem", True)),
                int(request.get("redeem_delay_ms", 0)),
            )
        if cmd == "redeem_held":
            return self.redeem_held()
        if cmd == "reaccept_last":
            return self.reaccept_last()
        if cmd == "raw":
            return self.raw(
                str(request.get("method", "")),
                dict(request.get("params") or {}),
                bool(request.get("stranger", False)),
            )
        if cmd == "held":
            with self._lock:
                return {"code": "ok", "held": self.held}
        return {"code": "unknown_cmd"}


def serve(run: Path, disk: Path, keeper: str, wait: float) -> int:
    """Wait for the launcher's files, then serve the control socket."""
    run.mkdir(mode=0o700, parents=True, exist_ok=True)
    deadline = time.monotonic() + wait
    while not all((run / name).exists() for name in ("guard.key", "keeper.pub")):
        if time.monotonic() > deadline:
            print("[guard] key material was not installed", file=sys.stderr)
            return 1
        time.sleep(0.1)
    guard = Guard(run, disk, keeper)
    path = run / "ctl.sock"
    if path.exists():
        path.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    os.chmod(path, 0o600)
    listener.listen(16)
    (run / "ready").write_text("1\n", encoding="utf-8")
    print("[guard] ready", file=sys.stderr)
    while True:
        conn, _ = listener.accept()
        with conn:
            try:
                request = json.loads(_read_line(conn))
                reply = guard.dispatch(request)
            except Exception as exc:  # noqa: BLE001 - report, keep serving
                reply = {"code": "guard_error", "message": type(exc).__name__}
            conn.sendall((json.dumps(reply, sort_keys=True) + "\n").encode("utf-8"))


def _read_line(conn: socket.socket) -> str:
    data = bytearray()
    while not data.endswith(b"\n"):
        part = conn.recv(4096)
        if not part:
            break
        data.extend(part)
    return data.decode("utf-8")


def control(run: Path, request: Dict[str, Any], timeout: float) -> int:
    """Send one control request to the daemon and print the reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(str(run / "ctl.sock"))
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        print(_read_line(sock).strip())
    return 0


def main(argv: Optional[list] = None) -> int:
    """``serve`` or ``ctl JSON``."""
    parser = argparse.ArgumentParser(description="Eggomi browser guard")
    parser.add_argument("--run", type=Path, default=RUN)
    sub = parser.add_subparsers(dest="mode", required=True)
    srv = sub.add_parser("serve")
    srv.add_argument("--disk", type=Path, default=DISK)
    srv.add_argument("--keeper", default=os.environ.get("EGGOMI_KEEPER", ""))
    srv.add_argument("--wait", type=float, default=600)
    ctl = sub.add_parser("ctl")
    ctl.add_argument("request")
    ctl.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args(argv)
    if args.mode == "serve":
        args.run.mkdir(mode=0o700, parents=True, exist_ok=True)
        keeper = args.keeper
        config = args.run / "keeper.addr"
        deadline = time.monotonic() + args.wait
        while not keeper:
            if config.exists():
                keeper = config.read_text("utf-8").strip()
            elif time.monotonic() > deadline:
                print("[guard] keeper address was not installed", file=sys.stderr)
                return 1
            else:
                time.sleep(0.1)
        return serve(args.run, args.disk, keeper, max(1.0, deadline - time.monotonic()))
    return control(args.run, json.loads(args.request), args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
