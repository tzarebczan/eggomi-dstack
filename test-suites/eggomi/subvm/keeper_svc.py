"""Keeper subVM service for the smolvm S3/S4 suites.

Runs inside the keeper smolvm. It holds the test secret on the keeper's own
disk and answers over the Noise KK keeper channel (``kkrpc``). The method
table is deny-by-default and per role:

    browser   Ping, MintSession, Redeem
    probe     Ping

There is no method that returns the secret, lists secrets, or lists
connections. ``MintSession`` returns session material only: a token derived
from the secret, sealed to the browser guard's channel key with a TTL of at
most 30 seconds. ``Redeem`` stands in for the origin that accepts that
session: a token is accepted once, before its expiry.

State directory layout (written by the launcher, never by a peer):

    keeper.key    32-byte keeper channel private key
    peers.json    {"browser": "<hex public>", "probe": "<hex public>"}
    secret        the test secret (one line)
    policy.json   optional {"purposes": [...]} allowlist
    boot-epoch    incremented on every start
    grants.jsonl  append-only grant journal (no token, no secret)
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import hmac
import json
import os
import secrets
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional

from cah.channel import ChannelClosed, ChannelError, parse_public
from cah.seal import seal_credential
from kkrpc import accept_peer, parse_address
from session_material import MAX_TTL_MS, binding, session_token

DEFAULT_PURPOSES = ("https://login.example.test",)
ACL: Mapping[str, frozenset] = {
    "browser": frozenset({"Ping", "MintSession", "Redeem"}),
    "probe": frozenset({"Ping"}),
}
MAX_FIELD = 512


def _error(code: str, message: str = "") -> Dict[str, Any]:
    return {"error": {"code": code, "message": message or code}}


class Keeper:
    """Keeper state and the method table."""

    def __init__(self, state: Path, now_ms: Callable[[], int] | None = None) -> None:
        """Load keys and peers from ``state``. The secret is read per use."""
        self.state = state
        self.private = (state / "keeper.key").read_bytes()
        if len(self.private) != 32:
            raise ValueError("keeper.key must be 32 bytes")
        raw_peers = json.loads((state / "peers.json").read_text(encoding="utf-8"))
        self.peers = {
            role: parse_public(value)
            for role, value in raw_peers.items()
            if role in ACL
        }
        policy_path = state / "policy.json"
        purposes = DEFAULT_PURPOSES
        if policy_path.exists():
            purposes = tuple(json.loads(policy_path.read_text("utf-8"))["purposes"])
        self.purposes = frozenset(purposes)
        self.epoch = self._advance_epoch()
        self.grants: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._now_ms = now_ms or (lambda: int(time.time() * 1000))
        self._mono = time.monotonic

    def _advance_epoch(self) -> int:
        path = self.state / "boot-epoch"
        current = int(path.read_text("utf-8").strip()) if path.exists() else 0
        path.write_text(f"{current + 1}\n", encoding="utf-8")
        return current + 1

    def _secret(self) -> Optional[bytes]:
        try:
            raw = (self.state / "secret").read_bytes().strip()
        except OSError:
            return None
        return raw or None

    def _journal(self, row: Dict[str, Any]) -> None:
        with (self.state / "grants.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def handle(self, role: str, method: str, params: Any) -> Dict[str, Any]:
        """Authorize by the channel role, then run the method."""
        if not isinstance(method, str) or method not in ACL.get(role, frozenset()):
            return _error("denied_method")
        if not isinstance(params, dict) or not _fields_ok(params):
            return _error("denied_payload")
        if method == "Ping":
            return {"result": {"pong": True, "role": role, "keeper_epoch": self.epoch}}
        if method == "MintSession":
            return self._mint(role, params)
        return self._redeem(role, params)

    def _mint(self, role: str, params: Dict[str, Any]) -> Dict[str, Any]:
        purpose = params.get("purpose")
        ttl_ms = params.get("ttl_ms")
        operation_id = params.get("operation_id")
        if purpose not in self.purposes:
            return _error("denied_purpose")
        if isinstance(ttl_ms, bool) or not isinstance(ttl_ms, int):
            return _error("denied_payload")
        if not 0 < ttl_ms <= MAX_TTL_MS:
            return _error("denied_ttl")
        if not isinstance(operation_id, str) or not operation_id:
            return _error("denied_payload")
        try:
            challenge = bytes.fromhex(str(params.get("challenge")))
        except ValueError:
            return _error("denied_payload")
        if len(challenge) != 32:
            return _error("denied_payload")
        secret = self._secret()
        if secret is None:
            return _error("unavailable")
        grant_ref = secrets.token_hex(16)
        expires_ms = self._now_ms() + ttl_ms
        token = session_token(secret, purpose, grant_ref, expires_ms)
        sealed = seal_credential(
            self.peers[role],
            token.encode("ascii"),
            grant_ref=grant_ref,
            expiry_challenge=challenge,
            expiry_offset_ms=ttl_ms,
            keeper_private=self.private,
            **binding(
                role=role,
                purpose=purpose,
                operation_id=operation_id,
                keeper_epoch=self.epoch,
            ),
        )
        with self._lock:
            self.grants[grant_ref] = {
                "purpose": purpose,
                "role": role,
                "expires_ms": expires_ms,
                # Expiry is enforced on the keeper's monotonic clock, so a wall
                # clock step cannot revive a grant. expires_ms is for reports.
                "deadline": self._mono() + ttl_ms / 1000,
                "state": "issued",
            }
            self._journal(
                {
                    "grant_ref": grant_ref,
                    "purpose": purpose,
                    "role": role,
                    "expires_ms": expires_ms,
                    "state": "issued",
                }
            )
        return {
            "result": {
                "grant_ref": grant_ref,
                "expires_ms": expires_ms,
                "keeper_epoch": self.epoch,
                "sealed": sealed,
            }
        }

    def _redeem(self, role: str, params: Dict[str, Any]) -> Dict[str, Any]:
        grant_ref = params.get("grant_ref")
        token = params.get("token")
        if not isinstance(grant_ref, str) or not isinstance(token, str):
            return _error("denied_payload")
        with self._lock:
            grant = self.grants.get(grant_ref)
            if grant is None or grant["role"] != role:
                return _error("unknown_grant")
            if grant["state"] in ("consumed", "expired"):
                return _error(grant["state"])
            if self._mono() > grant["deadline"]:
                grant["state"] = "expired"
                self._journal({"grant_ref": grant_ref, "state": "expired"})
                return _error("expired")
            secret = self._secret()
            if secret is None:
                return _error("unavailable")
            expect = session_token(
                secret, grant["purpose"], grant_ref, grant["expires_ms"]
            )
            if not hmac.compare_digest(expect, token):
                return _error("denied_token")
            grant["state"] = "consumed"
            self._journal({"grant_ref": grant_ref, "state": "consumed"})
        return {"result": {"ok": True, "grant_ref": grant_ref}}


def _fields_ok(params: Dict[str, Any]) -> bool:
    for value in params.values():
        if isinstance(value, str) and len(value) > MAX_FIELD:
            return False
        if isinstance(value, (dict, list)):
            return False
    return True


def serve_connection(keeper: Keeper, conn: socket.socket) -> None:
    """Admit one peer by its key, then answer requests until it closes."""
    with conn:
        conn.settimeout(30)
        try:
            role, session = accept_peer(conn, keeper.private, keeper.peers)
        except (ChannelError, OSError):
            return
        while True:
            try:
                request = session.read()
            except (ChannelClosed, ChannelError, OSError):
                return
            reply = keeper.handle(role, request.get("method"), request.get("params"))
            reply["id"] = request.get("id")
            try:
                session.write(reply)
            except (ChannelError, OSError):
                return


def wait_for_state(state: Path, timeout: float) -> None:
    """Wait for the launcher to install keys, peers, and the secret."""
    deadline = time.monotonic() + timeout
    needed = ("keeper.key", "peers.json", "secret")
    while not all((state / name).exists() for name in needed):
        if time.monotonic() > deadline:
            raise TimeoutError("keeper state was not installed")
        time.sleep(0.1)


def main(argv: Optional[list] = None) -> int:
    """Run the keeper channel listener."""
    parser = argparse.ArgumentParser(description="Eggomi keeper subVM service")
    parser.add_argument("--state", type=Path, default=Path("/var/lib/eggomi-keeper"))
    parser.add_argument("--listen", default="0.0.0.0:7011")
    parser.add_argument("--wait", type=float, default=600)
    args = parser.parse_args(argv)
    args.state.mkdir(parents=True, exist_ok=True)
    os.chmod(args.state, 0o700)
    wait_for_state(args.state, args.wait)
    keeper = Keeper(args.state)
    host, port = parse_address(args.listen)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(64)
    print(f"[keeper] epoch {keeper.epoch} listening on {args.listen}", file=sys.stderr)
    while True:
        conn, _addr = listener.accept()
        threading.Thread(
            target=serve_connection, args=(keeper, conn), daemon=True
        ).start()


if __name__ == "__main__":
    raise SystemExit(main())
