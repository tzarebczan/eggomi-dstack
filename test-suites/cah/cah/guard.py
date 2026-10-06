"""Single-use fill at the browser guard.

The consumed set and the fence secret live outside the guard disk. Restoring
a snapshot of that disk does not revive a consumed nonce. A wrapped lease key
whose epoch does not match the fence is destroyed.

Checks and the fill are one step. The guard records ``(grant_ref, nonce)``
before it types the value. A crash between those two writes leaves
``unknown``, and that record is never followed by a second fill.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .crypto_lab import KeyDestroyed, unwrap_private
from .seal import LiveBinding, open_credential

_TERMINAL = frozenset({"filled", "refused", "unknown"})


class GuardStore:
    """Durable ``(grant_ref, nonce)`` outcomes for one guard lease."""

    def __init__(self, fence_dir: Path, wrapped_key_path: Path) -> None:
        """Load the fence that sits outside the guard snapshot."""
        self.fence_dir = fence_dir
        self.wrapped_key_path = wrapped_key_path
        self.journal_path = fence_dir / "consumed.jsonl"
        self.secret_path = fence_dir / "secret"
        self.epoch_path = fence_dir / "epoch"

    def lease_private(self) -> bytes:
        """Unwrap the lease key. A fence mismatch deletes the wrapped key."""
        try:
            secret = self.secret_path.read_bytes()
            epoch = int(self.epoch_path.read_text(encoding="utf-8").strip())
            wrapped = self.wrapped_key_path.read_bytes()
            return unwrap_private(secret, epoch, wrapped)
        except (OSError, ValueError, KeyDestroyed) as exc:
            self._destroy_key()
            raise KeyDestroyed("lease key does not match the fence") from exc

    def lookup(self, grant_ref: str, nonce: str) -> Optional[str]:
        """Return the recorded outcome, with an in-progress row as ``unknown``."""
        state = self._states().get((grant_ref, nonce))
        if state == "in_progress":
            return "unknown"
        return state

    def accept(
        self,
        blob: Mapping[str, Any],
        live: LiveBinding,
        *,
        now_mono: Optional[float] = None,
        crash_after_record: bool = False,
    ) -> Dict[str, Any]:
        """Re-check every live field, then fill at most once.

        ``now_mono`` defaults to the guard's monotonic clock. A keeper
        timestamp on the blob is not consulted.
        """
        try:
            private = self.lease_private()
        except KeyDestroyed:
            return {"ok": False, "code": "denied_recipient"}
        offset = blob.get("expiry_offset_ms")
        if _expired(live, offset, now_mono if now_mono is not None else time.monotonic()):
            return {"ok": False, "code": "grant_expired"}
        try:
            plaintext = open_credential(private, blob, live)
        except ValueError:
            return {"ok": False, "code": "denied_payload"}
        grant_ref = str(blob.get("grant_ref"))
        nonce = str(blob.get("nonce"))
        recorded = self.lookup(grant_ref, nonce)
        if recorded is not None:
            return {"ok": recorded == "filled", "code": recorded, "repeat": True}
        self._append(grant_ref, nonce, "in_progress")
        if crash_after_record:
            return {"ok": False, "code": "unknown", "repeat": False}
        if not plaintext:
            self._append(grant_ref, nonce, "refused")
            return {"ok": False, "code": "refused"}
        self._append(grant_ref, nonce, "filled")
        try:
            fill = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            return {"ok": False, "code": "denied_payload"}
        return {"ok": True, "code": "filled", "fill": fill, "repeat": False}

    def _states(self) -> Dict[tuple[str, str], str]:
        found: Dict[tuple[str, str], str] = {}
        if not self.journal_path.exists():
            return found
        for line in self.journal_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            key = (str(row.get("grant_ref")), str(row.get("nonce")))
            state = str(row.get("state"))
            if state in _TERMINAL or state == "in_progress":
                found[key] = state
        return found

    def _append(self, grant_ref: str, nonce: str, state: str) -> None:
        self.fence_dir.mkdir(parents=True, exist_ok=True)
        line = json.dumps(
            {"grant_ref": grant_ref, "nonce": nonce, "state": state},
            sort_keys=True,
        )
        with self.journal_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(self.journal_path, 0o600)

    def _destroy_key(self) -> None:
        if self.wrapped_key_path.exists():
            self.wrapped_key_path.unlink()


def _expired(live: LiveBinding, offset: object, now_mono: float) -> bool:
    if isinstance(offset, bool) or not isinstance(offset, int):
        return True
    if offset <= 0 or offset > 30_000:
        return True
    elapsed_ms = (now_mono - live.challenge_mono) * 1000
    if elapsed_ms < 0:
        return True
    return elapsed_ms > offset
