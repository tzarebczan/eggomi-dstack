"""Single-use fill at the browser guard.

The consumed set and the fence secret live outside the guard disk. Restoring
a snapshot of that disk does not revive a consumed grant. A wrapped channel
key whose epoch does not match the fence is destroyed. A transient read
error refuses the fill and leaves the wrapped key in place.

Checks and the fill are one step, under the fence lock. Unwrapping the
channel key, the expiry check against the guard clock, opening the seal,
and the durable record all happen while that lock is held, and
``advance_epoch`` takes the same lock. A rebind therefore lands either
before the unwrap (the old key no longer opens) or after the record. The
guard records ``grant_ref`` before it returns the value. A new nonce for that grant does not fill again. A crash
between the record and the fill leaves ``unknown``, and that record is never
followed by a second fill.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import fcntl
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping, Optional

from .crypto_lab import KeyDestroyed, unwrap_private
from .grants import fsync_dir
from .seal import LiveBinding, open_credential

_TERMINAL = frozenset({"filled", "refused", "unknown"})


class GuardStore:
    """Durable ``grant_ref`` outcomes for one guard channel key."""

    def __init__(self, fence_dir: Path, wrapped_key_path: Path) -> None:
        """Load the fence that sits outside the guard snapshot."""
        self.fence_dir = fence_dir
        self.wrapped_key_path = wrapped_key_path
        self.journal_path = fence_dir / "consumed.jsonl"
        self.secret_path = fence_dir / "secret"
        self.epoch_path = fence_dir / "epoch"

    def lease_private(self) -> bytes:
        """Unwrap the channel key.

        An epoch mismatch deletes the wrapped key. A missing fence file does
        not, so a short read cannot destroy a still-valid wrap.
        """
        try:
            secret = self.secret_path.read_bytes()
            epoch = int(self.epoch_path.read_text(encoding="utf-8").strip())
            wrapped = self.wrapped_key_path.read_bytes()
        except (OSError, ValueError) as exc:
            raise KeyDestroyed("lease key does not match the fence") from exc
        if len(wrapped) < 8:
            raise KeyDestroyed("wrapped lease key is the wrong size")
        stored_epoch = int.from_bytes(wrapped[:8], "big")
        if stored_epoch != epoch:
            self._destroy_key()
            raise KeyDestroyed("fence epoch does not match the wrapped lease key")
        try:
            return unwrap_private(secret, epoch, wrapped)
        except KeyDestroyed as exc:
            raise KeyDestroyed("lease key does not match the fence") from exc

    def advance_epoch(self) -> int:
        """Advance the fence epoch that wraps this guard's channel key.

        Callers do this when the channel key is rebound. The previous wrap
        no longer opens. The epoch file is the fence, not a copy inside the
        guard role directory. It takes the fence lock, so it cannot land
        between a fill's unwrap and its record.
        """
        with self._locked():
            return self._advance_epoch_locked()

    def _advance_epoch_locked(self) -> int:
        self.fence_dir.mkdir(parents=True, exist_ok=True)
        current = 1
        if self.epoch_path.exists():
            current = int(self.epoch_path.read_text(encoding="utf-8").strip())
        nxt = current + 1
        tmp = self.epoch_path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            handle.write(f"{nxt}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.epoch_path)
        fsync_dir(self.fence_dir)
        return nxt

    def lookup(self, grant_ref: str) -> Optional[str]:
        """Return the recorded outcome for ``grant_ref``.

        An in-progress row is ``unknown``. The nonce is not part of the key.
        """
        state = self._states().get(grant_ref)
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
        """Re-check every live field, then fill a grant_ref at most once.

        ``now_mono`` defaults to the guard's monotonic clock, read after the
        fence lock is held. A keeper timestamp on the blob is not consulted.
        A second seal of the same grant, including one with a fresh nonce,
        returns the recorded outcome and no plaintext.
        """
        with self._locked():
            try:
                private = self.lease_private()
            except KeyDestroyed:
                return {"ok": False, "code": "denied_recipient"}
            offset = blob.get("expiry_offset_ms")
            now = now_mono if now_mono is not None else time.monotonic()
            if _expired(live, offset, now):
                return {"ok": False, "code": "grant_expired"}
            try:
                plaintext = open_credential(private, blob, live)
            except ValueError:
                return {"ok": False, "code": "denied_payload"}
            grant_ref = str(blob.get("grant_ref"))
            nonce = str(blob.get("nonce"))
            recorded = self.lookup(grant_ref)
            if recorded is not None:
                return {"ok": recorded == "filled", "code": recorded, "repeat": True}
            self._append(grant_ref, nonce, "in_progress")
            if crash_after_record:
                return {"ok": False, "code": "unknown", "repeat": False}
            try:
                fill = plaintext.decode("utf-8")
            except UnicodeDecodeError:
                self._append(grant_ref, nonce, "refused")
                return {"ok": False, "code": "denied_payload"}
            if not fill:
                self._append(grant_ref, nonce, "refused")
                return {"ok": False, "code": "refused"}
            self._append(grant_ref, nonce, "filled")
            return {"ok": True, "code": "filled", "fill": fill, "repeat": False}

    def _states(self) -> Dict[str, str]:
        found: Dict[str, str] = {}
        if not self.journal_path.exists():
            return found
        for line in self.journal_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            state = str(row.get("state"))
            if state in _TERMINAL or state == "in_progress":
                found[str(row.get("grant_ref"))] = state
        return found

    def _append(self, grant_ref: str, nonce: str, state: str) -> None:
        self.fence_dir.mkdir(parents=True, exist_ok=True)
        line = json.dumps(
            {"grant_ref": grant_ref, "nonce": nonce, "state": state},
            sort_keys=True,
        )
        created = not self.journal_path.exists()
        with self.journal_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(self.journal_path, 0o600)
        if created:
            fsync_dir(self.fence_dir)

    def _destroy_key(self) -> None:
        if self.wrapped_key_path.exists():
            self.wrapped_key_path.unlink()

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.fence_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.journal_path.with_name(self.journal_path.name + ".lock")
        handle = lock_path.open("a", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()


def _expired(live: LiveBinding, offset: object, now_mono: float) -> bool:
    if isinstance(offset, bool) or not isinstance(offset, int):
        return True
    if offset <= 0 or offset > 30_000:
        return True
    elapsed_ms = (now_mono - live.challenge_mono) * 1000
    if elapsed_ms < 0:
        return True
    return elapsed_ms > offset
