"""Opaque workload use-grants.

The wire value is a random reference. Keeper stores the binding: requester,
recipient possession, policy, task, lease, and destination. A copied reference
presented by another admitted browser is refused, and the grant stays unused.

Consumption and boot revocation are appended to a journal outside the grant
snapshot. Reloading an older ``grants.json`` does not revive a journaled
grant. Use ttl is capped at 60 seconds.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import fcntl
import json
import os
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from .registry import WorkloadIdentity

SCHEMA = "workload-use-grant/v1"
MAX_TTL_SECONDS = 60.0
TERMINAL = frozenset({"consumed", "revoked_boot"})


class GrantStore:
    """Keeper-side store. The journal wins over a restored grants file."""

    def __init__(
        self,
        path: Path,
        journal_path: Optional[Path] = None,
        epoch_path: Optional[Path] = None,
    ) -> None:
        """Load grants whose epoch matches the keeper epoch file."""
        self.path = path
        self.journal_path = journal_path or path.with_name("authority-journal.jsonl")
        self.epoch_path = epoch_path or path.with_name("keeper-epoch")
        self._grants: Dict[str, Dict[str, Any]] = {}
        self._journal: Dict[str, str] = {}
        self._bootstrap: set[str] = set()
        self._epoch = 1
        self._load()

    def issue(
        self,
        requester: WorkloadIdentity,
        recipient: WorkloadIdentity,
        policy_revision: str,
        resource_handle: str,
        origin: str,
        task_id: str,
        operation_id: str,
        lease_id: str,
        lease_epoch: int,
        ttl_seconds: float,
        frame_id: str,
        navigation_generation: str,
    ) -> Dict[str, Any]:
        """Create a single-use grant and return the stored record.

        The recipient must already have a certificate fingerprint or a pid
        and start time. The caller sends only ``grant_ref`` to the requester.
        """
        if ttl_seconds <= 0 or ttl_seconds > MAX_TTL_SECONDS:
            raise ValueError("use grant ttl must be in (0, 60] seconds")
        if not recipient.has_possession():
            raise ValueError("recipient has no possession proof")
        if not frame_id or not navigation_generation:
            raise ValueError("destination binding is empty")
        now_unix = time.time()
        record = {
            "schema_version": SCHEMA,
            "grant_ref": secrets.token_hex(32),
            "requester": _party(requester),
            "recipient": _party(recipient),
            "policy": {
                "revision": policy_revision,
                "method": "CompleteFill",
                "resource_handle": resource_handle,
                "origin": origin,
            },
            "destination_binding": {
                "origin": origin,
                "document_generation": navigation_generation,
                "frame_binding": frame_id,
            },
            "task": {"task_id": task_id, "operation_id": operation_id},
            "lease": {
                "lease_id": lease_id,
                "epoch": lease_epoch,
                "use_limit": 1,
                "ttl_seconds": ttl_seconds,
                "issued_unix": now_unix,
                "expires_unix": now_unix + ttl_seconds,
                "expires_mono": time.monotonic() + ttl_seconds,
            },
            "disposition": "issued",
            "uses": 0,
        }
        with self._locked():
            self._sync_locked()
            self._grants[record["grant_ref"]] = record
            self._save_locked()
        return record

    def resolve(
        self,
        grant_ref: str,
        observed: WorkloadIdentity,
        origin: str,
        operation_id: str,
        frame_id: str,
        navigation_generation: str,
    ) -> Dict[str, Any]:
        """Recheck recipient possession and consume the grant on success.

        Role, instance, boot, origin, frame, and operation mismatches do not
        consume the grant. A boot-generation mismatch is terminal.
        """
        with self._locked():
            self._sync_locked()
            tombstone = self._journal.get(grant_ref)
            if tombstone == "consumed":
                return {"ok": False, "code": "grant_consumed"}
            if tombstone == "revoked_boot":
                return {"ok": False, "code": "denied_boot"}
            grant = self._grants.get(grant_ref)
            if grant is None:
                return {"ok": False, "code": "denied_grant"}
            if grant["disposition"] in TERMINAL or int(grant["uses"]) >= int(
                grant["lease"]["use_limit"]
            ):
                code = (
                    "grant_consumed"
                    if grant["disposition"] == "consumed"
                    else "denied_boot"
                )
                return {"ok": False, "code": code}
            if _expired(grant):
                return {"ok": False, "code": "grant_expired"}
            if operation_id != grant["task"]["operation_id"]:
                return {"ok": False, "code": "denied_payload"}
            destination = grant["destination_binding"]
            if (
                frame_id != destination["frame_binding"]
                or navigation_generation != destination["document_generation"]
            ):
                return {"ok": False, "code": "denied_payload"}
            recipient = grant["recipient"]
            if observed.role != recipient["role"]:
                return {"ok": False, "code": "denied_role"}
            if observed.instance_id != recipient["instance_id"]:
                return {"ok": False, "code": "denied_recipient"}
            if observed.boot_id != recipient[
                "boot_id"
            ] or observed.boot_generation != int(recipient["boot_generation"]):
                self._terminal_locked(grant_ref, "revoked_boot")
                return {"ok": False, "code": "denied_boot"}
            if not _possession_matches(recipient, observed):
                return {"ok": False, "code": "denied_recipient"}
            if origin != grant["policy"]["origin"]:
                return {"ok": False, "code": "denied_origin"}
            self._terminal_locked(grant_ref, "consumed")
            return {
                "ok": True,
                "code": "ok",
                "operation_id": grant["task"]["operation_id"],
                "resource_handle": grant["policy"]["resource_handle"],
                "origin": grant["policy"]["origin"],
            }

    def get(self, grant_ref: str) -> Optional[Dict[str, Any]]:
        """Return a copy of one grant record."""
        with self._locked():
            self._sync_locked()
            grant = self._grants.get(grant_ref)
            if grant is None:
                return None
            return json.loads(json.dumps(grant))

    def find_operation(self, operation_id: str) -> Optional[Dict[str, Any]]:
        """Return a copy of the grant issued for ``operation_id``."""
        with self._locked():
            self._sync_locked()
            for grant in self._grants.values():
                if grant["task"]["operation_id"] == operation_id:
                    return json.loads(json.dumps(grant))
            return None

    def bootstrap_used(self, token_sha256: str) -> bool:
        """Return whether this bootstrap token hash is already journaled."""
        with self._locked():
            self._sync_locked()
            return token_sha256 in self._bootstrap

    def note_bootstrap(self, token_sha256: str) -> None:
        """Record a spent bootstrap token and advance the keeper epoch."""
        with self._locked():
            self._sync_locked()
            if token_sha256 in self._bootstrap:
                return
            _append_journal(
                self.journal_path,
                {"kind": "bootstrap", "token_sha256": token_sha256},
            )
            self._bootstrap.add(token_sha256)
            self._bump_epoch_locked()
            self._save_locked()

    def _load(self) -> None:
        with self._locked():
            self._ensure_epoch_locked()
            self._read_journal_locked()
            self._grants = {}
            if not self.path.exists():
                return
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            file_epoch = raw.get("epoch") if isinstance(raw, dict) else None
            grants = raw.get("grants") if isinstance(raw, dict) else None
            if not isinstance(grants, dict) or file_epoch != self._epoch:
                return
            for key, value in grants.items():
                if isinstance(key, str) and isinstance(value, dict):
                    _refresh_deadline(value)
                    self._grants[key] = value
            self._apply_journal_locked()

    def _sync_locked(self) -> None:
        self._ensure_epoch_locked()
        previous = self._epoch
        self._epoch = _read_epoch(self.epoch_path)
        self._read_journal_locked()
        if self._epoch != previous and self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and raw.get("epoch") != self._epoch:
                self._grants = {
                    ref: grant
                    for ref, grant in self._grants.items()
                    if self._journal.get(ref) in TERMINAL
                }
        self._apply_journal_locked()

    def _apply_journal_locked(self) -> None:
        for ref, disposition in self._journal.items():
            grant = self._grants.get(ref)
            if grant is None:
                continue
            grant["disposition"] = disposition
            if disposition == "consumed":
                grant["uses"] = max(int(grant["uses"]), 1)

    def _terminal_locked(self, grant_ref: str, disposition: str) -> None:
        grant = self._grants[grant_ref]
        grant["disposition"] = disposition
        if disposition == "consumed":
            grant["uses"] = int(grant["uses"]) + 1
        self._journal[grant_ref] = disposition
        _append_journal(
            self.journal_path,
            {"kind": "grant", "grant_ref": grant_ref, "disposition": disposition},
        )
        self._bump_epoch_locked()
        self._save_locked()

    def _bump_epoch_locked(self) -> None:
        self._epoch += 1
        _write_epoch(self.epoch_path, self._epoch)

    def _ensure_epoch_locked(self) -> None:
        if not self.epoch_path.exists():
            _write_epoch(self.epoch_path, 1)
            self._epoch = 1

    def _read_journal_locked(self) -> None:
        grants: Dict[str, str] = {}
        bootstrap: set[str] = set()
        if self.journal_path.exists():
            for line in self.journal_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                if row.get("kind") == "grant" and row.get("disposition") in TERMINAL:
                    grants[str(row["grant_ref"])] = str(row["disposition"])
                elif row.get("kind") == "bootstrap" and isinstance(
                    row.get("token_sha256"), str
                ):
                    bootstrap.add(row["token_sha256"])
        self._journal = grants
        self._bootstrap = bootstrap

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"epoch": self._epoch, "grants": self._grants}
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with _journal_lock(self.journal_path):
            yield


def revoke_instance_grants(
    grants_path: Path,
    journal_path: Path,
    epoch_path: Path,
    instance_id: str,
) -> int:
    """Journal ``revoked_boot`` for every issued grant of ``instance_id``.

    The keeper process observes the journal on its next resolve. A restored
    grants file from before this call does not clear the journal.
    """
    with _journal_lock(journal_path):
        epoch = _read_epoch(epoch_path) if epoch_path.exists() else 1
        grants: Dict[str, Dict[str, Any]] = {}
        file_epoch = None
        if grants_path.exists():
            raw = json.loads(grants_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("grants"), dict):
                grants = raw["grants"]
                file_epoch = raw.get("epoch")
        if file_epoch != epoch:
            grants = {}
        count = 0
        for ref, grant in grants.items():
            recipient = grant.get("recipient")
            if not isinstance(recipient, dict):
                continue
            if recipient.get("instance_id") != instance_id:
                continue
            if grant.get("disposition") != "issued":
                continue
            grant["disposition"] = "revoked_boot"
            _append_journal(
                journal_path,
                {"kind": "grant", "grant_ref": ref, "disposition": "revoked_boot"},
            )
            count += 1
        epoch += 1
        _write_epoch(epoch_path, epoch)
        grants_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = grants_path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps({"epoch": epoch, "grants": grants}, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        os.chmod(tmp, 0o600)
        os.replace(tmp, grants_path)
        return count


def _possession_matches(recipient: Dict[str, Any], observed: WorkloadIdentity) -> bool:
    fingerprint = recipient.get("cert_fingerprint")
    pid = recipient.get("pid")
    starttime = recipient.get("starttime")
    has_fp = isinstance(fingerprint, str) and bool(fingerprint)
    has_pid = (
        isinstance(pid, int)
        and not isinstance(pid, bool)
        and isinstance(starttime, int)
        and not isinstance(starttime, bool)
    )
    if not has_fp and not has_pid:
        return False
    if has_fp and observed.cert_fingerprint != fingerprint:
        return False
    if has_pid and (observed.pid != pid or observed.starttime != starttime):
        return False
    return True


def _refresh_deadline(grant: Dict[str, Any]) -> None:
    lease = grant.get("lease")
    if not isinstance(lease, dict) or "expires_unix" not in lease:
        return
    remaining = float(lease["expires_unix"]) - time.time()
    lease["expires_mono"] = time.monotonic() + remaining


def _expired(grant: Dict[str, Any]) -> bool:
    lease = grant["lease"]
    issued = float(lease["issued_unix"])
    now = time.time()
    if now < issued:
        return True
    if now > float(lease["expires_unix"]):
        return True
    expires_mono = lease.get("expires_mono")
    if isinstance(expires_mono, (int, float)) and time.monotonic() > float(
        expires_mono
    ):
        return True
    return False


def _party(identity: WorkloadIdentity) -> Dict[str, Any]:
    return {
        "role": identity.role,
        "instance_id": identity.instance_id,
        "boot_id": identity.boot_id,
        "boot_generation": identity.boot_generation,
        "cert_fingerprint": identity.cert_fingerprint,
        "pid": identity.pid,
        "starttime": identity.starttime,
    }


def _append_journal(path: Path, row: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
        os.chmod(path, 0o600)


def _read_epoch(path: Path) -> int:
    text = path.read_text(encoding="utf-8").strip()
    value = int(text)
    if value < 1:
        raise ValueError("keeper epoch must be positive")
    return value


def _write_epoch(path: Path, epoch: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(f"{epoch}\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


@contextmanager
def _journal_lock(journal_path: Path) -> Iterator[None]:
    journal_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = journal_path.with_name(journal_path.name + ".lock")
    handle = lock_path.open("a", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
