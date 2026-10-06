"""Opaque workload use-grants.

The wire value is a random reference. Keeper stores the binding: requester,
recipient possession, policy, task, lease, and destination. A copied reference
presented by another admitted browser is refused, and the grant stays unused.

Consumption and boot denial are appended to a journal. The production
journal and keeper epoch live under ``state/host-fence``, outside
``authority/``. Restoring ``authority/`` does not revive a consumed grant.
The wire code for a boot mismatch is ``denied_boot``. Use ttl is capped at
60 seconds. The sealed credential's own expiry is a separate 30 second
guard check. Empty audience, field, and tenant match nothing.

One approved operation yields at most one grant. Issue journals the
operation id before the grant is saved, so restoring ``authority/`` does not
let a second ``PrepareUse`` for that operation issue again. Journal rows,
and the directory entry of a newly created journal or epoch file, are
fsynced before the call that wrote them returns.

Each keeper-core start advances a durable boot epoch under ``host-fence/``
(``begin_keeper_boot``). A grant records the boot that issued it. Resolve
under a later boot is terminal ``denied_boot``.
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
TERMINAL = frozenset({"consumed", "denied_boot"})


class OperationSpent(ValueError):
    """The operation already has a grant. A new attempt needs a new operation."""


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
        self._operations: set[str] = set()
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
        *,
        audience_role: str = "",
        audience_instance: str = "",
        audience_key: str = "",
        field: str = "",
        tenant: str = "",
        fence: str = "",
        keeper_epoch: int,
    ) -> Dict[str, Any]:
        """Create a single-use grant and return the stored record.

        The recipient must already have a certificate fingerprint, a channel
        key, or a pid and start time. The caller sends only ``grant_ref`` to
        the requester. Audience, field, tenant, fence, and the keeper boot
        epoch are bindings, not requester choices. A second grant for
        ``operation_id`` raises ``OperationSpent``, including after the
        grants file is restored, because the journal records the issue.
        """
        if ttl_seconds <= 0 or ttl_seconds > MAX_TTL_SECONDS:
            raise ValueError("use grant ttl must be in (0, 60] seconds")
        if not recipient.has_possession():
            raise ValueError("recipient has no possession proof")
        if not frame_id or not navigation_generation:
            raise ValueError("destination binding is empty")
        if not _nonempty(audience_role, audience_instance, field, tenant, fence):
            raise ValueError("audience, field, tenant, and fence must be non-empty")
        _require_public(audience_key)
        if (
            isinstance(keeper_epoch, bool)
            or not isinstance(keeper_epoch, int)
            or keeper_epoch < 1
        ):
            raise ValueError("keeper boot epoch must be a positive integer")
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
            "audience": {
                "role": audience_role,
                "instance_id": audience_instance,
                "channel_public": audience_key,
            },
            "field": field,
            "tenant": tenant,
            "fence": fence,
            "lease": {
                "lease_id": lease_id,
                "epoch": lease_epoch,
                "keeper_epoch": keeper_epoch,
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
            if operation_id in self._operations or any(
                grant["task"]["operation_id"] == operation_id
                for grant in self._grants.values()
            ):
                raise OperationSpent("operation already has a grant")
            _append_journal(
                self.journal_path,
                {
                    "kind": "issue",
                    "operation_id": operation_id,
                    "grant_ref": record["grant_ref"],
                },
            )
            self._operations.add(operation_id)
            self._grants[record["grant_ref"]] = record
            self._save_locked()
        return record

    def resolve(
        self,
        grant_ref: str,
        presenter: WorkloadIdentity,
        origin: str,
        operation_id: str,
        frame_id: str,
        navigation_generation: str,
        *,
        broker_instance: Optional[str] = None,
        field: Optional[str] = None,
        tenant: Optional[str] = None,
        keeper_epoch: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Recheck the authenticated presenter and consume the grant on success.

        ``presenter`` is the guard identified by a possession proof. Broker
        observations are not an argument. Role, instance, origin, frame, and
        operation mismatches do not consume the grant. A boot-generation
        mismatch is terminal ``denied_boot``. So is a grant issued under a
        keeper boot other than ``keeper_epoch``, when the caller passes one.
        """
        with self._locked():
            self._sync_locked()
            tombstone = self._journal.get(grant_ref)
            if tombstone == "consumed":
                return {"ok": False, "code": "grant_consumed"}
            if tombstone == "denied_boot":
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
            if (
                keeper_epoch is not None
                and grant["lease"].get("keeper_epoch") != keeper_epoch
            ):
                self._terminal_locked(grant_ref, "denied_boot")
                return {"ok": False, "code": "denied_boot"}
            if operation_id != grant["task"]["operation_id"]:
                return {"ok": False, "code": "denied_payload"}
            destination = grant["destination_binding"]
            if (
                frame_id != destination["frame_binding"]
                or navigation_generation != destination["document_generation"]
            ):
                return {"ok": False, "code": "denied_payload"}
            recipient = grant["recipient"]
            if presenter.role != recipient["role"]:
                return {"ok": False, "code": "denied_role"}
            if presenter.instance_id != recipient["instance_id"]:
                return {"ok": False, "code": "denied_recipient"}
            if presenter.boot_id != recipient[
                "boot_id"
            ] or presenter.boot_generation != int(recipient["boot_generation"]):
                self._terminal_locked(grant_ref, "denied_boot")
                return {"ok": False, "code": "denied_boot"}
            if not _possession_matches(recipient, presenter):
                return {"ok": False, "code": "denied_recipient"}
            if origin != grant["policy"]["origin"]:
                return {"ok": False, "code": "denied_origin"}
            audience = (
                grant.get("audience") if isinstance(grant.get("audience"), dict) else {}
            )
            stored_broker = audience.get("instance_id")
            if (
                not isinstance(stored_broker, str)
                or not stored_broker
                or broker_instance != stored_broker
            ):
                return {"ok": False, "code": "denied_role"}
            if not _exact(grant.get("field"), field):
                return {"ok": False, "code": "denied_payload"}
            if not _exact(grant.get("tenant"), tenant):
                return {"ok": False, "code": "denied_payload"}
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
            if self.epoch_path.exists():
                self._epoch = _read_epoch(self.epoch_path)
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
        self._epoch = _read_epoch(self.epoch_path)
        self._read_journal_locked()
        if self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            file_epoch = raw.get("epoch") if isinstance(raw, dict) else None
            grants = raw.get("grants") if isinstance(raw, dict) else None
            if file_epoch == self._epoch and isinstance(grants, dict):
                loaded: Dict[str, Dict[str, Any]] = {}
                for key, value in grants.items():
                    if isinstance(key, str) and isinstance(value, dict):
                        _refresh_deadline(value)
                        loaded[key] = value
                self._grants = loaded
            else:
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
        operations: set[str] = set()
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
                elif row.get("kind") == "issue" and isinstance(
                    row.get("operation_id"), str
                ):
                    operations.add(row["operation_id"])
        self._journal = grants
        self._bootstrap = bootstrap
        self._operations = operations

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


def host_fence_paths(authority: Path) -> tuple[Path, Path]:
    """Return the consume journal and keeper epoch outside ``authority``.

    A snapshot of ``authority/`` does not include these files. Restoring that
    snapshot cannot roll the epoch backward or erase a journaled consume.
    """
    fence = authority.parent / "host-fence"
    return fence / "authority-journal.jsonl", fence / "keeper-epoch"


def keeper_boot_path(authority: Path) -> Path:
    """Return the keeper boot epoch file, beside the consume journal."""
    return authority.parent / "host-fence" / "keeper-boot-epoch"


def begin_keeper_boot(path: Path) -> int:
    """Advance and return the durable keeper boot epoch.

    keeper-core calls this once at start. The value only increases, and it is
    written before the server accepts a call, so a grant or seal from an
    earlier boot never matches the running keeper.
    """
    with _journal_lock(path):
        current = _read_epoch(path) if path.exists() else 0
        nxt = current + 1
        _write_epoch(path, nxt)
        return nxt


def revoke_instance_grants(
    grants_path: Path,
    journal_path: Path,
    epoch_path: Path,
    instance_id: str,
) -> int:
    """Journal ``denied_boot`` for every issued grant of ``instance_id``.

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
            grant["disposition"] = "denied_boot"
            _append_journal(
                journal_path,
                {"kind": "grant", "grant_ref": ref, "disposition": "denied_boot"},
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


def _nonempty(*values: str) -> bool:
    return all(isinstance(value, str) and bool(value) for value in values)


def _exact(stored: object, presented: Optional[str]) -> bool:
    """Return whether ``presented`` is the non-empty stored binding."""
    return isinstance(stored, str) and bool(stored) and presented == stored


def _require_public(value: str) -> None:
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("audience key is not hex") from exc
    if len(raw) != 32:
        raise ValueError("audience key must be 32 bytes")


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
    channel = recipient.get("channel_public")
    has_channel = isinstance(channel, str) and bool(channel)
    if not has_fp and not has_pid and not has_channel:
        return False
    if has_fp and observed.cert_fingerprint != fingerprint:
        return False
    if has_pid and (observed.pid != pid or observed.starttime != starttime):
        return False
    if has_channel and observed.channel_public != channel:
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
        "channel_public": identity.channel_public,
    }


def _append_journal(path: Path, row: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    created = not path.exists()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)
    if created:
        fsync_dir(path.parent)


def _read_epoch(path: Path) -> int:
    text = path.read_text(encoding="utf-8").strip()
    value = int(text)
    if value < 1:
        raise ValueError("keeper epoch must be positive")
    return value


def _write_epoch(path: Path, epoch: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(f"{epoch}\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    fsync_dir(path.parent)


def fsync_dir(directory: Path) -> None:
    """Make a created or renamed entry in ``directory`` durable."""
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


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
