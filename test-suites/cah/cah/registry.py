"""Admission registry for one lab run.

The launcher creates rows. keeper-core may append a scoped bootstrap row.
Peer identity is the row recorded for a pid plus start time, or for a
certificate fingerprint. A self-declared role in an RPC body is not consulted.

Boot generations only advance. Rebinding a pid, start time, or fingerprint
mints a new generation. An older boot id is refused.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional


class BootRollback(ValueError):
    """A boot id would move a workload back to an older incarnation."""


@dataclass(frozen=True)
class WorkloadIdentity:
    """One admitted workload incarnation."""

    trust_domain: str
    tenant: str
    role: str
    instance_id: str
    boot_id: str
    boot_generation: int
    cert_fingerprint: Optional[str]
    pid: Optional[int]
    starttime: Optional[int]

    def has_possession(self) -> bool:
        """Return whether this row has a key or a live process binding."""
        if isinstance(self.cert_fingerprint, str) and self.cert_fingerprint:
            return True
        return self.pid is not None and self.starttime is not None


@dataclass(frozen=True)
class BindResult:
    """Outcome of attaching a process to an instance."""

    kind: str
    instance_id: str
    boot_generation: int


@dataclass
class AdmissionRegistry:
    """In-memory view of ``admission-registry/v1``."""

    trust_domain: str
    tenant: str
    workloads: List[Dict[str, object]]

    def find_pid(self, pid: int) -> Optional[WorkloadIdentity]:
        """Return the workload bound to this pid and its current start time.

        A recycled pid with a different ``/proc/<pid>/stat`` start time does
        not inherit the old row.
        """
        for row in self.workloads:
            if row.get("pid") != pid:
                continue
            stored = row.get("starttime")
            if not isinstance(stored, int) or isinstance(stored, bool):
                return None
            try:
                live = process_starttime(pid)
            except OSError:
                return None
            if live != stored:
                return None
            return self._identity(row)
        return None

    def find_fingerprint(self, fingerprint: str) -> Optional[WorkloadIdentity]:
        """Return the workload bound to a certificate fingerprint."""
        if not fingerprint:
            return None
        for row in self.workloads:
            if row.get("cert_fingerprint") == fingerprint:
                return self._identity(row)
        return None

    def find_instance(self, instance_id: str) -> Optional[WorkloadIdentity]:
        """Return the admitted instance, even when no process is bound."""
        for row in self.workloads:
            if row.get("instance_id") == instance_id:
                return self._identity(row)
        return None

    def _identity(self, row: Dict[str, object]) -> WorkloadIdentity:
        pid = row.get("pid")
        fingerprint = row.get("cert_fingerprint")
        starttime = row.get("starttime")
        return WorkloadIdentity(
            trust_domain=self.trust_domain,
            tenant=self.tenant,
            role=str(row["role"]),
            instance_id=str(row["instance_id"]),
            boot_id=str(row["boot_id"]),
            boot_generation=_generation(row.get("boot_generation")),
            cert_fingerprint=str(fingerprint) if isinstance(fingerprint, str) else None,
            pid=int(pid)
            if isinstance(pid, int) and not isinstance(pid, bool)
            else None,
            starttime=(
                int(starttime)
                if isinstance(starttime, int) and not isinstance(starttime, bool)
                else None
            ),
        )


def process_starttime(pid: int) -> int:
    """Return the kernel start-time tick for ``pid``.

    This is field 22 of ``/proc/<pid>/stat`` (the value after the comm field).
    """
    if pid <= 0:
        raise ValueError("pid must be positive")
    data = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    fields = data[data.rfind(")") + 2 :].split()
    return int(fields[19])


def load_registry(path: Path) -> AdmissionRegistry:
    """Load the registry. A missing file is an empty lab registry."""
    if not path.exists() or path.stat().st_size == 0:
        return AdmissionRegistry(
            trust_domain="lab.cah", tenant="tenant-lab-1", workloads=[]
        )
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != "admission-registry/v1":
        raise ValueError("admission registry schema is not admission-registry/v1")
    workloads = raw.get("workloads")
    if not isinstance(workloads, list):
        raise ValueError("admission registry workloads must be a list")
    return AdmissionRegistry(
        trust_domain=str(raw["trust_domain"]),
        tenant=str(raw["tenant"]),
        workloads=workloads,
    )


def bind_process(
    path: Path,
    instance_id: str,
    pid: Optional[int],
    fingerprint: Optional[str] = None,
) -> BindResult:
    """Attach a live pid to an instance.

    The first bind records the pid and start time. A later bind with a
    different pid, start time, or fingerprint advances ``boot_generation``
    and clears the previous process binding. Callers revoke outstanding
    grants for that instance when the result kind is ``rebound``.
    """
    starttime = process_starttime(pid) if pid is not None else None

    def mutate(registry: AdmissionRegistry) -> BindResult:
        for row in registry.workloads:
            if row.get("instance_id") != instance_id:
                continue
            current_pid = row.get("pid")
            current_start = row.get("starttime")
            current_fp = row.get("cert_fingerprint")
            next_fp = fingerprint if fingerprint is not None else current_fp
            same = (
                current_pid == pid
                and current_start == starttime
                and current_fp == next_fp
                and current_pid is not None
            )
            if same:
                return BindResult(
                    "unchanged", instance_id, _generation(row.get("boot_generation"))
                )
            fresh = current_pid is None and current_start is None
            if not fresh:
                row["boot_generation"] = _generation(row.get("boot_generation")) + 1
            row["pid"] = pid
            row["starttime"] = starttime
            if fingerprint is not None:
                row["cert_fingerprint"] = fingerprint
            kind = "bound" if fresh else "rebound"
            return BindResult(
                kind, instance_id, _generation(row.get("boot_generation"))
            )
        raise ValueError(f"instance {instance_id} is not admitted")

    return _mutate(path, mutate)


def set_boot(path: Path, instance_id: str, boot_id: str) -> int:
    """Advance one instance to a boot id it has not used before.

    The previous id stays in ``boot_history``. Repeating it raises
    ``BootRollback`` and does not change the row.
    """
    if not boot_id:
        raise ValueError("boot id is empty")

    def mutate(registry: AdmissionRegistry) -> int:
        for row in registry.workloads:
            if row.get("instance_id") != instance_id:
                continue
            history = row.get("boot_history")
            if not isinstance(history, list) or not history:
                history = [str(row["boot_id"])]
            if boot_id in history:
                raise BootRollback(f"boot id {boot_id} is not newer for {instance_id}")
            history.append(boot_id)
            row["boot_history"] = history
            row["boot_id"] = boot_id
            row["boot_generation"] = _generation(row.get("boot_generation")) + 1
            return _generation(row.get("boot_generation"))
        raise ValueError(f"instance {instance_id} is not admitted")

    return _mutate(path, mutate)


def save_registry(path: Path, registry: AdmissionRegistry) -> None:
    """Atomically replace the registry file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    for row in registry.workloads:
        if "boot_generation" not in row:
            row["boot_generation"] = 1
        if not isinstance(row.get("boot_history"), list):
            row["boot_history"] = [row["boot_id"]]
        if "starttime" not in row:
            row["starttime"] = None
    payload = {
        "schema_version": "admission-registry/v1",
        "trust_domain": registry.trust_domain,
        "tenant": registry.tenant,
        "workloads": registry.workloads,
    }
    _atomic_write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _mutate(path: Path, fn: object) -> object:
    with _lock(path):
        registry = load_registry(path)
        result = fn(registry)  # type: ignore[operator]
        save_registry(path, registry)
        return result


@contextmanager
def _lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    handle = lock_path.open("a", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _generation(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return 1
    return value
