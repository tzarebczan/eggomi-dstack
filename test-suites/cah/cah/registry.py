"""Launcher-owned admission registry.

Processes do not write this file. Peer identity is whatever the launcher
recorded for a pid or certificate fingerprint. A self-declared role in an
RPC body is not consulted.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass(frozen=True)
class WorkloadIdentity:
    """One admitted workload incarnation."""

    trust_domain: str
    tenant: str
    role: str
    instance_id: str
    boot_id: str
    cert_fingerprint: Optional[str]
    pid: Optional[int]


@dataclass
class AdmissionRegistry:
    """In-memory view of ``admission-registry/v1``."""

    trust_domain: str
    tenant: str
    workloads: List[Dict[str, object]]

    def find_pid(self, pid: int) -> Optional[WorkloadIdentity]:
        """Return the workload currently bound to ``pid``."""
        for row in self.workloads:
            if row.get("pid") == pid:
                return self._identity(row)
        return None

    def find_fingerprint(self, fingerprint: str) -> Optional[WorkloadIdentity]:
        """Return the workload bound to a certificate fingerprint."""
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
        return WorkloadIdentity(
            trust_domain=self.trust_domain,
            tenant=self.tenant,
            role=str(row["role"]),
            instance_id=str(row["instance_id"]),
            boot_id=str(row["boot_id"]),
            cert_fingerprint=str(fingerprint) if isinstance(fingerprint, str) else None,
            pid=int(pid) if isinstance(pid, int) else None,
        )


def load_registry(path: Path) -> AdmissionRegistry:
    """Load the registry. A missing file is an empty lab registry."""
    if not path.exists():
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
) -> None:
    """Attach a live pid, and optional cert fingerprint, to an instance."""
    registry = load_registry(path)
    for row in registry.workloads:
        if row.get("instance_id") == instance_id:
            row["pid"] = pid
            if fingerprint is not None:
                row["cert_fingerprint"] = fingerprint
            save_registry(path, registry)
            return
    raise ValueError(f"instance {instance_id} is not admitted")


def set_boot(path: Path, instance_id: str, boot_id: str) -> None:
    """Replace the admitted boot id for one instance."""
    registry = load_registry(path)
    for row in registry.workloads:
        if row.get("instance_id") == instance_id:
            row["boot_id"] = boot_id
            save_registry(path, registry)
            return
    raise ValueError(f"instance {instance_id} is not admitted")


def save_registry(path: Path, registry: AdmissionRegistry) -> None:
    """Atomically replace the registry file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "admission-registry/v1",
        "trust_domain": registry.trust_domain,
        "tenant": registry.tenant,
        "workloads": registry.workloads,
    }
    _atomic_write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
