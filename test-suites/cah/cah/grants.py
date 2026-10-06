"""Opaque workload use-grants.

The wire value is a random reference. The binding (requester, recipient,
policy, task, lease) stays in keeper-core. A copied reference is useless
without the admitted recipient identity.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .registry import WorkloadIdentity

SCHEMA = "workload-use-grant/v1"


class GrantStore:
    """Process-local store persisted so tests can read dispositions."""

    def __init__(self, path: Path) -> None:
        """Load any grants already on disk."""
        self.path = path
        self._lock = threading.Lock()
        self._grants: Dict[str, Dict[str, Any]] = {}
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._grants = {
                    key: value for key, value in raw.items() if isinstance(value, dict)
                }

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
    ) -> Dict[str, Any]:
        """Create a single-use grant and return the stored record.

        The caller must send only ``grant_ref`` to the requester.
        """
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
            "task": {"task_id": task_id, "operation_id": operation_id},
            "lease": {
                "lease_id": lease_id,
                "epoch": lease_epoch,
                "use_limit": 1,
                "expires_unix": time.time() + ttl_seconds,
            },
            "disposition": "issued",
            "uses": 0,
        }
        with self._lock:
            self._grants[record["grant_ref"]] = record
            self._save()
        return record

    def resolve(
        self,
        grant_ref: str,
        observed: WorkloadIdentity,
        origin: str,
        operation_id: str,
    ) -> Dict[str, Any]:
        """Recheck the recipient and consume the grant on success.

        Role, boot, origin, and operation mismatches do not consume the grant.
        """
        with self._lock:
            grant = self._grants.get(grant_ref)
            if grant is None:
                return {"ok": False, "code": "denied_grant"}
            if grant["disposition"] == "consumed" or int(grant["uses"]) >= int(
                grant["lease"]["use_limit"]
            ):
                return {"ok": False, "code": "grant_consumed"}
            if time.time() > float(grant["lease"]["expires_unix"]):
                return {"ok": False, "code": "grant_expired"}
            if operation_id != grant["task"]["operation_id"]:
                return {"ok": False, "code": "denied_payload"}
            recipient = grant["recipient"]
            if (
                observed.role != recipient["role"]
                or observed.instance_id != recipient["instance_id"]
            ):
                return {"ok": False, "code": "denied_role"}
            if observed.boot_id != recipient["boot_id"]:
                return {"ok": False, "code": "denied_boot"}
            expected_fp = recipient.get("cert_fingerprint")
            if (
                isinstance(expected_fp, str)
                and observed.cert_fingerprint != expected_fp
            ):
                return {"ok": False, "code": "denied_recipient"}
            if origin != grant["policy"]["origin"]:
                return {"ok": False, "code": "denied_origin"}
            grant["uses"] = int(grant["uses"]) + 1
            grant["disposition"] = "consumed"
            self._save()
            return {
                "ok": True,
                "code": "ok",
                "operation_id": grant["task"]["operation_id"],
                "resource_handle": grant["policy"]["resource_handle"],
                "origin": grant["policy"]["origin"],
            }

    def get(self, grant_ref: str) -> Optional[Dict[str, Any]]:
        """Return a copy of one grant record."""
        with self._lock:
            grant = self._grants.get(grant_ref)
            if grant is None:
                return None
            return json.loads(json.dumps(grant))

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(self._grants, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)


def _party(identity: WorkloadIdentity) -> Dict[str, Any]:
    return {
        "role": identity.role,
        "instance_id": identity.instance_id,
        "boot_id": identity.boot_id,
        "cert_fingerprint": identity.cert_fingerprint,
    }
