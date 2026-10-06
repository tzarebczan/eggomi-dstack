"""Keeper-written prepare policy.

The keeper, or a test double that simulates that write, publishes immutable
revisions under its private directory. ``PrepareUse`` loads the current
revision from disk on every call. Admission does not read this directory.
A requester echo that disagrees with the loaded revision is ``denied_payload``
and stores nothing.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


@dataclass(frozen=True)
class PreparedUse:
    """Authority values taken from the keeper policy."""

    operation_id: str
    task_id: str
    resource_handle: str
    origin: str
    policy_revision: str
    lease_id: str
    lease_epoch: int
    recipient_instance_id: str
    frame_id: str
    navigation_generation: str
    tenant: str
    audience_role: str
    audience_instance: str
    field: str
    fence: str


def publish_revision(directory: Path, document: Dict[str, Any]) -> str:
    """Publish one keeper revision and point ``current`` at it.

    Repeating the same revision bytes is a no-op. A different document for
    an existing revision id is refused. ``current`` moves only to a revision
    that this call creates. Pointing it back at an older revision is refused.
    The caller is the keeper writer. In the lab demo the launcher is that
    test double and publishes through this function. It does not copy a
    fixture to ``authority/keeper-policy.json``.
    """
    _validate(document)
    revision = str(document["policy_revision"])
    if not _REVISION.match(revision):
        raise ValueError("keeper policy revision name is not safe")
    directory.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    target = directory / f"{revision}.json"
    current_path = directory / "current"
    current = current_path.read_text(encoding="utf-8").strip() if current_path.exists() else ""
    if target.exists() and target.read_text(encoding="utf-8") != payload:
        raise ValueError("keeper policy revision is immutable")
    if target.exists():
        if current == revision:
            return revision
        raise ValueError("keeper policy current pointer does not move backward")
    _atomic(target, payload)
    _atomic(current_path, revision + "\n")
    return revision


def load_current(directory: Path) -> Dict[str, Any]:
    """Load the current revision from disk. Nothing is cached."""
    name = (directory / "current").read_text(encoding="utf-8").strip()
    if not _REVISION.match(name):
        raise ValueError("keeper policy current revision is not safe")
    path = directory / f"{name}.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    _validate(raw)
    if raw.get("policy_revision") != name:
        raise ValueError("keeper policy revision pointer does not match the document")
    return raw


def load_policy(path: Path) -> Dict[str, Any]:
    """Load one ``cah-keeper-policy/v1`` document. A bad document raises ``ValueError``."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    _validate(raw)
    return raw


def evaluate_prepare(
    policy: Dict[str, Any], body: Dict[str, Any]
) -> Optional[PreparedUse]:
    """Return the keeper binding when ``body`` matches it exactly."""
    operation_id = body.get("operation_id")
    if not isinstance(operation_id, str):
        return None
    operation = policy["operations"].get(operation_id)
    if not isinstance(operation, dict):
        return None
    recipient_id = operation.get("recipient_instance_id")
    handle = operation.get("resource_handle")
    if not isinstance(recipient_id, str) or not isinstance(handle, str):
        return None
    credential = policy["credentials"].get(handle)
    lease = policy["leases"].get(recipient_id)
    if not isinstance(credential, dict) or not isinstance(lease, dict):
        return None
    origins = credential.get("origins")
    if (
        not isinstance(origins, list)
        or len(origins) != 1
        or not isinstance(origins[0], str)
    ):
        return None
    audience = policy["audience"]
    origin = origins[0]
    expected = {
        "operation_id": operation_id,
        "task_id": operation.get("task_id"),
        "resource_handle": handle,
        "origin": origin,
        "policy_revision": policy["policy_revision"],
        "lease_id": lease.get("lease_id"),
        "lease_epoch": lease.get("epoch"),
        "recipient_instance_id": recipient_id,
        "tenant": policy["tenant"],
        "audience_role": audience.get("role"),
        "audience_instance": audience.get("instance_id"),
        "field": credential.get("field"),
    }
    for key, value in expected.items():
        if body.get(key) != value:
            return None
    frame_id = operation.get("frame_id")
    navigation = operation.get("navigation_generation")
    fence = lease.get("fence")
    if (
        not isinstance(frame_id, str)
        or not isinstance(navigation, str)
        or not isinstance(fence, str)
    ):
        return None
    if not isinstance(expected["task_id"], str) or not isinstance(
        expected["lease_id"], str
    ):
        return None
    if isinstance(expected["lease_epoch"], bool) or not isinstance(
        expected["lease_epoch"], int
    ):
        return None
    return PreparedUse(
        operation_id=operation_id,
        task_id=expected["task_id"],
        resource_handle=handle,
        origin=origin,
        policy_revision=str(expected["policy_revision"]),
        lease_id=expected["lease_id"],
        lease_epoch=expected["lease_epoch"],
        recipient_instance_id=recipient_id,
        frame_id=frame_id,
        navigation_generation=navigation,
        tenant=str(expected["tenant"]),
        audience_role=str(expected["audience_role"]),
        audience_instance=str(expected["audience_instance"]),
        field=str(expected["field"]),
        fence=fence,
    )


def _validate(raw: Dict[str, Any]) -> None:
    if raw.get("schema_version") != "cah-keeper-policy/v1":
        raise ValueError("keeper policy schema is not cah-keeper-policy/v1")
    if not isinstance(raw.get("policy_revision"), str) or not raw["policy_revision"]:
        raise ValueError("keeper policy revision is missing")
    if not isinstance(raw.get("tenant"), str) or not raw["tenant"]:
        raise ValueError("keeper policy tenant is missing")
    audience = raw.get("audience")
    if not isinstance(audience, dict):
        raise ValueError("keeper policy audience is missing")
    if not isinstance(audience.get("role"), str) or not audience["role"]:
        raise ValueError("keeper policy audience role is missing")
    if not isinstance(audience.get("instance_id"), str) or not audience["instance_id"]:
        raise ValueError("keeper policy audience instance is missing")
    for key in ("credentials", "leases", "operations"):
        if not isinstance(raw.get(key), dict) or not raw[key]:
            raise ValueError(f"keeper policy {key} is missing")
    for credential in raw["credentials"].values():
        if not isinstance(credential, dict):
            raise ValueError("keeper policy credential is missing")
        if not isinstance(credential.get("field"), str) or not credential["field"]:
            raise ValueError("keeper policy field is missing")
    for lease in raw["leases"].values():
        if not isinstance(lease, dict):
            raise ValueError("keeper policy lease is missing")
        if not isinstance(lease.get("fence"), str) or not lease["fence"]:
            raise ValueError("keeper policy fence is missing")


def _atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
