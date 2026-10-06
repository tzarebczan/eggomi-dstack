"""Keeper-owned prepare policy.

PrepareUse may repeat these fields. It cannot choose them. Disagreement
with the fixture is ``denied_payload``. The fixture is loaded from the
keeper authority directory, not from the requester.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


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


def load_policy(path: Path) -> Dict[str, Any]:
    """Load ``cah-keeper-policy/v1``. A bad document raises ``ValueError``."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != "cah-keeper-policy/v1":
        raise ValueError("keeper policy schema is not cah-keeper-policy/v1")
    if not isinstance(raw.get("policy_revision"), str) or not raw["policy_revision"]:
        raise ValueError("keeper policy revision is missing")
    for key in ("credentials", "leases", "operations"):
        if not isinstance(raw.get(key), dict) or not raw[key]:
            raise ValueError(f"keeper policy {key} is missing")
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
    }
    for key, value in expected.items():
        if body.get(key) != value:
            return None
    frame_id = operation.get("frame_id")
    navigation = operation.get("navigation_generation")
    if not isinstance(frame_id, str) or not isinstance(navigation, str):
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
    )
