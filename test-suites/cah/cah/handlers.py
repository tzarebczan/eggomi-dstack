"""Compartment methods for the Eggomi profile.

keeper-core stores use-grants and is the only process that consumes them.
credential-broker releases the fill value only after keeper-core accepts the
observed recipient. connector has no allow-list edges.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .access import AccessGraph
from .auth import AUTHORITY_FIELDS, AuthContext
from .grants import GrantStore
from .registry import load_registry, save_registry
from .rpc import call_rpc, rpc_error, rpc_ok

MAX_FIELD = 8192
HandlerFn = Callable[["ServerState", AuthContext, Dict[str, Any]], Dict[str, Any]]


@dataclass
class ServerState:
    """Process-wide state for one compartment server."""

    role: str
    state: Path
    transport: str
    access: AccessGraph
    registry_path: Path
    grants: Optional[GrantStore]
    secret: Optional[str]
    keeper_addr: Optional[str]
    cert: Optional[Path]
    key: Optional[Path]
    ca: Optional[Path]
    grant_ttl: float
    _lock: threading.Lock


def dispatch(
    state: ServerState, auth: AuthContext, method: str, body: Dict[str, Any]
) -> Dict[str, Any]:
    """Authorize one call, then run the method.

    Identity fields in the body are refused before the method runs. The
    caller's role comes only from ``auth``.
    """
    if any(key in body for key in AUTHORITY_FIELDS):
        return rpc_error("denied_authority_field")
    if not _fields_ok(body):
        return rpc_error("denied_payload")
    if not auth.admitted or auth.identity is None:
        return rpc_error(auth.denial_code or "denied_unadmitted")
    if not state.access.permitted(auth.identity.role, state.role, method):
        return rpc_error("denied_role")
    method_fn = METHODS.get((state.role, method))
    if method_fn is None:
        return rpc_error("denied_role")
    return method_fn(state, auth, body)


def prepare_use(
    state: ServerState, auth: AuthContext, body: Dict[str, Any]
) -> Dict[str, Any]:
    """Issue an opaque use-grant for an admitted browser-guard recipient."""
    if state.grants is None or auth.identity is None:
        return rpc_error("denied_payload")
    fields = (
        "operation_id",
        "task_id",
        "lease_id",
        "policy_revision",
        "resource_handle",
        "origin",
        "recipient_instance_id",
    )
    if any(not isinstance(body.get(key), str) or not body[key] for key in fields):
        return rpc_error("denied_payload")
    epoch = body.get("lease_epoch")
    if isinstance(epoch, bool) or not isinstance(epoch, int):
        return rpc_error("denied_payload")
    recipient = load_registry(state.registry_path).find_instance(
        str(body["recipient_instance_id"])
    )
    if recipient is None or recipient.role != "browser-guard":
        return rpc_error("denied_recipient")
    record = state.grants.issue(
        requester=auth.identity,
        recipient=recipient,
        policy_revision=str(body["policy_revision"]),
        resource_handle=str(body["resource_handle"]),
        origin=str(body["origin"]),
        task_id=str(body["task_id"]),
        operation_id=str(body["operation_id"]),
        lease_id=str(body["lease_id"]),
        lease_epoch=epoch,
        ttl_seconds=state.grant_ttl,
    )
    return rpc_ok(
        {"grant_ref": record["grant_ref"], "operation_id": body["operation_id"]}
    )


def resolve_use_grant(
    state: ServerState, _auth: AuthContext, body: Dict[str, Any]
) -> Dict[str, Any]:
    """Consume a grant when the broker's observed peer matches it."""
    if state.grants is None:
        return rpc_error("denied_payload")
    grant_ref = body.get("grant_ref")
    origin = body.get("origin")
    operation_id = body.get("operation_id")
    if not all(
        isinstance(item, str) and item for item in (grant_ref, origin, operation_id)
    ):
        return rpc_error("denied_payload")
    observed = _observed(state, body)
    if observed is None:
        return rpc_error("denied_unadmitted")
    result = state.grants.resolve(
        str(grant_ref), observed, str(origin), str(operation_id)
    )
    if not result["ok"]:
        return rpc_error(str(result["code"]))
    return rpc_ok(
        {
            "operation_id": result["operation_id"],
            "resource_handle": result["resource_handle"],
        }
    )


def complete_fill(
    state: ServerState, auth: AuthContext, body: Dict[str, Any]
) -> Dict[str, Any]:
    """Release the fill value to the authenticated browser-guard only."""
    if state.secret is None or state.keeper_addr is None or auth.identity is None:
        return rpc_error("denied_payload")
    fields = (
        "grant_ref",
        "operation_id",
        "origin",
        "frame_id",
        "navigation_generation",
    )
    if any(not isinstance(body.get(key), str) or not body[key] for key in fields):
        return rpc_error("denied_payload")
    report: Dict[str, Any] = {
        "grant_ref": body["grant_ref"],
        "origin": body["origin"],
        "operation_id": body["operation_id"],
    }
    if state.transport == "mtls":
        if not auth.identity.cert_fingerprint:
            return rpc_error("denied_unadmitted")
        report["observed_fingerprint"] = auth.identity.cert_fingerprint
    else:
        if auth.identity.pid is None:
            return rpc_error("denied_unadmitted")
        report["observed_peer_pid"] = auth.identity.pid
    upstream = call_rpc(
        state.keeper_addr,
        "ResolveUseGrant",
        report,
        transport=state.transport,
        cert=state.cert,
        key=state.key,
        ca=state.ca,
        expect_server_role="keeper-core",
    )
    if not upstream.get("ok"):
        return rpc_error(str(upstream.get("code", "denied_grant")))
    if upstream["body"].get("operation_id") != body["operation_id"]:
        return rpc_error("denied_payload")
    _record_fill_context(state, body)
    return rpc_ok({"operation_id": body["operation_id"], "fill": state.secret})


def report_outcome(
    state: ServerState, auth: AuthContext, body: Dict[str, Any]
) -> Dict[str, Any]:
    """Record a fill outcome. The fill value is not accepted here."""
    if "fill" in body or auth.identity is None:
        return rpc_error("denied_payload")
    operation_id = body.get("operation_id")
    outcome = body.get("outcome")
    if not isinstance(operation_id, str) or outcome not in {"filled", "refused"}:
        return rpc_error("denied_payload")
    path = state.state / "outcomes.jsonl"
    line = json.dumps(
        {
            "operation_id": operation_id,
            "outcome": outcome,
            "recipient_instance": auth.identity.instance_id,
            "recipient_boot": auth.identity.boot_id,
        },
        sort_keys=True,
    )
    with state._lock:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        os.chmod(path, 0o600)
    return rpc_ok({"operation_id": operation_id})


def admit_workload(
    state: ServerState, _auth: AuthContext, body: Dict[str, Any]
) -> Dict[str, Any]:
    """Admit one scoped instance with a one-use bootstrap token.

    The token does not choose the role. The pending scope file, written by
    the launcher, is the only admission this method can perform.
    """
    token = body.get("bootstrap_token")
    admit_role = body.get("admit_role")
    admit_instance = body.get("admit_instance_id")
    admit_boot = body.get("admit_boot_id")
    if not all(
        isinstance(item, str) and item
        for item in (token, admit_role, admit_instance, admit_boot)
    ):
        return rpc_error("denied_payload")
    scope_path = state.state / "bootstrap-scope.json"
    with state._lock:
        if not scope_path.exists():
            return rpc_error("denied_bootstrap")
        scope = json.loads(scope_path.read_text(encoding="utf-8"))
        if scope.get("used") is True:
            return rpc_error("denied_bootstrap")
        digest = hashlib.sha256(str(token).encode("utf-8")).hexdigest()
        expected = str(scope.get("token_sha256", ""))
        if not expected or not hmac.compare_digest(digest, expected):
            return rpc_error("denied_bootstrap")
        if (
            admit_role != scope.get("admit_role")
            or admit_instance != scope.get("admit_instance_id")
            or admit_boot != scope.get("admit_boot_id")
        ):
            return rpc_error("denied_bootstrap")
        registry = load_registry(state.registry_path)
        registry.workloads.append(
            {
                "role": admit_role,
                "instance_id": admit_instance,
                "boot_id": admit_boot,
                "cert_fingerprint": None,
                "pid": None,
            }
        )
        save_registry(state.registry_path, registry)
        scope["used"] = True
        tmp = scope_path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(scope, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.chmod(tmp, 0o600)
        os.replace(tmp, scope_path)
    return rpc_ok({"instance_id": admit_instance})


METHODS: Dict[tuple[str, str], HandlerFn] = {
    ("keeper-core", "PrepareUse"): prepare_use,
    ("keeper-core", "ResolveUseGrant"): resolve_use_grant,
    ("keeper-core", "ReportOutcome"): report_outcome,
    ("keeper-core", "AdmitWorkload"): admit_workload,
    ("credential-broker", "CompleteFill"): complete_fill,
}


def _observed(state: ServerState, body: Dict[str, Any]) -> Any:
    registry = load_registry(state.registry_path)
    fingerprint = body.get("observed_fingerprint")
    pid = body.get("observed_peer_pid")
    if isinstance(fingerprint, str) and fingerprint:
        return registry.find_fingerprint(fingerprint)
    if isinstance(pid, int) and not isinstance(pid, bool):
        return registry.find_pid(pid)
    return None


def _fields_ok(body: Dict[str, Any]) -> bool:
    for value in body.values():
        if isinstance(value, str) and len(value) > MAX_FIELD:
            return False
        if isinstance(value, (dict, list)):
            return False
    return True


def _record_fill_context(state: ServerState, body: Dict[str, Any]) -> None:
    path = state.state / "fill-context.jsonl"
    line = json.dumps(
        {
            "operation_id": body["operation_id"],
            "origin": body["origin"],
            "frame_id": body["frame_id"],
            "navigation_generation": body["navigation_generation"],
        },
        sort_keys=True,
    )
    with state._lock:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        os.chmod(path, 0o600)
