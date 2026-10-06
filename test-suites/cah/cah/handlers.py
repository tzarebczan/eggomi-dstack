"""Compartment methods for the Eggomi profile.

keeper-core stores use-grants and seals one credential per approved use.
credential-broker forwards that sealed answer and holds no standing secret.
The launcher writes admission; keeper-core only reads the registry.
``observed_*`` fields are not authority.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .access import AccessGraph
from .auth import AUTHORITY_FIELDS, AuthContext
from .channel import parse_public
from .grants import GrantStore
from .policy import evaluate_prepare, load_current
from .registry import WorkloadIdentity, load_registry
from .rpc import call_rpc, rpc_error, rpc_ok
from .seal import proof_matches, proof_transcript, seal_credential

MAX_FIELD = 8192
MAX_SEAL_MS = 30_000
HandlerFn = Callable[["ServerState", AuthContext, Dict[str, Any]], Dict[str, Any]]
_OUTCOMES = frozenset({"filled", "refused", "unknown"})


@dataclass
class ServerState:
    """Process-wide state for one compartment server."""

    role: str
    state: Path
    transport: str
    access: AccessGraph
    registry_path: Path
    grants: Optional[GrantStore]
    keeper_addr: Optional[str]
    cert: Optional[Path]
    key: Optional[Path]
    ca: Optional[Path]
    grant_ttl: float
    policy_dir: Optional[Path]
    resource_handle: Optional[str]
    expect_server: Optional[Dict[str, str]]
    authority: Path
    channel_private: Optional[bytes]
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
    """Issue an opaque use-grant for the keeper policy's recipient.

    The current policy revision is loaded from disk on this call. Origin,
    handle, lease, audience, field, tenant, and destination come from that
    revision. The requester's copy of those fields must match.
    """
    if state.grants is None or auth.identity is None or state.policy_dir is None:
        return rpc_error("denied_payload")
    try:
        policy = load_current(state.policy_dir)
    except (OSError, ValueError, json.JSONDecodeError):
        return rpc_error("denied_payload")
    prepared = evaluate_prepare(policy, body)
    if prepared is None:
        return rpc_error("denied_payload")
    registry = load_registry(state.registry_path)
    recipient = registry.find_instance(prepared.recipient_instance_id)
    if recipient is None or recipient.role != "browser-guard":
        return rpc_error("denied_recipient")
    if not _recipient_ready(recipient, state.transport):
        return rpc_error("denied_recipient")
    audience = registry.find_instance(prepared.audience_instance)
    if (
        audience is None
        or audience.role != prepared.audience_role
        or not audience.channel_public
    ):
        return rpc_error("denied_recipient")
    try:
        record = state.grants.issue(
            requester=auth.identity,
            recipient=recipient,
            policy_revision=prepared.policy_revision,
            resource_handle=prepared.resource_handle,
            origin=prepared.origin,
            task_id=prepared.task_id,
            operation_id=prepared.operation_id,
            lease_id=prepared.lease_id,
            lease_epoch=prepared.lease_epoch,
            ttl_seconds=state.grant_ttl,
            frame_id=prepared.frame_id,
            navigation_generation=prepared.navigation_generation,
            audience_role=prepared.audience_role,
            audience_instance=prepared.audience_instance,
            audience_key=audience.channel_public,
            field=prepared.field,
            tenant=prepared.tenant,
            fence=prepared.fence,
        )
    except ValueError:
        return rpc_error("denied_payload")
    return rpc_ok(
        {"grant_ref": record["grant_ref"], "operation_id": prepared.operation_id}
    )


def resolve_use_grant(
    state: ServerState, auth: AuthContext, body: Dict[str, Any]
) -> Dict[str, Any]:
    """Seal one credential for the guard that proved the lease key.

    The presenter is the registry row for ``guard_public`` after the
    possession proof checks. Body fields named ``observed_*`` are refused
    by dispatch and are not read here.
    """
    if state.grants is None or auth.identity is None or state.channel_private is None:
        return rpc_error("denied_payload")
    parsed = _resolve_body(body)
    if parsed is None:
        return rpc_error("denied_payload")
    try:
        guard_public = parse_public(parsed["guard_public"])
        proof = bytes.fromhex(parsed["proof"])
        challenge = bytes.fromhex(parsed["challenge"])
    except ValueError:
        return rpc_error("denied_payload")
    if len(proof) != 32 or len(challenge) != 32:
        return rpc_error("denied_payload")
    transcript = proof_transcript(
        grant_ref=parsed["grant_ref"],
        origin=parsed["origin"],
        operation_id=parsed["operation_id"],
        frame_id=parsed["frame_id"],
        navigation_generation=parsed["navigation_generation"],
        challenge=challenge,
        guard_public=guard_public,
        field=parsed["field"],
        tenant=parsed["tenant"],
    )
    if not proof_matches(state.channel_private, guard_public, transcript, proof):
        return rpc_error("denied_recipient")
    presenter = load_registry(state.registry_path).find_channel(parsed["guard_public"])
    if presenter is None:
        return rpc_error("denied_recipient")
    preview = state.grants.get(parsed["grant_ref"])
    if preview is not None:
        audience = preview.get("audience")
        if isinstance(audience, dict) and audience.get("channel_public"):
            if auth.identity.channel_public != audience.get("channel_public"):
                return rpc_error("denied_role")
    result = state.grants.resolve(
        parsed["grant_ref"],
        presenter,
        parsed["origin"],
        parsed["operation_id"],
        parsed["frame_id"],
        parsed["navigation_generation"],
        broker_instance=auth.identity.instance_id,
        field=parsed["field"],
        tenant=parsed["tenant"],
    )
    if not result["ok"]:
        return rpc_error(str(result["code"]))
    grant = state.grants.get(parsed["grant_ref"])
    secret = _fill_secret(state)
    if grant is None or secret is None or not presenter.channel_public:
        return rpc_error("denied_payload")
    try:
        sealed = _seal_grant(grant, secret, challenge, presenter.channel_public)
    except ValueError:
        return rpc_error("denied_payload")
    return rpc_ok(
        {
            "operation_id": result["operation_id"],
            "resource_handle": result["resource_handle"],
            "sealed": sealed,
        }
    )


def complete_fill(
    state: ServerState, auth: AuthContext, body: Dict[str, Any]
) -> Dict[str, Any]:
    """Forward one sealed answer to the authenticated guard.

    The broker does not hold the credential. It refuses a ``guard_public``
    that is not the channel peer, so a copied proof cannot be relayed.
    """
    if state.keeper_addr is None or auth.identity is None:
        return rpc_error("denied_payload")
    if not auth.identity.channel_public:
        return rpc_error("denied_unadmitted")
    fields = (
        "grant_ref",
        "operation_id",
        "origin",
        "frame_id",
        "navigation_generation",
        "guard_public",
        "proof",
        "challenge",
        "field",
        "tenant",
    )
    if any(not isinstance(body.get(key), str) or not body[key] for key in fields):
        return rpc_error("denied_payload")
    if body["guard_public"] != auth.identity.channel_public:
        return rpc_error("denied_recipient")
    report = {key: body[key] for key in fields}
    upstream = call_rpc(
        state.keeper_addr,
        "ResolveUseGrant",
        report,
        transport=state.transport,
        cert=state.cert,
        key=state.key,
        ca=state.ca,
        expect_server=state.expect_server,
        expect_server_role="keeper-core",
        channel_private=state.channel_private,
        registry_path=state.registry_path,
    )
    if not upstream.get("ok"):
        return rpc_error(str(upstream.get("code", "denied_grant")))
    sealed = upstream["body"].get("sealed")
    if not isinstance(sealed, dict) or sealed.get("grant_ref") != body["grant_ref"]:
        return rpc_error("denied_payload")
    if upstream["body"].get("operation_id") != body["operation_id"]:
        return rpc_error("denied_payload")
    _record_fill_context(state, body)
    return rpc_ok({"operation_id": body["operation_id"], "sealed": sealed})


def report_outcome(
    state: ServerState, auth: AuthContext, body: Dict[str, Any]
) -> Dict[str, Any]:
    """Record a fill outcome. The fill value is not accepted here.

    ``unknown`` is the outcome for a consumed grant whose answer was lost
    between the durable record and the fill.
    """
    if "fill" in body or auth.identity is None:
        return rpc_error("denied_payload")
    operation_id = body.get("operation_id")
    outcome = body.get("outcome")
    if not isinstance(operation_id, str) or outcome not in _OUTCOMES:
        return rpc_error("denied_payload")
    if not _outcome_recipient(state, operation_id, auth.identity):
        return rpc_error("denied_payload")
    _append_outcome(state, operation_id, str(outcome), auth.identity)
    return rpc_ok({"operation_id": operation_id, "outcome": outcome})


def query_outcome(
    state: ServerState, auth: AuthContext, body: Dict[str, Any]
) -> Dict[str, Any]:
    """Return the recorded outcome for one consumed operation.

    A missing report is ``denied_payload``. ``unknown`` is returned as stored.
    """
    if auth.identity is None:
        return rpc_error("denied_payload")
    operation_id = body.get("operation_id")
    if not isinstance(operation_id, str) or not operation_id:
        return rpc_error("denied_payload")
    if not _outcome_recipient(state, operation_id, auth.identity):
        return rpc_error("denied_payload")
    found = _last_outcome(state, operation_id, auth.identity.instance_id)
    if found is None:
        return rpc_error("denied_payload")
    return rpc_ok({"operation_id": operation_id, "outcome": found})


METHODS: Dict[tuple[str, str], HandlerFn] = {
    ("keeper-core", "PrepareUse"): prepare_use,
    ("keeper-core", "ResolveUseGrant"): resolve_use_grant,
    ("keeper-core", "ReportOutcome"): report_outcome,
    ("keeper-core", "QueryOutcome"): query_outcome,
    ("credential-broker", "CompleteFill"): complete_fill,
}


def _resolve_body(body: Dict[str, Any]) -> Optional[Dict[str, str]]:
    fields = (
        "grant_ref",
        "origin",
        "operation_id",
        "frame_id",
        "navigation_generation",
        "guard_public",
        "proof",
        "challenge",
        "field",
        "tenant",
    )
    parsed: Dict[str, str] = {}
    for key in fields:
        value = body.get(key)
        if not isinstance(value, str) or not value:
            return None
        parsed[key] = value
    return parsed


def _seal_grant(
    grant: Dict[str, Any], secret: str, challenge: bytes, lease_public_hex: str
) -> Dict[str, Any]:
    lease = grant["lease"]
    remaining_ms = int((float(lease["expires_unix"]) - time.time()) * 1000)
    offset = min(MAX_SEAL_MS, remaining_ms)
    if offset <= 0:
        raise ValueError("grant has no remaining lifetime")
    audience = grant.get("audience") if isinstance(grant.get("audience"), dict) else {}
    recipient = grant["recipient"]
    return seal_credential(
        parse_public(lease_public_hex),
        secret.encode("utf-8"),
        grant_ref=str(grant["grant_ref"]),
        tenant=str(grant.get("tenant") or ""),
        audience=str(audience.get("channel_public") or ""),
        recipient_instance=str(recipient["instance_id"]),
        recipient_boot_generation=int(recipient["boot_generation"]),
        origin=str(grant["policy"]["origin"]),
        field=str(grant.get("field") or ""),
        frame_id=str(grant["destination_binding"]["frame_binding"]),
        navigation_generation=str(grant["destination_binding"]["document_generation"]),
        fence=str(grant.get("fence") or ""),
        epoch=int(lease["epoch"]),
        expiry_challenge=challenge,
        expiry_offset_ms=offset,
        requester_instance=str(grant["requester"]["instance_id"]),
        task_id=str(grant["task"]["task_id"]),
        operation_id=str(grant["task"]["operation_id"]),
        resource_handle=str(grant["policy"]["resource_handle"]),
    )


def _fill_secret(state: ServerState) -> Optional[str]:
    path = state.authority / "fill-secret"
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return None
    return text


def _recipient_ready(recipient: WorkloadIdentity, transport: str) -> bool:
    if not recipient.channel_public or not recipient.has_possession():
        return False
    if transport == "mtls":
        return bool(recipient.cert_fingerprint)
    return recipient.pid is not None and recipient.starttime is not None


def _fields_ok(body: Dict[str, Any]) -> bool:
    for value in body.values():
        if isinstance(value, str) and len(value) > MAX_FIELD:
            return False
        if isinstance(value, (dict, list)):
            return False
    return True


def _outcome_recipient(
    state: ServerState, operation_id: str, identity: WorkloadIdentity
) -> bool:
    if state.grants is None:
        return False
    grant = state.grants.find_operation(operation_id)
    if grant is None or grant["disposition"] != "consumed":
        return False
    return grant["recipient"]["instance_id"] == identity.instance_id


def _append_outcome(
    state: ServerState, operation_id: str, outcome: str, identity: WorkloadIdentity
) -> None:
    path = state.state / "outcomes.jsonl"
    line = json.dumps(
        {
            "operation_id": operation_id,
            "outcome": outcome,
            "recipient_instance": identity.instance_id,
            "recipient_boot": identity.boot_id,
        },
        sort_keys=True,
    )
    with state._lock:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)


def _last_outcome(
    state: ServerState, operation_id: str, instance_id: str
) -> Optional[str]:
    path = state.state / "outcomes.jsonl"
    if not path.exists():
        return None
    found = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if (
            row.get("operation_id") == operation_id
            and row.get("recipient_instance") == instance_id
            and row.get("outcome") in _OUTCOMES
        ):
            found = str(row["outcome"])
    return found


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
