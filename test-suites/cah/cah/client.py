"""One-shot compartment client.

The process waits until the launcher admits its pid, then performs a single
RPC. It does not put its role or boot id in the request body. A fill opens
the sealed answer with the guard's own lease, not with fields from the broker.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .crypto_lab import generate_private, public_key
from .guard import GuardStore
from .registry import load_registry
from .rpc import call_rpc
from .seal import LiveBinding, guard_proof, proof_transcript


def main(argv: list[str] | None = None) -> int:
    """Run the named client case and write its response code."""
    parser = argparse.ArgumentParser(description="CAH compartment client")
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--case", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--transport", choices=("unix", "mtls"), required=True)
    parser.add_argument("--keeper", required=True)
    parser.add_argument("--broker", required=True)
    parser.add_argument("--connector", required=True)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--grant-file", type=Path)
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--ca", type=Path)
    parser.add_argument("--unadmitted-cert", action="store_true")
    parser.add_argument("--expect-domain", default="")
    parser.add_argument("--expect-tenant", default="")
    parser.add_argument("--keeper-instance", default="")
    parser.add_argument("--keeper-fp", default="")
    parser.add_argument("--broker-instance", default="")
    parser.add_argument("--broker-fp", default="")
    parser.add_argument("--connector-instance", default="")
    parser.add_argument("--connector-fp", default="")
    args = parser.parse_args(argv)
    if args.mode == "agent":
        return _agent(args)
    if not args.unadmitted_cert:
        _wait_go(args.state)
    elif args.transport == "unix":
        _wait_go(args.state)
    fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
    try:
        started = time.perf_counter()
        response = _call(args, fixture)
        elapsed = time.perf_counter() - started
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: client {args.case} failed: {exc}", file=sys.stderr)
        return 1
    _write_result(args, response, elapsed)
    return 0


def _wait_go(state: Path) -> None:
    deadline = time.monotonic() + 5
    flag = state / "go" / str(os.getpid())
    while time.monotonic() < deadline:
        if flag.exists():
            return
        time.sleep(0.02)
    raise RuntimeError("launcher did not admit this client")


def _agent(args: argparse.Namespace) -> int:
    """Serve commands for one bound process until ``quit``."""
    _wait_go(args.state)
    inbox = args.state / "inbox" / f"{os.getpid()}.json"
    while True:
        spec = _wait_json(inbox)
        if spec.get("mode") == "quit":
            return 0
        fixture = spec["fixture"]
        if spec.get("grant_ref"):
            grant_path = args.state / "fixtures" / f"{spec['case']}.grant"
            grant_path.parent.mkdir(parents=True, exist_ok=True)
            grant_path.write_text(str(spec["grant_ref"]) + "\n", encoding="utf-8")
            args.grant_file = grant_path
        args.mode = str(spec["mode"])
        args.case = str(spec["case"])
        try:
            started = time.perf_counter()
            response = _call(args, fixture)
            elapsed = time.perf_counter() - started
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"error: client {args.case} failed: {exc}", file=sys.stderr)
            return 1
        _write_result(args, response, elapsed)
        done = args.state / "done" / f"{os.getpid()}"
        done.parent.mkdir(parents=True, exist_ok=True)
        done.write_text(args.case + "\n", encoding="utf-8")


def _wait_json(path: Path) -> Dict[str, Any]:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if path.exists():
            payload = json.loads(path.read_text(encoding="utf-8"))
            path.unlink()
            if isinstance(payload, dict):
                return payload
            break
        time.sleep(0.02)
    raise RuntimeError("launcher did not send a command")


def _write_result(
    args: argparse.Namespace, response: Dict[str, Any], elapsed: float
) -> None:
    result: Dict[str, Any] = {
        "code": response["code"],
        "ok": bool(response["ok"]),
        "seconds": elapsed,
        "operation_id": response["body"].get("operation_id"),
        "grant_ref": response["body"].get("grant_ref"),
    }
    fill = response["body"].get("fill")
    if isinstance(fill, str):
        result["fill"] = fill
    out = args.state / "results" / f"{args.case}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.chmod(out, 0o600)
    print(f"[cah] case {args.case} {response['code']}", flush=True)


def _call(args: argparse.Namespace, fixture: Dict[str, Any]) -> Dict[str, Any]:
    mode = args.mode
    if mode == "prepare":
        return _rpc(args, args.keeper, "keeper-core", "PrepareUse", _prepare_body(fixture))
    if mode == "smuggle":
        body = _prepare_body(fixture)
        body["role"] = "browser-guard"
        return _rpc(args, args.keeper, "keeper-core", "PrepareUse", body)
    if mode == "steal":
        grant_ref = args.grant_file.read_text(encoding="utf-8").strip()
        return _rpc(
            args,
            args.broker,
            "credential-broker",
            "CompleteFill",
            {
                "grant_ref": grant_ref,
                "operation_id": fixture["operation_id"],
                "origin": fixture["origin"],
                "frame_id": fixture["frame_id"],
                "navigation_generation": fixture["navigation_generation"],
            },
        )
    if mode == "fill":
        return _fill(args, fixture)
    if mode == "outcome":
        return _rpc(
            args,
            args.keeper,
            "keeper-core",
            "ReportOutcome",
            {"operation_id": fixture["operation_id"], "outcome": "filled"},
        )
    if mode == "poke":
        return _rpc(args, args.connector, "connector", "Health", {})
    raise RuntimeError(f"unknown client mode {mode}")


def _prepare_body(fixture: Dict[str, Any]) -> Dict[str, Any]:
    keys = (
        "operation_id",
        "task_id",
        "lease_id",
        "lease_epoch",
        "policy_revision",
        "resource_handle",
        "origin",
        "recipient_instance_id",
        "tenant",
        "audience_role",
        "audience_instance",
        "field",
    )
    return {key: fixture[key] for key in keys}


def _fill(args: argparse.Namespace, fixture: Dict[str, Any]) -> Dict[str, Any]:
    """Prove the lease key, then open the sealed answer locally."""
    private = _load_private(args.state, args.instance)
    grant_ref = args.grant_file.read_text(encoding="utf-8").strip()
    challenge = generate_private()
    challenge_mono = time.monotonic()
    guard_public = public_key(private)
    transcript = proof_transcript(
        grant_ref=grant_ref,
        origin=str(fixture["origin"]),
        operation_id=str(fixture["operation_id"]),
        frame_id=str(fixture["frame_id"]),
        navigation_generation=str(fixture["navigation_generation"]),
        challenge=challenge,
        guard_public=guard_public,
        field=str(fixture["field"]),
        tenant=str(fixture["tenant"]),
    )
    keeper_public = _role_public(args.state / "admission.json", "keeper-core")
    proof = guard_proof(private, keeper_public, transcript)
    response = _rpc(
        args,
        args.broker,
        "credential-broker",
        "CompleteFill",
        {
            "grant_ref": grant_ref,
            "operation_id": fixture["operation_id"],
            "origin": fixture["origin"],
            "frame_id": fixture["frame_id"],
            "navigation_generation": fixture["navigation_generation"],
            "guard_public": guard_public.hex(),
            "proof": proof.hex(),
            "challenge": challenge.hex(),
            "field": fixture["field"],
            "tenant": fixture["tenant"],
        },
    )
    if not response.get("ok"):
        return response
    sealed = response["body"].get("sealed")
    if not isinstance(sealed, dict):
        return {"ok": False, "code": "denied_payload", "body": {}}
    opened = _open_sealed(args, fixture, sealed, challenge, challenge_mono)
    if not opened.get("ok"):
        return {"ok": False, "code": str(opened.get("code")), "body": {}}
    return {
        "ok": True,
        "code": "ok",
        "body": {
            "operation_id": fixture["operation_id"],
            "fill": opened.get("fill"),
        },
    }


def _open_sealed(
    args: argparse.Namespace,
    fixture: Dict[str, Any],
    sealed: Dict[str, Any],
    challenge: bytes,
    challenge_mono: float,
) -> Dict[str, Any]:
    registry_path = args.state / "admission.json"
    registry = load_registry(registry_path)
    me = registry.find_instance(args.instance)
    if me is None:
        return {"ok": False, "code": "denied_unadmitted"}
    lease_path = args.state / "roles" / args.instance / "lease.json"
    lease = json.loads(lease_path.read_text(encoding="utf-8"))
    live = LiveBinding(
        tenant=str(lease["tenant"]),
        audience=_role_public(registry_path, "credential-broker").hex(),
        recipient_instance=me.instance_id,
        recipient_boot_generation=me.boot_generation,
        origin=str(fixture["origin"]),
        field=str(lease["field"]),
        frame_id=str(fixture["frame_id"]),
        navigation_generation=str(fixture["navigation_generation"]),
        fence=str(lease["fence"]),
        epoch=int(lease["epoch"]),
        requester_instance=str(fixture["requester_instance"]),
        task_id=str(fixture["task_id"]),
        operation_id=str(fixture["operation_id"]),
        resource_handle=str(fixture["resource_handle"]),
        challenge=challenge,
        challenge_mono=challenge_mono,
    )
    store = GuardStore(
        args.state / "fence" / args.instance,
        args.state / "roles" / args.instance / "channel.key.wrapped",
    )
    return store.accept(sealed, live)


def _load_private(state: Path, instance: str) -> bytes:
    role = state / "roles" / instance
    raw_path = role / "channel.key"
    if raw_path.exists():
        raw = raw_path.read_bytes()
        if len(raw) != 32:
            raise RuntimeError("channel key is not 32 bytes")
        return raw
    wrapped = role / "channel.key.wrapped"
    if wrapped.exists():
        return GuardStore(state / "fence" / instance, wrapped).lease_private()
    raise RuntimeError("channel key is missing")


def _role_public(registry_path: Path, role: str) -> bytes:
    registry = load_registry(registry_path)
    for row in registry.workloads:
        public = row.get("channel_public")
        if row.get("role") == role and isinstance(public, str) and public:
            return bytes.fromhex(public)
    raise RuntimeError(f"no channel key for {role}")


def _rpc(
    args: argparse.Namespace,
    address: str,
    server_role: str,
    method: str,
    body: Dict[str, Any],
) -> Dict[str, Any]:
    cert: Optional[Path] = args.cert
    key: Optional[Path] = args.key
    ca: Optional[Path] = args.ca
    expect = None
    channel_private = None
    registry_path = None
    peer_role = None
    if args.transport == "mtls":
        pins = {
            "keeper-core": (args.keeper_instance, args.keeper_fp),
            "credential-broker": (args.broker_instance, args.broker_fp),
            "connector": (args.connector_instance, args.connector_fp),
        }
        instance, fingerprint = pins[server_role]
        expect = {
            "domain": args.expect_domain,
            "tenant": args.expect_tenant,
            "role": server_role,
            "instance": instance,
            "fingerprint": fingerprint,
        }
    else:
        channel_private = _load_private(args.state, args.instance)
        registry_path = args.state / "admission.json"
        peer_role = server_role
    return call_rpc(
        address,
        method,
        body,
        transport=args.transport,
        cert=cert,
        key=key,
        ca=ca,
        expect_server=expect,
        expect_server_role=server_role if args.transport == "mtls" else None,
        channel_private=channel_private,
        registry_path=registry_path,
        peer_role=peer_role,
    )


if __name__ == "__main__":
    raise SystemExit(main())
