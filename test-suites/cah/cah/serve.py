"""Run one compartment server until the launcher writes the stop file."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import sys
import threading
from pathlib import Path
from typing import Any

from .access import load_access
from .auth import AuthContext
from .grants import GrantStore, host_fence_paths
from .handlers import ServerState, dispatch
from .rpc import serve


def main(argv: list[str] | None = None) -> int:
    """Start the server named by ``--role``."""
    parser = argparse.ArgumentParser(description="run one CAH compartment server")
    parser.add_argument("--role", required=True)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--transport", choices=("unix", "mtls"), required=True)
    parser.add_argument("--listen", required=True)
    parser.add_argument("--access", required=True, type=Path)
    parser.add_argument("--keeper", default="")
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--ca", type=Path)
    parser.add_argument("--grant-ttl", type=float, default=30)
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--authority", type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--channel-key", required=True, type=Path)
    parser.add_argument("--resource-handle", default="")
    parser.add_argument("--expect-domain", default="")
    parser.add_argument("--expect-tenant", default="")
    parser.add_argument("--expect-role", default="")
    parser.add_argument("--expect-instance", default="")
    parser.add_argument("--expect-fingerprint", default="")
    args = parser.parse_args(argv)
    try:
        channel_private = _read_channel_key(args.channel_key)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    state_dir = args.state
    authority = args.authority or (state_dir / "authority")
    registry_path = args.registry or (state_dir / "admission.json")
    grants = None
    policy_dir = None
    if args.role == "keeper-core":
        if args.policy is None or not args.policy.is_dir():
            print("error: keeper-core requires a policy directory", file=sys.stderr)
            return 1
        policy_dir = args.policy
        journal_path, epoch_path = host_fence_paths(authority)
        grants = GrantStore(authority / "grants.json", journal_path, epoch_path)
    expect_server = None
    if args.expect_fingerprint:
        expect_server = {
            "domain": args.expect_domain,
            "tenant": args.expect_tenant,
            "role": args.expect_role,
            "instance": args.expect_instance,
            "fingerprint": args.expect_fingerprint,
        }
    server_state = ServerState(
        role=args.role,
        state=state_dir,
        transport=args.transport,
        access=load_access(args.access),
        registry_path=registry_path,
        grants=grants,
        keeper_addr=args.keeper or None,
        cert=args.cert,
        key=args.key,
        ca=args.ca,
        grant_ttl=args.grant_ttl,
        policy_dir=policy_dir,
        resource_handle=args.resource_handle or None,
        expect_server=expect_server,
        authority=authority,
        channel_private=channel_private,
        _lock=threading.Lock(),
    )

    def handler(auth: AuthContext, method: str, body: dict[str, Any]) -> dict[str, Any]:
        return dispatch(server_state, auth, method, body)

    serve(
        args.listen,
        args.transport,
        registry_path,
        handler,
        state_dir / "stop",
        role=args.role,
        cert=args.cert,
        key=args.key,
        ca=args.ca,
        channel_private=channel_private,
    )
    return 0


def _read_channel_key(path: Path) -> bytes:
    raw = path.read_bytes()
    if len(raw) != 32:
        raise ValueError("channel key must be 32 bytes")
    return raw


if __name__ == "__main__":
    raise SystemExit(main())
