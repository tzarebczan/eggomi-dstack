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
from .grants import GrantStore
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
    args = parser.parse_args(argv)
    secret = None
    if args.role == "credential-broker":
        secret = sys.stdin.readline().rstrip("\n")
        if not secret:
            print("error: missing fill secret on stdin", file=sys.stderr)
            return 1
    state_dir = args.state
    registry_path = state_dir / "admission.json"
    grants = (
        GrantStore(state_dir / "grants.json") if args.role == "keeper-core" else None
    )
    server_state = ServerState(
        role=args.role,
        state=state_dir,
        transport=args.transport,
        access=load_access(args.access),
        registry_path=registry_path,
        grants=grants,
        secret=secret,
        keeper_addr=args.keeper or None,
        cert=args.cert,
        key=args.key,
        ca=args.ca,
        grant_ttl=args.grant_ttl,
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
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
