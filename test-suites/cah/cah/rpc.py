"""RPC client and the authenticated server loop."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import socket
import ssl
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .auth import AuthContext, authenticate_mtls, authenticate_unix, server_spiffe_role
from .forward import connect, parse_address
from .frame import FrameError, read_frame, write_frame

Handler = Callable[[AuthContext, str, Dict[str, Any]], Dict[str, Any]]


def rpc_ok(body: Dict[str, Any]) -> Dict[str, Any]:
    """Build a successful RPC response."""
    return {"ok": True, "code": "ok", "body": body}


def rpc_error(code: str) -> Dict[str, Any]:
    """Build a refusal. The body stays empty so secrets cannot leak."""
    return {"ok": False, "code": code, "body": {}}


def call_rpc(
    address: str,
    method: str,
    body: Dict[str, Any],
    *,
    transport: str,
    cert: Optional[Path] = None,
    key: Optional[Path] = None,
    ca: Optional[Path] = None,
    expect_server_role: Optional[str] = None,
    timeout: float = 5,
) -> Dict[str, Any]:
    """Send one request and return the response object."""
    sock = connect(address, timeout=timeout)
    try:
        if transport == "mtls":
            if cert is None or key is None or ca is None or expect_server_role is None:
                raise RuntimeError("mtls client is missing certificate material")
            sock = _wrap_client(sock, cert, key, ca, expect_server_role)
        elif transport != "unix":
            raise RuntimeError("transport must be unix or mtls")
        write_frame(sock, {"method": method, "body": body})
        response = read_frame(sock)
    finally:
        sock.close()
    if not isinstance(response.get("code"), str) or not isinstance(
        response.get("body"), dict
    ):
        raise RuntimeError("rpc response is missing code or body")
    return response


def serve(
    address: str,
    transport: str,
    registry_path: Path,
    handler: Handler,
    stop_file: Path,
    *,
    role: str,
    cert: Optional[Path] = None,
    key: Optional[Path] = None,
    ca: Optional[Path] = None,
) -> None:
    """Accept connections until ``stop_file`` appears.

    ``tcp:127.0.0.1:0`` binds an ephemeral port. The bound address is written
    to ``ready/<role>`` beside the stop file.
    """
    listen_sock, bound = _bind(address)
    ready = stop_file.parent / "ready" / role
    ready.parent.mkdir(parents=True, exist_ok=True)
    ready.write_text(bound + "\n", encoding="utf-8")
    print(f"[cah] {role} listening on {bound}", flush=True)
    listen_sock.settimeout(0.2)
    while not stop_file.exists():
        try:
            conn, _peer = listen_sock.accept()
        except TimeoutError:
            continue
        except OSError:
            break
        threading.Thread(
            target=_handle,
            args=(conn, transport, registry_path, handler, cert, key, ca),
            daemon=True,
        ).start()
    listen_sock.close()


def _handle(
    conn: socket.socket,
    transport: str,
    registry_path: Path,
    handler: Handler,
    cert: Optional[Path],
    key: Optional[Path],
    ca: Optional[Path],
) -> None:
    try:
        conn.settimeout(5)
        if transport == "mtls":
            if cert is None or key is None or ca is None:
                raise RuntimeError("mtls server is missing certificate material")
            conn = _wrap_server(conn, cert, key, ca)
            auth = authenticate_mtls(conn, registry_path)
        else:
            auth = authenticate_unix(conn, registry_path)
        request = read_frame(conn)
        method = request.get("method")
        body = request.get("body")
        if not isinstance(method, str) or not isinstance(body, dict):
            response = rpc_error("denied_payload")
        else:
            response = handler(auth, method, body)
        write_frame(conn, response)
    except (FrameError, OSError, ssl.SSLError, RuntimeError):
        print("[cah] request failed", flush=True)
    finally:
        conn.close()


def _bind(address: str) -> tuple[socket.socket, str]:
    parsed = parse_address(address)
    if isinstance(parsed, str):
        path = Path(parsed)
        if path.exists():
            path.unlink()
        path.parent.mkdir(parents=True, exist_ok=True)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(parsed)
        path.chmod(0o600)
        bound = address
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(parsed)
        host, port = sock.getsockname()
        bound = f"tcp:{host}:{port}"
    sock.listen(32)
    return sock, bound


def _wrap_server(conn: socket.socket, cert: Path, key: Path, ca: Path) -> ssl.SSLSocket:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.options |= ssl.OP_NO_TICKET
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    ctx.load_verify_locations(cafile=str(ca))
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx.wrap_socket(conn, server_side=True)


def _wrap_client(
    conn: socket.socket,
    cert: Path,
    key: Path,
    ca: Path,
    expect_server_role: str,
) -> ssl.SSLSocket:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.options |= ssl.OP_NO_TICKET
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    ctx.load_verify_locations(cafile=str(ca))
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Identity is the SPIFFE URI, not a DNS name. Hostname checks would reject
    # these lab certificates, so the URI role is checked immediately below.
    ctx.check_hostname = False
    wrapped = ctx.wrap_socket(conn, server_side=False, server_hostname="cah.lab")
    role = server_spiffe_role(wrapped)
    if role != expect_server_role:
        wrapped.close()
        raise RuntimeError("server certificate role does not match the callee")
    return wrapped


def chmod_private(path: Path) -> None:
    """Restrict a state file to the current user."""
    os.chmod(path, 0o600)
