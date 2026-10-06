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

from .auth import AuthContext, authenticate_mtls, authenticate_unix, peer_spiffe
from .channel import (
    ChannelError,
    GateDenial,
    client_handshake,
    server_handshake,
    write_gate_denial,
)
from .forward import connect, parse_address
from .frame import FrameError, read_frame, write_frame
from .registry import load_registry

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
    expect_server: Optional[Dict[str, str]] = None,
    channel_private: Optional[bytes] = None,
    registry_path: Optional[Path] = None,
    peer_role: Optional[str] = None,
    peer_instance: Optional[str] = None,
    timeout: float = 5,
) -> Dict[str, Any]:
    """Send one request and return the response object.

    mTLS requires ``expect_server``: trust domain, tenant, role, instance, and
    certificate fingerprint. ``expect_server_role`` is not a substitute. A
    caller that only knows the role is refused before the handshake.

    Unix selects the callee registry row by role and instance. The first row
    with that role is not the pin.
    """
    if transport == "mtls":
        if cert is None or key is None or ca is None:
            raise RuntimeError("mtls client is missing certificate material")
        if not _pin_complete(expect_server):
            raise RuntimeError("mtls client is missing the callee pin")
    elif transport != "unix":
        raise RuntimeError("transport must be unix or mtls")
    unix_role = ""
    unix_instance = ""
    if transport == "unix":
        if channel_private is None or registry_path is None:
            raise RuntimeError("unix client is missing the channel key")
        unix_role, unix_instance = _unix_peer(
            expect_server, peer_role, expect_server_role, peer_instance
        )
    sock = connect(address, timeout=timeout)
    try:
        if transport == "mtls":
            assert cert is not None and key is not None and ca is not None
            assert expect_server is not None
            sock = _wrap_client(sock, cert, key, ca, expect_server)
            write_frame(sock, {"method": method, "body": body})
            response = read_frame(sock)
        else:
            assert registry_path is not None and channel_private is not None
            try:
                session = client_handshake(
                    sock,
                    channel_private,
                    _peer_public(registry_path, unix_role, unix_instance),
                )
            except GateDenial as exc:
                return rpc_error(exc.code)
            session.write({"method": method, "body": body})
            response = session.read()
    except ChannelError as exc:
        raise RuntimeError("keyed channel failed") from exc
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
    channel_private: Optional[bytes] = None,
) -> None:
    """Accept connections until ``stop_file`` appears.

    ``tcp:127.0.0.1:0`` binds an ephemeral port. The bound address is written
    to ``ready/<role>`` beside the stop file.
    """
    listen_sock, bound = _bind(address)
    ready = stop_file.parent / "ready" / role
    _write_ready(ready, bound)
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
            args=(
                conn,
                transport,
                registry_path,
                handler,
                cert,
                key,
                ca,
                channel_private,
            ),
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
    channel_private: Optional[bytes],
) -> None:
    try:
        conn.settimeout(5)
        if transport == "mtls":
            if cert is None or key is None or ca is None:
                raise RuntimeError("mtls server is missing certificate material")
            tls = _wrap_server(conn, cert, key, ca)
            auth = _mtls_with_pidfd(conn, tls, registry_path)
            _exchange_plain(tls, auth, handler)
        else:
            _exchange_unix(conn, registry_path, handler, channel_private)
    except (FrameError, ChannelError, OSError, ssl.SSLError, RuntimeError):
        print("[cah] request failed", flush=True)
    finally:
        conn.close()


def _mtls_with_pidfd(
    raw: socket.socket, tls: ssl.SSLSocket, registry_path: Path
) -> AuthContext:
    """Require the certificate key, and a live pidfd when the socket is Unix.

    ``SO_PEERPIDFD`` is a Unix-socket option. Lab mTLS over TCP uses the
    certificate as the keyed channel. A Unix socket wrapped in TLS still
    has to name the same instance as that certificate.
    """
    auth = authenticate_mtls(tls, registry_path)
    if raw.family != socket.AF_UNIX:
        return auth
    gate = authenticate_unix(raw, registry_path)
    if (
        not gate.admitted
        or not auth.admitted
        or gate.identity is None
        or auth.identity is None
        or gate.identity.instance_id != auth.identity.instance_id
    ):
        return AuthContext("mtls", False, "denied_unadmitted", None)
    return auth


def _exchange_plain(
    conn: socket.socket, auth: AuthContext, handler: Handler
) -> None:
    request = read_frame(conn)
    method = request.get("method")
    body = request.get("body")
    if not isinstance(method, str) or not isinstance(body, dict):
        response = rpc_error("denied_payload")
    else:
        response = handler(auth, method, body)
    write_frame(conn, response)


def _exchange_unix(
    conn: socket.socket,
    registry_path: Path,
    handler: Handler,
    channel_private: Optional[bytes],
) -> None:
    """Gate on the pidfd, then speak only over the keyed channel."""
    auth = authenticate_unix(conn, registry_path)
    if (
        channel_private is None
        or not auth.admitted
        or auth.identity is None
        or not auth.identity.channel_public
    ):
        write_gate_denial(conn, auth.denial_code or "denied_unadmitted")
        _drain(conn)
        return
    session = server_handshake(
        conn, channel_private, bytes.fromhex(auth.identity.channel_public)
    )
    request = session.read()
    method = request.get("method")
    body = request.get("body")
    if not isinstance(method, str) or not isinstance(body, dict):
        response = rpc_error("denied_payload")
    else:
        response = handler(auth, method, body)
    session.write(response)


def _drain(sock: socket.socket) -> None:
    """Read leftover client bytes so a gate denial is not a reset."""
    try:
        sock.settimeout(1)
        while sock.recv(4096):
            continue
    except (TimeoutError, OSError):
        return


def _unix_peer(
    expect_server: Optional[Dict[str, str]],
    peer_role: Optional[str],
    expect_server_role: Optional[str],
    peer_instance: Optional[str],
) -> tuple[str, str]:
    """Resolve the Unix callee to one role and one instance id."""
    role = peer_role or expect_server_role or ""
    instance = peer_instance or ""
    if expect_server is not None:
        pinned_role = expect_server.get("role") or ""
        pinned_instance = expect_server.get("instance") or ""
        if pinned_role and role and pinned_role != role:
            raise RuntimeError("unix client peer role disagrees with the callee pin")
        if pinned_instance and instance and pinned_instance != instance:
            raise RuntimeError("unix client peer instance disagrees with the callee pin")
        role = role or pinned_role
        instance = instance or pinned_instance
    if not role or not instance:
        raise RuntimeError("unix client is missing the peer instance")
    return role, instance


def _peer_public(registry_path: Path, role: str, instance_id: str) -> bytes:
    """Return the channel key for one admitted instance of ``role``."""
    registry = load_registry(registry_path)
    identity = registry.find_instance(instance_id)
    public = identity.channel_public if identity is not None else None
    if (
        identity is None
        or identity.role != role
        or not isinstance(public, str)
        or not public
    ):
        raise RuntimeError(f"no channel key for {role} {instance_id}")
    return bytes.fromhex(public)


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
    expect_server: Dict[str, str],
) -> ssl.SSLSocket:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.options |= ssl.OP_NO_TICKET
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    ctx.load_verify_locations(cafile=str(ca))
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Identity is the SPIFFE URI, not a DNS name. Hostname checks would reject
    # these lab certificates, so the URI is checked immediately below.
    ctx.check_hostname = False
    wrapped = ctx.wrap_socket(conn, server_side=False, server_hostname="cah.lab")
    peer = peer_spiffe(wrapped)
    if peer is None:
        wrapped.close()
        raise RuntimeError("server certificate does not carry one spiffe uri")
    uri, fingerprint = peer
    if (
        uri["domain"] != expect_server["domain"]
        or uri["tenant"] != expect_server["tenant"]
        or uri["role"] != expect_server["role"]
        or uri["instance"] != expect_server["instance"]
        or fingerprint != expect_server["fingerprint"]
    ):
        wrapped.close()
        raise RuntimeError("server certificate does not match the callee pin")
    return wrapped


def _pin_complete(pin: Optional[Dict[str, str]]) -> bool:
    """Return whether ``pin`` names the full callee identity."""
    if pin is None:
        return False
    return all(
        isinstance(pin.get(key), str) and bool(pin[key])
        for key in ("domain", "tenant", "role", "instance", "fingerprint")
    )


def _write_ready(ready: Path, bound: str) -> None:
    """Publish a non-empty ready file in one replace."""
    ready.parent.mkdir(parents=True, exist_ok=True)
    tmp = ready.with_name(ready.name + ".tmp")
    tmp.write_text(bound + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, ready)


def chmod_private(path: Path) -> None:
    """Restrict a state file to the current user."""
    os.chmod(path, 0o600)
