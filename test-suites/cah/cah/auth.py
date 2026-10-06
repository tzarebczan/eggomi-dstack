"""Map a transport peer into one authorization context.

Unix peer credentials and lab mTLS certificates both become a
``WorkloadIdentity`` looked up in the launcher registry. Certificate CN and
RPC body fields are not identity.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import os
import re
import socket
import ssl
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from .registry import WorkloadIdentity, load_registry

SPIFFE_RE = re.compile(
    r"^spiffe://(?P<domain>[^/]+)/tenant/(?P<tenant>[^/]+)"
    r"/role/(?P<role>[^/]+)/instance/(?P<instance>[^/]+)$"
)

AUTHORITY_FIELDS = frozenset(
    {
        "role",
        "boot_id",
        "instance_id",
        "cert_fingerprint",
        "caller",
        "spiffe_id",
    }
)


@dataclass(frozen=True)
class AuthContext:
    """Identity supplied by the transport, plus whether it is admitted."""

    transport: str
    admitted: bool
    denial_code: Optional[str]
    identity: Optional[WorkloadIdentity]


def authenticate_unix(conn: socket.socket, registry_path: Path) -> AuthContext:
    """Admit the peer only when its pid and start time are in the registry."""
    pid, uid, _gid = _peercred(conn)
    if uid != os.getuid():
        return AuthContext("unix-peercred", False, "denied_unadmitted", None)
    registry = load_registry(registry_path)
    identity = registry.find_pid(pid)
    if identity is None or not identity.has_possession():
        return AuthContext("unix-peercred", False, "denied_unadmitted", None)
    return AuthContext("unix-peercred", True, None, identity)


def authenticate_mtls(conn: ssl.SSLSocket, registry_path: Path) -> AuthContext:
    """Admit the peer only when its cert fingerprint is in the registry.

    Exactly one SPIFFE URI is accepted, and it must match that row. The
    certificate subject CN is ignored. A certificate that chains to the lab
    root is still refused when the fingerprint was never admitted.
    """
    peer = peer_spiffe(conn)
    if peer is None:
        return AuthContext("mtls", False, "denied_unadmitted", None)
    uri, fingerprint = peer
    registry = load_registry(registry_path)
    identity = registry.find_fingerprint(fingerprint)
    if identity is None:
        return AuthContext("mtls", False, "denied_unadmitted", None)
    if not _uri_matches(uri, identity):
        return AuthContext("mtls", False, "denied_unadmitted", None)
    return AuthContext("mtls", True, None, identity)


def peer_spiffe(conn: ssl.SSLSocket) -> Optional[Tuple[dict[str, str], str]]:
    """Return the single SPIFFE URI and the SHA-256 certificate fingerprint.

    Zero URIs or more than one URI is not an identity.
    """
    der = conn.getpeercert(binary_form=True)
    if not isinstance(der, bytes):
        return None
    cert = conn.getpeercert()
    if not isinstance(cert, dict):
        return None
    names = cert.get("subjectAltName") or ()
    uris = [value for kind, value in names if kind == "URI"]
    if len(uris) != 1:
        return None
    match = SPIFFE_RE.match(uris[0])
    if not match:
        return None
    return match.groupdict(), hashlib.sha256(der).hexdigest()


def _uri_matches(uri: dict[str, str], identity: WorkloadIdentity) -> bool:
    return (
        uri["role"] == identity.role
        and uri["instance"] == identity.instance_id
        and uri["tenant"] == identity.tenant
        and uri["domain"] == identity.trust_domain
    )


def fingerprint_pem(path: Path) -> str:
    """SHA-256 fingerprint of a PEM certificate, hex encoded."""
    der = ssl.PEM_cert_to_DER_cert(path.read_text(encoding="utf-8"))
    return hashlib.sha256(der).hexdigest()


def _peercred(conn: socket.socket) -> Tuple[int, int, int]:
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return pid, uid, gid
