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
    r"/service/(?P<role>[^/]+)/instance/(?P<instance>[^/]+)$"
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
    """Admit the peer only when its pid is in the launcher registry."""
    pid, uid, _gid = _peercred(conn)
    if uid != os.getuid():
        return AuthContext("unix-peercred", False, "denied_unadmitted", None)
    registry = load_registry(registry_path)
    identity = registry.find_pid(pid)
    if identity is None:
        return AuthContext("unix-peercred", False, "denied_unadmitted", None)
    return AuthContext("unix-peercred", True, None, identity)


def authenticate_mtls(conn: ssl.SSLSocket, registry_path: Path) -> AuthContext:
    """Admit the peer only when its cert fingerprint is in the registry.

    The SPIFFE URI must match that row. The certificate subject CN is ignored.
    A certificate that chains to the lab root is still refused when the
    fingerprint was never admitted.
    """
    der = conn.getpeercert(binary_form=True)
    if not isinstance(der, bytes):
        return AuthContext("mtls", False, "denied_unadmitted", None)
    fingerprint = hashlib.sha256(der).hexdigest()
    uri = _spiffe_uri(conn)
    if uri is None:
        return AuthContext("mtls", False, "denied_unadmitted", None)
    registry = load_registry(registry_path)
    identity = registry.find_fingerprint(fingerprint)
    if identity is None:
        return AuthContext("mtls", False, "denied_unadmitted", None)
    if (
        uri["role"] != identity.role
        or uri["instance"] != identity.instance_id
        or uri["tenant"] != identity.tenant
        or uri["domain"] != identity.trust_domain
    ):
        return AuthContext("mtls", False, "denied_unadmitted", None)
    return AuthContext("mtls", True, None, identity)


def server_spiffe_role(conn: ssl.SSLSocket) -> Optional[str]:
    """Return the server certificate's SPIFFE role, if the URI is well formed."""
    uri = _spiffe_uri(conn)
    if uri is None:
        return None
    return uri["role"]


def fingerprint_pem(path: Path) -> str:
    """SHA-256 fingerprint of a PEM certificate, hex encoded."""
    der = ssl.PEM_cert_to_DER_cert(path.read_text(encoding="utf-8"))
    return hashlib.sha256(der).hexdigest()


def _spiffe_uri(conn: ssl.SSLSocket) -> Optional[dict[str, str]]:
    cert = conn.getpeercert()
    if not isinstance(cert, dict):
        return None
    names = cert.get("subjectAltName") or ()
    for kind, value in names:
        if kind != "URI":
            continue
        match = SPIFFE_RE.match(value)
        if match:
            return match.groupdict()
    return None


def _peercred(conn: socket.socket) -> Tuple[int, int, int]:
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return pid, uid, gid
