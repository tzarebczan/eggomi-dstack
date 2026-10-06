"""Map a transport peer into one authorization context.

Unix admission uses ``SO_PEERPIDFD`` (Linux 6.5+). There is no fallback to
``SO_PEERCRED`` plus ``/proc``. pid and start time only gate channel setup.
The keyed channel then proves the workload's registered key. Certificate CN
and RPC body fields are not identity. The uid check still refuses a peer
whose uid is not the server uid.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import errno
import hashlib
import os
import re
import select
import socket
import ssl
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from .registry import WorkloadIdentity, load_registry, process_starttime

# Linux 6.5 ``asm-generic/socket.h``. CPython does not export this name.
SO_PEERPIDFD = 77

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
        "observed_fingerprint",
        "observed_peer_pid",
        "observed_starttime",
        "observed_role",
    }
)


class PidfdUnavailable(OSError):
    """This kernel or socket cannot return ``SO_PEERPIDFD``."""


@dataclass(frozen=True)
class AuthContext:
    """Identity supplied by the transport, plus whether it is admitted."""

    transport: str
    admitted: bool
    denial_code: Optional[str]
    identity: Optional[WorkloadIdentity]


def authenticate_unix(conn: socket.socket, registry_path: Path) -> AuthContext:
    """Admit the connector only when its pidfd is alive and the pid is bound.

    The pid comes from ``SO_PEERPIDFD`` and ``/proc/self/fdinfo``. Start time
    is field 22 of ``/proc/<pid>/stat``, read only after the pidfd is still
    alive, so a reused pid cannot match. Failure of the pidfd option refuses
    the peer.
    """
    try:
        pidfd = open_peer_pidfd(conn)
    except PidfdUnavailable:
        return AuthContext("unix-pidfd", False, "denied_unadmitted", None)
    try:
        return _authenticate_pidfd(pidfd, registry_path)
    finally:
        os.close(pidfd)


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


def open_peer_pidfd(conn: socket.socket) -> int:
    """Return a pidfd for the process that connected ``conn``.

    The caller must close the descriptor. ``SO_PEERCRED`` is not consulted.
    """
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4)
    except OSError as exc:
        if exc.errno in {errno.ENOPROTOOPT, errno.EOPNOTSUPP, errno.EINVAL}:
            raise PidfdUnavailable("SO_PEERPIDFD is not available") from exc
        raise
    if len(raw) != 4:
        raise PidfdUnavailable("SO_PEERPIDFD returned a short value")
    (pidfd,) = struct.unpack("i", raw)
    if pidfd < 0:
        raise PidfdUnavailable("SO_PEERPIDFD returned a negative descriptor")
    return pidfd


def pidfd_alive(pidfd: int) -> bool:
    """Return whether ``pidfd`` still refers to a running process.

    A pidfd becomes readable when its process exits. That is the check that
    the start time read afterwards still belongs to this process.
    """
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    return not poller.poll(0)


def pid_from_pidfd(pidfd: int) -> int:
    """Return the pid recorded in ``/proc/self/fdinfo`` for ``pidfd``."""
    text = Path(f"/proc/self/fdinfo/{pidfd}").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("Pid:"):
            pid = int(line.split()[1])
            if pid > 0:
                return pid
    raise OSError("pidfd has no pid")


def uid_from_status(pid: int) -> int:
    """Return the real uid from ``/proc/<pid>/status``."""
    text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("Uid:"):
            return int(line.split()[1])
    raise OSError("process status has no uid")


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


def _authenticate_pidfd(pidfd: int, registry_path: Path) -> AuthContext:
    denied = AuthContext("unix-pidfd", False, "denied_unadmitted", None)
    try:
        if not pidfd_alive(pidfd):
            return denied
        pid = pid_from_pidfd(pidfd)
        if not pidfd_alive(pidfd):
            return denied
        starttime = process_starttime(pid)
        uid = uid_from_status(pid)
        if not pidfd_alive(pidfd):
            return denied
    except OSError:
        return denied
    if uid != os.geteuid():
        return denied
    registry = load_registry(registry_path)
    identity = registry.find_pid(pid)
    if identity is None or identity.starttime != starttime:
        return denied
    if not identity.channel_public and not identity.cert_fingerprint:
        return denied
    return AuthContext("unix-pidfd", True, None, identity)


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
