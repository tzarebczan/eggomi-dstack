"""Vsock adapter interface.

This slice does not open ``AF_VSOCK``. Callers that need a cross-compartment
path use :func:`placeholder`, which is a byte-forwarder labeled with a CID
and port. The label is routing, not identity.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from .forward import Forwarder, start_forwarder


class VsockUnavailable(RuntimeError):
    """AF_VSOCK is not used in this slice."""


def open_vsock(cid: int, port: int) -> None:
    """Refuse to open a real vsock socket.

    Nested smolvm and guest vsock plumbing are deferred. Tests that need the
    byte path call :func:`placeholder` instead.
    """
    raise VsockUnavailable(
        f"AF_VSOCK cid {cid} port {port} is not opened; use the byte-forward placeholder"
    )


def placeholder(cid: int, port: int, upstream: str) -> Forwarder:
    """Start a byte-forwarder recorded as vsock ``cid:port``.

    The CID and port are not passed to the kernel. TLS, when used, ends at
    ``upstream``.
    """
    if cid < 0 or not 0 < port < 65536:
        raise ValueError(
            "vsock placeholder needs a non-negative cid and a tcp-range port"
        )
    forwarder = start_forwarder(upstream)
    forwarder.label = f"vsock:{cid}:{port}"
    return forwarder
