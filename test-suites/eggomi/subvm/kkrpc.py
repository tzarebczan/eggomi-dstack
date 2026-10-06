"""Noise KK request/response over one TCP connection per call.

The keeper channel between smolvm subVMs reuses the CAH compartment channel
(``cah.channel``: ``Noise_KK_25519_ChaChaPoly_SHA256``, prologue
``eggomi/cah-channel/v1``). The keeper knows every admitted peer's static key
before the handshake, so a peer is identified by the key that completes
message 1, never by its address. The relay between subVMs (the outer CVM, or
the host in L2) carries only ciphertext.

This module adds what the CAH stubs do not need: a responder that admits one
of several registered keys, and a one-call client.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import socket
from typing import Any, Dict, Mapping, Optional, Tuple

from cah.channel import (
    HELLO,
    PROLOGUE,
    ChannelError,
    Session,
    client_handshake,
    encode_frame,
    read_frame,
)
from cah.noise import KkResponder, NoiseError


def accept_peer(
    sock: socket.socket, server_private: bytes, peers: Mapping[str, bytes]
) -> Tuple[str, Session]:
    """Complete the responder side for whichever registered peer sent message 1.

    ``peers`` maps a role name to that role's 32-byte static public key. A
    message 1 that no registered key authenticates raises ``ChannelError``
    and nothing is written, so an unregistered caller learns nothing.
    """
    body = read_frame(sock)
    if not body or body[0] != HELLO:
        raise ChannelError("client handshake is not recognized")
    for role, public in peers.items():
        responder = KkResponder(
            prologue=PROLOGUE, static_private=server_private, remote_static=public
        )
        try:
            responder.read_message1(body[1:])
        except NoiseError:
            continue
        message, transport = responder.write_message2()
        sock.sendall(encode_frame(bytes([HELLO]) + message))
        return role, Session(sock, transport)
    raise ChannelError("no registered peer key authenticates message 1")


def call(
    address: Tuple[str, int],
    client_private: bytes,
    server_public: bytes,
    method: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """Open a channel, send one request, and return the decoded response.

    The response is ``{"result": ...}`` or ``{"error": {"code", "message"}}``.
    A transport or handshake failure raises ``OSError`` or ``ChannelError``.
    """
    with socket.create_connection(address, timeout=timeout) as sock:
        sock.settimeout(timeout)
        session = client_handshake(sock, client_private, server_public)
        session.write({"id": 1, "method": method, "params": params or {}})
        reply = session.read()
    if reply.get("id") != 1:
        raise ChannelError("response id does not match the request")
    return reply


def parse_address(value: str) -> Tuple[str, int]:
    """Parse ``host:port``."""
    host, _, port = value.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"address is not host:port: {value!r}")
    return host, int(port)
