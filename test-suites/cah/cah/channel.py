"""The compartment channel: Noise KK keyed to the registered static key.

``Noise_KK_25519_ChaChaPoly_SHA256`` with the prologue
``eggomi/cah-channel/v1``. This is the wire Eggomi's keeper speaks
(``apps/desktop/src/keeper/cah/channel.ts``). The workload is the initiator
and knows the keeper's static key. The keeper knows the workload's from its
launcher-signed registry row.

pid and start time only decide whether this handshake may start. A process
that holds the connected fd but not the registered key cannot finish
message 1, and on an established channel it cannot write a frame that
authenticates: each is ChaChaPoly under the next counter, so an injected,
replayed or reordered frame fails and the connection closes.

On the socket every frame is a u16 big-endian length, then that many bytes
(1..65 535):

    workload -> keeper   0x01 || KK message 1 (e, es, ss; empty payload)
    keeper -> workload   0x01 || KK message 2 (e, ee, se; empty payload)
                         or 0x00 || an ASCII refusal code, then close
    then, both ways      one Noise transport message per frame (empty
                         associated data, implicit counter nonce) carrying
                         keeper.sock JSON:
      request  {"id": n, "method": "...", "params": {...}}
      response {"id": n, "result": ...} | {"id": n, "error": {"code", "message"}}

A plain fork copies the key and is the same compartment. The key must stay
out of templates, out of files another compartment can read, and off the
command line.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import socket
import struct
from typing import Any, Dict, Optional

from .noise import (
    MAX_MESSAGE,
    TAGLEN,
    KkInitiator,
    KkResponder,
    NoiseError,
    Transport,
)

PROLOGUE = b"eggomi/cah-channel/v1"
HELLO = 0x01
REFUSAL = 0x00
MAX_PAYLOAD = MAX_MESSAGE - TAGLEN
_HEADER = struct.Struct("!H")
_EMPTY = b""


class ChannelError(ValueError):
    """The handshake failed, a frame did not authenticate, or the peer closed."""


class ChannelClosed(ChannelError):
    """The peer closed the connection on a frame boundary."""


class GateDenial(Exception):
    """The keeper refused the connection before the keyed channel existed."""

    def __init__(self, code: str) -> None:
        """Record the refusal ``code``."""
        super().__init__(code)
        self.code = code


def encode_frame(body: bytes) -> bytes:
    """Return ``body`` behind its u16 big-endian length."""
    if not 1 <= len(body) <= MAX_MESSAGE:
        raise ChannelError("frame length is outside 1..65535")
    return _HEADER.pack(len(body)) + body


def read_frame(sock: socket.socket) -> bytes:
    """Read one frame. A zero length is a protocol error.

    A close before the first header byte is ``ChannelClosed``. A close in
    the middle of a frame is a ``ChannelError``.
    """
    first = sock.recv(1)
    if not first:
        raise ChannelClosed("connection closed")
    header = first + _read_exact(sock, _HEADER.size - 1)
    (length,) = _HEADER.unpack(header)
    if length == 0:
        raise ChannelError("frame length is zero")
    return _read_exact(sock, length)


class Session:
    """An established channel: one transport message per frame."""

    def __init__(self, sock: socket.socket, transport: Transport) -> None:
        """Wrap ``sock`` with the handshake's two cipher states."""
        self.sock = sock
        self._send = transport.send
        self._receive = transport.receive
        self.handshake_hash = transport.handshake_hash

    def write(self, payload: Dict[str, Any]) -> None:
        """Send one JSON object as one transport message."""
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        if len(raw) > MAX_PAYLOAD:
            raise ChannelError("frame exceeds one Noise transport message")
        self.sock.sendall(encode_frame(self._send.encrypt_with_ad(_EMPTY, raw)))

    def read(self) -> Dict[str, Any]:
        """Read one JSON object. A frame that does not decrypt is an error.

        The caller closes the connection on any ``ChannelError``.
        """
        body = read_frame(self.sock)
        try:
            raw = self._receive.decrypt_with_ad(_EMPTY, body)
        except NoiseError as exc:
            raise ChannelError("frame does not authenticate") from exc
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ChannelError("frame is not utf-8 json") from exc
        if not isinstance(value, dict):
            raise ChannelError("frame payload is not an object")
        return value


def client_handshake(
    sock: socket.socket,
    client_private: bytes,
    server_public: bytes,
    *,
    ephemeral: Optional[bytes] = None,
) -> Session:
    """Prove ``client_private`` to the keeper whose static key is ``server_public``.

    A pre-channel refusal is raised as ``GateDenial`` and is not an RPC
    result. ``ephemeral`` is for vectors only.
    """
    initiator = KkInitiator(
        prologue=PROLOGUE,
        static_private=client_private,
        remote_static=server_public,
        ephemeral=ephemeral,
    )
    hello = encode_frame(bytes([HELLO]) + initiator.write_message1())
    try:
        sock.sendall(hello)
    except BrokenPipeError:
        pass
    try:
        body = read_frame(sock)
    except ChannelClosed as exc:
        raise ChannelError("connection closed during the client handshake") from exc
    except ConnectionResetError as exc:
        raise ChannelError("connection reset during the client handshake") from exc
    if body[0] == REFUSAL:
        raise GateDenial(_ascii(body[1:]))
    if body[0] != HELLO:
        raise ChannelError("handshake reply is not recognized")
    try:
        _payload, transport = initiator.read_message2(body[1:])
    except NoiseError as exc:
        raise ChannelError("server handshake does not authenticate") from exc
    return Session(sock, transport)


def server_handshake(
    sock: socket.socket,
    server_private: bytes,
    client_public: bytes,
    *,
    ephemeral: Optional[bytes] = None,
) -> Session:
    """Accept only a peer that proves ``client_public``.

    A failed handshake raises ``ChannelError`` and nothing is written; the
    caller closes the connection.
    """
    body = read_frame(sock)
    if body[0] != HELLO:
        raise ChannelError("client handshake is not recognized")
    responder = KkResponder(
        prologue=PROLOGUE,
        static_private=server_private,
        remote_static=client_public,
        ephemeral=ephemeral,
    )
    try:
        responder.read_message1(body[1:])
        message, transport = responder.write_message2()
    except NoiseError as exc:
        raise ChannelError("client handshake does not authenticate") from exc
    sock.sendall(encode_frame(bytes([HELLO]) + message))
    return Session(sock, transport)


def write_gate_denial(sock: socket.socket, code: str) -> None:
    """Send a pre-channel refusal: ``0x00`` and an ASCII code."""
    raw = code.encode("ascii")
    if not raw or len(raw) > 64:
        raise ChannelError("gate denial code is empty or too long")
    sock.sendall(encode_frame(bytes([REFUSAL]) + raw))


def _ascii(raw: bytes) -> str:
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ChannelError("gate denial is not ascii") from exc


def _read_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise ChannelError("connection closed inside a frame")
        chunks.extend(part)
    return bytes(chunks)


def parse_public(value: Optional[str]) -> bytes:
    """Decode a 32-byte hex public key."""
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError("channel public key is missing")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("channel public key is not hex") from exc
    if len(raw) != 32:
        raise ValueError("channel public key is not 32 bytes")
    return raw
