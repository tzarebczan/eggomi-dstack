"""Keyed compartment channel for Unix RPC.

pid and start time only decide whether this handshake may start. After it
succeeds, every frame is AEAD under keys derived from the workload's
registered static key. A process that holds the connected fd but not that
key cannot complete the handshake or produce a later frame.

A plain fork copies the key and is the same compartment. The key must stay
out of templates, out of files another compartment can read, and off the
command line.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import struct
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .crypto_lab import aead_open, aead_seal, generate_private, hkdf_sha256, public_key, x25519

_CLIENT_MAGIC = b"CH1\x01"
_SERVER_MAGIC = b"CH2\x01"
_GATE_MAGIC = b"CH0\x01"
_HEADER = struct.Struct("!I")
_MAX = 1024 * 1024


class ChannelError(ValueError):
    """The handshake or a frame tag failed."""


class GateDenial(Exception):
    """The server refused the connection before the keyed channel existed."""

    def __init__(self, code: str) -> None:
        """Record the gate ``code``."""
        super().__init__(code)
        self.code = code


@dataclass
class Session:
    """One direction pair of AEAD keys and a strictly increasing counter."""

    sock: socket.socket
    send_key: bytes
    recv_key: bytes
    send_counter: int = 0
    recv_counter: int = 0

    def write(self, payload: Dict[str, Any]) -> None:
        """Send one JSON object as an authenticated frame."""
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(raw) > _MAX:
            raise ChannelError("frame exceeds 1 MiB")
        nonce = self.send_counter.to_bytes(8, "big")
        ciphertext, tag = aead_seal(self.send_key, nonce, b"cah-frame/v1", raw)
        body = nonce + tag + ciphertext
        self.sock.sendall(_HEADER.pack(len(body)) + body)
        self.send_counter += 1

    def read(self) -> Dict[str, Any]:
        """Read one authenticated JSON object. A repeated counter is refused."""
        header = _read_exact(self.sock, _HEADER.size)
        (length,) = _HEADER.unpack(header)
        if length <= 40 or length > _MAX + 40:
            raise ChannelError("frame length is outside the channel limit")
        body = _read_exact(self.sock, length)
        nonce = body[:8]
        tag = body[8:40]
        ciphertext = body[40:]
        expect = self.recv_counter.to_bytes(8, "big")
        if nonce != expect:
            raise ChannelError("frame counter is not the next value")
        try:
            raw = aead_open(self.recv_key, nonce, b"cah-frame/v1", ciphertext, tag)
        except ValueError as exc:
            raise ChannelError("frame tag does not match") from exc
        self.recv_counter += 1
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ChannelError("frame is not utf-8 json") from exc
        if not isinstance(value, dict):
            raise ChannelError("frame payload is not an object")
        return value


def client_handshake(
    sock: socket.socket, client_private: bytes, server_public: bytes
) -> Session:
    """Prove possession of ``client_private`` and return the session.

    A gate denial from the server is raised as ``GateDenial`` and is not a
    successful RPC.
    """
    client_public = public_key(client_private)
    ephemeral_private = generate_private()
    ephemeral_public = public_key(ephemeral_private)
    transcript = _transcript(ephemeral_public, server_public, client_public)
    shared = x25519(ephemeral_private, server_public) + x25519(
        client_private, server_public
    )
    tag = _mac(shared, b"cah-channel-c1/v1", transcript)
    try:
        sock.sendall(_CLIENT_MAGIC + ephemeral_public + tag)
    except BrokenPipeError:
        reply = _read_exact(sock, 4)
        if reply == _GATE_MAGIC:
            raise GateDenial(_read_gate_code(sock))
        raise ChannelError("connection closed during the client handshake") from None
    reply = _read_exact(sock, 4)
    if reply == _GATE_MAGIC:
        raise GateDenial(_read_gate_code(sock))
    if reply != _SERVER_MAGIC:
        raise ChannelError("server handshake magic is not recognized")
    server_ephemeral = _read_exact(sock, 32)
    server_tag = _read_exact(sock, 32)
    transcript2 = transcript + server_ephemeral
    shared2 = shared + x25519(ephemeral_private, server_ephemeral) + x25519(
        client_private, server_ephemeral
    )
    expect = _mac(shared2, b"cah-channel-s2/v1", transcript2)
    if not hmac.compare_digest(expect, server_tag):
        raise ChannelError("server handshake tag does not match")
    send_key = hkdf_sha256(shared2, b"cah-channel-c2s/v1" + transcript2)
    recv_key = hkdf_sha256(shared2, b"cah-channel-s2c/v1" + transcript2)
    return Session(sock, send_key, recv_key)


def server_handshake(
    sock: socket.socket, server_private: bytes, client_public: bytes
) -> Session:
    """Accept a client that proves ``client_public``. Any other key is refused."""
    header = _read_exact(sock, 4)
    if header != _CLIENT_MAGIC:
        raise ChannelError("client handshake magic is not recognized")
    ephemeral_public = _read_exact(sock, 32)
    tag = _read_exact(sock, 32)
    server_public = public_key(server_private)
    transcript = _transcript(ephemeral_public, server_public, client_public)
    shared = x25519(server_private, ephemeral_public) + x25519(
        server_private, client_public
    )
    expect = _mac(shared, b"cah-channel-c1/v1", transcript)
    if not hmac.compare_digest(expect, tag):
        raise ChannelError("client handshake tag does not match")
    ephemeral_private = generate_private()
    server_ephemeral = public_key(ephemeral_private)
    transcript2 = transcript + server_ephemeral
    shared2 = shared + x25519(ephemeral_private, ephemeral_public) + x25519(
        ephemeral_private, client_public
    )
    server_tag = _mac(shared2, b"cah-channel-s2/v1", transcript2)
    sock.sendall(_SERVER_MAGIC + server_ephemeral + server_tag)
    recv_key = hkdf_sha256(shared2, b"cah-channel-c2s/v1" + transcript2)
    send_key = hkdf_sha256(shared2, b"cah-channel-s2c/v1" + transcript2)
    return Session(sock, send_key, recv_key)


def write_gate_denial(sock: socket.socket, code: str) -> None:
    """Send a pre-channel refusal. It carries no method result."""
    raw = code.encode("utf-8")
    if len(raw) > 64:
        raise ChannelError("gate denial code is too long")
    sock.sendall(_GATE_MAGIC + bytes([len(raw)]) + raw)


def _read_gate_code(sock: socket.socket) -> str:
    (length,) = _read_exact(sock, 1)
    raw = _read_exact(sock, length)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ChannelError("gate denial is not utf-8") from exc


def _transcript(ephemeral: bytes, server_public: bytes, client_public: bytes) -> bytes:
    return b"cah-channel/v1" + ephemeral + server_public + client_public


def _mac(shared: bytes, label: bytes, transcript: bytes) -> bytes:
    key = hkdf_sha256(shared, label)
    return hmac.new(key, transcript, hashlib.sha256).digest()


def _read_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise ChannelError("connection closed during the channel handshake")
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
