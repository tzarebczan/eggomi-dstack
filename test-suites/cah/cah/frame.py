"""Length-prefixed JSON frames for compartment RPC."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import socket
import struct
from typing import Any, Dict

MAX_FRAME_BYTES = 1024 * 1024
_HEADER = struct.Struct("!I")


class FrameError(ValueError):
    """A frame was empty, too large, or not a JSON object."""


def write_frame(sock: socket.socket, payload: Dict[str, Any]) -> None:
    """Send one JSON object as a 4-byte length prefix plus UTF-8 bytes."""
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(raw) > MAX_FRAME_BYTES:
        raise FrameError("frame exceeds 1 MiB")
    sock.sendall(_HEADER.pack(len(raw)) + raw)


def read_frame(sock: socket.socket) -> Dict[str, Any]:
    """Read one JSON object frame.

    ``null`` and non-objects are rejected. Callers must not coerce a missing
    payload into a zero or an empty success.
    """
    header = _read_exact(sock, _HEADER.size)
    (length,) = _HEADER.unpack(header)
    if length <= 0 or length > MAX_FRAME_BYTES:
        raise FrameError("frame length is outside 1..1048576")
    raw = _read_exact(sock, length)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FrameError("frame is not utf-8 json") from exc
    if not isinstance(value, dict):
        raise FrameError("frame payload is not an object")
    return value


def _read_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise FrameError("connection closed before the frame finished")
        chunks.extend(part)
    return bytes(chunks)
