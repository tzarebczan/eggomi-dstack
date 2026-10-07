"""Minimal Chrome DevTools Protocol pieces for the L1 gVisor lab (stdlib only).

``relay`` runs inside the browser sandbox. Headless Chromium binds DevTools
to the sandbox's loopback only, so the relay publishes it on the browser's
side of the guard network, and nowhere else.

``Cdp`` is the guard's client: one WebSocket to the browser target, flat
sessions for page targets, and request/response matching by id.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import sys
import threading
import urllib.request
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def relay(listen: Tuple[str, int], target: Tuple[str, int]) -> None:
    """Forward every connection on ``listen`` to ``target``."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(listen)
    server.listen(16)
    while True:
        conn, _ = server.accept()
        try:
            upstream = socket.create_connection(target, timeout=5)
            upstream.settimeout(None)
        except OSError:
            conn.close()
            continue
        threading.Thread(target=_pipe, args=(conn, upstream), daemon=True).start()
        threading.Thread(target=_pipe, args=(upstream, conn), daemon=True).start()


def version(address: Tuple[str, int], timeout: float = 3.0) -> Dict[str, Any]:
    """GET /json/version through the relay."""
    host, port = address
    with urllib.request.urlopen(
        f"http://{host}:{port}/json/version", timeout=timeout
    ) as resp:
        return json.loads(resp.read().decode("utf-8"))


class Cdp:
    """One DevTools WebSocket (the browser target) with flat page sessions."""

    def __init__(self, address: Tuple[str, int], timeout: float = 30.0) -> None:
        """Connect to the browser target named by /json/version."""
        url = urlparse(version(address, timeout)["webSocketDebuggerUrl"])
        self.sock = socket.create_connection(address, timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {url.path} HTTP/1.1\r\nHost: {address[0]}:{address[1]}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(request.encode("ascii"))
        head = b""
        while b"\r\n\r\n" not in head:
            part = self.sock.recv(4096)
            if not part:
                raise ConnectionError("DevTools closed the WebSocket handshake")
            head += part
        status = head.split(b"\r\n", 1)[0]
        if b" 101 " not in status + b" ":
            raise ConnectionError(f"DevTools refused the WebSocket: {status!r}")
        self._buf = head.split(b"\r\n\r\n", 1)[1]
        self._next = 0

    def close(self) -> None:
        """Close the WebSocket."""
        try:
            self._send_frame(0x8, b"")
        except OSError:
            pass
        self.sock.close()

    def __enter__(self) -> "Cdp":
        """Use as a context manager."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Close on exit."""
        self.close()

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        head = bytes([0x80 | opcode])
        size = len(payload)
        if size < 126:
            head += bytes([0x80 | size])
        elif size < 1 << 16:
            head += bytes([0x80 | 126]) + struct.pack(">H", size)
        else:
            head += bytes([0x80 | 127]) + struct.pack(">Q", size)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(head + mask + masked)

    def _read(self, count: int) -> bytes:
        while len(self._buf) < count:
            part = self.sock.recv(65536)
            if not part:
                raise ConnectionError("DevTools closed the WebSocket")
            self._buf += part
        out, self._buf = self._buf[:count], self._buf[count:]
        return out

    def _recv_message(self) -> bytes:
        message = b""
        while True:
            b0, b1 = self._read(2)
            size = b1 & 0x7F
            if size == 126:
                size = struct.unpack(">H", self._read(2))[0]
            elif size == 127:
                size = struct.unpack(">Q", self._read(8))[0]
            if b1 & 0x80:
                mask = self._read(4)
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(self._read(size)))
            else:
                data = self._read(size)
            opcode = b0 & 0x0F
            if opcode == 0x9:
                self._send_frame(0xA, data)
                continue
            if opcode == 0x8:
                raise ConnectionError("DevTools closed the WebSocket")
            message += data
            if b0 & 0x80:
                return message

    def call(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        session: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send one command and return its result; events are discarded."""
        self._next += 1
        ident = self._next
        body: Dict[str, Any] = {"id": ident, "method": method, "params": params or {}}
        if session:
            body["sessionId"] = session
        self._send_frame(0x1, json.dumps(body).encode("utf-8"))
        while True:
            reply = json.loads(self._recv_message())
            if reply.get("id") != ident:
                continue
            if "error" in reply:
                raise RuntimeError(f"{method}: {reply['error'].get('message')}")
            return reply.get("result", {})

    def open_page(self, url: str) -> Tuple[str, str]:
        """Open a page target and attach to it; return (target, session)."""
        target = self.call("Target.createTarget", {"url": url})["targetId"]
        session = self.call(
            "Target.attachToTarget", {"targetId": target, "flatten": True}
        )["sessionId"]
        return target, session

    def evaluate(self, session: str, expression: str, timeout_ms: int = 60000) -> Any:
        """Evaluate in a page and return the value (promises are awaited)."""
        result = self.call(
            "Runtime.evaluate",
            {
                "expression": expression,
                "awaitPromise": True,
                "returnByValue": True,
                "timeout": timeout_ms,
            },
            session,
        )
        if "exceptionDetails" in result:
            raise RuntimeError(f"page threw: {result['exceptionDetails'].get('text')}")
        return result.get("result", {}).get("value")

    def pages(self) -> list:
        """Page targets as Target.getTargets reports them."""
        return [
            t
            for t in self.call("Target.getTargets")["targetInfos"]
            if t["type"] == "page"
        ]


def _address(value: str) -> Tuple[str, int]:
    host, _, port = value.rpartition(":")
    return host, int(port)


def main(argv: list) -> int:
    """``relay LISTEN TARGET`` (in the browser sandbox)."""
    if len(argv) == 3 and argv[0] == "relay":
        relay(_address(argv[1]), _address(argv[2]))
        return 0
    print("usage: cdp.py relay LISTEN_HOST:PORT TARGET_HOST:PORT", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
