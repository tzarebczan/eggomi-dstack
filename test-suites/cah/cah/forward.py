"""Byte-forwarding transport placeholder.

The forwarder copies bytes. It does not terminate TLS and it does not add an
identity header. A proxy that terminated TLS would be a different principal.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import socket
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Union

Address = Union[Tuple[str, int], str]


@dataclass
class Forwarder:
    """A running byte pipe from ``listen`` to ``upstream``."""

    listen: Address
    upstream: Address
    _stop: threading.Event
    _thread: threading.Thread
    _sock: socket.socket
    label: str = ""

    def endpoint(self) -> str:
        """Return the ``tcp:`` or ``unix:`` address clients should use."""
        return format_address(self.listen)

    def close(self) -> None:
        """Stop accepting and close the listening socket."""
        self._stop.set()
        self._sock.close()
        self._thread.join(timeout=2)


def start_forwarder(upstream: str, listen: Optional[str] = None) -> Forwarder:
    """Listen locally and copy each connection's bytes to ``upstream``.

    ``listen`` may be ``tcp:127.0.0.1:0`` or a ``unix:`` path. The default is
    an ephemeral TCP port on loopback, which is the lab stand-in for a vsock
    port mapping.
    """
    upstream_addr = parse_address(upstream)
    if listen is None:
        listen_sock = _tcp_listener(0)
    else:
        kind, value = _split(listen)
        if kind == "tcp":
            host, port_text = value.rsplit(":", 1)
            listen_sock = _tcp_listener(int(port_text), host)
        elif kind == "unix":
            listen_sock = _unix_listener(Path(value))
        else:
            raise ValueError("listen address must be tcp or unix")
    listen_addr = _sock_address(listen_sock)
    stop = threading.Event()
    thread = threading.Thread(
        target=_accept_loop,
        args=(listen_sock, listen_addr, upstream_addr, stop),
        name="cah-byte-forward",
        daemon=True,
    )
    thread.start()
    return Forwarder(listen_addr, upstream_addr, stop, thread, listen_sock)


def format_address(addr: Address) -> str:
    """Encode a socket address as ``tcp:`` or ``unix:``."""
    if isinstance(addr, str):
        return "unix:" + addr
    host, port = addr
    return f"tcp:{host}:{port}"


def parse_address(text: str) -> Address:
    """Parse a ``tcp:host:port`` or ``unix:path`` address."""
    kind, value = _split(text)
    if kind == "unix":
        return value
    if kind == "tcp":
        host, port_text = value.rsplit(":", 1)
        return host, int(port_text)
    raise ValueError("address must start with tcp: or unix:")


def connect(text: str, timeout: float = 5) -> socket.socket:
    """Open a client socket to a ``tcp:`` or ``unix:`` address."""
    addr = parse_address(text)
    if isinstance(addr, str):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(addr)
    return sock


def _accept_loop(
    listen_sock: socket.socket,
    listen_addr: Address,
    upstream: Address,
    stop: threading.Event,
) -> None:
    listen_sock.settimeout(0.2)
    while not stop.is_set():
        try:
            client, _peer = listen_sock.accept()
        except TimeoutError:
            continue
        except OSError:
            break
        threading.Thread(
            target=_pipe_pair,
            args=(client, upstream),
            name="cah-byte-forward-conn",
            daemon=True,
        ).start()


def _pipe_pair(client: socket.socket, upstream: Address) -> None:
    remote: Optional[socket.socket] = None
    try:
        if isinstance(upstream, str):
            remote = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        else:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.settimeout(5)
        remote.connect(upstream)
        remote.settimeout(None)
        client.settimeout(None)
        left = threading.Thread(target=_copy, args=(client, remote), daemon=True)
        right = threading.Thread(target=_copy, args=(remote, client), daemon=True)
        left.start()
        right.start()
        left.join()
        right.join()
    except OSError:
        pass
    finally:
        client.close()
        if remote is not None:
            remote.close()


def _copy(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _tcp_listener(port: int, host: str = "127.0.0.1") -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(32)
    return sock


def _unix_listener(path: Path) -> socket.socket:
    if path.exists():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    sock.listen(32)
    path.chmod(0o600)
    return sock


def _sock_address(sock: socket.socket) -> Address:
    addr = sock.getsockname()
    if isinstance(addr, str):
        return addr
    return addr[0], int(addr[1])


def _split(text: str) -> tuple[str, str]:
    if ":" not in text:
        raise ValueError("address is missing a scheme")
    kind, value = text.split(":", 1)
    return kind, value
