"""Byte-forward and vsock placeholder behavior."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import socket
import threading
import unittest

from cah.forward import connect, format_address
from cah.vsock import VsockUnavailable, open_vsock, placeholder


class ForwardTests(unittest.TestCase):
    """The placeholder copies bytes and does not invent identity."""

    def test_open_vsock_is_refused(self) -> None:
        """AF_VSOCK is not opened in this slice."""
        with self.assertRaises(VsockUnavailable):
            open_vsock(3, 5200)

    def test_placeholder_forwards_bytes(self) -> None:
        """A labeled vsock placeholder still delivers the original bytes."""
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        upstream.settimeout(5)
        port = upstream.getsockname()[1]

        def serve() -> None:
            conn, _addr = upstream.accept()
            data = conn.recv(64)
            conn.sendall(data)
            conn.close()

        thread = threading.Thread(target=serve)
        thread.start()
        forwarder = placeholder(3, 5200, f"tcp:127.0.0.1:{port}")
        try:
            self.assertEqual(forwarder.label, "vsock:3:5200")
            client = connect(forwarder.endpoint())
            client.sendall(b"grant-ref-bytes")
            echoed = client.recv(64)
            client.close()
            self.assertEqual(echoed, b"grant-ref-bytes")
        finally:
            forwarder.close()
            upstream.close()
            thread.join(timeout=2)

    def test_tcp_address_format(self) -> None:
        """TCP listen addresses stay dialable after formatting."""
        self.assertEqual(format_address(("127.0.0.1", 9)), "tcp:127.0.0.1:9")


if __name__ == "__main__":
    unittest.main()
