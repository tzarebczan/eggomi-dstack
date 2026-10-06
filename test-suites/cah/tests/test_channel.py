"""Keyed channel handshake and pidfd gate."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import errno
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from cah.auth import SO_PEERPIDFD, authenticate_unix, open_peer_pidfd, pidfd_alive
from cah.channel import (
    ChannelError,
    GateDenial,
    client_handshake,
    server_handshake,
    write_gate_denial,
)
from cah.crypto_lab import generate_private, public_key
from cah.registry import AdmissionRegistry, bind_process, save_registry
from cah.rpc import rpc_ok, serve


class ChannelTests(unittest.TestCase):
    """Frames after the handshake require the registered static key."""

    def test_handshake_round_trip(self) -> None:
        """A matching static key carries one request and one response."""
        client_key = generate_private()
        server_key = generate_private()
        left, right = socket.socketpair()
        errors: list[BaseException] = []
        holder: dict[str, object] = {}

        def server() -> None:
            try:
                session = server_handshake(right, server_key, public_key(client_key))
                holder["request"] = session.read()
                session.write({"ok": True, "code": "ok", "body": {}})
            except BaseException as exc:  # noqa: BLE001 - test captures the thread error
                errors.append(exc)

        thread = threading.Thread(target=server)
        thread.start()
        try:
            session = client_handshake(left, client_key, public_key(server_key))
            session.write({"method": "Ping", "body": {}})
            response = session.read()
        finally:
            thread.join(timeout=5)
            left.close()
            right.close()
        self.assertEqual(errors, [])
        self.assertEqual(holder["request"], {"method": "Ping", "body": {}})
        self.assertTrue(response["ok"])

    def test_wrong_client_key_is_refused(self) -> None:
        """A different static key does not complete the handshake."""
        server_key = generate_private()
        left, right = socket.socketpair()

        def server() -> None:
            try:
                server_handshake(right, server_key, public_key(generate_private()))
            except ChannelError:
                pass
            finally:
                right.close()

        thread = threading.Thread(target=server)
        thread.start()
        left.settimeout(2)
        with self.assertRaises(ChannelError):
            client_handshake(left, generate_private(), public_key(server_key))
        thread.join(timeout=5)
        left.close()

    def test_gate_denial_is_not_a_session(self) -> None:
        """CH0 is a refusal before any method runs."""
        left, right = socket.socketpair()
        write_gate_denial(right, "denied_unadmitted")
        with self.assertRaises(GateDenial) as caught:
            client_handshake(left, generate_private(), public_key(generate_private()))
        self.assertEqual(caught.exception.code, "denied_unadmitted")
        left.close()
        right.close()


class PidfdTests(unittest.TestCase):
    """SO_PEERPIDFD is required. SO_PEERCRED is not a fallback."""

    def test_missing_pidfd_does_not_call_peercred(self) -> None:
        """An older socket option is a denial, not a credential lookup."""

        class Fake:
            def getsockopt(self, level: int, opt: int, buflen: int) -> bytes:
                del level, buflen
                if opt == socket.SO_PEERCRED:
                    raise AssertionError("SO_PEERCRED was consulted")
                if opt == SO_PEERPIDFD:
                    raise OSError(errno.ENOPROTOOPT, "SO_PEERPIDFD")
                raise OSError(errno.EINVAL, "unsupported")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            save_registry(
                path,
                AdmissionRegistry(trust_domain="lab.cah", tenant="tenant-lab-1", workloads=[]),
            )
            auth = authenticate_unix(Fake(), path)  # type: ignore[arg-type]
        self.assertFalse(auth.admitted)
        self.assertEqual(auth.denial_code, "denied_unadmitted")

    def test_dead_pidfd_is_refused(self) -> None:
        """A pidfd that has become readable is not an admitted peer."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sock_path = root / "peer.sock"
            listen = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listen.bind(str(sock_path))
            listen.listen(1)
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import socket,sys,time; s=socket.socket(socket.AF_UNIX); "
                    "s.connect(sys.argv[1]); time.sleep(30)",
                    str(sock_path),
                ]
            )
            conn, _peer = listen.accept()
            try:
                pidfd = open_peer_pidfd(conn)
                self.assertTrue(pidfd_alive(pidfd))
                registry = root / "admission.json"
                save_registry(
                    registry,
                    AdmissionRegistry(
                        trust_domain="lab.cah",
                        tenant="tenant-lab-1",
                        workloads=[
                            {
                                "role": "omi-runner",
                                "instance_id": "omi-1",
                                "boot_id": "boot-omi-1",
                                "boot_generation": 1,
                                "boot_history": ["boot-omi-1"],
                                "cert_fingerprint": None,
                                "pid": None,
                                "starttime": None,
                                "channel_public": "ab" * 32,
                            }
                        ],
                    ),
                )
                bind_process(registry, "omi-1", proc.pid)
                proc.kill()
                proc.wait(timeout=5)
                self.assertFalse(pidfd_alive(pidfd))
                os.close(pidfd)
                auth = authenticate_unix(conn, registry)
                self.assertFalse(auth.admitted)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)
                conn.close()
                listen.close()

    def test_passed_fd_cannot_speak_as_the_parent(self) -> None:
        """A child that holds the connected fd still lacks the parent's key."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            calls: list[str] = []

            def handler(auth: object, method: str, body: dict[str, object]) -> dict[str, object]:
                del auth, body
                calls.append(method)
                return rpc_ok({})

            parent_key = generate_private()
            server_key = generate_private()
            registry = root / "admission.json"
            save_registry(
                registry,
                AdmissionRegistry(
                    trust_domain="lab.cah",
                    tenant="tenant-lab-1",
                    workloads=[
                        {
                            "role": "omi-runner",
                            "instance_id": "omi-1",
                            "boot_id": "boot-omi-1",
                            "boot_generation": 1,
                            "boot_history": ["boot-omi-1"],
                            "cert_fingerprint": None,
                            "pid": None,
                            "starttime": None,
                            "channel_public": public_key(parent_key).hex(),
                        },
                        {
                            "role": "keeper-core",
                            "instance_id": "keeper-1",
                            "boot_id": "boot-keeper-1",
                            "boot_generation": 1,
                            "boot_history": ["boot-keeper-1"],
                            "cert_fingerprint": None,
                            "pid": None,
                            "starttime": None,
                            "channel_public": public_key(server_key).hex(),
                        },
                    ],
                ),
            )
            bind_process(registry, "omi-1", os.getpid())
            stop = root / "stop"
            thread = threading.Thread(
                target=serve,
                args=("unix:" + str(root / "rpc.sock"), "unix", registry, handler, stop),
                kwargs={"role": "keeper-core", "channel_private": server_key},
                daemon=True,
            )
            thread.start()
            ready = root / "ready" / "keeper-core"
            deadline = __import__("time").monotonic() + 5
            while not ready.exists() and __import__("time").monotonic() < deadline:
                __import__("time").sleep(0.02)
            address = ready.read_text(encoding="utf-8").strip().removeprefix("unix:")
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.connect(address)
            marker = root / "child.out"
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import socket,sys; "
                    "s=socket.socket(fileno=int(sys.argv[1])); "
                    "s.sendall(b'not-a-handshake'); "
                    "s.settimeout(2)\n"
                    "try:\n data=s.recv(128)\nexcept Exception:\n data=b''\n"
                    "open(sys.argv[2],'wb').write(data)",
                    str(conn.fileno()),
                    str(marker),
                ],
                pass_fds=(conn.fileno(),),
            )
            child.wait(timeout=5)
            self.assertEqual(calls, [])
            self.assertNotIn(b'"ok"', marker.read_bytes())
            other = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            other.connect(address)
            session = client_handshake(other, parent_key, public_key(server_key))
            session.write({"method": "Ping", "body": {}})
            response = session.read()
            self.assertTrue(response["ok"])
            self.assertEqual(calls, ["Ping"])
            stop.write_text("stop\n", encoding="utf-8")
            thread.join(timeout=5)
            conn.close()
            other.close()


if __name__ == "__main__":
    unittest.main()
