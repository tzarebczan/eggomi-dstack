"""Keyed channel handshake and pidfd gate."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import errno
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict

from cah.auth import SO_PEERPIDFD, authenticate_unix, open_peer_pidfd, pidfd_alive
from cah.channel import (
    ChannelClosed,
    ChannelError,
    GateDenial,
    client_handshake,
    encode_frame,
    read_frame,
    server_handshake,
    write_gate_denial,
)
from cah.crypto_lab import generate_private, public_key
from cah.registry import AdmissionRegistry, bind_process, rebind_channel, save_registry
from cah.rpc import open_channel, rpc_error, rpc_ok, serve


def _wait_address(root: Path, role: str) -> str:
    ready = root / "ready" / role
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if ready.is_file() and ready.stat().st_size:
            address = ready.read_text(encoding="utf-8").strip().removeprefix("unix:")
            if address:
                return address
        time.sleep(0.02)
    raise AssertionError("server did not become ready")


def _row(role: str, instance: str, public: bytes) -> Dict[str, Any]:
    return {
        "role": role,
        "instance_id": instance,
        "boot_id": f"boot-{instance}",
        "boot_generation": 1,
        "boot_history": [f"boot-{instance}"],
        "cert_fingerprint": None,
        "pid": None,
        "starttime": None,
        "channel_public": public.hex(),
    }


class ChannelTests(unittest.TestCase):
    """Frames after the handshake require the registered static key."""

    def _pair(self) -> tuple[Any, Any, bytes, bytes]:
        client_key = generate_private()
        server_key = generate_private()
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        return left, right, client_key, server_key

    def test_handshake_round_trip(self) -> None:
        """A matching static key carries one request and one response."""
        left, right, client_key, server_key = self._pair()
        errors: list[BaseException] = []
        holder: dict[str, object] = {}

        def server() -> None:
            try:
                session = server_handshake(right, server_key, public_key(client_key))
                holder["request"] = session.read()
                session.write({"id": 1, "result": {}})
            except BaseException as exc:  # noqa: BLE001 - test captures the thread error
                errors.append(exc)

        thread = threading.Thread(target=server)
        thread.start()
        session = client_handshake(left, client_key, public_key(server_key))
        session.write({"id": 1, "method": "Ping", "params": {}})
        response = session.read()
        thread.join(timeout=5)
        self.assertEqual(errors, [])
        self.assertEqual(holder["request"], {"id": 1, "method": "Ping", "params": {}})
        self.assertEqual(response, {"id": 1, "result": {}})

    def test_frames_are_u16_length_then_hello_or_transport(self) -> None:
        """Message 1 and 2 are 0x01 plus 48 bytes. A transport frame adds a tag."""
        left, right, client_key, server_key = self._pair()
        seen: dict[str, bytes] = {}

        def server() -> None:
            raw = right.recv(2 + 49)
            seen["hello"] = raw
            right.shutdown(socket.SHUT_WR)

        thread = threading.Thread(target=server)
        thread.start()
        left.settimeout(2)
        with self.assertRaises(ChannelError):
            client_handshake(left, client_key, public_key(server_key))
        thread.join(timeout=5)
        hello = seen["hello"]
        self.assertEqual(hello[:2], (49).to_bytes(2, "big"))
        self.assertEqual(hello[2], 0x01)
        self.assertEqual(len(hello), 51)

    def test_transport_frame_size(self) -> None:
        """A request is one Noise transport message: JSON plus a 16-byte tag."""
        left, right, client_key, server_key = self._pair()
        result: dict[str, bytes] = {}

        def server() -> None:
            server_handshake(right, server_key, public_key(client_key))
            result["frame"] = read_frame(right)

        thread = threading.Thread(target=server)
        thread.start()
        session = client_handshake(left, client_key, public_key(server_key))
        session.write({"id": 1, "method": "health", "params": {}})
        thread.join(timeout=5)
        plain = b'{"id":1,"method":"health","params":{}}'
        self.assertEqual(len(result["frame"]), len(plain) + 16)
        self.assertNotIn(b"health", result["frame"])

    def test_wrong_client_key_is_refused(self) -> None:
        """A different static key does not complete the handshake."""
        left, right, _client_key, server_key = self._pair()
        outcome: list[str] = []

        def server() -> None:
            try:
                server_handshake(right, server_key, public_key(generate_private()))
                outcome.append("accepted")
            except ChannelError:
                outcome.append("refused")
            finally:
                right.shutdown(socket.SHUT_RDWR)

        thread = threading.Thread(target=server)
        thread.start()
        left.settimeout(2)
        with self.assertRaises(ChannelError):
            client_handshake(left, generate_private(), public_key(server_key))
        thread.join(timeout=5)
        self.assertEqual(outcome, ["refused"])

    def test_impostor_keeper_cannot_answer(self) -> None:
        """A keeper with another static key cannot read message 1."""
        left, right, client_key, server_key = self._pair()
        outcome: list[str] = []

        def impostor() -> None:
            try:
                server_handshake(right, generate_private(), public_key(client_key))
                outcome.append("accepted")
            except ChannelError:
                outcome.append("refused")
            finally:
                right.shutdown(socket.SHUT_RDWR)

        thread = threading.Thread(target=impostor)
        thread.start()
        left.settimeout(2)
        with self.assertRaises(ChannelError):
            client_handshake(left, client_key, public_key(server_key))
        thread.join(timeout=5)
        self.assertEqual(outcome, ["refused"])

    def test_gate_denial_is_not_a_session(self) -> None:
        """0x00 and an ASCII code is a refusal before any method runs."""
        left, right, client_key, server_key = self._pair()
        write_gate_denial(right, "denied_unadmitted")
        self.assertEqual(left.recv(64), b"\x00\x12\x00denied_unadmitted")
        write_gate_denial(right, "denied_unadmitted")
        with self.assertRaises(GateDenial) as caught:
            client_handshake(left, client_key, public_key(server_key))
        self.assertEqual(caught.exception.code, "denied_unadmitted")

    def test_tampered_replayed_and_empty_frames_fail(self) -> None:
        """A flipped bit, a replay and a zero length are each refused."""
        for case in ("flip", "replay", "empty"):
            with self.subTest(case=case):
                left, right, client_key, server_key = self._pair()
                holder: dict[str, Any] = {}

                def server() -> None:
                    holder["session"] = server_handshake(
                        right, server_key, public_key(client_key)
                    )

                thread = threading.Thread(target=server)
                thread.start()
                session = client_handshake(left, client_key, public_key(server_key))
                thread.join(timeout=5)
                responder = holder["session"]
                session.write({"id": 1, "method": "a", "params": {}})
                first = read_frame(right)
                if case == "flip":
                    bad = bytearray(first)
                    bad[0] ^= 1
                    left.sendall(encode_frame(bytes(bad)))
                elif case == "replay":
                    responder_ok = responder._receive.decrypt_with_ad(b"", first)
                    self.assertIn(b'"a"', responder_ok)
                    left.sendall(encode_frame(first))
                else:
                    left.sendall(b"\x00\x00")
                with self.assertRaises(ChannelError):
                    responder.read()

    def test_oversized_payload_is_refused_before_it_is_sent(self) -> None:
        """A request over one Noise message is an error, not two frames."""
        left, right, client_key, server_key = self._pair()

        def server() -> None:
            server_handshake(right, server_key, public_key(client_key))

        thread = threading.Thread(target=server)
        thread.start()
        session = client_handshake(left, client_key, public_key(server_key))
        thread.join(timeout=5)
        with self.assertRaises(ChannelError):
            session.write({"id": 1, "method": "x", "params": {"pad": "a" * 70000}})
        with self.assertRaises(ChannelError):
            encode_frame(b"")


class ServedChannelTests(unittest.TestCase):
    """serve() on the Unix socket: several calls, each rechecked."""

    def setUp(self) -> None:
        """Admit this process as omi-1 and start keeper-core."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.client_key = generate_private()
        self.server_key = generate_private()
        self.registry = self.root / "admission.json"
        save_registry(
            self.registry,
            AdmissionRegistry(
                trust_domain="lab.cah",
                tenant="tenant-lab-1",
                workloads=[
                    _row("omi-runner", "omi-1", public_key(self.client_key)),
                    _row("keeper-core", "keeper-1", public_key(self.server_key)),
                ],
            ),
        )
        bind_process(self.registry, "omi-1", os.getpid())
        self.calls: list[str] = []

        def handler(auth: Any, method: str, body: Dict[str, Any]) -> Dict[str, Any]:
            del auth
            self.calls.append(method)
            if method == "Refuse":
                return rpc_error("denied_role")
            return rpc_ok({"echo": body})

        stop = self.root / "stop"
        thread = threading.Thread(
            target=serve,
            args=("unix:" + str(self.root / "rpc.sock"), "unix", self.registry, handler, stop),
            kwargs={"role": "keeper-core", "channel_private": self.server_key},
            daemon=True,
        )
        thread.start()

        def halt() -> None:
            stop.write_text("stop\n", encoding="utf-8")
            thread.join(timeout=5)

        self.addCleanup(halt)
        self.address = _wait_address(self.root, "keeper-core")

    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(self.address)
        self.addCleanup(sock.close)
        return sock

    def test_several_calls_share_one_channel(self) -> None:
        """Results and errors come back as keeper.sock JSON under their ids."""
        sock = self._connect()
        channel = open_channel(sock, self.client_key, public_key(self.server_key))
        first = channel.call("Ping", {"n": 1})
        self.assertEqual(first, rpc_ok({"echo": {"n": 1}}))
        second = channel.call("Refuse", {})
        self.assertEqual(second, rpc_error("denied_role"))
        channel.session.write({"id": 7, "method": "Ping", "params": {"n": 2}})
        self.assertEqual(
            channel.session.read(), {"id": 7, "result": {"echo": {"n": 2}}}
        )
        channel.session.write({"id": 8, "method": "Refuse"})
        self.assertEqual(
            channel.session.read(),
            {"id": 8, "error": {"code": "denied_role", "message": "denied_role"}},
        )
        self.assertEqual(self.calls, ["Ping", "Refuse", "Ping", "Refuse"])

    def test_rebound_row_is_refused_on_the_next_call(self) -> None:
        """denied_boot is the last frame, then FIN."""
        sock = self._connect()
        channel = open_channel(sock, self.client_key, public_key(self.server_key))
        self.assertTrue(channel.call("Ping", {})["ok"])
        rebind_channel(self.registry, "omi-1", public_key(generate_private()).hex())
        self.assertEqual(channel.call("Ping", {}), rpc_error("denied_boot"))
        with self.assertRaises(ChannelClosed):
            read_frame(sock)
        self.assertEqual(self.calls, ["Ping"])

    def test_removed_row_is_refused_on_the_next_call(self) -> None:
        """A row that is gone is denied_unadmitted, then FIN."""
        sock = self._connect()
        channel = open_channel(sock, self.client_key, public_key(self.server_key))
        self.assertTrue(channel.call("Ping", {})["ok"])
        raw = json.loads(self.registry.read_text(encoding="utf-8"))
        raw["workloads"] = [r for r in raw["workloads"] if r["instance_id"] != "omi-1"]
        self.registry.write_text(json.dumps(raw), encoding="utf-8")
        self.assertEqual(channel.call("Ping", {}), rpc_error("denied_unadmitted"))
        with self.assertRaises(ChannelClosed):
            read_frame(sock)

    def test_bad_frame_closes_without_a_reply(self) -> None:
        """A frame that does not decrypt ends the connection. No method runs."""
        sock = self._connect()
        channel = open_channel(sock, self.client_key, public_key(self.server_key))
        sock.sendall(encode_frame(b"\x00" * 40))
        with self.assertRaises(ChannelError):
            read_frame(sock)
        self.assertEqual(self.calls, [])
        del channel

    def test_malformed_request_closes_without_a_reply(self) -> None:
        """A request with no integer id is not answered."""
        sock = self._connect()
        channel = open_channel(sock, self.client_key, public_key(self.server_key))
        channel.session.write({"method": "Ping", "body": {}})
        with self.assertRaises(ChannelError):
            channel.session.read()
        self.assertEqual(self.calls, [])

    def test_unadmitted_peer_gets_a_refusal_frame(self) -> None:
        """No signed row for this pid: 0x00 denied_unadmitted, then close."""
        raw = json.loads(self.registry.read_text(encoding="utf-8"))
        for row in raw["workloads"]:
            row.pop("launcher_sig", None)
        self.registry.write_text(json.dumps(raw), encoding="utf-8")
        sock = self._connect()
        with self.assertRaises(GateDenial) as caught:
            open_channel(sock, self.client_key, public_key(self.server_key))
        self.assertEqual(caught.exception.code, "denied_unadmitted")


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
            address = _wait_address(root, "keeper-core")
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.connect(address)
            marker = root / "child.out"
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import socket,sys\n"
                    "from cah.channel import client_handshake\n"
                    "from cah.crypto_lab import generate_private\n"
                    "sock=socket.socket(fileno=int(sys.argv[1]))\n"
                    "server=bytes.fromhex(sys.argv[3])\n"
                    "try:\n"
                    " client_handshake(sock, generate_private(), server)\n"
                    " status=b'handshake-ok'\n"
                    "except Exception as exc:\n"
                    " status=type(exc).__name__.encode()+b':'+str(exc).encode()\n"
                    "open(sys.argv[2],'wb').write(status)\n",
                    str(conn.fileno()),
                    str(marker),
                    public_key(server_key).hex(),
                ],
                pass_fds=(conn.fileno(),),
            )
            child.wait(timeout=5)
            self.assertEqual(calls, [])
            self.assertNotIn(b"handshake-ok", marker.read_bytes())
            self.assertNotIn(b'"ok"', marker.read_bytes())
            other = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            other.connect(address)
            channel = open_channel(other, parent_key, public_key(server_key))
            response = channel.call("Ping", {})
            self.assertTrue(response["ok"])
            self.assertEqual(calls, ["Ping"])
            stop.write_text("stop\n", encoding="utf-8")
            thread.join(timeout=5)
            conn.close()
            other.close()


if __name__ == "__main__":
    unittest.main()
