"""mTLS clients pin the full callee identity."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import socket
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path

from cah.crypto_lab import generate_private, public_key
from cah.frame import FrameError, read_frame, write_frame
from cah.registry import AdmissionRegistry, bind_process, save_registry
from cah.rpc import _peer_public, _wrap_server, call_rpc, rpc_ok, serve
from cah.tls_lab import IssuedCert, LabMaterial, issue_lab

TRUST = "lab.cah"
TENANT = "tenant-lab-1"


class RpcPinTests(unittest.TestCase):
    """A lab certificate is accepted only when the callee pin matches it."""

    def test_role_only_does_not_connect(self) -> None:
        """A role string is not a substitute for the callee pin."""
        with tempfile.TemporaryDirectory() as tmp:
            material = _material(Path(tmp))
            browser = material.for_instance("browser-1")
            with self.assertRaises(RuntimeError) as caught:
                call_rpc(
                    "tcp:127.0.0.1:1",
                    "Ping",
                    {},
                    transport="mtls",
                    cert=browser.cert_path,
                    key=browser.key_path,
                    ca=material.ca_cert,
                    expect_server_role="keeper-core",
                )
            self.assertIn("callee pin", str(caught.exception))

    def test_same_role_other_instance_is_refused(self) -> None:
        """Another lab certificate with the keeper role is not the pinned keeper."""
        with tempfile.TemporaryDirectory() as tmp:
            material = _material(Path(tmp))
            keeper = material.for_instance("keeper-1")
            other = material.for_instance("keeper-evil")
            browser = material.for_instance("browser-1")
            port, thread = _serve(other.cert_path, other.key_path, material.ca_cert)
            try:
                with self.assertRaises(RuntimeError) as caught:
                    call_rpc(
                        f"tcp:127.0.0.1:{port}",
                        "Ping",
                        {},
                        transport="mtls",
                        cert=browser.cert_path,
                        key=browser.key_path,
                        ca=material.ca_cert,
                        expect_server=_pin(keeper),
                    )
            finally:
                thread.join(timeout=5)
            self.assertIn("callee pin", str(caught.exception))

    def test_matching_pin_round_trip(self) -> None:
        """The pinned keeper certificate is accepted."""
        with tempfile.TemporaryDirectory() as tmp:
            material = _material(Path(tmp))
            keeper = material.for_instance("keeper-1")
            browser = material.for_instance("browser-1")
            port, thread = _serve(keeper.cert_path, keeper.key_path, material.ca_cert)
            try:
                response = call_rpc(
                    f"tcp:127.0.0.1:{port}",
                    "Ping",
                    {},
                    transport="mtls",
                    cert=browser.cert_path,
                    key=browser.key_path,
                    ca=material.ca_cert,
                    expect_server=_pin(keeper),
                )
            finally:
                thread.join(timeout=5)
            self.assertTrue(response["ok"])

    def test_two_uri_sans_are_not_an_identity(self) -> None:
        """SPIFFE requires exactly one URI. The first match is not used."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            material = _material(root)
            browser = material.for_instance("browser-1")
            cert, key = _two_uri_cert(root, material)
            port, thread = _serve(cert, key, material.ca_cert)
            try:
                with self.assertRaises(RuntimeError) as caught:
                    call_rpc(
                        f"tcp:127.0.0.1:{port}",
                        "Ping",
                        {},
                        transport="mtls",
                        cert=browser.cert_path,
                        key=browser.key_path,
                        ca=material.ca_cert,
                        expect_server=_pin(material.for_instance("keeper-1")),
                    )
            finally:
                thread.join(timeout=5)
            self.assertIn("one spiffe uri", str(caught.exception))


class UnixPeerPinTests(unittest.TestCase):
    """Unix clients select the callee by instance, not the first role row."""

    def test_missing_instance_is_refused_before_connect(self) -> None:
        """A role string is not a Unix callee pin."""
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError) as caught:
                call_rpc(
                    "unix:" + str(Path(tmp) / "missing.sock"),
                    "Ping",
                    {},
                    transport="unix",
                    channel_private=generate_private(),
                    registry_path=Path(tmp) / "admission.json",
                    peer_role="keeper-core",
                )
            self.assertIn("peer instance", str(caught.exception))

    def test_named_instance_is_not_the_first_role_row(self) -> None:
        """A stale keeper row listed first does not supply the channel key."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client_key = generate_private()
            keeper_key = generate_private()
            stale_key = generate_private()
            registry = root / "admission.json"
            save_registry(
                registry,
                AdmissionRegistry(
                    trust_domain="lab.cah",
                    tenant="tenant-lab-1",
                    workloads=[
                        _row("keeper-core", "keeper-stale", public_key(stale_key)),
                        _row("keeper-core", "keeper-1", public_key(keeper_key)),
                        _row("omi-runner", "omi-1", public_key(client_key)),
                    ],
                ),
            )
            self.assertEqual(
                _peer_public(registry, "keeper-core", "keeper-1"),
                public_key(keeper_key),
            )
            with self.assertRaises(RuntimeError):
                _peer_public(registry, "keeper-core", "keeper-stale-role")
            bind_process(registry, "omi-1", os.getpid())
            calls: list[str] = []

            def handler(
                auth: object, method: str, body: dict[str, object]
            ) -> dict[str, object]:
                del auth, body
                calls.append(method)
                return rpc_ok({})

            stop = root / "stop"
            thread = threading.Thread(
                target=serve,
                args=("unix:" + str(root / "rpc.sock"), "unix", registry, handler, stop),
                kwargs={"role": "keeper-core", "channel_private": keeper_key},
                daemon=True,
            )
            thread.start()
            address = _wait_unix_ready(root)
            try:
                with self.assertRaises(RuntimeError) as caught:
                    call_rpc(
                        address,
                        "Ping",
                        {},
                        transport="unix",
                        channel_private=client_key,
                        registry_path=registry,
                        peer_role="keeper-core",
                        peer_instance="keeper-stale",
                    )
                self.assertIn("keyed channel failed", str(caught.exception))
                self.assertEqual(calls, [])
                response = call_rpc(
                    address,
                    "Ping",
                    {},
                    transport="unix",
                    channel_private=client_key,
                    registry_path=registry,
                    peer_role="keeper-core",
                    peer_instance="keeper-1",
                )
            finally:
                stop.write_text("stop\n", encoding="utf-8")
                thread.join(timeout=5)
            self.assertTrue(response["ok"])
            self.assertEqual(calls, ["Ping"])


def _row(role: str, instance_id: str, channel_public: bytes) -> dict[str, object]:
    return {
        "role": role,
        "instance_id": instance_id,
        "boot_id": f"boot-{instance_id}",
        "boot_generation": 1,
        "boot_history": [f"boot-{instance_id}"],
        "cert_fingerprint": None,
        "pid": None,
        "starttime": None,
        "channel_public": channel_public.hex(),
    }


def _wait_unix_ready(root: Path) -> str:
    ready = root / "ready" / "keeper-core"
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if ready.is_file() and ready.stat().st_size:
            text = ready.read_text(encoding="utf-8").strip()
            if text:
                return text
        time.sleep(0.02)
    raise AssertionError("keeper did not publish a ready address")


def _material(root: Path) -> LabMaterial:
    return issue_lab(
        root / "certs",
        TRUST,
        TENANT,
        [
            ("keeper-core", "keeper-1"),
            ("keeper-core", "keeper-evil"),
            ("browser-guard", "browser-1"),
        ],
    )


def _pin(issued: IssuedCert) -> dict[str, str]:
    return {
        "domain": TRUST,
        "tenant": TENANT,
        "role": issued.role,
        "instance": issued.instance_id,
        "fingerprint": issued.fingerprint,
    }


def _serve(cert: Path, key: Path, ca: Path) -> tuple[int, threading.Thread]:
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(("127.0.0.1", 0))
    listen.listen(1)
    port = listen.getsockname()[1]
    started = threading.Event()

    def run() -> None:
        listen.settimeout(5)
        started.set()
        wrapped: ssl.SSLSocket | None = None
        conn: socket.socket | None = None
        try:
            conn, _addr = listen.accept()
            wrapped = _wrap_server(conn, cert, key, ca)
            read_frame(wrapped)
            write_frame(wrapped, {"ok": True, "code": "ok", "body": {}})
        except (OSError, ssl.SSLError, FrameError, RuntimeError):
            pass
        finally:
            if wrapped is not None:
                wrapped.close()
            elif conn is not None:
                conn.close()
            listen.close()

    thread = threading.Thread(target=run)
    thread.start()
    started.wait(timeout=2)
    return port, thread


def _two_uri_cert(root: Path, material: LabMaterial) -> tuple[Path, Path]:
    directory = root / "two-uri"
    directory.mkdir()
    key = directory / "server.key"
    csr = directory / "server.csr"
    cert = directory / "server.crt"
    ext = directory / "server.ext"
    ext.write_text(
        "basicConstraints=CA:FALSE\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
        "subjectAltName="
        f"URI:spiffe://{TRUST}/tenant/{TENANT}/role/keeper-core/instance/keeper-1,"
        f"URI:spiffe://{TRUST}/tenant/{TENANT}/role/connector/instance/connector-1\n",
        encoding="utf-8",
    )
    _openssl(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(csr),
            "-subj",
            "/CN=two-uri",
        ]
    )
    _openssl(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(material.ca_cert),
            "-CAkey",
            str(material.ca_key),
            "-CAcreateserial",
            "-out",
            str(cert),
            "-days",
            "1",
            "-sha256",
            "-extfile",
            str(ext),
        ]
    )
    return cert, key


def _openssl(argv: list[str]) -> None:
    import subprocess

    result = subprocess.run(argv, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "openssl failed").strip()
        raise RuntimeError(f"openssl failed: {detail}")


if __name__ == "__main__":
    unittest.main()
