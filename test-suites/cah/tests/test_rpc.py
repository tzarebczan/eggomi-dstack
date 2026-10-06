"""mTLS clients pin the full callee identity."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path

from cah.frame import FrameError, read_frame, write_frame
from cah.rpc import _wrap_server, call_rpc
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
