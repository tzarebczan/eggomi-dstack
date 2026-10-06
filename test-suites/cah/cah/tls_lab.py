"""Lab CA for mutual TLS.

SPIRE is not started. Certificates carry a SPIFFE-shaped URI so the same
authorization context can be filled from a peer certificate. The subject CN
is deliberately not the role name.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .auth import fingerprint_pem


@dataclass(frozen=True)
class IssuedCert:
    """Paths and fingerprint for one lab certificate."""

    role: str
    instance_id: str
    cert_path: Path
    key_path: Path
    fingerprint: str


@dataclass(frozen=True)
class LabMaterial:
    """CA and per-instance certificates for one run."""

    ca_cert: Path
    ca_key: Path
    issued: dict[str, IssuedCert]

    def for_instance(self, instance_id: str) -> IssuedCert:
        """Return the certificate issued for ``instance_id``."""
        return self.issued[instance_id]


def issue_lab(
    directory: Path,
    trust_domain: str,
    tenant: str,
    instances: list[tuple[str, str]],
) -> LabMaterial:
    """Issue a one-day lab CA and one client/server cert per instance.

    ``instances`` is a list of ``(role, instance_id)`` pairs.
    """
    directory.mkdir(parents=True, exist_ok=True)
    ca_key = directory / "ca.key"
    ca_cert = directory / "ca.crt"
    _run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "1",
            "-nodes",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_cert),
            "-subj",
            "/CN=cah-lab-root",
        ]
    )
    ca_key.chmod(0o600)
    issued: dict[str, IssuedCert] = {}
    for role, instance_id in instances:
        stem = directory / instance_id
        key_path = stem.with_suffix(".key")
        csr_path = stem.with_suffix(".csr")
        cert_path = stem.with_suffix(".crt")
        ext_path = stem.with_suffix(".ext")
        uri = f"spiffe://{trust_domain}/tenant/{tenant}/role/{role}/instance/{instance_id}"
        ext_path.write_text(
            "basicConstraints=CA:FALSE\n"
            "extendedKeyUsage=serverAuth,clientAuth\n"
            f"subjectAltName=URI:{uri}\n",
            encoding="utf-8",
        )
        _run(
            [
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-keyout",
                str(key_path),
                "-out",
                str(csr_path),
                "-subj",
                f"/CN=ignored-cn-{instance_id}",
            ]
        )
        _run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(csr_path),
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(cert_path),
                "-days",
                "1",
                "-sha256",
                "-extfile",
                str(ext_path),
            ]
        )
        key_path.chmod(0o600)
        issued[instance_id] = IssuedCert(
            role=role,
            instance_id=instance_id,
            cert_path=cert_path,
            key_path=key_path,
            fingerprint=fingerprint_pem(cert_path),
        )
    return LabMaterial(ca_cert=ca_cert, ca_key=ca_key, issued=issued)


def _run(argv: list[str]) -> None:
    result = subprocess.run(argv, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "openssl failed").strip()
        raise RuntimeError(f"openssl failed: {detail}")
