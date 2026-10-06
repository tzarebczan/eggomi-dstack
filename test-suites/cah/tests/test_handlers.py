"""Keeper handlers refuse forged authority and a repeated instance."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import unittest
from pathlib import Path

from cah.access import load_access
from cah.auth import AuthContext
from cah.grants import GrantStore
from cah.handlers import ServerState, dispatch
from cah.policy import load_policy
from cah.registry import AdmissionRegistry, WorkloadIdentity, save_registry

PROFILE = Path(__file__).resolve().parents[1] / "profiles" / "eggomi"


def _identity(role: str, instance: str) -> WorkloadIdentity:
    return WorkloadIdentity(
        trust_domain="lab.cah",
        tenant="tenant-lab-1",
        role=role,
        instance_id=instance,
        boot_id="boot-" + instance,
        boot_generation=1,
        cert_fingerprint=None,
        pid=1000,
        starttime=10,
    )


def _auth(identity: WorkloadIdentity) -> AuthContext:
    return AuthContext("unix-peercred", True, None, identity)


class HandlerTests(unittest.TestCase):
    """PrepareUse and AdmitWorkload use keeper-owned files."""

    def test_forged_prepare_stores_nothing(self) -> None:
        """An attacker origin is refused before a grant row exists."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            authority = root / "authority"
            authority.mkdir()
            registry = root / "admission.json"
            save_registry(
                registry,
                AdmissionRegistry(
                    trust_domain="lab.cah",
                    tenant="tenant-lab-1",
                    workloads=[
                        {
                            "role": "browser-guard",
                            "instance_id": "browser-1",
                            "boot_id": "boot-browser-1",
                            "boot_generation": 1,
                            "boot_history": ["boot-browser-1"],
                            "cert_fingerprint": None,
                            "pid": 42,
                            "starttime": 7,
                        }
                    ],
                ),
            )
            state = ServerState(
                role="keeper-core",
                state=root,
                transport="unix",
                access=load_access(PROFILE / "service-access.json"),
                registry_path=registry,
                grants=GrantStore(authority / "grants.json"),
                secret=None,
                keeper_addr=None,
                cert=None,
                key=None,
                ca=None,
                grant_ttl=60,
                policy=load_policy(PROFILE / "keeper-policy.json"),
                resource_handle=None,
                expect_server=None,
                authority=authority,
                _lock=threading.Lock(),
            )
            body = {
                "operation_id": "op-positive",
                "task_id": "task-lab-1",
                "resource_handle": "cred-lab-1",
                "origin": "https://attacker.example",
                "policy_revision": "pol-lab-1",
                "lease_id": "lease-lab-1",
                "lease_epoch": 1,
                "recipient_instance_id": "browser-1",
            }
            forged = dispatch(
                state, _auth(_identity("omi-runner", "omi-1")), "PrepareUse", body
            )
            self.assertEqual(forged["code"], "denied_payload")
            self.assertFalse((authority / "grants.json").exists())
            body["origin"] = "https://lab.invalid/signin"
            ok = dispatch(
                state, _auth(_identity("omi-runner", "omi-1")), "PrepareUse", body
            )
            self.assertTrue(ok["ok"])
            stored = json.loads((authority / "grants.json").read_text(encoding="utf-8"))
            origins = {row["policy"]["origin"] for row in stored["grants"].values()}
            self.assertEqual(origins, {"https://lab.invalid/signin"})

    def test_duplicate_instance_does_not_consume_the_new_token(self) -> None:
        """A second AdmitWorkload for an existing instance leaves the new token unused."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            authority = root / "authority"
            authority.mkdir()
            registry = root / "admission.json"
            save_registry(
                registry,
                AdmissionRegistry(
                    trust_domain="lab.cah", tenant="tenant-lab-1", workloads=[]
                ),
            )
            grants = GrantStore(authority / "grants.json")
            state = ServerState(
                role="keeper-core",
                state=root,
                transport="unix",
                access=load_access(PROFILE / "service-access.json"),
                registry_path=registry,
                grants=grants,
                secret=None,
                keeper_addr=None,
                cert=None,
                key=None,
                ca=None,
                grant_ttl=60,
                policy=None,
                resource_handle=None,
                expect_server=None,
                authority=authority,
                _lock=threading.Lock(),
            )
            first = _admit(state, "token-1")
            self.assertTrue(first["ok"], first)
            second = _admit(state, "token-2")
            self.assertEqual(second["code"], "denied_bootstrap")
            digest = hashlib.sha256(b"token-2").hexdigest()
            self.assertFalse(grants.bootstrap_used(digest))


def _admit(state: ServerState, token: str) -> dict[str, object]:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    scope = {
        "token_sha256": digest,
        "used": False,
        "admit_role": "connector",
        "admit_instance_id": "connector-scoped-1",
        "admit_boot_id": "boot-connector-scoped-1",
    }
    path = state.authority / "bootstrap-scope.json"
    path.write_text(json.dumps(scope) + "\n", encoding="utf-8")
    return dispatch(
        state,
        _auth(_identity("platform-launcher", "launcher-1")),
        "AdmitWorkload",
        {
            "bootstrap_token": token,
            "admit_role": "connector",
            "admit_instance_id": "connector-scoped-1",
            "admit_boot_id": "boot-connector-scoped-1",
        },
    )


if __name__ == "__main__":
    unittest.main()
