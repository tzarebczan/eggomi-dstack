"""Keeper handlers refuse forged authority and reload policy per call."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from cah.access import load_access
from cah.admission import admit_scoped
from cah.auth import AuthContext
from cah.crypto_lab import generate_private, public_key
from cah.grants import GrantStore, host_fence_paths
from cah.handlers import ServerState, dispatch
from cah.policy import load_policy, publish_revision
from cah.registry import AdmissionRegistry, WorkloadIdentity, save_registry
from cah.seal import guard_proof, proof_transcript

PROFILE = Path(__file__).resolve().parents[1] / "profiles" / "eggomi"
BROWSER_KEY = "11" * 32
BROKER_KEY = "22" * 32


def _identity(role: str, instance: str, channel: str | None = None) -> WorkloadIdentity:
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
        channel_public=channel,
    )


def _auth(identity: WorkloadIdentity) -> AuthContext:
    return AuthContext("unix-pidfd", True, None, identity)


def _prepare_body() -> dict[str, object]:
    return {
        "operation_id": "op-positive",
        "task_id": "task-lab-1",
        "resource_handle": "cred-lab-1",
        "origin": "https://lab.invalid/signin",
        "policy_revision": "pol-lab-1",
        "lease_id": "lease-lab-1",
        "lease_epoch": 1,
        "recipient_instance_id": "browser-1",
        "tenant": "tenant-lab-1",
        "audience_role": "credential-broker",
        "audience_instance": "broker-1",
        "field": "password",
    }


class HandlerTests(unittest.TestCase):
    """PrepareUse loads the keeper directory. Admission does not."""

    def test_forged_prepare_stores_nothing(self) -> None:
        """An attacker origin is refused before a grant row exists."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = _keeper(root)
            body = _prepare_body()
            body["origin"] = "https://attacker.example"
            forged = dispatch(
                state, _auth(_identity("omi-runner", "omi-1")), "PrepareUse", body
            )
            self.assertEqual(forged["code"], "denied_payload")
            self.assertFalse((root / "authority" / "grants.json").exists())
            ok = dispatch(
                state,
                _auth(_identity("omi-runner", "omi-1")),
                "PrepareUse",
                _prepare_body(),
            )
            self.assertTrue(ok["ok"], ok)
            stored = json.loads(
                (root / "authority" / "grants.json").read_text(encoding="utf-8")
            )
            origins = {row["policy"]["origin"] for row in stored["grants"].values()}
            self.assertEqual(origins, {"https://lab.invalid/signin"})
            row = next(iter(stored["grants"].values()))
            self.assertEqual(row["tenant"], "tenant-lab-1")
            self.assertEqual(row["field"], "password")
            self.assertEqual(row["audience"]["instance_id"], "broker-1")
            self.assertEqual(row["audience"]["channel_public"], BROKER_KEY)

    def test_prepare_reloads_the_current_revision(self) -> None:
        """A keeper rewrite is visible on the next PrepareUse without a restart."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = _keeper(root)
            first = dispatch(
                state,
                _auth(_identity("omi-runner", "omi-1")),
                "PrepareUse",
                _prepare_body(),
            )
            self.assertTrue(first["ok"], first)
            document = load_policy(PROFILE / "keeper-policy.json")
            document["policy_revision"] = "pol-lab-2"
            document["credentials"]["cred-lab-1"]["origins"] = [
                "https://other.invalid/signin"
            ]
            publish_revision(root / "authority" / "policy", document)
            stale = dispatch(
                state,
                _auth(_identity("omi-runner", "omi-1")),
                "PrepareUse",
                _prepare_body(),
            )
            self.assertEqual(stale["code"], "denied_payload")
            fresh = _prepare_body()
            fresh["policy_revision"] = "pol-lab-2"
            fresh["origin"] = "https://other.invalid/signin"
            fresh["operation_id"] = "op-copied"
            second = dispatch(
                state, _auth(_identity("omi-runner", "omi-1")), "PrepareUse", fresh
            )
            self.assertTrue(second["ok"], second)

    def test_second_prepare_for_one_operation_stores_nothing(self) -> None:
        """One approved operation yields one grant. A repeat is denied_payload."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = _keeper(root)
            omi = _auth(_identity("omi-runner", "omi-1"))
            first = dispatch(state, omi, "PrepareUse", _prepare_body())
            self.assertTrue(first["ok"], first)
            again = dispatch(state, omi, "PrepareUse", _prepare_body())
            self.assertEqual(again["code"], "denied_payload")
            stored = json.loads(
                (root / "authority" / "grants.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(stored["grants"]), 1)
            row = next(iter(stored["grants"].values()))
            self.assertEqual(row["lease"]["keeper_epoch"], 1)

    def test_observed_field_is_not_authority(self) -> None:
        """A body field named observed_* is refused before a grant is stored."""
        with tempfile.TemporaryDirectory() as tmp:
            state = _keeper(Path(tmp))
            body = _prepare_body()
            body["observed_peer_pid"] = "1"
            refused = dispatch(
                state, _auth(_identity("omi-runner", "omi-1")), "PrepareUse", body
            )
            self.assertEqual(refused["code"], "denied_authority_field")

    def test_unknown_outcome_is_queryable(self) -> None:
        """Unknown is stored and returned for the consumed grant's recipient."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = _keeper(root)
            issued = dispatch(
                state,
                _auth(_identity("omi-runner", "omi-1")),
                "PrepareUse",
                _prepare_body(),
            )
            self.assertTrue(issued["ok"], issued)
            assert state.grants is not None
            grant = state.grants.get(str(issued["body"]["grant_ref"]))
            assert grant is not None
            presenter = WorkloadIdentity(
                trust_domain="lab.cah",
                tenant="tenant-lab-1",
                role="browser-guard",
                instance_id="browser-1",
                boot_id="boot-browser-1",
                boot_generation=1,
                cert_fingerprint=None,
                pid=42,
                starttime=7,
                channel_public=BROWSER_KEY,
            )
            resolved = state.grants.resolve(
                str(grant["grant_ref"]),
                presenter,
                "https://lab.invalid/signin",
                "op-positive",
                "frame-1",
                "nav-1",
                broker_instance="broker-1",
                field="password",
                tenant="tenant-lab-1",
            )
            self.assertTrue(resolved["ok"], resolved)
            quiet = dispatch(
                state,
                _auth(_identity("omi-runner", "omi-1")),
                "QueryOutcome",
                {"operation_id": "op-positive"},
            )
            self.assertEqual(quiet["body"].get("outcome"), "unknown")
            reported = dispatch(
                state,
                _auth(presenter),
                "ReportOutcome",
                {"operation_id": "op-positive", "outcome": "unknown"},
            )
            self.assertTrue(reported["ok"], reported)
            queried = dispatch(
                state,
                _auth(presenter),
                "QueryOutcome",
                {"operation_id": "op-positive"},
            )
            self.assertEqual(queried["body"].get("outcome"), "unknown")
            asked = dispatch(
                state,
                _auth(_identity("omi-runner", "omi-1")),
                "QueryOutcome",
                {"operation_id": "op-positive"},
            )
            self.assertEqual(asked["body"].get("outcome"), "unknown")
            overwritten = dispatch(
                state,
                _auth(presenter),
                "ReportOutcome",
                {"operation_id": "op-positive", "outcome": "filled"},
            )
            self.assertEqual(overwritten["code"], "denied_payload")
            still = dispatch(
                state,
                _auth(_identity("omi-runner", "omi-1")),
                "QueryOutcome",
                {"operation_id": "op-positive"},
            )
            self.assertEqual(still["body"].get("outcome"), "unknown")
            other = _identity("browser-guard", "browser-2", "33" * 32)
            hidden = dispatch(
                state,
                _auth(other),
                "QueryOutcome",
                {"operation_id": "op-positive"},
            )
            self.assertEqual(hidden["code"], "denied_payload")

    def test_missing_secret_does_not_consume(self) -> None:
        """A seal that cannot be built leaves the grant issued."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keeper_sk = generate_private()
            browser_sk = generate_private()
            browser_pk = public_key(browser_sk).hex()
            state = _keeper(root, browser_key=browser_pk, keeper_private=keeper_sk)
            issued = dispatch(
                state,
                _auth(_identity("omi-runner", "omi-1")),
                "PrepareUse",
                _prepare_body(),
            )
            self.assertTrue(issued["ok"], issued)
            grant_ref = str(issued["body"]["grant_ref"])
            challenge = bytes(range(32))
            guard_public = public_key(browser_sk)
            transcript = proof_transcript(
                grant_ref=grant_ref,
                origin="https://lab.invalid/signin",
                operation_id="op-positive",
                frame_id="frame-1",
                navigation_generation="nav-1",
                challenge=challenge,
                guard_public=guard_public,
                field="password",
                tenant="tenant-lab-1",
            )
            proof = guard_proof(browser_sk, public_key(keeper_sk), transcript)
            body = {
                "grant_ref": grant_ref,
                "origin": "https://lab.invalid/signin",
                "operation_id": "op-positive",
                "frame_id": "frame-1",
                "navigation_generation": "nav-1",
                "guard_public": browser_pk,
                "proof": proof.hex(),
                "challenge": challenge.hex(),
                "field": "password",
                "tenant": "tenant-lab-1",
            }
            broker = _auth(_identity("credential-broker", "broker-1", BROKER_KEY))
            refused = dispatch(state, broker, "ResolveUseGrant", body)
            self.assertEqual(refused["code"], "denied_payload")
            assert state.grants is not None
            self.assertEqual(state.grants.get(grant_ref)["disposition"], "issued")
            secret = root / "authority" / "fill-secret"
            secret.write_text("cah-synthetic-fill-v1\n", encoding="utf-8")
            opened = dispatch(state, broker, "ResolveUseGrant", body)
            self.assertTrue(opened["ok"], opened)
            self.assertIn("sealed", opened["body"])
            self.assertEqual(state.grants.get(grant_ref)["disposition"], "consumed")

    def test_duplicate_instance_does_not_consume_the_new_token(self) -> None:
        """A second launcher admit for an existing instance leaves the new token unused."""
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
            journal_path, epoch_path = host_fence_paths(authority)
            grants = GrantStore(authority / "grants.json", journal_path, epoch_path)
            first = _admit(registry, authority, "token-1", "platform-launcher")
            self.assertTrue(first["ok"], first)
            second = _admit(registry, authority, "token-2", "platform-launcher")
            self.assertEqual(second["code"], "denied_bootstrap")
            import hashlib

            digest = hashlib.sha256(b"token-2").hexdigest()
            self.assertFalse(grants.bootstrap_used(digest))
            self.assertFalse((authority / "policy").exists())


def _keeper(
    root: Path,
    browser_key: str = BROWSER_KEY,
    broker_key: str = BROKER_KEY,
    keeper_private: bytes = bytes(32),
) -> ServerState:
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
                    "channel_public": browser_key,
                },
                {
                    "role": "credential-broker",
                    "instance_id": "broker-1",
                    "boot_id": "boot-broker-1",
                    "boot_generation": 1,
                    "boot_history": ["boot-broker-1"],
                    "cert_fingerprint": None,
                    "pid": 43,
                    "starttime": 8,
                    "channel_public": broker_key,
                },
            ],
        ),
    )
    publish_revision(authority / "policy", load_policy(PROFILE / "keeper-policy.json"))
    return ServerState(
        role="keeper-core",
        state=root,
        transport="unix",
        access=load_access(PROFILE / "service-access.json"),
        registry_path=registry,
        grants=GrantStore(authority / "grants.json"),
        keeper_addr=None,
        cert=None,
        key=None,
        ca=None,
        grant_ttl=60,
        policy_dir=authority / "policy",
        resource_handle=None,
        expect_server=None,
        authority=authority,
        channel_private=keeper_private,
        _lock=threading.Lock(),
    )


def _admit(
    registry: Path, authority: Path, token: str, caller_role: str
) -> dict[str, object]:
    import hashlib

    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    scope = {
        "token_sha256": digest,
        "used": False,
        "admit_role": "connector",
        "admit_instance_id": "connector-scoped-1",
        "admit_boot_id": "boot-connector-scoped-1",
    }
    path = authority / "bootstrap-scope.json"
    if not path.exists():
        path.write_text(json.dumps(scope) + "\n", encoding="utf-8")
    return admit_scoped(
        registry,
        authority,
        caller_role=caller_role,
        token=token,
        admit_role="connector",
        admit_instance="connector-scoped-1",
        admit_boot="boot-connector-scoped-1",
    )


if __name__ == "__main__":
    unittest.main()
