"""Use-grant consumption, possession, and journal rules."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cah.grants import GrantStore
from cah.registry import WorkloadIdentity


def _id(
    role: str,
    instance: str,
    boot: str,
    fingerprint: str | None = "fp",
    pid: int | None = None,
    starttime: int | None = None,
    generation: int = 1,
) -> WorkloadIdentity:
    return WorkloadIdentity(
        trust_domain="lab.cah",
        tenant="tenant-lab-1",
        role=role,
        instance_id=instance,
        boot_id=boot,
        boot_generation=generation,
        cert_fingerprint=fingerprint,
        pid=pid,
        starttime=starttime,
    )


def _issue(store: GrantStore, recipient: WorkloadIdentity) -> dict[str, object]:
    return store.issue(
        _id("omi-runner", "omi-1", "boot-omi-1"),
        recipient,
        "pol",
        "cred",
        "https://lab.invalid/signin",
        "task",
        "op-1",
        "lease",
        1,
        60,
        "frame-1",
        "nav-1",
    )


class GrantTests(unittest.TestCase):
    """Keeper-side grant checks without processes."""

    def test_wrong_role_stays_issued_and_replay_is_consumed(self) -> None:
        """A role mismatch does not consume; a matching resolve does."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            recipient = _id("browser-guard", "browser-1", "boot-1")
            record = _issue(store, recipient)
            wrong_role = _id("omi-runner", "omi-1", "boot-1")
            copied = store.resolve(
                str(record["grant_ref"]),
                wrong_role,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(copied["code"], "denied_role")
            self.assertEqual(store.get(str(record["grant_ref"]))["uses"], 0)
            ok = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertTrue(ok["ok"])
            again = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(again["code"], "grant_consumed")

    def test_other_browser_and_missing_fingerprint_do_not_skip(self) -> None:
        """Instance and fingerprint mismatches stay issued."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            recipient = _id("browser-guard", "browser-1", "boot-1", fingerprint="aa")
            record = _issue(store, recipient)
            other = _id("browser-guard", "browser-2", "boot-2", fingerprint="aa")
            copied = store.resolve(
                str(record["grant_ref"]),
                other,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(copied["code"], "denied_recipient")
            self.assertEqual(
                store.get(str(record["grant_ref"]))["disposition"], "issued"
            )
            blank = _id("browser-guard", "browser-1", "boot-1", fingerprint=None)
            skipped = store.resolve(
                str(record["grant_ref"]),
                blank,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(skipped["code"], "denied_recipient")
            self.assertEqual(store.get(str(record["grant_ref"]))["uses"], 0)

    def test_null_fingerprint_still_checks_pid(self) -> None:
        """A missing certificate does not waive the process binding."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            recipient = _id(
                "browser-guard",
                "browser-1",
                "boot-1",
                fingerprint=None,
                pid=10,
                starttime=20,
            )
            record = _issue(store, recipient)
            other = _id(
                "browser-guard",
                "browser-1",
                "boot-1",
                fingerprint=None,
                pid=11,
                starttime=21,
            )
            refused = store.resolve(
                str(record["grant_ref"]),
                other,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(refused["code"], "denied_recipient")
            self.assertEqual(store.get(str(record["grant_ref"]))["uses"], 0)
            with self.assertRaises(ValueError):
                _issue(
                    store, _id("browser-guard", "browser-2", "boot-2", fingerprint=None)
                )

    def test_boot_generation_mismatch_revokes(self) -> None:
        """An older boot generation cannot resolve, and the grant does not stay usable."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            recipient = _id("browser-guard", "browser-1", "boot-1", generation=1)
            record = _issue(store, recipient)
            rolled = _id("browser-guard", "browser-1", "boot-1", generation=2)
            refused = store.resolve(
                str(record["grant_ref"]),
                rolled,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(refused["code"], "denied_boot")
            self.assertEqual(
                store.get(str(record["grant_ref"]))["disposition"], "revoked_boot"
            )
            again = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(again["code"], "denied_boot")

    def test_frame_mismatch_does_not_consume(self) -> None:
        """Navigation and frame must match the stored destination."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            recipient = _id("browser-guard", "browser-1", "boot-1")
            record = _issue(store, recipient)
            refused = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-replaced",
            )
            self.assertEqual(refused["code"], "denied_payload")
            self.assertEqual(store.get(str(record["grant_ref"]))["uses"], 0)
            ok = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertTrue(ok["ok"])

    def test_restored_pre_consume_snapshot_stays_consumed(self) -> None:
        """The journal wins over a grants file from before consumption."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "grants.json"
            store = GrantStore(path)
            recipient = _id("browser-guard", "browser-1", "boot-1")
            record = _issue(store, recipient)
            snapshot = path.read_bytes()
            epoch = (root / "keeper-epoch").read_bytes()
            ok = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertTrue(ok["ok"])
            path.write_bytes(snapshot)
            (root / "keeper-epoch").write_bytes(epoch)
            reloaded = GrantStore(path)
            again = reloaded.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(again["code"], "grant_consumed")
            restored = reloaded.get(str(record["grant_ref"]))
            self.assertIsNotNone(restored)
            assert restored is not None
            self.assertEqual(restored["disposition"], "consumed")

    def test_bootstrap_journal_survives_reload(self) -> None:
        """A spent bootstrap token stays spent after the store is reopened."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "grants.json"
            store = GrantStore(path)
            store.note_bootstrap("abc")
            self.assertTrue(store.bootstrap_used("abc"))
            reloaded = GrantStore(path)
            self.assertTrue(reloaded.bootstrap_used("abc"))

    def test_expired_grant_is_not_zero_use(self) -> None:
        """An expired grant is refused and stays unconsumed."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "grants.json"
            store = GrantStore(path)
            recipient = _id("browser-guard", "browser-1", "boot-1")
            record = _issue(store, recipient)
            raw = json.loads(path.read_text(encoding="utf-8"))
            lease = raw["grants"][record["grant_ref"]]["lease"]
            lease["expires_unix"] = float(lease["issued_unix"]) - 1
            path.write_text(json.dumps(raw) + "\n", encoding="utf-8")
            reloaded = GrantStore(path)
            refused = reloaded.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(refused["code"], "grant_expired")
            self.assertEqual(reloaded.get(str(record["grant_ref"]))["uses"], 0)

    def test_ttl_above_cap_is_refused(self) -> None:
        """Use ttl cannot exceed 60 seconds."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            with self.assertRaises(ValueError):
                store.issue(
                    _id("omi-runner", "omi-1", "boot-omi-1"),
                    _id("browser-guard", "browser-1", "boot-1"),
                    "pol",
                    "cred",
                    "https://lab.invalid/signin",
                    "task",
                    "op-1",
                    "lease",
                    1,
                    61,
                    "frame-1",
                    "nav-1",
                )


if __name__ == "__main__":
    unittest.main()
