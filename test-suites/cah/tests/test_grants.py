"""Use-grant consumption rules."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cah.grants import GrantStore
from cah.registry import WorkloadIdentity


def _id(
    role: str, instance: str, boot: str, fingerprint: str | None = None
) -> WorkloadIdentity:
    return WorkloadIdentity(
        trust_domain="lab.cah",
        tenant="tenant-lab-1",
        role=role,
        instance_id=instance,
        boot_id=boot,
        cert_fingerprint=fingerprint,
        pid=None,
    )


class GrantTests(unittest.TestCase):
    """Keeper-side grant checks without processes."""

    def test_wrong_boot_and_replay_do_not_widen_use(self) -> None:
        """A mismatched boot leaves the grant issued; a match consumes it."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            requester = _id("omi-runner", "omi-1", "boot-omi-1")
            recipient = _id("browser-guard", "browser-1", "boot-1")
            record = store.issue(
                requester,
                recipient,
                "pol",
                "cred",
                "https://lab.invalid/signin",
                "task",
                "op-1",
                "lease",
                1,
                60,
            )
            wrong_boot = _id("browser-guard", "browser-1", "boot-2")
            refused = store.resolve(
                record["grant_ref"], wrong_boot, "https://lab.invalid/signin", "op-1"
            )
            self.assertEqual(refused["code"], "denied_boot")
            self.assertEqual(store.get(record["grant_ref"])["disposition"], "issued")
            wrong_role = _id("omi-runner", "omi-1", "boot-1")
            copied = store.resolve(
                record["grant_ref"], wrong_role, "https://lab.invalid/signin", "op-1"
            )
            self.assertEqual(copied["code"], "denied_role")
            self.assertEqual(store.get(record["grant_ref"])["uses"], 0)
            ok = store.resolve(
                record["grant_ref"], recipient, "https://lab.invalid/signin", "op-1"
            )
            self.assertTrue(ok["ok"])
            again = store.resolve(
                record["grant_ref"], recipient, "https://lab.invalid/signin", "op-1"
            )
            self.assertEqual(again["code"], "grant_consumed")

    def test_expired_grant_is_not_zero_use(self) -> None:
        """An expired grant is refused and stays unconsumed."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            recipient = _id("browser-guard", "browser-1", "boot-1")
            record = store.issue(
                _id("omi-runner", "omi-1", "boot-omi-1"),
                recipient,
                "pol",
                "cred",
                "https://lab.invalid/signin",
                "task",
                "op-1",
                "lease",
                1,
                -1,
            )
            refused = store.resolve(
                record["grant_ref"], recipient, "https://lab.invalid/signin", "op-1"
            )
            self.assertEqual(refused["code"], "grant_expired")
            self.assertEqual(store.get(record["grant_ref"])["uses"], 0)


if __name__ == "__main__":
    unittest.main()
