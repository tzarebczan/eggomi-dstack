"""Keeper policy is the PrepareUse authority."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import unittest
from pathlib import Path

from cah.policy import evaluate_prepare, load_policy

POLICY = (
    Path(__file__).resolve().parents[1] / "profiles" / "eggomi" / "keeper-policy.json"
)


def _body() -> dict[str, object]:
    return {
        "operation_id": "op-positive",
        "task_id": "task-lab-1",
        "resource_handle": "cred-lab-1",
        "origin": "https://lab.invalid/signin",
        "policy_revision": "pol-lab-1",
        "lease_id": "lease-lab-1",
        "lease_epoch": 1,
        "recipient_instance_id": "browser-1",
    }


class PolicyTests(unittest.TestCase):
    """A requester cannot choose origin, lease, or recipient."""

    def test_matching_prepare_uses_policy_destination(self) -> None:
        """A matching body returns the policy frame and navigation."""
        prepared = evaluate_prepare(load_policy(POLICY), _body())
        self.assertIsNotNone(prepared)
        assert prepared is not None
        self.assertEqual(prepared.origin, "https://lab.invalid/signin")
        self.assertEqual(prepared.frame_id, "frame-1")
        self.assertEqual(prepared.navigation_generation, "nav-1")
        self.assertEqual(prepared.recipient_instance_id, "browser-1")

    def test_forged_origin_is_refused(self) -> None:
        """An attacker origin does not become the stored policy."""
        forged = _body()
        forged["origin"] = "https://attacker.example"
        self.assertIsNone(evaluate_prepare(load_policy(POLICY), forged))

    def test_forged_recipient_is_refused(self) -> None:
        """The requester cannot retarget the lease."""
        forged = _body()
        forged["recipient_instance_id"] = "browser-2"
        self.assertIsNone(evaluate_prepare(load_policy(POLICY), forged))


if __name__ == "__main__":
    unittest.main()
