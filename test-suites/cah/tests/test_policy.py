"""Keeper policy is the PrepareUse authority."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cah.policy import evaluate_prepare, load_current, load_policy, publish_revision

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
        "tenant": "tenant-lab-1",
        "audience_role": "credential-broker",
        "audience_instance": "broker-1",
        "field": "password",
    }


class PolicyTests(unittest.TestCase):
    """A requester cannot choose origin, lease, or recipient."""

    def test_matching_prepare_uses_policy_destination(self) -> None:
        """A matching body returns the policy frame and navigation."""
        prepared = evaluate_prepare(load_policy(POLICY), _body(), "omi-1")
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
        self.assertIsNone(evaluate_prepare(load_policy(POLICY), forged, "omi-1"))

    def test_other_requester_cannot_spend_the_operation(self) -> None:
        """The operation names its requester. Another admitted runner is refused."""
        self.assertIsNone(evaluate_prepare(load_policy(POLICY), _body(), "omi-2"))

    def test_forged_recipient_is_refused(self) -> None:
        """The requester cannot retarget the lease."""
        forged = _body()
        forged["recipient_instance_id"] = "browser-2"
        self.assertIsNone(evaluate_prepare(load_policy(POLICY), forged, "omi-1"))

    def test_publish_is_reloaded_and_immutable(self) -> None:
        """The current pointer changes, and an existing revision id cannot."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            document = load_policy(POLICY)
            publish_revision(directory, document)
            self.assertEqual(load_current(directory)["policy_revision"], "pol-lab-1")
            nxt = json.loads(json.dumps(document))
            nxt["policy_revision"] = "pol-lab-2"
            nxt["tenant"] = "tenant-lab-2"
            publish_revision(directory, nxt)
            loaded = load_current(directory)
            self.assertEqual(loaded["tenant"], "tenant-lab-2")
            prepared = evaluate_prepare(loaded, _body(), "omi-1")
            self.assertIsNone(prepared)
            changed = json.loads(json.dumps(nxt))
            changed["tenant"] = "tenant-other"
            with self.assertRaises(ValueError):
                publish_revision(directory, changed)
            with self.assertRaises(ValueError):
                publish_revision(directory, document)
            self.assertEqual(load_current(directory)["policy_revision"], "pol-lab-2")


if __name__ == "__main__":
    unittest.main()
