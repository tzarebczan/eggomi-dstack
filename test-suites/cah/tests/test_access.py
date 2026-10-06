"""Default-deny service-access checks."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import unittest
from pathlib import Path

from cah.access import load_access
from cah.demo import CLIENTS, SERVERS

PROFILE_DIR = Path(__file__).resolve().parents[1] / "profiles" / "eggomi"
PROFILE = PROFILE_DIR / "service-access.json"


class AccessTests(unittest.TestCase):
    """The Eggomi profile allow-list."""

    def test_default_deny_and_scoped_bootstrap(self) -> None:
        """Unknown edges are refused and bootstrap is one use."""
        graph = load_access(PROFILE)
        self.assertEqual(graph.profile, "eggomi")
        self.assertTrue(graph.permitted("omi-runner", "keeper-core", "PrepareUse"))
        self.assertTrue(
            graph.permitted("browser-guard", "credential-broker", "CompleteFill")
        )
        self.assertFalse(
            graph.permitted("omi-runner", "credential-broker", "CompleteFill")
        )
        self.assertFalse(graph.permitted("browser-guard", "keeper-core", "PrepareUse"))
        self.assertFalse(graph.permitted("omi-runner", "keeper-core", "AdmitWorkload"))
        self.assertFalse(graph.permitted("connector", "keeper-core", "Health"))
        self.assertIsNotNone(graph.bootstrap)
        assert graph.bootstrap is not None
        self.assertTrue(graph.bootstrap.one_use)
        self.assertEqual(graph.bootstrap.caller_role, "platform-launcher")

    def test_graph_matches_the_demo_instances(self) -> None:
        """The profile graph names the same instances the demo admits."""
        graph = json.loads((PROFILE_DIR / "graph.json").read_text(encoding="utf-8"))
        from_file = {
            (row["role"], row["instance_id"], row["boot_id"])
            for row in graph["compartments"]
        }
        from_demo = {
            (role, instance, boot) for role, instance, boot in SERVERS + CLIENTS
        }
        self.assertEqual(from_file, from_demo)


if __name__ == "__main__":
    unittest.main()
