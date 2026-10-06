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

WS1_ACCESS = (
    Path(__file__).resolve().parents[1] / "contracts" / "ws1" / "service-access.json"
)

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
        self.assertTrue(
            graph.permitted("browser-guard", "keeper-core", "QueryOutcome")
        )
        self.assertTrue(graph.permitted("omi-runner", "keeper-core", "QueryOutcome"))
        self.assertFalse(
            graph.permitted("credential-broker", "keeper-core", "QueryOutcome")
        )
        self.assertFalse(graph.permitted("omi-runner", "keeper-core", "AdmitWorkload"))
        self.assertFalse(graph.permitted("connector", "keeper-core", "Health"))
        self.assertIsNone(graph.bootstrap)

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

    def test_allow_edges_map_onto_ws1(self) -> None:
        """Every runtime edge is mapped, and real WS1 edges exist in the pin."""
        access = json.loads(PROFILE.read_text(encoding="utf-8"))
        mapping = json.loads(
            (PROFILE_DIR / "service-access-map.json").read_text(encoding="utf-8")
        )
        mapped = {
            (edge["caller_role"], edge["callee"], edge["method"])
            for edge in mapping["edges"]
        }
        for edge in access["allow"]:
            key = (edge["caller_role"], edge["callee"], edge["method"])
            self.assertIn(key, mapped)
        ws1 = json.loads(WS1_ACCESS.read_text(encoding="utf-8"))
        ws1_edges = {
            (edge["caller"], edge["callee"], edge["method"])
            for edge in ws1["allowed_edges"]
        }
        for edge in mapping["edges"]:
            if edge["ws1_method"] is None:
                self.assertTrue(edge["deviation"])
                continue
            triple = (edge["ws1_caller"], edge["ws1_callee"], edge["ws1_method"])
            self.assertIn(triple, ws1_edges)


if __name__ == "__main__":
    unittest.main()
