"""End-to-end host-native compartment demo."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cah.demo import CANARY, run_demo
from cah.metrics import load_schema, sum_present, validate_record

SCHEMA = load_schema(
    Path(__file__).resolve().parents[1] / "schemas" / "measurement.schema.json"
)


class DemoTests(unittest.TestCase):
    """Positive fill plus copied, wrong-role, and wrong-boot refusals."""

    def test_unix_peercred_fill(self) -> None:
        """Unix peer credentials drive the Eggomi profile fill."""
        self._run("unix")

    def test_mtls_fill_through_byte_forwarder(self) -> None:
        """Lab mTLS still identifies the browser through the byte forwarder."""
        self._run("mtls")

    def _run(self, transport: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = run_demo(Path(tmp) / "state", transport)
            self.assertTrue(report["ok"], json.dumps(report["cases"], indent=2))
            self.assertEqual(report["evidence_level"], "E1")
            self.assertEqual(report["ws_sim_id"], "WS-SIM06")
            self.assertEqual(report["ws1_evidence"], "process_e2e")
            self.assertFalse(report["outer_cvm"]["entered"])
            self.assertEqual(report["canary_leaks"], [])
            by_name = {row["name"]: row for row in report["cases"]}
            self.assertEqual(by_name["forged_origin"]["actual"], "denied_payload")
            self.assertEqual(by_name["hostile_navigation"]["actual"], "denied_payload")
            self.assertEqual(by_name["copied_wrong_role"]["actual"], "denied_role")
            self.assertEqual(
                by_name["copied_second_browser"]["actual"], "denied_recipient"
            )
            self.assertEqual(by_name["copied_owner_fill"]["actual"], "ok")
            if transport == "mtls":
                self.assertTrue(report["cn_ignored"])
                self.assertTrue(str(report["vsock"]).startswith("vsock:"))
            state = Path(tmp) / "state"
            positive = (state / "results" / "positive_fill.json").read_text(
                encoding="utf-8"
            )
            self.assertIn(CANARY, positive)
            stolen = (state / "results" / "copied_wrong_role.json").read_text(
                encoding="utf-8"
            )
            self.assertNotIn(CANARY, stolen)
            copied = (state / "results" / "copied_second_browser.json").read_text(
                encoding="utf-8"
            )
            self.assertNotIn(CANARY, copied)
            owner = (state / "results" / "copied_owner_fill.json").read_text(
                encoding="utf-8"
            )
            self.assertIn(CANARY, owner)
            records = json.loads(
                (state / "measurements.json").read_text(encoding="utf-8")
            )
            for record in records:
                validate_record(record, SCHEMA)
            self.assertIsNone(sum_present(records, "power_watts"))
            self.assertIsNone(sum_present(records, "tls_handshake_seconds"))
            handshake = next(
                row for row in records if row["metric_id"] == "tls_handshake_seconds"
            )
            self.assertEqual(handshake["origin"], "unavailable")
            self.assertIsNone(handshake["value"])
            denied = next(
                row
                for row in records
                if row["metric_id"] == "authorization_denied_count"
            )
            self.assertGreater(denied["value"], 0)


if __name__ == "__main__":
    unittest.main()
