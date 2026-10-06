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
            self.assertFalse(report["outer_cvm"]["entered"])
            self.assertEqual(report["canary_leaks"], [])
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
            records = json.loads(
                (state / "measurements.json").read_text(encoding="utf-8")
            )
            for record in records:
                validate_record(record, SCHEMA)
            self.assertIsNone(sum_present(records, "power_watts"))
            denied = next(
                row
                for row in records
                if row["metric_id"] == "authorization_denied_count"
            )
            self.assertGreater(denied["value"], 0)


if __name__ == "__main__":
    unittest.main()
