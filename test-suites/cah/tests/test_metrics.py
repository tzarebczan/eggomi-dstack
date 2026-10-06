"""Measurement provenance: null is not zero."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import unittest
from pathlib import Path

from cah.metrics import (
    MeasurementError,
    load_schema,
    measurement,
    sum_present,
    validate_record,
)

SCHEMA = load_schema(
    Path(__file__).resolve().parents[1] / "schemas" / "measurement.schema.json"
)


class MetricTests(unittest.TestCase):
    """resource-measurement/v1 invariants used by the harness."""

    def test_unavailable_rejects_numeric_zero(self) -> None:
        """A missing sample cannot be stored as 0."""
        record = measurement(
            SCHEMA,
            run_id="cah-fill-unix",
            metric_id="power_watts",
            measurement_scope="physical_host",
            role="aggregate",
            origin="unavailable",
            privacy="approved_aggregate",
            interval_seconds=1,
            value=None,
            sample_count=0,
            counter_reset=False,
            aggregation_basis="no host power counter was read",
            protected_attribution_ref=None,
            missing_reason="host power counter is not available on this lab vm",
            time_basis="utc_real",
            interval_start=None,
            observation_ref=None,
        )
        self.assertIsNone(record["value"])
        record["value"] = 0
        with self.assertRaises(MeasurementError):
            validate_record(record, SCHEMA)
        self.assertIsNone(
            sum_present(
                [
                    measurement(
                        SCHEMA,
                        run_id="cah-fill-unix",
                        metric_id="power_watts",
                        measurement_scope="physical_host",
                        role="aggregate",
                        origin="unavailable",
                        privacy="approved_aggregate",
                        interval_seconds=1,
                        value=None,
                        sample_count=0,
                        counter_reset=False,
                        aggregation_basis="no host power counter was read",
                        protected_attribution_ref=None,
                        missing_reason="host power counter is not available on this lab vm",
                        time_basis="utc_real",
                        interval_start=None,
                        observation_ref=None,
                    )
                ],
                "power_watts",
            )
        )

    def test_mixed_scope_and_partial_coverage_are_not_a_total(self) -> None:
        """A sum refuses mixed identities and does not drop an unavailable row."""
        present = measurement(
            SCHEMA,
            run_id="cah-fill-unix",
            metric_id="cpu_seconds",
            measurement_scope="component",
            role="credential-broker",
            origin="measured",
            privacy="protected_detail",
            interval_seconds=1,
            value=1.5,
            sample_count=1,
            counter_reset=False,
            aggregation_basis="one process counter",
            protected_attribution_ref="fill-v1",
            missing_reason=None,
            time_basis="utc_real",
            interval_start="2026-10-06T00:00:00Z",
            observation_ref="run:cah-fill-unix:cpu",
        )
        other_role = dict(present)
        other_role["role"] = "keeper-core"
        other_role["observation_ref"] = "run:cah-fill-unix:cpu-keeper"
        with self.assertRaises(MeasurementError):
            sum_present([present, other_role], "cpu_seconds")
        missing = dict(present)
        missing["origin"] = "unavailable"
        missing["privacy"] = "approved_aggregate"
        missing["value"] = None
        missing["sample_count"] = 0
        missing["protected_attribution_ref"] = None
        missing["observation_ref"] = None
        missing["interval_start"] = None
        missing["missing_reason"] = "second sample was not read"
        self.assertIsNone(sum_present([present, missing], "cpu_seconds"))
        self.assertEqual(sum_present([present], "cpu_seconds"), 1.5)


if __name__ == "__main__":
    unittest.main()
