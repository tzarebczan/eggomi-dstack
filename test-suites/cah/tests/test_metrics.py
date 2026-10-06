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


if __name__ == "__main__":
    unittest.main()
