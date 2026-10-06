"""Resource measurements in the WSE ``resource-measurement/v1`` shape.

``origin=unavailable`` keeps ``value`` null. Callers must not substitute 0.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "resource-measurement/v1"
REQUIRED = (
    "schema_version",
    "run_id",
    "metric_id",
    "unit",
    "measurement_scope",
    "role",
    "origin",
    "privacy",
    "interval_seconds",
    "value",
    "sample_count",
    "counter_reset",
    "aggregation_basis",
    "protected_attribution_ref",
    "missing_reason",
    "time_basis",
    "interval_start",
    "observation_ref",
)


class MeasurementError(ValueError):
    """A record violated the measurement contract."""


def load_schema(path: Path) -> Dict[str, Any]:
    """Load the pinned measurement schema."""
    return json.loads(path.read_text(encoding="utf-8"))


def unit_for(schema: Dict[str, Any], metric_id: str) -> str:
    """Read the schema's unit constraint for one metric id."""
    for cond in schema.get("allOf", []):
        const = (
            cond.get("if", {}).get("properties", {}).get("metric_id", {}).get("const")
        )
        if const == metric_id:
            return str(cond["then"]["properties"]["unit"]["const"])
    raise MeasurementError(f"metric {metric_id} has no unit constraint")


def measurement(
    schema: Dict[str, Any],
    *,
    run_id: str,
    metric_id: str,
    measurement_scope: str,
    role: str,
    origin: str,
    privacy: str,
    interval_seconds: float,
    value: Optional[float],
    sample_count: int,
    counter_reset: bool,
    aggregation_basis: str,
    protected_attribution_ref: Optional[str],
    missing_reason: Optional[str],
    time_basis: str,
    interval_start: Optional[str],
    observation_ref: Optional[str],
) -> Dict[str, Any]:
    """Build one record and reject contract violations before it is stored."""
    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "metric_id": metric_id,
        "unit": unit_for(schema, metric_id),
        "measurement_scope": measurement_scope,
        "role": role,
        "origin": origin,
        "privacy": privacy,
        "interval_seconds": interval_seconds,
        "value": value,
        "sample_count": sample_count,
        "counter_reset": counter_reset,
        "aggregation_basis": aggregation_basis,
        "protected_attribution_ref": protected_attribution_ref,
        "missing_reason": missing_reason,
        "time_basis": time_basis,
        "interval_start": interval_start,
        "observation_ref": observation_ref,
    }
    validate_record(record, schema)
    return record


def validate_record(record: Dict[str, Any], schema: Dict[str, Any]) -> None:
    """Validate one record against the pinned schema's invariants."""
    missing = [key for key in REQUIRED if key not in record]
    if missing:
        raise MeasurementError("measurement is missing " + ",".join(missing))
    extra = [key for key in record if key not in REQUIRED]
    if extra:
        raise MeasurementError("measurement has unknown fields " + ",".join(extra))
    if record["schema_version"] != SCHEMA_VERSION:
        raise MeasurementError("measurement schema_version is wrong")
    _enum(schema, "metric_id", record["metric_id"])
    _enum(schema, "measurement_scope", record["measurement_scope"])
    _enum(schema, "role", record["role"])
    _enum(schema, "origin", record["origin"])
    _enum(schema, "privacy", record["privacy"])
    _enum(schema, "time_basis", record["time_basis"])
    if record["unit"] != unit_for(schema, record["metric_id"]):
        raise MeasurementError("measurement unit does not match the metric")
    if (
        not isinstance(record["interval_seconds"], (int, float))
        or record["interval_seconds"] <= 0
    ):
        raise MeasurementError("interval_seconds must be greater than 0")
    if record["origin"] == "unavailable":
        if record["value"] is not None:
            raise MeasurementError(
                "unavailable measurement value must be null, not a number"
            )
        if record["sample_count"] != 0:
            raise MeasurementError("unavailable measurement sample_count must be 0")
        if (
            not isinstance(record["missing_reason"], str)
            or not record["missing_reason"]
        ):
            raise MeasurementError("unavailable measurement needs missing_reason")
    else:
        if isinstance(record["value"], bool) or not isinstance(
            record["value"], (int, float)
        ):
            raise MeasurementError("measured value must be a number")
        if not isinstance(record["sample_count"], int) or record["sample_count"] < 1:
            raise MeasurementError("present measurement needs sample_count >= 1")
        if record["missing_reason"] is not None:
            raise MeasurementError("present measurement missing_reason must be null")
        if record["origin"] == "measured":
            if record["time_basis"] not in {"monotonic_real", "utc_real"}:
                raise MeasurementError("measured time_basis must be real")
            if (
                not isinstance(record["interval_start"], str)
                or not record["interval_start"]
            ):
                raise MeasurementError("measured interval_start is required")
    if record["privacy"] == "approved_aggregate":
        if record["protected_attribution_ref"] is not None:
            raise MeasurementError(
                "approved aggregate cannot carry a protected attribution ref"
            )
        if record["observation_ref"] is not None:
            raise MeasurementError("approved aggregate cannot carry an observation ref")
    if record["origin"] == "measured" and record["privacy"] == "protected_detail":
        if (
            not isinstance(record["observation_ref"], str)
            or not record["observation_ref"]
        ):
            raise MeasurementError("protected measured row needs observation_ref")
    if not isinstance(record["counter_reset"], bool):
        raise MeasurementError("counter_reset must be a boolean")
    if (
        not isinstance(record["aggregation_basis"], str)
        or not record["aggregation_basis"]
    ):
        raise MeasurementError("aggregation_basis is required")


def sum_present(records: List[Dict[str, Any]], metric_id: str) -> Optional[float]:
    """Sum present values for one metric inside one scope and role.

    Rows for other metrics are ignored. A mix of ``measurement_scope`` or
    ``role`` for this metric is refused. If any selected row is unavailable,
    the result is ``None`` rather than a partial total. ``None`` is not zero.
    """
    selected = [record for record in records if record["metric_id"] == metric_id]
    if not selected:
        return None
    identities = {(record["measurement_scope"], record["role"]) for record in selected}
    if len(identities) > 1:
        raise MeasurementError("refusing to sum a metric across scopes or roles")
    total = 0.0
    for record in selected:
        if record["origin"] == "unavailable":
            if record["value"] is not None:
                raise MeasurementError("refusing to skip a non-null unavailable value")
            return None
        total += float(record["value"])
    return total


def _enum(schema: Dict[str, Any], field: str, value: object) -> None:
    allowed = schema["properties"][field]["enum"]
    if value not in allowed:
        raise MeasurementError(f"{field} is not in the schema enum")
