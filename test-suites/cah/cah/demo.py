"""Host-native Eggomi-profile fill demo.

This is an E1 lab run: real processes and the use-grant checks, without a
confidential VM. When KVM is present but QEMU or a dev image is not, the
outer simulated-SNP substrate is left unentered and the fidelity label stays
E1.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .metrics import load_schema, measurement, sum_present, validate_record
from .registry import (
    AdmissionRegistry,
    bind_process,
    load_registry,
    save_registry,
    set_boot,
)
from .tls_lab import LabMaterial, issue_lab
from .vsock import placeholder

CANARY = "cah-synthetic-fill-v1"
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PROFILE = PACKAGE_ROOT / "profiles" / "eggomi"
SCHEMA_PATH = PACKAGE_ROOT / "schemas" / "measurement.schema.json"
TRUST_DOMAIN = "lab.cah"
TENANT = "tenant-lab-1"
SERVERS = (
    ("keeper-core", "keeper-1", "boot-keeper-1"),
    ("credential-broker", "broker-1", "boot-broker-1"),
    ("connector", "connector-1", "boot-connector-1"),
)
CLIENTS = (
    ("browser-guard", "browser-1", "boot-browser-1"),
    ("omi-runner", "omi-1", "boot-omi-1"),
    ("platform-launcher", "launcher-1", "boot-launcher-1"),
)


def main(argv: Optional[List[str]] = None) -> int:
    """Run the fill demo and write a report plus measurement records."""
    parser = argparse.ArgumentParser(description="run the CAH host-native fill demo")
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--transport", choices=("unix", "mtls"), default="unix")
    parser.add_argument("--grant-ttl", type=float, default=120)
    args = parser.parse_args(argv)
    report = run_demo(args.state, args.transport, args.grant_ttl)
    print(
        json.dumps(
            {"ok": report["ok"], "evidence_level": report["evidence_level"]},
            sort_keys=True,
        )
    )
    return 0 if report["ok"] else 1


def run_demo(state: Path, transport: str, grant_ttl: float = 120) -> Dict[str, Any]:
    """Execute positive fill and refusal cases. Return the run report."""
    if state.exists():
        shutil.rmtree(state)
    state.mkdir(parents=True)
    started = time.time()
    interval_start = datetime.now(timezone.utc).isoformat()
    material: Optional[LabMaterial] = None
    instances = [(role, instance) for role, instance, _boot in SERVERS + CLIENTS]
    instances.append(("browser-guard", "stranger-1"))
    if transport == "mtls":
        material = issue_lab(state / "certs", TRUST_DOMAIN, TENANT, instances)
    _write_registry(state, material)
    access = PROFILE / "service-access.json"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PACKAGE_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUNBUFFERED"] = "1"
    procs: List[subprocess.Popen[bytes]] = []
    logs: List[Any] = []
    forwarder = None
    broker_pid: Optional[int] = None
    try:
        keeper_addr = _start_server(
            procs,
            logs,
            state,
            env,
            transport,
            material,
            "keeper-core",
            "keeper-1",
            access,
            "",
            grant_ttl,
        )
        broker_addr = _start_server(
            procs,
            logs,
            state,
            env,
            transport,
            material,
            "credential-broker",
            "broker-1",
            access,
            keeper_addr,
            grant_ttl,
        )
        broker_pid = procs[-1].pid
        connector_addr = _start_server(
            procs,
            logs,
            state,
            env,
            transport,
            material,
            "connector",
            "connector-1",
            access,
            "",
            grant_ttl,
        )
        broker_public = broker_addr
        vsock_label = ""
        if transport == "mtls":
            forwarder = placeholder(3, 5200, broker_addr)
            broker_public = forwarder.endpoint()
            vsock_label = forwarder.label
        elif transport == "unix":
            # The unix path is the compartment channel. The placeholder is
            # still constructed against a discard upstream in the unit tests.
            vsock_label = "not-used"
        cases = _run_cases(
            state, env, transport, material, keeper_addr, broker_public, connector_addr
        )
        canary_hits = _canary_hits(state)
        measurements = _measurements(
            state,
            transport,
            started,
            interval_start,
            cases,
            broker_pid,
            material,
        )
        try:
            dispositions_ok = _grant_dispositions(state)
        except (KeyError, OSError, json.JSONDecodeError):
            dispositions_ok = False
        ok = all(row["actual"] == row["expect"] for row in cases) and not canary_hits
        ok = ok and dispositions_ok
        report: Dict[str, Any] = {
            "schema_version": "cah-run-report/v1",
            "ok": ok,
            "evidence_level": "E1",
            "deployment_class": "L",
            "fidelity": "host-native",
            "transport": "unix-peercred" if transport == "unix" else "mtls",
            "profile": "eggomi",
            "scenario_port": "fill-v1",
            "retired_scenario_alias": "J06",
            "ws_sim_id": None,
            "pristine_templates_only": True,
            "spire": "deferred",
            "nested_smolvm": "deferred",
            "vsock": vsock_label
            if transport == "mtls"
            else "byte-forward placeholder; unix peercred used for RPC",
            "cn_ignored": _cn_ignored(material) if material else None,
            "outer_cvm": _outer_cvm(),
            "cases": cases,
            "canary_leaks": canary_hits,
            "measurements": str(state / "measurements.json"),
        }
        (state / "report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (state / "measurements.json").write_text(
            json.dumps(measurements, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if CANARY.encode() in (state / "report.json").read_bytes():
            report["ok"] = False
            report["canary_leaks"].append("report.json")
            (state / "report.json").write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        return report
    finally:
        if forwarder is not None:
            forwarder.close()
        for handle in logs:
            handle.close()
        stop = state / "stop"
        stop.write_text("stop\n", encoding="utf-8")
        deadline = time.monotonic() + 2
        for proc in procs:
            while time.monotonic() < deadline and proc.poll() is None:
                time.sleep(0.05)
            if proc.poll() is None:
                proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()


def _run_cases(
    state: Path,
    env: Dict[str, str],
    transport: str,
    material: Optional[LabMaterial],
    keeper: str,
    broker: str,
    connector: str,
) -> List[Dict[str, str]]:
    cases: List[Dict[str, str]] = []

    def case(
        name: str,
        mode: str,
        role: str,
        instance: str,
        expect: str,
        *,
        operation_id: str = "op-unused",
        grant_ref: Optional[str] = None,
        token: Optional[str] = None,
        admit: bool = True,
        stranger: bool = False,
    ) -> Dict[str, Any]:
        """Run one client process and record the RPC code."""
        result = _client(
            state,
            env,
            transport,
            material,
            keeper,
            broker,
            connector,
            name,
            mode,
            role,
            instance,
            operation_id,
            grant_ref,
            token,
            admit,
            stranger,
        )
        cases.append({"name": name, "expect": expect, "actual": str(result["code"])})
        return result

    case(
        "smuggle_authority_field",
        "smuggle",
        "omi-runner",
        "omi-1",
        "denied_authority_field",
    )
    case(
        "browser_cannot_prepare",
        "prepare",
        "browser-guard",
        "browser-1",
        "denied_role",
        operation_id="op-browser",
    )
    prepared = case(
        "prepare_positive",
        "prepare",
        "omi-runner",
        "omi-1",
        "ok",
        operation_id="op-positive",
    )
    filled = case(
        "positive_fill",
        "fill",
        "browser-guard",
        "browser-1",
        "ok",
        operation_id="op-positive",
        grant_ref=str(prepared["grant_ref"]),
    )
    if filled.get("fill") != CANARY:
        cases.append(
            {"name": "positive_fill_value", "expect": "present", "actual": "missing"}
        )
    case(
        "outcome",
        "outcome",
        "browser-guard",
        "browser-1",
        "ok",
        operation_id="op-positive",
    )
    case(
        "replay_consumed",
        "fill",
        "browser-guard",
        "browser-1",
        "grant_consumed",
        operation_id="op-positive",
        grant_ref=str(prepared["grant_ref"]),
    )
    copied = case(
        "prepare_copied",
        "prepare",
        "omi-runner",
        "omi-1",
        "ok",
        operation_id="op-copied",
    )
    case(
        "copied_wrong_role",
        "steal",
        "omi-runner",
        "omi-1",
        "denied_role",
        operation_id="op-copied",
        grant_ref=str(copied["grant_ref"]),
    )
    boot_grant = case(
        "prepare_wrong_boot",
        "prepare",
        "omi-runner",
        "omi-1",
        "ok",
        operation_id="op-boot",
    )
    set_boot(state / "admission.json", "browser-1", "boot-browser-2")
    case(
        "wrong_boot",
        "fill",
        "browser-guard",
        "browser-1",
        "denied_boot",
        operation_id="op-boot",
        grant_ref=str(boot_grant["grant_ref"]),
    )
    case("connector_default_deny", "poke", "omi-runner", "omi-1", "denied_role")
    case(
        "unadmitted",
        "prepare",
        "browser-guard",
        "stranger-1",
        "denied_unadmitted",
        operation_id="op-stranger",
        admit=False,
        stranger=True,
    )
    token = _write_bootstrap(state)
    case(
        "bootstrap_wrong_role",
        "bootstrap-steal",
        "omi-runner",
        "omi-1",
        "denied_role",
        token=token,
    )
    case(
        "bootstrap_wrong_scope",
        "bootstrap-scope",
        "platform-launcher",
        "launcher-1",
        "denied_bootstrap",
        token=token,
    )
    case(
        "bootstrap_ok",
        "bootstrap",
        "platform-launcher",
        "launcher-1",
        "ok",
        token=token,
    )
    case(
        "bootstrap_replay",
        "bootstrap",
        "platform-launcher",
        "launcher-1",
        "denied_bootstrap",
        token=token,
    )
    return cases


def _client(
    state: Path,
    env: Dict[str, str],
    transport: str,
    material: Optional[LabMaterial],
    keeper: str,
    broker: str,
    connector: str,
    case: str,
    mode: str,
    role: str,
    instance: str,
    operation_id: str,
    grant_ref: Optional[str],
    token: Optional[str],
    admit: bool,
    stranger: bool,
) -> Dict[str, Any]:
    fixture = json.loads((PROFILE / "fill-fixture.json").read_text(encoding="utf-8"))
    fixture["operation_id"] = operation_id
    fixture_path = state / "fixtures" / f"{case}.json"
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
    grant_path = None
    if grant_ref is not None:
        grant_path = state / "fixtures" / f"{case}.grant"
        grant_path.write_text(grant_ref + "\n", encoding="utf-8")
    cmd = [
        sys.executable,
        "-m",
        "cah.client",
        "--state",
        str(state),
        "--case",
        case,
        "--mode",
        mode,
        "--transport",
        transport,
        "--keeper",
        keeper,
        "--broker",
        broker,
        "--connector",
        connector,
        "--fixture",
        str(fixture_path),
    ]
    if grant_path is not None:
        cmd.extend(["--grant-file", str(grant_path)])
    if transport == "mtls":
        if material is None:
            raise RuntimeError("mtls transport is missing lab certificates")
        issued = material.for_instance(instance)
        cmd.extend(
            [
                "--cert",
                str(issued.cert_path),
                "--key",
                str(issued.key_path),
                "--ca",
                str(material.ca_cert),
            ]
        )
        if stranger:
            cmd.append("--unadmitted-cert")
    log_path = state / "logs" / f"{case}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if token is not None else subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
        )
        if admit and not stranger:
            bind_process(state / "admission.json", instance, proc.pid)
        (state / "go" / str(proc.pid)).parent.mkdir(parents=True, exist_ok=True)
        (state / "go" / str(proc.pid)).write_text("go\n", encoding="utf-8")
        if token is not None and proc.stdin is not None:
            proc.stdin.write((token + "\n").encode("utf-8"))
            proc.stdin.close()
        try:
            code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise RuntimeError(f"client {case} timed out") from None
    if code != 0:
        detail = log_path.read_text(encoding="utf-8")
        raise RuntimeError(f"client {case} exited {code}: {detail}")
    return json.loads((state / "results" / f"{case}.json").read_text(encoding="utf-8"))


def _start_server(
    procs: List[subprocess.Popen[bytes]],
    logs: List[Any],
    state: Path,
    env: Dict[str, str],
    transport: str,
    material: Optional[LabMaterial],
    role: str,
    instance: str,
    access: Path,
    keeper: str,
    grant_ttl: float,
) -> str:
    if transport == "unix":
        listen = "unix:" + str(state / "socks" / f"{role}.sock")
    else:
        listen = "tcp:127.0.0.1:0"
    cmd = [
        sys.executable,
        "-m",
        "cah.serve",
        "--role",
        role,
        "--state",
        str(state),
        "--transport",
        transport,
        "--listen",
        listen,
        "--access",
        str(access),
        "--grant-ttl",
        str(grant_ttl),
    ]
    if keeper:
        cmd.extend(["--keeper", keeper])
    if transport == "mtls":
        if material is None:
            raise RuntimeError("mtls transport is missing lab certificates")
        issued = material.for_instance(instance)
        cmd.extend(
            [
                "--cert",
                str(issued.cert_path),
                "--key",
                str(issued.key_path),
                "--ca",
                str(material.ca_cert),
            ]
        )
    log_path = state / "logs" / f"{role}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("w", encoding="utf-8")
    logs.append(log)
    stdin: Any = subprocess.PIPE if role == "credential-broker" else subprocess.DEVNULL
    proc = subprocess.Popen(
        cmd, stdin=stdin, stdout=log, stderr=subprocess.STDOUT, env=env
    )
    procs.append(proc)
    if role == "credential-broker" and proc.stdin is not None:
        proc.stdin.write((CANARY + "\n").encode("utf-8"))
        proc.stdin.close()
    bind_process(state / "admission.json", instance, proc.pid)
    return _wait_ready(state, role, proc, log_path)


def _wait_ready(
    state: Path, role: str, proc: subprocess.Popen[bytes], log_path: Path
) -> str:
    ready = state / "ready" / role
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if ready.exists():
            return ready.read_text(encoding="utf-8").strip()
        if proc.poll() is not None:
            raise RuntimeError(
                f"{role} exited early: {log_path.read_text(encoding='utf-8')}"
            )
        time.sleep(0.02)
    raise RuntimeError(
        f"{role} did not become ready: {log_path.read_text(encoding='utf-8')}"
    )


def _write_registry(state: Path, material: Optional[LabMaterial]) -> None:
    workloads = []
    for role, instance, boot in SERVERS + CLIENTS:
        fingerprint = None
        if material is not None:
            fingerprint = material.for_instance(instance).fingerprint
        workloads.append(
            {
                "role": role,
                "instance_id": instance,
                "boot_id": boot,
                "cert_fingerprint": fingerprint,
                "pid": None,
            }
        )
    save_registry(
        state / "admission.json",
        AdmissionRegistry(
            trust_domain=TRUST_DOMAIN, tenant=TENANT, workloads=workloads
        ),
    )


def _write_bootstrap(state: Path) -> str:
    token = "bootstrap-" + hashlib.sha256(os.urandom(32)).hexdigest()
    scope = {
        "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "admit_role": "connector",
        "admit_instance_id": "connector-scoped-1",
        "admit_boot_id": "boot-connector-scoped-1",
        "used": False,
    }
    path = state / "bootstrap-scope.json"
    path.write_text(
        json.dumps(scope, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.chmod(path, 0o600)
    return token


def _grant_dispositions(state: Path) -> bool:
    raw = json.loads((state / "grants.json").read_text(encoding="utf-8"))
    by_op = {row["task"]["operation_id"]: row for row in raw.values()}
    if by_op["op-positive"]["disposition"] != "consumed":
        return False
    if by_op["op-copied"]["disposition"] != "issued":
        return False
    if by_op["op-boot"]["disposition"] != "issued":
        return False
    scope = json.loads((state / "bootstrap-scope.json").read_text(encoding="utf-8"))
    if scope.get("used") is not True:
        return False
    registry = load_registry(state / "admission.json")
    return registry.find_instance("connector-scoped-1") is not None


def _canary_hits(state: Path) -> List[str]:
    hits = []
    needle = CANARY.encode("utf-8")
    for path in state.rglob("*"):
        if not path.is_file():
            continue
        if path.name == "positive_fill.json":
            continue
        if needle in path.read_bytes():
            hits.append(str(path.relative_to(state)))
    return hits


def _measurements(
    state: Path,
    transport: str,
    started: float,
    interval_start: str,
    cases: List[Dict[str, str]],
    broker_pid: Optional[int],
    material: Optional[LabMaterial],
) -> List[Dict[str, Any]]:
    schema = load_schema(SCHEMA_PATH)
    elapsed = max(time.time() - started, 0.001)
    run_id = "cah-fill-" + transport
    denials = sum(
        1 for case in cases if case["actual"] != "ok" and case["expect"] != "present"
    )
    positive = json.loads(
        (state / "results" / "positive_fill.json").read_text(encoding="utf-8")
    )
    records = [
        measurement(
            schema,
            run_id=run_id,
            metric_id="authorization_denied_count",
            measurement_scope="component",
            role="aggregate",
            origin="measured",
            privacy="protected_detail",
            interval_seconds=elapsed,
            value=denials,
            sample_count=1,
            counter_reset=False,
            aggregation_basis="count of refused rpc responses in this host-native run",
            protected_attribution_ref="fill-v1",
            missing_reason=None,
            time_basis="utc_real",
            interval_start=interval_start,
            observation_ref=f"run:{run_id}:denials",
        ),
        measurement(
            schema,
            run_id=run_id,
            metric_id="browser_action_seconds",
            measurement_scope="operation",
            role="browser-guard",
            origin="measured",
            privacy="protected_detail",
            interval_seconds=elapsed,
            value=float(positive["seconds"]),
            sample_count=1,
            counter_reset=False,
            aggregation_basis="wall time of the successful completefill rpc",
            protected_attribution_ref="fill-v1",
            missing_reason=None,
            time_basis="utc_real",
            interval_start=interval_start,
            observation_ref=f"run:{run_id}:fill",
        ),
        _resource(
            schema,
            run_id,
            elapsed,
            interval_start,
            "cpu_seconds",
            broker_pid,
            _cpu_seconds,
        ),
        _resource(
            schema,
            run_id,
            elapsed,
            interval_start,
            "memory_resident_bytes",
            broker_pid,
            _rss_bytes,
        ),
        _tls_record(schema, run_id, elapsed, interval_start, transport, positive),
        _identity_record(schema, run_id, elapsed, interval_start, transport, material),
        measurement(
            schema,
            run_id=run_id,
            metric_id="power_watts",
            measurement_scope="physical_host",
            role="aggregate",
            origin="unavailable",
            privacy="approved_aggregate",
            interval_seconds=elapsed,
            value=None,
            sample_count=0,
            counter_reset=False,
            aggregation_basis="no host power counter was read",
            protected_attribution_ref=None,
            missing_reason="host power counter is not available on this lab vm",
            time_basis="utc_real",
            interval_start=None,
            observation_ref=None,
        ),
    ]
    for record in records:
        validate_record(record, schema)
    if sum_present(records, "power_watts") is not None:
        raise RuntimeError("unavailable power was coerced away from null")
    return records


def _resource(
    schema: Dict[str, Any],
    run_id: str,
    elapsed: float,
    interval_start: str,
    metric_id: str,
    pid: Optional[int],
    reader: Any,
) -> Dict[str, Any]:
    value = None if pid is None else reader(pid)
    if value is None:
        return measurement(
            schema,
            run_id=run_id,
            metric_id=metric_id,
            measurement_scope="component",
            role="credential-broker",
            origin="unavailable",
            privacy="approved_aggregate",
            interval_seconds=elapsed,
            value=None,
            sample_count=0,
            counter_reset=False,
            aggregation_basis="process counter could not be read",
            protected_attribution_ref=None,
            missing_reason="credential-broker process counter was not readable",
            time_basis="utc_real",
            interval_start=None,
            observation_ref=None,
        )
    return measurement(
        schema,
        run_id=run_id,
        metric_id=metric_id,
        measurement_scope="component",
        role="credential-broker",
        origin="measured",
        privacy="protected_detail",
        interval_seconds=elapsed,
        value=float(value),
        sample_count=1,
        counter_reset=False,
        aggregation_basis="credential-broker process counter from /proc",
        protected_attribution_ref="fill-v1",
        missing_reason=None,
        time_basis="utc_real",
        interval_start=interval_start,
        observation_ref=f"run:{run_id}:{metric_id}",
    )


def _tls_record(
    schema: Dict[str, Any],
    run_id: str,
    elapsed: float,
    interval_start: str,
    transport: str,
    positive: Dict[str, Any],
) -> Dict[str, Any]:
    if transport != "mtls":
        return measurement(
            schema,
            run_id=run_id,
            metric_id="tls_handshake_seconds",
            measurement_scope="component",
            role="credential-broker",
            origin="unavailable",
            privacy="approved_aggregate",
            interval_seconds=elapsed,
            value=None,
            sample_count=0,
            counter_reset=False,
            aggregation_basis="unix peercred path does not handshake tls",
            protected_attribution_ref=None,
            missing_reason="unix peercred path does not perform a tls handshake",
            time_basis="utc_real",
            interval_start=None,
            observation_ref=None,
        )
    return measurement(
        schema,
        run_id=run_id,
        metric_id="tls_handshake_seconds",
        measurement_scope="component",
        role="credential-broker",
        origin="estimated",
        privacy="protected_detail",
        interval_seconds=elapsed,
        value=float(positive["seconds"]),
        sample_count=1,
        counter_reset=False,
        aggregation_basis=(
            "upper bound from the fill rpc through the byte-forwarder; "
            "includes the handshake and the grant check"
        ),
        protected_attribution_ref="fill-v1",
        missing_reason=None,
        time_basis="utc_real",
        interval_start=interval_start,
        observation_ref=f"run:{run_id}:tls",
    )


def _identity_record(
    schema: Dict[str, Any],
    run_id: str,
    elapsed: float,
    interval_start: str,
    transport: str,
    material: Optional[LabMaterial],
) -> Dict[str, Any]:
    if transport != "mtls" or material is None:
        return measurement(
            schema,
            run_id=run_id,
            metric_id="identity_issuance_count",
            measurement_scope="component",
            role="workload-issuer",
            origin="unavailable",
            privacy="approved_aggregate",
            interval_seconds=elapsed,
            value=None,
            sample_count=0,
            counter_reset=False,
            aggregation_basis="no svid was issued",
            protected_attribution_ref=None,
            missing_reason="SPIRE issuance is deferred and this unix run did not issue certificates",
            time_basis="utc_real",
            interval_start=None,
            observation_ref=None,
        )
    return measurement(
        schema,
        run_id=run_id,
        metric_id="identity_issuance_count",
        measurement_scope="component",
        role="workload-issuer",
        origin="measured",
        privacy="protected_detail",
        interval_seconds=elapsed,
        value=len(material.issued),
        sample_count=1,
        counter_reset=False,
        aggregation_basis="count of lab openssl certificates written for this run; SPIRE was not started",
        protected_attribution_ref="fill-v1",
        missing_reason=None,
        time_basis="utc_real",
        interval_start=interval_start,
        observation_ref=f"run:{run_id}:lab-ca",
    )


def _cpu_seconds(pid: int) -> Optional[float]:
    path = Path(f"/proc/{pid}/stat")
    if not path.exists():
        return None
    data = path.read_text(encoding="utf-8")
    fields = data[data.rfind(")") + 2 :].split()
    ticks = os.sysconf("SC_CLK_TCK")
    return (int(fields[11]) + int(fields[12])) / ticks


def _rss_bytes(pid: int) -> Optional[int]:
    path = Path(f"/proc/{pid}/status")
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    return None


def _cn_ignored(material: LabMaterial) -> bool:
    issued = material.for_instance("browser-1")
    result = subprocess.run(
        ["openssl", "x509", "-in", str(issued.cert_path), "-noout", "-subject"],
        check=False,
        capture_output=True,
        text=True,
    )
    subject = result.stdout
    return "ignored-cn-browser-1" in subject and "browser-guard" not in subject


def _outer_cvm() -> Dict[str, Any]:
    kvm_node = Path("/dev/kvm").exists()
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    qemu = shutil.which("qemu-system-x86_64") is not None
    swtpm = shutil.which("swtpm") is not None
    image = bool(os.environ.get("EGGOMI_DEV_IMAGE"))
    if kvm and qemu and swtpm and image:
        reason = (
            "kvm, qemu, and a dev image are present; this fill demo still runs "
            "host-native because compartment processes are not injected into the guest"
        )
    elif kvm_node and not kvm:
        reason = (
            "/dev/kvm exists but this user cannot open it, so the simulated "
            "SNP substrate was not launched"
        )
    elif kvm and not qemu:
        reason = (
            "kvm is openable and qemu-system-x86_64 is not installed, so the "
            "simulated SNP substrate was not launched"
        )
    elif not kvm_node:
        reason = "/dev/kvm is absent; host-native stub mode"
    else:
        reason = "the simulated SNP substrate was not launched from this fill demo"
    return {
        "entered": False,
        "kvm_node": kvm_node,
        "kvm": kvm,
        "sev": Path("/dev/sev").exists(),
        "qemu": qemu,
        "swtpm": swtpm,
        "dev_image_selected": image,
        "reason": reason,
    }


if __name__ == "__main__":
    raise SystemExit(main())
