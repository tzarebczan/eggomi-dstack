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

from .admission import admit_scoped
from .confine import popen_confined
from .crypto_lab import generate_private, public_key, wrap_private
from .grants import host_fence_paths, revoke_instance_grants
from .guard import GuardStore
from .launcher import LauncherSigner, launcher_dir
from .metrics import load_schema, measurement, sum_present, validate_record
from .policy import load_policy, publish_revision
from .registry import (
    AdmissionRegistry,
    BindResult,
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
    ("browser-guard", "browser-2", "boot-browser-2"),
    ("omi-runner", "omi-1", "boot-omi-1"),
    ("platform-launcher", "launcher-1", "boot-launcher-1"),
)
FILL_RESULTS = frozenset({"positive_fill.json", "copied_owner_fill.json"})


def main(argv: Optional[List[str]] = None) -> int:
    """Run the fill demo and write a report plus measurement records."""
    parser = argparse.ArgumentParser(description="run the CAH host-native fill demo")
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--transport", choices=("unix", "mtls"), default="unix")
    parser.add_argument("--grant-ttl", type=float, default=60)
    args = parser.parse_args(argv)
    report = run_demo(args.state, args.transport, args.grant_ttl)
    print(
        json.dumps(
            {"ok": report["ok"], "evidence_level": report["evidence_level"]},
            sort_keys=True,
        )
    )
    return 0 if report["ok"] else 1


def run_demo(state: Path, transport: str, grant_ttl: float = 60) -> Dict[str, Any]:
    """Execute positive fill and refusal cases. Return the run report."""
    if state.exists():
        shutil.rmtree(state)
    state.mkdir(parents=True)
    started = time.time()
    interval_start = datetime.now(timezone.utc).isoformat()
    material: Optional[LabMaterial] = None
    authority = state / "authority"
    authority.mkdir(mode=0o700)
    (state / "roles").mkdir()
    (state / "fence").mkdir(mode=0o700)
    (state / "host-fence").mkdir(mode=0o700)
    instances = [(role, instance) for role, instance, _boot in SERVERS + CLIENTS]
    instances.append(("browser-guard", "stranger-1"))
    if transport == "mtls":
        material = issue_lab(authority / "certs", TRUST_DOMAIN, TENANT, instances)
        public = state / "public"
        public.mkdir()
        shutil.copyfile(material.ca_cert, public / "ca.crt")
        for _role, instance in instances:
            _export_material(state, material, instance)
    policy_dir = authority / "policy"
    publish_revision(policy_dir, load_policy(PROFILE / "keeper-policy.json"))
    secret_path = authority / "fill-secret"
    secret_path.write_text(CANARY + "\n", encoding="utf-8")
    os.chmod(secret_path, 0o600)
    publics = _install_channel_keys(state, instances)
    _write_registry(state, material, publics)
    access = PROFILE / "service-access.json"
    pins = _server_pins(material)
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
            pins,
            policy_dir,
            confine=False,
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
            pins,
            policy_dir,
            confine=True,
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
            pins,
            policy_dir,
            confine=True,
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
        held = {
            "browser-1": _hold_client(
                procs,
                logs,
                state,
                env,
                transport,
                material,
                "browser-guard",
                "browser-1",
                keeper_addr,
                broker_public,
                connector_addr,
                pins,
            ),
            "browser-2": _hold_client(
                procs,
                logs,
                state,
                env,
                transport,
                material,
                "browser-guard",
                "browser-2",
                keeper_addr,
                broker_public,
                connector_addr,
                pins,
            ),
        }
        cases = _run_cases(
            state,
            env,
            transport,
            material,
            keeper_addr,
            broker_public,
            connector_addr,
            held,
            pins,
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
            "transport": "unix-pidfd" if transport == "unix" else "mtls",
            "profile": "eggomi",
            "scenario_port": "fill-v1",
            "retired_scenario_alias": "J06",
            "ws_sim_id": "WS-SIM06",
            "ws1_evidence": "process_e2e",
            "confinement": "user-mount-namespace",
            "pristine_templates_only": True,
            "spire": "deferred",
            "nested_smolvm": "deferred",
            "vsock": vsock_label
            if transport == "mtls"
            else "byte-forward placeholder; unix pidfd and the keyed channel used for RPC",
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
    held: Dict[str, Dict[str, Any]],
    pins: Dict[str, Dict[str, str]],
) -> List[Dict[str, str]]:
    cases: List[Dict[str, str]] = []

    def record(name: str, expect: str, result: Dict[str, Any]) -> Dict[str, Any]:
        cases.append({"name": name, "expect": expect, "actual": str(result["code"])})
        return result

    def oneshot(
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
        origin: Optional[str] = None,
    ) -> Dict[str, Any]:
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
            pins,
            origin,
        )
        return record(name, expect, result)

    def held_case(
        name: str,
        instance: str,
        mode: str,
        expect: str,
        *,
        operation_id: str = "op-positive",
        grant_ref: Optional[str] = None,
        navigation_generation: Optional[str] = None,
    ) -> Dict[str, Any]:
        result = _submit(
            state,
            held[instance],
            name,
            mode,
            operation_id,
            grant_ref,
            navigation_generation,
        )
        return record(name, expect, result)

    oneshot(
        "smuggle_authority_field",
        "smuggle",
        "omi-runner",
        "omi-1",
        "denied_authority_field",
    )
    held_case(
        "browser_cannot_prepare",
        "browser-1",
        "prepare",
        "denied_role",
        operation_id="op-browser",
    )
    oneshot(
        "forged_origin",
        "prepare",
        "omi-runner",
        "omi-1",
        "denied_payload",
        operation_id="op-positive",
        origin="https://attacker.example",
    )
    prepared = oneshot(
        "prepare_positive",
        "prepare",
        "omi-runner",
        "omi-1",
        "ok",
        operation_id="op-positive",
    )
    held_case(
        "hostile_navigation",
        "browser-1",
        "fill",
        "denied_payload",
        operation_id="op-positive",
        grant_ref=str(prepared["grant_ref"]),
        navigation_generation="nav-replaced",
    )
    _expect_disposition(state, cases, "op-positive", "issued", "hostile_left_issued")
    filled = held_case(
        "positive_fill",
        "browser-1",
        "fill",
        "ok",
        operation_id="op-positive",
        grant_ref=str(prepared["grant_ref"]),
    )
    if filled.get("fill") != CANARY:
        cases.append(
            {"name": "positive_fill_value", "expect": "present", "actual": "missing"}
        )
    held_case(
        "outcome",
        "browser-1",
        "outcome",
        "ok",
        operation_id="op-positive",
    )
    held_case(
        "outcome_other_browser",
        "browser-2",
        "outcome",
        "denied_payload",
        operation_id="op-positive",
    )
    held_case(
        "replay_consumed",
        "browser-1",
        "fill",
        "grant_consumed",
        operation_id="op-positive",
        grant_ref=str(prepared["grant_ref"]),
    )
    copied = oneshot(
        "prepare_copied",
        "prepare",
        "omi-runner",
        "omi-1",
        "ok",
        operation_id="op-copied",
    )
    oneshot(
        "copied_wrong_role",
        "steal",
        "omi-runner",
        "omi-1",
        "denied_role",
        operation_id="op-copied",
        grant_ref=str(copied["grant_ref"]),
    )
    _expect_disposition(state, cases, "op-copied", "issued", "wrong_role_left_issued")
    held_case(
        "copied_second_browser",
        "browser-2",
        "fill",
        "denied_recipient",
        operation_id="op-copied",
        grant_ref=str(copied["grant_ref"]),
    )
    _expect_disposition(state, cases, "op-copied", "issued", "copied_left_issued")
    held_case(
        "copied_owner_fill",
        "browser-1",
        "fill",
        "ok",
        operation_id="op-copied",
        grant_ref=str(copied["grant_ref"]),
    )
    boot_grant = oneshot(
        "prepare_wrong_boot",
        "prepare",
        "omi-runner",
        "omi-1",
        "ok",
        operation_id="op-boot",
    )
    set_boot(state / "admission.json", "browser-1", "boot-browser-1-next")
    journal_path, epoch_path = host_fence_paths(state / "authority")
    revoke_instance_grants(
        state / "authority" / "grants.json",
        journal_path,
        epoch_path,
        "browser-1",
    )
    held_case(
        "wrong_boot",
        "browser-1",
        "fill",
        "denied_boot",
        operation_id="op-boot",
        grant_ref=str(boot_grant["grant_ref"]),
    )
    oneshot("connector_default_deny", "poke", "omi-runner", "omi-1", "denied_role")
    oneshot(
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
    _local_bootstrap(
        state,
        cases,
        "bootstrap_wrong_role",
        "omi-runner",
        token,
        "connector",
        "denied_role",
    )
    _local_bootstrap(
        state,
        cases,
        "bootstrap_wrong_scope",
        "platform-launcher",
        token,
        "omi-runner",
        "denied_bootstrap",
    )
    _local_bootstrap(
        state, cases, "bootstrap_ok", "platform-launcher", token, "connector", "ok"
    )
    _local_bootstrap(
        state,
        cases,
        "bootstrap_replay",
        "platform-launcher",
        token,
        "connector",
        "denied_bootstrap",
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
    pins: Dict[str, Dict[str, str]],
    origin: Optional[str],
) -> Dict[str, Any]:
    fixture = _fixture(operation_id, origin)
    if mode.startswith("bootstrap"):
        fixture.update(_bootstrap_fields())
    fixture_path = state / "fixtures" / f"{case}.json"
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
    cmd = _client_cmd(
        state,
        transport,
        material,
        keeper,
        broker,
        connector,
        case,
        mode,
        instance,
        fixture_path,
        grant_ref,
        pins,
        stranger,
    )
    log_path = state / "logs" / f"{case}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        proc = _spawn(
            cmd,
            state,
            instance,
            env,
            subprocess.PIPE if token is not None else subprocess.DEVNULL,
            log,
            log,
            confine=True,
        )
        if admit and not stranger:
            _bind(state, instance, proc.pid)
        (state / "go" / str(proc.pid)).parent.mkdir(parents=True, exist_ok=True)
        (state / "go" / str(proc.pid)).write_text("go\n", encoding="utf-8")
        if token is not None and proc.stdin is not None:
            proc.stdin.write((token + "\n").encode("utf-8"))
            proc.stdin.close()
        try:
            code = proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise RuntimeError(f"client {case} timed out") from None
    if code != 0:
        detail = log_path.read_text(encoding="utf-8")
        raise RuntimeError(f"client {case} exited {code}: {detail}")
    return json.loads((state / "results" / f"{case}.json").read_text(encoding="utf-8"))


def _hold_client(
    procs: List[subprocess.Popen[bytes]],
    logs: List[Any],
    state: Path,
    env: Dict[str, str],
    transport: str,
    material: Optional[LabMaterial],
    role: str,
    instance: str,
    keeper: str,
    broker: str,
    connector: str,
    pins: Dict[str, Dict[str, str]],
) -> Dict[str, Any]:
    """Start one browser process and keep its pid bound for later commands."""
    del role
    fixture_path = state / "fixtures" / f"{instance}-hold.json"
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_path.write_text("{}\n", encoding="utf-8")
    cmd = _client_cmd(
        state,
        transport,
        material,
        keeper,
        broker,
        connector,
        instance,
        "agent",
        instance,
        fixture_path,
        None,
        pins,
        False,
    )
    log_path = state / "logs" / f"{instance}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("w", encoding="utf-8")
    logs.append(log)
    proc = _spawn(
        cmd,
        state,
        instance,
        env,
        subprocess.DEVNULL,
        log,
        log,
        confine=True,
    )
    procs.append(proc)
    _bind(state, instance, proc.pid)
    (state / "go" / str(proc.pid)).parent.mkdir(parents=True, exist_ok=True)
    (state / "go" / str(proc.pid)).write_text("go\n", encoding="utf-8")
    return {"proc": proc, "instance": instance, "pid": proc.pid, "log": log_path}


def _submit(
    state: Path,
    held: Dict[str, Any],
    case: str,
    mode: str,
    operation_id: str,
    grant_ref: Optional[str],
    navigation_generation: Optional[str],
) -> Dict[str, Any]:
    fixture = _fixture(operation_id, None)
    if navigation_generation is not None:
        fixture["navigation_generation"] = navigation_generation
    pid = int(held["pid"])
    done = state / "done" / str(pid)
    if done.exists():
        done.unlink()
    inbox = state / "inbox" / f"{pid}.json"
    inbox.parent.mkdir(parents=True, exist_ok=True)
    inbox.write_text(
        json.dumps(
            {
                "case": case,
                "mode": mode,
                "fixture": fixture,
                "grant_ref": grant_ref,
            }
        ),
        encoding="utf-8",
    )
    deadline = time.monotonic() + 20
    proc: subprocess.Popen[bytes] = held["proc"]
    while time.monotonic() < deadline:
        if done.exists() and done.read_text(encoding="utf-8").strip() == case:
            return json.loads(
                (state / "results" / f"{case}.json").read_text(encoding="utf-8")
            )
        if proc.poll() is not None:
            detail = Path(held["log"]).read_text(encoding="utf-8")
            raise RuntimeError(f"held client {held['instance']} exited: {detail}")
        time.sleep(0.02)
    raise RuntimeError(f"held client {held['instance']} did not finish {case}")


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
    pins: Dict[str, Dict[str, str]],
    policy_path: Path,
    confine: bool,
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
        "--launcher-public",
        _launcher_public(state),
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
        "--registry",
        str(state / "admission.json"),
        "--authority",
        str(state / "authority"),
        "--channel-key",
        str(state / "roles" / instance / "channel.key"),
    ]
    if keeper:
        cmd.extend(["--keeper", keeper])
        pin = pins.get("keeper-core")
        if pin:
            cmd.extend(
                [
                    "--expect-domain",
                    pin["domain"],
                    "--expect-tenant",
                    pin["tenant"],
                    "--expect-role",
                    pin["role"],
                    "--expect-instance",
                    pin["instance"],
                    "--expect-fingerprint",
                    pin["fingerprint"],
                ]
            )
        else:
            cmd.extend(
                [
                    "--expect-role",
                    "keeper-core",
                    "--expect-instance",
                    "keeper-1",
                ]
            )
    if role == "keeper-core":
        cmd.extend(["--policy", str(policy_path)])
    if role == "credential-broker":
        cmd.extend(["--resource-handle", "cred-lab-1"])
    if transport == "mtls":
        cert, key, ca = _material_paths(state, material, instance)
        cmd.extend(["--cert", str(cert), "--key", str(key), "--ca", str(ca)])
    log_path = state / "logs" / f"{role}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("w", encoding="utf-8")
    logs.append(log)
    proc = _spawn(
        cmd,
        state,
        instance,
        env,
        subprocess.DEVNULL,
        log,
        log,
        confine=confine,
    )
    procs.append(proc)
    _bind(state, instance, proc.pid)
    return _wait_ready(state, role, proc, log_path)


def _spawn(
    cmd: List[str],
    state: Path,
    instance: str,
    env: Dict[str, str],
    stdin: Any,
    stdout: Any,
    stderr: Any,
    confine: bool,
) -> subprocess.Popen[bytes]:
    role_dir = state / "roles" / instance
    role_dir.mkdir(parents=True, exist_ok=True)
    if not confine:
        return subprocess.Popen(cmd, stdin=stdin, stdout=stdout, stderr=stderr, env=env)
    keep_dirs = [role_dir]
    own_fence = state / "fence" / instance
    if own_fence.is_dir():
        keep_dirs.append(own_fence)
    return popen_confined(
        cmd,
        hide_dirs=[
            launcher_dir(state / "admission.json"),
            state / "authority",
            state / "roles",
            state / "fence",
            state / "host-fence",
        ],
        keep_dirs=keep_dirs,
        ro_files=[state / "admission.json"],
        env=env,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
    )


def _client_cmd(
    state: Path,
    transport: str,
    material: Optional[LabMaterial],
    keeper: str,
    broker: str,
    connector: str,
    case: str,
    mode: str,
    instance: str,
    fixture_path: Path,
    grant_ref: Optional[str],
    pins: Dict[str, Dict[str, str]],
    stranger: bool,
) -> List[str]:
    cmd = [
        sys.executable,
        "-m",
        "cah.client",
        "--launcher-public",
        _launcher_public(state),
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
        "--instance",
        instance,
    ]
    if grant_ref is not None:
        grant_path = state / "fixtures" / f"{case}.grant"
        grant_path.write_text(grant_ref + "\n", encoding="utf-8")
        cmd.extend(["--grant-file", str(grant_path)])
    cmd.extend(_pin_args(pins) if pins else _unix_instance_args())
    if transport == "mtls":
        cert, key, ca = _material_paths(state, material, instance)
        cmd.extend(["--cert", str(cert), "--key", str(key), "--ca", str(ca)])
        if stranger:
            cmd.append("--unadmitted-cert")
    return cmd


def _unix_instance_args() -> List[str]:
    """Name each Unix callee. The client does not take the first row of a role."""
    return [
        "--keeper-instance",
        "keeper-1",
        "--broker-instance",
        "broker-1",
        "--connector-instance",
        "connector-1",
    ]


def _pin_args(pins: Dict[str, Dict[str, str]]) -> List[str]:
    if not pins:
        return []
    args = ["--expect-domain", TRUST_DOMAIN, "--expect-tenant", TENANT]
    for role, flag in (
        ("keeper-core", "keeper"),
        ("credential-broker", "broker"),
        ("connector", "connector"),
    ):
        pin = pins[role]
        args.extend(
            [
                f"--{flag}-instance",
                pin["instance"],
                f"--{flag}-fp",
                pin["fingerprint"],
            ]
        )
    return args


def _material_paths(
    state: Path, material: Optional[LabMaterial], instance: str
) -> tuple[Path, Path, Path]:
    exported_cert = state / "roles" / instance / "cert.crt"
    if exported_cert.exists():
        return (
            exported_cert,
            state / "roles" / instance / "key.pem",
            state / "public" / "ca.crt",
        )
    if material is None:
        raise RuntimeError("mtls transport is missing lab certificates")
    issued = material.for_instance(instance)
    return issued.cert_path, issued.key_path, material.ca_cert


def _fixture(operation_id: str, origin: Optional[str]) -> Dict[str, Any]:
    fixture = json.loads((PROFILE / "fill-fixture.json").read_text(encoding="utf-8"))
    fixture["operation_id"] = operation_id
    if origin is not None:
        fixture["origin"] = origin
    return fixture


def _install_channel_keys(
    state: Path, instances: List[tuple[str, str]]
) -> Dict[str, str]:
    """Write one X25519 key per instance. Browser keys are fence-wrapped."""
    publics: Dict[str, str] = {}
    for _role, instance in instances:
        private = generate_private()
        publics[instance] = public_key(private).hex()
        role_dir = state / "roles" / instance
        role_dir.mkdir(parents=True, exist_ok=True)
        if instance in {"browser-1", "browser-2"}:
            _wrap_guard_key(state, instance, private)
        else:
            path = role_dir / "channel.key"
            path.write_bytes(private)
            os.chmod(path, 0o600)
    return publics


def _wrap_guard_key(state: Path, instance: str, private: bytes) -> None:
    fence = state / "fence" / instance
    fence.mkdir(parents=True, mode=0o700)
    secret = generate_private()
    (fence / "secret").write_bytes(secret)
    os.chmod(fence / "secret", 0o600)
    (fence / "epoch").write_text("1\n", encoding="utf-8")
    os.chmod(fence / "epoch", 0o600)
    wrapped = state / "roles" / instance / "channel.key.wrapped"
    wrapped.write_bytes(wrap_private(secret, 1, private))
    os.chmod(wrapped, 0o600)
    fence_name = "fence-browser-1" if instance == "browser-1" else f"fence-{instance}"
    lease = {
        "epoch": 1,
        "fence": fence_name,
        "field": "password",
        "keeper_epoch": 1,
        "tenant": TENANT,
    }
    lease_path = state / "roles" / instance / "lease.json"
    lease_path.write_text(
        json.dumps(lease, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.chmod(lease_path, 0o600)


def _local_bootstrap(
    state: Path,
    cases: List[Dict[str, str]],
    name: str,
    caller_role: str,
    token: str,
    admit_role: str,
    expect: str,
) -> None:
    """Run launcher admission in this process. Confined clients cannot write it."""
    fields = _bootstrap_fields()
    response = admit_scoped(
        state / "admission.json",
        state / "authority",
        caller_role=caller_role,
        token=token,
        admit_role=admit_role,
        admit_instance=fields["admit_instance_id"],
        admit_boot=fields["admit_boot_id"],
    )
    cases.append({"name": name, "expect": expect, "actual": str(response["code"])})


def _bootstrap_fields() -> Dict[str, str]:
    return {
        "admit_role": "connector",
        "admit_instance_id": "connector-scoped-1",
        "admit_boot_id": "boot-connector-scoped-1",
    }


def _bind(state: Path, instance: str, pid: int) -> BindResult:
    result = bind_process(state / "admission.json", instance, pid)
    if result.kind == "unchanged":
        return result
    # Every bind advances boot_generation, the first one included, so every
    # bind revokes the instance's issued grants. The guard fence (its
    # wrapped key) moves only on a rebind: the first bind is the key the
    # launcher provisioned.
    journal_path, epoch_path = host_fence_paths(state / "authority")
    revoke_instance_grants(
        state / "authority" / "grants.json",
        journal_path,
        epoch_path,
        instance,
    )
    if result.kind == "rebound":
        fence = state / "fence" / instance
        if fence.is_dir():
            wrapped = state / "roles" / instance / "channel.key.wrapped"
            GuardStore(fence, wrapped).advance_epoch()
    return result


def _expect_disposition(
    state: Path,
    cases: List[Dict[str, str]],
    operation_id: str,
    disposition: str,
    name: str,
) -> None:
    actual = _grant_by_operation(state, operation_id).get("disposition")
    cases.append(
        {
            "name": name,
            "expect": disposition,
            "actual": str(actual),
        }
    )


def _grant_by_operation(state: Path, operation_id: str) -> Dict[str, Any]:
    raw = json.loads((state / "authority" / "grants.json").read_text(encoding="utf-8"))
    for row in raw["grants"].values():
        if row["task"]["operation_id"] == operation_id:
            return row
    raise KeyError(operation_id)


def _export_material(state: Path, material: LabMaterial, instance: str) -> None:
    dest = state / "roles" / instance
    dest.mkdir(parents=True, exist_ok=True)
    issued = material.for_instance(instance)
    shutil.copyfile(issued.cert_path, dest / "cert.crt")
    shutil.copyfile(issued.key_path, dest / "key.pem")
    os.chmod(dest / "key.pem", 0o600)


def _server_pins(material: Optional[LabMaterial]) -> Dict[str, Dict[str, str]]:
    if material is None:
        return {}
    pins = {}
    for role, instance, _boot in SERVERS:
        pins[role] = {
            "domain": TRUST_DOMAIN,
            "tenant": TENANT,
            "role": role,
            "instance": instance,
            "fingerprint": material.for_instance(instance).fingerprint,
        }
    return pins


def _wait_ready(
    state: Path, role: str, proc: subprocess.Popen[bytes], log_path: Path
) -> str:
    ready = state / "ready" / role
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if ready.is_file():
            text = ready.read_text(encoding="utf-8").strip()
            if text:
                return text
        if proc.poll() is not None:
            raise RuntimeError(
                f"{role} exited early: {log_path.read_text(encoding='utf-8')}"
            )
        time.sleep(0.02)
    raise RuntimeError(
        f"{role} did not become ready: {log_path.read_text(encoding='utf-8')}"
    )


def _write_registry(
    state: Path, material: Optional[LabMaterial], publics: Dict[str, str]
) -> None:
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
                "boot_generation": 1,
                "boot_history": [boot],
                "cert_fingerprint": fingerprint,
                "pid": None,
                "starttime": None,
                "channel_public": publics[instance],
            }
        )
        (state / "roles" / instance).mkdir(parents=True, exist_ok=True)
    (state / "roles" / "stranger-1").mkdir(parents=True, exist_ok=True)
    save_registry(
        state / "admission.json",
        AdmissionRegistry(
            trust_domain=TRUST_DOMAIN, tenant=TENANT, workloads=workloads
        ),
    )


def _launcher_public(state: Path) -> str:
    """Return the launcher row key every compartment is configured with."""
    return LauncherSigner.at(launcher_dir(state / "admission.json")).public.hex()


def _write_bootstrap(state: Path) -> str:
    token = "bootstrap-" + hashlib.sha256(os.urandom(32)).hexdigest()
    scope = {
        "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "admit_role": "connector",
        "admit_instance_id": "connector-scoped-1",
        "admit_boot_id": "boot-connector-scoped-1",
        "used": False,
    }
    path = state / "authority" / "bootstrap-scope.json"
    path.write_text(
        json.dumps(scope, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.chmod(path, 0o600)
    return token


def _grant_dispositions(state: Path) -> bool:
    raw = json.loads((state / "authority" / "grants.json").read_text(encoding="utf-8"))
    by_op = {row["task"]["operation_id"]: row for row in raw["grants"].values()}
    if by_op["op-positive"]["disposition"] != "consumed":
        return False
    if by_op["op-copied"]["disposition"] != "consumed":
        return False
    if by_op["op-boot"]["disposition"] != "denied_boot":
        return False
    if any(
        row["policy"]["origin"] == "https://attacker.example"
        for row in raw["grants"].values()
    ):
        return False
    scope = json.loads(
        (state / "authority" / "bootstrap-scope.json").read_text(encoding="utf-8")
    )
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
        if path.name in FILL_RESULTS:
            continue
        if path.resolve() == (state / "authority" / "fill-secret").resolve():
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
        1
        for case in cases
        if case["expect"] not in {"ok", "present"} and case["actual"] == case["expect"]
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
            time_basis="monotonic_real",
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
        _tls_record(schema, run_id, elapsed, interval_start, transport),
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
    _interval_start: str,
    transport: str,
) -> Dict[str, Any]:
    if transport == "mtls":
        basis = "lab mtls is enabled but the handshake is not timed separately"
        reason = "a tls handshake timer is not measured on this lab path"
    else:
        basis = "unix pidfd path does not handshake tls"
        reason = "unix pidfd path does not perform a tls handshake"
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
        aggregation_basis=basis,
        protected_attribution_ref=None,
        missing_reason=reason,
        time_basis="utc_real",
        interval_start=None,
        observation_ref=None,
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
