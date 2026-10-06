# CAH integration manifest

W0 record for the confidential-agent harness on the private mirror
`tzarebczan/eggomi-dstack`. Role placement is the
[integration map](integration-map.md). Operator steps are in the
[CAH README](README.md).

## Pins

| Pin | Value |
| --- | --- |
| Research branch | `cursor/cah-compartment-stubs-194a` |
| Stack base | `cursor/eggomi-snp-harness-cf5c` |
| Outer-substrate HEAD inspected | `cffddc7ab357eb33cae4f1816823e289138cdbc0` (`fix(eggomi): align the SNP harness with host gates`) |
| Outer PR | [tzarebczan/eggomi-dstack#1](https://github.com/tzarebczan/eggomi-dstack/pull/1), open, base `next`, commits `19f64e57`, `a25bbea9`, `54355c07`, `5f896a39`, `cffddc7a` |
| Eggomi predecessor HEAD | Not inspected. On 2026-10-06 the agent's GitHub App token was scoped to `tzarebczan/eggomi-dstack` only (`GET /installation/repositories` lists this repo), so `GET /repos/tzarebczan/eggomi` returned HTTP 404. The private repository exists. This is a token-scope gap, not a missing repo. No Eggomi commit SHA was read. |
| WS1 revision 1 zip | SHA-256 `f3da0ddc62b6ad94711a045bf9fffd96a618857268cd2d7ff8f43ca6be05413c`. Vendored copies and hashes are in `test-suites/cah/profiles/eggomi/ws1-pins.json`. |
| `contracts/service-access.json` | `379db489ac1d7385bb9c3aee847ff69c7e2d6149a9d0a9519d79814f77fef9a1` |
| `contracts/scenarios.json` | `a9ff9e44836fe70b75e66e3367c76f24922bf507f27e4deb7d3f0625faef9820` |
| `contracts/metrics.json` | `ab065b7d1422713c17e2a906df4253cd3cf6c82b0e93cb3f21c83506329a3ce5` |
| `contracts/acceptance.json` | `3b4416a9f1203de1ae3653998b68cb34f7d275526ae964307d4543a7bf9cafcf` |
| `contracts/experiment.schema.json` | `4c203000b22f9fa99a3714435565e9980d9efe78408d42e3336283312121af6f` |
| `contracts/baseline-manifest.json` | `2b2c9fc43de329ee4caa6a6b3f4efafbc6071d20c73194ac9a5901e489ed0d23` |
| Measurement schema in use | WSE 1.0 `schemas/measurement.schema.json`, SHA-256 `68d13090ca64469b258790e850e28f747f2100f06d9f807d80cb314d95634003`, copied to `test-suites/cah/schemas/measurement.schema.json`. The emitter still validates this file. WS1 `contracts/metrics.json` is pinned above and is not yet the wire format. |
| Scenario catalog | `catalog_pin` `a9ff9e44836fe70b75e66e3367c76f24922bf507f27e4deb7d3f0625faef9820` (`contracts/ws1/scenarios.json`). Authoritative range is WS-SIM01–WS-SIM18. |

Coordinator-described Eggomi paths and pull requests are unverified. They are
listed in the integration map so a later checkout can be diffed against them.
This manifest does not claim those SHAs, merge states, or file contents.

## Hardware inventory

Collected on this agent VM on 2026-10-06. `MemAvailable` is a point sample.

| Item | Observation |
| --- | --- |
| Kernel | Linux 6.12.94+ x86_64 |
| CPU | 4 vCPU, Intel Xeon, family 6 model 207 stepping 2, VT-x, hypervisor KVM |
| Memory | `MemTotal` 16398384 kB, `MemAvailable` 5085764 kB |
| `/dev/kvm` | Present, `crw-rw----` root gid 103. uid 1000 (`ubuntu`) is not in that group and cannot open the node. |
| `/dev/sev`, `/dev/sev-guest` | Absent |
| Nested KVM | `/sys/module/kvm_intel/parameters/nested` is `Y` |
| `qemu-system-x86_64`, `swtpm` | Not installed |
| Python / OpenSSL | Python 3.12.3, OpenSSL 3.0.13 |
| `jsonschema`, shellcheck | Not installed. Measurement checks are hand-rolled against the pinned schema. Scripts were syntax-checked with `bash -n`. |

S0 was not launched. The fill demo records `outer_cvm.entered: false` and
`evidence_level: E1`.

## Harness ports

One runner: `test-suites/eggomi` for the outer CVM, `test-suites/cah` for
compartment ports.

| Port | Contract |
| --- | --- |
| RPC | 4-byte big-endian length plus UTF-8 JSON, maximum 1 MiB. Responses are `{ok, code, body}`. Errors use an empty body. |
| Addresses | `unix:<path>` and `tcp:<host>:<port>`. Servers bind `tcp` on `127.0.0.1:0` and publish the chosen address in `ready/<role>`. |
| Unix identity | `SO_PEERCRED` pid, uid must equal the server uid, pid must be in the admission registry. |
| Lab mTLS | TLS 1.3, client certificates required, session tickets disabled. Hostname check is off because the SPIFFE URI SAN is the identity. The mTLS broker path is `vsock.placeholder(cid=3, port=5200)`, label `vsock:3:5200`. `open_vsock()` raises `VsockUnavailable`. `AF_VSOCK` is not opened. |
| Access graph | `test-suites/cah/profiles/eggomi/service-access.json` (`service-access/v1`, default deny, one-use scoped `AdmitWorkload`). |
| Use-grant | `workload-use-grant/v1`. Wire value is an opaque hex reference. Server-side binding is requester, recipient possession, policy, destination, task, and lease. Example: `test-suites/cah/examples/workload-use-grant.json`. A null fingerprint in an old example is not a skip. |
| Service-access map | Runtime graph stays `service-access/v1`. `profiles/eggomi/service-access-map.json` names each edge's WS1 counterpart or an explicit deviation. |
| Experiment record | `test-suites/cah/examples/experiment.json` is `cah-experiment/v1` for this harness. It is not a claim that a run satisfied `contracts/ws1/experiment.schema.json`. |
| Metrics | `resource-measurement/v1` via `cah.metrics`. `power_watts` is `unavailable` with a null value on this VM. |
| Outer substrate | `test-suites/eggomi/scripts/s0-sim-smoke.sh`, `s1-persistence.sh`, `s6-faults.sh`. `test-suites/cah/scripts/cah-launch.sh` calls S0 only in outer mode. |
| Fill | `python3 -m cah.demo`. Report schema `cah-run-report/v1`. |

Methods implemented on the servers: `PrepareUse` and `ResolveUseGrant`,
`ReportOutcome`, and `AdmitWorkload` on `keeper-core`; `CompleteFill` on
`credential-broker`. `connector` has an empty method table, so an admitted
caller still receives `denied_role`.

## Scenario aliases

`test-suites/cah/profiles/eggomi/scenario-aliases.json` records retired
journey ids J01–J14. A harness port is filled only where a test already
exists:

| Retired id | Port |
| --- | --- |
| J06 Browser sign-in and read | `fill-v1` (this demo). Catalog port WS-SIM06 `browser-signin`, evidence `process_e2e`. Hostile navigation and a bound fill only. Profile attach, profile commit, and WS-LIFE04 are not executed. |
| J13 Rolling release and issuer rotation | `s6-faults`. Not a WS-SIM id. Supports WS-PERF06 and the negative half of WS-PLAT01. |
| J14 Pristine branch and teardown | `s1-persistence`. Closest catalog id is WS-SIM12 `branch-and-restore`. This suite does not execute that procedure. |

Every other J id has a null port. The fill report sets `ws_sim_id` to `WS-SIM06`. S0, when launched, is `vm_e2e` and is not labeled E2.

## W0 return packet

Placement, mount, egress, the key inventory, and route gates G0–G5 are pinned
in [w0-packet.md](w0-packet.md) and
`test-suites/cah/profiles/eggomi/w0-packet.json`. This slice's evidence is
E1 / `process_e2e`. It does not claim `vm_e2e`, `confidential_baremetal`, or
E3.

WS1 evidence classes, in the vendored `experiment.schema.json` order, are
`analytical`, `discrete_event`, `process_e2e`, `vm_e2e`,
`confidential_baremetal`, and `disposable_live_provider`.

`agent-handover.md` and `simulation-measurement-contract.md` are named in the
PR #2 review and are not files in the vendored pin set. The only G-id sentence
in that set is WS-PERF06: missing supporting hardware evidence blocks a G2/G5
claim. G0, G1, G3, and G4 therefore have no criterion text here and are
deferred, not passed. G2 and G5 are deferred for that WS-PERF06 reason: this
VM has no `/dev/sev`, uid 1000 cannot open `/dev/kvm`, and S0 was not launched.

| Object | Where it lives in a fill run |
| --- | --- |
| Lab CA key | `state/authority/certs/ca.key` (mode 0600), mTLS only. Confined processes hide `state/authority`. |
| Instance keys | `state/authority/certs/<instance>.key` and `state/roles/<instance>/key.pem` (mode 0600), mTLS only. A confined process keeps only its own role directory. |
| Fill secret | Broker stdin (`cah-synthetic-fill-v1`). Not a key file. Released only into `results/positive_fill.json` and `results/copied_owner_fill.json`. |
| Grant store | `state/authority/grants.json`, `authority-journal.jsonl`, and `keeper-epoch` (mode 0600). The journal wins over a restored snapshot. |
| Registry | `state/admission.json`, lock `admission.json.lock`. Confined processes see it read-only. |

| Gate | Status |
| --- | --- |
| G0 | Deferred. Criterion text is not in the vendored contracts. |
| G1 | Deferred. Criterion text is not in the vendored contracts. |
| G2 | Deferred. WS-PERF06 blocks a G2 claim without hardware evidence. Not `vm_e2e`. |
| G3 | Deferred. Criterion text is not in the vendored contracts. |
| G4 | Deferred. Criterion text is not in the vendored contracts. |
| G5 | Deferred. WS-PERF06 blocks a G5 claim without hardware evidence. Not `confidential_baremetal`. |

No gate in this packet is passed. The host-native fill remains `process_e2e`.

## Gaps recorded for the next checkout

SPIRE is deferred (W2). Nested smolvm, guest injection of these stubs, real
`AF_VSOCK`, Eggomi application wiring, E3 hardware evidence, and a migration
from `resource-measurement/v1` onto the pinned WS1 metric names are deferred.
Same-uid ptrace across the mount namespace is not additionally blocked.
Templates start empty on each run. Consumption is journaled outside the grant
snapshot. This tree does not branch a live keeper by checkpoint.
