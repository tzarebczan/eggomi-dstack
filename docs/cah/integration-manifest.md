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
| Eggomi predecessor HEAD | Not inspected. On 2026-10-06, `GET /repos/tzarebczan/eggomi` with the eggomi-dstack credential returned HTTP 404. No Eggomi commit SHA was read. |
| Pack semantics | WS1 revision 1, as described by the coordinator. The revision zip was not attached. |
| Measurement schema | WSE 1.0 `schemas/measurement.schema.json`, SHA-256 `68d13090ca64469b258790e850e28f747f2100f06d9f807d80cb314d95634003`, copied to `test-suites/cah/schemas/measurement.schema.json`. Replace this file when the WS1 `contracts/` bundle is pinned. |
| Scenario catalog | `catalog_pin` is null. Authoritative range is WS-SIM01–WS-SIM18. Names inside that range were not invented. |

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
| Use-grant | `workload-use-grant/v1`. Wire value is an opaque hex reference. Server-side binding is requester, recipient, policy, task, and lease. Example: `test-suites/cah/examples/workload-use-grant.json`. |
| Experiment record | `test-suites/cah/examples/experiment.json` is `cah-experiment/v1` for this harness. It does not claim to satisfy the unseen WS1 `experiment.schema`. |
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
| J06 Browser sign-in and read | `fill-v1` (this demo) |
| J13 Rolling release and issuer rotation | `s6-faults` |
| J14 Pristine branch and teardown | `s1-persistence` |

Every other J id has a null port. `ws_sim_id` on the fill report is null.

## Gaps recorded for the next checkout

SPIRE is deferred (W2). Nested smolvm, guest injection of these stubs, real
`AF_VSOCK`, Eggomi application wiring, and E3 hardware evidence are deferred.
Templates start empty on each run. This tree does not checkpoint a live
keeper authority.
