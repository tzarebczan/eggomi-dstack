# CAH integration map

W0 map from workload-compartment roles to this repository and to Eggomi paths
the coordinator described. Pins and the hardware inventory are in the
[integration manifest](integration-manifest.md).

J01–J14 are retired journey ids. WS-SIM01–WS-SIM18 is the authoritative
catalog. The revision zip was not attached, so this map leaves `ws_sim_id`
empty and uses harness port names (`fill-v1`, `s6-faults`, `s1-persistence`)
only where a test already exists.

Eggomi paths and pull requests were not read. On 2026-10-06 the eggomi-dstack
credential received HTTP 404 for `tzarebczan/eggomi`. Treat the Eggomi column
as a coordinator description until a checkout records real SHAs.

Evidence: E0 is a model, E1 is real processes with fakes, E2 is a real inner
runtime without a confidential-hardware claim, E3 is TEE hardware. This slice
is E1. Deployment class is L (lab).

| Role | This repo | Eggomi path (unverified) | Evidence | Owner | Gap |
| --- | --- | --- | --- | --- | --- |
| keeper-core | `cah` server, `PrepareUse`, `ResolveUseGrant`, `ReportOutcome`, `AdmitWorkload` | `infra/dstack` hostd stub; `apps/desktop/src/keeper`. In-flight PRs #657, #661, #662, #664, #666, #668, #676 | E1 | CAH on this mirror; Eggomi keeper later | Pristine templates. No live keeper checkpoint. |
| credential-broker | `cah` server, `CompleteFill` after keeper resolve | No compose service by this name. Egress stays a separate role. | E1 | CAH | Fill release is the stub broker. Egress policy is untouched. |
| browser-guard | Fill client | `infra/dstack` browser | E1 | CAH | Process is host-native. It is not inside the browser workload or gVisor. |
| omi-runner | `PrepareUse` client | Planned agent loop | E1 | CAH | Requests a grant. Does not run a model. |
| connector | Server with no allow edge | Matrix / stealth paths mentioned beside `infra/dstack` | E1 refusal | CAH | `denied_role` only. No bridge. |
| platform-launcher | Scoped `AdmitWorkload` client | Compose / host launcher | E1 | CAH | One-use scope file. SPIRE is deferred. |
| data-service | Not started | — | — | Later | No process. |
| matrix-device | Not started | PR #668 described as matrix-bridge narrowing | — | Eggomi | No process. |
| workbench | Not started | `infra/dstack` workbench / gVisor | — | Eggomi | No process. |
| workload-issuer | Metric role only, when a record needs it | — | — | Later | No server. |
| telemetry-agent | Not started | — | — | Later | Measurements are written by the demo driver. |

Outer substrate mapping:

| Concern | Port | Evidence when run |
| --- | --- | --- |
| Simulated SNP boot and quote shape | `test-suites/eggomi/scripts/s0-sim-smoke.sh` | E2 once KVM, QEMU, swtpm, and a dev image are present. Skipped here. |
| Encrypted disk and swtpm persistence | `s1-persistence.sh` (retired alias J14) | Same gate as S0. |
| Production-root rejection | `s6-faults.sh` (retired alias J13) | Existing verifier. Docker-backed step exits 77 without a daemon. |
| Browser fill and refusals | `python3 -m cah.demo` (retired alias J06, port `fill-v1`) | E1 on this VM. |

The Eggomi lab stack the coordinator described (`infra/dstack` compose,
`compose.lab.yaml`, browser, egress, hostd, workbench, stealth/Tor, probes,
`LAB-NOTES.md`) is the layout these ports should join. Compose for that lab
stack stays in Eggomi `infra/dstack`.
