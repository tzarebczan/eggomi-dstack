# Confidential-agent harness

The confidential-agent harness (CAH) is a generic compartment graph that runs
on the existing Eggomi simulated-SNP substrate. Eggomi is the first profile.
The harness name is CAH.

Outer launch, quote checks, and persistence stay in
[`test-suites/eggomi`](../../test-suites/eggomi/README.md) (S0, S1, and S6).
Compartment stubs, the service-access graph, and the fill demo live in
[`test-suites/cah`](../../test-suites/cah/README.md).

Pins, hardware, and ports are in the
[integration manifest](integration-manifest.md). Role placement is in the
[integration map](integration-map.md). How this profile later sits beside
Eggomi `infra/dstack` is in the [Eggomi profile](eggomi-profile.md).

## What this slice runs

Host-native processes (evidence E1, deployment class L) talk over a
length-prefixed JSON RPC. Unix `SO_PEERCRED` and lab mTLS both resolve to the
same admission registry. The registry is written by the launcher. Servers
reload it from disk.

`keeper-core` issues an opaque use-grant. `credential-broker` asks keeper to
resolve that grant, then releases one synthetic fill to `browser-guard`. A
copied grant presented by the wrong role, a grant whose recipient boot id has
changed, an unadmitted certificate, and a connector with no allow edge are
refused. Mismatches leave the grant issued. A second redeem of a consumed
grant returns `grant_consumed`.

The fill demo does not enter the guest. `CAH_MODE=outer` runs S0 and then
exits. S0 does not inject these stubs.

## Run

From the repository root, with Python 3.12:

```bash
./test-suites/cah/scripts/cah-launch.sh
CAH_TRANSPORT=mtls ./test-suites/cah/scripts/host-native-fill.sh
./test-suites/cah/scripts/run-tests.sh
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `CAH_MODE` | `auto` | `host-native` runs the fill. `outer` runs S0 only. `auto` runs S0 first when `/dev/kvm` is openable, `EGGOMI_DEV_IMAGE` is set, and `qemu-system-x86_64` and `swtpm` are installed, then still runs the host-native fill. |
| `CAH_TRANSPORT` | `unix` | `unix` or `mtls`. |
| `CAH_STATE_DIR` | `test-suites/cah/.state/fill-<transport>` | Run directory. Gitignored. |
| `EGGOMI_DEV_IMAGE` | unset | Development image name for S0. The fill demo ignores it for guest injection. |

A passing run prints `{"evidence_level": "E1", "ok": true}` and writes
`report.json` plus `measurements.json`. The synthetic fill value appears only
in `results/positive_fill.json`.

## Authorization

`profiles/eggomi/service-access.json` is `service-access/v1` with
`"default": "deny"`. Allowed edges are `AdmitWorkload`, `PrepareUse`,
`ResolveUseGrant`, `CompleteFill`, and `ReportOutcome`.

Bootstrap `AdmitWorkload` is callable only by `platform-launcher`, once, and
only when the token hash matches the launcher scope file for that role,
instance, and boot. A wrong role does not consume the token.

RPC bodies that carry `role`, `boot_id`, `instance_id`, `cert_fingerprint`,
`caller`, or `spiffe_id` are `denied_authority_field`. Lab certificates use a
SPIFFE URI SAN of the form
`spiffe://lab.cah/tenant/<tenant>/service/<role>/instance/<instance>`. The
certificate CN is ignored. A certificate absent from the registry is
`denied_unadmitted`.

On this lab host the processes share a uid, so the admission file and the lab
CA key are readable by every stub. That is an E1 limit. It is not a
confidentiality claim.

## Measurements

Records use `resource-measurement/v1`. The schema file is the pinned WSE 1.0
copy described in [`test-suites/cah/schemas/PROVENANCE.md`](../../test-suites/cah/schemas/PROVENANCE.md).
`origin` is `measured`, `estimated`, `simulated`, or `unavailable`. An
unavailable sample has `value: null` and `sample_count: 0`. Summing present
samples skips unavailable rows and yields no total when every row is
unavailable.

## Deferred

SPIRE, real `AF_VSOCK`, nested smolvm, injecting stubs into the S0 guest,
wiring Eggomi application code, an E3 hardware run, and a byte pin of the
WS1 revision 1 contract zip are deferred. J01–J14 stay retired journey ids.
`ws_sim_id` stays empty until that catalog is attached.
