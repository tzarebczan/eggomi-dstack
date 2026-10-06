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

`keeper-core` issues an opaque use-grant from its own policy. The requester
cannot choose origin, lease, or recipient; a forged origin is
`denied_payload` and stores nothing. `credential-broker` asks keeper to
resolve that grant, then releases one synthetic fill to the bound
`browser-guard`. An `omi-runner` call to the broker is `denied_role` on the
access graph and does not inspect the grant. A second admitted browser that
presents the same `grant_ref` is `denied_recipient` at resolve. Those are
different checks. A boot id only advances. A pid rebind and a certificate
fingerprint change both advance `boot_generation` and revoke that instance's
issued grants. A generation mismatch is `revoked_boot`. An unadmitted
certificate and a connector with no allow edge are refused. Role, instance,
and frame mismatches leave the grant issued. A
second redeem of a consumed grant returns `grant_consumed`.

The authority rules, including why `get_secret` and keeper
checkpoint-as-scaling are not this model, are in
[authority-model.md](authority-model.md).

The fill demo does not enter the guest. `CAH_MODE=outer` runs S0 and then
exits. S0 does not inject these stubs. The report names `ws_sim_id`
`WS-SIM06` (`browser-signin`) as the catalog port and `ws1_evidence`
`process_e2e`. The run refuses a hostile navigation and fills the bound
browser. It does not execute profile attach, profile commit, or WS-LIFE04,
and it is not `vm_e2e` or a confidential-hardware claim. A simulated SNP
boot, when the host can launch it, is `vm_e2e`.

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
`report.json` plus `measurements.json`. The synthetic fill value appears only in `results/positive_fill.json` and
`results/copied_owner_fill.json`.

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
`spiffe://lab.cah/tenant/<tenant>/role/<role>/instance/<instance>`. The
certificate CN is ignored. Clients that use mTLS pin the full SPIFFE id and
the certificate fingerprint. A certificate absent from the registry is
`denied_unadmitted`.

Non-keeper processes run in a user and mount namespace that hides
`state/authority` (policy, journal, lab CA key) and other role keys.
`admission.json` is read-only inside that namespace. Keeper stays unconfined
because it owns those files. The processes still share a uid, and same-uid
ptrace is not additionally blocked. That is an E1 limit. It is not a
confidentiality claim.

## Measurements

Records use `resource-measurement/v1`. The schema file is the pinned WSE 1.0
copy described in [`test-suites/cah/schemas/PROVENANCE.md`](../../test-suites/cah/schemas/PROVENANCE.md).
`origin` is `measured`, `estimated`, `simulated`, or `unavailable`. An
unavailable sample has `value: null` and `sample_count: 0`. `sum_present`
refuses to add one metric across different scopes or roles. If any selected
row is unavailable, the total is null rather than a partial sum.
`tls_handshake_seconds` is unavailable on both transports until a handshake
timer exists. The emitter still uses this WSE 1.0 schema. WS1 metric names
are pinned and not yet the wire format.

## Deferred

SPIRE, real `AF_VSOCK`, nested smolvm, injecting stubs into the S0 guest,
wiring Eggomi application code, an E3 hardware run, and a full migration onto
`eggomi_*` metric names are deferred. Route gates G2 and G5 stay deferred:
vendored WS-PERF06 says missing hardware evidence blocks those claims, and
this slice is E1 / `process_e2e`. G0, G1, G3, and G4 have no criterion text
in the vendored contracts, so they are deferred rather than marked passed.
Placement, mount, egress, the key inventory, and gates G0–G5 are pinned in
the [W0 packet](w0-packet.md). J01–J14 stay retired journey ids.
