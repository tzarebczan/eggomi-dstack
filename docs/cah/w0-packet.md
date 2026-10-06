# CAH W0 return packet

This is the handover record for the host-native Eggomi profile. The
machine-readable pin is
`test-suites/cah/profiles/eggomi/w0-packet.json`. Hashes for the vendored
WS1 revision 1 contracts stay in
[integration-manifest.md](integration-manifest.md).

This slice is E1 / `process_e2e`. It does not claim `vm_e2e`,
`confidential_baremetal`, or E3.

## What the vendored pack does and does not say

`agent-handover.md` and `simulation-measurement-contract.md` are named in the
PR #2 review. They are not files in the vendored pin set. The zip SHA-256
`f3da0ddc62b6ad94711a045bf9fffd96a618857268cd2d7ff8f43ca6be05413c` is pinned.
The only G-id sentence in the vendored contracts is WS-PERF06 in
`contracts/ws1/acceptance.json`: missing supporting hardware evidence blocks
a G2/G5 claim.

G0, G1, G3, and G4 have no criterion text in this tree. They are deferred.
They are not marked passed. G2 and G5 are deferred because that hardware
evidence is absent.

WS1 evidence classes, in vendored `experiment.schema.json` order:

`analytical`, `discrete_event`, `process_e2e`, `vm_e2e`,
`confidential_baremetal`, `disposable_live_provider`.

## Placement

Host-native processes on the launcher host. The fill demo does not enter the
S0 guest. `CAH_MODE=outer` runs S0 and exits without injecting these stubs.

`test-suites/eggomi` owns the outer simulated-SNP substrate. CAH does not
start a second simulator. The dstack outer-substrate commit inspected for
this stack is recorded in the integration manifest. The Eggomi predecessor
SHA was not read.

The later neighbor the coordinator described is Eggomi `infra/dstack`. That
tree was not inspected. This packet does not claim those paths.

## Mount

Keeper stays unconfined. It owns `state/authority`: the lab CA key, the
keeper policy, the grant store, and the journal.

Every other compartment process runs in a user and mount namespace. That
namespace hides `state/authority` and `state/roles`, bind-mounts only that
process's role directory, and remounts `admission.json` read-only. Same-uid
ptrace is not additionally blocked. That is an E1 limit.

## Egress

Host network egress on this slice is unrestricted. That does not meet
WS-NET01, and it is not a broker bypass. The mTLS broker path is labeled
`vsock:3:5200`. `open_vsock()` raises `VsockUnavailable`. `AF_VSOCK` is not
opened. The label is a local byte forwarder.

Egress allowlists stay on the Eggomi egress role when that layout is wired.
The stub broker does not implement them.

## Key inventory

| Id | Path | Who can read it |
| --- | --- | --- |
| Lab CA key | `state/authority/certs/ca.key`, mode 0600, mTLS only | Keeper. Confined processes hide `state/authority`. The public certificate is `state/public/ca.crt`. |
| Instance keys | `state/authority/certs/<instance>.key` and `state/roles/<instance>/key.pem`, mode 0600, mTLS only | That instance's mount keeps only its own role directory. Unix transport does not issue these keys. |
| Fill secret | `state/authority/fill-secret`, mode 0600, lab canary `cah-synthetic-fill-v1` | Keeper only. Resolve seals it once per grant to the recipient guard. The broker relays ciphertext and never holds it. The guard may write the opened value only to `results/positive_fill.json` and `results/copied_owner_fill.json`. |
| Grant store | `state/authority/grants.json` plus `state/host-fence/authority-journal.jsonl`, `state/host-fence/keeper-epoch` and `state/host-fence/keeper-boot-epoch`, mode 0600 | Keeper. Restoring `state/authority` does not roll either epoch back or erase a journaled consume. The boot epoch advances at every keeper start and is sealed into each answer. |
| Registry | `state/admission.json`, lock `admission.json.lock`, mode 0600 | Launcher and keeper write it under the lock. Confined processes see a read-only bind. Every row carries `launcher_sig`. |
| Launcher key | `state/launcher/row-signing.key` (Ed25519) and `state/launcher/key-owners.jsonl`, mode 0600 | Launcher. Confined processes hide `state/launcher`. Readers are configured with the public key. The owner journal keeps each key's first instance and role. |

A certificate-fingerprint change or a channel public key change advances
`boot_generation`. The caller revokes that instance's issued grants on
`rebound`, the same path as a pid rebind, and advances that guard's fence
epoch.

## Route gates

| Gate | Status | Why |
| --- | --- | --- |
| G0 | Deferred | Criterion text is not in the vendored WS1 r1 contracts. |
| G1 | Deferred | Criterion text is not in the vendored WS1 r1 contracts. |
| G2 | Deferred | WS-PERF06 blocks a G2 claim without hardware evidence. This VM has no `/dev/sev`, uid 1000 cannot open `/dev/kvm`, and S0 was not launched. Not `vm_e2e`. |
| G3 | Deferred | Criterion text is not in the vendored WS1 r1 contracts. |
| G4 | Deferred | Criterion text is not in the vendored WS1 r1 contracts. |
| G5 | Deferred | WS-PERF06 blocks a G5 claim without hardware evidence. Not `confidential_baremetal`. |

`passed_gate_ids` is empty. The fill that this tree does run is `process_e2e`.
