# CAH name map

Sits beside [`authority-model.md`](authority-model.md). The stack column is
this mirror's CAH package after the asks 2–8 freeze. The Eggomi column is
carried forward from the previous pack. This file does not re-audit those
Eggomi paths, and it does not change Eggomi adapters.

Each row is a different object. Adapters use the stack name for the stack
object and leave the Eggomi name on the Eggomi object.

| Stack contract | Eggomi surface | Adapter rule |
| --- | --- | --- |
| `PrepareUse` on keeper-core. The current `cah-keeper-policy/v1` revision is loaded from the keeper directory on every call. | Desktop keeper methods are `health`, `computer.acquire`, `computer.attach`, `computer.release`. Those three throw `kek_authority_unset`, then `not_implemented`. | Add `PrepareUse` as its own method. The keeper publishes immutable revisions. In the lab demo the launcher is that test double and publishes the profile fixture once through `publish_revision`. It does not copy the fixture to `authority/keeper-policy.json`. Leave `computer.*` on the computer lease. |
| Opaque `workload-use-grant/v1`. The wire value is `grant_ref`. The record binds audience, field, tenant, fence, and the keeper boot epoch. One operation id yields at most one grant. | `computer-lease` is a signed control-chain entry. Workbench grants are `packages`, `system`, and `hosting`. | Hold the CAH grant as opaque bytes. Leave the control chain, the workbench grant, and the agent ticket on their own jobs. |
| `service-access/v1`, default deny. `QueryOutcome` is an edge. `AdmitWorkload` is not. | hostd listens on `runtime.sock`, `control.sock`, and `keys.sock`. | Publish calls on the service-access graph. Leave `keys.sock` as the hostd stub. |
| Channel possession is the registered X25519 public key, or a certificate fingerprint on mTLS. `SO_PEERPIDFD` plus start time only gates setup. There is no `SO_PEERCRED` fallback. | `SO_PEERCRED` collects pid, uid, and gid. Admission compares uid. | Keep the uid check. Refuse the peer when `SO_PEERPIDFD` is missing. The keyed channel is the identity after setup. |
| `boot_generation` advances on any change to a stored identity field: a pid, start-time, certificate, or channel-public bind or rebind, including the first bind onto an empty row, a certificate-only row and a return to a previous channel key. The wire code is `denied_boot`. | hostd has `hostKeyEpoch`, `kekVersion`, and the confidential lease fence. The desktop KEK witness has `bootEpoch`. | Record `boot_generation` as its own integer. Leave `bootEpoch`, the lease fence, and `compose_hash` on their current jobs. |
| Unix RPC is Noise KK (`Noise_KK_25519_ChaChaPoly_SHA256`, prologue `eggomi/cah-channel/v1`), u16-length frames, keeper.sock JSON. The keeper rechecks the row before each call. The client selects the callee registry row by role and instance. mTLS keeps the five-field callee pin. | `apps/desktop/src/keeper/cah/channel.ts` speaks the same wire. The possession row's `SO_PEERCRED` check stays the hostd peer check. | One protocol on both sides; `vectors/eggomi-interop.json` pins the bytes. A process that holds a passed fd but not the registered key cannot complete a frame. A plain fork that copies the key is the same compartment. |
| Resolve returns `cah-sealed-answer/v3`, sealed to the guard's registered channel key and authenticated with the keeper static key. Associated data includes the §4.1 fields, the keeper boot epoch, and the operation. The guard records `grant_ref` once. `unknown` is queryable by the recipient and the requester. | omi-node §3.9.4 "fill" is broker credential fill. | The broker holds no standing secret. A seal from a throwaway key does not open. `observed_*` is not authority. |
| Launcher `admit_scoped` writes `admission-registry/v1`. Every row carries `launcher_sig` (Ed25519 over `rowMessage`). Readers verify it with a configured public key. The launcher refuses a key or fingerprint whose first owner is another instance or role. Keeper only reads the registry. | omi-node §R1 "admission" is turn readiness. `apps/desktop/src/keeper/cah/registry.ts` verifies the same signature. | Call the stack write by its stack name. Configure the keeper with the launcher's public key. Leave turn admission on its current job. |
| `authority-model.md` supersedes CAH `get_secret`, `mint_session_token`, and `list_connections`. | dstack guest-agent `GetKey("eggomi/store-kek/v1")` stays inside hostd. | Leave dstack `GetKey` on the store-KEK path. Keeper adapters do not call CAH `get_secret`. |

See [`policy-ownership.md`](policy-ownership.md) and
[`stack-answers.md`](stack-answers.md).
