# Stack answers S1–S7

Answers for the keeper, 2026-10-06. PR #1 (simulated SEV-SNP harness),
PR #2 (asks 2–8) and PR #4 (ask 9, simulated SNP KMS) are merged on `next`
at `30bba240`. The keeper-gap pass after that merge is the PR that adds
this paragraph. Pin the `next` SHA it merges as. `revoked_boot` is not a
wire code.

## Founder decisions on the adapter's questions (#747, #748)

The stack asks from those decisions land in one PR after `56cd7653`.

| Ask | Status |
| --- | --- |
| Launcher signs each row (`launcher_sig`) | Done. Ed25519 over Eggomi's `rowMessage` bytes. The key is `state/launcher/row-signing.key`, outside every compartment. Readers take the 32-byte public key by configuration (`--launcher-public`). An unsigned or badly signed row is no identity, at the pidfd gate and at resolve. `cah/launcher.py`, `cah/registry.py`. |
| Refuse a key already bound elsewhere | Done. First owner (instance and role) wins, even after its row is gone. Memory is `state/launcher/key-owners.jsonl`, fsynced, outside `authority/` and the registry. |
| Lab channel moves to Noise KK | Done. `Noise_KK_25519_ChaChaPoly_SHA256`, prologue `eggomi/cah-channel/v1`, Eggomi's framing and keeper.sock JSON. `cah-channel/v1` is gone. The keeper rechecks the row before every call. `cah/noise.py` passes the official KK vectors. |
| Interop proof | Done. `vectors/eggomi-interop.json` comes from Eggomi's `channel.ts`, `registry.ts` and `packages/noise`; `tests/test_interop.py` reproduces it in Python in CI. `scripts/eggomi-interop.sh <eggomi-repo>` also runs Eggomi's TypeScript against the stack over sockets. |
| CI job | Done. `.github/workflows/cah-tests.yml` on `ubuntu-24.04`. It fails before the tests when the kernel is older than 6.5, `SO_PEERPIDFD` is missing, or user and mount namespaces do not work. Nothing is skipped. |

## Keeper-gap pass after the merge

- One approved operation yields one grant. `PrepareUse` for an operation id
  that already has a grant is `denied_payload` and stores nothing. Issue is
  journaled under `host-fence/` with the operation id, so restoring
  `authority/` does not allow a second grant (and so a second fill) for one
  approved use. Each policy operation names its `requester_instance_id`, so
  another admitted requester cannot spend it.
- keeper-core advances a durable boot epoch at every start
  (`state/host-fence/keeper-boot-epoch`). Grants record it. Resolve of a
  grant from an earlier boot is terminal `denied_boot`. The sealed answer is
  `cah-sealed-answer/v3`; its associated data adds `keeper_epoch`, which the
  guard reads from its lease, not from the broker. A seal from an older
  keeper boot does not open under a lease re-granted by the newer one.
- Keeper and guard journal rows are fsynced, and so is the directory entry
  of a new journal or epoch file. The consume is durable before resolve
  hands out the sealed bytes.
- The guard holds one fence lock across unwrap, expiry, open, and record.
  `advance_epoch` takes the same lock, so a rebind cannot land between the
  unwrap and the fill, and waiting on the lock past the deadline is
  `grant_expired`.
- Not changed: whoever holds a guard's private key can seal a blob that
  guard opens (static-static authentication). That holder is the guard, and
  the key's secrecy inside the compartment is already the boundary.
- The W0 packet and integration manifest no longer say the fill secret is
  broker stdin. The keeper holds it in `authority/fill-secret`.

## S1

PR #2 rebased cleanly onto PR #1 tip `3e904dd7`. The only PR #1 commits were
`.cursor/environment.json` access for the eggomi checkout. No conflicts.
The certificate-only boot generation fix is preserved: bind fingerprint A,
rebind B, return to A, and a restored grant snapshot still resolves as
`denied_boot`. That behavior landed as `16b02171` on this branch (the
rebased form of the previous tip). PR #2 was not merged into PR #1.

## S2

[`name-map.md`](name-map.md) sits beside the authority model. The stale
in-flight PR list is gone from [`integration-map.md`](integration-map.md).

## S3

Policy revisions are published by the keeper test double and loaded on every
`PrepareUse`. See [`policy-ownership.md`](policy-ownership.md). Admission
does not read the policy directory.

## S4

Grant records bind `audience`, `field`, and `tenant`. Empty values match
nothing. `unknown` is a `ReportOutcome` value. `QueryOutcome` returns it for
the consumed recipient and for the requester. A consumed grant with no
report is `unknown`. The first terminal report for a `grant_ref` is final.
The wire code is `denied_boot`. `revoked_boot` is not stored or returned.

## S5

`ResolveUseGrant` seals the keeper-held fill secret to the recipient guard's
registered channel key (`cah-sealed-answer/v3`). The KDF mixes
`X25519(keeper_static, guard_channel)`. The guard opens with the keeper
public key from the registry, not a key carried in the blob. A throwaway
sealer key does not open. The broker forwards the blob and does not hold
the canary. Associated data covers the §4.1 fields, including the keeper boot epoch,
plus requester, task, operation, and resource. The guard rebuilds that data from its lease, its
registry row, and the operation it is running. It records `grant_ref`
before returning a fill. A new nonce for that grant does not fill again. A
crash after that record is `unknown` and is not followed by a second fill.
The seal is built before the consume is journaled. `observed_*` is
`denied_authority_field`. `AdmitWorkload` is off keeper-core. The launcher
writes the registry.

## S6

Deferred on this branch. Real-hardware SNP vectors, the MrConfigV3 identity
spec, and the choice of a TypeScript or WASM verifier are keeper and
hardware work. `HOST_ATTEST_KEY_PROVIDERS` waits for hardware. The simulated
KMS layer from F2 is ask 9. It merged as PR #4, lab-only, and its outputs
do not pass a production gate. Phala TDX is unchanged. The platform-tagged
verdict stays with the keeper.

## S7

`SO_PEERCRED` is gone. Unix admission uses `SO_PEERPIDFD` and refuses when
that option is missing. The pidfd must still be alive before start time is
trusted. pid and start time only gate channel setup. Unix RPC then runs on
Noise KK keyed to the registered static key (prologue
`eggomi/cah-channel/v1`), the same wire as Eggomi's keeper. Lab mTLS over TCP is the keyed channel on that
transport, because `SO_PEERPIDFD` is not available on an `AF_INET` socket.
Key secrecy inside the compartment is the identity boundary. A passed fd
without the key cannot complete a frame. Tests cover a dead pidfd, a missing
`SO_PEERPIDFD` with no peercred fallback, and fd passing.

## Asks

| Ask | Status |
| --- | --- |
| 1 freeze and undraft PR #2 | Done. PR #2 merged on `next`. The freeze is the `next` SHA of the keeper-gap pass. |
| 2 name map, drop stale PR list | Done. |
| 3 policy loaded every call | Done. |
| 4 audience, field, tenant, unknown, `denied_boot` | Done. Empty bindings match nothing. The first terminal outcome per `grant_ref` sticks. The requester can query `unknown`. |
| 5 sealed credential, broker holds no secret, admission off keeper | Done. The seal is keeper-authenticated. The recipient key is the guard channel key, not a separate per-lease key. |
| 6 associated data, single-use, `unknown` on crash | Done. Single-use is `grant_ref`, and one operation yields one grant. A fresh nonce does not fill again. The keeper boot epoch is in the associated data. |
| 7 pidfd plus keyed channel, fd-passing and pid-reuse vectors | Done. Cert-only A→B→A kept. Channel-key A→B→A advances `boot_generation` the same way. |
| 8 fence outside the guard disk, guard-clock expiry, operation binding | Done in the lab layout. The keeper epoch and consume journal are `state/host-fence`, outside `authority/`. Restoring `authority/` does not make a consumed grant resolve `ok`. The guard fence is `state/fence/<instance>`, hidden from other compartments, and that guard bind-mounts only its own directory. `advance_epoch` moves the fence epoch; a restored wrap does not open. This is a host file, not a TPM NV counter or a KMS monotonic counter. |
| 9 simulated SNP KMS | Merged as PR #4. Lab-only. |
