# Stack answers S1–S7

Answers for the keeper, 2026-10-06. Asks 2–8 are on
`cursor/cah-compartment-stubs-194a`. Ask 9 is a separate branch stacked on
PR #1. This note does not merge either pull request.

Asks 2–8 were first committed as `b10847b9bcf7f252021a054575b5e06cf003e8d3`.
The S1–S7 note is `00055b3f7029765227a9d5daad6b28eaac4de268`.
The review fix on this branch is the tip of PR #2. Pin that tip.
`revoked_boot` is not a wire code on these commits.

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

`ResolveUseGrant` seals the standing fill secret to the recipient guard's
registered channel key (`cah-sealed-answer/v2`). The KDF mixes
`X25519(keeper_static, guard_channel)`. The guard opens with the keeper
public key from the registry, not a key carried in the blob. A throwaway
sealer key does not open. The broker forwards the blob and does not hold
the canary. Associated data covers the §4.1 fields plus requester, task,
operation, and resource. The guard rebuilds that data from its lease, its
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
KMS layer from F2 is ask 9, on a branch stacked on PR #1, and its outputs
do not pass a production gate. Phala TDX is unchanged. The platform-tagged
verdict stays with the keeper.

## S7

`SO_PEERCRED` is gone. Unix admission uses `SO_PEERPIDFD` and refuses when
that option is missing. The pidfd must still be alive before start time is
trusted. pid and start time only gate channel setup. Unix RPC then uses the
registered static key. Lab mTLS over TCP is the keyed channel on that
transport, because `SO_PEERPIDFD` is not available on an `AF_INET` socket.
Key secrecy inside the compartment is the identity boundary. A passed fd
without the key cannot complete a frame. Tests cover a dead pidfd, a missing
`SO_PEERPIDFD` with no peercred fallback, and fd passing.

## Asks

| Ask | Status |
| --- | --- |
| 1 freeze and undraft PR #2 | Done once this branch is pushed and the PR is marked ready. |
| 2 name map, drop stale PR list | Done. |
| 3 policy loaded every call | Done. |
| 4 audience, field, tenant, unknown, `denied_boot` | Done. Empty bindings match nothing. The first terminal outcome per `grant_ref` sticks. The requester can query `unknown`. |
| 5 sealed credential, broker holds no secret, admission off keeper | Done. The seal is keeper-authenticated. The recipient key is the guard channel key, not a separate per-lease key. |
| 6 associated data, single-use, `unknown` on crash | Done. Single-use is `grant_ref`. A fresh nonce does not fill again. |
| 7 pidfd plus keyed channel, fd-passing and pid-reuse vectors | Done. Cert-only A→B→A kept. Channel-key A→B→A advances `boot_generation` the same way. |
| 8 fence outside the guard disk, guard-clock expiry, operation binding | Done in the lab layout. The keeper epoch and consume journal are `state/host-fence`, outside `authority/`. Restoring `authority/` does not make a consumed grant resolve `ok`. The guard fence is `state/fence/<instance>`, hidden from other compartments, and that guard bind-mounts only its own directory. `advance_epoch` moves the fence epoch; a restored wrap does not open. This is a host file, not a TPM NV counter or a KMS monotonic counter. |
| 9 simulated SNP KMS | Separate PR stacked on PR #1. Lab-only. |
