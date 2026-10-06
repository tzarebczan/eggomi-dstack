# Stack answers S1–S7

Answers for the keeper, 2026-10-06. Asks 2–8 are on
`cursor/cah-compartment-stubs-194a`. Ask 9 is a separate branch stacked on
PR #1. This note does not merge either pull request.

Asks 2–8 are commit `b10847b9bcf7f252021a054575b5e06cf003e8d3`.
The S1–S7 note is `00055b3f7029765227a9d5daad6b28eaac4de268`.
Pin the tip of PR #2. This Freeze section is the only change after that note.
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

Grant records bind `audience`, `field`, and `tenant`. `unknown` is a
`ReportOutcome` value and `QueryOutcome` returns it for the consumed
recipient. The wire code is `denied_boot`. `revoked_boot` is not stored or
returned.

## S5

`ResolveUseGrant` seals one credential to the recipient guard's per-lease
X25519 key (`cah-sealed-answer/v1`). The broker forwards the blob and does
not hold the canary. Associated data covers the §4.1 fields plus requester,
task, operation, and resource. The guard rebuilds that data from its lease,
its registry row, and the operation it is running. It records
`(grant_ref, nonce)` before returning a fill. A crash after that record is
`unknown` and is not followed by a second fill. `observed_*` is
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
| 4 audience, field, tenant, unknown, `denied_boot` | Done. |
| 5 sealed credential, broker holds no secret, admission off keeper | Done. |
| 6 associated data, single-use, `unknown` on crash | Done. |
| 7 pidfd plus keyed channel, fd-passing and pid-reuse vectors | Done. Cert-only A→B→A kept. |
| 8 fence outside the guard disk, guard-clock expiry, operation binding | Done. |
| 9 simulated SNP KMS | Separate PR stacked on PR #1. Lab-only. |
