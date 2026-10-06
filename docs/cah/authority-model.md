# CAH authority model

This note supersedes two claims in
[docs/eggomi/ARCHITECTURE.md](../eggomi/ARCHITECTURE.md):

- keeper exposing a live secret API such as `get_secret`,
  `mint_session_token`, or `list_connections`
- branching a live keeper by checkpoint and treating that branch as ordinary
  scaling

WS1 forbids both. The host-native Eggomi profile on this branch follows the
rules below. Older sentences in the Eggomi architecture that still name those
APIs are historical sketch text, not the model this stack runs.

## Who chooses authority

`PrepareUse` may repeat origin, resource handle, policy revision, lease,
audience, field, tenant, and recipient. Keeper loads the current
`cah-keeper-policy/v1` revision from its private directory on that call.
Nothing is cached. A mismatch, including an origin the requester invented,
is `denied_payload` and stores no grant. Frame id and navigation generation
are taken from the policy, not from the omi body. Admission does not read
the policy directory. The launcher does not install the profile fixture as
the live authority file. A test double calls `publish_revision` to simulate
the keeper write.

The runtime allow graph stays `service-access/v1`. The mapping to
`eggomi/workload-service-access/v1` is
`test-suites/cah/profiles/eggomi/service-access-map.json`. Three edges are
explicit deviations and are not silent replacements of the WS1 file:

| Runtime edge | WS1 direction this stub does not implement |
| --- | --- |
| `credential-broker` → keeper `ResolveUseGrant` | keeper → broker `AuthorizeUse` |
| browser → keeper `ReportOutcome` | keeper → browser `ExecuteBrowserOperation` |
| browser → keeper `QueryOutcome` | WS1 has no separate outcome query |
| launcher writes the registry in-process | launcher → identity-service `IssueForVerifiedLaunch` |

The opaque grant stays in keeper. The broker asks keeper to consume it.

## Recipient binding

A grant is issued only when the recipient already has a channel public key,
a certificate fingerprint, or a pid plus start time. Resolve identifies the
presenter by a possession proof over the guard's lease key, then checks the
registry row for that key. Body fields named `observed_*` are refused.
A null fingerprint does not skip the check.

A second admitted `browser-guard` that presents a copied `grant_ref` is
`denied_recipient` at resolve. The grant stays issued for the bound
recipient. An `omi-runner` call to the broker is a different check: the
access graph returns `denied_role` before the grant is examined.

Rebinding a pid, a start time, or a certificate fingerprint advances
`boot_generation` and revokes that instance's issued grants. A fingerprint
change is a rebind whether or not the row already has a pid. The first bind,
which records a fingerprint or a pid on a row that has neither, does not
advance the generation. Repeating the same fingerprint on that empty row does
not either. `set_boot` accepts only a boot id that is not already in
`boot_history`. Repeating an older id raises `BootRollback`. A generation
mismatch on resolve is terminal `denied_boot`. Returning to an earlier
fingerprint does not revive a grant that the rebind revoked. `denied_boot`
is the only wire code for that outcome.

`CompleteFill` carries a proof and the live frame. Keeper compares frame and
navigation to `destination_binding`. A mismatch is `denied_payload` and does
not consume the grant. On success the answer is one sealed credential. The
broker forwards it and does not hold the plaintext. The guard rebuilds the
associated data from its lease, its registry row, and the operation it is
running. The lease carries the profile-lease fence, the lease epoch, and the
keeper boot epoch it was granted under. A seal from an older keeper boot does
not open. Expiry is a guard monotonic offset of at most 30 seconds from a
challenge the guard issued. The keeper's `expires_mono` is not that check.

## Consumption survives reload

Consumption and bootstrap-token use are appended to
`authority/authority-journal.jsonl`. The keeper epoch lives beside that
journal, not only inside `grants.json`. Restoring an older grant snapshot, or
a scope file that still says `used: false`, does not revive a journaled
grant or token.

Issue is journaled with its operation id before the grant is saved. One
operation id yields one grant, so a restored `grants.json` cannot be used to
prepare the same approved use again. Every journal row is fsynced before the
call returns, so the consume is durable before the sealed answer leaves.

Use ttl is capped at 60 seconds.

## What this process split is

Non-keeper processes run in a user and mount namespace that hides
`state/authority` and other role directories, then bind-mounts only that
process's role material. `admission.json` is remounted read-only in that
namespace. Keeper stays unconfined because it owns the policy, the lab CA
key, and the journal.

Same-uid ptrace between the launcher and a stub is not additionally blocked.
Evidence for the fill remains E1 / `process_e2e`. It is not a confidentiality
claim and not `confidential_baremetal`.
