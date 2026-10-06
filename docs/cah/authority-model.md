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

`PrepareUse` may repeat origin, resource handle, policy revision, lease, and
recipient. Keeper compares that echo to `cah-keeper-policy/v1` in the keeper
authority directory. A mismatch, including an origin the requester invented,
is `denied_payload` and stores no grant. Frame id and navigation generation
are taken from the policy, not from the omi body.

The runtime allow graph stays `service-access/v1`. The mapping to
`eggomi/workload-service-access/v1` is
`test-suites/cah/profiles/eggomi/service-access-map.json`. Three edges are
explicit deviations and are not silent replacements of the WS1 file:

| Runtime edge | WS1 direction this stub does not implement |
| --- | --- |
| `credential-broker` → keeper `ResolveUseGrant` | keeper → broker `AuthorizeUse` |
| browser → keeper `ReportOutcome` | keeper → browser `ExecuteBrowserOperation` |
| launcher → keeper `AdmitWorkload` | launcher → identity-service `IssueForVerifiedLaunch` |

The opaque grant stays in keeper. The broker asks keeper to consume it.

## Recipient binding

A grant is issued only when the recipient already has a certificate
fingerprint or a pid plus `/proc/<pid>/stat` start time. Resolve checks every
proof that was stored. A null fingerprint does not skip the check.

A second admitted `browser-guard` that presents a copied `grant_ref` is
`denied_recipient` at resolve. The grant stays issued for the bound
recipient. An `omi-runner` call to the broker is a different check: the
access graph returns `denied_role` before the grant is examined.

Rebinding a pid or start time advances `boot_generation` and revokes that
instance's issued grants. Replacing a fingerprint does the same when the row
already has a pid or start time. Replacing only `cert_fingerprint` while pid
and start time are still empty does not advance the generation, and issued
grants for that instance are not revoked. That cert-only rebind is still
open. `set_boot` accepts only a boot id that is not already in
`boot_history`. Repeating an older id raises `BootRollback`. A generation
mismatch on resolve is terminal `revoked_boot`.

`CompleteFill` sends `frame_id` and `navigation_generation`. Keeper compares
them to `destination_binding`. A mismatch is `denied_payload` and does not
consume the grant.

## Consumption survives reload

Consumption and bootstrap-token use are appended to
`authority/authority-journal.jsonl`. The keeper epoch lives beside that
journal, not only inside `grants.json`. Restoring an older grant snapshot, or
a scope file that still says `used: false`, does not revive a journaled
grant or token.

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
