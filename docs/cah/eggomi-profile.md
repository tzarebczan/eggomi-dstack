# Eggomi profile

Eggomi is profile 1 of the confidential-agent harness. The profile graph is
`test-suites/cah/profiles/eggomi/graph.json`. The allow graph is
`service-access.json`. The fill inputs are `fill-fixture.json`.

Started roles are `keeper-core`, `credential-broker`, `connector`,
`browser-guard`, `omi-runner`, and `platform-launcher`. `data-service`,
`matrix-device`, `workbench`, `workload-issuer`, and `telemetry-agent` are
listed and not started.

## Where the stubs sit later

Eggomi already has a lab CVM layout under `infra/dstack` on its master branch
(coordinator description, not inspected here): compose, `compose.lab.yaml`,
browser, egress, a hostd stub, workbench/gVisor, stealth/Tor, probes, and
`LAB-NOTES.md`. CAH should be consumed by that layout.

| CAH role | Later Eggomi neighbor | Port to consume |
| --- | --- | --- |
| keeper-core | hostd and `apps/desktop/src/keeper` | Keeper RPC: `PrepareUse`, `ResolveUseGrant`, `ReportOutcome`. Admission stays with the launcher. |
| browser-guard | `infra/dstack` browser | `CompleteFill` to the broker, then `ReportOutcome` to keeper. |
| credential-broker | New neighbor beside egress | Resolves a use-grant with keeper and returns the fill. Egress allowlists stay on the egress role. |
| omi-runner | Agent loop when it exists | `PrepareUse` only. |
| platform-launcher | The process that starts the compose stack | In-process one-use scope write. Keeper has no `AdmitWorkload`. |
| connector | Matrix or stealth compartments | No allow edge until `service-access.json` grows one. |

The profile does not replace `compose.lab.yaml` and does not add a parallel
simulator. Outer SNP simulation remains
[`test-suites/eggomi`](../../test-suites/eggomi/README.md). When Eggomi wires
these sockets, it should pass the bound `unix:` or `tcp:` address published
in `ready/<role>` and keep identity in the admission registry (or, later, in
a SPIFFE URI that the same registry already understands).

## Use-grant shape

`examples/workload-use-grant.json` shows the server-side record:

- requester and recipient, each with role, instance, boot generation, and a possession proof
- policy revision, method `CompleteFill`, resource handle, and origin
- destination binding: origin, document generation, and frame
- task id and operation id
- lease id, epoch, `use_limit` 1, and a ttl of at most 60 seconds

The bytes on the wire are an opaque reference. `omi-runner` receives that
reference from `PrepareUse` and the bound browser presents it to
`CompleteFill`. Origin, audience, field, tenant, and destination come from
the keeper policy. The record also stores those bindings. Resolve identifies
the guard by a possession proof of its lease key, not by `observed_*`
fields. A missing fingerprint does not skip that check. The resolve body is
one sealed credential (`cah-sealed-answer/v1`). The broker does not hold the
plaintext. The fill canary lives in `authority/fill-secret`, which confined
processes cannot read.

An `omi-runner` request to the broker is `denied_role` on the access graph.
That is not the copied-grant check. A second admitted `browser-guard` that
presents the same reference is `denied_recipient` at resolve, and the grant
stays `issued` for the bound recipient. A certificate-fingerprint change is
a rebind, with or without a pid: `boot_generation` advances and that
instance's issued grants are revoked. Binding the previous fingerprint again
does not restore them. A boot-generation mismatch is terminal `denied_boot`.
`ReportOutcome` accepts `filled`, `refused`, or `unknown`. `QueryOutcome`
returns that record to the same recipient.

## Limits of this profile

The synthetic fill is a lab canary sealed to the guard. The broker stdin
path is gone.
Disk and checkpoint searches from test plan S4 are still open, because these
processes are not smolvm guests.

Non-keeper stubs cannot read `state/authority` or rewrite `admission.json`
from their mount namespace. They still share a uid with the launcher, so
same-uid ptrace is an E1 limit. SPIRE, nested smolvm, and guest injection are
the follow-on that would change that placement. In-flight Eggomi keeper pull
requests stay mergeable on their own branch. This profile does not land
application changes in `tzarebczan/eggomi`. The 2026-10-06 HTTP 404 for that
repository was a GitHub App token scoped only to `eggomi-dstack`, not a
missing repository.
