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
| platform-launcher | The process that starts the compose stack | `AdmitWorkload` with a one-use scope file. |
| connector | Matrix or stealth compartments | No allow edge until `service-access.json` grows one. |

The profile does not replace `compose.lab.yaml` and does not add a parallel
simulator. Outer SNP simulation remains
[`test-suites/eggomi`](../../test-suites/eggomi/README.md). When Eggomi wires
these sockets, it should pass the bound `unix:` or `tcp:` address published
in `ready/<role>` and keep identity in the admission registry (or, later, in
a SPIFFE URI that the same registry already understands).

## Use-grant shape

`examples/workload-use-grant.json` shows the server-side record:

- requester and recipient, each with role, instance, boot, and certificate fingerprint
- policy revision, method `CompleteFill`, resource handle, and origin
- task id and operation id
- lease id, epoch, `use_limit` 1, and expiry

The bytes on the wire are an opaque reference. `omi-runner` receives that
reference from `PrepareUse` and the browser presents it to `CompleteFill`.
Keeper binds the reference to the recipient that the broker observed on the
transport (`observed_peer_pid` or `observed_fingerprint`). A copied reference
presented by another role or another boot id stays `issued`.

## Limits of this profile

The synthetic fill is passed to the broker on stdin. It is a lab canary.
Disk and checkpoint searches from test plan S4 are still open, because these
processes are not smolvm guests.

Same-uid E1 means the registry and lab CA are not a secret from the other
stubs. SPIRE, nested smolvm, and guest injection are the follow-on that would
change that placement. In-flight Eggomi keeper pull requests stay mergeable
on their own branch. This profile does not land application changes in
`tzarebczan/eggomi`.
