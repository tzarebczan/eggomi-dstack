<!--
SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
SPDX-License-Identifier: Apache-2.0
-->

# CAH compartment stubs

Host-native Eggomi profile for the confidential-agent harness. Evidence for
the fill is E1. The outer simulated-SNP substrate is
[`../eggomi`](../eggomi/README.md). Design notes are in
[`docs/cah`](../../docs/cah/README.md).

## Run the fill

```bash
./test-suites/cah/scripts/cah-launch.sh
```

On this agent VM (2026-10-06), from `/workspace`, that printed:

```text
[cah] /dev/kvm exists but this user cannot open it
[cah] simulated SNP substrate not entered; fill fidelity is E1 host-native
{"evidence_level": "E1", "ok": true}
[cah] report /workspace/test-suites/cah/.state/fill-unix/report.json
[cah] measurements /workspace/test-suites/cah/.state/fill-unix/measurements.json
```

`report.json` then contains `"ok": true`, `"evidence_level": "E1"`,
`"fidelity": "host-native"`, and:

```json
"outer_cvm": {
  "dev_image_selected": false,
  "entered": false,
  "kvm": false,
  "kvm_node": true,
  "qemu": false,
  "reason": "/dev/kvm exists but this user cannot open it, so the simulated SNP substrate was not launched",
  "sev": false,
  "swtpm": false
}
```

Case results from that run:

| Case | Code |
| --- | --- |
| `smuggle_authority_field` | `denied_authority_field` |
| `browser_cannot_prepare` | `denied_role` |
| `forged_origin` | `denied_payload` |
| `prepare_positive` | `ok` |
| `hostile_navigation` | `denied_payload` |
| `hostile_left_issued` | `issued` |
| `positive_fill` | `ok` |
| `outcome` | `ok` |
| `outcome_other_browser` | `denied_payload` |
| `replay_consumed` | `grant_consumed` |
| `prepare_copied` | `ok` |
| `copied_wrong_role` | `denied_role` (access graph) |
| `wrong_role_left_issued` | `issued` |
| `copied_second_browser` | `denied_recipient` (admitted browser-2) |
| `copied_left_issued` | `issued` |
| `copied_owner_fill` | `ok` |
| `prepare_wrong_boot` | `ok` |
| `wrong_boot` | `denied_boot` |
| `connector_default_deny` | `denied_role` |
| `unadmitted` | `denied_unadmitted` |
| `bootstrap_wrong_role` | `denied_role` |
| `bootstrap_wrong_scope` | `denied_bootstrap` |
| `bootstrap_ok` | `ok` |
| `bootstrap_replay` | `denied_bootstrap` |

`CAH_TRANSPORT=mtls ./test-suites/cah/scripts/host-native-fill.sh` runs the
same cases over lab mTLS. The broker listen address is reached through the
byte-forwarder labeled `vsock:3:5200`. The browser certificate subject
contains `ignored-cn-browser-1` and the report field `cn_ignored` is true.

## Tests

```bash
./test-suites/cah/scripts/run-tests.sh
```

Requires Python 3.12, the `cryptography` package
(`pip install -r test-suites/cah/requirements.txt`), and
`PYTHONPATH=test-suites/cah` (the script sets that).
Ruff, when installed, is `ruff==0.11.4` with select `E,F,I,D` and ignore
`D203,D213,E501`.

## Eggomi interop

`tests/test_interop.py` checks that this suite and Eggomi's keeper agree on
the Noise KK channel bytes and on the `launcher_sig` row bytes and
signature. The vector half always runs: it recomputes
`vectors/eggomi-interop.json`, which Eggomi's own `channel.ts`,
`registry.ts` and `packages/noise` produced, in Python. The live half runs
Eggomi's TypeScript against the stack over Unix sockets (an Eggomi workload
through this keeper's pidfd gate, this workload against Eggomi's
`serveChannel`), feeds a stack-written registry to Eggomi's `readRegistry`,
and regenerates the vectors file to prove it is still Eggomi's output:

```bash
CAH_EGGOMI_NODE_MODULES=/path/to/eggomi/node_modules \
  ./test-suites/cah/scripts/eggomi-interop.sh /path/to/eggomi origin/master
```

It needs `node` (22.15+ for `module.registerHooks`, or older with
`module.register`) and a `node_modules` holding `@noble/ciphers`,
`@noble/curves`, `@noble/hashes` and `typescript`. Eggomi sources are read
through `git archive`. `CAH_INTEROP_UPDATE=1` rewrites the vectors file
first. Without `CAH_EGGOMI_CHECKOUT` the live tests are skipped by name.

## Layout

```text
cah/            Python package (stdlib plus `cryptography`)
profiles/eggomi service-access, graph, fill fixture, J-id aliases
examples/       workload-use-grant and harness-local experiment record
schemas/        pinned resource-measurement/v1 schema
scripts/        launch, fill, unit tests
tests/          access, grants, metrics, forwarder, channel, launcher, interop, full demo
interop/        Node driver for Eggomi's keeper code (live interop only)
vectors/        official Noise KK vectors and the Eggomi interop vectors
```

`.state/` is gitignored. Each demo deletes its state directory and starts
from an empty admission registry.
