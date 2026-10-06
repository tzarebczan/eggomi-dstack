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
| `prepare_positive` | `ok` |
| `positive_fill` | `ok` |
| `outcome` | `ok` |
| `replay_consumed` | `grant_consumed` |
| `prepare_copied` | `ok` |
| `copied_wrong_role` | `denied_role` |
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

Requires Python 3.12 and `PYTHONPATH=test-suites/cah` (the script sets that).
Ruff, when installed, is `ruff==0.11.4` with select `E,F,I,D` and ignore
`D203,D213,E501`.

## Layout

```text
cah/            Python package (stdlib only)
profiles/eggomi service-access, graph, fill fixture, J-id aliases
examples/       workload-use-grant and harness-local experiment record
schemas/        pinned resource-measurement/v1 schema
scripts/        launch, fill, unit tests
tests/          access, grants, metrics, forwarder, full demo
```

`.state/` is gitignored. Each demo deletes its state directory and starts
from an empty admission registry.
