<!--
SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
SPDX-License-Identifier: Apache-2.0
-->

# Eggomi SEV-SNP simulation harness

This harness boots a dstack development image through the existing
`dstack-amd-sev-snp` simulator path. It uses throwaway mock attestation roots,
QEMU `no_tee`, and swtpm, so it provides no confidentiality and must never
handle production secrets.

## Run S0

The outer VM needs KVM, but it does not need `/dev/sev` or an SNP-capable CPU.
Install QEMU, swtpm, jq, curl, and Docker with the Compose plugin. Build or
install:

- a dstack development guest image with `metadata.json` containing
  `"is_dev": true`;
- `dstack-vmm`, `supervisor`, and the VMM CLI;
- `dstack-mock-attestation`.

The full guest image and VMM setup are described in
[Develop with simulated AMD SEV-SNP](../../docs/eggomi/development-with-simulated-snp.md).
From the repository root, create a job-unique seed and matching mock roots:

```bash
./test-suites/eggomi/scripts/mock-collateral.sh generate
cat test-suites/eggomi/.state/vmm-tee-simulator.toml
```

Merge the printed `[cvm.tee_simulator]` table into the VMM configuration and
restart `dstack-vmm`. The default collateral URL, `http://10.0.2.2:18088`,
assumes QEMU user networking. Override `EGGOMI_COLLATERAL_URL` before generation
when the guest reaches its host through another address.

Run the smoke:

```bash
export EGGOMI_DEV_IMAGE=dstack-dev-<version>
# Set this only when `dstack vmm ls` finds more than one VMM. Use that
# command's address, which may be an HTTP URL or a unix socket.
# export DSTACK_VMM_URL=unix:$HOME/.dstack-vmm/run/vmm.sock
./test-suites/eggomi/scripts/s0-sim-smoke.sh
```

Enable `[cvm.port_mapping]` before deploying. S0 publishes the persistence
probe on `127.0.0.1:18089`, and the VMM rejects that request while port
mapping is disabled. The development image must also contain
`measurement.snp.cbor`, which current `dstack-dev` builds do.

S0 starts the mock AMD-KDS-shaped collateral service, creates a TPM-backed
state probe, deploys it with
`--simulated-tee dstack-amd-sev-snp`, and waits for
`status=running, boot_progress=done`. It checks the per-VM manifest and
simulator handoff for:

- `simulated_tee=dstack-amd-sev-snp`, `no_tee=true`, and swtpm;
- an SNP measurement document and MrConfigV3 binding;
- the job seed generated above;
- no host-selected trust anchor in `.sys-config.json`.

When Docker is available, S0 also invokes the existing privileged attestation
E2E for the SNP case. That test requests evidence through the simulated TSM
ABI, accepts it with the generated mock root, and rejects the same evidence
with the verifier's production roots. Set `EGGOMI_RUN_S6=false` to defer that
step, or run it directly:

```bash
./test-suites/eggomi/scripts/s6-faults.sh
```

The VM is deliberately left running for S1. Remove it with `dstack remove
VM_ID` after completing the persistence check.

## Run S1

S1 gracefully stops and starts the S0 VM. It requires the instance ID and the
application's persistent marker to remain unchanged, the boot counter to
advance, and both `hda.img` and the swtpm permanent state to survive.

```bash
./test-suites/eggomi/scripts/s1-persistence.sh
```

By default the scripts inspect `~/.dstack-vmm/vm`. Set `EGGOMI_VM_DIR` before
S0 when the VMM stores VM work directories elsewhere. S1 is a lifecycle stub:
it covers dstack's encrypted-disk and swtpm persistence boundary, while inner
smolvm checkpoint policy remains a later milestone.

## Results and gates

The harness writes artifacts under `test-suites/eggomi/.state/work/`.
`s0-metrics.prom` records outer boot time, QEMU RSS, VM work-directory disk
usage, and S1 restart time. Guest `MemAvailable` is emitted as `NaN` until a
guest metrics endpoint is added.

Missing KVM, tools, a running VMM, or a development image makes S0 exit with
code 77 and write a metrics file with `eggomi_s0_available 0`. This is an
explicit environment skip, not a passing simulator run. Use `--preflight` to
check the host without deploying:

```bash
./test-suites/eggomi/scripts/s0-sim-smoke.sh --preflight
```

S6 has two production-root checks. The default command runs both unit hooks
and then the container check when Docker is usable:

```bash
./test-suites/eggomi/scripts/s6-faults.sh
./test-suites/eggomi/scripts/s6-faults.sh measurement-mismatch
./test-suites/eggomi/scripts/s6-faults.sh prod-root-unit
./test-suites/eggomi/scripts/s6-faults.sh prod-root-reject
```

`prod-root-unit` asks the production SEV-SNP quote verifier to reject mock
evidence signed under a throwaway ARK. It needs Cargo, not KVM or Docker.
`prod-root-reject` runs the existing privileged attestation container: the
simulator produces SNP evidence, mock roots accept it, and the verifier's
built-in production roots reject it. Without Docker or a reachable daemon
that command exits 77. `./s6-faults.sh` without arguments keeps the unit
result and records that skip instead of treating it as a passing container
run.

## Run S2

S2 deploys `s2-compose.yml`, a guest client that quotes through the guest
agent and calls a long-running `snp-sim-kms serve` on the host. The script
then checks four outcomes: release refused while the gate is off; a signed
release for the matching measurement and nonce; refusal of a replay, a
report_data mismatch, and a MEASUREMENT mismatch; and production-root
refusal of the release evidence.

```bash
cargo build --manifest-path dstack/Cargo.toml --release -p snp-sim-kms
./test-suites/eggomi/scripts/s2-kms.sh
```

S0, S1, and S2 reuse a collateral server that already listens on
`EGGOMI_COLLATERAL_PORT`. The [L1 runbook](../../docs/eggomi/l1-lab-runbook.md)
covers a standing lab, run with `scripts/l1-lab.sh`, and records measured
results.

## Lab SNP KMS

`snp-sim-kms` is the in-process simulated SEV-SNP key service. It is lab-only:
a production quote verifier rejects its VCEK chain, and `production_gate`
does not return success. From the repository root, run `cargo test --manifest-path dstack/Cargo.toml -p snp-sim-kms`. The notes are in
[docs/eggomi/simulated-snp-kms.md](../../docs/eggomi/simulated-snp-kms.md).

## Nested virtualization

S0 and S1 cover only the outer dstack CVM. smolvm subVMs inside an SNP CVM
are not possible on real hardware today: Linux refuses `kvm_amd` inside an
SEV guest, and AMD lists nested virtualization in SEV guests as a future
feature (AMDESE/AMDSEV issue #63). Do not enable nested KVM in the lab guest;
it would pass where real SNP fails. `nested-kvm-probe.yml` records what the
guest sees. On the first L1 host the guest CPU showed `svm`, but the guest
kernel has no KVM and `/dev/kvm` was missing. Inner isolation is pending a
founder decision (see [ARCHITECTURE](../../docs/eggomi/ARCHITECTURE.md#inner-isolation)).
Host-native smolvm (L2) remains the baseline for the non-confidential local
computer only.

Delete `.state/` between CI jobs or whenever rotating the mock seed. Never
copy these roots or seeds into a production KMS, verifier, image, or secret
workflow.

Compartment RPC for the Eggomi profile runs from
[`test-suites/cah`](../cah/README.md). `CAH_MODE=outer` is the only CAH path
that invokes S0. The fill demo stays on the host.
