# Eggomi CVM / SNP simulation test plan

This plan accompanies [ARCHITECTURE.md](ARCHITECTURE.md). It describes private
working-mirror tests; it does not authorize upstream issues or pull requests.

## Environments

| ID | Hardware | Outer TEE | Inner subVM | Secrets |
| --- | --- | --- | --- | --- |
| L1 | Local KVM | `--simulated-tee dstack-amd-sev-snp` | smolvm when nested | throwaway seed |
| L2 | Local or CI | none | host-native smolvm | none |
| L3 | Cloud VM, nested KVM off | simulated SNP | container fallback | throwaway seed |
| P1 | AMD SNP bare metal | real SNP | smolvm | production KMS policy |

CI uses L1 when KVM is available. Without KVM it must report S0 as skipped,
run the unit-level S6 hooks, and use L2 for later smolvm coverage. A skip is
not equivalent to an L1 pass.

## Suites

### S0: outer simulator smoke

1. Build or install a dstack development image with `is_dev: true`.
2. Generate a job-unique mock seed and matching roots.
3. Serve AMD-KDS-shaped collateral.
4. Deploy with `--simulated-tee dstack-amd-sev-snp`.
5. Wait for `status=running` and `boot_progress=done`.
6. Assert the per-VM simulator config contains SNP measurement and MrConfigV3
   material.
7. Verify evidence with mock roots and the explicit external-root opt-in.
8. Verify the same evidence is rejected by production roots.
9. Record boot duration, QEMU RSS, VM disk use, and guest memory when exposed.

Implemented by `test-suites/eggomi/scripts/s0-sim-smoke.sh`, with the quote
verification path delegated to the existing dstack attestation Compose E2E.

### S1: persistence

1. Write a marker and boot counter on the application's persistent volume.
2. Record the VM and instance IDs, disk image, and swtpm state.
3. Gracefully stop and start the same VM.
4. Require the marker and instance ID to remain unchanged.
5. Require the boot counter to advance and the same disk/swtpm paths to remain.
6. Re-run attestation under the same job seed when quote retrieval is exposed
   by the application harness.

The first five steps are implemented by
`test-suites/eggomi/scripts/s1-persistence.sh`. Step 6 remains an extension
point; S0/S6 already prove quote generation and verification for the same
simulator implementation.

### S2: KMS release gate

1. Configure KMS with mock SNP roots.
2. Require key release to fail while `sev_snp_key_release = false`.
3. Enable the release gate and matching external authorization, then require
   release to succeed.
4. Prevent this suite from using production collateral or secrets.

The in-process lab stand-in is `snp-sim-kms`. It boots a simulated VCEK
chain, refuses release while the gate is off, releases one key only when
`MEASUREMENT` and `report_data` match, and refuses that output at
`QuoteVerifier::new_prod`. See
[simulated-snp-kms.md](simulated-snp-kms.md). The production `dstack-kms`
binary, its key derivation, and Phala TDX are unchanged. Wiring this policy
into a long-running KMS process with mock collateral endpoints is still
deferred.

### S3: browser and keeper lifecycle

1. Create keeper and browser smolvms inside the guest, or host-native in L2.
2. Measure create, start, exec, stop, checkpoint, and restore.
3. Stop idle browser and measure memory reclamation.
4. Restore or branch browser while keeper RPC remains available.

This suite requires the later smolvm integration and nested KVM for the full
L1 form.

### S4: secret capability RPC

1. Store a test secret in keeper.
2. Mint TTL-scoped session material for browser.
3. Search browser disk and checkpoints for the raw secret; no copy may exist.
4. Require expired material to fail.

The host-native stand-in is CAH `fill-v1` under `test-suites/cah` (retired
alias J06, WS-SIM06 `browser-signin`, evidence class `process_e2e`). It shows
one successful fill. A wrong role is refused by the access graph before the
grant is checked, and that grant stays issued. A second admitted
`browser-guard` that presents the copied grant reference is refused at
resolve (`denied_recipient`); that is a separate check, and the grant stays
issued until the bound recipient fills. A changed boot id is refused.
Evidence is E1. The disk and checkpoint search above stays open. See
[docs/cah](../cah/README.md).

### S5: activity and metrics

Run a configurable mix of:

- `llm_churn` against a stub or local endpoint;
- `matrix_churn` for sync and send;
- `bridge_churn` for keeper reconnects;
- `browser_churn` for navigation and tab lifecycle;
- `lifecycle_churn` for browser stop, start, snapshot, and restore.

Export timestamped scenario, outer RSS, guest memory, disk use, keeper/browser
RSS, RPC latency, and error count. Initial budgets belong in the harness once
representative baselines exist.

### S6: fail-closed hooks

The first milestone wires the existing production-path checks:

- `measurement-mismatch` runs the KMS SNP binding test that mutates a verified
  launch measurement and requires rejection;
- `prod-root-unit` generates mock SNP evidence and requires the production
  ARKs in `sev-snp-qvl` to reject it;
- `prod-root-reject` generates SNP-shaped evidence through
  `dstack-tee-simulator`, accepts it with matching mock roots, then requires
  rejection by `dstack-verifier` configured with its built-in production roots.
  This command needs privileged Docker and exits 77 when Docker is unavailable.

Run them with:

```bash
./test-suites/eggomi/scripts/s6-faults.sh measurement-mismatch
./test-suites/eggomi/scripts/s6-faults.sh prod-root-unit
./test-suites/eggomi/scripts/s6-faults.sh prod-root-reject
```

Future hooks cover stale TCB policy, missing collateral, and collateral loss
during verification. Every failure must remain fail-closed and must not
release a key.

## First-milestone completion

- [x] S0 harness selects simulated AMD SEV-SNP and reports environment gates.
- [x] Mock collateral uses a job-unique throwaway seed.
- [x] Boot wait and SNP launch-shape assertions are scripted.
- [x] Mock-root acceptance and production-root rejection use existing
  production verification code.
- [x] S1 checks outer encrypted-disk/application-volume and swtpm persistence.
- [x] S6 exposes measurement-mismatch and production-root rejection hooks.
- [x] CAH host-native `fill-v1` exercises keeper, broker, and browser-guard stubs (E1).
- [ ] Run S0/S1 on an L1 host with `/dev/kvm`, swtpm, and a development image.
- [ ] Implement smolvm S3/S4 and activity S5 in the later milestone.
