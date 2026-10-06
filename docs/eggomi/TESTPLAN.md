# Eggomi CVM / SNP simulation test plan

This plan accompanies [ARCHITECTURE.md](ARCHITECTURE.md). It describes private
working-mirror tests; it does not authorize upstream issues or pull requests.

## Environments

| ID | Hardware | Outer TEE | Inner subVM | Secrets |
| --- | --- | --- | --- | --- |
| L1 | Local KVM | `--simulated-tee dstack-amd-sev-snp` | not smolvm (not viable on real SNP); pending decision | throwaway seed |
| L2 | Local or CI | none | host-native smolvm | none |
| L3 | Cloud VM, nested KVM off | simulated SNP | container fallback | throwaway seed |
| P1 | AMD SNP bare metal | real SNP | not smolvm (not viable today); pending decision | production KMS policy |

CI uses L1 when KVM is available. Without KVM it must report S0 as skipped,
run the unit-level S6 hooks, and use L2 for later smolvm coverage. A skip is
not equivalent to an L1 pass.

smolvm subVMs inside an SNP CVM are not possible on real hardware today.
Linux refuses `kvm_amd` inside an SEV guest ("SVM: KVM is unsupported when
running as an SEV guest"), and AMD lists nested virtualization in SEV guests
as a future feature (AMDESE/AMDSEV issue #63). L1 therefore never enables
nested KVM in the guest: a lab that did would pass where P1 fails.
`test-suites/eggomi/nested-kvm-probe.yml` records what the L1 guest sees.
L2's host-native smolvm stays valid only for the non-confidential local or
desktop computer.

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
binary, its key derivation, and Phala TDX are unchanged.

`test-suites/eggomi/scripts/s2-kms.sh` runs the same policy as a long-running
`snp-sim-kms serve` process that a simulated-SNP CVM calls. The guest quotes
`app_release_report_data(app_id, nonce)` through the guest agent and posts the
evidence to the KMS. The KMS fetches the VCEK chain from the mock AMD-KDS
endpoint and enrolls the MEASUREMENT recomputed from the VM's `vm_config`. S2
requires these outcomes:

- release is refused while the gate is off;
- a matching release succeeds, and its signature verifies under the KMS root
  key attested by the bootstrap quote;
- a replayed quote under a new nonce, a report_data mismatch, and a
  MEASUREMENT mismatch are each refused;
- production AMD roots refuse the evidence the release was decided on.

The [L1 runbook](l1-lab-runbook.md) records the first run.

### S3: browser and keeper lifecycle

S3's inside-the-CVM form is blocked. smolvm subVMs inside an SNP CVM are not
possible on real hardware today, so "smolvm when nested" on L1 and smolvm on
P1 are not viable. The inner-isolation mechanism is pending a founder
decision. The options:

1. one CVM per role (browser, keeper, and later omi each in its own SNP CVM);
2. gVisor or Landlock sandboxes for each role inside one CVM, as in the CC1 lab;
3. VMPL/SVSM partitions inside one CVM, later, once the stack supports them;
4. smolvm only on the non-confidential local or desktop computer, where no
   SNP boundary is claimed.

Once a mechanism is chosen, S3 measures its lifecycle: create, start, exec,
stop, and restore; memory reclamation when the browser idles; and browser
restart while keeper RPC stays available. The host-native L2 form below
remains valid for option 4.

1. Create keeper and browser smolvms host-native in L2.
2. Measure create, start, exec, stop, checkpoint, and restore.
3. Stop idle browser and measure memory reclamation.
4. Restore or branch browser while keeper RPC remains available.

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
- [x] Run S0/S1 on an L1 host with `/dev/kvm`, swtpm, and a development image
  (2026-10-06; see the [L1 runbook](l1-lab-runbook.md)).
- [x] S2 against a long-running lab KMS with mock collateral endpoints.
- [x] Check smolvm inside the CVM: not viable on real SNP; the L1 probe shows
  `svm` but no guest KVM. Guest KVM stays off by design.
- [ ] Founder decision on inner isolation inside one SNP CVM.
- [ ] Implement S3/S4 for the chosen mechanism, and activity S5.
