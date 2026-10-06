# Develop Eggomi with simulated AMD SEV-SNP

Eggomi can exercise dstack's SEV-SNP attestation and persistence paths on a
KVM host that has no SNP hardware. The development guest runs
`dstack-tee-simulator`, QEMU runs with `no_tee`, and swtpm provides persistent
TPM-backed application keys.

This mode has no hardware isolation. The host can read guest memory, and all
keys and data must be disposable. A verifier using dstack's built-in AMD roots
rejects the simulated evidence.

## Build the development components

Follow [Build the dstack guest OS](../building-guest-os.md), then build the
development flavor:

```bash
FLAVORS="dev" ./os/mkosi/repro-build/repro-build.sh
```

Extract the resulting archive into the VMM image directory and confirm that
the image is marked for development:

```bash
mkdir -p ~/.dstack-vmm/image
tar -xzf os/mkosi/repro-build/build/out/dev/dstack-dev-*.tar.gz \
  -C ~/.dstack-vmm/image
jq '{version, git_revision, is_dev}' \
  ~/.dstack-vmm/image/dstack-dev-*/metadata.json
```

The output must include `"is_dev": true`. Production images do not contain
`dstack-tee-simulator`.

Install QEMU, swtpm, and the other host tools. On Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y qemu-system-x86 swtpm swtpm-tools jq curl
test -r /dev/kvm && test -w /dev/kvm
```

Build the VMM, supervisor, mock collateral server, and verifier:

```bash
cargo build --manifest-path dstack/Cargo.toml --release \
  -p dstack-vmm -p supervisor -p mock-attestation -p dstack-verifier
```

## Generate mock collateral

The Eggomi harness creates a random 32-byte seed per state directory and
derives matching public roots:

```bash
./test-suites/eggomi/scripts/mock-collateral.sh generate
cat test-suites/eggomi/.state/vmm-tee-simulator.toml
```

The generated table looks like this:

```toml
[cvm.tee_simulator]
mock_attestation_seed = "<64 hexadecimal characters>"
collateral_base_url = "http://10.0.2.2:18088"
```

Merge it into the VMM configuration. With QEMU user networking, `10.0.2.2`
routes from the guest to the host. The harness serves the matching
AMD-KDS-shaped endpoints on host port 18088 while each scenario runs.

Use the same image, VMM binaries, and working-directory setup as
[Develop with dstack without TEE hardware](../development-without-tee.md).
Set user networking and swtpm-capable QEMU in `vmm.toml`:

```toml
[image]
path = "/home/USER/.dstack-vmm/image"

[cvm]
qemu_path = "/usr/bin/qemu-system-x86_64"

[cvm.networking]
mode = "user"

[cvm.port_mapping]
enabled = true

[supervisor]
exe = "/home/USER/.local/bin/supervisor"
```

Port mapping is disabled in the sample `vmm.toml`. The persistence probe needs
it so QEMU can publish the guest's port 8080. A deployment that requests a
port while it is disabled fails with `Port mapping is disabled`.

Start the VMM only after adding the generated simulator table. Simulation is
still selected per VM, not globally. The CLI discovers that VMM when it is
the only one running; set `DSTACK_VMM_URL` to the address shown by
`dstack vmm ls` when several are present.

## Deploy the SNP simulator

Create an app-compose file with the TPM key provider:

```bash
dstack compose \
  --name eggomi-snp-sim \
  --docker-compose test-suites/eggomi/docker-compose.yml \
  --key-provider tpm \
  --public-logs \
  --public-sysinfo \
  --output app-compose.json
```

In one terminal, serve the collateral:

```bash
./test-suites/eggomi/scripts/mock-collateral.sh serve
```

In another terminal, deploy the development image:

```bash
dstack deploy \
  --name eggomi-snp-sim \
  --image dstack-dev-<version> \
  --compose app-compose.json \
  --vcpu 2 --memory 3G --disk 10G \
  --port tcp:127.0.0.1:18089:8080 \
  --simulated-tee dstack-amd-sev-snp
```

The command prints `Created VM with ID: VM_ID`. Wait until:

```bash
dstack info VM_ID
```

reports `Status: running` and `Boot Progress: done`. The guest must be able
to pull `alpine:3.20` for the persistence probe. The VMM writes an
instance-specific `.tee-simulator.json`. Its `platform` is
`dstack-amd-sev-snp`, and its `vm_config` contains both `sev_snp_measurement`
and the MrConfigV3 document. Current development images include
`measurement.snp.cbor`; the VMM attaches that launch measurement for a
simulated SNP boot even when the host has no SNP hardware. The simulator
signs `MEASUREMENT` from those inputs, which is the value the verifier
recomputes. QEMU itself still runs with `no_tee`.

The scripted form performs these checks and records boot metrics:

```bash
export EGGOMI_DEV_IMAGE=dstack-dev-<version>
./test-suites/eggomi/scripts/s0-sim-smoke.sh
```

## Verify with mock roots

Mock evidence follows the production-shaped TSM, report, VCEK, ASK, ARK, and
AMD KDS paths. A service that verifies it must opt into external roots:

```toml
[attestation]
insecure_allow_external_trust_anchors = true

[attestation.urls]
amd_kds = "http://127.0.0.1:18088/vcek/v1"

[attestation.root_ca]
sev_snp_milan = "/path/to/active-mock-roots/sev-snp-root-ca.pem"
sev_snp_genoa = "/path/to/active-mock-roots/sev-snp-root-ca.pem"
sev_snp_turin = "/path/to/active-mock-roots/sev-snp-root-ca.pem"
```

The roots appear under
`test-suites/eggomi/.state/active-mock-roots/` while the server runs.
`insecure_allow_external_trust_anchors` is mandatory for hand-written roots;
do not enable it in a production verifier or KMS.

Run the existing attestation E2E through the Eggomi hook:

```bash
./test-suites/eggomi/scripts/s6-faults.sh prod-root-reject
```

Successful output includes:

```text
{"development_root_accepted":true}
{"production_root_rejected":true}
[dstack-amd-sev-snp] dstack-util -> verifier trust-root isolation E2E passed
```

The negative check keeps the mock collateral URL but removes external roots
and the insecure opt-in. This isolates the trust-anchor decision: the same
cryptographically valid simulated report must fail against built-in production
AMD roots.

## Check persistence

After S0, run:

```bash
./test-suites/eggomi/scripts/s1-persistence.sh
```

S1 stops and starts the same VM, then checks the instance ID, encrypted data
disk path, swtpm permanent state, and a marker stored in the application
volume. See the [harness README](../../test-suites/eggomi/README.md) for
environment variables, metrics, explicit skip behavior, and the nested
virtualization boundary for future browser and keeper smolvms.
