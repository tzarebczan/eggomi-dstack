# L1 simulated-SNP lab runbook

L1 is a KVM host without SEV-SNP hardware running dstack CVMs under
`--simulated-tee dstack-amd-sev-snp` (see [TESTPLAN](TESTPLAN.md)). This
runbook covers the lab as first brought up on an AMD Ryzen 9 5950X
workstation (no `/dev/sev`, `kvm_amd` nested=1) next to an unrelated dstack
lab. The simulator gives no confidentiality: the host can read guest memory,
and every root, seed, and key here is throwaway.

## Layout

Everything lives under one lab directory, `EGGOMI_LAB_DIR`, which defaults to
`~/lab/eggomi-snp`:

| Path | Contents |
| --- | --- |
| `eggomi-dstack/` | checkout of this fork |
| `target/` | `CARGO_TARGET_DIR`; only `release/` is needed at run time |
| `image/dstack-dev-0.6.0/` | development guest image (`is_dev: true`, `measurement.snp.cbor`) |
| `env.sh` | environment for the harness scripts |
| `state/` | `EGGOMI_STATE_DIR`: job seed, mock roots, harness artifacts |
| `vmm/vmm.toml`, `vmm/vmm.sock`, `vmm/vm/` | VMM config, API socket, VM work directories |
| `logs/` | `vmm.log`, `collateral.log`, `kms.log`, harness logs |
| `*.pid` | collateral and KMS pid files; the VMM pid is `vmm/vmm.pid` |

`test-suites/eggomi/scripts/l1-lab.sh` drives the lab. Every command below
runs from the checkout and assumes `. "$EGGOMI_LAB_DIR/env.sh"` and
`LABCTL=test-suites/eggomi/scripts/l1-lab.sh`. `env.sh` sets `LAB` to the lab
directory, so do not use that name for the script.

## Ports, CIDs, and sockets

The defaults are chosen so that a second dstack lab can run on the same host.

| Resource | Default | Override at `init` |
| --- | --- | --- |
| Guest port mapping range | `127.0.0.1:19100-19109` | `EGGOMI_LAB_PORT_BASE` |
| S0/S1 persistence probe | `19100 -> 8080` | |
| S2 guest client | `19101 -> 8080` | |
| Mock AMD-KDS collateral | `0.0.0.0:18100`, guest `10.0.2.2:18100` | `EGGOMI_LAB_SERVICE_PORT_BASE` |
| Lab KMS | `127.0.0.1:18101`, guest `10.0.2.2:18101` | `EGGOMI_LAB_SERVICE_PORT_BASE` + 1 |
| VMM API | `unix:$LAB/vmm/vmm.sock` | |
| Host API (vsock CID 2) | port `10100` | `EGGOMI_LAB_HOST_API_PORT` |
| Guest vsock CIDs | `2000-2099` | `EGGOMI_LAB_CID_START` |

The VMM's host API binds vsock CID 2. Two VMMs on one host therefore need
different `[host_api] port` values; dstack's default is 10000. The S2 compose
file names the KMS at `10.0.2.2:18101`, and `s2-kms.sh` rewrites that port
when `EGGOMI_KMS_PORT` differs.

### passt networking (opt-in)

`EGGOMI_LAB_NET=passt` at `init` writes a `[cvm.networking]` that runs each
VM's NIC through passt instead of QEMU's user mode: rootless (a sidecar of the
VM's launcher, over a socketpair), with the same view from the guest.

It is not faster here. Measured on beast (2026-10-08, QEMU 10, a 4-vCPU
guest of eggomi's VMM release fetching the 167 MB gVisor bundle from the
host's loopback over HTTP): about 0.9 GB/s through passt and about 0.9 GB/s
through user mode (0.71-0.96 GB/s over three runs each). The release's image
pull, about 400 MB, took 14.1 s through passt and 14.8 s through user mode,
within run-to-run noise: the guest's decompression and unpacking bound it,
not the transport. So the lab stays on user mode; passt is here for a host
that needs it, and as the base for a faster path (vhost-user) later. Its
address comes from DHCP (`10.0.2.10/24`), `10.0.2.2` is the host's loopback
(`map_host_loopback`, so the collateral, the KMS and every published port are
where they were), its resolver is `10.0.2.3`, which passt forwards to the
host's own (`dns_forward`, to `dns_host`, the host's first nameserver: passt's
default skips a loopback stub such as systemd-resolved's), and the port map is published on the host's
loopback (`--tcp-ports 127.0.0.1/<host>:<guest>`). passt must be on `PATH`
or named by `EGGOMI_LAB_PASST`; no root is needed to install it:

```bash
# Arch's package, checked against the pacman keyring, unpacked as the user.
f=passt-2026_07_28.f8df3f1-1-x86_64.pkg.tar.zst
curl -fsSO "https://geo.mirror.pkgbuild.com/extra/os/x86_64/$f" && curl -fsSO "https://geo.mirror.pkgbuild.com/extra/os/x86_64/$f.sig"
gpgv --keyring /etc/pacman.d/gnupg/pubring.gpg "$f.sig" "$f"
tar --zstd -xf "$f" -C /tmp usr/bin/passt usr/bin/passt.avx2 && install -m 0755 /tmp/usr/bin/passt* ~/.local/bin/
```

An existing lab switches by editing `vmm.toml` the same way and restarting
the VMM:

```toml
[cvm]
passt_path = "/home/tom/.local/bin/passt"

[cvm.networking]
mode = "passt"
address = "10.0.2.10"
netmask = "255.255.255.0"
gateway = "10.0.2.2"
map_host_loopback = "10.0.2.2"
no_map_gw = false
dns = ["10.0.2.3"]
dns_forward = "10.0.2.3"
dns_host = "127.0.0.53"
ipv4_only = true
```

 A running VM keeps its NIC until it is stopped; a VM whose NIC follows
the node's mode gets passt at its next start.

## Build

Build only these crates into the lab's target directory. Run `df -h /`
before each step.

```bash
export CARGO_TARGET_DIR=$EGGOMI_LAB_DIR/target
cargo build --manifest-path dstack/Cargo.toml --release \
  -p dstack-vmm -p supervisor -p mock-attestation -p snp-sim-kms
```

The release outputs take about 1.6 GB. S6's unit hooks add about 4 GB of
debug artifacts under `target/debug`, which may be deleted afterwards.

## Guest image

Upstream publishes no 0.6.0 development image: `mkosi-os-v0.6.0` carries only
the production `dstack-0.6.0.tar.gz`. The lab uses a `dstack-dev-0.6.0` built
with `FLAVORS=dev ./os/mkosi/repro-build/repro-build.sh` from upstream
revision `4699c48e`, the same revision as the release. The fork's changes
since that revision are host-side (VMM, verifier, harness), so the image
matches `next`. Check it:

```bash
jq '{version, git_revision, is_dev}' "$EGGOMI_LAB_DIR/image/dstack-dev-0.6.0/metadata.json"
(cd "$EGGOMI_LAB_DIR/image/dstack-dev-0.6.0" && sha256sum -c sha256sum.txt)
```

It must report `"is_dev": true` and include `measurement.snp.cbor`. On btrfs,
`cp --reflink=always` makes a copy of an existing image directory for free.

## Start

```bash
$LABCTL init              # once: env.sh, job seed and mock roots, vmm.toml
. "$EGGOMI_LAB_DIR/env.sh"
$LABCTL start             # dstack-vmm under setsid; it starts its supervisor
$LABCTL start-collateral  # mock AMD-KDS endpoints for the job seed
./test-suites/eggomi/scripts/s0-sim-smoke.sh
$LABCTL start-kms         # lab KMS enrolled to the S0 VM, release gate open
$LABCTL status
```

The VMM, collateral server, and KMS run detached from the shell and survive
logout. VMs run under the VMM's supervisor. `init` refuses to overwrite an
existing `env.sh`; delete `state/` to rotate the seed.

## Run the suites

```bash
EGGOMI_RUN_S6=false ./test-suites/eggomi/scripts/s0-sim-smoke.sh
./test-suites/eggomi/scripts/s1-persistence.sh
./test-suites/eggomi/scripts/s2-kms.sh
./test-suites/eggomi/scripts/s6-faults.sh measurement-mismatch
./test-suites/eggomi/scripts/s6-faults.sh prod-root-unit
./test-suites/eggomi/scripts/s6-faults.sh prod-root-reject
```

S0, S1, and S2 reuse a collateral server that is already listening on
`EGGOMI_COLLATERAL_PORT`. That server must have been started from the same
`state/`, or KMS releases fail closed with a chain error. S2 deploys its own
VM and removes it when it finishes. It starts its own KMS instances on
`EGGOMI_KMS_PORT`, so stop the standing one first (`$LABCTL stop-kms`) and
restart it afterwards. S2 refuses to start while that port is in use. Set `EGGOMI_S2_KEEP_VM=true` to keep the
VM, or set `EGGOMI_S2_VM_ID` to reuse one.

`prod-root-reject` builds a privileged Docker image. Its build cache holds
about 5 GB of debug artifacts in a cache mount, plus 0.5 GB of registry
cache and a 356 MB image. Remove them afterwards by ID: `docker buildx du
--verbose` lists the entries described as `cached mount /src/target` and
`/usr/local/cargo/registry`, and `docker buildx prune -f --filter id=ID`
deletes one of them. Then run `docker image rm dstack-tests-attestation:local`.

## Measured results (first bring-up, 2026-10-06)

| Check | Result |
| --- | --- |
| S0 | pass. Boot to `boot_progress=done` in 36 s; QEMU RSS 1.27 GB for a 3 GB guest; VM work directory 26 MB allocated |
| S1 | pass. Restart 132 s under concurrent host load, then 48 s on a quiet host; marker, instance ID, `hda.img`, and swtpm state persisted |
| S2 | pass: gate-off refused, release signed and verified, replay, report_data, and MEASUREMENT mismatches refused, production roots refused |
| S6 `measurement-mismatch` | pass |
| S6 `prod-root-unit` | pass |
| S6 `prod-root-reject` | pass in 120 s, including the Docker build |
| Nested KVM in guest | **no**, and kept off: not viable on real SNP (see below) |

The production verifier refuses the mock chain at its first certificate
check. The mock ASK is signed with ECDSA P-384 (`1.2.840.10045.4.3.3`), and
the built-in AMD path accepts only AMD's own algorithm. `production-gate`
therefore first requires the job's mock root to accept the same report and
collateral, so a collateral outage cannot pass as a root rejection.

Guest `MemAvailable` is not collected yet. Lab disk at rest is about 2.5 GB.
That counts the reflinked image (730 MB of shared extents) and `target/release`
(1.6 GB); a running VM adds about 30 MB.

## Nested virtualization

QEMU runs with `-accel kvm -cpu host`, so with `kvm_amd` `nested=1` on the
host the guest CPU advertises `svm`. The dstack 0.6.0 guest kernel has no KVM,
though. `CONFIG_KVM`/`CONFIG_KVM_AMD` are absent from
`os/mkosi/components/kernel/kernel.config`, `/lib/modules` has no `kvm*.ko`,
`modprobe kvm_amd` fails, and `/dev/kvm` does not exist. Check it with the
probe compose file:

```bash
python3 "$DSTACK_VMM_CLI" --url "$DSTACK_VMM_URL" compose --name nested-probe \
  --docker-compose test-suites/eggomi/nested-kvm-probe.yml --key-provider tpm \
  --public-logs --public-sysinfo --output /tmp/nested.json
python3 "$DSTACK_VMM_CLI" --url "$DSTACK_VMM_URL" deploy --name nested-probe \
  --image "$EGGOMI_DEV_IMAGE" --compose /tmp/nested.json --vcpu 2 --memory 2G \
  --disk 4G --port tcp:127.0.0.1:19102:8080 --simulated-tee dstack-amd-sev-snp
curl http://127.0.0.1:19102/   # cpu_virt_flag=svm, dev_kvm=missing
```

Do not enable KVM in the guest kernel to make this pass. smolvm subVMs inside
an SNP CVM are not possible on real hardware today: Linux refuses `kvm_amd`
inside an SEV guest ("SVM: KVM is unsupported when running as an SEV
guest"), and AMD lists nested virtualization in SEV guests as a future
feature (AMDESE/AMDSEV issue #63). A lab with nested KVM would pass where
real SNP fails. The probe stays as the evidence for this finding.

"smolvm when nested" on L1 and smolvm on P1 are therefore not viable. The
inner-isolation choice is pending a founder decision:

1. one CVM per role (browser, keeper, and later omi each in its own SNP CVM);
2. gVisor or Landlock sandboxes for each role inside one CVM, as in the CC1 lab;
3. VMPL/SVSM partitions inside one CVM, later, once the stack supports them;
4. smolvm only on the non-confidential local or desktop computer, where no
   SNP boundary is claimed.

Option 2 with gVisor is measured in this lab, in its own CVM: see
[inner-isolation-gvisor.md](inner-isolation-gvisor.md).

## Stop and teardown

```bash
$LABCTL cli stop VM_ID        # graceful guest shutdown; disk and swtpm kept
$LABCTL stop-kms
$LABCTL stop-collateral
$LABCTL stop                  # VMM; stop VMs first
```

`$LABCTL cli remove VM_ID` deletes a VM's work directory. Full teardown, after
removing every VM, is `rm -rf "$EGGOMI_LAB_DIR"`. Nothing outside it is
created, except the VMM registration under `$XDG_RUNTIME_DIR/dstack-vmm`
(removed when the VMM exits) and any Docker artifacts from
`prod-root-reject`.

## Moving to a real SNP host (P1)

What changes:

1. **Host.** The host must have `/dev/sev`, `kvm_amd` `sev_snp=Y`, RMP
   enabled, and SNP-capable QEMU and OVMF. See [amd-sev-snp.md](../amd-sev-snp.md).
2. **Install.** Run `sudo dstackup install --platform amd-sev-snp --image
   dstack-<version>` with a production (non-dev) image. It must carry
   `digest.txt` and the SNP measurement material. A development image
   carries `dstack-tee-simulator` and must not be used.
3. **VMM.** Drop `[cvm.tee_simulator]` and the `--simulated-tee` flag. Set
   `platform = "amd-sev-snp"` (or `auto`). QEMU then launches a real SNP guest
   instead of `no_tee`.
4. **Roots.** Remove `insecure_allow_external_trust_anchors` and every
   `[attestation.root_ca]` override, so verifiers use the built-in AMD ARKs
   and the real AMD KDS (`amd_kds_base_url` empty, or a controlled mirror).
5. **KMS.** Replace `snp-sim-kms` with `dstack-kms`, using production
   authorization and `[core] sev_snp_key_release = true` once the host,
   image, and policy are validated. Its key derivation is
   production `derive_k256_key`, not the lab HKDF.
6. **Identity.** HOST_DATA carries the MrConfigV3 digest. Wire the keeper's
   MrConfigV3 check (eggomi#757 item 4) against hardware vectors.

The S6 production-root checks must keep failing for simulated evidence, and
`snp-sim-kms` output must never reach a production verifier or keeper gate.
