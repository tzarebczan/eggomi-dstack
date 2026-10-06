# SubVM suites S3 and S4: L2 results

Status: S3 and S4 run host-native with smolvm (environment L2). smolvm inside
a confidential CVM is not a target: an SEV-SNP guest cannot run KVM
(`kvm_amd` refuses with "SVM: KVM is unsupported when running as an SEV
guest"), and the simulated lab's dstack 0.6.0 guest kernel has no KVM
either. These results serve the local or desktop computer, where smolvm runs
on the user's own machine, and serve as the reference for whichever inner
isolation the CVM uses. The last section maps the suites onto those options.

This note does not change [ARCHITECTURE.md](ARCHITECTURE.md) or the
[TESTPLAN.md](TESTPLAN.md) environment table.

## Layout

| | keeper | browser |
| --- | --- | --- |
| Base | `alpine:3.22` + `python3 py3-cryptography` | `alpine:3.22` + `chromium font-dejavu python3 py3-cryptography` |
| Pack | 37 MB `.smolmachine` | 325 MB `.smolmachine` |
| Limits | 1 vCPU, 512 MiB | 2 vCPU, 2048 MiB |
| Workload | `keeper_svc.py` on `0.0.0.0:7011` | `guard_svc.py` beside headless Chromium (`--no-zygote --no-sandbox --disable-gpu`, CDP on guest `127.0.0.1:9222`) |
| Network | none outbound; guest port 7011 published on host `127.0.0.1:47011` | `--net-backend virtio-net --allow-cidr 100.96.0.1/32`, the gateway only |
| Secret material | test secret on the keeper's own disk | guard key in tmpfs with a wrapped copy on disk; session tokens in memory |

Each run copies `test-suites/cah/cah` and `test-suites/eggomi/subvm` into
the machines after their first start. It then installs keys and the secret
as files with `smolvm machine cp`. No secret appears on a command line or in
a pack, and the run deletes its keys and secret when it ends.

## The keeper channel

The channel is the CAH compartment channel, unchanged:
`Noise_KK_25519_ChaChaPoly_SHA256` with prologue `eggomi/cah-channel/v1`
(`cah.channel`). The launcher (the host, in L2) generates one static key per
compartment and gives the keeper the public keys of the peers it admits:
`browser`, and `probe` (the host's availability probe). The keeper
identifies a caller only by the key that completes KK message 1
(`kkrpc.accept_peer`). A caller with an unregistered key gets no reply, and
the relay in between sees only ciphertext.

The transport is TCP. The browser connects to its gateway,
`100.96.0.1:47011`. smolvm's userspace network stack maps the gateway to the
host's loopback, where smolvm publishes the keeper's guest port 7011. Two
other transports were tried and rejected:

- `--expose-socket` on the keeper and `--mount-socket` on the browser carry
  a Unix socket over virtio-vsock with no network at all, and they work.
  But `machine checkpoint` refuses any machine with published sockets, host
  mounts, or named inter-VM networks. A browser that used them could not be
  checkpointed or restored (gap G3).
- TSI networking with `--allow-cidr 127.0.0.1/32` does not reach the host,
  because TSI keeps guest loopback inside the guest.

Gateway egress reaches every port on the host's loopback, not just the
keeper's (gap G5). The KK channel prevents that from becoming keeper
access, but the browser can still reach any other loopback service. On a
desktop, run smolvm in its own network namespace so that its loopback holds
only the published keeper port.

The method table is deny-by-default, per channel role:

| Role | Methods |
| --- | --- |
| browser | `Ping`, `MintSession`, `Redeem` |
| probe | `Ping` |

There is no `GetSecret`, list, or connection-enumeration method.

## Session material, not the secret

`MintSession {purpose, ttl_ms, challenge, operation_id}` checks the purpose
against the keeper's allowlist and caps the TTL at 30 s, the CAH seal limit.
It derives a token, `HMAC-SHA256(secret, "eggomi-s4-session/v1" | purpose |
grant_ref | expires_ms)`, and seals it to the guard's channel key in the CAH
`cah-sealed-answer/v3` format. The guard rebuilds the binding from its own
values and opens the seal with `cah.guard.GuardStore.accept`. That call
refuses with `grant_expired` once the offset has passed on the guard's
monotonic clock, and records each `grant_ref` only once. `Redeem` stands in
for the origin that accepts the session: it accepts a token once, before
`expires_ms`.

This is deliberately not the CAH `fill-v1` answer. `fill-v1` seals the raw
credential to the guard so the guard can type it into a page. S4's
requirement, and security invariant 3, is that the secret never appears on a
browser's disks or in its snapshots. S4's positive control shows why the two
conflict. The session token sits in guard memory exactly as a filled
password would, and S4 finds it in every browser checkpoint. A raw fill held
at checkpoint time would be in that checkpoint too. Using `fill-v1` with
checkpointable browsers therefore needs one of two things:

- the guard holds only session material; or
- a browser is checkpointed only after the guard has dropped the fill and
  the guest has scrubbed freed memory (`init_on_free=1`), with S4's scan as
  the check.

## S3 results

These figures come from `./test-suites/eggomi/scripts/s3-smolvm.sh`, run on
2026-10-06. The host was an AMD Ryzen 9 5950X with 125 GB RAM, Linux 7.2 on
btrfs. smolvm was 1.23.7 built from mirror branch `claude/eggomi-subvm`; that
build is the upstream 1.23.7 code plus G1 and G2 below. Two runs on the stock
1.23.7 release binary gave the same picture, with timings within about
±50%.

Lifecycle, in seconds:

| Operation | keeper | browser |
| --- | --- | --- |
| create (from pack) | 0.03 | 0.49 |
| start (VM boot) | 0.44 | 0.43 |
| ready (start to workload answering) | 1.45 | 3.65 |
| exec, p50 of 9 | 0.030 | 0.061 |
| checkpoint (total / source paused) | | 1.46 / 0.60 |
| checkpoint size | | 168 MB |
| stop | 0.15 | 0.22 |
| restore: create from checkpoint | | 1.68 |
| restore: start | | 0.75 |
| restore: total to ready | | 2.45 |
| branch the restored browser | | 0.46 (ready 0.49) |

`ready` runs from `machine start` until the workload answers. For keeper
that is a KK `Ping` from the host. For browser it is the guard's ready file
plus Chromium's `/json/version`. Both include copying the harness in.

Memory, as host VMM RSS and guest used (MemTotal - MemAvailable):

| Phase | browser host RSS | browser guest used |
| --- | --- | --- |
| idle (keeper idle: 132 MB host, 57 MB guest) | 478 MB | 255 MB |
| after a 256 MiB tab | 812 MB | 264 MB |
| 30 s later (free-page reporting) | 487 MB | 260 MB |
| after `machine reclaim` (balloon pulse, 1.0 s) | 394 MB | 342 MB |
| after a checkpoint | 570 MB | 333 MB |
| after stop | 0 (570 MB returned) | |
| restored and started `--branchable` | 132 MB | 329 MB |
| branch child | 138 MB (71 MB shared) | 315 MB |

Keeper RPC availability: the probe sent a KK `Ping` every 100 ms while the
browser was stopped, restored, and branched. It recorded 45 attempts with 0
failures; the longest gap between successes was 0.17 s and p50 latency was
31 ms.

What the numbers say:

- Free-page reporting alone returned 325 MB of the heavy tab within 30 s.
  An on-demand balloon pulse returned another 93 MB of page cache. Stopping
  returns everything, and restore puts a warm browser back in 2.5 s.
- A checkpoint raises the source's host RSS and keeps it raised (gap G4):
  +176 MB here. For a `--branchable` (memfd-backed) machine, a manual run
  went from 435 MB to 1,099 MB. Neither free-page reporting nor a balloon
  pulse brought that back, because a branch source is excluded from
  reclaim. Run browsers non-branchable by default; restore one
  `--branchable` only when it is to be branched.
- Restored and branched machines map RAM lazily from the checkpoint. That is
  why their RSS starts lower than a cold-booted browser's.

## S4 results

`./test-suites/eggomi/scripts/s4-secret-rpc.sh` ran on the same host and
build. It passed all 14 cases and every leak search:

| Case | Result |
| --- | --- |
| mint, open at the guard, redeem | `filled`, then `ok` |
| redeem the same token again | `consumed` |
| open the same seal again | recorded outcome `filled`, `repeat`, no plaintext returned |
| open after the TTL (1.0 s TTL, opened at 1.5 s) | `grant_expired` at the guard |
| redeem after the TTL (1.5 s TTL, redeemed at 2.0 s) | `expired` at the origin stand-in |
| `GetSecret`, `ListConnections` | `denied_method` |
| unregistered channel key | `handshake_refused` (no KK reply) |
| purpose outside the allowlist / 60 s TTL | `denied_purpose` / `denied_ttl` |
| restored browser: keeper RPC | `ok` |
| restored browser: redeem the carried session after its TTL | `expired` |

The leak search looked for three encodings of the secret: raw, UTF-16LE,
and hex. Checkpoint payloads were decompressed before searching, and disk
images were searched sparse-aware.

| Target | Secret hits | Positive control |
| --- | --- | --- |
| browser checkpoint taken while the guard held a live session | 0 | that session's token: 12 hits |
| browser disks (storage, overlay) after stop | 0 | |
| restored browser's disks | 0 | |
| keeper disks | | the secret: 1 hit (`storage.qcow2`) |

The positive controls are what make the zero counts meaningful. The scanner
does see guard memory inside a checkpoint, and it does find the secret on
the disk that holds it.

## smolvm gaps

These gaps were found against upstream `smol-machines/smolvm` main at
`b2bf5fe8` (1.23.7). The private mirror `tzarebczan/smolvm` was 7 commits
behind upstream main, so the work branch starts from upstream main.

| Id | Gap | Status |
| --- | --- | --- |
| G1 | `machine status --json` omits the guest memory that the text form prints, so a supervisor must exec into each guest | Fixed on mirror branch `claude/eggomi-subvm`: adds a `memory` object |
| G2 | Memory cannot be reclaimed on demand. Idle reclaim waits for `SMOLVM_IDLE_RECLAIM` minutes of CPU idleness (default 10) | Fixed on the mirror: `smolvm machine reclaim`, which shares one pulse function with idle reclaim. With a stock build, the harness speaks the per-VM `control.sock` protocol (`BALLOON n`) instead |
| G3 | Portable checkpoints refuse published sockets, host mounts, and named inter-VM networks, so a checkpointable browser cannot use a vsock keeper channel | Open. S3/S4 use TCP through the gateway |
| G4 | Checkpoint capture leaves the source's host RSS raised: about +170 MB when non-branchable, about +650 MB and not reclaimable when branchable | Open. The cause is likely libkrun's RAM streaming |
| G5 | Gateway egress (`--allow-cidr <gateway>/32`) opens every port on the host's loopback; there is no per-port host-service allowance | Open. Mitigate with a dedicated network namespace |
| G6 | Each restore leaves a 450-650 MB shared extraction under `vms/_shared`. `--restore-cache-entries 0` does not apply to file checkpoints | By design: a bounded restore cache, default 3 entries. `smolvm pack prune --all` clears it |

## Mapping S3 and S4 onto the inner-isolation options

The suites divide into a part that does not depend on the substrate and a
part that does:

- **Portable to any substrate:** `keeper_svc.py`, `guard_svc.py`, `kkrpc.py`,
  and `session_material.py`. They need only a TCP path from browser to
  keeper and a launcher that installs per-compartment keys. The S4 case list
  and the leak scanner (`host_tools.py scan`: plain files, sparse disk images,
  smolvm checkpoints) also carry over.
- **smolvm-specific:** `lib-smolvm.sh`, plus the lifecycle and memory steps
  in S3.

### (a) One dstack CVM per role (keeper CVM + browser CVM)

- **S3 lifecycle** maps to dstack-vmm `deploy`, `stop`, and `start`, which
  S0/S1 already time. Expect boot in tens of seconds, not smolvm's 0.4 s.
  There is no RAM checkpoint, restore, or branch: confidential guest memory
  cannot be snapshotted by the host. "Restore" becomes a fresh boot that
  recovers state from the encrypted volume, so the warm-browser restore
  measured here (2.5 s) has no equivalent.
- **Memory:** each CVM's RAM is a fixed reservation. Do not count on balloon
  or free-page-reporting reclaim from an SNP guest; reclaim means stopping
  the browser CVM. The useful S3 metrics are boot time, the browser CVM's
  QEMU RSS, and the cost of keeping the browser CVM stopped while idle.
- **Keeper channel:** KK over TCP between the two CVMs, through the dstack
  gateway or a host-side port. `kkrpc` works unchanged. Keys should be bound
  to each CVM's attestation (the launcher-signed registry row, or RA-TLS),
  so that a peer key implies a measured image, not just possession.
- **S4:** the browser CVM's volume is encrypted, so a host-side disk scan
  proves nothing. Run the disk scan inside the browser CVM against its
  decrypted volume. In the simulator only (QEMU `no_tee`), the host can dump
  guest RAM with QMP `dump-guest-memory`. Scanning that dump with the same
  two positive controls replaces the checkpoint scan. On real SNP no such
  dump exists, which is the point of the design.

### (b) gVisor or Landlock sandboxes inside one CVM

- **S3 lifecycle:** with gVisor, `runsc create`, `start`, `exec`, and `kill`.
  `runsc checkpoint` and `runsc restore` provide a checkpoint/restore pair,
  so S3's restore step carries over. Landlock sandboxes are plain processes:
  start and stop cost almost nothing, and there is no checkpoint unless CRIU
  is added.
- **Memory:** memory freed in the sandbox returns to the CVM kernel without
  a balloon. Measure per-sandbox RSS or cgroup `memory.current` instead of
  VMM RSS. Reclaim inside the CVM does not shrink the CVM itself.
- **Keeper channel:** a Unix socket bind-mounted into the browser sandbox,
  with no network path at all. With Landlock, the existing CAH Unix
  transport (pidfd admission plus KK) applies directly. With gVisor, the
  host-UDS option is needed, and pidfd admission sees the sandbox process,
  not the browser inside it, so the KK key carries the identity.
- **S4:** scan the browser sandbox's root and upper directories and, for
  gVisor, its checkpoint image. The scanner reads plain files today. A
  compressed `runsc` image needs a decoder alongside the smolvm one. The
  boundary is weaker than smolvm's or (a)'s: one guest kernel for every
  role.

### (c) VMPL/SVSM partitions (later)

- The keeper runs at a more privileged VMPL than the browser inside one SNP
  guest, under an SVSM such as COCONUT. Its memory is hardware-protected
  from the browser partition, not just isolated by a hypervisor.
- **S3:** there is no per-partition VM lifecycle or snapshot. The useful
  measurements become partition start and teardown, and the latency of the
  SVSM-mediated calls.
- **Keeper channel:** SVSM calls or shared pages, not TCP. The KK framing
  can stay as the payload format; `kkrpc` would need a new transport.
- **S4:** cases carry over. The memory scan is an in-guest read of the
  browser partition's pages, plus a negative test showing that the browser
  partition cannot read keeper pages.

For the local or desktop computer, L2 as measured here is the design: smolvm
on the user's machine with the keeper channel described above.

## Files

| Path | Role |
| --- | --- |
| `test-suites/eggomi/scripts/s3-smolvm.sh` | S3: lifecycle and memory |
| `test-suites/eggomi/scripts/s4-secret-rpc.sh` | S4: secret capability RPC and leak search |
| `test-suites/eggomi/scripts/lib-smolvm.sh` | shared gates, base packs, machine setup |
| `test-suites/eggomi/scripts/subvm-unit-tests.sh` | host-only unit tests |
| `test-suites/eggomi/subvm/keeper_svc.py` | keeper service, in the keeper VM |
| `test-suites/eggomi/subvm/guard_svc.py` | browser guard, in the browser VM |
| `test-suites/eggomi/subvm/kkrpc.py` | multi-peer KK responder and one-call client |
| `test-suites/eggomi/subvm/session_material.py` | token derivation and seal binding |
| `test-suites/eggomi/subvm/host_tools.py` | keygen, probe, RSS, balloon pulse, scanner |
