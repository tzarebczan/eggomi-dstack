<!--
SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
SPDX-License-Identifier: Apache-2.0
-->

# Inner isolation with gVisor inside one CVM (L1)

Status: measured in the L1 simulated-SNP lab on 2026-10-07. The design under
test is one CVM per user, with the keeper, guard, and browser each in its own
gVisor sandbox (`runsc --platform=systrap`, no KVM) and each in its own
cgroup v2 with memory and CPU limits. smolvm subVMs are out inside the CVM: a
real SEV-SNP guest cannot run KVM ([l1-lab-runbook](l1-lab-runbook.md#nested-virtualization)).
The smolvm results that this note compares against are in
[subvm-l2-results.md](subvm-l2-results.md) (PR #10).

Summary:

- runsc runs unmodified in the dstack 0.6.0 development image. One
  `init_script` in the app compose registers it with dockerd, and a compose
  service can then use `runtime: runsc`. Nothing in the image was rebuilt.
- Chromium keeps its own sandbox under gVisor. It runs as a non-root user
  with no `--no-sandbox` and no extra flags, and its renderers get their own
  user, PID, and network namespaces plus a seccomp-bpf filter.
- S3' passes. Lifecycle times are close to smolvm's, and restore is faster:
  2.2 s to a ready browser, against 2.8 s. Per-role memory is lower, and
  keeper RPC had no failures (111 probes) while the browser was checkpointed,
  stopped, and restored.
- S4' passes. All 14 cases pass, all 9 boundary checks pass, and no search
  finds the secret: three browser checkpoint images, the browser's, guard's,
  and restored browser's storage, and containerd's leftover restore copy.
  Each memory-image search has a positive control that must hit (a canary
  page, the filled token), and so does the keeper volume (the secret). Each
  storage search must have read the target's files, and a failed search
  fails the suite.
- Four findings need design attention. Each is described below. The
  release hardening of eggomi#780 closes findings 1, 2, and 5 and caps the
  ZFS ARC in the measured init script; see
  [Release hardening](#release-hardening-eggomi780).
  1. A sandbox can reach the CVM's own services through its bridge gateway,
     dstack-guest-agent on `:8090` among them. A CVM input floor is needed.
  2. containerd leaves a full copy of every restored checkpoint in the CVM's
     tmpfs. The copy holds the browser's memory.
  3. `memory.reclaim` returns almost nothing, because gVisor's memory is
     shmem and the CVM has no swap. gVisor does return freed memory on its
     own.
  4. A filled session survives closing its tab in the browser's memory. This
     is the reason for the pristine-checkpoint rule.

## Layout

The lab CVM is `eggomi-gvisor-lab`. It runs the `dstack-dev-0.6.0` image with
`--simulated-tee dstack-amd-sev-snp`, 4 vCPU, 6 GB, and a 20 GB disk, beside
the standing S0 CVM (which was left alone). Inside it is Docker 26.1.5 with
cgroup v2 and the systemd driver, and gVisor `release-20260928.0` with the
systrap platform. That is the release the founder approved for CC1, fetched
from gVisor's bucket and pinned by SHA-512.

| | keeper | guard | browser |
| --- | --- | --- | --- |
| Sandbox | runsc, systrap | runsc, systrap | runsc, systrap |
| Image | `alpine:3.22` + `python3 py3-cryptography` (55 MB) | same | `alpine:3.22` + `chromium font-dejavu python3` (869 MB) |
| cgroup limits | 512 MiB, 1 CPU | 256 MiB, 1 CPU | 2 GiB, 2 CPU |
| Workload | `keeper_svc.py` on `:7011` | `gv_guard.py` (CAH guard plus a DevTools client) | Chromium 142 headless, uid 10001, with its sandbox on; DevTools relay on `:9223` |
| Networks | keeper bridge | keeper bridge and browser bridge | browser bridge |
| Secret material | the secret on its own volume | the only channel key (tmpfs); session material in memory | nothing until a fill |

Both bridges are Docker `--internal`, with no egress and no route between
them. The browser has no route to the keeper at all. Its one path out is
DevTools, and the guard is the only party that connects to it. A launcher
container (runc, on the keeper bridge) generates keys and runs the keeper
probe. Keys and the secret live in the CVM's tmpfs, and they reach the
sandboxes on stdin through `docker exec -i`, never on a command line.

The keeper channel is the CAH Noise KK channel, unchanged (`kkrpc.py` and
`session_material.py` from PR #10), over TCP between the bridges' addresses.
A Unix-socket channel was not used. gVisor needs `--host-uds` to reach a host
socket, and a sandbox with a host socket open cannot be checkpointed. That is
the same limit as smolvm's G3.

### Getting runsc into the dstack 0.6.0 image

The development image's docker can use runsc as it ships. The app compose
carries [`init-gvisor.sh`](../../test-suites/eggomi/gvisor/init-gvisor.sh)
as its `init_script`. dstack-prepare sources that script with the data disk
mounted and before docker.service starts, and the script is part of
compose-hash. It does these things (steps 3 to 5 are the release hardening
described below):

1. It fetches the release bundle and checks it against the pinned SHA-512.
   It keeps only five files, each pinned too: `runsc`, and `gvisor_sentry`,
   `runsc-fd-parking`, `gvisor-sentry-prewarmer`, and `checkpointgofer`
   from `gvisor-bin/`. They go on the encrypted data disk, and later boots
   re-check them.
2. It adds `runtimes.runsc = {path, runtimeArgs: ["--platform=systrap"]}`
   and `experimental: true` (for `docker checkpoint`) to
   `/etc/docker/daemon.json`. `/etc` is a writable overlay.
3. It installs the CVM input floor (`EGGOMI-FLOOR`, IPv4 and IPv6).
4. It caps the ZFS ARC.
5. It installs `gv-ckpt`, the checkpoint policy, and starts its reaper.
6. It starts a lab sshd on the `/etc` overlay. This step is lab only.

Boot log: `init-gvisor: runsc version release-20260928.0 registered
(systrap)`. The compose's `runsc-smoke` service (`runtime: runsc`) reports
`kernel=4.19.0-gvisor`.

A production image needs these things:

- runsc and its sidecars, either baked into the measured rootfs or fetched
  by a measured init script as here. Since 20260928.0, runsc refuses to
  start without `gvisor-bin/gvisor_sentry`.
- The runtime registered before dockerd starts. dstack 0.6.0's
  `init_script` does this. Phala Cloud's 0.5.9 drops `init_script`, so there
  the CC1 pre-launch path applies.
- `experimental` only if Docker checkpoints are used. Calling `runsc
  checkpoint`/`restore` directly does not need it.
- The input floor, the ARC cap, and `gv-ckpt`, in the measured init script
  ([Release hardening](#release-hardening-eggomi780)).
- No KVM. systrap needs none.

## S3': lifecycle and memory

[`s3-gvisor.sh`](../../test-suites/eggomi/scripts/s3-gvisor.sh) runs
[`incvm-s3.sh`](../../test-suites/eggomi/gvisor/incvm-s3.sh) as root in the
CVM. Metric names follow `s3-smolvm.sh`. There are four runs on 2026-10-07:
run 1 on a freshly booted CVM, then runs 2 to 4 on that same CVM. Run 4
followed the review fixes, which added checks but changed no measurement.
The figures below are from run 3. Across the runs, most lifecycle times
stayed within 10 % and probe results within 10 %. The exceptions: browser
exec p50 was 0.047 s in run 1, guard stop ranged from 0.31 to 1.08 s, and
browser stop from 0.29 to 0.41 s. Restore to ready took 2.33, 2.41, 2.18,
and 2.43 s, and memory figures agreed within 3 % (run 1 aside, as noted
below).

Memory is reported three ways, because no single gVisor figure corresponds
to smolvm's VMM RSS:

| Metric | Meaning |
| --- | --- |
| `cgroup_memory_bytes` | the role cgroup's `memory.current`: what the role is charged, page cache included. This is the figure to budget with. |
| `host_rss_bytes` | the PSS of the sandbox's host processes (Sentry, Gofer, systrap stubs), summed once per address space. It includes shared binaries charged to other cgroups. |
| `guest_used_bytes` | MemTotal - MemAvailable from the sandbox's own `/proc/meminfo`. gVisor counts its file cache here. |

### Comparison with smolvm

| | smolvm (L2, on the host) | gVisor (L1, in the CVM) |
| --- | --- | --- |
| keeper create / start / ready | 0.03 / 0.38 / 0.99 s | 0.10 / 0.35 / 0.81 s |
| guard create / start / ready | in the browser VM | 0.13 / 0.46 / 1.41 s |
| browser create / start / ready | 0.09 / 0.27 / 1.52 s | 0.09 / 0.36 / 1.57 s |
| exec, p50 of 9 (keeper / browser) | 0.016 / 0.027 s | 0.028 / 0.029 s |
| browser checkpoint | 1.23 s (source paused 0.51 s) | 2.22 s, `--leave-running` (no pause figure) |
| checkpoint size | 166 MB (zstd) | 176 MB (uncompressed: runsc's default) |
| browser stop | 0.16 s | 0.30 s (0.29-0.41 s across runs) |
| restore to ready | 2.82 s | 2.18 s (`docker start --checkpoint` 1.75 s) |
| branch a restored browser | 0.49 s | not available: Docker restores into the same container |
| keeper idle | 132 MB host RSS, 58 MB guest | 33 MB cgroup, 42 MB PSS, 28 MB sandbox |
| guard idle | (in the browser VM) | 40 MB cgroup, 49 MB PSS |
| browser idle | 483 MB host RSS, 267 MB guest | 233 MB cgroup, 340 MB PSS, 555 MB sandbox |
| keeper + guard + browser idle | 615 MB host RSS | 306 MB cgroup, 431 MB PSS |
| browser with a 256 MiB tab | 825 MB | 538 MB cgroup (+305 MB) |
| tab memory returned without intervention | 348 MB in 30 s (free-page reporting) | 288 MB within 30 s of the tab closing (the Sentry releases freed pages) |
| on-demand reclaim | balloon pulse: 73 MB in 1.0 s | `memory.reclaim`: 6 MB (`EAGAIN`) in 2 ms |
| checkpoint raises the source by | +163 MB host RSS (G4) | +49 MB cgroup (page cache of the image) |
| browser stop returns | 567 MB host RSS | 293 MB cgroup; CVM used -192 MB, shmem -174 MB |
| restored browser idle | 141 MB host RSS (lazy) | 256 MB cgroup |
| keeper probe during stop/restore | 48 attempts, 0 failures, max gap 0.16 s, p50 31 ms | 111 attempts, 0 failures, max gap 0.146 s, p50 3.2 ms (all runs: 0 failures) |
| restore leftovers | G6: 450-650 MB on disk under `vms/_shared` | 176 MB per restore in the CVM's `/tmp` (RAM). The suite measures and removes it |
| per-role limits | VM size (vCPU, MiB) | cgroup v2 `memory.max` and `cpu.max`, checked per run |

The CVM's own memory, as `cvm_used_bytes` (MemTotal - MemAvailable inside
the CVM):

| Phase | CVM used | of which ZFS ARC | of which shmem |
| --- | --- | --- | --- |
| idle, three roles up | 1,453 MB | 714 MB | 215 MB |
| active (tab open, sessions flowing) | 1,837 MB | 712 MB | 505 MB |
| after the tab closed and 30 s | 1,453 MB | 712 MB | 215 MB |
| before the browser stop (after a checkpoint) | 1,738 MB | 845 MB | 215 MB |
| after the browser stop | 1,546 MB | 865 MB | 41 MB |
| all roles stopped | 1,248 MB | 723 MB | 10 MB |

On the host, the CVM's QEMU RSS rose to 4.0 GB of its 6 GB and did not
fall. Memory that a sandbox returns goes back to the CVM's kernel, not to the
host. There is no balloon, and an SNP guest's private memory would not take
one in any case. This matches the smolvm note's expectation for option (a).
Size the CVM for the peak.

What the numbers say:

- **Fixed cost per sandbox is small.** An empty runsc sandbox is charged
  12.9 MB, against 0.3 MB under runc. A Python process holding the CAH
  stubs is charged 27.0 MB, against 10.5 MB under runc. Three sandboxes cost
  about 45 MB more than three runc containers.
- **gVisor returns freed memory without being asked.** A closed tab's
  288 MB was back in the CVM within 30 s. This plays the part that
  free-page reporting plays for smolvm.
- **`memory.reclaim` is nearly useless here.** gVisor keeps application
  memory in a memfd, which counts as shmem, and the CVM has no swap. So the
  kernel can reclaim only page cache. On a cold CVM, run 1 reclaimed 119 MB
  of Chromium's file pages, which were first charged to the browser. Warm
  runs reclaimed 6 MB. The levers are tab and browser lifecycle, and
  stopping the browser, not cgroup reclaim. zram swap in the CVM would make
  `memory.reclaim` work, but it is untested here.
- **Checkpoints cost ZFS ARC.** dstack's data disk is ZFS, and the ARC is
  not page cache, so MemAvailable counts it as used. Writing a 176 MB image
  raised the ARC by about 130 MB. The ARC is allowed to grow to 5.1 GB of the
  6 GB CVM. Cap `zfs_arc_max` in a production image.
- **Restore is quick, but it is not a branch.** `docker start --checkpoint`
  restores into the same container, so there is no equivalent of smolvm's
  `machine branch`. A second copy would need `runsc restore` against a
  bundle of its own, which was not tried.

## S4': secret capability RPC, leak search, boundary

[`s4-gvisor.sh`](../../test-suites/eggomi/scripts/s4-gvisor.sh) runs
[`incvm-s4.sh`](../../test-suites/eggomi/gvisor/incvm-s4.sh). It passed on
all four runs. Hit counts below are the range across runs 3 and 4.

### The 14 cases

These are the cases of `s4-secret-rpc.sh`, with the guard in its own
sandbox. The live session is filled into a browser page over DevTools, and
the restored browser's carried session is read back from that page.

| Case | Result |
| --- | --- |
| ping | `ok` |
| mint, open at the guard, redeem | `filled`, then `ok` |
| redeem the same token again | `consumed` |
| open the same seal again | `filled`, `repeat`, no plaintext returned |
| open after the TTL (1.0 s TTL, opened at 1.5 s) | `grant_expired` at the guard |
| redeem after the TTL (1.5 s TTL, redeemed at 2.0 s) | `expired` |
| `GetSecret`, `ListConnections` | `denied_method` |
| unregistered channel key | `handshake_refused` |
| purpose outside the allowlist / 60 s TTL | `denied_purpose` / `denied_ttl` |
| live session (20 s TTL), filled into a login page | `filled`, fill `ok` |
| restored browser: keeper RPC from the guard, and DevTools | `ok`, `ok` |
| restored browser: its page still holds the original grant and token, and redeeming them after the TTL | `expired` (grant and token match) |

### Leak search

The search is `host_tools.py scan` from PR #10. It looks for the secret
raw, as UTF-16LE, and as hex. runsc writes `checkpoint.img`, `pages.img`,
and `pages_meta.img` uncompressed, so the image is searched as stored. A
checkpoint search counts only if it read all three files and `pages.img` is
over 32 MB.

| Target | Secret hits | Positive control |
| --- | --- | --- |
| browser checkpoint, pristine (before any fill) | 0 | a canary page opened before it: 128-138 hits |
| browser checkpoint right after the fill | 0 | the filled token: 6-7 hits |
| browser checkpoint after the filled tab was closed | 0 | (observation) the token: 2-3 hits |
| containerd's leftover restore copy (`/tmp/ctrd-checkpoint*`) | 0 | the filled token: 6-7 hits (before eggomi#780; since then no copy is left to search: `gv-ckpt` removes it in the restore step, and S4' checks that none remains) |
| browser storage: writable layer (including gVisor's `root:self` file store) and container directory | 0 | |
| guard storage | 0 | |
| restored browser storage | 0 | |
| keeper volume | | the secret: 1 hit |

The secret never left the keeper sandbox. The browser held only the derived
session token, and the token expired as designed after restore.

### Boundary checks

Each check has its own test in S4' and a control that shows the probe
detects what it looks for. The in-sandbox probe runs as root inside the
browser sandbox, the strongest position a compromised renderer could reach
after escaping Chromium's own sandbox. Its request goes in on stdin, so its
markers appear on no command line.

| Check | Evidence | Control |
| --- | --- | --- |
| The browser runs on gVisor's kernel | `uname -r` = `4.19.0-gvisor` | |
| Chromium's sandbox is on | 2 renderers, both seccomp mode 2, each in its own user, PID, and network namespace; browser uid 10001 | |
| The browser cannot read the keeper's files | a search of the browser's whole filesystem for the keeper canary (3,885 files read, none unreadable): 0 hits. Keeper, guard, Docker, cgroup, and lab paths do not exist | the same search in the keeper finds `/var/lib/eggomi-keeper/canary` |
| The browser cannot see the keeper's processes | no `keeper_svc` or `gv_guard` among the browser's processes | the keeper's probe lists `keeper_svc` |
| The browser cannot read the keeper's memory | `/proc/<keeper Sentry pid>/mem` and the guard's: `ENOENT`. No `/proc/kcore` and no `/dev/mem` | |
| The browser cannot connect to the keeper | the keeper, the guard's keeper-side address, and the launcher: `ENETUNREACH`; the guard's browser-side address: `ECONNREFUSED` (no listener) | the keeper connects to itself |
| The CVM floor blocks the CVM's own services | from the browser, `10.231.11.1:8090` and `:22` are not connected. Since eggomi#780 the floor is the measured init script's, and the check also requires its rules | before the floor, the launcher reaches the guest agent on `:8090`. Since eggomi#780: through a one-rule hole for the launcher alone, and not once the hole is closed |
| An escape into the browser Sentry's host namespaces sees no other sandbox | a fresh `/proc` in that PID namespace lists only the browser's Sentry and stubs; the keeper's and guard's Sentry pids are `ENOENT`; the namespace's interfaces attach only to the browser bridge | the same escape into the keeper's namespaces sees the keeper's Sentry and attaches only to the keeper bridge; the guard's attaches to both |
| The Sentries are isolated on the host | each Sentry has seccomp mode 2, `no_new_privs`, its own PID, network, mount, IPC, UTS, and user namespaces (all distinct across the three), and a root holding only `etc` and `proc` | |

The escape check simulates a process that got out of gVisor into the
Sentry's host PID and network namespaces. It cannot run code inside the
Sentry, so it enters from the CVM with `nsenter`. A real escapee would also
be in the Sentry's own user namespace, under its seccomp filter, with
`CapEff` `0x8001f` scoped to that namespace and a root of `etc` and `proc`.
That is a narrower position than the simulation. An escapee's kernel
network stack has no route even in the keeper's own namespace, because
runsc's netstack owns the veth. So the network proof is bridge attachment,
not a connect.

## Findings

1. **A sandbox reaches the CVM's services through its bridge gateway.**
   Docker's `--internal` removes egress, but the bridge's gateway address is
   the CVM itself. From a runsc sandbox, `10.231.12.1:8090`
   (dstack-guest-agent) and `:22` (the lab sshd) both connected. The suites
   add an input floor: `iptables -I INPUT -i <role bridge> -m conntrack
   --ctstate NEW,INVALID -j DROP` for each role bridge. With it, the browser
   reaches neither port, and traffic between sandboxes on a bridge is
   unaffected. A production compose needs this floor, or CC1's
   `nft-egress.sh` equivalent, in a measured init script. **Closed:**
   init-gvisor.sh installs it (eggomi#780 item 1), and the suites no longer
   add their own.
2. **containerd leaves every restore's checkpoint image in tmpfs.** `docker
   start --checkpoint` stages the image in `/tmp/ctrd-checkpoint*`, which is
   RAM in the CVM, and never removes it. The copy survives the restore and
   the container's removal. Each copy is a full browser memory image, filled
   session included, and it pins 150 to 180 MB until reboot. S3' measures it
   (`restore_tmp_copy_bytes`), S4' searches it, and both remove it. The
   restore path must remove it too, or use `runsc restore` directly.
   **Closed:** `gv-ckpt restore` removes it in the same step (item 2).
3. **Docker checkpoints need `experimental`.** Docker can only restore into
   the same container. A checkpoint is uncompressed by default, so it is as
   large as the browser's memory.
4. **`memory.reclaim` does not reclaim gVisor memory without swap.** See
   S3'.
5. **A filled session outlives its tab.** After the tab that held the fill
   was closed, the next checkpoint still held the token (2 to 3 hits). See the
   pristine-checkpoint rule, which `gv-ckpt` now enforces (item 4).

## Release hardening (eggomi#780)

Four changes make the design fit for a release. All four live in the
measured init script ([`init-gvisor.sh`](../../test-suites/eggomi/gvisor/init-gvisor.sh)),
so compose-hash covers them. Each one has a suite check that fails on a CVM
booted without it. The suites no longer install anything of their own.

| # | Change | Enforced by | Check (fails without it) |
| --- | --- | --- | --- |
| 1 | CVM input floor | an `EGGOMI-FLOOR` chain, IPv4 and IPv6, jumped to first from `INPUT`. It returns established traffic and drops everything else from `docker0`, `br-+`, and `gv+`. If the floor cannot be installed, dockerd is masked and no container starts | S3' `cvm_floor_measured`; S4' boundary `cvm_floor_blocks_cvm_services`: the rules are init's, and the browser reaches neither `:8090` nor `:22`. Control: with a one-rule hole for the launcher alone, the launcher reaches `:8090`. With the hole closed, even a runc container cannot |
| 2 | No restore residue | `gv-ckpt restore` runs `docker start --checkpoint`, then removes the copy containerd staged in `/tmp` in the same step. The reaper also removes any copy a raw restore left behind, after 60 s | S3' `restore_staged_copy_seen` (the control: the tool saw and removed a copy of 171 MB) and `no_restore_residue`; S4' policy `restore_leaves_no_residue`, for a post-fill and a pristine restore |
| 3 | ZFS ARC cap | `zfs_arc_max` = MemTotal/16, clamped to 256 MiB..1 GiB and kept above `zfs_arc_min`. That is 371 MiB in the 6 GB CVM, against a default of 5.1 GB | S3' `zfs_arc_capped`: the cap is in force, and the ARC stayed within it (plus 64 MiB) at every sample |
| 4 | Pristine-checkpoint rule | `gv-ckpt`. `arm` marks a browser that started from its image as pristine. `filled` records a fill before it happens. `create --reuse` is refused after a fill. A post-fill checkpoint carries the filled session's expiry as its deadline. The reaper deletes it at that deadline, and `restore` refuses it after the deadline, as it does any image `gv-ckpt` did not create | S4' policy checks: `browser_armed_pristine`, `pristine_reuse_checkpoint_allowed`, `reuse_checkpoint_refused_after_fill`, `post_fill_checkpoints_carry_the_session_deadline`, `post_fill_images_deleted_at_expiry`, `expired_post_fill_image_refused`, and `pristine_image_reusable` |

`gv-ckpt` ([`gv_ckpt.py`](../../test-suites/eggomi/gvisor/gv_ckpt.py)) is
inlined into the init script when gvisor-lab.sh renders it, and installed as
`/run/eggomi/bin/gv-ckpt` (root only). Its state is in tmpfs, so `arm` also
refuses a container that was created before the current boot. The reaper
wakes at the next deadline, or every 5 s at the latest. A release's
launcher calls `gv-ckpt` instead of `docker checkpoint` and `docker start
--checkpoint`. A raw Docker checkpoint does not get past `restore`, which
refuses images it did not record, and the reaper deletes any checkpoint of a
tracked browser that it did not record. Host-only unit tests run against a fake
docker CLI: `test-suites/eggomi/scripts/gvisor-unit-tests.sh`.

Lab run on 2026-10-07. A fresh CVM, `eggomi-gvisor-780`, was booted with the
hardened init script beside the standing lab CVM, which was left alone.

- The boot log shows each step: `ZFS ARC capped at 388786688 bytes` and
  `gv-ckpt installed; reaper running`. `iptables -S` shows `-A INPUT -j
  EGGOMI-FLOOR` as the first rule, and the same chain exists under ip6tables.
- S3' passed all 18 checks. These six are new: `cvm_floor_measured`,
  `browser_armed_pristine`, `checkpoint_via_policy`,
  `restore_staged_copy_seen`, `no_restore_residue`, and `zfs_arc_capped`.
  Restore to ready took 2.29 s (`gv-ckpt restore` 1.83 s, cleanup included).
  The browser checkpoint took 5.1 s, against 2.2 s before; the image now
  goes through a smaller ARC.
- S4' passed: 14/14 cases, 9/9 boundary checks, and 8/8 policy checks.
  Every leak search found 0 hits, and each positive control hit: canary 128,
  filled token 6, secret on the keeper volume 1. After the fill, `create
  --reuse` was refused (`not_pristine`) and wrote no image. Both restores
  left no copy in `/tmp`; `gv-ckpt` had removed 155 MB and 144 MB. Both
  post-fill images were gone 1.45 s after the session expired: the suite
  first looks after its post-expiry redeem, so this is an upper bound. A
  restore of the reaped image was refused (`unknown_checkpoint`), and the
  pristine image restored and answered DevTools. The floor control behaved
  as designed: with the hole open, the launcher connected to `:8090` and
  `:22`; with it closed, both connections timed out, as did the browser's.
- Negative control: the same suites, run on the standing lab CVM booted with
  the earlier init script, fail exactly the hardening checks. S3' fails the
  six new checks. S4' fails all 8 policy checks (`gv-ckpt` is missing), and
  two boundary checks: `cvm_floor_blocks_cvm_services`, and
  `browser_cannot_connect_keeper`, because the browser now reaches the
  gateway's `:8090` and `:22`. The suites left that CVM as they found it.
- With the cap, the ARC peaked at 393 MB, against 865 MB before. The CVM
  used 1,052 MB idle and 1,435 MB active, against 1,453 and 1,837 MB before.
  The host-side QEMU RSS peaked at 3.2 GB, against 4.0 GB.

### Sizing

The CVM's memory cannot shrink once it is touched: there is no balloon, and
the host-side QEMU RSS never falls. So size the CVM for its peak, and
reserve all of it on the host. The peak is bounded by:

```text
CVM RAM >= base + ARC cap + keeper.max + guard.max + 2 x browser.max + 10 %
```

- **base** is the CVM with no roles running, without the ARC: about
  500 MB (754 MB used when all roles had stopped, of which 251 MB was ARC).
- **ARC cap** is MemTotal/16, clamped to 256 MiB..1 GiB (371 MiB at 6 GB).
- The roles' cgroup limits, `memory.max`, bound what the sandboxes are
  charged, page cache included.
- **The browser counts twice.** While a restore runs, containerd's staged
  copy (tmpfs) and the restored sandbox both hold the browser's memory, until
  `gv-ckpt` removes the copy. The copy is as large as the browser's memory
  at checkpoint time, so `browser.max` bounds it.

With the lab's limits (keeper 512 MiB, guard 256 MiB, browser 2 GiB), the
bound is 0.5 + 0.39 + 0.54 + 0.27 + 4.29 = 6.0 GB, plus 10 %: about 6.6 GB.
The 6 GB lab CVM is enough for what was measured (peak used 1.4 GB), but not
for the bound. A release should either size the CVM at 7 GB, or cap the
browser at 1.5 GiB, which brings the bound to about 5.4 GB. Calling `runsc
restore` directly would remove the staged copy and the factor of two, but
that path is untested.

## Overhead

Measured in the lab CVM by hand, as runc and runsc twins of the same image
and command:

| | runc | runsc (systrap) |
| --- | --- | --- |
| empty sandbox, memory charged | 0.3 MB | 12.9 MB |
| Python with the CAH stubs loaded, idle | 10.5 MB | 27.0 MB |
| `docker run --rm alpine true` (median of 5) | 0.53 s | 0.55 s |
| 2,000 X25519 key generations (compute) | 2.23 s | 2.34 s (+5 %) |
| 3,000 create, stat, and unlink in `/tmp` | 0.45 s (overlay on ZFS) | 0.20 s (gVisor's tmpfs) |

CC1 measured the syscall-heavy end: package managers ran 1.5 to 1.8 times
slower under runsc, and fork, stat, and small-file workloads 2 to 7 times
slower (eggomi repository, `infra/dstack/LAB-NOTES.md`, "gVisor full
shell"). For
these roles the overhead is in memory, about 13 to 17 MB per sandbox, and in
Chromium's startup. Keeper RPC is faster than in smolvm (p50 3.2 ms against
31 ms), because the hop is a veth inside one kernel rather than a VMM
network stack.

## What gVisor's boundary does and does not protect

Compared with a VM boundary (smolvm, or one CVM per role):

| Threat | gVisor sandbox in one CVM | VM boundary |
| --- | --- | --- |
| Renderer exploit, then a Linux syscall exploit | **Contained.** The application never talks to the CVM's kernel. It talks to the Sentry, a Go reimplementation of the Linux syscall surface (`4.19.0-gvisor`). | Contained by the guest kernel and then the VMM. |
| Reading another role's files, processes, or memory | **Contained.** There is a separate filesystem view and `/proc`, and no route between the networks (S4'). | Contained. |
| Sentry compromise (a gVisor bug) | **Partly contained.** The attacker gets a host process in its own user, PID, mount, and network namespaces, under a seccomp allowlist, with no capabilities outside its user namespace and an almost empty root. The next step is a CVM kernel bug reachable through that allowlist. | The next step is a VMM or hypervisor bug. With one CVM per role, SNP itself also separates the roles. |
| CVM kernel compromise | **Not contained.** One kernel holds every role's memory, the keeper's included. | Contained by separate address spaces (smolvm) or by separate SNP guests (one CVM per role). |
| Side channels (cache, Spectre-class) between roles | **Not addressed.** The roles share a kernel, cores, and caches. | Partly addressed. VMs share cores unless pinned, and SNP adds memory encryption but not cache isolation. |
| Host or hypervisor reading memory | Addressed by the CVM (SNP) for all roles together. Inside, it is one trust domain. | Addressed per CVM. A per-role CVM keeps each role's attestation separate. |
| Resource exhaustion by one role | cgroup limits per role (`memory.max`, `cpu.max`). Without swap, memory is reclaimed only by gVisor itself or by a stop. | Fixed VM sizes. Without a balloon in SNP, a stop. |
| Checkpoints | Plain files of the browser's memory in the CVM's encrypted disk and in tmpfs (finding 2). The host never sees them. | smolvm: files on the user's machine. A per-role CVM has no RAM checkpoint at all. |

gVisor is a single-kernel design with a much smaller attack surface. It is
not a hardware boundary. The keeper's secret is safe from the browser as
long as both the Sentry and the CVM kernel hold. With one CVM per role, the
keeper's secret is safe as long as SNP holds. The CVM's own attestation
covers runsc, because the init script and its pinned hashes are in
compose-hash.

## The pristine-checkpoint rule for browsers

A browser checkpoint is a copy of everything in the browser's memory. S4'
shows the following:

- **Before any fill**, a checkpoint holds no session material. The canary
  page shows that the search sees the page content.
- **Right after a fill**, the checkpoint holds the filled token (6 to 7
  hits). So does containerd's leftover restore copy.
- **After the filled tab is closed**, the token is still there (2 to 3 hits).
  Closing a tab frees the page but does not scrub it.
- A restored browser carries the token, and the token is bounded only by its
  TTL. Redeeming it after the TTL gives `expired`.

The rule is this. **A browser image may be checkpointed for reuse only while
it is pristine: before its first fill since it started from a clean image.**
After a fill, the browser may be checkpointed only for a short
suspend-and-resume of the same session. Such an image must be deleted, and
containerd's `/tmp` copy with it, by the time the filled session's TTL
expires. It must never be branched or reused as a template. The fill should
carry only TTL-bound session material, never a raw credential (CAH
`fill-v1`). A raw credential would sit in the image with no expiry. A
browser that has filled returns to the pristine state only by restarting from
a pristine checkpoint. Closing tabs does not do it.

## Files

| Path | Role |
| --- | --- |
| `test-suites/eggomi/scripts/gvisor-lab.sh` | fetch, serve, deploy, and remove the lab CVM; `ssh` into it |
| `test-suites/eggomi/scripts/s3-gvisor.sh`, `s4-gvisor.sh` | host wrappers: gate (exit 77), ship, run in the CVM, sample QEMU RSS, collect |
| `test-suites/eggomi/scripts/lib-gvisor.sh` | the host wrappers' shared code |
| `test-suites/eggomi/gvisor/init-gvisor.sh` | the app compose's `init_script`: runsc, dockerd runtime, CVM floor, ZFS ARC cap, `gv-ckpt`, lab sshd |
| `test-suites/eggomi/gvisor/gv_ckpt.py` | `gv-ckpt`, the checkpoint policy, inlined into the init script: pristine rule, restore without residue, post-fill reaper |
| `test-suites/eggomi/gvisor/tests/`, `scripts/gvisor-unit-tests.sh` | `gv-ckpt`'s host-only unit tests, against a fake docker CLI |
| `test-suites/eggomi/gvisor/compose.yml` | the lab CVM's compose (`runsc-smoke`) |
| `test-suites/eggomi/gvisor/Dockerfile.python`, `Dockerfile.browser` | the role images |
| `test-suites/eggomi/gvisor/incvm-lib.sh`, `incvm-s3.sh`, `incvm-s4.sh` | the suites, run as root in the CVM |
| `test-suites/eggomi/gvisor/gv_guard.py`, `cdp.py` | the guard in its own sandbox, and the DevTools client and relay |
| `test-suites/eggomi/gvisor/boundary_probe.py`, `gvctl.py` | in-sandbox probe; CVM-side cgroup, PSS, reclaim, and Sentry views |
| `test-suites/eggomi/subvm/*.py` | from PR #10 (on `next`), reused unchanged: keeper, guard, KK RPC, session material, scanner |

Outputs: `$EGGOMI_STATE_DIR/work/s3-gvisor-metrics.prom`,
`s3-gvisor-report.json`, `s4-gvisor-metrics.prom`, and `s4-gvisor-report.json`.
Both suites run one at a time, and each removes its sandboxes, networks,
volume, checkpoints, keys, and restore copies when it exits.
