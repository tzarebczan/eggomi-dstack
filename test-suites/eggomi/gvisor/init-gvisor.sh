# shellcheck shell=bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# init-gvisor.sh: the app compose's init_script for the L1 gVisor
# inner-isolation lab CVM. Lab only: it opens a root shell. dstack-prepare
# sources it with the data disk mounted and before docker.service starts, so
# dockerd reads the runtime at its first start. It is part of compose-hash.
#
#   1. gVisor: the release bundle is fetched from the lab host
#      (`gvisor-lab.sh serve`, a copy of gVisor's own release), checked against
#      its pinned SHA-512, and only the pinned files are kept, each checked
#      again, on the encrypted data disk. A later boot re-checks them and
#      fetches only on a mismatch.
#   2. dockerd gains runtimes.runsc with the systrap platform (no KVM in the
#      guest; a real SEV-SNP guest cannot run KVM either) and experimental
#      mode, for `docker checkpoint`.
#   3. The CVM input floor (eggomi#780 item 1): new connections from the
#      container bridges to the CVM itself are dropped, so no sandbox reaches
#      the CVM's own services (dstack-guest-agent on :8090, sshd) through its
#      bridge gateway. Fails closed: without the floor, dockerd is masked and
#      no container starts.
#   4. The ZFS ARC cap (item 3): zfs_arc_max is MemTotal/16, clamped to
#      256 MiB..1 GiB, instead of ZFS's default of almost all of the CVM.
#   5. gv-ckpt (items 2 and 4), the checkpoint policy: restores remove
#      containerd's staged copy in the same step, a browser is checkpointed
#      for reuse only while pristine, and its reaper deletes post-fill images
#      at their session's expiry. Installed to /run/eggomi/bin/gv-ckpt.
#   6. A lab sshd on guest port 22 with the lab key. The dev image's rootfs
#      and /root are read-only and its own sshd does not listen on TCP, so the
#      key and an sshd config go on the writable /etc overlay.
#
# Steps 1, 2, 4, and 6 fail soft: a step that cannot complete logs a warning
# and returns 0, so the CVM still boots and the harness reports the gap
# (exit 77, or a failed check). Steps 3 and 5 are release hardening and fail
# closed. gvisor-lab.sh fills in the __PLACEHOLDERS__.

eggomi_gv_sha512_ok() {
  sha512sum -c --status - 2>/dev/null
}

eggomi_gv_runtime() {
  local url=__GVISOR_URL__ want=__GVISOR_BUNDLE_SHA512__
  local dir=${DATA_MNT:-/var/volatile/dstack/persistent}/eggomi-gvisor
  # One "sha512  path" line per kept file.
  local files='__GVISOR_FILES__'
  mkdir -p "$dir" && chmod 0700 "$dir" || return 0
  if ! (cd "$dir" && printf '%s\n' "$files" | eggomi_gv_sha512_ok); then
    rm -rf "$dir/new" "$dir/bundle.tmp"
    if ! curl -fsS --max-time 600 -o "$dir/bundle.tmp" "$url"; then
      printf 'init-gvisor: WARNING: could not fetch %s\n' "$url" >&2
      rm -f "$dir/bundle.tmp"
      return 0
    fi
    if ! printf '%s  %s\n' "$want" "$dir/bundle.tmp" | eggomi_gv_sha512_ok; then
      printf 'init-gvisor: WARNING: the bundle is not the pinned SHA-512; discarded\n' >&2
      rm -f "$dir/bundle.tmp"
      return 0
    fi
    mkdir -p "$dir/new" || return 0
    # Only the pinned names, as plain files (the guest has Python, no bzip2).
    if ! printf '%s\n' "$files" | awk '{print $2}' | python3 -c '
import sys, tarfile
names = sys.stdin.read().split()
with tarfile.open(sys.argv[1], "r:bz2") as t:
    for n in names:
        m = t.getmember(n)
        assert m.isfile(), n
        t.extract(m, sys.argv[2], filter="data")
' "$dir/bundle.tmp" "$dir/new" || ! (cd "$dir/new" && printf '%s\n' "$files" | eggomi_gv_sha512_ok); then
      printf 'init-gvisor: WARNING: the bundle does not hold the pinned files; discarded\n' >&2
      rm -rf "$dir/new" "$dir/bundle.tmp"
      return 0
    fi
    rm -f "$dir/bundle.tmp"
    chmod -R a-w,u+w "$dir/new" && chmod 0755 "$dir/new" "$dir/new/gvisor-bin" &&
      rm -rf "$dir/runsc" "$dir/gvisor-bin" &&
      mv "$dir/new/runsc" "$dir/runsc" && mv "$dir/new/gvisor-bin" "$dir/gvisor-bin" &&
      rm -rf "$dir/new" || return 0
  fi
  local daemon=/etc/docker/daemon.json
  mkdir -p /etc/docker || return 0
  [ -s "$daemon" ] || printf '{}\n' >"$daemon" || return 0
  if ! jq --arg p "$dir/runsc" \
    '.runtimes.runsc = {"path": $p, "runtimeArgs": ["--platform=systrap"]} | .experimental = true' \
    "$daemon" >"$daemon.new" || ! mv "$daemon.new" "$daemon"; then
    printf 'init-gvisor: WARNING: could not register runsc with dockerd\n' >&2
    return 0
  fi
  printf 'init-gvisor: %s registered (systrap)\n' "$("$dir/runsc" --version 2>/dev/null | head -n 1)" >&2
}

eggomi_gv_sshd() {
  local hostkeys='' k
  install -d -m 0755 /etc/ssh/lab /run/sshd || return 0
  printf '%s\n' '__LAB_SSH_PUBKEY__' >/etc/ssh/lab/authorized_keys || return 0
  chmod 0644 /etc/ssh/lab/authorized_keys
  ssh-keygen -A >/dev/null 2>&1 || return 0
  for k in /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ecdsa_key /etc/ssh/ssh_host_rsa_key; do
    [ -f "$k" ] && hostkeys="${hostkeys}HostKey ${k}
"
  done
  printf '%s\n' 'Port 22' 'AddressFamily inet' 'ListenAddress 0.0.0.0' \
    'PidFile /run/lab-sshd.pid' 'UsePAM no' 'PasswordAuthentication no' \
    'KbdInteractiveAuthentication no' 'PubkeyAuthentication yes' \
    'PermitRootLogin prohibit-password' 'AuthorizedKeysFile /etc/ssh/lab/authorized_keys' \
    'StrictModes no' "$hostkeys" >/etc/ssh/lab/sshd_config
  if /usr/sbin/sshd -t -f /etc/ssh/lab/sshd_config; then
    /usr/sbin/sshd -f /etc/ssh/lab/sshd_config -e -D >/dev/kmsg 2>&1 &
    printf 'init-gvisor: lab sshd on port 22\n' >&2
  else
    printf 'init-gvisor: WARNING: lab sshd config rejected\n' >&2
  fi
}

# The floor drops what the role bridges open towards the CVM: Docker's
# --internal removes egress, but the bridge gateway is the CVM itself. Replies
# to the CVM's own connections pass, and traffic between containers on one
# bridge is forwarded, not INPUT. Interfaces: docker0, Compose's br-*, and
# the gv* role bridges the lab suites name. Published ports and the CVM's
# uplink are untouched.
eggomi_gv_floor() {
  local ipt ifc
  for ipt in iptables ip6tables; do
    if ! command -v "$ipt" >/dev/null 2>&1; then
      [ "$ipt" = ip6tables ] && [ ! -e /proc/net/if_inet6 ] && continue
      return 1
    fi
    "$ipt" -w -N EGGOMI-FLOOR 2>/dev/null || "$ipt" -w -F EGGOMI-FLOOR || return 1
    "$ipt" -w -A EGGOMI-FLOOR -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN || return 1
    for ifc in docker0 'br-+' 'gv+'; do
      "$ipt" -w -A EGGOMI-FLOOR -i "$ifc" -j DROP || return 1
    done
    "$ipt" -w -C INPUT -j EGGOMI-FLOOR 2>/dev/null || "$ipt" -w -I INPUT 1 -j EGGOMI-FLOOR || return 1
  done
}

# zfs_arc_max at MemTotal/16, clamped to 256 MiB..1 GiB and kept above
# zfs_arc_min. The ARC is not page cache: MemAvailable counts it as used, and
# its default ceiling (5.1 GB of a 6 GB CVM) would crowd out the sandboxes.
eggomi_gv_arc() {
  local param=/sys/module/zfs/parameters/zfs_arc_max mem cap min
  if [ ! -w "$param" ]; then
    printf 'init-gvisor: WARNING: no ZFS ARC parameter; the ARC is not capped\n' >&2
    return 0
  fi
  mem=$(awk '/^MemTotal:/ {printf "%d", $2 * 1024}' /proc/meminfo)
  cap=$((mem / 16))
  [ "$cap" -ge $((256 << 20)) ] || cap=$((256 << 20))
  [ "$cap" -le $((1 << 30)) ] || cap=$((1 << 30))
  min=$(awk '$1 == "c_min" {printf "%d", $3}' /proc/spl/kstat/zfs/arcstats 2>/dev/null)
  [ -z "$min" ] || [ "$cap" -gt "$min" ] || cap=$((min + (64 << 20)))
  if printf '%s\n' "$cap" >"$param"; then
    printf 'init-gvisor: ZFS ARC capped at %s bytes\n' "$cap" >&2
  else
    printf 'init-gvisor: WARNING: could not cap the ZFS ARC\n' >&2
  fi
}

eggomi_gv_ckpt() {
  local bin=/run/eggomi/bin/gv-ckpt
  install -d -m 0700 /run/eggomi /run/eggomi/bin || return 1
  cat >"$bin.tmp" <<'EGGOMI_GV_CKPT_PY' || return 1
__GV_CKPT_PY__
EGGOMI_GV_CKPT_PY
  chmod 0700 "$bin.tmp" && mv "$bin.tmp" "$bin" || return 1
  setsid "$bin" reap --loop 5 >/dev/kmsg 2>&1 </dev/null &
  printf 'init-gvisor: gv-ckpt installed; reaper running\n' >&2
}

# Fail closed: no container runs without the floor and the checkpoint policy.
eggomi_gv_fail_closed() {
  printf 'init-gvisor: ERROR: %s; dockerd is masked and no container starts\n' "$1" >&2
  systemctl mask --runtime docker.service docker.socket >/dev/null 2>&1 || true
}

eggomi_gv_runtime
eggomi_gv_floor || eggomi_gv_fail_closed "the CVM input floor could not be installed"
eggomi_gv_arc
eggomi_gv_ckpt || eggomi_gv_fail_closed "gv-ckpt could not be installed"
eggomi_gv_sshd
