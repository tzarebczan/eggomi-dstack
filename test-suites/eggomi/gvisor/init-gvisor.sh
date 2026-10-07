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
#   3. A lab sshd on guest port 22 with the lab key. The dev image's rootfs
#      and /root are read-only and its own sshd does not listen on TCP, so the
#      key and an sshd config go on the writable /etc overlay.
#
# Fails soft: a step that cannot complete logs a warning and returns 0, so
# the CVM still boots and the harness reports the gap (exit 77).
# gvisor-lab.sh fills in the __PLACEHOLDERS__.

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

eggomi_gv_runtime
eggomi_gv_sshd
