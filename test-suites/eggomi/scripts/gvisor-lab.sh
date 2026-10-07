#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# Bring up the L1 gVisor inner-isolation lab CVM: one simulated-SNP dstack
# CVM whose init_script registers runsc (systrap) with dockerd and starts a
# lab sshd. S3' and S4' (s3-gvisor.sh, s4-gvisor.sh) run their roles in it.
# See docs/eggomi/inner-isolation-gvisor.md. Lab only.
#
#   fetch    download gVisor's release bundle once and check its SHA-512
#   serve    serve the bundle to the guest on 127.0.0.1:$EGGOMI_GVISOR_BUNDLE_PORT
#   deploy   render the app compose and deploy the CVM (needs serve)
#   wait     wait for boot and for the lab shell
#   ssh ...  run a command in the CVM as root
#   status | stop-serve | remove
#
# Environment (after `. $EGGOMI_LAB_DIR/env.sh`):
#   EGGOMI_GVISOR_DIR          state: bundle, lab key, vm-id (default $LAB/gvisor)
#   EGGOMI_GVISOR_SSH_PORT     host port for guest port 22 (default 19103)
#   EGGOMI_GVISOR_BUNDLE_PORT  bundle server port (default 18102)
#   EGGOMI_GVISOR_VM_NAME      default eggomi-gvisor-lab
#   EGGOMI_GVISOR_VCPU / _MEMORY / _DISK   default 4 / 6G / 20G
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
GV_SRC="$ROOT/test-suites/eggomi/gvisor"
LAB=${LAB:-${EGGOMI_LAB_DIR:-"$HOME/lab/eggomi-snp"}}
GV_DIR=${EGGOMI_GVISOR_DIR:-"$LAB/gvisor"}
SSH_PORT=${EGGOMI_GVISOR_SSH_PORT:-19103}
BUNDLE_PORT=${EGGOMI_GVISOR_BUNDLE_PORT:-18102}
VM_NAME=${EGGOMI_GVISOR_VM_NAME:-eggomi-gvisor-lab}

# gVisor release-20260928.0 (founder-approved for CC1 on 2026-10-01). From
# this release runsc needs its sentry sidecar in gvisor-bin/ beside it.
GVISOR_VERSION=20260928.0
GVISOR_URL="https://storage.googleapis.com/gvisor/releases/release/$GVISOR_VERSION/x86_64/gvisor.tar.bz2"
GVISOR_BUNDLE_SHA512=c8d3a9fd4d4c4f5b8ff213caa4517356be128d18659ec4cde37828fe797f61a9725a602a846c81a8ed19c057a996515d31c081eba343ed4613a89951ba32ed59
GVISOR_FILES='7393507f8b2525338ea627fece891939b44566ad70843eec30b6fb7b94e8955da054fa8c5464e019a5af8a295f842ab2e37c77d764a342b590ea987e1bbfc6b9  runsc
2e1fe6c155f2b0662f06321813ff0f18df0921c4b02e7d978dec00c606d078ae528eddba40a105e2d11726d1586248e0b6ff2dc96f6a8effe16d4465a1df49c0  gvisor-bin/gvisor_sentry
bdcb8034e31250379e24e40399b62c66be88318d969c462fe065a8a785c83d3a638214685ae04d7ee09f7a66695f6381635f989271ad8f0a23ee6e08040b3454  gvisor-bin/runsc-fd-parking
f0c131766303ca4733a4e42bd171d8ddf42a0a0087564605b3207b0f4c148d9ff355bad25e27d388c7c9cf06265160b3a02047ec195c035d9e8f428d8f608ce6  gvisor-bin/gvisor-sentry-prewarmer
3d6d4d1cf243a8ce25c89a9c9d142b66bb1cbcc702342e9b8ce8a30750b8d3cd126e64936e2ce308a185cb54aa511a7f576223bfe3f3b8504cd25cc5c6847aa3  gvisor-bin/checkpointgofer'

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[gvisor-lab] %s\n' "$*" >&2
}

vmm() {
  python3 "$DSTACK_VMM_CLI" --url "$DSTACK_VMM_URL" "$@"
}

need_env() {
  [[ -n "${DSTACK_VMM_CLI:-}" && -n "${DSTACK_VMM_URL:-}" ]] \
    || die "source \$EGGOMI_LAB_DIR/env.sh first"
}

fetch() {
  mkdir -p "$GV_DIR"
  local bundle="$GV_DIR/gvisor.tar.bz2"
  if [[ -s "$bundle" ]] && printf '%s  %s\n' "$GVISOR_BUNDLE_SHA512" "$bundle" | sha512sum -c --status; then
    log "bundle present and verified"
    return
  fi
  log "downloading $GVISOR_URL (167 MB)"
  curl -fsS -o "$bundle.tmp" "$GVISOR_URL"
  printf '%s  %s\n' "$GVISOR_BUNDLE_SHA512" "$bundle.tmp" | sha512sum -c --status \
    || { rm -f "$bundle.tmp"; die "bundle SHA-512 mismatch"; }
  mv "$bundle.tmp" "$bundle"
}

serve() {
  [[ -s "$GV_DIR/gvisor.tar.bz2" ]] || die "run '$0 fetch' first"
  if [[ -s "$GV_DIR/serve.pid" ]] && kill -0 "$(cat "$GV_DIR/serve.pid")" 2>/dev/null; then
    log "bundle server already running"
    return
  fi
  mkdir -p "$GV_DIR/www"
  ln -sf ../gvisor.tar.bz2 "$GV_DIR/www/gvisor.tar.bz2"
  setsid python3 -m http.server "$BUNDLE_PORT" --bind 127.0.0.1 --directory "$GV_DIR/www" \
    >"$GV_DIR/serve.log" 2>&1 </dev/null &
  echo $! >"$GV_DIR/serve.pid"
  log "serving the bundle on 127.0.0.1:$BUNDLE_PORT (guest: 10.0.2.2:$BUNDLE_PORT)"
}

stop_serve() {
  if [[ -s "$GV_DIR/serve.pid" ]]; then
    kill "$(cat "$GV_DIR/serve.pid")" 2>/dev/null || true
    rm -f "$GV_DIR/serve.pid"
  fi
}

render_init() {
  local pub
  pub=$(cat "$GV_DIR/lab_ssh_ed25519.pub")
  python3 - "$GV_SRC/init-gvisor.sh" "http://10.0.2.2:$BUNDLE_PORT/gvisor.tar.bz2" \
    "$GVISOR_BUNDLE_SHA512" "$GVISOR_FILES" "$pub" <<'PY'
import sys
text = open(sys.argv[1], encoding="utf-8").read()
for key, value in zip(
    ("__GVISOR_URL__", "__GVISOR_BUNDLE_SHA512__", "__GVISOR_FILES__", "__LAB_SSH_PUBKEY__"),
    sys.argv[2:],
):
    assert key in text, key
    text = text.replace(key, value)
sys.stdout.write(text)
PY
}

deploy() {
  need_env
  [[ -s "$GV_DIR/gvisor.tar.bz2" ]] || die "run '$0 fetch' first"
  if [[ ! -s "$GV_DIR/lab_ssh_ed25519" ]]; then
    ssh-keygen -q -t ed25519 -N '' -C eggomi-gvisor-lab -f "$GV_DIR/lab_ssh_ed25519"
  fi
  [[ ! -s "$GV_DIR/vm-id" ]] || die "a lab CVM exists ($(cat "$GV_DIR/vm-id")); '$0 remove' first"
  render_init >"$GV_DIR/init-gvisor.rendered.sh"
  vmm compose --name "$VM_NAME" --docker-compose "$GV_SRC/compose.yml" --key-provider tpm \
    --public-logs --public-sysinfo --output "$GV_DIR/app-compose.base.json" >/dev/null
  jq --rawfile init "$GV_DIR/init-gvisor.rendered.sh" '.init_script = [$init]' \
    "$GV_DIR/app-compose.base.json" >"$GV_DIR/app-compose.json"
  local out vm_id
  out=$(vmm deploy --name "$VM_NAME" --image "${EGGOMI_DEV_IMAGE:-dstack-dev-0.6.0}" \
    --compose "$GV_DIR/app-compose.json" --vcpu "${EGGOMI_GVISOR_VCPU:-4}" \
    --memory "${EGGOMI_GVISOR_MEMORY:-6G}" --disk "${EGGOMI_GVISOR_DISK:-20G}" \
    --port "tcp:127.0.0.1:$SSH_PORT:22" --simulated-tee dstack-amd-sev-snp 2>&1) \
    || die "deploy failed: $out"
  vm_id=$(awk -F': ' '/^Created VM with ID: / {print $2}' <<<"$out" | tail -n1)
  [[ -n "$vm_id" ]] || die "could not parse the VM id: $out"
  printf '%s\n' "$vm_id" >"$GV_DIR/vm-id"
  log "deployed $vm_id"
}

gv_ssh() {
  ssh -q -i "$GV_DIR/lab_ssh_ed25519" -p "$SSH_PORT" -o BatchMode=yes \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
    root@127.0.0.1 "$@"
}

wait_ready() {
  need_env
  local vm_id deadline=$((SECONDS + ${1:-600})) info
  vm_id=$(cat "$GV_DIR/vm-id")
  while ((SECONDS < deadline)); do
    info=$(vmm info "$vm_id" --json 2>/dev/null || true)
    if [[ "$(jq -r '.status // ""' <<<"$info")" == running &&
      "$(jq -r '.boot_progress // ""' <<<"$info")" == "done" ]] && gv_ssh true 2>/dev/null; then
      log "CVM $vm_id booted; lab shell up"
      return
    fi
    sleep 5
  done
  die "CVM $vm_id did not become ready"
}

status() {
  need_env
  [[ -s "$GV_DIR/vm-id" ]] || { echo "no lab CVM"; return; }
  vmm info "$(cat "$GV_DIR/vm-id")" --json | jq '{id, name, status, boot_progress}'
  gv_ssh 'docker info -f "{{json .Runtimes}}"; docker ps --format "{{.Names}} {{.Status}}"' || true
}

remove() {
  need_env
  [[ -s "$GV_DIR/vm-id" ]] || return 0
  local vm_id
  vm_id=$(cat "$GV_DIR/vm-id")
  vmm stop -f "$vm_id" >/dev/null 2>&1 || true
  vmm remove "$vm_id"
  rm -f "$GV_DIR/vm-id"
}

case "${1:-}" in
  fetch) fetch ;;
  serve) serve ;;
  stop-serve) stop_serve ;;
  deploy) deploy ;;
  wait) wait_ready "${2:-600}" ;;
  ssh) shift; gv_ssh "$@" ;;
  status) status ;;
  remove) remove ;;
  *) die "usage: $0 fetch|serve|deploy|wait|ssh CMD|status|stop-serve|remove" ;;
esac
