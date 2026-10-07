# shellcheck shell=bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# Host side of the L1 gVisor suites (S3', S4'). Source this file after
# setting SUITE_TAG (s3 or s4). The suites run inside the lab CVM that
# gvisor-lab.sh deploys: this side gates on it, ships the harness into the
# CVM's tmpfs, runs test-suites/eggomi/gvisor/incvm-$SUITE_TAG.sh there as
# root, samples the CVM's QEMU RSS on the host meanwhile, and copies the
# metrics and report back.
#
# Environment:
#   EGGOMI_LAB_DIR / LAB     lab directory (default ~/lab/eggomi-snp)
#   EGGOMI_GVISOR_DIR        lab CVM state (default $LAB/gvisor)
#   EGGOMI_STATE_DIR         harness state (default test-suites/eggomi/.state)
#   EGGOMI_S3_SETTLE, EGGOMI_S3_TAB_MIB, EGGOMI_KEEP   passed to the CVM side

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
SUITE_DIR="$ROOT/test-suites/eggomi"
GV_SRC="$SUITE_DIR/gvisor"
SUBVM_DIR="$SUITE_DIR/subvm"
CAH_DIR="$ROOT/test-suites/cah"
LABCTL="$SUITE_DIR/scripts/gvisor-lab.sh"
LAB=${LAB:-${EGGOMI_LAB_DIR:-"$HOME/lab/eggomi-snp"}}
GV_DIR=${EGGOMI_GVISOR_DIR:-"$LAB/gvisor"}
STATE_DIR=${EGGOMI_STATE_DIR:-"$SUITE_DIR/.state"}
WORK_DIR="$STATE_DIR/work"
METRICS="$WORK_DIR/$SUITE_TAG-gvisor-metrics.prom"
REPORT="$WORK_DIR/$SUITE_TAG-gvisor-report.json"

log() {
  printf '[eggomi-%s-gvisor] %s\n' "$SUITE_TAG" "$*" >&2
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

# Exit 77 with a metrics file that says the suite did not run.
skip() {
  mkdir -p "$WORK_DIR"
  rm -f "$REPORT"
  printf '# Eggomi %s (gVisor) was gated before any sandbox ran.\neggomi_%s_available 0\n' \
    "$SUITE_TAG" "$SUITE_TAG" >"$METRICS"
  printf 'skip: %s\n' "$1" >&2
  exit 77
}

cvm() {
  "$LABCTL" ssh "$@"
}

gvisor_gate() {
  local tool
  for tool in ssh jq tar python3 awk; do
    command -v "$tool" >/dev/null 2>&1 || skip "missing required command: $tool"
  done
  [[ -s "$GV_DIR/vm-id" && -s "$GV_DIR/lab_ssh_ed25519" ]] \
    || skip "no gVisor lab CVM; run: gvisor-lab.sh fetch && gvisor-lab.sh serve && gvisor-lab.sh deploy && gvisor-lab.sh wait"
  cvm true 2>/dev/null || skip "the lab CVM's shell does not answer (gvisor-lab.sh status)"
  cvm "docker info -f '{{json .Runtimes}}' | jq -e .runsc >/dev/null" 2>/dev/null \
    || skip "dockerd in the lab CVM has no runsc runtime (init-gvisor.sh did not register it)"
}

# Build the role images in the CVM once; they need registry and distro access.
ensure_images() {
  local image file
  for image in py browser; do
    if cvm "docker image inspect eggomi-gv-$image:lab >/dev/null 2>&1"; then
      continue
    fi
    file="$GV_SRC/Dockerfile.$image"
    [[ $image == py ]] && file="$GV_SRC/Dockerfile.python"
    log "building eggomi-gv-$image:lab in the CVM (needs network once)"
    cvm "docker build -q -t eggomi-gv-$image:lab -" <"$file" >/dev/null \
      || skip "could not build eggomi-gv-$image:lab in the CVM"
  done
}

# The harness goes to the CVM's tmpfs: py/ is bind-mounted read-only into
# the sandboxes, sh/ runs as root in the CVM.
ship() {
  local stage
  stage=$(mktemp -d "$WORK_DIR/gv-ship.XXXXXX")
  mkdir -p "$stage/py" "$stage/sh"
  cp -r "$CAH_DIR/cah" "$stage/py/"
  cp "$SUBVM_DIR"/{kkrpc,session_material,keeper_svc,guard_svc,host_tools}.py "$stage/py/"
  cp "$GV_SRC"/{gv_guard,cdp,boundary_probe,gvctl}.py "$GV_SRC/browser-init.sh" "$stage/py/"
  cp "$GV_SRC"/incvm-*.sh "$stage/sh/"
  find "$stage" -name __pycache__ -prune -exec rm -rf {} +
  tar -C "$stage" -cf - py sh | cvm \
    'rm -rf /run/eggomi-gv/code && mkdir -p /run/eggomi-gv/code && tar -xf - -C /run/eggomi-gv/code && chmod -R a+rX /run/eggomi-gv/code'
  rm -rf "$stage"
}

# The CVM's QEMU process. The VMM's qemu.pid names its vm-launcher, whose
# child is QEMU.
qemu_pid() {
  local launcher
  launcher=$(cat "$1" 2>/dev/null || true)
  [[ -n "$launcher" ]] || return 0
  if [[ "$(cat "/proc/$launcher/comm" 2>/dev/null)" == qemu-system-x86 ]]; then
    printf '%s\n' "$launcher"
  else
    pgrep -P "$launcher" -f qemu-system | head -n1
  fi
}

# Sample the CVM's QEMU RSS on the host every half second until STOP exists.
qemu_sampler() {
  local pidfile=$1 out=$2 stop=$3 pid
  pid=$(qemu_pid "$pidfile")
  while [[ ! -e "$stop" ]]; do
    if [[ -n "$pid" && -r "/proc/$pid/status" ]]; then
      awk -v t="$(date +%s.%N)" '/^VmRSS:/ {printf "%s %d\n", t, $2 * 1024}' "/proc/$pid/status" >>"$out"
    fi
    sleep 0.5
  done
}

run_incvm() {
  mkdir -p "$WORK_DIR"
  rm -f "$METRICS" "$REPORT"
  gvisor_gate
  ensure_images
  ship
  local vm_id samples="$WORK_DIR/$SUITE_TAG-gvisor-qemu-rss.txt" stop="$WORK_DIR/$SUITE_TAG-gvisor-sampler.stop"
  vm_id=$(cat "$GV_DIR/vm-id")
  rm -f "$samples" "$stop"
  qemu_sampler "$LAB/vmm/vm/$vm_id/qemu.pid" "$samples" "$stop" &
  local sampler=$! rc=0
  # shellcheck disable=SC2064 # expand now: these locals are gone at exit
  trap "touch '$stop'; kill $sampler 2>/dev/null || true; rm -f '$stop'" EXIT
  trap 'exit 130' INT TERM
  cvm "env EGGOMI_S3_SETTLE=${EGGOMI_S3_SETTLE:-30} EGGOMI_S3_TAB_MIB=${EGGOMI_S3_TAB_MIB:-256} \
    EGGOMI_KEEP=${EGGOMI_KEEP:-0} bash /run/eggomi-gv/code/sh/incvm-$SUITE_TAG.sh" || rc=$?
  touch "$stop"
  wait "$sampler" || true
  rm -f "$stop"
  if ((rc == 77)); then
    cvm "cat /run/eggomi-gv/out/$SUITE_TAG-gvisor-metrics.prom" >"$METRICS" 2>/dev/null || true
    exit 77
  fi
  cvm "cat /run/eggomi-gv/out/$SUITE_TAG-gvisor-metrics.prom" >"$METRICS" \
    || die "the CVM side wrote no metrics (exit $rc)"
  cvm "cat /run/eggomi-gv/out/$SUITE_TAG-gvisor-report.json" >"$REPORT" 2>/dev/null || true
  if [[ -s "$samples" ]]; then
    awk -v tag="$SUITE_TAG" 'NR == 1 {first = $2} {if ($2 > max) max = $2; last = $2}
      END {printf "eggomi_%s_cvm_qemu_rss_bytes{phase=\"run_start\"} %d\n", tag, first
           printf "eggomi_%s_cvm_qemu_rss_bytes{phase=\"run_peak\"} %d\n", tag, max
           printf "eggomi_%s_cvm_qemu_rss_bytes{phase=\"run_end\"} %d\n", tag, last}' \
      "$samples" >>"$METRICS"
  fi
  log "metrics: $METRICS"
  [[ -s "$REPORT" ]] && log "report: $REPORT"
  return "$rc"
}
