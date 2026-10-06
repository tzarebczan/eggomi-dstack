#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
SUITE_DIR="$ROOT/test-suites/eggomi"
STATE_DIR=${EGGOMI_STATE_DIR:-"$SUITE_DIR/.state"}
WORK_DIR="$STATE_DIR/work"
VMM_CLI_PATH=${DSTACK_VMM_CLI:-"$ROOT/dstack/vmm/src/vmm-cli.py"}
VMM_URL=${DSTACK_VMM_URL:-}
VMM_CLI=(python3 "$VMM_CLI_PATH")
[[ -n "$VMM_URL" ]] && VMM_CLI+=(--url "$VMM_URL")
COLLATERAL_PID=""

log() {
  printf '[eggomi-s1] %s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$COLLATERAL_PID" ]] && kill -0 "$COLLATERAL_PID" 2>/dev/null; then
    kill "$COLLATERAL_PID" 2>/dev/null || true
    wait "$COLLATERAL_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

wait_for_status() {
  local vm_id=$1 wanted=$2 timeout=$3 deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    local info status progress error
    info=$("${VMM_CLI[@]}" info "$vm_id" --json 2>/dev/null || true)
    if [[ -n "$info" ]]; then
      status=$(jq -r '.status // ""' <<<"$info")
      progress=$(jq -r '.boot_progress // ""' <<<"$info")
      error=$(jq -r '.boot_error // ""' <<<"$info")
      if [[ -n "$error" && "$error" != null ]]; then
        die "vm restart failed: $error"
      fi
      if [[ "$wanted" == stopped && ( "$status" == stopped || "$status" == exited ) ]]; then
        return
      fi
      if [[ "$wanted" == running && "$status" == running && "$progress" == done ]]; then
        printf '%s\n' "$info" >"$WORK_DIR/vm-info-after-restart.json"
        return
      fi
    fi
    sleep 3
  done
  die "timed out waiting for VM state $wanted"
}

wait_for_probe_change() {
  local port=$1 marker_before=$2 count_before=$3 deadline=$((SECONDS + 120))
  while ((SECONDS < deadline)); do
    if curl -fsS "http://127.0.0.1:${port}/" -o "$WORK_DIR/probe-after.txt" 2>/dev/null; then
      local marker_after count_after
      marker_after=$(awk -F= '$1 == "marker_id" {print $2}' "$WORK_DIR/probe-after.txt")
      count_after=$(awk -F= '$1 == "boot_count" {print $2}' "$WORK_DIR/probe-after.txt")
      [[ "$marker_after" == "$marker_before" ]] \
        || die "persistent marker changed across restart"
      [[ "$count_after" =~ ^[0-9]+$ && "$count_after" -gt "$count_before" ]] \
        || die "persistent boot counter did not advance"
      return
    fi
    sleep 2
  done
  die "persistence probe did not return after restart"
}

main() {
  [[ -s "$STATE_DIR/last-run.env" ]] \
    || die "missing S0 state; run scripts/s0-sim-smoke.sh first"
  # shellcheck disable=SC1091
  source "$STATE_DIR/last-run.env"
  local vm_id=${1:-$EGGOMI_VM_ID}
  local app_port=${EGGOMI_APP_PORT:-18089}
  local vm_dir=${EGGOMI_VM_DIR:-"$HOME/.dstack-vmm/vm"}
  local vm_work="$vm_dir/$vm_id"
  local marker_before count_before instance_before instance_after restart_start restart_seconds

  [[ -s "$WORK_DIR/probe-before.txt" ]] || die "missing S0 persistence probe output"
  [[ -s "$vm_work/hda.img" ]] || die "missing persistent VM disk"
  [[ -s "$vm_work/swtpm/tpm2-00.permall" ]] || die "missing swtpm state"
  marker_before=$(awk -F= '$1 == "marker_id" {print $2}' "$WORK_DIR/probe-before.txt")
  count_before=$(awk -F= '$1 == "boot_count" {print $2}' "$WORK_DIR/probe-before.txt")
  instance_before=$("${VMM_CLI[@]}" info "$vm_id" --json | jq -er '.instance_id')

  "$SUITE_DIR/scripts/mock-collateral.sh" serve >"$WORK_DIR/mock-collateral-s1.log" 2>&1 &
  COLLATERAL_PID=$!
  sleep 1
  kill -0 "$COLLATERAL_PID" 2>/dev/null \
    || die "mock collateral server exited; see $WORK_DIR/mock-collateral-s1.log"

  restart_start=$SECONDS
  "${VMM_CLI[@]}" stop "$vm_id"
  wait_for_status "$vm_id" stopped 180
  "${VMM_CLI[@]}" start "$vm_id"
  wait_for_status "$vm_id" running "${EGGOMI_BOOT_TIMEOUT:-720}"
  restart_seconds=$((SECONDS - restart_start))

  instance_after=$(jq -er '.instance_id' "$WORK_DIR/vm-info-after-restart.json")
  [[ "$instance_after" == "$instance_before" ]] \
    || die "instance id changed across stop/start"
  [[ -s "$vm_work/hda.img" ]] || die "persistent VM disk disappeared"
  [[ -s "$vm_work/swtpm/tpm2-00.permall" ]] || die "swtpm state disappeared"
  wait_for_probe_change "$app_port" "$marker_before" "$count_before"

  cat >>"$WORK_DIR/s0-metrics.prom" <<EOF
# Eggomi S1 graceful stop/start timing.
eggomi_s1_restart_seconds $restart_seconds
eggomi_s1_persistence_ok 1
EOF
  log "s1 passed for VM $vm_id; marker, instance id, disk, and swtpm state persisted"
}

main "$@"
