#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
SUITE_DIR="$ROOT/test-suites/eggomi"
STATE_DIR=${EGGOMI_STATE_DIR:-"$SUITE_DIR/.state"}
WORK_DIR="$STATE_DIR/work"
VM_DIR=${EGGOMI_VM_DIR:-"$HOME/.dstack-vmm/vm"}
DEV_IMAGE=${EGGOMI_DEV_IMAGE:-}
VMM_URL=${DSTACK_VMM_URL:-}
VMM_CLI_PATH=${DSTACK_VMM_CLI:-"$ROOT/dstack/vmm/src/vmm-cli.py"}
APP_PORT=${EGGOMI_APP_PORT:-18089}
BOOT_TIMEOUT=${EGGOMI_BOOT_TIMEOUT:-720}
RUN_S6=${EGGOMI_RUN_S6:-auto}
METRICS="$WORK_DIR/s0-metrics.prom"
MOCK_CONFIG="$STATE_DIR/mock-roots/tee-simulator.json"
VMM_CLI=(python3 "$VMM_CLI_PATH")
[[ -n "$VMM_URL" ]] && VMM_CLI+=(--url "$VMM_URL")
COLLATERAL_PID=""

log() {
  printf '[eggomi-s0] %s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

skip() {
  local reason=$1
  mkdir -p "$WORK_DIR"
  cat >"$METRICS" <<EOF
# Eggomi S0 was gated before VM launch.
eggomi_s0_available 0
eggomi_s0_boot_seconds NaN
eggomi_s0_qemu_rss_bytes NaN
eggomi_s0_guest_mem_available_bytes NaN
eggomi_s0_vm_disk_bytes NaN
EOF
  printf 'skip: %s\n' "$reason" >&2
  printf 'metrics: %s\n' "$METRICS" >&2
  exit 77
}

need_bin() {
  command -v "$1" >/dev/null 2>&1 || skip "missing required command: $1"
}

cleanup() {
  if [[ -n "$COLLATERAL_PID" ]] && kill -0 "$COLLATERAL_PID" 2>/dev/null; then
    kill "$COLLATERAL_PID" 2>/dev/null || true
    wait "$COLLATERAL_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

wait_for_collateral() {
  local deadline=$((SECONDS + 30))
  while ((SECONDS < deadline)); do
    if curl -fsS "http://127.0.0.1:${EGGOMI_COLLATERAL_PORT:-18088}/vcek/v1/Milan/cert_chain" \
      >/dev/null 2>&1; then
      return
    fi
    kill -0 "$COLLATERAL_PID" 2>/dev/null \
      || die "mock collateral server exited; see $WORK_DIR/mock-collateral.log"
    sleep 1
  done
  die "mock collateral server did not become ready"
}

wait_for_boot() {
  local vm_id=$1 deadline=$((SECONDS + BOOT_TIMEOUT)) last=""
  while ((SECONDS < deadline)); do
    local info status progress error current
    info=$("${VMM_CLI[@]}" info "$vm_id" --json 2>/dev/null || true)
    if [[ -n "$info" ]]; then
      status=$(jq -r '.status // ""' <<<"$info")
      progress=$(jq -r '.boot_progress // ""' <<<"$info")
      error=$(jq -r '.boot_error // ""' <<<"$info")
      current="status=$status progress=${progress:-none} error=${error:-none}"
      if [[ "$current" != "$last" ]]; then
        log "$current"
        last=$current
      fi
      if [[ -n "$error" && "$error" != null ]]; then
        "${VMM_CLI[@]}" logs "$vm_id" -n 300 >&2 || true
        die "vm boot failed: $error"
      fi
      if [[ "$status" == running && "$progress" == "done" ]]; then
        printf '%s\n' "$info" >"$WORK_DIR/vm-info.json"
        return
      fi
      if [[ "$status" == stopped || "$status" == exited ]]; then
        "${VMM_CLI[@]}" logs "$vm_id" -n 300 >&2 || true
        die "vm stopped before boot completed"
      fi
    fi
    sleep 5
  done
  "${VMM_CLI[@]}" logs "$vm_id" -n 300 >&2 || true
  die "timed out waiting for boot_progress=done"
}

wait_for_probe() {
  local deadline=$((SECONDS + 120))
  while ((SECONDS < deadline)); do
    if curl -fsS "http://127.0.0.1:${APP_PORT}/" -o "$WORK_DIR/probe-before.txt"; then
      grep -Eq '^marker_id=[0-9a-f-]+$' "$WORK_DIR/probe-before.txt" \
        || die "persistence probe returned no marker id"
      grep -Eq '^boot_count=1$' "$WORK_DIR/probe-before.txt" \
        || die "persistence probe did not report its first boot"
      return
    fi
    sleep 2
  done
  die "persistence probe did not become reachable on host port $APP_PORT"
}

assert_snp_launch_shape() {
  local vm_id=$1
  local vm_work="$VM_DIR/$vm_id"
  local manifest="$vm_work/vm-manifest.json"
  local simulator="$vm_work/shared/.tee-simulator.json"
  local sys_config="$vm_work/shared/.sys-config.json"

  [[ -s "$manifest" ]] || die "missing VM manifest at $manifest; set EGGOMI_VM_DIR"
  [[ -s "$simulator" ]] || die "missing simulator config at $simulator"
  [[ -s "$sys_config" ]] || die "missing system config at $sys_config"

  jq -e '.simulated_tee == "dstack-amd-sev-snp" and .no_tee == true and .swtpm == true' \
    "$manifest" >/dev/null \
    || die "vm manifest is not a simulated SNP deployment with swtpm"
  if ! jq -e '.platform == "dstack-amd-sev-snp"
    and (.mock_attestation_seed | test("^[0-9a-fA-F]{64}$"))
    and ((.mr_config | fromjson | .version) == 3)
    and ((.vm_config | fromjson | .mr_config | fromjson | .version) == 3)
    and ((.vm_config | fromjson | .sev_snp_measurement) | length > 0)' \
    "$simulator" >/dev/null; then
    die "simulator handoff is missing the SNP measurement or MrConfigV3 binding; the dev image must include measurement.snp.cbor"
  fi
  jq -e --slurpfile expected "$MOCK_CONFIG" \
    '.mock_attestation_seed == $expected[0].mock_attestation_seed' "$simulator" >/dev/null \
    || die "simulator seed does not match the job mock-collateral seed"
  jq -e 'has("tee_simulator") | not' "$sys_config" >/dev/null \
    || die "sys-config contains a host-selected trust anchor"

  [[ -s "$vm_work/hda.img" ]] || die "missing persistent VM disk"
  [[ -s "$vm_work/swtpm/tpm2-00.permall" ]] || die "missing persistent swtpm state"
}

write_metrics() {
  local vm_id=$1 boot_seconds=$2
  local vm_work="$VM_DIR/$vm_id"
  local rss_kib disk_bytes
  rss_kib=$(ps -eo rss=,args= | awk -v id="$vm_id" \
    '$0 ~ /qemu-system/ && index($0, id) {sum += $1} END {print sum + 0}')
  # disk_prealloc=off leaves a sparse qcow2. `du -b` is --apparent-size and
  # would record the virtual size. -B1 without --apparent-size is allocated bytes.
  disk_bytes=$(du -s -B1 "$vm_work" 2>/dev/null | awk '{print $1}' || true)
  [[ -n "$disk_bytes" ]] || disk_bytes=NaN
  cat >"$METRICS" <<EOF
# Eggomi S0 outer-CVM smoke metrics.
eggomi_s0_available 1
eggomi_s0_boot_seconds $boot_seconds
eggomi_s0_qemu_rss_bytes $((rss_kib * 1024))
# Guest MemAvailable collection requires a guest metrics endpoint in a later milestone.
eggomi_s0_guest_mem_available_bytes NaN
# Allocated host bytes. Sparse virtual size is not counted.
eggomi_s0_vm_disk_bytes $disk_bytes
EOF
}

run_prod_root_e2e() {
  if [[ "$RUN_S6" == false ]]; then
    log "s6 container check disabled by EGGOMI_RUN_S6=false"
    return
  fi
  if [[ "$RUN_S6" == auto ]] && ! command -v docker >/dev/null 2>&1; then
    log "s6 container check skipped; docker is not installed"
    return
  fi
  set +e
  "$SUITE_DIR/scripts/s6-faults.sh" prod-root-reject
  local rc=$?
  set -e
  if ((rc == 77)); then
    if [[ "$RUN_S6" == true ]]; then
      die "s6 production-root container check was skipped"
    fi
    log "s6 container check skipped"
    return
  fi
  if ((rc != 0)); then
    die "s6 production-root rejection failed"
  fi
}

main() {
  mkdir -p "$WORK_DIR"
  need_bin jq
  need_bin curl
  need_bin python3
  [[ -r /dev/kvm && -w /dev/kvm ]] \
    || skip "/dev/kvm is not readable and writable; enable KVM or nested virtualization"
  [[ -n "$DEV_IMAGE" ]] || skip "set EGGOMI_DEV_IMAGE to an installed dstack development image"
  need_bin qemu-system-x86_64
  need_bin swtpm
  [[ -f "$VMM_CLI_PATH" ]] || skip "missing VMM CLI: $VMM_CLI_PATH"
  [[ -s "$MOCK_CONFIG" ]] \
    || skip "run '$SUITE_DIR/scripts/mock-collateral.sh generate', merge the emitted VMM config, and restart dstack-vmm"

  local images
  images=$("${VMM_CLI[@]}" lsimage --json 2>/dev/null) \
    || skip "dstack-vmm is unavailable; start it with the generated tee-simulator configuration"
  jq -e --arg image "$DEV_IMAGE" \
    '.[] | select(.name == $image and .is_dev == true)' <<<"$images" >/dev/null \
    || skip "image '$DEV_IMAGE' is absent or is_dev is not true"

  if [[ "${1:-}" == --preflight ]]; then
    log "preflight passed"
    return
  fi

  "$SUITE_DIR/scripts/mock-collateral.sh" serve >"$WORK_DIR/mock-collateral.log" 2>&1 &
  COLLATERAL_PID=$!
  wait_for_collateral
  run_prod_root_e2e

  "${VMM_CLI[@]}" compose \
    --name eggomi-snp-sim \
    --docker-compose "$SUITE_DIR/docker-compose.yml" \
    --key-provider tpm \
    --public-logs \
    --public-sysinfo \
    --output "$WORK_DIR/app-compose.json"

  local start_seconds output vm_id boot_seconds deploy_rc
  start_seconds=$SECONDS
  set +e
  output=$("${VMM_CLI[@]}" deploy \
    --name "eggomi-snp-sim-${USER:-ci}" \
    --image "$DEV_IMAGE" \
    --compose "$WORK_DIR/app-compose.json" \
    --vcpu "${EGGOMI_VCPU:-2}" \
    --memory "${EGGOMI_MEMORY:-3G}" \
    --disk "${EGGOMI_DISK:-10G}" \
    --port "tcp:127.0.0.1:${APP_PORT}:8080" \
    --simulated-tee dstack-amd-sev-snp 2>&1)
  deploy_rc=$?
  set -e
  printf '%s\n' "$output" | tee "$WORK_DIR/deploy.log"
  if ((deploy_rc != 0)); then
    if grep -q 'Port mapping is disabled' <<<"$output"; then
      die "port mapping is disabled; set [cvm.port_mapping] enabled = true in vmm.toml and restart dstack-vmm"
    fi
    die "deploy failed"
  fi
  vm_id=$(awk -F': ' '/^Created VM with ID: / {print $2}' <<<"$output" | tail -n1)
  [[ -n "$vm_id" ]] || die "could not parse deployed VM id"
  printf '%s\n' "$vm_id" >"$WORK_DIR/vm-id"

  wait_for_boot "$vm_id"
  boot_seconds=$((SECONDS - start_seconds))
  assert_snp_launch_shape "$vm_id"
  wait_for_probe
  write_metrics "$vm_id" "$boot_seconds"

  cat >"$STATE_DIR/last-run.env" <<EOF
EGGOMI_VM_ID=$vm_id
EGGOMI_APP_PORT=$APP_PORT
EGGOMI_VM_DIR=$VM_DIR
EOF
  log "s0 passed for VM $vm_id in ${boot_seconds}s"
  log "metrics: $METRICS"
  log "leave this VM running, then run scripts/s1-persistence.sh"
}

main "$@"
