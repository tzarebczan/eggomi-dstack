#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

# S2: the lab snp-sim-kms as a long-running process that a simulated-SNP CVM
# calls. Four cases, each against evidence the guest agent produced:
#   gate-off      release refused while the SNP release gate is closed;
#   release       release succeeds for the enrolled MEASUREMENT and the
#                 caller's nonce, and the signed record verifies under the
#                 KMS's attested root key;
#   mismatch      release refused for a report_data mismatch (and a replayed
#                 quote under a new nonce) and for a MEASUREMENT mismatch;
#   prod-roots    the evidence the release was decided on is refused by the
#                 production AMD roots.
# Throwaway mock roots only. Never point this at production collateral.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
SUITE_DIR="$ROOT/test-suites/eggomi"
STATE_DIR=${EGGOMI_STATE_DIR:-"$SUITE_DIR/.state"}
WORK_DIR="$STATE_DIR/work/s2"
VM_DIR=${EGGOMI_VM_DIR:-"$HOME/.dstack-vmm/vm"}
DEV_IMAGE=${EGGOMI_DEV_IMAGE:-}
VMM_URL=${DSTACK_VMM_URL:-}
VMM_CLI_PATH=${DSTACK_VMM_CLI:-"$ROOT/dstack/vmm/src/vmm-cli.py"}
TARGET_DIR=${CARGO_TARGET_DIR:-"$ROOT/dstack/target"}
KMS_BIN=${SNP_SIM_KMS_BIN:-"$TARGET_DIR/release/snp-sim-kms"}
KMS_PORT=${EGGOMI_KMS_PORT:-18101}
CLIENT_PORT=${EGGOMI_S2_PORT:-18091}
COLLATERAL_PORT=${EGGOMI_COLLATERAL_PORT:-18088}
KDS_URL="http://127.0.0.1:${COLLATERAL_PORT}/vcek/v1"
KMS_URL="http://127.0.0.1:${KMS_PORT}"
CLIENT_URL="http://127.0.0.1:${CLIENT_PORT}"
BOOT_TIMEOUT=${EGGOMI_BOOT_TIMEOUT:-720}
KEEP_VM=${EGGOMI_S2_KEEP_VM:-false}
APP_ID=$(printf 'eggomi-s2-app' | od -An -tx1 | tr -d ' \n')
MOCK_CONFIG="$STATE_DIR/mock-roots/tee-simulator.json"
VMM_CLI=(python3 "$VMM_CLI_PATH")
[[ -n "$VMM_URL" ]] && VMM_CLI+=(--url "$VMM_URL")
COLLATERAL_PID=""
KMS_PID=""
VM_ID=""
CREATED_VM=false

log() {
  printf '[eggomi-s2] %s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

skip() {
  printf 'skip: %s\n' "$*" >&2
  exit 77
}

need_bin() {
  command -v "$1" >/dev/null 2>&1 || skip "missing required command: $1"
}

stop_kms() {
  if [[ -n "$KMS_PID" ]] && kill -0 "$KMS_PID" 2>/dev/null; then
    kill "$KMS_PID" 2>/dev/null || true
    wait "$KMS_PID" 2>/dev/null || true
  fi
  KMS_PID=""
}

cleanup() {
  stop_kms
  if [[ -n "$COLLATERAL_PID" ]] && kill -0 "$COLLATERAL_PID" 2>/dev/null; then
    kill "$COLLATERAL_PID" 2>/dev/null || true
    wait "$COLLATERAL_PID" 2>/dev/null || true
  fi
  if [[ "$CREATED_VM" == true && "$KEEP_VM" != true && -n "$VM_ID" ]]; then
    "${VMM_CLI[@]}" remove "$VM_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

nonce() {
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

ensure_collateral() {
  if curl -fsS --max-time 5 "http://127.0.0.1:${COLLATERAL_PORT}/vcek/v1/Milan/cert_chain" >/dev/null 2>&1; then
    log "reusing the mock collateral server on port $COLLATERAL_PORT"
    return
  fi
  EGGOMI_COLLATERAL_PORT=$COLLATERAL_PORT "$SUITE_DIR/scripts/mock-collateral.sh" serve \
    >"$WORK_DIR/mock-collateral.log" 2>&1 &
  COLLATERAL_PID=$!
  local deadline=$((SECONDS + 30))
  until curl -fsS --max-time 5 "http://127.0.0.1:${COLLATERAL_PORT}/vcek/v1/Milan/cert_chain" >/dev/null 2>&1; do
    kill -0 "$COLLATERAL_PID" 2>/dev/null || die "mock collateral server exited; see $WORK_DIR/mock-collateral.log"
    ((SECONDS < deadline)) || die "mock collateral server did not become ready"
    sleep 1
  done
}

# start_kms LABEL [snp-sim-kms serve flags...]
start_kms() {
  local label=$1
  shift
  stop_kms
  # S2 needs its own KMS instances (gate off, gate on, wrong measurement). A
  # standing lab KMS on the same port would answer the readiness probe while
  # our child fails to bind.
  if curl -fsS --max-time 5 "$KMS_URL/health" >/dev/null 2>&1; then
    die "port $KMS_PORT already serves a KMS; stop it (l1-lab.sh stop-kms) or set EGGOMI_KMS_PORT"
  fi
  "$KMS_BIN" serve \
    --listen "127.0.0.1:${KMS_PORT}" \
    --mock-config "$MOCK_CONFIG" \
    --kds-url "$KDS_URL" \
    "$@" >"$WORK_DIR/kms-$label.log" 2>&1 &
  KMS_PID=$!
  local deadline=$((SECONDS + 30))
  until curl -fsS --max-time 5 "$KMS_URL/health" -o "$WORK_DIR/kms-$label-health.json" 2>/dev/null; do
    kill -0 "$KMS_PID" 2>/dev/null || die "snp-sim-kms exited; see $WORK_DIR/kms-$label.log"
    ((SECONDS < deadline)) || die "snp-sim-kms did not become ready"
    sleep 0.5
  done
  kill -0 "$KMS_PID" 2>/dev/null || die "snp-sim-kms exited; see $WORK_DIR/kms-$label.log"
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
      [[ "$current" != "$last" ]] && log "$current"
      last=$current
      [[ -z "$error" || "$error" == null ]] || die "vm boot failed: $error"
      [[ "$status" == running && "$progress" == "done" ]] && return
      [[ "$status" != stopped && "$status" != exited ]] || die "vm stopped before boot completed"
    fi
    sleep 5
  done
  die "timed out waiting for boot_progress=done"
}

# request NAME QUERY: ask the guest client for one release; writes NAME.json.
request() {
  local name=$1 query=$2
  curl -fsS --max-time 120 "$CLIENT_URL/release?$query" -o "$WORK_DIR/$name.json" \
    || die "guest client request '$name' failed"
  jq -e '.attestation | length > 0' "$WORK_DIR/$name.json" >/dev/null \
    || die "guest client returned no attestation for '$name'"
}

# expect_refused NAME PATTERN
expect_refused() {
  local name=$1 pattern=$2
  jq -e '.kms_status == 403 and .kms.refused == true' "$WORK_DIR/$name.json" >/dev/null \
    || die "case '$name' was not refused: $(jq -c '{kms_status, kms}' "$WORK_DIR/$name.json")"
  jq -e --arg p "$pattern" '.kms.error | test($p)' "$WORK_DIR/$name.json" >/dev/null \
    || die "case '$name' refused for another reason: $(jq -r '.kms.error' "$WORK_DIR/$name.json")"
  log "$name: refused ($(jq -r '.kms.error' "$WORK_DIR/$name.json" | head -c 160))"
}

deploy_vm() {
  sed "s|http://10.0.2.2:18101|http://10.0.2.2:${KMS_PORT}|" "$SUITE_DIR/s2-compose.yml" \
    >"$WORK_DIR/s2-compose.yml"
  "${VMM_CLI[@]}" compose \
    --name eggomi-s2-kms \
    --docker-compose "$WORK_DIR/s2-compose.yml" \
    --key-provider tpm \
    --public-logs \
    --public-sysinfo \
    --output "$WORK_DIR/app-compose.json" >/dev/null
  local output
  output=$("${VMM_CLI[@]}" deploy \
    --name "eggomi-s2-kms-${USER:-ci}" \
    --image "$DEV_IMAGE" \
    --compose "$WORK_DIR/app-compose.json" \
    --vcpu "${EGGOMI_VCPU:-2}" \
    --memory "${EGGOMI_MEMORY:-3G}" \
    --disk "${EGGOMI_DISK:-10G}" \
    --port "tcp:127.0.0.1:${CLIENT_PORT}:8080" \
    --simulated-tee dstack-amd-sev-snp 2>&1) || die "deploy failed: $output"
  VM_ID=$(awk -F': ' '/^Created VM with ID: / {print $2}' <<<"$output" | tail -n1)
  [[ -n "$VM_ID" ]] || die "could not parse deployed VM id"
  CREATED_VM=true
  printf '%s\n' "$VM_ID" >"$WORK_DIR/vm-id"
  log "deployed S2 VM $VM_ID"
}

main() {
  mkdir -p "$WORK_DIR"
  need_bin jq
  need_bin curl
  need_bin python3
  [[ -r /dev/kvm && -w /dev/kvm ]] || skip "/dev/kvm is not readable and writable"
  [[ -n "$DEV_IMAGE" || -n "${EGGOMI_S2_VM_ID:-}" ]] \
    || skip "set EGGOMI_DEV_IMAGE to an installed dstack development image"
  [[ -x "$KMS_BIN" ]] \
    || skip "missing snp-sim-kms; build it with: cargo build --manifest-path dstack/Cargo.toml --release -p snp-sim-kms"
  [[ -s "$MOCK_CONFIG" ]] || skip "run '$SUITE_DIR/scripts/mock-collateral.sh generate' first"
  "${VMM_CLI[@]}" lsvm --json >/dev/null 2>&1 || skip "dstack-vmm is unavailable"

  if curl -fsS --max-time 5 "$KMS_URL/health" >/dev/null 2>&1; then
    die "port $KMS_PORT already serves a KMS; stop it (l1-lab.sh stop-kms) or set EGGOMI_KMS_PORT"
  fi
  ensure_collateral
  local started=$SECONDS
  if [[ -n "${EGGOMI_S2_VM_ID:-}" ]]; then
    VM_ID=$EGGOMI_S2_VM_ID
    log "reusing S2 VM $VM_ID"
  else
    deploy_vm
  fi
  wait_for_boot "$VM_ID"
  local deadline=$((SECONDS + 300))
  until curl -fsS --max-time 5 "$CLIENT_URL/health" >/dev/null 2>&1; do
    ((SECONDS < deadline)) || die "guest client did not become reachable on port $CLIENT_PORT"
    sleep 3
  done
  log "guest client ready after $((SECONDS - started))s"

  local simulator="$VM_DIR/$VM_ID/shared/.tee-simulator.json" measurement wrong
  [[ -s "$simulator" ]] || die "missing $simulator; set EGGOMI_VM_DIR"
  jq -e '.platform == "dstack-amd-sev-snp"' "$simulator" >/dev/null \
    || die "S2 VM is not a simulated SNP deployment"
  measurement=$("$KMS_BIN" measurement --vm-config "$simulator")
  log "enrolled MEASUREMENT $measurement (recomputed from the VM's vm_config)"

  # Case 1: the release gate is closed.
  start_kms gate-off --enroll-vm-config "$simulator"
  jq -e '.release_enabled == false' "$WORK_DIR/kms-gate-off-health.json" >/dev/null
  request gate-off "app_id=$APP_ID&nonce=$(nonce)"
  expect_refused gate-off 'release is not enabled'

  # Case 2: the gate is open, and the quote matches MEASUREMENT and report_data.
  start_kms release --enroll-vm-config "$simulator" --release-enabled
  curl -fsS --max-time 30 "$KMS_URL/v1/bootstrap" -o "$WORK_DIR/bootstrap.json"
  local release_nonce
  release_nonce=$(nonce)
  request release "app_id=$APP_ID&nonce=$release_nonce"
  jq -e '.kms_status == 200' "$WORK_DIR/release.json" >/dev/null \
    || die "matching release was refused: $(jq -c '.kms' "$WORK_DIR/release.json")"
  jq '.kms' "$WORK_DIR/release.json" >"$WORK_DIR/signed-release.json"
  jq -r '.attestation' "$WORK_DIR/release.json" >"$WORK_DIR/release-attestation.hex"
  local expected_rd
  expected_rd=$(curl -fsS --max-time 30 "$KMS_URL/v1/report-data?app_id=$APP_ID&nonce=$release_nonce" | jq -r '.report_data')
  jq -e --arg rd "$expected_rd" '.report_data == $rd' "$WORK_DIR/release.json" >/dev/null \
    || die "guest client and KMS disagree on report_data"
  jq -e '(.measurement | length) == 48 and .simulated == true and .production_accepted == false' \
    "$WORK_DIR/signed-release.json" >/dev/null || die "release record has the wrong shape"
  "$KMS_BIN" verify-release \
    --mock-config "$MOCK_CONFIG" \
    --bootstrap "$WORK_DIR/bootstrap.json" \
    --release "$WORK_DIR/signed-release.json" \
    --measurement "$measurement" \
    --app-id "$APP_ID" \
    --nonce "$release_nonce" | tee "$WORK_DIR/verify-release.json"
  log "release: signed release verified under the attested KMS root"

  # Case 3: mismatches. A replayed quote under a fresh nonce, a quote over
  # another nonce, and a KMS enrolled to another MEASUREMENT.
  jq -n --arg app "$APP_ID" --arg nonce "$(nonce)" --rawfile att "$WORK_DIR/release-attestation.hex" \
    '{app_id: $app, nonce: $nonce, attestation: ($att | rtrimstr("\n"))}' >"$WORK_DIR/replay-request.json"
  local replay_status
  replay_status=$(curl -sS --max-time 120 -o "$WORK_DIR/replay-kms.json" -w '%{http_code}' \
    -H 'Content-Type: application/json' --data @"$WORK_DIR/replay-request.json" "$KMS_URL/v1/release")
  jq -n --argjson status "$replay_status" --slurpfile kms "$WORK_DIR/replay-kms.json" \
    '{kms_status: $status, kms: $kms[0], attestation: "recorded"}' >"$WORK_DIR/replay.json"
  expect_refused replay 'report_data mismatch'
  request mismatch-report-data "app_id=$APP_ID&nonce=$(nonce)&quote_nonce=$(nonce)"
  expect_refused mismatch-report-data 'report_data mismatch'
  wrong=$(python3 -c 'import sys; m = bytearray.fromhex(sys.argv[1]); m[0] ^= 1; print(m.hex())' "$measurement")
  start_kms mismatch-measurement --measurement "$wrong" --release-enabled
  request mismatch-measurement "app_id=$APP_ID&nonce=$(nonce)"
  expect_refused mismatch-measurement 'measurement mismatch'
  stop_kms

  # Case 4: production AMD roots refuse the evidence the release used.
  "$KMS_BIN" production-gate \
    --mock-config "$MOCK_CONFIG" \
    --attestation "$WORK_DIR/release-attestation.hex" \
    --report-data "$expected_rd" \
    --kds-url "$KDS_URL" | tee "$WORK_DIR/production-gate.json"
  jq -e '.development_root_accepted == true and .production_root_rejected == true
    and .production_gate_refused == true' "$WORK_DIR/production-gate.json" >/dev/null \
    || die "production roots did not refuse the simulated evidence"
  log "prod-roots: production AMD roots refused the release evidence"

  cat >"$WORK_DIR/s2-metrics.prom" <<EOF
# Eggomi S2 lab KMS release gate, driven from a simulated-SNP CVM.
eggomi_s2_gate_off_refused 1
eggomi_s2_release_ok 1
eggomi_s2_release_signature_verified 1
eggomi_s2_replay_refused 1
eggomi_s2_report_data_mismatch_refused 1
eggomi_s2_measurement_mismatch_refused 1
eggomi_s2_production_root_rejected 1
eggomi_s2_seconds $((SECONDS - started))
EOF
  log "s2 passed for VM $VM_ID; artifacts in $WORK_DIR"
}

main "$@"
