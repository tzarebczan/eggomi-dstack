#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

# Control an L1 simulated-SNP lab: one dstack-vmm, the mock collateral
# server, and the lab snp-sim-kms, all under one lab directory. See
# docs/eggomi/l1-lab-runbook.md. Lab only: throwaway mock roots, no KMS
# key ever reaches a production service.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
LAB=${EGGOMI_LAB_DIR:-"$HOME/lab/eggomi-snp"}
VMM_DIR="$LAB/vmm"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

pid_alive() {
  [[ -s $1 ]] && kill -0 "$(cat "$1")" 2>/dev/null
}

load_env() {
  [[ -s "$LAB/env.sh" ]] || die "missing $LAB/env.sh; run '$0 init' first"
  # shellcheck disable=SC1091
  . "$LAB/env.sh"
}

# init: write env.sh and vmm.toml. Ports, CIDs, and paths are overridable so
# a second lab on the same host does not collide with the first.
init() {
  local port_base=${EGGOMI_LAB_PORT_BASE:-19100}
  local service_base=${EGGOMI_LAB_SERVICE_PORT_BASE:-18100}
  local cid_start=${EGGOMI_LAB_CID_START:-2000}
  local host_api_port=${EGGOMI_LAB_HOST_API_PORT:-10100}
  local image=${EGGOMI_DEV_IMAGE:-dstack-dev-0.6.0}
  local target=${CARGO_TARGET_DIR:-"$LAB/target"}
  mkdir -p "$LAB/logs" "$LAB/image" "$LAB/state" "$VMM_DIR/run" "$VMM_DIR/vm"
  [[ ! -e "$LAB/env.sh" ]] || die "$LAB/env.sh exists; remove it to re-initialise"
  # Single-quoted lines are written literally: they expand when env.sh is
  # sourced, relative to the LAB and CARGO_TARGET_DIR it exports.
  # shellcheck disable=SC2016
  {
    echo "# Eggomi L1 simulated-SNP lab. Source this file before running the harness."
    printf 'export LAB=%q\n' "$LAB"
    printf 'export CARGO_TARGET_DIR=%q\n' "$target"
    echo 'export EGGOMI_STATE_DIR="$LAB/state"'
    echo 'export EGGOMI_VM_DIR="$LAB/vmm/vm"'
    printf 'export EGGOMI_COLLATERAL_PORT=%q\n' "$service_base"
    printf 'export EGGOMI_COLLATERAL_URL=%q\n' "http://10.0.2.2:$service_base"
    printf 'export EGGOMI_KMS_PORT=%q\n' "$((service_base + 1))"
    printf 'export EGGOMI_APP_PORT=%q\n' "$port_base"
    printf 'export EGGOMI_S2_PORT=%q\n' "$((port_base + 1))"
    printf 'export EGGOMI_DEV_IMAGE=%q\n' "$image"
    echo 'export MOCK_ATTESTATION_BIN="$CARGO_TARGET_DIR/release/dstack-mock-attestation"'
    echo 'export SNP_SIM_KMS_BIN="$CARGO_TARGET_DIR/release/snp-sim-kms"'
    echo 'export DSTACK_VMM_URL="unix:$LAB/vmm/vmm.sock"'
    printf 'export DSTACK_VMM_CLI=%q\n' "$ROOT/dstack/vmm/src/vmm-cli.py"
  } >"$LAB/env.sh"
  load_env
  if [[ ! -s "$EGGOMI_STATE_DIR/mock-roots/tee-simulator.json" ]]; then
    "$ROOT/test-suites/eggomi/scripts/mock-collateral.sh" generate
  fi
  {
    cat <<EOF
# Eggomi L1 simulated-SNP lab VMM. Overrides the defaults compiled into
# dstack-vmm (dstack/vmm/vmm.toml). Lab only: throwaway mock roots, no KMS.
address = "unix:$VMM_DIR/vmm.sock"
run_path = "$VMM_DIR/vm"
kms_url = ""
log_level = "info"

[image]
path = "$LAB/image"

[cvm]
platform = "auto"
qemu_path = "$(command -v qemu-system-x86_64 || echo /usr/bin/qemu-system-x86_64)"
kms_urls = []
gateway_urls = []
cid_start = $cid_start
cid_pool_size = 100
max_allocable_vcpu = 8
max_allocable_memory_in_mb = 16_384

[cvm.networking]
mode = "user"

[cvm.port_mapping]
enabled = true
address = "127.0.0.1"
range = [
    { protocol = "tcp", from = $port_base, to = $((port_base + 9)) },
]

[cvm.auto_restart]
enabled = false

[supervisor]
exe = "$target/release/supervisor"
sock = "$VMM_DIR/run/supervisor.sock"
pid_file = "$VMM_DIR/run/supervisor.pid"
log_file = "$VMM_DIR/run/supervisor.log"

# Every VMM on a host listens on vsock CID 2; give each its own port.
[host_api]
address = "vsock:2"
port = $host_api_port

[key_provider]
enabled = false

EOF
    cat "$EGGOMI_STATE_DIR/vmm-tee-simulator.toml"
  } >"$VMM_DIR/vmm.toml"
  chmod 0600 "$VMM_DIR/vmm.toml"
  printf 'initialised %s; install the dev image under %s/image\n' "$LAB" "$LAB"
}

start_vmm() {
  if pid_alive "$VMM_DIR/vmm.pid"; then
    echo "vmm already running (pid $(cat "$VMM_DIR/vmm.pid"))"
    return
  fi
  cd "$VMM_DIR"
  setsid nohup "$CARGO_TARGET_DIR/release/dstack-vmm" -c "$VMM_DIR/vmm.toml" \
    >>"$LAB/logs/vmm.log" 2>&1 </dev/null &
  echo $! >"$VMM_DIR/vmm.pid"
  local deadline=$((SECONDS + 30))
  until [[ -S $VMM_DIR/vmm.sock ]]; do
    ((SECONDS < deadline)) || die "vmm socket did not appear; see $LAB/logs/vmm.log"
    sleep 1
  done
  echo "vmm pid $(cat "$VMM_DIR/vmm.pid"), socket $VMM_DIR/vmm.sock"
}

start_collateral() {
  if pid_alive "$LAB/collateral.pid"; then
    echo "collateral already running"
    return
  fi
  setsid nohup "$ROOT/test-suites/eggomi/scripts/mock-collateral.sh" serve \
    >>"$LAB/logs/collateral.log" 2>&1 </dev/null &
  echo $! >"$LAB/collateral.pid"
  echo "collateral pid $(cat "$LAB/collateral.pid") on :$EGGOMI_COLLATERAL_PORT"
}

# Long-running lab KMS, enrolled to the MEASUREMENT of the VM recorded in
# state/last-run.env (the S0 VM, unless EGGOMI_KMS_VM_ID names another), with
# the release gate open. Set EGGOMI_KMS_RELEASE=false to keep it closed.
start_kms() {
  if pid_alive "$LAB/kms.pid"; then
    echo "snp-sim-kms already running"
    return
  fi
  local vm_id=${EGGOMI_KMS_VM_ID:-}
  if [[ -z "$vm_id" ]]; then
    [[ -s "$EGGOMI_STATE_DIR/last-run.env" ]] || die "run S0 first or set EGGOMI_KMS_VM_ID"
    vm_id=$(sed -n 's/^EGGOMI_VM_ID=//p' "$EGGOMI_STATE_DIR/last-run.env")
  fi
  local gate=(--release-enabled)
  [[ "${EGGOMI_KMS_RELEASE:-true}" == true ]] || gate=()
  setsid nohup "$SNP_SIM_KMS_BIN" serve --listen "127.0.0.1:$EGGOMI_KMS_PORT" \
    --mock-config "$EGGOMI_STATE_DIR/mock-roots/tee-simulator.json" \
    --kds-url "http://127.0.0.1:$EGGOMI_COLLATERAL_PORT/vcek/v1" \
    --enroll-vm-config "$EGGOMI_VM_DIR/$vm_id/shared/.tee-simulator.json" \
    "${gate[@]}" >>"$LAB/logs/kms.log" 2>&1 </dev/null &
  echo $! >"$LAB/kms.pid"
  echo "snp-sim-kms pid $(cat "$LAB/kms.pid") on 127.0.0.1:$EGGOMI_KMS_PORT (guest: 10.0.2.2:$EGGOMI_KMS_PORT)"
}

stop_pidfile() {
  local file=$1
  if pid_alive "$file"; then
    kill "$(cat "$file")"
    echo "stopped $(basename "$file" .pid)"
  fi
  rm -f "$file"
}

status() {
  local name file
  for name in vmm collateral kms; do
    file="$LAB/$name.pid"
    [[ $name == vmm ]] && file="$VMM_DIR/vmm.pid"
    if pid_alive "$file"; then
      echo "$name: running pid $(cat "$file")"
    else
      echo "$name: stopped"
    fi
  done
  python3 "$DSTACK_VMM_CLI" --url "$DSTACK_VMM_URL" lsvm 2>/dev/null || true
  df -h / | tail -1
  du -sh "$LAB" 2>/dev/null || true
}

case "${1:-status}" in
  init) init ;;
  start) load_env; start_vmm ;;
  stop) load_env; stop_pidfile "$VMM_DIR/vmm.pid" ;;
  start-collateral) load_env; start_collateral ;;
  stop-collateral) load_env; stop_pidfile "$LAB/collateral.pid" ;;
  start-kms) load_env; start_kms ;;
  stop-kms) load_env; stop_pidfile "$LAB/kms.pid" ;;
  status) load_env; status ;;
  cli) shift; load_env; exec python3 "$DSTACK_VMM_CLI" --url "$DSTACK_VMM_URL" "$@" ;;
  *)
    die "usage: $0 {init|start|stop|status|start-collateral|stop-collateral|start-kms|stop-kms|cli ...}"
    ;;
esac
