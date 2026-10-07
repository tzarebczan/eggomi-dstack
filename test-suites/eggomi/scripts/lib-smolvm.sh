# shellcheck shell=bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for the smolvm subVM suites (S3, S4). Source this file; it
# expects SUITE_TAG (s3 or s4) to be set first.
#
# Environment:
#   SMOLVM                   smolvm launcher (default: smolvm on PATH)
#   SMOLVM_DATA_DIR          smolvm state root (smolvm's own variable)
#   EGGOMI_STATE_DIR         harness state (default test-suites/eggomi/.state)
#   EGGOMI_SMOLVM_PACKS      base .smolmachine cache (default $STATE_DIR/smolvm-packs)
#   EGGOMI_SMOLVM_BASE_IMAGE base OCI image (default alpine:3.22)
#   EGGOMI_KEEPER_PORT       host port the keeper channel is published on
#   EGGOMI_SMOLVM_GATEWAY    the browser's view of the host (default 100.96.0.1)
#   EGGOMI_KEEP=1            keep machines after the run

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
SUITE_DIR="$ROOT/test-suites/eggomi"
SUBVM_DIR="$SUITE_DIR/subvm"
CAH_DIR="$ROOT/test-suites/cah"
STATE_DIR=${EGGOMI_STATE_DIR:-"$SUITE_DIR/.state"}
WORK_DIR="$STATE_DIR/work"
RUN_DIR="$WORK_DIR/$SUITE_TAG"
METRICS="$WORK_DIR/$SUITE_TAG-metrics.prom"
REPORT="$WORK_DIR/$SUITE_TAG-report.json"
SMOLVM_BIN=${SMOLVM:-smolvm}
PACK_DIR=${EGGOMI_SMOLVM_PACKS:-"$STATE_DIR/smolvm-packs"}
BASE_IMAGE=${EGGOMI_SMOLVM_BASE_IMAGE:-alpine:3.22}
KEEPER_PORT=${EGGOMI_KEEPER_PORT:-47011}
GATEWAY=${EGGOMI_SMOLVM_GATEWAY:-100.96.0.1}
KEEPER_APK="python3 py3-cryptography"
BROWSER_APK="chromium font-dejavu python3 py3-cryptography"
# The keeper policy's allowed purpose; used by S4.
# shellcheck disable=SC2034
PURPOSE="https://login.example.test"
RUN_ID=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
MACHINES=()
BACKGROUND=()

export PYTHONPATH="$CAH_DIR:$SUBVM_DIR${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

log() {
  printf '[eggomi-%s] %s\n' "$SUITE_TAG" "$*" >&2
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

# Exit 77 with a metrics file that says the suite did not run. A skip is an
# environment gate, not a pass.
skip() {
  mkdir -p "$WORK_DIR"
  rm -f "$REPORT"
  printf '# Eggomi %s was gated before any subVM ran.\neggomi_%s_available 0\n' \
    "$SUITE_TAG" "$SUITE_TAG" >"$METRICS"
  printf 'skip: %s\n' "$1" >&2
  printf 'metrics: %s\n' "$METRICS" >&2
  exit 77
}

# Called first by each suite: no report from an earlier run may survive into
# this one, and the run directory is private (it holds keys while running).
begin_run() {
  mkdir -p "$RUN_DIR"
  chmod 700 "$RUN_DIR"
  rm -f "$METRICS" "$REPORT"
}

sv() {
  "$SMOLVM_BIN" "$@"
}

host_tool() {
  python3 "$SUBVM_DIR/host_tools.py" "$@"
}

now() {
  date +%s.%N
}

# seconds between two `now` stamps, millisecond precision
since() {
  awk -v a="$1" -v b="$(now)" 'BEGIN { printf "%.3f", b - a }'
}

smolvm_gate() {
  local tool
  for tool in python3 jq tar awk od; do
    command -v "$tool" >/dev/null 2>&1 || skip "missing required command: $tool"
  done
  python3 -c 'import cryptography' 2>/dev/null \
    || skip "host python3 lacks the cryptography package (pip install -r test-suites/cah/requirements.txt)"
  python3 -c 'import compression.zstd' 2>/dev/null || command -v zstd >/dev/null 2>&1 \
    || skip "need python 3.14+ or the zstd command to read checkpoints"
  [[ -r /dev/kvm && -w /dev/kvm ]] \
    || skip "/dev/kvm is not readable and writable; enable KVM or nested virtualization"
  command -v "$SMOLVM_BIN" >/dev/null 2>&1 || [[ -x "$SMOLVM_BIN" ]] \
    || skip "smolvm not found; install it or set SMOLVM to its launcher"
  SMOLVM_VERSION=$(sv --version 2>/dev/null | awk '{print $2}') \
    || skip "smolvm --version failed"
  [[ -n "$SMOLVM_VERSION" ]] || skip "smolvm --version printed nothing"
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$KEEPER_PORT\$"; then
    skip "host port $KEEPER_PORT is in use; set EGGOMI_KEEPER_PORT"
  fi
}

cleanup() {
  local pid name
  for pid in "${BACKGROUND[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  # Throwaway keys, the test secret, any held token, and checkpoints (which
  # hold the guard's key and session in RAM) never outlive a run.
  rm -rf "$RUN_DIR/keys" "$RUN_DIR/token"
  if [[ "${EGGOMI_KEEP_CHECKPOINT:-0}" != 1 ]]; then
    rm -f "$RUN_DIR"/*.checkpoint
  fi
  if [[ "${EGGOMI_KEEP:-0}" == 1 ]]; then
    log "keeping machines: ${MACHINES[*]}"
    return
  fi
  # Newest first: a branch child must go before its source.
  local i
  for ((i = ${#MACHINES[@]} - 1; i >= 0; i--)); do
    name=${MACHINES[i]}
    sv machine stop --name "$name" >/dev/null 2>&1 || true
    sv machine delete --name "$name" -f >/dev/null 2>&1 \
      || log "could not delete $name; remove it with: smolvm machine delete --name $name -f"
  done
}

# Build (once) a base .smolmachine for ROLE and set BASE_PACK to it. The pack
# holds only the Alpine packages; the harness code is copied in per run, so
# editing the suite does not rebuild a 300 MB browser image.
ensure_base() {
  local role=$1 apk hash out builder
  case "$role" in
    keeper) apk=$KEEPER_APK ;;
    browser) apk=$BROWSER_APK ;;
    *) die "unknown role $role" ;;
  esac
  hash=$(printf '%s\n' "$BASE_IMAGE" "$apk" "$SMOLVM_VERSION" | sha256sum | cut -c1-12)
  out="$PACK_DIR/eggomi-$role-$hash"
  BASE_PACK="$out.smolmachine"
  [[ -s "$BASE_PACK" ]] && return
  mkdir -p "$PACK_DIR"
  builder="eggomi-build-$role-$RUN_ID"
  log "building the $role base ($BASE_IMAGE + $apk); this needs network once"
  sv machine create --name "$builder" --image "$BASE_IMAGE" --net --cpus 2 --mem 2048 \
    >"$RUN_DIR/build-$role.log" 2>&1 || die "could not create $builder"
  MACHINES+=("$builder")
  sv machine start --name "$builder" >>"$RUN_DIR/build-$role.log" 2>&1 \
    || skip "could not pull $BASE_IMAGE; see $RUN_DIR/build-$role.log"
  sv machine exec --name "$builder" -- sh -c "apk add -q --no-cache $apk" \
    >>"$RUN_DIR/build-$role.log" 2>&1 \
    || skip "could not install $apk in the builder (network?); see $RUN_DIR/build-$role.log"
  sv machine stop --name "$builder" >>"$RUN_DIR/build-$role.log" 2>&1
  sv pack create --from-vm "$builder" -o "$out" >>"$RUN_DIR/build-$role.log" 2>&1 \
    || die "pack create failed; see $RUN_DIR/build-$role.log"
  rm -f "$out"
  sv machine delete --name "$builder" -f >/dev/null 2>&1 || true
}

make_code_tar() {
  tar --exclude=__pycache__ -cf "$RUN_DIR/code.tar" \
    -C "$CAH_DIR" cah \
    -C "$SUBVM_DIR" kkrpc.py session_material.py keeper_svc.py guard_svc.py \
    keeper-init.sh browser-init.sh
}

install_code() {
  local name=$1
  sv machine cp "$RUN_DIR/code.tar" "$name:/tmp/eggomi-code.tar" >/dev/null 2>&1 \
    || die "could not copy the harness into $name"
  sv machine exec --name "$name" -- sh -c \
    'mkdir -p /opt/eggomi && tar -xf /tmp/eggomi-code.tar -C /opt/eggomi && rm /tmp/eggomi-code.tar && touch /opt/eggomi/.installed' \
    || die "could not unpack the harness in $name"
}

WAIT_INSTALLED='until [ -f /opt/eggomi/.installed ]; do sleep 0.1; done; exec sh /opt/eggomi/'

create_keeper() {
  local name=$1 pack=$2
  MACHINES+=("$name")
  sv machine create --name "$name" --from "$pack" --cpus 1 --mem 512 \
    -p "$KEEPER_PORT:7011" -- sh -c "${WAIT_INSTALLED}keeper-init.sh" >/dev/null
}

# The browser's only egress is the gateway, which smolvm maps to host
# loopback. That is where the keeper channel is published.
create_browser() {
  local name=$1 pack=$2
  MACHINES+=("$name")
  sv machine create --name "$name" --from "$pack" --cpus 2 --mem 2048 \
    --net-backend virtio-net --allow-cidr "$GATEWAY/32" \
    -- sh -c "${WAIT_INSTALLED}browser-init.sh" >/dev/null
}

# Keys and the secret go in as files, never on a command line.
install_keeper_state() {
  local name=$1 keys=$2 secret=$3
  sv machine exec --name "$name" -- sh -c 'mkdir -p /var/lib/eggomi-keeper && chmod 700 /var/lib/eggomi-keeper'
  sv machine cp "$secret" "$name:/var/lib/eggomi-keeper/secret" >/dev/null 2>&1
  sv machine cp "$keys/peers.json" "$name:/var/lib/eggomi-keeper/peers.json" >/dev/null 2>&1
  sv machine cp "$keys/keeper.key" "$name:/var/lib/eggomi-keeper/keeper.key" >/dev/null 2>&1
  sv machine exec --name "$name" -- sh -c 'chmod 600 /var/lib/eggomi-keeper/*; sync'
}

install_browser_state() {
  local name=$1 keys=$2
  printf '%s:%s\n' "$GATEWAY" "$KEEPER_PORT" >"$keys/keeper.addr"
  sv machine exec --name "$name" -- sh -c 'mkdir -p /run/eggomi-guard && chmod 700 /run/eggomi-guard'
  sv machine cp "$keys/keeper.pub" "$name:/run/eggomi-guard/keeper.pub" >/dev/null 2>&1
  sv machine cp "$keys/browser.key" "$name:/run/eggomi-guard/guard.key" >/dev/null 2>&1
  sv machine cp "$keys/keeper.addr" "$name:/run/eggomi-guard/keeper.addr" >/dev/null 2>&1
}

wait_keeper() {
  local keys=$1 deadline=$((SECONDS + ${2:-60}))
  while ((SECONDS < deadline)); do
    if host_tool ping "127.0.0.1:$KEEPER_PORT" "$keys" | jq -e '.ok' >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_browser() {
  local name=$1 deadline=$((SECONDS + ${2:-90}))
  while ((SECONDS < deadline)); do
    if sv machine exec --name "$name" -- sh -c \
      'test -f /run/eggomi-guard/ready && wget -qO- http://127.0.0.1:9222/json/version >/dev/null' \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

guard_ctl() {
  local name=$1 request=$2
  sv machine exec --name "$name" -- env PYTHONPATH=/opt/eggomi \
    python3 /opt/eggomi/guard_svc.py ctl "$request"
}

machine_pid() {
  sv machine status --name "$1" --json | jq -r '.pid // empty'
}

machine_dir() {
  sv machine data-dir --name "$1"
}

host_rss() {
  local pid
  pid=$(machine_pid "$1")
  [[ -n "$pid" && -r "/proc/$pid/status" ]] || { echo '{"rss": 0}'; return; }
  host_tool rss "$pid"
}

# Guest MemTotal - MemAvailable. smolvm builds with guest memory in
# `status --json` (mirror branch claude/eggomi-subvm) answer without an exec.
guest_used_bytes() {
  local used
  used=$(sv machine status --name "$1" --json 2>/dev/null | jq -r '.memory.used_bytes // empty')
  if [[ -n "$used" ]]; then
    printf '%s\n' "$used"
    return
  fi
  # shellcheck disable=SC2016 # awk's own $2, expanded in the guest
  sv machine exec --name "$1" -- awk \
    '/^MemTotal:/ {t = $2} /^MemAvailable:/ {a = $2} END {printf "%d\n", (t - a) * 1024}' \
    /proc/meminfo
}

# Balloon pulse: `smolvm machine reclaim` when this smolvm has it, otherwise
# the same protocol on the per-VM control socket. Prints JSON with .seconds.
balloon_pulse() {
  local name=$1 target=$2 start out
  if sv machine reclaim --help >/dev/null 2>&1; then
    start=$(now)
    out=$(sv machine reclaim --name "$name" --target-mib "$target" --settle 0 --json)
    jq -c --arg s "$(since "$start")" '. + {seconds: ($s | tonumber), via: "machine reclaim"}' <<<"$out"
  else
    host_tool balloon "$(machine_dir "$name")/control.sock" "$target" \
      | jq -c '. + {via: "control.sock"}'
  fi
}

disk_bytes() {
  du -s -B1 "$(machine_dir "$1")" 2>/dev/null | awk '{print $1}'
}

exec_p50() {
  local name=$1 i start samples=()
  for i in 1 2 3 4 5 6 7 8 9; do
    start=$(now)
    sv machine exec --name "$name" -- true >/dev/null
    samples+=("$(since "$start")")
  done
  printf '%s\n' "${samples[@]}" | sort -n | awk 'NR == 5'
}
