# shellcheck shell=bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for S3' and S4' inside the L1 gVisor lab CVM (root in the
# CVM). The host wrappers (scripts/s3-gvisor.sh, s4-gvisor.sh) ship this tree
# to /run/eggomi-gv/code and run incvm-s3.sh or incvm-s4.sh over the lab
# shell. Source this file after setting SUITE_TAG.
#
# Layout per run: one gVisor sandbox (Docker runtime runsc, systrap) per
# role, each in its own cgroup with its own memory and CPU limits:
#
#   keeper   10.231.10.10  keeper net only; the secret on its own volume
#   guard    10.231.10.20  keeper net + browser net; the only channel key
#            10.231.11.20
#   browser  10.231.11.30  browser net only; Chromium (own sandbox on) and
#                          a DevTools relay on :9223
#   tools    10.231.10.40  launcher side (runc): keygen and the keeper probe
#
# Both networks are Docker --internal bridges: no egress, and no route from
# one to the other. The browser has no route to the keeper at all.

CODE=/run/eggomi-gv/code
PY="$CODE/py"
OUT=/run/eggomi-gv/out
RUN_ID=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
RUN_DIR="/run/eggomi-gv/run-$SUITE_TAG-$RUN_ID"
METRICS="$OUT/$SUITE_TAG-gvisor-metrics.prom"
REPORT="$OUT/$SUITE_TAG-gvisor-report.json"
PY_IMAGE=${EGGOMI_GV_PY_IMAGE:-eggomi-gv-py:lab}
BROWSER_IMAGE=${EGGOMI_GV_BROWSER_IMAGE:-eggomi-gv-browser:lab}
LABEL=eggomi.gvisor.run
NET_K="gv-k-$RUN_ID"
NET_C="gv-c-$RUN_ID"
BR_K="gvk$RUN_ID"
BR_C="gvc$RUN_ID"
VOL_K="gv-keeper-state-$RUN_ID"
K="gv-keeper-$RUN_ID"
G="gv-guard-$RUN_ID"
B="gv-browser-$RUN_ID"
T="gv-tools-$RUN_ID"
KEEPER_IP=10.231.10.10
GUARD_K_IP=10.231.10.20
GUARD_C_IP=10.231.11.20
BROWSER_IP=10.231.11.30
TOOLS_IP=10.231.10.40
KEEPER_ADDR="$KEEPER_IP:7011"
CDP_ADDR="$BROWSER_IP:9223"
# shellcheck disable=SC2034 # used by the suites that source this file
PURPOSE="https://login.example.test"
# Per-role cgroup limits (Docker --memory/--cpus; cgroup v2 memory.max/cpu.max).
KEEPER_LIMITS=(--memory 512m --cpus 1)
GUARD_LIMITS=(--memory 256m --cpus 1)
BROWSER_LIMITS=(--memory 2g --cpus 2)

log() {
  printf '[eggomi-%s-gvisor] %s\n' "$SUITE_TAG" "$*" >&2
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

skip() {
  mkdir -p "$OUT"
  printf '# Eggomi %s (gVisor) was gated before any sandbox ran.\neggomi_%s_available 0\n' \
    "$SUITE_TAG" "$SUITE_TAG" >"$METRICS"
  printf 'skip: %s\n' "$1" >&2
  exit 77
}

now() {
  date +%s.%N
}

since() {
  awk -v a="$1" -v b="$(now)" 'BEGIN { printf "%.3f", b - a }'
}

gvctl() {
  python3 "$PY/gvctl.py" "$@"
}

cid() {
  docker inspect -f '{{.Id}}' "$1"
}

# Gate: dockerd must have the runsc runtime and both role images.
incvm_gate() {
  local tool
  for tool in docker jq python3 awk od nsenter unshare; do
    command -v "$tool" >/dev/null 2>&1 || skip "the CVM lacks $tool"
  done
  docker info -f '{{json .Runtimes}}' 2>/dev/null | jq -e '.runsc' >/dev/null \
    || skip "dockerd has no runsc runtime; see init-gvisor.sh in the boot log"
  local image
  for image in "$PY_IMAGE" "$BROWSER_IMAGE"; do
    docker image inspect "$image" >/dev/null 2>&1 || skip "image $image is missing"
  done
  local runsc
  runsc=$(docker info -f '{{json .Runtimes}}' | jq -r '.runsc.path')
  # shellcheck disable=SC2034 # read by the suites
  RUNSC_VERSION=$("$runsc" --version | awk 'NR == 1 {print $3}')
}

begin_run() {
  mkdir -p "$OUT" "$RUN_DIR/keys" "$RUN_DIR/probe"
  chmod 700 "$RUN_DIR" "$RUN_DIR/keys"
  rm -f "$METRICS" "$REPORT"
  # A crashed earlier run must not hold the lab subnets or its keys. One
  # suite runs at a time.
  docker ps -aq --filter "label=$LABEL" | xargs -r docker rm -f >/dev/null
  docker network ls -q --filter "label=$LABEL" | xargs -r docker network rm >/dev/null
  docker volume ls -q --filter "label=$LABEL" | xargs -r docker volume rm >/dev/null
  find /run/eggomi-gv -maxdepth 1 -name 'run-*' ! -path "$RUN_DIR" -exec rm -rf {} +
  purge_restore_copies
  local rule
  { iptables -S INPUT | grep -E -- '-i gv[kc][0-9a-f]{8} ' || true; } | sed 's/^-A /-D /' | while read -r rule; do
    # shellcheck disable=SC2086 # a rule is a list of iptables words
    iptables $rule
  done
}

cleanup() {
  local pid
  for pid in "${BACKGROUND[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  if [[ "${EGGOMI_KEEP:-0}" == 1 ]]; then
    log "keeping sandboxes for run $RUN_ID"
    return
  fi
  # Containers first: their checkpoints (guard key and sessions in RAM)
  # live in their directories and go with them.
  docker ps -aq --filter "label=$LABEL=$RUN_ID" | xargs -r docker rm -f >/dev/null 2>&1 || true
  floor_off
  docker network rm "$NET_K" "$NET_C" >/dev/null 2>&1 || true
  docker volume rm "$VOL_K" >/dev/null 2>&1 || true
  purge_restore_copies
  rm -rf "$RUN_DIR"
}

# The CVM floor for the role bridges: Docker's --internal stops egress, but a
# sandbox can still open connections to the CVM itself through its bridge
# gateway (dstack-guest-agent on :8090, the lab sshd). Drop new connections
# from the role bridges to the CVM; replies to the CVM's own connections
# still pass. Container-to-container traffic on a bridge is not INPUT.
floor_on() {
  local br
  for br in "$BR_K" "$BR_C"; do
    iptables -I INPUT -i "$br" -m conntrack --ctstate NEW,INVALID -j DROP
  done
}

floor_off() {
  local br
  for br in "$BR_K" "$BR_C"; do
    while iptables -D INPUT -i "$br" -m conntrack --ctstate NEW,INVALID -j DROP 2>/dev/null; do :; done
  done
}

setup_lab() {
  docker network create --internal --label "$LABEL=$RUN_ID" --subnet 10.231.10.0/24 \
    -o "com.docker.network.bridge.name=$BR_K" "$NET_K" >/dev/null
  docker network create --internal --label "$LABEL=$RUN_ID" --subnet 10.231.11.0/24 \
    -o "com.docker.network.bridge.name=$BR_C" "$NET_C" >/dev/null
  docker volume create --label "$LABEL=$RUN_ID" "$VOL_K" >/dev/null
  # Keys and the throwaway secret live in the CVM's tmpfs only.
  docker run --rm --runtime runc --network none -v "$RUN_DIR/keys:/keys" -v "$PY:/opt/eggomi:ro" \
    -e PYTHONPATH=/opt/eggomi "$PY_IMAGE" python3 /opt/eggomi/host_tools.py keygen /keys >/dev/null
  python3 -c "import secrets; print('eggomi-$SUITE_TAG-gv-secret-' + secrets.token_hex(24))" >"$RUN_DIR/secret"
  python3 -c "import secrets; print('eggomi-keeper-canary-' + secrets.token_hex(16))" >"$RUN_DIR/keeper-canary"
  chmod 600 "$RUN_DIR/secret"
  printf '%s\n' "$KEEPER_ADDR" >"$RUN_DIR/keys/keeper.addr"
  printf '%s\n' "$CDP_ADDR" >"$RUN_DIR/keys/browser.addr"
  docker run -d --name "$T" --label "$LABEL=$RUN_ID" --runtime runc --network "$NET_K" --ip "$TOOLS_IP" \
    -v "$RUN_DIR/keys:/keys:ro" -v "$RUN_DIR/probe:/probe" -v "$PY:/opt/eggomi:ro" \
    -e PYTHONPATH=/opt/eggomi -e PYTHONDONTWRITEBYTECODE=1 "$PY_IMAGE" sleep infinity >/dev/null
}

create_keeper() {
  docker create --name "$K" --label "$LABEL=$RUN_ID" --runtime runsc "${KEEPER_LIMITS[@]}" \
    --network "$NET_K" --ip "$KEEPER_IP" -v "$PY:/opt/eggomi:ro" -v "$VOL_K:/var/lib/eggomi-keeper" \
    -e PYTHONPATH=/opt/eggomi -e PYTHONUNBUFFERED=1 -e PYTHONDONTWRITEBYTECODE=1 "$PY_IMAGE" \
    python3 /opt/eggomi/keeper_svc.py --state /var/lib/eggomi-keeper --listen 0.0.0.0:7011 >/dev/null
}

create_guard() {
  docker create --name "$G" --label "$LABEL=$RUN_ID" --runtime runsc "${GUARD_LIMITS[@]}" \
    --network "$NET_K" --ip "$GUARD_K_IP" --tmpfs /run/eggomi-guard:mode=0700 \
    -v "$PY:/opt/eggomi:ro" -e PYTHONPATH=/opt/eggomi -e PYTHONUNBUFFERED=1 \
    -e PYTHONDONTWRITEBYTECODE=1 "$PY_IMAGE" python3 /opt/eggomi/gv_guard.py serve >/dev/null
  docker network connect --ip "$GUARD_C_IP" "$NET_C" "$G"
}

create_browser() {
  docker create --name "$B" --label "$LABEL=$RUN_ID" --runtime runsc "${BROWSER_LIMITS[@]}" \
    --user 10001 --network "$NET_C" --ip "$BROWSER_IP" -v "$PY:/opt/eggomi:ro" \
    -e PYTHONDONTWRITEBYTECODE=1 "$BROWSER_IMAGE" sh /opt/eggomi/browser-init.sh >/dev/null
}

# put CONTAINER SRC DEST: a file into a running sandbox through stdin, never
# on a command line, written whole (tmp + rename).
put() {
  docker exec -i "$1" sh -c "umask 077; mkdir -p \"\$(dirname '$3')\" && cat >'$3.tmp' && mv '$3.tmp' '$3'" <"$2"
}

install_keeper_state() {
  put "$K" "$RUN_DIR/keys/peers.json" /var/lib/eggomi-keeper/peers.json
  put "$K" "$RUN_DIR/keys/keeper.key" /var/lib/eggomi-keeper/keeper.key
  put "$K" "$RUN_DIR/keeper-canary" /var/lib/eggomi-keeper/canary
  put "$K" "$RUN_DIR/secret" /var/lib/eggomi-keeper/secret
}

# The guard key goes last: the guard starts once it appears.
install_guard_state() {
  put "$G" "$RUN_DIR/keys/keeper.addr" /run/eggomi-guard/keeper.addr
  put "$G" "$RUN_DIR/keys/browser.addr" /run/eggomi-guard/browser.addr
  put "$G" "$RUN_DIR/keys/keeper.pub" /run/eggomi-guard/keeper.pub
  put "$G" "$RUN_DIR/keys/browser.key" /run/eggomi-guard/guard.key
}

keeper_ping() {
  docker exec "$T" python3 /opt/eggomi/host_tools.py ping "$KEEPER_ADDR" /keys
}

wait_keeper() {
  local deadline=$((SECONDS + ${1:-60}))
  while ((SECONDS < deadline)); do
    keeper_ping 2>/dev/null | jq -e '.ok' >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}

guard_ctl() {
  docker exec "$G" python3 /opt/eggomi/gv_guard.py ctl "$1"
}

wait_guard() {
  local deadline=$((SECONDS + ${1:-60}))
  while ((SECONDS < deadline)); do
    if docker exec "$G" test -f /run/eggomi-guard/ready 2>/dev/null &&
      [[ "$(guard_ctl '{"cmd":"ping"}' 2>/dev/null | jq -r '.code')" == ok ]]; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

# Browser ready: Chromium answers DevTools through its relay, as the guard
# sees it (the browser's only path out).
wait_browser() {
  local deadline=$((SECONDS + ${1:-90}))
  while ((SECONDS < deadline)); do
    [[ "$(guard_ctl '{"cmd":"browser"}' 2>/dev/null | jq -r '.code')" == ok ]] && return 0
    sleep 0.2
  done
  return 1
}

exec_p50() {
  local name=$1 start samples=()
  for _ in 1 2 3 4 5 6 7 8 9; do
    start=$(now)
    docker exec "$name" true >/dev/null
    samples+=("$(since "$start")")
  done
  printf '%s\n' "${samples[@]}" | sort -n | awk 'NR == 5'
}

# MemTotal - MemAvailable as the sandbox's own (gVisor) /proc/meminfo says.
sandbox_used_bytes() {
  docker exec "$1" awk '/^MemTotal:/ {t = $2} /^MemAvailable:/ {a = $2} END {printf "%d\n", (t - a) * 1024}' \
    /proc/meminfo
}

sentry_pid() {
  gvctl sentries "$(cid "$1")" | jq -r '.[].pid'
}

# Search PATHS for the needle file's encodings (raw, UTF-16LE, hex) with the
# L2 scanner. Prints the total hit count; the JSON goes to OUT_JSON.
scan_hits() {
  local needle=$1 out=$2
  shift 2
  python3 "$PY/host_tools.py" scan "$needle" "$@" >"$out"
  jq -r '.hits | add' "$out"
}

# containerd stages a restore's checkpoint image in /tmp/ctrd-checkpoint*,
# which in the CVM is RAM (tmpfs), and leaves it there after the restore and
# after the container is removed: a full copy of the browser's memory. The
# suites measure and search it, then remove it.
restore_copies() {
  find /tmp -maxdepth 1 -name 'ctrd-checkpoint*' -type d 2>/dev/null
}

purge_restore_copies() {
  restore_copies | xargs -r rm -rf
}

# What of a container's storage the CVM holds: its writable layer (gVisor's
# root overlay file store lands here, root:self) and its container directory
# (config, logs, checkpoints).
container_paths() {
  docker inspect -f '{{.GraphDriver.Data.UpperDir}} /var/lib/docker/containers/{{.Id}}' "$1"
}

BACKGROUND=()
