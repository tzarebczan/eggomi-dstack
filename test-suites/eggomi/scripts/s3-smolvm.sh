#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# S3: browser and keeper smolvm lifecycle, host-native (L2).
#
# Creates a keeper and a browser subVM from cached base packs, then measures
# create, start, ready, exec, stop, checkpoint, and restore; host RSS and
# guest memory at idle, after a heavy tab, after free-page reporting, after a
# balloon pulse, and after a checkpoint; what stopping the browser returns;
# and whether keeper RPC stays up while the browser is stopped, restored from
# its checkpoint, and branched.
#
# Writes $EGGOMI_STATE_DIR/work/s3-metrics.prom and s3-report.json. Exits 77
# when the host cannot run smolvm.
set -euo pipefail

SUITE_TAG=s3
# shellcheck source=lib-smolvm.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-smolvm.sh"

SETTLE=${EGGOMI_S3_SETTLE:-30}
TAB_MIB=${EGGOMI_S3_TAB_MIB:-256}
PROM="$RUN_DIR/metrics.tmp"
FAILURES=()

metric() {
  printf 'eggomi_s3_%s %s\n' "$1" "$2" >>"$PROM"
}

check() {
  local name=$1
  shift
  if "$@"; then
    metric "check{name=\"$name\"}" 1
  else
    metric "check{name=\"$name\"}" 0
    FAILURES+=("$name")
    log "check failed: $name"
  fi
}

mem_sample() {
  local machine=$1 role=$2 phase=$3 rss
  rss=$(host_rss "$machine")
  metric "host_rss_bytes{machine=\"$role\",phase=\"$phase\"}" "$(jq -r '.rss' <<<"$rss")"
  metric "host_rss_shmem_bytes{machine=\"$role\",phase=\"$phase\"}" "$(jq -r '.shmem // 0' <<<"$rss")"
  if [[ "${4:-guest}" == guest ]]; then
    metric "guest_used_bytes{machine=\"$role\",phase=\"$phase\"}" "$(guest_used_bytes "$machine")"
  fi
  jq -r '.rss' <<<"$rss"
}

keeper_rpc_from() {
  local machine=$1
  [[ "$(guard_ctl "$machine" '{"cmd": "ping"}' | jq -r '.code')" == ok ]]
}

heavy_tab() {
  local machine=$1 page="$RUN_DIR/tab.html"
  cat >"$page" <<EOF
<!doctype html><body><script>
const held = [];
for (let i = 0; i < $((TAB_MIB / 4)); i++) {
  const block = new Uint8Array(4 << 20);
  for (let j = 0; j < block.length; j += 4096) block[j] = 1;
  held.push(block);
}
document.body.textContent = "tab held " + held.length * 4 + " MiB";
</script></body>
EOF
  sv machine cp "$page" "$machine:/tmp/tab.html" >/dev/null 2>&1
  sv machine exec --name "$machine" -- chromium --headless=new --no-sandbox --no-zygote \
    --disable-gpu --disable-dev-shm-usage --user-data-dir=/tmp/tab-profile \
    --dump-dom file:///tmp/tab.html 2>/dev/null | grep -q "tab held"
}

main() {
  mkdir -p "$RUN_DIR"
  smolvm_gate
  if [[ "${1:-}" == --preflight ]]; then
    log "preflight passed (smolvm $SMOLVM_VERSION)"
    return
  fi
  : >"$PROM"
  trap cleanup EXIT
  ensure_base keeper
  local keeper_pack=$BASE_PACK
  ensure_base browser
  local browser_pack=$BASE_PACK
  make_code_tar
  local keys="$RUN_DIR/keys"
  rm -rf "$keys"
  host_tool keygen "$keys" >/dev/null
  python3 -c 'import secrets; print("eggomi-s3-throwaway-" + secrets.token_hex(24))' \
    >"$keys/secret"
  chmod 600 "$keys/secret"

  local K="eggomi-s3-keeper-$RUN_ID" B="eggomi-s3-browser-$RUN_ID"
  local R="eggomi-s3-restored-$RUN_ID" C="eggomi-s3-branch-$RUN_ID"
  local t

  # keeper -----------------------------------------------------------------
  t=$(now); create_keeper "$K" "$keeper_pack"; metric 'lifecycle_seconds{machine="keeper",op="create"}' "$(since "$t")"
  t=$(now); sv machine start --name "$K" >/dev/null; metric 'lifecycle_seconds{machine="keeper",op="start"}' "$(since "$t")"
  install_code "$K"
  install_keeper_state "$K" "$keys" "$keys/secret"
  wait_keeper "$keys" || die "keeper did not answer on 127.0.0.1:$KEEPER_PORT"
  metric 'lifecycle_seconds{machine="keeper",op="ready"}' "$(since "$t")"
  metric 'lifecycle_seconds{machine="keeper",op="exec_p50"}' "$(exec_p50 "$K")"

  # browser ----------------------------------------------------------------
  t=$(now); create_browser "$B" "$browser_pack"; metric 'lifecycle_seconds{machine="browser",op="create"}' "$(since "$t")"
  t=$(now); sv machine start --name "$B" >/dev/null; metric 'lifecycle_seconds{machine="browser",op="start"}' "$(since "$t")"
  install_code "$B"
  install_browser_state "$B" "$keys"
  wait_browser "$B" || die "browser guard or Chromium did not become ready"
  metric 'lifecycle_seconds{machine="browser",op="ready"}' "$(since "$t")"
  check keeper_rpc_from_browser keeper_rpc_from "$B"
  metric 'lifecycle_seconds{machine="browser",op="exec_p50"}' "$(exec_p50 "$B")"

  log "settling ${SETTLE}s before idle samples"
  sleep "$SETTLE"
  mem_sample "$K" keeper idle >/dev/null
  local idle tab settled ballooned checkpointed
  idle=$(mem_sample "$B" browser idle)
  metric 'host_rss_bytes{machine="keeper+browser",phase="idle"}' \
    "$(($(host_rss "$K" | jq -r '.rss') + idle))"

  # heavy tab, free page reporting, balloon --------------------------------
  check heavy_tab heavy_tab "$B"
  tab=$(mem_sample "$B" browser after_tab)
  metric 'tab_growth_bytes{machine="browser"}' "$((tab - idle))"
  sleep "$SETTLE"
  settled=$(mem_sample "$B" browser after_settle)
  metric 'reclaimed_bytes{machine="browser",via="free_page_reporting"}' "$((tab - settled))"
  balloon_pulse "$B" $((2048 * 8 / 10)) >"$RUN_DIR/balloon.json"
  metric 'balloon_seconds{machine="browser"}' "$(jq -r '.seconds' "$RUN_DIR/balloon.json")"
  sleep 5
  ballooned=$(mem_sample "$B" browser after_balloon)
  metric 'reclaimed_bytes{machine="browser",via="balloon_pulse"}' "$((settled - ballooned))"

  # checkpoint -------------------------------------------------------------
  local ckpt="$RUN_DIR/browser.checkpoint" out
  rm -f "$ckpt"
  t=$(now)
  out=$(sv machine checkpoint --name "$B" -o "$ckpt" 2>&1) || die "checkpoint failed: $out"
  metric 'lifecycle_seconds{machine="browser",op="checkpoint"}' "$(since "$t")"
  printf '%s\n' "$out" >"$RUN_DIR/checkpoint.log"
  metric 'lifecycle_seconds{machine="browser",op="checkpoint_pause"}' \
    "$(grep -Eo '[0-9.]+s source pause' <<<"$out" | grep -Eo '^[0-9.]+' | tail -1 || echo NaN)"
  metric 'checkpoint_bytes{machine="browser"}' "$(stat -c %s "$ckpt")"
  checkpointed=$(mem_sample "$B" browser after_checkpoint)
  metric 'checkpoint_rss_growth_bytes{machine="browser"}' "$((checkpointed - ballooned))"
  metric 'vm_disk_bytes{machine="keeper"}' "$(disk_bytes "$K")"
  metric 'vm_disk_bytes{machine="browser"}' "$(disk_bytes "$B")"

  # keeper RPC stays up while the browser stops, restores, and branches ----
  local plog="$RUN_DIR/probe.jsonl" pstop="$RUN_DIR/probe.stop"
  rm -f "$plog" "$pstop"
  host_tool probe "127.0.0.1:$KEEPER_PORT" "$keys" "$plog" "$pstop" --interval 0.1 &
  BACKGROUND+=("$!")
  local probe_pid=$!
  sleep 1

  local pid before_stop
  pid=$(machine_pid "$B")
  before_stop=$(host_rss "$B" | jq -r '.rss')
  t=$(now); sv machine stop --name "$B" >/dev/null; metric 'lifecycle_seconds{machine="browser",op="stop"}' "$(since "$t")"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    check browser_vmm_exited false
  else
    check browser_vmm_exited true
    metric 'reclaimed_bytes{machine="browser",via="stop"}' "$before_stop"
  fi

  t=$(now)
  MACHINES+=("$R")
  sv machine create --name "$R" --from "$ckpt" --restore-cache-entries 0 >/dev/null
  metric 'lifecycle_seconds{machine="browser",op="restore_create"}' "$(since "$t")"
  local t2
  t2=$(now)
  sv machine start --name "$R" --branchable >/dev/null
  metric 'lifecycle_seconds{machine="browser",op="restore_start"}' "$(since "$t2")"
  wait_browser "$R" || die "restored browser did not become ready"
  metric 'lifecycle_seconds{machine="browser",op="restore_ready"}' "$(since "$t")"
  check keeper_rpc_from_restored keeper_rpc_from "$R"
  mem_sample "$R" restored idle >/dev/null

  t=$(now)
  MACHINES+=("$C")
  sv machine branch --from "$R" --name "$C" >"$RUN_DIR/branch.log" 2>&1 || die "branch failed"
  metric 'lifecycle_seconds{machine="browser",op="branch"}' "$(since "$t")"
  wait_browser "$C" || die "branch child did not become ready"
  metric 'lifecycle_seconds{machine="browser",op="branch_ready"}' "$(since "$t")"
  check keeper_rpc_from_branch keeper_rpc_from "$C"
  mem_sample "$R" restored after_branch >/dev/null
  mem_sample "$C" branch idle >/dev/null
  sleep 1

  touch "$pstop"
  wait "$probe_pid" || true
  host_tool probe-summary "$plog" >"$RUN_DIR/probe-summary.json"
  metric 'keeper_probe_attempts_total' "$(jq -r '.attempts' "$RUN_DIR/probe-summary.json")"
  metric 'keeper_probe_failures_total' "$(jq -r '.failures' "$RUN_DIR/probe-summary.json")"
  metric 'keeper_probe_max_gap_seconds' "$(jq -r '.max_gap_seconds // "NaN"' "$RUN_DIR/probe-summary.json")"
  metric 'keeper_probe_p50_ms' "$(jq -r '.p50_ms // "NaN"' "$RUN_DIR/probe-summary.json")"
  check keeper_probe_no_failures test "$(jq -r '.failures' "$RUN_DIR/probe-summary.json")" -eq 0

  t=$(now); sv machine stop --name "$C" >/dev/null; metric 'lifecycle_seconds{machine="branch",op="stop"}' "$(since "$t")"
  t=$(now); sv machine stop --name "$R" >/dev/null; metric 'lifecycle_seconds{machine="restored",op="stop"}' "$(since "$t")"
  t=$(now); sv machine stop --name "$K" >/dev/null; metric 'lifecycle_seconds{machine="keeper",op="stop"}' "$(since "$t")"
  [[ "${EGGOMI_KEEP_CHECKPOINT:-0}" == 1 ]] || rm -f "$ckpt"

  {
    printf '# Eggomi S3 smolvm subVM lifecycle (L2 host-native), smolvm %s.\n' "$SMOLVM_VERSION"
    printf '# host_rss is the VMM process VmRSS; guest_used is MemTotal - MemAvailable.\n'
    printf 'eggomi_s3_available 1\n'
    cat "$PROM"
  } >"$METRICS"
  jq -n \
    --arg version "$SMOLVM_VERSION" \
    --arg run "$RUN_ID" \
    --argjson failures "$(printf '%s\n' "${FAILURES[@]}" | jq -R . | jq -s 'map(select(length > 0))')" \
    --slurpfile probe "$RUN_DIR/probe-summary.json" \
    --slurpfile balloon "$RUN_DIR/balloon.json" \
    --rawfile metrics "$METRICS" \
    '{schema: "eggomi-s3-report/v1", environment: "L2", smolvm: $version, run: $run,
      ok: ($failures | length == 0), failures: $failures, keeper_probe: $probe[0],
      balloon: $balloon[0], metrics: $metrics}' >"$REPORT"
  log "metrics: $METRICS"
  log "report: $REPORT"
  if ((${#FAILURES[@]})); then
    die "s3 failed checks: ${FAILURES[*]}"
  fi
  log "s3 passed"
}

main "$@"
