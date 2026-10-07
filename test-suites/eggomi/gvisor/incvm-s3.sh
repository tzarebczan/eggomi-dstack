#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# S3' (gVisor), inside the L1 lab CVM: keeper, guard, and browser lifecycle
# and memory, each role in its own runsc (systrap) sandbox and cgroup.
#
# Measures create, start, ready, exec, checkpoint, stop, and restore; per-role
# memory at idle, while active (a 256 MiB tab open and sessions flowing),
# after the tab closes, after memory.reclaim, and after a checkpoint; what
# memory.reclaim and stopping the browser return; the CVM's own memory; and
# whether keeper RPC stays up while the browser is checkpointed, stopped,
# and restored. Metric names follow s3-smolvm.sh where they apply.
set -euo pipefail

SUITE_TAG=s3
# shellcheck source=incvm-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/incvm-lib.sh"

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

# mem_sample ROLE CONTAINER PHASE: per-role cgroup and sandbox memory. Prints
# memory.current, which is what memory.reclaim and stop act on.
mem_sample() {
  local role=$1 name=$2 phase=$3 cg
  cg=$(gvctl cgroup "$(cid "$name")")
  printf '%s\n' "$cg" >"$RUN_DIR/cgroup-$role-$phase.json"
  metric "host_rss_bytes{machine=\"$role\",phase=\"$phase\"}" "$(jq -r '.pss' <<<"$cg")"
  metric "host_rss_shmem_bytes{machine=\"$role\",phase=\"$phase\"}" "$(jq -r '.shmem' <<<"$cg")"
  metric "cgroup_memory_bytes{machine=\"$role\",phase=\"$phase\"}" "$(jq -r '.memory_current' <<<"$cg")"
  metric "guest_used_bytes{machine=\"$role\",phase=\"$phase\"}" "$(sandbox_used_bytes "$name")"
  jq -r '.memory_current' <<<"$cg"
}

cvm_sample() {
  local phase=$1 mi
  mi=$(gvctl meminfo)
  metric "cvm_used_bytes{phase=\"$phase\"}" "$(jq -r '.used' <<<"$mi")"
  metric "cvm_zfs_arc_bytes{phase=\"$phase\"}" "$(jq -r '.zfs_arc' <<<"$mi")"
  metric "cvm_shmem_bytes{phase=\"$phase\"}" "$(jq -r '.shmem' <<<"$mi")"
  jq -r '.used' <<<"$mi"
}

roles_sample() {
  local phase=$1
  mem_sample keeper "$K" "$phase" >/dev/null
  mem_sample guard "$G" "$phase" >/dev/null
  mem_sample browser "$B" "$phase"
}

probe_covered() {
  jq -e --argjson t0 "$1" --argjson t1 "$2" \
    '.attempts >= 20 and .first <= $t0 and .last >= $t1' "$RUN_DIR/probe-summary.json" >/dev/null
}

probe_exited() {
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    docker exec "$T" pgrep -f 'host_tools.py probe' >/dev/null 2>&1 || return 0
    sleep 0.5
  done
  return 1
}

guard_ok() {
  [[ "$(guard_ctl "$1" | jq -r '.code')" == ok ]]
}

chromium_sandboxed() {
  docker exec -i -u 0 "$B" python3 /opt/eggomi/boundary_probe.py <<<'{"chromium": true}' \
    >"$RUN_DIR/chromium-sandbox.json"
  jq -e '.chromium.renderers >= 1 and .chromium.all_seccomp_filter and .chromium.all_own_namespaces
    and .chromium.browser_uid == ["10001"]' "$RUN_DIR/chromium-sandbox.json" >/dev/null
}

# Sessions flow while the active sample is taken: each outcome is recorded,
# and the suite requires successes and no failures.
session_burst() {
  local until=$1 out
  while (($(date +%s) < until)); do
    out=$(guard_ctl "{\"cmd\":\"session\",\"purpose\":\"$PURPOSE\",\"ttl_ms\":5000}" 2>&1) \
      || out='{"error":"ctl_failed"}'
    printf '%s\n' "$out" >>"$RUN_DIR/burst.jsonl"
  done
}

burst_ok() {
  local good bad
  good=$(jq -s '[.[] | select(.mint == "ok" and .accept == "filled" and .redeem == "ok")] | length' \
    "$RUN_DIR/burst.jsonl")
  bad=$(jq -s '[.[] | select((.mint == "ok" and .accept == "filled" and .redeem == "ok") | not)] | length' \
    "$RUN_DIR/burst.jsonl")
  metric 'active_sessions_total' "$good"
  metric 'active_session_failures_total' "$bad"
  ((good >= 3 && bad == 0))
}

main() {
  incvm_gate
  begin_run
  : >"$PROM"
  : >"$RUN_DIR/burst.jsonl"
  trap cleanup EXIT
  setup_lab
  floor_on
  local t

  # keeper -----------------------------------------------------------------
  t=$(now); create_keeper; metric 'lifecycle_seconds{machine="keeper",op="create"}' "$(since "$t")"
  t=$(now); docker start "$K" >/dev/null; metric 'lifecycle_seconds{machine="keeper",op="start"}' "$(since "$t")"
  install_keeper_state
  wait_keeper 60 || die "keeper did not answer on $KEEPER_ADDR"
  metric 'lifecycle_seconds{machine="keeper",op="ready"}' "$(since "$t")"
  metric 'lifecycle_seconds{machine="keeper",op="exec_p50"}' "$(exec_p50 "$K")"

  # guard ------------------------------------------------------------------
  t=$(now); create_guard; metric 'lifecycle_seconds{machine="guard",op="create"}' "$(since "$t")"
  t=$(now); docker start "$G" >/dev/null; metric 'lifecycle_seconds{machine="guard",op="start"}' "$(since "$t")"
  install_guard_state
  wait_guard 60 || die "guard did not reach the keeper"
  metric 'lifecycle_seconds{machine="guard",op="ready"}' "$(since "$t")"
  metric 'lifecycle_seconds{machine="guard",op="exec_p50"}' "$(exec_p50 "$G")"

  # browser ----------------------------------------------------------------
  t=$(now); create_browser; metric 'lifecycle_seconds{machine="browser",op="create"}' "$(since "$t")"
  t=$(now); docker start "$B" >/dev/null; metric 'lifecycle_seconds{machine="browser",op="start"}' "$(since "$t")"
  wait_browser 90 || die "the guard did not reach Chromium's DevTools"
  metric 'lifecycle_seconds{machine="browser",op="ready"}' "$(since "$t")"
  metric 'lifecycle_seconds{machine="browser",op="exec_p50"}' "$(exec_p50 "$B")"
  check keeper_rpc_from_guard guard_ok '{"cmd":"ping"}'
  check chromium_own_sandbox chromium_sandboxed
  gvctl cgroup "$(cid "$K")" | jq -c '{machine: "keeper", memory_max, cpu_max}' >"$RUN_DIR/limits.jsonl"
  gvctl cgroup "$(cid "$G")" | jq -c '{machine: "guard", memory_max, cpu_max}' >>"$RUN_DIR/limits.jsonl"
  gvctl cgroup "$(cid "$B")" | jq -c '{machine: "browser", memory_max, cpu_max}' >>"$RUN_DIR/limits.jsonl"

  log "settling ${SETTLE}s before idle samples"
  sleep "$SETTLE"
  local idle active closed reclaimed checkpointed cvm_idle
  idle=$(roles_sample idle)
  cvm_idle=$(cvm_sample idle)
  metric 'host_rss_bytes{machine="keeper+guard+browser",phase="idle"}' \
    "$(jq -s 'map(.pss) | add' "$RUN_DIR"/cgroup-{keeper,guard,browser}-idle.json)"

  # active: a heavy tab open while sessions flow ----------------------------
  local tab target burst_pid
  tab=$(guard_ctl "{\"cmd\":\"tab\",\"mib\":$TAB_MIB}")
  check heavy_tab test "$(jq -r '.code' <<<"$tab")" = ok
  target=$(jq -r '.target' <<<"$tab")
  session_burst $(($(date +%s) + 6)) &
  burst_pid=$!
  BACKGROUND+=("$burst_pid")
  sleep 3
  active=$(roles_sample active)
  cvm_sample active >/dev/null
  wait "$burst_pid" || true
  check sessions_flowed_while_active burst_ok
  metric 'tab_growth_bytes{machine="browser"}' "$((active - idle))"

  # tab closed, then memory.reclaim ------------------------------------------
  local closed_reply
  closed_reply=$(guard_ctl "{\"cmd\":\"close\",\"target\":\"$target\"}")
  [[ "$(jq -r '.code' <<<"$closed_reply")" == ok ]] || die "the heavy tab did not close: $closed_reply"
  sleep "$SETTLE"
  closed=$(mem_sample browser "$B" after_settle)
  cvm_sample after_settle >/dev/null
  metric 'reclaimed_bytes{machine="browser",via="tab_close_settle"}' "$((active - closed))"
  gvctl reclaim "$(cid "$B")" "$closed" >"$RUN_DIR/reclaim.json"
  metric 'reclaim_seconds{machine="browser"}' "$(jq -r '.seconds' "$RUN_DIR/reclaim.json")"
  sleep 2
  reclaimed=$(mem_sample browser "$B" after_reclaim)
  cvm_sample after_reclaim >/dev/null
  metric 'reclaimed_bytes{machine="browser",via="memory_reclaim"}' "$((closed - reclaimed))"
  local role name
  for role in keeper guard; do
    name=$K
    [[ $role == guard ]] && name=$G
    gvctl reclaim "$(cid "$name")" "$(jq -r '.memory_current' "$RUN_DIR/cgroup-$role-active.json")" \
      >"$RUN_DIR/reclaim-$role.json"
    metric "reclaimed_bytes{machine=\"$role\",via=\"memory_reclaim\"}" "$(jq -r '.reclaimed' "$RUN_DIR/reclaim-$role.json")"
  done

  # keeper RPC stays up while the browser checkpoints, stops, and restores --
  local plog="$RUN_DIR/probe/probe.jsonl" probe_t0 probe_t1
  docker exec -d "$T" python3 /opt/eggomi/host_tools.py probe "$KEEPER_ADDR" /keys \
    /probe/probe.jsonl /probe/probe.stop --interval 0.1
  sleep 1
  probe_t0=$(date +%s.%N)

  t=$(now)
  docker checkpoint create --leave-running "$B" s3 >/dev/null || die "checkpoint failed"
  metric 'lifecycle_seconds{machine="browser",op="checkpoint"}' "$(since "$t")"
  local ckpt
  ckpt="/var/lib/docker/containers/$(cid "$B")/checkpoints/s3"
  metric 'checkpoint_bytes{machine="browser"}' "$(du -s -B1 --apparent-size "$ckpt" | awk '{print $1}')"
  checkpointed=$(mem_sample browser "$B" after_checkpoint)
  metric 'checkpoint_rss_growth_bytes{machine="browser"}' "$((checkpointed - reclaimed))"
  check browser_alive_after_checkpoint guard_ok '{"cmd":"browser"}'

  local before_stop cvm_before cvm_after browser_cg
  browser_cg="/sys/fs/cgroup/system.slice/docker-$(cid "$B").scope"
  before_stop=$(mem_sample browser "$B" before_stop)
  cvm_before=$(cvm_sample before_stop)
  t=$(now); docker stop -t 10 "$B" >/dev/null; metric 'lifecycle_seconds{machine="browser",op="stop"}' "$(since "$t")"
  sleep 1
  cvm_after=$(cvm_sample after_browser_stop)
  check browser_cgroup_released test ! -d "$browser_cg"
  metric 'reclaimed_bytes{machine="browser",via="stop"}' "$before_stop"
  metric 'cvm_returned_bytes{via="browser_stop"}' "$((cvm_before - cvm_after))"

  t=$(now)
  docker start --checkpoint s3 "$B" >/dev/null || die "restore failed"
  metric 'lifecycle_seconds{machine="browser",op="restore_start"}' "$(since "$t")"
  wait_browser 90 || die "restored browser did not answer DevTools"
  metric 'lifecycle_seconds{machine="browser",op="restore_ready"}' "$(since "$t")"
  check keeper_rpc_from_guard_after_restore guard_ok '{"cmd":"ping"}'
  check restored_browser_cdp guard_ok '{"cmd":"browser"}'
  check chromium_own_sandbox_after_restore chromium_sandboxed
  local copies copy_bytes=0
  copies=$(restore_copies)
  if [[ -n "$copies" ]]; then
    # shellcheck disable=SC2086 # one path per line, no spaces
    copy_bytes=$(du -sbc $copies | awk 'END {print $1}')
  fi
  metric 'restore_tmp_copies{machine="browser"}' "$(grep -c . <<<"$copies" || true)"
  metric 'restore_tmp_copy_bytes{machine="browser"}' "$copy_bytes"
  purge_restore_copies
  sleep 2
  mem_sample browser "$B" restored_idle >/dev/null
  cvm_sample restored_idle >/dev/null
  probe_t1=$(date +%s.%N)
  sleep 1

  touch "$RUN_DIR/probe/probe.stop"
  sleep 1
  check keeper_probe_exited probe_exited
  python3 "$PY/host_tools.py" probe-summary "$plog" >"$RUN_DIR/probe-summary.json"
  check keeper_probe_covered_lifecycle probe_covered "$probe_t0" "$probe_t1"
  metric 'keeper_probe_attempts_total' "$(jq -r '.attempts' "$RUN_DIR/probe-summary.json")"
  metric 'keeper_probe_failures_total' "$(jq -r '.failures' "$RUN_DIR/probe-summary.json")"
  metric 'keeper_probe_max_gap_seconds' "$(jq -r '.max_gap_seconds // "NaN"' "$RUN_DIR/probe-summary.json")"
  metric 'keeper_probe_p50_ms' "$(jq -r '.p50_ms // "NaN"' "$RUN_DIR/probe-summary.json")"
  check keeper_probe_no_failures test "$(jq -r '.failures' "$RUN_DIR/probe-summary.json")" -eq 0

  t=$(now); docker stop -t 10 "$B" >/dev/null; metric 'lifecycle_seconds{machine="restored",op="stop"}' "$(since "$t")"
  t=$(now); docker stop -t 10 "$G" >/dev/null; metric 'lifecycle_seconds{machine="guard",op="stop"}' "$(since "$t")"
  t=$(now); docker stop -t 10 "$K" >/dev/null; metric 'lifecycle_seconds{machine="keeper",op="stop"}' "$(since "$t")"
  cvm_sample all_stopped >/dev/null
  metric 'cvm_returned_bytes{via="all_roles_stopped"}' "$((cvm_idle - $(jq -r '.used' <<<"$(gvctl meminfo)")))"

  {
    printf '# Eggomi S3 gVisor sandbox lifecycle (L1, in the simulated-SNP CVM), runsc %s, systrap.\n' "$RUNSC_VERSION"
    printf '# host_rss is the PSS of the sandbox host processes (Sentry, Gofer, systrap stubs);\n'
    printf '# cgroup_memory is the role cgroup memory.current; guest_used is the sandbox /proc/meminfo.\n'
    printf 'eggomi_s3_available 1\n'
    cat "$PROM"
  } >"$METRICS"
  jq -n \
    --arg version "$RUNSC_VERSION" \
    --arg run "$RUN_ID" \
    --argjson failures "$(printf '%s\n' "${FAILURES[@]}" | jq -R . | jq -s 'map(select(length > 0))')" \
    --slurpfile probe "$RUN_DIR/probe-summary.json" \
    --slurpfile reclaim "$RUN_DIR/reclaim.json" \
    --slurpfile limits "$RUN_DIR/limits.jsonl" \
    --slurpfile chromium "$RUN_DIR/chromium-sandbox.json" \
    --rawfile metrics "$METRICS" \
    '{schema: "eggomi-s3-report/v1", environment: "L1-gvisor", runsc: $version, platform: "systrap",
      run: $run, ok: ($failures | length == 0), failures: $failures, keeper_probe: $probe[0],
      memory_reclaim: $reclaim[0], limits: $limits, chromium_sandbox: $chromium[0].chromium,
      metrics: $metrics}' >"$REPORT"
  log "metrics: $METRICS"
  if ((${#FAILURES[@]})); then
    die "s3 failed checks: ${FAILURES[*]}"
  fi
  log "s3 passed"
}

main "$@"
