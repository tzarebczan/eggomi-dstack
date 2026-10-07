#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# S4' (gVisor), inside the L1 lab CVM: secret capability RPC between gVisor
# sandboxes, leak searches, and the sandbox boundary.
#
# The keeper sandbox holds a throwaway secret on its own volume. The guard
# sandbox gets only TTL-scoped session material over the Noise KK keeper
# channel and fills it into a browser page over DevTools. The suite
#
#   1. runs the 14 cases of s4-secret-rpc.sh, adapted: the guard is its own
#      sandbox, a live session is filled into the browser, and the restored
#      browser's carried session is read back from its page;
#   2. checkpoints the browser while pristine (before any fill), right after
#      a fill, and after the filled tab is closed, and searches each
#      checkpoint image and the browser's and guard's storage for the raw
#      secret (raw, UTF-16LE, hex). Any hit fails the suite;
#   3. requires positive controls, so a clean search means something: a
#      canary page in the pristine checkpoint, the filled token in the filled
#      checkpoint, and the secret on the keeper's volume;
#   4. proves the boundary, each with a control that shows the probe can
#      see what it looks for: what the browser sandbox (as root) sees of the
#      keeper's files, processes, memory, and network; what a process that
#      escaped into the browser Sentry's host namespaces sees; and the CVM
#      floor that keeps sandboxes off the CVM's own services.
set -euo pipefail

SUITE_TAG=s4
# shellcheck source=incvm-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/incvm-lib.sh"

CASES="$RUN_DIR/cases.jsonl"
BOUNDARY="$RUN_DIR/boundary.jsonl"
FAILED=0
BFAILED=0

# record NAME EXPECT_JSON ACTUAL_JSON: EXPECT's keys must match in ACTUAL.
record() {
  local name=$1 expect=$2 actual=$3 pass
  if jq -e --argjson e "$expect" 'to_entries as $a | ($e | to_entries | all(. as $x | $a | any(.key == $x.key and .value == $x.value)))' \
    <<<"$actual" >/dev/null 2>&1; then
    pass=true
  else
    pass=false
    FAILED=$((FAILED + 1))
    log "case $name: expected $expect, got $actual"
  fi
  jq -cn --arg name "$name" --argjson expect "$expect" --argjson actual "$actual" \
    --argjson pass "$pass" '{name: $name, expect: $expect, actual: $actual, pass: $pass}' >>"$CASES"
}

# boundary NAME JQ_TEST EVIDENCE_JSON: the test must hold on the evidence.
boundary() {
  local name=$1 test=$2 evidence=$3 pass=false
  if jq -e "$test" <<<"$evidence" >/dev/null 2>&1; then
    pass=true
  else
    BFAILED=$((BFAILED + 1))
    log "boundary $name failed: $test"
  fi
  jq -cn --arg name "$name" --arg test "$test" --argjson evidence "$evidence" --argjson pass "$pass" \
    '{name: $name, test: $test, pass: $pass, evidence: $evidence}' >>"$BOUNDARY"
}

probe_in() {
  docker exec -i -u 0 "$1" python3 /opt/eggomi/boundary_probe.py <<<"$2"
}

# A process that escaped gVisor into a Sentry's host PID and network
# namespaces, simulated from the CVM: it gets a /proc of that PID namespace
# and that namespace's network. (A real escapee would also be in the Sentry's
# own user namespace, under its seccomp filter, with an almost empty root.)
escape_probe() {
  local pid=$1 request=$2
  # nsenter forks into the PID namespace when it enters one.
  nsenter -t "$pid" -p -n -- unshare -m --mount-proc -- \
    python3 "$PY/boundary_probe.py" <<<"$request"
}

ckpt_dir() {
  printf '/var/lib/docker/containers/%s/checkpoints/%s\n' "$(cid "$B")" "$1"
}

# A checkpoint search counts only if it read the memory image.
ckpt_covered() {
  jq -e '.files_scanned >= 3' "$1" >/dev/null &&
    [[ "$(stat -c %s "$2/pages.img")" -gt $((32 << 20)) ]]
}

main() {
  incvm_gate
  begin_run
  : >"$CASES"
  : >"$BOUNDARY"
  trap cleanup EXIT
  setup_lab
  local secret="$RUN_DIR/secret" token="$RUN_DIR/token" canary="$RUN_DIR/page-canary"
  python3 -c 'import secrets; print("eggomi-pristine-canary-" + secrets.token_hex(16))' >"$canary"

  # The CVM floor: shown to matter (the tools container reaches the CVM's
  # guest agent through its gateway), then switched on.
  local before_floor
  before_floor=$(docker exec -i "$T" python3 /opt/eggomi/boundary_probe.py \
    <<<'{"connect": ["10.231.10.1:8090", "10.231.10.1:22"]}')
  floor_on

  create_keeper
  docker start "$K" >/dev/null
  install_keeper_state
  wait_keeper || die "keeper did not answer on $KEEPER_ADDR"
  create_guard
  docker start "$G" >/dev/null
  install_guard_state
  wait_guard || die "guard did not reach the keeper"
  create_browser
  docker start "$B" >/dev/null
  wait_browser || die "the guard did not reach Chromium's DevTools"

  # 1. Cases -----------------------------------------------------------------
  local P=$PURPOSE out
  record ping '{"code":"ok"}' "$(guard_ctl '{"cmd":"ping"}')"
  record session '{"mint":"ok","accept":"filled","redeem":"ok"}' \
    "$(guard_ctl "{\"cmd\":\"session\",\"purpose\":\"$P\",\"ttl_ms\":10000}")"
  record replay_redeem '{"code":"consumed"}' "$(guard_ctl '{"cmd":"redeem_held"}')"
  record replay_seal '{"code":"filled","repeat":true,"plaintext_returned":false}' \
    "$(guard_ctl '{"cmd":"reaccept_last"}')"
  record expired_at_guard '{"mint":"ok","accept":"grant_expired"}' \
    "$(guard_ctl "{\"cmd\":\"session\",\"purpose\":\"$P\",\"ttl_ms\":1000,\"accept_delay_ms\":1500}")"
  record expired_at_origin '{"mint":"ok","accept":"filled","redeem":"expired"}' \
    "$(guard_ctl "{\"cmd\":\"session\",\"purpose\":\"$P\",\"ttl_ms\":1500,\"redeem_delay_ms\":2000}")"
  record get_secret_denied '{"code":"denied_method"}' "$(guard_ctl '{"cmd":"raw","method":"GetSecret"}')"
  record list_connections_denied '{"code":"denied_method"}' \
    "$(guard_ctl '{"cmd":"raw","method":"ListConnections"}')"
  record unregistered_key_refused '{"code":"handshake_refused"}' \
    "$(guard_ctl '{"cmd":"raw","method":"Ping","stranger":true}')"
  record other_purpose_denied '{"mint":"denied_purpose"}' \
    "$(guard_ctl '{"cmd":"session","purpose":"https://evil.example","ttl_ms":1000}')"
  record long_ttl_denied '{"mint":"denied_ttl"}' \
    "$(guard_ctl "{\"cmd\":\"session\",\"purpose\":\"$P\",\"ttl_ms\":60000}")"

  # 2. Boundary (before any fill, so no session is in the browser) ----------
  local kpid gpid bpid kcanary
  kpid=$(sentry_pid "$K")
  gpid=$(sentry_pid "$G")
  bpid=$(sentry_pid "$B")
  kcanary=$(cat "$RUN_DIR/keeper-canary")
  local req ev
  req=$(jq -cn --arg c "$kcanary" --argjson k "$kpid" --argjson g "$gpid" '{
    markers: ["keeper_svc", "gv_guard"], pids: [$k, $g],
    paths: ["/var/lib/eggomi-keeper", "/run/eggomi-guard", "/var/lib/docker", "/run/docker.sock",
            "/var/run/docker.sock", "/run/eggomi-gv", "/sys/fs/cgroup/system.slice"],
    connect: ["10.231.10.10:7011", "10.231.10.20:7011", "10.231.11.20:7011", "10.231.10.40:7011",
              "10.231.11.1:8090", "10.231.11.1:22"],
    canary: $c, roots: ["/"], chromium: true}')
  ev=$(probe_in "$B" "$req")
  printf '%s\n' "$ev" >"$RUN_DIR/boundary-browser.json"
  local control
  control=$(probe_in "$K" "$(jq -c '.chromium = false' <<<"$req")")
  printf '%s\n' "$control" >"$RUN_DIR/boundary-keeper-control.json"

  boundary browser_kernel_is_gvisor '.browser.kernel | endswith("gvisor")' \
    "$(jq -n --argjson b "$ev" '{browser: $b}')"
  boundary chromium_own_sandbox \
    '.chromium.renderers >= 1 and .chromium.all_seccomp_filter and .chromium.all_own_namespaces' \
    "$(jq -c '{chromium}' <<<"$ev")"
  boundary browser_cannot_read_keeper_files \
    '(.browser.grep.hits | length) == 0 and .browser.grep.files_scanned > 1000
     and ([.browser.paths[]] | all(. == false))
     and (.keeper_control.grep.hits | any(endswith("/var/lib/eggomi-keeper/canary")))' \
    "$(jq -n --argjson b "$ev" --argjson k "$control" \
      '{browser: {grep: $b.grep, paths: $b.paths}, keeper_control: {grep: $k.grep}}')"
  boundary browser_cannot_see_keeper_processes \
    '(.browser.markers | all(length == 0)) and (.keeper_control.markers.keeper_svc | length) >= 1' \
    "$(jq -n --argjson b "$ev" --argjson k "$control" \
      '{browser: {markers: $b.markers, pid_count: $b.pid_count}, keeper_control: {markers: $k.markers}}')"
  boundary browser_cannot_read_keeper_memory \
    '([.mem[]] | all(. == "ENOENT")) and .kcore == false and .dev_mem == false' \
    "$(jq -c '{mem, kcore, dev_mem}' <<<"$ev")"
  boundary browser_cannot_connect_keeper \
    '([.browser.connect[]] | all(. != "connected"))
     and .keeper_control.connect["10.231.10.10:7011"] == "connected"' \
    "$(jq -n --argjson b "$ev" --argjson k "$control" \
      '{browser: {connect: $b.connect}, keeper_control: {connect: $k.connect}}')"
  boundary cvm_floor_blocks_cvm_services \
    '.before_floor.connect["10.231.10.1:8090"] == "connected"
     and .browser_after_floor["10.231.11.1:8090"] != "connected"
     and .browser_after_floor["10.231.11.1:22"] != "connected"' \
    "$(jq -n --argjson f "$before_floor" --argjson b "$ev" \
      '{before_floor: $f, browser_after_floor: {"10.231.11.1:8090": $b.connect["10.231.11.1:8090"],
        "10.231.11.1:22": $b.connect["10.231.11.1:22"]}}')"

  # Escape: from the browser Sentry's host PID and network namespaces. The
  # control escapes into the keeper Sentry's namespaces the same way.
  local kid gid bid sentries esc_b esc_k
  kid=$(cid "$K")
  gid=$(cid "$G")
  bid=$(cid "$B")
  sentries=$(gvctl sentries "$kid" "$gid" "$bid")
  printf '%s\n' "$sentries" >"$RUN_DIR/sentries.json"
  req=$(jq -cn --arg k "$kid" --arg g "$gid" --arg b "$bid" --argjson kp "$kpid" --argjson gp "$gpid" \
    '{markers: [$k, $g, $b], pids: [$kp, $gp], connect: ["10.231.10.10:7011"]}')
  esc_b=$(escape_probe "$bpid" "$req")
  esc_k=$(escape_probe "$kpid" "$req")
  # The escapee's kernel network stack has no route even in the keeper's own
  # namespace (runsc's netstack owns the veth), so the network proof is which
  # bridge each Sentry's namespace attaches to: the browser's only to the
  # browser bridge, the keeper's only to the keeper bridge, the guard's to both.
  boundary escaped_browser_sentry_sees_no_other_sandbox \
    '(.browser_escape.markers[.k] | length) == 0 and (.browser_escape.markers[.g] | length) == 0
     and ([.browser_escape.mem[]] | all(. == "ENOENT"))
     and .browser_escape.connect["10.231.10.10:7011"] != "connected"
     and (.keeper_escape_control.markers[.k] | length) >= 1
     and .bridges.browser == [.br_c] and .bridges.keeper == [.br_k]
     and .bridges.guard == ([.br_c, .br_k] | sort)' \
    "$(jq -n --arg k "$kid" --arg g "$gid" --arg bc "$BR_C" --arg bk "$BR_K" \
      --argjson b "$esc_b" --argjson c "$esc_k" --argjson s "$sentries" \
      --arg kid "$kid" --arg gid "$gid" --arg bid "$bid" \
      '{k: $k, g: $g, br_c: $bc, br_k: $bk, browser_escape: $b, keeper_escape_control: $c,
        bridges: {keeper: $s[$kid].bridges, guard: $s[$gid].bridges, browser: $s[$bid].bridges}}')"
  # shellcheck disable=SC2016 # $s is a jq variable
  boundary sentries_isolated_on_the_host \
    '[.[]] as $s | ($s | all(.seccomp == "2" and .no_new_privs == "1"))
     and (["pid", "net", "mnt", "ipc", "uts", "user"] | all(. as $n | ($s | map(.ns[$n]) | unique | length) == 3))' \
    "$sentries"

  # 3. A pristine checkpoint, then a fill, then checkpoints after it --------
  out=$(guard_ctl "{\"cmd\":\"canary\",\"text\":\"$(cat "$canary")\"}")
  [[ "$(jq -r '.code' <<<"$out")" == ok ]] || die "canary page failed: $out"
  docker checkpoint create --leave-running "$B" pristine >/dev/null || die "pristine checkpoint failed"

  local live fill
  live=$(guard_ctl "{\"cmd\":\"session\",\"purpose\":\"$P\",\"ttl_ms\":20000,\"redeem\":false}")
  fill=$(guard_ctl '{"cmd":"fill"}')
  record live_session_filled '{"mint":"ok","accept":"filled","fill":"ok"}' \
    "$(jq -c --argjson f "$fill" '. + {fill: $f.code}' <<<"$live")"
  out=$(guard_ctl '{"cmd":"held"}')
  jq -r '.held.token' <<<"$out" >"$token"
  chmod 600 "$token"
  local expires_ms t ckpt_seconds
  expires_ms=$(jq -r '.held.expires_ms' <<<"$out")
  t=$(now)
  docker checkpoint create --leave-running "$B" filled >/dev/null || die "filled checkpoint failed"
  ckpt_seconds=$(since "$t")
  guard_ctl "{\"cmd\":\"close\",\"target\":\"$(jq -r '.target' <<<"$fill")\"}" >/dev/null
  sleep 2
  docker checkpoint create --leave-running "$B" closed >/dev/null || die "after-close checkpoint failed"
  docker stop -t 10 "$B" >/dev/null

  local s_pristine s_filled s_closed c_pristine c_filled t_closed s_bdisk s_gdisk k_disk
  s_pristine=$(scan_hits "$secret" "$RUN_DIR/scan-secret-pristine.json" "$(ckpt_dir pristine)")
  s_filled=$(scan_hits "$secret" "$RUN_DIR/scan-secret-filled.json" "$(ckpt_dir filled)")
  s_closed=$(scan_hits "$secret" "$RUN_DIR/scan-secret-closed.json" "$(ckpt_dir closed)")
  c_pristine=$(scan_hits "$canary" "$RUN_DIR/scan-canary-pristine.json" "$(ckpt_dir pristine)")
  c_filled=$(scan_hits "$token" "$RUN_DIR/scan-token-filled.json" "$(ckpt_dir filled)")
  t_closed=$(scan_hits "$token" "$RUN_DIR/scan-token-closed.json" "$(ckpt_dir closed)")
  # shellcheck disable=SC2046 # two paths per container
  s_bdisk=$(scan_hits "$secret" "$RUN_DIR/scan-secret-browser-storage.json" $(container_paths "$B"))
  # shellcheck disable=SC2046
  s_gdisk=$(scan_hits "$secret" "$RUN_DIR/scan-secret-guard-storage.json" $(container_paths "$G"))
  sync
  k_disk=$(scan_hits "$secret" "$RUN_DIR/scan-secret-keeper-volume.json" \
    "$(docker volume inspect -f '{{.Mountpoint}}' "$VOL_K")")

  # 4. Restore the filled checkpoint: the carried session is TTL-bound ------
  docker start --checkpoint filled "$B" >/dev/null || die "restore failed"
  wait_browser || die "restored browser did not answer DevTools"
  local rping rcdp
  rping=$(guard_ctl '{"cmd":"ping"}' | jq -r '.code')
  rcdp=$(guard_ctl '{"cmd":"browser"}' | jq -r '.code')
  # containerd's leftover restore copy (tmpfs): the filled image again.
  local copies s_copy t_copy
  copies=$(restore_copies)
  [[ -n "$copies" ]] || die "no containerd restore copy found; the restore path changed"
  # shellcheck disable=SC2086 # one path per line, no spaces
  s_copy=$(scan_hits "$secret" "$RUN_DIR/scan-secret-restore-copy.json" $copies)
  # shellcheck disable=SC2086
  t_copy=$(scan_hits "$token" "$RUN_DIR/scan-token-restore-copy.json" $copies)
  purge_restore_copies
  record restored_keeper_rpc '{"code":"ok","cdp":"ok"}' \
    "$(jq -cn --arg p "$rping" --arg c "$rcdp" '{code: $p, cdp: $c}')"
  local wait_s
  wait_s=$(awk -v e="$expires_ms" -v n="$(date +%s%3N)" 'BEGIN { w = (e - n) / 1000 + 1; print (w > 0 ? w : 0) }')
  sleep "$wait_s"
  record restored_session_expired '{"code":"expired"}' "$(guard_ctl '{"cmd":"redeem_from_page"}')"
  docker stop -t 10 "$B" >/dev/null
  local s_restored
  # shellcheck disable=SC2046
  s_restored=$(scan_hits "$secret" "$RUN_DIR/scan-secret-restored-storage.json" $(container_paths "$B"))

  # Coverage: each checkpoint search read the memory image.
  local coverage=true name
  for name in pristine filled closed; do
    ckpt_covered "$RUN_DIR/scan-secret-$name.json" "$(ckpt_dir "$name")" || coverage=false
  done
  jq -e '.files_scanned >= 1' "$RUN_DIR/scan-secret-keeper-volume.json" >/dev/null || coverage=false
  [[ $coverage == true ]] || log "a leak search did not cover its target; see $RUN_DIR/scan-*.json"
  local ckpt_bytes
  ckpt_bytes=$(du -s -B1 --apparent-size "$(ckpt_dir filled)" | awk '{print $1}')

  local cases_total bcount ok=true
  cases_total=$(wc -l <"$CASES")
  bcount=$(wc -l <"$BOUNDARY")
  ((FAILED == 0 && cases_total == 14)) || ok=false
  ((BFAILED == 0 && bcount == 9)) || ok=false
  ((s_pristine == 0 && s_filled == 0 && s_closed == 0)) || ok=false
  ((s_bdisk == 0 && s_gdisk == 0 && s_restored == 0 && s_copy == 0)) || ok=false
  ((c_pristine > 0 && c_filled > 0 && k_disk > 0 && t_copy > 0)) || ok=false
  [[ $coverage == true ]] || ok=false

  cat >"$METRICS" <<EOF
# Eggomi S4 secret capability RPC (L1 gVisor, in the simulated-SNP CVM), runsc $RUNSC_VERSION, systrap.
# secret_hits must be 0. positive_control_hits must be > 0 for a clean search to count.
# token_hits_after_tab_close is an observation: the pristine-checkpoint rule.
eggomi_s4_available 1
eggomi_s4_cases_total $cases_total
eggomi_s4_cases_failed_total $FAILED
eggomi_s4_boundary_checks_total $bcount
eggomi_s4_boundary_checks_failed_total $BFAILED
eggomi_s4_secret_hits{target="browser_checkpoint_pristine"} $s_pristine
eggomi_s4_secret_hits{target="browser_checkpoint"} $s_filled
eggomi_s4_secret_hits{target="browser_checkpoint_after_tab_close"} $s_closed
eggomi_s4_secret_hits{target="browser_disk"} $s_bdisk
eggomi_s4_secret_hits{target="guard_disk"} $s_gdisk
eggomi_s4_secret_hits{target="restored_browser_disk"} $s_restored
eggomi_s4_secret_hits{target="containerd_restore_copy"} $s_copy
eggomi_s4_positive_control_hits{target="canary_page_in_pristine_checkpoint"} $c_pristine
eggomi_s4_positive_control_hits{target="session_token_in_browser_checkpoint"} $c_filled
eggomi_s4_positive_control_hits{target="secret_on_keeper_disk"} $k_disk
eggomi_s4_positive_control_hits{target="session_token_in_restore_copy"} $t_copy
eggomi_s4_token_hits_after_tab_close $t_closed
eggomi_s4_scan_coverage $([[ $coverage == true ]] && echo 1 || echo 0)
eggomi_s4_checkpoint_seconds $ckpt_seconds
eggomi_s4_checkpoint_bytes $ckpt_bytes
eggomi_s4_ok $([[ $ok == true ]] && echo 1 || echo 0)
EOF
  jq -n \
    --arg version "$RUNSC_VERSION" \
    --arg run "$RUN_ID" \
    --argjson ok "$ok" \
    --slurpfile cases "$CASES" \
    --slurpfile boundary "$BOUNDARY" \
    --slurpfile sentries "$RUN_DIR/sentries.json" \
    --slurpfile sp "$RUN_DIR/scan-secret-pristine.json" \
    --slurpfile sf "$RUN_DIR/scan-secret-filled.json" \
    --slurpfile sc "$RUN_DIR/scan-secret-closed.json" \
    --slurpfile cp "$RUN_DIR/scan-canary-pristine.json" \
    --slurpfile tf "$RUN_DIR/scan-token-filled.json" \
    --slurpfile tc "$RUN_DIR/scan-token-closed.json" \
    --slurpfile bd "$RUN_DIR/scan-secret-browser-storage.json" \
    --slurpfile gd "$RUN_DIR/scan-secret-guard-storage.json" \
    --slurpfile rd "$RUN_DIR/scan-secret-restored-storage.json" \
    --slurpfile kd "$RUN_DIR/scan-secret-keeper-volume.json" \
    --slurpfile rc "$RUN_DIR/scan-secret-restore-copy.json" \
    --slurpfile tr "$RUN_DIR/scan-token-restore-copy.json" \
    '{schema: "eggomi-s4-report/v1", environment: "L1-gvisor", runsc: $version, platform: "systrap",
      run: $run, ok: $ok, cases: $cases, boundary: $boundary, sentries: $sentries[0],
      scans: {secret_in_pristine_checkpoint: $sp[0], secret_in_filled_checkpoint: $sf[0],
              secret_in_after_close_checkpoint: $sc[0], secret_on_browser_storage: $bd[0],
              secret_on_guard_storage: $gd[0], secret_on_restored_browser_storage: $rd[0],
              control_canary_in_pristine_checkpoint: $cp[0],
              control_token_in_filled_checkpoint: $tf[0],
              observed_token_in_after_close_checkpoint: $tc[0],
              control_secret_on_keeper_volume: $kd[0],
              secret_in_containerd_restore_copy: $rc[0],
              control_token_in_containerd_restore_copy: $tr[0]}}' >"$REPORT"
  rm -f "$token"
  log "metrics: $METRICS"
  [[ $ok == true ]] || die "s4 failed; see $REPORT"
  log "s4 passed"
}

main "$@"
