#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# S4: secret capability RPC between smolvm subVMs, host-native (L2).
#
# The keeper subVM stores a throwaway secret on its own disk. The browser
# subVM's guard receives only TTL-scoped session material over the Noise KK
# keeper channel: a token derived from the secret, sealed to the guard's key
# in the CAH sealed-answer format. The suite then
#
#   1. checks the session path, replay, expiry at the guard and at the
#      origin stand-in, and the deny-by-default method table;
#   2. checkpoints the browser while the guard still holds a live session and
#      searches that checkpoint and the browser's disks for the raw secret
#      (raw, UTF-16LE, and hex). Any hit fails the suite;
#   3. requires two positive controls, so a clean search means something:
#      the held token must be found in the browser checkpoint, and the secret
#      must be found on the keeper's disk;
#   4. restores the checkpoint and requires the carried session to be
#      expired once its TTL has passed.
#
# Writes $EGGOMI_STATE_DIR/work/s4-metrics.prom and s4-report.json. Exits 77
# when the host cannot run smolvm.
set -euo pipefail

SUITE_TAG=s4
# shellcheck source=lib-smolvm.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-smolvm.sh"

CASES="$RUN_DIR/cases.jsonl"
FAILED=0

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

scan_hits() {
  local needle=$1 out=$2
  shift 2
  host_tool scan "$needle" "$@" >"$out"
  jq -r '.hits | add' "$out"
}

main() {
  begin_run
  smolvm_gate
  if [[ "${1:-}" == --preflight ]]; then
    log "preflight passed (smolvm $SMOLVM_VERSION)"
    return
  fi
  : >"$CASES"
  trap cleanup EXIT
  ensure_base keeper
  local keeper_pack=$BASE_PACK
  ensure_base browser
  local browser_pack=$BASE_PACK
  make_code_tar
  local keys="$RUN_DIR/keys" secret="$RUN_DIR/keys/secret" token="$RUN_DIR/token"
  rm -rf "$keys" "$token"
  host_tool keygen "$keys" >/dev/null
  python3 -c 'import secrets; print("eggomi-s4-secret-" + secrets.token_hex(24))' >"$secret"
  chmod 600 "$secret"

  local K="eggomi-s4-keeper-$RUN_ID" B="eggomi-s4-browser-$RUN_ID" R="eggomi-s4-restored-$RUN_ID"
  create_keeper "$K" "$keeper_pack"
  sv machine start --name "$K" >/dev/null
  install_code "$K"
  install_keeper_state "$K" "$keys" "$secret"
  wait_keeper "$keys" || die "keeper did not answer on 127.0.0.1:$KEEPER_PORT"
  create_browser "$B" "$browser_pack"
  sv machine start --name "$B" >/dev/null
  install_code "$B"
  install_browser_state "$B" "$keys"
  wait_browser "$B" || die "browser guard or Chromium did not become ready"

  local P=$PURPOSE out
  record ping '{"code":"ok"}' "$(guard_ctl "$B" '{"cmd":"ping"}')"
  record session '{"mint":"ok","accept":"filled","redeem":"ok"}' \
    "$(guard_ctl "$B" "{\"cmd\":\"session\",\"purpose\":\"$P\",\"ttl_ms\":10000}")"
  record replay_redeem '{"code":"consumed"}' "$(guard_ctl "$B" '{"cmd":"redeem_held"}')"
  record replay_seal '{"code":"filled","repeat":true,"plaintext_returned":false}' \
    "$(guard_ctl "$B" '{"cmd":"reaccept_last"}')"
  record expired_at_guard '{"mint":"ok","accept":"grant_expired"}' \
    "$(guard_ctl "$B" "{\"cmd\":\"session\",\"purpose\":\"$P\",\"ttl_ms\":1000,\"accept_delay_ms\":1500}")"
  record expired_at_origin '{"mint":"ok","accept":"filled","redeem":"expired"}' \
    "$(guard_ctl "$B" "{\"cmd\":\"session\",\"purpose\":\"$P\",\"ttl_ms\":1500,\"redeem_delay_ms\":2000}")"
  record get_secret_denied '{"code":"denied_method"}' \
    "$(guard_ctl "$B" '{"cmd":"raw","method":"GetSecret"}')"
  record list_connections_denied '{"code":"denied_method"}' \
    "$(guard_ctl "$B" '{"cmd":"raw","method":"ListConnections"}')"
  record unregistered_key_refused '{"code":"handshake_refused"}' \
    "$(guard_ctl "$B" '{"cmd":"raw","method":"Ping","stranger":true}')"
  record other_purpose_denied '{"mint":"denied_purpose"}' \
    "$(guard_ctl "$B" '{"cmd":"session","purpose":"https://evil.example","ttl_ms":1000}')"
  record long_ttl_denied '{"mint":"denied_ttl"}' \
    "$(guard_ctl "$B" "{\"cmd\":\"session\",\"purpose\":\"$P\",\"ttl_ms\":60000}")"

  # A live session the guard still holds when the browser is checkpointed.
  record live_session '{"mint":"ok","accept":"filled"}' \
    "$(guard_ctl "$B" "{\"cmd\":\"session\",\"purpose\":\"$P\",\"ttl_ms\":20000,\"redeem\":false}")"
  out=$(guard_ctl "$B" '{"cmd":"held"}')
  jq -r '.held.token' <<<"$out" >"$token"
  chmod 600 "$token"
  local expires_ms
  expires_ms=$(jq -r '.held.expires_ms' <<<"$out")

  local ckpt="$RUN_DIR/browser.checkpoint" t
  rm -f "$ckpt"
  t=$(now)
  sv machine checkpoint --name "$B" -o "$ckpt" >"$RUN_DIR/checkpoint.log" 2>&1 \
    || die "checkpoint failed; see $RUN_DIR/checkpoint.log"
  local ckpt_seconds
  ckpt_seconds=$(since "$t")

  local secret_ckpt token_ckpt secret_disk keeper_disk secret_restored
  secret_ckpt=$(scan_hits "$secret" "$RUN_DIR/scan-browser-checkpoint.json" "$ckpt")
  token_ckpt=$(scan_hits "$token" "$RUN_DIR/scan-token-checkpoint.json" "$ckpt")
  sv machine stop --name "$B" >/dev/null
  secret_disk=$(scan_hits "$secret" "$RUN_DIR/scan-browser-disk.json" "$(machine_dir "$B")")
  # The keeper keeps running (its grant table is in memory); sync puts the
  # secret file's blocks into the host-side disk image before the search.
  sv machine exec --name "$K" -- sync
  keeper_disk=$(scan_hits "$secret" "$RUN_DIR/scan-keeper-disk.json" "$(machine_dir "$K")")

  # Restore: the session the checkpoint carries is bounded by its TTL.
  MACHINES+=("$R")
  sv machine create --name "$R" --from "$ckpt" --restore-cache-entries 0 >/dev/null
  sv machine start --name "$R" >/dev/null
  wait_browser "$R" || die "restored browser did not become ready"
  record restored_keeper_rpc '{"code":"ok"}' "$(guard_ctl "$R" '{"cmd":"ping"}')"
  local wait_s
  wait_s=$(awk -v e="$expires_ms" -v n="$(date +%s%3N)" 'BEGIN { w = (e - n) / 1000 + 1; print (w > 0 ? w : 0) }')
  sleep "$wait_s"
  record restored_session_expired '{"code":"expired"}' "$(guard_ctl "$R" '{"cmd":"redeem_held"}')"
  sv machine stop --name "$R" >/dev/null
  secret_restored=$(scan_hits "$secret" "$RUN_DIR/scan-restored-disk.json" "$(machine_dir "$R")")
  [[ "${EGGOMI_KEEP_CHECKPOINT:-0}" == 1 ]] || rm -f "$ckpt"

  # Coverage: each search must have read what it claims to have read.
  local coverage=true
  jq -e '.kinds.checkpoint == 1' "$RUN_DIR/scan-browser-checkpoint.json" >/dev/null || coverage=false
  jq -e '.kinds.checkpoint == 1' "$RUN_DIR/scan-token-checkpoint.json" >/dev/null || coverage=false
  local scan_file
  for scan_file in scan-browser-disk scan-restored-disk scan-keeper-disk; do
    jq -e '(.kinds.qcow2 // 0) + (.kinds.file // 0) >= 2 and (.kinds.qcow2 // 0) >= 1' \
      "$RUN_DIR/$scan_file.json" >/dev/null || coverage=false
  done
  [[ $coverage == true ]] || log "a leak search did not cover its target; see $RUN_DIR/scan-*.json"

  local cases_total ok=true
  cases_total=$(wc -l <"$CASES")
  ((FAILED == 0)) || ok=false
  ((secret_ckpt == 0 && secret_disk == 0 && secret_restored == 0)) || ok=false
  ((token_ckpt > 0 && keeper_disk > 0)) || ok=false
  [[ $coverage == true ]] || ok=false

  cat >"$METRICS" <<EOF
# Eggomi S4 secret capability RPC (L2 host-native), smolvm $SMOLVM_VERSION.
# secret_hits must be 0. positive_control_hits must be > 0 for a clean search to count.
eggomi_s4_available 1
eggomi_s4_cases_total $cases_total
eggomi_s4_cases_failed_total $FAILED
eggomi_s4_secret_hits{target="browser_checkpoint"} $secret_ckpt
eggomi_s4_secret_hits{target="browser_disk"} $secret_disk
eggomi_s4_secret_hits{target="restored_browser_disk"} $secret_restored
eggomi_s4_positive_control_hits{target="session_token_in_browser_checkpoint"} $token_ckpt
eggomi_s4_positive_control_hits{target="secret_on_keeper_disk"} $keeper_disk
eggomi_s4_scan_coverage $([[ $coverage == true ]] && echo 1 || echo 0)
eggomi_s4_checkpoint_seconds $ckpt_seconds
eggomi_s4_ok $([[ $ok == true ]] && echo 1 || echo 0)
EOF
  jq -n \
    --arg version "$SMOLVM_VERSION" \
    --arg run "$RUN_ID" \
    --argjson ok "$ok" \
    --slurpfile cases "$CASES" \
    --slurpfile browser_checkpoint "$RUN_DIR/scan-browser-checkpoint.json" \
    --slurpfile token_checkpoint "$RUN_DIR/scan-token-checkpoint.json" \
    --slurpfile browser_disk "$RUN_DIR/scan-browser-disk.json" \
    --slurpfile restored_disk "$RUN_DIR/scan-restored-disk.json" \
    --slurpfile keeper_disk "$RUN_DIR/scan-keeper-disk.json" \
    '{schema: "eggomi-s4-report/v1", environment: "L2", smolvm: $version, run: $run,
      ok: $ok, cases: $cases,
      scans: {secret_in_browser_checkpoint: $browser_checkpoint[0],
              secret_on_browser_disk: $browser_disk[0],
              secret_on_restored_browser_disk: $restored_disk[0],
              control_token_in_browser_checkpoint: $token_checkpoint[0],
              control_secret_on_keeper_disk: $keeper_disk[0]}}' >"$REPORT"
  rm -f "$token"
  log "metrics: $METRICS"
  log "report: $REPORT"
  [[ $ok == true ]] || die "s4 failed; see $REPORT"
  log "s4 passed"
}

main "$@"
