#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
SUITE_DIR="$ROOT/test-suites/eggomi"
STATE_DIR=${EGGOMI_STATE_DIR:-"$SUITE_DIR/.state"}
WORK_DIR="$STATE_DIR/work"
MOCK_CONFIG="$STATE_DIR/mock-roots/tee-simulator.json"

log() {
  printf '[eggomi-s6] %s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

measurement_mismatch() {
  log "running the SEV-SNP measurement-mismatch unit hook"
  cargo test --manifest-path "$ROOT/dstack/Cargo.toml" \
    -p dstack-kms accepts_recomputed_matching_measurement_and_rejects_mismatch
}

prod_root_reject() {
  command -v docker >/dev/null 2>&1 \
    || { printf 'skip: Docker is required for the production-root rejection hook\n' >&2; exit 77; }
  docker compose version >/dev/null 2>&1 \
    || { printf 'skip: the Docker Compose plugin is required\n' >&2; exit 77; }
  mkdir -p "$WORK_DIR"

  local seed started elapsed output
  if [[ -s "$MOCK_CONFIG" ]]; then
    seed=$(jq -er '.mock_attestation_seed' "$MOCK_CONFIG")
  else
    command -v openssl >/dev/null 2>&1 || die "openssl is required to create a test seed"
    seed=$(openssl rand -hex 32)
  fi
  [[ "$seed" =~ ^[0-9a-fA-F]{64}$ ]] || die "mock seed must be 32 bytes of hexadecimal"

  started=$SECONDS
  (
    cd "$ROOT/dstack/tests/e2e/attestation"
    docker compose build
    MOCK_ATTESTATION_SEED="$seed" docker compose run --rm \
      -e MOCK_ATTESTATION_SEED amd-sev-snp
  ) | tee "$WORK_DIR/s6-prod-root-reject.log"
  (
    cd "$ROOT/dstack/tests/e2e/attestation"
    docker compose down --remove-orphans
  )
  elapsed=$((SECONDS - started))
  output=$(cat "$WORK_DIR/s6-prod-root-reject.log")
  grep -q '"development_root_accepted":true' <<<"$output" \
    || die "mock-root acceptance assertion was not observed"
  grep -q '"production_root_rejected":true' <<<"$output" \
    || die "production-root rejection assertion was not observed"
  grep -q 'dstack-util -> verifier trust-root isolation E2E passed' <<<"$output" \
    || die "snp attestation E2E success marker was not observed"

  cat >"$WORK_DIR/s6-metrics.prom" <<EOF
# End-to-end simulator generation plus positive and negative verification.
eggomi_s6_attestation_e2e_seconds $elapsed
eggomi_s6_mock_root_accepted 1
eggomi_s6_production_root_rejected 1
EOF
  log "production roots rejected the simulated SNP evidence"
}

case "${1:-all}" in
  measurement-mismatch) measurement_mismatch ;;
  prod-root-reject) prod_root_reject ;;
  all)
    measurement_mismatch
    prod_root_reject
    ;;
  *) die "usage: $0 {all|measurement-mismatch|prod-root-reject}" ;;
esac
