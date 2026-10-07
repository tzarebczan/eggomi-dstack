#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
STATE_DIR=${EGGOMI_STATE_DIR:-"$ROOT/test-suites/eggomi/.state"}
MOCK_ATTESTATION_BIN=${MOCK_ATTESTATION_BIN:-"${CARGO_TARGET_DIR:-$ROOT/dstack/target}/release/dstack-mock-attestation"}
COLLATERAL_PORT=${EGGOMI_COLLATERAL_PORT:-18088}
COLLATERAL_URL=${EGGOMI_COLLATERAL_URL:-"http://10.0.2.2:${COLLATERAL_PORT}"}
CONFIG="$STATE_DIR/mock-roots/tee-simulator.json"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_bin() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

generate() {
  need_bin jq
  [[ -x "$MOCK_ATTESTATION_BIN" ]] \
    || die "missing dstack-mock-attestation; build it with: cargo build --manifest-path dstack/Cargo.toml --release -p mock-attestation"
  [[ ! -e "$CONFIG" ]] \
    || die "mock config already exists at $CONFIG; remove the Eggomi state directory to rotate the seed"

  mkdir -p "$STATE_DIR/mock-roots"
  "$MOCK_ATTESTATION_BIN" generate \
    --output "$STATE_DIR/mock-roots" \
    --collateral-base-url "$COLLATERAL_URL"

  local tmp seed
  tmp=$(mktemp "$STATE_DIR/mock-roots/tee-simulator.json.XXXXXX")
  jq '.platform = "dstack-amd-sev-snp"' "$CONFIG" >"$tmp"
  mv "$tmp" "$CONFIG"
  chmod 0600 "$CONFIG"
  seed=$(jq -er '.mock_attestation_seed | select(test("^[0-9a-fA-F]{64}$"))' "$CONFIG")

  cat >"$STATE_DIR/vmm-tee-simulator.toml" <<EOF
[cvm.tee_simulator]
mock_attestation_seed = "$seed"
collateral_base_url = "$COLLATERAL_URL"
EOF

  printf 'generated job-unique mock assets in %s\n' "$STATE_DIR/mock-roots"
  printf 'merge %s into the VMM configuration, then restart the VMM\n' \
    "$STATE_DIR/vmm-tee-simulator.toml"
}

serve() {
  [[ -x "$MOCK_ATTESTATION_BIN" ]] \
    || die "missing dstack-mock-attestation: $MOCK_ATTESTATION_BIN"
  [[ -s "$CONFIG" ]] || die "missing $CONFIG; run '$0 generate' first"
  exec "$MOCK_ATTESTATION_BIN" serve \
    --listen "0.0.0.0:${COLLATERAL_PORT}" \
    --config "$CONFIG" \
    --output "$STATE_DIR/active-mock-roots"
}

case "${1:-}" in
  generate) generate ;;
  serve) serve ;;
  *) die "usage: $0 {generate|serve}" ;;
esac
