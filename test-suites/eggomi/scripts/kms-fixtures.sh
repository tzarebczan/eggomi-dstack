#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# kms-fixtures.sh [OUT]: the fixture-dump target for the lab-only simulated
# SNP KMS (eggomi#757 item 3). It builds snp-sim-kms, runs `snp-sim-kms
# fixtures`, and adds the source commit to the provenance. The binary checks
# every output before it writes the set (see docs/eggomi/simulated-snp-kms.md),
# so a set that fails a check is never written. A keeper records the result
# instead of recording through a local test module.
#
# Environment:
#   EGGOMI_KMS_FIXTURE_SEED  32-byte hex mock-attestation seed (default 0x11
#                            x 32, the crate tests' seed). It derives only the
#                            mock ARK, ASK, and VCEK keys.
#   EGGOMI_KMS_FIXTURES_BIN  use this snp-sim-kms instead of building one. Its
#                            commit is unknown, so source_sha is null and the
#                            path goes in provenance.prebuilt_binary.
#   CARGO_TARGET_DIR         cargo's target directory (default dstack/target)
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
OUT=${1:-"$ROOT/test-suites/eggomi/.state/work/snp-sim-kms-fixtures.json"}
SEED=${EGGOMI_KMS_FIXTURE_SEED:-$(printf '11%.0s' {1..32})}
BIN=${EGGOMI_KMS_FIXTURES_BIN:-}

if [[ -z "$BIN" ]]; then
  cargo build --release --manifest-path "$ROOT/dstack/Cargo.toml" -p snp-sim-kms >&2
  BIN="${CARGO_TARGET_DIR:-$ROOT/dstack/target}/release/snp-sim-kms"
fi
mkdir -p "$(dirname "$OUT")"
tmp=$(mktemp "$OUT.XXXXXX")
trap 'rm -f "$tmp"' EXIT
"$BIN" fixtures --seed "$SEED" --out "$tmp"
# The commit is known only for a binary built here from this checkout. A
# binary passed in is recorded as such, with no commit attributed to it.
sha=null dirty=null binary=null
if [[ -z "${EGGOMI_KMS_FIXTURES_BIN:-}" ]]; then
  sha=$(git -C "$ROOT" rev-parse HEAD | jq -R .)
  dirty=false
  if [[ -n "$(git -C "$ROOT" status --porcelain -- dstack/crates/snp-sim-kms dstack/crates/mock-attestation)" ]]; then
    dirty=true
  fi
else
  binary=$(jq -Rn --arg b "$BIN" '$b')
fi
jq -e --argjson sha "$sha" --argjson dirty "$dirty" --argjson binary "$binary" \
  'select(.schema == "snp-sim-kms-fixtures/v2")
   | .provenance += {source_repo: "tzarebczan/eggomi-dstack", source_sha: $sha, source_dirty: $dirty,
                     prebuilt_binary: $binary, target: "test-suites/eggomi/scripts/kms-fixtures.sh"}' \
  "$tmp" >"$OUT.new"
mv "$OUT.new" "$OUT"
printf 'kms-fixtures: wrote %s (source %s)\n' "$OUT" "$(jq -r '.provenance | if .source_sha then .source_sha[0:8] + (if .source_dirty then ", dirty" else "" end) else "prebuilt " + .prebuilt_binary end' "$OUT")" >&2
