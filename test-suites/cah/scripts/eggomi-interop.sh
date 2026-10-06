#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

# Run the live Eggomi interop tests (tests/test_interop.py) against an Eggomi
# revision. The Eggomi sources are exported with `git archive`, so the Eggomi
# checkout is only read.
#
#   scripts/eggomi-interop.sh <eggomi-repo> [rev]      (rev: origin/master)
#
# CAH_EGGOMI_NODE_MODULES names a node_modules directory with @noble/ciphers,
# @noble/curves, @noble/hashes and typescript (default <eggomi-repo>/node_modules).
# CAH_INTEROP_UPDATE=1 first rewrites vectors/eggomi-interop.json from Eggomi.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
SUITE="$ROOT/test-suites/cah"
REPO=${1:?usage: eggomi-interop.sh <eggomi-repo> [rev]}
REV=${2:-origin/master}

command -v node >/dev/null || { echo "error: node is not on PATH" >&2; exit 1; }
EXPORT=$(mktemp -d)
LOG=$(mktemp)
trap 'rm -rf "$EXPORT" "$LOG"' EXIT
git -C "$REPO" archive "$REV" packages/noise apps/desktop/src/keeper | tar -x -C "$EXPORT"

export CAH_EGGOMI_CHECKOUT="$EXPORT"
export CAH_EGGOMI_NODE_MODULES="${CAH_EGGOMI_NODE_MODULES:-$REPO/node_modules}"
export CAH_EGGOMI_COMMIT
CAH_EGGOMI_COMMIT=$(git -C "$REPO" rev-parse "$REV")
export PYTHONPATH="$SUITE${PYTHONPATH:+:$PYTHONPATH}"

if [[ "${CAH_INTEROP_UPDATE:-0}" == 1 ]]; then
  node --import "$SUITE/interop/ts-loader.mjs" "$SUITE/interop/eggomi-interop.mjs" vectors \
    > "$SUITE/vectors/eggomi-interop.json"
  echo "[cah] rewrote vectors/eggomi-interop.json from Eggomi $CAH_EGGOMI_COMMIT"
fi
echo "[cah] Eggomi $CAH_EGGOMI_COMMIT"
python3 -m unittest discover -s "$SUITE/tests" -p test_interop.py -v 2>&1 | tee "$LOG"
if grep -q "skipped 'live" "$LOG"; then
  echo "error: the live interop tests were skipped" >&2
  exit 1
fi
