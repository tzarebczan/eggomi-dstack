#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

# Host-native E1 fill. This does not boot a CVM.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
SUITE="$ROOT/test-suites/cah"
STATE=${CAH_STATE_DIR:-"$SUITE/.state/fill-${CAH_TRANSPORT:-unix}"}
TRANSPORT=${CAH_TRANSPORT:-unix}

export PYTHONPATH="$SUITE${PYTHONPATH:+:$PYTHONPATH}"
mkdir -p "$STATE"
python3 -m cah.demo --state "$STATE" --transport "$TRANSPORT"
echo "[cah] report $STATE/report.json"
echo "[cah] measurements $STATE/measurements.json"
