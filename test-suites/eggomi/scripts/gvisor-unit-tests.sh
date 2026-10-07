#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# Host-only tests for gv-ckpt, the checkpoint policy init-gvisor.sh installs
# in the gVisor lab CVM. A fake docker CLI stands in; no CVM, no runsc.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
export PYTHONPATH="$ROOT/test-suites/eggomi/gvisor${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1
python3 -m unittest discover -s "$ROOT/test-suites/eggomi/gvisor/tests" -v
