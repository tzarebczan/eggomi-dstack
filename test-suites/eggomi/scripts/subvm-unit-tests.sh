#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# Host-only tests for the smolvm subVM keeper channel and leak scanner. No KVM.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
export PYTHONPATH="$ROOT/test-suites/cah:$ROOT/test-suites/eggomi/subvm${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1
python3 -m unittest discover -s "$ROOT/test-suites/eggomi/subvm/tests" -v
