#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
export PYTHONPATH="$ROOT/test-suites/cah${PYTHONPATH:+:$PYTHONPATH}"
python3 -m unittest discover -s "$ROOT/test-suites/cah/tests" -v
