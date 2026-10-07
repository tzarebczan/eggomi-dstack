#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# S4' (gVisor): secret capability RPC between keeper, guard, and browser
# sandboxes (runsc, systrap) inside the L1 simulated-SNP lab CVM; leak
# searches of the browser's checkpoint images and storage with positive
# controls; and the sandbox boundary checks. The suite itself is
# test-suites/eggomi/gvisor/incvm-s4.sh; this wrapper gates on the lab CVM
# (gvisor-lab.sh) and runs it there.
#
# Writes $EGGOMI_STATE_DIR/work/s4-gvisor-metrics.prom and
# s4-gvisor-report.json. Exits 77 when the lab CVM, its runsc runtime, or the
# role images are missing.
set -euo pipefail

SUITE_TAG=s4
# shellcheck source=lib-gvisor.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-gvisor.sh"

if [[ "${1:-}" == --preflight ]]; then
  mkdir -p "$WORK_DIR"
  gvisor_gate
  log "preflight passed"
  exit 0
fi
run_incvm
