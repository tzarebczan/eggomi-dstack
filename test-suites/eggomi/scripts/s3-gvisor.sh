#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# S3' (gVisor): keeper, guard, and browser lifecycle and memory, each in its
# own runsc (systrap) sandbox and cgroup inside the L1 simulated-SNP lab CVM.
# The suite itself is test-suites/eggomi/gvisor/incvm-s3.sh; this wrapper
# gates on the lab CVM (gvisor-lab.sh), runs it there, and adds the CVM's
# QEMU RSS as the host sees it.
#
# Writes $EGGOMI_STATE_DIR/work/s3-gvisor-metrics.prom and
# s3-gvisor-report.json. Exits 77 when the lab CVM, its runsc runtime, or the
# role images are missing.
set -euo pipefail

SUITE_TAG=s3
# shellcheck source=lib-gvisor.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib-gvisor.sh"

if [[ "${1:-}" == --preflight ]]; then
  mkdir -p "$WORK_DIR"
  gvisor_gate
  log "preflight passed"
  exit 0
fi
run_incvm
