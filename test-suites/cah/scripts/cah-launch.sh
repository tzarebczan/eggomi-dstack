#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

# Choose host-native compartment stubs or the existing simulated-SNP substrate.
# The fill demo is always host-native. Entering S0 does not place the stubs
# inside the guest.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
MODE=${CAH_MODE:-auto}
TRANSPORT=${CAH_TRANSPORT:-unix}

kvm=0
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  kvm=1
fi

run_outer=0
if [[ "$MODE" == "outer" ]]; then
  run_outer=1
elif [[ "$MODE" == "auto" && "$kvm" == 1 && -n "${EGGOMI_DEV_IMAGE:-}" ]]; then
  if command -v qemu-system-x86_64 >/dev/null 2>&1 && command -v swtpm >/dev/null 2>&1; then
    run_outer=1
  fi
fi

if [[ "$run_outer" == 1 ]]; then
  echo "[cah] launching the existing simulated SNP substrate (S0)"
  "$ROOT/test-suites/eggomi/scripts/s0-sim-smoke.sh"
  echo "[cah] S0 does not inject compartment stubs into the guest"
else
  if [[ -e /dev/kvm && "$kvm" == 0 ]]; then
    echo "[cah] /dev/kvm exists but this user cannot open it"
  fi
  echo "[cah] simulated SNP substrate not entered; fill fidelity is E1 host-native"
fi

if [[ "$MODE" == "outer" ]]; then
  exit 0
fi

CAH_TRANSPORT="$TRANSPORT" "$ROOT/test-suites/cah/scripts/host-native-fill.sh"
