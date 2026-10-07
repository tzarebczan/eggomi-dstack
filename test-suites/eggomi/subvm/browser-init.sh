#!/bin/sh
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# Browser subVM workload: the guard next to a headless Chromium. The flags are
# the fork-friendly set from smolvm's headless-browser example. The guard
# waits in tmpfs for the launcher's key and the keeper address.
set -eu
until [ -f /opt/eggomi/.installed ]; do sleep 0.1; done
export PYTHONPATH=/opt/eggomi PYTHONUNBUFFERED=1
python3 /opt/eggomi/guard_svc.py serve >/var/log/eggomi-guard.log 2>&1 &
exec chromium --headless=new --no-zygote --no-sandbox --disable-gpu \
  --disable-dev-shm-usage --remote-debugging-port=9222 \
  --user-data-dir=/tmp/chromium about:blank
