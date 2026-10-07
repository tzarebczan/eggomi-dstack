#!/bin/sh
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# Browser sandbox workload (uid 10001). Chromium keeps its own sandbox: no
# --no-sandbox and no --no-zygote. Its renderers get their own user, PID, and
# network namespaces and a seccomp-bpf filter, all from gVisor's kernel.
# DevTools binds the sandbox loopback; the relay publishes it on the browser
# network, which only the guard shares.
set -eu
export PYTHONDONTWRITEBYTECODE=1
python3 /opt/eggomi/cdp.py relay 0.0.0.0:9223 127.0.0.1:9222 &
exec chromium --headless=new --disable-gpu --disable-dev-shm-usage \
  --remote-debugging-port=9222 --user-data-dir=/tmp/chromium about:blank
