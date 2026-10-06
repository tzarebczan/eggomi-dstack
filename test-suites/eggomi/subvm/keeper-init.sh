#!/bin/sh
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# Keeper subVM workload. The launcher copies /opt/eggomi in after the first
# start and then installs the keys, peer table, and test secret.
set -eu
until [ -f /opt/eggomi/.installed ]; do sleep 0.1; done
export PYTHONPATH=/opt/eggomi PYTHONUNBUFFERED=1
exec python3 /opt/eggomi/keeper_svc.py --state /var/lib/eggomi-keeper --listen 0.0.0.0:7011
