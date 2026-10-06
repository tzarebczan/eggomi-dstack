"""Launcher-written admission.

The keeper does not expose ``AdmitWorkload``. The launcher writes the
registry from the one-use scope file and journals the token beside the
grant journal. This module does not read keeper policy.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Dict

from .grants import GrantStore
from .registry import load_registry, save_registry
from .rpc import rpc_error, rpc_ok


def admit_scoped(
    registry_path: Path,
    authority: Path,
    *,
    caller_role: str,
    token: str,
    admit_role: str,
    admit_instance: str,
    admit_boot: str,
) -> Dict[str, Any]:
    """Admit one scoped instance when ``caller_role`` is the launcher.

    A caller that is not ``platform-launcher`` is ``denied_role`` and does
    not spend the token. A scope mismatch or a repeated instance is
    ``denied_bootstrap`` and does not spend a new token. Policy is not read.
    """
    if caller_role != "platform-launcher":
        return rpc_error("denied_role")
    if not all(
        isinstance(item, str) and item
        for item in (token, admit_role, admit_instance, admit_boot)
    ):
        return rpc_error("denied_payload")
    scope_path = authority / "bootstrap-scope.json"
    if not scope_path.exists():
        return rpc_error("denied_bootstrap")
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    grants = GrantStore(
        authority / "grants.json",
        authority / "authority-journal.jsonl",
        authority / "keeper-epoch",
    )
    if grants.bootstrap_used(digest) or scope.get("used") is True:
        return rpc_error("denied_bootstrap")
    expected = str(scope.get("token_sha256", ""))
    if not expected or not hmac.compare_digest(digest, expected):
        return rpc_error("denied_bootstrap")
    if (
        admit_role != scope.get("admit_role")
        or admit_instance != scope.get("admit_instance_id")
        or admit_boot != scope.get("admit_boot_id")
    ):
        return rpc_error("denied_bootstrap")
    registry = load_registry(registry_path)
    if registry.find_instance(admit_instance) is not None:
        return rpc_error("denied_bootstrap")
    registry.workloads.append(
        {
            "role": admit_role,
            "instance_id": admit_instance,
            "boot_id": admit_boot,
            "boot_generation": 1,
            "boot_history": [admit_boot],
            "cert_fingerprint": None,
            "pid": None,
            "starttime": None,
            "channel_public": None,
        }
    )
    save_registry(registry_path, registry)
    scope["used"] = True
    tmp = scope_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(scope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, scope_path)
    grants.note_bootstrap(digest)
    return rpc_ok({"instance_id": admit_instance})
