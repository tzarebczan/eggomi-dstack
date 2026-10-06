"""Default-deny role and method graph.

The graph is the profile's ``service-access.json``. A method that is absent
is refused. Scoped bootstrap is one row in that graph, not an implicit admin
channel.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, Tuple


@dataclass(frozen=True)
class BootstrapScope:
    """The single AdmitWorkload edge, when the profile defines one."""

    callee: str
    method: str
    caller_role: str
    one_use: bool


@dataclass(frozen=True)
class AccessGraph:
    """Allow-list of ``(caller role, callee role, method)`` triples."""

    profile: str
    allow: FrozenSet[Tuple[str, str, str]]
    bootstrap: BootstrapScope | None

    def permitted(self, caller_role: str, callee: str, method: str) -> bool:
        """Return whether this caller may invoke ``method`` on ``callee``."""
        return (caller_role, callee, method) in self.allow


def load_access(path: Path) -> AccessGraph:
    """Load a service-access document. Unknown shapes fail closed."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != "service-access/v1":
        raise ValueError("service-access schema_version is not service-access/v1")
    if raw.get("default") != "deny":
        raise ValueError("service-access default must be deny")
    allow = set()
    for edge in raw.get("allow", []):
        caller = _required_str(edge, "caller_role")
        callee = _required_str(edge, "callee")
        method = _required_str(edge, "method")
        allow.add((caller, callee, method))
    bootstrap_raw = raw.get("bootstrap")
    bootstrap: BootstrapScope | None = None
    if bootstrap_raw is not None:
        bootstrap = BootstrapScope(
            callee=_required_str(bootstrap_raw, "callee"),
            method=_required_str(bootstrap_raw, "method"),
            caller_role=_required_str(bootstrap_raw, "caller_role"),
            one_use=bool(bootstrap_raw.get("one_use")),
        )
        if not bootstrap.one_use:
            raise ValueError("scoped bootstrap must be one_use")
        if (bootstrap.caller_role, bootstrap.callee, bootstrap.method) not in allow:
            raise ValueError("bootstrap edge is missing from the allow list")
    return AccessGraph(
        profile=_required_str(raw, "profile"),
        allow=frozenset(allow),
        bootstrap=bootstrap,
    )


def _required_str(obj: Dict[str, object], key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"service-access field {key} is missing")
    return value
