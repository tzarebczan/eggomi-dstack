"""Session material the keeper subVM mints for the browser subVM.

The browser never receives the keeper's secret. It receives a token derived
from the secret, bound to one purpose, one grant, and one expiry, and sealed
to the browser guard's channel key with the CAH sealed-answer format
(``cah.seal``, ``cah-sealed-answer/v3``). The seal's expiry offset is checked
by ``cah.guard.GuardStore`` on the guard's monotonic clock. The token's own
expiry is checked by whoever redeems it; in this lab that is the keeper,
standing in for the origin that issued the session.

Both sides build the sealed answer's binding from the values here and from
what each one already knows. Neither side copies a binding field from the
other's message.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict

TOKEN_SCHEMA = b"eggomi-s4-session/v1"
TENANT = "eggomi-lab"
AUDIENCE = "keeper-direct"
FIELD = "session"
FRAME_ID = "subvm"
NAVIGATION_GENERATION = "1"
TASK_ID = "s4"
RESOURCE_HANDLE = "eggomi-s4-test-secret"
LEASE_EPOCH = 1
BOOT_GENERATION = 1
MAX_TTL_MS = 30_000


def session_token(secret: bytes, purpose: str, grant_ref: str, expires_ms: int) -> str:
    """Return the hex session token for one grant. The secret is not recoverable."""
    message = b"\n".join(
        [
            TOKEN_SCHEMA,
            purpose.encode("utf-8"),
            grant_ref.encode("ascii"),
            str(expires_ms).encode("ascii"),
        ]
    )
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def binding(
    *, role: str, purpose: str, operation_id: str, keeper_epoch: int
) -> Dict[str, Any]:
    """Return the sealed-answer binding fields shared by keeper and guard."""
    return {
        "tenant": TENANT,
        "audience": AUDIENCE,
        "recipient_instance": role,
        "recipient_boot_generation": BOOT_GENERATION,
        "origin": purpose,
        "field": FIELD,
        "frame_id": FRAME_ID,
        "navigation_generation": NAVIGATION_GENERATION,
        "fence": "",
        "epoch": LEASE_EPOCH,
        "keeper_epoch": keeper_epoch,
        "requester_instance": role,
        "task_id": TASK_ID,
        "operation_id": operation_id,
        "resource_handle": RESOURCE_HANDLE,
    }
