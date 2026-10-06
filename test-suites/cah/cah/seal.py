"""Seal one credential to a guard's per-lease key.

Every bound field is associated data. The guard rebuilds that data from
values it checks itself. A field taken from the broker's frame is not used.
The plaintext is the one-time credential. The broker never receives it.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Dict, Mapping

from .crypto_lab import aead_open, aead_seal, generate_private, hkdf_sha256, public_key, x25519

SCHEMA = "cah-sealed-answer/v1"
MAX_OFFSET_MS = 30_000


@dataclass(frozen=True)
class LiveBinding:
    """Values the guard knows from its lease, the frame, and the channel."""

    tenant: str
    audience: str
    recipient_instance: str
    recipient_boot_generation: int
    origin: str
    field: str
    frame_id: str
    navigation_generation: str
    fence: str
    epoch: int
    requester_instance: str
    task_id: str
    operation_id: str
    resource_handle: str
    challenge: bytes
    challenge_mono: float


def seal_credential(
    lease_public: bytes,
    plaintext: bytes,
    *,
    grant_ref: str,
    tenant: str,
    audience: str,
    recipient_instance: str,
    recipient_boot_generation: int,
    origin: str,
    field: str,
    frame_id: str,
    navigation_generation: str,
    fence: str,
    epoch: int,
    expiry_challenge: bytes,
    expiry_offset_ms: int,
    requester_instance: str,
    task_id: str,
    operation_id: str,
    resource_handle: str,
) -> Dict[str, Any]:
    """Seal ``plaintext`` to ``lease_public`` and return the wire object.

    ``expiry_offset_ms`` is at most 30 seconds. The nonce is random and is
    covered by the associated data.
    """
    if len(lease_public) != 32:
        raise ValueError("lease public key must be 32 bytes")
    if not plaintext:
        raise ValueError("sealed credential is empty")
    if len(expiry_challenge) != 32:
        raise ValueError("expiry challenge must be 32 bytes")
    if isinstance(expiry_offset_ms, bool) or not isinstance(expiry_offset_ms, int):
        raise ValueError("expiry offset is not an integer")
    if expiry_offset_ms <= 0 or expiry_offset_ms > MAX_OFFSET_MS:
        raise ValueError("seal expiry must be in (0, 30] seconds")
    nonce = generate_private()
    ephemeral_private = generate_private()
    ephemeral_public = public_key(ephemeral_private)
    shared = x25519(ephemeral_private, lease_public)
    key = hkdf_sha256(shared, b"cah-sealed-answer/v1")
    aad = associated_data(
        grant_ref=grant_ref,
        nonce=nonce,
        tenant=tenant,
        audience=audience,
        recipient_instance=recipient_instance,
        recipient_boot_generation=recipient_boot_generation,
        origin=origin,
        field=field,
        frame_id=frame_id,
        navigation_generation=navigation_generation,
        fence=fence,
        epoch=epoch,
        expiry_challenge=expiry_challenge,
        expiry_offset_ms=expiry_offset_ms,
        requester_instance=requester_instance,
        task_id=task_id,
        operation_id=operation_id,
        resource_handle=resource_handle,
    )
    ciphertext, tag = aead_seal(key, nonce, aad, plaintext)
    return {
        "schema_version": SCHEMA,
        "grant_ref": grant_ref,
        "nonce": nonce.hex(),
        "ephemeral_public": ephemeral_public.hex(),
        "expiry_challenge": expiry_challenge.hex(),
        "expiry_offset_ms": expiry_offset_ms,
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    }


def open_credential(lease_private: bytes, blob: Mapping[str, Any], live: LiveBinding) -> bytes:
    """Open ``blob`` with associated data rebuilt from ``live``.

    Header fields that the guard did not issue, other than the nonce and the
    expiry offset the keeper chose, are not copied into the associated data.
    A mismatch raises ``ValueError`` and must not be treated as a fill.
    """
    if len(lease_private) != 32:
        raise ValueError("lease private key must be 32 bytes")
    if blob.get("schema_version") != SCHEMA:
        raise ValueError("sealed answer schema is not cah-sealed-answer/v1")
    nonce = _hex32(blob.get("nonce"), "nonce")
    ephemeral = _hex32(blob.get("ephemeral_public"), "ephemeral public key")
    tag = _hex32(blob.get("tag"), "tag")
    offset = blob.get("expiry_offset_ms")
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError("expiry offset is not an integer")
    if offset <= 0 or offset > MAX_OFFSET_MS:
        raise ValueError("seal expiry must be in (0, 30] seconds")
    ciphertext = blob.get("ciphertext")
    if not isinstance(ciphertext, str):
        raise ValueError("ciphertext is missing")
    try:
        raw_ciphertext = bytes.fromhex(ciphertext)
    except ValueError as exc:
        raise ValueError("ciphertext is not hex") from exc
    grant_ref = blob.get("grant_ref")
    if not isinstance(grant_ref, str) or not grant_ref:
        raise ValueError("grant ref is missing")
    aad = associated_data(
        grant_ref=grant_ref,
        nonce=nonce,
        tenant=live.tenant,
        audience=live.audience,
        recipient_instance=live.recipient_instance,
        recipient_boot_generation=live.recipient_boot_generation,
        origin=live.origin,
        field=live.field,
        frame_id=live.frame_id,
        navigation_generation=live.navigation_generation,
        fence=live.fence,
        epoch=live.epoch,
        expiry_challenge=live.challenge,
        expiry_offset_ms=offset,
        requester_instance=live.requester_instance,
        task_id=live.task_id,
        operation_id=live.operation_id,
        resource_handle=live.resource_handle,
    )
    shared = x25519(lease_private, ephemeral)
    key = hkdf_sha256(shared, b"cah-sealed-answer/v1")
    return aead_open(key, nonce, aad, raw_ciphertext, tag)


def guard_proof(guard_private: bytes, keeper_public: bytes, transcript: bytes) -> bytes:
    """Return a possession tag over ``transcript`` for the keeper's static key."""
    shared = x25519(guard_private, keeper_public)
    key = hkdf_sha256(shared, b"cah-guard-proof/v1")
    return hmac.new(key, transcript, hashlib.sha256).digest()


def proof_matches(
    keeper_private: bytes, guard_public: bytes, transcript: bytes, proof: bytes
) -> bool:
    """Return whether ``proof`` was made by the holder of ``guard_public``."""
    if len(proof) != 32 or len(guard_public) != 32 or len(keeper_private) != 32:
        return False
    shared = x25519(keeper_private, guard_public)
    key = hkdf_sha256(shared, b"cah-guard-proof/v1")
    expect = hmac.new(key, transcript, hashlib.sha256).digest()
    return hmac.compare_digest(expect, proof)


def proof_transcript(
    *,
    grant_ref: str,
    origin: str,
    operation_id: str,
    frame_id: str,
    navigation_generation: str,
    challenge: bytes,
    guard_public: bytes,
    field: str,
    tenant: str,
) -> bytes:
    """Return the bytes the guard signs and the keeper verifies."""
    lines = [
        "cah-guard-proof/v1",
        f"grant_ref={grant_ref}",
        f"origin={origin}",
        f"operation_id={operation_id}",
        f"frame_id={frame_id}",
        f"navigation_generation={navigation_generation}",
        f"challenge={challenge.hex()}",
        f"guard_public={guard_public.hex()}",
        f"field={field}",
        f"tenant={tenant}",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def associated_data(
    *,
    grant_ref: str,
    nonce: bytes,
    tenant: str,
    audience: str,
    recipient_instance: str,
    recipient_boot_generation: int,
    origin: str,
    field: str,
    frame_id: str,
    navigation_generation: str,
    fence: str,
    epoch: int,
    expiry_challenge: bytes,
    expiry_offset_ms: int,
    requester_instance: str,
    task_id: str,
    operation_id: str,
    resource_handle: str,
) -> bytes:
    """Return the canonical associated data for one sealed answer."""
    lines = [
        "cah-sealed-ad/v1",
        f"grant_ref={grant_ref}",
        f"nonce={nonce.hex()}",
        f"tenant={tenant}",
        f"audience={audience}",
        f"recipient_instance={recipient_instance}",
        f"recipient_boot_generation={recipient_boot_generation}",
        f"origin={origin}",
        f"field={field}",
        f"frame_id={frame_id}",
        f"navigation_generation={navigation_generation}",
        f"fence={fence}",
        f"epoch={epoch}",
        f"expiry_challenge={expiry_challenge.hex()}",
        f"expiry_offset_ms={expiry_offset_ms}",
        f"requester_instance={requester_instance}",
        f"task_id={task_id}",
        f"operation_id={operation_id}",
        f"resource_handle={resource_handle}",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _hex32(value: object, label: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} is missing")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} is not hex") from exc
    if len(raw) != 32:
        raise ValueError(f"{label} must be 32 bytes")
    return raw
