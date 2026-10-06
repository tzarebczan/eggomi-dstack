"""Lab X25519, HKDF, and HMAC-based AEAD.

The constructions here are the harness channel and the sealed answer.
They are not a production cipher suite. The static key stays inside the
compartment: that secrecy is the identity boundary.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Tuple

P = 2**255 - 19
_A24 = 121665
BASE_POINT = bytes([9]) + bytes(31)


class KeyDestroyed(ValueError):
    """A wrapped lease key does not match the fence epoch."""


def generate_private() -> bytes:
    """Return a fresh 32-byte X25519 scalar seed."""
    return secrets.token_bytes(32)


def public_key(private: bytes) -> bytes:
    """Return the X25519 public key for ``private``."""
    return x25519(private, BASE_POINT)


def x25519(scalar: bytes, point: bytes) -> bytes:
    """Return the RFC 7748 X25519 shared secret or public key.

    Inputs are 32-byte strings. The scalar is clamped the way RFC 7748
    specifies.
    """
    if len(scalar) != 32 or len(point) != 32:
        raise ValueError("x25519 inputs must be 32 bytes")
    k = _decode_scalar(scalar)
    x1 = _decode_u(point)
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for bit in range(254, -1, -1):
        kt = (k >> bit) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        mont_a = (x2 + z2) % P
        aa = (mont_a * mont_a) % P
        mont_b = (x2 - z2) % P
        bb = (mont_b * mont_b) % P
        e_val = (aa - bb) % P
        mont_c = (x3 + z3) % P
        mont_d = (x3 - z3) % P
        da = (mont_d * mont_a) % P
        cb = (mont_c * mont_b) % P
        x3 = ((da + cb) * (da + cb)) % P
        z3 = (x1 * (da - cb) * (da - cb)) % P
        x2 = (aa * bb) % P
        z2 = (e_val * (aa + _A24 * e_val)) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    out = _encode_u((x2 * pow(z2, P - 2, P)) % P)
    if out == b"\x00" * 32:
        raise ValueError("x25519 output is all zeros")
    return out


def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """Return HKDF-SHA256 output with an empty salt."""
    if length <= 0 or length > 255 * 32:
        raise ValueError("hkdf length is outside 1..8160")
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def aead_seal(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """Encrypt ``plaintext`` and return ``(ciphertext, tag)``.

    The keystream is HMAC-SHA256 in counter mode. The tag is HMAC-SHA256
    over length-prefixed nonce, associated data, and ciphertext. This is a
    lab AEAD for the harness, not a production suite.
    """
    if len(key) != 32:
        raise ValueError("aead key must be 32 bytes")
    if not nonce:
        raise ValueError("aead nonce is empty")
    ciphertext = _xor(plaintext, _keystream(key, nonce, len(plaintext)))
    tag = hmac.new(key, _aead_tag_input(nonce, aad, ciphertext), hashlib.sha256).digest()
    return ciphertext, tag


def aead_open(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Return the plaintext, or raise ``ValueError`` when the tag does not match."""
    if len(key) != 32 or len(tag) != 32:
        raise ValueError("aead open inputs are the wrong size")
    expect = hmac.new(key, _aead_tag_input(nonce, aad, ciphertext), hashlib.sha256).digest()
    if not hmac.compare_digest(expect, tag):
        raise ValueError("aead tag does not match")
    return _xor(ciphertext, _keystream(key, nonce, len(ciphertext)))


def wrap_private(fence_secret: bytes, epoch: int, private: bytes) -> bytes:
    """Wrap a lease key to a fence epoch that lives outside the guard disk."""
    if len(fence_secret) != 32 or len(private) != 32 or epoch < 1:
        raise ValueError("lease wrap inputs are the wrong size")
    mask = hmac.new(
        fence_secret,
        b"cah-lease-wrap/v1" + epoch.to_bytes(8, "big"),
        hashlib.sha256,
    ).digest()
    body = _xor(private, mask)
    mac = hmac.new(
        fence_secret,
        b"cah-lease-mac/v1" + epoch.to_bytes(8, "big") + body,
        hashlib.sha256,
    ).digest()
    return epoch.to_bytes(8, "big") + body + mac


def unwrap_private(fence_secret: bytes, epoch: int, wrapped: bytes) -> bytes:
    """Unwrap a lease key. A different fence epoch destroys the caller's trust in it."""
    if len(wrapped) != 8 + 32 + 32 or len(fence_secret) != 32 or epoch < 1:
        raise KeyDestroyed("wrapped lease key is the wrong size")
    stored_epoch = int.from_bytes(wrapped[:8], "big")
    body = wrapped[8:40]
    mac = wrapped[40:]
    if stored_epoch != epoch:
        raise KeyDestroyed("fence epoch does not match the wrapped lease key")
    expect = hmac.new(
        fence_secret,
        b"cah-lease-mac/v1" + epoch.to_bytes(8, "big") + body,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(expect, mac):
        raise KeyDestroyed("wrapped lease key mac does not match")
    mask = hmac.new(
        fence_secret,
        b"cah-lease-wrap/v1" + epoch.to_bytes(8, "big"),
        hashlib.sha256,
    ).digest()
    return _xor(body, mask)


def _decode_scalar(scalar: bytes) -> int:
    raw = bytearray(scalar)
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    return int.from_bytes(raw, "little")


def _decode_u(point: bytes) -> int:
    raw = bytearray(point)
    raw[31] &= 127
    return int.from_bytes(raw, "little")


def _encode_u(value: int) -> bytes:
    return (value % P).to_bytes(32, "little")


def _aead_tag_input(nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """Return the length-prefixed tag input for the lab AEAD."""
    return b"".join(
        (
            b"cah-aead/v2",
            len(nonce).to_bytes(8, "big"),
            nonce,
            len(aad).to_bytes(8, "big"),
            aad,
            len(ciphertext).to_bytes(8, "big"),
            ciphertext,
        )
    )


def _keystream(key: bytes, nonce: bytes, size: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        block = hmac.new(
            key,
            b"cah-ks/v1" + nonce + counter.to_bytes(4, "big"),
            hashlib.sha256,
        ).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:size])


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))
