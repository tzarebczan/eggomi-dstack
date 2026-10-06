"""Noise_KK_25519_ChaChaPoly_SHA256 for the compartment channel.

The Noise Protocol Framework, revision 34, only the KK pattern and only this
cipher suite. Each side knows the other's static key before the handshake:

    KK:
      -> s
      <- s
      ...
      -> e, es, ss
      <- e, ee, se

The primitives are the ``cryptography`` package's X25519 and
ChaCha20-Poly1305, plus ``hashlib`` and ``hmac`` for SHA-256. Readings of the
spec this module shares with Eggomi's ``packages/noise``:

- The nonce is a u64. ``2**64 - 1`` is reserved, so an encrypt or decrypt at
  that value fails and the session is spent (section 5.1).
- A failed decrypt leaves the nonce where it was. The channel closes anyway.
- A DH whose result is all zeros is refused.
- A message over 65 535 bytes is refused before it is written or read.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PROTOCOL_NAME = b"Noise_KK_25519_ChaChaPoly_SHA256"
DHLEN = 32
HASHLEN = 32
TAGLEN = 16
MAX_MESSAGE = 65535
MAX_NONCE = 2**64 - 1
_EMPTY = b""


class NoiseError(ValueError):
    """A handshake or transport step failed. ``code`` names the reason."""

    def __init__(self, code: str, message: str) -> None:
        """Record ``code``: decrypt, nonce, size, key or state."""
        super().__init__(message)
        self.code = code


def public_from_private(private: bytes) -> bytes:
    """Return the X25519 public key for a 32-byte private key."""
    if len(private) != DHLEN:
        raise NoiseError("key", "an X25519 key is 32 bytes")
    key = X25519PrivateKey.from_private_bytes(private)
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _dh(private: bytes, public: bytes) -> bytes:
    if len(private) != DHLEN or len(public) != DHLEN:
        raise NoiseError("key", "an X25519 key is 32 bytes")
    try:
        out = X25519PrivateKey.from_private_bytes(private).exchange(
            X25519PublicKey.from_public_bytes(public)
        )
    except ValueError as exc:
        raise NoiseError("key", "the DH came out all zeros") from exc
    if out == bytes(DHLEN):
        raise NoiseError("key", "the DH came out all zeros")
    return out


def _nonce(n: int) -> bytes:
    """ChaChaPoly's nonce: 32 bits of zeros, then ``n`` as a little-endian u64."""
    return bytes(4) + n.to_bytes(8, "little")


def _hkdf2(chaining_key: bytes, ikm: bytes) -> Tuple[bytes, bytes]:
    temp = hmac.new(chaining_key, ikm, hashlib.sha256).digest()
    out1 = hmac.new(temp, b"\x01", hashlib.sha256).digest()
    out2 = hmac.new(temp, out1 + b"\x02", hashlib.sha256).digest()
    return out1, out2


class CipherState:
    """Section 5.1. One direction of a transport, or the handshake cipher."""

    def __init__(self, key: Optional[bytes] = None) -> None:
        """Start with ``key``, or with no key (plaintext passthrough)."""
        self._key: Optional[bytes] = None
        self.n = 0
        if key is not None:
            self.initialize_key(key)

    def initialize_key(self, key: bytes) -> None:
        """Install ``key`` and reset the nonce."""
        if len(key) != 32:
            raise NoiseError("key", "a cipher key is 32 bytes")
        self._key = bytes(key)
        self.n = 0

    def has_key(self) -> bool:
        """Return whether a key is installed."""
        return self._key is not None

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        """Encrypt under the next nonce."""
        if self._key is None:
            return bytes(plaintext)
        if self.n >= MAX_NONCE:
            raise NoiseError("nonce", "the nonce space is spent")
        out = ChaCha20Poly1305(self._key).encrypt(_nonce(self.n), plaintext, ad)
        self.n += 1
        return out

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        """Decrypt under the next nonce. A failure leaves the nonce unchanged."""
        if self._key is None:
            return bytes(ciphertext)
        if self.n >= MAX_NONCE:
            raise NoiseError("nonce", "the nonce space is spent")
        if len(ciphertext) < TAGLEN:
            raise NoiseError("decrypt", "shorter than a tag")
        try:
            out = ChaCha20Poly1305(self._key).decrypt(_nonce(self.n), ciphertext, ad)
        except InvalidTag as exc:
            raise NoiseError("decrypt", "the message does not authenticate") from exc
        self.n += 1
        return out


class _SymmetricState:
    """Section 5.2."""

    def __init__(self, protocol_name: bytes) -> None:
        if len(protocol_name) <= HASHLEN:
            self.h = protocol_name + bytes(HASHLEN - len(protocol_name))
        else:
            self.h = hashlib.sha256(protocol_name).digest()
        self.ck = self.h
        self.cipher = CipherState()

    def mix_key(self, ikm: bytes) -> None:
        self.ck, key = _hkdf2(self.ck, ikm)
        self.cipher.initialize_key(key)

    def mix_hash(self, data: bytes) -> None:
        self.h = hashlib.sha256(self.h + data).digest()

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self.cipher.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self.cipher.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> Tuple[CipherState, CipherState]:
        """Initiator-to-responder first, then responder-to-initiator."""
        k1, k2 = _hkdf2(self.ck, _EMPTY)
        return CipherState(k1), CipherState(k2)


@dataclass
class Transport:
    """A finished handshake: both directions and the handshake hash."""

    send: CipherState
    receive: CipherState
    handshake_hash: bytes


def _kk_symmetric(
    prologue: bytes, initiator_static: bytes, responder_static: bytes
) -> _SymmetricState:
    state = _SymmetricState(PROTOCOL_NAME)
    state.mix_hash(prologue)
    state.mix_hash(initiator_static)
    state.mix_hash(responder_static)
    return state


def _ephemeral(given: Optional[bytes]) -> Tuple[bytes, bytes]:
    private = secrets.token_bytes(DHLEN) if given is None else bytes(given)
    return private, public_from_private(private)


def _check_size(message: bytes) -> None:
    if len(message) > MAX_MESSAGE:
        raise NoiseError("size", "over 65 535 bytes")


class _Steps:
    """Run handshake steps in order. A failed step spends the handshake."""

    def __init__(self) -> None:
        self.step = "first"

    def advance(self, expect: str, nxt: str) -> None:
        if self.step != expect:
            raise NoiseError("state", "handshake step out of order")
        self.step = nxt


class KkInitiator:
    """The workload: writes ``-> e, es, ss`` and reads ``<- e, ee, se``."""

    def __init__(
        self,
        *,
        prologue: bytes,
        static_private: bytes,
        remote_static: bytes,
        ephemeral: Optional[bytes] = None,
    ) -> None:
        """``ephemeral`` is for vectors only. Left out, it is fresh."""
        if len(remote_static) != DHLEN:
            raise NoiseError("key", "a remote static key is 32 bytes")
        self._s = bytes(static_private)
        self._rs = bytes(remote_static)
        self._e, self._e_pub = _ephemeral(ephemeral)
        self._ss = _kk_symmetric(prologue, public_from_private(self._s), self._rs)
        self._steps = _Steps()

    def write_message1(self, payload: bytes = _EMPTY) -> bytes:
        """Return message 1: the ephemeral key, then the encrypted payload."""
        self._steps.advance("first", "failed")
        self._ss.mix_hash(self._e_pub)
        self._ss.mix_key(_dh(self._e, self._rs))
        self._ss.mix_key(_dh(self._s, self._rs))
        message = self._e_pub + self._ss.encrypt_and_hash(payload)
        _check_size(message)
        self._steps.step = "second"
        return message

    def read_message2(self, message: bytes) -> Tuple[bytes, Transport]:
        """Read message 2 and return its payload and the transport."""
        self._steps.advance("second", "failed")
        _check_size(message)
        if len(message) < DHLEN + TAGLEN:
            raise NoiseError("size", "shorter than a handshake message")
        re = bytes(message[:DHLEN])
        self._ss.mix_hash(re)
        self._ss.mix_key(_dh(self._e, re))
        self._ss.mix_key(_dh(self._s, re))
        payload = self._ss.decrypt_and_hash(bytes(message[DHLEN:]))
        c1, c2 = self._ss.split()
        self._steps.step = "done"
        return payload, Transport(send=c1, receive=c2, handshake_hash=self._ss.h)


class KkResponder:
    """The keeper: reads ``-> e, es, ss`` and writes ``<- e, ee, se``."""

    def __init__(
        self,
        *,
        prologue: bytes,
        static_private: bytes,
        remote_static: bytes,
        ephemeral: Optional[bytes] = None,
    ) -> None:
        """``remote_static`` is the workload's registered key."""
        if len(remote_static) != DHLEN:
            raise NoiseError("key", "a remote static key is 32 bytes")
        self._s = bytes(static_private)
        self._rs = bytes(remote_static)
        self._e, self._e_pub = _ephemeral(ephemeral)
        self._ss = _kk_symmetric(prologue, self._rs, public_from_private(self._s))
        self._re: Optional[bytes] = None
        self._steps = _Steps()

    def read_message1(self, message: bytes) -> bytes:
        """Read message 1. A peer without the registered key fails here."""
        self._steps.advance("first", "failed")
        _check_size(message)
        if len(message) < DHLEN + TAGLEN:
            raise NoiseError("size", "shorter than a handshake message")
        re = bytes(message[:DHLEN])
        self._ss.mix_hash(re)
        self._ss.mix_key(_dh(self._s, re))
        self._ss.mix_key(_dh(self._s, self._rs))
        payload = self._ss.decrypt_and_hash(bytes(message[DHLEN:]))
        self._re = re
        self._steps.step = "second"
        return payload

    def write_message2(self, payload: bytes = _EMPTY) -> Tuple[bytes, Transport]:
        """Return message 2 and the transport."""
        self._steps.advance("second", "failed")
        assert self._re is not None
        self._ss.mix_hash(self._e_pub)
        self._ss.mix_key(_dh(self._e, self._re))
        self._ss.mix_key(_dh(self._e, self._rs))
        message = self._e_pub + self._ss.encrypt_and_hash(payload)
        _check_size(message)
        c1, c2 = self._ss.split()
        self._steps.step = "done"
        return message, Transport(send=c2, receive=c1, handshake_hash=self._ss.h)
