"""Noise_KK_25519_ChaChaPoly_SHA256 against the official KK vectors."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import unittest
from pathlib import Path

from cah.noise import (
    MAX_NONCE,
    PROTOCOL_NAME,
    CipherState,
    KkInitiator,
    KkResponder,
    NoiseError,
    public_from_private,
)

VECTORS = Path(__file__).resolve().parents[1] / "vectors" / "noise-kk-upstream.json"


def _h(value: str) -> bytes:
    return bytes.fromhex(value)


class KkVectorTests(unittest.TestCase):
    """The handshake, the handshake hash and every transport message."""

    def test_official_vectors(self) -> None:
        """The cacophony and snow vectors, as Eggomi's packages/noise runs them."""
        upstream = json.loads(VECTORS.read_text(encoding="utf-8"))["upstream"]
        self.assertEqual(len(upstream), 2)
        for vector in upstream:
            with self.subTest(source=vector["source"]):
                self.assertEqual(vector["protocol_name"], PROTOCOL_NAME.decode())
                self.assertRegex(
                    vector["source"], r"^https://github\.com/.+/blob/[0-9a-f]{40}/"
                )
                initiator = KkInitiator(
                    prologue=_h(vector["init_prologue"]),
                    static_private=_h(vector["init_static"]),
                    remote_static=_h(vector["init_remote_static"]),
                    ephemeral=_h(vector["init_ephemeral"]),
                )
                responder = KkResponder(
                    prologue=_h(vector["resp_prologue"]),
                    static_private=_h(vector["resp_static"]),
                    remote_static=_h(vector["resp_remote_static"]),
                    ephemeral=_h(vector["resp_ephemeral"]),
                )
                m1, m2, *rest = vector["messages"]
                self.assertEqual(
                    initiator.write_message1(_h(m1["payload"])).hex(), m1["ciphertext"]
                )
                self.assertEqual(
                    responder.read_message1(_h(m1["ciphertext"])).hex(), m1["payload"]
                )
                message, responder_t = responder.write_message2(_h(m2["payload"]))
                self.assertEqual(message.hex(), m2["ciphertext"])
                payload, initiator_t = initiator.read_message2(message)
                self.assertEqual(payload.hex(), m2["payload"])
                if "handshake_hash" in vector:
                    self.assertEqual(
                        initiator_t.handshake_hash.hex(), vector["handshake_hash"]
                    )
                    self.assertEqual(
                        responder_t.handshake_hash.hex(), vector["handshake_hash"]
                    )
                for index, item in enumerate(rest):
                    sender, receiver = (
                        (initiator_t, responder_t)
                        if index % 2 == 0
                        else (responder_t, initiator_t)
                    )
                    ciphertext = sender.send.encrypt_with_ad(b"", _h(item["payload"]))
                    self.assertEqual(ciphertext.hex(), item["ciphertext"])
                    self.assertEqual(
                        receiver.receive.decrypt_with_ad(b"", ciphertext).hex(),
                        item["payload"],
                    )


class KkRefusalTests(unittest.TestCase):
    """What the vectors do not pin."""

    def test_wrong_initiator_static_is_refused(self) -> None:
        """The responder expects another workload key: message 1 fails."""
        keeper = b"\x11" * 32
        initiator = KkInitiator(
            prologue=b"p",
            static_private=b"\x22" * 32,
            remote_static=public_from_private(keeper),
        )
        responder = KkResponder(
            prologue=b"p",
            static_private=keeper,
            remote_static=public_from_private(b"\x33" * 32),
        )
        with self.assertRaises(NoiseError) as caught:
            responder.read_message1(initiator.write_message1())
        self.assertEqual(caught.exception.code, "decrypt")

    def test_prologue_mismatch_is_refused(self) -> None:
        """Both sides must bind eggomi/cah-channel/v1."""
        keeper = b"\x11" * 32
        workload = b"\x22" * 32
        initiator = KkInitiator(
            prologue=b"eggomi/cah-channel/v1",
            static_private=workload,
            remote_static=public_from_private(keeper),
        )
        responder = KkResponder(
            prologue=b"cah-channel/v1",
            static_private=keeper,
            remote_static=public_from_private(workload),
        )
        with self.assertRaises(NoiseError):
            responder.read_message1(initiator.write_message1())

    def test_steps_run_once_and_in_order(self) -> None:
        """A second message 1 is a state error."""
        initiator = KkInitiator(
            prologue=b"",
            static_private=b"\x22" * 32,
            remote_static=public_from_private(b"\x11" * 32),
        )
        initiator.write_message1()
        with self.assertRaises(NoiseError) as caught:
            initiator.write_message1()
        self.assertEqual(caught.exception.code, "state")

    def test_low_order_point_is_refused(self) -> None:
        """An all-zero DH result is refused."""
        with self.assertRaises(NoiseError) as caught:
            KkInitiator(
                prologue=b"",
                static_private=b"\x22" * 32,
                remote_static=bytes(32),
            ).write_message1()
        self.assertEqual(caught.exception.code, "key")

    def test_reserved_nonce_is_refused(self) -> None:
        """2**64 - 1 is never used for a message."""
        cipher = CipherState(b"\x01" * 32)
        cipher.n = MAX_NONCE
        with self.assertRaises(NoiseError) as caught:
            cipher.encrypt_with_ad(b"", b"x")
        self.assertEqual(caught.exception.code, "nonce")

    def test_failed_decrypt_keeps_the_nonce(self) -> None:
        """Section 5.1: n does not advance on a failure."""
        cipher = CipherState(b"\x01" * 32)
        with self.assertRaises(NoiseError):
            cipher.decrypt_with_ad(b"", b"\x00" * 20)
        self.assertEqual(cipher.n, 0)


if __name__ == "__main__":
    unittest.main()
