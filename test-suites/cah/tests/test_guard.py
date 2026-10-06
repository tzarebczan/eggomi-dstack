"""Guard single-use, expiry, and fence checks."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from cah.crypto_lab import generate_private, public_key, wrap_private
from cah.guard import GuardStore
from cah.seal import LiveBinding, open_credential, seal_credential


def _live(**overrides: object) -> LiveBinding:
    values: dict[str, object] = {
        "tenant": "tenant-lab-1",
        "audience": "aa" * 32,
        "recipient_instance": "browser-1",
        "recipient_boot_generation": 1,
        "origin": "https://lab.invalid/signin",
        "field": "password",
        "frame_id": "frame-1",
        "navigation_generation": "nav-1",
        "fence": "fence-browser-1",
        "epoch": 1,
        "requester_instance": "omi-1",
        "task_id": "task-lab-1",
        "operation_id": "op-positive",
        "resource_handle": "cred-lab-1",
        "challenge": bytes(range(32)),
        "challenge_mono": 1_000.0,
    }
    values.update(overrides)
    return LiveBinding(**values)  # type: ignore[arg-type]


def _seal(public: bytes, **overrides: object) -> dict[str, object]:
    live = _live(**overrides)
    return seal_credential(
        public,
        b"cah-synthetic-fill-v1",
        grant_ref="grant-1",
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
        expiry_offset_ms=5_000,
        requester_instance=live.requester_instance,
        task_id=live.task_id,
        operation_id=live.operation_id,
        resource_handle=live.resource_handle,
    )


class GuardTests(unittest.TestCase):
    """The fence, not the guard disk, is the consumed-set authority."""

    def test_repeat_and_crash_do_not_fill_twice(self) -> None:
        """A recorded nonce returns the recorded outcome and no second plaintext."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, store = _store(root, epoch=1)
            blob = _seal(public_key(private))
            live = _live()
            first = store.accept(blob, live, now_mono=1_001.0)
            self.assertEqual(first.get("fill"), "cah-synthetic-fill-v1")
            again = store.accept(blob, live, now_mono=1_001.0)
            self.assertTrue(again.get("repeat"))
            self.assertNotIn("fill", again)
            self.assertEqual(again["code"], "filled")

    def test_crash_after_record_is_unknown(self) -> None:
        """A crash between the durable record and the fill is unknown."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, store = _store(root, epoch=1)
            blob = _seal(public_key(private))
            live = _live()
            crashed = store.accept(blob, live, now_mono=1_001.0, crash_after_record=True)
            self.assertEqual(crashed["code"], "unknown")
            self.assertNotIn("fill", crashed)
            later = store.accept(blob, live, now_mono=1_001.0)
            self.assertEqual(later["code"], "unknown")
            self.assertNotIn("fill", later)
            self.assertEqual(store.lookup("grant-1", str(blob["nonce"])), "unknown")

    def test_snapshot_of_the_guard_disk_does_not_revive_consume(self) -> None:
        """Restoring the wrapped key does not clear the fence journal."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, store = _store(root, epoch=1)
            wrapped = root / "channel.key.wrapped"
            snapshot = root / "snapshot"
            shutil.copyfile(wrapped, snapshot)
            blob = _seal(public_key(private))
            live = _live()
            self.assertTrue(store.accept(blob, live, now_mono=1_001.0)["ok"])
            shutil.copyfile(snapshot, wrapped)
            restored = store.accept(blob, live, now_mono=1_001.0)
            self.assertNotIn("fill", restored)
            self.assertEqual(restored["code"], "filled")

    def test_epoch_mismatch_destroys_the_wrapped_key(self) -> None:
        """A fence epoch that moved deletes the wrapped lease key."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, store = _store(root, epoch=1)
            (root / "fence" / "epoch").write_text("2\n", encoding="utf-8")
            blob = _seal(public_key(private))
            refused = store.accept(blob, _live(), now_mono=1_001.0)
            self.assertEqual(refused["code"], "denied_recipient")
            self.assertFalse((root / "channel.key.wrapped").exists())

    def test_expiry_uses_the_guard_clock(self) -> None:
        """A keeper wall clock is not consulted. The guard monotonic clock is."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, store = _store(root, epoch=1)
            blob = _seal(public_key(private))
            fresh = store.accept(blob, _live(), now_mono=1_001.0)
            self.assertTrue(fresh["ok"])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, store = _store(root, epoch=1)
            blob = _seal(public_key(private))
            expired = store.accept(blob, _live(), now_mono=1_020.0)
            self.assertEqual(expired["code"], "grant_expired")
            self.assertFalse((root / "fence" / "consumed.jsonl").exists())

    def test_operation_mismatch_does_not_fill(self) -> None:
        """The guard checks the operation it is running, not the sealed header."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, store = _store(root, epoch=1)
            blob = _seal(public_key(private))
            opened = open_credential(private, blob, _live())
            self.assertEqual(opened, b"cah-synthetic-fill-v1")
            refused = store.accept(
                blob, _live(operation_id="op-other"), now_mono=1_001.0
            )
            self.assertEqual(refused["code"], "denied_payload")
            self.assertFalse((root / "fence" / "consumed.jsonl").exists())


def _store(root: Path, epoch: int) -> tuple[bytes, GuardStore]:
    private = generate_private()
    fence = root / "fence"
    fence.mkdir()
    secret = generate_private()
    (fence / "secret").write_bytes(secret)
    (fence / "epoch").write_text(f"{epoch}\n", encoding="utf-8")
    wrapped = root / "channel.key.wrapped"
    wrapped.write_bytes(wrap_private(secret, epoch, private))
    return private, GuardStore(fence, wrapped)


if __name__ == "__main__":
    unittest.main()
