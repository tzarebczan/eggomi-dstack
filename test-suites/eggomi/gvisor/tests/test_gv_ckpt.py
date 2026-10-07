"""Host-only tests for gv-ckpt, the CVM's browser checkpoint policy."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

import gv_ckpt

HERE = Path(__file__).resolve().parent


class GvCkptTest(unittest.TestCase):
    """The pristine rule, the restore residue, and the reaper, on a fake docker."""

    def setUp(self) -> None:
        """Point gv-ckpt at a scratch state dir, docker root, and stage dir."""
        self.tmp = Path(tempfile.mkdtemp(prefix="gv-ckpt-"))
        for name in ("state", "docker", "stage"):
            (self.tmp / name).mkdir()
        self.db = self.tmp / "db.json"
        self.add_container("browser", "c0ffee" * 10 + "abcd")
        os.environ.update(
            FAKE_DOCKER_DB=str(self.db),
            FAKE_DOCKER_ROOT=str(self.tmp / "docker"),
            FAKE_DOCKER_STAGE=str(self.tmp / "stage"),
        )
        self.saved = {
            k: getattr(gv_ckpt, k)
            for k in ("STATE_DIR", "DOCKER", "DOCKER_ROOT", "STAGE_DIR")
        }
        gv_ckpt.STATE_DIR = self.tmp / "state"
        gv_ckpt.DOCKER = str(HERE / "fake_docker.py")
        gv_ckpt.DOCKER_ROOT = self.tmp / "docker"
        gv_ckpt.STAGE_DIR = self.tmp / "stage"

    def tearDown(self) -> None:
        """Restore the module and remove the scratch tree."""
        for k, v in self.saved.items():
            setattr(gv_ckpt, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def add_container(self, name: str, cid: str, created: str | None = None) -> None:
        """Register a running container with the fake docker."""
        db = json.loads(self.db.read_text()) if self.db.exists() else {"containers": {}}
        now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        db["containers"][name] = {
            "id": cid,
            "created": created or now + ".123456789Z",
            "started": now + ".223456789Z",
            "running": True,
        }
        self.db.write_text(json.dumps(db))

    def set_running(self, name: str, running: bool) -> None:
        """Stop or start a fake container without a checkpoint."""
        db = json.loads(self.db.read_text())
        db["containers"][name]["running"] = running
        self.db.write_text(json.dumps(db))

    def run_cmd(self, *argv: str) -> tuple:
        """Run gv-ckpt; return (exit status, JSON reply)."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = gv_ckpt.main(list(argv))
        return rc, json.loads(out.getvalue())

    def image(self, name: str) -> Path:
        """Where the fake docker keeps the browser's checkpoint NAME."""
        return gv_ckpt.checkpoint_dir("c0ffee" * 10 + "abcd", name)

    def test_pristine_reuse_then_refused_after_fill(self) -> None:
        """A reuse checkpoint is allowed before the first fill and refused after."""
        self.assertEqual(self.run_cmd("arm", "browser")[0], 0)
        rc, out = self.run_cmd(
            "create", "--reuse", "--leave-running", "browser", "pristine"
        )
        self.assertEqual((rc, out["kind"]), (0, "pristine"))
        expires = gv_ckpt.now_ms() + 30_000
        rc, out = self.run_cmd("filled", "browser", str(expires))
        self.assertEqual((rc, out["deadline_ms"]), (0, expires))
        rc, out = self.run_cmd(
            "create", "--reuse", "--leave-running", "browser", "again"
        )
        self.assertEqual((rc, out["code"]), (3, "not_pristine"))
        self.assertFalse(self.image("again").exists())
        rc, out = self.run_cmd("create", "--leave-running", "browser", "suspend")
        self.assertEqual(
            (rc, out["kind"], out["deadline_ms"]), (0, "post_fill", expires)
        )

    def test_restore_removes_the_staged_copy(self) -> None:
        """The copy containerd stages in /tmp is gone when restore returns."""
        self.run_cmd("arm", "browser")
        self.run_cmd("create", "--reuse", "--leave-running", "browser", "pristine")
        self.set_running("browser", False)
        rc, out = self.run_cmd("restore", "browser", "pristine")
        self.assertEqual(rc, 0, out)
        self.assertEqual((out["staged_copies_removed"], out["residue"]), (1, 0))
        self.assertGreater(out["staged_bytes"], 0)
        self.assertEqual(list((self.tmp / "stage").iterdir()), [])
        # Restored from a pristine image, the browser is pristine again.
        rc, out = self.run_cmd(
            "create", "--reuse", "--leave-running", "browser", "pristine-2"
        )
        self.assertEqual((rc, out["kind"]), (0, "pristine"))

    def test_post_fill_image_deleted_and_refused_at_expiry(self) -> None:
        """The reaper deletes post-fill images at the deadline; restore refuses them."""
        self.run_cmd("arm", "browser")
        self.run_cmd("create", "--reuse", "--leave-running", "browser", "pristine")
        self.run_cmd("filled", "browser", str(gv_ckpt.now_ms() + 300))
        self.run_cmd("create", "--leave-running", "browser", "suspend-a")
        self.run_cmd("create", "--leave-running", "browser", "suspend-b")
        time.sleep(0.4)
        rc, out = self.run_cmd("reap")
        self.assertEqual(rc, 0)
        self.assertEqual(
            sorted(r["name"] for r in out["reaped"]), ["suspend-a", "suspend-b"]
        )
        self.assertFalse(self.image("suspend-a").exists())
        self.assertTrue(self.image("pristine").exists())
        self.set_running("browser", False)
        rc, out = self.run_cmd("restore", "browser", "suspend-a")
        self.assertEqual((rc, out["code"]), (3, "unknown_checkpoint"))

    def test_restore_refuses_and_deletes_an_expired_image_without_the_reaper(
        self,
    ) -> None:
        """Restore itself enforces the deadline, even if the reaper lags."""
        self.run_cmd("arm", "browser")
        self.run_cmd("filled", "browser", str(gv_ckpt.now_ms() + 300))
        self.run_cmd("create", "--leave-running", "browser", "suspend")
        self.set_running("browser", False)
        time.sleep(0.4)
        rc, out = self.run_cmd("restore", "browser", "suspend")
        self.assertEqual((rc, out["code"], out["deleted"]), (3, "expired", True))
        self.assertFalse(self.image("suspend").exists())

    def test_a_suspend_restored_before_expiry_keeps_the_deadline(self) -> None:
        """A post-fill suspend restores before expiry and stays post-fill."""
        self.run_cmd("arm", "browser")
        expires = gv_ckpt.now_ms() + 30_000
        self.run_cmd("filled", "browser", str(expires))
        self.run_cmd("create", "--leave-running", "browser", "suspend")
        self.set_running("browser", False)
        rc, out = self.run_cmd("restore", "browser", "suspend")
        self.assertEqual((rc, out["kind"]), (0, "post_fill"))
        rc, out = self.run_cmd("create", "--reuse", "--leave-running", "browser", "x")
        self.assertEqual((rc, out["code"]), (3, "not_pristine"))
        rc, out = self.run_cmd("create", "--leave-running", "browser", "y")
        self.assertEqual((rc, out["deadline_ms"]), (0, expires))

    def test_arm_refuses_a_filled_or_stale_container(self) -> None:
        """Only a container that never filled, created this boot, can be pristine."""
        self.run_cmd("arm", "browser")
        self.run_cmd("filled", "browser", str(gv_ckpt.now_ms() + 1000))
        self.assertEqual(self.run_cmd("arm", "browser")[1]["code"], "not_pristine")
        self.add_container("old", "0" * 64, created="2000-01-01T00:00:00Z")
        self.assertEqual(self.run_cmd("arm", "old")[1]["code"], "stale_container")

    def test_unknown_or_unarmed_images_are_refused(self) -> None:
        """Images the tool did not make, and runs it did not arm, are refused."""
        rc, out = self.run_cmd("create", "--reuse", "--leave-running", "browser", "x")
        self.assertEqual((rc, out["code"]), (3, "unarmed"))
        d = self.image("raw")
        d.mkdir(parents=True)
        self.set_running("browser", False)
        rc, out = self.run_cmd("restore", "browser", "raw")
        self.assertEqual((rc, out["code"]), (3, "unknown_checkpoint"))
        self.assertEqual(
            self.run_cmd("create", "browser", "../x")[1]["code"], "bad_name"
        )
        self.assertEqual(
            self.run_cmd("filled", "browser", str(gv_ckpt.now_ms() + 10**8))[1]["code"],
            "ttl_too_long",
        )

    def test_reap_deletes_unrecorded_checkpoints_of_a_tracked_browser(self) -> None:
        """A raw docker checkpoint of a tracked browser is deleted on sight."""
        self.run_cmd("arm", "browser")
        self.run_cmd("create", "--reuse", "--leave-running", "browser", "pristine")
        raw = self.image("raw")
        raw.mkdir(parents=True)
        (raw / "pages.img").write_bytes(b"filled session")
        rc, out = self.run_cmd("reap")
        self.assertEqual(rc, 0)
        self.assertEqual([r["name"] for r in out["reaped"]], ["raw"])
        self.assertTrue(out["reaped"][0]["unrecorded"])
        self.assertFalse(raw.exists())
        self.assertTrue(self.image("pristine").exists())

    def test_reap_removes_stale_staged_copies(self) -> None:
        """A staged copy a raw restore left behind goes after a minute."""
        stale = self.tmp / "stage" / "ctrd-checkpoint-raw"
        fresh = self.tmp / "stage" / "ctrd-checkpoint-new"
        for d in (stale, fresh):
            d.mkdir()
            (d / "pages.img").write_bytes(b"x")
        old = time.time() - 120
        os.utime(stale, (old, old))
        rc, out = self.run_cmd("reap")
        self.assertEqual((rc, out["stale_stage_removed"]), (0, 1))
        self.assertFalse(stale.exists())
        self.assertTrue(fresh.exists())

    def test_parse_time_takes_nanoseconds(self) -> None:
        """Docker's nanosecond timestamps parse to epoch seconds."""
        self.assertAlmostEqual(
            gv_ckpt.parse_time("1970-01-01T00:00:01.500000000Z"), 1.5
        )
        self.assertAlmostEqual(gv_ckpt.parse_time("1970-01-01T01:00:01+01:00"), 1.0)


if __name__ == "__main__":
    unittest.main()
