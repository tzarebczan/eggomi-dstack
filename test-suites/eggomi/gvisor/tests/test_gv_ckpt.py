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
import subprocess
import sys
import tempfile
import threading
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

    def test_an_image_whose_deadline_passes_during_restore_is_deleted(self) -> None:
        """The lock blocks the reaper, so restore reaps before releasing it."""
        self.run_cmd("arm", "browser")
        self.run_cmd("filled", "browser", str(gv_ckpt.now_ms() + 300))
        self.run_cmd("create", "--leave-running", "browser", "suspend")
        self.set_running("browser", False)
        os.environ["FAKE_DOCKER_RESTORE_DELAY"] = "0.5"
        try:
            rc, out = self.run_cmd("restore", "browser", "suspend")
        finally:
            del os.environ["FAKE_DOCKER_RESTORE_DELAY"]
        self.assertEqual((rc, out["image_deleted_at_deadline"]), (0, True))
        self.assertFalse(self.image("suspend").exists())

    def test_the_sleeping_reaper_sees_a_deadline_added_later(self) -> None:
        """A post-fill image created while the reaper sleeps is reaped on time."""
        stop = threading.Event()
        thread = threading.Thread(target=gv_ckpt.reap_loop, args=(60.0, stop))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            thread.start()
            try:
                time.sleep(0.3)  # the reaper has reaped once and is sleeping
                self.run_cmd("arm", "browser")
                self.run_cmd("filled", "browser", str(gv_ckpt.now_ms() + 400))
                self.run_cmd("create", "--leave-running", "browser", "suspend")
                self.assertTrue(self.image("suspend").exists())
                deadline = time.time() + 3
                while self.image("suspend").exists() and time.time() < deadline:
                    time.sleep(0.05)
            finally:
                stop.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
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

    def test_reap_keeps_state_when_dockerd_does_not_answer(self) -> None:
        """Only a definite "No such container" drops a container's state."""
        self.run_cmd("arm", "browser")
        self.run_cmd("create", "--reuse", "--leave-running", "browser", "pristine")
        state = self.tmp / "state" / ("c0ffee" * 10 + "abcd.json")
        self.assertTrue(state.exists())
        os.environ["FAKE_DOCKER_DOWN"] = "1"
        try:
            rc, out = self.run_cmd("reap")
        finally:
            del os.environ["FAKE_DOCKER_DOWN"]
        self.assertTrue(state.exists())
        self.assertEqual((rc, out["docker_unanswered"]), (0, ["c0ffee" * 2]))
        # dockerd is back: the pristine record still governs restores.
        self.set_running("browser", False)
        rc, out = self.run_cmd("restore", "browser", "pristine")
        self.assertEqual((rc, out["kind"]), (0, "pristine"))
        # A container that is really gone drops its state.
        db = json.loads(self.db.read_text())
        del db["containers"]["browser"]
        self.db.write_text(json.dumps(db))
        rc, out = self.run_cmd("reap")
        self.assertEqual((rc, out["docker_unanswered"]), (0, []))
        self.assertFalse(state.exists())

    def test_a_docker_timeout_reads_as_unanswered(self) -> None:
        """A hung docker call is not taken for a missing container."""
        saved = gv_ckpt.DOCKER_TIMEOUT_SECONDS
        gv_ckpt.DOCKER_TIMEOUT_SECONDS = 0.2
        os.environ["FAKE_DOCKER_HANG"] = "5"
        try:
            self.assertIsNone(gv_ckpt.container_gone("c0ffee" * 10 + "abcd"))
        finally:
            gv_ckpt.DOCKER_TIMEOUT_SECONDS = saved
            del os.environ["FAKE_DOCKER_HANG"]

    def test_reap_deletes_expired_images_before_any_docker_call(self) -> None:
        """Expiry comes from the record files; a hung dockerd cannot delay it."""
        self.run_cmd("arm", "browser")
        self.run_cmd("create", "--reuse", "--leave-running", "browser", "pristine")
        self.run_cmd("filled", "browser", str(gv_ckpt.now_ms() + 300))
        self.run_cmd("create", "--leave-running", "browser", "suspend")
        time.sleep(0.4)
        seen = []
        real = gv_ckpt.docker

        def watching(*args: str, check: bool = True):
            seen.append((args[:2], self.image("suspend").exists()))
            return real(*args, check=check)

        gv_ckpt.docker = watching
        try:
            rc, out = self.run_cmd("reap")
        finally:
            gv_ckpt.docker = real
        self.assertEqual(rc, 0)
        self.assertTrue(seen, "reap made no docker call at all")
        self.assertFalse(seen[0][1], f"first docker call {seen[0][0]} saw the image")
        self.assertFalse(self.image("suspend").exists())
        self.assertTrue(self.image("pristine").exists())
        self.assertEqual([r["name"] for r in out["reaped"]], ["suspend"])
        state = json.loads(
            (self.tmp / "state" / ("c0ffee" * 10 + "abcd.json")).read_text()
        )
        self.assertEqual(sorted(state["checkpoints"]), ["pristine"])

    def test_the_reaper_expires_on_disk_while_the_lock_is_held(self) -> None:
        """A step stuck on dockerd holds the lock; the deadline still holds."""
        self.run_cmd("arm", "browser")
        self.run_cmd("filled", "browser", str(gv_ckpt.now_ms() + 300))
        self.run_cmd("create", "--leave-running", "browser", "suspend")
        stop = threading.Event()
        thread = threading.Thread(target=gv_ckpt.reap_loop, args=(0.1, stop))
        out = io.StringIO()
        held = threading.Event()
        release = threading.Event()

        def hold() -> None:
            with gv_ckpt.locked():
                held.set()
                release.wait(10)

        holder = threading.Thread(target=hold)
        holder.start()
        held.wait(5)
        try:
            with contextlib.redirect_stdout(out):
                thread.start()
                deadline = time.time() + 3
                while self.image("suspend").exists() and time.time() < deadline:
                    time.sleep(0.05)
                self.assertFalse(self.image("suspend").exists())
        finally:
            release.set()
            holder.join(5)
            stop.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())

    def start_reaper(self) -> "subprocess.Popen[bytes]":
        """Run the reaper as the CVM does: its own process, a short loop."""
        env = dict(
            os.environ,
            EGGOMI_GV_CKPT_STATE=str(gv_ckpt.STATE_DIR),
            EGGOMI_GV_CKPT_DOCKER=gv_ckpt.DOCKER,
            EGGOMI_GV_CKPT_DOCKER_ROOT=str(gv_ckpt.DOCKER_ROOT),
            EGGOMI_GV_CKPT_STAGE=str(gv_ckpt.STAGE_DIR),
        )
        return subprocess.Popen(
            [sys.executable, gv_ckpt.__file__, "reap", "--loop", "0.1"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def test_an_image_still_being_written_is_deleted_at_its_deadline(self) -> None:
        """The record is published first, so a slow create cannot outlive it."""
        self.run_cmd("arm", "browser")
        self.run_cmd("filled", "browser", str(gv_ckpt.now_ms() + 600))
        result = {}

        def create() -> None:
            result["out"] = self.run_cmd("create", "--leave-running", "browser", "s")

        os.environ["FAKE_DOCKER_CREATE_AFTER"] = "2.5"
        reaper = self.start_reaper()
        try:
            creator = threading.Thread(target=create)
            creator.start()
            deadline = time.time() + 1.0
            while not self.image("s").exists() and time.time() < deadline:
                time.sleep(0.02)
            self.assertTrue(self.image("s").exists(), "docker wrote the image")
            deadline = time.time() + 2.0
            while self.image("s").exists() and time.time() < deadline:
                time.sleep(0.05)
            gone_while_writing = not self.image("s").exists()
            still_writing = creator.is_alive()
            creator.join(10)
        finally:
            del os.environ["FAKE_DOCKER_CREATE_AFTER"]
            reaper.kill()
            reaper.wait(5)
        self.assertTrue(still_writing and gone_while_writing)
        rc, reply = result["out"]
        self.assertEqual((rc, reply["code"]), (3, "expired"))
        self.assertFalse(self.image("s").exists())
        state = json.loads(
            (self.tmp / "state" / ("c0ffee" * 10 + "abcd.json")).read_text()
        )
        self.assertEqual(state["checkpoints"], {})

    def test_a_restore_that_outlives_the_deadline_says_so(self) -> None:
        """The lockless pass deletes the image mid-restore; the reply reports it."""
        self.run_cmd("arm", "browser")
        self.run_cmd("filled", "browser", str(gv_ckpt.now_ms() + 400))
        self.run_cmd("create", "--leave-running", "browser", "s")
        self.set_running("browser", False)
        os.environ["FAKE_DOCKER_RESTORE_AFTER"] = "1.0"
        reaper = self.start_reaper()
        try:
            rc, reply = self.run_cmd("restore", "browser", "s")
        finally:
            del os.environ["FAKE_DOCKER_RESTORE_AFTER"]
            reaper.kill()
            reaper.wait(5)
        self.assertEqual(rc, 0, reply)
        self.assertTrue(reply.get("image_deleted_at_deadline"), reply)
        self.assertFalse(self.image("s").exists())

    def test_a_create_that_died_leaves_no_image(self) -> None:
        """A pending record found under the lock is a dead create: reaped."""
        self.run_cmd("arm", "browser")
        state_path = self.tmp / "state" / ("c0ffee" * 10 + "abcd.json")
        state = json.loads(state_path.read_text())
        state["checkpoints"]["half"] = {
            "kind": "pristine",
            "deadline_ms": None,
            "created_ms": gv_ckpt.now_ms(),
            "pending": True,
        }
        state_path.write_text(json.dumps(state))
        self.image("half").mkdir(parents=True)
        self.set_running("browser", False)
        rc, out = self.run_cmd("restore", "browser", "half")
        self.assertEqual((rc, out["code"]), (3, "incomplete"))
        rc, out = self.run_cmd("reap")
        self.assertEqual([r["name"] for r in out["reaped"]], ["half"])
        self.assertFalse(self.image("half").exists())

    def test_a_stopping_checkpoint_sets_the_restart_policy_aside(self) -> None:
        """Without it dockerd restarts the container at once; restore puts it back."""
        db = json.loads(self.db.read_text())
        db["containers"]["browser"]["restart"] = "unless-stopped"
        self.db.write_text(json.dumps(db))
        log = self.tmp / "docker.log"
        os.environ["FAKE_DOCKER_LOG"] = str(log)
        try:
            self.run_cmd("arm", "browser")
            rc, out = self.run_cmd("create", "--reuse", "browser", "pristine")
            self.assertEqual((rc, out["kind"]), (0, "pristine"))
            db = json.loads(self.db.read_text())
            self.assertFalse(db["containers"]["browser"]["running"])
            self.assertEqual(db["containers"]["browser"]["restart"], "no")
            rc, out = self.run_cmd("restore", "browser", "pristine")
            self.assertEqual(rc, 0, out)
            db = json.loads(self.db.read_text())
            self.assertEqual(db["containers"]["browser"]["restart"], "unless-stopped")
            self.assertEqual(
                log.read_text().split(),
                ["update", "--restart=no", "update", "--restart=unless-stopped"],
            )
        finally:
            del os.environ["FAKE_DOCKER_LOG"]

    def test_reap_deletes_every_image_left_over_from_before_a_reboot(self) -> None:
        """A cleared /run leaves images with no record; one pass deletes them."""
        self.run_cmd("arm", "browser")
        self.run_cmd("create", "--reuse", "--leave-running", "browser", "pristine")
        self.run_cmd("filled", "browser", str(gv_ckpt.now_ms() + 600_000))
        self.run_cmd("create", "--leave-running", "browser", "suspend")
        # An image of a container this boot never saw at all.
        other = gv_ckpt.checkpoint_dir("f" * 64, "filled")
        other.mkdir(parents=True)
        (other / "pages.img").write_bytes(b"filled session")
        # The reboot: tmpfs state is gone, the data disk is not.
        for path in (self.tmp / "state").glob("*.json"):
            path.unlink()
        rc, out = self.run_cmd("reap")
        self.assertEqual(rc, 0)
        self.assertFalse(self.image("suspend").exists())
        self.assertFalse(self.image("pristine").exists())
        self.assertFalse(other.exists())
        self.assertEqual(
            sorted(r["name"] for r in out["reaped"] if r.get("orphan")),
            ["filled", "pristine", "suspend"],
        )

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
