"""Host-only tests for the smolvm subVM keeper channel and the leak scanner."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

import host_tools
import keeper_svc
from guard_svc import Guard

SECRET = b"eggomi-s4-unit-secret-0123456789abcdef"
PURPOSE = "https://login.example.test"


class KeeperChannelTest(unittest.TestCase):
    """Keeper and guard over a real loopback TCP keeper channel."""

    def setUp(self) -> None:
        """Start a keeper on loopback and a guard bound to it."""
        self.tmp = Path(tempfile.mkdtemp(prefix="eggomi-subvm-"))
        keys = self.tmp / "keys"
        host_tools.keygen(keys)
        self.keys = keys
        state = self.tmp / "keeper"
        state.mkdir()
        shutil.copy(keys / "keeper.key", state / "keeper.key")
        shutil.copy(keys / "peers.json", state / "peers.json")
        (state / "secret").write_bytes(SECRET + b"\n")
        self.keeper = keeper_svc.Keeper(state)
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.address = "127.0.0.1:%d" % self.listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()
        run = self.tmp / "run"
        run.mkdir()
        shutil.copy(keys / "browser.key", run / "guard.key")
        shutil.copy(keys / "keeper.pub", run / "keeper.pub")
        self.guard = Guard(run, self.tmp / "disk", self.address)

    def tearDown(self) -> None:
        """Remove the temporary state."""
        self.listener.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(
                target=keeper_svc.serve_connection, args=(self.keeper, conn), daemon=True
            ).start()

    def test_guard_key_leaves_tmpfs_and_only_a_wrap_reaches_disk(self) -> None:
        """The installed key is consumed; only its wrap is on disk."""
        self.assertFalse((self.tmp / "run" / "guard.key").exists())
        wrapped = (self.tmp / "disk" / "lease.wrapped").read_bytes()
        self.assertNotIn((self.keys / "browser.key").read_bytes(), wrapped)

    def test_session_is_minted_opened_redeemed_once(self) -> None:
        """A session opens once and redeems once."""
        out = self.guard.session(PURPOSE, 5000, 0, True, 0)
        self.assertEqual(out, {"mint": "ok", "grant_ref": out["grant_ref"],
                               "accept": "filled", "redeem": "ok"})
        token = self.guard.held["token"]
        self.assertEqual(len(token), 64)
        self.assertNotIn(SECRET.decode(), token)
        self.assertEqual(self.guard.redeem_held()["code"], "consumed")
        again = self.guard.reaccept_last()
        self.assertEqual(again["code"], "filled")
        self.assertTrue(again["repeat"])
        self.assertFalse(again["plaintext_returned"])

    def test_expired_at_the_guard(self) -> None:
        """A seal opened after its offset is refused by the guard."""
        out = self.guard.session(PURPOSE, 300, 600, True, 0)
        self.assertEqual(out["accept"], "grant_expired")
        self.assertNotIn("redeem", out)

    def test_expired_at_the_origin(self) -> None:
        """A token presented after its expiry is refused."""
        out = self.guard.session(PURPOSE, 400, 0, True, 700)
        self.assertEqual(out["accept"], "filled")
        self.assertEqual(out["redeem"], "expired")

    def test_deny_by_default(self) -> None:
        """Unknown methods, keys, purposes, and long TTLs are refused."""
        self.assertEqual(self.guard.raw("GetSecret", {}, False)["code"], "denied_method")
        self.assertEqual(self.guard.raw("ListConnections", {}, False)["code"], "denied_method")
        self.assertEqual(self.guard.raw("Ping", {}, True)["code"], "handshake_refused")
        self.assertEqual(
            self.guard.session("https://evil.example", 1000, 0, False, 0)["mint"],
            "denied_purpose",
        )
        self.assertEqual(self.guard.session(PURPOSE, 30_001, 0, False, 0)["mint"], "denied_ttl")

    def test_probe_may_only_ping(self) -> None:
        """The probe role has Ping and nothing else."""
        self.assertTrue(host_tools.ping(self.address, self.keys)["ok"])
        reply = self.keeper.handle("probe", "MintSession", {"purpose": PURPOSE})
        self.assertEqual(reply["error"]["code"], "denied_method")

    def test_wrong_token_is_refused_and_not_consumed(self) -> None:
        """A wrong token does not burn the grant."""
        out = self.guard.session(PURPOSE, 5000, 0, False, 0)
        reply = self.keeper.handle(
            "browser", "Redeem", {"grant_ref": out["grant_ref"], "token": "0" * 64}
        )
        self.assertEqual(reply["error"]["code"], "denied_token")
        self.assertEqual(self.guard.redeem_held()["code"], "ok")

    def test_secret_never_crosses_the_channel(self) -> None:
        """No encoding of the secret is in a reply or the journal."""
        reply = self.keeper.handle(
            "browser",
            "MintSession",
            {"purpose": PURPOSE, "ttl_ms": 1000, "challenge": "11" * 32,
             "operation_id": "op"},
        )
        blob = json.dumps(reply).encode()
        for form in host_tools.encodings(SECRET).values():
            self.assertNotIn(form, blob)
        journal = (self.tmp / "keeper" / "grants.jsonl").read_bytes()
        self.assertNotIn(SECRET, journal)


class ScannerTest(unittest.TestCase):
    """The leak scanner finds every encoding, across chunk edges and holes."""

    def setUp(self) -> None:
        """Write the needle file."""
        self.tmp = Path(tempfile.mkdtemp(prefix="eggomi-scan-"))
        self.needle = self.tmp / "needle"
        self.needle.write_bytes(SECRET + b"\n")

    def tearDown(self) -> None:
        """Remove the temporary state."""
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_chunk_edges(self) -> None:
        """Matches across chunk boundaries are counted once."""
        needles = host_tools.encodings(SECRET)
        data = b"x" * 10 + SECRET + b"y" * 5 + SECRET
        chunks = [data[i : i + 7] for i in range(0, len(data), 7)]
        self.assertEqual(host_tools.count_stream(chunks, needles)["raw"], 2)

    def test_sparse_file_and_encodings(self) -> None:
        """UTF-16LE and hex copies in a sparse file are found."""
        path = self.tmp / "disk.raw"
        with path.open("wb") as handle:
            handle.truncate(64 << 20)
            handle.seek(40 << 20)
            handle.write(SECRET.decode().encode("utf-16-le"))
            handle.seek(50 << 20)
            handle.write(SECRET.hex().encode())
        result = host_tools.scan(SECRET, [path])
        self.assertEqual(result["hits"], {"raw": 0, "utf16le": 1, "hex": 1})

    @unittest.skipUnless(shutil.which("zstd"), "zstd is not installed")
    def test_checkpoint_container(self) -> None:
        """A secret inside a checkpoint payload is found."""
        payload = subprocess.run(
            ["zstd", "-q", "-c"], input=b"\0" * 4096 + SECRET + b"\0" * 4096,
            stdout=subprocess.PIPE, check=True,
        ).stdout
        manifest = json.dumps({"checkpoint": {"version": 4}}).encode()
        footer = struct.pack(
            "<8sIQQQQQI", b"SMOLPACK", 1, 0, 0, len(payload), len(payload),
            len(manifest), 0,
        ).ljust(64, b"\0")
        path = self.tmp / "vm.checkpoint"
        path.write_bytes(payload + manifest + footer)
        self.assertTrue(host_tools.is_checkpoint(path))
        result = host_tools.scan(SECRET, [path])
        self.assertEqual(result["hits"]["raw"], 1)
        self.assertEqual(result["files_with_hits"][str(path)]["kind"], "checkpoint")

    def test_clean_tree(self) -> None:
        """Random data has no hits."""
        (self.tmp / "a").write_bytes(os.urandom(1 << 16))
        result = host_tools.scan(SECRET, [self.tmp / "a"])
        self.assertEqual(result["hits"], {"raw": 0, "utf16le": 0, "hex": 0})
        self.assertEqual(result["files_scanned"], 1)


if __name__ == "__main__":
    unittest.main()
