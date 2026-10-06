"""The launcher signs every registry row, and an unsigned row is no identity."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

from cah.auth import authenticate_unix
from cah.launcher import (
    KEY_OWNERS,
    KeyAlreadyBound,
    LauncherSigner,
    RowNotSignable,
    js_json,
    launcher_dir,
    row_attributed,
    row_message,
)
from cah.registry import (
    AdmissionRegistry,
    bind_process,
    load_registry,
    rebind_channel,
    save_registry,
)

TD = "lab.cah"
TENANT = "tenant-lab-1"


def _row(instance: str = "browser-1", channel: str = "ab" * 32) -> Dict[str, Any]:
    return {
        "role": "browser-guard",
        "instance_id": instance,
        "boot_id": f"boot-{instance}",
        "boot_generation": 1,
        "boot_history": [f"boot-{instance}"],
        "cert_fingerprint": None,
        "pid": None,
        "starttime": None,
        "channel_public": channel,
    }


def _save(path: Path, rows: List[Dict[str, Any]]) -> None:
    save_registry(path, AdmissionRegistry(trust_domain=TD, tenant=TENANT, workloads=rows))


def _rewrite(path: Path, mutate: Any) -> None:
    """Edit the file as a writer other than the launcher would."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    mutate(raw["workloads"])
    path.write_text(json.dumps(raw), encoding="utf-8")


class RowMessageTests(unittest.TestCase):
    """The signed bytes are Eggomi's rowMessage."""

    def test_row_message_is_the_domain_line_and_a_compact_array(self) -> None:
        """Field order, nulls and integers follow registry.ts exactly."""
        row = _row()
        row.update({"pid": 4242, "starttime": 99, "cert_fingerprint": "fp-1"})
        message = row_message(TD, TENANT, row)
        expect = (
            'eggomi/admission-row/v1\n["lab.cah","tenant-lab-1","browser-guard",'
            '"browser-1","boot-browser-1",1,["boot-browser-1"],"'
            + "ab" * 32
            + '","fp-1",4242,99]'
        ).encode("utf-8")
        self.assertEqual(message, expect)

    def test_string_escaping_matches_json_stringify(self) -> None:
        """Control characters, non-ASCII text and lone surrogates.

        The expected text is what ``JSON.stringify`` returns for the same
        array under Node 26.
        """
        value = ["\x00\x08\t\n\x0b\x0c\r\x1f\x7f \ud800x\"\\/é😀"]
        self.assertEqual(
            js_json(value),
            '["\\u0000\\b\\t\\n\\u000b\\f\\r\\u001f\x7f \\ud800x\\"\\\\/é😀"]',
        )

    def test_known_signature(self) -> None:
        """Ed25519 is deterministic: one seed and one row give one signature."""
        signer = LauncherSigner.from_seed(bytes(range(32)))
        row = _row()
        sig = signer.sign_row(TD, TENANT, row)
        self.assertRegex(sig, r"^[0-9a-f]{128}$")
        self.assertEqual(sig, signer.sign_row(TD, TENANT, _row()))
        row["launcher_sig"] = sig
        self.assertTrue(row_attributed(TD, TENANT, row, keys=[signer.public]))
        self.assertFalse(row_attributed(TD, "tenant-other", row, keys=[signer.public]))


class SignedRegistryTests(unittest.TestCase):
    """save_registry signs, and lookups only see attributed rows."""

    def test_every_saved_row_carries_a_valid_signature(self) -> None:
        """The launcher key lives beside the registry, outside authority/."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            _save(path, [_row("browser-1"), _row("browser-2", "cd" * 32)])
            raw = json.loads(path.read_text(encoding="utf-8"))
            key = launcher_dir(path) / "row-signing.key"
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(launcher_dir(path).name, "authority")
            public = LauncherSigner.at(launcher_dir(path)).public
            for row in raw["workloads"]:
                self.assertRegex(row["launcher_sig"], r"^[0-9a-f]{128}$")
                self.assertTrue(row_attributed(TD, TENANT, row, keys=[public]))
            self.assertNotIn(public.hex(), path.read_text(encoding="utf-8"))

    def test_rebind_is_re_signed(self) -> None:
        """A row the launcher changes is signed again over its new fields."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            _save(path, [_row()])
            before = json.loads(path.read_text(encoding="utf-8"))["workloads"][0]
            bind_process(path, "browser-1", os.getpid())
            after = json.loads(path.read_text(encoding="utf-8"))["workloads"][0]
            self.assertNotEqual(before["launcher_sig"], after["launcher_sig"])
            identity = load_registry(path).find_instance("browser-1")
            self.assertIsNotNone(identity)
            assert identity is not None
            self.assertEqual(identity.pid, os.getpid())

    def test_unsigned_row_is_no_identity(self) -> None:
        """Removing launcher_sig removes the row from every lookup."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            _save(path, [_row()])
            bind_process(path, "browser-1", os.getpid())
            registry = load_registry(path)
            self.assertIsNotNone(registry.find_instance("browser-1"))
            self.assertIsNotNone(registry.find_channel("ab" * 32))
            self.assertIsNotNone(registry.find_pid(os.getpid()))

            def strip(rows: List[Dict[str, Any]]) -> None:
                del rows[0]["launcher_sig"]

            _rewrite(path, strip)
            registry = load_registry(path)
            self.assertIsNone(registry.find_instance("browser-1"))
            self.assertIsNone(registry.find_channel("ab" * 32))
            self.assertIsNone(registry.find_pid(os.getpid()))

    def test_edited_row_is_no_identity(self) -> None:
        """A hand edit of a signed field breaks the signature."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            _save(path, [_row()])

            def swap(rows: List[Dict[str, Any]]) -> None:
                rows[0]["channel_public"] = "ef" * 32

            _rewrite(path, swap)
            registry = load_registry(path)
            self.assertIsNone(registry.find_channel("ef" * 32))
            self.assertIsNone(registry.find_instance("browser-1"))

    def test_row_signed_by_another_key_is_no_identity(self) -> None:
        """Only a configured launcher key attributes a row."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            stranger = LauncherSigner.from_seed(b"\x07" * 32)
            save_registry(
                path,
                AdmissionRegistry(trust_domain=TD, tenant=TENANT, workloads=[_row()]),
                signer=stranger,
            )
            self.assertIsNone(load_registry(path).find_instance("browser-1"))

    def test_malformed_row_is_not_signed(self) -> None:
        """A pid without a start time is refused, and nothing is written."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            row = _row()
            row["pid"] = 12
            with self.assertRaises(RowNotSignable):
                _save(path, [row])
            self.assertFalse(path.exists())
            for bad in (
                {"channel_public": "AB" * 32},
                {"boot_history": ["other"]},
                {"boot_generation": 0},
                {"cert_fingerprint": ""},
            ):
                row = _row()
                row.update(bad)
                with self.assertRaises(RowNotSignable):
                    _save(path, [row])

    def test_keeper_gate_refuses_an_unsigned_row(self) -> None:
        """The pidfd gate admits this pid only while its row is signed."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            _save(path, [_row()])
            bind_process(path, "browser-1", os.getpid())
            left, right = socket.socketpair()
            try:
                auth = authenticate_unix(right, path)
                self.assertTrue(auth.admitted)

                def strip(rows: List[Dict[str, Any]]) -> None:
                    rows[0]["launcher_sig"] = "00" * 64

                _rewrite(path, strip)
                auth = authenticate_unix(right, path)
                self.assertFalse(auth.admitted)
                self.assertEqual(auth.denial_code, "denied_unadmitted")
            finally:
                left.close()
                right.close()


class KeyOwnerTests(unittest.TestCase):
    """A key or fingerprint keeps its first owner, even after its row is gone."""

    def test_second_instance_cannot_take_a_bound_channel_key(self) -> None:
        """The save is refused and the file is unchanged."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            _save(path, [_row("browser-1")])
            before = path.read_bytes()
            with self.assertRaises(KeyAlreadyBound):
                _save(path, [_row("browser-1"), _row("browser-2")])
            self.assertEqual(path.read_bytes(), before)

    def test_key_stays_owned_after_its_row_is_gone(self) -> None:
        """A clone launched with the parent's key after the parent left."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            _save(path, [_row("browser-1")])
            _save(path, [])
            path.unlink()
            with self.assertRaises(KeyAlreadyBound):
                _save(path, [_row("clone-1")])
            self.assertFalse(path.exists())
            journal = launcher_dir(path) / KEY_OWNERS
            self.assertIn("ch:" + "ab" * 32, journal.read_text(encoding="utf-8"))
            self.assertNotIn("authority", str(journal.relative_to(tmp)))

    def test_same_instance_with_another_role_is_refused(self) -> None:
        """The owner is the instance and the role together."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            _save(path, [_row("browser-1")])
            row = _row("browser-1")
            row["role"] = "omi-runner"
            with self.assertRaises(KeyAlreadyBound):
                _save(path, [row])

    def test_fingerprint_is_owned_like_a_channel_key(self) -> None:
        """A certificate fingerprint moved to another instance is refused."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            first = _row("browser-1")
            first["cert_fingerprint"] = "fp-one"
            _save(path, [first, _row("browser-2", "cd" * 32)])
            with self.assertRaises(KeyAlreadyBound):
                bind_process(path, "browser-2", None, fingerprint="fp-one")
            identity = load_registry(path).find_instance("browser-2")
            assert identity is not None
            self.assertIsNone(identity.cert_fingerprint)

    def test_rebind_to_another_instances_key_is_refused(self) -> None:
        """An instance may return to its own key but not take another's."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            _save(path, [_row("browser-1"), _row("browser-2", "cd" * 32)])
            with self.assertRaises(KeyAlreadyBound):
                rebind_channel(path, "browser-2", "ab" * 32)
            rebind_channel(path, "browser-1", "ef" * 32)
            back = rebind_channel(path, "browser-1", "ab" * 32)
            self.assertEqual(back.kind, "rebound")
            self.assertEqual(back.boot_generation, 3)
            identity = load_registry(path).find_instance("browser-2")
            assert identity is not None
            self.assertEqual(identity.channel_public, "cd" * 32)

    def test_memory_survives_a_new_process(self) -> None:
        """The owner journal is read from disk on every save."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            _save(path, [_row("browser-1")])
            code = (
                "import sys\n"
                "from pathlib import Path\n"
                "from cah.launcher import KeyAlreadyBound\n"
                "from cah.registry import AdmissionRegistry, save_registry\n"
                "row={'role':'browser-guard','instance_id':'clone-1',"
                "'boot_id':'b','boot_generation':1,'boot_history':['b'],"
                "'channel_public':'ab'*32}\n"
                "try:\n"
                " save_registry(Path(sys.argv[1]), AdmissionRegistry("
                "trust_domain='lab.cah', tenant='t', workloads=[row]))\n"
                "except KeyAlreadyBound:\n"
                " sys.exit(3)\n"
            )
            env = dict(os.environ)
            env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
            done = subprocess.run(
                [sys.executable, "-c", code, str(path)], env=env, check=False
            )
            self.assertEqual(done.returncode, 3)

    def test_spliced_rows_for_one_instance_are_no_identity(self) -> None:
        """Two validly signed versions of one row, pasted together."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            _save(path, [_row("browser-1")])
            old = json.loads(path.read_text(encoding="utf-8"))["workloads"][0]
            rebind_channel(path, "browser-1", "ef" * 32)
            self.assertIsNotNone(load_registry(path).find_instance("browser-1"))

            def splice(rows: List[Dict[str, Any]]) -> None:
                rows.insert(0, old)

            _rewrite(path, splice)
            registry = load_registry(path)
            self.assertIsNone(registry.find_instance("browser-1"))
            self.assertIsNone(registry.find_channel("ab" * 32))


if __name__ == "__main__":
    unittest.main()
