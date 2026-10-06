"""Boot ids advance, and a process rebind mints a new generation."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from cah.grants import GrantStore, revoke_instance_grants
from cah.registry import (
    AdmissionRegistry,
    BootRollback,
    WorkloadIdentity,
    bind_process,
    load_registry,
    rebind_channel,
    save_registry,
    set_boot,
)


class RegistryTests(unittest.TestCase):
    """Admission rows do not roll back into an older incarnation."""

    def test_rebind_advances_and_old_boot_is_refused(self) -> None:
        """A second pid is a new generation, and the first boot id cannot return."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            save_registry(
                path,
                AdmissionRegistry(
                    trust_domain="lab.cah",
                    tenant="tenant-lab-1",
                    workloads=[
                        {
                            "role": "browser-guard",
                            "instance_id": "browser-1",
                            "boot_id": "boot-1",
                            "boot_generation": 1,
                            "boot_history": ["boot-1"],
                            "cert_fingerprint": None,
                            "pid": None,
                            "starttime": None,
                        }
                    ],
                ),
            )
            first = bind_process(path, "browser-1", os.getpid())
            self.assertEqual(first.kind, "bound")
            self.assertEqual(first.boot_generation, 2)
            child = subprocess.Popen(["sleep", "30"])
            try:
                second = bind_process(path, "browser-1", child.pid)
            finally:
                child.kill()
                child.wait(timeout=5)
            self.assertEqual(second.kind, "rebound")
            self.assertEqual(second.boot_generation, 3)
            generation = set_boot(path, "browser-1", "boot-2")
            self.assertEqual(generation, 4)
            with self.assertRaises(BootRollback):
                set_boot(path, "browser-1", "boot-1")
            row = load_registry(path).find_instance("browser-1")
            self.assertIsNotNone(row)
            assert row is not None
            self.assertEqual(row.boot_id, "boot-2")
            self.assertEqual(row.boot_generation, 4)

    def test_cert_only_rebind_advances_and_return_does_not_revive(self) -> None:
        """Fingerprint A to B is generation 2, and A again does not revive the grant."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "admission.json"
            grants_path = root / "grants.json"
            journal_path = root / "authority-journal.jsonl"
            epoch_path = root / "keeper-epoch"
            save_registry(
                path,
                AdmissionRegistry(
                    trust_domain="lab.cah",
                    tenant="tenant-lab-1",
                    workloads=[
                        {
                            "role": "browser-guard",
                            "instance_id": "browser-1",
                            "boot_id": "boot-1",
                            "boot_generation": 1,
                            "boot_history": ["boot-1"],
                            "cert_fingerprint": None,
                            "pid": None,
                            "starttime": None,
                        }
                    ],
                ),
            )
            first = bind_process(path, "browser-1", None, "aa")
            self.assertEqual(first.kind, "bound")
            self.assertEqual(first.boot_generation, 2)
            repeated = bind_process(path, "browser-1", None, "aa")
            self.assertEqual(repeated.kind, "unchanged")
            self.assertEqual(repeated.boot_generation, 2)
            store = GrantStore(grants_path, journal_path, epoch_path)
            record = store.issue(
                _party("omi-runner", "omi-1", "boot-omi-1", "omi-fp"),
                _party("browser-guard", "browser-1", "boot-1", "aa"),
                "pol",
                "cred",
                "https://lab.invalid/signin",
                "task",
                "op-1",
                "lease",
                1,
                60,
                "frame-1",
                "nav-1",
                audience_role="credential-broker",
                audience_instance="broker-1",
                audience_key="cc" * 32,
                field="password",
                tenant="tenant-lab-1",
                fence="fence-browser-1",
                keeper_epoch=1,
            )
            self.assertEqual(
                store.get(str(record["grant_ref"]))["disposition"], "issued"
            )
            snapshot = grants_path.read_bytes()
            epoch_snapshot = epoch_path.read_bytes()
            second = bind_process(path, "browser-1", None, "bb")
            self.assertEqual(second.kind, "rebound")
            self.assertEqual(second.boot_generation, 3)
            if second.kind == "rebound":
                revoke_instance_grants(
                    grants_path, journal_path, epoch_path, "browser-1"
                )
            self.assertEqual(
                store.get(str(record["grant_ref"]))["disposition"], "denied_boot"
            )
            third = bind_process(path, "browser-1", None, "aa")
            self.assertEqual(third.kind, "rebound")
            self.assertEqual(third.boot_generation, 4)
            returned = load_registry(path).find_instance("browser-1")
            self.assertIsNotNone(returned)
            assert returned is not None
            self.assertEqual(returned.cert_fingerprint, "aa")
            self.assertEqual(returned.boot_generation, 4)
            grants_path.write_bytes(snapshot)
            epoch_path.write_bytes(epoch_snapshot)
            reloaded = GrantStore(grants_path, journal_path, epoch_path)
            revived = reloaded.resolve(
                str(record["grant_ref"]),
                _party("browser-guard", "browser-1", "boot-1", "aa"),
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(revived["code"], "denied_boot")
            restored = reloaded.get(str(record["grant_ref"]))
            self.assertIsNotNone(restored)
            assert restored is not None
            self.assertEqual(restored["disposition"], "denied_boot")

    def test_fingerprint_change_with_pid_is_rebind(self) -> None:
        """A certificate change on a live pid is a rebind, not a fresh bind."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            save_registry(
                path,
                AdmissionRegistry(
                    trust_domain="lab.cah",
                    tenant="tenant-lab-1",
                    workloads=[
                        {
                            "role": "browser-guard",
                            "instance_id": "browser-1",
                            "boot_id": "boot-1",
                            "boot_generation": 1,
                            "boot_history": ["boot-1"],
                            "cert_fingerprint": None,
                            "pid": None,
                            "starttime": None,
                        }
                    ],
                ),
            )
            pid = os.getpid()
            first = bind_process(path, "browser-1", pid, "aa")
            self.assertEqual(first.kind, "bound")
            self.assertEqual(first.boot_generation, 2)
            second = bind_process(path, "browser-1", pid, "bb")
            self.assertEqual(second.kind, "rebound")
            self.assertEqual(second.boot_generation, 3)

    def test_channel_key_rebind_advances_and_return_does_not_revive(self) -> None:
        """Channel key A to B is generation 2, and A again does not revive the grant."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "admission.json"
            grants_path = root / "grants.json"
            journal_path = root / "authority-journal.jsonl"
            epoch_path = root / "keeper-epoch"
            key_a = "1a" * 32
            key_b = "2b" * 32
            save_registry(
                path,
                AdmissionRegistry(
                    trust_domain="lab.cah",
                    tenant="tenant-lab-1",
                    workloads=[
                        {
                            "role": "browser-guard",
                            "instance_id": "browser-1",
                            "boot_id": "boot-1",
                            "boot_generation": 1,
                            "boot_history": ["boot-1"],
                            "cert_fingerprint": "fp",
                            "pid": None,
                            "starttime": None,
                            "channel_public": None,
                        }
                    ],
                ),
            )
            first = rebind_channel(path, "browser-1", key_a)
            self.assertEqual(first.kind, "bound")
            self.assertEqual(first.boot_generation, 2)
            repeated = rebind_channel(path, "browser-1", key_a)
            self.assertEqual(repeated.kind, "unchanged")
            self.assertEqual(repeated.boot_generation, 2)
            store = GrantStore(grants_path, journal_path, epoch_path)
            recipient = _party("browser-guard", "browser-1", "boot-1", "fp", key_a)
            record = store.issue(
                _party("omi-runner", "omi-1", "boot-omi-1", "omi-fp"),
                recipient,
                "pol",
                "cred",
                "https://lab.invalid/signin",
                "task",
                "op-1",
                "lease",
                1,
                60,
                "frame-1",
                "nav-1",
                audience_role="credential-broker",
                audience_instance="broker-1",
                audience_key="cc" * 32,
                field="password",
                tenant="tenant-lab-1",
                fence="fence-browser-1",
                keeper_epoch=1,
            )
            snapshot = grants_path.read_bytes()
            epoch_snapshot = epoch_path.read_bytes()
            second = rebind_channel(path, "browser-1", key_b)
            self.assertEqual(second.kind, "rebound")
            self.assertEqual(second.boot_generation, 3)
            revoke_instance_grants(grants_path, journal_path, epoch_path, "browser-1")
            third = rebind_channel(path, "browser-1", key_a)
            self.assertEqual(third.kind, "rebound")
            self.assertEqual(third.boot_generation, 4)
            grants_path.write_bytes(snapshot)
            epoch_path.write_bytes(epoch_snapshot)
            reloaded = GrantStore(grants_path, journal_path, epoch_path)
            revived = reloaded.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
                broker_instance="broker-1",
                field="password",
                tenant="tenant-lab-1",
            )
            self.assertEqual(revived["code"], "denied_boot")
            raw = load_registry(path)
            row = next(
                item for item in raw.workloads if item.get("instance_id") == "browser-1"
            )
            row["channel_public"] = key_b
            save_registry(path, raw)
            rewritten = load_registry(path).find_instance("browser-1")
            self.assertIsNotNone(rewritten)
            assert rewritten is not None
            self.assertEqual(rewritten.boot_generation, 5)


def _party(
    role: str,
    instance: str,
    boot: str,
    fingerprint: str,
    channel: str | None = None,
) -> WorkloadIdentity:
    """Build one possession identity for a grant fixture."""
    return WorkloadIdentity(
        trust_domain="lab.cah",
        tenant="tenant-lab-1",
        role=role,
        instance_id=instance,
        boot_id=boot,
        boot_generation=1,
        cert_fingerprint=fingerprint,
        pid=None,
        starttime=None,
        channel_public=channel,
    )


class FirstBindTests(unittest.TestCase):
    """Any change to a stored identity field advances boot_generation."""

    def _empty(self, path: Path) -> None:
        save_registry(
            path,
            AdmissionRegistry(
                trust_domain="lab.cah",
                tenant="tenant-lab-1",
                workloads=[
                    {
                        "role": "browser-guard",
                        "instance_id": "browser-1",
                        "boot_id": "boot-1",
                        "boot_generation": 1,
                        "boot_history": ["boot-1"],
                        "cert_fingerprint": None,
                        "pid": None,
                        "starttime": None,
                        "channel_public": None,
                    }
                ],
            ),
        )

    def test_first_pid_bind_advances(self) -> None:
        """An empty row that gets a pid moves from generation 1 to 2."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            self._empty(path)
            first = bind_process(path, "browser-1", os.getpid())
            self.assertEqual((first.kind, first.boot_generation), ("bound", 2))
            again = bind_process(path, "browser-1", os.getpid())
            self.assertEqual((again.kind, again.boot_generation), ("unchanged", 2))

    def test_first_fingerprint_bind_advances(self) -> None:
        """An empty row that gets a certificate fingerprint advances."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            self._empty(path)
            first = bind_process(path, "browser-1", None, "fp-1")
            self.assertEqual((first.kind, first.boot_generation), ("bound", 2))

    def test_first_channel_key_advances(self) -> None:
        """An empty channel_public that gets a key advances."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            self._empty(path)
            first = rebind_channel(path, "browser-1", "1a" * 32)
            self.assertEqual((first.kind, first.boot_generation), ("bound", 2))

    def test_first_bind_revokes_grants_issued_before_it(self) -> None:
        """The launcher's bind revokes a grant issued to the pre-bind row."""
        from cah.demo import _bind

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            (state / "authority").mkdir()
            (state / "host-fence").mkdir()
            path = state / "admission.json"
            self._empty(path)
            rebind_channel(path, "browser-1", "1a" * 32)
            row = load_registry(path).find_instance("browser-1")
            assert row is not None
            from cah.grants import host_fence_paths

            journal_path, epoch_path = host_fence_paths(state / "authority")
            store = GrantStore(
                state / "authority" / "grants.json", journal_path, epoch_path
            )
            record = store.issue(
                _party("omi-runner", "omi-1", "boot-omi-1", "omi-fp"),
                row,
                "pol",
                "cred",
                "https://lab.invalid/signin",
                "task",
                "op-1",
                "lease",
                1,
                60,
                "frame-1",
                "nav-1",
                audience_role="credential-broker",
                audience_instance="broker-1",
                audience_key="cc" * 32,
                field="password",
                tenant="tenant-lab-1",
                fence="fence-browser-1",
                keeper_epoch=1,
            )
            result = _bind(state, "browser-1", os.getpid())
            self.assertEqual((result.kind, result.boot_generation), ("bound", 3))
            self.assertEqual(
                store.get(str(record["grant_ref"]))["disposition"], "denied_boot"
            )

    def test_save_refuses_a_generation_that_goes_back(self) -> None:
        """An otherwise identical row saved with a lower generation is refused."""
        from cah.launcher import RowNotSignable

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            self._empty(path)
            rebind_channel(path, "browser-1", "1a" * 32)
            raw = load_registry(path)
            raw.workloads[0]["boot_generation"] = 1
            with self.assertRaises(RowNotSignable):
                save_registry(path, raw)
            self.assertTrue(path.with_name("admission.json.wlock").exists())

    def test_reader_refuses_a_same_generation_incarnation_change(self) -> None:
        """Two signed spellings of generation 2 with different keys."""
        from cah.launcher import LauncherSigner

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            self._empty(path)
            rebind_channel(path, "browser-1", "1a" * 32)
            self.assertIsNotNone(load_registry(path).find_instance("browser-1"))
            signer = LauncherSigner.at(Path(tmp) / "launcher")
            import json

            raw = json.loads(path.read_text(encoding="utf-8"))
            row = raw["workloads"][0]
            row["channel_public"] = "2b" * 32
            row["launcher_sig"] = signer.sign_row("lab.cah", "tenant-lab-1", row)
            path.write_text(json.dumps(raw), encoding="utf-8")
            self.assertIsNone(load_registry(path).find_instance("browser-1"))

    def test_any_save_path_advances_a_changed_row(self) -> None:
        """A direct launcher save that fills an identity field also advances."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admission.json"
            self._empty(path)
            raw = load_registry(path)
            raw.workloads[0]["channel_public"] = "1a" * 32
            save_registry(path, raw)
            row = load_registry(path).find_instance("browser-1")
            assert row is not None
            self.assertEqual(row.boot_generation, 2)


if __name__ == "__main__":
    unittest.main()
