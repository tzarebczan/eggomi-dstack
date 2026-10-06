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
            self.assertEqual(first.boot_generation, 1)
            child = subprocess.Popen(["sleep", "30"])
            try:
                second = bind_process(path, "browser-1", child.pid)
            finally:
                child.kill()
                child.wait(timeout=5)
            self.assertEqual(second.kind, "rebound")
            self.assertEqual(second.boot_generation, 2)
            generation = set_boot(path, "browser-1", "boot-2")
            self.assertEqual(generation, 3)
            with self.assertRaises(BootRollback):
                set_boot(path, "browser-1", "boot-1")
            row = load_registry(path).find_instance("browser-1")
            self.assertIsNotNone(row)
            assert row is not None
            self.assertEqual(row.boot_id, "boot-2")
            self.assertEqual(row.boot_generation, 3)

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
            self.assertEqual(first.boot_generation, 1)
            repeated = bind_process(path, "browser-1", None, "aa")
            self.assertEqual(repeated.kind, "bound")
            self.assertEqual(repeated.boot_generation, 1)
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
            )
            self.assertEqual(
                store.get(str(record["grant_ref"]))["disposition"], "issued"
            )
            snapshot = grants_path.read_bytes()
            epoch_snapshot = epoch_path.read_bytes()
            second = bind_process(path, "browser-1", None, "bb")
            self.assertEqual(second.kind, "rebound")
            self.assertEqual(second.boot_generation, 2)
            if second.kind == "rebound":
                revoke_instance_grants(
                    grants_path, journal_path, epoch_path, "browser-1"
                )
            self.assertEqual(
                store.get(str(record["grant_ref"]))["disposition"], "revoked_boot"
            )
            third = bind_process(path, "browser-1", None, "aa")
            self.assertEqual(third.kind, "rebound")
            self.assertEqual(third.boot_generation, 3)
            returned = load_registry(path).find_instance("browser-1")
            self.assertIsNotNone(returned)
            assert returned is not None
            self.assertEqual(returned.cert_fingerprint, "aa")
            self.assertEqual(returned.boot_generation, 3)
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
            self.assertEqual(restored["disposition"], "revoked_boot")

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
            self.assertEqual(first.boot_generation, 1)
            second = bind_process(path, "browser-1", pid, "bb")
            self.assertEqual(second.kind, "rebound")
            self.assertEqual(second.boot_generation, 2)


def _party(role: str, instance: str, boot: str, fingerprint: str) -> WorkloadIdentity:
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
    )


if __name__ == "__main__":
    unittest.main()
