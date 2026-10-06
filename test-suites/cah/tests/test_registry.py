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

from cah.registry import (
    AdmissionRegistry,
    BootRollback,
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


if __name__ == "__main__":
    unittest.main()
