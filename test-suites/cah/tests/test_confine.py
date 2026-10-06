"""A confined compartment cannot read keeper authority."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cah.confine import popen_confined

_CHILD = """
import sys
from pathlib import Path
root = Path(sys.argv[1])
secret = root / "authority" / "secret.txt"
admission = root / "admission.json"
seen = secret.is_file()
try:
    admission.write_text("rewritten\\n", encoding="utf-8")
    wrote = True
except OSError:
    wrote = False
print(f"secret_seen={int(seen)} wrote={int(wrote)}")
"""


class ConfineTests(unittest.TestCase):
    """User and mount namespaces hide the authority directory."""

    def test_child_cannot_read_authority_or_rewrite_admission(self) -> None:
        """The parent still sees the secret after the child runs."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            authority = root / "authority"
            authority.mkdir()
            (authority / "secret.txt").write_text("keeper-only\n", encoding="utf-8")
            role = root / "roles" / "browser-1"
            role.mkdir(parents=True)
            admission = root / "admission.json"
            admission.write_text("{}\n", encoding="utf-8")
            env = dict(os.environ)
            env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
            proc = popen_confined(
                [sys.executable, "-c", _CHILD, str(root)],
                hide_dirs=[authority, root / "roles"],
                keep_dirs=[role],
                ro_files=[admission],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = proc.communicate(timeout=20)
            self.assertEqual(
                proc.returncode,
                0,
                stderr.decode("utf-8", errors="replace"),
            )
            self.assertIn(b"secret_seen=0 wrote=0", stdout)
            self.assertEqual(
                (authority / "secret.txt").read_text(encoding="utf-8"),
                "keeper-only\n",
            )
            self.assertEqual(admission.read_text(encoding="utf-8"), "{}\n")

    def test_child_cannot_rewrite_fence_or_outcomes(self) -> None:
        """A confined broker cannot see the fence or append an outcome."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            authority = root / "authority"
            authority.mkdir()
            fence = root / "fence"
            fence.mkdir()
            (fence / "secret").write_bytes(b"s" * 32)
            (fence / "epoch").write_text("1\n", encoding="utf-8")
            (root / "host-fence").mkdir()
            role = root / "roles" / "broker-1"
            role.mkdir(parents=True)
            env = dict(os.environ)
            env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
            proc = popen_confined(
                [sys.executable, "-c", _FENCE_CHILD, str(root)],
                hide_dirs=[authority, root / "roles", fence, root / "host-fence"],
                keep_dirs=[role],
                ro_files=[],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = proc.communicate(timeout=20)
            self.assertEqual(
                proc.returncode,
                0,
                stderr.decode("utf-8", errors="replace"),
            )
            self.assertIn(b"secret_seen=0", stdout)
            self.assertEqual((fence / "epoch").read_text(encoding="utf-8"), "1\n")
            self.assertFalse((authority / "outcomes.jsonl").exists())


_FENCE_CHILD = """
import sys
from pathlib import Path
root = Path(sys.argv[1])
secret = root / "fence" / "secret"
seen = secret.is_file()
try:
    (root / "fence" / "epoch").write_text("2\\n", encoding="utf-8")
    wrote = True
except OSError:
    wrote = False
try:
    with (root / "authority" / "outcomes.jsonl").open("a", encoding="utf-8") as handle:
        handle.write("{}\\n")
    forged = True
except OSError:
    forged = False
print(f"secret_seen={int(seen)} epoch_written={int(wrote)} forged={int(forged)}")
"""


if __name__ == "__main__":
    unittest.main()
