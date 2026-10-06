"""Use-grant consumption, possession, and journal rules."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cah.grants import (
    GrantStore,
    OperationSpent,
    begin_keeper_boot,
    host_fence_paths,
    keeper_boot_path,
)
from cah.registry import WorkloadIdentity


def _id(
    role: str,
    instance: str,
    boot: str,
    fingerprint: str | None = "fp",
    pid: int | None = None,
    starttime: int | None = None,
    generation: int = 1,
) -> WorkloadIdentity:
    return WorkloadIdentity(
        trust_domain="lab.cah",
        tenant="tenant-lab-1",
        role=role,
        instance_id=instance,
        boot_id=boot,
        boot_generation=generation,
        cert_fingerprint=fingerprint,
        pid=pid,
        starttime=starttime,
    )


def _issue(
    store: GrantStore, recipient: WorkloadIdentity, operation_id: str = "op-1"
) -> dict[str, object]:
    return store.issue(
        _id("omi-runner", "omi-1", "boot-omi-1"),
        recipient,
        "pol",
        "cred",
        "https://lab.invalid/signin",
        "task",
        operation_id,
        "lease",
        1,
        60,
        "frame-1",
        "nav-1",
        audience_role="credential-broker",
        audience_instance="broker-1",
        audience_key="aa" * 32,
        field="password",
        tenant="tenant-lab-1",
        fence="fence-browser-1",
        keeper_epoch=1,
    )


class GrantTests(unittest.TestCase):
    """Keeper-side grant checks without processes."""

    def test_wrong_role_stays_issued_and_replay_is_consumed(self) -> None:
        """A role mismatch does not consume; a matching resolve does."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            recipient = _id("browser-guard", "browser-1", "boot-1")
            record = _issue(store, recipient)
            wrong_role = _id("omi-runner", "omi-1", "boot-1")
            copied = store.resolve(
                str(record["grant_ref"]),
                wrong_role,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(copied["code"], "denied_role")
            self.assertEqual(store.get(str(record["grant_ref"]))["uses"], 0)
            ok = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
                **_bound(),
            )
            self.assertTrue(ok["ok"])
            again = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(again["code"], "grant_consumed")

    def test_other_browser_and_missing_fingerprint_do_not_skip(self) -> None:
        """Instance and fingerprint mismatches stay issued."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            recipient = _id("browser-guard", "browser-1", "boot-1", fingerprint="aa")
            record = _issue(store, recipient)
            other = _id("browser-guard", "browser-2", "boot-2", fingerprint="aa")
            copied = store.resolve(
                str(record["grant_ref"]),
                other,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(copied["code"], "denied_recipient")
            self.assertEqual(
                store.get(str(record["grant_ref"]))["disposition"], "issued"
            )
            blank = _id("browser-guard", "browser-1", "boot-1", fingerprint=None)
            skipped = store.resolve(
                str(record["grant_ref"]),
                blank,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(skipped["code"], "denied_recipient")
            self.assertEqual(store.get(str(record["grant_ref"]))["uses"], 0)

    def test_null_fingerprint_still_checks_pid(self) -> None:
        """A missing certificate does not waive the process binding."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            recipient = _id(
                "browser-guard",
                "browser-1",
                "boot-1",
                fingerprint=None,
                pid=10,
                starttime=20,
            )
            record = _issue(store, recipient)
            other = _id(
                "browser-guard",
                "browser-1",
                "boot-1",
                fingerprint=None,
                pid=11,
                starttime=21,
            )
            refused = store.resolve(
                str(record["grant_ref"]),
                other,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(refused["code"], "denied_recipient")
            self.assertEqual(store.get(str(record["grant_ref"]))["uses"], 0)
            with self.assertRaises(ValueError):
                _issue(
                    store,
                    _id("browser-guard", "browser-2", "boot-2", fingerprint=None),
                    "op-2",
                )

    def test_boot_generation_mismatch_revokes(self) -> None:
        """An older boot generation cannot resolve, and the grant does not stay usable."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            recipient = _id("browser-guard", "browser-1", "boot-1", generation=1)
            record = _issue(store, recipient)
            rolled = _id("browser-guard", "browser-1", "boot-1", generation=2)
            refused = store.resolve(
                str(record["grant_ref"]),
                rolled,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(refused["code"], "denied_boot")
            self.assertEqual(
                store.get(str(record["grant_ref"]))["disposition"], "denied_boot"
            )
            again = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(again["code"], "denied_boot")

    def test_frame_mismatch_does_not_consume(self) -> None:
        """Navigation and frame must match the stored destination."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            recipient = _id("browser-guard", "browser-1", "boot-1")
            record = _issue(store, recipient)
            refused = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-replaced",
            )
            self.assertEqual(refused["code"], "denied_payload")
            self.assertEqual(store.get(str(record["grant_ref"]))["uses"], 0)
            ok = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
                **_bound(),
            )
            self.assertTrue(ok["ok"])

    def test_restored_pre_consume_snapshot_stays_consumed(self) -> None:
        """The journal wins over a grants file from before consumption."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "grants.json"
            store = GrantStore(path)
            recipient = _id("browser-guard", "browser-1", "boot-1")
            record = _issue(store, recipient)
            snapshot = path.read_bytes()
            epoch = (root / "keeper-epoch").read_bytes()
            ok = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
                **_bound(),
            )
            self.assertTrue(ok["ok"])
            path.write_bytes(snapshot)
            (root / "keeper-epoch").write_bytes(epoch)
            reloaded = GrantStore(path)
            again = reloaded.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(again["code"], "grant_consumed")
            restored = reloaded.get(str(record["grant_ref"]))
            self.assertIsNotNone(restored)
            assert restored is not None
            self.assertEqual(restored["disposition"], "consumed")

    def test_bootstrap_journal_survives_reload(self) -> None:
        """A spent bootstrap token stays spent after the store is reopened."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "grants.json"
            store = GrantStore(path)
            store.note_bootstrap("abc")
            self.assertTrue(store.bootstrap_used("abc"))
            reloaded = GrantStore(path)
            self.assertTrue(reloaded.bootstrap_used("abc"))

    def test_expired_grant_is_not_zero_use(self) -> None:
        """An expired grant is refused and stays unconsumed."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "grants.json"
            store = GrantStore(path)
            recipient = _id("browser-guard", "browser-1", "boot-1")
            record = _issue(store, recipient)
            raw = json.loads(path.read_text(encoding="utf-8"))
            lease = raw["grants"][record["grant_ref"]]["lease"]
            lease["expires_unix"] = float(lease["issued_unix"]) - 1
            path.write_text(json.dumps(raw) + "\n", encoding="utf-8")
            reloaded = GrantStore(path)
            refused = reloaded.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            self.assertEqual(refused["code"], "grant_expired")
            self.assertEqual(reloaded.get(str(record["grant_ref"]))["uses"], 0)

    def test_ttl_above_cap_is_refused(self) -> None:
        """Use ttl cannot exceed 60 seconds."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            with self.assertRaises(ValueError):
                store.issue(
                    _id("omi-runner", "omi-1", "boot-omi-1"),
                    _id("browser-guard", "browser-1", "boot-1"),
                    "pol",
                    "cred",
                    "https://lab.invalid/signin",
                    "task",
                    "op-1",
                    "lease",
                    1,
                    61,
                    "frame-1",
                    "nav-1",
                    keeper_epoch=1,
                )

    def test_audience_field_and_tenant_do_not_consume(self) -> None:
        """A broker, field, or tenant mismatch leaves the grant issued."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            recipient = _id("browser-guard", "browser-1", "boot-1")
            record = store.issue(
                _id("omi-runner", "omi-1", "boot-omi-1"),
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
                audience_key="aa" * 32,
                field="password",
                tenant="tenant-lab-1",
                fence="fence-browser-1",
                keeper_epoch=1,
            )
            wrong_broker = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
                broker_instance="broker-2",
                field="password",
                tenant="tenant-lab-1",
            )
            self.assertEqual(wrong_broker["code"], "denied_role")
            wrong_field = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
                broker_instance="broker-1",
                field="otp",
                tenant="tenant-lab-1",
            )
            self.assertEqual(wrong_field["code"], "denied_payload")
            wrong_tenant = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
                broker_instance="broker-1",
                field="password",
                tenant="tenant-other",
            )
            self.assertEqual(wrong_tenant["code"], "denied_payload")
            self.assertEqual(store.get(str(record["grant_ref"]))["uses"], 0)
            self.assertEqual(
                store.get(str(record["grant_ref"]))["disposition"], "issued"
            )

    def test_reopen_keeps_grants_across_a_later_epoch(self) -> None:
        """A new store reads the epoch file before it decides the grants are stale."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "grants.json"
            store = GrantStore(path)
            record = _issue(store, _id("browser-guard", "browser-1", "boot-1"))
            store.note_bootstrap("ab" * 32)
            reopened = GrantStore(path)
            self.assertIsNotNone(reopened.get(str(record["grant_ref"])))
            reopened.note_bootstrap("cd" * 32)
            again = GrantStore(path)
            self.assertEqual(
                again.get(str(record["grant_ref"]))["disposition"], "issued"
            )

    def test_empty_bindings_match_nothing(self) -> None:
        """An empty field, tenant, or audience cannot be issued or matched."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            recipient = _id("browser-guard", "browser-1", "boot-1")
            with self.assertRaises(ValueError):
                store.issue(
                    _id("omi-runner", "omi-1", "boot-omi-1"),
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
                    audience_key="aa" * 32,
                    field="",
                    tenant="tenant-lab-1",
                    fence="fence-browser-1",
                    keeper_epoch=1,
                )
            record = _issue(store, recipient)
            blank = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
                broker_instance="",
                field="",
                tenant="",
            )
            self.assertEqual(blank["code"], "denied_role")
            self.assertEqual(store.get(str(record["grant_ref"]))["uses"], 0)

    def test_other_store_reloads_when_the_epoch_matches(self) -> None:
        """A stale in-memory map does not overwrite grants saved at the new epoch."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "grants.json"
            reader = GrantStore(path)
            writer = GrantStore(path)
            recipient = _id("browser-guard", "browser-1", "boot-1")
            record = _issue(writer, recipient)
            writer.note_bootstrap("ab" * 32)
            added = _issue(reader, _id("browser-guard", "browser-2", "boot-2"), "op-2")
            reloaded = GrantStore(path)
            self.assertIsNotNone(reloaded.get(str(record["grant_ref"])))
            self.assertIsNotNone(reloaded.get(str(added["grant_ref"])))

    def test_one_grant_per_operation_survives_a_restore(self) -> None:
        """A second grant for one approved operation is refused, even after restore."""
        with tempfile.TemporaryDirectory() as tmp:
            authority = Path(tmp) / "authority"
            journal, epoch = host_fence_paths(authority)
            store = GrantStore(authority / "grants.json", journal, epoch)
            recipient = _id("browser-guard", "browser-1", "boot-1")
            empty = (
                (authority / "grants.json").read_bytes()
                if (authority / "grants.json").exists()
                else None
            )
            first = _issue(store, recipient, "op-once")
            with self.assertRaises(OperationSpent):
                _issue(store, recipient, "op-once")
            if empty is None:
                (authority / "grants.json").unlink()
            else:
                (authority / "grants.json").write_bytes(empty)
            restored = GrantStore(authority / "grants.json", journal, epoch)
            self.assertIsNone(restored.get(str(first["grant_ref"])))
            with self.assertRaises(OperationSpent):
                _issue(restored, recipient, "op-once")
            other = _issue(restored, recipient, "op-next")
            self.assertNotEqual(other["grant_ref"], first["grant_ref"])

    def test_journal_rows_are_fsynced_before_resolve_returns(self) -> None:
        """The consume record is durable before the caller may release a seal."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            recipient = _id("browser-guard", "browser-1", "boot-1")
            record = _issue(store, recipient)
            synced: list[int] = []
            real_fsync = os.fsync

            def spy(fd: int) -> None:
                synced.append(fd)
                real_fsync(fd)

            with mock.patch("cah.grants.os.fsync", side_effect=spy):
                result = store.resolve(
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
            self.assertTrue(result["ok"])
            self.assertTrue(synced)

    def test_grant_from_an_earlier_keeper_boot_is_denied_boot(self) -> None:
        """A keeper restart advances the boot epoch; old grants do not resolve."""
        with tempfile.TemporaryDirectory() as tmp:
            authority = Path(tmp) / "authority"
            boot = keeper_boot_path(authority)
            self.assertEqual(begin_keeper_boot(boot), 1)
            store = GrantStore(authority / "grants.json")
            recipient = _id("browser-guard", "browser-1", "boot-1")
            record = _issue(store, recipient)
            self.assertEqual(begin_keeper_boot(boot), 2)
            args = (
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
            )
            kwargs = {
                "broker_instance": "broker-1",
                "field": "password",
                "tenant": "tenant-lab-1",
            }
            stale = store.resolve(*args, keeper_epoch=2, **kwargs)
            self.assertEqual(stale["code"], "denied_boot")
            again = store.resolve(*args, keeper_epoch=1, **kwargs)
            self.assertEqual(again["code"], "denied_boot")
            self.assertEqual(int(boot.read_text(encoding="utf-8")), 2)

    def test_new_journal_directory_entry_is_fsynced(self) -> None:
        """Creating the journal fsyncs its directory, not only the file."""
        with tempfile.TemporaryDirectory() as tmp:
            store = GrantStore(Path(tmp) / "grants.json")
            synced_dirs: list[bool] = []
            real_fsync = os.fsync

            def spy(fd: int) -> None:
                synced_dirs.append(stat.S_ISDIR(os.fstat(fd).st_mode))
                real_fsync(fd)

            with mock.patch("cah.grants.os.fsync", side_effect=spy):
                _issue(store, _id("browser-guard", "browser-1", "boot-1"))
            self.assertIn(True, synced_dirs)

    def test_restoring_authority_does_not_revive_consume(self) -> None:
        """The host fence sits outside authority/, so a restored snapshot stays consumed."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            authority = root / "authority"
            authority.mkdir()
            journal, epoch = host_fence_paths(authority)
            store = GrantStore(authority / "grants.json", journal, epoch)
            recipient = _id("browser-guard", "browser-1", "boot-1")
            record = _issue(store, recipient)
            snapshot = root / "snap"
            shutil.copytree(authority, snapshot)
            ok = store.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
                **_bound(),
            )
            self.assertTrue(ok["ok"])
            shutil.rmtree(authority)
            shutil.copytree(snapshot, authority)
            reloaded = GrantStore(authority / "grants.json", journal, epoch)
            again = reloaded.resolve(
                str(record["grant_ref"]),
                recipient,
                "https://lab.invalid/signin",
                "op-1",
                "frame-1",
                "nav-1",
                **_bound(),
            )
            self.assertEqual(again["code"], "grant_consumed")


def _bound() -> dict[str, str]:
    return {
        "broker_instance": "broker-1",
        "field": "password",
        "tenant": "tenant-lab-1",
    }


if __name__ == "__main__":
    unittest.main()
