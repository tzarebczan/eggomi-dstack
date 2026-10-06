"""Launcher attribution for ``admission-registry/v1`` rows.

Each row carries ``launcher_sig``: Ed25519 (RFC 8032, pure) by the launcher's
host key, stored as 128 lowercase hex characters. A row without a valid one
is no identity. The signed bytes are the UTF-8 encoding of
``"eggomi/admission-row/v1\\n"`` followed by a compact JSON array, in
``JSON.stringify`` encoding, of ``trust_domain`` and ``tenant`` (from the
document), then ``role``, ``instance_id``, ``boot_id``, ``boot_generation``,
``boot_history``, ``channel_public``, ``cert_fingerprint``, ``pid`` and
``starttime``. This is Eggomi's ``rowMessage``
(``apps/desktop/src/keeper/cah/registry.ts``).

The private key lives in the launcher directory on the host, outside every
compartment and outside ``authority/``. Readers are configured with the
32-byte public key. The registry never names it. A process that signs rows
trusts its own key. Every other process is given the key on its command
line (``--launcher-public``).

The launcher also remembers each key's first owner. A channel key or a
certificate fingerprint, once signed for one instance and role, is never
signed for another, even after the first row is gone. That memory is
``key-owners.jsonl`` in the launcher directory: append-only, each line
fsynced before the registry that uses it is written, outside ``authority/``
and outside the registry, so neither a restored ``authority/`` nor a
rewritten registry clears it.
"""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

ROW_DOMAIN = "eggomi/admission-row/v1\n"
LAUNCHER_DIR = "launcher"
SIGNING_KEY = "row-signing.key"
KEY_OWNERS = "key-owners.jsonl"
_HEX32 = re.compile(r"^[0-9a-f]{64}$")
_SIG = re.compile(r"^[0-9a-f]{128}$")
_SURROGATE = re.compile("[\ud800-\udfff]")
_MAX_SAFE = 2**53 - 1

_trusted: List[bytes] = []
_trusted_lock = threading.Lock()


class RowNotSignable(ValueError):
    """A row is malformed, so the launcher does not sign it."""


class KeyAlreadyBound(RowNotSignable):
    """A row's key or fingerprint belongs to another instance or role."""

    def __init__(self, key: str, first_owner: str, claimant: str) -> None:
        """Name the key and both owners."""
        super().__init__(
            f"{key.split(':', 1)[0]} key is bound to {first_owner}, not {claimant}"
        )
        self.key = key
        self.first_owner = first_owner
        self.claimant = claimant


def launcher_dir(registry_path: Path) -> Path:
    """Return the launcher's host directory beside ``registry_path``.

    It is a sibling of ``authority/`` and ``host-fence/``. The launcher hides
    it from every confined compartment.
    """
    return registry_path.parent / LAUNCHER_DIR


def js_json(value: Any) -> str:
    """Encode ``value`` the way ``JSON.stringify`` does, without whitespace.

    Only strings, safe integers, ``None`` and lists occur in a row message.
    ``json.dumps`` with ``ensure_ascii=False`` matches ``JSON.stringify`` for
    every string except a lone surrogate, which ``JSON.stringify`` writes as
    a lowercase ``\\uXXXX`` escape.
    """
    _check_encodable(value)
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return _SURROGATE.sub(lambda m: "\\u%04x" % ord(m.group(0)), text)


def row_message(trust_domain: str, tenant: str, row: Mapping[str, Any]) -> bytes:
    """Return the bytes the launcher signs for ``row``.

    The row must already be well formed (``require_signable``).
    """
    fields = [
        trust_domain,
        tenant,
        row["role"],
        row["instance_id"],
        row["boot_id"],
        row["boot_generation"],
        list(row["boot_history"]),
        row.get("channel_public"),
        row.get("cert_fingerprint"),
        row.get("pid"),
        row.get("starttime"),
    ]
    return (ROW_DOMAIN + js_json(fields)).encode("utf-8")


def require_signable(trust_domain: str, tenant: str, row: Mapping[str, Any]) -> None:
    """Refuse a row the keeper would parse as malformed.

    The rules are Eggomi's ``parseRow``: non-empty role, instance and boot
    id; ``boot_generation`` an integer of at least 1; ``boot_history`` unique
    non-empty strings ending in ``boot_id``; ``channel_public`` 64 lowercase
    hex or null; a non-empty fingerprint or null; ``pid`` positive and
    ``starttime`` non-negative, both set or both null.
    """
    if not _nonempty(trust_domain) or not _nonempty(tenant):
        raise RowNotSignable("trust domain and tenant must be non-empty")
    for name in ("role", "instance_id", "boot_id"):
        if not _nonempty(row.get(name)):
            raise RowNotSignable(f"{name} must be a non-empty string")
    generation = row.get("boot_generation")
    if not _safe_int(generation) or generation < 1:
        raise RowNotSignable("boot_generation must be an integer of at least 1")
    history = row.get("boot_history")
    if (
        not isinstance(history, list)
        or not all(_nonempty(item) for item in history)
        or len(set(history)) != len(history)
        or not history
        or history[-1] != row.get("boot_id")
    ):
        raise RowNotSignable("boot_history must be unique and end in boot_id")
    channel = row.get("channel_public")
    if channel is not None and not (isinstance(channel, str) and _HEX32.match(channel)):
        raise RowNotSignable("channel_public must be 64 lowercase hex characters")
    fingerprint = row.get("cert_fingerprint")
    if fingerprint is not None and not _nonempty(fingerprint):
        raise RowNotSignable("cert_fingerprint must be a non-empty string")
    pid = row.get("pid")
    starttime = row.get("starttime")
    if pid is not None and not (_safe_int(pid) and pid > 0):
        raise RowNotSignable("pid must be a positive integer")
    if starttime is not None and not (_safe_int(starttime) and starttime >= 0):
        raise RowNotSignable("starttime must be a non-negative integer")
    if (pid is None) != (starttime is None):
        raise RowNotSignable("pid and starttime must both be set or both be null")


class LauncherSigner:
    """The launcher's Ed25519 row key. Only the launcher process loads it."""

    def __init__(self, private: Ed25519PrivateKey, *, trust: bool) -> None:
        """Wrap ``private``. With ``trust``, this process accepts its rows."""
        self._private = private
        self.public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        if trust:
            trust_launcher_key(self.public)

    @classmethod
    def at(cls, directory: Path) -> "LauncherSigner":
        """Load the key in ``directory``, creating it once with mode 0600.

        The launcher process that loads it trusts it.
        """
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        path = directory / SIGNING_KEY
        if not path.exists():
            seed = Ed25519PrivateKey.generate().private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()
            )
            tmp = path.with_name(path.name + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, seed)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(tmp, path)
            except FileExistsError:
                pass
            finally:
                tmp.unlink()
            fsync_dir(directory)
        raw = path.read_bytes()
        if len(raw) != 32:
            raise ValueError("launcher row key must be 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(raw), trust=True)

    @classmethod
    def from_seed(cls, seed: bytes) -> "LauncherSigner":
        """Build a signer from a fixed 32-byte seed for vectors and tests.

        This process does not trust it unless ``trust_launcher_key`` is called.
        """
        return cls(Ed25519PrivateKey.from_private_bytes(seed), trust=False)

    def sign_row(self, trust_domain: str, tenant: str, row: Dict[str, Any]) -> str:
        """Return ``launcher_sig`` for ``row`` after checking it is well formed."""
        require_signable(trust_domain, tenant, row)
        return self._private.sign(row_message(trust_domain, tenant, row)).hex()


def possession_keys(row: Mapping[str, Any]) -> List[str]:
    """Return the row's channel key and fingerprint in one namespace."""
    keys: List[str] = []
    channel = row.get("channel_public")
    if isinstance(channel, str) and channel:
        keys.append(f"ch:{channel}")
    fingerprint = row.get("cert_fingerprint")
    if isinstance(fingerprint, str) and fingerprint:
        keys.append(f"fp:{fingerprint}")
    return keys


def owner_of(row: Mapping[str, Any]) -> str:
    """Return the owner a key binds to: ``[instance_id, role]`` as JSON."""
    return js_json([str(row.get("instance_id")), str(row.get("role"))])


class KeyOwners:
    """The launcher's durable first-owner memory for keys and fingerprints."""

    def __init__(self, directory: Path) -> None:
        """Use ``directory/key-owners.jsonl``."""
        self.path = directory / KEY_OWNERS

    def owners(self) -> Dict[str, str]:
        """Return each key's first owner. A corrupt line raises."""
        if not self.path.exists():
            return {}
        owners: Dict[str, str] = {}
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            key = entry.get("key") if isinstance(entry, dict) else None
            owner = entry.get("owner") if isinstance(entry, dict) else None
            if not isinstance(key, str) or not isinstance(owner, str):
                raise ValueError("key owner journal row is malformed")
            owners.setdefault(key, owner)
        return owners

    def claim(self, rows: Sequence[Mapping[str, Any]]) -> None:
        """Record new keys for ``rows``, or raise ``KeyAlreadyBound``.

        Every row is checked before anything is recorded, so a refused save
        records nothing. New owners are fsynced before this returns, which is
        before the caller writes a registry that names them.
        """
        with self._locked():
            owners = self.owners()
            fresh: Dict[str, str] = {}
            for row in rows:
                claimant = owner_of(row)
                for key in possession_keys(row):
                    first = owners.get(key, fresh.get(key))
                    if first is None:
                        fresh[key] = claimant
                    elif first != claimant:
                        raise KeyAlreadyBound(key, first, claimant)
            if fresh:
                self._append(fresh)

    def _append(self, fresh: Mapping[str, str]) -> None:
        created = not self.path.exists()
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            for key, owner in fresh.items():
                line = json.dumps({"key": key, "owner": owner}, sort_keys=True) + "\n"
                os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        if created:
            fsync_dir(self.path.parent)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        handle = self.path.with_name(self.path.name + ".lock").open("a")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()


def trust_launcher_key(public: bytes) -> None:
    """Accept rows signed by ``public`` (32 raw bytes) in this process."""
    if len(public) != 32:
        raise ValueError("launcher public key must be 32 bytes")
    with _trusted_lock:
        if public not in _trusted:
            _trusted.append(bytes(public))


def trusted_launcher_keys() -> Sequence[bytes]:
    """Return the launcher keys this process accepts."""
    with _trusted_lock:
        return tuple(_trusted)


def parse_public(value: str) -> bytes:
    """Decode a ``--launcher-public`` value (64 hex characters)."""
    if not isinstance(value, str) or not _HEX32.match(value.lower()):
        raise ValueError("launcher public key must be 64 hex characters")
    return bytes.fromhex(value)


def row_attributed(
    trust_domain: str,
    tenant: str,
    row: Mapping[str, Any],
    keys: Optional[Iterable[bytes]] = None,
) -> bool:
    """Return whether ``row`` carries a valid ``launcher_sig``.

    A malformed row, a missing or non-hex signature, or a signature by a key
    this process does not trust is not attributed.
    """
    sig = row.get("launcher_sig")
    if not isinstance(sig, str) or not _SIG.match(sig):
        return False
    try:
        require_signable(trust_domain, tenant, row)
    except RowNotSignable:
        return False
    message = row_message(trust_domain, tenant, row)
    signature = bytes.fromhex(sig)
    for raw in trusted_launcher_keys() if keys is None else keys:
        try:
            Ed25519PublicKey.from_public_bytes(raw).verify(signature, message)
            return True
        except InvalidSignature:
            continue
    return False


def fsync_dir(directory: Path) -> None:
    """Make a created or renamed entry in ``directory`` durable."""
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _safe_int(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and -_MAX_SAFE <= value <= _MAX_SAFE
    )


def _check_encodable(value: Any) -> None:
    if value is None or isinstance(value, str):
        return
    if isinstance(value, bool):
        raise RowNotSignable("a row message holds no booleans")
    if isinstance(value, int):
        if not _safe_int(value):
            raise RowNotSignable("a row message integer must be a safe integer")
        return
    if isinstance(value, list):
        for item in value:
            _check_encodable(item)
        return
    raise RowNotSignable(f"a row message cannot hold {type(value).__name__}")
