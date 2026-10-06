"""Vendored WS1 files match the recorded pack hashes."""

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINS = ROOT / "profiles" / "eggomi" / "ws1-pins.json"
ZIP_SHA256 = "f3da0ddc62b6ad94711a045bf9fffd96a618857268cd2d7ff8f43ca6be05413c"
EXPECTED = {
    "contracts/ws1/service-access.json": (
        "379db489ac1d7385bb9c3aee847ff69c7e2d6149a9d0a9519d79814f77fef9a1"
    ),
    "contracts/ws1/scenarios.json": (
        "a9ff9e44836fe70b75e66e3367c76f24922bf507f27e4deb7d3f0625faef9820"
    ),
    "contracts/ws1/metrics.json": (
        "ab065b7d1422713c17e2a906df4253cd3cf6c82b0e93cb3f21c83506329a3ce5"
    ),
    "contracts/ws1/acceptance.json": (
        "3b4416a9f1203de1ae3653998b68cb34f7d275526ae964307d4543a7bf9cafcf"
    ),
    "contracts/ws1/experiment.schema.json": (
        "4c203000b22f9fa99a3714435565e9980d9efe78408d42e3336283312121af6f"
    ),
    "contracts/ws1/baseline-manifest.json": (
        "2b2c9fc43de329ee4caa6a6b3f4efafbc6071d20c73194ac9a5901e489ed0d23"
    ),
}


class PinTests(unittest.TestCase):
    """The attached WS1 revision 1 contracts stay byte-pinned."""

    def test_vendored_contracts_match_pins(self) -> None:
        """Each vendored file hashes to the pin and to the expected constant."""
        raw = json.loads(PINS.read_text(encoding="utf-8"))
        self.assertEqual(raw["zip_sha256"], ZIP_SHA256)
        self.assertEqual(raw["files"], EXPECTED)
        for name, digest in EXPECTED.items():
            data = (ROOT / name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
