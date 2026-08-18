from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from threat_sim_preflight.attack_data import load_attack_index
from threat_sim_preflight.model import PlanValidationError


class AttackDataTests(unittest.TestCase):
    def test_indexes_current_attack_patterns_only(self) -> None:
        bundle = {
            "type": "bundle",
            "objects": [
                {"type": "attack-pattern", "name": "Current", "external_references": [{"source_name": "mitre-attack", "external_id": "T1000"}]},
                {"type": "attack-pattern", "name": "Revoked", "revoked": True, "external_references": [{"source_name": "mitre-attack", "external_id": "T1001"}]},
                {"type": "identity", "name": "Ignored"},
            ],
        }
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bundle.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")
            self.assertEqual(load_attack_index(path), {"T1000": "Current"})

    def test_rejects_non_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bundle.json"
            path.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(PlanValidationError, "STIX bundle"):
                load_attack_index(path)


if __name__ == "__main__":
    unittest.main()
