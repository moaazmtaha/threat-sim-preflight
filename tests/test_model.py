from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from threat_sim_preflight.loader import load_plan
from threat_sim_preflight.model import PlanValidationError

from helpers import example_plan


class ModelTests(unittest.TestCase):
    def test_loads_toml_example(self) -> None:
        plan = example_plan()
        self.assertEqual(plan.environment, "production")
        self.assertEqual(len(plan.actions), 2)
        self.assertEqual(plan.actions[1].depends_on, ("account-discovery",))

    def test_rejects_unknown_extension(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "plan.yaml"
            path.write_text("schema_version: 1", encoding="utf-8")
            with self.assertRaisesRegex(PlanValidationError, "toml or .json"):
                load_plan(path)

    def test_collects_structural_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "plan.json"
            path.write_text('{"schema_version": 2}', encoding="utf-8")
            with self.assertRaises(PlanValidationError) as context:
                load_plan(path)
            self.assertGreater(len(context.exception.issues), 10)

    def test_rejects_bad_technique_format(self) -> None:
        source = (Path(__file__).parents[1] / "examples" / "production-plan.toml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "plan.toml"
            path.write_text(source.replace('"T1087.002"', '"TA0001"', 1), encoding="utf-8")
            with self.assertRaisesRegex(PlanValidationError, "T1059"):
                load_plan(path)


if __name__ == "__main__":
    unittest.main()
