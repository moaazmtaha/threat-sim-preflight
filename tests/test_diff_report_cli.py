from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from threat_sim_preflight.cli import main
from threat_sim_preflight.diff import compare_plans, diff_markdown
from threat_sim_preflight.report import markdown_report, result_document
from threat_sim_preflight.rules import check_plan
from threat_sim_preflight.sarif import sarif_document

from helpers import example_plan


class DiffReportCliTests(unittest.TestCase):
    def test_diff_detects_material_changes(self) -> None:
        baseline = example_plan()
        candidate = replace(
            baseline,
            environment="staging",
            scope=baseline.scope[:-1],
            actions=(replace(baseline.actions[0], objective="Changed objective"),),
        )
        diff = compare_plans(baseline, candidate)
        self.assertEqual(diff.removed_assets, ("finance-share",))
        self.assertEqual(diff.removed_actions, ("controlled-powershell",))
        self.assertEqual(diff.changed_actions, ("account-discovery",))
        self.assertTrue(diff.environment_changed)
        self.assertIn("Changed actions", diff_markdown(diff))

    def test_reports_escape_markdown_and_emit_sarif(self) -> None:
        plan = replace(example_plan(), owner=example_plan().authorizer, title="Bad | `title`")
        result = check_plan(plan, now=datetime(2026, 8, 18, 12, tzinfo=timezone.utc))
        markdown = markdown_report(result, source="plan|name")
        self.assertIn("Bad \\| \\`title\\`", markdown)
        document = result_document(result, source="plan.toml")
        self.assertEqual(document["summary"]["warning"], 1)
        sarif = sarif_document(result, source_path=Path("plan.toml"))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "AUTH001")

    def test_cli_writes_reports(self) -> None:
        source = Path(__file__).parents[1] / "examples" / "production-plan.toml"
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "out"
            code = main(["report", str(source), "--as-of", "2026-08-18T12:00:00+00:00", "--out-dir", str(output)])
            self.assertEqual(code, 0)
            self.assertEqual({path.name for path in output.iterdir()}, {"report.json", "report.md", "results.sarif"})
            self.assertTrue(json.loads((output / "report.json").read_text(encoding="utf-8"))["summary"]["ready"])

    def test_cli_rejects_naive_as_of(self) -> None:
        source = Path(__file__).parents[1] / "examples" / "production-plan.toml"
        self.assertEqual(main(["check", str(source), "--as-of", "2026-08-18T12:00:00"]), 2)


if __name__ == "__main__":
    unittest.main()
