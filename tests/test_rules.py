from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import unittest

from threat_sim_preflight.model import Waiver
from threat_sim_preflight.rules import check_plan

from helpers import example_plan


NOW = datetime(2026, 8, 18, 12, tzinfo=timezone.utc)


class RuleTests(unittest.TestCase):
    def test_example_is_ready(self) -> None:
        result = check_plan(example_plan(), now=NOW)
        self.assertTrue(result.ready)
        self.assertEqual(result.score, 100)
        self.assertEqual(result.findings, ())

    def test_expired_window_blocks(self) -> None:
        plan = replace(example_plan(), window_end="2026-08-17T20:00:00+00:00")
        result = check_plan(plan, now=NOW)
        self.assertIn("WIN003", {finding.rule_id for finding in result.active_findings})
        self.assertFalse(result.ready)

    def test_bad_action_triggers_scope_safety_telemetry_and_detection(self) -> None:
        plan = example_plan()
        bad = replace(
            plan.actions[0],
            targets=("missing", "finance-share"),
            depends_on=("missing-action",),
            expected_telemetry=("missing-log",),
            cleanup=(),
            stop_conditions=(),
            destructive=True,
            destructive_authorized=False,
            reversible=False,
            data_access="content",
            technique_id="T9999",
        )
        result = check_plan(replace(plan, actions=(bad, plan.actions[1])), attack_index={"T1059.001": "PowerShell"}, now=NOW)
        rules = {finding.rule_id for finding in result.active_findings}
        self.assertTrue(
            {"SCOPE001", "SCOPE002", "DEP001", "TEL002", "SAFE001", "SAFE002", "SAFE003", "SAFE004", "DATA001", "DET001", "ATT001"}.issubset(rules)
        )
        self.assertFalse(result.ready)

    def test_dependency_cycle_blocks(self) -> None:
        plan = example_plan()
        first, second = plan.actions
        result = check_plan(replace(plan, actions=(replace(first, depends_on=(second.id,)), second)), now=NOW)
        self.assertIn("DEP002", {finding.rule_id for finding in result.active_findings})

    def test_current_waiver_is_visible_but_not_active(self) -> None:
        plan = example_plan()
        plan = replace(
            plan,
            owner=plan.authorizer,
            waivers=(Waiver("AUTH001", "Approved single-person lab workflow", "Security lead", "2026-09-01"),),
        )
        result = check_plan(plan, now=NOW)
        finding = next(finding for finding in result.findings if finding.rule_id == "AUTH001")
        self.assertTrue(finding.waived)
        self.assertTrue(result.ready)
        self.assertEqual(result.score, 100)

    def test_expired_waiver_does_not_suppress(self) -> None:
        plan = example_plan()
        plan = replace(
            plan,
            owner=plan.authorizer,
            waivers=(Waiver("AUTH001", "Old exception", "Security lead", "2026-08-01"),),
        )
        result = check_plan(plan, now=NOW)
        self.assertEqual({finding.rule_id for finding in result.active_findings}, {"AUTH001", "WVR002"})

    def test_stale_and_future_telemetry_are_reported(self) -> None:
        plan = example_plan()
        stale = replace(plan.telemetry[0], verified_at="2026-01-01T00:00:00+00:00")
        future = replace(plan.telemetry[1], verified_at="2026-09-01T00:00:00+00:00")
        result = check_plan(replace(plan, telemetry=(stale, future)), now=NOW)
        self.assertEqual({finding.rule_id for finding in result.active_findings}, {"TEL004", "TEL005"})

    def test_production_flag_mismatch(self) -> None:
        plan = replace(example_plan(), environment="lab")
        result = check_plan(plan, now=NOW)
        self.assertIn("PROD002", {finding.rule_id for finding in result.active_findings})


if __name__ == "__main__":
    unittest.main()
