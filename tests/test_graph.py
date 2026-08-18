from __future__ import annotations

from dataclasses import replace
import unittest

from threat_sim_preflight.graph import dependency_cycles, topological_order

from helpers import example_plan


class GraphTests(unittest.TestCase):
    def test_topological_order_is_deterministic(self) -> None:
        plan = example_plan()
        self.assertEqual(topological_order(plan.actions), ("account-discovery", "controlled-powershell"))

    def test_detects_cycle(self) -> None:
        plan = example_plan()
        first, second = plan.actions
        actions = (replace(first, depends_on=(second.id,)), second)
        self.assertEqual(dependency_cycles(actions), (("account-discovery", "controlled-powershell", "account-discovery"),))
        self.assertEqual(topological_order(actions), ())

    def test_unknown_dependency_does_not_break_order(self) -> None:
        plan = example_plan()
        actions = (replace(plan.actions[0], depends_on=("missing",)), plan.actions[1])
        self.assertEqual(topological_order(actions), ("account-discovery", "controlled-powershell"))


if __name__ == "__main__":
    unittest.main()
