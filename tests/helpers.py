from __future__ import annotations

from pathlib import Path

from threat_sim_preflight.loader import load_plan


def example_plan():
    return load_plan(Path(__file__).parents[1] / "examples" / "production-plan.toml")
