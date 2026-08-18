from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .model import Action, Plan


@dataclass(frozen=True, slots=True)
class PlanDiff:
    added_assets: tuple[str, ...]
    removed_assets: tuple[str, ...]
    added_actions: tuple[str, ...]
    removed_actions: tuple[str, ...]
    changed_actions: tuple[str, ...]
    added_techniques: tuple[str, ...]
    removed_techniques: tuple[str, ...]
    environment_changed: bool
    window_changed: bool

    @property
    def has_changes(self) -> bool:
        return any(value for value in asdict(self).values())


def compare_plans(baseline: Plan, candidate: Plan) -> PlanDiff:
    old_actions = {action.id: action for action in baseline.actions}
    new_actions = {action.id: action for action in candidate.actions}
    common = old_actions.keys() & new_actions.keys()
    old_assets = {asset.id for asset in baseline.scope}
    new_assets = {asset.id for asset in candidate.scope}
    old_techniques = {action.technique_id for action in baseline.actions}
    new_techniques = {action.technique_id for action in candidate.actions}
    return PlanDiff(
        added_assets=tuple(sorted(new_assets - old_assets)),
        removed_assets=tuple(sorted(old_assets - new_assets)),
        added_actions=tuple(sorted(new_actions.keys() - old_actions.keys())),
        removed_actions=tuple(sorted(old_actions.keys() - new_actions.keys())),
        changed_actions=tuple(sorted(action_id for action_id in common if old_actions[action_id] != new_actions[action_id])),
        added_techniques=tuple(sorted(new_techniques - old_techniques)),
        removed_techniques=tuple(sorted(old_techniques - new_techniques)),
        environment_changed=baseline.environment != candidate.environment,
        window_changed=(baseline.window_start, baseline.window_end) != (candidate.window_start, candidate.window_end),
    )


def diff_document(diff: PlanDiff) -> dict[str, Any]:
    return asdict(diff) | {"has_changes": diff.has_changes}


def diff_markdown(diff: PlanDiff) -> str:
    lines = ["# Threat-simulation plan diff", ""]
    if not diff.has_changes:
        return "\n".join(lines + ["No material plan changes detected.", ""])
    for label, values in (
        ("Added assets", diff.added_assets),
        ("Removed assets", diff.removed_assets),
        ("Added actions", diff.added_actions),
        ("Removed actions", diff.removed_actions),
        ("Changed actions", diff.changed_actions),
        ("Added techniques", diff.added_techniques),
        ("Removed techniques", diff.removed_techniques),
    ):
        lines.extend([f"## {label}", "", ", ".join(f"`{item}`" for item in values) if values else "None", ""])
    lines.extend(["## Plan-level changes", "", f"- Environment changed: {str(diff.environment_changed).lower()}", f"- Execution window changed: {str(diff.window_changed).lower()}", ""])
    return "\n".join(lines)
