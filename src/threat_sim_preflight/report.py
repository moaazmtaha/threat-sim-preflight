from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .graph import topological_order
from .rules import CheckResult


def result_document(result: CheckResult, *, source: str) -> dict[str, Any]:
    counts = {
        severity: sum(finding.severity == severity and not finding.waived for finding in result.findings)
        for severity in ("error", "warning", "note")
    }
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evaluated_at": result.evaluated_at.isoformat(),
        "source": source,
        "summary": {
            "title": result.plan.title,
            "ready": result.ready,
            "score": result.score,
            "actions": len(result.plan.actions),
            "assets": len(result.plan.scope),
            "waived": sum(finding.waived for finding in result.findings),
            **counts,
        },
        "execution_order": list(topological_order(result.plan.actions)),
        "findings": [asdict(finding) for finding in result.findings],
    }


def markdown_report(result: CheckResult, *, source: str) -> str:
    status = "READY" if result.ready else "NOT READY"
    active = result.active_findings
    lines = [
        f"# {_md(result.plan.title)}",
        "",
        f"**{status}** · readiness score {result.score}/100 · evaluated {result.evaluated_at.isoformat()} · {_md(source)}",
        "",
        "## Findings",
        "",
        "| Severity | Rule | Location | Finding |",
        "| --- | --- | --- | --- |",
    ]
    if not result.findings:
        lines.append("| — | — | — | No findings. |")
    for finding in result.findings:
        severity = f"waived {finding.severity}" if finding.waived else finding.severity
        message = finding.message
        if finding.waived:
            message += f" Waiver: {finding.waiver_rationale}"
        lines.append(
            f"| {_md(severity)} | `{_md(finding.rule_id)}` | `{_md(finding.location)}` | {_md(message)} |"
        )
    lines.extend(["", "## Proposed execution order", ""])
    order = topological_order(result.plan.actions)
    if order:
        lines.extend(f"{index}. `{_md(action_id)}`" for index, action_id in enumerate(order, 1))
    else:
        lines.append("No valid order: resolve dependency errors or cycles.")
    lines.extend(
        [
            "",
            "## Coverage",
            "",
            f"- Scope assets: {len(result.plan.scope)}",
            f"- Planned actions: {len(result.plan.actions)}",
            f"- ATT&CK techniques: {len({action.technique_id for action in result.plan.actions})}",
            f"- Telemetry sources: {len(result.plan.telemetry)}",
            f"- Detection validations: {len(result.plan.detections)}",
            f"- Active blocking findings: {sum(f.severity == 'error' for f in active)}",
            "",
            "Generated locally by threat-sim-preflight. This is a plan-quality gate, not authorization to execute.",
            "",
        ]
    )
    return "\n".join(lines)


def write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _md(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`").replace("\n", " ")
