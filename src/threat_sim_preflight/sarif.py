from __future__ import annotations

from pathlib import Path
from typing import Any

from .rules import CheckResult


def sarif_document(result: CheckResult, *, source_path: Path) -> dict[str, Any]:
    uri = source_path.as_posix() if not source_path.is_absolute() else source_path.name
    rule_ids = sorted({finding.rule_id for finding in result.findings})
    rules = [
        {
            "id": rule_id,
            "name": _slug(rule_id),
            "shortDescription": {"text": f"Threat-simulation preflight rule {rule_id}."},
            "defaultConfiguration": {"level": "warning"},
        }
        for rule_id in rule_ids
    ]
    findings = [
        {
            "ruleId": finding.rule_id,
            "level": "none" if finding.waived else {"error": "error", "warning": "warning", "note": "note"}[finding.severity],
            "message": {"text": finding.message},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "properties": {
                "planLocation": finding.location,
                "waived": finding.waived,
                "waiverRationale": finding.waiver_rationale,
            },
        }
        for finding in result.findings
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "threat-sim-preflight",
                        "informationUri": "https://github.com/moaazmtaha/threat-sim-preflight",
                        "semanticVersion": "0.1.0",
                        "rules": rules,
                    }
                },
                "results": findings,
                "properties": {"evaluatedAt": result.evaluated_at.isoformat(), "ready": result.ready, "score": result.score},
            }
        ],
    }


def _slug(rule_id: str) -> str:
    return "preflight-" + rule_id.lower()
