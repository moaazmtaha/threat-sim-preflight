from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import sys

from .attack_data import load_attack_index
from .diff import compare_plans, diff_document, diff_markdown
from .loader import load_plan
from .model import PlanValidationError
from .report import markdown_report, result_document, write_json, write_text
from .rules import CheckResult, check_plan
from .sarif import sarif_document


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat-sim-preflight",
        description="Check an authorized threat-simulation plan before execution.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Validate structure without running policy checks.")
    validate.add_argument("plan", type=Path)

    check = commands.add_parser("check", help="Run readiness checks and print findings.")
    _check_arguments(check)
    check.add_argument("--strict", action="store_true", help="Return failure when warnings remain.")

    report = commands.add_parser("report", help="Run checks and write Markdown, JSON, and SARIF reports.")
    _check_arguments(report)
    report.add_argument("--out-dir", type=Path, default=Path("preflight-report"))

    diff = commands.add_parser("diff", help="Compare material scope, action, technique, and window changes.")
    diff.add_argument("baseline", type=Path)
    diff.add_argument("candidate", type=Path)
    diff.add_argument("--format", choices=("markdown", "json"), default="markdown")
    return parser


def _check_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("plan", type=Path)
    parser.add_argument("--attack-stix", type=Path, help="Optional local MITRE ATT&CK STIX bundle.")
    parser.add_argument("--as-of", help="Evaluate time rules at an ISO 8601 timestamp (for reproducible review).")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "diff":
            diff = compare_plans(load_plan(args.baseline), load_plan(args.candidate))
            print(json.dumps(diff_document(diff), indent=2, sort_keys=True) if args.format == "json" else diff_markdown(diff), end="\n" if args.format == "json" else "")
            return 0
        plan = load_plan(args.plan)
        if args.command == "validate":
            print(f"valid: {len(plan.scope)} assets, {len(plan.actions)} actions")
            return 0
        attack_index = load_attack_index(args.attack_stix) if args.attack_stix else None
        now = _parse_as_of(args.as_of) if args.as_of else None
        result = check_plan(plan, attack_index=attack_index, now=now)
        if args.command == "check":
            _print_findings(result)
            if not result.ready or (args.strict and any(f.severity == "warning" for f in result.active_findings)):
                return 1
            return 0
        out_dir: Path = args.out_dir
        write_json(out_dir / "report.json", result_document(result, source=str(args.plan)))
        write_text(out_dir / "report.md", markdown_report(result, source=str(args.plan)))
        write_json(out_dir / "results.sarif", sarif_document(result, source_path=args.plan))
        _print_findings(result)
        print(f"reports: {out_dir.resolve()}")
        return 0 if result.ready else 1
    except PlanValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _parse_as_of(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed
    except ValueError as exc:
        raise PlanValidationError(["--as-of must be an ISO 8601 timestamp with an offset"]) from exc


def _print_findings(result: CheckResult) -> None:
    status = "READY" if result.ready else "NOT READY"
    print(f"{status} | score {result.score}/100 | {len(result.findings)} findings")
    for finding in result.findings:
        suffix = " [waived]" if finding.waived else ""
        print(f"{finding.severity.upper():7} {finding.rule_id} {finding.location}: {finding.message}{suffix}")


if __name__ == "__main__":
    raise SystemExit(main())
