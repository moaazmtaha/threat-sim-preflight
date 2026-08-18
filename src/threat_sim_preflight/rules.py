from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date, datetime, timezone
from typing import Iterable, Mapping

from .graph import dependency_cycles
from .model import Plan, Waiver


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    location: str
    waived: bool = False
    waiver_rationale: str = ""


@dataclass(frozen=True, slots=True)
class CheckResult:
    plan: Plan
    findings: tuple[Finding, ...]
    evaluated_at: datetime

    @property
    def active_findings(self) -> tuple[Finding, ...]:
        return tuple(finding for finding in self.findings if not finding.waived)

    @property
    def ready(self) -> bool:
        return not any(finding.severity == "error" for finding in self.active_findings)

    @property
    def score(self) -> int:
        penalty = sum(
            {"error": 20, "warning": 5, "note": 0}[finding.severity]
            for finding in self.active_findings
        )
        return max(0, 100 - penalty)


def check_plan(
    plan: Plan,
    *,
    attack_index: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> CheckResult:
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []

    approved = _moment(plan.approved_at, "AUTH002", "approved_at", findings)
    window_start = _moment(plan.window_start, "WIN001", "window_start", findings)
    window_end = _moment(plan.window_end, "WIN001", "window_end", findings)
    if window_start and window_end and window_start >= window_end:
        findings.append(_finding("WIN002", "error", "window_start must be before window_end.", "window"))
    if window_end and now > window_end:
        findings.append(_finding("WIN003", "error", "The authorized execution window has expired.", "window_end"))
    if approved and window_start and approved > window_start:
        findings.append(_finding("AUTH003", "warning", "Approval is dated after the execution window begins.", "approved_at"))
    if approved and approved > now:
        findings.append(_finding("AUTH004", "error", "Approval timestamp is in the future.", "approved_at"))
    if plan.owner.casefold() == plan.authorizer.casefold():
        findings.append(_finding("AUTH001", "warning", "Plan owner and authorizer are the same person.", "authorizer"))

    scope = {asset.id: asset for asset in plan.scope}
    telemetry = {source.id: source for source in plan.telemetry}
    action_ids = {action.id for action in plan.actions}
    detection_techniques = {detection.technique_id for detection in plan.detections}
    used_techniques = {action.technique_id for action in plan.actions}

    for action in plan.actions:
        location = f"actions.{action.id}"
        if not action.targets:
            findings.append(_finding("SCOPE003", "error", "Action has no target assets.", location))
        for target in action.targets:
            if target not in scope:
                findings.append(_finding("SCOPE001", "error", f"Action references unknown scope asset {target}.", location))
            elif not scope[target].allowed:
                findings.append(_finding("SCOPE002", "error", f"Target {target} is explicitly outside the allowed scope.", location))
        for dependency in action.depends_on:
            if dependency not in action_ids:
                findings.append(_finding("DEP001", "error", f"Unknown action dependency {dependency}.", location))
            elif dependency == action.id:
                findings.append(_finding("DEP003", "error", "An action cannot depend on itself.", location))
        if not action.expected_telemetry:
            findings.append(_finding("TEL001", "warning", "Action names no expected telemetry.", location))
        for source_id in action.expected_telemetry:
            if source_id not in telemetry:
                findings.append(_finding("TEL002", "error", f"Unknown telemetry source {source_id}.", location))
        if not action.stop_conditions:
            findings.append(_finding("SAFE001", "error", "Action has no explicit stop condition.", location))
        if not action.cleanup:
            findings.append(_finding("SAFE002", "error", "Action has no cleanup step.", location))
        if plan.environment == "production" and action.destructive and not action.destructive_authorized:
            findings.append(_finding("SAFE003", "error", "Destructive production action lacks explicit authorization.", location))
        if plan.environment == "production" and not action.reversible:
            findings.append(_finding("SAFE004", "error", "Production action is marked irreversible.", location))
        if plan.environment == "production" and action.data_access == "content":
            findings.append(_finding("DATA001", "warning", "Production action may access content; verify minimization and retention.", location))
        if action.technique_id not in detection_techniques:
            findings.append(_finding("DET001", "warning", f"No detection validation covers {action.technique_id}.", location))
        if attack_index is not None and action.technique_id not in attack_index:
            findings.append(_finding("ATT001", "warning", f"{action.technique_id} was not found in the supplied current ATT&CK bundle.", location))

    for cycle in dependency_cycles(plan.actions):
        findings.append(_finding("DEP002", "error", f"Action dependency cycle: {' -> '.join(cycle)}.", "actions"))

    for source in plan.telemetry:
        verified = _moment(source.verified_at, "TEL003", f"telemetry.{source.id}", findings)
        if verified and (now - verified).days > 30:
            findings.append(_finding("TEL004", "warning", f"Telemetry source {source.id} was last verified more than 30 days ago.", f"telemetry.{source.id}"))
        if verified and verified > now:
            findings.append(_finding("TEL005", "error", f"Telemetry source {source.id} has a future verification timestamp.", f"telemetry.{source.id}"))

    for detection in plan.detections:
        location = f"detections.{detection.id}"
        if detection.technique_id not in used_techniques:
            findings.append(_finding("DET002", "note", f"Detection covers unused technique {detection.technique_id}.", location))
        if not detection.telemetry_ids:
            findings.append(_finding("DET003", "warning", "Detection names no telemetry source.", location))
        for source_id in detection.telemetry_ids:
            if source_id not in telemetry:
                findings.append(_finding("DET004", "error", f"Detection references unknown telemetry source {source_id}.", location))

    if plan.environment == "production" and not any(asset.production for asset in plan.scope):
        findings.append(_finding("PROD001", "warning", "Plan is production but no scope asset is marked production.", "scope"))
    if plan.environment != "production" and any(asset.production for asset in plan.scope):
        findings.append(_finding("PROD002", "warning", "Non-production plan includes a production-marked asset.", "scope"))

    findings = _apply_waivers(findings, plan.waivers, now.date())
    return CheckResult(plan=plan, findings=tuple(sorted(findings, key=_finding_key)), evaluated_at=now)


def _apply_waivers(findings: list[Finding], waivers: Iterable[Waiver], today: date) -> list[Finding]:
    valid: dict[str, Waiver] = {}
    extra: list[Finding] = []
    known_rules = {finding.rule_id for finding in findings}
    for waiver in waivers:
        try:
            expires = date.fromisoformat(waiver.expires)
        except ValueError:
            extra.append(_finding("WVR001", "error", f"Waiver for {waiver.rule_id} has an invalid expiry date.", "waivers"))
            continue
        if expires < today:
            extra.append(_finding("WVR002", "warning", f"Waiver for {waiver.rule_id} expired on {waiver.expires}.", "waivers"))
            continue
        if waiver.rule_id not in known_rules:
            extra.append(_finding("WVR003", "note", f"Waiver for {waiver.rule_id} does not match a current finding.", "waivers"))
            continue
        valid[waiver.rule_id] = waiver
    waived = [
        replace(finding, waived=True, waiver_rationale=valid[finding.rule_id].rationale)
        if finding.rule_id in valid
        else finding
        for finding in findings
    ]
    return waived + extra


def _moment(value: str, rule_id: str, location: str, findings: list[Finding]) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(timezone.utc)
    except ValueError:
        findings.append(_finding(rule_id, "error", f"{location} must be an ISO 8601 timestamp with an offset.", location))
        return None


def _finding(rule_id: str, severity: str, message: str, location: str) -> Finding:
    return Finding(rule_id=rule_id, severity=severity, message=message, location=location)


def _finding_key(finding: Finding) -> tuple[int, bool, str, str]:
    return ({"error": 0, "warning": 1, "note": 2}[finding.severity], finding.waived, finding.rule_id, finding.location)
