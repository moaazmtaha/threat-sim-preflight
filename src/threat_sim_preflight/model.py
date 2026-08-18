from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable, Mapping


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
ENVIRONMENTS = {"lab", "staging", "production"}


class PlanValidationError(ValueError):
    def __init__(self, issues: Iterable[str]) -> None:
        self.issues = tuple(issues)
        super().__init__("; ".join(self.issues))


@dataclass(frozen=True, slots=True)
class ScopeAsset:
    id: str
    kind: str
    owner: str
    allowed: bool
    production: bool


@dataclass(frozen=True, slots=True)
class Telemetry:
    id: str
    source: str
    owner: str
    verified_at: str


@dataclass(frozen=True, slots=True)
class Action:
    id: str
    name: str
    technique_id: str
    objective: str
    targets: tuple[str, ...]
    depends_on: tuple[str, ...]
    expected_telemetry: tuple[str, ...]
    cleanup: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    destructive: bool
    destructive_authorized: bool
    reversible: bool
    data_access: str


@dataclass(frozen=True, slots=True)
class Detection:
    id: str
    name: str
    technique_id: str
    owner: str
    telemetry_ids: tuple[str, ...]
    validation: str


@dataclass(frozen=True, slots=True)
class Waiver:
    rule_id: str
    rationale: str
    approved_by: str
    expires: str


@dataclass(frozen=True, slots=True)
class Plan:
    title: str
    owner: str
    environment: str
    change_ticket: str
    evidence_store: str
    authorizer: str
    approved_at: str
    window_start: str
    window_end: str
    timezone: str
    stop_contact: str
    cleanup_owner: str
    scope: tuple[ScopeAsset, ...]
    telemetry: tuple[Telemetry, ...]
    actions: tuple[Action, ...]
    detections: tuple[Detection, ...]
    waivers: tuple[Waiver, ...]

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> Plan:
        issues: list[str] = []
        if document.get("schema_version") != 1:
            issues.append("schema_version must be 1")
        title = _text(document, "title", issues)
        owner = _text(document, "owner", issues)
        environment = _text(document, "environment", issues).lower()
        if environment and environment not in ENVIRONMENTS:
            issues.append("environment must be lab, staging, or production")
        fields = {
            name: _text(document, name, issues)
            for name in (
                "change_ticket",
                "evidence_store",
                "authorizer",
                "approved_at",
                "window_start",
                "window_end",
                "timezone",
                "stop_contact",
                "cleanup_owner",
            )
        }

        scope = _parse_scope(document.get("scope"), issues)
        telemetry = _parse_telemetry(document.get("telemetry", []), issues)
        actions = _parse_actions(document.get("actions"), issues)
        detections = _parse_detections(document.get("detections", []), issues)
        waivers = _parse_waivers(document.get("waivers", []), issues)
        _unique_ids(scope, "scope", issues)
        _unique_ids(telemetry, "telemetry", issues)
        _unique_ids(actions, "actions", issues)
        _unique_ids(detections, "detections", issues)
        if issues:
            raise PlanValidationError(issues)
        return cls(
            title=title,
            owner=owner,
            environment=environment,
            scope=scope,
            telemetry=telemetry,
            actions=actions,
            detections=detections,
            waivers=waivers,
            **fields,
        )


def _text(document: Mapping[str, Any], name: str, issues: list[str]) -> str:
    value = document.get(name)
    if not isinstance(value, str) or not value.strip():
        issues.append(f"{name} must be non-empty text")
        return ""
    return value.strip()


def _identifier(raw: Mapping[str, Any], prefix: str, issues: list[str]) -> str:
    value = raw.get("id")
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        issues.append(f"{prefix}.id must be a stable 1-128 character identifier")
        return ""
    return value


def _array(document: Mapping[str, Any], name: str, prefix: str, issues: list[str]) -> tuple[str, ...]:
    raw = document.get(name, [])
    if not isinstance(raw, list) or any(not isinstance(item, str) or not item.strip() for item in raw):
        issues.append(f"{prefix}.{name} must be an array of non-empty strings")
        return ()
    return tuple(dict.fromkeys(item.strip() for item in raw))


def _bool(document: Mapping[str, Any], name: str, prefix: str, issues: list[str], default: bool) -> bool:
    value = document.get(name, default)
    if not isinstance(value, bool):
        issues.append(f"{prefix}.{name} must be boolean")
        return default
    return value


def _objects(raw: Any, name: str, issues: list[str], *, required: bool) -> list[Mapping[str, Any]]:
    if not isinstance(raw, list) or (required and not raw):
        issues.append(f"{name} must be a{' non-empty' if required else 'n'} array")
        return []
    result = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            issues.append(f"{name}[{index}] must be an object")
        else:
            result.append(item)
    return result


def _parse_scope(raw: Any, issues: list[str]) -> tuple[ScopeAsset, ...]:
    result = []
    for index, item in enumerate(_objects(raw, "scope", issues, required=True)):
        prefix = f"scope[{index}]"
        result.append(
            ScopeAsset(
                id=_identifier(item, prefix, issues),
                kind=_text_at(item, "kind", prefix, issues),
                owner=_text_at(item, "owner", prefix, issues),
                allowed=_bool(item, "allowed", prefix, issues, False),
                production=_bool(item, "production", prefix, issues, False),
            )
        )
    return tuple(result)


def _parse_telemetry(raw: Any, issues: list[str]) -> tuple[Telemetry, ...]:
    result = []
    for index, item in enumerate(_objects(raw, "telemetry", issues, required=False)):
        prefix = f"telemetry[{index}]"
        result.append(
            Telemetry(
                id=_identifier(item, prefix, issues),
                source=_text_at(item, "source", prefix, issues),
                owner=_text_at(item, "owner", prefix, issues),
                verified_at=_text_at(item, "verified_at", prefix, issues),
            )
        )
    return tuple(result)


def _parse_actions(raw: Any, issues: list[str]) -> tuple[Action, ...]:
    result = []
    for index, item in enumerate(_objects(raw, "actions", issues, required=True)):
        prefix = f"actions[{index}]"
        technique_id = _text_at(item, "technique_id", prefix, issues).upper()
        if technique_id and not TECHNIQUE_ID.fullmatch(technique_id):
            issues.append(f"{prefix}.technique_id must look like T1059 or T1059.001")
        data_access = str(item.get("data_access", "none")).strip().lower()
        if data_access not in {"none", "metadata", "content"}:
            issues.append(f"{prefix}.data_access must be none, metadata, or content")
            data_access = "none"
        result.append(
            Action(
                id=_identifier(item, prefix, issues),
                name=_text_at(item, "name", prefix, issues),
                technique_id=technique_id,
                objective=_text_at(item, "objective", prefix, issues),
                targets=_array(item, "targets", prefix, issues),
                depends_on=_array(item, "depends_on", prefix, issues),
                expected_telemetry=_array(item, "expected_telemetry", prefix, issues),
                cleanup=_array(item, "cleanup", prefix, issues),
                stop_conditions=_array(item, "stop_conditions", prefix, issues),
                destructive=_bool(item, "destructive", prefix, issues, False),
                destructive_authorized=_bool(item, "destructive_authorized", prefix, issues, False),
                reversible=_bool(item, "reversible", prefix, issues, True),
                data_access=data_access,
            )
        )
    return tuple(result)


def _parse_detections(raw: Any, issues: list[str]) -> tuple[Detection, ...]:
    result = []
    for index, item in enumerate(_objects(raw, "detections", issues, required=False)):
        prefix = f"detections[{index}]"
        technique_id = _text_at(item, "technique_id", prefix, issues).upper()
        if technique_id and not TECHNIQUE_ID.fullmatch(technique_id):
            issues.append(f"{prefix}.technique_id must look like T1059 or T1059.001")
        result.append(
            Detection(
                id=_identifier(item, prefix, issues),
                name=_text_at(item, "name", prefix, issues),
                technique_id=technique_id,
                owner=_text_at(item, "owner", prefix, issues),
                telemetry_ids=_array(item, "telemetry_ids", prefix, issues),
                validation=_text_at(item, "validation", prefix, issues),
            )
        )
    return tuple(result)


def _parse_waivers(raw: Any, issues: list[str]) -> tuple[Waiver, ...]:
    result = []
    for index, item in enumerate(_objects(raw, "waivers", issues, required=False)):
        prefix = f"waivers[{index}]"
        result.append(
            Waiver(
                rule_id=_text_at(item, "rule_id", prefix, issues).upper(),
                rationale=_text_at(item, "rationale", prefix, issues),
                approved_by=_text_at(item, "approved_by", prefix, issues),
                expires=_text_at(item, "expires", prefix, issues),
            )
        )
    return tuple(result)


def _text_at(document: Mapping[str, Any], name: str, prefix: str, issues: list[str]) -> str:
    value = document.get(name)
    if not isinstance(value, str) or not value.strip():
        issues.append(f"{prefix}.{name} must be non-empty text")
        return ""
    return value.strip()


def _unique_ids(items: Iterable[Any], name: str, issues: list[str]) -> None:
    seen: set[str] = set()
    for item in items:
        if not item.id:
            continue
        if item.id in seen:
            issues.append(f"duplicate {name} id: {item.id}")
        seen.add(item.id)
