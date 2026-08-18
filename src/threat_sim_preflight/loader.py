from __future__ import annotations

import json
from pathlib import Path
import tomllib
from typing import Any

from .model import Plan, PlanValidationError


MAX_INPUT_BYTES = 5 * 1024 * 1024


def load_plan(path: Path) -> Plan:
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise PlanValidationError(["plan exceeds the 5 MiB input limit"])
        raw = path.read_bytes()
        if path.suffix.lower() == ".toml":
            document = tomllib.loads(raw.decode("utf-8"))
        elif path.suffix.lower() == ".json":
            document = json.loads(raw.decode("utf-8"))
        else:
            raise PlanValidationError(["plan must use a .toml or .json extension"])
    except PlanValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PlanValidationError([f"cannot parse {path}: {exc}"]) from exc
    if not isinstance(document, dict):
        raise PlanValidationError(["plan root must be an object/table"])
    return Plan.from_dict(_stringify_temporals(document))


def _stringify_temporals(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _stringify_temporals(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_stringify_temporals(item) for item in value]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value
