from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import PlanValidationError


MAX_ATTACK_BYTES = 100 * 1024 * 1024


def load_attack_index(path: Path) -> dict[str, str]:
    try:
        if path.stat().st_size > MAX_ATTACK_BYTES:
            raise PlanValidationError(["ATT&CK bundle exceeds the 100 MiB limit"])
        document = json.loads(path.read_text(encoding="utf-8"))
    except PlanValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PlanValidationError([f"cannot parse ATT&CK bundle {path}: {exc}"]) from exc
    if not isinstance(document, dict) or not isinstance(document.get("objects"), list):
        raise PlanValidationError(["ATT&CK input must be a STIX bundle with an objects array"])
    index: dict[str, str] = {}
    for item in document["objects"]:
        if not isinstance(item, dict) or item.get("type") != "attack-pattern":
            continue
        if item.get("revoked") is True or item.get("x_mitre_deprecated") is True:
            continue
        for reference in item.get("external_references", []):
            if isinstance(reference, dict) and reference.get("source_name") == "mitre-attack":
                external_id = reference.get("external_id")
                if isinstance(external_id, str) and isinstance(item.get("name"), str):
                    index[external_id.upper()] = item["name"]
    if not index:
        raise PlanValidationError(["ATT&CK bundle contains no current enterprise technique records"])
    return index
