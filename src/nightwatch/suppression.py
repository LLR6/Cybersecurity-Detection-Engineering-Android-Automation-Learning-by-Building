from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any

from .models import Alert


def load_suppressions(path: str | Path) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("suppressions", [])
    if not isinstance(data, list):
        raise ValueError("suppression file must contain a list or {'suppressions': [...]}")

    out: list[dict[str, Any]] = []
    for index, item in enumerate(data, 1):
        if not isinstance(item, dict):
            raise ValueError(f"suppression #{index} must be an object")
        rule_id = str(item.get("rule_id", "*")).strip() or "*"
        entity = str(item.get("entity", "*")).strip() or "*"
        reason = str(item.get("reason", "known benign")).strip() or "known benign"
        out.append({"rule_id": rule_id, "entity": entity, "reason": reason})
    return out


def apply_suppressions(
    alerts: list[Alert], suppressions: list[dict[str, Any]]
) -> tuple[list[Alert], list[dict[str, Any]]]:
    kept: list[Alert] = []
    suppressed: list[dict[str, Any]] = []

    for alert in alerts:
        matched = None
        for item in suppressions:
            if fnmatch.fnmatchcase(alert.rule_id, item["rule_id"]) and fnmatch.fnmatchcase(
                alert.entity, item["entity"]
            ):
                matched = item
                break

        if matched is None:
            kept.append(alert)
            continue

        suppressed.append(
            {
                "rule_id": alert.rule_id,
                "entity": alert.entity,
                "score": alert.score,
                "reason": matched["reason"],
                "matched_rule_id": matched["rule_id"],
                "matched_entity": matched["entity"],
            }
        )

    return kept, suppressed
