from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Alert


def alert_key(alert: Alert) -> tuple[str, str]:
    return alert.rule_id, alert.entity


def load_truth(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema") != "nightwatch-eval/v1":
        raise ValueError("unsupported evaluation truth schema")
    expected = data.get("expected")
    if not isinstance(expected, list):
        raise ValueError("expected must be a list")
    normalized = []
    seen = set()
    for index, item in enumerate(expected, 1):
        if not isinstance(item, dict):
            raise ValueError(f"expected #{index} must be an object")
        rule_id = str(item.get("rule_id", "")).strip()
        entity = str(item.get("entity", "")).strip()
        if not rule_id or not entity:
            raise ValueError(f"expected #{index} needs rule_id and entity")
        key = (rule_id, entity)
        if key in seen:
            raise ValueError(f"duplicate expected alert: {rule_id} / {entity}")
        seen.add(key)
        normalized.append({"rule_id": rule_id, "entity": entity})
    return {"schema": data["schema"], "expected": normalized}


def evaluate(alerts: list[Alert], truth: dict[str, Any]) -> dict[str, Any]:
    expected = {(x["rule_id"], x["entity"]) for x in truth["expected"]}
    observed = {alert_key(a) for a in alerts}
    matched = sorted(expected & observed)
    missed = sorted(expected - observed)
    unexpected = sorted(observed - expected)
    tp, fp, fn = len(matched), len(unexpected), len(missed)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "schema": "nightwatch-evaluation-report/v1",
        "counts": {"tp": tp, "fp": fp, "fn": fn},
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
        "matched": [{"rule_id": r, "entity": e} for r, e in matched],
        "missed": [{"rule_id": r, "entity": e} for r, e in missed],
        "unexpected": [{"rule_id": r, "entity": e} for r, e in unexpected],
    }


def as_markdown(report: dict[str, Any]) -> str:
    c = report["counts"]
    lines = [
        "# NightWatch Evaluation", "",
        f"- TP: **{c['tp']}**",
        f"- FP: **{c['fp']}**",
        f"- FN: **{c['fn']}**",
        f"- Precision: **{report['precision']}**",
        f"- Recall: **{report['recall']}**",
        f"- F1: **{report['f1']}**", "",
    ]
    for title, key in (("Matched", "matched"), ("Missed", "missed"), ("Unexpected", "unexpected")):
        lines += [f"## {title}", ""]
        rows = report[key]
        lines += ["- none"] if not rows else [f"- {x['rule_id']} · {x['entity']}" for x in rows]
        lines.append("")
    return "\n".join(lines)
