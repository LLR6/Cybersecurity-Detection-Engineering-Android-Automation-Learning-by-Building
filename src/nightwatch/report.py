from __future__ import annotations

import json

from .engine import risk_by_entity
from .models import Alert


def as_json(alerts: list[Alert]) -> str:
    return json.dumps({
        "alerts": [a.to_dict() for a in alerts],
        "risk_by_entity": risk_by_entity(alerts),
    }, ensure_ascii=False, indent=2)


def as_markdown(alerts: list[Alert]) -> str:
    lines = ["# NightWatch Report", ""]
    risks = risk_by_entity(alerts)
    if risks:
        lines += ["## Risk map", "", "| Entity | Risk |", "|---|---:|"]
        lines += [f"| `{entity}` | {score} |" for entity, score in risks.items()]
        lines.append("")

    lines += ["## Alerts", ""]
    if not alerts:
        lines.append("No alerts.")
        return "\n".join(lines)

    for alert in alerts:
        lines += [
            f"### {alert.rule_id} · {alert.title}",
            "",
            f"- severity: **{alert.severity}**",
            f"- score: **{alert.score}**",
            f"- entity: `{alert.entity}`",
            f"- window: `{alert.first_seen.isoformat()}` → `{alert.last_seen.isoformat()}`",
        ]
        if alert.techniques:
            attack = ", ".join(f"{x['id']} {x['name']}" for x in alert.techniques)
            lines.append(f"- ATT&CK: {attack}")
        lines += [
            f"- evidence: `{JSON.stringify ? "" : ""}`",
            "",
        ]
    return "\n".join(lines)
