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
            f"- evidence: `{json.dumps(alert.evidence, ensure_ascii=False)}`",
            "",
        ]
    return "\n".join(lines)


def cases_markdown(cases) -> str:
    lines = ["# NightWatch Cases", ""]
    if not cases:
        return "\n".join(lines + ["No cases."])

    for case in cases:
        lines += [
            f"## {case.case_id} · Risk {case.score}",
            "",
            f"- window: `{case.first_seen.isoformat()}` → `{case.last_seen.isoformat()}`",
            f"- entities: {', '.join(case.entities) or '-'}",
            f"- rules: {', '.join(case.rules)}",
            f"- ATT&CK: {', '.join(case.techniques) or '-'}",
            "",
            "| Time | Rule | Score | Entity |",
            "|---|---|---:|---|",
        ]
        for alert in case.alerts:
            lines.append(
                f"| {alert.first_seen.isoformat()} | {alert.rule_id} | {alert.score} | `{alert.entity}` |"
            )
        lines.append("")
    return "\n".join(lines)