from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import timedelta

from .models import Alert


IP_TOKEN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")


def _ips(value: str) -> set[str]:
    out = set()
    for token in IP_TOKEN.findall(value):
        try:
            out.add(str(ipaddress.ip_address(token)))
        except ValueError:
            pass
    return out


def _fuse(scores: list[int]) -> int:
    survival = 1.0
    for score in scores:
        survival *= 1 - score / 100
    return round((1 - survival) * 100)


@dataclass(slots=True)
class Case:
    case_id: str
    score: int
    first_seen: object
    last_seen: object
    entities: list[str]
    rules: list[str]
    techniques: list[str]
    alerts: list[Alert]


def build_cases(alerts: list[Alert], gap_minutes: int = 30) -> list[Case]:
    if not alerts:
        return []

    parent = list(range(len(alerts)))
    tokens = [_ips(a.entity) for a in alerts]
    gap = timedelta(minutes=gap_minutes)

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i in range(len(alerts)):
        for j in range(i + 1, len(alerts)):
            if not tokens[i] or not (tokens[i] & tokens[j]):
                continue
            a, b = alerts[i], alerts[j]
            if a.first_seen <= b.last_seen + gap and b.first_seen <= a.last_seen + gap:
                union(i, j)

    groups = {}
    for i, alert in enumerate(alerts):
        groups.setdefault(find(i), []).append(alert)

    cases = []
    ordered = sorted(groups.values(), key=lambda g: min(a.first_seen for a in g))
    for idx, group in enumerate(ordered, 1):
        entities = sorted(set().union(*(_ips(a.entity) for a in group)))
        techniques = sorted({
            f"{t['id']} {t['name']}"
            for a in group
            for t in a.techniques
        })
        cases.append(Case(
            case_id=f"CASE-{idx:03d}",
            score=_fuse([a.score for a in group]),
            first_seen=min(a.first_seen for a in group),
            last_seen=max(a.last_seen for a in group),
            entities=entities,
            rules=sorted({a.rule_id for a in group}),
            techniques=techniques,
            alerts=sorted(group, key=lambda a: a.first_seen),
        ))
    return sorted(cases, key=lambda c: (-c.score, c.first_seen))
