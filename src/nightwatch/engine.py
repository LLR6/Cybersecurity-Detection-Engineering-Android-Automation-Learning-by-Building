from __future__ import annotations

import json
from pathlib import Path

from .adapters import load_suricata, load_zeek
from .detectors import DETECTORS
from .metadata import enrich
from .models import Alert, Event


def load_jsonl(path: str | Path) -> list[Event]:
    events: list[Event] = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(Event.from_dict(json.loads(line)))
            except Exception as exc:
                raise ValueError(f"invalid event at line {line_no}: {exc}") from exc
    return events


def load_events(path: str | Path, fmt: str = "auto") -> list[Event]:
    path = Path(path)
    if fmt == "auto":
        name = path.name.lower()
        fmt = "zeek" if path.suffix == ".log" else "suricata" if "eve" in name else "jsonl"
    if fmt == "suricata":
        return load_suricata(path)
    if fmt == "zeek":
        return load_zeek(path)
    if fmt == "jsonl":
        return load_jsonl(path)
    raise ValueError(f"unknown input format: {fmt}")


def run(events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    for detector in DETECTORS:
        alerts.extend(detector(events))
    enrich(alerts)
    return sorted(alerts, key=lambda a: (-a.score, a.first_seen))


def risk_by_entity(alerts: list[Alert]) -> dict[str, int]:
    buckets: dict[str, list[int]] = {}
    for alert in alerts:
        buckets.setdefault(alert.entity, []).append(alert.score)

    result: dict[str, int] = {}
    for entity, scores in buckets.items():
        survival = 1.0
        for score in scores:
            survival *= 1 - score / 100
        result[entity] = round((1 - survival) * 100)
    return dict(sorted(result.items(), key=lambda kv: -kv[1]))
