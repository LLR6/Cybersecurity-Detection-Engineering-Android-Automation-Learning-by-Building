from __future__ import annotations

import math
import statistics
from collections import defaultdict, deque
from typing import Iterable

from .models import Alert, Event


SEVERITY_SCORE = {"low": 25, "medium": 50, "high": 75, "critical": 95}


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def auth_chain(events: Iterable[Event]) -> list[Alert]:
    groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        if event.kind == "auth":
            groups[(event.src, event.user)].append(event)

    alerts: list[Alert] = []
    for (src, user), items in groups.items():
        items.sort(key=lambda e: e.ts)
        fails: deque[Event] = deque()
        for event in items:
            while fails and (event.ts - fails[0].ts).total_seconds() > 120:
                fails.popleft()
            if event.status.lower() in {"fail", "failed", "denied"}:
                fails.append(event)
                continue
            if event.status.lower() in {"ok", "success", "accepted"} and len(fails) >= 5:
                delta = (event.ts - fails[-1].ts).total_seconds()
                if delta <= 60:
                    alerts.append(Alert(
                        rule_id="AUTH-SEQ-001",
                        title="Burst failures followed by successful login",
                        severity="critical",
                        score=95,
                        entity=f"{src}:{user}",
                        first_seen=fails[0].ts,
                        last_seen=event.ts,
                        evidence={"failures": len(fails), "success_after_seconds": delta},
                    ))
                    fails.clear()
    return alerts


def port_scan(events: Iterable[Event]) -> list[Alert]:
    groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        if event.kind == "net" and event.port is not None:
            groups[(event.src, event.dst)].append(event)

    alerts: list[Alert] = []
    for (src, dst), items in groups.items():
        items.sort(key=lambda e: e.ts)
        window: deque[Event] = deque()
        for event in items:
            window.append(event)
            while window and (event.ts - window[0].ts).total_seconds() > 60:
                window.popleft()
            ports = {e.port for e in window}
            if len(ports) >= 12:
                alerts.append(Alert(
                    rule_id="NET-SCAN-001",
                    title="High fan-out destination port scan",
                    severity="high",
                    score=78,
                    entity=f"{src}->{dst}",
                    first_seen=window[0].ts,
                    last_seen=event.ts,
                    evidence={"distinct_ports": len(ports), "window_seconds": 60},
                ))
                break
    return alerts


def beaconing(events: Iterable[Event]) -> list[Alert]:
    groups: dict[tuple[str, str, int | None], list[Event]] = defaultdict(list)
    for event in events:
        if event.kind == "net":
            groups[(event.src, event.dst, event.port)].append(event)

    alerts: list[Alert] = []
    for (src, dst, port), items in groups.items():
        if len(items) < 6:
            continue
        items.sort(key=lambda e: e.ts)
        gaps = [(b.ts - a.ts).total_seconds() for a, b in zip(items, items[1:])]
        mean = statistics.fmean(gaps)
        if mean < 5 or len(gaps) < 5:
            continue
        cv = statistics.pstdev(gaps) / mean if mean else 1.0
        if cv <= 0.12:
            alerts.append(Alert(
                rule_id="NET-BEACON-001",
                title="Low-jitter periodic outbound connection",
                severity="high" if cv <= 0.05 else "medium",
                score=82 if cv <= 0.05 else 62,
                entity=f"{src}->{dst}:{port}",
                first_seen=items[0].ts,
                last_seen=items[-1].ts,
                evidence={"interval_mean": round(mean, 2), "interval_cv": round(cv, 4), "samples": len(items)},
            ))
    return alerts


def dns_tunnel(events: Iterable[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        if event.kind != "dns" or not event.query:
            continue
        labels = event.query.rstrip(".").split(".")
        longest = max(labels, key=len)
        ent = _entropy(longest)
        if (len(longest) >= 32 and ent >= 4.0) or len(event.query) >= 110:
            alerts.append(Alert(
                rule_id="DNS-TUNNEL-001",
                title="Long high-entropy DNS label",
                severity="medium",
                score=58,
                entity=event.src or event.query,
                first_seen=event.ts,
                last_seen=event.ts,
                evidence={"query": event.query, "label_len": len(longest), "entropy": round(ent, 3)},
            ))
    return alerts


DETECTORS = [auth_chain, port_scan, beaconing, dns_tunnel]
