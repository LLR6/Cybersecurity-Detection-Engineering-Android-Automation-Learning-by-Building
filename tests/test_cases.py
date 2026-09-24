from datetime import datetime, timedelta, timezone

from nightwatch.cases import build_cases
from nightwatch.models import Alert


T0 = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)


def alert(rule, score, entity, minute, technique=None):
    return Alert(
        rule_id=rule,
        title=rule,
        severity="high",
        score=score,
        entity=entity,
        first_seen=T0 + timedelta(minutes=minute),
        last_seen=T0 + timedelta(minutes=minute, seconds=30),
        evidence={},
        techniques=technique or [],
    )


def test_related_alerts_become_one_case():
    alerts = [
        alert("NET-SCAN-001", 78, "198.51.100.8->10.0.0.20", 0),
        alert(
            "CHAIN-001",
            92,
            "198.51.100.8->10.0.0.20",
            5,
            [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
        ),
    ]
    cases = build_cases(alerts)
    assert len(cases) == 1
    assert cases[0].score > 95
    assert cases[0].rules == ["CHAIN-001", "NET-SCAN-001"]


def test_unrelated_alerts_stay_separate():
    alerts = [
        alert("NET-SCAN-001", 78, "198.51.100.8->10.0.0.20", 0),
        alert("DNS-TUNNEL-001", 58, "10.0.0.99", 1),
    ]
    assert len(build_cases(alerts)) == 2


def test_time_gap_breaks_case():
    alerts = [
        alert("NET-SCAN-001", 78, "198.51.100.8->10.0.0.20", 0),
        alert("AUTH-SEQ-001", 95, "198.51.100.8:root", 90),
    ]
    assert len(build_cases(alerts, gap_minutes=30)) == 2
