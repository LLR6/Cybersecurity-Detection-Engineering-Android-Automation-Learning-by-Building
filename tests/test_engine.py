from datetime import datetime, timedelta, timezone

from nightwatch.engine import risk_by_entity, run
from nightwatch.models import Event


T0 = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)


def ev(seconds: int, kind: str, **kwargs) -> Event:
    return Event(ts=T0 + timedelta(seconds=seconds), kind=kind, **kwargs)


def test_auth_fail_then_success():
    events = [ev(i * 10, "auth", src="10.0.0.8", user="root", status="fail") for i in range(5)]
    events.append(ev(48, "auth", src="10.0.0.8", user="root", status="success"))
    alerts = run(events)
    assert alerts[0].rule_id == "AUTH-SEQ-001"
    assert alerts[0].score == 95


def test_port_scan():
    events = [ev(i * 2, "net", src="10.0.0.9", dst="10.0.0.20", port=20 + i) for i in range(12)]
    alerts = run(events)
    assert any(a.rule_id == "NET-SCAN-001" for a in alerts)


def test_beacon():
    events = [ev(i * 30, "net", src="10.0.0.3", dst="8.8.8.8", port=443) for i in range(8)]
    alerts = run(events)
    beacon = next(a for a in alerts if a.rule_id == "NET-BEACON-001")
    assert beacon.evidence["interval_cv"] == 0.0


def test_dns_entropy():
    q = "aZ8fK2mQ9xP7cV4nR6tY1uI3oL5sD0hJ.evil.example"
    alerts = run([ev(1, "dns", src="10.0.0.6", query=q)])
    assert any(a.rule_id == "DNS-TUNNEL-001" for a in alerts)


def test_risk_aggregation():
    events = [ev(i * 30, "net", src="10.0.0.3", dst="8.8.8.8", port=443) for i in range(8)]
    alerts = run(events)
    risk = risk_by_entity(alerts)
    assert next(iter(risk.values())) >= 80
