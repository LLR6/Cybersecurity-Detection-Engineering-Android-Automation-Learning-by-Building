import json
from datetime import datetime, timezone

from nightwatch.models import Alert
from nightwatch.suppression import apply_suppressions, load_suppressions


T0 = datetime(2026, 9, 29, tzinfo=timezone.utc)


def make_alert(rule_id: str, entity: str) -> Alert:
    return Alert(
        rule_id=rule_id,
        title=rule_id,
        severity="medium",
        score=60,
        entity=entity,
        first_seen=T0,
        last_seen=T0,
        evidence={},
    )


def test_glob_suppression_keeps_audit_reason():
    alerts = [
        make_alert("NET-BEACON-001", "10.0.0.8->203.0.113.5:443"),
        make_alert("DNS-TUNNEL-001", "10.0.0.9"),
    ]
    kept, suppressed = apply_suppressions(
        alerts,
        [{"rule_id": "NET-BEACON-*", "entity": "10.0.0.8->*", "reason": "known updater"}],
    )
    assert [x.rule_id for x in kept] == ["DNS-TUNNEL-001"]
    assert suppressed[0]["reason"] == "known updater"
    assert suppressed[0]["matched_rule_id"] == "NET-BEACON-*"


def test_load_wrapped_suppression_file(tmp_path):
    path = tmp_path / "suppressions.json"
    path.write_text(
        json.dumps({"suppressions": [{"rule_id": "NET-*", "entity": "*", "reason": "lab"}]}),
        encoding="utf-8",
    )
    assert load_suppressions(path)[0]["reason"] == "lab"
