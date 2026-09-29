from datetime import datetime, timezone

from nightwatch.evaluation import evaluate
from nightwatch.models import Alert

T0 = datetime(2026, 9, 29, tzinfo=timezone.utc)


def alert(rule_id, entity):
    return Alert(rule_id=rule_id, title=rule_id, severity="medium", score=50, entity=entity,
                 first_seen=T0, last_seen=T0, evidence={})


def test_evaluation_counts_exact_rule_entity_pairs():
    truth = {"schema": "nightwatch-eval/v1", "expected": [
        {"rule_id": "A", "entity": "host-1"},
        {"rule_id": "B", "entity": "host-2"},
    ]}
    report = evaluate([alert("A", "host-1"), alert("C", "host-3")], truth)
    assert report["counts"] == {"tp": 1, "fp": 1, "fn": 1}
    assert report["precision"] == 0.5
    assert report["recall"] == 0.5
    assert report["f1"] == 0.5


def test_perfect_evaluation_is_one():
    truth = {"schema": "nightwatch-eval/v1", "expected": [{"rule_id": "A", "entity": "host-1"}]}
    report = evaluate([alert("A", "host-1")], truth)
    assert report["counts"] == {"tp": 1, "fp": 0, "fn": 0}
    assert report["f1"] == 1.0
