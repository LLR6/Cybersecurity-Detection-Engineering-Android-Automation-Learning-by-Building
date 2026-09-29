import json

import pytest

from nightwatch.engine import load_events, load_jsonl


def test_jsonl_reports_failing_line_number(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"ts":"2026-09-29T00:00:00Z","kind":"dns","src":"h","query":"a.example"}\n{broken}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="line 2"):
        load_jsonl(path)


def test_auto_format_for_unknown_json_filename_defaults_to_jsonl(tmp_path):
    path = tmp_path / "events.data"
    path.write_text(json.dumps({"ts":"2026-09-29T00:00:00Z","kind":"dns","src":"h","query":"a.example"}) + "\n", encoding="utf-8")
    events = load_events(path, "auto")
    assert len(events) == 1


def test_empty_jsonl_is_valid_empty_input(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("\n\n", encoding="utf-8")
    assert load_jsonl(path) == []
