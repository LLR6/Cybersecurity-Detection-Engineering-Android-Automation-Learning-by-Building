from pathlib import Path

from nightwatch.adapters import load_suricata, load_zeek


def test_suricata_adapter(tmp_path: Path):
    p = tmp_path / "eve.json"
    p.write_text(
        '{"timestamp":"2026-09-24T12:00:00+00:00","event_type":"dns","src_ip":"10.0.0.3","dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","dns":{"rrname":"example.org"}}\n'
        '{"timestamp":"2026-09-24T12:00:01+00:00","event_type":"flow","src_ip":"10.0.0.3","dest_ip":"1.1.1.1","dest_port":443,"proto":"TCP"}\n',
        encoding="utf-8",
    )
    events = load_suricata(p)
    assert [e.kind for e in events] == ["dns", "net"]
    assert events[0].query == "example.org"
    assert events[1].sensor == "suricata"


def test_zeek_adapter(tmp_path: Path):
    p = tmp_path / "conn.log"
    p.write_text(
        "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\n"
        "1790251200.0\t10.0.0.2\t10.0.0.8\t443\ttcp\n",
        encoding="utf-8",
    )
    events = load_zeek(p)
    assert len(events) == 1
    assert events[0].kind == "net"
    assert events[0].port == 443
    assert events[0].sensor == "zeek"
