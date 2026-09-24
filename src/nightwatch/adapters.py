from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import Event, parse_ts


def load_suricata(path: str | Path) -> list[Event]:
    events: list[Event] = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                event_type = data.get("event_type", "")
                base = {
                    "ts": parse_ts(data["timestamp"]),
                    "src": str(data.get("src_ip", "")),
                    "dst": str(data.get("dest_ip", "")),
                    "port": int(data["dest_port"]) if data.get("dest_port") is not None else None,
                    "protocol": str(data.get("proto", "")),
                    "sensor": "suricata",
                    "raw": data,
                }
                if event_type == "dns":
                    dns = data.get("dns") or {}
                    query = dns.get("rrname") or dns.get("query", {}).get("rrname", "")
                    events.append(Event(kind="dns", query=str(query), **base))
                elif event_type in {"flow", "http", "tls", "alert"}:
                    events.append(Event(kind="net", **base))
            except Exception as exc:
                raise ValueError(f"invalid Suricata event at line {line_no}: {exc}") from exc
    return events


def load_zeek(path: str | Path) -> list[Event]:
    fields: list[str] = []
    events: list[Event] = []

    with Path(path).open("r", encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, 1):
            line = raw.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if not fields:
                raise ValueError("Zeek log is missing #fields header")

            parts = line.split("\t")
            if len(parts) != len(fields):
                raise ValueError(f"invalid Zeek row at line {line_no}")
            row = dict(zip(fields, parts))
            ts = datetime.fromtimestamp(float(row["ts"]), tz=timezone.utc)

            src = row.get("id.orig_h", "")
            dst = row.get("id.resp_h", "")
            port = row.get("id.resp_p")
            port_num = int(port) if port and port != "-" else None

            if "query" in row:
                events.append(Event(
                    ts=ts,
                    kind="dns",
                    src=src,
                    dst=dst,
                    port=port_num,
                    query="" if row.get("query") == "-" else row.get("query", ""),
                    protocol=row.get("proto", ""),
                    sensor="zeek",
                    raw=row,
                ))
            else:
                events.append(Event(
                    ts=ts,
                    kind="net",
                    src=src,
                    dst=dst,
                    port=port_num,
                    protocol=row.get("proto", ""),
                    sensor="zeek",
                    raw=row,
                ))
    return events
