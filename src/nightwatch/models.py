from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def parse_ts(value: str) -> datetime:
    value = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass(slots=True)
class Event:
    ts: datetime
    kind: str
    src: str = ""
    dst: str = ""
    user: str = ""
    port: int | None = None
    query: str = ""
    status: str = ""
    action: str = ""
    protocol: str = ""
    sensor: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        return cls(
            ts=parse_ts(data["ts"]),
            kind=str(data.get("kind", "unknown")),
            src=str(data.get("src", "")),
            dst=str(data.get("dst", "")),
            user=str(data.get("user", "")),
            port=int(data["port"]) if data.get("port") is not None else None,
            query=str(data.get("query", "")),
            status=str(data.get("status", "")),
            action=str(data.get("action", "")),
            protocol=str(data.get("protocol", "")),
            sensor=str(data.get("sensor", "")),
            raw=data,
        )


@dataclass(slots=True)
class Alert:
    rule_id: str
    title: str
    severity: str
    score: int
    entity: str
    first_seen: datetime
    last_seen: datetime
    evidence: dict[str, Any]
    techniques: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["first_seen"] = self.first_seen.isoformat()
        data["last_seen"] = self.last_seen.isoformat()
        return data
