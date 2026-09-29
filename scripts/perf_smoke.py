import argparse
import json
import time
from pathlib import Path

from nightwatch.engine import load_events, run


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a non-gating NightWatch performance smoke report")
    parser.add_argument("input")
    parser.add_argument("--input-format", choices=["auto", "jsonl", "suricata", "zeek"], default="auto")
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be >= 1")

    load_start = time.perf_counter()
    events = load_events(args.input, args.input_format)
    load_seconds = time.perf_counter() - load_start

    durations = []
    alert_count = 0
    for _ in range(args.repeats):
        start = time.perf_counter()
        alerts = run(events)
        durations.append(time.perf_counter() - start)
        alert_count = len(alerts)

    mean = sum(durations) / len(durations)
    report = {
        "schema": "nightwatch-performance-smoke/v1",
        "input": str(args.input),
        "events": len(events),
        "alerts": alert_count,
        "repeats": args.repeats,
        "load_seconds": round(load_seconds, 6),
        "run_seconds": {
            "mean": round(mean, 6),
            "min": round(min(durations), 6),
            "max": round(max(durations), 6),
        },
        "events_per_second_mean": round(len(events) / mean, 2) if mean else None,
        "note": "Non-gating smoke measurement. Compare trends only on similar runners and fixtures.",
    }
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
