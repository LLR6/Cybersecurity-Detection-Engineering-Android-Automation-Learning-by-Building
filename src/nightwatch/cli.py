from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from .engine import load_events, run
from .report import as_json, as_markdown


def main() -> None:
    parser = argparse.ArgumentParser(prog="nightwatch")
    parser.add_argument("input")
    parser.add_argument("--input-format", choices=["auto", "jsonl", "suricata", "zeek"], default="auto")
    parser.add_argument("--format", choices=["json", "md"], default="md")
    parser.add_argument("--out")
    parser.add_argument("--stats", action="store_true")
    args = parser.parse_args()

    events = load_events(args.input, args.input_format)
    alerts = run(events)

    if args.stats:
        counts = Counter(e.kind for e in events)
        print(f"events={len(events)} alerts={len(alerts)} kinds={dict(counts)}")

    output = as_json(alerts) if args.format == "json" else as_markdown(alerts)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)


if __name__ == "__main__":
    main()
