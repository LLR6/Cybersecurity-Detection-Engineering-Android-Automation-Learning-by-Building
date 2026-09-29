from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from importlib.metadata import PackageNotFoundError, version

def package_version():
    try:
        return version("lr-nightwatch")
    except PackageNotFoundError:
        return "dev"


from .cases import build_cases
from .engine import load_events, run
from .report import as_json, as_markdown, cases_markdown
from .suppression import apply_suppressions, load_suppressions


def main() -> None:
    parser = argparse.ArgumentParser(prog="nightwatch")
    parser.add_argument("--version", action="version", version=f"%(prog)s {package_version()}")
    parser.add_argument("input")
    parser.add_argument("--input-format", choices=["auto", "jsonl", "suricata", "zeek"], default="auto")
    parser.add_argument("--format", choices=["json", "md"], default="md")
    parser.add_argument("--out")
    parser.add_argument("--stats", action="store_true")
    parser.add_argument("--case-report", help="write correlated cases as Markdown")
    parser.add_argument("--case-gap", type=int, default=30, help="maximum alert gap in minutes when building cases")
    parser.add_argument("--suppressions", help="JSON file containing rule/entity glob suppressions")
    parser.add_argument("--suppressed-out", help="optional JSON audit file for suppressed alerts")
    args = parser.parse_args()

    if args.case_gap < 0:
        parser.error("--case-gap must be >= 0")

    try:
        events = load_events(args.input, args.input_format)
        alerts = run(events)
        suppressed = []
        if args.suppressions:
            rules = load_suppressions(args.suppressions)
            alerts, suppressed = apply_suppressions(alerts, rules)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    if args.stats:
        counts = Counter(e.kind for e in events)
        print(
            f"events={len(events)} alerts={len(alerts)} suppressed={len(suppressed)} "
            f"kinds={dict(counts)}"
        )

    output = as_json(alerts) if args.format == "json" else as_markdown(alerts)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)

    if args.case_report:
        cases = build_cases(alerts, gap_minutes=args.case_gap)
        Path(args.case_report).write_text(cases_markdown(cases), encoding="utf-8")

    if args.suppressed_out:
        Path(args.suppressed_out).write_text(
            json.dumps(
                {
                    "schema": "nightwatch/suppressed/v1",
                    "count": len(suppressed),
                    "suppressed": suppressed,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
