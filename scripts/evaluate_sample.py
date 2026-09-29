import argparse
import json
from pathlib import Path

from nightwatch.engine import load_events, run
from nightwatch.evaluation import as_markdown, evaluate, load_truth


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate NightWatch alerts against labeled expected rule/entity pairs")
    parser.add_argument("input")
    parser.add_argument("truth")
    parser.add_argument("--input-format", choices=["auto", "jsonl", "suricata", "zeek"], default="auto")
    parser.add_argument("--format", choices=["json", "md"], default="md")
    parser.add_argument("--out")
    parser.add_argument("--fail-on-regression", action="store_true")
    args = parser.parse_args()
    try:
        report = evaluate(run(load_events(args.input, args.input_format)), load_truth(args.truth))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    output = json.dumps(report, ensure_ascii=False, indent=2) + "\n" if args.format == "json" else as_markdown(report)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output, end="" if output.endswith("\n") else "\n")
    return 2 if args.fail_on_regression and (report["counts"]["fp"] or report["counts"]["fn"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
