from __future__ import annotations

import argparse
from pathlib import Path

from .engine import load_jsonl, run
from .report import as_json, as_markdown


def main() -> None:
    parser = argparse.ArgumentParser(prog="nightwatch")
    parser.add_argument("input")
    parser.add_argument("--format", choices=["json", "md"], default="md")
    parser.add_argument("--out")
    args = parser.parse_args()

    alerts = run(load_jsonl(args.input))
    output = as_json(alerts) if args.format == "json" else as_markdown(alerts)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)


if __name__ == "__main__":
    main()
