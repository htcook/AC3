"""
CLI: python -m ac3_lint <report.json> [--json] [--fail-on warning]

Returns exit code 0 if the report passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .issues import Severity
from .runner import run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ac3_lint",
        description="Lint an AC3 report dict for quality issues.",
    )
    parser.add_argument("path", type=Path, help="Path to the report JSON file.")
    parser.add_argument(
        "--json", action="store_true",
        help="Emit JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--fail-on", choices=["error", "warning", "info"], default="error",
        help="Severity threshold that causes non-zero exit (default: error).",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI color in text output.",
    )
    args = parser.parse_args(argv)

    try:
        report = json.loads(args.path.read_text())
    except FileNotFoundError:
        print(f"error: file not found: {args.path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"error: invalid JSON: {e}", file=sys.stderr)
        return 2

    fail_on = {"error": Severity.ERROR,
               "warning": Severity.WARNING,
               "info": Severity.INFO}[args.fail_on]
    result = run(report, fail_on=fail_on)

    if args.json:
        print(result.to_json())
    else:
        print(result.format_text(color=not args.no_color))

    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
