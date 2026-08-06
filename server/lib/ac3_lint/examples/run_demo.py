"""
Demo: run the linter against three synthetic reports.

  1. examples/sample_domain_report_broken.json   — mirrors criticalsec.com bugs
  2. examples/sample_pentest_report_broken.json  — mirrors Broken Crystals bugs
  3. examples/sample_domain_report_clean.json    — should pass

Usage:
    python -m examples.run_demo

Or from the package root:
    cd /path/to/ac3_lint
    python examples/run_demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running from package root or from examples/
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ac3_lint import run, Severity  # noqa: E402


SAMPLES = [
    ("examples/sample_domain_report_broken.json",  "Domain Intel — broken (criticalsec.com)"),
    ("examples/sample_pentest_report_broken.json", "Pentest — broken (Broken Crystals)"),
    ("examples/sample_domain_report_clean.json",   "Domain Intel — clean (should pass)"),
]


def main() -> int:
    overall_failed = 0
    for rel_path, label in SAMPLES:
        path = ROOT / rel_path
        report = json.loads(path.read_text())

        print("=" * 78)
        print(f"  {label}")
        print(f"  source: {rel_path}")
        print("=" * 78)

        result = run(report)
        print(result.format_text(color=sys.stdout.isatty()))

        if not result.passed:
            overall_failed += 1
        print()

    print("=" * 78)
    print(f"Demo complete. {overall_failed}/{len(SAMPLES)} sample(s) failed lint "
          f"(broken samples should fail; clean sample should pass).")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
