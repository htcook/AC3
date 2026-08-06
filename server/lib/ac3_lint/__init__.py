"""
ac3_lint — report-quality linter for the AC3 reporting pipeline.

Usage:

    from ac3_lint import run, Severity

    report = {...}  # your generator's intermediate dict
    result = run(report)

    print(result.format_text())
    if not result.passed:
        sys.exit(1)
"""

from .issues import LintIssue, Severity
from .runner import LintResult, run

__all__ = ["LintIssue", "Severity", "LintResult", "run"]
__version__ = "0.1.0"
