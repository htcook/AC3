"""
Runner — executes all registered checks against a report dict and aggregates
issues. Provides:

  - run(report) -> LintResult
  - LintResult.passed (bool, gates the pipeline)
  - LintResult.issues (full list)
  - LintResult.format_text() / .to_dict() / .to_json()
"""

from __future__ import annotations

import json
import traceback
from dataclasses import dataclass, field
from typing import Iterable

from .checks import ALL_CHECKS, CheckFn
from .issues import LintIssue, Severity


@dataclass
class LintResult:
    issues: list[LintIssue] = field(default_factory=list)
    checks_run: int = 0
    checks_errored: int = 0
    fail_on: Severity = Severity.ERROR

    @property
    def passed(self) -> bool:
        """True if no issue at or above fail_on severity."""
        order = [Severity.INFO, Severity.WARNING, Severity.ERROR]
        threshold = order.index(self.fail_on)
        return not any(order.index(i.severity) >= threshold for i in self.issues)

    def by_severity(self, sev: Severity) -> list[LintIssue]:
        return [i for i in self.issues if i.severity == sev]

    @property
    def errors(self) -> list[LintIssue]:
        return self.by_severity(Severity.ERROR)

    @property
    def warnings(self) -> list[LintIssue]:
        return self.by_severity(Severity.WARNING)

    @property
    def infos(self) -> list[LintIssue]:
        return self.by_severity(Severity.INFO)

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "checks_run": self.checks_run,
            "checks_errored": self.checks_errored,
            "summary": {
                "errors": len(self.errors),
                "warnings": len(self.warnings),
                "infos": len(self.infos),
            },
            "issues": [i.to_dict() for i in self.issues],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def format_text(self, *, color: bool = True) -> str:
        """Human-readable summary suitable for CI logs."""
        lines: list[str] = []
        red = "\033[31m" if color else ""
        yellow = "\033[33m" if color else ""
        cyan = "\033[36m" if color else ""
        bold = "\033[1m" if color else ""
        reset = "\033[0m" if color else ""

        status = (f"{red}{bold}FAIL{reset}" if not self.passed
                  else f"\033[32m{bold}PASS{reset}" if color else "PASS")
        lines.append(f"AC3 Lint Result: {status}")
        lines.append(f"  Checks run:     {self.checks_run}")
        lines.append(f"  Checks errored: {self.checks_errored}")
        lines.append(f"  Errors:   {len(self.errors)}")
        lines.append(f"  Warnings: {len(self.warnings)}")
        lines.append(f"  Infos:    {len(self.infos)}")
        lines.append("")

        for sev, color_code, label in [
            (Severity.ERROR, red, "ERRORS"),
            (Severity.WARNING, yellow, "WARNINGS"),
            (Severity.INFO, cyan, "INFOS"),
        ]:
            entries = self.by_severity(sev)
            if not entries:
                continue
            lines.append(f"{color_code}{bold}── {label} ({len(entries)}) ──{reset}")
            for issue in entries:
                lines.append(f"  {color_code}[{issue.check_id}]{reset} {issue.check_name}")
                lines.append(f"    {bold}{issue.message}{reset}")
                if issue.location:
                    lines.append(f"    at: {issue.location}")
                if issue.detail:
                    for dl in issue.detail.splitlines():
                        lines.append(f"      {dl}")
                if issue.suggestion:
                    lines.append(f"    fix: {issue.suggestion}")
                lines.append("")
        return "\n".join(lines)


def run(report: dict, *, checks: Iterable[CheckFn] | None = None,
        fail_on: Severity = Severity.ERROR) -> LintResult:
    """
    Run all registered checks (or a custom subset) against `report`.
    Each check is run in isolation; a check that raises is recorded as a
    'checks_errored' bump but doesn't abort the run.
    """
    checks_to_run = list(checks) if checks is not None else ALL_CHECKS
    result = LintResult(fail_on=fail_on)

    for check in checks_to_run:
        result.checks_run += 1
        try:
            issues = check(report) or []
            for issue in issues:
                if isinstance(issue, LintIssue):
                    result.issues.append(issue)
        except Exception as e:  # noqa: BLE001
            result.checks_errored += 1
            result.issues.append(LintIssue(
                check_id="AC3LINT-INTERNAL",
                check_name=getattr(check, "__name__", str(check)),
                severity=Severity.WARNING,
                message=f"Check raised an exception: {type(e).__name__}: {e}",
                location=getattr(check, "__module__", ""),
                detail=traceback.format_exc(limit=3),
            ))
    # Stable sort: ERROR > WARNING > INFO, then by check_id
    sev_rank = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.INFO: 2}
    result.issues.sort(key=lambda i: (sev_rank[i.severity], i.check_id))
    return result
