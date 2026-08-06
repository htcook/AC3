"""
LintIssue — the canonical result type for every check.

Every check returns a list of LintIssue objects. The runner aggregates them
and the CLI formats them. Severity controls whether the gate passes:

  ERROR    — must be fixed before report ships
  WARNING  — should be reviewed; report can ship with sign-off
  INFO     — advisory; useful but non-blocking
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class LintIssue:
    check_id: str          # stable identifier, e.g. "AC3LINT-COUNT-001"
    check_name: str        # human-readable name
    severity: Severity
    message: str           # one-line description of the problem
    location: str = ""     # where in the report (section, table, field)
    detail: str = ""       # multi-line detail, optional
    suggestion: str = ""   # how to fix it
    evidence: dict[str, Any] = field(default_factory=dict)  # raw values that triggered the check

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
