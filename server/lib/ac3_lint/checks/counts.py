"""
Count reconciliation checks.

Catches contradictions where the same quantity is reported with different
numbers in different places — the most common LLM-narrative bug.
"""

from __future__ import annotations

import re
from typing import List

from ..issues import LintIssue, Severity
from ..models import get, iter_text_blocks


def check_asset_count_consistency(report: dict) -> List[LintIssue]:
    """counts.total_assets must match len(assets) + len(vendor_assets)."""
    issues: List[LintIssue] = []
    declared = get(report, "counts", "total_assets")
    if declared is None:
        return issues

    customer_assets = report.get("assets") or []
    vendor_assets = report.get("vendor_assets") or []
    actual = len(customer_assets) + len(vendor_assets)

    if int(declared) != actual:
        issues.append(LintIssue(
            check_id="AC3LINT-COUNT-001",
            check_name="asset_count_consistency",
            severity=Severity.ERROR,
            message=f"Declared asset count ({declared}) does not match actual rows ({actual}).",
            location="counts.total_assets vs assets[] + vendor_assets[]",
            suggestion="Compute total_assets once at build time as len(assets) + len(vendor_assets) "
                       "and inject into the cover/exec-summary template.",
            evidence={"declared": declared, "customer_assets": len(customer_assets),
                      "vendor_assets": len(vendor_assets), "computed": actual},
        ))
    return issues


def check_findings_count_consistency(report: dict) -> List[LintIssue]:
    """counts.confirmed_findings vs counts.potential_findings vs len(findings)."""
    issues: List[LintIssue] = []
    declared_confirmed = get(report, "counts", "confirmed_findings")
    declared_potential = get(report, "counts", "potential_findings", default=0) or 0
    findings = report.get("findings") or []

    if declared_confirmed is None:
        return issues

    # If findings[] is empty, the report is only carrying summary counts (e.g. an
    # exec-summary-only export). Don't flag — there's nothing to reconcile against.
    if not findings:
        return issues

    confirmed = sum(1 for f in findings
                    if isinstance(f, dict)
                    and str(f.get("status", "confirmed")).lower() == "confirmed")
    potential = sum(1 for f in findings
                    if isinstance(f, dict)
                    and str(f.get("status", "")).lower() in ("potential", "inferred"))

    if int(declared_confirmed) != confirmed:
        issues.append(LintIssue(
            check_id="AC3LINT-COUNT-002",
            check_name="confirmed_findings_count",
            severity=Severity.ERROR,
            message=f"Declared confirmed findings ({declared_confirmed}) does not "
                    f"match findings[] entries with status=confirmed ({confirmed}).",
            location="counts.confirmed_findings vs findings[]",
            suggestion="Single source of truth: count from findings[] at render time.",
            evidence={"declared": declared_confirmed, "computed": confirmed},
        ))

    if int(declared_potential) != potential:
        issues.append(LintIssue(
            check_id="AC3LINT-COUNT-003",
            check_name="potential_findings_count",
            severity=Severity.WARNING,
            message=f"Declared potential findings ({declared_potential}) does not "
                    f"match findings[] entries with status=potential ({potential}).",
            location="counts.potential_findings vs findings[]",
            evidence={"declared": declared_potential, "computed": potential},
        ))
    return issues


_NUMBER_NEAR_NOUN = re.compile(
    # number, optional adjective(s), then the noun
    r"\b(\d{1,4})\s+(?:[a-z]+\s+){0,3}?"
    r"(asset|assets|finding|findings|confirmed|potential|"
    r"sources?|breach(?:es)?|exposures?|listings?|kev|cve)\b",
    re.IGNORECASE,
)


def check_narrative_count_drift(report: dict) -> List[LintIssue]:
    """
    Scan rendered prose for numeric assertions that disagree with canonical
    counts. Catches the 'Confirmed Findings: 17' on the cover vs '25 findings'
    in the exec summary class of bug.
    """
    issues: List[LintIssue] = []
    canonical = {
        "asset": get(report, "counts", "total_assets"),
        "assets": get(report, "counts", "total_assets"),
        "finding": get(report, "counts", "confirmed_findings"),
        "findings": get(report, "counts", "confirmed_findings"),
        "confirmed": get(report, "counts", "confirmed_findings"),
        "potential": get(report, "counts", "potential_findings"),
        "sources": get(report, "counts", "data_sources"),
        "source": get(report, "counts", "data_sources"),
        "kev": get(report, "counts", "kev_matches"),
        "exposures": get(report, "counts", "breach_exposures"),
    }
    canonical = {k: int(v) for k, v in canonical.items() if v is not None}

    for location, text in iter_text_blocks(report):
        for m in _NUMBER_NEAR_NOUN.finditer(text):
            num = int(m.group(1))
            noun = m.group(2).lower()
            if noun in canonical and num != canonical[noun]:
                # Skip obvious counts inside lists (e.g. "1 of 5 findings")
                # by only flagging when the number doesn't appear to be a fraction
                snippet = text[max(0, m.start() - 30):min(len(text), m.end() + 30)]
                if re.search(r"\b" + str(num) + r"\s*(of|/)\s*\d+\b", snippet, re.IGNORECASE):
                    continue
                issues.append(LintIssue(
                    check_id="AC3LINT-COUNT-004",
                    check_name="narrative_count_drift",
                    severity=Severity.ERROR,
                    message=f"Narrative claims '{num} {noun}' but canonical count is "
                            f"{canonical[noun]}.",
                    location=location,
                    detail=f"Snippet: ...{snippet.strip()}...",
                    suggestion="Inject canonical counts as template variables; never let the "
                               "LLM emit numbers from its own context.",
                    evidence={"narrative_value": num, "canonical_value": canonical[noun],
                              "noun": noun},
                ))
    return issues
