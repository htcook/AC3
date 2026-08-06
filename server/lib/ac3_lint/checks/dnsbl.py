"""
DNSBL response false-positive detection.

Catches the criticalsec.com bug where multi.uribl.com returned a 'Query Refused'
TXT record and the report flagged it as a real blacklist hit.
"""

from __future__ import annotations

import re
from typing import List

from ..issues import LintIssue, Severity


# Tokens in a TXT record that indicate the response is a query-state error,
# NOT a real listing.
_REFUSED_TOKENS = re.compile(
    r"\b(query\s+refused|refused\.shtml|rate[\s-]?limit|too\s+many\s+queries|"
    r"please\s+register|access\s+denied|not\s+authorized|"
    r"contact[\w\s]+for\s+access|public\s+resolvers\s+(?:not|are\s+not)\s+permitted|"
    r"see\s+https?://[\w./-]*?(?:refused|denied|abuse))\b",
    re.IGNORECASE,
)

# Return codes that are widely-published as 'lookup error' rather than 'listed'
_ERROR_RETURN_CODES = {
    "127.255.255.255",  # Spamhaus Datafeed query refused
    "127.255.255.254",  # public resolver / typo
}


def check_dnsbl_refused_responses(report: dict) -> List[LintIssue]:
    issues: List[LintIssue] = []
    for entry in report.get("dnsbl", []) or []:
        if not isinstance(entry, dict):
            continue
        zone = entry.get("zone", "?")
        txt = str(entry.get("txt_record") or "")
        rcode = str(entry.get("return_code") or "")
        action = entry.get("action_required") or entry.get("action")

        is_refused = bool(_REFUSED_TOKENS.search(txt)) or rcode in _ERROR_RETURN_CODES

        if is_refused and action:
            issues.append(LintIssue(
                check_id="AC3LINT-DNSBL-001",
                check_name="dnsbl_refused_treated_as_listing",
                severity=Severity.ERROR,
                message=f"DNSBL '{zone}' returned a query-error response but is flagged "
                        f"as actionable.",
                location=f"dnsbl[].zone='{zone}'",
                detail=f"TXT: {txt[:200]}",
                suggestion="Add a refused-token check before classifying a DNSBL result "
                           "as a real listing. Recommended tokens: 'refused', 'rate "
                           "limit', 'please register', URLs containing 'refused' or "
                           "'denied'. Treat these as 'lookup error', not 'listed'.",
                evidence={"zone": zone, "return_code": rcode,
                          "txt_excerpt": txt[:200]},
            ))
    return issues


def check_dnsbl_count_excludes_errors(report: dict) -> List[LintIssue]:
    """Headline 'X actionable listings' should exclude refused responses."""
    issues: List[LintIssue] = []
    declared = (report.get("counts") or {}).get("blacklist_actionable")
    if declared is None:
        return issues

    listings = report.get("dnsbl") or []
    truly_actionable = 0
    for entry in listings:
        if not isinstance(entry, dict):
            continue
        txt = str(entry.get("txt_record") or "")
        rcode = str(entry.get("return_code") or "")
        if _REFUSED_TOKENS.search(txt) or rcode in _ERROR_RETURN_CODES:
            continue
        if entry.get("action_required") or entry.get("action"):
            truly_actionable += 1

    if int(declared) != truly_actionable:
        issues.append(LintIssue(
            check_id="AC3LINT-DNSBL-002",
            check_name="dnsbl_actionable_count_includes_errors",
            severity=Severity.WARNING,
            message=f"Declared '{declared}' actionable DNSBL listings, but after "
                    f"excluding query-error responses only {truly_actionable} remain.",
            location="counts.blacklist_actionable",
            evidence={"declared": declared, "truly_actionable": truly_actionable},
        ))
    return issues
