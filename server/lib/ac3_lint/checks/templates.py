"""
Template residue / serialization-bug detection.

Catches:
  - JS '[object Object]' leaking into rendered output
  - Unfilled template placeholders ({{ }}, ${...}, <FOO>, [FOO])
  - System error messages left in customer-facing text
  - Truncated strings that were rendered but cut mid-word
"""

from __future__ import annotations

import re
from typing import List

from ..issues import LintIssue, Severity
from ..models import iter_text_blocks


_OBJECT_OBJECT = re.compile(r"\[object\s+Object\]", re.IGNORECASE)

_PLACEHOLDER_PATTERNS = [
    re.compile(r"\{\{\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\}\}"),       # {{ var }}
    re.compile(r"\$\{\s*[a-zA-Z_][a-zA-Z0-9_.]*\s*\}"),         # ${var}
    re.compile(r"<\s*([A-Z_][A-Z0-9_]{2,})\s*>"),               # <PLACEHOLDER>
    re.compile(r"\bTODO\b|\bFIXME\b|\bXXX\b"),
]

_SYSTEM_ERROR_PATTERNS = [
    re.compile(r"could not be generated due to a processing error", re.IGNORECASE),
    re.compile(r"\berror:\s*(?:none|undefined|null)\b", re.IGNORECASE),
    re.compile(r"\bUndefinedError\b|\bKeyError\b|\bTypeError\b"),
    re.compile(r"<unknown>", re.IGNORECASE),
    re.compile(r"failed to render", re.IGNORECASE),
]

# A truncated detection rule is one that ends mid-string (unbalanced quotes/parens)
# without a normal terminator. Catches both: `...(msg:"text"` (closing paren missing)
# and `...(msg:"text` (closing quote missing).
_TRUNCATED_SURICATA = re.compile(
    r'\(msg:"[^"\n]*$|'        # unclosed msg quote at end
    r'\(msg:"[^"\n]+"\s*$',    # closed quote but missing closing paren / semicolons
    re.MULTILINE,
)


def check_object_serialization(report: dict) -> List[LintIssue]:
    issues: List[LintIssue] = []
    for location, text in iter_text_blocks(report):
        for m in _OBJECT_OBJECT.finditer(text):
            issues.append(LintIssue(
                check_id="AC3LINT-TPL-001",
                check_name="object_object_serialization",
                severity=Severity.ERROR,
                message="Found '[object Object]' in rendered output — JavaScript "
                        "serialization bug in the renderer.",
                location=location,
                detail=f"Snippet: ...{text[max(0,m.start()-20):m.end()+20]}...",
                suggestion="Renderer is calling .toString() on a JS object. Use "
                           "JSON.stringify or render fields explicitly.",
                evidence={"location": location},
            ))

    # Also check structured fields commonly affected
    for asset in report.get("assets", []) or []:
        if isinstance(asset, dict):
            for k, v in asset.items():
                if isinstance(v, str) and "[object Object]" in v:
                    issues.append(LintIssue(
                        check_id="AC3LINT-TPL-001",
                        check_name="object_object_serialization",
                        severity=Severity.ERROR,
                        message=f"Field assets[].{k} contains '[object Object]'.",
                        location=f"assets[].{k}",
                        evidence={"value": v},
                    ))
    return issues


def check_template_placeholders(report: dict) -> List[LintIssue]:
    issues: List[LintIssue] = []
    for location, text in iter_text_blocks(report):
        for pat in _PLACEHOLDER_PATTERNS:
            for m in pat.finditer(text):
                # Skip <CRITICAL>, <HIGH> if they're being used as actual rating words
                # (those would be inside parens or quotes typically; we err toward flagging)
                snippet = text[max(0, m.start()-20):min(len(text), m.end()+20)]
                issues.append(LintIssue(
                    check_id="AC3LINT-TPL-002",
                    check_name="unfilled_template_placeholder",
                    severity=Severity.ERROR,
                    message=f"Unfilled template placeholder '{m.group(0)}' in output.",
                    location=location,
                    detail=f"Snippet: ...{snippet}...",
                    suggestion="Validate all template variables are bound before render. "
                               "Refuse to emit when any placeholder pattern matches.",
                    evidence={"placeholder": m.group(0)},
                ))
    return issues


def check_system_error_in_output(report: dict) -> List[LintIssue]:
    issues: List[LintIssue] = []
    for location, text in iter_text_blocks(report):
        for pat in _SYSTEM_ERROR_PATTERNS:
            m = pat.search(text)
            if m:
                snippet = text[max(0, m.start()-30):min(len(text), m.end()+30)]
                issues.append(LintIssue(
                    check_id="AC3LINT-TPL-003",
                    check_name="system_error_in_customer_output",
                    severity=Severity.ERROR,
                    message=f"System error message leaked to customer-facing text: "
                            f"'{m.group(0)}'.",
                    location=location,
                    detail=f"Snippet: ...{snippet}...",
                    suggestion="Catch generation failures upstream. Replace with an honest "
                               "'no data available for this section' message rather than "
                               "leaking error strings.",
                    evidence={"error_token": m.group(0)},
                ))
    return issues


def check_truncated_detection_rules(report: dict) -> List[LintIssue]:
    """Sigma/Suricata rules cut mid-string."""
    issues: List[LintIssue] = []
    for f in report.get("findings", []) or []:
        if not isinstance(f, dict):
            continue
        for rule_field in ("suricata_rule", "sigma_rule"):
            rule = f.get(rule_field)
            if not isinstance(rule, str):
                continue
            if rule_field == "suricata_rule" and _TRUNCATED_SURICATA.search(rule):
                issues.append(LintIssue(
                    check_id="AC3LINT-TPL-004",
                    check_name="truncated_suricata_rule",
                    severity=Severity.ERROR,
                    message=f"Suricata rule on finding '{f.get('id', '?')}' is "
                            f"truncated mid-string.",
                    location=f"findings[{f.get('id', '?')}].{rule_field}",
                    suggestion="Increase output token limit on the rule generator, or "
                               "store rules in a separate field with no length cap.",
                    evidence={"finding_id": f.get("id"),
                              "tail": rule[-60:] if len(rule) > 60 else rule},
                ))
    return issues


def check_duplicate_detection_rules(report: dict) -> List[LintIssue]:
    """
    If every finding has the same Sigma rule body, the rules are templated, not
    generated. That's misleading detection guidance.
    """
    issues: List[LintIssue] = []
    bodies: dict[str, list[str]] = {}
    for f in report.get("findings", []) or []:
        if not isinstance(f, dict):
            continue
        rule = f.get("sigma_rule")
        if not isinstance(rule, str) or not rule.strip():
            continue
        # Normalize: ignore the title/id/description lines, focus on detection block
        body = re.sub(r"^(title|id|description|date):.*$", "", rule, flags=re.MULTILINE)
        body = re.sub(r"\s+", " ", body).strip()
        bodies.setdefault(body, []).append(f.get("id", "?"))

    for body, fids in bodies.items():
        if len(fids) >= 3:
            issues.append(LintIssue(
                check_id="AC3LINT-TPL-005",
                check_name="duplicate_sigma_rules",
                severity=Severity.WARNING,
                message=f"{len(fids)} findings share an identical Sigma rule body. "
                        f"Detection guidance is templated, not finding-specific.",
                location="findings[].sigma_rule",
                suggestion="Generate detection rules per-finding from the actual evidence, "
                           "or omit the section for findings where detection logic "
                           "doesn't apply (e.g., availability/configuration observations).",
                evidence={"affected_findings": fids[:10]},
            ))
    return issues
