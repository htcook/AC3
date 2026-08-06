"""
LLM-inference quarantine.

Findings whose evidence is 'LLM analysis of other asset' must not be:
  - assigned a non-zero CVSS score,
  - included in the main findings count,
  - placed in the risk matrix,
  - attributed to a real scanning tool.

They belong in a separate 'Hypotheses for Manual Investigation' section
that is explicitly not part of the deliverable findings.
"""

from __future__ import annotations

import re
from typing import List

from ..issues import LintIssue, Severity


_LLM_TOOL_TOKENS = ("llm inference engine", "llm inference", "llm analysis",
                    "ai inference", "language model")
_LLM_EVIDENCE_TOKENS = ("inferred by llm", "llm analysis of", "based on inference",
                        "no direct evidence", "speculative")


def _is_llm_inference(finding: dict) -> bool:
    tool = str(finding.get("tool") or finding.get("methodology_tool") or "").lower()
    if any(tok in tool for tok in _LLM_TOOL_TOKENS):
        return True
    evidence = str(finding.get("evidence") or "").lower()
    if any(tok in evidence for tok in _LLM_EVIDENCE_TOKENS):
        return True
    title = str(finding.get("title") or "").lower()
    return "(inferred)" in title


def check_llm_inference_quarantine(report: dict) -> List[LintIssue]:
    issues: List[LintIssue] = []
    for f in report.get("findings", []) or []:
        if not isinstance(f, dict):
            continue
        if not _is_llm_inference(f):
            continue
        fid = f.get("id", "?")

        cvss = f.get("cvss")
        try:
            cvss_val = float(cvss) if cvss not in (None, "", "N/A") else 0.0
        except (TypeError, ValueError):
            cvss_val = 0.0

        if cvss_val > 0:
            issues.append(LintIssue(
                check_id="AC3LINT-LLM-001",
                check_name="llm_inference_with_cvss",
                severity=Severity.ERROR,
                message=f"Finding '{fid}' is an LLM inference but has CVSS {cvss_val}. "
                        f"Inferences must not carry CVSS scores.",
                location=f"findings[{fid}].cvss",
                suggestion="Move LLM-inferred items to a separate 'Hypotheses' section "
                           "without severity/CVSS/risk-matrix placement. They are triage "
                           "hints, not findings.",
                evidence={"id": fid, "cvss": cvss_val, "tool": f.get("tool")},
            ))

        sev = str(f.get("severity") or "").upper()
        if sev not in ("INFORMATIONAL", "INFO", "", "N/A"):
            issues.append(LintIssue(
                check_id="AC3LINT-LLM-002",
                check_name="llm_inference_with_severity",
                severity=Severity.ERROR,
                message=f"Finding '{fid}' is an LLM inference but has severity "
                        f"'{sev}'. Inferences must be Informational at most.",
                location=f"findings[{fid}].severity",
                evidence={"id": fid, "severity": sev},
            ))

        # Self-reference bug: 'Inferred by LLM analysis of other asset (X)' where X is the
        # finding's own asset
        ev = str(f.get("evidence") or "")
        asset = str(f.get("asset") or "")
        m = re.search(r"analysis of (?:other )?asset\s*\(([^)]+)\)", ev, re.IGNORECASE)
        if m and asset and m.group(1).strip() == asset.strip():
            issues.append(LintIssue(
                check_id="AC3LINT-LLM-003",
                check_name="llm_inference_self_reference",
                severity=Severity.WARNING,
                message=f"Finding '{fid}' claims to be inferred from 'other asset' "
                        f"but the asset cited is the same as the finding's own asset.",
                location=f"findings[{fid}].evidence",
                suggestion="Template-residue: the prompt template is emitting boilerplate "
                           "text that doesn't reflect the actual cross-asset reasoning.",
                evidence={"id": fid, "asset": asset, "cited_asset": m.group(1)},
            ))

    return issues


def check_risk_matrix_excludes_llm(report: dict) -> List[LintIssue]:
    """Risk matrix entries should not reference LLM-inference finding IDs."""
    issues: List[LintIssue] = []
    findings_by_id = {f.get("id"): f for f in report.get("findings", []) or []
                      if isinstance(f, dict) and f.get("id")}
    for row in report.get("risk_matrix", []) or []:
        if not isinstance(row, dict):
            continue
        fid = row.get("finding_id")
        if not fid or fid not in findings_by_id:
            continue
        if _is_llm_inference(findings_by_id[fid]):
            issues.append(LintIssue(
                check_id="AC3LINT-LLM-004",
                check_name="llm_inference_in_risk_matrix",
                severity=Severity.ERROR,
                message=f"LLM-inferred finding '{fid}' appears in the risk matrix. "
                        f"Quarantined findings must not be plotted.",
                location=f"risk_matrix[].finding_id='{fid}'",
                evidence={"finding_id": fid},
            ))
    return issues
