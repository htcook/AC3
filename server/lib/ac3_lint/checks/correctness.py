"""
Miscellaneous correctness checks:
  - port state ↔ recommendation consistency
  - KEV match claims require version
  - compliance framework labeling
  - ROE completeness for pentest reports
  - engagement tool-failure gate
  - risk-matrix likelihood logic
"""

from __future__ import annotations

import re
from typing import List

from ..issues import LintIssue, Severity
from ..models import get


def check_port_state_recommendation_consistency(report: dict) -> List[LintIssue]:
    """A port marked CLOSED shouldn't appear in 'exposed' recommendations."""
    issues: List[LintIssue] = []
    closed_ports = set()
    for p in report.get("ports", []) or []:
        if not isinstance(p, dict):
            continue
        state = str(p.get("status") or p.get("state") or "").upper()
        if state in ("CLOSED", "FILTERED", "REJECTED"):
            closed_ports.add(str(p.get("port")))

    if not closed_ports:
        return issues

    # Look for 'port X exposed' phrasing in recommendations
    recs = report.get("recommendations") or []
    for rec in recs:
        if not isinstance(rec, dict):
            continue
        text = str(rec.get("recommendation") or rec.get("text") or "")
        m = re.search(r"port\s+(\d+).*?exposed", text, re.IGNORECASE)
        if m and m.group(1) in closed_ports:
            issues.append(LintIssue(
                check_id="AC3LINT-PORT-001",
                check_name="closed_port_in_exposed_recommendation",
                severity=Severity.ERROR,
                message=f"Recommendation references port {m.group(1)} as 'exposed' but "
                        f"port table marks it CLOSED.",
                location="recommendations vs ports[]",
                suggestion="Likely a column-mapping bug in the port-state renderer. "
                           "Verify the state field is being read from the correct column.",
                evidence={"port": m.group(1)},
            ))
    return issues


def check_kev_requires_version(report: dict) -> List[LintIssue]:
    """
    KEV (CISA Known Exploited Vulnerabilities) matches require a specific CVE.
    A 'technology family' match (e.g. 'jQuery') with no version is not a KEV hit.
    """
    issues: List[LintIssue] = []
    declared = (report.get("counts") or {}).get("kev_matches")
    if declared is None:
        return issues

    findings = report.get("findings", []) or []
    real_kev = 0
    family_only = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        if not f.get("kev_listed"):
            continue
        cve = f.get("cve")
        cve_status = str(f.get("cve_status") or "").lower()
        product_version = f.get("product_version") or f.get("version")
        if cve and cve_status == "confirmed" and product_version:
            real_kev += 1
        else:
            family_only += 1

    if int(declared) > 0 and real_kev == 0 and family_only > 0:
        issues.append(LintIssue(
            check_id="AC3LINT-KEV-001",
            check_name="kev_count_without_version",
            severity=Severity.ERROR,
            message=f"Headline claims {declared} KEV matches, but no findings have "
                    f"a confirmed CVE+version. {family_only} are technology-family "
                    f"matches only, which are not KEV hits.",
            location="counts.kev_matches",
            suggestion="Only count a KEV hit when the CVE is confirmed AND the product "
                       "version is known. Family matches go in a 'potential' section "
                       "with explicit 'pending verification' label.",
            evidence={"declared": declared, "real_kev": real_kev,
                      "family_only": family_only},
        ))
    return issues


def check_compliance_framework_labeling(report: dict) -> List[LintIssue]:
    """
    A single percentage score against a compound framework string with very few
    checks is misleading. Flag for relabeling — unless the label already
    includes a caveat ("subset", "partial", "limited", "not a full audit").
    """
    issues: List[LintIssue] = []
    comp = report.get("compliance") or {}
    if not isinstance(comp, dict):
        return issues
    benchmark = str(comp.get("benchmark") or "")
    total_checks = comp.get("total_checks")
    if not benchmark or total_checks is None:
        return issues

    has_caveat = any(tok in benchmark.lower() for tok in
                     ("subset", "partial", "limited", "not a full audit",
                      "external hygiene", "informational"))
    has_compound = sum(1 for fw in ("CIS", "STIG", "NIST", "ISO", "HIPAA", "PCI",
                                     "FedRAMP", "CMMC")
                       if fw in benchmark)
    if has_compound >= 2 and int(total_checks) < 50 and not has_caveat:
        issues.append(LintIssue(
            check_id="AC3LINT-COMP-001",
            check_name="compound_framework_with_few_checks",
            severity=Severity.WARNING,
            message=f"Compliance section claims '{benchmark}' but only ran "
                    f"{total_checks} checks. A combined score across compound "
                    f"frameworks with <50 checks is not defensible to a 3PAO.",
            location="compliance.benchmark",
            suggestion="Either (a) split scores per framework, or (b) rename the "
                       "section to 'External hygiene checks (limited subset)' with "
                       "explicit caveats. Don't aggregate disjoint frameworks into a "
                       "single percentage.",
            evidence={"benchmark": benchmark, "total_checks": total_checks},
        ))
    return issues


def check_roe_completeness(report: dict) -> List[LintIssue]:
    """For pentest reports: ROE signer/document/expiry should not be absent."""
    if str(report.get("report_type", "")).lower() != "pentest":
        return []
    issues: List[LintIssue] = []
    roe = report.get("roe") or {}
    if not isinstance(roe, dict):
        return issues

    blank = lambda v: v in (None, "", "N/A", "n/a", "None")

    if blank(roe.get("signer")) and blank(roe.get("signer_name")):
        issues.append(LintIssue(
            check_id="AC3LINT-ROE-001",
            check_name="roe_signer_missing",
            severity=Severity.WARNING,
            message="ROE signer not recorded — required by FedRAMP Pen Test Guidance §6.1.",
            location="roe.signer",
            evidence={"roe": {k: v for k, v in roe.items() if k in
                              ("signer", "signed_date", "expiry_date")}},
        ))
    if not roe.get("document_uploaded"):
        issues.append(LintIssue(
            check_id="AC3LINT-ROE-002",
            check_name="roe_document_missing",
            severity=Severity.WARNING,
            message="ROE document not attached to engagement record.",
            location="roe.document_uploaded",
            suggestion="3PAOs assessing your platform will flag this. Block engagement "
                       "completion until the signed ROE is uploaded.",
            evidence={},
        ))
    if blank(roe.get("expiry_date")):
        issues.append(LintIssue(
            check_id="AC3LINT-ROE-003",
            check_name="roe_expiry_missing",
            severity=Severity.INFO,
            message="ROE expiry date not recorded.",
            location="roe.expiry_date",
            evidence={},
        ))
    return issues


def check_tool_execution_gate(report: dict, fail_threshold: float = 0.5) -> List[LintIssue]:
    """
    If more than `fail_threshold` of planned tools failed, the engagement should
    be marked incomplete rather than shipping a 'no findings' report.
    """
    issues: List[LintIssue] = []
    tools = report.get("tool_executions") or []
    if not tools:
        return issues

    planned = len(tools)
    failed = 0
    for t in tools:
        if not isinstance(t, dict):
            continue
        ec = t.get("exit_code")
        dur = t.get("duration_ms") or 0
        # Heuristics for 'didn't really run':
        #  - exit code is non-zero AND not in known-good (e.g. nikto often exits 0)
        #  - duration < 100ms (didn't actually do work)
        #  - exit code is -1 or in the 127/128 range (command-not-found / signal)
        if ec is None:
            continue
        try:
            ec_int = int(ec)
        except (TypeError, ValueError):
            continue
        bad = (ec_int < 0 or ec_int in (1, 2, 127, 253) or ec_int >= 128)
        if bad and dur < 1000:
            failed += 1

    if planned >= 5 and failed / planned >= fail_threshold:
        issues.append(LintIssue(
            check_id="AC3LINT-EXEC-001",
            check_name="engagement_tool_failure_rate",
            severity=Severity.ERROR,
            message=f"{failed}/{planned} tools failed to execute "
                    f"({failed/planned:.0%}). Engagement should not ship as 'completed'.",
            location="tool_executions[]",
            suggestion="Add a gate: when tool failure rate exceeds threshold, mark the "
                       "engagement 'requires retest — infrastructure failure' and route "
                       "to ops instead of generating a customer-facing report.",
            evidence={"planned": planned, "failed": failed,
                      "failure_rate": round(failed / planned, 2)},
        ))
    return issues


def check_risk_matrix_likelihood_logic(report: dict) -> List[LintIssue]:
    """
    Findings flagged low-confidence (e.g., LLM-inferred) cannot be Very High
    Likelihood. Likelihood should be a function of confidence × exploitability.
    """
    issues: List[LintIssue] = []
    findings_by_id = {f.get("id"): f for f in report.get("findings", []) or []
                      if isinstance(f, dict) and f.get("id")}

    for row in report.get("risk_matrix", []) or []:
        if not isinstance(row, dict):
            continue
        fid = row.get("finding_id")
        likelihood = str(row.get("likelihood") or "").lower()
        if fid not in findings_by_id:
            continue
        f = findings_by_id[fid]
        confidence = str(f.get("confidence") or "").lower()
        if confidence == "low" and "very high" in likelihood:
            issues.append(LintIssue(
                check_id="AC3LINT-RISK-001",
                check_name="low_confidence_high_likelihood",
                severity=Severity.WARNING,
                message=f"Finding '{fid}' has low confidence but is plotted at "
                        f"Very High Likelihood in the risk matrix.",
                location=f"risk_matrix[].finding_id='{fid}'",
                suggestion="Cap likelihood at the confidence ceiling: low confidence → "
                           "max Medium likelihood. Otherwise the matrix loses analytical "
                           "value (everything clusters Very High).",
                evidence={"id": fid, "confidence": confidence,
                          "likelihood": likelihood},
            ))
    return issues


def check_manual_verification_consistency(report: dict) -> List[LintIssue]:
    """
    If any section says 'findings have not been manually verified' and another
    says 'all findings validated through manual testing', that's a contradiction.
    """
    issues: List[LintIssue] = []
    not_verified = re.compile(
        r"(?:findings|results)\s+have\s+not\s+been\s+manually\s+verified",
        re.IGNORECASE)
    yes_verified = re.compile(
        r"all\s+findings\s+(?:in\s+this\s+report\s+)?have\s+been\s+(?:validated|verified)\s+"
        r"through\s+manual",
        re.IGNORECASE)

    blocks = list((report.get("rendered_text") or {}).items())
    has_no = any(not_verified.search(str(t)) for _, t in blocks)
    has_yes = any(yes_verified.search(str(t)) for _, t in blocks)

    if has_no and has_yes:
        issues.append(LintIssue(
            check_id="AC3LINT-VERIFY-001",
            check_name="contradictory_manual_verification_claims",
            severity=Severity.ERROR,
            message="Report contains both 'findings have not been manually verified' "
                    "AND 'all findings validated through manual testing'. Pick one.",
            location="rendered_text (multiple sections)",
            suggestion="The honest answer for an automated pipeline is usually 'not "
                       "manually verified'. Remove boilerplate to the contrary.",
            evidence={},
        ))
    return issues
