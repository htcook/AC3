"""
All check functions, registered for the runner.

A 'check' is a callable: (report: dict) -> list[LintIssue].
Add new checks by writing a function and importing it here.
"""

from __future__ import annotations

from typing import Callable, List

from ..issues import LintIssue
from . import counts, ratings, exploits, vendor, llm_quarantine, dnsbl, templates, correctness


CheckFn = Callable[[dict], List[LintIssue]]


# Registry of all checks. Order is presentational only — runner runs all of them.
ALL_CHECKS: list[CheckFn] = [
    # Count reconciliation
    counts.check_asset_count_consistency,
    counts.check_findings_count_consistency,
    counts.check_narrative_count_drift,

    # Rating word consistency
    ratings.check_rating_word_consistency,
    ratings.check_peak_vs_overall_band,

    # Exploit status / proof
    exploits.check_exploit_status_proof_agreement,
    exploits.check_exploitation_summary_agreement,

    # Vendor / scope leakage
    vendor.check_vendor_in_customer_assets,
    vendor.check_vendor_in_web_security,
    vendor.check_vendor_managed_dragging_grade,

    # LLM inference quarantine
    llm_quarantine.check_llm_inference_quarantine,
    llm_quarantine.check_risk_matrix_excludes_llm,

    # DNSBL false positives
    dnsbl.check_dnsbl_refused_responses,
    dnsbl.check_dnsbl_count_excludes_errors,

    # Template / serialization
    templates.check_object_serialization,
    templates.check_template_placeholders,
    templates.check_system_error_in_output,
    templates.check_truncated_detection_rules,
    templates.check_duplicate_detection_rules,

    # Misc correctness
    correctness.check_port_state_recommendation_consistency,
    correctness.check_kev_requires_version,
    correctness.check_compliance_framework_labeling,
    correctness.check_roe_completeness,
    correctness.check_tool_execution_gate,
    correctness.check_risk_matrix_likelihood_logic,
    correctness.check_manual_verification_consistency,
]
