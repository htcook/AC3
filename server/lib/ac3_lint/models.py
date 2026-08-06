"""
Report navigation helpers.

The linter takes a dict ("the report") and runs checks against it. We don't
require a strict schema, because your generator's intermediate format may
evolve. Instead, every check uses defensive navigation through these helpers
and skips gracefully when a section is absent.

Canonical top-level keys the linter understands:

    report_type:        "domain_intel" | "pentest"
    metadata:           {scan_id|engagement_id, target, scan_mode, ...}
    coverage:           {nuclei_findings, tool_executions, web_assets_crawled, ...}
    risk:               {overall_score, overall_band, peak_asset_score, ...}
    counts:             {total_assets, confirmed_findings, potential_findings,
                         kev_matches, breach_exposures, ...}
    assets:             [{hostname, ip, risk_score, risk_band, technologies, ...}]
    vendor_assets:      [{hostname, vendor, category, exclusion_reason}]
    dnsbl:              [{zone, return_code, txt_record, severity, ...}]
    registration:       {registrar, dnssec_enabled, transfer_lock, delete_lock, ...}
    email_security:     {spf, dkim, dmarc, score, grade}
    ports:              [{port, service, host, status, severity, rationale}]
    compliance:         {benchmark, score, total_checks, passed, failed}
    web_security:       [{asset, grade, server, missing_headers}]
    findings:           [{id, title, severity, cvss, cve_status, tool, evidence,
                          sigma_rule, suricata_rule, ...}]
    exploitation:       [{id, target, status, access_level, shell, proof_lines,
                          result_type, ...}]
    tool_executions:    [{tool, phase, command, exit_code, duration_ms,
                          findings_count}]
    roe:                {status, signed_date, expiry_date, signer, document_uploaded}
    risk_matrix:        [{finding_id, likelihood, impact, risk_rating}]
    analytical_confidence: {high, moderate, low}
    rendered_text:      {section_name: "rendered prose"}  # for narrative checks

If your generator uses different keys, write a thin adapter function rather
than reshaping the linter — the helpers below already tolerate missing keys.
"""

from __future__ import annotations

from typing import Any, Iterable


def get(report: dict, *path: str, default: Any = None) -> Any:
    """Navigate a nested dict by path, returning default if any key is missing."""
    cur: Any = report
    for key in path:
        if not isinstance(cur, dict):
            return default
        if key not in cur:
            return default
        cur = cur[key]
    return cur


def iter_text_blocks(report: dict) -> Iterable[tuple[str, str]]:
    """
    Yield (location_name, text) tuples for every rendered prose block in the
    report, plus any string field that's >40 chars and might contain stale
    template residue. Used by narrative-text checks.
    """
    rendered = report.get("rendered_text") or {}
    if isinstance(rendered, dict):
        for section, text in rendered.items():
            if isinstance(text, str) and text.strip():
                yield (f"rendered_text.{section}", text)

    # also walk findings/exploitation entries for description, impact, etc.
    for finding in report.get("findings", []) or []:
        if not isinstance(finding, dict):
            continue
        fid = finding.get("id", "?")
        for k in ("description", "impact", "attack_scenario", "remediation_short_term"):
            v = finding.get(k)
            if isinstance(v, str) and len(v) > 40:
                yield (f"findings[{fid}].{k}", v)

    for ex in report.get("exploitation", []) or []:
        if not isinstance(ex, dict):
            continue
        eid = ex.get("id", "?")
        proof = ex.get("proof_lines")
        if isinstance(proof, list):
            joined = "\n".join(str(p) for p in proof)
            if joined.strip():
                yield (f"exploitation[{eid}].proof_lines", joined)
        elif isinstance(proof, str) and proof.strip():
            yield (f"exploitation[{eid}].proof_lines", proof)


def report_type(report: dict) -> str:
    return str(report.get("report_type", "")).lower()
