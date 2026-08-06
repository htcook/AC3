"""
Vendor / supply-chain domain leakage.

Catches the criticalsec.com -> google.com / googlemail.com / 1e100.net
attribution bug, where MX targets, hosting provider domains, and PTR
hostnames get treated as customer assets. This is a credibility-killer.
"""

from __future__ import annotations

from typing import List

from ..issues import LintIssue, Severity


# Domains that should NEVER appear in a customer's asset list — they are
# always upstream infrastructure. Extend as you encounter more.
VENDOR_DOMAINS: set[str] = {
    # Google
    "google.com", "googlemail.com", "googleusercontent.com", "1e100.net",
    "googleapis.com", "gstatic.com",
    # Microsoft
    "microsoft.com", "outlook.com", "office.com", "office365.com",
    "azure.com", "windows.net", "msftncsi.com",
    # AWS
    "amazonaws.com", "awsdns.com", "cloudfront.net",
    # Other major CDNs / mail / DNS infra
    "cloudflare.com", "fastly.net", "akamaiedge.net", "akamaitechnologies.com",
    "domaincontrol.com", "dnsmadeeasy.com", "registrar-servers.com",
    "mailgun.org", "sendgrid.net", "mailchimp.com",
    "github.io", "gitlab.io", "netlify.app",
}


def _root_domain(host: str) -> str:
    """Strip subdomains down to a 2-label root for matching."""
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    # Naive 2-label root; good enough for the vendor allowlist
    return ".".join(parts[-2:])


def _is_vendor(host: str) -> bool:
    if not host:
        return False
    h = host.lower().strip(".")
    if h in VENDOR_DOMAINS:
        return True
    root = _root_domain(h)
    return root in VENDOR_DOMAINS


def check_vendor_in_customer_assets(report: dict) -> List[LintIssue]:
    """Customer assets[] must not contain hostnames that are clearly vendor infra."""
    issues: List[LintIssue] = []
    target = (report.get("metadata") or {}).get("target") or ""
    target_root = _root_domain(target)

    for asset in report.get("assets", []) or []:
        if not isinstance(asset, dict):
            continue
        host = asset.get("hostname") or asset.get("name") or ""
        if not host:
            continue
        host_root = _root_domain(host)
        # Allow if it shares the customer's root domain
        if target_root and host_root == target_root:
            continue
        if _is_vendor(host):
            issues.append(LintIssue(
                check_id="AC3LINT-VENDOR-001",
                check_name="vendor_in_customer_assets",
                severity=Severity.ERROR,
                message=f"Vendor hostname '{host}' appears in customer assets[] for "
                        f"target '{target}'. Should be in vendor_assets[] or excluded.",
                location=f"assets[].hostname='{host}'",
                suggestion="Apply a vendor-domain allowlist before classifying discovered "
                           "subdomains. MX targets, NS hostnames, and reverse-DNS PTR "
                           "values should never become 'customer assets'.",
                evidence={"hostname": host, "target": target,
                          "vendor_root": host_root},
            ))
    return issues


def check_vendor_in_web_security(report: dict) -> List[LintIssue]:
    """Vendor hostnames must not appear in customer web-security grading."""
    issues: List[LintIssue] = []
    target_root = _root_domain((report.get("metadata") or {}).get("target") or "")
    for entry in report.get("web_security", []) or []:
        if not isinstance(entry, dict):
            continue
        asset = entry.get("asset") or entry.get("hostname") or ""
        if not asset:
            continue
        if target_root and _root_domain(asset) == target_root:
            continue
        if _is_vendor(asset):
            issues.append(LintIssue(
                check_id="AC3LINT-VENDOR-002",
                check_name="vendor_in_web_security",
                severity=Severity.ERROR,
                message=f"Vendor asset '{asset}' is being graded in web_security[] "
                        f"and counted against the customer's score.",
                location=f"web_security[].asset='{asset}'",
                suggestion="Exclude vendor-managed assets from customer-facing security "
                           "grades. Optionally surface them in a separate 'supply chain "
                           "context' section.",
                evidence={"asset": asset, "grade": entry.get("grade")},
            ))
    return issues


def check_vendor_managed_dragging_grade(report: dict) -> List[LintIssue]:
    """
    If email_security explicitly notes a managed provider (e.g. Google Workspace),
    a 'mail server' F-grade in domain_health shouldn't drag the customer score.
    """
    issues: List[LintIssue] = []
    provider = (get_dict(report, "email_security").get("mail_provider") or "").lower()
    if not provider:
        return issues
    if "managed" not in provider and "google" not in provider \
            and "microsoft" not in provider and "office" not in provider:
        return issues
    server_grade = (get_dict(report, "domain_health").get("mail_server_grade") or "").upper()
    if server_grade in ("D", "E", "F"):
        issues.append(LintIssue(
            check_id="AC3LINT-VENDOR-003",
            check_name="managed_provider_dragging_grade",
            severity=Severity.WARNING,
            message=f"Mail server grade '{server_grade}' is dragging the customer score, "
                    f"but mail provider is '{provider}' (vendor-managed).",
            location="domain_health.mail_server_grade",
            suggestion="Don't grade vendor-managed infrastructure against the customer. "
                       "Either drop the sub-grade or label it 'vendor (informational)'.",
            evidence={"provider": provider, "server_grade": server_grade},
        ))
    return issues


def get_dict(report: dict, key: str) -> dict:
    v = report.get(key)
    return v if isinstance(v, dict) else {}
