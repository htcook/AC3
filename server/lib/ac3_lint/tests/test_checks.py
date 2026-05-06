"""
Sanity tests for each check module. Run with:

    python -m unittest tests.test_checks

These are not exhaustive — they verify each check fires on a positive case
and stays quiet on a negative case. Add more cases as you encounter new
failure modes in production.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ac3_lint import run, Severity  # noqa: E402
from ac3_lint.checks import counts, ratings, exploits, vendor  # noqa: E402
from ac3_lint.checks import llm_quarantine, dnsbl, templates, correctness  # noqa: E402


class TestCounts(unittest.TestCase):
    def test_asset_count_mismatch_fires(self):
        report = {
            "counts": {"total_assets": 13},
            "assets": [{"hostname": "a"}, {"hostname": "b"}],
            "vendor_assets": [{"hostname": "c"}],
        }
        issues = counts.check_asset_count_consistency(report)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].check_id, "AC3LINT-COUNT-001")

    def test_asset_count_match_quiet(self):
        report = {
            "counts": {"total_assets": 3},
            "assets": [{"hostname": "a"}, {"hostname": "b"}],
            "vendor_assets": [{"hostname": "c"}],
        }
        self.assertEqual(counts.check_asset_count_consistency(report), [])

    def test_narrative_drift_fires(self):
        report = {
            "counts": {"total_assets": 8, "confirmed_findings": 17},
            "rendered_text": {
                "exec": "The scope encompassed 13 discovered assets analyzed."
            },
        }
        issues = counts.check_narrative_count_drift(report)
        self.assertTrue(any(i.check_id == "AC3LINT-COUNT-004" for i in issues))


class TestRatings(unittest.TestCase):
    def test_rating_word_disagreement_fires(self):
        report = {
            "risk": {"overall_band": "MEDIUM"},
            "rendered_text": {
                "exec": "Confidence in the overall LOW risk rating is high."
            },
        }
        issues = ratings.check_rating_word_consistency(report)
        self.assertTrue(any(i.check_id == "AC3LINT-RATING-001" for i in issues))

    def test_rating_word_agreement_quiet(self):
        report = {
            "risk": {"overall_band": "MEDIUM"},
            "rendered_text": {
                "exec": "The overall risk rating is MEDIUM."
            },
        }
        self.assertEqual(ratings.check_rating_word_consistency(report), [])


class TestExploits(unittest.TestCase):
    def test_succeeded_with_failed_proof_fires(self):
        report = {
            "exploitation": [
                {"id": "E-1", "status": "SUCCEEDED", "access_level": "none",
                 "shell_obtained": False,
                 "proof_lines": ["[+] EXPLOIT_FAILED: Authentication failed"]}
            ]
        }
        issues = exploits.check_exploit_status_proof_agreement(report)
        self.assertTrue(any(i.check_id == "AC3LINT-EXPLOIT-001" for i in issues))

    def test_placeholder_credential_fires(self):
        report = {
            "exploitation": [
                {"id": "E-1", "status": "SUCCEEDED",
                 "proof_lines": ["X_SCAN_KEY is still set to the default placeholder."]}
            ]
        }
        issues = exploits.check_exploit_status_proof_agreement(report)
        self.assertTrue(any(i.check_id == "AC3LINT-EXPLOIT-003" for i in issues))


class TestVendor(unittest.TestCase):
    def test_google_in_customer_assets_fires(self):
        report = {
            "metadata": {"target": "criticalsec.com"},
            "assets": [{"hostname": "google.com"}],
        }
        issues = vendor.check_vendor_in_customer_assets(report)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].check_id, "AC3LINT-VENDOR-001")

    def test_customer_subdomain_quiet(self):
        report = {
            "metadata": {"target": "criticalsec.com"},
            "assets": [{"hostname": "mail.criticalsec.com"}],
        }
        self.assertEqual(vendor.check_vendor_in_customer_assets(report), [])

    def test_managed_provider_dragging_grade(self):
        report = {
            "email_security": {"mail_provider": "Google Workspace (Managed Service)"},
            "domain_health": {"mail_server_grade": "F"},
        }
        issues = vendor.check_vendor_managed_dragging_grade(report)
        self.assertTrue(any(i.check_id == "AC3LINT-VENDOR-003" for i in issues))


class TestLLMQuarantine(unittest.TestCase):
    def test_llm_inference_with_cvss_fires(self):
        report = {
            "findings": [
                {"id": "F-1", "title": "Common web vuln (Inferred)",
                 "tool": "LLM Inference Engine",
                 "cvss": 6.5, "severity": "Medium",
                 "evidence": "Inferred by LLM analysis of other asset (X).",
                 "asset": "X"}
            ]
        }
        issues = llm_quarantine.check_llm_inference_quarantine(report)
        ids = {i.check_id for i in issues}
        self.assertIn("AC3LINT-LLM-001", ids)
        self.assertIn("AC3LINT-LLM-002", ids)
        self.assertIn("AC3LINT-LLM-003", ids)


class TestDNSBL(unittest.TestCase):
    def test_query_refused_fires(self):
        report = {
            "dnsbl": [
                {"zone": "multi.uribl.com", "return_code": "127.0.0.1",
                 "txt_record": "Query Refused. See http://uribl.com/refused.shtml",
                 "action_required": True}
            ]
        }
        issues = dnsbl.check_dnsbl_refused_responses(report)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].check_id, "AC3LINT-DNSBL-001")

    def test_real_listing_quiet(self):
        report = {
            "dnsbl": [
                {"zone": "cbl.anti-spam.org.cn", "return_code": "208.98.40.203",
                 "txt_record": "CBL — IP detected sending spam",
                 "action_required": True}
            ]
        }
        self.assertEqual(dnsbl.check_dnsbl_refused_responses(report), [])


class TestTemplates(unittest.TestCase):
    def test_object_object_fires(self):
        report = {
            "rendered_text": {"any": "Risk Signals [object Object], [object Object] here"}
        }
        issues = templates.check_object_serialization(report)
        self.assertTrue(any(i.check_id == "AC3LINT-TPL-001" for i in issues))

    def test_processing_error_fires(self):
        report = {
            "rendered_text": {"narrative": "The exploitation narrative could not be generated due to a processing error."}
        }
        issues = templates.check_system_error_in_output(report)
        self.assertTrue(any(i.check_id == "AC3LINT-TPL-003" for i in issues))

    def test_truncated_suricata_fires(self):
        report = {
            "findings": [
                {"id": "F-1",
                 "suricata_rule": 'alert ip any -> any any (msg:"AC3 Security Finding - Potential"'}
            ]
        }
        issues = templates.check_truncated_detection_rules(report)
        self.assertTrue(any(i.check_id == "AC3LINT-TPL-004" for i in issues))


class TestCorrectness(unittest.TestCase):
    def test_closed_port_in_recommendation_fires(self):
        report = {
            "ports": [{"port": "143", "service": "IMAP", "status": "CLOSED"}],
            "recommendations": [
                {"recommendation": "The 'IMAP (port 143) exposed' (Sev 5/10) finding."}
            ],
        }
        issues = correctness.check_port_state_recommendation_consistency(report)
        self.assertTrue(any(i.check_id == "AC3LINT-PORT-001" for i in issues))

    def test_tool_failure_gate_fires(self):
        report = {
            "tool_executions": [
                {"tool": "raw", "exit_code": -1, "duration_ms": 0, "findings_count": 0},
                {"tool": "arjun", "exit_code": 2, "duration_ms": 400, "findings_count": 0},
                {"tool": "katana", "exit_code": -1, "duration_ms": 11, "findings_count": 0},
                {"tool": "feroxbuster", "exit_code": 2, "duration_ms": 15, "findings_count": 0},
                {"tool": "testssl", "exit_code": 127, "duration_ms": 100, "findings_count": 0},
                {"tool": "nikto", "exit_code": 0, "duration_ms": 86680, "findings_count": 1},
            ]
        }
        issues = correctness.check_tool_execution_gate(report)
        self.assertTrue(any(i.check_id == "AC3LINT-EXEC-001" for i in issues))

    def test_kev_without_version_fires(self):
        report = {
            "counts": {"kev_matches": 6},
            "findings": [
                {"id": "F-1", "kev_listed": True, "cve": None, "cve_status": "potential"}
            ]
        }
        issues = correctness.check_kev_requires_version(report)
        self.assertTrue(any(i.check_id == "AC3LINT-KEV-001" for i in issues))

    def test_compound_compliance_with_few_checks_fires(self):
        report = {
            "compliance": {"benchmark": "CIS + DISA STIG + NIST 800-53",
                           "score": 47, "total_checks": 16}
        }
        issues = correctness.check_compliance_framework_labeling(report)
        self.assertTrue(any(i.check_id == "AC3LINT-COMP-001" for i in issues))


class TestEndToEnd(unittest.TestCase):
    def test_clean_report_passes(self):
        path = ROOT / "examples" / "sample_domain_report_clean.json"
        import json
        report = json.loads(path.read_text())
        result = run(report)
        # Clean report may have warnings but should not have errors
        self.assertEqual(len(result.errors), 0,
                         f"Clean report unexpectedly has errors: "
                         f"{[i.check_id for i in result.errors]}")

    def test_broken_domain_report_fails(self):
        path = ROOT / "examples" / "sample_domain_report_broken.json"
        import json
        report = json.loads(path.read_text())
        result = run(report)
        self.assertFalse(result.passed)
        # Spot-check that we caught the headline issues
        ids = {i.check_id for i in result.errors}
        self.assertIn("AC3LINT-COUNT-001", ids)   # 13 vs 8 asset count
        self.assertIn("AC3LINT-RATING-001", ids)  # MEDIUM vs LOW rating word
        self.assertIn("AC3LINT-VENDOR-002", ids)  # google.com graded in web_security
        self.assertIn("AC3LINT-DNSBL-001", ids)   # Query Refused treated as listing

    def test_broken_pentest_report_fails(self):
        path = ROOT / "examples" / "sample_pentest_report_broken.json"
        import json
        report = json.loads(path.read_text())
        result = run(report)
        self.assertFalse(result.passed)
        ids = {i.check_id for i in result.errors}
        self.assertIn("AC3LINT-EXPLOIT-001", ids)  # SUCCEEDED + EXPLOIT_FAILED
        self.assertIn("AC3LINT-EXPLOIT-003", ids)  # placeholder X-Scan-Key
        self.assertIn("AC3LINT-LLM-001", ids)      # LLM inference with CVSS
        self.assertIn("AC3LINT-TPL-001", ids)      # [object Object]
        self.assertIn("AC3LINT-TPL-003", ids)      # 'processing error' in output
        self.assertIn("AC3LINT-TPL-004", ids)      # truncated suricata
        self.assertIn("AC3LINT-VERIFY-001", ids)   # contradictory verification claims


if __name__ == "__main__":
    unittest.main(verbosity=2)
