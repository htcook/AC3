/**
 * Compliance Evidence Export — AC3 → AC3-Plus Integration
 *
 * Exports engagement findings and evidence to the compliance service
 * (POST compliance.aceofcloud.io/api/findings/import).
 *
 * Maps AC3 findings to the evidence contract format:
 * - Engagement vulns → gap_findings (with control_ids from compliance-framework-mapping)
 * - Tool outputs → poam_evidence (with provenance hash chain)
 * - Phishing results → AT-2/IR-4/CA-8 evidence
 * - Detection validation → SI-4/IR-6/CA-7 evidence
 */

import { ENV } from "../_core/env";
import crypto from "crypto";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ExportFinding {
  source_finding_id: string;
  system_ref: string;
  control_ids: string[];
  untagged_reason?: string;
  gap_statement: string;
  severity: "high" | "moderate" | "low";
  finding_type: "condition" | "coverage";
  cve?: string;
  cwe?: string;
  mitre_technique?: string;
  owasp_category?: string;
  tool?: string;
  source?: string;
  detected_at: string;
}

export interface ExportEvidence {
  source_evidence_id: string;
  system_ref: string;
  control_ids: string[];
  linked_source_finding_ids: string[];
  file_name: string;
  artifact: {
    storage: "s3";
    path: string;
    mime_type: string;
    size?: number;
  };
  provenance: {
    integrity_hash: string;
    previous_hash?: string;
    collection_method: "automated" | "manual" | "hybrid";
    source_module: string;
    timestamp: string;
  };
  notes?: string;
}

export interface ExportPayload {
  system_id: string;
  findings: ExportFinding[];
  evidence: ExportEvidence[];
}

export interface ExportResult {
  success: boolean;
  findings_created: number;
  findings_updated: number;
  findings_reopened: number;
  evidence_created: number;
  links_created: number;
  rejected: Array<{ source_id: string; reason: string }>;
  error?: string;
}

// ─── Control Mapping (CWE → NIST 800-53) ────────────────────────────────────

const CWE_TO_CONTROLS: Record<string, string[]> = {
  "CWE-79": ["SI-10", "SC-18"],       // XSS → Input Validation, Mobile Code
  "CWE-89": ["SI-10", "SC-4"],        // SQLi → Input Validation, Info in Shared Resources
  "CWE-22": ["AC-6", "CM-7"],         // Path Traversal → Least Privilege, Least Functionality
  "CWE-78": ["SI-10", "CM-7"],        // OS Command Injection
  "CWE-287": ["IA-2", "IA-5"],        // Improper Authentication
  "CWE-306": ["AC-3", "IA-2"],        // Missing Authentication
  "CWE-200": ["SC-28", "AC-4"],       // Information Exposure
  "CWE-522": ["IA-5", "SC-13"],       // Insufficiently Protected Credentials
  "CWE-611": ["SI-10", "SC-4"],       // XXE
  "CWE-918": ["SC-7", "AC-4"],        // SSRF
  "CWE-502": ["SI-10", "SC-4"],       // Deserialization
  "CWE-434": ["CM-7", "SI-10"],       // Unrestricted Upload
  "CWE-352": ["SC-23", "SI-10"],      // CSRF
  "CWE-269": ["AC-6", "CM-5"],        // Improper Privilege Management
  "CWE-732": ["AC-3", "AC-6"],        // Incorrect Permission Assignment
};

// Phishing campaign → compliance controls
const PHISHING_CONTROLS = {
  click_rate: ["AT-2"],       // Security Awareness Training
  report_rate: ["IR-4"],      // Incident Handling
  overall: ["CA-8"],          // Penetration Testing
};

// Detection validation → compliance controls
const DETECTION_CONTROLS = {
  siem_alert: ["SI-4", "IR-6"],    // System Monitoring, Incident Reporting
  edr_detection: ["SI-4"],          // System Monitoring
  rule_effectiveness: ["CA-7"],     // Continuous Monitoring
};

// ─── Export Functions ─────────────────────────────────────────────────────────

/**
 * Push findings and evidence to the compliance service.
 */
export async function pushToComplianceService(
  payload: ExportPayload,
  serviceToken: string
): Promise<ExportResult> {
  const complianceUrl = ENV.AC3_PLUS_COMPLIANCE_URL || "https://compliance.aceofcloud.io";

  try {
    const response = await fetch(`${complianceUrl}/api/findings/import`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${serviceToken}`,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(30000),
    });

    if (!response.ok) {
      const errorText = await response.text();
      return {
        success: false,
        findings_created: 0,
        findings_updated: 0,
        findings_reopened: 0,
        evidence_created: 0,
        links_created: 0,
        rejected: [],
        error: `HTTP ${response.status}: ${errorText}`,
      };
    }

    const result = await response.json();
    return { success: true, ...result };
  } catch (err: any) {
    return {
      success: false,
      findings_created: 0,
      findings_updated: 0,
      findings_reopened: 0,
      evidence_created: 0,
      links_created: 0,
      rejected: [],
      error: err.message || "Network error",
    };
  }
}

/**
 * Convert an AC3 engagement finding to the export format.
 */
export function mapFindingToExport(finding: {
  id: string | number;
  title: string;
  description: string;
  severity: string;
  cwe?: string;
  cve?: string;
  tool?: string;
  detectedAt: number;
  engagementId: number;
  systemRef?: string;
}): ExportFinding {
  // Map CWE to control IDs
  const controlIds: string[] = [];
  if (finding.cwe && CWE_TO_CONTROLS[finding.cwe]) {
    controlIds.push(...CWE_TO_CONTROLS[finding.cwe]);
  }

  // Normalize severity
  const severityMap: Record<string, "high" | "moderate" | "low"> = {
    critical: "high",
    high: "high",
    medium: "moderate",
    moderate: "moderate",
    low: "low",
    info: "low",
    informational: "low",
  };

  return {
    source_finding_id: `ac3-finding-${finding.engagementId}-${finding.id}`,
    system_ref: finding.systemRef || `engagement-${finding.engagementId}`,
    control_ids: controlIds,
    untagged_reason: controlIds.length === 0 ? "No CWE-to-control mapping available" : undefined,
    gap_statement: `${finding.title}: ${finding.description}`,
    severity: severityMap[finding.severity.toLowerCase()] || "moderate",
    finding_type: "condition",
    cve: finding.cve,
    cwe: finding.cwe,
    tool: finding.tool,
    source: "ac3",
    detected_at: new Date(finding.detectedAt).toISOString(),
  };
}

/**
 * Convert phishing campaign results to compliance evidence.
 */
export function mapPhishingToEvidence(campaign: {
  id: string | number;
  name: string;
  clickRate: number;
  reportRate: number;
  totalTargets: number;
  completedAt: number;
  engagementId: number;
  systemRef?: string;
}): ExportEvidence {
  const hash = crypto
    .createHash("sha256")
    .update(JSON.stringify(campaign))
    .digest("hex");

  return {
    source_evidence_id: `ac3-phishing-${campaign.engagementId}-${campaign.id}`,
    system_ref: campaign.systemRef || `engagement-${campaign.engagementId}`,
    control_ids: ["AT-2", "IR-4", "CA-8"],
    linked_source_finding_ids: [],
    file_name: `phishing_campaign_${campaign.id}_results.json`,
    artifact: {
      storage: "s3",
      path: `evidence/phishing/${campaign.engagementId}/${campaign.id}/results.json`,
      mime_type: "application/json",
      size: JSON.stringify(campaign).length,
    },
    provenance: {
      integrity_hash: hash,
      collection_method: "automated",
      source_module: "ac3-gophish-integration",
      timestamp: new Date(campaign.completedAt).toISOString(),
    },
    notes: `Phishing campaign "${campaign.name}": ${campaign.clickRate}% click rate, ${campaign.reportRate}% report rate (${campaign.totalTargets} targets)`,
  };
}

/**
 * Convert detection validation results to compliance evidence.
 */
export function mapDetectionToEvidence(validation: {
  id: string | number;
  ruleName: string;
  detected: boolean;
  detectionTime?: number;
  technique: string;
  engagementId: number;
  systemRef?: string;
}): ExportEvidence {
  const hash = crypto
    .createHash("sha256")
    .update(JSON.stringify(validation))
    .digest("hex");

  return {
    source_evidence_id: `ac3-detection-${validation.engagementId}-${validation.id}`,
    system_ref: validation.systemRef || `engagement-${validation.engagementId}`,
    control_ids: ["SI-4", "CA-7"],
    linked_source_finding_ids: [],
    file_name: `detection_validation_${validation.id}.json`,
    artifact: {
      storage: "s3",
      path: `evidence/detection/${validation.engagementId}/${validation.id}/result.json`,
      mime_type: "application/json",
    },
    provenance: {
      integrity_hash: hash,
      collection_method: "automated",
      source_module: "ac3-detection-validation-engine",
      timestamp: new Date().toISOString(),
    },
    notes: `Detection rule "${validation.ruleName}" for ${validation.technique}: ${validation.detected ? "DETECTED" : "MISSED"}${validation.detectionTime ? ` in ${validation.detectionTime}ms` : ""}`,
  };
}

/**
 * Generate a service-to-service JWT for AC3 → compliance API calls.
 */
export function generateServiceToken(orgId: string): string {
  const jwt = require("jsonwebtoken");
  const secret = ENV.AC3_PLUS_SERVICE_SECRET || ENV.JWT_SECRET;

  return jwt.sign(
    {
      sub: "ac3-service",
      org_id: orgId,
      iss: "ac3-platform",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300, // 5 min expiry
    },
    secret,
    { algorithm: "HS256" }
  );
}
