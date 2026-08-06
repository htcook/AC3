/**
 * Data Retention Policy Engine — P2 Gap Remediation
 * 
 * Implements configurable data retention policies for compliance with
 * federal data handling requirements (FedRAMP, NIST 800-53 SI-12, AU-11).
 * 
 * Features:
 * - Policy definitions per data category
 * - Retention period enforcement
 * - Automated purge scheduling
 * - Legal hold support
 * - Audit trail for all retention actions
 * - Compliance reporting
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type DataCategory =
  | "engagement_data"
  | "scan_results"
  | "evidence"
  | "credentials"
  | "activity_logs"
  | "chat_messages"
  | "threat_intel"
  | "user_sessions"
  | "platform_errors"
  | "report_artifacts";

export type RetentionAction = "archive" | "anonymize" | "delete" | "legal_hold";

export interface RetentionPolicy {
  id: string;
  category: DataCategory;
  displayName: string;
  description: string;
  retentionDays: number;
  archiveAfterDays: number | null;   // Move to cold storage before deletion
  action: RetentionAction;
  complianceReference: string;       // NIST control ID
  enabled: boolean;
  legalHoldOverride: boolean;        // If true, legal hold prevents action
}

export interface RetentionAuditEntry {
  id: string;
  policyId: string;
  category: DataCategory;
  action: RetentionAction;
  recordsAffected: number;
  executedAt: number;
  executedBy: string;
  details: string;
}

export interface RetentionReport {
  generatedAt: number;
  policies: Array<RetentionPolicy & {
    recordsSubject: number;
    oldestRecord: number | null;
    nextPurgeDate: number | null;
    legalHoldActive: boolean;
  }>;
  recentActions: RetentionAuditEntry[];
  complianceStatus: "compliant" | "warning" | "non_compliant";
  warnings: string[];
}

// ─── Default Policies ───────────────────────────────────────────────────────

export const DEFAULT_RETENTION_POLICIES: RetentionPolicy[] = [
  {
    id: "RET-ENG",
    category: "engagement_data",
    displayName: "Engagement Records",
    description: "Penetration test engagement data including scope, ROE, and results",
    retentionDays: 2555,           // 7 years (federal record retention)
    archiveAfterDays: 365,
    action: "archive",
    complianceReference: "NIST SI-12, AU-11",
    enabled: true,
    legalHoldOverride: true,
  },
  {
    id: "RET-SCAN",
    category: "scan_results",
    displayName: "Scan Results",
    description: "Vulnerability scan outputs, DAST/SAST results, and observation data",
    retentionDays: 1095,           // 3 years
    archiveAfterDays: 180,
    action: "archive",
    complianceReference: "NIST SI-12",
    enabled: true,
    legalHoldOverride: true,
  },
  {
    id: "RET-EVID",
    category: "evidence",
    displayName: "Evidence Chain of Custody",
    description: "KSI evidence, integrity hashes, and chain of custody records",
    retentionDays: 2555,           // 7 years (audit evidence)
    archiveAfterDays: 365,
    action: "archive",
    complianceReference: "NIST AU-11, SA-11",
    enabled: true,
    legalHoldOverride: true,
  },
  {
    id: "RET-CRED",
    category: "credentials",
    displayName: "Stored Credentials",
    description: "Encrypted credentials used during engagements",
    retentionDays: 90,             // Purge after engagement + buffer
    archiveAfterDays: null,
    action: "delete",
    complianceReference: "NIST IA-5, SC-28",
    enabled: true,
    legalHoldOverride: false,      // Credentials should always be purged
  },
  {
    id: "RET-LOG",
    category: "activity_logs",
    displayName: "Activity Logs",
    description: "User activity logs, audit trail, and system events",
    retentionDays: 1095,           // 3 years
    archiveAfterDays: 365,
    action: "archive",
    complianceReference: "NIST AU-11",
    enabled: true,
    legalHoldOverride: true,
  },
  {
    id: "RET-CHAT",
    category: "chat_messages",
    displayName: "Chat History",
    description: "AI chat sessions and message history",
    retentionDays: 365,            // 1 year
    archiveAfterDays: 180,
    action: "delete",
    complianceReference: "NIST SI-12",
    enabled: true,
    legalHoldOverride: true,
  },
  {
    id: "RET-INTEL",
    category: "threat_intel",
    displayName: "Threat Intelligence",
    description: "Threat intel feeds, IOCs, and enrichment data",
    retentionDays: 730,            // 2 years
    archiveAfterDays: 365,
    action: "archive",
    complianceReference: "NIST SI-5, RA-5",
    enabled: true,
    legalHoldOverride: true,
  },
  {
    id: "RET-SESS",
    category: "user_sessions",
    displayName: "User Sessions",
    description: "Session tokens, device fingerprints, and login records",
    retentionDays: 90,
    archiveAfterDays: null,
    action: "delete",
    complianceReference: "NIST AC-12, SC-23",
    enabled: true,
    legalHoldOverride: false,
  },
  {
    id: "RET-ERR",
    category: "platform_errors",
    displayName: "Platform Errors",
    description: "System error logs and crash reports",
    retentionDays: 180,
    archiveAfterDays: null,
    action: "delete",
    complianceReference: "NIST SI-11",
    enabled: true,
    legalHoldOverride: false,
  },
  {
    id: "RET-RPT",
    category: "report_artifacts",
    displayName: "Report Artifacts",
    description: "Generated reports, OSCAL exports, and compliance documents",
    retentionDays: 2555,           // 7 years
    archiveAfterDays: 365,
    action: "archive",
    complianceReference: "NIST AU-11, CA-7",
    enabled: true,
    legalHoldOverride: true,
  },
];

// ─── Policy Engine ──────────────────────────────────────────────────────────

/**
 * Get records that are subject to retention action based on policy.
 */
export function getRecordsSubjectToRetention(
  policy: RetentionPolicy,
  now: number = Date.now()
): { cutoffDate: number; archiveCutoff: number | null } {
  const MS_PER_DAY = 24 * 60 * 60 * 1000;
  const cutoffDate = now - (policy.retentionDays * MS_PER_DAY);
  const archiveCutoff = policy.archiveAfterDays
    ? now - (policy.archiveAfterDays * MS_PER_DAY)
    : null;

  return { cutoffDate, archiveCutoff };
}

/**
 * Check if a legal hold is active for a given category.
 */
export function isLegalHoldActive(
  policy: RetentionPolicy,
  activeLegalHolds: string[]
): boolean {
  return policy.legalHoldOverride && activeLegalHolds.includes(policy.category);
}

/**
 * Determine the effective action considering legal holds.
 */
export function getEffectiveAction(
  policy: RetentionPolicy,
  activeLegalHolds: string[]
): RetentionAction {
  if (isLegalHoldActive(policy, activeLegalHolds)) {
    return "legal_hold";
  }
  return policy.action;
}

/**
 * Validate that all policies meet minimum federal retention requirements.
 */
export function validatePolicies(
  policies: RetentionPolicy[]
): { valid: boolean; warnings: string[] } {
  const warnings: string[] = [];

  // Federal minimums
  const FEDERAL_MINIMUMS: Partial<Record<DataCategory, number>> = {
    engagement_data: 1095,    // 3 years minimum
    evidence: 1095,
    activity_logs: 365,
    report_artifacts: 1095,
  };

  for (const policy of policies) {
    const minimum = FEDERAL_MINIMUMS[policy.category];
    if (minimum && policy.retentionDays < minimum) {
      warnings.push(
        `Policy "${policy.displayName}" retention of ${policy.retentionDays} days is below federal minimum of ${minimum} days`
      );
    }

    // Warn if archive is after retention
    if (policy.archiveAfterDays && policy.archiveAfterDays >= policy.retentionDays) {
      warnings.push(
        `Policy "${policy.displayName}" archive date (${policy.archiveAfterDays}d) is after retention date (${policy.retentionDays}d)`
      );
    }
  }

  return {
    valid: warnings.length === 0,
    warnings,
  };
}

/**
 * Generate a compliance report for all retention policies.
 */
export function generateRetentionReport(
  policies: RetentionPolicy[],
  recordCounts: Map<DataCategory, { count: number; oldest: number | null }>,
  recentActions: RetentionAuditEntry[],
  activeLegalHolds: string[]
): RetentionReport {
  const now = Date.now();
  const MS_PER_DAY = 24 * 60 * 60 * 1000;
  const validation = validatePolicies(policies);

  const enrichedPolicies = policies.map(policy => {
    const counts = recordCounts.get(policy.category) || { count: 0, oldest: null };
    const { cutoffDate } = getRecordsSubjectToRetention(policy, now);
    const legalHoldActive = isLegalHoldActive(policy, activeLegalHolds);

    let nextPurgeDate: number | null = null;
    if (counts.oldest && policy.enabled && !legalHoldActive) {
      nextPurgeDate = counts.oldest + (policy.retentionDays * MS_PER_DAY);
    }

    return {
      ...policy,
      recordsSubject: counts.count,
      oldestRecord: counts.oldest,
      nextPurgeDate,
      legalHoldActive,
    };
  });

  // Determine overall compliance status
  let complianceStatus: "compliant" | "warning" | "non_compliant" = "compliant";
  if (!validation.valid) complianceStatus = "warning";
  if (policies.some(p => !p.enabled && ["engagement_data", "evidence", "activity_logs"].includes(p.category))) {
    complianceStatus = "non_compliant";
  }

  return {
    generatedAt: now,
    policies: enrichedPolicies,
    recentActions,
    complianceStatus,
    warnings: validation.warnings,
  };
}
