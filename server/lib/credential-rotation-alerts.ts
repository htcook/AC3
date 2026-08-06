/**
 * Credential Rotation Alert Engine
 * Scans cloud credentials for approaching expiry dates, generates alerts,
 * and dispatches notifications to the project owner.
 */

export interface AlertRule {
  id: number;
  credentialId: number;
  alertName: string;
  thresholdDays: number;
  isEnabled: boolean;
  notifyOwner: boolean;
}

export interface CredentialExpiryInfo {
  credentialId: number;
  credentialName: string;
  provider: string;
  expiresAt: Date | null;
  daysUntilExpiry: number | null;
  status: string;
  lastValidatedAt: Date | null;
}

export interface AlertCheckResult {
  ruleId: number;
  credentialId: number;
  alertType: "expiring_soon" | "expired" | "rotation_due" | "validation_failed";
  severity: "critical" | "high" | "medium" | "low";
  message: string;
  daysUntilExpiry: number | null;
  shouldNotify: boolean;
}

/**
 * Default rotation thresholds by provider
 * AWS access keys: 90 days recommended rotation
 * Azure client secrets: configurable, typically 90-180 days
 * GCP service account keys: 90 days recommended
 */
export const DEFAULT_ROTATION_THRESHOLDS: Record<string, number> = {
  aws: 90,
  azure: 180,
  gcp: 90,
};

/**
 * Severity thresholds (days until expiry)
 */
export const SEVERITY_THRESHOLDS = {
  critical: 3,   // 3 days or less
  high: 7,       // 7 days or less
  medium: 30,    // 30 days or less
  low: 60,       // 60 days or less
};

/**
 * Calculate days until a credential expires
 */
export function calculateDaysUntilExpiry(expiresAt: Date | null): number | null {
  if (!expiresAt) return null;
  const now = new Date();
  const diffMs = expiresAt.getTime() - now.getTime();
  return Math.ceil(diffMs / (1000 * 60 * 60 * 24));
}

/**
 * Determine alert severity based on days until expiry
 */
export function determineSeverity(daysUntilExpiry: number | null): "critical" | "high" | "medium" | "low" {
  if (daysUntilExpiry === null) return "low";
  if (daysUntilExpiry <= SEVERITY_THRESHOLDS.critical) return "critical";
  if (daysUntilExpiry <= SEVERITY_THRESHOLDS.high) return "high";
  if (daysUntilExpiry <= SEVERITY_THRESHOLDS.medium) return "medium";
  return "low";
}

/**
 * Determine alert type based on credential state
 */
export function determineAlertType(
  daysUntilExpiry: number | null,
  status: string,
  thresholdDays: number
): "expiring_soon" | "expired" | "rotation_due" | "validation_failed" {
  if (status === "error") return "validation_failed";
  if (daysUntilExpiry !== null && daysUntilExpiry <= 0) return "expired";
  if (daysUntilExpiry !== null && daysUntilExpiry <= thresholdDays) return "expiring_soon";
  return "rotation_due";
}

/**
 * Generate alert message based on credential info and alert type
 */
export function generateAlertMessage(
  cred: CredentialExpiryInfo,
  alertType: string,
  daysUntilExpiry: number | null
): string {
  const providerLabel = cred.provider.toUpperCase();

  switch (alertType) {
    case "expired":
      return `[EXPIRED] ${providerLabel} credential "${cred.credentialName}" has expired. ` +
        `Immediate rotation required to restore access.`;
    case "expiring_soon":
      return `[EXPIRING] ${providerLabel} credential "${cred.credentialName}" expires in ${daysUntilExpiry} day(s). ` +
        `Schedule rotation before ${cred.expiresAt?.toISOString().split("T")[0] || "unknown"}.`;
    case "rotation_due":
      return `[ROTATION DUE] ${providerLabel} credential "${cred.credentialName}" has not been rotated ` +
        `within the recommended period. Consider generating new credentials.`;
    case "validation_failed":
      return `[VALIDATION FAILED] ${providerLabel} credential "${cred.credentialName}" failed validation. ` +
        `The credential may have been revoked or the service may be unreachable.`;
    default:
      return `Alert for ${providerLabel} credential "${cred.credentialName}".`;
  }
}

/**
 * Check a single credential against an alert rule
 */
export function checkCredentialAgainstRule(
  cred: CredentialExpiryInfo,
  rule: AlertRule
): AlertCheckResult | null {
  if (!rule.isEnabled) return null;

  const daysUntilExpiry = calculateDaysUntilExpiry(cred.expiresAt);
  const alertType = determineAlertType(daysUntilExpiry, cred.status, rule.thresholdDays);

  // Only generate alert if credential is actually problematic
  if (alertType === "rotation_due" && daysUntilExpiry !== null && daysUntilExpiry > rule.thresholdDays) {
    return null; // Not yet due for rotation
  }

  // For credentials without expiry, check if rotation is recommended based on last validation
  if (daysUntilExpiry === null && cred.status !== "error") {
    if (cred.lastValidatedAt) {
      const daysSinceValidation = calculateDaysUntilExpiry(
        new Date(Date.now() + (DEFAULT_ROTATION_THRESHOLDS[cred.provider] || 90) * 24 * 60 * 60 * 1000)
      );
      if (daysSinceValidation !== null && daysSinceValidation > rule.thresholdDays) {
        return null; // Not yet due
      }
    } else {
      return null; // No expiry and no validation history, skip
    }
  }

  const severity = determineSeverity(daysUntilExpiry);
  const message = generateAlertMessage(cred, alertType, daysUntilExpiry);

  return {
    ruleId: rule.id,
    credentialId: cred.credentialId,
    alertType,
    severity,
    message,
    daysUntilExpiry,
    shouldNotify: rule.notifyOwner && (severity === "critical" || severity === "high"),
  };
}

/**
 * Batch check all credentials against all rules
 */
export function batchCheckCredentials(
  credentials: CredentialExpiryInfo[],
  rules: AlertRule[]
): AlertCheckResult[] {
  const results: AlertCheckResult[] = [];

  for (const rule of rules) {
    const cred = credentials.find(c => c.credentialId === rule.credentialId);
    if (!cred) continue;

    const result = checkCredentialAgainstRule(cred, rule);
    if (result) results.push(result);
  }

  return results;
}

/**
 * Format notification content for owner alerts
 */
export function formatNotificationContent(alerts: AlertCheckResult[], credentials: CredentialExpiryInfo[]): {
  title: string;
  content: string;
} {
  const criticalCount = alerts.filter(a => a.severity === "critical").length;
  const highCount = alerts.filter(a => a.severity === "high").length;

  const title = criticalCount > 0
    ? `🚨 ${criticalCount} Critical Credential Alert(s)`
    : `⚠️ ${highCount} Credential Alert(s) Require Attention`;

  const lines = alerts.map(alert => {
    const cred = credentials.find(c => c.credentialId === alert.credentialId);
    const providerIcon = cred?.provider === "aws" ? "☁️" : cred?.provider === "azure" ? "🔷" : "🟢";
    return `${providerIcon} [${alert.severity.toUpperCase()}] ${alert.message}`;
  });

  const content = [
    `Credential Rotation Alert Summary`,
    `─────────────────────────────────`,
    `Total Alerts: ${alerts.length}`,
    `Critical: ${criticalCount} | High: ${highCount} | Medium: ${alerts.filter(a => a.severity === "medium").length}`,
    ``,
    ...lines,
    ``,
    `Please review and rotate affected credentials in the Cloud Credential Vault.`,
  ].join("\n");

  return { title, content };
}
