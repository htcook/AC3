import "./chunk-KFQGP6VL.js";

// server/lib/credential-rotation-alerts.ts
var DEFAULT_ROTATION_THRESHOLDS = {
  aws: 90,
  azure: 180,
  gcp: 90
};
var SEVERITY_THRESHOLDS = {
  critical: 3,
  // 3 days or less
  high: 7,
  // 7 days or less
  medium: 30,
  // 30 days or less
  low: 60
  // 60 days or less
};
function calculateDaysUntilExpiry(expiresAt) {
  if (!expiresAt) return null;
  const now = /* @__PURE__ */ new Date();
  const diffMs = expiresAt.getTime() - now.getTime();
  return Math.ceil(diffMs / (1e3 * 60 * 60 * 24));
}
function determineSeverity(daysUntilExpiry) {
  if (daysUntilExpiry === null) return "low";
  if (daysUntilExpiry <= SEVERITY_THRESHOLDS.critical) return "critical";
  if (daysUntilExpiry <= SEVERITY_THRESHOLDS.high) return "high";
  if (daysUntilExpiry <= SEVERITY_THRESHOLDS.medium) return "medium";
  return "low";
}
function determineAlertType(daysUntilExpiry, status, thresholdDays) {
  if (status === "error") return "validation_failed";
  if (daysUntilExpiry !== null && daysUntilExpiry <= 0) return "expired";
  if (daysUntilExpiry !== null && daysUntilExpiry <= thresholdDays) return "expiring_soon";
  return "rotation_due";
}
function generateAlertMessage(cred, alertType, daysUntilExpiry) {
  const providerLabel = cred.provider.toUpperCase();
  switch (alertType) {
    case "expired":
      return `[EXPIRED] ${providerLabel} credential "${cred.credentialName}" has expired. Immediate rotation required to restore access.`;
    case "expiring_soon":
      return `[EXPIRING] ${providerLabel} credential "${cred.credentialName}" expires in ${daysUntilExpiry} day(s). Schedule rotation before ${cred.expiresAt?.toISOString().split("T")[0] || "unknown"}.`;
    case "rotation_due":
      return `[ROTATION DUE] ${providerLabel} credential "${cred.credentialName}" has not been rotated within the recommended period. Consider generating new credentials.`;
    case "validation_failed":
      return `[VALIDATION FAILED] ${providerLabel} credential "${cred.credentialName}" failed validation. The credential may have been revoked or the service may be unreachable.`;
    default:
      return `Alert for ${providerLabel} credential "${cred.credentialName}".`;
  }
}
function checkCredentialAgainstRule(cred, rule) {
  if (!rule.isEnabled) return null;
  const daysUntilExpiry = calculateDaysUntilExpiry(cred.expiresAt);
  const alertType = determineAlertType(daysUntilExpiry, cred.status, rule.thresholdDays);
  if (alertType === "rotation_due" && daysUntilExpiry !== null && daysUntilExpiry > rule.thresholdDays) {
    return null;
  }
  if (daysUntilExpiry === null && cred.status !== "error") {
    if (cred.lastValidatedAt) {
      const daysSinceValidation = calculateDaysUntilExpiry(
        new Date(Date.now() + (DEFAULT_ROTATION_THRESHOLDS[cred.provider] || 90) * 24 * 60 * 60 * 1e3)
      );
      if (daysSinceValidation !== null && daysSinceValidation > rule.thresholdDays) {
        return null;
      }
    } else {
      return null;
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
    shouldNotify: rule.notifyOwner && (severity === "critical" || severity === "high")
  };
}
function batchCheckCredentials(credentials, rules) {
  const results = [];
  for (const rule of rules) {
    const cred = credentials.find((c) => c.credentialId === rule.credentialId);
    if (!cred) continue;
    const result = checkCredentialAgainstRule(cred, rule);
    if (result) results.push(result);
  }
  return results;
}
function formatNotificationContent(alerts, credentials) {
  const criticalCount = alerts.filter((a) => a.severity === "critical").length;
  const highCount = alerts.filter((a) => a.severity === "high").length;
  const title = criticalCount > 0 ? `\u{1F6A8} ${criticalCount} Critical Credential Alert(s)` : `\u26A0\uFE0F ${highCount} Credential Alert(s) Require Attention`;
  const lines = alerts.map((alert) => {
    const cred = credentials.find((c) => c.credentialId === alert.credentialId);
    const providerIcon = cred?.provider === "aws" ? "\u2601\uFE0F" : cred?.provider === "azure" ? "\u{1F537}" : "\u{1F7E2}";
    return `${providerIcon} [${alert.severity.toUpperCase()}] ${alert.message}`;
  });
  const content = [
    `Credential Rotation Alert Summary`,
    `\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500`,
    `Total Alerts: ${alerts.length}`,
    `Critical: ${criticalCount} | High: ${highCount} | Medium: ${alerts.filter((a) => a.severity === "medium").length}`,
    ``,
    ...lines,
    ``,
    `Please review and rotate affected credentials in the Cloud Credential Vault.`
  ].join("\n");
  return { title, content };
}
export {
  DEFAULT_ROTATION_THRESHOLDS,
  SEVERITY_THRESHOLDS,
  batchCheckCredentials,
  calculateDaysUntilExpiry,
  checkCredentialAgainstRule,
  determineAlertType,
  determineSeverity,
  formatNotificationContent,
  generateAlertMessage
};
