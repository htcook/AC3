/**
 * MSSP Cross-Tenant Analytics & Billing Module
 * ═══════════════════════════════════════════════════════════════
 * Provides MSSP operators with cross-tenant visibility:
 *
 *   1. Cross-Tenant Analytics — aggregate security posture, engagement
 *      activity, and vulnerability trends across all managed tenants
 *   2. Billing Metering — track usage per tenant for billing purposes
 *      (scans, LLM calls, storage, agent deployments)
 *   3. SLA Monitoring — track response times and compliance deadlines
 *   4. Tenant Health Scoring — composite risk score per tenant
 */

// ═══════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════

export interface TenantSecurityPosture {
  tenantId: number;
  tenantName: string;
  riskScore: number; // 0-100, higher = more risk
  riskLevel: "critical" | "high" | "medium" | "low";
  openVulnerabilities: { critical: number; high: number; medium: number; low: number };
  lastEngagement: number | null;
  lastScan: number | null;
  agentsDeployed: number;
  agentsActive: number;
  owaspCoverageScore: number; // 0-100
  complianceStatus: "compliant" | "at_risk" | "non_compliant";
  daysSinceLastAssessment: number | null;
}

export interface CrossTenantSummary {
  totalTenants: number;
  activeTenants: number;
  totalEngagements: number;
  totalScans: number;
  avgRiskScore: number;
  riskDistribution: { critical: number; high: number; medium: number; low: number };
  totalOpenVulns: number;
  avgOwaspCoverage: number;
  tenantsNeedingAttention: TenantSecurityPosture[];
  topVulnerabilityTypes: Array<{ type: string; count: number; affectedTenants: number }>;
  trendDirection: "improving" | "stable" | "declining";
  generatedAt: number;
}

export interface UsageMeter {
  tenantId: number;
  tenantName: string;
  period: string; // YYYY-MM
  scansRun: number;
  llmCallsMade: number;
  llmTokensUsed: number;
  storageUsedMb: number;
  agentHours: number;
  engagementsCreated: number;
  reportsGenerated: number;
  apiCallsMade: number;
  estimatedCostUsd: number;
}

export interface BillingSummary {
  period: string;
  totalRevenue: number;
  tenantBreakdown: UsageMeter[];
  topConsumers: Array<{ tenantId: number; tenantName: string; costUsd: number; percentOfTotal: number }>;
  usageTrend: Array<{ period: string; totalCost: number; tenantCount: number }>;
}

export interface SLAStatus {
  tenantId: number;
  tenantName: string;
  slaType: "response_time" | "assessment_frequency" | "remediation_deadline" | "report_delivery";
  target: string;
  actual: string;
  met: boolean;
  dueDate: number | null;
  daysRemaining: number | null;
}

// ═══════════════════════════════════════════════════════════════
// §2 — PRICING TIERS
// ═══════════════════════════════════════════════════════════════

export interface PricingTier {
  id: string;
  name: string;
  description: string;
  monthlyBase: number;
  includedScans: number;
  includedLlmCalls: number;
  includedAgents: number;
  includedStorageMb: number;
  overageScanCost: number;
  overageLlmCallCost: number;
  overageAgentHourCost: number;
  overageStorageMbCost: number;
  features: string[];
}

export const PRICING_TIERS: PricingTier[] = [
  {
    id: "starter",
    name: "Starter",
    description: "For small teams getting started with security assessments",
    monthlyBase: 499,
    includedScans: 50,
    includedLlmCalls: 500,
    includedAgents: 5,
    includedStorageMb: 1024,
    overageScanCost: 5,
    overageLlmCallCost: 0.10,
    overageAgentHourCost: 0.50,
    overageStorageMbCost: 0.05,
    features: ["Basic scanning", "Vulnerability reports", "OWASP coverage", "Email support"],
  },
  {
    id: "professional",
    name: "Professional",
    description: "For growing security teams with advanced needs",
    monthlyBase: 1499,
    includedScans: 200,
    includedLlmCalls: 2000,
    includedAgents: 20,
    includedStorageMb: 5120,
    overageScanCost: 3,
    overageLlmCallCost: 0.08,
    overageAgentHourCost: 0.35,
    overageStorageMbCost: 0.03,
    features: ["All Starter features", "LLM-powered analysis", "Threat group intelligence", "Agent deployment", "SIEM integration", "Priority support"],
  },
  {
    id: "enterprise",
    name: "Enterprise",
    description: "For large organizations and MSSPs managing multiple clients",
    monthlyBase: 4999,
    includedScans: 1000,
    includedLlmCalls: 10000,
    includedAgents: 100,
    includedStorageMb: 25600,
    overageScanCost: 2,
    overageLlmCallCost: 0.05,
    overageAgentHourCost: 0.25,
    overageStorageMbCost: 0.02,
    features: ["All Professional features", "Multi-tenant management", "Cross-tenant analytics", "Custom compliance frameworks", "Data exfiltration simulation", "Cloud workload testing", "Dedicated support", "SLA guarantees"],
  },
  {
    id: "government",
    name: "Government / FedRAMP",
    description: "For government agencies and defense contractors requiring FedRAMP compliance",
    monthlyBase: 9999,
    includedScans: 5000,
    includedLlmCalls: 50000,
    includedAgents: 500,
    includedStorageMb: 102400,
    overageScanCost: 1,
    overageLlmCallCost: 0.03,
    overageAgentHourCost: 0.15,
    overageStorageMbCost: 0.01,
    features: ["All Enterprise features", "FedRAMP compliance tracking", "CMMC assessment support", "FIPS 140-2 validated crypto", "Air-gapped deployment option", "Dedicated infrastructure", "24/7 support with SLA"],
  },
];

export function getPricingTier(tierId: string): PricingTier | undefined {
  return PRICING_TIERS.find(t => t.id === tierId);
}

// ═══════════════════════════════════════════════════════════════
// §3 — USAGE METERING
// ═══════════════════════════════════════════════════════════════

/**
 * Calculate the estimated cost for a tenant's usage in a given period.
 */
export function calculateTenantCost(usage: Omit<UsageMeter, "estimatedCostUsd">, tierId: string): number {
  const tier = getPricingTier(tierId);
  if (!tier) return 0;

  let cost = tier.monthlyBase;

  // Overage calculations
  const scanOverage = Math.max(0, usage.scansRun - tier.includedScans);
  cost += scanOverage * tier.overageScanCost;

  const llmOverage = Math.max(0, usage.llmCallsMade - tier.includedLlmCalls);
  cost += llmOverage * tier.overageLlmCallCost;

  const agentOverage = Math.max(0, usage.agentHours - (tier.includedAgents * 720)); // 720 hours/month
  cost += agentOverage * tier.overageAgentHourCost;

  const storageOverage = Math.max(0, usage.storageUsedMb - tier.includedStorageMb);
  cost += storageOverage * tier.overageStorageMbCost;

  return Math.round(cost * 100) / 100;
}

// ═══════════════════════════════════════════════════════════════
// §4 — RISK SCORING
// ═══════════════════════════════════════════════════════════════

export interface RiskFactors {
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
  lowVulns: number;
  daysSinceLastAssessment: number | null;
  owaspCoveragePercent: number;
  agentCoverage: number; // 0-1, ratio of active agents to expected
  complianceGaps: number;
  exposedServices: number;
  unpatched: number;
}

/**
 * Calculate a composite risk score (0-100) from multiple risk factors.
 * Higher score = higher risk.
 */
export function calculateRiskScore(factors: RiskFactors): number {
  let score = 0;

  // Vulnerability severity weighting (max 40 points)
  score += Math.min(20, factors.criticalVulns * 5);
  score += Math.min(10, factors.highVulns * 2);
  score += Math.min(7, factors.mediumVulns * 0.5);
  score += Math.min(3, factors.lowVulns * 0.1);

  // Assessment recency (max 20 points)
  if (factors.daysSinceLastAssessment === null) {
    score += 20; // Never assessed = maximum risk
  } else if (factors.daysSinceLastAssessment > 90) {
    score += 15;
  } else if (factors.daysSinceLastAssessment > 30) {
    score += 8;
  } else if (factors.daysSinceLastAssessment > 7) {
    score += 3;
  }

  // OWASP coverage gap (max 15 points)
  score += Math.max(0, 15 - (factors.owaspCoveragePercent / 100 * 15));

  // Agent coverage gap (max 10 points)
  score += Math.max(0, 10 - (factors.agentCoverage * 10));

  // Compliance gaps (max 10 points)
  score += Math.min(10, factors.complianceGaps * 2);

  // Exposed services (max 5 points)
  score += Math.min(5, factors.exposedServices * 0.5);

  return Math.min(100, Math.round(score));
}

export function getRiskLevel(score: number): "critical" | "high" | "medium" | "low" {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

// ═══════════════════════════════════════════════════════════════
// §5 — CROSS-TENANT ANALYTICS BUILDER
// ═══════════════════════════════════════════════════════════════

/**
 * Build a cross-tenant security summary from individual tenant postures.
 */
export function buildCrossTenantSummary(tenants: TenantSecurityPosture[]): CrossTenantSummary {
  const activeTenants = tenants.filter(t => t.lastEngagement !== null || t.agentsActive > 0);

  const riskDistribution = { critical: 0, high: 0, medium: 0, low: 0 };
  let totalRiskScore = 0;
  let totalOwaspCoverage = 0;
  let totalOpenVulns = 0;

  for (const t of tenants) {
    riskDistribution[t.riskLevel]++;
    totalRiskScore += t.riskScore;
    totalOwaspCoverage += t.owaspCoverageScore;
    totalOpenVulns += t.openVulnerabilities.critical + t.openVulnerabilities.high + t.openVulnerabilities.medium + t.openVulnerabilities.low;
  }

  const avgRiskScore = tenants.length > 0 ? Math.round(totalRiskScore / tenants.length) : 0;
  const avgOwaspCoverage = tenants.length > 0 ? Math.round(totalOwaspCoverage / tenants.length) : 0;

  // Tenants needing attention: critical/high risk or non-compliant
  const tenantsNeedingAttention = tenants
    .filter(t => t.riskLevel === "critical" || t.riskLevel === "high" || t.complianceStatus === "non_compliant")
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 10);

  return {
    totalTenants: tenants.length,
    activeTenants: activeTenants.length,
    totalEngagements: 0, // Populated from DB in router
    totalScans: 0, // Populated from DB in router
    avgRiskScore,
    riskDistribution,
    totalOpenVulns,
    avgOwaspCoverage,
    tenantsNeedingAttention,
    topVulnerabilityTypes: [], // Populated from DB in router
    trendDirection: avgRiskScore > 60 ? "declining" : avgRiskScore > 35 ? "stable" : "improving",
    generatedAt: Date.now(),
  };
}

// ═══════════════════════════════════════════════════════════════
// §6 — SLA MONITORING
// ═══════════════════════════════════════════════════════════════

export interface SLADefinition {
  type: SLAStatus["slaType"];
  name: string;
  description: string;
  defaultTarget: string;
  unit: string;
}

export const SLA_DEFINITIONS: SLADefinition[] = [
  { type: "response_time", name: "Incident Response Time", description: "Maximum time to acknowledge and begin responding to a critical finding", defaultTarget: "4 hours", unit: "hours" },
  { type: "assessment_frequency", name: "Assessment Frequency", description: "Maximum days between security assessments", defaultTarget: "30 days", unit: "days" },
  { type: "remediation_deadline", name: "Remediation Deadline", description: "Maximum days to remediate critical vulnerabilities", defaultTarget: "14 days", unit: "days" },
  { type: "report_delivery", name: "Report Delivery", description: "Maximum days to deliver post-engagement report", defaultTarget: "5 days", unit: "days" },
];

/**
 * Check SLA compliance for a tenant based on their activity.
 */
export function checkSLACompliance(
  tenantId: number,
  tenantName: string,
  lastAssessmentDate: number | null,
  lastReportDate: number | null,
  openCriticalFindings: Array<{ foundAt: number; resolvedAt: number | null }>,
  slaTargets?: Partial<Record<SLAStatus["slaType"], number>>
): SLAStatus[] {
  const now = Date.now();
  const results: SLAStatus[] = [];

  // Assessment frequency SLA
  const assessmentTargetDays = slaTargets?.assessment_frequency || 30;
  const daysSinceAssessment = lastAssessmentDate ? Math.floor((now - lastAssessmentDate) / 86400000) : null;
  results.push({
    tenantId,
    tenantName,
    slaType: "assessment_frequency",
    target: `${assessmentTargetDays} days`,
    actual: daysSinceAssessment !== null ? `${daysSinceAssessment} days` : "Never assessed",
    met: daysSinceAssessment !== null && daysSinceAssessment <= assessmentTargetDays,
    dueDate: lastAssessmentDate ? lastAssessmentDate + assessmentTargetDays * 86400000 : null,
    daysRemaining: daysSinceAssessment !== null ? Math.max(0, assessmentTargetDays - daysSinceAssessment) : null,
  });

  // Report delivery SLA
  const reportTargetDays = slaTargets?.report_delivery || 5;
  const daysSinceReport = lastReportDate ? Math.floor((now - lastReportDate) / 86400000) : null;
  results.push({
    tenantId,
    tenantName,
    slaType: "report_delivery",
    target: `${reportTargetDays} days`,
    actual: daysSinceReport !== null ? `${daysSinceReport} days since last report` : "No reports",
    met: true, // Assume met unless we have pending reports
    dueDate: null,
    daysRemaining: null,
  });

  // Remediation deadline SLA
  const remediationTargetDays = slaTargets?.remediation_deadline || 14;
  const unresolvedCritical = openCriticalFindings.filter(f => !f.resolvedAt);
  const oldestUnresolved = unresolvedCritical.length > 0
    ? Math.min(...unresolvedCritical.map(f => f.foundAt))
    : null;
  const daysSinceOldest = oldestUnresolved ? Math.floor((now - oldestUnresolved) / 86400000) : null;

  results.push({
    tenantId,
    tenantName,
    slaType: "remediation_deadline",
    target: `${remediationTargetDays} days`,
    actual: unresolvedCritical.length > 0
      ? `${unresolvedCritical.length} unresolved critical findings (oldest: ${daysSinceOldest} days)`
      : "No open critical findings",
    met: daysSinceOldest === null || daysSinceOldest <= remediationTargetDays,
    dueDate: oldestUnresolved ? oldestUnresolved + remediationTargetDays * 86400000 : null,
    daysRemaining: daysSinceOldest !== null ? Math.max(0, remediationTargetDays - daysSinceOldest) : null,
  });

  return results;
}

// ═══════════════════════════════════════════════════════════════
// §7 — EXECUTIVE REPORT DATA
// ═══════════════════════════════════════════════════════════════

export interface MSSPExecutiveReport {
  title: string;
  period: string;
  generatedAt: number;
  summary: CrossTenantSummary;
  billing: BillingSummary | null;
  slaCompliance: {
    totalChecks: number;
    metCount: number;
    complianceRate: number;
    violations: SLAStatus[];
  };
  recommendations: string[];
}

/**
 * Generate executive report data for MSSP leadership.
 */
export function buildExecutiveReport(
  summary: CrossTenantSummary,
  billing: BillingSummary | null,
  slaStatuses: SLAStatus[],
  period: string,
): MSSPExecutiveReport {
  const violations = slaStatuses.filter(s => !s.met);
  const complianceRate = slaStatuses.length > 0
    ? Math.round((slaStatuses.filter(s => s.met).length / slaStatuses.length) * 100)
    : 100;

  const recommendations: string[] = [];

  if (summary.riskDistribution.critical > 0) {
    recommendations.push(`${summary.riskDistribution.critical} tenant(s) are at CRITICAL risk level — prioritize immediate assessment and remediation.`);
  }
  if (summary.avgOwaspCoverage < 60) {
    recommendations.push(`Average OWASP coverage is ${summary.avgOwaspCoverage}% — recommend expanding scan tool coverage to close testing gaps.`);
  }
  if (violations.length > 0) {
    recommendations.push(`${violations.length} SLA violation(s) detected — review remediation timelines and assessment schedules.`);
  }
  if (summary.tenantsNeedingAttention.length > 3) {
    recommendations.push(`${summary.tenantsNeedingAttention.length} tenants need attention — consider increasing assessment frequency for high-risk clients.`);
  }
  if (summary.trendDirection === "declining") {
    recommendations.push("Overall security posture is declining — schedule executive review to discuss resource allocation.");
  }
  if (recommendations.length === 0) {
    recommendations.push("All metrics within acceptable ranges. Continue current assessment cadence and monitoring.");
  }

  return {
    title: `AC3 MSSP Executive Report — ${period}`,
    period,
    generatedAt: Date.now(),
    summary,
    billing,
    slaCompliance: {
      totalChecks: slaStatuses.length,
      metCount: slaStatuses.filter(s => s.met).length,
      complianceRate,
      violations,
    },
    recommendations,
  };
}
