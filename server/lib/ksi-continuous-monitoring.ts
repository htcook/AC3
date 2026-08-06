/**
 * KSI Continuous Monitoring — P2 Gap Remediation
 * 
 * Implements automated continuous monitoring for FedRAMP Key Security Indicators.
 * Tracks compliance drift, generates alerts when KSIs fall out of compliance,
 * and produces monitoring reports.
 * 
 * Features:
 * - Compliance drift detection (score changes over time)
 * - Automated re-validation scheduling
 * - Alert generation for compliance degradation
 * - Trend analysis and forecasting
 * - Monitoring dashboard data aggregation
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type MonitoringStatus = "compliant" | "degraded" | "non_compliant" | "unknown";
export type AlertSeverity = "critical" | "high" | "medium" | "low";
export type DriftDirection = "improving" | "stable" | "degrading";

export interface KsiMonitoringState {
  ksiId: string;
  currentScore: number;        // 0-100
  previousScore: number;
  status: MonitoringStatus;
  driftDirection: DriftDirection;
  driftRate: number;           // Score change per day
  lastValidated: number;
  nextValidation: number;
  consecutiveFailures: number;
  alerts: MonitoringAlert[];
}

export interface MonitoringAlert {
  id: string;
  ksiId: string;
  severity: AlertSeverity;
  title: string;
  description: string;
  triggeredAt: number;
  acknowledged: boolean;
  resolvedAt: number | null;
}

export interface MonitoringDashboard {
  overallComplianceScore: number;
  totalKsis: number;
  compliantCount: number;
  degradedCount: number;
  nonCompliantCount: number;
  unknownCount: number;
  recentAlerts: MonitoringAlert[];
  trendData: TrendPoint[];
  nextScheduledValidations: Array<{ ksiId: string; scheduledAt: number }>;
}

export interface TrendPoint {
  timestamp: number;
  complianceScore: number;
  compliantCount: number;
  totalKsis: number;
}

// ─── Compliance Scoring ─────────────────────────────────────────────────────

/**
 * Calculate compliance score for a KSI based on validation results.
 */
export function calculateKsiScore(params: {
  hasEvidence: boolean;
  evidenceAge: number;       // Days since last evidence
  validationPassed: boolean;
  validationAge: number;     // Days since last validation
  coverageStatus: string;
  frequency: string;
}): number {
  let score = 0;

  // Evidence exists (30 points)
  if (params.hasEvidence) {
    score += 30;
    // Freshness bonus (up to 10 points)
    if (params.evidenceAge <= 7) score += 10;
    else if (params.evidenceAge <= 30) score += 7;
    else if (params.evidenceAge <= 90) score += 3;
  }

  // Validation passed (40 points)
  if (params.validationPassed) {
    score += 40;
    // Freshness bonus (up to 10 points)
    if (params.validationAge <= 7) score += 10;
    else if (params.validationAge <= 30) score += 7;
    else if (params.validationAge <= 90) score += 3;
  }

  // Coverage status (10 points)
  if (params.coverageStatus === "direct") score += 10;
  else if (params.coverageStatus === "supporting") score += 5;

  return Math.min(100, score);
}

/**
 * Determine monitoring status from score.
 */
export function getMonitoringStatus(score: number): MonitoringStatus {
  if (score >= 80) return "compliant";
  if (score >= 50) return "degraded";
  if (score > 0) return "non_compliant";
  return "unknown";
}

/**
 * Calculate drift direction from score history.
 */
export function calculateDrift(
  currentScore: number,
  previousScore: number,
  daysBetween: number
): { direction: DriftDirection; rate: number } {
  if (daysBetween === 0) return { direction: "stable", rate: 0 };

  const diff = currentScore - previousScore;
  const rate = diff / daysBetween;

  if (Math.abs(diff) < 2) return { direction: "stable", rate: 0 };
  return {
    direction: diff > 0 ? "improving" : "degrading",
    rate: Math.round(rate * 100) / 100,
  };
}

// ─── Alert Generation ───────────────────────────────────────────────────────

/**
 * Generate alerts based on monitoring state changes.
 */
export function generateAlerts(
  state: KsiMonitoringState,
  previousState?: KsiMonitoringState
): MonitoringAlert[] {
  const alerts: MonitoringAlert[] = [];
  const now = Date.now();
  const alertId = () => `MON-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`;

  // Critical: Score dropped below 50 (non-compliant)
  if (state.currentScore < 50 && (!previousState || previousState.currentScore >= 50)) {
    alerts.push({
      id: alertId(),
      ksiId: state.ksiId,
      severity: "critical",
      title: `KSI ${state.ksiId} fell below compliance threshold`,
      description: `Score dropped from ${previousState?.currentScore || "N/A"} to ${state.currentScore}. Immediate remediation required.`,
      triggeredAt: now,
      acknowledged: false,
      resolvedAt: null,
    });
  }

  // High: Score degrading rapidly (>5 points/day)
  if (state.driftRate < -5) {
    alerts.push({
      id: alertId(),
      ksiId: state.ksiId,
      severity: "high",
      title: `KSI ${state.ksiId} compliance rapidly degrading`,
      description: `Score declining at ${Math.abs(state.driftRate)} points/day. Current score: ${state.currentScore}.`,
      triggeredAt: now,
      acknowledged: false,
      resolvedAt: null,
    });
  }

  // Medium: Validation overdue
  if (state.nextValidation < now) {
    const overdueDays = Math.round((now - state.nextValidation) / (24 * 60 * 60 * 1000));
    alerts.push({
      id: alertId(),
      ksiId: state.ksiId,
      severity: "medium",
      title: `KSI ${state.ksiId} validation overdue by ${overdueDays} days`,
      description: `Last validated ${new Date(state.lastValidated).toISOString()}. Re-validation was due ${new Date(state.nextValidation).toISOString()}.`,
      triggeredAt: now,
      acknowledged: false,
      resolvedAt: null,
    });
  }

  // High: Consecutive failures
  if (state.consecutiveFailures >= 3) {
    alerts.push({
      id: alertId(),
      ksiId: state.ksiId,
      severity: "high",
      title: `KSI ${state.ksiId} has ${state.consecutiveFailures} consecutive validation failures`,
      description: `This KSI has failed validation ${state.consecutiveFailures} times in a row. Manual investigation recommended.`,
      triggeredAt: now,
      acknowledged: false,
      resolvedAt: null,
    });
  }

  return alerts;
}

// ─── Dashboard Aggregation ──────────────────────────────────────────────────

/**
 * Aggregate monitoring states into a dashboard view.
 */
export function buildMonitoringDashboard(
  states: KsiMonitoringState[],
  trendHistory: TrendPoint[]
): MonitoringDashboard {
  const compliantCount = states.filter(s => s.status === "compliant").length;
  const degradedCount = states.filter(s => s.status === "degraded").length;
  const nonCompliantCount = states.filter(s => s.status === "non_compliant").length;
  const unknownCount = states.filter(s => s.status === "unknown").length;

  const totalScore = states.reduce((sum, s) => sum + s.currentScore, 0);
  const overallScore = states.length > 0 ? Math.round(totalScore / states.length) : 0;

  const allAlerts = states.flatMap(s => s.alerts).filter(a => !a.resolvedAt);
  allAlerts.sort((a, b) => b.triggeredAt - a.triggeredAt);

  const upcomingValidations = states
    .filter(s => s.nextValidation > Date.now())
    .sort((a, b) => a.nextValidation - b.nextValidation)
    .slice(0, 10)
    .map(s => ({ ksiId: s.ksiId, scheduledAt: s.nextValidation }));

  return {
    overallComplianceScore: overallScore,
    totalKsis: states.length,
    compliantCount,
    degradedCount,
    nonCompliantCount,
    unknownCount,
    recentAlerts: allAlerts.slice(0, 20),
    trendData: trendHistory,
    nextScheduledValidations: upcomingValidations,
  };
}

/**
 * Calculate the next validation date based on frequency.
 */
export function getNextValidationDate(
  lastValidated: number,
  frequency: string
): number {
  const MS_PER_DAY = 24 * 60 * 60 * 1000;
  const frequencyDays: Record<string, number> = {
    daily: 1,
    weekly: 7,
    biweekly: 14,
    monthly: 30,
    quarterly: 90,
    semiannual: 180,
    annual: 365,
  };

  const days = frequencyDays[frequency.toLowerCase()] || 30;
  return lastValidated + (days * MS_PER_DAY);
}
