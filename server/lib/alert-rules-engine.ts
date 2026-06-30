/**
 * SSIL Observation-Based Alerting Rules Engine
 * 
 * Evaluates incoming observations and signals against user-defined alert rules.
 * When thresholds are crossed, triggers owner notifications and logs alert history.
 * Supports cooldown periods, severity escalation, and per-asset/per-scanner filtering.
 */

import * as crypto from "crypto";
import { eq, desc, and, gte, sql } from "drizzle-orm";
import { notifyOwner } from "../_core/notification";
import type { NormalizedObservation } from "./observation-normalizer";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface AlertRuleConditions {
  severityThreshold?: "info" | "low" | "medium" | "high" | "critical";
  cvssThreshold?: number;
  riskScoreThreshold?: number;
  observationCountThreshold?: number;
  timeWindowMinutes?: number;
  scannerFilter?: string[];
  assetFilter?: string[];
  observationTypeFilter?: string[];
  customExpression?: string;
}

export interface AlertRule {
  ruleId: string;
  name: string;
  description?: string;
  isEnabled: boolean;
  triggerType: AlertTriggerType;
  conditions: AlertRuleConditions;
  notifyOwner: boolean;
  cooldownMinutes: number;
  lastTriggeredAt?: number;
  triggerCount: number;
}

export type AlertTriggerType =
  | "critical_cve"
  | "new_open_port"
  | "high_severity_signal"
  | "risk_score_threshold"
  | "observation_count"
  | "new_vulnerability"
  | "tls_expiry"
  | "misconfiguration"
  | "custom";

export interface AlertEvent {
  alertId: string;
  ruleId: string;
  ruleName: string;
  triggerType: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  message: string;
  matchedObservationIds: string[];
  matchedSignalIds: string[];
  matchedAssetId?: string;
  matchedAssetHost?: string;
  matchedDetails: Record<string, unknown>;
  notificationSent: boolean;
  notificationResult?: string;
  triggeredAt: number;
}

export interface EvaluationContext {
  observations: NormalizedObservation[];
  signals?: Array<{
    signalId: string;
    signalType: string;
    severity: string;
    confidence: number;
    category: string;
    assetId: string;
    enrichmentCvss?: number;
    enrichmentCve?: string;
  }>;
  riskCards?: Array<{
    assetId: string;
    compositeScore: number;
    cvssScore: number;
    carverScore: number;
    biaScore: number;
  }>;
}

// ─── Severity Ordering ──────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function severityAtOrAbove(
  actual: string,
  threshold: string
): boolean {
  return (SEVERITY_ORDER[actual] ?? 0) >= (SEVERITY_ORDER[threshold] ?? 0);
}

function maxSeverity(items: string[]): string {
  let max = "info";
  for (const s of items) {
    if ((SEVERITY_ORDER[s] ?? 0) > (SEVERITY_ORDER[max] ?? 0)) max = s;
  }
  return max;
}

// ─── Default Alert Rules (Presets) ──────────────────────────────────────────

// ─── Global Notification Rate Limiter ──────────────────────────────────────
// Prevents email floods: max 5 notifications per hour, with digest batching
const GLOBAL_NOTIFICATION_LIMIT = 5;
const GLOBAL_NOTIFICATION_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const notificationTimestamps: number[] = [];

function canSendNotification(): boolean {
  const now = Date.now();
  // Remove timestamps outside the window
  while (notificationTimestamps.length > 0 && notificationTimestamps[0] < now - GLOBAL_NOTIFICATION_WINDOW_MS) {
    notificationTimestamps.shift();
  }
  return notificationTimestamps.length < GLOBAL_NOTIFICATION_LIMIT;
}

function recordNotificationSent(): void {
  notificationTimestamps.push(Date.now());
}

// Pending digest for batched alerts that exceed the rate limit
let pendingDigestAlerts: Array<{ severity: string; title: string; message: string }> = [];
let digestTimer: ReturnType<typeof setTimeout> | null = null;
const DIGEST_DELAY_MS = 5 * 60 * 1000; // 5 minutes — batch alerts into a single digest

async function flushDigest(): Promise<void> {
  if (pendingDigestAlerts.length === 0) return;
  const alerts = [...pendingDigestAlerts];
  pendingDigestAlerts = [];
  digestTimer = null;

  if (!canSendNotification()) {
    console.log(`[AlertEngine] Digest suppressed — global rate limit reached (${alerts.length} alerts dropped)`);
    return;
  }

  const criticalCount = alerts.filter(a => a.severity === 'critical').length;
  const highCount = alerts.filter(a => a.severity === 'high').length;
  const otherCount = alerts.length - criticalCount - highCount;

  const title = `[DIGEST] ${alerts.length} Alert${alerts.length > 1 ? 's' : ''} — ${criticalCount} Critical, ${highCount} High`;
  const content = [
    `Alert digest (${alerts.length} alerts batched):`,
    '',
    ...alerts.slice(0, 10).map((a, i) => `${i + 1}. [${a.severity.toUpperCase()}] ${a.title}`),
    ...(alerts.length > 10 ? [`... and ${alerts.length - 10} more`] : []),
  ].join('\n');

  try {
    await notifyOwner({ title, content });
    recordNotificationSent();
    console.log(`[AlertEngine] Digest sent: ${alerts.length} alerts`);
  } catch {
    console.error('[AlertEngine] Failed to send digest notification');
  }
}

function queueForDigest(severity: string, title: string, message: string): void {
  pendingDigestAlerts.push({ severity, title, message });
  if (!digestTimer) {
    digestTimer = setTimeout(() => flushDigest(), DIGEST_DELAY_MS);
  }
}

export const DEFAULT_ALERT_RULES: Omit<AlertRule, "triggerCount" | "lastTriggeredAt">[] = [
  {
    ruleId: "default-critical-cve",
    name: "Critical CVE Detected",
    description: "Triggers when any observation contains a CVE with CVSS >= 9.0",
    isEnabled: true,
    triggerType: "critical_cve",
    conditions: { cvssThreshold: 9.0 },
    notifyOwner: true,
    cooldownMinutes: 240, // 4 hours (was 30 min)
  },
  {
    ruleId: "default-new-open-port",
    name: "New Open Port Discovered",
    description: "Triggers when a new open port is detected on any monitored asset",
    isEnabled: true,
    triggerType: "new_open_port",
    conditions: {},
    notifyOwner: false, // Disabled email — too noisy, still logs to alert history
    cooldownMinutes: 360, // 6 hours (was 60 min)
  },
  {
    ruleId: "default-high-severity-signal",
    name: "High Severity Signal",
    description: "Triggers when a signal with severity high or critical is derived",
    isEnabled: true,
    triggerType: "high_severity_signal",
    conditions: { severityThreshold: "critical" }, // Raised from "high" to "critical" only
    notifyOwner: true,
    cooldownMinutes: 360, // 6 hours (was 15 min)
  },
  {
    ruleId: "default-risk-score",
    name: "Risk Score Threshold Exceeded",
    description: "Triggers when an asset's composite risk score exceeds 80",
    isEnabled: false,
    triggerType: "risk_score_threshold",
    conditions: { riskScoreThreshold: 80 },
    notifyOwner: false,
    cooldownMinutes: 720, // 12 hours
  },
  {
    ruleId: "default-observation-burst",
    name: "Observation Burst Detected",
    description: "Triggers when more than 50 observations arrive in a 5-minute window",
    isEnabled: false,
    triggerType: "observation_count",
    conditions: { observationCountThreshold: 50, timeWindowMinutes: 5 },
    notifyOwner: false,
    cooldownMinutes: 360,
  },
  {
    ruleId: "default-new-vuln",
    name: "New Vulnerability Finding",
    description: "Triggers on any new vulnerability finding with severity >= high",
    isEnabled: true,
    triggerType: "new_vulnerability",
    conditions: { severityThreshold: "high" }, // Raised from "medium" to "high"
    notifyOwner: false, // Disabled email — too noisy during scans, still logs to alert history
    cooldownMinutes: 360, // 6 hours (was 15 min)
  },
  {
    ruleId: "default-tls-expiry",
    name: "TLS Certificate Expiring Soon",
    description: "Triggers when a TLS certificate is detected expiring within 30 days",
    isEnabled: true,
    triggerType: "tls_expiry",
    conditions: { timeWindowMinutes: 43200 }, // 30 days in minutes
    notifyOwner: true,
    cooldownMinutes: 1440, // once per day (unchanged)
  },
  {
    ruleId: "default-misconfiguration",
    name: "Misconfiguration Detected",
    description: "Triggers on any new misconfiguration observation with severity >= high",
    isEnabled: true,
    triggerType: "misconfiguration",
    conditions: { severityThreshold: "high" }, // Raised from "medium" to "high"
    notifyOwner: false, // Disabled email — too noisy, still logs to alert history
    cooldownMinutes: 360, // 6 hours (was 30 min)
  },
];

// ─── Alert Rules Engine ─────────────────────────────────────────────────────

export class AlertRulesEngine {
  private rules: Map<string, AlertRule> = new Map();
  private alertHistory: AlertEvent[] = [];
  private listeners: Array<(event: AlertEvent) => void> = [];

  constructor() {}

  // ── Rule Management ─────────────────────────────────────────────────────

  loadRules(rules: AlertRule[]): void {
    this.rules.clear();
    for (const rule of rules) {
      this.rules.set(rule.ruleId, { ...rule });
    }
  }

  addRule(rule: AlertRule): void {
    this.rules.set(rule.ruleId, { ...rule });
  }

  removeRule(ruleId: string): boolean {
    return this.rules.delete(ruleId);
  }

  getRule(ruleId: string): AlertRule | undefined {
    return this.rules.get(ruleId);
  }

  getAllRules(): AlertRule[] {
    return Array.from(this.rules.values());
  }

  enableRule(ruleId: string): boolean {
    const rule = this.rules.get(ruleId);
    if (!rule) return false;
    rule.isEnabled = true;
    return true;
  }

  disableRule(ruleId: string): boolean {
    const rule = this.rules.get(ruleId);
    if (!rule) return false;
    rule.isEnabled = false;
    return true;
  }

  // ── Event Listeners ─────────────────────────────────────────────────────

  onAlert(listener: (event: AlertEvent) => void): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  private emit(event: AlertEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Don't let listener errors break the engine
      }
    }
  }

  // ── Core Evaluation ─────────────────────────────────────────────────────

  async evaluate(context: EvaluationContext): Promise<AlertEvent[]> {
    const triggered: AlertEvent[] = [];
    const now = Date.now();

    for (const rule of this.rules.values()) {
      if (!rule.isEnabled) continue;

      // Check cooldown
      if (rule.lastTriggeredAt) {
        const cooldownMs = rule.cooldownMinutes * 60 * 1000;
        if (now - rule.lastTriggeredAt < cooldownMs) continue;
      }

      // Evaluate rule against context
      const result = this.evaluateRule(rule, context);
      if (!result) continue;

      // Create alert event
      const alertEvent: AlertEvent = {
        alertId: `alert-${crypto.randomUUID().substring(0, 24)}`,
        ruleId: rule.ruleId,
        ruleName: rule.name,
        triggerType: rule.triggerType,
        severity: result.severity,
        title: result.title,
        message: result.message,
        matchedObservationIds: result.matchedObservationIds,
        matchedSignalIds: result.matchedSignalIds,
        matchedAssetId: result.matchedAssetId,
        matchedAssetHost: result.matchedAssetHost,
        matchedDetails: result.matchedDetails,
        notificationSent: false,
        triggeredAt: now,
      };

      // Send notification if configured — with global rate limiting and digest batching
      if (rule.notifyOwner) {
        if (canSendNotification()) {
          try {
            const sent = await notifyOwner({
              title: `[${result.severity.toUpperCase()}] ${result.title}`,
              content: result.message,
            });
            if (sent) recordNotificationSent();
            alertEvent.notificationSent = sent;
            alertEvent.notificationResult = sent ? "delivered" : "failed";
          } catch (err) {
            alertEvent.notificationResult = `error: ${err instanceof Error ? err.message : "unknown"}`;
          }
        } else {
          // Rate limited — queue for digest instead of sending individually
          queueForDigest(result.severity, result.title, result.message);
          alertEvent.notificationSent = false;
          alertEvent.notificationResult = "rate_limited_queued_for_digest";
          console.log(`[AlertEngine] Rate limited: ${result.title} — queued for digest`);
        }
      }

      // Update rule state
      rule.lastTriggeredAt = now;
      rule.triggerCount += 1;

      // Store and emit
      this.alertHistory.push(alertEvent);
      triggered.push(alertEvent);
      this.emit(alertEvent);
    }

    return triggered;
  }

  private evaluateRule(
    rule: AlertRule,
    context: EvaluationContext
  ): {
    severity: "info" | "low" | "medium" | "high" | "critical";
    title: string;
    message: string;
    matchedObservationIds: string[];
    matchedSignalIds: string[];
    matchedAssetId?: string;
    matchedAssetHost?: string;
    matchedDetails: Record<string, unknown>;
  } | null {
    const { conditions } = rule;

    // Apply scanner filter
    let filteredObs = context.observations;
    if (conditions.scannerFilter?.length) {
      filteredObs = filteredObs.filter((o) =>
        conditions.scannerFilter!.includes(o.scanner.name)
      );
    }

    // Apply asset filter
    if (conditions.assetFilter?.length) {
      filteredObs = filteredObs.filter((o) =>
        conditions.assetFilter!.includes(o.asset.host)
      );
    }

    // Apply observation type filter
    if (conditions.observationTypeFilter?.length) {
      filteredObs = filteredObs.filter((o) =>
        conditions.observationTypeFilter!.includes(o.observationType)
      );
    }

    switch (rule.triggerType) {
      case "critical_cve":
        return this.evaluateCriticalCve(rule, filteredObs, context);
      case "new_open_port":
        return this.evaluateNewOpenPort(rule, filteredObs);
      case "high_severity_signal":
        return this.evaluateHighSeveritySignal(rule, context);
      case "risk_score_threshold":
        return this.evaluateRiskScoreThreshold(rule, context);
      case "observation_count":
        return this.evaluateObservationCount(rule, filteredObs);
      case "new_vulnerability":
        return this.evaluateNewVulnerability(rule, filteredObs);
      case "tls_expiry":
        return this.evaluateTlsExpiry(rule, filteredObs);
      case "misconfiguration":
        return this.evaluateMisconfiguration(rule, filteredObs);
      default:
        return null;
    }
  }

  // ── Evaluators ──────────────────────────────────────────────────────────

  private evaluateCriticalCve(
    rule: AlertRule,
    observations: NormalizedObservation[],
    context: EvaluationContext
  ) {
    const threshold = rule.conditions.cvssThreshold ?? 9.0;

    // Check observations with CVE evidence
    const cveObs = observations.filter(
      (o) => o.evidence.cve && o.evidence.cvss && o.evidence.cvss >= threshold
    );

    // Also check signals with CVSS enrichment
    const cveSignals = (context.signals || []).filter(
      (s) => s.enrichmentCvss && s.enrichmentCvss >= threshold
    );

    if (cveObs.length === 0 && cveSignals.length === 0) return null;

    const allCves = [
      ...cveObs.map((o) => o.evidence.cve).filter(Boolean),
      ...cveSignals.map((s) => s.enrichmentCve).filter(Boolean),
    ];
    const uniqueCves = [...new Set(allCves)];
    const maxCvss = Math.max(
      ...cveObs.map((o) => o.evidence.cvss || 0),
      ...cveSignals.map((s) => s.enrichmentCvss || 0)
    );

    const firstMatch = cveObs[0] || null;

    return {
      severity: (maxCvss >= 9.0 ? "critical" : "high") as "critical" | "high",
      title: `Critical CVE${uniqueCves.length > 1 ? "s" : ""} Detected: ${uniqueCves.slice(0, 3).join(", ")}`,
      message:
        `${uniqueCves.length} CVE(s) with CVSS >= ${threshold} detected.\n` +
        `Highest CVSS: ${maxCvss.toFixed(1)}\n` +
        `CVEs: ${uniqueCves.join(", ")}\n` +
        (firstMatch ? `First detected on: ${firstMatch.asset.host}:${firstMatch.asset.port}` : ""),
      matchedObservationIds: cveObs.map((o) => o.observationId),
      matchedSignalIds: cveSignals.map((s) => s.signalId),
      matchedAssetId: firstMatch?.asset.assetId,
      matchedAssetHost: firstMatch?.asset.host,
      matchedDetails: { cves: uniqueCves, maxCvss, threshold },
    };
  }

  private evaluateNewOpenPort(
    rule: AlertRule,
    observations: NormalizedObservation[]
  ) {
    const portObs = observations.filter(
      (o) =>
        o.observationType === "service_banner" ||
        o.observationType === "exposure_surface"
    );

    if (portObs.length === 0) return null;

    const portsByHost = new Map<string, Set<number>>();
    for (const obs of portObs) {
      const key = obs.asset.host;
      if (!portsByHost.has(key)) portsByHost.set(key, new Set());
      portsByHost.get(key)!.add(obs.asset.port);
    }

    const hostSummaries = Array.from(portsByHost.entries()).map(
      ([host, ports]) => `${host}: ports ${Array.from(ports).sort((a, b) => a - b).join(", ")}`
    );

    const totalPorts = portObs.length;
    const firstMatch = portObs[0];

    return {
      severity: "medium" as const,
      title: `${totalPorts} New Open Port${totalPorts > 1 ? "s" : ""} Discovered`,
      message:
        `New open ports detected across ${portsByHost.size} host(s):\n` +
        hostSummaries.join("\n"),
      matchedObservationIds: portObs.map((o) => o.observationId),
      matchedSignalIds: [],
      matchedAssetId: firstMatch?.asset.assetId,
      matchedAssetHost: firstMatch?.asset.host,
      matchedDetails: {
        totalPorts,
        hosts: Object.fromEntries(
          Array.from(portsByHost.entries()).map(([h, p]) => [h, Array.from(p)])
        ),
      },
    };
  }

  private evaluateHighSeveritySignal(
    rule: AlertRule,
    context: EvaluationContext
  ) {
    const threshold = rule.conditions.severityThreshold ?? "high";
    const matchedSignals = (context.signals || []).filter((s) =>
      severityAtOrAbove(s.severity, threshold)
    );

    if (matchedSignals.length === 0) return null;

    const severity = maxSeverity(matchedSignals.map((s) => s.severity)) as
      | "high"
      | "critical";
    const categories = [...new Set(matchedSignals.map((s) => s.category))];
    const firstSignal = matchedSignals[0];

    return {
      severity,
      title: `${matchedSignals.length} High-Severity Signal${matchedSignals.length > 1 ? "s" : ""} Detected`,
      message:
        `${matchedSignals.length} signal(s) at severity ${threshold} or above.\n` +
        `Categories: ${categories.join(", ")}\n` +
        `Types: ${[...new Set(matchedSignals.map((s) => s.signalType))].join(", ")}`,
      matchedObservationIds: [],
      matchedSignalIds: matchedSignals.map((s) => s.signalId),
      matchedAssetId: firstSignal?.assetId,
      matchedAssetHost: undefined,
      matchedDetails: { signalCount: matchedSignals.length, categories, threshold },
    };
  }

  private evaluateRiskScoreThreshold(
    rule: AlertRule,
    context: EvaluationContext
  ) {
    const threshold = rule.conditions.riskScoreThreshold ?? 80;
    const matchedCards = (context.riskCards || []).filter(
      (r) => r.compositeScore >= threshold
    );

    if (matchedCards.length === 0) return null;

    const maxScore = Math.max(...matchedCards.map((r) => r.compositeScore));
    const firstCard = matchedCards[0];

    return {
      severity: (maxScore >= 90 ? "critical" : "high") as "critical" | "high",
      title: `Risk Score Threshold Exceeded: ${maxScore.toFixed(1)}`,
      message:
        `${matchedCards.length} asset(s) exceed risk score threshold of ${threshold}.\n` +
        `Highest score: ${maxScore.toFixed(1)}\n` +
        `Assets: ${matchedCards.map((r) => r.assetId).join(", ")}`,
      matchedObservationIds: [],
      matchedSignalIds: [],
      matchedAssetId: firstCard?.assetId,
      matchedAssetHost: undefined,
      matchedDetails: { maxScore, threshold, assetCount: matchedCards.length },
    };
  }

  private evaluateObservationCount(
    rule: AlertRule,
    observations: NormalizedObservation[]
  ) {
    const threshold = rule.conditions.observationCountThreshold ?? 50;
    const windowMs = (rule.conditions.timeWindowMinutes ?? 5) * 60 * 1000;
    const cutoff = Date.now() - windowMs;

    const recentObs = observations.filter((o) => new Date(o.timestamp).getTime() >= cutoff);
    if (recentObs.length < threshold) return null;

    const scannerCounts = new Map<string, number>();
    for (const obs of recentObs) {
      const name = obs.scanner.name;
      scannerCounts.set(name, (scannerCounts.get(name) || 0) + 1);
    }

    return {
      severity: "medium" as const,
      title: `Observation Burst: ${recentObs.length} in ${rule.conditions.timeWindowMinutes ?? 5}min`,
      message:
        `${recentObs.length} observations received in the last ${rule.conditions.timeWindowMinutes ?? 5} minutes (threshold: ${threshold}).\n` +
        `By scanner: ${Array.from(scannerCounts.entries())
          .map(([s, c]) => `${s}: ${c}`)
          .join(", ")}`,
      matchedObservationIds: recentObs.map((o) => o.observationId),
      matchedSignalIds: [],
      matchedDetails: {
        count: recentObs.length,
        threshold,
        windowMinutes: rule.conditions.timeWindowMinutes ?? 5,
        byScannerName: Object.fromEntries(scannerCounts),
      },
    };
  }

  private evaluateNewVulnerability(
    rule: AlertRule,
    observations: NormalizedObservation[]
  ) {
    const threshold = rule.conditions.severityThreshold ?? "medium";
    const vulnObs = observations.filter(
      (o) =>
        o.observationType === "vulnerability_finding" &&
        severityAtOrAbove(o.severity, threshold)
    );

    if (vulnObs.length === 0) return null;

    const severity = maxSeverity(vulnObs.map((o) => o.severity)) as
      | "medium"
      | "high"
      | "critical";
    const firstMatch = vulnObs[0];
    const cves = vulnObs.map((o) => o.evidence.cve).filter(Boolean);

    return {
      severity,
      title: `${vulnObs.length} New Vulnerability Finding${vulnObs.length > 1 ? "s" : ""}`,
      message:
        `${vulnObs.length} new vulnerability finding(s) at severity ${threshold} or above.\n` +
        (cves.length > 0 ? `CVEs: ${[...new Set(cves)].join(", ")}\n` : "") +
        `First finding: ${firstMatch.evidence.summary}\n` +
        `Asset: ${firstMatch.asset.host}:${firstMatch.asset.port}`,
      matchedObservationIds: vulnObs.map((o) => o.observationId),
      matchedSignalIds: [],
      matchedAssetId: firstMatch.asset.assetId,
      matchedAssetHost: firstMatch.asset.host,
      matchedDetails: {
        vulnCount: vulnObs.length,
        cves: [...new Set(cves)],
        severities: vulnObs.map((o) => o.severity),
      },
    };
  }

  private evaluateTlsExpiry(
    rule: AlertRule,
    observations: NormalizedObservation[]
  ) {
    const windowMinutes = rule.conditions.timeWindowMinutes ?? 43200; // 30 days
    const expiryThresholdMs = windowMinutes * 60 * 1000;
    const now = Date.now();

    const tlsObs = observations.filter((o) => o.observationType === "tls");

    // Check for TLS observations with expiry data in evidence
    const expiringObs = tlsObs.filter((o) => {
      const certExpiry = (o.evidence as Record<string, unknown>).certExpiry;
      if (!certExpiry) return false;
      const expiryTime =
        typeof certExpiry === "number"
          ? certExpiry
          : new Date(certExpiry as string).getTime();
      return expiryTime > 0 && expiryTime - now < expiryThresholdMs;
    });

    if (expiringObs.length === 0) return null;

    const firstMatch = expiringObs[0];
    const daysUntilExpiry = Math.floor(
      ((firstMatch.evidence as Record<string, unknown>).certExpiry as number - now) /
        (1000 * 60 * 60 * 24)
    );

    return {
      severity: (daysUntilExpiry <= 7 ? "critical" : "high") as "critical" | "high",
      title: `TLS Certificate Expiring: ${expiringObs.length} cert${expiringObs.length > 1 ? "s" : ""}`,
      message:
        `${expiringObs.length} TLS certificate(s) expiring within ${Math.floor(windowMinutes / 1440)} days.\n` +
        `First expiring: ${firstMatch.asset.host}:${firstMatch.asset.port}` +
        (daysUntilExpiry > 0 ? ` (${daysUntilExpiry} days remaining)` : " (EXPIRED)"),
      matchedObservationIds: expiringObs.map((o) => o.observationId),
      matchedSignalIds: [],
      matchedAssetId: firstMatch.asset.assetId,
      matchedAssetHost: firstMatch.asset.host,
      matchedDetails: {
        expiringCount: expiringObs.length,
        nearestExpiryDays: daysUntilExpiry,
      },
    };
  }

  private evaluateMisconfiguration(
    rule: AlertRule,
    observations: NormalizedObservation[]
  ) {
    const threshold = rule.conditions.severityThreshold ?? "medium";
    const misconfigObs = observations.filter(
      (o) =>
        o.observationType === "misconfiguration" &&
        severityAtOrAbove(o.severity, threshold)
    );

    if (misconfigObs.length === 0) return null;

    const severity = maxSeverity(misconfigObs.map((o) => o.severity)) as
      | "medium"
      | "high"
      | "critical";
    const firstMatch = misconfigObs[0];

    return {
      severity,
      title: `${misconfigObs.length} Misconfiguration${misconfigObs.length > 1 ? "s" : ""} Detected`,
      message:
        `${misconfigObs.length} misconfiguration(s) at severity ${threshold} or above.\n` +
        `First finding: ${firstMatch.evidence.summary}\n` +
        `Asset: ${firstMatch.asset.host}:${firstMatch.asset.port}`,
      matchedObservationIds: misconfigObs.map((o) => o.observationId),
      matchedSignalIds: [],
      matchedAssetId: firstMatch.asset.assetId,
      matchedAssetHost: firstMatch.asset.host,
      matchedDetails: { misconfigCount: misconfigObs.length },
    };
  }

  // ── History ─────────────────────────────────────────────────────────────

  getAlertHistory(limit = 100): AlertEvent[] {
    return this.alertHistory.slice(-limit);
  }

  getAlertsByRule(ruleId: string): AlertEvent[] {
    return this.alertHistory.filter((a) => a.ruleId === ruleId);
  }

  getUnacknowledgedAlerts(): AlertEvent[] {
    return this.alertHistory.filter((a) => !a.notificationSent);
  }

  clearHistory(): void {
    this.alertHistory = [];
  }

  // ── Stats ───────────────────────────────────────────────────────────────

  getStats(): {
    totalRules: number;
    enabledRules: number;
    totalAlerts: number;
    alertsBySeverity: Record<string, number>;
    alertsByType: Record<string, number>;
    lastAlertAt?: number;
  } {
    const alertsBySeverity: Record<string, number> = {};
    const alertsByType: Record<string, number> = {};

    for (const alert of this.alertHistory) {
      alertsBySeverity[alert.severity] =
        (alertsBySeverity[alert.severity] || 0) + 1;
      alertsByType[alert.triggerType] =
        (alertsByType[alert.triggerType] || 0) + 1;
    }

    const lastAlert = this.alertHistory[this.alertHistory.length - 1];

    return {
      totalRules: this.rules.size,
      enabledRules: Array.from(this.rules.values()).filter((r) => r.isEnabled)
        .length,
      totalAlerts: this.alertHistory.length,
      alertsBySeverity,
      alertsByType,
      lastAlertAt: lastAlert?.triggeredAt,
    };
  }
}

// ─── Singleton ──────────────────────────────────────────────────────────────

let engineInstance: AlertRulesEngine | null = null;

export function getAlertRulesEngine(): AlertRulesEngine {
  if (!engineInstance) {
    engineInstance = new AlertRulesEngine();
    // Load default rules
    engineInstance.loadRules(
      DEFAULT_ALERT_RULES.map((r) => ({
        ...r,
        triggerCount: 0,
        lastTriggeredAt: undefined,
      }))
    );
  }
  return engineInstance;
}

export function resetAlertRulesEngine(): void {
  engineInstance = null;
}
