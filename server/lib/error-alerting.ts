/**
 * Error Alerting — Real-time notification on critical errors and rate spikes
 * 
 * Features:
 * - Immediate notification on critical errors (React crashes, server 500s)
 * - Rate spike detection (alerts when error frequency exceeds threshold)
 * - Deduplication (same error message won't spam notifications within cooldown)
 * - Severity-based routing (critical = immediate, error = batched summary)
 * - Engagement context included in alerts for operational awareness
 * 
 * Author: Harrison Cook — AceofCloud
 */

import { notifyOwner } from "../_core/notification";

// ─── Configuration ──────────────────────────────────────────────────────────

interface AlertConfig {
  /** Minimum seconds between alerts for the same error fingerprint */
  deduplicationCooldownSec: number;
  /** Number of errors in the window before triggering a rate spike alert */
  rateSpikeThreshold: number;
  /** Window size in seconds for rate spike detection */
  rateSpikeWindowSec: number;
  /** Whether to send alerts (can be disabled for testing) */
  enabled: boolean;
  /** Severity levels that trigger immediate alerts */
  immediateSeverities: string[];
}

const DEFAULT_CONFIG: AlertConfig = {
  deduplicationCooldownSec: 300, // 5 minutes
  rateSpikeThreshold: 10,        // 10 errors in window = spike
  rateSpikeWindowSec: 60,        // 1-minute window
  enabled: true,
  immediateSeverities: ["critical"],
};

let config: AlertConfig = { ...DEFAULT_CONFIG };

// ─── State ──────────────────────────────────────────────────────────────────

/** Track when we last alerted for each error fingerprint */
const alertCooldowns = new Map<string, number>();

/** Sliding window of error timestamps for rate spike detection */
const errorTimestamps: number[] = [];

/** Stats for monitoring */
const alertStats = {
  totalAlertsSent: 0,
  totalSuppressed: 0,
  totalRateSpikeAlerts: 0,
  lastAlertAt: null as number | null,
  lastRateSpikeAt: null as number | null,
};

// ─── Core Functions ─────────────────────────────────────────────────────────

/**
 * Generate a fingerprint for deduplication.
 * Groups errors by message prefix + source + page.
 */
function getErrorFingerprint(error: {
  message: string;
  source: string;
  page?: string | null;
}): string {
  // Take first 100 chars of message to group similar errors
  const msgPrefix = error.message.slice(0, 100).replace(/\d+/g, "N");
  return `${error.source}:${error.page || "unknown"}:${msgPrefix}`;
}

/**
 * Check if we're within the deduplication cooldown for this error.
 */
function isInCooldown(fingerprint: string): boolean {
  const lastAlert = alertCooldowns.get(fingerprint);
  if (!lastAlert) return false;
  return (Date.now() - lastAlert) < (config.deduplicationCooldownSec * 1000);
}

/**
 * Record an error timestamp and check for rate spikes.
 */
function checkRateSpike(): boolean {
  const now = Date.now();
  errorTimestamps.push(now);

  // Remove timestamps outside the window
  const windowStart = now - (config.rateSpikeWindowSec * 1000);
  while (errorTimestamps.length > 0 && errorTimestamps[0] < windowStart) {
    errorTimestamps.shift();
  }

  return errorTimestamps.length >= config.rateSpikeThreshold;
}

/**
 * Format an error into a notification message.
 */
function formatErrorAlert(error: {
  message: string;
  source: string;
  severity: string;
  page?: string | null;
  stack?: string | null;
  engagementContext?: Record<string, unknown> | null;
  userId?: number | null;
}): { title: string; content: string } {
  const severityEmoji = {
    critical: "🚨",
    error: "⚠️",
    warning: "⚡",
    info: "ℹ️",
  }[error.severity] || "⚠️";

  const title = `${severityEmoji} ${error.severity.toUpperCase()}: ${error.message.slice(0, 80)}`;

  const parts: string[] = [
    `**Source:** ${error.source}`,
    `**Page:** ${error.page || "N/A"}`,
    `**Time:** ${new Date().toISOString()}`,
  ];

  if (error.userId) {
    parts.push(`**User ID:** ${error.userId}`);
  }

  if (error.engagementContext) {
    const ctx = error.engagementContext;
    if (ctx.engagementName) parts.push(`**Engagement:** ${ctx.engagementName}`);
    if (ctx.clientName) parts.push(`**Client:** ${ctx.clientName}`);
  }

  if (error.stack) {
    // Include first 5 lines of stack trace
    const shortStack = error.stack.split("\n").slice(0, 5).join("\n");
    parts.push(`\n**Stack:**\n\`\`\`\n${shortStack}\n\`\`\``);
  }

  return { title, content: parts.join("\n") };
}

/**
 * Format a rate spike alert.
 */
function formatRateSpikeAlert(count: number, windowSec: number): { title: string; content: string } {
  return {
    title: `🔥 Error Rate Spike: ${count} errors in ${windowSec}s`,
    content: [
      `**Alert:** Error rate has exceeded the threshold.`,
      `**Count:** ${count} errors in the last ${windowSec} seconds`,
      `**Threshold:** ${config.rateSpikeThreshold} errors/${windowSec}s`,
      `**Time:** ${new Date().toISOString()}`,
      ``,
      `Check the Error Dashboard for details: /error-dashboard`,
    ].join("\n"),
  };
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Process an error and send alerts if appropriate.
 * Called by the error-logger after persisting the error.
 * Fire-and-forget — never throws.
 */
export async function processErrorAlert(error: {
  message: string;
  source: string;
  severity: string;
  page?: string | null;
  stack?: string | null;
  engagementContext?: Record<string, unknown> | null;
  userId?: number | null;
}): Promise<void> {
  if (!config.enabled) return;

  try {
    // 1. Check for rate spike
    const isSpike = checkRateSpike();
    if (isSpike) {
      const now = Date.now();
      // Only send rate spike alert once per window
      if (!alertStats.lastRateSpikeAt || (now - alertStats.lastRateSpikeAt) > (config.rateSpikeWindowSec * 1000)) {
        alertStats.lastRateSpikeAt = now;
        alertStats.totalRateSpikeAlerts++;
        const { title, content } = formatRateSpikeAlert(errorTimestamps.length, config.rateSpikeWindowSec);
        await notifyOwner({ title, content }).catch(() => {});
      }
    }

    // 2. Check if this severity warrants an immediate alert
    if (!config.immediateSeverities.includes(error.severity)) {
      return; // Non-critical errors don't get individual alerts
    }

    // 3. Check deduplication cooldown
    const fingerprint = getErrorFingerprint(error);
    if (isInCooldown(fingerprint)) {
      alertStats.totalSuppressed++;
      return;
    }

    // 4. Send the alert
    alertCooldowns.set(fingerprint, Date.now());
    alertStats.totalAlertsSent++;
    alertStats.lastAlertAt = Date.now();

    const { title, content } = formatErrorAlert(error);
    await notifyOwner({ title, content }).catch((err) => {
      console.error("[ErrorAlerting] Failed to send notification:", err.message);
    });
  } catch (err) {
    // Never throw from alerting — it's fire-and-forget
    console.error("[ErrorAlerting] Unexpected error in processErrorAlert:", err);
  }
}

/**
 * Update alerting configuration.
 */
export function updateAlertConfig(updates: Partial<AlertConfig>): void {
  config = { ...config, ...updates };
}

/**
 * Get current alerting configuration and stats.
 */
export function getAlertStatus(): {
  config: AlertConfig;
  stats: typeof alertStats;
  cooldownCount: number;
  windowErrorCount: number;
} {
  // Clean up expired cooldowns
  const now = Date.now();
  const cooldownMs = config.deduplicationCooldownSec * 1000;
  for (const [key, timestamp] of alertCooldowns.entries()) {
    if (now - timestamp > cooldownMs) {
      alertCooldowns.delete(key);
    }
  }

  return {
    config,
    stats: { ...alertStats },
    cooldownCount: alertCooldowns.size,
    windowErrorCount: errorTimestamps.length,
  };
}

/**
 * Reset alerting state (for testing or after maintenance).
 */
export function resetAlertState(): void {
  alertCooldowns.clear();
  errorTimestamps.length = 0;
  alertStats.totalAlertsSent = 0;
  alertStats.totalSuppressed = 0;
  alertStats.totalRateSpikeAlerts = 0;
  alertStats.lastAlertAt = null;
  alertStats.lastRateSpikeAt = null;
}
