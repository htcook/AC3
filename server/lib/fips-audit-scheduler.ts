/**
 * FIPS Compliance Audit Scheduler
 *
 * Runs a full FIPS 140-3 compliance audit on a configurable schedule
 * (default: daily at 02:00 UTC). When any check degrades from "compliant"
 * to "warning" or "non_compliant", sends an owner notification via the
 * built-in notification service.
 *
 * The scheduler also compares current results against the most recent
 * stored audit to detect regressions.
 */

import { getDb } from "../db";
import { fipsComplianceRecords } from "../../drizzle/schema";
import { desc, eq } from "drizzle-orm";
import { getFIPSCrypto } from "./fips-crypto";
import { notifyOwner } from "../_core/notification";

// ─── Types ──────────────────────────────────────────────────────────────

interface AuditCheck {
  checkType: "tls_cipher" | "algorithm_usage" | "key_strength" | "provider_status" | "full_audit";
  status: "compliant" | "non_compliant" | "warning";
  component: string;
  details: Record<string, unknown>;
}

export interface ScheduledAuditResult {
  timestamp: number;
  checks: AuditCheck[];
  overallStatus: "compliant" | "non_compliant" | "warning";
  degraded: boolean;
  notificationSent: boolean;
}

// ─── Audit Execution ────────────────────────────────────────────────────

/**
 * Run a full FIPS compliance audit, store results, compare against
 * previous audit, and notify owner on degradation.
 */
export async function runScheduledFipsAudit(): Promise<ScheduledAuditResult> {
  const fips = getFIPSCrypto();
  const report = fips.getComplianceReport();
  const checks: AuditCheck[] = [];

  // 1. Provider status
  checks.push({
    checkType: "provider_status",
    status: report.fipsProviderActive ? "compliant" : "warning",
    component: "openssl-fips-provider",
    details: {
      active: report.fipsProviderActive,
      opensslVersion: report.opensslVersion,
      note: report.fipsProviderActive
        ? "FIPS provider active"
        : "FIPS provider not active — using software-only mode with FIPS-approved algorithms.",
    },
  });

  // 2. AES-256-GCM
  try {
    const testData = "FIPS scheduled audit payload";
    const encrypted = fips.encrypt(testData, "fips-scheduled-audit");
    const decrypted = fips.decrypt(encrypted, "fips-scheduled-audit");
    checks.push({
      checkType: "algorithm_usage",
      status: decrypted.toString() === testData ? "compliant" : "non_compliant",
      component: "aes-256-gcm",
      details: { algorithm: "aes-256-gcm", operation: "encrypt-decrypt", result: "pass" },
    });
  } catch (e: any) {
    checks.push({
      checkType: "algorithm_usage",
      status: "non_compliant",
      component: "aes-256-gcm",
      details: { error: e.message },
    });
  }

  // 3. ECDSA P-256
  try {
    const kp = fips.generateKeyPair("P-256");
    const sig = fips.sign("scheduled-audit-test", kp.privateKey);
    const valid = fips.verify("scheduled-audit-test", sig, kp.publicKey);
    checks.push({
      checkType: "key_strength",
      status: valid ? "compliant" : "non_compliant",
      component: "ecdsa-p256",
      details: { curve: "P-256", signVerify: valid ? "pass" : "fail" },
    });
  } catch (e: any) {
    checks.push({
      checkType: "key_strength",
      status: "non_compliant",
      component: "ecdsa-p256",
      details: { error: e.message },
    });
  }

  // 4. HMAC-SHA256
  try {
    const hmacResult = fips.hmac("scheduled audit data");
    const verified = fips.verifyHmac("scheduled audit data", hmacResult);
    checks.push({
      checkType: "algorithm_usage",
      status: verified ? "compliant" : "non_compliant",
      component: "hmac-sha256",
      details: { algorithm: "hmac-sha256", result: verified ? "pass" : "fail" },
    });
  } catch (e: any) {
    checks.push({
      checkType: "algorithm_usage",
      status: "non_compliant",
      component: "hmac-sha256",
      details: { error: e.message },
    });
  }

  // 5. PBKDF2
  try {
    const pw = fips.hashPassword("scheduled-audit-password");
    const valid = fips.verifyPassword("scheduled-audit-password", pw);
    checks.push({
      checkType: "algorithm_usage",
      status: valid ? "compliant" : "non_compliant",
      component: "pbkdf2-sha256",
      details: { iterations: pw.iterations, result: valid ? "pass" : "fail" },
    });
  } catch (e: any) {
    checks.push({
      checkType: "algorithm_usage",
      status: "non_compliant",
      component: "pbkdf2-sha256",
      details: { error: e.message },
    });
  }

  // 6. TLS cipher validation
  const tlsCheck = !!(report.tlsCiphers.tls12 || report.tlsCiphers.tls13);
  checks.push({
    checkType: "tls_cipher",
    status: tlsCheck ? "compliant" : "warning",
    component: "tls-cipher-suites",
    details: {
      tls12: report.tlsCiphers.tls12,
      tls13: report.tlsCiphers.tls13,
    },
  });

  // Full audit summary
  const allCompliant = checks.every((c) => c.status === "compliant");
  const hasNonCompliant = checks.some((c) => c.status === "non_compliant");
  const overallStatus = hasNonCompliant ? "non_compliant" : allCompliant ? "compliant" : "warning";

  checks.push({
    checkType: "full_audit",
    status: overallStatus,
    component: "platform-wide",
    details: {
      totalChecks: checks.length,
      compliant: checks.filter((c) => c.status === "compliant").length,
      warnings: checks.filter((c) => c.status === "warning").length,
      nonCompliant: checks.filter((c) => c.status === "non_compliant").length,
      scheduledAudit: true,
    },
  });

  // ─── Store results ──────────────────────────────────────────────────

  const db = await getDb();
  const now = Date.now();

  if (db) {
    for (const check of checks) {
      await db.insert(fipsComplianceRecords).values({
        checkType: check.checkType,
        status: check.status,
        component: check.component,
        details: check.details,
        opensslVersion: report.opensslVersion,
        fipsProviderActive: report.fipsProviderActive,
        createdAt: now,
      });
    }
  }

  // ─── Compare against previous audit ─────────────────────────────────

  let degraded = false;

  if (db) {
    // Get the most recent full_audit record before this one
    const [previousAudit] = await db
      .select()
      .from(fipsComplianceRecords)
      .where(eq(fipsComplianceRecords.checkType, "full_audit"))
      .orderBy(desc(fipsComplianceRecords.id))
      .limit(1);

    if (previousAudit) {
      const prevDetails = previousAudit.details as Record<string, unknown> | null;
      const prevNonCompliant = (prevDetails?.nonCompliant as number) ?? 0;
      const prevWarnings = (prevDetails?.warnings as number) ?? 0;
      const currentNonCompliant = checks.filter((c) => c.status === "non_compliant").length;
      const currentWarnings = checks.filter((c) => c.status === "warning").length;

      // Degradation = more non-compliant or more warnings than before
      if (currentNonCompliant > prevNonCompliant || currentWarnings > prevWarnings) {
        degraded = true;
      }

      // Also check if overall status worsened
      const statusRank = { compliant: 0, warning: 1, non_compliant: 2 };
      const prevStatus = previousAudit.status as keyof typeof statusRank;
      if ((statusRank[overallStatus] ?? 0) > (statusRank[prevStatus] ?? 0)) {
        degraded = true;
      }
    }
  }

  // ─── Send notification on degradation ───────────────────────────────

  let notificationSent = false;

  if (degraded || hasNonCompliant) {
    const failedComponents = checks
      .filter((c) => c.status === "non_compliant")
      .map((c) => c.component);
    const warningComponents = checks
      .filter((c) => c.status === "warning")
      .map((c) => c.component);

    const title = hasNonCompliant
      ? `⚠️ FIPS 140-3 Compliance FAILURE Detected`
      : `⚠️ FIPS 140-3 Compliance Degradation`;

    const contentLines = [
      `**Scheduled FIPS Compliance Audit — ${new Date(now).toISOString()}**`,
      ``,
      `Overall Status: **${overallStatus.toUpperCase()}**`,
      `OpenSSL Version: ${report.opensslVersion}`,
      `FIPS Provider: ${report.fipsProviderActive ? "Active" : "Inactive (software-only)"}`,
      ``,
    ];

    if (failedComponents.length > 0) {
      contentLines.push(`**Non-Compliant Components:** ${failedComponents.join(", ")}`);
    }
    if (warningComponents.length > 0) {
      contentLines.push(`**Warning Components:** ${warningComponents.join(", ")}`);
    }

    contentLines.push(
      ``,
      `Total Checks: ${checks.length}`,
      `Compliant: ${checks.filter((c) => c.status === "compliant").length}`,
      `Warnings: ${warningComponents.length}`,
      `Non-Compliant: ${failedComponents.length}`,
      ``,
      `Review the FIPS Compliance dashboard for full details.`,
    );

    try {
      notificationSent = await notifyOwner({
        title,
        content: contentLines.join("\n"),
      });
      if (notificationSent) {
        console.log("[FIPSAudit] Owner notification sent for compliance degradation");
      }
    } catch (err) {
      console.warn("[FIPSAudit] Failed to send owner notification:", err);
    }
  }

  return {
    timestamp: now,
    checks,
    overallStatus,
    degraded,
    notificationSent,
  };
}

// ─── Scheduler ──────────────────────────────────────────────────────────

let auditTimer: ReturnType<typeof setTimeout> | null = null;
let auditInterval: ReturnType<typeof setInterval> | null = null;

/**
 * Calculate milliseconds until the next occurrence of a given UTC hour.
 */
function msUntilUtcHour(hour: number): number {
  const now = new Date();
  const target = new Date(now);
  target.setUTCHours(hour, 0, 0, 0);

  if (target.getTime() <= now.getTime()) {
    // Already past today's target; schedule for tomorrow
    target.setUTCDate(target.getUTCDate() + 1);
  }

  return target.getTime() - now.getTime();
}

/**
 * Initialize the FIPS audit scheduler.
 * Runs daily at 02:00 UTC by default.
 */
export function initFipsAuditScheduler(utcHour: number = 2): void {
  // Clear any existing scheduler
  if (auditTimer) clearTimeout(auditTimer);
  if (auditInterval) clearInterval(auditInterval);

  const msUntilFirst = msUntilUtcHour(utcHour);
  const dailyMs = 24 * 60 * 60 * 1000;

  console.log(
    `[FIPSAudit] Scheduling daily audit at ${utcHour}:00 UTC (first run in ${Math.round(msUntilFirst / 60_000)} minutes)`
  );

  // Schedule first run
  auditTimer = setTimeout(async () => {
    try {
      const result = await runScheduledFipsAudit();
      console.log(
        `[FIPSAudit] Scheduled audit complete: ${result.overallStatus}` +
          (result.degraded ? " (DEGRADED)" : "") +
          (result.notificationSent ? " (notification sent)" : "")
      );
    } catch (err) {
      console.error("[FIPSAudit] Scheduled audit failed:", err);
    }

    // Then repeat daily
    auditInterval = setInterval(async () => {
      try {
        const result = await runScheduledFipsAudit();
        console.log(
          `[FIPSAudit] Scheduled audit complete: ${result.overallStatus}` +
            (result.degraded ? " (DEGRADED)" : "") +
            (result.notificationSent ? " (notification sent)" : "")
        );
      } catch (err) {
        console.error("[FIPSAudit] Scheduled audit failed:", err);
      }
    }, dailyMs);
  }, msUntilFirst);
}

/**
 * Stop the FIPS audit scheduler.
 */
export function stopFipsAuditScheduler(): void {
  if (auditTimer) {
    clearTimeout(auditTimer);
    auditTimer = null;
  }
  if (auditInterval) {
    clearInterval(auditInterval);
    auditInterval = null;
  }
  console.log("[FIPSAudit] Scheduler stopped");
}
