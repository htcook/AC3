import {
  getFIPSCrypto
} from "./chunk-5CE4P7TD.js";
import {
  init_notification,
  notifyOwner
} from "./chunk-EW7K5JMQ.js";
import {
  getDb,
  init_db
} from "./chunk-RSFTEATL.js";
import {
  fipsComplianceRecords,
  init_schema
} from "./chunk-L4JENJ4Z.js";

// server/lib/fips-audit-scheduler.ts
init_db();
init_schema();
import { desc, eq } from "drizzle-orm";
init_notification();
async function runScheduledFipsAudit() {
  const fips = getFIPSCrypto();
  const report = fips.getComplianceReport();
  const checks = [];
  checks.push({
    checkType: "provider_status",
    status: report.fipsProviderActive ? "compliant" : "warning",
    component: "openssl-fips-provider",
    details: {
      active: report.fipsProviderActive,
      opensslVersion: report.opensslVersion,
      note: report.fipsProviderActive ? "FIPS provider active" : "FIPS provider not active \u2014 using software-only mode with FIPS-approved algorithms."
    }
  });
  try {
    const testData = "FIPS scheduled audit payload";
    const encrypted = fips.encrypt(testData, "fips-scheduled-audit");
    const decrypted = fips.decrypt(encrypted, "fips-scheduled-audit");
    checks.push({
      checkType: "algorithm_usage",
      status: decrypted.toString() === testData ? "compliant" : "non_compliant",
      component: "aes-256-gcm",
      details: { algorithm: "aes-256-gcm", operation: "encrypt-decrypt", result: "pass" }
    });
  } catch (e) {
    checks.push({
      checkType: "algorithm_usage",
      status: "non_compliant",
      component: "aes-256-gcm",
      details: { error: e.message }
    });
  }
  try {
    const kp = fips.generateKeyPair("P-256");
    const sig = fips.sign("scheduled-audit-test", kp.privateKey);
    const valid = fips.verify("scheduled-audit-test", sig, kp.publicKey);
    checks.push({
      checkType: "key_strength",
      status: valid ? "compliant" : "non_compliant",
      component: "ecdsa-p256",
      details: { curve: "P-256", signVerify: valid ? "pass" : "fail" }
    });
  } catch (e) {
    checks.push({
      checkType: "key_strength",
      status: "non_compliant",
      component: "ecdsa-p256",
      details: { error: e.message }
    });
  }
  try {
    const hmacResult = fips.hmac("scheduled audit data");
    const verified = fips.verifyHmac("scheduled audit data", hmacResult);
    checks.push({
      checkType: "algorithm_usage",
      status: verified ? "compliant" : "non_compliant",
      component: "hmac-sha256",
      details: { algorithm: "hmac-sha256", result: verified ? "pass" : "fail" }
    });
  } catch (e) {
    checks.push({
      checkType: "algorithm_usage",
      status: "non_compliant",
      component: "hmac-sha256",
      details: { error: e.message }
    });
  }
  try {
    const pw = fips.hashPassword("scheduled-audit-password");
    const valid = fips.verifyPassword("scheduled-audit-password", pw);
    checks.push({
      checkType: "algorithm_usage",
      status: valid ? "compliant" : "non_compliant",
      component: "pbkdf2-sha256",
      details: { iterations: pw.iterations, result: valid ? "pass" : "fail" }
    });
  } catch (e) {
    checks.push({
      checkType: "algorithm_usage",
      status: "non_compliant",
      component: "pbkdf2-sha256",
      details: { error: e.message }
    });
  }
  const tlsCheck = !!(report.tlsCiphers.tls12 || report.tlsCiphers.tls13);
  checks.push({
    checkType: "tls_cipher",
    status: tlsCheck ? "compliant" : "warning",
    component: "tls-cipher-suites",
    details: {
      tls12: report.tlsCiphers.tls12,
      tls13: report.tlsCiphers.tls13
    }
  });
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
      scheduledAudit: true
    }
  });
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
        createdAt: now
      });
    }
  }
  let degraded = false;
  if (db) {
    const [previousAudit] = await db.select().from(fipsComplianceRecords).where(eq(fipsComplianceRecords.checkType, "full_audit")).orderBy(desc(fipsComplianceRecords.id)).limit(1);
    if (previousAudit) {
      const prevDetails = previousAudit.details;
      const prevNonCompliant = prevDetails?.nonCompliant ?? 0;
      const prevWarnings = prevDetails?.warnings ?? 0;
      const currentNonCompliant = checks.filter((c) => c.status === "non_compliant").length;
      const currentWarnings = checks.filter((c) => c.status === "warning").length;
      if (currentNonCompliant > prevNonCompliant || currentWarnings > prevWarnings) {
        degraded = true;
      }
      const statusRank = { compliant: 0, warning: 1, non_compliant: 2 };
      const prevStatus = previousAudit.status;
      if ((statusRank[overallStatus] ?? 0) > (statusRank[prevStatus] ?? 0)) {
        degraded = true;
      }
    }
  }
  let notificationSent = false;
  if (degraded || hasNonCompliant) {
    const failedComponents = checks.filter((c) => c.status === "non_compliant").map((c) => c.component);
    const warningComponents = checks.filter((c) => c.status === "warning").map((c) => c.component);
    const title = hasNonCompliant ? `\u26A0\uFE0F FIPS 140-3 Compliance FAILURE Detected` : `\u26A0\uFE0F FIPS 140-3 Compliance Degradation`;
    const contentLines = [
      `**Scheduled FIPS Compliance Audit \u2014 ${new Date(now).toISOString()}**`,
      ``,
      `Overall Status: **${overallStatus.toUpperCase()}**`,
      `OpenSSL Version: ${report.opensslVersion}`,
      `FIPS Provider: ${report.fipsProviderActive ? "Active" : "Inactive (software-only)"}`,
      ``
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
      `Review the FIPS Compliance dashboard for full details.`
    );
    try {
      notificationSent = await notifyOwner({
        title,
        content: contentLines.join("\n")
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
    notificationSent
  };
}
var auditTimer = null;
var auditInterval = null;
function msUntilUtcHour(hour) {
  const now = /* @__PURE__ */ new Date();
  const target = new Date(now);
  target.setUTCHours(hour, 0, 0, 0);
  if (target.getTime() <= now.getTime()) {
    target.setUTCDate(target.getUTCDate() + 1);
  }
  return target.getTime() - now.getTime();
}
function initFipsAuditScheduler(utcHour = 2) {
  if (auditTimer) clearTimeout(auditTimer);
  if (auditInterval) clearInterval(auditInterval);
  const msUntilFirst = msUntilUtcHour(utcHour);
  const dailyMs = 24 * 60 * 60 * 1e3;
  console.log(
    `[FIPSAudit] Scheduling daily audit at ${utcHour}:00 UTC (first run in ${Math.round(msUntilFirst / 6e4)} minutes)`
  );
  auditTimer = setTimeout(async () => {
    try {
      const result = await runScheduledFipsAudit();
      console.log(
        `[FIPSAudit] Scheduled audit complete: ${result.overallStatus}` + (result.degraded ? " (DEGRADED)" : "") + (result.notificationSent ? " (notification sent)" : "")
      );
    } catch (err) {
      console.error("[FIPSAudit] Scheduled audit failed:", err);
    }
    auditInterval = setInterval(async () => {
      try {
        const result = await runScheduledFipsAudit();
        console.log(
          `[FIPSAudit] Scheduled audit complete: ${result.overallStatus}` + (result.degraded ? " (DEGRADED)" : "") + (result.notificationSent ? " (notification sent)" : "")
        );
      } catch (err) {
        console.error("[FIPSAudit] Scheduled audit failed:", err);
      }
    }, dailyMs);
  }, msUntilFirst);
}
function stopFipsAuditScheduler() {
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

export {
  runScheduledFipsAudit,
  initFipsAuditScheduler,
  stopFipsAuditScheduler
};
