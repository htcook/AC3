/**
 * CSPM Scheduled Scan Scheduler
 * Manages cron-based recurring Prowler/ScoutSuite/Trivy scans.
 * Uses node-cron for scheduling and the cspm-dashboard router for execution.
 */
import cron from "node-cron";
import { getDb } from "../db";
import { scheduledCspmScans, cloudCredentials } from "../../drizzle/schema";
import { eq, and, lte, sql } from "drizzle-orm";
import { createScanRun, completeScanRun, failScanRun, storeFindings, storeContainerVulnerabilities } from "./cspm-db";
import { decryptCredentialObject } from "./credential-crypto";
import { executeRawCommand } from "./scan-server-executor";

// ── State ─────────────────────────────────────────────────────────────────
let _cronTask: ReturnType<typeof cron.schedule> | null = null;
let _lastCheckAt: number | null = null;
let _totalScansTriggered = 0;
let _activeScanCount = 0;
const MAX_CONCURRENT_SCANS = 2;
const CRON_EXPRESSION = "*/5 * * * *"; // Check every 5 minutes

interface SchedulerRun {
  scheduleId: number;
  scanRunId: number;
  tool: string;
  provider: string;
  triggeredAt: number;
  status: "running" | "completed" | "failed";
  completedAt?: number;
  error?: string;
  findingsCount?: number;
}

const _recentRuns: SchedulerRun[] = [];
const MAX_RECENT_RUNS = 50;

// ── Cron Expression Helpers ──────────────────────────────────────────────

export function getNextRunTime(cronExpr: string): number | null {
  try {
    if (!cron.validate(cronExpr)) return null;
    // Simple approximation: parse cron to get next occurrence
    // For production, use a proper cron parser. Here we estimate based on interval.
    const parts = cronExpr.split(" ");
    const now = Date.now();
    // Default: next 5 minutes
    let intervalMs = 5 * 60 * 1000;
    if (parts[1] === "0" && parts[0] === "0") {
      // Daily at midnight
      intervalMs = 24 * 60 * 60 * 1000;
    } else if (parts[0] === "0" && parts[1] !== "*") {
      // Hourly at specific minute
      intervalMs = 60 * 60 * 1000;
    } else if (parts[1].startsWith("*/")) {
      // Every N hours
      const hours = parseInt(parts[1].replace("*/", ""));
      intervalMs = hours * 60 * 60 * 1000;
    } else if (parts[0].startsWith("*/")) {
      // Every N minutes
      const mins = parseInt(parts[0].replace("*/", ""));
      intervalMs = mins * 60 * 1000;
    }
    return now + intervalMs;
  } catch {
    return null;
  }
}

export function validateCronExpression(expr: string): boolean {
  return cron.validate(expr);
}

// ── Core Scheduler Logic ─────────────────────────────────────────────────

async function checkAndTriggerScheduledScans(): Promise<{ checked: number; triggered: number }> {
  _lastCheckAt = Date.now();
  let checked = 0;
  let triggered = 0;

  try {
    const db = await getDb();
    if (!db) return { checked: 0, triggered: 0 };

    // Find all active schedules whose nextRunAt has passed
    const now = Date.now();
    const dueSchedules = await db.select()
      .from(scheduledCspmScans)
      .where(and(
        eq(scheduledCspmScans.isActive, 1),
        lte(scheduledCspmScans.nextRunAt, now),
      ));

    checked = dueSchedules.length;

    for (const schedule of dueSchedules) {
      if (_activeScanCount >= MAX_CONCURRENT_SCANS) break;

      try {
        _activeScanCount++;
        triggered++;
        _totalScansTriggered++;

        // Execute the scan asynchronously
        executeScan(schedule).catch(err => {
          console.error(`[CSPM Scheduler] Scan failed for schedule ${schedule.id}:`, err.message);
        }).finally(() => {
          _activeScanCount--;
        });

        // Update nextRunAt
        const nextRun = getNextRunTime(schedule.cronExpression);
        await db.update(scheduledCspmScans)
          .set({
            lastRunAt: now,
            lastRunStatus: "running",
            totalRuns: sql`total_runs + 1`,
            nextRunAt: nextRun,
            updatedAt: now,
          })
          .where(eq(scheduledCspmScans.id, schedule.id));
      } catch (err: any) {
        console.error(`[CSPM Scheduler] Failed to trigger schedule ${schedule.id}:`, err.message);
        _activeScanCount--;
      }
    }
  } catch (err: any) {
    console.error("[CSPM Scheduler] Check failed:", err.message);
  }

  return { checked, triggered };
}

async function executeScan(schedule: any) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  // Fetch credential
  const [cred] = await db.select().from(cloudCredentials)
    .where(eq(cloudCredentials.id, schedule.credentialId));
  if (!cred) throw new Error(`Credential ${schedule.credentialId} not found`);

  const decrypted = decryptCredentialObject({
    encryptedData: cred.encryptedData,
    iv: cred.encryptionIv,
    tag: cred.encryptionTag,
  });

  const provider = cred.credProvider;
  const credentials: Record<string, string> = {};

  switch (provider) {
    case "aws":
      credentials.accessKeyId = decrypted.accessKeyId || "";
      credentials.secretAccessKey = decrypted.secretAccessKey || "";
      if (decrypted.sessionToken) credentials.sessionToken = decrypted.sessionToken;
      credentials.region = cred.credRegion || "us-east-1";
      if (cred.roleArn) credentials.roleArn = cred.roleArn;
      break;
    case "azure":
      credentials.clientId = decrypted.clientId || "";
      credentials.clientSecret = decrypted.clientSecret || "";
      credentials.tenantId = cred.tenantId || decrypted.tenantId || "";
      if (cred.subscriptionId) credentials.subscriptionId = cred.subscriptionId;
      break;
    case "gcp":
      credentials.projectId = cred.projectId || decrypted.projectId || "";
      credentials.serviceAccountKey = typeof decrypted === "string" ? decrypted : JSON.stringify(decrypted);
      break;
    default:
      Object.assign(credentials, decrypted);
  }

  const services = schedule.services as string[] | null;
  const compliance = schedule.complianceFramework;
  const timeout = schedule.timeoutSeconds || 600;

  // Create scan run
  const scanRunId = await createScanRun({
    credentialId: schedule.credentialId,
    engagementId: schedule.engagementId,
    scanTool: schedule.scanTool,
    scanProvider: provider,
    scanScope: { services, compliance, scheduledScanId: schedule.id },
    triggeredBy: `scheduler:${schedule.name}`,
    complianceFramework: compliance,
  });

  if (!scanRunId) throw new Error("Failed to create scan run");

  const run: SchedulerRun = {
    scheduleId: schedule.id,
    scanRunId,
    tool: schedule.scanTool,
    provider,
    triggeredAt: Date.now(),
    status: "running",
  };
  _recentRuns.unshift(run);
  if (_recentRuns.length > MAX_RECENT_RUNS) _recentRuns.pop();

  const startTime = Date.now();

  try {
    if (schedule.scanTool === "prowler") {
      let cmd = `prowler ${provider} -M json-ocsf --no-banner`;
      if (provider === "aws") {
        cmd = `AWS_ACCESS_KEY_ID='${credentials.accessKeyId}' AWS_SECRET_ACCESS_KEY='${credentials.secretAccessKey}' ${credentials.sessionToken ? `AWS_SESSION_TOKEN='${credentials.sessionToken}' ` : ""}AWS_DEFAULT_REGION='${credentials.region}' ${cmd}`;
        if (credentials.roleArn) cmd += ` -R ${credentials.roleArn}`;
      } else if (provider === "azure") {
        cmd = `AZURE_TENANT_ID='${credentials.tenantId}' AZURE_CLIENT_ID='${credentials.clientId}' AZURE_CLIENT_SECRET='${credentials.clientSecret}' ${cmd} --sp-env-auth`;
      }
      if (services?.length) cmd += ` --services ${services.join(" ")}`;
      if (compliance) cmd += ` --compliance ${compliance}`;

      const result = await executeRawCommand(cmd, timeout);
      const { parseProwlerJsonOutput } = await import("../routers/prowler-integration");
      const findings = parseProwlerJsonOutput(result.stdout || "");
      const scanResult = {
        provider, totalChecks: findings.length,
        passed: findings.filter((f: any) => f.status === "PASS").length,
        failed: findings.filter((f: any) => f.status === "FAIL").length,
        warnings: findings.filter((f: any) => f.status === "WARNING").length,
        findings, rawOutput: (result.stdout || "").substring(0, 50000),
        durationMs: Date.now() - startTime, errors: [] as string[],
      };
      await completeScanRun(scanRunId, scanResult);
      await storeFindings({ scanRunId, scanTool: "prowler", findings, provider });
      run.status = "completed";
      run.findingsCount = findings.length;
    } else if (schedule.scanTool === "scoutsuite") {
      let cmd = `python3 -m ScoutSuite --provider ${provider} --no-browser --result-format json`;
      if (provider === "aws") {
        cmd = `AWS_ACCESS_KEY_ID='${credentials.accessKeyId}' AWS_SECRET_ACCESS_KEY='${credentials.secretAccessKey}' ${cmd}`;
      } else if (provider === "azure") {
        cmd = `AZURE_TENANT_ID='${credentials.tenantId}' AZURE_CLIENT_ID='${credentials.clientId}' AZURE_CLIENT_SECRET='${credentials.clientSecret}' ${cmd} --cli`;
      }
      if (services?.length) cmd += ` --services ${services.join(" ")}`;

      const result = await executeRawCommand(cmd, timeout);
      // Parse ScoutSuite output (simplified)
      const findings: any[] = [];
      try {
        const parsed = JSON.parse(result.stdout || "{}");
        if (parsed.services) {
          for (const [svc, svcData] of Object.entries(parsed.services as Record<string, any>)) {
            if (svcData?.findings) {
              for (const [, finding] of Object.entries(svcData.findings as Record<string, any>)) {
                findings.push({
                  checkId: (finding as any).id || svc,
                  checkTitle: (finding as any).description || "",
                  severity: (finding as any).level || "medium",
                  status: (finding as any).flagged_items > 0 ? "FAIL" : "PASS",
                  service: svc,
                  region: "global",
                  resourceArn: "",
                  resourceId: "",
                  description: (finding as any).rationale || "",
                  risk: "",
                  remediation: (finding as any).remediation || "",
                  complianceFrameworks: [],
                });
              }
            }
          }
        }
      } catch { /* empty */ }

      const scanResult = {
        provider, totalChecks: findings.length,
        passed: findings.filter((f: any) => f.status === "PASS").length,
        failed: findings.filter((f: any) => f.status === "FAIL").length,
        warnings: 0,
        findings, rawOutput: (result.stdout || "").substring(0, 50000),
        durationMs: Date.now() - startTime, errors: [] as string[],
      };
      await completeScanRun(scanRunId, scanResult);
      await storeFindings({ scanRunId, scanTool: "scoutsuite", findings, provider });
      run.status = "completed";
      run.findingsCount = findings.length;
    } else if (schedule.scanTool === "trivy") {
      // Trivy scans the scan server's Docker images
      const result = await executeRawCommand(
        `trivy image --format json --severity CRITICAL,HIGH,MEDIUM,LOW ${credentials.image || ""}`,
        timeout
      );
      const findings: any[] = [];
      try {
        const parsed = JSON.parse(result.stdout || "{}");
        if (parsed.Results) {
          for (const r of parsed.Results) {
            for (const v of (r.Vulnerabilities || [])) {
              findings.push({
                checkId: v.VulnerabilityID,
                checkTitle: v.Title || v.VulnerabilityID,
                severity: v.Severity?.toLowerCase() || "unknown",
                status: "FAIL",
                service: r.Target,
                region: "",
                resourceArn: "",
                resourceId: v.PkgName,
                description: v.Description || "",
                risk: "",
                remediation: v.FixedVersion ? `Upgrade to ${v.FixedVersion}` : "No fix available",
                complianceFrameworks: [],
              });
            }
          }
        }
      } catch { /* empty */ }

      const scanResult = {
        provider: "docker", totalChecks: findings.length,
        passed: 0, failed: findings.length, warnings: 0,
        findings, rawOutput: (result.stdout || "").substring(0, 50000),
        durationMs: Date.now() - startTime, errors: [] as string[],
      };
      await completeScanRun(scanRunId, scanResult);
      await storeFindings({ scanRunId, scanTool: "trivy", findings, provider: "docker" });
      run.status = "completed";
      run.findingsCount = findings.length;
    }

    // Update schedule with last run info
    await db.update(scheduledCspmScans)
      .set({
        lastRunId: scanRunId,
        lastRunStatus: "completed",
        updatedAt: Date.now(),
      })
      .where(eq(scheduledCspmScans.id, schedule.id));

    run.completedAt = Date.now();
  } catch (err: any) {
    await failScanRun(scanRunId, err.message);
    run.status = "failed";
    run.error = err.message;
    run.completedAt = Date.now();

    await db.update(scheduledCspmScans)
      .set({
        lastRunId: scanRunId,
        lastRunStatus: "error",
        updatedAt: Date.now(),
      })
      .where(eq(scheduledCspmScans.id, schedule.id));
  }
}

// ── Public API ───────────────────────────────────────────────────────────

export function startCspmScheduler() {
  if (_cronTask) return;
  _cronTask = cron.schedule(CRON_EXPRESSION, () => {
    checkAndTriggerScheduledScans().catch(err => {
      console.error("[CSPM Scheduler] Unhandled error:", err);
    });
  });
  console.log("[CSPM Scheduler] Started - checking every 5 minutes");
}

export function stopCspmScheduler() {
  if (_cronTask) {
    _cronTask.stop();
    _cronTask = null;
    console.log("[CSPM Scheduler] Stopped");
  }
}

export function getCspmSchedulerStatus() {
  return {
    running: _cronTask !== null,
    lastCheckAt: _lastCheckAt,
    totalScansTriggered: _totalScansTriggered,
    activeScanCount: _activeScanCount,
    recentRuns: _recentRuns.slice(0, 20),
    cronExpression: CRON_EXPRESSION,
  };
}
