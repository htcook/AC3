import "./chunk-KFQGP6VL.js";

// server/lib/cicd-cron-scheduler.ts
function parseCronExpression(expr) {
  const parts = expr.trim().split(/\s+/);
  if (parts.length !== 5) return null;
  function parseField(field, min, max) {
    const values = /* @__PURE__ */ new Set();
    for (const part of field.split(",")) {
      const stepMatch = part.match(/^(.+)\/(\d+)$/);
      let range = stepMatch ? stepMatch[1] : part;
      const step = stepMatch ? parseInt(stepMatch[2]) : 1;
      if (step < 1) return null;
      if (range === "*") {
        for (let i = min; i <= max; i += step) values.add(i);
      } else if (range.includes("-")) {
        const [startStr, endStr] = range.split("-");
        const start = parseInt(startStr);
        const end = parseInt(endStr);
        if (isNaN(start) || isNaN(end) || start < min || end > max || start > end) return null;
        for (let i = start; i <= end; i += step) values.add(i);
      } else {
        const val = parseInt(range);
        if (isNaN(val) || val < min || val > max) return null;
        values.add(val);
      }
    }
    return values.size > 0 ? Array.from(values).sort((a, b) => a - b) : null;
  }
  const minutes = parseField(parts[0], 0, 59);
  const hours = parseField(parts[1], 0, 23);
  const daysOfMonth = parseField(parts[2], 1, 31);
  const months = parseField(parts[3], 1, 12);
  const daysOfWeek = parseField(parts[4], 0, 6);
  if (!minutes || !hours || !daysOfMonth || !months || !daysOfWeek) return null;
  return { minutes, hours, daysOfMonth, months, daysOfWeek };
}
function matchesCron(date, cron) {
  const minute = date.getUTCMinutes();
  const hour = date.getUTCHours();
  const dom = date.getUTCDate();
  const month = date.getUTCMonth() + 1;
  const dow = date.getUTCDay();
  return cron.minutes.includes(minute) && cron.hours.includes(hour) && cron.daysOfMonth.includes(dom) && cron.months.includes(month) && cron.daysOfWeek.includes(dow);
}
function getNextRunTime(after, cronExpr) {
  const cron = parseCronExpression(cronExpr);
  if (!cron) return null;
  const candidate = new Date(after);
  candidate.setUTCSeconds(0, 0);
  candidate.setUTCMinutes(candidate.getUTCMinutes() + 1);
  const maxIterations = 366 * 24 * 60;
  for (let i = 0; i < maxIterations; i++) {
    if (matchesCron(candidate, cron)) {
      return candidate;
    }
    candidate.setUTCMinutes(candidate.getUTCMinutes() + 1);
  }
  return null;
}
function describeCron(expr) {
  const cron = parseCronExpression(expr);
  if (!cron) return null;
  const parts = [];
  if (cron.minutes.length === 60) {
    parts.push("every minute");
  } else if (cron.minutes.length === 1) {
    parts.push(`at minute ${cron.minutes[0]}`);
  } else {
    parts.push(`at minutes ${cron.minutes.join(", ")}`);
  }
  if (cron.hours.length === 24) {
    parts.push("every hour");
  } else if (cron.hours.length === 1) {
    parts.push(`at ${cron.hours[0]}:00 UTC`);
  } else {
    parts.push(`at hours ${cron.hours.join(", ")} UTC`);
  }
  const dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  if (cron.daysOfWeek.length < 7) {
    parts.push(`on ${cron.daysOfWeek.map((d) => dayNames[d]).join(", ")}`);
  }
  if (cron.daysOfMonth.length < 31) {
    parts.push(`on day(s) ${cron.daysOfMonth.join(", ")}`);
  }
  const monthNames = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  if (cron.months.length < 12) {
    parts.push(`in ${cron.months.map((m) => monthNames[m]).join(", ")}`);
  }
  return parts.join(", ");
}
var CRON_PRESETS = [
  { label: "Every hour", cron: "0 * * * *", description: "Runs at the start of every hour" },
  { label: "Every 6 hours", cron: "0 */6 * * *", description: "Runs every 6 hours" },
  { label: "Every 12 hours", cron: "0 */12 * * *", description: "Runs twice daily" },
  { label: "Daily at midnight UTC", cron: "0 0 * * *", description: "Runs once daily at 00:00 UTC" },
  { label: "Daily at 6 AM UTC", cron: "0 6 * * *", description: "Runs once daily at 06:00 UTC" },
  { label: "Weekdays at 9 AM UTC", cron: "0 9 * * 1-5", description: "Runs Mon-Fri at 09:00 UTC" },
  { label: "Weekly on Monday", cron: "0 0 * * 1", description: "Runs every Monday at midnight UTC" },
  { label: "Monthly on 1st", cron: "0 0 1 * *", description: "Runs on the 1st of each month" }
];
var schedulerInterval = null;
var isRunning = false;
async function checkScheduledPipelines() {
  if (isRunning) return;
  isRunning = true;
  try {
    const { getDb } = await import("./db-F33RXQPM.js");
    const { cicdPipelines, cicdRuns } = await import("./schema-OF2ORZ4R.js");
    const { eq, and, sql, isNotNull } = await import("drizzle-orm");
    const db = await getDb();
    if (!db) return;
    const rows = await db.execute(sql.raw(
      `SELECT id, cicd_name, cicd_schedule_cron, cicd_schedule_target_url, cicd_schedule_last_run, cicd_schedule_next_run, cicd_fail_threshold, cicd_sector_context
       FROM cicd_pipelines
       WHERE cicd_is_active = 1
         AND cicd_schedule_enabled = 1
         AND cicd_schedule_cron IS NOT NULL
         AND cicd_schedule_target_url IS NOT NULL`
    ));
    const pipelines = rows.rows || rows;
    if (!pipelines?.length) return;
    const now = /* @__PURE__ */ new Date();
    for (const pipeline of pipelines) {
      try {
        const cronExpr = pipeline.cicd_schedule_cron;
        if (!cronExpr || typeof cronExpr !== "string") continue;
        const nextRun = pipeline.cicd_schedule_next_run ? new Date(pipeline.cicd_schedule_next_run) : null;
        let shouldRun = false;
        if (nextRun && now >= nextRun) {
          shouldRun = true;
        } else if (!nextRun) {
          const cron = parseCronExpression(cronExpr);
          if (cron && matchesCron(now, cron)) {
            shouldRun = true;
          }
        }
        if (!shouldRun) continue;
        console.log(`[CronScheduler] Triggering scheduled scan for pipeline "${pipeline.cicd_name}" (ID: ${pipeline.id})`);
        const result = await db.insert(cicdRuns).values({
          cicdRunPipelineId: pipeline.id,
          cicdCommitSha: null,
          cicdBranch: "scheduled",
          cicdRunStatus: "pending"
        });
        const runId = result[0].insertId;
        const nextRunTime = getNextRunTime(now, cronExpr);
        await db.execute(sql.raw(
          `UPDATE cicd_pipelines SET
            cicd_schedule_last_run = '${now.toISOString().slice(0, 19).replace("T", " ")}',
            cicd_schedule_next_run = ${nextRunTime ? `'${nextRunTime.toISOString().slice(0, 19).replace("T", " ")}'` : "NULL"},
            cicd_last_triggered = '${now.toISOString().slice(0, 19).replace("T", " ")}'
          WHERE id = ${pipeline.id}`
        ));
        const targetUrl = pipeline.cicd_schedule_target_url;
        import("./aws-cicd-connector-EJ3YJH4M.js").then(async ({ executeCicdScan }) => {
          try {
            await db.update(cicdRuns).set({
              cicdRunStatus: "running",
              cicdStartedAt: (/* @__PURE__ */ new Date()).toISOString()
            }).where(eq(cicdRuns.id, runId));
            const scanResult = await executeCicdScan({
              targetUrl,
              scanTypes: ["nuclei"],
              pipelineId: pipeline.id,
              runId,
              branch: "scheduled"
            });
            await db.update(cicdRuns).set({
              cicdRunStatus: scanResult.status === "passed" ? "passed" : scanResult.status === "error" ? "error" : "failed",
              cicdTotalTests: scanResult.totalFindings,
              cicdPassedTests: scanResult.mediumCount + scanResult.lowCount,
              cicdFailedTests: scanResult.criticalCount + scanResult.highCount,
              cicdRiskScore: scanResult.maxCvss,
              cicdReportUrl: JSON.stringify({
                criticalCount: scanResult.criticalCount,
                highCount: scanResult.highCount,
                mediumCount: scanResult.mediumCount,
                lowCount: scanResult.lowCount,
                maxCvss: scanResult.maxCvss,
                duration: scanResult.duration,
                findings: scanResult.findings.slice(0, 100)
              }),
              cicdCompletedAt: (/* @__PURE__ */ new Date()).toISOString()
            }).where(eq(cicdRuns.id, runId));
            if (scanResult.threatContext) {
              await db.execute(sql.raw(
                `UPDATE cicd_runs SET cicd_threat_context = '${JSON.stringify(scanResult.threatContext).replace(/'/g, "''")}' WHERE id = ${runId}`
              ));
            }
            console.log(`[CronScheduler] Scheduled run ${runId} completed: ${scanResult.status}`);
            if (scanResult.status === "failed" || scanResult.status === "error") {
              try {
                const { notifyOwner } = await import("./notification-4RFY3TAD.js");
                await notifyOwner({
                  title: `\u23F0 Scheduled CI/CD Scan ${scanResult.status === "error" ? "Error" : "Failed"}: ${pipeline.cicd_name}`,
                  content: [
                    `Pipeline: ${pipeline.cicd_name} (Scheduled Run #${runId})`,
                    `Status: ${scanResult.status.toUpperCase()}`,
                    `Target: ${targetUrl}`,
                    `Max CVSS: ${scanResult.maxCvss.toFixed(1)}`,
                    `Findings: ${scanResult.criticalCount} critical, ${scanResult.highCount} high, ${scanResult.mediumCount} medium, ${scanResult.lowCount} low`
                  ].join("\n")
                });
              } catch {
              }
            }
          } catch (err) {
            console.error(`[CronScheduler] Scheduled run ${runId} error: ${err.message}`);
            await db.update(cicdRuns).set({
              cicdRunStatus: "error",
              cicdCompletedAt: (/* @__PURE__ */ new Date()).toISOString()
            }).where(eq(cicdRuns.id, runId));
          }
        });
      } catch (pipeErr) {
        console.warn(`[CronScheduler] Error processing pipeline ${pipeline.id}: ${pipeErr.message}`);
      }
    }
  } catch (err) {
    console.error(`[CronScheduler] Check failed: ${err.message}`);
  } finally {
    isRunning = false;
  }
}
function startCronScheduler() {
  if (schedulerInterval) return;
  console.log("[CronScheduler] Starting CI/CD cron scheduler (60s interval)");
  schedulerInterval = setInterval(checkScheduledPipelines, 6e4);
  setTimeout(checkScheduledPipelines, 3e4);
}
function stopCronScheduler() {
  if (schedulerInterval) {
    clearInterval(schedulerInterval);
    schedulerInterval = null;
    console.log("[CronScheduler] Stopped CI/CD cron scheduler");
  }
}
export {
  CRON_PRESETS,
  describeCron,
  getNextRunTime,
  matchesCron,
  parseCronExpression,
  startCronScheduler,
  stopCronScheduler
};
