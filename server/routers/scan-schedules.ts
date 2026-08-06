import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import { scanSchedules, engagements } from "../../drizzle/schema";
import { eq, desc, and, sql } from "drizzle-orm";
import { parseVulnScan } from "../lib/vuln-scanner-parser";

// ─── In-memory schedule tracker ─────────────────────────────────────────────
const activeTimers = new Map<number, NodeJS.Timeout>();

async function executeScanSchedule(scheduleId: number) {
  const db = await getDb();
  const [schedule] = await db.select().from(scanSchedules).where(eq(scanSchedules.id, scheduleId));
  if (!schedule || !schedule.isActive) return;

  // Mark as running
  await db.update(scanSchedules).set({
    lastRunStatus: "running",
    lastRunAt: sql`CURRENT_TIMESTAMP`,
  }).where(eq(scanSchedules.id, scheduleId));

  try {
    const config = schedule.connectionConfig as any;
    let reportContent = "";

    // Fetch report from scanner API
    if (schedule.scannerType === "nessus") {
      // Nessus REST API: GET /scans/{scan_id}/export
      const exportRes = await fetch(`${config.apiUrl}/scans/${config.scanId}/export`, {
        method: "POST",
        headers: {
          "X-ApiKeys": `accessKey=${config.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ format: "nessus" }),
      });
      if (exportRes.ok) {
        const { file: fileId } = await exportRes.json();
        // Poll for export completion
        let ready = false;
        for (let i = 0; i < 30; i++) {
          await new Promise(r => setTimeout(r, 5000));
          const statusRes = await fetch(
            `${config.apiUrl}/scans/${config.scanId}/export/${fileId}/status`,
            { headers: { "X-ApiKeys": `accessKey=${config.apiKey}` } }
          );
          if (statusRes.ok) {
            const { status } = await statusRes.json();
            if (status === "ready") { ready = true; break; }
          }
        }
        if (ready) {
          const downloadRes = await fetch(
            `${config.apiUrl}/scans/${config.scanId}/export/${fileId}/download`,
            { headers: { "X-ApiKeys": `accessKey=${config.apiKey}` } }
          );
          reportContent = await downloadRes.text();
        }
      }
    } else if (schedule.scannerType === "qualys") {
      // Qualys API: POST /api/2.0/fo/scan/?action=fetch
      const res = await fetch(`${config.apiUrl}/api/2.0/fo/scan/?action=fetch&scan_ref=${config.scanId}&output_format=csv`, {
        headers: {
          "X-Requested-With": "curl",
          "Authorization": `Basic ${Buffer.from(`${config.username}:${config.password}`).toString("base64")}`,
        },
      });
      if (res.ok) reportContent = await res.text();
    } else if (schedule.scannerType === "openvas") {
      // OpenVAS GMP API
      const res = await fetch(`${config.apiUrl}/report/${config.reportId}/format/xml`, {
        headers: config.headers || {},
      });
      if (res.ok) reportContent = await res.text();
    } else if (schedule.scannerType === "zap") {
      // ZAP API: GET /JSON/core/view/alerts
      const res = await fetch(`${config.apiUrl}/JSON/core/view/alerts/?apikey=${config.apiKey}&start=0&count=500`);
      if (res.ok) reportContent = await res.text();
    } else if (schedule.scannerType === "burp") {
      // Burp Enterprise API
      const res = await fetch(`${config.apiUrl}/api-internal/scan/${config.scanId}/report?report_type=detailed`, {
        headers: { "Authorization": `Bearer ${config.apiKey}` },
      });
      if (res.ok) reportContent = await res.text();
    } else if (schedule.scannerType === "rapid7") {
      // InsightVM API
      const res = await fetch(`${config.apiUrl}/api/3/reports/${config.reportId}/history/latest/output`, {
        headers: { "Authorization": `Basic ${Buffer.from(`${config.username}:${config.password}`).toString("base64")}` },
      });
      if (res.ok) reportContent = await res.text();
    }

    if (!reportContent) {
      throw new Error("No report content received from scanner API");
    }

    // Parse the report
    const findings = parseVulnScan(schedule.scannerType, reportContent);

    // Update schedule stats
    await db.update(scanSchedules).set({
      lastRunStatus: "success",
      lastRunStats: {
        totalParsed: findings.length,
        imported: findings.length,
        skipped: 0,
        failed: 0,
      },
      totalRuns: sql`${scanSchedules.totalRuns} + 1`,
      totalFindings: sql`${scanSchedules.totalFindings} + ${findings.length}`,
      updatedAt: sql`CURRENT_TIMESTAMP`,
    }).where(eq(scanSchedules.id, scheduleId));

    console.log(`[ScanSchedule] Schedule ${scheduleId} completed: ${findings.length} findings`);
  } catch (err: any) {
    await db.update(scanSchedules).set({
      lastRunStatus: "failed",
      lastRunStats: { error: err.message },
      totalRuns: sql`${scanSchedules.totalRuns} + 1`,
      updatedAt: sql`CURRENT_TIMESTAMP`,
    }).where(eq(scanSchedules.id, scheduleId));
    console.error(`[ScanSchedule] Schedule ${scheduleId} failed:`, err.message);
  }
}

function parseCronToMs(cron: string): number {
  // Simple cron interval parser for common patterns
  // Supports: "every_hour", "every_6h", "every_12h", "every_day", "every_week"
  const presets: Record<string, number> = {
    "every_hour": 3600000,
    "every_2h": 7200000,
    "every_6h": 21600000,
    "every_12h": 43200000,
    "every_day": 86400000,
    "every_week": 604800000,
  };
  return presets[cron] || 86400000; // default daily
}

function startScheduleTimer(scheduleId: number, cronExpression: string) {
  stopScheduleTimer(scheduleId);
  const intervalMs = parseCronToMs(cronExpression);
  const timer = setInterval(() => executeScanSchedule(scheduleId), intervalMs);
  activeTimers.set(scheduleId, timer);
  console.log(`[ScanSchedule] Started timer for schedule ${scheduleId} (interval: ${intervalMs}ms)`);
}

function stopScheduleTimer(scheduleId: number) {
  const existing = activeTimers.get(scheduleId);
  if (existing) {
    clearInterval(existing);
    activeTimers.delete(scheduleId);
  }
}

export const scanSchedulesRouter = router({
  // List all schedules
  list: protectedProcedure.query(async () => {
    const db = await getDb();
    const rows = await db.select({
      schedule: scanSchedules,
      engagementName: engagements.name,
    })
      .from(scanSchedules)
      .leftJoin(engagements, eq(scanSchedules.engagementId, engagements.id))
      .orderBy(desc(scanSchedules.id));
    return rows.map(r => ({
      ...r.schedule,
      engagementName: r.engagementName,
      isTimerActive: activeTimers.has(r.schedule.id),
    }));
  }),

  // Create a new schedule
  create: protectedProcedure
    .input(z.object({
      name: z.string().min(1),
      engagementId: z.number().optional(),
      scannerType: z.enum(["nessus", "qualys", "rapid7", "openvas", "burp", "zap"]),
      connectionConfig: z.object({
        apiUrl: z.string().url(),
        apiKey: z.string().optional(),
        username: z.string().optional(),
        password: z.string().optional(),
        scanId: z.string().optional(),
        reportId: z.string().optional(),
        headers: z.record(z.string()).optional(),
      }),
      cronExpression: z.string().min(1),
      autoStart: z.boolean().default(true),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const [result] = await db.insert(scanSchedules).values({
        name: input.name,
        engagementId: input.engagementId ?? null,
        scannerType: input.scannerType,
        connectionConfig: input.connectionConfig,
        cronExpression: input.cronExpression,
        isActive: input.autoStart,
      });
      const id = result.insertId;
      if (input.autoStart) {
        startScheduleTimer(id, input.cronExpression);
      }
      return { id, started: input.autoStart };
    }),

  // Toggle schedule active/inactive
  toggle: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const [schedule] = await db.select().from(scanSchedules).where(eq(scanSchedules.id, input.id));
      if (!schedule) throw new Error("Schedule not found");

      const newActive = !schedule.isActive;
      await db.update(scanSchedules).set({
        isActive: newActive,
        updatedAt: sql`CURRENT_TIMESTAMP`,
      }).where(eq(scanSchedules.id, input.id));

      if (newActive) {
        startScheduleTimer(input.id, schedule.cronExpression);
      } else {
        stopScheduleTimer(input.id);
      }
      return { id: input.id, isActive: newActive };
    }),

  // Run a schedule immediately (manual trigger)
  runNow: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      // Fire and forget — don't block the mutation
      executeScanSchedule(input.id).catch(err =>
        console.error(`[ScanSchedule] Manual run failed for ${input.id}:`, err)
      );
      return { triggered: true };
    }),

  // Delete a schedule
  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      stopScheduleTimer(input.id);
      const db = await getDb();
      await db.delete(scanSchedules).where(eq(scanSchedules.id, input.id));
      return { deleted: true };
    }),

  // Get active timer count
  status: protectedProcedure.query(() => ({
    activeTimers: activeTimers.size,
    timerIds: Array.from(activeTimers.keys()),
  })),
});
