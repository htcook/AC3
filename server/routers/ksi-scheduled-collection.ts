import * as schema from "../../drizzle/schema";
// @ts-nocheck
/**
 * Scheduled Auto-Collection Router
 * Manages automated evidence collection schedules with configurable cadences.
 * Wires existing scanner outputs into the Key Security Indicators evidence chain
 * on a recurring basis without manual intervention.
 */
import { router, protectedProcedure } from "../_core/trpc";
import { z } from "zod";
import { getDb as _getDb, getDbRequired } from "../db";
import crypto from "crypto";

async function db() { return getDbRequired(); }
import { eq, desc, and, lte, sql, count } from "drizzle-orm";
import { randomUUID } from "crypto";
import {
  collectCalderaEvidence,
  collectGophishEvidence,
  collectZapEvidence,
  crossRefThreatCatalog,
} from "../lib/live-scanner-api";

// Source type definitions with default cadences and display names
const SOURCE_DEFINITIONS = [
  { sourceType: "vuln_scanner", displayName: "Vulnerability Scanner", defaultCadence: "daily" as const, ksiMappings: ["KSI-SVC-VSR", "KSI-SVC-VRM"] },
  { sourceType: "web_app_scanner", displayName: "Web Application Scanner", defaultCadence: "daily" as const, ksiMappings: ["KSI-SVC-VSR", "KSI-SCR-PEN"] },
  { sourceType: "osint_recon", displayName: "OSINT & Reconnaissance", defaultCadence: "every_12h" as const, ksiMappings: ["KSI-INR-TIF", "KSI-INR-TIU"] },
  { sourceType: "darkweb_intel", displayName: "Dark Web Intelligence", defaultCadence: "every_6h" as const, ksiMappings: ["KSI-INR-TIF", "KSI-INR-DWM"] },
  { sourceType: "phishing_campaigns", displayName: "Phishing Campaigns", defaultCadence: "daily" as const, ksiMappings: ["KSI-SCR-SAT"] },
  { sourceType: "edr_validation", displayName: "EDR Validation Tests", defaultCadence: "daily" as const, ksiMappings: ["KSI-MLA-EDR", "KSI-MLA-OSM"] },
  { sourceType: "ngfw_validation", displayName: "NGFW Validation Tests", defaultCadence: "daily" as const, ksiMappings: ["KSI-CNA-NSD"] },
  { sourceType: "ad_attack_sim", displayName: "AD Attack Simulation", defaultCadence: "weekly" as const, ksiMappings: ["KSI-IAM-MFA", "KSI-IAM-PAM"] },
  { sourceType: "cloud_misconfigs", displayName: "Cloud Misconfigurations", defaultCadence: "every_12h" as const, ksiMappings: ["KSI-CNA-HCI", "KSI-CNA-EDE"] },
  { sourceType: "atomic_red_team", displayName: "Atomic Red Team Tests", defaultCadence: "weekly" as const, ksiMappings: ["KSI-SCR-APT", "KSI-SCR-PEN"] },
  { sourceType: "threat_intel", displayName: "Threat Intelligence Feeds", defaultCadence: "every_6h" as const, ksiMappings: ["KSI-INR-TIF", "KSI-INR-TIU"] },
] as const;

const CADENCE_MS: Record<string, number> = {
  hourly: 60 * 60 * 1000,
  every_6h: 6 * 60 * 60 * 1000,
  every_12h: 12 * 60 * 60 * 1000,
  daily: 24 * 60 * 60 * 1000,
  weekly: 7 * 24 * 60 * 60 * 1000,
};

// ─── Live Collection Dispatcher ──────────────────────────────────────────────
// Maps source types to live scanner API calls + DB table fallbacks

function computeHash(data: string, previousHash?: string | null): string {
  const payload = previousHash ? `${previousHash}:${data}` : data;
  return crypto.createHash("sha256").update(payload).digest("hex");
}

function generateId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`;
}

async function insertScheduledEvidence(
  dbConn: any,
  ksiId: string,
  title: string,
  description: string,
  sourceModule: string,
  rawData: any,
  collectedBy?: number | null,
  collectedByName?: string | null,
) {
  const { ksiEvidence } = await import("../../drizzle/schema");
  const evidenceId = generateId("EVD");
  const lastEvidence = await dbConn.select()
    .from(ksiEvidence)
    .where(eq(ksiEvidence.ksiId, ksiId))
    .orderBy(desc(ksiEvidence.createdAt))
    .limit(1);

  const previousHash = lastEvidence[0]?.integrityHash || null;
  const dataToHash = JSON.stringify({ evidenceId, ksiId, title, sourceModule, rawData, timestamp: new Date().toISOString() });
  const integrityHash = computeHash(dataToHash, previousHash);

  await dbConn.insert(ksiEvidence).values({
    evidenceId, ksiId, title, description,
    evidenceType: "scan_result",
    sourceModule,
    sourceId: `scheduled-${sourceModule}-${Date.now()}`,
    collectionMethod: "automated",
    rawData,
    integrityHash,
    previousHash,
    status: "collected",
    collectedBy,
    collectedByName: collectedByName ?? "Scheduled-Collector",
  });
  return { evidenceId, integrityHash };
}

async function collectLiveForSource(
  sourceType: string,
  userId?: number | null,
  userName?: string | null,
): Promise<number> {
  const dbConn = await db();
  if (!dbConn) return 0;
  let collected = 0;

  const sourceDef = SOURCE_DEFINITIONS.find(s => s.sourceType === sourceType);
  if (!sourceDef) return 0;

  // Live scanner sources → call real APIs
  if (sourceType === "phishing_campaigns" || sourceType === "gophish") {
    const liveEvidence = await collectGophishEvidence();
    for (const ev of liveEvidence) {
      let threatActorMatches: any[] = [];
      if (ev.techniqueIds?.length) {
        threatActorMatches = await crossRefThreatCatalog(ev.techniqueIds, dbConn);
      }
      for (const ksiId of sourceDef.ksiMappings) {
        await insertScheduledEvidence(dbConn, ksiId, ev.title, ev.description, "gophish-live",
          { ...ev.evidenceData, threatActorMatches: threatActorMatches.slice(0, 5), liveCollection: true },
          userId, userName);
        collected++;
      }
    }
    return collected;
  }

  if (sourceType === "atomic_red_team" || sourceType === "caldera") {
    const liveEvidence = await collectCalderaEvidence();
    for (const ev of liveEvidence) {
      let threatActorMatches: any[] = [];
      if (ev.techniqueIds?.length) {
        threatActorMatches = await crossRefThreatCatalog(ev.techniqueIds, dbConn);
      }
      for (const ksiId of sourceDef.ksiMappings) {
        await insertScheduledEvidence(dbConn, ksiId, ev.title, ev.description, "caldera-live",
          { ...ev.evidenceData, threatActorMatches: threatActorMatches.slice(0, 5), liveCollection: true },
          userId, userName);
        collected++;
      }
    }
    return collected;
  }

  if (sourceType === "web_app_scanner" || sourceType === "zap") {
    const liveEvidence = await collectZapEvidence();
    for (const ev of liveEvidence) {
      let threatActorMatches: any[] = [];
      if (ev.techniqueIds?.length) {
        threatActorMatches = await crossRefThreatCatalog(ev.techniqueIds, dbConn);
      }
      for (const ksiId of sourceDef.ksiMappings) {
        await insertScheduledEvidence(dbConn, ksiId, ev.title, ev.description, "zap-live",
          { ...ev.evidenceData, threatActorMatches: threatActorMatches.slice(0, 5), liveCollection: true },
          userId, userName);
        collected++;
      }
    }
    return collected;
  }

  // DB-backed sources → count records from local tables
  const tableMap: Record<string, { table: any; countCol: any }> = {};
  try {
    const schema = await import("../../drizzle/schema");
    tableMap["vuln_scanner"] = { table: schema.vulnScanFindings, countCol: count() };
    tableMap["osint_recon"] = { table: schema.osintFindings, countCol: count() };
    tableMap["darkweb_intel"] = { table: schema.darkWebRecords, countCol: count() };
    tableMap["edr_validation"] = { table: schema.edrTestResults, countCol: count() };
    tableMap["ngfw_validation"] = { table: schema.ngfwValidationTests, countCol: count() };
    tableMap["ad_attack_sim"] = { table: schema.adAttackSimulations, countCol: count() };
    tableMap["cloud_misconfigs"] = { table: schema.cloudMisconfigurations, countCol: count() };
    tableMap["threat_intel"] = { table: schema.threatActors, countCol: count() };
  } catch { /* tables may not exist */ }

  const entry = tableMap[sourceType];
  if (entry) {
    const rows = await dbConn.select({ count: count() }).from(entry.table);
    const rowCount = rows[0]?.count || 0;
    if (rowCount > 0) {
      for (const ksiId of sourceDef.ksiMappings) {
        await insertScheduledEvidence(dbConn, ksiId,
          `Scheduled Collection: ${sourceDef.displayName}`,
          `${rowCount} records collected from ${sourceDef.displayName}`,
          sourceType,
          { recordCount: rowCount, sweepTime: new Date().toISOString(), liveCollection: false },
          userId, userName);
        collected++;
      }
    }
  }

  return collected;
}

export const ksiScheduledCollectionRouter = router({
  // Initialize all default schedules
  initializeSchedules: protectedProcedure.mutation(async () => {
    const { collectionSchedules } = await import("../../drizzle/schema");
    const now = Date.now();
    let created = 0;

    for (const src of SOURCE_DEFINITIONS) {
      const existing = await (await db()).select().from(collectionSchedules)
        .where(eq(collectionSchedules.sourceType, src.sourceType));

      if (existing.length === 0) {
        const cadenceMs = CADENCE_MS[src.defaultCadence] || CADENCE_MS.daily;
        await (await db()).insert(collectionSchedules).values({
          id: randomUUID(),
          sourceType: src.sourceType,
          displayName: src.displayName,
          enabled: true,
          cadence: src.defaultCadence,
          lastRunAt: null,
          nextRunAt: now + cadenceMs,
          lastStatus: "never_run",
          lastError: null,
          lastEvidenceCount: 0,
          totalRuns: 0,
          totalEvidenceCollected: 0,
          createdAt: now,
          updatedAt: now,
        });
        created++;
      }
    }

    return { created, total: SOURCE_DEFINITIONS.length };
  }),

  // List all schedules
  listSchedules: protectedProcedure.query(async () => {
    const { collectionSchedules } = await import("../../drizzle/schema");
    return (await db()).select().from(collectionSchedules).orderBy(collectionSchedules.displayName);
  }),

  // Update a schedule's cadence or enabled state
  updateSchedule: protectedProcedure
    .input(z.object({
      scheduleId: z.string(),
      enabled: z.boolean().optional(),
      cadence: z.enum(["hourly", "every_6h", "every_12h", "daily", "weekly"]).optional(),
    }))
    .mutation(async ({ input }) => {
      const { collectionSchedules } = await import("../../drizzle/schema");
      const now = Date.now();
      const updates: any = { updatedAt: now };

      if (input.enabled !== undefined) updates.enabled = input.enabled;
      if (input.cadence) {
        updates.cadence = input.cadence;
        // Recalculate next run time
        const cadenceMs = CADENCE_MS[input.cadence] || CADENCE_MS.daily;
        updates.nextRunAt = now + cadenceMs;
      }

      await (await db()).update(collectionSchedules).set(updates).where(eq(collectionSchedules.id, input.scheduleId));
      return { success: true };
    }),

  // Run a specific source collection manually
  runCollection: protectedProcedure
    .input(z.object({ sourceType: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const { collectionSchedules, collectionJobHistory } = await import("../../drizzle/schema");
      const now = Date.now();
      const jobId = randomUUID();

      // Record job start
      await (await db()).insert(collectionJobHistory).values({
        id: jobId,
        scheduleId: "",
        sourceType: input.sourceType,
        status: "running",
        startedAt: now,
        completedAt: null,
        evidenceCollected: 0,
        errorMessage: null,
        triggeredBy: ctx.user?.name || "manual",
      });

      try {
        // Call the live scanner integration for this source type
        const evidenceCount = await collectLiveForSource(input.sourceType, ctx.user?.id, ctx.user?.name);

        // Update job as completed
        await (await db()).update(collectionJobHistory).set({
          status: "completed",
          completedAt: Date.now(),
          evidenceCollected: evidenceCount,
        }).where(eq(collectionJobHistory.id, jobId));

        // Update the schedule record
        const [schedule] = await (await db()).select().from(collectionSchedules)
          .where(eq(collectionSchedules.sourceType, input.sourceType));

        if (schedule) {
          const cadenceMs = CADENCE_MS[schedule.cadence] || CADENCE_MS.daily;
          await (await db()).update(collectionSchedules).set({
            lastRunAt: now,
            nextRunAt: now + cadenceMs,
            lastStatus: "success",
            lastError: null,
            lastEvidenceCount: evidenceCount,
            totalRuns: (schedule.totalRuns || 0) + 1,
            totalEvidenceCollected: (schedule.totalEvidenceCollected || 0) + evidenceCount,
            updatedAt: now,
          }).where(eq(collectionSchedules.id, schedule.id));
        }

        return { jobId, evidenceCollected: evidenceCount, status: "completed" };
      } catch (err: any) {
        await (await db()).update(collectionJobHistory).set({
          status: "failed",
          completedAt: Date.now(),
          errorMessage: err.message,
        }).where(eq(collectionJobHistory.id, jobId));

        // Update schedule with failure
        const [schedule] = await (await db()).select().from(collectionSchedules)
          .where(eq(collectionSchedules.sourceType, input.sourceType));
        if (schedule) {
          await (await db()).update(collectionSchedules).set({
            lastRunAt: now,
            lastStatus: "failure",
            lastError: err.message,
            totalRuns: (schedule.totalRuns || 0) + 1,
            updatedAt: now,
          }).where(eq(collectionSchedules.id, schedule.id));
        }

        throw err;
      }
    }),

  // Run all enabled schedules that are due
  runDueCollections: protectedProcedure.mutation(async ({ ctx }) => {
    const { collectionSchedules } = await import("../../drizzle/schema");
    const now = Date.now();

    const dueSchedules = await (await db()).select().from(collectionSchedules)
      .where(and(
        eq(collectionSchedules.enabled, true),
        lte(collectionSchedules.nextRunAt, now),
      ));

    let ran = 0;
    let totalEvidence = 0;

    for (const schedule of dueSchedules) {
      try {
        // Live collection for each due source
        const evidenceCount = await collectLiveForSource(schedule.sourceType, ctx.user?.id, ctx.user?.name);
        const cadenceMs = CADENCE_MS[schedule.cadence] || CADENCE_MS.daily;

        await (await db()).update(collectionSchedules).set({
          lastRunAt: now,
          nextRunAt: now + cadenceMs,
          lastStatus: "success",
          lastError: null,
          lastEvidenceCount: evidenceCount,
          totalRuns: (schedule.totalRuns || 0) + 1,
          totalEvidenceCollected: (schedule.totalEvidenceCollected || 0) + evidenceCount,
          updatedAt: now,
        }).where(eq(collectionSchedules.id, schedule.id));

        ran++;
        totalEvidence += evidenceCount;
      } catch (err: any) {
        await (await db()).update(collectionSchedules).set({
          lastRunAt: now,
          lastStatus: "failure",
          lastError: err.message,
          totalRuns: (schedule.totalRuns || 0) + 1,
          updatedAt: now,
        }).where(eq(collectionSchedules.id, schedule.id));
      }
    }

    return { schedulesRun: ran, totalEvidence, dueCount: dueSchedules.length };
  }),

  // Get job history
  getJobHistory: protectedProcedure
    .input(z.object({
      sourceType: z.string().optional(),
      limit: z.number().default(50),
    }))
    .query(async ({ input }) => {
      const { collectionJobHistory } = await import("../../drizzle/schema");
      const conditions: any[] = [];
      if (input.sourceType) conditions.push(eq(collectionJobHistory.sourceType, input.sourceType));
      const where = conditions.length > 0 ? and(...conditions) : undefined;

      return (await db()).select().from(collectionJobHistory)
        .where(where)
        .orderBy(desc(collectionJobHistory.startedAt))
        .limit(input.limit);
    }),

  // Get dashboard stats
  getDashboardStats: protectedProcedure.query(async () => {
    const { collectionSchedules, collectionJobHistory } = await import("../../drizzle/schema");
    const now = Date.now();

    const schedules = await (await db()).select().from(collectionSchedules);
    const enabledCount = schedules.filter(s => s.enabled).length;
    const dueCount = schedules.filter(s => s.enabled && s.nextRunAt && s.nextRunAt <= now).length;
    const failedCount = schedules.filter(s => s.lastStatus === "failure").length;
    const totalEvidence = schedules.reduce((sum, s) => sum + (s.totalEvidenceCollected || 0), 0);
    const totalRuns = schedules.reduce((sum, s) => sum + (s.totalRuns || 0), 0);

    // Get recent jobs
    const recentJobs = await (await db()).select().from(collectionJobHistory)
      .orderBy(desc(collectionJobHistory.startedAt))
      .limit(10);

    return {
      totalSchedules: schedules.length,
      enabledCount,
      dueCount,
      failedCount,
      totalEvidence,
      totalRuns,
      recentJobs,
      sourceDefinitions: SOURCE_DEFINITIONS.map(s => ({
        sourceType: s.sourceType,
        displayName: s.displayName,
        ksiMappings: s.ksiMappings,
      })),
    };
  }),
});
