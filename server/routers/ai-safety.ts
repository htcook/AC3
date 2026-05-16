/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * AI SAFETY ROUTER — tRPC endpoints for:
 *   - Autonomy level management (get, override, clear suspension)
 *   - Audit log queries (tenant-scoped)
 *   - Safety dashboard stats
 * ═══════════════════════════════════════════════════════════════════════════════
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import { aiAuditLogs, autonomyOverrides } from "../../drizzle/schema";
import { eq, and, desc, sql, count, gte } from "drizzle-orm";
import {
  evaluateAutonomyLevel,
  canExecuteAction,
  getAutonomyDescription,
  evaluateAnomaly,
  buildAutonomyContext,
  type AutonomyLevel,
  type RoeEngagementType,
  type GraduationTier,
  type ActionCategory,
} from "../lib/graduated-autonomy";
import { queryAuditLogs, flushAuditBufferToDb } from "../lib/ai-safety-middleware";

export const aiSafetyRouter = router({
  // ═══════════════════════════════════════════════════════════════════════════
  // AUTONOMY LEVEL MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /** Get the current autonomy state for an engagement */
  getAutonomyState: protectedProcedure
    .input(z.object({
      engagementId: z.string(),
      roeType: z.enum([
        "vulnerability_scanning", "penetration_testing", "red_team",
        "phishing", "social_engineering", "physical", "purple_team",
      ]),
      graduationTier: z.number().min(1).max(5),
    }))
    .query(async ({ input }) => {
      const db = getDb();

      // Check for active operator override
      let operatorOverride: number | undefined;
      if (db) {
        const [override] = await db.select()
          .from(autonomyOverrides)
          .where(and(
            eq(autonomyOverrides.engagementId, input.engagementId),
            eq(autonomyOverrides.active, 1),
          ))
          .orderBy(desc(autonomyOverrides.createdAt))
          .limit(1);

        if (override) {
          // Check if expired
          if (override.expiresAt && new Date(override.expiresAt) < new Date()) {
            // Mark as inactive
            await db.update(autonomyOverrides)
              .set({ active: 0 })
              .where(eq(autonomyOverrides.id, override.id));
          } else {
            operatorOverride = override.overrideLevel as AutonomyLevel;
          }
        }
      }

      const state = evaluateAutonomyLevel({
        roeType: input.roeType as RoeEngagementType,
        graduationTier: input.graduationTier as GraduationTier,
        operatorOverride: operatorOverride as AutonomyLevel | undefined,
      });

      const description = getAutonomyDescription(state.currentLevel);
      const contextPrompt = buildAutonomyContext(state);

      return {
        ...state,
        description,
        contextPrompt,
        hasActiveOverride: operatorOverride !== undefined,
      };
    }),

  /** Set an operator override for an engagement's autonomy level */
  setAutonomyOverride: protectedProcedure
    .input(z.object({
      engagementId: z.string(),
      overrideLevel: z.number().min(0).max(3),
      previousLevel: z.number().min(0).max(3),
      reason: z.string().min(10, "Reason must be at least 10 characters"),
      expiresInHours: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = getDb();
      if (!db) throw new Error("Database not available");

      // Deactivate any existing overrides for this engagement
      await db.update(autonomyOverrides)
        .set({ active: 0 })
        .where(and(
          eq(autonomyOverrides.engagementId, input.engagementId),
          eq(autonomyOverrides.active, 1),
        ));

      // Insert new override
      const expiresAt = input.expiresInHours
        ? new Date(Date.now() + input.expiresInHours * 3600_000).toISOString().slice(0, 19).replace("T", " ")
        : null;

      await db.insert(autonomyOverrides).values({
        engagementId: input.engagementId,
        overrideLevel: input.overrideLevel,
        previousLevel: input.previousLevel,
        reason: input.reason,
        setBy: ctx.user!.id,
        setByName: ctx.user!.name || "Unknown",
        expiresAt,
        active: 1,
      });

      return {
        success: true,
        newLevel: input.overrideLevel,
        expiresAt,
      };
    }),

  /** Clear an active autonomy override (restore computed level) */
  clearAutonomyOverride: protectedProcedure
    .input(z.object({
      engagementId: z.string(),
    }))
    .mutation(async ({ input }) => {
      const db = getDb();
      if (!db) throw new Error("Database not available");

      await db.update(autonomyOverrides)
        .set({ active: 0 })
        .where(and(
          eq(autonomyOverrides.engagementId, input.engagementId),
          eq(autonomyOverrides.active, 1),
        ));

      return { success: true };
    }),

  /** Get override history for an engagement */
  getOverrideHistory: protectedProcedure
    .input(z.object({
      engagementId: z.string(),
      limit: z.number().optional().default(20),
    }))
    .query(async ({ input }) => {
      const db = getDb();
      if (!db) return [];

      return db.select()
        .from(autonomyOverrides)
        .where(eq(autonomyOverrides.engagementId, input.engagementId))
        .orderBy(desc(autonomyOverrides.createdAt))
        .limit(input.limit);
    }),

  /** Check if a specific action is permitted at the current autonomy level */
  checkActionPermission: protectedProcedure
    .input(z.object({
      engagementId: z.string(),
      roeType: z.enum([
        "vulnerability_scanning", "penetration_testing", "red_team",
        "phishing", "social_engineering", "physical", "purple_team",
      ]),
      graduationTier: z.number().min(1).max(5),
      actionCategory: z.enum([
        "passive_recon", "active_recon", "port_scanning", "vulnerability_scanning",
        "exploitation", "privilege_escalation", "lateral_movement", "persistence",
        "data_exfiltration", "c2_deployment", "social_engineering", "physical_access",
      ]),
      isInScope: z.boolean(),
    }))
    .query(async ({ input }) => {
      const state = evaluateAutonomyLevel({
        roeType: input.roeType as RoeEngagementType,
        graduationTier: input.graduationTier as GraduationTier,
      });

      return canExecuteAction({
        autonomyState: state,
        actionCategory: input.actionCategory as ActionCategory,
        isInScope: input.isInScope,
      });
    }),

  /** Get all autonomy level descriptions */
  getAutonomyLevels: protectedProcedure
    .query(() => {
      return [0, 1, 2, 3].map(level => ({
        level,
        ...getAutonomyDescription(level as AutonomyLevel),
      }));
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // AUDIT LOG QUERIES
  // ═══════════════════════════════════════════════════════════════════════════

  /** Query audit logs (tenant-scoped) */
  getAuditLogs: protectedProcedure
    .input(z.object({
      tenantId: z.string().optional(),
      engagementId: z.string().optional(),
      action: z.string().optional(),
      severity: z.enum(["info", "warning", "critical", "alert"]).optional(),
      limit: z.number().optional().default(50),
      offset: z.number().optional().default(0),
    }).optional())
    .query(async ({ input, ctx }) => {
      // Force tenant scoping — users can only see their own tenant's logs
      const tenantId = ctx.user?.openId || "default-tenant";
      return queryAuditLogs({
        tenantId,
        engagementId: input?.engagementId,
        action: input?.action,
        severity: input?.severity,
        limit: input?.limit,
        offset: input?.offset,
      });
    }),

  /** Get safety dashboard statistics */
  getSafetyStats: protectedProcedure
    .input(z.object({
      hoursBack: z.number().optional().default(24),
    }).optional())
    .query(async ({ input, ctx }) => {
      const db = getDb();
      if (!db) return {
        totalRequests: 0,
        blockedRequests: 0,
        injectionsDetected: 0,
        piiScrubbed: 0,
        crossTenantViolations: 0,
        avgResponseTime: 0,
      };

      const tenantId = ctx.user?.openId || "default-tenant";
      const since = new Date(Date.now() - (input?.hoursBack || 24) * 3600_000)
        .toISOString().slice(0, 19).replace("T", " ");

      const [stats] = await db.select({
        totalRequests: count(),
        blockedRequests: sql<number>`SUM(CASE WHEN action_blocked = 1 THEN 1 ELSE 0 END)`,
        injectionsDetected: sql<number>`SUM(CASE WHEN injection_detected = 1 THEN 1 ELSE 0 END)`,
        piiScrubbed: sql<number>`SUM(CASE WHEN pii_detected = 1 THEN 1 ELSE 0 END)`,
        crossTenantViolations: sql<number>`SUM(CASE WHEN cross_tenant_violation = 1 THEN 1 ELSE 0 END)`,
        avgResponseTime: sql<number>`AVG(response_time_ms)`,
      })
        .from(aiAuditLogs)
        .where(and(
          eq(aiAuditLogs.tenantId, tenantId),
          gte(aiAuditLogs.createdAt, since),
        ));

      return {
        totalRequests: (stats as any)?.totalRequests || 0,
        blockedRequests: Number((stats as any)?.blockedRequests) || 0,
        injectionsDetected: Number((stats as any)?.injectionsDetected) || 0,
        piiScrubbed: Number((stats as any)?.piiScrubbed) || 0,
        crossTenantViolations: Number((stats as any)?.crossTenantViolations) || 0,
        avgResponseTime: Math.round(Number((stats as any)?.avgResponseTime) || 0),
      };
    }),

  /** Force flush the audit buffer to database */
  flushAuditBuffer: protectedProcedure
    .mutation(async () => {
      const flushed = await flushAuditBufferToDb();
      return { flushed };
    }),
});
