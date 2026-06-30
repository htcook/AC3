import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const domainHealthRouter = router({
  /**
   * Run a standalone domain health check (blacklist, SMTP, DNS, rDNS, connectivity).
   * Returns the full DomainHealthReport.
   */
  check: protectedProcedure
    .input(z.object({
      domain: z.string().min(1),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // ROE scope enforcement if engagement context provided
      if (input.engagementId) {
        const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
        await enforceTargetScope(input.engagementId, input.domain, "Domain Health Check", ctx);
      }
      const { runDomainHealthCheck } = await import("../lib/passive/domain-health");
      const report = await runDomainHealthCheck(input.domain);
      return report;
    }),

  /**
   * Get domain health data from an existing scan's pipelineOutput.
   * Avoids re-running the check if data already exists.
   */
  getFromScan: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { domainIntelScans } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const [scan] = await db.select({
        pipelineOutput: domainIntelScans.pipelineOutput,
      }).from(domainIntelScans).where(eq(domainIntelScans.id, input.scanId)).limit(1);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });
      const po = scan.pipelineOutput as any;
      return po?.domainHealth || null;
    }),
});
