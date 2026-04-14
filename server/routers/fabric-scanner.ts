/**
 * Microsoft Fabric Scanner Router
 *
 * tRPC procedures for scanning client Microsoft Fabric environments.
 * Integrates with the cloud credentials system for secure credential storage.
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  scanFabricEnvironment,
  validateFabricCredentials,
  checkTenantSecuritySettings,
  enumerateInfrastructure,
  type FabricCredentials,
} from "../lib/fabric-scanner";

// Helper to get Fabric credentials from stored cloud credential
async function getFabricCreds(credentialId: number): Promise<FabricCredentials> {
  const { getDb } = await import("../db");
  const { cloudCredentials } = await import("../../drizzle/schema");
  const { eq, and } = await import("drizzle-orm");
  const { decryptCredential } = await import("../lib/credential-crypto");

  const db = await getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

  const [cred] = await db
    .select()
    .from(cloudCredentials)
    .where(
      and(
        eq(cloudCredentials.id, credentialId),
        eq(cloudCredentials.credProvider, "azure")
      )
    )
    .limit(1);

  if (!cred) {
    throw new TRPCError({ code: "NOT_FOUND", message: "Cloud credential not found or not Azure type" });
  }

  const decrypted = decryptCredential({
    encryptedData: cred.encryptedData,
    iv: cred.encryptionIv,
    tag: cred.encryptionTag,
  });

  const parsed = JSON.parse(decrypted);
  return {
    tenantId: cred.tenantId || parsed.tenantId,
    clientId: parsed.clientId,
    clientSecret: parsed.clientSecret,
  };
}

export const fabricScannerRouter = router({
  /**
   * Validate Fabric credentials before running a scan
   */
  validateCredentials: protectedProcedure
    .input(z.object({ credentialId: z.number() }))
    .mutation(async ({ input }) => {
      const creds = await getFabricCreds(input.credentialId);
      return validateFabricCredentials(creds);
    }),

  /**
   * Run a full Fabric environment scan
   */
  runScan: protectedProcedure
    .input(
      z.object({
        credentialId: z.number(),
        engagementId: z.number().optional(),
        modifiedSince: z.string().datetime().optional(),
        includeLineage: z.boolean().default(false),
        includeDatasourceDetails: z.boolean().default(true),
        includeDatasetSchema: z.boolean().default(false),
        includeDatasetExpressions: z.boolean().default(false),
        includeArtifactUsers: z.boolean().default(true),
      })
    )
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudEnumerationRuns } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const creds = await getFabricCreds(input.credentialId);

      // Create enumeration run record
      const [run] = await db.insert(cloudEnumerationRuns).values({
        credentialId: input.credentialId,
        enumEngagementId: input.engagementId ?? null,
        enumProvider: "azure",
        enumStatus: "running",
        enumStartedAt: new Date().toISOString().slice(0, 19).replace("T", " "),
      } as any);

      const runId = (run as any).insertId;

      try {
        // Run the scan
        const result = await scanFabricEnvironment(creds, {
          modifiedSince: input.modifiedSince ? new Date(input.modifiedSince) : undefined,
          includeLineage: input.includeLineage,
          includeDatasourceDetails: input.includeDatasourceDetails,
          includeDatasetSchema: input.includeDatasetSchema,
          includeDatasetExpressions: input.includeDatasetExpressions,
          includeArtifactUsers: input.includeArtifactUsers,
        });

        // Also check tenant-level settings
        let tenantMisconfigs: any[] = [];
        try {
          tenantMisconfigs = await checkTenantSecuritySettings(creds);
        } catch { /* tenant settings may require higher permissions */ }

        // Enumerate infrastructure
        let infra: any = { capacities: [], gateways: [], misconfigurations: [] };
        try {
          infra = await enumerateInfrastructure(creds);
        } catch { /* infrastructure enum may require higher permissions */ }

        // Merge all misconfigurations
        const allMisconfigs = [
          ...result.misconfigurations,
          ...tenantMisconfigs,
          ...infra.misconfigurations,
        ];

        // Update run record
        await db
          .update(cloudEnumerationRuns)
          .set({
            enumStatus: result.errors.length > 0 ? "partial" : "completed",
            enumCompletedAt: new Date().toISOString().slice(0, 19).replace("T", " "),
            totalMisconfigsFound: allMisconfigs.length,
            enumResults: JSON.stringify({
              workspaces: result.workspaces,
              misconfigurations: allMisconfigs,
              infrastructure: infra,
              errors: result.errors,
            }),
          } as any)
          .where(eq(cloudEnumerationRuns.id, runId));

        return {
          runId,
          summary: {
            ...result.summary,
            totalMisconfigurations: allMisconfigs.length,
          },
          misconfigurations: allMisconfigs,
          workspaceCount: result.workspaces.length,
          errors: result.errors,
          infrastructure: {
            capacities: infra.capacities.length,
            gateways: infra.gateways.length,
          },
        };
      } catch (e: any) {
        // Update run as failed
        await db
          .update(cloudEnumerationRuns)
          .set({
            enumStatus: "error",
            enumCompletedAt: new Date().toISOString().slice(0, 19).replace("T", " "),
            enumErrorLog: JSON.stringify({ error: e.message }),
          } as any)
          .where(eq(cloudEnumerationRuns.id, runId));

        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Fabric scan failed: ${e.message}`,
        });
      }
    }),

  /**
   * Get scan history for a credential
   */
  getScanHistory: protectedProcedure
    .input(z.object({ credentialId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudEnumerationRuns } = await import("../../drizzle/schema");
      const { eq, desc } = await import("drizzle-orm");

      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const runs = await db
        .select()
        .from(cloudEnumerationRuns)
        .where(eq(cloudEnumerationRuns.credentialId, input.credentialId))
        .orderBy(desc(cloudEnumerationRuns.id))
        .limit(20);

      return runs.map((r: any) => ({
        id: r.id,
        status: r.enumStatus,
        startedAt: r.enumStartedAt,
        completedAt: r.enumCompletedAt,
        summary: r.enumResults ? JSON.parse(typeof r.enumResults === "string" ? r.enumResults : JSON.stringify(r.enumResults)).summary : null,
      }));
    }),

  /**
   * Get detailed results for a specific scan run
   */
  getScanResult: protectedProcedure
    .input(z.object({ runId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { cloudEnumerationRuns } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");

      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const [run] = await db
        .select()
        .from(cloudEnumerationRuns)
        .where(eq(cloudEnumerationRuns.id, input.runId))
        .limit(1);

      if (!run) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Scan run not found" });
      }

      const r = run as any;
      return {
        id: r.id,
        status: r.enumStatus,
        startedAt: r.enumStartedAt,
        completedAt: r.enumCompletedAt,
        data: r.enumResults ? (typeof r.enumResults === "string" ? JSON.parse(r.enumResults) : r.enumResults) : null,
        errors: r.enumErrorLog ? (typeof r.enumErrorLog === "string" ? JSON.parse(r.enumErrorLog) : r.enumErrorLog) : null,
      };
    }),
});
