import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const vulnScannerRouter = router({
  listImports: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { vulnScanImports } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { desc } = await import("drizzle-orm");
    return db.select().from(vulnScanImports).orderBy(desc(vulnScanImports.importedAt));
  }),

  importScan: protectedProcedure
    .input(z.object({ scannerType: z.enum(["nessus", "qualys", "rapid7", "openvas", "custom"]), fileContent: z.string(), fileName: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const { getDb } = await import("../db");
      const { vulnScanImports, vulnScanFindings } = await import("../../drizzle/schema");
      const { parseVulnScan } = await import("../lib/vuln-scanner-parser");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

      const result = await parseVulnScan(input.scannerType, input.fileContent);

      const importResult = await db.insert(vulnScanImports).values({
        scannerType: input.scannerType,
        fileName: input.fileName,
        totalHosts: result.totalHosts,
        totalVulns: result.totalVulns,
        criticalCount: result.criticalCount,
        highCount: result.highCount,
        mediumCount: result.mediumCount,
        lowCount: result.lowCount,
        importedBy: String(ctx.user.id),
      });

      const importId = importResult[0].insertId;

      if (result.findings.length > 0) {
        const findingsToInsert = result.findings.map((f) => ({
          importId,
          cveId: f.cveId,
          title: f.title,
          severity: f.severity,
          cvssScore: f.cvssScore,
          hostIp: f.hostIp,
          hostName: f.hostName,
          port: f.port,
          protocol: f.protocol,
          description: f.description,
          solution: f.solution,
          pluginId: f.pluginId,
          exploitAvailable: f.exploitAvailable,
        }));
        await db.insert(vulnScanFindings).values(findingsToInsert);
      }

      return { id: importId, totalVulns: result.totalVulns, totalHosts: result.totalHosts };
    }),

  getImportDetails: protectedProcedure
    .input(z.object({ importId: z.number() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { vulnScanImports, vulnScanFindings } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      const scanImport = await db.select().from(vulnScanImports).where(eq(vulnScanImports.id, input.importId));
      if (!scanImport[0]) throw new TRPCError({ code: "NOT_FOUND", message: "Import not found" });
      const findings = await db.select().from(vulnScanFindings).where(eq(vulnScanFindings.importId, input.importId));
      return { import: scanImport[0], findings };
    }),

  listFindings: protectedProcedure
    .input(z.object({ importId: z.number().optional(), severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(), cveId: z.string().optional() }))
    .query(async ({ input }) => {
      const { getDb } = await import("../db");
      const { vulnScanFindings } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { and, eq } = await import("drizzle-orm");
      const conditions = [];
      if (input.importId) conditions.push(eq(vulnScanFindings.importId, input.importId));
      if (input.severity) conditions.push(eq(vulnScanFindings.severity, input.severity));
      if (input.cveId) conditions.push(eq(vulnScanFindings.cveId, input.cveId));
      return db.select().from(vulnScanFindings).where(conditions.length ? and(...conditions) : undefined);
    }),

  getStats: protectedProcedure.query(async () => {
    const { getDb } = await import("../db");
    const { vulnScanImports } = await import("../../drizzle/schema");
    const db = await getDb();
    if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
    const { sql } = await import("drizzle-orm");
    const result = await db.select({
      totalImports: sql<number>`count(*)`,
      totalHosts: sql<number>`COALESCE(sum(${vulnScanImports.totalHosts}), 0)`,
      totalVulns: sql<number>`COALESCE(sum(${vulnScanImports.totalVulns}), 0)`,
      critical: sql<number>`COALESCE(sum(${vulnScanImports.criticalCount}), 0)`,
      high: sql<number>`COALESCE(sum(${vulnScanImports.highCount}), 0)`,
      medium: sql<number>`COALESCE(sum(${vulnScanImports.mediumCount}), 0)`,
      low: sql<number>`COALESCE(sum(${vulnScanImports.lowCount}), 0)`,
    }).from(vulnScanImports);
    return result[0];
  }),

  deleteImport: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const { getDb } = await import("../db");
      const { vulnScanImports, vulnScanFindings } = await import("../../drizzle/schema");
      const db = await getDb();
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { eq } = await import("drizzle-orm");
      await db.transaction(async (tx) => {
        await tx.delete(vulnScanFindings).where(eq(vulnScanFindings.importId, input.id));
        await tx.delete(vulnScanImports).where(eq(vulnScanImports.id, input.id));
      });
      return { success: true };
    }),
});
