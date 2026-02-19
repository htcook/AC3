/**
 * Attack Path Visualization Router
 * Manages attack path graphs showing how vulnerabilities chain across assets.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb as _getDb } from "../db";
import { attackPaths, domainIntelScans, discoveredAssets } from "../../drizzle/schema";
import { eq, desc, like, and, sql } from "drizzle-orm";
import crypto from "crypto";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}

function generateId() {
  return `ap_${crypto.randomBytes(8).toString("hex")}`;
}

// Node types for attack path visualization
const nodeSchema = z.object({
  id: z.string(),
  label: z.string(),
  type: z.enum(["entry", "asset", "vulnerability", "technique", "objective", "pivot"]),
  data: z.any().optional(),
  x: z.number().optional(),
  y: z.number().optional(),
});

const edgeSchema = z.object({
  id: z.string(),
  source: z.string(),
  target: z.string(),
  label: z.string().optional(),
  type: z.enum(["exploits", "leads_to", "enables", "requires", "lateral_move"]).optional(),
  weight: z.number().optional(),
});

export const attackPathsRouter = router({
  // ─── List attack paths ───
  list: protectedProcedure
    .input(z.object({
      search: z.string().optional(),
      engagementId: z.string().optional(),
      status: z.string().optional(),
      limit: z.number().min(1).max(100).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [];
      if (input?.search) filters.push(like(attackPaths.name, `%${input.search}%`));
      if (input?.engagementId) filters.push(eq(attackPaths.engagementId, input.engagementId));
      if (input?.status) filters.push(eq(attackPaths.status, input.status));
      const where = filters.length > 0 ? and(...filters) : undefined;

      const [items, countResult] = await Promise.all([
        db.select().from(attackPaths).where(where)
          .orderBy(desc(attackPaths.createdAt))
          .limit(input?.limit ?? 50)
          .offset(input?.offset ?? 0),
        db.select({ count: sql<number>`count(*)` }).from(attackPaths).where(where),
      ]);
      return { items, total: Number(countResult[0]?.count ?? 0) };
    }),

  // ─── Get single attack path ───
  get: protectedProcedure
    .input(z.object({ pathId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [path] = await db.select().from(attackPaths)
        .where(eq(attackPaths.pathId, input.pathId));
      if (!path) throw new TRPCError({ code: "NOT_FOUND", message: "Attack path not found" });
      return path;
    }),

  // ─── Create attack path ───
  create: protectedProcedure
    .input(z.object({
      name: z.string().min(1),
      description: z.string().optional(),
      engagementId: z.string().optional(),
      nodes: z.array(nodeSchema).optional(),
      edges: z.array(edgeSchema).optional(),
      riskScore: z.number().min(0).max(100).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const pathId = generateId();
      await db.insert(attackPaths).values({
        pathId,
        name: input.name,
        description: input.description,
        engagementId: input.engagementId,
        nodes: input.nodes ? JSON.stringify(input.nodes) : JSON.stringify([]),
        edges: input.edges ? JSON.stringify(input.edges) : JSON.stringify([]),
        riskScore: input.riskScore,
        status: "draft",
        createdBy: ctx.user.id,
      });
      return { pathId };
    }),

  // ─── Update attack path ───
  update: protectedProcedure
    .input(z.object({
      pathId: z.string(),
      name: z.string().optional(),
      description: z.string().optional(),
      nodes: z.array(nodeSchema).optional(),
      edges: z.array(edgeSchema).optional(),
      riskScore: z.number().min(0).max(100).optional(),
      status: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const updates: any = {};
      if (input.name !== undefined) updates.name = input.name;
      if (input.description !== undefined) updates.description = input.description;
      if (input.nodes !== undefined) updates.nodes = JSON.stringify(input.nodes);
      if (input.edges !== undefined) updates.edges = JSON.stringify(input.edges);
      if (input.riskScore !== undefined) updates.riskScore = input.riskScore;
      if (input.status !== undefined) updates.status = input.status;

      await db.update(attackPaths).set(updates)
        .where(eq(attackPaths.pathId, input.pathId));
      return { success: true };
    }),

  // ─── Delete attack path ───
  delete: protectedProcedure
    .input(z.object({ pathId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.delete(attackPaths).where(eq(attackPaths.pathId, input.pathId));
      return { success: true };
    }),

  // ─── Generate attack path from scan results ───
  generateFromScan: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      // Get scan
      const scanIdNum = parseInt(input.scanId, 10);
      if (isNaN(scanIdNum)) throw new TRPCError({ code: "BAD_REQUEST", message: "Invalid scan ID" });
      const [scan] = await db.select().from(domainIntelScans)
        .where(eq(domainIntelScans.id, scanIdNum));
      if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found" });

      // Get assets for this scan
      const assets = await db.select().from(discoveredAssets)
        .where(eq(discoveredAssets.scanId, scan.id));

      // Build attack path from assets and findings
      const nodes: any[] = [];
      const edges: any[] = [];
      let nodeIdx = 0;

      // Entry point node
      const entryId = `n_${nodeIdx++}`;
      nodes.push({
        id: entryId,
        label: "External Attacker",
        type: "entry",
        data: { description: "Initial access from internet" },
      });

      // Add asset nodes
      const assetNodeMap = new Map<string, string>();
      for (const asset of assets) {
        const nodeId = `n_${nodeIdx++}`;
        assetNodeMap.set(String(asset.id), nodeId);
        const findings = Array.isArray(asset.postureFindings) ? asset.postureFindings : [];
        const riskLevel = (asset.hybridRiskScore ?? 0) > 70 ? "critical" :
                          (asset.hybridRiskScore ?? 0) > 50 ? "high" :
                          (asset.hybridRiskScore ?? 0) > 30 ? "medium" : "low";
        nodes.push({
          id: nodeId,
          label: asset.hostname || `Asset ${asset.id}`,
          type: "asset",
          data: {
            hostname: asset.hostname,
            riskScore: asset.hybridRiskScore,
            riskLevel,
            findingCount: findings.length,
          },
        });

        // Connect entry to internet-facing assets
        edges.push({
          id: `e_${edges.length}`,
          source: entryId,
          target: nodeId,
          label: "targets",
          type: "leads_to",
        });

        // Add vulnerability nodes for high-risk findings
        const highRiskFindings = findings.filter((f: any) =>
          f.severity === "critical" || f.severity === "high"
        );
        for (const finding of highRiskFindings.slice(0, 3)) {
          const vulnId = `n_${nodeIdx++}`;
          nodes.push({
            id: vulnId,
            label: finding.title || finding.type || "Vulnerability",
            type: "vulnerability",
            data: { severity: finding.severity, description: finding.description },
          });
          edges.push({
            id: `e_${edges.length}`,
            source: nodeId,
            target: vulnId,
            label: "exposes",
            type: "exploits",
          });
        }
      }

      // Add objective node
      const objectiveId = `n_${nodeIdx++}`;
      nodes.push({
        id: objectiveId,
        label: "Data Exfiltration",
        type: "objective",
        data: { description: "Attacker objective" },
      });

      // Connect high-risk assets to objective
      for (const asset of assets.filter(a => (a.hybridRiskScore ?? 0) > 50)) {
        const nodeId = assetNodeMap.get(String(asset.id));
        if (nodeId) {
          edges.push({
            id: `e_${edges.length}`,
            source: nodeId,
            target: objectiveId,
            label: "enables",
            type: "enables",
          });
        }
      }

      // Calculate overall risk score
      const avgRisk = assets.length > 0
        ? Math.round(assets.reduce((sum, a) => sum + (a.hybridRiskScore ?? 0), 0) / assets.length)
        : 0;

      const pathId = generateId();
      await db.insert(attackPaths).values({
        pathId,
        name: `Attack Path - ${scan.primaryDomain}`,
        description: `Auto-generated attack path from domain scan of ${scan.primaryDomain}. ${assets.length} assets, ${nodes.length} nodes.`,
        engagementId: scan.engagementId ? String(scan.engagementId) : undefined,
        nodes: JSON.stringify(nodes),
        edges: JSON.stringify(edges),
        riskScore: avgRisk,
        status: "generated",
        createdBy: ctx.user.id,
      });

      return { pathId, nodeCount: nodes.length, edgeCount: edges.length, riskScore: avgRisk };
    }),

  // ─── Stats ───
  stats: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const [totalCount] = await db.select({ count: sql<number>`count(*)` }).from(attackPaths);
    return {
      total: Number(totalCount?.count ?? 0),
    };
  }),
});
