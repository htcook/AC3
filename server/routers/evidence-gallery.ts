/**
 * Evidence Gallery Router
 *
 * Provides:
 *   1. PNG export of rendered HTML evidence panels
 *   2. Gallery listing of auto-captured evidence snapshots per engagement
 *   3. Filtering by phase, agent, and operation
 *   4. Live Caldera evidence capture on demand
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { assertEngagementAccess } from "../lib/engagement-access-guard";
import { TRPCError } from "@trpc/server";
import { getDb as _getDb } from "../db";
import { evidenceItems, evidenceChainOfCustody, engagements } from "../../drizzle/schema";
import { eq, desc, like, and, or, sql, inArray } from "drizzle-orm";
import crypto from "crypto";
import { doStoragePut } from "../do-storage";
import {
  captureCalderaEvidence,
  renderEvidenceToFile,
  type CalderaEvidenceSnapshot,
  type AgentEvidence,
} from "../lib/caldera-evidence-collector";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  return db;
}

// ─── Evidence panel types for export ───────────────────────────────────
const PANEL_TYPES = ["agentTable", "operationTimeline", "adversaryProfile", "attackChainSummary"] as const;
type PanelType = typeof PANEL_TYPES[number];

const panelLabels: Record<PanelType, string> = {
  agentTable: "C2 Agent Check-Ins",
  operationTimeline: "Operation Timeline",
  adversaryProfile: "Adversary Profile",
  attackChainSummary: "Attack Chain Summary",
};

export const evidenceGalleryRouter = router({
  // ─── Capture live Caldera evidence for an engagement ───
  captureEvidence: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      operationId: z.string().optional(),
      adversaryId: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      await assertEngagementAccess(ctx.user, input.engagementId);
      const db = await getDbSafe();

      // Get engagement details
      const [eng] = await db.select().from(engagements)
        .where(eq(engagements.id, input.engagementId));
      if (!eng) throw new TRPCError({ code: "NOT_FOUND", message: "Engagement not found" });

      const snapshot = await captureCalderaEvidence({
        engagementId: input.engagementId,
        engagementName: eng.name,
        operationId: input.operationId,
        adversaryId: input.adversaryId,
        targets: [],
      });

      if (!snapshot) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to capture Caldera evidence. Check Caldera connection." });
      }

      // Store each rendered panel as an evidence item
      const createdItems: string[] = [];
      for (const panelType of PANEL_TYPES) {
        const html = snapshot.renderedHtml[panelType];
        if (!html || html.includes("NO DATA")) continue;

        const evidenceId = `ev_cal_${crypto.randomBytes(6).toString("hex")}`;
        const suffix = crypto.randomBytes(4).toString("hex");
        const fileKey = `evidence-gallery/${input.engagementId}/${panelType}-${suffix}.html`;

        // Upload HTML to S3
        const { url } = await doStoragePut(fileKey, Buffer.from(html, "utf-8"), "text/html");

        await db.insert(evidenceItems).values({
          evidenceId,
          engagementId: String(input.engagementId),
          title: `${panelLabels[panelType]} — ${eng.name}`,
          description: `Auto-captured Caldera evidence: ${panelLabels[panelType]}`,
          type: "caldera_evidence",
          category: panelType,
          fileUrl: url,
          fileKey,
          fileName: `${panelType}.html`,
          mimeType: "text/html",
          tags: JSON.stringify([
            "caldera", "auto-captured", panelType,
            ...snapshot.agents.map((a: AgentEvidence) => `agent:${a.paw}`),
          ]),
          metadata: JSON.stringify({
            calderaServerUrl: snapshot.calderaServerUrl,
            calderaServerIp: snapshot.calderaServerIp,
            agentCount: snapshot.agents.length,
            operationCount: snapshot.operations.length,
            hasAdversary: !!snapshot.adversaryProfile,
            capturedAt: snapshot.capturedAt,
            panelType,
            phase: panelType === "agentTable" ? "exploitation" : "post-exploitation",
          }),
          classification: "confidential",
          collectedBy: "AC3 Auto-Collector",
          collectedAt: new Date(),
        });

        // Log chain of custody
        await db.insert(evidenceChainOfCustody).values({
          evidenceId,
          action: "auto_captured",
          performedBy: "AC3 Caldera Evidence Collector",
          details: `Auto-captured ${panelLabels[panelType]} from Caldera C2 (${snapshot.agents.length} agents)`,
        });

        createdItems.push(evidenceId);
      }

      return {
        success: true,
        itemsCreated: createdItems.length,
        evidenceIds: createdItems,
        snapshot: {
          agentCount: snapshot.agents.length,
          operationCount: snapshot.operations.length,
          hasAdversary: !!snapshot.adversaryProfile,
          capturedAt: snapshot.capturedAt,
          calderaServerUrl: snapshot.calderaServerUrl,
        },
      };
    }),

  // ─── Export evidence panel as PNG ───
  exportPng: protectedProcedure
    .input(z.object({
      evidenceId: z.string(),
    }))
    .mutation(async ({ input, ctx }) => {
      await assertEngagementAccess(ctx.user, input.engagementId);
      const db = await getDbSafe();
      const [item] = await db.select().from(evidenceItems)
        .where(eq(evidenceItems.evidenceId, input.evidenceId));
      if (!item) throw new TRPCError({ code: "NOT_FOUND", message: "Evidence item not found" });

      if (!item.fileUrl) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "No file attached to this evidence item" });
      }

      // Fetch the HTML content
      let html: string;
      try {
        const resp = await fetch(item.fileUrl, { signal: AbortSignal.timeout(15000) });
        html = await resp.text();
      } catch {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to fetch evidence HTML" });
      }

      // Render to PNG
      const fs = await import("fs/promises");
      const tmpDir = "/tmp/evidence-export";
      await fs.mkdir(tmpDir, { recursive: true });
      const pngPath = `${tmpDir}/${input.evidenceId}.png`;

      const result = await renderEvidenceToFile(html, pngPath);

      if (!result.success) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to render evidence to PNG" });
      }

      // Upload rendered file to S3
      const fileBuffer = await fs.readFile(result.path);
      const suffix = crypto.randomBytes(4).toString("hex");
      const mimeType = result.format === "png" ? "image/png" : "text/html";
      const ext = result.format === "png" ? "png" : "html";
      const fileKey = `evidence-exports/${input.evidenceId}-${suffix}.${ext}`;

      const { url } = await doStoragePut(fileKey, fileBuffer, mimeType);

      // Log export in custody chain
      await db.insert(evidenceChainOfCustody).values({
        evidenceId: input.evidenceId,
        action: "exported",
        performedBy: "AC3 Evidence Exporter",
        details: `Exported as ${result.format.toUpperCase()} (${fileBuffer.length} bytes)`,
      });

      // Clean up temp files
      try { await fs.unlink(result.path); } catch {}
      try { await fs.unlink(result.path.replace(/\.(png|html)$/, ".html")); } catch {}

      return {
        url,
        format: result.format,
        size: fileBuffer.length,
      };
    }),

  // ─── Export evidence directly from live Caldera (no DB required) ───
  exportLive: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      panelType: z.enum(["agentTable", "operationTimeline", "adversaryProfile", "attackChainSummary"]),
      operationId: z.string().optional(),
      adversaryId: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      await assertEngagementAccess(ctx.user, input.engagementId);
      const db = await getDbSafe();
      const [eng] = await db.select().from(engagements)
        .where(eq(engagements.id, input.engagementId));
      if (!eng) throw new TRPCError({ code: "NOT_FOUND", message: "Engagement not found" });

      const snapshot = await captureCalderaEvidence({
        engagementId: input.engagementId,
        engagementName: eng.name,
        operationId: input.operationId,
        adversaryId: input.adversaryId,
        targets: [],
      });

      if (!snapshot) {
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Failed to capture Caldera evidence" });
      }

      const html = snapshot.renderedHtml[input.panelType];
      if (!html) {
        throw new TRPCError({ code: "BAD_REQUEST", message: `No data for panel type: ${input.panelType}` });
      }

      // Render to PNG
      const fs = await import("fs/promises");
      const tmpDir = "/tmp/evidence-export";
      await fs.mkdir(tmpDir, { recursive: true });
      const pngPath = `${tmpDir}/live-${input.panelType}-${Date.now()}.png`;

      const result = await renderEvidenceToFile(html, pngPath);
      const fileBuffer = await fs.readFile(result.path);
      const suffix = crypto.randomBytes(4).toString("hex");
      const mimeType = result.format === "png" ? "image/png" : "text/html";
      const ext = result.format === "png" ? "png" : "html";
      const fileKey = `evidence-exports/live-${input.panelType}-${suffix}.${ext}`;

      const { url } = await doStoragePut(fileKey, fileBuffer, mimeType);

      // Clean up
      try { await fs.unlink(result.path); } catch {}
      try { await fs.unlink(result.path.replace(/\.(png|html)$/, ".html")); } catch {}

      return {
        url,
        format: result.format,
        size: fileBuffer.length,
        panelType: input.panelType,
        label: panelLabels[input.panelType],
      };
    }),

  // ─── Gallery listing with filtering ───
  gallery: protectedProcedure
    .input(z.object({
      engagementId: z.string().optional(),
      phase: z.enum(["exploitation", "post-exploitation", "all"]).default("all"),
      agentPaw: z.string().optional(),
      operationId: z.string().optional(),
      panelType: z.enum(["agentTable", "operationTimeline", "adversaryProfile", "attackChainSummary", "all"]).default("all"),
      limit: z.number().min(1).max(100).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [
        eq(evidenceItems.type, "caldera_evidence"),
      ];

      if (input?.engagementId) {
        filters.push(eq(evidenceItems.engagementId, input.engagementId));
      }
      if (input?.panelType && input.panelType !== "all") {
        filters.push(eq(evidenceItems.category, input.panelType));
      }

      const where = and(...filters);

      const [items, countResult] = await Promise.all([
        db.select().from(evidenceItems).where(where)
          .orderBy(desc(evidenceItems.createdAt))
          .limit(input?.limit ?? 50)
          .offset(input?.offset ?? 0),
        db.select({ count: sql<number>`count(*)` }).from(evidenceItems).where(where),
      ]);

      // Post-filter by phase and agent (stored in metadata/tags JSON)
      let filtered = items;
      if (input?.phase && input.phase !== "all") {
        filtered = filtered.filter(item => {
          try {
            const meta = typeof item.metadata === "string" ? JSON.parse(item.metadata) : item.metadata;
            return meta?.phase === input.phase;
          } catch { return true; }
        });
      }
      if (input?.agentPaw) {
        filtered = filtered.filter(item => {
          try {
            const tags = typeof item.tags === "string" ? JSON.parse(item.tags) : item.tags;
            return Array.isArray(tags) && tags.some((t: string) => t.includes(input.agentPaw!));
          } catch { return true; }
        });
      }

      // Parse metadata for each item
      const enriched = filtered.map(item => {
        let meta: any = {};
        try {
          meta = typeof item.metadata === "string" ? JSON.parse(item.metadata) : (item.metadata || {});
        } catch {}
        let tags: string[] = [];
        try {
          tags = typeof item.tags === "string" ? JSON.parse(item.tags) : (item.tags || []);
        } catch {}

        return {
          ...item,
          parsedMetadata: meta,
          parsedTags: tags,
          panelLabel: panelLabels[meta.panelType as PanelType] || meta.panelType || item.category || "Unknown",
        };
      });

      return {
        items: enriched,
        total: Number(countResult[0]?.count ?? 0),
        filteredTotal: enriched.length,
      };
    }),

  // ─── Gallery stats per engagement ───
  galleryStats: protectedProcedure
    .input(z.object({
      engagementId: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const filters: any[] = [eq(evidenceItems.type, "caldera_evidence")];
      if (input?.engagementId) {
        filters.push(eq(evidenceItems.engagementId, input.engagementId));
      }
      const where = and(...filters);

      const [totalResult] = await db.select({ count: sql<number>`count(*)` }).from(evidenceItems).where(where);
      const categoryBreakdown = await db.select({
        category: evidenceItems.category,
        count: sql<number>`count(*)`,
      }).from(evidenceItems).where(where).groupBy(evidenceItems.category);

      // Get unique engagements with evidence
      const engagementBreakdown = await db.select({
        engagementId: evidenceItems.engagementId,
        count: sql<number>`count(*)`,
      }).from(evidenceItems).where(where).groupBy(evidenceItems.engagementId);

      return {
        total: Number(totalResult?.count ?? 0),
        byCategory: categoryBreakdown.map(r => ({
          category: r.category,
          label: panelLabels[r.category as PanelType] || r.category || "Unknown",
          count: Number(r.count),
        })),
        byEngagement: engagementBreakdown.map(r => ({
          engagementId: r.engagementId,
          count: Number(r.count),
        })),
      };
    }),

  // ─── List engagements with evidence ───
  engagementsWithEvidence: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const result = await db.select({
      engagementId: evidenceItems.engagementId,
      count: sql<number>`count(*)`,
      latestCapture: sql<string>`MAX(${evidenceItems.createdAt})`,
    })
      .from(evidenceItems)
      .where(eq(evidenceItems.type, "caldera_evidence"))
      .groupBy(evidenceItems.engagementId);

    // Enrich with engagement names
    const engIds = result.map(r => r.engagementId).filter(Boolean) as string[];
    let engMap = new Map<string, string>();
    if (engIds.length > 0) {
      const numericIds = engIds.map(Number).filter(n => !isNaN(n));
      if (numericIds.length > 0) {
        const engs = await db.select({ id: engagements.id, name: engagements.name })
          .from(engagements)
          .where(inArray(engagements.id, numericIds));
        for (const e of engs) {
          engMap.set(String(e.id), e.name);
        }
      }
    }

    return result.map(r => ({
      engagementId: r.engagementId,
      engagementName: engMap.get(r.engagementId || "") || `Engagement ${r.engagementId}`,
      evidenceCount: Number(r.count),
      latestCapture: r.latestCapture,
    }));
  }),
});
