/**
 * Evidence Persistence Helper
 *
 * Persists Caldera exploit/post-exploit evidence snapshots to the
 * `evidenceItems` table with S3 storage for HTML panels.
 * Used by the engagement orchestrator during automated scans
 * and by the evidence gallery router for manual captures.
 */
import crypto from "crypto";
import { getDb } from "../db";
import { evidenceItems, evidenceChainOfCustody } from "../../drizzle/schema";
import { doStoragePut } from "../do-storage";
import type { CalderaEvidenceSnapshot } from "./caldera-evidence-collector";

// ─── Panel metadata ───────────────────────────────────────────────────
const PANEL_TYPES = ["agentTable", "operationTimeline", "adversaryProfile", "attackChainSummary"] as const;
type PanelType = (typeof PANEL_TYPES)[number];

const panelLabels: Record<PanelType, string> = {
  agentTable: "C2 Agent Check-Ins",
  operationTimeline: "Operation Timeline",
  adversaryProfile: "Adversary Profile",
  attackChainSummary: "Attack Chain Summary",
};

const panelPhase: Record<PanelType, string> = {
  agentTable: "exploitation",
  operationTimeline: "post-exploitation",
  adversaryProfile: "post-exploitation",
  attackChainSummary: "post-exploitation",
};

export interface PersistEvidenceOptions {
  snapshot: CalderaEvidenceSnapshot;
  /** "exploitation" | "post_exploit" */
  phase: string;
  /** Optional integrity gate result to embed in metadata */
  integrityGate?: {
    passed: boolean;
    contentHash: string;
    provenanceValid: boolean;
    warnings: string[];
    errors: string[];
  };
}

/**
 * Persist all rendered HTML panels from a CalderaEvidenceSnapshot
 * into S3 + evidenceItems + chain-of-custody rows.
 *
 * Returns the number of evidence items persisted.
 */
export async function persistCalderaEvidence(opts: PersistEvidenceOptions): Promise<number> {
  const { snapshot, phase, integrityGate } = opts;
  const db = getDb();
  let persisted = 0;

  for (const panelType of PANEL_TYPES) {
    const html = snapshot.renderedHtml[panelType];
    if (!html || html.length < 50) continue; // skip empty/placeholder panels

    try {
      const evidenceId = `ev_cal_${crypto.randomBytes(6).toString("hex")}`;
      const suffix = crypto.randomBytes(4).toString("hex");
      const fileKey = `evidence-gallery/${snapshot.engagementId}/${phase}-${panelType}-${suffix}.html`;

      // Upload HTML to S3
      const { url } = await doStoragePut(fileKey, Buffer.from(html, "utf-8"), "text/html");

      await db.insert(evidenceItems).values({
        evidenceId,
        engagementId: String(snapshot.engagementId),
        title: `${panelLabels[panelType]} — ${snapshot.engagementName} (${phase})`,
        description: `Auto-captured Caldera evidence during ${phase} phase: ${panelLabels[panelType]}`,
        type: "caldera_evidence",
        category: panelType,
        fileUrl: url,
        fileKey,
        fileName: `${phase}-${panelType}.html`,
        mimeType: "text/html",
        tags: JSON.stringify([
          "caldera",
          "auto-captured",
          phase,
          panelType,
          ...snapshot.agents.map((a) => `agent:${a.paw}`),
        ]),
        metadata: JSON.stringify({
          calderaServerUrl: snapshot.calderaServerUrl,
          calderaServerIp: snapshot.calderaServerIp,
          agentCount: snapshot.agents.length,
          operationCount: snapshot.operations.length,
          hasAdversary: !!snapshot.adversaryProfile,
          capturedAt: snapshot.capturedAt,
          panelType,
          phase: panelPhase[panelType],
          orchestratorPhase: phase,
          ...(integrityGate
            ? {
                integrityPassed: integrityGate.passed,
                contentHash: integrityGate.contentHash,
                provenanceValid: integrityGate.provenanceValid,
              }
            : {}),
        }),
        classification: "confidential",
        collectedBy: "AC3 Orchestrator Auto-Collector",
        collectedAt: new Date(),
      });

      // Chain of custody entry
      await db.insert(evidenceChainOfCustody).values({
        evidenceId,
        action: "auto_captured",
        performedBy: "AC3 Engagement Orchestrator",
        details: `Auto-captured ${panelLabels[panelType]} during ${phase} phase from Caldera C2 (${snapshot.agents.length} agents, ${snapshot.operations.length} operations)`,
      });

      persisted++;
    } catch (err: any) {
      // Log but don't fail the whole pipeline for a single panel
      console.error(`[evidence-persistence] Failed to persist ${panelType} for engagement ${snapshot.engagementId}:`, err.message);
    }
  }

  return persisted;
}

/**
 * Persist a generic evidence item (for ScanForge, Nuclei, etc.)
 * with raw text/JSON content uploaded to S3.
 */
export async function persistGenericEvidence(opts: {
  engagementId: number | string;
  title: string;
  description: string;
  type: string;
  category: string;
  content: string;
  contentType?: string;
  tags?: string[];
  metadata?: Record<string, any>;
  collectedBy?: string;
}): Promise<string | null> {
  try {
    const db = getDb();
    const evidenceId = `ev_gen_${crypto.randomBytes(6).toString("hex")}`;
    const suffix = crypto.randomBytes(4).toString("hex");
    const ext = opts.contentType === "text/html" ? "html" : "json";
    const fileKey = `evidence-gallery/${opts.engagementId}/${opts.category}-${suffix}.${ext}`;

    const { url } = await doStoragePut(
      fileKey,
      Buffer.from(opts.content, "utf-8"),
      opts.contentType || "application/json",
    );

    await db.insert(evidenceItems).values({
      evidenceId,
      engagementId: String(opts.engagementId),
      title: opts.title,
      description: opts.description,
      type: opts.type,
      category: opts.category,
      fileUrl: url,
      fileKey,
      fileName: `${opts.category}-${suffix}.${ext}`,
      mimeType: opts.contentType || "application/json",
      tags: JSON.stringify(opts.tags || []),
      metadata: JSON.stringify(opts.metadata || {}),
      classification: "confidential",
      collectedBy: opts.collectedBy || "AC3 Auto-Collector",
      collectedAt: new Date(),
    });

    await db.insert(evidenceChainOfCustody).values({
      evidenceId,
      action: "auto_captured",
      performedBy: opts.collectedBy || "AC3 Auto-Collector",
      details: opts.description,
    });

    return evidenceId;
  } catch (err: any) {
    console.error(`[evidence-persistence] Failed to persist generic evidence:`, err.message);
    return null;
  }
}
