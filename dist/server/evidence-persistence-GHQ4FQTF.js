import {
  doStoragePut,
  init_do_storage
} from "./chunk-CTBPXKB3.js";
import {
  getDb,
  init_db
} from "./chunk-AGW4B7XR.js";
import "./chunk-NRYVRXXR.js";
import {
  evidenceChainOfCustody,
  evidenceItems,
  init_schema
} from "./chunk-YB6W7YNA.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/evidence-persistence.ts
import crypto from "crypto";
async function persistCalderaEvidence(opts) {
  const { snapshot, phase, integrityGate } = opts;
  const db = await getDb();
  let persisted = 0;
  for (const panelType of PANEL_TYPES) {
    const html = snapshot.renderedHtml[panelType];
    if (!html || html.length < 50) continue;
    try {
      const evidenceId = `ev_cal_${crypto.randomBytes(6).toString("hex")}`;
      const suffix = crypto.randomBytes(4).toString("hex");
      const fileKey = `evidence-gallery/${snapshot.engagementId}/${phase}-${panelType}-${suffix}.html`;
      const { url } = await doStoragePut(fileKey, Buffer.from(html, "utf-8"), "text/html");
      await db.insert(evidenceItems).values({
        evidenceId,
        engagementId: String(snapshot.engagementId),
        title: `${panelLabels[panelType]} \u2014 ${snapshot.engagementName} (${phase})`,
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
          ...snapshot.agents.map((a) => `agent:${a.paw}`)
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
          ...integrityGate ? {
            integrityPassed: integrityGate.passed,
            contentHash: integrityGate.contentHash,
            provenanceValid: integrityGate.provenanceValid
          } : {}
        }),
        classification: "confidential",
        collectedBy: "AC3 Orchestrator Auto-Collector",
        collectedAt: /* @__PURE__ */ new Date()
      });
      await db.insert(evidenceChainOfCustody).values({
        evidenceId,
        action: "auto_captured",
        performedBy: "AC3 Engagement Orchestrator",
        details: `Auto-captured ${panelLabels[panelType]} during ${phase} phase from Caldera C2 (${snapshot.agents.length} agents, ${snapshot.operations.length} operations)`
      });
      persisted++;
    } catch (err) {
      console.error(`[evidence-persistence] Failed to persist ${panelType} for engagement ${snapshot.engagementId}:`, err.message);
    }
  }
  return persisted;
}
async function persistGenericEvidence(opts) {
  try {
    const db = await getDb();
    const evidenceId = `ev_gen_${crypto.randomBytes(6).toString("hex")}`;
    const suffix = crypto.randomBytes(4).toString("hex");
    const ext = opts.contentType === "text/html" ? "html" : "json";
    const fileKey = `evidence-gallery/${opts.engagementId}/${opts.category}-${suffix}.${ext}`;
    const { url } = await doStoragePut(
      fileKey,
      Buffer.from(opts.content, "utf-8"),
      opts.contentType || "application/json"
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
      collectedAt: /* @__PURE__ */ new Date()
    });
    await db.insert(evidenceChainOfCustody).values({
      evidenceId,
      action: "auto_captured",
      performedBy: opts.collectedBy || "AC3 Auto-Collector",
      details: opts.description
    });
    return evidenceId;
  } catch (err) {
    console.error(`[evidence-persistence] Failed to persist generic evidence:`, err.message);
    return null;
  }
}
var PANEL_TYPES, panelLabels, panelPhase;
var init_evidence_persistence = __esm({
  "server/lib/evidence-persistence.ts"() {
    init_db();
    init_schema();
    init_do_storage();
    PANEL_TYPES = ["agentTable", "operationTimeline", "adversaryProfile", "attackChainSummary"];
    panelLabels = {
      agentTable: "C2 Agent Check-Ins",
      operationTimeline: "Operation Timeline",
      adversaryProfile: "Adversary Profile",
      attackChainSummary: "Attack Chain Summary"
    };
    panelPhase = {
      agentTable: "exploitation",
      operationTimeline: "post-exploitation",
      adversaryProfile: "post-exploitation",
      attackChainSummary: "post-exploitation"
    };
  }
});
init_evidence_persistence();
export {
  persistCalderaEvidence,
  persistGenericEvidence
};
