import {
  getDb,
  init_db
} from "./chunk-AGW4B7XR.js";
import "./chunk-NRYVRXXR.js";
import {
  engagements,
  init_schema,
  scanResults
} from "./chunk-YB6W7YNA.js";
import "./chunk-KFQGP6VL.js";

// server/lib/supplemental-scan-feeder.ts
init_db();
init_schema();
import { eq } from "drizzle-orm";
async function feedScanResultsToEngagement(engagementId, scannerType, findings) {
  const db = await getDb();
  if (!db) {
    console.warn("[SupplementalScanFeeder] Database unavailable, skipping feed");
    return { inserted: 0, engagementId };
  }
  const [engagement] = await db.select({ id: engagements.id }).from(engagements).where(eq(engagements.id, engagementId)).limit(1);
  if (!engagement) {
    console.warn(`[SupplementalScanFeeder] Engagement #${engagementId} not found`);
    return { inserted: 0, engagementId };
  }
  const scanResultRows = findings.map((f) => ({
    engagementId,
    scanTool: `supplemental_${scannerType}`,
    target: f.host,
    rawOutput: JSON.stringify({
      finding: f.name,
      severity: f.severity,
      matched: f.matched || f.host,
      description: f.description || "",
      cve: f.cveId,
      cwe: f.cweId,
      templateId: f.templateId,
      tags: f.tags || [],
      extractedResults: f.extractedResults || [],
      curl: f.curl,
      port: f.port,
      type: f.type,
      evidence: f.evidence || f.matched || ""
    }),
    parsedFindings: JSON.stringify([{
      title: f.name,
      severity: f.severity,
      description: f.description || f.name,
      evidence: f.evidence || f.matched || f.curl || "",
      cve: f.cveId,
      cwe: f.cweId,
      host: f.host,
      port: f.port,
      tags: f.tags,
      source: `supplemental_${scannerType}`,
      confidence: f.cveId ? "high" : "medium"
    }]),
    exitCode: 0,
    durationMs: 0,
    createdAt: Date.now()
  }));
  let inserted = 0;
  for (const row of scanResultRows) {
    try {
      await db.insert(scanResults).values(row);
      inserted++;
    } catch (err) {
      console.warn(`[SupplementalScanFeeder] Failed to insert finding: ${err.message}`);
    }
  }
  console.log(
    `[SupplementalScanFeeder] Fed ${inserted}/${findings.length} findings from ${scannerType} into engagement #${engagementId}`
  );
  return { inserted, engagementId };
}
async function feedTerminalEvidenceToEngagement(engagementId, command, output, target) {
  const db = await getDb();
  if (!db) return { success: false };
  try {
    await db.insert(scanResults).values({
      engagementId,
      scanTool: "manual_terminal",
      target,
      rawOutput: JSON.stringify({
        command,
        output: output.slice(0, 5e4),
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      }),
      parsedFindings: JSON.stringify([{
        title: `Manual command: ${command.slice(0, 80)}`,
        severity: "info",
        description: `Manual terminal command executed against ${target}`,
        evidence: output.slice(0, 1e4),
        source: "manual_terminal",
        confidence: "manual"
      }]),
      exitCode: 0,
      durationMs: 0,
      createdAt: Date.now()
    });
    return { success: true };
  } catch (err) {
    console.warn(`[SupplementalScanFeeder] Terminal evidence feed failed: ${err.message}`);
    return { success: false };
  }
}
export {
  feedScanResultsToEngagement,
  feedTerminalEvidenceToEngagement
};
