import {
  getDb,
  init_db
} from "./chunk-RSFTEATL.js";
import "./chunk-KDOLKO2A.js";
import {
  domainIntelScans,
  init_schema,
  threatAlertThresholds
} from "./chunk-L4JENJ4Z.js";
import "./chunk-KFQGP6VL.js";

// server/lib/seed-alert-thresholds.ts
init_db();
init_schema();
import { eq } from "drizzle-orm";
async function seedDefaultAlertThresholds() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const completedScans = await db.select({
    id: domainIntelScans.id,
    primaryDomain: domainIntelScans.primaryDomain,
    sector: domainIntelScans.sector,
    totalAssets: domainIntelScans.totalAssets,
    overallRiskScore: domainIntelScans.overallRiskScore
  }).from(domainIntelScans).where(eq(domainIntelScans.status, "completed"));
  const existingThresholds = await db.select({ scanId: threatAlertThresholds.scanId }).from(threatAlertThresholds);
  const existingScanIds = new Set(
    existingThresholds.map((t) => t.scanId).filter(Boolean)
  );
  let created = 0;
  let skipped = 0;
  for (const scan of completedScans) {
    if (existingScanIds.has(scan.id)) {
      skipped++;
      continue;
    }
    const riskScore = scan.overallRiskScore || 50;
    const relevanceThreshold = riskScore >= 70 ? 60 : riskScore >= 50 ? 70 : 80;
    const sensitiveSecors = ["Healthcare", "Banking", "Finance", "Government"];
    const isSensitive = sensitiveSecors.some(
      (s) => scan.sector?.toLowerCase().includes(s.toLowerCase())
    );
    const threatLevelFilter = isSensitive ? "medium" : "high";
    await db.insert(threatAlertThresholds).values({
      scanId: scan.id,
      label: `${scan.primaryDomain || "Unknown"} \u2014 ${scan.sector || "General"} Monitor`,
      relevanceThreshold,
      threatLevelFilter,
      enabled: 1,
      notifyOnNew: 1,
      notifyOnRising: 1,
      createdBy: "system-seed"
    });
    created++;
  }
  const hasGlobal = existingThresholds.some((t) => t.scanId === null);
  if (!hasGlobal) {
    await db.insert(threatAlertThresholds).values({
      scanId: null,
      label: "Global \u2014 Critical Threat Monitor",
      relevanceThreshold: 90,
      threatLevelFilter: "critical",
      enabled: 1,
      notifyOnNew: 1,
      notifyOnRising: 1,
      createdBy: "system-seed"
    });
    created++;
  }
  return { created, skipped, scans: completedScans };
}
export {
  seedDefaultAlertThresholds
};
