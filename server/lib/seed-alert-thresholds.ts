/**
 * Seed default alert thresholds for all completed domain intel scans.
 * Called once to bootstrap monitoring for active engagements.
 */
import { getDb } from "../db";
import { eq } from "drizzle-orm";
import { domainIntelScans, threatAlertThresholds } from "../../drizzle/schema";

interface ScanInfo {
  id: number;
  primaryDomain: string | null;
  sector: string | null;
  totalAssets: number | null;
  overallRiskScore: number | null;
}

export async function seedDefaultAlertThresholds(): Promise<{
  created: number;
  skipped: number;
  scans: ScanInfo[];
}> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  // Get all completed scans with sector data
  const completedScans = await db
    .select({
      id: domainIntelScans.id,
      primaryDomain: domainIntelScans.primaryDomain,
      sector: domainIntelScans.sector,
      totalAssets: domainIntelScans.totalAssets,
      overallRiskScore: domainIntelScans.overallRiskScore,
    })
    .from(domainIntelScans)
    .where(eq(domainIntelScans.status, "completed"));

  // Get existing thresholds to avoid duplicates
  const existingThresholds = await db
    .select({ scanId: threatAlertThresholds.scanId })
    .from(threatAlertThresholds);

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

    // Determine threshold based on risk score
    // Higher risk = lower threshold (more sensitive alerting)
    const riskScore = scan.overallRiskScore || 50;
    const relevanceThreshold = riskScore >= 70 ? 60 : riskScore >= 50 ? 70 : 80;

    // Determine threat level filter based on sector sensitivity
    const sensitiveSecors = ["Healthcare", "Banking", "Finance", "Government"];
    const isSensitive = sensitiveSecors.some(
      (s) => scan.sector?.toLowerCase().includes(s.toLowerCase())
    );
    const threatLevelFilter = isSensitive ? "medium" : "high";

    await db.insert(threatAlertThresholds).values({
      scanId: scan.id,
      label: `${scan.primaryDomain || "Unknown"} — ${scan.sector || "General"} Monitor`,
      relevanceThreshold,
      threatLevelFilter: threatLevelFilter as "any" | "critical" | "high" | "medium",
      enabled: 1,
      notifyOnNew: 1,
      notifyOnRising: 1,
      createdBy: "system-seed",
    });

    created++;
  }

  // Also create a global "catch-all" threshold if none exists
  const hasGlobal = existingThresholds.some((t) => t.scanId === null);
  if (!hasGlobal) {
    await db.insert(threatAlertThresholds).values({
      scanId: null,
      label: "Global — Critical Threat Monitor",
      relevanceThreshold: 90,
      threatLevelFilter: "critical",
      enabled: 1,
      notifyOnNew: 1,
      notifyOnRising: 1,
      createdBy: "system-seed",
    });
    created++;
  }

  return { created, skipped, scans: completedScans };
}
