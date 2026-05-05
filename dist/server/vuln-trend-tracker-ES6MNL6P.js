import {
  getDb,
  init_db
} from "./chunk-AGW4B7XR.js";
import "./chunk-NRYVRXXR.js";
import {
  init_schema,
  vulnScanSnapshots,
  vulnTrendEntries
} from "./chunk-YB6W7YNA.js";
import "./chunk-KFQGP6VL.js";

// server/lib/vuln-trend-tracker.ts
init_db();
init_schema();
import { eq, desc, and } from "drizzle-orm";
async function recordScanSnapshot(input) {
  const db = await getDb();
  let totalVulns = 0, criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
  let totalPorts = 0;
  let totalConfidence = 0, confCount = 0;
  const categoryMap = {};
  const assetBreakdown = [];
  for (const asset of input.assets) {
    const vulns = asset.vulns || [];
    totalVulns += vulns.length;
    totalPorts += (asset.ports || []).length;
    for (const v of vulns) {
      switch (v.severity) {
        case "critical":
          criticalCount++;
          break;
        case "high":
          highCount++;
          break;
        case "medium":
          mediumCount++;
          break;
        case "low":
          lowCount++;
          break;
      }
      if (v.confidence) {
        totalConfidence += v.confidence;
        confCount++;
      }
      if (v.category) {
        categoryMap[v.category] = (categoryMap[v.category] || 0) + 1;
      }
    }
    assetBreakdown.push({
      hostname: asset.hostname,
      vulnCount: vulns.length,
      portCount: (asset.ports || []).length,
      riskSignals: (asset.passiveRecon?.riskSignals || []).length
    });
  }
  const prevSnapshots = await db.select().from(vulnScanSnapshots).where(eq(vulnScanSnapshots.engagementId, input.engagementId)).orderBy(desc(vulnScanSnapshots.createdAt)).limit(1);
  const prevSnapshot = prevSnapshots[0];
  let prevVulnSet = /* @__PURE__ */ new Set();
  if (prevSnapshot) {
    const prevEntries = await db.select().from(vulnTrendEntries).where(eq(vulnTrendEntries.snapshotId, prevSnapshot.id));
    prevVulnSet = new Set(prevEntries.map((e) => `${e.hostname}::${e.vulnTitle}`));
  }
  const currentVulnSet = /* @__PURE__ */ new Set();
  for (const asset of input.assets) {
    for (const v of asset.vulns || []) {
      currentVulnSet.add(`${asset.hostname}::${v.title}`);
    }
  }
  const newVulns = [...currentVulnSet].filter((v) => !prevVulnSet.has(v));
  const resolvedVulns = [...prevVulnSet].filter((v) => !currentVulnSet.has(v));
  const [insertResult] = await db.insert(vulnScanSnapshots).values({
    engagementId: input.engagementId,
    snapshotType: input.snapshotType,
    totalAssets: input.assets.length,
    totalVulns,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    totalPorts,
    totalExploits: input.exploitCount || 0,
    avgConfidence: confCount > 0 ? Math.round(totalConfidence / confCount) : 0,
    newVulnsFound: newVulns.length,
    resolvedVulns: resolvedVulns.length,
    categories: categoryMap,
    assetBreakdown,
    metadata: input.metadata || {}
  });
  const snapshotId = insertResult.insertId;
  const trendEntries = [];
  for (const asset of input.assets) {
    for (const v of asset.vulns || []) {
      const key = `${asset.hostname}::${v.title}`;
      const isNew = !prevVulnSet.has(key);
      trendEntries.push({
        snapshotId,
        engagementId: input.engagementId,
        hostname: asset.hostname,
        vulnTitle: v.title,
        severity: v.severity,
        category: v.category || null,
        confidence: v.confidence || null,
        cve: v.cve || null,
        tool: v.tool || null,
        status: isNew ? "new" : "existing",
        firstSeenSnapshotId: isNew ? snapshotId : null
      });
    }
  }
  if (trendEntries.length > 0) {
    for (let i = 0; i < trendEntries.length; i += 100) {
      const batch = trendEntries.slice(i, i + 100);
      await db.insert(vulnTrendEntries).values(batch);
    }
  }
  return {
    snapshotId,
    totalVulns,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    totalPorts,
    newVulnsFound: newVulns.length,
    resolvedVulns: resolvedVulns.length
  };
}
async function getVulnTrend(engagementId) {
  const db = await getDb();
  const snapshots = await db.select().from(vulnScanSnapshots).where(eq(vulnScanSnapshots.engagementId, engagementId)).orderBy(vulnScanSnapshots.createdAt);
  return snapshots.map((s) => ({
    id: s.id,
    type: s.snapshotType,
    date: s.createdAt,
    totalVulns: s.totalVulns,
    critical: s.criticalCount,
    high: s.highCount,
    medium: s.mediumCount,
    low: s.lowCount,
    ports: s.totalPorts,
    exploits: s.totalExploits,
    avgConfidence: s.avgConfidence,
    newFound: s.newVulnsFound,
    resolved: s.resolvedVulns,
    assets: s.totalAssets,
    categories: s.categories,
    assetBreakdown: s.assetBreakdown
  }));
}
async function getVulnDiff(engagementId, fromSnapshotId, toSnapshotId) {
  const db = await getDb();
  const fromEntries = await db.select().from(vulnTrendEntries).where(and(
    eq(vulnTrendEntries.engagementId, engagementId),
    eq(vulnTrendEntries.snapshotId, fromSnapshotId)
  ));
  const toEntries = await db.select().from(vulnTrendEntries).where(and(
    eq(vulnTrendEntries.engagementId, engagementId),
    eq(vulnTrendEntries.snapshotId, toSnapshotId)
  ));
  const fromSet = new Set(fromEntries.map((e) => `${e.hostname}::${e.vulnTitle}`));
  const toSet = new Set(toEntries.map((e) => `${e.hostname}::${e.vulnTitle}`));
  return {
    added: toEntries.filter((e) => !fromSet.has(`${e.hostname}::${e.vulnTitle}`)),
    removed: fromEntries.filter((e) => !toSet.has(`${e.hostname}::${e.vulnTitle}`)),
    unchanged: toEntries.filter((e) => fromSet.has(`${e.hostname}::${e.vulnTitle}`))
  };
}
export {
  getVulnDiff,
  getVulnTrend,
  recordScanSnapshot
};
