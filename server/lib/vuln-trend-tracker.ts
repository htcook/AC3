/**
 * Vulnerability Trend Tracker
 * 
 * Records scan snapshots and tracks vulnerability changes over time.
 * Provides trend data for visualization and reporting.
 */

import { getDb } from '../db';
import { vulnScanSnapshots, vulnTrendEntries } from '../../drizzle/schema';
import { eq, desc, and, sql } from 'drizzle-orm';

interface AssetVulnData {
  hostname: string;
  vulns: Array<{
    title: string;
    severity: string;
    category?: string;
    confidence?: number;
    cve?: string;
    tool?: string;
  }>;
  ports: any[];
  passiveRecon?: { riskSignals?: any[] };
}

interface SnapshotInput {
  engagementId: number;
  snapshotType: 'passive' | 'active' | 'llm_synthesis' | 'full_pipeline' | 'resynthesis';
  assets: AssetVulnData[];
  exploitCount?: number;
  metadata?: Record<string, any>;
}

/**
 * Record a scan snapshot and compute trend entries
 */
export async function recordScanSnapshot(input: SnapshotInput) {
  const db = await getDb();
  
  // Compute aggregate stats
  let totalVulns = 0, criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
  let totalPorts = 0;
  let totalConfidence = 0, confCount = 0;
  const categoryMap: Record<string, number> = {};
  const assetBreakdown: any[] = [];

  for (const asset of input.assets) {
    const vulns = asset.vulns || [];
    totalVulns += vulns.length;
    totalPorts += (asset.ports || []).length;
    
    for (const v of vulns) {
      switch (v.severity) {
        case 'critical': criticalCount++; break;
        case 'high': highCount++; break;
        case 'medium': mediumCount++; break;
        case 'low': lowCount++; break;
      }
      if (v.confidence) { totalConfidence += v.confidence; confCount++; }
      if (v.category) { categoryMap[v.category] = (categoryMap[v.category] || 0) + 1; }
    }

    assetBreakdown.push({
      hostname: asset.hostname,
      vulnCount: vulns.length,
      portCount: (asset.ports || []).length,
      riskSignals: (asset.passiveRecon?.riskSignals || []).length,
    });
  }

  // Get previous snapshot for this engagement to compute deltas
  const prevSnapshots = await db.select()
    .from(vulnScanSnapshots)
    .where(eq(vulnScanSnapshots.engagementId, input.engagementId))
    .orderBy(desc(vulnScanSnapshots.createdAt))
    .limit(1);
  
  const prevSnapshot = prevSnapshots[0];
  
  // Get previous vulns for delta computation
  let prevVulnSet = new Set<string>();
  if (prevSnapshot) {
    const prevEntries = await db.select()
      .from(vulnTrendEntries)
      .where(eq(vulnTrendEntries.snapshotId, prevSnapshot.id));
    prevVulnSet = new Set(prevEntries.map(e => `${e.hostname}::${e.vulnTitle}`));
  }

  // Build current vuln set
  const currentVulnSet = new Set<string>();
  for (const asset of input.assets) {
    for (const v of (asset.vulns || [])) {
      currentVulnSet.add(`${asset.hostname}::${v.title}`);
    }
  }

  // Compute deltas
  const newVulns = [...currentVulnSet].filter(v => !prevVulnSet.has(v));
  const resolvedVulns = [...prevVulnSet].filter(v => !currentVulnSet.has(v));

  // Insert snapshot
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
    metadata: input.metadata || {},
  });

  const snapshotId = insertResult.insertId;

  // Insert trend entries for each vuln
  const trendEntries: any[] = [];
  for (const asset of input.assets) {
    for (const v of (asset.vulns || [])) {
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
        status: isNew ? 'new' : 'existing',
        firstSeenSnapshotId: isNew ? snapshotId : null,
      });
    }
  }

  // Batch insert trend entries
  if (trendEntries.length > 0) {
    // Insert in batches of 100
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
    resolvedVulns: resolvedVulns.length,
  };
}

/**
 * Get trend data for an engagement (all snapshots over time)
 */
export async function getVulnTrend(engagementId: number) {
  const db = await getDb();
  
  const snapshots = await db.select()
    .from(vulnScanSnapshots)
    .where(eq(vulnScanSnapshots.engagementId, engagementId))
    .orderBy(vulnScanSnapshots.createdAt);

  return snapshots.map(s => ({
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
    assetBreakdown: s.assetBreakdown,
  }));
}

/**
 * Get detailed vuln changes between two snapshots
 */
export async function getVulnDiff(engagementId: number, fromSnapshotId: number, toSnapshotId: number) {
  const db = await getDb();
  
  const fromEntries = await db.select()
    .from(vulnTrendEntries)
    .where(and(
      eq(vulnTrendEntries.engagementId, engagementId),
      eq(vulnTrendEntries.snapshotId, fromSnapshotId)
    ));

  const toEntries = await db.select()
    .from(vulnTrendEntries)
    .where(and(
      eq(vulnTrendEntries.engagementId, engagementId),
      eq(vulnTrendEntries.snapshotId, toSnapshotId)
    ));

  const fromSet = new Set(fromEntries.map(e => `${e.hostname}::${e.vulnTitle}`));
  const toSet = new Set(toEntries.map(e => `${e.hostname}::${e.vulnTitle}`));

  return {
    added: toEntries.filter(e => !fromSet.has(`${e.hostname}::${e.vulnTitle}`)),
    removed: fromEntries.filter(e => !toSet.has(`${e.hostname}::${e.vulnTitle}`)),
    unchanged: toEntries.filter(e => fromSet.has(`${e.hostname}::${e.vulnTitle}`)),
  };
}
