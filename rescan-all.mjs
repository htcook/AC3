/**
 * Re-scan script: Resets the 10 remaining domain scans and re-runs the pipeline.
 * Each scan is reset to 'discovering' status, old assets are cleared, and the pipeline
 * is triggered sequentially to avoid overloading external APIs.
 */
import { getDb } from "./server/db.ts";
import { domainIntelScans, discoveredAssets } from "./drizzle/schema.ts";
import { eq, desc, sql } from "drizzle-orm";

const db = await getDb();
if (!db) { console.error("No DB connection"); process.exit(1); }

// Get all remaining scans
const scans = await db.select({
  id: domainIntelScans.id,
  domain: domainIntelScans.primaryDomain,
  sector: domainIntelScans.sector,
  clientType: domainIntelScans.clientType,
  orgProfile: domainIntelScans.orgProfile,
  criticalFunctions: domainIntelScans.criticalFunctions,
  complianceFlags: domainIntelScans.complianceFlags,
  notes: domainIntelScans.notes,
}).from(domainIntelScans).orderBy(desc(domainIntelScans.id));

console.log(`Found ${scans.length} scans to re-run:`);
scans.forEach(s => console.log(`  ID ${s.id}: ${s.domain} [${s.sector}]`));

// Import the pipeline
const { runDomainIntelPipeline } = await import("./server/domainIntel.ts");

// Process each scan sequentially
for (const scan of scans) {
  console.log(`\n${"=".repeat(80)}`);
  console.log(`[RESCAN] Starting: ${scan.domain} (ID: ${scan.id})`);
  console.log(`${"=".repeat(80)}`);
  
  try {
    // 1. Clear old discovered assets for this scan
    await db.execute(sql.raw(`DELETE FROM discovered_assets WHERE scanId = ${scan.id}`));
    await db.execute(sql.raw(`DELETE FROM false_positive_findings WHERE scanId = ${scan.id}`));
    await db.execute(sql.raw(`DELETE FROM scoring_audit_log WHERE scanId = ${scan.id}`));
    console.log(`  [RESCAN] Cleared old data for scan ${scan.id}`);

    // 2. Reset scan status
    await db.update(domainIntelScans)
      .set({
        status: 'discovering',
        totalAssets: 0,
        totalFindings: 0,
        confirmedFindings: 0,
        probableFindings: 0,
        potentialFindings: 0,
        overallRiskScore: null,
        overallRiskBand: null,
        executiveSummary: null,
      })
      .where(eq(domainIntelScans.id, scan.id));
    console.log(`  [RESCAN] Reset scan ${scan.id} to 'discovering'`);

    // 3. Build org profile from stored data
    const orgProfile = scan.orgProfile || {
      customerName: scan.domain.split('.')[0],
      primaryDomain: scan.domain,
      sector: scan.sector || 'Technology',
      clientType: scan.clientType || 'enterprise',
      criticalFunctions: scan.criticalFunctions || ['web_services', 'email', 'dns'],
      complianceFlags: scan.complianceFlags || [],
    };

    // 4. Run the pipeline
    const startTime = Date.now();
    const result = await runDomainIntelPipeline(
      orgProfile,
      async (stage) => {
        await db.update(domainIntelScans)
          .set({ status: stage })
          .where(eq(domainIntelScans.id, scan.id))
          .catch(() => {});
        console.log(`  [RESCAN] ${scan.domain} → ${stage}`);
      },
      { scanMode: 'standard', skipEngagement: true }
    );

    const durationSec = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`  [RESCAN] Pipeline completed in ${durationSec}s`);
    console.log(`  [RESCAN] Assets: ${result.assets?.length || 0}, Risk: ${result.riskCard?.overallRiskScore || 'N/A'}`);

    // 5. Store discovered assets in batches
    if (result.assets && result.assets.length > 0) {
      const assetRecords = result.assets.map(a => ({
        scanId: scan.id,
        assetId: a.asset.assetId,
        hostname: a.asset.hostname,
        url: a.asset.url || null,
        assetType: a.asset.assetType,
        dnsRecords: a.asset.dnsRecords || null,
        dnsStatus: a.asset.dnsStatus || null,
        headers: a.asset.headers || null,
        technologies: a.asset.technologies || null,
        detectedTechnologies: a.asset.technologyVersions
          ? Object.entries(a.asset.technologyVersions).map(([name, version]) => ({
              name,
              version: version || '',
              category: 'detected',
              confidence: version ? 0.9 : 0.7,
            }))
          : (a.asset.technologies || []).map(t => ({ name: t, version: '', category: 'inferred', confidence: 0.5 })),
        assetClasses: a.assetClasses,
        tags: a.asset.tags,
        carverScores: a.carverScores,
        shockScores: a.shockScores,
        missionImpactScore: Math.round(a.missionImpactScore * 10),
        suggestedTier: a.suggestedTier,
        hybridRiskScore: a.hybridRiskScore,
        riskBand: a.riskBand,
        cvssEstimate: Math.round(a.cvssEstimate * 10),
        contextIndicators: a.contextIndicators,
        postureFindings: a.postureFindings,
        testVectors: a.testVectors,
        recommendedCalderaAbilities: a.testVectors?.filter(v => v.suggestedEmulation?.calderaAbilityHint).map(v => v.suggestedEmulation) || null,
        recommendedGophishTemplates: null,
        recommendedAttackChain: null,
        confidence: a.confidence,
        confidenceExplanation: a.contextIndicators,
        impactScore: a.impactScore || 0,
        likelihoodScore: a.likelihoodScore || 0,
        assetCriticalityScore: a.assetCriticalityScore || 0,
        assetCriticalityBand: a.assetCriticalityBand || 'low',
        vulnRiskScore: a.vulnRiskScore || 0,
        vulnRiskBand: a.vulnRiskBand || 'low',
        missionFunction: a.missionFunction || 'public_facing_services',
        essentialService: a.essentialService || 'general_server',
        businessImpactLevel: a.businessImpactLevel || 'moderate',
        deviceType: a.deviceType || 'unknown',
        platformType: a.platformType || 'unknown',
        missionJustification: a.missionJustification || '',
      }));

      // Batch insert
      const { bulkCreateDiscoveredAssets, createDiscoveredAsset } = await import("./server/db.ts");
      const BATCH_SIZE = 5;
      for (let i = 0; i < assetRecords.length; i += BATCH_SIZE) {
        const batch = assetRecords.slice(i, i + BATCH_SIZE);
        try {
          await bulkCreateDiscoveredAssets(batch);
        } catch (batchErr) {
          for (const record of batch) {
            try { await createDiscoveredAsset(record); } catch (e) {
              console.warn(`  [RESCAN] Failed to insert asset ${record.hostname}: ${e.message?.substring(0, 80)}`);
            }
          }
        }
      }
      console.log(`  [RESCAN] Stored ${assetRecords.length} assets`);
    }

    // 6. Update scan with final results
    await db.update(domainIntelScans)
      .set({
        status: 'completed',
        totalAssets: result.assets?.length || 0,
        totalFindings: result.assets?.reduce((sum, a) => sum + (a.postureFindings?.length || 0), 0) || 0,
        overallRiskScore: result.riskCard?.overallRiskScore || null,
        overallRiskBand: result.riskCard?.overallRiskBand || null,
        executiveSummary: result.executiveSummary || null,
      })
      .where(eq(domainIntelScans.id, scan.id));

    console.log(`  [RESCAN] ✓ ${scan.domain} completed — ${result.assets?.length || 0} assets, risk: ${result.riskCard?.overallRiskScore || 'N/A'}`);

  } catch (err) {
    console.error(`  [RESCAN] ✗ ${scan.domain} FAILED: ${err.message}`);
    await db.update(domainIntelScans)
      .set({ status: 'failed' })
      .where(eq(domainIntelScans.id, scan.id))
      .catch(() => {});
  }
}

console.log(`\n${"=".repeat(80)}`);
console.log("[RESCAN] All scans completed.");
console.log(`${"=".repeat(80)}`);

process.exit(0);
