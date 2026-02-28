import 'dotenv/config';
import { getDb, createDiscoveredAsset, updateDomainIntelScan } from './server/db';
import { domainIntelScans, discoveredAssets } from './drizzle/schema';
import { eq, and, inArray, lt, sql } from 'drizzle-orm';
import { runDomainIntelPipeline, type OrgProfile } from './server/domainIntel';

const STUCK_THRESHOLD_MS = 15 * 60 * 1000;

async function main() {
  const db = await getDb();
  if (!db) {
    console.error('Failed to connect to database');
    process.exit(1);
  }

  // Find all failed scans that were auto-reset (from our bulk reset), plus any still-stuck scans
  const cutoff = new Date(Date.now() - STUCK_THRESHOLD_MS);
  const stuckScans = await db.select()
    .from(domainIntelScans)
    .where(
      and(
        sql`(
          (${domainIntelScans.status} = 'failed' AND (JSON_EXTRACT(${domainIntelScans.pipelineOutput}, '$.autoReset') = true OR JSON_EXTRACT(${domainIntelScans.pipelineOutput}, '$.retryFailed') = true))
          OR
          (${domainIntelScans.status} IN ('pending', 'passive_recon', 'discovering', 'analyzing', 'scoring', 'recommending') AND ${domainIntelScans.updatedAt} < ${cutoff})
        )`,
        sql`${domainIntelScans.primaryDomain} NOT REGEXP '^(msp|enterprise|saas|paas|iaas|mixed_hosting|other)-[0-9]+\\.com$'`
      )
    )
    .orderBy(domainIntelScans.createdAt);

  console.log(`\n=== FOUND ${stuckScans.length} STUCK/FAILED SCANS ===\n`);

  if (stuckScans.length === 0) {
    console.log('No stuck scans to retry.');
    process.exit(0);
  }

  for (const scan of stuckScans) {
    console.log(`  ID: ${scan.id} | ${scan.primaryDomain} | Status: ${scan.status} | Assets: ${scan.totalAssets}`);
  }

  // Process each scan
  let successCount = 0;
  let failCount = 0;
  let queuedCount = 0;

  for (const scan of stuckScans) {
    const scanId = scan.id;
    const domain = scan.primaryDomain;
    
    try {
      // Step 1: Clean up orphaned assets
      await db.delete(discoveredAssets).where(eq(discoveredAssets.scanId, scanId));

      // Step 2: Reset scan status
      await db.update(domainIntelScans)
        .set({
          status: 'discovering',
          totalAssets: 0,
          totalFindings: 0,
          confirmedFindings: 0,
          probableFindings: 0,
          overallRiskScore: null,
          overallRiskBand: null,
          pipelineOutput: null,
          updatedAt: new Date(),
        })
        .where(eq(domainIntelScans.id, scanId));

      // Step 3: Build org profile from scan data
      const orgProfile: OrgProfile = {
        primaryDomain: scan.primaryDomain,
        orgName: scan.orgName || scan.primaryDomain,
        industry: (scan.industry as any) || 'technology',
        employeeCount: (scan.employeeCount as any) || '1001-5000',
        criticalFunctions: (scan.criticalFunctions as string[]) || [],
        complianceFlags: (scan.complianceFlags as string[]) || [],
      };

      // Step 4: Fire and forget the pipeline (same pattern as the retryScan mutation)
      console.log(`  🔄 Starting pipeline for ${domain} (ID: ${scanId})...`);

      // Run pipeline in background (don't await)
      (async () => {
        try {
          const result = await runDomainIntelPipeline(orgProfile, async (stage) => {
            await updateDomainIntelScan(scanId, { status: stage });
          }, { scanMode: (scan as any).scanMode || 'standard' });

          // Save results using same pattern as routers.ts retryScan
          if (result.assets && result.assets.length > 0) {
            const assetRecords = result.assets.map((a: any) => ({
              scanId,
              assetId: a.asset.assetId,
              hostname: a.asset.hostname,
              url: a.asset.url || null,
              assetType: a.asset.assetType,
              dnsRecords: a.asset.dnsRecords || null,
              dnsStatus: a.asset.dnsStatus || null,
              headers: a.asset.headers || null,
              technologies: a.asset.technologies || null,
              detectedTechnologies: a.asset.technologyVersions
                ? Object.entries(a.asset.technologyVersions).map(([name, version]) => ({ name, version: version as string }))
                : null,
              carverScores: a.carverScores || null,
              shockScores: a.shockScores || null,
              missionImpactScore: a.missionImpactScore || null,
              suggestedTier: a.suggestedTier || null,
              hybridRiskScore: a.hybridRiskScore || null,
              riskBand: a.riskBand || null,
              cvssEstimate: a.cvssEstimate || null,
              impactScore: a.impactScore || null,
              likelihoodScore: a.likelihoodScore || null,
              vulnRiskScore: a.vulnRiskScore || null,
              contextIndicators: a.contextIndicators || null,
              postureFindings: a.postureFindings || null,
              testVectors: a.testVectors || null,
              missionFunction: a.asset.missionFunction || null,
              essentialService: a.asset.essentialService || null,
            }));

            // Batch insert in groups of 5
            for (let i = 0; i < assetRecords.length; i += 5) {
              const batch = assetRecords.slice(i, i + 5);
              for (const record of batch) {
                try {
                  await createDiscoveredAsset(record);
                } catch (e: any) {
                  console.error(`[Retry] Failed to insert asset ${record.hostname}: ${e.message}`);
                }
              }
            }
            console.log(`[Retry] Stored ${assetRecords.length} assets for scan ${scanId}`);
          }

          await updateDomainIntelScan(scanId, {
            status: result.engagement ? 'completed' : 'scan_complete',
            totalAssets: result.assets?.length || 0,
            totalFindings: result.assets?.reduce((sum, a) => sum + (a.postureFindings?.length || 0), 0) || 0,
            confirmedFindings: result.assets?.reduce((sum, a) => sum + (a.postureFindings?.filter(f => f.confidence === 'confirmed').length || 0), 0) || 0,
            probableFindings: result.assets?.reduce((sum, a) => sum + (a.postureFindings?.filter(f => f.confidence === 'probable').length || 0), 0) || 0,
            overallRiskScore: result.riskScore ?? null,
            overallRiskBand: result.riskBand ?? null,
            pipelineOutput: result as any,
          });
          console.log(`  ✅ ${domain} completed: ${result.assets?.length || 0} assets, risk: ${result.riskScore ?? 'N/A'}`);
        } catch (err: any) {
          console.error(`  ❌ ${domain} pipeline failed: ${err.message}`);
          await updateDomainIntelScan(scanId, {
            status: 'failed',
            pipelineOutput: { error: err.message, stack: err.stack?.substring(0, 1000), failedAt: new Date().toISOString(), retryFailed: true } as any,
          }).catch(() => {});
        }
      })();

      queuedCount++;
      
      // Stagger starts by 3 seconds to avoid LLM rate limits
      await new Promise(r => setTimeout(r, 3000));
      
    } catch (err: any) {
      console.error(`  ❌ Failed to queue ${domain}: ${err.message}`);
      failCount++;
    }
  }

  console.log(`\n=== QUEUED ${queuedCount} SCANS FOR RETRY ===`);
  console.log(`Pipelines are running in background. Monitor progress in the dashboard.`);
  console.log(`Waiting 5 minutes for initial results...\n`);

  // Wait and check progress periodically
  for (let i = 0; i < 10; i++) {
    await new Promise(r => setTimeout(r, 30000)); // Check every 30s
    
    const updated = await db.select({
      id: domainIntelScans.id,
      domain: domainIntelScans.primaryDomain,
      status: domainIntelScans.status,
      assets: domainIntelScans.totalAssets,
    })
    .from(domainIntelScans)
    .where(inArray(domainIntelScans.id, stuckScans.map(s => s.id)));

    const completed = updated.filter(s => s.status === 'completed' || s.status === 'scan_complete');
    const failed = updated.filter(s => s.status === 'failed');
    const inProgress = updated.filter(s => !['completed', 'scan_complete', 'failed'].includes(s.status));
    
    console.log(`[${new Date().toLocaleTimeString()}] Progress: ${completed.length} completed, ${inProgress.length} in-progress, ${failed.length} failed`);
    
    if (inProgress.length === 0) {
      console.log('\nAll scans finished!');
      break;
    }
  }

  // Final summary
  const finalResults = await db.select({
    id: domainIntelScans.id,
    domain: domainIntelScans.primaryDomain,
    status: domainIntelScans.status,
    assets: domainIntelScans.totalAssets,
    riskScore: domainIntelScans.overallRiskScore,
  })
  .from(domainIntelScans)
  .where(inArray(domainIntelScans.id, stuckScans.map(s => s.id)));

  console.log(`\n=== FINAL RESULTS ===`);
  for (const r of finalResults) {
    const icon = (r.status === 'completed' || r.status === 'scan_complete') ? '✅' : r.status === 'failed' ? '❌' : '⏳';
    console.log(`  ${icon} ${r.domain}: ${r.status} | ${r.assets} assets | Risk: ${r.riskScore ?? 'N/A'}`);
  }
  
  const completedCount = finalResults.filter(r => r.status === 'completed' || r.status === 'scan_complete').length;
  const failedCount = finalResults.filter(r => r.status === 'failed').length;
  const pendingCount = finalResults.filter(r => !['completed', 'scan_complete', 'failed'].includes(r.status)).length;
  
  console.log(`\nCompleted: ${completedCount} | Failed: ${failedCount} | Still running: ${pendingCount}`);
  
  process.exit(0);
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
