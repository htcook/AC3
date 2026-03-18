import { TRPCError } from "@trpc/server";
import { protectedProcedure, publicProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import { ENV } from "../_core/env";
import { invokeLLM } from "../_core/llm";
import { and, count, eq, max, min, not, or } from "drizzle-orm";
import * as schema from "../../drizzle/schema";

export const domainIntelRouter = router({
    // Start a new domain intel scan (async fire-and-forget pattern)
    startScan: protectedProcedure
      .input(z.object({
        primaryDomain: z.string().min(1),
        additionalDomains: z.array(z.string()).optional(),
        clientType: z.enum(['msp', 'enterprise', 'saas', 'paas', 'iaas', 'mixed_hosting', 'other']),
        sector: z.string().min(1),
        customerName: z.string().min(1),
        criticalFunctions: z.array(z.string()),
        complianceFlags: z.array(z.string()).optional(),
        notes: z.string().optional(),
        engagementId: z.number().optional(),
        scanMode: z.enum(['strict_passive', 'standard', 'active']).optional(),
        scanOnly: z.boolean().optional(),
        scopedAssets: z.array(z.string()).optional(), // RoE-restricted: only scan these exact hostnames/IPs
      }))
      .mutation(async ({ input, ctx }) => {
        // ── Deduplication guard: check for existing scan with same engagement + domain ──
        if (input.engagementId) {
          const existingScans = await db.getDomainIntelScansByEngagement(input.engagementId);
          const existing = existingScans.find(s => s.primaryDomain === input.primaryDomain);
          if (existing) {
            // If the existing scan is in a terminal state, allow re-scan; otherwise return existing
            if (existing.status !== 'completed' && existing.status !== 'error' && existing.status !== 'failed') {
              return { scanId: existing.id, deduplicated: true, message: `Scan already in progress for ${input.primaryDomain} (status: ${existing.status})` };
            }
            // For completed/error scans, allow a new scan (user explicitly wants to re-run)
          }
        }

        // Create scan record immediately
        const scanId = await db.createDomainIntelScan({
          primaryDomain: input.primaryDomain,
          additionalDomains: input.additionalDomains || [],
          clientType: input.clientType,
          sector: input.sector,
          engagementId: input.engagementId,
          orgProfile: {
            customerName: input.customerName,
            primaryDomain: input.primaryDomain,
            sector: input.sector,
            clientType: input.clientType,
            criticalFunctions: input.criticalFunctions,
            complianceFlags: input.complianceFlags || [],
            scopedAssets: input.scopedAssets || [],
            scanMode: input.scanMode || 'standard',
          },
          criticalFunctions: input.criticalFunctions,
          complianceFlags: input.complianceFlags || [],
          notes: input.notes,
          status: 'discovering',
          createdBy: ctx.user.id,
        });

        // Return scanId immediately — run pipeline in background to avoid timeout
        // The frontend will poll getScanStatus for progress
        const pipelineInput = { ...input };
        setImmediate(async () => {
          try {
            console.log(`[DomainIntel] Pipeline started for scan ${scanId}: ${input.primaryDomain}`);
            const { runDomainIntelPipeline } = await import('../domainIntel');

            await db.updateDomainIntelScan(scanId, { status: 'discovering' });

            const result = await runDomainIntelPipeline(
              {
                customerName: pipelineInput.customerName,
                primaryDomain: pipelineInput.primaryDomain,
                additionalDomains: pipelineInput.additionalDomains,
                sector: pipelineInput.sector,
                clientType: pipelineInput.clientType,
                criticalFunctions: pipelineInput.criticalFunctions,
                complianceFlags: pipelineInput.complianceFlags || [],
                notes: pipelineInput.notes,
              },
              // Progress callback: update scan status in DB so frontend can poll
              async (stage) => {
                await db.updateDomainIntelScan(scanId, { status: stage }).catch(() => {});
                console.log(`[DomainIntel] Scan ${scanId} stage: ${stage}`);
              },
              { scanMode: pipelineInput.scanMode || 'standard', skipEngagement: !!pipelineInput.scanOnly, scopedAssets: pipelineInput.scopedAssets }
            );

            // Store discovered assets — batch inserts to avoid oversized queries
            const assetRecords = result.assets.map(a => ({
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
                ? Object.entries(a.asset.technologyVersions).map(([name, version]) => ({
                    name,
                    version: version || '',
                    category: 'detected',
                    confidence: version ? 0.9 : 0.7,
                  }))
                : (a.asset.technologies || []).map((t: string) => ({ name: t, version: '', category: 'inferred', confidence: 0.5 })),
              assetClasses: a.asset.assetClasses,
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
              recommendedCalderaAbilities: a.testVectors.filter((v: any) => v.suggestedEmulation?.calderaAbilityHint).map((v: any) => v.suggestedEmulation),
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

            // Batch insert assets in chunks of 5 to avoid oversized queries
            // Each asset can have hundreds of postureFindings (100KB+ JSON each)
            if (assetRecords.length > 0) {
              const BATCH_SIZE = 5;
              for (let i = 0; i < assetRecords.length; i += BATCH_SIZE) {
                const batch = assetRecords.slice(i, i + BATCH_SIZE);
                try {
                  await db.bulkCreateDiscoveredAssets(batch);
                } catch (batchErr: any) {
                  // If batch fails, try inserting one at a time
                  console.warn(`[DomainIntel] Batch insert failed (${i}-${i + batch.length}), falling back to individual inserts: ${batchErr.message}`);
                  for (const record of batch) {
                    try {
                      await db.createDiscoveredAsset(record);
                    } catch (singleErr: any) {
                      console.error(`[DomainIntel] Failed to insert asset ${record.hostname}: ${singleErr.message}`);
                    }
                  }
                }
              }
              console.log(`[DomainIntel] Stored ${assetRecords.length} assets for scan ${scanId}`);
            }

            // ─── Persist Re-Scoring Timeline to Audit Log ────────────────
            // Write one scoring_audit_log row per timeline event so the Scoring
            // Timeline UI can display the full evolution without re-running the pipeline.
            if (result.rescoringTimeline && result.rescoringTimeline.length > 0) {
              try {
                // Build a map of assetId (string) → discovered_assets.id (int)
                const storedAssets = await db.getDiscoveredAssetsByScan(scanId);
                const assetIdMap = new Map<string, number>();
                for (const sa of storedAssets) {
                  if (sa.assetId) assetIdMap.set(sa.assetId, sa.id);
                }

                const auditEntries = result.rescoringTimeline
                  .map(evt => {
                    const dbAssetId = assetIdMap.get(evt.assetId);
                    if (!dbAssetId) return null;
                    // Find the matching analysis for full score snapshot
                    const analysis = result.assets.find(a => a.asset.assetId === evt.assetId);
                    return {
                      assetId: dbAssetId,
                      scanId,
                      carverScores: analysis?.carverScores || null,
                      shockScores: analysis?.shockScores || null,
                      cvssEstimate: analysis?.cvssEstimate || null,
                      missionImpactScore: analysis?.missionImpactScore || null,
                      impactScore: evt.phase === 'initial_scan' ? (analysis?.impactScore || 0) : (analysis?.impactScore || 0),
                      likelihoodScore: analysis?.likelihoodScore || 0,
                      hybridRiskScore: evt.newScore,
                      riskBand: evt.newBand,
                      triggerType: evt.triggerType,
                      previousScore: evt.previousScore,
                      delta: evt.delta,
                      changeDescription: evt.changeDescription,
                      factorChanges: evt.factorChanges,
                      pipelinePhase: evt.phase,
                      computedBy: 'pipeline',
                    };
                  })
                  .filter((e): e is NonNullable<typeof e> => e !== null);

                if (auditEntries.length > 0) {
                  await db.bulkInsertScoringAuditEntries(auditEntries);
                  console.log(`[DomainIntel] Persisted ${auditEntries.length} re-scoring timeline events to audit log`);
                }
              } catch (auditErr: any) {
                console.error(`[DomainIntel] Failed to persist re-scoring timeline (non-fatal): ${auditErr.message}`);
              }
            }

            // Trim pipelineOutput before storing to prevent oversized DB writes.
            // The full result can contain passiveRecon (1000+ observations), exploitMatches (1000+ entries),
            // and all asset postureFindings duplicated — this can exceed 15-20MB.
            // We store a trimmed version with summaries and metadata only;
            // the full asset data is already stored in discovered_assets table.
            const trimmedOutput = {
              orgProfile: result.orgProfile,
              overallRiskScore: result.overallRiskScore,
              overallRiskBand: result.overallRiskBand,
              totalAssets: result.totalAssets,
              totalFindings: result.totalFindings,
              confirmedFindings: result.confirmedFindingsCount || 0,
              probableFindings: result.probableFindingsCount || 0,
              potentialFindings: result.potentialFindingsCount || 0,
              discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
              discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
              // Full discovery coverage object for the Coverage tab
              discoveryCoverage: result.discoveryCoverage ? {
                coverageScore: result.discoveryCoverage.coverageScore,
                coverageBand: result.discoveryCoverage.coverageBand,
                priorities: result.discoveryCoverage.priorities,
                assessment: result.discoveryCoverage.assessment,
                structuralGaps: result.discoveryCoverage.structuralGaps,
                actionableGaps: result.discoveryCoverage.actionableGaps,
              } : undefined,
              // Email security analysis for the Email Security tab
              emailSecurityReport: (result as any).emailSecurityReport || (result as any).emailSecurity || undefined,
              executiveSummary: result.executiveSummary,
              threatModelSummary: result.threatModelSummary,
              // Keep KEV enrichment summary but trim the full match list
              kevEnrichment: result.kevEnrichment ? {
                riskBoost: result.kevEnrichment.riskBoost,
                ransomwareExposure: result.kevEnrichment.ransomwareExposure,
                criticalKevCount: result.kevEnrichment.criticalKevCount,
                summary: result.kevEnrichment.summary,
                chainSteps: result.kevEnrichment.chainSteps,
                matchCount: result.kevEnrichment.matches.length,
                // Keep top 50 KEV matches for campaign design reference
                matches: result.kevEnrichment.matches.slice(0, 50),
              } : undefined,
              // Keep breach data summary (small)
              breachData: result.breachData,
              // Keep exploit match summary but trim the full list
              exploitMatches: result.exploitMatches ? {
                totalMetasploit: result.exploitMatches.totalMetasploit,
                totalExploitDb: result.exploitMatches.totalExploitDb,
                totalCalderaAbilities: result.exploitMatches.totalCalderaAbilities,
                remoteAccessCount: result.exploitMatches.remoteAccessCount,
                matchCount: result.exploitMatches.matches.length,
                // Keep top 30 exploit matches for reference
                matches: result.exploitMatches.matches.slice(0, 30),
              } : undefined,
              // Passive recon summary only — full observations are too large
              passiveRecon: result.passiveRecon ? {
                summary: result.passiveRecon.summary,
                riskSignals: result.passiveRecon.riskSignals?.slice(0, 30),
                connectorResults: result.passiveRecon.connectorResults?.map(cr => ({
                  connector: cr.connector,
                  observationCount: cr.observations.length,
                  durationMs: cr.durationMs,
                  errors: cr.errors,
                })),
              } : undefined,
              // Discovered subdomains — deduplicated from all passive recon connectors
              discoveredSubdomains: (() => {
                if (!result.passiveRecon?.allObservations) return [];
                const seen = new Set<string>();
                return result.passiveRecon.allObservations
                  .filter(o => o.assetType === 'subdomain' && o.name)
                  .filter(o => {
                    const key = o.name!.toLowerCase();
                    if (seen.has(key)) return false;
                    seen.add(key);
                    return true;
                  })
                  .map(o => ({
                    name: o.name!,
                    ip: o.ip || null,
                    source: o.source,
                    firstSeen: o.firstSeen || null,
                    lastSeen: o.lastSeen || null,
                    tags: o.tags?.filter(t => t.startsWith('port:') || t.startsWith('product:') || t.startsWith('version:')) || [],
                  }))
                  .slice(0, 500);
              })(),
              // Open ports & services — extracted from all IP observations
              discoveredPorts: (() => {
                if (!result.passiveRecon?.allObservations) return [];
                const portMap = new Map<string, { ip: string; port: number; transport: string; product: string; version: string; hostname: string; source: string; vulns: string[]; cpes: string[]; banner: string; os: string }>();
                for (const obs of result.passiveRecon.allObservations) {
                  if (obs.assetType !== 'ip' || !obs.ip) continue;
                  const evidence = obs.evidence as any;
                  // Extract from tags for Shodan observations
                  const portTags = (obs.tags || []).filter(t => t.startsWith('port:'));
                  if (evidence?.port) {
                    const key = `${obs.ip}:${evidence.port}`;
                    if (!portMap.has(key)) {
                      portMap.set(key, {
                        ip: obs.ip,
                        port: evidence.port,
                        transport: evidence.transport || 'tcp',
                        product: evidence.product || '',
                        version: evidence.version || '',
                        hostname: obs.name || obs.ip,
                        source: obs.source,
                        vulns: (evidence.vulns || []).slice(0, 10),
                        cpes: (evidence.cpes || []).slice(0, 5),
                        banner: (evidence.banner || evidence.bannerSnippet || '').slice(0, 200),
                        os: evidence.os || '',
                      });
                    }
                  } else if (evidence?.ports && Array.isArray(evidence.ports)) {
                    // InternetDB-style: multiple ports in one observation
                    for (const p of evidence.ports) {
                      const key = `${obs.ip}:${p}`;
                      if (!portMap.has(key)) {
                        portMap.set(key, {
                          ip: obs.ip,
                          port: p,
                          transport: 'tcp',
                          product: '',
                          version: '',
                          hostname: obs.name || obs.ip,
                          source: obs.source,
                          vulns: (evidence.vulns || []).slice(0, 10),
                          cpes: (evidence.cpes || []).slice(0, 5),
                          banner: (evidence.banner || evidence.bannerSnippet || '').slice(0, 200),
                          os: evidence.os || '',
                        });
                      }
                    }
                  }
                }
                return Array.from(portMap.values()).slice(0, 500);
              })(),
              // Asset summaries only — full data is in discovered_assets table
              assetSummaries: result.assets.map(a => ({
                assetId: a.asset.assetId,
                hostname: a.asset.hostname,
                assetType: a.asset.assetType,
                hybridRiskScore: a.hybridRiskScore,
                riskBand: a.riskBand,
                findingCount: a.postureFindings.length,
                vulnRiskScore: a.vulnRiskScore,
              })),
              // Cross-module enrichment results (Bug Bounty, Threat Intel, OpSec, Discovery)
              crossModuleEnrichment: result.crossModuleEnrichment ? {
                bugBounty: result.crossModuleEnrichment.bugBounty,
                threatIntel: result.crossModuleEnrichment.threatIntel,
                opsec: result.crossModuleEnrichment.opsec,
                discoveryDeepDive: result.crossModuleEnrichment.discoveryDeepDive,
                summary: result.crossModuleEnrichment.summary,
              } : undefined,
              // Post-enrichment LLM analysis (attack paths, blind spots, recommendations)
              postEnrichmentAnalysis: result.postEnrichmentAnalysis ? {
                executiveAnalysis: (result.postEnrichmentAnalysis as any).executiveAnalysis || result.postEnrichmentAnalysis.overallAssessment,
                attackPaths: result.postEnrichmentAnalysis.attackPaths?.slice(0, 20),
                blindSpots: result.postEnrichmentAnalysis.blindSpots?.slice(0, 20),
                prioritizedRecommendations: result.postEnrichmentAnalysis.prioritizedRecommendations?.slice(0, 30),
                crossFindingCorrelations: result.postEnrichmentAnalysis.crossFindingCorrelations?.slice(0, 20),
                threatActorMapping: result.postEnrichmentAnalysis.threatActorMapping?.slice(0, 15),
                overallAssessment: result.postEnrichmentAnalysis.overallAssessment,
                confidenceStatement: result.postEnrichmentAnalysis.confidenceStatement,
                enrichmentSources: (result.postEnrichmentAnalysis as any).enrichmentSources,
              } : undefined,
              // Org discovery results — related domains found via WHOIS/DNS/cert pivoting
              orgDiscovery: result.orgDiscovery ? {
                seedDomain: result.orgDiscovery.seedDomain,
                orgName: result.orgDiscovery.orgName,
                orgEmail: result.orgDiscovery.orgEmail,
                totalCandidatesFound: result.orgDiscovery.totalCandidatesFound,
                verifiedDomains: result.orgDiscovery.verifiedDomains.slice(0, 50),
                unverifiedDomains: result.orgDiscovery.unverifiedDomains.slice(0, 30),
                discoveryStats: result.orgDiscovery.discoveryStats,
                durationMs: result.orgDiscovery.durationMs,
              } : undefined,
              complianceScan: result.complianceScan || undefined,
              containerExposure: result.containerExposure || undefined,
            };

            // ── Delta Comparison: Compare with previous scan for the same domain ──
            let deltaReport: any = null;
            try {
              const previousScan = await db.getPreviousCompletedScan(pipelineInput.primaryDomain, scanId);
              if (previousScan) {
                const { compareReconResults } = await import('../lib/passive/delta-comparison');
                // Extract observations from previous scan's pipelineOutput
                const prevOutput = previousScan.pipelineOutput as any;
                const prevObservations = prevOutput?.passiveRecon?.allObservations
                  || prevOutput?.passiveRecon?.observations
                  || [];
                // Current observations from pipeline result
                const currentObservations = result.passiveRecon?.allObservations || [];
                const prevDate = previousScan.createdAt ? new Date(previousScan.createdAt) : null;
                deltaReport = compareReconResults(prevObservations, currentObservations, prevDate);
                // Trim deltas to keep pipelineOutput manageable (keep top 100 non-unchanged)
                if (deltaReport.deltas) {
                  const significantDeltas = deltaReport.deltas.filter((d: any) => d.status !== 'unchanged');
                  deltaReport.deltas = significantDeltas.slice(0, 100);
                  deltaReport.previousScanId = previousScan.id;
                }
                console.log(`[DomainIntel] Delta comparison: ${deltaReport.stats.newObservations} new, ${deltaReport.stats.removedObservations} removed, ${deltaReport.stats.changedObservations} changed, trend=${deltaReport.overallRiskTrend}`);
              } else {
                console.log(`[DomainIntel] No previous scan found for ${pipelineInput.primaryDomain} — skipping delta comparison`);
              }
            } catch (deltaErr: any) {
              console.error(`[DomainIntel] Delta comparison failed (non-fatal):`, deltaErr.message);
            }

            // Merge delta report into trimmed output
            const outputWithDelta = deltaReport
              ? { ...trimmedOutput, deltaReport }
              : trimmedOutput;

            // If scan-only mode, skip threat actor matching and campaign design
            if (pipelineInput.scanOnly) {
              await db.updateDomainIntelScan(scanId, {
                status: 'scan_complete',
                totalAssets: result.totalAssets,
                totalFindings: result.totalFindings,
              confirmedFindings: result.confirmedFindingsCount || 0,
              probableFindings: result.probableFindingsCount || 0,
              potentialFindings: result.potentialFindingsCount || 0,
                discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
                discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
                overallRiskScore: result.overallRiskScore,
                overallRiskBand: result.overallRiskBand,
                executiveSummary: result.executiveSummary,
                threatModelSummary: result.threatModelSummary,
                campaignRecommendations: [],
                pipelineOutput: outputWithDelta,
              });
              console.log(`[DomainIntel] Scan-only completed for scan ${scanId}: ${result.totalAssets} assets, risk=${result.overallRiskScore}`);
              try { const { emitReconComplete } = await import('../lib/ws-event-hub'); emitReconComplete({ scanId, domain: pipelineInput.primaryDomain, findings: result.totalFindings || 0, engagementId: pipelineInput.engagementId }); } catch {}
              // Auto-crawl discovered web assets (fire-and-forget)
              setImmediate(async () => {
                try {
                  const { triggerAutoCrawl } = await import('../lib/auto-crawl');
                  await triggerAutoCrawl(scanId, pipelineInput.primaryDomain);
                } catch (crawlErr: any) {
                  console.error(`[AutoCrawl] Failed for scan ${scanId}:`, crawlErr.message);
                }
              });
            } else {
              // Full engagement: run threat actor matching + campaign design
              let threatActorMatches = null;
              try {
                const { matchThreatActors } = await import('../lib/threat-actor-matcher');
                const allTech: string[] = [];
                const assets = Array.isArray(result.assets) ? result.assets : [];
                for (const a of assets) {
                  if (a.asset?.technologies) allTech.push(...a.asset.technologies);
                }
                threatActorMatches = await matchThreatActors({
                  sector: pipelineInput.sector,
                  clientType: pipelineInput.clientType,
                  discoveredTechnologies: allTech,
                  discoveredAssets: assets.map(a => ({
                    hostname: a.asset?.hostname,
                    assetType: a.asset?.assetType,
                    technologies: a.asset?.technologies,
                  })),
                  riskScore: result.overallRiskScore,
                  criticalFunctions: pipelineInput.criticalFunctions,
                });
              } catch (matchErr: any) {
                console.error('[DomainIntel] Threat actor matching failed:', matchErr.message);
              }

              // Update scan with results (including threat actor matches + delta)
              const pipelineOutputWithMatches = {
                ...outputWithDelta,
                threatActorMatches,
              };
              await db.updateDomainIntelScan(scanId, {
                status: 'completed',
                totalAssets: result.totalAssets,
                totalFindings: result.totalFindings,
              confirmedFindings: result.confirmedFindingsCount || 0,
              probableFindings: result.probableFindingsCount || 0,
              potentialFindings: result.potentialFindingsCount || 0,
                discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
                discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
                overallRiskScore: result.overallRiskScore,
                overallRiskBand: result.overallRiskBand,
                executiveSummary: result.executiveSummary,
                threatModelSummary: result.threatModelSummary,
                campaignRecommendations: result.campaignRecommendations,
                pipelineOutput: pipelineOutputWithMatches,
              });

              console.log(`[DomainIntel] Pipeline completed for scan ${scanId}: ${result.totalAssets} assets, risk=${result.overallRiskScore}`);
              try { const { emitReconComplete, emitSystemNotification } = await import('../lib/ws-event-hub'); emitReconComplete({ scanId, domain: pipelineInput.primaryDomain, findings: result.totalFindings || 0, engagementId: pipelineInput.engagementId }); emitSystemNotification({ title: 'Domain Intel Complete', message: `Scan of ${pipelineInput.primaryDomain}: ${result.totalAssets} assets, ${result.totalFindings} findings, risk=${result.overallRiskScore}`, severity: 'info' }); } catch {}

              // Auto-harvest credentials from passive recon observations into engagement credential list
              if (pipelineInput.engagementId && result.passiveRecon?.allObservations) {
                setImmediate(async () => {
                  try {
                    const { harvestCredentialsFromObservations, harvestFromExistingFindings } = await import('../lib/credential-harvester');
                    // Harvest from passive recon observations (DeHashed, IntelX, Hudson Rock, LeakCheck)
                    const obsResult = await harvestCredentialsFromObservations(
                      pipelineInput.engagementId!,
                      pipelineInput.primaryDomain,
                      result.passiveRecon!.allObservations
                    );
                    console.log(`[CredentialHarvester] Observations: ${obsResult.inserted} inserted, ${obsResult.duplicates} duplicates for engagement ${pipelineInput.engagementId}`);
                    // Also harvest from existing credentialFindings table (DeHashed breach data)
                    const findingsResult = await harvestFromExistingFindings(
                      pipelineInput.engagementId!,
                      pipelineInput.primaryDomain
                    );
                    console.log(`[CredentialHarvester] Existing findings: ${findingsResult.inserted} inserted, ${findingsResult.duplicates} duplicates`);
                  } catch (harvestErr: any) {
                    console.error(`[CredentialHarvester] Failed for engagement ${pipelineInput.engagementId}:`, harvestErr.message);
                  }
                });
              }

              // Auto-crawl discovered web assets (fire-and-forget)
              setImmediate(async () => {
                try {
                  const { triggerAutoCrawl } = await import('../lib/auto-crawl');
                  await triggerAutoCrawl(scanId, pipelineInput.primaryDomain);
                } catch (crawlErr: any) {
                  console.error(`[AutoCrawl] Failed for scan ${scanId}:`, crawlErr.message);
                }
              });
            }
          } catch (err: any) {
            const errMsg = err?.message || (typeof err === 'string' ? err : 'Unknown pipeline error');
            const errStack = err?.stack?.substring(0, 1000) || '';
            console.error(`[DomainIntel] Pipeline failed for scan ${scanId}:`, errMsg, errStack.substring(0, 500));
            // Store error details so they can be viewed in the UI
            await db.updateDomainIntelScan(scanId, {
              status: 'failed',
              pipelineOutput: { error: errMsg, stack: errStack, failedAt: new Date().toISOString() },
            }).catch((updateErr) => {
              console.error(`[DomainIntel] Failed to update scan ${scanId} status to failed:`, updateErr?.message || 'unknown');
            });
          }
        });

        return { scanId };
      }),

    // Start engagement on an existing scan-complete scan (runs threat actor matching + campaign design)
    startEngagement: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        if (scan.status !== 'scan_complete') {
          throw new TRPCError({ code: 'BAD_REQUEST', message: `Scan must be in scan_complete status to start engagement. Current status: ${scan.status}` });
        }

        // Update status to indicate engagement is running
        await db.updateDomainIntelScan(input.scanId, { status: 'recommending' });

        const scanId = input.scanId;
        setImmediate(async () => {
          try {
            console.log(`[DomainIntel] Starting engagement for scan ${scanId}`);
            const pipeline = scan.pipelineOutput as any;
            const orgProfile = scan.orgProfile as any;
            const assets = await db.getDiscoveredAssetsByScan(scanId);

            // Reconstruct analyses from stored assets for campaign generation
            const { generateCampaignRecommendations, generateSummaries } = await import('../domainIntel');
            const analyses = assets.map((a: any) => ({
              asset: {
                assetId: a.assetId || a.hostname,
                hostname: a.hostname,
                url: a.url,
                assetType: a.assetType || 'unknown',
                dnsRecords: a.dnsRecords || [],
                dnsStatus: a.dnsStatus,
                headers: a.headers,
                technologies: a.technologies || [],
                assetClasses: a.assetClasses || [],
                tags: a.tags || [],
              },
              carverScores: a.carverScores || {},
              shockScores: a.shockScores || {},
              missionImpactScore: (a.missionImpactScore || 0) / 10,
              suggestedTier: a.suggestedTier || 'tier_3',
              hybridRiskScore: a.hybridRiskScore || 0,
              riskBand: a.riskBand || 'low',
              cvssEstimate: (a.cvssEstimate || 0) / 10,
              contextIndicators: a.contextIndicators || [],
              postureFindings: a.postureFindings || [],
              testVectors: a.testVectors || [],
              confidence: a.confidence || 0,
              assetCriticalityScore: a.assetCriticalityScore || 0,
              assetCriticalityBand: a.assetCriticalityBand || 'low',
              vulnRiskScore: a.vulnRiskScore || 0,
              vulnRiskBand: a.vulnRiskBand || 'low',
              impactScore: a.impactScore || 0,
              likelihoodScore: a.likelihoodScore || 0,
              missionFunction: a.missionFunction || 'public_facing_services',
              essentialService: a.essentialService || 'general_server',
              businessImpactLevel: a.businessImpactLevel || 'moderate',
              deviceType: a.deviceType || 'unknown',
              platformType: a.platformType || 'unknown',
              missionJustification: a.missionJustification || '',
            }));

            // Run campaign design
            const kevEnrichment = pipeline?.kevEnrichment;
            const campaigns = await generateCampaignRecommendations(analyses, orgProfile, kevEnrichment);

            // Run threat actor matching
            let threatActorMatches = null;
            try {
              const { matchThreatActors } = await import('../lib/threat-actor-matcher');
              const allTech: string[] = [];
              for (const a of analyses) {
                if (a.asset.technologies) allTech.push(...a.asset.technologies);
              }
              threatActorMatches = await matchThreatActors({
                sector: orgProfile.sector,
                clientType: orgProfile.clientType,
                discoveredTechnologies: allTech,
                discoveredAssets: analyses.map(a => ({
                  hostname: a.asset.hostname,
                  assetType: a.asset.assetType,
                  technologies: a.asset.technologies,
                })),
                riskScore: scan.overallRiskScore || 0,
                criticalFunctions: orgProfile.criticalFunctions || [],
              });
            } catch (matchErr: any) {
              console.error('[DomainIntel] Threat actor matching failed:', matchErr.message);
            }

            // Generate full summaries (with campaigns)
            const summaries = await generateSummaries(analyses, campaigns, orgProfile);

            // Update scan with engagement results — merge threat actor matches into existing trimmed output
            const pipelineOutputWithMatches = {
              ...pipeline,
              threatActorMatches,
            };
            await db.updateDomainIntelScan(scanId, {
              status: 'completed',
              executiveSummary: summaries.executiveSummary,
              threatModelSummary: summaries.threatModelSummary,
              campaignRecommendations: campaigns,
              pipelineOutput: pipelineOutputWithMatches,
            });

            console.log(`[DomainIntel] Engagement completed for scan ${scanId}: ${campaigns.length} campaigns designed`);
          } catch (err: any) {
            console.error(`[DomainIntel] Engagement failed for scan ${scanId}:`, err.message, err.stack?.substring(0, 500));
            // Revert to scan_complete so user can retry, and store error details
            const existingOutput = scan.pipelineOutput as any;
            await db.updateDomainIntelScan(scanId, {
              status: 'scan_complete',
              pipelineOutput: {
                ...(existingOutput || {}),
                engagementError: { message: err.message, failedAt: new Date().toISOString() },
              },
            }).catch(() => {});
          }
        });

        return { scanId };
      }),

    // Poll scan status (used by frontend to track async pipeline progress)
    getScanStatus: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        // Detect stuck scans: if status is an in-progress stage and hasn't been updated in 15 minutes
        const STUCK_THRESHOLD_MS = 15 * 60 * 1000; // 15 minutes
        const inProgressStatuses = ['pending', 'passive_recon', 'discovering', 'analyzing', 'scoring', 'recommending'];
        const isStuck = inProgressStatuses.includes(scan.status)
          && scan.updatedAt
          && (Date.now() - new Date(scan.updatedAt).getTime() > STUCK_THRESHOLD_MS);

        // Extract error info from pipelineOutput if available
        const pipelineOutput = scan.pipelineOutput as any;
        const errorInfo = pipelineOutput?.error
          ? { message: pipelineOutput.error, failedAt: pipelineOutput.failedAt }
          : pipelineOutput?.engagementError || null;

        return {
          scanId: scan.id,
          status: isStuck ? 'failed' as const : scan.status,
          isStuck: !!isStuck,
          primaryDomain: scan.primaryDomain,
          totalAssets: scan.totalAssets || 0,
          overallRiskScore: scan.overallRiskScore || null,
          overallRiskBand: scan.overallRiskBand || null,
          errorInfo,
        };
      }),

    // Retry a failed or stuck scan by resetting it and re-running the pipeline
    retryScan: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        // Allow retry only for failed scans, pending scans, or stuck scans (in-progress for >15 min)
        const STUCK_THRESHOLD_MS = 15 * 60 * 1000; // 15 minutes
        const inProgressStatuses = ['pending', 'passive_recon', 'discovering', 'analyzing', 'scoring', 'recommending'];
        const isStuck = inProgressStatuses.includes(scan.status)
          && scan.updatedAt
          && (Date.now() - new Date(scan.updatedAt).getTime() > STUCK_THRESHOLD_MS);

        if (scan.status !== 'failed' && scan.status !== 'pending' && !isStuck) {
          throw new TRPCError({
            code: 'BAD_REQUEST',
            message: `Scan cannot be retried in status "${scan.status}". Only failed or stuck scans can be retried.`,
          });
        }

        // Clean up any orphaned assets from a partial previous run
        try {
          await db.deleteDiscoveredAssetsByScan(input.scanId);
        } catch { /* ignore if no assets exist */ }

        // Reset scan to discovering
        await db.updateDomainIntelScan(input.scanId, {
          status: 'discovering',
          totalAssets: 0,
          totalFindings: 0,
          confirmedFindings: 0,
          probableFindings: 0,
          potentialFindings: 0,
          discoveryCoverageScore: 0,
          discoveryCoverageBand: null,
          overallRiskScore: null,
          overallRiskBand: null,
          executiveSummary: null,
          threatModelSummary: null,
          campaignRecommendations: null,
          pipelineOutput: null,
        });

        // Re-run the pipeline in background
        const orgProfile = scan.orgProfile as any;
        const scanId = input.scanId;
        setImmediate(async () => {
          try {
            console.log(`[DomainIntel] Retrying pipeline for scan ${scanId}: ${scan.primaryDomain}`);
            const { runDomainIntelPipeline } = await import('../domainIntel');

            const result = await runDomainIntelPipeline(
              {
                customerName: orgProfile?.customerName || scan.primaryDomain,
                primaryDomain: scan.primaryDomain,
                additionalDomains: (scan.additionalDomains as string[]) || [],
                sector: scan.sector || 'Technology',
                clientType: scan.clientType,
                criticalFunctions: (scan.criticalFunctions as string[]) || [],
                complianceFlags: (scan.complianceFlags as string[]) || [],
                notes: scan.notes || undefined,
              },
              async (stage) => {
                await db.updateDomainIntelScan(scanId, { status: stage }).catch(() => {});
                console.log(`[DomainIntel] Retry scan ${scanId} stage: ${stage}`);
              },
              { scanMode: 'standard', skipEngagement: true }
            );

            // Batch insert assets
            const assetRecords = result.assets.map(a => ({
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
                ? Object.entries(a.asset.technologyVersions).map(([name, version]) => ({
                    name,
                    version: version || '',
                    category: 'detected',
                    confidence: version ? 0.9 : 0.7,
                  }))
                : (a.asset.technologies || []).map((t: string) => ({ name: t, version: '', category: 'inferred', confidence: 0.5 })),
              assetClasses: a.asset.assetClasses,
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
              recommendedCalderaAbilities: a.testVectors.filter((v: any) => v.suggestedEmulation?.calderaAbilityHint).map((v: any) => v.suggestedEmulation),
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

            if (assetRecords.length > 0) {
              const BATCH_SIZE = 5;
              for (let i = 0; i < assetRecords.length; i += BATCH_SIZE) {
                const batch = assetRecords.slice(i, i + BATCH_SIZE);
                try {
                  await db.bulkCreateDiscoveredAssets(batch);
                } catch (batchErr: any) {
                  console.warn(`[DomainIntel] Retry batch insert failed, falling back to individual: ${batchErr.message}`);
                  for (const record of batch) {
                    try { await db.createDiscoveredAsset(record); } catch (e: any) {
                      console.error(`[DomainIntel] Retry: failed to insert asset ${record.hostname}: ${e.message}`);
                    }
                  }
                }
              }
            }

            // Trimmed output
            const trimmedOutput = {
              orgProfile: result.orgProfile,
              overallRiskScore: result.overallRiskScore,
              overallRiskBand: result.overallRiskBand,
              totalAssets: result.totalAssets,
              totalFindings: result.totalFindings,
              confirmedFindings: result.confirmedFindingsCount || 0,
              probableFindings: result.probableFindingsCount || 0,
              potentialFindings: result.potentialFindingsCount || 0,
              discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
              discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
              // Full discovery coverage object for the Coverage tab
              discoveryCoverage: result.discoveryCoverage ? {
                coverageScore: result.discoveryCoverage.coverageScore,
                coverageBand: result.discoveryCoverage.coverageBand,
                priorities: result.discoveryCoverage.priorities,
                assessment: result.discoveryCoverage.assessment,
                structuralGaps: result.discoveryCoverage.structuralGaps,
                actionableGaps: result.discoveryCoverage.actionableGaps,
              } : undefined,
              // Email security analysis for the Email Security tab
              emailSecurityReport: (result as any).emailSecurityReport || (result as any).emailSecurity || undefined,
              executiveSummary: result.executiveSummary,
              threatModelSummary: result.threatModelSummary,
              kevEnrichment: result.kevEnrichment ? {
                riskBoost: result.kevEnrichment.riskBoost,
                ransomwareExposure: result.kevEnrichment.ransomwareExposure,
                criticalKevCount: result.kevEnrichment.criticalKevCount,
                summary: result.kevEnrichment.summary,
                chainSteps: result.kevEnrichment.chainSteps,
                matchCount: result.kevEnrichment.matches.length,
                matches: result.kevEnrichment.matches.slice(0, 50),
              } : undefined,
              breachData: result.breachData,
              exploitMatches: result.exploitMatches ? {
                totalMetasploit: result.exploitMatches.totalMetasploit,
                totalExploitDb: result.exploitMatches.totalExploitDb,
                totalCalderaAbilities: result.exploitMatches.totalCalderaAbilities,
                remoteAccessCount: result.exploitMatches.remoteAccessCount,
                matchCount: result.exploitMatches.matches.length,
                matches: result.exploitMatches.matches.slice(0, 30),
              } : undefined,
              passiveRecon: result.passiveRecon ? {
                summary: result.passiveRecon.summary,
                riskSignals: result.passiveRecon.riskSignals?.slice(0, 30),
                connectorResults: result.passiveRecon.connectorResults?.map((cr: any) => ({
                  connector: cr.connector,
                  observationCount: cr.observations.length,
                  durationMs: cr.durationMs,
                  errors: cr.errors,
                })),
              } : undefined,
              assetSummaries: result.assets.map(a => ({
                assetId: a.asset.assetId,
                hostname: a.asset.hostname,
                assetType: a.asset.assetType,
                hybridRiskScore: a.hybridRiskScore,
                riskBand: a.riskBand,
                findingCount: a.postureFindings.length,
                vulnRiskScore: a.vulnRiskScore,
              })),
              // Cross-module enrichment results (Bug Bounty, Threat Intel, OpSec, Discovery)
              crossModuleEnrichment: result.crossModuleEnrichment ? {
                bugBounty: result.crossModuleEnrichment.bugBounty,
                threatIntel: result.crossModuleEnrichment.threatIntel,
                opsec: result.crossModuleEnrichment.opsec,
                discoveryDeepDive: result.crossModuleEnrichment.discoveryDeepDive,
                summary: result.crossModuleEnrichment.summary,
              } : undefined,
              // Post-enrichment LLM analysis (attack paths, blind spots, recommendations)
              postEnrichmentAnalysis: result.postEnrichmentAnalysis ? {
                executiveAnalysis: (result.postEnrichmentAnalysis as any).executiveAnalysis || result.postEnrichmentAnalysis.overallAssessment,
                attackPaths: result.postEnrichmentAnalysis.attackPaths?.slice(0, 20),
                blindSpots: result.postEnrichmentAnalysis.blindSpots?.slice(0, 20),
                prioritizedRecommendations: result.postEnrichmentAnalysis.prioritizedRecommendations?.slice(0, 30),
                crossFindingCorrelations: result.postEnrichmentAnalysis.crossFindingCorrelations?.slice(0, 20),
                threatActorMapping: result.postEnrichmentAnalysis.threatActorMapping?.slice(0, 15),
                overallAssessment: result.postEnrichmentAnalysis.overallAssessment,
                confidenceStatement: result.postEnrichmentAnalysis.confidenceStatement,
                enrichmentSources: (result.postEnrichmentAnalysis as any).enrichmentSources,
              } : undefined,
              // Org discovery results
              orgDiscovery: result.orgDiscovery ? {
                seedDomain: result.orgDiscovery.seedDomain,
                orgName: result.orgDiscovery.orgName,
                orgEmail: result.orgDiscovery.orgEmail,
                totalCandidatesFound: result.orgDiscovery.totalCandidatesFound,
                verifiedDomains: result.orgDiscovery.verifiedDomains.slice(0, 50),
                unverifiedDomains: result.orgDiscovery.unverifiedDomains.slice(0, 30),
                discoveryStats: result.orgDiscovery.discoveryStats,
                durationMs: result.orgDiscovery.durationMs,
              } : undefined,
              complianceScan: result.complianceScan || undefined,
              containerExposure: result.containerExposure || undefined,
              retriedAt: new Date().toISOString(),
            };

            await db.updateDomainIntelScan(scanId, {
              status: 'scan_complete',
              totalAssets: result.totalAssets,
              totalFindings: result.totalFindings,
              confirmedFindings: result.confirmedFindingsCount || 0,
              probableFindings: result.probableFindingsCount || 0,
              potentialFindings: result.potentialFindingsCount || 0,
              discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
              discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
              overallRiskScore: result.overallRiskScore,
              overallRiskBand: result.overallRiskBand,
              executiveSummary: result.executiveSummary,
              threatModelSummary: result.threatModelSummary,
              campaignRecommendations: [],
              pipelineOutput: trimmedOutput,
            });

            console.log(`[DomainIntel] Retry completed for scan ${scanId}: ${result.totalAssets} assets, risk=${result.overallRiskScore}`);
            try { const { emitReconComplete } = await import('../lib/ws-event-hub'); emitReconComplete({ scanId, domain: scan.primaryDomain, findings: result.totalFindings || 0, engagementId: scan.engagementId || undefined }); } catch {}
          } catch (err: any) {
            console.error(`[DomainIntel] Retry pipeline failed for scan ${scanId}:`, err.message, err.stack?.substring(0, 500));
            await db.updateDomainIntelScan(scanId, {
              status: 'failed',
              pipelineOutput: { error: err.message, stack: err.stack?.substring(0, 1000), failedAt: new Date().toISOString(), retryFailed: true },
            }).catch(() => {});
          }
        });

        return { scanId: input.scanId, message: 'Scan retry started' };
      }),

    // Bulk retry all failed or stuck scans
    bulkRetryStuckScans: protectedProcedure
      .mutation(async ({ ctx }) => {
        const allScans = await db.getDomainIntelScans();
        const STUCK_THRESHOLD_MS = 15 * 60 * 1000;
        const now = Date.now();

        const retryable = allScans.filter((s: any) => {
          if (s.status === 'failed') return true;
          const inProgressStatuses = ['pending', 'passive_recon', 'discovering', 'analyzing', 'scoring', 'recommending'];
          if (inProgressStatuses.includes(s.status) && s.updatedAt) {
            return (now - new Date(s.updatedAt).getTime()) > STUCK_THRESHOLD_MS;
          }
          return false;
        });

        if (retryable.length === 0) {
          return { retriedCount: 0, message: 'No failed or stuck scans found' };
        }

        // Trigger retry for each scan with staggered starts
        let queued = 0;
        for (const scan of retryable) {
          const scanId = scan.id;
          const delay = queued * 3000; // 3s stagger
          setTimeout(async () => {
            try {
              await db.deleteDiscoveredAssetsByScan(scanId).catch(() => {});
              await db.updateDomainIntelScan(scanId, {
                status: 'discovering',
                totalAssets: 0,
                totalFindings: 0,
                confirmedFindings: 0,
                probableFindings: 0,
                potentialFindings: 0,
                discoveryCoverageScore: 0,
                discoveryCoverageBand: null,
                overallRiskScore: null,
                overallRiskBand: null,
                executiveSummary: null,
                threatModelSummary: null,
                campaignRecommendations: null,
                pipelineOutput: null,
              });

              const orgProfile = scan.orgProfile as any;
              const { runDomainIntelPipeline } = await import('../domainIntel');
              const result = await runDomainIntelPipeline(
                {
                  customerName: orgProfile?.customerName || scan.primaryDomain,
                  primaryDomain: scan.primaryDomain,
                  additionalDomains: (scan.additionalDomains as string[]) || [],
                  sector: scan.sector || 'Technology',
                  clientType: scan.clientType,
                  criticalFunctions: (scan.criticalFunctions as string[]) || [],
                  complianceFlags: (scan.complianceFlags as string[]) || [],
                  notes: scan.notes || undefined,
                },
                async (stage) => {
                  await db.updateDomainIntelScan(scanId, { status: stage }).catch(() => {});
                },
                { scanMode: 'standard', skipEngagement: true }
              );

              // Batch insert assets
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
                  ? Object.entries(a.asset.technologyVersions).map(([name, version]) => ({ name, version: version || '', category: 'detected', confidence: version ? 0.9 : 0.7 }))
                  : (a.asset.technologies || []).map((t: string) => ({ name: t, version: '', category: 'inferred', confidence: 0.5 })),
                assetClasses: a.asset.assetClasses,
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
                recommendedCalderaAbilities: a.testVectors.filter((v: any) => v.suggestedEmulation?.calderaAbilityHint).map((v: any) => v.suggestedEmulation),
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

              if (assetRecords.length > 0) {
                const BATCH_SIZE = 5;
                for (let i = 0; i < assetRecords.length; i += BATCH_SIZE) {
                  const batch = assetRecords.slice(i, i + BATCH_SIZE);
                  try { await db.bulkCreateDiscoveredAssets(batch); } catch {
                    for (const record of batch) {
                      try { await db.createDiscoveredAsset(record); } catch {}
                    }
                  }
                }
              }

              await db.updateDomainIntelScan(scanId, {
                status: 'scan_complete',
                totalAssets: result.totalAssets,
                totalFindings: result.totalFindings,
                confirmedFindings: result.confirmedFindingsCount || 0,
                probableFindings: result.probableFindingsCount || 0,
                potentialFindings: result.potentialFindingsCount || 0,
                discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
                discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
                overallRiskScore: result.overallRiskScore,
                overallRiskBand: result.overallRiskBand,
                executiveSummary: result.executiveSummary,
                threatModelSummary: result.threatModelSummary,
                campaignRecommendations: [],
                pipelineOutput: { retriedAt: new Date().toISOString(), bulkRetry: true },
              });
              console.log(`[DomainIntel] Bulk retry completed for scan ${scanId}: ${scan.primaryDomain}`);
            } catch (err: any) {
              console.error(`[DomainIntel] Bulk retry failed for scan ${scanId}: ${err.message}`);
              await db.updateDomainIntelScan(scanId, {
                status: 'failed',
                pipelineOutput: { error: err.message, failedAt: new Date().toISOString(), bulkRetryFailed: true },
              }).catch(() => {});
            }
          }, delay);
          queued++;
        }

        return { retriedCount: queued, message: `${queued} scans queued for retry` };
      }),

    // Refresh a completed scan — re-runs the full pipeline while preserving original data as a snapshot
    refreshScan: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        // Allow refresh only for completed or scan_complete scans
        if (scan.status !== 'completed' && scan.status !== 'scan_complete') {
          throw new TRPCError({
            code: 'BAD_REQUEST',
            message: `Scan must be completed to refresh. Current status: ${scan.status}`,
          });
        }

        // Snapshot the current results before re-running
        const previousSnapshot = {
          snapshotAt: new Date().toISOString(),
          status: scan.status,
          totalAssets: scan.totalAssets,
          totalFindings: scan.totalFindings,
          confirmedFindings: scan.confirmedFindings,
          probableFindings: scan.probableFindings,
          potentialFindings: scan.potentialFindings,
          overallRiskScore: scan.overallRiskScore,
          overallRiskBand: scan.overallRiskBand,
          discoveryCoverageScore: scan.discoveryCoverageScore,
          discoveryCoverageBand: scan.discoveryCoverageBand,
          executiveSummary: scan.executiveSummary,
          threatModelSummary: scan.threatModelSummary,
          campaignRecommendations: scan.campaignRecommendations,
          entityProfile: (scan.pipelineOutput as any)?.entityProfile || null,
          financialImpact: (scan.pipelineOutput as any)?.financialImpact || null,
          autoCrawlSummary: (scan.pipelineOutput as any)?.autoCrawlSummary || null,
        };

        // Determine if this was a full engagement or scan-only
        const wasFullEngagement = scan.status === 'completed';

        // Clean up old assets (they will be re-discovered)
        try {
          await db.deleteDiscoveredAssetsByScan(input.scanId);
        } catch { /* ignore if no assets exist */ }

        // Clean up old web crawl results for this scan
        try {
          const { eq: eqOp } = await import('drizzle-orm');
          const { webCrawlResults: wcr } = await import('../../drizzle/schema');
          const dbInst = await (await import('../db')).getDb();
          if (dbInst) await dbInst.delete(wcr).where(eqOp(wcr.scanId, input.scanId));
        } catch { /* ignore */ }

        // Set status to refreshing (uses 'discovering' status so frontend polling works)
        await db.updateDomainIntelScan(input.scanId, {
          status: 'discovering',
          totalAssets: 0,
          totalFindings: 0,
          confirmedFindings: 0,
          probableFindings: 0,
          potentialFindings: 0,
          discoveryCoverageScore: 0,
          discoveryCoverageBand: null,
          overallRiskScore: null,
          overallRiskBand: null,
          executiveSummary: null,
          threatModelSummary: null,
          campaignRecommendations: null,
          pipelineOutput: { refreshing: true, previousSnapshot, refreshStartedAt: new Date().toISOString() },
        });

        const scanId = input.scanId;
        const orgProfile = scan.orgProfile as any;
        setImmediate(async () => {
          try {
            console.log(`[DomainIntel] Refresh pipeline started for scan ${scanId}: ${scan.primaryDomain}`);
            const { runDomainIntelPipeline } = await import('../domainIntel');

            const result = await runDomainIntelPipeline(
              {
                customerName: orgProfile?.customerName || scan.primaryDomain,
                primaryDomain: scan.primaryDomain,
                additionalDomains: (scan.additionalDomains as string[]) || [],
                sector: scan.sector || 'Technology',
                clientType: scan.clientType,
                criticalFunctions: (scan.criticalFunctions as string[]) || [],
                complianceFlags: (scan.complianceFlags as string[]) || [],
                notes: scan.notes || undefined,
              },
              async (stage) => {
                await db.updateDomainIntelScan(scanId, { status: stage }).catch(() => {});
                console.log(`[DomainIntel] Refresh scan ${scanId} stage: ${stage}`);
              },
              {
                scanMode: (orgProfile?.scanMode as any) || 'standard',
                skipEngagement: !wasFullEngagement,
                scopedAssets: (orgProfile?.scopedAssets as string[])?.length > 0 ? (orgProfile.scopedAssets as string[]) : undefined,
              }
            );

            // Batch insert new assets
            const assetRecords = result.assets.map(a => ({
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
                ? Object.entries(a.asset.technologyVersions).map(([name, version]) => ({
                    name,
                    version: version || '',
                    category: 'detected',
                    confidence: version ? 0.9 : 0.7,
                  }))
                : (a.asset.technologies || []).map((t: string) => ({ name: t, version: '', category: 'inferred', confidence: 0.5 })),
              assetClasses: a.asset.assetClasses,
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
              recommendedCalderaAbilities: a.testVectors.filter((v: any) => v.suggestedEmulation?.calderaAbilityHint).map((v: any) => v.suggestedEmulation),
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

            if (assetRecords.length > 0) {
              const BATCH_SIZE = 5;
              for (let i = 0; i < assetRecords.length; i += BATCH_SIZE) {
                const batch = assetRecords.slice(i, i + BATCH_SIZE);
                try {
                  await db.bulkCreateDiscoveredAssets(batch);
                } catch (batchErr: any) {
                  console.warn(`[DomainIntel] Refresh batch insert failed, falling back: ${batchErr.message}`);
                  for (const record of batch) {
                    try { await db.createDiscoveredAsset(record); } catch (e: any) {
                      console.error(`[DomainIntel] Refresh: failed to insert asset ${record.hostname}: ${e.message}`);
                    }
                  }
                }
              }
            }

            // Build trimmed output with previous snapshot preserved
            const trimmedOutput: any = {
              orgProfile: result.orgProfile,
              overallRiskScore: result.overallRiskScore,
              overallRiskBand: result.overallRiskBand,
              totalAssets: result.totalAssets,
              totalFindings: result.totalFindings,
              confirmedFindings: result.confirmedFindingsCount || 0,
              probableFindings: result.probableFindingsCount || 0,
              potentialFindings: result.potentialFindingsCount || 0,
              discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
              discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
              discoveryCoverage: result.discoveryCoverage ? {
                coverageScore: result.discoveryCoverage.coverageScore,
                coverageBand: result.discoveryCoverage.coverageBand,
                priorities: result.discoveryCoverage.priorities,
                assessment: result.discoveryCoverage.assessment,
                structuralGaps: result.discoveryCoverage.structuralGaps,
                actionableGaps: result.discoveryCoverage.actionableGaps,
              } : undefined,
              emailSecurityReport: (result as any).emailSecurityReport || (result as any).emailSecurity || undefined,
              executiveSummary: result.executiveSummary,
              threatModelSummary: result.threatModelSummary,
              kevEnrichment: result.kevEnrichment ? {
                riskBoost: result.kevEnrichment.riskBoost,
                ransomwareExposure: result.kevEnrichment.ransomwareExposure,
                criticalKevCount: result.kevEnrichment.criticalKevCount,
                summary: result.kevEnrichment.summary,
                chainSteps: result.kevEnrichment.chainSteps,
                matchCount: result.kevEnrichment.matches.length,
                matches: result.kevEnrichment.matches.slice(0, 50),
              } : undefined,
              breachData: result.breachData,
              exploitMatches: result.exploitMatches ? {
                totalMetasploit: result.exploitMatches.totalMetasploit,
                totalExploitDb: result.exploitMatches.totalExploitDb,
                totalCalderaAbilities: result.exploitMatches.totalCalderaAbilities,
                remoteAccessCount: result.exploitMatches.remoteAccessCount,
                matchCount: result.exploitMatches.matches.length,
                matches: result.exploitMatches.matches.slice(0, 30),
              } : undefined,
              passiveRecon: result.passiveRecon ? {
                summary: result.passiveRecon.summary,
                riskSignals: result.passiveRecon.riskSignals?.slice(0, 30),
                connectorResults: result.passiveRecon.connectorResults?.map((cr: any) => ({
                  connector: cr.connector,
                  observationCount: cr.observations.length,
                  durationMs: cr.durationMs,
                  errors: cr.errors,
                })),
              } : undefined,
              assetSummaries: result.assets.map(a => ({
                assetId: a.asset.assetId,
                hostname: a.asset.hostname,
                assetType: a.asset.assetType,
                hybridRiskScore: a.hybridRiskScore,
                riskBand: a.riskBand,
                findingCount: a.postureFindings.length,
                vulnRiskScore: a.vulnRiskScore,
              })),
              crossModuleEnrichment: result.crossModuleEnrichment ? {
                bugBounty: result.crossModuleEnrichment.bugBounty,
                threatIntel: result.crossModuleEnrichment.threatIntel,
                opsec: result.crossModuleEnrichment.opsec,
                discoveryDeepDive: result.crossModuleEnrichment.discoveryDeepDive,
                summary: result.crossModuleEnrichment.summary,
              } : undefined,
              postEnrichmentAnalysis: result.postEnrichmentAnalysis ? {
                executiveAnalysis: (result.postEnrichmentAnalysis as any).executiveAnalysis || result.postEnrichmentAnalysis.overallAssessment,
                attackPaths: result.postEnrichmentAnalysis.attackPaths?.slice(0, 20),
                blindSpots: result.postEnrichmentAnalysis.blindSpots?.slice(0, 20),
                prioritizedRecommendations: result.postEnrichmentAnalysis.prioritizedRecommendations?.slice(0, 30),
                crossFindingCorrelations: result.postEnrichmentAnalysis.crossFindingCorrelations?.slice(0, 20),
                threatActorMapping: result.postEnrichmentAnalysis.threatActorMapping?.slice(0, 15),
                overallAssessment: result.postEnrichmentAnalysis.overallAssessment,
                confidenceStatement: result.postEnrichmentAnalysis.confidenceStatement,
                enrichmentSources: (result.postEnrichmentAnalysis as any).enrichmentSources,
              } : undefined,
              // Org discovery results
              orgDiscovery: result.orgDiscovery ? {
                seedDomain: result.orgDiscovery.seedDomain,
                orgName: result.orgDiscovery.orgName,
                orgEmail: result.orgDiscovery.orgEmail,
                totalCandidatesFound: result.orgDiscovery.totalCandidatesFound,
                verifiedDomains: result.orgDiscovery.verifiedDomains.slice(0, 50),
                unverifiedDomains: result.orgDiscovery.unverifiedDomains.slice(0, 30),
                discoveryStats: result.orgDiscovery.discoveryStats,
                durationMs: result.orgDiscovery.durationMs,
              } : undefined,
              complianceScan: result.complianceScan || undefined,
              containerExposure: result.containerExposure || undefined,
              // Preserve the previous snapshot for comparison
              previousSnapshot,
              refreshedAt: new Date().toISOString(),
            };

            if (wasFullEngagement) {
              // Full engagement: run threat actor matching + campaign design
              let threatActorMatches = null;
              try {
                const { matchThreatActors } = await import('../lib/threat-actor-matcher');
                const allTech: string[] = [];
                for (const a of result.assets) {
                  if (a.asset?.technologies) allTech.push(...a.asset.technologies);
                }
                threatActorMatches = await matchThreatActors({
                  sector: orgProfile?.sector || scan.sector,
                  clientType: orgProfile?.clientType || scan.clientType,
                  discoveredTechnologies: allTech,
                  discoveredAssets: result.assets.map(a => ({
                    hostname: a.asset?.hostname,
                    assetType: a.asset?.assetType,
                    technologies: a.asset?.technologies,
                  })),
                  riskScore: result.overallRiskScore,
                  criticalFunctions: orgProfile?.criticalFunctions || (scan.criticalFunctions as string[]) || [],
                });
              } catch (matchErr: any) {
                console.error('[DomainIntel] Refresh: Threat actor matching failed:', matchErr.message);
              }

              // Generate summaries
              const { generateCampaignRecommendations, generateSummaries } = await import('../domainIntel');
              const analyses = result.assets.map(a => ({
                asset: a.asset,
                carverScores: a.carverScores,
                shockScores: a.shockScores,
                missionImpactScore: a.missionImpactScore,
                suggestedTier: a.suggestedTier,
                hybridRiskScore: a.hybridRiskScore,
                riskBand: a.riskBand,
                cvssEstimate: a.cvssEstimate,
                contextIndicators: a.contextIndicators,
                postureFindings: a.postureFindings,
                testVectors: a.testVectors,
                confidence: a.confidence,
                assetCriticalityScore: a.assetCriticalityScore || 0,
                assetCriticalityBand: a.assetCriticalityBand || 'low',
                vulnRiskScore: a.vulnRiskScore || 0,
                vulnRiskBand: a.vulnRiskBand || 'low',
                impactScore: a.impactScore || 0,
                likelihoodScore: a.likelihoodScore || 0,
                missionFunction: a.missionFunction || 'public_facing_services',
                essentialService: a.essentialService || 'general_server',
                businessImpactLevel: a.businessImpactLevel || 'moderate',
                deviceType: a.deviceType || 'unknown',
                platformType: a.platformType || 'unknown',
                missionJustification: a.missionJustification || '',
              }));
              const kevEnrichment = result.kevEnrichment;
              const campaigns = await generateCampaignRecommendations(analyses, orgProfile, kevEnrichment);
              const summaries = await generateSummaries(analyses, campaigns, orgProfile);

              trimmedOutput.threatActorMatches = threatActorMatches;

              await db.updateDomainIntelScan(scanId, {
                status: 'completed',
                totalAssets: result.totalAssets,
                totalFindings: result.totalFindings,
                confirmedFindings: result.confirmedFindingsCount || 0,
                probableFindings: result.probableFindingsCount || 0,
                potentialFindings: result.potentialFindingsCount || 0,
                discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
                discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
                overallRiskScore: result.overallRiskScore,
                overallRiskBand: result.overallRiskBand,
                executiveSummary: summaries.executiveSummary,
                threatModelSummary: summaries.threatModelSummary,
                campaignRecommendations: campaigns,
                pipelineOutput: trimmedOutput,
              });
              console.log(`[DomainIntel] Refresh (full engagement) completed for scan ${scanId}: ${result.totalAssets} assets, risk=${result.overallRiskScore}`);
            } else {
              // Scan-only mode
              await db.updateDomainIntelScan(scanId, {
                status: 'scan_complete',
                totalAssets: result.totalAssets,
                totalFindings: result.totalFindings,
                confirmedFindings: result.confirmedFindingsCount || 0,
                probableFindings: result.probableFindingsCount || 0,
                potentialFindings: result.potentialFindingsCount || 0,
                discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
                discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
                overallRiskScore: result.overallRiskScore,
                overallRiskBand: result.overallRiskBand,
                executiveSummary: result.executiveSummary,
                threatModelSummary: result.threatModelSummary,
                campaignRecommendations: [],
                pipelineOutput: trimmedOutput,
              });
              console.log(`[DomainIntel] Refresh (scan-only) completed for scan ${scanId}: ${result.totalAssets} assets, risk=${result.overallRiskScore}`);
            }

            // Emit events
            try {
              const { emitReconComplete, emitSystemNotification } = await import('../lib/ws-event-hub');
              emitReconComplete({ scanId, domain: scan.primaryDomain, findings: result.totalFindings || 0, engagementId: scan.engagementId || undefined });
              emitSystemNotification({ title: 'Scan Refresh Complete', message: `Refreshed scan of ${scan.primaryDomain}: ${result.totalAssets} assets, ${result.totalFindings} findings, risk=${result.overallRiskScore}`, severity: 'info' });
            } catch {}

            // Auto-crawl + entity resolution (fire-and-forget, same as new scans)
            setImmediate(async () => {
              try {
                const { triggerAutoCrawl } = await import('../lib/auto-crawl');
                await triggerAutoCrawl(scanId, scan.primaryDomain);
              } catch (crawlErr: any) {
                console.error(`[AutoCrawl] Failed for refreshed scan ${scanId}:`, crawlErr.message);
              }
            });
          } catch (err: any) {
            console.error(`[DomainIntel] Refresh pipeline failed for scan ${scanId}:`, err.message, err.stack?.substring(0, 500));
            // Restore to previous completed status so user can retry
            await db.updateDomainIntelScan(scanId, {
              status: wasFullEngagement ? 'completed' : 'scan_complete',
              pipelineOutput: {
                ...(previousSnapshot || {}),
                refreshError: { message: err.message, failedAt: new Date().toISOString() },
              },
            }).catch(() => {});
          }
        });

        return { scanId: input.scanId, message: 'Scan refresh started — the pipeline will re-run in background' };
      }),

    // Delete a scan and its assets
    deleteScan: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .mutation(async ({ input }) => {
        // Delete discovered assets first
        try {
          await db.deleteDiscoveredAssetsByScan(input.scanId);
        } catch { /* ignore if no assets */ }
        // Delete the scan record
        await db.deleteDomainIntelScan(input.scanId);
        return { success: true };
      }),

    // Get scan recovery scheduler status
    recoveryStatus: protectedProcedure.query(async () => {
      const { getScanRecoveryStatus } = await import('../lib/scan-recovery');
      return getScanRecoveryStatus();
    }),

    // List all scans
    listScans: protectedProcedure.query(async () => {
      return db.getDomainIntelScans();
    }),

    // Get scan by ID with assets
    getScan: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.id);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        const assets = await db.getDiscoveredAssetsByScan(input.id);
        return { scan, assets };
      }),

    // Get assets for a scan
    getAssets: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        return db.getDiscoveredAssetsByScan(input.scanId);
      }),

    // Get delta comparison report for a scan (changes since previous scan of same domain)
    getDelta: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        const output = scan.pipelineOutput as any;
        if (!output?.deltaReport) {
          return {
            available: false as const,
            reason: 'No delta comparison available — this may be the first scan for this domain.',
          };
        }
        return {
          available: true as const,
          deltaReport: output.deltaReport,
          previousScanId: output.deltaReport.previousScanId || null,
        };
      }),

    // Exclude a discovered asset (mark as incorrect/irrelevant)
    excludeAsset: protectedProcedure
      .input(z.object({ assetId: z.number(), reason: z.string().min(1) }))
      .mutation(async ({ input }) => {
        await db.excludeDiscoveredAsset(input.assetId, input.reason);
        return { success: true };
      }),

    // Re-include a previously excluded asset
    includeAsset: protectedProcedure
      .input(z.object({ assetId: z.number() }))
      .mutation(async ({ input }) => {
        await db.includeDiscoveredAsset(input.assetId);
        return { success: true };
      }),

    // Bulk exclude assets
    bulkExcludeAssets: protectedProcedure
      .input(z.object({ assetIds: z.array(z.number()), reason: z.string().min(1) }))
      .mutation(async ({ input }) => {
        await db.bulkExcludeDiscoveredAssets(input.assetIds, input.reason);
        return { success: true, count: input.assetIds.length };
      }),

    // Bulk re-include assets
    bulkIncludeAssets: protectedProcedure
      .input(z.object({ assetIds: z.array(z.number()) }))
      .mutation(async ({ input }) => {
        await db.bulkIncludeDiscoveredAssets(input.assetIds);
        return { success: true, count: input.assetIds.length };
      }),

     // Get scans for an engagement
    byEngagement: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        return db.getDomainIntelScansByEngagement(input.engagementId);
      }),

    // Match threat actors for a completed scan
    matchThreatActors: protectedProcedure
      .input(z.object({ scanId: z.number(), useLLM: z.boolean().optional() }))
      .mutation(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        if (scan.status !== 'completed') throw new TRPCError({ code: 'BAD_REQUEST', message: 'Scan must be completed first' });

        const pipelineOutput = scan.pipelineOutput as any;
        if (!pipelineOutput) throw new TRPCError({ code: 'BAD_REQUEST', message: 'No pipeline output available' });

        const { matchThreatActors, matchThreatActorsWithLLM } = await import('../lib/threat-actor-matcher');
        const assets = pipelineOutput.assets || [];
        const allTech: string[] = [];
        for (const a of assets) {
          if (a.asset?.technologies) allTech.push(...a.asset.technologies);
        }

        const orgProfile = (scan.orgProfile as any) || {};
        const dbMatches = await matchThreatActors({
          sector: scan.sector || orgProfile.sector || 'technology',
          clientType: scan.clientType || orgProfile.clientType || 'enterprise',
          discoveredTechnologies: allTech,
          discoveredAssets: assets.map((a: any) => ({
            hostname: a.asset?.hostname || '',
            assetType: a.asset?.assetType || '',
            technologies: a.asset?.technologies || [],
          })),
          riskScore: scan.overallRiskScore || 0,
          criticalFunctions: (scan.criticalFunctions as string[]) || [],
        });

        let llmEnhanced = null;
        if (input.useLLM) {
          try {
            llmEnhanced = await matchThreatActorsWithLLM({
              orgProfile: {
                customerName: orgProfile.customerName || scan.primaryDomain,
                sector: scan.sector || orgProfile.sector || 'technology',
                clientType: scan.clientType || orgProfile.clientType || 'enterprise',
                criticalFunctions: (scan.criticalFunctions as string[]) || [],
              },
              discoveredAssets: assets.map((a: any) => ({
                hostname: a.asset?.hostname || '',
                assetType: a.asset?.assetType || '',
                technologies: a.asset?.technologies || [],
                riskBand: a.riskBand,
              })),
              overallRiskScore: scan.overallRiskScore || 0,
              executiveSummary: scan.executiveSummary || '',
              campaignRecommendations: (scan.campaignRecommendations as any[]) || [],
              topDatabaseMatches: dbMatches.topMatches,
            });
          } catch (err: any) {
            console.error('[DomainIntel] LLM threat actor matching failed:', err.message);
          }
        }

        // Store matches in pipeline output
        const updatedOutput = { ...pipelineOutput, threatActorMatches: dbMatches, llmThreatActorAnalysis: llmEnhanced };
        await db.updateDomainIntelScan(input.scanId, { pipelineOutput: updatedOutput });

        return { dbMatches, llmEnhanced };
      }),

    // ─── False Positive Management ─────────────────────────────────
    // Mark a finding as false positive
    markFalsePositive: protectedProcedure
      .input(z.object({
        scanId: z.number(),
        assetId: z.number(),
        findingIndex: z.number(),
        findingTitle: z.string(),
        findingType: z.string().optional(),
        findingSeverity: z.string().optional(),
        reason: z.string().min(1, 'A reason is required'),
      }))
      .mutation(async ({ input, ctx }) => {
        const { createHash } = await import('crypto');
        const findingHash = createHash('sha256')
          .update(`${input.findingTitle}|${input.assetId}|${input.findingType || ''}`)
          .digest('hex').slice(0, 64);

        await db.createFalsePositive({
          scanId: input.scanId,
          assetId: input.assetId,
          findingIndex: input.findingIndex,
          findingHash,
          findingTitle: input.findingTitle,
          findingType: input.findingType || null,
          findingSeverity: input.findingSeverity || null,
          reason: input.reason,
          markedBy: ctx.user.name || `user-${ctx.user.id}`,
        });
        return { success: true, findingHash };
      }),

    // Reinstate a finding (un-mark as false positive)
    reinstateFinding: protectedProcedure
      .input(z.object({
        fpId: z.number(),
        reason: z.string().min(1, 'A reason for reinstatement is required'),
      }))
      .mutation(async ({ input, ctx }) => {
        await db.reinstateFalsePositive(
          input.fpId,
          ctx.user.name || `user-${ctx.user.id}`,
          input.reason
        );
        return { success: true };
      }),

    // List false positives for a scan
    listFalsePositives: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        return db.getFalsePositivesByScan(input.scanId);
      }),

    // List all false positives (cross-scan, by hash)
    listAllFalsePositives: protectedProcedure
      .query(async () => {
        return db.getAllFalsePositives();
      }),

    // Compare two scans side-by-side
    compareScans: protectedProcedure
      .input(z.object({ scanIdA: z.number(), scanIdB: z.number() }))
      .query(async ({ input }) => {
        const [scanA, scanB] = await Promise.all([
          db.getDomainIntelScanById(input.scanIdA),
          db.getDomainIntelScanById(input.scanIdB),
        ]);
        if (!scanA || !scanB) throw new TRPCError({ code: 'NOT_FOUND', message: 'One or both scans not found' });

        const outA = scanA.pipelineOutput as any || {};
        const outB = scanB.pipelineOutput as any || {};

        const assetsA = (outA.assets || []).map((a: any) => a.asset || a);
        const assetsB = (outB.assets || []).map((a: any) => a.asset || a);

        const findingsA = (outA.assets || []).flatMap((a: any) => a.postureFindings || []);
        const findingsB = (outB.assets || []).flatMap((a: any) => a.postureFindings || []);

        const hostnamesA = new Set<string>(assetsA.map((a: any) => a.hostname as string));
        const hostnamesB = new Set<string>(assetsB.map((a: any) => a.hostname as string));

        const newAssets = assetsB.filter((a: any) => !hostnamesA.has(a.hostname));
        const removedAssets = assetsA.filter((a: any) => !hostnamesB.has(a.hostname));
        const commonHostnames = Array.from(hostnamesA).filter(h => hostnamesB.has(h));

        // Compare findings by CVE ID
        const cveSetA = new Set<string>(findingsA.flatMap((f: any) => (f.cveIds || []) as string[]));
        const cveSetB = new Set<string>(findingsB.flatMap((f: any) => (f.cveIds || []) as string[]));
        const newCves = Array.from(cveSetB).filter(c => !cveSetA.has(c));
        const resolvedCves = Array.from(cveSetA).filter(c => !cveSetB.has(c));

        // Compare risk scores per common asset
        const riskChanges = commonHostnames.map(hostname => {
          const assetAnalysisA = (outA.assets || []).find((a: any) => (a.asset || a).hostname === hostname);
          const assetAnalysisB = (outB.assets || []).find((a: any) => (a.asset || a).hostname === hostname);
          const riskA = assetAnalysisA?.hybridRiskScore ?? 0;
          const riskB = assetAnalysisB?.hybridRiskScore ?? 0;
          const bandA = assetAnalysisA?.riskBand ?? 'unknown';
          const bandB = assetAnalysisB?.riskBand ?? 'unknown';
          return { hostname, riskA, riskB, delta: riskB - riskA, bandA, bandB };
        }).filter(r => r.delta !== 0).sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta));

        // Compare corroboration tiers
        const tierCountA: Record<string, number> = { confirmed: 0, probable: 0, potential: 0 };
        const tierCountB: Record<string, number> = { confirmed: 0, probable: 0, potential: 0 };
        findingsA.forEach((f: any) => { if (f.corroborationTier) tierCountA[f.corroborationTier] = (tierCountA[f.corroborationTier] || 0) + 1; });
        findingsB.forEach((f: any) => { if (f.corroborationTier) tierCountB[f.corroborationTier] = (tierCountB[f.corroborationTier] || 0) + 1; });

        // New findings in scan B not in scan A (by finding ID)
        const findingIdsA = new Set(findingsA.map((f: any) => f.id));
        const newFindings = findingsB.filter((f: any) => !findingIdsA.has(f.id));
        const findingIdsB = new Set(findingsB.map((f: any) => f.id));
        const resolvedFindings = findingsA.filter((f: any) => !findingIdsB.has(f.id));

        return {
          scanA: {
            id: scanA.id,
            primaryDomain: scanA.primaryDomain,
            createdAt: scanA.createdAt,
            overallRiskScore: outA.overallRiskScore ?? 0,
            overallRiskBand: outA.overallRiskBand ?? 'unknown',
            totalAssets: assetsA.length,
            totalFindings: findingsA.length,
          },
          scanB: {
            id: scanB.id,
            primaryDomain: scanB.primaryDomain,
            createdAt: scanB.createdAt,
            overallRiskScore: outB.overallRiskScore ?? 0,
            overallRiskBand: outB.overallRiskBand ?? 'unknown',
            totalAssets: assetsB.length,
            totalFindings: findingsB.length,
          },
          riskDelta: (outB.overallRiskScore ?? 0) - (outA.overallRiskScore ?? 0),
          newAssets: newAssets.map((a: any) => ({ hostname: a.hostname, assetType: a.assetType, discoveryMethod: a.discoveryMethod })),
          removedAssets: removedAssets.map((a: any) => ({ hostname: a.hostname, assetType: a.assetType })),
          riskChanges,
          newCves,
          resolvedCves,
          newFindings: newFindings.slice(0, 50).map((f: any) => ({
            id: f.id, title: f.title, severity: f.severity, category: f.category,
            cveIds: f.cveIds, corroborationTier: f.corroborationTier, assetHostname: f.assetHostname,
          })),
          resolvedFindings: resolvedFindings.slice(0, 50).map((f: any) => ({
            id: f.id, title: f.title, severity: f.severity, category: f.category,
            cveIds: f.cveIds, corroborationTier: f.corroborationTier, assetHostname: f.assetHostname,
          })),
          tierComparison: { scanA: tierCountA, scanB: tierCountB },
        };
      }),

    // Deploy matched exploits as emulation abilities
    deployExploits: protectedProcedure
      .input(z.object({
        scanId: z.number(),
        cveIds: z.array(z.string()).optional(), // Optional: deploy specific CVEs only
      }))
      .mutation(async ({ input }) => {
        const { deployExploitsToCaldera, createExploitAdversary, matchExploitsToFindings } = await import('../lib/exploit-matcher');
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan || !scan.pipelineOutput) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found or no results' });

        const results = scan.pipelineOutput as any;
        const exploitData = results.exploitMatches;
        if (!exploitData || !exploitData.matches || exploitData.matches.length === 0) {
          // Try to match on the fly from posture findings
          const allFindings = (results.assets || []).flatMap((a: any) => (a.postureFindings || []).map((f: any) => ({
            title: f.title,
            cveIds: f.cveIds,
            corroborationTier: f.corroborationTier,
            severity: f.severity,
            description: f.evidenceDetail,
          })));
          const findingsWithCves = allFindings.filter((f: any) => f.cveIds && f.cveIds.length > 0);
          if (findingsWithCves.length === 0) {
            return { success: false, error: 'No CVE-backed findings to match', deployed: [], failed: [] };
          }
          const freshMatches = await matchExploitsToFindings(findingsWithCves);
          if (freshMatches.matches.length === 0) {
            return { success: false, error: 'No exploits found for confirmed CVEs', deployed: [], failed: [] };
          }

          let matchesToDeploy = freshMatches.matches;
          if (input.cveIds && input.cveIds.length > 0) {
            matchesToDeploy = matchesToDeploy.filter(m => input.cveIds!.includes(m.cveId));
          }

          const deployResult = await deployExploitsToCaldera(matchesToDeploy);
          return { success: true, ...deployResult };
        }

        let matchesToDeploy = exploitData.matches;
        if (input.cveIds && input.cveIds.length > 0) {
          matchesToDeploy = matchesToDeploy.filter((m: any) => input.cveIds!.includes(m.cveId));
        }

        const deployResult = await deployExploitsToCaldera(matchesToDeploy);
        return { success: true, ...deployResult };
      }),

    // Create a Caldera adversary from matched exploits
    createExploitAdversary: protectedProcedure
      .input(z.object({
        scanId: z.number(),
      }))
      .mutation(async ({ input }) => {
        const { createExploitAdversary, matchExploitsToFindings } = await import('../lib/exploit-matcher');
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan || !scan.pipelineOutput) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found or no results' });

        const results = scan.pipelineOutput as any;
        let matches = results.exploitMatches?.matches;

        if (!matches || matches.length === 0) {
          // Try to match on the fly
          const allFindings = (results.assets || []).flatMap((a: any) => (a.postureFindings || []).map((f: any) => ({
            title: f.title,
            cveIds: f.cveIds,
            corroborationTier: f.corroborationTier,
            severity: f.severity,
            description: f.evidenceDetail,
          })));
          const findingsWithCves = allFindings.filter((f: any) => f.cveIds && f.cveIds.length > 0);
          const freshMatches = await matchExploitsToFindings(findingsWithCves);
          matches = freshMatches.matches;
        }

        if (!matches || matches.length === 0) {
          return { success: false, error: 'No exploit matches available' };
        }

        const domain = results.orgProfile?.primaryDomain || scan.primaryDomain || 'unknown';
        return createExploitAdversary(domain, matches);
      }),

    // ─── Auto-BIA Report Generator ─────────────────────────────────
    generateBiaReport: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .mutation(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        const assets = await db.getDiscoveredAssetsByScan(input.scanId);
        if (!assets.length) throw new TRPCError({ code: 'BAD_REQUEST', message: 'No assets found for this scan' });

        const { generateBiaReport } = await import('../lib/bia-report-generator');
        const orgProfile = (scan.orgProfile as any) || {};

        const biaAssets = assets
          .filter(a => !a.excluded)
          .map(a => {
            let analysis: any = {};
            try { analysis = typeof a.llmClassification === 'string' ? JSON.parse(a.llmClassification) : (a.llmClassification || {}); } catch {}
            return {
              id: a.id,
              hostname: a.hostname,
              assetType: a.assetType || 'unknown',
              missionFunction: a.missionFunction || analysis.missionFunction || 'operational_continuity',
              essentialService: a.essentialService || analysis.essentialService || '',
              businessImpactLevel: a.businessImpactLevel || analysis.businessImpactLevel || 'operational',
              carverScores: (a.carverScores as any) || analysis.carverScores || { criticality: 5, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 },
              shockScores: (a.shockScores as any) || analysis.shockScores || { scope: 5, handling: 5, operationalImpact: 5, cascadingEffects: 5, knowledge: 5 },
              hybridRiskScore: a.hybridRiskScore || 0,
              riskBand: a.riskBand || 'low',
              impactScore: a.impactScore || 0,
              likelihoodScore: a.likelihoodScore || 0,
              assetCriticalityScore: a.assetCriticalityScore || 0,
              assetCriticalityBand: a.assetCriticalityBand || 'low',
              vulnRiskScore: a.vulnRiskScore || 0,
              vulnRiskBand: a.vulnRiskBand || 'low',
              missionImpactScore: a.missionImpactScore || 0,
              fips199Category: (a.fips199Category as any) || analysis.fips199Category || undefined,
              criticalityTier: a.criticalityTier || analysis.criticalityTier || undefined,
              missionDependencies: (a.missionDependencies as any) || analysis.missionDependencies || undefined,
              postureFindings: (a.postureFindings as any) || analysis.postureFindings || [],
              deviceType: a.deviceType || analysis.deviceType || undefined,
              platformType: a.platformType || analysis.platformType || undefined,
            };
          });

        const report = generateBiaReport(
          {
            customerName: orgProfile.customerName || scan.primaryDomain,
            primaryDomain: scan.primaryDomain,
            sector: scan.sector || orgProfile.sector || 'Unknown',
            clientType: scan.clientType || 'enterprise',
            criticalFunctions: (scan.criticalFunctions as string[]) || [],
            complianceFlags: (scan.complianceFlags as string[]) || [],
          },
          biaAssets,
          scan.overallRiskScore || 0,
          scan.overallRiskBand || 'low',
        );

        return report;
      }),

    // ─── Recursive Discovery (SpiderFoot-style entity spidering) ─────
    startRecursiveDiscovery: protectedProcedure
      .input(z.object({
        scanId: z.number(),
        maxDepth: z.number().min(1).max(5).default(3),
        maxEntities: z.number().min(10).max(500).default(200),
        maxApiCalls: z.number().min(10).max(1000).default(500),
        scopeRestriction: z.enum(['strict', 'related', 'unrestricted']).default('related'),
        entityTypes: z.array(z.enum(['domain', 'ip', 'email', 'organization', 'url', 'certificate'])).default(['domain', 'ip', 'email']),
      }))
      .mutation(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        // Get the scan's observations to seed recursive discovery
        const scanData = scan.pipelineOutput as any;
        const initialObservations = scanData?.passiveRecon?.allObservations || [];

        if (initialObservations.length === 0) {
          throw new TRPCError({ code: 'BAD_REQUEST', message: 'No observations found in scan — run a domain intel scan first' });
        }

        const { runRecursiveDiscovery } = await import('../lib/passive/recursive-discovery');
        // Get API keys from environment
        const apiKeys: Record<string, string> = {};
        if (process.env.SHODAN_API_KEY) apiKeys.shodan = process.env.SHODAN_API_KEY;
        if (process.env.CENSYS_API_ID) apiKeys.censys_id = process.env.CENSYS_API_ID;
        if (process.env.CENSYS_API_SECRET) apiKeys.censys_secret = process.env.CENSYS_API_SECRET;
        if (process.env.URLSCAN_API_KEY) apiKeys.urlscan = process.env.URLSCAN_API_KEY;
        if (process.env.SECURITYTRAILS_API_KEY) apiKeys.securitytrails = process.env.SECURITYTRAILS_API_KEY;
        if (process.env.DEHASHED_API_KEY) apiKeys.dehashed = process.env.DEHASHED_API_KEY;
        if (process.env.ABUSEIPDB_API_KEY) apiKeys.abuseipdb = process.env.ABUSEIPDB_API_KEY;
        if (process.env.BINARYEDGE_API_KEY) apiKeys.binaryedge = process.env.BINARYEDGE_API_KEY;
        if (process.env.GREYNOISE_API_KEY) apiKeys.greynoise = process.env.GREYNOISE_API_KEY;
        if (process.env.GITHUB_PAT || process.env.GITHUB_CLASSIC_TOKEN) apiKeys.github = process.env.GITHUB_PAT || process.env.GITHUB_CLASSIC_TOKEN || '';
        if (process.env.VIRUSTOTAL_API_KEY) apiKeys.virustotal = process.env.VIRUSTOTAL_API_KEY;
        if (process.env.HIBP_API_KEY) apiKeys.hibp = process.env.HIBP_API_KEY;
        if (process.env.WHOISXML_API_KEY) apiKeys.whoisxml = process.env.WHOISXML_API_KEY;
        if (process.env.LEAKIX_API_KEY) apiKeys.leakix = process.env.LEAKIX_API_KEY;
        if (process.env.FULLHUNT_API_KEY) apiKeys.fullhunt = process.env.FULLHUNT_API_KEY;
        if (process.env.NETLAS_API_KEY) apiKeys.netlas = process.env.NETLAS_API_KEY;
        if (process.env.HUNTER_API_KEY) apiKeys.hunter = process.env.HUNTER_API_KEY;
        if (process.env.PASSIVETOTAL_API_KEY) apiKeys.passivetotal = process.env.PASSIVETOTAL_API_KEY;
        if (process.env.INTELX_API_KEY) apiKeys.intelx = process.env.INTELX_API_KEY;
        if (process.env.HUDSON_ROCK_API_KEY) apiKeys.hudson_rock = process.env.HUDSON_ROCK_API_KEY;
        if (process.env.LEAKCHECK_API_KEY) apiKeys.leakcheck = process.env.LEAKCHECK_API_KEY;

        // Import ALL_CONNECTORS from passive index
        const { ALL_CONNECTORS } = await import('../lib/passive/index');

        const result = await runRecursiveDiscovery(
          scan.primaryDomain,
          initialObservations,
          ALL_CONNECTORS,
          {
            maxDepth: input.maxDepth,
            maxEntities: input.maxEntities,
            maxApiCalls: input.maxApiCalls,
            scopeRestriction: input.scopeRestriction,
            entityTypes: input.entityTypes,
            apiKeys,
          }
        );

        // Store recursive discovery results in the scan record
        await db.updateDomainIntelScan(input.scanId, {
          pipelineOutput: {
            ...((scan.pipelineOutput as any) || {}),
            recursiveDiscovery: {
              stats: result.stats,
              entityCount: result.entities.length,
              graphEdgeCount: result.entityGraph.length,
              completedAt: new Date().toISOString(),
            },
          },
        });

        return {
          stats: result.stats,
          entities: result.entities.slice(0, 100), // Limit response size
          entityGraph: result.entityGraph.slice(0, 200),
          totalEntities: result.entities.length,
          totalEdges: result.entityGraph.length,
        };
      }),

    getRecursiveDiscoveryStatus: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        const pipelineOutput = scan.pipelineOutput as any;
        const recursiveDiscovery = pipelineOutput?.recursiveDiscovery || null;

        return {
          hasResults: !!recursiveDiscovery,
          stats: recursiveDiscovery?.stats || null,
          entityCount: recursiveDiscovery?.entityCount || 0,
          graphEdgeCount: recursiveDiscovery?.graphEdgeCount || 0,
          completedAt: recursiveDiscovery?.completedAt || null,
        };
      }),

    getConnectorCatalog: publicProcedure
      .query(async () => {
        // Return the full list of available connectors with metadata
        const connectorInfo = [
          { name: 'shodan-internetdb', description: 'Shodan InternetDB — fast CVE/port lookup (free)', requiresKey: false, category: 'infrastructure', free: true },
          { name: 'crtsh', description: 'Certificate Transparency logs — subdomain discovery', requiresKey: false, category: 'certificates', free: true },
          { name: 'shodan', description: 'Shodan — internet-wide device/service scanning', requiresKey: true, category: 'infrastructure', free: false },
          { name: 'wayback', description: 'Wayback Machine — historical URL archive', requiresKey: false, category: 'historical', free: true },
          { name: 'censys', description: 'Censys — host and certificate search', requiresKey: true, category: 'infrastructure', free: false },
          { name: 'urlscan', description: 'URLScan.io — URL analysis and screenshots', requiresKey: true, category: 'web', free: false },
          { name: 'rdap', description: 'RDAP — domain registration data', requiresKey: false, category: 'whois', free: true },
          { name: 'ripestat', description: 'RIPE Stat — IP/ASN intelligence', requiresKey: false, category: 'infrastructure', free: true },
          { name: 'securitytrails', description: 'SecurityTrails — DNS history and subdomain enum', requiresKey: true, category: 'dns', free: false },
          { name: 'dehashed', description: 'DeHashed — credential breach search', requiresKey: true, category: 'breaches', free: false },
          { name: 'binaryedge', description: 'BinaryEdge — internet scanning and threat intel', requiresKey: true, category: 'infrastructure', free: false },
          { name: 'greynoise', description: 'GreyNoise — IP noise/threat classification', requiresKey: true, category: 'threat-intel', free: false },
          { name: 'email-security', description: 'Email security — DMARC/SPF/DKIM analysis', requiresKey: false, category: 'email', free: true },
          { name: 'http-security', description: 'HTTP security — headers and WAF detection', requiresKey: false, category: 'web', free: true },
          { name: 'cloud-assets', description: 'Cloud assets — S3/Azure/GCP bucket enumeration', requiresKey: false, category: 'cloud', free: true },
          { name: 'dns-deep', description: 'Deep DNS — comprehensive record analysis', requiresKey: false, category: 'dns', free: true },
          { name: 'github-leaks', description: 'GitHub — code leak and secret scanning', requiresKey: false, category: 'code', free: true },
          { name: 'virustotal', description: 'VirusTotal — malware/URL/domain reputation', requiresKey: true, category: 'threat-intel', free: false },
          { name: 'hibp', description: 'Have I Been Pwned — breach exposure lookup', requiresKey: true, category: 'breaches', free: false },
          { name: 'whoisxml', description: 'WhoisXML — WHOIS records and subdomain enum', requiresKey: true, category: 'whois', free: false },
          { name: 'leakix', description: 'LeakIX — exposed services and data leaks', requiresKey: true, category: 'leaks', free: false },
          { name: 'fullhunt', description: 'FullHunt — attack surface discovery', requiresKey: true, category: 'infrastructure', free: false },
          { name: 'netlas', description: 'Netlas.io — internet-wide host scanning', requiresKey: true, category: 'infrastructure', free: false },
          { name: 'hunter', description: 'Hunter.io — email discovery and verification', requiresKey: true, category: 'email', free: false },
          { name: 'social-media', description: 'Social media — GitHub org/user presence', requiresKey: false, category: 'social', free: true },
          { name: 'abuseipdb', description: 'AbuseIPDB — IP abuse reputation scoring', requiresKey: true, category: 'threat-intel', free: false },
          { name: 'passivetotal', description: 'PassiveTotal — passive DNS and SSL history', requiresKey: true, category: 'dns', free: false },
          { name: 'intelx', description: 'IntelX — darkweb/paste site search for domain mentions', requiresKey: true, category: 'darkweb', free: false },
          { name: 'hudson-rock', description: 'Hudson Rock — stealer log credential exposure', requiresKey: true, category: 'darkweb', free: false },
          { name: 'leakcheck', description: 'LeakCheck — credential leak database search', requiresKey: true, category: 'breaches', free: false },
          { name: 'company-intel', description: 'Company Intel — LLM-powered firmographic data extraction', requiresKey: false, category: 'business-intel', free: true },
          { name: 'threatminer', description: 'ThreatMiner — domain/IP threat intel and APT reports', requiresKey: false, category: 'threat-intel', free: true },
          { name: 'ip-api', description: 'IP-API — IP geolocation, ASN, and org info', requiresKey: false, category: 'infrastructure', free: true },
          { name: 'bgpview', description: 'BGPView — ASN lookup, network peers, IP prefixes', requiresKey: false, category: 'infrastructure', free: true },
          { name: 'ransomware-live', description: 'Ransomware.live — ransomware victim tracking', requiresKey: false, category: 'darkweb', free: true },
          { name: 'threatfox', description: 'ThreatFox/abuse.ch — IOC database with domain correlation', requiresKey: false, category: 'threat-intel', free: true },
          { name: 'builtwith', description: 'BuiltWith — technology stack detection (CMS, frameworks)', requiresKey: false, category: 'web', free: true },
          { name: 'circl-pdns', description: 'CIRCL PassiveDNS — historical DNS resolution data', requiresKey: false, category: 'dns', free: true },
          { name: 'commoncrawl', description: 'CommonCrawl — historical web data for company context', requiresKey: false, category: 'historical', free: true },
          { name: 'reverse-whois', description: 'Reverse WHOIS — discover all domains owned by target org', requiresKey: false, category: 'whois', free: true },
          { name: 'typosquat', description: 'Typosquat — detect lookalike/phishing domains', requiresKey: false, category: 'phishing', free: true },
        ];

        return {
          connectors: connectorInfo,
          totalCount: connectorInfo.length,
          freeCount: connectorInfo.filter(c => c.free).length,
          paidCount: connectorInfo.filter(c => !c.free).length,
          categories: Array.from(new Set(connectorInfo.map(c => c.category))),
        };
      }),

    // ─── Subdomain Change Detection ────────────────────────────────────
    detectChanges: protectedProcedure
      .input(z.object({ currentScanId: z.number(), previousScanId: z.number().optional() }))
      .query(async ({ input }) => {
        const currentScan = await db.getDomainIntelScanById(input.currentScanId);
        if (!currentScan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Current scan not found' });
        if (currentScan.status !== 'completed') throw new TRPCError({ code: 'BAD_REQUEST', message: 'Current scan must be completed' });

        // Find previous scan for the same domain
        let previousScanId = input.previousScanId;
        if (!previousScanId) {
          const allScans = await db.getDomainIntelScans();
          const sameDomainScans = allScans
            .filter((s: any) => s.primaryDomain === currentScan.primaryDomain && s.id !== currentScan.id && s.status === 'completed')
            .sort((a: any, b: any) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
          if (sameDomainScans.length === 0) {
            return { hasHistory: false, message: 'No previous scan found for this domain. Run another scan to enable change detection.' };
          }
          previousScanId = sameDomainScans[0].id;
        }

        const previousScan = await db.getDomainIntelScanById(previousScanId);
        if (!previousScan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Previous scan not found' });

        const currentAssets = await db.getDiscoveredAssetsByScan(input.currentScanId);
        const previousAssets = await db.getDiscoveredAssetsByScan(previousScanId);
        const currentPipeline = currentScan.pipelineOutput as any;
        const previousPipeline = previousScan.pipelineOutput as any;

        const { detectSubdomainChanges } = await import('../lib/domain-intel-advanced');
        const result = detectSubdomainChanges(
          input.currentScanId,
          previousScanId,
          currentScan.primaryDomain,
          currentAssets,
          previousAssets,
          currentPipeline,
          previousPipeline,
          new Date(currentScan.createdAt).getTime(),
          new Date(previousScan.createdAt).getTime()
        );

        return { hasHistory: true, ...result };
      }),

    // ─── Technology Vulnerability CVE Cross-Reference ──────────────────
    techVulnerabilities: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        if (scan.status !== 'completed') throw new TRPCError({ code: 'BAD_REQUEST', message: 'Scan must be completed' });

        const assets = await db.getDiscoveredAssetsByScan(input.scanId);
        const pipelineOutput = scan.pipelineOutput as any;

        const { crossReferenceTechVulnerabilities } = await import('../lib/domain-intel-advanced');
        return crossReferenceTechVulnerabilities(assets, pipelineOutput);
      }),

    // ─── Subdomain Takeover Detection ──────────────────────────────────
    takeoverDetection: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        if (scan.status !== 'completed') throw new TRPCError({ code: 'BAD_REQUEST', message: 'Scan must be completed' });

        const assets = await db.getDiscoveredAssetsByScan(input.scanId);
        const pipelineOutput = scan.pipelineOutput as any;

        const { detectSubdomainTakeover } = await import('../lib/domain-intel-advanced');
        return detectSubdomainTakeover(assets, pipelineOutput);
      }),

    // ─── CVE-to-Threat-Actor Enrichment ────────────────────────────────
    cveActorEnrichment: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        const assets = await db.getDiscoveredAssetsByScan(input.scanId);
        const pipelineOutput = scan.pipelineOutput as any;

        const { crossReferenceTechVulnerabilities, enrichCvesWithThreatActors } = await import('../lib/domain-intel-advanced');
        const techVulnResult = crossReferenceTechVulnerabilities(assets, pipelineOutput);
        return enrichCvesWithThreatActors(techVulnResult);
      }),

    // ─── Active Takeover PoC Validation ────────────────────────────────
    validateTakeover: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .mutation(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        const assets = await db.getDiscoveredAssetsByScan(input.scanId);
        const pipelineOutput = scan.pipelineOutput as any;

        const { detectSubdomainTakeover, validateTakeoverCandidates } = await import('../lib/domain-intel-advanced');
        const takeoverResult = await detectSubdomainTakeover(assets, pipelineOutput);

        if (!takeoverResult.candidates || takeoverResult.candidates.length === 0) {
          return {
            totalValidated: 0,
            confirmedCount: 0,
            likelyCount: 0,
            possibleCount: 0,
            unlikelyCount: 0,
            errorCount: 0,
            results: [],
            summary: 'No takeover candidates found to validate.',
          };
        }

        return validateTakeoverCandidates(takeoverResult.candidates);
      }),

    // ─── Quick Scan (domain-only, auto-enrichment) ─────────────────
    quickScan: protectedProcedure
      .input(z.object({
        domain: z.string().min(1),
        scanMode: z.enum(['strict_passive', 'standard', 'active']).optional(),
        scanOnly: z.boolean().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const cleanDomain = input.domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();

        // Create scan record with placeholder org profile — enrichment runs in background
        const scanId = await db.createDomainIntelScan({
          primaryDomain: cleanDomain,
          additionalDomains: [],
          clientType: 'enterprise',
          sector: 'Technology',
          orgProfile: {
            customerName: cleanDomain,
            primaryDomain: cleanDomain,
            sector: 'Technology',
            clientType: 'enterprise',
            criticalFunctions: [],
            complianceFlags: [],
          },
          criticalFunctions: [],
          complianceFlags: [],
          notes: 'Quick scan — org profile auto-enriched from domain',
          status: 'pending',
          createdBy: ctx.user.id,
        });

        // Run enrichment + pipeline in background
        const scanMode = input.scanMode || 'standard';
        const scanOnly = input.scanOnly !== false;
        setImmediate(async () => {
          try {
            console.log(`[DomainIntel] Quick scan started for ${cleanDomain} (scan ${scanId})`);

            // Phase 1: Auto-enrich org profile from domain
            await db.updateDomainIntelScan(scanId, { status: 'passive_recon' }).catch(() => {});
            const { runEnrichmentPipeline, mergeLLMOrgData, buildBIAFromLLMData } = await import('../lib/org-enrichment');
            const { invokeLLM } = await import('../_core/llm');
            const { ENV } = await import('../_core/env');

            const enrichResult = await runEnrichmentPipeline(cleanDomain, {
              shodanApiKey: ENV.SHODAN_API_KEY || undefined,
              securityTrailsApiKey: ENV.SECURITYTRAILS_API_KEY || undefined,
              censysApiId: ENV.CENSYS_API_ID || undefined,
              censysApiSecret: ENV.CENSYS_API_SECRET || undefined,
            });

            // Use LLM to extract structured org profile from scraped data
            let orgProfile = enrichResult.orgProfile;
            let biaProfile = null;
            try {
              const orgLLMResponse = await invokeLLM({
                _caller: "domain-intel-core",
                messages: [
                  { role: 'system', content: 'You are an expert OSINT analyst. Extract structured organization information from the provided website data. Return valid JSON only.' },
                  { role: 'user', content: enrichResult.llmOrgPrompt },
                ],
                response_format: {
                  type: 'json_schema',
                  json_schema: {
                    name: 'org_profile',
                    strict: true,
                    schema: {
                      type: 'object',
                      properties: {
                        companyName: { type: 'string', description: 'Official company name' },
                        industry: { type: 'string', description: 'Primary industry' },
                        sector: { type: 'string', description: 'Business sector (Technology, Financial Services, Healthcare, Government, Education, Manufacturing, Retail, Energy, Telecommunications, Legal, Media & Entertainment, Non-Profit, Defense, Transportation, Other)' },
                        description: { type: 'string', description: 'Brief company description (2-3 sentences)' },
                        clientType: { type: 'string', description: 'One of: msp, enterprise, saas, paas, iaas, mixed_hosting, other' },
                        employeeRange: { type: 'string', description: 'Estimated employee count range' },
                        products: { type: 'array', items: { type: 'object', properties: { name: { type: 'string' }, description: { type: 'string' }, category: { type: 'string' }, criticality: { type: 'string' } }, required: ['name', 'description', 'category', 'criticality'], additionalProperties: false } },
                        services: { type: 'array', items: { type: 'object', properties: { name: { type: 'string' }, description: { type: 'string' }, category: { type: 'string' }, criticality: { type: 'string' } }, required: ['name', 'description', 'category', 'criticality'], additionalProperties: false } },
                        criticalFunctions: { type: 'array', items: { type: 'string' }, description: 'Critical business functions: identity, email, payments, customer_data, intellectual_property, supply_chain, communications, operations, compliance, hr, development, infrastructure, sales, marketing, support' },
                        complianceFlags: { type: 'array', items: { type: 'string' }, description: 'Likely compliance requirements: SOC2, HIPAA, PCI-DSS, GDPR, NIST, ISO27001, FedRAMP, CMMC, SOX, CCPA, FERPA, ITAR' },
                        regulatoryNotes: { type: 'string', description: 'Notes on regulatory environment' },
                      },
                      required: ['companyName', 'industry', 'sector', 'description', 'clientType', 'employeeRange', 'products', 'services', 'criticalFunctions', 'complianceFlags', 'regulatoryNotes'],
                      additionalProperties: false,
                    },
                  },
                },
              });

              const orgContent = orgLLMResponse.choices[0].message.content;
              const llmOrgData = JSON.parse(typeof orgContent === 'string' ? orgContent : '{}');
              orgProfile = mergeLLMOrgData(orgProfile, llmOrgData);

              // Build BIA profile
              const biaLLMResponse = await invokeLLM({
                _caller: "domain-intel-core",
                messages: [
                  { role: 'system', content: 'You are a business impact analysis expert. Analyze the organization and produce a structured BIA assessment. Return valid JSON only.' },
                  { role: 'user', content: enrichResult.llmBiaPrompt },
                ],
                response_format: {
                  type: 'json_schema',
                  json_schema: {
                    name: 'bia_profile',
                    strict: true,
                    schema: {
                      type: 'object',
                      properties: {
                        overallCriticality: { type: 'string', description: 'critical, high, medium, or low' },
                        hybridScore: { type: 'number', description: 'Overall hybrid BIA score 0-100' },
                        missionCriticalSystems: { type: 'array', items: { type: 'object', properties: { name: { type: 'string' }, description: { type: 'string' }, type: { type: 'string' }, criticality: { type: 'string' }, exposureLevel: { type: 'string' } }, required: ['name', 'description', 'type', 'criticality', 'exposureLevel'], additionalProperties: false } },
                        recommendations: { type: 'array', items: { type: 'string' } },
                        carverScores: { type: 'object', properties: { criticality: { type: 'number' }, accessibility: { type: 'number' }, recuperability: { type: 'number' }, vulnerability: { type: 'number' }, effect: { type: 'number' }, recognizability: { type: 'number' } }, required: ['criticality', 'accessibility', 'recuperability', 'vulnerability', 'effect', 'recognizability'], additionalProperties: false },
                      },
                      required: ['overallCriticality', 'hybridScore', 'missionCriticalSystems', 'recommendations', 'carverScores'],
                      additionalProperties: false,
                    },
                  },
                },
              });

              const biaContent = biaLLMResponse.choices[0].message.content;
              const llmBiaData = JSON.parse(typeof biaContent === 'string' ? biaContent : '{}');
              biaProfile = buildBIAFromLLMData(cleanDomain, orgProfile, llmBiaData);

              console.log(`[DomainIntel] Quick scan enrichment complete for ${cleanDomain}: ${orgProfile.companyName}, sector=${orgProfile.sector}`);
            } catch (llmErr: any) {
              console.error(`[DomainIntel] LLM enrichment failed for ${cleanDomain}:`, llmErr.message);
            }

            // Derive scan parameters from enriched profile
            const derivedSector = orgProfile.sector || 'Technology';
            const derivedClientType = (orgProfile as any).clientType || 'enterprise';
            const derivedCriticalFunctions = (orgProfile as any).criticalFunctions || [];
            const derivedComplianceFlags = (orgProfile as any).complianceFlags || [];

            // Update scan record with enriched org profile
            await db.updateDomainIntelScan(scanId, {
              sector: derivedSector,
              clientType: derivedClientType,
              criticalFunctions: derivedCriticalFunctions,
              complianceFlags: derivedComplianceFlags,
              orgProfile: {
                customerName: orgProfile.companyName || cleanDomain,
                primaryDomain: cleanDomain,
                sector: derivedSector,
                clientType: derivedClientType,
                criticalFunctions: derivedCriticalFunctions,
                complianceFlags: derivedComplianceFlags,
                enrichedProfile: orgProfile,
                biaProfile,
              },
              status: 'discovering',
            });

            // Phase 2: Run the standard domain intel pipeline
            const { runDomainIntelPipeline } = await import('../domainIntel');
            const result = await runDomainIntelPipeline(
              {
                customerName: orgProfile.companyName || cleanDomain,
                primaryDomain: cleanDomain,
                additionalDomains: [],
                sector: derivedSector,
                clientType: derivedClientType,
                criticalFunctions: derivedCriticalFunctions,
                complianceFlags: derivedComplianceFlags,
                notes: `Auto-enriched: ${orgProfile.description || ''}`,
              },
              async (stage) => {
                await db.updateDomainIntelScan(scanId, { status: stage }).catch(() => {});
                console.log(`[DomainIntel] Quick scan ${scanId} stage: ${stage}`);
              },
              { scanMode, skipEngagement: scanOnly }
            );

            // Store results using same pattern as startScan
            const assetRecords = result.assets.map(a => ({
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
                ? Object.entries(a.asset.technologyVersions).map(([name, version]) => ({
                    name,
                    version: version || '',
                    category: 'detected',
                    confidence: version ? 0.9 : 0.7,
                  }))
                : (a.asset.technologies || []).map((t: string) => ({ name: t, version: '', category: 'inferred', confidence: 0.5 })),
              assetClasses: a.asset.assetClasses,
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
              recommendedCalderaAbilities: a.testVectors.filter((v: any) => v.suggestedEmulation?.calderaAbilityHint).map((v: any) => v.suggestedEmulation),
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
            if (assetRecords.length > 0) {
              const BATCH_SIZE = 5;
              for (let i = 0; i < assetRecords.length; i += BATCH_SIZE) {
                const batch = assetRecords.slice(i, i + BATCH_SIZE);
                try {
                  await db.bulkCreateDiscoveredAssets(batch);
                } catch (batchErr: any) {
                  for (const record of batch) {
                    try { await db.createDiscoveredAsset(record); } catch {}
                  }
                }
              }
            }

            // Trim pipeline output for storage
            const trimmedOutput = {
              totalAssets: result.totalAssets,
              totalFindings: result.totalFindings,
              confirmedFindings: result.confirmedFindingsCount,
              probableFindings: result.probableFindingsCount,
              potentialFindings: result.potentialFindingsCount,
              discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
              discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
              // Full discovery coverage object for the Coverage tab
              discoveryCoverage: result.discoveryCoverage ? {
                coverageScore: result.discoveryCoverage.coverageScore,
                coverageBand: result.discoveryCoverage.coverageBand,
                priorities: result.discoveryCoverage.priorities,
                assessment: result.discoveryCoverage.assessment,
                structuralGaps: result.discoveryCoverage.structuralGaps,
                actionableGaps: result.discoveryCoverage.actionableGaps,
              } : undefined,
              // Email security analysis for the Email Security tab
              emailSecurityReport: (result as any).emailSecurityReport || (result as any).emailSecurity || undefined,
              enrichedOrgProfile: orgProfile,
              biaProfile,
              enrichmentSources: enrichResult.orgProfile.enrichmentSources,
              // Org discovery results
              orgDiscovery: result.orgDiscovery ? {
                seedDomain: result.orgDiscovery.seedDomain,
                orgName: result.orgDiscovery.orgName,
                orgEmail: result.orgDiscovery.orgEmail,
                totalCandidatesFound: result.orgDiscovery.totalCandidatesFound,
                verifiedDomains: result.orgDiscovery.verifiedDomains.slice(0, 50),
                unverifiedDomains: result.orgDiscovery.unverifiedDomains.slice(0, 30),
                discoveryStats: result.orgDiscovery.discoveryStats,
                durationMs: result.orgDiscovery.durationMs,
              } : undefined,
              complianceScan: result.complianceScan || undefined,
              containerExposure: result.containerExposure || undefined,
            };

            const finalStatus = scanOnly ? 'scan_complete' : 'completed';
            await db.updateDomainIntelScan(scanId, {
              status: finalStatus,
              totalAssets: result.totalAssets,
              totalFindings: result.totalFindings || 0,
              confirmedFindings: result.confirmedFindingsCount || 0,
              probableFindings: result.probableFindingsCount || 0,
              potentialFindings: result.potentialFindingsCount || 0,
              discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
              discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
              overallRiskScore: result.overallRiskScore,
              overallRiskBand: result.overallRiskBand,
              executiveSummary: result.executiveSummary,
              threatModelSummary: result.threatModelSummary,
              campaignRecommendations: result.campaignRecommendations,
              pipelineOutput: trimmedOutput,
            });

            console.log(`[DomainIntel] Quick scan completed for ${cleanDomain}: ${result.totalAssets} assets, risk=${result.overallRiskScore}`);
            try {
              const { emitReconComplete, emitSystemNotification } = await import('../lib/ws-event-hub');
              emitReconComplete({ scanId, domain: cleanDomain, findings: result.totalFindings || 0 });
              emitSystemNotification({ title: 'Quick Scan Complete', message: `${cleanDomain}: ${result.totalAssets} assets, ${result.totalFindings} findings, risk=${result.overallRiskScore}`, severity: 'info' });
            } catch {}
          } catch (err: any) {
            console.error(`[DomainIntel] Quick scan failed for ${cleanDomain}:`, err.message, err.stack?.substring(0, 500));
            await db.updateDomainIntelScan(scanId, {
              status: 'failed',
              pipelineOutput: { error: err.message, stack: err.stack?.substring(0, 1000), failedAt: new Date().toISOString() },
            }).catch(() => {});
          }
        });

        return { scanId };
      }),

    // ─── Get Enrichment Profile ─────────────────────────────────────
    getEnrichmentProfile: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        const orgProfile = scan.orgProfile as any;
        return {
          enrichedProfile: orgProfile?.enrichedProfile || null,
          biaProfile: orgProfile?.biaProfile || null,
          customerName: orgProfile?.customerName || scan.primaryDomain,
          sector: scan.sector,
          clientType: scan.clientType,
          criticalFunctions: scan.criticalFunctions,
          complianceFlags: scan.complianceFlags,
        };
      }),

  });
