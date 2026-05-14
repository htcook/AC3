/**
 * catalog-auto-enrichment.ts — Continuous Catalog Enrichment Pipeline
 * 
 * Orchestrates automatic enrichment of the master threat actor catalog from:
 * 1. DFIR report ingestion → playbooks, observations, attack chains
 * 2. IOC-to-TTP reverse engineering → technique mappings from indicators
 * 3. Exploit outcome learning → successful exploit recipes fed back into catalog
 * 4. Hacking Articles ingestion → structured technique walkthroughs
 * 5. Threat intel feeds → new actor profiles, updated TTPs, fresh IOCs
 * 
 * This module is the single entry point for all catalog enrichment.
 * It can be called after engagements, on schedule, or manually.
 */

import { getDb } from '../db';
import * as schema from '../../drizzle/schema';
import { eq, sql, and, isNull, desc, lt, count } from 'drizzle-orm';

// ═══════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════

export interface EnrichmentResult {
  source: string;
  itemsProcessed: number;
  itemsAdded: number;
  itemsFailed: number;
  details: string[];
  durationMs: number;
}

export interface EnrichmentSummary {
  totalSources: number;
  totalProcessed: number;
  totalAdded: number;
  totalFailed: number;
  results: EnrichmentResult[];
  startedAt: string;
  completedAt: string;
  durationMs: number;
}

export interface EnrichmentConfig {
  /** Which enrichment sources to run */
  sources?: ('dfir' | 'ioc' | 'exploit_outcomes' | 'hacking_articles' | 'threat_intel')[];
  /** Max items to process per source (prevents runaway) */
  maxItemsPerSource?: number;
  /** Only process items newer than this date */
  since?: Date;
  /** Specific threat actor IDs to focus on */
  actorIds?: number[];
  /** Specific engagement ID to learn from */
  engagementId?: number;
  /** Dry run — analyze but don't persist */
  dryRun?: boolean;
}

// ═══════════════════════════════════════════════════════════════════
// Main Orchestrator
// ═══════════════════════════════════════════════════════════════════

/**
 * Run the full catalog auto-enrichment pipeline.
 * Each source is independent — failures in one don't block others.
 */
export async function runCatalogEnrichment(
  config: EnrichmentConfig = {}
): Promise<EnrichmentSummary> {
  const startedAt = new Date();
  const results: EnrichmentResult[] = [];
  const sources = config.sources || ['dfir', 'ioc', 'exploit_outcomes', 'hacking_articles', 'threat_intel'];
  const maxItems = config.maxItemsPerSource || 50;

  console.log(`[CatalogEnrichment] Starting enrichment pipeline: sources=${sources.join(',')}, maxItems=${maxItems}`);

  for (const source of sources) {
    try {
      let result: EnrichmentResult;
      switch (source) {
        case 'dfir':
          result = await enrichFromDFIR(config, maxItems);
          break;
        case 'ioc':
          result = await enrichFromIOCs(config, maxItems);
          break;
        case 'exploit_outcomes':
          result = await enrichFromExploitOutcomes(config, maxItems);
          break;
        case 'hacking_articles':
          result = await enrichFromHackingArticles(config, maxItems);
          break;
        case 'threat_intel':
          result = await enrichFromThreatIntel(config, maxItems);
          break;
        default:
          result = { source, itemsProcessed: 0, itemsAdded: 0, itemsFailed: 0, details: ['Unknown source'], durationMs: 0 };
      }
      results.push(result);
      console.log(`[CatalogEnrichment] ${source}: processed=${result.itemsProcessed}, added=${result.itemsAdded}, failed=${result.itemsFailed}`);
    } catch (e) {
      results.push({
        source,
        itemsProcessed: 0,
        itemsAdded: 0,
        itemsFailed: 1,
        details: [`Source failed: ${(e as Error).message}`],
        durationMs: 0,
      });
      console.error(`[CatalogEnrichment] ${source} failed:`, (e as Error).message);
    }
  }

  const completedAt = new Date();
  return {
    totalSources: results.length,
    totalProcessed: results.reduce((s, r) => s + r.itemsProcessed, 0),
    totalAdded: results.reduce((s, r) => s + r.itemsAdded, 0),
    totalFailed: results.reduce((s, r) => s + r.itemsFailed, 0),
    results,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationMs: completedAt.getTime() - startedAt.getTime(),
  };
}

// ═══════════════════════════════════════════════════════════════════
// Source 1: DFIR Report Ingestion
// ═══════════════════════════════════════════════════════════════════

async function enrichFromDFIR(config: EnrichmentConfig, maxItems: number): Promise<EnrichmentResult> {
  const start = Date.now();
  const details: string[] = [];
  let processed = 0, added = 0, failed = 0;
  const drizzleDb = await getDb();

  try {
    const { ingestDFIRReport } = await import('./dfir-report-ingestion');

    // Find unprocessed DFIR observations (observations without linked playbooks)
    const existingObs = await drizzleDb
      .select({ id: schema.dfirObservations.id, rawContent: schema.dfirObservations.rawContent })
      .from(schema.dfirObservations)
      .where(eq(schema.dfirObservations.processed, false))
      .limit(maxItems);

    if (existingObs.length === 0) {
      details.push('No unprocessed DFIR observations found');
      return { source: 'dfir', itemsProcessed: 0, itemsAdded: 0, itemsFailed: 0, details, durationMs: Date.now() - start };
    }

    for (const obs of existingObs) {
      try {
        processed++;
        const result = await ingestDFIRReport({
          content: obs.rawContent || '',
          source: 'dfir_observation_reprocess',
          sourceUrl: '',
        });
        if (result.playbooks.length > 0 || result.observations.length > 0) {
          added += result.playbooks.length + result.observations.length;
          details.push(`Observation ${obs.id}: extracted ${result.playbooks.length} playbooks, ${result.observations.length} observations`);
        }
        // Mark as processed
        await drizzleDb
          .update(schema.dfirObservations)
          .set({ processed: true })
          .where(eq(schema.dfirObservations.id, obs.id));
      } catch (e) {
        failed++;
        details.push(`Observation ${obs.id} failed: ${(e as Error).message}`);
      }
    }
  } catch (e) {
    details.push(`DFIR module load failed: ${(e as Error).message}`);
    failed++;
  }

  return { source: 'dfir', itemsProcessed: processed, itemsAdded: added, itemsFailed: failed, details, durationMs: Date.now() - start };
}

// ═══════════════════════════════════════════════════════════════════
// Source 2: IOC-to-TTP Reverse Engineering
// ═══════════════════════════════════════════════════════════════════

async function enrichFromIOCs(config: EnrichmentConfig, maxItems: number): Promise<EnrichmentResult> {
  const start = Date.now();
  const details: string[] = [];
  let processed = 0, added = 0, failed = 0;
  const drizzleDb = await getDb();

  try {
    const { reverseEngineerIOC, batchReverseEngineerIOCs } = await import('./ioc-ttp-reverse-engineer');

    // Find IOCs that haven't been reverse-engineered yet (no entry in ioc_ttp_mappings)
    const unmappedIOCs = await drizzleDb
      .select({
        id: schema.threatActorIocs.id,
        type: schema.threatActorIocs.iocType,
        value: schema.threatActorIocs.value,
        actorId: schema.threatActorIocs.actorId,
      })
      .from(schema.threatActorIocs)
      .where(
        sql`${schema.threatActorIocs.id} NOT IN (
          SELECT DISTINCT CAST(JSON_EXTRACT(${schema.iocTtpMappings.metadata}, '$.sourceIocId') AS UNSIGNED)
          FROM ${schema.iocTtpMappings}
          WHERE JSON_EXTRACT(${schema.iocTtpMappings.metadata}, '$.sourceIocId') IS NOT NULL
        )`
      )
      .limit(maxItems);

    if (unmappedIOCs.length === 0) {
      details.push('No unmapped IOCs found');
      return { source: 'ioc', itemsProcessed: 0, itemsAdded: 0, itemsFailed: 0, details, durationMs: Date.now() - start };
    }

    // Batch process IOCs
    const iocInputs = unmappedIOCs.map(ioc => ({
      type: ioc.type as any,
      value: ioc.value,
      context: { actorId: ioc.actorId },
    }));

    const results = await batchReverseEngineerIOCs(iocInputs);
    processed = results.length;

    for (const result of results) {
      if (result.mappings && result.mappings.length > 0) {
        added += result.mappings.length;
        details.push(`IOC ${result.iocValue}: mapped to ${result.mappings.length} techniques`);
      }
    }
  } catch (e) {
    details.push(`IOC module load failed: ${(e as Error).message}`);
    failed++;
  }

  return { source: 'ioc', itemsProcessed: processed, itemsAdded: added, itemsFailed: failed, details, durationMs: Date.now() - start };
}

// ═══════════════════════════════════════════════════════════════════
// Source 3: Exploit Outcome Learning
// ═══════════════════════════════════════════════════════════════════

async function enrichFromExploitOutcomes(config: EnrichmentConfig, maxItems: number): Promise<EnrichmentResult> {
  const start = Date.now();
  const details: string[] = [];
  let processed = 0, added = 0, failed = 0;
  const drizzleDb = await getDb();

  try {
    // Find successful exploit outcomes that haven't been converted to playbooks yet
    // Look at engagement logs for successful exploits
    const recentEngagements = await drizzleDb
      .select({
        id: schema.engagements.id,
        metadata: schema.engagements.metadata,
      })
      .from(schema.engagements)
      .where(eq(schema.engagements.status, 'completed'))
      .orderBy(desc(schema.engagements.updatedAt))
      .limit(maxItems);

    for (const eng of recentEngagements) {
      try {
        const metadata = eng.metadata as any;
        if (!metadata?.exploitResults) continue;

        const successfulExploits = (metadata.exploitResults || []).filter(
          (r: any) => r.success === true || r.succeeded === true
        );

        if (successfulExploits.length === 0) continue;
        processed++;

        for (const exploit of successfulExploits) {
          try {
            // Convert successful exploit to a playbook entry
            const playbookData = {
              actorId: null, // Not actor-specific — learned from our own testing
              mitreTechniqueId: exploit.mitreTechnique || mapExploitToMitre(exploit),
              name: `Auto-learned: ${exploit.vulnTitle || exploit.cve || 'Unknown'}`,
              description: `Successfully exploited ${exploit.vulnTitle || ''} on ${exploit.targetHost || ''} during engagement ${eng.id}`,
              platform: exploit.platform || 'web',
              executorType: exploit.toolUsed || 'custom_script',
              command: exploit.payload || exploit.command || '',
              prerequisites: JSON.stringify(exploit.prerequisites || []),
              expectedOutput: exploit.output?.substring(0, 500) || '',
              successIndicators: JSON.stringify(exploit.successIndicators || []),
              source: 'engagement_outcome',
              sourceUrl: '',
              confidence: 95, // High confidence — we actually succeeded
              metadata: JSON.stringify({
                engagementId: eng.id,
                targetHost: exploit.targetHost,
                cve: exploit.cve,
                severity: exploit.severity,
                toolUsed: exploit.toolUsed,
              }),
            };

            // Check for duplicate before inserting
            const existing = await drizzleDb
              .select({ id: schema.exploitPlaybooks.id })
              .from(schema.exploitPlaybooks)
              .where(
                and(
                  eq(schema.exploitPlaybooks.mitreTechniqueId, playbookData.mitreTechniqueId),
                  eq(schema.exploitPlaybooks.command, playbookData.command),
                )
              )
              .limit(1);

            if (existing.length === 0 && playbookData.command) {
              await drizzleDb.insert(schema.exploitPlaybooks).values(playbookData as any);
              added++;
              details.push(`Engagement ${eng.id}: added playbook for ${exploit.vulnTitle || exploit.cve}`);
            }
          } catch (e) {
            failed++;
          }
        }
      } catch (e) {
        failed++;
      }
    }
  } catch (e) {
    details.push(`Exploit outcome processing failed: ${(e as Error).message}`);
    failed++;
  }

  return { source: 'exploit_outcomes', itemsProcessed: processed, itemsAdded: added, itemsFailed: failed, details, durationMs: Date.now() - start };
}

// ═══════════════════════════════════════════════════════════════════
// Source 4: Hacking Articles Ingestion
// ═══════════════════════════════════════════════════════════════════

async function enrichFromHackingArticles(config: EnrichmentConfig, maxItems: number): Promise<EnrichmentResult> {
  const start = Date.now();
  const details: string[] = [];
  let processed = 0, added = 0, failed = 0;

  try {
    const { processArticleBatch } = await import('./hacking-articles-ingestion');

    // Process a batch of articles from the priority categories
    const result = await processArticleBatch({
      categories: ['privilege-escalation', 'lateral-movement', 'persistence', 'credential-dumping', 'defense-evasion'],
      maxArticles: Math.min(maxItems, 10), // Limit to 10 per run (LLM-intensive)
      skipAlreadyIngested: true,
    });

    processed = result.processed;
    added = result.playbooks + result.observations + result.chains;
    failed = result.failed;
    details.push(`Processed ${result.processed} articles: ${result.playbooks} playbooks, ${result.observations} observations, ${result.chains} chains`);
  } catch (e) {
    details.push(`Hacking Articles module load failed: ${(e as Error).message}`);
    failed++;
  }

  return { source: 'hacking_articles', itemsProcessed: processed, itemsAdded: added, itemsFailed: failed, details, durationMs: Date.now() - start };
}

// ═══════════════════════════════════════════════════════════════════
// Source 5: Threat Intel Feed Enrichment
// ═══════════════════════════════════════════════════════════════════

async function enrichFromThreatIntel(config: EnrichmentConfig, maxItems: number): Promise<EnrichmentResult> {
  const start = Date.now();
  const details: string[] = [];
  let processed = 0, added = 0, failed = 0;
  const drizzleDb = await getDb();

  try {
    // Enrich actors that have incomplete profiles (missing abilities, IOCs, or tools)
    const actorsNeedingEnrichment = await drizzleDb
      .select({
        id: schema.threatActors.id,
        name: schema.threatActors.name,
        aliases: schema.threatActors.aliases,
      })
      .from(schema.threatActors)
      .where(
        sql`${schema.threatActors.id} NOT IN (
          SELECT DISTINCT ${schema.threatActorAbilities.actorId}
          FROM ${schema.threatActorAbilities}
        ) OR ${schema.threatActors.id} NOT IN (
          SELECT DISTINCT ${schema.threatActorIocs.actorId}
          FROM ${schema.threatActorIocs}
        )`
      )
      .limit(maxItems);

    if (actorsNeedingEnrichment.length === 0) {
      // Fall back to actors with fewest abilities (need more data)
      const leastEnrichedActors = await drizzleDb
        .select({
          id: schema.threatActors.id,
          name: schema.threatActors.name,
          abilityCount: count(schema.threatActorAbilities.id),
        })
        .from(schema.threatActors)
        .leftJoin(schema.threatActorAbilities, eq(schema.threatActors.id, schema.threatActorAbilities.actorId))
        .groupBy(schema.threatActors.id)
        .orderBy(sql`COUNT(${schema.threatActorAbilities.id}) ASC`)
        .limit(maxItems);

      if (leastEnrichedActors.length > 0) {
        for (const actor of leastEnrichedActors) {
          try {
            processed++;
            const { enrichThreatActorWithLLM } = await import('./threat-actor-crawler');
            const enrichResult = await enrichThreatActorWithLLM(actor.id, actor.name);
            if (enrichResult) {
              added += enrichResult.abilitiesAdded + enrichResult.iocsAdded;
              details.push(`${actor.name}: +${enrichResult.abilitiesAdded} abilities, +${enrichResult.iocsAdded} IOCs`);
            }
          } catch (e) {
            failed++;
            details.push(`${actor.name} enrichment failed: ${(e as Error).message}`);
          }
        }
      } else {
        details.push('All actors have complete profiles');
      }
    } else {
      for (const actor of actorsNeedingEnrichment) {
        try {
          processed++;
          const { enrichThreatActorWithLLM } = await import('./threat-actor-crawler');
          const enrichResult = await enrichThreatActorWithLLM(actor.id, actor.name);
          if (enrichResult) {
            added += enrichResult.abilitiesAdded + enrichResult.iocsAdded;
            details.push(`${actor.name}: +${enrichResult.abilitiesAdded} abilities, +${enrichResult.iocsAdded} IOCs`);
          }
        } catch (e) {
          failed++;
          details.push(`${actor.name} enrichment failed: ${(e as Error).message}`);
        }
      }
    }
  } catch (e) {
    details.push(`Threat intel enrichment failed: ${(e as Error).message}`);
    failed++;
  }

  return { source: 'threat_intel', itemsProcessed: processed, itemsAdded: added, itemsFailed: failed, details, durationMs: Date.now() - start };
}

// ═══════════════════════════════════════════════════════════════════
// Post-Engagement Enrichment Hook
// ═══════════════════════════════════════════════════════════════════

/**
 * Called after an engagement completes to extract learnings and feed them
 * back into the catalog. This is the "learning loop" that makes the system
 * smarter with every engagement.
 */
export async function enrichCatalogFromEngagement(engagementId: number): Promise<EnrichmentResult> {
  const start = Date.now();
  const details: string[] = [];
  let processed = 0, added = 0, failed = 0;
  const drizzleDb = await getDb();

  try {
    // 1. Extract successful exploit outcomes → playbooks
    const exploitResult = await enrichFromExploitOutcomes({ engagementId }, 100);
    processed += exploitResult.itemsProcessed;
    added += exploitResult.itemsAdded;
    failed += exploitResult.itemsFailed;
    details.push(...exploitResult.details);

    // 2. Extract IOCs discovered during engagement → TTP mappings
    const engagement = await drizzleDb
      .select({ metadata: schema.engagements.metadata })
      .from(schema.engagements)
      .where(eq(schema.engagements.id, engagementId))
      .limit(1);

    if (engagement.length > 0) {
      const metadata = engagement[0].metadata as any;
      const discoveredIOCs = metadata?.discoveredIOCs || metadata?.iocs || [];

      if (discoveredIOCs.length > 0) {
        try {
          const { batchReverseEngineerIOCs } = await import('./ioc-ttp-reverse-engineer');
          const iocInputs = discoveredIOCs.map((ioc: any) => ({
            type: ioc.type || 'unknown',
            value: ioc.value || ioc.indicator || '',
            context: { engagementId },
          }));
          const iocResults = await batchReverseEngineerIOCs(iocInputs);
          const iocAdded = iocResults.reduce((s, r) => s + (r.mappings?.length || 0), 0);
          added += iocAdded;
          details.push(`IOC reverse engineering: ${iocAdded} TTP mappings from ${discoveredIOCs.length} IOCs`);
        } catch (e) {
          details.push(`IOC processing failed: ${(e as Error).message}`);
        }
      }

      // 3. Push successful exploit patterns to Caldera as abilities
      try {
        const { enrichCalderaFromCatalog } = await import('./catalog-caldera-enrichment');
        const calderaResult = await enrichCalderaFromCatalog({ engagementId });
        if (calderaResult) {
          added += calderaResult.abilitiesCreated + calderaResult.operationsCreated;
          details.push(`Caldera: +${calderaResult.abilitiesCreated} abilities, +${calderaResult.operationsCreated} operations`);
        }
      } catch (e) {
        details.push(`Caldera enrichment failed: ${(e as Error).message}`);
      }
    }
  } catch (e) {
    details.push(`Post-engagement enrichment failed: ${(e as Error).message}`);
    failed++;
  }

  return {
    source: `engagement_${engagementId}`,
    itemsProcessed: processed,
    itemsAdded: added,
    itemsFailed: failed,
    details,
    durationMs: Date.now() - start,
  };
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/**
 * Map an exploit outcome to a MITRE technique ID based on vuln type
 */
function mapExploitToMitre(exploit: any): string {
  const title = (exploit.vulnTitle || exploit.title || '').toLowerCase();
  const cve = exploit.cve || '';

  // SQL Injection
  if (title.includes('sql injection') || title.includes('sqli')) return 'T1190';
  // XSS
  if (title.includes('cross-site scripting') || title.includes('xss')) return 'T1059.007';
  // Command Injection
  if (title.includes('command injection') || title.includes('os command') || title.includes('rce')) return 'T1059';
  // File Upload
  if (title.includes('file upload') || title.includes('unrestricted upload')) return 'T1105';
  // Path Traversal / LFI
  if (title.includes('path traversal') || title.includes('local file inclusion') || title.includes('lfi')) return 'T1083';
  // SSRF
  if (title.includes('ssrf') || title.includes('server-side request')) return 'T1090';
  // Authentication Bypass
  if (title.includes('authentication bypass') || title.includes('auth bypass')) return 'T1078';
  // Deserialization
  if (title.includes('deserialization') || title.includes('deserialize')) return 'T1059';
  // XXE
  if (title.includes('xxe') || title.includes('xml external')) return 'T1059';
  // Default: exploitation of public-facing application
  return 'T1190';
}
