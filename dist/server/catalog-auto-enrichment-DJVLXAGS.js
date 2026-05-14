import {
  getDb,
  init_db
} from "./chunk-B7OU3XQL.js";
import "./chunk-NRYVRXXR.js";
import {
  dfirObservations,
  engagements,
  exploitPlaybooks,
  init_schema,
  iocTtpMappings,
  threatActorAbilities,
  threatActorIocs,
  threatActors
} from "./chunk-TYPEU32S.js";
import "./chunk-KFQGP6VL.js";

// server/lib/catalog-auto-enrichment.ts
init_db();
init_schema();
import { eq, sql, and, desc, count } from "drizzle-orm";
async function runCatalogEnrichment(config = {}) {
  const startedAt = /* @__PURE__ */ new Date();
  const results = [];
  const sources = config.sources || ["dfir", "ioc", "exploit_outcomes", "hacking_articles", "threat_intel"];
  const maxItems = config.maxItemsPerSource || 50;
  console.log(`[CatalogEnrichment] Starting enrichment pipeline: sources=${sources.join(",")}, maxItems=${maxItems}`);
  for (const source of sources) {
    try {
      let result;
      switch (source) {
        case "dfir":
          result = await enrichFromDFIR(config, maxItems);
          break;
        case "ioc":
          result = await enrichFromIOCs(config, maxItems);
          break;
        case "exploit_outcomes":
          result = await enrichFromExploitOutcomes(config, maxItems);
          break;
        case "hacking_articles":
          result = await enrichFromHackingArticles(config, maxItems);
          break;
        case "threat_intel":
          result = await enrichFromThreatIntel(config, maxItems);
          break;
        default:
          result = { source, itemsProcessed: 0, itemsAdded: 0, itemsFailed: 0, details: ["Unknown source"], durationMs: 0 };
      }
      results.push(result);
      console.log(`[CatalogEnrichment] ${source}: processed=${result.itemsProcessed}, added=${result.itemsAdded}, failed=${result.itemsFailed}`);
    } catch (e) {
      results.push({
        source,
        itemsProcessed: 0,
        itemsAdded: 0,
        itemsFailed: 1,
        details: [`Source failed: ${e.message}`],
        durationMs: 0
      });
      console.error(`[CatalogEnrichment] ${source} failed:`, e.message);
    }
  }
  const completedAt = /* @__PURE__ */ new Date();
  return {
    totalSources: results.length,
    totalProcessed: results.reduce((s, r) => s + r.itemsProcessed, 0),
    totalAdded: results.reduce((s, r) => s + r.itemsAdded, 0),
    totalFailed: results.reduce((s, r) => s + r.itemsFailed, 0),
    results,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationMs: completedAt.getTime() - startedAt.getTime()
  };
}
async function enrichFromDFIR(config, maxItems) {
  const start = Date.now();
  const details = [];
  let processed = 0, added = 0, failed = 0;
  const drizzleDb = await getDb();
  try {
    const { ingestDFIRReport } = await import("./dfir-report-ingestion-77BVLL3D.js");
    const existingObs = await drizzleDb.select({ id: dfirObservations.id, rawContent: dfirObservations.rawContent }).from(dfirObservations).where(eq(dfirObservations.processed, false)).limit(maxItems);
    if (existingObs.length === 0) {
      details.push("No unprocessed DFIR observations found");
      return { source: "dfir", itemsProcessed: 0, itemsAdded: 0, itemsFailed: 0, details, durationMs: Date.now() - start };
    }
    for (const obs of existingObs) {
      try {
        processed++;
        const result = await ingestDFIRReport({
          content: obs.rawContent || "",
          source: "dfir_observation_reprocess",
          sourceUrl: ""
        });
        if (result.playbooks.length > 0 || result.observations.length > 0) {
          added += result.playbooks.length + result.observations.length;
          details.push(`Observation ${obs.id}: extracted ${result.playbooks.length} playbooks, ${result.observations.length} observations`);
        }
        await drizzleDb.update(dfirObservations).set({ processed: true }).where(eq(dfirObservations.id, obs.id));
      } catch (e) {
        failed++;
        details.push(`Observation ${obs.id} failed: ${e.message}`);
      }
    }
  } catch (e) {
    details.push(`DFIR module load failed: ${e.message}`);
    failed++;
  }
  return { source: "dfir", itemsProcessed: processed, itemsAdded: added, itemsFailed: failed, details, durationMs: Date.now() - start };
}
async function enrichFromIOCs(config, maxItems) {
  const start = Date.now();
  const details = [];
  let processed = 0, added = 0, failed = 0;
  const drizzleDb = await getDb();
  try {
    const { reverseEngineerIOC, batchReverseEngineerIOCs } = await import("./ioc-ttp-reverse-engineer-7MTJBAXK.js");
    const unmappedIOCs = await drizzleDb.select({
      id: threatActorIocs.id,
      type: threatActorIocs.iocType,
      value: threatActorIocs.value,
      actorId: threatActorIocs.actorId
    }).from(threatActorIocs).where(
      sql`${threatActorIocs.id} NOT IN (
          SELECT DISTINCT CAST(JSON_EXTRACT(${iocTtpMappings.metadata}, '$.sourceIocId') AS UNSIGNED)
          FROM ${iocTtpMappings}
          WHERE JSON_EXTRACT(${iocTtpMappings.metadata}, '$.sourceIocId') IS NOT NULL
        )`
    ).limit(maxItems);
    if (unmappedIOCs.length === 0) {
      details.push("No unmapped IOCs found");
      return { source: "ioc", itemsProcessed: 0, itemsAdded: 0, itemsFailed: 0, details, durationMs: Date.now() - start };
    }
    const iocInputs = unmappedIOCs.map((ioc) => ({
      type: ioc.type,
      value: ioc.value,
      context: { actorId: ioc.actorId }
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
    details.push(`IOC module load failed: ${e.message}`);
    failed++;
  }
  return { source: "ioc", itemsProcessed: processed, itemsAdded: added, itemsFailed: failed, details, durationMs: Date.now() - start };
}
async function enrichFromExploitOutcomes(config, maxItems) {
  const start = Date.now();
  const details = [];
  let processed = 0, added = 0, failed = 0;
  const drizzleDb = await getDb();
  try {
    const recentEngagements = await drizzleDb.select({
      id: engagements.id,
      metadata: engagements.metadata
    }).from(engagements).where(eq(engagements.status, "completed")).orderBy(desc(engagements.updatedAt)).limit(maxItems);
    for (const eng of recentEngagements) {
      try {
        const metadata = eng.metadata;
        if (!metadata?.exploitResults) continue;
        const successfulExploits = (metadata.exploitResults || []).filter(
          (r) => r.success === true || r.succeeded === true
        );
        if (successfulExploits.length === 0) continue;
        processed++;
        for (const exploit of successfulExploits) {
          try {
            const playbookData = {
              actorId: null,
              // Not actor-specific — learned from our own testing
              mitreTechniqueId: exploit.mitreTechnique || mapExploitToMitre(exploit),
              name: `Auto-learned: ${exploit.vulnTitle || exploit.cve || "Unknown"}`,
              description: `Successfully exploited ${exploit.vulnTitle || ""} on ${exploit.targetHost || ""} during engagement ${eng.id}`,
              platform: exploit.platform || "web",
              executorType: exploit.toolUsed || "custom_script",
              command: exploit.payload || exploit.command || "",
              prerequisites: JSON.stringify(exploit.prerequisites || []),
              expectedOutput: exploit.output?.substring(0, 500) || "",
              successIndicators: JSON.stringify(exploit.successIndicators || []),
              source: "engagement_outcome",
              sourceUrl: "",
              confidence: 95,
              // High confidence — we actually succeeded
              metadata: JSON.stringify({
                engagementId: eng.id,
                targetHost: exploit.targetHost,
                cve: exploit.cve,
                severity: exploit.severity,
                toolUsed: exploit.toolUsed
              })
            };
            const existing = await drizzleDb.select({ id: exploitPlaybooks.id }).from(exploitPlaybooks).where(
              and(
                eq(exploitPlaybooks.mitreTechniqueId, playbookData.mitreTechniqueId),
                eq(exploitPlaybooks.command, playbookData.command)
              )
            ).limit(1);
            if (existing.length === 0 && playbookData.command) {
              await drizzleDb.insert(exploitPlaybooks).values(playbookData);
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
    details.push(`Exploit outcome processing failed: ${e.message}`);
    failed++;
  }
  return { source: "exploit_outcomes", itemsProcessed: processed, itemsAdded: added, itemsFailed: failed, details, durationMs: Date.now() - start };
}
async function enrichFromHackingArticles(config, maxItems) {
  const start = Date.now();
  const details = [];
  let processed = 0, added = 0, failed = 0;
  try {
    const { processArticleBatch } = await import("./hacking-articles-ingestion-SDHKF4KW.js");
    const result = await processArticleBatch({
      categories: ["privilege-escalation", "lateral-movement", "persistence", "credential-dumping", "defense-evasion"],
      maxArticles: Math.min(maxItems, 10),
      // Limit to 10 per run (LLM-intensive)
      skipAlreadyIngested: true
    });
    processed = result.processed;
    added = result.playbooks + result.observations + result.chains;
    failed = result.failed;
    details.push(`Processed ${result.processed} articles: ${result.playbooks} playbooks, ${result.observations} observations, ${result.chains} chains`);
  } catch (e) {
    details.push(`Hacking Articles module load failed: ${e.message}`);
    failed++;
  }
  return { source: "hacking_articles", itemsProcessed: processed, itemsAdded: added, itemsFailed: failed, details, durationMs: Date.now() - start };
}
async function enrichFromThreatIntel(config, maxItems) {
  const start = Date.now();
  const details = [];
  let processed = 0, added = 0, failed = 0;
  const drizzleDb = await getDb();
  try {
    const actorsNeedingEnrichment = await drizzleDb.select({
      id: threatActors.id,
      name: threatActors.name,
      aliases: threatActors.aliases
    }).from(threatActors).where(
      sql`${threatActors.id} NOT IN (
          SELECT DISTINCT ${threatActorAbilities.actorId}
          FROM ${threatActorAbilities}
        ) OR ${threatActors.id} NOT IN (
          SELECT DISTINCT ${threatActorIocs.actorId}
          FROM ${threatActorIocs}
        )`
    ).limit(maxItems);
    if (actorsNeedingEnrichment.length === 0) {
      const leastEnrichedActors = await drizzleDb.select({
        id: threatActors.id,
        name: threatActors.name,
        abilityCount: count(threatActorAbilities.id)
      }).from(threatActors).leftJoin(threatActorAbilities, eq(threatActors.id, threatActorAbilities.actorId)).groupBy(threatActors.id).orderBy(sql`COUNT(${threatActorAbilities.id}) ASC`).limit(maxItems);
      if (leastEnrichedActors.length > 0) {
        for (const actor of leastEnrichedActors) {
          try {
            processed++;
            const { enrichThreatActorWithLLM } = await import("./threat-actor-crawler-3I3G5JKD.js");
            const enrichResult = await enrichThreatActorWithLLM(actor.id, actor.name);
            if (enrichResult) {
              added += enrichResult.abilitiesAdded + enrichResult.iocsAdded;
              details.push(`${actor.name}: +${enrichResult.abilitiesAdded} abilities, +${enrichResult.iocsAdded} IOCs`);
            }
          } catch (e) {
            failed++;
            details.push(`${actor.name} enrichment failed: ${e.message}`);
          }
        }
      } else {
        details.push("All actors have complete profiles");
      }
    } else {
      for (const actor of actorsNeedingEnrichment) {
        try {
          processed++;
          const { enrichThreatActorWithLLM } = await import("./threat-actor-crawler-3I3G5JKD.js");
          const enrichResult = await enrichThreatActorWithLLM(actor.id, actor.name);
          if (enrichResult) {
            added += enrichResult.abilitiesAdded + enrichResult.iocsAdded;
            details.push(`${actor.name}: +${enrichResult.abilitiesAdded} abilities, +${enrichResult.iocsAdded} IOCs`);
          }
        } catch (e) {
          failed++;
          details.push(`${actor.name} enrichment failed: ${e.message}`);
        }
      }
    }
  } catch (e) {
    details.push(`Threat intel enrichment failed: ${e.message}`);
    failed++;
  }
  return { source: "threat_intel", itemsProcessed: processed, itemsAdded: added, itemsFailed: failed, details, durationMs: Date.now() - start };
}
async function enrichCatalogFromEngagement(engagementId) {
  const start = Date.now();
  const details = [];
  let processed = 0, added = 0, failed = 0;
  const drizzleDb = await getDb();
  try {
    const exploitResult = await enrichFromExploitOutcomes({ engagementId }, 100);
    processed += exploitResult.itemsProcessed;
    added += exploitResult.itemsAdded;
    failed += exploitResult.itemsFailed;
    details.push(...exploitResult.details);
    const engagement = await drizzleDb.select({ metadata: engagements.metadata }).from(engagements).where(eq(engagements.id, engagementId)).limit(1);
    if (engagement.length > 0) {
      const metadata = engagement[0].metadata;
      const discoveredIOCs = metadata?.discoveredIOCs || metadata?.iocs || [];
      if (discoveredIOCs.length > 0) {
        try {
          const { batchReverseEngineerIOCs } = await import("./ioc-ttp-reverse-engineer-7MTJBAXK.js");
          const iocInputs = discoveredIOCs.map((ioc) => ({
            type: ioc.type || "unknown",
            value: ioc.value || ioc.indicator || "",
            context: { engagementId }
          }));
          const iocResults = await batchReverseEngineerIOCs(iocInputs);
          const iocAdded = iocResults.reduce((s, r) => s + (r.mappings?.length || 0), 0);
          added += iocAdded;
          details.push(`IOC reverse engineering: ${iocAdded} TTP mappings from ${discoveredIOCs.length} IOCs`);
        } catch (e) {
          details.push(`IOC processing failed: ${e.message}`);
        }
      }
      try {
        const { enrichCalderaFromCatalog } = await import("./catalog-caldera-enrichment-VOHQKBFL.js");
        const calderaResult = await enrichCalderaFromCatalog({ engagementId });
        if (calderaResult) {
          added += calderaResult.abilitiesCreated + calderaResult.operationsCreated;
          details.push(`Caldera: +${calderaResult.abilitiesCreated} abilities, +${calderaResult.operationsCreated} operations`);
        }
      } catch (e) {
        details.push(`Caldera enrichment failed: ${e.message}`);
      }
    }
  } catch (e) {
    details.push(`Post-engagement enrichment failed: ${e.message}`);
    failed++;
  }
  return {
    source: `engagement_${engagementId}`,
    itemsProcessed: processed,
    itemsAdded: added,
    itemsFailed: failed,
    details,
    durationMs: Date.now() - start
  };
}
function mapExploitToMitre(exploit) {
  const title = (exploit.vulnTitle || exploit.title || "").toLowerCase();
  const cve = exploit.cve || "";
  if (title.includes("sql injection") || title.includes("sqli")) return "T1190";
  if (title.includes("cross-site scripting") || title.includes("xss")) return "T1059.007";
  if (title.includes("command injection") || title.includes("os command") || title.includes("rce")) return "T1059";
  if (title.includes("file upload") || title.includes("unrestricted upload")) return "T1105";
  if (title.includes("path traversal") || title.includes("local file inclusion") || title.includes("lfi")) return "T1083";
  if (title.includes("ssrf") || title.includes("server-side request")) return "T1090";
  if (title.includes("authentication bypass") || title.includes("auth bypass")) return "T1078";
  if (title.includes("deserialization") || title.includes("deserialize")) return "T1059";
  if (title.includes("xxe") || title.includes("xml external")) return "T1059";
  return "T1190";
}
export {
  enrichCatalogFromEngagement,
  runCatalogEnrichment
};
