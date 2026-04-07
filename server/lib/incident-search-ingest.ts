/**
 * Incident Search Auto-Ingest
 * 
 * After an incident search enrichment completes, this module feeds newly
 * discovered actors, TTPs, and IOCs back into the threat catalog tables
 * so they're available for future scans and cross-referencing.
 * 
 * Tables affected:
 * - threatActors (new actors from web search)
 * - threatActorAbilities (new TTPs linked to actors)
 * - threatActorIocs (new IOCs linked to actors)
 * - ttpKnowledge (new MITRE technique entries)
 */

import { getDb } from "../db";
import { threatActors, threatActorAbilities, threatActorIocs, ttpKnowledge } from "../../drizzle/schema";
import { eq } from "drizzle-orm";

interface IncidentMatch {
  source: "threat_catalog_event" | "threat_catalog_ioc" | "web_search";
  actorId?: string;
  actorName?: string;
  actorType?: string;
  eventType?: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  date?: string;
  victimName?: string;
  victimSector?: string;
  mitreTechniques?: string[];
  iocType?: string;
  iocValue?: string;
  confidence: "confirmed" | "probable" | "possible";
  relevanceScore: number;
}

export interface IngestResult {
  actorsCreated: number;
  actorsUpdated: number;
  abilitiesCreated: number;
  iocsCreated: number;
  ttpKnowledgeCreated: number;
  errors: string[];
}

/**
 * Generate a stable actorId from an actor name.
 * Converts "Lazarus Group" → "lazarus-group"
 */
function toActorId(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

/**
 * Map eventType/actorType to a threat level for the actor record.
 */
function inferThreatLevel(matches: IncidentMatch[]): string {
  const hasCritical = matches.some(m => m.severity === "critical");
  const hasRansomware = matches.some(m => m.eventType === "ransomware" || m.actorType === "ransomware");
  const hasAPT = matches.some(m => m.actorType === "apt");
  if (hasCritical || hasRansomware) return "critical";
  if (hasAPT) return "high";
  return "medium";
}

/**
 * Map actor type strings from incident search to threat catalog actor types.
 */
function normalizeActorType(type?: string): string {
  const map: Record<string, string> = {
    ransomware: "ransomware_group",
    apt: "apt_group",
    cybercrime: "cybercrime_group",
    hacktivist: "hacktivist_group",
    unknown: "unknown",
  };
  return map[type || "unknown"] || "unknown";
}

/**
 * Ingest newly discovered actors from incident search web results into the
 * threatActors table. Only creates actors that don't already exist.
 */
async function ingestNewActors(
  webMatches: IncidentMatch[],
  domain: string
): Promise<{ created: number; updated: number; errors: string[] }> {
  const db = await getDb();
  if (!db) return { created: 0, updated: 0, errors: ["Database not available"] };

  const result = { created: 0, updated: 0, errors: [] as string[] };

  // Group matches by actor name
  const actorMap = new Map<string, IncidentMatch[]>();
  for (const m of webMatches) {
    if (!m.actorName || m.actorName === "Unknown" || m.actorName === "unknown") continue;
    const existing = actorMap.get(m.actorName) || [];
    existing.push(m);
    actorMap.set(m.actorName, existing);
  }

  for (const [actorName, matches] of actorMap) {
    const actorId = toActorId(actorName);
    try {
      // Check if actor already exists
      const [existing] = await db
        .select({ id: threatActors.id })
        .from(threatActors)
        .where(eq(threatActors.actorId, actorId))
        .limit(1);

      if (existing) {
        result.updated++;
        continue; // Actor already in catalog
      }

      // Build description from incident matches
      const descriptions = matches
        .map(m => m.title)
        .filter((v, i, a) => a.indexOf(v) === i)
        .slice(0, 5);

      const techniques = [...new Set(matches.flatMap(m => m.mitreTechniques || []))];
      const sectors = [...new Set(matches.map(m => m.victimSector).filter(Boolean))];

      await db.insert(threatActors).values({
        actorId,
        name: actorName,
        actorType: normalizeActorType(matches[0]?.actorType),
        description: `Auto-discovered via incident search for ${domain}. Known incidents: ${descriptions.join("; ")}`,
        threatLevel: inferThreatLevel(matches),
        origin: "unknown",
        targetSectors: sectors.length > 0 ? JSON.stringify(sectors) : null,
        mitreTechniques: techniques.length > 0 ? JSON.stringify(techniques) : null,
        aliases: null,
        firstSeen: matches[0]?.date || null,
        lastSeen: matches[matches.length - 1]?.date || null,
        isActive: true,
        source: "incident_search_auto_ingest",
      });

      result.created++;
    } catch (err: any) {
      result.errors.push(`Actor ${actorName}: ${err.message}`);
    }
  }

  return result;
}

/**
 * Ingest new MITRE ATT&CK techniques discovered from incident search
 * into the ttpKnowledge table.
 */
async function ingestNewTTPs(
  allMatches: IncidentMatch[]
): Promise<{ created: number; errors: string[] }> {
  const db = await getDb();
  if (!db) return { created: 0, errors: ["Database not available"] };

  const result = { created: 0, errors: [] as string[] };

  // Collect all unique techniques
  const techniques = [...new Set(allMatches.flatMap(m => m.mitreTechniques || []))];

  for (const techniqueId of techniques) {
    try {
      // Check if technique already exists in knowledge base
      const [existing] = await db
        .select({ id: ttpKnowledge.id })
        .from(ttpKnowledge)
        .where(eq(ttpKnowledge.techniqueId, techniqueId))
        .limit(1);

      if (existing) continue; // Already known

      // Find which actors use this technique
      const actorsUsing = allMatches
        .filter(m => m.mitreTechniques?.includes(techniqueId))
        .map(m => m.actorName)
        .filter(Boolean)
        .filter((v, i, a) => a.indexOf(v) === i);

      // Infer tactic from technique ID pattern (basic mapping)
      const tactic = inferTacticFromTechnique(techniqueId);

      await db.insert(ttpKnowledge).values({
        techniqueId,
        name: techniqueId, // Will be enriched later by TTP knowledge enrichment
        tactic: tactic,
        description: `Discovered via incident search. Used by: ${actorsUsing.join(", ") || "unknown actors"}`,
        severity: "medium",
        detectionDifficulty: "medium",
        source: "incident_search_auto_ingest",
      });

      result.created++;
    } catch (err: any) {
      result.errors.push(`TTP ${techniqueId}: ${err.message}`);
    }
  }

  return result;
}

/**
 * Ingest IOCs from incident search matches into the threatActorIocs table.
 * Currently handles domain and URL IOCs from web search results.
 */
async function ingestNewIOCs(
  webMatches: IncidentMatch[],
  domain: string
): Promise<{ created: number; errors: string[] }> {
  const db = await getDb();
  if (!db) return { created: 0, errors: ["Database not available"] };

  const result = { created: 0, errors: [] as string[] };

  // Extract IOCs from matches that have explicit IOC data
  const iocMatches = webMatches.filter(m => m.iocType && m.iocValue);

  for (const m of iocMatches) {
    const actorId = m.actorId || (m.actorName ? toActorId(m.actorName) : null);
    if (!actorId) continue;

    try {
      // Check for duplicate
      const [existing] = await db
        .select({ id: threatActorIocs.id })
        .from(threatActorIocs)
        .where(eq(threatActorIocs.value, m.iocValue!))
        .limit(1);

      if (existing) continue;

      await db.insert(threatActorIocs).values({
        actorId,
        iocType: m.iocType!,
        value: m.iocValue!,
        description: `Auto-ingested from incident search for ${domain}: ${m.title}`,
        iocConfidence: m.confidence === "confirmed" ? "high" : m.confidence === "probable" ? "medium" : "low",
        firstSeen: m.date || null,
        lastSeen: m.date || null,
        source: "incident_search_auto_ingest",
      });

      result.created++;
    } catch (err: any) {
      result.errors.push(`IOC ${m.iocValue}: ${err.message}`);
    }
  }

  return result;
}

/**
 * Ingest MITRE abilities (technique → actor links) into threatActorAbilities.
 */
async function ingestActorAbilities(
  webMatches: IncidentMatch[]
): Promise<{ created: number; errors: string[] }> {
  const db = await getDb();
  if (!db) return { created: 0, errors: ["Database not available"] };

  const result = { created: 0, errors: [] as string[] };

  // Build actor → techniques map
  const actorTechMap = new Map<string, Set<string>>();
  for (const m of webMatches) {
    if (!m.actorName || !m.mitreTechniques?.length) continue;
    const actorId = toActorId(m.actorName);
    const existing = actorTechMap.get(actorId) || new Set();
    for (const t of m.mitreTechniques) existing.add(t);
    actorTechMap.set(actorId, existing);
  }

  for (const [actorId, techniques] of actorTechMap) {
    for (const techniqueId of techniques) {
      try {
        // Check if this actor-technique link already exists
        const [existing] = await db
          .select({ id: threatActorAbilities.id })
          .from(threatActorAbilities)
          .where(eq(threatActorAbilities.actorId, actorId))
          .limit(1);

        // Simple dedup: if actor has any abilities, check more carefully
        if (existing) {
          const allAbilities = await db
            .select({ techniqueId: threatActorAbilities.techniqueId })
            .from(threatActorAbilities)
            .where(eq(threatActorAbilities.actorId, actorId));
          if (allAbilities.some(a => a.techniqueId === techniqueId)) continue;
        }

        const tactic = inferTacticFromTechnique(techniqueId);

        await db.insert(threatActorAbilities).values({
          actorId,
          techniqueId,
          tactic: tactic || "unknown",
          name: `${techniqueId} (auto-discovered)`,
          description: `Auto-linked from incident search web results`,
        });

        result.created++;
      } catch (err: any) {
        result.errors.push(`Ability ${actorId}/${techniqueId}: ${err.message}`);
      }
    }
  }

  return result;
}

/**
 * Basic tactic inference from MITRE technique ID.
 * T1190 → initial-access, T1078 → defense-evasion, etc.
 */
function inferTacticFromTechnique(techniqueId: string): string {
  const tacticMap: Record<string, string> = {
    "T1190": "initial-access",
    "T1133": "initial-access",
    "T1566": "initial-access",
    "T1078": "defense-evasion",
    "T1059": "execution",
    "T1053": "execution",
    "T1547": "persistence",
    "T1098": "persistence",
    "T1003": "credential-access",
    "T1110": "credential-access",
    "T1021": "lateral-movement",
    "T1570": "lateral-movement",
    "T1041": "exfiltration",
    "T1567": "exfiltration",
    "T1486": "impact",
    "T1490": "impact",
    "T1071": "command-and-control",
    "T1105": "command-and-control",
    "T1082": "discovery",
    "T1083": "discovery",
    "T1560": "collection",
    "T1005": "collection",
  };

  // Check exact match first, then base technique (strip sub-technique)
  if (tacticMap[techniqueId]) return tacticMap[techniqueId];
  const baseTechnique = techniqueId.split(".")[0];
  if (tacticMap[baseTechnique]) return tacticMap[baseTechnique];
  return "unknown";
}

/**
 * Main entry point: run all ingest operations after an incident search.
 */
export async function ingestIncidentSearchResults(
  catalogMatches: IncidentMatch[],
  webSearchMatches: IncidentMatch[],
  domain: string
): Promise<IngestResult> {
  console.log(`[IncidentIngest] Starting auto-ingest for ${domain}: ${webSearchMatches.length} web matches`);

  const allMatches = [...catalogMatches, ...webSearchMatches];

  const [actorResult, ttpResult, iocResult, abilityResult] = await Promise.all([
    ingestNewActors(webSearchMatches, domain),
    ingestNewTTPs(allMatches),
    ingestNewIOCs(webSearchMatches, domain),
    ingestActorAbilities(webSearchMatches),
  ]);

  const result: IngestResult = {
    actorsCreated: actorResult.created,
    actorsUpdated: actorResult.updated,
    abilitiesCreated: abilityResult.created,
    iocsCreated: iocResult.created,
    ttpKnowledgeCreated: ttpResult.created,
    errors: [
      ...actorResult.errors,
      ...ttpResult.errors,
      ...iocResult.errors,
      ...abilityResult.errors,
    ],
  };

  console.log(
    `[IncidentIngest] Complete for ${domain}: ` +
    `${result.actorsCreated} actors created, ${result.actorsUpdated} existing, ` +
    `${result.abilitiesCreated} abilities, ${result.iocsCreated} IOCs, ` +
    `${result.ttpKnowledgeCreated} TTPs` +
    (result.errors.length > 0 ? ` (${result.errors.length} errors)` : "")
  );

  return result;
}
