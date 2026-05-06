import {
  getDb,
  init_db
} from "./chunk-VL2KRLTM.js";
import "./chunk-NRYVRXXR.js";
import {
  init_schema,
  threatActorAbilities,
  threatActorIocs,
  threatActors,
  ttpKnowledge
} from "./chunk-IG2G4XDA.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/incident-search-ingest.ts
import { eq } from "drizzle-orm";
function toActorId(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}
function inferThreatLevel(matches) {
  const hasCritical = matches.some((m) => m.severity === "critical");
  const hasRansomware = matches.some((m) => m.eventType === "ransomware" || m.actorType === "ransomware");
  const hasAPT = matches.some((m) => m.actorType === "apt");
  if (hasCritical || hasRansomware) return "critical";
  if (hasAPT) return "high";
  return "medium";
}
function normalizeActorType(type) {
  const map = {
    ransomware: "ransomware_group",
    apt: "apt_group",
    cybercrime: "cybercrime_group",
    hacktivist: "hacktivist_group",
    unknown: "unknown"
  };
  return map[type || "unknown"] || "unknown";
}
async function ingestNewActors(webMatches, domain) {
  const db = await getDb();
  if (!db) return { created: 0, updated: 0, errors: ["Database not available"] };
  const result = { created: 0, updated: 0, errors: [] };
  const actorMap = /* @__PURE__ */ new Map();
  for (const m of webMatches) {
    if (!m.actorName || m.actorName === "Unknown" || m.actorName === "unknown") continue;
    const existing = actorMap.get(m.actorName) || [];
    existing.push(m);
    actorMap.set(m.actorName, existing);
  }
  for (const [actorName, matches] of actorMap) {
    const actorId = toActorId(actorName);
    try {
      const [existing] = await db.select({ id: threatActors.id }).from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
      if (existing) {
        result.updated++;
        continue;
      }
      const descriptions = matches.map((m) => m.title).filter((v, i, a) => a.indexOf(v) === i).slice(0, 5);
      const techniques = [...new Set(matches.flatMap((m) => m.mitreTechniques || []))];
      const sectors = [...new Set(matches.map((m) => m.victimSector).filter(Boolean))];
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
        source: "incident_search_auto_ingest"
      });
      result.created++;
    } catch (err) {
      result.errors.push(`Actor ${actorName}: ${err.message}`);
    }
  }
  return result;
}
async function ingestNewTTPs(allMatches) {
  const db = await getDb();
  if (!db) return { created: 0, errors: ["Database not available"] };
  const result = { created: 0, errors: [] };
  const techniques = [...new Set(allMatches.flatMap((m) => m.mitreTechniques || []))];
  for (const techniqueId of techniques) {
    try {
      const [existing] = await db.select({ id: ttpKnowledge.id }).from(ttpKnowledge).where(eq(ttpKnowledge.techniqueId, techniqueId)).limit(1);
      if (existing) continue;
      const actorsUsing = allMatches.filter((m) => m.mitreTechniques?.includes(techniqueId)).map((m) => m.actorName).filter(Boolean).filter((v, i, a) => a.indexOf(v) === i);
      const tactic = inferTacticFromTechnique(techniqueId);
      await db.insert(ttpKnowledge).values({
        techniqueId,
        name: techniqueId,
        // Will be enriched later by TTP knowledge enrichment
        tactic,
        description: `Discovered via incident search. Used by: ${actorsUsing.join(", ") || "unknown actors"}`,
        severity: "medium",
        detectionDifficulty: "medium",
        source: "incident_search_auto_ingest"
      });
      result.created++;
    } catch (err) {
      result.errors.push(`TTP ${techniqueId}: ${err.message}`);
    }
  }
  return result;
}
async function ingestNewIOCs(webMatches, domain) {
  const db = await getDb();
  if (!db) return { created: 0, errors: ["Database not available"] };
  const result = { created: 0, errors: [] };
  const iocMatches = webMatches.filter((m) => m.iocType && m.iocValue);
  for (const m of iocMatches) {
    const actorId = m.actorId || (m.actorName ? toActorId(m.actorName) : null);
    if (!actorId) continue;
    try {
      const [existing] = await db.select({ id: threatActorIocs.id }).from(threatActorIocs).where(eq(threatActorIocs.value, m.iocValue)).limit(1);
      if (existing) continue;
      await db.insert(threatActorIocs).values({
        actorId,
        iocType: m.iocType,
        value: m.iocValue,
        description: `Auto-ingested from incident search for ${domain}: ${m.title}`,
        iocConfidence: m.confidence === "confirmed" ? "high" : m.confidence === "probable" ? "medium" : "low",
        firstSeen: m.date || null,
        lastSeen: m.date || null,
        source: "incident_search_auto_ingest"
      });
      result.created++;
    } catch (err) {
      result.errors.push(`IOC ${m.iocValue}: ${err.message}`);
    }
  }
  return result;
}
async function ingestActorAbilities(webMatches) {
  const db = await getDb();
  if (!db) return { created: 0, errors: ["Database not available"] };
  const result = { created: 0, errors: [] };
  const actorTechMap = /* @__PURE__ */ new Map();
  for (const m of webMatches) {
    if (!m.actorName || !m.mitreTechniques?.length) continue;
    const actorId = toActorId(m.actorName);
    const existing = actorTechMap.get(actorId) || /* @__PURE__ */ new Set();
    for (const t of m.mitreTechniques) existing.add(t);
    actorTechMap.set(actorId, existing);
  }
  for (const [actorId, techniques] of actorTechMap) {
    for (const techniqueId of techniques) {
      try {
        const [existing] = await db.select({ id: threatActorAbilities.id }).from(threatActorAbilities).where(eq(threatActorAbilities.actorId, actorId)).limit(1);
        if (existing) {
          const allAbilities = await db.select({ techniqueId: threatActorAbilities.techniqueId }).from(threatActorAbilities).where(eq(threatActorAbilities.actorId, actorId));
          if (allAbilities.some((a) => a.techniqueId === techniqueId)) continue;
        }
        const tactic = inferTacticFromTechnique(techniqueId);
        await db.insert(threatActorAbilities).values({
          actorId,
          techniqueId,
          tactic: tactic || "unknown",
          name: `${techniqueId} (auto-discovered)`,
          description: `Auto-linked from incident search web results`
        });
        result.created++;
      } catch (err) {
        result.errors.push(`Ability ${actorId}/${techniqueId}: ${err.message}`);
      }
    }
  }
  return result;
}
function inferTacticFromTechnique(techniqueId) {
  const tacticMap = {
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
    "T1005": "collection"
  };
  if (tacticMap[techniqueId]) return tacticMap[techniqueId];
  const baseTechnique = techniqueId.split(".")[0];
  if (tacticMap[baseTechnique]) return tacticMap[baseTechnique];
  return "unknown";
}
async function ingestIncidentSearchResults(catalogMatches, webSearchMatches, domain) {
  console.log(`[IncidentIngest] Starting auto-ingest for ${domain}: ${webSearchMatches.length} web matches`);
  const allMatches = [...catalogMatches, ...webSearchMatches];
  const [actorResult, ttpResult, iocResult, abilityResult] = await Promise.all([
    ingestNewActors(webSearchMatches, domain),
    ingestNewTTPs(allMatches),
    ingestNewIOCs(webSearchMatches, domain),
    ingestActorAbilities(webSearchMatches)
  ]);
  const result = {
    actorsCreated: actorResult.created,
    actorsUpdated: actorResult.updated,
    abilitiesCreated: abilityResult.created,
    iocsCreated: iocResult.created,
    ttpKnowledgeCreated: ttpResult.created,
    errors: [
      ...actorResult.errors,
      ...ttpResult.errors,
      ...iocResult.errors,
      ...abilityResult.errors
    ]
  };
  console.log(
    `[IncidentIngest] Complete for ${domain}: ${result.actorsCreated} actors created, ${result.actorsUpdated} existing, ${result.abilitiesCreated} abilities, ${result.iocsCreated} IOCs, ${result.ttpKnowledgeCreated} TTPs` + (result.errors.length > 0 ? ` (${result.errors.length} errors)` : "")
  );
  return result;
}
var init_incident_search_ingest = __esm({
  "server/lib/incident-search-ingest.ts"() {
    init_db();
    init_schema();
  }
});
init_incident_search_ingest();
export {
  ingestIncidentSearchResults
};
