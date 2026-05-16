import {
  init_llm,
  invokeLLM
} from "./chunk-AOUQ6RTC.js";
import "./chunk-RUIEEOYK.js";
import {
  getDb,
  init_db
} from "./chunk-RSFTEATL.js";
import "./chunk-KDOLKO2A.js";
import {
  init_schema,
  threatActorIocs,
  threatActors,
  threatGroupEvents
} from "./chunk-L4JENJ4Z.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/incident-search-enrichment.ts
import { eq, like, or, desc } from "drizzle-orm";
async function searchThreatCatalog(domain) {
  const matches = [];
  const db = await getDb();
  if (!db) return matches;
  const domainParts = domain.split(".");
  const orgCandidates = [];
  if (domainParts.length >= 2) {
    orgCandidates.push(domainParts[domainParts.length - 2]);
  }
  orgCandidates.push(domain);
  if (domainParts.length >= 3) {
    orgCandidates.push(domainParts.slice(-2).join("."));
  }
  try {
    for (const orgName of orgCandidates) {
      const events = await db.select().from(threatGroupEvents).where(
        or(
          like(threatGroupEvents.tgeVictimName, `%${orgName}%`),
          like(threatGroupEvents.tgeTitle, `%${orgName}%`),
          like(threatGroupEvents.tgeDescription, `%${orgName}%`),
          like(threatGroupEvents.tgeTitle, `%${domain}%`),
          like(threatGroupEvents.tgeDescription, `%${domain}%`)
        )
      ).orderBy(desc(threatGroupEvents.tgeEventDate)).limit(20);
      for (const event of events) {
        const victimLower = (event.tgeVictimName || "").toLowerCase();
        const titleLower = (event.tgeTitle || "").toLowerCase();
        const descLower = (event.tgeDescription || "").toLowerCase();
        const orgLower = orgName.toLowerCase();
        const domainLower = domain.toLowerCase();
        const isDirectMatch = victimLower.includes(orgLower) || titleLower.includes(domainLower) || descLower.includes(domainLower);
        if (!isDirectMatch && orgLower.length < 4) continue;
        let actorName = event.tgeActorId;
        let actorType;
        try {
          const [actor] = await db.select({ name: threatActors.name, actorType: threatActors.actorType }).from(threatActors).where(eq(threatActors.actorId, event.tgeActorId)).limit(1);
          if (actor) {
            actorName = actor.name;
            actorType = actor.actorType;
          }
        } catch {
        }
        matches.push({
          source: "threat_catalog_event",
          actorId: event.tgeActorId,
          actorName,
          actorType,
          eventType: event.eventType,
          title: event.tgeTitle,
          description: event.tgeDescription || "",
          severity: event.tgeSeverity || "medium",
          date: event.tgeEventDate || void 0,
          victimName: event.tgeVictimName || void 0,
          victimSector: event.tgeVictimSector || void 0,
          mitreTechniques: event.tgeMitreTechniques || [],
          confidence: victimLower.includes(orgLower) ? "confirmed" : "probable",
          relevanceScore: victimLower.includes(orgLower) ? 0.95 : 0.7
        });
      }
    }
  } catch (err) {
    console.error(`[IncidentSearch] Threat catalog event search failed: ${err.message}`);
  }
  try {
    const iocs = await db.select().from(threatActorIocs).where(
      or(
        like(threatActorIocs.value, `%${domain}%`),
        ...orgCandidates.map((org) => like(threatActorIocs.value, `%${org}%`))
      )
    ).limit(20);
    for (const ioc of iocs) {
      if (!["domain", "url", "ip", "hostname", "email"].includes(ioc.iocType)) continue;
      const iocLower = (ioc.value || "").toLowerCase();
      const domainLower = domain.toLowerCase();
      if (!iocLower.includes(domainLower) && !orgCandidates.some((o) => iocLower.includes(o.toLowerCase()))) continue;
      let actorName = ioc.actorId;
      let actorType;
      try {
        const [actor] = await db.select({ name: threatActors.name, actorType: threatActors.actorType }).from(threatActors).where(eq(threatActors.actorId, ioc.actorId)).limit(1);
        if (actor) {
          actorName = actor.name;
          actorType = actor.actorType;
        }
      } catch {
      }
      matches.push({
        source: "threat_catalog_ioc",
        actorId: ioc.actorId,
        actorName,
        actorType,
        title: `IOC Match: ${ioc.iocType} indicator linked to ${actorName}`,
        description: ioc.description || `${ioc.iocType} indicator "${ioc.value}" associated with threat actor ${actorName}`,
        severity: ioc.iocConfidence === "high" ? "high" : "medium",
        iocType: ioc.iocType,
        iocValue: ioc.value,
        confidence: ioc.iocConfidence === "high" ? "confirmed" : "probable",
        relevanceScore: ioc.iocConfidence === "high" ? 0.9 : 0.6
      });
    }
  } catch (err) {
    console.error(`[IncidentSearch] IOC search failed: ${err.message}`);
  }
  const seen = /* @__PURE__ */ new Set();
  return matches.filter((m) => {
    const key = `${m.actorId || ""}:${m.eventType || ""}:${m.title}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
async function searchWebForIncidents(domain) {
  const matches = [];
  const domainParts = domain.split(".");
  const orgName = domainParts.length >= 2 ? domainParts[domainParts.length - 2] : domain;
  const orgNameCapitalized = orgName.charAt(0).toUpperCase() + orgName.slice(1);
  let trainingContextBlock = "";
  try {
    const { getIncidentSearchPromptContext } = await import("./incident-training-context-RSKNUOYG.js");
    trainingContextBlock = await getIncidentSearchPromptContext(domain);
  } catch {
  }
  try {
    const response = await invokeLLM({
      _caller: "incident-search-enrichment:searchIncidents",
      messages: [
        {
          role: "system",
          content: `You are a cybersecurity threat intelligence analyst. Search your knowledge for any known security incidents, ransomware attacks, data breaches, or threat actor activity targeting the specified organization or domain. Return ONLY factual, verified incidents \u2014 do not speculate or fabricate. If you have no knowledge of incidents, return an empty array.${trainingContextBlock ? `

${trainingContextBlock}` : ""}

Return JSON matching this schema:
{
  "incidents": [
    {
      "title": "Brief incident title",
      "description": "Detailed description including breach methodology, impact, and timeline",
      "severity": "critical|high|medium|low",
      "date": "YYYY-MM or YYYY-MM-DD if known",
      "actorName": "Threat actor name if attributed",
      "actorType": "ransomware|apt|cybercrime|hacktivist|unknown",
      "eventType": "ransomware|data_breach|attack|campaign|data_leak",
      "mitreTechniques": ["T1190", "T1078"],
      "breachMethodology": "How the breach was accomplished if known",
      "dataExposed": "What data was compromised if known",
      "confidence": "confirmed|probable|possible"
    }
  ]
}`
        },
        {
          role: "user",
          content: `Search for known security incidents, ransomware attacks, data breaches, and threat actor activity targeting:
- Organization: ${orgNameCapitalized}
- Domain: ${domain}
- Parent domain: ${domainParts.slice(-2).join(".")}

Focus on incidents from 2023-2026. Include ransomware events, data breaches, APT campaigns, and any publicly reported security incidents.`
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "incident_search",
          strict: true,
          schema: {
            type: "object",
            properties: {
              incidents: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    title: { type: "string" },
                    description: { type: "string" },
                    severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
                    date: { type: "string" },
                    actorName: { type: "string" },
                    actorType: { type: "string", enum: ["ransomware", "apt", "cybercrime", "hacktivist", "unknown"] },
                    eventType: { type: "string", enum: ["ransomware", "data_breach", "attack", "campaign", "data_leak"] },
                    mitreTechniques: { type: "array", items: { type: "string" } },
                    breachMethodology: { type: "string" },
                    dataExposed: { type: "string" },
                    confidence: { type: "string", enum: ["confirmed", "probable", "possible"] }
                  },
                  required: ["title", "description", "severity", "date", "actorName", "actorType", "eventType", "mitreTechniques", "breachMethodology", "dataExposed", "confidence"],
                  additionalProperties: false
                }
              }
            },
            required: ["incidents"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (content) {
      const parsed = JSON.parse(content);
      for (const incident of parsed.incidents || []) {
        matches.push({
          source: "web_search",
          actorName: incident.actorName || void 0,
          actorType: incident.actorType || void 0,
          eventType: incident.eventType || void 0,
          title: incident.title,
          description: `${incident.description}${incident.breachMethodology ? `

Breach Methodology: ${incident.breachMethodology}` : ""}${incident.dataExposed ? `

Data Exposed: ${incident.dataExposed}` : ""}`,
          severity: incident.severity,
          date: incident.date || void 0,
          mitreTechniques: incident.mitreTechniques || [],
          confidence: incident.confidence || "possible",
          relevanceScore: incident.confidence === "confirmed" ? 0.85 : incident.confidence === "probable" ? 0.65 : 0.4
        });
      }
    }
  } catch (err) {
    console.error(`[IncidentSearch] Web search failed: ${err.message}`);
  }
  return matches;
}
async function runIncidentSearchEnrichment(domain) {
  console.log(`[IncidentSearch] Starting incident search for ${domain}`);
  const startMs = Date.now();
  const [catalogMatches, webSearchMatches] = await Promise.all([
    searchThreatCatalog(domain),
    searchWebForIncidents(domain)
  ]);
  const allMatches = [...catalogMatches, ...webSearchMatches];
  const hasRansomwareEvent = allMatches.some(
    (m) => m.eventType === "ransomware" || m.actorType === "ransomware" || m.title.toLowerCase().includes("ransomware")
  );
  const hasRecentBreach = allMatches.some((m) => {
    if (!m.date) return false;
    const eventYear = parseInt(m.date.substring(0, 4));
    return eventYear >= 2024 && (m.eventType === "data_breach" || m.eventType === "data_leak" || m.eventType === "ransomware");
  });
  const hasActiveThreats = allMatches.some(
    (m) => m.confidence === "confirmed" && (m.severity === "critical" || m.severity === "high")
  );
  let riskFloorContribution = 0;
  if (hasRansomwareEvent) riskFloorContribution = Math.max(riskFloorContribution, 75);
  if (hasRecentBreach) riskFloorContribution = Math.max(riskFloorContribution, 65);
  if (hasActiveThreats) riskFloorContribution = Math.max(riskFloorContribution, 60);
  for (const m of allMatches) {
    if (m.confidence === "confirmed" && m.severity === "critical") {
      riskFloorContribution = Math.max(riskFloorContribution, 80);
    }
  }
  const existingActorIds = new Set(catalogMatches.map((m) => m.actorId).filter(Boolean));
  const newActorsDiscovered = webSearchMatches.filter((m) => m.actorName && !existingActorIds.has(m.actorName)).map((m) => m.actorName).filter((v, i, a) => a.indexOf(v) === i);
  const newTTPsDiscovered = webSearchMatches.flatMap((m) => m.mitreTechniques || []).filter((v, i, a) => a.indexOf(v) === i);
  const newIOCsDiscovered = [];
  const summary = generateSummary(domain, allMatches, hasRansomwareEvent, hasRecentBreach);
  const elapsed = Date.now() - startMs;
  console.log(`[IncidentSearch] Complete for ${domain}: ${allMatches.length} matches (${catalogMatches.length} catalog, ${webSearchMatches.length} web) in ${elapsed}ms`);
  return {
    domain,
    searchedAt: Date.now(),
    catalogMatches,
    webSearchMatches,
    totalMatches: allMatches.length,
    hasActiveThreats,
    hasRansomwareEvent,
    hasRecentBreach,
    riskFloorContribution,
    summary,
    newActorsDiscovered,
    newTTPsDiscovered,
    newIOCsDiscovered
  };
}
function generateSummary(domain, matches, hasRansomware, hasRecentBreach) {
  if (matches.length === 0) {
    return `No known security incidents or threat actor activity found targeting ${domain} in the threat intelligence catalog or public sources.`;
  }
  const parts = [];
  const catalogCount = matches.filter((m) => m.source !== "web_search").length;
  const webCount = matches.filter((m) => m.source === "web_search").length;
  parts.push(`${matches.length} security incident(s) identified targeting ${domain}`);
  if (catalogCount > 0) parts.push(`${catalogCount} from internal threat catalog`);
  if (webCount > 0) parts.push(`${webCount} from open-source intelligence`);
  if (hasRansomware) {
    const ransomwareMatches = matches.filter((m) => m.eventType === "ransomware" || m.actorType === "ransomware");
    const actors = ransomwareMatches.map((m) => m.actorName).filter(Boolean);
    parts.push(`RANSOMWARE EVENT CONFIRMED${actors.length > 0 ? ` \u2014 attributed to ${actors.join(", ")}` : ""}`);
  }
  if (hasRecentBreach) {
    parts.push("Recent data breach or data leak event identified");
  }
  const uniqueActors = [...new Set(matches.map((m) => m.actorName).filter(Boolean))];
  if (uniqueActors.length > 0) {
    parts.push(`Threat actors involved: ${uniqueActors.join(", ")}`);
  }
  return parts.join(". ") + ".";
}
var init_incident_search_enrichment = __esm({
  "server/lib/incident-search-enrichment.ts"() {
    init_db();
    init_schema();
    init_llm();
  }
});
init_incident_search_enrichment();
export {
  runIncidentSearchEnrichment
};
