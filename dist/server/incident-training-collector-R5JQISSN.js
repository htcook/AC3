import {
  bulkInsertDITrainingExamples,
  init_db
} from "./chunk-AX6SVAQZ.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-DQZ564DJ.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/incident-training-collector.ts
import { randomBytes } from "crypto";
function genId() {
  return `ditd_${randomBytes(12).toString("hex")}`;
}
function qualityBand(score) {
  if (score >= 0.75) return "high";
  if (score >= 0.4) return "medium";
  return "low";
}
function buildIncidentContextExample(domain, sector, incidentSearch, riskScore, riskBand) {
  if (incidentSearch.totalMatches === 0) return null;
  const allMatches = [...incidentSearch.catalogMatches, ...incidentSearch.webSearchMatches];
  const matchSummaries = allMatches.slice(0, 10).map((m) => {
    const parts = [`- [${m.severity.toUpperCase()}] ${m.title}`];
    if (m.actorName) parts.push(`  Actor: ${m.actorName}`);
    if (m.date) parts.push(`  Date: ${m.date}`);
    if (m.description) parts.push(`  ${m.description.slice(0, 200)}`);
    return parts.join("\n");
  }).join("\n\n");
  const quality = Math.min(1, (incidentSearch.totalMatches >= 3 ? 0.3 : incidentSearch.totalMatches * 0.1) + (incidentSearch.hasRansomwareEvent ? 0.2 : 0) + (incidentSearch.hasRecentBreach ? 0.15 : 0) + (incidentSearch.hasActiveThreats ? 0.15 : 0) + (allMatches.some((m) => m.confidence === "confirmed") ? 0.2 : 0));
  return {
    exampleId: genId(),
    exampleType: "incident_context",
    trainingMessages: [
      {
        role: "system",
        content: "You are a threat intelligence analyst. Given a target domain, analyze its incident history and provide a risk assessment based on known incidents, threat actor activity, and breach exposure."
      },
      {
        role: "user",
        content: `Analyze the incident history for domain: ${domain}${sector ? ` (Sector: ${sector})` : ""}. What incidents, threat actors, and breach events are associated with this target?`
      },
      {
        role: "assistant",
        content: `## Incident Intelligence Assessment for ${domain}

**Risk Score:** ${riskScore}/100 (${riskBand})
**Total Incidents Found:** ${incidentSearch.totalMatches}
**Active Threats:** ${incidentSearch.hasActiveThreats ? "YES" : "No"}
**Ransomware Events:** ${incidentSearch.hasRansomwareEvent ? "YES" : "No"}
**Recent Breaches:** ${incidentSearch.hasRecentBreach ? "YES" : "No"}

### Incident Details

${matchSummaries}

### Assessment

${incidentSearch.summary}`
      }
    ],
    qualityScore: quality,
    qualityBand: qualityBand(quality),
    incidentCount: incidentSearch.totalMatches,
    actorsDiscovered: incidentSearch.newActorsDiscovered.length,
    ttpsDiscovered: incidentSearch.newTTPsDiscovered.length
  };
}
function buildActorAttributionExamples(domain, sector, incidentSearch) {
  const actorMatches = [...incidentSearch.catalogMatches, ...incidentSearch.webSearchMatches].filter((m) => m.actorName);
  const actorGroups = /* @__PURE__ */ new Map();
  for (const m of actorMatches) {
    const key = m.actorName;
    if (!actorGroups.has(key)) actorGroups.set(key, []);
    actorGroups.get(key).push(m);
  }
  const examples = [];
  for (const [actorName, matches] of actorGroups) {
    const ttps = [...new Set(matches.flatMap((m) => m.mitreTechniques || []))];
    const events = matches.map((m) => `- ${m.title} (${m.severity}, ${m.date || "unknown date"}): ${m.description?.slice(0, 150) || "N/A"}`).join("\n");
    const quality = Math.min(1, (matches.length >= 2 ? 0.3 : 0.15) + (ttps.length >= 3 ? 0.3 : ttps.length * 0.1) + (matches.some((m) => m.confidence === "confirmed") ? 0.2 : 0.1) + (matches.some((m) => m.severity === "critical") ? 0.2 : 0.1));
    examples.push({
      exampleId: genId(),
      exampleType: "actor_attribution",
      trainingMessages: [
        {
          role: "system",
          content: "You are a threat intelligence analyst specializing in threat actor attribution. Given a domain and threat actor, describe the actor's known operations against the target, including TTPs, campaigns, and impact."
        },
        {
          role: "user",
          content: `What is the relationship between threat actor "${actorName}" and the domain ${domain}${sector ? ` (${sector} sector)` : ""}?`
        },
        {
          role: "assistant",
          content: `## Threat Actor Attribution: ${actorName} \u2192 ${domain}

**Actor:** ${actorName}
**Actor Type:** ${matches[0].actorType || "Unknown"}
**Known Events Against Target:** ${matches.length}
${ttps.length > 0 ? `**MITRE ATT&CK TTPs:** ${ttps.join(", ")}` : ""}

### Events

${events}

### Attribution Confidence

Based on ${matches.length} correlated event(s), the attribution confidence is ${matches[0].confidence}.`
        }
      ],
      qualityScore: quality,
      qualityBand: qualityBand(quality),
      incidentCount: matches.length,
      actorsDiscovered: 1,
      ttpsDiscovered: ttps.length
    });
  }
  return examples;
}
function buildBreachPatternExample(domain, sector, incidentSearch) {
  if (!incidentSearch.hasRecentBreach) return null;
  const breachMatches = [...incidentSearch.catalogMatches, ...incidentSearch.webSearchMatches].filter((m) => m.eventType === "data_breach" || m.eventType === "credential_leak" || m.title.toLowerCase().includes("breach"));
  if (breachMatches.length === 0) return null;
  const breachDetails = breachMatches.slice(0, 5).map((m) => {
    return `- **${m.title}** (${m.severity}, ${m.date || "unknown"})
  Source: ${m.source}
  ${m.description?.slice(0, 200) || ""}`;
  }).join("\n\n");
  const quality = Math.min(1, (breachMatches.length >= 2 ? 0.3 : 0.15) + (breachMatches.some((m) => m.confidence === "confirmed") ? 0.3 : 0.15) + (breachMatches.some((m) => m.severity === "critical") ? 0.2 : 0.1) + 0.2);
  return {
    exampleId: genId(),
    exampleType: "breach_pattern",
    trainingMessages: [
      {
        role: "system",
        content: "You are a breach intelligence analyst. Given a target domain, analyze known breach events, credential exposures, and data leak patterns to assess the organization's breach exposure risk."
      },
      {
        role: "user",
        content: `What breach events and credential exposures are known for ${domain}${sector ? ` (${sector} sector)` : ""}?`
      },
      {
        role: "assistant",
        content: `## Breach Intelligence for ${domain}

**Known Breach Events:** ${breachMatches.length}
**Credential Exposure:** ${breachMatches.some((m) => m.eventType === "credential_leak") ? "YES" : "Unknown"}

### Breach Details

${breachDetails}

### Risk Assessment

This domain has ${breachMatches.length} known breach event(s). ${breachMatches.some((m) => m.severity === "critical") ? "At least one event is rated CRITICAL severity." : ""} Organizations with prior breach history are statistically more likely to experience future incidents.`
      }
    ],
    qualityScore: quality,
    qualityBand: qualityBand(quality),
    incidentCount: breachMatches.length,
    actorsDiscovered: 0,
    ttpsDiscovered: 0
  };
}
function buildRansomwareProfileExample(domain, sector, incidentSearch) {
  if (!incidentSearch.hasRansomwareEvent) return null;
  const ransomwareMatches = [...incidentSearch.catalogMatches, ...incidentSearch.webSearchMatches].filter((m) => m.eventType === "ransomware" || m.title.toLowerCase().includes("ransomware") || m.title.toLowerCase().includes("ransom"));
  if (ransomwareMatches.length === 0) return null;
  const ransomDetails = ransomwareMatches.slice(0, 5).map((m) => {
    return `- **${m.title}** (${m.severity}, ${m.date || "unknown"})
  Actor: ${m.actorName || "Unknown"}
  ${m.description?.slice(0, 200) || ""}`;
  }).join("\n\n");
  const actors = [...new Set(ransomwareMatches.map((m) => m.actorName).filter(Boolean))];
  const ttps = [...new Set(ransomwareMatches.flatMap((m) => m.mitreTechniques || []))];
  const quality = Math.min(1, 0.7 + (ransomwareMatches.length >= 2 ? 0.15 : 0) + (actors.length > 0 ? 0.15 : 0));
  return {
    exampleId: genId(),
    exampleType: "ransomware_profile",
    trainingMessages: [
      {
        role: "system",
        content: "You are a ransomware intelligence analyst. Given a target domain, analyze known ransomware events, identify the threat actors involved, and assess the organization's ransomware risk profile."
      },
      {
        role: "user",
        content: `Has ${domain}${sector ? ` (${sector} sector)` : ""} been targeted by ransomware? What are the details?`
      },
      {
        role: "assistant",
        content: `## Ransomware Intelligence for ${domain}

**Ransomware Events:** ${ransomwareMatches.length}
**Known Actors:** ${actors.length > 0 ? actors.join(", ") : "Unknown"}
${ttps.length > 0 ? `**TTPs Used:** ${ttps.join(", ")}` : ""}

### Event Details

${ransomDetails}

### Risk Profile

This domain has ${ransomwareMatches.length} confirmed ransomware event(s). ${actors.length > 0 ? `Known actors include ${actors.join(", ")}.` : ""} Organizations previously targeted by ransomware face elevated risk of repeat attacks, especially within the same sector.`
      }
    ],
    qualityScore: quality,
    qualityBand: qualityBand(quality),
    incidentCount: ransomwareMatches.length,
    actorsDiscovered: actors.length,
    ttpsDiscovered: ttps.length
  };
}
function buildAttackSurfaceExample(domain, sector, affiliatedDomains) {
  if (!affiliatedDomains || !affiliatedDomains.affiliatedDomains || affiliatedDomains.affiliatedDomains.length === 0) return null;
  const domains = affiliatedDomains.affiliatedDomains;
  const highConf = domains.filter((d) => d.confidence >= 80);
  const domainList = domains.slice(0, 15).map(
    (d) => `- ${d.domain} (${d.relationship}, ${d.confidence}% confidence, source: ${d.source})`
  ).join("\n");
  const quality = Math.min(1, (domains.length >= 5 ? 0.3 : domains.length * 0.06) + (highConf.length >= 3 ? 0.3 : highConf.length * 0.1) + (affiliatedDomains.registrantOrg ? 0.2 : 0) + 0.2);
  return {
    exampleId: genId(),
    exampleType: "attack_surface_map",
    trainingMessages: [
      {
        role: "system",
        content: "You are an attack surface analyst. Given a target domain, identify affiliated domains owned by the same organization through reverse WHOIS, certificate transparency, DNS correlation, and intelligence knowledge."
      },
      {
        role: "user",
        content: `What domains are affiliated with ${domain}${sector ? ` (${sector} sector)` : ""}? Map the organization's full attack surface.`
      },
      {
        role: "assistant",
        content: `## Attack Surface Map for ${domain}

**Registrant Organization:** ${affiliatedDomains.registrantOrg || "Unknown"}
**Total Affiliated Domains:** ${domains.length}
**High Confidence:** ${highConf.length}

### Affiliated Domains

${domainList}

### Assessment

${affiliatedDomains.summary || `${domains.length} affiliated domains were discovered through reverse WHOIS, certificate transparency, and DNS correlation analysis.`}`
      }
    ],
    qualityScore: quality,
    qualityBand: qualityBand(quality),
    incidentCount: 0,
    actorsDiscovered: 0,
    ttpsDiscovered: 0
  };
}
async function collectTrainingData(input) {
  const { scanId, domain, sector, incidentSearch, affiliatedDomains, riskScore, riskBand } = input;
  const examples = [];
  const typeCounts = {};
  try {
    if (incidentSearch) {
      const ctx = buildIncidentContextExample(domain, sector, incidentSearch, riskScore, riskBand);
      if (ctx) {
        examples.push({ ...ctx, scanId, domain, sector });
        typeCounts.incident_context = (typeCounts.incident_context || 0) + 1;
      }
      const actorExamples = buildActorAttributionExamples(domain, sector, incidentSearch);
      for (const ae of actorExamples) {
        examples.push({ ...ae, scanId, domain, sector });
        typeCounts.actor_attribution = (typeCounts.actor_attribution || 0) + 1;
      }
      const breach = buildBreachPatternExample(domain, sector, incidentSearch);
      if (breach) {
        examples.push({ ...breach, scanId, domain, sector });
        typeCounts.breach_pattern = (typeCounts.breach_pattern || 0) + 1;
      }
      const ransom = buildRansomwareProfileExample(domain, sector, incidentSearch);
      if (ransom) {
        examples.push({ ...ransom, scanId, domain, sector });
        typeCounts.ransomware_profile = (typeCounts.ransomware_profile || 0) + 1;
      }
    }
    if (affiliatedDomains) {
      const surface = buildAttackSurfaceExample(domain, sector, affiliatedDomains);
      if (surface) {
        examples.push({ ...surface, scanId, domain, sector, riskScoreAtScan: riskScore, riskBandAtScan: riskBand });
        typeCounts.attack_surface_map = (typeCounts.attack_surface_map || 0) + 1;
      }
    }
    if (examples.length > 0) {
      for (const ex of examples) {
        ex.riskScoreAtScan = riskScore;
        ex.riskBandAtScan = riskBand;
      }
      await bulkInsertDITrainingExamples(examples);
    }
    const highQuality = examples.filter((e) => e.qualityBand === "high").length;
    return {
      totalExamples: examples.length,
      examplesByType: typeCounts,
      highQualityCount: highQuality
    };
  } catch (err) {
    console.error("[TrainingCollector] Error collecting training data:", err);
    return { totalExamples: 0, examplesByType: {}, highQualityCount: 0 };
  }
}
var init_incident_training_collector = __esm({
  "server/lib/incident-training-collector.ts"() {
    init_db();
  }
});
init_incident_training_collector();
export {
  collectTrainingData
};
