/**
 * Incident Training Data Collector
 * 
 * Extracts structured training examples from completed DI scan results.
 * Each example is a (system + user + assistant) message tuple in OpenAI format
 * that teaches the LLM about domain → incident → risk relationships.
 * 
 * Training example types:
 * 1. incident_context: domain → full incident history → risk assessment
 * 2. actor_attribution: domain → threat actor → TTPs used
 * 3. breach_pattern: domain → breach details → credential exposure
 * 4. ransomware_profile: domain → ransomware event → impact
 * 5. attack_surface_map: domain → affiliated domains → expanded surface
 */

import { randomBytes } from "crypto";
import { bulkInsertDITrainingExamples } from "../db";
import type { IncidentSearchResult, IncidentMatch } from "./incident-search-enrichment";

function genId(): string {
  return `ditd_${randomBytes(12).toString("hex")}`;
}

function qualityBand(score: number): "high" | "medium" | "low" {
  if (score >= 0.75) return "high";
  if (score >= 0.4) return "medium";
  return "low";
}

// ─── Training Example Generators ────────────────────────────────────────────

function buildIncidentContextExample(
  domain: string,
  sector: string | undefined,
  incidentSearch: IncidentSearchResult,
  riskScore: number,
  riskBand: string,
): any | null {
  if (incidentSearch.totalMatches === 0) return null;

  const allMatches = [...incidentSearch.catalogMatches, ...incidentSearch.webSearchMatches];
  const matchSummaries = allMatches.slice(0, 10).map(m => {
    const parts = [`- [${m.severity.toUpperCase()}] ${m.title}`];
    if (m.actorName) parts.push(`  Actor: ${m.actorName}`);
    if (m.date) parts.push(`  Date: ${m.date}`);
    if (m.description) parts.push(`  ${m.description.slice(0, 200)}`);
    return parts.join("\n");
  }).join("\n\n");

  const quality = Math.min(1, (
    (incidentSearch.totalMatches >= 3 ? 0.3 : incidentSearch.totalMatches * 0.1) +
    (incidentSearch.hasRansomwareEvent ? 0.2 : 0) +
    (incidentSearch.hasRecentBreach ? 0.15 : 0) +
    (incidentSearch.hasActiveThreats ? 0.15 : 0) +
    (allMatches.some(m => m.confidence === "confirmed") ? 0.2 : 0)
  ));

  return {
    exampleId: genId(),
    exampleType: "incident_context" as const,
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
        content: `## Incident Intelligence Assessment for ${domain}\n\n**Risk Score:** ${riskScore}/100 (${riskBand})\n**Total Incidents Found:** ${incidentSearch.totalMatches}\n**Active Threats:** ${incidentSearch.hasActiveThreats ? "YES" : "No"}\n**Ransomware Events:** ${incidentSearch.hasRansomwareEvent ? "YES" : "No"}\n**Recent Breaches:** ${incidentSearch.hasRecentBreach ? "YES" : "No"}\n\n### Incident Details\n\n${matchSummaries}\n\n### Assessment\n\n${incidentSearch.summary}`
      }
    ],
    qualityScore: quality,
    qualityBand: qualityBand(quality),
    incidentCount: incidentSearch.totalMatches,
    actorsDiscovered: incidentSearch.newActorsDiscovered.length,
    ttpsDiscovered: incidentSearch.newTTPsDiscovered.length,
  };
}

function buildActorAttributionExamples(
  domain: string,
  sector: string | undefined,
  incidentSearch: IncidentSearchResult,
): any[] {
  const actorMatches = [...incidentSearch.catalogMatches, ...incidentSearch.webSearchMatches]
    .filter(m => m.actorName);

  // Group by actor
  const actorGroups = new Map<string, IncidentMatch[]>();
  for (const m of actorMatches) {
    const key = m.actorName!;
    if (!actorGroups.has(key)) actorGroups.set(key, []);
    actorGroups.get(key)!.push(m);
  }

  const examples: any[] = [];
  for (const [actorName, matches] of actorGroups) {
    const ttps = [...new Set(matches.flatMap(m => m.mitreTechniques || []))];
    const events = matches.map(m => `- ${m.title} (${m.severity}, ${m.date || "unknown date"}): ${m.description?.slice(0, 150) || "N/A"}`).join("\n");

    const quality = Math.min(1, (
      (matches.length >= 2 ? 0.3 : 0.15) +
      (ttps.length >= 3 ? 0.3 : ttps.length * 0.1) +
      (matches.some(m => m.confidence === "confirmed") ? 0.2 : 0.1) +
      (matches.some(m => m.severity === "critical") ? 0.2 : 0.1)
    ));

    examples.push({
      exampleId: genId(),
      exampleType: "actor_attribution" as const,
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
          content: `## Threat Actor Attribution: ${actorName} → ${domain}\n\n**Actor:** ${actorName}\n**Actor Type:** ${matches[0].actorType || "Unknown"}\n**Known Events Against Target:** ${matches.length}\n${ttps.length > 0 ? `**MITRE ATT&CK TTPs:** ${ttps.join(", ")}` : ""}\n\n### Events\n\n${events}\n\n### Attribution Confidence\n\nBased on ${matches.length} correlated event(s), the attribution confidence is ${matches[0].confidence}.`
        }
      ],
      qualityScore: quality,
      qualityBand: qualityBand(quality),
      incidentCount: matches.length,
      actorsDiscovered: 1,
      ttpsDiscovered: ttps.length,
    });
  }

  return examples;
}

function buildBreachPatternExample(
  domain: string,
  sector: string | undefined,
  incidentSearch: IncidentSearchResult,
): any | null {
  if (!incidentSearch.hasRecentBreach) return null;

  const breachMatches = [...incidentSearch.catalogMatches, ...incidentSearch.webSearchMatches]
    .filter(m => m.eventType === "data_breach" || m.eventType === "credential_leak" || m.title.toLowerCase().includes("breach"));

  if (breachMatches.length === 0) return null;

  const breachDetails = breachMatches.slice(0, 5).map(m => {
    return `- **${m.title}** (${m.severity}, ${m.date || "unknown"})\n  Source: ${m.source}\n  ${m.description?.slice(0, 200) || ""}`;
  }).join("\n\n");

  const quality = Math.min(1, (
    (breachMatches.length >= 2 ? 0.3 : 0.15) +
    (breachMatches.some(m => m.confidence === "confirmed") ? 0.3 : 0.15) +
    (breachMatches.some(m => m.severity === "critical") ? 0.2 : 0.1) +
    0.2 // breach data is inherently high-value
  ));

  return {
    exampleId: genId(),
    exampleType: "breach_pattern" as const,
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
        content: `## Breach Intelligence for ${domain}\n\n**Known Breach Events:** ${breachMatches.length}\n**Credential Exposure:** ${breachMatches.some(m => m.eventType === "credential_leak") ? "YES" : "Unknown"}\n\n### Breach Details\n\n${breachDetails}\n\n### Risk Assessment\n\nThis domain has ${breachMatches.length} known breach event(s). ${breachMatches.some(m => m.severity === "critical") ? "At least one event is rated CRITICAL severity." : ""} Organizations with prior breach history are statistically more likely to experience future incidents.`
      }
    ],
    qualityScore: quality,
    qualityBand: qualityBand(quality),
    incidentCount: breachMatches.length,
    actorsDiscovered: 0,
    ttpsDiscovered: 0,
  };
}

function buildRansomwareProfileExample(
  domain: string,
  sector: string | undefined,
  incidentSearch: IncidentSearchResult,
): any | null {
  if (!incidentSearch.hasRansomwareEvent) return null;

  const ransomwareMatches = [...incidentSearch.catalogMatches, ...incidentSearch.webSearchMatches]
    .filter(m => m.eventType === "ransomware" || m.title.toLowerCase().includes("ransomware") || m.title.toLowerCase().includes("ransom"));

  if (ransomwareMatches.length === 0) return null;

  const ransomDetails = ransomwareMatches.slice(0, 5).map(m => {
    return `- **${m.title}** (${m.severity}, ${m.date || "unknown"})\n  Actor: ${m.actorName || "Unknown"}\n  ${m.description?.slice(0, 200) || ""}`;
  }).join("\n\n");

  const actors = [...new Set(ransomwareMatches.map(m => m.actorName).filter(Boolean))];
  const ttps = [...new Set(ransomwareMatches.flatMap(m => m.mitreTechniques || []))];

  // Ransomware examples are always high-value
  const quality = Math.min(1, 0.7 + (ransomwareMatches.length >= 2 ? 0.15 : 0) + (actors.length > 0 ? 0.15 : 0));

  return {
    exampleId: genId(),
    exampleType: "ransomware_profile" as const,
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
        content: `## Ransomware Intelligence for ${domain}\n\n**Ransomware Events:** ${ransomwareMatches.length}\n**Known Actors:** ${actors.length > 0 ? actors.join(", ") : "Unknown"}\n${ttps.length > 0 ? `**TTPs Used:** ${ttps.join(", ")}` : ""}\n\n### Event Details\n\n${ransomDetails}\n\n### Risk Profile\n\nThis domain has ${ransomwareMatches.length} confirmed ransomware event(s). ${actors.length > 0 ? `Known actors include ${actors.join(", ")}.` : ""} Organizations previously targeted by ransomware face elevated risk of repeat attacks, especially within the same sector.`
      }
    ],
    qualityScore: quality,
    qualityBand: qualityBand(quality),
    incidentCount: ransomwareMatches.length,
    actorsDiscovered: actors.length,
    ttpsDiscovered: ttps.length,
  };
}

function buildAttackSurfaceExample(
  domain: string,
  sector: string | undefined,
  affiliatedDomains: any,
): any | null {
  if (!affiliatedDomains || !affiliatedDomains.affiliatedDomains || affiliatedDomains.affiliatedDomains.length === 0) return null;

  const domains = affiliatedDomains.affiliatedDomains;
  const highConf = domains.filter((d: any) => d.confidence >= 80);
  const domainList = domains.slice(0, 15).map((d: any) => 
    `- ${d.domain} (${d.relationship}, ${d.confidence}% confidence, source: ${d.source})`
  ).join("\n");

  const quality = Math.min(1, (
    (domains.length >= 5 ? 0.3 : domains.length * 0.06) +
    (highConf.length >= 3 ? 0.3 : highConf.length * 0.1) +
    (affiliatedDomains.registrantOrg ? 0.2 : 0) +
    0.2
  ));

  return {
    exampleId: genId(),
    exampleType: "attack_surface_map" as const,
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
        content: `## Attack Surface Map for ${domain}\n\n**Registrant Organization:** ${affiliatedDomains.registrantOrg || "Unknown"}\n**Total Affiliated Domains:** ${domains.length}\n**High Confidence:** ${highConf.length}\n\n### Affiliated Domains\n\n${domainList}\n\n### Assessment\n\n${affiliatedDomains.summary || `${domains.length} affiliated domains were discovered through reverse WHOIS, certificate transparency, and DNS correlation analysis.`}`
      }
    ],
    qualityScore: quality,
    qualityBand: qualityBand(quality),
    incidentCount: 0,
    actorsDiscovered: 0,
    ttpsDiscovered: 0,
  };
}

// ─── Main Collector ─────────────────────────────────────────────────────────

export interface TrainingCollectorInput {
  scanId: number;
  domain: string;
  sector?: string;
  incidentSearch: IncidentSearchResult | null;
  affiliatedDomains?: any;
  riskScore: number;
  riskBand: string;
}

export interface TrainingCollectorResult {
  totalExamples: number;
  examplesByType: Record<string, number>;
  highQualityCount: number;
}

/**
 * Extract training examples from a completed DI scan and persist them.
 * Called after the DI pipeline completes.
 */
export async function collectTrainingData(input: TrainingCollectorInput): Promise<TrainingCollectorResult> {
  const { scanId, domain, sector, incidentSearch, affiliatedDomains, riskScore, riskBand } = input;
  const examples: any[] = [];
  const typeCounts: Record<string, number> = {};

  try {
    // 1. Incident context example
    if (incidentSearch) {
      const ctx = buildIncidentContextExample(domain, sector, incidentSearch, riskScore, riskBand);
      if (ctx) {
        examples.push({ ...ctx, scanId, domain, sector });
        typeCounts.incident_context = (typeCounts.incident_context || 0) + 1;
      }

      // 2. Actor attribution examples (one per actor)
      const actorExamples = buildActorAttributionExamples(domain, sector, incidentSearch);
      for (const ae of actorExamples) {
        examples.push({ ...ae, scanId, domain, sector });
        typeCounts.actor_attribution = (typeCounts.actor_attribution || 0) + 1;
      }

      // 3. Breach pattern example
      const breach = buildBreachPatternExample(domain, sector, incidentSearch);
      if (breach) {
        examples.push({ ...breach, scanId, domain, sector });
        typeCounts.breach_pattern = (typeCounts.breach_pattern || 0) + 1;
      }

      // 4. Ransomware profile example
      const ransom = buildRansomwareProfileExample(domain, sector, incidentSearch);
      if (ransom) {
        examples.push({ ...ransom, scanId, domain, sector });
        typeCounts.ransomware_profile = (typeCounts.ransomware_profile || 0) + 1;
      }
    }

    // 5. Attack surface map example
    if (affiliatedDomains) {
      const surface = buildAttackSurfaceExample(domain, sector, affiliatedDomains);
      if (surface) {
        examples.push({ ...surface, scanId, domain, sector, riskScoreAtScan: riskScore, riskBandAtScan: riskBand });
        typeCounts.attack_surface_map = (typeCounts.attack_surface_map || 0) + 1;
      }
    }

    // Persist all examples
    if (examples.length > 0) {
      // Add risk context to all examples
      for (const ex of examples) {
        ex.riskScoreAtScan = riskScore;
        ex.riskBandAtScan = riskBand;
      }
      await bulkInsertDITrainingExamples(examples);
    }

    const highQuality = examples.filter(e => e.qualityBand === "high").length;

    return {
      totalExamples: examples.length,
      examplesByType: typeCounts,
      highQualityCount: highQuality,
    };
  } catch (err) {
    console.error("[TrainingCollector] Error collecting training data:", err);
    return { totalExamples: 0, examplesByType: {}, highQualityCount: 0 };
  }
}
