/**
 * Domain Intelligence Threat Enrichment Module
 * 
 * Bridges the enriched threat actor catalog into the Domain Intelligence
 * scan pipeline and report generation, providing:
 * 1. Rich threat matching data (attack paths, technique heatmaps) in scan output
 * 2. Catalog-enriched actor profiles (playbooks, chains, DFIR observations)
 * 3. IOC-to-TTP reverse engineering on discovered IOCs during DI scans
 * 4. Cross-finding correlation with DFIR-learned observations
 * 5. Comprehensive threat actor section for DI reports
 */

import { sql, eq, inArray, desc } from "drizzle-orm";
import {
  exploitPlaybooks,
  attackChainsCatalog,
  dfirObservations,
  iocTtpMappings,
  threatActors,
  threatActorAbilities,
  threatActorIocs,
} from "../../drizzle/schema";

// ─── Interfaces ──────────────────────────────────────────────────────────────

export interface DIThreatEnrichment {
  /** Matched actors with full catalog profiles */
  enrichedActors: EnrichedActorProfile[];
  /** Attack paths synthesized from catalog chains */
  attackPaths: SynthesizedAttackPath[];
  /** Technique heatmap — which techniques are most likely given the target */
  techniqueHeatmap: TechniqueHeatEntry[];
  /** IOC-derived TTPs from discovered indicators */
  iocDerivedTTPs: IOCDerivedTTP[];
  /** DFIR cross-correlations — findings that match real-world incident observations */
  dfirCorrelations: DFIRCorrelation[];
  /** Risk amplifiers — factors that increase risk based on catalog intelligence */
  riskAmplifiers: RiskAmplifier[];
  /** Summary statistics */
  stats: {
    totalActorsMatched: number;
    totalPlaybooksRelevant: number;
    totalChainsRelevant: number;
    totalDFIRCorrelations: number;
    totalIOCTTPs: number;
    highestRiskActor: string;
    highestRiskScore: number;
  };
}

export interface EnrichedActorProfile {
  actorId: string;
  name: string;
  aliases: string[];
  origin: string;
  motivation: string;
  sophisticationLevel: string;
  targetSectors: string[];
  /** Relevance score to this specific target (0-100) */
  relevanceScore: number;
  /** Key TTPs this actor uses */
  keyTTPs: Array<{ techniqueId: string; techniqueName: string; tactic: string; frequency: string }>;
  /** Signature tools */
  signatureTools: string[];
  /** Known CVEs exploited */
  exploitedCVEs: string[];
  /** Relevant playbooks from catalog */
  relevantPlaybooks: Array<{
    name: string;
    vulnClass: string;
    technique: string;
    platform: string;
    confidence: string;
  }>;
  /** Relevant attack chains from catalog */
  relevantChains: Array<{
    name: string;
    objective: string;
    stepCount: number;
    phases: string[];
  }>;
  /** DFIR observations for this actor */
  dfirObservationCount: number;
  /** Phishing profile summary */
  phishingCapabilities: string[];
}

export interface SynthesizedAttackPath {
  pathName: string;
  actorName: string;
  /** Ordered steps in the attack path */
  steps: Array<{
    phase: string;
    technique: string;
    techniqueId: string;
    tool: string;
    description: string;
  }>;
  /** Likelihood based on target profile match (0-100) */
  likelihood: number;
  /** Impact if successful (0-100) */
  impact: number;
}

export interface TechniqueHeatEntry {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  /** How many matched actors use this technique */
  actorCount: number;
  /** How many catalog playbooks cover this technique */
  playbookCount: number;
  /** How many DFIR observations confirm this technique */
  dfirCount: number;
  /** Combined heat score (0-100) */
  heatScore: number;
}

export interface IOCDerivedTTP {
  iocType: string;
  iocValue: string;
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  confidence: string;
  reasoning: string;
  /** Actors known to use this technique */
  associatedActors: string[];
}

export interface DFIRCorrelation {
  /** The finding from the DI scan */
  scanFinding: string;
  /** The DFIR observation it correlates with */
  dfirObservation: string;
  /** The technique involved */
  techniqueId: string;
  techniqueName: string;
  /** Actor associated with the DFIR observation */
  actorName: string;
  /** Confidence of the correlation */
  confidence: string;
  /** What this means for the target */
  implication: string;
}

export interface RiskAmplifier {
  factor: string;
  description: string;
  amplification: number; // multiplier, e.g., 1.5 = 50% increase
  source: string;
}

// ─── Core Enrichment Function ────────────────────────────────────────────────

/**
 * Enrich DI scan results with comprehensive threat actor intelligence from the catalog.
 * Call this during or after the DI scan pipeline to add rich threat context.
 */
export async function enrichDIScanWithThreatIntel(params: {
  /** Matched actor IDs from the basic threat matching */
  matchedActorIds: string[];
  /** Target domain being scanned */
  targetDomain: string;
  /** Target industry/sector */
  targetSector?: string;
  /** Discovered technologies */
  technologies?: string[];
  /** Discovered CVEs */
  discoveredCVEs?: string[];
  /** Discovered IOCs (domains, IPs, etc.) */
  discoveredIOCs?: Array<{ type: string; value: string }>;
  /** Scan findings for DFIR correlation */
  scanFindings?: string[];
}): Promise<DIThreatEnrichment> {
  const { getDb } = await import("../db");
  const db = await getDb();
  
  const enrichment: DIThreatEnrichment = {
    enrichedActors: [],
    attackPaths: [],
    techniqueHeatmap: [],
    iocDerivedTTPs: [],
    dfirCorrelations: [],
    riskAmplifiers: [],
    stats: {
      totalActorsMatched: 0,
      totalPlaybooksRelevant: 0,
      totalChainsRelevant: 0,
      totalDFIRCorrelations: 0,
      totalIOCTTPs: 0,
      highestRiskActor: "",
      highestRiskScore: 0,
    },
  };
  
  if (!db || params.matchedActorIds.length === 0) return enrichment;
  
  try {
    // ── 1. Build enriched actor profiles ──────────────────────────────────
    for (const actorId of params.matchedActorIds.slice(0, 10)) {
      const profile = await buildEnrichedActorProfile(db, actorId, params);
      if (profile) {
        enrichment.enrichedActors.push(profile);
      }
    }
    
    enrichment.stats.totalActorsMatched = enrichment.enrichedActors.length;
    
    // ── 2. Synthesize attack paths from catalog chains ───────────────────
    const actorIds = enrichment.enrichedActors.map(a => a.actorId);
    if (actorIds.length > 0) {
      try {
        const [chainRows] = await db.execute(
          sql`SELECT ac.*, ta.name as actorName 
            FROM attack_chains_catalog ac 
            LEFT JOIN threat_actors ta ON ac.actorId = ta.actorId
            WHERE ac.actorId IN (${sql.join(actorIds.map(id => sql`${id}`), sql`,`)})
            ORDER BY ac.confidence DESC
            LIMIT 15`
        );
        
        for (const chain of (chainRows as any[])) {
          const steps = typeof chain.steps === "string" ? JSON.parse(chain.steps) : (chain.steps || []);
          
          enrichment.attackPaths.push({
            pathName: chain.chainName || "Unnamed Path",
            actorName: chain.actorName || "Unknown",
            steps: steps.map((s: any) => ({
              phase: s.tactic || s.phase || "",
              technique: s.techniqueName || "",
              techniqueId: s.techniqueId || "",
              tool: s.tool || "manual",
              description: s.description || "",
            })),
            likelihood: calculatePathLikelihood(chain, params),
            impact: calculatePathImpact(chain),
          });
        }
        
        enrichment.stats.totalChainsRelevant = enrichment.attackPaths.length;
      } catch { /* chains table may be empty */ }
    }
    
    // ── 3. Build technique heatmap ───────────────────────────────────────
    const techniqueMap = new Map<string, TechniqueHeatEntry>();
    
    for (const actor of enrichment.enrichedActors) {
      for (const ttp of actor.keyTTPs) {
        const existing = techniqueMap.get(ttp.techniqueId) || {
          techniqueId: ttp.techniqueId,
          techniqueName: ttp.techniqueName,
          tactic: ttp.tactic,
          actorCount: 0,
          playbookCount: 0,
          dfirCount: 0,
          heatScore: 0,
        };
        existing.actorCount++;
        techniqueMap.set(ttp.techniqueId, existing);
      }
    }
    
    // Count playbooks per technique
    for (const actor of enrichment.enrichedActors) {
      for (const pb of actor.relevantPlaybooks) {
        const entry = techniqueMap.get(pb.technique);
        if (entry) entry.playbookCount++;
      }
      enrichment.stats.totalPlaybooksRelevant += actor.relevantPlaybooks.length;
    }
    
    // Count DFIR observations per technique
    try {
      const [dfirRows] = await db.execute(
        sql`SELECT techniqueId, COUNT(*) as cnt FROM dfir_observations 
          WHERE actorId IN (${sql.join(actorIds.map(id => sql`${id}`), sql`,`)})
          GROUP BY techniqueId`
      );
      
      for (const row of (dfirRows as any[])) {
        const entry = techniqueMap.get(row.techniqueId);
        if (entry) entry.dfirCount = Number(row.cnt);
      }
    } catch { /* DFIR table may be empty */ }
    
    // Calculate heat scores
    for (const [, entry] of techniqueMap) {
      entry.heatScore = Math.min(100, 
        entry.actorCount * 20 + 
        entry.playbookCount * 15 + 
        entry.dfirCount * 25
      );
    }
    
    enrichment.techniqueHeatmap = [...techniqueMap.values()]
      .sort((a, b) => b.heatScore - a.heatScore)
      .slice(0, 25);
    
    // ── 4. IOC-to-TTP reverse engineering ────────────────────────────────
    if (params.discoveredIOCs && params.discoveredIOCs.length > 0) {
      try {
        const { reverseEngineerIOCs } = await import("./ioc-ttp-reverse-engineer");
        const iocResults = await reverseEngineerIOCs(params.discoveredIOCs);
        
        for (const result of iocResults) {
          for (const mapping of result.mappings) {
            enrichment.iocDerivedTTPs.push({
              iocType: result.iocType,
              iocValue: result.iocValue,
              techniqueId: mapping.techniqueId,
              techniqueName: mapping.techniqueName,
              tactic: mapping.tactic,
              confidence: mapping.confidence,
              reasoning: mapping.reasoning,
              associatedActors: enrichment.enrichedActors
                .filter(a => a.keyTTPs.some(t => t.techniqueId === mapping.techniqueId))
                .map(a => a.name),
            });
          }
        }
        
        enrichment.stats.totalIOCTTPs = enrichment.iocDerivedTTPs.length;
      } catch { /* IOC module may not be available */ }
    }
    
    // ── 5. DFIR cross-correlations ───────────────────────────────────────
    if (params.scanFindings && params.scanFindings.length > 0 && actorIds.length > 0) {
      try {
        const [dfirRows] = await db.execute(
          sql`SELECT d.*, ta.name as actorName 
            FROM dfir_observations d 
            LEFT JOIN threat_actors ta ON d.actorId = ta.actorId
            WHERE d.actorId IN (${sql.join(actorIds.map(id => sql`${id}`), sql`,`)})
            AND d.confidence IN ('high', 'medium')
            ORDER BY d.confidence DESC
            LIMIT 50`
        );
        
        for (const obs of (dfirRows as any[])) {
          // Check if any scan finding correlates with this DFIR observation
          const description = (obs.description || "").toLowerCase();
          const techniqueName = (obs.techniqueName || "").toLowerCase();
          
          for (const finding of params.scanFindings) {
            const findingLower = finding.toLowerCase();
            // Simple keyword correlation
            const keywords = techniqueName.split(/\s+/).filter((w: string) => w.length > 3);
            const matched = keywords.some((kw: string) => findingLower.includes(kw));
            
            if (matched) {
              enrichment.dfirCorrelations.push({
                scanFinding: finding,
                dfirObservation: (obs.description || "").substring(0, 200),
                techniqueId: obs.techniqueId || "",
                techniqueName: obs.techniqueName || "",
                actorName: obs.actorName || "Unknown",
                confidence: obs.confidence || "medium",
                implication: `This finding correlates with ${obs.actorName}'s known use of ${obs.techniqueName}. ` +
                  `In real incidents, this technique was observed with: ${(typeof obs.toolsObserved === "string" ? JSON.parse(obs.toolsObserved) : (obs.toolsObserved || [])).join(", ") || "various tools"}.`,
              });
            }
          }
        }
        
        enrichment.stats.totalDFIRCorrelations = enrichment.dfirCorrelations.length;
      } catch { /* DFIR table may be empty */ }
    }
    
    // ── 6. Calculate risk amplifiers ─────────────────────────────────────
    // CVE overlap with actor-exploited CVEs
    if (params.discoveredCVEs && params.discoveredCVEs.length > 0) {
      for (const actor of enrichment.enrichedActors) {
        const overlap = params.discoveredCVEs.filter(cve => actor.exploitedCVEs.includes(cve));
        if (overlap.length > 0) {
          enrichment.riskAmplifiers.push({
            factor: `CVE overlap with ${actor.name}`,
            description: `${overlap.length} discovered CVE(s) are known to be exploited by ${actor.name}: ${overlap.join(", ")}`,
            amplification: 1.0 + (overlap.length * 0.25),
            source: "threat-actor-catalog",
          });
        }
      }
    }
    
    // Technology stack match
    if (params.technologies && params.technologies.length > 0) {
      for (const actor of enrichment.enrichedActors) {
        for (const pb of actor.relevantPlaybooks) {
          if (params.technologies.some(t => pb.vulnClass.toLowerCase().includes(t.toLowerCase()))) {
            enrichment.riskAmplifiers.push({
              factor: `${actor.name} has playbooks targeting ${pb.vulnClass}`,
              description: `${actor.name} has documented exploit playbooks for ${pb.vulnClass} (${pb.confidence} confidence)`,
              amplification: 1.3,
              source: "exploit-playbook-catalog",
            });
            break; // One per actor
          }
        }
      }
    }
    
    // Highest risk actor
    if (enrichment.enrichedActors.length > 0) {
      const sorted = [...enrichment.enrichedActors].sort((a, b) => b.relevanceScore - a.relevanceScore);
      enrichment.stats.highestRiskActor = sorted[0].name;
      enrichment.stats.highestRiskScore = sorted[0].relevanceScore;
    }
    
  } catch (err: any) {
    console.error(`[DIThreatEnrich] Error enriching DI scan: ${err.message}`);
  }
  
  return enrichment;
}

// ─── Helper Functions ────────────────────────────────────────────────────────

async function buildEnrichedActorProfile(
  db: any, 
  actorId: string, 
  params: any
): Promise<EnrichedActorProfile | null> {
  try {
    const [actor] = await db.select().from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
    if (!actor) return null;
    
    const parseJSON = (val: any) => {
      if (!val) return [];
      if (typeof val === "string") try { return JSON.parse(val); } catch { return []; }
      return val;
    };
    
    // Get abilities (TTPs)
    const abilities = await db.select().from(threatActorAbilities)
      .where(eq(threatActorAbilities.actorId, actorId))
      .limit(30);
    
    // Get relevant playbooks
    let playbooks: any[] = [];
    try {
      const [pbRows] = await db.execute(
        sql`SELECT * FROM exploit_playbooks WHERE actorId = ${actorId} ORDER BY confidence DESC LIMIT 10`
      );
      playbooks = pbRows as any[];
    } catch { /* table may be empty */ }
    
    // Get relevant chains
    let chains: any[] = [];
    try {
      const [chainRows] = await db.execute(
        sql`SELECT * FROM attack_chains_catalog WHERE actorId = ${actorId} ORDER BY confidence DESC LIMIT 5`
      );
      chains = chainRows as any[];
    } catch { /* table may be empty */ }
    
    // Get DFIR observation count
    let dfirCount = 0;
    try {
      const [countRows] = await db.execute(
        sql`SELECT COUNT(*) as cnt FROM dfir_observations WHERE actorId = ${actorId}`
      );
      dfirCount = Number((countRows as any[])[0]?.cnt) || 0;
    } catch { /* table may be empty */ }
    
    // Calculate relevance score
    const targetSectors = parseJSON(actor.targetSectors);
    const exploitedCves = parseJSON(actor.exploitedCves);
    const tools = parseJSON(actor.tools);
    
    let relevanceScore = 30; // Base score for being matched
    if (params.targetSector && targetSectors.some((s: string) => 
      s.toLowerCase().includes(params.targetSector.toLowerCase()))) {
      relevanceScore += 25;
    }
    if (params.discoveredCVEs) {
      const cveOverlap = params.discoveredCVEs.filter((cve: string) => exploitedCves.includes(cve));
      relevanceScore += Math.min(25, cveOverlap.length * 10);
    }
    relevanceScore += Math.min(10, playbooks.length * 2);
    relevanceScore += Math.min(10, chains.length * 3);
    relevanceScore = Math.min(100, relevanceScore);
    
    // Build phishing capabilities
    const phishingCapabilities: string[] = [];
    const phishingAbilities = abilities.filter((a: any) => 
      (a.techniqueId || "").startsWith("T1566") || (a.techniqueId || "").startsWith("T1598")
    );
    if (phishingAbilities.length > 0) {
      phishingCapabilities.push(`${phishingAbilities.length} phishing techniques documented`);
    }
    
    return {
      actorId,
      name: actor.name,
      aliases: parseJSON(actor.aliases).slice(0, 5),
      origin: actor.origin || "Unknown",
      motivation: actor.motivation || "Unknown",
      sophisticationLevel: actor.sophisticationLevel || "Unknown",
      targetSectors: targetSectors.slice(0, 5),
      relevanceScore,
      keyTTPs: abilities.slice(0, 15).map((a: any) => ({
        techniqueId: a.techniqueId || "",
        techniqueName: a.name || "",
        tactic: a.tactic || "",
        frequency: a.frequency || "unknown",
      })),
      signatureTools: (Array.isArray(tools) ? tools.map((t: any) => typeof t === "string" ? t : t.name) : []).slice(0, 10),
      exploitedCVEs: exploitedCves.slice(0, 10),
      relevantPlaybooks: playbooks.map((pb: any) => ({
        name: pb.name || "",
        vulnClass: pb.vulnClass || "",
        technique: pb.techniqueId || "",
        platform: pb.targetPlatform || "",
        confidence: pb.confidence || "medium",
      })),
      relevantChains: chains.map((c: any) => {
        const steps = typeof c.steps === "string" ? JSON.parse(c.steps) : (c.steps || []);
        return {
          name: c.chainName || "",
          objective: c.objective || "",
          stepCount: steps.length,
          phases: [...new Set(steps.map((s: any) => s.tactic || s.phase).filter(Boolean))],
        };
      }),
      dfirObservationCount: dfirCount,
      phishingCapabilities,
    };
  } catch (err: any) {
    console.error(`[DIThreatEnrich] Error building profile for ${actorId}: ${err.message}`);
    return null;
  }
}

function calculatePathLikelihood(chain: any, params: any): number {
  let likelihood = 40; // Base
  if (chain.confidence === "high") likelihood += 20;
  else if (chain.confidence === "medium") likelihood += 10;
  // More steps = more complex = lower likelihood of full execution
  const steps = typeof chain.steps === "string" ? JSON.parse(chain.steps) : (chain.steps || []);
  likelihood -= Math.min(20, steps.length * 2);
  return Math.max(10, Math.min(90, likelihood));
}

function calculatePathImpact(chain: any): number {
  const steps = typeof chain.steps === "string" ? JSON.parse(chain.steps) : (chain.steps || []);
  const tactics = steps.map((s: any) => (s.tactic || "").toLowerCase());
  let impact = 30;
  if (tactics.includes("exfiltration")) impact += 25;
  if (tactics.includes("impact")) impact += 20;
  if (tactics.includes("privilege-escalation")) impact += 15;
  if (tactics.includes("lateral-movement")) impact += 10;
  return Math.min(100, impact);
}

// ─── Report Section Generator ────────────────────────────────────────────────

/**
 * Generate a comprehensive threat actor section for DI reports.
 * Returns formatted markdown content ready for inclusion in the report.
 */
export function generateDIReportThreatSection(enrichment: DIThreatEnrichment): string {
  const sections: string[] = [];
  
  sections.push("## Threat Actor Intelligence Analysis\n");
  
  if (enrichment.enrichedActors.length === 0) {
    sections.push("No specific threat actors were matched to this target profile.\n");
    return sections.join("\n");
  }
  
  // Summary
  sections.push(`### Summary\n`);
  sections.push(`**${enrichment.stats.totalActorsMatched}** threat actors were identified as relevant to this target, ` +
    `with **${enrichment.stats.totalPlaybooksRelevant}** documented exploit playbooks and ` +
    `**${enrichment.stats.totalChainsRelevant}** known attack chains. ` +
    `The highest-risk actor is **${enrichment.stats.highestRiskActor}** ` +
    `(relevance score: ${enrichment.stats.highestRiskScore}/100).\n`);
  
  // Actor profiles
  sections.push(`### Matched Threat Actors\n`);
  for (const actor of enrichment.enrichedActors) {
    sections.push(`#### ${actor.name} (Relevance: ${actor.relevanceScore}/100)\n`);
    sections.push(`| Attribute | Details |`);
    sections.push(`|-----------|---------|`);
    sections.push(`| **Origin** | ${actor.origin} |`);
    sections.push(`| **Motivation** | ${actor.motivation} |`);
    sections.push(`| **Sophistication** | ${actor.sophisticationLevel} |`);
    if (actor.aliases.length > 0) sections.push(`| **Aliases** | ${actor.aliases.join(", ")} |`);
    if (actor.targetSectors.length > 0) sections.push(`| **Target Sectors** | ${actor.targetSectors.join(", ")} |`);
    if (actor.signatureTools.length > 0) sections.push(`| **Signature Tools** | ${actor.signatureTools.join(", ")} |`);
    if (actor.exploitedCVEs.length > 0) sections.push(`| **Known CVEs** | ${actor.exploitedCVEs.join(", ")} |`);
    sections.push(`| **Documented Playbooks** | ${actor.relevantPlaybooks.length} |`);
    sections.push(`| **Attack Chains** | ${actor.relevantChains.length} |`);
    sections.push(`| **DFIR Observations** | ${actor.dfirObservationCount} |`);
    sections.push("");
    
    if (actor.keyTTPs.length > 0) {
      sections.push(`**Key TTPs:**\n`);
      sections.push(`| Technique | Name | Tactic |`);
      sections.push(`|-----------|------|--------|`);
      for (const ttp of actor.keyTTPs.slice(0, 10)) {
        sections.push(`| ${ttp.techniqueId} | ${ttp.techniqueName} | ${ttp.tactic} |`);
      }
      sections.push("");
    }
  }
  
  // Attack paths
  if (enrichment.attackPaths.length > 0) {
    sections.push(`### Synthesized Attack Paths\n`);
    sections.push(`These attack paths are derived from documented threat actor behavior and represent likely attack scenarios:\n`);
    
    for (const path of enrichment.attackPaths) {
      sections.push(`#### ${path.pathName} (${path.actorName})`);
      sections.push(`Likelihood: ${path.likelihood}% | Impact: ${path.impact}%\n`);
      sections.push(`| Step | Phase | Technique | Tool |`);
      sections.push(`|------|-------|-----------|------|`);
      for (let i = 0; i < path.steps.length; i++) {
        const step = path.steps[i];
        sections.push(`| ${i + 1} | ${step.phase} | ${step.techniqueId} ${step.technique} | ${step.tool} |`);
      }
      sections.push("");
    }
  }
  
  // Technique heatmap
  if (enrichment.techniqueHeatmap.length > 0) {
    sections.push(`### Technique Heatmap\n`);
    sections.push(`Techniques ranked by combined threat intelligence from actor matching, playbooks, and DFIR observations:\n`);
    sections.push(`| Technique | Name | Tactic | Actors | Playbooks | DFIR | Heat Score |`);
    sections.push(`|-----------|------|--------|--------|-----------|------|------------|`);
    for (const entry of enrichment.techniqueHeatmap.slice(0, 15)) {
      sections.push(`| ${entry.techniqueId} | ${entry.techniqueName} | ${entry.tactic} | ${entry.actorCount} | ${entry.playbookCount} | ${entry.dfirCount} | ${entry.heatScore}/100 |`);
    }
    sections.push("");
  }
  
  // DFIR correlations
  if (enrichment.dfirCorrelations.length > 0) {
    sections.push(`### DFIR Cross-Correlations\n`);
    sections.push(`The following scan findings correlate with techniques observed in real-world incident response investigations:\n`);
    for (const corr of enrichment.dfirCorrelations) {
      sections.push(`**Finding:** ${corr.scanFinding}`);
      sections.push(`**Correlates with:** ${corr.techniqueName} (${corr.techniqueId}) — ${corr.actorName}`);
      sections.push(`**Implication:** ${corr.implication}`);
      sections.push(`**Confidence:** ${corr.confidence}\n`);
    }
  }
  
  // Risk amplifiers
  if (enrichment.riskAmplifiers.length > 0) {
    sections.push(`### Risk Amplifiers\n`);
    sections.push(`| Factor | Description | Amplification |`);
    sections.push(`|--------|-------------|---------------|`);
    for (const amp of enrichment.riskAmplifiers) {
      sections.push(`| ${amp.factor} | ${amp.description} | ${((amp.amplification - 1) * 100).toFixed(0)}% increase |`);
    }
    sections.push("");
  }
  
  return sections.join("\n");
}
