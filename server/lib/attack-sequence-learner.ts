/**
 * Attack Sequence Learner
 *
 * LLM-powered pipeline that processes ingested incident reports to:
 * 1. Extract structured attack sequences (ordered TTP chains)
 * 2. Identify threat actors and their behavioral patterns
 * 3. Map exploits to real-world usage context
 * 4. Generate Caldera adversary emulation profiles
 * 5. Build reusable attack sequence templates
 *
 * This is the "brain" that turns raw threat intel into actionable
 * red team playbooks and campaign designs.
 */

import { invokeLLM } from "../_core/llm";
import { getDb } from "../db";
import {
  incidentReports,
  attackSequenceTemplates,
  exploitIntelligence,
  threatActors,
  ttpKnowledge,
  darkwebEnrichedRecords,
  type InsertAttackSequenceTemplate,
  type InsertExploitIntelligence,
  type InsertTtpKnowledge,
} from "../../drizzle/schema";
import { eq, and, sql, isNull, inArray, desc, gt, isNotNull } from "drizzle-orm";

// ─── Helpers ─────────────────────────────────────────────────────────────

async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

function generateTemplateId(): string {
  return `ast-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

// ─── Phase 1: Extract Attack Sequences from Reports ─────────────────────

interface ExtractedAttackSequence {
  phases: {
    order: number;
    tactic: string;
    techniques: { id: string; name: string; tools: string[]; commands: string[]; description: string }[];
    duration: string;
    description: string;
  }[];
  actors: { name: string; aliases: string[]; type: string; confidence: number }[];
  malware: string[];
  exploits: { cve: string; exploitType: string; targetProduct: string; weaponized: boolean }[];
  attackType: string;
  complexity: string;
  targetEnvironment: string;
  targetSectors: string[];
  dwellTime: string;
  narrative: string;
  lessonsLearned: string;
  emulationGuidance: string;
  // Phase 1 extension: environmental assumptions extracted from DFIR evidence
  environmentalAssumptions: {
    operatingSystem: string[];           // e.g. ["Windows Server 2019", "Ubuntu 22.04"]
    networkTopology: string;             // e.g. "flat_network", "segmented", "air_gapped"
    securityControls: string[];          // e.g. ["CrowdStrike Falcon", "Palo Alto NGFW"]
    identityProvider: string;            // e.g. "Active Directory", "Azure AD", "Okta"
    cloudProvider: string;               // e.g. "AWS", "Azure", "GCP", "on-prem"
    privilegeLevel: string;              // e.g. "user", "local_admin", "domain_admin"
    patchLevel: string;                  // e.g. "current", "30_days_behind", "unpatched"
    monitoringGaps: string[];            // e.g. ["no_sysmon", "limited_dns_logging"]
    assumptions: string[];               // free-form assumptions derived from report context
  };
  // Phase 1 extension: expected telemetry signals per phase
  expectedTelemetry: {
    phase: number;
    signals: {
      source: string;                    // e.g. "Sysmon", "Windows Security", "EDR"
      eventId: string;                   // e.g. "4688", "1", "ProcessCreate"
      description: string;
      detectable: boolean;               // whether this signal is typically visible
      confidence: string;                // "high", "medium", "low"
    }[];
  }[];
}

export async function extractAttackSequence(reportId: number): Promise<ExtractedAttackSequence | null> {
  const db = await requireDb();
  const [report] = await db.select().from(incidentReports).where(eq(incidentReports.id, reportId)).limit(1);
  if (!report) return null;

  const content = report.fullContent || report.summary || "";
  if (content.length < 100) return null;

  // Truncate to fit LLM context window
  const truncatedContent = content.slice(0, 25000);

  const response = await invokeLLM({ _caller: "attack-sequence-learner.analyze",
    messages: [
      {
        role: "system",
        content: `You are an elite threat intelligence analyst and red team operator. Your task is to extract a structured attack sequence from an incident report or threat advisory.

You must identify:
1. The ordered phases of the attack (following MITRE ATT&CK kill chain)
2. Specific techniques used in each phase with their MITRE IDs (e.g., T1566.001)
3. Tools, malware, and commands used
4. Threat actors involved
5. Exploits/CVEs leveraged
6. The target environment and sectors
7. A narrative summary of the attack flow
8. Lessons learned for defenders
9. How to emulate this attack in a Caldera adversary emulation exercise
10. Environmental assumptions — infer the target OS, network topology, security controls, identity provider, cloud provider, privilege levels, patch state, and monitoring gaps from the report evidence
11. Expected telemetry — for each attack phase, list the detection signals (log sources, event IDs) that SHOULD fire if monitoring is properly configured, and whether each signal is typically detectable

Be extremely specific. Use real MITRE technique IDs. If the report doesn't contain enough detail for a field, use your expert knowledge to infer the most likely techniques based on the described behavior.

Return valid JSON matching the schema exactly.`,
      },
      {
        role: "user",
        content: `Analyze this incident report and extract the complete attack sequence:

Title: ${report.title}
Source: ${report.source}
Type: ${report.incidentType || "unknown"}
${report.cvesMentioned ? `Known CVEs: ${JSON.stringify(report.cvesMentioned)}` : ""}
${report.ttpsExtracted ? `Pre-extracted TTPs: ${JSON.stringify(report.ttpsExtracted)}` : ""}

Content:
${truncatedContent}`,
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "attack_sequence_extraction",
        strict: true,
        schema: {
          type: "object",
          properties: {
            phases: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  order: { type: "integer", description: "Phase order (1-based)" },
                  tactic: { type: "string", description: "MITRE ATT&CK tactic name (lowercase with hyphens)" },
                  techniques: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        id: { type: "string", description: "MITRE technique ID e.g. T1566.001" },
                        name: { type: "string", description: "Technique name" },
                        tools: { type: "array", items: { type: "string" }, description: "Tools used" },
                        commands: { type: "array", items: { type: "string" }, description: "Example commands" },
                        description: { type: "string", description: "How this technique was used" },
                      },
                      required: ["id", "name", "tools", "commands", "description"],
                      additionalProperties: false,
                    },
                  },
                  duration: { type: "string", description: "Estimated duration of this phase" },
                  description: { type: "string", description: "What happened in this phase" },
                },
                required: ["order", "tactic", "techniques", "duration", "description"],
                additionalProperties: false,
              },
            },
            actors: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  aliases: { type: "array", items: { type: "string" } },
                  type: { type: "string", description: "apt, cybercrime, ransomware, hacktivist, unknown" },
                  confidence: { type: "integer", description: "0-100" },
                },
                required: ["name", "aliases", "type", "confidence"],
                additionalProperties: false,
              },
            },
            malware: { type: "array", items: { type: "string" } },
            exploits: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  cve: { type: "string" },
                  exploitType: { type: "string" },
                  targetProduct: { type: "string" },
                  weaponized: { type: "boolean" },
                },
                required: ["cve", "exploitType", "targetProduct", "weaponized"],
                additionalProperties: false,
              },
            },
            attackType: { type: "string", description: "ransomware, apt_espionage, data_theft, supply_chain, etc." },
            complexity: { type: "string", description: "basic, intermediate, advanced, nation-state" },
            targetEnvironment: { type: "string", description: "windows_ad, linux_cloud, hybrid, ot_ics, etc." },
            targetSectors: { type: "array", items: { type: "string" } },
            dwellTime: { type: "string", description: "Estimated total dwell time" },
            narrative: { type: "string", description: "Narrative summary of the full attack flow (2-3 paragraphs)" },
            lessonsLearned: { type: "string", description: "Key takeaways for defenders" },
            emulationGuidance: { type: "string", description: "How to emulate this attack in Cyber C2" },
            environmentalAssumptions: {
              type: "object",
              properties: {
                operatingSystem: { type: "array", items: { type: "string" }, description: "Target OS versions inferred from report" },
                networkTopology: { type: "string", description: "flat_network, segmented, air_gapped, hybrid" },
                securityControls: { type: "array", items: { type: "string" }, description: "EDR, firewall, SIEM products mentioned or inferred" },
                identityProvider: { type: "string", description: "Active Directory, Azure AD, Okta, etc." },
                cloudProvider: { type: "string", description: "AWS, Azure, GCP, on-prem, hybrid" },
                privilegeLevel: { type: "string", description: "Starting privilege: user, local_admin, domain_admin" },
                patchLevel: { type: "string", description: "current, 30_days_behind, 90_days_behind, unpatched" },
                monitoringGaps: { type: "array", items: { type: "string" }, description: "Gaps that enabled the attack" },
                assumptions: { type: "array", items: { type: "string" }, description: "Free-form assumptions from report context" },
              },
              required: ["operatingSystem", "networkTopology", "securityControls", "identityProvider", "cloudProvider", "privilegeLevel", "patchLevel", "monitoringGaps", "assumptions"],
              additionalProperties: false,
            },
            expectedTelemetry: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  phase: { type: "integer", description: "Phase order number" },
                  signals: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        source: { type: "string", description: "Log source: Sysmon, Windows Security, EDR, etc." },
                        eventId: { type: "string", description: "Event ID or signal name" },
                        description: { type: "string", description: "What this signal indicates" },
                        detectable: { type: "boolean", description: "Whether typically visible with standard monitoring" },
                        confidence: { type: "string", description: "high, medium, low" },
                      },
                      required: ["source", "eventId", "description", "detectable", "confidence"],
                      additionalProperties: false,
                    },
                  },
                },
                required: ["phase", "signals"],
                additionalProperties: false,
              },
            },
          },
          required: [
            "phases", "actors", "malware", "exploits", "attackType",
            "complexity", "targetEnvironment", "targetSectors", "dwellTime",
            "narrative", "lessonsLearned", "emulationGuidance",
            "environmentalAssumptions", "expectedTelemetry",
          ],
          additionalProperties: false,
        },
      },
    },
  });

  try {
    const content = response.choices?.[0]?.message?.content;
    if (!content || typeof content !== "string") return null;
    const extracted = JSON.parse(content) as ExtractedAttackSequence;

    // Update the incident report with extracted data
    await db.update(incidentReports)
      .set({
        attackSequence: extracted.phases,
        ttpsExtracted: extracted.phases.flatMap(p =>
          p.techniques.map(t => ({ techniqueId: t.id, techniqueName: t.name, tactic: p.tactic, confidence: 85 }))
        ),
        actorsIdentified: extracted.actors,
        malwareIdentified: extracted.malware,
        exploitContext: extracted.exploits,
        targetSectors: extracted.targetSectors,
        attackNarrative: extracted.narrative,
        lessonsLearned: extracted.lessonsLearned,
        emulationGuidance: extracted.emulationGuidance,
        incidentType: extracted.attackType,
        status: "extracted",
      })
      .where(eq(incidentReports.id, reportId));

    return extracted;
  } catch {
    return null;
  }
}

// ─── Phase 2: Generate Attack Sequence Templates ────────────────────────

export async function generateAttackTemplate(reportId: number): Promise<InsertAttackSequenceTemplate | null> {
  const db = await requireDb();
  const [report] = await db.select().from(incidentReports).where(eq(incidentReports.id, reportId)).limit(1);
  if (!report || !report.attackSequence) return null;

  const phases = report.attackSequence as any[];
  if (!phases || phases.length === 0) return null;

  // Generate Caldera adversary profile mapping
  const response = await invokeLLM({ _caller: "attack-sequence-learner.generateAttackTemplate",
    messages: [
      {
        role: "system",
        content: `You are a Caldera adversary emulation expert. Given an attack sequence extracted from a real incident, generate:
1. A Caldera adversary profile with atomic ordering of abilities
2. Detection difficulty rating (1-10)
3. Common Sigma rules that would detect each phase
4. Evasion techniques used or recommended

You know the Caldera platform intimately — abilities, executors (psh, cmd, sh, bash), payloads, and how to chain them.
Return valid JSON.`,
      },
      {
        role: "user",
        content: `Generate a Caldera emulation profile for this attack sequence:

Attack: ${report.title}
Type: ${report.incidentType}
Actors: ${JSON.stringify(report.actorsIdentified || [])}

Phases:
${JSON.stringify(phases, null, 2)}

Emulation Guidance: ${report.emulationGuidance || "N/A"}`,
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "caldera_emulation_profile",
        strict: true,
        schema: {
          type: "object",
          properties: {
            calderaProfile: {
              type: "object",
              properties: {
                name: { type: "string" },
                description: { type: "string" },
                atomicOrdering: { type: "array", items: { type: "string" }, description: "Ordered list of technique IDs" },
                objectives: { type: "array", items: { type: "string" } },
              },
              required: ["name", "description", "atomicOrdering", "objectives"],
              additionalProperties: false,
            },
            detectionDifficulty: { type: "integer", description: "1-10 scale" },
            commonDetections: { type: "array", items: { type: "string" }, description: "Sigma rule names" },
            evasionTechniques: { type: "array", items: { type: "string" }, description: "Evasion technique IDs" },
          },
          required: ["calderaProfile", "detectionDifficulty", "commonDetections", "evasionTechniques"],
          additionalProperties: false,
        },
      },
    },
  });

  try {
    const content = response.choices?.[0]?.message?.content;
    if (!content || typeof content !== "string") return null;
    const profile = JSON.parse(content);

    const actors = (report.actorsIdentified as any[]) || [];
    const template: InsertAttackSequenceTemplate = {
      templateId: generateTemplateId(),
      name: `${report.title} — Emulation Template`,
      description: report.attackNarrative || report.summary || undefined,
      sourceIncidentIds: [reportId],
      sourceActors: actors.map((a: any) => a.name),
      phases: phases,
      totalPhases: phases.length,
      attackType: report.incidentType || undefined,
      complexity: "intermediate",
      targetEnvironment: "hybrid",
      targetSectors: (report.targetSectors as string[]) || undefined,
      calderaAdversaryProfile: profile.calderaProfile,
      detectionDifficulty: profile.detectionDifficulty,
      commonDetections: profile.commonDetections,
      evasionTechniques: profile.evasionTechniques,
      confidence: 80,
      status: "draft",
    };

    await db.insert(attackSequenceTemplates).values(template);

    // Mark report as enriched
    await db.update(incidentReports)
      .set({ status: "enriched" })
      .where(eq(incidentReports.id, reportId));

    return template;
  } catch {
    return null;
  }
}

// ─── Phase 3: Enrich Exploit Intelligence ───────────────────────────────

export async function enrichExploitsFromReport(reportId: number): Promise<number> {
  const db = await requireDb();
  const [report] = await db.select().from(incidentReports).where(eq(incidentReports.id, reportId)).limit(1);
  if (!report) return 0;

  const exploits = (report.exploitContext as any[]) || [];
  let enriched = 0;

  for (const exploit of exploits) {
    if (!exploit.cve) continue;

    // Check if we already have this CVE from this source
    const existing = await db.select({ id: exploitIntelligence.id })
      .from(exploitIntelligence)
      .where(and(
        eq(exploitIntelligence.cveId, exploit.cve),
        eq(exploitIntelligence.source, "incident_report")
      ))
      .limit(1);

    if (existing.length > 0) {
      // Update with new usage data
      await db.update(exploitIntelligence)
        .set({
          usedInIncidents: sql`JSON_ARRAY_APPEND(COALESCE(usedInIncidents, JSON_ARRAY()), '$', ${reportId})`,
          weaponized: exploit.weaponized || undefined,
        })
        .where(eq(exploitIntelligence.id, existing[0]!.id));
    } else {
      const actors = (report.actorsIdentified as any[]) || [];
      const record: InsertExploitIntelligence = {
        cveId: exploit.cve,
        exploitType: exploit.exploitType || undefined,
        targetProduct: exploit.targetProduct || undefined,
        weaponized: exploit.weaponized || false,
        usedByActors: actors.map((a: any) => a.name),
        usedInIncidents: [reportId],
        attackPhase: "initial_access",
        source: "incident_report",
        confidence: 75,
      };
      await db.insert(exploitIntelligence).values(record);
    }
    enriched++;
  }

  return enriched;
}

// ─── Phase 4: Cross-Reference with Threat Actors ────────────────────────

export async function crossReferenceActors(reportId: number): Promise<number> {
  const db = await requireDb();
  const [report] = await db.select().from(incidentReports).where(eq(incidentReports.id, reportId)).limit(1);
  if (!report) return 0;

  const actors = (report.actorsIdentified as any[]) || [];
  let linked = 0;

  for (const actor of actors) {
    if (!actor.name) continue;

    // Try to find existing actor by name or alias
    const existing = await db.select()
      .from(threatActors)
      .where(eq(threatActors.name, actor.name))
      .limit(1);

    if (existing.length > 0) {
      // Update activity timeline
      const existingActor = existing[0]!;
      const timeline = (existingActor.activityTimeline as any[]) || [];
      timeline.push({
        date: report.publishedAt || new Date().toISOString(),
        event: report.title,
        source: report.source,
        reportId,
      });
      await db.update(threatActors)
        .set({
          activityTimeline: timeline,
          lastActive: report.publishedAt || new Date().toISOString().split("T")[0],
        })
        .where(eq(threatActors.id, existingActor.id));
      linked++;
    }
    // If actor doesn't exist, we don't auto-create — that's handled by the actor sync service
  }

  return linked;
}

// ─── Phase 5: Update TTP Knowledge Base ─────────────────────────────────

export async function updateTtpKnowledgeFromReport(reportId: number): Promise<number> {
  const db = await requireDb();
  const [report] = await db.select().from(incidentReports).where(eq(incidentReports.id, reportId)).limit(1);
  if (!report) return 0;

  const ttps = (report.ttpsExtracted as any[]) || [];
  let updated = 0;

  for (const ttp of ttps) {
    if (!ttp.techniqueId) continue;

    // Check if we have this technique in the knowledge base
    const existing = await db.select()
      .from(ttpKnowledge)
      .where(eq(ttpKnowledge.techniqueId, ttp.techniqueId))
      .limit(1);

    if (existing.length > 0) {
      // The technique exists — we could update its real-world usage data
      // For now, increment confidence based on additional evidence
      const current = existing[0]!;
      const newConfidence = Math.min(100, (current.confidence || 50) + 2);
      await db.update(ttpKnowledge)
        .set({ confidence: newConfidence })
        .where(eq(ttpKnowledge.id, current.id));
      updated++;
    }
  }

  return updated;
}

// ─── Full Processing Pipeline ───────────────────────────────────────────

export interface ProcessingResult {
  reportId: number;
  title: string;
  phasesExtracted: number;
  actorsIdentified: number;
  exploitsEnriched: number;
  actorsLinked: number;
  ttpsUpdated: number;
  templateGenerated: boolean;
  error?: string;
}

export async function processReport(reportId: number): Promise<ProcessingResult> {
  const db = await requireDb();
  const [report] = await db.select().from(incidentReports).where(eq(incidentReports.id, reportId)).limit(1);
  if (!report) throw new Error(`Report ${reportId} not found`);

  const result: ProcessingResult = {
    reportId,
    title: report.title || "",
    phasesExtracted: 0,
    actorsIdentified: 0,
    exploitsEnriched: 0,
    actorsLinked: 0,
    ttpsUpdated: 0,
    templateGenerated: false,
  };

  try {
    // Step 1: Extract attack sequence
    const extracted = await extractAttackSequence(reportId);
    if (extracted) {
      result.phasesExtracted = extracted.phases.length;
      result.actorsIdentified = extracted.actors.length;

      // Step 2: Generate template
      const template = await generateAttackTemplate(reportId);
      result.templateGenerated = !!template;

      // Step 3: Enrich exploits
      result.exploitsEnriched = await enrichExploitsFromReport(reportId);

      // Step 4: Cross-reference actors
      result.actorsLinked = await crossReferenceActors(reportId);

      // Step 5: Update TTP knowledge
      result.ttpsUpdated = await updateTtpKnowledgeFromReport(reportId);

      // Step 6: Bidirectional enrichment — pull catalog/darkweb data to strengthen TTP knowledge
      try {
        const enriched = await bidirectionalEnrich(extracted);
        result.ttpsUpdated += enriched;
      } catch (e: any) {
        console.warn(`[AttackSequenceLearner] Bidirectional enrichment failed: ${e.message}`);
      }

      // Mark as training-ready
      await db.update(incidentReports)
        .set({ status: "training_ready" })
        .where(eq(incidentReports.id, reportId));
    }
  } catch (e: any) {
    result.error = e.message;
  }

  return result;
}

// ─── Batch Processing ───────────────────────────────────────────────────

export async function processBatch(limit = 5): Promise<ProcessingResult[]> {
  const db = await requireDb();

  // Get unprocessed reports (raw status), prioritizing high-value sources
  const reports = await db.select({ id: incidentReports.id, source: incidentReports.source })
    .from(incidentReports)
    .where(eq(incidentReports.irStatus, "raw"))
    .orderBy(
      sql`FIELD(source, 'dfir_report', 'cisa_advisory', 'unit42', 'misp_circl', 'hacker_news', 'dark_reading') DESC`,
      sql`ir_created_at DESC`
    )
    .limit(limit);

  const results: ProcessingResult[] = [];
  for (const report of reports) {
    try {
      const result = await processReport(report.id);
      results.push(result);
    } catch (e: any) {
      results.push({
        reportId: report.id,
        title: "",
        phasesExtracted: 0,
        actorsIdentified: 0,
        exploitsEnriched: 0,
        actorsLinked: 0,
        ttpsUpdated: 0,
        templateGenerated: false,
        error: e.message,
      });
    }
  }

  return results;
}

// ─── Statistics ─────────────────────────────────────────────────────────

export async function getLearnerStats(): Promise<{
  totalReports: number;
  byStatus: Record<string, number>;
  totalTemplates: number;
  templatesByType: Record<string, number>;
  totalExploits: number;
  weaponizedExploits: number;
  avgPhasesPerTemplate: number;
  topActors: { name: string; incidents: number }[];
  topTechniques: { id: string; count: number }[];
}> {
  const db = await requireDb();

  const [reportCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(incidentReports);
  const statusCounts = await db.select({
    status: incidentReports.status,
    count: sql<number>`COUNT(*)`,
  }).from(incidentReports).groupBy(incidentReports.status);

  const [templateCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(attackSequenceTemplates);
  const typeCounts = await db.select({
    type: attackSequenceTemplates.attackType,
    count: sql<number>`COUNT(*)`,
  }).from(attackSequenceTemplates).groupBy(attackSequenceTemplates.attackType);

  const [exploitCount] = await db.select({ count: sql<number>`COUNT(*)` }).from(exploitIntelligence);
  const [weaponizedCount] = await db.select({ count: sql<number>`COUNT(*)` })
    .from(exploitIntelligence).where(eq(exploitIntelligence.weaponized, true));

  const [avgPhases] = await db.select({
    avg: sql<number>`COALESCE(AVG(totalPhases), 0)`,
  }).from(attackSequenceTemplates);

  const byStatus: Record<string, number> = {};
  for (const s of statusCounts) {
    byStatus[s.status || "unknown"] = s.count;
  }

  const templatesByType: Record<string, number> = {};
  for (const t of typeCounts) {
    templatesByType[t.type || "unknown"] = t.count;
  }

  return {
    totalReports: reportCount?.count || 0,
    byStatus,
    totalTemplates: templateCount?.count || 0,
    templatesByType,
    totalExploits: exploitCount?.count || 0,
    weaponizedExploits: weaponizedCount?.count || 0,
    avgPhasesPerTemplate: avgPhases?.avg || 0,
    topActors: [], // Would need a more complex query across JSON fields
    topTechniques: [], // Would need JSON extraction query
  };
}

// ─── Threat Catalog Integration ──────────────────────────────────────────

/**
 * Learn from the Threat Intelligence Catalog.
 * Ingests ThreatGroupProfile techniques into ttpKnowledge with
 * environmental context derived from actor targeting patterns.
 */
export async function learnFromCatalog(options?: {
  actorTypes?: string[];
  threatLevels?: string[];
  limit?: number;
}): Promise<{
  actorsProcessed: number;
  techniquesIngested: number;
  knowledgeUpdated: number;
  errors: string[];
}> {
  const db = await requireDb();
  const result = { actorsProcessed: 0, techniquesIngested: 0, knowledgeUpdated: 0, errors: [] as string[] };

  // Query threat actors with techniques
  const conditions: any[] = [isNotNull(threatActors.techniques)];
  if (options?.actorTypes?.length) {
    conditions.push(inArray(threatActors.type, options.actorTypes as any));
  }
  if (options?.threatLevels?.length) {
    conditions.push(inArray(threatActors.threatLevel, options.threatLevels as any));
  }

  const actors = await db.select()
    .from(threatActors)
    .where(and(...conditions))
    .orderBy(desc(threatActors.confidence))
    .limit(options?.limit ?? 100);

  for (const actor of actors) {
    try {
      const techniques = (actor.techniques as any[]) || [];
      const tools = (actor.tools as string[]) || [];
      const malware = (actor.malware as string[]) || [];
      const targetSectors = (actor.targetSectors as string[]) || [];
      const targetRegions = (actor.targetRegions as string[]) || [];

      for (const tech of techniques) {
        if (!tech.id) continue;
        result.techniquesIngested++;

        // Check if TTP knowledge already exists
        const existing = await db.select()
          .from(ttpKnowledge)
          .where(eq(ttpKnowledge.techniqueId, tech.id))
          .limit(1);

        // Build environmental constraints from actor targeting patterns
        const envConstraints = {
          targetedSectors: targetSectors,
          targetedRegions: targetRegions,
          associatedActors: [{ id: actor.actorId, name: actor.name, type: actor.type, confidence: actor.confidence }],
          associatedTools: tools.filter(t => tech.description?.toLowerCase().includes(t.toLowerCase()) || true).slice(0, 10),
          associatedMalware: malware.slice(0, 10),
          sophisticationLevel: actor.sophistication || "intermediate",
          motivation: actor.motivation || "unknown",
        };

        // Build expected telemetry from actor's known IOC patterns
        const expectedTelemetry = {
          actorFingerprints: {
            tools: tools.slice(0, 5),
            malware: malware.slice(0, 5),
            actorType: actor.type,
          },
          catalogSource: true,
          catalogConfidence: actor.confidence || 50,
        };

        if (existing.length > 0) {
          // Merge environmental constraints with existing knowledge
          const existingEnv = (existing[0].environmentalConstraints as any) || {};
          const existingTelemetry = (existing[0].expectedTelemetry as any) || {};

          const mergedActors = [
            ...((existingEnv.associatedActors as any[]) || []),
            ...envConstraints.associatedActors,
          ];
          // Deduplicate actors by id
          const uniqueActors = Array.from(
            new Map(mergedActors.map(a => [a.id, a])).values()
          );

          const mergedEnv = {
            ...existingEnv,
            targetedSectors: [...new Set([...(existingEnv.targetedSectors || []), ...envConstraints.targetedSectors])],
            targetedRegions: [...new Set([...(existingEnv.targetedRegions || []), ...envConstraints.targetedRegions])],
            associatedActors: uniqueActors,
            associatedTools: [...new Set([...(existingEnv.associatedTools || []), ...envConstraints.associatedTools])],
            associatedMalware: [...new Set([...(existingEnv.associatedMalware || []), ...envConstraints.associatedMalware])],
          };

          const mergedTelemetry = {
            ...existingTelemetry,
            actorFingerprints: [
              ...((existingTelemetry.actorFingerprints as any[]) || []),
              expectedTelemetry.actorFingerprints,
            ].slice(0, 20),
            catalogSource: true,
            catalogConfidence: Math.max(existingTelemetry.catalogConfidence || 0, expectedTelemetry.catalogConfidence),
          };

          // Boost confidence if multiple sources corroborate
          const newConfidence = Math.min(100, (existing[0].confidence || 50) + 5);

          await db.update(ttpKnowledge)
            .set({
              environmentalConstraints: mergedEnv,
              expectedTelemetry: mergedTelemetry,
              confidence: newConfidence,
              dataSource: existing[0].dataSource === "llm-enriched" ? "llm+catalog" : existing[0].dataSource + "+catalog",
              updatedAt: new Date(),
            })
            .where(eq(ttpKnowledge.techniqueId, tech.id));
          result.knowledgeUpdated++;
        } else {
          // Create new TTP knowledge entry from catalog data
          await db.insert(ttpKnowledge).values({
            techniqueId: tech.id,
            techniqueName: tech.name || tech.id,
            tactic: tech.tactic || "unknown",
            description: tech.description || `${tech.name} — sourced from threat catalog (${actor.name})`,
            executionMethods: [],
            toolsUsed: tools.map(t => ({ name: t, type: "offensive" as const, description: "", commonActors: [actor.name] })),
            iocPatterns: [],
            artifacts: [],
            detectionRules: [],
            eventLogSources: [],
            calderaAbilities: [],
            attackChainPosition: tech.tactic || "unknown",
            prerequisiteTechniques: [],
            followUpTechniques: [],
            defensiveGaps: [],
            redTeamValue: tech.score || 5,
            blueTeamPriority: 5,
            purpleTeamNotes: `Sourced from threat catalog: ${actor.name} (${actor.type})`,
            environmentalConstraints: envConstraints,
            expectedTelemetry: expectedTelemetry,
            dataSource: "catalog",
            confidence: Math.min(actor.confidence || 50, 70), // Cap at 70 since catalog-only lacks deep analysis
            lastEnriched: new Date(),
          } as any);
          result.knowledgeUpdated++;
        }
      }
      result.actorsProcessed++;
    } catch (e: any) {
      result.errors.push(`Actor ${actor.actorId}: ${e.message}`);
    }
  }

  console.log(`[AttackSequenceLearner] Catalog ingestion: ${result.actorsProcessed} actors, ${result.techniquesIngested} techniques, ${result.knowledgeUpdated} knowledge entries updated`);
  return result;
}

// ─── Darkweb Intelligence Integration ────────────────────────────────────

/**
 * Learn from Darkweb Enriched Records.
 * Extracts TTPs from LLM-enriched darkweb events and correlates
 * with existing TTP knowledge for real-world validation.
 */
export async function learnFromDarkweb(options?: {
  minRiskScore?: number;
  sinceDays?: number;
  limit?: number;
}): Promise<{
  recordsProcessed: number;
  techniquesExtracted: number;
  knowledgeUpdated: number;
  iocsCrossReferenced: number;
  errors: string[];
}> {
  const db = await requireDb();
  const result = {
    recordsProcessed: 0,
    techniquesExtracted: 0,
    knowledgeUpdated: 0,
    iocsCrossReferenced: 0,
    errors: [] as string[],
  };

  const minScore = options?.minRiskScore ?? 30;
  const sinceDays = options?.sinceDays ?? 90;
  const cutoff = new Date(Date.now() - sinceDays * 86400000);

  // Query darkweb enriched records with MITRE techniques
  const records = await db.select()
    .from(darkwebEnrichedRecords)
    .where(
      and(
        isNotNull(darkwebEnrichedRecords.mitreTechniques),
        gt(darkwebEnrichedRecords.riskScore, minScore),
        gt(darkwebEnrichedRecords.createdAt, cutoff),
      )
    )
    .orderBy(desc(darkwebEnrichedRecords.riskScore))
    .limit(options?.limit ?? 200);

  for (const record of records) {
    try {
      const techniques = (record.mitreTechniques as string[]) || [];
      const tactics = (record.mitreTactics as string[]) || [];
      const relatedActors = (record.relatedActors as string[]) || [];
      const relatedCves = (record.relatedCves as string[]) || [];
      const relatedIocs = (record.relatedIocs as any[]) || [];
      const affectedSectors = (record.affectedSectors as string[]) || [];
      const affectedCountries = (record.affectedCountries as string[]) || [];

      for (const techId of techniques) {
        if (!techId || !techId.startsWith("T")) continue;
        result.techniquesExtracted++;

        const existing = await db.select()
          .from(ttpKnowledge)
          .where(eq(ttpKnowledge.techniqueId, techId))
          .limit(1);

        // Build darkweb-sourced environmental context
        const darkwebContext = {
          source: "darkweb",
          riskScore: record.riskScore,
          threatAssessment: record.threatAssessment?.substring(0, 500),
          relatedActors,
          relatedCves,
          affectedSectors,
          affectedCountries,
          observedAt: record.createdAt?.toISOString(),
        };

        // Build expected telemetry from darkweb IOCs
        const darkwebTelemetry = {
          darkwebIocs: relatedIocs.slice(0, 20),
          darkwebCves: relatedCves,
          darkwebValidated: true,
          darkwebRiskScore: record.riskScore,
          darkwebObservedAt: record.createdAt?.toISOString(),
        };

        if (existing.length > 0) {
          const existingEnv = (existing[0].environmentalConstraints as any) || {};
          const existingTelemetry = (existing[0].expectedTelemetry as any) || {};

          // Merge darkweb context into environmental constraints
          const darkwebSources = [...((existingEnv.darkwebSources as any[]) || []), darkwebContext];
          // Keep last 10 darkweb sources
          const mergedEnv = {
            ...existingEnv,
            darkwebSources: darkwebSources.slice(-10),
            darkwebValidated: true,
            lastDarkwebSighting: record.createdAt?.toISOString(),
            targetedSectors: [...new Set([...(existingEnv.targetedSectors || []), ...affectedSectors])],
            targetedRegions: [...new Set([...(existingEnv.targetedRegions || []), ...affectedCountries])],
          };

          // Merge IOCs into expected telemetry
          const existingIocs = (existingTelemetry.darkwebIocs as any[]) || [];
          const allIocs = [...existingIocs, ...relatedIocs];
          // Deduplicate IOCs by value
          const uniqueIocs = Array.from(
            new Map(allIocs.map((ioc: any) => [ioc.value || JSON.stringify(ioc), ioc])).values()
          ).slice(0, 50);

          const mergedTelemetry = {
            ...existingTelemetry,
            darkwebIocs: uniqueIocs,
            darkwebCves: [...new Set([...(existingTelemetry.darkwebCves || []), ...relatedCves])],
            darkwebValidated: true,
            darkwebRiskScore: Math.max(existingTelemetry.darkwebRiskScore || 0, record.riskScore || 0),
            lastDarkwebObserved: record.createdAt?.toISOString(),
          };

          // Boost confidence for darkweb-validated techniques
          const newConfidence = Math.min(100, (existing[0].confidence || 50) + 3);

          await db.update(ttpKnowledge)
            .set({
              environmentalConstraints: mergedEnv,
              expectedTelemetry: mergedTelemetry,
              confidence: newConfidence,
              dataSource: existing[0].dataSource?.includes("darkweb")
                ? existing[0].dataSource
                : (existing[0].dataSource || "unknown") + "+darkweb",
              updatedAt: new Date(),
            })
            .where(eq(ttpKnowledge.techniqueId, techId));
          result.knowledgeUpdated++;
          result.iocsCrossReferenced += relatedIocs.length;
        } else {
          // Create new TTP knowledge entry from darkweb data
          const tactic = tactics[0] || "unknown";
          await db.insert(ttpKnowledge).values({
            techniqueId: techId,
            techniqueName: techId, // Will be enriched later by ttp-engine
            tactic,
            description: `Observed in darkweb intelligence. ${record.summary?.substring(0, 300) || ""}`,
            executionMethods: [],
            toolsUsed: [],
            iocPatterns: relatedIocs.map((ioc: any) => ({
              type: ioc.type || "unknown",
              pattern: ioc.value || "",
              description: "Sourced from darkweb intelligence",
              confidence: "medium" as const,
              volatility: "medium" as const,
            })),
            artifacts: [],
            detectionRules: [],
            eventLogSources: [],
            calderaAbilities: [],
            attackChainPosition: tactic,
            prerequisiteTechniques: [],
            followUpTechniques: [],
            defensiveGaps: [],
            redTeamValue: Math.round((record.riskScore || 50) / 10),
            blueTeamPriority: Math.round((record.riskScore || 50) / 10),
            purpleTeamNotes: `Sourced from darkweb intelligence (risk score: ${record.riskScore})`,
            environmentalConstraints: {
              darkwebSources: [darkwebContext],
              darkwebValidated: true,
              lastDarkwebSighting: record.createdAt?.toISOString(),
              targetedSectors: affectedSectors,
              targetedRegions: affectedCountries,
            },
            expectedTelemetry: darkwebTelemetry,
            dataSource: "darkweb",
            confidence: Math.min(record.riskScore || 40, 60), // Cap at 60 since darkweb-only lacks verification
            lastEnriched: new Date(),
          } as any);
          result.knowledgeUpdated++;
          result.iocsCrossReferenced += relatedIocs.length;
        }
      }
      result.recordsProcessed++;
    } catch (e: any) {
      result.errors.push(`Record ${record.id}: ${e.message}`);
    }
  }

  console.log(`[AttackSequenceLearner] Darkweb ingestion: ${result.recordsProcessed} records, ${result.techniquesExtracted} techniques, ${result.knowledgeUpdated} knowledge entries, ${result.iocsCrossReferenced} IOCs cross-referenced`);
  return result;
}

// ─── Bidirectional Enrichment ────────────────────────────────────────────

/**
 * After processing a DFIR report, pull matching catalog/darkweb data
 * to strengthen the confidence and fill gaps in TTP knowledge.
 * Also feeds environmental assumptions from DFIR back into the catalog.
 */
async function bidirectionalEnrich(extracted: ExtractedAttackSequence): Promise<number> {
  const db = await requireDb();
  let updated = 0;

  // Collect all technique IDs from the extracted sequence
  const techniqueIds = new Set<string>();
  for (const phase of extracted.phases) {
    for (const tech of phase.techniques) {
      if (tech.id) techniqueIds.add(tech.id);
    }
  }
  if (techniqueIds.size === 0) return 0;

  const techArray = Array.from(techniqueIds);

  // 1. Pull matching threat actors from catalog that use these techniques
  const matchingActors = await db.select({
    actorId: threatActors.actorId,
    name: threatActors.name,
    type: threatActors.type,
    techniques: threatActors.techniques,
    tools: threatActors.tools,
    malware: threatActors.malware,
    targetSectors: threatActors.targetSectors,
    confidence: threatActors.confidence,
  })
    .from(threatActors)
    .where(isNotNull(threatActors.techniques))
    .limit(200);

  // Find actors whose techniques overlap with the extracted report
  const overlappingActors = matchingActors.filter(actor => {
    const actorTechs = (actor.techniques as any[]) || [];
    return actorTechs.some(t => techniqueIds.has(t.id));
  });

  // 2. Pull matching darkweb records that reference these techniques
  const matchingDarkweb = await db.select()
    .from(darkwebEnrichedRecords)
    .where(isNotNull(darkwebEnrichedRecords.mitreTechniques))
    .orderBy(desc(darkwebEnrichedRecords.riskScore))
    .limit(100);

  const overlappingDarkweb = matchingDarkweb.filter(record => {
    const techs = (record.mitreTechniques as string[]) || [];
    return techs.some(t => techniqueIds.has(t));
  });

  // 3. For each technique in the report, enrich with catalog + darkweb data
  for (const techId of techArray) {
    const existing = await db.select()
      .from(ttpKnowledge)
      .where(eq(ttpKnowledge.techniqueId, techId))
      .limit(1);

    if (existing.length === 0) continue;

    const entry = existing[0];
    const existingEnv = (entry.environmentalConstraints as any) || {};
    const existingTelemetry = (entry.expectedTelemetry as any) || {};

    // Enrich from catalog actors
    const actorsForTech = overlappingActors.filter(a =>
      ((a.techniques as any[]) || []).some(t => t.id === techId)
    );

    let envUpdates: any = { ...existingEnv };
    let telemetryUpdates: any = { ...existingTelemetry };
    let confidenceBoost = 0;
    let sourceAdditions: string[] = [];

    if (actorsForTech.length > 0) {
      const catalogActors = actorsForTech.map(a => ({
        id: a.actorId, name: a.name, type: a.type, confidence: a.confidence,
      }));
      const existingActors = (envUpdates.associatedActors as any[]) || [];
      const allActors = [...existingActors, ...catalogActors];
      envUpdates.associatedActors = Array.from(
        new Map(allActors.map(a => [a.id, a])).values()
      );

      const allTools = actorsForTech.flatMap(a => (a.tools as string[]) || []);
      envUpdates.associatedTools = [...new Set([...(envUpdates.associatedTools || []), ...allTools])];

      const allSectors = actorsForTech.flatMap(a => (a.targetSectors as string[]) || []);
      envUpdates.targetedSectors = [...new Set([...(envUpdates.targetedSectors || []), ...allSectors])];

      confidenceBoost += Math.min(actorsForTech.length * 2, 10);
      sourceAdditions.push("catalog");
    }

    // Enrich from darkweb records
    const darkwebForTech = overlappingDarkweb.filter(r =>
      ((r.mitreTechniques as string[]) || []).includes(techId)
    );

    if (darkwebForTech.length > 0) {
      envUpdates.darkwebValidated = true;
      envUpdates.lastDarkwebSighting = darkwebForTech[0].createdAt?.toISOString();

      const darkwebIocs = darkwebForTech.flatMap(r => (r.relatedIocs as any[]) || []);
      const existingIocs = (telemetryUpdates.darkwebIocs as any[]) || [];
      const allIocs = [...existingIocs, ...darkwebIocs];
      telemetryUpdates.darkwebIocs = Array.from(
        new Map(allIocs.map((ioc: any) => [ioc.value || JSON.stringify(ioc), ioc])).values()
      ).slice(0, 50);

      const darkwebCves = darkwebForTech.flatMap(r => (r.relatedCves as string[]) || []);
      telemetryUpdates.darkwebCves = [...new Set([...(telemetryUpdates.darkwebCves || []), ...darkwebCves])];
      telemetryUpdates.darkwebValidated = true;

      confidenceBoost += Math.min(darkwebForTech.length * 2, 8);
      sourceAdditions.push("darkweb");
    }

    // Enrich from DFIR environmental assumptions
    if (extracted.environmentalAssumptions) {
      const assumptions = extracted.environmentalAssumptions;
      envUpdates.dfirAssumptions = {
        ...(envUpdates.dfirAssumptions || {}),
        operatingSystem: [...new Set([...(envUpdates.dfirAssumptions?.operatingSystem || []), ...(assumptions.operatingSystem || [])])],
        networkTopology: assumptions.networkTopology || envUpdates.dfirAssumptions?.networkTopology,
        securityControls: [...new Set([...(envUpdates.dfirAssumptions?.securityControls || []), ...(assumptions.securityControls || [])])],
        privilegeLevel: assumptions.privilegeLevel || envUpdates.dfirAssumptions?.privilegeLevel,
        assumptions: [...new Set([...(envUpdates.dfirAssumptions?.assumptions || []), ...(assumptions.assumptions || [])])],
      };
    }

    // Enrich from DFIR expected telemetry
    if (extracted.expectedTelemetry) {
      telemetryUpdates.dfirTelemetry = extracted.expectedTelemetry;
    }

    if (confidenceBoost > 0 || sourceAdditions.length > 0) {
      const newConfidence = Math.min(100, (entry.confidence || 50) + confidenceBoost);
      let newSource = entry.dataSource || "unknown";
      for (const src of sourceAdditions) {
        if (!newSource.includes(src)) {
          newSource += `+${src}`;
        }
      }

      await db.update(ttpKnowledge)
        .set({
          environmentalConstraints: envUpdates,
          expectedTelemetry: telemetryUpdates,
          confidence: newConfidence,
          dataSource: newSource,
          updatedAt: new Date(),
        })
        .where(eq(ttpKnowledge.techniqueId, techId));
      updated++;
    }
  }

  console.log(`[AttackSequenceLearner] Bidirectional enrichment: ${updated} TTP entries updated from ${overlappingActors.length} catalog actors and ${overlappingDarkweb.length} darkweb records`);
  return updated;
}
