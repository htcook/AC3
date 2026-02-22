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
  type InsertAttackSequenceTemplate,
  type InsertExploitIntelligence,
} from "../../drizzle/schema";
import { eq, and, sql, isNull, inArray } from "drizzle-orm";

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
}

export async function extractAttackSequence(reportId: number): Promise<ExtractedAttackSequence | null> {
  const db = await requireDb();
  const [report] = await db.select().from(incidentReports).where(eq(incidentReports.id, reportId)).limit(1);
  if (!report) return null;

  const content = report.fullContent || report.summary || "";
  if (content.length < 100) return null;

  // Truncate to fit LLM context window
  const truncatedContent = content.slice(0, 25000);

  const response = await invokeLLM({
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
            emulationGuidance: { type: "string", description: "How to emulate this attack in Caldera" },
          },
          required: [
            "phases", "actors", "malware", "exploits", "attackType",
            "complexity", "targetEnvironment", "targetSectors", "dwellTime",
            "narrative", "lessonsLearned", "emulationGuidance",
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
  const response = await invokeLLM({
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
    .where(eq(incidentReports.status, "raw"))
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
