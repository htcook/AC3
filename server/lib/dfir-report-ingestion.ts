/**
 * DFIR Report Ingestion Module
 *
 * Ingests DFIR reports, incident response write-ups, and threat intelligence
 * publications to extract actionable adversary techniques, tools, exploit code,
 * and attack chains. Extracted data feeds into:
 *
 *   1. dfir_observations — individual technique observations with artifacts
 *   2. exploit_playbooks — concrete exploit code/commands attributed to actors
 *   3. attack_chains_catalog — ordered multi-step attack sequences
 *   4. ioc_ttp_mappings — IOCs found in reports reverse-engineered to TTPs
 *
 * Sources: DFIR reports (Mandiant, CrowdStrike, Recorded Future, Unit42, etc.),
 * CISA advisories, MITRE ATT&CK updates, blog posts, academic papers.
 *
 * The module uses LLM-powered extraction with structured output schemas to
 * ensure consistent, machine-readable data from unstructured report text.
 */

import { invokeLLM } from "../_core/llm";
import { getDb } from "../db";
import { sql } from "drizzle-orm";
import { batchReverseEngineerIocs, type IocInput } from "./ioc-ttp-reverse-engineer";

// ─── Types ───────────────────────────────────────────────────────────────

export interface ReportInput {
  title: string;
  source: string;          // "Mandiant", "CrowdStrike", "CISA", "Unit42", etc.
  url?: string;
  date?: string;           // ISO date string
  content: string;         // Full text or summary of the report
  actorId?: string;        // If known, the attributed threat actor
  actorName?: string;
}

export interface ExtractedObservation {
  observationType: string;
  techniqueId: string;
  techniqueName: string;
  description: string;
  artifacts: string[];
  toolsObserved: string[];
  associatedIocs: Array<{ type: string; value: string; description?: string }>;
  detectionMethods: string[];
  mitigations: string[];
  confidence: number;
}

export interface ExtractedPlaybook {
  title: string;
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  code: string;
  language: string;
  toolName?: string;
  targetConditions: string[];
  exploitedCves: string[];
  targetServices: string[];
  targetPlatforms: string[];
  evasionTechniques: string[];
  successIndicators: string[];
  confidence: number;
}

export interface ExtractedChain {
  chainName: string;
  description: string;
  steps: Array<{
    order: number;
    techniqueId: string;
    techniqueName: string;
    tactic: string;
    description: string;
    toolUsed?: string;
    command?: string;
  }>;
  tacticsTraversed: string[];
  exploitedCves: string[];
  toolsUsed: string[];
  typicalDuration?: string;
  confidence: number;
}

export interface IngestionResult {
  reportId: string;
  reportTitle: string;
  observations: number;
  playbooks: number;
  chains: number;
  iocMappings: number;
  errors: string[];
}

// ─── LLM Extraction ─────────────────────────────────────────────────────

async function extractObservations(report: ReportInput): Promise<ExtractedObservation[]> {
  const prompt = `You are a senior DFIR analyst extracting structured threat intelligence from an incident report.

REPORT TITLE: ${report.title}
SOURCE: ${report.source}
DATE: ${report.date || "Unknown"}
${report.actorName ? `ATTRIBUTED ACTOR: ${report.actorName}` : ""}

REPORT CONTENT:
${report.content.slice(0, 12000)}

Extract ALL observable adversary techniques from this report. For each observation, identify:
1. The observation type (initial_access, execution, persistence, privilege_escalation, defense_evasion, credential_access, discovery, lateral_movement, collection, exfiltration, command_and_control, impact, tool_usage, malware_behavior, infrastructure, victim_profile)
2. The MITRE ATT&CK technique ID and name
3. A detailed description of what the adversary did
4. Specific artifacts left behind (file paths, registry keys, network indicators)
5. Tools the adversary used
6. Any IOCs mentioned (with type and value)
7. How this activity could be detected
8. Recommended mitigations

Be thorough — extract every technique mentioned, even if briefly. Include both confirmed and inferred techniques.`;

  try {
    const response = await invokeLLM({
      _caller: "dfir-ingestion:extractObservations",
      messages: [
        { role: "system", content: "You are a DFIR intelligence extraction specialist. Return structured JSON only." },
        { role: "user", content: prompt },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "dfir_observations",
          strict: true,
          schema: {
            type: "object",
            properties: {
              observations: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    observationType: { type: "string" },
                    techniqueId: { type: "string" },
                    techniqueName: { type: "string" },
                    description: { type: "string" },
                    artifacts: { type: "array", items: { type: "string" } },
                    toolsObserved: { type: "array", items: { type: "string" } },
                    associatedIocs: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          type: { type: "string" },
                          value: { type: "string" },
                          description: { type: "string" },
                        },
                        required: ["type", "value", "description"],
                        additionalProperties: false,
                      },
                    },
                    detectionMethods: { type: "array", items: { type: "string" } },
                    mitigations: { type: "array", items: { type: "string" } },
                    confidence: { type: "number" },
                  },
                  required: ["observationType", "techniqueId", "techniqueName", "description", "artifacts", "toolsObserved", "associatedIocs", "detectionMethods", "mitigations", "confidence"],
                  additionalProperties: false,
                },
              },
            },
            required: ["observations"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response?.choices?.[0]?.message?.content;
    if (!content) return [];
    return JSON.parse(content).observations || [];
  } catch (err) {
    console.error("[DFIR-Ingestion] Observation extraction failed:", err);
    return [];
  }
}

async function extractPlaybooks(report: ReportInput): Promise<ExtractedPlaybook[]> {
  const prompt = `You are an offensive security researcher extracting exploit playbooks from a DFIR/threat intelligence report.

REPORT TITLE: ${report.title}
SOURCE: ${report.source}
${report.actorName ? `ATTRIBUTED ACTOR: ${report.actorName}` : ""}

REPORT CONTENT:
${report.content.slice(0, 12000)}

Extract ALL concrete exploit techniques, commands, scripts, and tool configurations mentioned in this report.
For each playbook entry, provide:
1. A descriptive title
2. The MITRE technique ID and name
3. The tactic (initial-access, execution, persistence, etc.)
4. The actual code, command, or configuration used (be as specific as possible)
5. The language/format (bash, powershell, python, config, etc.)
6. The tool name if applicable
7. Target conditions (what must be true for this to work)
8. Any CVEs exploited
9. Target services and platforms
10. Evasion techniques used alongside
11. Success indicators

Focus on ACTIONABLE content — actual commands, scripts, payloads, and configurations that could be reproduced in a red team exercise.`;

  try {
    const response = await invokeLLM({
      _caller: "dfir-ingestion:extractPlaybooks",
      messages: [
        { role: "system", content: "You are an offensive security extraction specialist. Return structured JSON only." },
        { role: "user", content: prompt },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "exploit_playbooks",
          strict: true,
          schema: {
            type: "object",
            properties: {
              playbooks: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    title: { type: "string" },
                    techniqueId: { type: "string" },
                    techniqueName: { type: "string" },
                    tactic: { type: "string" },
                    code: { type: "string" },
                    language: { type: "string" },
                    toolName: { type: "string" },
                    targetConditions: { type: "array", items: { type: "string" } },
                    exploitedCves: { type: "array", items: { type: "string" } },
                    targetServices: { type: "array", items: { type: "string" } },
                    targetPlatforms: { type: "array", items: { type: "string" } },
                    evasionTechniques: { type: "array", items: { type: "string" } },
                    successIndicators: { type: "array", items: { type: "string" } },
                    confidence: { type: "number" },
                  },
                  required: ["title", "techniqueId", "techniqueName", "tactic", "code", "language", "toolName", "targetConditions", "exploitedCves", "targetServices", "targetPlatforms", "evasionTechniques", "successIndicators", "confidence"],
                  additionalProperties: false,
                },
              },
            },
            required: ["playbooks"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response?.choices?.[0]?.message?.content;
    if (!content) return [];
    return JSON.parse(content).playbooks || [];
  } catch (err) {
    console.error("[DFIR-Ingestion] Playbook extraction failed:", err);
    return [];
  }
}

async function extractAttackChains(report: ReportInput): Promise<ExtractedChain[]> {
  const prompt = `You are a kill chain analyst extracting multi-step attack sequences from a DFIR report.

REPORT TITLE: ${report.title}
SOURCE: ${report.source}
${report.actorName ? `ATTRIBUTED ACTOR: ${report.actorName}` : ""}

REPORT CONTENT:
${report.content.slice(0, 12000)}

Extract ALL multi-step attack chains described in this report. An attack chain is an ordered sequence of techniques the adversary used to achieve their objective.

For each chain:
1. A descriptive name (e.g., "APT29 SolarWinds Supply Chain → Lateral Movement → Exfiltration")
2. Overall description of the attack flow
3. Ordered steps with technique IDs, descriptions, tools, and commands
4. All tactics traversed (in order)
5. CVEs exploited across the chain
6. All tools used
7. Typical duration if mentioned
8. Your confidence level

Focus on the SEQUENCE and DEPENDENCIES between steps — what had to succeed before the next step could execute.`;

  try {
    const response = await invokeLLM({
      _caller: "dfir-ingestion:extractAttackChains",
      messages: [
        { role: "system", content: "You are a kill chain analysis specialist. Return structured JSON only." },
        { role: "user", content: prompt },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "attack_chains",
          strict: true,
          schema: {
            type: "object",
            properties: {
              chains: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    chainName: { type: "string" },
                    description: { type: "string" },
                    steps: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          order: { type: "number" },
                          techniqueId: { type: "string" },
                          techniqueName: { type: "string" },
                          tactic: { type: "string" },
                          description: { type: "string" },
                          toolUsed: { type: "string" },
                          command: { type: "string" },
                        },
                        required: ["order", "techniqueId", "techniqueName", "tactic", "description", "toolUsed", "command"],
                        additionalProperties: false,
                      },
                    },
                    tacticsTraversed: { type: "array", items: { type: "string" } },
                    exploitedCves: { type: "array", items: { type: "string" } },
                    toolsUsed: { type: "array", items: { type: "string" } },
                    typicalDuration: { type: "string" },
                    confidence: { type: "number" },
                  },
                  required: ["chainName", "description", "steps", "tacticsTraversed", "exploitedCves", "toolsUsed", "typicalDuration", "confidence"],
                  additionalProperties: false,
                },
              },
            },
            required: ["chains"],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response?.choices?.[0]?.message?.content;
    if (!content) return [];
    return JSON.parse(content).chains || [];
  } catch (err) {
    console.error("[DFIR-Ingestion] Chain extraction failed:", err);
    return [];
  }
}

// ─── Database Persistence ────────────────────────────────────────────────

async function persistObservations(
  reportId: string, report: ReportInput, observations: ExtractedObservation[]
): Promise<number> {
  const db = await getDb();
  if (!db || observations.length === 0) return 0;
  let count = 0;

  for (const obs of observations) {
    try {
      await db.execute(sql`
        INSERT INTO dfir_observations (
          dfir_report_id, dfir_report_title, dfir_report_source, dfir_report_url, dfir_report_date,
          dfir_actor_id, dfir_actor_name, dfir_observation_type,
          dfir_technique_id, dfir_technique_name, dfir_description,
          dfir_artifacts, dfir_tools_observed, dfir_associated_iocs,
          dfir_detection_methods, dfir_mitigations, dfir_confidence
        ) VALUES (
          ${reportId}, ${report.title}, ${report.source}, ${report.url || null}, ${report.date || null},
          ${report.actorId || null}, ${report.actorName || null}, ${obs.observationType},
          ${obs.techniqueId}, ${obs.techniqueName}, ${obs.description},
          ${JSON.stringify(obs.artifacts)}, ${JSON.stringify(obs.toolsObserved)},
          ${JSON.stringify(obs.associatedIocs)},
          ${JSON.stringify(obs.detectionMethods)}, ${JSON.stringify(obs.mitigations)},
          ${Math.min(100, Math.max(0, obs.confidence))}
        )
      `);
      count++;
    } catch (err) {
      console.error(`[DFIR-Ingestion] Failed to persist observation ${obs.techniqueId}:`, err);
    }
  }
  return count;
}

async function persistPlaybooks(
  report: ReportInput, playbooks: ExtractedPlaybook[]
): Promise<number> {
  const db = await getDb();
  if (!db || playbooks.length === 0) return 0;
  let count = 0;

  for (const pb of playbooks) {
    try {
      await db.execute(sql`
        INSERT INTO exploit_playbooks (
          ep_actor_id, ep_actor_name, playbook_title,
          ep_technique_id, ep_technique_name, ep_tactic,
          ep_code, ep_language, ep_tool_name,
          ep_target_conditions, ep_exploited_cves, ep_target_services,
          ep_target_platforms, ep_evasion_techniques, ep_success_indicators,
          ep_source_type, ep_source_reference, ep_confidence, ep_observed_date
        ) VALUES (
          ${report.actorId || "unknown"}, ${report.actorName || "Unknown"},
          ${pb.title}, ${pb.techniqueId}, ${pb.techniqueName}, ${pb.tactic},
          ${pb.code}, ${pb.language}, ${pb.toolName || null},
          ${JSON.stringify(pb.targetConditions)}, ${JSON.stringify(pb.exploitedCves)},
          ${JSON.stringify(pb.targetServices)}, ${JSON.stringify(pb.targetPlatforms)},
          ${JSON.stringify(pb.evasionTechniques)}, ${JSON.stringify(pb.successIndicators)},
          'dfir_report', ${report.url || report.source},
          ${Math.min(100, Math.max(0, pb.confidence))}, ${report.date || null}
        )
      `);
      count++;
    } catch (err) {
      console.error(`[DFIR-Ingestion] Failed to persist playbook ${pb.title}:`, err);
    }
  }
  return count;
}

async function persistChains(
  report: ReportInput, chains: ExtractedChain[]
): Promise<number> {
  const db = await getDb();
  if (!db || chains.length === 0) return 0;
  let count = 0;

  for (const chain of chains) {
    try {
      await db.execute(sql`
        INSERT INTO attack_chains_catalog (
          acc_actor_id, acc_actor_name, acc_chain_name, acc_description,
          acc_steps, acc_tactics_traversed, acc_risk_score,
          acc_exploited_cves, acc_tools_used, acc_typical_duration,
          acc_source_type, acc_source_reference, acc_confidence, acc_observed_date
        ) VALUES (
          ${report.actorId || "unknown"}, ${report.actorName || "Unknown"},
          ${chain.chainName}, ${chain.description},
          ${JSON.stringify(chain.steps)}, ${JSON.stringify(chain.tacticsTraversed)},
          ${Math.min(100, Math.max(0, chain.confidence))},
          ${JSON.stringify(chain.exploitedCves)}, ${JSON.stringify(chain.toolsUsed)},
          ${chain.typicalDuration || null},
          'dfir_report', ${report.url || report.source},
          ${Math.min(100, Math.max(0, chain.confidence))}, ${report.date || null}
        )
      `);
      count++;
    } catch (err) {
      console.error(`[DFIR-Ingestion] Failed to persist chain ${chain.chainName}:`, err);
    }
  }
  return count;
}

// ─── IOC Extraction & Reverse Engineering ────────────────────────────────

async function processExtractedIocs(
  report: ReportInput, observations: ExtractedObservation[]
): Promise<number> {
  const allIocs: IocInput[] = [];

  for (const obs of observations) {
    for (const ioc of obs.associatedIocs || []) {
      if (ioc.value && ioc.type) {
        allIocs.push({
          type: ioc.type,
          value: ioc.value,
          description: ioc.description || `From DFIR observation: ${obs.techniqueName}`,
          actorId: report.actorId,
          actorName: report.actorName,
        });
      }
    }
  }

  if (allIocs.length === 0) return 0;

  // Deduplicate by type+value
  const seen = new Set<string>();
  const uniqueIocs = allIocs.filter(ioc => {
    const key = `${ioc.type}:${ioc.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const results = await batchReverseEngineerIocs(uniqueIocs, { skipLLM: true, persist: true });
  return results.reduce((sum, r) => sum + r.mappings.length, 0);
}

// ─── Public API ──────────────────────────────────────────────────────────

/**
 * Ingest a single DFIR report and extract all intelligence.
 * Runs three parallel LLM extractions: observations, playbooks, and chains.
 * Then processes any IOCs found through the reverse engineering pipeline.
 */
export async function ingestDfirReport(report: ReportInput): Promise<IngestionResult> {
  const reportId = `dfir-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const errors: string[] = [];

  console.log(`[DFIR-Ingestion] Ingesting report: ${report.title} from ${report.source}`);

  // Run all three extractions in parallel
  const [observations, playbooks, chains] = await Promise.all([
    extractObservations(report).catch(err => { errors.push(`Observations: ${err.message}`); return []; }),
    extractPlaybooks(report).catch(err => { errors.push(`Playbooks: ${err.message}`); return []; }),
    extractAttackChains(report).catch(err => { errors.push(`Chains: ${err.message}`); return []; }),
  ]);

  // Persist all extracted data
  const [obsCount, pbCount, chainCount] = await Promise.all([
    persistObservations(reportId, report, observations),
    persistPlaybooks(report, playbooks),
    persistChains(report, chains),
  ]);

  // Process IOCs through reverse engineering pipeline
  const iocMappings = await processExtractedIocs(report, observations);

  console.log(`[DFIR-Ingestion] Report "${report.title}": ${obsCount} observations, ${pbCount} playbooks, ${chainCount} chains, ${iocMappings} IOC mappings`);

  return {
    reportId,
    reportTitle: report.title,
    observations: obsCount,
    playbooks: pbCount,
    chains: chainCount,
    iocMappings,
    errors,
  };
}

/**
 * Batch ingest multiple DFIR reports.
 */
export async function batchIngestReports(
  reports: ReportInput[],
  options?: { concurrency?: number }
): Promise<IngestionResult[]> {
  const { concurrency = 2 } = options || {};
  const results: IngestionResult[] = [];

  for (let i = 0; i < reports.length; i += concurrency) {
    const batch = reports.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map(r => ingestDfirReport(r)));
    results.push(...batchResults);
  }

  return results;
}

/**
 * Query the catalog for playbooks matching specific conditions.
 * Used by the exploit pipeline to find actor-attributed exploit code.
 */
export async function findPlaybooksForTarget(params: {
  techniqueId?: string;
  tactic?: string;
  service?: string;
  platform?: string;
  cve?: string;
  actorId?: string;
  limit?: number;
}): Promise<Array<{
  id: number;
  actorName: string;
  title: string;
  techniqueId: string;
  tactic: string;
  code: string;
  language: string;
  toolName: string | null;
  confidence: number;
  source: string | null;
}>> {
  const db = await getDb();
  if (!db) return [];

  const conditions: string[] = ["1=1"];
  if (params.techniqueId) conditions.push(`ep_technique_id = '${params.techniqueId}'`);
  if (params.tactic) conditions.push(`ep_tactic = '${params.tactic}'`);
  if (params.actorId) conditions.push(`ep_actor_id = '${params.actorId}'`);
  if (params.cve) conditions.push(`JSON_CONTAINS(ep_exploited_cves, '"${params.cve}"')`);
  if (params.service) conditions.push(`JSON_CONTAINS(ep_target_services, '"${params.service}"')`);
  if (params.platform) conditions.push(`JSON_CONTAINS(ep_target_platforms, '"${params.platform}"')`);

  const whereClause = conditions.join(" AND ");
  const limit = params.limit || 10;

  const rows = await db.execute(sql.raw(`
    SELECT id, ep_actor_name, playbook_title, ep_technique_id, ep_tactic,
           ep_code, ep_language, ep_tool_name, ep_confidence, ep_source_reference
    FROM exploit_playbooks
    WHERE ${whereClause}
    ORDER BY ep_confidence DESC
    LIMIT ${limit}
  `));

  return ((rows[0] as any[]) || []).map((r: any) => ({
    id: r.id,
    actorName: r.ep_actor_name,
    title: r.playbook_title,
    techniqueId: r.ep_technique_id,
    tactic: r.ep_tactic,
    code: r.ep_code,
    language: r.ep_language,
    toolName: r.ep_tool_name,
    confidence: r.ep_confidence,
    source: r.ep_source_reference,
  }));
}

/**
 * Query the catalog for attack chains matching specific criteria.
 * Used by Ember and the chain planner for actor-emulated operations.
 */
export async function findAttackChains(params: {
  actorId?: string;
  tactic?: string;
  cve?: string;
  technology?: string;
  limit?: number;
}): Promise<Array<{
  id: number;
  actorName: string;
  chainName: string;
  description: string;
  steps: any[];
  tacticsTraversed: string[];
  toolsUsed: string[];
  confidence: number;
}>> {
  const db = await getDb();
  if (!db) return [];

  const conditions: string[] = ["1=1"];
  if (params.actorId) conditions.push(`acc_actor_id = '${params.actorId}'`);
  if (params.cve) conditions.push(`JSON_CONTAINS(acc_exploited_cves, '"${params.cve}"')`);
  if (params.technology) conditions.push(`JSON_CONTAINS(acc_target_technologies, '"${params.technology}"')`);
  if (params.tactic) conditions.push(`JSON_CONTAINS(acc_tactics_traversed, '"${params.tactic}"')`);

  const whereClause = conditions.join(" AND ");
  const limit = params.limit || 10;

  const rows = await db.execute(sql.raw(`
    SELECT id, acc_actor_name, acc_chain_name, acc_description,
           acc_steps, acc_tactics_traversed, acc_tools_used, acc_confidence
    FROM attack_chains_catalog
    WHERE ${whereClause}
    ORDER BY acc_confidence DESC
    LIMIT ${limit}
  `));

  return ((rows[0] as any[]) || []).map((r: any) => ({
    id: r.id,
    actorName: r.acc_actor_name,
    chainName: r.acc_chain_name,
    description: r.acc_description,
    steps: typeof r.acc_steps === "string" ? JSON.parse(r.acc_steps) : r.acc_steps,
    tacticsTraversed: typeof r.acc_tactics_traversed === "string" ? JSON.parse(r.acc_tactics_traversed) : r.acc_tactics_traversed,
    toolsUsed: typeof r.acc_tools_used === "string" ? JSON.parse(r.acc_tools_used) : r.acc_tools_used,
    confidence: r.acc_confidence,
  }));
}

/**
 * Build a context block from DFIR observations for a specific actor.
 * Used to enrich the exploit pipeline with real-world adversary behavior.
 */
export async function buildDfirContextForActor(actorId: string): Promise<string> {
  const db = await getDb();
  if (!db) return "";

  // Get observations
  const [obsRows] = await db.execute(sql`
    SELECT dfir_observation_type, dfir_technique_id, dfir_technique_name,
           dfir_description, dfir_tools_observed, dfir_confidence
    FROM dfir_observations
    WHERE dfir_actor_id = ${actorId}
    ORDER BY dfir_confidence DESC
    LIMIT 20
  `);

  // Get playbooks
  const [pbRows] = await db.execute(sql`
    SELECT playbook_title, ep_technique_id, ep_tactic, ep_tool_name, ep_language, ep_confidence
    FROM exploit_playbooks
    WHERE ep_actor_id = ${actorId}
    ORDER BY ep_confidence DESC
    LIMIT 10
  `);

  // Get chains
  const [chainRows] = await db.execute(sql`
    SELECT acc_chain_name, acc_tactics_traversed, acc_tools_used, acc_confidence
    FROM attack_chains_catalog
    WHERE acc_actor_id = ${actorId}
    ORDER BY acc_confidence DESC
    LIMIT 5
  `);

  const obs = (obsRows as any[]) || [];
  const pbs = (pbRows as any[]) || [];
  const chains = (chainRows as any[]) || [];

  if (obs.length === 0 && pbs.length === 0 && chains.length === 0) return "";

  let context = `## DFIR-Derived Intelligence for ${actorId}\n\n`;

  if (obs.length > 0) {
    context += `### Observed Techniques (${obs.length} observations)\n`;
    for (const o of obs) {
      const tools = typeof o.dfir_tools_observed === "string" ? JSON.parse(o.dfir_tools_observed) : o.dfir_tools_observed;
      context += `- ${o.dfir_technique_id} (${o.dfir_technique_name}) [${o.dfir_confidence}%]: ${o.dfir_description.slice(0, 200)}\n`;
      if (tools?.length) context += `  Tools: ${tools.join(", ")}\n`;
    }
    context += "\n";
  }

  if (pbs.length > 0) {
    context += `### Exploit Playbooks (${pbs.length} available)\n`;
    for (const pb of pbs) {
      context += `- "${pb.playbook_title}" — ${pb.ep_technique_id} (${pb.ep_tactic}) via ${pb.ep_tool_name || pb.ep_language} [${pb.ep_confidence}%]\n`;
    }
    context += "\n";
  }

  if (chains.length > 0) {
    context += `### Known Attack Chains (${chains.length} documented)\n`;
    for (const c of chains) {
      const tactics = typeof c.acc_tactics_traversed === "string" ? JSON.parse(c.acc_tactics_traversed) : c.acc_tactics_traversed;
      const tools = typeof c.acc_tools_used === "string" ? JSON.parse(c.acc_tools_used) : c.acc_tools_used;
      context += `- "${c.acc_chain_name}" — ${tactics?.join(" → ") || "multi-phase"}\n`;
      if (tools?.length) context += `  Tools: ${tools.join(", ")}\n`;
    }
    context += "\n";
  }

  return context;
}

/**
 * Get ingestion statistics for the catalog.
 */
export async function getIngestionStats(): Promise<{
  totalObservations: number;
  totalPlaybooks: number;
  totalChains: number;
  uniqueReports: number;
  uniqueActors: number;
  topActors: Array<{ actorId: string; actorName: string; observations: number }>;
  topTechniques: Array<{ techniqueId: string; techniqueName: string; count: number }>;
}> {
  const db = await getDb();
  if (!db) return { totalObservations: 0, totalPlaybooks: 0, totalChains: 0, uniqueReports: 0, uniqueActors: 0, topActors: [], topTechniques: [] };

  const [obsCount] = await db.execute(sql`SELECT COUNT(*) as cnt FROM dfir_observations`);
  const [pbCount] = await db.execute(sql`SELECT COUNT(*) as cnt FROM exploit_playbooks`);
  const [chainCount] = await db.execute(sql`SELECT COUNT(*) as cnt FROM attack_chains_catalog`);
  const [reportCount] = await db.execute(sql`SELECT COUNT(DISTINCT dfir_report_id) as cnt FROM dfir_observations`);
  const [actorCount] = await db.execute(sql`SELECT COUNT(DISTINCT dfir_actor_id) as cnt FROM dfir_observations WHERE dfir_actor_id IS NOT NULL`);

  const [topActorRows] = await db.execute(sql`
    SELECT dfir_actor_id, dfir_actor_name, COUNT(*) as cnt
    FROM dfir_observations WHERE dfir_actor_id IS NOT NULL
    GROUP BY dfir_actor_id, dfir_actor_name ORDER BY cnt DESC LIMIT 10
  `);

  const [topTechRows] = await db.execute(sql`
    SELECT dfir_technique_id, dfir_technique_name, COUNT(*) as cnt
    FROM dfir_observations GROUP BY dfir_technique_id, dfir_technique_name ORDER BY cnt DESC LIMIT 10
  `);

  return {
    totalObservations: (obsCount as any[])?.[0]?.cnt || 0,
    totalPlaybooks: (pbCount as any[])?.[0]?.cnt || 0,
    totalChains: (chainCount as any[])?.[0]?.cnt || 0,
    uniqueReports: (reportCount as any[])?.[0]?.cnt || 0,
    uniqueActors: (actorCount as any[])?.[0]?.cnt || 0,
    topActors: ((topActorRows as any[]) || []).map((r: any) => ({
      actorId: r.dfir_actor_id, actorName: r.dfir_actor_name, observations: r.cnt,
    })),
    topTechniques: ((topTechRows as any[]) || []).map((r: any) => ({
      techniqueId: r.dfir_technique_id, techniqueName: r.dfir_technique_name, count: r.cnt,
    })),
  };
}
