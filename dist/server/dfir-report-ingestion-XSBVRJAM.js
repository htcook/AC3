import {
  batchReverseEngineerIocs
} from "./chunk-4BG2TERP.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-D3Z2XQH2.js";
import "./chunk-RUIEEOYK.js";
import {
  getDb,
  init_db
} from "./chunk-3OPUTHKA.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-H7DAFEQB.js";
import "./chunk-KFQGP6VL.js";

// server/lib/dfir-report-ingestion.ts
init_llm();
init_db();
import { sql } from "drizzle-orm";
async function extractObservations(report) {
  const prompt = `You are a senior DFIR analyst extracting structured threat intelligence from an incident report.

REPORT TITLE: ${report.title}
SOURCE: ${report.source}
DATE: ${report.date || "Unknown"}
${report.actorName ? `ATTRIBUTED ACTOR: ${report.actorName}` : ""}

REPORT CONTENT:
${report.content.slice(0, 12e3)}

Extract ALL observable adversary techniques from this report. For each observation, identify:
1. The observation type (initial_access, execution, persistence, privilege_escalation, defense_evasion, credential_access, discovery, lateral_movement, collection, exfiltration, command_and_control, impact, tool_usage, malware_behavior, infrastructure, victim_profile)
2. The MITRE ATT&CK technique ID and name
3. A detailed description of what the adversary did
4. Specific artifacts left behind (file paths, registry keys, network indicators)
5. Tools the adversary used
6. Any IOCs mentioned (with type and value)
7. How this activity could be detected
8. Recommended mitigations

Be thorough \u2014 extract every technique mentioned, even if briefly. Include both confirmed and inferred techniques.`;
  try {
    const response = await invokeLLM({
      _caller: "dfir-ingestion:extractObservations",
      messages: [
        { role: "system", content: "You are a DFIR intelligence extraction specialist. Return structured JSON only." },
        { role: "user", content: prompt }
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
                          description: { type: "string" }
                        },
                        required: ["type", "value", "description"],
                        additionalProperties: false
                      }
                    },
                    detectionMethods: { type: "array", items: { type: "string" } },
                    mitigations: { type: "array", items: { type: "string" } },
                    confidence: { type: "number" }
                  },
                  required: ["observationType", "techniqueId", "techniqueName", "description", "artifacts", "toolsObserved", "associatedIocs", "detectionMethods", "mitigations", "confidence"],
                  additionalProperties: false
                }
              }
            },
            required: ["observations"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response?.choices?.[0]?.message?.content;
    if (!content) return [];
    return JSON.parse(content).observations || [];
  } catch (err) {
    console.error("[DFIR-Ingestion] Observation extraction failed:", err);
    return [];
  }
}
async function extractPlaybooks(report) {
  const prompt = `You are an offensive security researcher extracting exploit playbooks from a DFIR/threat intelligence report.

REPORT TITLE: ${report.title}
SOURCE: ${report.source}
${report.actorName ? `ATTRIBUTED ACTOR: ${report.actorName}` : ""}

REPORT CONTENT:
${report.content.slice(0, 12e3)}

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

Focus on ACTIONABLE content \u2014 actual commands, scripts, payloads, and configurations that could be reproduced in a red team exercise.`;
  try {
    const response = await invokeLLM({
      _caller: "dfir-ingestion:extractPlaybooks",
      messages: [
        { role: "system", content: "You are an offensive security extraction specialist. Return structured JSON only." },
        { role: "user", content: prompt }
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
                    confidence: { type: "number" }
                  },
                  required: ["title", "techniqueId", "techniqueName", "tactic", "code", "language", "toolName", "targetConditions", "exploitedCves", "targetServices", "targetPlatforms", "evasionTechniques", "successIndicators", "confidence"],
                  additionalProperties: false
                }
              }
            },
            required: ["playbooks"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response?.choices?.[0]?.message?.content;
    if (!content) return [];
    return JSON.parse(content).playbooks || [];
  } catch (err) {
    console.error("[DFIR-Ingestion] Playbook extraction failed:", err);
    return [];
  }
}
async function extractAttackChains(report) {
  const prompt = `You are a kill chain analyst extracting multi-step attack sequences from a DFIR report.

REPORT TITLE: ${report.title}
SOURCE: ${report.source}
${report.actorName ? `ATTRIBUTED ACTOR: ${report.actorName}` : ""}

REPORT CONTENT:
${report.content.slice(0, 12e3)}

Extract ALL multi-step attack chains described in this report. An attack chain is an ordered sequence of techniques the adversary used to achieve their objective.

For each chain:
1. A descriptive name (e.g., "APT29 SolarWinds Supply Chain \u2192 Lateral Movement \u2192 Exfiltration")
2. Overall description of the attack flow
3. Ordered steps with technique IDs, descriptions, tools, and commands
4. All tactics traversed (in order)
5. CVEs exploited across the chain
6. All tools used
7. Typical duration if mentioned
8. Your confidence level

Focus on the SEQUENCE and DEPENDENCIES between steps \u2014 what had to succeed before the next step could execute.`;
  try {
    const response = await invokeLLM({
      _caller: "dfir-ingestion:extractAttackChains",
      messages: [
        { role: "system", content: "You are a kill chain analysis specialist. Return structured JSON only." },
        { role: "user", content: prompt }
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
                          command: { type: "string" }
                        },
                        required: ["order", "techniqueId", "techniqueName", "tactic", "description", "toolUsed", "command"],
                        additionalProperties: false
                      }
                    },
                    tacticsTraversed: { type: "array", items: { type: "string" } },
                    exploitedCves: { type: "array", items: { type: "string" } },
                    toolsUsed: { type: "array", items: { type: "string" } },
                    typicalDuration: { type: "string" },
                    confidence: { type: "number" }
                  },
                  required: ["chainName", "description", "steps", "tacticsTraversed", "exploitedCves", "toolsUsed", "typicalDuration", "confidence"],
                  additionalProperties: false
                }
              }
            },
            required: ["chains"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response?.choices?.[0]?.message?.content;
    if (!content) return [];
    return JSON.parse(content).chains || [];
  } catch (err) {
    console.error("[DFIR-Ingestion] Chain extraction failed:", err);
    return [];
  }
}
async function persistObservations(reportId, report, observations) {
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
async function persistPlaybooks(report, playbooks) {
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
async function persistChains(report, chains) {
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
async function processExtractedIocs(report, observations) {
  const allIocs = [];
  for (const obs of observations) {
    for (const ioc of obs.associatedIocs || []) {
      if (ioc.value && ioc.type) {
        allIocs.push({
          type: ioc.type,
          value: ioc.value,
          description: ioc.description || `From DFIR observation: ${obs.techniqueName}`,
          actorId: report.actorId,
          actorName: report.actorName
        });
      }
    }
  }
  if (allIocs.length === 0) return 0;
  const seen = /* @__PURE__ */ new Set();
  const uniqueIocs = allIocs.filter((ioc) => {
    const key = `${ioc.type}:${ioc.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const results = await batchReverseEngineerIocs(uniqueIocs, { skipLLM: true, persist: true });
  return results.reduce((sum, r) => sum + r.mappings.length, 0);
}
async function ingestDfirReport(report) {
  const reportId = `dfir-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const errors = [];
  console.log(`[DFIR-Ingestion] Ingesting report: ${report.title} from ${report.source}`);
  const [observations, playbooks, chains] = await Promise.all([
    extractObservations(report).catch((err) => {
      errors.push(`Observations: ${err.message}`);
      return [];
    }),
    extractPlaybooks(report).catch((err) => {
      errors.push(`Playbooks: ${err.message}`);
      return [];
    }),
    extractAttackChains(report).catch((err) => {
      errors.push(`Chains: ${err.message}`);
      return [];
    })
  ]);
  const [obsCount, pbCount, chainCount] = await Promise.all([
    persistObservations(reportId, report, observations),
    persistPlaybooks(report, playbooks),
    persistChains(report, chains)
  ]);
  const iocMappings = await processExtractedIocs(report, observations);
  console.log(`[DFIR-Ingestion] Report "${report.title}": ${obsCount} observations, ${pbCount} playbooks, ${chainCount} chains, ${iocMappings} IOC mappings`);
  return {
    reportId,
    reportTitle: report.title,
    observations: obsCount,
    playbooks: pbCount,
    chains: chainCount,
    iocMappings,
    errors
  };
}
async function batchIngestReports(reports, options) {
  const { concurrency = 2 } = options || {};
  const results = [];
  for (let i = 0; i < reports.length; i += concurrency) {
    const batch = reports.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map((r) => ingestDfirReport(r)));
    results.push(...batchResults);
  }
  return results;
}
async function findPlaybooksForTarget(params) {
  const db = await getDb();
  if (!db) return [];
  const conditions = ["1=1"];
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
  return (rows[0] || []).map((r) => ({
    id: r.id,
    actorName: r.ep_actor_name,
    title: r.playbook_title,
    techniqueId: r.ep_technique_id,
    tactic: r.ep_tactic,
    code: r.ep_code,
    language: r.ep_language,
    toolName: r.ep_tool_name,
    confidence: r.ep_confidence,
    source: r.ep_source_reference
  }));
}
async function findAttackChains(params) {
  const db = await getDb();
  if (!db) return [];
  const conditions = ["1=1"];
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
  return (rows[0] || []).map((r) => ({
    id: r.id,
    actorName: r.acc_actor_name,
    chainName: r.acc_chain_name,
    description: r.acc_description,
    steps: typeof r.acc_steps === "string" ? JSON.parse(r.acc_steps) : r.acc_steps,
    tacticsTraversed: typeof r.acc_tactics_traversed === "string" ? JSON.parse(r.acc_tactics_traversed) : r.acc_tactics_traversed,
    toolsUsed: typeof r.acc_tools_used === "string" ? JSON.parse(r.acc_tools_used) : r.acc_tools_used,
    confidence: r.acc_confidence
  }));
}
async function buildDfirContextForActor(actorId) {
  const db = await getDb();
  if (!db) return "";
  const [obsRows] = await db.execute(sql`
    SELECT dfir_observation_type, dfir_technique_id, dfir_technique_name,
           dfir_description, dfir_tools_observed, dfir_confidence
    FROM dfir_observations
    WHERE dfir_actor_id = ${actorId}
    ORDER BY dfir_confidence DESC
    LIMIT 20
  `);
  const [pbRows] = await db.execute(sql`
    SELECT playbook_title, ep_technique_id, ep_tactic, ep_tool_name, ep_language, ep_confidence
    FROM exploit_playbooks
    WHERE ep_actor_id = ${actorId}
    ORDER BY ep_confidence DESC
    LIMIT 10
  `);
  const [chainRows] = await db.execute(sql`
    SELECT acc_chain_name, acc_tactics_traversed, acc_tools_used, acc_confidence
    FROM attack_chains_catalog
    WHERE acc_actor_id = ${actorId}
    ORDER BY acc_confidence DESC
    LIMIT 5
  `);
  const obs = obsRows || [];
  const pbs = pbRows || [];
  const chains = chainRows || [];
  if (obs.length === 0 && pbs.length === 0 && chains.length === 0) return "";
  let context = `## DFIR-Derived Intelligence for ${actorId}

`;
  if (obs.length > 0) {
    context += `### Observed Techniques (${obs.length} observations)
`;
    for (const o of obs) {
      const tools = typeof o.dfir_tools_observed === "string" ? JSON.parse(o.dfir_tools_observed) : o.dfir_tools_observed;
      context += `- ${o.dfir_technique_id} (${o.dfir_technique_name}) [${o.dfir_confidence}%]: ${o.dfir_description.slice(0, 200)}
`;
      if (tools?.length) context += `  Tools: ${tools.join(", ")}
`;
    }
    context += "\n";
  }
  if (pbs.length > 0) {
    context += `### Exploit Playbooks (${pbs.length} available)
`;
    for (const pb of pbs) {
      context += `- "${pb.playbook_title}" \u2014 ${pb.ep_technique_id} (${pb.ep_tactic}) via ${pb.ep_tool_name || pb.ep_language} [${pb.ep_confidence}%]
`;
    }
    context += "\n";
  }
  if (chains.length > 0) {
    context += `### Known Attack Chains (${chains.length} documented)
`;
    for (const c of chains) {
      const tactics = typeof c.acc_tactics_traversed === "string" ? JSON.parse(c.acc_tactics_traversed) : c.acc_tactics_traversed;
      const tools = typeof c.acc_tools_used === "string" ? JSON.parse(c.acc_tools_used) : c.acc_tools_used;
      context += `- "${c.acc_chain_name}" \u2014 ${tactics?.join(" \u2192 ") || "multi-phase"}
`;
      if (tools?.length) context += `  Tools: ${tools.join(", ")}
`;
    }
    context += "\n";
  }
  return context;
}
async function getIngestionStats() {
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
    totalObservations: obsCount?.[0]?.cnt || 0,
    totalPlaybooks: pbCount?.[0]?.cnt || 0,
    totalChains: chainCount?.[0]?.cnt || 0,
    uniqueReports: reportCount?.[0]?.cnt || 0,
    uniqueActors: actorCount?.[0]?.cnt || 0,
    topActors: (topActorRows || []).map((r) => ({
      actorId: r.dfir_actor_id,
      actorName: r.dfir_actor_name,
      observations: r.cnt
    })),
    topTechniques: (topTechRows || []).map((r) => ({
      techniqueId: r.dfir_technique_id,
      techniqueName: r.dfir_technique_name,
      count: r.cnt
    }))
  };
}
export {
  batchIngestReports,
  buildDfirContextForActor,
  findAttackChains,
  findPlaybooksForTarget,
  getIngestionStats,
  ingestDfirReport
};
