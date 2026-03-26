/**
 * TTP Knowledge Engine
 * 
 * Uses LLM to deeply research and understand each MITRE ATT&CK technique:
 * - How the technique is performed (tools, commands, execution methods)
 * - What IOCs are generated (file hashes, registry, network, event logs)
 * - Detection rules (Sigma, YARA, Suricata, Splunk SPL, KQL)
 * - Caldera ability mappings
 * - Attack chain positioning and follow-up techniques
 * - Red/Blue/Purple team exercise value
 * 
 * This knowledge enables:
 * - Highly accurate blocking rules and SOC rules
 * - Intelligent Caldera campaign design
 * - Better threat actor emulation for Red/Blue/Purple exercises
 */

import { invokeLLM } from "../_core/llm";
import * as db from "../db";
import type { InsertTtpKnowledge } from "../../drizzle/schema";

// ─── MITRE ATT&CK Tactic Ordering ──────────────────────────────────────
const TACTIC_ORDER = [
  "reconnaissance", "resource-development", "initial-access", "execution",
  "persistence", "privilege-escalation", "defense-evasion", "credential-access",
  "discovery", "lateral-movement", "collection", "command-and-control",
  "exfiltration", "impact",
];

// ─── Core TTP Research Engine ───────────────────────────────────────────

/**
 * Research a single MITRE ATT&CK technique in depth using LLM.
 * Generates comprehensive knowledge including execution methods,
 * IOC patterns, detection rules, and team exercise value.
 */
export async function researchTechnique(techniqueId: string, techniqueName: string, tactic: string): Promise<InsertTtpKnowledge> {
  const response = await invokeLLM({
    _caller: "ttp-engine.analyze",
    messages: [
      {
        role: "system",
        content: `You are an elite red team operator and detection engineer with 20+ years of experience. You have deep expertise in:
- MITRE ATT&CK framework and all techniques
- Offensive security tools (Cobalt Strike, Metasploit, Impacket, Mimikatz, Rubeus, BloodHound, etc.)
- Caldera adversary emulation platform and its abilities
- Detection engineering (Sigma, YARA, Suricata, Splunk SPL, KQL)
- Windows/Linux/macOS internals and forensics
- Network traffic analysis and PCAP inspection
- Incident response and digital forensics

Your task is to provide DEEP, ACTIONABLE intelligence about a specific ATT&CK technique. Be extremely specific about:
1. Exact commands, tools, and methods used to execute the technique
2. Precise IOCs generated (with actual patterns, not generic descriptions)
3. Working detection rules in multiple formats
4. How this technique fits into real attack chains

Return valid JSON matching the specified schema.`,
      },
      {
        role: "user",
        content: `Provide deep technical analysis of MITRE ATT&CK technique:

Technique ID: ${techniqueId}
Technique Name: ${techniqueName}
Tactic: ${tactic}

Return JSON with this exact structure:
{
  "description": "Comprehensive 3-5 paragraph technical description of how this technique works, including real-world examples from known APT campaigns",
  "executionMethods": [
    {
      "method": "Name of execution method",
      "tools": ["tool1", "tool2"],
      "commands": ["exact command line example 1", "exact command line example 2"],
      "prerequisites": ["what's needed before this can work"],
      "platforms": ["windows", "linux", "macos"]
    }
  ],
  "toolsUsed": [
    {
      "name": "Tool name",
      "type": "offensive|defensive|dual-use|native",
      "description": "How this tool implements the technique",
      "commonActors": ["APT groups known to use this tool for this technique"]
    }
  ],
  "iocPatterns": [
    {
      "type": "file_hash|registry_key|network_signature|event_log|process|dns|certificate|mutex|named_pipe|service",
      "pattern": "Exact IOC pattern or regex",
      "description": "What this IOC indicates",
      "confidence": "high|medium|low",
      "volatility": "high|medium|low"
    }
  ],
  "artifacts": [
    {
      "category": "filesystem|registry|memory|network|log",
      "description": "What artifact is left behind",
      "location": "Exact path or location",
      "persistence": "permanent|temporary|volatile"
    }
  ],
  "detectionRules": [
    {
      "format": "sigma",
      "name": "Rule name",
      "rule": "Complete working Sigma rule in YAML format",
      "description": "What this rule detects",
      "falsePositiveRate": "high|medium|low"
    },
    {
      "format": "splunk_spl",
      "name": "Rule name",
      "rule": "Complete Splunk SPL query",
      "description": "What this query finds",
      "falsePositiveRate": "high|medium|low"
    },
    {
      "format": "kql",
      "name": "Rule name",
      "rule": "Complete KQL query for Microsoft Sentinel/Defender",
      "description": "What this query detects",
      "falsePositiveRate": "high|medium|low"
    }
  ],
  "eventLogSources": [
    {
      "source": "Log source name (e.g., Sysmon, Security, PowerShell)",
      "eventId": "Event ID number",
      "description": "What this event captures relevant to this technique"
    }
  ],
  "attackChainPosition": "Where this technique typically appears: initial_access|execution|persistence|privilege_escalation|defense_evasion|credential_access|discovery|lateral_movement|collection|command_and_control|exfiltration|impact",
  "prerequisiteTechniques": ["T1xxx.xxx IDs of techniques that typically precede this one"],
  "followUpTechniques": ["T1xxx.xxx IDs of techniques that typically follow this one"],
  "defensiveGaps": [
    {
      "gap": "Common defensive gap",
      "impact": "What happens if this gap exists",
      "recommendation": "How to close this gap"
    }
  ],
  "redTeamValue": 8,
  "blueTeamPriority": 7,
  "purpleTeamNotes": "Specific notes for purple team exercises using this technique",
  "environmentalConstraints": {
    "requiredOS": ["windows", "linux", "macos"],
    "requiredPrivileges": "user|admin|system|root",
    "requiredNetworkAccess": "local|internal|external|any",
    "requiredSoftware": ["Software or service that must be present"],
    "securityControlsToEvade": ["EDR", "AV", "SIEM", "firewall"],
    "commonMisconfigurations": ["Misconfiguration that enables this technique"],
    "cloudApplicability": "aws|azure|gcp|none|all",
    "containerApplicability": "docker|kubernetes|none|all"
  },
  "expectedTelemetry": {
    "processEvents": ["Process creation patterns to expect"],
    "networkSignatures": ["Network traffic patterns generated"],
    "fileSystemChanges": ["Files created, modified, or deleted"],
    "registryChanges": ["Registry keys modified (Windows)"],
    "authenticationEvents": ["Login/auth events generated"],
    "logSources": ["Specific log sources that capture this activity"],
    "detectionTimeWindow": "seconds|minutes|hours|days",
    "noiseLevel": "high|medium|low"
  }
}`,
      },
    ],
    response_format: { type: "json_object" },
  });

  const content = String(response.choices[0].message.content || "{}");
  let parsed: any;
  try {
    let cleaned = content.trim();
    if (cleaned.startsWith("```")) {
      cleaned = cleaned.replace(/^```(?:json)?\s*\n?/, "").replace(/\n?```\s*$/, "");
    }
    parsed = JSON.parse(cleaned);
  } catch {
    console.error(`[TTP Engine] Failed to parse LLM response for ${techniqueId}`);
    parsed = {};
  }

  return {
    techniqueId,
    techniqueName,
    tactic,
    description: parsed.description || `${techniqueName} - analysis pending`,
    executionMethods: parsed.executionMethods || [],
    toolsUsed: parsed.toolsUsed || [],
    iocPatterns: parsed.iocPatterns || [],
    artifacts: parsed.artifacts || [],
    detectionRules: parsed.detectionRules || [],
    eventLogSources: parsed.eventLogSources || [],
    calderaAbilities: [], // Will be populated from Cyber C2 ability catalog
    attackChainPosition: parsed.attackChainPosition || tactic,
    prerequisiteTechniques: parsed.prerequisiteTechniques || [],
    followUpTechniques: parsed.followUpTechniques || [],
    defensiveGaps: parsed.defensiveGaps || [],
    redTeamValue: parsed.redTeamValue || 5,
    blueTeamPriority: parsed.blueTeamPriority || 5,
    purpleTeamNotes: parsed.purpleTeamNotes || "",
    environmentalConstraints: parsed.environmentalConstraints || null,
    expectedTelemetry: parsed.expectedTelemetry || null,
    dataSource: "llm-enriched",
    confidence: 75,
    lastEnriched: new Date(),
  };
}

/**
 * Research and store a technique in the knowledge base.
 * If already enriched recently, skip unless force=true.
 */
export async function enrichTechnique(techniqueId: string, techniqueName: string, tactic: string, force = false): Promise<{ action: string; techniqueId: string }> {
  // Check if already enriched
  if (!force) {
    const existing = await db.getTtpKnowledge(techniqueId);
    if (existing && existing.detectionRules && (existing.detectionRules as any[]).length > 0) {
      return { action: "skipped", techniqueId };
    }
  }

  console.log(`[TTP Engine] Researching ${techniqueId}: ${techniqueName}...`);
  const knowledge = await researchTechnique(techniqueId, techniqueName, tactic);
  
  // Cross-reference with emulation abilities
  try {
    const abilities = await db.listAllAbilities({ search: techniqueId, limit: 50 });
    if (abilities && Array.isArray(abilities) && abilities.length > 0) {
      knowledge.calderaAbilities = abilities.map((a: any) => ({
        abilityId: a.abilityId,
        name: a.name,
        executor: Object.keys(a.platforms || {}).join(", "),
        command: a.description?.substring(0, 200),
      }));
    }
  } catch {
    // Abilities lookup optional
  }

  await db.upsertTtpKnowledge(knowledge);
  return { action: "enriched", techniqueId };
}

/**
 * Batch enrich multiple techniques. Processes sequentially to avoid
 * overwhelming the LLM API.
 */
export async function batchEnrichTechniques(
  techniques: Array<{ id: string; name: string; tactic: string }>,
  force = false
): Promise<{
  total: number;
  enriched: number;
  skipped: number;
  errors: number;
  results: Array<{ techniqueId: string; action: string; error?: string }>;
}> {
  const results: Array<{ techniqueId: string; action: string; error?: string }> = [];
  let enriched = 0;
  let skipped = 0;
  let errors = 0;

  for (const tech of techniques) {
    try {
      const result = await enrichTechnique(tech.id, tech.name, tech.tactic, force);
      results.push(result);
      if (result.action === "enriched") enriched++;
      else skipped++;
    } catch (err: any) {
      results.push({ techniqueId: tech.id, action: "error", error: err.message });
      errors++;
    }
  }

  return { total: techniques.length, enriched, skipped, errors, results };
}

/**
 * Generate a comprehensive system prompt for the LLM that includes
 * deep TTP knowledge for intelligent campaign design.
 */
export async function generateCampaignDesignPrompt(params: {
  targetSector: string;
  targetTechnologies: string[];
  threatActors: Array<{ name: string; techniques: Array<{ id: string; name: string; tactic: string }> }>;
  riskScore: number;
}): Promise<string> {
  // Collect all unique technique IDs from the threat actors
  const allTechniqueIds = new Set<string>();
  for (const actor of params.threatActors) {
    for (const t of actor.techniques) {
      allTechniqueIds.add(t.id);
    }
  }

  // Fetch TTP knowledge for all relevant techniques
  const ttpData: any[] = [];
  for (const techId of Array.from(allTechniqueIds)) {
    const knowledge = await db.getTtpKnowledge(techId);
    if (knowledge) {
      ttpData.push(knowledge);
    }
  }

  // Build the enhanced system prompt
  const ttpSummary = ttpData.map(t => {
    const methods = (t.executionMethods as any[] || []).slice(0, 2);
    const tools = (t.toolsUsed as any[] || []).slice(0, 3);
    const detections = (t.detectionRules as any[] || []).length;
    return `- ${t.techniqueId} (${t.techniqueName}): ${methods.length} execution methods, ${tools.length} tools, ${detections} detection rules. Chain position: ${t.attackChainPosition}. Red team value: ${t.redTeamValue}/10.`;
  }).join("\n");

  const actorSummary = params.threatActors.map(a => 
    `- ${a.name}: ${a.techniques.length} techniques`
  ).join("\n");

  return `You are an expert Red Team campaign designer with deep knowledge of adversary TTPs.

TARGET ORGANIZATION:
- Sector: ${params.targetSector}
- Technologies: ${params.targetTechnologies.join(", ")}
- Risk Score: ${params.riskScore}/100

RELEVANT THREAT ACTORS:
${actorSummary}

TTP KNOWLEDGE BASE (${ttpData.length} techniques analyzed):
${ttpSummary}

CAMPAIGN DESIGN PRINCIPLES:
1. Chain techniques in realistic attack sequences (initial access → execution → persistence → lateral movement → objective)
2. Select emulation abilities that match the threat actor's known TTPs
3. Include detection validation points for Blue Team
4. Design phishing templates that match the actor's known social engineering patterns
5. Ensure each campaign step has corresponding detection rules for SOC validation
6. Prioritize techniques with high red team value and that target the discovered technology stack

When designing campaigns, reference specific technique IDs, tool names, and detection rules from the knowledge base above.`;
}

/**
 * Generate SOC detection rules for a specific campaign or set of techniques.
 */
export async function generateDetectionRules(techniqueIds: string[]): Promise<{
  sigma: string[];
  splunk: string[];
  kql: string[];
  suricata: string[];
}> {
  const rules = { sigma: [] as string[], splunk: [] as string[], kql: [] as string[], suricata: [] as string[] };

  for (const techId of techniqueIds) {
    const knowledge = await db.getTtpKnowledge(techId);
    if (!knowledge || !knowledge.detectionRules) continue;

    for (const rule of knowledge.detectionRules as any[]) {
      switch (rule.format) {
        case "sigma": rules.sigma.push(rule.rule); break;
        case "splunk_spl": rules.splunk.push(rule.rule); break;
        case "kql": rules.kql.push(rule.rule); break;
        case "suricata": rules.suricata.push(rule.rule); break;
      }
    }
  }

  return rules;
}
