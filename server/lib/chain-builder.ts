/**
 * Intelligent Campaign Chain Builder
 * 
 * Automatically populates Cyber C2 operations with abilities based on:
 * 1. Matched threat actors and their known TTPs
 * 2. TTP Knowledge Base technique-to-ability mappings
 * 3. OSINT/Discovery findings (vulns, misconfigs)
 * 4. Domain Intel results (tech stack, open ports, posture findings)
 * 5. Campaign recommendation attack chains
 */

import { ENV } from "../_core/env";
import { invokeLLM } from "../_core/llm";
import { getLOTLContext } from "./knowledge/offensive-techniques-knowledge";

// MITRE technique to Caldera tactic mapping
const TECHNIQUE_TACTIC_MAP: Record<string, string[]> = {
  "T1566": ["initial-access"],
  "T1566.001": ["initial-access"],
  "T1566.002": ["initial-access"],
  "T1190": ["initial-access"],
  "T1078": ["initial-access", "persistence", "privilege-escalation", "defense-evasion"],
  "T1078.001": ["persistence", "privilege-escalation"],
  "T1078.004": ["initial-access", "persistence"],
  "T1595": ["reconnaissance"],
  "T1595.002": ["reconnaissance"],
  "T1059": ["execution"],
  "T1059.001": ["execution"],
  "T1059.003": ["execution"],
  "T1059.005": ["execution"],
  "T1059.006": ["execution"],
  "T1053": ["execution", "persistence", "privilege-escalation"],
  "T1068": ["privilege-escalation"],
  "T1548": ["privilege-escalation", "defense-evasion"],
  "T1134": ["privilege-escalation", "defense-evasion"],
  "T1055": ["defense-evasion", "privilege-escalation"],
  "T1027": ["defense-evasion"],
  "T1070": ["defense-evasion"],
  "T1070.004": ["defense-evasion"],
  "T1562": ["defense-evasion"],
  "T1562.001": ["defense-evasion"],
  "T1003": ["credential-access"],
  "T1003.001": ["credential-access"],
  "T1003.003": ["credential-access"],
  "T1110": ["credential-access"],
  "T1555": ["credential-access"],
  "T1552": ["credential-access"],
  "T1082": ["discovery"],
  "T1083": ["discovery"],
  "T1057": ["discovery"],
  "T1018": ["discovery"],
  "T1016": ["discovery"],
  "T1049": ["discovery"],
  "T1087": ["discovery"],
  "T1069": ["discovery"],
  "T1021": ["lateral-movement"],
  "T1021.001": ["lateral-movement"],
  "T1021.002": ["lateral-movement"],
  "T1021.004": ["lateral-movement"],
  "T1210": ["lateral-movement"],
  "T1005": ["collection"],
  "T1074": ["collection"],
  "T1560": ["collection"],
  "T1530": ["collection"],
  "T1041": ["exfiltration"],
  "T1048": ["exfiltration"],
  "T1567": ["exfiltration"],
  "T1486": ["impact"],
  "T1489": ["impact"],
  "T1071": ["command-and-control"],
  "T1071.001": ["command-and-control"],
  "T1105": ["command-and-control"],
  "T1573": ["command-and-control"],
};

interface CalderaAbility {
  ability_id: string;
  tactic: string;
  technique_id: string;
  technique_name: string;
  name: string;
  description: string;
  executors: any[];
  privilege?: string;
  plugin?: string;
}

interface AttackChainStep {
  step: number;
  phase: string;
  technique: string;
  action: string;
  tool?: string;
}

interface CampaignRecommendation {
  name: string;
  priority: string;
  attackChain: AttackChainStep[];
  targetAssets?: string[];
  objectives?: string[];
}

interface ThreatActorMatch {
  actorId: string;
  name?: string;
  matchScore: number;
  techniques?: (string | { id: string; name?: string; score?: number; tactic?: string })[];
  relevantTechniques?: (string | { id: string; name?: string; score?: number; tactic?: string })[];
}

interface ChainBuildResult {
  operationId: string;
  operationName: string;
  adversaryId: string;
  adversaryName: string;
  totalAbilities: number;
  abilitiesByTactic: Record<string, number>;
  techniquesCovered: string[];
  techniquesNotCovered: string[];
  chainOrder: Array<{
    step: number;
    abilityId: string;
    abilityName: string;
    technique: string;
    tactic: string;
    phase: string;
  }>;
}

/**
 * Build an intelligent attack chain for a Cyber C2 operation based on:
 * - Campaign recommendation attack chains
 * - Matched threat actor TTPs
 * - Available emulation abilities
 * - OSINT findings (vulns, misconfigs)
 */
export async function buildOperationChain(params: {
  operationId: string;
  scanId?: number;
  campaignRecommendation?: CampaignRecommendation;
  threatActorMatches?: ThreatActorMatch[];
  findings?: any[];
  kevSteps?: Array<{ techniqueId: string; priority: number; source: "kev"; context: string }>;
  vulnSteps?: Array<{ techniqueId: string; priority: number; source: "vuln_feed"; context: string; corroborationTier?: string }>;
  allAbilities: CalderaAbility[];
  calderaBaseUrl: string;
  calderaApiKey: string;
}): Promise<ChainBuildResult> {
  const {
    operationId,
    campaignRecommendation,
    threatActorMatches,
    findings,
    kevSteps,
    vulnSteps,
    allAbilities,
  } = params;

  // Step 1: Collect all relevant techniques from multiple sources
  const techniqueSources = collectTechniques(
    campaignRecommendation,
    threatActorMatches,
    findings,
    kevSteps,
    vulnSteps
  );

  // Step 2: Build ability index by technique
  const abilityIndex = buildAbilityIndex(allAbilities);

  // Step 3: Select best abilities for each technique in the attack chain
  const selectedAbilities = selectAbilitiesForChain(
    techniqueSources,
    abilityIndex,
    allAbilities
  );

  // Step 4: Order abilities into a logical attack chain
  const orderedChain = orderAttackChain(selectedAbilities);

  // Step 5: Create or update the Caldera adversary with the selected abilities
  const adversaryResult = await createAdversaryFromChain(
    params.calderaBaseUrl,
    params.calderaApiKey,
    operationId,
    campaignRecommendation?.name || "Auto-Generated Campaign",
    orderedChain
  );

  // Step 6: Update the operation to use the new adversary
  await updateOperationAdversary(
    params.calderaBaseUrl,
    params.calderaApiKey,
    operationId,
    adversaryResult.adversaryId
  );

  // Build result summary
  const abilitiesByTactic: Record<string, number> = {};
  orderedChain.forEach(item => {
    abilitiesByTactic[item.tactic] = (abilitiesByTactic[item.tactic] || 0) + 1;
  });

  const coveredTechniques = Array.from(new Set(orderedChain.map(a => a.techniqueId)));
  const allRequestedTechniques = Array.from(new Set(techniqueSources.map(t => t.techniqueId)));
  const notCovered = allRequestedTechniques.filter(t => !coveredTechniques.includes(t));

  return {
    operationId,
    operationName: campaignRecommendation?.name || "Auto-Generated",
    adversaryId: adversaryResult.adversaryId,
    adversaryName: adversaryResult.adversaryName,
    totalAbilities: orderedChain.length,
    abilitiesByTactic,
    techniquesCovered: coveredTechniques,
    techniquesNotCovered: notCovered,
    chainOrder: orderedChain.map((a, i) => ({
      step: i + 1,
      abilityId: a.abilityId,
      abilityName: a.abilityName,
      technique: a.techniqueId,
      tactic: a.tactic,
      phase: a.phase,
    })),
  };
}

interface TechniqueSource {
  techniqueId: string;
  source: "campaign" | "actor" | "finding" | "enrichment" | "kev";
  priority: number; // 1 = highest
  phase?: string;
  context?: string;
}

function collectTechniques(
  campaign?: CampaignRecommendation,
  actors?: ThreatActorMatch[],
  findings?: any[],
  kevSteps?: Array<{ techniqueId: string; priority: number; source: "kev"; context: string }>,
  vulnSteps?: Array<{ techniqueId: string; priority: number; source: "vuln_feed"; context: string; corroborationTier?: string }>
): TechniqueSource[] {
  const techniques: TechniqueSource[] = [];

  // From campaign attack chain (highest priority - these are the specific steps)
  if (campaign?.attackChain) {
    campaign.attackChain.forEach((step, i) => {
      const techIds = step.technique.split(",").map(t => t.trim());
      techIds.forEach(tid => {
        techniques.push({
          techniqueId: tid,
          source: "campaign",
          priority: 1,
          phase: step.phase || `Step ${step.step}`,
          context: step.action,
        });
      });
    });
  }

  // From matched threat actors (medium priority)
  if (actors) {
    actors.forEach(actor => {
      const techs = actor.techniques || actor.relevantTechniques || [];
      techs.forEach(t => {
        // Handle both string and object formats: "T1059" or { id: "T1059", name: "..." }
        const tid = typeof t === 'string' ? t : (t?.id || '');
        if (!tid) return;
        techniques.push({
          techniqueId: tid,
          source: "actor",
          priority: 2,
          context: `Used by ${actor.name || actor.actorId}`,
        });
      });
    });
  }

  // From OSINT findings (high priority for vuln-specific techniques)
  if (findings) {
    findings.forEach(finding => {
      if (finding.cve || finding.vulnerability) {
        // Map common vuln types to techniques
        const vulnTechniques = mapFindingToTechniques(finding);
        vulnTechniques.forEach(tid => {
          techniques.push({
            techniqueId: tid,
            source: "finding",
            priority: 1,
            context: `Exploiting: ${finding.title || finding.description || finding.cve}`,
          });
        });
      }
    });
  }

  // From CISA KEV (highest priority - actively exploited in the wild)
  if (kevSteps) {
    kevSteps.forEach(step => {
      techniques.push({
        techniqueId: step.techniqueId,
        source: "kev",
        priority: 1, // Same priority as campaign - these are actively exploited
        context: step.context,
      });
    });
  }

  // From vulnerability feed matches (high priority - exploits available in the wild)
  if (vulnSteps) {
    vulnSteps.forEach(step => {
      techniques.push({
        techniqueId: step.techniqueId,
        source: "enrichment",
        priority: 1, // Same as KEV - these have confirmed exploits
        context: step.context,
      });
    });
  }

  // Deduplicate, keeping highest priority
  const seen = new Map<string, TechniqueSource>();
  techniques.forEach(t => {
    const existing = seen.get(t.techniqueId);
    if (!existing || t.priority < existing.priority) {
      seen.set(t.techniqueId, t);
    }
  });

  return Array.from(seen.values());
}

function mapFindingToTechniques(finding: any): string[] {
  const techniques: string[] = [];
  const desc = (finding.title || finding.description || "").toLowerCase();

  if (desc.includes("sql injection") || desc.includes("sqli")) techniques.push("T1190");
  if (desc.includes("xss") || desc.includes("cross-site scripting")) techniques.push("T1190");
  if (desc.includes("rce") || desc.includes("remote code execution")) techniques.push("T1190", "T1059");
  if (desc.includes("default credential") || desc.includes("weak password")) techniques.push("T1078.001", "T1110");
  if (desc.includes("open port") || desc.includes("exposed service")) techniques.push("T1595.002");
  if (desc.includes("ssl") || desc.includes("tls") || desc.includes("certificate")) techniques.push("T1557");
  if (desc.includes("directory listing") || desc.includes("information disclosure")) techniques.push("T1083");
  if (desc.includes("missing header") || desc.includes("cors")) techniques.push("T1190");
  if (desc.includes("outdated") || desc.includes("unpatched")) techniques.push("T1190", "T1210");
  if (desc.includes("phishing")) techniques.push("T1566.001", "T1566.002");
  if (desc.includes("privilege") || desc.includes("escalation")) techniques.push("T1068");
  if (desc.includes("lateral") || desc.includes("smb") || desc.includes("rdp")) techniques.push("T1021", "T1210");
  if (desc.includes("exfiltration") || desc.includes("data leak")) techniques.push("T1041", "T1567");
  if (desc.includes("cloud") || desc.includes("s3") || desc.includes("bucket")) techniques.push("T1530");
  if (desc.includes("dns") || desc.includes("zone transfer")) techniques.push("T1071.004");

  return Array.from(new Set(techniques));
}

interface AbilityMatch {
  abilityId: string;
  abilityName: string;
  techniqueId: string;
  tactic: string;
  phase: string;
  score: number;
  executorCount: number;
  description: string;
}

function buildAbilityIndex(abilities: CalderaAbility[]): Map<string, CalderaAbility[]> {
  const index = new Map<string, CalderaAbility[]>();
  abilities.forEach(a => {
    const tid = a.technique_id;
    if (!tid) return;
    // Handle multi-technique abilities (e.g., "T1190, T1210")
    const tids = tid.split(",").map(t => t.trim());
    tids.forEach(t => {
      if (!index.has(t)) index.set(t, []);
      index.get(t)!.push(a);
    });
  });
  return index;
}

function selectAbilitiesForChain(
  techniques: TechniqueSource[],
  abilityIndex: Map<string, CalderaAbility[]>,
  allAbilities: CalderaAbility[]
): AbilityMatch[] {
  const selected: AbilityMatch[] = [];
  const usedAbilityIds = new Set<string>();

  // Phase 1: Direct technique matches
  techniques.forEach(tech => {
    // Safety: ensure techniqueId is a string
    if (!tech.techniqueId || typeof tech.techniqueId !== 'string') return;
    const candidates = abilityIndex.get(tech.techniqueId) || [];
    if (candidates.length === 0) {
      // Try parent technique (e.g., T1059.001 -> T1059)
      const parent = String(tech.techniqueId).split(".")[0];
      const parentCandidates = abilityIndex.get(parent) || [];
      if (parentCandidates.length > 0) {
        const best = selectBestAbility(parentCandidates, usedAbilityIds);
        if (best) {
          usedAbilityIds.add(best.ability_id);
          selected.push({
            abilityId: best.ability_id,
            abilityName: best.name,
            techniqueId: tech.techniqueId,
            tactic: best.tactic,
            phase: tech.phase || mapTacticToPhase(best.tactic),
            score: tech.priority,
            executorCount: best.executors?.length || 0,
            description: best.description || "",
          });
        }
      }
      return;
    }

    // Select the best ability for this technique
    const best = selectBestAbility(candidates, usedAbilityIds);
    if (best) {
      usedAbilityIds.add(best.ability_id);
      selected.push({
        abilityId: best.ability_id,
        abilityName: best.name,
        techniqueId: tech.techniqueId,
        tactic: best.tactic,
        phase: tech.phase || mapTacticToPhase(best.tactic),
        score: tech.priority,
        executorCount: best.executors?.length || 0,
        description: best.description || "",
      });
    }
  });

  // Phase 2: Fill gaps - add essential discovery/collection abilities if missing
  const coveredTactics = new Set(selected.map(a => a.tactic));
  const essentialTactics = ["discovery", "credential-access", "defense-evasion", "collection"];
  essentialTactics.forEach(tactic => {
    if (!coveredTactics.has(tactic)) {
      const tacticAbilities = allAbilities.filter(a => a.tactic === tactic);
      const best = selectBestAbility(tacticAbilities, usedAbilityIds);
      if (best) {
        usedAbilityIds.add(best.ability_id);
        selected.push({
          abilityId: best.ability_id,
          abilityName: best.name,
          techniqueId: best.technique_id,
          tactic: best.tactic,
          phase: mapTacticToPhase(best.tactic),
          score: 3,
          executorCount: best.executors?.length || 0,
          description: best.description || "",
        });
      }
    }
  });

  return selected;
}

function selectBestAbility(
  candidates: CalderaAbility[],
  usedIds: Set<string>
): CalderaAbility | null {
  // Filter out already-used abilities
  const available = candidates.filter(a => !usedIds.has(a.ability_id));
  if (available.length === 0) return candidates[0] || null;

  // Score each ability
  const scored = available.map(a => {
    let score = 0;
    // Prefer abilities with more executors (more versatile)
    score += (a.executors?.length || 0) * 2;
    // Prefer abilities from stockpile plugin (official)
    if (a.plugin === "stockpile") score += 5;
    // Prefer abilities with descriptions
    if (a.description && a.description.length > 20) score += 3;
    // Prefer abilities that don't require elevated privileges
    if (!a.privilege || a.privilege === "User") score += 2;
    return { ability: a, score };
  });

  scored.sort((a, b) => b.score - a.score);
  return scored[0]?.ability || null;
}

function mapTacticToPhase(tactic: string): string {
  const phaseMap: Record<string, string> = {
    "reconnaissance": "Reconnaissance",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command & Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "multiple": "Multiple",
  };
  return phaseMap[tactic] || tactic;
}

// Kill chain phase ordering for logical attack progression
const PHASE_ORDER = [
  "Reconnaissance",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command & Control",
  "Exfiltration",
  "Impact",
  "Multiple",
];

function orderAttackChain(abilities: AbilityMatch[]): AbilityMatch[] {
  return abilities.sort((a, b) => {
    const aIdx = PHASE_ORDER.indexOf(a.phase);
    const bIdx = PHASE_ORDER.indexOf(b.phase);
    if (aIdx !== bIdx) return aIdx - bIdx;
    return a.score - b.score; // Higher priority first within same phase
  });
}

async function createAdversaryFromChain(
  baseUrl: string,
  apiKey: string,
  operationId: string,
  campaignName: string,
  chain: AbilityMatch[]
): Promise<{ adversaryId: string; adversaryName: string }> {
  const adversaryName = `auto-chain-${campaignName.replace(/[^a-zA-Z0-9]/g, "-").toLowerCase().substring(0, 50)}-${Date.now().toString(36)}`;
  const abilityIds = chain.map(a => a.abilityId);

  const response = await fetch(`${baseUrl}/api/v2/adversaries`, {
    method: "POST",
    headers: {
      "KEY": apiKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      name: adversaryName,
      description: `Auto-generated adversary for operation ${operationId}. Campaign: ${campaignName}. ${chain.length} abilities across ${new Set(chain.map(a => a.tactic)).size} tactics.`,
      atomic_ordering: abilityIds,
      objective: "",
      tags: ["auto-generated", "chain-builder"],
    }),
  });

  if (!response.ok) {
    throw new Error(`Failed to create adversary: ${response.status} ${await response.text()}`);
  }

  const adversary = await response.json() as any;
  return {
    adversaryId: adversary.adversary_id,
    adversaryName: adversary.name,
  };
}

async function updateOperationAdversary(
  baseUrl: string,
  apiKey: string,
  operationId: string,
  adversaryId: string
): Promise<void> {
  const response = await fetch(`${baseUrl}/api/v2/operations/${operationId}`, {
    method: "PATCH",
    headers: {
      "KEY": apiKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      adversary: { adversary_id: adversaryId },
    }),
  });

  if (!response.ok) {
    const text = await response.text();
    console.warn(`Warning: Could not update operation adversary: ${response.status} ${text}`);
  }
}

/**
 * Use LLM to intelligently select and order abilities for a specific campaign
 * based on the target organization's profile and vulnerabilities
 */
export async function buildChainWithLLM(params: {
  campaignRecommendation: CampaignRecommendation;
  orgProfile: any;
  findings: any[];
  threatActors: ThreatActorMatch[];
  availableAbilities: CalderaAbility[];
}): Promise<{
  selectedAbilities: string[];
  reasoning: string;
  attackNarrative: string;
}> {
  const { campaignRecommendation, orgProfile, findings, threatActors, availableAbilities } = params;

  // Build a concise ability catalog for the LLM
  const abilityCatalog = availableAbilities
    .filter(a => a.technique_id)
    .slice(0, 200) // Limit to avoid token overflow
    .map(a => ({
      id: a.ability_id,
      name: a.name,
      technique: a.technique_id,
      tactic: a.tactic,
      desc: (a.description || "").substring(0, 100),
    }));

  const prompt = `You are an expert Red Team operator designing a Caldera adversary emulation campaign.

CAMPAIGN: ${campaignRecommendation.name}
PRIORITY: ${campaignRecommendation.priority}
ATTACK CHAIN:
${campaignRecommendation.attackChain.map(s => `  Step ${s.step} (${s.phase}): ${s.technique} - ${s.action}`).join("\n")}

ORGANIZATION PROFILE:
${JSON.stringify(orgProfile || {}, null, 2).substring(0, 500)}

KEY FINDINGS:
${(findings || []).slice(0, 10).map(f => `- ${f.title || f.description}`).join("\n")}

MATCHED THREAT ACTORS:
${(threatActors || []).slice(0, 5).map(a => `- ${a.name || a.actorId} (score: ${a.matchScore})`).join("\n")}

AVAILABLE CALDERA ABILITIES (sample):
${JSON.stringify(abilityCatalog.slice(0, 50), null, 2)}

Select the 15-30 most appropriate abilities from the catalog that best match this campaign's attack chain. 
Order them in logical execution sequence. For each, explain why it was selected.

Return JSON:
{
  "selectedAbilities": ["ability_id_1", "ability_id_2", ...],
  "reasoning": "Brief explanation of selection logic",
  "attackNarrative": "Step-by-step narrative of how the attack would unfold"
}`;

  try {
    const response = await invokeLLM({ _priority: 'essential',
      messages: [
        { role: "system", content: `You are an expert adversary emulation engineer. Return valid JSON only.

${getLOTLContext()}

When selecting abilities, prefer those that leverage Living Off the Land techniques (native OS binaries, legitimate tools) for stealth. Prioritize LOLBAS/GTFOBins-based abilities for execution, persistence, and defense evasion phases.` },
        { role: "user", content: prompt },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "chain_selection",
          strict: true,
          schema: {
            type: "object",
            properties: {
              selectedAbilities: { type: "array", items: { type: "string" } },
              reasoning: { type: "string" },
              attackNarrative: { type: "string" },
            },
            required: ["selectedAbilities", "reasoning", "attackNarrative"],
            additionalProperties: false,
          },
        },
      },
    });

    const rawContent = response.choices?.[0]?.message?.content || "{}";
    const content = typeof rawContent === 'string' ? rawContent : JSON.stringify(rawContent);
    return JSON.parse(content);
  } catch (error) {
    console.error("LLM chain building failed, falling back to rule-based:", error);
    return {
      selectedAbilities: [],
      reasoning: "LLM unavailable, using rule-based selection",
      attackNarrative: "",
    };
  }
}

/**
 * Auto-build chains for all paused operations that don't have chains yet
 */
export async function autoBuildAllChains(params: {
  calderaBaseUrl: string;
  calderaApiKey: string;
  scanData?: {
    pipelineOutput: any;
    findings?: any[];
  };
  vulnSteps?: Array<{ techniqueId: string; priority: number; source: "vuln_feed"; context: string; corroborationTier?: string }>;
}): Promise<ChainBuildResult[]> {
  const { calderaBaseUrl, calderaApiKey, scanData, vulnSteps } = params;

  // Fetch all operations
  const opsResponse = await fetch(`${calderaBaseUrl}/api/v2/operations`, {
    headers: { KEY: calderaApiKey },
  });
  const operations = await opsResponse.json() as any[];

  // Fetch all abilities
  const abilitiesResponse = await fetch(`${calderaBaseUrl}/api/v2/abilities`, {
    headers: { KEY: calderaApiKey },
  });
  const allAbilities = await abilitiesResponse.json() as CalderaAbility[];

  // Find paused operations with no chain steps
  const pausedOps = operations.filter(
    (op: any) => op.state === "paused" && (!op.chain || op.chain.length === 0)
  );

  const results: ChainBuildResult[] = [];

  // Get campaign recommendations and threat actor matches from scan data
  const campaigns = scanData?.pipelineOutput?.campaignRecommendations || [];
  const actorMatches = scanData?.pipelineOutput?.threatActorMatches?.topMatches || [];
  const findings = scanData?.findings || [];
  const kevChainSteps = scanData?.pipelineOutput?.kevEnrichment?.chainSteps || [];

  for (const op of pausedOps) {
    try {
      // Try to match this operation to a campaign recommendation
      const matchedCampaign = findMatchingCampaign(op, campaigns);

      const result = await buildOperationChain({
        operationId: op.id,
        campaignRecommendation: matchedCampaign || {
          name: op.name,
          priority: "high",
          attackChain: generateDefaultChain(op, actorMatches),
        },
        threatActorMatches: actorMatches,
        findings,
        kevSteps: kevChainSteps,
        vulnSteps,
        allAbilities,
        calderaBaseUrl,
        calderaApiKey,
      });

      results.push(result);
    } catch (error) {
      console.error(`Failed to build chain for operation ${op.id}:`, error);
    }
  }

  return results;
}

function findMatchingCampaign(
  operation: any,
  campaigns: CampaignRecommendation[]
): CampaignRecommendation | null {
  const opName = (operation.name || "").toLowerCase();
  const advName = (operation.adversary?.name || "").toLowerCase();

  for (const campaign of campaigns) {
    const cName = (campaign.name || "").toLowerCase();
    // Check for keyword overlap
    const keywords = cName.split(/\s+/);
    const matchCount = keywords.filter(
      k => k.length > 3 && (opName.includes(k) || advName.includes(k))
    ).length;
    if (matchCount >= 2) return campaign;
  }

  return null;
}

function generateDefaultChain(
  operation: any,
  actorMatches: ThreatActorMatch[]
): AttackChainStep[] {
  // Build a default attack chain based on the adversary's known techniques
  const adversary = operation.adversary;
  const chain: AttackChainStep[] = [];
  let step = 1;

  // Standard kill chain phases
  const phases = [
    { phase: "Reconnaissance", techniques: ["T1595.002", "T1592"] },
    { phase: "Initial Access", techniques: ["T1566.001", "T1190"] },
    { phase: "Execution", techniques: ["T1059.001", "T1059.003"] },
    { phase: "Persistence", techniques: ["T1053", "T1078"] },
    { phase: "Privilege Escalation", techniques: ["T1068", "T1548"] },
    { phase: "Defense Evasion", techniques: ["T1027", "T1070.004"] },
    { phase: "Credential Access", techniques: ["T1003.001", "T1555"] },
    { phase: "Discovery", techniques: ["T1082", "T1083", "T1057"] },
    { phase: "Lateral Movement", techniques: ["T1021.001", "T1210"] },
    { phase: "Collection", techniques: ["T1005", "T1074"] },
    { phase: "Exfiltration", techniques: ["T1041", "T1567"] },
  ];

  phases.forEach(p => {
    p.techniques.forEach(t => {
      chain.push({
        step: step++,
        phase: p.phase,
        technique: t,
        action: `Execute ${t} during ${p.phase} phase`,
      });
    });
  });

  return chain;
}
