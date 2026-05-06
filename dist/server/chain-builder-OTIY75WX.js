import {
  getLOTLContext,
  init_offensive_techniques_knowledge
} from "./chunk-PUZE3GU2.js";
import "./chunk-5TJ6FS74.js";
import "./chunk-UYX5D64U.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-7ZNGVPYR.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-KFQGP6VL.js";

// server/lib/chain-builder.ts
init_llm();
init_offensive_techniques_knowledge();
async function buildOperationChain(params) {
  const {
    operationId,
    campaignRecommendation,
    threatActorMatches,
    findings,
    kevSteps,
    vulnSteps,
    allAbilities
  } = params;
  const techniqueSources = collectTechniques(
    campaignRecommendation,
    threatActorMatches,
    findings,
    kevSteps,
    vulnSteps
  );
  const abilityIndex = buildAbilityIndex(allAbilities);
  const selectedAbilities = selectAbilitiesForChain(
    techniqueSources,
    abilityIndex,
    allAbilities
  );
  const orderedChain = orderAttackChain(selectedAbilities);
  const adversaryResult = await createAdversaryFromChain(
    params.calderaBaseUrl,
    params.calderaApiKey,
    operationId,
    campaignRecommendation?.name || "Auto-Generated Campaign",
    orderedChain
  );
  await updateOperationAdversary(
    params.calderaBaseUrl,
    params.calderaApiKey,
    operationId,
    adversaryResult.adversaryId
  );
  const abilitiesByTactic = {};
  orderedChain.forEach((item) => {
    abilitiesByTactic[item.tactic] = (abilitiesByTactic[item.tactic] || 0) + 1;
  });
  const coveredTechniques = Array.from(new Set(orderedChain.map((a) => a.techniqueId)));
  const allRequestedTechniques = Array.from(new Set(techniqueSources.map((t) => t.techniqueId)));
  const notCovered = allRequestedTechniques.filter((t) => !coveredTechniques.includes(t));
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
      phase: a.phase
    }))
  };
}
function collectTechniques(campaign, actors, findings, kevSteps, vulnSteps) {
  const techniques = [];
  if (campaign?.attackChain) {
    campaign.attackChain.forEach((step, i) => {
      const techIds = step.technique.split(",").map((t) => t.trim());
      techIds.forEach((tid) => {
        techniques.push({
          techniqueId: tid,
          source: "campaign",
          priority: 1,
          phase: step.phase || `Step ${step.step}`,
          context: step.action
        });
      });
    });
  }
  if (actors) {
    actors.forEach((actor) => {
      const techs = actor.techniques || actor.relevantTechniques || [];
      techs.forEach((t) => {
        const tid = typeof t === "string" ? t : t?.id || "";
        if (!tid) return;
        techniques.push({
          techniqueId: tid,
          source: "actor",
          priority: 2,
          context: `Used by ${actor.name || actor.actorId}`
        });
      });
    });
  }
  if (findings) {
    findings.forEach((finding) => {
      if (finding.cve || finding.vulnerability) {
        const vulnTechniques = mapFindingToTechniques(finding);
        vulnTechniques.forEach((tid) => {
          techniques.push({
            techniqueId: tid,
            source: "finding",
            priority: 1,
            context: `Exploiting: ${finding.title || finding.description || finding.cve}`
          });
        });
      }
    });
  }
  if (kevSteps) {
    kevSteps.forEach((step) => {
      techniques.push({
        techniqueId: step.techniqueId,
        source: "kev",
        priority: 1,
        // Same priority as campaign - these are actively exploited
        context: step.context
      });
    });
  }
  if (vulnSteps) {
    vulnSteps.forEach((step) => {
      techniques.push({
        techniqueId: step.techniqueId,
        source: "enrichment",
        priority: 1,
        // Same as KEV - these have confirmed exploits
        context: step.context
      });
    });
  }
  const seen = /* @__PURE__ */ new Map();
  techniques.forEach((t) => {
    const existing = seen.get(t.techniqueId);
    if (!existing || t.priority < existing.priority) {
      seen.set(t.techniqueId, t);
    }
  });
  return Array.from(seen.values());
}
function mapFindingToTechniques(finding) {
  const techniques = [];
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
function buildAbilityIndex(abilities) {
  const index = /* @__PURE__ */ new Map();
  abilities.forEach((a) => {
    const tid = a.technique_id;
    if (!tid) return;
    const tids = tid.split(",").map((t) => t.trim());
    tids.forEach((t) => {
      if (!index.has(t)) index.set(t, []);
      index.get(t).push(a);
    });
  });
  return index;
}
function selectAbilitiesForChain(techniques, abilityIndex, allAbilities) {
  const selected = [];
  const usedAbilityIds = /* @__PURE__ */ new Set();
  techniques.forEach((tech) => {
    if (!tech.techniqueId || typeof tech.techniqueId !== "string") return;
    const candidates = abilityIndex.get(tech.techniqueId) || [];
    if (candidates.length === 0) {
      const parent = String(tech.techniqueId).split(".")[0];
      const parentCandidates = abilityIndex.get(parent) || [];
      if (parentCandidates.length > 0) {
        const best2 = selectBestAbility(parentCandidates, usedAbilityIds);
        if (best2) {
          usedAbilityIds.add(best2.ability_id);
          selected.push({
            abilityId: best2.ability_id,
            abilityName: best2.name,
            techniqueId: tech.techniqueId,
            tactic: best2.tactic,
            phase: tech.phase || mapTacticToPhase(best2.tactic),
            score: tech.priority,
            executorCount: best2.executors?.length || 0,
            description: best2.description || ""
          });
        }
      }
      return;
    }
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
        description: best.description || ""
      });
    }
  });
  const coveredTactics = new Set(selected.map((a) => a.tactic));
  const essentialTactics = ["discovery", "credential-access", "defense-evasion", "collection"];
  essentialTactics.forEach((tactic) => {
    if (!coveredTactics.has(tactic)) {
      const tacticAbilities = allAbilities.filter((a) => a.tactic === tactic);
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
          description: best.description || ""
        });
      }
    }
  });
  return selected;
}
function selectBestAbility(candidates, usedIds) {
  const available = candidates.filter((a) => !usedIds.has(a.ability_id));
  if (available.length === 0) return candidates[0] || null;
  const scored = available.map((a) => {
    let score = 0;
    score += (a.executors?.length || 0) * 2;
    if (a.plugin === "stockpile") score += 5;
    if (a.description && a.description.length > 20) score += 3;
    if (!a.privilege || a.privilege === "User") score += 2;
    return { ability: a, score };
  });
  scored.sort((a, b) => b.score - a.score);
  return scored[0]?.ability || null;
}
function mapTacticToPhase(tactic) {
  const phaseMap = {
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
    "multiple": "Multiple"
  };
  return phaseMap[tactic] || tactic;
}
var PHASE_ORDER = [
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
  "Multiple"
];
function orderAttackChain(abilities) {
  return abilities.sort((a, b) => {
    const aIdx = PHASE_ORDER.indexOf(a.phase);
    const bIdx = PHASE_ORDER.indexOf(b.phase);
    if (aIdx !== bIdx) return aIdx - bIdx;
    return a.score - b.score;
  });
}
async function createAdversaryFromChain(baseUrl, apiKey, operationId, campaignName, chain) {
  const adversaryName = `auto-chain-${campaignName.replace(/[^a-zA-Z0-9]/g, "-").toLowerCase().substring(0, 50)}-${Date.now().toString(36)}`;
  const abilityIds = chain.map((a) => a.abilityId);
  const response = await fetch(`${baseUrl}/api/v2/adversaries`, {
    method: "POST",
    headers: {
      "KEY": apiKey,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      name: adversaryName,
      description: `Auto-generated adversary for operation ${operationId}. Campaign: ${campaignName}. ${chain.length} abilities across ${new Set(chain.map((a) => a.tactic)).size} tactics.`,
      atomic_ordering: abilityIds,
      objective: "",
      tags: ["auto-generated", "chain-builder"]
    })
  });
  if (!response.ok) {
    throw new Error(`Failed to create adversary: ${response.status} ${await response.text()}`);
  }
  const adversary = await response.json();
  return {
    adversaryId: adversary.adversary_id,
    adversaryName: adversary.name
  };
}
async function updateOperationAdversary(baseUrl, apiKey, operationId, adversaryId) {
  const response = await fetch(`${baseUrl}/api/v2/operations/${operationId}`, {
    method: "PATCH",
    headers: {
      "KEY": apiKey,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      adversary: { adversary_id: adversaryId }
    })
  });
  if (!response.ok) {
    const text = await response.text();
    console.warn(`Warning: Could not update operation adversary: ${response.status} ${text}`);
  }
}
async function buildChainWithLLM(params) {
  const { campaignRecommendation, orgProfile, findings, threatActors, availableAbilities } = params;
  const abilityCatalog = availableAbilities.filter((a) => a.technique_id).slice(0, 200).map((a) => ({
    id: a.ability_id,
    name: a.name,
    technique: a.technique_id,
    tactic: a.tactic,
    desc: (a.description || "").substring(0, 100)
  }));
  const prompt = `You are an expert Red Team operator designing a Caldera adversary emulation campaign.

CAMPAIGN: ${campaignRecommendation.name}
PRIORITY: ${campaignRecommendation.priority}
ATTACK CHAIN:
${campaignRecommendation.attackChain.map((s) => `  Step ${s.step} (${s.phase}): ${s.technique} - ${s.action}`).join("\n")}

ORGANIZATION PROFILE:
${JSON.stringify(orgProfile || {}, null, 2).substring(0, 500)}

KEY FINDINGS:
${(findings || []).slice(0, 10).map((f) => `- ${f.title || f.description}`).join("\n")}

MATCHED THREAT ACTORS:
${(threatActors || []).slice(0, 5).map((a) => `- ${a.name || a.actorId} (score: ${a.matchScore})`).join("\n")}

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
    const response = await invokeLLM({
      _caller: "chain-builder.buildChainWithLLM",
      _priority: "essential",
      messages: [
        { role: "system", content: `You are an expert adversary emulation engineer. Return valid JSON only.

${getLOTLContext()}

When selecting abilities, prefer those that leverage Living Off the Land techniques (native OS binaries, legitimate tools) for stealth. Prioritize LOLBAS/GTFOBins-based abilities for execution, persistence, and defense evasion phases.` },
        { role: "user", content: prompt }
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
              attackNarrative: { type: "string" }
            },
            required: ["selectedAbilities", "reasoning", "attackNarrative"],
            additionalProperties: false
          }
        }
      }
    });
    const rawContent = response.choices?.[0]?.message?.content || "{}";
    const content = typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent);
    return JSON.parse(content);
  } catch (error) {
    console.error("LLM chain building failed, falling back to rule-based:", error);
    return {
      selectedAbilities: [],
      reasoning: "LLM unavailable, using rule-based selection",
      attackNarrative: ""
    };
  }
}
async function autoBuildAllChains(params) {
  const { calderaBaseUrl, calderaApiKey, scanData, vulnSteps } = params;
  const opsResponse = await fetch(`${calderaBaseUrl}/api/v2/operations`, {
    headers: { KEY: calderaApiKey }
  });
  const operations = await opsResponse.json();
  const abilitiesResponse = await fetch(`${calderaBaseUrl}/api/v2/abilities`, {
    headers: { KEY: calderaApiKey }
  });
  const allAbilities = await abilitiesResponse.json();
  const pausedOps = operations.filter(
    (op) => op.state === "paused" && (!op.chain || op.chain.length === 0)
  );
  const results = [];
  const campaigns = scanData?.pipelineOutput?.campaignRecommendations || [];
  const actorMatches = scanData?.pipelineOutput?.threatActorMatches?.topMatches || [];
  const findings = scanData?.findings || [];
  const kevChainSteps = scanData?.pipelineOutput?.kevEnrichment?.chainSteps || [];
  for (const op of pausedOps) {
    try {
      const matchedCampaign = findMatchingCampaign(op, campaigns);
      const result = await buildOperationChain({
        operationId: op.id,
        campaignRecommendation: matchedCampaign || {
          name: op.name,
          priority: "high",
          attackChain: generateDefaultChain(op, actorMatches)
        },
        threatActorMatches: actorMatches,
        findings,
        kevSteps: kevChainSteps,
        vulnSteps,
        allAbilities,
        calderaBaseUrl,
        calderaApiKey
      });
      results.push(result);
    } catch (error) {
      console.error(`Failed to build chain for operation ${op.id}:`, error);
    }
  }
  return results;
}
function findMatchingCampaign(operation, campaigns) {
  const opName = (operation.name || "").toLowerCase();
  const advName = (operation.adversary?.name || "").toLowerCase();
  for (const campaign of campaigns) {
    const cName = (campaign.name || "").toLowerCase();
    const keywords = cName.split(/\s+/);
    const matchCount = keywords.filter(
      (k) => k.length > 3 && (opName.includes(k) || advName.includes(k))
    ).length;
    if (matchCount >= 2) return campaign;
  }
  return null;
}
function generateDefaultChain(operation, actorMatches) {
  const adversary = operation.adversary;
  const chain = [];
  let step = 1;
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
    { phase: "Exfiltration", techniques: ["T1041", "T1567"] }
  ];
  phases.forEach((p) => {
    p.techniques.forEach((t) => {
      chain.push({
        step: step++,
        phase: p.phase,
        technique: t,
        action: `Execute ${t} during ${p.phase} phase`
      });
    });
  });
  return chain;
}
export {
  autoBuildAllChains,
  buildChainWithLLM,
  buildOperationChain
};
