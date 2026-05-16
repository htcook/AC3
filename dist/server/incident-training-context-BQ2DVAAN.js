import {
  getDITrainingExamplesForDomain,
  getDITrainingExamplesForSector,
  getHighQualityDITrainingExamples,
  incrementDITrainingUsage,
  init_db
} from "./chunk-CKIMRR6W.js";
import "./chunk-KDOLKO2A.js";
import "./chunk-Q4QB2XQC.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/incident-training-context.ts
function estimateTokens(text) {
  return Math.ceil(text.length / 4);
}
function extractAssistantContent(example) {
  try {
    const messages = typeof example.trainingMessages === "string" ? JSON.parse(example.trainingMessages) : example.trainingMessages;
    const assistant = messages.find((m) => m.role === "assistant");
    return assistant?.content || "";
  } catch {
    return "";
  }
}
function buildContextBlock(example) {
  const content = extractAssistantContent(example);
  if (!content) return "";
  const typeLabel = {
    incident_context: "Incident History",
    actor_attribution: "Threat Actor Intelligence",
    breach_pattern: "Breach Intelligence",
    ransomware_profile: "Ransomware Intelligence",
    attack_surface_map: "Attack Surface Intelligence"
  };
  const label = typeLabel[example.exampleType] || "Intelligence";
  const qualityTag = example.analystRating === "accurate" ? " [VERIFIED]" : "";
  const truncated = content.length > 400 ? content.slice(0, 400) + "..." : content;
  return `### ${label} \u2014 ${example.domain}${qualityTag}
${truncated}`;
}
async function getIncidentTrainingContext(domain, sector, config = {}) {
  const {
    maxExamples = 5,
    maxTokenBudget = 2e3,
    prioritizeSameDomain = true,
    prioritizeSameSector = true
  } = config;
  const selectedExamples = [];
  const usedIds = /* @__PURE__ */ new Set();
  let tokenCount = 0;
  const sources = { sameDomain: 0, sameSector: 0, highQuality: 0 };
  function addExamples(examples, source) {
    for (const ex of examples) {
      if (selectedExamples.length >= maxExamples) break;
      if (usedIds.has(ex.exampleId)) continue;
      if (ex.qualityBand === "rejected") continue;
      const block = buildContextBlock(ex);
      const blockTokens = estimateTokens(block);
      if (tokenCount + blockTokens > maxTokenBudget) continue;
      selectedExamples.push(ex);
      usedIds.add(ex.exampleId);
      tokenCount += blockTokens;
      sources[source]++;
    }
  }
  try {
    if (prioritizeSameDomain) {
      const domainExamples = await getDITrainingExamplesForDomain(domain, 10);
      addExamples(domainExamples, "sameDomain");
    }
    if (prioritizeSameSector && sector && selectedExamples.length < maxExamples) {
      const sectorExamples = await getDITrainingExamplesForSector(sector, 20);
      addExamples(sectorExamples, "sameSector");
    }
    if (selectedExamples.length < maxExamples) {
      const highQuality = await getHighQualityDITrainingExamples(20);
      addExamples(highQuality, "highQuality");
    }
    if (selectedExamples.length === 0) {
      return {
        systemPromptAddition: "",
        exampleIds: [],
        totalExamplesUsed: 0,
        sources
      };
    }
    const contextBlocks = selectedExamples.map(buildContextBlock).filter(Boolean);
    const systemPromptAddition = [
      "\n\n## Historical Incident Intelligence Context",
      "",
      "The following intelligence was gathered from previous scans and analyst-verified assessments.",
      "Use this context to enrich your analysis of the current target. Cross-reference known actors,",
      "TTPs, and breach patterns with the current domain's findings.",
      "",
      ...contextBlocks,
      "",
      "---"
    ].join("\n");
    const exampleIds = selectedExamples.map((e) => e.exampleId);
    await incrementDITrainingUsage(exampleIds);
    return {
      systemPromptAddition,
      exampleIds,
      totalExamplesUsed: selectedExamples.length,
      sources
    };
  } catch (err) {
    console.error("[TrainingContext] Error building context:", err);
    return {
      systemPromptAddition: "",
      exampleIds: [],
      totalExamplesUsed: 0,
      sources
    };
  }
}
async function getIncidentSearchPromptContext(domain, sector) {
  const context = await getIncidentTrainingContext(domain, sector, {
    maxExamples: 3,
    maxTokenBudget: 1e3
  });
  return context.systemPromptAddition;
}
var init_incident_training_context = __esm({
  "server/lib/incident-training-context.ts"() {
    init_db();
  }
});
init_incident_training_context();
export {
  getIncidentSearchPromptContext,
  getIncidentTrainingContext
};
