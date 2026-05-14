import {
  init_llm,
  invokeLLM
} from "./chunk-WJ24GKGB.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-KFQGP6VL.js";

// server/lib/threat-actor-classifier.ts
init_llm();
var currentBatchProgress = {
  total: 0,
  processed: 0,
  succeeded: 0,
  failed: 0,
  results: [],
  errors: [],
  status: "idle",
  startedAt: null,
  completedAt: null
};
var cancelRequested = false;
function getProgress() {
  return { ...currentBatchProgress };
}
function cancelBatch() {
  cancelRequested = true;
}
function resetProgress() {
  currentBatchProgress = {
    total: 0,
    processed: 0,
    succeeded: 0,
    failed: 0,
    results: [],
    errors: [],
    status: "idle",
    startedAt: null,
    completedAt: null
  };
  cancelRequested = false;
}
async function classifyActor(actor) {
  const profileSummary = buildProfileSummary(actor);
  const response = await invokeLLM({
    messages: [
      {
        role: "system",
        content: `You are a cyber threat intelligence analyst specializing in threat actor classification. 
Your task is to classify threat actors into one of these categories based on their profile data:

- **apt**: Nation-state sponsored or state-affiliated advanced persistent threat groups. Key indicators: government sponsorship, long-term espionage campaigns, sophisticated custom tooling, targeting government/military/critical infrastructure, specific nation-state attribution.
- **ransomware**: Groups primarily conducting ransomware operations. Key indicators: ransomware deployment, double/triple extortion, data leak sites, RaaS (Ransomware-as-a-Service) operations, financial motivation through encryption.
- **cybercrime**: Financially motivated criminal groups not primarily focused on ransomware. Key indicators: banking trojans, credit card fraud, BEC scams, credential theft for sale, cryptomining, general financial fraud.
- **hacktivist**: Ideologically or politically motivated groups. Key indicators: DDoS campaigns for political causes, website defacement, data leaks for activism, anti-government/corporate messaging, loose organizational structure.
- **access_broker**: Groups that specialize in selling initial access to compromised networks. Key indicators: selling RDP/VPN access, credential harvesting for resale, operating on dark web marketplaces, enabling other threat actors.
- **influence_ops**: Groups conducting information operations and disinformation campaigns. Key indicators: social media manipulation, fake news propagation, election interference, coordinated inauthentic behavior, propaganda.

Analyze ALL available data carefully. Consider:
1. Primary motivation (espionage, financial, ideological, access sales, information warfare)
2. TTPs and their alignment with known actor categories
3. Tools and malware used (custom vs commodity)
4. Target sectors and regions (government targets suggest APT, financial targets suggest cybercrime)
5. Sophistication level
6. Origin country (some countries are known for state-sponsored APT activity)

Be precise and provide clear reasoning.`
      },
      {
        role: "user",
        content: `Classify this threat actor:

${profileSummary}`
      }
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "threat_actor_classification",
        strict: true,
        schema: {
          type: "object",
          properties: {
            classifiedType: {
              type: "string",
              enum: ["apt", "ransomware", "cybercrime", "hacktivist", "access_broker", "influence_ops"],
              description: "The primary classification for this threat actor"
            },
            confidence: {
              type: "number",
              description: "Confidence level 0-100. Use 90+ for clear-cut cases, 70-89 for strong indicators, 50-69 for moderate evidence, below 50 for weak/ambiguous signals."
            },
            reasoning: {
              type: "string",
              description: "2-3 sentence explanation of why this classification was chosen, citing specific evidence from the profile."
            },
            secondaryType: {
              type: "string",
              enum: ["apt", "ransomware", "cybercrime", "hacktivist", "access_broker", "influence_ops", "none"],
              description: "Secondary classification if the actor shows traits of multiple categories. Use 'none' if clearly single-category."
            },
            secondaryConfidence: {
              type: "number",
              description: "Confidence for secondary classification (0 if none)"
            },
            indicators: {
              type: "array",
              items: { type: "string" },
              description: "3-5 key signals from the profile that drove this classification decision"
            }
          },
          required: ["classifiedType", "confidence", "reasoning", "secondaryType", "secondaryConfidence", "indicators"],
          additionalProperties: false
        }
      }
    }
  });
  const content = response.choices?.[0]?.message?.content;
  if (!content) {
    throw new Error("No response from LLM");
  }
  const parsed = JSON.parse(content);
  return {
    actorId: actor.actorId,
    name: actor.name,
    previousType: "unknown",
    classifiedType: parsed.classifiedType,
    confidence: Math.min(100, Math.max(0, parsed.confidence)),
    reasoning: parsed.reasoning,
    secondaryType: parsed.secondaryType === "none" ? null : parsed.secondaryType,
    secondaryConfidence: parsed.secondaryConfidence || 0,
    indicators: parsed.indicators || []
  };
}
async function classifyBatch(actors, options = {}) {
  const { batchSize = 5, delayMs = 1e3, autoApplyThreshold = 75, onResult } = options;
  cancelRequested = false;
  currentBatchProgress = {
    total: actors.length,
    processed: 0,
    succeeded: 0,
    failed: 0,
    results: [],
    errors: [],
    status: "running",
    startedAt: Date.now(),
    completedAt: null
  };
  for (let i = 0; i < actors.length; i += batchSize) {
    if (cancelRequested) {
      currentBatchProgress.status = "cancelled";
      currentBatchProgress.completedAt = Date.now();
      return currentBatchProgress;
    }
    const batch = actors.slice(i, i + batchSize);
    const results = await Promise.allSettled(
      batch.map((actor) => classifyActor(actor))
    );
    for (let j = 0; j < results.length; j++) {
      const result = results[j];
      currentBatchProgress.processed++;
      if (result.status === "fulfilled") {
        currentBatchProgress.succeeded++;
        currentBatchProgress.results.push(result.value);
        if (result.value.confidence >= autoApplyThreshold && onResult) {
          try {
            await onResult(result.value);
          } catch (e) {
            console.error(`[Classifier] Failed to apply result for ${result.value.actorId}:`, e);
          }
        }
      } else {
        currentBatchProgress.failed++;
        currentBatchProgress.errors.push({
          actorId: batch[j].actorId,
          name: batch[j].name,
          error: result.reason?.message || "Unknown error"
        });
      }
    }
    if (i + batchSize < actors.length && !cancelRequested) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  currentBatchProgress.status = "completed";
  currentBatchProgress.completedAt = Date.now();
  return currentBatchProgress;
}
function buildProfileSummary(actor) {
  const parts = [];
  parts.push(`**Name:** ${actor.name}`);
  if (actor.aliases.length > 0) parts.push(`**Aliases:** ${actor.aliases.join(", ")}`);
  if (actor.origin) parts.push(`**Origin:** ${actor.origin}`);
  if (actor.motivation) parts.push(`**Motivation:** ${actor.motivation}`);
  if (actor.sophistication) parts.push(`**Sophistication:** ${actor.sophistication}`);
  if (actor.firstSeen) parts.push(`**First Seen:** ${actor.firstSeen}`);
  if (actor.lastActive) parts.push(`**Last Active:** ${actor.lastActive}`);
  if (actor.description) parts.push(`**Description:** ${actor.description}`);
  if (actor.targetSectors.length > 0) parts.push(`**Target Sectors:** ${actor.targetSectors.join(", ")}`);
  if (actor.targetRegions.length > 0) parts.push(`**Target Regions:** ${actor.targetRegions.join(", ")}`);
  if (actor.techniques.length > 0) parts.push(`**MITRE Techniques:** ${actor.techniques.slice(0, 20).join(", ")}${actor.techniques.length > 20 ? ` (+${actor.techniques.length - 20} more)` : ""}`);
  if (actor.tools.length > 0) parts.push(`**Tools:** ${actor.tools.join(", ")}`);
  if (actor.malware.length > 0) parts.push(`**Malware:** ${actor.malware.join(", ")}`);
  return parts.join("\n");
}
function validateClassification(result) {
  const issues = [];
  if (!["apt", "ransomware", "cybercrime", "hacktivist", "access_broker", "influence_ops"].includes(result.classifiedType)) {
    issues.push(`Invalid classification type: ${result.classifiedType}`);
  }
  if (result.confidence < 0 || result.confidence > 100) {
    issues.push(`Confidence out of range: ${result.confidence}`);
  }
  if (!result.reasoning || result.reasoning.length < 10) {
    issues.push("Reasoning is too short or missing");
  }
  if (result.secondaryType && result.secondaryType === result.classifiedType) {
    issues.push("Secondary type should not match primary type");
  }
  if (result.indicators.length === 0) {
    issues.push("No indicators provided");
  }
  return { valid: issues.length === 0, issues };
}
export {
  cancelBatch,
  classifyActor,
  classifyBatch,
  getProgress,
  resetProgress,
  validateClassification
};
