/**
 * Incident Training Context Injection
 * 
 * Retrieves relevant historical training examples and injects them into
 * LLM system prompts for future DI scans. This creates a feedback loop:
 * 
 * Scan → Incident Search → Training Examples → Future Scan Prompts → Better Results
 * 
 * Context selection strategy:
 * 1. Same domain (highest priority) — exact match from prior scans
 * 2. Same sector — similar organizations in the same industry
 * 3. Same actors — domains targeted by the same threat actors
 * 4. High-quality examples — analyst-verified training data
 */

import {
  getDITrainingExamplesForDomain,
  getDITrainingExamplesForSector,
  getHighQualityDITrainingExamples,
  incrementDITrainingUsage,
} from "../db";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface TrainingContextConfig {
  maxExamples?: number;       // Max examples to inject (default: 5)
  maxTokenBudget?: number;    // Approximate token budget (default: 2000)
  prioritizeSameDomain?: boolean;
  prioritizeSameSector?: boolean;
  includeActorContext?: boolean;
  includeBreachContext?: boolean;
  includeRansomwareContext?: boolean;
}

export interface InjectedContext {
  systemPromptAddition: string;
  exampleIds: string[];
  totalExamplesUsed: number;
  sources: {
    sameDomain: number;
    sameSector: number;
    highQuality: number;
  };
}

// ─── Context Builder ────────────────────────────────────────────────────────

function estimateTokens(text: string): number {
  // Rough estimate: ~4 chars per token
  return Math.ceil(text.length / 4);
}

function extractAssistantContent(example: any): string {
  try {
    const messages = typeof example.trainingMessages === "string"
      ? JSON.parse(example.trainingMessages)
      : example.trainingMessages;
    const assistant = messages.find((m: any) => m.role === "assistant");
    return assistant?.content || "";
  } catch {
    return "";
  }
}

/**
 * Build a context injection block from a training example.
 * Returns a condensed version suitable for system prompt injection.
 */
function buildContextBlock(example: any): string {
  const content = extractAssistantContent(example);
  if (!content) return "";

  const typeLabel: Record<string, string> = {
    incident_context: "Incident History",
    actor_attribution: "Threat Actor Intelligence",
    breach_pattern: "Breach Intelligence",
    ransomware_profile: "Ransomware Intelligence",
    attack_surface_map: "Attack Surface Intelligence",
  };

  const label = typeLabel[example.exampleType] || "Intelligence";
  const qualityTag = example.analystRating === "accurate" ? " [VERIFIED]" : "";
  
  // Truncate content to ~300 chars for prompt efficiency
  const truncated = content.length > 400 ? content.slice(0, 400) + "..." : content;

  return `### ${label} — ${example.domain}${qualityTag}\n${truncated}`;
}

// ─── Main Context Injection ─────────────────────────────────────────────────

/**
 * Retrieve and format historical incident context for injection into
 * the LLM system prompt during a DI scan.
 */
export async function getIncidentTrainingContext(
  domain: string,
  sector?: string,
  config: TrainingContextConfig = {},
): Promise<InjectedContext> {
  const {
    maxExamples = 5,
    maxTokenBudget = 2000,
    prioritizeSameDomain = true,
    prioritizeSameSector = true,
  } = config;

  const selectedExamples: any[] = [];
  const usedIds = new Set<string>();
  let tokenCount = 0;
  const sources = { sameDomain: 0, sameSector: 0, highQuality: 0 };

  // Helper to add examples with dedup and budget check
  function addExamples(examples: any[], source: "sameDomain" | "sameSector" | "highQuality") {
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
    // Priority 1: Same domain examples
    if (prioritizeSameDomain) {
      const domainExamples = await getDITrainingExamplesForDomain(domain, 10);
      addExamples(domainExamples, "sameDomain");
    }

    // Priority 2: Same sector examples
    if (prioritizeSameSector && sector && selectedExamples.length < maxExamples) {
      const sectorExamples = await getDITrainingExamplesForSector(sector, 20);
      addExamples(sectorExamples, "sameSector");
    }

    // Priority 3: High-quality examples (analyst-verified)
    if (selectedExamples.length < maxExamples) {
      const highQuality = await getHighQualityDITrainingExamples(20);
      addExamples(highQuality, "highQuality");
    }

    // Build the system prompt addition
    if (selectedExamples.length === 0) {
      return {
        systemPromptAddition: "",
        exampleIds: [],
        totalExamplesUsed: 0,
        sources,
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
      "---",
    ].join("\n");

    // Track usage
    const exampleIds = selectedExamples.map(e => e.exampleId);
    await incrementDITrainingUsage(exampleIds);

    return {
      systemPromptAddition,
      exampleIds,
      totalExamplesUsed: selectedExamples.length,
      sources,
    };
  } catch (err) {
    console.error("[TrainingContext] Error building context:", err);
    return {
      systemPromptAddition: "",
      exampleIds: [],
      totalExamplesUsed: 0,
      sources,
    };
  }
}

/**
 * Build a compact context string for the incident search LLM prompt.
 * This is a lighter version specifically for the incident search stage.
 */
export async function getIncidentSearchPromptContext(
  domain: string,
  sector?: string,
): Promise<string> {
  const context = await getIncidentTrainingContext(domain, sector, {
    maxExamples: 3,
    maxTokenBudget: 1000,
  });

  return context.systemPromptAddition;
}
