/**
 * PayloadsAllTheThings Knowledge Module
 *
 * Loads 616 payloads across 30 vulnerability categories from the DO scan server.
 * Data sourced from swisskyrepo/PayloadsAllTheThings repository, processed into
 * structured JSON with category mappings, WAF bypass techniques, detection patterns,
 * MITRE ATT&CK mappings, and training lab correlations.
 */

import { loadKnowledgeData } from "./knowledge-loader";

// ─── Type Definitions ─────────────────────────────────────────────────────

export interface PayloadCategory {
  id: string;
  name: string;
  description: string;
  key_payloads: string[];
  bypass_techniques: string[];
  tools: string[];
  coverage_gaps: string;
  recommended_labs: string[];
}

export interface PayloadEntry {
  id: string;
  category: string;
  category_id: string;
  payload: string;
  waf_bypasses: string[];
  detection_patterns: string[];
  mitre_techniques: string[];
  source: string;
}

export interface TechniqueEntry {
  id: string;
  topic: string;
  technique_count: number;
  tools: string[];
  mitre_mappings: string[];
  automation_potential: string;
  ace_c3_enhancements: string;
  source: string;
}

export interface ToolEntry {
  id: string;
  name: string;
  description: string;
  categories: string[];
}

export interface TrainingLabMapping {
  lab: string;
  vulnerability_types: string[];
  matching_payload_count: number;
  category_ids: string[];
}

export interface PayloadsKnowledgeData {
  metadata: {
    source: string;
    version: string;
    total_categories: number;
    total_payloads: number;
    total_techniques: number;
    total_tools: number;
    generated_at: string;
  };
  categories: PayloadCategory[];
  payloads: PayloadEntry[];
  techniques: TechniqueEntry[];
  tools: ToolEntry[];
  training_lab_mapping: TrainingLabMapping[];
}

// ─── Data Loading ─────────────────────────────────────────────────────────

const FALLBACK: PayloadsKnowledgeData = {
  metadata: {
    source: "PayloadsAllTheThings",
    version: "fallback",
    total_categories: 0,
    total_payloads: 0,
    total_techniques: 0,
    total_tools: 0,
    generated_at: new Date().toISOString(),
  },
  categories: [],
  payloads: [],
  techniques: [],
  tools: [],
  training_lab_mapping: [],
};

let _data: PayloadsKnowledgeData = FALLBACK;
let _loaded = false;

export async function initPayloadsKnowledge(): Promise<void> {
  if (_loaded) return;
  _data = await loadKnowledgeData<PayloadsKnowledgeData>(
    "payloads_knowledge.json",
    FALLBACK
  );
  _loaded = true;
  console.log(
    `[PayloadsKnowledge] Loaded ${_data.metadata.total_payloads} payloads across ${_data.metadata.total_categories} categories`
  );
}

// Auto-init on import
initPayloadsKnowledge().catch((e) =>
  console.warn("[PayloadsKnowledge] Auto-init failed:", e.message)
);

// ─── Query Functions ──────────────────────────────────────────────────────

/** Get all payload categories */
export function getPayloadCategories(): PayloadCategory[] {
  return _data.categories;
}

/** Get payloads for a specific vulnerability category */
export function getPayloadsByCategory(categoryName: string): PayloadEntry[] {
  const lower = categoryName.toLowerCase();
  return _data.payloads.filter(
    (p) => p.category.toLowerCase() === lower
  );
}

/** Search payloads by keyword across payload text, category, and detection patterns */
export function searchPayloads(query: string, limit = 50): PayloadEntry[] {
  const lower = query.toLowerCase();
  return _data.payloads
    .filter(
      (p) =>
        p.payload.toLowerCase().includes(lower) ||
        p.category.toLowerCase().includes(lower) ||
        p.detection_patterns.some((d) => d.toLowerCase().includes(lower))
    )
    .slice(0, limit);
}

/** Get WAF bypass techniques for a category */
export function getWafBypasses(categoryName: string): string[] {
  const payloads = getPayloadsByCategory(categoryName);
  const bypasses = new Set<string>();
  for (const p of payloads) {
    for (const b of p.waf_bypasses) {
      bypasses.add(b);
    }
  }
  // Also check category-level bypasses
  const cat = _data.categories.find(
    (c) => c.name.toLowerCase() === categoryName.toLowerCase()
  );
  if (cat) {
    for (const b of cat.bypass_techniques) {
      bypasses.add(b);
    }
  }
  return Array.from(bypasses);
}

/** Get all techniques (methodology/recon) */
export function getTechniques(): TechniqueEntry[] {
  return _data.techniques;
}

/** Get tools referenced across all payloads */
export function getTools(): ToolEntry[] {
  return _data.tools;
}

/** Get training lab mapping — which labs cover which vulnerability types */
export function getTrainingLabMapping(): TrainingLabMapping[] {
  return _data.training_lab_mapping;
}

/** Get payloads relevant to a specific training lab */
export function getPayloadsForLab(labName: string): PayloadEntry[] {
  const mapping = _data.training_lab_mapping.find(
    (m) => m.lab.toLowerCase() === labName.toLowerCase()
  );
  if (!mapping) return [];
  return _data.payloads.filter((p) =>
    mapping.vulnerability_types.includes(p.category)
  );
}

/**
 * Build a context string for LLM-based scanning of a specific vulnerability type.
 * Returns formatted payload examples, bypass techniques, and detection patterns.
 */
export function buildPayloadContext(
  categoryName: string,
  maxPayloads = 20
): string {
  const payloads = getPayloadsByCategory(categoryName).slice(0, maxPayloads);
  const bypasses = getWafBypasses(categoryName);
  const cat = _data.categories.find(
    (c) => c.name.toLowerCase() === categoryName.toLowerCase()
  );

  if (payloads.length === 0) {
    return `No payloads found for category: ${categoryName}`;
  }

  const payloadList = payloads
    .map((p, i) => `${i + 1}. \`${p.payload}\``)
    .join("\n");

  const bypassList =
    bypasses.length > 0
      ? bypasses.map((b) => `- ${b}`).join("\n")
      : "None documented";

  const detectionPatterns = new Set<string>();
  for (const p of payloads) {
    for (const d of p.detection_patterns) {
      detectionPatterns.add(d);
    }
  }
  const detectionList =
    detectionPatterns.size > 0
      ? Array.from(detectionPatterns)
          .map((d) => `- \`${d}\``)
          .join("\n")
      : "None documented";

  const mitreTechniques = new Set<string>();
  for (const p of payloads) {
    for (const m of p.mitre_techniques) {
      mitreTechniques.add(m);
    }
  }

  return `## ${categoryName} Payloads (PayloadsAllTheThings)
${cat?.description || ""}

### Sample Payloads (${payloads.length} of ${getPayloadsByCategory(categoryName).length} total)
${payloadList}

### WAF Bypass Techniques
${bypassList}

### Detection Patterns
${detectionList}

### MITRE ATT&CK Mappings
${mitreTechniques.size > 0 ? Array.from(mitreTechniques).join(", ") : "None mapped"}

### Recommended Tools
${cat?.tools?.join(", ") || "See individual payload entries"}`;
}

/**
 * Build comprehensive context for LLM scanning across multiple categories.
 */
export function buildMultiCategoryContext(
  categories: string[],
  maxPayloadsPerCategory = 10
): string {
  const sections = categories
    .map((cat) => buildPayloadContext(cat, maxPayloadsPerCategory))
    .filter((s) => !s.startsWith("No payloads"));

  if (sections.length === 0) {
    return "No matching payload data found for the requested categories.";
  }

  return `# PayloadsAllTheThings Knowledge Base
Source: ${_data.metadata.source} (${_data.metadata.version})
Total: ${_data.metadata.total_payloads} payloads across ${_data.metadata.total_categories} categories

${sections.join("\n\n---\n\n")}`;
}

/** Get full metadata about the loaded knowledge */
export function getPayloadsMetadata(): PayloadsKnowledgeData["metadata"] {
  return _data.metadata;
}
