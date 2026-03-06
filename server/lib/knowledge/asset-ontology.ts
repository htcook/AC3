/**
 * Asset Ontology Knowledge Module — provides IT architecture and asset role
 * intelligence to the LLM during engagement planning and exploitation.
 *
 * Loads the asset role ontology (160 product entries), inference rules,
 * and architecture patterns to help the LLM:
 *   1. Classify discovered assets by role (database, reverse_proxy, identity_provider, etc.)
 *   2. Infer security test focus areas based on asset class
 *   3. Recognize common enterprise architecture patterns
 *   4. Prioritize targets by deployment zone and business criticality
 */

import { readFileSync } from "fs";
import { join } from "path";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface AssetOntologyEntry {
  product_name: string;
  vendor_category: string;
  asset_class: string;
  primary_functions: string[];
  security_test_focus: string[];
  common_ports: number[];
  deployment_zones: string[];
}

export interface ArchitecturePattern {
  name: string;
  description: string;
  components: string[];
  security_focus: string[];
}

export interface InferenceRule {
  name: string;
  conditions: string[];
  inference: {
    asset_role: string;
    confidence: number;
  };
}

// ─── Singleton loaders ──────────────────────────────────────────────────────

let _ontology: AssetOntologyEntry[] | null = null;
let _patterns: ArchitecturePattern[] | null = null;
let _rules: InferenceRule[] | null = null;

function loadOntology(): AssetOntologyEntry[] {
  if (_ontology) return _ontology;
  try {
    const raw = readFileSync(join(__dirname, "asset_role_ontology.json"), "utf-8");
    _ontology = JSON.parse(raw) as AssetOntologyEntry[];
    // Deduplicate by product_name (keep first occurrence)
    const seen = new Set<string>();
    _ontology = _ontology.filter(e => {
      const base = e.product_name.replace(/_\d+$/, ""); // strip numeric suffixes
      if (seen.has(base)) return false;
      seen.add(base);
      return true;
    });
    console.log(`[AssetOntology] Loaded ${_ontology.length} unique product entries`);
    return _ontology;
  } catch (e: any) {
    console.warn("[AssetOntology] Failed to load ontology:", e.message);
    _ontology = [];
    return _ontology;
  }
}

function loadPatterns(): ArchitecturePattern[] {
  if (_patterns) return _patterns;
  try {
    const raw = readFileSync(join(__dirname, "architecture_pattern_packs.json"), "utf-8");
    _patterns = JSON.parse(raw) as ArchitecturePattern[];
    return _patterns;
  } catch (e: any) {
    _patterns = [];
    return _patterns;
  }
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Look up a product by name and return its ontology entry.
 * Supports fuzzy matching (e.g. "nginx" matches "nginx", "apache" matches "apache_httpd").
 */
export function lookupProduct(productName: string): AssetOntologyEntry | undefined {
  const ontology = loadOntology();
  const normalised = productName.toLowerCase().replace(/[^a-z0-9]/g, "_");

  // Exact match
  const exact = ontology.find(e => e.product_name.toLowerCase() === normalised);
  if (exact) return exact;

  // Partial match
  return ontology.find(e =>
    e.product_name.toLowerCase().includes(normalised) ||
    normalised.includes(e.product_name.toLowerCase().replace(/_\d+$/, ""))
  );
}

/**
 * Look up all products in a given asset class (e.g. "database", "reverse_proxy").
 */
export function getProductsByClass(assetClass: string): AssetOntologyEntry[] {
  const ontology = loadOntology();
  return ontology.filter(e => e.asset_class.toLowerCase() === assetClass.toLowerCase());
}

/**
 * Look up all products in a given vendor category (e.g. "data_layer", "identity").
 */
export function getProductsByCategory(category: string): AssetOntologyEntry[] {
  const ontology = loadOntology();
  return ontology.filter(e => e.vendor_category.toLowerCase() === category.toLowerCase());
}

/**
 * Given a list of detected technologies/services, infer asset roles and security focus areas.
 * Returns enrichment data that can be injected into the LLM prompt.
 */
export function inferAssetContext(detectedTechnologies: string[]): {
  matchedProducts: Array<{
    product: string;
    assetClass: string;
    securityFocus: string[];
    deploymentZones: string[];
    functions: string[];
  }>;
  architecturePatternMatch: ArchitecturePattern | null;
  aggregatedSecurityFocus: string[];
} {
  const ontology = loadOntology();
  const patterns = loadPatterns();

  const matchedProducts: Array<{
    product: string;
    assetClass: string;
    securityFocus: string[];
    deploymentZones: string[];
    functions: string[];
  }> = [];

  const allSecurityFocus = new Set<string>();
  const matchedProductNames = new Set<string>();

  for (const tech of detectedTechnologies) {
    const entry = lookupProduct(tech);
    if (entry) {
      matchedProducts.push({
        product: entry.product_name,
        assetClass: entry.asset_class,
        securityFocus: entry.security_test_focus,
        deploymentZones: entry.deployment_zones,
        functions: entry.primary_functions,
      });
      entry.security_test_focus.forEach(f => allSecurityFocus.add(f));
      matchedProductNames.add(entry.product_name.replace(/_\d+$/, ""));
    }
  }

  // Try to match an architecture pattern
  let bestPattern: ArchitecturePattern | null = null;
  let bestScore = 0;
  for (const pattern of patterns) {
    const score = pattern.components.filter(c =>
      matchedProductNames.has(c) || detectedTechnologies.some(t => t.toLowerCase().includes(c.toLowerCase()))
    ).length;
    if (score > bestScore) {
      bestScore = score;
      bestPattern = pattern;
    }
  }

  return {
    matchedProducts,
    architecturePatternMatch: bestScore >= 2 ? bestPattern : null,
    aggregatedSecurityFocus: [...allSecurityFocus],
  };
}

/**
 * Format asset ontology context into a prompt-ready string for LLM injection.
 */
export function formatOntologyForPrompt(detectedTechnologies: string[]): string {
  const context = inferAssetContext(detectedTechnologies);

  if (context.matchedProducts.length === 0) return "";

  let prompt = `\n## Asset Intelligence (from ontology knowledge base)
The following asset role classifications were inferred from detected technologies:\n`;

  for (const mp of context.matchedProducts) {
    prompt += `\n- **${mp.product}** → Role: ${mp.assetClass} | Zone: ${mp.deploymentZones.join(", ")} | Functions: ${mp.functions.join(", ")}
  Security test priorities: ${mp.securityFocus.join(", ")}`;
  }

  if (context.architecturePatternMatch) {
    const p = context.architecturePatternMatch;
    prompt += `\n\n**Detected Architecture Pattern: ${p.name}**
${p.description}
Components: ${p.components.join(", ")}
Security focus areas: ${p.security_focus.join(", ")}`;
  }

  if (context.aggregatedSecurityFocus.length > 0) {
    prompt += `\n\n**Aggregated security test priorities:** ${context.aggregatedSecurityFocus.join(", ")}`;
  }

  return prompt;
}

/**
 * Get all unique asset classes in the ontology.
 */
export function getAssetClasses(): string[] {
  const ontology = loadOntology();
  return [...new Set(ontology.map(e => e.asset_class))].sort();
}

/**
 * Get all architecture patterns.
 */
export function getArchitecturePatterns(): ArchitecturePattern[] {
  return loadPatterns();
}
