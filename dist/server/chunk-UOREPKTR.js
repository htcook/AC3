import {
  SCAN_API_KEY,
  SCAN_SERVICE_URL,
  init_scan_service_url
} from "./chunk-UYX5D64U.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/knowledge/asset-ontology.ts
import { readFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
function deduplicateOntology(entries) {
  const seen = /* @__PURE__ */ new Set();
  return entries.filter((e) => {
    const base = e.product_name.replace(/_\d+$/, "");
    if (seen.has(base)) return false;
    seen.add(base);
    return true;
  });
}
async function loadOntologyAsync() {
  if (_ontology) return _ontology;
  const localPath = join(__esm_dirname, "asset_role_ontology.json");
  if (existsSync(localPath)) {
    try {
      const raw = readFileSync(localPath, "utf-8");
      _ontology = deduplicateOntology(JSON.parse(raw));
      console.log(`[AssetOntology] Loaded ${_ontology.length} unique product entries from local file`);
      return _ontology;
    } catch (e) {
      console.warn("[AssetOntology] Local file read failed:", e.message);
    }
  }
  try {
    const res = await fetch(`${SCAN_SERVICE_URL}/api/knowledge/asset_role_ontology.json`, {
      headers: { "X-Scan-Key": SCAN_API_KEY },
      signal: AbortSignal.timeout(1e4)
    });
    if (res.ok) {
      _ontology = deduplicateOntology(await res.json());
      console.log(`[AssetOntology] Loaded ${_ontology.length} unique product entries from DO scan service`);
      return _ontology;
    }
  } catch (e) {
    console.warn("[AssetOntology] DO fetch error:", e.message);
  }
  _ontology = [];
  return _ontology;
}
function loadOntology() {
  if (_ontology) return _ontology;
  const localPath = join(__esm_dirname, "asset_role_ontology.json");
  if (existsSync(localPath)) {
    try {
      const raw = readFileSync(localPath, "utf-8");
      _ontology = deduplicateOntology(JSON.parse(raw));
      console.log(`[AssetOntology] Loaded ${_ontology.length} unique product entries from local file`);
      return _ontology;
    } catch (e) {
      console.warn("[AssetOntology] Local file read failed:", e.message);
    }
  }
  loadOntologyAsync().catch(() => {
  });
  _ontology = [];
  return _ontology;
}
function loadPatterns() {
  if (_patterns) return _patterns;
  try {
    const raw = readFileSync(join(__esm_dirname, "architecture_pattern_packs.json"), "utf-8");
    _patterns = JSON.parse(raw);
    return _patterns;
  } catch (e) {
    _patterns = [];
    return _patterns;
  }
}
function lookupProduct(productName) {
  const ontology = loadOntology();
  const normalised = productName.toLowerCase().replace(/[^a-z0-9]/g, "_");
  const exact = ontology.find((e) => e.product_name.toLowerCase() === normalised);
  if (exact) return exact;
  return ontology.find(
    (e) => e.product_name.toLowerCase().includes(normalised) || normalised.includes(e.product_name.toLowerCase().replace(/_\d+$/, ""))
  );
}
function inferAssetContext(detectedTechnologies) {
  const ontology = loadOntology();
  const patterns = loadPatterns();
  const matchedProducts = [];
  const allSecurityFocus = /* @__PURE__ */ new Set();
  const matchedProductNames = /* @__PURE__ */ new Set();
  for (const tech of detectedTechnologies) {
    const entry = lookupProduct(tech);
    if (entry) {
      matchedProducts.push({
        product: entry.product_name,
        assetClass: entry.asset_class,
        securityFocus: entry.security_test_focus,
        deploymentZones: entry.deployment_zones,
        functions: entry.primary_functions
      });
      entry.security_test_focus.forEach((f) => allSecurityFocus.add(f));
      matchedProductNames.add(entry.product_name.replace(/_\d+$/, ""));
    }
  }
  let bestPattern = null;
  let bestScore = 0;
  for (const pattern of patterns) {
    const score = pattern.components.filter(
      (c) => matchedProductNames.has(c) || detectedTechnologies.some((t) => t.toLowerCase().includes(c.toLowerCase()))
    ).length;
    if (score > bestScore) {
      bestScore = score;
      bestPattern = pattern;
    }
  }
  return {
    matchedProducts,
    architecturePatternMatch: bestScore >= 2 ? bestPattern : null,
    aggregatedSecurityFocus: [...allSecurityFocus]
  };
}
function formatOntologyForPrompt(detectedTechnologies) {
  const context = inferAssetContext(detectedTechnologies);
  if (context.matchedProducts.length === 0) return "";
  let prompt = `
## Asset Intelligence (from ontology knowledge base)
The following asset role classifications were inferred from detected technologies:
`;
  for (const mp of context.matchedProducts) {
    prompt += `
- **${mp.product}** \u2192 Role: ${mp.assetClass} | Zone: ${mp.deploymentZones.join(", ")} | Functions: ${mp.functions.join(", ")}
  Security test priorities: ${mp.securityFocus.join(", ")}`;
  }
  if (context.architecturePatternMatch) {
    const p = context.architecturePatternMatch;
    prompt += `

**Detected Architecture Pattern: ${p.name}**
${p.description}
Components: ${p.components.join(", ")}
Security focus areas: ${p.security_focus.join(", ")}`;
  }
  if (context.aggregatedSecurityFocus.length > 0) {
    prompt += `

**Aggregated security test priorities:** ${context.aggregatedSecurityFocus.join(", ")}`;
  }
  return prompt;
}
function getArchitecturePatterns() {
  return loadPatterns();
}
var __esm_dirname, _ontology, _patterns;
var init_asset_ontology = __esm({
  "server/lib/knowledge/asset-ontology.ts"() {
    "use strict";
    init_scan_service_url();
    __esm_dirname = dirname(fileURLToPath(import.meta.url));
    _ontology = null;
    _patterns = null;
    loadOntologyAsync().catch(() => {
    });
  }
});

export {
  inferAssetContext,
  formatOntologyForPrompt,
  getArchitecturePatterns,
  init_asset_ontology
};
