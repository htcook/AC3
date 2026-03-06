/**
 * Attack Chain Retriever — loads the 300 attack chains from the training bundle
 * and provides filtered retrieval by OWASP category, MITRE technique, or keyword.
 *
 * Used to inject relevant few-shot examples into the orchestrator's LLM exploitation
 * planning prompt so the LLM can reference proven attack patterns.
 */

import { readFileSync } from "fs";
import { join } from "path";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface AttackChainStep {
  phase: string;
  goal: string;
}

export interface AttackChain {
  id: string;
  name: string;
  owasp_category: string;
  mitre_techniques: string[];
  preconditions: string[];
  steps: AttackChainStep[];
  evidence_expected: string[];
}

// ─── Singleton loader ───────────────────────────────────────────────────────

let _chains: AttackChain[] | null = null;

function loadChains(): AttackChain[] {
  if (_chains) return _chains;
  try {
    const raw = readFileSync(join(__dirname, "attack_chains_300.json"), "utf-8");
    _chains = JSON.parse(raw) as AttackChain[];
    console.log(`[AttackChainRetriever] Loaded ${_chains.length} attack chains`);
    return _chains;
  } catch (e: any) {
    console.warn("[AttackChainRetriever] Failed to load attack chains:", e.message);
    _chains = [];
    return _chains;
  }
}

// ─── OWASP → vulnerability keyword mapping ──────────────────────────────────

const OWASP_VULN_MAP: Record<string, string[]> = {
  "Injection": ["sqli", "sql injection", "command injection", "ldap injection", "xpath", "nosql injection", "os command"],
  "Broken Authentication": ["auth bypass", "credential", "session", "brute force", "default password", "weak auth"],
  "Sensitive Data Exposure": ["data leak", "information disclosure", "cleartext", "unencrypted", "pii", "sensitive data", "exposure"],
  "XML External Entities": ["xxe", "xml", "entity injection", "dtd"],
  "Broken Access Control": ["idor", "privilege escalation", "access control", "authorization", "path traversal", "directory traversal"],
  "Security Misconfiguration": ["misconfiguration", "default config", "debug mode", "directory listing", "verbose error", "stack trace"],
  "Cross-Site Scripting": ["xss", "cross-site scripting", "reflected xss", "stored xss", "dom xss", "script injection"],
  "Insecure Deserialization": ["deserialization", "object injection", "pickle", "java deserialize", "unserialize"],
  "Using Components with Known Vulnerabilities": ["cve", "outdated", "vulnerable version", "known vulnerability", "eol", "end of life"],
  "Insufficient Logging & Monitoring": ["logging", "monitoring", "audit", "detection gap"],
  "Server-Side Request Forgery": ["ssrf", "server-side request", "internal request"],
  "Cryptographic Failures": ["weak crypto", "ssl", "tls", "certificate", "hash", "encryption"],
};

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Get attack chains filtered by OWASP category name (exact or fuzzy match).
 */
export function getChainsByOwaspCategory(category: string, limit = 3): AttackChain[] {
  const chains = loadChains();
  const normalised = category.toLowerCase().trim();

  // Exact match first
  const exact = chains.filter(c => c.owasp_category.toLowerCase() === normalised);
  if (exact.length > 0) return exact.slice(0, limit);

  // Fuzzy match — check if category is contained in chain's owasp_category or vice versa
  const fuzzy = chains.filter(c =>
    c.owasp_category.toLowerCase().includes(normalised) ||
    normalised.includes(c.owasp_category.toLowerCase())
  );
  return fuzzy.slice(0, limit);
}

/**
 * Get attack chains filtered by MITRE ATT&CK technique ID (e.g. "T1190").
 */
export function getChainsByMitreTechnique(techniqueId: string, limit = 3): AttackChain[] {
  const chains = loadChains();
  const tid = techniqueId.toUpperCase().trim();
  return chains.filter(c => c.mitre_techniques.some(t => t.toUpperCase() === tid)).slice(0, limit);
}

/**
 * Get attack chains relevant to a set of detected vulnerabilities.
 * Matches vulnerability descriptions against OWASP categories using keyword mapping.
 */
export function getChainsByVulnDescriptions(vulnDescriptions: string[], limit = 5): AttackChain[] {
  const chains = loadChains();
  const combined = vulnDescriptions.join(" ").toLowerCase();

  // Score each OWASP category by keyword hits
  const categoryScores: Record<string, number> = {};
  for (const [category, keywords] of Object.entries(OWASP_VULN_MAP)) {
    let score = 0;
    for (const kw of keywords) {
      if (combined.includes(kw)) score++;
    }
    if (score > 0) categoryScores[category] = score;
  }

  // Sort categories by score descending
  const rankedCategories = Object.entries(categoryScores)
    .sort((a, b) => b[1] - a[1])
    .map(([cat]) => cat);

  // Collect chains from top-scoring categories
  const result: AttackChain[] = [];
  const seen = new Set<string>();
  for (const cat of rankedCategories) {
    const matching = chains.filter(c =>
      c.owasp_category.toLowerCase() === cat.toLowerCase() && !seen.has(c.id)
    );
    for (const chain of matching.slice(0, 2)) {
      result.push(chain);
      seen.add(chain.id);
      if (result.length >= limit) return result;
    }
  }

  return result;
}

/**
 * Format attack chains into a concise prompt-ready string for LLM context injection.
 */
export function formatChainsForPrompt(chains: AttackChain[]): string {
  if (chains.length === 0) return "";

  const formatted = chains.map((c, i) => {
    const steps = c.steps.map(s => `  ${s.phase}: ${s.goal}`).join("\n");
    return `### Reference Attack Chain ${i + 1}: ${c.name} [${c.id}]
Category: ${c.owasp_category} | MITRE: ${c.mitre_techniques.join(", ")}
Steps:
${steps}
Evidence: ${c.evidence_expected.join(", ")}`;
  }).join("\n\n");

  return `\n## Reference Attack Chains (from training corpus)
Use these proven attack patterns as guidance for your exploitation plan. Adapt the steps to the specific target and findings.

${formatted}`;
}

/**
 * Get all unique OWASP categories present in the chain corpus.
 */
export function getAvailableCategories(): string[] {
  const chains = loadChains();
  return [...new Set(chains.map(c => c.owasp_category))].sort();
}

/**
 * Get chain count per OWASP category.
 */
export function getCategoryDistribution(): Record<string, number> {
  const chains = loadChains();
  const dist: Record<string, number> = {};
  for (const c of chains) {
    dist[c.owasp_category] = (dist[c.owasp_category] || 0) + 1;
  }
  return dist;
}
