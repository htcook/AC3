/**
 * Bug Bounty Knowledge Module
 * 
 * Loads attack patterns, extraction rules, and triage prompts from the
 * Ace C3 Bug Bounty Knowledge Training Bundle. Provides context injection
 * for the orchestrator's LLM prompts during vulnerability hypothesis
 * generation and scan triage phases.
 */

import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename_esm = fileURLToPath(import.meta.url);
const __dirname_esm = dirname(__filename_esm);
const BUNDLE_DIR = join(__dirname_esm, "bugbounty-bundle");

// ─── Types ───────────────────────────────────────────────────────────────────

interface AttackPattern {
  pattern_id: string;
  signals: string[];
  hypothesis: string;
  safe_tests: string[];
  impact: string[];
  fixes: string[];
  owasp?: string;
  cwe?: string;
  mitre?: string[];
}

interface ExtractionRule {
  vulnerability_class: string[];
  owasp_map: Record<string, string>;
}

interface TrainingExample {
  input: {
    observations: string[];
    scope_statement: string;
    tech_context?: string[];
  };
  output: {
    hypotheses: string[];
    next_tests: string[];
    impact_summary: string;
    remediation: string[];
    owasp?: string;
    confidence?: number;
  };
}

// ─── Lazy-loaded data ────────────────────────────────────────────────────────

let _samplePattern: AttackPattern | null = null;
let _sampleReport: any | null = null;
let _extractionRules: ExtractionRule | null = null;
let _trainingExamples: TrainingExample[] | null = null;
let _triagePrompt: string | null = null;
let _patternPrompt: string | null = null;

function loadJSON(relativePath: string): any {
  try {
    return JSON.parse(readFileSync(join(BUNDLE_DIR, relativePath), "utf-8"));
  } catch {
    return null;
  }
}

function loadText(relativePath: string): string {
  try {
    return readFileSync(join(BUNDLE_DIR, relativePath), "utf-8");
  } catch {
    return "";
  }
}

function loadJSONL(relativePath: string): any[] {
  try {
    const content = readFileSync(join(BUNDLE_DIR, relativePath), "utf-8");
    return content
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

function getSamplePattern(): AttackPattern | null {
  if (!_samplePattern) {
    _samplePattern = loadJSON("datasets/samples/sample_attack_pattern.json");
  }
  return _samplePattern;
}

function getSampleReport(): any {
  if (!_sampleReport) {
    _sampleReport = loadJSON("datasets/samples/sample_normalized_report.json");
  }
  return _sampleReport;
}

function getExtractionRules(): ExtractionRule | null {
  if (!_extractionRules) {
    const raw = loadText("extractors/extraction_rules.yaml");
    // Simple YAML-like parsing for the field_hints section
    const vulnClasses: string[] = [];
    const owaspMap: Record<string, string> = {};
    let inVulnClass = false;
    let inOwaspMap = false;
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (trimmed === "vulnerability_class:") { inVulnClass = true; inOwaspMap = false; continue; }
      if (trimmed === "owasp_map:") { inOwaspMap = true; inVulnClass = false; continue; }
      if (trimmed.startsWith("normalization_steps:")) { inVulnClass = false; inOwaspMap = false; continue; }
      if (inVulnClass && trimmed.startsWith("- ")) {
        vulnClasses.push(trimmed.slice(2).trim());
      }
      if (inOwaspMap && trimmed.includes(":")) {
        const [key, val] = trimmed.split(":").map((s) => s.trim());
        if (key && val) owaspMap[key] = val;
      }
    }
    _extractionRules = { vulnerability_class: vulnClasses, owasp_map: owaspMap };
  }
  return _extractionRules;
}

function getTrainingExamples(): TrainingExample[] {
  if (!_trainingExamples) {
    _trainingExamples = loadJSONL("datasets/samples/sample_training.jsonl");
  }
  return _trainingExamples;
}

function getTriagePrompt(): string {
  if (!_triagePrompt) {
    _triagePrompt = loadText("prompts/04_triage_scan_to_hypotheses.md");
  }
  return _triagePrompt;
}

function getPatternPrompt(): string {
  if (!_patternPrompt) {
    _patternPrompt = loadText("prompts/02_extract_attack_pattern.md");
  }
  return _patternPrompt;
}

// ─── Vulnerability class to OWASP mapping ────────────────────────────────────

const VULN_CLASS_KEYWORDS: Record<string, string[]> = {
  "IDOR": ["idor", "insecure direct object", "object reference", "broken access control"],
  "Broken Access Control": ["access control", "authorization", "privilege escalation", "authz"],
  "XSS": ["xss", "cross-site scripting", "reflected", "stored xss", "dom xss"],
  "SQL Injection": ["sql injection", "sqli", "sql", "database injection"],
  "SSRF": ["ssrf", "server-side request forgery", "request forgery"],
  "CSRF": ["csrf", "cross-site request forgery"],
  "Open Redirect": ["open redirect", "redirect", "url redirect"],
  "Auth Bypass": ["auth bypass", "authentication bypass", "login bypass"],
  "JWT Misconfig": ["jwt", "json web token", "token manipulation"],
  "RCE": ["rce", "remote code execution", "command injection", "code execution"],
  "XXE": ["xxe", "xml external entity", "xml injection"],
  "Deserialization": ["deserialization", "insecure deserialization", "pickle", "serialize"],
  "Logic Flaw": ["logic flaw", "business logic", "race condition", "logic bug"],
};

/**
 * Given scan findings or vulnerability descriptions, return matching
 * bug bounty attack patterns and triage guidance for the LLM.
 */
export function getBugBountyContext(
  findings: string[],
  maxPatterns: number = 3
): string {
  const rules = getExtractionRules();
  const pattern = getSamplePattern();
  const report = getSampleReport();
  const triagePrompt = getTriagePrompt();

  if (!rules || !pattern) return "";

  // Match vulnerability classes from findings text
  const findingsText = findings.join(" ").toLowerCase();
  const matchedClasses: Set<string> = new Set();

  for (const [vulnClass, keywords] of Object.entries(VULN_CLASS_KEYWORDS)) {
    for (const kw of keywords) {
      if (findingsText.includes(kw)) {
        matchedClasses.add(vulnClass);
        break;
      }
    }
  }

  // Build context sections
  const sections: string[] = [];

  // Section 1: Triage methodology
  if (triagePrompt) {
    sections.push(`## Bug Bounty Triage Methodology\n${triagePrompt}`);
  }

  // Section 2: Known vulnerability classes and OWASP mapping
  sections.push(`## Known Vulnerability Classes (from Bug Bounty Knowledge Base)
The following vulnerability classes are commonly found in bug bounty programs:
${rules.vulnerability_class.map((vc) => `- ${vc}${rules.owasp_map[vc] ? ` → OWASP: ${rules.owasp_map[vc]}` : ""}`).join("\n")}

${matchedClasses.size > 0 ? `**Detected matches from current findings:** ${[...matchedClasses].join(", ")}` : ""}`);

  // Section 3: Attack pattern template (signals → hypothesis → safe tests)
  sections.push(`## Attack Pattern Template (Bug Bounty Reasoning)
When analyzing vulnerabilities, follow this pattern:
1. **Signals**: What observations indicate a vulnerability?
2. **Hypothesis**: What vulnerability class does this match?
3. **Safe Tests**: What non-destructive tests can validate the hypothesis?
4. **Impact**: What is the potential business/security impact?
5. **Fixes**: What remediation should be recommended?

### Example Pattern (IDOR):
- Signals: ${pattern.signals.join("; ")}
- Hypothesis: ${pattern.hypothesis}
- Safe Tests: ${pattern.safe_tests.join("; ")}
- Impact: ${pattern.impact.join("; ")}
- Fixes: ${pattern.fixes.join("; ")}
- OWASP: ${pattern.owasp || "N/A"}, CWE: ${pattern.cwe || "N/A"}`);

  // Section 4: If we have matched classes, provide specific guidance
  if (matchedClasses.size > 0) {
    const guidanceLines: string[] = [];
    for (const vc of matchedClasses) {
      const owaspCat = rules.owasp_map[vc] || vc;
      guidanceLines.push(`### ${vc} (OWASP: ${owaspCat})
- Focus safe tests on validating ${vc.toLowerCase()} conditions
- Check for missing authorization/validation at the server side
- Document evidence with request/response pairs (redacted)
- Map to CWE and MITRE ATT&CK where applicable`);
    }
    sections.push(`## Targeted Guidance for Detected Vulnerability Classes\n${guidanceLines.join("\n\n")}`);
  }

  // Section 5: Normalized report example for structured output
  if (report) {
    sections.push(`## Example Normalized Report Structure
When documenting findings, structure them like this:
- Title: ${report.title}
- Vulnerability Class: ${report.vulnerability_class}
- OWASP: ${report.owasp_category}, CWE: ${report.cwe}
- Asset Context: ${report.asset_context.app_type} (${report.asset_context.auth_model})
- Entry Point: ${report.asset_context.entry_point}
- Attack Chain: ${report.attack_chain.length} steps
- Impact: ${report.impact.summary}
- Severity: ${report.severity} (CVSS ~${report.cvss_estimate})
- Remediation: ${report.remediation.join("; ")}`);
  }

  return sections.join("\n\n");
}

/**
 * Get the scan-to-hypotheses triage prompt for injecting into the
 * orchestrator's vulnerability correlation LLM call.
 */
export function getTriageSystemPrompt(): string {
  return getTriagePrompt();
}

/**
 * Get all known vulnerability classes for classification.
 */
export function getVulnerabilityClasses(): string[] {
  const rules = getExtractionRules();
  return rules?.vulnerability_class || [];
}

/**
 * Get OWASP mapping for a vulnerability class.
 */
export function getOwaspMapping(vulnClass: string): string | undefined {
  const rules = getExtractionRules();
  return rules?.owasp_map[vulnClass];
}

/**
 * Get training examples for few-shot prompting.
 */
export function getTrainingExamplesForPrompt(maxExamples: number = 2): string {
  const examples = getTrainingExamples();
  if (examples.length === 0) return "";

  const selected = examples.slice(0, maxExamples);
  return selected
    .map(
      (ex, i) =>
        `### Training Example ${i + 1}:
**Observations:** ${ex.input.observations.join("; ")}
**Tech Context:** ${ex.input.tech_context?.join(", ") || "N/A"}
**Hypotheses:** ${ex.output.hypotheses.join("; ")}
**Next Tests:** ${ex.output.next_tests.join("; ")}
**Impact:** ${ex.output.impact_summary}
**Remediation:** ${ex.output.remediation.join("; ")}
**OWASP:** ${ex.output.owasp || "N/A"}, **Confidence:** ${ex.output.confidence || "N/A"}`
    )
    .join("\n\n");
}
