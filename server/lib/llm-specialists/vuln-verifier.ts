/**
 * AC3 LLM Specialist — Vulnerability Verifier
 *
 * Evaluates scan findings to determine if vulnerabilities are real, contextual, or false positives.
 * Used after nuclei, ZAP, or ScanForge discovery findings.
 */

import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { assembleSystemPrompt, buildCustomerContext } from "./core-policy";

const ROLE_PROMPT = `## Role: Vulnerability Verification Analyst

You are the AC3 Vulnerability Verification Analyst.

Your task is to determine whether a vulnerability finding is:
• Real and exploitable
• Likely contextual risk (real but mitigated or low impact)
• Probably a false positive

Evaluate:
• Exploit prerequisites (network access, authentication, specific versions)
• Environmental dependencies (OS, runtime, configuration)
• Compensating controls (WAF, rate limiting, network segmentation)
• Authentication requirements
• Privilege requirements
• Known exploit availability and reliability

Do not inflate severity. A finding with no proof of exploitability should be rated conservatively.

### CRITICAL: Hydra http-get/https-get False Positive Pattern
When evaluating Hydra findings that use http-get or https-get modules:
- Hydra http-get tests HTTP Basic Authentication (sends Authorization header)
- Many modern web apps (SPAs, Nuxt.js, React, Angular behind CloudFront/CDN) do NOT use HTTP Basic Auth
- These servers return HTTP 200 for ALL requests regardless of the Authorization header
- Hydra interprets any non-401 response as "valid credentials" — this is a FALSE POSITIVE
- KEY INDICATOR: If Hydra reports multiple different username:password combinations as valid for the same http-get service, it is almost certainly a false positive (a real HTTP Basic Auth server would only accept the correct credentials)
- If the target uses form-based login (email/password form), OAuth, or JWT authentication, Hydra http-get results are ALWAYS false positives
- Verdict for this pattern: FALSE POSITIVE with High confidence`;

const OUTPUT_SCHEMA = {
  type: "json_schema" as const,
  json_schema: {
    name: "vuln_verification",
    strict: true,
    schema: {
      type: "object",
      properties: {
        finding_summary: { type: "string" },
        affected_asset: { type: "string" },
        affected_asset_function: { type: "string" },
        evidence_review: {
          type: "array",
          items: {
            type: "object",
            properties: {
              tag: { type: "string", description: "OBSERVED | INFERRED | HYPOTHESIS" },
              detail: { type: "string" },
            },
            required: ["tag", "detail"],
            additionalProperties: false,
          },
        },
        false_positive_likelihood: { type: "string", description: "High | Medium | Low" },
        exploitability: {
          type: "object",
          properties: {
            rating: { type: "string", description: "Confirmed | Likely | Possible | Unlikely" },
            prerequisites: { type: "array", items: { type: "string" } },
            known_exploits: { type: "boolean" },
            rationale: { type: "string" },
          },
          required: ["rating", "prerequisites", "known_exploits", "rationale"],
          additionalProperties: false,
        },
        business_impact: {
          type: "object",
          properties: {
            severity: { type: "string", description: "Critical | High | Medium | Low | Informational" },
            rationale: { type: "string" },
          },
          required: ["severity", "rationale"],
          additionalProperties: false,
        },
        attacker_interest: { type: "string", description: "High | Medium | Low" },
        attack_mapping: {
          type: "array",
          items: {
            type: "object",
            properties: {
              technique_id: { type: "string", description: "MITRE ATT&CK ID e.g. T1190" },
              technique_name: { type: "string" },
              tactic: { type: "string" },
            },
            required: ["technique_id", "technique_name", "tactic"],
            additionalProperties: false,
          },
        },
        safe_validation_step: { type: "string", description: "A safe way to confirm this finding without causing damage" },
        analyst_verdict: { type: "string", description: "True Positive | Likely True Positive | Inconclusive | Likely False Positive | False Positive" },
        confidence: { type: "string", description: "High | Medium | Low" },
      },
      required: ["finding_summary", "affected_asset", "affected_asset_function", "evidence_review", "false_positive_likelihood", "exploitability", "business_impact", "attacker_interest", "attack_mapping", "safe_validation_step", "analyst_verdict", "confidence"],
      additionalProperties: false,
    },
  },
};

export interface VulnVerifierInput {
  finding: {
    title: string;
    severity?: string;
    cve?: string;
    description: string;
    evidence: string;
    source: string;
    hostname: string;
    port?: number;
  };
  assetContext?: string;
  engagement?: {
    engagementType: string;
    clientName?: string;
    industry?: string;
    scope?: string;
    targetCount: number;
  };
  engagementId?: number;
}

export interface VulnVerifierOutput {
  finding_summary: string;
  affected_asset: string;
  affected_asset_function: string;
  evidence_review: Array<{ tag: string; detail: string }>;
  false_positive_likelihood: string;
  exploitability: {
    rating: string;
    prerequisites: string[];
    known_exploits: boolean;
    rationale: string;
  };
  business_impact: { severity: string; rationale: string };
  attacker_interest: string;
  attack_mapping: Array<{ technique_id: string; technique_name: string; tactic: string }>;
  safe_validation_step: string;
  analyst_verdict: string;
  confidence: string;
}

export async function verifyVulnerability(input: VulnVerifierInput): Promise<VulnVerifierOutput> {
  // Inject banking domain knowledge if applicable
  let bankingVulnCtx = '';
  try {
    if (/bank|altoro|mutual|vulnbank|fintech|payment/i.test(input.finding?.hostname || '')) {
      const { getBankingContextCompact } = await import('./banking-domain-knowledge');
      bankingVulnCtx = '\n\n' + getBankingContextCompact();
    }
  } catch (e) { /* non-fatal */ }

  // Inject missed vuln training knowledge to reduce false negatives
  let missedVulnCtx = '';
  try {
    const { getMissedVulnSummary } = await import('../knowledge/missed-vuln-training-knowledge');
    const summary = getMissedVulnSummary();
    const relevantPatterns = summary.filter(p =>
      p.cwe.some(c => input.finding?.cwe?.includes(c) || input.finding?.title?.toLowerCase().includes(p.name.toLowerCase().split(' ')[0]))
    );
    if (relevantPatterns.length > 0) {
      missedVulnCtx = '\n\nKnown missed vulnerability patterns relevant to this finding:\n' +
        relevantPatterns.map(p => `- ${p.name} (${p.severity}, CWE: ${p.cwe.join(', ')})`).join('\n') +
        '\nThese patterns are frequently missed by automated scanners. Be more lenient when verifying findings that match these patterns.';
    }
  } catch (e) { /* non-fatal */ }

  const systemPrompt = assembleSystemPrompt({
    rolePrompt: ROLE_PROMPT,
    customerContext: input.engagement ? buildCustomerContext(input.engagement) : undefined,
    assetContext: (input.assetContext || '') + bankingVulnCtx + missedVulnCtx,
  });

  const f = input.finding;
  const userMessage = [
    `Verify the following vulnerability finding:`,
    ``,
    `Title: ${f.title}`,
    f.severity ? `Severity: ${f.severity}` : null,
    f.cve ? `CVE: ${f.cve}` : null,
    `Source: ${f.source}`,
    `Host: ${f.hostname}${f.port ? ':' + f.port : ''}`,
    ``,
    `Description: ${f.description}`,
    ``,
    `Evidence:`,
    f.evidence,
  ].filter(Boolean).join('\n');

  const result = await throttledLLMCall({ _priority: 'essential',
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage },
    ],
    response_format: OUTPUT_SCHEMA,
    _caller: "specialist:vuln-verifier",
    _engagementId: input.engagementId,
  });

  const content = result.choices?.[0]?.message?.content;
  if (!content) throw new Error("Vuln verifier returned empty response");
  return JSON.parse(content) as VulnVerifierOutput;
}
