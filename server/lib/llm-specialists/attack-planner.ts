/**
 * AC3 LLM Specialist — Attack Path Planner
 *
 * Designs realistic attack paths based on discovered assets and vulnerabilities.
 * Used by generateScanPlan and active scan strategy determination.
 *
 * IMPORTANT: This specialist receives passiveReconSummary from the orchestrator
 * which already contains asset data + enrichment context (capped at 12K chars).
 * To avoid token overflow (429 "Request too large"), we:
 *   1. Do NOT duplicate asset data via buildAssetContext (it's in passiveReconSummary)
 *   2. Use compact banking context instead of full domain knowledge
 *   3. Cap the total prompt to MAX_SPECIALIST_CHARS
 *   4. Truncate passiveReconSummary if needed to fit budget
 */

import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { assembleSystemPrompt, buildCustomerContext } from "./core-policy";
import { parseLLMJson } from "../../../shared/llm-json-parser";

/**
 * Maximum total characters for the specialist prompt (system + user).
 * ~10K tokens ≈ 40K chars. Leaves headroom for the response_format schema
 * and the LLM's own response within the model's context window.
 */
const MAX_SPECIALIST_CHARS = 40_000;

/**
 * Estimate character count for the response_format schema overhead.
 * The JSON schema is sent as part of the request and counts toward tokens.
 */
const SCHEMA_OVERHEAD_CHARS = 2_000;

const ROLE_PROMPT = `## Role: Attack Path Planner

You are the AC3 Adversary Emulation Planner.

Your task is to design realistic attack paths and determine optimal active scanning strategy based on discovered assets and passive reconnaissance.

Priorities:
• Operational realism — only suggest attacks that are feasible given the evidence
• Minimal assumptions — don't invent services or vulnerabilities not observed
• Realistic attacker goals — focus on what a real adversary would target
• Privilege escalation opportunities — identify paths to higher access

Attack stages to consider:
Initial Access → Credential Access → Privilege Escalation → Persistence → Lateral Movement → Collection → Exfiltration

Available active scan tools:
• ScanForge Discovery (Masscan/Naabu/RustScan): High-speed port scanning, service detection
• httpx: HTTP probing, tech fingerprinting, response analysis
• nuclei: Template-based vulnerability scanning (CVEs, misconfigs, exposures)
• zap: Web application scanning (OWASP Top 10, XSS, SQLi, CSRF)
• nikto: Web server misconfiguration scanning
• gobuster: Directory/file brute-forcing
• ffuf: Web fuzzing (parameters, paths, vhosts)
• testssl: TLS/SSL configuration testing
• dnsrecon: DNS enumeration and zone transfer testing`;

const OUTPUT_SCHEMA = {
  type: "json_schema" as const,
  json_schema: {
    name: "attack_plan",
    strict: true,
    schema: {
      type: "object",
      properties: {
        attack_objective: { type: "string", description: "Primary goal of the attack path" },
        initial_access_options: {
          type: "array",
          items: {
            type: "object",
            properties: {
              vector: { type: "string" },
              target: { type: "string" },
              feasibility: { type: "string", description: "High | Medium | Low" },
              evidence_tag: { type: "string", description: "OBSERVED | INFERRED | HYPOTHESIS" },
              rationale: { type: "string" },
            },
            required: ["vector", "target", "feasibility", "evidence_tag", "rationale"],
            additionalProperties: false,
          },
        },
        attack_chain: {
          type: "array",
          items: {
            type: "object",
            properties: {
              stage: { type: "string" },
              technique: { type: "string" },
              mitre_id: { type: "string", description: "ATT&CK technique ID e.g. T1190" },
              target: { type: "string" },
              description: { type: "string" },
            },
            required: ["stage", "technique", "mitre_id", "target", "description"],
            additionalProperties: false,
          },
        },
        scan_plan: {
          type: "object",
          properties: {
            discovery_targets: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  target: { type: "string" },
                  ports: { type: "string", description: "Port specification e.g. 1-1000 or 80,443,8080" },
                  flags: { type: "string", description: "Nmap flags e.g. -sV -sC --script=http-enum" },
                  rationale: { type: "string" },
                },
                required: ["target", "ports", "flags", "rationale"],
                additionalProperties: false,
              },
            },
            nuclei_targets: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  target: { type: "string" },
                  templates: { type: "string", description: "Template tags or paths e.g. cves,misconfig,exposure" },
                  rationale: { type: "string" },
                },
                required: ["target", "templates", "rationale"],
                additionalProperties: false,
              },
            },
            web_scan_targets: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  target: { type: "string" },
                  tool: { type: "string", description: "zap | nikto | gobuster | ffuf | testssl" },
                  config: { type: "string", description: "Tool-specific configuration" },
                  rationale: { type: "string" },
                },
                required: ["target", "tool", "config", "rationale"],
                additionalProperties: false,
              },
            },
          },
          required: ["discovery_targets", "nuclei_targets", "web_scan_targets"],
          additionalProperties: false,
        },
        detection_opportunities: {
          type: "array",
          items: { type: "string" },
          description: "What defenders might detect during this attack",
        },
        estimated_impact: { type: "string" },
        confidence: { type: "string", description: "High | Medium | Low" },
      },
      required: ["attack_objective", "initial_access_options", "attack_chain", "scan_plan", "detection_opportunities", "estimated_impact", "confidence"],
      additionalProperties: false,
    },
  },
};

export interface AttackPlannerInput {
  passiveReconSummary: string;
  engagement: {
    engagementType: string;
    clientName?: string;
    industry?: string;
    scope?: string;
    targetCount: number;
  };
  assets: Array<{
    hostname: string;
    ip?: string;
    type: string;
    status?: string;
    ports?: Array<{ port: number; service?: string; version?: string }>;
    technologies?: string[];
    wafDetected?: string;
    cloudProvider?: string;
    riskSignals?: Array<{ severity: string; rationale: string }>;
  }>;
  engagementId?: number;
}

export interface AttackPlannerOutput {
  attack_objective: string;
  initial_access_options: Array<{
    vector: string;
    target: string;
    feasibility: string;
    evidence_tag: string;
    rationale: string;
  }>;
  attack_chain: Array<{
    stage: string;
    technique: string;
    mitre_id: string;
    target: string;
    description: string;
  }>;
  scan_plan: {
    discovery_targets: Array<{ target: string; ports: string; flags: string; rationale: string }>;
    nuclei_targets: Array<{ target: string; templates: string; rationale: string }>;
    web_scan_targets: Array<{ target: string; tool: string; config: string; rationale: string }>;
  };
  detection_opportunities: string[];
  estimated_impact: string;
  confidence: string;
}

/**
 * Truncate a string to maxLen characters, appending a marker if truncated.
 */
function truncateWithMarker(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen) + '\n[...truncated to fit token budget]';
}

export async function planAttack(input: AttackPlannerInput): Promise<AttackPlannerOutput> {
  // ── Step 1: Build compact domain-specific context (NOT the full knowledge base) ──
  let domainHint = '';
  try {
    const isBanking = input.assets?.some((a: any) => /bank|altoro|mutual|vulnbank|fintech|payment/i.test(a.hostname || ''));
    if (isBanking) {
      // Use compact banking context (~500 chars) instead of full domain knowledge (~12K+)
      const { getBankingContextCompact } = await import('./banking-domain-knowledge');
      domainHint = '\n\n## Domain Context\n' + getBankingContextCompact();
    }
  } catch (e) { /* non-fatal */ }

  // ── Step 2: Build compact missed vuln hint (top 5 most relevant, not all 19) ──
  let missedVulnHint = '';
  try {
    const { buildMissedVulnAttackContext } = await import('../knowledge/missed-vuln-training-knowledge');
    const targetPreset = input.assets?.[0]?.hostname?.includes('juice') ? 'juice-shop'
      : input.assets?.[0]?.hostname?.includes('dvwa') ? 'dvwa'
      : input.assets?.[0]?.hostname?.includes('bwapp') ? 'bwapp'
      : input.assets?.[0]?.hostname?.includes('mutillidae') ? 'mutillidae'
      : input.assets?.[0]?.hostname?.includes('webgoat') ? 'webgoat'
      : input.assets?.[0]?.hostname?.includes('crapi') ? 'crapi'
      : undefined;
    const fullCtx = buildMissedVulnAttackContext(targetPreset);
    // Take only the first 5 lines (most relevant patterns) to save tokens
    const lines = fullCtx.split('\n').filter(Boolean);
    const trimmed = lines.slice(0, 5).join('\n');
    if (trimmed) {
      missedVulnHint = '\n\n## Key Missed Vulnerabilities\n' + trimmed;
    }
  } catch (e) { /* non-fatal */ }

  // ── Step 3: Assemble system prompt WITHOUT duplicate asset data ──
  // passiveReconSummary already contains full asset data + enrichment context,
  // so we only put engagement metadata + domain hints in the system prompt.
  const systemPrompt = assembleSystemPrompt({
    rolePrompt: ROLE_PROMPT,
    customerContext: buildCustomerContext(input.engagement),
    // NO buildAssetContext here — assets are in passiveReconSummary (user message)
    additionalContext: (domainHint + missedVulnHint).trim() || undefined,
  });

  // ── Step 4: Budget-aware user message truncation ──
  const userPrefix = 'Based on the following passive reconnaissance results, design an attack path and active scanning strategy:\n\n';
  const totalBudget = MAX_SPECIALIST_CHARS - SCHEMA_OVERHEAD_CHARS;
  const systemLen = systemPrompt.length;
  const prefixLen = userPrefix.length;
  const reconBudget = Math.max(totalBudget - systemLen - prefixLen, 4_000); // At least 4K chars for recon

  const reconSummary = truncateWithMarker(input.passiveReconSummary, reconBudget);
  const userMessage = userPrefix + reconSummary;

  // ── Step 5: Log prompt size for observability ──
  const totalChars = systemPrompt.length + userMessage.length;
  const estimatedTokens = Math.ceil(totalChars / 4);
  console.log(`[AttackPlanner] Prompt size: ${totalChars} chars (~${estimatedTokens} tokens). System: ${systemPrompt.length}, User: ${userMessage.length}. Budget: ${totalBudget}`);

  if (totalChars > MAX_SPECIALIST_CHARS) {
    console.warn(`[AttackPlanner] WARNING: Prompt exceeds budget (${totalChars} > ${MAX_SPECIALIST_CHARS}). May hit token limits.`);
  }

  const result = await throttledLLMCall({ _priority: 'essential',
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage },
    ],
    response_format: OUTPUT_SCHEMA,
    _caller: "specialist:attack-planner",
    _engagementId: input.engagementId,
  });

  const content = result.choices?.[0]?.message?.content;
  if (!content) throw new Error("Attack planner returned empty response");
  return parseLLMJson<AttackPlannerOutput>(content, { fallback: {} as AttackPlannerOutput }).data;
}
