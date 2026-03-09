/**
 * Ace C3 LLM Specialist — Attack Path Planner
 *
 * Designs realistic attack paths based on discovered assets and vulnerabilities.
 * Used by generateScanPlan and active scan strategy determination.
 */

import { invokeLLM } from "../../_core/llm";
import { assembleSystemPrompt, buildAssetContext, buildCustomerContext } from "./core-policy";

const ROLE_PROMPT = `## Role: Attack Path Planner

You are the Ace C3 Adversary Emulation Planner.

Your task is to design realistic attack paths and determine optimal active scanning strategy based on discovered assets and passive reconnaissance.

Priorities:
• Operational realism — only suggest attacks that are feasible given the evidence
• Minimal assumptions — don't invent services or vulnerabilities not observed
• Realistic attacker goals — focus on what a real adversary would target
• Privilege escalation opportunities — identify paths to higher access

Attack stages to consider:
Initial Access → Credential Access → Privilege Escalation → Persistence → Lateral Movement → Collection → Exfiltration

Available active scan tools:
• nmap: Port scanning, service detection, OS fingerprinting, NSE scripts
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
            nmap_targets: {
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
          required: ["nmap_targets", "nuclei_targets", "web_scan_targets"],
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
    nmap_targets: Array<{ target: string; ports: string; flags: string; rationale: string }>;
    nuclei_targets: Array<{ target: string; templates: string; rationale: string }>;
    web_scan_targets: Array<{ target: string; tool: string; config: string; rationale: string }>;
  };
  detection_opportunities: string[];
  estimated_impact: string;
  confidence: string;
}

export async function planAttack(input: AttackPlannerInput): Promise<AttackPlannerOutput> {
  const systemPrompt = assembleSystemPrompt({
    rolePrompt: ROLE_PROMPT,
    customerContext: buildCustomerContext(input.engagement),
    assetContext: buildAssetContext(input.assets),
  });

  const userMessage = `Based on the following passive reconnaissance results, design an attack path and active scanning strategy:\n\n${input.passiveReconSummary}`;

  const result = await invokeLLM({ _priority: 'essential',
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
  return JSON.parse(content) as AttackPlannerOutput;
}
