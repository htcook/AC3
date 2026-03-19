/**
 * AC3 LLM Specialist — Threat Actor Mapper
 *
 * Correlates findings with APT and cybercrime groups.
 * Used after passive/active scanning to identify relevant threat actors.
 */

import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { assembleSystemPrompt, buildAssetContext, buildCustomerContext } from "./core-policy";

const ROLE_PROMPT = `## Role: Threat Actor Correlation Engine

You are the AC3 Threat Actor Correlation Engine.

Your job is to identify which threat actors may realistically target the organization or infrastructure based on observed evidence.

Evaluate:
• Industry sector and geographic region
• Exposed technologies and services
• Identity surfaces (SSO, VPN, email gateways)
• Cloud footprint and provider
• Internet-facing services and their versions
• Known vulnerability exposure

Map findings to known attacker behaviors when supported by evidence.
Do NOT force ATT&CK mappings without plausible operational alignment.
Do NOT list every APT group — only those with genuine relevance to the target.`;

const OUTPUT_SCHEMA = {
  type: "json_schema" as const,
  json_schema: {
    name: "threat_mapping",
    strict: true,
    schema: {
      type: "object",
      properties: {
        threat_exposure_summary: { type: "string" },
        sector_threat_landscape: { type: "string" },
        likely_threat_actors: {
          type: "array",
          items: {
            type: "object",
            properties: {
              name: { type: "string", description: "Threat actor name e.g. APT29, FIN7" },
              aliases: { type: "array", items: { type: "string" } },
              type: { type: "string", description: "nation_state | cybercrime | hacktivism | ransomware" },
              relevance: { type: "string", description: "Why this actor is relevant to this target" },
              evidence_tag: { type: "string", description: "OBSERVED | INFERRED | HYPOTHESIS" },
              confidence: { type: "string", description: "High | Medium | Low" },
            },
            required: ["name", "aliases", "type", "relevance", "evidence_tag", "confidence"],
            additionalProperties: false,
          },
        },
        attack_behaviors: {
          type: "array",
          items: {
            type: "object",
            properties: {
              technique_id: { type: "string" },
              technique_name: { type: "string" },
              tactic: { type: "string" },
              actors_using: { type: "array", items: { type: "string" } },
              relevance_to_target: { type: "string" },
            },
            required: ["technique_id", "technique_name", "tactic", "actors_using", "relevance_to_target"],
            additionalProperties: false,
          },
        },
        defensive_priorities: {
          type: "array",
          items: { type: "string" },
          description: "Top defensive actions based on threat actor alignment",
        },
        overall_confidence: { type: "string", description: "High | Medium | Low" },
      },
      required: ["threat_exposure_summary", "sector_threat_landscape", "likely_threat_actors", "attack_behaviors", "defensive_priorities", "overall_confidence"],
      additionalProperties: false,
    },
  },
};

export interface ThreatMapperInput {
  findingsSummary: string;
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

export interface ThreatMapperOutput {
  threat_exposure_summary: string;
  sector_threat_landscape: string;
  likely_threat_actors: Array<{
    name: string;
    aliases: string[];
    type: string;
    relevance: string;
    evidence_tag: string;
    confidence: string;
  }>;
  attack_behaviors: Array<{
    technique_id: string;
    technique_name: string;
    tactic: string;
    actors_using: string[];
    relevance_to_target: string;
  }>;
  defensive_priorities: string[];
  overall_confidence: string;
}

export async function mapThreats(input: ThreatMapperInput): Promise<ThreatMapperOutput> {
  // Inject banking domain knowledge if applicable
  let bankingThreatCtx = '';
  try {
    const isBanking = input.assets?.some((a: any) => /bank|altoro|mutual|vulnbank|fintech|payment/i.test(a.hostname || ''));
    if (isBanking) {
      const { getBankingContextCompact } = await import('./banking-domain-knowledge');
      bankingThreatCtx = '\n\n' + getBankingContextCompact() + '\n\nKnown banking threat actors: Carbanak/FIN7, Lazarus Group (DPRK), APT38, Silence Group, TA505, FIN8, Cobalt Group, Magecart. Focus on financial sector TTPs: credential harvesting, SWIFT fraud, ATM jackpotting, card skimming, business email compromise, and ransomware targeting financial institutions.';
    }
  } catch (e) { /* non-fatal */ }
  const systemPrompt = assembleSystemPrompt({
    rolePrompt: ROLE_PROMPT,
    customerContext: buildCustomerContext(input.engagement),
    assetContext: buildAssetContext(input.assets) + bankingThreatCtx,
  });

  const userMessage = `Based on the following scan findings and asset data, identify relevant threat actors and attack behaviors:\n\n${input.findingsSummary}`;

  const result = await throttledLLMCall({ _priority: 'essential',
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage },
    ],
    response_format: OUTPUT_SCHEMA,
    _caller: "specialist:threat-mapper",
    _engagementId: input.engagementId,
  });

  const content = result.choices?.[0]?.message?.content;
  if (!content) throw new Error("Threat mapper returned empty response");
  return JSON.parse(content) as ThreatMapperOutput;
}
