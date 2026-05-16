import {
  assembleSystemPrompt,
  buildAssetContext,
  buildCustomerContext,
  init_core_policy
} from "./chunk-NO5RORCF.js";
import {
  init_llm_json_parser,
  parseLLMJson
} from "./chunk-UQ7CH3JX.js";
import {
  init_llm_throttle,
  throttledLLMCall
} from "./chunk-PJBTUWZW.js";
import "./chunk-AOUQ6RTC.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-KDOLKO2A.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/llm-specialists/threat-mapper.ts
async function mapThreats(input) {
  let bankingThreatCtx = "";
  try {
    const isBanking = input.assets?.some((a) => /bank|altoro|mutual|vulnbank|fintech|payment/i.test(a.hostname || ""));
    if (isBanking) {
      const { getBankingContextCompact } = await import("./banking-domain-knowledge-Y6J6N5XW.js");
      bankingThreatCtx = "\n\n" + getBankingContextCompact() + "\n\nKnown banking threat actors: Carbanak/FIN7, Lazarus Group (DPRK), APT38, Silence Group, TA505, FIN8, Cobalt Group, Magecart. Focus on financial sector TTPs: credential harvesting, SWIFT fraud, ATM jackpotting, card skimming, business email compromise, and ransomware targeting financial institutions.";
    }
  } catch (e) {
  }
  const systemPrompt = assembleSystemPrompt({
    rolePrompt: ROLE_PROMPT,
    customerContext: buildCustomerContext(input.engagement),
    assetContext: buildAssetContext(input.assets) + bankingThreatCtx
  });
  const userMessage = `Based on the following scan findings and asset data, identify relevant threat actors and attack behaviors:

${input.findingsSummary}`;
  const result = await throttledLLMCall({
    _priority: "essential",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage }
    ],
    response_format: OUTPUT_SCHEMA,
    _caller: "specialist:threat-mapper",
    _engagementId: input.engagementId
  });
  const content = result.choices?.[0]?.message?.content;
  if (!content) throw new Error("Threat mapper returned empty response");
  return parseLLMJson(content, { fallback: {} }).data;
}
var ROLE_PROMPT, OUTPUT_SCHEMA;
var init_threat_mapper = __esm({
  "server/lib/llm-specialists/threat-mapper.ts"() {
    init_llm_throttle();
    init_core_policy();
    init_llm_json_parser();
    ROLE_PROMPT = `## Role: Threat Actor Correlation Engine

You are the AC3 Threat Actor Correlation Engine.

Your job is to identify which threat actors may realistically target the organization or infrastructure based on observed evidence.

Evaluate:
\u2022 Industry sector and geographic region
\u2022 Exposed technologies and services
\u2022 Identity surfaces (SSO, VPN, email gateways)
\u2022 Cloud footprint and provider
\u2022 Internet-facing services and their versions
\u2022 Known vulnerability exposure

Map findings to known attacker behaviors when supported by evidence.
Do NOT force ATT&CK mappings without plausible operational alignment.
Do NOT list every APT group \u2014 only those with genuine relevance to the target.`;
    OUTPUT_SCHEMA = {
      type: "json_schema",
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
                  confidence: { type: "string", description: "High | Medium | Low" }
                },
                required: ["name", "aliases", "type", "relevance", "evidence_tag", "confidence"],
                additionalProperties: false
              }
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
                  relevance_to_target: { type: "string" }
                },
                required: ["technique_id", "technique_name", "tactic", "actors_using", "relevance_to_target"],
                additionalProperties: false
              }
            },
            defensive_priorities: {
              type: "array",
              items: { type: "string" },
              description: "Top defensive actions based on threat actor alignment"
            },
            overall_confidence: { type: "string", description: "High | Medium | Low" }
          },
          required: ["threat_exposure_summary", "sector_threat_landscape", "likely_threat_actors", "attack_behaviors", "defensive_priorities", "overall_confidence"],
          additionalProperties: false
        }
      }
    };
  }
});
init_threat_mapper();
export {
  mapThreats
};
