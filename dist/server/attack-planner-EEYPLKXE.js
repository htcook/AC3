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
} from "./chunk-KGBBSWIP.js";
import "./chunk-WJ24GKGB.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/llm-specialists/attack-planner.ts
async function planAttack(input) {
  let bankingAttackCtx = "";
  try {
    const isBanking = input.assets?.some((a) => /bank|altoro|mutual|vulnbank|fintech|payment/i.test(a.hostname || ""));
    if (isBanking) {
      const { buildBankingDomainContext } = await import("./banking-domain-knowledge-Y6J6N5XW.js");
      bankingAttackCtx = "\n\n" + buildBankingDomainContext({ phase: "vuln_detection", includeRegulatory: true, includeTechStack: true, includeAttackScenarios: true });
    }
  } catch (e) {
  }
  let missedVulnCtx = "";
  try {
    const { buildMissedVulnAttackContext } = await import("./missed-vuln-training-knowledge-JOACOWBY.js");
    const targetPreset = input.assets?.[0]?.hostname?.includes("juice") ? "juice-shop" : input.assets?.[0]?.hostname?.includes("dvwa") ? "dvwa" : input.assets?.[0]?.hostname?.includes("bwapp") ? "bwapp" : input.assets?.[0]?.hostname?.includes("mutillidae") ? "mutillidae" : input.assets?.[0]?.hostname?.includes("webgoat") ? "webgoat" : input.assets?.[0]?.hostname?.includes("crapi") ? "crapi" : void 0;
    missedVulnCtx = "\n\n## Commonly Missed Vulnerabilities \u2014 MUST Include in Attack Plan\n" + buildMissedVulnAttackContext(targetPreset);
  } catch (e) {
  }
  const systemPrompt = assembleSystemPrompt({
    rolePrompt: ROLE_PROMPT,
    customerContext: buildCustomerContext(input.engagement),
    assetContext: buildAssetContext(input.assets) + bankingAttackCtx + missedVulnCtx
  });
  const userMessage = `Based on the following passive reconnaissance results, design an attack path and active scanning strategy:

${input.passiveReconSummary}`;
  const result = await throttledLLMCall({
    _priority: "essential",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage }
    ],
    response_format: OUTPUT_SCHEMA,
    _caller: "specialist:attack-planner",
    _engagementId: input.engagementId
  });
  const content = result.choices?.[0]?.message?.content;
  if (!content) throw new Error("Attack planner returned empty response");
  return parseLLMJson(content, { fallback: {} }).data;
}
var ROLE_PROMPT, OUTPUT_SCHEMA;
var init_attack_planner = __esm({
  "server/lib/llm-specialists/attack-planner.ts"() {
    init_llm_throttle();
    init_core_policy();
    init_llm_json_parser();
    ROLE_PROMPT = `## Role: Attack Path Planner

You are the AC3 Adversary Emulation Planner.

Your task is to design realistic attack paths and determine optimal active scanning strategy based on discovered assets and passive reconnaissance.

Priorities:
\u2022 Operational realism \u2014 only suggest attacks that are feasible given the evidence
\u2022 Minimal assumptions \u2014 don't invent services or vulnerabilities not observed
\u2022 Realistic attacker goals \u2014 focus on what a real adversary would target
\u2022 Privilege escalation opportunities \u2014 identify paths to higher access

Attack stages to consider:
Initial Access \u2192 Credential Access \u2192 Privilege Escalation \u2192 Persistence \u2192 Lateral Movement \u2192 Collection \u2192 Exfiltration

Available active scan tools:
\u2022 ScanForge Discovery (Masscan/Naabu/RustScan): High-speed port scanning, service detection
\u2022 httpx: HTTP probing, tech fingerprinting, response analysis
\u2022 nuclei: Template-based vulnerability scanning (CVEs, misconfigs, exposures)
\u2022 zap: Web application scanning (OWASP Top 10, XSS, SQLi, CSRF)
\u2022 nikto: Web server misconfiguration scanning
\u2022 gobuster: Directory/file brute-forcing
\u2022 ffuf: Web fuzzing (parameters, paths, vhosts)
\u2022 testssl: TLS/SSL configuration testing
\u2022 dnsrecon: DNS enumeration and zone transfer testing`;
    OUTPUT_SCHEMA = {
      type: "json_schema",
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
                  rationale: { type: "string" }
                },
                required: ["vector", "target", "feasibility", "evidence_tag", "rationale"],
                additionalProperties: false
              }
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
                  description: { type: "string" }
                },
                required: ["stage", "technique", "mitre_id", "target", "description"],
                additionalProperties: false
              }
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
                      rationale: { type: "string" }
                    },
                    required: ["target", "ports", "flags", "rationale"],
                    additionalProperties: false
                  }
                },
                nuclei_targets: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      target: { type: "string" },
                      templates: { type: "string", description: "Template tags or paths e.g. cves,misconfig,exposure" },
                      rationale: { type: "string" }
                    },
                    required: ["target", "templates", "rationale"],
                    additionalProperties: false
                  }
                },
                web_scan_targets: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      target: { type: "string" },
                      tool: { type: "string", description: "zap | nikto | gobuster | ffuf | testssl" },
                      config: { type: "string", description: "Tool-specific configuration" },
                      rationale: { type: "string" }
                    },
                    required: ["target", "tool", "config", "rationale"],
                    additionalProperties: false
                  }
                }
              },
              required: ["discovery_targets", "nuclei_targets", "web_scan_targets"],
              additionalProperties: false
            },
            detection_opportunities: {
              type: "array",
              items: { type: "string" },
              description: "What defenders might detect during this attack"
            },
            estimated_impact: { type: "string" },
            confidence: { type: "string", description: "High | Medium | Low" }
          },
          required: ["attack_objective", "initial_access_options", "attack_chain", "scan_plan", "detection_opportunities", "estimated_impact", "confidence"],
          additionalProperties: false
        }
      }
    };
  }
});
init_attack_planner();
export {
  planAttack
};
