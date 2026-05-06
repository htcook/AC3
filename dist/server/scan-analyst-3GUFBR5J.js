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
} from "./chunk-UJVJACSD.js";
import "./chunk-4BQS7LEI.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/llm-specialists/scan-analyst.ts
async function analyzeScan(input) {
  let bankingAdditionalCtx = "";
  try {
    if (/bank|altoro|mutual|vulnbank|fintech|payment/i.test(input.hostname || "")) {
      const { getBankingContextCompact } = await import("./banking-domain-knowledge-Y6J6N5XW.js");
      bankingAdditionalCtx = "\n\n" + getBankingContextCompact();
    }
  } catch (e) {
  }
  const systemPrompt = assembleSystemPrompt({
    rolePrompt: ROLE_PROMPT,
    customerContext: input.engagement ? buildCustomerContext(input.engagement) : void 0,
    assetContext: input.assets ? buildAssetContext(input.assets) : void 0,
    additionalContext: FEW_SHOT_EXAMPLE + bankingAdditionalCtx
  });
  const userMessage = `Analyze the following scan data for: ${input.hostname}

${input.scanData}`;
  const result = await throttledLLMCall({
    _priority: "essential",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage }
    ],
    response_format: OUTPUT_SCHEMA,
    _caller: "specialist:scan-analyst",
    _engagementId: input.engagementId
  });
  const content = result.choices?.[0]?.message?.content;
  if (!content) throw new Error("Scan analyst returned empty response");
  return parseLLMJson(content, { fallback: {} }).data;
}
var ROLE_PROMPT, OUTPUT_SCHEMA, FEW_SHOT_EXAMPLE;
var init_scan_analyst = __esm({
  "server/lib/llm-specialists/scan-analyst.ts"() {
    init_llm_throttle();
    init_core_policy();
    init_llm_json_parser();
    ROLE_PROMPT = `## Role: Scan Analyst

You are the AC3 Scan Analysis Module.

Your job is to interpret reconnaissance and scan data like a senior penetration tester.

Focus on determining:
\u2022 What the asset likely is
\u2022 What role it serves in the environment
\u2022 Whether exposure is meaningful

Priorities:
1. Identify asset function
2. Determine exposure type (intentional public service vs misconfiguration)
3. Evaluate attacker interest level
4. Highlight unusual configuration signals

Asset classes to consider:
\u2022 Reverse proxy / ingress: nginx, envoy, haproxy, traefik
\u2022 Identity infrastructure: Okta, Entra ID, ADFS, Keycloak
\u2022 CI/CD systems: Jenkins, GitLab, GitHub Actions
\u2022 Cloud control plane: AWS console, Azure management, GCP console
\u2022 Data infrastructure: SQL databases, object storage, Redis, Elasticsearch
\u2022 Admin surfaces: admin panels, bastions, VPN portals, SSH gateways
\u2022 API services: REST/GraphQL endpoints, microservice gateways`;
    OUTPUT_SCHEMA = {
      type: "json_schema",
      json_schema: {
        name: "scan_analysis",
        strict: true,
        schema: {
          type: "object",
          properties: {
            asset_summary: { type: "string", description: "Brief description of the asset" },
            likely_function: { type: "string", description: "What role this asset serves" },
            exposure_analysis: {
              type: "object",
              properties: {
                type: { type: "string", description: "intentional_public | misconfiguration | internal_leak | unknown" },
                severity: { type: "string", description: "High | Medium | Low | Informational" },
                rationale: { type: "string", description: "Why this exposure matters or doesn't" }
              },
              required: ["type", "severity", "rationale"],
              additionalProperties: false
            },
            evidence: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  tag: { type: "string", description: "OBSERVED | INFERRED | HYPOTHESIS" },
                  detail: { type: "string" }
                },
                required: ["tag", "detail"],
                additionalProperties: false
              }
            },
            security_significance: { type: "string", description: "High | Medium | Low" },
            attacker_interest: {
              type: "object",
              properties: {
                level: { type: "string", description: "High | Medium | Low" },
                rationale: { type: "string" }
              },
              required: ["level", "rationale"],
              additionalProperties: false
            },
            recommended_next: {
              type: "array",
              items: { type: "string" },
              description: "Recommended next investigation steps"
            },
            confidence: { type: "string", description: "High | Medium | Low" }
          },
          required: ["asset_summary", "likely_function", "exposure_analysis", "evidence", "security_significance", "attacker_interest", "recommended_next", "confidence"],
          additionalProperties: false
        }
      }
    };
    FEW_SHOT_EXAMPLE = `## Example

Input:
Host: login.company.com
Observations: Public login page, SSO detected, Okta integration

Output:
{
  "asset_summary": "Internet-facing authentication portal with SSO integration",
  "likely_function": "Employee or contractor authentication gateway",
  "exposure_analysis": { "type": "intentional_public", "severity": "Medium", "rationale": "Login portals are expected to be public but represent high-value targets for credential attacks" },
  "evidence": [
    { "tag": "OBSERVED", "detail": "Public login page with Okta SSO integration detected" },
    { "tag": "INFERRED", "detail": "Likely serves as primary authentication gateway for internal services" }
  ],
  "security_significance": "High",
  "attacker_interest": { "level": "High", "rationale": "Identity infrastructure is a primary target for credential theft, MFA bypass, and initial access campaigns" },
  "recommended_next": ["Test for MFA enforcement", "Check for credential stuffing protections", "Enumerate SSO provider configuration"],
  "confidence": "High"
}`;
  }
});
init_scan_analyst();
export {
  analyzeScan
};
