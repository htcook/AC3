/**
 * AC3 LLM Specialist — Scan Analyst
 *
 * Interprets reconnaissance and scan data like a senior penetration tester.
 * Used during passive recon analysis and active scan interpretation.
 */

import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { assembleSystemPrompt, buildAssetContext, buildCustomerContext } from "./core-policy";

const ROLE_PROMPT = `## Role: Scan Analyst

You are the AC3 Scan Analysis Module.

Your job is to interpret reconnaissance and scan data like a senior penetration tester.

Focus on determining:
• What the asset likely is
• What role it serves in the environment
• Whether exposure is meaningful

Priorities:
1. Identify asset function
2. Determine exposure type (intentional public service vs misconfiguration)
3. Evaluate attacker interest level
4. Highlight unusual configuration signals

Asset classes to consider:
• Reverse proxy / ingress: nginx, envoy, haproxy, traefik
• Identity infrastructure: Okta, Entra ID, ADFS, Keycloak
• CI/CD systems: Jenkins, GitLab, GitHub Actions
• Cloud control plane: AWS console, Azure management, GCP console
• Data infrastructure: SQL databases, object storage, Redis, Elasticsearch
• Admin surfaces: admin panels, bastions, VPN portals, SSH gateways
• API services: REST/GraphQL endpoints, microservice gateways`;

const OUTPUT_SCHEMA = {
  type: "json_schema" as const,
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
            rationale: { type: "string", description: "Why this exposure matters or doesn't" },
          },
          required: ["type", "severity", "rationale"],
          additionalProperties: false,
        },
        evidence: {
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
        security_significance: { type: "string", description: "High | Medium | Low" },
        attacker_interest: {
          type: "object",
          properties: {
            level: { type: "string", description: "High | Medium | Low" },
            rationale: { type: "string" },
          },
          required: ["level", "rationale"],
          additionalProperties: false,
        },
        recommended_next: {
          type: "array",
          items: { type: "string" },
          description: "Recommended next investigation steps",
        },
        confidence: { type: "string", description: "High | Medium | Low" },
      },
      required: ["asset_summary", "likely_function", "exposure_analysis", "evidence", "security_significance", "attacker_interest", "recommended_next", "confidence"],
      additionalProperties: false,
    },
  },
};

const FEW_SHOT_EXAMPLE = `## Example

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

export interface ScanAnalystInput {
  hostname: string;
  scanData: string;
  engagement?: {
    engagementType: string;
    clientName?: string;
    industry?: string;
    scope?: string;
    targetCount: number;
  };
  assets?: Array<{
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

export interface ScanAnalystOutput {
  asset_summary: string;
  likely_function: string;
  exposure_analysis: { type: string; severity: string; rationale: string };
  evidence: Array<{ tag: string; detail: string }>;
  security_significance: string;
  attacker_interest: { level: string; rationale: string };
  recommended_next: string[];
  confidence: string;
}

export async function analyzeScan(input: ScanAnalystInput): Promise<ScanAnalystOutput> {
  // Inject banking domain knowledge if applicable
  let bankingAdditionalCtx = '';
  try {
    if (/bank|altoro|mutual|vulnbank|fintech|payment/i.test(input.hostname || '')) {
      const { getBankingContextCompact } = await import('./banking-domain-knowledge');
      bankingAdditionalCtx = '\n\n' + getBankingContextCompact();
    }
  } catch (e) { /* non-fatal */ }
  const systemPrompt = assembleSystemPrompt({
    rolePrompt: ROLE_PROMPT,
    customerContext: input.engagement ? buildCustomerContext(input.engagement) : undefined,
    assetContext: input.assets ? buildAssetContext(input.assets) : undefined,
    additionalContext: FEW_SHOT_EXAMPLE + bankingAdditionalCtx,
  });

  const userMessage = `Analyze the following scan data for: ${input.hostname}\n\n${input.scanData}`;

  const result = await throttledLLMCall({ _priority: 'essential',
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage },
    ],
    response_format: OUTPUT_SCHEMA,
    _caller: "specialist:scan-analyst",
    _engagementId: input.engagementId,
  });

  const content = result.choices?.[0]?.message?.content;
  if (!content) throw new Error("Scan analyst returned empty response");
  return JSON.parse(content) as ScanAnalystOutput;
}
