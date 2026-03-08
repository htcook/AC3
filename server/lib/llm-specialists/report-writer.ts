/**
 * Ace C3 LLM Specialist — Pentest Report Writer
 *
 * Generates professional penetration testing report findings.
 * Used when generating client-ready reporting.
 */

import { invokeLLM } from "../../_core/llm";
import { assembleSystemPrompt, buildCustomerContext } from "./core-policy";

const ROLE_PROMPT = `## Role: Penetration Test Report Writer

You are the Ace C3 Penetration Test Report Writer.

Write findings in professional penetration testing report format suitable for client delivery.

Focus on:
• Clarity — non-technical stakeholders should understand the risk
• Reproducibility — another tester should be able to verify the finding
• Business risk — frame impact in business terms, not just technical severity
• Remediation guidance — provide specific, actionable fixes

Writing style:
• Use formal, professional language
• Avoid jargon without explanation
• Be precise about what was observed vs. what is inferred
• Include all necessary technical detail for reproduction`;

const OUTPUT_SCHEMA = {
  type: "json_schema" as const,
  json_schema: {
    name: "pentest_finding",
    strict: true,
    schema: {
      type: "object",
      properties: {
        title: { type: "string" },
        severity: { type: "string", description: "Critical | High | Medium | Low | Informational" },
        cvss_score: { type: "number", description: "CVSS 3.1 base score 0.0-10.0" },
        affected_asset: { type: "string" },
        description: { type: "string", description: "Clear description of the vulnerability" },
        evidence: {
          type: "array",
          items: {
            type: "object",
            properties: {
              type: { type: "string", description: "screenshot | http_request | http_response | command_output | configuration" },
              description: { type: "string" },
              data: { type: "string" },
            },
            required: ["type", "description", "data"],
            additionalProperties: false,
          },
        },
        impact: { type: "string", description: "Business impact description" },
        reproduction_steps: {
          type: "array",
          items: { type: "string" },
          description: "Step-by-step reproduction instructions",
        },
        remediation: {
          type: "object",
          properties: {
            short_term: { type: "string", description: "Immediate mitigation" },
            long_term: { type: "string", description: "Permanent fix" },
            effort: { type: "string", description: "Low | Medium | High" },
          },
          required: ["short_term", "long_term", "effort"],
          additionalProperties: false,
        },
        references: {
          type: "array",
          items: { type: "string" },
          description: "CVE IDs, CWE IDs, OWASP references, vendor advisories",
        },
        mitre_mapping: {
          type: "array",
          items: {
            type: "object",
            properties: {
              technique_id: { type: "string" },
              technique_name: { type: "string" },
              tactic: { type: "string" },
            },
            required: ["technique_id", "technique_name", "tactic"],
            additionalProperties: false,
          },
        },
      },
      required: ["title", "severity", "cvss_score", "affected_asset", "description", "evidence", "impact", "reproduction_steps", "remediation", "references", "mitre_mapping"],
      additionalProperties: false,
    },
  },
};

export interface ReportWriterInput {
  finding: {
    title: string;
    rawEvidence: string;
    hostname: string;
    severity?: string;
    cve?: string;
    scanSource: string;
  };
  engagement?: {
    engagementType: string;
    clientName?: string;
    industry?: string;
    scope?: string;
    targetCount: number;
  };
  engagementId?: number;
}

export interface ReportWriterOutput {
  title: string;
  severity: string;
  cvss_score: number;
  affected_asset: string;
  description: string;
  evidence: Array<{ type: string; description: string; data: string }>;
  impact: string;
  reproduction_steps: string[];
  remediation: { short_term: string; long_term: string; effort: string };
  references: string[];
  mitre_mapping: Array<{ technique_id: string; technique_name: string; tactic: string }>;
}

export async function writeReportFinding(input: ReportWriterInput): Promise<ReportWriterOutput> {
  const systemPrompt = assembleSystemPrompt({
    rolePrompt: ROLE_PROMPT,
    customerContext: input.engagement ? buildCustomerContext(input.engagement) : undefined,
  });

  const f = input.finding;
  const userMessage = [
    `Write a professional pentest report finding for:`,
    ``,
    `Title: ${f.title}`,
    `Host: ${f.hostname}`,
    f.severity ? `Scanner severity: ${f.severity}` : null,
    f.cve ? `CVE: ${f.cve}` : null,
    `Source: ${f.scanSource}`,
    ``,
    `Raw evidence:`,
    f.rawEvidence,
  ].filter(Boolean).join('\n');

  const result = await invokeLLM({
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage },
    ],
    response_format: OUTPUT_SCHEMA,
    _caller: "specialist:report-writer",
    _engagementId: input.engagementId,
  });

  const content = result.choices?.[0]?.message?.content;
  if (!content) throw new Error("Report writer returned empty response");
  return JSON.parse(content) as ReportWriterOutput;
}
