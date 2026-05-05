/**
 * AC3 LLM Specialist — Cyber C2 Operation Builder
 *
 * Translates attack paths into Cyber C2 adversary profiles and operations.
 * Used to generate automated adversary emulation campaigns.
 */

import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { assembleSystemPrompt, buildCustomerContext } from "./core-policy";
import { parseLLMJson } from "../../../shared/llm-json-parser";

const ROLE_PROMPT = `## Role: Cyber C2 Operation Builder

You are the AC3 Cyber C2 Operation Builder.

Translate attack paths and findings into Cyber C2 adversary operations.

Ensure operations are:
• Aligned to MITRE ATT&CK techniques with correct IDs
• Realistic and achievable with available Cyber C2 abilities
• Minimally intrusive when possible (prefer detection over destruction)
• Sequenced logically (recon → access → escalation → objective)

Cyber C2 concepts:
• Adversary: A named threat profile with a list of abilities
• Ability: A single ATT&CK technique implementation (has executor, command, cleanup)
• Operation: An adversary profile executed against a group of agents
• Agent: A deployed beacon on a target host
• Fact: A key-value pair discovered during operation (e.g., host.user.name)

Available executors: psh (PowerShell), sh (bash), cmd (Windows cmd)`;

const OUTPUT_SCHEMA = {
  type: "json_schema" as const,
  json_schema: {
    name: "caldera_operation",
    strict: true,
    schema: {
      type: "object",
      properties: {
        operation_name: { type: "string" },
        description: { type: "string" },
        adversary_profile: {
          type: "object",
          properties: {
            name: { type: "string" },
            description: { type: "string" },
            objective: { type: "string" },
          },
          required: ["name", "description", "objective"],
          additionalProperties: false,
        },
        abilities: {
          type: "array",
          items: {
            type: "object",
            properties: {
              name: { type: "string" },
              tactic: { type: "string" },
              technique_id: { type: "string" },
              technique_name: { type: "string" },
              executor: { type: "string", description: "psh | sh | cmd" },
              command: { type: "string", description: "The command to execute" },
              cleanup: { type: "string", description: "Cleanup command to reverse the action" },
              description: { type: "string" },
              facts_collected: { type: "array", items: { type: "string" }, description: "Facts this ability discovers" },
            },
            required: ["name", "tactic", "technique_id", "technique_name", "executor", "command", "cleanup", "description", "facts_collected"],
            additionalProperties: false,
          },
        },
        execution_sequence: {
          type: "array",
          items: { type: "string" },
          description: "Ordered list of ability names to execute",
        },
        required_agents: {
          type: "array",
          items: {
            type: "object",
            properties: {
              platform: { type: "string", description: "linux | windows | darwin" },
              privilege: { type: "string", description: "user | elevated | root" },
              location: { type: "string", description: "Where the agent should be deployed" },
            },
            required: ["platform", "privilege", "location"],
            additionalProperties: false,
          },
        },
        expected_telemetry: {
          type: "array",
          items: { type: "string" },
          description: "What detection telemetry this operation should generate",
        },
        risk_assessment: { type: "string", description: "Impact risk of running this operation" },
        confidence: { type: "string", description: "High | Medium | Low" },
      },
      required: ["operation_name", "description", "adversary_profile", "abilities", "execution_sequence", "required_agents", "expected_telemetry", "risk_assessment", "confidence"],
      additionalProperties: false,
    },
  },
};

export interface CalderaBuilderInput {
  attackPath: string;
  findings: string;
  targetPlatform?: string;
  engagement?: {
    engagementType: string;
    clientName?: string;
    industry?: string;
    scope?: string;
    targetCount: number;
  };
  engagementId?: number;
}

export interface CalderaBuilderOutput {
  operation_name: string;
  description: string;
  adversary_profile: { name: string; description: string; objective: string };
  abilities: Array<{
    name: string;
    tactic: string;
    technique_id: string;
    technique_name: string;
    executor: string;
    command: string;
    cleanup: string;
    description: string;
    facts_collected: string[];
  }>;
  execution_sequence: string[];
  required_agents: Array<{ platform: string; privilege: string; location: string }>;
  expected_telemetry: string[];
  risk_assessment: string;
  confidence: string;
}

export async function buildCalderaOp(input: CalderaBuilderInput): Promise<CalderaBuilderOutput> {
  const systemPrompt = assembleSystemPrompt({
    rolePrompt: ROLE_PROMPT,
    customerContext: input.engagement ? buildCustomerContext(input.engagement) : undefined,
  });

  const userMessage = [
    `Build a Cyber C2 adversary operation based on the following attack path and findings:`,
    ``,
    input.targetPlatform ? `Target platform: ${input.targetPlatform}` : null,
    ``,
    `## Attack Path`,
    input.attackPath,
    ``,
    `## Findings`,
    input.findings,
  ].filter(Boolean).join('\n');

  const result = await throttledLLMCall({ _priority: 'essential',
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage },
    ],
    response_format: OUTPUT_SCHEMA,
    _caller: "specialist:caldera-builder",
    _engagementId: input.engagementId,
  });

  const content = result.choices?.[0]?.message?.content;
  if (!content) throw new Error("Cyber C2 builder returned empty response");
  return parseLLMJson<CalderaBuilderOutput>(content, { fallback: {} as CalderaBuilderOutput }).data;
}
