/**
 * Ace C3 LLM Specialist — Operations Decider
 *
 * Determines the next best action in the engagement pipeline.
 * Replaces the monolithic llmDecide function with focused decision-making.
 */

import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { assembleSystemPrompt, buildCustomerContext } from "./core-policy";

const ROLE_PROMPT = `## Role: Operations Decision Engine

You are the Ace C3 Operations Decision Engine.

Your task is to determine the optimal next action in an ongoing penetration test engagement.

You receive:
• Current pipeline phase and recent activity log
• Asset summary and scan results so far
• Available tools and their current status

Decision framework:
1. What has been completed so far?
2. What gaps remain in coverage?
3. What is the highest-value next action?
4. Are there any blockers or dependencies?

Prefer actions that:
• Fill coverage gaps (untested attack surfaces)
• Follow up on promising findings
• Maximize information gain per action
• Respect scope boundaries`;

const OUTPUT_SCHEMA = {
  type: "json_schema" as const,
  json_schema: {
    name: "ops_decision",
    strict: true,
    schema: {
      type: "object",
      properties: {
        current_assessment: { type: "string", description: "Brief assessment of current engagement state" },
        coverage_gaps: {
          type: "array",
          items: { type: "string" },
          description: "What hasn't been tested yet",
        },
        recommended_action: {
          type: "object",
          properties: {
            action: { type: "string", description: "The recommended next action" },
            target: { type: "string", description: "Which asset or scope to target" },
            tool: { type: "string", description: "Which tool to use" },
            rationale: { type: "string" },
            priority: { type: "string", description: "Critical | High | Medium | Low" },
          },
          required: ["action", "target", "tool", "rationale", "priority"],
          additionalProperties: false,
        },
        alternative_actions: {
          type: "array",
          items: {
            type: "object",
            properties: {
              action: { type: "string" },
              rationale: { type: "string" },
            },
            required: ["action", "rationale"],
            additionalProperties: false,
          },
        },
        blockers: {
          type: "array",
          items: { type: "string" },
          description: "Any issues preventing progress",
        },
        should_escalate: { type: "boolean", description: "Whether findings warrant escalation to operator" },
        confidence: { type: "string", description: "High | Medium | Low" },
      },
      required: ["current_assessment", "coverage_gaps", "recommended_action", "alternative_actions", "blockers", "should_escalate", "confidence"],
      additionalProperties: false,
    },
  },
};

export interface OpsDeciderInput {
  currentPhase: string;
  recentActivity: string;
  assetSummary: string;
  availableTools: string[];
  engagement?: {
    engagementType: string;
    clientName?: string;
    industry?: string;
    scope?: string;
    targetCount: number;
  };
  engagementId?: number;
}

export interface OpsDeciderOutput {
  current_assessment: string;
  coverage_gaps: string[];
  recommended_action: {
    action: string;
    target: string;
    tool: string;
    rationale: string;
    priority: string;
  };
  alternative_actions: Array<{ action: string; rationale: string }>;
  blockers: string[];
  should_escalate: boolean;
  confidence: string;
}

export async function decideNextOp(input: OpsDeciderInput): Promise<OpsDeciderOutput> {
  const systemPrompt = assembleSystemPrompt({
    rolePrompt: ROLE_PROMPT,
    customerContext: input.engagement ? buildCustomerContext(input.engagement) : undefined,
  });

  const userMessage = [
    `Current phase: ${input.currentPhase}`,
    `Available tools: ${input.availableTools.join(', ')}`,
    ``,
    `## Recent Activity`,
    input.recentActivity,
    ``,
    `## Asset Summary`,
    input.assetSummary,
    ``,
    `What should be the next action?`,
  ].join('\n');

  const result = await throttledLLMCall({ _priority: 'essential',
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage },
    ],
    response_format: OUTPUT_SCHEMA,
    _caller: "specialist:ops-decider",
    _engagementId: input.engagementId,
  });

  const content = result.choices?.[0]?.message?.content;
  if (!content) throw new Error("Ops decider returned empty response");
  return JSON.parse(content) as OpsDeciderOutput;
}
