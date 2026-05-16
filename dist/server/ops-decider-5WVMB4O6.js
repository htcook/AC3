import {
  assembleSystemPrompt,
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

// server/lib/llm-specialists/ops-decider.ts
async function decideNextOp(input) {
  const systemPrompt = assembleSystemPrompt({
    rolePrompt: ROLE_PROMPT,
    customerContext: input.engagement ? buildCustomerContext(input.engagement) : void 0
  });
  const userMessage = [
    `Current phase: ${input.currentPhase}`,
    `Available tools: ${input.availableTools.join(", ")}`,
    ``,
    `## Recent Activity`,
    input.recentActivity,
    ``,
    `## Asset Summary`,
    input.assetSummary,
    ``,
    `What should be the next action?`
  ].join("\n");
  const result = await throttledLLMCall({
    _priority: "essential",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage }
    ],
    response_format: OUTPUT_SCHEMA,
    _caller: "specialist:ops-decider",
    _engagementId: input.engagementId
  });
  const content = result.choices?.[0]?.message?.content;
  if (!content) throw new Error("Ops decider returned empty response");
  return parseLLMJson(content, { fallback: {} }).data;
}
var ROLE_PROMPT, OUTPUT_SCHEMA;
var init_ops_decider = __esm({
  "server/lib/llm-specialists/ops-decider.ts"() {
    init_llm_throttle();
    init_core_policy();
    init_llm_json_parser();
    ROLE_PROMPT = `## Role: Operations Decision Engine

You are the AC3 Operations Decision Engine.

Your task is to determine the optimal next action in an ongoing penetration test engagement.

You receive:
\u2022 Current pipeline phase and recent activity log
\u2022 Asset summary and scan results so far
\u2022 Available tools and their current status

Decision framework:
1. What has been completed so far?
2. What gaps remain in coverage?
3. What is the highest-value next action?
4. Are there any blockers or dependencies?

Prefer actions that:
\u2022 Fill coverage gaps (untested attack surfaces)
\u2022 Follow up on promising findings
\u2022 Maximize information gain per action
\u2022 Respect scope boundaries`;
    OUTPUT_SCHEMA = {
      type: "json_schema",
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
              description: "What hasn't been tested yet"
            },
            recommended_action: {
              type: "object",
              properties: {
                action: { type: "string", description: "The recommended next action" },
                target: { type: "string", description: "Which asset or scope to target" },
                tool: { type: "string", description: "Which tool to use" },
                rationale: { type: "string" },
                priority: { type: "string", description: "Critical | High | Medium | Low" }
              },
              required: ["action", "target", "tool", "rationale", "priority"],
              additionalProperties: false
            },
            alternative_actions: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  action: { type: "string" },
                  rationale: { type: "string" }
                },
                required: ["action", "rationale"],
                additionalProperties: false
              }
            },
            blockers: {
              type: "array",
              items: { type: "string" },
              description: "Any issues preventing progress"
            },
            should_escalate: { type: "boolean", description: "Whether findings warrant escalation to operator" },
            confidence: { type: "string", description: "High | Medium | Low" }
          },
          required: ["current_assessment", "coverage_gaps", "recommended_action", "alternative_actions", "blockers", "should_escalate", "confidence"],
          additionalProperties: false
        }
      }
    };
  }
});
init_ops_decider();
export {
  decideNextOp
};
