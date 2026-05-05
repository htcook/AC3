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
} from "./chunk-SG5FPEKQ.js";
import "./chunk-BRIFEITD.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/llm-specialists/caldera-builder.ts
async function buildCalderaOp(input) {
  const systemPrompt = assembleSystemPrompt({
    rolePrompt: ROLE_PROMPT,
    customerContext: input.engagement ? buildCustomerContext(input.engagement) : void 0
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
    input.findings
  ].filter(Boolean).join("\n");
  const result = await throttledLLMCall({
    _priority: "essential",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage }
    ],
    response_format: OUTPUT_SCHEMA,
    _caller: "specialist:caldera-builder",
    _engagementId: input.engagementId
  });
  const content = result.choices?.[0]?.message?.content;
  if (!content) throw new Error("Cyber C2 builder returned empty response");
  return parseLLMJson(content, { fallback: {} }).data;
}
var ROLE_PROMPT, OUTPUT_SCHEMA;
var init_caldera_builder = __esm({
  "server/lib/llm-specialists/caldera-builder.ts"() {
    init_llm_throttle();
    init_core_policy();
    init_llm_json_parser();
    ROLE_PROMPT = `## Role: Cyber C2 Operation Builder

You are the AC3 Cyber C2 Operation Builder.

Translate attack paths and findings into Cyber C2 adversary operations.

Ensure operations are:
\u2022 Aligned to MITRE ATT&CK techniques with correct IDs
\u2022 Realistic and achievable with available Cyber C2 abilities
\u2022 Minimally intrusive when possible (prefer detection over destruction)
\u2022 Sequenced logically (recon \u2192 access \u2192 escalation \u2192 objective)

Cyber C2 concepts:
\u2022 Adversary: A named threat profile with a list of abilities
\u2022 Ability: A single ATT&CK technique implementation (has executor, command, cleanup)
\u2022 Operation: An adversary profile executed against a group of agents
\u2022 Agent: A deployed beacon on a target host
\u2022 Fact: A key-value pair discovered during operation (e.g., host.user.name)

Available executors: psh (PowerShell), sh (bash), cmd (Windows cmd)`;
    OUTPUT_SCHEMA = {
      type: "json_schema",
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
                objective: { type: "string" }
              },
              required: ["name", "description", "objective"],
              additionalProperties: false
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
                  facts_collected: { type: "array", items: { type: "string" }, description: "Facts this ability discovers" }
                },
                required: ["name", "tactic", "technique_id", "technique_name", "executor", "command", "cleanup", "description", "facts_collected"],
                additionalProperties: false
              }
            },
            execution_sequence: {
              type: "array",
              items: { type: "string" },
              description: "Ordered list of ability names to execute"
            },
            required_agents: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  platform: { type: "string", description: "linux | windows | darwin" },
                  privilege: { type: "string", description: "user | elevated | root" },
                  location: { type: "string", description: "Where the agent should be deployed" }
                },
                required: ["platform", "privilege", "location"],
                additionalProperties: false
              }
            },
            expected_telemetry: {
              type: "array",
              items: { type: "string" },
              description: "What detection telemetry this operation should generate"
            },
            risk_assessment: { type: "string", description: "Impact risk of running this operation" },
            confidence: { type: "string", description: "High | Medium | Low" }
          },
          required: ["operation_name", "description", "adversary_profile", "abilities", "execution_sequence", "required_agents", "expected_telemetry", "risk_assessment", "confidence"],
          additionalProperties: false
        }
      }
    };
  }
});
init_caldera_builder();
export {
  buildCalderaOp
};
