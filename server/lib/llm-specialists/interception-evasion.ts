/**
 * AC3 LLM Specialist — Interception & Evasion Analyst
 *
 * Reasons about detected security products, recommends evasion strategies,
 * and generates adaptive C2/payload/persistence recommendations based on
 * the interception fingerprinting engine's output.
 *
 * Used by:
 *   - Scan pipeline: post-DI-scan defense profiling
 *   - C2 pipeline: adaptive channel selection
 *   - Exploit pipeline: payload customization
 *   - Post-exploit pipeline: persistence & lateral movement adaptation
 */
import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { assembleSystemPrompt, buildAssetContext } from "./core-policy";
import { parseLLMJson } from "../../../shared/llm-json-parser";

// ═══════════════════════════════════════════════════════════════════
// ROLE PROMPT — Interception & Evasion Specialist
// ═══════════════════════════════════════════════════════════════════

const ROLE_PROMPT = `## Role: Interception & Evasion Analyst
You are the AC3 Interception & Evasion Analysis Module.
You reason like a senior red team operator who specializes in defense evasion,
EDR bypass, and OPSEC-aware operations.

Your job is to:
• Analyze detected security products and their capabilities
• Recommend specific evasion techniques for each detected product
• Assess operational risk of different attack approaches
• Recommend C2 channel configurations that avoid detection
• Suggest payload formats and delivery methods that bypass defenses
• Plan persistence mechanisms that survive in monitored environments
• Map evasion techniques to MITRE ATT&CK Defense Evasion (TA0005)

Key knowledge areas:
• EDR internals: userland hooks, kernel callbacks, ETW providers, minifilters
• AV evasion: AMSI bypass, signature avoidance, heuristic evasion
• Network monitoring: SSL inspection bypass, IDS/IPS evasion, traffic mimicry
• Host monitoring: Sysmon evasion, event log manipulation, FIM bypass
• Memory forensics: sleep obfuscation, memory encryption, reflective loading
• Process injection: syscall-based injection, callback-based execution
• Credential access: LSASS alternatives, DCSync, Kerberos attacks

Product-specific knowledge:
• CrowdStrike Falcon: kernel-level monitoring, cloud-based ML, process tree analysis
• Microsoft Defender for Endpoint: AMSI, ETW, cloud-delivered protection, ASR rules
• SentinelOne: behavioral AI, rollback capability, kernel-level monitoring
• Carbon Black: process event monitoring, binary reputation, threat hunting
• Cortex XDR: behavioral analytics, exploit prevention, host firewall
• Elastic Security: Elastic Agent, endpoint behavioral rules, memory protection
• Symantec: SONAR behavioral protection, Insight reputation
• Trend Micro: behavior monitoring, virtual patching, web reputation
• Sophos: CryptoGuard, deep learning, exploit prevention
• Cybereason: MalOp detection, behavioral correlation
• Cylance: AI-based prevention, memory protection, script control

Evidence classification:
[CONFIRMED] — product positively identified via process/service/driver/header
[PROBABLE] — strong indicators suggest product presence
[POSSIBLE] — weak signals that may indicate product presence
[INFERRED] — derived from behavioral patterns or configuration artifacts`;

// ═══════════════════════════════════════════════════════════════════
// Output Schemas
// ═══════════════════════════════════════════════════════════════════

const EVASION_STRATEGY_SCHEMA = {
  type: "json_schema" as const,
  json_schema: {
    name: "evasion_strategy",
    strict: true,
    schema: {
      type: "object",
      properties: {
        overallRisk: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Overall risk level of the defensive posture",
        },
        recommendedPosture: {
          type: "string",
          enum: ["ghost", "stealth", "balanced", "aggressive"],
          description: "Recommended operational posture",
        },
        summary: {
          type: "string",
          description: "Executive summary of the defense landscape and recommended approach",
        },
        productAnalysis: {
          type: "array",
          items: {
            type: "object",
            properties: {
              product: { type: "string" },
              vendor: { type: "string" },
              capabilities: { type: "string", description: "Key detection capabilities" },
              weaknesses: { type: "string", description: "Known bypass opportunities" },
              evasionTechniques: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    technique: { type: "string" },
                    mitreId: { type: "string" },
                    description: { type: "string" },
                    risk: { type: "string", enum: ["low", "medium", "high"] },
                    reliability: { type: "string", enum: ["proven", "likely", "experimental"] },
                  },
                  required: ["technique", "mitreId", "description", "risk", "reliability"],
                  additionalProperties: false,
                },
              },
            },
            required: ["product", "vendor", "capabilities", "weaknesses", "evasionTechniques"],
            additionalProperties: false,
          },
        },
        c2Recommendations: {
          type: "array",
          items: {
            type: "object",
            properties: {
              protocol: { type: "string" },
              rationale: { type: "string" },
              configuration: { type: "string" },
              risk: { type: "string", enum: ["low", "medium", "high"] },
            },
            required: ["protocol", "rationale", "configuration", "risk"],
            additionalProperties: false,
          },
        },
        payloadRecommendations: {
          type: "array",
          items: {
            type: "object",
            properties: {
              type: { type: "string" },
              format: { type: "string" },
              rationale: { type: "string" },
              evasionSteps: { type: "string" },
              risk: { type: "string", enum: ["low", "medium", "high"] },
            },
            required: ["type", "format", "rationale", "evasionSteps", "risk"],
            additionalProperties: false,
          },
        },
        persistenceRecommendations: {
          type: "array",
          items: {
            type: "object",
            properties: {
              method: { type: "string" },
              rationale: { type: "string" },
              survivesReboot: { type: "boolean" },
              detectionRisk: { type: "string", enum: ["low", "medium", "high"] },
            },
            required: ["method", "rationale", "survivesReboot", "detectionRisk"],
            additionalProperties: false,
          },
        },
        lateralMovementRecommendations: {
          type: "array",
          items: {
            type: "object",
            properties: {
              technique: { type: "string" },
              mitreId: { type: "string" },
              rationale: { type: "string" },
              risk: { type: "string", enum: ["low", "medium", "high"] },
            },
            required: ["technique", "mitreId", "rationale", "risk"],
            additionalProperties: false,
          },
        },
        beaconConfig: {
          type: "object",
          properties: {
            minIntervalMs: { type: "number" },
            maxIntervalMs: { type: "number" },
            jitterPercent: { type: "number" },
            rationale: { type: "string" },
          },
          required: ["minIntervalMs", "maxIntervalMs", "jitterPercent", "rationale"],
          additionalProperties: false,
        },
        opsecChecklist: {
          type: "array",
          items: {
            type: "object",
            properties: {
              item: { type: "string" },
              priority: { type: "string", enum: ["critical", "high", "medium", "low"] },
              phase: { type: "string", description: "Which phase of the operation this applies to" },
            },
            required: ["item", "priority", "phase"],
            additionalProperties: false,
          },
        },
      },
      required: [
        "overallRisk", "recommendedPosture", "summary", "productAnalysis",
        "c2Recommendations", "payloadRecommendations", "persistenceRecommendations",
        "lateralMovementRecommendations", "beaconConfig", "opsecChecklist",
      ],
      additionalProperties: false,
    },
  },
};

// ═══════════════════════════════════════════════════════════════════
// Input/Output Types
// ═══════════════════════════════════════════════════════════════════

export interface InterceptionEvasionInput {
  /** Detected security products from fingerprinting engine */
  findings: Array<{
    vendor: string;
    product: string;
    domain: string;
    category: string;
    confidence: number;
    evidence: string[];
    mitre: Array<{ techniqueId: string; techniqueName: string }>;
    operationalImpact: string;
  }>;
  /** Target environment info */
  target: string;
  /** Operation phase */
  phase: "pre_deployment" | "initial_access" | "post_exploitation" | "lateral_movement" | "persistence";
  /** Asset context if available */
  assets?: Array<{
    hostname: string;
    type: string;
    technologies?: string[];
    riskSignals?: Array<{ severity: string; rationale: string }>;
  }>;
  /** Engagement context */
  engagementType?: string;
  sector?: string;
}

export interface InterceptionEvasionOutput {
  overallRisk: "critical" | "high" | "medium" | "low";
  recommendedPosture: "ghost" | "stealth" | "balanced" | "aggressive";
  summary: string;
  productAnalysis: Array<{
    product: string;
    vendor: string;
    capabilities: string;
    weaknesses: string;
    evasionTechniques: Array<{
      technique: string;
      mitreId: string;
      description: string;
      risk: "low" | "medium" | "high";
      reliability: "proven" | "likely" | "experimental";
    }>;
  }>;
  c2Recommendations: Array<{
    protocol: string;
    rationale: string;
    configuration: string;
    risk: "low" | "medium" | "high";
  }>;
  payloadRecommendations: Array<{
    type: string;
    format: string;
    rationale: string;
    evasionSteps: string;
    risk: "low" | "medium" | "high";
  }>;
  persistenceRecommendations: Array<{
    method: string;
    rationale: string;
    survivesReboot: boolean;
    detectionRisk: "low" | "medium" | "high";
  }>;
  lateralMovementRecommendations: Array<{
    technique: string;
    mitreId: string;
    rationale: string;
    risk: "low" | "medium" | "high";
  }>;
  beaconConfig: {
    minIntervalMs: number;
    maxIntervalMs: number;
    jitterPercent: number;
    rationale: string;
  };
  opsecChecklist: Array<{
    item: string;
    priority: "critical" | "high" | "medium" | "low";
    phase: string;
  }>;
}

// ═══════════════════════════════════════════════════════════════════
// Main Function
// ═══════════════════════════════════════════════════════════════════

/**
 * Analyze detected security products and generate comprehensive evasion strategy.
 */
export async function analyzeInterceptions(input: InterceptionEvasionInput): Promise<InterceptionEvasionOutput> {
  const findingsBlock = input.findings.map(f => {
    const evidenceStr = f.evidence.slice(0, 5).join(", ");
    const mitreStr = f.mitre.map(m => `${m.techniqueId} (${m.techniqueName})`).join(", ");
    return `• ${f.vendor} ${f.product} [${f.domain}/${f.category}] confidence=${(f.confidence * 100).toFixed(0)}%
  Evidence: ${evidenceStr}
  MITRE: ${mitreStr}
  Impact: ${f.operationalImpact}`;
  }).join("\n");

  const assetContext = input.assets
    ? buildAssetContext(input.assets.map(a => ({
        hostname: a.hostname,
        type: a.type,
        technologies: a.technologies,
        riskSignals: a.riskSignals,
      })))
    : "";

  const additionalContext = `## Detected Security Products
${findingsBlock}

## Operation Phase
${input.phase.replace(/_/g, " ")}

## Target
${input.target}
${input.sector ? `Sector: ${input.sector}` : ""}
${input.engagementType ? `Engagement: ${input.engagementType}` : ""}

## Task
Analyze the detected security products above and produce a comprehensive evasion strategy.
For each product, identify its specific detection capabilities and known weaknesses.
Recommend specific, actionable evasion techniques mapped to MITRE ATT&CK.
Tailor C2, payload, persistence, and lateral movement recommendations to the detected defense posture.
Consider the operation phase when prioritizing recommendations.`;

  const systemPrompt = assembleSystemPrompt({
    rolePrompt: ROLE_PROMPT,
    assetContext: assetContext || undefined,
    additionalContext,
  });

  const response = await throttledLLMCall("interception-evasion", async () =>
    invokeLLM({
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: `Analyze the detected security products and generate a comprehensive evasion strategy for the ${input.phase.replace(/_/g, " ")} phase against ${input.target}.` },
      ],
      response_format: EVASION_STRATEGY_SCHEMA,
    })
  );

  const content = response.choices?.[0]?.message?.content;
  if (!content) {
    throw new Error("Empty response from interception-evasion specialist");
  }

  return parseLLMJson<InterceptionEvasionOutput>(content, { fallback: {} as InterceptionEvasionOutput }).data;
}

/**
 * Quick evasion check — lightweight call for real-time decisions.
 * Returns a single recommended action for a specific operation.
 */
export async function quickEvasionCheck(input: {
  operation: string;
  detectedProducts: string[];
  target: string;
}): Promise<{
  proceed: boolean;
  risk: "low" | "medium" | "high" | "critical";
  recommendation: string;
  preSteps: string[];
}> {
  const systemPrompt = assembleSystemPrompt({
    rolePrompt: ROLE_PROMPT,
    additionalContext: `## Quick Evasion Check
Operation: ${input.operation}
Target: ${input.target}
Detected Products: ${input.detectedProducts.join(", ")}

Provide a quick go/no-go recommendation with specific pre-execution steps.`,
  });

  const schema = {
    type: "json_schema" as const,
    json_schema: {
      name: "quick_evasion_check",
      strict: true,
      schema: {
        type: "object",
        properties: {
          proceed: { type: "boolean", description: "Whether to proceed with the operation" },
          risk: { type: "string", enum: ["low", "medium", "high", "critical"] },
          recommendation: { type: "string", description: "Brief recommendation" },
          preSteps: {
            type: "array",
            items: { type: "string" },
            description: "Steps to take before executing the operation",
          },
        },
        required: ["proceed", "risk", "recommendation", "preSteps"],
        additionalProperties: false,
      },
    },
  };

  const response = await throttledLLMCall("interception-evasion-quick", async () =>
    invokeLLM({
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: `Quick evasion check for: ${input.operation}` },
      ],
      response_format: schema,
    })
  );

  const content = response.choices?.[0]?.message?.content;
  if (!content) {
    return { proceed: true, risk: "medium", recommendation: "Unable to assess — proceed with caution", preSteps: [] };
  }

  return JSON.parse(content);
}
