/**
 * Auto-Discovery Engine — LLM-Powered API Classification & Assessment
 * ═══════════════════════════════════════════════════════════════════════
 * 
 * When a customer adds a new API source, this engine:
 *   1. Probes the API (health check, sample request, OpenAPI spec detection)
 *   2. Sends the API metadata to the LLM for classification
 *   3. Returns a structured proposal for customer review
 *   4. Learns from customer corrections to improve future classifications
 * 
 * The engine NEVER auto-wires into live pipelines — it always produces
 * a proposal that requires explicit customer approval.
 */

import { invokeLLM } from "../../_core/llm";
import { BUILTIN_CATALOG, CATALOG_BY_ID } from "./builtin-catalog";
import type {
  IntegrationCategory,
  PipelineStage,
  AuthMethod,
  AutoDiscoveryResult,
  IntegrationValueAssessment,
  ClassificationFeedback,
} from "./types";
import { CATEGORY_METADATA, PIPELINE_STAGE_METADATA } from "./types";

// ═══════════════════════════════════════════════════════════════════════
// §1 — API PROBING
// ═══════════════════════════════════════════════════════════════════════

export interface ApiProbeInput {
  /** The base URL of the API */
  baseUrl: string;
  /** Optional API key to use for probing */
  apiKey?: string;
  /** Optional API key header name */
  apiKeyHeader?: string;
  /** Optional documentation URL */
  docsUrl?: string;
  /** Customer-provided description of what this API does */
  customerDescription?: string;
  /** Customer-provided name */
  customerName?: string;
}

export interface ApiProbeResult {
  /** Whether the API is reachable */
  reachable: boolean;
  /** HTTP status code from health check */
  statusCode?: number;
  /** Response content type */
  contentType?: string;
  /** Whether an OpenAPI/Swagger spec was detected */
  hasOpenApiSpec: boolean;
  /** OpenAPI spec URL if found */
  openApiSpecUrl?: string;
  /** Partial OpenAPI spec (first 4000 chars) */
  openApiSpecPreview?: string;
  /** Sample response body (first 2000 chars) */
  sampleResponse?: string;
  /** Response headers of interest */
  interestingHeaders: Record<string, string>;
  /** Detected rate limit headers */
  rateLimitHeaders?: { limit?: string; remaining?: string; reset?: string };
  /** Detected auth method from response */
  detectedAuthMethod?: AuthMethod;
  /** Error message if probe failed */
  error?: string;
}

/**
 * Probe an API to gather metadata for classification.
 * This is a non-destructive read-only probe — it only sends GET requests.
 */
export async function probeApi(input: ApiProbeInput): Promise<ApiProbeResult> {
  const result: ApiProbeResult = {
    reachable: false,
    hasOpenApiSpec: false,
    interestingHeaders: {},
  };

  const headers: Record<string, string> = {
    "Accept": "application/json, text/html, */*",
    "User-Agent": "AC3-Integration-Probe/1.0",
  };

  // Add API key if provided
  if (input.apiKey) {
    const headerName = input.apiKeyHeader || "X-API-Key";
    headers[headerName] = input.apiKey;
    // Also try Authorization: Bearer
    if (!input.apiKeyHeader) {
      headers["Authorization"] = `Bearer ${input.apiKey}`;
    }
  }

  const timeout = 10_000;

  try {
    // Step 1: Health check — try the base URL
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const resp = await fetch(input.baseUrl, {
        headers,
        signal: controller.signal,
        redirect: "follow",
      });
      clearTimeout(timer);

      result.reachable = true;
      result.statusCode = resp.status;
      result.contentType = resp.headers.get("content-type") ?? undefined;

      // Capture interesting headers
      const interestingHeaderNames = [
        "server", "x-powered-by", "x-api-version", "x-ratelimit-limit",
        "x-ratelimit-remaining", "x-ratelimit-reset", "ratelimit-limit",
        "ratelimit-remaining", "ratelimit-reset", "x-request-id",
        "access-control-allow-origin", "www-authenticate",
      ];
      for (const name of interestingHeaderNames) {
        const val = resp.headers.get(name);
        if (val) result.interestingHeaders[name] = val;
      }

      // Detect rate limit headers
      const rlLimit = resp.headers.get("x-ratelimit-limit") || resp.headers.get("ratelimit-limit");
      const rlRemaining = resp.headers.get("x-ratelimit-remaining") || resp.headers.get("ratelimit-remaining");
      const rlReset = resp.headers.get("x-ratelimit-reset") || resp.headers.get("ratelimit-reset");
      if (rlLimit || rlRemaining) {
        result.rateLimitHeaders = { limit: rlLimit ?? undefined, remaining: rlRemaining ?? undefined, reset: rlReset ?? undefined };
      }

      // Detect auth method from response
      if (resp.status === 401 || resp.status === 403) {
        const wwwAuth = resp.headers.get("www-authenticate");
        if (wwwAuth?.toLowerCase().includes("bearer")) result.detectedAuthMethod = "bearer_token";
        else if (wwwAuth?.toLowerCase().includes("basic")) result.detectedAuthMethod = "basic_auth";
        else result.detectedAuthMethod = "api_key";
      }

      // Capture sample response (first 2000 chars)
      try {
        const body = await resp.text();
        result.sampleResponse = body.slice(0, 2000);
      } catch { /* ignore body read errors */ }
    } catch (err: any) {
      clearTimeout(timer);
      if (err.name === "AbortError") {
        result.error = "Timeout: API did not respond within 10 seconds";
      } else {
        result.error = `Connection error: ${err.message}`;
      }
    }

    // Step 2: Try to find OpenAPI spec
    const specPaths = [
      "/openapi.json", "/swagger.json", "/api-docs", "/v1/openapi.json",
      "/v2/swagger.json", "/docs", "/api/docs", "/.well-known/openapi.json",
    ];

    for (const path of specPaths) {
      try {
        const specUrl = new URL(path, input.baseUrl).toString();
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 5000);
        const specResp = await fetch(specUrl, { headers: { Accept: "application/json" }, signal: ctrl.signal });
        clearTimeout(t);
        if (specResp.ok) {
          const specBody = await specResp.text();
          // Check if it looks like an OpenAPI/Swagger spec
          if (specBody.includes('"openapi"') || specBody.includes('"swagger"') || specBody.includes('"paths"')) {
            result.hasOpenApiSpec = true;
            result.openApiSpecUrl = specUrl;
            result.openApiSpecPreview = specBody.slice(0, 4000);
            break;
          }
        }
      } catch { /* ignore spec probe errors */ }
    }
  } catch (err: any) {
    result.error = `Probe failed: ${err.message}`;
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — LLM CLASSIFICATION
// ═══════════════════════════════════════════════════════════════════════

const CLASSIFICATION_SYSTEM_PROMPT = `You are the AC3 Integration Classification Engine. Your job is to analyze a new API that a customer wants to add to their cybersecurity platform and determine:

1. **Category** — What kind of tool/service is this?
   Categories: osint, exploit_db, threat_intel, scanner, pentest_tool, phishing, c2, siem_soar, cloud, credential, custom

2. **Pipeline Stages** — Which engagement pipeline stages should this feed into?
   Stages: recon, passive_discovery, enumeration, vuln_detection, social_engineering, exploitation, post_exploit, reporting, monitoring, enrichment

3. **Data Types** — What kind of data does this API provide?
   Examples: subdomains, ip_addresses, certificates, vulnerabilities, credentials, iocs, malware_samples, etc.

4. **Input Types** — What does this API accept as input?
   Examples: domain, ip, url, cidr, email, file_hash, etc.

5. **Output Types** — What AC3 asset types does this produce?
   Examples: subdomain, ip, certificate, url, credential, breach, infrastructure, domain

6. **Value Assessment** — How valuable is this compared to existing sources?

EXISTING INTEGRATIONS (for overlap analysis):
{existingIntegrations}

IMPORTANT RULES:
- Be specific about pipeline stages — don't just say "all stages"
- Consider whether this is passive-only or requires active probing
- Identify overlaps with existing integrations honestly
- If you're not confident, say so — the customer will review and correct
- Never classify something as "custom" if it fits a known category
- Consider the cybersecurity context: OSINT tools gather intel, scanners find vulns, exploit tools attack, etc.

Respond in JSON format matching the AutoDiscoveryResult schema.`;

/**
 * Use LLM to classify a new API based on probe results and customer input.
 * Returns a structured proposal for customer review.
 */
export async function classifyApi(
  input: ApiProbeInput,
  probeResult: ApiProbeResult,
): Promise<AutoDiscoveryResult> {
  // Build existing integrations summary for overlap analysis
  const existingSummary = BUILTIN_CATALOG
    .map(e => `- ${e.displayName} (${e.category}): ${e.description} [stages: ${e.pipelineStages.join(", ")}]`)
    .join("\n");

  // Build the classification prompt
  const userPrompt = `Classify this new API integration:

**Base URL:** ${input.baseUrl}
**Customer Name:** ${input.customerName || "Not provided"}
**Customer Description:** ${input.customerDescription || "Not provided"}
**Documentation URL:** ${input.docsUrl || "Not provided"}

**Probe Results:**
- Reachable: ${probeResult.reachable}
- Status Code: ${probeResult.statusCode ?? "N/A"}
- Content Type: ${probeResult.contentType ?? "N/A"}
- Has OpenAPI Spec: ${probeResult.hasOpenApiSpec}
- Detected Auth Method: ${probeResult.detectedAuthMethod ?? "unknown"}
- Rate Limit: ${probeResult.rateLimitHeaders ? JSON.stringify(probeResult.rateLimitHeaders) : "Not detected"}
- Response Headers: ${JSON.stringify(probeResult.interestingHeaders)}
${probeResult.openApiSpecPreview ? `\n**OpenAPI Spec Preview (first 4000 chars):**\n\`\`\`json\n${probeResult.openApiSpecPreview}\n\`\`\`` : ""}
${probeResult.sampleResponse ? `\n**Sample Response (first 2000 chars):**\n\`\`\`\n${probeResult.sampleResponse}\n\`\`\`` : ""}

Analyze this API and provide your classification as JSON.`;

  try {
    const response = await invokeLLM({
      messages: [
        {
          role: "system",
          content: CLASSIFICATION_SYSTEM_PROMPT.replace("{existingIntegrations}", existingSummary),
        },
        { role: "user", content: userPrompt },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "api_classification",
          strict: true,
          schema: {
            type: "object",
            properties: {
              category: { type: "string", description: "Integration category", enum: ["osint", "exploit_db", "threat_intel", "scanner", "pentest_tool", "phishing", "c2", "siem_soar", "cloud", "credential", "custom"] },
              confidence: { type: "number", description: "Classification confidence 0-100" },
              pipelineStages: { type: "array", items: { type: "string" }, description: "Pipeline stages this feeds into" },
              dataTypes: { type: "array", items: { type: "string" }, description: "Data types provided" },
              inputTypes: { type: "array", items: { type: "string" }, description: "Input types accepted" },
              outputTypes: { type: "array", items: { type: "string" }, description: "AC3 asset types produced" },
              description: { type: "string", description: "What this API does" },
              reasoning: { type: "string", description: "Why this classification was chosen" },
              suggestedName: { type: "string", description: "Suggested integration ID (snake_case)" },
              suggestedDisplayName: { type: "string", description: "Suggested display name" },
              supportsPassiveOnly: { type: "boolean", description: "Whether this is passive-only" },
              requiresActiveProbing: { type: "boolean", description: "Whether this requires active probing" },
              overlapAnalysis: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    existingId: { type: "string" },
                    existingName: { type: "string" },
                    overlapPercent: { type: "number" },
                  },
                  required: ["existingId", "existingName", "overlapPercent"],
                  additionalProperties: false,
                },
                description: "Overlap with existing integrations",
              },
              valueScore: { type: "number", description: "Overall value score 0-100" },
              uniqueDataScore: { type: "number", description: "Unique data score 0-100" },
              reliabilityScore: { type: "number", description: "Reliability score 0-100" },
              valueSummary: { type: "string", description: "Value assessment summary" },
              valueAdds: { type: "array", items: { type: "string" }, description: "Specific value-adds" },
              concerns: { type: "array", items: { type: "string" }, description: "Potential concerns" },
            },
            required: [
              "category", "confidence", "pipelineStages", "dataTypes", "inputTypes",
              "outputTypes", "description", "reasoning", "suggestedName", "suggestedDisplayName",
              "supportsPassiveOnly", "requiresActiveProbing", "overlapAnalysis",
              "valueScore", "uniqueDataScore", "reliabilityScore", "valueSummary",
              "valueAdds", "concerns",
            ],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");

    const parsed = JSON.parse(content);

    // Build the AutoDiscoveryResult
    const result: AutoDiscoveryResult = {
      category: parsed.category as IntegrationCategory,
      confidence: parsed.confidence,
      pipelineStages: parsed.pipelineStages as PipelineStage[],
      dataTypes: parsed.dataTypes,
      inputTypes: parsed.inputTypes,
      outputTypes: parsed.outputTypes,
      description: parsed.description,
      reasoning: parsed.reasoning,
      suggestedName: parsed.suggestedName,
      suggestedDisplayName: parsed.suggestedDisplayName,
      hasOpenApiSpec: probeResult.hasOpenApiSpec,
      detectedAuthMethod: probeResult.detectedAuthMethod ?? "api_key",
      detectedRateLimit: probeResult.rateLimitHeaders?.limit ? parseInt(probeResult.rateLimitHeaders.limit) : undefined,
      similarExisting: (parsed.overlapAnalysis || []).map((o: any) => ({
        id: o.existingId,
        name: o.existingName,
        overlapPercent: o.overlapPercent,
      })),
      valueAssessment: {
        overallScore: parsed.valueScore,
        uniqueDataScore: parsed.uniqueDataScore,
        reliabilityScore: parsed.reliabilityScore,
        freshnessScore: 50, // Default — can't assess freshness from a single probe
        overlapSources: (parsed.overlapAnalysis || []).filter((o: any) => o.overlapPercent > 30).map((o: any) => o.existingId),
        overlapPercent: Math.max(0, ...(parsed.overlapAnalysis || []).map((o: any) => o.overlapPercent)),
        summary: parsed.valueSummary,
        valueAdds: parsed.valueAdds,
        concerns: parsed.concerns,
        assessedBy: "llm",
        assessedAt: Date.now(),
      },
      rawLlmResponse: content,
    };

    return result;
  } catch (err: any) {
    // Return a low-confidence fallback classification
    return {
      category: "custom",
      confidence: 10,
      pipelineStages: ["enrichment"],
      dataTypes: ["unknown"],
      inputTypes: ["unknown"],
      outputTypes: [],
      description: input.customerDescription || `API at ${input.baseUrl}`,
      reasoning: `LLM classification failed: ${err.message}. Defaulting to 'custom' category. Customer should manually classify this integration.`,
      suggestedName: input.customerName?.toLowerCase().replace(/\s+/g, "_") || "custom_api",
      suggestedDisplayName: input.customerName || "Custom API",
      hasOpenApiSpec: probeResult.hasOpenApiSpec,
      detectedAuthMethod: probeResult.detectedAuthMethod ?? "api_key",
      similarExisting: [],
      valueAssessment: {
        overallScore: 0,
        uniqueDataScore: 0,
        reliabilityScore: 0,
        freshnessScore: 0,
        overlapSources: [],
        overlapPercent: 0,
        summary: "Classification failed — manual review required",
        valueAdds: [],
        concerns: ["LLM classification failed — customer must manually verify"],
        assessedBy: "llm",
        assessedAt: Date.now(),
      },
      rawLlmResponse: undefined,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — FEEDBACK LEARNING
// ═══════════════════════════════════════════════════════════════════════

/**
 * In-memory feedback store — customer corrections improve future classifications.
 * In production, this would be persisted to the database.
 */
const feedbackStore: ClassificationFeedback[] = [];

/**
 * Record a customer correction to improve future classifications.
 */
export function recordClassificationFeedback(feedback: ClassificationFeedback): void {
  feedbackStore.push(feedback);
}

/**
 * Get all recorded feedback for analysis.
 */
export function getClassificationFeedback(): ClassificationFeedback[] {
  return [...feedbackStore];
}

/**
 * Build a feedback context string for the LLM to learn from past corrections.
 * This is injected into the classification prompt when available.
 */
export function buildFeedbackContext(): string {
  if (feedbackStore.length === 0) return "";

  const examples = feedbackStore.slice(-20).map(f => {
    const stageChange = JSON.stringify(f.originalStages) !== JSON.stringify(f.correctedStages);
    return `- API with characteristics ${JSON.stringify(f.apiCharacteristics)}: ` +
      `LLM said "${f.originalCategory}" → Customer corrected to "${f.correctedCategory}"` +
      (stageChange ? ` (stages: ${f.originalStages.join(",")} → ${f.correctedStages.join(",")})` : "");
  });

  return `\n\nPAST CORRECTIONS (learn from these):\n${examples.join("\n")}`;
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — FULL DISCOVERY PIPELINE
// ═══════════════════════════════════════════════════════════════════════

export interface DiscoveryPipelineResult {
  /** API probe results */
  probe: ApiProbeResult;
  /** LLM classification result */
  classification: AutoDiscoveryResult;
  /** Whether the API is ready for review */
  readyForReview: boolean;
  /** Issues that need customer attention */
  issues: string[];
  /** Suggested next steps */
  nextSteps: string[];
}

/**
 * Run the full auto-discovery pipeline:
 *   1. Probe the API
 *   2. Classify with LLM
 *   3. Assess value
 *   4. Generate proposal for customer review
 */
export async function runDiscoveryPipeline(input: ApiProbeInput): Promise<DiscoveryPipelineResult> {
  const issues: string[] = [];
  const nextSteps: string[] = [];

  // Step 1: Probe the API
  const probe = await probeApi(input);

  if (!probe.reachable) {
    issues.push(`API at ${input.baseUrl} is not reachable: ${probe.error}`);
    nextSteps.push("Verify the API URL is correct and accessible from the AC3 platform");
    nextSteps.push("Check if the API requires VPN or IP whitelisting");
  }

  if (probe.statusCode === 401 || probe.statusCode === 403) {
    issues.push("API returned authentication error — API key may be required or invalid");
    nextSteps.push("Provide a valid API key for this integration");
  }

  // Step 2: Classify with LLM
  const classification = await classifyApi(input, probe);

  if (classification.confidence < 50) {
    issues.push(`Low classification confidence (${classification.confidence}%) — please review carefully`);
    nextSteps.push("Review the proposed category and pipeline stages and correct if needed");
  }

  if (classification.valueAssessment.overlapPercent > 70) {
    issues.push(`High overlap (${classification.valueAssessment.overlapPercent}%) with existing integrations: ${classification.similarExisting.map(s => s.name).join(", ")}`);
    nextSteps.push("Consider whether this source provides unique data not available from existing integrations");
  }

  // Step 3: Generate next steps
  if (issues.length === 0) {
    nextSteps.push("Review the proposed classification and approve to wire into your pipeline");
  }

  if (!input.apiKey && classification.detectedAuthMethod !== "none") {
    nextSteps.push("Provide API credentials to enable this integration");
  }

  if (classification.hasOpenApiSpec) {
    nextSteps.push("OpenAPI spec detected — the platform can auto-generate a connector adapter");
  }

  return {
    probe,
    classification,
    readyForReview: probe.reachable || !!input.customerDescription,
    issues,
    nextSteps,
  };
}
