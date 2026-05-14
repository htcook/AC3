import { ENV } from "./env";

export type Role = "system" | "user" | "assistant" | "tool" | "function";

export type TextContent = {
  type: "text";
  text: string;
};

export type ImageContent = {
  type: "image_url";
  image_url: {
    url: string;
    detail?: "auto" | "low" | "high";
  };
};

export type FileContent = {
  type: "file_url";
  file_url: {
    url: string;
    mime_type?: "audio/mpeg" | "audio/wav" | "application/pdf" | "audio/mp4" | "video/mp4" ;
  };
};

export type MessageContent = string | TextContent | ImageContent | FileContent;

export type Message = {
  role: Role;
  content: MessageContent | MessageContent[];
  name?: string;
  tool_call_id?: string;
};

export type Tool = {
  type: "function";
  function: {
    name: string;
    description?: string;
    parameters?: Record<string, unknown>;
  };
};

export type ToolChoicePrimitive = "none" | "auto" | "required";
export type ToolChoiceByName = { name: string };
export type ToolChoiceExplicit = {
  type: "function";
  function: {
    name: string;
  };
};

export type ToolChoice =
  | ToolChoicePrimitive
  | ToolChoiceByName
  | ToolChoiceExplicit;

/**
 * LLM call priority tiers for cost-optimized routing:
 * - "essential": Always uses OpenAI (gpt-4o) — accuracy-critical tasks like
 *   vulnerability verification, attack planning, exploit generation, hybrid scoring
 * - "standard": Uses Forge (gemini-2.5-flash) by default; if OpenAI key is set
 *   and Forge fails, falls back to OpenAI. Default for untagged calls.
 * - "bulk": Always uses Forge — high-volume commodity tasks like text
 *   summarization, classification, report writing, enrichment
 */
export type LLMPriority = "essential" | "standard" | "bulk";

export type InvokeParams = {
  messages: Message[];
  tools?: Tool[];
  toolChoice?: ToolChoice;
  tool_choice?: ToolChoice;
  maxTokens?: number;
  max_tokens?: number;
  outputSchema?: OutputSchema;
  output_schema?: OutputSchema;
  responseFormat?: ResponseFormat;
  response_format?: ResponseFormat;
  /** Optional caller identifier for telemetry (e.g. "engagement-orchestrator.generateScanPlan") */
  _caller?: string;
  /** Optional engagement ID for telemetry context */
  _engagementId?: number;
  /**
   * LLM routing priority. Controls which provider handles this call.
   * - "essential": Always OpenAI (gpt-4o) for accuracy-critical work
   * - "standard": Forge first, OpenAI fallback (default)
   * - "bulk": Always Forge for commodity tasks
   */
  _priority?: LLMPriority;
  /**
   * Custom timeout in milliseconds for this LLM call.
   * Default: 90_000 (90s). Use higher values for enrichment-class calls
   * that process large context (BIA, report generation, etc.).
   * Max: 300_000 (5 minutes).
   */
  _timeoutMs?: number;
};

export type ToolCall = {
  id: string;
  type: "function";
  function: {
    name: string;
    arguments: string;
  };
};

export type InvokeResult = {
  id: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: {
      role: Role;
      content: string | Array<TextContent | ImageContent | FileContent>;
      tool_calls?: ToolCall[];
    };
    finish_reason: string | null;
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
};

export type JsonSchema = {
  name: string;
  schema: Record<string, unknown>;
  strict?: boolean;
};

export type OutputSchema = JsonSchema;

export type ResponseFormat =
  | { type: "text" }
  | { type: "json_object" }
  | { type: "json_schema"; json_schema: JsonSchema };

const ensureArray = (
  value: MessageContent | MessageContent[]
): MessageContent[] => (Array.isArray(value) ? value : [value]);

const normalizeContentPart = (
  part: MessageContent
): TextContent | ImageContent | FileContent => {
  if (typeof part === "string") {
    return { type: "text", text: part };
  }

  if (part.type === "text") {
    return part;
  }

  if (part.type === "image_url") {
    return part;
  }

  if (part.type === "file_url") {
    return part;
  }

  throw new Error("Unsupported message content part");
};

const normalizeMessage = (message: Message) => {
  const { role, name, tool_call_id } = message;

  if (role === "tool" || role === "function") {
    const content = ensureArray(message.content)
      .map(part => (typeof part === "string" ? part : JSON.stringify(part)))
      .join("\n");

    return {
      role,
      name,
      tool_call_id,
      content,
    };
  }

  const contentParts = ensureArray(message.content).map(normalizeContentPart);

  // If there's only text content, collapse to a single string for compatibility
  if (contentParts.length === 1 && contentParts[0].type === "text") {
    return {
      role,
      name,
      content: contentParts[0].text,
    };
  }

  return {
    role,
    name,
    content: contentParts,
  };
};

const normalizeToolChoice = (
  toolChoice: ToolChoice | undefined,
  tools: Tool[] | undefined
): "none" | "auto" | ToolChoiceExplicit | undefined => {
  if (!toolChoice) return undefined;

  if (toolChoice === "none" || toolChoice === "auto") {
    return toolChoice;
  }

  if (toolChoice === "required") {
    if (!tools || tools.length === 0) {
      throw new Error(
        "tool_choice 'required' was provided but no tools were configured"
      );
    }

    if (tools.length > 1) {
      throw new Error(
        "tool_choice 'required' needs a single tool or specify the tool name explicitly"
      );
    }

    return {
      type: "function",
      function: { name: tools[0].function.name },
    };
  }

  if ("name" in toolChoice) {
    return {
      type: "function",
      function: { name: toolChoice.name },
    };
  }

  return toolChoice;
}

// ─── Provider Resolution (Tiered Routing) ───────────────────────────────────────────
// Routes LLM calls to the appropriate provider based on priority tier:
//   essential → OpenAI (gpt-4o) for accuracy-critical tasks
//   standard  → OpenAI on DO (no Forge proxy latency); Forge on Manus
//   bulk      → Forge on Manus; OpenAI on DO if available, else Forge
//
// Environment detection: if BUILT_IN_FORGE_API_URL is empty or missing,
// we're on DO/self-hosted and should prefer OpenAI to avoid Forge proxy overhead.

const HAS_FORGE = !!(ENV.forgeApiUrl && ENV.forgeApiUrl.trim().length > 0 && ENV.forgeApiKey && ENV.forgeApiKey.trim().length > 0);
const IS_EXTERNAL_DEPLOYMENT = !HAS_FORGE || !(ENV.forgeApiUrl || '').includes('manus');

if (IS_EXTERNAL_DEPLOYMENT) {
  console.log('[LLM Router] External deployment detected — preferring OpenAI direct over Forge proxy');
} else {
  console.log('[LLM Router] Manus deployment detected — using Forge as primary provider');
}

function getForgeConfig(): { apiUrl: string; apiKey: string; model: string; provider: string } {
  const forgeUrl = ENV.forgeApiUrl && ENV.forgeApiUrl.trim().length > 0
    ? `${ENV.forgeApiUrl.replace(/\/$/, '')}/v1/chat/completions`
    : 'https://forge.manus.im/v1/chat/completions';
  return {
    apiUrl: forgeUrl,
    apiKey: ENV.forgeApiKey,
    model: 'gemini-2.5-flash',
    provider: 'forge',
  };
}

function getAzureOpenAIConfig(): { apiUrl: string; apiKey: string; model: string; provider: string } | null {
  if (ENV.azureOpenaiEndpoint && ENV.azureOpenaiKey) {
    const endpoint = ENV.azureOpenaiEndpoint.replace(/\/$/, '');
    const deployment = ENV.azureOpenaiDeployment;
    const apiVersion = ENV.azureOpenaiApiVersion;
    return {
      apiUrl: `${endpoint}/openai/deployments/${deployment}/chat/completions?api-version=${apiVersion}`,
      apiKey: ENV.azureOpenaiKey,
      model: deployment,
      provider: 'azure-openai',
    };
  }
  return null;
}

function getOpenAIConfig(): { apiUrl: string; apiKey: string; model: string; provider: string } | null {
  // Prefer Azure OpenAI if configured (for GovCloud/FedRAMP deployments)
  const azure = getAzureOpenAIConfig();
  if (azure) return azure;
  if (ENV.openaiApiKey && ENV.openaiApiKey.trim().length > 0) {
    return {
      apiUrl: 'https://api.openai.com/v1/chat/completions',
      apiKey: ENV.openaiApiKey,
      model: 'gpt-4o',
      provider: 'openai',
    };
  }
  return null;
}

function resolveProvider(priority: LLMPriority = 'standard'): { apiUrl: string; apiKey: string; model: string; provider: string } {
  const openai = getOpenAIConfig();
  const forge = getForgeConfig();

  switch (priority) {
    case 'essential':
      // Always prefer OpenAI for accuracy-critical tasks
      if (openai) {
        console.log(`[LLM Router] Priority=essential → OpenAI (gpt-4o)`);
        return openai;
      }
      console.log(`[LLM Router] Priority=essential but no OpenAI key → Forge fallback`);
      return forge;

    case 'bulk':
      // On external deployments (DO), use OpenAI if available to avoid Forge latency
      if (IS_EXTERNAL_DEPLOYMENT && openai) {
        console.log(`[LLM Router] Priority=bulk (external) → OpenAI (gpt-4o)`);
        return openai;
      }
      // On Manus, use Forge for commodity tasks to conserve OpenAI tokens
      console.log(`[LLM Router] Priority=bulk → Forge (gemini-2.5-flash)`);
      return forge;

    case 'standard':
    default:
      // On external deployments (DO), prefer OpenAI to avoid Forge proxy overhead
      if (IS_EXTERNAL_DEPLOYMENT && openai) {
        console.log(`[LLM Router] Priority=standard (external) → OpenAI (gpt-4o)`);
        return openai;
      }
      // On Manus, use Forge by default; OpenAI is fallback if Forge fails
      console.log(`[LLM Router] Priority=standard → Forge (gemini-2.5-flash)`);
      return forge;
  }
}

// assertApiKey is no longer needed - key validation is done inline in invokeLLM

const normalizeResponseFormat = ({
  responseFormat,
  response_format,
  outputSchema,
  output_schema,
}: {
  responseFormat?: ResponseFormat;
  response_format?: ResponseFormat;
  outputSchema?: OutputSchema;
  output_schema?: OutputSchema;
}):
  | { type: "json_schema"; json_schema: JsonSchema }
  | { type: "text" }
  | { type: "json_object" }
  | undefined => {
  const explicitFormat = responseFormat || response_format;
  if (explicitFormat) {
    if (
      explicitFormat.type === "json_schema" &&
      !explicitFormat.json_schema?.schema
    ) {
      throw new Error(
        "responseFormat json_schema requires a defined schema object"
      );
    }
    return explicitFormat;
  }

  const schema = outputSchema || output_schema;
  if (!schema) return undefined;

  if (!schema.name || !schema.schema) {
    throw new Error("outputSchema requires both name and schema");
  }

  return {
    type: "json_schema",
    json_schema: {
      name: schema.name,
      schema: schema.schema,
      ...(typeof schema.strict === "boolean" ? { strict: schema.strict } : {}),
    },
  };
};

// ─── Retry Configuration ──────────────────────────────────────────────────
const MAX_RETRIES = 3;
const INITIAL_BACKOFF_MS = 2_000; // 2s → 4s → 8s
const RETRYABLE_STATUS_CODES = new Set([403, 429, 500, 502, 503, 504]);

function isRetryable(status: number): boolean {
  return RETRYABLE_STATUS_CODES.has(status);
}

async function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ─── Semantic Inference Cache (automatic dedup for all call sites) ────────────
import { SemanticInferenceCache, CallSiteVolumeTracker } from '../lib/llm-inference-optimizer';

const inferenceCache = new SemanticInferenceCache({
  maxEntries: 500,
  defaultTtlMs: 5 * 60 * 1000, // 5 minute default TTL
});

const callSiteTracker = new CallSiteVolumeTracker();

/** Get cache stats for monitoring */
export function getLLMCacheStats() {
  return {
    cache: inferenceCache.getStats(),
    callSites: callSiteTracker.getTopCallers(20),
    graduationCandidates: inferenceCache.getGraduationCandidates(5),
  };
}

/** Get per-engagement call summary */
export function getEngagementLLMSummary(engagementId: number) {
  return callSiteTracker.getEngagementSummary(engagementId);
}

/** Get anomalies detected in call patterns */
export function getLLMAnomalies() {
  return callSiteTracker.detectAnomalies();
}

export async function invokeLLM(params: InvokeParams): Promise<InvokeResult> {
  // ─── LLM Feature Gate ──────────────────────────────────────────────────────
  // When LLM_ENABLED=false, return a graceful "disabled" response instead of
  // throwing errors. This allows the platform to run without any LLM provider.
  if (!ENV.llmEnabled) {
    return {
      id: 'llm-disabled',
      created: Math.floor(Date.now() / 1000),
      model: 'disabled',
      choices: [{
        index: 0,
        message: { role: 'assistant' as const, content: '[AI features are disabled in this deployment]' },
        finish_reason: 'stop',
      }],
      usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
    } as InvokeResult;
  }
  const {
    messages,
    tools,
    toolChoice,
    tool_choice,
    outputSchema,
    output_schema,
    responseFormat,
    response_format,
    _caller,
    _engagementId,
    _priority = 'standard',
  } = params;

  // ─── Semantic Cache Lookup ──────────────────────────────────────────────────
  // Only cache calls without tools (tool calls are inherently non-deterministic)
  const isCacheable = !tools || tools.length === 0;
  if (isCacheable && _caller) {
    const cached = inferenceCache.lookup(messages as any[], _caller);
    if (cached) {
      console.log(`[LLM] Cache HIT for caller=${_caller} (saved API call)`);
      // Track as a cached call (0 tokens, 0 latency)
      callSiteTracker.recordCall(_caller, 0, 0, false, _engagementId);
      // Return a synthetic InvokeResult from cache
      return {
        id: `cache-${cached.hash.slice(0, 12)}`,
        created: Math.floor(Date.now() / 1000),
        model: cached.model || 'cached',
        choices: [{
          index: 0,
          message: { role: 'assistant' as const, content: cached.content },
          finish_reason: 'stop',
        }],
        usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
      } as InvokeResult;
    }
  }

  const telemetryStart = Date.now();
  let telemetryRetries = 0;
  let telemetryHttpStatus: number | undefined;
  let telemetryStatus: "success" | "error" | "timeout" | "retried_success" = "success";
  let telemetryError: string | undefined;

  const { apiUrl, apiKey, model, provider } = resolveProvider(_priority);
  if (!apiKey) {
    throw new Error(`LLM API key not configured (provider: ${provider})`);
  }
  console.log(`[LLM] Using provider: ${provider} (model: ${model}) priority=${_priority}`);

  const payload: Record<string, unknown> = {
    model,
    messages: messages.map(normalizeMessage),
  };

  if (tools && tools.length > 0) {
    payload.tools = tools;
  }

  const normalizedToolChoice = normalizeToolChoice(
    toolChoice || tool_choice,
    tools
  );
  if (normalizedToolChoice) {
    payload.tool_choice = normalizedToolChoice;
  }

  // Set max_tokens based on provider model limits
  // Forge uses gemini-2.5-flash which supports max 16384 completion tokens
  // OpenAI gpt-4o also supports 16384 completion tokens
  payload.max_tokens = 16384;
  // Only add thinking budget for Forge/Gemini; OpenAI uses native reasoning
  if (provider === 'forge') {
    payload.thinking = { budget_tokens: 128 };
  }

  const normalizedResponseFormat = normalizeResponseFormat({
    responseFormat,
    response_format,
    outputSchema,
    output_schema,
  });

  if (normalizedResponseFormat) {
    payload.response_format = normalizedResponseFormat;
  }

  const bodyStr = JSON.stringify(payload);
  const payloadSizeKB = (bodyStr.length / 1024).toFixed(1);
  console.log(`[LLM] Request payload: ${payloadSizeKB}KB (${bodyStr.length} bytes) caller=${_caller || 'unknown'}`);
  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    // Configurable timeout — default 90s, max 5 minutes
    const LLM_TIMEOUT_MS = Math.min(params._timeoutMs || 90_000, 300_000);
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), LLM_TIMEOUT_MS);

    try {
      const headers: Record<string, string> = {
        "content-type": "application/json",
      };
      // Azure OpenAI uses "api-key" header; all others use Bearer token
      if (provider === 'azure-openai') {
        headers["api-key"] = apiKey;
      } else {
        headers["authorization"] = `Bearer ${apiKey}`;
      }
      const response = await fetch(apiUrl, {
        method: "POST",
        headers,
        body: bodyStr,
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorText = await response.text();
        const status = response.status;

        // If retryable and we have attempts left, wait and retry
        if (isRetryable(status) && attempt < MAX_RETRIES) {
          const backoff = INITIAL_BACKOFF_MS * Math.pow(2, attempt);
          console.warn(
            `[LLM] Attempt ${attempt + 1}/${MAX_RETRIES + 1} failed with ${status} ${response.statusText}. Retrying in ${backoff}ms...`
          );
          lastError = new Error(
            `LLM invoke failed: ${status} ${response.statusText} – ${errorText}`
          );
          clearTimeout(timeoutId);
          await sleep(backoff);
          continue;
        }

        // Provider fallback: if Forge exhausted retries, try OpenAI as last resort
        if (provider === 'forge' && (status === 403 || status === 429)) {
          const openai = getOpenAIConfig();
          if (openai) {
            console.warn(`[LLM] Forge failed with ${status} after ${MAX_RETRIES + 1} attempts. Falling back to OpenAI...`);
            try {
              const fallbackResponse = await fetch(openai.apiUrl, {
                method: 'POST',
                headers: { 'content-type': 'application/json', authorization: `Bearer ${openai.apiKey}` },
                body: JSON.stringify({ ...JSON.parse(bodyStr), model: openai.model, thinking: undefined }),
              });
              if (fallbackResponse.ok) {
                const fallbackResult = (await fallbackResponse.json()) as InvokeResult;
                console.log(`[LLM] OpenAI fallback succeeded`);
                recordTelemetry({
                  caller: _caller, model: openai.model, status: 'retried_success',
                  httpStatus: 200, latencyMs: Date.now() - telemetryStart,
                  retryCount: attempt + 1,
                  tokensIn: fallbackResult.usage?.prompt_tokens ?? 0,
                  tokensOut: fallbackResult.usage?.completion_tokens ?? 0,
                  hasResponseFormat: !!normalizedResponseFormat, engagementId: _engagementId,
                });
                return fallbackResult;
              }
            } catch (fallbackErr: any) {
              console.warn(`[LLM] OpenAI fallback also failed: ${fallbackErr.message}`);
            }
          }
        }

        // Record failed telemetry
        recordTelemetry({
          caller: _caller,
          model,
          status: "error",
          httpStatus: status,
          latencyMs: Date.now() - telemetryStart,
          retryCount: attempt,
          hasResponseFormat: !!normalizedResponseFormat,
          errorMessage: `${status} ${response.statusText} \u2013 ${errorText}`.substring(0, 1000),
          engagementId: _engagementId,
        });

        throw new Error(
          `LLM invoke failed [providers_exhausted]: ${status} ${response.statusText} \u2013 ${errorText}`
        );
      }

      if (attempt > 0) {
        console.log(`[LLM] Succeeded on attempt ${attempt + 1} after ${attempt} retries`);
      }

      const result = (await response.json()) as InvokeResult;

      // Record telemetry (fire-and-forget)
      telemetryHttpStatus = 200;
      telemetryStatus = attempt > 0 ? "retried_success" : "success";
      telemetryRetries = attempt;
      const tokensIn = result.usage?.prompt_tokens ?? 0;
      const tokensOut = result.usage?.completion_tokens ?? 0;
      recordTelemetry({
        caller: _caller,
        model: (result.model || model),
        status: telemetryStatus,
        httpStatus: 200,
        latencyMs: Date.now() - telemetryStart,
        retryCount: telemetryRetries,
        tokensIn,
        tokensOut,
        hasResponseFormat: !!normalizedResponseFormat,
        engagementId: _engagementId,
      });

      // ─── Store in Semantic Cache ──────────────────────────────────────────
      if (isCacheable && _caller) {
        const content = result.choices?.[0]?.message?.content;
        if (typeof content === 'string' && content.length > 0) {
          inferenceCache.store(
            messages as any[],
            content,
            result.model || model,
            tokensIn,
            tokensOut,
            _caller,
            _engagementId
          );
        }
      }

      // ─── Track Call Site Volume ──────────────────────────────────────────
      callSiteTracker.recordCall(
        _caller || 'unknown',
        tokensIn,
        tokensOut,
        false, // success
        _engagementId
      );

      // Fire-and-forget shadow testing — never blocks the primary response
      if (_caller && !_caller.startsWith('shadow-test:')) {
        import("../lib/shadow-testing").then(async ({ shouldShadowTest, executeShadowTest }) => {
          try {
            const shadowConfig = await shouldShadowTest(_caller || 'unknown', _priority);
            if (shadowConfig) {
              executeShadowTest(shadowConfig, params, result).catch(() => {});
            }
          } catch { /* shadow testing must never break the caller */ }
        }).catch(() => {});
      }

      return result;
    } catch (err: any) {
      clearTimeout(timeoutId);

      if (err.name === 'AbortError') {
        if (attempt < MAX_RETRIES) {
          const backoff = INITIAL_BACKOFF_MS * Math.pow(2, attempt);
          console.warn(
            `[LLM] Attempt ${attempt + 1}/${MAX_RETRIES + 1} timed out after ${LLM_TIMEOUT_MS / 1000}s. Retrying in ${backoff}ms...`
          );
          lastError = new Error(`LLM invoke timed out after ${LLM_TIMEOUT_MS / 1000}s`);
          await sleep(backoff);
          continue;
        }
        recordTelemetry({
          caller: _caller,
          model,
          status: "timeout",
          latencyMs: Date.now() - telemetryStart,
          retryCount: attempt,
          hasResponseFormat: !!normalizedResponseFormat,
          errorMessage: `Timed out after ${LLM_TIMEOUT_MS / 1000}s \u2014 all ${MAX_RETRIES + 1} attempts exhausted`,
          engagementId: _engagementId,
        });
        throw new Error(`LLM invoke failed [providers_exhausted]: timed out after ${LLM_TIMEOUT_MS / 1000}s \u2014 all ${MAX_RETRIES + 1} attempts exhausted`);
      }

      // Network errors (ECONNRESET, ECONNREFUSED, etc.) are retryable
      if (attempt < MAX_RETRIES && (err.code === 'ECONNRESET' || err.code === 'ECONNREFUSED' || err.code === 'UND_ERR_SOCKET' || err.message?.includes('fetch failed'))) {
        const backoff = INITIAL_BACKOFF_MS * Math.pow(2, attempt);
        console.warn(
          `[LLM] Attempt ${attempt + 1}/${MAX_RETRIES + 1} network error: ${err.message}. Retrying in ${backoff}ms...`
        );
        lastError = err;
        await sleep(backoff);
        continue;
      }

      // Record telemetry for unrecoverable errors
      recordTelemetry({
        caller: _caller,
        model,
        status: "error",
        latencyMs: Date.now() - telemetryStart,
        retryCount: attempt,
        hasResponseFormat: !!normalizedResponseFormat,
        errorMessage: (err.message || String(err)).substring(0, 1000),
        engagementId: _engagementId,
      });

      throw err;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // Should not reach here, but safety net
  throw lastError || new Error('LLM invoke failed after all retries');
}

// ─── Telemetry Recording (fire-and-forget) ─────────────────────────────────
function recordTelemetry(data: {
  caller?: string;
  model: string;
  status: "success" | "error" | "timeout" | "retried_success";
  httpStatus?: number;
  latencyMs: number;
  retryCount: number;
  tokensIn?: number;
  tokensOut?: number;
  hasResponseFormat?: boolean;
  errorMessage?: string;
  engagementId?: number;
}): void {
  // Lazy import to avoid circular dependency at module load time
  import("../db").then(({ recordLlmTelemetry }) => {
    recordLlmTelemetry({
      calledAt: new Date(),
      caller: data.caller || inferCaller(),
      model: data.model,
      status: data.status,
      httpStatus: data.httpStatus ?? null,
      latencyMs: data.latencyMs,
      retryCount: data.retryCount,
      tokensIn: data.tokensIn ?? 0,
      tokensOut: data.tokensOut ?? 0,
      hasResponseFormat: data.hasResponseFormat ?? false,
      errorMessage: data.errorMessage ?? null,
      engagementId: data.engagementId ?? null,
    });
  }).catch(() => { /* telemetry must never break the caller */ });
}

/**
 * Infer the caller from the stack trace when _caller is not provided.
 * Extracts the first meaningful frame outside of llm.ts.
 */
function inferCaller(): string {
  try {
    const stack = new Error().stack || "";
    const lines = stack.split("\n");
    // Skip frames from llm.ts itself, db.ts telemetry recording, and generic frames
    const skipPatterns = [
      "llm.ts", "llm.js",
      "at Error", "at Object",
      "at inferCaller", "at recordTelemetry", "at logTelemetry",
      "at invokeLLM", "at async invokeLLM",
      "at processTicksAndRejections",
      "node:internal", "node_modules",
      "_core/", "procedureBuilder",
    ];
    for (const line of lines) {
      if (skipPatterns.some(p => line.includes(p))) continue;
      // Try to match function name like "at functionName ("
      const match = line.match(/at\s+(?:async\s+)?([\w$.]+)\s+\(/);
      if (match && match[1] !== "inferCaller") {
        // Convert class.method to more readable format
        const name = match[1];
        // Skip generic wrappers
        if (["Module", "Promise", "Object", "Array", "Function"].includes(name.split(".")[0])) continue;
        return name;
      }
      // Try to extract filename:line as fallback
      const fileMatch = line.match(/\/([\w-]+)\.(?:ts|js):(\d+)/);
      if (fileMatch) {
        const fileName = fileMatch[1];
        // Skip framework/internal files
        if (["llm", "db", "context", "trpc", "index"].includes(fileName)) continue;
        return `${fileName}:${fileMatch[2]}`;
      }
    }
  } catch { /* ignore */ }
  return "unknown";
}
