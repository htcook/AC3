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
};

// ─── Provider Resolution ─────────────────────────────────────────────────
// When OPENAI_API_KEY is set, use OpenAI directly (no token limits).
// Otherwise fall back to Forge proxy.
function resolveProvider(): { apiUrl: string; apiKey: string; model: string; provider: string } {
  if (ENV.openaiApiKey && ENV.openaiApiKey.trim().length > 0) {
    return {
      apiUrl: 'https://api.openai.com/v1/chat/completions',
      apiKey: ENV.openaiApiKey,
      model: 'gpt-4o',
      provider: 'openai',
    };
  }
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

const assertApiKey = () => {
  const { apiKey, provider } = resolveProvider();
  if (!apiKey) {
    throw new Error(`LLM API key not configured (provider: ${provider})`);
  }
};

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

export async function invokeLLM(params: InvokeParams): Promise<InvokeResult> {
  assertApiKey();

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
  } = params;

  const telemetryStart = Date.now();
  let telemetryRetries = 0;
  let telemetryHttpStatus: number | undefined;
  let telemetryStatus: "success" | "error" | "timeout" | "retried_success" = "success";
  let telemetryError: string | undefined;

  const { apiUrl, apiKey, model, provider } = resolveProvider();
  console.log(`[LLM] Using provider: ${provider} (model: ${model})`);

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

  payload.max_tokens = 32768;
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
    // 90-second timeout to prevent hanging on slow/unresponsive LLM API
    const LLM_TIMEOUT_MS = 90_000;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), LLM_TIMEOUT_MS);

    try {
      const response = await fetch(apiUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${apiKey}`,
        },
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
          `LLM invoke failed: ${status} ${response.statusText} \u2013 ${errorText}`
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
        throw new Error(`LLM invoke timed out after ${LLM_TIMEOUT_MS / 1000}s \u2014 all ${MAX_RETRIES + 1} attempts exhausted`);
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
    for (const line of lines) {
      if (line.includes("llm.ts") || line.includes("llm.js") || line.includes("at Error") || line.includes("at Object")) continue;
      const match = line.match(/at\s+(?:async\s+)?([\w.]+)\s+\(/);
      if (match) return match[1];
      const fileMatch = line.match(/([\w-]+)\.(?:ts|js):(\d+)/);
      if (fileMatch) return `${fileMatch[1]}:${fileMatch[2]}`;
    }
  } catch { /* ignore */ }
  return "unknown";
}
