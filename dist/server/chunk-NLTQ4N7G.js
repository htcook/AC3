import {
  CallSiteVolumeTracker,
  SemanticInferenceCache,
  init_llm_inference_optimizer
} from "./chunk-RUIEEOYK.js";
import {
  ENV,
  init_env
} from "./chunk-KDOLKO2A.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/_core/llm.ts
function getForgeConfig() {
  const forgeUrl = ENV.forgeApiUrl && ENV.forgeApiUrl.trim().length > 0 ? `${ENV.forgeApiUrl.replace(/\/$/, "")}/v1/chat/completions` : "https://forge.manus.im/v1/chat/completions";
  return {
    apiUrl: forgeUrl,
    apiKey: ENV.forgeApiKey,
    model: "gemini-2.5-flash",
    provider: "forge"
  };
}
function getOpenAIConfig() {
  if (ENV.openaiApiKey && ENV.openaiApiKey.trim().length > 0) {
    return {
      apiUrl: "https://api.openai.com/v1/chat/completions",
      apiKey: ENV.openaiApiKey,
      model: "gpt-4o",
      provider: "openai"
    };
  }
  return null;
}
function resolveProvider(priority = "standard") {
  const openai = getOpenAIConfig();
  const forge = getForgeConfig();
  switch (priority) {
    case "essential":
      if (openai) {
        console.log(`[LLM Router] Priority=essential \u2192 OpenAI (gpt-4o)`);
        return openai;
      }
      console.log(`[LLM Router] Priority=essential but no OpenAI key \u2192 Forge fallback`);
      return forge;
    case "bulk":
      if (IS_EXTERNAL_DEPLOYMENT && openai) {
        console.log(`[LLM Router] Priority=bulk (external) \u2192 OpenAI (gpt-4o)`);
        return openai;
      }
      console.log(`[LLM Router] Priority=bulk \u2192 Forge (gemini-2.5-flash)`);
      return forge;
    case "standard":
    default:
      if (IS_EXTERNAL_DEPLOYMENT && openai) {
        console.log(`[LLM Router] Priority=standard (external) \u2192 OpenAI (gpt-4o)`);
        return openai;
      }
      console.log(`[LLM Router] Priority=standard \u2192 Forge (gemini-2.5-flash)`);
      return forge;
  }
}
function isRetryable(status) {
  return RETRYABLE_STATUS_CODES.has(status);
}
async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function getLLMCacheStats() {
  return {
    cache: inferenceCache.getStats(),
    callSites: callSiteTracker.getTopCallers(20),
    graduationCandidates: inferenceCache.getGraduationCandidates(5)
  };
}
function getEngagementLLMSummary(engagementId) {
  return callSiteTracker.getEngagementSummary(engagementId);
}
function getLLMAnomalies() {
  return callSiteTracker.detectAnomalies();
}
async function invokeLLM(params) {
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
    _priority = "standard"
  } = params;
  const isCacheable = !tools || tools.length === 0;
  if (isCacheable && _caller) {
    const cached = inferenceCache.lookup(messages, _caller);
    if (cached) {
      console.log(`[LLM] Cache HIT for caller=${_caller} (saved API call)`);
      callSiteTracker.recordCall(_caller, 0, 0, false, _engagementId);
      return {
        id: `cache-${cached.hash.slice(0, 12)}`,
        created: Math.floor(Date.now() / 1e3),
        model: cached.model || "cached",
        choices: [{
          index: 0,
          message: { role: "assistant", content: cached.content },
          finish_reason: "stop"
        }],
        usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
      };
    }
  }
  const telemetryStart = Date.now();
  let telemetryRetries = 0;
  let telemetryHttpStatus;
  let telemetryStatus = "success";
  let telemetryError;
  const { apiUrl, apiKey, model, provider } = resolveProvider(_priority);
  if (!apiKey) {
    throw new Error(`LLM API key not configured (provider: ${provider})`);
  }
  console.log(`[LLM] Using provider: ${provider} (model: ${model}) priority=${_priority}`);
  const payload = {
    model,
    messages: messages.map(normalizeMessage)
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
  payload.max_tokens = 16384;
  if (provider === "forge") {
    payload.thinking = { budget_tokens: 128 };
  }
  const normalizedResponseFormat = normalizeResponseFormat({
    responseFormat,
    response_format,
    outputSchema,
    output_schema
  });
  if (normalizedResponseFormat) {
    payload.response_format = normalizedResponseFormat;
  }
  const bodyStr = JSON.stringify(payload);
  const payloadSizeKB = (bodyStr.length / 1024).toFixed(1);
  console.log(`[LLM] Request payload: ${payloadSizeKB}KB (${bodyStr.length} bytes) caller=${_caller || "unknown"}`);
  let lastError = null;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const LLM_TIMEOUT_MS = Math.min(params._timeoutMs || 9e4, 3e5);
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), LLM_TIMEOUT_MS);
    try {
      const response = await fetch(apiUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${apiKey}`
        },
        body: bodyStr,
        signal: controller.signal
      });
      if (!response.ok) {
        const errorText = await response.text();
        const status = response.status;
        if (isRetryable(status) && attempt < MAX_RETRIES) {
          const backoff = INITIAL_BACKOFF_MS * Math.pow(2, attempt);
          console.warn(
            `[LLM] Attempt ${attempt + 1}/${MAX_RETRIES + 1} failed with ${status} ${response.statusText}. Retrying in ${backoff}ms...`
          );
          lastError = new Error(
            `LLM invoke failed: ${status} ${response.statusText} \u2013 ${errorText}`
          );
          clearTimeout(timeoutId);
          await sleep(backoff);
          continue;
        }
        if (provider === "forge" && (status === 403 || status === 429)) {
          const openai = getOpenAIConfig();
          if (openai) {
            console.warn(`[LLM] Forge failed with ${status} after ${MAX_RETRIES + 1} attempts. Falling back to OpenAI...`);
            try {
              const fallbackResponse = await fetch(openai.apiUrl, {
                method: "POST",
                headers: { "content-type": "application/json", authorization: `Bearer ${openai.apiKey}` },
                body: JSON.stringify({ ...JSON.parse(bodyStr), model: openai.model, thinking: void 0 })
              });
              if (fallbackResponse.ok) {
                const fallbackResult = await fallbackResponse.json();
                console.log(`[LLM] OpenAI fallback succeeded`);
                recordTelemetry({
                  caller: _caller,
                  model: openai.model,
                  status: "retried_success",
                  httpStatus: 200,
                  latencyMs: Date.now() - telemetryStart,
                  retryCount: attempt + 1,
                  tokensIn: fallbackResult.usage?.prompt_tokens ?? 0,
                  tokensOut: fallbackResult.usage?.completion_tokens ?? 0,
                  hasResponseFormat: !!normalizedResponseFormat,
                  engagementId: _engagementId
                });
                return fallbackResult;
              }
            } catch (fallbackErr) {
              console.warn(`[LLM] OpenAI fallback also failed: ${fallbackErr.message}`);
            }
          }
        }
        recordTelemetry({
          caller: _caller,
          model,
          status: "error",
          httpStatus: status,
          latencyMs: Date.now() - telemetryStart,
          retryCount: attempt,
          hasResponseFormat: !!normalizedResponseFormat,
          errorMessage: `${status} ${response.statusText} \u2013 ${errorText}`.substring(0, 1e3),
          engagementId: _engagementId
        });
        throw new Error(
          `LLM invoke failed [providers_exhausted]: ${status} ${response.statusText} \u2013 ${errorText}`
        );
      }
      if (attempt > 0) {
        console.log(`[LLM] Succeeded on attempt ${attempt + 1} after ${attempt} retries`);
      }
      const result = await response.json();
      telemetryHttpStatus = 200;
      telemetryStatus = attempt > 0 ? "retried_success" : "success";
      telemetryRetries = attempt;
      const tokensIn = result.usage?.prompt_tokens ?? 0;
      const tokensOut = result.usage?.completion_tokens ?? 0;
      recordTelemetry({
        caller: _caller,
        model: result.model || model,
        status: telemetryStatus,
        httpStatus: 200,
        latencyMs: Date.now() - telemetryStart,
        retryCount: telemetryRetries,
        tokensIn,
        tokensOut,
        hasResponseFormat: !!normalizedResponseFormat,
        engagementId: _engagementId
      });
      if (isCacheable && _caller) {
        const content = result.choices?.[0]?.message?.content;
        if (typeof content === "string" && content.length > 0) {
          inferenceCache.store(
            messages,
            content,
            result.model || model,
            tokensIn,
            tokensOut,
            _caller,
            _engagementId
          );
        }
      }
      callSiteTracker.recordCall(
        _caller || "unknown",
        tokensIn,
        tokensOut,
        false,
        // success
        _engagementId
      );
      if (_caller && !_caller.startsWith("shadow-test:")) {
        import("./shadow-testing-WAMUY2K7.js").then(async ({ shouldShadowTest, executeShadowTest }) => {
          try {
            const shadowConfig = await shouldShadowTest(_caller || "unknown", _priority);
            if (shadowConfig) {
              executeShadowTest(shadowConfig, params, result).catch(() => {
              });
            }
          } catch {
          }
        }).catch(() => {
        });
      }
      return result;
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === "AbortError") {
        if (attempt < MAX_RETRIES) {
          const backoff = INITIAL_BACKOFF_MS * Math.pow(2, attempt);
          console.warn(
            `[LLM] Attempt ${attempt + 1}/${MAX_RETRIES + 1} timed out after ${LLM_TIMEOUT_MS / 1e3}s. Retrying in ${backoff}ms...`
          );
          lastError = new Error(`LLM invoke timed out after ${LLM_TIMEOUT_MS / 1e3}s`);
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
          errorMessage: `Timed out after ${LLM_TIMEOUT_MS / 1e3}s \u2014 all ${MAX_RETRIES + 1} attempts exhausted`,
          engagementId: _engagementId
        });
        throw new Error(`LLM invoke failed [providers_exhausted]: timed out after ${LLM_TIMEOUT_MS / 1e3}s \u2014 all ${MAX_RETRIES + 1} attempts exhausted`);
      }
      if (attempt < MAX_RETRIES && (err.code === "ECONNRESET" || err.code === "ECONNREFUSED" || err.code === "UND_ERR_SOCKET" || err.message?.includes("fetch failed"))) {
        const backoff = INITIAL_BACKOFF_MS * Math.pow(2, attempt);
        console.warn(
          `[LLM] Attempt ${attempt + 1}/${MAX_RETRIES + 1} network error: ${err.message}. Retrying in ${backoff}ms...`
        );
        lastError = err;
        await sleep(backoff);
        continue;
      }
      recordTelemetry({
        caller: _caller,
        model,
        status: "error",
        latencyMs: Date.now() - telemetryStart,
        retryCount: attempt,
        hasResponseFormat: !!normalizedResponseFormat,
        errorMessage: (err.message || String(err)).substring(0, 1e3),
        engagementId: _engagementId
      });
      throw err;
    } finally {
      clearTimeout(timeoutId);
    }
  }
  throw lastError || new Error("LLM invoke failed after all retries");
}
function recordTelemetry(data) {
  import("./db-GNA5CL3K.js").then(({ recordLlmTelemetry }) => {
    recordLlmTelemetry({
      calledAt: /* @__PURE__ */ new Date(),
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
      engagementId: data.engagementId ?? null
    });
  }).catch(() => {
  });
}
function inferCaller() {
  try {
    const stack = new Error().stack || "";
    const lines = stack.split("\n");
    const skipPatterns = [
      "llm.ts",
      "llm.js",
      "at Error",
      "at Object",
      "at inferCaller",
      "at recordTelemetry",
      "at logTelemetry",
      "at invokeLLM",
      "at async invokeLLM",
      "at processTicksAndRejections",
      "node:internal",
      "node_modules",
      "_core/",
      "procedureBuilder"
    ];
    for (const line of lines) {
      if (skipPatterns.some((p) => line.includes(p))) continue;
      const match = line.match(/at\s+(?:async\s+)?([\w$.]+)\s+\(/);
      if (match && match[1] !== "inferCaller") {
        const name = match[1];
        if (["Module", "Promise", "Object", "Array", "Function"].includes(name.split(".")[0])) continue;
        return name;
      }
      const fileMatch = line.match(/\/([\w-]+)\.(?:ts|js):(\d+)/);
      if (fileMatch) {
        const fileName = fileMatch[1];
        if (["llm", "db", "context", "trpc", "index"].includes(fileName)) continue;
        return `${fileName}:${fileMatch[2]}`;
      }
    }
  } catch {
  }
  return "unknown";
}
var ensureArray, normalizeContentPart, normalizeMessage, normalizeToolChoice, HAS_FORGE, IS_EXTERNAL_DEPLOYMENT, normalizeResponseFormat, MAX_RETRIES, INITIAL_BACKOFF_MS, RETRYABLE_STATUS_CODES, inferenceCache, callSiteTracker;
var init_llm = __esm({
  "server/_core/llm.ts"() {
    init_env();
    init_llm_inference_optimizer();
    ensureArray = (value) => Array.isArray(value) ? value : [value];
    normalizeContentPart = (part) => {
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
    normalizeMessage = (message) => {
      const { role, name, tool_call_id } = message;
      if (role === "tool" || role === "function") {
        const content = ensureArray(message.content).map((part) => typeof part === "string" ? part : JSON.stringify(part)).join("\n");
        return {
          role,
          name,
          tool_call_id,
          content
        };
      }
      const contentParts = ensureArray(message.content).map(normalizeContentPart);
      if (contentParts.length === 1 && contentParts[0].type === "text") {
        return {
          role,
          name,
          content: contentParts[0].text
        };
      }
      return {
        role,
        name,
        content: contentParts
      };
    };
    normalizeToolChoice = (toolChoice, tools) => {
      if (!toolChoice) return void 0;
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
          function: { name: tools[0].function.name }
        };
      }
      if ("name" in toolChoice) {
        return {
          type: "function",
          function: { name: toolChoice.name }
        };
      }
      return toolChoice;
    };
    HAS_FORGE = !!(ENV.forgeApiUrl && ENV.forgeApiUrl.trim().length > 0 && ENV.forgeApiKey && ENV.forgeApiKey.trim().length > 0);
    IS_EXTERNAL_DEPLOYMENT = !HAS_FORGE || !(ENV.forgeApiUrl || "").includes("manus");
    if (IS_EXTERNAL_DEPLOYMENT) {
      console.log("[LLM Router] External deployment detected \u2014 preferring OpenAI direct over Forge proxy");
    } else {
      console.log("[LLM Router] Manus deployment detected \u2014 using Forge as primary provider");
    }
    normalizeResponseFormat = ({
      responseFormat,
      response_format,
      outputSchema,
      output_schema
    }) => {
      const explicitFormat = responseFormat || response_format;
      if (explicitFormat) {
        if (explicitFormat.type === "json_schema" && !explicitFormat.json_schema?.schema) {
          throw new Error(
            "responseFormat json_schema requires a defined schema object"
          );
        }
        return explicitFormat;
      }
      const schema = outputSchema || output_schema;
      if (!schema) return void 0;
      if (!schema.name || !schema.schema) {
        throw new Error("outputSchema requires both name and schema");
      }
      return {
        type: "json_schema",
        json_schema: {
          name: schema.name,
          schema: schema.schema,
          ...typeof schema.strict === "boolean" ? { strict: schema.strict } : {}
        }
      };
    };
    MAX_RETRIES = 3;
    INITIAL_BACKOFF_MS = 2e3;
    RETRYABLE_STATUS_CODES = /* @__PURE__ */ new Set([403, 429, 500, 502, 503, 504]);
    inferenceCache = new SemanticInferenceCache({
      maxEntries: 500,
      defaultTtlMs: 5 * 60 * 1e3
      // 5 minute default TTL
    });
    callSiteTracker = new CallSiteVolumeTracker();
  }
});

export {
  getLLMCacheStats,
  getEngagementLLMSummary,
  getLLMAnomalies,
  invokeLLM,
  init_llm
};
