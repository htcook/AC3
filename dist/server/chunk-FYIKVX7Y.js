import {
  detectPromptInjection,
  init_ai_chat_safety,
  logAuditEvent,
  sanitizeAIOutput
} from "./chunk-RTDQ6SDF.js";

// server/lib/llm-safety-interceptor.ts
init_ai_chat_safety();
var DEFAULT_CONFIG = {
  enabled: true,
  blockHighSeverity: true,
  sanitizeOutputs: true,
  auditAll: true,
  bypassCallers: /* @__PURE__ */ new Set([
    // Internal system callers that don't process user-supplied text
    "shadow-test:",
    "llm-throttle",
    "inference-cache-warmup"
  ]),
  maxMessageLength: 1e5
};
var config = { ...DEFAULT_CONFIG };
var stats = {
  totalIntercepted: 0,
  totalBlocked: 0,
  totalSanitized: 0,
  totalInjectionDetected: 0,
  totalPiiScrubbed: 0,
  totalBypassed: 0,
  lastBlockedAt: null,
  lastInjectionAt: null,
  blockedCallers: /* @__PURE__ */ new Map(),
  injectionsByCategory: /* @__PURE__ */ new Map()
};
function interceptPreCall(params) {
  if (!config.enabled) {
    stats.totalBypassed++;
    return { proceed: true, inputModified: false };
  }
  const caller = params._caller || "unknown";
  for (const bypass of config.bypassCallers) {
    if (caller.startsWith(bypass)) {
      stats.totalBypassed++;
      return { proceed: true, inputModified: false };
    }
  }
  stats.totalIntercepted++;
  const userMessages = params.messages.filter((m) => m.role === "user");
  if (userMessages.length === 0) {
    return { proceed: true, inputModified: false };
  }
  let blocked = false;
  let blockReason;
  const allDetectedPatterns = [];
  let inputModified = false;
  const sanitizedMessages = [...params.messages];
  for (let i = 0; i < sanitizedMessages.length; i++) {
    const msg = sanitizedMessages[i];
    if (msg.role !== "user") continue;
    const textContent = extractTextContent(msg);
    if (!textContent) continue;
    if (textContent.length > config.maxMessageLength) {
      logAuditEvent({
        timestamp: Date.now(),
        tenantId: "system",
        userId: "interceptor",
        sessionId: `intercept-${caller}`,
        action: "oversized_message",
        details: `Message length ${textContent.length} exceeds max ${config.maxMessageLength} (caller: ${caller})`,
        severity: "warning"
      });
    }
    const injectionResult = detectPromptInjection(textContent);
    if (injectionResult.detected) {
      stats.totalInjectionDetected++;
      stats.lastInjectionAt = Date.now();
      for (const pattern of injectionResult.matchedPatterns) {
        allDetectedPatterns.push({
          id: pattern.id,
          name: pattern.name,
          severity: pattern.severity
        });
        const count = stats.injectionsByCategory.get(pattern.id) || 0;
        stats.injectionsByCategory.set(pattern.id, count + 1);
      }
      if (injectionResult.shouldBlock && config.blockHighSeverity) {
        blocked = true;
        blockReason = `Prompt injection detected in ${caller}: ${injectionResult.matchedPatterns.map((p) => p.name).join(", ")}`;
        stats.totalBlocked++;
        stats.lastBlockedAt = Date.now();
        const callerCount = stats.blockedCallers.get(caller) || 0;
        stats.blockedCallers.set(caller, callerCount + 1);
        logAuditEvent({
          timestamp: Date.now(),
          tenantId: "system",
          userId: "interceptor",
          sessionId: `intercept-${caller}`,
          action: "injection_blocked_transport",
          details: blockReason,
          severity: "critical"
        });
        break;
      }
      if (injectionResult.sanitizedInput !== textContent) {
        inputModified = true;
        sanitizedMessages[i] = replaceTextContent(msg, injectionResult.sanitizedInput);
        stats.totalSanitized++;
        logAuditEvent({
          timestamp: Date.now(),
          tenantId: "system",
          userId: "interceptor",
          sessionId: `intercept-${caller}`,
          action: "injection_sanitized_transport",
          details: `Low-severity patterns neutralized in ${caller}: ${injectionResult.matchedPatterns.map((p) => p.name).join(", ")}`,
          severity: "warning"
        });
      }
    }
  }
  if (blocked) {
    return {
      proceed: false,
      blockReason,
      detectedPatterns: allDetectedPatterns,
      inputModified
    };
  }
  return {
    proceed: true,
    sanitizedMessages: inputModified ? sanitizedMessages : void 0,
    detectedPatterns: allDetectedPatterns.length > 0 ? allDetectedPatterns : void 0,
    inputModified
  };
}
function interceptPostCall(result, params) {
  if (!config.enabled || !config.sanitizeOutputs) {
    return { result, outputModified: false, piiScrubbed: false, confidence: 1 };
  }
  const caller = params._caller || "unknown";
  for (const bypass of config.bypassCallers) {
    if (caller.startsWith(bypass)) {
      return { result, outputModified: false, piiScrubbed: false, confidence: 1 };
    }
  }
  let outputModified = false;
  let piiScrubbed = false;
  let minConfidence = 1;
  const sanitizedResult = { ...result, choices: [...result.choices] };
  for (let i = 0; i < sanitizedResult.choices.length; i++) {
    const choice = sanitizedResult.choices[i];
    const content = choice.message.content;
    if (typeof content !== "string" || !content) continue;
    const sanitization = sanitizeAIOutput(content, {
      tenantId: "system",
      scrubPII: true
    });
    if (sanitization.sanitizedOutput !== content) {
      outputModified = true;
      sanitizedResult.choices[i] = {
        ...choice,
        message: {
          ...choice.message,
          content: sanitization.sanitizedOutput
        }
      };
      if (sanitization.piiDetected) {
        piiScrubbed = true;
        stats.totalPiiScrubbed++;
      }
      stats.totalSanitized++;
      logAuditEvent({
        timestamp: Date.now(),
        tenantId: "system",
        userId: "interceptor",
        sessionId: `intercept-${caller}`,
        action: "output_sanitized_transport",
        details: `Output sanitized for ${caller}: PII=${sanitization.piiDetected}, dangerous=${sanitization.dangerousCodeDetected}, mods=${sanitization.modifications.length}`,
        severity: sanitization.piiDetected ? "warning" : "info"
      });
    }
    minConfidence = Math.min(minConfidence, sanitization.safetyConfidence);
  }
  return {
    result: outputModified ? sanitizedResult : result,
    outputModified,
    piiScrubbed,
    confidence: minConfidence
  };
}
function createSafeInvokeLLM(originalInvokeLLM) {
  return async (params) => {
    const preResult = interceptPreCall(params);
    if (!preResult.proceed) {
      console.warn(`[LLM Safety] BLOCKED call from ${params._caller}: ${preResult.blockReason}`);
      return {
        id: `safety-blocked-${Date.now()}`,
        created: Math.floor(Date.now() / 1e3),
        model: "safety-interceptor",
        choices: [{
          index: 0,
          message: {
            role: "assistant",
            content: "[BLOCKED] Your request was blocked by the AI safety system. A potential prompt injection or policy violation was detected. This incident has been logged for security review."
          },
          finish_reason: "stop"
        }],
        usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
      };
    }
    const effectiveParams = preResult.sanitizedMessages ? { ...params, messages: preResult.sanitizedMessages } : params;
    const result = await originalInvokeLLM(effectiveParams);
    const postResult = interceptPostCall(result, params);
    return postResult.result;
  };
}
var installed = false;
var originalFn = null;
async function installSafetyInterceptor() {
  if (installed) return;
  try {
    const llmModule = await import("./llm-ZHBF7TZ4.js");
    originalFn = llmModule.invokeLLM;
    const safeInvoke = createSafeInvokeLLM(originalFn);
    llmModule.invokeLLM = safeInvoke;
    installed = true;
    console.log("[LLM Safety] Transport-level safety interceptor installed successfully");
    console.log(`[LLM Safety] Config: blockHighSeverity=${config.blockHighSeverity}, sanitizeOutputs=${config.sanitizeOutputs}, auditAll=${config.auditAll}`);
    console.log(`[LLM Safety] Bypassing callers: ${[...config.bypassCallers].join(", ")}`);
  } catch (err) {
    console.error("[LLM Safety] Failed to install interceptor:", err.message);
  }
}
async function uninstallSafetyInterceptor() {
  if (!installed || !originalFn) return;
  try {
    const llmModule = await import("./llm-ZHBF7TZ4.js");
    llmModule.invokeLLM = originalFn;
    installed = false;
    originalFn = null;
    console.log("[LLM Safety] Transport-level safety interceptor uninstalled");
  } catch (err) {
    console.error("[LLM Safety] Failed to uninstall interceptor:", err.message);
  }
}
function updateInterceptorConfig(updates) {
  config = { ...config, ...updates };
  if (updates.bypassCallers) {
    config.bypassCallers = new Set(updates.bypassCallers);
  }
  console.log("[LLM Safety] Config updated:", JSON.stringify({
    enabled: config.enabled,
    blockHighSeverity: config.blockHighSeverity,
    sanitizeOutputs: config.sanitizeOutputs
  }));
}
function getInterceptorConfig() {
  return { ...config, bypassCallers: new Set(config.bypassCallers) };
}
function getInterceptorStats() {
  return {
    ...stats,
    blockedCallers: new Map(stats.blockedCallers),
    injectionsByCategory: new Map(stats.injectionsByCategory),
    installed
  };
}
function resetInterceptorStats() {
  stats.totalIntercepted = 0;
  stats.totalBlocked = 0;
  stats.totalSanitized = 0;
  stats.totalInjectionDetected = 0;
  stats.totalPiiScrubbed = 0;
  stats.totalBypassed = 0;
  stats.lastBlockedAt = null;
  stats.lastInjectionAt = null;
  stats.blockedCallers.clear();
  stats.injectionsByCategory.clear();
}
function extractTextContent(msg) {
  if (typeof msg.content === "string") return msg.content;
  if (Array.isArray(msg.content)) {
    const textParts = msg.content.filter(
      (c) => typeof c === "object" && "type" in c && c.type === "text"
    ).map((c) => c.text);
    return textParts.length > 0 ? textParts.join("\n") : null;
  }
  return null;
}
function replaceTextContent(msg, newText) {
  if (typeof msg.content === "string") {
    return { ...msg, content: newText };
  }
  if (Array.isArray(msg.content)) {
    let replaced = false;
    const newContent = msg.content.map((c) => {
      if (!replaced && typeof c === "object" && "type" in c && c.type === "text") {
        replaced = true;
        return { type: "text", text: newText };
      }
      return c;
    });
    return { ...msg, content: newContent };
  }
  return msg;
}

export {
  interceptPreCall,
  interceptPostCall,
  createSafeInvokeLLM,
  installSafetyInterceptor,
  uninstallSafetyInterceptor,
  updateInterceptorConfig,
  getInterceptorConfig,
  getInterceptorStats,
  resetInterceptorStats
};
