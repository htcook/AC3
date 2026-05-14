import {
  init_llm,
  invokeLLM
} from "./chunk-L5VXSJ4F.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/llm-throttle.ts
function throttledLLMCall(paramsOrLabelOrFn, maybeFn) {
  let params;
  let directFn;
  if (typeof paramsOrLabelOrFn === "function") {
    directFn = paramsOrLabelOrFn;
    params = { messages: [], _caller: "legacy-callback" };
  } else if (typeof paramsOrLabelOrFn === "string") {
    directFn = maybeFn;
    params = { messages: [], _caller: paramsOrLabelOrFn };
  } else {
    params = paramsOrLabelOrFn;
  }
  const priority = params._priority || "standard";
  return new Promise((resolve, reject) => {
    const entry = {
      params,
      priority,
      resolve,
      reject,
      enqueuedAt: Date.now(),
      caller: params._caller,
      _directFn: directFn
    };
    queues[priority].push(entry);
    totalQueued++;
    const depth = queues.essential.length + queues.standard.length + queues.bulk.length;
    if (depth > maxQueueDepth) maxQueueDepth = depth;
    console.log(`[LLM Throttle] Queued ${priority} call from ${params._caller || "unknown"} (depth: ${depth}, delay: ${Math.round(currentDelayMs)}ms)`);
    processQueue();
  });
}
function getNextEntry() {
  if (queues.essential.length > 0) return queues.essential.shift();
  if (queues.standard.length > 0) return queues.standard.shift();
  if (queues.bulk.length > 0) return queues.bulk.shift();
  return void 0;
}
async function processQueue() {
  if (isProcessing) return;
  isProcessing = true;
  while (true) {
    if (activeCount >= config.maxConcurrent) {
      await sleep(100);
      continue;
    }
    const entry = getNextEntry();
    if (!entry) {
      if (activeCount > 0) {
        await sleep(100);
        continue;
      }
      break;
    }
    const elapsed = Date.now() - lastCallAt;
    if (elapsed < currentDelayMs && lastCallAt > 0) {
      const waitMs = currentDelayMs - elapsed;
      console.log(`[LLM Throttle] Waiting ${Math.round(waitMs)}ms before next call (adaptive delay: ${Math.round(currentDelayMs)}ms)`);
      await sleep(waitMs);
    }
    const waitTime = Date.now() - entry.enqueuedAt;
    if (waitTime > 18e4) {
      console.warn(`[LLM Throttle] Dropping stale ${entry.priority} call from ${entry.caller} (waited ${Math.round(waitTime / 1e3)}s)`);
      entry.reject(new Error(`LLM call timed out in queue after ${Math.round(waitTime / 1e3)}s`));
      totalFailed++;
      continue;
    }
    activeCount++;
    lastCallAt = Date.now();
    totalProcessed++;
    processEntry(entry).catch(() => {
    });
  }
  isProcessing = false;
}
async function processEntry(entry) {
  try {
    const result = entry._directFn ? await entry._directFn() : await invokeLLM({ _caller: entry.params._caller || "llm-throttle", ...entry.params });
    activeCount--;
    consecutiveSuccesses++;
    if (consecutiveSuccesses >= config.cooldownThreshold) {
      const newDelay = currentDelayMs * config.cooldownMultiplier;
      currentDelayMs = Math.max(newDelay, config.minDelayMs);
      consecutiveSuccesses = 0;
      console.log(`[LLM Throttle] Cooldown: delay reduced to ${Math.round(currentDelayMs)}ms after ${config.cooldownThreshold} successes`);
    }
    totalSucceeded++;
    entry.resolve(result);
  } catch (err) {
    activeCount--;
    const message = err?.message || String(err);
    const isRateLimit = message.includes("403") || message.includes("429") || message.includes("rate limit") || message.includes("Forbidden") || message.includes("Too Many Requests");
    const isExhaustedRetries = message.includes("providers_exhausted") || message.includes("LLM invoke failed") || message.includes("All LLM providers failed");
    if (isRateLimit) {
      const newDelay = currentDelayMs * config.backoffMultiplier;
      currentDelayMs = Math.min(newDelay, config.maxDelayMs);
      consecutiveSuccesses = 0;
      totalRateLimited++;
      console.warn(`[LLM Throttle] Rate limited! Delay increased to ${Math.round(currentDelayMs)}ms`);
      if (!entry.params._throttleRetried && !isExhaustedRetries) {
        entry.params._throttleRetried = true;
        queues[entry.priority].unshift(entry);
        console.log(`[LLM Throttle] Re-queued ${entry.priority} call from ${entry.caller} for retry`);
        setTimeout(() => processQueue(), currentDelayMs);
        return;
      } else {
        console.warn(`[LLM Throttle] NOT re-queuing ${entry.caller} \u2014 ${isExhaustedRetries ? "all providers exhausted" : "already retried once"}. Letting caller handle fallback.`);
      }
    }
    totalFailed++;
    entry.reject(err);
  }
}
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
var DEFAULT_CONFIG, config, currentDelayMs, consecutiveSuccesses, lastCallAt, activeCount, isProcessing, queues, totalQueued, totalProcessed, totalRateLimited, totalSucceeded, totalFailed, maxQueueDepth;
var init_llm_throttle = __esm({
  "server/lib/llm-throttle.ts"() {
    "use strict";
    init_llm();
    DEFAULT_CONFIG = {
      minDelayMs: 800,
      maxDelayMs: 12e3,
      backoffMultiplier: 1.8,
      cooldownMultiplier: 0.8,
      cooldownThreshold: 3,
      maxConcurrent: 3
    };
    config = { ...DEFAULT_CONFIG };
    currentDelayMs = config.minDelayMs;
    consecutiveSuccesses = 0;
    lastCallAt = 0;
    activeCount = 0;
    isProcessing = false;
    queues = {
      essential: [],
      standard: [],
      bulk: []
    };
    totalQueued = 0;
    totalProcessed = 0;
    totalRateLimited = 0;
    totalSucceeded = 0;
    totalFailed = 0;
    maxQueueDepth = 0;
  }
});

export {
  throttledLLMCall,
  init_llm_throttle
};
