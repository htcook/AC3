/**
 * LLM Request Throttle — Global Rate Limiter for LLM API Calls
 * 
 * Prevents 403/429 rate limiting by enforcing a minimum delay between
 * successive LLM API calls across the entire application. Uses a FIFO
 * queue with configurable concurrency and inter-request spacing.
 * 
 * Architecture:
 * - All LLM calls go through `throttledLLMCall()` instead of direct `invokeLLM()`
 * - Requests are queued and processed sequentially with configurable delays
 * - Priority tiers get different queue treatment (essential > standard > bulk)
 * - Adaptive delay: increases on 403/429 errors, decreases on success streaks
 */

import { invokeLLM, type InvokeParams, type InvokeResult, type LLMPriority } from "../_core/llm";

// ─── Configuration ──────────────────────────────────────────────────

export interface ThrottleConfig {
  /** Minimum delay between LLM calls in ms (default: 1500ms) */
  minDelayMs: number;
  /** Maximum delay between LLM calls in ms (default: 15000ms) */
  maxDelayMs: number;
  /** Delay increase factor on rate limit error (default: 2.0) */
  backoffMultiplier: number;
  /** Delay decrease factor on success (default: 0.85) */
  cooldownMultiplier: number;
  /** Number of consecutive successes before reducing delay (default: 3) */
  cooldownThreshold: number;
  /** Maximum concurrent LLM calls (default: 1) */
  maxConcurrent: number;
}

const DEFAULT_CONFIG: ThrottleConfig = {
  minDelayMs: 800,
  maxDelayMs: 12000,
  backoffMultiplier: 1.8,
  cooldownMultiplier: 0.8,
  cooldownThreshold: 3,
  maxConcurrent: 3,
};

// ─── State ──────────────────────────────────────────────────────────

interface QueueEntry {
  params: InvokeParams;
  priority: LLMPriority;
  resolve: (result: InvokeResult) => void;
  reject: (error: Error) => void;
  enqueuedAt: number;
  caller?: string;
  /** Direct callback for legacy callers that pass () => invokeLLM(...) */
  _directFn?: () => Promise<InvokeResult>;
}

let config = { ...DEFAULT_CONFIG };
let currentDelayMs = config.minDelayMs;
let consecutiveSuccesses = 0;
let lastCallAt = 0;
let activeCount = 0;
let isProcessing = false;

// Priority queues: essential > standard > bulk
const queues: Record<LLMPriority, QueueEntry[]> = {
  essential: [],
  standard: [],
  bulk: [],
};

// Telemetry
let totalQueued = 0;
let totalProcessed = 0;
let totalRateLimited = 0;
let totalSucceeded = 0;
let totalFailed = 0;
let maxQueueDepth = 0;

// ─── Public API ─────────────────────────────────────────────────────

/**
 * Submit an LLM call through the global throttle queue.
 * Returns a promise that resolves when the call completes.
 *
 * Supports multiple calling conventions for backward compatibility:
 *   throttledLLMCall(params)                     — standard params object
 *   throttledLLMCall(label, () => invokeLLM(p))  — legacy label + callback
 *   throttledLLMCall(() => invokeLLM(p))          — legacy callback only
 */
export function throttledLLMCall(
  paramsOrLabelOrFn: InvokeParams | string | (() => Promise<InvokeResult>),
  maybeFn?: (() => Promise<InvokeResult>) | string,
): Promise<InvokeResult> {
  // ── Normalize the three calling conventions into a single InvokeParams ──
  let params: InvokeParams;
  let directFn: (() => Promise<InvokeResult>) | undefined;

  if (typeof paramsOrLabelOrFn === 'function') {
    // throttledLLMCall(() => invoke({...}))
    directFn = paramsOrLabelOrFn;
    params = { messages: [], _caller: 'legacy-callback' };
  } else if (typeof paramsOrLabelOrFn === 'string') {
    // throttledLLMCall("label", () => invoke({...}))
    directFn = maybeFn as (() => Promise<InvokeResult>);
    params = { messages: [], _caller: paramsOrLabelOrFn };
  } else {
    // throttledLLMCall({ messages, ... }) — standard path
    params = paramsOrLabelOrFn;
  }

  const priority = params._priority || 'standard';
  
  return new Promise<InvokeResult>((resolve, reject) => {
    const entry: QueueEntry = {
      params,
      priority,
      resolve,
      reject,
      enqueuedAt: Date.now(),
      caller: params._caller,
      _directFn: directFn,
    };
    
    queues[priority].push(entry);
    totalQueued++;
    
    const depth = queues.essential.length + queues.standard.length + queues.bulk.length;
    if (depth > maxQueueDepth) maxQueueDepth = depth;
    
    console.log(`[LLM Throttle] Queued ${priority} call from ${params._caller || 'unknown'} (depth: ${depth}, delay: ${Math.round(currentDelayMs)}ms)`);
    
    // Kick off processing if not already running
    processQueue();
  });
}

/**
 * Get current throttle statistics for monitoring.
 */
export function getThrottleStats() {
  const queueDepth = queues.essential.length + queues.standard.length + queues.bulk.length;
  return {
    currentDelayMs: Math.round(currentDelayMs),
    consecutiveSuccesses,
    activeCount,
    queueDepth,
    queues: {
      essential: queues.essential.length,
      standard: queues.standard.length,
      bulk: queues.bulk.length,
    },
    totals: {
      queued: totalQueued,
      processed: totalProcessed,
      succeeded: totalSucceeded,
      failed: totalFailed,
      rateLimited: totalRateLimited,
    },
    maxQueueDepth,
    isProcessing,
  };
}

/**
 * Update throttle configuration at runtime.
 */
export function updateThrottleConfig(updates: Partial<ThrottleConfig>): void {
  config = { ...config, ...updates };
  if (currentDelayMs < config.minDelayMs) currentDelayMs = config.minDelayMs;
  if (currentDelayMs > config.maxDelayMs) currentDelayMs = config.maxDelayMs;
  console.log(`[LLM Throttle] Config updated:`, config);
}

/**
 * Reset throttle state (for testing).
 */
export function resetThrottle(): void {
  config = { ...DEFAULT_CONFIG };
  currentDelayMs = config.minDelayMs;
  consecutiveSuccesses = 0;
  lastCallAt = 0;
  activeCount = 0;
  isProcessing = false;
  queues.essential.length = 0;
  queues.standard.length = 0;
  queues.bulk.length = 0;
  totalQueued = 0;
  totalProcessed = 0;
  totalRateLimited = 0;
  totalSucceeded = 0;
  totalFailed = 0;
  maxQueueDepth = 0;
}

// ─── Internal Processing ────────────────────────────────────────────

function getNextEntry(): QueueEntry | undefined {
  // Priority order: essential > standard > bulk
  if (queues.essential.length > 0) return queues.essential.shift()!;
  if (queues.standard.length > 0) return queues.standard.shift()!;
  if (queues.bulk.length > 0) return queues.bulk.shift()!;
  return undefined;
}

async function processQueue(): Promise<void> {
  if (isProcessing) return; // Already processing
  isProcessing = true;
  
  while (true) {
    // Wait for a slot if at max concurrency
    if (activeCount >= config.maxConcurrent) {
      await sleep(100);
      continue;
    }
    
    const entry = getNextEntry();
    if (!entry) {
      // If there are still active calls, wait for them to complete and check again
      if (activeCount > 0) {
        await sleep(100);
        continue;
      }
      break;
    }
    
    // Enforce minimum delay between calls
    const elapsed = Date.now() - lastCallAt;
    if (elapsed < currentDelayMs && lastCallAt > 0) {
      const waitMs = currentDelayMs - elapsed;
      console.log(`[LLM Throttle] Waiting ${Math.round(waitMs)}ms before next call (adaptive delay: ${Math.round(currentDelayMs)}ms)`);
      await sleep(waitMs);
    }
    
    // Check if call has been waiting too long (> 3 minutes)
    const waitTime = Date.now() - entry.enqueuedAt;
    if (waitTime > 180_000) {
      console.warn(`[LLM Throttle] Dropping stale ${entry.priority} call from ${entry.caller} (waited ${Math.round(waitTime / 1000)}s)`);
      entry.reject(new Error(`LLM call timed out in queue after ${Math.round(waitTime / 1000)}s`));
      totalFailed++;
      continue;
    }
    
    activeCount++;
    lastCallAt = Date.now();
    totalProcessed++;
    
    // Fire and continue (don't await — allows concurrency)
    processEntry(entry).catch(() => {});
  }
  
  isProcessing = false;
}

async function processEntry(entry: QueueEntry): Promise<void> {
  try {
    // Use direct callback for legacy callers, otherwise use standard invokeLLM
    const result = entry._directFn
      ? await entry._directFn()
      : await invokeLLM({ _caller: entry.params._caller || 'llm-throttle', ...entry.params });
    activeCount--;
    
    // Success: cool down the delay
    consecutiveSuccesses++;
    if (consecutiveSuccesses >= config.cooldownThreshold) {
      const newDelay = currentDelayMs * config.cooldownMultiplier;
      currentDelayMs = Math.max(newDelay, config.minDelayMs);
      consecutiveSuccesses = 0;
      console.log(`[LLM Throttle] Cooldown: delay reduced to ${Math.round(currentDelayMs)}ms after ${config.cooldownThreshold} successes`);
    }
    
    totalSucceeded++;
    entry.resolve(result);
  } catch (err: any) {
    activeCount--;
    const message = err?.message || String(err);
    
    // Check if this is a rate limit error
    const isRateLimit = message.includes('403') || message.includes('429') || message.includes('rate limit') || message.includes('Forbidden') || message.includes('Too Many Requests');
    
    // Check if invokeLLM already exhausted all its internal retries + fallback
    const isExhaustedRetries = message.includes('providers_exhausted') || message.includes('LLM invoke failed') || message.includes('All LLM providers failed');
    
    if (isRateLimit) {
      const newDelay = currentDelayMs * config.backoffMultiplier;
      currentDelayMs = Math.min(newDelay, config.maxDelayMs);
      consecutiveSuccesses = 0;
      totalRateLimited++;
      console.warn(`[LLM Throttle] Rate limited! Delay increased to ${Math.round(currentDelayMs)}ms`);
      
      // Only re-queue if invokeLLM hasn't already exhausted all retries/fallbacks
      if (!entry.params._throttleRetried && !isExhaustedRetries) {
        entry.params._throttleRetried = true;
        queues[entry.priority].unshift(entry);
        console.log(`[LLM Throttle] Re-queued ${entry.priority} call from ${entry.caller} for retry`);
        // Kick processing again after delay
        setTimeout(() => processQueue(), currentDelayMs);
        return;
      } else {
        console.warn(`[LLM Throttle] NOT re-queuing ${entry.caller} — ${isExhaustedRetries ? 'all providers exhausted' : 'already retried once'}. Letting caller handle fallback.`);
      }
    }
    
    totalFailed++;
    entry.reject(err);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Extend InvokeParams to track throttle retries (internal use only)
declare module "../_core/llm" {
  interface InvokeParams {
    _throttleRetried?: boolean;
  }
}
