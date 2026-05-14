import {
  __esm
} from "./chunk-KFQGP6VL.js";

// shared/retry-with-backoff.ts
function defaultIsRetryable(error) {
  if (!error) return false;
  const message = (error.message || "").toLowerCase();
  const code = error.code || "";
  if (["ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "ENOTFOUND", "EAI_AGAIN", "EPIPE", "EHOSTUNREACH"].includes(code)) {
    return true;
  }
  const status = error.status || error.statusCode || error.response?.status;
  if (status && (status === 429 || status === 502 || status === 503 || status === 504)) {
    return true;
  }
  if (message.includes("timeout") || message.includes("timed out")) return true;
  if (message.includes("rate limit") || message.includes("too many requests")) return true;
  if (message.includes("socket hang up") || message.includes("network")) return true;
  if (message.includes("econnreset") || message.includes("econnrefused")) return true;
  if (message.includes("temporarily unavailable") || message.includes("service unavailable")) return true;
  if (message.includes("internal server error") && status >= 500) return true;
  if (status === 400 || status === 401 || status === 403 || status === 404) return false;
  if (message.includes("invalid") || message.includes("unauthorized")) return false;
  if (message.includes("not found") || message.includes("forbidden")) return false;
  return false;
}
function calculateDelay(attempt, initialDelayMs, maxDelayMs, jitterFactor) {
  const exponentialDelay = initialDelayMs * Math.pow(2, attempt - 1);
  const cappedDelay = Math.min(exponentialDelay, maxDelayMs);
  const jitter = cappedDelay * jitterFactor * (Math.random() * 2 - 1);
  return Math.max(100, Math.round(cappedDelay + jitter));
}
async function retryWithBackoff(fn, options = {}) {
  const {
    maxRetries = 3,
    initialDelayMs = 1e3,
    maxDelayMs = 15e3,
    jitterFactor = 0.3,
    stageName = "unknown",
    isRetryable = defaultIsRetryable,
    onRetry
  } = options;
  const startTime = Date.now();
  let lastError;
  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      const value = await fn();
      return {
        success: true,
        value,
        attempts: attempt,
        totalDurationMs: Date.now() - startTime,
        retried: attempt > 1
      };
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      if (attempt > maxRetries || !isRetryable(error)) {
        const reason = attempt > maxRetries ? "max retries exhausted" : "non-retryable error";
        console.error(
          `[Retry:${stageName}] Failed (${reason}) after ${attempt} attempt(s): ${lastError.message}`
        );
        return {
          success: false,
          error: lastError,
          attempts: attempt,
          totalDurationMs: Date.now() - startTime,
          retried: attempt > 1
        };
      }
      const delay = calculateDelay(attempt, initialDelayMs, maxDelayMs, jitterFactor);
      console.warn(
        `[Retry:${stageName}] Attempt ${attempt}/${maxRetries + 1} failed: ${lastError.message}. Retrying in ${delay}ms...`
      );
      if (onRetry) {
        onRetry(attempt, error, delay);
      }
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
  return {
    success: false,
    error: lastError || new Error("Unknown retry failure"),
    attempts: maxRetries + 1,
    totalDurationMs: Date.now() - startTime,
    retried: true
  };
}
async function parallelWithRetry(tasks, globalOptions) {
  return Promise.all(
    tasks.map(
      (task) => retryWithBackoff(task.fn, {
        ...globalOptions,
        ...task.options,
        stageName: task.name
      })
    )
  );
}
var init_retry_with_backoff = __esm({
  "shared/retry-with-backoff.ts"() {
  }
});
init_retry_with_backoff();
export {
  parallelWithRetry,
  retryWithBackoff
};
