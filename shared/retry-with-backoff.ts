/**
 * Structured Retry with Exponential Backoff
 *
 * Provides resilient execution for I/O-bound pipeline stages that may
 * experience transient failures (network timeouts, rate limits, API errors).
 *
 * Features:
 * - Exponential backoff with configurable jitter
 * - Retryable error classification (network vs logic errors)
 * - Per-attempt logging for observability
 * - Configurable max retries and initial delay
 */

export interface RetryOptions {
  /** Maximum number of retry attempts (default: 3) */
  maxRetries?: number;
  /** Initial delay in milliseconds before first retry (default: 1000) */
  initialDelayMs?: number;
  /** Maximum delay cap in milliseconds (default: 15000) */
  maxDelayMs?: number;
  /** Jitter factor 0-1 to randomize delay (default: 0.3) */
  jitterFactor?: number;
  /** Stage name for logging (default: 'unknown') */
  stageName?: string;
  /** Custom function to determine if an error is retryable (default: built-in classifier) */
  isRetryable?: (error: any) => boolean;
  /** Optional callback on each retry attempt */
  onRetry?: (attempt: number, error: any, nextDelayMs: number) => void;
}

export interface RetryResult<T> {
  /** Whether the operation ultimately succeeded */
  success: boolean;
  /** The result value if successful */
  value?: T;
  /** The final error if all retries exhausted */
  error?: Error;
  /** Total number of attempts made (1 = no retries needed) */
  attempts: number;
  /** Total time spent including retries in milliseconds */
  totalDurationMs: number;
  /** Whether any retries were attempted */
  retried: boolean;
}

/**
 * Default retryable error classifier.
 * Returns true for transient/network errors that are likely to succeed on retry.
 */
function defaultIsRetryable(error: any): boolean {
  if (!error) return false;
  const message = (error.message || '').toLowerCase();
  const code = error.code || '';

  // Network errors
  if (['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'EPIPE', 'EHOSTUNREACH'].includes(code)) {
    return true;
  }

  // HTTP status-based (rate limit, server errors)
  const status = error.status || error.statusCode || error.response?.status;
  if (status && (status === 429 || status === 502 || status === 503 || status === 504)) {
    return true;
  }

  // Common transient error messages
  if (message.includes('timeout') || message.includes('timed out')) return true;
  if (message.includes('rate limit') || message.includes('too many requests')) return true;
  if (message.includes('socket hang up') || message.includes('network')) return true;
  if (message.includes('econnreset') || message.includes('econnrefused')) return true;
  if (message.includes('temporarily unavailable') || message.includes('service unavailable')) return true;
  if (message.includes('internal server error') && status >= 500) return true;

  // NOT retryable: validation errors, auth errors, not found, logic errors
  if (status === 400 || status === 401 || status === 403 || status === 404) return false;
  if (message.includes('invalid') || message.includes('unauthorized')) return false;
  if (message.includes('not found') || message.includes('forbidden')) return false;

  // Default: don't retry unknown errors
  return false;
}

/**
 * Calculate exponential backoff delay with jitter.
 */
function calculateDelay(attempt: number, initialDelayMs: number, maxDelayMs: number, jitterFactor: number): number {
  // Exponential: initialDelay * 2^(attempt-1)
  const exponentialDelay = initialDelayMs * Math.pow(2, attempt - 1);
  const cappedDelay = Math.min(exponentialDelay, maxDelayMs);

  // Add jitter: delay * (1 ± jitterFactor * random)
  const jitter = cappedDelay * jitterFactor * (Math.random() * 2 - 1);
  return Math.max(100, Math.round(cappedDelay + jitter));
}

/**
 * Execute an async function with structured retry and exponential backoff.
 *
 * @example
 * ```ts
 * const result = await retryWithBackoff(
 *   () => fetchThreatIntel(domain),
 *   { stageName: 'Stage 4.5 Threat Matching', maxRetries: 3 }
 * );
 * if (result.success) {
 *   console.log(`Got result in ${result.attempts} attempt(s)`);
 * } else {
 *   console.error(`Failed after ${result.attempts} attempts: ${result.error?.message}`);
 * }
 * ```
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<RetryResult<T>> {
  const {
    maxRetries = 3,
    initialDelayMs = 1000,
    maxDelayMs = 15000,
    jitterFactor = 0.3,
    stageName = 'unknown',
    isRetryable = defaultIsRetryable,
    onRetry,
  } = options;

  const startTime = Date.now();
  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      const value = await fn();
      return {
        success: true,
        value,
        attempts: attempt,
        totalDurationMs: Date.now() - startTime,
        retried: attempt > 1,
      };
    } catch (error: any) {
      lastError = error instanceof Error ? error : new Error(String(error));

      // If this was the last attempt or error is not retryable, fail immediately
      if (attempt > maxRetries || !isRetryable(error)) {
        const reason = attempt > maxRetries ? 'max retries exhausted' : 'non-retryable error';
        console.error(
          `[Retry:${stageName}] Failed (${reason}) after ${attempt} attempt(s): ${lastError.message}`
        );
        return {
          success: false,
          error: lastError,
          attempts: attempt,
          totalDurationMs: Date.now() - startTime,
          retried: attempt > 1,
        };
      }

      // Calculate backoff delay
      const delay = calculateDelay(attempt, initialDelayMs, maxDelayMs, jitterFactor);
      console.warn(
        `[Retry:${stageName}] Attempt ${attempt}/${maxRetries + 1} failed: ${lastError.message}. ` +
        `Retrying in ${delay}ms...`
      );

      if (onRetry) {
        onRetry(attempt, error, delay);
      }

      // Wait before retrying
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  // Should not reach here, but safety net
  return {
    success: false,
    error: lastError || new Error('Unknown retry failure'),
    attempts: maxRetries + 1,
    totalDurationMs: Date.now() - startTime,
    retried: true,
  };
}

/**
 * Convenience wrapper for Promise.allSettled with retry on each item.
 * Replaces bare Promise.allSettled for parallelized pipeline stages.
 *
 * @example
 * ```ts
 * const results = await parallelWithRetry([
 *   { name: 'Stage 4.5', fn: () => runThreatMatching() },
 *   { name: 'Stage 4.55', fn: () => runIncidentSearch() },
 *   { name: 'Stage 4.6', fn: () => runAffiliatedDomains() },
 * ]);
 * ```
 */
export async function parallelWithRetry<T>(
  tasks: Array<{ name: string; fn: () => Promise<T>; options?: Omit<RetryOptions, 'stageName'> }>,
  globalOptions?: Omit<RetryOptions, 'stageName'>
): Promise<RetryResult<T>[]> {
  return Promise.all(
    tasks.map(task =>
      retryWithBackoff(task.fn, {
        ...globalOptions,
        ...task.options,
        stageName: task.name,
      })
    )
  );
}
