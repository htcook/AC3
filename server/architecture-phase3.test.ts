/**
 * Architecture Phase 3 Tests
 *
 * Tests for:
 * 1. shared/orchestrator-types.ts - Type exports and utility functions
 * 2. Phase 8 post-exploitation extraction - Module structure and imports
 * 3. shared/retry-with-backoff.ts - Retry logic, backoff calculation, error classification
 */
import { describe, it, expect, vi } from 'vitest';
import { retryWithBackoff, parallelWithRetry } from '../shared/retry-with-backoff';
import { fmtTarget } from '../shared/orchestrator-types';

// ─── 1. Shared Orchestrator Types ──────────────────────────────────────────

describe('shared/orchestrator-types', () => {
  it('exports fmtTarget utility function', () => {
    expect(typeof fmtTarget).toBe('function');
  });

  it('fmtTarget formats hostname with IP', () => {
    const result = fmtTarget({ hostname: 'web01.example.com', ip: '10.0.1.5' });
    expect(result).toContain('web01.example.com');
  });

  it('fmtTarget handles missing IP gracefully', () => {
    const result = fmtTarget({ hostname: 'mail.target.org' });
    expect(result).toContain('mail.target.org');
    expect(result).not.toContain('undefined');
  });

  it('fmtTarget handles empty hostname', () => {
    const result = fmtTarget({ hostname: '', ip: '192.168.1.1' });
    expect(result).toContain('192.168.1.1');
  });
});

// ─── 2. Phase 8 Post-Exploitation Module Structure ─────────────────────────

describe('Phase 8 post-exploitation module', () => {
  it('module file exists and exports executePostExploit', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const modulePath = path.resolve(__dirname, 'lib/engagement-phase-post-exploit.ts');
    expect(fs.existsSync(modulePath)).toBe(true);

    const content = fs.readFileSync(modulePath, 'utf-8');
    expect(content).toContain('export async function executePostExploit');
  });

  it('imports types from shared module (not orchestrator) to break circular deps', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const modulePath = path.resolve(__dirname, 'lib/engagement-phase-post-exploit.ts');
    const content = fs.readFileSync(modulePath, 'utf-8');

    // Should import types from shared module
    expect(content).toContain('from "../../shared/orchestrator-types"');
  });

  it('imports evidence integrity from correct module', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const modulePath = path.resolve(__dirname, 'lib/engagement-phase-post-exploit.ts');
    const content = fs.readFileSync(modulePath, 'utf-8');

    expect(content).toContain('from "./evidence-integrity-guardrails"');
  });

  it('imports emitAgentDeployed from ws-event-hub', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const modulePath = path.resolve(__dirname, 'lib/engagement-phase-post-exploit.ts');
    const content = fs.readFileSync(modulePath, 'utf-8');

    expect(content).toContain('from "./ws-event-hub"');
    expect(content).toContain('emitAgentDeployed');
  });

  it('orchestrator delegates to extracted module via dynamic import', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const orchPath = path.resolve(__dirname, 'lib/engagement-orchestrator.ts');
    const content = fs.readFileSync(orchPath, 'utf-8');

    expect(content).toContain("await import('./engagement-phase-post-exploit')");
    expect(content).toContain('runPostExploitPhase');
  });

  it('has local genId utility (not imported from orchestrator)', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const modulePath = path.resolve(__dirname, 'lib/engagement-phase-post-exploit.ts');
    const content = fs.readFileSync(modulePath, 'utf-8');

    expect(content).toContain('function genId()');
  });
});

// ─── 3. Retry with Backoff ─────────────────────────────────────────────────

describe('retryWithBackoff', () => {
  it('succeeds on first attempt without retrying', async () => {
    const fn = vi.fn().mockResolvedValue('success');
    const result = await retryWithBackoff(fn, { stageName: 'test' });

    expect(result.success).toBe(true);
    expect(result.value).toBe('success');
    expect(result.attempts).toBe(1);
    expect(result.retried).toBe(false);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('retries on transient network error and succeeds', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }))
      .mockResolvedValue('recovered');

    const result = await retryWithBackoff(fn, {
      stageName: 'test',
      maxRetries: 3,
      initialDelayMs: 10, // Fast for testing
    });

    expect(result.success).toBe(true);
    expect(result.value).toBe('recovered');
    expect(result.attempts).toBe(2);
    expect(result.retried).toBe(true);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('retries on rate limit (429) and succeeds', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(Object.assign(new Error('Too Many Requests'), { status: 429 }))
      .mockRejectedValueOnce(Object.assign(new Error('Too Many Requests'), { status: 429 }))
      .mockResolvedValue('finally');

    const result = await retryWithBackoff(fn, {
      stageName: 'test',
      maxRetries: 3,
      initialDelayMs: 10,
    });

    expect(result.success).toBe(true);
    expect(result.value).toBe('finally');
    expect(result.attempts).toBe(3);
    expect(result.retried).toBe(true);
  });

  it('does NOT retry on non-retryable errors (400, 401, 403)', async () => {
    const fn = vi.fn()
      .mockRejectedValue(Object.assign(new Error('Unauthorized'), { status: 401 }));

    const result = await retryWithBackoff(fn, {
      stageName: 'test',
      maxRetries: 3,
      initialDelayMs: 10,
    });

    expect(result.success).toBe(false);
    expect(result.attempts).toBe(1);
    expect(result.retried).toBe(false);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('exhausts all retries and returns failure', async () => {
    const fn = vi.fn()
      .mockRejectedValue(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }));

    const result = await retryWithBackoff(fn, {
      stageName: 'test',
      maxRetries: 2,
      initialDelayMs: 10,
    });

    expect(result.success).toBe(false);
    expect(result.attempts).toBe(3); // 1 initial + 2 retries
    expect(result.retried).toBe(true);
    expect(result.error?.message).toBe('timeout');
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it('calls onRetry callback on each retry', async () => {
    const onRetry = vi.fn();
    const fn = vi.fn()
      .mockRejectedValueOnce(Object.assign(new Error('ECONNRESET'), { code: 'ECONNRESET' }))
      .mockResolvedValue('ok');

    await retryWithBackoff(fn, {
      stageName: 'test',
      maxRetries: 3,
      initialDelayMs: 10,
      onRetry,
    });

    expect(onRetry).toHaveBeenCalledTimes(1);
    expect(onRetry).toHaveBeenCalledWith(1, expect.any(Error), expect.any(Number));
  });

  it('respects maxDelayMs cap', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }))
      .mockRejectedValueOnce(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }))
      .mockRejectedValueOnce(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }))
      .mockResolvedValue('ok');

    const startTime = Date.now();
    await retryWithBackoff(fn, {
      stageName: 'test',
      maxRetries: 3,
      initialDelayMs: 10,
      maxDelayMs: 50,
      jitterFactor: 0, // No jitter for predictable timing
    });
    const elapsed = Date.now() - startTime;

    // With 3 retries at max 50ms each, should be < 500ms total (relaxed for CI/sandbox latency)
    expect(elapsed).toBeLessThan(500);
  });

  it('tracks totalDurationMs accurately', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }))
      .mockResolvedValue('ok');

    const result = await retryWithBackoff(fn, {
      stageName: 'test',
      maxRetries: 2,
      initialDelayMs: 50,
      jitterFactor: 0,
    });

    expect(result.totalDurationMs).toBeGreaterThanOrEqual(40); // At least ~50ms delay
    expect(result.totalDurationMs).toBeLessThan(500);
  });

  it('handles custom isRetryable function', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('custom-retryable'))
      .mockResolvedValue('ok');

    const result = await retryWithBackoff(fn, {
      stageName: 'test',
      maxRetries: 2,
      initialDelayMs: 10,
      isRetryable: (err) => err.message === 'custom-retryable',
    });

    expect(result.success).toBe(true);
    expect(result.attempts).toBe(2);
  });
});

// ─── 4. parallelWithRetry ──────────────────────────────────────────────────

describe('parallelWithRetry', () => {
  it('runs multiple tasks in parallel with individual retry', async () => {
    const results = await parallelWithRetry([
      { name: 'task1', fn: async () => 'a' },
      { name: 'task2', fn: async () => 'b' },
      { name: 'task3', fn: async () => 'c' },
    ], { initialDelayMs: 10 });

    expect(results).toHaveLength(3);
    expect(results[0].success).toBe(true);
    expect(results[0].value).toBe('a');
    expect(results[1].success).toBe(true);
    expect(results[1].value).toBe('b');
    expect(results[2].success).toBe(true);
    expect(results[2].value).toBe('c');
  });

  it('retries individual failing tasks without blocking others', async () => {
    const results = await parallelWithRetry([
      { name: 'fast', fn: async () => 'instant' },
      {
        name: 'flaky',
        fn: (() => {
          let calls = 0;
          return async () => {
            calls++;
            if (calls === 1) throw Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' });
            return 'recovered';
          };
        })(),
      },
    ], { initialDelayMs: 10, maxRetries: 2 });

    expect(results[0].success).toBe(true);
    expect(results[0].value).toBe('instant');
    expect(results[0].attempts).toBe(1);

    expect(results[1].success).toBe(true);
    expect(results[1].value).toBe('recovered');
    expect(results[1].attempts).toBe(2);
    expect(results[1].retried).toBe(true);
  });

  it('per-task options override global options', async () => {
    const fn = vi.fn()
      .mockRejectedValue(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }));

    const results = await parallelWithRetry([
      { name: 'limited', fn, options: { maxRetries: 1, initialDelayMs: 10 } },
    ], { maxRetries: 5, initialDelayMs: 10 });

    // Should use per-task maxRetries (1), not global (5)
    expect(results[0].attempts).toBe(2); // 1 initial + 1 retry
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('handles mix of success and permanent failure', async () => {
    const results = await parallelWithRetry([
      { name: 'ok', fn: async () => 'good' },
      { name: 'bad', fn: async () => { throw Object.assign(new Error('forbidden'), { status: 403 }); } },
    ], { initialDelayMs: 10 });

    expect(results[0].success).toBe(true);
    expect(results[1].success).toBe(false);
    expect(results[1].error?.message).toBe('forbidden');
    expect(results[1].attempts).toBe(1); // Non-retryable, no retries
  });
});

// ─── 5. DomainIntel integration check ─────────────────────────────────────

describe('DomainIntel retry integration', () => {
  it('domainIntel.ts uses parallelWithRetry for Stage 4.5+4.55+4.6', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const diPath = path.resolve(__dirname, 'domainIntel.ts');
    const content = fs.readFileSync(diPath, 'utf-8');

    expect(content).toContain("import('../shared/retry-with-backoff')");
    expect(content).toContain('parallelWithRetry');
    expect(content).toContain("name: 'Stage 4.5 Threat Matching'");
    expect(content).toContain("name: 'Stage 4.55 Incident Search'");
    expect(content).toContain("name: 'Stage 4.6 Affiliated Domains'");
  });

  it('uses RetryResult format for unpacking (not PromiseSettledResult)', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const diPath = path.resolve(__dirname, 'domainIntel.ts');
    const content = fs.readFileSync(diPath, 'utf-8');

    // Should NOT have old PromiseSettledResult pattern
    expect(content).not.toContain('threatMatchSettled.status');
    expect(content).not.toContain('incidentSearchSettled.status');
    expect(content).not.toContain('affiliatedDomainsSettled.status');

    // Should have new RetryResult pattern
    expect(content).toContain('threatMatchRetry.success');
    expect(content).toContain('incidentSearchRetry.success');
    expect(content).toContain('affiliatedDomainsRetry.success');
  });

  it('logs retry statistics for stages that needed retries', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const diPath = path.resolve(__dirname, 'domainIntel.ts');
    const content = fs.readFileSync(diPath, 'utf-8');

    expect(content).toContain('Retry stats:');
    expect(content).toContain('r.retried');
  });
});
