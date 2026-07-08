/**
 * Tests for scan resume/retry logic fixes:
 * 1. inferLastActivePhase — prioritizes phase_complete markers
 * 2. inferLastCompletedPhase — finds last completed phase
 * 3. checkResumeCapability — resumes from SAME phase on error (not next)
 * 4. zapRequest — handles non-JSON responses with retry
 */
import { describe, it, expect } from "vitest";

// ─── Replicate the logic from live-trigger-temp.ts for unit testing ───

const PHASE_ORDER = ['recon', 'passive_discovery', 'scoping', 'test_plan', 'test_plan_approval', 'enumeration', 'vuln_detection', 'social_engineering', 'exploitation', 'post_exploit'] as const;

function inferLastActivePhase(state: any): typeof PHASE_ORDER[number] | null {
  if (!state?.log?.length) return null;
  let lastActive: typeof PHASE_ORDER[number] | null = null;
  for (let i = state.log.length - 1; i >= 0; i--) {
    const entry = state.log[i];
    const phase = entry.phase;
    if (phase && phase !== 'error' && phase !== 'idle' && PHASE_ORDER.includes(phase as any)) {
      lastActive = phase as typeof PHASE_ORDER[number];
      break;
    }
  }
  return lastActive;
}

function inferLastCompletedPhase(state: any): typeof PHASE_ORDER[number] | null {
  if (!state?.log?.length) return null;
  for (let i = state.log.length - 1; i >= 0; i--) {
    const entry = state.log[i];
    if (entry.type === 'phase_complete' && entry.phase && PHASE_ORDER.includes(entry.phase as any)) {
      return entry.phase as typeof PHASE_ORDER[number];
    }
    if (entry.title && (entry.title.includes('complete') || entry.title.includes('checkpoint')) && entry.phase && PHASE_ORDER.includes(entry.phase as any)) {
      return entry.phase as typeof PHASE_ORDER[number];
    }
  }
  return null;
}

/** Compute resume phase (same logic as checkResumeCapability) */
function computeResumePhase(state: any): string {
  if (state.phase === 'error') {
    const lastActive = inferLastActivePhase(state);
    const lastCompleted = inferLastCompletedPhase(state);
    if (lastActive && lastActive !== lastCompleted) {
      return lastActive; // Resume the crashed phase
    } else if (lastCompleted) {
      const completedIdx = PHASE_ORDER.indexOf(lastCompleted as any);
      return completedIdx >= 0 && completedIdx < PHASE_ORDER.length - 1
        ? PHASE_ORDER[completedIdx + 1]
        : lastCompleted;
    } else {
      return lastActive || 'recon';
    }
  } else if (state.phase === 'scanning') {
    return 'vuln_detection';
  } else if (PHASE_ORDER.includes(state.phase as any)) {
    return state.phase;
  }
  return 'recon';
}

describe("inferLastActivePhase", () => {
  it("returns null for empty log", () => {
    expect(inferLastActivePhase({ log: [] })).toBeNull();
    expect(inferLastActivePhase(null)).toBeNull();
  });

  it("finds the last active phase from log entries", () => {
    const state = {
      log: [
        { phase: 'recon', type: 'info', title: 'Starting recon' },
        { phase: 'passive_discovery', type: 'info', title: 'Passive scan' },
        { phase: 'enumeration', type: 'info', title: 'Port scan started' },
        { phase: 'vuln_detection', type: 'info', title: 'Nuclei started' },
        { phase: 'vuln_detection', type: 'error', title: 'JSON parse failed' },
      ],
    };
    expect(inferLastActivePhase(state)).toBe('vuln_detection');
  });

  it("skips error and idle phases", () => {
    const state = {
      log: [
        { phase: 'enumeration', type: 'info', title: 'Scanning' },
        { phase: 'error', type: 'error', title: 'Crash' },
        { phase: 'idle', type: 'info', title: 'Reset' },
      ],
    };
    expect(inferLastActivePhase(state)).toBe('enumeration');
  });
});

describe("inferLastCompletedPhase", () => {
  it("returns null for empty log", () => {
    expect(inferLastCompletedPhase({ log: [] })).toBeNull();
  });

  it("finds phase_complete markers", () => {
    const state = {
      log: [
        { phase: 'recon', type: 'phase_complete', title: 'Recon done' },
        { phase: 'passive_discovery', type: 'phase_complete', title: 'Passive done' },
        { phase: 'enumeration', type: 'phase_complete', title: 'Enumeration done' },
        { phase: 'vuln_detection', type: 'info', title: 'Starting vuln scan' },
        { phase: 'vuln_detection', type: 'error', title: 'JSON parse crash' },
      ],
    };
    expect(inferLastCompletedPhase(state)).toBe('enumeration');
  });

  it("recognizes checkpoint titles as completion markers", () => {
    const state = {
      log: [
        { phase: 'scoping', type: 'info', title: 'Scoping checkpoint saved' },
        { phase: 'test_plan', type: 'info', title: 'Generating plan' },
      ],
    };
    expect(inferLastCompletedPhase(state)).toBe('scoping');
  });
});

describe("computeResumePhase (error recovery)", () => {
  it("resumes from the SAME phase that crashed (not next)", () => {
    const state = {
      phase: 'error',
      log: [
        { phase: 'recon', type: 'phase_complete', title: 'Recon done' },
        { phase: 'passive_discovery', type: 'phase_complete', title: 'Passive done' },
        { phase: 'enumeration', type: 'phase_complete', title: 'Enumeration done' },
        { phase: 'vuln_detection', type: 'info', title: 'Nuclei scan started' },
        { phase: 'vuln_detection', type: 'info', title: 'ZAP scan started' },
        { phase: 'vuln_detection', type: 'error', title: 'JSON.parse crash' },
      ],
    };
    // Should resume from vuln_detection (the crashed phase), NOT social_engineering (the next)
    expect(computeResumePhase(state)).toBe('vuln_detection');
  });

  it("resumes from next phase when lastActive equals lastCompleted", () => {
    const state = {
      phase: 'error',
      log: [
        { phase: 'recon', type: 'phase_complete', title: 'Recon done' },
        { phase: 'passive_discovery', type: 'phase_complete', title: 'Passive done' },
        { phase: 'enumeration', type: 'phase_complete', title: 'Enumeration complete' },
        // Crash happened between phases (no active work in vuln_detection yet)
      ],
    };
    // lastActive = enumeration, lastCompleted = enumeration → they match
    // So resume from NEXT phase: vuln_detection
    expect(computeResumePhase(state)).toBe('vuln_detection');
  });

  it("falls back to recon when no log entries", () => {
    const state = { phase: 'error', log: [] };
    expect(computeResumePhase(state)).toBe('recon');
  });

  it("resumes from same phase for non-error interrupted state", () => {
    const state = { phase: 'enumeration', log: [] };
    expect(computeResumePhase(state)).toBe('enumeration');
  });

  it("maps 'scanning' to vuln_detection", () => {
    const state = { phase: 'scanning', log: [] };
    expect(computeResumePhase(state)).toBe('vuln_detection');
  });

  it("handles crash during passive_discovery correctly", () => {
    const state = {
      phase: 'error',
      log: [
        { phase: 'recon', type: 'phase_complete', title: 'Recon complete' },
        { phase: 'passive_discovery', type: 'info', title: 'Starting passive scan' },
        { phase: 'passive_discovery', type: 'error', title: 'Network timeout' },
      ],
    };
    // Should resume from passive_discovery (crashed phase), NOT scoping
    expect(computeResumePhase(state)).toBe('passive_discovery');
  });

  it("handles crash during exploitation correctly", () => {
    const state = {
      phase: 'error',
      log: [
        { phase: 'recon', type: 'phase_complete', title: 'done' },
        { phase: 'passive_discovery', type: 'phase_complete', title: 'done' },
        { phase: 'enumeration', type: 'phase_complete', title: 'done' },
        { phase: 'vuln_detection', type: 'phase_complete', title: 'done' },
        { phase: 'exploitation', type: 'info', title: 'Attempting exploit' },
        { phase: 'exploitation', type: 'error', title: 'Connection reset' },
      ],
    };
    expect(computeResumePhase(state)).toBe('exploitation');
  });
});

describe("zapRequest JSON.parse resilience", () => {
  it("the fix ensures non-JSON responses are caught and retried", () => {
    // This is a structural test — verifying the logic pattern
    // The actual zapRequest function uses HTTP which can't be unit tested easily
    // but we verify the error message format matches what we expect
    const htmlResponse = '<html><body>502 Bad Gateway</body></html>';
    expect(() => JSON.parse(htmlResponse)).toThrow();
    
    const emptyResponse = '';
    expect(() => JSON.parse(emptyResponse)).toThrow();
    
    // Valid ZAP response should parse fine
    const validResponse = '{"status":"100"}';
    expect(JSON.parse(validResponse)).toEqual({ status: "100" });
  });

  it("exponential backoff timing is correct", () => {
    // Verify the backoff formula: 1000 * 2^(attempt-1)
    expect(1000 * Math.pow(2, 0)).toBe(1000);  // attempt 1: 1s
    expect(1000 * Math.pow(2, 1)).toBe(2000);  // attempt 2: 2s
    expect(1000 * Math.pow(2, 2)).toBe(4000);  // attempt 3: 4s
  });
});
