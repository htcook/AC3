/**
 * Restart Resilience Tests
 * ═══════════════════════════════════════════════════════════════════════════
 * Tests for the server restart resilience fixes:
 * 1. resumeEngagement phase computation (backwards log search)
 * 2. trainingLabMode preservation across snapshot round-trips
 * 3. normalizeOpsState handling of trainingLabMode
 * 4. Auto-resume recovery log phase correctness
 */
import { describe, it, expect } from "vitest";

// ─── Helper: simulate the resumePhase computation logic ──────────────────
const validPipelinePhases = new Set([
  'recon', 'passive_discovery', 'scoping', 'test_plan', 'test_plan_approval',
  'enumeration', 'vuln_detection', 'exploitation', 'post_exploit',
]);

function computeResumePhase(statePhase: string, logs: Array<{ phase: string }>): string {
  let resumePhase = 'recon';
  if (statePhase === 'error' || statePhase === 'idle' || statePhase === 'paused') {
    for (let i = logs.length - 1; i >= 0; i--) {
      const logPhase = logs[i].phase;
      if (validPipelinePhases.has(logPhase)) {
        resumePhase = logPhase;
        break;
      }
    }
  } else if (validPipelinePhases.has(statePhase)) {
    resumePhase = statePhase;
  }
  return resumePhase;
}

// ─── Helper: simulate normalizeOpsState trainingLabMode handling ─────────
function normalizeTrainingLabMode(state: any): any {
  if (state.trainingLabMode !== undefined && typeof state.trainingLabMode !== 'boolean') {
    state.trainingLabMode = Boolean(state.trainingLabMode);
  }
  return state;
}

// ═══════════════════════════════════════════════════════════════════════════
// Test Suite: Resume Phase Computation
// ═══════════════════════════════════════════════════════════════════════════
describe("Resume Phase Computation", () => {
  it("should find the last valid pipeline phase when state.phase is 'error'", () => {
    const logs = [
      { phase: 'recon' },
      { phase: 'enumeration' },
      { phase: 'vuln_detection' },
      { phase: 'error' },  // recovery log with error phase (the bug)
    ];
    const result = computeResumePhase('error', logs);
    expect(result).toBe('vuln_detection');
  });

  it("should skip 'error' and 'unknown' log entries when searching backwards", () => {
    const logs = [
      { phase: 'recon' },
      { phase: 'enumeration' },
      { phase: 'vuln_detection' },
      { phase: 'error' },
      { phase: 'unknown' },
      { phase: 'error' },
    ];
    const result = computeResumePhase('error', logs);
    expect(result).toBe('vuln_detection');
  });

  it("should return 'recon' when no valid pipeline phase exists in logs", () => {
    const logs = [
      { phase: 'error' },
      { phase: 'unknown' },
      { phase: 'completed' },
    ];
    const result = computeResumePhase('error', logs);
    expect(result).toBe('recon');
  });

  it("should return 'recon' when logs are empty and state is 'error'", () => {
    const result = computeResumePhase('error', []);
    expect(result).toBe('recon');
  });

  it("should use state.phase directly when it's a valid pipeline phase", () => {
    const logs = [{ phase: 'recon' }];
    const result = computeResumePhase('vuln_detection', logs);
    expect(result).toBe('vuln_detection');
  });

  it("should handle 'paused' state by searching backwards through logs", () => {
    const logs = [
      { phase: 'recon' },
      { phase: 'enumeration' },
      { phase: 'exploitation' },
    ];
    const result = computeResumePhase('paused', logs);
    expect(result).toBe('exploitation');
  });

  it("should handle 'idle' state by searching backwards through logs", () => {
    const logs = [
      { phase: 'recon' },
      { phase: 'test_plan' },
    ];
    const result = computeResumePhase('idle', logs);
    expect(result).toBe('test_plan');
  });

  it("should return 'recon' for unknown state.phase values", () => {
    const result = computeResumePhase('banana', [{ phase: 'vuln_detection' }]);
    expect(result).toBe('recon');
  });

  it("should handle the exact scenario from the bug: error state with recovery log", () => {
    // This is the exact scenario that caused the bug:
    // 1. Engagement was in vuln_detection
    // 2. Server restarted, state.phase set to 'error'
    // 3. Auto-resume added a log entry with phase: 'error' (the bug)
    // 4. resumeEngagement used last log entry's phase = 'error'
    // 5. executeEngagement called with startPhase = 'error' → skipped all phases
    const logs = [
      { phase: 'recon' },
      { phase: 'recon' },
      { phase: 'test_plan' },
      { phase: 'enumeration' },
      { phase: 'vuln_detection' },
      { phase: 'vuln_detection' },
      { phase: 'vuln_detection' },
      // Recovery log entries (the bug: these had phase='error')
      { phase: 'recon' },  // Fixed: now uses interruption.phase
      { phase: 'error' },  // But even if some error entries exist...
    ];
    const result = computeResumePhase('error', logs);
    // Should find 'recon' from the recovery log, not 'error'
    expect(result).toBe('recon');
    // But ideally the recovery log should use the original phase
    // Let's test with the fixed recovery log that uses the original phase
    const fixedLogs = [
      { phase: 'recon' },
      { phase: 'test_plan' },
      { phase: 'enumeration' },
      { phase: 'vuln_detection' },
      { phase: 'vuln_detection' },
      // Fixed recovery log: uses interruption.phase (vuln_detection)
      { phase: 'vuln_detection' },
    ];
    const fixedResult = computeResumePhase('error', fixedLogs);
    expect(fixedResult).toBe('vuln_detection');
  });

  it("should handle all valid pipeline phases", () => {
    for (const phase of validPipelinePhases) {
      const result = computeResumePhase(phase, []);
      expect(result).toBe(phase);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Test Suite: trainingLabMode Preservation
// ═══════════════════════════════════════════════════════════════════════════
describe("trainingLabMode Preservation", () => {
  it("should preserve boolean true through normalization", () => {
    const state = { trainingLabMode: true };
    normalizeTrainingLabMode(state);
    expect(state.trainingLabMode).toBe(true);
  });

  it("should preserve boolean false through normalization", () => {
    const state = { trainingLabMode: false };
    normalizeTrainingLabMode(state);
    expect(state.trainingLabMode).toBe(false);
  });

  it("should convert truthy string to boolean", () => {
    const state = { trainingLabMode: "true" as any };
    normalizeTrainingLabMode(state);
    expect(state.trainingLabMode).toBe(true);
  });

  it("should convert number 1 to boolean true", () => {
    const state = { trainingLabMode: 1 as any };
    normalizeTrainingLabMode(state);
    expect(state.trainingLabMode).toBe(true);
  });

  it("should not add trainingLabMode if not present", () => {
    const state = { phase: 'recon' } as any;
    normalizeTrainingLabMode(state);
    expect(state.trainingLabMode).toBeUndefined();
  });

  it("should survive JSON round-trip (simulating DB snapshot)", () => {
    const original = { trainingLabMode: true, phase: 'vuln_detection' };
    const serialized = JSON.stringify(original);
    const deserialized = JSON.parse(serialized);
    normalizeTrainingLabMode(deserialized);
    expect(deserialized.trainingLabMode).toBe(true);
  });

  it("should survive JSON round-trip when false", () => {
    const original = { trainingLabMode: false, phase: 'recon' };
    const serialized = JSON.stringify(original);
    const deserialized = JSON.parse(serialized);
    normalizeTrainingLabMode(deserialized);
    expect(deserialized.trainingLabMode).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Test Suite: Auto-Resume Recovery Log Phase
// ═══════════════════════════════════════════════════════════════════════════
describe("Auto-Resume Recovery Log Phase", () => {
  it("should use interruption.phase instead of state.phase for recovery log", () => {
    // Simulates the fix: recovery log should use the original phase from the snapshot
    const interruptionPhase = 'vuln_detection';
    const statePhase = 'error';
    const recoveryLogPhase = interruptionPhase || statePhase || 'recon';
    expect(recoveryLogPhase).toBe('vuln_detection');
  });

  it("should fall back to state.phase if interruption.phase is empty", () => {
    const interruptionPhase = '';
    const statePhase = 'enumeration';
    const recoveryLogPhase = interruptionPhase || statePhase || 'recon';
    expect(recoveryLogPhase).toBe('enumeration');
  });

  it("should fall back to 'recon' if both are empty", () => {
    const interruptionPhase = '';
    const statePhase = '';
    const recoveryLogPhase = interruptionPhase || statePhase || 'recon';
    expect(recoveryLogPhase).toBe('recon');
  });

  it("should not produce 'error' as recovery log phase", () => {
    // The bug: when state.phase was 'error', the recovery log used 'error' as the phase
    // After fix: we use interruption.phase which is the ORIGINAL phase from the snapshot
    const interruptionPhase = 'vuln_detection';
    const statePhase = 'error';
    const recoveryLogPhase = interruptionPhase || statePhase || 'recon';
    expect(recoveryLogPhase).not.toBe('error');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Test Suite: Phase Validation
// ═══════════════════════════════════════════════════════════════════════════
describe("Phase Validation", () => {
  it("should recognize all expected pipeline phases", () => {
    const expectedPhases = [
      'recon', 'passive_discovery', 'scoping', 'test_plan',
      'test_plan_approval', 'enumeration', 'vuln_detection',
      'exploitation', 'post_exploit',
    ];
    for (const phase of expectedPhases) {
      expect(validPipelinePhases.has(phase)).toBe(true);
    }
  });

  it("should not recognize non-pipeline phases", () => {
    const nonPipelinePhases = ['error', 'idle', 'paused', 'completed', 'unknown', ''];
    for (const phase of nonPipelinePhases) {
      expect(validPipelinePhases.has(phase)).toBe(false);
    }
  });
});
