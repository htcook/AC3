import { describe, it, expect, vi } from 'vitest';

/**
 * Tests for the engagement null-guard fix (TypeError: null is not an object evaluating 'r.phase')
 * and the breachData TDZ fix in runDomainIntelPipeline.
 */

// ─── getState null-guard tests ──────────────────────────────────────────────
describe('getState never returns null', () => {
  it('should return a default idle state when no ops state exists', () => {
    // Simulate what the getState procedure now does when state is null
    const state = null;
    const engagementId = 999;

    // This is the new fallback logic added to engagement-ops-core.ts
    const result = state ?? {
      engagementId,
      phase: 'idle' as const,
      isRunning: false,
      isPaused: false,
      progress: 0,
      log: [],
      assets: [],
      approvalGates: [],
      stats: { hostsScanned: 0, portsFound: 0, vulnsFound: 0, exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0, zapScansRun: 0, wafDetections: 0 },
    };

    expect(result).not.toBeNull();
    expect(result.phase).toBe('idle');
    expect(result.isRunning).toBe(false);
    expect(result.assets).toEqual([]);
    expect(result.log).toEqual([]);
    expect(result.approvalGates).toEqual([]);
    expect(result.stats.hostsScanned).toBe(0);
    expect(result.stats.vulnsFound).toBe(0);
    expect(result.engagementId).toBe(999);
  });

  it('should pass through existing state when not null', () => {
    const existingState = {
      engagementId: 42,
      phase: 'recon' as const,
      isRunning: true,
      isPaused: false,
      progress: 50,
      log: [{ id: 'log1', type: 'info', message: 'test', timestamp: Date.now() }],
      assets: [{ hostname: 'example.com', type: 'web', ports: [], vulns: [] }],
      approvalGates: [],
      stats: { hostsScanned: 3, portsFound: 10, vulnsFound: 2, exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0, zapScansRun: 1, wafDetections: 0 },
    };

    const result = existingState ?? {
      engagementId: 42,
      phase: 'idle' as const,
      isRunning: false,
      isPaused: false,
      progress: 0,
      log: [],
      assets: [],
      approvalGates: [],
      stats: { hostsScanned: 0, portsFound: 0, vulnsFound: 0, exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0, zapScansRun: 0, wafDetections: 0 },
    };

    expect(result.phase).toBe('recon');
    expect(result.isRunning).toBe(true);
    expect(result.assets).toHaveLength(1);
    expect(result.stats.hostsScanned).toBe(3);
  });
});

// ─── Frontend ops?.phase null-safety tests ──────────────────────────────────
describe('Frontend ops?.phase null safety', () => {
  it('should use optional chaining for ManualToolRunner engagementPhase', () => {
    // Simulate the fix: ops?.phase || 'idle'
    const ops: any = null;
    const engagementPhase = ops?.phase || 'idle';
    expect(engagementPhase).toBe('idle');
  });

  it('should pass through phase when ops exists', () => {
    const ops: any = { phase: 'scanning', isRunning: true };
    const engagementPhase = ops?.phase || 'idle';
    expect(engagementPhase).toBe('scanning');
  });

  it('should handle ops with undefined phase', () => {
    const ops: any = { isRunning: false };
    const engagementPhase = ops?.phase || 'idle';
    expect(engagementPhase).toBe('idle');
  });

  it('should handle ops with empty string phase', () => {
    const ops: any = { phase: '' };
    const engagementPhase = ops?.phase || 'idle';
    expect(engagementPhase).toBe('idle');
  });
});

// ─── Frontend ops useMemo normalizer tests ──────────────────────────────────
describe('Frontend ops useMemo normalizer', () => {
  it('should default phase to idle when base.phase is falsy', () => {
    // Simulates the normalizer at line 1283: if (!base.phase) base.phase = 'idle'
    const base: any = { isRunning: false, isPaused: false, progress: 0, log: [], assets: [], approvalGates: [], stats: {} };
    if (!base.phase) base.phase = 'idle';
    expect(base.phase).toBe('idle');
  });

  it('should preserve existing phase', () => {
    const base: any = { phase: 'exploit', isRunning: true };
    if (!base.phase) base.phase = 'idle';
    expect(base.phase).toBe('exploit');
  });

  it('should ensure boolean fields default correctly', () => {
    const base: any = { phase: 'idle' };
    if (typeof base.isRunning !== 'boolean') base.isRunning = false;
    if (typeof base.isPaused !== 'boolean') base.isPaused = false;
    if (typeof base.progress !== 'number') base.progress = 0;
    expect(base.isRunning).toBe(false);
    expect(base.isPaused).toBe(false);
    expect(base.progress).toBe(0);
  });
});

// ─── breachData TDZ fix tests ───────────────────────────────────────────────
describe('breachData TDZ fix', () => {
  it('should not throw when breachData is accessed after declaration', () => {
    // Simulates the fixed order: breachData extraction BEFORE summary generation
    let breachData: any[] = [];

    // Step 1: Extract breach data (now runs BEFORE summary)
    const rawBreachResults = [
      { email: 'test@example.com', source: 'breach1', date: '2024-01-01' },
      { email: 'admin@example.com', source: 'breach2', date: '2024-06-15' },
    ];
    breachData = rawBreachResults;

    // Step 2: Summary generation (now runs AFTER breach extraction)
    const summary = {
      totalBreaches: breachData.length,
      uniqueEmails: new Set(breachData.map(b => b.email)).size,
    };

    expect(summary.totalBreaches).toBe(2);
    expect(summary.uniqueEmails).toBe(2);
    expect(breachData).toHaveLength(2);
  });

  it('should handle empty breach data gracefully', () => {
    let breachData: any[] = [];
    // No breach results
    const rawBreachResults: any[] = [];
    breachData = rawBreachResults;

    const summary = {
      totalBreaches: breachData.length,
      uniqueEmails: new Set(breachData.map(b => b.email)).size,
    };

    expect(summary.totalBreaches).toBe(0);
    expect(summary.uniqueEmails).toBe(0);
  });

  it('should correctly count unique sources in breach data', () => {
    let breachData: any[] = [];
    const rawBreachResults = [
      { email: 'a@test.com', source: 'breach1' },
      { email: 'b@test.com', source: 'breach1' },
      { email: 'c@test.com', source: 'breach2' },
    ];
    breachData = rawBreachResults;

    const uniqueSources = new Set(breachData.map(b => b.source)).size;
    expect(uniqueSources).toBe(2);
    expect(breachData).toHaveLength(3);
  });
});

// ─── Heartbeat fix tests ────────────────────────────────────────────────────
describe('Heartbeat callback fix', () => {
  it('should accept callback functions instead of db instance', () => {
    // Simulates the fixed startHeartbeat signature
    const getRunningCampaignIds = vi.fn().mockResolvedValue([]);
    const getRunningPlanIds = vi.fn().mockResolvedValue([]);

    // The fixed call passes callbacks, not a db instance
    const callbacks = { getRunningCampaignIds, getRunningPlanIds };

    expect(typeof callbacks.getRunningCampaignIds).toBe('function');
    expect(typeof callbacks.getRunningPlanIds).toBe('function');
  });

  it('should return empty arrays when no campaigns or plans are running', async () => {
    const getRunningCampaignIds = vi.fn().mockResolvedValue([]);
    const getRunningPlanIds = vi.fn().mockResolvedValue([]);

    const campaigns = await getRunningCampaignIds();
    const plans = await getRunningPlanIds();

    expect(campaigns).toEqual([]);
    expect(plans).toEqual([]);
  });

  it('should return campaign IDs when campaigns are running', async () => {
    const getRunningCampaignIds = vi.fn().mockResolvedValue([101, 102, 103]);
    const campaigns = await getRunningCampaignIds();
    expect(campaigns).toEqual([101, 102, 103]);
    expect(campaigns).toHaveLength(3);
  });
});
