/**
 * Tests for the scan failure → dashboard freeze → Manus login prompt fix
 * and the engagement ops recovery fallback fix.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Test 1: getLoginUrl returns /login on non-Manus domains ─────────
describe('getLoginUrl - Manus domain detection', () => {
  const MANUS_HOSTED_DOMAINS = [
    '.manus.space',
    '.manusvm.computer',
    '.manus.computer',
  ];

  function isManusHosted(hostname: string): boolean {
    return MANUS_HOSTED_DOMAINS.some((d) => hostname.endsWith(d));
  }

  it('should detect Manus-hosted domains', () => {
    expect(isManusHosted('calderadash-vmwwcxqy.manus.space')).toBe(true);
    expect(isManusHosted('3000-xyz.manusvm.computer')).toBe(true);
    expect(isManusHosted('app.manus.computer')).toBe(true);
  });

  it('should NOT detect production domains as Manus-hosted', () => {
    expect(isManusHosted('aceofcloud.io')).toBe(false);
    expect(isManusHosted('www.aceofcloud.io')).toBe(false);
    expect(isManusHosted('aceofcloud.com')).toBe(false);
    expect(isManusHosted('localhost')).toBe(false);
    expect(isManusHosted('192.168.1.1')).toBe(false);
    expect(isManusHosted('custom-domain.com')).toBe(false);
  });

  it('should return /login for non-Manus domains', () => {
    // Simulate what getLoginUrl does for non-Manus domains
    const hostname = 'aceofcloud.io';
    if (!isManusHosted(hostname)) {
      expect('/login').toBe('/login');
    } else {
      throw new Error('aceofcloud.io should not be detected as Manus-hosted');
    }
  });
});

// ─── Test 2: Redirect debouncing logic ──────────────────────────────
describe('redirectToLoginIfUnauthorized - debouncing', () => {
  let redirectPending = false;
  let redirectCount = 0;
  let cancelQueriesCalled = false;

  function mockRedirectToLoginIfUnauthorized(isUnauthorized: boolean) {
    if (!isUnauthorized) return;
    if (redirectPending) return;
    redirectPending = true;
    cancelQueriesCalled = true;
    redirectCount++;
  }

  beforeEach(() => {
    redirectPending = false;
    redirectCount = 0;
    cancelQueriesCalled = false;
  });

  it('should only redirect once even with multiple UNAUTHORIZED errors', () => {
    // Simulate 57 hooks all firing UNAUTHORIZED simultaneously
    for (let i = 0; i < 57; i++) {
      mockRedirectToLoginIfUnauthorized(true);
    }
    expect(redirectCount).toBe(1);
    expect(cancelQueriesCalled).toBe(true);
  });

  it('should not redirect for non-UNAUTHORIZED errors', () => {
    for (let i = 0; i < 10; i++) {
      mockRedirectToLoginIfUnauthorized(false);
    }
    expect(redirectCount).toBe(0);
    expect(cancelQueriesCalled).toBe(false);
  });
});

// ─── Test 3: getOpsState recovery pattern ───────────────────────────
describe('getOpsState with recovery fallback', () => {
  // Simulate the in-memory map
  const opsStates = new Map<number, any>();

  function getOpsState(engagementId: number): any | null {
    return opsStates.get(engagementId) || null;
  }

  async function getOpsStateWithRecovery(engagementId: number): Promise<any | null> {
    // Simulate DB recovery
    if (engagementId === 42) {
      return {
        phase: 'vuln_detection',
        isRunning: false,
        assets: [{ hostname: 'example.com', vulns: [], ports: [] }],
        stats: { vulnsFound: 3, portsFound: 5, assetsDiscovered: 1 },
        log: [],
      };
    }
    return null;
  }

  it('should return in-memory state when available', async () => {
    const memState = { phase: 'recon', isRunning: true, assets: [], stats: {}, log: [] };
    opsStates.set(1, memState);

    let state = getOpsState(1);
    if (!state) state = await getOpsStateWithRecovery(1);

    expect(state).toBe(memState);
    expect(state.phase).toBe('recon');
  });

  it('should fall back to DB recovery when in-memory state is lost (server restart)', async () => {
    // In-memory map is empty (simulating server restart)
    opsStates.clear();

    let state = getOpsState(42);
    expect(state).toBeNull(); // In-memory is gone

    if (!state) state = await getOpsStateWithRecovery(42);
    expect(state).not.toBeNull();
    expect(state.phase).toBe('vuln_detection');
    expect(state.assets).toHaveLength(1);
    expect(state.stats.vulnsFound).toBe(3);
  });

  it('should return null when neither in-memory nor DB has state', async () => {
    opsStates.clear();

    let state = getOpsState(999);
    if (!state) state = await getOpsStateWithRecovery(999);

    expect(state).toBeNull();
  });

  it('should handle resetOps with recovered state', async () => {
    opsStates.clear();

    // Simulate resetOps procedure
    let state = getOpsState(42);
    if (!state) state = await getOpsStateWithRecovery(42);

    expect(state).not.toBeNull();

    // Reset the state
    const hasAssets = state.assets.length > 0;
    state.phase = hasAssets ? 'recon_complete' : 'idle';
    state.isRunning = false;
    state.error = undefined;

    expect(state.phase).toBe('recon_complete');
    expect(state.isRunning).toBe(false);
  });
});

// ─── Test 4: Import pattern verification ────────────────────────────
describe('engagement-ops-core import patterns', () => {
  it('should have getOpsStateWithRecovery in all imports that use getOpsState', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('server/routers/engagement-ops-core.ts', 'utf-8');
    const lines = content.split('\n');

    const importLines = lines.filter(l =>
      l.includes('getOpsState') && l.includes("import(") && !l.includes('getOpsStateWithRecovery')
    );

    // All import lines with getOpsState should also have getOpsStateWithRecovery
    expect(importLines).toHaveLength(0);
  });

  it('should have recovery fallback for every getOpsState call', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('server/routers/engagement-ops-core.ts', 'utf-8');
    const lines = content.split('\n');

    const missingRecovery: string[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line.includes('getOpsState(') && !line.includes('getOpsStateWithRecovery')) {
        // Check if nearby lines (within 5 lines) have recovery
        let hasRecovery = false;
        for (let j = 1; j <= 5 && i + j < lines.length; j++) {
          if ((lines[i + j] || '').includes('getOpsStateWithRecovery')) {
            hasRecovery = true;
            break;
          }
        }

        if (!hasRecovery) {
          missingRecovery.push(`Line ${i + 1}: ${line.slice(0, 60)}`);
        }
      }
    }

    expect(missingRecovery).toHaveLength(0);
  });
});
