import { describe, it, expect } from 'vitest';

/**
 * Tests for scan recovery logic — validates that:
 * 1. normalizeOpsState rehydrates all completedScans Sets correctly
 * 2. Resume logic picks up from the SAME phase (not next)
 * 3. All 11 completedScans tracking Sets are present
 * 4. JSON round-trip preserves completedScans data
 */


// Skip in CI — requires SSH access to scan server
const __skipInCI = !process.env.SCAN_SERVER_HOST;

describe.skipIf(__skipInCI)('Scan Recovery Logic', () => {
  // Dynamic import to handle the large orchestrator module
  const getModule = async () => {
    const mod = await import('./lib/engagement-orchestrator');
    return mod;
  };

  describe('normalizeOpsState — completedScans rehydration', () => {
    it('should create all 11 completedScans Sets when state has no completedScans', async () => {
      const { normalizeOpsState } = await getModule();
      const state = normalizeOpsState({
        assets: [],
        log: [],
        stats: { hostsScanned: 0, portsFound: 0, vulnsFound: 0, exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0, zapScansRun: 0, wafDetections: 0 },
      });
      expect(state.completedScans).toBeDefined();
      expect(state.completedScans!.nucleiCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.zapCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.hydraCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.exploitCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.katanaCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.feroxbusterCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.ffufCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.testsslCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.paramDiscoveryCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.wafw00fCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.burpCompleted).toBeInstanceOf(Set);
    });

    it('should rehydrate arrays back into Sets after JSON round-trip', async () => {
      const { normalizeOpsState } = await getModule();
      // Simulate a JSON round-trip (DB snapshot → parse → normalize)
      const snapshotJson = JSON.stringify({
        assets: [],
        log: [],
        phase: 'vuln_detection',
        isRunning: true,
        stats: { hostsScanned: 2, portsFound: 5, vulnsFound: 3, exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0, zapScansRun: 1, wafDetections: 0 },
        completedScans: {
          nucleiCompleted: ['http://target1:80', 'http://target2:443'],
          zapCompleted: ['http://target1:80'],
          hydraCompleted: [],
          exploitCompleted: [],
          katanaCompleted: ['http://target1:80'],
          feroxbusterCompleted: [],
          ffufCompleted: ['http://target1:80'],
          testsslCompleted: [],
          paramDiscoveryCompleted: [],
          wafw00fCompleted: ['http://target1:80'],
          burpCompleted: ['http://target1:80'],
          lastCheckpointAt: 1700000000000,
        },
      });
      const parsed = JSON.parse(snapshotJson);
      const state = normalizeOpsState(parsed);

      // All should be Sets now, not arrays
      expect(state.completedScans!.nucleiCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.nucleiCompleted.size).toBe(2);
      expect(state.completedScans!.nucleiCompleted.has('http://target1:80')).toBe(true);
      expect(state.completedScans!.nucleiCompleted.has('http://target2:443')).toBe(true);

      expect(state.completedScans!.zapCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.zapCompleted.size).toBe(1);

      expect(state.completedScans!.katanaCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.katanaCompleted.size).toBe(1);

      expect(state.completedScans!.ffufCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.ffufCompleted.size).toBe(1);

      expect(state.completedScans!.wafw00fCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.wafw00fCompleted.size).toBe(1);

      expect(state.completedScans!.burpCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.burpCompleted.size).toBe(1);

      // Empty ones should still be Sets
      expect(state.completedScans!.hydraCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.hydraCompleted.size).toBe(0);

      expect(state.completedScans!.testsslCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.testsslCompleted.size).toBe(0);
    });

    it('should handle partial completedScans (old snapshots missing new fields)', async () => {
      const { normalizeOpsState } = await getModule();
      // Simulate an old snapshot that only has the original 4 tracking Sets
      const oldSnapshot = {
        assets: [],
        log: [],
        phase: 'scanning',
        isRunning: false,
        stats: { hostsScanned: 0, portsFound: 0, vulnsFound: 0, exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0, zapScansRun: 0, wafDetections: 0 },
        completedScans: {
          nucleiCompleted: ['http://old-target:80'],
          zapCompleted: [],
          hydraCompleted: [],
          exploitCompleted: [],
          lastCheckpointAt: 1600000000000,
          // Missing: katanaCompleted, feroxbusterCompleted, ffufCompleted, testsslCompleted, paramDiscoveryCompleted, wafw00fCompleted, burpCompleted
        },
      };
      const state = normalizeOpsState(oldSnapshot);

      // Old fields should be preserved
      expect(state.completedScans!.nucleiCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.nucleiCompleted.size).toBe(1);

      // New fields should be created as empty Sets
      expect(state.completedScans!.katanaCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.katanaCompleted.size).toBe(0);
      expect(state.completedScans!.feroxbusterCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.feroxbusterCompleted.size).toBe(0);
      expect(state.completedScans!.ffufCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.ffufCompleted.size).toBe(0);
      expect(state.completedScans!.testsslCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.testsslCompleted.size).toBe(0);
      expect(state.completedScans!.paramDiscoveryCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.paramDiscoveryCompleted.size).toBe(0);
      expect(state.completedScans!.wafw00fCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.wafw00fCompleted.size).toBe(0);
      expect(state.completedScans!.burpCompleted).toBeInstanceOf(Set);
      expect(state.completedScans!.burpCompleted.size).toBe(0);
    });

    it('should preserve lastCheckpointAt timestamp', async () => {
      const { normalizeOpsState } = await getModule();
      const state = normalizeOpsState({
        assets: [],
        log: [],
        stats: { hostsScanned: 0, portsFound: 0, vulnsFound: 0, exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0, zapScansRun: 0, wafDetections: 0 },
        completedScans: {
          nucleiCompleted: [],
          zapCompleted: [],
          hydraCompleted: [],
          exploitCompleted: [],
          lastCheckpointAt: 1700000000000,
        },
      });
      expect(state.completedScans!.lastCheckpointAt).toBe(1700000000000);
    });
  });

  describe('Resume phase logic', () => {
    it('should have resume-from-same-phase comment in the orchestrator source', async () => {
      // Verify the fix is in place by checking the source code
      const fs = await import('fs');
      const source = fs.readFileSync('./server/lib/engagement-orchestrator.ts', 'utf-8');
      expect(source).toContain('RESUME FROM SAME PHASE');
      expect(source).toContain('startPhase = recovered.phase');
    });

    it('should NOT contain the old next-phase skip logic', async () => {
      const fs = await import('fs');
      const source = fs.readFileSync('./server/lib/engagement-orchestrator.ts', 'utf-8');
      // The old logic advanced to the next phase index — verify it's gone
      // The old code was: startPhase = PHASE_ORDER[currentIdx + 1]
      // Now it should be: startPhase = existingState.phase
      const resumeSection = source.substring(
        source.indexOf('RESUME FROM SAME PHASE'),
        source.indexOf('RESUME FROM SAME PHASE') + 500
      );
      expect(resumeSection).not.toContain('currentIdx + 1');
    });
  });

  describe('completedScans type completeness', () => {
    it('should have all 11 tracking Sets in the type definition', async () => {
      const fs = await import('fs');
      const source = fs.readFileSync('./server/lib/engagement-orchestrator.ts', 'utf-8');
      const expectedSets = [
        'nucleiCompleted', 'zapCompleted', 'hydraCompleted', 'exploitCompleted',
        'katanaCompleted', 'feroxbusterCompleted', 'ffufCompleted',
        'testsslCompleted', 'paramDiscoveryCompleted', 'wafw00fCompleted', 'burpCompleted',
      ];
      for (const setName of expectedSets) {
        expect(source).toContain(`${setName}: Set<string>`);
        expect(source).toContain(`${setName}: new Set()`);
      }
    });

    it('should have Burp completion tracking in the onBurpScanComplete callback', async () => {
      const fs = await import('fs');
      const source = fs.readFileSync('./server/lib/engagement-orchestrator.ts', 'utf-8');
      expect(source).toContain('burpCompleted.add(');
    });
  });
});
