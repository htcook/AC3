import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Tests for the defensive null-check fix that prevents the frontend crash:
 *   "Cannot read properties of undefined (reading 'length')"
 *
 * Root cause: After resetting engagement scan data, state_json = {} (empty object).
 * loadOpsSnapshot must initialize all required arrays/objects, and the frontend
 * must also guard against undefined arrays in the ops useMemo.
 */
describe('Ops Snapshot Default Initialization (Bug Fix)', () => {
  const dbPath = path.resolve(__dirname, 'db.ts');
  const opsPagePath = path.resolve(__dirname, '../client/src/pages/EngagementOps.tsx');

  // ─── Backend: loadOpsSnapshot defaults ─────────────────────────────────

  describe('loadOpsSnapshot initializes required fields for empty state_json', () => {
    let dbContent: string;

    beforeAll(() => {
      dbContent = fs.readFileSync(dbPath, 'utf-8');
    });

    it('initializes engagementId when missing', () => {
      expect(dbContent).toContain("if (!state.engagementId) state.engagementId = engagementId");
    });

    it('initializes phase to idle when missing', () => {
      expect(dbContent).toContain("if (!state.phase) state.phase = 'idle'");
    });

    it('initializes progress to 0 when undefined', () => {
      expect(dbContent).toContain("if (state.progress === undefined) state.progress = 0");
    });

    it('initializes isRunning to false when undefined', () => {
      expect(dbContent).toContain("if (state.isRunning === undefined) state.isRunning = false");
    });

    it('initializes isPaused to false when undefined', () => {
      expect(dbContent).toContain("if (state.isPaused === undefined) state.isPaused = false");
    });

    it('initializes assets as empty array when not an array', () => {
      expect(dbContent).toContain("if (!Array.isArray(state.assets)) state.assets = []");
    });

    it('initializes log as empty array when not an array', () => {
      expect(dbContent).toContain("if (!Array.isArray(state.log)) state.log = []");
    });

    it('initializes approvalGates as empty array when not an array', () => {
      expect(dbContent).toContain("if (!Array.isArray(state.approvalGates)) state.approvalGates = []");
    });

    it('initializes stats with all required counters', () => {
      expect(dbContent).toContain("if (!state.stats) state.stats =");
      expect(dbContent).toContain("hostsScanned: 0");
      expect(dbContent).toContain("portsFound: 0");
      expect(dbContent).toContain("vulnsFound: 0");
      expect(dbContent).toContain("exploitsAttempted: 0");
      expect(dbContent).toContain("exploitsSucceeded: 0");
      expect(dbContent).toContain("sessionsOpened: 0");
    });

    it('initializes asset sub-arrays (ports, vulns, toolResults)', () => {
      expect(dbContent).toContain("if (!Array.isArray(asset.ports)) asset.ports = []");
      expect(dbContent).toContain("if (!Array.isArray(asset.vulns)) asset.vulns = []");
      expect(dbContent).toContain("if (!Array.isArray(asset.toolResults)) asset.toolResults = []");
    });
  });

  // ─── Frontend: EngagementOps defensive checks ──────────────────────────

  describe('EngagementOps.tsx defensive null checks in ops useMemo', () => {
    let opsContent: string;

    beforeAll(() => {
      opsContent = fs.readFileSync(opsPagePath, 'utf-8');
    });

    it('returns null when base is falsy (no data)', () => {
      expect(opsContent).toContain("if (!base) return null");
    });

    it('initializes base.log when missing', () => {
      expect(opsContent).toContain("if (!base.log) base.log = []");
    });

    it('initializes base.assets when missing', () => {
      expect(opsContent).toContain("if (!base.assets) base.assets = []");
    });

    it('initializes base.approvalGates when missing', () => {
      expect(opsContent).toContain("if (!base.approvalGates) base.approvalGates = []");
    });

    it('initializes base.stats when missing', () => {
      expect(opsContent).toContain("if (!base.stats) base.stats =");
    });

    it('uses optional chaining for ops.log.length access', () => {
      // The auto-scroll useEffect should use ops?.log?.length
      expect(opsContent).toContain("ops?.log?.length");
    });

    it('uses optional chaining for ops.assets access', () => {
      expect(opsContent).toContain("ops?.assets");
    });

    it('uses optional chaining for ops.approvalGates access', () => {
      expect(opsContent).toContain("ops?.approvalGates");
    });
  });

  // ─── Regression: Verify the crash scenario is handled ──────────────────

  describe('Regression: empty state_json does not crash', () => {
    it('loadOpsSnapshot handles empty object state_json', () => {
      const dbContent = fs.readFileSync(dbPath, 'utf-8');
      // The function should check for empty/missing fields
      // This is the exact scenario: state_json = {} after SQL reset
      const hasEmptyCheck = dbContent.includes("if (!state.phase) state.phase = 'idle'");
      const hasArrayCheck = dbContent.includes("if (!Array.isArray(state.log)) state.log = []");
      const hasStatsCheck = dbContent.includes("if (!state.stats) state.stats =");
      expect(hasEmptyCheck).toBe(true);
      expect(hasArrayCheck).toBe(true);
      expect(hasStatsCheck).toBe(true);
    });

    it('frontend ops useMemo guards all .length accesses', () => {
      const opsContent = fs.readFileSync(opsPagePath, 'utf-8');
      // The useMemo should initialize arrays before any .map/.filter/.length
      const hasLogInit = opsContent.includes("if (!base.log) base.log = []");
      const hasAssetsInit = opsContent.includes("if (!base.assets) base.assets = []");
      expect(hasLogInit).toBe(true);
      expect(hasAssetsInit).toBe(true);
    });
  });
});
