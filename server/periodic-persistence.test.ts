import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const ORCHESTRATOR_PATH = path.join(__dirname, 'lib', 'engagement-orchestrator.ts');
const orchestratorSrc = fs.readFileSync(ORCHESTRATOR_PATH, 'utf-8');

describe('P4: Periodic Forced Persistence', () => {
  describe('Implementation Verification', () => {
    it('should have a periodicPersistTimers Map declared at module level', () => {
      expect(orchestratorSrc).toContain('const periodicPersistTimers = new Map<number, NodeJS.Timeout>()');
    });

    it('should set PERIODIC_PERSIST_INTERVAL_MS to 60 seconds', () => {
      expect(orchestratorSrc).toContain('const PERIODIC_PERSIST_INTERVAL_MS = 60_000');
    });

    it('should register periodic persist timer in periodicPersistTimers map', () => {
      expect(orchestratorSrc).toContain('periodicPersistTimers.set(engagementId, periodicPersistInterval)');
    });

    it('should clear existing periodic timer before creating a new one (re-run safety)', () => {
      expect(orchestratorSrc).toContain('const existingPeriodicTimer = periodicPersistTimers.get(engagementId)');
      expect(orchestratorSrc).toContain('if (existingPeriodicTimer) clearInterval(existingPeriodicTimer)');
    });

    it('should call saveOpsSnapshot inside the periodic interval', () => {
      // Find the periodic persist section and verify it calls saveOpsSnapshot
      const periodicSection = orchestratorSrc.substring(
        orchestratorSrc.indexOf('PERIODIC FORCED PERSISTENCE (P4)'),
        orchestratorSrc.indexOf('periodicPersistTimers.set(engagementId')
      );
      expect(periodicSection).toContain('saveOpsSnapshot(engagementId, state)');
    });

    it('should log periodic persist activity with phase, progress, assets, and logs', () => {
      expect(orchestratorSrc).toContain('[PeriodicPersist] Engagement #${engagementId}');
      expect(orchestratorSrc).toContain('phase=${state.phase}');
      expect(orchestratorSrc).toContain('progress=${state.progress}%');
      expect(orchestratorSrc).toContain('assets=${state.assets.length}');
      expect(orchestratorSrc).toContain('logs=${state.log.length}');
    });

    it('should handle errors gracefully without crashing the pipeline', () => {
      const periodicSection = orchestratorSrc.substring(
        orchestratorSrc.indexOf('PERIODIC FORCED PERSISTENCE (P4)'),
        orchestratorSrc.indexOf('periodicPersistTimers.set(engagementId')
      );
      expect(periodicSection).toContain('catch (e: any)');
      expect(periodicSection).toContain('[PeriodicPersist] Failed for engagement');
    });
  });

  describe('Self-Termination Guards', () => {
    it('should stop periodic timer when engagement is no longer running', () => {
      const periodicSection = orchestratorSrc.substring(
        orchestratorSrc.indexOf('PERIODIC FORCED PERSISTENCE (P4)'),
        orchestratorSrc.indexOf('periodicPersistTimers.set(engagementId')
      );
      expect(periodicSection).toContain('if (!state.isRunning');
      expect(periodicSection).toContain("state.phase === 'completed'");
      expect(periodicSection).toContain("state.phase === 'error'");
      expect(periodicSection).toContain('clearInterval(periodicPersistInterval)');
      expect(periodicSection).toContain('periodicPersistTimers.delete(engagementId)');
    });
  });

  describe('Lifecycle Cleanup', () => {
    it('should clear periodicPersistInterval on engagement completion', () => {
      // Find the completion section
      const completionIdx = orchestratorSrc.indexOf('// Complete');
      const completionSection = orchestratorSrc.substring(completionIdx, completionIdx + 500);
      expect(completionSection).toContain('clearInterval(periodicPersistInterval)');
    });

    it('should clear periodicPersistInterval on engagement error', () => {
      // Find the error catch section
      const errorIdx = orchestratorSrc.indexOf('clearInterval(heartbeatInterval); // Clean up heartbeat on error');
      const errorSection = orchestratorSrc.substring(errorIdx, errorIdx + 500);
      expect(errorSection).toContain('clearInterval(periodicPersistInterval)');
    });

    it('should clear all periodic timers during graceful shutdown (flushAllPendingState)', () => {
      const flushSection = orchestratorSrc.substring(
        orchestratorSrc.indexOf('export async function flushAllPendingState'),
        orchestratorSrc.indexOf('Force-persist all active states')
      );
      expect(flushSection).toContain('periodicPersistTimers');
      expect(flushSection).toContain('clearInterval(timer)');
      expect(flushSection).toContain('periodicPersistTimers.delete(engId)');
    });
  });

  describe('Integration with Existing Persistence', () => {
    it('should coexist with debounced persistence (not replace it)', () => {
      // Both mechanisms should exist
      expect(orchestratorSrc).toContain('const persistTimers = new Map<number, NodeJS.Timeout>()');
      expect(orchestratorSrc).toContain('const periodicPersistTimers = new Map<number, NodeJS.Timeout>()');
      expect(orchestratorSrc).toContain('function persistOpsStateDebounced');
    });

    it('should be placed after heartbeat interval setup', () => {
      const heartbeatIdx = orchestratorSrc.indexOf('PHASE ACTIVITY HEARTBEAT');
      const periodicIdx = orchestratorSrc.indexOf('PERIODIC FORCED PERSISTENCE (P4)');
      expect(periodicIdx).toBeGreaterThan(heartbeatIdx);
    });

    it('should be placed before the try block that starts phase execution', () => {
      const periodicIdx = orchestratorSrc.indexOf('PERIODIC FORCED PERSISTENCE (P4)');
      // Find the next "try {" after the periodic section
      const tryIdx = orchestratorSrc.indexOf('try {', orchestratorSrc.indexOf('periodicPersistTimers.set(engagementId'));
      expect(tryIdx).toBeGreaterThan(periodicIdx);
    });
  });

  describe('Graceful Shutdown Timer Cleanup Order', () => {
    it('should cancel periodic timers before force-persisting states', () => {
      const flushFn = orchestratorSrc.substring(
        orchestratorSrc.indexOf('export async function flushAllPendingState'),
        orchestratorSrc.indexOf('Abort all in-flight engagement operations')
      );
      const debounceCleanupIdx = flushFn.indexOf('Cancel all debounce timers');
      const periodicCleanupIdx = flushFn.indexOf('Cancel all periodic persistence timers');
      const forcePersistIdx = flushFn.indexOf('Force-persist all active states');

      expect(debounceCleanupIdx).toBeLessThan(periodicCleanupIdx);
      expect(periodicCleanupIdx).toBeLessThan(forcePersistIdx);
    });
  });
});
