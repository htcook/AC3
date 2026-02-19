import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

describe('Scan Recovery Scheduler', () => {
  let scanRecovery: typeof import('./lib/scan-recovery');

  beforeEach(async () => {
    scanRecovery = await import('./lib/scan-recovery');
    // Clear retry map between tests
    scanRecovery._testHelpers.clearRetryMap();
  });

  afterEach(() => {
    // Stop the scheduler if it was started during tests
    scanRecovery.stopScanRecoverySchedule();
  });

  // ─── Configuration Constants ──────────────────────────────────────────

  describe('Configuration', () => {
    it('should have a 15-minute stuck threshold', () => {
      expect(scanRecovery._testHelpers.STUCK_THRESHOLD_MS).toBe(15 * 60 * 1000);
    });

    it('should allow a maximum of 3 auto-retries', () => {
      expect(scanRecovery._testHelpers.MAX_AUTO_RETRIES).toBe(3);
    });

    it('should monitor all in-progress pipeline statuses', () => {
      const statuses = scanRecovery._testHelpers.IN_PROGRESS_STATUSES;
      expect(statuses).toContain('passive_recon');
      expect(statuses).toContain('discovering');
      expect(statuses).toContain('analyzing');
      expect(statuses).toContain('scoring');
      expect(statuses).toContain('recommending');
      expect(statuses).not.toContain('completed');
      expect(statuses).not.toContain('scan_complete');
      expect(statuses).not.toContain('failed');
      expect(statuses).not.toContain('pending');
    });
  });

  // ─── Retry Count Tracking ─────────────────────────────────────────────

  describe('Retry Count Tracking', () => {
    it('should start with 0 retries for unknown scan IDs', () => {
      expect(scanRecovery._testHelpers.getRetryCount(99999)).toBe(0);
    });

    it('should track retry counts per scan', () => {
      scanRecovery._testHelpers.setRetryCount(1, 2);
      scanRecovery._testHelpers.setRetryCount(2, 1);
      expect(scanRecovery._testHelpers.getRetryCount(1)).toBe(2);
      expect(scanRecovery._testHelpers.getRetryCount(2)).toBe(1);
    });

    it('should clear all retry counts', () => {
      scanRecovery._testHelpers.setRetryCount(1, 3);
      scanRecovery._testHelpers.setRetryCount(2, 1);
      scanRecovery._testHelpers.clearRetryMap();
      expect(scanRecovery._testHelpers.getRetryCount(1)).toBe(0);
      expect(scanRecovery._testHelpers.getRetryCount(2)).toBe(0);
    });
  });

  // ─── Scheduler Lifecycle ──────────────────────────────────────────────

  describe('Scheduler Lifecycle', () => {
    it('should report inactive status before initialization', () => {
      const status = scanRecovery.getScanRecoveryStatus();
      expect(status.active).toBe(false);
      expect(status.lastCheckAt).toBeNull();
      expect(status.isRunning).toBe(false);
      expect(status.totalRecoveries).toBeTypeOf('number');
      expect(status.totalFailures).toBeTypeOf('number');
    });

    it('should report correct config values', () => {
      const status = scanRecovery.getScanRecoveryStatus();
      expect(status.config.stuckThresholdMinutes).toBe(15);
      expect(status.config.maxAutoRetries).toBe(3);
      expect(status.config.cronSchedule).toBe('*/5 * * * *');
    });

    it('should activate when initialized', () => {
      scanRecovery.initScanRecoverySchedule();
      const status = scanRecovery.getScanRecoveryStatus();
      expect(status.active).toBe(true);
    });

    it('should deactivate when stopped', () => {
      scanRecovery.initScanRecoverySchedule();
      scanRecovery.stopScanRecoverySchedule();
      const status = scanRecovery.getScanRecoveryStatus();
      expect(status.active).toBe(false);
    });

    it('should be idempotent — multiple init calls should not create duplicates', () => {
      scanRecovery.initScanRecoverySchedule();
      scanRecovery.initScanRecoverySchedule(); // second call
      const status = scanRecovery.getScanRecoveryStatus();
      expect(status.active).toBe(true);
      scanRecovery.stopScanRecoverySchedule();
      expect(scanRecovery.getScanRecoveryStatus().active).toBe(false);
    });

    it('should be safe to stop when not started', () => {
      // Should not throw
      scanRecovery.stopScanRecoverySchedule();
      expect(scanRecovery.getScanRecoveryStatus().active).toBe(false);
    });
  });

  // ─── findStuckScans ───────────────────────────────────────────────────

  describe('findStuckScans', () => {
    it('should return an array', async () => {
      const result = await scanRecovery.findStuckScans();
      expect(Array.isArray(result)).toBe(true);
    });

    it('should include retryCount for each stuck scan', async () => {
      const result = await scanRecovery.findStuckScans();
      for (const scan of result) {
        expect(scan).toHaveProperty('id');
        expect(scan).toHaveProperty('primaryDomain');
        expect(scan).toHaveProperty('status');
        expect(scan).toHaveProperty('updatedAt');
        expect(scan).toHaveProperty('stuckDurationMs');
        expect(scan).toHaveProperty('retryCount');
        expect(typeof scan.retryCount).toBe('number');
      }
    });
  });

  // ─── runRecoveryCheck ─────────────────────────────────────────────────

  describe('runRecoveryCheck', () => {
    it('should return a structured result', async () => {
      const result = await scanRecovery.runRecoveryCheck();
      expect(result).toHaveProperty('checked');
      expect(result).toHaveProperty('stuckScans');
      expect(result).toHaveProperty('recovered');
      expect(result).toHaveProperty('exhausted');
      expect(result).toHaveProperty('skipped');
      expect(typeof result.checked).toBe('boolean');
      expect(typeof result.stuckScans).toBe('number');
    });

    it('should report checked=true when no scans are stuck', async () => {
      // With all scans completed, there should be nothing stuck
      const result = await scanRecovery.runRecoveryCheck();
      expect(result.checked).toBe(true);
    });
  });

  // ─── Module Exports ───────────────────────────────────────────────────

  describe('Module Exports', () => {
    it('should export findStuckScans function', () => {
      expect(typeof scanRecovery.findStuckScans).toBe('function');
    });

    it('should export recoverScan function', () => {
      expect(typeof scanRecovery.recoverScan).toBe('function');
    });

    it('should export runRecoveryCheck function', () => {
      expect(typeof scanRecovery.runRecoveryCheck).toBe('function');
    });

    it('should export initScanRecoverySchedule function', () => {
      expect(typeof scanRecovery.initScanRecoverySchedule).toBe('function');
    });

    it('should export stopScanRecoverySchedule function', () => {
      expect(typeof scanRecovery.stopScanRecoverySchedule).toBe('function');
    });

    it('should export getScanRecoveryStatus function', () => {
      expect(typeof scanRecovery.getScanRecoveryStatus).toBe('function');
    });

    it('should export _testHelpers with expected properties', () => {
      expect(scanRecovery._testHelpers).toHaveProperty('STUCK_THRESHOLD_MS');
      expect(scanRecovery._testHelpers).toHaveProperty('MAX_AUTO_RETRIES');
      expect(scanRecovery._testHelpers).toHaveProperty('IN_PROGRESS_STATUSES');
      expect(scanRecovery._testHelpers).toHaveProperty('getRetryCount');
      expect(scanRecovery._testHelpers).toHaveProperty('setRetryCount');
      expect(scanRecovery._testHelpers).toHaveProperty('clearRetryMap');
    });
  });
});
