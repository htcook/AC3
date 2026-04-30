import { describe, it, expect, beforeEach } from 'vitest';
import {
  acquireScanSlot,
  isScanSlotAvailable,
  getScanConcurrencyMetrics,
  getScanConcurrencyConfig,
  configureScanConcurrency,
  releaseAllForEngagement,
  resetScanConcurrency,
} from './lib/scan-concurrency';

describe('Scan Concurrency Limiter', () => {
  beforeEach(() => {
    resetScanConcurrency();
  });

  describe('Default Configuration', () => {
    it('should have sensible defaults for 8-vCPU droplet', () => {
      const config = getScanConcurrencyConfig();
      expect(config.maxConcurrentNuclei).toBe(2);
      expect(config.maxConcurrentZap).toBe(1);
      expect(config.maxConcurrentTotal).toBe(4);
      expect(config.maxPerEngagement).toBe(2);
      expect(config.queueTimeoutMs).toBe(300000); // 5 minutes
    });

    it('should start with zero active scans', () => {
      const metrics = getScanConcurrencyMetrics();
      expect(metrics.activeTotal).toBe(0);
      expect(metrics.activeNuclei).toBe(0);
      expect(metrics.activeZap).toBe(0);
      expect(metrics.queueDepth).toBe(0);
    });
  });

  describe('Slot Acquisition', () => {
    it('should acquire and release a nuclei slot', async () => {
      const release = await acquireScanSlot('nuclei', 1);
      expect(typeof release).toBe('function');

      const metrics = getScanConcurrencyMetrics();
      expect(metrics.activeNuclei).toBe(1);
      expect(metrics.activeTotal).toBe(1);
      expect(metrics.totalAcquired).toBe(1);

      release();
      const after = getScanConcurrencyMetrics();
      expect(after.activeNuclei).toBe(0);
      expect(after.totalReleased).toBe(1);
    });

    it('should acquire and release a ZAP slot', async () => {
      const release = await acquireScanSlot('zap', 1);
      const metrics = getScanConcurrencyMetrics();
      expect(metrics.activeZap).toBe(1);

      release();
      const after = getScanConcurrencyMetrics();
      expect(after.activeZap).toBe(0);
    });

    it('should track per-engagement counts', async () => {
      const r1 = await acquireScanSlot('nuclei', 100);
      const r2 = await acquireScanSlot('nuclei', 100);
      const r3 = await acquireScanSlot('nuclei', 200);

      const metrics = getScanConcurrencyMetrics();
      expect(metrics.perEngagement[100]).toBe(2);
      expect(metrics.perEngagement[200]).toBe(1);

      r1(); r3();
    });

    it('should track peak concurrent', async () => {
      const r1 = await acquireScanSlot('nuclei', 1);
      const r2 = await acquireScanSlot('nuclei', 2);
      const r3 = await acquireScanSlot('zap', 3);

      expect(getScanConcurrencyMetrics().peakConcurrent).toBe(3);

      r1(); r3();
      // Peak should remain at 3 even after release
      expect(getScanConcurrencyMetrics().peakConcurrent).toBe(3);
    });
  });

  describe('Per-Tool Limits', () => {
    it('should enforce nuclei concurrency limit (2)', async () => {
      const releases: (() => void)[] = [];
      // Acquire 2 nuclei slots across different engagements
      for (let i = 0; i < 2; i++) {
        releases.push(await acquireScanSlot('nuclei', i + 1));
      }

      // 3rd nuclei should NOT be immediately available
      expect(isScanSlotAvailable('nuclei', 3)).toBe(false);

      // But a ZAP slot should still be available (different tool)
      expect(isScanSlotAvailable('zap', 3)).toBe(true);

      releases.forEach(r => r());
    });

    it('should enforce ZAP concurrency limit (1)', async () => {
      const r1 = await acquireScanSlot('zap', 1);

      // 2nd ZAP should NOT be available
      expect(isScanSlotAvailable('zap', 2)).toBe(false);

      // But nuclei should still be available
      expect(isScanSlotAvailable('nuclei', 2)).toBe(true);

      r1();
    });
  });

  describe('Global Total Limit', () => {
    it('should enforce global total limit (4)', async () => {
      const releases: (() => void)[] = [];
      // Fill up: 2 nuclei + 1 ZAP + 1 nuclei = 4 total (across different engagements)
      releases.push(await acquireScanSlot('nuclei', 1));
      releases.push(await acquireScanSlot('nuclei', 2));
      releases.push(await acquireScanSlot('zap', 3));
      releases.push(await acquireScanSlot('nuclei', 4));

      const metrics = getScanConcurrencyMetrics();
      expect(metrics.activeTotal).toBe(4);

      // No more slots available for any tool
      expect(isScanSlotAvailable('nuclei', 5)).toBe(false);
      expect(isScanSlotAvailable('zap', 5)).toBe(false);

      releases.forEach(r => r());
    });
  });

  describe('Per-Engagement Fairness', () => {
    it('should enforce per-engagement limit (2)', async () => {
      const releases: (() => void)[] = [];
      // Same engagement acquires 2 slots
      for (let i = 0; i < 2; i++) {
        releases.push(await acquireScanSlot('nuclei', 42));
      }

      // 3rd slot for same engagement should be blocked
      expect(isScanSlotAvailable('nuclei', 42)).toBe(false);

      // But a different engagement can still acquire
      expect(isScanSlotAvailable('nuclei', 43)).toBe(true);

      releases.forEach(r => r());
    });
  });

  describe('Queue and Backpressure', () => {
    it('should queue requests when slots are full and drain on release', async () => {
      configureScanConcurrency({ maxConcurrentNuclei: 2, maxConcurrentTotal: 2 });

      const r1 = await acquireScanSlot('nuclei', 1);
      const r2 = await acquireScanSlot('nuclei', 2);

      // Queue a 3rd request — it should block
      let resolved = false;
      const p3 = acquireScanSlot('nuclei', 3).then(release => {
        resolved = true;
        return release;
      });

      // Give the event loop a tick
      await new Promise(r => setTimeout(r, 10));
      expect(resolved).toBe(false);
      expect(getScanConcurrencyMetrics().queueDepth).toBe(1);

      // Release one slot — queued request should resolve
      r1();
      await new Promise(r => setTimeout(r, 10));
      expect(resolved).toBe(true);
      expect(getScanConcurrencyMetrics().queueDepth).toBe(0);

      const r3 = await p3;
      r2(); r3();
    });

    it('should process queue in FIFO order', async () => {
      configureScanConcurrency({ maxConcurrentNuclei: 1, maxConcurrentTotal: 1 });

      const r1 = await acquireScanSlot('nuclei', 1);
      const order: number[] = [];

      const p2 = acquireScanSlot('nuclei', 2).then(release => { order.push(2); return release; });
      const p3 = acquireScanSlot('nuclei', 3).then(release => { order.push(3); return release; });

      r1();
      const r2 = await p2;
      r2();
      const r3 = await p3;
      r3();

      expect(order).toEqual([2, 3]);
    });

    it('should timeout queued requests after queueTimeoutMs', async () => {
      configureScanConcurrency({
        maxConcurrentNuclei: 1,
        maxConcurrentTotal: 1,
        queueTimeoutMs: 100, // Very short for testing
      });

      const r1 = await acquireScanSlot('nuclei', 1);

      // This should timeout
      await expect(acquireScanSlot('nuclei', 2)).rejects.toThrow('Scan queue timeout');

      const metrics = getScanConcurrencyMetrics();
      expect(metrics.totalTimedOut).toBe(1);

      r1();
    });
  });

  describe('Force Release', () => {
    it('should release all slots for a specific engagement', async () => {
      const r1 = await acquireScanSlot('nuclei', 100);
      const r2 = await acquireScanSlot('zap', 100);
      const r3 = await acquireScanSlot('nuclei', 200);

      expect(getScanConcurrencyMetrics().activeTotal).toBe(3);

      const released = releaseAllForEngagement(100);
      expect(released).toBe(2);
      expect(getScanConcurrencyMetrics().activeTotal).toBe(1);
      expect(getScanConcurrencyMetrics().perEngagement[200]).toBe(1);

      r3();
    });

    it('should also remove queued entries for the engagement', async () => {
      configureScanConcurrency({ maxConcurrentNuclei: 1, maxConcurrentTotal: 1 });

      const r1 = await acquireScanSlot('nuclei', 1);

      // Queue a request for engagement 2
      let rejected = false;
      acquireScanSlot('nuclei', 2).catch(() => { rejected = true; });

      await new Promise(r => setTimeout(r, 10));
      expect(getScanConcurrencyMetrics().queueDepth).toBe(1);

      // Force release engagement 2 — should reject the queued request
      releaseAllForEngagement(2);
      await new Promise(r => setTimeout(r, 10));
      expect(rejected).toBe(true);
      expect(getScanConcurrencyMetrics().queueDepth).toBe(0);

      r1();
    });
  });

  describe('Runtime Configuration', () => {
    it('should allow updating config at runtime', () => {
      const updated = configureScanConcurrency({
        maxConcurrentNuclei: 8,
        maxConcurrentZap: 4,
        maxConcurrentTotal: 12,
      });

      expect(updated.maxConcurrentNuclei).toBe(8);
      expect(updated.maxConcurrentZap).toBe(4);
      expect(updated.maxConcurrentTotal).toBe(12);
      // Unchanged values should persist
      expect(updated.maxPerEngagement).toBe(2);
    });

    it('should drain queue when config is relaxed', async () => {
      configureScanConcurrency({ maxConcurrentNuclei: 1, maxConcurrentTotal: 1 });

      const r1 = await acquireScanSlot('nuclei', 1);

      let resolved = false;
      const p2 = acquireScanSlot('nuclei', 2).then(release => {
        resolved = true;
        return release;
      });

      await new Promise(r => setTimeout(r, 10));
      expect(resolved).toBe(false);

      // Relax the config — should drain queue
      configureScanConcurrency({ maxConcurrentNuclei: 2, maxConcurrentTotal: 2 });
      await new Promise(r => setTimeout(r, 10));
      expect(resolved).toBe(true);

      const r2 = await p2;
      r1();
    });
  });

  describe('Availability Check', () => {
    it('isScanSlotAvailable should return true when slots are free', () => {
      expect(isScanSlotAvailable('nuclei', 1)).toBe(true);
      expect(isScanSlotAvailable('zap', 1)).toBe(true);
    });

    it('isScanSlotAvailable should return false when tool limit reached', async () => {
      configureScanConcurrency({ maxConcurrentNuclei: 1, maxConcurrentTotal: 6 });
      const r1 = await acquireScanSlot('nuclei', 1);
      expect(isScanSlotAvailable('nuclei', 2)).toBe(false);
      expect(isScanSlotAvailable('zap', 2)).toBe(true);
      r1();
    });
  });

  describe('Metrics', () => {
    it('should track average wait time', async () => {
      configureScanConcurrency({ maxConcurrentNuclei: 1, maxConcurrentTotal: 1 });

      const r1 = await acquireScanSlot('nuclei', 1);

      // Queue a request that will wait
      const start = Date.now();
      const p2 = acquireScanSlot('nuclei', 2);

      // Release after a short delay
      setTimeout(() => r1(), 50);
      const r2 = await p2;

      const metrics = getScanConcurrencyMetrics();
      expect(metrics.avgWaitMs).toBeGreaterThan(0);
      expect(metrics.totalAcquired).toBe(2);

      r2();
    });
  });
});
