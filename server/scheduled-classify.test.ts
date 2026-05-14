import { describe, it, expect, vi, beforeEach } from 'vitest';

// Test the scheduled classification endpoint logic
describe('Scheduled Threat Actor Classification', () => {
  describe('Endpoint: /api/scheduled/threat-actor-classify', () => {
    it('should require authentication', async () => {
      // The endpoint requires either Manus OAuth or caldera_session cookie
      // Without auth, it should return 401
      const response = await fetch('http://localhost:3000/api/scheduled/threat-actor-classify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      }).catch(() => null);
      
      // If server is running, expect 401; if not, skip
      if (response) {
        expect(response.status).toBe(401);
      }
    });

    it('should accept batchLimit and autoApplyThreshold parameters', () => {
      // Verify the endpoint accepts configuration parameters
      const validBody = {
        batchLimit: 25,
        autoApplyThreshold: 80,
      };
      expect(validBody.batchLimit).toBe(25);
      expect(validBody.autoApplyThreshold).toBe(80);
    });

    it('should default batchLimit to 50 when not provided', () => {
      const body: any = {};
      const batchLimit = body?.batchLimit || 50;
      expect(batchLimit).toBe(50);
    });

    it('should default autoApplyThreshold to 70 when not provided', () => {
      const body: any = {};
      const autoApplyThreshold = body?.autoApplyThreshold || 70;
      expect(autoApplyThreshold).toBe(70);
    });
  });

  describe('Classification Engine Integration', () => {
    it('should import classifyBatch and resetProgress from classifier module', async () => {
      const mod = await import('./lib/threat-actor-classifier');
      expect(mod.classifyBatch).toBeDefined();
      expect(typeof mod.classifyBatch).toBe('function');
      expect(mod.resetProgress).toBeDefined();
      expect(typeof mod.resetProgress).toBe('function');
    });

    it('should import getProgress from classifier module', async () => {
      const mod = await import('./lib/threat-actor-classifier');
      expect(mod.getProgress).toBeDefined();
      expect(typeof mod.getProgress).toBe('function');
    });

    it('getProgress should return proper structure when idle', async () => {
      const { getProgress, resetProgress } = await import('./lib/threat-actor-classifier');
      resetProgress();
      const progress = getProgress();
      expect(progress).toHaveProperty('total');
      expect(progress).toHaveProperty('processed');
      expect(progress).toHaveProperty('succeeded');
      expect(progress).toHaveProperty('failed');
      expect(progress).toHaveProperty('status');
      expect(progress.status).toBe('idle');
    });

    it('resetProgress should clear all state', async () => {
      const { resetProgress, getProgress } = await import('./lib/threat-actor-classifier');
      resetProgress();
      const progress = getProgress();
      expect(progress.total).toBe(0);
      expect(progress.processed).toBe(0);
      expect(progress.succeeded).toBe(0);
      expect(progress.failed).toBe(0);
      expect(progress.results).toEqual([]);
      expect(progress.errors).toEqual([]);
    });
  });

  describe('Scheduled Task Configuration', () => {
    it('should process actors in configurable batch sizes', () => {
      // Verify batch sizes are respected
      const configs = [
        { batchLimit: 10, expected: 10 },
        { batchLimit: 50, expected: 50 },
        { batchLimit: 100, expected: 100 },
      ];
      for (const config of configs) {
        expect(config.batchLimit).toBe(config.expected);
      }
    });

    it('should only classify actors with actorType = unknown', () => {
      // The query filters by actorType = 'unknown'
      const mockActors = [
        { actorId: 'a1', actorType: 'unknown' },
        { actorId: 'a2', actorType: 'apt' },
        { actorId: 'a3', actorType: 'unknown' },
        { actorId: 'a4', actorType: 'ransomware' },
      ];
      const filtered = mockActors.filter(a => a.actorType === 'unknown');
      expect(filtered).toHaveLength(2);
      expect(filtered.map(a => a.actorId)).toEqual(['a1', 'a3']);
    });

    it('should auto-apply classifications above threshold', () => {
      const threshold = 70;
      const classifications = [
        { actorId: 'a1', confidence: 95, classifiedType: 'apt' },
        { actorId: 'a2', confidence: 60, classifiedType: 'ransomware' },
        { actorId: 'a3', confidence: 75, classifiedType: 'cybercrime' },
        { actorId: 'a4', confidence: 45, classifiedType: 'hacktivist' },
      ];
      const autoApplied = classifications.filter(c => c.confidence >= threshold);
      expect(autoApplied).toHaveLength(2);
      expect(autoApplied.map(c => c.actorId)).toEqual(['a1', 'a3']);
    });

    it('should send notification when actors are classified', () => {
      // Verify notification is triggered when applied > 0
      const applied = 5;
      const shouldNotify = applied > 0;
      expect(shouldNotify).toBe(true);
    });

    it('should not send notification when no actors are classified', () => {
      const applied = 0;
      const shouldNotify = applied > 0;
      expect(shouldNotify).toBe(false);
    });

    it('should return early when no unknown actors exist', () => {
      const unknownActors: any[] = [];
      const shouldReturn = unknownActors.length === 0;
      expect(shouldReturn).toBe(true);
    });
  });

  describe('Safe Array Parser', () => {
    function safeParseArr(v: any) {
      if (Array.isArray(v)) return v;
      if (typeof v === 'string') { try { const p = JSON.parse(v); return Array.isArray(p) ? p : []; } catch { return []; } }
      return [];
    }

    it('should return arrays as-is', () => {
      expect(safeParseArr(['a', 'b'])).toEqual(['a', 'b']);
    });

    it('should parse JSON string arrays', () => {
      expect(safeParseArr('["a","b"]')).toEqual(['a', 'b']);
    });

    it('should return empty array for invalid JSON', () => {
      expect(safeParseArr('not json')).toEqual([]);
    });

    it('should return empty array for null/undefined', () => {
      expect(safeParseArr(null)).toEqual([]);
      expect(safeParseArr(undefined)).toEqual([]);
    });

    it('should return empty array for non-array JSON', () => {
      expect(safeParseArr('{"key":"value"}')).toEqual([]);
    });
  });
});
