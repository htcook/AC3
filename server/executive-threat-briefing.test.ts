import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Executive Threat Briefing Tests ──────────────────────────────────────────
describe('Executive Threat Briefing', () => {
  // ─── Module Exports ──────────────────────────────────────────────────────
  describe('Module Exports', () => {
    it('should export computeExecutiveThreatBriefing function', async () => {
      const mod = await import('./lib/executive-threat-briefing');
      expect(mod.computeExecutiveThreatBriefing).toBeDefined();
      expect(typeof mod.computeExecutiveThreatBriefing).toBe('function');
    });

    it('should export getRecentScansForBriefing function', async () => {
      const mod = await import('./lib/executive-threat-briefing');
      expect(mod.getRecentScansForBriefing).toBeDefined();
      expect(typeof mod.getRecentScansForBriefing).toBe('function');
    });
  });

  // ─── Sector Normalization Logic ──────────────────────────────────────────
  describe('Sector Normalization', () => {
    it('should handle the briefing engine with no scanId (uses latest scan)', async () => {
      const mod = await import('./lib/executive-threat-briefing');
      const result = await mod.computeExecutiveThreatBriefing({});
      expect(result).toBeDefined();
      expect(result).toHaveProperty('scan');
      expect(result).toHaveProperty('matchedActors');
      expect(result).toHaveProperty('summary');
      expect(result).toHaveProperty('trends');
      expect(result).toHaveProperty('carverProfile');
      expect(result).toHaveProperty('lastUpdated');
    });

    it('should return a valid summary structure', async () => {
      const mod = await import('./lib/executive-threat-briefing');
      const result = await mod.computeExecutiveThreatBriefing({});
      const { summary } = result;
      expect(summary).toHaveProperty('totalMatched');
      expect(summary).toHaveProperty('criticalActors');
      expect(summary).toHaveProperty('highActors');
      expect(summary).toHaveProperty('topAttackVectors');
      expect(summary).toHaveProperty('sectorRiskLevel');
      expect(summary).toHaveProperty('avgRelevanceScore');
      expect(typeof summary.totalMatched).toBe('number');
      expect(typeof summary.avgRelevanceScore).toBe('number');
      expect(Array.isArray(summary.topAttackVectors)).toBe(true);
    });

    it('should return matched actors with proper structure', async () => {
      const mod = await import('./lib/executive-threat-briefing');
      const result = await mod.computeExecutiveThreatBriefing({ limit: 5 });
      if (result.matchedActors.length > 0) {
        const actor = result.matchedActors[0];
        expect(actor).toHaveProperty('actorId');
        expect(actor).toHaveProperty('name');
        expect(actor).toHaveProperty('relevanceScore');
        expect(actor).toHaveProperty('relevanceFactors');
        expect(actor).toHaveProperty('matchedSectors');
        expect(actor).toHaveProperty('topTechniques');
        expect(actor).toHaveProperty('recommendedActions');
        expect(actor).toHaveProperty('attackVectors');
        expect(actor).toHaveProperty('iocCount');
        expect(typeof actor.relevanceScore).toBe('number');
        expect(actor.relevanceScore).toBeGreaterThanOrEqual(0);
        expect(actor.relevanceScore).toBeLessThanOrEqual(100);
      }
    });

    it('should return actors sorted by relevance score descending', async () => {
      const mod = await import('./lib/executive-threat-briefing');
      const result = await mod.computeExecutiveThreatBriefing({ limit: 15 });
      for (let i = 1; i < result.matchedActors.length; i++) {
        expect(result.matchedActors[i - 1].relevanceScore).toBeGreaterThanOrEqual(
          result.matchedActors[i].relevanceScore
        );
      }
    });

    it('should respect the limit parameter', async () => {
      const mod = await import('./lib/executive-threat-briefing');
      const result = await mod.computeExecutiveThreatBriefing({ limit: 5 });
      expect(result.matchedActors.length).toBeLessThanOrEqual(5);
    });

    it('should return relevance factors that sum to the relevance score', async () => {
      const mod = await import('./lib/executive-threat-briefing');
      const result = await mod.computeExecutiveThreatBriefing({ limit: 5 });
      for (const actor of result.matchedActors) {
        const { relevanceFactors: f } = actor;
        const rawSum = f.sectorMatch + f.threatLevelWeight + f.carverAlignment + f.recentActivity + f.iocOverlap;
        // Score is capped at 100
        expect(actor.relevanceScore).toBe(Math.min(100, Math.round(rawSum)));
      }
    });
  });

  // ─── Sector-specific Matching ────────────────────────────────────────────
  describe('Sector-specific Matching', () => {
    it('should match actors when sector is provided', async () => {
      const mod = await import('./lib/executive-threat-briefing');
      const result = await mod.computeExecutiveThreatBriefing({ sector: 'Technology' });
      expect(result.summary.totalMatched).toBeGreaterThan(0);
    });

    it('should match government-targeting actors for government sector', async () => {
      const mod = await import('./lib/executive-threat-briefing');
      const result = await mod.computeExecutiveThreatBriefing({ sector: 'Government' });
      // Government is a heavily targeted sector, should have matches
      expect(result.summary.totalMatched).toBeGreaterThan(0);
    });
  });

  // ─── Trends ──────────────────────────────────────────────────────────────
  describe('Trends', () => {
    it('should return eventsByMonth with proper structure', async () => {
      const mod = await import('./lib/executive-threat-briefing');
      const result = await mod.computeExecutiveThreatBriefing({});
      for (const entry of result.trends.eventsByMonth) {
        expect(entry).toHaveProperty('month');
        expect(entry).toHaveProperty('count');
        expect(entry).toHaveProperty('critical');
        expect(entry).toHaveProperty('high');
        expect(typeof entry.count).toBe('number');
      }
    });

    it('should return actorActivityTrend with valid trend values', async () => {
      const mod = await import('./lib/executive-threat-briefing');
      const result = await mod.computeExecutiveThreatBriefing({});
      for (const entry of result.trends.actorActivityTrend) {
        expect(entry).toHaveProperty('actorId');
        expect(entry).toHaveProperty('name');
        expect(entry).toHaveProperty('eventsLast30d');
        expect(entry).toHaveProperty('eventsLast90d');
        expect(entry).toHaveProperty('trend');
        expect(['rising', 'stable', 'declining']).toContain(entry.trend);
      }
    });
  });

  // ─── CARVER Profile ──────────────────────────────────────────────────────
  describe('CARVER Profile', () => {
    it('should return CARVER profile when scan has CARVER data', async () => {
      const mod = await import('./lib/executive-threat-briefing');
      const result = await mod.computeExecutiveThreatBriefing({});
      if (result.carverProfile) {
        expect(result.carverProfile).toHaveProperty('avgCriticality');
        expect(result.carverProfile).toHaveProperty('avgVulnerability');
        expect(result.carverProfile).toHaveProperty('avgAccessibility');
        expect(result.carverProfile).toHaveProperty('avgEffect');
        expect(result.carverProfile).toHaveProperty('avgRecuperability');
        expect(result.carverProfile).toHaveProperty('avgRecognizability');
        expect(result.carverProfile).toHaveProperty('priorityBreakdown');
        expect(result.carverProfile).toHaveProperty('topThreatLikelihoods');
        expect(typeof result.carverProfile.avgCriticality).toBe('number');
      }
    });
  });

  // ─── Briefing Scans Selector ─────────────────────────────────────────────
  describe('Briefing Scans Selector', () => {
    it('should return recent completed scans', async () => {
      const mod = await import('./lib/executive-threat-briefing');
      const scans = await mod.getRecentScansForBriefing();
      expect(Array.isArray(scans)).toBe(true);
      if (scans.length > 0) {
        expect(scans[0]).toHaveProperty('id');
        expect(scans[0]).toHaveProperty('domain');
        expect(scans[0]).toHaveProperty('sector');
        expect(scans[0]).toHaveProperty('status');
        expect(scans[0].status).toBe('completed');
      }
    });

    it('should return at most 30 scans', async () => {
      const mod = await import('./lib/executive-threat-briefing');
      const scans = await mod.getRecentScansForBriefing();
      expect(scans.length).toBeLessThanOrEqual(30);
    });
  });
});

// ─── Pipeline Trigger Endpoint Tests ──────────────────────────────────────────
describe('Pipeline Trigger Endpoints', () => {
  const PIPELINE_ENDPOINTS = [
    '/api/scheduled/dfir-bulk-ingest',
    '/api/scheduled/ioc-ttp-mapper',
    '/api/scheduled/catalog-enrichment',
    '/api/scheduled/playbook-promoter',
    '/api/scheduled/exploit-triage',
    '/api/scheduled/classify-actors',
  ];

  it('should have all 6 pipeline endpoints registered', async () => {
    for (const endpoint of PIPELINE_ENDPOINTS) {
      const res = await fetch(`http://localhost:3000${endpoint}`, { method: 'POST' });
      // Should get 200 (runs the pipeline) or 401 (auth required) — NOT 404
      expect(res.status).not.toBe(404);
    }
  });
});

// ─── tRPC Procedure Tests ─────────────────────────────────────────────────────
describe('tRPC Procedure Registration', () => {
  it('should have executiveDashboard.threatBriefing procedure', async () => {
    const res = await fetch('http://localhost:3000/api/trpc/executiveDashboard.threatBriefing');
    // Should return 401 (auth required) not 404
    expect(res.status).not.toBe(404);
  });

  it('should have executiveDashboard.briefingScans procedure', async () => {
    const res = await fetch('http://localhost:3000/api/trpc/executiveDashboard.briefingScans');
    expect(res.status).not.toBe(404);
  });

  it('should have threatIntel.triggerPipeline procedure', async () => {
    const res = await fetch('http://localhost:3000/api/trpc/threatIntel.triggerPipeline');
    expect(res.status).not.toBe(404);
  });

  it('should have threatIntel.refreshActorContext procedure', async () => {
    const res = await fetch('http://localhost:3000/api/trpc/threatIntel.refreshActorContext');
    expect(res.status).not.toBe(404);
  });
});
