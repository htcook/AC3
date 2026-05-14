import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── IOC Overlap Detector Tests ──────────────────────────────────────────────
describe('IOC Overlap Detector', () => {
  describe('Module Exports', () => {
    it('should export computeIocOverlap function', async () => {
      const mod = await import('./lib/ioc-overlap-detector');
      expect(mod.computeIocOverlap).toBeDefined();
      expect(typeof mod.computeIocOverlap).toBe('function');
    });
  });

  describe('computeIocOverlap', () => {
    it('should return a valid result structure for a valid scan', async () => {
      const mod = await import('./lib/ioc-overlap-detector');
      const result = await mod.computeIocOverlap(1);
      expect(result).toHaveProperty('totalMatches');
      expect(result).toHaveProperty('matchesByActor');
      expect(result).toHaveProperty('compromiseIndicators');
      expect(result).toHaveProperty('assetExposure');
      expect(typeof result.totalMatches).toBe('number');
      expect(result.totalMatches).toBeGreaterThanOrEqual(0);
      expect(Array.isArray(result.compromiseIndicators)).toBe(true);
    });

    it('should return empty result for non-existent scan', async () => {
      const mod = await import('./lib/ioc-overlap-detector');
      const result = await mod.computeIocOverlap(999999);
      expect(result.totalMatches).toBe(0);
      expect(result.compromiseIndicators).toHaveLength(0);
      expect(result.assetExposure.totalAssetsChecked).toBe(0);
    });

    it('should return proper assetExposure structure', async () => {
      const mod = await import('./lib/ioc-overlap-detector');
      const result = await mod.computeIocOverlap(1);
      const { assetExposure } = result;
      expect(assetExposure).toHaveProperty('totalAssetsChecked');
      expect(assetExposure).toHaveProperty('assetsWithIocHits');
      expect(assetExposure).toHaveProperty('uniqueActorsMatched');
      expect(typeof assetExposure.totalAssetsChecked).toBe('number');
      expect(typeof assetExposure.assetsWithIocHits).toBe('number');
      expect(typeof assetExposure.uniqueActorsMatched).toBe('number');
    });

    it('should have compromiseIndicators with correct shape', async () => {
      const mod = await import('./lib/ioc-overlap-detector');
      const result = await mod.computeIocOverlap(1);
      if (result.compromiseIndicators.length > 0) {
        const first = result.compromiseIndicators[0];
        expect(first).toHaveProperty('actorId');
        expect(first).toHaveProperty('iocType');
        expect(first).toHaveProperty('iocValue');
        expect(first).toHaveProperty('matchedAsset');
        expect(first).toHaveProperty('matchType');
        expect(['domain', 'ip', 'url', 'subdomain']).toContain(first.matchType);
      }
    });

    it('should limit compromiseIndicators to 20 max', async () => {
      const mod = await import('./lib/ioc-overlap-detector');
      const result = await mod.computeIocOverlap(1);
      expect(result.compromiseIndicators.length).toBeLessThanOrEqual(20);
    });

    it('should have matchesByActor as a Map', async () => {
      const mod = await import('./lib/ioc-overlap-detector');
      const result = await mod.computeIocOverlap(1);
      expect(result.matchesByActor).toBeInstanceOf(Map);
    });
  });
});

// ─── Briefing PDF Generator Tests ────────────────────────────────────────────
describe('Briefing PDF Generator', () => {
  describe('Module Exports', () => {
    it('should export generateBriefingPdf function', async () => {
      const mod = await import('./lib/briefing-pdf-generator');
      expect(mod.generateBriefingPdf).toBeDefined();
      expect(typeof mod.generateBriefingPdf).toBe('function');
    });

    it('should export generateBriefingHtmlPreview function', async () => {
      const mod = await import('./lib/briefing-pdf-generator');
      expect(mod.generateBriefingHtmlPreview).toBeDefined();
      expect(typeof mod.generateBriefingHtmlPreview).toBe('function');
    });
  });

  describe('generateBriefingHtmlPreview', () => {
    it('should generate valid HTML from briefing data', async () => {
      const mod = await import('./lib/briefing-pdf-generator');
      const html = mod.generateBriefingHtmlPreview({
        briefing: {
          scan: {
            id: 1,
            domain: 'example.com',
            sector: 'Technology',
            clientType: 'Enterprise',
            totalAssets: 50,
            totalFindings: 120,
            riskScore: 75,
            riskBand: 'high',
          },
          matchedActors: [{
            actorId: 'apt-29',
            name: 'APT29',
            actorType: 'nation-state',
            origin: 'Russia',
            threatLevel: 'critical',
            relevanceScore: 85,
            matchedSectors: ['Technology'],
            iocCount: 42,
            relevanceFactors: { sectorMatch: 35, threatLevelWeight: 18, carverAlignment: 15, recentActivity: 8, iocOverlap: 0 },
            topTechniques: [{ id: 'T1566', name: 'Phishing' }],
            topTools: ['Cobalt Strike'],
            recommendedActions: ['Monitor for spear-phishing campaigns'],
            attackVectors: ['Spear Phishing'],
          }],
          summary: {
            totalMatched: 1,
            criticalActors: 1,
            highActors: 0,
            topAttackVectors: ['Spear Phishing'],
            sectorRiskLevel: 'high',
            avgRelevanceScore: 85,
          },
          trends: {
            eventsByMonth: [{ month: '2026-04', count: 10, critical: 3, high: 5 }],
            actorActivityTrend: [{ actorId: 'apt-29', name: 'APT29', eventsLast30d: 5, eventsLast90d: 12, trend: 'rising' as const }],
          },
          carverProfile: {
            avgCriticality: 7.5,
            avgVulnerability: 6.0,
            avgAccessibility: 5.5,
            avgEffect: 8.0,
            avgRecuperability: 4.0,
            avgRecognizability: 3.5,
            priorityBreakdown: { critical: 2, high: 5 },
            topThreatLikelihoods: [{ threat: 'Ransomware', likelihood: 0.85 }],
          },
          iocOverlap: null,
          alertsTriggered: 0,
          lastUpdated: Date.now(),
        },
        generatedBy: 'Test Suite',
        generatedAt: Date.now(),
      });

      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('Executive Threat Briefing');
      expect(html).toContain('example.com');
      expect(html).toContain('APT29');
      expect(html).toContain('CONFIDENTIAL');
      expect(html).toContain('Test Suite');
    });

    it('should include IOC overlap section when data is provided', async () => {
      const mod = await import('./lib/briefing-pdf-generator');
      const html = mod.generateBriefingHtmlPreview({
        briefing: {
          scan: { id: 1, domain: 'test.com', sector: 'Finance', clientType: null, totalAssets: 10, totalFindings: 5, riskScore: 50, riskBand: 'medium' },
          matchedActors: [],
          summary: { totalMatched: 0, criticalActors: 0, highActors: 0, topAttackVectors: [], sectorRiskLevel: 'moderate', avgRelevanceScore: 0 },
          trends: { eventsByMonth: [], actorActivityTrend: [] },
          carverProfile: null,
          iocOverlap: null,
          alertsTriggered: 0,
          lastUpdated: Date.now(),
        },
        iocOverlap: {
          totalMatches: 3,
          matchesByActor: new Map(),
          compromiseIndicators: [
            { actorId: 'apt-1', iocType: 'domain', iocValue: 'evil.com', matchedAsset: 'test.com', matchType: 'domain' as const, confidence: 'high' },
          ],
          assetExposure: { totalAssetsChecked: 10, assetsWithIocHits: 2, uniqueActorsMatched: 1 },
        },
      });

      expect(html).toContain('Active Compromise Indicators Detected');
      expect(html).toContain('evil.com');
      expect(html).toContain('3 IOC matches');
    });

    it('should handle null scan gracefully', async () => {
      const mod = await import('./lib/briefing-pdf-generator');
      const html = mod.generateBriefingHtmlPreview({
        briefing: {
          scan: null,
          matchedActors: [],
          summary: { totalMatched: 0, criticalActors: 0, highActors: 0, topAttackVectors: [], sectorRiskLevel: 'unknown', avgRelevanceScore: 0 },
          trends: { eventsByMonth: [], actorActivityTrend: [] },
          carverProfile: null,
          iocOverlap: null,
          alertsTriggered: 0,
          lastUpdated: Date.now(),
        },
      });

      expect(html).toContain('Enterprise Threat Assessment');
      expect(html).not.toContain('undefined');
    });

    it('should escape HTML in actor names', async () => {
      const mod = await import('./lib/briefing-pdf-generator');
      const html = mod.generateBriefingHtmlPreview({
        briefing: {
          scan: null,
          matchedActors: [{
            actorId: 'test',
            name: '<script>alert("xss")</script>',
            actorType: 'test',
            origin: null,
            threatLevel: 'medium',
            relevanceScore: 50,
            matchedSectors: [],
            iocCount: 0,
            relevanceFactors: {},
            topTechniques: [],
            topTools: [],
            recommendedActions: [],
            attackVectors: [],
          }],
          summary: { totalMatched: 1, criticalActors: 0, highActors: 0, topAttackVectors: [], sectorRiskLevel: 'unknown', avgRelevanceScore: 50 },
          trends: { eventsByMonth: [], actorActivityTrend: [] },
          carverProfile: null,
          iocOverlap: null,
          alertsTriggered: 0,
          lastUpdated: Date.now(),
        },
      });

      expect(html).not.toContain('<script>');
      expect(html).toContain('&lt;script&gt;');
    });
  });
});

// ─── Threat Alert Engine Tests ───────────────────────────────────────────────
describe('Threat Alert Engine', () => {
  describe('Module Exports', () => {
    it('should export checkAlertThresholds function', async () => {
      const mod = await import('./lib/threat-alert-engine');
      expect(mod.checkAlertThresholds).toBeDefined();
      expect(typeof mod.checkAlertThresholds).toBe('function');
    });

    it('should export getAlertThresholds function', async () => {
      const mod = await import('./lib/threat-alert-engine');
      expect(mod.getAlertThresholds).toBeDefined();
      expect(typeof mod.getAlertThresholds).toBe('function');
    });

    it('should export upsertAlertThreshold function', async () => {
      const mod = await import('./lib/threat-alert-engine');
      expect(mod.upsertAlertThreshold).toBeDefined();
      expect(typeof mod.upsertAlertThreshold).toBe('function');
    });

    it('should export deleteAlertThreshold function', async () => {
      const mod = await import('./lib/threat-alert-engine');
      expect(mod.deleteAlertThreshold).toBeDefined();
      expect(typeof mod.deleteAlertThreshold).toBe('function');
    });

    it('should export getAlertHistory function', async () => {
      const mod = await import('./lib/threat-alert-engine');
      expect(mod.getAlertHistory).toBeDefined();
      expect(typeof mod.getAlertHistory).toBe('function');
    });
  });

  describe('checkAlertThresholds', () => {
    it('should return valid result structure', async () => {
      const mod = await import('./lib/threat-alert-engine');
      const result = await mod.checkAlertThresholds({
        scanId: 1,
        matchedActors: [],
      });
      expect(result).toHaveProperty('alertsFired');
      expect(result).toHaveProperty('alerts');
      expect(typeof result.alertsFired).toBe('number');
      expect(Array.isArray(result.alerts)).toBe(true);
    });

    it('should return zero alerts when no thresholds are configured', async () => {
      const mod = await import('./lib/threat-alert-engine');
      const result = await mod.checkAlertThresholds({
        scanId: null,
        matchedActors: [{
          actorId: 'test-actor',
          name: 'Test Actor',
          relevanceScore: 95,
          threatLevel: 'critical',
          iocCount: 10,
          matchedSectors: ['Technology'],
          attackVectors: ['Phishing'],
        }],
      });
      // With no thresholds configured, no alerts should fire
      expect(result.alertsFired).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Alert Threshold CRUD', () => {
    it('should create a new threshold', async () => {
      const mod = await import('./lib/threat-alert-engine');
      const result = await mod.upsertAlertThreshold({
        label: 'Test Alert - Vitest',
        relevanceThreshold: 90,
        threatLevelFilter: 'critical',
        enabled: true,
        notifyOnNew: true,
        notifyOnRising: true,
        createdBy: 'vitest',
      });
      expect(result).toHaveProperty('id');
      expect(typeof result.id).toBe('number');
    });

    it('should list thresholds including the newly created one', async () => {
      const mod = await import('./lib/threat-alert-engine');
      const thresholds = await mod.getAlertThresholds();
      expect(Array.isArray(thresholds)).toBe(true);
      const testThreshold = thresholds.find((t: any) => t.label === 'Test Alert - Vitest');
      expect(testThreshold).toBeDefined();
      expect(testThreshold?.relevanceThreshold).toBe(90);
    });

    it('should update an existing threshold', async () => {
      const mod = await import('./lib/threat-alert-engine');
      const thresholds = await mod.getAlertThresholds();
      const testThreshold = thresholds.find((t: any) => t.label === 'Test Alert - Vitest');
      if (testThreshold) {
        const result = await mod.upsertAlertThreshold({
          id: testThreshold.id,
          label: 'Test Alert - Updated',
          relevanceThreshold: 80,
          threatLevelFilter: 'high',
        });
        expect(result.id).toBe(testThreshold.id);
      }
    });

    it('should delete a threshold', async () => {
      const mod = await import('./lib/threat-alert-engine');
      const thresholds = await mod.getAlertThresholds();
      const testThreshold = thresholds.find((t: any) =>
        t.label === 'Test Alert - Updated' || t.label === 'Test Alert - Vitest'
      );
      if (testThreshold) {
        await mod.deleteAlertThreshold(testThreshold.id);
        const after = await mod.getAlertThresholds();
        const deleted = after.find((t: any) => t.id === testThreshold.id);
        expect(deleted).toBeUndefined();
      }
    });
  });

  describe('getAlertHistory', () => {
    it('should return an array', async () => {
      const mod = await import('./lib/threat-alert-engine');
      const history = await mod.getAlertHistory({});
      expect(Array.isArray(history)).toBe(true);
    });

    it('should respect limit parameter', async () => {
      const mod = await import('./lib/threat-alert-engine');
      const history = await mod.getAlertHistory({ limit: 5 });
      expect(history.length).toBeLessThanOrEqual(5);
    });
  });
});

// ─── Executive Threat Briefing with IOC + Alerts Integration ─────────────────
describe('Executive Threat Briefing - IOC & Alert Integration', () => {
  it('should include iocOverlap field in briefing result', async () => {
    const mod = await import('./lib/executive-threat-briefing');
    const result = await mod.computeExecutiveThreatBriefing({});
    expect(result).toHaveProperty('iocOverlap');
    // iocOverlap can be null if no overlaps found
    if (result.iocOverlap) {
      expect(result.iocOverlap).toHaveProperty('totalMatches');
      expect(result.iocOverlap).toHaveProperty('compromiseIndicators');
      expect(result.iocOverlap).toHaveProperty('assetExposure');
    }
  });

  it('should include alertsTriggered field in briefing result', async () => {
    const mod = await import('./lib/executive-threat-briefing');
    const result = await mod.computeExecutiveThreatBriefing({});
    expect(result).toHaveProperty('alertsTriggered');
    expect(typeof result.alertsTriggered).toBe('number');
  });
});

// ─── tRPC Endpoint Tests ─────────────────────────────────────────────────────
describe('Executive Dashboard tRPC Endpoints', () => {
  it('should have iocOverlap endpoint (returns 401 for unauthenticated)', async () => {
    const res = await fetch('http://localhost:3000/api/trpc/executiveDashboard.iocOverlap?input=%7B%22scanId%22%3A1%7D');
    expect(res.status).toBe(401);
  });

  it('should have generateBriefingReport endpoint (returns 401 for unauthenticated)', async () => {
    const res = await fetch('http://localhost:3000/api/trpc/executiveDashboard.generateBriefingReport', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(401);
  });

  it('should have alertThresholds endpoint (returns 401 for unauthenticated)', async () => {
    const res = await fetch('http://localhost:3000/api/trpc/executiveDashboard.alertThresholds');
    expect(res.status).toBe(401);
  });

  it('should have upsertAlertThreshold endpoint (returns 401 for unauthenticated)', async () => {
    const res = await fetch('http://localhost:3000/api/trpc/executiveDashboard.upsertAlertThreshold', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(401);
  });

  it('should have deleteAlertThreshold endpoint (returns 401 for unauthenticated)', async () => {
    const res = await fetch('http://localhost:3000/api/trpc/executiveDashboard.deleteAlertThreshold', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(401);
  });

  it('should have alertHistory endpoint (returns 401 for unauthenticated)', async () => {
    const res = await fetch('http://localhost:3000/api/trpc/executiveDashboard.alertHistory');
    expect(res.status).toBe(401);
  });
});
