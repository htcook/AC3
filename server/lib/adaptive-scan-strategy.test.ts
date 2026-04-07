import { describe, it, expect, beforeEach } from 'vitest';
import {
  computeAdaptiveStrategy,
  recordGraduationScores,
  recordConnectorPerformance,
  recordConnectorResults,
  getDomainHistory,
  applyConnectorStrategy,
  formatStrategySummary,
  _resetStores,
  type ConnectorPerformance,
  type SectorInsights,
} from './adaptive-scan-strategy';
import type { GraduationResult } from './post-pipeline-graduation';

describe('adaptive-scan-strategy', () => {
  beforeEach(() => {
    _resetStores();
  });

  function makeScores(overrides: Partial<GraduationResult['scores']> = {}): GraduationResult['scores'] {
    return {
      recon_analyst: 60,
      exploit_selector: 50,
      evasion_optimizer: 70,
      cognitive_core: 55,
      cloud_assessor: 30,
      supply_chain_analyst: 40,
      ...overrides,
    };
  }

  function makeSectorInsights(overrides?: Partial<SectorInsights>): SectorInsights {
    return {
      sector: 'fintech',
      sampleCount: 15,
      avgScores: makeScores({ recon_analyst: 65, cloud_assessor: 45 }),
      connectorAvgs: [
        { connector: 'shodan', avgObservations: 12, avgDurationMs: 3000, failureRate: 0.1, totalRuns: 10 },
        { connector: 'censys', avgObservations: 8, avgDurationMs: 4000, failureRate: 0.2, totalRuns: 8 },
        { connector: 'cloud_assets', avgObservations: 6, avgDurationMs: 5000, failureRate: 0.05, totalRuns: 12 },
        { connector: 'github_leaks', avgObservations: 3, avgDurationMs: 2000, failureRate: 0.5, totalRuns: 6 },
      ],
      ...overrides,
    };
  }

  // ─── Recording + History ──────────────────────────────────────────

  describe('recordGraduationScores + getDomainHistory', () => {
    it('should store and retrieve graduation scores', () => {
      recordGraduationScores('example.com', makeScores());
      const history = getDomainHistory('example.com');
      expect(history).not.toBeNull();
      expect(history!.avgGraduationScores).toBeDefined();
      expect(history!.avgGraduationScores!.recon_analyst).toBe(60);
    });

    it('should average multiple graduation scores', () => {
      recordGraduationScores('example.com', makeScores({ recon_analyst: 40 }));
      recordGraduationScores('example.com', makeScores({ recon_analyst: 80 }));
      const history = getDomainHistory('example.com');
      expect(history!.avgGraduationScores!.recon_analyst).toBe(60);
    });

    it('should be case-insensitive on domain', () => {
      recordGraduationScores('Example.COM', makeScores());
      const history = getDomainHistory('example.com');
      expect(history).not.toBeNull();
    });

    it('should accept opts with sector and scanId', () => {
      recordGraduationScores('sector.com', makeScores(), { sector: 'fintech', scanId: 42 });
      const history = getDomainHistory('sector.com');
      expect(history).not.toBeNull();
      expect(history!.avgGraduationScores!.recon_analyst).toBe(60);
    });
  });

  describe('recordConnectorPerformance + recordConnectorResults', () => {
    it('should store connector performance', () => {
      recordConnectorPerformance({
        connector: 'shodan',
        domain: 'example.com',
        observations: 15,
        durationMs: 3000,
        status: 'completed',
        scanId: 1,
        timestamp: Date.now(),
      });
      const history = getDomainHistory('example.com');
      expect(history!.connectorPerformance).toHaveLength(1);
      expect(history!.connectorPerformance[0].connector).toBe('shodan');
    });

    it('should bulk record from connector results', () => {
      recordConnectorResults('example.com', 1, [
        { connector: 'shodan', observations: [1, 2, 3], errors: [], durationMs: 2000, rateLimited: false },
        { connector: 'censys', observations: [], errors: ['Hard timeout: exceeded 30s'], durationMs: 30000, rateLimited: false },
        { connector: 'crtsh', observations: [], errors: ['Skipped: No API key'], durationMs: 0, rateLimited: false },
        { connector: 'urlscan', observations: [], errors: ['Connection refused'], durationMs: 500, rateLimited: false },
      ]);
      const history = getDomainHistory('example.com');
      expect(history!.connectorPerformance).toHaveLength(4);
      const statuses = history!.connectorPerformance.map(p => p.status);
      expect(statuses).toContain('completed');
      expect(statuses).toContain('timeout');
      expect(statuses).toContain('skipped');
      expect(statuses).toContain('failed');
    });

    it('should accept sector parameter in recordConnectorResults', () => {
      recordConnectorResults('sector-test.com', 1, [
        { connector: 'shodan', observations: [1], errors: [], durationMs: 1000, rateLimited: false },
      ], 'healthcare');
      const history = getDomainHistory('sector-test.com');
      expect(history!.connectorPerformance).toHaveLength(1);
    });
  });

  // ─── Strategy — No History ────────────────────────────────────────

  describe('computeAdaptiveStrategy — no history', () => {
    it('should return a default strategy with 0 confidence', () => {
      const strategy = computeAdaptiveStrategy('new-domain.com');
      expect(strategy.confidence).toBe(0);
      expect(strategy.scanDepth.scanMode).toBe('standard');
      expect(strategy.scanDepth.maxConcurrent).toBe(5);
      expect(strategy.evasionPreset.name).toBe('standard');
      expect(strategy.focusAreas).toHaveLength(0);
      expect(strategy.basedOn.scanCount).toBe(0);
      expect(strategy.basedOn.sectorLearningApplied).toBe(false);
    });
  });

  // ─── Strategy — With History ──────────────────────────────────────

  describe('computeAdaptiveStrategy — with history', () => {
    it('should increase depth for high recon_analyst scores', () => {
      recordGraduationScores('deep.com', makeScores({ recon_analyst: 85 }));
      const strategy = computeAdaptiveStrategy('deep.com');
      expect(strategy.scanDepth.maxConcurrent).toBeGreaterThan(5);
      expect(strategy.scanDepth.enableRecursiveDiscovery).toBe(true);
      expect(strategy.scanDepth.recursiveDepth).toBe(3);
    });

    it('should maximize breadth for low recon_analyst scores', () => {
      recordGraduationScores('broad.com', makeScores({ recon_analyst: 20 }));
      const strategy = computeAdaptiveStrategy('broad.com');
      expect(strategy.scanDepth.maxConcurrent).toBe(10);
      expect(strategy.scanDepth.enableRecursiveDiscovery).toBe(false);
    });

    it('should enable active mode for high cognitive_core with enough history', () => {
      for (let i = 0; i < 3; i++) {
        recordGraduationScores('smart.com', makeScores({ cognitive_core: 90 }));
      }
      const strategy = computeAdaptiveStrategy('smart.com');
      expect(strategy.scanDepth.scanMode).toBe('active');
    });

    it('should respect forceScanMode override', () => {
      for (let i = 0; i < 3; i++) {
        recordGraduationScores('forced.com', makeScores({ cognitive_core: 90 }));
      }
      const strategy = computeAdaptiveStrategy('forced.com', { forceScanMode: 'strict_passive' });
      expect(strategy.scanDepth.scanMode).toBe('strict_passive');
    });

    it('should identify cloud focus area when cloud_assessor is low', () => {
      recordGraduationScores('cloudy.com', makeScores({ cloud_assessor: 10 }));
      const strategy = computeAdaptiveStrategy('cloudy.com');
      const cloudArea = strategy.focusAreas.find(a => a.area.includes('Cloud'));
      expect(cloudArea).toBeDefined();
      expect(cloudArea!.priority).toBe('high');
    });

    it('should identify supply chain focus area when supply_chain_analyst is low', () => {
      recordGraduationScores('supply.com', makeScores({ supply_chain_analyst: 15 }));
      const strategy = computeAdaptiveStrategy('supply.com');
      const scArea = strategy.focusAreas.find(a => a.area.includes('Supply Chain'));
      expect(scArea).toBeDefined();
      expect(scArea!.priority).toBe('high');
    });

    it('should select no evasion for high evasion_optimizer', () => {
      recordGraduationScores('clean.com', makeScores({ evasion_optimizer: 90 }));
      const strategy = computeAdaptiveStrategy('clean.com');
      expect(strategy.evasionPreset.name).toBe('none');
    });

    it('should select aggressive evasion for low evasion_optimizer', () => {
      recordGraduationScores('waf.com', makeScores({ evasion_optimizer: 30 }));
      const strategy = computeAdaptiveStrategy('waf.com');
      expect(strategy.evasionPreset.name).toBe('aggressive');
      expect(strategy.evasionPreset.requestDelayMs).toBeGreaterThan(0);
      expect(strategy.evasionPreset.randomizeOrder).toBe(true);
    });
  });

  // ─── Connector Ranking ────────────────────────────────────────────

  describe('connector ranking', () => {
    it('should rank connectors higher that historically yield more observations', () => {
      for (let i = 0; i < 3; i++) {
        recordConnectorPerformance({
          connector: 'shodan', domain: 'ranked.com', observations: 20,
          durationMs: 2000, status: 'completed', scanId: i, timestamp: Date.now(),
        });
      }
      for (let i = 0; i < 3; i++) {
        recordConnectorPerformance({
          connector: 'censys', domain: 'ranked.com', observations: 0,
          durationMs: 30000, status: 'failed', scanId: i, timestamp: Date.now(),
        });
      }
      recordGraduationScores('ranked.com', makeScores());
      const strategy = computeAdaptiveStrategy('ranked.com');
      const shodanRank = strategy.connectorRanking.find(r => r.connector === 'shodan');
      const censysRank = strategy.connectorRanking.find(r => r.connector === 'censys');
      expect(shodanRank!.score).toBeGreaterThan(censysRank!.score);
    });

    it('should auto-exclude connectors with >80% failure rate over 3+ runs', () => {
      for (let i = 0; i < 4; i++) {
        recordConnectorPerformance({
          connector: 'broken_connector', domain: 'exclude.com', observations: 0,
          durationMs: 30000, status: 'failed', scanId: i, timestamp: Date.now(),
        });
      }
      const strategy = computeAdaptiveStrategy('exclude.com');
      const broken = strategy.connectorRanking.find(r => r.connector === 'broken_connector');
      expect(broken).toBeDefined();
      expect(broken!.include).toBe(false);
      expect(broken!.reason).toContain('Auto-excluded');
    });

    it('should respect forceInclude even for auto-excluded connectors', () => {
      for (let i = 0; i < 4; i++) {
        recordConnectorPerformance({
          connector: 'broken_connector', domain: 'force.com', observations: 0,
          durationMs: 30000, status: 'failed', scanId: i, timestamp: Date.now(),
        });
      }
      const strategy = computeAdaptiveStrategy('force.com', { forceInclude: ['broken_connector'] });
      const broken = strategy.connectorRanking.find(r => r.connector === 'broken_connector');
      expect(broken!.include).toBe(true);
    });

    it('should respect forceExclude', () => {
      recordConnectorPerformance({
        connector: 'shodan', domain: 'noforce.com', observations: 20,
        durationMs: 2000, status: 'completed', scanId: 1, timestamp: Date.now(),
      });
      const strategy = computeAdaptiveStrategy('noforce.com', { forceExclude: ['shodan'] });
      const shodan = strategy.connectorRanking.find(r => r.connector === 'shodan');
      expect(shodan!.include).toBe(false);
    });

    it('should boost cloud connectors when cloud_assessor is low', () => {
      recordGraduationScores('cloudgap.com', makeScores({ cloud_assessor: 10 }));
      const strategy = computeAdaptiveStrategy('cloudgap.com');
      const cloudConn = strategy.connectorRanking.find(r => r.connector === 'cloud_assets');
      expect(cloudConn).toBeDefined();
      expect(cloudConn!.reason).toContain('low cloud_assessor');
    });
  });

  // ─── Cross-Domain Sector Learning ─────────────────────────────────

  describe('sector learning', () => {
    it('should apply sector insights when domain has no history', () => {
      const sectorInsights = makeSectorInsights();
      const strategy = computeAdaptiveStrategy('new-fintech.com', { sector: 'fintech' }, sectorInsights);

      expect(strategy.basedOn.sectorLearningApplied).toBe(true);
      expect(strategy.basedOn.sectorSampleCount).toBe(15);
      expect(strategy.rationale.some(r => r.includes('Sector learning'))).toBe(true);
    });

    it('should use sector avg scores for scan depth when no domain history', () => {
      const sectorInsights = makeSectorInsights({
        avgScores: makeScores({ recon_analyst: 80 }),
      });
      const strategy = computeAdaptiveStrategy('new-sector.com', { sector: 'fintech' }, sectorInsights);

      // recon_analyst=80 should trigger DEEP scan depth
      expect(strategy.scanDepth.maxConcurrent).toBeGreaterThan(5);
      expect(strategy.scanDepth.enableRecursiveDiscovery).toBe(true);
    });

    it('should use sector avg scores for evasion when no domain history', () => {
      const sectorInsights = makeSectorInsights({
        avgScores: makeScores({ evasion_optimizer: 25 }),
      });
      const strategy = computeAdaptiveStrategy('new-evasion.com', { sector: 'fintech' }, sectorInsights);

      expect(strategy.evasionPreset.name).toBe('aggressive');
    });

    it('should use sector avg scores for focus areas when no domain history', () => {
      const sectorInsights = makeSectorInsights({
        avgScores: makeScores({ cloud_assessor: 10, supply_chain_analyst: 15 }),
      });
      const strategy = computeAdaptiveStrategy('new-focus.com', { sector: 'fintech' }, sectorInsights);

      expect(strategy.focusAreas.length).toBeGreaterThan(0);
      const cloudArea = strategy.focusAreas.find(a => a.area.includes('Cloud'));
      expect(cloudArea).toBeDefined();
    });

    it('should use sector connector avgs for ranking when no domain history', () => {
      const sectorInsights = makeSectorInsights({
        connectorAvgs: [
          { connector: 'shodan', avgObservations: 20, avgDurationMs: 2000, failureRate: 0.05, totalRuns: 20 },
          { connector: 'github_leaks', avgObservations: 1, avgDurationMs: 8000, failureRate: 0.7, totalRuns: 10 },
        ],
      });
      const strategy = computeAdaptiveStrategy('new-ranking.com', { sector: 'fintech' }, sectorInsights);

      const shodanRank = strategy.connectorRanking.find(r => r.connector === 'shodan');
      const githubRank = strategy.connectorRanking.find(r => r.connector === 'github_leaks');
      expect(shodanRank!.score).toBeGreaterThan(githubRank!.score);
      expect(shodanRank!.reason).toContain('[sector]');
    });

    it('should give sector-based boost to connectors with high sector runs and observations', () => {
      const sectorInsights = makeSectorInsights({
        connectorAvgs: [
          { connector: 'cloud_assets', avgObservations: 8, avgDurationMs: 3000, failureRate: 0.02, totalRuns: 15 },
        ],
      });
      const strategy = computeAdaptiveStrategy('sector-boost.com', { sector: 'fintech' }, sectorInsights);
      const cloudConn = strategy.connectorRanking.find(r => r.connector === 'cloud_assets');
      expect(cloudConn!.reason).toContain('Sector boost');
    });

    it('should prefer domain history over sector insights when both available', () => {
      recordGraduationScores('existing.com', makeScores({ recon_analyst: 20 }));
      const sectorInsights = makeSectorInsights({
        avgScores: makeScores({ recon_analyst: 80 }),
      });
      const strategy = computeAdaptiveStrategy('existing.com', { sector: 'fintech' }, sectorInsights);

      // Domain history (recon=20) should take precedence over sector (recon=80)
      expect(strategy.basedOn.sectorLearningApplied).toBe(false);
      expect(strategy.scanDepth.maxConcurrent).toBe(10); // BROAD mode for low recon
    });

    it('should have partial confidence from sector data alone', () => {
      const sectorInsights = makeSectorInsights({ sampleCount: 8 });
      const strategy = computeAdaptiveStrategy('sector-only.com', { sector: 'fintech' }, sectorInsights);

      expect(strategy.confidence).toBeGreaterThan(0);
      expect(strategy.confidence).toBeLessThanOrEqual(0.5);
    });

    it('should not auto-exclude connectors based on sector failure rate (only domain-level)', () => {
      const sectorInsights = makeSectorInsights({
        connectorAvgs: [
          { connector: 'bad_sector_conn', avgObservations: 0, avgDurationMs: 30000, failureRate: 0.95, totalRuns: 10 },
        ],
      });
      const strategy = computeAdaptiveStrategy('sector-noexclude.com', { sector: 'fintech' }, sectorInsights);
      const conn = strategy.connectorRanking.find(r => r.connector === 'bad_sector_conn');
      // Should still be included (auto-exclude only applies to domain-level data)
      // Score will be low but not auto-excluded
      expect(conn!.reason).not.toContain('Auto-excluded');
    });
  });

  // ─── basedOn metadata ─────────────────────────────────────────────

  describe('basedOn metadata', () => {
    it('should track sectorLearningApplied and sectorSampleCount', () => {
      const sectorInsights = makeSectorInsights({ sampleCount: 25 });
      const strategy = computeAdaptiveStrategy('meta.com', { sector: 'fintech' }, sectorInsights);
      expect(strategy.basedOn.sectorLearningApplied).toBe(true);
      expect(strategy.basedOn.sectorSampleCount).toBe(25);
    });

    it('should show sectorLearningApplied=false when domain has history', () => {
      recordGraduationScores('has-history.com', makeScores());
      const sectorInsights = makeSectorInsights();
      const strategy = computeAdaptiveStrategy('has-history.com', { sector: 'fintech' }, sectorInsights);
      expect(strategy.basedOn.sectorLearningApplied).toBe(false);
      expect(strategy.basedOn.graduationDataAvailable).toBe(true);
    });
  });

  // ─── applyConnectorStrategy ───────────────────────────────────────

  describe('applyConnectorStrategy', () => {
    it('should filter and reorder connectors based on strategy', () => {
      for (let i = 0; i < 4; i++) {
        recordConnectorPerformance({
          connector: 'bad', domain: 'apply.com', observations: 0,
          durationMs: 30000, status: 'failed', scanId: i, timestamp: Date.now(),
        });
      }
      recordConnectorPerformance({
        connector: 'good', domain: 'apply.com', observations: 25,
        durationMs: 1000, status: 'completed', scanId: 5, timestamp: Date.now(),
      });
      const strategy = computeAdaptiveStrategy('apply.com');
      const connectors = [
        { name: 'bad', collect: () => {} },
        { name: 'good', collect: () => {} },
        { name: 'unknown', collect: () => {} },
      ];
      const result = applyConnectorStrategy(connectors, strategy);
      expect(result.find(c => c.name === 'bad')).toBeUndefined();
      expect(result[0].name).toBe('good');
    });
  });

  // ─── formatStrategySummary ────────────────────────────────────────

  describe('formatStrategySummary', () => {
    it('should produce a readable summary string', () => {
      recordGraduationScores('summary.com', makeScores());
      const strategy = computeAdaptiveStrategy('summary.com');
      const summary = formatStrategySummary(strategy);
      expect(summary).toContain('[AdaptiveStrategy]');
      expect(summary).toContain('Confidence:');
      expect(summary).toContain('Scan depth:');
      expect(summary).toContain('Evasion:');
      expect(summary).toContain('Connectors:');
    });

    it('should include sector learning info when applied', () => {
      const sectorInsights = makeSectorInsights();
      const strategy = computeAdaptiveStrategy('sector-summary.com', { sector: 'fintech' }, sectorInsights);
      const summary = formatStrategySummary(strategy);
      expect(summary).toContain('sector');
    });
  });

  // ─── Confidence Scaling ───────────────────────────────────────────

  describe('confidence scaling', () => {
    it('should scale confidence with scan count up to 1.0', () => {
      for (let i = 0; i < 10; i++) {
        recordGraduationScores('confident.com', makeScores());
      }
      const strategy = computeAdaptiveStrategy('confident.com');
      expect(strategy.confidence).toBe(1);
    });

    it('should have partial confidence with fewer scans', () => {
      recordGraduationScores('partial.com', makeScores());
      recordGraduationScores('partial.com', makeScores());
      const strategy = computeAdaptiveStrategy('partial.com');
      expect(strategy.confidence).toBeGreaterThan(0);
      expect(strategy.confidence).toBeLessThan(1);
    });
  });
});
