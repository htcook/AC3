/**
 * Tests for Architecture Enhancements from Expert Review
 * 
 * Covers:
 * 1. LLM Inference Optimizer (semantic cache, cost attribution, call-site tracking)
 * 2. Cross-Training Event Bus (bias correction, lineage, holdout validation)
 * 3. Enhanced CVE Matching (technique-vs-vuln distinction, confidence calibration)
 * 4. Operational Metrics (finding lineage, rule effectiveness, engagement metrics)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  SemanticInferenceCache,
  CallSiteVolumeTracker,
  estimateCost,
  buildCostReport,
  deduplicateBatch,
} from './lib/llm-inference-optimizer';
import {
  CrossTrainingEventBus,
  SignalLineageTracker,
  HoldoutValidationManager,
  computeBiasWeight,
  SOURCE_BIAS_PROFILES,
} from './lib/cross-training-event-bus';
import {
  analyzeCveMatch,
  computeCalibratedConfidence,
  detectCalibrationDrift,
} from './lib/cve-matching-enhanced';
import {
  FindingLineageTracker,
  DetectionRuleEffectivenessTracker,
  buildEngagementMetrics,
  compareEngagements,
} from './lib/operational-metrics';

// ─── Test Helpers ────────────────────────────────────────────────────────────

function makeOutcome(overrides: Partial<any> = {}): any {
  return {
    id: `outcome-${Math.random().toString(36).slice(2, 8)}`,
    outcome: 'accepted',
    vulnClass: 'SQL Injection',
    scannerUsed: 'sqlmap',
    detectionMethod: 'active',
    severity: 'high',
    reproductionQuality: 0.8,
    extractedPatterns: [],
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. LLM INFERENCE OPTIMIZER
// ═══════════════════════════════════════════════════════════════════════════════

describe('SemanticInferenceCache', () => {
  let cache: SemanticInferenceCache;
  
  beforeEach(() => {
    cache = new SemanticInferenceCache({ maxEntries: 100, defaultTtlMs: 60000 });
  });
  
  it('should compute stable semantic hashes for equivalent inputs', () => {
    const messages1 = [{ role: 'user', content: 'Analyze  this   vulnerability' }];
    const messages2 = [{ role: 'user', content: 'Analyze this vulnerability' }];
    
    const hash1 = cache.computeSemanticHash(messages1);
    const hash2 = cache.computeSemanticHash(messages2);
    
    expect(hash1).toBe(hash2); // Whitespace normalization
  });
  
  it('should strip timestamps from semantic hashes', () => {
    const messages1 = [{ role: 'user', content: 'Scan started at 2025-01-15T10:30:00Z' }];
    const messages2 = [{ role: 'user', content: 'Scan started at 2026-05-02T14:00:00Z' }];
    
    const hash1 = cache.computeSemanticHash(messages1);
    const hash2 = cache.computeSemanticHash(messages2);
    
    expect(hash1).toBe(hash2);
  });
  
  it('should strip UUIDs from semantic hashes', () => {
    const messages1 = [{ role: 'user', content: 'Finding 550e8400-e29b-41d4-a716-446655440000 details' }];
    const messages2 = [{ role: 'user', content: 'Finding a1b2c3d4-e5f6-7890-abcd-ef1234567890 details' }];
    
    const hash1 = cache.computeSemanticHash(messages1);
    const hash2 = cache.computeSemanticHash(messages2);
    
    expect(hash1).toBe(hash2);
  });
  
  it('should cache and retrieve responses', () => {
    const messages = [{ role: 'user', content: 'Analyze this SQL injection finding' }];
    
    // Miss
    const miss = cache.lookup(messages, 'test-caller');
    expect(miss).toBeNull();
    
    // Store
    cache.store(messages, 'This is a SQL injection', 'gpt-4o', 100, 50, 'test-caller');
    
    // Hit
    const hit = cache.lookup(messages, 'test-caller');
    expect(hit).not.toBeNull();
    expect(hit!.content).toBe('This is a SQL injection');
    expect(hit!.fromCache).toBe(true);
  });
  
  it('should not cache no-cache callers', () => {
    const messages = [{ role: 'user', content: 'Generate exploit for target' }];
    
    cache.store(messages, 'exploit code', 'gpt-4o', 100, 50, 'exploit-generator');
    const result = cache.lookup(messages, 'exploit-generator');
    
    expect(result).toBeNull();
  });
  
  it('should expire entries after TTL', () => {
    const cache = new SemanticInferenceCache({ maxEntries: 100, defaultTtlMs: 1 });
    const messages = [{ role: 'user', content: 'Test TTL expiration for cache entries' }];
    
    cache.store(messages, 'response', 'gpt-4o', 100, 50, 'test', undefined, 1);
    
    // Wait for TTL to expire
    const start = Date.now();
    while (Date.now() - start < 5) {} // Busy wait 5ms
    
    const result = cache.lookup(messages, 'test');
    expect(result).toBeNull();
  });
  
  it('should track cache statistics', () => {
    const messages = [{ role: 'user', content: 'Test cache statistics tracking functionality' }];
    
    cache.lookup(messages, 'test'); // Miss
    cache.store(messages, 'response', 'gpt-4o', 100, 50, 'test');
    cache.lookup(messages, 'test'); // Hit
    cache.lookup(messages, 'test'); // Hit
    
    const stats = cache.getStats();
    expect(stats.totalLookups).toBe(3);
    expect(stats.totalHits).toBe(2);
    expect(stats.totalMisses).toBe(1);
    expect(stats.hitRate).toBeCloseTo(2/3, 2);
  });
  
  it('should identify graduation candidates', () => {
    const messages = [{ role: 'user', content: 'Format this vulnerability report for output' }];
    
    cache.store(messages, 'formatted', 'gpt-4o', 100, 50, 'format-report');
    // Simulate multiple hits
    for (let i = 0; i < 6; i++) {
      cache.lookup(messages, 'format-report');
    }
    
    const candidates = cache.getGraduationCandidates(5);
    expect(candidates.length).toBeGreaterThanOrEqual(1);
    expect(candidates[0].caller).toBe('format-report');
  });
});

describe('estimateCost', () => {
  it('should compute correct cost for gpt-4o', () => {
    const cost = estimateCost(1_000_000, 500_000, 'gpt-4o');
    // 1M input * $2.50/1M + 500K output * $10.00/1M = $2.50 + $5.00 = $7.50
    expect(cost).toBeCloseTo(7.50, 2);
  });
  
  it('should compute correct cost for gpt-4o-mini', () => {
    const cost = estimateCost(1_000_000, 1_000_000, 'gpt-4o-mini');
    // 1M * $0.15 + 1M * $0.60 = $0.75
    expect(cost).toBeCloseTo(0.75, 2);
  });
  
  it('should fall back to gpt-4o pricing for unknown models', () => {
    const cost = estimateCost(1_000_000, 0, 'unknown-model');
    expect(cost).toBeCloseTo(2.50, 2);
  });
});

describe('buildCostReport', () => {
  it('should build a comprehensive cost report', () => {
    const telemetry = [
      { caller: 'scan-planner', model: 'gpt-4o', llmStatus: 'ok', latencyMs: 1500, tokensIn: 5000, tokensOut: 2000, calledAt: '2025-01-01T10:00:00Z' },
      { caller: 'scan-planner', model: 'gpt-4o', llmStatus: 'ok', latencyMs: 1200, tokensIn: 4000, tokensOut: 1500, calledAt: '2025-01-01T10:01:00Z' },
      { caller: 'vuln-classifier', model: 'gpt-4o-mini', llmStatus: 'ok', latencyMs: 500, tokensIn: 2000, tokensOut: 500, calledAt: '2025-01-01T10:02:00Z' },
      { caller: 'vuln-classifier', model: 'gpt-4o-mini', llmStatus: 'error', latencyMs: 30000, tokensIn: 2000, tokensOut: 0, calledAt: '2025-01-01T10:03:00Z' },
    ];
    
    const report = buildCostReport(1, telemetry, 5);
    
    expect(report.engagementId).toBe(1);
    expect(report.totalCalls).toBe(4);
    expect(report.assetCount).toBe(5);
    expect(report.callSiteBreakdown.length).toBe(2);
    expect(report.modelBreakdown.length).toBe(2);
    expect(report.totalEstimatedCost).toBeGreaterThan(0);
    expect(report.costPerAsset).toBe(report.totalEstimatedCost / 5);
  });
  
  it('should identify graduation candidates from high-volume callers', () => {
    const telemetry = Array.from({ length: 50 }, (_, i) => ({
      caller: i < 30 ? 'format-normalizer' : 'scan-planner',
      model: 'gpt-4o',
      llmStatus: 'ok',
      latencyMs: 500,
      tokensIn: 1000,
      tokensOut: 500,
      calledAt: new Date(Date.now() + i * 60000).toISOString(),
    }));
    
    const report = buildCostReport(1, telemetry, 10);
    
    // format-normalizer should be a graduation candidate (60% of calls + name matches pattern)
    expect(report.graduationCandidates.length).toBeGreaterThan(0);
    const formatCandidate = report.graduationCandidates.find(c => c.caller === 'format-normalizer');
    expect(formatCandidate).toBeDefined();
    expect(formatCandidate!.graduationConfidence).toBeGreaterThan(0.5);
  });
});

describe('deduplicateBatch', () => {
  it('should deduplicate semantically equivalent calls', () => {
    const calls = [
      { id: '1', messages: [{ role: 'user', content: 'Analyze  this  finding' }] },
      { id: '2', messages: [{ role: 'user', content: 'Analyze this finding' }] },
      { id: '3', messages: [{ role: 'user', content: 'Different question entirely' }] },
    ];
    
    const result = deduplicateBatch(calls);
    
    expect(result.unique.length).toBe(2);
    expect(result.duplicateCount).toBe(1);
    expect(result.deduplicationRate).toBeCloseTo(1/3, 2);
  });
});

describe('CallSiteVolumeTracker', () => {
  it('should track per-caller volume', () => {
    const tracker = new CallSiteVolumeTracker();
    
    tracker.recordCall('scan-planner', 1000, 500, false, 1);
    tracker.recordCall('scan-planner', 2000, 800, false, 1);
    tracker.recordCall('vuln-classifier', 500, 200, true, 1);
    
    const topCallers = tracker.getTopCallers();
    expect(topCallers.length).toBe(2);
    expect(topCallers[0].caller).toBe('scan-planner');
    expect(topCallers[0].calls).toBe(2);
  });
  
  it('should track per-engagement summary', () => {
    const tracker = new CallSiteVolumeTracker();
    
    tracker.recordCall('test', 1000, 500, false, 42);
    tracker.recordCall('test', 2000, 800, false, 42);
    
    const summary = tracker.getEngagementSummary(42);
    expect(summary).not.toBeNull();
    expect(summary!.totalCalls).toBe(2);
    expect(summary!.totalTokens).toBe(4300);
  });
  
  it('should detect anomalous high error rates', () => {
    const tracker = new CallSiteVolumeTracker();
    
    for (let i = 0; i < 20; i++) {
      tracker.recordCall('broken-caller', 100, 0, true); // All errors
    }
    
    const anomalies = tracker.detectAnomalies();
    const errorAnomaly = anomalies.find(a => a.anomalyType === 'high_error_rate');
    expect(errorAnomaly).toBeDefined();
    expect(errorAnomaly!.caller).toBe('broken-caller');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. CROSS-TRAINING EVENT BUS
// ═══════════════════════════════════════════════════════════════════════════════

describe('computeBiasWeight', () => {
  it('should apply lower weight to over-reported vuln classes from bug bounty', () => {
    const xssWeight = computeBiasWeight({
      source: 'bug_bounty',
      payload: makeOutcome({ vulnClass: 'Cross-Site Scripting', severity: 'high' }),
    });
    
    const businessLogicWeight = computeBiasWeight({
      source: 'bug_bounty',
      payload: makeOutcome({ vulnClass: 'Business Logic', severity: 'high' }),
    });
    
    // XSS is over-reported in bug bounty (bias 1.3), so weight should be lower
    // Business Logic is under-reported (bias 0.8), so weight should be higher
    expect(businessLogicWeight).toBeGreaterThan(xssWeight);
  });
  
  it('should give higher reliability to training lab data', () => {
    const labWeight = computeBiasWeight({
      source: 'training_lab',
      payload: makeOutcome({ severity: 'high' }),
    });
    
    const scanWeight = computeBiasWeight({
      source: 'vuln_scan',
      payload: makeOutcome({ severity: 'high' }),
    });
    
    expect(labWeight).toBeGreaterThan(scanWeight);
  });
  
  it('should boost weight for hard-to-demonstrate findings from biased sources', () => {
    const easyDemo = computeBiasWeight({
      source: 'bug_bounty',
      payload: makeOutcome({ reproductionQuality: 0.9 }),
    });
    
    const hardDemo = computeBiasWeight({
      source: 'bug_bounty',
      payload: makeOutcome({ reproductionQuality: 0.3 }),
    });
    
    // Hard-to-demonstrate findings from bug bounty (high demonstrability bias)
    // should get a boost because they survived despite the bias
    expect(hardDemo).toBeGreaterThan(easyDemo);
  });
});

describe('SignalLineageTracker', () => {
  it('should track lineage entries and retrieve by component', () => {
    const tracker = new SignalLineageTracker();
    
    tracker.record({
      eventId: 'evt-1',
      source: 'bug_bounty',
      consumer: 'calibration_pipeline',
      affectedComponent: 'nuclei:XSS:confidence',
      changeType: 'calibration_updated',
      valueBefore: 0.5,
      valueAfter: 0.6,
      biasWeight: 0.8,
      sourceMetadata: {},
    });
    
    tracker.record({
      eventId: 'evt-2',
      source: 'pentest_engagement',
      consumer: 'calibration_pipeline',
      affectedComponent: 'nuclei:XSS:confidence',
      changeType: 'calibration_updated',
      valueBefore: 0.6,
      valueAfter: 0.65,
      biasWeight: 0.9,
      sourceMetadata: {},
    });
    
    const lineage = tracker.getLineageForComponent('nuclei:XSS:confidence');
    expect(lineage.length).toBe(2);
    // Both entries are present, order depends on timestamp resolution
    const sources = lineage.map(l => l.source);
    expect(sources).toContain('bug_bounty');
    expect(sources).toContain('pentest_engagement');
  });
  
  it('should produce a lineage summary', () => {
    const tracker = new SignalLineageTracker();
    
    tracker.record({
      eventId: 'evt-1', source: 'bug_bounty', consumer: 'calibration',
      affectedComponent: 'sqlmap:SQLi:confidence', changeType: 'calibration_updated',
      biasWeight: 0.8, sourceMetadata: {},
    });
    tracker.record({
      eventId: 'evt-2', source: 'pentest_engagement', consumer: 'calibration',
      affectedComponent: 'sqlmap:SQLi:confidence', changeType: 'calibration_updated',
      biasWeight: 0.9, sourceMetadata: {},
    });
    
    const summary = tracker.getLineageSummary();
    expect(summary['sqlmap:SQLi:confidence']).toBeDefined();
    expect(summary['sqlmap:SQLi:confidence'].totalUpdates).toBe(2);
  });
});

describe('HoldoutValidationManager', () => {
  it('should not holdout until minimum outcomes reached', () => {
    const manager = new HoldoutValidationManager({ minOutcomesBeforeHoldout: 10 });
    
    // First 10 should never be holdout
    for (let i = 0; i < 10; i++) {
      const result = manager.shouldHoldout(makeOutcome({ id: `early-${i}` }));
      expect(result).toBe(false);
    }
  });
  
  it('should deterministically select holdout items', () => {
    const manager1 = new HoldoutValidationManager({ minOutcomesBeforeHoldout: 0, seed: 'test-seed' });
    const manager2 = new HoldoutValidationManager({ minOutcomesBeforeHoldout: 0, seed: 'test-seed' });
    
    const outcome = makeOutcome({ id: 'deterministic-test' });
    
    const result1 = manager1.shouldHoldout(outcome);
    const result2 = manager2.shouldHoldout(outcome);
    
    expect(result1).toBe(result2); // Same seed + same ID = same result
  });
  
  it('should track training vs holdout set sizes', () => {
    const manager = new HoldoutValidationManager({
      minOutcomesBeforeHoldout: 0,
      holdoutRate: 0.5,
    });
    
    for (let i = 0; i < 100; i++) {
      manager.routeOutcome(makeOutcome({ id: `item-${i}` }));
    }
    
    const stats = manager.getStats();
    expect(stats.trainingSize + stats.holdoutSize).toBe(100);
    // With 50% holdout rate, expect roughly even split (±20%)
    expect(stats.holdoutSize).toBeGreaterThan(20);
    expect(stats.holdoutSize).toBeLessThan(80);
  });
});

describe('CrossTrainingEventBus', () => {
  it('should publish events and dispatch to subscribers', () => {
    const bus = new CrossTrainingEventBus({ holdoutConfig: { minOutcomesBeforeHoldout: 1000 } });
    const received: any[] = [];
    
    bus.subscribe('finding_validated', (event) => {
      received.push(event);
    });
    
    bus.publish('bug_bounty', 'finding_validated', makeOutcome());
    
    expect(received.length).toBe(1);
    expect(received[0].source).toBe('bug_bounty');
    expect(received[0].biasWeight).toBeGreaterThan(0);
  });
  
  it('should apply bias weights to events', () => {
    const bus = new CrossTrainingEventBus({ holdoutConfig: { minOutcomesBeforeHoldout: 1000 } });
    
    const event = bus.publish('bug_bounty', 'finding_validated', makeOutcome());
    
    expect(event.biasWeight).toBeGreaterThan(0);
    expect(event.biasWeight).toBeLessThanOrEqual(1);
  });
  
  it('should track event statistics', () => {
    const bus = new CrossTrainingEventBus({ holdoutConfig: { minOutcomesBeforeHoldout: 1000 } });
    
    bus.publish('bug_bounty', 'finding_validated', makeOutcome());
    bus.publish('pentest_engagement', 'finding_rejected', makeOutcome({ outcome: 'rejected' }));
    bus.publish('vuln_scan', 'finding_validated', makeOutcome());
    
    const stats = bus.getStats();
    expect(stats.totalEventsPublished).toBe(3);
    expect(stats.eventsBySource['bug_bounty']).toBe(1);
    expect(stats.eventsBySource['pentest_engagement']).toBe(1);
    expect(stats.eventsBySource['vuln_scan']).toBe(1);
  });
  
  it('should support wildcard subscribers', () => {
    const bus = new CrossTrainingEventBus({ holdoutConfig: { minOutcomesBeforeHoldout: 1000 } });
    const received: any[] = [];
    
    bus.subscribe('*', (event) => received.push(event));
    
    bus.publish('bug_bounty', 'finding_validated', makeOutcome());
    bus.publish('pentest_engagement', 'finding_rejected', makeOutcome({ outcome: 'rejected' }));
    
    expect(received.length).toBe(2);
  });
  
  it('should return unsubscribe function', () => {
    const bus = new CrossTrainingEventBus({ holdoutConfig: { minOutcomesBeforeHoldout: 1000 } });
    const received: any[] = [];
    
    const unsub = bus.subscribe('finding_validated', (event) => received.push(event));
    
    bus.publish('bug_bounty', 'finding_validated', makeOutcome());
    expect(received.length).toBe(1);
    
    unsub();
    bus.publish('bug_bounty', 'finding_validated', makeOutcome());
    expect(received.length).toBe(1); // No new events after unsubscribe
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3. ENHANCED CVE MATCHING
// ═══════════════════════════════════════════════════════════════════════════════

describe('analyzeCveMatch', () => {
  it('should identify exact vulnerability match', () => {
    const result = analyzeCveMatch({
      findingVulnClass: 'SQL Injection',
      findingCwe: 'CWE-89',
      findingComponent: 'Apache Struts',
      findingVersion: '2.5.10',
      findingEndpoint: '/api/users',
      detectionMethod: 'active',
      exploitVerified: false,
      cveId: 'CVE-2017-5638',
      cveCwe: 'CWE-89',
      cveComponent: 'Apache Struts',
      cveAffectedVersions: '2.3.5 - 2.5.12',
      cveAttackVector: 'Remote code execution via SQL injection',
    });
    
    expect(result.matchType).toBe('exact_vulnerability');
    expect(result.confidence).toBeGreaterThan(0.8);
    expect(result.safeToPropagateForTraining).toBe(true);
  });
  
  it('should identify version-confirmed match without full evidence', () => {
    const result = analyzeCveMatch({
      findingVulnClass: 'Remote Code Execution',
      findingCwe: 'CWE-94',
      findingComponent: 'Apache Log4j',
      findingVersion: '2.14.1',
      detectionMethod: 'passive',
      exploitVerified: false,
      cveId: 'CVE-2021-44228',
      cveCwe: 'CWE-502',
      cveComponent: 'Apache Log4j',
      cveAffectedVersions: '2.0 - 2.14.1',
    });
    
    expect(result.matchType).toBe('version_confirmed');
    expect(result.confidence).toBeGreaterThan(0.5);
    expect(result.confidence).toBeLessThan(0.9); // Passive + no CWE match
  });
  
  it('should identify technique-only match (NOT a CVE match)', () => {
    const result = analyzeCveMatch({
      findingVulnClass: 'SQL Injection',
      findingCwe: 'CWE-89',
      findingComponent: 'Custom App',
      findingVersion: '1.0',
      detectionMethod: 'active',
      exploitVerified: false,
      cveId: 'CVE-2017-5638',
      cveCwe: 'CWE-89',
      cveComponent: 'Apache Struts',
      cveAffectedVersions: '2.3.5 - 2.5.12',
      cveAttackVector: 'SQL injection in content-type header',
      cveVulnClass: 'SQL Injection',
    });
    
    expect(result.matchType).toBe('technique_match');
    expect(result.confidence).toBeLessThan(0.65); // Should be lower confidence
    expect(result.explanation).toContain('TECHNIQUE MATCH ONLY');
    expect(result.explanation).toContain('DIFFERENT specific vulnerability');
  });
  
  it('should give highest confidence to exploit-verified exact matches', () => {
    const exploitVerified = analyzeCveMatch({
      findingVulnClass: 'SQL Injection',
      findingCwe: 'CWE-89',
      findingComponent: 'WordPress',
      findingVersion: '5.7.1',
      findingEndpoint: '/wp-admin/admin-ajax.php',
      detectionMethod: 'exploit_verified',
      exploitVerified: true,
      cveId: 'CVE-2021-12345',
      cveCwe: 'CWE-89',
      cveComponent: 'WordPress',
      cveAffectedVersions: '5.0 - 5.7.2',
    });
    
    const passiveOnly = analyzeCveMatch({
      findingVulnClass: 'SQL Injection',
      findingCwe: 'CWE-89',
      findingComponent: 'WordPress',
      findingVersion: '5.7.1',
      findingEndpoint: '/wp-admin/admin-ajax.php',
      detectionMethod: 'passive',
      exploitVerified: false,
      cveId: 'CVE-2021-12345',
      cveCwe: 'CWE-89',
      cveComponent: 'WordPress',
      cveAffectedVersions: '5.0 - 5.7.2',
    });
    
    expect(exploitVerified.confidence).toBeGreaterThan(passiveOnly.confidence);
  });
  
  it('should mark class-only matches as unsafe for training propagation', () => {
    const result = analyzeCveMatch({
      findingVulnClass: 'SQL Injection',
      detectionMethod: 'passive',
      exploitVerified: false,
      cveId: 'CVE-2023-99999',
      cveAttackVector: 'SQL injection in login form',
      cveVulnClass: 'SQL Injection',
    });
    
    // With matching vuln class and attack vector similarity > 0.4, this is a class_match
    // (no CWE match, no component match, no version)
    expect(['class_match', 'technique_match']).toContain(result.matchType);
    expect(result.safeToPropagateForTraining).toBe(false);
  });
});

describe('computeCalibratedConfidence', () => {
  it('should give passive detection lower confidence than active', () => {
    const evidence: any = {
      versionInRange: true,
      cweMatch: true,
      exploitVerified: false,
      endpointConfirmed: false,
      attackVectorSimilarity: 0.8,
      indicators: [],
    };
    
    const passive = computeCalibratedConfidence('version_confirmed', 'passive', evidence);
    const active = computeCalibratedConfidence('version_confirmed', 'active', evidence);
    
    expect(active.confidence).toBeGreaterThan(passive.confidence);
  });
  
  it('should penalize missing version confirmation', () => {
    const withVersion: any = {
      versionInRange: true, cweMatch: true, exploitVerified: false,
      endpointConfirmed: false, attackVectorSimilarity: 0.8, indicators: [],
    };
    const withoutVersion: any = {
      versionInRange: false, cweMatch: true, exploitVerified: false,
      endpointConfirmed: false, attackVectorSimilarity: 0.8, indicators: [],
    };
    
    const conf1 = computeCalibratedConfidence('exact_vulnerability', 'active', withVersion);
    const conf2 = computeCalibratedConfidence('exact_vulnerability', 'active', withoutVersion);
    
    expect(conf1.confidence).toBeGreaterThan(conf2.confidence);
  });
});

describe('detectCalibrationDrift', () => {
  it('should detect under-confident passive findings', () => {
    const matchResults = Array.from({ length: 20 }, () => ({
      matchResult: {
        cveId: 'CVE-2023-1234',
        matchType: 'version_confirmed' as const,
        detectionMethod: 'passive' as const,
        confidence: 0.40, // Platform scores low
        rawConfidence: 0.40,
        calibrationAdjustment: 0,
        evidence: {} as any,
        matchQuality: 0.5,
        safeToPropagateForTraining: true,
        explanation: '',
      },
      programOutcome: 'accepted' as const, // But programs accept them
    }));
    
    const drift = detectCalibrationDrift(matchResults);
    
    expect(drift.recalibrationRecommended).toBe(true);
    expect(drift.methodDrift.passive.drift).toBeGreaterThan(0.2);
    expect(drift.recommendations.length).toBeGreaterThan(0);
    expect(drift.recommendations[0]).toContain('UNDER-CONFIDENT');
  });
  
  it('should detect over-confident active findings', () => {
    const matchResults = Array.from({ length: 20 }, () => ({
      matchResult: {
        cveId: 'CVE-2023-5678',
        matchType: 'technique_match' as const,
        detectionMethod: 'active' as const,
        confidence: 0.85, // Platform scores high
        rawConfidence: 0.85,
        calibrationAdjustment: 0,
        evidence: {} as any,
        matchQuality: 0.5,
        safeToPropagateForTraining: true,
        explanation: '',
      },
      programOutcome: 'rejected' as const, // But programs reject them
    }));
    
    const drift = detectCalibrationDrift(matchResults);
    
    expect(drift.recalibrationRecommended).toBe(true);
    expect(drift.methodDrift.active.drift).toBeGreaterThan(0.2);
    expect(drift.recommendations[0]).toContain('OVER-CONFIDENT');
  });
  
  it('should report no drift when calibration is good', () => {
    const matchResults = Array.from({ length: 20 }, () => ({
      matchResult: {
        cveId: 'CVE-2023-9999',
        matchType: 'exact_vulnerability' as const,
        detectionMethod: 'active' as const,
        confidence: 0.85,
        rawConfidence: 0.85,
        calibrationAdjustment: 0,
        evidence: {} as any,
        matchQuality: 0.9,
        safeToPropagateForTraining: true,
        explanation: '',
      },
      programOutcome: 'accepted' as const,
    }));
    
    const drift = detectCalibrationDrift(matchResults);
    
    expect(drift.overallDrift).toBeLessThan(0.15);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 4. OPERATIONAL METRICS
// ═══════════════════════════════════════════════════════════════════════════════

describe('FindingLineageTracker', () => {
  let tracker: FindingLineageTracker;
  
  beforeEach(() => {
    tracker = new FindingLineageTracker();
  });
  
  it('should track finding lifecycle from detection through validation', () => {
    tracker.startTracking({
      findingId: 'f-001',
      engagementId: 1,
      originTool: 'nuclei',
      originRule: 'CVE-2021-44228',
      initialEvidence: 'Log4j JNDI lookup detected',
    });
    
    tracker.recordEvent('f-001', {
      stage: 'enriched',
      trigger: 'cve-matcher:CVE-2021-44228',
      changes: { cveId: { before: null, after: 'CVE-2021-44228' } },
    });
    
    tracker.recordEvent('f-001', {
      stage: 'validated',
      trigger: 'human:analyst',
      changes: { status: { before: 'pending', after: 'confirmed' } },
    });
    
    const lineage = tracker.getLineage('f-001');
    expect(lineage).not.toBeNull();
    expect(lineage!.events.length).toBe(3);
    expect(lineage!.currentStage).toBe('validated');
    expect(lineage!.contributingTools).toContain('nuclei');
    expect(lineage!.contributingTools).toContain('cve-matcher');
  });
  
  it('should track cross-training signals in lineage', () => {
    tracker.startTracking({
      findingId: 'f-002',
      engagementId: 1,
      originTool: 'sqlmap',
    });
    
    tracker.recordEvent('f-002', {
      stage: 'cross_trained',
      trigger: 'cross-training:bug_bounty',
      changes: { confidence: { before: 0.6, after: 0.75 } },
      crossTrainingSignalId: 'cte-12345',
    });
    
    const lineage = tracker.getLineage('f-002');
    expect(lineage!.crossTrainingSignals).toContain('cte-12345');
  });
  
  it('should retrieve findings by engagement', () => {
    tracker.startTracking({ findingId: 'f-100', engagementId: 42, originTool: 'nuclei' });
    tracker.startTracking({ findingId: 'f-101', engagementId: 42, originTool: 'nikto' });
    tracker.startTracking({ findingId: 'f-200', engagementId: 99, originTool: 'sqlmap' });
    
    const eng42 = tracker.getEngagementFindings(42);
    expect(eng42.length).toBe(2);
    
    const eng99 = tracker.getEngagementFindings(99);
    expect(eng99.length).toBe(1);
  });
});

describe('DetectionRuleEffectivenessTracker', () => {
  let tracker: DetectionRuleEffectivenessTracker;
  
  beforeEach(() => {
    tracker = new DetectionRuleEffectivenessTracker();
  });
  
  it('should track rule firings and outcomes', () => {
    tracker.recordFiring('nuclei:CVE-2021-44228', 'nuclei', 'Remote Code Execution');
    tracker.recordOutcome('nuclei:CVE-2021-44228', true, 9.8);
    
    tracker.recordFiring('nuclei:CVE-2021-44228', 'nuclei', 'Remote Code Execution');
    tracker.recordOutcome('nuclei:CVE-2021-44228', true, 9.8);
    
    tracker.recordFiring('nuclei:CVE-2021-44228', 'nuclei', 'Remote Code Execution');
    tracker.recordOutcome('nuclei:CVE-2021-44228', false);
    
    const stats = tracker.getRuleStats('nuclei:CVE-2021-44228');
    expect(stats).not.toBeNull();
    expect(stats!.totalFirings).toBe(3);
    expect(stats!.truePositives).toBe(2);
    expect(stats!.falsePositives).toBe(1);
    expect(stats!.precision).toBeCloseTo(2/3, 2);
  });
  
  it('should recommend disabling noisy rules', () => {
    // Create a very noisy rule (mostly false positives)
    for (let i = 0; i < 20; i++) {
      tracker.recordFiring('nikto:missing-headers', 'nikto', 'Missing Headers');
      tracker.recordOutcome('nikto:missing-headers', i < 2); // Only 2 TP out of 20
    }
    
    const stats = tracker.getRuleStats('nikto:missing-headers');
    expect(stats!.recommendation).toBe('disable');
  });
  
  it('should recommend promoting high-value rules', () => {
    for (let i = 0; i < 10; i++) {
      tracker.recordFiring('nuclei:log4shell', 'nuclei', 'RCE');
      tracker.recordOutcome('nuclei:log4shell', true, 9.8); // All TP, high severity
    }
    
    const stats = tracker.getRuleStats('nuclei:log4shell');
    expect(stats!.recommendation).toBe('promote');
  });
  
  it('should return noisy and high-value rule lists', () => {
    // Noisy rule
    for (let i = 0; i < 15; i++) {
      tracker.recordFiring('noisy-rule', 'scanner', 'Info');
      tracker.recordOutcome('noisy-rule', false);
    }
    
    // High-value rule
    for (let i = 0; i < 15; i++) {
      tracker.recordFiring('good-rule', 'nuclei', 'RCE');
      tracker.recordOutcome('good-rule', true, 9.0);
    }
    
    const noisy = tracker.getNoisyRules(10, 0.3);
    expect(noisy.length).toBe(1);
    expect(noisy[0].ruleId).toBe('noisy-rule');
    
    const highValue = tracker.getHighValueRules(0.7, 6);
    expect(highValue.length).toBe(1);
    expect(highValue[0].ruleId).toBe('good-rule');
  });
});

describe('buildEngagementMetrics', () => {
  it('should build comprehensive engagement metrics', () => {
    const now = Date.now();
    
    const metrics = buildEngagementMetrics({
      engagementId: 1,
      startedAt: now - 3600000, // 1 hour ago
      currentPhase: 'vuln_detection',
      phaseTimings: { recon: 600000, enumeration: 1200000, vuln_detection: 1800000 },
      assets: [
        { id: 1, scanned: true, toolsUsed: ['nmap', 'nuclei', 'gobuster'] },
        { id: 2, scanned: true, toolsUsed: ['nmap', 'nikto'] },
        { id: 3, scanned: false, toolsUsed: [] },
      ],
      findings: [
        { severity: 'critical', vulnClass: 'RCE', tool: 'nuclei', confidence: 0.95, isTruePositive: true, hasCveMatch: true, cveMatchQuality: 0.9, hasCrossTrainingSignal: true, detectedAt: now - 1800000 },
        { severity: 'high', vulnClass: 'SQLi', tool: 'sqlmap', confidence: 0.85, isTruePositive: true, hasCveMatch: false, cveMatchQuality: 0, hasCrossTrainingSignal: false, detectedAt: now - 1200000 },
        { severity: 'medium', vulnClass: 'XSS', tool: 'nuclei', confidence: 0.60, isTruePositive: false, hasCveMatch: false, cveMatchQuality: 0, hasCrossTrainingSignal: false, detectedAt: now - 600000 },
      ],
      portsDiscovered: 15,
      servicesDiscovered: 8,
      costReport: null,
      ruleStats: [],
    });
    
    expect(metrics.engagementId).toBe(1);
    expect(metrics.coverage.totalAssets).toBe(3);
    expect(metrics.coverage.assetsScanned).toBe(2);
    expect(metrics.coverage.scanCoveragePercent).toBeCloseTo(66.67, 0);
    expect(metrics.findings.totalFindings).toBe(3);
    expect(metrics.findings.truePositiveRate).toBeCloseTo(2/3, 2);
    expect(metrics.findings.findingsPerAsset).toBe(1.5);
    expect(metrics.quality.crossTrainedFindings).toBe(1);
    expect(metrics.quality.cveMatchedFindings).toBe(1);
  });
});

describe('compareEngagements', () => {
  it('should compare metrics across engagements', () => {
    const now = Date.now();
    
    const metrics1 = buildEngagementMetrics({
      engagementId: 1,
      startedAt: now - 7200000,
      currentPhase: 'complete',
      phaseTimings: {},
      assets: [{ id: 1, scanned: true, toolsUsed: ['nmap'] }],
      findings: [
        { severity: 'high', vulnClass: 'SQLi', tool: 'sqlmap', confidence: 0.8, isTruePositive: true, hasCveMatch: false, cveMatchQuality: 0, hasCrossTrainingSignal: false, detectedAt: now - 3600000 },
        { severity: 'low', vulnClass: 'Info', tool: 'nikto', confidence: 0.3, isTruePositive: false, hasCveMatch: false, cveMatchQuality: 0, hasCrossTrainingSignal: false, detectedAt: now - 3000000 },
      ],
      portsDiscovered: 5,
      servicesDiscovered: 3,
      costReport: null,
      ruleStats: [],
    });
    
    const metrics2 = buildEngagementMetrics({
      engagementId: 2,
      startedAt: now - 3600000,
      currentPhase: 'complete',
      phaseTimings: {},
      assets: [{ id: 2, scanned: true, toolsUsed: ['nmap', 'nuclei'] }],
      findings: [
        { severity: 'critical', vulnClass: 'RCE', tool: 'nuclei', confidence: 0.95, isTruePositive: true, hasCveMatch: true, cveMatchQuality: 0.9, hasCrossTrainingSignal: true, detectedAt: now - 1800000 },
        { severity: 'high', vulnClass: 'SQLi', tool: 'sqlmap', confidence: 0.85, isTruePositive: true, hasCveMatch: false, cveMatchQuality: 0, hasCrossTrainingSignal: false, detectedAt: now - 1200000 },
      ],
      portsDiscovered: 8,
      servicesDiscovered: 5,
      costReport: null,
      ruleStats: [],
    });
    
    const comparison = compareEngagements([metrics1, metrics2]);
    
    expect(comparison.engagementIds).toEqual([1, 2]);
    expect(comparison.findingComparison.length).toBe(2);
    // Engagement 2 has higher TP rate (100% vs 50%)
    expect(comparison.recommendations.length).toBeGreaterThan(0);
    expect(comparison.recommendations[0]).toContain('improved');
  });
});
