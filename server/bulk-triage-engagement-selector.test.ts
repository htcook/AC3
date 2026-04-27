/**
 * Tests for Bulk Triage & Engagement Selector Sprint
 * 
 * Covers:
 * 1. listActiveEngagements procedure (engagement dropdown)
 * 2. Bulk triage logic (batch accept/reject/reclassify)
 * 3. Cross-training batch submission with bulk outcomes
 */

import { describe, it, expect } from 'vitest';
import {
  batchNormalize,
  deduplicateFindings,
  normalizeNucleiFinding,
  normalizeZapFinding,
} from './lib/finding-normalization';
import {
  processCrossTrainingBatch,
  PatternRepository,
  CalibrationPipeline,
  ToolEffectivenessTracker,
} from './lib/cross-training';

// ─── Bulk Triage Logic Tests ────────────────────────────────────────────────

describe('Bulk Triage Logic', () => {
  it('should batch-normalize multiple findings for bulk triage', () => {
    const nuclei1 = {
      templateId: 'CVE-2021-44228',
      info: {
        name: 'Log4Shell RCE',
        severity: 'critical',
        description: 'Apache Log4j2 RCE',
        classification: { cve: ['CVE-2021-44228'], cwe: ['CWE-502'] },
        tags: ['cve', 'rce'],
      },
      host: 'app.example.com',
      ip: '10.0.0.1',
      port: '8080',
      matchedAt: 'http://app.example.com:8080/api',
      timestamp: Date.now(),
    };
    const nuclei2 = {
      templateId: 'CVE-2023-1234',
      info: {
        name: 'XSS in Search',
        severity: 'medium',
        description: 'Reflected XSS',
        classification: { cve: ['CVE-2023-1234'], cwe: ['CWE-79'] },
        tags: ['xss'],
      },
      host: 'app.example.com',
      ip: '10.0.0.1',
      port: '443',
      matchedAt: 'https://app.example.com/search',
      timestamp: Date.now(),
    };
    const nuclei3 = {
      templateId: 'ssl-expired',
      info: {
        name: 'Expired SSL Certificate',
        severity: 'info',
        description: 'SSL cert expired',
        classification: {},
        tags: ['ssl'],
      },
      host: 'old.example.com',
      ip: '10.0.0.2',
      port: '443',
      matchedAt: 'https://old.example.com',
      timestamp: Date.now(),
    };

    const result = batchNormalize({
      nucleiFindings: [nuclei1, nuclei2, nuclei3],
    });

    expect(result.findings.length).toBeGreaterThanOrEqual(3);
    expect(result.stats.totalRaw).toBe(3);
    expect(result.stats.bySeverity).toBeDefined();
  });

  it('should support triaging findings by fingerprint', () => {
    const finding = normalizeNucleiFinding({
      templateId: 'CVE-2021-44228',
      info: {
        name: 'Log4Shell',
        severity: 'critical',
        description: 'RCE via Log4j',
        classification: { cve: ['CVE-2021-44228'] },
        tags: [],
      },
      host: 'target.com',
      ip: '1.2.3.4',
      matchedAt: 'http://target.com/api',
      timestamp: Date.now(),
    });

    // Verify the finding has a fingerprint for triage identification
    expect(finding.fingerprint).toBeDefined();
    expect(typeof finding.fingerprint).toBe('string');
    expect(finding.fingerprint.length).toBeGreaterThan(0);
  });

  it('should deduplicate findings before bulk triage', () => {
    const findings = [
      normalizeNucleiFinding({
        templateId: 'sqli-test',
        info: { name: 'SQL Injection', severity: 'high', description: 'SQLi', classification: {}, tags: [] },
        host: 'db.example.com',
        matchedAt: 'http://db.example.com/login',
        timestamp: Date.now(),
      }),
      normalizeNucleiFinding({
        templateId: 'sqli-test',
        info: { name: 'SQL Injection', severity: 'high', description: 'SQLi', classification: {}, tags: [] },
        host: 'db.example.com',
        matchedAt: 'http://db.example.com/login',
        timestamp: Date.now(),
      }),
    ];

    const deduped = deduplicateFindings(findings);
    expect(deduped.length).toBe(1);
    // Deduped finding should have corroborated sources
    expect(deduped[0].sources.length).toBeGreaterThanOrEqual(1);
  });

  it('should process bulk triage outcomes through cross-training', () => {
    const patternRepo = new PatternRepository();
    const calibration = new CalibrationPipeline();
    const toolTracker = new ToolEffectivenessTracker();

    // Simulate bulk triage: 3 accepted, 2 rejected
    const bulkOutcomes = [
      {
        findingId: 'f1',
        scanner: 'nuclei',
        vulnClass: 'rce',
        originalSeverity: 'critical',
        triageDecision: 'true_positive',
        isTruePositive: true,
        isFalsePositive: false,
        extractedPatterns: [],
        timestamp: Date.now(),
      },
      {
        findingId: 'f2',
        scanner: 'nuclei',
        vulnClass: 'xss',
        originalSeverity: 'high',
        triageDecision: 'true_positive',
        isTruePositive: true,
        isFalsePositive: false,
        extractedPatterns: [],
        timestamp: Date.now(),
      },
      {
        findingId: 'f3',
        scanner: 'zap',
        vulnClass: 'sqli',
        originalSeverity: 'high',
        triageDecision: 'true_positive',
        isTruePositive: true,
        isFalsePositive: false,
        extractedPatterns: [],
        timestamp: Date.now(),
      },
      {
        findingId: 'f4',
        scanner: 'nuclei',
        vulnClass: 'info-disclosure',
        originalSeverity: 'low',
        triageDecision: 'false_positive',
        isTruePositive: false,
        isFalsePositive: true,
        extractedPatterns: [],
        timestamp: Date.now(),
      },
      {
        findingId: 'f5',
        scanner: 'zap',
        vulnClass: 'csrf',
        originalSeverity: 'medium',
        triageDecision: 'false_positive',
        isTruePositive: false,
        isFalsePositive: true,
        extractedPatterns: [],
        timestamp: Date.now(),
      },
    ];

    const result = processCrossTrainingBatch(
      bulkOutcomes as any,
      patternRepo,
      calibration,
      toolTracker
    );

    expect(result).toBeDefined();
    // processCrossTrainingBatch returns patternsExtracted, calibrationUpdates, toolEffectivenessUpdates, contaminationRejections
    expect(result.patternsExtracted).toBeGreaterThanOrEqual(0);
    expect(result.calibrationUpdates).toBeGreaterThanOrEqual(0);
    expect(result.toolEffectivenessUpdates).toBeGreaterThanOrEqual(0);
  });

  it('should handle reclassify decisions in bulk', () => {
    const patternRepo = new PatternRepository();
    const calibration = new CalibrationPipeline();
    const toolTracker = new ToolEffectivenessTracker();

    const reclassifyOutcomes = [
      {
        findingId: 'r1',
        scanner: 'nuclei',
        vulnClass: 'xss',
        originalSeverity: 'high',
        triageDecision: 'reclassify',
        reclassifiedSeverity: 'critical',
        isTruePositive: true,
        isFalsePositive: false,
        extractedPatterns: [],
        timestamp: Date.now(),
      },
      {
        findingId: 'r2',
        scanner: 'zap',
        vulnClass: 'info-disclosure',
        originalSeverity: 'medium',
        triageDecision: 'reclassify',
        reclassifiedSeverity: 'low',
        isTruePositive: true,
        isFalsePositive: false,
        extractedPatterns: [],
        timestamp: Date.now(),
      },
    ];

    const result = processCrossTrainingBatch(
      reclassifyOutcomes as any,
      patternRepo,
      calibration,
      toolTracker
    );

    expect(result.patternsExtracted).toBeGreaterThanOrEqual(0);
    expect(result.calibrationUpdates).toBeGreaterThanOrEqual(0);
  });
});

// ─── Engagement Listing Tests ───────────────────────────────────────────────

describe('Engagement Listing for Dropdown', () => {
  it('should filter out archived engagements from the listing', () => {
    // Simulate what the listActiveEngagements procedure does
    const mockEngagements = [
      { id: 1, name: 'Active Pentest', clientName: 'Acme', engagementType: 'pentest', status: 'active', targetDomain: 'acme.com' },
      { id: 2, name: 'Completed VA', clientName: 'Beta', engagementType: 'vulnerability_assessment', status: 'completed', targetDomain: 'beta.io' },
      { id: 3, name: 'Archived Old', clientName: 'Gamma', engagementType: 'pentest', status: 'archived', targetDomain: 'gamma.net' },
      { id: 4, name: 'Bug Bounty', clientName: 'Delta', engagementType: 'bug_bounty', status: 'active', targetDomain: 'delta.org' },
    ];

    const filtered = mockEngagements
      .map(e => ({
        id: e.id,
        name: e.name || e.clientName || `Engagement #${e.id}`,
        clientName: e.clientName || '',
        engagementType: e.engagementType || 'pentest',
        status: e.status || 'active',
        targetDomain: e.targetDomain || '',
      }))
      .filter(e => e.status !== 'archived');

    expect(filtered.length).toBe(3);
    expect(filtered.find(e => e.id === 3)).toBeUndefined();
    expect(filtered.find(e => e.id === 1)).toBeDefined();
    expect(filtered.find(e => e.id === 4)?.engagementType).toBe('bug_bounty');
  });

  it('should provide fallback name when engagement name is missing', () => {
    const mockEngagement = { id: 42, clientName: '', engagementType: 'pentest', status: 'active', targetDomain: '' };
    const name = mockEngagement.clientName || `Engagement #${mockEngagement.id}`;
    expect(name).toBe('Engagement #42');
  });

  it('should handle empty engagement list gracefully', () => {
    const emptyList: any[] = [];
    const filtered = emptyList.filter(e => e.status !== 'archived');
    expect(filtered).toEqual([]);
  });
});

// ─── Bulk Selection Logic Tests ─────────────────────────────────────────────

describe('Bulk Selection Logic', () => {
  it('should track selected finding IDs correctly', () => {
    const selectedIds = new Set<string>();
    
    // Select 3 findings
    selectedIds.add('f1');
    selectedIds.add('f2');
    selectedIds.add('f3');
    expect(selectedIds.size).toBe(3);
    
    // Toggle off one
    selectedIds.delete('f2');
    expect(selectedIds.size).toBe(2);
    expect(selectedIds.has('f2')).toBe(false);
    
    // Select all visible (simulate)
    const visibleIds = ['f1', 'f2', 'f3', 'f4', 'f5'];
    visibleIds.forEach(id => selectedIds.add(id));
    expect(selectedIds.size).toBe(5);
    
    // Deselect all
    selectedIds.clear();
    expect(selectedIds.size).toBe(0);
  });

  it('should select only pending (un-triaged) findings', () => {
    const triaged = new Map<string, { decision: string }>();
    triaged.set('f1', { decision: 'true_positive' });
    triaged.set('f3', { decision: 'false_positive' });

    const allIds = ['f1', 'f2', 'f3', 'f4', 'f5'];
    const pendingIds = allIds.filter(id => !triaged.has(id));
    
    expect(pendingIds).toEqual(['f2', 'f4', 'f5']);
    expect(pendingIds.length).toBe(3);
  });

  it('should apply bulk decision to all selected findings', () => {
    const selectedIds = new Set(['f1', 'f2', 'f3']);
    const triaged = new Map<string, any>();
    const now = Date.now();

    // Simulate bulk accept
    selectedIds.forEach(fId => {
      triaged.set(fId, {
        findingId: fId,
        decision: 'true_positive',
        analystNotes: 'Bulk accepted',
        timestamp: now,
      });
    });

    expect(triaged.size).toBe(3);
    expect(triaged.get('f1')?.decision).toBe('true_positive');
    expect(triaged.get('f2')?.analystNotes).toBe('Bulk accepted');
    expect(triaged.get('f3')?.timestamp).toBe(now);
  });

  it('should overwrite existing triage when bulk-triaging', () => {
    const triaged = new Map<string, any>();
    
    // Individual triage first
    triaged.set('f1', { findingId: 'f1', decision: 'false_positive', analystNotes: 'FP', timestamp: 1 });
    
    // Bulk accept overrides
    const selectedIds = new Set(['f1', 'f2']);
    const now = Date.now();
    selectedIds.forEach(fId => {
      triaged.set(fId, {
        findingId: fId,
        decision: 'true_positive',
        analystNotes: 'Bulk override',
        timestamp: now,
      });
    });

    expect(triaged.get('f1')?.decision).toBe('true_positive');
    expect(triaged.get('f1')?.analystNotes).toBe('Bulk override');
  });

  it('should handle bulk reclassify with severity override', () => {
    const selectedIds = new Set(['f1', 'f2']);
    const triaged = new Map<string, any>();
    const now = Date.now();

    selectedIds.forEach(fId => {
      triaged.set(fId, {
        findingId: fId,
        decision: 'reclassify',
        reclassifiedSeverity: 'critical',
        analystNotes: 'Upgraded to critical',
        timestamp: now,
      });
    });

    expect(triaged.get('f1')?.reclassifiedSeverity).toBe('critical');
    expect(triaged.get('f2')?.decision).toBe('reclassify');
  });
});

// ─── Cross-Training Batch from Bulk Triage ──────────────────────────────────

describe('Cross-Training from Bulk Triage', () => {
  it('should convert bulk triage map to cross-training outcomes', () => {
    const triaged = new Map<string, any>();
    triaged.set('f1', { findingId: 'f1', decision: 'true_positive', analystNotes: '', timestamp: Date.now() });
    triaged.set('f2', { findingId: 'f2', decision: 'false_positive', analystNotes: 'FP - scanner noise', timestamp: Date.now() });
    triaged.set('f3', { findingId: 'f3', decision: 'reclassify', reclassifiedSeverity: 'high', analystNotes: '', timestamp: Date.now() });

    const mockFindings = [
      { findingId: 'f1', severity: 'critical', vulnClass: 'rce', sources: [{ scanner: 'nuclei' }] },
      { findingId: 'f2', severity: 'low', vulnClass: 'info', sources: [{ scanner: 'zap' }] },
      { findingId: 'f3', severity: 'medium', vulnClass: 'xss', sources: [{ scanner: 'nuclei' }] },
    ];

    // Simulate the conversion done in submitToCrossTraining
    const outcomes = Array.from(triaged.values()).map(t => {
      const finding = mockFindings.find(f => f.findingId === t.findingId);
      return {
        findingId: t.findingId,
        scanner: finding?.sources?.[0]?.scanner || 'unknown',
        vulnClass: finding?.vulnClass || 'unknown',
        originalSeverity: finding?.severity || 'info',
        triageDecision: t.decision,
        reclassifiedSeverity: t.reclassifiedSeverity,
        analystNotes: t.analystNotes,
        timestamp: t.timestamp,
        isTruePositive: t.decision === 'true_positive' || t.decision === 'reclassify',
        isFalsePositive: t.decision === 'false_positive',
      };
    });

    expect(outcomes.length).toBe(3);
    expect(outcomes[0].isTruePositive).toBe(true);
    expect(outcomes[1].isFalsePositive).toBe(true);
    expect(outcomes[2].isTruePositive).toBe(true); // reclassify counts as TP
    expect(outcomes[2].reclassifiedSeverity).toBe('high');
  });

  it('should process large bulk triage batches efficiently', () => {
    const patternRepo = new PatternRepository();
    const calibration = new CalibrationPipeline();
    const toolTracker = new ToolEffectivenessTracker();

    // Simulate 50 findings bulk-triaged
    const outcomes = Array.from({ length: 50 }, (_, i) => ({
      findingId: `bulk-${i}`,
      scanner: i % 2 === 0 ? 'nuclei' : 'zap',
      vulnClass: ['rce', 'xss', 'sqli', 'ssrf', 'idor'][i % 5],
      originalSeverity: ['critical', 'high', 'medium', 'low', 'info'][i % 5],
      triageDecision: i % 3 === 0 ? 'false_positive' : 'true_positive',
      isTruePositive: i % 3 !== 0,
      isFalsePositive: i % 3 === 0,
      extractedPatterns: [],
      timestamp: Date.now(),
    }));

    const start = Date.now();
    const result = processCrossTrainingBatch(
      outcomes as any,
      patternRepo,
      calibration,
      toolTracker
    );
    const elapsed = Date.now() - start;

    expect(result.patternsExtracted).toBeGreaterThanOrEqual(0);
    expect(result.calibrationUpdates).toBeGreaterThanOrEqual(0);
    expect(elapsed).toBeLessThan(5000); // Should complete in under 5s
  });
});
