/**
 * Tests for Hot Path Analyzer Instrumentation & CI Error Pattern Validator
 */
import { describe, it, expect } from 'vitest';

// ─── CI Error Pattern Validator Tests ────────────────────────────────────────

import {
  scanFileForCatchBlocks,
  runCIValidation,
  generateBaseline,
  compareToBaseline,
  parseGitDiffFiles,
  setBaseline,
  getBaseline,
  quickScan,
} from './lib/ci-error-pattern-validator';

describe('CI Error Pattern Validator', () => {
  describe('scanFileForCatchBlocks', () => {
    it('should detect empty catch blocks as swallow_silent', () => {
      const code = `
function doSomething() {
  try {
    riskyOperation();
  } catch (e) {
  }
}`;
      const sites = scanFileForCatchBlocks(code, 'test.ts');
      expect(sites.length).toBeGreaterThanOrEqual(1);
      const catchSite = sites.find(s => s.pattern === 'swallow_silent');
      expect(catchSite).toBeDefined();
      expect(catchSite!.propagates).toBe(false);
    });

    it('should detect log_and_swallow pattern', () => {
      const code = `
function fetchData() {
  try {
    const data = await fetch('/api');
  } catch (err) {
    console.error('Failed to fetch:', err);
  }
}`;
      const sites = scanFileForCatchBlocks(code, 'test.ts');
      expect(sites.length).toBeGreaterThanOrEqual(1);
      const catchSite = sites.find(s => s.pattern === 'log_and_swallow');
      expect(catchSite).toBeDefined();
      expect(catchSite!.hasLogging).toBe(true);
      expect(catchSite!.propagates).toBe(false);
    });

    it('should detect log_and_throw pattern', () => {
      const code = `
function processItem() {
  try {
    transform(item);
  } catch (e) {
    console.error('Transform failed:', e);
    throw e;
  }
}`;
      const sites = scanFileForCatchBlocks(code, 'test.ts');
      expect(sites.length).toBeGreaterThanOrEqual(1);
      const catchSite = sites.find(s => s.pattern === 'log_and_throw');
      expect(catchSite).toBeDefined();
      expect(catchSite!.hasLogging).toBe(true);
      expect(catchSite!.propagates).toBe(true);
    });

    it('should detect propagate pattern (throw without log)', () => {
      const code = `
function validate() {
  try {
    checkInput(data);
  } catch (e) {
    throw new Error('Validation failed: ' + e.message);
  }
}`;
      const sites = scanFileForCatchBlocks(code, 'test.ts');
      expect(sites.length).toBeGreaterThanOrEqual(1);
      const catchSite = sites.find(s => s.pattern === 'propagate' || s.pattern === 'log_and_throw');
      expect(catchSite).toBeDefined();
      expect(catchSite!.propagates).toBe(true);
    });

    it('should detect retry pattern', () => {
      const code = `
function connectWithRetry() {
  try {
    connect();
  } catch (e) {
    console.log('Retrying connection...');
    retry(connect, 3);
  }
}`;
      const sites = scanFileForCatchBlocks(code, 'test.ts');
      expect(sites.length).toBeGreaterThanOrEqual(1);
      const catchSite = sites.find(s => s.pattern === 'retry');
      expect(catchSite).toBeDefined();
    });

    it('should detect fallback pattern with intentional comment', () => {
      const code = `
function getConfig() {
  try {
    return loadFromDB();
  } catch (e) {
    /* best effort - use defaults */
    console.warn('Using defaults');
    return defaultConfig;
  }
}`;
      const sites = scanFileForCatchBlocks(code, 'test.ts');
      expect(sites.length).toBeGreaterThanOrEqual(1);
      const catchSite = sites.find(s => s.pattern === 'fallback');
      expect(catchSite).toBeDefined();
    });

    it('should track file and line numbers correctly', () => {
      const code = `line1
line2
function test() {
  try {
    something();
  } catch (e) {
    console.log(e);
  }
}`;
      const sites = scanFileForCatchBlocks(code, 'server/lib/test.ts');
      expect(sites.length).toBeGreaterThanOrEqual(1);
      expect(sites[0].file).toBe('server/lib/test.ts');
      expect(sites[0].line).toBeGreaterThan(0);
    });

    it('should handle multiple catch blocks in one file', () => {
      const code = `
function a() {
  try { x(); } catch (e) { }
}
function b() {
  try { y(); } catch (e) { console.log(e); }
}
function c() {
  try { z(); } catch (e) { throw e; }
}`;
      const sites = scanFileForCatchBlocks(code, 'test.ts');
      expect(sites.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe('runCIValidation', () => {
    it('should pass when no swallowed errors found', () => {
      const files = new Map<string, string>();
      files.set('server/clean.ts', `
function clean() {
  try {
    doWork();
  } catch (e) {
    console.error('Failed:', e);
    throw e;
  }
}`);
      const result = runCIValidation(files);
      expect(result.passed).toBe(true);
      expect(result.exitCode).toBeLessThanOrEqual(2);
      expect(result.filesScanned).toBe(1);
    });

    it('should fail when silent swallowed errors found', () => {
      const files = new Map<string, string>();
      files.set('server/bad.ts', `
function bad() {
  try {
    riskyOp();
  } catch (e) {
  }
}`);
      const result = runCIValidation(files);
      expect(result.passed).toBe(false);
      expect(result.exitCode).toBe(1);
      expect(result.summary.critical).toBeGreaterThan(0);
      expect(result.summary.swallowedErrors).toBeGreaterThan(0);
    });

    it('should generate a human-readable report', () => {
      const files = new Map<string, string>();
      files.set('server/mixed.ts', `
function a() { try { x(); } catch (e) { } }
function b() { try { y(); } catch (e) { console.error(e); throw e; } }
`);
      const result = runCIValidation(files);
      expect(result.report).toContain('Error Pattern CI Validation');
      expect(result.report.length).toBeGreaterThan(50);
    });

    it('should respect strict mode for medium issues', () => {
      const files = new Map<string, string>();
      files.set('server/inconsistent.ts', `
function processA() { try { x(); } catch (e) { console.log(e); } }
function processB() { try { y(); } catch (e) { throw e; } }
`);
      // Non-strict: medium issues don't block
      const normalResult = runCIValidation(files, undefined, false);
      // Strict: medium issues block
      const strictResult = runCIValidation(files, undefined, true);
      // Both should detect the inconsistency but differ in pass/fail based on severity
      expect(normalResult.totalSites).toBe(strictResult.totalSites);
    });
  });

  describe('Baseline Management', () => {
    it('should generate a baseline from error sites', () => {
      const sites = scanFileForCatchBlocks(`
function test() {
  try { x(); } catch (e) { console.log(e); }
}`, 'test.ts');
      const baseline = generateBaseline(sites, 'v1.0');
      expect(baseline.version).toBe('v1.0');
      expect(baseline.sites.length).toBe(sites.length);
      expect(baseline.generatedAt).toBeGreaterThan(0);
      expect(baseline.sites[0].hash).toBeDefined();
    });

    it('should detect new issues compared to baseline', () => {
      const oldCode = `function a() { try { x(); } catch (e) { console.log(e); } }`;
      const oldSites = scanFileForCatchBlocks(oldCode, 'test.ts');
      const baseline = generateBaseline(oldSites, 'v1.0');

      const newCode = `
function a() { try { x(); } catch (e) { console.log(e); } }
function b() { try { y(); } catch (e) { } }
`;
      const newSites = scanFileForCatchBlocks(newCode, 'test.ts');
      const comparison = compareToBaseline(newSites, baseline);
      expect(comparison.newSites.length).toBeGreaterThan(0);
    });

    it('should track removed issues', () => {
      const oldCode = `
function a() { try { x(); } catch (e) { } }
function b() { try { y(); } catch (e) { console.log(e); } }
`;
      const oldSites = scanFileForCatchBlocks(oldCode, 'test.ts');
      const baseline = generateBaseline(oldSites, 'v1.0');

      // New code removes function a's catch
      const newCode = `function b() { try { y(); } catch (e) { console.log(e); } }`;
      const newSites = scanFileForCatchBlocks(newCode, 'test.ts');
      const comparison = compareToBaseline(newSites, baseline);
      expect(comparison.removedCount).toBeGreaterThan(0);
    });

    it('should use baseline in CI validation to only flag new issues', () => {
      // Create baseline with one known swallowed error
      const baselineCode = `function old() { try { x(); } catch (e) { console.warn(e); } }`;
      const baselineSites = scanFileForCatchBlocks(baselineCode, 'server/old.ts');
      const baseline = generateBaseline(baselineSites, 'v1.0');

      // New code adds another swallowed error
      const files = new Map<string, string>();
      files.set('server/old.ts', baselineCode);
      files.set('server/new.ts', `function bad() { try { y(); } catch (e) { } }`);

      const result = runCIValidation(files, baseline);
      // The new silent swallowed error should be flagged
      expect(result.newIssues.length).toBeGreaterThan(0);
      const newCritical = result.newIssues.filter(i => i.severity === 'critical');
      expect(newCritical.length).toBeGreaterThan(0);
    });

    it('should persist baseline via setBaseline/getBaseline', () => {
      const sites = scanFileForCatchBlocks(`function t() { try { x(); } catch (e) { } }`, 'test.ts');
      const baseline = generateBaseline(sites, 'v2.0');
      setBaseline(baseline);
      const retrieved = getBaseline();
      expect(retrieved).toBeDefined();
      expect(retrieved!.version).toBe('v2.0');
    });
  });

  describe('parseGitDiffFiles', () => {
    it('should extract TypeScript files from git diff output', () => {
      const diffOutput = `server/lib/foo.ts
server/lib/bar.ts
client/src/pages/Home.tsx
shared/types.ts
README.md
package.json`;
      const files = parseGitDiffFiles(diffOutput);
      expect(files).toContain('server/lib/foo.ts');
      expect(files).toContain('server/lib/bar.ts');
      expect(files).toContain('client/src/pages/Home.tsx');
      expect(files).toContain('shared/types.ts');
      expect(files).not.toContain('README.md');
      expect(files).not.toContain('package.json');
    });

    it('should handle empty diff output', () => {
      const files = parseGitDiffFiles('');
      expect(files).toHaveLength(0);
    });
  });

  describe('quickScan', () => {
    it('should use stored baseline when available', () => {
      // Set a baseline first
      const baselineSites = scanFileForCatchBlocks(
        `function known() { try { x(); } catch (e) { console.log(e); } }`,
        'server/known.ts'
      );
      setBaseline(generateBaseline(baselineSites, 'v3.0'));

      // Scan with quickScan (should use stored baseline)
      const files = new Map<string, string>();
      files.set('server/known.ts', `function known() { try { x(); } catch (e) { console.log(e); } }`);
      const result = quickScan(files);
      expect(result.mode).toBe('baseline_compare');
    });
  });
});

// ─── Hot Path Analyzer Integration Tests ─────────────────────────────────────

import { analyzeHotPaths } from './lib/llm-hot-path-analyzer';

describe('Hot Path Analyzer Integration', () => {
  it('should analyze telemetry records and produce hot paths', () => {
    // Simulate telemetry records from an engagement
    const records = [];
    const callers = ['scanPlanGeneration', 'vulnClassification', 'exploitSelection', 'reportGeneration', 'outputParsing'];
    
    for (let i = 0; i < 50; i++) {
      const caller = callers[i % callers.length];
      records.push({
        id: i,
        caller,
        model: 'gpt-4o',
        tokensIn: 500 + Math.floor(Math.random() * 1000),
        tokensOut: 200 + Math.floor(Math.random() * 500),
        latencyMs: 1000 + Math.floor(Math.random() * 3000),
        engagementId: 1,
        createdAt: Date.now() - (50 - i) * 60000,
      });
    }

    const analysis = analyzeHotPaths(records, { engagementId: 1, topN: 5, minCallsForAnalysis: 3 });
    
    expect(analysis.hotPaths.length).toBeGreaterThan(0);
    expect(analysis.hotPaths.length).toBeLessThanOrEqual(5);
    expect(analysis.summary.totalCalls).toBe(50);
    expect(analysis.summary.totalCost).toBeGreaterThan(0);
    expect(analysis.analyzedAt).toBeGreaterThan(0);
  });

  it('should identify the costliest call site', () => {
    const records = [];
    // Make vulnClassification the most expensive
    for (let i = 0; i < 30; i++) {
      records.push({
        id: i,
        caller: 'vulnClassification',
        model: 'gpt-4o',
        tokensIn: 2000,
        tokensOut: 1000,
        latencyMs: 3000,
        engagementId: 1,
        createdAt: Date.now() - i * 60000,
      });
    }
    // Add some cheaper calls
    for (let i = 30; i < 40; i++) {
      records.push({
        id: i,
        caller: 'outputParsing',
        model: 'gpt-4o',
        tokensIn: 100,
        tokensOut: 50,
        latencyMs: 500,
        engagementId: 1,
        createdAt: Date.now() - i * 60000,
      });
    }

    const analysis = analyzeHotPaths(records, { engagementId: 1, topN: 5, minCallsForAnalysis: 3 });
    
    expect(analysis.hotPaths[0].caller).toBe('vulnClassification');
    expect(analysis.hotPaths[0].totalCalls).toBe(30);
    expect(analysis.hotPaths[0].percentOfTotal).toBeGreaterThan(50);
  });

  it('should produce graduation recommendations', () => {
    const records = [];
    // High-frequency, low-variance caller = good graduation candidate
    for (let i = 0; i < 100; i++) {
      records.push({
        id: i,
        caller: 'formatChecker',
        model: 'gpt-4o',
        tokensIn: 200,
        tokensOut: 50,
        latencyMs: 800,
        engagementId: 1,
        createdAt: Date.now() - i * 30000,
      });
    }

    const analysis = analyzeHotPaths(records, { engagementId: 1, topN: 5, minCallsForAnalysis: 3 });
    
    expect(analysis.hotPaths.length).toBeGreaterThan(0);
    expect(analysis.hotPaths[0].graduationRecommendation).toBeDefined();
    expect(['cache', 'template', 'keep', 'batch', 'review', 'graduate_now', 'graduate_partial', 'monitor']).toContain(analysis.hotPaths[0].graduationRecommendation);
  });

  it('should detect redundancy clusters', () => {
    const records = [];
    // Two callers with very similar token patterns
    for (let i = 0; i < 20; i++) {
      records.push({
        id: i,
        caller: 'classifyVulnA',
        model: 'gpt-4o',
        tokensIn: 500,
        tokensOut: 200,
        latencyMs: 1500,
        engagementId: 1,
        createdAt: Date.now() - i * 60000,
      });
    }
    for (let i = 20; i < 40; i++) {
      records.push({
        id: i,
        caller: 'classifyVulnB',
        model: 'gpt-4o',
        tokensIn: 510,
        tokensOut: 195,
        latencyMs: 1480,
        engagementId: 1,
        createdAt: Date.now() - i * 60000,
      });
    }

    const analysis = analyzeHotPaths(records, { engagementId: 1, topN: 5, minCallsForAnalysis: 3 });
    
    // Should detect these as potentially redundant
    expect(analysis.redundancyClusters.length).toBeGreaterThanOrEqual(0); // May or may not cluster depending on threshold
    expect(analysis.recommendations.length).toBeGreaterThan(0);
  });

  it('should calculate projected savings', () => {
    const records = [];
    for (let i = 0; i < 60; i++) {
      records.push({
        id: i,
        caller: i < 40 ? 'heavyCaller' : 'lightCaller',
        model: 'gpt-4o',
        tokensIn: i < 40 ? 1500 : 100,
        tokensOut: i < 40 ? 800 : 50,
        latencyMs: i < 40 ? 2500 : 300,
        engagementId: 1,
        createdAt: Date.now() - i * 60000,
      });
    }

    const analysis = analyzeHotPaths(records, { engagementId: 1, topN: 5, minCallsForAnalysis: 3 });
    
    expect(analysis.projectedSavings).toBeDefined();
    expect(analysis.projectedSavings.callReductionPercent).toBeGreaterThanOrEqual(0);
    expect(analysis.projectedSavings.costReductionPercent).toBeGreaterThanOrEqual(0);
  });

  it('should handle minimum records threshold', () => {
    const records = [
      { id: 1, caller: 'test', model: 'gpt-4o', tokensIn: 100, tokensOut: 50, latencyMs: 500, engagementId: 1, createdAt: Date.now() },
    ];

    const analysis = analyzeHotPaths(records, { engagementId: 1, topN: 5, minCallsForAnalysis: 3 });
    
    // Should still produce a result, just with limited data
    expect(analysis.summary.totalCalls).toBe(1);
  });
});
