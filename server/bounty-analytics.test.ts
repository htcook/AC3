import { describe, it, expect, beforeEach } from 'vitest';
import {
  generateHypotheses,
  type ReconData,
} from './lib/bounty-hypothesis-generator';
import {
  checkForDuplicate,
  batchCheckDuplicates,
  getDuplicateStats,
  type DuplicateCheckInput,
} from './lib/bounty-duplicate-detector';
import {
  optimizeSubmission,
  batchOptimizeSubmissions,
  getSubmissionQualityStats,
  type FindingInput,
} from './lib/bounty-submission-optimizer';
import {
  NegativeExampleRepository,
  ProgramContextManager,
} from './lib/bounty-negative-examples';
import {
  ConfidenceCalibrationEngine,
} from './lib/bounty-confidence-calibration';

// ─── Helper: Build minimal ReconData ─────────────────────────────────────────

function makeRecon(overrides: Partial<ReconData> = {}): ReconData {
  return {
    targetDomain: 'example.com',
    techStack: [],
    openPorts: [],
    subdomains: [],
    endpoints: [],
    headers: {},
    ...overrides,
  };
}

// ─── Hypothesis Generator Tests ──────────────────────────────────────────────

describe('Bug Bounty Hypothesis Generator', () => {
  it('generates hypotheses from tech stack and endpoints', () => {
    const recon = makeRecon({
      targetDomain: 'target.com',
      techStack: [
        { technology: 'WordPress', version: '5.9', confidence: 0.9, source: 'header' },
        { technology: 'PHP', version: '7.4', confidence: 0.8, source: 'header' },
      ],
      endpoints: [
        { path: '/wp-admin', method: 'GET', statusCode: 200, responseSize: 5000 },
        { path: '/wp-login.php', method: 'GET', statusCode: 200, responseSize: 3000 },
        { path: '/xmlrpc.php', method: 'POST', statusCode: 200, responseSize: 500 },
      ],
      headers: { 'X-Powered-By': 'PHP/7.4' },
    });
    const result = generateHypotheses(recon);
    expect(result.hypotheses.length).toBeGreaterThan(0);
    expect(result.hypotheses[0]).toHaveProperty('title');
    expect(result.hypotheses[0]).toHaveProperty('confidence');
    expect(result.hypotheses[0]).toHaveProperty('estimatedEffort');
    expect(result.hypotheses[0]).toHaveProperty('potentialSeverity');
    expect(result.reconQuality).toBeDefined();
  });

  it('generates API-specific hypotheses for API endpoints', () => {
    const recon = makeRecon({
      targetDomain: 'api.target.com',
      techStack: [
        { technology: 'Node.js', confidence: 0.8, source: 'header' },
      ],
      endpoints: [
        { path: '/api/v1/users', method: 'GET', statusCode: 200, responseSize: 2000 },
        { path: '/api/v1/admin', method: 'GET', statusCode: 403, responseSize: 100 },
        { path: '/graphql', method: 'POST', statusCode: 200, responseSize: 5000 },
      ],
    });
    const result = generateHypotheses(recon);
    expect(result.hypotheses.length).toBeGreaterThan(0);
  });

  it('includes recon quality assessment', () => {
    const recon = makeRecon({
      targetDomain: 'target.com',
      techStack: [
        { technology: 'Java Spring', confidence: 0.9, source: 'header' },
      ],
      endpoints: [
        { path: '/actuator', method: 'GET', statusCode: 200, responseSize: 1000 },
        { path: '/swagger-ui.html', method: 'GET', statusCode: 200, responseSize: 5000 },
      ],
    });
    const result = generateHypotheses(recon);
    expect(result.reconQuality).toBeDefined();
    expect(result.reconQuality).toHaveProperty('overallScore');
    expect(result.summary).toBeDefined();
  });

  it('handles empty input gracefully', () => {
    const recon = makeRecon();
    const result = generateHypotheses(recon);
    expect(Array.isArray(result.hypotheses)).toBe(true);
    expect(result.reconQuality).toBeDefined();
  });

  it('generates more hypotheses with richer recon data', () => {
    const sparseRecon = makeRecon({ targetDomain: 'sparse.com' });
    const richRecon = makeRecon({
      targetDomain: 'rich.com',
      techStack: [
        { technology: 'WordPress', version: '5.9', confidence: 0.9, source: 'header' },
        { technology: 'PHP', version: '7.4', confidence: 0.8, source: 'header' },
        { technology: 'MySQL', version: '5.7', confidence: 0.7, source: 'error_page' },
      ],
      openPorts: [
        { port: 80, service: 'http', state: 'open' },
        { port: 443, service: 'https', state: 'open' },
        { port: 3306, service: 'mysql', state: 'filtered' },
      ],
      subdomains: ['admin.rich.com', 'staging.rich.com', 'api.rich.com'],
      endpoints: [
        { path: '/wp-admin', method: 'GET', statusCode: 200, responseSize: 5000 },
        { path: '/api/v1/users', method: 'GET', statusCode: 200, responseSize: 2000 },
      ],
      headers: { 'X-Powered-By': 'PHP/7.4', 'Server': 'Apache/2.4' },
    });
    const sparseResult = generateHypotheses(sparseRecon);
    const richResult = generateHypotheses(richRecon);
    expect(richResult.hypotheses.length).toBeGreaterThanOrEqual(sparseResult.hypotheses.length);
  });
});

// ─── Duplicate Detector Tests ────────────────────────────────────────────────

describe('Bug Bounty Duplicate Detector', () => {
  it('detects high-probability duplicates for common patterns', () => {
    const input: DuplicateCheckInput = {
      vulnClass: 'graphql_introspection',
      title: 'GraphQL Introspection Enabled',
      affectedEndpoint: '/graphql',
    };
    const result = checkForDuplicate(input);
    expect(result.duplicateProbability).toBeGreaterThan(0.7);
    expect(result.recommendation).toBe('skip');
    expect(result.reasoning.length).toBeGreaterThan(0);
  });

  it('identifies known CVE matches', () => {
    const input: DuplicateCheckInput = {
      vulnClass: 'rce',
      title: 'Spring RCE',
      affectedEndpoint: '/api/endpoint',
      technology: 'Spring Framework',
      technologyVersion: '1.5',
    };
    const result = checkForDuplicate(input);
    expect(result.matchedReferences.some(r => r.source === 'cve')).toBe(true);
    expect(result.duplicateProbability).toBeGreaterThan(0.5);
  });

  it('flags novel opportunities for uncommon vuln classes', () => {
    const input: DuplicateCheckInput = {
      vulnClass: 'http_request_smuggling',
      title: 'HTTP Request Smuggling via CL.TE',
      affectedEndpoint: '/api/proxy',
      technology: 'Custom Proxy',
    };
    const result = checkForDuplicate(input);
    expect(result.duplicateProbability).toBeLessThan(0.5);
    expect(['proceed', 'novel_opportunity']).toContain(result.recommendation);
  });

  it('adjusts probability based on program profile', () => {
    const googleInput: DuplicateCheckInput = {
      vulnClass: 'xss_reflected',
      title: 'Reflected XSS',
      affectedEndpoint: '/search',
      programHandle: 'google',
    };
    const unknownInput: DuplicateCheckInput = {
      ...googleInput,
      programHandle: 'unknown-startup',
    };
    const googleResult = checkForDuplicate(googleInput);
    const unknownResult = checkForDuplicate(unknownInput);
    expect(googleResult.duplicateProbability).toBeGreaterThanOrEqual(unknownResult.duplicateProbability);
  });

  it('batch checks multiple findings', () => {
    const inputs: DuplicateCheckInput[] = [
      { vulnClass: 'graphql_introspection', title: 'GraphQL', affectedEndpoint: '/graphql' },
      { vulnClass: 'rce', title: 'RCE', affectedEndpoint: '/api/exec' },
      { vulnClass: 'open_redirect', title: 'Redirect', affectedEndpoint: '/login?next=evil' },
    ];
    const results = batchCheckDuplicates(inputs);
    expect(results.size).toBe(3);
    const stats = getDuplicateStats(results);
    expect(stats.total).toBe(3);
    expect(stats.recommendationBreakdown).toBeDefined();
  });
});

// ─── Submission Optimizer Tests ──────────────────────────────────────────────

describe('Bug Bounty Submission Optimizer', () => {
  it('generates optimized submission with all required fields', () => {
    const input: FindingInput = {
      vulnClass: 'sqli_classic',
      title: 'SQL Injection in Search',
      description: 'The search parameter is vulnerable to SQL injection',
      affectedEndpoint: '/api/search?q=test',
      severity: 'critical',
      technology: 'MySQL',
      platform: 'hackerone',
    };
    const result = optimizeSubmission(input);
    expect(result.title).toBeDefined();
    expect(result.severity).toBe('critical');
    expect(result.severityJustification.length).toBeGreaterThan(0);
    expect(result.impactStatement.length).toBeGreaterThan(0);
    expect(result.reproductionSteps.length).toBeGreaterThanOrEqual(3);
    expect(result.remediation.length).toBeGreaterThan(0);
    expect(result.cweId).toBe('CWE-89');
    expect(result.cvssEstimate).toBeDefined();
    expect(result.cvssEstimate!.score).toBeGreaterThan(8);
  });

  it('formats title per platform guidelines', () => {
    const input: FindingInput = {
      vulnClass: 'xss_reflected',
      title: 'Reflected XSS in Search',
      description: 'XSS via search parameter',
      affectedEndpoint: '/search',
      severity: 'medium',
      platform: 'hackerone',
    };
    const result = optimizeSubmission(input);
    expect(result.title).toMatch(/^\[MEDIUM\]/);

    const bugcrowdResult = optimizeSubmission({ ...input, platform: 'bugcrowd' });
    expect(bugcrowdResult.title).toContain('Medium');
  });

  it('includes platform-specific notes', () => {
    const input: FindingInput = {
      vulnClass: 'ssrf',
      title: 'SSRF',
      description: 'SSRF via URL parameter',
      affectedEndpoint: '/fetch',
      severity: 'critical',
      platform: 'hackerone',
    };
    const result = optimizeSubmission(input);
    expect(result.platformSpecificNotes.length).toBeGreaterThan(0);
    expect(result.platformSpecificNotes.some(n => n.includes('HackerOne'))).toBe(true);
  });

  it('assesses submission quality and identifies issues', () => {
    const input: FindingInput = {
      vulnClass: 'xss_reflected',
      title: 'XSS',
      description: 'XSS found',
      affectedEndpoint: '/page',
      severity: 'medium',
    };
    const result = optimizeSubmission(input);
    expect(result.qualityScore).toBeLessThan(100);
    expect(result.qualityIssues.length).toBeGreaterThan(0);
  });

  it('batch optimizes and provides quality stats', () => {
    const inputs: FindingInput[] = [
      { vulnClass: 'sqli_classic', title: 'SQLi', description: 'SQL injection', affectedEndpoint: '/api', severity: 'critical' },
      { vulnClass: 'xss_reflected', title: 'XSS', description: 'XSS found', affectedEndpoint: '/page', severity: 'medium' },
    ];
    const results = batchOptimizeSubmissions(inputs);
    expect(results.length).toBe(2);
    const stats = getSubmissionQualityStats(results);
    expect(stats.averageQuality).toBeGreaterThan(0);
  });
});

// ─── Negative Example Pipeline Tests ─────────────────────────────────────────

describe('Negative Example Pipeline', () => {
  let repo: NegativeExampleRepository;

  beforeEach(() => {
    repo = new NegativeExampleRepository();
  });

  it('adds and retrieves negative examples', () => {
    repo.addExample({
      id: 'neg-1', vulnClass: 'xss_reflected', title: 'Reflected XSS on Login',
      affectedEndpoint: '/login', severity: 'medium', rejectionReason: 'duplicate',
      rejectionDetail: 'Already reported by another researcher',
      submittedAt: '2024-01-01', rejectedAt: '2024-01-03',
      lessonsLearned: ['Check for duplicates before submitting reflected XSS'], tags: ['xss', 'duplicate'],
    });
    const results = repo.getExamples({ vulnClass: 'xss_reflected' });
    expect(results.length).toBe(1);
    expect(results[0].rejectionReason).toBe('duplicate');
  });

  it('generates training signals from negative examples', () => {
    repo.addExample({
      id: 'neg-1', vulnClass: 'info_disclosure', title: 'Server Version',
      affectedEndpoint: '/', severity: 'low', rejectionReason: 'informational_only',
      rejectionDetail: 'Not a vulnerability', submittedAt: '2024-01-01',
      rejectedAt: '2024-01-02', lessonsLearned: ['Info disclosure is often rejected'], tags: [],
    });
    repo.addPositiveExample('sqli_classic', '/api/search', 'MySQL', 'Accepted with bounty');

    const signals = repo.getTrainingSignals();
    expect(signals.length).toBe(2);
    expect(signals[0].isPositive).toBe(false);
    expect(signals[1].isPositive).toBe(true);
  });

  it('calculates stats with rejection breakdown', () => {
    repo.addExample({ id: '1', vulnClass: 'xss_reflected', title: 'XSS', affectedEndpoint: '/a', severity: 'medium', rejectionReason: 'duplicate', rejectionDetail: 'dup', submittedAt: '2024-01-01', rejectedAt: '2024-01-02', lessonsLearned: ['lesson1'], tags: [] });
    repo.addExample({ id: '2', vulnClass: 'info_disclosure', title: 'Info', affectedEndpoint: '/b', severity: 'low', rejectionReason: 'false_positive', rejectionDetail: 'fp', submittedAt: '2024-01-01', rejectedAt: '2024-01-02', lessonsLearned: ['lesson2'], tags: [] });
    repo.addExample({ id: '3', vulnClass: 'xss_reflected', title: 'XSS2', affectedEndpoint: '/c', severity: 'medium', rejectionReason: 'duplicate', rejectionDetail: 'dup2', submittedAt: '2024-01-01', rejectedAt: '2024-01-02', lessonsLearned: ['lesson1'], tags: [] });

    const stats = repo.getStats();
    expect(stats.totalExamples).toBe(3);
    expect(stats.duplicateRate).toBeCloseTo(2 / 3, 1);
    expect(stats.falsePositiveRate).toBeCloseTo(1 / 3, 1);
    expect(stats.topLessons[0].lesson).toBe('lesson1');
    expect(stats.topLessons[0].frequency).toBe(2);
  });

  it('analyzes rejection patterns', () => {
    for (let i = 0; i < 5; i++) {
      repo.addExample({
        id: `dup-${i}`, vulnClass: 'xss_reflected', title: `XSS ${i}`,
        affectedEndpoint: `/page${i}`, severity: 'medium', rejectionReason: 'duplicate',
        rejectionDetail: 'Already reported', submittedAt: '2024-01-01',
        rejectedAt: '2024-01-02', lessonsLearned: ['Check duplicates first'], tags: [],
      });
    }
    const patterns = repo.analyzePatterns();
    expect(patterns.length).toBeGreaterThan(0);
    expect(patterns[0].affectedVulnClasses).toContain('xss_reflected');
  });

  it('builds negative example context for LLM prompts', () => {
    repo.addExample({
      id: '1', vulnClass: 'csrf', title: 'CSRF on Logout',
      affectedEndpoint: '/logout', severity: 'low', rejectionReason: 'insufficient_impact',
      rejectionDetail: 'Logout CSRF has no security impact', submittedAt: '2024-01-01',
      rejectedAt: '2024-01-02', lessonsLearned: ['CSRF on logout is always rejected'], tags: [],
    });
    const context = repo.buildNegativeExampleContext('csrf');
    expect(context).toContain('csrf');
  });
});

// ─── Program Context Manager Tests ───────────────────────────────────────────

describe('Program Context Manager', () => {
  let manager: ProgramContextManager;

  beforeEach(() => {
    manager = new ProgramContextManager();
    manager.addProgram({
      handle: 'test-program',
      platform: 'hackerone',
      scopeAssets: [
        { type: 'domain', identifier: 'app.example.com', eligible: true },
        { type: 'wildcard', identifier: '*.example.com', eligible: true },
        { type: 'domain', identifier: 'staging.example.com', eligible: false, notes: 'Staging only' },
      ],
      outOfScopePatterns: ['cdn\\.example\\.com', 'third-party\\.com'],
      rewardStructure: [
        { severity: 'critical', minBounty: 5000, maxBounty: 15000, currency: 'USD' },
        { severity: 'high', minBounty: 2000, maxBounty: 5000, currency: 'USD' },
        { severity: 'medium', minBounty: 500, maxBounty: 2000, currency: 'USD' },
      ],
      responseTimeSLA: { firstResponse: '24h', triage: '72h', bounty: '14d' },
      acceptedVulnClasses: ['sqli_classic', 'rce', 'ssrf', 'idor'],
      rejectedVulnClasses: ['info_disclosure', 'missing_header'],
      historicalAcceptanceRate: 0.35,
      averageBountyByClass: { sqli_classic: 8000, ssrf: 6000, idor: 3000 },
      notes: ['Focus on API endpoints'],
    });
  });

  it('checks scope correctly', () => {
    const inScope = manager.isInScope('test-program', 'https://app.example.com/api', 'sqli_classic');
    expect(inScope.inScope).toBe(true);

    const outOfScope = manager.isInScope('test-program', 'https://cdn.example.com/asset', 'xss_reflected');
    expect(outOfScope.inScope).toBe(false);

    const rejectedClass = manager.isInScope('test-program', 'https://app.example.com/api', 'info_disclosure');
    expect(rejectedClass.inScope).toBe(false);
  });

  it('estimates bounty from historical data', () => {
    const estimate = manager.estimateBounty('test-program', 'sqli_classic', 'critical');
    expect(estimate.estimate).toBe(8000);
    expect(estimate.confidence).toBe('high');
  });

  it('falls back to reward tier when no historical data', () => {
    const estimate = manager.estimateBounty('test-program', 'xss_stored', 'high');
    expect(estimate.estimate).toBe(3500); // (2000 + 5000) / 2
    expect(estimate.confidence).toBe('medium');
  });

  it('builds program context for LLM prompts', () => {
    const context = manager.buildProgramContext('test-program');
    expect(context).toContain('test-program');
    expect(context).toContain('Scope');
  });
});

// ─── Confidence Calibration Tests ────────────────────────────────────────────

describe('Confidence Calibration Engine', () => {
  let engine: ConfidenceCalibrationEngine;

  beforeEach(() => {
    engine = new ConfidenceCalibrationEngine();
  });

  it('assesses confidence with full reasoning chain', () => {
    const result = engine.assessConfidence({
      vulnClass: 'sqli_classic', severity: 'critical', endpoint: '/api/search',
      technology: 'PHP', hasEvidence: true, evidenceCount: 3,
      isReproducible: true, scannerConfidence: 0.95, manuallyVerified: true,
    });
    expect(result.score).toBeGreaterThan(0.7);
    expect(result.level).toMatch(/high|very_high/);
    expect(result.reasoning.factors.length).toBeGreaterThan(0);
    expect(result.reasoning.summary.length).toBeGreaterThan(0);
    expect(result.reasoning.rawScore).toBeGreaterThan(0);
  });

  it('produces lower confidence for weak evidence', () => {
    const strong = engine.assessConfidence({
      vulnClass: 'xss_reflected', severity: 'medium', endpoint: '/search',
      hasEvidence: true, evidenceCount: 5, isReproducible: true,
      scannerConfidence: 0.9, manuallyVerified: true,
    });
    const weak = engine.assessConfidence({
      vulnClass: 'xss_reflected', severity: 'medium', endpoint: '/search',
      hasEvidence: false, evidenceCount: 0, isReproducible: false,
      scannerConfidence: 0.3, manuallyVerified: false,
    });
    expect(strong.score).toBeGreaterThan(weak.score);
  });

  it('records outcomes and builds calibration curves', () => {
    for (let i = 0; i < 10; i++) {
      engine.recordOutcome({
        vulnClass: 'xss_reflected',
        predictedConfidence: 0.8,
        actualOutcome: i < 4 ? 'accepted' : 'rejected',
        timestamp: Date.now(),
      });
    }
    const curve = engine.getCalibrationCurve('xss_reflected');
    expect(curve).toBeDefined();
    expect(curve!.sampleSize).toBe(10);
    expect(curve!.overallBias).toBeGreaterThan(0); // Overconfident
  });

  it('detects calibration drift', () => {
    for (let i = 0; i < 15; i++) {
      engine.recordOutcome({
        vulnClass: 'xss_reflected',
        predictedConfidence: 0.9,
        actualOutcome: i < 3 ? 'accepted' : 'rejected',
        timestamp: Date.now(),
      });
    }
    const drift = engine.detectDrift();
    expect(drift.hasDrift).toBe(true);
    expect(drift.direction).toBe('overconfident');
    expect(drift.severity).not.toBe('none');
    expect(drift.recommendation.length).toBeGreaterThan(0);
  });

  it('applies calibration adjustment to future assessments', () => {
    for (let i = 0; i < 10; i++) {
      engine.recordOutcome({
        vulnClass: 'info_disclosure',
        predictedConfidence: 0.8,
        actualOutcome: i < 2 ? 'accepted' : 'rejected',
        timestamp: Date.now(),
      });
    }
    const result = engine.assessConfidence({
      vulnClass: 'info_disclosure', severity: 'low', endpoint: '/status',
      hasEvidence: true, evidenceCount: 2, isReproducible: true,
      scannerConfidence: 0.7, manuallyVerified: false,
    });
    expect(result.calibrationAdjustment).toBeLessThan(0);
    expect(result.reasoning.adjustmentExplanation).toContain('calibration');
  });

  it('reports well-calibrated when data is insufficient', () => {
    const drift = engine.detectDrift();
    expect(drift.hasDrift).toBe(false);
    expect(drift.severity).toBe('none');
    expect(drift.recommendation).toContain('Insufficient data');
  });

  it('identifies worst vuln classes in drift report', () => {
    for (let i = 0; i < 10; i++) {
      engine.recordOutcome({
        vulnClass: 'xss_reflected', predictedConfidence: 0.9,
        actualOutcome: i < 2 ? 'accepted' : 'rejected', timestamp: Date.now(),
      });
    }
    for (let i = 0; i < 10; i++) {
      engine.recordOutcome({
        vulnClass: 'sqli_classic', predictedConfidence: 0.7,
        actualOutcome: i < 7 ? 'accepted' : 'rejected', timestamp: Date.now(),
      });
    }
    const drift = engine.detectDrift();
    expect(drift.worstVulnClasses.length).toBeGreaterThan(0);
    expect(drift.worstVulnClasses[0].vulnClass).toBe('xss_reflected');
  });
});
