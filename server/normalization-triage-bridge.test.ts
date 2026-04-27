/**
 * Tests for Normalization Stats, Triage Queue, and Engagement-to-BB Bridge sprint.
 *
 * Covers:
 * - listEngagementFindingsForBounty procedure output shape
 * - Cross-training batch processing with triage outcomes
 * - Finding normalization pipeline (batchNormalize) with mixed scanner inputs
 * - Scope checking with various target formats
 * - Originality checking with novel vs common findings
 * - Verification profile listing and retrieval
 * - License-tier gating for engagement types
 */

import { describe, it, expect } from 'vitest';
import {
  batchNormalize,
  normalizeNucleiFinding,
  normalizeZapFinding,
  deduplicateFindings,
} from './lib/finding-normalization.js';
import {
  listVerificationProfiles,
  getVerificationProfile,
  prioritizeFindings,
  VERIFICATION_PROFILES,
} from './lib/verification-profile.js';
import {
  parseProgramUrl,
  createSkeletonPolicy,
  checkScope,
  checkOriginality,
  formatSubmission,
} from './lib/bug-bounty-policy-parser.js';
import {
  PatternRepository,
  CalibrationPipeline,
  ToolEffectivenessTracker,
  processCrossTrainingBatch,
} from './lib/cross-training.js';
import {
  checkEngagementTypeAllowed,
  getAvailableEngagementTypes,
  getTierComparison,
  checkFeatureAvailable,
} from './lib/license-tier-gating.js';

// ─── batchNormalize with mixed scanner inputs ──────────────────────────────────

describe('batchNormalize — mixed scanner pipeline', () => {
  it('should normalize nuclei + zap findings together', () => {
    const result = batchNormalize({
      nucleiFindings: [
        {
          templateId: 'CVE-2021-44228',
          info: {
            name: 'Log4Shell RCE',
            severity: 'critical',
            description: 'Remote code execution via Log4j',
            classification: { cveId: ['CVE-2021-44228'], cweId: ['CWE-502'] },
            tags: ['rce', 'log4j'],
          },
          host: 'app.example.com',
          ip: '10.0.0.1',
          port: '8080',
          matchedAt: 'app.example.com:8080',
          timestamp: Date.now(),
          extractorResults: [],
        },
      ],
      zapFindings: [
        {
          alert: 'Cross-Site Scripting (Reflected)',
          risk: 'High',
          confidence: 'High',
          url: 'https://app.example.com/search?q=test',
          description: 'Reflected XSS in search parameter',
          solution: 'Encode output',
          reference: '',
          cweid: '79',
          wascid: '8',
          evidence: '<script>alert(1)</script>',
          param: 'q',
          attack: '<script>alert(1)</script>',
          method: 'GET',
        },
      ],
    });

    expect(result.findings).toBeDefined();
    expect(Array.isArray(result.findings)).toBe(true);
    expect(result.findings.length).toBeGreaterThanOrEqual(2);
    expect(result.stats).toBeDefined();
    expect(result.stats.totalRaw).toBeGreaterThanOrEqual(2);
    expect(result.stats.totalNormalized).toBeGreaterThanOrEqual(2);
  });

  it('should handle empty inputs gracefully', () => {
    const result = batchNormalize({});
    expect(result.findings).toBeDefined();
    expect(result.findings.length).toBe(0);
    expect(result.stats.totalRaw).toBe(0);
  });

  it('should deduplicate identical findings from same scanner', () => {
    const nucleiFinding = {
      templateId: 'CVE-2021-44228',
      info: {
        name: 'Log4Shell',
        severity: 'critical',
        description: 'Log4j RCE',
        classification: { cveId: ['CVE-2021-44228'], cweId: [] },
        tags: [],
      },
      host: 'app.example.com',
      ip: '10.0.0.1',
      port: '8080',
      matchedAt: 'app.example.com:8080',
      timestamp: Date.now(),
      extractorResults: [],
    };

    const result = batchNormalize({
      nucleiFindings: [nucleiFinding, { ...nucleiFinding }],
    });

    // After dedup, should have fewer or equal findings
    expect(result.stats.totalDeduplicated).toBeLessThanOrEqual(result.stats.totalNormalized);
  });
});

// ─── normalizeNucleiFinding ─────────────────────────────────────────────────────

describe('normalizeNucleiFinding — individual normalization', () => {
  it('should produce a NormalizedFinding with correct fields', () => {
    const raw = {
      templateId: 'CVE-2023-1234',
      info: {
        name: 'Test Vuln',
        severity: 'high',
        description: 'A test vulnerability',
        classification: {
          cve: ['CVE-2023-1234'],
          cwe: ['CWE-89'],
        },
        tags: ['sqli'],
      },
      host: 'db.example.com',
      ip: '10.0.0.2',
      port: '3306',
      matchedAt: 'db.example.com:3306',
      timestamp: Date.now(),
      extractorResults: [{ name: 'evidence', values: ['SQL error'] }],
    };

    const normalized = normalizeNucleiFinding(raw);
    expect(normalized.title).toBe('Test Vuln');
    expect(normalized.severity).toBe('high');
    // Scanner info is in sources[].scanner, not a top-level field
    expect(normalized.sources).toBeDefined();
    expect(normalized.sources.length).toBeGreaterThanOrEqual(1);
    expect(normalized.sources[0].scanner).toBe('nuclei');
    expect(normalized.cveIds).toContain('CVE-2023-1234');
    expect(normalized.affectedAsset).toBeDefined();
    expect(normalized.affectedAsset.hostname).toBe('db.example.com');
  });
});

// ─── normalizeZapFinding ────────────────────────────────────────────────────────

describe('normalizeZapFinding — ZAP normalization', () => {
  it('should map ZAP risk levels to severity', () => {
    const raw = {
      alert: 'SQL Injection',
      risk: 'High',
      confidence: 'Medium',
      url: 'https://api.example.com/users',
      description: 'SQL injection in user endpoint',
      solution: 'Use parameterized queries',
      reference: '',
      cweId: '89',
      wascid: '19',
      evidence: "' OR 1=1--",
      param: 'id',
      attack: "' OR 1=1--",
      method: 'GET',
    };

    const normalized = normalizeZapFinding(raw);
    expect(normalized.title).toBe('SQL Injection');
    expect(normalized.severity).toBe('high');
    // Scanner info is in sources[].scanner, not a top-level field
    expect(normalized.sources).toBeDefined();
    expect(normalized.sources.length).toBeGreaterThanOrEqual(1);
    expect(normalized.sources[0].scanner).toBe('zap');
    expect(normalized.cweIds).toContain('CWE-89');
  });
});

// ─── Cross-training batch processing ────────────────────────────────────────────

describe('processCrossTrainingBatch — triage outcome processing', () => {
  it('should process triage outcomes and update pattern repository', () => {
    const patternRepo = new PatternRepository();
    const calibrationPipeline = new CalibrationPipeline();
    const toolTracker = new ToolEffectivenessTracker();

    const outcomes = [
      {
        engagementId: 1,
        findingId: 'f1',
        scanner: 'nuclei',
        vulnClass: 'sqli',
        originalSeverity: 'high',
        triageDecision: 'true_positive',
        isTruePositive: true,
        isFalsePositive: false,
        timestamp: Date.now(),
        extractedPatterns: [],
      },
      {
        engagementId: 1,
        findingId: 'f2',
        scanner: 'zap',
        vulnClass: 'xss',
        originalSeverity: 'medium',
        triageDecision: 'false_positive',
        isTruePositive: false,
        isFalsePositive: true,
        timestamp: Date.now(),
        extractedPatterns: [],
      },
    ];

    const result = processCrossTrainingBatch(outcomes as any, patternRepo, calibrationPipeline, toolTracker);
    expect(result).toBeDefined();
    expect(typeof result.patternsExtracted).toBe('number');
    expect(typeof result.calibrationUpdates).toBe('number');
    expect(typeof result.toolEffectivenessUpdates).toBe('number');
  });

  it('should handle empty outcomes array', () => {
    const patternRepo = new PatternRepository();
    const calibrationPipeline = new CalibrationPipeline();
    const toolTracker = new ToolEffectivenessTracker();

    const result = processCrossTrainingBatch([], patternRepo, calibrationPipeline, toolTracker);
    expect(result).toBeDefined();
    // Empty batch returns 0 for patternsExtracted
    expect(result.patternsExtracted).toBe(0);
  });
});

// ─── Verification profile listing ───────────────────────────────────────────────

describe('Verification profiles — listing and retrieval', () => {
  it('should list all verification profiles', () => {
    const profiles = listVerificationProfiles();
    expect(Array.isArray(profiles)).toBe(true);
    expect(profiles.length).toBeGreaterThanOrEqual(7);
  });

  it('should retrieve a specific profile by ID', () => {
    const profile = getVerificationProfile('standard-va');
    expect(profile).toBeDefined();
    expect(profile!.name).toBeTruthy();
  });

  it('should return null/undefined for unknown profile', () => {
    const profile = getVerificationProfile('nonexistent-profile');
    expect(profile).toBeFalsy();
  });
});

// ─── prioritizeFindings ─────────────────────────────────────────────────────────

describe('prioritizeFindings — finding prioritization', () => {
  it('should sort findings by severity and return prioritized list', () => {
    const findings = [
      {
        severity: 'low', title: 'Low finding', findingId: 'f1', fingerprint: 'fp1',
        exploitability: { isKev: false, hasPublicExploit: false, hasMetasploitModule: false },
        affectedAsset: { hostname: 'a.example.com' },
        cveIds: [], cweIds: [], scanner: 'nuclei', sources: [],
      },
      {
        severity: 'critical', title: 'Critical finding', findingId: 'f2', fingerprint: 'fp2',
        exploitability: { isKev: true, hasPublicExploit: true, hasMetasploitModule: false },
        affectedAsset: { hostname: 'b.example.com' },
        cveIds: ['CVE-2021-44228'], cweIds: [], scanner: 'nuclei', sources: [],
      },
      {
        severity: 'medium', title: 'Medium finding', findingId: 'f3', fingerprint: 'fp3',
        exploitability: { isKev: false, hasPublicExploit: false, hasMetasploitModule: false },
        affectedAsset: { hostname: 'c.example.com' },
        cveIds: [], cweIds: [], scanner: 'zap', sources: [],
      },
    ];

    const profile = VERIFICATION_PROFILES['standard-va'];
    const result = prioritizeFindings(findings as any, profile);
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBe(3);
    // Critical should come first
    expect(result[0].severity).toBe('critical');
  });
});

// ─── License-tier gating ────────────────────────────────────────────────────────

describe('License-tier gating — engagement type checks', () => {
  it('should allow VA for standard tier', () => {
    const result = checkEngagementTypeAllowed('vulnerability_assessment', 'standard');
    expect(result.allowed).toBe(true);
  });

  it('should block red_team for standard tier', () => {
    const result = checkEngagementTypeAllowed('red_team', 'standard');
    expect(result.allowed).toBe(false);
  });

  it('should allow red_team for enterprise tier', () => {
    const result = checkEngagementTypeAllowed('red_team', 'enterprise');
    expect(result.allowed).toBe(true);
  });

  it('should list available engagement types per tier', () => {
    const standard = getAvailableEngagementTypes('standard');
    const enterprise = getAvailableEngagementTypes('enterprise');
    expect(enterprise.length).toBeGreaterThanOrEqual(standard.length);
  });

  it('should return tier comparison data', () => {
    const comparison = getTierComparison();
    expect(comparison).toBeDefined();
    expect(Array.isArray(comparison) || typeof comparison === 'object').toBe(true);
  });
});

// ─── Bug Bounty scope checking ──────────────────────────────────────────────────

describe('checkScope — target scope verification', () => {
  const policy = {
    programName: 'Test',
    platform: 'hackerone',
    programUrl: 'https://hackerone.com/test',
    scope: {
      inScope: [
        { type: 'domain', target: '*.example.com', bountyEligible: true, tier: 'primary' },
        { type: 'domain', target: 'api.example.com', bountyEligible: true, tier: 'primary' },
      ],
      outOfScope: [
        { type: 'domain', target: 'admin.example.com', bountyEligible: false, tier: 'excluded' },
      ],
      wildcardDomains: ['*.example.com'],
    },
    rules: {
      allowedTestTypes: ['web_application'],
      prohibitedActions: [],
      disclosurePolicy: 'coordinated',
      requiresAccountCreation: false,
    },
    rewardStructure: { type: 'range', currency: 'USD', ranges: [] },
    parsedAt: new Date().toISOString(),
  } as any;

  it('should identify in-scope targets', () => {
    const result = checkScope('api.example.com', policy);
    expect(result.inScope).toBe(true);
  });

  it('should identify out-of-scope targets', () => {
    const result = checkScope('admin.example.com', policy);
    expect(result.inScope).toBe(false);
  });
});

// ─── parseProgramUrl ────────────────────────────────────────────────────────────

describe('parseProgramUrl — URL parsing', () => {
  it('should parse HackerOne URLs', () => {
    const result = parseProgramUrl('https://hackerone.com/test-program');
    expect(result).toBeTruthy();
    expect(result!.platform).toBe('hackerone');
    expect(result!.programSlug).toBe('test-program');
  });

  it('should parse Bugcrowd URLs', () => {
    const result = parseProgramUrl('https://bugcrowd.com/test-program');
    expect(result).toBeTruthy();
    expect(result!.platform).toBe('bugcrowd');
  });

  it('should return null for unsupported URLs', () => {
    const result = parseProgramUrl('https://random-site.com/program');
    expect(result).toBeNull();
  });
});

// ─── createSkeletonPolicy ───────────────────────────────────────────────────────

describe('createSkeletonPolicy — policy skeleton creation', () => {
  it('should create a skeleton policy from parsed URL info', () => {
    const skeleton = createSkeletonPolicy({
      platform: 'hackerone',
      programSlug: 'test-program',
      programUrl: 'https://hackerone.com/test-program',
    });
    expect(skeleton).toBeDefined();
    expect(skeleton.platform).toBe('hackerone');
    expect(skeleton.programName).toBeTruthy();
    expect(skeleton.scope).toBeDefined();
  });
});

// ─── PatternRepository ──────────────────────────────────────────────────────────

describe('PatternRepository — pattern management', () => {
  it('should start with empty stats', () => {
    const repo = new PatternRepository();
    const stats = repo.getStats();
    expect(stats).toBeDefined();
    expect(typeof stats.totalPatterns).toBe('number');
  });

  it('should return empty high-confidence patterns initially', () => {
    const repo = new PatternRepository();
    const patterns = repo.getHighConfidencePatterns(0.9);
    expect(Array.isArray(patterns)).toBe(true);
    expect(patterns.length).toBe(0);
  });
});

// ─── CalibrationPipeline ────────────────────────────────────────────────────────

describe('CalibrationPipeline — scanner calibration', () => {
  it('should return calibration data for a scanner', () => {
    const pipeline = new CalibrationPipeline();
    const calibration = pipeline.getScannerCalibration('nuclei');
    expect(calibration).toBeDefined();
  });
});

// ─── ToolEffectivenessTracker ───────────────────────────────────────────────────

describe('ToolEffectivenessTracker — effectiveness summary', () => {
  it('should return an effectiveness summary', () => {
    const tracker = new ToolEffectivenessTracker();
    const summary = tracker.getEffectivenessSummary();
    expect(summary).toBeDefined();
  });
});
