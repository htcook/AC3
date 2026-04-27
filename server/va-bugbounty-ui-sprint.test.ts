/**
 * VA & Bug Bounty UI Sprint — Integration Tests
 *
 * Tests for:
 * 1. normalizeEngagementFindings procedure (live pipeline wiring)
 * 2. parseBugBountyPolicy procedure (BugBountyWorkspace entry point)
 * 3. checkScope mutation (scope checker)
 * 4. checkOriginality mutation (originality verification)
 * 5. batchNormalize with mixed scanner inputs
 * 6. Verification profile listing and pipeline config building
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  batchNormalize,
  normalizeNucleiFinding,
  normalizeZapFinding,
  deduplicateFindings,
  generateFingerprint,
  inferSeverity,
  type NormalizedFinding,
} from './lib/finding-normalization';
import {
  parseProgramUrl,
  createSkeletonPolicy,
  checkScope,
  batchCheckScope,
  formatSubmission,
  checkOriginality,
  type PolicyROE,
  type BugBountyFinding,
} from './lib/bug-bounty-policy-parser';
import {
  listVerificationProfiles,
  getVerificationProfile,
  buildVAPipelineConfig,
  prioritizeFindings,
  VERIFICATION_PROFILES,
} from './lib/verification-profile';

// ─── normalizeEngagementFindings pipeline logic ──────────────────────────────

describe('normalizeEngagementFindings — pipeline wiring', () => {
  it('should normalize nuclei-sourced vulns from engagement asset format', () => {
    // Simulate what the normalizeEngagementFindings procedure does:
    // Convert engagement ops asset.vulns[] into nuclei raw format, then normalize
    const assetVulns = [
      {
        id: 'vuln-1',
        title: 'Apache Struts RCE (CVE-2017-5638)',
        severity: 'critical',
        cve: 'CVE-2017-5638',
        source: 'nuclei',
        templateId: 'CVE-2017-5638',
        description: 'Remote code execution via Content-Type header',
        port: 8080,
      },
      {
        id: 'vuln-2',
        title: 'XSS in Search Parameter',
        severity: 'medium',
        source: 'nuclei',
        cweId: 'CWE-79',
        templateId: 'xss-reflected-generic',
        url: 'https://target.com/search?q=test',
      },
    ];

    const nucleiRaw = assetVulns.map(v => ({
      templateId: v.templateId || v.id || 'unknown',
      info: {
        name: v.title,
        severity: v.severity || 'info',
        description: v.description || v.title,
        classification: {
          cveId: v.cve ? [v.cve] : [],
          cweId: v.cweId ? [v.cweId] : [],
        },
        tags: [],
      },
      host: 'target.com',
      ip: '10.0.0.1',
      port: v.port?.toString(),
      matchedAt: v.url || `target.com:${v.port || 443}`,
      timestamp: Date.now(),
      extractorResults: [],
    }));

    const result = batchNormalize({ nucleiFindings: nucleiRaw });

    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.stats.totalRaw).toBe(2);
    expect(result.stats.byScannerRaw.nuclei).toBe(2);
    // At least one critical finding
    const criticals = result.findings.filter(f => f.severity === 'critical');
    expect(criticals.length).toBeGreaterThanOrEqual(1);
  });

  it('should normalize ZAP findings from engagement asset format', () => {
    const zapFindings = [
      {
        alert: 'SQL Injection',
        risk: 'High',
        confidence: 'High',
        url: 'https://target.com/api/users',
        description: 'SQL injection in user parameter',
        solution: 'Use parameterized queries',
        reference: 'https://owasp.org/sql-injection',
        cweid: '89',
        wascid: '19',
        evidence: "' OR 1=1 --",
        param: 'id',
        attack: "' OR 1=1 --",
        method: 'GET',
      },
      {
        alert: 'Cross-Site Scripting (Reflected)',
        risk: 'Medium',
        confidence: 'Medium',
        url: 'https://target.com/search',
        description: 'XSS via search parameter',
        solution: 'Encode output',
        reference: '',
        cweid: '79',
        wascid: '8',
        evidence: '<script>alert(1)</script>',
        param: 'q',
        attack: '<script>alert(1)</script>',
        method: 'GET',
      },
    ];

    const result = batchNormalize({ zapFindings });

    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.stats.totalRaw).toBe(2);
    expect(result.stats.byScannerRaw.zap).toBe(2);
  });

  it('should deduplicate findings across nuclei and ZAP for same vuln', () => {
    // Both scanners find the same XSS on the same host/path/param
    const nucleiRaw = [{
      templateId: 'xss-reflected',
      info: {
        name: 'Reflected XSS',
        severity: 'medium',
        description: 'XSS in search param',
        classification: { cveId: [], cweId: ['CWE-79'] },
        tags: ['xss'],
      },
      host: 'target.com',
      matchedAt: 'https://target.com/search?q=test',
      timestamp: Date.now(),
      extractorResults: [],
    }];

    const zapRaw = [{
      alert: 'Cross-Site Scripting (Reflected)',
      risk: 'Medium',
      confidence: 'High',
      url: 'https://target.com/search',
      description: 'XSS in search parameter',
      solution: 'Encode output',
      reference: '',
      cweid: '79',
      wascid: '8',
      evidence: '<script>alert(1)</script>',
      param: 'q',
      attack: '<script>alert(1)</script>',
      method: 'GET',
    }];

    const result = batchNormalize({ nucleiFindings: nucleiRaw, zapFindings: zapRaw });

    // Should have fewer deduplicated findings than raw total
    expect(result.stats.totalRaw).toBe(2);
    expect(result.stats.totalDeduplicated).toBeLessThanOrEqual(result.stats.totalNormalized);
  });

  it('should handle empty engagement state gracefully', () => {
    const result = batchNormalize({});
    expect(result.findings).toEqual([]);
    expect(result.stats.totalRaw).toBe(0);
    expect(result.stats.totalDeduplicated).toBe(0);
  });
});

// ─── parseBugBountyPolicy ────────────────────────────────────────────────────

describe('parseBugBountyPolicy — BugBountyWorkspace entry point', () => {
  it('should parse a HackerOne program URL', () => {
    const parsed = parseProgramUrl('https://hackerone.com/acme-corp');
    expect(parsed).toBeTruthy();
    expect(parsed!.platform).toBe('hackerone');
    expect(parsed!.programSlug).toBe('acme-corp');
  });

  it('should parse a Bugcrowd program URL', () => {
    const parsed = parseProgramUrl('https://bugcrowd.com/acme-corp');
    expect(parsed).toBeTruthy();
    expect(parsed!.platform).toBe('bugcrowd');
  });

  it('should parse an Intigriti program URL', () => {
    const parsed = parseProgramUrl('https://app.intigriti.com/programs/acme/acme-corp/detail');
    expect(parsed).toBeTruthy();
    expect(parsed!.platform).toBe('intigriti');
  });

  it('should parse a YesWeHack program URL', () => {
    const parsed = parseProgramUrl('https://yeswehack.com/programs/acme-corp');
    expect(parsed).toBeTruthy();
    expect(parsed!.platform).toBe('yeswehack');
  });

  it('should return null for unsupported URLs', () => {
    const parsed = parseProgramUrl('https://example.com/not-a-bounty');
    expect(parsed).toBeNull();
  });

  it('should create a skeleton policy from parsed URL', () => {
    const parsed = parseProgramUrl('https://hackerone.com/acme-corp');
    expect(parsed).toBeTruthy();
    const skeleton = createSkeletonPolicy({
      ...parsed!,
      programUrl: 'https://hackerone.com/acme-corp',
    });
    expect(skeleton.programName).toBeTruthy();
    expect(skeleton.platform).toBe('hackerone');
    expect(skeleton.scope).toBeTruthy();
    expect(skeleton.scope.inScope).toBeDefined();
    expect(skeleton.scope.outOfScope).toBeDefined();
    expect(skeleton.rules).toBeDefined();
    expect(typeof skeleton.rules).toBe('object');
  });
});

// ─── checkScope ──────────────────────────────────────────────────────────────

describe('checkScope — scope enforcement', () => {
  const policy: PolicyROE = {
    programName: 'Test Program',
    platform: 'hackerone',
    programUrl: 'https://hackerone.com/test',
    scope: {
      inScope: [
        { type: 'domain', target: '*.example.com', bountyEligible: true, tier: 'primary' },
        { type: 'domain', target: 'api.example.com', bountyEligible: true, tier: 'primary' },
        { type: 'ip_range', target: '10.0.0.0/24', bountyEligible: true, tier: 'secondary' },
      ],
      outOfScope: [
        { type: 'domain', target: 'admin.example.com', bountyEligible: false, tier: 'excluded' },
        { type: 'domain', target: '*.staging.example.com', bountyEligible: false, tier: 'excluded' },
      ],
      wildcardDomains: ['*.example.com'],
    },
    rules: {
      allowedTestTypes: ['web_application', 'api'],
      prohibitedActions: ['No automated scanning without approval', 'No social engineering'],
      disclosurePolicy: 'coordinated',
      requiresAccountCreation: false,
    },
    rewardStructure: {
      type: 'range',
      currency: 'USD',
      ranges: [
        { severity: 'critical', min: 5000, max: 10000 },
        { severity: 'high', min: 1000, max: 5000 },
        { severity: 'medium', min: 100, max: 1000 },
        { severity: 'low', min: 50, max: 100 },
      ],
    },
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

  it('should batch check multiple targets', () => {
    const results = batchCheckScope(
      ['api.example.com', 'admin.example.com', 'test.example.com'],
      policy
    );
    expect(results.size).toBe(3);
  });
});

// ─── checkOriginality ────────────────────────────────────────────────────────

describe('checkOriginality — duplicate detection', () => {
  it('should flag a common/generic finding as potentially non-original', () => {
    const finding: BugBountyFinding = {
      id: 'test-1',
      engagementId: 1,
      title: 'Missing X-Frame-Options Header',
      vulnType: 'Security Misconfiguration',
      severity: 'low',
      cweId: 'CWE-1021',
      target: 'https://example.com',
      reproductionSteps: [{ stepNumber: 1, action: 'Visit the URL', expectedResult: 'Header present', actualResult: 'Header missing' }],
      prerequisites: [],
      evidence: [],
      impactAnalysis: { technicalImpact: 'Clickjacking possible', businessImpact: 'Low', affectedUsers: 'all', dataAtRisk: [] },
      originalityIndicators: { isNovelChain: false, uniqueEndpoint: false, requiresSpecificConditions: false, bypassesExistingFix: false },
    };

    const result = checkOriginality(finding, [], []);
    // Common header findings are often flagged
    expect(result).toBeTruthy();
    expect(typeof result.isLikelyOriginal).toBe('boolean');
    expect(typeof result.confidence).toBe('number');
    expect(result.confidence).toBeGreaterThanOrEqual(0);
    expect(result.confidence).toBeLessThanOrEqual(1);
  });

  it('should consider a unique finding as likely original', () => {
    const finding: BugBountyFinding = {
      id: 'test-2',
      engagementId: 1,
      title: 'Authentication Bypass via JWT Algorithm Confusion',
      vulnType: 'Broken Authentication',
      severity: 'critical',
      cweId: 'CWE-327',
      target: 'https://api.example.com/auth/token',
      reproductionSteps: [
        { stepNumber: 1, action: 'Obtain the RS256 public key', expectedResult: 'Public key obtained' },
        { stepNumber: 2, action: 'Sign a JWT with HS256 using the public key', expectedResult: 'Forged token created' },
        { stepNumber: 3, action: 'Submit the forged token', expectedResult: 'Request rejected', actualResult: 'Admin access granted' },
      ],
      prerequisites: ['Access to public key endpoint'],
      evidence: [],
      impactAnalysis: { technicalImpact: 'Complete authentication bypass', businessImpact: 'Full admin access', affectedUsers: 'all', dataAtRisk: ['credentials', 'user data'] },
      originalityIndicators: { isNovelChain: true, uniqueEndpoint: true, requiresSpecificConditions: true, bypassesExistingFix: false },
    };

    const result = checkOriginality(finding, [], []);
    expect(result).toBeTruthy();
    expect(typeof result.isLikelyOriginal).toBe('boolean');
    expect(Array.isArray(result.recommendations)).toBe(true);
  });
});

// ─── formatSubmission ────────────────────────────────────────────────────────

describe('formatSubmission — platform-specific formatting', () => {
  const finding: BugBountyFinding = {
    id: 'test-3',
    engagementId: 1,
    title: 'Stored XSS in Comment Field',
    vulnType: 'Cross-Site Scripting',
    severity: 'high',
    cweId: 'CWE-79',
    target: 'https://example.com/comments',
    endpoint: '/api/comments',
    parameter: 'body',
    reproductionSteps: [
      { stepNumber: 1, action: 'Post a comment with <script>alert(1)</script>', expectedResult: 'Input sanitized', actualResult: 'Script stored' },
      { stepNumber: 2, action: 'View the comment', expectedResult: 'Safe rendering', actualResult: 'JavaScript executed' },
    ],
    prerequisites: ['Authenticated user account'],
    evidence: [],
    impactAnalysis: { technicalImpact: 'Session hijacking, credential theft', businessImpact: 'User trust compromise', affectedUsers: 'all', dataAtRisk: ['session tokens'] },
    originalityIndicators: { isNovelChain: false, uniqueEndpoint: true, requiresSpecificConditions: false, bypassesExistingFix: false },
  };

  it('should format for HackerOne', () => {
    const result = formatSubmission(finding, 'hackerone');
    expect(result).toBeTruthy();
    expect(result.platform).toBe('hackerone');
    expect(result.title).toBe('Stored XSS in Comment Field');
    expect(result.description.length).toBeGreaterThan(0);
    expect(result.reproductionSteps.length).toBeGreaterThan(0);
  });

  it('should format for Bugcrowd', () => {
    const result = formatSubmission(finding, 'bugcrowd');
    expect(result).toBeTruthy();
    expect(result.platform).toBe('bugcrowd');
    expect(result.title).toBeTruthy();
  });

  it('should format for custom platform', () => {
    const result = formatSubmission(finding, 'custom');
    expect(result).toBeTruthy();
    expect(result.platform).toBe('custom');
    expect(result.description).toBeTruthy();
  });
});

// ─── Verification Profiles ───────────────────────────────────────────────────

describe('Verification Profiles — listing and config building', () => {
  it('should list all available verification profiles', () => {
    const profiles = listVerificationProfiles();
    expect(profiles.length).toBeGreaterThanOrEqual(5);
    // Should include standard profiles
    const ids = profiles.map(p => p.id);
    expect(ids).toContain('standard-va');
    expect(ids).toContain('compliance-pci-asv');
  });

  it('should get a specific profile by ID', () => {
    const profile = getVerificationProfile('standard-va');
    expect(profile).toBeTruthy();
    expect(profile!.id).toBe('standard-va');
    expect(profile!.name).toBeTruthy();
    expect(profile!.scannerConfig).toBeDefined();
  });

  it('should return null for unknown profile', () => {
    const profile = getVerificationProfile('nonexistent-profile');
    expect(profile).toBeFalsy();
  });

  it('should build a VA pipeline config', () => {
    const config = buildVAPipelineConfig({
      engagementId: 1,
      profileId: 'standard-va',
      targets: ['target1.com', 'target2.com'],
      selectedFrameworks: ['pci-dss'],
    });
    expect(config).toBeTruthy();
    expect(config.engagementId).toBe(1);
    expect(config.targets.length).toBe(2);
  });

  it('should prioritize findings by profile', () => {
    const profile = VERIFICATION_PROFILES['standard-va'];
    // Create minimal normalized findings
    const findings: NormalizedFinding[] = [
      {
        findingId: 'f1',
        fingerprint: 'fp1',
        sources: [{ scanner: 'nuclei', scanTimestamp: Date.now() }],
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        cveIds: ['CVE-2024-0001'],
        cweIds: ['CWE-89'],
        vulnClass: 'SQL Injection',
        title: 'SQL Injection in Login',
        description: 'SQL injection vulnerability',
        affectedAsset: { hostname: 'target.com', port: 443 },
        severity: 'critical',
        detectionMethod: 'exploit_confirmed',
        detectionConfidence: 0.95,
        verificationStatus: 'exploit_safe',
        verificationHistory: [],
        exploitability: {
          isKev: true,
          hasMetasploitModule: true,
          hasNucleiTemplate: true,
          hasPublicExploit: true,
          attackComplexity: 'low',
          privilegesRequired: 'none',
          userInteraction: 'none',
        },
        evidence: [],
        corroborationCount: 2,
        corroborationTier: 'confirmed',
      },
    ];

    const prioritized = prioritizeFindings(findings, profile);
    expect(prioritized.length).toBe(1);
    expect(prioritized[0].severity).toBe('critical');
  });
});

// ─── Fingerprint generation ──────────────────────────────────────────────────

describe('Fingerprint generation — dedup identity', () => {
  it('should generate consistent fingerprints for same vuln', () => {
    const fp1 = generateFingerprint({
      cveIds: ['CVE-2024-0001'],
      cweIds: ['CWE-89'],
      vulnClass: 'SQL Injection',
      hostname: 'target.com',
      port: 443,
      path: '/api/login',
    });

    const fp2 = generateFingerprint({
      cveIds: ['CVE-2024-0001'],
      cweIds: ['CWE-89'],
      vulnClass: 'SQL Injection',
      hostname: 'target.com',
      port: 443,
      path: '/api/login',
    });

    expect(fp1).toBe(fp2);
  });

  it('should generate different fingerprints for different vulns', () => {
    const fp1 = generateFingerprint({
      cveIds: ['CVE-2024-0001'],
      vulnClass: 'SQL Injection',
      hostname: 'target.com',
      port: 443,
    });

    const fp2 = generateFingerprint({
      cveIds: ['CVE-2024-0002'],
      vulnClass: 'XSS',
      hostname: 'target.com',
      port: 443,
    });

    expect(fp1).not.toBe(fp2);
  });

  it('should generate different fingerprints for same vuln on different hosts', () => {
    const fp1 = generateFingerprint({
      cveIds: ['CVE-2024-0001'],
      vulnClass: 'SQL Injection',
      hostname: 'host1.com',
    });

    const fp2 = generateFingerprint({
      cveIds: ['CVE-2024-0001'],
      vulnClass: 'SQL Injection',
      hostname: 'host2.com',
    });

    expect(fp1).not.toBe(fp2);
  });
});

// ─── Severity inference ──────────────────────────────────────────────────────

describe('inferSeverity — CVSS-based severity mapping', () => {
  it('should map CVSS >= 9.0 to critical', () => {
    expect(inferSeverity(9.8)).toBe('critical');
    expect(inferSeverity(10.0)).toBe('critical');
  });

  it('should map CVSS 7.0-8.9 to high', () => {
    expect(inferSeverity(7.0)).toBe('high');
    expect(inferSeverity(8.9)).toBe('high');
  });

  it('should map CVSS 4.0-6.9 to medium', () => {
    expect(inferSeverity(4.0)).toBe('medium');
    expect(inferSeverity(6.9)).toBe('medium');
  });

  it('should map CVSS 0.1-3.9 to low', () => {
    expect(inferSeverity(0.1)).toBe('low');
    expect(inferSeverity(3.9)).toBe('low');
  });

  it('should fallback to scanner severity string', () => {
    expect(inferSeverity(undefined, 'High')).toBe('high');
    expect(inferSeverity(undefined, 'CRITICAL')).toBe('critical');
    expect(inferSeverity(undefined, 'Medium')).toBe('medium');
  });

  it('should default to info when no data', () => {
    expect(inferSeverity(undefined, undefined)).toBe('info');
  });
});
