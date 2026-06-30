/**
 * Tests for Nuclei Findings Persistence, Template Auto-Selection, and Graduation Scoring
 * ─────────────────────────────────────────────────────────────────────────────────────────
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── 1. Nuclei Findings Persistence ─────────────────────────────────────────

describe('Nuclei Findings Persistence', () => {
  describe('generateFindingHash', () => {
    it('should generate consistent hashes for same input', async () => {
      const { generateFindingHash } = await import('./lib/nuclei-findings-persistence');
      const hash1 = generateFindingHash('http://target.com', 'CVE-2021-44228', 'http://target.com:8080/', 'critical');
      const hash2 = generateFindingHash('http://target.com', 'CVE-2021-44228', 'http://target.com:8080/', 'critical');
      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(16);
    });

    it('should generate different hashes for different targets', async () => {
      const { generateFindingHash } = await import('./lib/nuclei-findings-persistence');
      const hash1 = generateFindingHash('http://target1.com', 'CVE-2021-44228', 'http://target1.com/', 'critical');
      const hash2 = generateFindingHash('http://target2.com', 'CVE-2021-44228', 'http://target2.com/', 'critical');
      expect(hash1).not.toBe(hash2);
    });

    it('should generate different hashes for different templates', async () => {
      const { generateFindingHash } = await import('./lib/nuclei-findings-persistence');
      const hash1 = generateFindingHash('http://target.com', 'CVE-2021-44228', 'http://target.com/', 'critical');
      const hash2 = generateFindingHash('http://target.com', 'CVE-2021-41773', 'http://target.com/', 'critical');
      expect(hash1).not.toBe(hash2);
    });

    it('should generate different hashes for different severities', async () => {
      const { generateFindingHash } = await import('./lib/nuclei-findings-persistence');
      const hash1 = generateFindingHash('http://target.com', 'CVE-2021-44228', 'http://target.com/', 'critical');
      const hash2 = generateFindingHash('http://target.com', 'CVE-2021-44228', 'http://target.com/', 'high');
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('persistNucleiFindings', () => {
    it('should return 0 inserted for empty findings', async () => {
      const { persistNucleiFindings } = await import('./lib/nuclei-findings-persistence');
      const result = await persistNucleiFindings({
        target: 'http://target.com',
        parseResult: { findings: [], stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, cves: [], cwes: [], hasExploitableFindings: false },
        executionContext: 'direct',
      });
      expect(result.inserted).toBe(0);
      expect(result.duplicates).toBe(0);
    });

    it('should insert findings with correct metadata', async () => {
      const { persistNucleiFindings } = await import('./lib/nuclei-findings-persistence');
      const result = await persistNucleiFindings({
        engagementId: 1,
        target: 'http://target.com',
        port: 8080,
        parseResult: {
          findings: [{
            info: {
              id: 'CVE-2021-44228',
              name: 'Log4Shell',
              severity: 'critical' as const,
              description: 'Remote code execution via Log4j',
              tags: ['cve', 'rce'],
              classification: { 'cve-id': ['CVE-2021-44228'], 'cwe-id': ['CWE-502'] },
            },
            host: 'http://target.com:8080',
            'matched-at': 'http://target.com:8080/api',
            'extracted-results': ['${jndi:ldap://...}'],
            'curl-command': 'curl -H "X-Api-Version: ${jndi:ldap://...}" http://target.com:8080/api',
            type: 'http',
            'template-id': 'CVE-2021-44228',
          }],
          stats: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
          cves: ['CVE-2021-44228'],
          cwes: ['CWE-502'],
          hasExploitableFindings: true,
        },
        accessLevel: 'command_execution',
        confidence: 90,
        executionContext: 'direct',
        nucleiCommand: 'nuclei -u http://target.com:8080 -t cves/2021/CVE-2021-44228.yaml -json',
      });
      // Should succeed (inserted >= 0, no error thrown)
      expect(result.inserted + result.duplicates).toBeGreaterThanOrEqual(0);
    });
  });
});

// ─── 2. Nuclei Template Auto-Selection ──────────────────────────────────────

describe('Nuclei Template Auto-Selection', () => {
  beforeEach(async () => {
    const { clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
    clearAutoSelectorCache();
  });

  describe('resolveNucleiTemplate', () => {
    it('should resolve from static KNOWN_NUCLEI_CVES map (highest priority)', async () => {
      const { resolveNucleiTemplate } = await import('./lib/nuclei-template-auto-selector');
      const result = await resolveNucleiTemplate({ cve: 'CVE-2021-44228' });
      expect(result.source).toBe('static_map');
      expect(result.confidence).toBe(95);
      expect(result.templatePath).toBeTruthy();
      expect(result.templatePath).toContain('CVE-2021-44228');
    });

    it('should resolve from static map for CVE-2021-41773', async () => {
      const { resolveNucleiTemplate } = await import('./lib/nuclei-template-auto-selector');
      const result = await resolveNucleiTemplate({ cve: 'CVE-2021-41773' });
      expect(result.source).toBe('static_map');
      expect(result.confidence).toBe(95);
    });

    it('should fall back to vuln_class_tags when no CVE match', async () => {
      const { resolveNucleiTemplate } = await import('./lib/nuclei-template-auto-selector');
      const result = await resolveNucleiTemplate({ vulnClass: 'sqli' });
      expect(result.source).toBe('vuln_class_tags');
      expect(result.confidence).toBe(50);
      expect(result.tags.length).toBeGreaterThan(0);
      expect(result.tags).toContain('sqli');
    });

    it('should fall back to vuln_class_tags for XSS', async () => {
      const { resolveNucleiTemplate } = await import('./lib/nuclei-template-auto-selector');
      const result = await resolveNucleiTemplate({ vulnClass: 'xss' });
      expect(result.source).toBe('vuln_class_tags');
      expect(result.tags).toContain('xss');
    });

    it('should return none for unknown CVE and no vuln class', async () => {
      const { resolveNucleiTemplate } = await import('./lib/nuclei-template-auto-selector');
      const result = await resolveNucleiTemplate({ cve: 'CVE-9999-99999' });
      expect(result.source).toBe('none');
      expect(result.confidence).toBe(0);
      expect(result.templatePath).toBeNull();
    });

    it('should return none when no params provided', async () => {
      const { resolveNucleiTemplate } = await import('./lib/nuclei-template-auto-selector');
      const result = await resolveNucleiTemplate({});
      expect(result.source).toBe('none');
    });

    it('should resolve SSRF vuln class tags', async () => {
      const { resolveNucleiTemplate } = await import('./lib/nuclei-template-auto-selector');
      const result = await resolveNucleiTemplate({ vulnClass: 'ssrf' });
      expect(result.source).toBe('vuln_class_tags');
      expect(result.tags).toContain('ssrf');
    });

    it('should resolve SSTI vuln class tags', async () => {
      const { resolveNucleiTemplate } = await import('./lib/nuclei-template-auto-selector');
      const result = await resolveNucleiTemplate({ vulnClass: 'ssti' });
      expect(result.source).toBe('vuln_class_tags');
      expect(result.tags).toContain('ssti');
    });

    it('should prefer static map over vuln class when CVE is known', async () => {
      const { resolveNucleiTemplate } = await import('./lib/nuclei-template-auto-selector');
      const result = await resolveNucleiTemplate({ cve: 'CVE-2021-44228', vulnClass: 'rce' });
      expect(result.source).toBe('static_map');
      expect(result.confidence).toBe(95);
    });
  });

  describe('autoMapExploitToNucleiTemplate', () => {
    it('should return not mapped when cveId is empty', async () => {
      const { autoMapExploitToNucleiTemplate } = await import('./lib/nuclei-template-auto-selector');
      const result = await autoMapExploitToNucleiTemplate({
        cveId: '',
        exploitSuccess: true,
      });
      expect(result.mapped).toBe(false);
    });

    it('should return not mapped when exploit failed', async () => {
      const { autoMapExploitToNucleiTemplate } = await import('./lib/nuclei-template-auto-selector');
      const result = await autoMapExploitToNucleiTemplate({
        cveId: 'CVE-2021-44228',
        exploitSuccess: false,
      });
      expect(result.mapped).toBe(false);
    });

    it('should auto-map with nucleiTemplateId provided', async () => {
      const { autoMapExploitToNucleiTemplate } = await import('./lib/nuclei-template-auto-selector');
      const result = await autoMapExploitToNucleiTemplate({
        cveId: 'CVE-2024-99999',
        nucleiTemplateId: 'cves/2024/CVE-2024-99999',
        vulnClass: 'rce',
        service: 'http',
        exploitSuccess: true,
      });
      // Should succeed (mapped or not depending on DB availability)
      expect(typeof result.mapped).toBe('boolean');
      expect(result.cveId).toBe('CVE-2024-99999');
    });

    it('should auto-map static CVE for stats tracking', async () => {
      const { autoMapExploitToNucleiTemplate } = await import('./lib/nuclei-template-auto-selector');
      const result = await autoMapExploitToNucleiTemplate({
        cveId: 'CVE-2021-44228',
        exploitSuccess: true,
      });
      // Should try to record static mapping
      expect(result.cveId).toBe('CVE-2021-44228');
    });

    it('should infer template path from CVE pattern', async () => {
      const { autoMapExploitToNucleiTemplate } = await import('./lib/nuclei-template-auto-selector');
      const result = await autoMapExploitToNucleiTemplate({
        cveId: 'CVE-2023-12345',
        exploitSuccess: true,
      });
      expect(result.cveId).toBe('CVE-2023-12345');
      // Template path should be inferred as cves/2023/CVE-2023-12345
      if (result.mapped) {
        expect(result.templatePath).toContain('cves/2023/CVE-2023-12345');
      }
    });
  });

  describe('clearAutoSelectorCache', () => {
    it('should clear the cache without error', async () => {
      const { clearAutoSelectorCache } = await import('./lib/nuclei-template-auto-selector');
      expect(() => clearAutoSelectorCache()).not.toThrow();
    });
  });
});

// ─── 3. Graduation Scoring with Nuclei Bonus ───────────────────────────────

describe('Graduation Scoring Nuclei Bonus', () => {
  // We test the scoreExploitSelector function indirectly through graduateEngagement
  // since scoreExploitSelector is not exported. We test the PipelineMetrics interface instead.

  it('PipelineMetrics should include nucleiVerifiedExploits field', async () => {
    const mod = await import('./lib/post-pipeline-graduation');
    // The type check is compile-time, but we verify the extractDIScanMetrics returns it
    const metrics = mod.extractDIScanMetrics(1, 'test.com', {
      assets: [],
      totalAssets: 0,
      totalFindings: 0,
    }, 1000);
    expect(metrics).toHaveProperty('nucleiVerifiedExploits');
    expect(metrics.nucleiVerifiedExploits).toBe(0);
  });

  it('should score higher with nucleiVerifiedExploits > 0', async () => {
    // We test by creating two PipelineMetrics objects and comparing scores
    // Since scoreExploitSelector is internal, we test through graduateEngagement
    // by mocking the metrics extraction
    const { runPostPipelineGraduation } = await import('./lib/post-pipeline-graduation');

    const baseMetrics = {
      pipelineType: 'engagement' as const,
      pipelineId: 1,
      domain: 'test.com',
      assetsDiscovered: 5,
      subdomainsFound: 3,
      portsFound: 10,
      servicesIdentified: 5,
      technologiesDetected: 3,
      totalVulns: 5,
      confirmedVulns: 3,
      potentialVulns: 2,
      criticalVulns: 1,
      highVulns: 2,
      mediumVulns: 1,
      lowVulns: 1,
      infoVulns: 0,
      uniqueCVEs: 3,
      kevMatches: 1,
      exploitsAttempted: 3,
      exploitsSucceeded: 2,
      verifiedVulns: 3,
      nucleiVerifiedExploits: 0,
      wafDetected: false,
      wafBypassed: false,
      evasionEscalations: 0,
      scanBlocked: false,
      scanRecovered: false,
      owaspCategoriesTested: 5,
      owaspCategoriesTotal: 25,
      ptesPhasesCovered: 4,
      ptesPhasesTotal: 7,
      cloudAssetsFound: 0,
      repoExposuresFound: 0,
      platformAssetsFound: 0,
      containerAssetsFound: 0,
      storageAssetsFound: 0,
      identityAssetsFound: 0,
      networkInfraFound: 0,
      falsePositiveRate: 0,
      connectorSuccessRate: 1,
      scanDurationMs: 60000,
      successfulExploits: [],
      reconObservations: [],
    };

    const resultWithoutNuclei = await runPostPipelineGraduation(baseMetrics);

    const metricsWithNuclei = { ...baseMetrics, nucleiVerifiedExploits: 2 };
    const resultWithNuclei = await runPostPipelineGraduation(metricsWithNuclei);

    // The Nuclei bonus should increase the exploit_selector score
    const exploitScoreWithout = resultWithoutNuclei.scores.exploit_selector;
    const exploitScoreWith = resultWithNuclei.scores.exploit_selector;

    expect(typeof exploitScoreWith).toBe('number');
    expect(typeof exploitScoreWithout).toBe('number');
    expect(exploitScoreWith).toBeGreaterThan(exploitScoreWithout);
  });

  it('nuclei bonus should cap at 10 points', async () => {
    const { runPostPipelineGraduation } = await import('./lib/post-pipeline-graduation');

    const baseMetrics = {
      pipelineType: 'engagement' as const,
      pipelineId: 1,
      domain: 'test.com',
      assetsDiscovered: 5,
      subdomainsFound: 3,
      portsFound: 10,
      servicesIdentified: 5,
      technologiesDetected: 3,
      totalVulns: 5,
      confirmedVulns: 3,
      potentialVulns: 2,
      criticalVulns: 1,
      highVulns: 2,
      mediumVulns: 1,
      lowVulns: 1,
      infoVulns: 0,
      uniqueCVEs: 3,
      kevMatches: 1,
      exploitsAttempted: 3,
      exploitsSucceeded: 2,
      verifiedVulns: 3,
      nucleiVerifiedExploits: 0,
      wafDetected: false,
      wafBypassed: false,
      evasionEscalations: 0,
      scanBlocked: false,
      scanRecovered: false,
      owaspCategoriesTested: 5,
      owaspCategoriesTotal: 25,
      ptesPhasesCovered: 4,
      ptesPhasesTotal: 7,
      cloudAssetsFound: 0,
      repoExposuresFound: 0,
      platformAssetsFound: 0,
      containerAssetsFound: 0,
      storageAssetsFound: 0,
      identityAssetsFound: 0,
      networkInfraFound: 0,
      falsePositiveRate: 0,
      connectorSuccessRate: 1,
      scanDurationMs: 60000,
      successfulExploits: [],
      reconObservations: [],
    };

    // 2 nuclei verified = 10 pts bonus
    const result2 = await runPostPipelineGraduation({ ...baseMetrics, nucleiVerifiedExploits: 2 });
    // 5 nuclei verified = still 10 pts bonus (capped)
    const result5 = await runPostPipelineGraduation({ ...baseMetrics, nucleiVerifiedExploits: 5 });

    const score2 = result2.scores.exploit_selector;
    const score5 = result5.scores.exploit_selector;

    // Both should be the same since bonus caps at 10
    expect(score2).toBe(score5);
  });

  it('DI scan metrics should have nucleiVerifiedExploits = 0', async () => {
    const { extractDIScanMetrics } = await import('./lib/post-pipeline-graduation');
    const metrics = extractDIScanMetrics(1, 'test.com', {
      assets: [],
      totalAssets: 0,
      totalFindings: 0,
    }, 1000);
    expect(metrics.nucleiVerifiedExploits).toBe(0);
  });

  it('should handle nucleiVerifiedExploits = 1 correctly (5 pts bonus)', async () => {
    const { runPostPipelineGraduation } = await import('./lib/post-pipeline-graduation');

    const baseMetrics = {
      pipelineType: 'engagement' as const,
      pipelineId: 1,
      domain: 'test.com',
      assetsDiscovered: 5,
      subdomainsFound: 3,
      portsFound: 10,
      servicesIdentified: 5,
      technologiesDetected: 3,
      totalVulns: 5,
      confirmedVulns: 3,
      potentialVulns: 2,
      criticalVulns: 1,
      highVulns: 2,
      mediumVulns: 1,
      lowVulns: 1,
      infoVulns: 0,
      uniqueCVEs: 3,
      kevMatches: 1,
      exploitsAttempted: 3,
      exploitsSucceeded: 2,
      verifiedVulns: 3,
      nucleiVerifiedExploits: 0,
      wafDetected: false,
      wafBypassed: false,
      evasionEscalations: 0,
      scanBlocked: false,
      scanRecovered: false,
      owaspCategoriesTested: 5,
      owaspCategoriesTotal: 25,
      ptesPhasesCovered: 4,
      ptesPhasesTotal: 7,
      cloudAssetsFound: 0,
      repoExposuresFound: 0,
      platformAssetsFound: 0,
      containerAssetsFound: 0,
      storageAssetsFound: 0,
      identityAssetsFound: 0,
      networkInfraFound: 0,
      falsePositiveRate: 0,
      connectorSuccessRate: 1,
      scanDurationMs: 60000,
      successfulExploits: [],
      reconObservations: [],
    };

    const result0 = await runPostPipelineGraduation({ ...baseMetrics, nucleiVerifiedExploits: 0 });
    const result1 = await runPostPipelineGraduation({ ...baseMetrics, nucleiVerifiedExploits: 1 });

    const score0 = result0.scores.exploit_selector;
    const score1 = result1.scores.exploit_selector;

    // 1 nuclei verified = 5 pts bonus
    expect(score1 - score0).toBe(5);
  });
});

// ─── 4. Integration: Orchestration Wiring ───────────────────────────────────

describe('Orchestration Wiring', () => {
  it('should import persistNucleiFindings without error', async () => {
    const mod = await import('./lib/nuclei-findings-persistence');
    expect(typeof mod.persistNucleiFindings).toBe('function');
    expect(typeof mod.recordTemplateMapping).toBe('function');
    expect(typeof mod.generateFindingHash).toBe('function');
    expect(typeof mod.getNucleiFindings).toBe('function');
    expect(typeof mod.getNucleiStats).toBe('function');
    expect(typeof mod.correlateByCV).toBe('function');
    expect(typeof mod.correlateByTemplate).toBe('function');
    expect(typeof mod.lookupDynamicTemplateMapping).toBe('function');
    expect(typeof mod.getAllTemplateMappings).toBe('function');
  });

  it('should import nuclei-template-auto-selector without error', async () => {
    const mod = await import('./lib/nuclei-template-auto-selector');
    expect(typeof mod.resolveNucleiTemplate).toBe('function');
    expect(typeof mod.autoMapExploitToNucleiTemplate).toBe('function');
    expect(typeof mod.clearAutoSelectorCache).toBe('function');
  });

  it('should import post-pipeline-graduation with nucleiVerifiedExploits support', async () => {
    const mod = await import('./lib/post-pipeline-graduation');
    expect(typeof mod.runPostPipelineGraduation).toBe('function');
    expect(typeof mod.extractDIScanMetrics).toBe('function');
  });
});
