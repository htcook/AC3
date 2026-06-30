import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { PipelineMetrics } from './post-pipeline-graduation';

// Mock graduation-lab-bridge to avoid side effects
vi.mock('./graduation-lab-bridge', () => ({
  recordScenarioResult: vi.fn(),
  recordTrainingData: vi.fn(),
}));

describe('post-pipeline-graduation', () => {
  let runPostPipelineGraduation: typeof import('./post-pipeline-graduation').runPostPipelineGraduation;
  let extractDIScanMetrics: typeof import('./post-pipeline-graduation').extractDIScanMetrics;
  let extractEngagementMetrics: typeof import('./post-pipeline-graduation').extractEngagementMetrics;
  let mockRecordScenarioResult: ReturnType<typeof vi.fn>;
  let mockRecordTrainingData: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const mod = await import('./post-pipeline-graduation');
    runPostPipelineGraduation = mod.runPostPipelineGraduation;
    extractDIScanMetrics = mod.extractDIScanMetrics;
    extractEngagementMetrics = mod.extractEngagementMetrics;
    const bridge = await import('./graduation-lab-bridge');
    mockRecordScenarioResult = bridge.recordScenarioResult as ReturnType<typeof vi.fn>;
    mockRecordTrainingData = bridge.recordTrainingData as ReturnType<typeof vi.fn>;
  });

  function makeBaseMetrics(overrides: Partial<PipelineMetrics> = {}): PipelineMetrics {
    return {
      pipelineType: 'di_scan',
      pipelineId: 1,
      domain: 'example.com',
      assetsDiscovered: 5,
      subdomainsFound: 3,
      portsFound: 10,
      servicesIdentified: 6,
      technologiesDetected: 4,
      totalVulns: 8,
      confirmedVulns: 3,
      potentialVulns: 5,
      criticalVulns: 1,
      highVulns: 2,
      mediumVulns: 3,
      lowVulns: 1,
      infoVulns: 1,
      uniqueCVEs: 4,
      kevMatches: 1,
      exploitsAttempted: 0,
      exploitsSucceeded: 0,
      verifiedVulns: 3,
      wafDetected: false,
      wafBypassed: false,
      evasionEscalations: 0,
      scanBlocked: false,
      scanRecovered: false,
      owaspCategoriesTested: 0,
      owaspCategoriesTotal: 25,
      ptesPhasesCovered: 3,
      ptesPhasesTotal: 7,
      cloudAssetsFound: 0,
      repoExposuresFound: 0,
      platformAssetsFound: 0,
      containerAssetsFound: 0,
      storageAssetsFound: 0,
      identityAssetsFound: 0,
      networkInfraFound: 0,
      falsePositiveRate: 0,
      connectorSuccessRate: 0.8,
      scanDurationMs: 60000,
      successfulExploits: [],
      reconObservations: [],
      ...overrides,
    };
  }

  describe('runPostPipelineGraduation', () => {
    it('should score all 6 specialist models', async () => {
      const metrics = makeBaseMetrics();
      const result = await runPostPipelineGraduation(metrics);

      expect(result.modelsScored).toBe(6);
      expect(result.scores).toHaveProperty('recon_analyst');
      expect(result.scores).toHaveProperty('exploit_selector');
      expect(result.scores).toHaveProperty('evasion_optimizer');
      expect(result.scores).toHaveProperty('cognitive_core');
      expect(result.scores).toHaveProperty('cloud_assessor');
      expect(result.scores).toHaveProperty('supply_chain_analyst');
    });

    it('should record 4 scenario results via graduation-lab-bridge', async () => {
      const metrics = makeBaseMetrics();
      await runPostPipelineGraduation(metrics);

      expect(mockRecordScenarioResult).toHaveBeenCalledTimes(4);
      const calls = mockRecordScenarioResult.mock.calls;
      const models = calls.map((c: any[]) => c[0].model);
      expect(models).toContain('recon_analyst');
      expect(models).toContain('exploit_selector');
      expect(models).toContain('evasion_optimizer');
      expect(models).toContain('cognitive_core');
    });

    it('should collect training examples from successful exploits', async () => {
      const metrics = makeBaseMetrics({
        pipelineType: 'engagement',
        successfulExploits: [
          { id: 'e1', target: '10.0.0.1', vulnTitle: 'SQLi', technique: 'T1190', tool: 'sqlmap', command: 'sqlmap -u ...', rawEvidence: 'pwned' },
          { id: 'e2', target: '10.0.0.2', vulnTitle: 'RCE', technique: 'T1059', tool: 'metasploit', command: 'exploit/...', rawEvidence: 'shell' },
        ],
      });
      const result = await runPostPipelineGraduation(metrics);

      expect(result.trainingExamplesCollected).toBe(2);
      expect(mockRecordTrainingData).toHaveBeenCalledWith('exploit_selector', expect.any(Array));
    });

    it('should collect training examples from recon observations', async () => {
      const metrics = makeBaseMetrics({
        reconObservations: [
          { source: 'shodan', assetType: 'host', name: 'example.com', ip: '1.2.3.4', findings: 5 },
          { source: 'censys', assetType: 'subdomain', name: 'sub.example.com', findings: 3 },
        ],
      });
      const result = await runPostPipelineGraduation(metrics);

      expect(result.trainingExamplesCollected).toBe(2);
      expect(mockRecordTrainingData).toHaveBeenCalledWith('recon_analyst', expect.any(Array));
    });

    it('should score recon_analyst higher with more assets', async () => {
      const low = makeBaseMetrics({ assetsDiscovered: 1, subdomainsFound: 0, portsFound: 1, servicesIdentified: 0, technologiesDetected: 0 });
      const high = makeBaseMetrics({ assetsDiscovered: 10, subdomainsFound: 8, portsFound: 15, servicesIdentified: 5, technologiesDetected: 6 });

      const lowResult = await runPostPipelineGraduation(low);
      const highResult = await runPostPipelineGraduation(high);

      expect(highResult.scores.recon_analyst).toBeGreaterThan(lowResult.scores.recon_analyst);
    });

    it('should give evasion_optimizer 90 when no WAF detected', async () => {
      const metrics = makeBaseMetrics({ wafDetected: false });
      const result = await runPostPipelineGraduation(metrics);
      expect(result.scores.evasion_optimizer).toBe(90);
    });

    it('should give evasion_optimizer 30 when blocked and not recovered', async () => {
      const metrics = makeBaseMetrics({ wafDetected: true, scanBlocked: true, scanRecovered: false });
      const result = await runPostPipelineGraduation(metrics);
      expect(result.scores.evasion_optimizer).toBe(30);
    });

    it('should give evasion_optimizer 70 when blocked but recovered', async () => {
      const metrics = makeBaseMetrics({ wafDetected: true, scanBlocked: true, scanRecovered: true });
      const result = await runPostPipelineGraduation(metrics);
      expect(result.scores.evasion_optimizer).toBe(70);
    });

    it('should give evasion_optimizer 95 when WAF bypassed', async () => {
      const metrics = makeBaseMetrics({ wafDetected: true, wafBypassed: true, scanBlocked: false });
      const result = await runPostPipelineGraduation(metrics);
      expect(result.scores.evasion_optimizer).toBe(95);
    });

    it('should score cloud_assessor based on cloud assets', async () => {
      const noCloud = makeBaseMetrics({ cloudAssetsFound: 0 });
      const hasCloud = makeBaseMetrics({ cloudAssetsFound: 3, storageAssetsFound: 2, containerAssetsFound: 1 });

      const noCloudResult = await runPostPipelineGraduation(noCloud);
      const hasCloudResult = await runPostPipelineGraduation(hasCloud);

      expect(noCloudResult.scores.cloud_assessor).toBe(0);
      expect(hasCloudResult.scores.cloud_assessor).toBeGreaterThan(0);
    });

    it('should produce a summary string', async () => {
      const metrics = makeBaseMetrics();
      const result = await runPostPipelineGraduation(metrics);
      expect(result.summary).toContain('specialist models scored');
      expect(result.summary).toContain('Training examples:');
    });

    it('should cap all scores at 100', async () => {
      const metrics = makeBaseMetrics({
        assetsDiscovered: 100,
        subdomainsFound: 100,
        portsFound: 100,
        servicesIdentified: 100,
        technologiesDetected: 100,
        totalVulns: 100,
        confirmedVulns: 100,
        criticalVulns: 50,
        highVulns: 50,
        kevMatches: 20,
        cloudAssetsFound: 20,
        storageAssetsFound: 20,
        containerAssetsFound: 20,
        identityAssetsFound: 20,
        repoExposuresFound: 20,
        platformAssetsFound: 20,
      });
      const result = await runPostPipelineGraduation(metrics);
      for (const [, score] of Object.entries(result.scores)) {
        expect(score).toBeLessThanOrEqual(100);
      }
    });

    it('should use DI scan scoring for exploit_selector when pipelineType is di_scan', async () => {
      const diMetrics = makeBaseMetrics({
        pipelineType: 'di_scan',
        totalVulns: 10,
        confirmedVulns: 5,
        criticalVulns: 2,
        highVulns: 3,
        kevMatches: 1,
      });
      const result = await runPostPipelineGraduation(diMetrics);
      // DI scans score on vuln identification, not exploit success
      expect(result.scores.exploit_selector).toBeGreaterThan(0);
    });

    it('should use engagement scoring for exploit_selector when pipelineType is engagement', async () => {
      const engMetrics = makeBaseMetrics({
        pipelineType: 'engagement',
        exploitsAttempted: 10,
        exploitsSucceeded: 7,
        totalVulns: 15,
        verifiedVulns: 10,
      });
      const result = await runPostPipelineGraduation(engMetrics);
      expect(result.scores.exploit_selector).toBeGreaterThan(0);
    });
  });

  describe('extractDIScanMetrics', () => {
    it('should extract metrics from a DI scan result', () => {
      const result = {
        totalAssets: 5,
        totalFindings: 12,
        overallRiskScore: 75,
        assets: [
          {
            asset: { hostname: 'web.example.com', technologies: ['nginx', 'react'] },
            findings: [
              { severity: 'critical', cve: 'CVE-2024-1234', confidence: 'confirmed' },
              { severity: 'high', cves: ['CVE-2024-5678'], confidence: 'probable' },
              { severity: 'medium' },
            ],
          },
          {
            asset: { hostname: 'api.example.com', technologies: ['express'] },
            findings: [
              { severity: 'low' },
              { severity: 'info' },
            ],
          },
        ],
        passiveRecon: {
          allObservations: [
            { assetType: 'subdomain', ip: '1.2.3.4', evidence: { port: 443, product: 'nginx' } },
            { assetType: 'subdomain', ip: '1.2.3.5', evidence: { port: 80, service: 'http' } },
            { assetType: 'host', ip: '1.2.3.6', evidence: { port: 22, product: 'openssh' } },
          ],
          connectorResults: [
            { connector: 'shodan', observations: [1, 2] },
            { connector: 'censys', observations: [3] },
            { connector: 'securitytrails', observations: [] },
          ],
        },
        kevEnrichment: { kevMatchCount: 2 },
      };

      const metrics = extractDIScanMetrics(42, 'example.com', result, 30000);

      expect(metrics.pipelineType).toBe('di_scan');
      expect(metrics.pipelineId).toBe(42);
      expect(metrics.domain).toBe('example.com');
      expect(metrics.assetsDiscovered).toBe(5);
      expect(metrics.criticalVulns).toBe(1);
      expect(metrics.highVulns).toBe(1);
      expect(metrics.mediumVulns).toBe(1);
      expect(metrics.lowVulns).toBe(1);
      expect(metrics.infoVulns).toBe(1);
      expect(metrics.confirmedVulns).toBe(1);
      expect(metrics.uniqueCVEs).toBe(2);
      expect(metrics.kevMatches).toBe(2);
      expect(metrics.portsFound).toBe(3);
      expect(metrics.servicesIdentified).toBe(3);
      expect(metrics.subdomainsFound).toBe(2);
      expect(metrics.technologiesDetected).toBe(3); // nginx, react, express
      expect(metrics.connectorSuccessRate).toBeCloseTo(2 / 3);
      expect(metrics.reconObservations).toHaveLength(2);
      expect(metrics.scanDurationMs).toBe(30000);
    });

    it('should handle empty result gracefully', () => {
      const result = { totalAssets: 0, totalFindings: 0, assets: [] };
      const metrics = extractDIScanMetrics(1, 'empty.com', result, 1000);

      expect(metrics.assetsDiscovered).toBe(0);
      expect(metrics.totalVulns).toBe(0);
      expect(metrics.portsFound).toBe(0);
      expect(metrics.reconObservations).toHaveLength(0);
    });
  });

  describe('extractEngagementMetrics', () => {
    it('should extract metrics from an engagement state', () => {
      const state = {
        targetDomain: 'target.com',
        startedAt: Date.now() - 120000,
        assets: [
          {
            hostname: 'web.target.com',
            technologies: ['apache', 'php'],
            ports: [
              { port: 80, service: 'http' },
              { port: 443, service: 'https' },
              { port: 22, service: 'unknown' },
            ],
            exploitAttempts: [
              { succeeded: true, id: 'e1', target: '10.0.0.1', technique: 'T1190' },
              { succeeded: false, id: 'e2' },
            ],
          },
          {
            hostname: 's3.amazonaws.com',
            technologies: ['aws'],
            ports: [],
            exploitAttempts: [],
          },
        ],
        stats: {
          subdomainsFound: 5,
          portsFound: 15,
          vulnsFound: 10,
          verifiedVulns: 4,
          criticalVulns: 2,
          highVulns: 3,
          mediumVulns: 3,
          lowVulns: 1,
          infoVulns: 1,
          exploitsAttempted: 5,
          exploitsSucceeded: 3,
        },
        evasionState: {
          currentLevel: 1,
          escalationHistory: [],
        },
        owaspCoverage: { tested: 15, total: 25 },
        log: [
          { type: 'phase_complete' },
          { type: 'phase_complete' },
          { type: 'info' },
        ],
      };

      const metrics = extractEngagementMetrics(99, state);

      expect(metrics.pipelineType).toBe('engagement');
      expect(metrics.pipelineId).toBe(99);
      expect(metrics.domain).toBe('target.com');
      expect(metrics.assetsDiscovered).toBe(2);
      expect(metrics.servicesIdentified).toBe(2); // http and https are non-unknown
      expect(metrics.exploitsAttempted).toBe(5);
      expect(metrics.exploitsSucceeded).toBe(3);
      expect(metrics.owaspCategoriesTested).toBe(15);
      expect(metrics.cloudAssetsFound).toBe(1); // s3.amazonaws.com
      expect(metrics.successfulExploits).toHaveLength(1);
      expect(metrics.ptesPhasesCovered).toBe(2);
    });

    it('should handle empty engagement state', () => {
      const state = { assets: [], stats: {} };
      const metrics = extractEngagementMetrics(1, state);

      expect(metrics.assetsDiscovered).toBe(0);
      expect(metrics.totalVulns).toBe(0);
      expect(metrics.exploitsAttempted).toBe(0);
    });
  });
});
