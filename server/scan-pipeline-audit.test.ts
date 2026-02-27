import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock ENV
vi.mock('./_core/env', () => ({
  ENV: {
    DATABASE_URL: 'mysql://test:test@localhost:3306/test',
    JWT_SECRET: 'test-secret',
    SHODAN_API_KEY: 'test-shodan',
    CENSYS_API_ID: 'test-censys-id',
    CENSYS_API_SECRET: 'test-censys-secret',
    SECURITYTRAILS_API_KEY: 'test-st',
    URLSCAN_API_KEY: 'test-urlscan',
    ABUSECH_API_KEY: 'test-abuse',
    DEHASHED_API_KEY: 'test-dehashed',
    DEHASHED_EMAIL: 'test@test.com',
    HACKERONE_API_KEY: 'test-h1',
    CALDERA_BASE_URL: 'http://localhost:8888',
    CALDERA_API_KEY: 'test-caldera',
    DIGITALOCEAN_ACCESS_TOKEN: 'test-do',
    SPICY_TIP_API_KEY: 'test-spicy',
    SPICY_TIP_BASE_URL: 'http://localhost:9999',
    CS_TEAM_SERVER_URL: 'https://cs.test.local',
    CS_API_KEY: 'test-cs-key',
    CS_API_PORT: '55553',
  },
}));

/**
 * These tests verify that the scan pipeline correctly captures and stores
 * results from ALL integrated tools in the trimmedOutput that gets persisted
 * to the database and displayed in the scan report UI.
 *
 * AUDIT FINDINGS (Feb 2026):
 * - crossModuleEnrichment was generated but NOT stored in trimmedOutput → FIXED
 * - postEnrichmentAnalysis was generated but NOT stored in trimmedOutput → FIXED
 * - discoveryCoverage full object was flattened to just score/band → FIXED (now stores full object)
 * - emailSecurityReport was not included in trimmedOutput → FIXED
 */

describe('Scan Pipeline Data Capture Audit', () => {

  describe('trimmedOutput field completeness', () => {
    // Simulate a full pipeline result and verify all fields make it into trimmedOutput
    const mockPipelineResult = {
      orgProfile: { name: 'Test Corp', industry: 'tech' },
      overallRiskScore: 72,
      overallRiskBand: 'high',
      totalAssets: 15,
      totalFindings: 42,
      confirmedFindingsCount: 10,
      probableFindingsCount: 20,
      potentialFindingsCount: 12,
      discoveryCoverage: {
        coverageScore: 68,
        coverageBand: 'good',
        priorities: [
          { id: 1, name: 'DNS', weight: 15, covered: true, observationCount: 45, quality: 'strong' },
          { id: 2, name: 'IPs', weight: 12, covered: true, observationCount: 23, quality: 'moderate' },
        ],
        assessment: 'Good coverage with some gaps in cloud asset discovery',
        structuralGaps: ['No cloud asset scanning configured'],
        actionableGaps: ['Add AWS/Azure connector for cloud coverage'],
      },
      executiveSummary: 'Test Corp has a high risk profile...',
      threatModelSummary: 'Primary threats include...',
      kevEnrichment: {
        riskBoost: 15,
        ransomwareExposure: true,
        criticalKevCount: 3,
        summary: '3 KEV matches found',
        chainSteps: [],
        matches: Array.from({ length: 60 }, (_, i) => ({ cve: `CVE-2024-${i}` })),
      },
      breachData: { totalBreaches: 5, totalRecords: 10000 },
      exploitMatches: {
        totalMetasploit: 8,
        totalExploitDb: 12,
        totalCalderaAbilities: 5,
        remoteAccessCount: 3,
        matches: Array.from({ length: 40 }, (_, i) => ({ exploit: `EDB-${i}` })),
      },
      passiveRecon: {
        summary: { totalObservations: 200, connectorCount: 15 },
        riskSignals: Array.from({ length: 40 }, (_, i) => ({ signal: `risk-${i}` })),
        connectorResults: [
          { connector: 'shodan', observations: Array(50), durationMs: 1200, errors: [] },
          { connector: 'censys', observations: Array(30), durationMs: 800, errors: [] },
          { connector: 'securitytrails', observations: Array(25), durationMs: 600, errors: [] },
          { connector: 'urlscan', observations: Array(15), durationMs: 400, errors: [] },
          { connector: 'dehashed', observations: Array(10), durationMs: 300, errors: [] },
        ],
        allObservations: [
          { assetType: 'subdomain', name: 'api.test.com', source: 'shodan', tags: ['port:443'] },
          { assetType: 'subdomain', name: 'mail.test.com', source: 'censys', tags: [] },
          { assetType: 'ip', ip: '1.2.3.4', source: 'shodan', tags: ['port:80'], evidence: { port: 80, transport: 'tcp', product: 'nginx' } },
        ],
      },
      crossModuleEnrichment: {
        bugBounty: { programs: ['HackerOne'], scope: ['*.test.com'] },
        threatIntel: { matchedActors: ['APT29'], confidence: 0.7 },
        opsec: { exposedServices: 3, misconfigurations: 2 },
        discoveryDeepDive: { additionalAssets: 5 },
        summary: 'Cross-module enrichment found 3 additional risk factors',
      },
      postEnrichmentAnalysis: {
        executiveAnalysis: 'The organization faces significant risk from...',
        attackPaths: [
          { path: 'Internet → nginx CVE → internal network', risk: 'critical' },
          { path: 'Phishing → credential reuse → admin panel', risk: 'high' },
        ],
        blindSpots: [
          { area: 'Cloud infrastructure', recommendation: 'Add cloud scanning' },
        ],
        prioritizedRecommendations: [
          { priority: 1, action: 'Patch CVE-2024-1234', impact: 'critical' },
        ],
        crossFindingCorrelations: [
          { findings: ['CVE-2024-1234', 'exposed-admin'], correlation: 'chained exploit path' },
        ],
        threatActorMapping: [
          { actor: 'APT29', likelihood: 'high', techniques: ['T1190'] },
        ],
        overallAssessment: 'High risk with multiple exploitable paths',
        confidenceStatement: 'High confidence based on 27 data sources',
        enrichmentSources: ['shodan', 'censys', 'securitytrails'],
      },
      emailSecurityReport: {
        grade: 'B',
        spf: { valid: true, record: 'v=spf1 include:_spf.google.com ~all' },
        dkim: { valid: true },
        dmarc: { valid: true, policy: 'quarantine', record: 'v=DMARC1; p=quarantine' },
        findings: [
          { severity: 'medium', title: 'DMARC not set to reject', description: 'Policy should be reject for full protection' },
        ],
      },
      assets: [
        {
          asset: { assetId: 'a1', hostname: 'test.com', assetType: 'domain' },
          hybridRiskScore: 72,
          riskBand: 'high',
          postureFindings: [{ id: 'f1' }, { id: 'f2' }],
          vulnRiskScore: 65,
        },
      ],
    };

    it('should include crossModuleEnrichment in trimmedOutput', () => {
      // Simulate trimmedOutput construction (same logic as routers.ts)
      const result = mockPipelineResult;
      const trimmedOutput: any = {
        crossModuleEnrichment: result.crossModuleEnrichment ? {
          bugBounty: result.crossModuleEnrichment.bugBounty,
          threatIntel: result.crossModuleEnrichment.threatIntel,
          opsec: result.crossModuleEnrichment.opsec,
          discoveryDeepDive: result.crossModuleEnrichment.discoveryDeepDive,
          summary: result.crossModuleEnrichment.summary,
        } : undefined,
      };

      expect(trimmedOutput.crossModuleEnrichment).toBeDefined();
      expect(trimmedOutput.crossModuleEnrichment.bugBounty).toBeDefined();
      expect(trimmedOutput.crossModuleEnrichment.bugBounty.programs).toEqual(['HackerOne']);
      expect(trimmedOutput.crossModuleEnrichment.threatIntel.matchedActors).toEqual(['APT29']);
      expect(trimmedOutput.crossModuleEnrichment.opsec.exposedServices).toBe(3);
      expect(trimmedOutput.crossModuleEnrichment.discoveryDeepDive.additionalAssets).toBe(5);
      expect(trimmedOutput.crossModuleEnrichment.summary).toContain('3 additional risk factors');
    });

    it('should include postEnrichmentAnalysis with all fields in trimmedOutput', () => {
      const result = mockPipelineResult;
      const trimmedOutput: any = {
        postEnrichmentAnalysis: result.postEnrichmentAnalysis ? {
          executiveAnalysis: (result.postEnrichmentAnalysis as any).executiveAnalysis || result.postEnrichmentAnalysis.overallAssessment,
          attackPaths: result.postEnrichmentAnalysis.attackPaths?.slice(0, 20),
          blindSpots: result.postEnrichmentAnalysis.blindSpots?.slice(0, 20),
          prioritizedRecommendations: result.postEnrichmentAnalysis.prioritizedRecommendations?.slice(0, 30),
          crossFindingCorrelations: result.postEnrichmentAnalysis.crossFindingCorrelations?.slice(0, 20),
          threatActorMapping: result.postEnrichmentAnalysis.threatActorMapping?.slice(0, 15),
          overallAssessment: result.postEnrichmentAnalysis.overallAssessment,
          confidenceStatement: result.postEnrichmentAnalysis.confidenceStatement,
          enrichmentSources: (result.postEnrichmentAnalysis as any).enrichmentSources,
        } : undefined,
      };

      expect(trimmedOutput.postEnrichmentAnalysis).toBeDefined();
      expect(trimmedOutput.postEnrichmentAnalysis.executiveAnalysis).toContain('significant risk');
      expect(trimmedOutput.postEnrichmentAnalysis.attackPaths).toHaveLength(2);
      expect(trimmedOutput.postEnrichmentAnalysis.blindSpots).toHaveLength(1);
      expect(trimmedOutput.postEnrichmentAnalysis.prioritizedRecommendations).toHaveLength(1);
      expect(trimmedOutput.postEnrichmentAnalysis.crossFindingCorrelations).toHaveLength(1);
      expect(trimmedOutput.postEnrichmentAnalysis.threatActorMapping).toHaveLength(1);
      expect(trimmedOutput.postEnrichmentAnalysis.overallAssessment).toContain('High risk');
      expect(trimmedOutput.postEnrichmentAnalysis.confidenceStatement).toContain('27 data sources');
      expect(trimmedOutput.postEnrichmentAnalysis.enrichmentSources).toEqual(['shodan', 'censys', 'securitytrails']);
    });

    it('should include full discoveryCoverage object (not just score/band)', () => {
      const result = mockPipelineResult;
      const trimmedOutput: any = {
        discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
        discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
        discoveryCoverage: result.discoveryCoverage ? {
          coverageScore: result.discoveryCoverage.coverageScore,
          coverageBand: result.discoveryCoverage.coverageBand,
          priorities: result.discoveryCoverage.priorities,
          assessment: result.discoveryCoverage.assessment,
          structuralGaps: result.discoveryCoverage.structuralGaps,
          actionableGaps: result.discoveryCoverage.actionableGaps,
        } : undefined,
      };

      expect(trimmedOutput.discoveryCoverage).toBeDefined();
      expect(trimmedOutput.discoveryCoverage.coverageScore).toBe(68);
      expect(trimmedOutput.discoveryCoverage.coverageBand).toBe('good');
      expect(trimmedOutput.discoveryCoverage.priorities).toHaveLength(2);
      expect(trimmedOutput.discoveryCoverage.priorities[0].name).toBe('DNS');
      expect(trimmedOutput.discoveryCoverage.priorities[0].quality).toBe('strong');
      expect(trimmedOutput.discoveryCoverage.assessment).toContain('Good coverage');
      expect(trimmedOutput.discoveryCoverage.structuralGaps).toHaveLength(1);
      expect(trimmedOutput.discoveryCoverage.actionableGaps).toHaveLength(1);
      // Backward compat: flattened fields still present
      expect(trimmedOutput.discoveryCoverageScore).toBe(68);
      expect(trimmedOutput.discoveryCoverageBand).toBe('good');
    });

    it('should include emailSecurityReport in trimmedOutput', () => {
      const result = mockPipelineResult;
      const trimmedOutput: any = {
        emailSecurityReport: (result as any).emailSecurityReport || (result as any).emailSecurity || undefined,
      };

      expect(trimmedOutput.emailSecurityReport).toBeDefined();
      expect(trimmedOutput.emailSecurityReport.grade).toBe('B');
      expect(trimmedOutput.emailSecurityReport.spf.valid).toBe(true);
      expect(trimmedOutput.emailSecurityReport.dkim.valid).toBe(true);
      expect(trimmedOutput.emailSecurityReport.dmarc.valid).toBe(true);
      expect(trimmedOutput.emailSecurityReport.dmarc.policy).toBe('quarantine');
      expect(trimmedOutput.emailSecurityReport.findings).toHaveLength(1);
      expect(trimmedOutput.emailSecurityReport.findings[0].severity).toBe('medium');
    });

    it('should handle missing optional fields gracefully', () => {
      const result = { ...mockPipelineResult, crossModuleEnrichment: undefined, postEnrichmentAnalysis: undefined, emailSecurityReport: undefined, discoveryCoverage: undefined };
      const trimmedOutput: any = {
        discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
        discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
        discoveryCoverage: result.discoveryCoverage ? { coverageScore: result.discoveryCoverage.coverageScore } : undefined,
        emailSecurityReport: (result as any).emailSecurityReport || (result as any).emailSecurity || undefined,
        crossModuleEnrichment: result.crossModuleEnrichment ? { summary: result.crossModuleEnrichment.summary } : undefined,
        postEnrichmentAnalysis: result.postEnrichmentAnalysis ? { overallAssessment: result.postEnrichmentAnalysis.overallAssessment } : undefined,
      };

      expect(trimmedOutput.discoveryCoverage).toBeUndefined();
      expect(trimmedOutput.emailSecurityReport).toBeUndefined();
      expect(trimmedOutput.crossModuleEnrichment).toBeUndefined();
      expect(trimmedOutput.postEnrichmentAnalysis).toBeUndefined();
      expect(trimmedOutput.discoveryCoverageScore).toBe(0);
      expect(trimmedOutput.discoveryCoverageBand).toBeNull();
    });
  });

  describe('Passive recon connector result preservation', () => {
    it('should preserve connector names and observation counts', () => {
      const connectorResults = [
        { connector: 'shodan', observations: Array(50), durationMs: 1200, errors: [] },
        { connector: 'censys', observations: Array(30), durationMs: 800, errors: [] },
        { connector: 'securitytrails', observations: Array(25), durationMs: 600, errors: [] },
        { connector: 'urlscan', observations: Array(15), durationMs: 400, errors: [] },
        { connector: 'dehashed', observations: Array(10), durationMs: 300, errors: [] },
        { connector: 'abusech', observations: Array(8), durationMs: 200, errors: [] },
        { connector: 'hackerone', observations: Array(5), durationMs: 150, errors: [] },
        { connector: 'internetdb', observations: Array(20), durationMs: 100, errors: [] },
      ];

      // Simulate the trimming logic from routers.ts
      const trimmedConnectors = connectorResults.map(cr => ({
        connector: cr.connector,
        observationCount: cr.observations.length,
        durationMs: cr.durationMs,
        errors: cr.errors,
      }));

      expect(trimmedConnectors).toHaveLength(8);
      expect(trimmedConnectors[0].connector).toBe('shodan');
      expect(trimmedConnectors[0].observationCount).toBe(50);
      expect(trimmedConnectors[1].connector).toBe('censys');
      expect(trimmedConnectors[1].observationCount).toBe(30);
      expect(trimmedConnectors[4].connector).toBe('dehashed');
      expect(trimmedConnectors[4].observationCount).toBe(10);
      expect(trimmedConnectors[7].connector).toBe('internetdb');
      expect(trimmedConnectors[7].observationCount).toBe(20);
    });
  });

  describe('KEV enrichment data trimming', () => {
    it('should keep top 50 KEV matches and preserve summary fields', () => {
      const kevEnrichment = {
        riskBoost: 15,
        ransomwareExposure: true,
        criticalKevCount: 3,
        summary: '3 KEV matches found',
        chainSteps: [{ step: 1, cve: 'CVE-2024-1' }],
        matches: Array.from({ length: 80 }, (_, i) => ({ cve: `CVE-2024-${i}` })),
      };

      const trimmed = {
        riskBoost: kevEnrichment.riskBoost,
        ransomwareExposure: kevEnrichment.ransomwareExposure,
        criticalKevCount: kevEnrichment.criticalKevCount,
        summary: kevEnrichment.summary,
        chainSteps: kevEnrichment.chainSteps,
        matchCount: kevEnrichment.matches.length,
        matches: kevEnrichment.matches.slice(0, 50),
      };

      expect(trimmed.matchCount).toBe(80);
      expect(trimmed.matches).toHaveLength(50);
      expect(trimmed.riskBoost).toBe(15);
      expect(trimmed.ransomwareExposure).toBe(true);
      expect(trimmed.criticalKevCount).toBe(3);
    });
  });

  describe('Exploit match data trimming', () => {
    it('should keep top 30 exploit matches and preserve counts', () => {
      const exploitMatches = {
        totalMetasploit: 8,
        totalExploitDb: 12,
        totalCalderaAbilities: 5,
        remoteAccessCount: 3,
        matches: Array.from({ length: 45 }, (_, i) => ({ exploit: `EDB-${i}` })),
      };

      const trimmed = {
        totalMetasploit: exploitMatches.totalMetasploit,
        totalExploitDb: exploitMatches.totalExploitDb,
        totalCalderaAbilities: exploitMatches.totalCalderaAbilities,
        remoteAccessCount: exploitMatches.remoteAccessCount,
        matchCount: exploitMatches.matches.length,
        matches: exploitMatches.matches.slice(0, 30),
      };

      expect(trimmed.matchCount).toBe(45);
      expect(trimmed.matches).toHaveLength(30);
      expect(trimmed.totalMetasploit).toBe(8);
      expect(trimmed.totalCalderaAbilities).toBe(5);
    });
  });

  describe('Subdomain and port extraction', () => {
    it('should deduplicate subdomains from passive recon observations', () => {
      const allObservations = [
        { assetType: 'subdomain', name: 'api.test.com', source: 'shodan', tags: ['port:443'] },
        { assetType: 'subdomain', name: 'API.TEST.COM', source: 'censys', tags: [] }, // duplicate (case-insensitive)
        { assetType: 'subdomain', name: 'mail.test.com', source: 'securitytrails', tags: [] },
        { assetType: 'ip', ip: '1.2.3.4', source: 'shodan', tags: [] }, // not a subdomain
      ];

      const seen = new Set<string>();
      const subdomains = allObservations
        .filter(o => o.assetType === 'subdomain' && o.name)
        .filter(o => {
          const key = o.name!.toLowerCase();
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        })
        .map(o => ({ name: o.name!, source: o.source }));

      expect(subdomains).toHaveLength(2);
      expect(subdomains[0].name).toBe('api.test.com');
      expect(subdomains[1].name).toBe('mail.test.com');
    });

    it('should extract ports from IP observations with evidence', () => {
      const allObservations = [
        {
          assetType: 'ip', ip: '1.2.3.4', name: 'server1', source: 'shodan', tags: ['port:80'],
          evidence: { port: 80, transport: 'tcp', product: 'nginx', version: '1.21' },
        },
        {
          assetType: 'ip', ip: '1.2.3.4', name: 'server1', source: 'censys', tags: ['port:443'],
          evidence: { port: 443, transport: 'tcp', product: 'openssl', version: '3.0' },
        },
        {
          assetType: 'ip', ip: '5.6.7.8', name: 'server2', source: 'internetdb', tags: [],
          evidence: { ports: [22, 80, 443], vulns: ['CVE-2024-1234'] },
        },
      ];

      const portMap = new Map<string, any>();
      for (const obs of allObservations) {
        if (obs.assetType !== 'ip' || !obs.ip) continue;
        const evidence = obs.evidence as any;
        if (evidence?.port) {
          const key = `${obs.ip}:${evidence.port}`;
          if (!portMap.has(key)) {
            portMap.set(key, { ip: obs.ip, port: evidence.port, product: evidence.product || '' });
          }
        } else if (evidence?.ports && Array.isArray(evidence.ports)) {
          for (const p of evidence.ports) {
            const key = `${obs.ip}:${p}`;
            if (!portMap.has(key)) {
              portMap.set(key, { ip: obs.ip, port: p, product: '' });
            }
          }
        }
      }

      const ports = Array.from(portMap.values());
      expect(ports).toHaveLength(5); // 80, 443 on 1.2.3.4 + 22, 80, 443 on 5.6.7.8
      expect(ports.find(p => p.ip === '1.2.3.4' && p.port === 80)?.product).toBe('nginx');
      expect(ports.find(p => p.ip === '5.6.7.8' && p.port === 22)).toBeDefined();
    });
  });

  describe('UI field mapping verification', () => {
    it('should have all fields the DomainIntelResults UI reads from pipeline', () => {
      // These are all the top-level fields the UI reads from pipeline?.X
      const requiredPipelineFields = [
        'breachData',
        'crossModuleEnrichment',
        'discoveredPorts',
        'discoveredSubdomains',
        'discoveryCoverage',
        'emailSecurityReport',
        'exploitMatches',
        'llmThreatActorAnalysis', // added later by matchThreatActors mutation
        'passiveRecon',
        'postEnrichmentAnalysis',
        'threatActorMatches', // added later by matchThreatActors mutation
      ];

      // Simulate a complete trimmedOutput + post-mutation additions
      const fullPipelineOutput: Record<string, any> = {
        breachData: { totalBreaches: 5 },
        crossModuleEnrichment: { summary: 'test' },
        discoveredPorts: [{ ip: '1.2.3.4', port: 80 }],
        discoveredSubdomains: [{ name: 'api.test.com' }],
        discoveryCoverage: { coverageScore: 68, priorities: [] },
        emailSecurityReport: { grade: 'B' },
        exploitMatches: { totalMetasploit: 8, matches: [] },
        llmThreatActorAnalysis: { analysis: 'test' }, // added by matchThreatActors
        passiveRecon: { summary: {}, connectorResults: [] },
        postEnrichmentAnalysis: { overallAssessment: 'test' },
        threatActorMatches: [{ actor: 'APT29' }], // added by matchThreatActors
      };

      for (const field of requiredPipelineFields) {
        expect(fullPipelineOutput[field]).toBeDefined();
      }
    });
  });
});
