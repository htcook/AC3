import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the LLM module
vi.mock('./_core/llm', () => ({
  invokeLLM: vi.fn().mockResolvedValue({
    choices: [{
      message: {
        content: JSON.stringify({
          attackPaths: [
            {
              id: "ap-1",
              name: "Web Application Exploitation Chain",
              description: "Exploit outdated web server to gain initial access",
              steps: [
                { order: 1, technique: "T1595", mitreTactic: "Reconnaissance", targetAsset: "www.example.com", finding: "Outdated nginx", difficulty: "easy" },
                { order: 2, technique: "T1190", mitreTactic: "Initial Access", targetAsset: "www.example.com", finding: "Known CVE", difficulty: "moderate" },
              ],
              likelihood: 7,
              impact: 8,
              overallRisk: 72,
            },
          ],
          blindSpots: [
            {
              area: "Internal Network Segmentation",
              description: "No visibility into internal network topology",
              suggestedAction: "Conduct internal network scan",
              severity: "high",
            },
          ],
          prioritizedRecommendations: [
            {
              rank: 1,
              title: "Patch Critical Vulnerabilities",
              description: "Address all confirmed CVEs with CVSS > 9.0",
              affectedAssets: ["www.example.com"],
              effort: "short_term",
              impact: "critical",
              category: "Vulnerability Management",
            },
          ],
          crossFindingCorrelations: [
            {
              findingIds: ["f1", "f2"],
              relationship: "Same service, multiple vulnerabilities",
              combinedRisk: "Critical exploit chain",
              exploitChainPotential: true,
            },
          ],
          threatActorMapping: [
            {
              actorName: "APT28",
              relevance: "medium",
              matchingTechniques: ["T1190", "T1595"],
              rationale: "Known to target web infrastructure",
            },
          ],
          overallAssessment: "The target organization has a moderate security posture with several critical findings.",
          confidenceStatement: "Medium confidence — based on passive reconnaissance data.",
        }),
      },
    }],
  }),
}));

describe('LLM Post-Enrichment Analysis', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Module Exports', () => {
    it('should export runPostEnrichmentAnalysis function', async () => {
      const mod = await import('./lib/llm-post-enrichment-analysis');
      expect(typeof mod.runPostEnrichmentAnalysis).toBe('function');
    });
  });

  describe('Post-Enrichment Analysis', () => {
    it('should generate structured analysis from pipeline data', async () => {
      const mod = await import('./lib/llm-post-enrichment-analysis');

      const mockAnalyses = [
        {
          asset: {
            assetId: 'asset-1',
            hostname: 'www.example.com',
            technologies: ['nginx/1.18', 'react'],
          },
          postureFindings: [
            {
              id: 'f1',
              title: 'Outdated nginx',
              severity: 7,
              confidence: 0.9,
              corroborationTier: 'confirmed',
              cveIds: ['CVE-2021-23017'],
            },
          ],
          hybridRiskScore: 72,
          riskBand: 'elevated',
          missionFunction: 'public_facing_services',
        },
      ];

      const mockOrg = {
        primaryDomain: 'example.com',
        customerName: 'Example Corp',
        sector: 'technology',
        clientType: 'enterprise',
      };

      const result = await mod.runPostEnrichmentAnalysis(mockAnalyses as any, mockOrg as any);

      expect(result).toBeDefined();
      // PostEnrichmentAnalysis interface fields
      expect(result).toHaveProperty('attackPaths');
      expect(result).toHaveProperty('blindSpots');
      expect(result).toHaveProperty('prioritizedRecommendations');
      expect(result).toHaveProperty('crossFindingCorrelations');
      expect(result).toHaveProperty('threatActorMapping');
      expect(result).toHaveProperty('overallAssessment');
      expect(result).toHaveProperty('confidenceStatement');

      expect(Array.isArray(result.attackPaths)).toBe(true);
      expect(Array.isArray(result.blindSpots)).toBe(true);
      expect(Array.isArray(result.prioritizedRecommendations)).toBe(true);
      expect(typeof result.overallAssessment).toBe('string');
      expect(typeof result.confidenceStatement).toBe('string');
    });

    it('should include attack paths with proper structure', async () => {
      const mod = await import('./lib/llm-post-enrichment-analysis');

      const result = await mod.runPostEnrichmentAnalysis(
        [{ asset: { assetId: 'a1', hostname: 'test.com', technologies: [] }, postureFindings: [], hybridRiskScore: 50, riskBand: 'moderate' }] as any,
        { primaryDomain: 'test.com', customerName: 'Test', sector: 'tech', clientType: 'startup' } as any,
      );

      expect(result.attackPaths.length).toBeGreaterThan(0);
      const path = result.attackPaths[0];
      expect(path).toHaveProperty('id');
      expect(path).toHaveProperty('name');
      expect(path).toHaveProperty('description');
      expect(path).toHaveProperty('steps');
      expect(path).toHaveProperty('likelihood');
      expect(path).toHaveProperty('impact');
      expect(path).toHaveProperty('overallRisk');
      expect(Array.isArray(path.steps)).toBe(true);
    });

    it('should include blind spots with severity', async () => {
      const mod = await import('./lib/llm-post-enrichment-analysis');

      const result = await mod.runPostEnrichmentAnalysis(
        [{ asset: { assetId: 'a1', hostname: 'test.com', technologies: [] }, postureFindings: [], hybridRiskScore: 50, riskBand: 'moderate' }] as any,
        { primaryDomain: 'test.com', customerName: 'Test', sector: 'tech', clientType: 'startup' } as any,
      );

      expect(result.blindSpots.length).toBeGreaterThan(0);
      const spot = result.blindSpots[0];
      expect(spot).toHaveProperty('area');
      expect(spot).toHaveProperty('severity');
      expect(spot).toHaveProperty('description');
      expect(spot).toHaveProperty('suggestedAction');
    });

    it('should include prioritized recommendations with rank', async () => {
      const mod = await import('./lib/llm-post-enrichment-analysis');

      const result = await mod.runPostEnrichmentAnalysis(
        [{ asset: { assetId: 'a1', hostname: 'test.com', technologies: [] }, postureFindings: [], hybridRiskScore: 50, riskBand: 'moderate' }] as any,
        { primaryDomain: 'test.com', customerName: 'Test', sector: 'tech', clientType: 'startup' } as any,
      );

      expect(result.prioritizedRecommendations.length).toBeGreaterThan(0);
      const rec = result.prioritizedRecommendations[0];
      expect(rec).toHaveProperty('rank');
      expect(rec).toHaveProperty('title');
      expect(rec).toHaveProperty('description');
      expect(rec).toHaveProperty('affectedAssets');
      expect(rec).toHaveProperty('effort');
      expect(rec).toHaveProperty('impact');
      expect(rec).toHaveProperty('category');
    });

    it('should handle cross-module enrichment data when provided', async () => {
      const mod = await import('./lib/llm-post-enrichment-analysis');

      const mockCrossModule = {
        bugBounty: { status: 'success', hasBugBountyProgram: true },
        threatIntel: { status: 'success', matchingThreatActors: [] },
        opsec: { status: 'success', defensiveGaps: [] },
        discoveryDeepDive: { status: 'success' },
        correlations: [],
        riskAdjustments: [],
        newFindings: [],
        summary: { modulesRun: 4, modulesSucceeded: 4, totalCorrelations: 0, totalNewFindings: 0, totalRiskAdjustments: 0 },
      };

      const result = await mod.runPostEnrichmentAnalysis(
        [{ asset: { assetId: 'a1', hostname: 'test.com', technologies: [] }, postureFindings: [], hybridRiskScore: 50, riskBand: 'moderate' }] as any,
        { primaryDomain: 'test.com', customerName: 'Test', sector: 'tech', clientType: 'startup' } as any,
        mockCrossModule as any,
      );

      expect(result).toBeDefined();
      expect(result).toHaveProperty('overallAssessment');
      expect(typeof result.overallAssessment).toBe('string');
    });
  });
});
