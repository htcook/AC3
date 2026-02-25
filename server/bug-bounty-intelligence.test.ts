import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the env module
vi.mock('./_core/env', () => ({
  ENV: {
    HACKERONE_API_KEY: 'test-api-key-123',
    SHODAN_API_KEY: 'test-shodan-key',
    SECURITYTRAILS_API_KEY: 'test-st-key',
  },
}));

// Mock fetch to avoid real API calls
const mockFetch = vi.fn().mockResolvedValue({
  ok: false,
  status: 401,
  json: async () => ({ errors: [{ title: 'Unauthorized' }] }),
  text: async () => 'Unauthorized',
});
vi.stubGlobal('fetch', mockFetch);

describe('Bug Bounty Intelligence Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ errors: [{ title: 'Unauthorized' }] }),
      text: async () => 'Unauthorized',
    });
  });

  describe('Module Exports', () => {
    it('should export enrichDomainIntel function', async () => {
      const mod = await import('./lib/bug-bounty-intelligence');
      expect(typeof mod.enrichDomainIntel).toBe('function');
    });

    it('should export enrichThreatIntelligence function', async () => {
      const mod = await import('./lib/bug-bounty-intelligence');
      expect(typeof mod.enrichThreatIntelligence).toBe('function');
    });

    it('should export enrichAttackVectors function', async () => {
      const mod = await import('./lib/bug-bounty-intelligence');
      expect(typeof mod.enrichAttackVectors).toBe('function');
    });

    it('should export enrichOpSec function', async () => {
      const mod = await import('./lib/bug-bounty-intelligence');
      expect(typeof mod.enrichOpSec).toBe('function');
    });

    it('should export generateFullIntelligenceReport function', async () => {
      const mod = await import('./lib/bug-bounty-intelligence');
      expect(typeof mod.generateFullIntelligenceReport).toBe('function');
    });
  });

  describe('Interface Types', () => {
    it('DomainIntelEnrichment should have required fields', async () => {
      const mod = await import('./lib/bug-bounty-intelligence');
      const result = await mod.enrichDomainIntel('example.com');
      expect(result).toBeDefined();
      expect(result).toHaveProperty('domain');
      expect(result.domain).toBe('example.com');
      expect(result).toHaveProperty('hasBugBountyProgram');
      expect(result).toHaveProperty('programName');
      expect(result).toHaveProperty('programHandle');
      expect(result).toHaveProperty('programUrl');
      expect(result).toHaveProperty('disclosedVulnerabilities');
      expect(result).toHaveProperty('topCWEs');
      expect(result).toHaveProperty('topVulnerabilities');
      expect(result).toHaveProperty('totalBountiesPaid');
      expect(result).toHaveProperty('avgBountyAmount');
      expect(result).toHaveProperty('lastDisclosedAt');
      expect(typeof result.hasBugBountyProgram).toBe('boolean');
      expect(Array.isArray(result.topCWEs)).toBe(true);
      expect(Array.isArray(result.topVulnerabilities)).toBe(true);
    });

    it('disclosedVulnerabilities should have severity counts', async () => {
      const mod = await import('./lib/bug-bounty-intelligence');
      const result = await mod.enrichDomainIntel('example.com');
      expect(result.disclosedVulnerabilities).toHaveProperty('total');
      expect(result.disclosedVulnerabilities).toHaveProperty('critical');
      expect(result.disclosedVulnerabilities).toHaveProperty('high');
      expect(result.disclosedVulnerabilities).toHaveProperty('medium');
      expect(result.disclosedVulnerabilities).toHaveProperty('low');
      expect(typeof result.disclosedVulnerabilities.critical).toBe('number');
      expect(typeof result.disclosedVulnerabilities.high).toBe('number');
    });
  });

  describe('Threat Intelligence Enrichment', () => {
    it('should return structured threat enrichment data', async () => {
      const mod = await import('./lib/bug-bounty-intelligence');
      const result = await mod.enrichThreatIntelligence();
      expect(result).toBeDefined();
      // Actual ThreatEnrichment interface fields
      expect(result).toHaveProperty('cweDistribution');
      expect(result).toHaveProperty('severityDistribution');
      expect(result).toHaveProperty('trendingWeaknesses');
      expect(result).toHaveProperty('exploitPatterns');
      expect(result).toHaveProperty('totalReportsAnalyzed');
      expect(result).toHaveProperty('timeRange');
      expect(Array.isArray(result.cweDistribution)).toBe(true);
      expect(Array.isArray(result.severityDistribution)).toBe(true);
      expect(Array.isArray(result.trendingWeaknesses)).toBe(true);
      expect(Array.isArray(result.exploitPatterns)).toBe(true);
      expect(typeof result.totalReportsAnalyzed).toBe('number');
    });
  });

  describe('Attack Vector Enrichment', () => {
    it('should return structured attack vector data', async () => {
      const mod = await import('./lib/bug-bounty-intelligence');
      const result = await mod.enrichAttackVectors();
      expect(result).toBeDefined();
      // Actual AttackVectorEnrichment interface fields
      expect(result).toHaveProperty('assetTypeBreakdown');
      expect(result).toHaveProperty('bountyValidatedVectors');
      expect(result).toHaveProperty('highValueTargets');
      expect(Array.isArray(result.assetTypeBreakdown)).toBe(true);
      expect(Array.isArray(result.bountyValidatedVectors)).toBe(true);
      expect(Array.isArray(result.highValueTargets)).toBe(true);
    });
  });

  describe('OpSec Enrichment', () => {
    it('should return structured opsec weakness data', async () => {
      const mod = await import('./lib/bug-bounty-intelligence');
      const result = await mod.enrichOpSec();
      expect(result).toBeDefined();
      // Actual OpSecEnrichment interface fields
      expect(result).toHaveProperty('weaknessCategories');
      expect(result).toHaveProperty('commonMisconfigurations');
      expect(result).toHaveProperty('defensiveGaps');
      expect(Array.isArray(result.weaknessCategories)).toBe(true);
      expect(Array.isArray(result.commonMisconfigurations)).toBe(true);
      expect(Array.isArray(result.defensiveGaps)).toBe(true);
    });
  });

  describe('Full Intelligence Report', () => {
    it('should generate a complete cross-module report', async () => {
      const mod = await import('./lib/bug-bounty-intelligence');
      const result = await mod.generateFullIntelligenceReport('example.com');
      expect(result).toBeDefined();
      // Actual BugBountyIntelligenceReport interface fields
      expect(result).toHaveProperty('generatedAt');
      expect(result).toHaveProperty('domainIntel');
      expect(result).toHaveProperty('threatEnrichment');
      expect(result).toHaveProperty('attackVectors');
      expect(result).toHaveProperty('opSec');
      expect(typeof result.generatedAt).toBe('string');
      // domainIntel should be a DomainIntelEnrichment when domain is provided
      expect(result.domainIntel).not.toBeNull();
      if (result.domainIntel) {
        expect(result.domainIntel.domain).toBe('example.com');
      }
    });
  });

  describe('Error Handling', () => {
    it('should handle API errors gracefully for domain enrichment', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));
      const mod = await import('./lib/bug-bounty-intelligence');
      const result = await mod.enrichDomainIntel('example.com');
      expect(result).toBeDefined();
      expect(result.domain).toBe('example.com');
    });

    it('should handle API errors gracefully for threat enrichment', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));
      const mod = await import('./lib/bug-bounty-intelligence');
      const result = await mod.enrichThreatIntelligence();
      expect(result).toBeDefined();
      expect(result).toHaveProperty('cweDistribution');
    });

    it('should handle API errors gracefully for attack vector enrichment', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));
      const mod = await import('./lib/bug-bounty-intelligence');
      const result = await mod.enrichAttackVectors();
      expect(result).toBeDefined();
      expect(result).toHaveProperty('bountyValidatedVectors');
    });

    it('should handle API errors gracefully for opsec enrichment', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));
      const mod = await import('./lib/bug-bounty-intelligence');
      const result = await mod.enrichOpSec();
      expect(result).toBeDefined();
      expect(result).toHaveProperty('weaknessCategories');
    });
  });
});
