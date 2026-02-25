import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the env module
vi.mock('./_core/env', () => ({
  ENV: {
    HACKERONE_API_KEY: 'test-api-key-123',
    SHODAN_API_KEY: 'test-shodan-key',
    SECURITYTRAILS_API_KEY: 'test-st-key',
    CENSYS_API_ID: 'test-censys-id',
    CENSYS_API_SECRET: 'test-censys-secret',
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

describe('Cross-Module Enrichment', () => {
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
    it('should export runCrossModuleEnrichment function', async () => {
      const mod = await import('./lib/cross-module-enrichment');
      expect(typeof mod.runCrossModuleEnrichment).toBe('function');
    });
  });

  describe('Cross-Module Enrichment Pipeline', () => {
    it('should run all enrichment modules and return structured result', async () => {
      const mod = await import('./lib/cross-module-enrichment');

      const mockAnalyses = [
        {
          asset: {
            assetId: 'asset-1',
            hostname: 'www.example.com',
            technologies: ['nginx', 'react'],
          },
          postureFindings: [],
          hybridRiskScore: 45,
          riskBand: 'moderate',
        },
        {
          asset: {
            assetId: 'asset-2',
            hostname: 'api.example.com',
            technologies: ['express', 'node.js'],
          },
          postureFindings: [],
          hybridRiskScore: 60,
          riskBand: 'elevated',
        },
      ];

      const result = await mod.runCrossModuleEnrichment(mockAnalyses as any, 'example.com');

      // Verify top-level structure matches CrossModuleEnrichmentResult
      expect(result).toBeDefined();
      expect(result).toHaveProperty('bugBounty');
      expect(result).toHaveProperty('threatIntel');
      expect(result).toHaveProperty('opsec');
      expect(result).toHaveProperty('discoveryDeepDive');
      expect(result).toHaveProperty('summary');

      // Verify summary structure
      expect(result.summary).toHaveProperty('modulesRun');
      expect(result.summary).toHaveProperty('modulesSucceeded');
      expect(result.summary).toHaveProperty('modulesFailed');
      expect(result.summary).toHaveProperty('totalCorrelations');
      expect(result.summary).toHaveProperty('totalNewFindings');
      expect(result.summary).toHaveProperty('totalRiskAdjustments');
      expect(result.summary).toHaveProperty('durationMs');
      expect(typeof result.summary.modulesRun).toBe('number');
      expect(typeof result.summary.modulesSucceeded).toBe('number');
      expect(typeof result.summary.totalCorrelations).toBe('number');
      expect(result.summary.modulesRun).toBe(4);
    });

    it('should handle empty analyses gracefully', async () => {
      const mod = await import('./lib/cross-module-enrichment');
      const result = await mod.runCrossModuleEnrichment([], 'example.com');
      expect(result).toBeDefined();
      expect(result.summary.modulesRun).toBe(4);
    });
  });

  describe('Bug Bounty Module', () => {
    it('should return status field for bug bounty enrichment', async () => {
      const mod = await import('./lib/cross-module-enrichment');
      const result = await mod.runCrossModuleEnrichment([], 'example.com');
      expect(result.bugBounty).toHaveProperty('status');
      expect(['success', 'failed', 'skipped']).toContain(result.bugBounty.status);
    });

    it('should return hasBugBountyProgram field', async () => {
      const mod = await import('./lib/cross-module-enrichment');
      const result = await mod.runCrossModuleEnrichment([], 'example.com');
      expect(result.bugBounty).toHaveProperty('hasBugBountyProgram');
      expect(typeof result.bugBounty.hasBugBountyProgram).toBe('boolean');
    });

    it('should return correlations array', async () => {
      const mod = await import('./lib/cross-module-enrichment');
      const result = await mod.runCrossModuleEnrichment([], 'example.com');
      expect(Array.isArray(result.bugBounty.correlations)).toBe(true);
    });

    it('should return newFindings array', async () => {
      const mod = await import('./lib/cross-module-enrichment');
      const result = await mod.runCrossModuleEnrichment([], 'example.com');
      expect(Array.isArray(result.bugBounty.newFindings)).toBe(true);
    });
  });

  describe('Threat Intel Module', () => {
    it('should return status field for threat intel enrichment', async () => {
      const mod = await import('./lib/cross-module-enrichment');
      const result = await mod.runCrossModuleEnrichment([], 'example.com');
      expect(result.threatIntel).toHaveProperty('status');
      expect(['success', 'failed', 'skipped']).toContain(result.threatIntel.status);
    });

    it('should return correlations array', async () => {
      const mod = await import('./lib/cross-module-enrichment');
      const result = await mod.runCrossModuleEnrichment([], 'example.com');
      expect(Array.isArray(result.threatIntel.correlations)).toBe(true);
    });

    it('should return riskAdjustments array', async () => {
      const mod = await import('./lib/cross-module-enrichment');
      const result = await mod.runCrossModuleEnrichment([], 'example.com');
      expect(Array.isArray(result.threatIntel.riskAdjustments)).toBe(true);
    });
  });

  describe('OpSec Module', () => {
    it('should return status field for opsec enrichment', async () => {
      const mod = await import('./lib/cross-module-enrichment');
      const result = await mod.runCrossModuleEnrichment([], 'example.com');
      expect(result.opsec).toHaveProperty('status');
      expect(['success', 'failed', 'skipped']).toContain(result.opsec.status);
    });

    it('should return defensiveGaps array', async () => {
      const mod = await import('./lib/cross-module-enrichment');
      const result = await mod.runCrossModuleEnrichment([], 'example.com');
      expect(Array.isArray(result.opsec.defensiveGaps)).toBe(true);
    });
  });

  describe('Discovery Deep Dive Module', () => {
    it('should return status field for discovery deep dive', async () => {
      const mod = await import('./lib/cross-module-enrichment');
      const result = await mod.runCrossModuleEnrichment([], 'example.com');
      expect(result.discoveryDeepDive).toHaveProperty('status');
      expect(['success', 'failed', 'skipped']).toContain(result.discoveryDeepDive.status);
    });

    it('should return correlations array', async () => {
      const mod = await import('./lib/cross-module-enrichment');
      const result = await mod.runCrossModuleEnrichment([], 'example.com');
      expect(Array.isArray(result.discoveryDeepDive.correlations)).toBe(true);
    });
  });
});
