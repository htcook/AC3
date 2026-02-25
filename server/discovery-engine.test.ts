import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the env module
vi.mock('./_core/env', () => ({
  ENV: {
    SHODAN_API_KEY: 'test-shodan-key',
    CENSYS_API_ID: 'test-censys-id',
    CENSYS_API_SECRET: 'test-censys-secret',
    SECURITYTRAILS_API_KEY: 'test-st-key',
    HACKERONE_API_KEY: 'test-h1-key',
  },
}));

// Mock the LLM module
vi.mock('./_core/llm', () => ({
  invokeLLM: vi.fn().mockResolvedValue({
    choices: [{
      message: {
        content: JSON.stringify({
          executiveSummary: "Test analysis summary",
          criticalFindings: [],
          attackSurface: { exposed: 0, services: [] },
          recommendations: [],
        }),
      },
    }],
  }),
}));

// Mock fetch to avoid real API calls
const mockFetch = vi.fn().mockResolvedValue({
  ok: false,
  status: 401,
  json: async () => ({ error: 'Unauthorized' }),
  text: async () => 'Unauthorized',
});
vi.stubGlobal('fetch', mockFetch);

describe('Discovery Engine', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ error: 'Unauthorized' }),
      text: async () => 'Unauthorized',
    });
  });

  describe('Module Exports', () => {
    it('should export getAvailableSources function', async () => {
      const mod = await import('./lib/discovery-engine');
      expect(typeof mod.getAvailableSources).toBe('function');
    });

    it('should export runDiscoveryPipeline function', async () => {
      const mod = await import('./lib/discovery-engine');
      expect(typeof mod.runDiscoveryPipeline).toBe('function');
    });

    it('should export shodanHostLookup function', async () => {
      const mod = await import('./lib/discovery-engine');
      expect(typeof mod.shodanHostLookup).toBe('function');
    });

    it('should export shodanDomainSearch function', async () => {
      const mod = await import('./lib/discovery-engine');
      expect(typeof mod.shodanDomainSearch).toBe('function');
    });

    it('should export censysHostSearch function', async () => {
      const mod = await import('./lib/discovery-engine');
      expect(typeof mod.censysHostSearch).toBe('function');
    });

    it('should export censysCertSearch function', async () => {
      const mod = await import('./lib/discovery-engine');
      expect(typeof mod.censysCertSearch).toBe('function');
    });

    it('should export securityTrailsSubdomains function', async () => {
      const mod = await import('./lib/discovery-engine');
      expect(typeof mod.securityTrailsSubdomains).toBe('function');
    });

    it('should export securityTrailsDNSHistory function', async () => {
      const mod = await import('./lib/discovery-engine');
      expect(typeof mod.securityTrailsDNSHistory).toBe('function');
    });

    it('should export securityTrailsDomainInfo function', async () => {
      const mod = await import('./lib/discovery-engine');
      expect(typeof mod.securityTrailsDomainInfo).toBe('function');
    });

    it('should export securityTrailsWHOIS function', async () => {
      const mod = await import('./lib/discovery-engine');
      expect(typeof mod.securityTrailsWHOIS).toBe('function');
    });

    it('should export analyzeScanWithLLM function', async () => {
      const mod = await import('./lib/discovery-engine');
      expect(typeof mod.analyzeScanWithLLM).toBe('function');
    });
  });

  describe('Available Sources', () => {
    it('should return array of source availability objects', async () => {
      const mod = await import('./lib/discovery-engine');
      const sources = mod.getAvailableSources();
      expect(Array.isArray(sources)).toBe(true);
      expect(sources.length).toBeGreaterThan(0);
    });

    it('should include shodan, censys, and securityTrails sources', async () => {
      const mod = await import('./lib/discovery-engine');
      const sources = mod.getAvailableSources();
      const sourceNames = sources.map((s: any) => s.source);
      expect(sourceNames).toContain('shodan');
      expect(sourceNames).toContain('censys');
      expect(sourceNames).toContain('securityTrails');
    });

    it('should have source, available, and reason fields', async () => {
      const mod = await import('./lib/discovery-engine');
      const sources = mod.getAvailableSources();
      for (const src of sources) {
        expect(src).toHaveProperty('source');
        expect(src).toHaveProperty('available');
        expect(src).toHaveProperty('reason');
        expect(typeof src.source).toBe('string');
        expect(typeof src.available).toBe('boolean');
        expect(typeof src.reason).toBe('string');
      }
    });
  });

  describe('Shodan Lookups', () => {
    it('should handle API errors gracefully for host lookup', async () => {
      const mod = await import('./lib/discovery-engine');
      const result = await mod.shodanHostLookup('1.2.3.4');
      // With mocked fetch returning 401, should return null
      expect(result).toBeNull();
    });

    it('should handle API errors gracefully for domain search', async () => {
      const mod = await import('./lib/discovery-engine');
      const result = await mod.shodanDomainSearch('example.com');
      // Should return empty/default structure on error
      expect(result).toBeDefined();
    });
  });

  describe('Censys Lookups', () => {
    it('should handle API errors gracefully for host search', async () => {
      const mod = await import('./lib/discovery-engine');
      const result = await mod.censysHostSearch('example.com');
      expect(result).toBeDefined();
    });

    it('should handle API errors gracefully for cert search', async () => {
      const mod = await import('./lib/discovery-engine');
      const result = await mod.censysCertSearch('example.com');
      expect(result).toBeDefined();
    });
  });

  describe('SecurityTrails Lookups', () => {
    it('should handle API errors gracefully for subdomains', async () => {
      const mod = await import('./lib/discovery-engine');
      const result = await mod.securityTrailsSubdomains('example.com');
      expect(result).toBeDefined();
    });

    it('should handle API errors gracefully for DNS history', async () => {
      const mod = await import('./lib/discovery-engine');
      const result = await mod.securityTrailsDNSHistory('example.com');
      expect(result).toBeDefined();
    });

    it('should handle API errors gracefully for domain info', async () => {
      const mod = await import('./lib/discovery-engine');
      const result = await mod.securityTrailsDomainInfo('example.com');
      expect(result).toBeDefined();
    });

    it('should handle API errors gracefully for WHOIS', async () => {
      const mod = await import('./lib/discovery-engine');
      const result = await mod.securityTrailsWHOIS('example.com');
      expect(result).toBeDefined();
    });
  });
});
