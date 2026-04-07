import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch as any;

// Mock LLM
vi.mock('./_core/llm', () => ({
  invokeLLM: vi.fn().mockResolvedValue({
    choices: [{
      message: {
        content: JSON.stringify({
          affiliatedDomains: [
            { domain: 'mypbs.org', relationship: 'Member portal for PBS', confidence: 'high' },
            { domain: 'pbskids.org', relationship: 'PBS Kids educational content', confidence: 'high' },
          ]
        })
      }
    }]
  })
}));

// Mock ENV
vi.mock('./_core/env', () => ({
  ENV: {
    SECURITYTRAILS_API_KEY: 'test-api-key',
  }
}));

describe('Affiliated Domain Discovery', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('should export runAffiliatedDomainDiscovery function', async () => {
    const mod = await import('./lib/affiliated-domain-discovery');
    expect(typeof mod.runAffiliatedDomainDiscovery).toBe('function');
  });

  it('should discover affiliated domains via LLM knowledge', async () => {
    // Mock all fetch calls to return empty/error (so only LLM works)
    mockFetch.mockRejectedValue(new Error('Network error'));

    const { runAffiliatedDomainDiscovery } = await import('./lib/affiliated-domain-discovery');
    const result = await runAffiliatedDomainDiscovery('pbs.org', 'Public Broadcasting Service');

    expect(result).toBeDefined();
    expect(result.targetDomain).toBe('pbs.org');
    expect(result.searchedAt).toBeGreaterThan(0);
    // LLM should have found mypbs.org and pbskids.org
    const llmDomains = result.affiliatedDomains.filter(d => d.source === 'llm_knowledge');
    expect(llmDomains.length).toBeGreaterThanOrEqual(1);
    expect(result.summary).toBeTruthy();
  });

  it('should deduplicate domains from multiple sources', async () => {
    // Mock SecurityTrails returning a domain
    mockFetch.mockImplementation((url: string) => {
      const urlStr = String(url);
      if (urlStr.includes('securitytrails.com') && urlStr.includes('whois')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            result: { registrant_org: 'Test Corp', registrant_email: 'admin@test.com' }
          })
        });
      }
      if (urlStr.includes('securitytrails.com') && urlStr.includes('domains/list')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            records: [
              { hostname: 'mypbs.org' },  // Same as LLM will return
              { hostname: 'pbslearning.org' },
            ]
          })
        });
      }
      if (urlStr.includes('securitytrails.com') && urlStr.includes('associated')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ records: [] })
        });
      }
      // crt.sh and DNS
      return Promise.reject(new Error('Not mocked'));
    });

    const { runAffiliatedDomainDiscovery } = await import('./lib/affiliated-domain-discovery');
    const result = await runAffiliatedDomainDiscovery('pbs.org', 'Public Broadcasting Service');

    // mypbs.org should appear only once (deduped), with boosted confidence
    const mypbsEntries = result.affiliatedDomains.filter(d => d.domain === 'mypbs.org');
    expect(mypbsEntries.length).toBe(1);
    // Confidence should be boosted since both ST and LLM found it
    expect(mypbsEntries[0].confidence).toBeGreaterThanOrEqual(75);
  });

  it('should filter out common service domains', async () => {
    mockFetch.mockImplementation((url: string) => {
      const urlStr = String(url);
      if (urlStr.includes('securitytrails.com') && urlStr.includes('whois')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            result: { registrant_org: 'Test Corp' }
          })
        });
      }
      if (urlStr.includes('securitytrails.com') && urlStr.includes('domains/list')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            records: [
              { hostname: 'google.com' },  // Should be filtered
              { hostname: 'cloudflare.com' },  // Should be filtered
              { hostname: 'legit-affiliate.com' },  // Should remain
            ]
          })
        });
      }
      if (urlStr.includes('securitytrails.com') && urlStr.includes('associated')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ records: [] }) });
      }
      return Promise.reject(new Error('Not mocked'));
    });

    const { runAffiliatedDomainDiscovery } = await import('./lib/affiliated-domain-discovery');
    const result = await runAffiliatedDomainDiscovery('example.com', 'Test Corp');

    const domainNames = result.affiliatedDomains.map(d => d.domain);
    expect(domainNames).not.toContain('google.com');
    expect(domainNames).not.toContain('cloudflare.com');
  });

  it('should handle missing SecurityTrails API key gracefully', async () => {
    // Re-mock ENV without API key
    vi.doMock('./_core/env', () => ({
      ENV: { SECURITYTRAILS_API_KEY: '' }
    }));

    mockFetch.mockRejectedValue(new Error('Network error'));

    const { runAffiliatedDomainDiscovery } = await import('./lib/affiliated-domain-discovery');
    const result = await runAffiliatedDomainDiscovery('example.com');

    // Should still return a valid result (from LLM at minimum)
    expect(result).toBeDefined();
    expect(result.targetDomain).toBe('example.com');
    expect(typeof result.totalDiscovered).toBe('number');
  });

  it('should generate a meaningful summary', async () => {
    mockFetch.mockRejectedValue(new Error('Network error'));

    const { runAffiliatedDomainDiscovery } = await import('./lib/affiliated-domain-discovery');
    const result = await runAffiliatedDomainDiscovery('pbs.org', 'PBS');

    expect(result.summary).toBeTruthy();
    expect(typeof result.summary).toBe('string');
    expect(result.summary.length).toBeGreaterThan(10);
  });

  it('should include source breakdown', async () => {
    mockFetch.mockRejectedValue(new Error('Network error'));

    const { runAffiliatedDomainDiscovery } = await import('./lib/affiliated-domain-discovery');
    const result = await runAffiliatedDomainDiscovery('pbs.org', 'PBS');

    expect(result.sourceBreakdown).toBeDefined();
    expect(typeof result.sourceBreakdown).toBe('object');
    // If LLM found domains, there should be an llm_knowledge entry
    if (result.totalDiscovered > 0) {
      expect(Object.keys(result.sourceBreakdown).length).toBeGreaterThan(0);
    }
  });

  it('should sort results by confidence descending', async () => {
    mockFetch.mockRejectedValue(new Error('Network error'));

    const { runAffiliatedDomainDiscovery } = await import('./lib/affiliated-domain-discovery');
    const result = await runAffiliatedDomainDiscovery('pbs.org', 'PBS');

    if (result.affiliatedDomains.length > 1) {
      for (let i = 1; i < result.affiliatedDomains.length; i++) {
        expect(result.affiliatedDomains[i].confidence).toBeLessThanOrEqual(
          result.affiliatedDomains[i - 1].confidence
        );
      }
    }
  });
});

describe('Incident Search Ingest', () => {
  it('should export ingestIncidentSearchResults function', async () => {
    const mod = await import('./lib/incident-search-ingest');
    expect(typeof mod.ingestIncidentSearchResults).toBe('function');
  });
});
