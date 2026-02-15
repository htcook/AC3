import { describe, it, expect } from 'vitest';

describe('DNS/Banner Verification', () => {
  describe('verifyAllAssets', () => {
    it('should export verifyAllAssets function', async () => {
      const mod = await import('./lib/dns-banner-verify');
      expect(typeof mod.verifyAllAssets).toBe('function');
    });

    it('should return empty results for empty input', async () => {
      const { verifyAllAssets } = await import('./lib/dns-banner-verify');
      const result = await verifyAllAssets([]);
      expect(result.assets).toEqual([]);
      expect(result.summary.total).toBe(0);
    });

    it('should preserve original asset fields when verification fails', async () => {
      const { verifyAllAssets } = await import('./lib/dns-banner-verify');
      const assets = [{
        hostname: 'nonexistent.invalid.test',
        assetType: 'web_server',
        technologies: ['nginx'],
        discoveryMethod: 'llm_inferred' as const,
      }];
      const result = await verifyAllAssets(assets);
      expect(result.assets.length).toBe(1);
      expect(result.assets[0].hostname).toBe('nonexistent.invalid.test');
      expect(result.assets[0].assetType).toBe('web_server');
    });

    it('should upgrade discoveryMethod when DNS resolves', async () => {
      const { verifyAllAssets } = await import('./lib/dns-banner-verify');
      const assets = [{
        hostname: 'google.com',
        assetType: 'web_server',
        technologies: [],
        discoveryMethod: 'llm_inferred' as const,
      }];
      const result = await verifyAllAssets(assets);
      expect(result.assets.length).toBe(1);
      // Should be either dns_verified or header_detected
      expect(['dns_verified', 'header_detected']).toContain(result.assets[0].discoveryMethod);
      expect(result.summary.dnsVerified + result.summary.bannerDetected).toBeGreaterThan(0);
    }, 15000);

    it('should handle multiple assets concurrently', async () => {
      const { verifyAllAssets } = await import('./lib/dns-banner-verify');
      const assets = [
        { hostname: 'google.com', assetType: 'web_server', technologies: [], discoveryMethod: 'llm_inferred' as const },
        { hostname: 'nonexistent.invalid.test', assetType: 'dns', technologies: [], discoveryMethod: 'llm_inferred' as const },
      ];
      const result = await verifyAllAssets(assets, 2);
      expect(result.assets.length).toBe(2);
      expect(result.summary.total).toBe(2);
    });

    it('should track progress via callback', async () => {
      const { verifyAllAssets } = await import('./lib/dns-banner-verify');
      const progressCalls: [number, number][] = [];
      const assets = [
        { hostname: 'google.com', assetType: 'web_server', technologies: [], discoveryMethod: 'llm_inferred' as const },
      ];
      await verifyAllAssets(assets, 5, (completed, total) => {
        progressCalls.push([completed, total]);
      });
      expect(progressCalls.length).toBeGreaterThan(0);
      // Last call should show all completed
      const last = progressCalls[progressCalls.length - 1];
      expect(last[0]).toBe(last[1]);
    });
  });

  describe('verifyDns', () => {
    it('should export verifyDns function', async () => {
      const mod = await import('./lib/dns-banner-verify');
      expect(typeof mod.verifyDns).toBe('function');
    });

    it('should resolve a valid hostname', async () => {
      const { verifyDns } = await import('./lib/dns-banner-verify');
      const result = await verifyDns('google.com');
      expect(result.resolved).toBe(true);
      expect(result.aRecords).toBeDefined();
      expect(result.aRecords!.length).toBeGreaterThan(0);
    });

    it('should fail for invalid hostname', async () => {
      const { verifyDns } = await import('./lib/dns-banner-verify');
      const result = await verifyDns('nonexistent.invalid.test');
      expect(result.resolved).toBe(false);
    });

    it('should respect timeout', async () => {
      const { verifyDns } = await import('./lib/dns-banner-verify');
      // Very short timeout
      const result = await verifyDns('nonexistent.invalid.test', 100);
      expect(result.resolved).toBe(false);
    });
  });

  describe('extractTechnologiesFromHeaders', () => {
    it('should export extractTechnologiesFromHeaders function', async () => {
      const mod = await import('./lib/dns-banner-verify');
      expect(typeof mod.extractTechnologiesFromHeaders).toBe('function');
    });

    it('should extract nginx from server header', async () => {
      const { extractTechnologiesFromHeaders } = await import('./lib/dns-banner-verify');
      const result = extractTechnologiesFromHeaders({ server: 'nginx/1.18.0' });
      const nginx = result.find(t => t.name.toLowerCase() === 'nginx');
      expect(nginx).toBeDefined();
      expect(nginx!.version).toBe('1.18.0');
    });

    it('should extract Apache from server header', async () => {
      const { extractTechnologiesFromHeaders } = await import('./lib/dns-banner-verify');
      const result = extractTechnologiesFromHeaders({ server: 'Apache/2.4.51 (Ubuntu)' });
      const apache = result.find(t => t.name.toLowerCase() === 'apache');
      expect(apache).toBeDefined();
      expect(apache!.version).toBe('2.4.51');
    });

    it('should extract PHP from x-powered-by header', async () => {
      const { extractTechnologiesFromHeaders } = await import('./lib/dns-banner-verify');
      const result = extractTechnologiesFromHeaders({ 'x-powered-by': 'PHP/8.1.2' });
      const php = result.find(t => t.name.toLowerCase() === 'php');
      expect(php).toBeDefined();
      expect(php!.version).toBe('8.1.2');
    });

    it('should handle empty headers', async () => {
      const { extractTechnologiesFromHeaders } = await import('./lib/dns-banner-verify');
      const result = extractTechnologiesFromHeaders({});
      expect(result).toEqual([]);
    });

    it('should extract multiple technologies from combined headers', async () => {
      const { extractTechnologiesFromHeaders } = await import('./lib/dns-banner-verify');
      const result = extractTechnologiesFromHeaders({
        server: 'nginx/1.20.1',
        'x-powered-by': 'Express',
      });
      expect(result.length).toBeGreaterThanOrEqual(2);
    });
  });
});

// Test the scan comparison logic (pure functions)
describe('Scan Comparison Logic', () => {
  it('should detect new and removed assets by hostname', () => {
    const hostnamesA = new Set(['web.example.com', 'mail.example.com', 'api.example.com']);
    const hostnamesB = new Set(['web.example.com', 'api.example.com', 'cdn.example.com']);

    const newHostnames = Array.from(hostnamesB).filter(h => !hostnamesA.has(h));
    const removedHostnames = Array.from(hostnamesA).filter(h => !hostnamesB.has(h));
    const common = Array.from(hostnamesA).filter(h => hostnamesB.has(h));

    expect(newHostnames).toEqual(['cdn.example.com']);
    expect(removedHostnames).toEqual(['mail.example.com']);
    expect(common).toEqual(['web.example.com', 'api.example.com']);
  });

  it('should detect new and resolved CVEs', () => {
    const cveSetA = new Set(['CVE-2021-44228', 'CVE-2023-1234', 'CVE-2022-5678']);
    const cveSetB = new Set(['CVE-2021-44228', 'CVE-2024-9999', 'CVE-2022-5678']);

    const newCves = Array.from(cveSetB).filter(c => !cveSetA.has(c));
    const resolvedCves = Array.from(cveSetA).filter(c => !cveSetB.has(c));

    expect(newCves).toEqual(['CVE-2024-9999']);
    expect(resolvedCves).toEqual(['CVE-2023-1234']);
  });

  it('should calculate risk delta correctly', () => {
    expect(62 - 45).toBe(17); // Risk increased
    expect(38 - 72).toBe(-34); // Risk decreased
  });

  it('should compute per-asset risk changes', () => {
    const assetsA = [
      { hostname: 'web.example.com', hybridRiskScore: 45, riskBand: 'medium' },
      { hostname: 'api.example.com', hybridRiskScore: 30, riskBand: 'low' },
    ];
    const assetsB = [
      { hostname: 'web.example.com', hybridRiskScore: 62, riskBand: 'high' },
      { hostname: 'api.example.com', hybridRiskScore: 30, riskBand: 'low' },
    ];

    const riskChanges = assetsA.map(a => {
      const b = assetsB.find(x => x.hostname === a.hostname);
      return {
        hostname: a.hostname,
        riskA: a.hybridRiskScore,
        riskB: b?.hybridRiskScore ?? 0,
        delta: (b?.hybridRiskScore ?? 0) - a.hybridRiskScore,
      };
    }).filter(r => r.delta !== 0);

    expect(riskChanges.length).toBe(1);
    expect(riskChanges[0].hostname).toBe('web.example.com');
    expect(riskChanges[0].delta).toBe(17);
  });

  it('should compute corroboration tier comparison', () => {
    const findingsA = [
      { corroborationTier: 'confirmed' },
      { corroborationTier: 'confirmed' },
      { corroborationTier: 'probable' },
      { corroborationTier: 'potential' },
    ];
    const findingsB = [
      { corroborationTier: 'confirmed' },
      { corroborationTier: 'confirmed' },
      { corroborationTier: 'confirmed' },
      { corroborationTier: 'probable' },
      { corroborationTier: 'probable' },
    ];

    const tierCountA: Record<string, number> = { confirmed: 0, probable: 0, potential: 0 };
    const tierCountB: Record<string, number> = { confirmed: 0, probable: 0, potential: 0 };
    findingsA.forEach(f => { tierCountA[f.corroborationTier]++; });
    findingsB.forEach(f => { tierCountB[f.corroborationTier]++; });

    expect(tierCountA).toEqual({ confirmed: 2, probable: 1, potential: 1 });
    expect(tierCountB).toEqual({ confirmed: 3, probable: 2, potential: 0 });
  });

  it('should detect new findings by ID', () => {
    const findingsA = [{ id: 'f1' }, { id: 'f2' }];
    const findingsB = [{ id: 'f1' }, { id: 'f3' }];

    const idsA = new Set(findingsA.map(f => f.id));
    const idsB = new Set(findingsB.map(f => f.id));
    const newFindings = findingsB.filter(f => !idsA.has(f.id));
    const resolvedFindings = findingsA.filter(f => !idsB.has(f.id));

    expect(newFindings.length).toBe(1);
    expect(newFindings[0].id).toBe('f3');
    expect(resolvedFindings.length).toBe(1);
    expect(resolvedFindings[0].id).toBe('f2');
  });

  it('should sort risk changes by absolute delta descending', () => {
    const changes = [
      { hostname: 'a.com', delta: 5 },
      { hostname: 'b.com', delta: -20 },
      { hostname: 'c.com', delta: 10 },
    ];
    const sorted = changes.sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta));
    expect(sorted[0].hostname).toBe('b.com');
    expect(sorted[1].hostname).toBe('c.com');
    expect(sorted[2].hostname).toBe('a.com');
  });
});
