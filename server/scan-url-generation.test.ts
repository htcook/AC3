import { describe, it, expect } from 'vitest';

/**
 * Tests for the Nuclei scan URL generation logic.
 * These test the URL building logic that was fixed to always include
 * protocol prefixes (http:// and https://) in the fallback case.
 */

// Extracted URL generation logic from engagement-orchestrator.ts
function buildNucleiTargetUrls(asset: { hostname: string; ports: Array<{ port: number; service: string }> }): string[] {
  const NUCLEI_INFRA_PORTS = new Set([1337, 31337, 8834, 9392, 5432, 3306, 27017, 6379]);
  const webPorts = asset.ports.filter(p =>
    (['http', 'https', 'http-proxy', 'http-alt'].includes(p.service) ||
    [80, 443, 8080, 8443, 8000, 3000, 5000].includes(p.port))
    && !NUCLEI_INFRA_PORTS.has(p.port)
  );

  const nucleiTargetUrls = webPorts.length > 0
    ? webPorts.map(p => {
        const scheme = p.port === 443 || p.port === 8443 ? 'https' : 'http';
        return `${scheme}://${asset.hostname}:${p.port}`;
      })
    : [`http://${asset.hostname}`, `https://${asset.hostname}`];

  return nucleiTargetUrls;
}

// Stats recalculation logic
function recalculateStats(assets: Array<{ hostname: string; status: string; ports: any[]; vulns: any[] }>) {
  return {
    assetsDiscovered: assets.length,
    portsFound: assets.reduce((sum, a) => sum + (a.ports || []).length, 0),
    vulnsFound: assets.reduce((sum, a) => sum + (a.vulns || []).length, 0),
    hostsScanned: assets.filter(a => a.status !== 'pending').length,
  };
}

describe('Nuclei Target URL Generation', () => {
  describe('with discovered web ports', () => {
    it('should generate http:// URLs for standard HTTP ports', () => {
      const urls = buildNucleiTargetUrls({
        hostname: 'example.com',
        ports: [{ port: 80, service: 'http' }],
      });
      expect(urls).toEqual(['http://example.com:80']);
    });

    it('should generate https:// URLs for port 443', () => {
      const urls = buildNucleiTargetUrls({
        hostname: 'example.com',
        ports: [{ port: 443, service: 'https' }],
      });
      expect(urls).toEqual(['https://example.com:443']);
    });

    it('should generate https:// URLs for port 8443', () => {
      const urls = buildNucleiTargetUrls({
        hostname: 'example.com',
        ports: [{ port: 8443, service: 'https' }],
      });
      expect(urls).toEqual(['https://example.com:8443']);
    });

    it('should generate multiple URLs for multiple web ports', () => {
      const urls = buildNucleiTargetUrls({
        hostname: 'brokencrystals.lab.aceofcloud.io',
        ports: [
          { port: 80, service: 'http' },
          { port: 443, service: 'https' },
          { port: 8080, service: 'http-proxy' },
        ],
      });
      expect(urls).toEqual([
        'http://brokencrystals.lab.aceofcloud.io:80',
        'https://brokencrystals.lab.aceofcloud.io:443',
        'http://brokencrystals.lab.aceofcloud.io:8080',
      ]);
    });

    it('should handle http-alt service type', () => {
      const urls = buildNucleiTargetUrls({
        hostname: 'target.com',
        ports: [{ port: 8000, service: 'http-alt' }],
      });
      expect(urls).toEqual(['http://target.com:8000']);
    });

    it('should include common web ports even with unknown service names', () => {
      const urls = buildNucleiTargetUrls({
        hostname: 'target.com',
        ports: [{ port: 3000, service: 'unknown' }],
      });
      expect(urls).toEqual(['http://target.com:3000']);
    });
  });

  describe('without discovered web ports (fallback)', () => {
    it('should generate both http:// and https:// URLs when no ports discovered', () => {
      const urls = buildNucleiTargetUrls({
        hostname: 'brokencrystals.lab.aceofcloud.io',
        ports: [],
      });
      expect(urls).toEqual([
        'http://brokencrystals.lab.aceofcloud.io',
        'https://brokencrystals.lab.aceofcloud.io',
      ]);
    });

    it('should NOT return bare hostname without protocol', () => {
      const urls = buildNucleiTargetUrls({
        hostname: 'target.com',
        ports: [],
      });
      for (const url of urls) {
        expect(url).toMatch(/^https?:\/\//);
      }
    });

    it('should generate fallback URLs when only infra ports are found', () => {
      const urls = buildNucleiTargetUrls({
        hostname: 'target.com',
        ports: [
          { port: 5432, service: 'postgresql' },
          { port: 3306, service: 'mysql' },
          { port: 6379, service: 'redis' },
        ],
      });
      // Infra ports are excluded, so fallback to http+https
      expect(urls).toEqual([
        'http://target.com',
        'https://target.com',
      ]);
    });

    it('should generate fallback URLs when only non-web ports are found', () => {
      const urls = buildNucleiTargetUrls({
        hostname: 'target.com',
        ports: [
          { port: 22, service: 'ssh' },
          { port: 25, service: 'smtp' },
        ],
      });
      expect(urls).toEqual([
        'http://target.com',
        'https://target.com',
      ]);
    });
  });

  describe('infra port exclusion', () => {
    it('should exclude Nessus port 8834', () => {
      const urls = buildNucleiTargetUrls({
        hostname: 'target.com',
        ports: [{ port: 8834, service: 'http' }],
      });
      expect(urls).toEqual(['http://target.com', 'https://target.com']);
    });

    it('should exclude OpenVAS port 9392', () => {
      const urls = buildNucleiTargetUrls({
        hostname: 'target.com',
        ports: [{ port: 9392, service: 'http' }],
      });
      expect(urls).toEqual(['http://target.com', 'https://target.com']);
    });

    it('should include web ports but exclude infra ports in mixed scenarios', () => {
      const urls = buildNucleiTargetUrls({
        hostname: 'target.com',
        ports: [
          { port: 80, service: 'http' },
          { port: 5432, service: 'postgresql' },
          { port: 443, service: 'https' },
        ],
      });
      expect(urls).toEqual([
        'http://target.com:80',
        'https://target.com:443',
      ]);
    });
  });
});

describe('Stats Recalculation', () => {
  it('should correctly count assets', () => {
    const stats = recalculateStats([
      { hostname: 'a.com', status: 'scanned', ports: [], vulns: [] },
      { hostname: 'b.com', status: 'scanned', ports: [], vulns: [] },
    ]);
    expect(stats.assetsDiscovered).toBe(2);
  });

  it('should correctly count ports across assets', () => {
    const stats = recalculateStats([
      { hostname: 'a.com', status: 'scanned', ports: [{ port: 80 }, { port: 443 }], vulns: [] },
      { hostname: 'b.com', status: 'scanned', ports: [{ port: 8080 }], vulns: [] },
    ]);
    expect(stats.portsFound).toBe(3);
  });

  it('should correctly count vulns across assets', () => {
    const stats = recalculateStats([
      { hostname: 'a.com', status: 'scanned', ports: [], vulns: [{ id: 'v1' }, { id: 'v2' }] },
      { hostname: 'b.com', status: 'scanned', ports: [], vulns: [{ id: 'v3' }] },
    ]);
    expect(stats.vulnsFound).toBe(3);
  });

  it('should only count scanned hosts (not pending)', () => {
    const stats = recalculateStats([
      { hostname: 'a.com', status: 'scanned', ports: [], vulns: [] },
      { hostname: 'b.com', status: 'pending', ports: [], vulns: [] },
      { hostname: 'c.com', status: 'error', ports: [], vulns: [] },
    ]);
    expect(stats.hostsScanned).toBe(2); // scanned + error (not pending)
    expect(stats.assetsDiscovered).toBe(3);
  });

  it('should handle empty assets array', () => {
    const stats = recalculateStats([]);
    expect(stats.assetsDiscovered).toBe(0);
    expect(stats.portsFound).toBe(0);
    expect(stats.vulnsFound).toBe(0);
    expect(stats.hostsScanned).toBe(0);
  });

  it('should handle assets with undefined ports/vulns', () => {
    const stats = recalculateStats([
      { hostname: 'a.com', status: 'scanned', ports: undefined as any, vulns: undefined as any },
    ]);
    expect(stats.assetsDiscovered).toBe(1);
    expect(stats.portsFound).toBe(0);
    expect(stats.vulnsFound).toBe(0);
  });

  it('should recalculate correctly after reset and re-population', () => {
    // Simulate: assets cleared, then re-populated during pipeline
    let assets: any[] = [];
    let stats = recalculateStats(assets);
    expect(stats.assetsDiscovered).toBe(0);

    // Re-populate during passive recon
    assets.push({ hostname: 'brokencrystals.lab.aceofcloud.io', status: 'scanned', ports: [{ port: 80 }], vulns: [] });
    stats = recalculateStats(assets);
    expect(stats.assetsDiscovered).toBe(1);
    expect(stats.portsFound).toBe(1);

    // Add vulns during active scanning
    assets[0].vulns.push({ id: 'nuclei-sqli-1', title: 'SQL Injection' });
    assets[0].vulns.push({ id: 'nuclei-xss-1', title: 'XSS' });
    stats = recalculateStats(assets);
    expect(stats.vulnsFound).toBe(2);
    expect(stats.assetsDiscovered).toBe(1);
  });
});
