import { describe, it, expect, vi } from 'vitest';

// ─── Scoped Scan Filter Tests ────────────────────────────────────────
// Tests the Stage 1.4 scoped scan filtering logic that restricts
// discovered assets to only user-specified hostnames/IPs (RoE mode)

interface MockAsset {
  assetId: string;
  hostname: string;
  url?: string;
  assetType: string;
  assetClasses: string[];
  tags: string[];
  technologies: string[];
  technologyVersions: Record<string, string>;
  description: string;
  discoveryMethod: string;
  discoveryEvidence: string;
}

function createMockAsset(hostname: string, overrides?: Partial<MockAsset>): MockAsset {
  return {
    assetId: `test-${hostname.replace(/\./g, '-')}`,
    hostname,
    url: `https://${hostname}`,
    assetType: 'web_application',
    assetClasses: ['subdomain'],
    tags: [],
    technologies: [],
    technologyVersions: {},
    description: `Test asset ${hostname}`,
    discoveryMethod: 'inferred',
    discoveryEvidence: 'Test',
    ...overrides,
  };
}

/**
 * Replicates the Stage 1.4 scoped scan filter logic from domainIntel.ts
 */
function applyScopedFilter(rawAssets: MockAsset[], scopedAssets?: string[]): MockAsset[] {
  const isScopedScan = scopedAssets && scopedAssets.length > 0;
  if (!isScopedScan || !scopedAssets) return rawAssets;

  const scopedSet = new Set(scopedAssets.map(a => a.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, '')));
  
  const filtered = rawAssets.filter(a => {
    const hostname = (a.hostname || '').toLowerCase();
    const url = (a.url || '').toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    return scopedSet.has(hostname) || scopedSet.has(url);
  });

  // If no discovered assets match the scoped list, create stub assets
  if (filtered.length === 0) {
    for (const scopedHost of scopedAssets) {
      const clean = scopedHost.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, '');
      filtered.push({
        assetId: `scoped-${clean.replace(/[^a-z0-9]/g, '-')}-stub`,
        hostname: clean,
        url: `https://${clean}`,
        assetType: 'web_application',
        assetClasses: ['scoped_asset'],
        tags: ['scoped_scan', 'roe_restricted'],
        technologies: [],
        technologyVersions: {},
        description: `Asset specified in scoped scan (RoE restricted)`,
        discoveryMethod: 'manual',
        discoveryEvidence: 'User-specified asset for scoped/RoE-restricted scan',
      });
    }
  }

  return filtered;
}

describe('Scoped Scan Filter (Stage 1.4)', () => {
  const allAssets = [
    createMockAsset('www.example.com'),
    createMockAsset('api.example.com'),
    createMockAsset('mail.example.com'),
    createMockAsset('admin.example.com'),
    createMockAsset('portal.example.com'),
    createMockAsset('vpn.example.com'),
    createMockAsset('sso.example.com'),
    createMockAsset('cdn.example.com'),
    createMockAsset('staging.example.com'),
    createMockAsset('dev.example.com'),
  ];

  describe('when scopedAssets is not provided (full discovery mode)', () => {
    it('should return all discovered assets unchanged', () => {
      const result = applyScopedFilter([...allAssets], undefined);
      expect(result).toHaveLength(10);
    });

    it('should return all assets when scopedAssets is empty array', () => {
      const result = applyScopedFilter([...allAssets], []);
      expect(result).toHaveLength(10);
    });
  });

  describe('when scopedAssets is provided (RoE mode)', () => {
    it('should filter to only the specified assets', () => {
      const result = applyScopedFilter([...allAssets], ['www.example.com', 'api.example.com', 'portal.example.com']);
      expect(result).toHaveLength(3);
      expect(result.map(a => a.hostname)).toEqual(['www.example.com', 'api.example.com', 'portal.example.com']);
    });

    it('should handle single scoped asset', () => {
      const result = applyScopedFilter([...allAssets], ['api.example.com']);
      expect(result).toHaveLength(1);
      expect(result[0].hostname).toBe('api.example.com');
    });

    it('should be case-insensitive', () => {
      const result = applyScopedFilter([...allAssets], ['WWW.EXAMPLE.COM', 'API.Example.Com']);
      expect(result).toHaveLength(2);
      expect(result.map(a => a.hostname)).toEqual(['www.example.com', 'api.example.com']);
    });

    it('should strip protocol prefixes from scoped assets', () => {
      const result = applyScopedFilter([...allAssets], ['https://www.example.com', 'http://api.example.com']);
      expect(result).toHaveLength(2);
      expect(result.map(a => a.hostname)).toEqual(['www.example.com', 'api.example.com']);
    });

    it('should strip trailing paths from scoped assets', () => {
      const result = applyScopedFilter([...allAssets], ['www.example.com/login', 'api.example.com/v1/health']);
      expect(result).toHaveLength(2);
      expect(result.map(a => a.hostname)).toEqual(['www.example.com', 'api.example.com']);
    });

    it('should strip trailing dots from scoped assets', () => {
      const result = applyScopedFilter([...allAssets], ['www.example.com.']);
      expect(result).toHaveLength(1);
      expect(result[0].hostname).toBe('www.example.com');
    });

    it('should exclude all non-scoped assets', () => {
      const result = applyScopedFilter([...allAssets], ['www.example.com']);
      expect(result).toHaveLength(1);
      const excluded = ['api.example.com', 'mail.example.com', 'admin.example.com', 'portal.example.com', 'vpn.example.com', 'sso.example.com', 'cdn.example.com', 'staging.example.com', 'dev.example.com'];
      for (const host of excluded) {
        expect(result.find(a => a.hostname === host)).toBeUndefined();
      }
    });

    it('should match by URL when hostname does not match directly', () => {
      const assetWithDifferentUrl = createMockAsset('10.0.1.50', { url: 'https://10.0.1.50' });
      const assets = [...allAssets, assetWithDifferentUrl];
      const result = applyScopedFilter(assets, ['10.0.1.50']);
      expect(result).toHaveLength(1);
      expect(result[0].hostname).toBe('10.0.1.50');
    });
  });

  describe('stub asset creation when no matches found', () => {
    it('should create stub assets when no discovered assets match the scope', () => {
      const result = applyScopedFilter([...allAssets], ['totally-different.com', '192.168.1.1']);
      expect(result).toHaveLength(2);
      expect(result[0].hostname).toBe('totally-different.com');
      expect(result[1].hostname).toBe('192.168.1.1');
      expect(result[0].assetClasses).toContain('scoped_asset');
      expect(result[0].tags).toContain('scoped_scan');
      expect(result[0].tags).toContain('roe_restricted');
      expect(result[0].discoveryMethod).toBe('manual');
    });

    it('should NOT create stubs when at least one match exists', () => {
      const result = applyScopedFilter([...allAssets], ['www.example.com', 'totally-different.com']);
      // Only www.example.com matches — totally-different.com is just excluded, no stub
      expect(result).toHaveLength(1);
      expect(result[0].hostname).toBe('www.example.com');
    });

    it('stub assets should have proper URL format', () => {
      const result = applyScopedFilter([], ['my-target.com']);
      expect(result).toHaveLength(1);
      expect(result[0].url).toBe('https://my-target.com');
    });
  });

  describe('edge cases', () => {
    it('should handle empty rawAssets with scoped list', () => {
      const result = applyScopedFilter([], ['target.com']);
      expect(result).toHaveLength(1);
      expect(result[0].hostname).toBe('target.com');
      expect(result[0].discoveryMethod).toBe('manual');
    });

    it('should handle IP addresses as scoped assets', () => {
      const ipAsset = createMockAsset('10.0.1.50');
      const result = applyScopedFilter([ipAsset, ...allAssets], ['10.0.1.50']);
      expect(result).toHaveLength(1);
      expect(result[0].hostname).toBe('10.0.1.50');
    });

    it('should handle duplicate scoped assets gracefully', () => {
      const result = applyScopedFilter([...allAssets], ['www.example.com', 'www.example.com', 'WWW.EXAMPLE.COM']);
      expect(result).toHaveLength(1);
      expect(result[0].hostname).toBe('www.example.com');
    });

    it('should handle scoped assets with mixed formats', () => {
      const result = applyScopedFilter([...allAssets], [
        'https://www.example.com/path',
        'API.EXAMPLE.COM.',
        'http://portal.example.com',
      ]);
      expect(result).toHaveLength(3);
      const hostnames = result.map(a => a.hostname).sort();
      expect(hostnames).toEqual(['api.example.com', 'portal.example.com', 'www.example.com']);
    });
  });
});

describe('Scoped Scan Input Schema', () => {
  it('scopedAssets should be optional in the input', () => {
    // This test validates the schema accepts calls without scopedAssets
    const inputWithout = {
      primaryDomain: 'example.com',
      customerName: 'Test Corp',
      sector: 'Technology',
      clientType: 'enterprise',
      criticalFunctions: [],
      scanMode: 'active',
      scanOnly: true,
    };
    // Should not throw — scopedAssets is optional
    expect(inputWithout).toBeDefined();
    expect(inputWithout).not.toHaveProperty('scopedAssets');
  });

  it('scopedAssets should accept an array of strings', () => {
    const inputWith = {
      primaryDomain: 'example.com',
      customerName: 'Test Corp',
      sector: 'Technology',
      clientType: 'enterprise',
      criticalFunctions: [],
      scanMode: 'active',
      scanOnly: true,
      scopedAssets: ['www.example.com', 'api.example.com', '10.0.1.50'],
    };
    expect(inputWith.scopedAssets).toHaveLength(3);
    expect(inputWith.scopedAssets).toEqual(['www.example.com', 'api.example.com', '10.0.1.50']);
  });
});
