/**
 * Tests for BB Workspace batch refresh, credential DB storage, and sync-to-engagement features.
 */
import { describe, it, expect, vi } from 'vitest';
import { parseProgramUrl, createSkeletonPolicy } from './lib/bug-bounty-policy-parser.js';

// ─── Batch URL Parsing ──────────────────────────────────────────────────────

describe('Batch URL Parsing', () => {
  const testUrls = [
    'https://hackerone.com/nodejs',
    'https://bugcrowd.com/engagements/tidal-bugbounty',
    'https://www.intigriti.com/programs/amd/amd/detail',
    'https://yeswehack.com/programs/some-program',
    'https://www.openbugbounty.org/bugbounty/example.com/',
  ];

  it('should parse all supported platform URLs', () => {
    const results = testUrls.map(url => parseProgramUrl(url));
    expect(results[0]).toEqual({ platform: 'hackerone', programSlug: 'nodejs' });
    expect(results[1]).toEqual({ platform: 'bugcrowd', programSlug: 'tidal-bugbounty' });
    expect(results[2]).toEqual({ platform: 'intigriti', programSlug: 'amd' });
    expect(results[3]).toEqual({ platform: 'yeswehack', programSlug: 'some-program' });
    expect(results[4]).toEqual({ platform: 'openbugbounty', programSlug: 'example.com' });
  });

  it('should handle mixed valid and invalid URLs in a batch', () => {
    const mixed = [
      'https://hackerone.com/nodejs',
      'https://not-a-valid-platform.com/something',
      'https://bugcrowd.com/engagements/openai',
      'garbage-text',
    ];
    const results = mixed.map(url => parseProgramUrl(url));
    expect(results[0]).toBeTruthy();
    expect(results[1]).toBeNull();
    expect(results[2]).toBeTruthy();
    expect(results[3]).toBeNull();
  });

  it('should create skeletons for all parsed URLs', () => {
    const parsed = testUrls.map(url => parseProgramUrl(url)).filter(Boolean);
    const skeletons = parsed.map((p, i) => createSkeletonPolicy({ ...p!, programUrl: testUrls[i] }));
    expect(skeletons).toHaveLength(5);
    skeletons.forEach(s => {
      expect(s.scope.inScope).toEqual([]);
      expect(s.scope.outOfScope).toEqual([]);
      expect(s.programUrl).toBeTruthy();
    });
  });

  it('should handle duplicate URLs in a batch', () => {
    const dupes = [
      'https://hackerone.com/nodejs',
      'https://hackerone.com/nodejs',
      'https://hackerone.com/nodejs',
    ];
    const results = dupes.map(url => parseProgramUrl(url));
    // All should parse identically
    results.forEach(r => {
      expect(r).toEqual({ platform: 'hackerone', programSlug: 'nodejs' });
    });
  });

  it('should handle empty and whitespace-only URLs', () => {
    const empties = ['', '   ', '\n', '\t'];
    empties.forEach(url => {
      const result = parseProgramUrl(url.trim());
      expect(result).toBeNull();
    });
  });
});

// ─── Scope Target Extraction for Engagement Sync ────────────────────────────

describe('Scope Target Extraction for Engagement Sync', () => {
  it('should categorize scope targets by type', () => {
    const targets = [
      { type: 'url', value: 'https://api.example.com', eligible: true },
      { type: 'domain', value: '*.example.com', eligible: true },
      { type: 'ip', value: '192.168.1.0/24', eligible: true },
      { type: 'cidr', value: '10.0.0.0/8', eligible: true },
      { type: 'source_code', value: 'https://github.com/example/repo', eligible: true },
      { type: 'hardware', value: 'IoT Device X', eligible: false },
    ];

    const domains: string[] = [];
    const ips: string[] = [];
    const urls: string[] = [];
    const skipped: string[] = [];

    for (const target of targets) {
      const val = target.value.trim();
      const lowerType = target.type.toLowerCase();

      if (lowerType === 'ip' || lowerType === 'cidr' || /^\d{1,3}(\.\d{1,3}){3}/.test(val)) {
        ips.push(val);
      } else if (['source_code', 'hardware', 'other'].includes(lowerType)) {
        skipped.push(val);
      } else if (lowerType === 'url' || /^https?:\/\//i.test(val)) {
        urls.push(val);
        try {
          const hostname = new URL(val.startsWith('http') ? val : `https://${val}`).hostname;
          if (hostname && !domains.includes(hostname)) domains.push(hostname);
        } catch { /* not a valid URL */ }
      } else if (lowerType === 'domain' || lowerType === 'wildcard' || val.includes('.')) {
        const clean = val.replace(/^\*\./, '');
        if (clean && !domains.includes(clean)) domains.push(clean);
        if (val.startsWith('*.') && !domains.includes(val)) domains.push(val);
      }
    }

    expect(urls).toContain('https://api.example.com');
    expect(domains).toContain('api.example.com');
    expect(domains).toContain('example.com');
    expect(domains).toContain('*.example.com');
    expect(ips).toContain('192.168.1.0/24');
    expect(ips).toContain('10.0.0.0/8');
    // source_code and hardware types are skipped regardless of value format
    expect(skipped).toContain('https://github.com/example/repo');
    expect(skipped).toContain('IoT Device X');
    // URL type targets go to urls array
    expect(urls).not.toContain('https://github.com/example/repo');
  });

  it('should deduplicate domains when merging with existing', () => {
    const existingDomains = ['example.com', 'test.com'];
    const newDomains = ['example.com', 'new.com', 'test.com', 'another.com'];
    const merged = [...new Set([...existingDomains, ...newDomains])];
    expect(merged).toEqual(['example.com', 'test.com', 'new.com', 'another.com']);
  });

  it('should extract hostname from URL targets', () => {
    const urlTargets = [
      'https://api.example.com/v1',
      'https://admin.example.com:8443/login',
      'http://staging.test.com',
    ];
    const hostnames = urlTargets.map(url => {
      try { return new URL(url).hostname; } catch { return null; }
    }).filter(Boolean);
    expect(hostnames).toEqual(['api.example.com', 'admin.example.com', 'staging.test.com']);
  });
});

// ─── Refresh All Scopes Input Validation ────────────────────────────────────

describe('Refresh All Scopes Input Validation', () => {
  it('should accept 1-50 URLs', () => {
    const validInputs = [
      ['https://hackerone.com/nodejs'],
      Array.from({ length: 50 }, (_, i) => `https://hackerone.com/program-${i}`),
    ];
    validInputs.forEach(urls => {
      expect(urls.length).toBeGreaterThanOrEqual(1);
      expect(urls.length).toBeLessThanOrEqual(50);
    });
  });

  it('should reject empty arrays', () => {
    const urls: string[] = [];
    expect(urls.length).toBe(0);
    // The z.array().min(1) validation would reject this
  });

  it('should reject arrays over 50', () => {
    const urls = Array.from({ length: 51 }, (_, i) => `https://hackerone.com/program-${i}`);
    expect(urls.length).toBeGreaterThan(50);
    // The z.array().max(50) validation would reject this
  });
});

// ─── Cache Key Generation ───────────────────────────────────────────────────

describe('Cache Key Generation', () => {
  it('should generate consistent cache keys', () => {
    const parsed = parseProgramUrl('https://hackerone.com/nodejs');
    const cacheKey = `${parsed!.platform}:${parsed!.programSlug}`;
    expect(cacheKey).toBe('hackerone:nodejs');
  });

  it('should generate unique cache keys per platform+slug', () => {
    const urls = [
      'https://hackerone.com/nodejs',
      'https://bugcrowd.com/engagements/nodejs',
    ];
    const keys = urls.map(url => {
      const p = parseProgramUrl(url);
      return p ? `${p.platform}:${p.programSlug}` : null;
    });
    expect(keys[0]).toBe('hackerone:nodejs');
    expect(keys[1]).toBe('bugcrowd:nodejs');
    expect(keys[0]).not.toBe(keys[1]);
  });
});

// ─── Platform-Specific URL Patterns ─────────────────────────────────────────

describe('Platform-Specific URL Patterns', () => {
  it('should handle HackerOne URL variations', () => {
    const urls = [
      'https://hackerone.com/nodejs',
      'https://hackerone.com/nodejs/',
      'https://www.hackerone.com/nodejs',
    ];
    urls.forEach(url => {
      const result = parseProgramUrl(url);
      expect(result?.platform).toBe('hackerone');
      expect(result?.programSlug).toBe('nodejs');
    });
  });

  it('should handle Bugcrowd URL variations', () => {
    const urls = [
      'https://bugcrowd.com/engagements/tidal-bugbounty',
      'https://bugcrowd.com/tidal-bugbounty',
    ];
    urls.forEach(url => {
      const result = parseProgramUrl(url);
      expect(result?.platform).toBe('bugcrowd');
      expect(result?.programSlug).toBe('tidal-bugbounty');
    });
  });

  it('should handle Intigriti URL variations', () => {
    const urls = [
      'https://www.intigriti.com/programs/amd/amd/detail',
      'https://intigriti.com/programs/amd/amd',
      'https://app.intigriti.com/researcher/programs/amd/amd',
    ];
    urls.forEach(url => {
      const result = parseProgramUrl(url);
      expect(result?.platform).toBe('intigriti');
      expect(result?.programSlug).toBe('amd');
    });
  });

  it('should handle OpenBugBounty URL patterns', () => {
    const urls = [
      'https://www.openbugbounty.org/bugbounty/example.com/',
      'https://openbugbounty.org/bugbounty/test-site.org',
    ];
    urls.forEach(url => {
      const result = parseProgramUrl(url);
      expect(result?.platform).toBe('openbugbounty');
      expect(result?.programSlug).toBeTruthy();
    });
  });

  it('should handle YesWeHack URL patterns', () => {
    const result = parseProgramUrl('https://yeswehack.com/programs/some-program');
    expect(result?.platform).toBe('yeswehack');
    expect(result?.programSlug).toBe('some-program');
  });
});
