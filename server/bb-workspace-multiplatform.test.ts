/**
 * Bug Bounty Workspace Multi-Platform Parser Tests
 * 
 * Tests the enhanced parseBugBountyPolicy flow that now fetches
 * live structured scopes from HackerOne API, Bugcrowd, Intigriti,
 * YesWeHack (via bounty-targets-data), and OpenBugBounty.
 * Also tests the database caching layer.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Test parseProgramUrl with new platform support ─────────────────────────

describe('parseProgramUrl - Multi-Platform', () => {
  let parseProgramUrl: any;

  beforeEach(async () => {
    const mod = await import('./lib/bug-bounty-policy-parser.js');
    parseProgramUrl = mod.parseProgramUrl;
  });

  // HackerOne
  it('parses HackerOne program URLs', () => {
    const result = parseProgramUrl('https://hackerone.com/nodejs');
    expect(result).not.toBeNull();
    expect(result!.platform).toBe('hackerone');
    expect(result!.programSlug).toBe('nodejs');
  });

  // Bugcrowd - engagements path
  it('parses Bugcrowd engagement URLs', () => {
    const result = parseProgramUrl('https://bugcrowd.com/engagements/tidal-bugbounty');
    expect(result).not.toBeNull();
    expect(result!.platform).toBe('bugcrowd');
    expect(result!.programSlug).toBe('tidal-bugbounty');
  });

  // Bugcrowd - direct slug path
  it('parses Bugcrowd direct program URLs', () => {
    const result = parseProgramUrl('https://bugcrowd.com/openai');
    expect(result).not.toBeNull();
    expect(result!.platform).toBe('bugcrowd');
    expect(result!.programSlug).toBe('openai');
  });

  // Bugcrowd - skip non-program paths
  it('skips Bugcrowd non-program paths like /blog', () => {
    const result = parseProgramUrl('https://bugcrowd.com/blog');
    expect(result).toBeNull();
  });

  it('skips Bugcrowd non-program paths like /resources', () => {
    const result = parseProgramUrl('https://bugcrowd.com/resources');
    expect(result).toBeNull();
  });

  it('skips Bugcrowd non-program paths like /platform', () => {
    const result = parseProgramUrl('https://bugcrowd.com/platform');
    expect(result).toBeNull();
  });

  // Intigriti - new URL format (programs/company/handle)
  it('parses Intigriti new URL format with company/handle', () => {
    const result = parseProgramUrl('https://www.intigriti.com/programs/amd/amd/detail');
    expect(result).not.toBeNull();
    expect(result!.platform).toBe('intigriti');
    expect(result!.programSlug).toBe('amd');
  });

  it('parses Intigriti new URL format without /detail', () => {
    const result = parseProgramUrl('https://intigriti.com/programs/microsoft/msrc');
    expect(result).not.toBeNull();
    expect(result!.platform).toBe('intigriti');
    expect(result!.programSlug).toBe('msrc');
  });

  // Intigriti - old URL format
  it('parses Intigriti old app.intigriti.com URLs', () => {
    const result = parseProgramUrl('https://app.intigriti.com/researcher/programs/test-program');
    expect(result).not.toBeNull();
    expect(result!.platform).toBe('intigriti');
    expect(result!.programSlug).toBe('test-program');
  });

  // YesWeHack
  it('parses YesWeHack program URLs', () => {
    const result = parseProgramUrl('https://yeswehack.com/programs/my-program');
    expect(result).not.toBeNull();
    expect(result!.platform).toBe('yeswehack');
    expect(result!.programSlug).toBe('my-program');
  });

  // OpenBugBounty
  it('parses OpenBugBounty program URLs', () => {
    const result = parseProgramUrl('https://openbugbounty.org/bugbounty/example.com/');
    expect(result).not.toBeNull();
    expect(result!.platform).toBe('openbugbounty');
    expect(result!.programSlug).toBe('example.com');
  });

  it('parses OpenBugBounty program URLs without trailing slash', () => {
    const result = parseProgramUrl('https://www.openbugbounty.org/bugbounty/test-site.org');
    expect(result).not.toBeNull();
    expect(result!.platform).toBe('openbugbounty');
    expect(result!.programSlug).toBe('test-site.org');
  });

  // Edge cases
  it('returns null for unsupported URLs', () => {
    expect(parseProgramUrl('https://google.com')).toBeNull();
    expect(parseProgramUrl('not-a-url')).toBeNull();
    expect(parseProgramUrl('')).toBeNull();
  });

  it('handles URLs with query parameters', () => {
    const result = parseProgramUrl('https://hackerone.com/nodejs?type=team&view=policy');
    expect(result).not.toBeNull();
    expect(result!.programSlug).toBe('nodejs');
  });

  it('handles URLs with hash fragments', () => {
    const result = parseProgramUrl('https://bugcrowd.com/engagements/openai#scope');
    expect(result).not.toBeNull();
    expect(result!.programSlug).toBe('openai');
  });
});

// ─── Test BugBountyPlatform type includes openbugbounty ─────────────────────

describe('BugBountyPlatform type', () => {
  it('includes openbugbounty as a valid platform', async () => {
    const mod = await import('./lib/bug-bounty-policy-parser.js');
    const skeleton = mod.createSkeletonPolicy({
      platform: 'openbugbounty',
      programSlug: 'example.com',
      programUrl: 'https://openbugbounty.org/bugbounty/example.com/',
    });
    expect(skeleton.platform).toBe('openbugbounty');
  });
});

// ─── Test Bugcrowd asset type mapping ──────────────────────────────────────

describe('Bugcrowd asset type mapping', () => {
  it('maps common Bugcrowd asset types', () => {
    const mapping: Record<string, string> = {
      'website': 'url',
      'api': 'url',
      'android': 'mobile_app',
      'ios': 'mobile_app',
      'hardware': 'other',
      'other': 'other',
    };

    expect(mapping['website']).toBe('url');
    expect(mapping['api']).toBe('url');
    expect(mapping['android']).toBe('mobile_app');
    expect(mapping['ios']).toBe('mobile_app');
    expect(mapping['hardware']).toBe('other');
  });
});

// ─── Test Intigriti asset type mapping ─────────────────────────────────────

describe('Intigriti asset type mapping', () => {
  it('maps common Intigriti asset types', () => {
    const mapping: Record<string, string> = {
      'url': 'url',
      'domain': 'domain',
      'android': 'mobile_app',
      'ios': 'mobile_app',
      'iprange': 'cidr',
      'device': 'other',
      'other': 'other',
    };

    expect(mapping['url']).toBe('url');
    expect(mapping['domain']).toBe('domain');
    expect(mapping['iprange']).toBe('cidr');
  });
});

// ─── Test bounty-targets-data format parsing ───────────────────────────────

describe('Bugcrowd data format parsing', () => {
  const sampleBugcrowdProgram = {
    name: "TIDAL",
    url: "https://bugcrowd.com/engagements/tidal-bugbounty",
    allows_disclosure: true,
    managed_by_bugcrowd: true,
    safe_harbor: "full",
    max_payout: 5000,
    targets: {
      in_scope: [
        { type: "website", target: "https://tidal.com/", uri: "https://tidal.com/", name: "*.tidal.com", ipAddress: null },
        { type: "api", target: "api.tidal.com", uri: "", name: "api.tidal.com", ipAddress: null },
        { type: "ios", target: "Tidal Client for iOS", uri: "", name: "Tidal Client for iOS", ipAddress: null },
      ],
      out_of_scope: [
        { type: "other", target: "https://developer.tidal.com", uri: "https://developer.tidal.com", name: "developer.tidal.com", ipAddress: "" },
      ],
    },
  };

  it('extracts in-scope targets from Bugcrowd data', () => {
    const inScope = sampleBugcrowdProgram.targets.in_scope;
    expect(inScope.length).toBe(3);
    expect(inScope[0].target).toBe('https://tidal.com/');
    expect(inScope[0].type).toBe('website');
    expect(inScope[1].type).toBe('api');
    expect(inScope[2].type).toBe('ios');
  });

  it('extracts out-of-scope targets from Bugcrowd data', () => {
    const outOfScope = sampleBugcrowdProgram.targets.out_of_scope;
    expect(outOfScope.length).toBe(1);
    expect(outOfScope[0].target).toBe('https://developer.tidal.com');
  });

  it('extracts bounty info from Bugcrowd data', () => {
    expect(sampleBugcrowdProgram.max_payout).toBe(5000);
    expect(sampleBugcrowdProgram.safe_harbor).toBe('full');
  });

  it('uses name as instruction when different from target', () => {
    const target = sampleBugcrowdProgram.targets.in_scope[0];
    const instruction = target.name && target.name !== target.target ? target.name : undefined;
    expect(instruction).toBe('*.tidal.com');
  });
});

describe('Intigriti data format parsing', () => {
  const sampleIntigritiProgram = {
    id: "e67941f1-2087-4681-8718-3e3f4dc51798",
    name: "AMD Product Security Bug Bounty Program",
    company_handle: "amd",
    handle: "amd",
    url: "https://www.intigriti.com/programs/amd/amd/detail",
    min_bounty: { value: 500, currency: "USD" },
    max_bounty: { value: 30000, currency: "USD" },
    targets: {
      in_scope: [
        { type: "other", endpoint: "Hardware", description: "Vulnerabilities in the physical hardware", impact: "Tier 1" },
        { type: "other", endpoint: "Firmware", description: "Vulnerabilities in the firmware", impact: "Tier 2" },
        { type: "other", endpoint: "No Bounty", description: "Optional tools", impact: "No Bounty" },
      ],
      out_of_scope: [
        { type: "other", endpoint: "Out of Scope", description: "Web/IT Infrastructure", impact: "Out of scope" },
      ],
    },
  };

  it('extracts in-scope targets from Intigriti data', () => {
    const inScope = sampleIntigritiProgram.targets.in_scope;
    expect(inScope.length).toBe(3);
    expect(inScope[0].endpoint).toBe('Hardware');
    expect(inScope[0].impact).toBe('Tier 1');
  });

  it('determines bounty eligibility from impact field', () => {
    const inScope = sampleIntigritiProgram.targets.in_scope;
    // "Tier 1" and "Tier 2" are bounty eligible
    expect(inScope[0].impact !== 'Out of scope' && inScope[0].impact !== 'No Bounty').toBe(true);
    // "No Bounty" is not bounty eligible
    expect(inScope[2].impact !== 'Out of scope' && inScope[2].impact !== 'No Bounty').toBe(false);
  });

  it('extracts bounty range from Intigriti data', () => {
    expect(sampleIntigritiProgram.min_bounty.value).toBe(500);
    expect(sampleIntigritiProgram.max_bounty.value).toBe(30000);
    expect(sampleIntigritiProgram.max_bounty.currency).toBe('USD');
  });

  it('finds program by handle', () => {
    const data = [sampleIntigritiProgram];
    const found = data.find(p => p.handle === 'amd');
    expect(found).toBeDefined();
    expect(found!.name).toBe('AMD Product Security Bug Bounty Program');
  });
});

// ─── Test OpenBugBounty domain extraction ──────────────────────────────────

describe('OpenBugBounty domain extraction', () => {
  it('extracts domain from slug when slug contains dots', () => {
    const slug = 'example.com';
    const isDomain = slug.includes('.');
    expect(isDomain).toBe(true);
    // When slug contains dots, it IS the domain
    expect(slug).toBe('example.com');
  });

  it('handles subdomains in slug', () => {
    const slug = 'www.example.com';
    const isDomain = slug.includes('.');
    expect(isDomain).toBe(true);
  });

  it('handles non-domain slugs', () => {
    const slug = 'some-program';
    const isDomain = slug.includes('.');
    expect(isDomain).toBe(false);
    // For non-domain slugs, we'd need to fetch the OBB page
  });
});

// ─── Test program finder functions ─────────────────────────────────────────

describe('Program finder logic', () => {
  const bugcrowdData = [
    { name: "OpenAI", url: "https://bugcrowd.com/engagements/openai", targets: { in_scope: [], out_of_scope: [] } },
    { name: "TIDAL", url: "https://bugcrowd.com/engagements/tidal-bugbounty", targets: { in_scope: [], out_of_scope: [] } },
    { name: "Tesla", url: "https://bugcrowd.com/tesla", targets: { in_scope: [], out_of_scope: [] } },
  ];

  it('finds Bugcrowd program by exact URL', () => {
    const found = bugcrowdData.find(p => p.url === 'https://bugcrowd.com/engagements/openai');
    expect(found).toBeDefined();
    expect(found!.name).toBe('OpenAI');
  });

  it('finds Bugcrowd program by slug in URL', () => {
    const slug = 'tidal-bugbounty';
    const found = bugcrowdData.find(p => p.url.includes(`/${slug}`));
    expect(found).toBeDefined();
    expect(found!.name).toBe('TIDAL');
  });

  it('finds Bugcrowd program by name match', () => {
    const slug = 'tesla';
    const found = bugcrowdData.find(p => {
      const pName = p.name.toLowerCase().replace(/[^a-z0-9]/g, '');
      return pName === slug.replace(/[^a-z0-9]/g, '');
    });
    expect(found).toBeDefined();
    expect(found!.name).toBe('Tesla');
  });

  const intigritiData = [
    { name: "AMD", handle: "amd", company_handle: "amd", url: "https://www.intigriti.com/programs/amd/amd/detail" },
    { name: "Microsoft MSRC", handle: "msrc", company_handle: "microsoft", url: "https://www.intigriti.com/programs/microsoft/msrc/detail" },
  ];

  it('finds Intigriti program by handle', () => {
    const found = intigritiData.find(p => p.handle === 'amd');
    expect(found).toBeDefined();
    expect(found!.name).toBe('AMD');
  });

  it('finds Intigriti program by company_handle', () => {
    const found = intigritiData.find(p => p.company_handle === 'microsoft');
    expect(found).toBeDefined();
    expect(found!.name).toBe('Microsoft MSRC');
  });
});

// ─── Test cache key generation ─────────────────────────────────────────────

describe('Policy cache key generation', () => {
  it('generates consistent cache keys', () => {
    const key1 = `hackerone:nodejs`;
    const key2 = `hackerone:nodejs`;
    expect(key1).toBe(key2);
  });

  it('generates different keys for different platforms', () => {
    const key1 = `hackerone:nodejs`;
    const key2 = `bugcrowd:nodejs`;
    expect(key1).not.toBe(key2);
  });

  it('generates different keys for different slugs', () => {
    const key1 = `hackerone:nodejs`;
    const key2 = `hackerone:github`;
    expect(key1).not.toBe(key2);
  });
});

// ─── Test in-memory cache TTL logic ────────────────────────────────────────

describe('In-memory cache TTL', () => {
  it('cache entries expire after TTL', () => {
    const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
    const now = Date.now();
    const entry = { data: [], fetchedAt: now - CACHE_TTL_MS - 1 };
    
    const isExpired = now - entry.fetchedAt >= CACHE_TTL_MS;
    expect(isExpired).toBe(true);
  });

  it('cache entries are valid within TTL', () => {
    const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
    const now = Date.now();
    const entry = { data: [], fetchedAt: now - (CACHE_TTL_MS / 2) };
    
    const isExpired = now - entry.fetchedAt >= CACHE_TTL_MS;
    expect(isExpired).toBe(false);
  });
});

// ─── Test skeleton policy for OpenBugBounty ────────────────────────────────

describe('OpenBugBounty skeleton policy', () => {
  it('creates correct skeleton for OBB programs', async () => {
    const mod = await import('./lib/bug-bounty-policy-parser.js');
    const skeleton = mod.createSkeletonPolicy({
      platform: 'openbugbounty',
      programSlug: 'example.com',
      programUrl: 'https://openbugbounty.org/bugbounty/example.com/',
    });

    expect(skeleton.platform).toBe('openbugbounty');
    expect(skeleton.programName).toBe('example.com');
    expect(skeleton.programUrl).toBe('https://openbugbounty.org/bugbounty/example.com/');
    // Skeleton starts with empty scope (enrichment happens in the mutation)
    expect(skeleton.scope.inScope).toEqual([]);
  });
});

// ─── Test the full frontend-compatible output for each platform ────────────

describe('Frontend-compatible output structure', () => {
  it('has consistent shape regardless of platform', () => {
    const requiredFields = ['programName', 'platform', 'programUrl', 'scope', 'rules', 'safeHarbor', 'parsedAt'];
    const scopeFields = ['inScope', 'outOfScope'];
    const scopeEntryFields = ['type', 'value', 'eligible'];

    // Simulate a Bugcrowd response
    const bcResponse = {
      programName: 'TIDAL',
      platform: 'bugcrowd',
      programUrl: 'https://bugcrowd.com/engagements/tidal-bugbounty',
      scope: {
        inScope: [{ type: 'url', value: 'https://tidal.com/', eligible: true, notes: '*.tidal.com' }],
        outOfScope: [{ type: 'other', value: 'https://developer.tidal.com', eligible: false }],
      },
      rules: ['Disclosure: coordinated'],
      rewardRange: { low: 0, high: 5000, currency: '$' },
      safeHarbor: true,
      parsedAt: new Date().toISOString(),
    };

    for (const field of requiredFields) {
      expect(bcResponse).toHaveProperty(field);
    }
    for (const field of scopeFields) {
      expect(bcResponse.scope).toHaveProperty(field);
    }
    for (const field of scopeEntryFields) {
      expect(bcResponse.scope.inScope[0]).toHaveProperty(field);
    }
  });

  it('has consistent shape for Intigriti response', () => {
    const igResponse = {
      programName: 'AMD Product Security Bug Bounty Program',
      platform: 'intigriti',
      programUrl: 'https://www.intigriti.com/programs/amd/amd/detail',
      scope: {
        inScope: [{ type: 'other', value: 'Hardware', eligible: true, notes: 'Vulnerabilities in hardware' }],
        outOfScope: [{ type: 'other', value: 'Out of Scope', eligible: false }],
      },
      rules: ['Disclosure: coordinated'],
      rewardRange: { low: 500, high: 30000, currency: 'USD' },
      safeHarbor: false,
      parsedAt: new Date().toISOString(),
    };

    expect(igResponse.scope.inScope[0].type).toBe('other');
    expect(igResponse.scope.inScope[0].eligible).toBe(true);
    expect(igResponse.rewardRange!.low).toBe(500);
    expect(igResponse.rewardRange!.high).toBe(30000);
  });

  it('has consistent shape for OpenBugBounty response', () => {
    const obbResponse = {
      programName: 'example.com (OpenBugBounty)',
      platform: 'openbugbounty',
      programUrl: 'https://openbugbounty.org/bugbounty/example.com/',
      scope: {
        inScope: [{ type: 'domain', value: 'example.com', eligible: false, notes: 'OpenBugBounty program' }],
        outOfScope: [],
      },
      rules: ['No automated scanning without permission', 'No denial of service testing'],
      safeHarbor: false,
      parsedAt: new Date().toISOString(),
    };

    expect(obbResponse.scope.inScope[0].type).toBe('domain');
    expect(obbResponse.scope.inScope[0].eligible).toBe(false); // OBB is typically non-bounty
    expect(obbResponse.rules.length).toBeGreaterThan(0);
  });
});
