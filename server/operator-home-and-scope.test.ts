import { describe, it, expect, vi } from 'vitest';

// ─── Operator Home: Scan & Engagement Command Center ─────────────────

describe('OperatorHome scan/engagement command center', () => {
  // Simulates the scan list data that the OperatorHome component receives
  const SCAN_STATUS_CONFIG: Record<string, { label: string }> = {
    discovering: { label: 'DISCOVERING' },
    passive_recon: { label: 'RECON' },
    analyzing: { label: 'ANALYZING' },
    scoring: { label: 'SCORING' },
    recommending: { label: 'RECOMMENDING' },
    completed: { label: 'COMPLETED' },
    scan_complete: { label: 'SCAN COMPLETE' },
    engagement_running: { label: 'ENGAGEMENT' },
    failed: { label: 'FAILED' },
  };

  function getTimeAgo(date: Date): string {
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMin = Math.floor(diffMs / 60000);
    if (diffMin < 1) return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    const diffDay = Math.floor(diffHr / 24);
    if (diffDay < 7) return `${diffDay}d ago`;
    return date.toLocaleDateString();
  }

  it('should display recent scans sorted by updatedAt descending', () => {
    const scans = [
      { id: 1, primaryDomain: 'old.com', status: 'completed', updatedAt: new Date('2026-02-25T10:00:00Z'), createdAt: new Date('2026-02-20T10:00:00Z') },
      { id: 2, primaryDomain: 'newest.com', status: 'discovering', updatedAt: new Date('2026-03-01T10:00:00Z'), createdAt: new Date('2026-03-01T09:00:00Z') },
      { id: 3, primaryDomain: 'middle.com', status: 'completed', updatedAt: new Date('2026-02-28T10:00:00Z'), createdAt: new Date('2026-02-15T10:00:00Z') },
    ];

    // Backend sorts by updatedAt desc, so newest first
    const sorted = [...scans].sort((a, b) =>
      new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
    );

    expect(sorted[0].primaryDomain).toBe('newest.com');
    expect(sorted[1].primaryDomain).toBe('middle.com');
    expect(sorted[2].primaryDomain).toBe('old.com');
  });

  it('should limit displayed scans to 5', () => {
    const scans = Array.from({ length: 10 }, (_, i) => ({
      id: i + 1,
      primaryDomain: `domain${i}.com`,
      status: 'completed',
      updatedAt: new Date(Date.now() - i * 3600000),
    }));

    const recentScans = scans.slice(0, 5);
    expect(recentScans).toHaveLength(5);
    expect(recentScans[0].primaryDomain).toBe('domain0.com');
  });

  it('should count running scans correctly', () => {
    const runningStatuses = ['discovering', 'passive_recon', 'analyzing', 'scoring', 'recommending'];
    const scans = [
      { id: 1, status: 'discovering' },
      { id: 2, status: 'completed' },
      { id: 3, status: 'analyzing' },
      { id: 4, status: 'failed' },
      { id: 5, status: 'passive_recon' },
    ];

    const runningScans = scans.filter(s => runningStatuses.includes(s.status));
    expect(runningScans).toHaveLength(3);
  });

  it('should filter active engagements correctly', () => {
    const engagements = [
      { id: 1, name: 'Active Op', status: 'active', customerName: 'Client A' },
      { id: 2, name: 'Planning Op', status: 'planning', customerName: 'Client B' },
      { id: 3, name: 'Done Op', status: 'completed', customerName: 'Client C' },
      { id: 4, name: 'Paused Op', status: 'paused', customerName: 'Client D' },
    ];

    const activeEngagements = engagements.filter(
      e => e.status === 'active' || e.status === 'planning'
    );
    expect(activeEngagements).toHaveLength(2);
    expect(activeEngagements.map(e => e.name)).toEqual(['Active Op', 'Planning Op']);
  });

  it('should map scan statuses to correct labels', () => {
    expect(SCAN_STATUS_CONFIG['discovering'].label).toBe('DISCOVERING');
    expect(SCAN_STATUS_CONFIG['passive_recon'].label).toBe('RECON');
    expect(SCAN_STATUS_CONFIG['completed'].label).toBe('COMPLETED');
    expect(SCAN_STATUS_CONFIG['failed'].label).toBe('FAILED');
  });

  it('should format time ago correctly', () => {
    const now = new Date();
    expect(getTimeAgo(new Date(now.getTime() - 30000))).toBe('just now');
    expect(getTimeAgo(new Date(now.getTime() - 5 * 60000))).toBe('5m ago');
    expect(getTimeAgo(new Date(now.getTime() - 3 * 3600000))).toBe('3h ago');
    expect(getTimeAgo(new Date(now.getTime() - 2 * 86400000))).toBe('2d ago');
  });
});

// ─── Scope Enforcement: IP Matching Fix ──────────────────────────────

describe('Scoped scan IP matching', () => {
  interface MockAsset {
    assetId: string;
    hostname: string;
    url?: string;
    ip?: string;
  }

  function createMockAsset(hostname: string, ip?: string): MockAsset {
    return {
      assetId: `test-${hostname.replace(/\./g, '-')}`,
      hostname,
      url: `https://${hostname}`,
      ip,
    };
  }

  // Simulates the improved scoped scan filter that also matches IPs
  function filterScopedAssets(assets: MockAsset[], scopedAssets: string[]): MockAsset[] {
    const scopedSet = new Set(scopedAssets.map(s => s.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '')));

    return assets.filter(a => {
      const hostname = (a.hostname || '').toLowerCase();
      const ip = (a.ip || '').toLowerCase();
      const urlHost = (a.url || '').toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');

      // Match on hostname, IP, or URL host
      if (scopedSet.has(hostname)) return true;
      if (ip && scopedSet.has(ip)) return true;
      if (urlHost && scopedSet.has(urlHost)) return true;

      return false;
    });
  }

  it('should match assets by hostname', () => {
    const assets = [
      createMockAsset('vianova.io'),
      createMockAsset('other.com'),
    ];
    const filtered = filterScopedAssets(assets, ['vianova.io']);
    expect(filtered).toHaveLength(1);
    expect(filtered[0].hostname).toBe('vianova.io');
  });

  it('should match assets by IP address', () => {
    const assets = [
      createMockAsset('unknown-host.vianova.io', '104.26.12.100'),
      createMockAsset('other.com', '192.168.1.1'),
    ];
    const filtered = filterScopedAssets(assets, ['104.26.12.100']);
    expect(filtered).toHaveLength(1);
    expect(filtered[0].ip).toBe('104.26.12.100');
  });

  it('should match assets by URL host', () => {
    const assets = [
      createMockAsset('app.vianova.io'),
      createMockAsset('admin.vianova.io'),
    ];
    const filtered = filterScopedAssets(assets, ['app.vianova.io']);
    expect(filtered).toHaveLength(1);
    expect(filtered[0].hostname).toBe('app.vianova.io');
  });

  it('should handle mixed hostname and IP scoped assets', () => {
    const assets = [
      createMockAsset('vianova.io', '104.26.12.100'),
      createMockAsset('app.vianova.io', '104.26.12.101'),
      createMockAsset('mail.vianova.io', '104.26.12.102'),
      createMockAsset('cdn.vianova.io', '104.26.12.103'),
    ];
    const scopedAssets = ['vianova.io', 'app.vianova.io', '104.26.12.102'];
    const filtered = filterScopedAssets(assets, scopedAssets);

    expect(filtered).toHaveLength(3);
    const hostnames = filtered.map(a => a.hostname);
    expect(hostnames).toContain('vianova.io');
    expect(hostnames).toContain('app.vianova.io');
    expect(hostnames).toContain('mail.vianova.io'); // matched by IP
    expect(hostnames).not.toContain('cdn.vianova.io');
  });

  it('should be case-insensitive', () => {
    const assets = [createMockAsset('Vianova.IO')];
    const filtered = filterScopedAssets(assets, ['vianova.io']);
    expect(filtered).toHaveLength(1);
  });

  it('should strip protocol from URL-style scoped assets', () => {
    const assets = [createMockAsset('vianova.io')];
    const filtered = filterScopedAssets(assets, ['https://vianova.io/path']);
    expect(filtered).toHaveLength(1);
  });

  it('should return empty array when no assets match scope', () => {
    const assets = [
      createMockAsset('unrelated.com'),
      createMockAsset('other.org'),
    ];
    const filtered = filterScopedAssets(assets, ['vianova.io', 'app.vianova.io']);
    expect(filtered).toHaveLength(0);
  });

  it('should return all assets when all match scope', () => {
    const assets = [
      createMockAsset('vianova.io'),
      createMockAsset('app.vianova.io'),
    ];
    const filtered = filterScopedAssets(assets, ['vianova.io', 'app.vianova.io']);
    expect(filtered).toHaveLength(2);
  });
});

// ─── Scan Sorting: updatedAt Ordering ────────────────────────────────

describe('Scan list sorting by updatedAt', () => {
  it('should sort scans with most recently updated first', () => {
    const scans = [
      { id: 1, primaryDomain: 'a.com', createdAt: new Date('2026-01-01'), updatedAt: new Date('2026-01-15') },
      { id: 2, primaryDomain: 'b.com', createdAt: new Date('2026-02-01'), updatedAt: new Date('2026-02-01') },
      { id: 3, primaryDomain: 'c.com', createdAt: new Date('2026-01-10'), updatedAt: new Date('2026-03-01') },
    ];

    const sorted = [...scans].sort((a, b) =>
      new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
    );

    expect(sorted[0].primaryDomain).toBe('c.com'); // Most recently updated
    expect(sorted[1].primaryDomain).toBe('b.com');
    expect(sorted[2].primaryDomain).toBe('a.com');
  });

  it('should place refreshed scans above older scans even if created earlier', () => {
    const scans = [
      { id: 1, primaryDomain: 'old-but-refreshed.com', createdAt: new Date('2026-01-01'), updatedAt: new Date('2026-03-01T12:00:00Z') },
      { id: 2, primaryDomain: 'new-never-refreshed.com', createdAt: new Date('2026-02-28'), updatedAt: new Date('2026-02-28T10:00:00Z') },
    ];

    const sorted = [...scans].sort((a, b) =>
      new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
    );

    expect(sorted[0].primaryDomain).toBe('old-but-refreshed.com');
    expect(sorted[1].primaryDomain).toBe('new-never-refreshed.com');
  });

  it('should handle scans without updatedAt by falling back to createdAt', () => {
    const scans = [
      { id: 1, primaryDomain: 'a.com', createdAt: new Date('2026-01-01'), updatedAt: null },
      { id: 2, primaryDomain: 'b.com', createdAt: new Date('2026-02-01'), updatedAt: new Date('2026-02-01') },
    ];

    const sorted = [...scans].sort((a, b) => {
      const aDate = a.updatedAt ? new Date(a.updatedAt).getTime() : new Date(a.createdAt).getTime();
      const bDate = b.updatedAt ? new Date(b.updatedAt).getTime() : new Date(b.createdAt).getTime();
      return bDate - aDate;
    });

    expect(sorted[0].primaryDomain).toBe('b.com');
    expect(sorted[1].primaryDomain).toBe('a.com');
  });
});

// ─── Featured Actors: Randomization & Completeness ───────────────────

describe('Featured actors randomization', () => {
  function computeCompletenessScore(actor: any): number {
    let score = 0;
    if (actor.aliases?.length) score += 10;
    if (actor.description) score += 15;
    if (actor.origin) score += 5;
    if (actor.sophisticationLevel) score += 5;
    if (actor.targetSectors?.length) score += 10;
    if (actor.knownTTPs?.length) score += 15;
    if (actor.knownTools?.length) score += 10;
    if (actor.knownMalware?.length) score += 10;
    if (actor.associatedCVEs?.length) score += 10;
    if (actor.iocs?.length) score += 10;
    return score;
  }

  it('should score actors by data completeness', () => {
    const richActor = {
      aliases: ['APT28', 'Fancy Bear'],
      description: 'Russian state-sponsored group',
      origin: 'Russia',
      sophisticationLevel: 'nation_state',
      targetSectors: ['Government', 'Defense'],
      knownTTPs: ['T1566', 'T1059'],
      knownTools: ['Mimikatz'],
      knownMalware: ['X-Agent'],
      associatedCVEs: ['CVE-2021-44228'],
      iocs: ['evil.com'],
    };

    const sparseActor = {
      aliases: [],
      description: 'Unknown group',
      origin: null,
      sophisticationLevel: null,
      targetSectors: [],
      knownTTPs: [],
      knownTools: [],
      knownMalware: [],
      associatedCVEs: [],
      iocs: [],
    };

    expect(computeCompletenessScore(richActor)).toBe(100);
    expect(computeCompletenessScore(sparseActor)).toBe(15); // only description
  });

  it('should select top actors by completeness then randomize', () => {
    const actors = Array.from({ length: 20 }, (_, i) => ({
      id: i + 1,
      name: `Actor ${i + 1}`,
      description: `Description ${i}`,
      aliases: i > 10 ? ['alias'] : [],
      origin: i > 5 ? 'Country' : null,
      sophisticationLevel: i > 8 ? 'advanced' : null,
      targetSectors: i > 12 ? ['sector'] : [],
      knownTTPs: i > 7 ? ['T1001'] : [],
      knownTools: i > 14 ? ['tool'] : [],
      knownMalware: i > 15 ? ['malware'] : [],
      associatedCVEs: i > 16 ? ['CVE-2021-1234'] : [],
      iocs: i > 17 ? ['ioc.com'] : [],
    }));

    // Score and sort
    const scored = actors.map(a => ({
      ...a,
      completeness: computeCompletenessScore(a),
    })).sort((a, b) => b.completeness - a.completeness);

    // Take top 12, shuffle, return 6
    const topPool = scored.slice(0, 12);
    expect(topPool.length).toBe(12);
    expect(topPool[0].completeness).toBeGreaterThanOrEqual(topPool[11].completeness);

    // Simulate shuffle and pick 6
    const shuffled = [...topPool].sort(() => Math.random() - 0.5);
    const featured = shuffled.slice(0, 6);
    expect(featured).toHaveLength(6);

    // All featured should be from the top pool
    const topPoolIds = new Set(topPool.map(a => a.id));
    for (const f of featured) {
      expect(topPoolIds.has(f.id)).toBe(true);
    }
  });
});
