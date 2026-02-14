import { describe, it, expect } from 'vitest';

// Test the exclusion reason categories
const EXCLUSION_REASONS = [
  { value: 'wrong_company', label: 'Wrong Company/Org' },
  { value: 'outdated', label: 'Outdated / Decommissioned' },
  { value: 'duplicate', label: 'Duplicate Entry' },
  { value: 'irrelevant', label: 'Not Relevant' },
  { value: 'false_positive', label: 'False Positive' },
  { value: 'custom', label: 'Other Reason' },
];

// Test asset filtering logic
function filterAssets(assets: any[], opts: {
  showExcluded: boolean;
  searchQuery?: string;
  riskFilter?: string;
  typeFilter?: string;
  confidenceFilter?: string;
}) {
  return assets.filter((a) => {
    if (!opts.showExcluded && a.excluded) return false;
    if (opts.showExcluded && !a.excluded) return false;

    if (opts.searchQuery) {
      const q = opts.searchQuery.toLowerCase();
      const matchesSearch =
        a.hostname?.toLowerCase().includes(q) ||
        a.url?.toLowerCase().includes(q) ||
        a.assetType?.toLowerCase().includes(q) ||
        (a.technologies || []).some((t: string) => t.toLowerCase().includes(q)) ||
        (a.tags || []).some((t: string) => t.toLowerCase().includes(q));
      if (!matchesSearch) return false;
    }

    if (opts.riskFilter && opts.riskFilter !== 'all' && a.riskBand !== opts.riskFilter) return false;
    if (opts.typeFilter && opts.typeFilter !== 'all' && a.assetType !== opts.typeFilter) return false;

    if (opts.confidenceFilter && opts.confidenceFilter !== 'all') {
      const conf = a.confidence || 0;
      if (opts.confidenceFilter === 'high' && conf < 80) return false;
      if (opts.confidenceFilter === 'medium' && (conf < 50 || conf >= 80)) return false;
      if (opts.confidenceFilter === 'low' && conf >= 50) return false;
    }

    return true;
  });
}

// Compute stats
function computeStats(assets: any[]) {
  const included = assets.filter((a) => !a.excluded);
  const excluded = assets.filter((a) => a.excluded);
  return {
    total: assets.length,
    included: included.length,
    excluded: excluded.length,
    critical: included.filter((a) => a.riskBand === 'critical').length,
    high: included.filter((a) => a.riskBand === 'high').length,
    medium: included.filter((a) => a.riskBand === 'medium').length,
    low: included.filter((a) => a.riskBand === 'low').length,
  };
}

const SAMPLE_ASSETS = [
  { id: 1, hostname: 'mail.acme.com', url: 'https://mail.acme.com', assetType: 'mail_gateway', riskBand: 'critical', confidence: 92, excluded: false, technologies: ['Exchange', 'IIS'], tags: ['email'] },
  { id: 2, hostname: 'sso.acme.com', url: 'https://sso.acme.com', assetType: 'sso', riskBand: 'high', confidence: 85, excluded: false, technologies: ['Okta'], tags: ['auth'] },
  { id: 3, hostname: 'cdn.othercorp.com', url: 'https://cdn.othercorp.com', assetType: 'cdn', riskBand: 'low', confidence: 30, excluded: true, exclusionReason: 'Wrong Company/Org', technologies: ['Cloudflare'], tags: [] },
  { id: 4, hostname: 'api.acme.com', url: 'https://api.acme.com', assetType: 'api', riskBand: 'medium', confidence: 70, excluded: false, technologies: ['Node.js', 'Express'], tags: ['api'] },
  { id: 5, hostname: 'old.acme.com', url: 'https://old.acme.com', assetType: 'web', riskBand: 'low', confidence: 45, excluded: true, exclusionReason: 'Outdated / Decommissioned', technologies: ['Apache'], tags: [] },
  { id: 6, hostname: 'payment.acme.com', url: 'https://payment.acme.com', assetType: 'payment', riskBand: 'critical', confidence: 95, excluded: false, technologies: ['Stripe'], tags: ['payment'] },
];

describe('Discovery Curation - Exclusion Reasons', () => {
  it('should have 6 predefined exclusion reasons', () => {
    expect(EXCLUSION_REASONS).toHaveLength(6);
  });

  it('should include wrong_company as a reason', () => {
    expect(EXCLUSION_REASONS.find(r => r.value === 'wrong_company')).toBeDefined();
  });

  it('should include custom as a reason for freeform input', () => {
    expect(EXCLUSION_REASONS.find(r => r.value === 'custom')).toBeDefined();
  });
});

describe('Discovery Curation - Asset Filtering', () => {
  it('should show only included assets by default', () => {
    const result = filterAssets(SAMPLE_ASSETS, { showExcluded: false });
    expect(result).toHaveLength(4);
    expect(result.every(a => !a.excluded)).toBe(true);
  });

  it('should show only excluded assets when showExcluded is true', () => {
    const result = filterAssets(SAMPLE_ASSETS, { showExcluded: true });
    expect(result).toHaveLength(2);
    expect(result.every(a => a.excluded)).toBe(true);
  });

  it('should filter by search query on hostname', () => {
    const result = filterAssets(SAMPLE_ASSETS, { showExcluded: false, searchQuery: 'mail' });
    expect(result).toHaveLength(1);
    expect(result[0].hostname).toBe('mail.acme.com');
  });

  it('should filter by search query on technology', () => {
    const result = filterAssets(SAMPLE_ASSETS, { showExcluded: false, searchQuery: 'okta' });
    expect(result).toHaveLength(1);
    expect(result[0].hostname).toBe('sso.acme.com');
  });

  it('should filter by search query on tag', () => {
    const result = filterAssets(SAMPLE_ASSETS, { showExcluded: false, searchQuery: 'payment' });
    expect(result).toHaveLength(1);
    expect(result[0].hostname).toBe('payment.acme.com');
  });

  it('should filter by risk band', () => {
    const result = filterAssets(SAMPLE_ASSETS, { showExcluded: false, riskFilter: 'critical' });
    expect(result).toHaveLength(2);
    expect(result.every(a => a.riskBand === 'critical')).toBe(true);
  });

  it('should filter by asset type', () => {
    const result = filterAssets(SAMPLE_ASSETS, { showExcluded: false, typeFilter: 'api' });
    expect(result).toHaveLength(1);
    expect(result[0].assetType).toBe('api');
  });

  it('should filter by high confidence', () => {
    const result = filterAssets(SAMPLE_ASSETS, { showExcluded: false, confidenceFilter: 'high' });
    expect(result).toHaveLength(3);
    expect(result.every(a => a.confidence >= 80)).toBe(true);
  });

  it('should filter by medium confidence', () => {
    const result = filterAssets(SAMPLE_ASSETS, { showExcluded: false, confidenceFilter: 'medium' });
    expect(result).toHaveLength(1);
    expect(result[0].confidence).toBe(70);
  });

  it('should filter by low confidence (none in included)', () => {
    const result = filterAssets(SAMPLE_ASSETS, { showExcluded: false, confidenceFilter: 'low' });
    expect(result).toHaveLength(0);
  });

  it('should combine search and risk filter', () => {
    const result = filterAssets(SAMPLE_ASSETS, { showExcluded: false, searchQuery: 'acme', riskFilter: 'critical' });
    expect(result).toHaveLength(2);
  });

  it('should return empty when no match', () => {
    const result = filterAssets(SAMPLE_ASSETS, { showExcluded: false, searchQuery: 'nonexistent' });
    expect(result).toHaveLength(0);
  });

  it('should search excluded assets when showExcluded is true', () => {
    const result = filterAssets(SAMPLE_ASSETS, { showExcluded: true, searchQuery: 'othercorp' });
    expect(result).toHaveLength(1);
    expect(result[0].hostname).toBe('cdn.othercorp.com');
  });
});

describe('Discovery Curation - Stats Computation', () => {
  it('should compute correct totals', () => {
    const stats = computeStats(SAMPLE_ASSETS);
    expect(stats.total).toBe(6);
    expect(stats.included).toBe(4);
    expect(stats.excluded).toBe(2);
  });

  it('should compute correct risk distribution for included only', () => {
    const stats = computeStats(SAMPLE_ASSETS);
    expect(stats.critical).toBe(2);
    expect(stats.high).toBe(1);
    expect(stats.medium).toBe(1);
    expect(stats.low).toBe(0); // the only low one is excluded
  });

  it('should handle all excluded', () => {
    const allExcluded = SAMPLE_ASSETS.map(a => ({ ...a, excluded: true }));
    const stats = computeStats(allExcluded);
    expect(stats.included).toBe(0);
    expect(stats.excluded).toBe(6);
    expect(stats.critical).toBe(0);
  });

  it('should handle all included', () => {
    const allIncluded = SAMPLE_ASSETS.map(a => ({ ...a, excluded: false }));
    const stats = computeStats(allIncluded);
    expect(stats.included).toBe(6);
    expect(stats.excluded).toBe(0);
  });

  it('should handle empty assets', () => {
    const stats = computeStats([]);
    expect(stats.total).toBe(0);
    expect(stats.included).toBe(0);
    expect(stats.excluded).toBe(0);
  });
});

describe('Discovery Curation - Selection Logic', () => {
  it('should toggle selection on and off', () => {
    const selected = new Set<number>();
    // Toggle on
    selected.add(1);
    expect(selected.has(1)).toBe(true);
    // Toggle off
    selected.delete(1);
    expect(selected.has(1)).toBe(false);
  });

  it('should select all filtered assets', () => {
    const filtered = filterAssets(SAMPLE_ASSETS, { showExcluded: false });
    const selected = new Set(filtered.map(a => a.id));
    expect(selected.size).toBe(4);
  });

  it('should clear selection', () => {
    const selected = new Set([1, 2, 3]);
    selected.clear();
    expect(selected.size).toBe(0);
  });
});
