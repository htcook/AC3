import { describe, it, expect, vi, beforeAll } from 'vitest';

/**
 * Tests for the 0-day vulnerability feed widget
 * Validates the data endpoints that power the ZeroDayFeed component
 */

describe('VulnFeedStats structure', () => {
  it('returns expected stat fields', async () => {
    const { getVulnFeedStats } = await import('./lib/vuln-feeds');
    const stats = await getVulnFeedStats();

    expect(stats).toHaveProperty('totalEntries');
    expect(stats).toHaveProperty('bySource');
    expect(stats).toHaveProperty('bySeverity');
    expect(stats).toHaveProperty('exploitAvailableCount');
    expect(stats).toHaveProperty('inTheWildCount');
    expect(stats).toHaveProperty('kevListedCount');
    expect(stats).toHaveProperty('ransomwareLinkedCount');
    expect(stats).toHaveProperty('lastUpdated');
    expect(stats).toHaveProperty('feedHealth');

    // Validate types
    expect(typeof stats.totalEntries).toBe('number');
    expect(typeof stats.exploitAvailableCount).toBe('number');
    expect(typeof stats.inTheWildCount).toBe('number');
    expect(typeof stats.kevListedCount).toBe('number');

    // bySource should have all feed sources
    expect(stats.bySource).toHaveProperty('cisa_kev');
    expect(stats.bySource).toHaveProperty('project_zero');
    expect(stats.bySource).toHaveProperty('nvd');
    expect(stats.bySource).toHaveProperty('circl');
    expect(stats.bySource).toHaveProperty('exploit_db');

    // bySeverity should have standard levels
    expect(stats.bySeverity).toHaveProperty('critical');
    expect(stats.bySeverity).toHaveProperty('high');
    expect(stats.bySeverity).toHaveProperty('medium');
    expect(stats.bySeverity).toHaveProperty('low');
  }, 60000);
});

describe('getRecentZeroDays', () => {
  it('returns array of VulnEntry objects', async () => {
    const { getRecentZeroDays } = await import('./lib/vuln-feeds');
    const results = await getRecentZeroDays(10);

    expect(Array.isArray(results)).toBe(true);
    // All entries should be in-the-wild
    for (const entry of results) {
      expect(entry.inTheWild).toBe(true);
      expect(entry).toHaveProperty('cveId');
      expect(entry).toHaveProperty('severity');
      expect(entry).toHaveProperty('datePublished');
      expect(entry).toHaveProperty('sources');
      expect(Array.isArray(entry.sources)).toBe(true);
    }
  }, 30000);

  it('respects limit parameter', async () => {
    const { getRecentZeroDays } = await import('./lib/vuln-feeds');
    const results = await getRecentZeroDays(5);
    expect(results.length).toBeLessThanOrEqual(5);
  }, 30000);

  it('returns entries sorted by date (newest first)', async () => {
    const { getRecentZeroDays } = await import('./lib/vuln-feeds');
    const results = await getRecentZeroDays(20);
    for (let i = 1; i < results.length; i++) {
      const prev = new Date(results[i - 1].datePublished).getTime();
      const curr = new Date(results[i].datePublished).getTime();
      expect(prev).toBeGreaterThanOrEqual(curr);
    }
  }, 30000);
});

describe('getWeaponizedCves', () => {
  it('returns array of CVEs with exploits available', async () => {
    const { getWeaponizedCves } = await import('./lib/vuln-feeds');
    const results = await getWeaponizedCves(10);

    expect(Array.isArray(results)).toBe(true);
    for (const entry of results) {
      expect(entry.exploitAvailable).toBe(true);
      // Should exclude KEV entries (shown separately)
      expect(entry.kevListed).toBe(false);
    }
  }, 30000);
});

describe('searchVulnerabilities', () => {
  it('filters by severity', async () => {
    const { searchVulnerabilities } = await import('./lib/vuln-feeds');
    const results = await searchVulnerabilities('', { severity: 'critical' }, 10);

    expect(Array.isArray(results)).toBe(true);
    for (const entry of results) {
      expect(entry.severity).toBe('critical');
    }
  }, 30000);

  it('filters by kevOnly', async () => {
    const { searchVulnerabilities } = await import('./lib/vuln-feeds');
    const results = await searchVulnerabilities('', { kevOnly: true }, 10);

    expect(Array.isArray(results)).toBe(true);
    for (const entry of results) {
      expect(entry.kevListed).toBe(true);
    }
  }, 30000);

  it('filters by zeroDayOnly', async () => {
    const { searchVulnerabilities } = await import('./lib/vuln-feeds');
    const results = await searchVulnerabilities('', { zeroDayOnly: true }, 10);

    expect(Array.isArray(results)).toBe(true);
    for (const entry of results) {
      expect(entry.inTheWild).toBe(true);
    }
  }, 30000);
});

describe('VulnEntry structure', () => {
  it('has all required fields', async () => {
    const { getRecentZeroDays } = await import('./lib/vuln-feeds');
    const results = await getRecentZeroDays(1);
    if (results.length === 0) return; // Skip if no data

    const entry = results[0];
    expect(entry).toHaveProperty('cveId');
    expect(entry).toHaveProperty('title');
    expect(entry).toHaveProperty('description');
    expect(entry).toHaveProperty('severity');
    expect(entry).toHaveProperty('vendor');
    expect(entry).toHaveProperty('product');
    expect(entry).toHaveProperty('datePublished');
    expect(entry).toHaveProperty('sources');
    expect(entry).toHaveProperty('exploitAvailable');
    expect(entry).toHaveProperty('inTheWild');
    expect(entry).toHaveProperty('kevListed');
    expect(entry).toHaveProperty('ransomwareLinked');
    expect(entry).toHaveProperty('suggestedTechniques');

    // Validate CVE ID format
    expect(entry.cveId).toMatch(/^CVE-\d{4}-\d+$/);

    // Validate severity is one of the expected values
    expect(['critical', 'high', 'medium', 'low', 'unknown']).toContain(entry.severity);
  }, 30000);
});
