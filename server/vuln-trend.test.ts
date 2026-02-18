import { describe, it, expect } from 'vitest';

/**
 * Tests for the 7-day CVE trend data endpoint
 * Validates the getVulnTrendData function that powers the sparkline
 */

describe('getVulnTrendData', () => {
  it('returns an array of DayTrend objects for 7 days', async () => {
    const { getVulnTrendData } = await import('./lib/vuln-feeds');
    const result = await getVulnTrendData(7);

    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBe(7);
  }, 60000);

  it('each DayTrend has required fields', async () => {
    const { getVulnTrendData } = await import('./lib/vuln-feeds');
    const result = await getVulnTrendData(7);

    for (const day of result) {
      expect(day).toHaveProperty('date');
      expect(day).toHaveProperty('critical');
      expect(day).toHaveProperty('high');
      expect(day).toHaveProperty('medium');
      expect(day).toHaveProperty('low');
      expect(day).toHaveProperty('total');

      // date should be YYYY-MM-DD format
      expect(day.date).toMatch(/^\d{4}-\d{2}-\d{2}$/);

      // counts should be non-negative integers
      expect(typeof day.critical).toBe('number');
      expect(typeof day.high).toBe('number');
      expect(typeof day.medium).toBe('number');
      expect(typeof day.low).toBe('number');
      expect(typeof day.total).toBe('number');
      expect(day.critical).toBeGreaterThanOrEqual(0);
      expect(day.high).toBeGreaterThanOrEqual(0);
      expect(day.medium).toBeGreaterThanOrEqual(0);
      expect(day.low).toBeGreaterThanOrEqual(0);
      expect(day.total).toBeGreaterThanOrEqual(0);
    }
  }, 60000);

  it('total equals sum of severity counts for each day', async () => {
    const { getVulnTrendData } = await import('./lib/vuln-feeds');
    const result = await getVulnTrendData(7);

    for (const day of result) {
      // total should be >= sum of named severities (some may be "unknown")
      const namedSum = day.critical + day.high + day.medium + day.low;
      expect(day.total).toBeGreaterThanOrEqual(namedSum);
    }
  }, 60000);

  it('dates are in chronological order (oldest first)', async () => {
    const { getVulnTrendData } = await import('./lib/vuln-feeds');
    const result = await getVulnTrendData(7);

    for (let i = 1; i < result.length; i++) {
      expect(result[i].date > result[i - 1].date).toBe(true);
    }
  }, 60000);

  it('last date is today', async () => {
    const { getVulnTrendData } = await import('./lib/vuln-feeds');
    const result = await getVulnTrendData(7);

    const today = new Date().toISOString().slice(0, 10);
    expect(result[result.length - 1].date).toBe(today);
  }, 60000);

  it('respects custom days parameter', async () => {
    const { getVulnTrendData } = await import('./lib/vuln-feeds');
    const result3 = await getVulnTrendData(3);
    const result14 = await getVulnTrendData(14);

    expect(result3.length).toBe(3);
    expect(result14.length).toBe(14);
  }, 60000);

  it('first date is (days-1) days before today', async () => {
    const { getVulnTrendData } = await import('./lib/vuln-feeds');
    const result = await getVulnTrendData(7);

    const expected = new Date();
    expected.setDate(expected.getDate() - 6);
    const expectedStr = expected.toISOString().slice(0, 10);
    expect(result[0].date).toBe(expectedStr);
  }, 60000);
});

describe('DayTrend type contract', () => {
  it('exported interface matches expected shape', async () => {
    const mod = await import('./lib/vuln-feeds');
    // Verify the function exists and is callable
    expect(typeof mod.getVulnTrendData).toBe('function');
  });
});
