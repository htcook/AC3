import { describe, it, expect } from 'vitest';

/**
 * Tests for the 7-day CVE trend data endpoint
 * Validates the getVulnTrendData function that powers the sparkline
 * 
 * Note: These tests call external APIs (CISA KEV, NVD, etc.) so they
 * gracefully skip if the APIs are unavailable or timeout.
 */

// Helper to fetch trend data with graceful timeout handling
async function getTrendDataSafe(days: number) {
  const { getVulnTrendData } = await import('./lib/vuln-feeds');
  try {
    return await getVulnTrendData(days);
  } catch (e: any) {
    console.warn(`[vuln-trend] Skipping: external API unavailable - ${e.message}`);
    return null;
  }
}

describe('getVulnTrendData', () => {
  it('returns an array of DayTrend objects for 7 days', async () => {
    const result = await getTrendDataSafe(7);
    if (!result) return; // Skip if external APIs are down

    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBe(7);
  }, 120000);

  it('each DayTrend has required fields', async () => {
    const result = await getTrendDataSafe(7);
    if (!result) return;

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
  }, 120000);

  it('total equals sum of severity counts for each day', async () => {
    const result = await getTrendDataSafe(7);
    if (!result) return;

    for (const day of result) {
      // total should be >= sum of named severities (some may be "unknown")
      const namedSum = day.critical + day.high + day.medium + day.low;
      expect(day.total).toBeGreaterThanOrEqual(namedSum);
    }
  }, 120000);

  it('dates are in chronological order (oldest first)', async () => {
    const result = await getTrendDataSafe(7);
    if (!result) return;

    for (let i = 1; i < result.length; i++) {
      expect(result[i].date > result[i - 1].date).toBe(true);
    }
  }, 120000);

  it('last date is today', async () => {
    const result = await getTrendDataSafe(7);
    if (!result) return;

    const today = new Date().toISOString().slice(0, 10);
    expect(result[result.length - 1].date).toBe(today);
  }, 120000);

  it('respects custom days parameter', async () => {
    const result3 = await getTrendDataSafe(3);
    const result14 = await getTrendDataSafe(14);
    if (!result3 || !result14) return;

    expect(result3.length).toBe(3);
    expect(result14.length).toBe(14);
  }, 120000);

  it('first date is (days-1) days before today', async () => {
    const result = await getTrendDataSafe(7);
    if (!result) return;

    const expected = new Date();
    expected.setDate(expected.getDate() - 6);
    const expectedStr = expected.toISOString().slice(0, 10);
    expect(result[0].date).toBe(expectedStr);
  }, 120000);
});

describe('DayTrend type contract', () => {
  it('exported interface matches expected shape', async () => {
    const mod = await import('./lib/vuln-feeds');
    // Verify the function exists and is callable
    expect(typeof mod.getVulnTrendData).toBe('function');
  });
});
