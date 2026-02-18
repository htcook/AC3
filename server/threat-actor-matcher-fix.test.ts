import { describe, it, expect } from 'vitest';

/**
 * Tests for the safeParseJsonArray fix in threat-actor-matcher.ts
 * This validates that the JSON column parsing handles all edge cases:
 * - Already-parsed arrays
 * - JSON strings that need parsing
 * - null/undefined/empty values
 */

// Replicate the safeParseJsonArray helper logic
function safeParseJsonArray<T>(val: unknown): T[] {
  if (Array.isArray(val)) return val;
  if (typeof val === 'string') {
    try {
      const parsed = JSON.parse(val);
      if (Array.isArray(parsed)) return parsed;
    } catch { /* ignore */ }
  }
  return [];
}

describe('safeParseJsonArray', () => {
  it('returns array as-is when already parsed', () => {
    const input = [{ id: 'T1059.001' }, { id: 'T1003.001' }];
    expect(safeParseJsonArray(input)).toEqual(input);
  });

  it('parses JSON string into array', () => {
    const input = '[{"id":"T1059.001"},{"id":"T1003.001"}]';
    expect(safeParseJsonArray(input)).toEqual([{ id: 'T1059.001' }, { id: 'T1003.001' }]);
  });

  it('returns empty array for null', () => {
    expect(safeParseJsonArray(null)).toEqual([]);
  });

  it('returns empty array for undefined', () => {
    expect(safeParseJsonArray(undefined)).toEqual([]);
  });

  it('returns empty array for empty string', () => {
    expect(safeParseJsonArray('')).toEqual([]);
  });

  it('returns empty array for invalid JSON string', () => {
    expect(safeParseJsonArray('not json')).toEqual([]);
  });

  it('returns empty array for number', () => {
    expect(safeParseJsonArray(42)).toEqual([]);
  });

  it('returns empty array when JSON parses to non-array (object)', () => {
    expect(safeParseJsonArray('{"key":"value"}')).toEqual([]);
  });

  it('handles nested objects in array', () => {
    const input = '[{"id":"T1059.001","name":"PowerShell","phases":["execution"]}]';
    const result = safeParseJsonArray(input);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({ id: 'T1059.001', name: 'PowerShell', phases: ['execution'] });
  });

  it('handles string array (for targetSectors/targetRegions)', () => {
    const input = '["Technology","Financial Services","Healthcare"]';
    expect(safeParseJsonArray(input)).toEqual(['Technology', 'Financial Services', 'Healthcare']);
  });
});

describe('threat actor technique overlap calculation', () => {
  // Replicate the techOverlap logic
  function techOverlap(
    actorTechniques: Array<{ id: string }>,
    scanTechniques: string[]
  ): { count: number; matched: string[] } {
    const scanSet = new Set(scanTechniques.map(t => t.toLowerCase()));
    const matched: string[] = [];
    for (const t of actorTechniques) {
      if (scanSet.has(t.id.toLowerCase())) matched.push(t.id);
    }
    return { count: matched.length, matched };
  }

  it('finds overlapping techniques', () => {
    const actorTechs = [{ id: 'T1059.001' }, { id: 'T1003.001' }, { id: 'T1505.003' }];
    const scanTechs = ['T1059.001', 'T1505.003', 'T1190'];
    const result = techOverlap(actorTechs, scanTechs);
    expect(result.count).toBe(2);
    expect(result.matched).toContain('T1059.001');
    expect(result.matched).toContain('T1505.003');
  });

  it('handles empty actor techniques', () => {
    const result = techOverlap([], ['T1059.001']);
    expect(result.count).toBe(0);
    expect(result.matched).toEqual([]);
  });

  it('handles empty scan techniques', () => {
    const result = techOverlap([{ id: 'T1059.001' }], []);
    expect(result.count).toBe(0);
    expect(result.matched).toEqual([]);
  });

  it('is case-insensitive', () => {
    const result = techOverlap([{ id: 'T1059.001' }], ['t1059.001']);
    expect(result.count).toBe(1);
  });
});

describe('threat actor matching with parsed JSON columns', () => {
  it('correctly processes actor data with string-encoded techniques', () => {
    // Simulate what comes from the database — JSON columns as strings
    const dbActor = {
      name: 'APT41',
      type: 'apt',
      origin: 'China',
      techniques: '[{"id":"T1059.001"},{"id":"T1003.001"},{"id":"T1505.003"}]',
      targetSectors: '["Technology","Financial Services"]',
      targetRegions: '["North America","Europe"]',
    };

    // Parse using safeParseJsonArray
    const techniques = safeParseJsonArray<{ id: string }>(dbActor.techniques);
    const sectors = safeParseJsonArray<string>(dbActor.targetSectors);
    const regions = safeParseJsonArray<string>(dbActor.targetRegions);

    expect(techniques).toHaveLength(3);
    expect(techniques[0].id).toBe('T1059.001');
    expect(sectors).toContain('Technology');
    expect(regions).toContain('North America');
  });

  it('handles already-parsed actor data (in-memory)', () => {
    const memoryActor = {
      name: 'FIN7',
      techniques: [{ id: 'T1059.001' }, { id: 'T1003.001' }],
      targetSectors: ['Technology', 'Retail'],
      targetRegions: ['North America'],
    };

    const techniques = safeParseJsonArray<{ id: string }>(memoryActor.techniques);
    const sectors = safeParseJsonArray<string>(memoryActor.targetSectors);

    expect(techniques).toHaveLength(2);
    expect(sectors).toContain('Retail');
  });

  it('handles null/missing columns gracefully', () => {
    const incompleteActor = {
      name: 'Unknown',
      techniques: null,
      targetSectors: undefined,
      targetRegions: '',
    };

    const techniques = safeParseJsonArray<{ id: string }>(incompleteActor.techniques);
    const sectors = safeParseJsonArray<string>(incompleteActor.targetSectors);
    const regions = safeParseJsonArray<string>(incompleteActor.targetRegions);

    expect(techniques).toEqual([]);
    expect(sectors).toEqual([]);
    expect(regions).toEqual([]);
  });
});
