import { describe, it, expect } from 'vitest';

// ─── Featured Actors Completeness Scoring Tests ────────────────────────────
// Tests the scoring algorithm used by the threatIntel.featuredActors endpoint
// to rank actors by data completeness and return a randomized subset.

function safeParseArr(v: unknown): any[] {
  if (Array.isArray(v)) return v;
  if (typeof v === "string") { try { const p = JSON.parse(v); return Array.isArray(p) ? p : []; } catch { return []; } }
  return [];
}
function safeParseObj(v: unknown): any {
  if (!v) return null;
  if (typeof v === "object" && !Array.isArray(v)) return v;
  if (typeof v === "string") { try { return JSON.parse(v); } catch { return null; } }
  return null;
}

interface MockActor {
  actorId: string;
  name: string;
  description?: string | null;
  origin?: string | null;
  motivation?: string | null;
  firstSeen?: string | null;
  lastActive?: string | null;
  threatLevel?: string | null;
  sophistication?: string | null;
  aliases?: any;
  techniques?: any;
  tools?: any;
  malware?: any;
  targetSectors?: any;
  targetRegions?: any;
  activityTimeline?: any;
  calderaProfile?: any;
  confidence?: number | null;
  stixId?: string | null;
}

function scoreActor(a: MockActor): number {
  let score = 0;
  const aliases = safeParseArr(a.aliases);
  const techniques = safeParseArr(a.techniques);
  const tools = safeParseArr(a.tools);
  const malware = safeParseArr(a.malware);
  const targetSectors = safeParseArr(a.targetSectors);
  const targetRegions = safeParseArr(a.targetRegions);
  const activityTimeline = safeParseArr(a.activityTimeline);
  const calderaProfile = safeParseObj(a.calderaProfile);

  // Core identity fields (weighted higher)
  if (a.description && a.description.length > 50) score += 15;
  else if (a.description) score += 5;
  if (a.origin) score += 5;
  if (a.motivation) score += 5;
  if (a.firstSeen) score += 3;
  if (a.lastActive) score += 5;

  // Threat level & sophistication
  if (a.threatLevel === 'critical') score += 10;
  else if (a.threatLevel === 'high') score += 7;
  else if (a.threatLevel === 'medium') score += 3;
  if (a.sophistication === 'nation-state') score += 8;
  else if (a.sophistication === 'advanced') score += 5;

  // Richness of structured data
  score += Math.min(aliases.length * 2, 10);
  score += Math.min(techniques.length, 20);
  score += Math.min(tools.length * 2, 12);
  score += Math.min(malware.length * 2, 12);
  score += Math.min(targetSectors.length * 2, 10);
  score += Math.min(targetRegions.length * 2, 10);
  score += Math.min(activityTimeline.length * 3, 15);
  if (calderaProfile) score += 10;
  if (a.confidence && a.confidence >= 80) score += 5;
  if (a.stixId) score += 3;

  return score;
}

function selectFeaturedActors(allActors: MockActor[], count: number): MockActor[] {
  const scored = allActors.map(a => ({ actor: a, score: scoreActor(a) }));
  scored.sort((a, b) => b.score - a.score);
  const poolSize = Math.min(scored.length, count * 3);
  const pool = scored.slice(0, poolSize);

  // Fisher-Yates shuffle
  for (let i = pool.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }

  return pool.slice(0, count).map(p => p.actor);
}

describe('Featured Actors Completeness Scoring', () => {
  const richActor: MockActor = {
    actorId: 'apt29',
    name: 'APT29 (Cozy Bear)',
    description: 'A sophisticated Russian state-sponsored threat group known for targeting government and diplomatic organizations worldwide with advanced persistent access techniques.',
    origin: 'Russia',
    motivation: 'espionage',
    firstSeen: '2008',
    lastActive: '2024',
    threatLevel: 'critical',
    sophistication: 'nation-state',
    aliases: ['Cozy Bear', 'The Dukes', 'YTTRIUM', 'Iron Hemlock', 'Grizzly Steppe'],
    techniques: Array.from({ length: 25 }, (_, i) => ({ id: `T${1000 + i}`, name: `Tech ${i}` })),
    tools: ['Cobalt Strike', 'Mimikatz', 'PsExec', 'AdFind', 'BloodHound', 'Rubeus'],
    malware: ['WellMess', 'WellMail', 'SUNBURST', 'TEARDROP', 'Raindrop', 'GoldMax'],
    targetSectors: ['Government', 'Diplomatic', 'Healthcare', 'Energy', 'Technology'],
    targetRegions: ['North America', 'Europe', 'Asia'],
    activityTimeline: [
      { date: '2024-01', event: 'Campaign targeting EU diplomats' },
      { date: '2023-06', event: 'SolarWinds follow-up operations' },
      { date: '2023-01', event: 'Cloud infrastructure targeting' },
      { date: '2022-05', event: 'NATO-aligned government targeting' },
      { date: '2021-12', event: 'SUNBURST aftermath operations' },
    ],
    calderaProfile: { id: 'apt29-profile', atomicOrdering: ['a1', 'a2'] },
    confidence: 95,
    stixId: 'intrusion-set--apt29',
  };

  const sparseActor: MockActor = {
    actorId: 'unknown-group-42',
    name: 'Unknown Group 42',
    description: 'Minimal info',
    origin: null,
    motivation: null,
    firstSeen: null,
    lastActive: null,
    threatLevel: 'low',
    sophistication: 'basic',
    aliases: [],
    techniques: [],
    tools: [],
    malware: [],
    targetSectors: [],
    targetRegions: [],
    activityTimeline: [],
    calderaProfile: null,
    confidence: 20,
    stixId: null,
  };

  const mediumActor: MockActor = {
    actorId: 'fin7',
    name: 'FIN7',
    description: 'A financially motivated cybercrime group known for targeting the retail and hospitality sectors.',
    origin: 'Eastern Europe',
    motivation: 'financial',
    firstSeen: '2013',
    lastActive: '2023',
    threatLevel: 'high',
    sophistication: 'advanced',
    aliases: ['Carbanak', 'Navigator Group'],
    techniques: Array.from({ length: 12 }, (_, i) => ({ id: `T${2000 + i}`, name: `Tech ${i}` })),
    tools: ['Cobalt Strike', 'Metasploit'],
    malware: ['Carbanak', 'GRIFFON'],
    targetSectors: ['Retail', 'Hospitality', 'Financial Services'],
    targetRegions: ['North America', 'Europe'],
    activityTimeline: [{ date: '2023-03', event: 'POS malware campaign' }],
    calderaProfile: null,
    confidence: 80,
    stixId: 'intrusion-set--fin7',
  };

  it('should score a rich actor higher than a sparse actor', () => {
    const richScore = scoreActor(richActor);
    const sparseScore = scoreActor(sparseActor);
    expect(richScore).toBeGreaterThan(sparseScore);
    expect(richScore).toBeGreaterThan(100); // Rich actor should score very high
    expect(sparseScore).toBeLessThan(20); // Sparse actor should score very low
  });

  it('should score a medium actor between rich and sparse', () => {
    const richScore = scoreActor(richActor);
    const mediumScore = scoreActor(mediumActor);
    const sparseScore = scoreActor(sparseActor);
    expect(mediumScore).toBeGreaterThan(sparseScore);
    expect(mediumScore).toBeLessThan(richScore);
  });

  it('should give higher score for critical threat level than high', () => {
    const criticalActor = { ...sparseActor, threatLevel: 'critical' };
    const highActor = { ...sparseActor, threatLevel: 'high' };
    expect(scoreActor(criticalActor)).toBeGreaterThan(scoreActor(highActor));
  });

  it('should give higher score for nation-state sophistication', () => {
    const nationState = { ...sparseActor, sophistication: 'nation-state' };
    const basic = { ...sparseActor, sophistication: 'basic' };
    expect(scoreActor(nationState)).toBeGreaterThan(scoreActor(basic));
  });

  it('should give higher score for long descriptions (>50 chars)', () => {
    const longDesc = { ...sparseActor, description: 'A very detailed description that is definitely longer than fifty characters in total length.' };
    const shortDesc = { ...sparseActor, description: 'Short' };
    const noDesc = { ...sparseActor, description: null };
    expect(scoreActor(longDesc)).toBeGreaterThan(scoreActor(shortDesc));
    expect(scoreActor(shortDesc)).toBeGreaterThan(scoreActor(noDesc));
  });

  it('should cap individual field contributions to prevent one-dimensional actors from dominating', () => {
    // Actor with 100 techniques but nothing else
    const techniqueHeavy = { ...sparseActor, techniques: Array.from({ length: 100 }, (_, i) => ({ id: `T${i}` })) };
    const techniqueScore = scoreActor(techniqueHeavy);
    // Techniques are capped at 20 points
    expect(techniqueScore).toBeLessThan(30); // sparse base + 20 technique cap
  });

  it('should handle JSON string fields correctly', () => {
    const jsonStringActor = {
      ...sparseActor,
      aliases: JSON.stringify(['Alias1', 'Alias2']),
      techniques: JSON.stringify([{ id: 'T1001' }, { id: 'T1002' }]),
      tools: JSON.stringify(['Tool1']),
    };
    const score = scoreActor(jsonStringActor);
    expect(score).toBeGreaterThan(scoreActor(sparseActor));
  });
});

describe('Featured Actors Selection (randomized from top pool)', () => {
  // Create a pool of 20 actors with varying completeness
  const actors: MockActor[] = Array.from({ length: 20 }, (_, i) => ({
    actorId: `actor-${i}`,
    name: `Actor ${i}`,
    description: i < 10 ? `A detailed description for actor ${i} that is definitely longer than fifty characters.` : (i < 15 ? 'Short' : null),
    origin: i < 12 ? 'Country' : null,
    motivation: i < 10 ? 'espionage' : null,
    firstSeen: i < 15 ? '2020' : null,
    lastActive: i < 10 ? '2024' : null,
    threatLevel: i < 5 ? 'critical' : i < 10 ? 'high' : i < 15 ? 'medium' : 'low',
    sophistication: i < 5 ? 'nation-state' : i < 10 ? 'advanced' : 'basic',
    aliases: Array.from({ length: Math.max(0, 5 - Math.floor(i / 4)) }, (_, j) => `Alias${j}`),
    techniques: Array.from({ length: Math.max(0, 20 - i) }, (_, j) => ({ id: `T${j}` })),
    tools: i < 10 ? ['Tool1', 'Tool2'] : [],
    malware: i < 8 ? ['Malware1'] : [],
    targetSectors: i < 10 ? ['Sector1', 'Sector2'] : [],
    targetRegions: i < 10 ? ['Region1'] : [],
    activityTimeline: i < 5 ? [{ date: '2024', event: 'Event' }] : [],
    calderaProfile: i < 5 ? { id: 'profile' } : null,
    confidence: 90 - i * 4,
    stixId: i < 10 ? `stix-${i}` : null,
  }));

  it('should return the requested number of actors', () => {
    const result = selectFeaturedActors(actors, 6);
    expect(result).toHaveLength(6);
  });

  it('should only select from the top-completeness pool (3x count)', () => {
    // With count=6, pool should be top 18 actors (3*6=18)
    // The bottom 2 actors (index 18, 19) should never appear
    const bottomActorIds = new Set(['actor-18', 'actor-19']);
    // Run multiple times to verify randomization doesn't leak bottom actors
    let foundBottom = false;
    for (let trial = 0; trial < 50; trial++) {
      const result = selectFeaturedActors(actors, 6);
      for (const a of result) {
        if (bottomActorIds.has(a.actorId)) {
          foundBottom = true;
          break;
        }
      }
      if (foundBottom) break;
    }
    expect(foundBottom).toBe(false);
  });

  it('should produce different orderings on multiple calls (randomization)', () => {
    const orderings = new Set<string>();
    for (let i = 0; i < 20; i++) {
      const result = selectFeaturedActors(actors, 6);
      orderings.add(result.map(a => a.actorId).join(','));
    }
    // With 18 actors shuffled and 6 picked, we should get multiple unique orderings
    expect(orderings.size).toBeGreaterThan(1);
  });

  it('should handle small actor pools gracefully', () => {
    const smallPool = actors.slice(0, 3);
    const result = selectFeaturedActors(smallPool, 6);
    expect(result).toHaveLength(3); // Can't return more than available
  });

  it('should handle empty actor list', () => {
    const result = selectFeaturedActors([], 6);
    expect(result).toHaveLength(0);
  });

  it('should handle count of 1', () => {
    const result = selectFeaturedActors(actors, 1);
    expect(result).toHaveLength(1);
  });
});

// ─── Scan List Sorting Tests ────────────────────────────────────────────────
// Tests that scan lists sort by updatedAt (most recently run/refreshed first)

describe('Scan List Sorting (most recently run/refreshed first)', () => {
  interface MockScan {
    id: number;
    createdAt: Date;
    updatedAt: Date;
    status: string;
  }

  function sortByUpdatedAt(scans: MockScan[]): MockScan[] {
    return [...scans].sort((a, b) => {
      const aTime = (a.updatedAt || a.createdAt).getTime();
      const bTime = (b.updatedAt || b.createdAt).getTime();
      return bTime - aTime; // descending (most recent first)
    });
  }

  const now = Date.now();
  const scans: MockScan[] = [
    { id: 1, createdAt: new Date(now - 86400000 * 5), updatedAt: new Date(now - 86400000 * 5), status: 'completed' }, // 5 days ago, never refreshed
    { id: 2, createdAt: new Date(now - 86400000 * 10), updatedAt: new Date(now - 3600000), status: 'completed' },    // 10 days ago, refreshed 1 hour ago
    { id: 3, createdAt: new Date(now - 86400000 * 1), updatedAt: new Date(now - 86400000 * 1), status: 'completed' }, // 1 day ago, never refreshed
    { id: 4, createdAt: new Date(now - 86400000 * 30), updatedAt: new Date(now - 60000), status: 'running' },         // 30 days ago, refreshed 1 minute ago
    { id: 5, createdAt: new Date(now - 86400000 * 2), updatedAt: new Date(now - 86400000 * 2), status: 'failed' },    // 2 days ago, never refreshed
  ];

  it('should sort by updatedAt descending (most recent first)', () => {
    const sorted = sortByUpdatedAt(scans);
    expect(sorted[0].id).toBe(4); // refreshed 1 minute ago
    expect(sorted[1].id).toBe(2); // refreshed 1 hour ago
    expect(sorted[2].id).toBe(3); // 1 day ago
    expect(sorted[3].id).toBe(5); // 2 days ago
    expect(sorted[4].id).toBe(1); // 5 days ago
  });

  it('should put recently refreshed old scans before newer un-refreshed scans', () => {
    const sorted = sortByUpdatedAt(scans);
    // Scan 2 was created 10 days ago but refreshed 1 hour ago — should appear before scan 3 (created 1 day ago)
    const scan2Index = sorted.findIndex(s => s.id === 2);
    const scan3Index = sorted.findIndex(s => s.id === 3);
    expect(scan2Index).toBeLessThan(scan3Index);
  });

  it('should handle scans where updatedAt equals createdAt (never refreshed)', () => {
    const neverRefreshed = scans.filter(s => s.createdAt.getTime() === s.updatedAt.getTime());
    const sorted = sortByUpdatedAt(neverRefreshed);
    // Should still sort by createdAt descending
    expect(sorted[0].id).toBe(3); // 1 day ago
    expect(sorted[1].id).toBe(5); // 2 days ago
    expect(sorted[2].id).toBe(1); // 5 days ago
  });

  it('should display updatedAt (not createdAt) as the date in the UI', () => {
    // Simulates the UI date display logic: (scan.updatedAt || scan.createdAt)
    const scan = scans[1]; // id=2, created 10 days ago, updated 1 hour ago
    const displayDate = new Date(scan.updatedAt || scan.createdAt);
    const createdDate = new Date(scan.createdAt);
    // The display date should be the updatedAt, not createdAt
    expect(displayDate.getTime()).toBeGreaterThan(createdDate.getTime());
    expect(displayDate.getTime()).toBe(scan.updatedAt.getTime());
  });
});
