/**
 * Ransomware Leak Site Monitor
 * 
 * Monitors ransomware group leak sites via ransomware.live API
 * to detect new victim postings. Records events in the ransomware_events
 * table and cross-references with threat actor catalog.
 * 
 * Sources:
 * - ransomware.live API v2 (free, no key required)
 * - Aggregates from multiple ransomware group leak sites
 * 
 * Tracked groups: LockBit, ALPHV/BlackCat, Cl0p, Play, Akira,
 * Rhysida, Black Basta, Medusa, RansomHub, Qilin, INC Ransom,
 * Hunters International, 8Base, BianLian, Fog, DragonForce
 */

import { getDb } from "../db";
import { ransomwareEvents, ransomwareGroups } from "../../drizzle/schema";
import { eq, desc, and, gte } from "drizzle-orm";

const RANSOMWARE_LIVE_BASE = "https://api.ransomware.live/v2";

// Priority groups to monitor (most active as of 2026)
const PRIORITY_GROUPS = [
  "lockbit3", "alphv", "clop", "play", "akira",
  "rhysida", "blackbasta", "medusa", "ransomhub", "qilin",
  "incransom", "hunters", "8base", "bianlian", "fog",
  "dragonforce", "embargo", "lynx", "cicada3301", "funksec",
];

// Map API group IDs to display names
const GROUP_DISPLAY_NAMES: Record<string, string> = {
  lockbit3: "LockBit",
  alphv: "BlackCat/ALPHV",
  clop: "Cl0p",
  play: "Play",
  akira: "Akira",
  rhysida: "Rhysida",
  blackbasta: "Black Basta",
  medusa: "Medusa",
  ransomhub: "RansomHub",
  qilin: "Qilin",
  incransom: "INC Ransom",
  hunters: "Hunters International",
  "8base": "8Base",
  bianlian: "BianLian",
  fog: "Fog",
  dragonforce: "DragonForce",
  embargo: "Embargo",
  lynx: "Lynx",
  cicada3301: "Cicada3301",
  funksec: "Funksec",
};

// Map to threat actor catalog IDs
const GROUP_TO_ACTOR_ID: Record<string, string> = {
  lockbit3: "lockbit",
  alphv: "alphv-blackcat",
  clop: "cl0p",
  play: "play-ransomware",
  akira: "akira",
  rhysida: "rhysida",
  blackbasta: "black-basta",
  medusa: "medusa-ransomware",
  ransomhub: "ransomhub",
  qilin: "qilin",
  incransom: "inc-ransom",
  hunters: "hunters-international",
  "8base": "8base",
  bianlian: "bianlian",
  fog: "fog-ransomware",
  dragonforce: "dragonforce",
  embargo: "embargo",
  lynx: "lynx",
  cicada3301: "cicada3301",
  funksec: "funksec",
};

export interface LeakVictim {
  victim: string;
  group_name: string;
  discovered: string;
  published?: string;
  country?: string;
  activity?: string;
  website?: string;
  description?: string;
}

export interface LeakMonitorResult {
  totalChecked: number;
  newVictims: number;
  groupBreakdown: Record<string, number>;
  errors: string[];
  durationMs: number;
}

/**
 * Fetch recent victims from ransomware.live API
 */
async function fetchRecentVictims(limit = 200): Promise<LeakVictim[]> {
  const url = `${RANSOMWARE_LIVE_BASE}/victims/recent`;
  const resp = await fetch(url, {
    headers: { "User-Agent": "Mozilla/5.0 (compatible; AC3-ThreatIntel/1.0)" },
    signal: AbortSignal.timeout(30000),
  });
  if (!resp.ok) {
    throw new Error(`ransomware.live API returned ${resp.status}`);
  }
  const data = await resp.json();
  return Array.isArray(data) ? data.slice(0, limit) : [];
}

/**
 * Fetch victims for a specific group
 */
async function fetchGroupVictims(groupId: string, limit = 50): Promise<LeakVictim[]> {
  const url = `${RANSOMWARE_LIVE_BASE}/victims/group/${encodeURIComponent(groupId)}`;
  const resp = await fetch(url, {
    headers: { "User-Agent": "Mozilla/5.0 (compatible; AC3-ThreatIntel/1.0)" },
    signal: AbortSignal.timeout(15000),
  });
  if (!resp.ok) {
    if (resp.status === 404) return []; // Group not found
    throw new Error(`ransomware.live API returned ${resp.status} for group ${groupId}`);
  }
  const data = await resp.json();
  return Array.isArray(data) ? data.slice(0, limit) : [];
}

/**
 * Check if a victim event already exists in our database
 */
async function victimExists(groupName: string, victimName: string, publishedAt: string): Promise<boolean> {
  const db = await getDb();
  if (!db) return false;

  const existing = await db
    .select({ id: ransomwareEvents.id })
    .from(ransomwareEvents)
    .where(
      and(
        eq(ransomwareEvents.reGroupName, groupName),
        eq(ransomwareEvents.victimName, victimName),
      )
    )
    .limit(1);

  return existing.length > 0;
}

/**
 * Record a new ransomware victim event
 */
async function recordVictimEvent(victim: LeakVictim): Promise<boolean> {
  const db = await getDb();
  if (!db) return false;

  const groupDisplayName = GROUP_DISPLAY_NAMES[victim.group_name] || victim.group_name;

  // Check if already recorded
  const exists = await victimExists(groupDisplayName, victim.victim, victim.discovered);
  if (exists) return false;

  await db.insert(ransomwareEvents).values({
    reGroupName: groupDisplayName,
    victimName: victim.victim,
    victimUrl: victim.website || null,
    reCountry: victim.country || null,
    reSector: null, // Will be enriched by LLM later
    reDescription: victim.description || `New victim posted by ${groupDisplayName} on ${victim.discovered}`,
    publishedAt: victim.discovered || new Date().toISOString(),
    reSource: "ransomware.live",
    verified: 1,
  });

  return true;
}

/**
 * Update group activity stats based on new victim counts
 */
async function updateGroupStats(groupName: string, newVictimCount: number): Promise<void> {
  const db = await getDb();
  if (!db) return;

  const existing = await db
    .select()
    .from(ransomwareGroups)
    .where(eq(ransomwareGroups.groupName, groupName))
    .limit(1);

  if (existing.length > 0) {
    const current = existing[0];
    const newVictims7d = (current.victims7d ?? 0) + newVictimCount;
    const newVictims30d = (current.victims30d ?? 0) + newVictimCount;
    const newTotal = (current.totalVictims ?? 0) + newVictimCount;

    // Update activity score based on new posting frequency
    let newScore = current.activityScore ?? 0;
    if (newVictimCount >= 5) newScore = Math.min(100, newScore + 15);
    else if (newVictimCount >= 2) newScore = Math.min(100, newScore + 8);
    else if (newVictimCount >= 1) newScore = Math.min(100, newScore + 3);

    const newTrend = newScore >= 70 ? "surging" : newScore >= 40 ? "active" : newScore >= 20 ? "declining" : "dormant";

    await db
      .update(ransomwareGroups)
      .set({
        victims7d: newVictims7d,
        victims30d: newVictims30d,
        totalVictims: newTotal,
        activityScore: newScore,
        trend: newTrend as "surging" | "active" | "declining" | "dormant",
        lastActive: new Date().toISOString().split("T")[0],
      })
      .where(eq(ransomwareGroups.groupName, groupName));
  }
}

/**
 * Main monitoring function — fetches recent victims and records new ones.
 * Called by the daily scheduled task endpoint.
 */
export async function runLeakSiteMonitor(): Promise<LeakMonitorResult> {
  const start = Date.now();
  const errors: string[] = [];
  const groupBreakdown: Record<string, number> = {};
  let totalChecked = 0;
  let newVictims = 0;

  try {
    // Fetch recent victims from the aggregated feed
    const recentVictims = await fetchRecentVictims(500);
    totalChecked = recentVictims.length;

    // Process each victim
    for (const victim of recentVictims) {
      try {
        const isNew = await recordVictimEvent(victim);
        if (isNew) {
          newVictims++;
          const displayName = GROUP_DISPLAY_NAMES[victim.group_name] || victim.group_name;
          groupBreakdown[displayName] = (groupBreakdown[displayName] || 0) + 1;
        }
      } catch (err: any) {
        errors.push(`Failed to record victim ${victim.victim}: ${err.message}`);
      }
    }

    // Update group stats for groups with new victims
    for (const [groupName, count] of Object.entries(groupBreakdown)) {
      try {
        await updateGroupStats(groupName, count);
      } catch (err: any) {
        errors.push(`Failed to update stats for ${groupName}: ${err.message}`);
      }
    }
  } catch (err: any) {
    errors.push(`Failed to fetch recent victims: ${err.message}`);
  }

  return {
    totalChecked,
    newVictims,
    groupBreakdown,
    errors,
    durationMs: Date.now() - start,
  };
}

/**
 * Get monitoring stats for the last N days
 */
export async function getLeakMonitorStats(days = 7): Promise<{
  totalEvents: number;
  newLast24h: number;
  topGroups: { group: string; count: number }[];
  topCountries: { country: string; count: number }[];
}> {
  const db = await getDb();
  if (!db) return { totalEvents: 0, newLast24h: 0, topGroups: [], topCountries: [] };

  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const events = await db
    .select()
    .from(ransomwareEvents)
    .where(gte(ransomwareEvents.createdAt, cutoff))
    .orderBy(desc(ransomwareEvents.createdAt));

  const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const newLast24h = events.filter(e => (e.createdAt ?? "") >= last24h).length;

  // Aggregate by group
  const groupMap = new Map<string, number>();
  const countryMap = new Map<string, number>();
  for (const e of events) {
    groupMap.set(e.reGroupName, (groupMap.get(e.reGroupName) || 0) + 1);
    if (e.reCountry) countryMap.set(e.reCountry, (countryMap.get(e.reCountry) || 0) + 1);
  }

  const topGroups = Array.from(groupMap.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([group, count]) => ({ group, count }));

  const topCountries = Array.from(countryMap.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([country, count]) => ({ country, count }));

  return { totalEvents: events.length, newLast24h, topGroups, topCountries };
}

/**
 * Ingest externally-researched ransomware victims from the scheduled task.
 * The scheduled task agent researches leak sites and POSTs structured data.
 */
export async function ingestExternalVictims(victims: LeakVictim[]): Promise<{ ingested: number; duplicates: number }> {
  let ingested = 0;
  let duplicates = 0;

  for (const victim of victims) {
    const isNew = await recordVictimEvent(victim);
    if (isNew) {
      ingested++;
      const displayName = GROUP_DISPLAY_NAMES[victim.group_name] || victim.group_name;
      await updateGroupStats(displayName, 1);
    } else {
      duplicates++;
    }
  }

  return { ingested, duplicates };
}

// Export constants for testing
export { PRIORITY_GROUPS, GROUP_DISPLAY_NAMES, GROUP_TO_ACTOR_ID };
