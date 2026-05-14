import {
  getDb,
  init_db
} from "./chunk-B7OU3XQL.js";
import "./chunk-NRYVRXXR.js";
import {
  init_schema,
  ransomwareEvents,
  ransomwareGroups
} from "./chunk-TYPEU32S.js";
import "./chunk-KFQGP6VL.js";

// server/lib/ransomware-leak-monitor.ts
init_db();
init_schema();
import { eq, desc, and, gte } from "drizzle-orm";
var RANSOMWARE_LIVE_BASE = "https://api.ransomware.live/v2";
var PRIORITY_GROUPS = [
  "lockbit3",
  "alphv",
  "clop",
  "play",
  "akira",
  "rhysida",
  "blackbasta",
  "medusa",
  "ransomhub",
  "qilin",
  "incransom",
  "hunters",
  "8base",
  "bianlian",
  "fog",
  "dragonforce",
  "embargo",
  "lynx",
  "cicada3301",
  "funksec"
];
var GROUP_DISPLAY_NAMES = {
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
  funksec: "Funksec"
};
var GROUP_TO_ACTOR_ID = {
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
  funksec: "funksec"
};
async function fetchRecentVictims(limit = 200) {
  const url = `${RANSOMWARE_LIVE_BASE}/victims/recent`;
  const resp = await fetch(url, {
    headers: { "User-Agent": "Mozilla/5.0 (compatible; AC3-ThreatIntel/1.0)" },
    signal: AbortSignal.timeout(3e4)
  });
  if (!resp.ok) {
    throw new Error(`ransomware.live API returned ${resp.status}`);
  }
  const data = await resp.json();
  return Array.isArray(data) ? data.slice(0, limit) : [];
}
async function victimExists(groupName, victimName, publishedAt) {
  const db = await getDb();
  if (!db) return false;
  const existing = await db.select({ id: ransomwareEvents.id }).from(ransomwareEvents).where(
    and(
      eq(ransomwareEvents.reGroupName, groupName),
      eq(ransomwareEvents.victimName, victimName)
    )
  ).limit(1);
  return existing.length > 0;
}
async function recordVictimEvent(victim) {
  const db = await getDb();
  if (!db) return false;
  const groupDisplayName = GROUP_DISPLAY_NAMES[victim.group_name] || victim.group_name;
  const exists = await victimExists(groupDisplayName, victim.victim, victim.discovered);
  if (exists) return false;
  await db.insert(ransomwareEvents).values({
    reGroupName: groupDisplayName,
    victimName: victim.victim,
    victimUrl: victim.website || null,
    reCountry: victim.country || null,
    reSector: null,
    // Will be enriched by LLM later
    reDescription: victim.description || `New victim posted by ${groupDisplayName} on ${victim.discovered}`,
    publishedAt: victim.discovered || (/* @__PURE__ */ new Date()).toISOString(),
    reSource: "ransomware.live",
    verified: 1
  });
  return true;
}
async function updateGroupStats(groupName, newVictimCount) {
  const db = await getDb();
  if (!db) return;
  const existing = await db.select().from(ransomwareGroups).where(eq(ransomwareGroups.groupName, groupName)).limit(1);
  if (existing.length > 0) {
    const current = existing[0];
    const newVictims7d = (current.victims7d ?? 0) + newVictimCount;
    const newVictims30d = (current.victims30d ?? 0) + newVictimCount;
    const newTotal = (current.totalVictims ?? 0) + newVictimCount;
    let newScore = current.activityScore ?? 0;
    if (newVictimCount >= 5) newScore = Math.min(100, newScore + 15);
    else if (newVictimCount >= 2) newScore = Math.min(100, newScore + 8);
    else if (newVictimCount >= 1) newScore = Math.min(100, newScore + 3);
    const newTrend = newScore >= 70 ? "surging" : newScore >= 40 ? "active" : newScore >= 20 ? "declining" : "dormant";
    await db.update(ransomwareGroups).set({
      victims7d: newVictims7d,
      victims30d: newVictims30d,
      totalVictims: newTotal,
      activityScore: newScore,
      trend: newTrend,
      lastActive: (/* @__PURE__ */ new Date()).toISOString().split("T")[0]
    }).where(eq(ransomwareGroups.groupName, groupName));
  }
}
async function runLeakSiteMonitor() {
  const start = Date.now();
  const errors = [];
  const groupBreakdown = {};
  let totalChecked = 0;
  let newVictims = 0;
  try {
    const recentVictims = await fetchRecentVictims(500);
    totalChecked = recentVictims.length;
    for (const victim of recentVictims) {
      try {
        const isNew = await recordVictimEvent(victim);
        if (isNew) {
          newVictims++;
          const displayName = GROUP_DISPLAY_NAMES[victim.group_name] || victim.group_name;
          groupBreakdown[displayName] = (groupBreakdown[displayName] || 0) + 1;
        }
      } catch (err) {
        errors.push(`Failed to record victim ${victim.victim}: ${err.message}`);
      }
    }
    for (const [groupName, count] of Object.entries(groupBreakdown)) {
      try {
        await updateGroupStats(groupName, count);
      } catch (err) {
        errors.push(`Failed to update stats for ${groupName}: ${err.message}`);
      }
    }
  } catch (err) {
    errors.push(`Failed to fetch recent victims: ${err.message}`);
  }
  return {
    totalChecked,
    newVictims,
    groupBreakdown,
    errors,
    durationMs: Date.now() - start
  };
}
async function getLeakMonitorStats(days = 7) {
  const db = await getDb();
  if (!db) return { totalEvents: 0, newLast24h: 0, topGroups: [], topCountries: [] };
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1e3).toISOString();
  const events = await db.select().from(ransomwareEvents).where(gte(ransomwareEvents.createdAt, cutoff)).orderBy(desc(ransomwareEvents.createdAt));
  const last24h = new Date(Date.now() - 24 * 60 * 60 * 1e3).toISOString();
  const newLast24h = events.filter((e) => (e.createdAt ?? "") >= last24h).length;
  const groupMap = /* @__PURE__ */ new Map();
  const countryMap = /* @__PURE__ */ new Map();
  for (const e of events) {
    groupMap.set(e.reGroupName, (groupMap.get(e.reGroupName) || 0) + 1);
    if (e.reCountry) countryMap.set(e.reCountry, (countryMap.get(e.reCountry) || 0) + 1);
  }
  const topGroups = Array.from(groupMap.entries()).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([group, count]) => ({ group, count }));
  const topCountries = Array.from(countryMap.entries()).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([country, count]) => ({ country, count }));
  return { totalEvents: events.length, newLast24h, topGroups, topCountries };
}
async function ingestExternalVictims(victims) {
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
export {
  GROUP_DISPLAY_NAMES,
  GROUP_TO_ACTOR_ID,
  PRIORITY_GROUPS,
  getLeakMonitorStats,
  ingestExternalVictims,
  runLeakSiteMonitor
};
