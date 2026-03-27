/**
 * Threat Intel Data Connectors — Master Catalog Ingestion
 * 
 * Sources:
 * 1. MITRE ATT&CK STIX — intrusion-sets with TTPs and software
 * 2. Ransomware.live — ransomware groups with real-time victim tracking
 * 3. Malpedia — threat actors (public list)
 * 4. MITRE Caldera — adversary profiles with ability chains
 * 
 * All connectors normalize into the threatActors + ransomwareGroups tables.
 */

import { getDb } from "../db";
import {
  threatActors, threatGroupEvents, threatIntelUpdates, ransomwareGroups,
} from "../../drizzle/schema";
import { eq, sql } from "drizzle-orm";
import { ENV } from "../_core/env";

async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

// ─── Types ───────────────────────────────────────────────────────────────────

interface MitreIntrusionSet {
  type: string;
  id: string;
  name: string;
  description?: string;
  aliases?: string[];
  created: string;
  modified: string;
  revoked?: boolean;
  x_mitre_deprecated?: boolean;
  external_references?: Array<{
    source_name: string;
    url?: string;
    external_id?: string;
  }>;
}

interface MitreRelationship {
  type: string;
  source_ref: string;
  target_ref: string;
  relationship_type: string;
}

interface MitreAttackPattern {
  type: string;
  id: string;
  name: string;
  revoked?: boolean;
  x_mitre_deprecated?: boolean;
  external_references?: Array<{
    source_name: string;
    external_id?: string;
  }>;
  kill_chain_phases?: Array<{
    kill_chain_name: string;
    phase_name: string;
  }>;
}

interface RansomwareLiveGroup {
  name: string;
  description?: string;
  locations?: Array<{
    available: boolean;
    fqdn: string;
    type: string;
    lastscrape?: string;
  }>;
  profile?: string[] | null;
  tools?: string[] | null;
}

interface RansomwareLiveVictim {
  group_name: string;
  post_title: string;
  discovered: string;
  published?: string;
  country?: string;
  description?: string;
  post_url?: string;
}

interface CalderaAdversary {
  adversary_id: string;
  name: string;
  description: string;
  atomic_ordering: string[];
}

interface CalderaAbility {
  ability_id: string;
  name: string;
  description: string;
  tactic: string;
  technique_id: string;
  technique_name: string;
}

export interface IngestionResult {
  source: string;
  groupsIngested: number;
  groupsUpdated: number;
  ttpsIngested: number;
  eventsIngested: number;
  errors: string[];
  duration: number;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function slugify(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function detectNation(desc: string): string | null {
  const d = desc.toLowerCase();
  const map: Record<string, string[]> = {
    Russia: ["russia", "russian", "gru", "fsb", "svr"],
    China: ["china", "chinese", "pla", "mss"],
    Iran: ["iran", "iranian", "irgc", "mois"],
    "North Korea": ["north korea", "dprk", "lazarus", "kimsuky"],
    Vietnam: ["vietnam", "vietnamese", "ocean lotus"],
    India: ["india", "indian", "sidewinder"],
    Pakistan: ["pakistan", "transparent tribe"],
    Turkey: ["turkey", "turkish"],
    Israel: ["israel", "israeli"],
  };
  for (const [nation, kws] of Object.entries(map)) {
    if (kws.some(k => d.includes(k))) return nation;
  }
  return null;
}

function detectSectors(desc: string): string[] {
  const d = desc.toLowerCase();
  const map: Record<string, string[]> = {
    Government: ["government", "diplomatic", "embassy", "military", "defense"],
    Financial: ["financial", "banking", "finance", "cryptocurrency"],
    Healthcare: ["healthcare", "health", "pharmaceutical"],
    Energy: ["energy", "oil", "gas", "utility"],
    Technology: ["technology", "software", "telecom"],
    Education: ["education", "university", "academic"],
    Manufacturing: ["manufacturing", "industrial", "ics", "scada"],
  };
  const out: string[] = [];
  for (const [sector, kws] of Object.entries(map)) {
    if (kws.some(k => d.includes(k))) out.push(sector);
  }
  return out;
}

function detectActorType(name: string, desc: string): "apt" | "cybercrime" | "ransomware" | "hacktivist" | "unknown" {
  const d = (name + " " + desc).toLowerCase();
  if (d.includes("ransomware")) return "ransomware";
  if (d.includes("financially motivated") || d.includes("cybercrime") || d.includes("financial gain")) return "cybercrime";
  if (d.includes("hacktivist") || d.includes("activist")) return "hacktivist";
  return "apt";
}

// ─── 1. MITRE ATT&CK STIX ───────────────────────────────────────────────────

const MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";

export async function ingestMitreAttack(): Promise<IngestionResult> {
  const start = Date.now();
  const r: IngestionResult = { source: "MITRE ATT&CK", groupsIngested: 0, groupsUpdated: 0, ttpsIngested: 0, eventsIngested: 0, errors: [], duration: 0 };

  try {
    const resp = await fetch(MITRE_STIX_URL, { signal: AbortSignal.timeout(60000) });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const bundle = await resp.json() as { objects: any[] };

    const groups: MitreIntrusionSet[] = [];
    const rels: MitreRelationship[] = [];
    const patterns = new Map<string, MitreAttackPattern>();

    for (const obj of bundle.objects) {
      if (obj.type === "intrusion-set" && !obj.revoked && !obj.x_mitre_deprecated) groups.push(obj);
      else if (obj.type === "relationship" && obj.relationship_type === "uses") rels.push(obj);
      else if (obj.type === "attack-pattern" && !obj.revoked && !obj.x_mitre_deprecated) patterns.set(obj.id, obj);
    }

    // Build group→technique map
    const groupTechs = new Map<string, Array<{ id: string; name: string; tactic: string }>>();
    for (const rel of rels) {
      if (!rel.source_ref.startsWith("intrusion-set--")) continue;
      const p = patterns.get(rel.target_ref);
      if (!p) continue;
      const extRef = p.external_references?.find(e => e.source_name === "mitre-attack");
      if (!extRef?.external_id) continue;
      const tactic = p.kill_chain_phases?.find(k => k.kill_chain_name === "mitre-attack")?.phase_name || "unknown";
      if (!groupTechs.has(rel.source_ref)) groupTechs.set(rel.source_ref, []);
      groupTechs.get(rel.source_ref)!.push({ id: extRef.external_id, name: p.name, tactic });
    }

    const db = await requireDb();

    for (const g of groups) {
      try {
        const mitreRef = g.external_references?.find(e => e.source_name === "mitre-attack");
        const mitreId = mitreRef?.external_id || "";
        const actorIdSlug = slugify(g.name);
        const techs = groupTechs.get(g.id) || [];
        const desc = g.description || "";
        const nation = detectNation(desc);
        const sectors = detectSectors(desc);
        const actorType = detectActorType(g.name, desc);
        const sophistication = techs.length > 30 ? "nation-state" : techs.length > 15 ? "advanced" : "intermediate";

        // Check if exists by stixId or actorId
        const existing = await db.select().from(threatActors)
          .where(sql`${threatActors.stixId} = ${g.id} OR ${threatActors.actorId} = ${actorIdSlug}`)
          .limit(1);

        if (existing.length > 0) {
          await db.update(threatActors).set({
            description: desc.length > (existing[0].description || "").length ? desc : existing[0].description,
            aliases: JSON.stringify(g.aliases || []),
            techniques: JSON.stringify(techs),
            targetSectors: JSON.stringify(sectors.length > 0 ? sectors : (Array.isArray(existing[0].targetSectors) ? existing[0].targetSectors : JSON.parse(existing[0].targetSectors as string || "[]"))),
            origin: nation || existing[0].origin,
            stixId: g.id,
            lastActive: g.modified.slice(0, 10),
            dataSource: (existing[0].dataSource || "").includes("mitre") ? existing[0].dataSource : `${existing[0].dataSource || ""},mitre-attack`.replace(/^,/, ""),
          }).where(eq(threatActors.id, existing[0].id));
          r.groupsUpdated++;
        } else {
          await db.insert(threatActors).values({
            actorId: actorIdSlug,
            name: g.name,
            actorType: actorType,
            description: desc || `${g.name} is a threat group tracked by MITRE ATT&CK.`,
            aliases: JSON.stringify(g.aliases || []),
            origin: nation,
            motivation: actorType === "ransomware" ? "financial" : actorType === "apt" ? "espionage" : null,
            firstSeen: g.created.slice(0, 10),
            lastActive: g.modified.slice(0, 10),
            threatLevel: techs.length > 25 ? "critical" : techs.length > 10 ? "high" : "medium",
            sophistication,
            targetSectors: JSON.stringify(sectors),
            targetRegions: JSON.stringify([]),
            techniques: JSON.stringify(techs),
            tools: JSON.stringify([]),
            malware: JSON.stringify([]),
            activityTimeline: JSON.stringify([]),
            stixId: g.id,
            dataSource: "mitre-attack",
            confidence: 95,
          });
          r.groupsIngested++;
        }
        r.ttpsIngested += techs.length;
      } catch (err: any) {
        r.errors.push(`${g.name}: ${err.message}`);
      }
    }

    await db.insert(threatIntelUpdates).values({
      sweepType: "manual",
      tiuStatus: "completed",
      groupsScanned: groups.length,
      updatesApplied: r.groupsIngested + r.groupsUpdated,
      newTtpsFound: r.ttpsIngested,
      tiuSummary: `MITRE ATT&CK: ${r.groupsIngested} new, ${r.groupsUpdated} updated, ${r.ttpsIngested} TTPs`,
      tiuDetails: JSON.stringify({ source: "mitre-attack", intrusionSets: groups.length }),
      durationMs: Date.now() - start,
    });
  } catch (err: any) {
    r.errors.push(`MITRE ingestion failed: ${err.message}`);
  }

  r.duration = Date.now() - start;
  return r;
}

// ─── 2. Ransomware.live ─────────────────────────────────────────────────────

const RW_GROUPS_URL = "https://api.ransomware.live/groups";
const RW_VICTIMS_URL = "https://api.ransomware.live/recentvictims";

export async function ingestRansomwareLive(): Promise<IngestionResult> {
  const start = Date.now();
  const r: IngestionResult = { source: "Ransomware.live", groupsIngested: 0, groupsUpdated: 0, ttpsIngested: 0, eventsIngested: 0, errors: [], duration: 0 };

  try {
    const resp = await fetch(RW_GROUPS_URL, { signal: AbortSignal.timeout(30000) });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const groups = await resp.json() as RansomwareLiveGroup[];

    const db = await requireDb();

    for (const g of groups) {
      try {
        if (!g.name) continue;
        const displayName = g.name.charAt(0).toUpperCase() + g.name.slice(1);
        const actorIdSlug = slugify(g.name);
        const desc = (g.description || "").replace(/<BR>/gi, "\n").trim();
        const onionSites = (g.locations || []).filter(l => l.fqdn).map(l => l.fqdn);
        const isActive = (g.locations || []).some(l => l.available);

        // Upsert into master catalog (threatActors)
        const existing = await db.select().from(threatActors)
          .where(eq(threatActors.actorId, actorIdSlug))
          .limit(1);

        if (existing.length > 0) {
          const updates: Record<string, any> = {};
          if (desc.length > (existing[0].description || "").length) updates.description = desc;
          if (!(existing[0].dataSource || "").includes("ransomware.live")) {
            updates.dataSource = `${existing[0].dataSource || ""},ransomware.live`.replace(/^,/, "");
          }
          if (Object.keys(updates).length > 0) {
            await db.update(threatActors).set(updates).where(eq(threatActors.id, existing[0].id));
          }
          r.groupsUpdated++;
        } else {
          await db.insert(threatActors).values({
            actorId: actorIdSlug,
            name: displayName,
            actorType: "ransomware",
            description: desc || `${displayName} is a ransomware group tracked by Ransomware.live.`,
            aliases: JSON.stringify([g.name]),
            motivation: "financial",
            threatLevel: "high",
            sophistication: "intermediate",
            targetSectors: JSON.stringify([]),
            targetRegions: JSON.stringify([]),
            techniques: JSON.stringify([]),
            tools: JSON.stringify(g.tools || []),
            malware: JSON.stringify([]),
            activityTimeline: JSON.stringify([]),
            dataSource: "ransomware.live",
            confidence: 85,
          });
          r.groupsIngested++;
        }

        // Upsert into ransomwareGroups extension
        const existingRg = await db.select().from(ransomwareGroups)
          .where(eq(ransomwareGroups.groupName, displayName))
          .limit(1);

        if (existingRg.length === 0) {
          await db.insert(ransomwareGroups).values({
            groupName: displayName,
            aliases: JSON.stringify([g.name]),
            description: desc || null,
            activityScore: isActive ? 60 : 20,
            trend: isActive ? "active" : "dormant",
            threatLevel: "high",
            knownInfrastructure: JSON.stringify(onionSites),
            associatedMalware: JSON.stringify(g.tools || []),
            extortionModel: "double",
            dataSource: "ransomware.live",
            confidence: 85,
          });
        } else {
          await db.update(ransomwareGroups).set({
            knownInfrastructure: JSON.stringify(onionSites),
            trend: isActive ? "active" : "dormant",
            activityScore: isActive ? Math.max(existingRg[0].activityScore || 0, 60) : existingRg[0].activityScore,
          }).where(eq(ransomwareGroups.id, existingRg[0].id));
        }
      } catch (err: any) {
        r.errors.push(`${g.name}: ${err.message}`);
      }
    }

    // Fetch recent victims → threatGroupEvents
    try {
      const vResp = await fetch(RW_VICTIMS_URL, { signal: AbortSignal.timeout(30000) });
      if (vResp.ok) {
        const victims = await vResp.json() as RansomwareLiveVictim[];
        for (const v of victims) {
          try {
            const actorIdSlug = slugify(v.group_name || "");
            const actor = await db.select().from(threatActors)
              .where(eq(threatActors.actorId, actorIdSlug))
              .limit(1);
            if (actor.length === 0) continue;

            // Dedup
            const dup = await db.select({ id: threatGroupEvents.id }).from(threatGroupEvents)
              .where(sql`${threatGroupEvents.tgeActorId} = ${actorIdSlug} AND ${threatGroupEvents.tgeTitle} = ${v.post_title || "Unknown"}`)
              .limit(1);
            if (dup.length > 0) continue;

            await db.insert(threatGroupEvents).values({
              tgeActorId: actorIdSlug,
              eventType: "attack",
              tgeTitle: v.post_title || "Unknown victim",
              tgeDescription: v.description || `Victim posted by ${v.group_name}`,
              tgeSeverity: "high",
              tgeVictimName: v.post_title,
              tgeVictimCountry: v.country || null,
              tgeSource: "ransomware.live",
              tgeSourceUrl: v.post_url || null,
              tgeConfidence: 90,
              eventDate: v.discovered ? new Date(v.discovered) : new Date(),
            });
            r.eventsIngested++;
          } catch (_) { /* skip */ }
        }
      }
    } catch (err: any) {
      r.errors.push(`Victims: ${err.message}`);
    }

    await db.insert(threatIntelUpdates).values({
      sweepType: "manual",
      tiuStatus: "completed",
      groupsScanned: groups.length,
      updatesApplied: r.groupsIngested + r.groupsUpdated,
      newEventsFound: r.eventsIngested,
      tiuSummary: `Ransomware.live: ${r.groupsIngested} new, ${r.groupsUpdated} updated, ${r.eventsIngested} victim events`,
      tiuDetails: JSON.stringify({ source: "ransomware.live", totalGroups: groups.length }),
      durationMs: Date.now() - start,
    });
  } catch (err: any) {
    r.errors.push(`Ransomware.live failed: ${err.message}`);
  }

  r.duration = Date.now() - start;
  return r;
}

// ─── 3. Malpedia (Public List) ───────────────────────────────────────────────

// Use the enriched /api/get/actors endpoint which returns descriptions, country, synonyms, etc.
const MALPEDIA_URL = "https://malpedia.caad.fkie.fraunhofer.de/api/get/actors";

function classifyActorType(name: string, meta: any): "apt" | "cybercrime" | "ransomware" | "hacktivist" | "access_broker" | "influence_ops" | "unknown" {
  const lower = name.toLowerCase();
  const rawClassification = meta?.["threat-actor-classification"];
  const classification = (typeof rawClassification === "string" ? rawClassification : Array.isArray(rawClassification) ? rawClassification.join(" ") : "").toLowerCase();
  if (lower.includes("ransom") || classification.includes("ransom")) return "ransomware";
  if (lower.includes("apt") || classification.includes("apt") || classification.includes("nation-state")) return "apt";
  if (classification.includes("hacktivist")) return "hacktivist";
  if (classification.includes("crime") || classification.includes("criminal")) return "cybercrime";
  if (meta?.["cfr-suspected-state-sponsor"]) return "apt";
  return "unknown";
}

function extractOrigin(meta: any): string | null {
  if (meta?.country) return meta.country;
  const sponsor = meta?.["cfr-suspected-state-sponsor"];
  if (sponsor) {
    // Map common names to ISO codes
    const map: Record<string, string> = {
      "russian federation": "RU", "russia": "RU",
      "china": "CN", "people's republic of china": "CN",
      "korea (democratic people's republic of)": "KP", "north korea": "KP",
      "iran, islamic republic of": "IR", "iran": "IR",
      "israel": "IL", "united states": "US", "united states of america": "US",
      "vietnam": "VN", "india": "IN", "pakistan": "PK", "turkey": "TR",
      "united arab emirates": "AE", "lebanon": "LB", "ukraine": "UA",
    };
    return map[sponsor.toLowerCase()] || sponsor;
  }
  return null;
}

function extractMotivation(meta: any): string | null {
  if (meta?.motive) return meta.motive;
  const incidents = meta?.["cfr-type-of-incident"] || [];
  if (incidents.length > 0) {
    const types = Array.isArray(incidents) ? incidents : [incidents];
    if (types.some((t: string) => t.toLowerCase().includes("espionage"))) return "espionage";
    if (types.some((t: string) => t.toLowerCase().includes("financial"))) return "financial";
    if (types.some((t: string) => t.toLowerCase().includes("destruct"))) return "disruption";
  }
  return null;
}

export async function ingestMalpedia(): Promise<IngestionResult> {
  const start = Date.now();
  const r: IngestionResult = { source: "Malpedia", groupsIngested: 0, groupsUpdated: 0, ttpsIngested: 0, eventsIngested: 0, errors: [], duration: 0 };

  try {
    const resp = await fetch(MALPEDIA_URL, { signal: AbortSignal.timeout(60000) });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const actorsMap = await resp.json() as Record<string, any>;

    // /api/get/actors returns { "ActorName": { description, meta, uuid, value }, ... }
    const entries = Object.entries(actorsMap);
    const db = await requireDb();

    for (const [displayName, data] of entries) {
      try {
        const meta = data?.meta || {};
        const actorIdSlug = slugify(displayName);

        // Build aliases from synonyms + value field
        const synonyms: string[] = Array.isArray(meta.synonyms) ? meta.synonyms : [];
        const allAliases = [displayName, ...synonyms].filter(Boolean);

        // Extract enrichment fields
        const origin = extractOrigin(meta);
        const motivation = extractMotivation(meta);
        const actorType = classifyActorType(displayName, meta);
        const description = data?.description || `${displayName} is a threat actor tracked by Malpedia.`;
        const targetSectors = Array.isArray(meta["targeted-sector"]) ? meta["targeted-sector"] :
          Array.isArray(meta["cfr-target-category"]) ? meta["cfr-target-category"] : [];
        const targetRegions = Array.isArray(meta["cfr-suspected-victims"]) ? meta["cfr-suspected-victims"] :
          Array.isArray(meta["suspected-victims"]) ? meta["suspected-victims"] : [];
        const firstSeen = meta.since || null;
        const stixId = data?.uuid ? `threat-actor--${data.uuid}` : null;
        const confidence = meta["attribution-confidence"] ? parseInt(meta["attribution-confidence"], 10) : 70;

        const existing = await db.select().from(threatActors)
          .where(eq(threatActors.actorId, actorIdSlug))
          .limit(1);

        if (existing.length > 0) {
          // Update existing entry with richer Malpedia data if it was sparse
          const updates: any = {};
          const ex = existing[0];
          if (!ex.description || ex.description.endsWith("tracked by Malpedia.")) updates.description = description;
          if (!ex.origin && origin) updates.origin = origin;
          if (!ex.motivation && motivation) updates.motivation = motivation;
          if (!ex.firstSeen && firstSeen) updates.firstSeen = firstSeen;
          if (!ex.stixId && stixId) updates.stixId = stixId;
          if (ex.actorType === "unknown" || ex.actorType === "apt") updates.actorType = actorType;
          if (targetSectors.length > 0 && (!ex.targetSectors || JSON.stringify(ex.targetSectors) === "[]")) {
            updates.targetSectors = JSON.stringify(targetSectors);
          }
          if (targetRegions.length > 0 && (!ex.targetRegions || JSON.stringify(ex.targetRegions) === "[]")) {
            updates.targetRegions = JSON.stringify(targetRegions);
          }
          // Merge aliases
          const existingAliases: string[] = Array.isArray(ex.aliases) ? ex.aliases :
            (typeof ex.aliases === "string" ? JSON.parse(ex.aliases || "[]") : []);
          const mergedAliases = Array.from(new Set([...existingAliases, ...allAliases]));
          updates.aliases = JSON.stringify(mergedAliases);

          if (!(ex.dataSource || "").includes("malpedia")) {
            updates.dataSource = `${ex.dataSource || ""},malpedia`.replace(/^,/, "");
          }

          if (Object.keys(updates).length > 0) {
            await db.update(threatActors).set(updates).where(eq(threatActors.id, ex.id));
            r.groupsUpdated++;
          }
        } else {
          await db.insert(threatActors).values({
            actorId: actorIdSlug,
            name: displayName,
            actorType: actorType,
            origin,
            description,
            motivation,
            firstSeen,
            stixId,
            aliases: JSON.stringify(allAliases),
            sophistication: meta["cfr-suspected-state-sponsor"] ? "nation-state" : "intermediate",
            targetSectors: JSON.stringify(targetSectors),
            targetRegions: JSON.stringify(targetRegions),
            techniques: JSON.stringify([]),
            tools: JSON.stringify([]),
            malware: JSON.stringify([]),
            activityTimeline: JSON.stringify([]),
            dataSource: "malpedia",
            confidence: Math.min(confidence, 100),
          });
          r.groupsIngested++;
        }
      } catch (err: any) {
        r.errors.push(`${displayName}: ${err.message}`);
      }
    }

    await db.insert(threatIntelUpdates).values({
      sweepType: "manual",
      tiuStatus: "completed",
      groupsScanned: entries.length,
      updatesApplied: r.groupsIngested + r.groupsUpdated,
      tiuSummary: `Malpedia: ${r.groupsIngested} new, ${r.groupsUpdated} enriched/cross-referenced`,
      tiuDetails: JSON.stringify({ source: "malpedia", totalActors: entries.length }),
      durationMs: Date.now() - start,
    });
  } catch (err: any) {
    r.errors.push(`Malpedia failed: ${err.message}`);
  }

  r.duration = Date.now() - start;
  return r;
}

// ─── 4. Caldera Adversary Sync ───────────────────────────────────────────────

export async function ingestCalderaAdversaries(): Promise<IngestionResult> {
  const start = Date.now();
  const r: IngestionResult = { source: "MITRE Caldera", groupsIngested: 0, groupsUpdated: 0, ttpsIngested: 0, eventsIngested: 0, errors: [], duration: 0 };

  try {
    const calderaUrl = ENV.calderaBaseUrl;
    const calderaKey = ENV.calderaApiKey;
    if (!calderaKey) throw new Error("CALDERA_API_KEY not configured");

    const advResp = await fetch(`${calderaUrl}/api/v2/adversaries`, {
      headers: { KEY: calderaKey },
      signal: AbortSignal.timeout(15000),
    });
    if (!advResp.ok) throw new Error(`HTTP ${advResp.status}`);
    const adversaries = await advResp.json() as CalderaAdversary[];

    // Fetch abilities for technique mapping
    const abMap = new Map<string, CalderaAbility>();
    try {
      const abResp = await fetch(`${calderaUrl}/api/v2/abilities`, {
        headers: { KEY: calderaKey },
        signal: AbortSignal.timeout(15000),
      });
      if (abResp.ok) {
        const abs = await abResp.json() as CalderaAbility[];
        for (const a of abs) abMap.set(a.ability_id, a);
      }
    } catch (_) { /* optional */ }

    const db = await requireDb();
    const seen = new Set<string>();

    for (const adv of adversaries) {
      try {
        const name = adv.name.replace(/\s*\(G\d+\)\s*$/, "").trim();
        if (seen.has(name.toLowerCase())) continue;
        seen.add(name.toLowerCase());

        const actorIdSlug = slugify(name);
        const techs: Array<{ id: string; name: string; tactic: string }> = [];
        for (const abId of adv.atomic_ordering) {
          const ab = abMap.get(abId);
          if (ab?.technique_id) {
            techs.push({ id: ab.technique_id, name: ab.technique_name || ab.name, tactic: ab.tactic });
          }
        }

        const existing = await db.select().from(threatActors)
          .where(eq(threatActors.actorId, actorIdSlug))
          .limit(1);

        if (existing.length > 0) {
          const updates: Record<string, any> = {};
          if (!(existing[0].dataSource || "").includes("caldera")) {
            updates.dataSource = `${existing[0].dataSource || ""},caldera`.replace(/^,/, "");
          }
          // Merge techniques — Drizzle may return a parsed array or a JSON string
          const rawTechs = existing[0].techniques;
          const existTechs: any[] = Array.isArray(rawTechs) ? rawTechs
            : typeof rawTechs === "string" ? JSON.parse(rawTechs || "[]")
            : [];
          const existIds = new Set(existTechs.map((t: any) => typeof t === "string" ? t : t.id));
          const newTechs = techs.filter(t => !existIds.has(t.id));
          if (newTechs.length > 0) {
            updates.techniques = JSON.stringify([...existTechs, ...newTechs]);
          }
          // Store Caldera profile
          updates.calderaProfile = JSON.stringify({
            adversaryId: adv.adversary_id,
            atomicOrdering: adv.atomic_ordering,
            abilityCount: adv.atomic_ordering.length,
          });

          if (Object.keys(updates).length > 0) {
            await db.update(threatActors).set(updates).where(eq(threatActors.id, existing[0].id));
          }
          r.groupsUpdated++;
        } else {
          await db.insert(threatActors).values({
            actorId: actorIdSlug,
            name,
            actorType: "apt",
            description: adv.description || `${name} adversary profile from MITRE Caldera with ${adv.atomic_ordering.length} abilities.`,
            aliases: JSON.stringify([adv.name]),
            sophistication: adv.atomic_ordering.length > 20 ? "advanced" : "intermediate",
            targetSectors: JSON.stringify([]),
            targetRegions: JSON.stringify([]),
            techniques: JSON.stringify(techs),
            tools: JSON.stringify([]),
            malware: JSON.stringify([]),
            calderaProfile: JSON.stringify({
              adversaryId: adv.adversary_id,
              atomicOrdering: adv.atomic_ordering,
              abilityCount: adv.atomic_ordering.length,
            }),
            activityTimeline: JSON.stringify([]),
            dataSource: "caldera",
            confidence: 90,
          });
          r.groupsIngested++;
        }
        r.ttpsIngested += techs.length;
      } catch (err: any) {
        r.errors.push(`${adv.name}: ${err.message}`);
      }
    }

    await db.insert(threatIntelUpdates).values({
      sweepType: "manual",
      tiuStatus: "completed",
      groupsScanned: adversaries.length,
      updatesApplied: r.groupsIngested + r.groupsUpdated,
      newTtpsFound: r.ttpsIngested,
      tiuSummary: `Caldera: ${r.groupsIngested} new, ${r.groupsUpdated} updated, ${r.ttpsIngested} abilities mapped`,
      tiuDetails: JSON.stringify({ source: "caldera", totalAdversaries: adversaries.length, abilities: abMap.size }),
      durationMs: Date.now() - start,
    });
  } catch (err: any) {
    r.errors.push(`Caldera failed: ${err.message}`);
  }

  r.duration = Date.now() - start;
  return r;
}

// ─── Full Catalog Sync ──────────────────────────────────────────────────────

export async function runFullCatalogSync(): Promise<{
  results: IngestionResult[];
  totalGroups: number;
  totalNew: number;
  totalUpdated: number;
  totalDuration: number;
}> {
  const results: IngestionResult[] = [];

  results.push(await ingestMitreAttack());
  results.push(await ingestRansomwareLive());
  results.push(await ingestMalpedia());
  results.push(await ingestCalderaAdversaries());

  const totalNew = results.reduce((s, r) => s + r.groupsIngested, 0);
  const totalUpdated = results.reduce((s, r) => s + r.groupsUpdated, 0);
  const totalDuration = results.reduce((s, r) => s + r.duration, 0);

  const db = await requireDb();
  const cnt = await db.select({ count: sql<number>`count(*)` }).from(threatActors);

  return { results, totalGroups: cnt[0]?.count || 0, totalNew, totalUpdated, totalDuration };
}

// ─── Auto-Discovery Hook ────────────────────────────────────────────────────
// Called from any pipeline that discovers a new threat actor name.

export async function ensureActorInCatalog(actorName: string, metadata?: {
  type?: "apt" | "cybercrime" | "ransomware" | "hacktivist" | "access_broker" | "influence_ops";
  description?: string;
  nationState?: string;
  ttps?: string[];
  source?: string;
}): Promise<string> {
  const db = await requireDb();
  const actorIdSlug = slugify(actorName);

  const existing = await db.select().from(threatActors)
    .where(eq(threatActors.actorId, actorIdSlug))
    .limit(1);

  if (existing.length > 0) {
    if (metadata?.ttps) {
      const rawTechs = existing[0].techniques;
      const existTechs: any[] = Array.isArray(rawTechs) ? rawTechs : typeof rawTechs === "string" ? JSON.parse(rawTechs || "[]") : [];
      const existIds = new Set(existTechs.map((t: any) => typeof t === "string" ? t : t.id));
      const newTtps = (metadata.ttps || []).filter(t => !existIds.has(t));
      if (newTtps.length > 0) {
        await db.update(threatActors).set({
          techniques: JSON.stringify([...existTechs, ...newTtps.map(t => ({ id: t, name: t, tactic: "unknown" }))]),
        }).where(eq(threatActors.id, existing[0].id));
      }
    }
    return existing[0].actorId;
  }

  await db.insert(threatActors).values({
    actorId: actorIdSlug,
    name: actorName,
    actorType: metadata?.type || "unknown",
    description: metadata?.description || `${actorName} — auto-discovered threat actor.`,
    aliases: JSON.stringify([]),
    origin: metadata?.nationState || null,
    sophistication: "intermediate",
    targetSectors: JSON.stringify([]),
    targetRegions: JSON.stringify([]),
    techniques: JSON.stringify((metadata?.ttps || []).map(t => ({ id: t, name: t, tactic: "unknown" }))),
    tools: JSON.stringify([]),
    malware: JSON.stringify([]),
    activityTimeline: JSON.stringify([]),
    dataSource: metadata?.source || "auto-discovery",
    confidence: 50,
  });

  await db.insert(threatIntelUpdates).values({
    sweepType: "triggered",
    tiuStatus: "completed",
    groupsScanned: 1,
    updatesApplied: 1,
    tiuSummary: `Auto-discovered: ${actorName}`,
    durationMs: 0,
  });

  return actorIdSlug;
}

// ─── Catalog Stats ──────────────────────────────────────────────────────────

export async function getCatalogStats() {
  const db = await requireDb();

  const actors = await db.select({
    actorType: threatActors.actorType,
    dataSource: threatActors.dataSource,
    origin: threatActors.origin,
    threatLevel: threatActors.threatLevel,
  }).from(threatActors);

  const byType: Record<string, number> = {};
  const bySource: Record<string, number> = {};
  const byNation: Record<string, number> = {};
  const byThreatLevel: Record<string, number> = {};

  for (const a of actors) {
    byType[a.actorType || "unknown"] = (byType[a.actorType || "unknown"] || 0) + 1;
    for (const s of (a.dataSource || "unknown").split(",")) {
      const src = s.trim();
      bySource[src] = (bySource[src] || 0) + 1;
    }
    if (a.origin) byNation[a.origin] = (byNation[a.origin] || 0) + 1;
    byThreatLevel[a.threatLevel || "medium"] = (byThreatLevel[a.threatLevel || "medium"] || 0) + 1;
  }

  const recentUpdates = await db.select({ count: sql<number>`count(*)` })
    .from(threatIntelUpdates)
    .where(sql`${threatIntelUpdates.tiuStartedAt} > DATE_SUB(NOW(), INTERVAL 24 HOUR)`);

  const lastSync = await db.select({ completedAt: threatIntelUpdates.tiuCompletedAt })
    .from(threatIntelUpdates)
    .where(eq(threatIntelUpdates.tiuStatus, "completed"))
    .orderBy(sql`${threatIntelUpdates.tiuCompletedAt} DESC`)
    .limit(1);

  return {
    totalActors: actors.length,
    byType,
    bySource,
    byNation,
    byThreatLevel,
    recentUpdates: recentUpdates[0]?.count || 0,
    lastSync: lastSync[0]?.completedAt || null,
  };
}
