/**
 * IAB (Initial Access Broker) Ingestion Service
 *
 * Automated pipeline that enriches the access_broker_listings table from
 * multiple threat intelligence sources:
 *
 *   1. ransomware.live — Groups with IAB connections, victim data with sector/country
 *   2. RansomLook — Darkweb market monitoring, 563+ groups, 144 markets
 *   3. CISA KEV — Known exploited vulnerabilities commonly used by IABs
 *
 * All feeds are clearnet — no Tor router required.
 *
 * NOTE: LLM enrichment has been DISABLED. All data must come from
 * verifiable, traceable sources for law enforcement referral purposes.
 * No AI-generated or simulated data is permitted in this pipeline.
 */

import { getDb } from "../db";
import {
  accessBrokerListings,
  type InsertAccessBrokerListing,
} from "../../drizzle/schema";
import { sql, eq } from "drizzle-orm";
// LLM enrichment DISABLED — all data must be traceable for LE referral
// import { invokeLLM } from "../_core/llm";

// ─── Types ──────────────────────────────────────────────────────────────

interface IABIngestionResult {
  source: string;
  fetched: number;
  inserted: number;
  skipped: number;
  error?: string;
  durationMs: number;
}

interface IABIngestionSummary {
  startedAt: Date;
  completedAt: Date;
  results: IABIngestionResult[];
  totalInserted: number;
  totalErrors: number;
}

// ─── Helpers ────────────────────────────────────────────────────────────

async function safeFetch(url: string, opts: RequestInit = {}, timeoutMs = 30000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function generateBrokerId(source: string, name: string): string {
  return `${source}:${name.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 60)}`;
}

// ─── Source 1: ransomware.live Groups with IAB Connections ──────────────

async function ingestRansomwareLiveGroups(): Promise<IABIngestionResult> {
  const start = Date.now();
  const source = "ransomware_live_groups";
  try {
    const res = await safeFetch("https://api.ransomware.live/v1/groups", {}, 60000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const groups = await res.json() as any[];
    if (!Array.isArray(groups)) throw new Error("Response is not an array");

    const db = await getDb();

    // Filter groups that have IAB-related characteristics
    const iabGroups = groups.filter((g: any) => {
      const str = JSON.stringify(g).toLowerCase();
      return (
        str.includes("initial access") ||
        str.includes("access broker") ||
        str.includes("access-as-a-service") ||
        str.includes("iab") ||
        str.includes("sells access") ||
        str.includes("selling access") ||
        str.includes("vpn access") ||
        str.includes("rdp access") ||
        str.includes("citrix") ||
        str.includes("webshell") ||
        str.includes("domain admin access")
      );
    });

    // Also include groups that explicitly list tools used by IABs
    const toolGroups = groups.filter((g: any) => {
      const tools = (g.tools || []).map((t: any) => (typeof t === 'string' ? t : t.name || '').toLowerCase());
      return tools.some((t: string) =>
        t.includes("cobalt strike") || t.includes("brute ratel") ||
        t.includes("sliver") || t.includes("systembc") ||
        t.includes("metasploit") || t.includes("anydesk")
      );
    });

    // Merge and deduplicate
    const allIabGroups = [...new Map(
      [...iabGroups, ...toolGroups].map(g => [g.name, g])
    ).values()];

    let inserted = 0;
    let skipped = 0;

    for (const group of allIabGroups) {
      const brokerId = generateBrokerId("rl", group.name);

      // Check if already exists
      const existing = await db.select({ id: accessBrokerListings.id })
        .from(accessBrokerListings)
        .where(eq(accessBrokerListings.brokerId, brokerId))
        .limit(1);

      if (existing.length > 0) {
        skipped++;
        continue;
      }

      // Determine listing type from group profile
      const desc = (group.description || '').toLowerCase();
      let listingType: InsertAccessBrokerListing['listingType'] = 'other';
      if (desc.includes('vpn')) listingType = 'vpn_access';
      else if (desc.includes('rdp')) listingType = 'rdp_access';
      else if (desc.includes('citrix')) listingType = 'citrix_access';
      else if (desc.includes('webshell')) listingType = 'webshell';
      else if (desc.includes('domain admin')) listingType = 'domain_admin';
      else if (desc.includes('credential')) listingType = 'credential_dump';
      else if (desc.includes('exploit') || desc.includes('zero-day')) listingType = 'zero_day';

      // Extract locations as victim countries (locations are objects with fqdn/title/type)
      const locations = group.locations || [];
      const country = Array.isArray(locations) && locations.length > 0
        ? locations.slice(0, 3).map((loc: any) => {
            if (typeof loc === 'string') return loc;
            return loc.title || loc.slug || loc.fqdn || 'unknown';
          }).join(', ').slice(0, 128)
        : undefined;

      const tools = (group.tools || []).map((t: any) => typeof t === 'string' ? t : t.name || '').filter(Boolean);

      // Safely extract accessType as a string (group.type can be an object like {raas: true})
      let accessType = 'unknown';
      if (typeof group.type === 'string') {
        accessType = group.type.slice(0, 128);
      } else if (group.type && typeof group.type === 'object') {
        // Extract keys that are true, e.g. {raas: true} → "raas"
        const types = Object.entries(group.type)
          .filter(([_, v]) => v === true)
          .map(([k]) => k);
        accessType = types.length > 0 ? types.join(', ').slice(0, 128) : 'unknown';
      }

      const listing: InsertAccessBrokerListing = {
        brokerId,
        brokerName: group.name,
        aliases: group.altname ? [group.altname] : [],
        listingType,
        accessType,
        victimCountry: country,
        forumSource: "ransomware.live",
        brokerReputation: (group._victim_count || 0) > 50 ? 'established' : (group._victim_count || 0) > 10 ? 'rising' : 'new',
        totalListings: group._victim_count || 0,
        linkedRansomwareGroups: group.lineage ? [typeof group.lineage === 'string' ? group.lineage : JSON.stringify(group.lineage)] : [],
        mitreTechniques: tools.length > 0 ? tools : undefined,
        iabStatus: 'active',
        iabFirstSeen: group.date || undefined,
        iabDataSource: "ransomware.live/v1/groups",
        iabConfidence: 65,
        iabDescription: (group.description || '').slice(0, 2000),
        iabRawData: group,
      };

      await db.insert(accessBrokerListings).values(listing);
      inserted++;
    }

    return { source, fetched: allIabGroups.length, inserted, skipped, durationMs: Date.now() - start };
  } catch (err: any) {
    return { source, fetched: 0, inserted: 0, skipped: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── Source 2: ransomware.live Recent Victims → IAB Attribution ─────────

async function ingestVictimIABAttribution(): Promise<IABIngestionResult> {
  const start = Date.now();
  const source = "ransomware_live_victim_attribution";
  try {
    const res = await safeFetch("https://api.ransomware.live/v1/recentvictims", {}, 60000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const victims = await res.json() as any[];
    if (!Array.isArray(victims)) throw new Error("Response is not an array");

    const db = await getDb();

    // Group victims by ransomware group to identify which groups are most active
    const groupActivity: Record<string, { count: number; sectors: Set<string>; countries: Set<string>; victims: any[] }> = {};
    for (const v of victims) {
      const gn = v.group_name || 'unknown';
      if (!groupActivity[gn]) {
        groupActivity[gn] = { count: 0, sectors: new Set(), countries: new Set(), victims: [] };
      }
      groupActivity[gn].count++;
      if (v.activity && v.activity !== 'Not Found') groupActivity[gn].sectors.add(v.activity);
      if (v.country) groupActivity[gn].countries.add(v.country);
      groupActivity[gn].victims.push(v);
    }

    let inserted = 0;
    let skipped = 0;

    // For each active group, create/update an IAB listing with sector targeting data
    for (const [groupName, activity] of Object.entries(groupActivity)) {
      if (activity.count < 2) continue; // Skip groups with only 1 victim (not enough data)

      const brokerId = generateBrokerId("rl-attr", groupName);

      const existing = await db.select({ id: accessBrokerListings.id })
        .from(accessBrokerListings)
        .where(eq(accessBrokerListings.brokerId, brokerId))
        .limit(1);

      if (existing.length > 0) {
        skipped++;
        continue;
      }

      const topSectors = [...activity.sectors].slice(0, 5);
      const topCountries = [...activity.countries].slice(0, 5);

      const listing: InsertAccessBrokerListing = {
        brokerId,
        brokerName: `${groupName} (victim attribution)`,
        listingType: 'other',
        accessType: 'ransomware_affiliate',
        victimSector: topSectors.join(', ') || undefined,
        victimCountry: topCountries.join(', ') || undefined,
        forumSource: "ransomware.live",
        brokerReputation: activity.count > 10 ? 'established' : activity.count > 3 ? 'rising' : 'new',
        totalListings: activity.count,
        linkedRansomwareGroups: [groupName],
        iabStatus: 'active',
        iabDataSource: "ransomware.live/v1/recentvictims",
        iabConfidence: 55,
        iabDescription: `Active ransomware group "${groupName}" with ${activity.count} recent victims across sectors: ${topSectors.join(', ') || 'unknown'}. Countries: ${topCountries.join(', ') || 'unknown'}.`,
        iabRawData: {
          groupName,
          victimCount: activity.count,
          sectors: [...activity.sectors],
          countries: [...activity.countries],
          sampleVictims: activity.victims.slice(0, 5).map(v => ({
            title: v.post_title,
            sector: v.activity,
            country: v.country,
            published: v.published,
          })),
        },
      };

      await db.insert(accessBrokerListings).values(listing);
      inserted++;
    }

    return { source, fetched: Object.keys(groupActivity).length, inserted, skipped, durationMs: Date.now() - start };
  } catch (err: any) {
    return { source, fetched: 0, inserted: 0, skipped: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── Source 3: CISA KEV → IAB Exploit Vectors ───────────────────────────

async function ingestCISAKEVExploits(): Promise<IABIngestionResult> {
  const start = Date.now();
  const source = "cisa_kev_exploits";
  try {
    const res = await safeFetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", {}, 60000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json() as any;
    const vulns = data.vulnerabilities || [];

    const db = await getDb();

    // Filter for recent KEVs that are commonly used by IABs (VPN, RDP, web-facing)
    const iabRelevantKeywords = [
      'vpn', 'rdp', 'remote desktop', 'citrix', 'fortinet', 'fortigate',
      'pulse secure', 'sonicwall', 'palo alto', 'cisco asa', 'exchange',
      'outlook', 'sharepoint', 'confluence', 'jira', 'gitlab', 'jenkins',
      'webshell', 'remote code execution', 'authentication bypass',
      'privilege escalation', 'initial access',
    ];

    // Only take KEVs from the last 12 months
    const cutoffDate = new Date();
    cutoffDate.setFullYear(cutoffDate.getFullYear() - 1);

    const recentIABVulns = vulns.filter((v: any) => {
      const addedDate = new Date(v.dateAdded);
      if (addedDate < cutoffDate) return false;
      const str = `${v.vendorProject} ${v.product} ${v.shortDescription} ${v.vulnerabilityName}`.toLowerCase();
      return iabRelevantKeywords.some(k => str.includes(k));
    });

    let inserted = 0;
    let skipped = 0;

    for (const vuln of recentIABVulns.slice(0, 100)) {
      const brokerId = generateBrokerId("kev", vuln.cveID);

      const existing = await db.select({ id: accessBrokerListings.id })
        .from(accessBrokerListings)
        .where(eq(accessBrokerListings.brokerId, brokerId))
        .limit(1);

      if (existing.length > 0) {
        skipped++;
        continue;
      }

      // Determine listing type from vulnerability
      const desc = `${vuln.vendorProject} ${vuln.product} ${vuln.shortDescription}`.toLowerCase();
      let listingType: InsertAccessBrokerListing['listingType'] = 'exploit_kit';
      if (desc.includes('vpn') || desc.includes('fortinet') || desc.includes('pulse') || desc.includes('sonicwall')) listingType = 'vpn_access';
      else if (desc.includes('rdp') || desc.includes('remote desktop')) listingType = 'rdp_access';
      else if (desc.includes('citrix')) listingType = 'citrix_access';
      else if (desc.includes('webshell') || desc.includes('web shell')) listingType = 'webshell';
      else if (desc.includes('zero-day') || desc.includes('0day')) listingType = 'zero_day';

      const listing: InsertAccessBrokerListing = {
        brokerId,
        brokerName: `${vuln.cveID} (${vuln.vendorProject} ${vuln.product})`,
        listingType,
        accessType: 'exploit_vector',
        victimSector: 'Cross-sector',
        forumSource: "CISA KEV",
        brokerReputation: 'established',
        mitreTechniques: vuln.knownRansomwareCampaignUse === 'Known' ? ['T1190', 'T1133'] : ['T1190'],
        iabStatus: 'active',
        iabFirstSeen: vuln.dateAdded,
        iabDataSource: "cisa.gov/kev",
        iabConfidence: vuln.knownRansomwareCampaignUse === 'Known' ? 90 : 70,
        iabDescription: `${vuln.vulnerabilityName}: ${vuln.shortDescription}. Vendor: ${vuln.vendorProject} ${vuln.product}. ${vuln.knownRansomwareCampaignUse === 'Known' ? 'KNOWN ransomware campaign use.' : ''} Required action: ${vuln.requiredAction || 'Apply vendor patch'}`,
        iabRawData: vuln,
      };

      await db.insert(accessBrokerListings).values(listing);
      inserted++;
    }

    return { source, fetched: recentIABVulns.length, inserted, skipped, durationMs: Date.now() - start };
  } catch (err: any) {
    return { source, fetched: 0, inserted: 0, skipped: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── Source 4: RansomLook Markets → IAB Marketplace Monitoring ──────────

async function ingestRansomLookMarkets(): Promise<IABIngestionResult> {
  const start = Date.now();
  const source = "ransomlook_markets";
  try {
    const res = await safeFetch("https://www.ransomlook.io/api/markets", {}, 30000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const markets = await res.json() as string[];
    if (!Array.isArray(markets)) throw new Error("Response is not an array");

    const db = await getDb();

    // Filter for markets that are likely IAB-related
    const iabKeywords = ['access', 'market', 'shop', 'store', 'exploit', 'cred', 'leak', 'breach', 'dark'];
    const iabMarkets = markets.filter(m => {
      const name = m.toLowerCase();
      return iabKeywords.some(k => name.includes(k));
    });

    let inserted = 0;
    let skipped = 0;

    for (const marketName of iabMarkets) {
      const brokerId = generateBrokerId("rlm", marketName);

      const existing = await db.select({ id: accessBrokerListings.id })
        .from(accessBrokerListings)
        .where(eq(accessBrokerListings.brokerId, brokerId))
        .limit(1);

      if (existing.length > 0) {
        skipped++;
        continue;
      }

      const listing: InsertAccessBrokerListing = {
        brokerId,
        brokerName: marketName,
        listingType: 'other',
        accessType: 'darkweb_market',
        forumSource: "RansomLook",
        brokerReputation: 'unknown',
        iabStatus: 'active',
        iabDataSource: "ransomlook.io/api/markets",
        iabConfidence: 40,
        iabDescription: `Darkweb marketplace "${marketName}" tracked by RansomLook. May host IAB listings, credential dumps, or exploit kits.`,
        iabRawData: { marketName, source: 'ransomlook' },
      };

      await db.insert(accessBrokerListings).values(listing);
      inserted++;
    }

    return { source, fetched: iabMarkets.length, inserted, skipped, durationMs: Date.now() - start };
  } catch (err: any) {
    return { source, fetched: 0, inserted: 0, skipped: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── LLM Enrichment: PERMANENTLY DISABLED ──────────────────────────────
// All data in this pipeline must come from verifiable, traceable sources
// for law enforcement referral purposes. LLM-generated data is not permitted.

async function enrichWithLLM(_rawListings: any[]): Promise<IABIngestionResult> {
  console.warn("[IAB-Ingestion] LLM enrichment is DISABLED — all data must be traceable for LE referral. Skipping.");
  return {
    source: 'llm_enrichment',
    fetched: 0,
    inserted: 0,
    skipped: 0,
    durationMs: 0,
  };
}

// ─── Main Ingestion Pipeline ────────────────────────────────────────────

export async function runIABIngestionPipeline(): Promise<IABIngestionSummary> {
  const startedAt = new Date();
  console.log("[IAB-Ingestion] Starting automated IAB data ingestion pipeline...");

  const results: IABIngestionResult[] = [];

  // Phase 1: Ingest from external sources (parallel)
  const [groupsResult, victimsResult, kevResult, marketsResult] = await Promise.allSettled([
    ingestRansomwareLiveGroups(),
    ingestVictimIABAttribution(),
    ingestCISAKEVExploits(),
    ingestRansomLookMarkets(),
  ]);

  for (const r of [groupsResult, victimsResult, kevResult, marketsResult]) {
    if (r.status === 'fulfilled') {
      results.push(r.value);
    } else {
      results.push({
        source: 'unknown',
        fetched: 0,
        inserted: 0,
        skipped: 0,
        error: r.reason?.message || 'Promise rejected',
        durationMs: 0,
      });
    }
  }

  // Phase 2: LLM enrichment DISABLED — all data must be traceable for LE referral
  // No AI-generated or simulated data is permitted in this pipeline.

  const completedAt = new Date();
  const totalInserted = results.reduce((sum, r) => sum + r.inserted, 0);
  const totalErrors = results.filter(r => r.error).length;

  console.log(`[IAB-Ingestion] Pipeline complete: ${totalInserted} new listings from ${results.length} sources (${totalErrors} errors)`);
  results.forEach(r => {
    console.log(`  - ${r.source}: ${r.inserted} inserted, ${r.skipped} skipped, ${r.fetched} fetched (${r.durationMs}ms)${r.error ? ` ERROR: ${r.error}` : ''}`);
  });

  return { startedAt, completedAt, results, totalInserted, totalErrors };
}

// ─── Individual source exports for selective ingestion ──────────────────

export {
  ingestRansomwareLiveGroups,
  ingestVictimIABAttribution,
  ingestCISAKEVExploits,
  ingestRansomLookMarkets,
  enrichWithLLM,
};
