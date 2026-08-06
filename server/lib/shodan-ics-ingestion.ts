/**
 * Shodan ICS/SCADA & Government Exposure Monitoring
 *
 * Pulls real-time data from Shodan to identify:
 *   1. ICS/SCADA exposed devices (Modbus, S7, BACnet, DNP3) in the US
 *   2. Government hosts with known vulnerabilities (RDP, VPN, web)
 *   3. Defense contractor hosts with known vulnerabilities
 *
 * All data is real, sourced from Shodan's internet-wide scanning.
 * Every listing includes the Shodan query, IP count, and org breakdown
 * for full traceability and law enforcement referral.
 *
 * NOTE: We do NOT store individual IPs in the IAB listings table.
 * We store aggregate exposure summaries that indicate attack surface
 * available to IABs. Individual IPs are available via Shodan directly.
 */

import { getDb } from "../db";
import {
  accessBrokerListings,
  type InsertAccessBrokerListing,
} from "../../drizzle/schema";
import { eq } from "drizzle-orm";

// ─── Types ──────────────────────────────────────────────────────────────

interface ShodanIngestionResult {
  source: string;
  fetched: number;
  inserted: number;
  skipped: number;
  error?: string;
  durationMs: number;
}

interface ShodanCountResponse {
  total: number;
  facets?: Record<string, Array<{ value: string; count: number }>>;
}

interface ShodanSearchResponse {
  total: number;
  matches: Array<{
    ip_str: string;
    port: number;
    org?: string;
    os?: string;
    product?: string;
    vulns?: string[];
    data?: string;
    timestamp?: string;
    hostnames?: string[];
    domains?: string[];
  }>;
  facets?: Record<string, Array<{ value: string; count: number }>>;
}

// ─── Helpers ────────────────────────────────────────────────────────────

const SHODAN_API_KEY = process.env.SHODAN_API_KEY || "";

async function shodanFetch<T>(endpoint: string, params: Record<string, string> = {}): Promise<T> {
  const url = new URL(`https://api.shodan.io${endpoint}`);
  url.searchParams.set("key", SHODAN_API_KEY);
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);
  try {
    const res = await fetch(url.toString(), { signal: controller.signal });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`Shodan HTTP ${res.status}: ${text.slice(0, 200)}`);
    }
    return await res.json() as T;
  } finally {
    clearTimeout(timer);
  }
}

function generateBrokerId(source: string, name: string): string {
  return `${source}:${name.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 60)}`;
}

// ─── ICS/SCADA Protocol Queries ─────────────────────────────────────────

interface ICSProtocol {
  name: string;
  port: number;
  query: string;
  description: string;
  severity: string;
}

const ICS_PROTOCOLS: ICSProtocol[] = [
  {
    name: "Modbus",
    port: 502,
    query: "port:502 country:US",
    description: "Modbus TCP — used in manufacturing, water treatment, power generation, oil & gas",
    severity: "critical",
  },
  {
    name: "Siemens S7",
    port: 102,
    query: "port:102 country:US",
    description: "Siemens S7comm — PLCs in manufacturing, power plants, water systems, chemical processing",
    severity: "critical",
  },
  {
    name: "BACnet",
    port: 47808,
    query: "port:47808 country:US",
    description: "BACnet — building automation, HVAC, access control, fire systems in government/commercial buildings",
    severity: "high",
  },
  {
    name: "DNP3",
    port: 20000,
    query: "port:20000 country:US",
    description: "DNP3 — electric utilities, water/wastewater, oil & gas SCADA systems",
    severity: "critical",
  },
  {
    name: "EtherNet/IP",
    port: 44818,
    query: "port:44818 country:US",
    description: "EtherNet/IP (CIP) — Rockwell/Allen-Bradley PLCs in manufacturing and critical infrastructure",
    severity: "critical",
  },
  {
    name: "Niagara Fox",
    port: 1911,
    query: "port:1911 country:US",
    description: "Niagara Fox — Tridium building automation, widely used in government facilities",
    severity: "high",
  },
];

// ─── Government & Defense Queries ───────────────────────────────────────

interface GovDefenseQuery {
  name: string;
  query: string;
  category: "us_gov" | "defense_contractor" | "ics_scada";
  description: string;
}

const GOV_DEFENSE_QUERIES: GovDefenseQuery[] = [
  {
    name: "US Gov RDP Exposed",
    query: 'port:3389 org:"Department of" country:US',
    category: "us_gov",
    description: "US government departments with exposed RDP — high-value IAB targets for remote access sales",
  },
  {
    name: "US Gov VPN Exposed",
    query: 'ssl:"gov" port:443 product:"Fortinet" country:US',
    category: "us_gov",
    description: "US government Fortinet VPN endpoints — commonly exploited by IABs (CVE-2024-21762, CVE-2023-27997)",
  },
  {
    name: "US Gov Citrix Exposed",
    query: 'ssl:"gov" product:"Citrix" country:US',
    category: "us_gov",
    description: "US government Citrix gateways — IAB exploit vector (CVE-2023-4966 Citrix Bleed)",
  },
  {
    name: "US Gov Exchange Exposed",
    query: 'http.title:"Outlook" org:"government" country:US',
    category: "us_gov",
    description: "US government Exchange/Outlook Web Access — ProxyShell/ProxyLogon IAB targets",
  },
  {
    name: "Defense Contractor RDP",
    query: 'port:3389 org:"defense" country:US',
    category: "defense_contractor",
    description: "Defense sector organizations with exposed RDP — DIB targets for IAB credential sales",
  },
  {
    name: "Defense Contractor VPN",
    query: 'org:"defense" product:"Fortinet" country:US',
    category: "defense_contractor",
    description: "Defense sector Fortinet VPN endpoints — high-value IAB targets with potential classified access",
  },
  {
    name: "Military Exposed Services",
    query: 'org:"military" country:US has_vuln:true',
    category: "defense_contractor",
    description: "US military-affiliated hosts with known vulnerabilities — critical IAB interest",
  },
];

// ─── Source 6a: ICS/SCADA Exposure Monitoring ───────────────────────────

export async function ingestShodanICSExposure(): Promise<ShodanIngestionResult> {
  const start = Date.now();
  const source = "shodan_ics_scada";

  if (!SHODAN_API_KEY) {
    return { source, fetched: 0, inserted: 0, skipped: 0, error: "SHODAN_API_KEY not configured", durationMs: Date.now() - start };
  }

  try {
    const db = await getDb();
    let inserted = 0;
    let skipped = 0;
    let fetched = 0;

    for (const protocol of ICS_PROTOCOLS) {
      try {
        // Use /shodan/host/count with facets for efficient querying (doesn't consume search credits)
        const countData = await shodanFetch<ShodanCountResponse>("/shodan/host/count", {
          query: protocol.query,
          facets: "org:10,country:5",
        });

        fetched++;

        const brokerId = generateBrokerId("shodan-ics", `${protocol.name}-us-exposure`);

        // Check if already exists
        const existing = await db.select({ id: accessBrokerListings.id })
          .from(accessBrokerListings)
          .where(eq(accessBrokerListings.brokerId, brokerId))
          .limit(1);

        if (existing.length > 0) {
          // Update the existing record with fresh data
          const orgFacets = countData.facets?.org || [];
          const topOrgs = orgFacets.slice(0, 10).map(f => `${f.value} (${f.count})`).join(", ");

          await db.update(accessBrokerListings)
            .set({
              iabDescription: `[LIVE] ${countData.total.toLocaleString()} exposed ${protocol.name} devices in the US (port ${protocol.port}). ${protocol.description}. Top organizations: ${topOrgs}. Last scanned: ${new Date().toISOString().split("T")[0]}.`,
              totalListings: countData.total,
              iabRawData: {
                protocol: protocol.name,
                port: protocol.port,
                query: protocol.query,
                total: countData.total,
                facets: countData.facets,
                lastUpdated: new Date().toISOString(),
              },
              updatedAt: new Date(),
            })
            .where(eq(accessBrokerListings.brokerId, brokerId));
          skipped++;
          continue;
        }

        const orgFacets = countData.facets?.org || [];
        const topOrgs = orgFacets.slice(0, 10).map(f => `${f.value} (${f.count})`).join(", ");

        const listing: InsertAccessBrokerListing = {
          brokerId,
          brokerName: `Shodan: ${protocol.name} Exposure (US)`,
          listingType: "other",
          accessType: "ics_scada_exposure",
          victimSector: "Critical Infrastructure, Energy, Manufacturing, Water",
          victimCountry: "US",
          forumSource: "Shodan",
          brokerReputation: "established",
          totalListings: countData.total,
          iabStatus: "active",
          iabFirstSeen: new Date().toISOString().split("T")[0],
          iabDataSource: `shodan.io/search?query=${encodeURIComponent(protocol.query)}`,
          iabConfidence: 85,
          iabDescription: `[LIVE] ${countData.total.toLocaleString()} exposed ${protocol.name} devices in the US (port ${protocol.port}). ${protocol.description}. Top organizations: ${topOrgs}. These represent potential IAB targets — exposed ICS/SCADA devices are routinely sold on darkweb forums for $5K-$50K+.`,
          iabRawData: {
            protocol: protocol.name,
            port: protocol.port,
            query: protocol.query,
            total: countData.total,
            facets: countData.facets,
            lastUpdated: new Date().toISOString(),
          },
        };

        await db.insert(accessBrokerListings).values(listing);
        inserted++;

        // Rate limit: Shodan basic plan allows 1 req/sec
        await new Promise(r => setTimeout(r, 1200));
      } catch (err: any) {
        console.warn(`[Shodan-ICS] Error querying ${protocol.name}: ${err.message}`);
      }
    }

    return { source, fetched, inserted, skipped, durationMs: Date.now() - start };
  } catch (err: any) {
    return { source, fetched: 0, inserted: 0, skipped: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── Source 6b: Government & Defense Exposure Monitoring ─────────────────

export async function ingestShodanGovDefenseExposure(): Promise<ShodanIngestionResult> {
  const start = Date.now();
  const source = "shodan_gov_defense";

  if (!SHODAN_API_KEY) {
    return { source, fetched: 0, inserted: 0, skipped: 0, error: "SHODAN_API_KEY not configured", durationMs: Date.now() - start };
  }

  try {
    const db = await getDb();
    let inserted = 0;
    let skipped = 0;
    let fetched = 0;

    for (const gq of GOV_DEFENSE_QUERIES) {
      try {
        // Use count endpoint with facets for efficient querying
        const countData = await shodanFetch<ShodanCountResponse>("/shodan/host/count", {
          query: gq.query,
          facets: "org:10,vuln:5",
        });

        fetched++;

        const brokerId = generateBrokerId("shodan-gov", gq.name);

        const existing = await db.select({ id: accessBrokerListings.id })
          .from(accessBrokerListings)
          .where(eq(accessBrokerListings.brokerId, brokerId))
          .limit(1);

        if (existing.length > 0) {
          // Update existing with fresh counts
          const orgFacets = countData.facets?.org || [];
          const vulnFacets = countData.facets?.vuln || [];
          const topOrgs = orgFacets.slice(0, 10).map(f => `${f.value} (${f.count})`).join(", ");
          const topVulns = vulnFacets.slice(0, 5).map(f => f.value).join(", ");

          await db.update(accessBrokerListings)
            .set({
              iabDescription: `[LIVE] ${countData.total} exposed hosts matching "${gq.name}". ${gq.description}. Organizations: ${topOrgs || "N/A"}. ${topVulns ? `Top CVEs: ${topVulns}.` : ""} Last scanned: ${new Date().toISOString().split("T")[0]}.`,
              totalListings: countData.total,
              iabRawData: {
                queryName: gq.name,
                query: gq.query,
                category: gq.category,
                total: countData.total,
                facets: countData.facets,
                lastUpdated: new Date().toISOString(),
              },
              updatedAt: new Date(),
            })
            .where(eq(accessBrokerListings.brokerId, brokerId));
          skipped++;
          continue;
        }

        const orgFacets = countData.facets?.org || [];
        const vulnFacets = countData.facets?.vuln || [];
        const topOrgs = orgFacets.slice(0, 10).map(f => `${f.value} (${f.count})`).join(", ");
        const topVulns = vulnFacets.slice(0, 5).map(f => f.value).join(", ");

        const listing: InsertAccessBrokerListing = {
          brokerId,
          brokerName: `Shodan: ${gq.name}`,
          listingType: gq.query.includes("3389") ? "rdp_access" : gq.query.includes("Fortinet") ? "vpn_access" : gq.query.includes("Citrix") ? "citrix_access" : "other",
          accessType: `${gq.category}_exposure`,
          victimSector: gq.category === "us_gov" ? "Government" : "Defense",
          victimCountry: "US",
          forumSource: "Shodan",
          brokerReputation: "established",
          totalListings: countData.total,
          iabStatus: "active",
          iabFirstSeen: new Date().toISOString().split("T")[0],
          iabDataSource: `shodan.io/search?query=${encodeURIComponent(gq.query)}`,
          iabConfidence: 80,
          iabDescription: `[LIVE] ${countData.total} exposed hosts matching "${gq.name}". ${gq.description}. Organizations: ${topOrgs || "N/A"}. ${topVulns ? `Top CVEs: ${topVulns}.` : ""} These represent the attack surface available to IABs targeting ${gq.category === "us_gov" ? "US government" : "defense sector"} networks.`,
          iabRawData: {
            queryName: gq.name,
            query: gq.query,
            category: gq.category,
            total: countData.total,
            facets: countData.facets,
            lastUpdated: new Date().toISOString(),
          },
        };

        await db.insert(accessBrokerListings).values(listing);
        inserted++;

        // Rate limit
        await new Promise(r => setTimeout(r, 1200));
      } catch (err: any) {
        console.warn(`[Shodan-Gov] Error querying ${gq.name}: ${err.message}`);
      }
    }

    return { source, fetched, inserted, skipped, durationMs: Date.now() - start };
  } catch (err: any) {
    return { source, fetched: 0, inserted: 0, skipped: 0, error: err.message, durationMs: Date.now() - start };
  }
}

// ─── Combined Shodan Ingestion ──────────────────────────────────────────

export async function runShodanIngestion(): Promise<ShodanIngestionResult[]> {
  console.log("[Shodan] Starting ICS/SCADA and Gov/Defense exposure monitoring...");

  const results: ShodanIngestionResult[] = [];

  // Run sequentially to respect Shodan rate limits (1 req/sec on basic plan)
  const icsResult = await ingestShodanICSExposure();
  results.push(icsResult);
  console.log(`[Shodan] ICS/SCADA: ${icsResult.inserted} new, ${icsResult.skipped} updated, ${icsResult.fetched} queried${icsResult.error ? ` ERROR: ${icsResult.error}` : ""}`);

  const govResult = await ingestShodanGovDefenseExposure();
  results.push(govResult);
  console.log(`[Shodan] Gov/Defense: ${govResult.inserted} new, ${govResult.skipped} updated, ${govResult.fetched} queried${govResult.error ? ` ERROR: ${govResult.error}` : ""}`);

  const totalInserted = results.reduce((s, r) => s + r.inserted, 0);
  const totalUpdated = results.reduce((s, r) => s + r.skipped, 0);
  console.log(`[Shodan] Complete: ${totalInserted} new listings, ${totalUpdated} updated`);

  return results;
}
