import {
  getDb,
  init_db
} from "./chunk-JP5I5SRV.js";
import {
  accessBrokerListings,
  init_schema
} from "./chunk-FLBHZBVD.js";

// server/lib/shodan-ics-ingestion.ts
init_db();
init_schema();
import { eq } from "drizzle-orm";
var SHODAN_API_KEY = process.env.SHODAN_API_KEY || "";
async function shodanFetch(endpoint, params = {}) {
  const url = new URL(`https://api.shodan.io${endpoint}`);
  url.searchParams.set("key", SHODAN_API_KEY);
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3e4);
  try {
    const res = await fetch(url.toString(), { signal: controller.signal });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`Shodan HTTP ${res.status}: ${text.slice(0, 200)}`);
    }
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}
function generateBrokerId(source, name) {
  return `${source}:${name.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 60)}`;
}
var ICS_PROTOCOLS = [
  {
    name: "Modbus",
    port: 502,
    query: "port:502 country:US",
    description: "Modbus TCP \u2014 used in manufacturing, water treatment, power generation, oil & gas",
    severity: "critical"
  },
  {
    name: "Siemens S7",
    port: 102,
    query: "port:102 country:US",
    description: "Siemens S7comm \u2014 PLCs in manufacturing, power plants, water systems, chemical processing",
    severity: "critical"
  },
  {
    name: "BACnet",
    port: 47808,
    query: "port:47808 country:US",
    description: "BACnet \u2014 building automation, HVAC, access control, fire systems in government/commercial buildings",
    severity: "high"
  },
  {
    name: "DNP3",
    port: 2e4,
    query: "port:20000 country:US",
    description: "DNP3 \u2014 electric utilities, water/wastewater, oil & gas SCADA systems",
    severity: "critical"
  },
  {
    name: "EtherNet/IP",
    port: 44818,
    query: "port:44818 country:US",
    description: "EtherNet/IP (CIP) \u2014 Rockwell/Allen-Bradley PLCs in manufacturing and critical infrastructure",
    severity: "critical"
  },
  {
    name: "Niagara Fox",
    port: 1911,
    query: "port:1911 country:US",
    description: "Niagara Fox \u2014 Tridium building automation, widely used in government facilities",
    severity: "high"
  }
];
var GOV_DEFENSE_QUERIES = [
  {
    name: "US Gov RDP Exposed",
    query: 'port:3389 org:"Department of" country:US',
    category: "us_gov",
    description: "US government departments with exposed RDP \u2014 high-value IAB targets for remote access sales"
  },
  {
    name: "US Gov VPN Exposed",
    query: 'ssl:"gov" port:443 product:"Fortinet" country:US',
    category: "us_gov",
    description: "US government Fortinet VPN endpoints \u2014 commonly exploited by IABs (CVE-2024-21762, CVE-2023-27997)"
  },
  {
    name: "US Gov Citrix Exposed",
    query: 'ssl:"gov" product:"Citrix" country:US',
    category: "us_gov",
    description: "US government Citrix gateways \u2014 IAB exploit vector (CVE-2023-4966 Citrix Bleed)"
  },
  {
    name: "US Gov Exchange Exposed",
    query: 'http.title:"Outlook" org:"government" country:US',
    category: "us_gov",
    description: "US government Exchange/Outlook Web Access \u2014 ProxyShell/ProxyLogon IAB targets"
  },
  {
    name: "Defense Contractor RDP",
    query: 'port:3389 org:"defense" country:US',
    category: "defense_contractor",
    description: "Defense sector organizations with exposed RDP \u2014 DIB targets for IAB credential sales"
  },
  {
    name: "Defense Contractor VPN",
    query: 'org:"defense" product:"Fortinet" country:US',
    category: "defense_contractor",
    description: "Defense sector Fortinet VPN endpoints \u2014 high-value IAB targets with potential classified access"
  },
  {
    name: "Military Exposed Services",
    query: 'org:"military" country:US has_vuln:true',
    category: "defense_contractor",
    description: "US military-affiliated hosts with known vulnerabilities \u2014 critical IAB interest"
  }
];
async function ingestShodanICSExposure() {
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
        const countData = await shodanFetch("/shodan/host/count", {
          query: protocol.query,
          facets: "org:10,country:5"
        });
        fetched++;
        const brokerId = generateBrokerId("shodan-ics", `${protocol.name}-us-exposure`);
        const existing = await db.select({ id: accessBrokerListings.id }).from(accessBrokerListings).where(eq(accessBrokerListings.brokerId, brokerId)).limit(1);
        if (existing.length > 0) {
          const orgFacets2 = countData.facets?.org || [];
          const topOrgs2 = orgFacets2.slice(0, 10).map((f) => `${f.value} (${f.count})`).join(", ");
          await db.update(accessBrokerListings).set({
            iabDescription: `[LIVE] ${countData.total.toLocaleString()} exposed ${protocol.name} devices in the US (port ${protocol.port}). ${protocol.description}. Top organizations: ${topOrgs2}. Last scanned: ${(/* @__PURE__ */ new Date()).toISOString().split("T")[0]}.`,
            totalListings: countData.total,
            iabRawData: {
              protocol: protocol.name,
              port: protocol.port,
              query: protocol.query,
              total: countData.total,
              facets: countData.facets,
              lastUpdated: (/* @__PURE__ */ new Date()).toISOString()
            },
            updatedAt: /* @__PURE__ */ new Date()
          }).where(eq(accessBrokerListings.brokerId, brokerId));
          skipped++;
          continue;
        }
        const orgFacets = countData.facets?.org || [];
        const topOrgs = orgFacets.slice(0, 10).map((f) => `${f.value} (${f.count})`).join(", ");
        const listing = {
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
          iabFirstSeen: (/* @__PURE__ */ new Date()).toISOString().split("T")[0],
          iabDataSource: `shodan.io/search?query=${encodeURIComponent(protocol.query)}`,
          iabConfidence: 85,
          iabDescription: `[LIVE] ${countData.total.toLocaleString()} exposed ${protocol.name} devices in the US (port ${protocol.port}). ${protocol.description}. Top organizations: ${topOrgs}. These represent potential IAB targets \u2014 exposed ICS/SCADA devices are routinely sold on darkweb forums for $5K-$50K+.`,
          iabRawData: {
            protocol: protocol.name,
            port: protocol.port,
            query: protocol.query,
            total: countData.total,
            facets: countData.facets,
            lastUpdated: (/* @__PURE__ */ new Date()).toISOString()
          }
        };
        await db.insert(accessBrokerListings).values(listing);
        inserted++;
        await new Promise((r) => setTimeout(r, 1200));
      } catch (err) {
        console.warn(`[Shodan-ICS] Error querying ${protocol.name}: ${err.message}`);
      }
    }
    return { source, fetched, inserted, skipped, durationMs: Date.now() - start };
  } catch (err) {
    return { source, fetched: 0, inserted: 0, skipped: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function ingestShodanGovDefenseExposure() {
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
        const countData = await shodanFetch("/shodan/host/count", {
          query: gq.query,
          facets: "org:10,vuln:5"
        });
        fetched++;
        const brokerId = generateBrokerId("shodan-gov", gq.name);
        const existing = await db.select({ id: accessBrokerListings.id }).from(accessBrokerListings).where(eq(accessBrokerListings.brokerId, brokerId)).limit(1);
        if (existing.length > 0) {
          const orgFacets2 = countData.facets?.org || [];
          const vulnFacets2 = countData.facets?.vuln || [];
          const topOrgs2 = orgFacets2.slice(0, 10).map((f) => `${f.value} (${f.count})`).join(", ");
          const topVulns2 = vulnFacets2.slice(0, 5).map((f) => f.value).join(", ");
          await db.update(accessBrokerListings).set({
            iabDescription: `[LIVE] ${countData.total} exposed hosts matching "${gq.name}". ${gq.description}. Organizations: ${topOrgs2 || "N/A"}. ${topVulns2 ? `Top CVEs: ${topVulns2}.` : ""} Last scanned: ${(/* @__PURE__ */ new Date()).toISOString().split("T")[0]}.`,
            totalListings: countData.total,
            iabRawData: {
              queryName: gq.name,
              query: gq.query,
              category: gq.category,
              total: countData.total,
              facets: countData.facets,
              lastUpdated: (/* @__PURE__ */ new Date()).toISOString()
            },
            updatedAt: /* @__PURE__ */ new Date()
          }).where(eq(accessBrokerListings.brokerId, brokerId));
          skipped++;
          continue;
        }
        const orgFacets = countData.facets?.org || [];
        const vulnFacets = countData.facets?.vuln || [];
        const topOrgs = orgFacets.slice(0, 10).map((f) => `${f.value} (${f.count})`).join(", ");
        const topVulns = vulnFacets.slice(0, 5).map((f) => f.value).join(", ");
        const listing = {
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
          iabFirstSeen: (/* @__PURE__ */ new Date()).toISOString().split("T")[0],
          iabDataSource: `shodan.io/search?query=${encodeURIComponent(gq.query)}`,
          iabConfidence: 80,
          iabDescription: `[LIVE] ${countData.total} exposed hosts matching "${gq.name}". ${gq.description}. Organizations: ${topOrgs || "N/A"}. ${topVulns ? `Top CVEs: ${topVulns}.` : ""} These represent the attack surface available to IABs targeting ${gq.category === "us_gov" ? "US government" : "defense sector"} networks.`,
          iabRawData: {
            queryName: gq.name,
            query: gq.query,
            category: gq.category,
            total: countData.total,
            facets: countData.facets,
            lastUpdated: (/* @__PURE__ */ new Date()).toISOString()
          }
        };
        await db.insert(accessBrokerListings).values(listing);
        inserted++;
        await new Promise((r) => setTimeout(r, 1200));
      } catch (err) {
        console.warn(`[Shodan-Gov] Error querying ${gq.name}: ${err.message}`);
      }
    }
    return { source, fetched, inserted, skipped, durationMs: Date.now() - start };
  } catch (err) {
    return { source, fetched: 0, inserted: 0, skipped: 0, error: err.message, durationMs: Date.now() - start };
  }
}
async function runShodanIngestion() {
  console.log("[Shodan] Starting ICS/SCADA and Gov/Defense exposure monitoring...");
  const results = [];
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

export {
  ingestShodanICSExposure,
  ingestShodanGovDefenseExposure,
  runShodanIngestion
};
