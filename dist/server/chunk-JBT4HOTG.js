import {
  getDb,
  init_db
} from "./chunk-L5ZLWR7T.js";
import {
  aptIcsMappings,
  icsExploits,
  incidentReports,
  init_schema,
  threatActors,
  threatGroupEvents
} from "./chunk-L4JENJ4Z.js";
import {
  __esm,
  __export
} from "./chunk-KFQGP6VL.js";

// server/lib/ics-scada-intel.ts
var ics_scada_intel_exports = {};
__export(ics_scada_intel_exports, {
  ICS_MALWARE_FAMILIES: () => ICS_MALWARE_FAMILIES,
  ICS_OPEN_SOURCE_TOOLS: () => ICS_OPEN_SOURCE_TOOLS,
  autoTagIcsActors: () => autoTagIcsActors,
  crossMapIcsMalwareToActors: () => crossMapIcsMalwareToActors,
  getIcsKeywords: () => getIcsKeywords,
  getIcsMalwareFamilies: () => getIcsMalwareFamilies,
  getIcsOpenSourceTools: () => getIcsOpenSourceTools,
  getIcsVendors: () => getIcsVendors,
  ingestCisaCsafOt: () => ingestCisaCsafOt,
  ingestCisaIcsAdvisories: () => ingestCisaIcsAdvisories,
  ingestSiemensProductCert: () => ingestSiemensProductCert,
  runIcsScadaIntelIngest: () => runIcsScadaIntelIngest
});
import { eq, sql } from "drizzle-orm";
async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}
async function safeFetch(url, opts, timeoutMs = 3e4) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}
function hashString(s) {
  let hash = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s.charCodeAt(i);
    hash = (hash << 5) - hash + ch;
    hash |= 0;
  }
  return Math.abs(hash).toString(36);
}
function slugify(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 80);
}
async function ingestCisaIcsAdvisories() {
  const start = Date.now();
  const result = { source: "CISA ICS Advisories", fetched: 0, newRecords: 0, errors: [], durationMs: 0 };
  try {
    const db = await requireDb();
    const feedUrl = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml";
    const res = await safeFetch(feedUrl, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; AC3-ThreatIntel/1.0)" }
    }, 3e4);
    if (!res.ok) {
      result.errors.push(`CISA ICS feed returned ${res.status}`);
      result.durationMs = Date.now() - start;
      return result;
    }
    const xml = await res.text();
    const items = parseRssItems(xml);
    result.fetched = items.length;
    for (const item of items.slice(0, 50)) {
      try {
        const icsaMatch = item.title.match(/ICSA-\d{2}-\d{3}-\d{2}/i) || item.link.match(/icsa-\d{2}-\d{3}-\d{2}/i);
        const advisoryId = icsaMatch ? icsaMatch[0].toUpperCase() : `CISA-ICS-${hashString(item.link)}`;
        const vendor = extractVendorFromTitle(item.title);
        const text = `${item.title} ${item.description}`.toLowerCase();
        let severity = "medium";
        if (text.includes("critical") || text.includes("cvss 9") || text.includes("cvss 10")) severity = "critical";
        else if (text.includes("high") || text.includes("remote code execution") || text.includes("rce")) severity = "high";
        const cveMatches = `${item.title} ${item.description}`.match(/CVE-\d{4}-\d{4,}/gi) || [];
        const uniqueCves = Array.from(new Set(cveMatches.map((c) => c.toUpperCase())));
        await db.insert(icsExploits).values({
          iceCveId: uniqueCves[0] || null,
          iceIcsCertAdvisoryId: advisoryId,
          iceTitle: item.title.slice(0, 500),
          iceDescription: item.description?.slice(0, 5e3) || "",
          iceAffectedVendor: vendor,
          iceAffectedProduct: extractProductFromTitle(item.title, vendor),
          iceCvssScore: extractCvssFromText(text),
          iceSafetyImpact: text.includes("safety") ? "high" : "none",
          iceAvailabilityImpact: text.includes("denial of service") || text.includes("dos") ? "high" : "medium",
          iceProcessIntegrityImpact: text.includes("code execution") || text.includes("manipulation") ? "high" : "medium",
          icePhysicalImpact: text.includes("physical") || text.includes("safety") ? 1 : 0,
          iceExploitAvailable: text.includes("exploit") || text.includes("poc") ? 1 : 0,
          icePublishedDate: item.pubDate || (/* @__PURE__ */ new Date()).toISOString(),
          iceSector: detectIcsSectors(text),
          iceReferences: [item.link]
        }).onDuplicateKeyUpdate({ set: { iceDescription: item.description?.slice(0, 5e3) || "" } });
        await db.insert(incidentReports).values({
          sourceId: advisoryId,
          source: "CISA ICS Advisory",
          title: item.title,
          url: item.link,
          publishedAt: item.pubDate,
          summary: item.description?.slice(0, 2e3) || "",
          cvesMentioned: uniqueCves,
          targetSectors: detectIcsSectors(text),
          incidentType: "ics_advisory",
          irSeverity: severity
        }).onDuplicateKeyUpdate({ set: { irUpdatedAt: sql`NOW()` } });
        result.newRecords++;
      } catch (err) {
      }
    }
  } catch (err) {
    result.errors.push(`CISA ICS ingest error: ${err.message}`);
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function ingestCisaCsafOt() {
  const start = Date.now();
  const result = { source: "CISA CSAF OT", fetched: 0, newRecords: 0, errors: [], durationMs: 0 };
  try {
    const db = await requireDb();
    const year = (/* @__PURE__ */ new Date()).getFullYear();
    const apiUrl = `https://api.github.com/repos/cisagov/CSAF/contents/csaf_files/OT/white/${year}`;
    const res = await safeFetch(apiUrl, {
      headers: {
        "User-Agent": "AC3-ThreatIntel/1.0",
        "Accept": "application/vnd.github.v3+json"
      }
    }, 2e4);
    if (!res.ok) {
      result.errors.push(`CSAF GitHub API returned ${res.status}`);
      result.durationMs = Date.now() - start;
      return result;
    }
    const files = await res.json();
    const jsonFiles = files.filter((f) => f.name.endsWith(".json")).slice(-30);
    result.fetched = jsonFiles.length;
    for (const file of jsonFiles) {
      try {
        const fileRes = await safeFetch(file.download_url, {
          headers: { "User-Agent": "AC3-ThreatIntel/1.0" }
        }, 15e3);
        if (!fileRes.ok) continue;
        const csaf = await fileRes.json();
        const doc = csaf.document || {};
        const vulns = csaf.vulnerabilities || [];
        const productTree = csaf.product_tree || {};
        const advisoryId = doc.tracking?.id || file.name.replace(".json", "").toUpperCase();
        const title = doc.title || advisoryId;
        const severity = doc.aggregate_severity?.text?.toLowerCase() || "medium";
        const cves = vulns.map((v) => v.cve).filter(Boolean);
        const branches = productTree.branches || [];
        const vendor = branches[0]?.name || "Unknown";
        const products = branches.flatMap(
          (b) => (b.branches || []).map((pb) => pb.name)
        ).filter(Boolean);
        const cvssScores = vulns.flatMap(
          (v) => (v.scores || []).map((s) => s.cvss_v3?.baseScore || 0)
        );
        const maxCvss = Math.max(...cvssScores, 0);
        await db.insert(icsExploits).values({
          iceCveId: cves[0] || null,
          iceIcsCertAdvisoryId: advisoryId,
          iceTitle: title.slice(0, 500),
          iceDescription: doc.notes?.find((n) => n.category === "summary")?.text?.slice(0, 5e3) || "",
          iceAffectedVendor: vendor,
          iceAffectedProduct: products[0] || "Unknown",
          iceAffectedVersions: products,
          iceCvssScore: maxCvss,
          iceSafetyImpact: maxCvss >= 9 ? "critical" : maxCvss >= 7 ? "high" : "medium",
          iceAvailabilityImpact: maxCvss >= 7 ? "high" : "medium",
          iceProcessIntegrityImpact: maxCvss >= 8 ? "high" : "medium",
          iceExploitAvailable: 0,
          icePublishedDate: doc.tracking?.current_release_date || (/* @__PURE__ */ new Date()).toISOString(),
          iceSector: [],
          iceReferences: [file.html_url]
        }).onDuplicateKeyUpdate({ set: { iceCvssScore: maxCvss } });
        result.newRecords++;
        await new Promise((resolve) => setTimeout(resolve, 500));
      } catch (err) {
        result.errors.push(`CSAF file ${file.name}: ${err.message}`);
      }
    }
  } catch (err) {
    result.errors.push(`CSAF OT ingest error: ${err.message}`);
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function ingestSiemensProductCert() {
  const start = Date.now();
  const result = { source: "Siemens ProductCERT", fetched: 0, newRecords: 0, errors: [], durationMs: 0 };
  try {
    const db = await requireDb();
    const indexUrl = "https://cert-portal.siemens.com/productcert/csaf/index.json";
    const res = await safeFetch(indexUrl, {
      headers: { "User-Agent": "AC3-ThreatIntel/1.0" }
    }, 2e4);
    if (!res.ok) {
      const rssUrl = "https://cert-portal.siemens.com/productcert/rss/advisories.atom";
      const rssRes = await safeFetch(rssUrl, {
        headers: { "User-Agent": "AC3-ThreatIntel/1.0" }
      }, 2e4);
      if (rssRes.ok) {
        const xml = await rssRes.text();
        const items = parseRssItems(xml);
        result.fetched = items.length;
        for (const item of items.slice(0, 20)) {
          try {
            const advisoryId = item.link.match(/ssa-\d+/i)?.[0]?.toUpperCase() || `SIEMENS-${hashString(item.link)}`;
            await db.insert(icsExploits).values({
              iceIcsCertAdvisoryId: advisoryId,
              iceTitle: item.title.slice(0, 500),
              iceDescription: item.description?.slice(0, 5e3) || "",
              iceAffectedVendor: "Siemens",
              iceAffectedProduct: extractProductFromTitle(item.title, "Siemens"),
              icePublishedDate: item.pubDate || (/* @__PURE__ */ new Date()).toISOString(),
              iceReferences: [item.link]
            }).onDuplicateKeyUpdate({ set: { iceDescription: item.description?.slice(0, 5e3) || "" } });
            result.newRecords++;
          } catch {
          }
        }
      } else {
        result.errors.push(`Siemens CSAF index returned ${res.status}`);
      }
      result.durationMs = Date.now() - start;
      return result;
    }
    const index = await res.json();
    const entries = Array.isArray(index) ? index.slice(-20) : [];
    result.fetched = entries.length;
    for (const entry of entries) {
      try {
        const url = typeof entry === "string" ? entry : entry.url || entry.href;
        if (!url) continue;
        const advisoryId = url.match(/ssa-\d+/i)?.[0]?.toUpperCase() || `SIEMENS-${hashString(url)}`;
        await db.insert(icsExploits).values({
          iceIcsCertAdvisoryId: advisoryId,
          iceTitle: `Siemens Advisory ${advisoryId}`,
          iceAffectedVendor: "Siemens",
          icePublishedDate: (/* @__PURE__ */ new Date()).toISOString(),
          iceReferences: [url]
        }).onDuplicateKeyUpdate({ set: { iceDescription: "" } });
        result.newRecords++;
      } catch {
      }
    }
  } catch (err) {
    result.errors.push(`Siemens ingest error: ${err.message}`);
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function autoTagIcsActors() {
  const result = { tagged: 0, alreadyTagged: 0, errors: [] };
  try {
    const db = await requireDb();
    const actors = await db.select({
      actorId: threatActors.actorId,
      name: threatActors.name,
      description: threatActors.description
    }).from(threatActors).limit(500);
    for (const actor of actors) {
      if (actor.description?.includes("[ICS/SCADA-CAPABLE]")) {
        result.alreadyTagged++;
        continue;
      }
      const desc = `${actor.name} ${actor.description || ""}`.toLowerCase();
      const hasIcsKeyword = ICS_KEYWORDS.some((kw) => desc.includes(kw));
      if (hasIcsKeyword) {
        await db.update(threatActors).set({ description: sql`CONCAT(COALESCE(description,''), ' [ICS/SCADA-CAPABLE]')` }).where(eq(threatActors.actorId, actor.actorId));
        result.tagged++;
        continue;
      }
      try {
        const events = await db.select({
          title: threatGroupEvents.tgeTitle,
          description: threatGroupEvents.tgeDescription
        }).from(threatGroupEvents).where(eq(threatGroupEvents.tgeActorId, actor.actorId)).limit(20);
        const eventText = events.map((e) => `${e.title} ${e.description || ""}`).join(" ").toLowerCase();
        if (ICS_KEYWORDS.some((kw) => eventText.includes(kw))) {
          await db.update(threatActors).set({ description: sql`CONCAT(COALESCE(description,''), ' [ICS/SCADA-CAPABLE]')` }).where(eq(threatActors.actorId, actor.actorId));
          result.tagged++;
        }
      } catch {
      }
    }
    try {
      const icsApts = await db.select({
        name: aptIcsMappings.aimAptGroupName
      }).from(aptIcsMappings);
      for (const apt of icsApts) {
        const actorId = slugify(apt.name);
        await db.update(threatActors).set({ description: sql`CONCAT(COALESCE(description,''), ' [ICS/SCADA-CAPABLE]')` }).where(eq(threatActors.actorId, actorId));
      }
    } catch {
    }
  } catch (err) {
    result.errors.push(`Auto-tag error: ${err.message}`);
  }
  return result;
}
async function crossMapIcsMalwareToActors() {
  const result = { mapped: 0, errors: [] };
  try {
    const db = await requireDb();
    for (const malware of ICS_MALWARE_FAMILIES) {
      if (!malware.attribution || malware.attribution === "Unknown") continue;
      const attributionLower = malware.attribution.toLowerCase();
      const actors = await db.select({
        actorId: threatActors.actorId,
        name: threatActors.name
      }).from(threatActors).limit(500);
      for (const actor of actors) {
        const actorLower = `${actor.actorId} ${actor.name}`.toLowerCase();
        if (attributionLower.includes(actorLower) || actorLower.includes(attributionLower.split("(")[0].trim().toLowerCase())) {
          await db.update(threatActors).set({ description: sql`CONCAT(COALESCE(description,''), ' [ICS/SCADA-CAPABLE]')` }).where(eq(threatActors.actorId, actor.actorId));
          await db.insert(threatGroupEvents).values({
            tgeActorId: actor.actorId,
            eventType: "new_tool",
            tgeTitle: `ICS Malware: ${malware.name} attributed to ${actor.name}`.slice(0, 512),
            tgeDescription: `${malware.description} Targeted vendors: ${malware.targetedVendors.join(", ")}. Targeted protocols: ${malware.targetedProtocols.join(", ")}. Targeted sectors: ${malware.targetedSectors.join(", ")}.`,
            tgeSeverity: "critical",
            tgeSource: "ICS Malware Knowledge Base",
            tgeConfidence: 90,
            eventDate: (/* @__PURE__ */ new Date(`${malware.year}-01-01`)).toISOString()
          }).onDuplicateKeyUpdate({ set: { tgeDescription: sql`VALUES(tge_description)` } });
          result.mapped++;
          break;
        }
      }
    }
  } catch (err) {
    result.errors.push(`Cross-map error: ${err.message}`);
  }
  return result;
}
async function runIcsScadaIntelIngest() {
  const start = Date.now();
  const results = [];
  let actorsTagged = 0;
  let malwareMapped = 0;
  console.log("[ICS-SCADA-Intel] Starting ICS/SCADA intelligence ingestion...");
  const sources = [
    { name: "CISA ICS Advisories", fn: ingestCisaIcsAdvisories },
    { name: "CISA CSAF OT", fn: ingestCisaCsafOt },
    { name: "Siemens ProductCERT", fn: ingestSiemensProductCert }
  ];
  for (const source of sources) {
    try {
      console.log(`[ICS-SCADA-Intel] Ingesting ${source.name}...`);
      const result = await source.fn();
      results.push(result);
      console.log(`[ICS-SCADA-Intel] ${source.name}: ${result.newRecords} new records (${result.durationMs}ms)`);
      await new Promise((resolve) => setTimeout(resolve, 1e3));
    } catch (err) {
      results.push({
        source: source.name,
        fetched: 0,
        newRecords: 0,
        errors: [err.message],
        durationMs: 0
      });
    }
  }
  try {
    console.log("[ICS-SCADA-Intel] Auto-tagging actors with ICS/SCADA capability...");
    const tagResult = await autoTagIcsActors();
    actorsTagged = tagResult.tagged;
    console.log(`[ICS-SCADA-Intel] Tagged ${tagResult.tagged} new actors, ${tagResult.alreadyTagged} already tagged`);
  } catch (err) {
    console.error("[ICS-SCADA-Intel] Auto-tag failed:", err.message);
  }
  try {
    console.log("[ICS-SCADA-Intel] Cross-mapping ICS malware to actors...");
    const mapResult = await crossMapIcsMalwareToActors();
    malwareMapped = mapResult.mapped;
    console.log(`[ICS-SCADA-Intel] Mapped ${mapResult.mapped} malware-to-actor links`);
  } catch (err) {
    console.error("[ICS-SCADA-Intel] Cross-map failed:", err.message);
  }
  const totalNewRecords = results.reduce((sum, r) => sum + r.newRecords, 0);
  const successfulSources = results.filter((r) => r.errors.length === 0).length;
  console.log(`[ICS-SCADA-Intel] Complete: ${successfulSources}/${sources.length} sources, ${totalNewRecords} new records, ${actorsTagged} actors tagged (${Date.now() - start}ms)`);
  return {
    totalSources: sources.length,
    successfulSources,
    totalNewRecords,
    actorsTagged,
    malwareMapped,
    results,
    durationMs: Date.now() - start
  };
}
function parseRssItems(xml) {
  const items = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>|<entry>([\s\S]*?)<\/entry>/gi;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const content = match[1] || match[2] || "";
    const title = content.match(/<title[^>]*>(.*?)<\/title>/i)?.[1]?.replace(/<!\[CDATA\[(.*?)\]\]>/g, "$1") || "";
    const link = content.match(/<link[^>]*href="([^"]+)"/i)?.[1] || content.match(/<link[^>]*>(.*?)<\/link>/i)?.[1]?.replace(/<!\[CDATA\[(.*?)\]\]>/g, "$1") || "";
    const description = content.match(/<description[^>]*>(.*?)<\/description>/is)?.[1]?.replace(/<!\[CDATA\[(.*?)\]\]>/gs, "$1")?.replace(/<[^>]+>/g, "") || "";
    const pubDate = content.match(/<pubDate[^>]*>(.*?)<\/pubDate>/i)?.[1] || content.match(/<published[^>]*>(.*?)<\/published>/i)?.[1] || content.match(/<updated[^>]*>(.*?)<\/updated>/i)?.[1] || "";
    if (title) items.push({ title: title.trim(), link: link.trim(), description: description.trim(), pubDate: pubDate.trim() });
  }
  return items;
}
function extractVendorFromTitle(title) {
  for (const vendor of ICS_VENDORS) {
    if (title.includes(vendor.name)) return vendor.name;
    for (const alias of vendor.aliases) {
      if (title.includes(alias)) return vendor.name;
    }
  }
  return "Unknown";
}
function extractProductFromTitle(title, vendor) {
  let product = title.replace(vendor, "").replace(/^[\s:—-]+/, "").replace(/ICSA-\d{2}-\d{3}-\d{2}\s*/i, "").trim();
  return product.slice(0, 255) || "Unknown";
}
function extractCvssFromText(text) {
  const cvssMatch = text.match(/cvss[:\s]*(\d+\.?\d*)/i);
  if (cvssMatch) return parseFloat(cvssMatch[1]);
  return 0;
}
function detectIcsSectors(text) {
  const sectors = [];
  const sectorMap = {
    "energy": "Energy",
    "power": "Energy",
    "electric": "Energy",
    "oil": "Oil & Gas",
    "gas": "Oil & Gas",
    "petroleum": "Oil & Gas",
    "water": "Water & Wastewater",
    "wastewater": "Water & Wastewater",
    "manufacturing": "Manufacturing",
    "chemical": "Chemical",
    "nuclear": "Nuclear",
    "transportation": "Transportation",
    "healthcare": "Healthcare",
    "building automation": "Building Automation",
    "hvac": "Building Automation",
    "food": "Food & Agriculture",
    "agriculture": "Food & Agriculture",
    "mining": "Mining",
    "defense": "Defense Industrial Base"
  };
  for (const [keyword, sector] of Object.entries(sectorMap)) {
    if (text.includes(keyword) && !sectors.includes(sector)) {
      sectors.push(sector);
    }
  }
  return sectors;
}
function getIcsMalwareFamilies() {
  return ICS_MALWARE_FAMILIES;
}
function getIcsOpenSourceTools() {
  return ICS_OPEN_SOURCE_TOOLS;
}
function getIcsVendors() {
  return ICS_VENDORS;
}
function getIcsKeywords() {
  return [...ICS_KEYWORDS];
}
var ICS_KEYWORDS, ICS_VENDORS, ICS_MALWARE_FAMILIES, ICS_OPEN_SOURCE_TOOLS;
var init_ics_scada_intel = __esm({
  "server/lib/ics-scada-intel.ts"() {
    init_db();
    init_schema();
    ICS_KEYWORDS = [
      // Protocols
      "modbus",
      "dnp3",
      "iec 104",
      "iec 61850",
      "opc ua",
      "opc-ua",
      "opcua",
      "opc da",
      "bacnet",
      "profinet",
      "ethercat",
      "ethernet/ip",
      "hart",
      "foundation fieldbus",
      "s7comm",
      "fins",
      "melsec",
      "codesys",
      "enip",
      // Device types
      "plc",
      "rtu",
      "hmi",
      "dcs",
      "scada",
      "ics",
      "safety instrumented",
      "sis",
      "engineering workstation",
      "historian",
      "data diode",
      // Vendors
      "siemens",
      "schneider electric",
      "rockwell",
      "allen-bradley",
      "honeywell",
      "abb",
      "ge digital",
      "yokogawa",
      "emerson",
      "omron",
      "mitsubishi electric",
      "beckhoff",
      "wago",
      "moxa",
      "advantech",
      "delta electronics",
      "phoenix contact",
      "unitronics",
      "codesys",
      "inductive automation",
      "ignition",
      // Sectors
      "power grid",
      "water treatment",
      "oil and gas",
      "pipeline",
      "manufacturing",
      "nuclear",
      "chemical plant",
      "electric utility",
      "substation",
      // Malware families
      "stuxnet",
      "industroyer",
      "crashoverride",
      "triton",
      "trisis",
      "hatman",
      "pipedream",
      "incontroller",
      "frostygoop",
      "fuxnet",
      "iocontrol",
      "blackenergy",
      "havex",
      "irongate",
      "industroyer2",
      "chaya_003",
      "dynowiper",
      "zionsiphon",
      "shamoon",
      "night dragon",
      // General
      "operational technology",
      "critical infrastructure",
      "industrial control",
      "cyber-physical",
      "purdue model",
      "ot network",
      "ot security"
    ];
    ICS_VENDORS = [
      { name: "Siemens", certUrl: "https://cert-portal.siemens.com/productcert/csaf/index.json", aliases: ["Siemens AG", "Siemens ProductCERT"] },
      { name: "Schneider Electric", certUrl: null, aliases: ["Schneider", "SE"] },
      { name: "Rockwell Automation", certUrl: null, aliases: ["Allen-Bradley", "Rockwell"] },
      { name: "Honeywell", certUrl: null, aliases: ["Honeywell Process Solutions"] },
      { name: "ABB", certUrl: null, aliases: ["ABB Ltd"] },
      { name: "Yokogawa", certUrl: null, aliases: ["Yokogawa Electric"] },
      { name: "Emerson", certUrl: null, aliases: ["Emerson Electric", "Fisher"] },
      { name: "Omron", certUrl: null, aliases: ["Omron Corporation"] },
      { name: "Mitsubishi Electric", certUrl: null, aliases: ["MELSEC", "Mitsubishi"] },
      { name: "GE Digital", certUrl: null, aliases: ["General Electric", "GE Vernova"] },
      { name: "Phoenix Contact", certUrl: null, aliases: [] },
      { name: "Beckhoff", certUrl: null, aliases: ["Beckhoff Automation"] },
      { name: "WAGO", certUrl: null, aliases: [] },
      { name: "Moxa", certUrl: null, aliases: ["Moxa Inc"] },
      { name: "Advantech", certUrl: null, aliases: ["Advantech Co"] },
      { name: "Delta Electronics", certUrl: null, aliases: ["Delta"] },
      { name: "Unitronics", certUrl: null, aliases: [] },
      { name: "CODESYS", certUrl: null, aliases: ["3S-Smart Software Solutions"] },
      { name: "Inductive Automation", certUrl: null, aliases: ["Ignition"] }
    ];
    ICS_MALWARE_FAMILIES = [
      {
        name: "Stuxnet",
        aliases: ["W32.Stuxnet"],
        year: 2010,
        attribution: "Equation Group (US/Israel)",
        targetedVendors: ["Siemens"],
        targetedProtocols: ["s7comm", "profinet"],
        targetedSectors: ["nuclear"],
        description: "First publicly known digital weapon against ICS. Targeted Siemens S7-300 PLCs controlling uranium centrifuges at Natanz, Iran.",
        mitreIcsTechniques: ["T0831", "T0821", "T0836", "T0843", "T0857", "T0855"],
        references: ["https://attack.mitre.org/software/S0603/"]
      },
      {
        name: "Havex",
        aliases: ["Oldrea", "Backdoor.Oldrea"],
        year: 2013,
        attribution: "Dragonfly/Energetic Bear (Russia)",
        targetedVendors: ["Multiple ICS vendors"],
        targetedProtocols: ["opc da"],
        targetedSectors: ["energy", "manufacturing", "pharmaceutical"],
        description: "ICS-focused RAT that scanned for OPC servers to map industrial networks. Distributed via trojanized ICS vendor software downloads.",
        mitreIcsTechniques: ["T0846", "T0887", "T0862"],
        references: ["https://attack.mitre.org/software/S0093/"]
      },
      {
        name: "BlackEnergy",
        aliases: ["BlackEnergy2", "BlackEnergy3", "BE2", "BE3"],
        year: 2014,
        attribution: "Sandworm (Russia GRU)",
        targetedVendors: ["Siemens", "GE", "Advantech"],
        targetedProtocols: ["modbus", "opc da"],
        targetedSectors: ["energy"],
        description: "Modular trojan targeting HMIs in ICS environments. Used in 2015 Ukraine power grid attack causing first confirmed cyber-caused power outage.",
        mitreIcsTechniques: ["T0886", "T0862", "T0826", "T0813"],
        references: ["https://attack.mitre.org/software/S0089/"]
      },
      {
        name: "Industroyer",
        aliases: ["CrashOverride", "Industroyer1"],
        year: 2017,
        attribution: "Sandworm/ELECTRUM (Russia GRU)",
        targetedVendors: ["ABB", "Siemens"],
        targetedProtocols: ["iec104", "iec61850", "opc da"],
        targetedSectors: ["energy"],
        description: "First malware specifically designed to attack electric power grids. Speaks native ICS protocols (IEC 104, IEC 61850, OPC DA).",
        mitreIcsTechniques: ["T0855", "T0826", "T0831", "T0827", "T0813"],
        references: ["https://attack.mitre.org/software/S0604/"]
      },
      {
        name: "TRITON",
        aliases: ["Trisis", "HatMan"],
        year: 2017,
        attribution: "XENOTIME / TsNIIKhM (Russia)",
        targetedVendors: ["Schneider Electric"],
        targetedProtocols: ["tristation"],
        targetedSectors: ["oil and gas", "petrochemical"],
        description: "First malware targeting Safety Instrumented Systems (SIS). Attempted to disable Schneider Electric Triconex safety controllers at a Saudi petrochemical facility.",
        mitreIcsTechniques: ["T0836", "T0855", "T0857", "T0821", "T0831"],
        references: ["https://attack.mitre.org/software/S0609/"]
      },
      {
        name: "Industroyer2",
        aliases: [],
        year: 2022,
        attribution: "Sandworm (Russia GRU)",
        targetedVendors: ["ABB", "Siemens"],
        targetedProtocols: ["iec104"],
        targetedSectors: ["energy"],
        description: "Simplified version of Industroyer targeting Ukrainian power grid in 2022. Deployed alongside CaddyWiper for destructive impact.",
        mitreIcsTechniques: ["T0855", "T0826", "T0831"],
        references: ["https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/"]
      },
      {
        name: "PIPEDREAM",
        aliases: ["INCONTROLLER"],
        year: 2022,
        attribution: "CHERNOVITE (State-sponsored, likely Russia)",
        targetedVendors: ["Schneider Electric", "Omron", "OPC Foundation"],
        targetedProtocols: ["opcua", "modbus", "codesys"],
        targetedSectors: ["energy", "water", "manufacturing"],
        description: "Modular ICS attack framework with components for OPC-UA, Modbus, CODESYS, and Omron FINS. First cross-industry ICS attack toolkit.",
        mitreIcsTechniques: ["T0855", "T0836", "T0843", "T0821", "T0831", "T0826"],
        references: ["https://www.dragos.com/blog/industry-news/chernovite-pipedream-malware-targeting-industrial-control-systems/"]
      },
      {
        name: "FrostyGoop",
        aliases: [],
        year: 2024,
        attribution: "Unknown (likely Russia-aligned)",
        targetedVendors: ["Multiple"],
        targetedProtocols: ["modbus"],
        targetedSectors: ["energy", "heating"],
        description: "Malware targeting Modbus TCP-enabled devices. Used in attacks against Ukrainian heating infrastructure during winter 2024.",
        mitreIcsTechniques: ["T0855", "T0831", "T0826"],
        references: ["https://www.dragos.com/blog/frostygoop-ics-malware-targeting-operational-technology/"]
      },
      {
        name: "Fuxnet",
        aliases: [],
        year: 2024,
        attribution: "BlackJack (Ukraine-aligned hacktivist)",
        targetedVendors: ["Russian ICS vendors"],
        targetedProtocols: ["modbus", "m-bus"],
        targetedSectors: ["water", "sewage"],
        description: "Improved Stuxnet-inspired malware used by BlackJack group to attack Russian municipal infrastructure companies.",
        mitreIcsTechniques: ["T0831", "T0826", "T0855"],
        references: ["https://claroty.com/team82/research/unpacking-the-blackjack-groups-fuxnet-malware"]
      },
      {
        name: "IOCONTROL",
        aliases: [],
        year: 2024,
        attribution: "CyberAv3ngers (Iran IRGC-affiliated)",
        targetedVendors: ["Unitronics", "Multiple IoT"],
        targetedProtocols: ["modbus", "mqtt"],
        targetedSectors: ["water", "fuel"],
        description: "Backdoor malware targeting IoT/OT devices. Used by Iran-linked CyberAv3ngers to compromise water and fuel management systems.",
        mitreIcsTechniques: ["T0886", "T0855", "T0821"],
        references: ["https://claroty.com/team82/research/inside-iocontrol-the-cyberav3ngers-ot-iot-malware"]
      },
      {
        name: "Chaya_003",
        aliases: [],
        year: 2024,
        attribution: "Unknown",
        targetedVendors: ["Siemens"],
        targetedProtocols: ["s7comm"],
        targetedSectors: ["manufacturing"],
        description: "Malware capable of killing Siemens engineering processes and executing commands from a C2 server.",
        mitreIcsTechniques: ["T0831", "T0821"],
        references: []
      },
      {
        name: "DynoWiper",
        aliases: [],
        year: 2025,
        attribution: "Unknown (likely Russia-aligned)",
        targetedVendors: ["Multiple HMI vendors"],
        targetedProtocols: [],
        targetedSectors: ["energy", "manufacturing"],
        description: "Wiper malware designed to corrupt and disrupt files on compromised HMIs in Poland.",
        mitreIcsTechniques: ["T0831", "T0826"],
        references: []
      },
      {
        name: "ZionSiphon",
        aliases: [],
        year: 2026,
        attribution: "Unknown (likely Iran-aligned)",
        targetedVendors: ["Multiple"],
        targetedProtocols: ["modbus"],
        targetedSectors: ["water"],
        description: "Likely LLM-generated malware targeting Israeli water treatment and desalination systems.",
        mitreIcsTechniques: ["T0855", "T0831", "T0826"],
        references: []
      }
    ];
    ICS_OPEN_SOURCE_TOOLS = [
      // Honeypots
      {
        name: "Conpot",
        category: "honeypot",
        description: "Low-interactive ICS/SCADA honeypot designed to collect intelligence about adversary motives and methods targeting industrial control systems.",
        githubUrl: "https://github.com/mushorg/conpot",
        license: "GPL-2.0",
        protocols: ["modbus", "s7comm", "bacnet", "ipmi", "enip", "guardian_ast", "kamstrup"],
        useCase: "Deploy as decoy ICS device to detect scanning and exploitation attempts. Supports Modbus, S7comm, BACnet, IPMI, EtherNet/IP.",
        lastUpdated: "2024"
      },
      {
        name: "GRFICSv2",
        category: "simulation",
        description: "Graphical Realism Framework for Industrial Control Simulations. 5-VM environment with 3D simulation, soft PLC, HMI, firewall, and workstation.",
        githubUrl: "https://github.com/Fortiphyd/GRFICSv2",
        license: "MIT",
        protocols: ["modbus", "openplc"],
        useCase: "Training and research environment for ICS security. Simulates chemical process with realistic PLC logic and 3D visualization.",
        lastUpdated: "2023"
      },
      {
        name: "Gridpot",
        category: "honeypot",
        description: "Open-source tools for realistic-behaving electric grid honeynets. Simulates power grid SCADA systems.",
        githubUrl: "https://github.com/sk4ld/gridpot",
        license: "MIT",
        protocols: ["modbus", "dnp3", "iec104"],
        useCase: "Electric grid honeypot for detecting attacks against power distribution SCADA systems.",
        lastUpdated: "2022"
      },
      // Monitoring
      {
        name: "Malcolm",
        category: "monitoring",
        description: "Network traffic analysis tool suite for full packet capture, ICS protocol analysis, and OT network visibility.",
        githubUrl: "https://github.com/cisagov/Malcolm",
        license: "BSD",
        protocols: ["modbus", "dnp3", "bacnet", "s7comm", "enip", "opcua"],
        useCase: "Passive network monitoring for OT environments. Integrates Zeek, Suricata, and Arkime for deep packet inspection of ICS protocols.",
        lastUpdated: "2026"
      },
      {
        name: "Zeek ICS Protocol Analyzers",
        category: "monitoring",
        description: "Zeek (formerly Bro) protocol analyzers for ICS/SCADA protocols including Modbus, DNP3, BACnet, and S7comm.",
        githubUrl: "https://github.com/zeek/zeek",
        license: "BSD",
        protocols: ["modbus", "dnp3", "bacnet", "s7comm"],
        useCase: "Network security monitoring with native ICS protocol parsing. Generates detailed logs of ICS traffic for analysis.",
        lastUpdated: "2026"
      },
      {
        name: "Grassmarlin",
        category: "monitoring",
        description: "NSA-developed passive network situational awareness tool for ICS/SCADA environments.",
        githubUrl: "https://github.com/nsacyber/GRASSMARLIN",
        license: "Public Domain",
        protocols: ["modbus", "dnp3", "bacnet", "enip", "opcua"],
        useCase: "Passive discovery and visualization of ICS network topology. Maps device communications without active scanning.",
        lastUpdated: "2022"
      },
      // Assessment
      {
        name: "Redpoint (Nmap NSE for ICS)",
        category: "assessment",
        description: "Nmap NSE scripts for ICS/SCADA device discovery and enumeration. Identifies PLCs, RTUs, and HMIs on the network.",
        githubUrl: "https://github.com/digitalbond/Redpoint",
        license: "GPL-2.0",
        protocols: ["modbus", "s7comm", "bacnet", "enip", "dnp3", "niagara_fox", "codesys"],
        useCase: "Active scanning for ICS device discovery. Identifies Siemens, Rockwell, Schneider, and other vendor devices.",
        lastUpdated: "2023"
      },
      {
        name: "PLCScan",
        category: "assessment",
        description: "PLC scanner that identifies and enumerates Siemens S7 and Modbus devices on the network.",
        githubUrl: "https://github.com/meeas/plcscan",
        license: "MIT",
        protocols: ["s7comm", "modbus"],
        useCase: "Quick PLC discovery and enumeration for penetration testing and security assessments.",
        lastUpdated: "2022"
      },
      {
        name: "ISF (Industrial Security Framework)",
        category: "framework",
        description: "Exploitation framework for ICS/SCADA systems. Similar to Metasploit but focused on industrial protocols.",
        githubUrl: "https://github.com/dark-lbp/isf",
        license: "MIT",
        protocols: ["modbus", "s7comm", "opcua"],
        useCase: "Penetration testing framework for ICS environments. Includes modules for PLC exploitation and protocol fuzzing.",
        lastUpdated: "2023"
      },
      {
        name: "SCADAShutdownTool",
        category: "assessment",
        description: "Tool for testing SCADA system resilience by simulating shutdown commands via industrial protocols.",
        githubUrl: "https://github.com/0xICF/SCADAShutdownTool",
        license: "GPL-3.0",
        protocols: ["modbus", "dnp3", "iec104", "opc"],
        useCase: "Authorized testing of SCADA system response to shutdown commands. For use in controlled environments only.",
        lastUpdated: "2022"
      },
      // Protocol Analysis
      {
        name: "s7-pcap-tool",
        category: "protocol_analysis",
        description: "Siemens S7 protocol PCAP analysis tool for extracting PLC communication details from network captures.",
        githubUrl: "https://github.com/gymgit/s7-pcap-tool",
        license: "MIT",
        protocols: ["s7comm"],
        useCase: "Forensic analysis of Siemens S7 protocol traffic. Extracts function codes, data blocks, and PLC operations.",
        lastUpdated: "2022"
      },
      {
        name: "ModbusPal",
        category: "simulation",
        description: "Java-based Modbus slave simulator for testing Modbus TCP/RTU communications.",
        githubUrl: "https://github.com/zeelos/ModbusPal",
        license: "GPL-3.0",
        protocols: ["modbus"],
        useCase: "Simulate Modbus slave devices for testing SCADA master stations and security tools.",
        lastUpdated: "2023"
      },
      // Forensics
      {
        name: "ControlThings Platform",
        category: "framework",
        description: "Linux distribution for ICS cyber security teams. Includes best-in-breed security assessment tools for ICS/SCADA.",
        githubUrl: "https://github.com/ControlThingsIO/ct-platform",
        license: "GPL-3.0",
        protocols: ["modbus", "dnp3", "bacnet", "s7comm", "enip", "opcua"],
        useCase: "All-in-one ICS security assessment platform. Pre-configured with tools for protocol analysis, vulnerability scanning, and exploitation.",
        lastUpdated: "2023"
      }
    ];
  }
});

export {
  ICS_MALWARE_FAMILIES,
  ICS_OPEN_SOURCE_TOOLS,
  ingestCisaIcsAdvisories,
  ingestCisaCsafOt,
  ingestSiemensProductCert,
  autoTagIcsActors,
  crossMapIcsMalwareToActors,
  runIcsScadaIntelIngest,
  getIcsMalwareFamilies,
  getIcsOpenSourceTools,
  getIcsVendors,
  getIcsKeywords,
  ics_scada_intel_exports,
  init_ics_scada_intel
};
