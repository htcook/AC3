import {
  getDb,
  init_db
} from "./chunk-VL2KRLTM.js";
import {
  exploitIntelligence,
  incidentReports,
  init_schema
} from "./chunk-IG2G4XDA.js";

// server/lib/threat-intel-ingest.ts
init_db();
init_schema();
import { eq, and, sql } from "drizzle-orm";
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
function parseRss(xml) {
  const items = [];
  const itemRegex = /<item[^>]*>([\s\S]*?)<\/item>|<entry[^>]*>([\s\S]*?)<\/entry>/gi;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const block = match[1] || match[2] || "";
    const getTag = (tag) => {
      const r = new RegExp(`<${tag}[^>]*>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?<\\/${tag}>`, "i");
      const m = block.match(r);
      return m ? m[1].trim() : "";
    };
    const getLink = () => {
      const atomLink = block.match(/<link[^>]*href="([^"]*)"[^>]*\/?>/i);
      if (atomLink) return atomLink[1];
      return getTag("link");
    };
    const categories = [];
    const catRegex = /<category[^>]*>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/category>/gi;
    let catMatch;
    while ((catMatch = catRegex.exec(block)) !== null) {
      categories.push(catMatch[1].trim());
    }
    items.push({
      title: getTag("title"),
      link: getLink(),
      description: getTag("description") || getTag("summary"),
      pubDate: getTag("pubDate") || getTag("published") || getTag("updated"),
      categories,
      content: getTag("content:encoded") || getTag("content")
    });
  }
  return items;
}
function stripHtml(html) {
  return html.replace(/<script[\s\S]*?<\/script>/gi, "").replace(/<style[\s\S]*?<\/style>/gi, "").replace(/<[^>]+>/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#039;/g, "'").replace(/&nbsp;/g, " ").replace(/\s+/g, " ").trim();
}
async function ingestDfirReport() {
  const start = Date.now();
  try {
    const res = await safeFetch("https://thedfirreport.com/feed/");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const xml = await res.text();
    const items = parseRss(xml);
    const db = await requireDb();
    let newCount = 0;
    for (const item of items) {
      const sourceId = hashString(item.link);
      const existing = await db.select({ id: incidentReports.id }).from(incidentReports).where(and(eq(incidentReports.source, "dfir_report"), eq(incidentReports.sourceId, sourceId))).limit(1);
      if (existing.length > 0) continue;
      const fullText = stripHtml(item.content || item.description);
      const techniqueMatches = fullText.match(/T\d{4}(?:\.\d{3})?/g) || [];
      const uniqueTechniques = Array.from(new Set(techniqueMatches));
      const cveMatches = fullText.match(/CVE-\d{4}-\d{4,}/gi) || [];
      const uniqueCves = Array.from(new Set(cveMatches.map((c) => c.toUpperCase())));
      const lowerContent = fullText.toLowerCase();
      let incidentType = "intrusion";
      if (lowerContent.includes("ransomware")) incidentType = "ransomware";
      else if (lowerContent.includes("apt") || lowerContent.includes("nation-state")) incidentType = "apt";
      else if (lowerContent.includes("phishing")) incidentType = "phishing";
      else if (lowerContent.includes("supply chain")) incidentType = "supply_chain";
      const record = {
        sourceId,
        source: "dfir_report",
        title: item.title,
        url: item.link,
        publishedAt: item.pubDate,
        summary: stripHtml(item.description).slice(0, 2e3),
        fullContent: fullText.slice(0, 6e4),
        // Cap at 60k chars
        ttpsExtracted: uniqueTechniques.map((t) => ({ techniqueId: t, confidence: 80 })),
        cvesMentioned: uniqueCves,
        incidentType,
        status: "raw"
      };
      await db.insert(incidentReports).values(record);
      newCount++;
    }
    return { source: "dfir_report", fetched: items.length, newRecords: newCount, durationMs: Date.now() - start };
  } catch (e) {
    return { source: "dfir_report", fetched: 0, newRecords: 0, error: e.message, durationMs: Date.now() - start };
  }
}
async function ingestCisaAdvisories() {
  const start = Date.now();
  try {
    const res = await safeFetch("https://www.cisa.gov/cybersecurity-advisories/all.xml", {}, 45e3);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const xml = await res.text();
    const items = parseRss(xml);
    const db = await requireDb();
    let newCount = 0;
    for (const item of items.slice(0, 100)) {
      const sourceId = hashString(item.link);
      const existing = await db.select({ id: incidentReports.id }).from(incidentReports).where(and(eq(incidentReports.source, "cisa_advisory"), eq(incidentReports.sourceId, sourceId))).limit(1);
      if (existing.length > 0) continue;
      const fullText = stripHtml(item.content || item.description);
      const cveMatches = fullText.match(/CVE-\d{4}-\d{4,}/gi) || [];
      const techniqueMatches = fullText.match(/T\d{4}(?:\.\d{3})?/g) || [];
      let incidentType = "advisory";
      const lowerTitle = item.title.toLowerCase();
      if (lowerTitle.includes("ransomware")) incidentType = "ransomware";
      else if (lowerTitle.includes("apt") || lowerTitle.includes("nation-state")) incidentType = "apt";
      else if (lowerTitle.includes("ics") || lowerTitle.includes("scada")) incidentType = "ics_ot";
      const record = {
        sourceId,
        source: "cisa_advisory",
        title: item.title,
        url: item.link,
        publishedAt: item.pubDate,
        summary: fullText.slice(0, 2e3),
        fullContent: fullText.slice(0, 6e4),
        ttpsExtracted: Array.from(new Set(techniqueMatches)).map((t) => ({ techniqueId: t, confidence: 90 })),
        cvesMentioned: Array.from(new Set(cveMatches.map((c) => c.toUpperCase()))),
        incidentType,
        severity: "high",
        status: "raw"
      };
      await db.insert(incidentReports).values(record);
      newCount++;
    }
    return { source: "cisa_advisory", fetched: items.length, newRecords: newCount, durationMs: Date.now() - start };
  } catch (e) {
    return { source: "cisa_advisory", fetched: 0, newRecords: 0, error: e.message, durationMs: Date.now() - start };
  }
}
async function ingestUnit42() {
  const start = Date.now();
  try {
    const res = await safeFetch("https://unit42.paloaltonetworks.com/feed/");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const xml = await res.text();
    const items = parseRss(xml);
    const db = await requireDb();
    let newCount = 0;
    for (const item of items.slice(0, 50)) {
      const sourceId = hashString(item.link);
      const existing = await db.select({ id: incidentReports.id }).from(incidentReports).where(and(eq(incidentReports.source, "unit42"), eq(incidentReports.sourceId, sourceId))).limit(1);
      if (existing.length > 0) continue;
      const fullText = stripHtml(item.content || item.description);
      const cveMatches = fullText.match(/CVE-\d{4}-\d{4,}/gi) || [];
      const techniqueMatches = fullText.match(/T\d{4}(?:\.\d{3})?/g) || [];
      let incidentType = "threat_research";
      const lower = fullText.toLowerCase();
      if (lower.includes("ransomware")) incidentType = "ransomware";
      else if (lower.includes("apt")) incidentType = "apt";
      else if (lower.includes("malware")) incidentType = "malware";
      const record = {
        sourceId,
        source: "unit42",
        title: item.title,
        url: item.link,
        publishedAt: item.pubDate,
        summary: fullText.slice(0, 2e3),
        fullContent: fullText.slice(0, 6e4),
        ttpsExtracted: Array.from(new Set(techniqueMatches)).map((t) => ({ techniqueId: t, confidence: 80 })),
        cvesMentioned: Array.from(new Set(cveMatches.map((c) => c.toUpperCase()))),
        incidentType,
        status: "raw"
      };
      await db.insert(incidentReports).values(record);
      newCount++;
    }
    return { source: "unit42", fetched: items.length, newRecords: newCount, durationMs: Date.now() - start };
  } catch (e) {
    return { source: "unit42", fetched: 0, newRecords: 0, error: e.message, durationMs: Date.now() - start };
  }
}
async function ingestNewsFeed(feedUrl, sourceName, maxItems = 50) {
  const start = Date.now();
  try {
    const res = await safeFetch(feedUrl, {}, 2e4);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const xml = await res.text();
    const items = parseRss(xml);
    const db = await requireDb();
    let newCount = 0;
    for (const item of items.slice(0, maxItems)) {
      const sourceId = hashString(item.link);
      const existing = await db.select({ id: incidentReports.id }).from(incidentReports).where(and(eq(incidentReports.source, sourceName), eq(incidentReports.sourceId, sourceId))).limit(1);
      if (existing.length > 0) continue;
      const fullText = stripHtml(item.content || item.description);
      const cveMatches = fullText.match(/CVE-\d{4}-\d{4,}/gi) || [];
      const techniqueMatches = fullText.match(/T\d{4}(?:\.\d{3})?/g) || [];
      const lower = (item.title + " " + fullText).toLowerCase();
      let incidentType = "news";
      if (lower.includes("ransomware")) incidentType = "ransomware";
      else if (lower.includes("breach") || lower.includes("data leak")) incidentType = "data_breach";
      else if (lower.includes("apt") || lower.includes("nation-state")) incidentType = "apt";
      else if (lower.includes("phishing")) incidentType = "phishing";
      else if (lower.includes("vulnerability") || lower.includes("cve-")) incidentType = "vulnerability";
      else if (lower.includes("malware")) incidentType = "malware";
      const record = {
        sourceId,
        source: sourceName,
        title: item.title,
        url: item.link,
        publishedAt: item.pubDate,
        summary: fullText.slice(0, 2e3),
        fullContent: fullText.slice(0, 3e4),
        // News articles are shorter
        ttpsExtracted: Array.from(new Set(techniqueMatches)).map((t) => ({ techniqueId: t, confidence: 85 })),
        cvesMentioned: Array.from(new Set(cveMatches.map((c) => c.toUpperCase()))),
        incidentType,
        status: "raw"
      };
      await db.insert(incidentReports).values(record);
      newCount++;
    }
    return { source: sourceName, fetched: items.length, newRecords: newCount, durationMs: Date.now() - start };
  } catch (e) {
    return { source: sourceName, fetched: 0, newRecords: 0, error: e.message, durationMs: Date.now() - start };
  }
}
async function ingestHackerNews() {
  return ingestNewsFeed("https://feeds.feedburner.com/TheHackersNews", "hacker_news");
}
async function ingestDarkReading() {
  return ingestNewsFeed("https://www.darkreading.com/rss.xml", "dark_reading");
}
async function ingestCyberScoop() {
  return ingestNewsFeed("https://cyberscoop.com/feed/", "cyberscoop");
}
async function ingestCybersecurityDive() {
  return ingestNewsFeed("https://www.cybersecuritydive.com/feeds/news/", "cybersecurity_dive");
}
async function ingestMispCircl() {
  const start = Date.now();
  try {
    const manifestRes = await safeFetch("https://www.circl.lu/doc/misp/feed-osint/manifest.json", {}, 3e4);
    if (!manifestRes.ok) throw new Error(`Manifest HTTP ${manifestRes.status}`);
    const manifest = await manifestRes.json();
    const db = await requireDb();
    let newCount = 0;
    const eventIds = Object.keys(manifest).slice(0, 30);
    for (const eventId of eventIds) {
      const sourceId = `circl-${eventId}`;
      const existing = await db.select({ id: incidentReports.id }).from(incidentReports).where(and(eq(incidentReports.source, "misp_circl"), eq(incidentReports.sourceId, sourceId))).limit(1);
      if (existing.length > 0) continue;
      try {
        const eventRes = await safeFetch(
          `https://www.circl.lu/doc/misp/feed-osint/${eventId}.json`,
          {},
          15e3
        );
        if (!eventRes.ok) continue;
        const eventData = await eventRes.json();
        const event = eventData.Event || eventData;
        const attributes = event.Attribute || [];
        const iocsExtracted = attributes.slice(0, 100).map((a) => ({
          type: a.type || "unknown",
          value: a.value || "",
          context: a.comment || ""
        }));
        const tags = event.Tag || [];
        const mitreTags = tags.filter((t) => t.name && t.name.includes("mitre-attack")).map((t) => {
          const techMatch = t.name.match(/T\d{4}(?:\.\d{3})?/);
          return techMatch ? { techniqueId: techMatch[0], confidence: 85 } : null;
        }).filter(Boolean);
        const record = {
          sourceId,
          source: "misp_circl",
          title: event.info || manifest[eventId]?.info || `MISP Event ${eventId}`,
          url: `https://www.circl.lu/doc/misp/feed-osint/${eventId}.json`,
          publishedAt: event.date || manifest[eventId]?.date || "",
          summary: (event.info || "").slice(0, 2e3),
          iocsExtracted,
          ttpsExtracted: mitreTags,
          incidentType: "threat_intel",
          status: "raw"
        };
        await db.insert(incidentReports).values(record);
        newCount++;
      } catch {
      }
    }
    return { source: "misp_circl", fetched: eventIds.length, newRecords: newCount, durationMs: Date.now() - start };
  } catch (e) {
    return { source: "misp_circl", fetched: 0, newRecords: 0, error: e.message, durationMs: Date.now() - start };
  }
}
async function ingestHhsOcrBreaches() {
  const start = Date.now();
  try {
    const res = await safeFetch(
      "https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf",
      {},
      3e4
    );
    const archiveRes = await safeFetch(
      "https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf",
      { headers: { "Accept": "text/html" } },
      3e4
    );
    const db = await requireDb();
    return { source: "hhs_ocr", fetched: 0, newRecords: 0, durationMs: Date.now() - start };
  } catch (e) {
    return { source: "hhs_ocr", fetched: 0, newRecords: 0, error: e.message, durationMs: Date.now() - start };
  }
}
async function ingestMetasploitCves() {
  const start = Date.now();
  try {
    const res = await safeFetch("https://feeds.ecrimelabs.net/data/metasploit-cve", {}, 3e4);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const lines = text.split("\n").filter((l) => l.trim() && !l.startsWith("#"));
    const db = await requireDb();
    let newCount = 0;
    for (const line of lines) {
      const parts = line.split(";");
      if (parts.length < 2) continue;
      const cveId = (parts[0] || "").trim().toUpperCase();
      if (!cveId.startsWith("CVE-")) continue;
      const modulePath = (parts[1] || "").trim();
      const description = (parts[2] || "").trim();
      const existing = await db.select({ id: exploitIntelligence.id }).from(exploitIntelligence).where(and(
        eq(exploitIntelligence.cveId, cveId),
        eq(exploitIntelligence.metasploitModule, modulePath)
      )).limit(1);
      if (existing.length > 0) continue;
      let exploitType = "unknown";
      if (modulePath.includes("exploit/")) {
        if (modulePath.includes("remote")) exploitType = "rce";
        else if (modulePath.includes("local")) exploitType = "lpe";
        else if (modulePath.includes("webapp")) exploitType = "webapp";
        else exploitType = "exploit";
      } else if (modulePath.includes("auxiliary/")) {
        exploitType = "auxiliary";
      }
      const record = {
        cveId,
        exploitType,
        metasploitModule: modulePath,
        targetProduct: description.slice(0, 255) || void 0,
        weaponized: true,
        // Has a Metasploit module = weaponized
        source: "metasploit",
        confidence: 95
      };
      await db.insert(exploitIntelligence).values(record);
      newCount++;
    }
    return { source: "metasploit_cve", fetched: lines.length, newRecords: newCount, durationMs: Date.now() - start };
  } catch (e) {
    return { source: "metasploit_cve", fetched: 0, newRecords: 0, error: e.message, durationMs: Date.now() - start };
  }
}
async function ingestCisaKevExploits() {
  const start = Date.now();
  try {
    const res = await safeFetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const db = await requireDb();
    let newCount = 0;
    for (const vuln of data.vulnerabilities || []) {
      const cveId = vuln.cveID;
      if (!cveId) continue;
      const existing = await db.select({ id: exploitIntelligence.id }).from(exploitIntelligence).where(and(
        eq(exploitIntelligence.cveId, cveId),
        eq(exploitIntelligence.eiSource, "cisa_kev")
      )).limit(1);
      if (existing.length > 0) continue;
      const record = {
        cveId,
        exploitType: "known_exploited",
        targetProduct: `${vuln.vendorProject || ""} ${vuln.product || ""}`.trim() || void 0,
        weaponized: true,
        firstExploitedInWild: vuln.dateAdded || void 0,
        cisaKev: true,
        attackPhase: vuln.knownRansomwareCampaignUse === "Known" ? "ransomware" : "initial_access",
        source: "cisa_kev",
        confidence: 100
      };
      await db.insert(exploitIntelligence).values(record);
      newCount++;
    }
    return { source: "cisa_kev_exploits", fetched: data.vulnerabilities?.length || 0, newRecords: newCount, durationMs: Date.now() - start };
  } catch (e) {
    return { source: "cisa_kev_exploits", fetched: 0, newRecords: 0, error: e.message, durationMs: Date.now() - start };
  }
}
async function ingestDigitalSideMisp() {
  const start = Date.now();
  try {
    const manifestRes = await safeFetch("https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/manifest.json", {}, 2e4);
    if (!manifestRes.ok) throw new Error(`HTTP ${manifestRes.status}`);
    const manifest = await manifestRes.json();
    const db = await requireDb();
    let newCount = 0;
    const eventIds = Object.keys(manifest).slice(0, 20);
    for (const eventId of eventIds) {
      const sourceId = `digitalside-${eventId}`;
      const existing = await db.select({ id: incidentReports.id }).from(incidentReports).where(and(eq(incidentReports.source, "digitalside_misp"), eq(incidentReports.sourceId, sourceId))).limit(1);
      if (existing.length > 0) continue;
      try {
        const eventRes = await safeFetch(
          `https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/${eventId}.json`,
          {},
          1e4
        );
        if (!eventRes.ok) continue;
        const eventData = await eventRes.json();
        const event = eventData.Event || eventData;
        const attributes = event.Attribute || [];
        const iocsExtracted = attributes.slice(0, 50).map((a) => ({
          type: a.type || "unknown",
          value: a.value || "",
          context: a.comment || ""
        }));
        const record = {
          sourceId,
          source: "digitalside_misp",
          title: event.info || `DigitalSide Event ${eventId}`,
          url: `https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/${eventId}.json`,
          publishedAt: event.date || "",
          summary: (event.info || "").slice(0, 2e3),
          iocsExtracted,
          incidentType: "threat_intel",
          status: "raw"
        };
        await db.insert(incidentReports).values(record);
        newCount++;
      } catch {
      }
    }
    return { source: "digitalside_misp", fetched: eventIds.length, newRecords: newCount, durationMs: Date.now() - start };
  } catch (e) {
    return { source: "digitalside_misp", fetched: 0, newRecords: 0, error: e.message, durationMs: Date.now() - start };
  }
}
var THREAT_INTEL_SOURCES = [
  { name: "dfir_report", fn: ingestDfirReport, category: "incident_reports", priority: 1 },
  { name: "cisa_advisory", fn: ingestCisaAdvisories, category: "government_advisories", priority: 1 },
  { name: "unit42", fn: ingestUnit42, category: "vendor_research", priority: 2 },
  { name: "hacker_news", fn: ingestHackerNews, category: "news", priority: 3 },
  { name: "dark_reading", fn: ingestDarkReading, category: "news", priority: 3 },
  { name: "cyberscoop", fn: ingestCyberScoop, category: "news", priority: 3 },
  { name: "cybersecurity_dive", fn: ingestCybersecurityDive, category: "news", priority: 3 },
  { name: "misp_circl", fn: ingestMispCircl, category: "threat_sharing", priority: 2 },
  { name: "digitalside_misp", fn: ingestDigitalSideMisp, category: "threat_sharing", priority: 2 },
  { name: "metasploit_cve", fn: ingestMetasploitCves, category: "exploit_intel", priority: 1 },
  { name: "cisa_kev_exploits", fn: ingestCisaKevExploits, category: "exploit_intel", priority: 1 }
];
async function runFullIngest() {
  const start = Date.now();
  const results = [];
  const grouped = /* @__PURE__ */ new Map();
  for (const src of THREAT_INTEL_SOURCES) {
    const group = grouped.get(src.priority) || [];
    group.push(src);
    grouped.set(src.priority, group);
  }
  const priorities = Array.from(grouped.keys()).sort();
  for (const priority of priorities) {
    const group = grouped.get(priority) || [];
    const groupResults = await Promise.allSettled(group.map((s) => s.fn()));
    for (let i = 0; i < groupResults.length; i++) {
      const r = groupResults[i];
      if (r && r.status === "fulfilled") {
        results.push(r.value);
      } else if (r && r.status === "rejected") {
        results.push({
          source: group[i]?.name || "unknown",
          fetched: 0,
          newRecords: 0,
          error: r.reason?.message || "Unknown error",
          durationMs: 0
        });
      }
    }
  }
  const successful = results.filter((r) => !r.error).length;
  const totalNew = results.reduce((sum, r) => sum + r.newRecords, 0);
  return {
    totalSources: results.length,
    successfulSources: successful,
    failedSources: results.length - successful,
    totalNewRecords: totalNew,
    results,
    durationMs: Date.now() - start
  };
}
async function getIngestStats() {
  const db = await requireDb();
  const [totalReports] = await db.select({ count: sql`COUNT(*)` }).from(incidentReports);
  const bySource = await db.select({
    source: incidentReports.source,
    count: sql`COUNT(*)`
  }).from(incidentReports).groupBy(incidentReports.source);
  const byStatus = await db.select({
    status: incidentReports.irStatus,
    count: sql`COUNT(*)`
  }).from(incidentReports).groupBy(incidentReports.irStatus);
  const byType = await db.select({
    type: incidentReports.incidentType,
    count: sql`COUNT(*)`
  }).from(incidentReports).groupBy(incidentReports.incidentType);
  const [totalExploits] = await db.select({ count: sql`COUNT(*)` }).from(exploitIntelligence);
  const [weaponized] = await db.select({ count: sql`COUNT(*)` }).from(exploitIntelligence).where(eq(exploitIntelligence.weaponized, 1));
  return {
    totalReports: totalReports?.count || 0,
    bySource: bySource.map((r) => ({ source: r.source, count: r.count })),
    byStatus: byStatus.map((r) => ({ status: r.status || "unknown", count: r.count })),
    byType: byType.map((r) => ({ type: r.type || "unknown", count: r.count })),
    totalExploits: totalExploits?.count || 0,
    weaponizedExploits: weaponized?.count || 0
  };
}

export {
  ingestDfirReport,
  ingestCisaAdvisories,
  ingestUnit42,
  ingestHackerNews,
  ingestDarkReading,
  ingestCyberScoop,
  ingestCybersecurityDive,
  ingestMispCircl,
  ingestHhsOcrBreaches,
  ingestMetasploitCves,
  ingestCisaKevExploits,
  ingestDigitalSideMisp,
  THREAT_INTEL_SOURCES,
  runFullIngest,
  getIngestStats
};
