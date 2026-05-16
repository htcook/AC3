import {
  getDb,
  init_db
} from "./chunk-TY7YEWON.js";
import "./chunk-NRYVRXXR.js";
import {
  incidentReports,
  init_schema,
  threatActors,
  threatGroupEvents
} from "./chunk-2DDCINQV.js";
import "./chunk-KFQGP6VL.js";

// server/lib/government-intel-sources.ts
init_db();
init_schema();
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
async function ingestOFACCyberSanctions() {
  const start = Date.now();
  const result = { source: "OFAC SDN (Cyber)", fetched: 0, newRecords: 0, errors: [], durationMs: 0 };
  try {
    const db = await requireDb();
    const sdnUrl = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML";
    const res = await safeFetch(sdnUrl, {}, 6e4);
    if (!res.ok) {
      const csvUrl = "https://www.treasury.gov/ofac/downloads/sdn.csv";
      const csvRes = await safeFetch(csvUrl, {}, 6e4);
      if (!csvRes.ok) {
        result.errors.push(`OFAC SDN download failed: ${res.status}`);
        result.durationMs = Date.now() - start;
        return result;
      }
      const csvText = await csvRes.text();
      const cyberEntities = parseOFACCsv(csvText);
      result.fetched = cyberEntities.length;
      await processOFACEntities(db, cyberEntities, result);
    } else {
      const xmlText = await res.text();
      const cyberEntities = parseOFACXml(xmlText);
      result.fetched = cyberEntities.length;
      await processOFACEntities(db, cyberEntities, result);
    }
  } catch (err) {
    result.errors.push(`OFAC ingest error: ${err.message}`);
  }
  result.durationMs = Date.now() - start;
  return result;
}
function parseOFACXml(xml) {
  const entities = [];
  const cyberPrograms = ["CYBER2", "CYBER-RELATED", "DPRK", "IRAN", "RUSSIA-EO14024"];
  const entryRegex = /<sdnEntry>([\s\S]*?)<\/sdnEntry>/gi;
  let match;
  while ((match = entryRegex.exec(xml)) !== null) {
    const entry = match[1];
    const programTag = entry.match(/<program>(.*?)<\/program>/gi);
    if (!programTag) continue;
    const programs = programTag.map((p) => p.replace(/<\/?program>/gi, "").trim());
    const isCyber = programs.some(
      (p) => cyberPrograms.some((cp) => p.toUpperCase().includes(cp))
    );
    if (!isCyber) continue;
    const lastName = entry.match(/<lastName>(.*?)<\/lastName>/i)?.[1] || "";
    const firstName = entry.match(/<firstName>(.*?)<\/firstName>/i)?.[1] || "";
    const name = firstName ? `${firstName} ${lastName}` : lastName;
    if (!name.trim()) continue;
    const sdnType = entry.match(/<sdnType>(.*?)<\/sdnType>/i)?.[1] || "";
    const type = sdnType.toLowerCase().includes("individual") ? "individual" : "entity";
    const aliases = [];
    const akaRegex = /<aka>([\s\S]*?)<\/aka>/gi;
    let akaMatch;
    while ((akaMatch = akaRegex.exec(entry)) !== null) {
      const akaName = akaMatch[1].match(/<lastName>(.*?)<\/lastName>/i)?.[1];
      if (akaName) aliases.push(akaName);
    }
    const nationality = entry.match(/<nationality>([\s\S]*?)<\/nationality>/i)?.[1]?.match(/<country>(.*?)<\/country>/i)?.[1] || "";
    const cryptoAddresses = [];
    const idRegex = /<id>([\s\S]*?)<\/id>/gi;
    let idMatch;
    while ((idMatch = idRegex.exec(entry)) !== null) {
      const idType = idMatch[1].match(/<idType>(.*?)<\/idType>/i)?.[1] || "";
      const idNumber = idMatch[1].match(/<idNumber>(.*?)<\/idNumber>/i)?.[1] || "";
      if (idType.toLowerCase().includes("digital currency") || idType.toLowerCase().includes("crypto")) {
        cryptoAddresses.push(`${idType}: ${idNumber}`);
      }
    }
    const sdnId = entry.match(/<uid>(.*?)<\/uid>/i)?.[1] || "";
    const remarks = entry.match(/<remarks>(.*?)<\/remarks>/i)?.[1] || "";
    const listDate = entry.match(/<dateOfList>(.*?)<\/dateOfList>/i)?.[1] || "";
    entities.push({
      name: name.trim(),
      aliases,
      nationality,
      program: programs.join(", "),
      type,
      cryptoAddresses,
      sdnId,
      listDate,
      remarks
    });
  }
  return entities;
}
function parseOFACCsv(csv) {
  const entities = [];
  const lines = csv.split("\n");
  for (const line of lines) {
    const parts = line.split('","').map((p) => p.replace(/^"|"$/g, ""));
    if (parts.length < 4) continue;
    const program = parts[3] || "";
    const cyberPrograms = ["CYBER2", "CYBER", "DPRK"];
    const isCyber = cyberPrograms.some((cp) => program.toUpperCase().includes(cp));
    if (!isCyber) continue;
    const name = parts[1] || "";
    const sdnType = parts[2] || "";
    const remarks = parts[11] || "";
    const cryptoAddresses = [];
    const cryptoRegex = /Digital Currency Address - (\w+) ([A-Za-z0-9]+)/g;
    let cryptoMatch;
    while ((cryptoMatch = cryptoRegex.exec(remarks)) !== null) {
      cryptoAddresses.push(`${cryptoMatch[1]}: ${cryptoMatch[2]}`);
    }
    entities.push({
      name: name.trim(),
      aliases: [],
      nationality: "",
      program,
      type: sdnType.toLowerCase().includes("individual") ? "individual" : "entity",
      cryptoAddresses,
      sdnId: parts[0] || "",
      listDate: "",
      remarks
    });
  }
  return entities;
}
async function processOFACEntities(db, entities, result) {
  for (const entity of entities) {
    try {
      const actorId = slugify(entity.name);
      const [existing] = await db.select({ id: threatActors.id }).from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
      if (!existing) {
        await db.insert(threatActors).values({
          actorId,
          name: entity.name,
          aliases: entity.aliases,
          actorType: entity.type === "individual" ? "cybercrime" : "apt",
          origin: entity.nationality || "Unknown",
          threatLevel: "high",
          description: `OFAC-sanctioned cyber actor. Program: ${entity.program}. ${entity.remarks}`.slice(0, 2e3),
          dataSource: "OFAC SDN List",
          lastActive: entity.listDate || (/* @__PURE__ */ new Date()).toISOString().slice(0, 10)
        }).onDuplicateKeyUpdate({ set: { updatedAt: sql`NOW()` } });
        result.newRecords++;
      }
      await db.insert(threatGroupEvents).values({
        tgeActorId: actorId,
        eventType: "law_enforcement",
        tgeTitle: `OFAC Cyber Sanctions: ${entity.name}`,
        tgeDescription: `OFAC-sanctioned under ${entity.program}. Crypto addresses: ${entity.cryptoAddresses.join(", ") || "None listed"}. ${entity.remarks}`.slice(0, 2e3),
        tgeSeverity: "critical",
        tgeSource: "OFAC SDN List",
        tgeSourceUrl: "https://ofac.treasury.gov/sanctions-list-service",
        tgeConfidence: 100,
        eventDate: entity.listDate ? new Date(entity.listDate).toISOString() : (/* @__PURE__ */ new Date()).toISOString()
      }).onDuplicateKeyUpdate({ set: { tgeDescription: sql`VALUES(tge_description)` } });
    } catch (err) {
      result.errors.push(`OFAC entity ${entity.name}: ${err.message}`);
    }
  }
}
async function ingestRewardsForJustice() {
  const start = Date.now();
  const result = { source: "Rewards for Justice (State Dept)", fetched: 0, newRecords: 0, errors: [], durationMs: 0 };
  try {
    const db = await requireDb();
    const urls = [
      "https://rewardsforjustice.net/rewards/foreign-malicious-cyber-activity-against-u-s-critical-infrastructure/"
    ];
    const mainPageUrl = "https://rewardsforjustice.net/";
    const mainRes = await safeFetch(mainPageUrl, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; AC3-ThreatIntel/1.0)" }
    }, 2e4);
    if (mainRes.ok) {
      const html = await mainRes.text();
      const linkRegex = /href="(https:\/\/rewardsforjustice\.net\/rewards\/[^"]+)"/gi;
      let linkMatch;
      while ((linkMatch = linkRegex.exec(html)) !== null) {
        const url = linkMatch[1];
        if (url.includes("cyber") || url.includes("hack") || url.includes("malicious")) {
          if (!urls.includes(url)) urls.push(url);
        }
      }
    }
    result.fetched = urls.length;
    for (const url of urls) {
      try {
        const res = await safeFetch(url, {
          headers: { "User-Agent": "Mozilla/5.0 (compatible; AC3-ThreatIntel/1.0)" }
        }, 15e3);
        if (!res.ok) continue;
        const html = await res.text();
        const rewardMatch = html.match(/reward of up to \$([0-9,.]+\s*million)/i);
        const rewardAmount = rewardMatch ? rewardMatch[1] : "Unknown";
        const titleMatch = html.match(/<h1[^>]*>(.*?)<\/h1>/i) || html.match(/<title>(.*?)<\/title>/i);
        const title = titleMatch ? titleMatch[1].replace(/<[^>]+>/g, "").trim() : "";
        if (title) {
          await db.insert(threatGroupEvents).values({
            tgeActorId: "state-sponsored-cyber",
            eventType: "law_enforcement",
            tgeTitle: `RFJ: ${title}`.slice(0, 512),
            tgeDescription: `Rewards for Justice offering up to $${rewardAmount} for information. Source: ${url}`,
            tgeSeverity: "critical",
            tgeSource: "US State Department - Rewards for Justice",
            tgeSourceUrl: url.slice(0, 1024),
            tgeConfidence: 100,
            eventDate: (/* @__PURE__ */ new Date()).toISOString()
          }).onDuplicateKeyUpdate({ set: { tgeDescription: sql`VALUES(tge_description)` } });
          result.newRecords++;
        }
      } catch (err) {
        result.errors.push(`RFJ page ${url}: ${err.message}`);
      }
    }
  } catch (err) {
    result.errors.push(`RFJ ingest error: ${err.message}`);
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function ingestFBICyberMostWanted() {
  const start = Date.now();
  const result = { source: "FBI Cyber Most Wanted", fetched: 0, newRecords: 0, errors: [], durationMs: 0 };
  try {
    const db = await requireDb();
    const url = "https://www.fbi.gov/wanted/cyber";
    const res = await safeFetch(url, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; AC3-ThreatIntel/1.0)" }
    }, 2e4);
    if (!res.ok) {
      result.errors.push(`FBI page returned ${res.status}`);
      result.durationMs = Date.now() - start;
      return result;
    }
    const html = await res.text();
    const personRegex = /href="(https:\/\/www\.fbi\.gov\/wanted\/cyber\/[^"]+)"/gi;
    const personUrls = [];
    let personMatch;
    while ((personMatch = personRegex.exec(html)) !== null) {
      if (!personUrls.includes(personMatch[1])) {
        personUrls.push(personMatch[1]);
      }
    }
    result.fetched = personUrls.length;
    const batch = personUrls.slice(0, 30);
    for (const personUrl of batch) {
      try {
        const slug = personUrl.split("/").pop() || "";
        const name = slug.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
        if (!name || name.length < 3) continue;
        const actorId = slugify(name);
        await db.insert(threatGroupEvents).values({
          tgeActorId: actorId,
          eventType: "law_enforcement",
          tgeTitle: `FBI Cyber Most Wanted: ${name}`.slice(0, 512),
          tgeDescription: `FBI Cyber Most Wanted fugitive. Charges: Cyber crimes. See: ${personUrl}`,
          tgeSeverity: "high",
          tgeSource: "FBI Cyber Most Wanted",
          tgeSourceUrl: personUrl.slice(0, 1024),
          tgeConfidence: 100,
          eventDate: (/* @__PURE__ */ new Date()).toISOString()
        }).onDuplicateKeyUpdate({ set: { tgeDescription: sql`VALUES(tge_description)` } });
        const [existing] = await db.select({ id: threatActors.id }).from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
        if (!existing) {
          await db.insert(threatActors).values({
            actorId,
            name,
            actorType: "cybercrime",
            threatLevel: "high",
            description: `FBI Cyber Most Wanted fugitive. See: ${personUrl}`,
            dataSource: "FBI Cyber Most Wanted",
            lastActive: (/* @__PURE__ */ new Date()).toISOString().slice(0, 10)
          }).onDuplicateKeyUpdate({ set: { updatedAt: sql`NOW()` } });
          result.newRecords++;
        }
      } catch (err) {
        result.errors.push(`FBI person ${personUrl}: ${err.message}`);
      }
    }
  } catch (err) {
    result.errors.push(`FBI ingest error: ${err.message}`);
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function ingestDOJCyberIndictments() {
  const start = Date.now();
  const result = { source: "DOJ Cybercrime Indictments", fetched: 0, newRecords: 0, errors: [], durationMs: 0 };
  try {
    const db = await requireDb();
    const feedUrl = "https://www.justice.gov/news/rss";
    const res = await safeFetch(feedUrl, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; AC3-ThreatIntel/1.0)" }
    }, 2e4);
    if (!res.ok) {
      result.errors.push(`DOJ RSS returned ${res.status}`);
      result.durationMs = Date.now() - start;
      return result;
    }
    const xml = await res.text();
    const items = parseSimpleRss(xml);
    result.fetched = items.length;
    const cyberKeywords = [
      "cyber",
      "hack",
      "ransomware",
      "malware",
      "computer fraud",
      "data breach",
      "phishing",
      "botnet",
      "ddos",
      "cryptocurrency",
      "dark web",
      "darknet",
      "identity theft",
      "wire fraud"
    ];
    const cyberItems = items.filter((item) => {
      const text = `${item.title} ${item.description}`.toLowerCase();
      return cyberKeywords.some((kw) => text.includes(kw));
    });
    for (const item of cyberItems.slice(0, 20)) {
      try {
        await db.insert(incidentReports).values({
          sourceId: `doj-${hashString(item.link || item.title)}`,
          title: item.title,
          source: "DOJ Press Release",
          url: item.link,
          irSeverity: "high",
          incidentType: "indictment",
          summary: item.description?.slice(0, 2e3) || "",
          publishedAt: item.pubDate || (/* @__PURE__ */ new Date()).toISOString()
        }).onDuplicateKeyUpdate({ set: { irUpdatedAt: sql`NOW()` } });
        result.newRecords++;
        await db.insert(threatGroupEvents).values({
          tgeActorId: "unknown-cyber",
          eventType: "law_enforcement",
          tgeTitle: `DOJ: ${item.title}`.slice(0, 512),
          tgeDescription: item.description?.slice(0, 2e3) || "",
          tgeSeverity: "high",
          tgeSource: "US Department of Justice",
          tgeSourceUrl: item.link?.slice(0, 1024) || "",
          tgeConfidence: 100,
          eventDate: item.pubDate ? new Date(item.pubDate).toISOString() : (/* @__PURE__ */ new Date()).toISOString()
        }).onDuplicateKeyUpdate({ set: { tgeDescription: sql`VALUES(tge_description)` } });
      } catch (err) {
        result.errors.push(`DOJ item: ${err.message}`);
      }
    }
  } catch (err) {
    result.errors.push(`DOJ ingest error: ${err.message}`);
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function ingestNSAAdvisories() {
  const start = Date.now();
  const result = { source: "NSA Cybersecurity Advisories", fetched: 0, newRecords: 0, errors: [], durationMs: 0 };
  try {
    const db = await requireDb();
    const url = "https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/";
    const res = await safeFetch(url, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; AC3-ThreatIntel/1.0)" }
    }, 2e4);
    if (!res.ok) {
      result.errors.push(`NSA page returned ${res.status}`);
      result.durationMs = Date.now() - start;
      return result;
    }
    const html = await res.text();
    const advisoryRegex = /href="([^"]*(?:CSA|CSI|CTR|ORN)[^"]*)"/gi;
    const advisoryUrls = [];
    let advMatch;
    while ((advMatch = advisoryRegex.exec(html)) !== null) {
      advisoryUrls.push(advMatch[1]);
    }
    const titleRegex = /<a[^>]*href="([^"]+)"[^>]*>(.*?(?:APT|threat|cyber|vulnerability|advisory)[^<]*)<\/a>/gi;
    let titleMatch;
    while ((titleMatch = titleRegex.exec(html)) !== null) {
      const link = titleMatch[1].startsWith("http") ? titleMatch[1] : `https://www.nsa.gov${titleMatch[1]}`;
      const title = titleMatch[2].replace(/<[^>]+>/g, "").trim();
      if (title.length > 10 && !advisoryUrls.includes(link)) {
        advisoryUrls.push(link);
      }
      try {
        await db.insert(incidentReports).values({
          sourceId: `nsa-${hashString(link)}`,
          title: `NSA: ${title}`,
          source: "NSA Cybersecurity Advisory",
          url: link,
          irSeverity: "high",
          incidentType: "advisory",
          summary: `NSA Cybersecurity Advisory: ${title}`,
          publishedAt: (/* @__PURE__ */ new Date()).toISOString()
        }).onDuplicateKeyUpdate({ set: { irUpdatedAt: sql`NOW()` } });
        result.newRecords++;
      } catch {
      }
    }
    result.fetched = advisoryUrls.length;
  } catch (err) {
    result.errors.push(`NSA ingest error: ${err.message}`);
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function ingestACSCAdvisories() {
  const start = Date.now();
  const result = { source: "ACSC (Australia)", fetched: 0, newRecords: 0, errors: [], durationMs: 0 };
  try {
    const db = await requireDb();
    const feedUrl = "https://www.cyber.gov.au/about-us/advisories/rss.xml";
    const res = await safeFetch(feedUrl, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; AC3-ThreatIntel/1.0)" }
    }, 2e4);
    if (!res.ok) {
      const altUrl = "https://www.cyber.gov.au/rss/advisories";
      const altRes = await safeFetch(altUrl, {
        headers: { "User-Agent": "Mozilla/5.0 (compatible; AC3-ThreatIntel/1.0)" }
      }, 2e4);
      if (!altRes.ok) {
        result.errors.push(`ACSC feed returned ${res.status}`);
        result.durationMs = Date.now() - start;
        return result;
      }
      const xml = await altRes.text();
      await processAdvisoryFeed(db, xml, "ACSC (Australia)", result);
    } else {
      const xml = await res.text();
      await processAdvisoryFeed(db, xml, "ACSC (Australia)", result);
    }
  } catch (err) {
    result.errors.push(`ACSC ingest error: ${err.message}`);
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function ingestCCCSAdvisories() {
  const start = Date.now();
  const result = { source: "CCCS (Canada)", fetched: 0, newRecords: 0, errors: [], durationMs: 0 };
  try {
    const db = await requireDb();
    const feedUrl = "https://www.cyber.gc.ca/api/cccs/v1/rss/en";
    const res = await safeFetch(feedUrl, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; AC3-ThreatIntel/1.0)" }
    }, 2e4);
    if (!res.ok) {
      const altUrl = "https://www.cyber.gc.ca/en/alerts-advisories.xml";
      const altRes = await safeFetch(altUrl, {
        headers: { "User-Agent": "Mozilla/5.0 (compatible; AC3-ThreatIntel/1.0)" }
      }, 2e4);
      if (!altRes.ok) {
        result.errors.push(`CCCS feed returned ${res.status}`);
        result.durationMs = Date.now() - start;
        return result;
      }
      const xml = await altRes.text();
      await processAdvisoryFeed(db, xml, "CCCS (Canada)", result);
    } else {
      const xml = await res.text();
      await processAdvisoryFeed(db, xml, "CCCS (Canada)", result);
    }
  } catch (err) {
    result.errors.push(`CCCS ingest error: ${err.message}`);
  }
  result.durationMs = Date.now() - start;
  return result;
}
function parseSimpleRss(xml) {
  const items = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>|<entry>([\s\S]*?)<\/entry>/gi;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const content = match[1] || match[2] || "";
    const title = content.match(/<title[^>]*>(.*?)<\/title>/i)?.[1]?.replace(/<!\[CDATA\[(.*?)\]\]>/g, "$1") || "";
    const link = content.match(/<link[^>]*href="([^"]+)"/i)?.[1] || content.match(/<link[^>]*>(.*?)<\/link>/i)?.[1]?.replace(/<!\[CDATA\[(.*?)\]\]>/g, "$1") || "";
    const description = content.match(/<description[^>]*>(.*?)<\/description>/is)?.[1]?.replace(/<!\[CDATA\[(.*?)\]\]>/gs, "$1")?.replace(/<[^>]+>/g, "") || "";
    const pubDate = content.match(/<pubDate[^>]*>(.*?)<\/pubDate>/i)?.[1] || content.match(/<published[^>]*>(.*?)<\/published>/i)?.[1] || content.match(/<updated[^>]*>(.*?)<\/updated>/i)?.[1] || "";
    if (title) {
      items.push({ title: title.trim(), link: link.trim(), description: description.trim(), pubDate: pubDate.trim() });
    }
  }
  return items;
}
async function processAdvisoryFeed(db, xml, source, result) {
  const items = parseSimpleRss(xml);
  result.fetched = items.length;
  const actorKeywords = [
    "apt",
    "threat actor",
    "state-sponsored",
    "nation-state",
    "ransomware",
    "malware",
    "campaign",
    "exploitation",
    "vulnerability",
    "critical",
    "advisory",
    "alert"
  ];
  for (const item of items.slice(0, 30)) {
    try {
      const text = `${item.title} ${item.description}`.toLowerCase();
      const isRelevant = actorKeywords.some((kw) => text.includes(kw));
      if (!isRelevant) continue;
      let severity = "medium";
      if (text.includes("critical") || text.includes("actively exploit")) severity = "critical";
      else if (text.includes("high") || text.includes("apt") || text.includes("state-sponsored")) severity = "high";
      await db.insert(incidentReports).values({
        sourceId: `${slugify(source)}-${hashString(item.link || item.title)}`,
        title: item.title.slice(0, 500),
        source,
        url: item.link,
        irSeverity: severity,
        incidentType: "advisory",
        summary: item.description?.slice(0, 2e3) || "",
        publishedAt: item.pubDate || (/* @__PURE__ */ new Date()).toISOString()
      }).onDuplicateKeyUpdate({ set: { irUpdatedAt: sql`NOW()` } });
      result.newRecords++;
    } catch (err) {
    }
  }
}
async function runGovernmentIntelIngest() {
  const start = Date.now();
  const results = [];
  console.log("[GovIntel] Starting government intelligence source ingestion...");
  const sources = [
    { name: "OFAC", fn: ingestOFACCyberSanctions },
    { name: "RFJ", fn: ingestRewardsForJustice },
    { name: "FBI", fn: ingestFBICyberMostWanted },
    { name: "DOJ", fn: ingestDOJCyberIndictments },
    { name: "NSA", fn: ingestNSAAdvisories },
    { name: "ACSC", fn: ingestACSCAdvisories },
    { name: "CCCS", fn: ingestCCCSAdvisories }
  ];
  for (const source of sources) {
    try {
      console.log(`[GovIntel] Ingesting ${source.name}...`);
      const result = await source.fn();
      results.push(result);
      console.log(`[GovIntel] ${source.name}: ${result.newRecords} new records (${result.durationMs}ms)`);
      await new Promise((resolve) => setTimeout(resolve, 2e3));
    } catch (err) {
      results.push({
        source: source.name,
        fetched: 0,
        newRecords: 0,
        errors: [err.message],
        durationMs: 0
      });
      console.error(`[GovIntel] ${source.name} failed:`, err.message);
    }
  }
  const totalNewRecords = results.reduce((sum, r) => sum + r.newRecords, 0);
  const successfulSources = results.filter((r) => r.errors.length === 0).length;
  console.log(`[GovIntel] Complete: ${successfulSources}/${sources.length} sources, ${totalNewRecords} new records (${Date.now() - start}ms)`);
  return {
    totalSources: sources.length,
    successfulSources,
    totalNewRecords,
    results,
    durationMs: Date.now() - start
  };
}
export {
  ingestACSCAdvisories,
  ingestCCCSAdvisories,
  ingestDOJCyberIndictments,
  ingestFBICyberMostWanted,
  ingestNSAAdvisories,
  ingestOFACCyberSanctions,
  ingestRewardsForJustice,
  runGovernmentIntelIngest
};
