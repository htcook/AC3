import {
  calculateKevRiskBoost,
  fetchKevCatalog,
  init_kev_service,
  matchTechnologiesAgainstKev
} from "./chunk-PFTNS476.js";
import {
  init_dynamic_cpe_matcher,
  isVersionAffected
} from "./chunk-NIB6SN7A.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/vuln-feeds.ts
async function fetchWithRetry(url, opts = {}, retries = 2, delay = 3e3) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fetch(url, opts);
    } catch (err) {
      if (attempt === retries) throw err;
      console.warn(`[VulnFeeds] Fetch attempt ${attempt + 1} failed for ${url.substring(0, 60)}..., retrying in ${delay}ms`);
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw new Error("fetchWithRetry exhausted");
}
function isCacheValid(entry, ttl) {
  return entry !== null && Date.now() - entry.timestamp < ttl;
}
async function fetchProjectZero() {
  if (isCacheValid(cache.projectZero, CACHE_TTL.projectZero)) {
    return cache.projectZero.data;
  }
  try {
    const res = await fetchWithRetry(PROJECT_ZERO_CSV_URL, {
      headers: { "User-Agent": "AC3-VulnFeed/1.0" },
      signal: AbortSignal.timeout(45e3)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const entries = [];
    const lines = text.split("\n").slice(1);
    for (const line of lines) {
      if (!line.trim()) continue;
      const fields = parseCSVLine(line);
      if (fields.length < 5) continue;
      const cveId = (fields[0] || "").trim();
      if (!cveId.startsWith("CVE-")) continue;
      entries.push({
        cveId,
        vendor: (fields[1] || "").trim(),
        product: (fields[2] || "").trim(),
        type: (fields[3] || "").trim(),
        description: (fields[4] || "").trim(),
        dateDiscovered: (fields[5] || "").trim(),
        attribution: (fields[6] || "").trim()
      });
    }
    cache.projectZero = { data: entries, timestamp: Date.now() };
    console.log(`[VulnFeeds] Project Zero: ${entries.length} 0-day entries loaded`);
    return entries;
  } catch (err) {
    console.error(`[VulnFeeds] Project Zero fetch error: ${err.message}`);
    return cache.projectZero?.data || [];
  }
}
async function fetchNvdRecent(days = 30) {
  if (isCacheValid(cache.nvdRecent, CACHE_TTL.nvd)) {
    return cache.nvdRecent.data;
  }
  try {
    const endDate = /* @__PURE__ */ new Date();
    const startDate = new Date(endDate.getTime() - days * 24 * 60 * 60 * 1e3);
    const fmt = (d) => d.toISOString().replace(/\.\d+Z$/, ".000");
    const url = `${NVD_API_BASE}?pubStartDate=${fmt(startDate)}&pubEndDate=${fmt(endDate)}&resultsPerPage=200`;
    const res = await fetchWithRetry(url, {
      headers: { "User-Agent": "AC3-VulnFeed/1.0" },
      signal: AbortSignal.timeout(45e3)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const items = [];
    for (const vuln of data.vulnerabilities || []) {
      const cve = vuln.cve;
      if (!cve) continue;
      const enDesc = cve.descriptions?.find((d) => d.lang === "en")?.value || "";
      const cvssV3 = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
      let vendor = "", product = "";
      let affectedVersionRange = null;
      const allNodes = cve.configurations?.flatMap((c) => c.nodes || []) || [];
      for (const node of allNodes) {
        for (const cm of node.cpeMatch || []) {
          if (cm?.criteria) {
            const parts = cm.criteria.split(":");
            if (!vendor && parts[3]) vendor = parts[3];
            if (!product && parts[4]) product = parts[4];
          }
          const rangeParts = [];
          if (cm?.versionStartIncluding) rangeParts.push(`>= ${cm.versionStartIncluding}`);
          if (cm?.versionStartExcluding) rangeParts.push(`> ${cm.versionStartExcluding}`);
          if (cm?.versionEndIncluding) rangeParts.push(`<= ${cm.versionEndIncluding}`);
          if (cm?.versionEndExcluding) rangeParts.push(`< ${cm.versionEndExcluding}`);
          if (rangeParts.length > 0 && !affectedVersionRange) {
            affectedVersionRange = rangeParts.join(", ");
          }
        }
      }
      items.push({
        cveId: cve.id,
        description: enDesc,
        published: cve.published || "",
        lastModified: cve.lastModified || "",
        cvssV3Score: cvssV3?.baseScore ?? null,
        cvssV3Severity: cvssV3?.baseSeverity ?? null,
        attackVector: cvssV3?.attackVector ?? null,
        attackComplexity: cvssV3?.attackComplexity ?? null,
        vendor,
        product,
        cweId: cve.weaknesses?.[0]?.description?.[0]?.value || null,
        affectedVersionRange
      });
    }
    cache.nvdRecent = { data: items, timestamp: Date.now() };
    console.log(`[VulnFeeds] NVD: ${items.length} recent CVEs loaded (last ${days} days)`);
    return items;
  } catch (err) {
    console.error(`[VulnFeeds] NVD fetch error: ${err.message}`);
    return cache.nvdRecent?.data || [];
  }
}
async function enrichCveFromNvd(cveId) {
  try {
    const url = `${NVD_API_BASE}?cveId=${cveId}`;
    const res = await fetch(url, {
      headers: { "User-Agent": "AC3-VulnFeed/1.0" },
      signal: AbortSignal.timeout(1e4)
    });
    if (!res.ok) return null;
    const data = await res.json();
    const cve = data.vulnerabilities?.[0]?.cve;
    if (!cve) return null;
    const enDesc = cve.descriptions?.find((d) => d.lang === "en")?.value || "";
    const cvssV3 = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
    let vendor = "", product = "";
    const cpeMatch = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0];
    if (cpeMatch?.criteria) {
      const parts = cpeMatch.criteria.split(":");
      vendor = parts[3] || "";
      product = parts[4] || "";
    }
    return {
      cveId: cve.id,
      description: enDesc,
      published: cve.published || "",
      lastModified: cve.lastModified || "",
      cvssV3Score: cvssV3?.baseScore ?? null,
      cvssV3Severity: cvssV3?.baseSeverity ?? null,
      attackVector: cvssV3?.attackVector ?? null,
      attackComplexity: cvssV3?.attackComplexity ?? null,
      vendor,
      product,
      cweId: cve.weaknesses?.[0]?.description?.[0]?.value || null
    };
  } catch {
    return null;
  }
}
async function fetchCirclRecent() {
  if (isCacheValid(cache.circlRecent, CACHE_TTL.circl)) {
    return cache.circlRecent.data;
  }
  try {
    const res = await fetchWithRetry(`${CIRCL_API_BASE}/last/50`, {
      headers: { "User-Agent": "AC3-VulnFeed/1.0" },
      signal: AbortSignal.timeout(3e4)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    cache.circlRecent = { data: data || [], timestamp: Date.now() };
    console.log(`[VulnFeeds] CIRCL: ${data?.length || 0} recent CVEs loaded`);
    return data || [];
  } catch (err) {
    console.error(`[VulnFeeds] CIRCL fetch error: ${err.message}`);
    return cache.circlRecent?.data || [];
  }
}
async function lookupCveCircl(cveId) {
  try {
    const res = await fetch(`${CIRCL_API_BASE}/cve/${cveId}`, {
      headers: { "User-Agent": "AC3-VulnFeed/1.0" },
      signal: AbortSignal.timeout(8e3)
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}
async function searchCirclByVendor(vendor) {
  try {
    const res = await fetch(`${CIRCL_API_BASE}/browse/${encodeURIComponent(vendor)}`, {
      headers: { "User-Agent": "AC3-VulnFeed/1.0" },
      signal: AbortSignal.timeout(8e3)
    });
    if (!res.ok) return [];
    const data = await res.json();
    return (data?.product || []).map((p) => typeof p === "string" ? p : p?.product || "");
  } catch {
    return [];
  }
}
async function fetchExploitDb() {
  if (isCacheValid(cache.exploitDb, CACHE_TTL.exploitDb)) {
    return cache.exploitDb.data;
  }
  try {
    const res = await fetch(EXPLOITDB_CSV_URL, {
      headers: { "User-Agent": "AC3-VulnFeed/1.0" },
      signal: AbortSignal.timeout(12e4)
      // 2 min — CSV is ~10MB
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const entries = [];
    const lines = text.split("\n").slice(1);
    for (const line of lines) {
      if (!line.trim()) continue;
      const fields = parseCSVLine(line);
      if (fields.length < 12) continue;
      const codes = (fields[11] || "").trim();
      const cveIds = codes.split(";").map((c) => c.trim()).filter((c) => c.startsWith("CVE-"));
      if (cveIds.length === 0) continue;
      entries.push({
        exploitId: (fields[0] || "").trim(),
        description: (fields[2] || "").trim(),
        datePublished: (fields[3] || "").trim(),
        author: (fields[4] || "").trim(),
        platform: (fields[6] || "").trim(),
        type: (fields[5] || "").trim(),
        cveIds
      });
    }
    cache.exploitDb = { data: entries, timestamp: Date.now() };
    console.log(`[VulnFeeds] Exploit-DB: ${entries.length} exploit entries with CVE mappings loaded`);
    return entries;
  } catch (err) {
    console.error(`[VulnFeeds] Exploit-DB fetch error: ${err.message}`);
    return cache.exploitDb?.data || [];
  }
}
function hasPublicExploit(cveId, exploitDb) {
  return exploitDb.find((e) => e.cveIds.includes(cveId)) || null;
}
function parseCSVLine(line) {
  const fields = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === "," && !inQuotes) {
      fields.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields;
}
function severityFromCvss(score) {
  if (score === null) return "unknown";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}
async function buildUnifiedMap() {
  if (isCacheValid(cache.unified, CACHE_TTL.unified)) {
    return cache.unified.data;
  }
  const map = /* @__PURE__ */ new Map();
  const kev = await fetchKevCatalog();
  for (const v of kev.vulnerabilities || []) {
    map.set(v.cveID, {
      cveId: v.cveID,
      title: v.vulnerabilityName,
      description: v.shortDescription,
      severity: "critical",
      // All KEV entries are critical by definition
      cvssScore: null,
      vendor: v.vendorProject,
      product: v.product,
      datePublished: v.dateAdded,
      dateAdded: v.dateAdded,
      sources: ["cisa_kev"],
      exploitAvailable: true,
      inTheWild: true,
      kevListed: true,
      ransomwareLinked: v.knownRansomwareCampaignUse === "Known",
      suggestedTechniques: [],
      patchAvailable: true
      // KEV entries require remediation
    });
  }
  const pzEntries = await fetchProjectZero();
  for (const pz of pzEntries) {
    const existing = map.get(pz.cveId);
    if (existing) {
      if (!existing.sources.includes("project_zero")) {
        existing.sources.push("project_zero");
      }
      existing.inTheWild = true;
    } else {
      map.set(pz.cveId, {
        cveId: pz.cveId,
        title: `${pz.vendor} ${pz.product} ${pz.type}`,
        description: pz.description || `0-day in ${pz.vendor} ${pz.product}`,
        severity: "critical",
        // 0-days are critical
        cvssScore: null,
        vendor: pz.vendor,
        product: pz.product,
        datePublished: pz.dateDiscovered,
        sources: ["project_zero"],
        exploitAvailable: true,
        inTheWild: true,
        kevListed: false,
        ransomwareLinked: false,
        suggestedTechniques: []
      });
    }
  }
  const nvdItems = await fetchNvdRecent(30);
  for (const nvd of nvdItems) {
    const existing = map.get(nvd.cveId);
    if (existing) {
      if (!existing.sources.includes("nvd")) {
        existing.sources.push("nvd");
      }
      existing.cvssScore = nvd.cvssV3Score;
      existing.severity = severityFromCvss(nvd.cvssV3Score);
      existing.attackVector = nvd.attackVector || void 0;
      existing.attackComplexity = nvd.attackComplexity || void 0;
      if (nvd.affectedVersionRange && !existing.affectedVersionRange) {
        existing.affectedVersionRange = nvd.affectedVersionRange;
      }
      if (!existing.description && nvd.description) {
        existing.description = nvd.description;
      }
    } else {
      map.set(nvd.cveId, {
        cveId: nvd.cveId,
        title: nvd.cveId,
        description: nvd.description,
        severity: severityFromCvss(nvd.cvssV3Score),
        cvssScore: nvd.cvssV3Score,
        vendor: nvd.vendor,
        product: nvd.product,
        datePublished: nvd.published,
        sources: ["nvd"],
        exploitAvailable: false,
        inTheWild: false,
        kevListed: false,
        ransomwareLinked: false,
        suggestedTechniques: [],
        attackVector: nvd.attackVector || void 0,
        attackComplexity: nvd.attackComplexity || void 0,
        affectedVersionRange: nvd.affectedVersionRange || void 0
      });
    }
  }
  const circlItems = await fetchCirclRecent();
  for (const c of circlItems) {
    const existing = map.get(c.id);
    if (existing) {
      if (!existing.sources.includes("circl")) {
        existing.sources.push("circl");
      }
      if (existing.cvssScore === null && c.cvss3) {
        existing.cvssScore = c.cvss3;
        existing.severity = severityFromCvss(c.cvss3);
      }
    } else {
      map.set(c.id, {
        cveId: c.id,
        title: c.id,
        description: c.summary || "",
        severity: severityFromCvss(c.cvss3 || c.cvss),
        cvssScore: c.cvss3 || c.cvss,
        vendor: "",
        product: "",
        datePublished: c.Published || "",
        sources: ["circl"],
        exploitAvailable: false,
        inTheWild: false,
        kevListed: false,
        ransomwareLinked: false,
        suggestedTechniques: []
      });
    }
  }
  const exploitDb = await fetchExploitDb();
  for (const exp of exploitDb) {
    for (const cveId of exp.cveIds) {
      const existing = map.get(cveId);
      if (existing) {
        existing.exploitAvailable = true;
        existing.exploitDbId = exp.exploitId;
        if (!existing.sources.includes("exploit_db")) {
          existing.sources.push("exploit_db");
        }
      }
    }
  }
  cache.unified = { data: map, timestamp: Date.now() };
  console.log(`[VulnFeeds] Unified map: ${map.size} total CVEs from all sources`);
  return map;
}
async function getVulnFeedStats() {
  const map = await buildUnifiedMap();
  const entries = Array.from(map.values());
  const bySource = {
    cisa_kev: 0,
    project_zero: 0,
    nvd: 0,
    circl: 0,
    exploit_db: 0
  };
  const bySeverity = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0
  };
  let exploitAvailableCount = 0;
  let inTheWildCount = 0;
  let kevListedCount = 0;
  let ransomwareLinkedCount = 0;
  for (const e of entries) {
    for (const s of e.sources) bySource[s]++;
    bySeverity[e.severity]++;
    if (e.exploitAvailable) exploitAvailableCount++;
    if (e.inTheWild) inTheWildCount++;
    if (e.kevListed) kevListedCount++;
    if (e.ransomwareLinked) ransomwareLinkedCount++;
  }
  return {
    totalEntries: entries.length,
    bySource,
    bySeverity,
    exploitAvailableCount,
    inTheWildCount,
    kevListedCount,
    ransomwareLinkedCount,
    lastUpdated: (/* @__PURE__ */ new Date()).toISOString(),
    feedHealth: {
      cisa_kev: cache.unified ? "ok" : "error",
      project_zero: cache.projectZero ? "ok" : "stale",
      nvd: cache.nvdRecent ? "ok" : "stale",
      circl: cache.circlRecent ? "ok" : "stale",
      exploit_db: cache.exploitDb ? "ok" : "stale"
    }
  };
}
async function getVulnTrendData(days = 7) {
  const map = await buildUnifiedMap();
  const entries = Array.from(map.values());
  const now = /* @__PURE__ */ new Date();
  const result = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().slice(0, 10);
    result.push({ date: dateStr, critical: 0, high: 0, medium: 0, low: 0, total: 0 });
  }
  for (const entry of entries) {
    const pubDate = (entry.datePublished || entry.dateAdded || "").slice(0, 10);
    const bucket = result.find((r) => r.date === pubDate);
    if (bucket) {
      bucket.total++;
      if (entry.severity === "critical") bucket.critical++;
      else if (entry.severity === "high") bucket.high++;
      else if (entry.severity === "medium") bucket.medium++;
      else if (entry.severity === "low") bucket.low++;
    }
  }
  return result;
}
async function getRecentZeroDays(limit = 50) {
  const map = await buildUnifiedMap();
  const cutoff = Date.now() - 120 * 24 * 60 * 60 * 1e3;
  return Array.from(map.values()).filter((e) => e.inTheWild && new Date(e.datePublished).getTime() >= cutoff).sort((a, b) => new Date(b.datePublished).getTime() - new Date(a.datePublished).getTime()).slice(0, limit);
}
async function getWeaponizedCves(limit = 50) {
  const map = await buildUnifiedMap();
  const cutoff = Date.now() - 120 * 24 * 60 * 60 * 1e3;
  return Array.from(map.values()).filter((e) => e.exploitAvailable && !e.kevListed && new Date(e.datePublished).getTime() >= cutoff).sort((a, b) => new Date(b.datePublished).getTime() - new Date(a.datePublished).getTime()).slice(0, limit);
}
async function matchTechnologiesAgainstAllFeeds(technologies, detectedVersions) {
  const map = await buildUnifiedMap();
  const kevCatalog = await fetchKevCatalog();
  const kevMatches = matchTechnologiesAgainstKev(technologies, kevCatalog);
  const kevRisk = calculateKevRiskBoost(kevMatches);
  const techMatches = [];
  let totalVulns = 0;
  let totalExploits = 0;
  let totalKev = 0;
  let totalZeroDay = 0;
  let confirmedVulnCount = 0;
  let probableVulnCount = 0;
  let potentialVulnCount = 0;
  const versions = detectedVersions || {};
  const PRODUCT_ALIASES = {
    "apache": ["http server", "httpd", "apache2"],
    "nginx": ["nginx"],
    "iis": ["internet information services", "iis"],
    "openssl": ["openssl"],
    "jquery": ["jquery"]
  };
  for (const tech of technologies) {
    const techLower = tech.toLowerCase().trim();
    if (techLower.length < 3) continue;
    const matchedVulns = [];
    for (const entry of Array.from(map.values())) {
      const vendorLower = (entry.vendor || "").toLowerCase();
      const productLower = (entry.product || "").toLowerCase();
      const titleLower = (entry.title || "").toLowerCase();
      const directProductMatch = productLower.length >= 3 && productLower.includes(techLower) || productLower.length >= 3 && techLower.includes(productLower);
      const aliases = PRODUCT_ALIASES[techLower] || [];
      const aliasProductMatch = aliases.some(
        (alias) => (productLower.includes(alias) || alias.includes(productLower)) && productLower.length >= 3
      );
      const techIsVendorName = vendorLower.length >= 3 && (techLower === vendorLower || vendorLower.includes(techLower));
      const titleMatch = titleLower.length >= 3 && titleLower.includes(techLower) && !techIsVendorName;
      const isProductMatch = directProductMatch || aliasProductMatch || titleMatch;
      const vendorMatch = !isProductMatch && vendorLower.length >= 3 && (vendorLower.includes(techLower) || techLower.includes(vendorLower));
      if (techLower.length >= 4 && (isProductMatch || vendorMatch)) {
        entry._matchSpecificity = isProductMatch ? "product" : "vendor_only";
        matchedVulns.push(entry);
      }
    }
    if (matchedVulns.length > 0) {
      const detectedVersion = versions[tech] || versions[techLower];
      const hasVersionMatch = !!detectedVersion;
      let filteredVulns;
      if (hasVersionMatch) {
        filteredVulns = matchedVulns.filter((v) => {
          if (!v.affectedVersionRange) return true;
          return isVersionAffected(detectedVersion, v.affectedVersionRange);
        });
        if (filteredVulns.length < matchedVulns.length) {
          console.log(`[VulnFeeds] Version filter for ${tech} v${detectedVersion}: ${matchedVulns.length} \u2192 ${filteredVulns.length} CVEs (removed ${matchedVulns.length - filteredVulns.length} non-matching)`);
        }
      } else {
        filteredVulns = matchedVulns;
      }
      if (filteredVulns.length === 0) continue;
      const exploitCount = filteredVulns.filter((v) => v.exploitAvailable).length;
      const kevCount = filteredVulns.filter((v) => v.kevListed).length;
      const zeroDayCount = filteredVulns.filter((v) => v.inTheWild).length;
      const hasKev = kevCount > 0;
      const hasZeroDay = zeroDayCount > 0;
      const hasExploit = exploitCount > 0;
      const hasProductSpecificMatch = matchedVulns.some((v) => v._matchSpecificity === "product");
      let tier;
      if ((hasKev || hasZeroDay || hasVersionMatch && hasExploit) && hasProductSpecificMatch) {
        tier = "confirmed";
      } else if (hasProductSpecificMatch && (hasVersionMatch || hasExploit)) {
        tier = "probable";
      } else if (!hasProductSpecificMatch && hasVersionMatch && hasExploit) {
        tier = "probable";
      } else {
        tier = "potential";
      }
      let techConfirmed = 0, techProbable = 0, techPotential = 0;
      for (const v of filteredVulns) {
        const isVulnProductSpecific = v._matchSpecificity === "product";
        if ((v.kevListed || v.inTheWild) && isVulnProductSpecific) {
          techConfirmed++;
        } else if (isVulnProductSpecific && (hasVersionMatch || v.exploitAvailable)) {
          techProbable++;
        } else if (!isVulnProductSpecific && hasVersionMatch && v.exploitAvailable) {
          techProbable++;
        } else {
          techPotential++;
        }
      }
      const maxCvss = Math.max(...filteredVulns.map((v) => v.cvssScore || 0));
      const riskScore = Math.min(100, Math.round(
        maxCvss / 10 * 40 + (exploitCount > 0 ? 25 : 0) + (kevCount > 0 ? 20 : 0) + (zeroDayCount > 0 ? 15 : 0)
      ));
      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
      const maxSeverity = filteredVulns.reduce(
        (max, v) => severityOrder[v.severity] > severityOrder[max] ? v.severity : max,
        "unknown"
      );
      techMatches.push({
        technology: tech,
        vulns: filteredVulns.sort((a, b) => {
          const scoreA = a.cvssScore || 0;
          const scoreB = b.cvssScore || 0;
          if (scoreB !== scoreA) return scoreB - scoreA;
          const kevA = a.kevListed ? 1 : 0;
          const kevB = b.kevListed ? 1 : 0;
          return kevB - kevA;
        }).slice(0, 25),
        maxSeverity,
        exploitCount,
        kevCount,
        riskScore,
        corroborationTier: tier,
        confirmedVulnCount: techConfirmed,
        probableVulnCount: techProbable,
        potentialVulnCount: techPotential,
        _matchSpecificity: hasProductSpecificMatch ? "product" : "vendor_only"
      });
      totalVulns += filteredVulns.length;
      totalExploits += exploitCount;
      totalKev += kevCount;
      totalZeroDay += zeroDayCount;
      confirmedVulnCount += techConfirmed;
      probableVulnCount += techProbable;
      potentialVulnCount += techPotential;
    }
  }
  return {
    matches: techMatches.sort((a, b) => {
      const tierOrder = { confirmed: 3, probable: 2, potential: 1 };
      const tierA = tierOrder[a.corroborationTier] || 0;
      const tierB = tierOrder[b.corroborationTier] || 0;
      if (tierB !== tierA) return tierB - tierA;
      return b.riskScore - a.riskScore;
    }),
    totalVulns,
    totalExploits,
    totalKev,
    totalZeroDay,
    overallRiskBoost: kevRisk.riskBoost,
    confirmedVulnCount,
    probableVulnCount,
    potentialVulnCount
  };
}
async function enrichCve(cveId) {
  const map = await buildUnifiedMap();
  const existing = map.get(cveId);
  if (existing) return existing;
  const nvd = await enrichCveFromNvd(cveId);
  if (nvd) {
    return {
      cveId: nvd.cveId,
      title: nvd.cveId,
      description: nvd.description,
      severity: severityFromCvss(nvd.cvssV3Score),
      cvssScore: nvd.cvssV3Score,
      vendor: nvd.vendor,
      product: nvd.product,
      datePublished: nvd.published,
      sources: ["nvd"],
      exploitAvailable: false,
      inTheWild: false,
      kevListed: false,
      ransomwareLinked: false,
      suggestedTechniques: [],
      attackVector: nvd.attackVector || void 0,
      attackComplexity: nvd.attackComplexity || void 0
    };
  }
  const circl = await lookupCveCircl(cveId);
  if (circl) {
    return {
      cveId: circl.id,
      title: circl.id,
      description: circl.summary || "",
      severity: severityFromCvss(circl.cvss3 || circl.cvss),
      cvssScore: circl.cvss3 || circl.cvss,
      vendor: "",
      product: "",
      datePublished: circl.Published || "",
      sources: ["circl"],
      exploitAvailable: false,
      inTheWild: false,
      kevListed: false,
      ransomwareLinked: false,
      suggestedTechniques: []
    };
  }
  return null;
}
async function searchVulnerabilities(query, filters, limit = 100) {
  const map = await buildUnifiedMap();
  const queryLower = query.toLowerCase();
  let results = Array.from(map.values());
  if (query) {
    results = results.filter(
      (e) => (e.cveId || "").toLowerCase().includes(queryLower) || (e.title || "").toLowerCase().includes(queryLower) || (e.description || "").toLowerCase().includes(queryLower) || (e.vendor || "").toLowerCase().includes(queryLower) || (e.product || "").toLowerCase().includes(queryLower)
    );
  }
  if (filters?.severity) {
    results = results.filter((e) => e.severity === filters.severity);
  }
  if (filters?.source) {
    results = results.filter((e) => e.sources.includes(filters.source));
  }
  if (filters?.exploitOnly) {
    results = results.filter((e) => e.exploitAvailable);
  }
  if (filters?.kevOnly) {
    results = results.filter((e) => e.kevListed);
  }
  if (filters?.zeroDayOnly) {
    results = results.filter((e) => e.inTheWild);
  }
  return results.sort((a, b) => {
    if (a.kevListed !== b.kevListed) return a.kevListed ? -1 : 1;
    if (a.inTheWild !== b.inTheWild) return a.inTheWild ? -1 : 1;
    if (a.exploitAvailable !== b.exploitAvailable) return a.exploitAvailable ? -1 : 1;
    return (b.cvssScore || 0) - (a.cvssScore || 0);
  }).slice(0, limit);
}
function getVulnFeedChainSteps(matches, detectedVersions) {
  const steps = [];
  const seenTechniques = /* @__PURE__ */ new Set();
  for (const match of matches) {
    const hasVersion = detectedVersions && Object.keys(detectedVersions).some(
      (tech) => tech.toLowerCase().includes(match.technology.toLowerCase()) || match.technology.toLowerCase().includes(tech.toLowerCase())
    );
    const tier = hasVersion ? "confirmed" : "probable";
    for (const vuln of match.vulns) {
      if (!vuln.exploitAvailable && !vuln.inTheWild && !vuln.kevListed) continue;
      for (const tid of vuln.suggestedTechniques) {
        if (seenTechniques.has(tid)) continue;
        seenTechniques.add(tid);
        let priority;
        if (tier === "confirmed") {
          priority = vuln.inTheWild || vuln.kevListed ? 1 : 2;
        } else {
          priority = vuln.inTheWild || vuln.kevListed ? 2 : 3;
        }
        const versionNote = hasVersion ? " [VERSION CONFIRMED]" : " [VERSION UNCONFIRMED]";
        steps.push({
          techniqueId: tid,
          priority,
          source: "vuln_feed",
          context: `${vuln.cveId} (${vuln.severity.toUpperCase()}, CVSS ${vuln.cvssScore || "N/A"}) affecting ${match.technology}${vuln.inTheWild ? " [0-DAY]" : ""}${vuln.kevListed ? " [KEV]" : ""}${vuln.exploitAvailable ? " [EXPLOIT]" : ""}${versionNote}`,
          corroborationTier: tier
        });
      }
    }
  }
  return steps;
}
var cache, CACHE_TTL, PROJECT_ZERO_CSV_URL, NVD_API_BASE, CIRCL_API_BASE, EXPLOITDB_CSV_URL;
var init_vuln_feeds = __esm({
  "server/lib/vuln-feeds.ts"() {
    init_kev_service();
    init_dynamic_cpe_matcher();
    cache = {
      projectZero: null,
      nvdRecent: null,
      circlRecent: null,
      exploitDb: null,
      unified: null
    };
    CACHE_TTL = {
      projectZero: 12 * 60 * 60 * 1e3,
      // 12 hours (CSV, infrequent updates)
      nvd: 2 * 60 * 60 * 1e3,
      // 2 hours (API, rate limited)
      circl: 1 * 60 * 60 * 1e3,
      // 1 hour (API, fast)
      exploitDb: 24 * 60 * 60 * 1e3,
      // 24 hours (CSV, large file)
      unified: 30 * 60 * 1e3
      // 30 minutes
    };
    PROJECT_ZERO_CSV_URL = "https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/export?format=csv&gid=0";
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    CIRCL_API_BASE = "https://cve.circl.lu/api";
    EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv";
  }
});

export {
  fetchProjectZero,
  fetchNvdRecent,
  enrichCveFromNvd,
  fetchCirclRecent,
  lookupCveCircl,
  searchCirclByVendor,
  fetchExploitDb,
  hasPublicExploit,
  parseCSVLine,
  severityFromCvss,
  buildUnifiedMap,
  getVulnFeedStats,
  getVulnTrendData,
  getRecentZeroDays,
  getWeaponizedCves,
  matchTechnologiesAgainstAllFeeds,
  enrichCve,
  searchVulnerabilities,
  getVulnFeedChainSteps,
  init_vuln_feeds
};
