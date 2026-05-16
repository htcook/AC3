import {
  getDb,
  init_db
} from "./chunk-AX6SVAQZ.js";
import "./chunk-NRYVRXXR.js";
import {
  corroborationResults,
  init_schema
} from "./chunk-DQZ564DJ.js";
import "./chunk-KFQGP6VL.js";

// server/lib/corroboration-engine.ts
init_db();
init_schema();
import { desc } from "drizzle-orm";
var SOURCE_WEIGHTS = {
  manual: 1,
  bas: 0.95,
  nessus: 0.85,
  qualys: 0.85,
  rapid7: 0.85,
  siem: 0.8,
  osint: 0.6,
  shodan: 0.55,
  censys: 0.55,
  threatintel: 0.7,
  // Integrated tool modules
  zap_passive: 0.65,
  zap_active: 0.85,
  zap: 0.8,
  nuclei_info: 0.6,
  nuclei_vuln: 0.8,
  nuclei_critical: 0.9,
  nuclei: 0.75,
  sliver_c2: 0.95,
  sliver: 0.95,
  atomic_red_team: 0.9,
  atomic: 0.9,
  metasploit: 0.95,
  caldera: 0.9,
  gophish: 0.7,
  bloodhound: 0.85
};
var CORROBORATION_BOOST = 12;
var CONTRADICTION_PENALTY = 18;
var SUPPRESSION_THRESHOLD = 25;
var CONFIRMATION_MIN_SOURCES = 3;
function findingMatchKey(f) {
  const keys = [];
  if (f.cveId) keys.push(`cve:${f.cveId.toUpperCase()}:${f.hostOrAsset.toLowerCase()}`);
  if (f.port && f.service) keys.push(`svc:${f.hostOrAsset.toLowerCase()}:${f.port}:${f.service.toLowerCase()}`);
  if (f.cweId) keys.push(`cwe:${f.cweId}:${f.hostOrAsset.toLowerCase()}`);
  keys.push(`title:${f.title.toLowerCase().replace(/[^a-z0-9]/g, "")}:${f.hostOrAsset.toLowerCase()}`);
  return keys;
}
function buildCorrelationMap(findings) {
  const map = /* @__PURE__ */ new Map();
  for (const f of findings) {
    for (const key of findingMatchKey(f)) {
      const existing = map.get(key) || [];
      existing.push(f);
      map.set(key, existing);
    }
  }
  return map;
}
function assessRelationship(primary, other) {
  if (primary.source === other.source) return "neutral";
  if (primary.cveId && other.cveId && primary.cveId.toUpperCase() === other.cveId.toUpperCase()) {
    const sevOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const diff = Math.abs(sevOrder[primary.severity] - sevOrder[other.severity]);
    if (diff >= 3) return "contradict";
    return "corroborate";
  }
  if (primary.hostOrAsset === other.hostOrAsset && primary.port === other.port && primary.service === other.service) {
    return "corroborate";
  }
  const pTitle = primary.title.toLowerCase().replace(/[^a-z0-9]/g, "");
  const oTitle = other.title.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (pTitle === oTitle) return "corroborate";
  return "neutral";
}
function corroborateFindings(findings) {
  const correlationMap = buildCorrelationMap(findings);
  const results = [];
  const processedIds = /* @__PURE__ */ new Set();
  for (const finding of findings) {
    if (processedIds.has(finding.id)) continue;
    processedIds.add(finding.id);
    const keys = findingMatchKey(finding);
    const relatedFindings = /* @__PURE__ */ new Set();
    for (const key of keys) {
      for (const r of correlationMap.get(key) || []) {
        if (r.id !== finding.id) relatedFindings.add(r);
      }
    }
    const corroborating = [];
    const contradicting = [];
    for (const related of Array.from(relatedFindings)) {
      const rel = assessRelationship(finding, related);
      if (rel === "corroborate" && !corroborating.includes(related.source)) corroborating.push(related.source);
      else if (rel === "contradict" && !contradicting.includes(related.source)) contradicting.push(related.source);
    }
    const sourceWeight = SOURCE_WEIGHTS[finding.source.toLowerCase()] || 0.5;
    let adjustedConfidence = finding.rawConfidence * sourceWeight;
    for (const src of corroborating) adjustedConfidence += CORROBORATION_BOOST * (SOURCE_WEIGHTS[src.toLowerCase()] || 0.5);
    for (const src of contradicting) adjustedConfidence -= CONTRADICTION_PENALTY * (SOURCE_WEIGHTS[src.toLowerCase()] || 0.5);
    adjustedConfidence = Math.max(0, Math.min(100, Math.round(adjustedConfidence)));
    let verdict;
    if (corroborating.length >= CONFIRMATION_MIN_SOURCES && adjustedConfidence >= 80) verdict = "confirmed";
    else if (corroborating.length >= 1 && adjustedConfidence >= 60) verdict = "likely";
    else if (adjustedConfidence >= 30) verdict = "unverified";
    else if (adjustedConfidence >= 15) verdict = "likely_false_positive";
    else verdict = "false_positive";
    const reasonParts = [];
    reasonParts.push(`Base confidence ${finding.rawConfidence}% from ${finding.source} (weight ${sourceWeight}).`);
    if (corroborating.length > 0) reasonParts.push(`Corroborated by ${corroborating.length} source(s): ${corroborating.join(", ")}.`);
    if (contradicting.length > 0) reasonParts.push(`Contradicted by ${contradicting.length} source(s): ${contradicting.join(", ")}.`);
    reasonParts.push(`Adjusted confidence: ${adjustedConfidence}%. Verdict: ${verdict}.`);
    results.push({
      findingId: finding.id,
      originalConfidence: finding.rawConfidence,
      adjustedConfidence,
      corroboratingSourceCount: corroborating.length,
      contradictingSourceCount: contradicting.length,
      corroboratingSources: corroborating,
      contradictingSources: contradicting,
      verdict,
      reasoning: reasonParts.join(" "),
      suppressRecommendation: adjustedConfidence < SUPPRESSION_THRESHOLD
    });
  }
  const suppressedCount = results.filter((r) => r.suppressRecommendation).length;
  return {
    totalFindings: results.length,
    corroboratedFindings: results.filter((r) => r.verdict === "confirmed" || r.verdict === "likely").length,
    suppressedFindings: suppressedCount,
    falsePositiveRate: results.length > 0 ? Math.round(suppressedCount / results.length * 100) : 0,
    results,
    generatedAt: Date.now()
  };
}
function estimateFPReduction(report) {
  if (report.totalFindings === 0) return 0;
  return Math.round(report.suppressedFindings / report.totalFindings * 100);
}
var ALL_SOURCES = ["nvd", "shodan", "censys", "urlscan", "abuseipdb", "securitytrails", "dehashed"];
async function queryShodan(findingType, findingValue) {
  const apiKey = process.env.SHODAN_API_KEY;
  if (!apiKey) return { source: "shodan", found: false, confidence: 0, details: "Shodan API key not configured \u2014 skipped" };
  try {
    let url;
    if (findingType === "ip" || findingType === "host") {
      url = `https://api.shodan.io/shodan/host/${encodeURIComponent(findingValue)}?key=${apiKey}`;
    } else if (findingType === "cve") {
      url = `https://api.shodan.io/shodan/host/search?key=${apiKey}&query=vuln:${encodeURIComponent(findingValue)}&minify=true`;
    } else {
      url = `https://api.shodan.io/shodan/host/search?key=${apiKey}&query=${encodeURIComponent(findingValue)}&minify=true`;
    }
    const response = await fetch(url, { signal: AbortSignal.timeout(15e3) });
    if (!response.ok) {
      if (response.status === 404) return { source: "shodan", found: false, confidence: 0, details: `No Shodan data found for ${findingValue}` };
      return { source: "shodan", found: false, confidence: 0, details: `Shodan API error: ${response.status}` };
    }
    const data = await response.json();
    const hasData = findingType === "cve" ? data.total && data.total > 0 : data.ip_str || data.ports?.length > 0;
    return {
      source: "shodan",
      found: !!hasData,
      confidence: hasData ? 70 : 0,
      details: hasData ? `Shodan confirms: ${findingType === "cve" ? `${data.total} hosts affected` : `${data.ports?.length || 0} open ports, OS: ${data.os || "unknown"}`}` : `No matching Shodan data for ${findingValue}`,
      rawData: { total: data.total, ports: data.ports, os: data.os, vulns: data.vulns }
    };
  } catch (err) {
    return { source: "shodan", found: false, confidence: 0, details: `Shodan query failed: ${err.message}` };
  }
}
async function queryCensys(findingType, findingValue) {
  const apiId = process.env.CENSYS_API_ID;
  const apiSecret = process.env.CENSYS_API_SECRET;
  if (!apiId || !apiSecret) return { source: "censys", found: false, confidence: 0, details: "Censys API credentials not configured \u2014 skipped" };
  try {
    const auth = Buffer.from(`${apiId}:${apiSecret}`).toString("base64");
    let url;
    let body;
    if (findingType === "ip" || findingType === "host") {
      url = `https://search.censys.io/api/v2/hosts/${encodeURIComponent(findingValue)}`;
    } else {
      url = `https://search.censys.io/api/v2/hosts/search`;
      body = JSON.stringify({ q: findingValue, per_page: 5 });
    }
    const response = await fetch(url, {
      method: body ? "POST" : "GET",
      headers: {
        "Authorization": `Basic ${auth}`,
        "Content-Type": "application/json"
      },
      body,
      signal: AbortSignal.timeout(15e3)
    });
    if (!response.ok) {
      if (response.status === 404) return { source: "censys", found: false, confidence: 0, details: `No Censys data for ${findingValue}` };
      return { source: "censys", found: false, confidence: 0, details: `Censys API error: ${response.status}` };
    }
    const data = await response.json();
    const hasData = data.result?.ip || data.result?.hits?.length > 0;
    return {
      source: "censys",
      found: !!hasData,
      confidence: hasData ? 65 : 0,
      details: hasData ? `Censys confirms: ${data.result?.ip ? `Host found with ${data.result?.services?.length || 0} services` : `${data.result?.hits?.length || 0} matching hosts`}` : `No matching Censys data for ${findingValue}`,
      rawData: data.result
    };
  } catch (err) {
    return { source: "censys", found: false, confidence: 0, details: `Censys query failed: ${err.message}` };
  }
}
async function queryUrlscan(findingType, findingValue) {
  const apiKey = process.env.URLSCAN_API_KEY;
  if (!apiKey) return { source: "urlscan", found: false, confidence: 0, details: "URLScan API key not configured \u2014 skipped" };
  try {
    const query = findingType === "domain" ? `domain:${findingValue}` : findingValue;
    const url = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(query)}&size=5`;
    const response = await fetch(url, {
      headers: { "API-Key": apiKey },
      signal: AbortSignal.timeout(15e3)
    });
    if (!response.ok) return { source: "urlscan", found: false, confidence: 0, details: `URLScan API error: ${response.status}` };
    const data = await response.json();
    const hasResults = data.results && data.results.length > 0;
    return {
      source: "urlscan",
      found: hasResults,
      confidence: hasResults ? 55 : 0,
      details: hasResults ? `URLScan found ${data.results.length} scan(s) for ${findingValue}. Latest: ${data.results[0]?.task?.time || "unknown"}` : `No URLScan results for ${findingValue}`,
      rawData: { total: data.total, results: data.results?.slice(0, 3) }
    };
  } catch (err) {
    return { source: "urlscan", found: false, confidence: 0, details: `URLScan query failed: ${err.message}` };
  }
}
async function queryNvd(findingType, findingValue) {
  try {
    let url;
    if (findingType === "cve" && findingValue.match(/^CVE-\d{4}-\d+$/i)) {
      url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(findingValue.toUpperCase())}`;
    } else {
      url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(findingValue)}&resultsPerPage=5`;
    }
    const response = await fetch(url, { signal: AbortSignal.timeout(15e3) });
    if (!response.ok) return { source: "nvd", found: false, confidence: 0, details: `NVD API error: ${response.status}` };
    const data = await response.json();
    const vulns = data.vulnerabilities || [];
    const hasData = vulns.length > 0;
    if (hasData) {
      const cve = vulns[0].cve;
      const cvss = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || "N/A";
      return {
        source: "nvd",
        found: true,
        confidence: 85,
        details: `NVD confirms: ${cve.id} \u2014 CVSS ${cvss}. ${cve.descriptions?.[0]?.value?.slice(0, 200) || ""}`,
        rawData: { cveId: cve.id, cvss, description: cve.descriptions?.[0]?.value }
      };
    }
    return { source: "nvd", found: false, confidence: 0, details: `No NVD data found for ${findingValue}` };
  } catch (err) {
    return { source: "nvd", found: false, confidence: 0, details: `NVD query failed: ${err.message}` };
  }
}
async function querySecurityTrails(findingType, findingValue) {
  const apiKey = process.env.SECURITYTRAILS_API_KEY;
  if (!apiKey) return { source: "securitytrails", found: false, confidence: 0, details: "SecurityTrails API key not configured \u2014 skipped" };
  try {
    let url;
    if (findingType === "domain") {
      url = `https://api.securitytrails.com/v1/domain/${encodeURIComponent(findingValue)}`;
    } else if (findingType === "ip" || findingType === "host") {
      url = `https://api.securitytrails.com/v1/ips/nearby/${encodeURIComponent(findingValue)}`;
    } else {
      return { source: "securitytrails", found: false, confidence: 0, details: `SecurityTrails does not support ${findingType} lookups` };
    }
    const response = await fetch(url, {
      headers: { "APIKEY": apiKey },
      signal: AbortSignal.timeout(15e3)
    });
    if (!response.ok) return { source: "securitytrails", found: false, confidence: 0, details: `SecurityTrails API error: ${response.status}` };
    const data = await response.json();
    const hasData = data.hostname || data.blocks?.length > 0;
    return {
      source: "securitytrails",
      found: !!hasData,
      confidence: hasData ? 60 : 0,
      details: hasData ? `SecurityTrails: ${data.hostname || findingValue} \u2014 A records: ${data.current_dns?.a?.values?.length || 0}, MX: ${data.current_dns?.mx?.values?.length || 0}` : `No SecurityTrails data for ${findingValue}`,
      rawData: data
    };
  } catch (err) {
    return { source: "securitytrails", found: false, confidence: 0, details: `SecurityTrails query failed: ${err.message}` };
  }
}
async function queryAbuseIpdb(findingType, findingValue) {
  const apiKey = process.env.ABUSECH_API_KEY;
  if (!apiKey) return { source: "abuseipdb", found: false, confidence: 0, details: "AbuseIPDB API key not configured \u2014 skipped" };
  if (findingType !== "ip" && findingType !== "host") {
    return { source: "abuseipdb", found: false, confidence: 0, details: "AbuseIPDB only supports IP lookups" };
  }
  try {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(findingValue)}&maxAgeInDays=90`;
    const response = await fetch(url, {
      headers: { "Key": apiKey, "Accept": "application/json" },
      signal: AbortSignal.timeout(15e3)
    });
    if (!response.ok) return { source: "abuseipdb", found: false, confidence: 0, details: `AbuseIPDB API error: ${response.status}` };
    const data = await response.json();
    const abuseScore = data.data?.abuseConfidenceScore || 0;
    const totalReports = data.data?.totalReports || 0;
    return {
      source: "abuseipdb",
      found: totalReports > 0,
      confidence: Math.min(80, abuseScore),
      details: totalReports > 0 ? `AbuseIPDB: ${findingValue} has ${totalReports} report(s), abuse score: ${abuseScore}%` : `AbuseIPDB: ${findingValue} has no abuse reports`,
      rawData: { abuseScore, totalReports, countryCode: data.data?.countryCode }
    };
  } catch (err) {
    return { source: "abuseipdb", found: false, confidence: 0, details: `AbuseIPDB query failed: ${err.message}` };
  }
}
async function queryDehashed(findingType, findingValue) {
  const apiKey = process.env.DEHASHED_API_KEY;
  const email = process.env.DEHASHED_EMAIL;
  if (!apiKey || !email) return { source: "dehashed", found: false, confidence: 0, details: "DeHashed credentials not configured \u2014 skipped" };
  try {
    const query = findingType === "email" ? `email:${findingValue}` : `domain:${findingValue}`;
    const auth = Buffer.from(`${email}:${apiKey}`).toString("base64");
    const url = `https://api.dehashed.com/search?query=${encodeURIComponent(query)}&size=5`;
    const response = await fetch(url, {
      headers: { "Authorization": `Basic ${auth}`, "Accept": "application/json" },
      signal: AbortSignal.timeout(15e3)
    });
    if (!response.ok) return { source: "dehashed", found: false, confidence: 0, details: `DeHashed API error: ${response.status}` };
    const data = await response.json();
    const totalEntries = data.total || 0;
    return {
      source: "dehashed",
      found: totalEntries > 0,
      confidence: totalEntries > 0 ? Math.min(75, 30 + totalEntries * 5) : 0,
      details: totalEntries > 0 ? `DeHashed: ${totalEntries} breach record(s) found for ${findingValue}` : `DeHashed: No breach records for ${findingValue}`,
      rawData: { total: totalEntries, balance: data.balance }
    };
  } catch (err) {
    return { source: "dehashed", found: false, confidence: 0, details: `DeHashed query failed: ${err.message}` };
  }
}
var SOURCE_QUERY_MAP = {
  shodan: queryShodan,
  censys: queryCensys,
  urlscan: queryUrlscan,
  nvd: queryNvd,
  securitytrails: querySecurityTrails,
  abuseipdb: queryAbuseIpdb,
  dehashed: queryDehashed
};
async function corroborateFromSources(params) {
  const sources = params.requestedSources || [...ALL_SOURCES];
  const sourceResults = [];
  const queryPromises = sources.map(async (source) => {
    const queryFn = SOURCE_QUERY_MAP[source];
    if (!queryFn) {
      return { source, found: false, confidence: 0, details: `Unknown source: ${source}` };
    }
    return queryFn(params.findingType, params.findingValue);
  });
  const results = await Promise.allSettled(queryPromises);
  for (const result of results) {
    if (result.status === "fulfilled") {
      sourceResults.push(result.value);
    } else {
      sourceResults.push({ source: "unknown", found: false, confidence: 0, details: `Query failed: ${result.reason}` });
    }
  }
  const corroboratingCount = sourceResults.filter((r) => r.found).length;
  const totalSourcesChecked = sourceResults.filter((r) => !r.details.includes("not configured") && !r.details.includes("skipped")).length;
  let overallConfidence = 0;
  let overallVerdict = "unverified";
  if (corroboratingCount > 0) {
    const confidenceSum = sourceResults.filter((r) => r.found).reduce((sum, r) => sum + r.confidence, 0);
    overallConfidence = Math.round(confidenceSum / corroboratingCount);
  }
  if (corroboratingCount >= 3 && overallConfidence >= 60) {
    overallVerdict = "confirmed";
    overallConfidence = Math.max(overallConfidence, 85);
  } else if (corroboratingCount >= 1 && overallConfidence >= 40) {
    overallVerdict = "suspicious";
  } else if (corroboratingCount === 0 && totalSourcesChecked >= 3) {
    overallVerdict = "false_positive";
    overallConfidence = Math.max(5, overallConfidence);
  } else {
    overallVerdict = "unverified";
    overallConfidence = Math.max(20, overallConfidence);
  }
  const db = await getDb();
  if (db) {
    try {
      await db.insert(corroborationResults).values({
        importId: 0,
        findingId: 0,
        originalConfidence: 50,
        adjustedConfidence: overallConfidence,
        corroboratingCount,
        contradictingCount: totalSourcesChecked - corroboratingCount,
        corroboratingSources: JSON.stringify(sourceResults.filter((r) => r.found).map((r) => r.source)),
        contradictingSources: JSON.stringify(sourceResults.filter((r) => !r.found).map((r) => r.source)),
        verdict: overallVerdict,
        reasoning: `Checked ${totalSourcesChecked} sources for ${params.findingType}:${params.findingValue}`
      });
    } catch (err) {
      console.error("[Corroboration] DB persist failed:", err);
    }
  }
  return {
    findingType: params.findingType,
    findingValue: params.findingValue,
    overallConfidence,
    overallVerdict,
    sourceResults,
    corroboratingCount,
    totalSourcesChecked
  };
}
function checkSourceAvailability(source) {
  const envMap = {
    shodan: "SHODAN_API_KEY",
    censys: "CENSYS_API_ID",
    urlscan: "URLSCAN_API_KEY",
    securitytrails: "SECURITYTRAILS_API_KEY",
    dehashed: "DEHASHED_API_KEY",
    abuseipdb: "ABUSECH_API_KEY",
    nvd: "NVD_API_KEY"
  };
  const envKey = envMap[source];
  if (source === "nvd") return true;
  return envKey ? !!process.env[envKey] : false;
}
function getAvailableSources() {
  return [
    { id: "nvd", name: "NVD (NIST)", configured: true, envVar: "NVD_API_KEY", description: "National Vulnerability Database \u2014 CVE lookup and CPE matching (no key required)" },
    { id: "shodan", name: "Shodan", configured: checkSourceAvailability("shodan"), envVar: "SHODAN_API_KEY", description: "Internet-wide scanning \u2014 open ports, services, banners" },
    { id: "censys", name: "Censys", configured: checkSourceAvailability("censys"), envVar: "CENSYS_API_ID", description: "Internet asset discovery \u2014 certificates, hosts, services" },
    { id: "urlscan", name: "URLScan.io", configured: checkSourceAvailability("urlscan"), envVar: "URLSCAN_API_KEY", description: "URL scanning \u2014 phishing, malware, suspicious sites" },
    { id: "abuseipdb", name: "AbuseIPDB", configured: checkSourceAvailability("abuseipdb"), envVar: "ABUSECH_API_KEY", description: "IP reputation \u2014 abuse reports, blacklists" },
    { id: "securitytrails", name: "SecurityTrails", configured: checkSourceAvailability("securitytrails"), envVar: "SECURITYTRAILS_API_KEY", description: "DNS history, WHOIS, and subdomain enumeration" },
    { id: "dehashed", name: "DeHashed", configured: checkSourceAvailability("dehashed"), envVar: "DEHASHED_API_KEY", description: "Credential breach database search" }
  ];
}
async function getCorroborationHistory(limit = 50) {
  const db = await getDb();
  if (!db) return [];
  try {
    const rows = await db.select().from(corroborationResults).orderBy(desc(corroborationResults.createdAt)).limit(limit);
    return rows;
  } catch (err) {
    console.error("[Corroboration] DB history query failed:", err);
    return [];
  }
}
export {
  corroborateFindings,
  corroborateFromSources,
  estimateFPReduction,
  getAvailableSources,
  getCorroborationHistory
};
