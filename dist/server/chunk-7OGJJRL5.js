// server/lib/zero-day-feed.ts
import { parse } from "csv-parse/sync";
var P0_SPREADSHEET_ID = "1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY";
var P0_ALL_SHEET_URL = `https://docs.google.com/spreadsheets/d/${P0_SPREADSHEET_ID}/gviz/tq?tqx=out:csv&sheet=All`;
var CACHE_TTL_MS = 6 * 60 * 60 * 1e3;
var FETCH_TIMEOUT_MS = 3e4;
var _cache = [];
var _cacheTimestamp = 0;
var _fetchPromise = null;
function parseP0Csv(csvText) {
  const entries = [];
  let records;
  try {
    records = parse(csvText, {
      relax_quotes: true,
      relax_column_count: true,
      skip_empty_lines: true
    });
  } catch {
    records = csvText.split("\n").filter((l) => l.trim()).map((line) => {
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
          fields.push(current.trim());
          current = "";
        } else {
          current += ch;
        }
      }
      fields.push(current.trim());
      return fields;
    });
  }
  for (let i = 1; i < records.length; i++) {
    const row = records[i];
    if (!row || row.length < 4) continue;
    const cve = (row[0] || "").trim();
    if (!cve || !cve.startsWith("CVE-")) continue;
    const datePatched = cleanField(row[6]);
    const yearMatch = cve.match(/CVE-(\d{4})/);
    const year = yearMatch ? parseInt(yearMatch[1], 10) : null;
    entries.push({
      cve,
      vendor: cleanField(row[1]) || "",
      product: cleanField(row[2]) || "",
      type: cleanField(row[3]) || "",
      description: cleanField(row[4]) || "",
      dateDiscovered: cleanField(row[5]),
      datePatched,
      advisoryUrl: cleanField(row[7]),
      analysisUrl: cleanField(row[8]),
      rootCauseAnalysis: cleanField(row[9]),
      reportedBy: cleanField(row[10]),
      source: "project_zero",
      year
    });
  }
  return entries;
}
function cleanField(val) {
  if (!val) return null;
  const trimmed = val.trim().replace(/^"|"$/g, "");
  if (trimmed === "" || trimmed === "???") return null;
  return trimmed;
}
async function fetchP0Feed() {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const resp = await fetch(P0_ALL_SHEET_URL, {
      signal: controller.signal,
      headers: { "User-Agent": "AceC3-ZeroDayFeed/1.0" }
    });
    if (!resp.ok) {
      throw new Error(`P0 feed HTTP ${resp.status}: ${resp.statusText}`);
    }
    const csvText = await resp.text();
    const entries = parseP0Csv(csvText);
    console.log(
      `[ZeroDayFeed] Fetched ${entries.length} entries from Project Zero`
    );
    return entries;
  } finally {
    clearTimeout(timeout);
  }
}
async function getZeroDayEntries(forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh && _cache.length > 0 && now - _cacheTimestamp < CACHE_TTL_MS) {
    return _cache;
  }
  if (_fetchPromise) return _fetchPromise;
  _fetchPromise = fetchP0Feed().then((entries) => {
    _cache = entries;
    _cacheTimestamp = Date.now();
    _fetchPromise = null;
    return entries;
  }).catch((err) => {
    _fetchPromise = null;
    console.error("[ZeroDayFeed] Fetch failed:", err);
    if (_cache.length > 0) {
      console.log("[ZeroDayFeed] Returning stale cache");
      return _cache;
    }
    throw err;
  });
  return _fetchPromise;
}
async function searchZeroDays(opts) {
  const entries = await getZeroDayEntries();
  let filtered = [...entries];
  if (opts.cve) {
    const cveUpper = opts.cve.toUpperCase().trim();
    filtered = filtered.filter((e) => e.cve.toUpperCase() === cveUpper);
  }
  if (opts.vendor) {
    const v = opts.vendor.toLowerCase();
    filtered = filtered.filter((e) => e.vendor.toLowerCase().includes(v));
  }
  if (opts.product) {
    const p = opts.product.toLowerCase();
    filtered = filtered.filter((e) => e.product.toLowerCase().includes(p));
  }
  if (opts.type) {
    const t = opts.type.toLowerCase();
    filtered = filtered.filter((e) => e.type.toLowerCase().includes(t));
  }
  if (opts.year) {
    filtered = filtered.filter((e) => e.year === opts.year);
  }
  if (opts.query) {
    const q = opts.query.toLowerCase();
    filtered = filtered.filter(
      (e) => e.cve.toLowerCase().includes(q) || e.vendor.toLowerCase().includes(q) || e.product.toLowerCase().includes(q) || e.description.toLowerCase().includes(q) || e.type && e.type.toLowerCase().includes(q) || e.reportedBy && e.reportedBy.toLowerCase().includes(q)
    );
  }
  const totalCount = filtered.length;
  const offset = opts.offset || 0;
  const limit = opts.limit || 50;
  return {
    entries: filtered.slice(offset, offset + limit),
    totalCount,
    query: opts.query || opts.cve || opts.vendor || opts.product || "",
    searchedAt: Date.now()
  };
}
async function crossReferenceAssets(assets) {
  const entries = await getZeroDayEntries();
  const matches = [];
  const byCve = /* @__PURE__ */ new Map();
  const byVendorProduct = /* @__PURE__ */ new Map();
  const byProduct = /* @__PURE__ */ new Map();
  for (const entry of entries) {
    const cveKey = entry.cve.toUpperCase();
    if (!byCve.has(cveKey)) byCve.set(cveKey, []);
    byCve.get(cveKey).push(entry);
    if (entry.vendor && entry.product) {
      const vpKey = `${entry.vendor.toLowerCase()}|${entry.product.toLowerCase()}`;
      if (!byVendorProduct.has(vpKey)) byVendorProduct.set(vpKey, []);
      byVendorProduct.get(vpKey).push(entry);
    }
    if (entry.product) {
      const pKey = entry.product.toLowerCase();
      if (!byProduct.has(pKey)) byProduct.set(pKey, []);
      byProduct.get(pKey).push(entry);
    }
  }
  for (const asset of assets) {
    if (asset.cves) {
      for (const cve of asset.cves) {
        const zdEntries = byCve.get(cve.toUpperCase());
        if (zdEntries) {
          for (const zd of zdEntries) {
            matches.push({
              zeroDayEntry: zd,
              matchType: "cve_exact",
              matchedAsset: asset.identifier,
              confidence: "high",
              severity: "critical"
            });
          }
        }
      }
    }
    if (asset.vendors && asset.products) {
      for (const vendor of asset.vendors) {
        for (const product of asset.products) {
          const vpKey = `${vendor.toLowerCase()}|${product.toLowerCase()}`;
          const zdEntries = byVendorProduct.get(vpKey);
          if (zdEntries) {
            for (const zd of zdEntries) {
              if (matches.some(
                (m) => m.zeroDayEntry.cve === zd.cve && m.matchedAsset === asset.identifier && m.matchType === "cve_exact"
              ))
                continue;
              matches.push({
                zeroDayEntry: zd,
                matchType: "vendor_product",
                matchedAsset: asset.identifier,
                confidence: "medium",
                severity: isRecent(zd) ? "critical" : "high"
              });
            }
          }
        }
      }
    }
    if (asset.products) {
      for (const product of asset.products) {
        const pKey = product.toLowerCase();
        const zdEntries = byProduct.get(pKey);
        if (zdEntries) {
          for (const zd of zdEntries) {
            if (matches.some(
              (m) => m.zeroDayEntry.cve === zd.cve && m.matchedAsset === asset.identifier
            ))
              continue;
            matches.push({
              zeroDayEntry: zd,
              matchType: "product_fuzzy",
              matchedAsset: asset.identifier,
              confidence: "low",
              severity: isRecent(zd) ? "high" : "medium"
            });
          }
        }
      }
    }
  }
  const confidenceOrder = { high: 0, medium: 1, low: 2 };
  const severityOrder = { critical: 0, high: 1, medium: 2 };
  matches.sort((a, b) => {
    const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
    if (sevDiff !== 0) return sevDiff;
    const confDiff = confidenceOrder[a.confidence] - confidenceOrder[b.confidence];
    if (confDiff !== 0) return confDiff;
    return (b.zeroDayEntry.year || 0) - (a.zeroDayEntry.year || 0);
  });
  return {
    matches,
    totalChecked: assets.length,
    zeroDaysChecked: entries.length,
    checkedAt: Date.now()
  };
}
function isRecent(entry) {
  const currentYear = (/* @__PURE__ */ new Date()).getFullYear();
  return entry.year !== null && entry.year >= currentYear - 1;
}
function extractAssetsFromObservations(observations, domain) {
  const assetMap = /* @__PURE__ */ new Map();
  assetMap.set(domain, {
    identifier: domain,
    cves: [],
    vendors: [],
    products: [],
    versions: []
  });
  for (const obs of observations) {
    const identifier = obs.assetValue || domain;
    if (!assetMap.has(identifier)) {
      assetMap.set(identifier, {
        identifier,
        cves: [],
        vendors: [],
        products: [],
        versions: []
      });
    }
    const asset = assetMap.get(identifier);
    if (obs.rawData) {
      const cveMatches = obs.rawData.match(/CVE-\d{4}-\d{4,}/gi);
      if (cveMatches) {
        for (const cve of cveMatches) {
          if (!asset.cves.includes(cve.toUpperCase())) {
            asset.cves.push(cve.toUpperCase());
          }
        }
      }
      try {
        const parsed = JSON.parse(obs.rawData);
        if (parsed.vendor && !asset.vendors.includes(parsed.vendor)) {
          asset.vendors.push(parsed.vendor);
        }
        if (parsed.product && !asset.products.includes(parsed.product)) {
          asset.products.push(parsed.product);
        }
        if (parsed.version && !asset.versions.includes(parsed.version)) {
          asset.versions.push(parsed.version);
        }
        if (parsed.technologies) {
          for (const tech of Array.isArray(parsed.technologies) ? parsed.technologies : [parsed.technologies]) {
            if (tech.name && !asset.products.includes(tech.name)) {
              asset.products.push(tech.name);
            }
            if (tech.vendor && !asset.vendors.includes(tech.vendor)) {
              asset.vendors.push(tech.vendor);
            }
          }
        }
        if (parsed.software) {
          for (const sw of Array.isArray(parsed.software) ? parsed.software : [parsed.software]) {
            if (typeof sw === "string" && !asset.products.includes(sw)) {
              asset.products.push(sw);
            } else if (sw?.name && !asset.products.includes(sw.name)) {
              asset.products.push(sw.name);
            }
          }
        }
      } catch {
        extractFromBanner(obs.rawData, asset);
      }
    }
    if (obs.source) {
      const sourceProducts = extractProductsFromSource(obs.source);
      for (const p of sourceProducts) {
        if (!asset.products.includes(p)) asset.products.push(p);
      }
    }
  }
  return Array.from(assetMap.values());
}
function extractFromBanner(banner, asset) {
  const patterns = [
    /Apache\/[\d.]+/i,
    /nginx\/[\d.]+/i,
    /Microsoft-IIS\/[\d.]+/i,
    /OpenSSH[_\/][\d.]+/i,
    /PHP\/[\d.]+/i,
    /WordPress\/[\d.]+/i,
    /jQuery\/[\d.]+/i
  ];
  for (const pattern of patterns) {
    const match = banner.match(pattern);
    if (match) {
      const parts = match[0].split(/[\/_ ]/);
      const product = parts[0];
      if (product && !asset.products.includes(product)) {
        asset.products.push(product);
      }
    }
  }
}
function extractProductsFromSource(source) {
  const sourceMap = {
    shodan: [],
    censys: [],
    wappalyzer: [],
    builtwith: [],
    github_repos: [],
    cloud_assets: [],
    ssl_certs: []
  };
  return sourceMap[source.toLowerCase()] || [];
}
async function getZeroDayFeedStats() {
  const entries = await getZeroDayEntries();
  const now = Date.now();
  const byYear = {};
  const byVendor = {};
  const byType = {};
  const currentYear = (/* @__PURE__ */ new Date()).getFullYear();
  const thirtyDaysAgo = /* @__PURE__ */ new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
  const recentZeroDays = [];
  for (const entry of entries) {
    if (entry.year) {
      byYear[entry.year] = (byYear[entry.year] || 0) + 1;
    }
    if (entry.vendor) {
      byVendor[entry.vendor] = (byVendor[entry.vendor] || 0) + 1;
    }
    if (entry.type) {
      byType[entry.type] = (byType[entry.type] || 0) + 1;
    }
    if (entry.year === currentYear) {
      recentZeroDays.push(entry);
    }
  }
  return {
    totalEntries: entries.length,
    byYear,
    byVendor,
    byType,
    lastFetched: _cacheTimestamp,
    cacheAge: now - _cacheTimestamp,
    recentZeroDays: recentZeroDays.slice(0, 20)
  };
}
var _testing = {
  parseP0Csv,
  cleanField,
  extractFromBanner,
  isRecent,
  resetCache: () => {
    _cache = [];
    _cacheTimestamp = 0;
    _fetchPromise = null;
  },
  setCache: (entries) => {
    _cache = entries;
    _cacheTimestamp = Date.now();
  }
};

export {
  getZeroDayEntries,
  searchZeroDays,
  crossReferenceAssets,
  extractAssetsFromObservations,
  getZeroDayFeedStats,
  _testing
};
