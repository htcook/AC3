/**
 * zero-day-feed.ts — Google Project Zero "0day In the Wild" feed connector
 *
 * Fetches and caches the full zero-day dataset from the public Google Sheets
 * spreadsheet maintained by Google TAG (formerly Project Zero).
 * Also integrates with the existing CISA KEV data for a unified zero-day view.
 */

import { parse } from "csv-parse/sync";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ZeroDayEntry {
  cve: string;
  vendor: string;
  product: string;
  type: string;
  description: string;
  dateDiscovered: string | null;
  datePatched: string | null;
  advisoryUrl: string | null;
  analysisUrl: string | null;
  rootCauseAnalysis: string | null;
  reportedBy: string | null;
  source: "project_zero" | "cisa_kev";
  year: number | null;
}

export interface ZeroDaySearchResult {
  entries: ZeroDayEntry[];
  totalCount: number;
  query: string;
  searchedAt: number;
}

export interface ZeroDayCrossRefMatch {
  zeroDayEntry: ZeroDayEntry;
  matchType: "cve_exact" | "vendor_product" | "product_fuzzy";
  matchedAsset: string;
  confidence: "high" | "medium" | "low";
  severity: "critical" | "high" | "medium";
}

export interface ZeroDayCrossRefResult {
  matches: ZeroDayCrossRefMatch[];
  totalChecked: number;
  zeroDaysChecked: number;
  checkedAt: number;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const P0_SPREADSHEET_ID = "1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY";
const P0_ALL_SHEET_URL = `https://docs.google.com/spreadsheets/d/${P0_SPREADSHEET_ID}/gviz/tq?tqx=out:csv&sheet=All`;

const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours
const FETCH_TIMEOUT_MS = 30_000;

// ─── In-Memory Cache ─────────────────────────────────────────────────────────

let _cache: ZeroDayEntry[] = [];
let _cacheTimestamp = 0;
let _fetchPromise: Promise<ZeroDayEntry[]> | null = null;

// ─── CSV Parsing ─────────────────────────────────────────────────────────────

function parseP0Csv(csvText: string): ZeroDayEntry[] {
  const entries: ZeroDayEntry[] = [];

  let records: string[][];
  try {
    records = parse(csvText, {
      relax_quotes: true,
      relax_column_count: true,
      skip_empty_lines: true,
    });
  } catch {
    // Fallback: manual line-by-line parsing for malformed CSV
    records = csvText
      .split("\n")
      .filter((l) => l.trim())
      .map((line) => {
        const fields: string[] = [];
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

  // Skip header row
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
      year,
    });
  }

  return entries;
}

function cleanField(val: string | undefined): string | null {
  if (!val) return null;
  const trimmed = val.trim().replace(/^"|"$/g, "");
  if (trimmed === "" || trimmed === "???") return null;
  return trimmed;
}

// ─── Fetch & Cache ───────────────────────────────────────────────────────────

async function fetchP0Feed(): Promise<ZeroDayEntry[]> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const resp = await fetch(P0_ALL_SHEET_URL, {
      signal: controller.signal,
      headers: { "User-Agent": "AceC3-ZeroDayFeed/1.0" },
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

/**
 * Get all zero-day entries, using cache when available.
 * Deduplicates concurrent fetches.
 */
export async function getZeroDayEntries(
  forceRefresh = false
): Promise<ZeroDayEntry[]> {
  const now = Date.now();

  if (!forceRefresh && _cache.length > 0 && now - _cacheTimestamp < CACHE_TTL_MS) {
    return _cache;
  }

  // Deduplicate concurrent fetches
  if (_fetchPromise) return _fetchPromise;

  _fetchPromise = fetchP0Feed()
    .then((entries) => {
      _cache = entries;
      _cacheTimestamp = Date.now();
      _fetchPromise = null;
      return entries;
    })
    .catch((err) => {
      _fetchPromise = null;
      console.error("[ZeroDayFeed] Fetch failed:", err);
      // Return stale cache if available
      if (_cache.length > 0) {
        console.log("[ZeroDayFeed] Returning stale cache");
        return _cache;
      }
      throw err;
    });

  return _fetchPromise;
}

// ─── Search ──────────────────────────────────────────────────────────────────

export interface ZeroDaySearchOptions {
  query?: string;
  cve?: string;
  vendor?: string;
  product?: string;
  type?: string;
  year?: number;
  limit?: number;
  offset?: number;
}

/**
 * Search zero-day entries with flexible filters.
 * Used by both the manual search tool and the pipeline cross-reference.
 */
export async function searchZeroDays(
  opts: ZeroDaySearchOptions
): Promise<ZeroDaySearchResult> {
  const entries = await getZeroDayEntries();
  let filtered = [...entries];

  // Exact CVE match
  if (opts.cve) {
    const cveUpper = opts.cve.toUpperCase().trim();
    filtered = filtered.filter((e) => e.cve.toUpperCase() === cveUpper);
  }

  // Vendor filter (case-insensitive partial match)
  if (opts.vendor) {
    const v = opts.vendor.toLowerCase();
    filtered = filtered.filter((e) => e.vendor.toLowerCase().includes(v));
  }

  // Product filter (case-insensitive partial match)
  if (opts.product) {
    const p = opts.product.toLowerCase();
    filtered = filtered.filter((e) => e.product.toLowerCase().includes(p));
  }

  // Type filter
  if (opts.type) {
    const t = opts.type.toLowerCase();
    filtered = filtered.filter((e) => e.type.toLowerCase().includes(t));
  }

  // Year filter
  if (opts.year) {
    filtered = filtered.filter((e) => e.year === opts.year);
  }

  // Free-text query (searches across CVE, vendor, product, description)
  if (opts.query) {
    const q = opts.query.toLowerCase();
    filtered = filtered.filter(
      (e) =>
        e.cve.toLowerCase().includes(q) ||
        e.vendor.toLowerCase().includes(q) ||
        e.product.toLowerCase().includes(q) ||
        e.description.toLowerCase().includes(q) ||
        (e.type && e.type.toLowerCase().includes(q)) ||
        (e.reportedBy && e.reportedBy.toLowerCase().includes(q))
    );
  }

  const totalCount = filtered.length;
  const offset = opts.offset || 0;
  const limit = opts.limit || 50;

  return {
    entries: filtered.slice(offset, offset + limit),
    totalCount,
    query: opts.query || opts.cve || opts.vendor || opts.product || "",
    searchedAt: Date.now(),
  };
}

// ─── Cross-Reference Engine ──────────────────────────────────────────────────

export interface AssetForCrossRef {
  /** The asset identifier — domain, IP, hostname, or software name */
  identifier: string;
  /** Known CVEs from scan findings */
  cves?: string[];
  /** Detected vendor names (from banners, headers, etc.) */
  vendors?: string[];
  /** Detected product names */
  products?: string[];
  /** Detected software versions */
  versions?: string[];
}

/**
 * Cross-reference a set of assets against the zero-day database.
 * Returns matches ranked by confidence.
 */
export async function crossReferenceAssets(
  assets: AssetForCrossRef[]
): Promise<ZeroDayCrossRefResult> {
  const entries = await getZeroDayEntries();
  const matches: ZeroDayCrossRefMatch[] = [];

  // Build lookup indices for fast matching
  const byCve = new Map<string, ZeroDayEntry[]>();
  const byVendorProduct = new Map<string, ZeroDayEntry[]>();
  const byProduct = new Map<string, ZeroDayEntry[]>();

  for (const entry of entries) {
    // CVE index
    const cveKey = entry.cve.toUpperCase();
    if (!byCve.has(cveKey)) byCve.set(cveKey, []);
    byCve.get(cveKey)!.push(entry);

    // Vendor+Product index
    if (entry.vendor && entry.product) {
      const vpKey = `${entry.vendor.toLowerCase()}|${entry.product.toLowerCase()}`;
      if (!byVendorProduct.has(vpKey)) byVendorProduct.set(vpKey, []);
      byVendorProduct.get(vpKey)!.push(entry);
    }

    // Product-only index
    if (entry.product) {
      const pKey = entry.product.toLowerCase();
      if (!byProduct.has(pKey)) byProduct.set(pKey, []);
      byProduct.get(pKey)!.push(entry);
    }
  }

  for (const asset of assets) {
    // 1. Exact CVE matches (highest confidence)
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
              severity: "critical",
            });
          }
        }
      }
    }

    // 2. Vendor + Product matches (medium confidence)
    if (asset.vendors && asset.products) {
      for (const vendor of asset.vendors) {
        for (const product of asset.products) {
          const vpKey = `${vendor.toLowerCase()}|${product.toLowerCase()}`;
          const zdEntries = byVendorProduct.get(vpKey);
          if (zdEntries) {
            for (const zd of zdEntries) {
              // Skip if already matched by CVE
              if (
                matches.some(
                  (m) =>
                    m.zeroDayEntry.cve === zd.cve &&
                    m.matchedAsset === asset.identifier &&
                    m.matchType === "cve_exact"
                )
              )
                continue;

              matches.push({
                zeroDayEntry: zd,
                matchType: "vendor_product",
                matchedAsset: asset.identifier,
                confidence: "medium",
                severity: isRecent(zd) ? "critical" : "high",
              });
            }
          }
        }
      }
    }

    // 3. Product-only fuzzy matches (lower confidence)
    if (asset.products) {
      for (const product of asset.products) {
        const pKey = product.toLowerCase();
        const zdEntries = byProduct.get(pKey);
        if (zdEntries) {
          for (const zd of zdEntries) {
            // Skip if already matched
            if (
              matches.some(
                (m) =>
                  m.zeroDayEntry.cve === zd.cve &&
                  m.matchedAsset === asset.identifier
              )
            )
              continue;

            matches.push({
              zeroDayEntry: zd,
              matchType: "product_fuzzy",
              matchedAsset: asset.identifier,
              confidence: "low",
              severity: isRecent(zd) ? "high" : "medium",
            });
          }
        }
      }
    }
  }

  // Sort: critical first, then by confidence, then by recency
  const confidenceOrder = { high: 0, medium: 1, low: 2 };
  const severityOrder = { critical: 0, high: 1, medium: 2 };
  matches.sort((a, b) => {
    const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
    if (sevDiff !== 0) return sevDiff;
    const confDiff =
      confidenceOrder[a.confidence] - confidenceOrder[b.confidence];
    if (confDiff !== 0) return confDiff;
    return (b.zeroDayEntry.year || 0) - (a.zeroDayEntry.year || 0);
  });

  return {
    matches,
    totalChecked: assets.length,
    zeroDaysChecked: entries.length,
    checkedAt: Date.now(),
  };
}

function isRecent(entry: ZeroDayEntry): boolean {
  const currentYear = new Date().getFullYear();
  return entry.year !== null && entry.year >= currentYear - 1;
}

// ─── Pipeline Integration Helper ─────────────────────────────────────────────

/**
 * Extract assets from DI scan observations for zero-day cross-referencing.
 * Called after scan completion to build the asset list.
 */
export function extractAssetsFromObservations(
  observations: Array<{
    assetType?: string;
    assetValue?: string;
    rawData?: string;
    source?: string;
  }>,
  domain: string
): AssetForCrossRef[] {
  const assetMap = new Map<string, AssetForCrossRef>();

  // Always include the target domain
  assetMap.set(domain, {
    identifier: domain,
    cves: [],
    vendors: [],
    products: [],
    versions: [],
  });

  for (const obs of observations) {
    const identifier = obs.assetValue || domain;
    if (!assetMap.has(identifier)) {
      assetMap.set(identifier, {
        identifier,
        cves: [],
        vendors: [],
        products: [],
        versions: [],
      });
    }

    const asset = assetMap.get(identifier)!;

    // Extract CVEs from raw data
    if (obs.rawData) {
      const cveMatches = obs.rawData.match(/CVE-\d{4}-\d{4,}/gi);
      if (cveMatches) {
        for (const cve of cveMatches) {
          if (!asset.cves!.includes(cve.toUpperCase())) {
            asset.cves!.push(cve.toUpperCase());
          }
        }
      }

      // Try to extract vendor/product from raw data
      try {
        const parsed = JSON.parse(obs.rawData);
        if (parsed.vendor && !asset.vendors!.includes(parsed.vendor)) {
          asset.vendors!.push(parsed.vendor);
        }
        if (parsed.product && !asset.products!.includes(parsed.product)) {
          asset.products!.push(parsed.product);
        }
        if (parsed.version && !asset.versions!.includes(parsed.version)) {
          asset.versions!.push(parsed.version);
        }
        // Also check nested technology/software fields
        if (parsed.technologies) {
          for (const tech of Array.isArray(parsed.technologies)
            ? parsed.technologies
            : [parsed.technologies]) {
            if (tech.name && !asset.products!.includes(tech.name)) {
              asset.products!.push(tech.name);
            }
            if (tech.vendor && !asset.vendors!.includes(tech.vendor)) {
              asset.vendors!.push(tech.vendor);
            }
          }
        }
        if (parsed.software) {
          for (const sw of Array.isArray(parsed.software)
            ? parsed.software
            : [parsed.software]) {
            if (typeof sw === "string" && !asset.products!.includes(sw)) {
              asset.products!.push(sw);
            } else if (sw?.name && !asset.products!.includes(sw.name)) {
              asset.products!.push(sw.name);
            }
          }
        }
      } catch {
        // Not JSON — try banner-style extraction
        extractFromBanner(obs.rawData, asset);
      }
    }

    // Extract from source connector name
    if (obs.source) {
      const sourceProducts = extractProductsFromSource(obs.source);
      for (const p of sourceProducts) {
        if (!asset.products!.includes(p)) asset.products!.push(p);
      }
    }
  }

  return Array.from(assetMap.values());
}

function extractFromBanner(banner: string, asset: AssetForCrossRef): void {
  // Common server banner patterns
  const patterns = [
    /Apache\/[\d.]+/i,
    /nginx\/[\d.]+/i,
    /Microsoft-IIS\/[\d.]+/i,
    /OpenSSH[_\/][\d.]+/i,
    /PHP\/[\d.]+/i,
    /WordPress\/[\d.]+/i,
    /jQuery\/[\d.]+/i,
  ];

  for (const pattern of patterns) {
    const match = banner.match(pattern);
    if (match) {
      const parts = match[0].split(/[\/_ ]/);
      const product = parts[0];
      if (product && !asset.products!.includes(product)) {
        asset.products!.push(product);
      }
    }
  }
}

function extractProductsFromSource(source: string): string[] {
  // Map connector names to product categories they might detect
  const sourceMap: Record<string, string[]> = {
    shodan: [],
    censys: [],
    wappalyzer: [],
    builtwith: [],
    github_repos: [],
    cloud_assets: [],
    ssl_certs: [],
  };
  return sourceMap[source.toLowerCase()] || [];
}

// ─── Feed Statistics ─────────────────────────────────────────────────────────

export interface ZeroDayFeedStats {
  totalEntries: number;
  byYear: Record<number, number>;
  byVendor: Record<string, number>;
  byType: Record<string, number>;
  lastFetched: number;
  cacheAge: number;
  recentZeroDays: ZeroDayEntry[]; // last 30 days
}

export async function getZeroDayFeedStats(): Promise<ZeroDayFeedStats> {
  const entries = await getZeroDayEntries();
  const now = Date.now();

  const byYear: Record<number, number> = {};
  const byVendor: Record<string, number> = {};
  const byType: Record<string, number> = {};

  const currentYear = new Date().getFullYear();
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
  const recentZeroDays: ZeroDayEntry[] = [];

  for (const entry of entries) {
    // By year
    if (entry.year) {
      byYear[entry.year] = (byYear[entry.year] || 0) + 1;
    }

    // By vendor
    if (entry.vendor) {
      byVendor[entry.vendor] = (byVendor[entry.vendor] || 0) + 1;
    }

    // By type
    if (entry.type) {
      byType[entry.type] = (byType[entry.type] || 0) + 1;
    }

    // Recent (current year entries as proxy since dateDiscovered is often "???")
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
    recentZeroDays: recentZeroDays.slice(0, 20),
  };
}

// ─── Exports for testing ─────────────────────────────────────────────────────

export const _testing = {
  parseP0Csv,
  cleanField,
  extractFromBanner,
  isRecent,
  resetCache: () => {
    _cache = [];
    _cacheTimestamp = 0;
    _fetchPromise = null;
  },
  setCache: (entries: ZeroDayEntry[]) => {
    _cache = entries;
    _cacheTimestamp = Date.now();
  },
};
