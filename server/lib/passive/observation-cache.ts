/**
 * Observation Cache — Per-Connector TTL Cache
 *
 * Caches connector results to avoid redundant API calls on re-scans.
 * Each connector has its own TTL based on data volatility:
 *
 * - Fast-changing data (Shodan, Censys): 6 hours
 * - Moderate data (DNS, certs, email security): 24 hours
 * - Slow-changing data (WHOIS, RDAP, crt.sh): 72 hours
 * - Static data (Wayback, GitHub leaks): 168 hours (1 week)
 *
 * Features:
 * - Per-connector TTL configuration
 * - Force-refresh flag to bypass cache
 * - LRU eviction when cache exceeds maxEntries
 * - Cache hit/miss statistics for telemetry
 * - Domain-scoped keys to prevent cross-target leakage
 */

import type { ConnectorResult } from "./types";

// ─── TTL Configuration ─────────────────────────────────────────────

/** TTL in milliseconds per connector category */
export const CONNECTOR_TTL: Record<string, number> = {
  // Fast-changing: 6 hours
  "shodan": 6 * 60 * 60 * 1000,
  "shodan-internetdb": 6 * 60 * 60 * 1000,
  "censys": 6 * 60 * 60 * 1000,
  "binaryedge": 6 * 60 * 60 * 1000,
  "greynoise": 6 * 60 * 60 * 1000,
  "abuseipdb": 6 * 60 * 60 * 1000,
  "urlscan": 6 * 60 * 60 * 1000,

  // Moderate: 24 hours
  "dns-deep": 24 * 60 * 60 * 1000,
  "http-security": 24 * 60 * 60 * 1000,
  "email-security": 24 * 60 * 60 * 1000,
  "cloud-assets": 24 * 60 * 60 * 1000,
  "social-media": 24 * 60 * 60 * 1000,
  "hunter": 24 * 60 * 60 * 1000,

  // Slow-changing: 72 hours
  "crtsh": 72 * 60 * 60 * 1000,
  "rdap": 72 * 60 * 60 * 1000,
  "ripestat": 72 * 60 * 60 * 1000,
  "securitytrails": 72 * 60 * 60 * 1000,
  "dehashed": 72 * 60 * 60 * 1000,

  // Static: 1 week
  "wayback": 168 * 60 * 60 * 1000,
  "github_leaks": 168 * 60 * 60 * 1000,
  "github_recon": 168 * 60 * 60 * 1000,
};

/** Default TTL for unknown connectors: 12 hours */
const DEFAULT_TTL = 12 * 60 * 60 * 1000;

// ─── Cache Entry ───────────────────────────────────────────────────

interface CacheEntry {
  key: string;
  connector: string;
  domain: string;
  result: ConnectorResult;
  cachedAt: number;
  ttl: number;
  accessedAt: number;
  hitCount: number;
}

// ─── Cache Statistics ──────────────────────────────────────────────

export interface CacheStats {
  totalEntries: number;
  hits: number;
  misses: number;
  evictions: number;
  hitRate: number;
  byConnector: Record<string, { hits: number; misses: number }>;
  memorySizeEstimate: number;
}

// ─── Observation Cache ─────────────────────────────────────────────

export class ObservationCache {
  private cache = new Map<string, CacheEntry>();
  private maxEntries: number;
  private stats = {
    hits: 0,
    misses: 0,
    evictions: 0,
    byConnector: {} as Record<string, { hits: number; misses: number }>,
  };

  constructor(maxEntries = 5000) {
    this.maxEntries = maxEntries;
  }

  /** Generate a cache key scoped to domain + connector */
  private makeKey(domain: string, connector: string): string {
    return `${domain.toLowerCase()}::${connector}`;
  }

  /** Get connector-specific TTL */
  private getTTL(connector: string): number {
    return CONNECTOR_TTL[connector] || DEFAULT_TTL;
  }

  /** Track per-connector stats */
  private trackStat(connector: string, hit: boolean): void {
    if (!this.stats.byConnector[connector]) {
      this.stats.byConnector[connector] = { hits: 0, misses: 0 };
    }
    if (hit) {
      this.stats.hits++;
      this.stats.byConnector[connector].hits++;
    } else {
      this.stats.misses++;
      this.stats.byConnector[connector].misses++;
    }
  }

  /**
   * Get cached result for a connector + domain pair.
   * Returns null if not cached, expired, or forceRefresh is true.
   */
  get(domain: string, connector: string, forceRefresh = false): ConnectorResult | null {
    if (forceRefresh) {
      this.trackStat(connector, false);
      return null;
    }

    const key = this.makeKey(domain, connector);
    const entry = this.cache.get(key);

    if (!entry) {
      this.trackStat(connector, false);
      return null;
    }

    // Check TTL expiry
    const now = Date.now();
    if (now - entry.cachedAt > entry.ttl) {
      this.cache.delete(key);
      this.trackStat(connector, false);
      return null;
    }

    // Cache hit — update access metadata
    entry.accessedAt = now;
    entry.hitCount++;
    this.trackStat(connector, true);
    return entry.result;
  }

  /**
   * Store a connector result in the cache.
   * Evicts LRU entries if cache is full.
   */
  set(domain: string, connector: string, result: ConnectorResult): void {
    const key = this.makeKey(domain, connector);
    const now = Date.now();

    // Evict if at capacity
    if (this.cache.size >= this.maxEntries && !this.cache.has(key)) {
      this.evictLRU();
    }

    this.cache.set(key, {
      key,
      connector,
      domain: domain.toLowerCase(),
      result,
      cachedAt: now,
      ttl: this.getTTL(connector),
      accessedAt: now,
      hitCount: 0,
    });
  }

  /** Evict the least recently used entry */
  private evictLRU(): void {
    let oldestKey: string | null = null;
    let oldestAccess = Infinity;

    for (const [key, entry] of this.cache) {
      if (entry.accessedAt < oldestAccess) {
        oldestAccess = entry.accessedAt;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.cache.delete(oldestKey);
      this.stats.evictions++;
    }
  }

  /** Invalidate all cache entries for a specific domain */
  invalidateDomain(domain: string): number {
    const prefix = `${domain.toLowerCase()}::`;
    let count = 0;
    for (const key of Array.from(this.cache.keys())) {
      if (key.startsWith(prefix)) {
        this.cache.delete(key);
        count++;
      }
    }
    return count;
  }

  /** Invalidate all cache entries for a specific connector */
  invalidateConnector(connector: string): number {
    const suffix = `::${connector}`;
    let count = 0;
    for (const key of Array.from(this.cache.keys())) {
      if (key.endsWith(suffix)) {
        this.cache.delete(key);
        count++;
      }
    }
    return count;
  }

  /** Clear the entire cache */
  clear(): void {
    this.cache.clear();
    this.stats = {
      hits: 0,
      misses: 0,
      evictions: 0,
      byConnector: {},
    };
  }

  /** Get cache statistics */
  getStats(): CacheStats {
    const total = this.stats.hits + this.stats.misses;
    let memorySizeEstimate = 0;
    for (const entry of this.cache.values()) {
      // Rough estimate: key + JSON size of result
      memorySizeEstimate += entry.key.length * 2 + JSON.stringify(entry.result).length * 2;
    }

    return {
      totalEntries: this.cache.size,
      hits: this.stats.hits,
      misses: this.stats.misses,
      evictions: this.stats.evictions,
      hitRate: total > 0 ? Math.round((this.stats.hits / total) * 100) / 100 : 0,
      byConnector: { ...this.stats.byConnector },
      memorySizeEstimate,
    };
  }

  /** Get all cached domains */
  getCachedDomains(): string[] {
    const domains = new Set<string>();
    for (const entry of this.cache.values()) {
      domains.add(entry.domain);
    }
    return Array.from(domains);
  }

  /** Check if a domain has any cached results */
  hasCachedResults(domain: string): boolean {
    const prefix = `${domain.toLowerCase()}::`;
    for (const key of this.cache.keys()) {
      if (key.startsWith(prefix)) return true;
    }
    return false;
  }
}

// ─── Singleton Instance ────────────────────────────────────────────

/** Global observation cache instance shared across all scans */
export const observationCache = new ObservationCache();
