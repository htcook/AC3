/**
 * Fingerprint Result Cache
 *
 * Persists service fingerprint results to the DB so repeat engagements
 * skip already-fingerprinted ports. Entries have a configurable TTL
 * (default 24 hours) and are keyed by (host, port).
 *
 * Usage:
 *   1. Before fingerprinting, call getCachedFingerprints(host, ports) to
 *      get any cached results and the list of ports that still need probing.
 *   2. After fingerprinting, call cacheFingerprints(host, results, engagementId)
 *      to persist the new results.
 *   3. Periodically call purgeExpiredCache() to clean up stale entries.
 */

import { getDb } from "../db";
import { fingerprintCache } from "../../drizzle/schema";
import { eq, and, inArray, gt } from "drizzle-orm";
import type { FingerprintResult } from "./service-fingerprinter";

// ─── Configuration ──────────────────────────────────────────────────────────

/** Default cache TTL: 24 hours in milliseconds */
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

/** Maximum cache TTL: 7 days */
const MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/** Minimum cache TTL: 1 hour */
const MIN_TTL_MS = 60 * 60 * 1000;

// ─── Types ──────────────────────────────────────────────────────────────────

export interface CacheLookupResult {
  /** Fingerprint results found in cache (still valid) */
  cached: FingerprintResult[];
  /** Port numbers that were NOT found in cache and need fresh probing */
  uncachedPorts: number[];
  /** Number of cache hits */
  hitCount: number;
  /** Number of cache misses */
  missCount: number;
  /** Whether the cache was used at all */
  cacheUsed: boolean;
}

export interface CacheStats {
  totalEntries: number;
  expiredEntries: number;
  uniqueHosts: number;
}

// ─── Cache Functions ────────────────────────────────────────────────────────

/**
 * Look up cached fingerprint results for a host and set of ports.
 * Returns cached results and the list of ports that still need probing.
 */
export async function getCachedFingerprints(
  host: string,
  ports: number[],
  options?: { ttlMs?: number },
): Promise<CacheLookupResult> {
  const ttlMs = Math.min(MAX_TTL_MS, Math.max(MIN_TTL_MS, options?.ttlMs || DEFAULT_TTL_MS));
  const now = Date.now();

  try {
    const db = await getDb();
    if (!db) {
      return {
        cached: [],
        uncachedPorts: ports,
        hitCount: 0,
        missCount: ports.length,
        cacheUsed: false,
      };
    }

    // Query for valid (non-expired) cached entries for this host+ports
    const rows = await db
      .select()
      .from(fingerprintCache)
      .where(
        and(
          eq(fingerprintCache.fcHost, host),
          inArray(fingerprintCache.fcPort, ports),
          gt(fingerprintCache.fcExpiresAt, now),
        ),
      );

    const cachedPorts = new Set(rows.map(r => r.fcPort));
    const uncachedPorts = ports.filter(p => !cachedPorts.has(p));

    // Convert DB rows back to FingerprintResult shape
    const cached: FingerprintResult[] = rows.map(row => ({
      port: row.fcPort,
      protocol: (row.fcProtocol || "unknown") as any,
      product: row.fcProduct || null,
      version: row.fcVersion || null,
      banner: row.fcBanner || null,
      os: row.fcOs || null,
      securityFlags: (row.fcSecurityFlags as any) || {},
      riskIndicators: (row.fcRiskIndicators as any) || [],
      potentialCves: (row.fcPotentialCves as any) || [],
      error: row.fcError === 1 ? "cached-error" : undefined,
      confidence: row.fcConfidence || 0,
      durationMs: 0, // Cached — no probe time
      _cached: true, // Mark as from cache
    })) as any;

    return {
      cached,
      uncachedPorts,
      hitCount: rows.length,
      missCount: uncachedPorts.length,
      cacheUsed: true,
    };
  } catch (err: any) {
    console.error("[FingerprintCache] Lookup error:", err.message);
    return {
      cached: [],
      uncachedPorts: ports,
      hitCount: 0,
      missCount: ports.length,
      cacheUsed: false,
    };
  }
}

/**
 * Cache fingerprint results for a host. Upserts by (host, port).
 */
export async function cacheFingerprints(
  host: string,
  results: FingerprintResult[],
  engagementId?: string,
  options?: { ttlMs?: number },
): Promise<{ cached: number; errors: number }> {
  const ttlMs = Math.min(MAX_TTL_MS, Math.max(MIN_TTL_MS, options?.ttlMs || DEFAULT_TTL_MS));
  const now = Date.now();
  const expiresAt = now + ttlMs;
  let cached = 0;
  let errors = 0;

  try {
    const db = await getDb();
    if (!db) return { cached: 0, errors: results.length };

    for (const fp of results) {
      try {
        // Delete existing entry for this host+port (upsert)
        await db
          .delete(fingerprintCache)
          .where(
            and(
              eq(fingerprintCache.fcHost, host),
              eq(fingerprintCache.fcPort, fp.port),
            ),
          );

        // Insert new entry
        await db.insert(fingerprintCache).values({
          fcHost: host,
          fcPort: fp.port,
          fcProtocol: fp.protocol || null,
          fcProduct: fp.product || null,
          fcVersion: fp.version || null,
          fcBanner: fp.banner || null,
          fcOs: fp.os || null,
          fcSecurityFlags: fp.securityFlags || null,
          fcRiskIndicators: fp.riskIndicators || null,
          fcPotentialCves: fp.potentialCves || null,
          fcError: fp.error ? 1 : 0,
          fcConfidence: (fp as any).confidence || 0,
          fcFingerprintedAt: now,
          fcExpiresAt: expiresAt,
          fcEngagementId: engagementId || null,
        });

        cached++;
      } catch (rowErr: any) {
        errors++;
        console.error(`[FingerprintCache] Error caching ${host}:${fp.port}:`, rowErr.message);
      }
    }

    return { cached, errors };
  } catch (err: any) {
    console.error("[FingerprintCache] Cache write error:", err.message);
    return { cached: 0, errors: results.length };
  }
}

/**
 * Purge expired cache entries. Call periodically to keep the table clean.
 */
export async function purgeExpiredCache(): Promise<number> {
  try {
    const db = await getDb();
    if (!db) return 0;

    const now = Date.now();
    const result = await db
      .delete(fingerprintCache)
      .where(gt(now, fingerprintCache.fcExpiresAt));

    // Drizzle delete doesn't return affected rows count easily,
    // but we can log the operation
    console.log("[FingerprintCache] Purged expired entries");
    return 0; // Approximate — drizzle doesn't expose affected rows
  } catch (err: any) {
    console.error("[FingerprintCache] Purge error:", err.message);
    return 0;
  }
}

/**
 * Invalidate all cache entries for a specific host (e.g., when re-scanning).
 */
export async function invalidateHostCache(host: string): Promise<void> {
  try {
    const db = await getDb();
    if (!db) return;

    await db
      .delete(fingerprintCache)
      .where(eq(fingerprintCache.fcHost, host));

    console.log(`[FingerprintCache] Invalidated cache for ${host}`);
  } catch (err: any) {
    console.error("[FingerprintCache] Invalidation error:", err.message);
  }
}
