import {
  getDb,
  init_db
} from "./chunk-RSFTEATL.js";
import "./chunk-KDOLKO2A.js";
import {
  fingerprintCache,
  init_schema
} from "./chunk-L4JENJ4Z.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/fingerprint-cache.ts
import { eq, and, inArray, gt } from "drizzle-orm";
async function getCachedFingerprints(host, ports, options) {
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
        cacheUsed: false
      };
    }
    const rows = await db.select().from(fingerprintCache).where(
      and(
        eq(fingerprintCache.fcHost, host),
        inArray(fingerprintCache.fcPort, ports),
        gt(fingerprintCache.fcExpiresAt, now)
      )
    );
    const cachedPorts = new Set(rows.map((r) => r.fcPort));
    const uncachedPorts = ports.filter((p) => !cachedPorts.has(p));
    const cached = rows.map((row) => ({
      port: row.fcPort,
      protocol: row.fcProtocol || "unknown",
      product: row.fcProduct || null,
      version: row.fcVersion || null,
      banner: row.fcBanner || null,
      os: row.fcOs || null,
      securityFlags: row.fcSecurityFlags || {},
      riskIndicators: row.fcRiskIndicators || [],
      potentialCves: row.fcPotentialCves || [],
      error: row.fcError === 1 ? "cached-error" : void 0,
      confidence: row.fcConfidence || 0,
      durationMs: 0,
      // Cached — no probe time
      _cached: true
      // Mark as from cache
    }));
    return {
      cached,
      uncachedPorts,
      hitCount: rows.length,
      missCount: uncachedPorts.length,
      cacheUsed: true
    };
  } catch (err) {
    console.error("[FingerprintCache] Lookup error:", err.message);
    return {
      cached: [],
      uncachedPorts: ports,
      hitCount: 0,
      missCount: ports.length,
      cacheUsed: false
    };
  }
}
async function cacheFingerprints(host, results, engagementId, options) {
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
        await db.delete(fingerprintCache).where(
          and(
            eq(fingerprintCache.fcHost, host),
            eq(fingerprintCache.fcPort, fp.port)
          )
        );
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
          fcConfidence: fp.confidence || 0,
          fcFingerprintedAt: now,
          fcExpiresAt: expiresAt,
          fcEngagementId: engagementId || null
        });
        cached++;
      } catch (rowErr) {
        errors++;
        console.error(`[FingerprintCache] Error caching ${host}:${fp.port}:`, rowErr.message);
      }
    }
    return { cached, errors };
  } catch (err) {
    console.error("[FingerprintCache] Cache write error:", err.message);
    return { cached: 0, errors: results.length };
  }
}
async function purgeExpiredCache() {
  try {
    const db = await getDb();
    if (!db) return 0;
    const now = Date.now();
    const result = await db.delete(fingerprintCache).where(gt(now, fingerprintCache.fcExpiresAt));
    console.log("[FingerprintCache] Purged expired entries");
    return 0;
  } catch (err) {
    console.error("[FingerprintCache] Purge error:", err.message);
    return 0;
  }
}
async function invalidateHostCache(host) {
  try {
    const db = await getDb();
    if (!db) return;
    await db.delete(fingerprintCache).where(eq(fingerprintCache.fcHost, host));
    console.log(`[FingerprintCache] Invalidated cache for ${host}`);
  } catch (err) {
    console.error("[FingerprintCache] Invalidation error:", err.message);
  }
}
var DEFAULT_TTL_MS, MAX_TTL_MS, MIN_TTL_MS;
var init_fingerprint_cache = __esm({
  "server/lib/fingerprint-cache.ts"() {
    init_db();
    init_schema();
    DEFAULT_TTL_MS = 24 * 60 * 60 * 1e3;
    MAX_TTL_MS = 7 * 24 * 60 * 60 * 1e3;
    MIN_TTL_MS = 60 * 60 * 1e3;
  }
});
init_fingerprint_cache();
export {
  cacheFingerprints,
  getCachedFingerprints,
  invalidateHostCache,
  purgeExpiredCache
};
