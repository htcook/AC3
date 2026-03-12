/**
 * Shared knowledge data loader — fetches JSON data from the DO scan server's
 * /api/knowledge/ endpoint with local file fallback and TTL-based memory cache.
 *
 * Used by modules that previously embedded large data arrays inline.
 * Pattern: try local JSON file first (for DO server), then fetch from API.
 *
 * Cache behaviour:
 *   - Data is cached in memory for CACHE_TTL_MS (default 6 hours).
 *   - After TTL expires the next call transparently re-fetches in the
 *     background while returning the stale value (stale-while-revalidate).
 *   - If the refresh fails, the stale value stays until the next attempt.
 */
import { readFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __esm_dirname = dirname(fileURLToPath(import.meta.url));
import { SCAN_SERVICE_URL, SCAN_API_KEY } from "../scan-service-url";

/** Cache TTL: 6 hours in milliseconds */
const CACHE_TTL_MS = 6 * 60 * 60 * 1000;

interface CacheEntry<T = any> {
  data: T;
  loadedAt: number;       // Date.now() when data was stored
  refreshing: boolean;    // true while a background refresh is in flight
}

// In-memory cache keyed by filename
const _cache = new Map<string, CacheEntry>();

/** Internal: fetch from DO API */
async function fetchFromDO<T>(filename: string): Promise<T | null> {
  try {
    const res = await fetch(
      `${SCAN_SERVICE_URL}/api/knowledge/${filename}`,
      {
        headers: { "X-Scan-Key": SCAN_API_KEY },
        signal: AbortSignal.timeout(15000),
      }
    );
    if (res.ok) {
      return (await res.json()) as T;
    }
    console.warn(`[KnowledgeLoader] DO fetch returned ${res.status} for ${filename}`);
  } catch (e: any) {
    console.warn(`[KnowledgeLoader] DO fetch error for ${filename}:`, e.message);
  }
  return null;
}

/** Internal: load from local file or DO API */
async function loadFresh<T>(filename: string): Promise<T | null> {
  // Try local file first (works when running on the DO scan server itself)
  const localPath = join(__esm_dirname, filename);
  if (existsSync(localPath)) {
    try {
      const raw = readFileSync(localPath, "utf-8");
      const data = JSON.parse(raw) as T;
      console.log(`[KnowledgeLoader] Loaded ${filename} from local file`);
      return data;
    } catch (e: any) {
      console.warn(`[KnowledgeLoader] Local file read failed for ${filename}:`, e.message);
    }
  }

  // Fetch from DO scan service API
  const data = await fetchFromDO<T>(filename);
  if (data !== null) {
    console.log(`[KnowledgeLoader] Loaded ${filename} from DO scan service`);
  }
  return data;
}

/** Background refresh: updates cache without blocking callers */
function backgroundRefresh<T>(filename: string, fallback: T): void {
  const entry = _cache.get(filename);
  if (entry?.refreshing) return; // already in flight
  if (entry) entry.refreshing = true;

  loadFresh<T>(filename)
    .then((data) => {
      if (data !== null) {
        _cache.set(filename, { data, loadedAt: Date.now(), refreshing: false });
        console.log(`[KnowledgeLoader] Refreshed ${filename} (cache updated)`);
      } else if (entry) {
        entry.refreshing = false; // keep stale data
      }
    })
    .catch(() => {
      if (entry) entry.refreshing = false;
    });
}

/**
 * Load a JSON knowledge file. Tries local file first, then DO API.
 * Results are cached in memory with a 6-hour TTL (stale-while-revalidate).
 */
export async function loadKnowledgeData<T = any>(
  filename: string,
  fallback: T
): Promise<T> {
  const cached = _cache.get(filename);

  if (cached) {
    const age = Date.now() - cached.loadedAt;
    if (age < CACHE_TTL_MS) {
      // Fresh — return immediately
      return cached.data as T;
    }
    // Stale — return stale data but trigger background refresh
    backgroundRefresh<T>(filename, fallback);
    return cached.data as T;
  }

  // Cold start — must fetch synchronously (first call)
  const data = await loadFresh<T>(filename);
  if (data !== null) {
    _cache.set(filename, { data, loadedAt: Date.now(), refreshing: false });
    return data;
  }

  // Return fallback (empty data)
  console.warn(`[KnowledgeLoader] Using fallback for ${filename}`);
  _cache.set(filename, { data: fallback, loadedAt: Date.now(), refreshing: false });
  return fallback;
}

/**
 * Synchronous getter — returns cached data or null if not yet loaded.
 * Call loadKnowledgeData() first to populate the cache.
 */
export function getCachedKnowledge<T = any>(filename: string): T | null {
  const entry = _cache.get(filename);
  return entry ? (entry.data as T) : null;
}

/**
 * Pre-warm multiple knowledge files in parallel at server startup.
 */
export async function preloadKnowledge(
  files: Array<{ filename: string; fallback: any }>
): Promise<void> {
  await Promise.allSettled(
    files.map(({ filename, fallback }) => loadKnowledgeData(filename, fallback))
  );
}

/**
 * Force-invalidate a cached entry so the next call re-fetches.
 * Useful for admin/debug endpoints.
 */
export function invalidateKnowledgeCache(filename?: string): void {
  if (filename) {
    _cache.delete(filename);
  } else {
    _cache.clear();
  }
}

/**
 * Return cache diagnostics (for admin/debug).
 */
export function getKnowledgeCacheStats(): Array<{
  filename: string;
  ageMinutes: number;
  refreshing: boolean;
}> {
  const now = Date.now();
  return Array.from(_cache.entries()).map(([filename, entry]) => ({
    filename,
    ageMinutes: Math.round((now - entry.loadedAt) / 60000),
    refreshing: entry.refreshing,
  }));
}
