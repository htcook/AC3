/**
 * Shared knowledge data loader — fetches JSON data from the DO scan server's
 * /api/knowledge/ endpoint with local file fallback and singleton caching.
 *
 * Used by modules that previously embedded large data arrays inline.
 * Pattern: try local JSON file first (for DO server), then fetch from API.
 */
import { readFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __esm_dirname = dirname(fileURLToPath(import.meta.url));
const SCAN_SERVICE_URL = process.env.SCAN_SERVER_HOST
  ? `http://${process.env.SCAN_SERVER_HOST}`
  : "http://159.223.152.190";
const SCAN_API_KEY = process.env.CALDERA_API_KEY || "ADMIN123";

// In-memory cache keyed by filename
const _cache = new Map<string, any>();

/**
 * Load a JSON knowledge file. Tries local file first, then DO API.
 * Results are cached in memory (singleton pattern).
 */
export async function loadKnowledgeData<T = any>(
  filename: string,
  fallback: T
): Promise<T> {
  if (_cache.has(filename)) return _cache.get(filename) as T;

  // Try local file (works when running on the DO scan server itself)
  const localPath = join(__esm_dirname, filename);
  if (existsSync(localPath)) {
    try {
      const raw = readFileSync(localPath, "utf-8");
      const data = JSON.parse(raw) as T;
      _cache.set(filename, data);
      console.log(`[KnowledgeLoader] Loaded ${filename} from local file`);
      return data;
    } catch (e: any) {
      console.warn(`[KnowledgeLoader] Local file read failed for ${filename}:`, e.message);
    }
  }

  // Fetch from DO scan service API
  try {
    const res = await fetch(
      `${SCAN_SERVICE_URL}/api/knowledge/${filename}`,
      {
        headers: { "X-Scan-Key": SCAN_API_KEY },
        signal: AbortSignal.timeout(15000),
      }
    );
    if (res.ok) {
      const data = (await res.json()) as T;
      _cache.set(filename, data);
      console.log(`[KnowledgeLoader] Loaded ${filename} from DO scan service`);
      return data;
    }
    console.warn(`[KnowledgeLoader] DO fetch returned ${res.status} for ${filename}`);
  } catch (e: any) {
    console.warn(`[KnowledgeLoader] DO fetch error for ${filename}:`, e.message);
  }

  // Return fallback (empty data)
  console.warn(`[KnowledgeLoader] Using fallback for ${filename}`);
  _cache.set(filename, fallback);
  return fallback;
}

/**
 * Synchronous getter — returns cached data or null if not yet loaded.
 * Call loadKnowledgeData() first to populate the cache.
 */
export function getCachedKnowledge<T = any>(filename: string): T | null {
  return (_cache.get(filename) as T) ?? null;
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
