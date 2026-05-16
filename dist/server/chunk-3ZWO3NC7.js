import {
  SCAN_API_KEY,
  SCAN_SERVICE_URL,
  init_scan_service_url
} from "./chunk-S5IAMGAW.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/knowledge/knowledge-loader.ts
import { readFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
async function fetchFromDO(filename) {
  try {
    const res = await fetch(
      `${SCAN_SERVICE_URL}/api/knowledge/${filename}`,
      {
        headers: { "X-Scan-Key": SCAN_API_KEY },
        signal: AbortSignal.timeout(15e3)
      }
    );
    if (res.ok) {
      return await res.json();
    }
    console.warn(`[KnowledgeLoader] DO fetch returned ${res.status} for ${filename}`);
  } catch (e) {
    console.warn(`[KnowledgeLoader] DO fetch error for ${filename}:`, e.message);
  }
  return null;
}
async function loadFresh(filename) {
  const localPath = join(__esm_dirname, filename);
  if (existsSync(localPath)) {
    try {
      const raw = readFileSync(localPath, "utf-8");
      const data2 = JSON.parse(raw);
      console.log(`[KnowledgeLoader] Loaded ${filename} from local file`);
      return data2;
    } catch (e) {
      console.warn(`[KnowledgeLoader] Local file read failed for ${filename}:`, e.message);
    }
  }
  const data = await fetchFromDO(filename);
  if (data !== null) {
    console.log(`[KnowledgeLoader] Loaded ${filename} from DO scan service`);
  }
  return data;
}
function backgroundRefresh(filename, fallback) {
  const entry = _cache.get(filename);
  if (entry?.refreshing) return;
  if (entry) entry.refreshing = true;
  loadFresh(filename).then((data) => {
    if (data !== null) {
      _cache.set(filename, { data, loadedAt: Date.now(), refreshing: false });
      console.log(`[KnowledgeLoader] Refreshed ${filename} (cache updated)`);
    } else if (entry) {
      entry.refreshing = false;
    }
  }).catch(() => {
    if (entry) entry.refreshing = false;
  });
}
async function loadKnowledgeData(filename, fallback) {
  const cached = _cache.get(filename);
  if (cached) {
    const age = Date.now() - cached.loadedAt;
    if (age < CACHE_TTL_MS) {
      return cached.data;
    }
    backgroundRefresh(filename, fallback);
    return cached.data;
  }
  const data = await loadFresh(filename);
  if (data !== null) {
    _cache.set(filename, { data, loadedAt: Date.now(), refreshing: false });
    return data;
  }
  console.warn(`[KnowledgeLoader] Using fallback for ${filename}`);
  _cache.set(filename, { data: fallback, loadedAt: Date.now(), refreshing: false });
  return fallback;
}
function invalidateKnowledgeCache(filename) {
  if (filename) {
    _cache.delete(filename);
  } else {
    _cache.clear();
  }
}
function getKnowledgeCacheStats() {
  const now = Date.now();
  return Array.from(_cache.entries()).map(([filename, entry]) => ({
    filename,
    ageMinutes: Math.round((now - entry.loadedAt) / 6e4),
    refreshing: entry.refreshing
  }));
}
var __esm_dirname, CACHE_TTL_MS, _cache;
var init_knowledge_loader = __esm({
  "server/lib/knowledge/knowledge-loader.ts"() {
    "use strict";
    init_scan_service_url();
    __esm_dirname = dirname(fileURLToPath(import.meta.url));
    CACHE_TTL_MS = 6 * 60 * 60 * 1e3;
    _cache = /* @__PURE__ */ new Map();
  }
});

export {
  loadKnowledgeData,
  invalidateKnowledgeCache,
  getKnowledgeCacheStats,
  init_knowledge_loader
};
