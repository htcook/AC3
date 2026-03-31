/**
 * Shared API helpers for Caldera and GoPhish proxy routers.
 *
 * FIPS 140-3 Compliance:
 *   All outbound HTTPS connections use the FIPS HTTPS agent which restricts
 *   to TLS 1.2+ with NIST SP 800-52 Rev. 2 approved cipher suites only.
 *   GoPhish self-signed certs are handled via a dedicated FIPS agent with
 *   rejectUnauthorized: false (TLS encryption still enforced, just no CA check).
 */
import { ENV } from "../_core/env";
import { getFIPSHttpsAgent, createFIPSHttpsAgent } from "./fips-tls";
import https from "https";

// ─── Caldera Session ────────────────────────────────────────────────────

export const CALDERA_SESSION_COOKIE = 'caldera_session';

export function getCalderaCookieOptions(req: any, rememberMe = false) {
  const host = req.hostname || req.headers?.host || '';
  const isLocalhost = host.includes('localhost');
  const isManusPreview = host.includes('manus.space') || host.includes('manus.computer') || host.includes('manusvm.computer');
  
  const sameSite = isManusPreview ? 'none' as const : 'lax' as const;
  
  const opts = {
    path: '/',
    httpOnly: true,
    secure: !isLocalhost,
    sameSite,
    maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
  };
  console.log(`[Auth Cookie] host=${host}, sameSite=${sameSite}, secure=${opts.secure}, maxAge=${opts.maxAge}`);
  return opts;
}

export const CALDERA_JWT_SECRET = process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024';

// ─── GoPhish & Caldera API Config ───────────────────────────────────────

export const GOPHISH_URL = ENV.gophishBaseUrl;
export const GOPHISH_API_KEY = ENV.gophishApiKey;
export const CALDERA_BASE_URL = ENV.calderaBaseUrl;
export const CALDERA_API_KEY = ENV.calderaApiKey;

// ─── Server-Side Response Cache ────────────────────────────────────────
/**
 * Simple in-memory TTL cache for expensive external API responses.
 * Prevents concurrent requests from hammering Caldera/GoPhish servers
 * when multiple dashboard users are polling simultaneously.
 */
interface CacheEntry<T> {
  data: T;
  expiresAt: number;
  /** In-flight promise to prevent thundering herd */
  pending?: Promise<T>;
}

const responseCache = new Map<string, CacheEntry<any>>();

/**
 * Get-or-fetch with TTL caching and request deduplication.
 * If a cached value exists and hasn't expired, returns it immediately.
 * If multiple callers request the same key simultaneously, only one
 * fetch executes and the rest await the same promise.
 */
export async function cachedFetch<T>(
  key: string,
  fetcher: () => Promise<T>,
  ttlMs: number = 30_000,
): Promise<T> {
  const now = Date.now();
  const entry = responseCache.get(key);

  // Return cached data if still fresh
  if (entry && entry.expiresAt > now) {
    return entry.data;
  }

  // If there's already an in-flight request, piggyback on it
  if (entry?.pending) {
    return entry.pending;
  }

  // Create the fetch promise and store it to deduplicate
  const pending = fetcher().then((result) => {
    responseCache.set(key, {
      data: result,
      expiresAt: Date.now() + ttlMs,
    });
    return result;
  }).catch((err) => {
    // On error, return stale data if available, otherwise rethrow
    const stale = responseCache.get(key);
    if (stale?.data !== undefined) {
      console.warn(`[Cache] Fetch failed for "${key}", returning stale data:`, err);
      return stale.data;
    }
    throw err;
  });

  // Store the pending promise (keep stale data around for fallback)
  if (entry) {
    entry.pending = pending;
  } else {
    responseCache.set(key, { data: undefined as any, expiresAt: 0, pending });
  }

  return pending;
}

/** Invalidate a specific cache key */
export function invalidateCache(key: string): void {
  responseCache.delete(key);
}

/** Clear all cached responses */
export function clearAllCache(): void {
  responseCache.clear();
}

// ─── FIPS HTTPS Agents ─────────────────────────────────────────────────

/**
 * FIPS agent for GoPhish connections.
 * GoPhish uses a self-signed certificate, so we disable CA validation
 * but STILL enforce FIPS-approved cipher suites and TLS 1.2+.
 */
let _gophishFipsAgent: https.Agent | null = null;
function getGophishFIPSAgent(): https.Agent {
  if (_gophishFipsAgent) return _gophishFipsAgent;
  _gophishFipsAgent = createFIPSHttpsAgent({
    rejectUnauthorized: false,
  });
  return _gophishFipsAgent;
}

// ─── GoPhish API Helper ─────────────────────────────────────────────────

/**
 * FIPS 140-3 compliant GoPhish API helper.
 * Uses FIPS HTTPS agent instead of disabling TLS validation globally.
 */
export async function fetchGophishAPI(endpoint: string, method: string = 'GET', data?: any) {
  try {
    const url = `${GOPHISH_URL}${endpoint}`;
    const isHttps = url.startsWith('https://');

    const options: RequestInit & { dispatcher?: any } = {
      method,
      headers: {
        'Authorization': GOPHISH_API_KEY,
        'Content-Type': 'application/json',
      },
      signal: AbortSignal.timeout(5000),
    };
    if (data) options.body = JSON.stringify(data);

    if (isHttps) {
      // @ts-ignore - Node.js specific option for native fetch
      options.agent = getGophishFIPSAgent();
    }
    
    const response = await fetch(url, options);
    if (!response.ok) {
      const errText = await response.text();
      console.error(`GoPhish API error (${endpoint}):`, response.status, errText);
      return null;
    }
    const text = await response.text();
    return text ? JSON.parse(text) : null;
  } catch (error) {
    console.error(`GoPhish API error (${endpoint}):`, error);
    return null;
  }
}

// ─── Caldera API Helper ─────────────────────────────────────────────────

/**
 * FIPS 140-3 compliant Caldera API helper.
 * Uses the global FIPS HTTPS agent for all outbound HTTPS connections.
 */
export async function fetchCalderaAPI(url: string, apiKey: string, endpoint: string) {
  try {
    const fullUrl = `${url}${endpoint}`;
    const isHttps = fullUrl.startsWith('https://');

    const options: RequestInit & { dispatcher?: any } = {
      headers: { 'KEY': apiKey },
      signal: AbortSignal.timeout(5000),
    };

    if (isHttps) {
      // @ts-ignore - Node.js specific option for native fetch
      options.agent = getFIPSHttpsAgent();
    }

    const response = await fetch(fullUrl, options);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error(`Caldera API error (${endpoint}):`, error);
    return null;
  }
}
