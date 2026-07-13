/**
 * Shared API helpers for Caldera proxy routers and session management.
 *
 * GoPhish API calls have been consolidated into server/lib/gophish-client.ts.
 */
import { ENV } from "../_core/env";

// ─── Caldera Session ────────────────────────────────────────────────────

export const CALDERA_SESSION_COOKIE = 'caldera_session';

export function getCalderaCookieOptions(req: any, rememberMe = false) {
  const host = req.hostname || req.headers?.host || '';
  const isLocalhost = host.includes('localhost');
  const isManusPreview = host.includes('manus.space') || host.includes('manus.computer') || host.includes('manusvm.computer');
  
  const sameSite = isManusPreview ? 'none' as const : 'lax' as const;
  
  const opts = {
    path: '/',
    httpOnly: false,
    secure: !isLocalhost,
    sameSite,
    maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
  };
  console.log(`[Auth Cookie] host=${host}, sameSite=${sameSite}, secure=${opts.secure}, maxAge=${opts.maxAge}`);
  return opts;
}

// SECURITY: JWT secret MUST come from env var. Fail closed if not set.
export const CALDERA_JWT_SECRET = process.env.CALDERA_JWT_SECRET || process.env.JWT_SECRET || '';

// ─── Caldera API Config ────────────────────────────────────────────────

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

// ─── Caldera API Helper ─────────────────────────────────────────────────

import { getUndiciDispatcher } from "./gophish-client";

/**
 * Caldera API helper.
 * Uses the shared undici dispatcher for TLS override (self-signed certs).
 */
export async function fetchCalderaAPI(url: string, apiKey: string, endpoint: string) {
  try {
    const fullUrl = `${url}${endpoint}`;
    const options: RequestInit & { dispatcher?: any } = {
      headers: { 'KEY': apiKey },
      signal: AbortSignal.timeout(15000),
    };
    if (fullUrl.startsWith('https://')) {
      const dispatcher = getUndiciDispatcher();
      if (dispatcher) options.dispatcher = dispatcher;
    }
    const response = await fetch(fullUrl, options);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error(`Caldera API error (${endpoint}):`, error);
    return null;
  }
}
