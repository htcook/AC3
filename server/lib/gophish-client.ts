/**
 * Consolidated GoPhish API Client
 *
 * Single source of truth for all GoPhish API calls.
 * Supports two error modes:
 *   - "silent" (default): returns null on failure (for proxy/status endpoints)
 *   - "throw": throws TRPCError on failure (for mutation/write endpoints)
 *
 * Features:
 *   - Undici dispatcher for native fetch() TLS override (self-signed certs)
 *   - Retry with exponential backoff on transient failures
 *   - 15-second timeout per request
 *   - Raw API key auth (no Bearer prefix — GoPhish expects raw key)
 */

import { ENV } from "../_core/env";

// ─── Undici Dispatcher (singleton) ─────────────────────────────────────────

let _undiciDispatcher: any = null;

function getUndiciDispatcher(): any {
  if (_undiciDispatcher) return _undiciDispatcher;
  try {
    const { Agent } = require("undici");
    _undiciDispatcher = new Agent({
      connect: { rejectUnauthorized: false },
    });
  } catch {
    console.warn("[GoPhish] undici not available — self-signed certs may fail");
  }
  return _undiciDispatcher;
}

// ─── Types ─────────────────────────────────────────────────────────────────

export interface FetchGophishOptions {
  /** HTTP method. Default: "GET" */
  method?: string;
  /** Request body (auto-serialized to JSON). Ignored for GET. */
  data?: any;
  /** Number of retries on transient (5xx / network) failures. Default: 2 */
  retries?: number;
  /** Request timeout in ms. Default: 15000 */
  timeoutMs?: number;
  /**
   * Error mode:
   *   - "silent": returns null on failure (default)
   *   - "throw": throws TRPCError on failure
   */
  errorMode?: "silent" | "throw";
}

// ─── Core Fetch ────────────────────────────────────────────────────────────

/**
 * Fetch from the GoPhish API.
 *
 * @param endpoint  API path, e.g. "/api/templates/"
 * @param opts      Optional configuration (method, data, retries, errorMode)
 * @returns         Parsed JSON response, or null on failure (silent mode)
 * @throws          TRPCError when errorMode is "throw" and the request fails
 */
export async function fetchGophish(
  endpoint: string,
  opts: FetchGophishOptions = {}
): Promise<any> {
  const {
    method = "GET",
    data,
    retries = 2,
    timeoutMs = 15000,
    errorMode = "silent",
  } = opts;

  const baseUrl = ENV.gophishBaseUrl;
  const apiKey = ENV.gophishApiKey;

  if (!baseUrl || !apiKey) {
    if (errorMode === "throw") {
      const { TRPCError } = await import("@trpc/server");
      throw new TRPCError({
        code: "PRECONDITION_FAILED",
        message: "GoPhish not configured",
      });
    }
    return null;
  }

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const url = `${baseUrl}${endpoint}`;
      const fetchOpts: RequestInit & { dispatcher?: any } = {
        method,
        headers: {
          Authorization: apiKey,
          "Content-Type": "application/json",
        },
        signal: AbortSignal.timeout(timeoutMs),
      };

      if (data && method !== "GET") {
        fetchOpts.body = JSON.stringify(data);
      }

      // Undici dispatcher for TLS override (self-signed certs)
      if (url.startsWith("https://")) {
        const dispatcher = getUndiciDispatcher();
        if (dispatcher) fetchOpts.dispatcher = dispatcher;
      }

      const response = await fetch(url, fetchOpts);

      if (!response.ok) {
        const errText = await response.text().catch(() => "");
        console.error(
          `[GoPhish] ${method} ${endpoint}: ${response.status} ${errText}`
        );

        // Retry on server errors
        if (attempt < retries && response.status >= 500) continue;

        if (errorMode === "throw") {
          const { TRPCError } = await import("@trpc/server");
          throw new TRPCError({
            code: "INTERNAL_SERVER_ERROR",
            message: `GoPhish ${method} ${endpoint}: ${response.status} ${errText}`,
          });
        }
        return null;
      }

      // 204 No Content
      if (response.status === 204) return null;

      const text = await response.text();
      return text ? JSON.parse(text) : null;
    } catch (error: any) {
      // If it's already a TRPCError, re-throw immediately
      if (error?.name === "TRPCError") throw error;

      console.error(
        `[GoPhish] ${method} ${endpoint} attempt ${attempt + 1}/${retries + 1}:`,
        error?.message || error
      );

      if (attempt < retries) {
        await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
        continue;
      }

      if (errorMode === "throw") {
        const { TRPCError } = await import("@trpc/server");
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `GoPhish ${method} ${endpoint} failed: ${error?.message || "unknown error"}`,
        });
      }
      return null;
    }
  }
  return null;
}

// ─── Convenience Wrappers ──────────────────────────────────────────────────

/** Silent GET — returns null on failure */
export function gophishGet(endpoint: string): Promise<any> {
  return fetchGophish(endpoint);
}

/** Silent POST — returns null on failure */
export function gophishPost(endpoint: string, data: any): Promise<any> {
  return fetchGophish(endpoint, { method: "POST", data });
}

/** Throwing GET — throws TRPCError on failure */
export function gophishGetOrThrow(endpoint: string): Promise<any> {
  return fetchGophish(endpoint, { errorMode: "throw" });
}

/** Throwing POST — throws TRPCError on failure */
export function gophishPostOrThrow(endpoint: string, data: any): Promise<any> {
  return fetchGophish(endpoint, { method: "POST", data, errorMode: "throw" });
}

/** Throwing PUT — throws TRPCError on failure */
export function gophishPutOrThrow(endpoint: string, data: any): Promise<any> {
  return fetchGophish(endpoint, { method: "PUT", data, errorMode: "throw" });
}

/** Throwing DELETE — throws TRPCError on failure */
export function gophishDeleteOrThrow(endpoint: string): Promise<any> {
  return fetchGophish(endpoint, { method: "DELETE", errorMode: "throw" });
}

/**
 * Re-export the undici dispatcher for use by other API clients
 * (e.g., Caldera, Sliver, Manjusaka) that also need TLS override.
 */
export { getUndiciDispatcher };
