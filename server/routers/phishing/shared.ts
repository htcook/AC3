/**
 * Shared helpers for phishing sub-routers.
 * Extracted from the original phishing-ops.ts to avoid duplication.
 */

import { TRPCError } from "@trpc/server";
import { getDb } from "../../db";

export async function requireDb() {
  const db = await getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });
  return db;
}

/**
 * Lazy-initialized undici Agent for native fetch() with TLS override.
 * Node.js native fetch uses undici — the `agent` option from https.Agent
 * is silently ignored. We must use `dispatcher` instead.
 */
let _undiciAgent: any = null;
function getUndiciDispatcher(): any {
  if (_undiciAgent) return _undiciAgent;
  try {
    const { Agent } = require('undici');
    _undiciAgent = new Agent({
      connect: { rejectUnauthorized: false },
    });
  } catch {
    console.warn('[GoPhish/shared] undici not available, self-signed certs may fail');
  }
  return _undiciAgent;
}

export async function fetchGophish(endpoint: string, method = "GET", data?: any) {
  const { ENV } = await import("../../_core/env");
  const baseUrl = ENV.gophishBaseUrl;
  const apiKey = ENV.gophishApiKey;
  if (!baseUrl || !apiKey) {
    throw new TRPCError({ code: "PRECONDITION_FAILED", message: "GoPhish not configured" });
  }
  const url = `${baseUrl}${endpoint}`;
  const opts: RequestInit & { dispatcher?: any } = {
    method,
    headers: {
      Authorization: apiKey,
      "Content-Type": "application/json",
    },
    signal: AbortSignal.timeout(15000),
  };
  if (data && method !== "GET") {
    opts.body = JSON.stringify(data);
  }
  // Use undici dispatcher for native fetch() TLS override (self-signed certs)
  if (url.startsWith('https://')) {
    const dispatcher = getUndiciDispatcher();
    if (dispatcher) {
      opts.dispatcher = dispatcher;
    }
  }
  const res = await fetch(url, opts);
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `GoPhish ${method} ${endpoint}: ${res.status} ${text}` });
  }
  if (res.status === 204) return null;
  return res.json();
}
