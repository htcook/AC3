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

export async function fetchGophish(endpoint: string, method = "GET", data?: any) {
  const { ENV } = await import("../../_core/env");
  const baseUrl = ENV.gophishBaseUrl;
  const apiKey = ENV.gophishApiKey;
  if (!baseUrl || !apiKey) {
    throw new TRPCError({ code: "PRECONDITION_FAILED", message: "GoPhish not configured" });
  }
  const url = `${baseUrl}${endpoint}`;
  const opts: RequestInit & { agent?: any } = {
    method,
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    ...(typeof globalThis !== "undefined" && { signal: AbortSignal.timeout(15000) }),
  };
  if (data && method !== "GET") {
    opts.body = JSON.stringify(data);
  }
  // FIPS 140-3: Use FIPS HTTPS agent with self-signed cert support
  if (url.startsWith('https://')) {
    const { createFIPSHttpsAgent } = await import('../../lib/fips-tls');
    // @ts-ignore - Node.js specific option
    opts.agent = createFIPSHttpsAgent({ rejectUnauthorized: false });
  }
  const res = await fetch(url, opts);
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `GoPhish ${method} ${endpoint}: ${res.status} ${text}` });
  }
  if (res.status === 204) return null;
  return res.json();
}
