/**
 * Shared helpers for phishing sub-routers.
 * Extracted from the original phishing-ops.ts to avoid duplication.
 */

import { TRPCError } from "@trpc/server";
import { getDb } from "../../db";
import { fetchGophish as _fetchGophish } from "../../lib/gophish-client";

export async function requireDb() {
  const db = await getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });
  return db;
}

/** Wrapper that uses throwing mode (matching original behavior of phishing sub-routers) */
export function fetchGophish(endpoint: string, method = "GET", data?: any) {
  return _fetchGophish(endpoint, { method, data, errorMode: "throw" });
}
