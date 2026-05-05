import {
  getDb,
  init_db
} from "./chunk-AGW4B7XR.js";
import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import {
  __require
} from "./chunk-KFQGP6VL.js";

// server/routers/phishing/shared.ts
init_db();
import { TRPCError } from "@trpc/server";

// server/lib/gophish-client.ts
init_env();
var _undiciDispatcher = null;
function getUndiciDispatcher() {
  if (_undiciDispatcher) return _undiciDispatcher;
  try {
    const { Agent } = __require("undici");
    _undiciDispatcher = new Agent({
      connect: { rejectUnauthorized: false }
    });
  } catch {
    console.warn("[GoPhish] undici not available \u2014 self-signed certs may fail");
  }
  return _undiciDispatcher;
}
async function fetchGophish(endpoint, opts = {}) {
  const {
    method = "GET",
    data,
    retries = 2,
    timeoutMs = 15e3,
    errorMode = "silent"
  } = opts;
  const baseUrl = ENV.gophishBaseUrl;
  const apiKey = ENV.gophishApiKey;
  if (!baseUrl || !apiKey) {
    if (errorMode === "throw") {
      const { TRPCError: TRPCError2 } = await import("@trpc/server");
      throw new TRPCError2({
        code: "PRECONDITION_FAILED",
        message: "GoPhish not configured"
      });
    }
    return null;
  }
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const url = `${baseUrl}${endpoint}`;
      const fetchOpts = {
        method,
        headers: {
          Authorization: apiKey,
          "Content-Type": "application/json"
        },
        signal: AbortSignal.timeout(timeoutMs)
      };
      if (data && method !== "GET") {
        fetchOpts.body = JSON.stringify(data);
      }
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
        if (attempt < retries && response.status >= 500) continue;
        if (errorMode === "throw") {
          const { TRPCError: TRPCError2 } = await import("@trpc/server");
          throw new TRPCError2({
            code: "INTERNAL_SERVER_ERROR",
            message: `GoPhish ${method} ${endpoint}: ${response.status} ${errText}`
          });
        }
        return null;
      }
      if (response.status === 204) return null;
      const text = await response.text();
      return text ? JSON.parse(text) : null;
    } catch (error) {
      if (error?.name === "TRPCError") throw error;
      console.error(
        `[GoPhish] ${method} ${endpoint} attempt ${attempt + 1}/${retries + 1}:`,
        error?.message || error
      );
      if (attempt < retries) {
        await new Promise((r) => setTimeout(r, 1e3 * (attempt + 1)));
        continue;
      }
      if (errorMode === "throw") {
        const { TRPCError: TRPCError2 } = await import("@trpc/server");
        throw new TRPCError2({
          code: "INTERNAL_SERVER_ERROR",
          message: `GoPhish ${method} ${endpoint} failed: ${error?.message || "unknown error"}`
        });
      }
      return null;
    }
  }
  return null;
}

// server/routers/phishing/shared.ts
async function requireDb() {
  const db = await getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database not available" });
  return db;
}
function fetchGophish2(endpoint, method = "GET", data) {
  return fetchGophish(endpoint, { method, data, errorMode: "throw" });
}

export {
  getUndiciDispatcher,
  fetchGophish,
  requireDb,
  fetchGophish2
};
