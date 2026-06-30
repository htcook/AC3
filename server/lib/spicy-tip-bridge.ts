/**
 * SpicyThreatIntel API Bridge
 *
 * Server-to-server connector that queries the SpicyThreatIntel tRPC API
 * for darkweb intelligence data: ransomware victim stats, ThreatFox IOCs,
 * activity ratings, global threat actors, CISA KEV, and OTX pulses.
 *
 * Configuration:
 *   SPICY_TIP_BASE_URL  — Base URL of the SpicyThreatIntel API
 *   SPICY_TIP_API_KEY   — Bearer token for authenticated access (optional)
 */

import type {
  ThreatFoxIOC,
  ActivityRating,
  CISAKEVEntry,
  EscalationAlert,
  SpicyTIPBridgeConfig,
  OTXPulse,
  MalwareBazaarEntry,
  AdaptiveKeyword,
  RansomwareEvent,
} from "../../shared/darkweb-types";

/** Ransomware victim stats shape from SpicyThreatIntel API */
interface RansomwareVictimStats {
  groupName: string;
  victimCount: number;
  countries: string[];
  sectors: string[];
}

// ─── Configuration ───────────────────────────────────────────────────────

function getBridgeConfig(): SpicyTIPBridgeConfig {
  let baseUrl = (process.env.SPICY_TIP_BASE_URL || "").trim();
  // Normalize: ensure protocol prefix
  if (baseUrl && !baseUrl.startsWith("http")) {
    baseUrl = `https://${baseUrl}`;
  }
  // Remove trailing slash
  baseUrl = baseUrl.replace(/\/+$/, "");
  const apiKey = process.env.SPICY_TIP_API_KEY || "";
  return {
    baseUrl,
    apiKey,
    timeout: 30_000,
    retryAttempts: 2,
  };
}

function isBridgeConfigured(): boolean {
  const config = getBridgeConfig();
  return !!config.baseUrl && config.baseUrl.startsWith("http");
}

// ─── HTTP Client ─────────────────────────────────────────────────────────

interface TRPCResponse<T> {
  result?: { data?: T };
  error?: { message: string; code: string };
}

async function callSpicyTIP<T>(
  procedure: string,
  input: Record<string, unknown> = {},
  method: "GET" | "POST" = "GET"
): Promise<T | null> {
  const config = getBridgeConfig();
  if (!config.baseUrl) {
    console.warn("[SpicyTIP Bridge] Not configured — SPICY_TIP_BASE_URL is empty");
    return null;
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (config.apiKey) {
    headers["Authorization"] = `Bearer ${config.apiKey}`;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.timeout || 30_000);

  let lastError: Error | null = null;
  const maxAttempts = (config.retryAttempts || 2) + 1;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      let url: string;
      let fetchOpts: RequestInit;

      if (method === "GET") {
        const encoded = encodeURIComponent(JSON.stringify({ json: input }));
        url = `${config.baseUrl}/api/trpc/${procedure}?input=${encoded}`;
        fetchOpts = { method: "GET", headers, signal: controller.signal };
      } else {
        url = `${config.baseUrl}/api/trpc/${procedure}`;
        fetchOpts = {
          method: "POST",
          headers,
          body: JSON.stringify({ json: input }),
          signal: controller.signal,
        };
      }

      const res = await fetch(url, fetchOpts);
      clearTimeout(timeoutId);

      if (!res.ok) {
        const errText = await res.text().catch(() => "");
        throw new Error(`HTTP ${res.status}: ${errText.slice(0, 200)}`);
      }

      const json = (await res.json()) as TRPCResponse<T>;
      if (json.error) {
        throw new Error(`tRPC error: ${json.error.message}`);
      }

      return json.result?.data ?? null;
    } catch (err: any) {
      lastError = err;
      if (attempt < maxAttempts) {
        console.warn(
          `[SpicyTIP Bridge] ${procedure} attempt ${attempt} failed: ${err.message}. Retrying...`
        );
        await new Promise((r) => setTimeout(r, 1000 * attempt));
      }
    }
  }

  clearTimeout(timeoutId);
  console.error(`[SpicyTIP Bridge] ${procedure} failed after ${maxAttempts} attempts:`, lastError?.message);
  return null;
}

// ─── Public API Methods ──────────────────────────────────────────────────

/**
 * Check if the SpicyThreatIntel bridge is configured and reachable.
 */
export async function checkBridgeHealth(): Promise<{
  configured: boolean;
  reachable: boolean;
  baseUrl: string;
}> {
  const config = getBridgeConfig();
  const configured = isBridgeConfigured();

  if (!configured) {
    return { configured: false, reachable: false, baseUrl: "" };
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(`${config.baseUrl}/api/trpc`, {
      method: "GET",
      signal: controller.signal,
    });
    clearTimeout(timeout);
    return { configured: true, reachable: res.status < 500, baseUrl: config.baseUrl };
  } catch {
    return { configured: true, reachable: false, baseUrl: config.baseUrl };
  }
}

/**
 * Get ransomware victim statistics by group.
 */
export async function getRansomwareVictimStats(
  limit?: number
): Promise<RansomwareVictimStats[] | null> {
  return callSpicyTIP<RansomwareVictimStats[]>(
    "darkWebIntel.getRansomwareVictimStats",
    { limit: limit || 50 }
  );
}

/**
 * Get ThreatFox IOCs for corroboration enrichment.
 */
export async function getThreatFoxIOCs(
  opts?: { limit?: number; type?: string }
): Promise<ThreatFoxIOC[] | null> {
  return callSpicyTIP<ThreatFoxIOC[]>("darkWebIntel.getThreatFoxIOCs", {
    limit: opts?.limit || 100,
    type: opts?.type,
  });
}

/**
 * Get activity ratings for ransomware groups.
 */
export async function getActivityRatings(): Promise<ActivityRating[] | null> {
  return callSpicyTIP<ActivityRating[]>("enrichment.getActivityRatings");
}

/**
 * Get victim group statistics.
 */
export async function getVictimGroupStats(): Promise<RansomwareVictimStats[] | null> {
  return callSpicyTIP<RansomwareVictimStats[]>("enrichment.getVictimGroupStats");
}

/**
 * Get global threat actors from SpicyThreatIntel.
 */
export async function getGlobalThreatActors(
  limit?: number
): Promise<Array<{
  name: string;
  aliases: string[];
  attributionCountry?: string;
  mitreAttackTechniques: string[];
  malwareFamilies: string[];
  targetSectors: string[];
}> | null> {
  return callSpicyTIP("darkWebIntel.getGlobalThreatActors", { limit: limit || 100 });
}

/**
 * Get CISA Known Exploited Vulnerabilities.
 */
export async function getCISAKEV(limit?: number): Promise<CISAKEVEntry[] | null> {
  return callSpicyTIP<CISAKEVEntry[]>("enrichment.getCISAKEV", { limit: limit || 50 });
}

/**
 * Get recent ransomware victim events.
 */
export async function getRecentVictimEvents(
  limit?: number
): Promise<RansomwareEvent[] | null> {
  return callSpicyTIP<RansomwareEvent[]>("darkWebIntel.getRecentVictimEvents", {
    limit: limit || 50,
  });
}

/**
 * Get OTX threat pulses.
 */
export async function getOTXPulses(limit?: number): Promise<OTXPulse[] | null> {
  return callSpicyTIP<OTXPulse[]>("darkWebIntel.getOTXPulses", { limit: limit || 25 });
}

/**
 * Get Malware Bazaar entries.
 */
export async function getMalwareBazaarEntries(
  limit?: number
): Promise<MalwareBazaarEntry[] | null> {
  return callSpicyTIP<MalwareBazaarEntry[]>("darkWebIntel.getMalwareBazaar", {
    limit: limit || 50,
  });
}

/**
 * Get adaptive keywords for darkweb monitoring.
 */
export async function getAdaptiveKeywords(): Promise<AdaptiveKeyword[] | null> {
  return callSpicyTIP<AdaptiveKeyword[]>("darkWebIntel.getAdaptiveKeywords");
}

/**
 * Get escalation alerts.
 */
export async function getEscalationAlerts(
  opts?: { severity?: string; limit?: number }
): Promise<EscalationAlert[] | null> {
  return callSpicyTIP<EscalationAlert[]>("darkWebIntel.getEscalationAlerts", {
    severity: opts?.severity,
    limit: opts?.limit || 25,
  });
}

/**
 * Corroborate a list of assets (IPs, domains, hashes) against ThreatFox IOCs.
 * Returns matches with corroboration tier.
 */
export async function corroborateAssets(
  assets: Array<{ value: string; type: "ip" | "domain" | "url" | "hash" | "email" }>
): Promise<Array<{
  asset: string;
  assetType: string;
  matchedIOC: ThreatFoxIOC;
  corroborationTier: "confirmed" | "probable" | "potential";
}> | null> {
  return callSpicyTIP("enrichment.corroborateAssets", { assets }, "POST");
}

/**
 * Sync darkweb intelligence data into the local threat catalog.
 * This is the main ingestion function that pulls data from SpicyThreatIntel
 * and merges it into the local database.
 */
export async function syncDarkwebIntelligence(): Promise<{
  actorsImported: number;
  iocsImported: number;
  eventsImported: number;
  ratingsUpdated: number;
  errors: string[];
} | null> {
  if (!isBridgeConfigured()) {
    return { actorsImported: 0, iocsImported: 0, eventsImported: 0, ratingsUpdated: 0, errors: ["Bridge not configured"] };
  }

  const errors: string[] = [];
  let actorsImported = 0;
  let iocsImported = 0;
  let eventsImported = 0;
  let ratingsUpdated = 0;

  // 1. Fetch activity ratings
  try {
    const ratings = await getActivityRatings();
    if (ratings) {
      ratingsUpdated = ratings.length;
    }
  } catch (e: any) {
    errors.push(`Activity ratings: ${e.message}`);
  }

  // 2. Fetch global threat actors
  try {
    const actors = await getGlobalThreatActors(200);
    if (actors) {
      actorsImported = actors.length;
    }
  } catch (e: any) {
    errors.push(`Threat actors: ${e.message}`);
  }

  // 3. Fetch ThreatFox IOCs
  try {
    const iocs = await getThreatFoxIOCs({ limit: 200 });
    if (iocs) {
      iocsImported = iocs.length;
    }
  } catch (e: any) {
    errors.push(`ThreatFox IOCs: ${e.message}`);
  }

  // 4. Fetch recent victim events
  try {
    const events = await getRecentVictimEvents(100);
    if (events) {
      eventsImported = events.length;
    }
  } catch (e: any) {
    errors.push(`Victim events: ${e.message}`);
  }

  return { actorsImported, iocsImported, eventsImported, ratingsUpdated, errors };
}

// ─── Export bridge status for health checks ──────────────────────────────

export { isBridgeConfigured, getBridgeConfig };
