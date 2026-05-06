import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/spicy-tip-bridge.ts
function getBridgeConfig() {
  let baseUrl = (process.env.SPICY_TIP_BASE_URL || "").trim();
  if (baseUrl && !baseUrl.startsWith("http")) {
    baseUrl = `https://${baseUrl}`;
  }
  baseUrl = baseUrl.replace(/\/+$/, "");
  const apiKey = process.env.SPICY_TIP_API_KEY || "";
  return {
    baseUrl,
    apiKey,
    timeout: 3e4,
    retryAttempts: 2
  };
}
function isBridgeConfigured() {
  const config = getBridgeConfig();
  return !!config.baseUrl && config.baseUrl.startsWith("http");
}
async function callSpicyTIP(procedure, input = {}, method = "GET") {
  const config = getBridgeConfig();
  if (!config.baseUrl) {
    console.warn("[SpicyTIP Bridge] Not configured \u2014 SPICY_TIP_BASE_URL is empty");
    return null;
  }
  const headers = {
    "Content-Type": "application/json"
  };
  if (config.apiKey) {
    headers["Authorization"] = `Bearer ${config.apiKey}`;
  }
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.timeout || 3e4);
  let lastError = null;
  const maxAttempts = (config.retryAttempts || 2) + 1;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      let url;
      let fetchOpts;
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
          signal: controller.signal
        };
      }
      const res = await fetch(url, fetchOpts);
      clearTimeout(timeoutId);
      if (!res.ok) {
        const errText = await res.text().catch(() => "");
        throw new Error(`HTTP ${res.status}: ${errText.slice(0, 200)}`);
      }
      const json = await res.json();
      if (json.error) {
        throw new Error(`tRPC error: ${json.error.message}`);
      }
      return json.result?.data ?? null;
    } catch (err) {
      lastError = err;
      if (attempt < maxAttempts) {
        console.warn(
          `[SpicyTIP Bridge] ${procedure} attempt ${attempt} failed: ${err.message}. Retrying...`
        );
        await new Promise((r) => setTimeout(r, 1e3 * attempt));
      }
    }
  }
  clearTimeout(timeoutId);
  console.error(`[SpicyTIP Bridge] ${procedure} failed after ${maxAttempts} attempts:`, lastError?.message);
  return null;
}
async function checkBridgeHealth() {
  const config = getBridgeConfig();
  const configured = isBridgeConfigured();
  if (!configured) {
    return { configured: false, reachable: false, baseUrl: "" };
  }
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5e3);
    const res = await fetch(`${config.baseUrl}/api/trpc`, {
      method: "GET",
      signal: controller.signal
    });
    clearTimeout(timeout);
    return { configured: true, reachable: res.status < 500, baseUrl: config.baseUrl };
  } catch {
    return { configured: true, reachable: false, baseUrl: config.baseUrl };
  }
}
async function getRansomwareVictimStats(limit) {
  return callSpicyTIP(
    "darkWebIntel.getRansomwareVictimStats",
    { limit: limit || 50 }
  );
}
async function getThreatFoxIOCs(opts) {
  return callSpicyTIP("darkWebIntel.getThreatFoxIOCs", {
    limit: opts?.limit || 100,
    type: opts?.type
  });
}
async function getActivityRatings() {
  return callSpicyTIP("enrichment.getActivityRatings");
}
async function getVictimGroupStats() {
  return callSpicyTIP("enrichment.getVictimGroupStats");
}
async function getGlobalThreatActors(limit) {
  return callSpicyTIP("darkWebIntel.getGlobalThreatActors", { limit: limit || 100 });
}
async function getCISAKEV(limit) {
  return callSpicyTIP("enrichment.getCISAKEV", { limit: limit || 50 });
}
async function getRecentVictimEvents(limit) {
  return callSpicyTIP("darkWebIntel.getRecentVictimEvents", {
    limit: limit || 50
  });
}
async function getOTXPulses(limit) {
  return callSpicyTIP("darkWebIntel.getOTXPulses", { limit: limit || 25 });
}
async function getMalwareBazaarEntries(limit) {
  return callSpicyTIP("darkWebIntel.getMalwareBazaar", {
    limit: limit || 50
  });
}
async function getAdaptiveKeywords() {
  return callSpicyTIP("darkWebIntel.getAdaptiveKeywords");
}
async function getEscalationAlerts(opts) {
  return callSpicyTIP("darkWebIntel.getEscalationAlerts", {
    severity: opts?.severity,
    limit: opts?.limit || 25
  });
}
async function corroborateAssets(assets) {
  return callSpicyTIP("enrichment.corroborateAssets", { assets }, "POST");
}
async function syncDarkwebIntelligence() {
  if (!isBridgeConfigured()) {
    return { actorsImported: 0, iocsImported: 0, eventsImported: 0, ratingsUpdated: 0, errors: ["Bridge not configured"] };
  }
  const errors = [];
  let actorsImported = 0;
  let iocsImported = 0;
  let eventsImported = 0;
  let ratingsUpdated = 0;
  try {
    const ratings = await getActivityRatings();
    if (ratings) {
      ratingsUpdated = ratings.length;
    }
  } catch (e) {
    errors.push(`Activity ratings: ${e.message}`);
  }
  try {
    const actors = await getGlobalThreatActors(200);
    if (actors) {
      actorsImported = actors.length;
    }
  } catch (e) {
    errors.push(`Threat actors: ${e.message}`);
  }
  try {
    const iocs = await getThreatFoxIOCs({ limit: 200 });
    if (iocs) {
      iocsImported = iocs.length;
    }
  } catch (e) {
    errors.push(`ThreatFox IOCs: ${e.message}`);
  }
  try {
    const events = await getRecentVictimEvents(100);
    if (events) {
      eventsImported = events.length;
    }
  } catch (e) {
    errors.push(`Victim events: ${e.message}`);
  }
  return { actorsImported, iocsImported, eventsImported, ratingsUpdated, errors };
}
var init_spicy_tip_bridge = __esm({
  "server/lib/spicy-tip-bridge.ts"() {
  }
});

export {
  getBridgeConfig,
  isBridgeConfigured,
  checkBridgeHealth,
  getRansomwareVictimStats,
  getThreatFoxIOCs,
  getActivityRatings,
  getVictimGroupStats,
  getGlobalThreatActors,
  getCISAKEV,
  getRecentVictimEvents,
  getOTXPulses,
  getMalwareBazaarEntries,
  getAdaptiveKeywords,
  getEscalationAlerts,
  corroborateAssets,
  syncDarkwebIntelligence,
  init_spicy_tip_bridge
};
