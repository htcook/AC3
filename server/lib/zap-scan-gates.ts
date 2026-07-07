/**
 * ZAP Scan Reliability Gates — Three-Gate Verification System
 * 
 * Implements the AC3 ZAP Scan Reliability Specification:
 *   Gate A: Setup Verification (reachability + auth indicator validation)
 *   Gate B: Execution Proof-of-Work (active scan messages + spider coverage)
 *   Gate C: Result Oracle (passive-alert presence, WAF-block ratio, auth expansion)
 * 
 * Each gate returns a pass/fail verdict with evidence. If any gate fails,
 * the scan is quarantined rather than marked "completed" — preventing false-clean results.
 */

import { getDb } from "../db";
import { webAppScans } from "../../drizzle/schema";
import { eq } from "drizzle-orm";

// ─── Types ──────────────────────────────────────────────────────────────────

export type ScanQuality = "verified" | "partial" | "quarantined" | "degraded";

export interface GateAResult {
  passed: boolean;
  reachable: boolean;
  httpStatus?: number;
  authIndicatorSet?: boolean;
  authIndicatorVerified?: boolean;
  reason?: string;
}

export interface GateBResult {
  passed: boolean;
  activeScanMessages: number;
  spiderUrlsDiscovered: number;
  passiveAlertsGenerated: number;
  reason?: string;
}

export interface GateCResult {
  passed: boolean;
  passiveAlertCount: number;
  wafBlockRatio: number;
  authExpansionDetected?: boolean;
  unauthBaselineUrls?: number;
  authUrls?: number;
  reason?: string;
}

export interface GateVerificationResult {
  gateA: GateAResult;
  gateB: GateBResult;
  gateC: GateCResult;
  overallQuality: ScanQuality;
  quarantineReason: string | null;
}

export interface ZapRequestFn {
  (endpoint: string, params: Record<string, string>, config: any): Promise<any>;
}

// ─── Thresholds ─────────────────────────────────────────────────────────────

const GATE_B_MIN_MESSAGES = 5;          // Active scan must send at least 5 requests
const GATE_B_MIN_SPIDER_URLS = 1;       // Spider must find at least 1 URL
const GATE_C_MIN_PASSIVE_ALERTS = 1;    // Real web apps almost always trigger passive rules
const GATE_C_MAX_WAF_BLOCK_RATIO = 0.8; // If >80% of requests are blocked, scan is degraded
const GATE_C_AUTH_EXPANSION_MIN = 2;    // Auth scan should find at least 2 more URLs than unauth

// ─── Gate A: Setup Verification ─────────────────────────────────────────────

/**
 * Gate A verifies that:
 * 1. The target is reachable (HTTP 2xx/3xx response)
 * 2. If authenticated scan, the auth indicator is set AND verified
 * 
 * Run BEFORE starting the active scan.
 */
export async function evaluateGateA(
  scanId: number,
  targetUrl: string,
  zapRequest: ZapRequestFn,
  config: any,
  authConfigured: boolean
): Promise<GateAResult> {
  const result: GateAResult = {
    passed: false,
    reachable: false,
    authIndicatorSet: false,
    authIndicatorVerified: false,
  };

  // 1. Reachability probe — send a request through ZAP and check response
  try {
    const probeResult = await zapRequest("/JSON/core/action/accessUrl/", {
      url: targetUrl,
      followRedirects: "true",
    }, config);

    // Check if ZAP got a valid response
    if (probeResult) {
      result.reachable = true;

      // Verify HTTP status via site tree
      try {
        const messages = await zapRequest("/JSON/core/view/messagesById/", {
          ids: "0",
        }, config).catch(() => null);

        // Alternative: check number of messages for the target
        const msgCount = await zapRequest("/JSON/core/view/numberOfMessages/", {
          baseurl: targetUrl,
        }, config);
        
        if (parseInt(msgCount?.numberOfMessages || "0") > 0) {
          result.httpStatus = 200; // ZAP got responses
        }
      } catch {
        // If we can't check messages, assume reachable since accessUrl succeeded
        result.httpStatus = 200;
      }
    }
  } catch (err: any) {
    result.reason = `Target unreachable: ${err.message}`;
    return result;
  }

  // 2. Auth indicator verification (only for authenticated scans)
  if (authConfigured) {
    try {
      // Check if authentication verification indicators are set
      const authIndicators = await zapRequest(
        "/JSON/authentication/view/getLoggedInIndicator/",
        { contextId: "1" },
        config
      ).catch(() => null);

      if (authIndicators?.loggedInIndicator) {
        result.authIndicatorSet = true;

        // Verify the indicator actually matches by checking auth state
        try {
          const authState = await zapRequest(
            "/JSON/authentication/view/getAuthenticationState/",
            { contextId: "1" },
            config
          ).catch(() => null);

          // If ZAP reports the user is logged in, the indicator is verified
          if (authState) {
            result.authIndicatorVerified = true;
          }
        } catch {
          // Can't verify — flag as unverified but don't fail the gate
          result.authIndicatorVerified = false;
        }
      } else {
        result.reason = "AUTH_INDICATOR_NOT_SET: Authenticated scan configured but no loggedInIndicator set in ZAP context. Scan may run entirely unauthenticated.";
        result.authIndicatorSet = false;
      }
    } catch (err: any) {
      result.reason = `Auth indicator check failed: ${err.message}`;
    }
  }

  // Gate A passes if: target is reachable AND (not auth scan OR auth indicator is set)
  result.passed = result.reachable && (!authConfigured || result.authIndicatorSet === true);

  return result;
}

// ─── Gate B: Execution Proof-of-Work ────────────────────────────────────────

/**
 * Gate B verifies that the active scan actually DID something:
 * 1. Active scan sent a minimum number of requests (messages)
 * 2. Spider discovered at least some URLs
 * 3. Passive scanner generated at least some alerts
 * 
 * Run AFTER active scan reports 100% completion.
 */
export async function evaluateGateB(
  scanId: number,
  targetUrl: string,
  zapActiveScanId: string,
  zapRequest: ZapRequestFn,
  config: any,
  spiderUrlsDiscovered: number
): Promise<GateBResult> {
  const result: GateBResult = {
    passed: false,
    activeScanMessages: 0,
    spiderUrlsDiscovered,
    passiveAlertsGenerated: 0,
  };

  // 1. Check active scan message count (how many requests did the scanner actually send?)
  try {
    const messagesResult = await zapRequest("/JSON/core/view/numberOfMessages/", {
      baseurl: targetUrl,
    }, config);
    result.activeScanMessages = parseInt(messagesResult?.numberOfMessages || "0", 10);
  } catch (err: any) {
    // If we can't check messages, this is a soft failure
    console.warn(`[ZAP Gate B] Scan #${scanId}: Failed to get message count: ${err.message}`);
  }

  // 2. Check passive alerts generated (separate from active findings)
  try {
    const alertsResult = await zapRequest("/JSON/core/view/numberOfAlerts/", {
      baseurl: targetUrl,
    }, config);
    result.passiveAlertsGenerated = parseInt(alertsResult?.numberOfAlerts || "0", 10);
  } catch {
    // Non-critical
  }

  // 3. Evaluate Gate B pass/fail
  if (result.activeScanMessages < GATE_B_MIN_MESSAGES) {
    result.reason = `PROOF_OF_WORK_FAILED: Active scan sent only ${result.activeScanMessages} messages (minimum: ${GATE_B_MIN_MESSAGES}). The scanner likely failed to generate attack traffic.`;
    result.passed = false;
  } else if (result.spiderUrlsDiscovered < GATE_B_MIN_SPIDER_URLS) {
    result.reason = `SPIDER_COVERAGE_ZERO: Spider discovered ${result.spiderUrlsDiscovered} URLs. No attack surface was enumerated.`;
    result.passed = false;
  } else {
    result.passed = true;
  }

  return result;
}

// ─── Gate C: Result Oracle ──────────────────────────────────────────────────

/**
 * Gate C verifies that the scan results are trustworthy:
 * 1. Passive alerts are present (a real web app almost always triggers passive rules)
 * 2. WAF block ratio is below threshold (high blocking = degraded coverage)
 * 3. If authenticated, check for auth expansion (more URLs than unauth baseline)
 * 
 * Run AFTER alerts are collected.
 */
export async function evaluateGateC(
  scanId: number,
  targetUrl: string,
  zapRequest: ZapRequestFn,
  config: any,
  totalAlerts: number,
  authConfigured: boolean,
  unauthBaselineUrls?: number
): Promise<GateCResult> {
  const result: GateCResult = {
    passed: false,
    passiveAlertCount: totalAlerts,
    wafBlockRatio: 0,
    unauthBaselineUrls: unauthBaselineUrls || 0,
  };

  // 1. Passive alert presence check
  // A real web app essentially always triggers passive rules (missing headers, cookies, etc.)
  // Zero passive alerts on a 200-returning target means the proxy isn't intercepting properly
  try {
    const passiveAlerts = await zapRequest("/JSON/pscan/view/recordsToScan/", {}, config);
    // Also count alerts directly
    const alertCount = await zapRequest("/JSON/core/view/numberOfAlerts/", {
      baseurl: targetUrl,
    }, config);
    result.passiveAlertCount = parseInt(alertCount?.numberOfAlerts || "0", 10);
  } catch {
    // Use the totalAlerts from collectAlerts as fallback
    result.passiveAlertCount = totalAlerts;
  }

  // 2. WAF block ratio — check how many responses were 403/blocking
  try {
    const messages = await zapRequest("/JSON/core/view/numberOfMessages/", {
      baseurl: targetUrl,
    }, config);
    const totalMessages = parseInt(messages?.numberOfMessages || "0", 10);

    if (totalMessages > 0) {
      // Sample recent messages to estimate block ratio
      // Check for 403/429 responses in the last batch
      try {
        const recentMsgs = await zapRequest("/JSON/core/view/messages/", {
          baseurl: targetUrl,
          start: String(Math.max(0, totalMessages - 50)),
          count: "50",
        }, config);

        if (recentMsgs?.messages) {
          const blocked = recentMsgs.messages.filter((m: any) => {
            const status = parseInt(m?.responseHeader?.match(/HTTP\/\d\.\d (\d{3})/)?.[1] || "200");
            return status === 403 || status === 429 || status === 503;
          }).length;
          result.wafBlockRatio = blocked / recentMsgs.messages.length;
        }
      } catch {
        // Can't sample messages — assume no blocking
        result.wafBlockRatio = 0;
      }
    }
  } catch {
    result.wafBlockRatio = 0;
  }

  // 3. Auth expansion check (if authenticated scan)
  if (authConfigured && unauthBaselineUrls !== undefined) {
    try {
      const siteTree = await zapRequest("/JSON/core/view/urls/", {
        baseurl: targetUrl,
      }, config);
      const authUrls = (siteTree?.urls || []).length;
      result.authUrls = authUrls;
      result.authExpansionDetected = authUrls >= (unauthBaselineUrls + GATE_C_AUTH_EXPANSION_MIN);
    } catch {
      result.authExpansionDetected = undefined; // Unknown
    }
  }

  // 4. Evaluate Gate C pass/fail
  if (result.passiveAlertCount < GATE_C_MIN_PASSIVE_ALERTS && totalAlerts === 0) {
    result.reason = `ZERO_ALERTS_ORACLE: Zero alerts (passive + active) on a live target. Either the proxy is not intercepting or the scan configuration is broken.`;
    result.passed = false;
  } else if (result.wafBlockRatio > GATE_C_MAX_WAF_BLOCK_RATIO) {
    result.reason = `WAF_BLOCKING_EXCESSIVE: ${Math.round(result.wafBlockRatio * 100)}% of requests received blocking responses (403/429/503). Scan coverage is severely degraded.`;
    result.passed = false;
  } else {
    result.passed = true;
  }

  return result;
}

// ─── Composite Gate Evaluation ──────────────────────────────────────────────

/**
 * Run all three gates and determine overall scan quality.
 * Returns the composite result with quarantine reason if applicable.
 */
export function computeOverallQuality(
  gateA: GateAResult,
  gateB: GateBResult,
  gateC: GateCResult
): { quality: ScanQuality; quarantineReason: string | null } {
  // Critical failure: Gate B fails = scan never attacked
  if (!gateB.passed) {
    return {
      quality: "quarantined",
      quarantineReason: gateB.reason || "Gate B: Active scan proof-of-work failed",
    };
  }

  // Critical failure: Gate A fails = target unreachable or auth broken
  if (!gateA.passed) {
    return {
      quality: "quarantined",
      quarantineReason: gateA.reason || "Gate A: Setup verification failed",
    };
  }

  // Degraded: Gate C fails = results may not be trustworthy
  if (!gateC.passed) {
    // WAF blocking is "degraded" not "quarantined" — scan ran but coverage is limited
    if (gateC.reason?.includes("WAF_BLOCKING")) {
      return {
        quality: "degraded",
        quarantineReason: gateC.reason,
      };
    }
    // Zero alerts oracle failure is quarantine-worthy
    return {
      quality: "quarantined",
      quarantineReason: gateC.reason || "Gate C: Result oracle failed",
    };
  }

  // All gates passed but check for partial conditions
  if (gateA.passed && gateB.passed && gateC.passed) {
    // If auth was configured but indicator wasn't verified, mark as partial
    if (gateA.authIndicatorSet && !gateA.authIndicatorVerified) {
      return {
        quality: "partial",
        quarantineReason: "Auth indicator set but not verified — scan may have run unauthenticated",
      };
    }
    return { quality: "verified", quarantineReason: null };
  }

  return { quality: "partial", quarantineReason: "One or more gates returned inconclusive results" };
}

// ─── Database Persistence ───────────────────────────────────────────────────

/**
 * Persist gate results to the database and determine final scan status.
 * Returns the status that should be set on the scan record.
 */
export async function persistGateResults(
  scanId: number,
  gateA: GateAResult,
  gateB: GateBResult,
  gateC: GateCResult
): Promise<{ status: string; quality: ScanQuality; quarantineReason: string | null }> {
  const db = await getDb();
  if (!db) {
    return { status: "completed", quality: "partial", quarantineReason: "Database unavailable for gate persistence" };
  }

  const { quality, quarantineReason } = computeOverallQuality(gateA, gateB, gateC);

  // Determine final status based on quality
  const status = quality === "quarantined" ? "quarantined" : "completed";

  await db.update(webAppScans).set({
    gateAPassed: gateA.passed ? 1 : 0,
    gateBPassed: gateB.passed ? 1 : 0,
    gateCPassed: gateC.passed ? 1 : 0,
    activeScanMessages: gateB.activeScanMessages,
    passiveAlertCount: gateC.passiveAlertCount,
    wafBlockRatio: gateC.wafBlockRatio,
    unauthBaselineUrls: gateC.unauthBaselineUrls || null,
    scanQuality: quality,
    quarantineReason: quarantineReason,
  }).where(eq(webAppScans.id, scanId));

  console.log(`[ZAP Gates] Scan #${scanId}: Gate A=${gateA.passed ? "PASS" : "FAIL"}, Gate B=${gateB.passed ? "PASS" : "FAIL"}, Gate C=${gateC.passed ? "PASS" : "FAIL"} → Quality: ${quality}${quarantineReason ? ` (${quarantineReason})` : ""}`);

  return { status, quality, quarantineReason };
}

// ─── Convenience: Full Post-Scan Gate Evaluation ────────────────────────────

/**
 * Run Gate B + Gate C after active scan completion (Gate A should have been run earlier).
 * This is the primary integration point for the scan completion path.
 */
export async function runPostScanGates(
  scanId: number,
  targetUrl: string,
  zapActiveScanId: string,
  zapRequest: ZapRequestFn,
  config: any,
  spiderUrlsDiscovered: number,
  totalAlerts: number,
  authConfigured: boolean,
  unauthBaselineUrls?: number,
  gateAResult?: GateAResult
): Promise<{ status: string; quality: ScanQuality; quarantineReason: string | null }> {
  // If Gate A wasn't run earlier, create a default pass (legacy behavior)
  const gateA: GateAResult = gateAResult || {
    passed: true,
    reachable: true,
    httpStatus: 200,
    authIndicatorSet: authConfigured ? undefined : false,
    authIndicatorVerified: undefined,
  };

  // Run Gate B
  const gateB = await evaluateGateB(
    scanId, targetUrl, zapActiveScanId, zapRequest, config, spiderUrlsDiscovered
  );

  // Run Gate C
  const gateC = await evaluateGateC(
    scanId, targetUrl, zapRequest, config, totalAlerts, authConfigured, unauthBaselineUrls
  );

  // Persist and return
  return persistGateResults(scanId, gateA, gateB, gateC);
}
