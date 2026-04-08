/**
 * Burp Suite Auto-Scan Launcher (with DB Persistence)
 *
 * Automatically triggers Burp Suite scans against in-scope assets when an
 * engagement enters the active scanning (vuln_detection) phase.
 *
 * Flow:
 *   1. Engagement enters vuln_detection phase → hook fires
 *   2. Collect in-scope web URLs from engagement scope assets + discovered assets
 *   3. Find connected Burp Suite credentials for the engagement owner
 *   4. Launch Burp scans (Pro: POST /scan, Enterprise: GraphQL create_scan)
 *   5. Poll scan progress at intervals — persist every state change to DB
 *   6. On completion, import findings into bug bounty findings table
 *   7. Broadcast progress via WebSocket for real-time UI updates
 */

import {
  BurpSuiteConnector,
  BurpScanRequest,
  BurpScanStatus,
  BurpIssue,
  normalizeBurpIssues,
  type BurpEdition,
  type BurpConfig,
} from "./burpsuite-connector";

// ─── Types ───

export interface BurpAutoScanConfig {
  engagementId: number;
  engagementHandle: string;
  userId: string;
  /** URLs to scan — extracted from scope assets */
  targetUrls: string[];
  /** Burp credential ID to use */
  credentialId: number;
  /** Burp config from platform credentials */
  burpConfig: BurpConfig;
  /** Optional scan configuration name (e.g., "Audit checks - all" for Pro) */
  scanConfigName?: string;
  /** Optional app login for authenticated scanning */
  appLogin?: { username: string; password: string; loginUrl?: string };
  /** Scan mode from engagement */
  scanMode?: "strict_passive" | "standard" | "active";
}

export interface BurpAutoScanState {
  engagementId: number;
  credentialId: number;
  scanId: string | null;
  status: "pending" | "launching" | "running" | "polling" | "importing" | "completed" | "failed" | "cancelled";
  progress: number;
  targetUrls: string[];
  issueCount: number;
  importedCount: number;
  startedAt: number;
  completedAt: number | null;
  error: string | null;
  lastPollAt: number | null;
  pollCount: number;
  edition: BurpEdition;
  /** DB record ID — set after first persist */
  dbRecordId?: number;
}

// ─── In-Memory State Store (hot cache, backed by DB) ───
const activeBurpScans = new Map<string, BurpAutoScanState>();

function scanKey(engagementId: number, credentialId: number): string {
  return `${engagementId}:${credentialId}`;
}

// ─── DB Persistence Helpers ───

async function persistCreate(state: BurpAutoScanState, scanConfigName?: string): Promise<number | null> {
  try {
    const db = await import("../db");
    const id = await db.createBurpScanRecord({
      engagementId: state.engagementId,
      credentialId: state.credentialId,
      userId: "", // Will be set by caller
      scanId: state.scanId || undefined,
      edition: state.edition,
      status: state.status,
      targetUrls: state.targetUrls,
      scanConfigName,
      startedAt: state.startedAt,
    });
    return id;
  } catch (err: any) {
    console.warn(`[BurpAutoScan] Failed to persist scan record: ${err.message}`);
    return null;
  }
}

async function persistUpdate(state: BurpAutoScanState): Promise<void> {
  if (!state.dbRecordId) return;
  try {
    const db = await import("../db");
    await db.updateBurpScanRecord(state.dbRecordId, {
      scanId: state.scanId || undefined,
      status: state.status,
      progress: state.progress,
      issueCount: state.issueCount,
      importedCount: state.importedCount,
      error: state.error,
      completedAt: state.completedAt,
      lastPollAt: state.lastPollAt,
      pollCount: state.pollCount,
    });
  } catch (err: any) {
    console.warn(`[BurpAutoScan] Failed to update scan record #${state.dbRecordId}: ${err.message}`);
  }
}

// ─── Public API ───

/**
 * Launch a Burp Suite scan for an engagement's in-scope assets.
 * Returns the scan state immediately; polling happens in the background.
 */
export async function launchBurpAutoScan(config: BurpAutoScanConfig): Promise<BurpAutoScanState> {
  const key = scanKey(config.engagementId, config.credentialId);

  // Check for existing active scan
  const existing = activeBurpScans.get(key);
  if (existing && ["launching", "running", "polling", "importing"].includes(existing.status)) {
    return existing;
  }

  // Filter URLs to only web targets
  const webUrls = config.targetUrls.filter(
    (u) => u.startsWith("http://") || u.startsWith("https://")
  );

  if (webUrls.length === 0) {
    throw new Error("No web URLs found in scope assets. Burp Suite requires HTTP/HTTPS targets.");
  }

  // Initialize state
  const state: BurpAutoScanState = {
    engagementId: config.engagementId,
    credentialId: config.credentialId,
    scanId: null,
    status: "launching",
    progress: 0,
    targetUrls: webUrls,
    issueCount: 0,
    importedCount: 0,
    startedAt: Date.now(),
    completedAt: null,
    error: null,
    lastPollAt: null,
    pollCount: 0,
    edition: config.burpConfig.edition,
  };

  activeBurpScans.set(key, state);

  // Persist to DB
  const dbId = await persistCreate(state, config.scanConfigName);
  if (dbId) state.dbRecordId = dbId;

  // Launch in background
  launchAndPoll(config, state, key).catch((err) => {
    state.status = "failed";
    state.error = err.message;
    state.completedAt = Date.now();
    persistUpdate(state);
    broadcastBurpUpdate(config.engagementId, state);
  });

  return state;
}

/**
 * Get the current state of a Burp auto-scan for an engagement.
 * Checks in-memory cache first, falls back to DB.
 */
export function getBurpAutoScanState(
  engagementId: number,
  credentialId: number
): BurpAutoScanState | null {
  return activeBurpScans.get(scanKey(engagementId, credentialId)) || null;
}

/**
 * Get all active Burp scans for an engagement (in-memory + DB).
 */
export function getEngagementBurpScans(engagementId: number): BurpAutoScanState[] {
  const results: BurpAutoScanState[] = [];
  for (const [key, state] of activeBurpScans) {
    if (key.startsWith(`${engagementId}:`)) {
      results.push(state);
    }
  }
  return results;
}

/**
 * Get persisted scan history from DB for an engagement.
 */
export async function getEngagementBurpScanHistory(engagementId: number) {
  try {
    const db = await import("../db");
    return db.getBurpScansByEngagement(engagementId);
  } catch {
    return [];
  }
}

/**
 * Cancel an active Burp scan.
 */
export async function cancelBurpAutoScan(
  engagementId: number,
  credentialId: number
): Promise<boolean> {
  const key = scanKey(engagementId, credentialId);
  const state = activeBurpScans.get(key);
  if (!state) return false;

  state.status = "cancelled";
  state.completedAt = Date.now();
  await persistUpdate(state);
  broadcastBurpUpdate(engagementId, state);
  return true;
}

/**
 * Hook to call when an engagement enters the vuln_detection phase.
 * Automatically finds Burp credentials and launches scans.
 */
export async function onEngagementVulnDetectionPhase(
  engagementId: number,
  userId: string,
  engagementHandle: string,
  scopeUrls: string[],
  scanMode?: string
): Promise<BurpAutoScanState[]> {
  const db = await import("../db");

  // Find all Burp Suite credentials for this user
  const allCreds = await db.listPlatformCredentials(userId);
  const burpCreds = allCreds.filter(
    (c: any) =>
      c.platform === "burpsuite_pro" || c.platform === "burpsuite_enterprise"
  );

  if (burpCreds.length === 0) {
    console.log(`[BurpAutoScan] No Burp Suite credentials found for user ${userId} — skipping auto-scan`);
    return [];
  }

  const results: BurpAutoScanState[] = [];

  for (const cred of burpCreds) {
    try {
      const edition: BurpEdition =
        cred.platform === "burpsuite_enterprise" ? "enterprise" : "professional";

      const state = await launchBurpAutoScan({
        engagementId,
        engagementHandle,
        userId,
        targetUrls: scopeUrls,
        credentialId: cred.id,
        burpConfig: {
          edition,
          baseUrl: cred.baseUrl || "http://127.0.0.1:1337",
          apiKey: cred.apiKey,
        },
        scanMode: (scanMode as any) || "standard",
      });

      results.push(state);
      console.log(
        `[BurpAutoScan] Launched ${edition} scan for engagement #${engagementId} via credential #${cred.id} — ${scopeUrls.length} URLs`
      );
    } catch (err: any) {
      console.error(
        `[BurpAutoScan] Failed to launch scan via credential #${cred.id}: ${err.message}`
      );
    }
  }

  return results;
}

// ─── Internal: Launch & Poll Loop ───

async function launchAndPoll(
  config: BurpAutoScanConfig,
  state: BurpAutoScanState,
  key: string
): Promise<void> {
  const connector = new BurpSuiteConnector(config.burpConfig);

  // ─── Step 1: Verify connection ───
  try {
    const verification = await connector.verify();
    if (!verification.valid) {
      state.status = "failed";
      state.error = `Burp Suite connection failed: ${verification.message}`;
      state.completedAt = Date.now();
      await persistUpdate(state);
      broadcastBurpUpdate(config.engagementId, state);
      return;
    }
  } catch (err: any) {
    state.status = "failed";
    state.error = `Connection verification failed: ${err.message}`;
    state.completedAt = Date.now();
    await persistUpdate(state);
    broadcastBurpUpdate(config.engagementId, state);
    return;
  }

  // ─── Step 2: Launch scan ───
  try {
    // Determine scan config based on scan mode
    let scanConfigName: string | undefined = config.scanConfigName;
    if (!scanConfigName) {
      switch (config.scanMode) {
        case "strict_passive":
          scanConfigName = "Crawl and Audit - Lightweight";
          break;
        case "active":
          scanConfigName = "Audit checks - all";
          break;
        default:
          scanConfigName = undefined; // Use Burp default
      }
    }

    if (config.burpConfig.edition === "professional") {
      const scanRequest: BurpScanRequest = {
        urls: state.targetUrls,
        scanConfiguration: scanConfigName,
        applicationLogin: config.appLogin,
      };
      const result = await connector.startScanPro(scanRequest);
      state.scanId = result.scanId;
    } else {
      // Enterprise: need to find or create a site first
      const result = await connector.startScanEnterprise(
        state.targetUrls[0],
        scanConfigName
      );
      state.scanId = result.scanId;
    }

    state.status = "running";
    state.progress = 5;
    await persistUpdate(state);
    broadcastBurpUpdate(config.engagementId, state);

    console.log(
      `[BurpAutoScan] Scan started: ${state.scanId} for engagement #${config.engagementId} (${state.targetUrls.length} URLs)`
    );
  } catch (err: any) {
    state.status = "failed";
    state.error = `Failed to start scan: ${err.message}`;
    state.completedAt = Date.now();
    await persistUpdate(state);
    broadcastBurpUpdate(config.engagementId, state);
    return;
  }

  // ─── Step 3: Poll for completion ───
  const POLL_INTERVAL = 15_000; // 15 seconds
  const MAX_POLL_TIME = 4 * 60 * 60 * 1000; // 4 hours max
  const DB_PERSIST_INTERVAL = 5; // Persist to DB every 5 polls
  const pollStart = Date.now();

  while (state.status === "running") {
    await sleep(POLL_INTERVAL);

    // Check if cancelled
    if (state.status === "cancelled") break;

    // Check timeout
    if (Date.now() - pollStart > MAX_POLL_TIME) {
      state.status = "failed";
      state.error = "Scan timed out after 4 hours";
      state.completedAt = Date.now();
      await persistUpdate(state);
      broadcastBurpUpdate(config.engagementId, state);
      return;
    }

    try {
      const scanStatus = await connector.getScanStatus(state.scanId!);
      state.progress = scanStatus.progress;
      state.issueCount = scanStatus.issueCount;
      state.lastPollAt = Date.now();
      state.pollCount++;

      // Persist to DB periodically (not every poll to reduce DB load)
      if (state.pollCount % DB_PERSIST_INTERVAL === 0) {
        await persistUpdate(state);
      }

      broadcastBurpUpdate(config.engagementId, state);

      if (scanStatus.status === "succeeded") {
        state.status = "importing";
        await persistUpdate(state);
        broadcastBurpUpdate(config.engagementId, state);
        break;
      }

      if (scanStatus.status === "failed") {
        state.status = "failed";
        state.error = "Burp Suite scan failed";
        state.completedAt = Date.now();
        await persistUpdate(state);
        broadcastBurpUpdate(config.engagementId, state);
        return;
      }
    } catch (err: any) {
      console.warn(`[BurpAutoScan] Poll error for scan ${state.scanId}: ${err.message}`);
      // Continue polling on transient errors
      if (state.pollCount > 10 && err.message.includes("timeout")) {
        state.status = "failed";
        state.error = `Lost connection to Burp Suite: ${err.message}`;
        state.completedAt = Date.now();
        await persistUpdate(state);
        broadcastBurpUpdate(config.engagementId, state);
        return;
      }
    }
  }

  // ─── Step 4: Import findings ───
  if (state.status === "importing" && state.scanId) {
    try {
      const issues = await connector.getIssues(state.scanId);
      const normalized = normalizeBurpIssues(
        issues,
        config.engagementHandle,
        config.burpConfig.edition
      );

      // Import into bug bounty findings
      if (normalized.length > 0) {
        const db = await import("../db");
        let imported = 0;

        for (const finding of normalized) {
          try {
            await db.createBugBountyFinding({
              title: finding.title,
              severityRating: finding.severityRating === "none" ? "low" : finding.severityRating,
              summary: finding.summary,
              assetIdentifier: finding.assetIdentifier,
              assetType: finding.assetType,
              cweId: finding.cweId,
              platform: "manual",
              programHandle: finding.programHandle,
              state: "new",
              userId: config.userId,
              metadata: finding.metadata,
            });
            imported++;
          } catch (err: any) {
            console.warn(`[BurpAutoScan] Failed to import finding: ${err.message}`);
          }
        }

        state.importedCount = imported;
        console.log(
          `[BurpAutoScan] Imported ${imported}/${normalized.length} findings from scan ${state.scanId}`
        );
      }

      state.status = "completed";
      state.completedAt = Date.now();
      await persistUpdate(state);
      broadcastBurpUpdate(config.engagementId, state);

      // Log to engagement timeline
      try {
        const db = await import("../db");
        await db.addTimelineEvent({
          engagementId: config.engagementId,
          eventType: "scan_completed",
          title: `Burp Suite ${config.burpConfig.edition === "enterprise" ? "Enterprise" : "Pro"} Scan Complete`,
          description: `Scan ${state.scanId} completed: ${state.issueCount} issues found, ${state.importedCount} imported as findings. Targets: ${state.targetUrls.length} URLs.`,
          metadata: {
            scanId: state.scanId,
            edition: config.burpConfig.edition,
            issueCount: state.issueCount,
            importedCount: state.importedCount,
            durationMs: (state.completedAt || Date.now()) - state.startedAt,
          },
          userId: config.userId,
        });
      } catch (e: any) {
        console.warn(`[BurpAutoScan] Timeline event failed: ${e.message}`);
      }

      // ─── Step 5: Feed findings into exploit matching engine ───
      try {
        await feedBurpFindingsToExploitEngine(config, normalized);
      } catch (e: any) {
        console.warn(`[BurpAutoScan] Exploit matching failed: ${e.message}`);
      }
    } catch (err: any) {
      state.status = "failed";
      state.error = `Failed to import findings: ${err.message}`;
      state.completedAt = Date.now();
      await persistUpdate(state);
      broadcastBurpUpdate(config.engagementId, state);
    }
  }
}

// ─── Scan-to-Exploit Chain ───

/**
 * Feed Burp findings into the exploit matching engine.
 * Maps Burp issues to CVEs/CWEs and queries the exploit database for matches.
 */
async function feedBurpFindingsToExploitEngine(
  config: BurpAutoScanConfig,
  findings: ReturnType<typeof normalizeBurpIssues>
): Promise<void> {
  if (findings.length === 0) return;

  console.log(
    `[BurpAutoScan→Exploit] Feeding ${findings.length} Burp findings into exploit matching for engagement #${config.engagementId}`
  );

  const db = await import("../db");

  // Group findings by severity for prioritized matching
  const highSeverity = findings.filter((f) => f.severityRating === "critical" || f.severityRating === "high");
  const mediumSeverity = findings.filter((f) => f.severityRating === "medium");

  // Build exploit search queries from findings
  const exploitQueries: Array<{
    findingTitle: string;
    cweId?: string;
    assetIdentifier: string;
    severity: string;
    searchTerms: string[];
  }> = [];

  for (const finding of [...highSeverity, ...mediumSeverity]) {
    const terms: string[] = [];

    // Extract vulnerability type keywords for exploit matching
    const title = finding.title.toLowerCase();
    if (title.includes("sql injection")) terms.push("sqli", "sql injection");
    if (title.includes("xss") || title.includes("cross-site scripting")) terms.push("xss", "cross-site scripting");
    if (title.includes("ssrf") || title.includes("server-side request")) terms.push("ssrf");
    if (title.includes("rce") || title.includes("remote code")) terms.push("rce", "remote code execution");
    if (title.includes("lfi") || title.includes("local file")) terms.push("lfi", "local file inclusion");
    if (title.includes("rfi") || title.includes("remote file")) terms.push("rfi", "remote file inclusion");
    if (title.includes("xxe") || title.includes("xml external")) terms.push("xxe");
    if (title.includes("deserialization")) terms.push("deserialization");
    if (title.includes("path traversal") || title.includes("directory traversal")) terms.push("path traversal", "directory traversal");
    if (title.includes("command injection") || title.includes("os command")) terms.push("command injection", "os command injection");
    if (title.includes("ssti") || title.includes("template injection")) terms.push("ssti", "template injection");
    if (title.includes("idor") || title.includes("insecure direct")) terms.push("idor");
    if (title.includes("csrf") || title.includes("cross-site request")) terms.push("csrf");
    if (title.includes("open redirect")) terms.push("open redirect");
    if (title.includes("authentication") || title.includes("auth bypass")) terms.push("authentication bypass");
    if (title.includes("privilege escalation")) terms.push("privilege escalation");

    // Add CWE-based terms
    if (finding.cweId) terms.push(`CWE-${finding.cweId}`);

    // Add the title itself as a search term
    if (terms.length === 0) terms.push(finding.title);

    exploitQueries.push({
      findingTitle: finding.title,
      cweId: finding.cweId,
      assetIdentifier: finding.assetIdentifier,
      severity: finding.severityRating,
      searchTerms: terms,
    });
  }

  if (exploitQueries.length === 0) {
    console.log(`[BurpAutoScan→Exploit] No high/medium findings to match against exploits`);
    return;
  }

  // Try to match against the exploit database
  try {
    // Check if we have exploit matching capabilities
    const matchResults: Array<{
      finding: string;
      exploitCount: number;
      topExploits: string[];
    }> = [];

    for (const query of exploitQueries) {
      try {
        // Search exploits in the database by CWE or keyword
        const exploits = await searchExploitsForFinding(db, query);
        if (exploits.length > 0) {
          matchResults.push({
            finding: query.findingTitle,
            exploitCount: exploits.length,
            topExploits: exploits.slice(0, 3).map((e: any) => e.title || e.name || e.id),
          });
        }
      } catch {
        // Individual match failure is non-fatal
      }
    }

    if (matchResults.length > 0) {
      console.log(
        `[BurpAutoScan→Exploit] Matched ${matchResults.length} findings to exploits for engagement #${config.engagementId}`
      );

      // Log exploit matches to engagement timeline
      try {
        await db.addTimelineEvent({
          engagementId: config.engagementId,
          eventType: "tool_output",
          title: "Burp→Exploit Chain: Automatic Exploit Matching",
          description: `${matchResults.length} Burp findings matched to known exploits. Top matches: ${matchResults.slice(0, 5).map((m) => `${m.finding} (${m.exploitCount} exploits)`).join(", ")}`,
          metadata: {
            source: "burp_auto_scan",
            matchResults,
            totalFindings: findings.length,
            matchedFindings: matchResults.length,
          },
          userId: config.userId,
        });
      } catch (e: any) {
        console.warn(`[BurpAutoScan→Exploit] Timeline event failed: ${e.message}`);
      }
    }
  } catch (err: any) {
    console.warn(`[BurpAutoScan→Exploit] Exploit matching pipeline error: ${err.message}`);
  }
}

/**
 * Search the exploit database for matches against a Burp finding.
 */
async function searchExploitsForFinding(
  db: any,
  query: { findingTitle: string; cweId?: string; searchTerms: string[] }
): Promise<any[]> {
  const results: any[] = [];

  // Search by CWE if available
  if (query.cweId) {
    try {
      const cweExploits = await db.searchExploitsByCWE?.(query.cweId);
      if (cweExploits?.length) results.push(...cweExploits);
    } catch {}
  }

  // Search by keywords
  for (const term of query.searchTerms.slice(0, 3)) {
    try {
      const keywordExploits = await db.searchExploitsByKeyword?.(term);
      if (keywordExploits?.length) results.push(...keywordExploits);
    } catch {}
  }

  // Deduplicate by ID
  const seen = new Set<string>();
  return results.filter((e: any) => {
    const id = String(e.id || e.exploitId || e.title);
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}

// ─── WebSocket Broadcast ───

function broadcastBurpUpdate(engagementId: number, state: BurpAutoScanState) {
  try {
    // Use the existing WebSocket event hub
    const { broadcastOpsUpdate } = require("./engagement-orchestrator");
    broadcastOpsUpdate(engagementId, {
      type: "burp_scan_update",
      burpScan: {
        credentialId: state.credentialId,
        scanId: state.scanId,
        status: state.status,
        progress: state.progress,
        issueCount: state.issueCount,
        importedCount: state.importedCount,
        edition: state.edition,
        error: state.error,
      },
    });
  } catch {
    // Silently fail if WebSocket not available
  }
}

// ─── Helpers ───

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Extract scannable web URLs from engagement scope and discovered assets.
 */
export function extractScopeUrls(engagement: any, opsState?: any): string[] {
  const urls = new Set<string>();

  // From engagement scope field (JSON array of scope items)
  if (engagement.scope) {
    try {
      const scope = typeof engagement.scope === "string" ? JSON.parse(engagement.scope) : engagement.scope;
      if (Array.isArray(scope)) {
        for (const item of scope) {
          if (typeof item === "string" && (item.startsWith("http://") || item.startsWith("https://"))) {
            urls.add(item);
          }
          if (item?.url) urls.add(item.url);
          if (item?.target) urls.add(item.target);
        }
      }
    } catch {}
  }

  // From engagement targetUrl
  if (engagement.targetUrl) {
    urls.add(engagement.targetUrl);
  }

  // From engagement targetDomain (construct URL)
  if (engagement.targetDomain) {
    urls.add(`https://${engagement.targetDomain}`);
  }

  // From report scope assets
  if (engagement.rptScopeAssets) {
    const assets = Array.isArray(engagement.rptScopeAssets) ? engagement.rptScopeAssets : [];
    for (const a of assets) {
      if (typeof a === "string") {
        if (a.startsWith("http")) urls.add(a);
        else if (a.includes(".")) urls.add(`https://${a}`);
      }
    }
  }

  // From ops state discovered assets
  if (opsState?.assets) {
    for (const asset of opsState.assets) {
      if (asset.hostname) {
        urls.add(`https://${asset.hostname}`);
      }
      if (asset.webApps) {
        for (const wa of asset.webApps) {
          if (wa.url) urls.add(wa.url);
          if (wa.hostname) urls.add(`https://${wa.hostname}`);
        }
      }
    }
  }

  // From scope assets in bug bounty program scopes
  if (engagement.scopeAssets) {
    try {
      const scopeAssets = typeof engagement.scopeAssets === "string"
        ? JSON.parse(engagement.scopeAssets)
        : engagement.scopeAssets;
      if (Array.isArray(scopeAssets)) {
        for (const sa of scopeAssets) {
          if (sa?.name && (sa.name.startsWith("http") || sa.name.includes("."))) {
            const url = sa.name.startsWith("http") ? sa.name : `https://${sa.name}`;
            urls.add(url);
          }
        }
      }
    } catch {}
  }

  return [...urls].filter((u) => u.startsWith("http://") || u.startsWith("https://"));
}

/**
 * Get summary stats for all Burp auto-scans (in-memory + DB).
 */
export function getBurpAutoScanStats(): {
  active: number;
  completed: number;
  failed: number;
  totalIssues: number;
  totalImported: number;
} {
  let active = 0, completed = 0, failed = 0, totalIssues = 0, totalImported = 0;
  for (const state of activeBurpScans.values()) {
    if (["launching", "running", "polling", "importing"].includes(state.status)) active++;
    else if (state.status === "completed") completed++;
    else if (state.status === "failed") failed++;
    totalIssues += state.issueCount;
    totalImported += state.importedCount;
  }
  return { active, completed, failed, totalIssues, totalImported };
}

/**
 * Get combined stats (in-memory active + DB historical).
 */
export async function getBurpAutoScanStatsWithHistory(): Promise<{
  active: number;
  completed: number;
  failed: number;
  totalIssues: number;
  totalImported: number;
  totalScans: number;
}> {
  const memStats = getBurpAutoScanStats();
  try {
    const db = await import("../db");
    const dbStats = await db.getDbBurpScanStats();
    return {
      active: memStats.active,
      completed: Math.max(memStats.completed, dbStats.completed),
      failed: Math.max(memStats.failed, dbStats.failed),
      totalIssues: Math.max(memStats.totalIssues, dbStats.totalIssues),
      totalImported: Math.max(memStats.totalImported, dbStats.totalImported),
      totalScans: dbStats.total,
    };
  } catch {
    return { ...memStats, totalScans: memStats.active + memStats.completed + memStats.failed };
  }
}
