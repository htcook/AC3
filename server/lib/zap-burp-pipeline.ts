/**
 * ZAP → Burp Cross-Tool Intelligence Pipeline
 *
 * Bridges ZAP spider/scan results into Burp Suite active scanning:
 *   1. Extract discovered URLs from completed ZAP spider scans
 *   2. Enrich with ZAP passive findings (tech stack, headers, cookies)
 *   3. Launch targeted Burp scans against ZAP-discovered attack surface
 *   4. Correlate findings between both tools (dedup + confidence boost)
 *   5. Log cross-tool events to engagement timeline
 *
 * The pipeline runs automatically when:
 *   - A ZAP scan completes in an engagement that also has Burp credentials
 *   - The engagement orchestrator enters vuln_detection phase
 *   - Manually triggered via the tRPC endpoint
 */

import { getDb } from "../db";
import {
  webAppScans,
  webAppFindings,
  engagementTimelineEvents,
  userPlatformCredentials,
} from "../../drizzle/schema";
import { eq, and, desc } from "drizzle-orm";
import {
  launchBurpAutoScan,
  extractScopeUrls,
  type BurpAutoScanConfig,
  type BurpAutoScanState,
} from "./burp-auto-scan";
import { captureToolCorrelation } from "./engagement-training-bridge";

// ─── Types ───

export interface ZapDiscoveredUrl {
  url: string;
  method: string;
  statusCode?: number;
  contentType?: string;
  /** Source: spider, ajax_spider, passive_scan, seed */
  source: "spider" | "ajax_spider" | "passive_scan" | "seed";
}

export interface ZapFingerprint {
  technologies: string[];
  headers: Record<string, string>;
  cookies: string[];
  forms: number;
  apiEndpoints: string[];
  loginPages: string[];
}

export interface CrossToolPipelineResult {
  zapScanId: number;
  zapUrlsDiscovered: number;
  urlsFedToBurp: number;
  /** Where the URLs came from: 'zap_scan' if extracted from ZAP findings, 'scope_fallback' if from engagement scope */
  urlSource: 'zap_scan' | 'scope_fallback' | 'override';
  burpScanLaunched: boolean;
  burpScanState?: BurpAutoScanState;
  fingerprint: ZapFingerprint;
  correlatedFindings: CorrelatedFinding[];
  error?: string;
}

export interface CorrelatedFinding {
  /** The vulnerability type/name */
  vulnType: string;
  /** ZAP finding ID (if found by ZAP) */
  zapFindingId?: number;
  /** Burp finding reference (if found by Burp) */
  burpFindingRef?: string;
  /** Which tool(s) found it */
  foundBy: ("zap" | "burp")[];
  /** Severity from the highest-confidence source */
  severity: string;
  /** Confidence boost when both tools agree */
  confidenceBoost: boolean;
  /** The affected URL */
  url: string;
  /** CWE ID if available */
  cweId?: string;
}

// ─── URL Extraction from ZAP Scans ───

/**
 * Extract all discovered URLs from a completed ZAP scan.
 * Pulls from both the web_app_findings table (which has URLs) and
 * the scan's target URL.
 */
export async function extractZapDiscoveredUrls(zapScanId: number): Promise<ZapDiscoveredUrl[]> {
  const db = await getDb();
  if (!db) return [];

  // Get the scan record
  const [scan] = await db.select().from(webAppScans).where(eq(webAppScans.id, zapScanId));
  if (!scan) return [];

  const urls: ZapDiscoveredUrl[] = [];
  const seen = new Set<string>();

  // Extract URLs from findings (these are confirmed reachable endpoints)
  const findings = await db.select().from(webAppFindings).where(eq(webAppFindings.scanId, zapScanId));

  for (const finding of findings) {
    // evidence is stored as text — parse it if JSON
    let evidenceObj: any = {};
    if (finding.evidence) {
      try { evidenceObj = JSON.parse(finding.evidence); } catch { /* plain text evidence */ }
    }

    const url = finding.url || evidenceObj?.url;
    if (url && !seen.has(url)) {
      seen.add(url);
      urls.push({
        url,
        method: finding.method || "GET",
        statusCode: evidenceObj?.statusCode,
        contentType: evidenceObj?.contentType,
        source: "passive_scan",
      });
    }

    // Also extract from evidence/request URLs
    if (evidenceObj?.requestUrl && !seen.has(evidenceObj.requestUrl)) {
      seen.add(evidenceObj.requestUrl);
      urls.push({
        url: evidenceObj.requestUrl,
        method: evidenceObj?.requestMethod || "GET",
        source: "passive_scan",
      });
    }
  }

  // Add the target URL itself
  if (scan.targetUrl && !seen.has(scan.targetUrl)) {
    seen.add(scan.targetUrl);
    urls.push({
      url: scan.targetUrl,
      method: "GET",
      source: "spider",
    });
  }

  return urls;
}

/**
 * Build a technology fingerprint from ZAP scan findings.
 * Extracts tech stack, headers, cookies, forms, and API endpoints.
 */
export function buildZapFingerprint(findings: any[], scanConfig?: any): ZapFingerprint {
  const technologies = new Set<string>();
  const headers: Record<string, string> = {};
  const cookies = new Set<string>();
  const apiEndpoints = new Set<string>();
  const loginPages = new Set<string>();
  let forms = 0;

  // Extract from LLM scan config
  if (scanConfig?.technologies) {
    for (const tech of scanConfig.technologies) {
      technologies.add(tech);
    }
  }

  for (const finding of findings) {
    const alertName = (finding.alertName || finding.alert || "").toLowerCase();
    const url = finding.url || "";

    // Technology detection from findings
    if (alertName.includes("x-powered-by")) {
      const tech = finding.description;
      if (tech) technologies.add(tech);
    }
    if (alertName.includes("server header")) {
      const server = finding.description;
      if (server) technologies.add(server);
    }

    // Cookie detection
    if (alertName.includes("cookie") || alertName.includes("set-cookie")) {
      if (finding.param) cookies.add(finding.param);
    }

    // API endpoint detection
    if (url.includes("/api/") || url.includes("/v1/") || url.includes("/v2/") ||
        url.includes("/graphql") || url.includes("/rest/")) {
      apiEndpoints.add(url);
    }

    // Login page detection
    if (url.includes("/login") || url.includes("/signin") || url.includes("/auth") ||
        alertName.includes("login") || alertName.includes("authentication")) {
      loginPages.add(url);
    }

    // Form detection
    if (alertName.includes("form") || alertName.includes("csrf")) {
      forms++;
    }
  }

  return {
    technologies: [...technologies],
    headers,
    cookies: [...cookies],
    forms,
    apiEndpoints: [...apiEndpoints],
    loginPages: [...loginPages],
  };
}

// ─── Cross-Tool Finding Correlation ───

/**
 * Normalize vulnerability key for cross-tool matching.
 * Maps different naming conventions to a common key.
 */
function normalizeVulnKey(vulnName: string, url: string): string {
  const name = vulnName.toLowerCase().trim();
  const urlPath = (() => {
    try { return new URL(url).pathname; } catch { return url; }
  })();

  const normalizations: Record<string, string> = {
    "sql injection": "sqli",
    "sql injection - mysql": "sqli",
    "sql injection - postgresql": "sqli",
    "sql injection - oracle": "sqli",
    "sql injection - sqlite": "sqli",
    "cross-site scripting": "xss",
    "cross-site scripting (reflected)": "xss_reflected",
    "cross-site scripting (stored)": "xss_stored",
    "cross-site scripting (dom-based)": "xss_dom",
    "reflected xss": "xss_reflected",
    "stored xss": "xss_stored",
    "dom-based xss": "xss_dom",
    "server-side request forgery": "ssrf",
    "ssrf": "ssrf",
    "os command injection": "cmdi",
    "command injection": "cmdi",
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "file path traversal": "path_traversal",
    "xml external entity": "xxe",
    "xxe": "xxe",
    "cross-site request forgery": "csrf",
    "csrf": "csrf",
    "open redirect": "open_redirect",
    "open redirection": "open_redirect",
    "insecure direct object reference": "idor",
    "idor": "idor",
    "server-side template injection": "ssti",
    "ssti": "ssti",
  };

  const normalized = normalizations[name] || name.replace(/[^a-z0-9]/g, "_");
  return `${normalized}:${urlPath}`;
}

/**
 * Correlate findings between ZAP and Burp scans for the same target.
 * Deduplicates, boosts confidence when both tools agree, and identifies
 * tool-specific findings.
 */
export async function correlateFindings(
  engagementId: number,
  zapScanId: number,
): Promise<CorrelatedFinding[]> {
  const db = await getDb();
  if (!db) return [];

  // Get ZAP findings
  const zapFindings = await db.select().from(webAppFindings)
    .where(eq(webAppFindings.scanId, zapScanId));

  // Get Burp findings from bug_bounty_findings for this engagement
  let burpFindings: any[] = [];
  try {
    const dbModule = await import("../db");
    const allFindings = await dbModule.getEngagementFindings(engagementId);
    burpFindings = (allFindings || []).filter((f: any) =>
      f.metadata?.source === "burp_auto_scan" || f.metadata?.scanner === "burp"
    );
  } catch {}

  const correlated: CorrelatedFinding[] = [];
  const zapByVuln = new Map<string, any>();
  const burpByVuln = new Map<string, any>();

  // Index ZAP findings by vulnerability type + URL
  for (const zf of zapFindings) {
    const key = normalizeVulnKey(zf.alertName || "", zf.url || "");
    zapByVuln.set(key, zf);
  }

  // Index Burp findings
  for (const bf of burpFindings) {
    const key = normalizeVulnKey(bf.title || "", bf.assetIdentifier || "");
    burpByVuln.set(key, bf);
  }

  // Find overlaps and unique findings
  const allKeys = new Set([...zapByVuln.keys(), ...burpByVuln.keys()]);

  for (const key of allKeys) {
    const zapF = zapByVuln.get(key);
    const burpF = burpByVuln.get(key);
    const foundBy: ("zap" | "burp")[] = [];
    if (zapF) foundBy.push("zap");
    if (burpF) foundBy.push("burp");

    correlated.push({
      vulnType: zapF?.alertName || burpF?.title || key,
      zapFindingId: zapF?.id,
      burpFindingRef: burpF?.id ? String(burpF.id) : undefined,
      foundBy,
      severity: zapF?.severity || burpF?.severityRating || "info",
      confidenceBoost: foundBy.length === 2,
      url: zapF?.url || burpF?.assetIdentifier || "",
      cweId: zapF?.cweId ? String(zapF.cweId) : burpF?.cweId,
    });
  }

  return correlated;
}

// ─── Main Pipeline ───

/**
 * Run the ZAP → Burp cross-tool pipeline for an engagement.
 *
 * Steps:
 *   1. Find the latest completed ZAP scan for the engagement's target
 *   2. Extract discovered URLs and build fingerprint
 *   3. Find Burp credentials for the engagement owner
 *   4. Launch a targeted Burp scan with ZAP-discovered URLs
 *   5. Correlate findings when Burp scan completes
 *   6. Log everything to the engagement timeline
 */
export async function runZapToBurpPipeline(params: {
  engagementId: number;
  userId: string;
  engagementHandle: string;
  /** Optional: specific ZAP scan ID to use. If not provided, uses the latest completed scan. */
  zapScanId?: number;
  /** Optional: Burp credential to use. If not provided, auto-discovers. */
  burpCredentialId?: number;
  /** Optional: override target URLs instead of extracting from ZAP */
  targetUrls?: string[];
}): Promise<CrossToolPipelineResult> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");

  console.log(`[ZAP→Burp Pipeline] Starting for engagement #${params.engagementId}`);

  // Step 1: Find the latest ZAP scan (completed OR running — running scans may already have findings)
  let zapScanId = params.zapScanId;
  let zapScanStatus: string | undefined;
  if (!zapScanId) {
    // First try completed scans, then fall back to running scans
    const dbModule = await import("../db");
    const engagement = await dbModule.getEngagementById(params.engagementId);
    if (!engagement) throw new Error(`Engagement #${params.engagementId} not found`);
    const targetDomain = engagement.targetDomain || "";

    for (const statusToCheck of ["completed", "running", "scanning", "active_scan", "spider", "starting"]) {
      const recentScans = await db.select()
        .from(webAppScans)
        .where(eq(webAppScans.status, statusToCheck))
        .orderBy(desc(webAppScans.completedAt))
        .limit(10);

      const matchingScan = recentScans.find(s =>
        s.targetUrl?.includes(targetDomain) ||
        s.scanName?.includes(String(params.engagementId))
      );

      if (matchingScan) {
        zapScanId = matchingScan.id;
        zapScanStatus = statusToCheck;
        break;
      }
    }
  }

  // Step 2: Extract URLs and build fingerprint
  let discoveredUrls: ZapDiscoveredUrl[] = [];
  let fingerprint: ZapFingerprint = {
    technologies: [], headers: {}, cookies: [], forms: 0,
    apiEndpoints: [], loginPages: [],
  };

  if (zapScanId) {
    discoveredUrls = await extractZapDiscoveredUrls(zapScanId);

    const findings = await db.select().from(webAppFindings)
      .where(eq(webAppFindings.scanId, zapScanId));
    const [scan] = await db.select().from(webAppScans)
      .where(eq(webAppScans.id, zapScanId));
    let scanConfig: any = null;
    if (scan?.llmScanConfig) {
      try { scanConfig = JSON.parse(scan.llmScanConfig); } catch {}
    }

    fingerprint = buildZapFingerprint(findings, scanConfig);

    console.log(`[ZAP→Burp Pipeline] ZAP scan #${zapScanId}: ${discoveredUrls.length} URLs, ${fingerprint.technologies.length} technologies, ${fingerprint.apiEndpoints.length} API endpoints`);
  }

  // Build target URL list for Burp
  let urlSource: 'zap_scan' | 'scope_fallback' | 'override' = 'zap_scan';
  const targetUrls = params.targetUrls
    ? (() => { urlSource = 'override'; return params.targetUrls!; })()
    : [...discoveredUrls.map(u => u.url)];

  // Deduplicate and normalize URLs
  const uniqueUrls = [...new Set(targetUrls)].filter(u =>
    u.startsWith("http://") || u.startsWith("https://")
  );

  if (uniqueUrls.length === 0) {
    // Fall back to engagement scope URLs
    urlSource = 'scope_fallback';
    const dbModule = await import("../db");
    const engagement = await dbModule.getEngagementById(params.engagementId);
    const opsState = await dbModule.loadOpsSnapshot(params.engagementId);
    const scopeUrls = extractScopeUrls(engagement, opsState?.stateJson);
    uniqueUrls.push(...scopeUrls);
    console.log(`[ZAP→Burp Pipeline] No ZAP-discovered URLs available (scan ${zapScanStatus || 'not found'}), falling back to ${scopeUrls.length} engagement scope URLs`);
  }

  if (uniqueUrls.length === 0) {
    return {
      zapScanId: zapScanId || 0,
      zapUrlsDiscovered: discoveredUrls.length,
      urlsFedToBurp: 0,
      urlSource: 'scope_fallback',
      burpScanLaunched: false,
      fingerprint,
      correlatedFindings: [],
      error: "No URLs available for Burp scanning",
    };
  }

  console.log(`[ZAP→Burp Pipeline] Feeding ${uniqueUrls.length} URLs to Burp (first 3: ${uniqueUrls.slice(0, 3).join(", ")})`);

  // Step 3: Find Burp credentials
  let burpCred: any = null;
  try {
    const numericUserId = parseInt(params.userId, 10);
    if (!isNaN(numericUserId)) {
      const creds = await db.select().from(userPlatformCredentials)
        .where(
          and(
            eq(userPlatformCredentials.userId, numericUserId),
            eq(userPlatformCredentials.isActive, 1),
          )
        );
      const burpCreds = creds.filter(c =>
        c.platform === "burpsuite_pro" || c.platform === "burpsuite_enterprise"
      );
      if (params.burpCredentialId) {
        burpCred = burpCreds.find(c => c.id === params.burpCredentialId);
      } else {
        burpCred = burpCreds[0]; // Use first available
      }
    }
  } catch {}

  if (!burpCred) {
    // ═══ ENV-VAR FALLBACK: Use scan server's headless Burp instance ═══
    const envScanHost = process.env.SCAN_SERVER_HOST;
    const envBurpApiKey = process.env.BURP_API_KEY || process.env.CALDERA_API_KEY;
    const envBurpBaseUrl = process.env.BURP_BASE_URL || (envScanHost ? `http://${envScanHost}:1337` : "");

    if (envBurpBaseUrl && envBurpApiKey) {
      console.log(`[ZAP→Burp Pipeline] No DB credentials — using env fallback: ${envBurpBaseUrl}`);
      burpCred = {
        id: -1,
        platform: "burpsuite_pro",
        baseUrl: envBurpBaseUrl,
        apiKeyEncrypted: envBurpApiKey,
      };
    } else {
    return {
      zapScanId: zapScanId || 0,
      zapUrlsDiscovered: discoveredUrls.length,
      urlsFedToBurp: uniqueUrls.length,
      urlSource,
      burpScanLaunched: false,
      fingerprint,
      correlatedFindings: [],
      error: "No Burp Suite credentials found and no env fallback available",
    };
    }
  }

  // Step 4: Launch Burp scan with ZAP-discovered URLs
  let burpScanState: BurpAutoScanState | undefined;
  try {
    // Build scan config name based on ZAP fingerprint
    const scanConfigName = fingerprint.apiEndpoints.length > 5
      ? "Audit checks - all"  // API-heavy target needs thorough audit
      : fingerprint.forms > 0
        ? "Crawl and Audit - Balanced" // Form-heavy target
        : undefined; // Use Burp default

    const edition = burpCred.platform === "burpsuite_enterprise" ? "enterprise" : "professional";
    const scanServerHost = process.env.SCAN_SERVER_HOST || "159.223.152.190";

    burpScanState = await launchBurpAutoScan({
      engagementId: params.engagementId,
      engagementHandle: params.engagementHandle,
      userId: params.userId,
      targetUrls: uniqueUrls,
      credentialId: burpCred.id,
      burpConfig: {
        edition,
        baseUrl: burpCred.baseUrl || `http://${scanServerHost}:1337`,
        apiKey: burpCred.apiKeyEncrypted || "",
      },
      scanConfigName,
      scanMode: "active",
    });

    console.log(`[ZAP→Burp Pipeline] Burp scan launched: status=${burpScanState.status}, ${uniqueUrls.length} URLs`);
  } catch (err: any) {
    console.error(`[ZAP→Burp Pipeline] Failed to launch Burp scan: ${err.message}`);
    return {
      zapScanId: zapScanId || 0,
      zapUrlsDiscovered: discoveredUrls.length,
      urlsFedToBurp: uniqueUrls.length,
      urlSource,
      burpScanLaunched: false,
      fingerprint,
      correlatedFindings: [],
      error: `Burp scan launch failed: ${err.message}`,
    };
  }

  // Step 5: Correlate findings (if ZAP scan exists)
  let correlatedFindings: CorrelatedFinding[] = [];
  if (zapScanId) {
    correlatedFindings = await correlateFindings(params.engagementId, zapScanId);

    // Track cross-tool correlation in training bridge
    for (const cf of correlatedFindings.filter(f => f.confidenceBoost)) {
      try {
        await captureToolCorrelation({
          engagementId: params.engagementId,
          primaryTool: "zap",
          secondaryTool: "burp",
          findingType: cf.vulnType,
          correlationType: "confirmed",
          primaryFindingId: cf.zapFindingId ? String(cf.zapFindingId) : undefined,
          secondaryFindingId: cf.burpFindingRef,
          detail: `${cf.vulnType} at ${cf.url} confirmed by both ZAP and Burp (severity: ${cf.severity})`,
        });
      } catch {}
    }
  }

  // Step 6: Log to engagement timeline
  try {
    await db.insert(engagementTimelineEvents).values({
      engagementId: params.engagementId,
      phase: "vulnerability_analysis",
      eventType: "tool_executed",
      severity: "info",
      title: "ZAP → Burp Cross-Tool Pipeline",
      description: [
        urlSource === 'zap_scan'
          ? `ZAP discovered ${discoveredUrls.length} URLs (scan #${zapScanId || "N/A"})`
          : `ZAP scan ${zapScanId ? `#${zapScanId} (${zapScanStatus || 'in progress'})` : 'not found'} — used ${uniqueUrls.length} engagement scope URLs as fallback`,
        `Fed ${uniqueUrls.length} unique URLs to Burp Suite (source: ${urlSource})`,
        `Technologies: ${fingerprint.technologies.slice(0, 5).join(", ") || "none detected"}`,
        `API endpoints: ${fingerprint.apiEndpoints.length}`,
        `Login pages: ${fingerprint.loginPages.length}`,
        correlatedFindings.length > 0
          ? `Cross-tool correlations: ${correlatedFindings.filter(f => f.confidenceBoost).length} confirmed by both tools`
          : "",
      ].filter(Boolean).join(". "),
      metadata: JSON.stringify({
        source: "zap_burp_pipeline",
        zapScanId,
        zapScanStatus,
        urlSource,
        zapUrlsDiscovered: discoveredUrls.length,
        urlsFedToBurp: uniqueUrls.length,
        technologies: fingerprint.technologies,
        apiEndpoints: fingerprint.apiEndpoints.length,
        loginPages: fingerprint.loginPages.length,
        correlatedCount: correlatedFindings.filter(f => f.confidenceBoost).length,
        burpScanStatus: burpScanState?.status,
      }),
      sourceModule: "zap-burp-pipeline",
      timestamp: Date.now(),
    });
  } catch (e: any) {
    console.warn(`[ZAP→Burp Pipeline] Timeline event failed: ${e.message}`);
  }

  return {
    zapScanId: zapScanId || 0,
    zapUrlsDiscovered: discoveredUrls.length,
    urlsFedToBurp: uniqueUrls.length,
    urlSource,
    burpScanLaunched: true,
    burpScanState,
    fingerprint,
    correlatedFindings,
  };
}

/**
 * Get cross-tool scan coverage summary for an engagement.
 * Shows which URLs were scanned by which tools.
 */
export async function getCrossToolCoverage(engagementId: number): Promise<{
  totalUrls: number;
  zapOnly: number;
  burpOnly: number;
  both: number;
  uncovered: number;
  urlDetails: Array<{
    url: string;
    scannedBy: ("zap" | "burp")[];
    findingCount: number;
  }>;
}> {
  const db = await getDb();
  if (!db) return { totalUrls: 0, zapOnly: 0, burpOnly: 0, both: 0, uncovered: 0, urlDetails: [] };

  // Get all ZAP findings URLs
  const zapFindings = await db.select({
    url: webAppFindings.url,
  }).from(webAppFindings);
  const zapUrls = new Set(zapFindings.map(f => f.url).filter(Boolean) as string[]);

  // Get Burp findings URLs
  let burpUrls = new Set<string>();
  try {
    const dbModule = await import("../db");
    const burpFindings = await dbModule.getEngagementFindings(engagementId);
    const burpFindingsList = (burpFindings || []).filter((f: any) =>
      f.metadata?.source === "burp_auto_scan" || f.metadata?.scanner === "burp"
    );
    burpUrls = new Set(burpFindingsList.map((f: any) => f.assetIdentifier).filter(Boolean));
  } catch {}

  // Get all scope URLs
  const dbModule = await import("../db");
  const engagement = await dbModule.getEngagementById(engagementId);
  const opsState = await dbModule.loadOpsSnapshot(engagementId);
  const scopeUrls = engagement ? extractScopeUrls(engagement, opsState?.stateJson) : [];

  const allUrls = new Set([...scopeUrls, ...zapUrls, ...burpUrls]);
  let zapOnly = 0, burpOnly = 0, both = 0, uncovered = 0;
  const urlDetails: Array<{ url: string; scannedBy: ("zap" | "burp")[]; findingCount: number }> = [];

  for (const url of allUrls) {
    const inZap = zapUrls.has(url);
    const inBurp = burpUrls.has(url);
    const scannedBy: ("zap" | "burp")[] = [];
    if (inZap) scannedBy.push("zap");
    if (inBurp) scannedBy.push("burp");

    if (inZap && inBurp) both++;
    else if (inZap) zapOnly++;
    else if (inBurp) burpOnly++;
    else uncovered++;

    urlDetails.push({ url, scannedBy, findingCount: scannedBy.length });
  }

  return {
    totalUrls: allUrls.size,
    zapOnly,
    burpOnly,
    both,
    uncovered,
    urlDetails: urlDetails.slice(0, 100), // Limit for API response size
  };
}

// ─── Severity Escalation Engine ───

/** Severity hierarchy from lowest to highest */
const SEVERITY_RANK: Record<string, number> = {
  info: 0, informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Escalation rules: how many levels to promote based on confirmation type */
const ESCALATION_RULES = {
  /** Both ZAP and Burp found the exact same vuln type at the same URL */
  crossToolConfirmed: { promote: 1, flagPriority: true },
  /** Same CWE confirmed by both tools at different URLs */
  cweCorroborated: { promote: 1, flagPriority: false },
  /** Same vuln type but different severity ratings between tools — use higher */
  severityDisagreement: { promote: 0, flagPriority: true },
} as const;

export interface EscalationResult {
  /** Finding identifier */
  findingId: string;
  /** Original severity before escalation */
  originalSeverity: string;
  /** New severity after escalation */
  escalatedSeverity: string;
  /** Whether severity was actually changed */
  wasEscalated: boolean;
  /** Whether flagged for priority exploitation */
  flaggedForExploit: boolean;
  /** Reason for escalation */
  reason: string;
  /** Which tools confirmed this finding */
  confirmedBy: ("zap" | "burp")[];
  /** The affected URL */
  url: string;
  /** CWE ID if available */
  cweId?: string;
  /** Estimated bounty value if applicable */
  estimatedBounty?: number;
}

export interface EscalationSummary {
  /** Total findings evaluated */
  totalEvaluated: number;
  /** Findings that were escalated */
  escalatedCount: number;
  /** Findings flagged for priority exploitation */
  priorityFlaggedCount: number;
  /** Breakdown by severity after escalation */
  severityBreakdown: Record<string, number>;
  /** Individual escalation results */
  results: EscalationResult[];
  /** Timestamp of escalation run */
  timestamp: number;
}

/**
 * Promote a severity string by N levels.
 * Returns the new severity string.
 */
export function promoteSeverity(current: string, levels: number): string {
  const rank = SEVERITY_RANK[current.toLowerCase()] ?? 0;
  const newRank = Math.min(rank + levels, 4); // Cap at critical
  const reverseMap = ['info', 'low', 'medium', 'high', 'critical'];
  return reverseMap[newRank] || current;
}

/**
 * Compare two severity strings. Returns:
 *   negative if a < b, 0 if equal, positive if a > b
 */
export function compareSeverity(a: string, b: string): number {
  return (SEVERITY_RANK[a.toLowerCase()] ?? 0) - (SEVERITY_RANK[b.toLowerCase()] ?? 0);
}

/**
 * Run severity escalation on correlated findings for an engagement.
 * 
 * When both ZAP and Burp confirm the same finding:
 *   1. Promote severity by one level (e.g. medium → high)
 *   2. Flag for priority exploitation
 *   3. Update the corroboration tier to 'confirmed'
 *   4. Estimate bounty value using Nextcloud reward tiers
 * 
 * Returns an EscalationSummary with all decisions.
 */
export async function runSeverityEscalation(
  engagementId: number,
  zapScanId?: number,
): Promise<EscalationSummary> {
  const db = await getDb();
  if (!db) {
    return {
      totalEvaluated: 0, escalatedCount: 0, priorityFlaggedCount: 0,
      severityBreakdown: {}, results: [], timestamp: Date.now(),
    };
  }

  // Get correlated findings
  let correlated: CorrelatedFinding[] = [];
  if (zapScanId) {
    correlated = await correlateFindings(engagementId, zapScanId);
  } else {
    // Find the latest ZAP scan for this engagement
    const recentScans = await db.select()
      .from(webAppScans)
      .where(eq(webAppScans.status, "completed"))
      .orderBy(desc(webAppScans.completedAt))
      .limit(5);

    const dbModule = await import("../db");
    const engagement = await dbModule.getEngagementById(engagementId);
    const targetDomain = engagement?.targetDomain || "";

    const matchingScan = recentScans.find(s =>
      s.targetUrl?.includes(targetDomain) ||
      s.scanName?.includes(String(engagementId))
    );

    if (matchingScan) {
      correlated = await correlateFindings(engagementId, matchingScan.id);
    }
  }

  const results: EscalationResult[] = [];
  const severityBreakdown: Record<string, number> = {};
  let escalatedCount = 0;
  let priorityFlaggedCount = 0;

  // Try to load Nextcloud bounty reward estimator
  let getMaxReward: ((severity: string) => number) | null = null;
  try {
    const ncModule = await import("./nextcloud-test-lab");
    getMaxReward = ncModule.getNextcloudMaxReward;
  } catch {}

  for (const cf of correlated) {
    let escalatedSeverity = cf.severity;
    let wasEscalated = false;
    let flaggedForExploit = false;
    let reason = "";

    if (cf.confidenceBoost && cf.foundBy.length === 2) {
      // Cross-tool confirmed: both ZAP and Burp found it
      const rule = ESCALATION_RULES.crossToolConfirmed;
      const promoted = promoteSeverity(cf.severity, rule.promote);
      if (compareSeverity(promoted, cf.severity) > 0) {
        escalatedSeverity = promoted;
        wasEscalated = true;
        reason = `Cross-tool confirmed by ZAP + Burp → severity promoted from ${cf.severity} to ${promoted}`;
      } else {
        reason = `Cross-tool confirmed by ZAP + Burp (already at ${cf.severity}, no further promotion)`;
      }
      flaggedForExploit = rule.flagPriority;
    } else if (cf.foundBy.length === 1) {
      // Single-tool finding — no escalation, but check if CWE matches another tool's finding
      const sameCwe = correlated.filter(
        other => other !== cf && other.cweId && other.cweId === cf.cweId && other.foundBy[0] !== cf.foundBy[0]
      );
      if (sameCwe.length > 0) {
        const rule = ESCALATION_RULES.cweCorroborated;
        const promoted = promoteSeverity(cf.severity, rule.promote);
        if (compareSeverity(promoted, cf.severity) > 0) {
          escalatedSeverity = promoted;
          wasEscalated = true;
          reason = `CWE-${cf.cweId} corroborated across tools → severity promoted from ${cf.severity} to ${promoted}`;
        } else {
          reason = `CWE-${cf.cweId} corroborated (already at ${cf.severity})`;
        }
        flaggedForExploit = rule.flagPriority;
      } else {
        reason = `Single-tool finding (${cf.foundBy[0]} only) — no escalation`;
      }
    }

    if (wasEscalated) escalatedCount++;
    if (flaggedForExploit) priorityFlaggedCount++;

    // Track severity breakdown
    severityBreakdown[escalatedSeverity] = (severityBreakdown[escalatedSeverity] || 0) + 1;

    const estimatedBounty = getMaxReward ? getMaxReward(escalatedSeverity) : undefined;

    results.push({
      findingId: cf.zapFindingId ? `zap-${cf.zapFindingId}` : cf.burpFindingRef || `unknown-${results.length}`,
      originalSeverity: cf.severity,
      escalatedSeverity,
      wasEscalated,
      flaggedForExploit,
      reason,
      confirmedBy: cf.foundBy,
      url: cf.url,
      cweId: cf.cweId,
      estimatedBounty,
    });
  }

  // Persist escalation results to engagement timeline
  if (results.length > 0) {
    try {
      await db.insert(engagementTimelineEvents).values({
        engagementId,
        phase: "vulnerability_analysis",
        eventType: "severity_escalation",
        severity: escalatedCount > 0 ? "high" : "info",
        title: `Severity Escalation: ${escalatedCount} promoted, ${priorityFlaggedCount} flagged for exploit`,
        description: [
          `Evaluated ${results.length} correlated findings.`,
          escalatedCount > 0 ? `${escalatedCount} findings had severity promoted due to cross-tool confirmation.` : "",
          priorityFlaggedCount > 0 ? `${priorityFlaggedCount} findings flagged for priority exploitation.` : "",
          `Severity breakdown: ${Object.entries(severityBreakdown).map(([k, v]) => `${k}:${v}`).join(", ")}`,
        ].filter(Boolean).join(" "),
        metadata: JSON.stringify({
          source: "severity_escalation_engine",
          escalatedCount,
          priorityFlaggedCount,
          severityBreakdown,
          topFindings: results.filter(r => r.wasEscalated || r.flaggedForExploit).slice(0, 10).map(r => ({
            finding: r.findingId,
            from: r.originalSeverity,
            to: r.escalatedSeverity,
            url: r.url,
            bounty: r.estimatedBounty,
          })),
        }),
        sourceModule: "zap-burp-pipeline",
        timestamp: Date.now(),
      });
    } catch (e: any) {
      console.warn(`[SeverityEscalation] Timeline event failed: ${e.message}`);
    }
  }

  // Update engagement ops state: mark escalated vulns with corroborationTier = 'confirmed'
  if (escalatedCount > 0) {
    try {
      const dbModule = await import("../db");
      const opsSnapshot = await dbModule.loadOpsSnapshot(engagementId);
      if (opsSnapshot?.stateJson) {
        let state: any;
        try { state = typeof opsSnapshot.stateJson === "string" ? JSON.parse(opsSnapshot.stateJson) : opsSnapshot.stateJson; } catch { state = null; }
        if (state?.assets) {
          let updated = false;
          for (const asset of state.assets) {
            if (!asset.vulns) continue;
            for (const vuln of asset.vulns) {
              const escalated = results.find(r =>
                r.wasEscalated &&
                (r.url.includes(asset.hostname) || r.url.includes(asset.ip)) &&
                (vuln.title?.toLowerCase().includes(r.findingId.replace(/^zap-/, "")) ||
                 vuln.cwe === r.cweId)
              );
              if (escalated) {
                vuln.severity = escalated.escalatedSeverity;
                vuln.corroborationTier = "confirmed";
                vuln.evidenceDetail = `${vuln.evidenceDetail || ""} [Severity escalated: ${escalated.reason}]`.trim();
                updated = true;
              }
            }
          }
          if (updated) {
            await dbModule.saveOpsSnapshot(engagementId, state);
          }
        }
      }
    } catch (e: any) {
      console.warn(`[SeverityEscalation] Ops state update failed: ${e.message}`);
    }
  }

  console.log(`[SeverityEscalation] Engagement #${engagementId}: ${results.length} evaluated, ${escalatedCount} escalated, ${priorityFlaggedCount} flagged`);

  return {
    totalEvaluated: results.length,
    escalatedCount,
    priorityFlaggedCount,
    severityBreakdown,
    results,
    timestamp: Date.now(),
  };
}

/**
 * Get escalation status for an engagement — returns the latest escalation summary
 * without re-running the engine.
 */
export async function getEscalationStatus(engagementId: number): Promise<EscalationSummary | null> {
  const db = await getDb();
  if (!db) return null;

  // Find the latest severity_escalation timeline event
  const [event] = await db.select()
    .from(engagementTimelineEvents)
    .where(
      and(
        eq(engagementTimelineEvents.engagementId, engagementId),
        eq(engagementTimelineEvents.eventType, "severity_escalation"),
      )
    )
    .orderBy(desc(engagementTimelineEvents.timestamp))
    .limit(1);

  if (!event) return null;

  let metadata: any = {};
  try { metadata = typeof event.metadata === "string" ? JSON.parse(event.metadata) : event.metadata || {}; } catch {}

  return {
    totalEvaluated: (metadata.topFindings?.length ?? 0) + (metadata.escalatedCount ?? 0),
    escalatedCount: metadata.escalatedCount ?? 0,
    priorityFlaggedCount: metadata.priorityFlaggedCount ?? 0,
    severityBreakdown: metadata.severityBreakdown ?? {},
    results: (metadata.topFindings || []).map((f: any) => ({
      findingId: f.finding,
      originalSeverity: f.from,
      escalatedSeverity: f.to,
      wasEscalated: f.from !== f.to,
      flaggedForExploit: true,
      reason: `Cross-tool confirmed (${f.from} → ${f.to})`,
      confirmedBy: ["zap", "burp"] as ("zap" | "burp")[],
      url: f.url,
      estimatedBounty: f.bounty,
    })),
    timestamp: event.timestamp ? Number(event.timestamp) : Date.now(),
  };
}


// ─── Deferred ZAP → Burp Re-Feed ───

/**
 * Deferred re-feed: after a ZAP scan completes, re-run the ZAP→Burp pipeline
 * with the full set of discovered URLs (not just the scope fallback).
 *
 * This is triggered from the orchestrator after ZAP scan completion, only when
 * the initial pipeline run used scope_fallback (meaning ZAP hadn't finished yet).
 *
 * Returns null if re-feed is not needed (initial run already used ZAP URLs).
 */
export async function deferredZapBurpRefeed(params: {
  engagementId: number;
  userId: string;
  engagementHandle: string;
  /** The completed ZAP scan ID to extract URLs from */
  completedZapScanId: number;
  /** The initial pipeline result — used to decide if re-feed is needed */
  initialPipelineResult?: CrossToolPipelineResult;
}): Promise<CrossToolPipelineResult | null> {
  // Only re-feed if the initial run used scope_fallback or had 0 ZAP URLs
  if (
    params.initialPipelineResult &&
    params.initialPipelineResult.urlSource === 'zap_scan' &&
    params.initialPipelineResult.zapUrlsDiscovered > 0
  ) {
    console.log(`[ZAP→Burp Deferred] Skipping re-feed for engagement #${params.engagementId}: initial pipeline already used ${params.initialPipelineResult.zapUrlsDiscovered} ZAP URLs`);
    return null;
  }

  // Extract URLs from the now-completed ZAP scan
  const discoveredUrls = await extractZapDiscoveredUrls(params.completedZapScanId);
  if (discoveredUrls.length === 0) {
    console.log(`[ZAP→Burp Deferred] No URLs discovered by ZAP scan #${params.completedZapScanId} — skipping re-feed`);
    return null;
  }

  // Check if the initial Burp scan already covered these URLs
  const initialUrlCount = params.initialPipelineResult?.urlsFedToBurp ?? 0;
  if (discoveredUrls.length <= initialUrlCount) {
    console.log(`[ZAP→Burp Deferred] ZAP discovered ${discoveredUrls.length} URLs, but initial run already fed ${initialUrlCount} — no new URLs to re-feed`);
    return null;
  }

  console.log(`[ZAP→Burp Deferred] Re-feeding ${discoveredUrls.length} ZAP-discovered URLs to Burp (initial run fed ${initialUrlCount} scope URLs)`);

  // Re-run the pipeline with the specific completed ZAP scan
  const result = await runZapToBurpPipeline({
    engagementId: params.engagementId,
    userId: params.userId,
    engagementHandle: params.engagementHandle,
    zapScanId: params.completedZapScanId,
  });

  // Log the deferred re-feed to the timeline
  const db = await getDb();
  if (db) {
    try {
      await db.insert(engagementTimelineEvents).values({
        engagementId: params.engagementId,
        phase: "vulnerability_analysis",
        eventType: "tool_executed",
        severity: "info",
        title: "ZAP → Burp Deferred Re-Feed",
        description: [
          `ZAP scan #${params.completedZapScanId} completed with ${discoveredUrls.length} discovered URLs`,
          `Initial pipeline used ${initialUrlCount} scope URLs — now re-feeding ${result.urlsFedToBurp} ZAP-discovered URLs to Burp`,
          `Technologies: ${result.fingerprint.technologies.slice(0, 5).join(", ") || "none detected"}`,
          result.correlatedFindings.length > 0
            ? `Cross-tool correlations: ${result.correlatedFindings.filter(f => f.confidenceBoost).length} confirmed`
            : "",
        ].filter(Boolean).join(". "),
        metadata: JSON.stringify({
          source: "zap_burp_deferred_refeed",
          completedZapScanId: params.completedZapScanId,
          zapUrlsDiscovered: discoveredUrls.length,
          initialUrlsFed: initialUrlCount,
          refeedUrlsFed: result.urlsFedToBurp,
          urlSource: result.urlSource,
        }),
        sourceModule: "zap-burp-pipeline",
        timestamp: Date.now(),
      });
    } catch (e: any) {
      console.warn(`[ZAP→Burp Deferred] Timeline event failed: ${e.message}`);
    }
  }

  return result;
}
