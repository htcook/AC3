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

  // Step 1: Find the latest completed ZAP scan
  let zapScanId = params.zapScanId;
  if (!zapScanId) {
    const recentScans = await db.select()
      .from(webAppScans)
      .where(eq(webAppScans.status, "completed"))
      .orderBy(desc(webAppScans.completedAt))
      .limit(10);

    // Find one that matches the engagement's target
    const dbModule = await import("../db");
    const engagement = await dbModule.getEngagementById(params.engagementId);
    if (!engagement) throw new Error(`Engagement #${params.engagementId} not found`);

    const targetDomain = engagement.targetDomain || "";
    const matchingScan = recentScans.find(s =>
      s.targetUrl?.includes(targetDomain) ||
      s.scanName?.includes(String(params.engagementId))
    );

    if (matchingScan) {
      zapScanId = matchingScan.id;
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
  const targetUrls = params.targetUrls || [
    ...discoveredUrls.map(u => u.url),
  ];

  // Deduplicate and normalize URLs
  const uniqueUrls = [...new Set(targetUrls)].filter(u =>
    u.startsWith("http://") || u.startsWith("https://")
  );

  if (uniqueUrls.length === 0) {
    // Fall back to engagement scope URLs
    const dbModule = await import("../db");
    const engagement = await dbModule.getEngagementById(params.engagementId);
    const opsState = await dbModule.loadOpsSnapshot(params.engagementId);
    const scopeUrls = extractScopeUrls(engagement, opsState?.stateJson);
    uniqueUrls.push(...scopeUrls);
  }

  if (uniqueUrls.length === 0) {
    return {
      zapScanId: zapScanId || 0,
      zapUrlsDiscovered: discoveredUrls.length,
      urlsFedToBurp: 0,
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
    return {
      zapScanId: zapScanId || 0,
      zapUrlsDiscovered: discoveredUrls.length,
      urlsFedToBurp: uniqueUrls.length,
      burpScanLaunched: false,
      fingerprint,
      correlatedFindings: [],
      error: "No Burp Suite credentials found",
    };
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
        `ZAP discovered ${discoveredUrls.length} URLs (scan #${zapScanId || "N/A"})`,
        `Fed ${uniqueUrls.length} unique URLs to Burp Suite`,
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
