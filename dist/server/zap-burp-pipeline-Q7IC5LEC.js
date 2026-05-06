import {
  extractScopeUrls,
  init_burp_auto_scan,
  launchBurpAutoScan
} from "./chunk-OB3JYB4Z.js";
import "./chunk-QM5T2QV6.js";
import "./chunk-5U7VSFQX.js";
import "./chunk-HPRQMQNG.js";
import "./chunk-XDFUGBDN.js";
import "./chunk-KKLFDDL7.js";
import "./chunk-LC3BTWBM.js";
import "./chunk-XEI56K2V.js";
import "./chunk-LI545HOX.js";
import "./chunk-5DEWV7VV.js";
import {
  captureToolCorrelation,
  init_engagement_training_bridge
} from "./chunk-G5JVZIMZ.js";
import "./chunk-MJGBFYEG.js";
import "./chunk-IL4FZKPB.js";
import "./chunk-H26DZ3R6.js";
import "./chunk-6W5SL2GI.js";
import "./chunk-R4LF5PWF.js";
import "./chunk-4SXJ2GAM.js";
import "./chunk-5BWO4Y3K.js";
import "./chunk-7DIV2VRB.js";
import "./chunk-WQ4FJHOM.js";
import "./chunk-JEOGLS4V.js";
import "./chunk-QSC5SQUD.js";
import "./chunk-PUZE3GU2.js";
import "./chunk-DQAUMKMW.js";
import "./chunk-UOREPKTR.js";
import "./chunk-C4KWO5EH.js";
import "./chunk-SSYKZXNO.js";
import "./chunk-WP62CKNZ.js";
import "./chunk-G45ZFGC3.js";
import "./chunk-LPSC3SDV.js";
import "./chunk-J6EMIQSU.js";
import "./chunk-Q72HEY35.js";
import "./chunk-5TJ6FS74.js";
import "./chunk-UYX5D64U.js";
import "./chunk-YW5WVS53.js";
import "./chunk-PFTNS476.js";
import "./chunk-435DEVD7.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-KUPDIQVG.js";
import {
  getDb,
  init_db
} from "./chunk-MZ5XD5V3.js";
import "./chunk-NRYVRXXR.js";
import {
  engagementTimelineEvents,
  init_schema,
  userPlatformCredentials,
  webAppFindings,
  webAppScans
} from "./chunk-GM677ZS3.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/zap-burp-pipeline.ts
import { eq, and, desc } from "drizzle-orm";
async function extractZapDiscoveredUrls(zapScanId) {
  const db = await getDb();
  if (!db) return [];
  const [scan] = await db.select().from(webAppScans).where(eq(webAppScans.id, zapScanId));
  if (!scan) return [];
  const urls = [];
  const seen = /* @__PURE__ */ new Set();
  const findings = await db.select().from(webAppFindings).where(eq(webAppFindings.scanId, zapScanId));
  for (const finding of findings) {
    let evidenceObj = {};
    if (finding.evidence) {
      try {
        evidenceObj = JSON.parse(finding.evidence);
      } catch {
      }
    }
    const url = finding.url || evidenceObj?.url;
    if (url && !seen.has(url)) {
      seen.add(url);
      urls.push({
        url,
        method: finding.method || "GET",
        statusCode: evidenceObj?.statusCode,
        contentType: evidenceObj?.contentType,
        source: "passive_scan"
      });
    }
    if (evidenceObj?.requestUrl && !seen.has(evidenceObj.requestUrl)) {
      seen.add(evidenceObj.requestUrl);
      urls.push({
        url: evidenceObj.requestUrl,
        method: evidenceObj?.requestMethod || "GET",
        source: "passive_scan"
      });
    }
  }
  if (scan.targetUrl && !seen.has(scan.targetUrl)) {
    seen.add(scan.targetUrl);
    urls.push({
      url: scan.targetUrl,
      method: "GET",
      source: "spider"
    });
  }
  return urls;
}
function buildZapFingerprint(findings, scanConfig) {
  const technologies = /* @__PURE__ */ new Set();
  const headers = {};
  const cookies = /* @__PURE__ */ new Set();
  const apiEndpoints = /* @__PURE__ */ new Set();
  const loginPages = /* @__PURE__ */ new Set();
  let forms = 0;
  if (scanConfig?.technologies) {
    for (const tech of scanConfig.technologies) {
      technologies.add(tech);
    }
  }
  for (const finding of findings) {
    const alertName = (finding.alertName || finding.alert || "").toLowerCase();
    const url = finding.url || "";
    if (alertName.includes("x-powered-by")) {
      const tech = finding.description;
      if (tech) technologies.add(tech);
    }
    if (alertName.includes("server header")) {
      const server = finding.description;
      if (server) technologies.add(server);
    }
    if (alertName.includes("cookie") || alertName.includes("set-cookie")) {
      if (finding.param) cookies.add(finding.param);
    }
    if (url.includes("/api/") || url.includes("/v1/") || url.includes("/v2/") || url.includes("/graphql") || url.includes("/rest/")) {
      apiEndpoints.add(url);
    }
    if (url.includes("/login") || url.includes("/signin") || url.includes("/auth") || alertName.includes("login") || alertName.includes("authentication")) {
      loginPages.add(url);
    }
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
    loginPages: [...loginPages]
  };
}
function normalizeVulnKey(vulnName, url) {
  const name = vulnName.toLowerCase().trim();
  const urlPath = (() => {
    try {
      return new URL(url).pathname;
    } catch {
      return url;
    }
  })();
  const normalizations = {
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
    "ssti": "ssti"
  };
  const normalized = normalizations[name] || name.replace(/[^a-z0-9]/g, "_");
  return `${normalized}:${urlPath}`;
}
async function correlateFindings(engagementId, zapScanId) {
  const db = await getDb();
  if (!db) return [];
  const zapFindings = await db.select().from(webAppFindings).where(eq(webAppFindings.scanId, zapScanId));
  let burpFindings = [];
  try {
    const dbModule = await import("./db-UCRYETLI.js");
    const allFindings = await dbModule.getEngagementFindings(engagementId);
    burpFindings = (allFindings || []).filter(
      (f) => f.metadata?.source === "burp_auto_scan" || f.metadata?.scanner === "burp"
    );
  } catch {
  }
  const correlated = [];
  const zapByVuln = /* @__PURE__ */ new Map();
  const burpByVuln = /* @__PURE__ */ new Map();
  for (const zf of zapFindings) {
    const key = normalizeVulnKey(zf.alertName || "", zf.url || "");
    zapByVuln.set(key, zf);
  }
  for (const bf of burpFindings) {
    const key = normalizeVulnKey(bf.title || "", bf.assetIdentifier || "");
    burpByVuln.set(key, bf);
  }
  const allKeys = /* @__PURE__ */ new Set([...zapByVuln.keys(), ...burpByVuln.keys()]);
  for (const key of allKeys) {
    const zapF = zapByVuln.get(key);
    const burpF = burpByVuln.get(key);
    const foundBy = [];
    if (zapF) foundBy.push("zap");
    if (burpF) foundBy.push("burp");
    correlated.push({
      vulnType: zapF?.alertName || burpF?.title || key,
      zapFindingId: zapF?.id,
      burpFindingRef: burpF?.id ? String(burpF.id) : void 0,
      foundBy,
      severity: zapF?.severity || burpF?.severityRating || "info",
      confidenceBoost: foundBy.length === 2,
      url: zapF?.url || burpF?.assetIdentifier || "",
      cweId: zapF?.cweId ? String(zapF.cweId) : burpF?.cweId
    });
  }
  return correlated;
}
async function runZapToBurpPipeline(params) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  console.log(`[ZAP\u2192Burp Pipeline] Starting for engagement #${params.engagementId}`);
  let zapScanId = params.zapScanId;
  let zapScanStatus;
  if (!zapScanId) {
    const dbModule = await import("./db-UCRYETLI.js");
    const engagement = await dbModule.getEngagementById(params.engagementId);
    if (!engagement) throw new Error(`Engagement #${params.engagementId} not found`);
    const targetDomain = engagement.targetDomain || "";
    for (const statusToCheck of ["completed", "running", "scanning", "active_scan", "spider", "starting"]) {
      const recentScans = await db.select().from(webAppScans).where(eq(webAppScans.status, statusToCheck)).orderBy(desc(webAppScans.completedAt)).limit(10);
      const matchingScan = recentScans.find(
        (s) => s.targetUrl?.includes(targetDomain) || s.scanName?.includes(String(params.engagementId))
      );
      if (matchingScan) {
        zapScanId = matchingScan.id;
        zapScanStatus = statusToCheck;
        break;
      }
    }
  }
  let discoveredUrls = [];
  let fingerprint = {
    technologies: [],
    headers: {},
    cookies: [],
    forms: 0,
    apiEndpoints: [],
    loginPages: []
  };
  if (zapScanId) {
    discoveredUrls = await extractZapDiscoveredUrls(zapScanId);
    const findings = await db.select().from(webAppFindings).where(eq(webAppFindings.scanId, zapScanId));
    const [scan] = await db.select().from(webAppScans).where(eq(webAppScans.id, zapScanId));
    let scanConfig = null;
    if (scan?.llmScanConfig) {
      try {
        scanConfig = JSON.parse(scan.llmScanConfig);
      } catch {
      }
    }
    fingerprint = buildZapFingerprint(findings, scanConfig);
    console.log(`[ZAP\u2192Burp Pipeline] ZAP scan #${zapScanId}: ${discoveredUrls.length} URLs, ${fingerprint.technologies.length} technologies, ${fingerprint.apiEndpoints.length} API endpoints`);
  }
  let urlSource = "zap_scan";
  const targetUrls = params.targetUrls ? (() => {
    urlSource = "override";
    return params.targetUrls;
  })() : [...discoveredUrls.map((u) => u.url)];
  const uniqueUrls = [...new Set(targetUrls)].filter(
    (u) => u.startsWith("http://") || u.startsWith("https://")
  );
  if (uniqueUrls.length === 0) {
    urlSource = "scope_fallback";
    const dbModule = await import("./db-UCRYETLI.js");
    const engagement = await dbModule.getEngagementById(params.engagementId);
    const opsState = await dbModule.loadOpsSnapshot(params.engagementId);
    const scopeUrls = extractScopeUrls(engagement, opsState?.stateJson);
    uniqueUrls.push(...scopeUrls);
    console.log(`[ZAP\u2192Burp Pipeline] No ZAP-discovered URLs available (scan ${zapScanStatus || "not found"}), falling back to ${scopeUrls.length} engagement scope URLs`);
  }
  if (uniqueUrls.length === 0) {
    return {
      zapScanId: zapScanId || 0,
      zapUrlsDiscovered: discoveredUrls.length,
      urlsFedToBurp: 0,
      urlSource: "scope_fallback",
      burpScanLaunched: false,
      fingerprint,
      correlatedFindings: [],
      error: "No URLs available for Burp scanning"
    };
  }
  console.log(`[ZAP\u2192Burp Pipeline] Feeding ${uniqueUrls.length} URLs to Burp (first 3: ${uniqueUrls.slice(0, 3).join(", ")})`);
  let burpCred = null;
  try {
    const numericUserId = parseInt(params.userId, 10);
    if (!isNaN(numericUserId)) {
      const creds = await db.select().from(userPlatformCredentials).where(
        and(
          eq(userPlatformCredentials.userId, numericUserId),
          eq(userPlatformCredentials.isActive, 1)
        )
      );
      const burpCreds = creds.filter(
        (c) => c.platform === "burpsuite_pro" || c.platform === "burpsuite_enterprise"
      );
      if (params.burpCredentialId) {
        burpCred = burpCreds.find((c) => c.id === params.burpCredentialId);
      } else {
        burpCred = burpCreds[0];
      }
    }
  } catch {
  }
  if (!burpCred) {
    const envScanHost = process.env.SCAN_SERVER_HOST;
    const envBurpApiKey = process.env.BURP_API_KEY || process.env.CALDERA_API_KEY;
    const envBurpBaseUrl = process.env.BURP_BASE_URL || (envScanHost ? `http://${envScanHost}:1337` : "");
    if (envBurpBaseUrl && envBurpApiKey) {
      console.log(`[ZAP\u2192Burp Pipeline] No DB credentials \u2014 using env fallback: ${envBurpBaseUrl}`);
      burpCred = {
        id: -1,
        platform: "burpsuite_pro",
        baseUrl: envBurpBaseUrl,
        apiKeyEncrypted: envBurpApiKey
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
        error: "No Burp Suite credentials found and no env fallback available"
      };
    }
  }
  let burpScanState;
  try {
    const scanConfigName = fingerprint.apiEndpoints.length > 5 ? "Audit checks - all" : fingerprint.forms > 0 ? "Crawl and Audit - Balanced" : void 0;
    const edition = burpCred.platform === "burpsuite_enterprise" ? "enterprise" : "professional";
    const scanServerHost = process.env.SCAN_SERVER_HOST || "137.184.211.238";
    burpScanState = await launchBurpAutoScan({
      engagementId: params.engagementId,
      engagementHandle: params.engagementHandle,
      userId: params.userId,
      targetUrls: uniqueUrls,
      credentialId: burpCred.id,
      burpConfig: {
        edition,
        baseUrl: burpCred.baseUrl || `http://${scanServerHost}:1337`,
        apiKey: burpCred.apiKeyEncrypted || ""
      },
      scanConfigName,
      scanMode: "active",
      appLogin: params.appLogin
    });
    console.log(`[ZAP\u2192Burp Pipeline] Burp scan launched: status=${burpScanState.status}, ${uniqueUrls.length} URLs`);
  } catch (err) {
    console.error(`[ZAP\u2192Burp Pipeline] Failed to launch Burp scan: ${err.message}`);
    return {
      zapScanId: zapScanId || 0,
      zapUrlsDiscovered: discoveredUrls.length,
      urlsFedToBurp: uniqueUrls.length,
      urlSource,
      burpScanLaunched: false,
      fingerprint,
      correlatedFindings: [],
      error: `Burp scan launch failed: ${err.message}`
    };
  }
  let correlatedFindings = [];
  if (zapScanId) {
    correlatedFindings = await correlateFindings(params.engagementId, zapScanId);
    for (const cf of correlatedFindings.filter((f) => f.confidenceBoost)) {
      try {
        await captureToolCorrelation({
          engagementId: params.engagementId,
          primaryTool: "zap",
          secondaryTool: "burp",
          findingType: cf.vulnType,
          correlationType: "confirmed",
          primaryFindingId: cf.zapFindingId ? String(cf.zapFindingId) : void 0,
          secondaryFindingId: cf.burpFindingRef,
          detail: `${cf.vulnType} at ${cf.url} confirmed by both ZAP and Burp (severity: ${cf.severity})`
        });
      } catch {
      }
    }
  }
  try {
    await db.insert(engagementTimelineEvents).values({
      engagementId: params.engagementId,
      phase: "vulnerability_analysis",
      eventType: "tool_executed",
      severity: "info",
      title: "ZAP \u2192 Burp Cross-Tool Pipeline",
      description: [
        urlSource === "zap_scan" ? `ZAP discovered ${discoveredUrls.length} URLs (scan #${zapScanId || "N/A"})` : `ZAP scan ${zapScanId ? `#${zapScanId} (${zapScanStatus || "in progress"})` : "not found"} \u2014 used ${uniqueUrls.length} engagement scope URLs as fallback`,
        `Fed ${uniqueUrls.length} unique URLs to Burp Suite (source: ${urlSource})`,
        `Technologies: ${fingerprint.technologies.slice(0, 5).join(", ") || "none detected"}`,
        `API endpoints: ${fingerprint.apiEndpoints.length}`,
        `Login pages: ${fingerprint.loginPages.length}`,
        correlatedFindings.length > 0 ? `Cross-tool correlations: ${correlatedFindings.filter((f) => f.confidenceBoost).length} confirmed by both tools` : ""
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
        correlatedCount: correlatedFindings.filter((f) => f.confidenceBoost).length,
        burpScanStatus: burpScanState?.status
      }),
      sourceModule: "zap-burp-pipeline",
      timestamp: Date.now()
    });
  } catch (e) {
    console.warn(`[ZAP\u2192Burp Pipeline] Timeline event failed: ${e.message}`);
  }
  return {
    zapScanId: zapScanId || 0,
    zapUrlsDiscovered: discoveredUrls.length,
    urlsFedToBurp: uniqueUrls.length,
    urlSource,
    burpScanLaunched: true,
    burpScanState,
    fingerprint,
    correlatedFindings
  };
}
async function getCrossToolCoverage(engagementId) {
  const db = await getDb();
  if (!db) return { totalUrls: 0, zapOnly: 0, burpOnly: 0, both: 0, uncovered: 0, urlDetails: [] };
  const zapFindings = await db.select({
    url: webAppFindings.url
  }).from(webAppFindings);
  const zapUrls = new Set(zapFindings.map((f) => f.url).filter(Boolean));
  let burpUrls = /* @__PURE__ */ new Set();
  try {
    const dbModule2 = await import("./db-UCRYETLI.js");
    const burpFindings = await dbModule2.getEngagementFindings(engagementId);
    const burpFindingsList = (burpFindings || []).filter(
      (f) => f.metadata?.source === "burp_auto_scan" || f.metadata?.scanner === "burp"
    );
    burpUrls = new Set(burpFindingsList.map((f) => f.assetIdentifier).filter(Boolean));
  } catch {
  }
  const dbModule = await import("./db-UCRYETLI.js");
  const engagement = await dbModule.getEngagementById(engagementId);
  const opsState = await dbModule.loadOpsSnapshot(engagementId);
  const scopeUrls = engagement ? extractScopeUrls(engagement, opsState?.stateJson) : [];
  const allUrls = /* @__PURE__ */ new Set([...scopeUrls, ...zapUrls, ...burpUrls]);
  let zapOnly = 0, burpOnly = 0, both = 0, uncovered = 0;
  const urlDetails = [];
  for (const url of allUrls) {
    const inZap = zapUrls.has(url);
    const inBurp = burpUrls.has(url);
    const scannedBy = [];
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
    urlDetails: urlDetails.slice(0, 100)
    // Limit for API response size
  };
}
function promoteSeverity(current, levels) {
  const rank = SEVERITY_RANK[current.toLowerCase()] ?? 0;
  const newRank = Math.min(rank + levels, 4);
  const reverseMap = ["info", "low", "medium", "high", "critical"];
  return reverseMap[newRank] || current;
}
function compareSeverity(a, b) {
  return (SEVERITY_RANK[a.toLowerCase()] ?? 0) - (SEVERITY_RANK[b.toLowerCase()] ?? 0);
}
async function runSeverityEscalation(engagementId, zapScanId) {
  const db = await getDb();
  if (!db) {
    return {
      totalEvaluated: 0,
      escalatedCount: 0,
      priorityFlaggedCount: 0,
      severityBreakdown: {},
      results: [],
      timestamp: Date.now()
    };
  }
  let correlated = [];
  if (zapScanId) {
    correlated = await correlateFindings(engagementId, zapScanId);
  } else {
    const recentScans = await db.select().from(webAppScans).where(eq(webAppScans.status, "completed")).orderBy(desc(webAppScans.completedAt)).limit(5);
    const dbModule = await import("./db-UCRYETLI.js");
    const engagement = await dbModule.getEngagementById(engagementId);
    const targetDomain = engagement?.targetDomain || "";
    const matchingScan = recentScans.find(
      (s) => s.targetUrl?.includes(targetDomain) || s.scanName?.includes(String(engagementId))
    );
    if (matchingScan) {
      correlated = await correlateFindings(engagementId, matchingScan.id);
    }
  }
  const results = [];
  const severityBreakdown = {};
  let escalatedCount = 0;
  let priorityFlaggedCount = 0;
  let getMaxReward = null;
  try {
    const ncModule = await import("./nextcloud-test-lab-6KMQNIPZ.js");
    getMaxReward = ncModule.getNextcloudMaxReward;
  } catch {
  }
  for (const cf of correlated) {
    let escalatedSeverity = cf.severity;
    let wasEscalated = false;
    let flaggedForExploit = false;
    let reason = "";
    if (cf.confidenceBoost && cf.foundBy.length === 2) {
      const rule = ESCALATION_RULES.crossToolConfirmed;
      const promoted = promoteSeverity(cf.severity, rule.promote);
      if (compareSeverity(promoted, cf.severity) > 0) {
        escalatedSeverity = promoted;
        wasEscalated = true;
        reason = `Cross-tool confirmed by ZAP + Burp \u2192 severity promoted from ${cf.severity} to ${promoted}`;
      } else {
        reason = `Cross-tool confirmed by ZAP + Burp (already at ${cf.severity}, no further promotion)`;
      }
      flaggedForExploit = rule.flagPriority;
    } else if (cf.foundBy.length === 1) {
      const sameCwe = correlated.filter(
        (other) => other !== cf && other.cweId && other.cweId === cf.cweId && other.foundBy[0] !== cf.foundBy[0]
      );
      if (sameCwe.length > 0) {
        const rule = ESCALATION_RULES.cweCorroborated;
        const promoted = promoteSeverity(cf.severity, rule.promote);
        if (compareSeverity(promoted, cf.severity) > 0) {
          escalatedSeverity = promoted;
          wasEscalated = true;
          reason = `CWE-${cf.cweId} corroborated across tools \u2192 severity promoted from ${cf.severity} to ${promoted}`;
        } else {
          reason = `CWE-${cf.cweId} corroborated (already at ${cf.severity})`;
        }
        flaggedForExploit = rule.flagPriority;
      } else {
        reason = `Single-tool finding (${cf.foundBy[0]} only) \u2014 no escalation`;
      }
    }
    if (wasEscalated) escalatedCount++;
    if (flaggedForExploit) priorityFlaggedCount++;
    severityBreakdown[escalatedSeverity] = (severityBreakdown[escalatedSeverity] || 0) + 1;
    const estimatedBounty = getMaxReward ? getMaxReward(escalatedSeverity) : void 0;
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
      estimatedBounty
    });
  }
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
          `Severity breakdown: ${Object.entries(severityBreakdown).map(([k, v]) => `${k}:${v}`).join(", ")}`
        ].filter(Boolean).join(" "),
        metadata: JSON.stringify({
          source: "severity_escalation_engine",
          escalatedCount,
          priorityFlaggedCount,
          severityBreakdown,
          topFindings: results.filter((r) => r.wasEscalated || r.flaggedForExploit).slice(0, 10).map((r) => ({
            finding: r.findingId,
            from: r.originalSeverity,
            to: r.escalatedSeverity,
            url: r.url,
            bounty: r.estimatedBounty
          }))
        }),
        sourceModule: "zap-burp-pipeline",
        timestamp: Date.now()
      });
    } catch (e) {
      console.warn(`[SeverityEscalation] Timeline event failed: ${e.message}`);
    }
  }
  if (escalatedCount > 0) {
    try {
      const dbModule = await import("./db-UCRYETLI.js");
      const opsSnapshot = await dbModule.loadOpsSnapshot(engagementId);
      if (opsSnapshot?.stateJson) {
        let state;
        try {
          state = typeof opsSnapshot.stateJson === "string" ? JSON.parse(opsSnapshot.stateJson) : opsSnapshot.stateJson;
        } catch {
          state = null;
        }
        if (state?.assets) {
          let updated = false;
          for (const asset of state.assets) {
            if (!asset.vulns) continue;
            for (const vuln of asset.vulns) {
              const escalated = results.find(
                (r) => r.wasEscalated && (r.url.includes(asset.hostname) || r.url.includes(asset.ip)) && (vuln.title?.toLowerCase().includes(r.findingId.replace(/^zap-/, "")) || vuln.cwe === r.cweId)
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
    } catch (e) {
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
    timestamp: Date.now()
  };
}
async function getEscalationStatus(engagementId) {
  const db = await getDb();
  if (!db) return null;
  const [event] = await db.select().from(engagementTimelineEvents).where(
    and(
      eq(engagementTimelineEvents.engagementId, engagementId),
      eq(engagementTimelineEvents.eventType, "severity_escalation")
    )
  ).orderBy(desc(engagementTimelineEvents.timestamp)).limit(1);
  if (!event) return null;
  let metadata = {};
  try {
    metadata = typeof event.metadata === "string" ? JSON.parse(event.metadata) : event.metadata || {};
  } catch {
  }
  return {
    totalEvaluated: (metadata.topFindings?.length ?? 0) + (metadata.escalatedCount ?? 0),
    escalatedCount: metadata.escalatedCount ?? 0,
    priorityFlaggedCount: metadata.priorityFlaggedCount ?? 0,
    severityBreakdown: metadata.severityBreakdown ?? {},
    results: (metadata.topFindings || []).map((f) => ({
      findingId: f.finding,
      originalSeverity: f.from,
      escalatedSeverity: f.to,
      wasEscalated: f.from !== f.to,
      flaggedForExploit: true,
      reason: `Cross-tool confirmed (${f.from} \u2192 ${f.to})`,
      confirmedBy: ["zap", "burp"],
      url: f.url,
      estimatedBounty: f.bounty
    })),
    timestamp: event.timestamp ? Number(event.timestamp) : Date.now()
  };
}
async function deferredZapBurpRefeed(params) {
  if (params.initialPipelineResult && params.initialPipelineResult.urlSource === "zap_scan" && params.initialPipelineResult.zapUrlsDiscovered > 0) {
    console.log(`[ZAP\u2192Burp Deferred] Skipping re-feed for engagement #${params.engagementId}: initial pipeline already used ${params.initialPipelineResult.zapUrlsDiscovered} ZAP URLs`);
    return null;
  }
  const discoveredUrls = await extractZapDiscoveredUrls(params.completedZapScanId);
  if (discoveredUrls.length === 0) {
    console.log(`[ZAP\u2192Burp Deferred] No URLs discovered by ZAP scan #${params.completedZapScanId} \u2014 skipping re-feed`);
    return null;
  }
  const initialUrlCount = params.initialPipelineResult?.urlsFedToBurp ?? 0;
  if (discoveredUrls.length <= initialUrlCount) {
    console.log(`[ZAP\u2192Burp Deferred] ZAP discovered ${discoveredUrls.length} URLs, but initial run already fed ${initialUrlCount} \u2014 no new URLs to re-feed`);
    return null;
  }
  console.log(`[ZAP\u2192Burp Deferred] Re-feeding ${discoveredUrls.length} ZAP-discovered URLs to Burp (initial run fed ${initialUrlCount} scope URLs)`);
  const result = await runZapToBurpPipeline({
    engagementId: params.engagementId,
    userId: params.userId,
    engagementHandle: params.engagementHandle,
    zapScanId: params.completedZapScanId,
    appLogin: params.appLogin
  });
  const db = await getDb();
  if (db) {
    try {
      await db.insert(engagementTimelineEvents).values({
        engagementId: params.engagementId,
        phase: "vulnerability_analysis",
        eventType: "tool_executed",
        severity: "info",
        title: "ZAP \u2192 Burp Deferred Re-Feed",
        description: [
          `ZAP scan #${params.completedZapScanId} completed with ${discoveredUrls.length} discovered URLs`,
          `Initial pipeline used ${initialUrlCount} scope URLs \u2014 now re-feeding ${result.urlsFedToBurp} ZAP-discovered URLs to Burp`,
          `Technologies: ${result.fingerprint.technologies.slice(0, 5).join(", ") || "none detected"}`,
          result.correlatedFindings.length > 0 ? `Cross-tool correlations: ${result.correlatedFindings.filter((f) => f.confidenceBoost).length} confirmed` : ""
        ].filter(Boolean).join(". "),
        metadata: JSON.stringify({
          source: "zap_burp_deferred_refeed",
          completedZapScanId: params.completedZapScanId,
          zapUrlsDiscovered: discoveredUrls.length,
          initialUrlsFed: initialUrlCount,
          refeedUrlsFed: result.urlsFedToBurp,
          urlSource: result.urlSource
        }),
        sourceModule: "zap-burp-pipeline",
        timestamp: Date.now()
      });
    } catch (e) {
      console.warn(`[ZAP\u2192Burp Deferred] Timeline event failed: ${e.message}`);
    }
  }
  return result;
}
var SEVERITY_RANK, ESCALATION_RULES;
var init_zap_burp_pipeline = __esm({
  "server/lib/zap-burp-pipeline.ts"() {
    init_db();
    init_schema();
    init_burp_auto_scan();
    init_engagement_training_bridge();
    SEVERITY_RANK = {
      info: 0,
      informational: 0,
      low: 1,
      medium: 2,
      high: 3,
      critical: 4
    };
    ESCALATION_RULES = {
      /** Both ZAP and Burp found the exact same vuln type at the same URL */
      crossToolConfirmed: { promote: 1, flagPriority: true },
      /** Same CWE confirmed by both tools at different URLs */
      cweCorroborated: { promote: 1, flagPriority: false },
      /** Same vuln type but different severity ratings between tools — use higher */
      severityDisagreement: { promote: 0, flagPriority: true }
    };
  }
});
init_zap_burp_pipeline();
export {
  buildZapFingerprint,
  compareSeverity,
  correlateFindings,
  deferredZapBurpRefeed,
  extractZapDiscoveredUrls,
  getCrossToolCoverage,
  getEscalationStatus,
  promoteSeverity,
  runSeverityEscalation,
  runZapToBurpPipeline
};
