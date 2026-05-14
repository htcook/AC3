import {
  engagement_orchestrator_exports,
  init_engagement_orchestrator
} from "./chunk-PXEHJMLH.js";
import {
  BurpSuiteConnector,
  init_burpsuite_connector,
  normalizeBurpIssues
} from "./chunk-H26DZ3R6.js";
import {
  __esm,
  __toCommonJS
} from "./chunk-KFQGP6VL.js";

// server/lib/burp-auto-scan.ts
function scanKey(engagementId, credentialId) {
  return `${engagementId}:${credentialId}`;
}
async function persistCreate(state, scanConfigName) {
  try {
    const db = await import("./db-LCEQKGBV.js");
    const id = await db.createBurpScanRecord({
      engagementId: state.engagementId,
      credentialId: state.credentialId,
      userId: "",
      // Will be set by caller
      scanId: state.scanId || void 0,
      edition: state.edition,
      status: state.status,
      targetUrls: state.targetUrls,
      scanConfigName,
      startedAt: state.startedAt
    });
    return id;
  } catch (err) {
    console.warn(`[BurpAutoScan] Failed to persist scan record: ${err.message}`);
    return null;
  }
}
async function persistUpdate(state) {
  if (!state.dbRecordId) return;
  try {
    const db = await import("./db-LCEQKGBV.js");
    await db.updateBurpScanRecord(state.dbRecordId, {
      scanId: state.scanId || void 0,
      status: state.status,
      progress: state.progress,
      issueCount: state.issueCount,
      importedCount: state.importedCount,
      error: state.error,
      completedAt: state.completedAt,
      lastPollAt: state.lastPollAt,
      pollCount: state.pollCount
    });
  } catch (err) {
    console.warn(`[BurpAutoScan] Failed to update scan record #${state.dbRecordId}: ${err.message}`);
  }
}
async function launchBurpAutoScan(config) {
  const key = scanKey(config.engagementId, config.credentialId);
  const existing = activeBurpScans.get(key);
  if (existing && ["launching", "running", "polling", "importing"].includes(existing.status)) {
    return existing;
  }
  const webUrls = config.targetUrls.filter(
    (u) => u.startsWith("http://") || u.startsWith("https://")
  );
  if (webUrls.length === 0) {
    throw new Error("No web URLs found in scope assets. Burp Suite requires HTTP/HTTPS targets.");
  }
  const state = {
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
    edition: config.burpConfig.edition
  };
  activeBurpScans.set(key, state);
  const dbId = await persistCreate(state, config.scanConfigName);
  if (dbId) state.dbRecordId = dbId;
  launchAndPoll(config, state, key).catch((err) => {
    state.status = "failed";
    state.error = err.message;
    state.completedAt = Date.now();
    persistUpdate(state);
    broadcastBurpUpdate(config.engagementId, state);
  });
  return state;
}
function getBurpAutoScanState(engagementId, credentialId) {
  return activeBurpScans.get(scanKey(engagementId, credentialId)) || null;
}
function getEngagementBurpScans(engagementId) {
  const results = [];
  for (const [key, state] of activeBurpScans) {
    if (key.startsWith(`${engagementId}:`)) {
      results.push(state);
    }
  }
  return results;
}
async function getEngagementBurpScanHistory(engagementId) {
  try {
    const db = await import("./db-LCEQKGBV.js");
    return db.getBurpScansByEngagement(engagementId);
  } catch {
    return [];
  }
}
async function cancelBurpAutoScan(engagementId, credentialId) {
  const key = scanKey(engagementId, credentialId);
  const state = activeBurpScans.get(key);
  if (!state) return false;
  state.status = "cancelled";
  state.completedAt = Date.now();
  await persistUpdate(state);
  broadcastBurpUpdate(engagementId, state);
  return true;
}
async function onEngagementVulnDetectionPhase(engagementId, userId, engagementHandle, scopeUrls, scanMode, appLogin, techHints) {
  const db = await import("./db-LCEQKGBV.js");
  const allCreds = await db.listPlatformCredentials(userId);
  const burpCreds = allCreds.filter(
    (c) => c.platform === "burpsuite_pro" || c.platform === "burpsuite_enterprise"
  );
  if (burpCreds.length === 0) {
    const scanServerHost = process.env.SCAN_SERVER_HOST;
    const envBurpApiKey = process.env.BURP_API_KEY || process.env.CALDERA_API_KEY;
    const envBurpBaseUrl = process.env.BURP_BASE_URL || (scanServerHost ? `http://${scanServerHost}:1337` : "");
    if (envBurpBaseUrl && envBurpApiKey) {
      console.log(`[BurpAutoScan] No DB credentials found \u2014 using env fallback: ${envBurpBaseUrl}`);
      burpCreds.push({
        id: -1,
        // Synthetic credential ID for env-var fallback
        userId: parseInt(userId, 10) || 0,
        platform: "burpsuite_pro",
        displayName: "Scan Server Burp (env fallback)",
        apiUsername: "",
        apiKey: envBurpApiKey,
        baseUrl: envBurpBaseUrl,
        isActive: 1,
        lastVerifiedAt: null,
        lastSyncAt: null,
        syncStatus: "idle",
        metadata: null
      });
    } else {
      console.log(`[BurpAutoScan] No Burp Suite credentials found for user ${userId} and no env fallback \u2014 skipping auto-scan`);
      return [];
    }
  }
  const results = [];
  for (const cred of burpCreds) {
    try {
      const edition = cred.platform === "burpsuite_enterprise" ? "enterprise" : "professional";
      const state = await launchBurpAutoScan({
        engagementId,
        engagementHandle,
        userId,
        targetUrls: scopeUrls,
        credentialId: cred.id,
        burpConfig: {
          edition,
          baseUrl: cred.baseUrl || "http://127.0.0.1:1337",
          apiKey: cred.apiKey
        },
        scanMode: scanMode || "standard",
        appLogin,
        techHints
      });
      results.push(state);
      console.log(
        `[BurpAutoScan] Launched ${edition} scan for engagement #${engagementId} via credential #${cred.id} \u2014 ${scopeUrls.length} URLs`
      );
    } catch (err) {
      console.error(
        `[BurpAutoScan] Failed to launch scan via credential #${cred.id}: ${err.message}`
      );
    }
  }
  return results;
}
async function launchAndPoll(config, state, key) {
  const connector = new BurpSuiteConnector(config.burpConfig);
  const diagnostics = [];
  try {
    const burpUrl = new URL(config.burpConfig.baseUrl);
    const netMod = await import("net");
    const burpReachable = await new Promise((resolve) => {
      const sock = new netMod.default.Socket();
      sock.setTimeout(5e3);
      sock.once("connect", () => {
        sock.destroy();
        resolve(true);
      });
      sock.once("timeout", () => {
        sock.destroy();
        resolve(false);
      });
      sock.once("error", () => {
        sock.destroy();
        resolve(false);
      });
      sock.connect(parseInt(burpUrl.port) || 1337, burpUrl.hostname);
    });
    diagnostics.push(`Burp API (${burpUrl.hostname}:${burpUrl.port || 1337}): ${burpReachable ? "reachable" : "UNREACHABLE"}`);
    if (!burpReachable) {
      state.status = "failed";
      state.error = `Burp Suite REST API unreachable at ${config.burpConfig.baseUrl}. Check that Burp is running with REST API enabled on the scan server.`;
      state.completedAt = Date.now();
      await persistUpdate(state);
      broadcastBurpUpdate(config.engagementId, state);
      return;
    }
    const targetUrl = state.targetUrls[0];
    if (targetUrl) {
      try {
        const targetHost = new URL(targetUrl);
        const targetReachable = await new Promise((resolve) => {
          const sock = new netMod.default.Socket();
          sock.setTimeout(5e3);
          sock.once("connect", () => {
            sock.destroy();
            resolve(true);
          });
          sock.once("timeout", () => {
            sock.destroy();
            resolve(false);
          });
          sock.once("error", () => {
            sock.destroy();
            resolve(false);
          });
          sock.connect(parseInt(targetHost.port) || (targetHost.protocol === "https:" ? 443 : 80), targetHost.hostname);
        });
        diagnostics.push(`Target (${targetHost.hostname}): ${targetReachable ? "reachable" : "UNREACHABLE from scan server"}`);
        if (!targetReachable) {
          diagnostics.push("WARNING: Target may not be reachable from the Burp scan server. Scan may complete with 0 findings.");
        }
      } catch {
      }
    }
  } catch (diagErr) {
    diagnostics.push(`Diagnostics error: ${diagErr.message}`);
  }
  console.log(`[BurpAutoScan] Pre-flight diagnostics: ${diagnostics.join(" | ")}`);
  try {
    const verification = await connector.verify();
    if (!verification.valid) {
      state.status = "failed";
      state.error = `Burp Suite connection failed: ${verification.message}. Diagnostics: ${diagnostics.join("; ")}`;
      state.completedAt = Date.now();
      await persistUpdate(state);
      broadcastBurpUpdate(config.engagementId, state);
      return;
    }
    diagnostics.push(`Burp API verified: ${verification.message}`);
  } catch (err) {
    state.status = "failed";
    state.error = `Connection verification failed: ${err.message}. Diagnostics: ${diagnostics.join("; ")}`;
    state.completedAt = Date.now();
    await persistUpdate(state);
    broadcastBurpUpdate(config.engagementId, state);
    return;
  }
  try {
    let scanConfigName = config.scanConfigName;
    if (!scanConfigName) {
      const techStr = (config.techHints || []).join(" ").toLowerCase();
      const hasJava = techStr.includes("java") || techStr.includes("tomcat") || techStr.includes("spring");
      const hasPHP = techStr.includes("php") || techStr.includes("wordpress") || techStr.includes("laravel");
      const hasDotNet = techStr.includes("asp.net") || techStr.includes(".net") || techStr.includes("iis");
      const hasNode = techStr.includes("node") || techStr.includes("express") || techStr.includes("next.js");
      const hasAPI = techStr.includes("api") || techStr.includes("graphql") || techStr.includes("rest");
      switch (config.scanMode) {
        case "strict_passive":
          scanConfigName = "Crawl and Audit - Lightweight";
          break;
        case "active":
          if (hasJava || hasDotNet) {
            scanConfigName = "Crawl and Audit - Deep";
            console.log(`[BurpAutoScan] Tech-aware config: using Deep crawl for ${hasJava ? "Java" : ".NET"} target`);
          } else if (hasAPI) {
            scanConfigName = "Audit checks - all";
            console.log(`[BurpAutoScan] Tech-aware config: using Audit-only for API target`);
          } else {
            scanConfigName = "Audit checks - all";
          }
          break;
        default:
          if (hasAPI) {
            scanConfigName = "Audit checks - all";
          } else {
            scanConfigName = "Crawl and Audit - Balanced";
          }
      }
      if (config.techHints?.length) {
        console.log(`[BurpAutoScan] Tech hints: [${config.techHints.slice(0, 5).join(", ")}], selected config: ${scanConfigName || "default"}`);
      }
    }
    if (config.burpConfig.edition === "professional") {
      const scanRequest = {
        urls: state.targetUrls,
        scanConfiguration: scanConfigName,
        applicationLogin: config.appLogin
      };
      const result = await connector.startScanPro(scanRequest);
      state.scanId = result.scanId;
    } else {
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
  } catch (err) {
    state.status = "failed";
    state.error = `Failed to start scan: ${err.message}`;
    state.completedAt = Date.now();
    await persistUpdate(state);
    broadcastBurpUpdate(config.engagementId, state);
    return;
  }
  const POLL_INTERVAL = 15e3;
  const MAX_POLL_TIME = 4 * 60 * 60 * 1e3;
  const DB_PERSIST_INTERVAL = 5;
  const pollStart = Date.now();
  while (state.status === "running") {
    await sleep(POLL_INTERVAL);
    if (state.status === "cancelled") break;
    if (Date.now() - pollStart > MAX_POLL_TIME) {
      state.status = "failed";
      state.error = "Scan timed out after 4 hours";
      state.completedAt = Date.now();
      await persistUpdate(state);
      broadcastBurpUpdate(config.engagementId, state);
      return;
    }
    try {
      const scanStatus = await connector.getScanStatus(state.scanId);
      state.progress = scanStatus.progress;
      state.issueCount = scanStatus.issueCount;
      state.lastPollAt = Date.now();
      state.pollCount++;
      if (state.pollCount % DB_PERSIST_INTERVAL === 0) {
        await persistUpdate(state);
      }
      broadcastBurpUpdate(config.engagementId, state);
      if (scanStatus.status === "succeeded") {
        const scanDurationMs = Date.now() - pollStart;
        if (scanDurationMs < 3e4 && scanStatus.issueCount === 0) {
          console.warn(`[BurpAutoScan] Suspicious fast completion: scan ${state.scanId} finished in ${Math.round(scanDurationMs / 1e3)}s with 0 issues. Target may be unreachable from Burp.`);
          state.error = `Scan completed suspiciously fast (${Math.round(scanDurationMs / 1e3)}s) with 0 findings. This typically indicates the target is unreachable from the Burp scan server, or the scan scope resolved to 0 crawlable URLs. Verify network connectivity between Burp and the target.`;
        }
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
    } catch (err) {
      console.warn(`[BurpAutoScan] Poll error for scan ${state.scanId}: ${err.message}`);
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
  if (state.status === "importing" && state.scanId) {
    try {
      const issues = await connector.getIssues(state.scanId);
      const normalized = normalizeBurpIssues(
        issues,
        config.engagementHandle,
        config.burpConfig.edition
      );
      if (normalized.length > 0) {
        const db = await import("./db-LCEQKGBV.js");
        let imported = 0;
        let deduplicated = 0;
        for (const finding of normalized) {
          try {
            const result = await db.createBugBountyFinding({
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
              metadata: finding.metadata
            });
            if (result.deduplicated) {
              deduplicated++;
            } else {
              imported++;
            }
          } catch (err) {
            console.warn(`[BurpAutoScan] Failed to import finding: ${err.message}`);
          }
        }
        state.importedCount = imported;
        state.deduplicatedCount = deduplicated;
        state.normalizedFindings = normalized;
        console.log(
          `[BurpAutoScan] Imported ${imported}/${normalized.length} findings from scan ${state.scanId}` + (deduplicated > 0 ? ` (${deduplicated} duplicates skipped)` : "")
        );
      }
      state.status = "completed";
      state.completedAt = Date.now();
      await persistUpdate(state);
      broadcastBurpUpdate(config.engagementId, state);
      try {
        const db = await import("./db-LCEQKGBV.js");
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
            durationMs: (state.completedAt || Date.now()) - state.startedAt
          },
          userId: config.userId
        });
      } catch (e) {
        console.warn(`[BurpAutoScan] Timeline event failed: ${e.message}`);
      }
      const scanDurationMs = (state.completedAt || Date.now()) - state.startedAt;
      const isSuspiciousFastComplete = scanDurationMs < 6e4 && normalized.length === 0;
      if (isSuspiciousFastComplete && !config._isAuditOnlyRetry) {
        console.log(
          `[BurpAutoScan] Suspicious fast completion: ${Math.round(scanDurationMs / 1e3)}s with 0 findings. Retrying with audit-only mode (no crawl) to force Burp to audit the provided URLs directly.`
        );
        try {
          const db = await import("./db-LCEQKGBV.js");
          await db.addTimelineEvent({
            engagementId: config.engagementId,
            eventType: "scan_warning",
            title: `\u26A0\uFE0F Burp Suite Fast-Complete Detected (${Math.round(scanDurationMs / 1e3)}s, 0 findings)`,
            description: `Burp scan completed suspiciously fast with no findings. This usually means Burp couldn't reach the target or the crawl failed. Retrying with audit-only mode on ${state.targetUrls.length} URLs. Diagnostics: edition=${config.burpConfig.edition}, baseUrl=${config.burpConfig.baseUrl}, targetUrls=${state.targetUrls.slice(0, 3).join(", ")}`,
            severity: "warning",
            sourceModule: "burp-auto-scan:fast-complete-retry"
          });
        } catch {
        }
        const retryConfig = {
          ...config,
          scanConfigName: "Audit checks - all"
          // Skip crawling, audit URLs directly
        };
        retryConfig._isAuditOnlyRetry = true;
        const retryState = {
          ...state,
          scanId: null,
          status: "launching",
          progress: 0,
          issueCount: 0,
          importedCount: 0,
          startedAt: Date.now(),
          completedAt: null,
          error: null,
          lastPollAt: null,
          pollCount: 0
        };
        activeBurpScans.set(key, retryState);
        const retryDbId = await persistCreate(retryState, "Audit checks - all (retry)");
        if (retryDbId) retryState.dbRecordId = retryDbId;
        await launchAndPoll(retryConfig, retryState, key);
        return;
      }
      try {
        await feedBurpFindingsToExploitEngine(config, normalized);
      } catch (e) {
        console.warn(`[BurpAutoScan] Exploit matching failed: ${e.message}`);
      }
      try {
        const { runSeverityEscalation } = await import("./zap-burp-pipeline-V47KHQPO.js");
        const escalation = await runSeverityEscalation(config.engagementId);
        if (escalation.escalatedCount > 0 || escalation.priorityFlaggedCount > 0) {
          console.log(
            `[BurpAutoScan] Severity escalation: ${escalation.escalatedCount} escalated, ${escalation.priorityFlaggedCount} flagged for priority exploitation`
          );
          const db = await import("./db-LCEQKGBV.js");
          await db.addTimelineEvent({
            engagementId: config.engagementId,
            eventType: "finding_discovered",
            title: `Cross-Tool Severity Escalation: ${escalation.escalatedCount} findings promoted`,
            description: [
              `${escalation.totalEvaluated} findings evaluated after Burp scan completion.`,
              `${escalation.escalatedCount} severity escalations (cross-tool confirmed).`,
              `${escalation.priorityFlaggedCount} flagged for priority exploitation.`,
              Object.entries(escalation.severityBreakdown).map(([sev, count]) => `${sev}: ${count}`).join(", ")
            ].filter(Boolean).join(" "),
            severity: escalation.escalatedCount > 0 ? "high" : "info",
            metadata: {
              source: "burp_completion_escalation",
              totalEvaluated: escalation.totalEvaluated,
              escalatedCount: escalation.escalatedCount,
              priorityFlaggedCount: escalation.priorityFlaggedCount,
              severityBreakdown: escalation.severityBreakdown,
              topResults: escalation.results.slice(0, 10).map((r) => ({
                finding: r.findingId,
                from: r.originalSeverity,
                to: r.escalatedSeverity,
                url: r.url
              }))
            },
            sourceModule: "burp-auto-scan:severity-escalation"
          });
        } else {
          console.log(`[BurpAutoScan] Severity escalation: no findings to escalate (${escalation.totalEvaluated} evaluated)`);
        }
      } catch (e) {
        console.warn(`[BurpAutoScan] Severity escalation failed: ${e.message}`);
      }
      try {
        await notifyBurpScanComplete(config, state);
      } catch (e) {
        console.warn(`[BurpAutoScan] Completion callback failed: ${e.message}`);
      }
    } catch (err) {
      state.status = "failed";
      state.error = `Failed to import findings: ${err.message}`;
      state.completedAt = Date.now();
      await persistUpdate(state);
      broadcastBurpUpdate(config.engagementId, state);
    }
  }
}
async function feedBurpFindingsToExploitEngine(config, findings) {
  if (findings.length === 0) return;
  console.log(
    `[BurpAutoScan\u2192Exploit] Feeding ${findings.length} Burp findings into exploit matching for engagement #${config.engagementId}`
  );
  const db = await import("./db-LCEQKGBV.js");
  const highSeverity = findings.filter((f) => f.severityRating === "critical" || f.severityRating === "high");
  const mediumSeverity = findings.filter((f) => f.severityRating === "medium");
  const exploitQueries = [];
  for (const finding of [...highSeverity, ...mediumSeverity]) {
    const terms = [];
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
    if (finding.cweId) terms.push(`CWE-${finding.cweId}`);
    if (terms.length === 0) terms.push(finding.title);
    exploitQueries.push({
      findingTitle: finding.title,
      cweId: finding.cweId,
      assetIdentifier: finding.assetIdentifier,
      severity: finding.severityRating,
      searchTerms: terms
    });
  }
  if (exploitQueries.length === 0) {
    console.log(`[BurpAutoScan\u2192Exploit] No high/medium findings to match against exploits`);
    return;
  }
  try {
    const matchResults = [];
    for (const query of exploitQueries) {
      try {
        const exploits = await searchExploitsForFinding(db, query);
        if (exploits.length > 0) {
          matchResults.push({
            finding: query.findingTitle,
            exploitCount: exploits.length,
            topExploits: exploits.slice(0, 3).map((e) => e.title || e.name || e.id)
          });
        }
      } catch {
      }
    }
    if (matchResults.length > 0) {
      console.log(
        `[BurpAutoScan\u2192Exploit] Matched ${matchResults.length} findings to exploits for engagement #${config.engagementId}`
      );
      try {
        await db.addTimelineEvent({
          engagementId: config.engagementId,
          eventType: "tool_output",
          title: "Burp\u2192Exploit Chain: Automatic Exploit Matching",
          description: `${matchResults.length} Burp findings matched to known exploits. Top matches: ${matchResults.slice(0, 5).map((m) => `${m.finding} (${m.exploitCount} exploits)`).join(", ")}`,
          metadata: {
            source: "burp_auto_scan",
            matchResults,
            totalFindings: findings.length,
            matchedFindings: matchResults.length
          },
          userId: config.userId
        });
      } catch (e) {
        console.warn(`[BurpAutoScan\u2192Exploit] Timeline event failed: ${e.message}`);
      }
    }
  } catch (err) {
    console.warn(`[BurpAutoScan\u2192Exploit] Exploit matching pipeline error: ${err.message}`);
  }
}
async function searchExploitsForFinding(db, query) {
  const results = [];
  if (query.cweId) {
    try {
      const cweExploits = await db.searchExploitsByCWE?.(query.cweId);
      if (cweExploits?.length) results.push(...cweExploits);
    } catch {
    }
  }
  for (const term of query.searchTerms.slice(0, 3)) {
    try {
      const keywordExploits = await db.searchExploitsByKeyword?.(term);
      if (keywordExploits?.length) results.push(...keywordExploits);
    } catch {
    }
  }
  const seen = /* @__PURE__ */ new Set();
  return results.filter((e) => {
    const id = String(e.id || e.exploitId || e.title);
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}
function broadcastBurpUpdate(engagementId, state) {
  try {
    const { broadcastOpsUpdate } = (init_engagement_orchestrator(), __toCommonJS(engagement_orchestrator_exports));
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
        error: state.error
      }
    });
  } catch {
  }
}
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function extractScopeUrls(engagement, opsState) {
  const urls = /* @__PURE__ */ new Set();
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
    } catch {
    }
  }
  if (engagement.targetUrl) {
    urls.add(engagement.targetUrl);
  }
  if (engagement.targetDomain) {
    urls.add(`https://${engagement.targetDomain}`);
    urls.add(`http://${engagement.targetDomain}`);
  }
  if (engagement.rptScopeAssets) {
    const assets = Array.isArray(engagement.rptScopeAssets) ? engagement.rptScopeAssets : [];
    for (const a of assets) {
      if (typeof a === "string") {
        if (a.startsWith("http")) urls.add(a);
        else if (a.includes(".")) urls.add(`https://${a}`);
      }
    }
  }
  if (opsState?.assets) {
    for (const asset of opsState.assets) {
      if (asset.hostname) {
        urls.add(`https://${asset.hostname}`);
        urls.add(`http://${asset.hostname}`);
      }
      if (asset.webApps) {
        for (const wa of asset.webApps) {
          if (wa.url) urls.add(wa.url);
          if (wa.hostname) urls.add(`https://${wa.hostname}`);
        }
      }
    }
  }
  if (engagement.scopeAssets) {
    try {
      const scopeAssets = typeof engagement.scopeAssets === "string" ? JSON.parse(engagement.scopeAssets) : engagement.scopeAssets;
      if (Array.isArray(scopeAssets)) {
        for (const sa of scopeAssets) {
          if (sa?.name && (sa.name.startsWith("http") || sa.name.includes("."))) {
            const url = sa.name.startsWith("http") ? sa.name : `https://${sa.name}`;
            urls.add(url);
          }
        }
      }
    } catch {
    }
  }
  return [...urls].filter((u) => u.startsWith("http://") || u.startsWith("https://"));
}
function getBurpAutoScanStats() {
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
async function getBurpAutoScanStatsWithHistory() {
  const memStats = getBurpAutoScanStats();
  try {
    const db = await import("./db-LCEQKGBV.js");
    const dbStats = await db.getDbBurpScanStats();
    return {
      active: memStats.active,
      completed: Math.max(memStats.completed, dbStats.completed),
      failed: Math.max(memStats.failed, dbStats.failed),
      totalIssues: Math.max(memStats.totalIssues, dbStats.totalIssues),
      totalImported: Math.max(memStats.totalImported, dbStats.totalImported),
      totalScans: dbStats.total
    };
  } catch {
    return { ...memStats, totalScans: memStats.active + memStats.completed + memStats.failed };
  }
}
function onBurpScanComplete(callback) {
  completionCallbacks.push(callback);
}
async function notifyBurpScanComplete(config, state) {
  if (completionCallbacks.length === 0) return;
  console.log(
    `[BurpAutoScan] Notifying ${completionCallbacks.length} completion callback(s) for scan ${state.scanId}`
  );
  for (const callback of completionCallbacks) {
    try {
      await callback(config, state);
    } catch (e) {
      console.warn(`[BurpAutoScan] Completion callback error: ${e.message}`);
    }
  }
}
var activeBurpScans, completionCallbacks;
var init_burp_auto_scan = __esm({
  "server/lib/burp-auto-scan.ts"() {
    init_burpsuite_connector();
    activeBurpScans = /* @__PURE__ */ new Map();
    completionCallbacks = [];
  }
});

export {
  launchBurpAutoScan,
  getBurpAutoScanState,
  getEngagementBurpScans,
  getEngagementBurpScanHistory,
  cancelBurpAutoScan,
  onEngagementVulnDetectionPhase,
  extractScopeUrls,
  getBurpAutoScanStats,
  getBurpAutoScanStatsWithHistory,
  onBurpScanComplete,
  init_burp_auto_scan
};
