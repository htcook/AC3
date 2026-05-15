import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/vuln-detection/zap-scanner.ts
function resolveTrainingLabZapUrl(hostname) {
  return TRAINING_LAB_ZAP_URL_MAP[hostname.toLowerCase()] || null;
}
function isCoHostedPort(port) {
  const version = (port.version || "").toLowerCase();
  const service = (port.service || "").toLowerCase();
  return CO_HOSTED_INDICATORS.some((ind) => version.includes(ind) || service.includes(ind));
}
function getFilteredWebPorts(asset, state) {
  const webPorts = asset.ports.filter(
    (p) => (["http", "https", "http-proxy", "http-alt"].includes(p.service) || COMMON_WEB_PORTS.has(p.port)) && !INFRA_PORTS.has(p.port)
  );
  webPorts.sort((a, b) => {
    const aPrimary = a.port === 80 || a.port === 443 ? 0 : 1;
    const bPrimary = b.port === 80 || b.port === 443 ? 0 : 1;
    if (aPrimary !== bPrimary) return aPrimary - bPrimary;
    const aCoHosted = isCoHostedPort(a) ? 1 : 0;
    const bCoHosted = isCoHostedPort(b) ? 1 : 0;
    if (aCoHosted !== bCoHosted) return aCoHosted - bCoHosted;
    return a.port - b.port;
  });
  const httpxLivePorts = asset.httpxLivePorts || [];
  const livePortNumbers = httpxLivePorts.filter((p) => p.statusCode >= 200 && p.statusCode < 400).map((p) => p.port);
  if (state.trainingLabMode && livePortNumbers.length > 0) {
    const filtered = webPorts.filter((wp) => livePortNumbers.includes(wp.port));
    return filtered.length > 0 ? filtered : webPorts;
  }
  return webPorts;
}
function detectTrainingLabCreds(hostname, targetUrl) {
  const hostLower = hostname.toLowerCase();
  const urlLower = targetUrl.toLowerCase();
  for (const [labKey, creds] of Object.entries(TRAINING_LAB_DEFAULT_CREDS)) {
    if (hostLower.includes(labKey) || urlLower.includes(labKey)) return creds;
  }
  return void 0;
}
function getZapSeedUrls(hostname, targetUrl, trainingLabMode) {
  const hostLower = hostname.toLowerCase();
  const table = trainingLabMode ? TRAINING_LAB_SEED_URLS : { brokencrystals: TRAINING_LAB_SEED_URLS["brokencrystals"] };
  for (const [labKey, paths] of Object.entries(table)) {
    if (hostLower.includes(labKey)) return paths.map((p) => `${targetUrl}${p}`);
  }
  return void 0;
}
function buildTechHints(asset, targetProfile) {
  const serviceVersions = asset.ports.map((p) => p.version).filter(Boolean);
  const httpxTechs = asset.passiveRecon?.technologies || [];
  const httpxHeaders = asset.httpxResponseHeaders || {};
  const headerHints = [];
  if (httpxHeaders["x-powered-by"]) headerHints.push(`X-Powered-By: ${httpxHeaders["x-powered-by"]}`);
  if (httpxHeaders["server"]) headerHints.push(`Server: ${httpxHeaders["server"]}`);
  if (httpxHeaders["set-cookie"]) headerHints.push(`Set-Cookie: ${httpxHeaders["set-cookie"].substring(0, 100)}`);
  const techHints = [.../* @__PURE__ */ new Set([...serviceVersions, ...httpxTechs, ...headerHints])];
  if (targetProfile) {
    const fp = targetProfile.fingerprint;
    if (fp?.cms?.name) techHints.push(`CMS: ${fp.cms.name}${fp.cms.version ? ` v${fp.cms.version}` : ""}`);
    if (fp?.appFramework?.name) techHints.push(`Framework: ${fp.appFramework.name} (${fp.appFramework.language})`);
    if (fp?.databases?.length > 0) techHints.push(`Databases: ${fp.databases.join(", ")}`);
    if (targetProfile.waf?.detected) techHints.push(`WAF: ${targetProfile.waf.vendor} (${targetProfile.waf.type})`);
    if (targetProfile.cdn?.detected) techHints.push(`CDN: ${targetProfile.cdn.provider}`);
  }
  return techHints;
}
function getZapPollingConfig(hostname, trainingLabMode, hasWafEvasion) {
  const isKnownLab = trainingLabMode || TRAINING_LAB_INDICATORS.some((lab) => hostname.toLowerCase().includes(lab));
  return {
    timeoutMinutes: isKnownLab ? 90 : 30,
    maxConsecutivePollFailures: isKnownLab ? 8 : 5,
    maxStallPolls: hasWafEvasion ? trainingLabMode ? 40 : 24 : trainingLabMode ? 12 : 8,
    pollIntervalMs: 15e3
  };
}
function buildZapScanTargets(asset, filteredWebPorts, labZapUrl, scannedUrls) {
  const targets = [];
  if (labZapUrl && !scannedUrls.has(`zap-proxy-done:${labZapUrl.zapBaseUrl}`)) {
    targets.push({ targetUrl: labZapUrl.zapBaseUrl, dedupKey: `zap-proxy-done:${labZapUrl.zapBaseUrl}` });
  } else if (!labZapUrl) {
    if (filteredWebPorts.length > 0) {
      for (const wp of filteredWebPorts) {
        const protocol = wp.port === 443 || wp.port === 8443 || wp.service === "https" ? "https" : "http";
        const url = `${protocol}://${asset.hostname}${wp.port === 80 || wp.port === 443 ? "" : `:${wp.port}`}`;
        targets.push({ targetUrl: url, dedupKey: `${asset.hostname}:${wp.port}` });
      }
    } else {
      targets.push({ targetUrl: `http://${asset.hostname}`, dedupKey: `${asset.hostname}:80` }, { targetUrl: `https://${asset.hostname}`, dedupKey: `${asset.hostname}:443` });
    }
  }
  return targets;
}
async function executeZapScanning(ctx) {
  const { state, addLog, acquireScanSlot, genId, broadcastReconFinding, broadcastOpsUpdate, isInRoeScope, persistOpsStateDebounced } = ctx;
  const result = { findingsCount: 0, webAppsScanned: 0, wafDetections: 0, burpFallbacks: 0, timeouts: 0 };
  const webApps = state.assets.filter(
    (a) => (a.type === "web_app" || a.type === "web" || a.ports.some((p) => ["http", "https", "http-proxy", "http-alt"].includes(p.service) || COMMON_WEB_PORTS.has(p.port))) && isInRoeScope(state, a.hostname, a.ip)
  );
  result.webAppsScanned = webApps.length;
  if (webApps.length === 0) {
    addLog(state, { phase: "vuln_detection", type: "info", title: "ZAP: No web apps", detail: "No HTTP/HTTPS assets in RoE scope" });
    return result;
  }
  const scannedTargetUrls = /* @__PURE__ */ new Set();
  for (const webApp of webApps) {
    const labZapUrl = resolveTrainingLabZapUrl(webApp.hostname);
    if (labZapUrl) {
      const dk = `zap-proxy:${labZapUrl.zapBaseUrl}`;
      if (!scannedTargetUrls.has(dk)) {
        scannedTargetUrls.add(dk);
        webApp.resolvedZapUrl = labZapUrl.zapBaseUrl;
      }
    }
    const filteredWebPorts = getFilteredWebPorts(webApp, state);
    const scanTargets = buildZapScanTargets(webApp, filteredWebPorts, labZapUrl, scannedTargetUrls);
    for (const { targetUrl, dedupKey } of scanTargets) {
      if (scannedTargetUrls.has(dedupKey)) continue;
      if (state.completedScans?.zapCompleted.has(dedupKey)) continue;
      scannedTargetUrls.add(dedupKey);
      let zapRelease = null;
      try {
        zapRelease = await acquireScanSlot("zap", state.engagementId);
        let wafVendor;
        const tp = state.targetProfiles?.[webApp.hostname];
        if (tp?.waf?.detected) {
          wafVendor = tp.waf.vendor;
          webApp.wafDetected = wafVendor;
        }
        try {
          const { detectWafEnhanced } = await import("./waf-detector-D74LRGMZ.js");
          const wr = await detectWafEnhanced(targetUrl);
          if (wr?.detected) {
            wafVendor = wr.vendor;
            webApp.wafDetected = wafVendor;
            state.stats.wafDetections++;
            result.wafDetections++;
          }
          if (wr?.activeProbe) webApp.activeProbe = wr.activeProbe;
        } catch {
        }
        const techHints = buildTechHints(webApp, tp);
        const webCreds = (webApp.confirmedCredentials || []).filter((c) => ["http", "https", "web_admin", "http-form", "http-get", "http-post"].includes(c.service) || c.protocol === "http" || c.protocol === "https");
        const hasConfirmedCreds = webCreds.length > 0;
        const trainingLabCreds = !hasConfirmedCreds ? detectTrainingLabCreds(webApp.hostname, targetUrl) : void 0;
        const authHints = hasConfirmedCreds ? { type: "form", loginUrl: `${targetUrl}/login`, credentials: { username: webCreds[0].username, password: webCreds[0].password } } : trainingLabCreds ? { type: "form", loginUrl: `${targetUrl}${trainingLabCreds.loginPath}`, credentials: { username: trainingLabCreds.username, password: trainingLabCreds.password } } : void 0;
        const { generateLLMScanConfig, startScan, configureZapAuthentication } = await import("./zap-scanner-O5AMDABP.js");
        let llmConfig = await generateLLMScanConfig({ targetUrl, scanMode: "active", techStackHints: techHints, authHints, scopeConstraints: [`Only scan ${webApp.hostname}`] });
        if (wafVendor) {
          try {
            const { applyWafEvasionConfig } = await import("./zap-scanner-O5AMDABP.js");
            llmConfig = applyWafEvasionConfig(llmConfig, wafVendor);
          } catch {
          }
        }
        if (tp) {
          try {
            const { getZapEvasionOverrides } = await import("./evasion-cli-adapter-OVRHDAK4.js");
            const o = getZapEvasionOverrides(tp);
            if (o) {
              llmConfig.activeScanConfig.delayInMs = Math.max(llmConfig.activeScanConfig.delayInMs || 0, o.delayInMs);
              llmConfig.activeScanConfig.threadPerHost = Math.min(llmConfig.activeScanConfig.threadPerHost || 5, o.threadPerHost);
            }
          } catch {
          }
        }
        const zapSeedUrls = getZapSeedUrls(webApp.hostname, targetUrl, state.trainingLabMode || false);
        let zapScanResult;
        let zapStarted = false;
        const ZAP_RETRY_DELAYS = [0, 15e3, 3e4];
        for (let attempt = 0; attempt < ZAP_RETRY_DELAYS.length; attempt++) {
          if (attempt > 0) await new Promise((r) => setTimeout(r, ZAP_RETRY_DELAYS[attempt]));
          try {
            zapScanResult = await startScan({ targetUrl, scanType: "full", scanMode: "active", userId: ctx.operatorCtx.id, scanName: `EngOps-${state.engagementId}-${webApp.hostname}-run${Date.now()}`, llmConfig, discoveredTechnologies: techHints, trainingLabMode: state.trainingLabMode || false, seedUrls: zapSeedUrls });
            zapStarted = true;
            break;
          } catch (err) {
            addLog(state, { phase: "vuln_detection", type: "warning", title: `ZAP Start Error: ${targetUrl}`, detail: err.message });
          }
        }
        if (!zapStarted) {
          result.burpFallbacks++;
          try {
            const { onEngagementVulnDetectionPhase } = await import("./burp-auto-scan-HDSNCGKE.js");
            await onEngagementVulnDetectionPhase(state.engagementId, ctx.operatorCtx.id, ctx.engagement?.handle || `eng-${state.engagementId}`, [targetUrl], state.scanMode || "active", hasConfirmedCreds ? { username: webCreds[0].username, password: webCreds[0].password } : void 0, techHints);
          } catch {
          }
          continue;
        }
        const zapScanId = zapScanResult?.scanId;
        if (zapScanId && hasConfirmedCreds) {
          try {
            await configureZapAuthentication(`scan-${zapScanId}`, targetUrl, webCreds, { techHints });
          } catch {
          }
        } else if (zapScanId && trainingLabCreds) {
          try {
            const sc = [{ username: trainingLabCreds.username, password: trainingLabCreds.password, service: "http-form", source: "training_lab_defaults", confirmedAt: Date.now() }];
            await configureZapAuthentication(`scan-${zapScanId}`, targetUrl, sc, { techHints, loginPath: trainingLabCreds.loginPath });
            webApp.trainingLabCreds = trainingLabCreds;
          } catch {
          }
        }
        state.stats.zapScansRun++;
        broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
        if (zapScanId) {
          const hasWafEvasion = state.assets?.some((a) => a.wafDetected);
          const pc = getZapPollingConfig(webApp.hostname, state.trainingLabMode || false, hasWafEvasion);
          const timeout = Date.now() + pc.timeoutMinutes * 60 * 1e3;
          let done = false, consecutiveFails = 0, stallCount = 0, lastKey = "";
          const { pollScanProgress } = await import("./zap-scanner-O5AMDABP.js");
          while (!done && Date.now() < timeout) {
            try {
              const p = await pollScanProgress(zapScanId);
              consecutiveFails = 0;
              if (p.status === "completed" || p.status === "error") {
                done = true;
                try {
                  const { getDb } = await import("./db-EEYUM2OC.js");
                  const db = await getDb();
                  if (db) {
                    const { webAppFindings } = await import("./schema-AEHUE7AH.js");
                    const { eq } = await import("drizzle-orm");
                    const findings = await db.select().from(webAppFindings).where(eq(webAppFindings.scanId, zapScanId));
                    let count = 0;
                    for (const f of findings) {
                      if ((f.severity || "info") === "info") continue;
                      webApp.zapFindings.push({ alert: f.alertName || "Unknown", risk: f.severity, url: f.url || targetUrl });
                      webApp.vulns.push({ id: genId(), severity: f.severity, title: `[ZAP] ${f.alertName || "Unknown"}`, source: "zap", corroborationTier: "confirmed", evidenceDetail: [f.method, f.url, f.param ? `Param: ${f.param}` : ""].filter(Boolean).join(" "), rawEvidence: [f.attack, f.evidence].filter(Boolean).join("\n").slice(0, 4e3), attack: f.attack, method: f.method, param: f.param, url: f.url });
                      count++;
                    }
                    state.stats.vulnsFound += count;
                    result.findingsCount += count;
                  }
                } catch {
                  const c = p.alertCounts || { high: 0, medium: 0, low: 0 };
                  const t = (c.high || 0) + (c.medium || 0) + (c.low || 0);
                  state.stats.vulnsFound += t;
                  result.findingsCount += t;
                }
              } else {
                const key = `${p.spiderProgress}:${p.activeScanProgress}:${p.urlsFound}`;
                if (key === lastKey) stallCount++;
                else {
                  stallCount = 0;
                  lastKey = key;
                }
                if (stallCount >= pc.maxStallPolls) {
                  done = true;
                } else {
                  if (state._heartbeatRef) state._heartbeatRef.lastActivityAt = Date.now();
                  await new Promise((r) => setTimeout(r, pc.pollIntervalMs));
                }
              }
            } catch {
              consecutiveFails++;
              if (consecutiveFails >= pc.maxConsecutivePollFailures) done = true;
              else await new Promise((r) => setTimeout(r, 2e4));
            }
          }
          if (!done) result.timeouts++;
        }
        const zapFindings = webApp.zapFindings?.filter((f) => f.url === targetUrl) || [];
        webApp.toolResults.push({ tool: "zap", command: `zap-scan ${targetUrl}`, exitCode: 0, durationMs: 0, timedOut: false, findingCount: zapFindings.length, findings: zapFindings.map((f) => ({ severity: f.risk, title: f.alert })), executedAt: Date.now(), phase: "vuln_detection" });
        for (const zf of zapFindings) {
          broadcastReconFinding(state.engagementId, { target: webApp.hostname, vulnerability: zf.alert, severity: zf.risk || "info", tool: "zap" });
        }
        if (state.completedScans) {
          state.completedScans.zapCompleted.add(dedupKey);
          state.completedScans.lastCheckpointAt = Date.now();
        }
      } catch (e) {
        addLog(state, { phase: "vuln_detection", type: "error", title: `ZAP Error: ${targetUrl}`, detail: e.message });
        if (state.completedScans) {
          state.completedScans.zapCompleted.add(dedupKey);
        }
      } finally {
        if (zapRelease) zapRelease();
      }
    }
    webApp.status = webApp.vulns.length > 0 ? "vulns_found" : "no_vulns";
  }
  try {
    const ir = state._initialZapBurpPipelineResult;
    if (ir && (ir.urlSource === "scope_fallback" || ir.zapUrlsDiscovered === 0)) {
      const { getDb } = await import("./db-EEYUM2OC.js");
      const db = await getDb();
      if (db) {
        const { webAppScans } = await import("./schema-AEHUE7AH.js");
        const { eq, and, desc } = await import("drizzle-orm");
        const scans = await db.select().from(webAppScans).where(and(eq(webAppScans.engagementId, state.engagementId), eq(webAppScans.status, "completed"))).orderBy(desc(webAppScans.completedAt)).limit(1);
        if (scans.length > 0) {
          const { deferredZapBurpRefeed } = await import("./zap-burp-pipeline-FJHG4RCH.js");
          await deferredZapBurpRefeed({ engagementId: state.engagementId, userId: ctx.operatorCtx.id, engagementHandle: ctx.engagement?.handle || `eng-${state.engagementId}`, completedZapScanId: scans[0].id, initialPipelineResult: ir, appLogin: ctx.burpAppLogin });
        }
      }
    }
  } catch {
  }
  return result;
}
var TRAINING_LAB_ZAP_URL_MAP, INFRA_PORTS, COMMON_WEB_PORTS, CO_HOSTED_INDICATORS, TRAINING_LAB_DEFAULT_CREDS, TRAINING_LAB_INDICATORS, TRAINING_LAB_SEED_URLS;
var init_zap_scanner = __esm({
  "server/lib/vuln-detection/zap-scanner.ts"() {
    TRAINING_LAB_ZAP_URL_MAP = {
      "juiceshop.lab.aceofcloud.io": { zapBaseUrl: "https://scan.aceofcloud.io/lab/juice-shop", skipPortScan: true },
      "altoro.lab.aceofcloud.io": { zapBaseUrl: "http://altoro.lab.aceofcloud.io/altoromutual", skipPortScan: true },
      "brokencrystals.lab.aceofcloud.io": { zapBaseUrl: "https://scan.aceofcloud.io/lab/broken-crystals", skipPortScan: true }
    };
    INFRA_PORTS = /* @__PURE__ */ new Set([31337, 8834, 9392, 5432, 3306, 27017, 6379]);
    COMMON_WEB_PORTS = /* @__PURE__ */ new Set([80, 443, 8080, 8443, 3e3, 3001, 5e3, 5001, 8e3, 8001, 8888, 9e3, 9090, 1337, 4200, 4443]);
    CO_HOSTED_INDICATORS = ["nextcloud", "gitea", "gitlab", "grafana", "prometheus", "portainer", "traefik", "phpmyadmin"];
    TRAINING_LAB_DEFAULT_CREDS = {
      "dvwa": { username: "admin", password: "password", loginPath: "/login.php" },
      "bwapp": { username: "bee", password: "bug", loginPath: "/login.php" },
      "altoro": { username: "admin", password: "admin", loginPath: "/altoromutual/login.jsp" },
      "juiceshop": { username: "admin@juice-sh.op", password: "admin123", loginPath: "/#/login" },
      "juice-shop": { username: "admin@juice-sh.op", password: "admin123", loginPath: "/#/login" },
      "hackazon": { username: "test_user", password: "test_user", loginPath: "/user/login" },
      "testphp": { username: "test", password: "test", loginPath: "/login.php" },
      "webgoat": { username: "guest", password: "guest", loginPath: "/WebGoat/login" },
      "mutillidae": { username: "admin", password: "admin", loginPath: "/index.php?page=login.php" },
      "bodgeit": { username: "test@test.com", password: "test", loginPath: "/bodgeit/login.jsp" },
      "gruyere": { username: "test", password: "test", loginPath: "/login" },
      "brokencrystals": { username: "admin", password: "admin", loginPath: "/api/auth/login" },
      "broken-crystals": { username: "admin", password: "admin", loginPath: "/api/auth/login" }
    };
    TRAINING_LAB_INDICATORS = [
      "brokencrystals",
      "broken-crystals",
      "dvwa",
      "juiceshop",
      "juice-shop",
      "bwapp",
      "altoro",
      "hackazon",
      "testphp",
      "webgoat",
      "mutillidae",
      "bodgeit",
      "gruyere"
    ];
    TRAINING_LAB_SEED_URLS = {
      "juiceshop": ["/", "/#/login", "/#/search", "/#/contact", "/#/complain", "/#/about", "/#/register", "/#/basket", "/#/score-board", "/rest/products/search?q=", "/api/Products", "/api/Challenges", "/rest/user/login", "/api/Feedbacks", "/ftp", "/redirect?to=/"],
      "dvwa": ["/", "/login.php", "/index.php", "/vulnerabilities/sqli/", "/vulnerabilities/sqli_blind/", "/vulnerabilities/xss_r/", "/vulnerabilities/xss_s/", "/vulnerabilities/exec/", "/vulnerabilities/fi/", "/vulnerabilities/upload/", "/vulnerabilities/csrf/", "/vulnerabilities/brute/"],
      "altoro": ["/", "/login.jsp", "/index.jsp", "/bank/main.jsp", "/bank/transaction.jsp", "/search.jsp", "/feedback.jsp", "/altoromutual/", "/altoromutual/login.jsp", "/altoromutual/bank/main.jsp"],
      "testphp": ["/", "/login.php", "/listproducts.php?cat=1", "/artists.php?artist=1", "/search.php?test=query", "/comment.php", "/guestbook.php"],
      "hackazon": ["/", "/user/login", "/user/register", "/search?searchString=test", "/product/view?id=1", "/cart", "/checkout", "/api/product", "/admin"],
      "brokencrystals": ["/", "/api/auth/login", "/api/testimonials", "/api/testimonials/count?query=test", "/api/metadata", "/api/file?path=test", "/api/render", "/api/users", "/swagger", "/api/spawn", "/api/goto?url=https://example.com"]
    };
  }
});
init_zap_scanner();
export {
  TRAINING_LAB_DEFAULT_CREDS,
  TRAINING_LAB_INDICATORS,
  buildTechHints,
  buildZapScanTargets,
  detectTrainingLabCreds,
  executeZapScanning,
  getFilteredWebPorts,
  getZapPollingConfig,
  getZapSeedUrls,
  resolveTrainingLabZapUrl
};
