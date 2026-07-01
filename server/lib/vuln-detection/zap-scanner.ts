/**
 * Vulnerability Detection — ZAP Web Application Scanner
 *
 * Extracted from engagement-orchestrator.ts executeVulnDetection.
 *
 * Responsibilities:
 *   1. Filter web application assets (HTTP/HTTPS within RoE scope)
 *   2. Training lab URL resolution (Docker DNS → reverse proxy)
 *   3. Port prioritization (primary first, co-hosted last)
 *   4. WAF detection and evasion profile application
 *   5. LLM-generated ZAP scan configuration
 *   6. Authenticated scanning (confirmed creds + training lab defaults)
 *   7. ZAP scan execution with retry and Burp fallback
 *   8. Scan polling with stall detection and timeout
 *   9. Finding extraction (detailed DB query with summary fallback)
 *   10. Deferred ZAP→Burp re-feed for discovered URLs
 *   11. Resume checkpoint support
 */

import type { VulnDetectionContext } from "./index";

// ─── Result Types ───────────────────────────────────────────────────────────

export interface ZapScanResult {
  findingsCount: number;
  webAppsScanned: number;
  wafDetections: number;
  burpFallbacks: number;
  timeouts: number;
}

// ─── Training Lab URL Resolution ────────────────────────────────────────────

const TRAINING_LAB_ZAP_URL_MAP: Record<string, { zapBaseUrl: string; skipPortScan: boolean }> = {
  "juiceshop.lab.aceofcloud.io": { zapBaseUrl: "https://scan.aceofcloud.io/lab/juice-shop", skipPortScan: true },
  "altoro.lab.aceofcloud.io": { zapBaseUrl: "http://altoro.lab.aceofcloud.io/altoromutual", skipPortScan: true },
  "brokencrystals.lab.aceofcloud.io": { zapBaseUrl: "https://scan.aceofcloud.io/lab/broken-crystals", skipPortScan: true },
};

export function resolveTrainingLabZapUrl(hostname: string): { zapBaseUrl: string; skipPortScan: boolean } | null {
  return TRAINING_LAB_ZAP_URL_MAP[hostname.toLowerCase()] || null;
}

// ─── Port Prioritization ────────────────────────────────────────────────────

const INFRA_PORTS = new Set([31337, 8834, 9392, 5432, 3306, 27017, 6379]);
const COMMON_WEB_PORTS = new Set([80, 443, 8080, 8443, 3000, 3001, 5000, 5001, 8000, 8001, 8888, 9000, 9090, 1337, 4200, 4443]);
const CO_HOSTED_INDICATORS = ["nextcloud", "gitea", "gitlab", "grafana", "prometheus", "portainer", "traefik", "phpmyadmin"];

function isCoHostedPort(port: any): boolean {
  const version = (port.version || "").toLowerCase();
  const service = (port.service || "").toLowerCase();
  return CO_HOSTED_INDICATORS.some(ind => version.includes(ind) || service.includes(ind));
}

export function getFilteredWebPorts(asset: any, state: any): any[] {
  const webPorts = asset.ports.filter((p: any) =>
    (["http", "https", "http-proxy", "http-alt"].includes(p.service) || COMMON_WEB_PORTS.has(p.port))
    && !INFRA_PORTS.has(p.port)
  );
  webPorts.sort((a: any, b: any) => {
    const aPrimary = (a.port === 80 || a.port === 443) ? 0 : 1;
    const bPrimary = (b.port === 80 || b.port === 443) ? 0 : 1;
    if (aPrimary !== bPrimary) return aPrimary - bPrimary;
    const aCoHosted = isCoHostedPort(a) ? 1 : 0;
    const bCoHosted = isCoHostedPort(b) ? 1 : 0;
    if (aCoHosted !== bCoHosted) return aCoHosted - bCoHosted;
    return a.port - b.port;
  });
  const httpxLivePorts: Array<{ port: number; statusCode: number }> = (asset as any).httpxLivePorts || [];
  const livePortNumbers = httpxLivePorts.filter(p => p.statusCode >= 200 && p.statusCode < 400).map(p => p.port);
  if (state.trainingLabMode && livePortNumbers.length > 0) {
    const filtered = webPorts.filter((wp: any) => livePortNumbers.includes(wp.port));
    return filtered.length > 0 ? filtered : webPorts;
  }
  return webPorts;
}

// ─── Training Lab Default Credentials ───────────────────────────────────────

export const TRAINING_LAB_DEFAULT_CREDS: Record<string, { username: string; password: string; loginPath: string }> = {
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
  "broken-crystals": { username: "admin", password: "admin", loginPath: "/api/auth/login" },
};

export const TRAINING_LAB_INDICATORS = [
  "brokencrystals", "broken-crystals", "dvwa", "juiceshop",
  "juice-shop", "bwapp", "altoro", "hackazon", "testphp",
  "webgoat", "mutillidae", "bodgeit", "gruyere",
];

export function detectTrainingLabCreds(hostname: string, targetUrl: string): { username: string; password: string; loginPath: string } | undefined {
  const hostLower = hostname.toLowerCase();
  const urlLower = targetUrl.toLowerCase();
  for (const [labKey, creds] of Object.entries(TRAINING_LAB_DEFAULT_CREDS)) {
    if (hostLower.includes(labKey) || urlLower.includes(labKey)) return creds;
  }
  return undefined;
}

// ─── Training Lab Seed URLs ─────────────────────────────────────────────────

const TRAINING_LAB_SEED_URLS: Record<string, string[]> = {
  "juiceshop": ["/", "/#/login", "/#/search", "/#/contact", "/#/complain", "/#/about", "/#/register", "/#/basket", "/#/score-board", "/rest/products/search?q=", "/api/Products", "/api/Challenges", "/rest/user/login", "/api/Feedbacks", "/ftp", "/redirect?to=/"],
  "dvwa": ["/", "/login.php", "/index.php", "/vulnerabilities/sqli/", "/vulnerabilities/sqli_blind/", "/vulnerabilities/xss_r/", "/vulnerabilities/xss_s/", "/vulnerabilities/exec/", "/vulnerabilities/fi/", "/vulnerabilities/upload/", "/vulnerabilities/csrf/", "/vulnerabilities/brute/"],
  "altoro": ["/", "/login.jsp", "/index.jsp", "/bank/main.jsp", "/bank/transaction.jsp", "/search.jsp", "/feedback.jsp", "/altoromutual/", "/altoromutual/login.jsp", "/altoromutual/bank/main.jsp"],
  "testphp": ["/", "/login.php", "/listproducts.php?cat=1", "/artists.php?artist=1", "/search.php?test=query", "/comment.php", "/guestbook.php"],
  "hackazon": ["/", "/user/login", "/user/register", "/search?searchString=test", "/product/view?id=1", "/cart", "/checkout", "/api/product", "/admin"],
  "brokencrystals": ["/", "/api/auth/login", "/api/testimonials", "/api/testimonials/count?query=test", "/api/metadata", "/api/file?path=test", "/api/render", "/api/users", "/swagger", "/api/spawn", "/api/goto?url=https://example.com"],
};

export function getZapSeedUrls(hostname: string, targetUrl: string, trainingLabMode: boolean): string[] | undefined {
  const hostLower = hostname.toLowerCase();
  const table = trainingLabMode ? TRAINING_LAB_SEED_URLS : { brokencrystals: TRAINING_LAB_SEED_URLS["brokencrystals"] };
  for (const [labKey, paths] of Object.entries(table)) {
    if (hostLower.includes(labKey)) return paths.map(p => `${targetUrl}${p}`);
  }
  return undefined;
}

// ─── Tech Hints Builder ─────────────────────────────────────────────────────

export function buildTechHints(asset: any, targetProfile: any): string[] {
  const serviceVersions = asset.ports.map((p: any) => p.version).filter(Boolean) as string[];
  const httpxTechs = asset.passiveRecon?.technologies || [];
  const httpxHeaders = (asset as any).httpxResponseHeaders || {};
  const headerHints: string[] = [];
  if (httpxHeaders["x-powered-by"]) headerHints.push(`X-Powered-By: ${httpxHeaders["x-powered-by"]}`);
  if (httpxHeaders["server"]) headerHints.push(`Server: ${httpxHeaders["server"]}`);
  if (httpxHeaders["set-cookie"]) headerHints.push(`Set-Cookie: ${httpxHeaders["set-cookie"].substring(0, 100)}`);
  const techHints = [...new Set([...serviceVersions, ...httpxTechs, ...headerHints])];
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

// ─── ZAP Polling Configuration ──────────────────────────────────────────────

export interface ZapPollingConfig {
  timeoutMinutes: number;
  maxConsecutivePollFailures: number;
  maxStallPolls: number;
  pollIntervalMs: number;
}

export function getZapPollingConfig(hostname: string, trainingLabMode: boolean, hasWafEvasion: boolean): ZapPollingConfig {
  const isKnownLab = trainingLabMode || TRAINING_LAB_INDICATORS.some(lab => hostname.toLowerCase().includes(lab));
  return {
    timeoutMinutes: isKnownLab ? 90 : 30,
    maxConsecutivePollFailures: isKnownLab ? 8 : 5,
    maxStallPolls: hasWafEvasion ? (trainingLabMode ? 40 : 24) : (trainingLabMode ? 12 : 8),
    pollIntervalMs: 15000,
  };
}

// ─── Scan Target Builder ────────────────────────────────────────────────────

export interface ZapScanTarget { targetUrl: string; dedupKey: string; }

export function buildZapScanTargets(asset: any, filteredWebPorts: any[], labZapUrl: any, scannedUrls: Set<string>): ZapScanTarget[] {
  const targets: ZapScanTarget[] = [];
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

// ─── Main ZAP Execution Pipeline ────────────────────────────────────────────

/**
 * Execute the full ZAP web application scanning pipeline.
 *
 * Handles: asset filtering, WAF detection, LLM config, authenticated scanning,
 * retry with Burp fallback, polling with stall detection, finding extraction,
 * and deferred ZAP→Burp re-feed.
 */
export async function executeZapScanning(ctx: VulnDetectionContext): Promise<ZapScanResult> {
  const { state, addLog, acquireScanSlot, genId, broadcastReconFinding, broadcastOpsUpdate, isInRoeScope, persistOpsStateDebounced } = ctx;

  const result: ZapScanResult = { findingsCount: 0, webAppsScanned: 0, wafDetections: 0, burpFallbacks: 0, timeouts: 0 };

  // T0-10 Fix: Use COMMON_WEB_PORTS for asset filtering (not just 80/443/8080/8443)
  // This ensures assets with HTTP services on non-standard ports (3000, 5000, 8000, etc.) are included
  const webApps = state.assets.filter((a: any) =>
    (a.type === "web_app" || a.type === "web" || a.ports.some((p: any) => ["http", "https", "http-proxy", "http-alt"].includes(p.service) || COMMON_WEB_PORTS.has(p.port)))
    && isInRoeScope(state, a.hostname, a.ip)
  );
  result.webAppsScanned = webApps.length;
  if (webApps.length === 0) { addLog(state, { phase: "vuln_detection", type: "info", title: "ZAP: No web apps", detail: "No HTTP/HTTPS assets in RoE scope" }); return result; }

  const scannedTargetUrls = new Set<string>();

  for (const webApp of webApps) {
    const labZapUrl = resolveTrainingLabZapUrl(webApp.hostname);
    if (labZapUrl) {
      const dk = `zap-proxy:${labZapUrl.zapBaseUrl}`;
      if (!scannedTargetUrls.has(dk)) { scannedTargetUrls.add(dk); (webApp as any).resolvedZapUrl = labZapUrl.zapBaseUrl; }
    }
    const filteredWebPorts = getFilteredWebPorts(webApp, state);
    const scanTargets = buildZapScanTargets(webApp, filteredWebPorts, labZapUrl, scannedTargetUrls);

    for (const { targetUrl, dedupKey } of scanTargets) {
      if (scannedTargetUrls.has(dedupKey)) continue;
      if (state.completedScans?.zapCompleted.has(dedupKey)) continue;
      scannedTargetUrls.add(dedupKey);

      let zapRelease: (() => void) | null = null;
      try {
        zapRelease = await acquireScanSlot("zap", state.engagementId);

        // WAF detection
        let wafVendor: string | undefined;
        const tp = state.targetProfiles?.[webApp.hostname];
        if (tp?.waf?.detected) { wafVendor = tp.waf.vendor; webApp.wafDetected = wafVendor; }
        try {
          const { detectWafEnhanced } = await import("../waf-detector");
          const wr = await detectWafEnhanced(targetUrl);
          if (wr?.detected) { wafVendor = wr.vendor; webApp.wafDetected = wafVendor; state.stats.wafDetections++; result.wafDetections++; }
          if (wr?.activeProbe) (webApp as any).activeProbe = wr.activeProbe;
        } catch { /* best-effort */ }

        // LLM config
        const techHints = buildTechHints(webApp, tp);
        const webCreds = (webApp.confirmedCredentials || []).filter((c: any) => ["http", "https", "web_admin", "http-form", "http-get", "http-post"].includes(c.service) || c.protocol === "http" || c.protocol === "https");
        const hasConfirmedCreds = webCreds.length > 0;
        const trainingLabCreds = !hasConfirmedCreds ? detectTrainingLabCreds(webApp.hostname, targetUrl) : undefined;
        const authHints = hasConfirmedCreds
          ? { type: "form", loginUrl: `${targetUrl}/login`, credentials: { username: webCreds[0].username, password: webCreds[0].password } }
          : trainingLabCreds ? { type: "form", loginUrl: `${targetUrl}${trainingLabCreds.loginPath}`, credentials: { username: trainingLabCreds.username, password: trainingLabCreds.password } } : undefined;

        const { generateLLMScanConfig, startScan, configureZapAuthentication } = await import("../zap-scanner");
        let llmConfig = await generateLLMScanConfig({ targetUrl, scanMode: "active", techStackHints: techHints, authHints, scopeConstraints: [`Only scan ${webApp.hostname}`] });
        if (wafVendor) { try { const { applyWafEvasionConfig } = await import("../zap-scanner"); llmConfig = applyWafEvasionConfig(llmConfig, wafVendor); } catch {} }
        if (tp) { try { const { getZapEvasionOverrides } = await import("../evasion-cli-adapter.js"); const o = getZapEvasionOverrides(tp); if (o) { llmConfig.activeScanConfig.delayInMs = Math.max(llmConfig.activeScanConfig.delayInMs || 0, o.delayInMs); llmConfig.activeScanConfig.threadPerHost = Math.min(llmConfig.activeScanConfig.threadPerHost || 5, o.threadPerHost); } } catch {} }

        const zapSeedUrls = getZapSeedUrls(webApp.hostname, targetUrl, state.trainingLabMode || false);

        // Start scan with retry
        let zapScanResult: any; let zapStarted = false;
        const ZAP_RETRY_DELAYS = [0, 15000, 30000];
        for (let attempt = 0; attempt < ZAP_RETRY_DELAYS.length; attempt++) {
          if (attempt > 0) await new Promise(r => setTimeout(r, ZAP_RETRY_DELAYS[attempt]));
          try {
            zapScanResult = await startScan({ targetUrl, scanType: "full", scanMode: "active", userId: ctx.operatorCtx.id, scanName: `EngOps-${state.engagementId}-${webApp.hostname}-run${Date.now()}`, llmConfig, discoveredTechnologies: techHints, trainingLabMode: state.trainingLabMode || false, seedUrls: zapSeedUrls });
            zapStarted = true; break;
          } catch (err: any) { addLog(state, { phase: "vuln_detection", type: "warning", title: `ZAP Start Error: ${targetUrl}`, detail: err.message }); }
        }

        if (!zapStarted) {
          result.burpFallbacks++;
          try { const { onEngagementVulnDetectionPhase } = await import("../burp-auto-scan"); await onEngagementVulnDetectionPhase(state.engagementId, ctx.operatorCtx.id, ctx.engagement?.handle || `eng-${state.engagementId}`, [targetUrl], state.scanMode || "active", hasConfirmedCreds ? { username: webCreds[0].username, password: webCreds[0].password } : undefined, techHints); } catch {}
          continue;
        }

        // Auth config
        const zapScanId = zapScanResult?.scanId;
        if (zapScanId && hasConfirmedCreds) { try { await configureZapAuthentication(`scan-${zapScanId}`, targetUrl, webCreds, { techHints } as any); } catch {} }
        else if (zapScanId && trainingLabCreds) { try { const sc = [{ username: trainingLabCreds.username, password: trainingLabCreds.password, service: "http-form", source: "training_lab_defaults", confirmedAt: Date.now() }]; await configureZapAuthentication(`scan-${zapScanId}`, targetUrl, sc, { techHints, loginPath: trainingLabCreds.loginPath } as any); (webApp as any).trainingLabCreds = trainingLabCreds; } catch {} }

        state.stats.zapScansRun++;
        broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });

        // Poll
        if (zapScanId) {
          const hasWafEvasion = state.assets?.some((a: any) => a.wafDetected);
          const pc = getZapPollingConfig(webApp.hostname, state.trainingLabMode || false, hasWafEvasion);
          const timeout = Date.now() + pc.timeoutMinutes * 60 * 1000;
          let done = false, consecutiveFails = 0, stallCount = 0, lastKey = "";
          const { pollScanProgress } = await import("../zap-scanner");

          while (!done && Date.now() < timeout) {
            try {
              const p = await pollScanProgress(zapScanId);
              consecutiveFails = 0;
              if (p.status === "completed" || p.status === "error" || p.status === "quarantined") {
                done = true;
                // Log quarantine events for engagement visibility
                if (p.status === "quarantined") {
                  addLog(state, { phase: "vuln_detection", type: "warning", title: `ZAP Scan Quarantined: ${targetUrl}`, detail: `Scan #${zapScanId} quarantined: ${(p as any).quarantineReason || "Gate verification failed"}. Results may be unreliable.` });
                }
                try {
                  const { getDb } = await import("../../db");
                  const db = await getDb();
                  if (db) {
                    const { webAppFindings } = await import("../../../drizzle/schema");
                    const { eq } = await import("drizzle-orm");
                    const findings = await db.select().from(webAppFindings).where(eq(webAppFindings.scanId, zapScanId));
                    let count = 0;
                    for (const f of findings) {
                      if ((f.severity || "info") === "info") continue;
                      // Mark findings from quarantined scans with lower confidence
                      const tier = p.status === "quarantined" ? "unverified" as const : "confirmed" as const;
                      webApp.zapFindings.push({ alert: f.alertName || "Unknown", risk: f.severity, url: f.url || targetUrl });
                      webApp.vulns.push({ id: genId(), severity: f.severity, title: `[ZAP] ${f.alertName || "Unknown"}`, source: "zap", corroborationTier: tier, evidenceDetail: [f.method, f.url, f.param ? `Param: ${f.param}` : ""].filter(Boolean).join(" "), rawEvidence: [f.attack, f.evidence].filter(Boolean).join("\n").slice(0, 4000), attack: f.attack, method: f.method, param: f.param, url: f.url } as any);
                      count++;
                    }
                    state.stats.vulnsFound += count; result.findingsCount += count;
                  }
                } catch { const c = p.alertCounts || { high: 0, medium: 0, low: 0 }; const t = (c.high || 0) + (c.medium || 0) + (c.low || 0); state.stats.vulnsFound += t; result.findingsCount += t; }
              } else {
                const key = `${p.spiderProgress}:${p.activeScanProgress}:${p.urlsFound}`;
                if (key === lastKey) stallCount++; else { stallCount = 0; lastKey = key; }
                if (stallCount >= pc.maxStallPolls) { done = true; }
                else { if ((state as any)._heartbeatRef) (state as any)._heartbeatRef.lastActivityAt = Date.now(); await new Promise(r => setTimeout(r, pc.pollIntervalMs)); }
              }
            } catch { consecutiveFails++; if (consecutiveFails >= pc.maxConsecutivePollFailures) done = true; else await new Promise(r => setTimeout(r, 20000)); }
          }
          if (!done) result.timeouts++;
        }

        // Store tool result + emit events
        const zapFindings = webApp.zapFindings?.filter((f: any) => f.url === targetUrl) || [];
        webApp.toolResults.push({ tool: "zap", command: `zap-scan ${targetUrl}`, exitCode: 0, durationMs: 0, timedOut: false, findingCount: zapFindings.length, findings: zapFindings.map((f: any) => ({ severity: f.risk, title: f.alert })), executedAt: Date.now(), phase: "vuln_detection" });
        for (const zf of zapFindings) { broadcastReconFinding(state.engagementId, { target: webApp.hostname, vulnerability: zf.alert, severity: zf.risk || "info", tool: "zap" }); }
        if (state.completedScans) { state.completedScans.zapCompleted.add(dedupKey); state.completedScans.lastCheckpointAt = Date.now(); }
      } catch (e: any) {
        addLog(state, { phase: "vuln_detection", type: "error", title: `ZAP Error: ${targetUrl}`, detail: e.message });
        if (state.completedScans) { state.completedScans.zapCompleted.add(dedupKey); }
      } finally { if (zapRelease) zapRelease(); }
    }
    webApp.status = webApp.vulns.length > 0 ? "vulns_found" : "no_vulns";
  }

  // Deferred ZAP→Burp re-feed
  try {
    const ir = (state as any)._initialZapBurpPipelineResult;
    if (ir && (ir.urlSource === "scope_fallback" || ir.zapUrlsDiscovered === 0)) {
      const { getDb } = await import("../../db");
      const db = await getDb();
      if (db) {
        const { webAppScans } = await import("../../../drizzle/schema");
        const { eq, and, desc } = await import("drizzle-orm");
        const scans = await db.select().from(webAppScans).where(and(eq(webAppScans.engagementId, state.engagementId), eq(webAppScans.status, "completed"))).orderBy(desc(webAppScans.completedAt)).limit(1);
        if (scans.length > 0) { const { deferredZapBurpRefeed } = await import("../zap-burp-pipeline"); await deferredZapBurpRefeed({ engagementId: state.engagementId, userId: ctx.operatorCtx.id, engagementHandle: ctx.engagement?.handle || `eng-${state.engagementId}`, completedZapScanId: scans[0].id, initialPipelineResult: ir, appLogin: ctx.burpAppLogin }); }
      }
    }
  } catch {}

  return result;
}
