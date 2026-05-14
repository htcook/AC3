import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/vuln-detection/injection-scanner.ts
function getTrainingLabEndpoints(hostname) {
  const hostLower = hostname.toLowerCase();
  for (const [labKey, endpoints] of Object.entries(TRAINING_LAB_INJECTABLE_ENDPOINTS)) {
    if (hostLower.includes(labKey)) return endpoints;
  }
  return [];
}
async function performAuthHandoff(webApp, state, addLog) {
  const webCreds = webApp.confirmedCredentials || [];
  let cookieStr = webCreds.length > 0 ? webCreds[0]?.sessionCookie || "" : "";
  if (!cookieStr && webApp.trainingLabCreds?.sessionCookie) {
    cookieStr = webApp.trainingLabCreds.sessionCookie;
    return { cookieStr, method: "reused" };
  }
  if (state.trainingLabMode && !cookieStr && webCreds.length > 0) {
    const hostname = webApp.hostname.toLowerCase();
    const authBaseUrl = `http://${webApp.hostname}`;
    try {
      if (hostname.includes("juiceshop") || hostname.includes("juice-shop")) {
        const loginCred = webCreds.find((c) => c.loginPath === "/rest/user/login") || webCreds[0];
        const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
        const loginResult = await executeTool({ tool: "curl", args: `-s -X POST ${authBaseUrl}/rest/user/login -H "Content-Type: application/json" -d '{"email":"${loginCred.username}","password":"${loginCred.password}"}'`, timeout: 15 });
        if (loginResult.stdout) {
          try {
            const resp = JSON.parse(loginResult.stdout);
            const token = resp.authentication?.token || resp.token;
            if (token) {
              cookieStr = `token=${token}`;
              loginCred.sessionCookie = cookieStr;
              return { cookieStr, method: "jwt" };
            }
          } catch {
          }
        }
      } else if (hostname.includes("dvwa")) {
        const loginCred = webCreds.find((c) => c.loginPath === "/login.php") || webCreds[0];
        const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
        const getLogin = await executeTool({ tool: "curl", args: `-s -c /tmp/dvwa_cookies.txt -b /tmp/dvwa_cookies.txt ${authBaseUrl}/login.php`, timeout: 15 });
        const csrfMatch = getLogin.stdout?.match(/user_token.*?value=['"]([^'"]+)['"]/i);
        const loginResult = await executeTool({ tool: "curl", args: `-s -c /tmp/dvwa_cookies.txt -b /tmp/dvwa_cookies.txt -X POST ${authBaseUrl}/login.php -d "username=${loginCred.username}&password=${loginCred.password}&Login=Login&user_token=${csrfMatch?.[1] || ""}" -D -`, timeout: 15 });
        const sessionMatch = loginResult.stdout?.match(/PHPSESSID=([^;\s]+)/i);
        if (sessionMatch?.[1]) {
          cookieStr = `PHPSESSID=${sessionMatch[1]}; security=low`;
          loginCred.sessionCookie = cookieStr;
          return { cookieStr, method: "phpsessid" };
        }
      } else if (webCreds[0]?.loginPath) {
        const loginCred = webCreds[0];
        const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
        const loginResult = await executeTool({ tool: "curl", args: `-s -X POST ${authBaseUrl}${loginCred.loginPath} -d "username=${loginCred.username}&password=${loginCred.password}" -D -`, timeout: 15 });
        const setCookieMatch = loginResult.stdout?.match(/Set-Cookie:\s*([^\n]+)/i);
        if (setCookieMatch?.[1]) {
          cookieStr = setCookieMatch[1].split(";")[0].trim();
          loginCred.sessionCookie = cookieStr;
          return { cookieStr, method: "form_cookie" };
        }
      }
    } catch (err) {
      addLog(state, { phase: "vuln_detection", type: "warning", title: `Auth Handoff Error: ${webApp.hostname}`, detail: err.message });
    }
  }
  return { cookieStr, method: cookieStr ? "reused" : "none" };
}
async function buildInjectableUrls(webApp, targetUrl, state, engagementId) {
  const injectableUrls = [];
  try {
    const { getDb } = await import("./db-OF4HQS7N.js");
    const db = await getDb();
    if (db) {
      const { webAppScans } = await import("./schema-R6EY37IN.js");
      const { eq, desc } = await import("drizzle-orm");
      const latestScan = await db.select().from(webAppScans).where(eq(webAppScans.engagementId, engagementId)).orderBy(desc(webAppScans.id)).limit(1);
      if (latestScan[0]?.urlsDiscovered) {
        injectableUrls.push({ url: `${targetUrl}/`, method: "GET", params: ["id", "search", "q", "query", "page", "cat", "item"] }, { url: `${targetUrl}/search`, method: "GET", params: ["q", "query", "term", "keyword"] });
      }
    }
  } catch {
  }
  if (injectableUrls.length === 0) injectableUrls.push({ url: `${targetUrl}/`, method: "GET", params: ["id", "search", "q"] });
  if (state.trainingLabMode) {
    const labEndpoints = getTrainingLabEndpoints(webApp.hostname);
    for (const ep of labEndpoints) {
      const fullUrl = `${targetUrl}${ep.path}`;
      if (!injectableUrls.some((u) => u.url === fullUrl)) injectableUrls.push({ url: fullUrl, method: ep.method, params: ep.params });
    }
  }
  return injectableUrls;
}
async function executeInjectionScanning(ctx) {
  const { state, addLog, genId, isInRoeScope } = ctx;
  const result = { sqlInjections: 0, blindSqlInjections: 0, xssVulns: 0, domXssVulns: 0, commandInjections: 0, sstiVulns: 0, totalFindings: 0, endpointsTested: 0 };
  addLog(state, { phase: "vuln_detection", type: "info", title: "\u{1F489} Supplementary Injection Scanning", detail: "Running SQLMap, XSStrike, Commix, and tplmap on discovered web app parameters" });
  const webApps = state.assets.filter(
    (a) => (a.type === "web_app" || a.type === "web" || a.ports.some((p) => ["http", "https"].includes(p.service))) && isInRoeScope(state, a.hostname, a.ip)
  );
  for (const webApp of webApps) {
    const resolvedUrl = webApp.resolvedZapUrl;
    const targetUrl = resolvedUrl || `${webApp.protocol || "https"}://${webApp.hostname}${webApp.port && webApp.port !== 443 && webApp.port !== 80 ? ":" + webApp.port : ""}`;
    const injectableUrls = await buildInjectableUrls(webApp, targetUrl, state, state.engagementId);
    result.endpointsTested += injectableUrls.length;
    const { cookieStr } = await performAuthHandoff(webApp, state, addLog);
    try {
      const approved = await ctx.requestApproval(state, { phase: "vuln_detection", riskTier: "orange", title: `SQLMap: ${webApp.hostname}`, description: `Testing ${injectableUrls.length} URLs for SQL injection`, target: webApp.hostname, toolCommand: `sqlmap --batch ${targetUrl}` });
      if (approved) {
        const { batchSqlmapScan, analyzeSqlmapFindings, runBlindSqliPass, ingestSqlmapToWebAppFindings } = await import("./sqlmap-scanner-QRM34ED5.js");
        const isLab = state.trainingLabMode === true;
        const sqlmapResults = await batchSqlmapScan(injectableUrls, { engagementId: state.engagementId, risk: isLab ? 3 : 2, level: isLab ? 5 : 3, cookie: cookieStr || void 0, timeoutSeconds: isLab ? 180 : 120, enumerateDbs: true, enumerateTables: isLab, techniques: isLab ? "BEUSTQ" : void 0 });
        const findings = sqlmapResults.flatMap((r) => r.findings);
        const sqliCount = findings.filter((f) => f.type === "sqli").length;
        if (sqliCount > 0) {
          webApp.vulns.push({ id: genId(), severity: "critical", title: `[SQLMap] ${sqliCount} SQL injection vulnerabilities`, corroborationTier: "confirmed", rawEvidence: findings.map((f) => `${f.type}: ${f.title || ""} ${f.payload || ""}`).join("\n").slice(0, 4e3), source: "sqlmap" });
          state.stats.vulnsFound += sqliCount;
        }
        result.sqlInjections += sqliCount;
        result.totalFindings += findings.length;
        try {
          await analyzeSqlmapFindings(findings, targetUrl);
        } catch {
        }
        try {
          await ingestSqlmapToWebAppFindings(sqlmapResults, state.engagementId, webApp.hostname);
        } catch {
        }
        webApp.toolResults.push({ tool: "sqlmap", command: `sqlmap --batch --risk ${isLab ? 3 : 2} --level ${isLab ? 5 : 3} ${targetUrl}`, exitCode: 0, durationMs: sqlmapResults.reduce((s, r) => s + r.stats.durationSeconds * 1e3, 0), timedOut: false, findingCount: findings.length, findings: findings.map((f) => ({ severity: f.severity, title: f.title })), executedAt: Date.now(), phase: "vuln_detection" });
        if (isLab) {
          try {
            const blindResult = await runBlindSqliPass({ engagementId: state.engagementId, targetHostname: webApp.hostname, targetUrl, knownInjectableUrls: injectableUrls, cookie: cookieStr || void 0, isTrainingLab: true });
            if (blindResult.blindSqliFound > 0) {
              webApp.vulns.push({ id: genId(), severity: "critical", title: `[SQLMap Blind] ${blindResult.blindSqliFound} blind SQL injection`, corroborationTier: "confirmed", source: "sqlmap" });
              state.stats.vulnsFound += blindResult.blindSqliFound;
              result.blindSqlInjections += blindResult.blindSqliFound;
            }
          } catch {
          }
        }
        addLog(state, { phase: "vuln_detection", type: "scan_result", title: `SQLMap Complete: ${webApp.hostname}`, detail: `${sqliCount} SQL injection vulns confirmed` });
      }
    } catch (err) {
      addLog(state, { phase: "vuln_detection", type: "warning", title: `SQLMap Error: ${webApp.hostname}`, detail: err.message });
    }
    try {
      const approved = await ctx.requestApproval(state, { phase: "vuln_detection", riskTier: "orange", title: `XSS Scan: ${webApp.hostname}`, description: `Testing ${injectableUrls.length} URLs for XSS`, target: webApp.hostname, toolCommand: `xsstrike/dalfox ${targetUrl}` });
      if (approved) {
        const { batchXssScan, analyzeXssFindings, ingestXssToWebAppFindings } = await import("./xsstrike-scanner-SNAAOCGX.js");
        const xssResults = await batchXssScan(injectableUrls, { engagementId: state.engagementId, cookie: cookieStr || void 0, timeoutSeconds: 90, domAnalysis: true, wafBypass: true });
        const findings = xssResults.flatMap((r) => r.findings).filter((f) => f.type !== "waf_detected");
        const xssCount = findings.length;
        const domCount = findings.filter((f) => f.type === "dom_xss").length;
        if (xssCount > 0) {
          const sev = domCount > 0 || findings.some((f) => f.type === "stored_xss") ? "high" : "medium";
          webApp.vulns.push({ id: genId(), severity: sev, title: `[XSS] ${xssCount} XSS vulnerabilities (${domCount} DOM-based)`, corroborationTier: "confirmed", source: "xss-scanner" });
          state.stats.vulnsFound += xssCount;
        }
        result.xssVulns += xssCount;
        result.domXssVulns += domCount;
        result.totalFindings += xssCount;
        try {
          await analyzeXssFindings(findings, targetUrl);
        } catch {
        }
        try {
          await ingestXssToWebAppFindings(xssResults, state.engagementId, webApp.hostname);
        } catch {
        }
        webApp.toolResults.push({ tool: xssResults.find((r) => r.tool !== "none")?.tool || "xsstrike", command: `xsstrike ${targetUrl}`, exitCode: 0, durationMs: xssResults.reduce((s, r) => s + r.stats.durationSeconds * 1e3, 0), timedOut: false, findingCount: findings.length, findings: findings.map((f) => ({ severity: f.severity, title: f.title })), executedAt: Date.now(), phase: "vuln_detection" });
        addLog(state, { phase: "vuln_detection", type: "scan_result", title: `XSS Complete: ${webApp.hostname}`, detail: `${xssCount} XSS vulns (${domCount} DOM-based)` });
      }
    } catch (err) {
      addLog(state, { phase: "vuln_detection", type: "warning", title: `XSS Error: ${webApp.hostname}`, detail: err.message });
    }
  }
  for (const webApp of webApps) {
    if (!isInRoeScope(state, webApp.hostname, webApp.ip)) continue;
    const targetUrl = webApp.urls?.[0] || `http://${webApp.hostname}`;
    const crawledUrls = (webApp.crawledUrls || []).filter((u) => u.url.includes("?")).slice(0, 8);
    if (crawledUrls.length === 0) continue;
    try {
      const approved = await ctx.requestApproval(state, { phase: "vuln_detection", riskTier: "orange", title: `Commix: ${webApp.hostname}`, description: `Testing ${crawledUrls.length} URLs for OS command injection`, target: webApp.hostname, toolCommand: `commix --url="${targetUrl}" --batch` });
      if (approved) {
        const { batchCommixScan, ingestCommixToWebAppFindings } = await import("./commix-scanner-HVMLCSVT.js");
        const isLab = state.trainingLabMode === true;
        const commixResults = await batchCommixScan(crawledUrls, { engagementId: state.engagementId, cookie: webApp.sessionCookie || void 0, timeoutSeconds: isLab ? 120 : 90, level: isLab ? 3 : 2 });
        const findings = commixResults.flatMap((r) => r.findings);
        const cmdiCount = findings.filter((f) => f.type === "cmdi" || f.type === "blind_cmdi").length;
        if (cmdiCount > 0) {
          webApp.vulns.push({ id: genId(), severity: "critical", title: `[Commix] ${cmdiCount} OS command injection`, corroborationTier: "confirmed", source: "commix" });
          state.stats.vulnsFound += cmdiCount;
        }
        result.commandInjections += cmdiCount;
        result.totalFindings += findings.length;
        try {
          await ingestCommixToWebAppFindings(commixResults, state.engagementId, webApp.hostname);
        } catch {
        }
        webApp.toolResults.push({ tool: "commix", command: `commix --url="${targetUrl}" --batch --level=${isLab ? 3 : 2}`, exitCode: 0, durationMs: commixResults.reduce((s, r) => s + r.stats.durationSeconds * 1e3, 0), timedOut: false, findingCount: findings.length, findings: findings.map((f) => ({ severity: f.severity, title: f.title })), executedAt: Date.now(), phase: "vuln_detection" });
        addLog(state, { phase: "vuln_detection", type: "scan_result", title: `Commix Complete: ${webApp.hostname}`, detail: `${cmdiCount} command injection vulns` });
      }
    } catch (err) {
      addLog(state, { phase: "vuln_detection", type: "warning", title: `Commix Error: ${webApp.hostname}`, detail: err.message });
    }
  }
  for (const webApp of webApps) {
    if (!isInRoeScope(state, webApp.hostname, webApp.ip)) continue;
    const targetUrl = webApp.urls?.[0] || `http://${webApp.hostname}`;
    const crawledUrls = (webApp.crawledUrls || []).filter((u) => u.url.includes("?")).slice(0, 8);
    if (crawledUrls.length === 0) continue;
    try {
      const approved = await ctx.requestApproval(state, { phase: "vuln_detection", riskTier: "orange", title: `tplmap SSTI: ${webApp.hostname}`, description: `Testing ${crawledUrls.length} URLs for Server-Side Template Injection`, target: webApp.hostname, toolCommand: `tplmap -u "${targetUrl}"` });
      if (approved) {
        const { batchTplmapScan, ingestTplmapToWebAppFindings } = await import("./tplmap-scanner-H6FZBCXD.js");
        const tplmapResults = await batchTplmapScan(crawledUrls, { engagementId: state.engagementId, cookie: webApp.sessionCookie || void 0, timeoutSeconds: 90, level: 2 });
        const findings = tplmapResults.flatMap((r) => r.findings);
        const sstiCount = findings.filter((f) => f.type === "ssti" || f.type === "blind_ssti").length;
        const engines = [...new Set(tplmapResults.map((r) => r.stats.engineDetected).filter(Boolean))];
        if (sstiCount > 0) {
          webApp.vulns.push({ id: genId(), severity: "critical", title: `[tplmap] ${sstiCount} SSTI vulnerabilities${engines.length ? ` (${engines.join(", ")})` : ""}`, corroborationTier: "confirmed", source: "tplmap" });
          state.stats.vulnsFound += sstiCount;
        }
        result.sstiVulns += sstiCount;
        result.totalFindings += findings.length;
        try {
          await ingestTplmapToWebAppFindings(tplmapResults, state.engagementId, webApp.hostname);
        } catch {
        }
        webApp.toolResults.push({ tool: "tplmap", command: `tplmap -u "${targetUrl}" --level 2`, exitCode: 0, durationMs: tplmapResults.reduce((s, r) => s + r.stats.durationSeconds * 1e3, 0), timedOut: false, findingCount: findings.length, findings: findings.map((f) => ({ severity: f.severity, title: f.title })), executedAt: Date.now(), phase: "vuln_detection" });
        addLog(state, { phase: "vuln_detection", type: "scan_result", title: `tplmap Complete: ${webApp.hostname}`, detail: `${sstiCount} SSTI vulns${engines.length ? `, engines: ${engines.join(", ")}` : ""}` });
      }
    } catch (err) {
      addLog(state, { phase: "vuln_detection", type: "warning", title: `tplmap Error: ${webApp.hostname}`, detail: err.message });
    }
  }
  return result;
}
var TRAINING_LAB_INJECTABLE_ENDPOINTS;
var init_injection_scanner = __esm({
  "server/lib/vuln-detection/injection-scanner.ts"() {
    TRAINING_LAB_INJECTABLE_ENDPOINTS = {
      "juiceshop": [
        { path: "/rest/products/search", method: "GET", params: ["q"] },
        { path: "/api/Products", method: "GET", params: ["q"] },
        { path: "/rest/user/login", method: "POST", params: ["email", "password"] },
        { path: "/api/Feedbacks", method: "POST", params: ["comment", "rating"] },
        { path: "/profile", method: "GET", params: ["username"] },
        { path: "/redirect", method: "GET", params: ["to"] }
      ],
      "dvwa": [
        { path: "/vulnerabilities/sqli/", method: "GET", params: ["id", "Submit"] },
        { path: "/vulnerabilities/sqli_blind/", method: "GET", params: ["id", "Submit"] },
        { path: "/vulnerabilities/xss_r/", method: "GET", params: ["name"] },
        { path: "/vulnerabilities/xss_s/", method: "POST", params: ["txtName", "mtxMessage"] },
        { path: "/vulnerabilities/exec/", method: "POST", params: ["ip", "Submit"] },
        { path: "/vulnerabilities/fi/", method: "GET", params: ["page"] }
      ],
      "altoro": [
        { path: "/login.jsp", method: "POST", params: ["uid", "passw"] },
        { path: "/bank/transaction.jsp", method: "GET", params: ["id"] },
        { path: "/search.jsp", method: "GET", params: ["query"] }
      ],
      "testphp": [
        { path: "/listproducts.php", method: "GET", params: ["cat"] },
        { path: "/artists.php", method: "GET", params: ["artist"] },
        { path: "/showimage.php", method: "GET", params: ["file"] },
        { path: "/search.php", method: "GET", params: ["test"] }
      ],
      "hackazon": [
        { path: "/search", method: "GET", params: ["searchString"] },
        { path: "/user/login", method: "POST", params: ["username", "password"] },
        { path: "/product/view", method: "GET", params: ["id"] }
      ]
    };
  }
});
init_injection_scanner();
export {
  buildInjectableUrls,
  executeInjectionScanning,
  getTrainingLabEndpoints,
  performAuthHandoff
};
