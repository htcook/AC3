import {
  findMsfModules,
  init_zap_scanner,
  mapToMitre
} from "./chunk-XAC5FGKN.js";
import "./chunk-UK4O2S6Y.js";
import "./chunk-IU7QQ35X.js";
import {
  init_llm_throttle,
  throttledLLMCall
} from "./chunk-GTXFXXF6.js";
import {
  executeTool,
  init_scan_server_executor
} from "./chunk-KW2CWOOD.js";
import "./chunk-Y2UB65JM.js";
import "./chunk-E7WGGYZE.js";
import "./chunk-PIYDKQBM.js";
import "./chunk-JPJQZXKW.js";
import "./chunk-SD56WPOS.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-TCEHBLTC.js";
import "./chunk-RUIEEOYK.js";
import {
  getDb,
  init_db
} from "./chunk-L5ZLWR7T.js";
import "./chunk-NRYVRXXR.js";
import {
  init_schema,
  scanResults,
  webAppFindings,
  webAppScans
} from "./chunk-L4JENJ4Z.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/scanners/xsstrike-scanner.ts
function parseXssStrikeOutput(stdout, targetUrl) {
  const findings = [];
  let wafDetected = false;
  let wafName;
  const lines = stdout.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    const wafMatch = trimmed.match(/WAF.*?detected.*?:\s*(.+)/i) || trimmed.match(/\[WAF\]\s*(.+)/i);
    if (wafMatch) {
      wafDetected = true;
      wafName = wafMatch[1].trim();
      findings.push({
        id: `xss-waf-${Date.now()}`,
        type: "waf_detected",
        severity: "info",
        parameter: "",
        url: targetUrl,
        context: "detection",
        wafName,
        title: `WAF Detected: ${wafName}`,
        description: `XSS scanner detected a Web Application Firewall: ${wafName}. WAF bypass techniques will be attempted.`,
        cweId: 693,
        references: []
      });
    }
    const vulnMatch = trimmed.match(/(?:Vulnerable|XSS found|Payload|VULN).*?(?:parameter|param)?\s*['"]?([^'":\s]+)['"]?/i);
    if (vulnMatch || /\[VULN\]|\[XSS\]|Vulnerable/i.test(trimmed)) {
      const param = vulnMatch?.[1] || "unknown";
      let xssType = "reflected_xss";
      let context = "HTML";
      if (/DOM|document\.|innerHTML|eval\(|setTimeout/i.test(trimmed)) {
        xssType = "dom_xss";
        context = "JavaScript DOM";
      } else if (/stored|persistent/i.test(trimmed)) {
        xssType = "stored_xss";
        context = "Stored";
      } else if (/attribute|attr|on\w+=/i.test(trimmed)) {
        context = "HTML Attribute";
      } else if (/script|javascript:|eval/i.test(trimmed)) {
        context = "JavaScript";
      }
      const payloadMatch = trimmed.match(/payload[:\s]*['"]?(.+?)['"]?\s*$/i) || trimmed.match(/→\s*(.+)/);
      const payload = payloadMatch?.[1]?.substring(0, 500);
      findings.push({
        id: `xss-${xssType}-${param}-${Date.now()}-${findings.length}`,
        type: xssType,
        severity: xssType === "dom_xss" || xssType === "stored_xss" ? "high" : "medium",
        parameter: param,
        url: targetUrl,
        context,
        payload,
        title: `${xssType === "dom_xss" ? "DOM" : xssType === "stored_xss" ? "Stored" : "Reflected"} XSS in parameter '${param}'`,
        description: `XSS vulnerability detected in parameter '${param}' within ${context} context.${payload ? ` Payload: ${payload.substring(0, 100)}` : ""}`,
        cweId: xssType === "dom_xss" ? 79 : xssType === "stored_xss" ? 79 : 79,
        references: [
          "https://owasp.org/www-community/attacks/xss/",
          "https://cwe.mitre.org/data/definitions/79.html"
        ]
      });
    }
  }
  return { findings, wafDetected, wafName };
}
function parseDalfoxOutput(stdout, targetUrl) {
  const findings = [];
  let wafDetected = false;
  let wafName;
  const lines = stdout.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (/\[WAF\]|\[W\]/i.test(trimmed)) {
      wafDetected = true;
      const wafMatch = trimmed.match(/\[WAF\]\s*(.+)/i) || trimmed.match(/\[W\]\s*(.+)/i);
      wafName = wafMatch?.[1]?.trim() || "Unknown WAF";
    }
    const pocMatch = trimmed.match(/\[POC\]\[([^\]]+)\]\s*(\S+)\s*(.*)/i) || trimmed.match(/\[V\]\[([^\]]+)\]\s*(\S+)\s*(.*)/i);
    if (pocMatch) {
      const [, type, url, payload] = pocMatch;
      let xssType = "reflected_xss";
      let context = "HTML";
      if (/DOM|dom/i.test(type)) {
        xssType = "dom_xss";
        context = "JavaScript DOM";
      } else if (/stored|persist/i.test(type)) {
        xssType = "stored_xss";
        context = "Stored";
      } else if (/attr/i.test(type)) {
        context = "HTML Attribute";
      } else if (/inJS|javascript/i.test(type)) {
        context = "JavaScript";
      } else if (/inTag/i.test(type)) {
        context = "HTML Tag";
      }
      let param = "unknown";
      try {
        const parsedUrl = new URL(url);
        const params = Array.from(parsedUrl.searchParams.keys());
        param = params[0] || "unknown";
      } catch {
      }
      findings.push({
        id: `xss-dalfox-${xssType}-${param}-${Date.now()}-${findings.length}`,
        type: xssType,
        severity: xssType === "dom_xss" || xssType === "stored_xss" ? "high" : "medium",
        parameter: param,
        url: url || targetUrl,
        context,
        payload: payload?.substring(0, 500),
        title: `${xssType === "dom_xss" ? "DOM" : xssType === "stored_xss" ? "Stored" : "Reflected"} XSS: ${type}`,
        description: `Dalfox confirmed ${xssType.replace("_", " ")} vulnerability in ${context} context.${payload ? ` Proof-of-concept payload: ${payload.substring(0, 100)}` : ""}`,
        cweId: 79,
        references: [
          "https://owasp.org/www-community/attacks/xss/",
          "https://cwe.mitre.org/data/definitions/79.html"
        ]
      });
    }
    const paramMatch = trimmed.match(/\[I\]\[Param\]\s*(\S+)/i);
    if (paramMatch) {
    }
  }
  return { findings, wafDetected, wafName };
}
async function startXssScan(config) {
  const startTime = Date.now();
  const timeout = config.timeoutSeconds || 180;
  const toolOrder = config.preferredTool === "dalfox" ? ["dalfox", "xsstrike"] : ["xsstrike", "dalfox"];
  let activeTool = "none";
  let result = null;
  for (const tool of toolOrder) {
    try {
      const checkResult = await executeTool({
        tool: "bash",
        args: `-c "which ${tool} 2>/dev/null && echo FOUND || echo NOTFOUND"`,
        timeoutSeconds: 10
      });
      if (checkResult.stdout.includes("FOUND")) {
        activeTool = tool;
        break;
      }
    } catch {
    }
  }
  if (activeTool === "none") {
    try {
      const pipCheck = await executeTool({
        tool: "bash",
        args: `-c "python3 -c 'import xsstrike' 2>/dev/null && echo FOUND || pip3 install xsstrike 2>/dev/null && echo INSTALLED || echo NOTFOUND"`,
        timeoutSeconds: 30
      });
      if (pipCheck.stdout.includes("FOUND") || pipCheck.stdout.includes("INSTALLED")) {
        activeTool = "xsstrike";
      }
    } catch {
    }
  }
  if (activeTool === "none") {
    console.log(`[XSS] Neither XSStrike nor Dalfox available on scan server \u2014 skipping XSS scan`);
    return {
      scanId: null,
      status: "error",
      target: config.targetUrl,
      tool: "none",
      findings: [],
      stats: { urlsTested: 0, parametersTested: 0, xssFound: 0, domXssFound: 0, wafDetected: false, durationSeconds: 0 },
      rawOutput: "",
      error: "Neither XSStrike nor Dalfox is installed on the scan server. Install with: pip3 install xsstrike OR go install github.com/hahwul/dalfox/v2@latest"
    };
  }
  let command;
  if (activeTool === "dalfox") {
    const args = [
      "url",
      `"${config.targetUrl}"`,
      "--silence",
      "--no-color",
      "--timeout",
      String(Math.min(timeout, 30))
    ];
    if (config.parameter) args.push("-p", config.parameter);
    if (config.cookie) args.push("--cookie", `"${config.cookie}"`);
    if (config.headers) {
      for (const [key, value] of Object.entries(config.headers)) {
        args.push("--header", `"${key}: ${value}"`);
      }
    }
    if (config.method === "POST" && config.postData) {
      args.push("--data", `"${config.postData}"`);
    }
    if (config.wafBypass) args.push("--waf-evasion");
    if (config.blindCallback) args.push("--blind", `"${config.blindCallback}"`);
    if (config.domAnalysis) args.push("--deep-domxss");
    command = `dalfox ${args.join(" ")} 2>&1`;
  } else {
    const args = [
      "-u",
      `"${config.targetUrl}"`,
      "--skip"
      // Skip confirmation prompts
    ];
    if (config.cookie) args.push("--headers", `"Cookie: ${config.cookie}"`);
    if (config.headers) {
      const headerStr = Object.entries(config.headers).map(([k, v]) => `${k}: ${v}`).join("\\n");
      args.push("--headers", `"${headerStr}"`);
    }
    if (config.postData) {
      args.push("--data", `"${config.postData}"`);
    }
    if (config.fuzzAll) args.push("--fuzzer");
    if (config.crawlDepth) args.push("--crawl", "-l", String(config.crawlDepth));
    if (config.blindCallback) args.push("--blind", `"${config.blindCallback}"`);
    command = `xsstrike ${args.join(" ")} 2>&1 || python3 -m xsstrike ${args.join(" ")} 2>&1`;
  }
  console.log(`[XSS] Starting ${activeTool} scan: ${command.substring(0, 300)}`);
  console.log(`[XSS] Config: target=${config.targetUrl}, cookie=${config.cookie ? "yes(" + config.cookie.substring(0, 30) + "...)" : "none"}, timeout=${timeout}s, dom=${config.domAnalysis}, wafBypass=${config.wafBypass}`);
  try {
    result = await executeTool({
      tool: "bash",
      args: `-c "${command}"`,
      target: config.targetUrl,
      timeoutSeconds: timeout + 60,
      engagementId: config.engagementId
    });
    console.log(`[XSS] executeTool returned: exitCode=${result.exitCode}, timedOut=${result.timedOut}, stdout=${result.stdout?.substring(0, 200) || "(empty)"}`);
  } catch (err) {
    console.error(`[XSS] executeTool threw: ${err.message}
${err.stack?.substring(0, 300)}`);
    return {
      scanId: null,
      status: "error",
      target: config.targetUrl,
      tool: activeTool,
      findings: [],
      stats: { urlsTested: 1, parametersTested: 0, xssFound: 0, domXssFound: 0, wafDetected: false, durationSeconds: (Date.now() - startTime) / 1e3 },
      rawOutput: "",
      error: err.message
    };
  }
  const parsed = activeTool === "dalfox" ? parseDalfoxOutput(result.stdout, config.targetUrl) : parseXssStrikeOutput(result.stdout, config.targetUrl);
  const durationSeconds = (Date.now() - startTime) / 1e3;
  const xssFindings = parsed.findings.filter((f) => f.type !== "waf_detected");
  const domXssFindings = xssFindings.filter((f) => f.type === "dom_xss");
  const db = await getDb();
  let scanId = null;
  if (db && parsed.findings.length > 0) {
    try {
      const [inserted] = await db.insert(scanResults).values({
        engagementId: config.engagementId,
        tool: activeTool,
        target: config.targetUrl.substring(0, 255),
        command: `${activeTool} -u "${config.targetUrl}"${config.parameter ? ` -p ${config.parameter}` : ""}${config.wafBypass ? " --waf-bypass" : ""}`,
        findings: JSON.stringify(parsed.findings),
        findingCount: parsed.findings.length,
        rawOutput: result.stdout.substring(0, 5e4),
        exitCode: result.exitCode ?? 0,
        durationMs: Math.round(durationSeconds * 1e3),
        timedOut: result.timedOut ? 1 : 0,
        severitySummary: JSON.stringify({
          critical: parsed.findings.filter((f) => f.severity === "critical").length,
          high: parsed.findings.filter((f) => f.severity === "high").length,
          medium: parsed.findings.filter((f) => f.severity === "medium").length,
          low: parsed.findings.filter((f) => f.severity === "low").length,
          info: parsed.findings.filter((f) => f.severity === "info").length
        }),
        phase: "vuln_detection"
      }).$returningId();
      scanId = inserted?.id ?? null;
    } catch (e) {
      console.error(`[XSS] Failed to persist scan results: ${e.message}`);
    }
  }
  console.log(`[XSS] ${activeTool} scan completed in ${durationSeconds.toFixed(1)}s \u2014 ${xssFindings.length} XSS findings (${domXssFindings.length} DOM), WAF=${parsed.wafDetected}`);
  return {
    scanId,
    status: result.timedOut ? "timeout" : "completed",
    target: config.targetUrl,
    tool: activeTool,
    findings: parsed.findings,
    stats: {
      urlsTested: 1,
      parametersTested: parsed.findings.length,
      xssFound: xssFindings.length,
      domXssFound: domXssFindings.length,
      wafDetected: parsed.wafDetected,
      durationSeconds
    },
    rawOutput: result.stdout
  };
}
async function batchXssScan(urls, config) {
  const results = [];
  const maxUrls = Math.min(urls.length, 15);
  console.log(`[XSS Batch] Testing ${maxUrls} URLs (of ${urls.length} discovered) for XSS`);
  for (let i = 0; i < maxUrls; i++) {
    const { url, method, params } = urls[i];
    if (params.length === 0) continue;
    console.log(`[XSS Batch] [${i + 1}/${maxUrls}] Testing: ${url} (${method}, params: ${params.join(",")})`);
    const result = await startXssScan({
      ...config,
      targetUrl: url,
      method,
      parameter: params[0],
      // Test primary parameter
      timeoutSeconds: Math.min(config.timeoutSeconds || 90, 90)
    });
    results.push(result);
    if (result.tool === "none") {
      console.log(`[XSS Batch] No XSS tool available \u2014 aborting batch`);
      break;
    }
  }
  const totalXss = results.reduce((sum, r) => sum + r.stats.xssFound, 0);
  const totalDom = results.reduce((sum, r) => sum + r.stats.domXssFound, 0);
  console.log(`[XSS Batch] Completed: ${results.length} URLs tested, ${totalXss} XSS found (${totalDom} DOM)`);
  return results;
}
async function analyzeXssFindings(findings, targetUrl) {
  if (findings.length === 0) {
    return { riskSummary: "No XSS findings.", exploitScenarios: [], recommendations: [] };
  }
  const findingSummary = findings.slice(0, 20).map(
    (f) => `[${f.severity.toUpperCase()}] ${f.type} \u2014 param '${f.parameter}' in ${f.context} context at ${f.url}${f.payload ? ` (payload: ${f.payload.substring(0, 80)})` : ""}`
  ).join("\n");
  const response = await throttledLLMCall("xss-analyst", () => invokeLLM({
    _caller: "xsstrike-scanner.analyzeXssFindings",
    messages: [
      {
        role: "system",
        content: `You are an XSS exploitation specialist reviewing scanner findings. Analyze the findings and provide:
1. Risk summary with real-world attack scenarios (session hijacking, keylogging, phishing, crypto mining)
2. Exploit scenarios showing how each XSS can be weaponized based on its context (HTML, JS, attribute, DOM)
3. Specific remediation recommendations (CSP, output encoding, DOMPurify, HttpOnly cookies)

Target: ${targetUrl}
Respond in JSON format.`
      },
      {
        role: "user",
        content: `Analyze these XSS findings:

${findingSummary}`
      }
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "xss_analysis",
        strict: true,
        schema: {
          type: "object",
          properties: {
            riskSummary: { type: "string" },
            exploitScenarios: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  type: { type: "string" },
                  parameter: { type: "string" },
                  context: { type: "string" },
                  impact: { type: "string" },
                  exploitability: { type: "string" }
                },
                required: ["type", "parameter", "context", "impact", "exploitability"],
                additionalProperties: false
              }
            },
            recommendations: {
              type: "array",
              items: { type: "string" }
            }
          },
          required: ["riskSummary", "exploitScenarios", "recommendations"],
          additionalProperties: false
        }
      }
    }
  }));
  try {
    const parsed = JSON.parse(response.choices[0]?.message?.content || "{}");
    return {
      riskSummary: parsed.riskSummary || "Analysis unavailable.",
      exploitScenarios: parsed.exploitScenarios || [],
      recommendations: parsed.recommendations || []
    };
  } catch {
    return { riskSummary: "LLM analysis failed to parse.", exploitScenarios: [], recommendations: [] };
  }
}
async function ingestXssToWebAppFindings(results, engagementId, targetHostname) {
  const db = await getDb();
  if (!db) return { webAppScanId: null, findingsIngested: 0 };
  const allFindings = results.flatMap((r) => r.findings);
  if (allFindings.length === 0) return { webAppScanId: null, findingsIngested: 0 };
  try {
    const targetUrl = results[0]?.target || `https://${targetHostname}`;
    const totalDuration = results.reduce((sum, r) => sum + r.stats.durationSeconds, 0);
    const toolUsed = results.find((r) => r.tool !== "none")?.tool || "xsstrike";
    const xssFindings = allFindings.filter((f) => f.type !== "waf_detected");
    const [scanRecord] = await db.insert(webAppScans).values({
      targetUrl: targetUrl.substring(0, 2048),
      scanName: `XSS-EngOps-${engagementId}-${targetHostname}`,
      scanType: `xss_${toolUsed}`,
      status: "completed",
      startedAt: new Date(Date.now() - totalDuration * 1e3),
      completedAt: /* @__PURE__ */ new Date(),
      totalAlerts: allFindings.length,
      alertCounts: JSON.stringify({
        high: allFindings.filter((f) => f.severity === "critical" || f.severity === "high").length,
        medium: allFindings.filter((f) => f.severity === "medium").length,
        low: allFindings.filter((f) => f.severity === "low").length,
        info: allFindings.filter((f) => f.severity === "info").length
      }),
      scanMode: "active"
    }).$returningId();
    const webAppScanId = scanRecord?.id;
    if (!webAppScanId) return { webAppScanId: null, findingsIngested: 0 };
    let ingested = 0;
    for (const finding of allFindings) {
      const cweId = XSS_TYPE_CWE[finding.type] || finding.cweId || 79;
      const mitre = mapToMitre(cweId, finding.title);
      const msfModules = findMsfModules(cweId);
      const severityMap = {
        critical: "high",
        high: "high",
        medium: "medium",
        low: "low",
        info: "info"
      };
      const confidenceMap = {
        reflected_xss: 0.85,
        // Confirmed reflected XSS
        dom_xss: 0.9,
        // DOM-based XSS (harder to detect, higher confidence when found)
        stored_xss: 0.95,
        // Stored XSS (most dangerous, highest confidence)
        blind_xss: 0.8,
        // Blind XSS (callback-based, slightly lower confidence)
        waf_bypass: 0.75,
        // WAF bypass (informational)
        waf_detected: 0.7
        // WAF detection (informational)
      };
      const solutionMap = {
        reflected_xss: "Implement context-aware output encoding for all user-supplied data. Use Content Security Policy (CSP) headers to restrict inline script execution. Apply input validation with allowlists. Use HttpOnly and Secure flags on session cookies to prevent cookie theft via XSS.",
        dom_xss: "Avoid using dangerous DOM APIs like innerHTML, document.write(), and eval(). Use textContent or createElement() instead. Implement DOMPurify for sanitizing HTML content. Add CSP with strict-dynamic to prevent DOM-based script injection. Review all client-side JavaScript for unsafe sink usage.",
        stored_xss: "CRITICAL: Stored XSS persists in the application and affects all users who view the affected content. Immediately sanitize all stored user input. Implement server-side output encoding. Use CSP headers. Review all database-stored content that is rendered in HTML. Consider implementing a content sanitization library like DOMPurify on both client and server.",
        blind_xss: "Blind XSS payloads execute in admin panels or internal tools when viewing user-submitted data. Sanitize all user input before storage and rendering. Implement CSP headers on all internal admin pages. Review all admin/support interfaces that display user content.",
        waf_bypass: "WAF bypass indicates the current WAF rules are insufficient. Update WAF signatures and rules. Implement application-level input validation in addition to WAF. Consider using a more robust WAF solution. Fix the underlying XSS vulnerability rather than relying solely on WAF.",
        waf_detected: "A WAF was detected protecting the application. While WAFs provide defense-in-depth, they should not be the sole protection against XSS. Ensure application-level output encoding and input validation are also implemented."
      };
      try {
        await db.insert(webAppFindings).values({
          scanId: webAppScanId,
          alertName: `[${toolUsed.toUpperCase()}] ${finding.title}`.substring(0, 512),
          severity: severityMap[finding.severity] || "medium",
          confidence: confidenceMap[finding.type] || 0.7,
          description: `${finding.description}${finding.context ? ` Context: ${finding.context}.` : ""}`.substring(0, 4e3),
          solution: (solutionMap[finding.type] || "Review and remediate the identified XSS vulnerability. Implement output encoding and Content Security Policy.").substring(0, 4e3),
          referenceLinks: finding.references.join("\n").substring(0, 2e3) || null,
          cweId,
          wascId: finding.type !== "waf_detected" && finding.type !== "waf_bypass" ? 8 : null,
          // WASC-8 = Cross-Site Scripting
          url: finding.url?.substring(0, 2048) || null,
          method: null,
          param: finding.parameter?.substring(0, 512) || null,
          attack: finding.payload?.substring(0, 2e3) || null,
          evidence: finding.context ? `XSS Type: ${finding.type.replace(/_/g, " ")}. Context: ${finding.context}.${finding.wafName ? ` WAF: ${finding.wafName}` : ""}`.substring(0, 2e3) : `XSS Type: ${finding.type.replace(/_/g, " ")}`.substring(0, 2e3),
          zapPluginId: `${toolUsed}-${finding.type}`,
          // Pseudo plugin ID for XSStrike/Dalfox
          zapAlertRef: finding.id,
          // MITRE ATT&CK mapping
          mitreAttackId: mitre?.techniqueId || null,
          mitreAttackName: mitre?.techniqueName || null,
          mitreTactic: mitre?.tactic || null,
          // Exploit correlation
          exploitAvailable: msfModules.length > 0 ? 1 : 0,
          exploitModulePath: msfModules.length > 0 ? msfModules[0] : null
        });
        ingested++;
      } catch (insertErr) {
        console.error(`[XSS] Failed to ingest finding to web_app_findings: ${insertErr.message}`);
      }
    }
    console.log(`[XSS] Ingested ${ingested}/${allFindings.length} findings into web_app_findings (scan #${webAppScanId})`);
    return { webAppScanId, findingsIngested: ingested };
  } catch (err) {
    console.error(`[XSS] Failed to create web_app_scans record: ${err.message}`);
    return { webAppScanId: null, findingsIngested: 0 };
  }
}
var XSS_TYPE_CWE;
var init_xsstrike_scanner = __esm({
  "server/lib/scanners/xsstrike-scanner.ts"() {
    init_scan_server_executor();
    init_llm();
    init_llm_throttle();
    init_db();
    init_schema();
    init_zap_scanner();
    XSS_TYPE_CWE = {
      reflected_xss: 79,
      // CWE-79: Improper Neutralization of Input During Web Page Generation
      dom_xss: 79,
      // CWE-79 (subtype: DOM-based, sometimes CWE-20)
      stored_xss: 79,
      // CWE-79 (subtype: Persistent/Stored)
      blind_xss: 79,
      // CWE-79 (subtype: Blind)
      waf_bypass: 693,
      // CWE-693: Protection Mechanism Failure
      waf_detected: 693
      // CWE-693: Protection Mechanism Failure
    };
  }
});
init_xsstrike_scanner();
export {
  analyzeXssFindings,
  batchXssScan,
  ingestXssToWebAppFindings,
  startXssScan
};
