import {
  analyzeWapitiFindingsDeterministic,
  init_deterministic_scanner_analysis,
  useDeterministicAnalysis
} from "./chunk-EILMWEUF.js";
import {
  init_llm_throttle,
  throttledLLMCall
} from "./chunk-E5Y22AVE.js";
import {
  executeTool,
  init_scan_server_executor
} from "./chunk-AS3C3IQF.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-BO7KGWQN.js";
import {
  getDb,
  init_db
} from "./chunk-5G2CDI2L.js";
import {
  init_schema,
  scanResults
} from "./chunk-2ZYBVKLY.js";

// server/lib/scanners/wapiti-scanner.ts
init_scan_server_executor();
init_llm();
init_llm_throttle();
init_deterministic_scanner_analysis();
init_db();
init_schema();
function wapitiLevelToSeverity(level) {
  switch (level) {
    case 4:
      return "critical";
    case 3:
      return "high";
    case 2:
      return "medium";
    case 1:
      return "low";
    default:
      return "info";
  }
}
function moduleToCategory(module) {
  const map = {
    sql: "injection",
    xss: "injection",
    xxe: "injection",
    exec: "command-execution",
    file: "file-handling",
    ssrf: "ssrf",
    redirect: "open-redirect",
    crlf: "injection",
    htaccess: "misconfiguration",
    backup: "sensitive-files",
    csp: "headers",
    cookieflags: "headers",
    cors: "headers",
    headers: "headers",
    shellshock: "command-execution",
    wapp: "fingerprinting",
    nikto: "general",
    csrf: "csrf",
    blindsql: "injection",
    permanentxss: "injection"
  };
  return map[module] || "general";
}
function parseWapitiJSON(jsonStr) {
  const findings = [];
  const infos = [];
  const anomalies = [];
  let crawledUrls = 0;
  try {
    const report = JSON.parse(jsonStr);
    if (report.vulnerabilities) {
      for (const [module, vulnList] of Object.entries(report.vulnerabilities)) {
        if (!Array.isArray(vulnList)) continue;
        for (const vuln of vulnList) {
          findings.push({
            id: `wapiti-${module}-${Math.random().toString(36).slice(2, 10)}`,
            module,
            category: moduleToCategory(module),
            level: vuln.level || 2,
            severity: wapitiLevelToSeverity(vuln.level || 2),
            description: vuln.info || vuln.description || "",
            method: vuln.method || "GET",
            path: vuln.path || "/",
            parameter: vuln.parameter || null,
            httpResponse: vuln.http_request ? String(vuln.http_request).slice(0, 500) : null,
            curlCommand: vuln.curl_command || null,
            wstgCode: vuln.wstg ? String(vuln.wstg) : null,
            cweId: vuln.cwe ? `CWE-${vuln.cwe}` : null,
            references: Array.isArray(vuln.referer) ? vuln.referer : []
          });
        }
      }
    }
    if (report.infos) {
      for (const [module, infoList] of Object.entries(report.infos)) {
        if (!Array.isArray(infoList)) continue;
        for (const info of infoList) {
          infos.push({
            id: `wapiti-info-${module}-${Math.random().toString(36).slice(2, 10)}`,
            module,
            category: moduleToCategory(module),
            level: 0,
            severity: "info",
            description: info.info || info.description || "",
            method: info.method || "GET",
            path: info.path || "/",
            parameter: null,
            httpResponse: null,
            curlCommand: null,
            wstgCode: info.wstg ? String(info.wstg) : null,
            cweId: null,
            references: []
          });
        }
      }
    }
    if (report.anomalies) {
      for (const [module, anomalyList] of Object.entries(report.anomalies)) {
        if (!Array.isArray(anomalyList)) continue;
        for (const anomaly of anomalyList) {
          anomalies.push({
            id: `wapiti-anomaly-${module}-${Math.random().toString(36).slice(2, 10)}`,
            module,
            category: "anomaly",
            level: anomaly.level || 1,
            severity: wapitiLevelToSeverity(anomaly.level || 1),
            description: anomaly.info || anomaly.description || "",
            method: anomaly.method || "GET",
            path: anomaly.path || "/",
            parameter: anomaly.parameter || null,
            httpResponse: null,
            curlCommand: null,
            wstgCode: null,
            cweId: null,
            references: []
          });
        }
      }
    }
    crawledUrls = report.crawled_urls_count || report.crawled_urls?.length || 0;
  } catch (err) {
    console.error("[Wapiti] Failed to parse JSON report:", err);
  }
  return { findings, infos, anomalies, crawledUrls };
}
function parseWapitiText(output) {
  const findings = [];
  const vulnRegex = /\[\*\]\s+(.+?)\s+in\s+(\S+)(?:\s+via\s+parameter\s+"([^"]+)")?/gm;
  let match;
  while ((match = vulnRegex.exec(output)) !== null) {
    const desc = match[1];
    const path = match[2];
    const param = match[3] || null;
    findings.push({
      id: `wapiti-text-${Math.random().toString(36).slice(2, 10)}`,
      module: desc.toLowerCase().includes("sql") ? "sql" : desc.toLowerCase().includes("xss") ? "xss" : "general",
      category: "general",
      level: 2,
      severity: "medium",
      description: desc,
      method: "GET",
      path,
      parameter: param,
      httpResponse: null,
      curlCommand: null,
      wstgCode: null,
      cweId: null,
      references: []
    });
  }
  return findings;
}
async function startWapitiScan(config) {
  const startTime = Date.now();
  const timeout = config.timeoutSeconds || 300;
  const outputFile = `/tmp/wapiti-report-${Date.now()}.json`;
  const args = [
    "--url",
    config.targetUrl,
    "--format",
    "json",
    "--output",
    outputFile,
    "--flush-session",
    "--timeout",
    String(Math.min(timeout, 30))
  ];
  if (config.modules) args.push("--module", config.modules);
  if (config.scope) args.push("--scope", config.scope);
  if (config.maxUrls) args.push("--max-links-per-page", String(config.maxUrls));
  if (config.maxDepth) args.push("--max-depth", String(config.maxDepth));
  if (config.maxScanTime) args.push("--max-scan-time", String(config.maxScanTime));
  if (config.verbosity) args.push("-v", String(config.verbosity));
  if (config.userAgent) args.push("--user-agent", `"${config.userAgent}"`);
  if (config.cookie) args.push("--cookie", `"${config.cookie}"`);
  if (config.noColor !== false) args.push("--no-bugreport");
  const fullArgs = args.join(" ");
  console.log(`[Wapiti] Starting scan: wapiti ${fullArgs}`);
  let result;
  try {
    result = await executeTool({
      tool: "bash",
      args: `-c "wapiti ${fullArgs} 2>&1 || python3 -m wapiti ${fullArgs} 2>&1"`,
      target: config.targetUrl,
      timeoutSeconds: timeout + 60,
      engagementId: config.engagementId
    });
  } catch (err) {
    return {
      scanId: null,
      status: "error",
      target: config.targetUrl,
      findings: [],
      infos: [],
      anomalies: [],
      stats: { crawledUrls: 0, scannedUrls: 0, modulesRun: 0, durationSeconds: (Date.now() - startTime) / 1e3 },
      rawOutput: "",
      error: err.message
    };
  }
  if (result.timedOut) {
    return {
      scanId: null,
      status: "timeout",
      target: config.targetUrl,
      findings: parseWapitiText(result.stdout),
      infos: [],
      anomalies: [],
      stats: { crawledUrls: 0, scannedUrls: 0, modulesRun: 0, durationSeconds: timeout },
      rawOutput: result.stdout
    };
  }
  let jsonReport = "";
  try {
    const catResult = await executeTool({
      tool: "cat",
      args: outputFile,
      timeoutSeconds: 10
    });
    jsonReport = catResult.stdout;
  } catch {
  }
  let findings;
  let infos = [];
  let anomalies = [];
  let crawledUrls = 0;
  if (jsonReport.trim()) {
    const parsed = parseWapitiJSON(jsonReport);
    findings = parsed.findings;
    infos = parsed.infos;
    anomalies = parsed.anomalies;
    crawledUrls = parsed.crawledUrls;
  } else {
    findings = parseWapitiText(result.stdout);
  }
  const durationSeconds = (Date.now() - startTime) / 1e3;
  let scanId = null;
  try {
    const db = await getDb();
    const allFindings = [...findings, ...anomalies];
    const severitySummary = {
      critical: allFindings.filter((f) => f.severity === "critical").length,
      high: allFindings.filter((f) => f.severity === "high").length,
      medium: allFindings.filter((f) => f.severity === "medium").length,
      low: allFindings.filter((f) => f.severity === "low").length,
      info: [...allFindings, ...infos].filter((f) => f.severity === "info").length
    };
    const [inserted] = await db.insert(scanResults).values({
      engagementId: config.engagementId,
      tool: "wapiti",
      target: config.targetUrl,
      command: `wapiti ${fullArgs}`,
      rawOutput: result.stdout.slice(0, 5e5),
      rawStderr: result.stderr?.slice(0, 5e4) || null,
      exitCode: result.exitCode,
      durationMs: Math.round(durationSeconds * 1e3),
      timedOut: 0,
      findings: JSON.stringify({ vulnerabilities: findings, infos, anomalies }),
      findingCount: findings.length,
      severitySummary: JSON.stringify(severitySummary),
      phase: "vuln_detection",
      operatorId: config.operatorId || null
    });
    scanId = inserted.insertId;
  } catch (dbErr) {
    console.error(`[Wapiti] Failed to store scan result:`, dbErr.message);
  }
  console.log(`[Wapiti] Scan complete: ${findings.length} vulns, ${infos.length} infos, ${anomalies.length} anomalies in ${durationSeconds.toFixed(1)}s`);
  return {
    scanId,
    status: "completed",
    target: config.targetUrl,
    findings,
    infos,
    anomalies,
    stats: {
      crawledUrls,
      scannedUrls: crawledUrls,
      modulesRun: config.modules ? config.modules.split(",").length : 16,
      durationSeconds
    },
    rawOutput: result.stdout
  };
}
async function analyzeWapitiFindings(findings, targetUrl) {
  if (findings.length === 0) {
    return { riskSummary: "No findings to analyze.", injectionVectors: [], recommendations: [] };
  }
  if (useDeterministicAnalysis("wapiti")) {
    console.log(`[Wapiti] Using deterministic analysis for ${findings.length} findings (Tier 1 offload)`);
    return analyzeWapitiFindingsDeterministic(findings, targetUrl);
  }
  const findingSummary = findings.slice(0, 25).map(
    (f) => `[${f.severity.toUpperCase()}] ${f.module} \u2014 ${f.method} ${f.path}${f.parameter ? ` (param: ${f.parameter})` : ""} \u2014 ${f.description.slice(0, 120)}`
  ).join("\n");
  const response = await throttledLLMCall("wapiti-analyst", () => invokeLLM({
    _caller: "wapiti-scanner.analyzeWapitiFindings",
    messages: [
      {
        role: "system",
        content: `You are a web application security analyst reviewing Wapiti scanner findings. Wapiti specializes in injection testing (SQL, XSS, XXE, command exec, SSRF). Analyze the findings and provide:
1. Risk summary (2-3 sentences)
2. Injection vectors with exploitability assessment
3. Remediation recommendations

Target: ${targetUrl}
Respond in JSON format.`
      },
      {
        role: "user",
        content: `Analyze these Wapiti findings:

${findingSummary}`
      }
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "wapiti_analysis",
        strict: true,
        schema: {
          type: "object",
          properties: {
            riskSummary: { type: "string" },
            injectionVectors: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  path: { type: "string" },
                  parameter: { type: "string" },
                  type: { type: "string" },
                  severity: { type: "string" },
                  exploitability: { type: "string" }
                },
                required: ["path", "parameter", "type", "severity", "exploitability"],
                additionalProperties: false
              }
            },
            recommendations: {
              type: "array",
              items: { type: "string" }
            }
          },
          required: ["riskSummary", "injectionVectors", "recommendations"],
          additionalProperties: false
        }
      }
    }
  }));
  try {
    const parsed = JSON.parse(response.choices[0]?.message?.content || "{}");
    return {
      riskSummary: parsed.riskSummary || "Analysis unavailable.",
      injectionVectors: parsed.injectionVectors || [],
      recommendations: parsed.recommendations || []
    };
  } catch {
    return { riskSummary: "LLM analysis failed to parse.", injectionVectors: [], recommendations: [] };
  }
}

export {
  startWapitiScan,
  analyzeWapitiFindings
};
