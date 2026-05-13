import {
  analyzeArachniFindingsDeterministic,
  init_deterministic_scanner_analysis,
  useDeterministicAnalysis
} from "./chunk-EILMWEUF.js";
import {
  init_llm_throttle,
  throttledLLMCall
} from "./chunk-UJVJACSD.js";
import {
  executeRawCommand,
  executeTool,
  init_scan_server_executor
} from "./chunk-BDKAXPQT.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-4BQS7LEI.js";
import {
  getDb,
  init_db
} from "./chunk-VL2KRLTM.js";
import {
  init_schema,
  scanResults
} from "./chunk-IG2G4XDA.js";

// server/lib/scanners/arachni-scanner.ts
init_scan_server_executor();
init_llm();
init_llm_throttle();
init_deterministic_scanner_analysis();
init_db();
init_schema();
function arachniSeverityToOurs(severity) {
  switch (severity?.toLowerCase()) {
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "informational":
      return "info";
    default:
      return "medium";
  }
}
var CRITICAL_CHECKS = /* @__PURE__ */ new Set([
  "os_cmd_injection",
  "os_cmd_injection_timing",
  "code_injection",
  "code_injection_timing",
  "file_inclusion",
  "rfi",
  "sql_injection",
  "sql_injection_timing",
  "sql_injection_differential",
  "xpath_injection",
  "ldap_injection",
  "xxe",
  "unserialize"
]);
function parseArachniJSON(jsonStr) {
  const findings = [];
  let sitemap = [];
  let stats = {
    pagesAudited: 0,
    requestCount: 0,
    responsesReceived: 0,
    durationSeconds: 0,
    checksRun: 0
  };
  let plugins = {};
  try {
    const report = JSON.parse(jsonStr);
    if (Array.isArray(report.issues)) {
      for (const issue of report.issues) {
        const checkName = issue.check?.shortname || issue.name || "";
        let severity = arachniSeverityToOurs(issue.severity);
        if (CRITICAL_CHECKS.has(checkName) && severity !== "info") {
          severity = "critical";
        }
        findings.push({
          id: `arachni-${issue.digest || Math.random().toString(36).slice(2, 10)}`,
          name: issue.name || checkName,
          module: checkName,
          severity,
          description: issue.description || "",
          remedy: issue.remedy_guidance || issue.remedy_code || null,
          url: issue.vector?.url || issue.page?.url || "",
          method: issue.vector?.method?.toUpperCase() || "GET",
          parameter: issue.vector?.affected_input_name || null,
          injectedValue: issue.vector?.injected || null,
          proof: issue.proof ? String(issue.proof).slice(0, 500) : null,
          cweId: issue.cwe ? `CWE-${issue.cwe}` : null,
          cvssv2: issue.cvssv2 || null,
          references: issue.references || {},
          tags: issue.tags || [],
          platform: issue.platform_name || null,
          trusted: issue.trusted !== false
        });
      }
    }
    if (Array.isArray(report.sitemap)) {
      sitemap = report.sitemap.map((s) => typeof s === "string" ? s : s.url || "");
    }
    if (report.statistics || report.stats) {
      const s = report.statistics || report.stats;
      stats = {
        pagesAudited: s.found_pages || s.audited_pages || 0,
        requestCount: s.http?.request_count || s.requests || 0,
        responsesReceived: s.http?.response_count || s.responses || 0,
        durationSeconds: s.runtime || s.duration || 0,
        checksRun: s.checks || report.issues?.length || 0
      };
    }
    if (report.plugins) {
      plugins = report.plugins;
    }
  } catch (err) {
    console.error("[Arachni] Failed to parse JSON report:", err);
  }
  return { findings, sitemap, stats, plugins };
}
function parseArachniText(output) {
  const findings = [];
  const vulnRegex = /\[[\+!]\]\s+(.+?)\s+\((\w+)\)\s+(?:in\s+.+?\s+)?at\s+(\S+)/gm;
  let match;
  while ((match = vulnRegex.exec(output)) !== null) {
    const name = match[1];
    const module = match[2];
    const url = match[3];
    const isCritical = CRITICAL_CHECKS.has(module);
    findings.push({
      id: `arachni-text-${Math.random().toString(36).slice(2, 10)}`,
      name,
      module,
      severity: isCritical ? "critical" : "medium",
      description: name,
      remedy: null,
      url,
      method: "GET",
      parameter: null,
      injectedValue: null,
      proof: null,
      cweId: null,
      cvssv2: null,
      references: {},
      tags: [],
      platform: null,
      trusted: true
    });
  }
  return findings;
}
async function startArachniScan(config) {
  const startTime = Date.now();
  const timeout = config.timeoutSeconds || 600;
  const reportFile = `/tmp/arachni-report-${Date.now()}.json`;
  const args = [
    config.targetUrl,
    "--report-save-path",
    reportFile.replace(".json", ".afr"),
    "--timeout",
    `00:${Math.floor(timeout / 60).toString().padStart(2, "0")}:00`,
    "--output-only-positives"
  ];
  if (config.checks?.length) {
    args.push("--checks", config.checks.join(","));
  }
  if (config.scope) {
    const scopeMap = {
      page: "--scope-page-limit 1",
      subdomain: "--scope-include-subdomains",
      domain: "--scope-include-subdomains",
      global: ""
    };
    if (scopeMap[config.scope]) args.push(scopeMap[config.scope]);
  }
  if (config.maxPages) args.push("--scope-page-limit", String(config.maxPages));
  if (config.maxDepth) args.push("--scope-directory-depth-limit", String(config.maxDepth));
  if (config.browserPoolSize) args.push("--browser-cluster-pool-size", String(config.browserPoolSize));
  if (config.httpRequestConcurrency) args.push("--http-request-concurrency", String(config.httpRequestConcurrency));
  if (config.userAgent) args.push("--http-user-agent", `"${config.userAgent}"`);
  if (config.cookie) args.push("--http-cookie-string", `"${config.cookie}"`);
  if (config.excludePatterns?.length) {
    for (const pattern of config.excludePatterns) {
      args.push("--scope-exclude-pattern", pattern);
    }
  }
  if (config.domChecks === false) args.push("--checks", "*,-*dom*");
  const fullArgs = args.join(" ");
  console.log(`[Arachni] Starting scan: arachni ${fullArgs}`);
  let result;
  try {
    result = await executeRawCommand(
      `arachni ${fullArgs} 2>&1 || docker run --rm arachni/arachni arachni ${fullArgs} 2>&1`,
      timeout + 60
    );
  } catch (err) {
    return {
      scanId: null,
      status: "error",
      target: config.targetUrl,
      findings: [],
      sitemap: [],
      stats: { pagesAudited: 0, requestCount: 0, responsesReceived: 0, durationSeconds: (Date.now() - startTime) / 1e3, checksRun: 0 },
      plugins: {},
      rawOutput: "",
      error: err.message
    };
  }
  if (result.timedOut) {
    return {
      scanId: null,
      status: "timeout",
      target: config.targetUrl,
      findings: parseArachniText(result.stdout),
      sitemap: [],
      stats: { pagesAudited: 0, requestCount: 0, responsesReceived: 0, durationSeconds: timeout, checksRun: 0 },
      plugins: {},
      rawOutput: result.stdout
    };
  }
  let jsonReport = "";
  try {
    const afrFile = reportFile.replace(".json", ".afr");
    const convertResult = await executeRawCommand(
      `arachni_reporter ${afrFile} --reporter json:outfile=${reportFile} 2>&1 && cat ${reportFile}`,
      30
    );
    jsonReport = convertResult.stdout;
  } catch {
    try {
      const catResult = await executeTool({ tool: "cat", args: reportFile, timeoutSeconds: 10 });
      jsonReport = catResult.stdout;
    } catch {
    }
  }
  let findings;
  let sitemap = [];
  let stats = {
    pagesAudited: 0,
    requestCount: 0,
    responsesReceived: 0,
    durationSeconds: (Date.now() - startTime) / 1e3,
    checksRun: 0
  };
  let plugins = {};
  if (jsonReport.trim()) {
    const parsed = parseArachniJSON(jsonReport);
    findings = parsed.findings;
    sitemap = parsed.sitemap;
    stats = { ...parsed.stats, durationSeconds: (Date.now() - startTime) / 1e3 };
    plugins = parsed.plugins;
  } else {
    findings = parseArachniText(result.stdout);
    stats.durationSeconds = (Date.now() - startTime) / 1e3;
  }
  let scanId = null;
  try {
    const db = await getDb();
    const severitySummary = {
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length
    };
    const [inserted] = await db.insert(scanResults).values({
      engagementId: config.engagementId,
      tool: "arachni",
      target: config.targetUrl,
      command: `arachni ${fullArgs}`,
      rawOutput: result.stdout.slice(0, 5e5),
      rawStderr: result.stderr?.slice(0, 5e4) || null,
      exitCode: result.exitCode,
      durationMs: Math.round(stats.durationSeconds * 1e3),
      timedOut: 0,
      findings: JSON.stringify(findings),
      findingCount: findings.length,
      severitySummary: JSON.stringify(severitySummary),
      phase: "vuln_detection",
      operatorId: config.operatorId || null
    });
    scanId = inserted.insertId;
  } catch (dbErr) {
    console.error(`[Arachni] Failed to store scan result:`, dbErr.message);
  }
  console.log(`[Arachni] Scan complete: ${findings.length} findings, ${sitemap.length} pages in ${stats.durationSeconds.toFixed(1)}s`);
  return {
    scanId,
    status: "completed",
    target: config.targetUrl,
    findings,
    sitemap,
    stats,
    plugins,
    rawOutput: result.stdout
  };
}
async function analyzeArachniFindings(findings, targetUrl) {
  if (findings.length === 0) {
    return { riskSummary: "No findings to analyze.", exploitChains: [], recommendations: [] };
  }
  if (useDeterministicAnalysis("arachni")) {
    console.log(`[Arachni] Using deterministic analysis for ${findings.length} findings (Tier 1 offload)`);
    return analyzeArachniFindingsDeterministic(findings, targetUrl);
  }
  const findingSummary = findings.slice(0, 25).map(
    (f) => `[${f.severity.toUpperCase()}] ${f.name} (${f.module}) \u2014 ${f.method} ${f.url}${f.parameter ? ` [param: ${f.parameter}]` : ""}${f.proof ? ` \u2014 proof: ${f.proof.slice(0, 80)}` : ""}`
  ).join("\n");
  const response = await throttledLLMCall("arachni-analyst", () => invokeLLM({
    _caller: "arachni-scanner.analyzeArachniFindings",
    messages: [
      {
        role: "system",
        content: `You are a senior penetration tester analyzing Arachni web scanner findings. Arachni performs deep injection testing with proof-of-concept payloads. Analyze the findings and identify:
1. Risk summary (2-3 sentences)
2. Potential exploit chains (combining multiple findings)
3. Prioritized remediation recommendations

Target: ${targetUrl}
Respond in JSON format.`
      },
      {
        role: "user",
        content: `Analyze these Arachni findings:

${findingSummary}`
      }
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "arachni_analysis",
        strict: true,
        schema: {
          type: "object",
          properties: {
            riskSummary: { type: "string" },
            exploitChains: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  chain: { type: "array", items: { type: "string" } },
                  impact: { type: "string" },
                  likelihood: { type: "string" }
                },
                required: ["chain", "impact", "likelihood"],
                additionalProperties: false
              }
            },
            recommendations: {
              type: "array",
              items: { type: "string" }
            }
          },
          required: ["riskSummary", "exploitChains", "recommendations"],
          additionalProperties: false
        }
      }
    }
  }));
  try {
    const parsed = JSON.parse(response.choices[0]?.message?.content || "{}");
    return {
      riskSummary: parsed.riskSummary || "Analysis unavailable.",
      exploitChains: parsed.exploitChains || [],
      recommendations: parsed.recommendations || []
    };
  } catch {
    return { riskSummary: "LLM analysis failed to parse.", exploitChains: [], recommendations: [] };
  }
}

export {
  startArachniScan,
  analyzeArachniFindings
};
