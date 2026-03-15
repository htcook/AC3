/**
 * Wapiti Web Application Scanner Module
 *
 * Open-source web application vulnerability scanner that performs:
 * - Black-box testing (no source code access)
 * - SQL injection, XSS, CRLF, file handling, command execution
 * - XXE, SSRF, open redirect, .htaccess bypass, backup file detection
 * - CSP/cookie/CORS/HTTP header analysis
 * - Shellshock, directory listing, CSRF detection
 *
 * Execution: SSH → scan server → wapiti → JSON output → parse → scan_results
 *
 * Wapiti excels at injection testing — complements Nikto's server-level checks.
 */

import { executeTool, type ToolExecResult } from "../scan-server-executor";
import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { analyzeWapitiFindingsDeterministic, useDeterministicAnalysis } from "../deterministic-scanner-analysis";
import { getDb } from "../../db";
import { scanResults } from "../../../drizzle/schema";

// ─── Types ──────────────────────────────────────────────────────────────────────
export interface WapitiConfig {
  /** Target URL */
  targetUrl: string;
  /** Engagement ID for audit trail */
  engagementId: number;
  /** Attack modules to enable (comma-separated): sql, xss, xxe, exec, file, ssrf, redirect, crlf, htaccess, backup, csp, cookieflags, cors, headers, shellshock, wapp */
  modules?: string;
  /** Scan scope: page, folder, domain, punk (default: folder) */
  scope?: "page" | "folder" | "domain" | "punk";
  /** Max scan duration in seconds (default 300) */
  timeoutSeconds?: number;
  /** Max URLs to crawl */
  maxUrls?: number;
  /** Max depth for crawler */
  maxDepth?: number;
  /** Max scan time in seconds (wapiti-internal) */
  maxScanTime?: number;
  /** Verbosity level (0-2) */
  verbosity?: number;
  /** Custom user agent */
  userAgent?: string;
  /** Authentication cookie */
  cookie?: string;
  /** Operator ID */
  operatorId?: number;
  /** Color output (disable for parsing) */
  noColor?: boolean;
}

export interface WapitiFinding {
  id: string;
  module: string;
  category: string;
  level: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  method: string;
  path: string;
  parameter: string | null;
  httpResponse: string | null;
  curlCommand: string | null;
  wstgCode: string | null;
  cweId: string | null;
  references: string[];
}

export interface WapitiScanResult {
  scanId: number | null;
  status: "completed" | "error" | "timeout";
  target: string;
  findings: WapitiFinding[];
  infos: WapitiFinding[];
  anomalies: WapitiFinding[];
  stats: {
    crawledUrls: number;
    scannedUrls: number;
    modulesRun: number;
    durationSeconds: number;
  };
  rawOutput: string;
  error?: string;
}

// ─── Severity Mapping ───────────────────────────────────────────────────────

function wapitiLevelToSeverity(level: number): WapitiFinding["severity"] {
  switch (level) {
    case 4: return "critical";
    case 3: return "high";
    case 2: return "medium";
    case 1: return "low";
    default: return "info";
  }
}

function moduleToCategory(module: string): string {
  const map: Record<string, string> = {
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
    permanentxss: "injection",
  };
  return map[module] || "general";
}

// ─── Output Parser ──────────────────────────────────────────────────────────

/**
 * Parse Wapiti's JSON report output.
 * Wapiti outputs a structured JSON report with classifications, vulnerabilities, anomalies, and infos.
 */
function parseWapitiJSON(jsonStr: string): {
  findings: WapitiFinding[];
  infos: WapitiFinding[];
  anomalies: WapitiFinding[];
  crawledUrls: number;
} {
  const findings: WapitiFinding[] = [];
  const infos: WapitiFinding[] = [];
  const anomalies: WapitiFinding[] = [];
  let crawledUrls = 0;

  try {
    const report = JSON.parse(jsonStr);

    // Parse vulnerabilities
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
            references: Array.isArray(vuln.referer) ? vuln.referer : [],
          });
        }
      }
    }

    // Parse infos (technology detection, etc.)
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
            references: [],
          });
        }
      }
    }

    // Parse anomalies (server errors, timeouts)
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
            references: [],
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

/**
 * Parse Wapiti text output (fallback).
 */
function parseWapitiText(output: string): WapitiFinding[] {
  const findings: WapitiFinding[] = [];
  // Match lines like: [*] SQL Injection in http://target/page via parameter "id"
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
      references: [],
    });
  }
  return findings;
}

// ─── Main Scan Function ─────────────────────────────────────────────────────

export async function startWapitiScan(config: WapitiConfig): Promise<WapitiScanResult> {
  const startTime = Date.now();
  const timeout = config.timeoutSeconds || 300;
  const outputFile = `/tmp/wapiti-report-${Date.now()}.json`;

  // Build wapiti command
  const args: string[] = [
    "--url", config.targetUrl,
    "--format", "json",
    "--output", outputFile,
    "--flush-session",
    "--timeout", String(Math.min(timeout, 30)),
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

  // Wapiti is a Python tool, may need to be called via python3
  let result: ToolExecResult;
  try {
    result = await executeTool({
      tool: "bash",
      args: `-c "wapiti ${fullArgs} 2>&1 || python3 -m wapiti ${fullArgs} 2>&1"`,
      target: config.targetUrl,
      timeoutSeconds: timeout + 60,
      engagementId: config.engagementId,
    });
  } catch (err: any) {
    return {
      scanId: null,
      status: "error",
      target: config.targetUrl,
      findings: [],
      infos: [],
      anomalies: [],
      stats: { crawledUrls: 0, scannedUrls: 0, modulesRun: 0, durationSeconds: (Date.now() - startTime) / 1000 },
      rawOutput: "",
      error: err.message,
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
      rawOutput: result.stdout,
    };
  }

  // Read JSON report
  let jsonReport = "";
  try {
    const catResult = await executeTool({
      tool: "cat",
      args: outputFile,
      timeoutSeconds: 10,
    });
    jsonReport = catResult.stdout;
  } catch {
    // JSON report not created
  }

  // Parse findings
  let findings: WapitiFinding[];
  let infos: WapitiFinding[] = [];
  let anomalies: WapitiFinding[] = [];
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

  const durationSeconds = (Date.now() - startTime) / 1000;

  // Store in scan_results
  let scanId: number | null = null;
  try {
    const db = getDb();
    const allFindings = [...findings, ...anomalies];
    const severitySummary = {
      critical: allFindings.filter(f => f.severity === "critical").length,
      high: allFindings.filter(f => f.severity === "high").length,
      medium: allFindings.filter(f => f.severity === "medium").length,
      low: allFindings.filter(f => f.severity === "low").length,
      info: [...allFindings, ...infos].filter(f => f.severity === "info").length,
    };

    const [inserted] = await db.insert(scanResults).values({
      engagementId: config.engagementId,
      tool: "wapiti",
      target: config.targetUrl,
      command: `wapiti ${fullArgs}`,
      rawOutput: result.stdout.slice(0, 500_000),
      rawStderr: result.stderr?.slice(0, 50_000) || null,
      exitCode: result.exitCode,
      durationMs: Math.round(durationSeconds * 1000),
      timedOut: 0,
      findings: JSON.stringify({ vulnerabilities: findings, infos, anomalies }),
      findingCount: findings.length,
      severitySummary: JSON.stringify(severitySummary),
      phase: "vuln_detection",
      operatorId: config.operatorId || null,
    });
    scanId = inserted.insertId;
  } catch (dbErr: any) {
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
      durationSeconds,
    },
    rawOutput: result.stdout,
  };
}

// ─── LLM-Powered Finding Analysis ──────────────────────────────────────────

export async function analyzeWapitiFindings(
  findings: WapitiFinding[],
  targetUrl: string,
): Promise<{
  riskSummary: string;
  injectionVectors: Array<{ path: string; parameter: string; type: string; severity: string; exploitability: string }>;
  recommendations: string[];
}> {
  if (findings.length === 0) {
    return { riskSummary: "No findings to analyze.", injectionVectors: [], recommendations: [] };
  }

  // Tier 1 Offload: Use deterministic analysis by default
  if (useDeterministicAnalysis("wapiti")) {
    console.log(`[Wapiti] Using deterministic analysis for ${findings.length} findings (Tier 1 offload)`);
    return analyzeWapitiFindingsDeterministic(findings, targetUrl);
  }

  // Fallback: LLM-powered analysis
  const findingSummary = findings.slice(0, 25).map(f =>
    `[${f.severity.toUpperCase()}] ${f.module} — ${f.method} ${f.path}${f.parameter ? ` (param: ${f.parameter})` : ""} — ${f.description.slice(0, 120)}`
  ).join("\n");

  const response = await throttledLLMCall("wapiti-analyst", () => invokeLLM({
    messages: [
      {
        role: "system",
        content: `You are a web application security analyst reviewing Wapiti scanner findings. Wapiti specializes in injection testing (SQL, XSS, XXE, command exec, SSRF). Analyze the findings and provide:
1. Risk summary (2-3 sentences)
2. Injection vectors with exploitability assessment
3. Remediation recommendations

Target: ${targetUrl}
Respond in JSON format.`,
      },
      {
        role: "user",
        content: `Analyze these Wapiti findings:\n\n${findingSummary}`,
      },
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
                  exploitability: { type: "string" },
                },
                required: ["path", "parameter", "type", "severity", "exploitability"],
                additionalProperties: false,
              },
            },
            recommendations: {
              type: "array",
              items: { type: "string" },
            },
          },
          required: ["riskSummary", "injectionVectors", "recommendations"],
          additionalProperties: false,
        },
      },
    },
  }));

  try {
    const parsed = JSON.parse(response.choices[0]?.message?.content || "{}");
    return {
      riskSummary: parsed.riskSummary || "Analysis unavailable.",
      injectionVectors: parsed.injectionVectors || [],
      recommendations: parsed.recommendations || [],
    };
  } catch {
    return { riskSummary: "LLM analysis failed to parse.", injectionVectors: [], recommendations: [] };
  }
}
