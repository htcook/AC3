/**
 * Arachni Web Application Scanner Module
 *
 * Full-featured, modular web application security scanner that performs:
 * - Active and passive vulnerability checks
 * - SQL injection, XSS, code injection, file inclusion, CSRF
 * - Path traversal, response splitting, unvalidated redirects
 * - Intelligent form handling and authentication support
 * - DOM-based vulnerability detection via integrated browser
 * - Comprehensive technology fingerprinting
 *
 * Execution: SSH → scan server → arachni → JSON/AFR report → parse → scan_results
 *
 * Note: Arachni project is no longer actively maintained but remains a powerful
 * scanner. The binary (arachni) should be pre-installed on the scan server.
 * If unavailable, falls back to arachni_cli Docker image.
 */

import { executeTool, executeRawCommand, type ToolExecResult } from "../scan-server-executor";
import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { getDb } from "../../db";
import { scanResults } from "../../../drizzle/schema";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ArachniConfig {
  /** Target URL */
  targetUrl: string;
  /** Engagement ID for audit trail */
  engagementId: number;
  /** Checks to enable (empty = all) */
  checks?: string[];
  /** Audit scope: page, subdomain, domain, global */
  scope?: "page" | "subdomain" | "domain" | "global";
  /** Max scan duration in seconds (default 600) */
  timeoutSeconds?: number;
  /** Max pages to crawl */
  maxPages?: number;
  /** Max depth for crawler */
  maxDepth?: number;
  /** Browser cluster pool size (for DOM checks) */
  browserPoolSize?: number;
  /** HTTP request concurrency */
  httpRequestConcurrency?: number;
  /** Custom user agent */
  userAgent?: string;
  /** Cookie string for authenticated scanning */
  cookie?: string;
  /** Operator ID */
  operatorId?: number;
  /** Exclude URL patterns (regex) */
  excludePatterns?: string[];
  /** Enable DOM-based checks (requires browser) */
  domChecks?: boolean;
}

export interface ArachniFinding {
  id: string;
  name: string;
  module: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  remedy: string | null;
  url: string;
  method: string;
  parameter: string | null;
  injectedValue: string | null;
  proof: string | null;
  cweId: string | null;
  cvssv2: number | null;
  references: Record<string, string>;
  tags: string[];
  platform: string | null;
  trusted: boolean;
}

export interface ArachniScanResult {
  scanId: number | null;
  status: "completed" | "error" | "timeout";
  target: string;
  findings: ArachniFinding[];
  sitemap: string[];
  stats: {
    pagesAudited: number;
    requestCount: number;
    responsesReceived: number;
    durationSeconds: number;
    checksRun: number;
  };
  plugins: Record<string, any>;
  rawOutput: string;
  error?: string;
}

// ─── Severity Mapping ───────────────────────────────────────────────────────

function arachniSeverityToOurs(severity: string): ArachniFinding["severity"] {
  switch (severity?.toLowerCase()) {
    case "high": return "high";
    case "medium": return "medium";
    case "low": return "low";
    case "informational": return "info";
    default: return "medium";
  }
}

// Arachni check name → severity override for known critical checks
const CRITICAL_CHECKS: Set<string> = new Set([
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
  "unserialize",
]);

// ─── Output Parser ──────────────────────────────────────────────────────────

/**
 * Parse Arachni's JSON report format.
 * Arachni outputs detailed JSON with issues, sitemap, and plugin results.
 */
function parseArachniJSON(jsonStr: string): {
  findings: ArachniFinding[];
  sitemap: string[];
  stats: ArachniScanResult["stats"];
  plugins: Record<string, any>;
} {
  const findings: ArachniFinding[] = [];
  let sitemap: string[] = [];
  let stats: ArachniScanResult["stats"] = {
    pagesAudited: 0,
    requestCount: 0,
    responsesReceived: 0,
    durationSeconds: 0,
    checksRun: 0,
  };
  let plugins: Record<string, any> = {};

  try {
    const report = JSON.parse(jsonStr);

    // Parse issues
    if (Array.isArray(report.issues)) {
      for (const issue of report.issues) {
        const checkName = issue.check?.shortname || issue.name || "";
        let severity = arachniSeverityToOurs(issue.severity);
        // Upgrade to critical for known dangerous checks
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
          trusted: issue.trusted !== false,
        });
      }
    }

    // Parse sitemap
    if (Array.isArray(report.sitemap)) {
      sitemap = report.sitemap.map((s: any) => typeof s === "string" ? s : s.url || "");
    }

    // Parse stats
    if (report.statistics || report.stats) {
      const s = report.statistics || report.stats;
      stats = {
        pagesAudited: s.found_pages || s.audited_pages || 0,
        requestCount: s.http?.request_count || s.requests || 0,
        responsesReceived: s.http?.response_count || s.responses || 0,
        durationSeconds: s.runtime || s.duration || 0,
        checksRun: s.checks || report.issues?.length || 0,
      };
    }

    // Parse plugin results
    if (report.plugins) {
      plugins = report.plugins;
    }
  } catch (err) {
    console.error("[Arachni] Failed to parse JSON report:", err);
  }

  return { findings, sitemap, stats, plugins };
}

/**
 * Parse Arachni text/stdout output (fallback).
 */
function parseArachniText(output: string): ArachniFinding[] {
  const findings: ArachniFinding[] = [];
  // Match patterns like: [+] SQL Injection (sql_injection) in form input 'id' at http://target/page
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
      trusted: true,
    });
  }
  return findings;
}

// ─── Main Scan Function ─────────────────────────────────────────────────────

export async function startArachniScan(config: ArachniConfig): Promise<ArachniScanResult> {
  const startTime = Date.now();
  const timeout = config.timeoutSeconds || 600;
  const reportFile = `/tmp/arachni-report-${Date.now()}.json`;

  // Build arachni command
  const args: string[] = [
    config.targetUrl,
    "--report-save-path", reportFile.replace(".json", ".afr"),
    "--timeout", `00:${Math.floor(timeout / 60).toString().padStart(2, "0")}:00`,
    "--output-only-positives",
  ];

  if (config.checks?.length) {
    args.push("--checks", config.checks.join(","));
  }

  if (config.scope) {
    const scopeMap: Record<string, string> = {
      page: "--scope-page-limit 1",
      subdomain: "--scope-include-subdomains",
      domain: "--scope-include-subdomains",
      global: "",
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

  // Try direct arachni binary first, then Docker fallback
  let result: ToolExecResult;
  try {
    result = await executeRawCommand(
      `arachni ${fullArgs} 2>&1 || docker run --rm arachni/arachni arachni ${fullArgs} 2>&1`,
      timeout + 60,
    );
  } catch (err: any) {
    return {
      scanId: null,
      status: "error",
      target: config.targetUrl,
      findings: [],
      sitemap: [],
      stats: { pagesAudited: 0, requestCount: 0, responsesReceived: 0, durationSeconds: (Date.now() - startTime) / 1000, checksRun: 0 },
      plugins: {},
      rawOutput: "",
      error: err.message,
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
      rawOutput: result.stdout,
    };
  }

  // Convert AFR to JSON report
  let jsonReport = "";
  try {
    const afrFile = reportFile.replace(".json", ".afr");
    const convertResult = await executeRawCommand(
      `arachni_reporter ${afrFile} --reporter json:outfile=${reportFile} 2>&1 && cat ${reportFile}`,
      30,
    );
    jsonReport = convertResult.stdout;
  } catch {
    // AFR conversion failed, try reading any JSON output directly
    try {
      const catResult = await executeTool({ tool: "cat", args: reportFile, timeoutSeconds: 10 });
      jsonReport = catResult.stdout;
    } catch {
      // No report file
    }
  }

  // Parse findings
  let findings: ArachniFinding[];
  let sitemap: string[] = [];
  let stats: ArachniScanResult["stats"] = {
    pagesAudited: 0, requestCount: 0, responsesReceived: 0,
    durationSeconds: (Date.now() - startTime) / 1000, checksRun: 0,
  };
  let plugins: Record<string, any> = {};

  if (jsonReport.trim()) {
    const parsed = parseArachniJSON(jsonReport);
    findings = parsed.findings;
    sitemap = parsed.sitemap;
    stats = { ...parsed.stats, durationSeconds: (Date.now() - startTime) / 1000 };
    plugins = parsed.plugins;
  } else {
    findings = parseArachniText(result.stdout);
    stats.durationSeconds = (Date.now() - startTime) / 1000;
  }

  // Store in scan_results
  let scanId: number | null = null;
  try {
    const db = getDb();
    const severitySummary = {
      critical: findings.filter(f => f.severity === "critical").length,
      high: findings.filter(f => f.severity === "high").length,
      medium: findings.filter(f => f.severity === "medium").length,
      low: findings.filter(f => f.severity === "low").length,
      info: findings.filter(f => f.severity === "info").length,
    };

    const [inserted] = await db.insert(scanResults).values({
      engagementId: config.engagementId,
      tool: "arachni",
      target: config.targetUrl,
      command: `arachni ${fullArgs}`,
      rawOutput: result.stdout.slice(0, 500_000),
      rawStderr: result.stderr?.slice(0, 50_000) || null,
      exitCode: result.exitCode,
      durationMs: Math.round(stats.durationSeconds * 1000),
      timedOut: 0,
      findings: JSON.stringify(findings),
      findingCount: findings.length,
      severitySummary: JSON.stringify(severitySummary),
      phase: "vuln_detection",
      operatorId: config.operatorId || null,
    });
    scanId = inserted.insertId;
  } catch (dbErr: any) {
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
    rawOutput: result.stdout,
  };
}

// ─── LLM-Powered Finding Analysis ──────────────────────────────────────────

export async function analyzeArachniFindings(
  findings: ArachniFinding[],
  targetUrl: string,
): Promise<{
  riskSummary: string;
  exploitChains: Array<{ chain: string[]; impact: string; likelihood: string }>;
  recommendations: string[];
}> {
  if (findings.length === 0) {
    return { riskSummary: "No findings to analyze.", exploitChains: [], recommendations: [] };
  }

  const findingSummary = findings.slice(0, 25).map(f =>
    `[${f.severity.toUpperCase()}] ${f.name} (${f.module}) — ${f.method} ${f.url}${f.parameter ? ` [param: ${f.parameter}]` : ""}${f.proof ? ` — proof: ${f.proof.slice(0, 80)}` : ""}`
  ).join("\n");

  const response = await throttledLLMCall("arachni-analyst", () => invokeLLM({
    messages: [
      {
        role: "system",
        content: `You are a senior penetration tester analyzing Arachni web scanner findings. Arachni performs deep injection testing with proof-of-concept payloads. Analyze the findings and identify:
1. Risk summary (2-3 sentences)
2. Potential exploit chains (combining multiple findings)
3. Prioritized remediation recommendations

Target: ${targetUrl}
Respond in JSON format.`,
      },
      {
        role: "user",
        content: `Analyze these Arachni findings:\n\n${findingSummary}`,
      },
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
                  likelihood: { type: "string" },
                },
                required: ["chain", "impact", "likelihood"],
                additionalProperties: false,
              },
            },
            recommendations: {
              type: "array",
              items: { type: "string" },
            },
          },
          required: ["riskSummary", "exploitChains", "recommendations"],
          additionalProperties: false,
        },
      },
    },
  }));

  try {
    const parsed = JSON.parse(response.choices[0]?.message?.content || "{}");
    return {
      riskSummary: parsed.riskSummary || "Analysis unavailable.",
      exploitChains: parsed.exploitChains || [],
      recommendations: parsed.recommendations || [],
    };
  } catch {
    return { riskSummary: "LLM analysis failed to parse.", exploitChains: [], recommendations: [] };
  }
}
