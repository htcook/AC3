/**
 * Nikto Web Scanner Module
 *
 * Lightweight, fast web server scanner that checks for:
 * - Dangerous files/programs, outdated server versions
 * - Server configuration issues (directory indexing, HTTP methods)
 * - Default files and programs (admin panels, phpinfo, etc.)
 * - 6,700+ potentially dangerous files/CGIs
 *
 * Execution: SSH → scan server → nikto → JSON/CSV output → parse → scan_results
 *
 * Nikto is ideal for quick web server audits — faster than ZAP for surface-level checks.
 */

import { executeTool, type ToolExecResult } from "../scan-server-executor";
import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { analyzeNiktoFindingsDeterministic, useDeterministicAnalysis } from "../deterministic-scanner-analysis";
import { getDb } from "../../db";
import { scanResults } from "../../../drizzle/schema";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface NiktoConfig {
  /** Target URL (http://host:port) */
  targetUrl: string;
  /** Engagement ID for audit trail */
  engagementId: number;
  /** Tuning options: 1=interesting file, 2=misconfig, 3=info disclosure, 4=injection, 5=remote file retrieval, 6=DOS, 7=remote shell, 8=command exec, 9=SQL injection, 0=file upload */
  tuning?: string;
  /** Max scan duration in seconds (default 300) */
  timeoutSeconds?: number;
  /** Use SSL */
  ssl?: boolean;
  /** Specific port to scan */
  port?: number;
  /** Evasion technique (1-8) */
  evasion?: string;
  /** Output format */
  outputFormat?: "json" | "csv" | "xml";
  /** Operator ID */
  operatorId?: number;
  /** Custom user agent */
  userAgent?: string;
  /** Follow redirects */
  followRedirects?: boolean;
  /** Max redirects to follow */
  maxRedirects?: number;
}

export interface NiktoFinding {
  id: string;
  osvdbId: string | null;
  method: string;
  uri: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  references: string[];
}

export interface NiktoScanResult {
  scanId: number | null;
  status: "completed" | "error" | "timeout";
  target: string;
  findings: NiktoFinding[];
  serverBanner: string | null;
  stats: {
    itemsChecked: number;
    itemsFound: number;
    errorsEncountered: number;
    durationSeconds: number;
  };
  rawOutput: string;
  error?: string;
}

// ─── Severity Mapping ───────────────────────────────────────────────────────

const SEVERITY_KEYWORDS: Record<string, NiktoFinding["severity"]> = {
  "remote code execution": "critical",
  "rce": "critical",
  "command execution": "critical",
  "remote shell": "critical",
  "sql injection": "high",
  "file inclusion": "high",
  "directory traversal": "high",
  "authentication bypass": "high",
  "default password": "high",
  "default credential": "high",
  "backdoor": "critical",
  "xss": "medium",
  "cross-site scripting": "medium",
  "open redirect": "medium",
  "information disclosure": "low",
  "directory listing": "low",
  "directory indexing": "low",
  "server version": "info",
  "allowed http methods": "info",
  "x-frame-options": "low",
  "x-content-type-options": "low",
  "content-security-policy": "low",
  "strict-transport-security": "low",
  "phpinfo": "medium",
  "admin panel": "medium",
  "backup file": "medium",
  "config file": "high",
  ".env": "high",
  ".git": "high",
  "robots.txt": "info",
  "sitemap": "info",
};

function classifySeverity(description: string): NiktoFinding["severity"] {
  const lower = description.toLowerCase();
  for (const [keyword, severity] of Object.entries(SEVERITY_KEYWORDS)) {
    if (lower.includes(keyword)) return severity;
  }
  // Default heuristic: if OSVDB is present, at least low; otherwise info
  return "low";
}

function classifyCategory(description: string): string {
  const lower = description.toLowerCase();
  if (lower.includes("header") || lower.includes("x-frame") || lower.includes("csp")) return "headers";
  if (lower.includes("directory") || lower.includes("listing") || lower.includes("index")) return "misconfiguration";
  if (lower.includes("method") || lower.includes("options") || lower.includes("trace")) return "http-methods";
  if (lower.includes("version") || lower.includes("banner") || lower.includes("server:")) return "fingerprinting";
  if (lower.includes("injection") || lower.includes("xss") || lower.includes("sqli")) return "injection";
  if (lower.includes("file") || lower.includes("backup") || lower.includes("config")) return "sensitive-files";
  if (lower.includes("admin") || lower.includes("login") || lower.includes("panel")) return "authentication";
  if (lower.includes("ssl") || lower.includes("tls") || lower.includes("certificate")) return "ssl-tls";
  return "general";
}

// ─── Output Parser ──────────────────────────────────────────────────────────

/**
 * Parse Nikto's CSV output format.
 * Format: "host","IP","port","OSVDB-ID","HTTP Method","URI","Description"
 */
function parseNiktoCSV(output: string): NiktoFinding[] {
  const findings: NiktoFinding[] = [];
  const lines = output.split("\n").filter(l => l.trim() && !l.startsWith("#"));

  for (const line of lines) {
    // CSV parsing: handle quoted fields
    const fields: string[] = [];
    let current = "";
    let inQuotes = false;
    for (const char of line) {
      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === "," && !inQuotes) {
        fields.push(current.trim());
        current = "";
      } else {
        current += char;
      }
    }
    fields.push(current.trim());

    if (fields.length >= 7) {
      const description = fields[6] || "";
      const osvdbId = fields[3] || "";
      findings.push({
        id: `nikto-${osvdbId || Math.random().toString(36).slice(2, 10)}`,
        osvdbId: osvdbId && osvdbId !== "0" ? `OSVDB-${osvdbId}` : null,
        method: fields[4] || "GET",
        uri: fields[5] || "/",
        description,
        severity: classifySeverity(description),
        category: classifyCategory(description),
        references: osvdbId && osvdbId !== "0" ? [`https://osvdb.org/${osvdbId}`] : [],
      });
    }
  }

  return findings;
}

/**
 * Parse Nikto's text output (fallback when CSV/JSON not available).
 * Lines like: + OSVDB-3268: /icons/: Directory indexing found.
 */
function parseNiktoText(output: string): NiktoFinding[] {
  const findings: NiktoFinding[] = [];
  const findingRegex = /^\+\s+(OSVDB-\d+)?:?\s*(.+?):\s*(.+)$/gm;

  let match;
  while ((match = findingRegex.exec(output)) !== null) {
    const osvdbId = match[1] || null;
    const uri = match[2]?.trim() || "/";
    const description = match[3]?.trim() || "";

    if (description && !description.startsWith("Target") && !description.startsWith("Start Time")) {
      findings.push({
        id: `nikto-${osvdbId || Math.random().toString(36).slice(2, 10)}`,
        osvdbId,
        method: "GET",
        uri,
        description,
        severity: classifySeverity(description),
        category: classifyCategory(description),
        references: osvdbId ? [`https://osvdb.org/${osvdbId.replace("OSVDB-", "")}`] : [],
      });
    }
  }

  // Also capture lines like: + The anti-clickjacking X-Frame-Options header is not present.
  const simpleRegex = /^\+\s+(?!Target|Start|End|host|Server|retrieved)(.+)$/gm;
  while ((match = simpleRegex.exec(output)) !== null) {
    const desc = match[1].trim();
    // Skip if already captured by findingRegex
    if (!findings.some(f => f.description === desc) && desc.length > 10) {
      findings.push({
        id: `nikto-${Math.random().toString(36).slice(2, 10)}`,
        osvdbId: null,
        method: "GET",
        uri: "/",
        description: desc,
        severity: classifySeverity(desc),
        category: classifyCategory(desc),
        references: [],
      });
    }
  }

  return findings;
}

/**
 * Extract server banner from Nikto output.
 */
function extractServerBanner(output: string): string | null {
  const bannerMatch = output.match(/Server:\s*(.+)/i);
  return bannerMatch ? bannerMatch[1].trim() : null;
}

// ─── Main Scan Function ─────────────────────────────────────────────────────

export async function startNiktoScan(config: NiktoConfig): Promise<NiktoScanResult> {
  const startTime = Date.now();
  const timeout = config.timeoutSeconds || 300;

  // Build nikto command
  const args: string[] = [
    "-h", config.targetUrl,
    "-Format", "csv",
    "-output", "/tmp/nikto-output.csv",
    "-nointeractive",
    "-maxtime", `${timeout}s`,
  ];

  if (config.tuning) args.push("-Tuning", config.tuning);
  if (config.ssl) args.push("-ssl");
  if (config.port) args.push("-p", String(config.port));
  if (config.evasion) args.push("-evasion", config.evasion);
  if (config.userAgent) args.push("-useragent", `"${config.userAgent}"`);
  if (config.followRedirects) args.push("-followredirects");

  const fullArgs = args.join(" ");
  console.log(`[Nikto] Starting scan: nikto ${fullArgs}`);

  let result: ToolExecResult;
  try {
    result = await executeTool({
      tool: "nikto",
      args: fullArgs,
      target: config.targetUrl,
      timeoutSeconds: timeout + 30, // Extra buffer for SSH overhead
      engagementId: config.engagementId,
    });
  } catch (err: any) {
    return {
      scanId: null,
      status: "error",
      target: config.targetUrl,
      findings: [],
      serverBanner: null,
      stats: { itemsChecked: 0, itemsFound: 0, errorsEncountered: 1, durationSeconds: (Date.now() - startTime) / 1000 },
      rawOutput: "",
      error: err.message,
    };
  }

  if (result.timedOut) {
    return {
      scanId: null,
      status: "timeout",
      target: config.targetUrl,
      findings: parseNiktoText(result.stdout),
      serverBanner: extractServerBanner(result.stdout),
      stats: { itemsChecked: 0, itemsFound: 0, errorsEncountered: 0, durationSeconds: timeout },
      rawOutput: result.stdout,
    };
  }

  // Try to read CSV output file
  let csvOutput = "";
  try {
    const csvResult = await executeTool({
      tool: "cat",
      args: "/tmp/nikto-output.csv",
      timeoutSeconds: 10,
    });
    csvOutput = csvResult.stdout;
  } catch {
    // CSV file not created, fall back to stdout parsing
  }

  // Parse findings
  let findings: NiktoFinding[];
  if (csvOutput.trim()) {
    findings = parseNiktoCSV(csvOutput);
  } else {
    findings = parseNiktoText(result.stdout);
  }

  const durationSeconds = (Date.now() - startTime) / 1000;
  const serverBanner = extractServerBanner(result.stdout);

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
      tool: "nikto",
      target: config.targetUrl,
      command: `nikto ${fullArgs}`,
      rawOutput: result.stdout.slice(0, 500_000),
      rawStderr: result.stderr?.slice(0, 50_000) || null,
      exitCode: result.exitCode,
      durationMs: Math.round(durationSeconds * 1000),
      timedOut: 0,
      findings: JSON.stringify(findings),
      findingCount: findings.length,
      severitySummary: JSON.stringify(severitySummary),
      phase: "vuln_detection",
      operatorId: config.operatorId || null,
    });
    scanId = inserted.insertId;
  } catch (dbErr: any) {
    console.error(`[Nikto] Failed to store scan result:`, dbErr.message);
  }

  console.log(`[Nikto] Scan complete: ${findings.length} findings in ${durationSeconds.toFixed(1)}s`);

  return {
    scanId,
    status: "completed",
    target: config.targetUrl,
    findings,
    serverBanner,
    stats: {
      itemsChecked: findings.length * 10, // Approximate
      itemsFound: findings.length,
      errorsEncountered: result.exitCode !== 0 ? 1 : 0,
      durationSeconds,
    },
    rawOutput: result.stdout,
  };
}

// ─── LLM-Powered Finding Analysis ──────────────────────────────────────────

export async function analyzeNiktoFindings(
  findings: NiktoFinding[],
  targetUrl: string,
  serverBanner: string | null,
): Promise<{
  riskSummary: string;
  prioritizedFindings: Array<NiktoFinding & { exploitability: string; recommendation: string }>;
  attackSurface: string[];
}> {
  if (findings.length === 0) {
    return { riskSummary: "No findings to analyze.", prioritizedFindings: [], attackSurface: [] };
  }

  // Tier 1 Offload: Use deterministic analysis by default
  if (useDeterministicAnalysis("nikto")) {
    console.log(`[Nikto] Using deterministic analysis for ${findings.length} findings (Tier 1 offload)`);
    return analyzeNiktoFindingsDeterministic(findings, targetUrl, serverBanner) as any;
  }

  // Fallback: LLM-powered analysis (when SCANNER_ANALYSIS_MODE_NIKTO=llm)
  const findingSummary = findings.slice(0, 30).map(f =>
    `[${f.severity.toUpperCase()}] ${f.method} ${f.uri} — ${f.description}`
  ).join("\n");

  const response = await throttledLLMCall("nikto-analyst", () => invokeLLM({ _caller: "nikto-scanner",
    _caller: "nikto-scanner.analyzeNiktoFindings",
    messages: [
      {
        role: "system",
        content: `You are a penetration testing analyst reviewing Nikto web scanner findings. Analyze the findings for a target and provide:
1. A concise risk summary (2-3 sentences)
2. Prioritized findings with exploitability assessment and remediation recommendations
3. Attack surface observations

Server banner: ${serverBanner || "Unknown"}
Target: ${targetUrl}

Respond in JSON format.`,
      },
      {
        role: "user",
        content: `Analyze these Nikto findings:\n\n${findingSummary}`,
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "nikto_analysis",
        strict: true,
        schema: {
          type: "object",
          properties: {
            riskSummary: { type: "string" },
            prioritizedFindings: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  uri: { type: "string" },
                  severity: { type: "string" },
                  exploitability: { type: "string" },
                  recommendation: { type: "string" },
                },
                required: ["uri", "severity", "exploitability", "recommendation"],
                additionalProperties: false,
              },
            },
            attackSurface: {
              type: "array",
              items: { type: "string" },
            },
          },
          required: ["riskSummary", "prioritizedFindings", "attackSurface"],
          additionalProperties: false,
        },
      },
    },
  }));

  try {
    const parsed = JSON.parse(response.choices[0]?.message?.content || "{}");
    return {
      riskSummary: parsed.riskSummary || "Analysis unavailable.",
      prioritizedFindings: (parsed.prioritizedFindings || []).map((pf: any, i: number) => ({
        ...findings[i],
        ...pf,
      })),
      attackSurface: parsed.attackSurface || [],
    };
  } catch {
    return { riskSummary: "LLM analysis failed to parse.", prioritizedFindings: [], attackSurface: [] };
  }
}
