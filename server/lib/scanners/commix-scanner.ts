/**
 * Commix Scanner Module
 *
 * Dedicated OS command injection detection and exploitation tool that performs:
 * - Automated detection of command injection vulnerabilities (results-based, blind time-based, blind file-based)
 * - Multiple injection techniques: classic, eval-based, time-based, file-based
 * - Support for GET, POST, cookie, and header injection points
 * - WAF/IPS evasion via tamper scripts and encoding
 * - Pseudo-terminal shell access on confirmed injection points
 * - Support for Unix and Windows targets
 *
 * Execution: SSH → scan server → commix → text output → parse → scan_results
 *
 * Commix fills a critical gap that SQLMap and ZAP don't cover: OS command injection
 * through application parameters (e.g., ping, traceroute, file operations).
 */
import { executeTool, type ToolExecResult } from "../scan-server-executor";
import { getDb } from "../../db";
import { scanResults, webAppFindings } from "../../../drizzle/schema";
import { mapToMitre } from "../zap-scanner";

// ─── Types ──────────────────────────────────────────────────────────────────────

export interface CommixConfig {
  /** Target URL with injectable parameter */
  targetUrl: string;
  /** Engagement ID for audit trail */
  engagementId: number;
  /** Specific parameter to test */
  parameter?: string;
  /** HTTP method */
  method?: "GET" | "POST";
  /** POST data for POST requests */
  postData?: string;
  /** Cookie string for authenticated scanning */
  cookie?: string;
  /** Custom headers */
  headers?: Record<string, string>;
  /** Injection level (1-3): higher = more techniques */
  level?: 1 | 2 | 3;
  /** Timeout per URL in seconds */
  timeoutSeconds?: number;
  /** Target OS hint: unix or windows */
  targetOs?: "unix" | "windows";
  /** Enable tamper scripts for WAF bypass */
  tamper?: string;
  /** Batch mode (non-interactive) */
  batch?: boolean;
}

export interface CommixFinding {
  type: "cmdi" | "blind_cmdi" | "info";
  severity: "critical" | "high" | "medium" | "info";
  title: string;
  url: string;
  parameter?: string;
  technique?: string;
  payload?: string;
  osOutput?: string;
  rawOutput?: string;
}

export interface CommixScanResult {
  targetUrl: string;
  findings: CommixFinding[];
  stats: {
    durationSeconds: number;
    parametersTestedCount: number;
    injectionsFound: number;
    wafDetected: boolean;
  };
  rawOutput: string;
  exitCode: number;
  timedOut: boolean;
}

// ─── Core Scanner ───────────────────────────────────────────────────────────────

function buildCommixCommand(config: CommixConfig): string {
  const parts = ["commix"];

  parts.push(`--url="${config.targetUrl}"`);
  parts.push("--batch"); // Non-interactive

  if (config.parameter) parts.push(`-p "${config.parameter}"`);
  if (config.method === "POST") parts.push("--method=POST");
  if (config.postData) parts.push(`--data="${config.postData}"`);
  if (config.cookie) parts.push(`--cookie="${config.cookie}"`);

  if (config.headers) {
    for (const [key, value] of Object.entries(config.headers)) {
      parts.push(`--header="${key}: ${value}"`);
    }
  }

  // Injection level
  const level = config.level || 2;
  parts.push(`--level=${level}`);

  // Target OS
  if (config.targetOs) parts.push(`--os=${config.targetOs}`);

  // Tamper scripts for WAF bypass
  if (config.tamper) parts.push(`--tamper="${config.tamper}"`);

  // Techniques: all by default (classic, eval-based, time-based, file-based)
  parts.push("--technique=CEFT");

  // Output verbosity
  parts.push("-v 2");

  return parts.join(" ");
}

function parseCommixOutput(output: string, targetUrl: string): CommixFinding[] {
  const findings: CommixFinding[] = [];
  const lines = output.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();

    // Confirmed command injection
    if (/the\s+.*parameter.*is\s+injectable/i.test(trimmed) ||
        /command\s+injection.*identified/i.test(trimmed)) {
      const paramMatch = trimmed.match(/['"]([^'"]+)['"]\s+parameter/i) ||
                         trimmed.match(/parameter\s+['"]([^'"]+)['"]/i);
      const techMatch = trimmed.match(/via\s+(.*?)(?:\s+technique|\s+injection|$)/i);
      findings.push({
        type: "cmdi",
        severity: "critical",
        title: `[Commix] Command Injection: ${paramMatch?.[1] || 'unknown param'} via ${techMatch?.[1] || 'classic'}`,
        url: targetUrl,
        parameter: paramMatch?.[1],
        technique: techMatch?.[1] || "classic",
        rawOutput: trimmed,
      });
    }

    // Blind command injection (time-based)
    if (/time-based\s+blind/i.test(trimmed) && /injectable/i.test(trimmed)) {
      const paramMatch = trimmed.match(/['"]([^'"]+)['"]/);
      findings.push({
        type: "blind_cmdi",
        severity: "critical",
        title: `[Commix] Blind Command Injection (time-based): ${paramMatch?.[1] || 'unknown param'}`,
        url: targetUrl,
        parameter: paramMatch?.[1],
        technique: "time-based blind",
        rawOutput: trimmed,
      });
    }

    // File-based blind injection
    if (/file-based/i.test(trimmed) && /injectable/i.test(trimmed)) {
      const paramMatch = trimmed.match(/['"]([^'"]+)['"]/);
      findings.push({
        type: "blind_cmdi",
        severity: "critical",
        title: `[Commix] Blind Command Injection (file-based): ${paramMatch?.[1] || 'unknown param'}`,
        url: targetUrl,
        parameter: paramMatch?.[1],
        technique: "file-based blind",
        rawOutput: trimmed,
      });
    }

    // OS command execution output (proof of exploitation)
    if (/^\s*(uid=\d+|root:|www-data:|Linux\s|Windows\s|MINGW)/i.test(trimmed)) {
      // This is OS output from a confirmed injection
      if (findings.length > 0) {
        findings[findings.length - 1].osOutput = trimmed;
        findings[findings.length - 1].payload = trimmed;
      }
    }

    // Eval-based injection
    if (/eval-based/i.test(trimmed) && /injectable/i.test(trimmed)) {
      const paramMatch = trimmed.match(/['"]([^'"]+)['"]/);
      findings.push({
        type: "cmdi",
        severity: "critical",
        title: `[Commix] Eval-Based Command Injection: ${paramMatch?.[1] || 'unknown param'}`,
        url: targetUrl,
        parameter: paramMatch?.[1],
        technique: "eval-based",
        rawOutput: trimmed,
      });
    }
  }

  return findings;
}

export async function runCommixScan(config: CommixConfig): Promise<CommixScanResult> {
  const startTime = Date.now();
  const timeout = config.timeoutSeconds || 120;
  const command = buildCommixCommand(config);

  let result: ToolExecResult;
  try {
    result = await executeTool({
      tool: "commix",
      command,
      timeout,
      engagementId: config.engagementId,
    });
  } catch (err: any) {
    return {
      targetUrl: config.targetUrl,
      findings: [],
      stats: { durationSeconds: (Date.now() - startTime) / 1000, parametersTestedCount: 0, injectionsFound: 0, wafDetected: false },
      rawOutput: `Error: ${err.message}`,
      exitCode: -1,
      timedOut: false,
    };
  }

  const output = result.stdout + "\n" + result.stderr;
  const findings = parseCommixOutput(output, config.targetUrl);
  const wafDetected = /waf|firewall|blocked|403.*forbidden/i.test(output);

  return {
    targetUrl: config.targetUrl,
    findings,
    stats: {
      durationSeconds: (Date.now() - startTime) / 1000,
      parametersTestedCount: 1,
      injectionsFound: findings.filter(f => f.type === "cmdi" || f.type === "blind_cmdi").length,
      wafDetected,
    },
    rawOutput: output.slice(0, 10000),
    exitCode: result.exitCode ?? 0,
    timedOut: result.timedOut || false,
  };
}

export async function batchCommixScan(
  urls: Array<{ url: string; method?: string; params?: string[] }>,
  config: {
    engagementId: number;
    cookie?: string;
    timeoutSeconds?: number;
    level?: 1 | 2 | 3;
    targetOs?: "unix" | "windows";
  }
): Promise<CommixScanResult[]> {
  const results: CommixScanResult[] = [];

  // Limit to top 10 URLs to avoid excessive scanning
  const targetUrls = urls.slice(0, 10);

  for (const target of targetUrls) {
    try {
      const result = await runCommixScan({
        targetUrl: target.url,
        engagementId: config.engagementId,
        cookie: config.cookie,
        timeoutSeconds: config.timeoutSeconds || 90,
        level: config.level || 2,
        targetOs: config.targetOs,
        batch: true,
      });
      results.push(result);

      // If we found confirmed injection, log it prominently
      if (result.stats.injectionsFound > 0) {
        console.log(`[Commix] CONFIRMED: ${result.stats.injectionsFound} command injection(s) on ${target.url}`);
      }
    } catch (err: any) {
      console.warn(`[Commix] Error scanning ${target.url}: ${err.message}`);
      results.push({
        targetUrl: target.url,
        findings: [],
        stats: { durationSeconds: 0, parametersTestedCount: 0, injectionsFound: 0, wafDetected: false },
        rawOutput: `Error: ${err.message}`,
        exitCode: -1,
        timedOut: false,
      });
    }
  }

  return results;
}

export async function ingestCommixToWebAppFindings(
  results: CommixScanResult[],
  engagementId: number,
  hostname: string
): Promise<{ findingsIngested: number }> {
  const db = await getDb();
  if (!db) return { findingsIngested: 0 };

  let ingested = 0;
  for (const result of results) {
    for (const finding of result.findings) {
      if (finding.type !== "cmdi" && finding.type !== "blind_cmdi") continue;

      try {
        const mitre = mapToMitre("Command Injection", finding.title);
        await db.insert(webAppFindings).values({
          engagementId,
          hostname,
          findingType: "command_injection",
          severity: finding.severity,
          title: finding.title,
          description: `Command injection vulnerability found via Commix.\nParameter: ${finding.parameter || 'unknown'}\nTechnique: ${finding.technique || 'unknown'}\nURL: ${finding.url}`,
          url: finding.url,
          parameter: finding.parameter || null,
          evidence: finding.rawOutput?.slice(0, 4000) || null,
          payload: finding.payload || null,
          remediation: "Sanitize all user input before passing to OS commands. Use parameterized APIs (e.g., subprocess with list args) instead of shell execution. Implement allowlists for expected input values.",
          tool: "commix",
          confidence: finding.type === "cmdi" ? "confirmed" : "firm",
          mitreAttackId: mitre?.attackId || "T1059",
          mitreAttackName: mitre?.attackName || "Command and Scripting Interpreter",
          cweId: "CWE-78",
          cweName: "OS Command Injection",
          falsePositive: false,
        });
        ingested++;
      } catch (err: any) {
        console.warn(`[Commix] Failed to ingest finding: ${err.message}`);
      }
    }
  }

  return { findingsIngested: ingested };
}
