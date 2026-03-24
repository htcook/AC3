/**
 * XSStrike Scanner Module
 *
 * Advanced XSS detection and exploitation tool that performs:
 * - Reflected XSS detection with context-aware payload generation
 * - DOM-based XSS analysis via headless browser
 * - Stored XSS detection through form submission + verification
 * - WAF fingerprinting and bypass payload generation
 * - Fuzzing with custom payloads and encoding schemes
 * - Parameter discovery and blind XSS testing
 *
 * Execution: SSH → scan server → xsstrike/dalfox → text output → parse → scan_results
 *
 * XSStrike/Dalfox complement ZAP's XSS scanning with:
 * - Context-aware payload generation (HTML, JS, attribute, URL contexts)
 * - Advanced WAF bypass techniques (encoding chains, polyglot payloads)
 * - DOM analysis that ZAP's passive scanner misses
 * - Faster parameter-level fuzzing than ZAP's active scan
 *
 * The module tries XSStrike first, falls back to Dalfox if unavailable.
 */
import { executeTool, type ToolExecResult } from "../scan-server-executor";
import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { getDb } from "../../db";
import { scanResults } from "../../../drizzle/schema";

// ─── Types ──────────────────────────────────────────────────────────────────────

export interface XssConfig {
  /** Target URL with reflectable parameter (e.g., http://target.com/search?q=test) */
  targetUrl: string;
  /** Engagement ID for audit trail */
  engagementId: number;
  /** Specific parameter to test */
  parameter?: string;
  /** HTTP method: GET or POST */
  method?: "GET" | "POST";
  /** POST data */
  postData?: string;
  /** Cookie string for authenticated scanning */
  cookie?: string;
  /** Custom headers */
  headers?: Record<string, string>;
  /** Max scan duration in seconds (default 180) */
  timeoutSeconds?: number;
  /** Whether to use DOM analysis (headless browser) */
  domAnalysis?: boolean;
  /** Whether to fuzz all parameters */
  fuzzAll?: boolean;
  /** Whether to attempt WAF bypass */
  wafBypass?: boolean;
  /** Blind XSS callback URL (e.g., XSSHunter or Burp Collaborator) */
  blindCallback?: string;
  /** Crawl depth for discovering additional pages */
  crawlDepth?: number;
  /** Operator ID */
  operatorId?: number;
  /** URLs discovered by ZAP spider to test (batch mode) */
  urlsToTest?: Array<{ url: string; method: string; params: string[] }>;
  /** Preferred tool: xsstrike or dalfox */
  preferredTool?: "xsstrike" | "dalfox";
}

export interface XssFinding {
  id: string;
  type: "reflected_xss" | "dom_xss" | "stored_xss" | "blind_xss" | "waf_bypass" | "waf_detected";
  severity: "critical" | "high" | "medium" | "low" | "info";
  parameter: string;
  url: string;
  context: string; // HTML, JS, attribute, URL, etc.
  payload?: string;
  title: string;
  description: string;
  wafName?: string;
  cweId: number;
  references: string[];
}

export interface XssScanResult {
  scanId: number | null;
  status: "completed" | "error" | "timeout";
  target: string;
  tool: "xsstrike" | "dalfox" | "none";
  findings: XssFinding[];
  stats: {
    urlsTested: number;
    parametersTested: number;
    xssFound: number;
    domXssFound: number;
    wafDetected: boolean;
    durationSeconds: number;
  };
  rawOutput: string;
  error?: string;
}

// ─── XSStrike Output Parsing ────────────────────────────────────────────────

function parseXssStrikeOutput(stdout: string, targetUrl: string): {
  findings: XssFinding[];
  wafDetected: boolean;
  wafName?: string;
} {
  const findings: XssFinding[] = [];
  let wafDetected = false;
  let wafName: string | undefined;
  const lines = stdout.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();

    // WAF detection
    const wafMatch = trimmed.match(/WAF.*?detected.*?:\s*(.+)/i) ||
                     trimmed.match(/\[WAF\]\s*(.+)/i);
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
        references: [],
      });
    }

    // XSStrike vulnerability detection
    const vulnMatch = trimmed.match(/(?:Vulnerable|XSS found|Payload|VULN).*?(?:parameter|param)?\s*['"]?([^'":\s]+)['"]?/i);
    if (vulnMatch || /\[VULN\]|\[XSS\]|Vulnerable/i.test(trimmed)) {
      const param = vulnMatch?.[1] || "unknown";

      // Determine XSS type from context
      let xssType: XssFinding["type"] = "reflected_xss";
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

      // Extract payload
      const payloadMatch = trimmed.match(/payload[:\s]*['"]?(.+?)['"]?\s*$/i) ||
                           trimmed.match(/→\s*(.+)/);
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
          "https://cwe.mitre.org/data/definitions/79.html",
        ],
      });
    }
  }

  return { findings, wafDetected, wafName };
}

// ─── Dalfox Output Parsing ──────────────────────────────────────────────────

function parseDalfoxOutput(stdout: string, targetUrl: string): {
  findings: XssFinding[];
  wafDetected: boolean;
  wafName?: string;
} {
  const findings: XssFinding[] = [];
  let wafDetected = false;
  let wafName: string | undefined;
  const lines = stdout.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();

    // Dalfox WAF detection
    if (/\[WAF\]|\[W\]/i.test(trimmed)) {
      wafDetected = true;
      const wafMatch = trimmed.match(/\[WAF\]\s*(.+)/i) || trimmed.match(/\[W\]\s*(.+)/i);
      wafName = wafMatch?.[1]?.trim() || "Unknown WAF";
    }

    // Dalfox vulnerability findings (format: [POC][TYPE] URL PAYLOAD)
    const pocMatch = trimmed.match(/\[POC\]\[([^\]]+)\]\s*(\S+)\s*(.*)/i) ||
                     trimmed.match(/\[V\]\[([^\]]+)\]\s*(\S+)\s*(.*)/i);
    if (pocMatch) {
      const [, type, url, payload] = pocMatch;
      let xssType: XssFinding["type"] = "reflected_xss";
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

      // Extract parameter from URL
      let param = "unknown";
      try {
        const parsedUrl = new URL(url);
        const params = Array.from(parsedUrl.searchParams.keys());
        param = params[0] || "unknown";
      } catch { /* use default */ }

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
          "https://cwe.mitre.org/data/definitions/79.html",
        ],
      });
    }

    // Dalfox parameter discovery
    const paramMatch = trimmed.match(/\[I\]\[Param\]\s*(\S+)/i);
    if (paramMatch) {
      // Info-level: parameter discovered for testing
    }
  }

  return { findings, wafDetected, wafName };
}

// ─── Main Scan Function ─────────────────────────────────────────────────────

export async function startXssScan(config: XssConfig): Promise<XssScanResult> {
  const startTime = Date.now();
  const timeout = config.timeoutSeconds || 180;

  // Try XSStrike first, fall back to Dalfox
  const toolOrder = config.preferredTool === "dalfox"
    ? ["dalfox", "xsstrike"]
    : ["xsstrike", "dalfox"];

  let activeTool: "xsstrike" | "dalfox" | "none" = "none";
  let result: ToolExecResult | null = null;

  for (const tool of toolOrder) {
    try {
      // Check if tool is available
      const checkResult = await executeTool({
        tool: "bash",
        args: `-c "which ${tool} 2>/dev/null && echo FOUND || echo NOTFOUND"`,
        timeoutSeconds: 10,
      });

      if (checkResult.stdout.includes("FOUND")) {
        activeTool = tool as "xsstrike" | "dalfox";
        break;
      }
    } catch { /* try next tool */ }
  }

  if (activeTool === "none") {
    // Neither tool available — try Python-based XSStrike from pip
    try {
      const pipCheck = await executeTool({
        tool: "bash",
        args: `-c "python3 -c 'import xsstrike' 2>/dev/null && echo FOUND || pip3 install xsstrike 2>/dev/null && echo INSTALLED || echo NOTFOUND"`,
        timeoutSeconds: 30,
      });
      if (pipCheck.stdout.includes("FOUND") || pipCheck.stdout.includes("INSTALLED")) {
        activeTool = "xsstrike";
      }
    } catch { /* continue */ }
  }

  if (activeTool === "none") {
    console.log(`[XSS] Neither XSStrike nor Dalfox available on scan server — skipping XSS scan`);
    return {
      scanId: null,
      status: "error",
      target: config.targetUrl,
      tool: "none",
      findings: [],
      stats: { urlsTested: 0, parametersTested: 0, xssFound: 0, domXssFound: 0, wafDetected: false, durationSeconds: 0 },
      rawOutput: "",
      error: "Neither XSStrike nor Dalfox is installed on the scan server. Install with: pip3 install xsstrike OR go install github.com/hahwul/dalfox/v2@latest",
    };
  }

  // Build command based on active tool
  let command: string;

  if (activeTool === "dalfox") {
    const args: string[] = [
      "url", `"${config.targetUrl}"`,
      "--silence",
      "--no-color",
      "--timeout", String(Math.min(timeout, 30)),
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
    // XSStrike command
    const args: string[] = [
      "-u", `"${config.targetUrl}"`,
      "--skip",  // Skip confirmation prompts
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

  console.log(`[XSS] Starting ${activeTool} scan: ${command.substring(0, 200)}...`);

  try {
    result = await executeTool({
      tool: "bash",
      args: `-c "${command}"`,
      target: config.targetUrl,
      timeoutSeconds: timeout + 60,
      engagementId: config.engagementId,
    });
  } catch (err: any) {
    return {
      scanId: null,
      status: "error",
      target: config.targetUrl,
      tool: activeTool,
      findings: [],
      stats: { urlsTested: 1, parametersTested: 0, xssFound: 0, domXssFound: 0, wafDetected: false, durationSeconds: (Date.now() - startTime) / 1000 },
      rawOutput: "",
      error: err.message,
    };
  }

  // Parse output based on tool
  const parsed = activeTool === "dalfox"
    ? parseDalfoxOutput(result.stdout, config.targetUrl)
    : parseXssStrikeOutput(result.stdout, config.targetUrl);

  const durationSeconds = (Date.now() - startTime) / 1000;
  const xssFindings = parsed.findings.filter(f => f.type !== "waf_detected");
  const domXssFindings = xssFindings.filter(f => f.type === "dom_xss");

  // Persist findings to scan_results table
  const db = await getDb();
  let scanId: number | null = null;
  if (db && parsed.findings.length > 0) {
    try {
      const [inserted] = await db.insert(scanResults).values({
        engagementId: config.engagementId,
        scanType: activeTool,
        target: config.targetUrl,
        findings: JSON.stringify(parsed.findings),
        rawOutput: result.stdout.substring(0, 50000),
        status: result.timedOut ? "timeout" : "completed",
        startedAt: new Date(startTime),
        completedAt: new Date(),
      }).$returningId();
      scanId = inserted?.id ?? null;
    } catch (e: any) {
      console.error(`[XSS] Failed to persist scan results: ${e.message}`);
    }
  }

  console.log(`[XSS] ${activeTool} scan completed in ${durationSeconds.toFixed(1)}s — ${xssFindings.length} XSS findings (${domXssFindings.length} DOM), WAF=${parsed.wafDetected}`);

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
      durationSeconds,
    },
    rawOutput: result.stdout,
  };
}

// ─── Batch Scan: Test multiple URLs from ZAP spider results ─────────────────

export async function batchXssScan(
  urls: Array<{ url: string; method: string; params: string[] }>,
  config: Omit<XssConfig, "targetUrl" | "parameter">,
): Promise<XssScanResult[]> {
  const results: XssScanResult[] = [];
  const maxUrls = Math.min(urls.length, 15); // Cap at 15 URLs

  console.log(`[XSS Batch] Testing ${maxUrls} URLs (of ${urls.length} discovered) for XSS`);

  for (let i = 0; i < maxUrls; i++) {
    const { url, method, params } = urls[i];
    if (params.length === 0) continue;

    console.log(`[XSS Batch] [${i + 1}/${maxUrls}] Testing: ${url} (${method}, params: ${params.join(",")})`);

    const result = await startXssScan({
      ...config,
      targetUrl: url,
      method: method as "GET" | "POST",
      parameter: params[0], // Test primary parameter
      timeoutSeconds: Math.min(config.timeoutSeconds || 90, 90),
    });

    results.push(result);

    // If tool is not available, no point continuing
    if (result.tool === "none") {
      console.log(`[XSS Batch] No XSS tool available — aborting batch`);
      break;
    }
  }

  const totalXss = results.reduce((sum, r) => sum + r.stats.xssFound, 0);
  const totalDom = results.reduce((sum, r) => sum + r.stats.domXssFound, 0);
  console.log(`[XSS Batch] Completed: ${results.length} URLs tested, ${totalXss} XSS found (${totalDom} DOM)`);

  return results;
}

// ─── LLM-Powered Finding Analysis ───────────────────────────────────────────

export async function analyzeXssFindings(
  findings: XssFinding[],
  targetUrl: string,
): Promise<{
  riskSummary: string;
  exploitScenarios: Array<{ type: string; parameter: string; context: string; impact: string; exploitability: string }>;
  recommendations: string[];
}> {
  if (findings.length === 0) {
    return { riskSummary: "No XSS findings.", exploitScenarios: [], recommendations: [] };
  }

  const findingSummary = findings.slice(0, 20).map(f =>
    `[${f.severity.toUpperCase()}] ${f.type} — param '${f.parameter}' in ${f.context} context at ${f.url}${f.payload ? ` (payload: ${f.payload.substring(0, 80)})` : ""}`
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
Respond in JSON format.`,
      },
      {
        role: "user",
        content: `Analyze these XSS findings:\n\n${findingSummary}`,
      },
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
                  exploitability: { type: "string" },
                },
                required: ["type", "parameter", "context", "impact", "exploitability"],
                additionalProperties: false,
              },
            },
            recommendations: {
              type: "array",
              items: { type: "string" },
            },
          },
          required: ["riskSummary", "exploitScenarios", "recommendations"],
          additionalProperties: false,
        },
      },
    },
  }));

  try {
    const parsed = JSON.parse(response.choices[0]?.message?.content || "{}");
    return {
      riskSummary: parsed.riskSummary || "Analysis unavailable.",
      exploitScenarios: parsed.exploitScenarios || [],
      recommendations: parsed.recommendations || [],
    };
  } catch {
    return { riskSummary: "LLM analysis failed to parse.", exploitScenarios: [], recommendations: [] };
  }
}
