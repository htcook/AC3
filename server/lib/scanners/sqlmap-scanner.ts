/**
 * SQLMap Scanner Module
 *
 * Dedicated SQL injection detection and exploitation tool that performs:
 * - Automated detection of SQL injection vulnerabilities (boolean-blind, time-blind, error-based, UNION, stacked queries)
 * - Database fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, etc.)
 * - Data extraction (tables, columns, records)
 * - OS command execution via SQL injection (when exploitable)
 * - WAF/IPS detection and bypass techniques
 * - Tamper script support for evasion
 *
 * Execution: SSH → scan server → sqlmap → JSON/text output → parse → scan_results
 *
 * SQLMap complements ZAP's generic injection fuzzing with deep, dedicated SQLi exploitation.
 * It excels at confirming and exploiting SQL injection vulnerabilities that ZAP detects
 * at a surface level, and can find blind SQLi that ZAP misses entirely.
 */
import { executeTool, type ToolExecResult } from "../scan-server-executor";
import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { analyzeSqlmapFindingsDeterministic, useDeterministicAnalysis } from "../deterministic-scanner-analysis";
import { getDb } from "../../db";
import { scanResults, webAppScans, webAppFindings } from "../../../drizzle/schema";
import { mapToMitre, findMsfModules } from "../zap-scanner";

// ─── Types ──────────────────────────────────────────────────────────────────────

export interface SqlmapConfig {
  /** Target URL with injectable parameter (e.g., http://target.com/page?id=1) */
  targetUrl: string;
  /** Engagement ID for audit trail */
  engagementId: number;
  /** Specific parameter to test (if not set, tests all) */
  parameter?: string;
  /** HTTP method: GET or POST */
  method?: "GET" | "POST";
  /** POST data (for POST requests) */
  postData?: string;
  /** Cookie string for authenticated scanning */
  cookie?: string;
  /** Custom headers (key: value pairs) */
  headers?: Record<string, string>;
  /** Injection techniques to test: B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline */
  techniques?: string;
  /** Risk level (1-3): 1=safe, 2=moderate, 3=aggressive (OR-based, heavy time-based) */
  risk?: 1 | 2 | 3;
  /** Level (1-5): higher = more payloads, more HTTP headers tested */
  level?: 1 | 2 | 3 | 4 | 5;
  /** Tamper scripts for WAF bypass (comma-separated) */
  tamperScripts?: string;
  /** Database type hint (mysql, postgresql, mssql, oracle, sqlite) */
  dbms?: string;
  /** Max scan duration in seconds (default 300) */
  timeoutSeconds?: number;
  /** Whether to enumerate databases after finding injection */
  enumerateDbs?: boolean;
  /** Whether to enumerate tables */
  enumerateTables?: boolean;
  /** Whether to dump data (CAUTION: only in authorized engagements) */
  dumpData?: boolean;
  /** Specific database to target */
  database?: string;
  /** Specific table to target */
  table?: string;
  /** Operator ID */
  operatorId?: number;
  /** Proxy URL (e.g., for routing through ZAP) */
  proxy?: string;
  /** User agent string */
  userAgent?: string;
  /** Number of threads (default 1, max 10) */
  threads?: number;
  /** URLs discovered by ZAP spider to test (batch mode) */
  urlsToTest?: Array<{ url: string; method: string; params: string[] }>;
}

export interface SqlmapFinding {
  id: string;
  type: "sqli" | "dbms_fingerprint" | "waf_detected" | "data_extracted" | "os_access";
  severity: "critical" | "high" | "medium" | "low" | "info";
  technique: string;
  parameter: string;
  url: string;
  dbms?: string;
  payload?: string;
  title: string;
  description: string;
  databases?: string[];
  tables?: string[];
  wafName?: string;
  cweId: number;
  references: string[];
}

export interface SqlmapScanResult {
  scanId: number | null;
  status: "completed" | "error" | "timeout";
  target: string;
  findings: SqlmapFinding[];
  injectable: boolean;
  dbmsFingerprint?: string;
  wafDetected?: string;
  stats: {
    urlsTested: number;
    parametersTested: number;
    injectableParams: number;
    techniquesUsed: string[];
    durationSeconds: number;
  };
  rawOutput: string;
  error?: string;
}

// ─── SQLMap Output Parsing ──────────────────────────────────────────────────

function parseSqlmapOutput(stdout: string, targetUrl: string): {
  findings: SqlmapFinding[];
  injectable: boolean;
  dbms?: string;
  waf?: string;
  techniques: string[];
  paramsTested: number;
  injectableParams: number;
} {
  const findings: SqlmapFinding[] = [];
  const techniques: string[] = [];
  let injectable = false;
  let dbms: string | undefined;
  let waf: string | undefined;
  let paramsTested = 0;
  let injectableParams = 0;

  const lines = stdout.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();

    // WAF/IPS detection
    const wafMatch = trimmed.match(/\[WARNING\].*(?:WAF|IPS|IDS).*?['"]?([^'"]+)['"]?\s*(?:detected|identified)/i) ||
                     trimmed.match(/identified.*?WAF.*?['"]([^'"]+)['"]/i);
    if (wafMatch) {
      waf = wafMatch[1] || "Unknown WAF";
      findings.push({
        id: `sqlmap-waf-${Date.now()}`,
        type: "waf_detected",
        severity: "info",
        technique: "fingerprint",
        parameter: "",
        url: targetUrl,
        wafName: waf,
        title: `WAF/IPS Detected: ${waf}`,
        description: `SQLMap detected a Web Application Firewall or Intrusion Prevention System: ${waf}. This may limit injection testing effectiveness.`,
        cweId: 693,
        references: [],
      });
    }

    // DBMS fingerprint
    const dbmsMatch = trimmed.match(/back-end DBMS:\s*(.+)/i) ||
                      trimmed.match(/the back-end DBMS is\s*(.+)/i);
    if (dbmsMatch) {
      dbms = dbmsMatch[1].trim();
      findings.push({
        id: `sqlmap-dbms-${Date.now()}`,
        type: "dbms_fingerprint",
        severity: "info",
        technique: "fingerprint",
        parameter: "",
        url: targetUrl,
        dbms,
        title: `Database Fingerprint: ${dbms}`,
        description: `SQLMap identified the back-end database management system as ${dbms}.`,
        cweId: 200,
        references: [],
      });
    }

    // Injectable parameter detection
    const injectMatch = trimmed.match(/(?:GET|POST|COOKIE|HEADER)\s+parameter\s+'([^']+)'\s+is\s+(?:vulnerable|injectable)/i) ||
                        trimmed.match(/Parameter:\s+'?([^']+)'?\s+\(.*(?:injectable|vulnerable)/i);
    if (injectMatch) {
      injectable = true;
      injectableParams++;
      const param = injectMatch[1];

      findings.push({
        id: `sqlmap-sqli-${param}-${Date.now()}`,
        type: "sqli",
        severity: "critical",
        technique: "detected",
        parameter: param,
        url: targetUrl,
        title: `SQL Injection: parameter '${param}'`,
        description: `SQLMap confirmed SQL injection vulnerability in parameter '${param}'. The parameter is exploitable and can be used to extract data, bypass authentication, or potentially execute OS commands.`,
        cweId: 89,
        references: [
          "https://owasp.org/www-community/attacks/SQL_Injection",
          "https://cwe.mitre.org/data/definitions/89.html",
        ],
      });
    }

    // Specific injection technique detection
    const techMatch = trimmed.match(/Type:\s*(.+)/i);
    if (techMatch && trimmed.includes("Type:")) {
      const tech = techMatch[1].trim();
      if (!techniques.includes(tech)) techniques.push(tech);
    }

    // Parameter testing count
    if (trimmed.match(/testing\s+'[^']+'/i)) {
      paramsTested++;
    }

    // Database enumeration results
    const dbListMatch = trimmed.match(/available databases\s*\[(\d+)\]:/i);
    if (dbListMatch) {
      const dbCount = parseInt(dbListMatch[1], 10);
      findings.push({
        id: `sqlmap-dbs-${Date.now()}`,
        type: "data_extracted",
        severity: "high",
        technique: "enumeration",
        parameter: "",
        url: targetUrl,
        title: `Database Enumeration: ${dbCount} databases found`,
        description: `SQLMap successfully enumerated ${dbCount} databases on the target system.`,
        databases: [],
        cweId: 200,
        references: [],
      });
    }

    // Table enumeration
    const tableMatch = trimmed.match(/Database:\s*(\S+)\s*\[(\d+)\s+tables?\]/i);
    if (tableMatch) {
      findings.push({
        id: `sqlmap-tables-${tableMatch[1]}-${Date.now()}`,
        type: "data_extracted",
        severity: "high",
        technique: "enumeration",
        parameter: "",
        url: targetUrl,
        database: tableMatch[1],
        title: `Table Enumeration: ${tableMatch[2]} tables in '${tableMatch[1]}'`,
        description: `SQLMap enumerated ${tableMatch[2]} tables in database '${tableMatch[1]}'.`,
        cweId: 200,
        references: [],
      });
    }
  }

  // Parse technique details from payload lines
  for (const line of lines) {
    const payloadMatch = line.match(/Payload:\s*(.+)/i);
    if (payloadMatch) {
      const lastFinding = findings.filter(f => f.type === "sqli").pop();
      if (lastFinding && !lastFinding.payload) {
        lastFinding.payload = payloadMatch[1].trim().substring(0, 500);
      }
    }
  }

  return { findings, injectable, dbms, waf, techniques, paramsTested, injectableParams };
}

// ─── Main Scan Function ─────────────────────────────────────────────────────

export async function startSqlmapScan(config: SqlmapConfig): Promise<SqlmapScanResult> {
  const startTime = Date.now();
  const timeout = config.timeoutSeconds || 300;
  const outputDir = `/tmp/sqlmap-output-${Date.now()}`;

  // Build sqlmap command
  const args: string[] = [
    "--url", `"${config.targetUrl}"`,
    "--batch",           // Non-interactive mode
    "--output-dir", outputDir,
    "--flush-session",   // Fresh session for each scan
    "--disable-coloring",
  ];

  // HTTP method and data
  if (config.method === "POST" && config.postData) {
    args.push("--data", `"${config.postData}"`);
  }

  // Specific parameter
  if (config.parameter) {
    args.push("-p", config.parameter);
  }

  // Authentication
  if (config.cookie) {
    args.push("--cookie", `"${config.cookie}"`);
  }
  if (config.headers) {
    for (const [key, value] of Object.entries(config.headers)) {
      args.push("--header", `"${key}: ${value}"`);
    }
  }

  // Injection configuration
  if (config.techniques) {
    args.push("--technique", config.techniques);
  }
  if (config.risk) {
    args.push("--risk", String(config.risk));
  }
  if (config.level) {
    args.push("--level", String(config.level));
  }
  if (config.tamperScripts) {
    args.push("--tamper", `"${config.tamperScripts}"`);
  }
  if (config.dbms) {
    args.push("--dbms", config.dbms);
  }

  // Enumeration options
  if (config.enumerateDbs) {
    args.push("--dbs");
  }
  if (config.enumerateTables && config.database) {
    args.push("--tables", "-D", config.database);
  }
  if (config.dumpData && config.database && config.table) {
    args.push("--dump", "-D", config.database, "-T", config.table, "--dump-format", "CSV");
  }

  // Performance
  if (config.threads && config.threads > 1) {
    args.push("--threads", String(Math.min(config.threads, 10)));
  }

  // Proxy
  if (config.proxy) {
    args.push("--proxy", config.proxy);
  }

  // User agent
  if (config.userAgent) {
    args.push("--user-agent", `"${config.userAgent}"`);
  } else {
    args.push("--random-agent");
  }

  // Smart mode: skip non-injectable parameters quickly
  args.push("--smart");

  const fullArgs = args.join(" ");
  console.log(`[SQLMap] Starting scan: sqlmap ${fullArgs.substring(0, 300)}`);
  console.log(`[SQLMap] Config: target=${config.targetUrl}, cookie=${config.cookie ? 'yes(' + config.cookie.substring(0, 30) + '...)' : 'none'}, risk=${config.risk}, level=${config.level}, timeout=${timeout}s`);

  let result: ToolExecResult;
  try {
    result = await executeTool({
      tool: "bash",
      args: `-c "python3 /opt/sqlmap-latest/sqlmap.py ${fullArgs} 2>&1 || sqlmap ${fullArgs} 2>&1"`,
      target: config.targetUrl,
      timeoutSeconds: timeout + 60,
      engagementId: config.engagementId,
    });
    console.log(`[SQLMap] executeTool returned: exitCode=${result.exitCode}, timedOut=${result.timedOut}, stdout=${result.stdout?.substring(0, 200) || '(empty)'}`);
  } catch (err: any) {
    console.error(`[SQLMap] executeTool threw: ${err.message}\n${err.stack?.substring(0, 300)}`);
    return {
      scanId: null,
      status: "error",
      target: config.targetUrl,
      findings: [],
      injectable: false,
      stats: { urlsTested: 1, parametersTested: 0, injectableParams: 0, techniquesUsed: [], durationSeconds: (Date.now() - startTime) / 1000 },
      rawOutput: "",
      error: err.message,
    };
  }

  if (result.timedOut) {
    const parsed = parseSqlmapOutput(result.stdout, config.targetUrl);
    return {
      scanId: null,
      status: "timeout",
      target: config.targetUrl,
      findings: parsed.findings,
      injectable: parsed.injectable,
      dbmsFingerprint: parsed.dbms,
      wafDetected: parsed.waf,
      stats: {
        urlsTested: 1,
        parametersTested: parsed.paramsTested,
        injectableParams: parsed.injectableParams,
        techniquesUsed: parsed.techniques,
        durationSeconds: timeout,
      },
      rawOutput: result.stdout,
    };
  }

  const parsed = parseSqlmapOutput(result.stdout, config.targetUrl);
  const durationSeconds = (Date.now() - startTime) / 1000;

  // Persist findings to scan_results table (fixed column names to match schema)
  const db = await getDb();
  let scanId: number | null = null;
  if (db && parsed.findings.length > 0) {
    try {
      const [inserted] = await db.insert(scanResults).values({
        engagementId: config.engagementId,
        tool: "sqlmap",
        target: config.targetUrl.substring(0, 255),
        command: `sqlmap --url "${config.targetUrl}" --batch --risk ${config.risk || 2} --level ${config.level || 3}`,
        findings: JSON.stringify(parsed.findings),
        findingCount: parsed.findings.length,
        rawOutput: result.stdout.substring(0, 50000),
        exitCode: result.exitCode ?? 0,
        durationMs: Math.round(durationSeconds * 1000),
        timedOut: 0,
        severitySummary: JSON.stringify({
          critical: parsed.findings.filter(f => f.severity === 'critical').length,
          high: parsed.findings.filter(f => f.severity === 'high').length,
          medium: parsed.findings.filter(f => f.severity === 'medium').length,
          low: parsed.findings.filter(f => f.severity === 'low').length,
          info: parsed.findings.filter(f => f.severity === 'info').length,
        }),
        phase: 'vuln_detection',
      }).$returningId();
      scanId = inserted?.id ?? null;
    } catch (e: any) {
      console.error(`[SQLMap] Failed to persist scan results: ${e.message}`);
    }
  }

  console.log(`[SQLMap] Scan completed in ${durationSeconds.toFixed(1)}s — ${parsed.findings.length} findings, injectable=${parsed.injectable}, dbms=${parsed.dbms || "unknown"}`);

  return {
    scanId,
    status: "completed",
    target: config.targetUrl,
    findings: parsed.findings,
    injectable: parsed.injectable,
    dbmsFingerprint: parsed.dbms,
    wafDetected: parsed.waf,
    stats: {
      urlsTested: 1,
      parametersTested: parsed.paramsTested,
      injectableParams: parsed.injectableParams,
      techniquesUsed: parsed.techniques,
      durationSeconds,
    },
    rawOutput: result.stdout,
  };
}

// ─── Batch Scan: Test multiple URLs from ZAP spider results ─────────────────

export async function batchSqlmapScan(
  urls: Array<{ url: string; method: string; params: string[] }>,
  config: Omit<SqlmapConfig, "targetUrl" | "parameter">,
): Promise<SqlmapScanResult[]> {
  const results: SqlmapScanResult[] = [];
  const maxUrls = Math.min(urls.length, 20); // Cap at 20 URLs to avoid excessive scanning

  console.log(`[SQLMap Batch] Testing ${maxUrls} URLs (of ${urls.length} discovered) for SQL injection`);

  for (let i = 0; i < maxUrls; i++) {
    const { url, method, params } = urls[i];
    if (params.length === 0) continue; // Skip URLs without parameters

    console.log(`[SQLMap Batch] [${i + 1}/${maxUrls}] Testing: ${url} (${method}, params: ${params.join(",")})`);

    const result = await startSqlmapScan({
      ...config,
      targetUrl: url,
      method: method as "GET" | "POST",
      // Test first 3 params per URL to keep scan time reasonable
      parameter: params.slice(0, 3).join(","),
      timeoutSeconds: Math.min(config.timeoutSeconds || 120, 120), // Max 2 min per URL
    });

    results.push(result);

    // Early exit if we've found injectable params — focus exploitation there
    if (result.injectable && result.findings.filter(f => f.type === "sqli").length >= 3) {
      console.log(`[SQLMap Batch] Found ${result.findings.filter(f => f.type === "sqli").length} SQLi vulns — stopping batch to focus exploitation`);
      break;
    }
  }

  const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
  const totalInjectable = results.filter(r => r.injectable).length;
  console.log(`[SQLMap Batch] Completed: ${results.length} URLs tested, ${totalInjectable} injectable, ${totalFindings} total findings`);

  return results;
}

// ─── LLM-Powered Finding Analysis ───────────────────────────────────────────

export async function analyzeSqlmapFindings(
  findings: SqlmapFinding[],
  targetUrl: string,
): Promise<{
  riskSummary: string;
  exploitChains: Array<{ technique: string; parameter: string; impact: string; exploitability: string; nextSteps: string }>;
  recommendations: string[];
}> {
  if (findings.length === 0) {
    return { riskSummary: "No SQL injection findings.", exploitChains: [], recommendations: [] };
  }

  // Tier 1 Offload: Use deterministic analysis if available
  if (typeof analyzeSqlmapFindingsDeterministic === "function" && useDeterministicAnalysis("sqlmap")) {
    console.log(`[SQLMap] Using deterministic analysis for ${findings.length} findings (Tier 1 offload)`);
    return analyzeSqlmapFindingsDeterministic(findings, targetUrl);
  }

  // Fallback: LLM-powered analysis
  const findingSummary = findings.slice(0, 20).map(f =>
    `[${f.severity.toUpperCase()}] ${f.type} — ${f.parameter || "N/A"} at ${f.url} — ${f.title}${f.payload ? ` (payload: ${f.payload.substring(0, 80)})` : ""}`
  ).join("\n");

  const response = await throttledLLMCall("sqlmap-analyst", () => invokeLLM({
    _caller: "sqlmap-scanner.analyzeSqlmapFindings",
    messages: [
      {
        role: "system",
        content: `You are a SQL injection exploitation specialist reviewing SQLMap findings. SQLMap is the gold standard for SQL injection detection and exploitation. Analyze the findings and provide:
1. Risk summary with business impact assessment
2. Exploit chains showing how each injection can be leveraged (data exfiltration, auth bypass, RCE)
3. Specific remediation recommendations (parameterized queries, WAF rules, input validation)

Target: ${targetUrl}
Respond in JSON format.`,
      },
      {
        role: "user",
        content: `Analyze these SQLMap findings:\n\n${findingSummary}`,
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "sqlmap_analysis",
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
                  technique: { type: "string" },
                  parameter: { type: "string" },
                  impact: { type: "string" },
                  exploitability: { type: "string" },
                  nextSteps: { type: "string" },
                },
                required: ["technique", "parameter", "impact", "exploitability", "nextSteps"],
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


// ─── Ingest SQLMap Findings into web_app_findings (same table as ZAP) ──────

/**
 * Creates a web_app_scans record for SQLMap and ingests findings into web_app_findings
 * with MITRE ATT&CK mapping, Metasploit module correlation, and proper severity.
 * This allows SQLMap findings to appear alongside ZAP findings in the unified findings view.
 */
export async function ingestSqlmapToWebAppFindings(
  results: SqlmapScanResult[],
  engagementId: number,
  targetHostname: string,
): Promise<{ webAppScanId: number | null; findingsIngested: number }> {
  const db = await getDb();
  if (!db) return { webAppScanId: null, findingsIngested: 0 };

  const allFindings = results.flatMap(r => r.findings);
  if (allFindings.length === 0) return { webAppScanId: null, findingsIngested: 0 };

  try {
    // Create a web_app_scans record to link SQLMap findings
    const targetUrl = results[0]?.target || `https://${targetHostname}`;
    const totalDuration = results.reduce((sum, r) => sum + r.stats.durationSeconds, 0);
    const sqliCount = allFindings.filter(f => f.type === "sqli").length;

    const [scanRecord] = await db.insert(webAppScans).values({
      targetUrl: targetUrl.substring(0, 2048),
      scanName: `SQLMap-EngOps-${engagementId}-${targetHostname}`,
      scanType: "sqlmap_blind",
      status: "completed",
      startedAt: new Date(Date.now() - totalDuration * 1000),
      completedAt: new Date(),
      totalAlerts: allFindings.length,
      alertCounts: JSON.stringify({
        high: allFindings.filter(f => f.severity === "critical" || f.severity === "high").length,
        medium: allFindings.filter(f => f.severity === "medium").length,
        low: allFindings.filter(f => f.severity === "low").length,
        info: allFindings.filter(f => f.severity === "info").length,
      }),
      scanMode: "active",
    }).$returningId();

    const webAppScanId = scanRecord?.id;
    if (!webAppScanId) return { webAppScanId: null, findingsIngested: 0 };

    // Ingest each finding into web_app_findings with MITRE ATT&CK mapping
    let ingested = 0;
    for (const finding of allFindings) {
      const mitre = mapToMitre(finding.cweId, finding.title);
      const msfModules = findMsfModules(finding.cweId);

      // Map SQLMap severity to ZAP-compatible severity
      const severityMap: Record<string, string> = {
        critical: "high",  // web_app_findings uses high as max
        high: "high",
        medium: "medium",
        low: "low",
        info: "info",
      };

      // Map SQLMap finding type to confidence
      const confidenceMap: Record<string, number> = {
        sqli: 0.95,           // SQLMap-confirmed injection = very high confidence
        dbms_fingerprint: 0.9,
        data_extracted: 0.95,
        os_access: 0.99,
        waf_detected: 0.8,
      };

      // Build solution based on finding type
      const solutionMap: Record<string, string> = {
        sqli: "Use parameterized queries (prepared statements) for all database interactions. Implement input validation with allowlists. Apply the principle of least privilege to database accounts. Consider using an ORM that automatically parameterizes queries.",
        dbms_fingerprint: "Suppress detailed error messages in production. Configure custom error pages. Remove version information from HTTP headers.",
        data_extracted: "Immediately rotate all exposed credentials. Review and restrict database permissions. Implement data loss prevention controls.",
        os_access: "CRITICAL: OS-level access achieved via SQL injection. Immediately isolate the affected system. Patch the injection vulnerability. Review all database user privileges and remove FILE/EXECUTE permissions.",
        waf_detected: "WAF detected but bypassed. Review WAF rules and update signatures. Consider implementing application-level input validation in addition to WAF.",
      };

      try {
        await db.insert(webAppFindings).values({
          scanId: webAppScanId,
          alertName: `[SQLMap] ${finding.title}`.substring(0, 512),
          severity: severityMap[finding.severity] || "medium",
          confidence: confidenceMap[finding.type] || 0.7,
          description: finding.description.substring(0, 4000),
          solution: (solutionMap[finding.type] || "Review and remediate the identified vulnerability.").substring(0, 4000),
          referenceLinks: finding.references.join("\n").substring(0, 2000) || null,
          cweId: finding.cweId,
          wascId: finding.type === "sqli" ? 19 : null,  // WASC-19 = SQL Injection
          url: finding.url?.substring(0, 2048) || null,
          method: null,  // SQLMap doesn't always report method
          param: finding.parameter?.substring(0, 512) || null,
          attack: finding.payload?.substring(0, 2000) || null,
          evidence: finding.dbms
            ? `DBMS: ${finding.dbms}. Technique: ${finding.technique}`.substring(0, 2000)
            : `Technique: ${finding.technique}`.substring(0, 2000),
          zapPluginId: `sqlmap-${finding.type}`,  // Pseudo plugin ID for SQLMap
          zapAlertRef: finding.id,
          // MITRE ATT&CK mapping
          mitreAttackId: mitre?.techniqueId || null,
          mitreAttackName: mitre?.techniqueName || null,
          mitreTactic: mitre?.tactic || null,
          // Exploit correlation
          exploitAvailable: msfModules.length > 0 ? 1 : 0,
          exploitModulePath: msfModules.length > 0 ? msfModules[0] : null,
        });
        ingested++;
      } catch (insertErr: any) {
        console.error(`[SQLMap] Failed to ingest finding to web_app_findings: ${insertErr.message}`);
      }
    }

    console.log(`[SQLMap] Ingested ${ingested}/${allFindings.length} findings into web_app_findings (scan #${webAppScanId})`);
    return { webAppScanId, findingsIngested: ingested };
  } catch (err: any) {
    console.error(`[SQLMap] Failed to create web_app_scans record: ${err.message}`);
    return { webAppScanId: null, findingsIngested: 0 };
  }
}

// ─── ZAP → SQLMap Handoff: Extract confirmed injection points ──────────────

/**
 * Extracts confirmed SQL injection URLs from ZAP's web_app_findings for a given scan.
 * These are passed to SQLMap for deeper blind SQLi exploitation.
 */
export async function extractZapSqliForHandoff(
  zapScanId: number,
): Promise<Array<{ url: string; method: string; params: string[] }>> {
  const db = await getDb();
  if (!db) return [];

  try {
    const { eq, like, or } = await import("drizzle-orm");
    const sqliFindings = await db.select({
      url: webAppFindings.url,
      method: webAppFindings.method,
      param: webAppFindings.param,
      alertName: webAppFindings.alertName,
    }).from(webAppFindings)
      .where(
        // Match SQL injection findings from ZAP
        eq(webAppFindings.scanId, zapScanId),
      );

    // Filter to only SQLi-related findings
    const sqliRelated = sqliFindings.filter(f =>
      f.alertName?.toLowerCase().includes('sql injection') ||
      f.alertName?.toLowerCase().includes('sqli') ||
      f.alertName?.toLowerCase().includes('sql query')
    );

    // Deduplicate by URL and collect params
    const urlMap = new Map<string, { method: string; params: Set<string> }>();
    for (const finding of sqliRelated) {
      if (!finding.url) continue;
      const key = finding.url;
      if (!urlMap.has(key)) {
        urlMap.set(key, { method: finding.method || "GET", params: new Set() });
      }
      if (finding.param) {
        urlMap.get(key)!.params.add(finding.param);
      }
    }

    const handoffUrls = Array.from(urlMap.entries()).map(([url, data]) => ({
      url,
      method: data.method,
      params: Array.from(data.params),
    }));

    console.log(`[SQLMap Handoff] Extracted ${handoffUrls.length} SQLi URLs from ZAP scan #${zapScanId} for blind exploitation`);
    return handoffUrls;
  } catch (err: any) {
    console.error(`[SQLMap Handoff] Failed to extract ZAP SQLi findings: ${err.message}`);
    return [];
  }
}

// ─── Blind SQLi Focused Scan ───────────────────────────────────────────────

/**
 * Runs a focused blind SQLi scan using SQLMap with time-based and boolean-blind techniques.
 * This complements ZAP's fast playbook which skips time-based rules for speed.
 *
 * Strategy:
 * 1. If ZAP found error-based SQLi, SQLMap confirms and tests blind variants on those same URLs
 * 2. If no ZAP SQLi findings, SQLMap tests known injectable endpoints with blind techniques
 * 3. Uses BT techniques (Boolean-blind + Time-blind) as primary, with E (Error) as fallback
 */
export async function runBlindSqliPass(config: {
  engagementId: number;
  targetHostname: string;
  targetUrl: string;
  zapScanId?: number;
  knownInjectableUrls: Array<{ url: string; method: string; params: string[] }>;
  cookie?: string;
  isTrainingLab: boolean;
}): Promise<{
  results: SqlmapScanResult[];
  webAppScanId: number | null;
  findingsIngested: number;
  blindSqliFound: number;
}> {
  const { engagementId, targetHostname, targetUrl, zapScanId, knownInjectableUrls, cookie, isTrainingLab } = config;

  console.log(`[SQLMap Blind] Starting blind SQLi pass for ${targetHostname} (engagement #${engagementId})`);

  // Step 1: Get ZAP-confirmed SQLi URLs for deeper exploitation
  let handoffUrls: Array<{ url: string; method: string; params: string[] }> = [];
  if (zapScanId) {
    handoffUrls = await extractZapSqliForHandoff(zapScanId);
    if (handoffUrls.length > 0) {
      console.log(`[SQLMap Blind] ZAP handoff: ${handoffUrls.length} confirmed SQLi URLs to test with blind techniques`);
    }
  }

  // Step 2: Merge ZAP handoff URLs with known injectable endpoints (dedup)
  const allUrls = [...handoffUrls];
  const seenUrls = new Set(handoffUrls.map(u => u.url));
  for (const url of knownInjectableUrls) {
    if (!seenUrls.has(url.url)) {
      allUrls.push(url);
      seenUrls.add(url.url);
    }
  }

  if (allUrls.length === 0) {
    console.log(`[SQLMap Blind] No URLs to test — skipping blind SQLi pass`);
    return { results: [], webAppScanId: null, findingsIngested: 0, blindSqliFound: 0 };
  }

  // Step 3: Run SQLMap with blind-focused techniques
  // For training labs: use all techniques but prioritize blind (BT first, then EUSQ)
  // For production: use only BT (Boolean + Time) to minimize noise
  const techniques = isTrainingLab ? "BTEUS" : "BT";
  const risk = isTrainingLab ? 3 : 2;
  const level = isTrainingLab ? 5 : 3;
  const timeoutPerUrl = isTrainingLab ? 180 : 90;

  console.log(`[SQLMap Blind] Testing ${allUrls.length} URLs with techniques=${techniques}, risk=${risk}, level=${level}`);

  const results = await batchSqlmapScan(allUrls, {
    engagementId,
    risk: risk as 1 | 2 | 3,
    level: level as 1 | 2 | 3 | 4 | 5,
    techniques,
    cookie: cookie || undefined,
    timeoutSeconds: timeoutPerUrl,
    enumerateDbs: true,
    enumerateTables: isTrainingLab,
    threads: 3,  // Moderate threading for blind techniques (time-based needs sequential)
  });

  const allFindings = results.flatMap(r => r.findings);
  const blindSqliFound = allFindings.filter(f => f.type === "sqli").length;

  console.log(`[SQLMap Blind] Completed: ${allUrls.length} URLs tested, ${blindSqliFound} blind SQLi found, ${allFindings.length} total findings`);

  // Step 4: Ingest findings into web_app_findings for unified view
  const { webAppScanId, findingsIngested } = await ingestSqlmapToWebAppFindings(
    results,
    engagementId,
    targetHostname,
  );

  return { results, webAppScanId, findingsIngested, blindSqliFound };
}
