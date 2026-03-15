/**
 * Active Verification Probes
 * 
 * Lightweight, non-destructive probes that verify vulnerability presence
 * without full exploitation. Inspired by Nuclei's template-based approach.
 * 
 * Probes check for: version banners, error signatures, default credentials,
 * misconfiguration indicators, and known-vulnerable response patterns.
 * 
 * These run BEFORE full exploit validation to triage findings quickly.
 * 
 * @module active-probes
 */

// ─── Types ─────────────────────────────────────────────────────────

export type ProbeType =
  | "banner_grab"        // Check service version banner
  | "http_header"        // Check HTTP response headers
  | "http_body"          // Check HTTP response body patterns
  | "http_status"        // Check HTTP status code
  | "tls_check"          // Check TLS certificate and configuration
  | "dns_check"          // Check DNS configuration
  | "default_creds"      // Check for default credentials (non-destructive)
  | "path_disclosure"    // Check for sensitive path exposure
  | "error_signature"    // Check for error messages revealing vulnerability
  | "config_check";      // Check for misconfiguration indicators

export type ProbeResult = "vulnerable" | "not_vulnerable" | "inconclusive" | "error" | "timeout";

export interface ProbeTemplate {
  id: string;
  name: string;
  description: string;
  type: ProbeType;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cveIds: string[];
  targetService: string;
  targetPort: number | null;
  
  // HTTP probe config
  httpMethod?: "GET" | "POST" | "HEAD" | "OPTIONS" | "PUT" | "DELETE";
  httpPath?: string;
  httpHeaders?: Record<string, string>;
  httpBody?: string;
  
  // Match conditions (any match = vulnerable)
  matchConditions: MatchCondition[];
  
  // Negative match (if present, NOT vulnerable)
  safeConditions?: MatchCondition[];
  
  tags: string[];
  references: string[];
}

export interface MatchCondition {
  type: "status_code" | "header" | "body" | "banner" | "regex" | "word";
  value: string;
  negate?: boolean; // If true, match means NOT vulnerable
}

export interface ProbeExecution {
  templateId: string;
  templateName: string;
  target: string;
  port: number | null;
  result: ProbeResult;
  matchedConditions: string[];
  responseSnippet: string | null;
  confidence: number; // 0.0 - 1.0
  durationMs: number;
  timestamp: number;
  error?: string;
}

export interface ProbeScanResult {
  target: string;
  totalProbes: number;
  vulnerable: number;
  notVulnerable: number;
  inconclusive: number;
  errors: number;
  executions: ProbeExecution[];
  durationMs: number;
  summary: string;
}

// ─── Built-in Probe Templates ──────────────────────────────────────

export const PROBE_TEMPLATES: ProbeTemplate[] = [
  // ── Critical: Known RCE indicators ──
  {
    id: "probe-log4j-jndi",
    name: "Log4j JNDI Lookup (CVE-2021-44228)",
    description: "Checks for Log4Shell vulnerability by looking for JNDI-related error patterns",
    type: "error_signature",
    severity: "critical",
    cveIds: ["CVE-2021-44228", "CVE-2021-45046"],
    targetService: "http",
    targetPort: null,
    httpMethod: "GET",
    httpPath: "/",
    httpHeaders: { "X-Api-Version": "${jndi:ldap://test}" },
    matchConditions: [
      { type: "body", value: "javax.naming" },
      { type: "body", value: "InitialContext" },
      { type: "header", value: "X-Log4j" },
    ],
    tags: ["rce", "log4j", "java"],
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
  },
  {
    id: "probe-spring4shell",
    name: "Spring4Shell (CVE-2022-22965)",
    description: "Checks for Spring Framework RCE via class loader manipulation",
    type: "error_signature",
    severity: "critical",
    cveIds: ["CVE-2022-22965"],
    targetService: "http",
    targetPort: null,
    httpMethod: "GET",
    httpPath: "/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=test",
    matchConditions: [
      { type: "status_code", value: "200" },
      { type: "body", value: "class.module" },
    ],
    safeConditions: [
      { type: "status_code", value: "400" },
      { type: "status_code", value: "403" },
    ],
    tags: ["rce", "spring", "java"],
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
  },
  
  // ── High: Authentication bypass indicators ──
  {
    id: "probe-default-admin",
    name: "Default Admin Panel Exposure",
    description: "Checks for exposed admin panels with default paths",
    type: "path_disclosure",
    severity: "high",
    cveIds: [],
    targetService: "http",
    targetPort: null,
    httpMethod: "GET",
    httpPath: "/admin",
    matchConditions: [
      { type: "status_code", value: "200" },
      { type: "body", value: "login" },
      { type: "body", value: "password" },
    ],
    tags: ["admin", "exposure", "authentication"],
    references: [],
  },
  {
    id: "probe-git-exposure",
    name: ".git Directory Exposure",
    description: "Checks for exposed .git directory leaking source code",
    type: "path_disclosure",
    severity: "high",
    cveIds: [],
    targetService: "http",
    targetPort: null,
    httpMethod: "GET",
    httpPath: "/.git/config",
    matchConditions: [
      { type: "status_code", value: "200" },
      { type: "body", value: "[core]" },
      { type: "body", value: "repositoryformatversion" },
    ],
    tags: ["exposure", "source-code", "git"],
    references: [],
  },
  {
    id: "probe-env-file",
    name: ".env File Exposure",
    description: "Checks for exposed environment file with credentials",
    type: "path_disclosure",
    severity: "high",
    cveIds: [],
    targetService: "http",
    targetPort: null,
    httpMethod: "GET",
    httpPath: "/.env",
    matchConditions: [
      { type: "status_code", value: "200" },
      { type: "regex", value: "(DB_PASSWORD|API_KEY|SECRET|TOKEN)=" },
    ],
    tags: ["exposure", "credentials", "env"],
    references: [],
  },
  
  // ── Medium: Information disclosure ──
  {
    id: "probe-server-status",
    name: "Apache Server-Status Exposure",
    description: "Checks for exposed Apache server-status page",
    type: "path_disclosure",
    severity: "medium",
    cveIds: [],
    targetService: "http",
    targetPort: null,
    httpMethod: "GET",
    httpPath: "/server-status",
    matchConditions: [
      { type: "status_code", value: "200" },
      { type: "body", value: "Apache Server Status" },
    ],
    tags: ["info-disclosure", "apache"],
    references: [],
  },
  {
    id: "probe-phpinfo",
    name: "PHPInfo Exposure",
    description: "Checks for exposed phpinfo() page",
    type: "path_disclosure",
    severity: "medium",
    cveIds: [],
    targetService: "http",
    targetPort: null,
    httpMethod: "GET",
    httpPath: "/phpinfo.php",
    matchConditions: [
      { type: "status_code", value: "200" },
      { type: "body", value: "PHP Version" },
      { type: "body", value: "phpinfo()" },
    ],
    tags: ["info-disclosure", "php"],
    references: [],
  },
  
  // ── TLS / Certificate checks ──
  {
    id: "probe-weak-tls",
    name: "Weak TLS Configuration",
    description: "Checks for TLS versions below 1.2",
    type: "tls_check",
    severity: "medium",
    cveIds: [],
    targetService: "https",
    targetPort: 443,
    matchConditions: [
      { type: "banner", value: "TLSv1.0" },
      { type: "banner", value: "TLSv1.1" },
      { type: "banner", value: "SSLv3" },
    ],
    tags: ["tls", "crypto", "weak-config"],
    references: [],
  },
  
  // ── Security header checks ──
  {
    id: "probe-missing-security-headers",
    name: "Missing Security Headers",
    description: "Checks for absence of critical security headers",
    type: "http_header",
    severity: "low",
    cveIds: [],
    targetService: "http",
    targetPort: null,
    httpMethod: "HEAD",
    httpPath: "/",
    matchConditions: [
      // These are "absence" checks — vulnerable if header is missing
      { type: "header", value: "x-frame-options", negate: true },
      { type: "header", value: "content-security-policy", negate: true },
      { type: "header", value: "strict-transport-security", negate: true },
    ],
    tags: ["headers", "best-practice"],
    references: [],
  },
  
  // ── Directory listing ──
  {
    id: "probe-directory-listing",
    name: "Directory Listing Enabled",
    description: "Checks for enabled directory listing",
    type: "config_check",
    severity: "low",
    cveIds: [],
    targetService: "http",
    targetPort: null,
    httpMethod: "GET",
    httpPath: "/",
    matchConditions: [
      { type: "body", value: "Index of /" },
      { type: "body", value: "Directory listing for" },
      { type: "body", value: "Parent Directory" },
    ],
    tags: ["directory-listing", "misconfiguration"],
    references: [],
  },
];

// ─── Probe Execution Engine ────────────────────────────────────────

/**
 * Execute a single probe template against a target.
 * Uses fetch for HTTP probes with strict timeouts.
 */
export async function executeProbe(
  template: ProbeTemplate,
  target: string,
  port?: number,
  timeoutMs: number = 10000
): Promise<ProbeExecution> {
  const start = Date.now();
  const effectivePort = port || template.targetPort;
  
  try {
    if (template.type === "tls_check" || template.type === "dns_check") {
      // TLS and DNS probes require specialized handling
      return {
        templateId: template.id,
        templateName: template.name,
        target,
        port: effectivePort,
        result: "inconclusive",
        matchedConditions: [],
        responseSnippet: null,
        confidence: 0.3,
        durationMs: Date.now() - start,
        timestamp: Date.now(),
        error: `${template.type} probes require specialized network access`,
      };
    }
    
    // HTTP-based probes
    const protocol = effectivePort === 443 ? "https" : "http";
    const portSuffix = effectivePort && effectivePort !== 80 && effectivePort !== 443
      ? `:${effectivePort}` : "";
    const url = `${protocol}://${target}${portSuffix}${template.httpPath || "/"}`;
    
    const response = await fetch(url, {
      method: template.httpMethod || "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; AC3-Probe/1.0)",
        ...template.httpHeaders,
      },
      body: template.httpBody || undefined,
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "follow",
    });
    
    const statusCode = response.status.toString();
    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key.toLowerCase()] = value;
    });
    
    const body = await response.text().catch(() => "");
    const bodySnippet = body.slice(0, 1000);
    
    // Check safe conditions first (if match, NOT vulnerable)
    if (template.safeConditions) {
      for (const condition of template.safeConditions) {
        if (evaluateCondition(condition, statusCode, responseHeaders, body)) {
          return {
            templateId: template.id,
            templateName: template.name,
            target,
            port: effectivePort,
            result: "not_vulnerable",
            matchedConditions: [`Safe condition matched: ${condition.type}=${condition.value}`],
            responseSnippet: bodySnippet,
            confidence: 0.7,
            durationMs: Date.now() - start,
            timestamp: Date.now(),
          };
        }
      }
    }
    
    // Check vulnerability conditions
    const matchedConditions: string[] = [];
    for (const condition of template.matchConditions) {
      if (evaluateCondition(condition, statusCode, responseHeaders, body)) {
        matchedConditions.push(`${condition.type}=${condition.value}${condition.negate ? " (absent)" : ""}`);
      }
    }
    
    // Determine result
    const matchRatio = matchedConditions.length / template.matchConditions.length;
    let result: ProbeResult;
    let confidence: number;
    
    if (matchRatio >= 0.5) {
      result = "vulnerable";
      confidence = Math.min(0.95, 0.5 + (matchRatio * 0.45));
    } else if (matchRatio > 0) {
      result = "inconclusive";
      confidence = 0.3 + (matchRatio * 0.2);
    } else {
      result = "not_vulnerable";
      confidence = 0.7;
    }
    
    return {
      templateId: template.id,
      templateName: template.name,
      target,
      port: effectivePort,
      result,
      matchedConditions,
      responseSnippet: result === "vulnerable" ? bodySnippet : null,
      confidence,
      durationMs: Date.now() - start,
      timestamp: Date.now(),
    };
    
  } catch (err: any) {
    const isTimeout = err.name === "TimeoutError" || err.message?.includes("timeout");
    
    return {
      templateId: template.id,
      templateName: template.name,
      target,
      port: effectivePort,
      result: isTimeout ? "timeout" : "error",
      matchedConditions: [],
      responseSnippet: null,
      confidence: 0,
      durationMs: Date.now() - start,
      timestamp: Date.now(),
      error: err.message,
    };
  }
}

/**
 * Run all applicable probes against a target.
 */
export async function runProbeScan(
  target: string,
  options?: {
    port?: number;
    templates?: ProbeTemplate[];
    severityFilter?: string[];
    tagFilter?: string[];
    maxConcurrent?: number;
    timeoutMs?: number;
  }
): Promise<ProbeScanResult> {
  const start = Date.now();
  let templates = options?.templates || PROBE_TEMPLATES;
  
  // Apply filters
  if (options?.severityFilter?.length) {
    templates = templates.filter(t => options.severityFilter!.includes(t.severity));
  }
  if (options?.tagFilter?.length) {
    templates = templates.filter(t => t.tags.some(tag => options.tagFilter!.includes(tag)));
  }
  
  // Execute probes (sequential to avoid overwhelming target)
  const executions: ProbeExecution[] = [];
  for (const template of templates) {
    const execution = await executeProbe(template, target, options?.port, options?.timeoutMs);
    executions.push(execution);
  }
  
  // Summarize
  const vulnerable = executions.filter(e => e.result === "vulnerable").length;
  const notVulnerable = executions.filter(e => e.result === "not_vulnerable").length;
  const inconclusive = executions.filter(e => e.result === "inconclusive").length;
  const errors = executions.filter(e => e.result === "error" || e.result === "timeout").length;
  
  const vulnNames = executions
    .filter(e => e.result === "vulnerable")
    .map(e => e.templateName);
  
  const summary = vulnerable > 0
    ? `${vulnerable} potential vulnerabilit${vulnerable > 1 ? "ies" : "y"} detected: ${vulnNames.join(", ")}`
    : `No vulnerabilities detected across ${templates.length} probes.`;
  
  return {
    target,
    totalProbes: templates.length,
    vulnerable,
    notVulnerable,
    inconclusive,
    errors,
    executions,
    durationMs: Date.now() - start,
    summary,
  };
}

/**
 * Get probe templates matching specific CVE IDs.
 */
export function getProbesForCves(cveIds: string[]): ProbeTemplate[] {
  const cveSet = new Set(cveIds.map(c => c.toUpperCase()));
  return PROBE_TEMPLATES.filter(t => t.cveIds.some(c => cveSet.has(c.toUpperCase())));
}

/**
 * Get probe templates by tag.
 */
export function getProbesByTag(tag: string): ProbeTemplate[] {
  return PROBE_TEMPLATES.filter(t => t.tags.includes(tag.toLowerCase()));
}

// ─── Helpers ───────────────────────────────────────────────────────

function evaluateCondition(
  condition: MatchCondition,
  statusCode: string,
  headers: Record<string, string>,
  body: string
): boolean {
  let matched = false;
  
  switch (condition.type) {
    case "status_code":
      matched = statusCode === condition.value;
      break;
    case "header":
      // Check if header exists and optionally matches value
      const headerKey = condition.value.toLowerCase();
      if (condition.negate) {
        // Negate: vulnerable if header is ABSENT
        matched = !(headerKey in headers);
      } else {
        matched = headerKey in headers;
      }
      break;
    case "body":
    case "word":
      matched = body.toLowerCase().includes(condition.value.toLowerCase());
      break;
    case "banner":
      matched = body.toLowerCase().includes(condition.value.toLowerCase());
      break;
    case "regex":
      try {
        matched = new RegExp(condition.value, "i").test(body);
      } catch {
        matched = false;
      }
      break;
  }
  
  return condition.negate ? !matched : matched;
}
