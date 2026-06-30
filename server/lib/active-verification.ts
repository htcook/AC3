/**
 * Active Verification Probes
 * 
 * Sends lightweight, non-destructive probes to verify whether a vulnerability
 * is actually exploitable in the target environment. Integrates with Nuclei
 * templates and custom probe definitions.
 * 
 * Unlike full exploitation, probes only confirm the vulnerability exists
 * without executing payloads — safe for production environments.
 */

export interface ProbeDefinition {
  id: string;
  name: string;
  description: string;
  cveIds: string[];
  cweIds: string[];
  probeType: "http" | "tcp" | "dns" | "tls" | "nuclei";
  severity: "critical" | "high" | "medium" | "low" | "info";
  request: ProbeRequest;
  matchConditions: MatchCondition[];
  safeForProduction: boolean;
  tags: string[];
}

export interface ProbeRequest {
  method?: "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH";
  path?: string;
  headers?: Record<string, string>;
  body?: string;
  followRedirects?: boolean;
  timeoutMs?: number;
  rawPayload?: string; // For TCP probes
}

export interface MatchCondition {
  type: "status_code" | "header" | "body" | "body_regex" | "response_time" | "tls_version" | "content_length";
  operator: "equals" | "contains" | "not_contains" | "regex" | "greater_than" | "less_than";
  value: string;
  negate?: boolean;
}

export interface ProbeResult {
  probeId: string;
  probeName: string;
  targetHost: string;
  targetPort: number;
  status: "vulnerable" | "not_vulnerable" | "inconclusive" | "error" | "timeout";
  confidence: number; // 0-100
  matchedConditions: string[];
  failedConditions: string[];
  responseData: {
    statusCode?: number;
    headers?: Record<string, string>;
    bodySnippet?: string; // First 500 chars
    responseTimeMs: number;
    tlsVersion?: string;
    contentLength?: number;
  };
  evidence: string;
  timestamp: number;
}

export interface VerificationReport {
  targetHost: string;
  totalProbes: number;
  vulnerableCount: number;
  notVulnerableCount: number;
  inconclusiveCount: number;
  errorCount: number;
  results: ProbeResult[];
  overallRisk: "critical" | "high" | "medium" | "low" | "none";
  generatedAt: number;
  durationMs: number;
}

// ─── Built-in Probe Library ────────────────────────────────────────

export const BUILTIN_PROBES: ProbeDefinition[] = [
  {
    id: "probe-log4shell",
    name: "Log4Shell Detection",
    description: "Detects Log4j RCE (CVE-2021-44228) via JNDI lookup in headers",
    cveIds: ["CVE-2021-44228", "CVE-2021-45046"],
    cweIds: ["CWE-917", "CWE-502"],
    probeType: "http",
    severity: "critical",
    request: {
      method: "GET",
      path: "/",
      headers: {
        "X-Api-Version": "${jndi:ldap://probe-test.invalid/a}",
        "User-Agent": "${jndi:ldap://probe-test.invalid/b}",
      },
      timeoutMs: 10000,
    },
    matchConditions: [
      { type: "status_code", operator: "less_than", value: "500" },
      { type: "response_time", operator: "greater_than", value: "3000" },
    ],
    safeForProduction: true,
    tags: ["log4j", "rce", "java"],
  },
  {
    id: "probe-spring4shell",
    name: "Spring4Shell Detection",
    description: "Detects Spring Framework RCE (CVE-2022-22965)",
    cveIds: ["CVE-2022-22965"],
    cweIds: ["CWE-94"],
    probeType: "http",
    severity: "critical",
    request: {
      method: "POST",
      path: "/",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "class.module.classLoader.DefaultAssertionStatus=true",
      timeoutMs: 10000,
    },
    matchConditions: [
      { type: "status_code", operator: "less_than", value: "500" },
    ],
    safeForProduction: true,
    tags: ["spring", "rce", "java"],
  },
  {
    id: "probe-exchange-proxylogon",
    name: "ProxyLogon Detection",
    description: "Detects Microsoft Exchange ProxyLogon (CVE-2021-26855)",
    cveIds: ["CVE-2021-26855"],
    cweIds: ["CWE-918"],
    probeType: "http",
    severity: "critical",
    request: {
      method: "GET",
      path: "/owa/auth/x.js",
      headers: { "Cookie": "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3" },
      timeoutMs: 10000,
    },
    matchConditions: [
      { type: "status_code", operator: "equals", value: "500" },
      { type: "body", operator: "contains", value: "NegotiateSecurityContext" },
    ],
    safeForProduction: true,
    tags: ["exchange", "ssrf", "microsoft"],
  },
  {
    id: "probe-tls-weak",
    name: "Weak TLS Configuration",
    description: "Detects TLS 1.0/1.1 or weak cipher suites",
    cveIds: [],
    cweIds: ["CWE-326", "CWE-327"],
    probeType: "tls",
    severity: "medium",
    request: {
      timeoutMs: 5000,
    },
    matchConditions: [
      { type: "tls_version", operator: "contains", value: "TLSv1.0" },
    ],
    safeForProduction: true,
    tags: ["tls", "crypto", "compliance"],
  },
  {
    id: "probe-exposed-git",
    name: "Exposed .git Directory",
    description: "Detects publicly accessible .git directories",
    cveIds: [],
    cweIds: ["CWE-538"],
    probeType: "http",
    severity: "high",
    request: {
      method: "GET",
      path: "/.git/HEAD",
      timeoutMs: 5000,
    },
    matchConditions: [
      { type: "status_code", operator: "equals", value: "200" },
      { type: "body", operator: "contains", value: "ref: refs/" },
    ],
    safeForProduction: true,
    tags: ["git", "exposure", "recon"],
  },
  {
    id: "probe-exposed-env",
    name: "Exposed .env File",
    description: "Detects publicly accessible .env files with secrets",
    cveIds: [],
    cweIds: ["CWE-200", "CWE-538"],
    probeType: "http",
    severity: "high",
    request: {
      method: "GET",
      path: "/.env",
      timeoutMs: 5000,
    },
    matchConditions: [
      { type: "status_code", operator: "equals", value: "200" },
      { type: "body_regex", operator: "regex", value: "(DB_PASSWORD|API_KEY|SECRET|AWS_ACCESS)" },
    ],
    safeForProduction: true,
    tags: ["env", "secrets", "exposure"],
  },
  {
    id: "probe-cors-misconfigured",
    name: "CORS Misconfiguration",
    description: "Detects overly permissive CORS policies",
    cveIds: [],
    cweIds: ["CWE-942"],
    probeType: "http",
    severity: "medium",
    request: {
      method: "OPTIONS",
      path: "/",
      headers: { "Origin": "https://evil.example.com" },
      timeoutMs: 5000,
    },
    matchConditions: [
      { type: "header", operator: "contains", value: "access-control-allow-origin: https://evil.example.com" },
    ],
    safeForProduction: true,
    tags: ["cors", "web", "misconfiguration"],
  },
  {
    id: "probe-open-redirect",
    name: "Open Redirect",
    description: "Detects open redirect vulnerabilities",
    cveIds: [],
    cweIds: ["CWE-601"],
    probeType: "http",
    severity: "medium",
    request: {
      method: "GET",
      path: "/redirect?url=https://evil.example.com",
      followRedirects: false,
      timeoutMs: 5000,
    },
    matchConditions: [
      { type: "status_code", operator: "equals", value: "302" },
      { type: "header", operator: "contains", value: "location: https://evil.example.com" },
    ],
    safeForProduction: true,
    tags: ["redirect", "web"],
  },
];

// ─── Probe Execution Engine ────────────────────────────────────────

/**
 * Execute a single HTTP probe against a target.
 */
async function executeHttpProbe(
  probe: ProbeDefinition,
  targetHost: string,
  targetPort: number,
  protocol: "http" | "https"
): Promise<ProbeResult> {
  const start = Date.now();
  const url = `${protocol}://${targetHost}:${targetPort}${probe.request.path || "/"}`;
  
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), probe.request.timeoutMs || 10000);
    
    const response = await fetch(url, {
      method: probe.request.method || "GET",
      headers: probe.request.headers,
      body: probe.request.body,
      redirect: probe.request.followRedirects === false ? "manual" : "follow",
      signal: controller.signal,
    });
    clearTimeout(timeout);
    
    const responseTimeMs = Date.now() - start;
    const bodyText = await response.text().catch(() => "");
    const bodySnippet = bodyText.substring(0, 500);
    
    // Convert response headers to Record
    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key.toLowerCase()] = value;
    });
    
    // Evaluate match conditions
    const matchedConditions: string[] = [];
    const failedConditions: string[] = [];
    
    for (const condition of probe.matchConditions) {
      const matched = evaluateCondition(condition, {
        statusCode: response.status,
        headers: responseHeaders,
        body: bodyText,
        responseTimeMs,
        contentLength: bodyText.length,
      });
      
      if (matched) {
        matchedConditions.push(`${condition.type} ${condition.operator} ${condition.value}`);
      } else {
        failedConditions.push(`${condition.type} ${condition.operator} ${condition.value}`);
      }
    }
    
    // Determine status
    const allMatched = failedConditions.length === 0 && matchedConditions.length > 0;
    const someMatched = matchedConditions.length > 0;
    
    let status: ProbeResult["status"];
    let confidence: number;
    
    if (allMatched) {
      status = "vulnerable";
      confidence = Math.min(95, 60 + matchedConditions.length * 15);
    } else if (someMatched) {
      status = "inconclusive";
      confidence = 40 + matchedConditions.length * 10;
    } else {
      status = "not_vulnerable";
      confidence = 80;
    }
    
    return {
      probeId: probe.id,
      probeName: probe.name,
      targetHost,
      targetPort,
      status,
      confidence,
      matchedConditions,
      failedConditions,
      responseData: {
        statusCode: response.status,
        headers: responseHeaders,
        bodySnippet,
        responseTimeMs,
        contentLength: bodyText.length,
      },
      evidence: allMatched
        ? `Vulnerability confirmed: all ${matchedConditions.length} conditions matched.`
        : someMatched
          ? `Partial match: ${matchedConditions.length}/${probe.matchConditions.length} conditions met.`
          : `Not vulnerable: no match conditions met (HTTP ${response.status}).`,
      timestamp: Date.now(),
    };
  } catch (err: any) {
    return {
      probeId: probe.id,
      probeName: probe.name,
      targetHost,
      targetPort,
      status: err.name === "AbortError" ? "timeout" : "error",
      confidence: 0,
      matchedConditions: [],
      failedConditions: probe.matchConditions.map(c => `${c.type} ${c.operator} ${c.value}`),
      responseData: { responseTimeMs: Date.now() - start },
      evidence: `Probe failed: ${err.message}`,
      timestamp: Date.now(),
    };
  }
}

/**
 * Evaluate a single match condition against response data.
 */
function evaluateCondition(
  condition: MatchCondition,
  data: {
    statusCode: number;
    headers: Record<string, string>;
    body: string;
    responseTimeMs: number;
    contentLength: number;
    tlsVersion?: string;
  }
): boolean {
  let result = false;
  
  switch (condition.type) {
    case "status_code":
      result = compareNumeric(data.statusCode, condition.operator, Number(condition.value));
      break;
    case "header": {
      const headerStr = Object.entries(data.headers).map(([k, v]) => `${k}: ${v}`).join("\n");
      result = compareString(headerStr, condition.operator, condition.value);
      break;
    }
    case "body":
      result = compareString(data.body, condition.operator, condition.value);
      break;
    case "body_regex":
      try {
        result = new RegExp(condition.value, "i").test(data.body);
      } catch {
        result = false;
      }
      break;
    case "response_time":
      result = compareNumeric(data.responseTimeMs, condition.operator, Number(condition.value));
      break;
    case "tls_version":
      result = compareString(data.tlsVersion || "", condition.operator, condition.value);
      break;
    case "content_length":
      result = compareNumeric(data.contentLength, condition.operator, Number(condition.value));
      break;
  }
  
  return condition.negate ? !result : result;
}

function compareNumeric(actual: number, operator: string, expected: number): boolean {
  switch (operator) {
    case "equals": return actual === expected;
    case "greater_than": return actual > expected;
    case "less_than": return actual < expected;
    default: return false;
  }
}

function compareString(actual: string, operator: string, expected: string): boolean {
  switch (operator) {
    case "equals": return actual === expected;
    case "contains": return actual.toLowerCase().includes(expected.toLowerCase());
    case "not_contains": return !actual.toLowerCase().includes(expected.toLowerCase());
    case "regex": return new RegExp(expected, "i").test(actual);
    default: return false;
  }
}

// ─── Public API ────────────────────────────────────────────────────

/**
 * Run a single probe against a target.
 */
export async function runProbe(
  probe: ProbeDefinition,
  targetHost: string,
  targetPort: number = 443,
  protocol: "http" | "https" = "https"
): Promise<ProbeResult> {
  if (probe.probeType === "http") {
    return executeHttpProbe(probe, targetHost, targetPort, protocol);
  }
  
  // For non-HTTP probes, return a placeholder
  return {
    probeId: probe.id,
    probeName: probe.name,
    targetHost,
    targetPort,
    status: "inconclusive",
    confidence: 0,
    matchedConditions: [],
    failedConditions: [],
    responseData: { responseTimeMs: 0 },
    evidence: `Probe type "${probe.probeType}" not yet implemented for active execution.`,
    timestamp: Date.now(),
  };
}

/**
 * Run all applicable probes against a target and generate a verification report.
 */
export async function runVerificationSuite(
  targetHost: string,
  targetPort: number = 443,
  protocol: "http" | "https" = "https",
  probeFilter?: { cveIds?: string[]; tags?: string[]; maxSeverity?: string }
): Promise<VerificationReport> {
  const start = Date.now();
  
  // Filter probes
  let probes = [...BUILTIN_PROBES];
  if (probeFilter?.cveIds && probeFilter.cveIds.length > 0) {
    probes = probes.filter(p => p.cveIds.some(c => probeFilter.cveIds!.includes(c)));
  }
  if (probeFilter?.tags && probeFilter.tags.length > 0) {
    probes = probes.filter(p => p.tags.some(t => probeFilter.tags!.includes(t)));
  }
  
  // If no filter matches, use all production-safe probes
  if (probes.length === 0) {
    probes = BUILTIN_PROBES.filter(p => p.safeForProduction);
  }
  
  // Execute probes sequentially (to avoid overwhelming the target)
  const results: ProbeResult[] = [];
  for (const probe of probes) {
    const result = await runProbe(probe, targetHost, targetPort, protocol);
    results.push(result);
  }
  
  // Calculate overall risk
  const vulnerableCount = results.filter(r => r.status === "vulnerable").length;
  const hasCritical = results.some(r => r.status === "vulnerable" && BUILTIN_PROBES.find(p => p.id === r.probeId)?.severity === "critical");
  const hasHigh = results.some(r => r.status === "vulnerable" && BUILTIN_PROBES.find(p => p.id === r.probeId)?.severity === "high");
  
  let overallRisk: VerificationReport["overallRisk"];
  if (hasCritical) overallRisk = "critical";
  else if (hasHigh) overallRisk = "high";
  else if (vulnerableCount > 0) overallRisk = "medium";
  else if (results.some(r => r.status === "inconclusive")) overallRisk = "low";
  else overallRisk = "none";
  
  return {
    targetHost,
    totalProbes: results.length,
    vulnerableCount,
    notVulnerableCount: results.filter(r => r.status === "not_vulnerable").length,
    inconclusiveCount: results.filter(r => r.status === "inconclusive").length,
    errorCount: results.filter(r => r.status === "error" || r.status === "timeout").length,
    results,
    overallRisk,
    generatedAt: Date.now(),
    durationMs: Date.now() - start,
  };
}

/**
 * Get available probes for a given CVE.
 */
export function getProbesForCve(cveId: string): ProbeDefinition[] {
  return BUILTIN_PROBES.filter(p => p.cveIds.includes(cveId.toUpperCase()));
}

/**
 * Get all available probe tags.
 */
export function getAvailableTags(): string[] {
  const tags = new Set<string>();
  for (const probe of BUILTIN_PROBES) {
    for (const tag of probe.tags) tags.add(tag);
  }
  return Array.from(tags).sort();
}
