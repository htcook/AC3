import "./chunk-KFQGP6VL.js";

// server/lib/active-probes.ts
var PROBE_TEMPLATES = [
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
      { type: "header", value: "X-Log4j" }
    ],
    tags: ["rce", "log4j", "java"],
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
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
      { type: "body", value: "class.module" }
    ],
    safeConditions: [
      { type: "status_code", value: "400" },
      { type: "status_code", value: "403" }
    ],
    tags: ["rce", "spring", "java"],
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"]
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
      { type: "body", value: "password" }
    ],
    tags: ["admin", "exposure", "authentication"],
    references: []
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
      { type: "body", value: "repositoryformatversion" }
    ],
    tags: ["exposure", "source-code", "git"],
    references: []
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
      { type: "regex", value: "(DB_PASSWORD|API_KEY|SECRET|TOKEN)=" }
    ],
    tags: ["exposure", "credentials", "env"],
    references: []
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
      { type: "body", value: "Apache Server Status" }
    ],
    tags: ["info-disclosure", "apache"],
    references: []
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
      { type: "body", value: "phpinfo()" }
    ],
    tags: ["info-disclosure", "php"],
    references: []
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
      { type: "banner", value: "SSLv3" }
    ],
    tags: ["tls", "crypto", "weak-config"],
    references: []
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
      { type: "header", value: "strict-transport-security", negate: true }
    ],
    tags: ["headers", "best-practice"],
    references: []
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
      { type: "body", value: "Parent Directory" }
    ],
    tags: ["directory-listing", "misconfiguration"],
    references: []
  }
];
async function executeProbe(template, target, port, timeoutMs = 1e4) {
  const start = Date.now();
  const effectivePort = port || template.targetPort;
  try {
    if (template.type === "tls_check" || template.type === "dns_check") {
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
        error: `${template.type} probes require specialized network access`
      };
    }
    const protocol = effectivePort === 443 ? "https" : "http";
    const portSuffix = effectivePort && effectivePort !== 80 && effectivePort !== 443 ? `:${effectivePort}` : "";
    const url = `${protocol}://${target}${portSuffix}${template.httpPath || "/"}`;
    const response = await fetch(url, {
      method: template.httpMethod || "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; AC3-Probe/1.0)",
        ...template.httpHeaders
      },
      body: template.httpBody || void 0,
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "follow"
    });
    const statusCode = response.status.toString();
    const responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key.toLowerCase()] = value;
    });
    const body = await response.text().catch(() => "");
    const bodySnippet = body.slice(0, 1e3);
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
            timestamp: Date.now()
          };
        }
      }
    }
    const matchedConditions = [];
    for (const condition of template.matchConditions) {
      if (evaluateCondition(condition, statusCode, responseHeaders, body)) {
        matchedConditions.push(`${condition.type}=${condition.value}${condition.negate ? " (absent)" : ""}`);
      }
    }
    const matchRatio = matchedConditions.length / template.matchConditions.length;
    let result;
    let confidence;
    if (matchRatio >= 0.5) {
      result = "vulnerable";
      confidence = Math.min(0.95, 0.5 + matchRatio * 0.45);
    } else if (matchRatio > 0) {
      result = "inconclusive";
      confidence = 0.3 + matchRatio * 0.2;
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
      timestamp: Date.now()
    };
  } catch (err) {
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
      error: err.message
    };
  }
}
async function runProbeScan(target, options) {
  const start = Date.now();
  let templates = options?.templates || PROBE_TEMPLATES;
  if (options?.severityFilter?.length) {
    templates = templates.filter((t) => options.severityFilter.includes(t.severity));
  }
  if (options?.tagFilter?.length) {
    templates = templates.filter((t) => t.tags.some((tag) => options.tagFilter.includes(tag)));
  }
  const executions = [];
  for (const template of templates) {
    const execution = await executeProbe(template, target, options?.port, options?.timeoutMs);
    executions.push(execution);
  }
  const vulnerable = executions.filter((e) => e.result === "vulnerable").length;
  const notVulnerable = executions.filter((e) => e.result === "not_vulnerable").length;
  const inconclusive = executions.filter((e) => e.result === "inconclusive").length;
  const errors = executions.filter((e) => e.result === "error" || e.result === "timeout").length;
  const vulnNames = executions.filter((e) => e.result === "vulnerable").map((e) => e.templateName);
  const summary = vulnerable > 0 ? `${vulnerable} potential vulnerabilit${vulnerable > 1 ? "ies" : "y"} detected: ${vulnNames.join(", ")}` : `No vulnerabilities detected across ${templates.length} probes.`;
  return {
    target,
    totalProbes: templates.length,
    vulnerable,
    notVulnerable,
    inconclusive,
    errors,
    executions,
    durationMs: Date.now() - start,
    summary
  };
}
function getProbesForCves(cveIds) {
  const cveSet = new Set(cveIds.map((c) => c.toUpperCase()));
  return PROBE_TEMPLATES.filter((t) => t.cveIds.some((c) => cveSet.has(c.toUpperCase())));
}
function getProbesByTag(tag) {
  return PROBE_TEMPLATES.filter((t) => t.tags.includes(tag.toLowerCase()));
}
function evaluateCondition(condition, statusCode, headers, body) {
  let matched = false;
  switch (condition.type) {
    case "status_code":
      matched = statusCode === condition.value;
      break;
    case "header":
      const headerKey = condition.value.toLowerCase();
      if (condition.negate) {
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
export {
  PROBE_TEMPLATES,
  executeProbe,
  getProbesByTag,
  getProbesForCves,
  runProbeScan
};
