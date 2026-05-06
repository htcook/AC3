import {
  executeRawCommand,
  executeTool,
  init_scan_server_executor
} from "./chunk-OR6TJBFA.js";
import {
  getDb,
  init_db
} from "./chunk-SI4LILOM.js";
import {
  init_schema,
  scanResults
} from "./chunk-YQRYZ5JK.js";

// server/lib/scanners/http-header-audit-scanner.ts
init_scan_server_executor();
init_db();
init_schema();
var HEADER_SPECS = [
  {
    name: "Strict-Transport-Security",
    required: true,
    severity: "high",
    cwe: "CWE-319",
    validate: (value) => {
      if (!value) return { grade: "missing", notes: "HSTS not set \u2014 no transport security enforcement", issues: ["Missing HSTS header"] };
      const maxAge = parseInt(value.match(/max-age=(\d+)/)?.[1] || "0", 10);
      const includesSub = /includeSubDomains/i.test(value);
      const preload = /preload/i.test(value);
      if (maxAge < 31536e3) return { grade: "weak", notes: `max-age=${maxAge} is less than 1 year (31536000)`, issues: ["HSTS max-age too short"] };
      if (!includesSub) return { grade: "acceptable", notes: "Missing includeSubDomains directive", issues: ["HSTS missing includeSubDomains"] };
      if (!preload) return { grade: "acceptable", notes: "Missing preload directive", issues: ["HSTS missing preload"] };
      return { grade: "good", notes: `max-age=${maxAge}, includeSubDomains, preload`, issues: [] };
    }
  },
  {
    name: "Content-Security-Policy",
    required: true,
    severity: "high",
    cwe: "CWE-79",
    validate: (value) => {
      if (!value) return { grade: "missing", notes: "No CSP \u2014 XSS protection relies solely on browser heuristics", issues: ["Missing CSP header"] };
      const issues = [];
      if (value.includes("'unsafe-inline'")) issues.push("CSP allows unsafe-inline (XSS risk)");
      if (value.includes("'unsafe-eval'")) issues.push("CSP allows unsafe-eval (code injection risk)");
      if (value.includes("*") && !value.includes("*.")) issues.push("CSP uses wildcard source (overly permissive)");
      if (!value.includes("default-src")) issues.push("CSP missing default-src directive");
      if (issues.length > 2) return { grade: "weak", notes: issues.join("; "), issues };
      if (issues.length > 0) return { grade: "acceptable", notes: issues.join("; "), issues };
      return { grade: "good", notes: "CSP configured with restrictive directives", issues: [] };
    }
  },
  {
    name: "X-Frame-Options",
    required: true,
    severity: "medium",
    cwe: "CWE-1021",
    validate: (value) => {
      if (!value) return { grade: "missing", notes: "No clickjacking protection", issues: ["Missing X-Frame-Options"] };
      const upper = value.toUpperCase();
      if (upper === "DENY") return { grade: "good", notes: "DENY \u2014 strongest clickjacking protection", issues: [] };
      if (upper === "SAMEORIGIN") return { grade: "good", notes: "SAMEORIGIN \u2014 allows same-origin framing only", issues: [] };
      if (upper.startsWith("ALLOW-FROM")) return { grade: "acceptable", notes: "ALLOW-FROM is deprecated in modern browsers", issues: ["X-Frame-Options ALLOW-FROM deprecated"] };
      return { grade: "weak", notes: `Unrecognized value: ${value}`, issues: ["Invalid X-Frame-Options value"] };
    }
  },
  {
    name: "X-Content-Type-Options",
    required: true,
    severity: "medium",
    cwe: "CWE-16",
    validate: (value) => {
      if (!value) return { grade: "missing", notes: "No MIME sniffing protection", issues: ["Missing X-Content-Type-Options"] };
      if (value.toLowerCase() === "nosniff") return { grade: "good", notes: "nosniff \u2014 MIME sniffing blocked", issues: [] };
      return { grade: "weak", notes: `Unexpected value: ${value}`, issues: ["Invalid X-Content-Type-Options value"] };
    }
  },
  {
    name: "Referrer-Policy",
    required: true,
    severity: "low",
    cwe: "CWE-200",
    validate: (value) => {
      if (!value) return { grade: "missing", notes: "No referrer policy \u2014 full URL leaked in Referer header", issues: ["Missing Referrer-Policy"] };
      const safe = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"];
      const risky = ["unsafe-url", "no-referrer-when-downgrade"];
      if (safe.includes(value.toLowerCase())) return { grade: "good", notes: `${value} \u2014 restrictive policy`, issues: [] };
      if (risky.includes(value.toLowerCase())) return { grade: "weak", notes: `${value} \u2014 leaks referrer information`, issues: [`Referrer-Policy '${value}' leaks URL info`] };
      return { grade: "acceptable", notes: value, issues: [] };
    }
  },
  {
    name: "Permissions-Policy",
    required: false,
    severity: "low",
    cwe: "CWE-16",
    validate: (value) => {
      if (!value) return { grade: "missing", notes: "No Permissions-Policy \u2014 browser features unrestricted", issues: ["Missing Permissions-Policy"] };
      const restrictedFeatures = (value.match(/\w+=()/g) || []).length;
      if (restrictedFeatures >= 5) return { grade: "good", notes: `${restrictedFeatures} features restricted`, issues: [] };
      if (restrictedFeatures >= 2) return { grade: "acceptable", notes: `Only ${restrictedFeatures} features restricted`, issues: ["Permissions-Policy could restrict more features"] };
      return { grade: "weak", notes: "Very few features restricted", issues: ["Permissions-Policy too permissive"] };
    }
  },
  {
    name: "X-XSS-Protection",
    required: false,
    severity: "info",
    cwe: "CWE-79",
    validate: (value) => {
      if (!value) return { grade: "acceptable", notes: "Deprecated header \u2014 CSP is the modern replacement", issues: [] };
      if (value === "0") return { grade: "acceptable", notes: "Explicitly disabled (recommended if CSP is set)", issues: [] };
      if (value.includes("1; mode=block")) return { grade: "acceptable", notes: "Enabled with block mode (legacy protection)", issues: [] };
      return { grade: "acceptable", notes: value, issues: [] };
    }
  },
  {
    name: "Cache-Control",
    required: false,
    severity: "low",
    cwe: "CWE-525",
    validate: (value) => {
      if (!value) return { grade: "acceptable", notes: "No Cache-Control \u2014 browser default caching applies", issues: [] };
      const hasNoStore = /no-store/i.test(value);
      const hasPrivate = /private/i.test(value);
      if (hasNoStore) return { grade: "good", notes: "no-store \u2014 sensitive data not cached", issues: [] };
      if (hasPrivate) return { grade: "acceptable", notes: "private \u2014 not cached by shared proxies", issues: [] };
      return { grade: "acceptable", notes: value, issues: [] };
    }
  }
];
function parseHeaders(curlOutput) {
  const headers = /* @__PURE__ */ new Map();
  const lines = curlOutput.split("\n");
  for (const line of lines) {
    const match = line.match(/^([A-Za-z0-9-]+):\s*(.+)/);
    if (match) {
      headers.set(match[1].toLowerCase(), match[2].trim());
    }
  }
  return headers;
}
function parseStatusCode(curlOutput) {
  const match = curlOutput.match(/HTTP\/[\d.]+ (\d{3})/);
  return match ? parseInt(match[1], 10) : null;
}
function parseCookies(curlOutput) {
  const cookies = [];
  const setCookieRegex = /set-cookie:\s*(.+)/gi;
  let match;
  while ((match = setCookieRegex.exec(curlOutput)) !== null) {
    const cookieStr = match[1];
    const nameValue = cookieStr.split(";")[0];
    const name = nameValue.split("=")[0].trim();
    const secure = /;\s*secure/i.test(cookieStr);
    const httpOnly = /;\s*httponly/i.test(cookieStr);
    const sameSiteMatch = cookieStr.match(/;\s*samesite=(\w+)/i);
    const pathMatch = cookieStr.match(/;\s*path=([^;]+)/i);
    const domainMatch = cookieStr.match(/;\s*domain=([^;]+)/i);
    const issues = [];
    if (!secure) issues.push("Missing Secure flag");
    if (!httpOnly) issues.push("Missing HttpOnly flag");
    if (!sameSiteMatch) issues.push("Missing SameSite attribute");
    else if (sameSiteMatch[1].toLowerCase() === "none" && !secure) issues.push("SameSite=None without Secure flag");
    cookies.push({
      name,
      secure,
      httpOnly,
      sameSite: sameSiteMatch ? sameSiteMatch[1] : null,
      path: pathMatch ? pathMatch[1].trim() : "/",
      domain: domainMatch ? domainMatch[1].trim() : null,
      issues
    });
  }
  return cookies;
}
function parseCORS(headers) {
  const issues = [];
  const allowOrigin = headers.get("access-control-allow-origin") || null;
  const allowCredentials = headers.get("access-control-allow-credentials") === "true";
  const allowMethods = (headers.get("access-control-allow-methods") || "").split(",").map((m) => m.trim()).filter(Boolean);
  const allowHeaders = (headers.get("access-control-allow-headers") || "").split(",").map((h) => h.trim()).filter(Boolean);
  const exposeHeaders = (headers.get("access-control-expose-headers") || "").split(",").map((h) => h.trim()).filter(Boolean);
  const maxAgeStr = headers.get("access-control-max-age");
  const maxAge = maxAgeStr ? parseInt(maxAgeStr, 10) : null;
  if (allowOrigin === "*") {
    issues.push("CORS allows all origins (wildcard *)");
    if (allowCredentials) issues.push("CRITICAL: Wildcard origin with credentials \u2014 allows any site to steal authenticated data");
  }
  if (allowOrigin && allowOrigin !== "*" && allowOrigin.includes(",")) {
    issues.push("Multiple origins in Allow-Origin (may indicate reflection vulnerability)");
  }
  return { allowOrigin, allowCredentials, allowMethods, allowHeaders, exposeHeaders, maxAge, issues };
}
function parseTLSInfo(curlOutput) {
  const issues = [];
  const protocolMatch = curlOutput.match(/SSL connection using (TLSv[\d.]+)/i) || curlOutput.match(/\* (TLSv[\d.]+)/);
  const cipherMatch = curlOutput.match(/SSL connection using .+ \/ (.+)/i);
  const issuerMatch = curlOutput.match(/issuer: (.+)/i);
  const expiryMatch = curlOutput.match(/expire date: (.+)/i);
  const subjectMatch = curlOutput.match(/subject: (.+)/i);
  const protocol = protocolMatch ? protocolMatch[1] : null;
  if (protocol) {
    if (protocol.includes("1.0") || protocol.includes("1.1")) {
      issues.push(`Deprecated TLS version: ${protocol}`);
    }
  }
  const expiry = expiryMatch ? expiryMatch[1].trim() : null;
  if (expiry) {
    try {
      const expiryDate = new Date(expiry);
      if (expiryDate < /* @__PURE__ */ new Date()) issues.push("TLS certificate has expired");
      else if (expiryDate < new Date(Date.now() + 30 * 24 * 60 * 60 * 1e3)) issues.push("TLS certificate expires within 30 days");
    } catch {
    }
  }
  return {
    protocol,
    cipher: cipherMatch ? cipherMatch[1].trim() : null,
    certIssuer: issuerMatch ? issuerMatch[1].trim() : null,
    certExpiry: expiry,
    certSubject: subjectMatch ? subjectMatch[1].trim() : null,
    issues
  };
}
function generateFindings(securityHeaders, cookies, cors, tls, serverHeader, poweredBy, isHTTPS) {
  const findings = [];
  for (const header of securityHeaders) {
    if (header.grade === "missing" && HEADER_SPECS.find((s) => s.name === header.name)?.required) {
      const spec = HEADER_SPECS.find((s) => s.name === header.name);
      findings.push({
        id: `http-header-missing-${header.name.toLowerCase()}-${Date.now()}`,
        category: "header_missing",
        severity: spec.severity,
        title: `Missing Security Header: ${header.name}`,
        description: `The ${header.name} header is not set. ${header.notes}`,
        recommendation: getHeaderRecommendation(header.name),
        cwe: spec.cwe,
        evidence: `Header ${header.name} not present in response`,
        header: header.name
      });
    } else if (header.grade === "weak" || header.grade === "critical") {
      const spec = HEADER_SPECS.find((s) => s.name === header.name);
      findings.push({
        id: `http-header-weak-${header.name.toLowerCase()}-${Date.now()}`,
        category: "header_weak",
        severity: header.grade === "critical" ? "high" : "medium",
        title: `Weak Security Header: ${header.name}`,
        description: `The ${header.name} header is configured but has issues: ${header.notes}`,
        recommendation: getHeaderRecommendation(header.name),
        cwe: spec?.cwe || null,
        evidence: `${header.name}: ${header.value}`,
        header: header.name
      });
    }
  }
  for (const cookie of cookies) {
    if (cookie.issues.length > 0) {
      const isCritical = cookie.issues.some((i) => i.includes("CRITICAL") || i.includes("Secure") && i.includes("HttpOnly"));
      findings.push({
        id: `http-cookie-${cookie.name}-${Date.now()}`,
        category: "cookie",
        severity: isCritical ? "high" : "medium",
        title: `Insecure Cookie: ${cookie.name}`,
        description: `Cookie "${cookie.name}" has security issues: ${cookie.issues.join(", ")}`,
        recommendation: "Set Secure, HttpOnly, and SameSite=Strict (or Lax) flags on all cookies. Ensure SameSite=None cookies also have the Secure flag.",
        cwe: "CWE-614",
        evidence: cookie.issues.join("; "),
        header: "Set-Cookie"
      });
    }
  }
  if (cors.issues.length > 0) {
    const isCritical = cors.issues.some((i) => i.includes("CRITICAL"));
    findings.push({
      id: `http-cors-${Date.now()}`,
      category: "cors",
      severity: isCritical ? "critical" : "medium",
      title: isCritical ? "Critical CORS Misconfiguration" : "CORS Misconfiguration Detected",
      description: cors.issues.join(". "),
      recommendation: "Restrict Access-Control-Allow-Origin to specific trusted domains. Never use wildcard (*) with credentials. Validate the Origin header server-side.",
      cwe: "CWE-942",
      evidence: `Allow-Origin: ${cors.allowOrigin}, Allow-Credentials: ${cors.allowCredentials}`,
      header: "Access-Control-Allow-Origin"
    });
  }
  if (tls && tls.issues.length > 0) {
    for (const issue of tls.issues) {
      const isExpired = issue.includes("expired");
      const isDeprecated = issue.includes("Deprecated");
      findings.push({
        id: `http-tls-${issue.replace(/\s+/g, "-").toLowerCase()}-${Date.now()}`,
        category: "tls",
        severity: isExpired ? "critical" : isDeprecated ? "high" : "medium",
        title: issue,
        description: issue,
        recommendation: isExpired ? "Renew the TLS certificate immediately." : isDeprecated ? "Disable TLS 1.0 and 1.1. Configure the server to use TLS 1.2+ only." : "Review TLS configuration and update to current best practices.",
        cwe: isDeprecated ? "CWE-326" : "CWE-295",
        evidence: `Protocol: ${tls.protocol}, Cipher: ${tls.cipher}`,
        header: null
      });
    }
  }
  if (!isHTTPS) {
    findings.push({
      id: `http-no-https-${Date.now()}`,
      category: "tls",
      severity: "high",
      title: "Service Running on HTTP (No Encryption)",
      description: "The service is accessible over unencrypted HTTP. All data including credentials and session tokens are transmitted in plaintext.",
      recommendation: "Enable HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS. Set HSTS header.",
      cwe: "CWE-319",
      evidence: "Service responded on HTTP port without TLS",
      header: null
    });
  }
  if (serverHeader) {
    findings.push({
      id: `http-server-disclosure-${Date.now()}`,
      category: "disclosure",
      severity: "low",
      title: "Server Version Disclosed",
      description: `The Server header reveals: "${serverHeader}". This helps attackers identify specific vulnerabilities.`,
      recommendation: "Remove or minimize the Server header. In nginx: 'server_tokens off;'. In Apache: 'ServerTokens Prod'.",
      cwe: "CWE-200",
      evidence: `Server: ${serverHeader}`,
      header: "Server"
    });
  }
  if (poweredBy) {
    findings.push({
      id: `http-powered-by-${Date.now()}`,
      category: "disclosure",
      severity: "low",
      title: "Technology Stack Disclosed via X-Powered-By",
      description: `The X-Powered-By header reveals: "${poweredBy}". This exposes the backend technology stack.`,
      recommendation: "Remove the X-Powered-By header. In Express.js: app.disable('x-powered-by'). In PHP: expose_php = Off.",
      cwe: "CWE-200",
      evidence: `X-Powered-By: ${poweredBy}`,
      header: "X-Powered-By"
    });
  }
  return findings;
}
function getHeaderRecommendation(headerName) {
  const recs = {
    "Strict-Transport-Security": "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "Add a restrictive CSP. Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'",
    "X-Frame-Options": "Add: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed)",
    "X-Content-Type-Options": "Add: X-Content-Type-Options: nosniff",
    "Referrer-Policy": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    "Permissions-Policy": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()"
  };
  return recs[headerName] || `Add the ${headerName} header with appropriate security values.`;
}
function calculateGradeScore(headers, cookies, cors, tls, isHTTPS) {
  let score = 100;
  for (const h of headers) {
    if (h.grade === "missing" && HEADER_SPECS.find((s) => s.name === h.name)?.required) score -= 12;
    else if (h.grade === "weak") score -= 8;
    else if (h.grade === "critical") score -= 15;
    else if (h.grade === "acceptable" && h.notes.includes("Missing")) score -= 3;
  }
  for (const c of cookies) {
    score -= Math.min(c.issues.length * 3, 10);
  }
  if (cors.issues.some((i) => i.includes("CRITICAL"))) score -= 20;
  else if (cors.issues.length > 0) score -= 8;
  if (!isHTTPS) score -= 25;
  if (tls?.issues.some((i) => i.includes("expired"))) score -= 20;
  if (tls?.issues.some((i) => i.includes("Deprecated"))) score -= 10;
  return Math.max(0, Math.min(100, score));
}
async function startHTTPHeaderAudit(config) {
  const startTime = Date.now();
  const isHTTPS = config.https !== false;
  const port = config.port || (isHTTPS ? 443 : 80);
  const protocol = isHTTPS ? "https" : "http";
  const path = config.path || "/";
  const url = `${protocol}://${config.host}:${port}${path}`;
  const timeout = config.timeoutSeconds || 30;
  const ua = config.userAgent || "Mozilla/5.0 (compatible; AC3-SecurityAudit/1.0)";
  console.log(`[HTTPHeaderAudit] Starting audit of ${url}`);
  let rawOutput = "";
  let statusCode = null;
  let headerMap = /* @__PURE__ */ new Map();
  let cookies = [];
  let tlsInfo = null;
  try {
    const redirectFlag = config.followRedirects !== false ? "-L" : "";
    const curlResult = await executeRawCommand(
      `curl -sS -D - -o /dev/null ${redirectFlag} -k --max-time ${timeout} -A "${ua}" -H "Origin: https://evil.example.com" "${url}" 2>&1`,
      timeout + 5
    );
    rawOutput += `=== curl headers ===
${curlResult.stdout}
`;
    statusCode = parseStatusCode(curlResult.stdout);
    headerMap = parseHeaders(curlResult.stdout);
    cookies = parseCookies(curlResult.stdout);
  } catch (err) {
    console.warn(`[HTTPHeaderAudit] curl failed: ${err.message}`);
  }
  if (isHTTPS && config.checkTLS !== false) {
    try {
      const tlsResult = await executeRawCommand(
        `curl -vvI -k --max-time 10 "${url}" 2>&1 | grep -E "SSL|TLS|issuer|subject|expire|certificate"`,
        15
      );
      rawOutput += `
=== TLS info ===
${tlsResult.stdout}
`;
      tlsInfo = parseTLSInfo(tlsResult.stdout);
    } catch (err) {
      console.warn(`[HTTPHeaderAudit] TLS check failed: ${err.message}`);
    }
  }
  try {
    const discoveryResult = await executeTool({
      tool: "naabu",
      args: `-p ${port} --script http-headers,http-server-header,http-security-headers,http-cors -sV ${config.host}`,
      target: config.host,
      timeoutSeconds: timeout,
      engagementId: config.engagementId
    });
    rawOutput += `
=== ScanForge discovery HTTP scripts ===
${discoveryResult.stdout}
`;
    if (headerMap.size === 0) {
      headerMap = parseHeaders(discoveryResult.stdout);
    }
  } catch (err) {
    console.warn(`[HTTPHeaderAudit] ScanForge discovery HTTP scripts failed: ${err.message}`);
  }
  const securityHeaders = HEADER_SPECS.map((spec) => {
    const value = headerMap.get(spec.name.toLowerCase()) || null;
    const validation = spec.validate(value);
    return {
      name: spec.name,
      value,
      present: value !== null,
      grade: validation.grade,
      notes: validation.notes
    };
  });
  const cors = parseCORS(headerMap);
  const serverHeader = headerMap.get("server") || null;
  const poweredBy = headerMap.get("x-powered-by") || null;
  const findings = generateFindings(securityHeaders, cookies, cors, tlsInfo, serverHeader, poweredBy, isHTTPS);
  const gradeScore = calculateGradeScore(securityHeaders, cookies, cors, tlsInfo, isHTTPS);
  const durationSeconds = (Date.now() - startTime) / 1e3;
  let scanId = null;
  try {
    const db = await getDb();
    const severitySummary = {
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length
    };
    const [inserted] = await db.insert(scanResults).values({
      engagementId: config.engagementId,
      tool: "http-header-audit",
      target: url,
      command: `http-header-audit ${url}`,
      rawOutput: rawOutput.slice(0, 5e5),
      rawStderr: null,
      exitCode: 0,
      durationMs: Math.round(durationSeconds * 1e3),
      timedOut: 0,
      findings: JSON.stringify({
        findings,
        headers: securityHeaders,
        cookies,
        cors,
        tls: tlsInfo,
        gradeScore
      }),
      findingCount: findings.length,
      severitySummary: JSON.stringify(severitySummary),
      phase: "vuln_detection",
      operatorId: config.operatorId || null
    });
    scanId = inserted.insertId;
  } catch (dbErr) {
    console.error(`[HTTPHeaderAudit] Failed to store scan result:`, dbErr.message);
  }
  console.log(`[HTTPHeaderAudit] Audit complete: ${findings.length} findings, grade ${gradeScore}/100 in ${durationSeconds.toFixed(1)}s`);
  return {
    scanId,
    status: "completed",
    host: config.host,
    port,
    url,
    statusCode,
    serverHeader,
    headers: securityHeaders,
    cookies,
    cors,
    tls: tlsInfo,
    findings,
    stats: {
      totalFindings: findings.length,
      headersPresent: securityHeaders.filter((h) => h.present).length,
      headersMissing: securityHeaders.filter((h) => !h.present && HEADER_SPECS.find((s) => s.name === h.name)?.required).length,
      gradeScore,
      durationSeconds
    },
    rawOutput
  };
}

export {
  startHTTPHeaderAudit
};
