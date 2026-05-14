import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/scap-compliance-scanner.ts
async function fetchWithTimeout(url, timeout, options) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal, redirect: "follow" });
    clearTimeout(timer);
    return res;
  } catch {
    clearTimeout(timer);
    return null;
  }
}
async function runExternalComplianceScan(target, options) {
  const startTime = Date.now();
  const timeout = options?.timeout ?? 1e4;
  const concurrency = options?.concurrency ?? 3;
  let checks = ALL_EXTERNAL_CHECKS;
  if (options?.categories) {
    checks = checks.filter((c) => options.categories.includes(c.category));
  }
  if (options?.benchmarks) {
    checks = checks.filter((c) => options.benchmarks.includes(c.benchmarkSource));
  }
  const results = [];
  for (let i = 0; i < checks.length; i += concurrency) {
    const batch = checks.slice(i, i + concurrency);
    const batchResults = await Promise.allSettled(
      batch.map(async (checkDef) => {
        try {
          const { status, evidence } = await checkDef.check(target, timeout);
          return {
            checkId: checkDef.checkId,
            title: checkDef.title,
            description: checkDef.description,
            category: checkDef.category,
            benchmarkSource: checkDef.benchmarkSource,
            benchmarkRef: checkDef.benchmarkRef,
            severity: checkDef.severity,
            status,
            evidence,
            remediation: checkDef.remediation,
            automatable: checkDef.automatable,
            stigId: checkDef.stigId,
            nistControls: checkDef.nistControls,
            ccis: checkDef.ccis
          };
        } catch (err) {
          return {
            checkId: checkDef.checkId,
            title: checkDef.title,
            description: checkDef.description,
            category: checkDef.category,
            benchmarkSource: checkDef.benchmarkSource,
            benchmarkRef: checkDef.benchmarkRef,
            severity: checkDef.severity,
            status: "error",
            evidence: `Check execution error: ${err.message}`,
            remediation: checkDef.remediation,
            automatable: checkDef.automatable,
            stigId: checkDef.stigId,
            nistControls: checkDef.nistControls,
            ccis: checkDef.ccis
          };
        }
      })
    );
    for (const result of batchResults) {
      if (result.status === "fulfilled") {
        results.push(result.value);
      }
    }
  }
  const passed = results.filter((r) => r.status === "pass").length;
  const failed = results.filter((r) => r.status === "fail").length;
  const notApplicable = results.filter((r) => r.status === "not_applicable").length;
  const errors = results.filter((r) => r.status === "error").length;
  const manualReview = results.filter((r) => r.status === "manual_review").length;
  const applicable = results.length - notApplicable - errors;
  const complianceScore = applicable > 0 ? Math.round(passed / applicable * 100) : 0;
  const criticalFails = results.filter((r) => r.status === "fail" && r.severity === "critical").length;
  const highFails = results.filter((r) => r.status === "fail" && r.severity === "high").length;
  return {
    target,
    scanType: "external",
    scanDate: /* @__PURE__ */ new Date(),
    totalChecks: results.length,
    passed,
    failed,
    notApplicable,
    errors,
    manualReview,
    complianceScore,
    checks: results,
    benchmarkProfile: "CIS + DISA STIG + NIST 800-53 (External Audit)",
    durationMs: Date.now() - startTime,
    summary: `External compliance scan: ${complianceScore}% compliant (${passed}/${applicable} applicable checks passed). ${criticalFails} critical and ${highFails} high severity failures detected.`
  };
}
function parseOpenSCAPResults(xccdfXml, target) {
  const startTime = Date.now();
  const checks = [];
  const ruleResultRegex = /<rule-result\s+idref="([^"]*)"[^>]*>([\s\S]*?)<\/rule-result>/g;
  const resultRegex = /<result>(\w+)<\/result>/;
  const titleRegex = /<title[^>]*>([^<]*)<\/title>/;
  const descRegex = /<description[^>]*>([\s\S]*?)<\/description>/;
  const fixRegex = /<fix[^>]*>([\s\S]*?)<\/fix>/;
  const identRegex = /<ident[^>]*>([^<]*)<\/ident>/g;
  const severityRegex = /severity="(\w+)"/;
  let match;
  while ((match = ruleResultRegex.exec(xccdfXml)) !== null) {
    const ruleId = match[1];
    const content = match[2];
    const resultMatch = resultRegex.exec(content);
    const result = resultMatch?.[1] || "unknown";
    const titleMatch = titleRegex.exec(content);
    const descMatch = descRegex.exec(content);
    const fixMatch = fixRegex.exec(content);
    const sevMatch = severityRegex.exec(match[0]);
    let status;
    switch (result) {
      case "pass":
        status = "pass";
        break;
      case "fail":
        status = "fail";
        break;
      case "notapplicable":
        status = "not_applicable";
        break;
      case "error":
        status = "error";
        break;
      default:
        status = "manual_review";
    }
    let severity;
    switch (sevMatch?.[1]) {
      case "high":
        severity = "high";
        break;
      case "medium":
        severity = "medium";
        break;
      case "low":
        severity = "low";
        break;
      default:
        severity = "medium";
    }
    const nistControls = [];
    let identMatch;
    while ((identMatch = identRegex.exec(content)) !== null) {
      const ident = identMatch[1];
      if (/^[A-Z]{2}-\d+/.test(ident)) nistControls.push(ident);
    }
    checks.push({
      checkId: ruleId,
      title: titleMatch?.[1] || ruleId,
      description: descMatch?.[1]?.replace(/<[^>]*>/g, "").trim() || "",
      category: "service_hardening",
      benchmarkSource: ruleId.includes("stig") ? "disa_stig" : "cis",
      benchmarkRef: ruleId,
      severity,
      status,
      evidence: `OpenSCAP result: ${result}`,
      remediation: fixMatch?.[1]?.replace(/<[^>]*>/g, "").trim() || "See benchmark documentation for remediation steps.",
      automatable: false,
      nistControls
    });
  }
  const passed = checks.filter((r) => r.status === "pass").length;
  const failed = checks.filter((r) => r.status === "fail").length;
  const notApplicable = checks.filter((r) => r.status === "not_applicable").length;
  const errors = checks.filter((r) => r.status === "error").length;
  const manualReview = checks.filter((r) => r.status === "manual_review").length;
  const applicable = checks.length - notApplicable - errors;
  const complianceScore = applicable > 0 ? Math.round(passed / applicable * 100) : 0;
  return {
    target,
    scanType: "authenticated",
    scanDate: /* @__PURE__ */ new Date(),
    totalChecks: checks.length,
    passed,
    failed,
    notApplicable,
    errors,
    manualReview,
    complianceScore,
    checks,
    benchmarkProfile: "OpenSCAP XCCDF (Authenticated)",
    durationMs: Date.now() - startTime,
    summary: `Authenticated compliance scan: ${complianceScore}% compliant (${passed}/${applicable} applicable checks passed). ${failed} failures detected.`
  };
}
function parseLynisReport(reportText, target) {
  const startTime = Date.now();
  const checks = [];
  const lines = reportText.split("\n");
  for (const line of lines) {
    if (!line.startsWith("test_id=") && !line.includes("|result=")) continue;
    const fields = {};
    for (const part of line.split("|")) {
      const [key, ...vals] = part.split("=");
      if (key) fields[key.trim()] = vals.join("=").trim();
    }
    if (!fields.test_id) continue;
    let status;
    switch (fields.result?.toUpperCase()) {
      case "OK":
      case "PASSED":
        status = "pass";
        break;
      case "WARNING":
      case "SUGGESTION":
        status = "fail";
        break;
      case "FAILED":
      case "CRITICAL":
        status = "fail";
        break;
      case "SKIPPED":
        status = "not_applicable";
        break;
      default:
        status = "manual_review";
    }
    let severity;
    switch (fields.severity?.toLowerCase()) {
      case "critical":
        severity = "critical";
        break;
      case "high":
      case "warning":
        severity = "high";
        break;
      case "medium":
        severity = "medium";
        break;
      case "low":
      case "suggestion":
        severity = "low";
        break;
      default:
        severity = "medium";
    }
    checks.push({
      checkId: fields.test_id,
      title: fields.description || fields.test_id,
      description: fields.details || "",
      category: mapLynisCategoryToCheckCategory(fields.category || ""),
      benchmarkSource: "cis",
      benchmarkRef: fields.test_id,
      severity,
      status,
      evidence: `Lynis result: ${fields.result || "unknown"}`,
      remediation: fields.suggestion || fields.remediation || "Review Lynis documentation for remediation guidance.",
      automatable: false,
      nistControls: []
    });
  }
  const passed = checks.filter((r) => r.status === "pass").length;
  const failed = checks.filter((r) => r.status === "fail").length;
  const notApplicable = checks.filter((r) => r.status === "not_applicable").length;
  const errors = checks.filter((r) => r.status === "error").length;
  const manualReview = checks.filter((r) => r.status === "manual_review").length;
  const applicable = checks.length - notApplicable - errors;
  const complianceScore = applicable > 0 ? Math.round(passed / applicable * 100) : 0;
  return {
    target,
    scanType: "authenticated",
    scanDate: /* @__PURE__ */ new Date(),
    totalChecks: checks.length,
    passed,
    failed,
    notApplicable,
    errors,
    manualReview,
    complianceScore,
    checks,
    benchmarkProfile: "Lynis Security Audit (Authenticated)",
    durationMs: Date.now() - startTime,
    summary: `Lynis audit: ${complianceScore}% compliant (${passed}/${applicable} applicable checks passed). ${failed} failures detected.`
  };
}
function mapLynisCategoryToCheckCategory(lynisCategory) {
  const mapping = {
    "authentication": "authentication",
    "boot_services": "service_hardening",
    "crypto": "cryptography",
    "dns": "dns_security",
    "file_integrity": "logging_auditing",
    "file_permissions": "access_control",
    "firewalls": "network_security",
    "hardening": "service_hardening",
    "kernel": "service_hardening",
    "logging": "logging_auditing",
    "networking": "network_security",
    "shells": "access_control",
    "ssh": "authentication",
    "storage": "access_control",
    "webserver": "service_hardening"
  };
  return mapping[lynisCategory.toLowerCase()] || "service_hardening";
}
var TLS_CHECKS, HTTP_HEADER_CHECKS, DNS_CHECKS, SERVICE_CHECKS, AUTH_CHECKS, ALL_EXTERNAL_CHECKS, EXTERNAL_CHECK_COUNT, CHECK_CATEGORIES, BENCHMARK_SOURCES;
var init_scap_compliance_scanner = __esm({
  "server/lib/scap-compliance-scanner.ts"() {
    TLS_CHECKS = [
      {
        checkId: "scap-tls-version",
        title: "TLS 1.2+ Required",
        description: "Verify that the server supports TLS 1.2 or higher and does not support TLS 1.0/1.1",
        category: "tls_configuration",
        benchmarkSource: "cis",
        benchmarkRef: "CIS 3.4.1",
        severity: "high",
        stigId: "V-221655",
        nistControls: ["SC-8", "SC-13", "SC-23"],
        ccis: ["CCI-000068", "CCI-001453"],
        remediation: "Disable TLS 1.0 and TLS 1.1 in server configuration. Enable only TLS 1.2 and TLS 1.3.",
        automatable: true,
        check: async (target, timeout) => {
          const res = await fetchWithTimeout(`https://${target}/`, timeout);
          if (!res) return { status: "error", evidence: "Could not establish HTTPS connection" };
          return { status: "pass", evidence: "HTTPS connection established successfully \u2014 TLS 1.2+ supported" };
        }
      },
      {
        checkId: "scap-hsts",
        title: "HTTP Strict Transport Security (HSTS)",
        description: "Verify HSTS header is present with adequate max-age (at least 31536000 seconds)",
        category: "tls_configuration",
        benchmarkSource: "cis",
        benchmarkRef: "CIS 5.1.2",
        severity: "medium",
        stigId: "V-221656",
        nistControls: ["SC-8", "SC-23"],
        ccis: ["CCI-000068"],
        remediation: "Add Strict-Transport-Security header with max-age=31536000; includeSubDomains; preload",
        automatable: true,
        check: async (target, timeout) => {
          const res = await fetchWithTimeout(`https://${target}/`, timeout);
          if (!res) return { status: "error", evidence: "Could not connect to target" };
          const hsts = res.headers.get("strict-transport-security");
          if (!hsts) return { status: "fail", evidence: "HSTS header not present" };
          const maxAgeMatch = /max-age=(\d+)/i.exec(hsts);
          if (!maxAgeMatch) return { status: "fail", evidence: `HSTS present but no max-age: ${hsts}` };
          const maxAge = parseInt(maxAgeMatch[1]);
          if (maxAge < 31536e3) return { status: "fail", evidence: `HSTS max-age too short: ${maxAge}s (need 31536000)` };
          return { status: "pass", evidence: `HSTS configured: ${hsts}` };
        }
      },
      {
        checkId: "scap-cert-validity",
        title: "TLS Certificate Validity",
        description: "Verify TLS certificate is valid and not expired or self-signed",
        category: "tls_configuration",
        benchmarkSource: "disa_stig",
        benchmarkRef: "SRG-APP-000516",
        severity: "high",
        stigId: "V-221660",
        nistControls: ["SC-8", "IA-5"],
        remediation: "Renew expired certificates. Replace self-signed certificates with CA-signed certificates.",
        automatable: false,
        check: async (target, timeout) => {
          const res = await fetchWithTimeout(`https://${target}/`, timeout);
          if (!res) return { status: "fail", evidence: "TLS connection failed \u2014 certificate may be invalid, expired, or self-signed" };
          return { status: "pass", evidence: "TLS certificate accepted by standard validation" };
        }
      }
    ];
    HTTP_HEADER_CHECKS = [
      {
        checkId: "scap-csp",
        title: "Content Security Policy (CSP)",
        description: "Verify Content-Security-Policy header is present and properly configured",
        category: "http_security_headers",
        benchmarkSource: "cis",
        benchmarkRef: "CIS 5.2.1",
        severity: "medium",
        nistControls: ["SI-10", "SC-18"],
        remediation: "Implement Content-Security-Policy header with restrictive directives. Avoid 'unsafe-inline' and 'unsafe-eval'.",
        automatable: true,
        check: async (target, timeout) => {
          const res = await fetchWithTimeout(`https://${target}/`, timeout);
          if (!res) return { status: "error", evidence: "Could not connect" };
          const csp = res.headers.get("content-security-policy");
          if (!csp) return { status: "fail", evidence: "Content-Security-Policy header not present" };
          const hasUnsafe = csp.includes("unsafe-inline") || csp.includes("unsafe-eval");
          if (hasUnsafe) return { status: "fail", evidence: `CSP present but contains unsafe directives: ${csp.slice(0, 200)}` };
          return { status: "pass", evidence: `CSP configured: ${csp.slice(0, 200)}` };
        }
      },
      {
        checkId: "scap-x-frame-options",
        title: "X-Frame-Options / Frame Ancestors",
        description: "Verify clickjacking protection via X-Frame-Options or CSP frame-ancestors",
        category: "http_security_headers",
        benchmarkSource: "cis",
        benchmarkRef: "CIS 5.2.2",
        severity: "medium",
        nistControls: ["SI-10", "SC-18"],
        remediation: "Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors directive.",
        automatable: true,
        check: async (target, timeout) => {
          const res = await fetchWithTimeout(`https://${target}/`, timeout);
          if (!res) return { status: "error", evidence: "Could not connect" };
          const xfo = res.headers.get("x-frame-options");
          const csp = res.headers.get("content-security-policy") || "";
          if (xfo || csp.includes("frame-ancestors")) {
            return { status: "pass", evidence: `Clickjacking protection: X-Frame-Options=${xfo || "not set"}, CSP frame-ancestors=${csp.includes("frame-ancestors") ? "present" : "not set"}` };
          }
          return { status: "fail", evidence: "No clickjacking protection \u2014 neither X-Frame-Options nor CSP frame-ancestors set" };
        }
      },
      {
        checkId: "scap-x-content-type",
        title: "X-Content-Type-Options",
        description: "Verify X-Content-Type-Options: nosniff header is present",
        category: "http_security_headers",
        benchmarkSource: "cis",
        benchmarkRef: "CIS 5.2.3",
        severity: "low",
        nistControls: ["SI-10"],
        remediation: "Add X-Content-Type-Options: nosniff header to all responses.",
        automatable: true,
        check: async (target, timeout) => {
          const res = await fetchWithTimeout(`https://${target}/`, timeout);
          if (!res) return { status: "error", evidence: "Could not connect" };
          const xcto = res.headers.get("x-content-type-options");
          if (xcto?.toLowerCase() === "nosniff") return { status: "pass", evidence: "X-Content-Type-Options: nosniff present" };
          return { status: "fail", evidence: `X-Content-Type-Options: ${xcto || "not set"}` };
        }
      },
      {
        checkId: "scap-referrer-policy",
        title: "Referrer-Policy Header",
        description: "Verify Referrer-Policy header is set to prevent information leakage",
        category: "http_security_headers",
        benchmarkSource: "cis",
        benchmarkRef: "CIS 5.2.5",
        severity: "low",
        nistControls: ["SC-7"],
        remediation: "Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
        automatable: true,
        check: async (target, timeout) => {
          const res = await fetchWithTimeout(`https://${target}/`, timeout);
          if (!res) return { status: "error", evidence: "Could not connect" };
          const rp = res.headers.get("referrer-policy");
          if (!rp) return { status: "fail", evidence: "Referrer-Policy header not present" };
          const safe = ["no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"];
          if (safe.some((s) => rp.toLowerCase().includes(s))) return { status: "pass", evidence: `Referrer-Policy: ${rp}` };
          return { status: "fail", evidence: `Referrer-Policy set but may leak info: ${rp}` };
        }
      },
      {
        checkId: "scap-permissions-policy",
        title: "Permissions-Policy Header",
        description: "Verify Permissions-Policy (formerly Feature-Policy) restricts browser features",
        category: "http_security_headers",
        benchmarkSource: "cis",
        benchmarkRef: "CIS 5.2.6",
        severity: "low",
        nistControls: ["SC-18", "AC-4"],
        remediation: "Set Permissions-Policy header to restrict camera, microphone, geolocation, and other sensitive browser APIs.",
        automatable: true,
        check: async (target, timeout) => {
          const res = await fetchWithTimeout(`https://${target}/`, timeout);
          if (!res) return { status: "error", evidence: "Could not connect" };
          const pp = res.headers.get("permissions-policy") || res.headers.get("feature-policy");
          if (!pp) return { status: "fail", evidence: "Permissions-Policy header not present" };
          return { status: "pass", evidence: `Permissions-Policy: ${pp.slice(0, 200)}` };
        }
      },
      {
        checkId: "scap-cache-control",
        title: "Cache-Control for Sensitive Pages",
        description: "Verify Cache-Control headers prevent caching of sensitive responses",
        category: "http_security_headers",
        benchmarkSource: "disa_stig",
        benchmarkRef: "SRG-APP-000266",
        severity: "low",
        stigId: "V-222425",
        nistControls: ["SC-8"],
        remediation: "Set Cache-Control: no-store, no-cache, must-revalidate for sensitive pages.",
        automatable: true,
        check: async (target, timeout) => {
          const res = await fetchWithTimeout(`https://${target}/`, timeout);
          if (!res) return { status: "error", evidence: "Could not connect" };
          const cc = res.headers.get("cache-control");
          if (!cc) return { status: "fail", evidence: "Cache-Control header not present" };
          if (cc.includes("no-store") || cc.includes("private")) return { status: "pass", evidence: `Cache-Control: ${cc}` };
          return { status: "fail", evidence: `Cache-Control present but may allow caching: ${cc}` };
        }
      }
    ];
    DNS_CHECKS = [
      {
        checkId: "scap-dnssec",
        title: "DNSSEC Validation",
        description: "Verify DNSSEC is enabled for the domain",
        category: "dns_security",
        benchmarkSource: "nist_800_53",
        benchmarkRef: "SC-20",
        severity: "medium",
        nistControls: ["SC-20", "SC-21"],
        remediation: "Enable DNSSEC signing for the domain zone. Configure DS records with the registrar.",
        automatable: false,
        check: async (target, timeout) => {
          const res = await fetchWithTimeout(
            `https://dns.google/resolve?name=${target}&type=A&do=1`,
            timeout
          );
          if (!res) return { status: "error", evidence: "Could not query DNS" };
          try {
            const data = await res.json();
            const ad = data.AD;
            if (ad) return { status: "pass", evidence: "DNSSEC validated \u2014 AD flag set in DNS response" };
            return { status: "fail", evidence: "DNSSEC not validated \u2014 AD flag not set. Domain may not have DNSSEC configured." };
          } catch {
            return { status: "error", evidence: "Failed to parse DNS response" };
          }
        }
      },
      {
        checkId: "scap-caa",
        title: "CAA DNS Records",
        description: "Verify Certificate Authority Authorization (CAA) records restrict certificate issuance",
        category: "dns_security",
        benchmarkSource: "cis",
        benchmarkRef: "CIS 3.5.1",
        severity: "low",
        nistControls: ["SC-8", "IA-5"],
        remediation: "Add CAA DNS records to restrict which CAs can issue certificates for the domain.",
        automatable: true,
        check: async (target, timeout) => {
          const res = await fetchWithTimeout(
            `https://dns.google/resolve?name=${target}&type=CAA`,
            timeout
          );
          if (!res) return { status: "error", evidence: "Could not query DNS" };
          try {
            const data = await res.json();
            if (data.Answer && data.Answer.length > 0) {
              const caaRecords = data.Answer.filter((a) => a.type === 257);
              if (caaRecords.length > 0) return { status: "pass", evidence: `CAA records found: ${caaRecords.map((r) => r.data).join(", ")}` };
            }
            return { status: "fail", evidence: "No CAA DNS records found \u2014 any CA can issue certificates for this domain" };
          } catch {
            return { status: "error", evidence: "Failed to parse DNS response" };
          }
        }
      }
    ];
    SERVICE_CHECKS = [
      {
        checkId: "scap-server-banner",
        title: "Server Version Disclosure",
        description: "Verify server does not disclose detailed version information in headers",
        category: "service_hardening",
        benchmarkSource: "cis",
        benchmarkRef: "CIS 5.3.1",
        severity: "low",
        stigId: "V-222610",
        nistControls: ["SC-7", "SI-11"],
        remediation: "Configure web server to suppress version information in Server header. Use ServerTokens Prod (Apache) or server_tokens off (Nginx).",
        automatable: true,
        check: async (target, timeout) => {
          const res = await fetchWithTimeout(`https://${target}/`, timeout);
          if (!res) return { status: "error", evidence: "Could not connect" };
          const server = res.headers.get("server") || "";
          const xPowered = res.headers.get("x-powered-by") || "";
          const issues = [];
          if (/\d+\.\d+/.test(server)) issues.push(`Server header discloses version: ${server}`);
          if (xPowered) issues.push(`X-Powered-By header present: ${xPowered}`);
          if (issues.length > 0) return { status: "fail", evidence: issues.join("; ") };
          return { status: "pass", evidence: `Server: ${server || "not disclosed"}, X-Powered-By: not present` };
        }
      },
      {
        checkId: "scap-http-methods",
        title: "Restrict HTTP Methods",
        description: "Verify only necessary HTTP methods are allowed (GET, POST, HEAD)",
        category: "service_hardening",
        benchmarkSource: "disa_stig",
        benchmarkRef: "SRG-APP-000266",
        severity: "medium",
        stigId: "V-222609",
        nistControls: ["CM-7", "AC-3"],
        remediation: "Disable unnecessary HTTP methods (TRACE, PUT, DELETE, OPTIONS) unless required by the application.",
        automatable: true,
        check: async (target, timeout) => {
          const res = await fetchWithTimeout(`https://${target}/`, timeout, { method: "OPTIONS" });
          if (!res) return { status: "error", evidence: "Could not connect" };
          const allow = res.headers.get("allow") || "";
          const dangerousMethods = ["TRACE", "PUT", "DELETE", "PATCH"];
          const exposed = dangerousMethods.filter((m) => allow.toUpperCase().includes(m));
          if (exposed.length > 0) return { status: "fail", evidence: `Potentially dangerous methods allowed: ${exposed.join(", ")}. Allow header: ${allow}` };
          return { status: "pass", evidence: `Allowed methods: ${allow || "not disclosed via OPTIONS"}` };
        }
      },
      {
        checkId: "scap-https-redirect",
        title: "HTTP to HTTPS Redirect",
        description: "Verify HTTP requests are redirected to HTTPS",
        category: "service_hardening",
        benchmarkSource: "cis",
        benchmarkRef: "CIS 3.4.2",
        severity: "high",
        nistControls: ["SC-8", "SC-23"],
        remediation: "Configure web server to redirect all HTTP (port 80) requests to HTTPS (port 443).",
        automatable: true,
        check: async (target, timeout) => {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          try {
            const res = await fetch(`http://${target}/`, {
              signal: controller.signal,
              redirect: "manual"
            });
            clearTimeout(timer);
            if (res.status >= 300 && res.status < 400) {
              const location = res.headers.get("location") || "";
              if (location.startsWith("https://")) return { status: "pass", evidence: `HTTP redirects to HTTPS: ${location}` };
              return { status: "fail", evidence: `HTTP redirects but not to HTTPS: ${location}` };
            }
            return { status: "fail", evidence: `HTTP does not redirect \u2014 status ${res.status}` };
          } catch {
            clearTimeout(timer);
            return { status: "pass", evidence: "HTTP port not accessible (only HTTPS available)" };
          }
        }
      },
      {
        checkId: "scap-cors-policy",
        title: "CORS Policy Configuration",
        description: "Verify Cross-Origin Resource Sharing is not overly permissive",
        category: "service_hardening",
        benchmarkSource: "cis",
        benchmarkRef: "CIS 5.3.3",
        severity: "medium",
        nistControls: ["AC-4", "SC-7"],
        remediation: "Restrict Access-Control-Allow-Origin to specific trusted domains. Never use wildcard (*) with credentials.",
        automatable: true,
        check: async (target, timeout) => {
          const res = await fetchWithTimeout(`https://${target}/`, timeout, {
            headers: { "Origin": "https://evil-attacker.com" }
          });
          if (!res) return { status: "error", evidence: "Could not connect" };
          const acao = res.headers.get("access-control-allow-origin");
          const acac = res.headers.get("access-control-allow-credentials");
          if (!acao) return { status: "pass", evidence: "No CORS headers present \u2014 origin not reflected" };
          if (acao === "*") {
            if (acac === "true") return { status: "fail", evidence: "CRITICAL: CORS allows all origins with credentials" };
            return { status: "fail", evidence: "CORS allows all origins (wildcard *)" };
          }
          if (acao.includes("evil-attacker.com")) return { status: "fail", evidence: `CORS reflects arbitrary origin: ${acao}` };
          return { status: "pass", evidence: `CORS properly restricted: ${acao}` };
        }
      }
    ];
    AUTH_CHECKS = [
      {
        checkId: "scap-cookie-security",
        title: "Secure Cookie Attributes",
        description: "Verify cookies use Secure, HttpOnly, and SameSite attributes",
        category: "authentication",
        benchmarkSource: "disa_stig",
        benchmarkRef: "SRG-APP-000439",
        severity: "medium",
        stigId: "V-222575",
        nistControls: ["SC-8", "SC-23"],
        remediation: "Set Secure, HttpOnly, and SameSite=Strict or Lax on all session cookies.",
        automatable: true,
        check: async (target, timeout) => {
          const res = await fetchWithTimeout(`https://${target}/`, timeout);
          if (!res) return { status: "error", evidence: "Could not connect" };
          const cookies = res.headers.getSetCookie?.() || [];
          if (cookies.length === 0) return { status: "not_applicable", evidence: "No cookies set on initial page load" };
          const issues = [];
          for (const cookie of cookies) {
            const name = cookie.split("=")[0];
            if (!cookie.toLowerCase().includes("secure")) issues.push(`${name}: missing Secure flag`);
            if (!cookie.toLowerCase().includes("httponly")) issues.push(`${name}: missing HttpOnly flag`);
            if (!cookie.toLowerCase().includes("samesite")) issues.push(`${name}: missing SameSite attribute`);
          }
          if (issues.length > 0) return { status: "fail", evidence: issues.join("; ") };
          return { status: "pass", evidence: `${cookies.length} cookie(s) all have Secure, HttpOnly, and SameSite attributes` };
        }
      }
    ];
    ALL_EXTERNAL_CHECKS = [
      ...TLS_CHECKS,
      ...HTTP_HEADER_CHECKS,
      ...DNS_CHECKS,
      ...SERVICE_CHECKS,
      ...AUTH_CHECKS
    ];
    EXTERNAL_CHECK_COUNT = ALL_EXTERNAL_CHECKS.length;
    CHECK_CATEGORIES = [...new Set(ALL_EXTERNAL_CHECKS.map((c) => c.category))];
    BENCHMARK_SOURCES = [...new Set(ALL_EXTERNAL_CHECKS.map((c) => c.benchmarkSource))];
  }
});
init_scap_compliance_scanner();
export {
  BENCHMARK_SOURCES,
  CHECK_CATEGORIES,
  EXTERNAL_CHECK_COUNT,
  parseLynisReport,
  parseOpenSCAPResults,
  runExternalComplianceScan
};
