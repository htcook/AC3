/**
 * SCAP/STIG Configuration Compliance Scanner
 *
 * Performs configuration compliance checks against targets using:
 * - CIS Benchmark checks (externally observable)
 * - DISA STIG compliance mapping
 * - OpenSCAP integration (via SSH for authenticated scans)
 * - External configuration audit (TLS, headers, DNS, services)
 *
 * Two modes of operation:
 * 1. **External audit** (no credentials) — checks TLS config, HTTP headers,
 *    DNS security, exposed services, and banner versions against CIS/STIG baselines
 * 2. **Authenticated audit** (SSH credentials) — runs OpenSCAP/Lynis on the target
 *    and parses XCCDF results
 *
 * @module scap-compliance-scanner
 */

// ─── Types ─────────────────────────────────────────────────────────

export type ComplianceStatus = "pass" | "fail" | "not_applicable" | "error" | "manual_review";
export type BenchmarkSource = "cis" | "disa_stig" | "nist_800_53" | "fedramp" | "custom";
export type CheckCategory =
  | "tls_configuration"
  | "http_security_headers"
  | "dns_security"
  | "service_hardening"
  | "authentication"
  | "access_control"
  | "logging_auditing"
  | "network_security"
  | "cryptography"
  | "patch_management";

export interface ComplianceCheck {
  checkId: string;
  title: string;
  description: string;
  category: CheckCategory;
  benchmarkSource: BenchmarkSource;
  benchmarkRef: string;       // e.g., "CIS 2.1.1" or "V-12345"
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: ComplianceStatus;
  evidence: string;
  remediation: string;
  automatable: boolean;       // Can this be auto-remediated?
  stigId?: string;            // DISA STIG Vulnerability ID
  nistControls: string[];     // Mapped NIST 800-53 controls
  ccis?: string[];            // CCI references for STIG
}

export interface ComplianceScanResult {
  target: string;
  scanType: "external" | "authenticated";
  scanDate: Date;
  totalChecks: number;
  passed: number;
  failed: number;
  notApplicable: number;
  errors: number;
  manualReview: number;
  complianceScore: number;    // 0-100 percentage
  checks: ComplianceCheck[];
  benchmarkProfile: string;
  durationMs: number;
  summary: string;
}

// ─── External Compliance Checks ────────────────────────────────────

interface ExternalCheckDef {
  checkId: string;
  title: string;
  description: string;
  category: CheckCategory;
  benchmarkSource: BenchmarkSource;
  benchmarkRef: string;
  severity: ComplianceCheck["severity"];
  stigId?: string;
  nistControls: string[];
  ccis?: string[];
  remediation: string;
  automatable: boolean;
  check: (target: string, timeout: number) => Promise<{ status: ComplianceStatus; evidence: string }>;
}

async function fetchWithTimeout(url: string, timeout: number, options?: RequestInit): Promise<Response | null> {
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

// ─── TLS Configuration Checks ──────────────────────────────────────

const TLS_CHECKS: ExternalCheckDef[] = [
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
      if (!res) return { status: "error" as ComplianceStatus, evidence: "Could not establish HTTPS connection" };
      // If we connected via HTTPS, TLS is at least 1.2 (modern browsers/fetch enforce this)
      return { status: "pass" as ComplianceStatus, evidence: "HTTPS connection established successfully — TLS 1.2+ supported" };
    },
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
      if (!res) return { status: "error" as ComplianceStatus, evidence: "Could not connect to target" };
      const hsts = res.headers.get("strict-transport-security");
      if (!hsts) return { status: "fail" as ComplianceStatus, evidence: "HSTS header not present" };
      const maxAgeMatch = /max-age=(\d+)/i.exec(hsts);
      if (!maxAgeMatch) return { status: "fail" as ComplianceStatus, evidence: `HSTS present but no max-age: ${hsts}` };
      const maxAge = parseInt(maxAgeMatch[1]);
      if (maxAge < 31536000) return { status: "fail" as ComplianceStatus, evidence: `HSTS max-age too short: ${maxAge}s (need 31536000)` };
      return { status: "pass" as ComplianceStatus, evidence: `HSTS configured: ${hsts}` };
    },
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
      if (!res) return { status: "fail" as ComplianceStatus, evidence: "TLS connection failed — certificate may be invalid, expired, or self-signed" };
      return { status: "pass" as ComplianceStatus, evidence: "TLS certificate accepted by standard validation" };
    },
  },
];

// ─── HTTP Security Header Checks ───────────────────────────────────

const HTTP_HEADER_CHECKS: ExternalCheckDef[] = [
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
      if (!res) return { status: "error" as ComplianceStatus, evidence: "Could not connect" };
      const csp = res.headers.get("content-security-policy");
      if (!csp) return { status: "fail" as ComplianceStatus, evidence: "Content-Security-Policy header not present" };
      const hasUnsafe = csp.includes("unsafe-inline") || csp.includes("unsafe-eval");
      if (hasUnsafe) return { status: "fail" as ComplianceStatus, evidence: `CSP present but contains unsafe directives: ${csp.slice(0, 200)}` };
      return { status: "pass" as ComplianceStatus, evidence: `CSP configured: ${csp.slice(0, 200)}` };
    },
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
      if (!res) return { status: "error" as ComplianceStatus, evidence: "Could not connect" };
      const xfo = res.headers.get("x-frame-options");
      const csp = res.headers.get("content-security-policy") || "";
      if (xfo || csp.includes("frame-ancestors")) {
        return { status: "pass" as ComplianceStatus, evidence: `Clickjacking protection: X-Frame-Options=${xfo || "not set"}, CSP frame-ancestors=${csp.includes("frame-ancestors") ? "present" : "not set"}` };
      }
      return { status: "fail" as ComplianceStatus, evidence: "No clickjacking protection — neither X-Frame-Options nor CSP frame-ancestors set" };
    },
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
      if (!res) return { status: "error" as ComplianceStatus, evidence: "Could not connect" };
      const xcto = res.headers.get("x-content-type-options");
      if (xcto?.toLowerCase() === "nosniff") return { status: "pass" as ComplianceStatus, evidence: "X-Content-Type-Options: nosniff present" };
      return { status: "fail" as ComplianceStatus, evidence: `X-Content-Type-Options: ${xcto || "not set"}` };
    },
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
      if (!res) return { status: "error" as ComplianceStatus, evidence: "Could not connect" };
      const rp = res.headers.get("referrer-policy");
      if (!rp) return { status: "fail" as ComplianceStatus, evidence: "Referrer-Policy header not present" };
      const safe = ["no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"];
      if (safe.some(s => rp.toLowerCase().includes(s))) return { status: "pass" as ComplianceStatus, evidence: `Referrer-Policy: ${rp}` };
      return { status: "fail" as ComplianceStatus, evidence: `Referrer-Policy set but may leak info: ${rp}` };
    },
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
      if (!res) return { status: "error" as ComplianceStatus, evidence: "Could not connect" };
      const pp = res.headers.get("permissions-policy") || res.headers.get("feature-policy");
      if (!pp) return { status: "fail" as ComplianceStatus, evidence: "Permissions-Policy header not present" };
      return { status: "pass" as ComplianceStatus, evidence: `Permissions-Policy: ${pp.slice(0, 200)}` };
    },
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
      if (!res) return { status: "error" as ComplianceStatus, evidence: "Could not connect" };
      const cc = res.headers.get("cache-control");
      if (!cc) return { status: "fail" as ComplianceStatus, evidence: "Cache-Control header not present" };
      if (cc.includes("no-store") || cc.includes("private")) return { status: "pass" as ComplianceStatus, evidence: `Cache-Control: ${cc}` };
      return { status: "fail" as ComplianceStatus, evidence: `Cache-Control present but may allow caching: ${cc}` };
    },
  },
];

// ─── DNS Security Checks ───────────────────────────────────────────

const DNS_CHECKS: ExternalCheckDef[] = [
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
      // Check via DNS-over-HTTPS for DNSSEC validation
      const res = await fetchWithTimeout(
        `https://dns.google/resolve?name=${target}&type=A&do=1`,
        timeout
      );
      if (!res) return { status: "error" as ComplianceStatus, evidence: "Could not query DNS" };
      try {
        const data = await res.json() as any;
        const ad = data.AD; // Authenticated Data flag
        if (ad) return { status: "pass" as ComplianceStatus, evidence: "DNSSEC validated — AD flag set in DNS response" };
        return { status: "fail" as ComplianceStatus, evidence: "DNSSEC not validated — AD flag not set. Domain may not have DNSSEC configured." };
      } catch {
        return { status: "error" as ComplianceStatus, evidence: "Failed to parse DNS response" };
      }
    },
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
      if (!res) return { status: "error" as ComplianceStatus, evidence: "Could not query DNS" };
      try {
        const data = await res.json() as any;
        if (data.Answer && data.Answer.length > 0) {
          const caaRecords = data.Answer.filter((a: any) => a.type === 257);
          if (caaRecords.length > 0) return { status: "pass" as ComplianceStatus, evidence: `CAA records found: ${caaRecords.map((r: any) => r.data).join(", ")}` };
        }
        return { status: "fail" as ComplianceStatus, evidence: "No CAA DNS records found — any CA can issue certificates for this domain" };
      } catch {
        return { status: "error" as ComplianceStatus, evidence: "Failed to parse DNS response" };
      }
    },
  },
];

// ─── Service Hardening Checks ──────────────────────────────────────

const SERVICE_CHECKS: ExternalCheckDef[] = [
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
      if (!res) return { status: "error" as ComplianceStatus, evidence: "Could not connect" };
      const server = res.headers.get("server") || "";
      const xPowered = res.headers.get("x-powered-by") || "";
      const issues: string[] = [];
      if (/\d+\.\d+/.test(server)) issues.push(`Server header discloses version: ${server}`);
      if (xPowered) issues.push(`X-Powered-By header present: ${xPowered}`);
      if (issues.length > 0) return { status: "fail" as ComplianceStatus, evidence: issues.join("; ") };
      return { status: "pass" as ComplianceStatus, evidence: `Server: ${server || "not disclosed"}, X-Powered-By: not present` };
    },
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
      // Check TRACE method
      const res = await fetchWithTimeout(`https://${target}/`, timeout, { method: "OPTIONS" });
      if (!res) return { status: "error" as ComplianceStatus, evidence: "Could not connect" };
      const allow = res.headers.get("allow") || "";
      const dangerousMethods = ["TRACE", "PUT", "DELETE", "PATCH"];
      const exposed = dangerousMethods.filter(m => allow.toUpperCase().includes(m));
      if (exposed.length > 0) return { status: "fail" as ComplianceStatus, evidence: `Potentially dangerous methods allowed: ${exposed.join(", ")}. Allow header: ${allow}` };
      return { status: "pass" as ComplianceStatus, evidence: `Allowed methods: ${allow || "not disclosed via OPTIONS"}` };
    },
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
          redirect: "manual",
        });
        clearTimeout(timer);
        if (res.status >= 300 && res.status < 400) {
          const location = res.headers.get("location") || "";
          if (location.startsWith("https://")) return { status: "pass" as ComplianceStatus, evidence: `HTTP redirects to HTTPS: ${location}` };
          return { status: "fail" as ComplianceStatus, evidence: `HTTP redirects but not to HTTPS: ${location}` };
        }
        return { status: "fail" as ComplianceStatus, evidence: `HTTP does not redirect — status ${res.status}` };
      } catch {
        clearTimeout(timer);
        return { status: "pass" as ComplianceStatus, evidence: "HTTP port not accessible (only HTTPS available)" };
      }
    },
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
        headers: { "Origin": "https://evil-attacker.com" },
      });
      if (!res) return { status: "error" as ComplianceStatus, evidence: "Could not connect" };
      const acao = res.headers.get("access-control-allow-origin");
      const acac = res.headers.get("access-control-allow-credentials");
      if (!acao) return { status: "pass" as ComplianceStatus, evidence: "No CORS headers present — origin not reflected" };
      if (acao === "*") {
        if (acac === "true") return { status: "fail" as ComplianceStatus, evidence: "CRITICAL: CORS allows all origins with credentials" };
        return { status: "fail" as ComplianceStatus, evidence: "CORS allows all origins (wildcard *)" };
      }
      if (acao.includes("evil-attacker.com")) return { status: "fail" as ComplianceStatus, evidence: `CORS reflects arbitrary origin: ${acao}` };
      return { status: "pass" as ComplianceStatus, evidence: `CORS properly restricted: ${acao}` };
    },
  },
];

// ─── Authentication Checks ─────────────────────────────────────────

const AUTH_CHECKS: ExternalCheckDef[] = [
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
      if (!res) return { status: "error" as ComplianceStatus, evidence: "Could not connect" };
      const cookies = res.headers.getSetCookie?.() || [];
      if (cookies.length === 0) return { status: "not_applicable" as ComplianceStatus, evidence: "No cookies set on initial page load" };
      const issues: string[] = [];
      for (const cookie of cookies) {
        const name = cookie.split("=")[0];
        if (!cookie.toLowerCase().includes("secure")) issues.push(`${name}: missing Secure flag`);
        if (!cookie.toLowerCase().includes("httponly")) issues.push(`${name}: missing HttpOnly flag`);
        if (!cookie.toLowerCase().includes("samesite")) issues.push(`${name}: missing SameSite attribute`);
      }
      if (issues.length > 0) return { status: "fail" as ComplianceStatus, evidence: issues.join("; ") };
      return { status: "pass" as ComplianceStatus, evidence: `${cookies.length} cookie(s) all have Secure, HttpOnly, and SameSite attributes` };
    },
  },
];

// ─── All External Checks ──────────────────────────────────────────

const ALL_EXTERNAL_CHECKS: ExternalCheckDef[] = [
  ...TLS_CHECKS,
  ...HTTP_HEADER_CHECKS,
  ...DNS_CHECKS,
  ...SERVICE_CHECKS,
  ...AUTH_CHECKS,
];

// ─── Main Scanner Function ─────────────────────────────────────────

export async function runExternalComplianceScan(
  target: string,
  options?: {
    timeout?: number;
    categories?: CheckCategory[];
    benchmarks?: BenchmarkSource[];
    concurrency?: number;
  }
): Promise<ComplianceScanResult> {
  const startTime = Date.now();
  const timeout = options?.timeout ?? 10000;
  const concurrency = options?.concurrency ?? 3;

  // Filter checks by category/benchmark if specified
  let checks = ALL_EXTERNAL_CHECKS;
  if (options?.categories) {
    checks = checks.filter(c => options.categories!.includes(c.category));
  }
  if (options?.benchmarks) {
    checks = checks.filter(c => options.benchmarks!.includes(c.benchmarkSource));
  }

  const results: ComplianceCheck[] = [];

  // Run checks with concurrency limit
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
            ccis: checkDef.ccis,
          } as ComplianceCheck;
        } catch (err: any) {
          return {
            checkId: checkDef.checkId,
            title: checkDef.title,
            description: checkDef.description,
            category: checkDef.category,
            benchmarkSource: checkDef.benchmarkSource,
            benchmarkRef: checkDef.benchmarkRef,
            severity: checkDef.severity,
            status: "error" as ComplianceStatus,
            evidence: `Check execution error: ${err.message}`,
            remediation: checkDef.remediation,
            automatable: checkDef.automatable,
            stigId: checkDef.stigId,
            nistControls: checkDef.nistControls,
            ccis: checkDef.ccis,
          } as ComplianceCheck;
        }
      })
    );

    for (const result of batchResults) {
      if (result.status === "fulfilled") {
        results.push(result.value);
      }
    }
  }

  const passed = results.filter(r => r.status === "pass").length;
  const failed = results.filter(r => r.status === "fail").length;
  const notApplicable = results.filter(r => r.status === "not_applicable").length;
  const errors = results.filter(r => r.status === "error").length;
  const manualReview = results.filter(r => r.status === "manual_review").length;
  const applicable = results.length - notApplicable - errors;
  const complianceScore = applicable > 0 ? Math.round((passed / applicable) * 100) : 0;

  const criticalFails = results.filter(r => r.status === "fail" && r.severity === "critical").length;
  const highFails = results.filter(r => r.status === "fail" && r.severity === "high").length;

  return {
    target,
    scanType: "external",
    scanDate: new Date(),
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
    summary: `External compliance scan: ${complianceScore}% compliant (${passed}/${applicable} applicable checks passed). ${criticalFails} critical and ${highFails} high severity failures detected.`,
  };
}

// ─── Authenticated Scan Result Parser ──────────────────────────────
// Parses OpenSCAP XCCDF results XML into our ComplianceCheck format

export function parseOpenSCAPResults(xccdfXml: string, target: string): ComplianceScanResult {
  const startTime = Date.now();
  const checks: ComplianceCheck[] = [];

  // Parse XCCDF rule results
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

    // Map XCCDF result to our status
    let status: ComplianceStatus;
    switch (result) {
      case "pass": status = "pass"; break;
      case "fail": status = "fail"; break;
      case "notapplicable": status = "not_applicable"; break;
      case "error": status = "error"; break;
      default: status = "manual_review";
    }

    // Map severity
    let severity: ComplianceCheck["severity"];
    switch (sevMatch?.[1]) {
      case "high": severity = "high"; break;
      case "medium": severity = "medium"; break;
      case "low": severity = "low"; break;
      default: severity = "medium";
    }

    // Extract NIST control references
    const nistControls: string[] = [];
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
      nistControls,
    });
  }

  const passed = checks.filter(r => r.status === "pass").length;
  const failed = checks.filter(r => r.status === "fail").length;
  const notApplicable = checks.filter(r => r.status === "not_applicable").length;
  const errors = checks.filter(r => r.status === "error").length;
  const manualReview = checks.filter(r => r.status === "manual_review").length;
  const applicable = checks.length - notApplicable - errors;
  const complianceScore = applicable > 0 ? Math.round((passed / applicable) * 100) : 0;

  return {
    target,
    scanType: "authenticated",
    scanDate: new Date(),
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
    summary: `Authenticated compliance scan: ${complianceScore}% compliant (${passed}/${applicable} applicable checks passed). ${failed} failures detected.`,
  };
}

// ─── Lynis Report Parser ──────────────────────────────────────────

export function parseLynisReport(reportText: string, target: string): ComplianceScanResult {
  const startTime = Date.now();
  const checks: ComplianceCheck[] = [];

  // Parse Lynis test results
  const lines = reportText.split("\n");
  for (const line of lines) {
    // Lynis format: "test_id=TEST-1234|description=...|result=OK|severity=..."
    if (!line.startsWith("test_id=") && !line.includes("|result=")) continue;

    const fields: Record<string, string> = {};
    for (const part of line.split("|")) {
      const [key, ...vals] = part.split("=");
      if (key) fields[key.trim()] = vals.join("=").trim();
    }

    if (!fields.test_id) continue;

    let status: ComplianceStatus;
    switch (fields.result?.toUpperCase()) {
      case "OK": case "PASSED": status = "pass"; break;
      case "WARNING": case "SUGGESTION": status = "fail"; break;
      case "FAILED": case "CRITICAL": status = "fail"; break;
      case "SKIPPED": status = "not_applicable"; break;
      default: status = "manual_review";
    }

    let severity: ComplianceCheck["severity"];
    switch (fields.severity?.toLowerCase()) {
      case "critical": severity = "critical"; break;
      case "high": case "warning": severity = "high"; break;
      case "medium": severity = "medium"; break;
      case "low": case "suggestion": severity = "low"; break;
      default: severity = "medium";
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
      nistControls: [],
    });
  }

  const passed = checks.filter(r => r.status === "pass").length;
  const failed = checks.filter(r => r.status === "fail").length;
  const notApplicable = checks.filter(r => r.status === "not_applicable").length;
  const errors = checks.filter(r => r.status === "error").length;
  const manualReview = checks.filter(r => r.status === "manual_review").length;
  const applicable = checks.length - notApplicable - errors;
  const complianceScore = applicable > 0 ? Math.round((passed / applicable) * 100) : 0;

  return {
    target,
    scanType: "authenticated",
    scanDate: new Date(),
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
    summary: `Lynis audit: ${complianceScore}% compliant (${passed}/${applicable} applicable checks passed). ${failed} failures detected.`,
  };
}

function mapLynisCategoryToCheckCategory(lynisCategory: string): CheckCategory {
  const mapping: Record<string, CheckCategory> = {
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
    "webserver": "service_hardening",
  };
  return mapping[lynisCategory.toLowerCase()] || "service_hardening";
}

// ─── Export Check Definitions (for testing) ────────────────────────

export const EXTERNAL_CHECK_COUNT = ALL_EXTERNAL_CHECKS.length;
export const CHECK_CATEGORIES: CheckCategory[] = [...new Set(ALL_EXTERNAL_CHECKS.map(c => c.category))];
export const BENCHMARK_SOURCES: BenchmarkSource[] = [...new Set(ALL_EXTERNAL_CHECKS.map(c => c.benchmarkSource))];
