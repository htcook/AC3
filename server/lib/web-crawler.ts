/**
 * Lightweight Web Crawler / Scanner
 *
 * Uses axios + cheerio (no headless browser) to crawl publicly accessible
 * web pages discovered during domain intelligence reconnaissance.
 *
 * Extracts security-relevant metadata:
 * - HTTP response headers (security header analysis & grading)
 * - Technology fingerprinting (server, framework, CMS, JS libs)
 * - Forms & input fields (potential attack surface)
 * - Internal/external links (site map)
 * - Exposed paths (robots.txt, .env, .git, sitemap.xml, security.txt)
 * - Cookie security analysis
 * - TLS certificate info
 */

import axios, { type AxiosResponse } from "axios";
import * as cheerio from "cheerio";
import { URL } from "node:url";
import https from "node:https";
import tls from "node:tls";

// ─── Types ─────────────────────────────────────────────────────────────────

export interface CrawlConfig {
  maxDepth: number;
  maxPages: number;
  timeoutMs: number;
  userAgent: string;
  followRedirects: boolean;
  respectRobotsTxt: boolean;
  checkExposedPaths: boolean;
  checkSecurityTxt: boolean;
  checkSitemap: boolean;
}

export const DEFAULT_CRAWL_CONFIG: CrawlConfig = {
  maxDepth: 2,
  maxPages: 50,
  timeoutMs: 15000,
  userAgent: "AceC3-WebScanner/1.0 (Security Assessment)",
  followRedirects: true,
  respectRobotsTxt: true,
  checkExposedPaths: true,
  checkSecurityTxt: true,
  checkSitemap: true,
};

export interface SecurityHeaderAnalysis {
  present: { name: string; value: string; status: "good" | "warning" }[];
  missing: { name: string; severity: "high" | "medium" | "low"; description: string }[];
  misconfigured: { name: string; value: string; issue: string; severity: "high" | "medium" | "low" }[];
}

export interface DetectedTechnology {
  name: string;
  version?: string;
  category: string;
  confidence: number; // 0-100
  evidence: string;
}

export interface FormInfo {
  action: string;
  method: string;
  inputs: { name: string; type: string; id?: string }[];
  hasFileUpload: boolean;
  hasPasswordField: boolean;
}

export interface ExposedPath {
  path: string;
  status: number;
  type: "sensitive_file" | "directory_listing" | "config_file" | "backup" | "version_control" | "info_disclosure";
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
}

export interface CookieAnalysis {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  domain: string;
  path: string;
  issues: string[];
}

export interface SecurityFinding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  category: string;
  remediation: string;
}

export interface CrawlPageResult {
  url: string;
  finalUrl: string;
  httpStatus: number;
  responseTimeMs: number;
  contentType: string;
  contentLength: number;
  depth: number;
  // Analysis
  securityHeaders: SecurityHeaderAnalysis;
  securityHeaderGrade: string;
  detectedTechnologies: DetectedTechnology[];
  serverHeader: string | null;
  poweredBy: string | null;
  pageTitle: string;
  metaDescription: string;
  internalLinks: string[];
  externalLinks: string[];
  resourceUrls: string[];
  forms: FormInfo[];
  exposedPaths: ExposedPath[];
  robotsTxt: string | null;
  securityTxt: string | null;
  sitemapUrls: string[];
  cookies: CookieAnalysis[];
  tlsInfo: Record<string, unknown> | null;
  findings: SecurityFinding[];
  findingCounts: { critical: number; high: number; medium: number; low: number; info: number };
  rawHeaders: Record<string, string>;
}

export interface CrawlJobResult {
  jobId: string;
  domain: string;
  pages: CrawlPageResult[];
  totalUrlsCrawled: number;
  totalUrlsFailed: number;
  totalFindings: number;
  findingSummary: { critical: number; high: number; medium: number; low: number; info: number };
  technologiesSummary: DetectedTechnology[];
  securityGrade: string;
  startedAt: number;
  completedAt: number;
}

// ─── Security Header Analysis ──────────────────────────────────────────────

const SECURITY_HEADERS = [
  { name: "strict-transport-security", severity: "high" as const, description: "HSTS not set — allows protocol downgrade attacks" },
  { name: "content-security-policy", severity: "high" as const, description: "CSP not set — vulnerable to XSS and injection attacks" },
  { name: "x-frame-options", severity: "medium" as const, description: "X-Frame-Options not set — vulnerable to clickjacking" },
  { name: "x-content-type-options", severity: "medium" as const, description: "X-Content-Type-Options not set — allows MIME sniffing" },
  { name: "referrer-policy", severity: "low" as const, description: "Referrer-Policy not set — may leak sensitive URL data" },
  { name: "permissions-policy", severity: "low" as const, description: "Permissions-Policy not set — browser features not restricted" },
  { name: "x-xss-protection", severity: "low" as const, description: "X-XSS-Protection not set (legacy but still useful for older browsers)" },
  { name: "cross-origin-opener-policy", severity: "low" as const, description: "COOP not set — cross-origin window references allowed" },
  { name: "cross-origin-resource-policy", severity: "low" as const, description: "CORP not set — resources can be loaded cross-origin" },
  { name: "cross-origin-embedder-policy", severity: "low" as const, description: "COEP not set — cross-origin embedding unrestricted" },
];

function analyzeSecurityHeaders(headers: Record<string, string>): SecurityHeaderAnalysis {
  const result: SecurityHeaderAnalysis = { present: [], missing: [], misconfigured: [] };
  const lowerHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    lowerHeaders[k.toLowerCase()] = v;
  }

  for (const hdr of SECURITY_HEADERS) {
    const value = lowerHeaders[hdr.name];
    if (!value) {
      result.missing.push({ name: hdr.name, severity: hdr.severity, description: hdr.description });
      continue;
    }

    // Check for misconfigurations
    let misconfigured = false;
    if (hdr.name === "strict-transport-security") {
      const maxAge = parseInt(value.match(/max-age=(\d+)/)?.[1] || "0", 10);
      if (maxAge < 31536000) {
        result.misconfigured.push({ name: hdr.name, value, issue: `max-age too short (${maxAge}s, recommend ≥31536000)`, severity: "medium" });
        misconfigured = true;
      }
    }
    if (hdr.name === "content-security-policy" && value.includes("unsafe-inline")) {
      result.misconfigured.push({ name: hdr.name, value: value.substring(0, 200), issue: "CSP allows unsafe-inline — weakens XSS protection", severity: "medium" });
      misconfigured = true;
    }
    if (hdr.name === "x-frame-options" && !["deny", "sameorigin"].includes(value.toLowerCase())) {
      result.misconfigured.push({ name: hdr.name, value, issue: `Invalid value (expected DENY or SAMEORIGIN)`, severity: "medium" });
      misconfigured = true;
    }

    if (!misconfigured) {
      result.present.push({ name: hdr.name, value: value.substring(0, 200), status: "good" });
    } else {
      result.present.push({ name: hdr.name, value: value.substring(0, 200), status: "warning" });
    }
  }

  // Check for information disclosure headers
  if (lowerHeaders["server"]) {
    const sv = lowerHeaders["server"];
    if (/\d/.test(sv)) {
      result.misconfigured.push({ name: "server", value: sv, issue: "Server header discloses version information", severity: "low" });
    }
  }
  if (lowerHeaders["x-powered-by"]) {
    result.misconfigured.push({ name: "x-powered-by", value: lowerHeaders["x-powered-by"], issue: "X-Powered-By header discloses technology stack", severity: "low" });
  }

  return result;
}

function gradeSecurityHeaders(analysis: SecurityHeaderAnalysis): string {
  let score = 100;
  for (const m of analysis.missing) {
    if (m.severity === "high") score -= 20;
    else if (m.severity === "medium") score -= 10;
    else score -= 5;
  }
  for (const mc of analysis.misconfigured) {
    if (mc.severity === "high") score -= 15;
    else if (mc.severity === "medium") score -= 8;
    else score -= 3;
  }
  score = Math.max(0, score);
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 70) return "B";
  if (score >= 55) return "C";
  if (score >= 40) return "D";
  return "F";
}

// ─── Technology Detection ──────────────────────────────────────────────────

interface TechPattern {
  name: string;
  category: string;
  patterns: { type: "header" | "meta" | "html" | "script" | "cookie"; regex: RegExp; versionGroup?: number }[];
}

const TECH_PATTERNS: TechPattern[] = [
  // Web servers
  { name: "Nginx", category: "Web Server", patterns: [
    { type: "header", regex: /nginx\/?(\S+)?/i, versionGroup: 1 },
  ]},
  { name: "Apache", category: "Web Server", patterns: [
    { type: "header", regex: /Apache\/?(\S+)?/i, versionGroup: 1 },
  ]},
  { name: "IIS", category: "Web Server", patterns: [
    { type: "header", regex: /Microsoft-IIS\/?(\S+)?/i, versionGroup: 1 },
  ]},
  { name: "Cloudflare", category: "CDN", patterns: [
    { type: "header", regex: /cloudflare/i },
    { type: "cookie", regex: /__cfduid|__cf_bm/i },
  ]},
  { name: "AWS CloudFront", category: "CDN", patterns: [
    { type: "header", regex: /CloudFront/i },
  ]},
  // Frameworks
  { name: "Express.js", category: "Framework", patterns: [
    { type: "header", regex: /Express/i },
  ]},
  { name: "Next.js", category: "Framework", patterns: [
    { type: "header", regex: /__next/i },
    { type: "html", regex: /_next\/static/i },
    { type: "meta", regex: /next-head-count/i },
  ]},
  { name: "React", category: "JavaScript Library", patterns: [
    { type: "html", regex: /react[-.](?:dom|router)|__NEXT_DATA__|data-reactroot/i },
    { type: "script", regex: /react(?:\.production|\.development)/i },
  ]},
  { name: "Vue.js", category: "JavaScript Library", patterns: [
    { type: "html", regex: /data-v-[a-f0-9]+|vue[-.](?:router|resource)/i },
    { type: "script", regex: /vue(?:\.min)?\.js/i },
  ]},
  { name: "Angular", category: "JavaScript Library", patterns: [
    { type: "html", regex: /ng-(?:app|controller|model|version)|angular(?:\.min)?\.js/i },
  ]},
  { name: "jQuery", category: "JavaScript Library", patterns: [
    { type: "script", regex: /jquery[-.](\d+\.\d+(?:\.\d+)?)/i, versionGroup: 1 },
    { type: "html", regex: /jquery(?:\.min)?\.js/i },
  ]},
  // CMS
  { name: "WordPress", category: "CMS", patterns: [
    { type: "html", regex: /wp-content|wp-includes|wp-json/i },
    { type: "meta", regex: /WordPress\s*(\d+\.\d+(?:\.\d+)?)?/i, versionGroup: 1 },
  ]},
  { name: "Drupal", category: "CMS", patterns: [
    { type: "html", regex: /drupal\.js|Drupal\.settings|sites\/default\/files/i },
    { type: "header", regex: /X-Drupal/i },
  ]},
  { name: "Joomla", category: "CMS", patterns: [
    { type: "html", regex: /\/media\/jui\/|\/components\/com_/i },
    { type: "meta", regex: /Joomla/i },
  ]},
  // Analytics
  { name: "Google Analytics", category: "Analytics", patterns: [
    { type: "script", regex: /google-analytics\.com|googletagmanager\.com|gtag/i },
  ]},
  { name: "Google Tag Manager", category: "Analytics", patterns: [
    { type: "html", regex: /googletagmanager\.com\/gtm\.js/i },
  ]},
  // Security
  { name: "reCAPTCHA", category: "Security", patterns: [
    { type: "script", regex: /recaptcha/i },
    { type: "html", regex: /g-recaptcha/i },
  ]},
  { name: "hCaptcha", category: "Security", patterns: [
    { type: "script", regex: /hcaptcha\.com/i },
  ]},
  // E-commerce
  { name: "Shopify", category: "E-commerce", patterns: [
    { type: "html", regex: /cdn\.shopify\.com|Shopify\.theme/i },
  ]},
  { name: "WooCommerce", category: "E-commerce", patterns: [
    { type: "html", regex: /woocommerce|wc-cart/i },
  ]},
  // Hosting / Platform
  { name: "Vercel", category: "Hosting", patterns: [
    { type: "header", regex: /vercel/i },
  ]},
  { name: "Netlify", category: "Hosting", patterns: [
    { type: "header", regex: /netlify/i },
  ]},
  // PHP
  { name: "PHP", category: "Language", patterns: [
    { type: "header", regex: /PHP\/?(\S+)?/i, versionGroup: 1 },
    { type: "cookie", regex: /PHPSESSID/i },
  ]},
  // ASP.NET
  { name: "ASP.NET", category: "Framework", patterns: [
    { type: "header", regex: /ASP\.NET/i },
    { type: "cookie", regex: /ASP\.NET_SessionId|\.ASPXAUTH/i },
  ]},
];

function detectTechnologies(
  headers: Record<string, string>,
  html: string,
  $: cheerio.CheerioAPI,
): DetectedTechnology[] {
  const detected: DetectedTechnology[] = [];
  const seen = new Set<string>();

  const headerStr = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n");
  const scripts = $("script[src]").map((_, el) => $(el).attr("src") || "").get().join("\n");
  const metas = $("meta").map((_, el) => {
    const name = $(el).attr("name") || $(el).attr("property") || "";
    const content = $(el).attr("content") || "";
    return `${name}=${content}`;
  }).get().join("\n");
  const cookieStr = headers["set-cookie"] || "";

  for (const tech of TECH_PATTERNS) {
    if (seen.has(tech.name)) continue;

    for (const pattern of tech.patterns) {
      let source = "";
      switch (pattern.type) {
        case "header": source = headerStr; break;
        case "html": source = html; break;
        case "script": source = scripts; break;
        case "meta": source = metas; break;
        case "cookie": source = cookieStr; break;
      }

      const match = source.match(pattern.regex);
      if (match) {
        const version = pattern.versionGroup ? match[pattern.versionGroup] || undefined : undefined;
        detected.push({
          name: tech.name,
          version,
          category: tech.category,
          confidence: 85,
          evidence: `Matched ${pattern.type}: ${pattern.regex.source}`,
        });
        seen.add(tech.name);
        break;
      }
    }
  }

  return detected;
}

// ─── Exposed Path Checks ───────────────────────────────────────────────────

const EXPOSED_PATHS_TO_CHECK: { path: string; type: ExposedPath["type"]; severity: ExposedPath["severity"]; description: string }[] = [
  { path: "/.env", type: "config_file", severity: "critical", description: "Environment file exposed — may contain credentials" },
  { path: "/.git/HEAD", type: "version_control", severity: "critical", description: "Git repository exposed — source code leakage" },
  { path: "/.git/config", type: "version_control", severity: "critical", description: "Git config exposed — may reveal remote URLs and credentials" },
  { path: "/wp-config.php.bak", type: "backup", severity: "critical", description: "WordPress config backup — contains DB credentials" },
  { path: "/.DS_Store", type: "info_disclosure", severity: "medium", description: "macOS directory metadata exposed" },
  { path: "/server-status", type: "info_disclosure", severity: "high", description: "Apache server-status page exposed" },
  { path: "/phpinfo.php", type: "info_disclosure", severity: "high", description: "PHP info page exposed — reveals server configuration" },
  { path: "/web.config", type: "config_file", severity: "high", description: "IIS web.config exposed — may contain sensitive settings" },
  { path: "/.htaccess", type: "config_file", severity: "medium", description: "Apache .htaccess file accessible" },
  { path: "/crossdomain.xml", type: "config_file", severity: "medium", description: "Flash crossdomain policy — may allow cross-origin access" },
  { path: "/elmah.axd", type: "info_disclosure", severity: "high", description: "ELMAH error log exposed — may reveal stack traces" },
  { path: "/trace.axd", type: "info_disclosure", severity: "high", description: "ASP.NET trace exposed" },
  { path: "/backup/", type: "backup", severity: "high", description: "Backup directory accessible" },
  { path: "/admin/", type: "directory_listing", severity: "medium", description: "Admin panel accessible" },
  { path: "/api/", type: "info_disclosure", severity: "low", description: "API endpoint directory accessible" },
  { path: "/.well-known/security.txt", type: "info_disclosure", severity: "info", description: "Security.txt file present (good practice)" },
  { path: "/sitemap.xml", type: "info_disclosure", severity: "info", description: "Sitemap.xml accessible" },
  { path: "/robots.txt", type: "info_disclosure", severity: "info", description: "Robots.txt accessible" },
  { path: "/swagger-ui.html", type: "info_disclosure", severity: "medium", description: "Swagger API docs exposed" },
  { path: "/api-docs", type: "info_disclosure", severity: "medium", description: "API documentation endpoint exposed" },
  { path: "/.svn/entries", type: "version_control", severity: "critical", description: "SVN repository exposed" },
  { path: "/debug/", type: "info_disclosure", severity: "high", description: "Debug endpoint accessible" },
  { path: "/wp-admin/", type: "directory_listing", severity: "medium", description: "WordPress admin panel accessible" },
  { path: "/wp-login.php", type: "info_disclosure", severity: "low", description: "WordPress login page accessible" },
];

async function checkExposedPaths(
  baseUrl: string,
  config: CrawlConfig,
): Promise<{ paths: ExposedPath[]; robotsTxt: string | null; securityTxt: string | null; sitemapUrls: string[] }> {
  const paths: ExposedPath[] = [];
  let robotsTxt: string | null = null;
  let securityTxt: string | null = null;
  const sitemapUrls: string[] = [];

  const checks = EXPOSED_PATHS_TO_CHECK.map(async (check) => {
    try {
      const url = new URL(check.path, baseUrl).toString();
      const resp = await axios.get(url, {
        timeout: Math.min(config.timeoutMs, 8000),
        maxRedirects: 2,
        validateStatus: () => true,
        headers: { "User-Agent": config.userAgent },
        maxContentLength: 1024 * 512, // 512KB max
      });

      if (resp.status >= 200 && resp.status < 400) {
        const contentType = resp.headers["content-type"] || "";
        // Skip if it's a generic 404 page that returns 200
        const body = typeof resp.data === "string" ? resp.data : "";
        if (body.toLowerCase().includes("not found") || body.toLowerCase().includes("404")) {
          return;
        }

        paths.push({
          path: check.path,
          status: resp.status,
          type: check.type,
          severity: check.severity,
          description: check.description,
        });

        // Capture special files
        if (check.path === "/robots.txt" && contentType.includes("text")) {
          robotsTxt = body.substring(0, 10000);
          // Extract sitemap URLs from robots.txt
          const sitemapMatches = body.matchAll(/Sitemap:\s*(\S+)/gi);
          for (const m of sitemapMatches) {
            sitemapUrls.push(m[1]);
          }
        }
        if (check.path.includes("security.txt") && contentType.includes("text")) {
          securityTxt = body.substring(0, 5000);
        }
        if (check.path === "/sitemap.xml" && contentType.includes("xml")) {
          const urlMatches = body.matchAll(/<loc>\s*(.*?)\s*<\/loc>/gi);
          for (const m of urlMatches) {
            sitemapUrls.push(m[1]);
          }
        }
      }
    } catch {
      // Timeout or connection error — skip
    }
  });

  // Run checks in batches of 5 to avoid overwhelming the target
  for (let i = 0; i < checks.length; i += 5) {
    await Promise.all(checks.slice(i, i + 5));
  }

  return { paths, robotsTxt, securityTxt, sitemapUrls: [...new Set(sitemapUrls)] };
}

// ─── Cookie Analysis ───────────────────────────────────────────────────────

function analyzeCookies(setCookieHeaders: string | string[] | undefined): CookieAnalysis[] {
  if (!setCookieHeaders) return [];
  const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];

  return cookies.map((cookie) => {
    const parts = cookie.split(";").map((p) => p.trim());
    const [nameValue] = parts;
    const name = nameValue?.split("=")[0] || "unknown";
    const lower = cookie.toLowerCase();
    const issues: string[] = [];

    const secure = lower.includes("secure");
    const httpOnly = lower.includes("httponly");
    const sameSiteMatch = lower.match(/samesite=(\w+)/);
    const sameSite = sameSiteMatch ? sameSiteMatch[1] : null;
    const domainMatch = lower.match(/domain=([^;]+)/);
    const domain = domainMatch ? domainMatch[1].trim() : "";
    const pathMatch = lower.match(/path=([^;]+)/);
    const path = pathMatch ? pathMatch[1].trim() : "/";

    if (!secure) issues.push("Missing Secure flag — cookie sent over HTTP");
    if (!httpOnly) issues.push("Missing HttpOnly flag — accessible via JavaScript");
    if (!sameSite || sameSite === "none") issues.push("SameSite=None or missing — vulnerable to CSRF");

    return { name, secure, httpOnly, sameSite, domain, path, issues };
  });
}

// ─── TLS Info ──────────────────────────────────────────────────────────────

async function getTlsInfo(hostname: string): Promise<Record<string, unknown> | null> {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(null), 5000);
    try {
      const socket = tls.connect(443, hostname, { servername: hostname, rejectUnauthorized: false }, () => {
        clearTimeout(timeout);
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        socket.destroy();
        resolve({
          protocol,
          cipher: cipher?.name,
          cipherVersion: cipher?.version,
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          issuer: cert.issuer ? `${cert.issuer.O || ""} ${cert.issuer.CN || ""}`.trim() : null,
          subject: cert.subject ? cert.subject.CN : null,
          subjectAltNames: cert.subjectaltname,
          serialNumber: cert.serialNumber,
          fingerprint256: cert.fingerprint256,
        });
      });
      socket.on("error", () => { clearTimeout(timeout); resolve(null); });
    } catch {
      clearTimeout(timeout);
      resolve(null);
    }
  });
}

// ─── Generate Findings from Analysis ───────────────────────────────────────

function generateFindings(
  headerAnalysis: SecurityHeaderAnalysis,
  cookies: CookieAnalysis[],
  exposedPaths: ExposedPath[],
  technologies: DetectedTechnology[],
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // Header findings
  for (const m of headerAnalysis.missing) {
    findings.push({
      severity: m.severity === "high" ? "high" : m.severity === "medium" ? "medium" : "low",
      title: `Missing Security Header: ${m.name}`,
      description: m.description,
      category: "Security Headers",
      remediation: `Add the ${m.name} header to your HTTP responses.`,
    });
  }
  for (const mc of headerAnalysis.misconfigured) {
    findings.push({
      severity: mc.severity === "high" ? "high" : mc.severity === "medium" ? "medium" : "low",
      title: `Misconfigured Header: ${mc.name}`,
      description: mc.issue,
      category: "Security Headers",
      remediation: `Review and correct the ${mc.name} header configuration.`,
    });
  }

  // Cookie findings
  for (const cookie of cookies) {
    for (const issue of cookie.issues) {
      findings.push({
        severity: issue.includes("Secure") ? "medium" : issue.includes("HttpOnly") ? "medium" : "low",
        title: `Cookie Security Issue: ${cookie.name}`,
        description: issue,
        category: "Cookie Security",
        remediation: `Update cookie "${cookie.name}" to include appropriate security flags.`,
      });
    }
  }

  // Exposed path findings
  for (const ep of exposedPaths) {
    if (ep.severity !== "info") {
      findings.push({
        severity: ep.severity,
        title: `Exposed Path: ${ep.path}`,
        description: ep.description,
        category: "Information Disclosure",
        remediation: `Restrict access to ${ep.path} or remove it from the web server.`,
      });
    }
  }

  // Technology version disclosure
  for (const tech of technologies) {
    if (tech.version) {
      findings.push({
        severity: "info",
        title: `Technology Version Detected: ${tech.name} ${tech.version}`,
        description: `${tech.name} version ${tech.version} detected. Known versions may be targeted by version-specific exploits.`,
        category: "Technology Fingerprint",
        remediation: `Consider hiding version information and ensure ${tech.name} is up to date.`,
      });
    }
  }

  return findings;
}

// ─── Single Page Crawl ─────────────────────────────────────────────────────

export async function crawlPage(
  url: string,
  depth: number,
  config: CrawlConfig,
): Promise<CrawlPageResult | null> {
  const startTime = Date.now();

  try {
    const parsedUrl = new URL(url);
    const response: AxiosResponse = await axios.get(url, {
      timeout: config.timeoutMs,
      maxRedirects: config.followRedirects ? 5 : 0,
      validateStatus: () => true,
      headers: {
        "User-Agent": config.userAgent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
      },
      maxContentLength: 5 * 1024 * 1024, // 5MB max
      responseType: "text",
    });

    const responseTimeMs = Date.now() - startTime;
    const html = typeof response.data === "string" ? response.data : String(response.data);
    const $ = cheerio.load(html);

    // Flatten headers to Record<string, string>
    const rawHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(response.headers)) {
      rawHeaders[k] = Array.isArray(v) ? v.join(", ") : String(v || "");
    }

    // Security headers
    const securityHeaders = analyzeSecurityHeaders(rawHeaders);
    const securityHeaderGrade = gradeSecurityHeaders(securityHeaders);

    // Technology detection
    const detectedTechnologies = detectTechnologies(rawHeaders, html, $);

    // Server info
    const serverHeader = rawHeaders["server"] || null;
    const poweredBy = rawHeaders["x-powered-by"] || null;

    // Page metadata
    const pageTitle = $("title").first().text().trim().substring(0, 512);
    const metaDescription = $('meta[name="description"]').attr("content")?.substring(0, 1000) || "";

    // Links
    const internalLinks: string[] = [];
    const externalLinks: string[] = [];
    $("a[href]").each((_, el) => {
      const href = $(el).attr("href");
      if (!href || href.startsWith("#") || href.startsWith("javascript:") || href.startsWith("mailto:") || href.startsWith("tel:")) return;
      try {
        const linkUrl = new URL(href, url);
        if (linkUrl.hostname === parsedUrl.hostname || linkUrl.hostname.endsWith(`.${parsedUrl.hostname}`)) {
          internalLinks.push(linkUrl.toString());
        } else {
          externalLinks.push(linkUrl.toString());
        }
      } catch { /* invalid URL */ }
    });

    // Resource URLs
    const resourceUrls: string[] = [];
    $("script[src], link[href], img[src]").each((_, el) => {
      const src = $(el).attr("src") || $(el).attr("href");
      if (src) {
        try {
          resourceUrls.push(new URL(src, url).toString());
        } catch { /* invalid URL */ }
      }
    });

    // Forms
    const forms: FormInfo[] = [];
    $("form").each((_, el) => {
      const $form = $(el);
      const inputs = $form.find("input, textarea, select").map((_, inp) => ({
        name: $(inp).attr("name") || "",
        type: $(inp).attr("type") || "text",
        id: $(inp).attr("id"),
      })).get();
      forms.push({
        action: $form.attr("action") || "",
        method: ($form.attr("method") || "GET").toUpperCase(),
        inputs,
        hasFileUpload: inputs.some((i) => i.type === "file"),
        hasPasswordField: inputs.some((i) => i.type === "password"),
      });
    });

    // Cookies
    const cookies = analyzeCookies(response.headers["set-cookie"]);

    // Exposed paths (only for root page)
    let exposedPaths: ExposedPath[] = [];
    let robotsTxt: string | null = null;
    let securityTxt: string | null = null;
    let sitemapUrls: string[] = [];
    if (depth === 0 && config.checkExposedPaths) {
      const pathResult = await checkExposedPaths(`${parsedUrl.protocol}//${parsedUrl.host}`, config);
      exposedPaths = pathResult.paths;
      robotsTxt = pathResult.robotsTxt;
      securityTxt = pathResult.securityTxt;
      sitemapUrls = pathResult.sitemapUrls;
    }

    // TLS info (only for HTTPS root page)
    let tlsInfo: Record<string, unknown> | null = null;
    if (depth === 0 && parsedUrl.protocol === "https:") {
      tlsInfo = await getTlsInfo(parsedUrl.hostname);
    }

    // Generate findings
    const findings = generateFindings(securityHeaders, cookies, exposedPaths, detectedTechnologies);
    const findingCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) findingCounts[f.severity]++;

    return {
      url,
      finalUrl: response.request?.res?.responseUrl || url,
      httpStatus: response.status,
      responseTimeMs,
      contentType: rawHeaders["content-type"] || "",
      contentLength: parseInt(rawHeaders["content-length"] || "0", 10) || html.length,
      depth,
      securityHeaders,
      securityHeaderGrade,
      detectedTechnologies,
      serverHeader,
      poweredBy,
      pageTitle,
      metaDescription,
      internalLinks: [...new Set(internalLinks)].slice(0, 200),
      externalLinks: [...new Set(externalLinks)].slice(0, 100),
      resourceUrls: [...new Set(resourceUrls)].slice(0, 100),
      forms,
      exposedPaths,
      robotsTxt,
      securityTxt,
      sitemapUrls,
      cookies,
      tlsInfo,
      findings,
      findingCounts,
      rawHeaders,
    };
  } catch (err: any) {
    console.error(`[WebCrawler] Failed to crawl ${url}: ${err.message}`);
    return null;
  }
}

// ─── Full Domain Crawl ─────────────────────────────────────────────────────

export async function crawlDomain(
  domain: string,
  seedUrls: string[],
  config: Partial<CrawlConfig> = {},
): Promise<CrawlJobResult> {
  const cfg: CrawlConfig = { ...DEFAULT_CRAWL_CONFIG, ...config };
  const jobId = `crawl_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
  const startedAt = Date.now();

  // Normalize seed URLs
  const seeds = seedUrls.length > 0
    ? seedUrls
    : [`https://${domain}`, `http://${domain}`];

  const visited = new Set<string>();
  const queue: { url: string; depth: number }[] = seeds.map((u) => ({ url: u, depth: 0 }));
  const pages: CrawlPageResult[] = [];
  const allTechnologies: DetectedTechnology[] = [];

  console.log(`[WebCrawler] Starting crawl of ${domain} with ${seeds.length} seed URLs, maxDepth=${cfg.maxDepth}, maxPages=${cfg.maxPages}`);

  while (queue.length > 0 && pages.length < cfg.maxPages) {
    const batch = queue.splice(0, 3); // Process 3 at a time

    const results = await Promise.all(
      batch.map(async ({ url, depth }) => {
        // Normalize URL for dedup
        const normalized = normalizeUrl(url);
        if (visited.has(normalized)) return null;
        visited.add(normalized);

        // Check depth
        if (depth > cfg.maxDepth) return null;

        // Only crawl same domain
        try {
          const parsedUrl = new URL(url);
          if (parsedUrl.hostname !== domain && !parsedUrl.hostname.endsWith(`.${domain}`)) return null;
        } catch { return null; }

        return crawlPage(url, depth, cfg);
      }),
    );

    for (const result of results) {
      if (!result) continue;
      pages.push(result);
      allTechnologies.push(...result.detectedTechnologies);

      // Add internal links to queue
      if (result.depth < cfg.maxDepth) {
        for (const link of result.internalLinks) {
          const normalized = normalizeUrl(link);
          if (!visited.has(normalized) && pages.length + queue.length < cfg.maxPages * 2) {
            queue.push({ url: link, depth: result.depth + 1 });
          }
        }
      }
    }
  }

  // Aggregate findings
  const findingSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let totalFindings = 0;
  for (const page of pages) {
    totalFindings += page.findings.length;
    findingSummary.critical += page.findingCounts.critical;
    findingSummary.high += page.findingCounts.high;
    findingSummary.medium += page.findingCounts.medium;
    findingSummary.low += page.findingCounts.low;
    findingSummary.info += page.findingCounts.info;
  }

  // Deduplicate technologies
  const techMap = new Map<string, DetectedTechnology>();
  for (const tech of allTechnologies) {
    const existing = techMap.get(tech.name);
    if (!existing || (tech.version && !existing.version)) {
      techMap.set(tech.name, tech);
    }
  }

  // Overall security grade (worst page grade)
  const gradeOrder = ["F", "D", "C", "B", "A", "A+"];
  let worstGradeIdx = gradeOrder.length - 1;
  for (const page of pages) {
    const idx = gradeOrder.indexOf(page.securityHeaderGrade);
    if (idx < worstGradeIdx) worstGradeIdx = idx;
  }

  const completedAt = Date.now();
  console.log(`[WebCrawler] Completed crawl of ${domain}: ${pages.length} pages, ${totalFindings} findings in ${completedAt - startedAt}ms`);

  return {
    jobId,
    domain,
    pages,
    totalUrlsCrawled: pages.length,
    totalUrlsFailed: visited.size - pages.length,
    totalFindings,
    findingSummary,
    technologiesSummary: [...techMap.values()],
    securityGrade: gradeOrder[worstGradeIdx] || "F",
    startedAt,
    completedAt,
  };
}

// ─── Quick Single-URL Scan ─────────────────────────────────────────────────

export async function quickScan(url: string): Promise<CrawlPageResult | null> {
  return crawlPage(url, 0, {
    ...DEFAULT_CRAWL_CONFIG,
    maxDepth: 0,
    maxPages: 1,
  });
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function normalizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    // Remove trailing slash, fragment, and common tracking params
    parsed.hash = "";
    parsed.searchParams.delete("utm_source");
    parsed.searchParams.delete("utm_medium");
    parsed.searchParams.delete("utm_campaign");
    let path = parsed.pathname.replace(/\/+$/, "") || "/";
    return `${parsed.protocol}//${parsed.host}${path}${parsed.search}`;
  } catch {
    return url;
  }
}
