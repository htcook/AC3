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
  userAgent: "AC3-WebScanner/1.0 (Security Assessment)",
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
  /** cpe is the CPE 2.3 product name for NVD/KEV matching (e.g. "apache:http_server") */
  cpe?: string;
  patterns: { type: "header" | "meta" | "html" | "script" | "cookie" | "url"; regex: RegExp; versionGroup?: number; confidence?: number }[];
}

// ─── Comprehensive Technology Fingerprinting Patterns ─────────────────────
// Inspired by Wappalyzer's open-source pattern database.
// Each pattern includes version extraction groups where possible.
// Confidence levels: header=95, cookie=90, html/script=85, meta=80, url=75

const TECH_PATTERNS: TechPattern[] = [
  // ═══ Web Servers ═══
  { name: "Nginx", category: "Web Server", cpe: "nginx:nginx", patterns: [
    { type: "header", regex: /server:\s*nginx\/?([\d.]+)?/i, versionGroup: 1, confidence: 95 },
    { type: "header", regex: /nginx\/?([\d.]+)?/i, versionGroup: 1, confidence: 90 },
  ]},
  { name: "Apache HTTP Server", category: "Web Server", cpe: "apache:http_server", patterns: [
    { type: "header", regex: /server:\s*Apache\/?([\d.]+)?/i, versionGroup: 1, confidence: 95 },
    { type: "header", regex: /Apache\/?([\d.]+)?/i, versionGroup: 1, confidence: 90 },
  ]},
  { name: "Microsoft IIS", category: "Web Server", cpe: "microsoft:internet_information_services", patterns: [
    { type: "header", regex: /Microsoft-IIS\/?([\d.]+)?/i, versionGroup: 1, confidence: 95 },
  ]},
  { name: "LiteSpeed", category: "Web Server", cpe: "litespeedtech:litespeed_web_server", patterns: [
    { type: "header", regex: /LiteSpeed\/?([\d.]+)?/i, versionGroup: 1, confidence: 95 },
  ]},
  { name: "Caddy", category: "Web Server", cpe: "caddyserver:caddy", patterns: [
    { type: "header", regex: /Caddy/i, confidence: 90 },
  ]},
  { name: "OpenResty", category: "Web Server", cpe: "openresty:openresty", patterns: [
    { type: "header", regex: /openresty\/?([\d.]+)?/i, versionGroup: 1, confidence: 95 },
  ]},
  { name: "Tomcat", category: "Web Server", cpe: "apache:tomcat", patterns: [
    { type: "header", regex: /Apache-Coyote\/?([\d.]+)?/i, versionGroup: 1, confidence: 90 },
    { type: "header", regex: /Tomcat\/?([\d.]+)?/i, versionGroup: 1, confidence: 90 },
    { type: "html", regex: /Apache Tomcat\/?([\d.]+)?/i, versionGroup: 1, confidence: 85 },
  ]},
  { name: "Gunicorn", category: "Web Server", patterns: [
    { type: "header", regex: /gunicorn\/?([\d.]+)?/i, versionGroup: 1, confidence: 95 },
  ]},
  { name: "Envoy", category: "Web Server", patterns: [
    { type: "header", regex: /envoy/i, confidence: 90 },
  ]},

  // ═══ CDN / Edge ═══
  { name: "Cloudflare", category: "CDN", patterns: [
    { type: "header", regex: /server:\s*cloudflare/i, confidence: 95 },
    { type: "header", regex: /cf-ray/i, confidence: 95 },
    { type: "cookie", regex: /__cfduid|__cf_bm|cf_clearance/i, confidence: 90 },
  ]},
  { name: "AWS CloudFront", category: "CDN", patterns: [
    { type: "header", regex: /CloudFront/i, confidence: 95 },
    { type: "header", regex: /x-amz-cf-id/i, confidence: 95 },
  ]},
  { name: "Fastly", category: "CDN", patterns: [
    { type: "header", regex: /x-served-by:.*cache/i, confidence: 85 },
    { type: "header", regex: /via:.*varnish/i, confidence: 75 },
    { type: "header", regex: /x-fastly-request-id/i, confidence: 95 },
  ]},
  { name: "Akamai", category: "CDN", patterns: [
    { type: "header", regex: /x-akamai/i, confidence: 95 },
    { type: "header", regex: /akamai/i, confidence: 85 },
  ]},
  { name: "Varnish", category: "Cache", patterns: [
    { type: "header", regex: /varnish\/?([\d.]+)?/i, versionGroup: 1, confidence: 90 },
    { type: "header", regex: /x-varnish/i, confidence: 90 },
  ]},
  { name: "KeyCDN", category: "CDN", patterns: [
    { type: "header", regex: /keycdn/i, confidence: 90 },
  ]},
  { name: "StackPath", category: "CDN", patterns: [
    { type: "header", regex: /stackpath/i, confidence: 90 },
  ]},
  { name: "Sucuri", category: "CDN", patterns: [
    { type: "header", regex: /sucuri/i, confidence: 90 },
    { type: "header", regex: /x-sucuri-id/i, confidence: 95 },
  ]},

  // ═══ Languages / Runtimes ═══
  { name: "PHP", category: "Language", cpe: "php:php", patterns: [
    { type: "header", regex: /x-powered-by:\s*PHP\/?([\d.]+)?/i, versionGroup: 1, confidence: 95 },
    { type: "header", regex: /PHP\/?([\d.]+)/i, versionGroup: 1, confidence: 90 },
    { type: "cookie", regex: /PHPSESSID/i, confidence: 85 },
    { type: "html", regex: /\.php(?:\?|"|\'|\s)/i, confidence: 70 },
  ]},
  { name: "Python", category: "Language", cpe: "python:python", patterns: [
    { type: "header", regex: /Python\/?([\d.]+)?/i, versionGroup: 1, confidence: 85 },
    { type: "header", regex: /WSGIServer/i, confidence: 80 },
  ]},
  { name: "Node.js", category: "Language", cpe: "nodejs:node.js", patterns: [
    { type: "header", regex: /x-powered-by:\s*Express/i, confidence: 85 },
  ]},
  { name: "Ruby", category: "Language", patterns: [
    { type: "header", regex: /x-powered-by:\s*Phusion Passenger/i, confidence: 85 },
    { type: "header", regex: /x-runtime/i, confidence: 75 },
  ]},
  { name: "ASP.NET", category: "Framework", cpe: "microsoft:asp.net", patterns: [
    { type: "header", regex: /x-powered-by:\s*ASP\.NET/i, confidence: 95 },
    { type: "header", regex: /x-aspnet-version:\s*([\d.]+)/i, versionGroup: 1, confidence: 95 },
    { type: "header", regex: /x-aspnetmvc-version:\s*([\d.]+)/i, versionGroup: 1, confidence: 95 },
    { type: "cookie", regex: /ASP\.NET_SessionId|\.ASPXAUTH/i, confidence: 90 },
    { type: "html", regex: /__VIEWSTATE|__EVENTVALIDATION/i, confidence: 85 },
  ]},
  { name: "Java", category: "Language", cpe: "oracle:jdk", patterns: [
    { type: "header", regex: /x-powered-by:\s*(?:JSP|Servlet|JSF)\/?([\d.]+)?/i, versionGroup: 1, confidence: 90 },
    { type: "cookie", regex: /JSESSIONID/i, confidence: 85 },
    { type: "html", regex: /\.jsp(?:\?|"|\'|\s)/i, confidence: 75 },
  ]},
  { name: "Go", category: "Language", patterns: [
    { type: "header", regex: /x-powered-by:\s*Go/i, confidence: 85 },
  ]},
  { name: "Perl", category: "Language", cpe: "perl:perl", patterns: [
    { type: "header", regex: /mod_perl\/?([\d.]+)?/i, versionGroup: 1, confidence: 90 },
  ]},

  // ═══ JavaScript Frameworks ═══
  { name: "React", category: "JavaScript Framework", patterns: [
    { type: "html", regex: /data-reactroot|data-reactid|__NEXT_DATA__/i, confidence: 90 },
    { type: "script", regex: /react(?:\.production|\.development)\.min\.js/i, confidence: 90 },
    { type: "script", regex: /react-dom[-.]([\d.]+)/i, versionGroup: 1, confidence: 85 },
    { type: "html", regex: /react[-.]dom[-.]([\d.]+)/i, versionGroup: 1, confidence: 85 },
  ]},
  { name: "Vue.js", category: "JavaScript Framework", patterns: [
    { type: "html", regex: /data-v-[a-f0-9]{6,}/i, confidence: 90 },
    { type: "script", regex: /vue(?:\.min)?\.js/i, confidence: 85 },
    { type: "script", regex: /vue@([\d.]+)/i, versionGroup: 1, confidence: 90 },
    { type: "html", regex: /vue[-.]([\d.]+)/i, versionGroup: 1, confidence: 80 },
    { type: "html", regex: /vue[-.](?:router|resource)/i, confidence: 85 },
  ]},
  { name: "Angular", category: "JavaScript Framework", patterns: [
    { type: "html", regex: /ng-version="([\d.]+)"/i, versionGroup: 1, confidence: 95 },
    { type: "html", regex: /ng-app|ng-controller|ng-model/i, confidence: 85 },
    { type: "script", regex: /angular(?:\.min)?\.js/i, confidence: 85 },
    { type: "script", regex: /angular[-@]([\d.]+)/i, versionGroup: 1, confidence: 90 },
  ]},
  { name: "Svelte", category: "JavaScript Framework", patterns: [
    { type: "html", regex: /svelte-[a-z0-9]+|__svelte/i, confidence: 85 },
    { type: "script", regex: /svelte/i, confidence: 75 },
  ]},
  { name: "Ember.js", category: "JavaScript Framework", patterns: [
    { type: "html", regex: /ember-view|data-ember/i, confidence: 90 },
    { type: "script", regex: /ember(?:\.min)?\.js/i, confidence: 85 },
  ]},
  { name: "Backbone.js", category: "JavaScript Framework", patterns: [
    { type: "script", regex: /backbone(?:\.min)?\.js/i, confidence: 85 },
    { type: "script", regex: /backbone[-.]([\d.]+)/i, versionGroup: 1, confidence: 85 },
  ]},
  { name: "Alpine.js", category: "JavaScript Framework", patterns: [
    { type: "html", regex: /x-data|x-bind|x-on|x-show/i, confidence: 80 },
    { type: "script", regex: /alpinejs|alpine(?:\.min)?\.js/i, confidence: 85 },
  ]},
  { name: "Preact", category: "JavaScript Framework", patterns: [
    { type: "script", regex: /preact(?:\.min)?\.js/i, confidence: 85 },
    { type: "script", regex: /preact[-@]([\d.]+)/i, versionGroup: 1, confidence: 90 },
  ]},
  { name: "Stimulus", category: "JavaScript Framework", patterns: [
    { type: "html", regex: /data-controller|data-action|data-target/i, confidence: 75 },
    { type: "script", regex: /stimulus(?:\.min)?\.js/i, confidence: 85 },
  ]},
  { name: "HTMX", category: "JavaScript Framework", patterns: [
    { type: "html", regex: /hx-get|hx-post|hx-trigger|hx-swap/i, confidence: 90 },
    { type: "script", regex: /htmx(?:\.min)?\.js/i, confidence: 90 },
    { type: "script", regex: /htmx\.org@([\d.]+)/i, versionGroup: 1, confidence: 95 },
  ]},

  // ═══ Full-Stack / Meta Frameworks ═══
  { name: "Next.js", category: "Framework", patterns: [
    { type: "html", regex: /_next\/static/i, confidence: 95 },
    { type: "html", regex: /__NEXT_DATA__/i, confidence: 95 },
    { type: "header", regex: /x-nextjs-cache/i, confidence: 95 },
    { type: "meta", regex: /next-head-count/i, confidence: 90 },
    { type: "script", regex: /_next\/static\/chunks\/webpack-([a-f0-9]+)/i, confidence: 90 },
  ]},
  { name: "Nuxt.js", category: "Framework", patterns: [
    { type: "html", regex: /__nuxt|nuxt-link|data-n-head/i, confidence: 90 },
    { type: "script", regex: /_nuxt\//i, confidence: 90 },
  ]},
  { name: "Gatsby", category: "Framework", patterns: [
    { type: "html", regex: /gatsby-/i, confidence: 85 },
    { type: "html", regex: /___gatsby/i, confidence: 95 },
    { type: "meta", regex: /generator=Gatsby\s*([\d.]+)?/i, versionGroup: 1, confidence: 95 },
  ]},
  { name: "Remix", category: "Framework", patterns: [
    { type: "html", regex: /data-remix|__remix/i, confidence: 90 },
    { type: "script", regex: /remix/i, confidence: 70 },
  ]},
  { name: "Astro", category: "Framework", patterns: [
    { type: "html", regex: /astro-island|data-astro/i, confidence: 90 },
    { type: "meta", regex: /generator=Astro\s*v?([\d.]+)?/i, versionGroup: 1, confidence: 95 },
  ]},
  { name: "SvelteKit", category: "Framework", patterns: [
    { type: "html", regex: /__sveltekit/i, confidence: 90 },
  ]},

  // ═══ Backend Frameworks ═══
  { name: "Express.js", category: "Framework", patterns: [
    { type: "header", regex: /x-powered-by:\s*Express/i, confidence: 95 },
  ]},
  { name: "Django", category: "Framework", cpe: "djangoproject:django", patterns: [
    { type: "cookie", regex: /csrftoken|django/i, confidence: 80 },
    { type: "html", regex: /csrfmiddlewaretoken/i, confidence: 85 },
    { type: "header", regex: /x-frame-options.*SAMEORIGIN/i, confidence: 50 },
  ]},
  { name: "Flask", category: "Framework", patterns: [
    { type: "header", regex: /Werkzeug\/?([\d.]+)?/i, versionGroup: 1, confidence: 90 },
  ]},
  { name: "Ruby on Rails", category: "Framework", cpe: "rubyonrails:rails", patterns: [
    { type: "header", regex: /x-powered-by:\s*Phusion Passenger/i, confidence: 80 },
    { type: "header", regex: /x-runtime/i, confidence: 70 },
    { type: "cookie", regex: /_rails_session|_session_id/i, confidence: 85 },
    { type: "html", regex: /csrf-token|authenticity_token/i, confidence: 75 },
    { type: "meta", regex: /csrf-token/i, confidence: 75 },
  ]},
  { name: "Laravel", category: "Framework", cpe: "laravel:laravel", patterns: [
    { type: "cookie", regex: /laravel_session|XSRF-TOKEN/i, confidence: 80 },
    { type: "html", regex: /laravel/i, confidence: 60 },
  ]},
  { name: "Spring", category: "Framework", cpe: "vmware:spring_framework", patterns: [
    { type: "header", regex: /x-application-context/i, confidence: 85 },
    { type: "cookie", regex: /JSESSIONID/i, confidence: 60 },
    { type: "html", regex: /spring/i, confidence: 50 },
  ]},
  { name: "FastAPI", category: "Framework", patterns: [
    { type: "html", regex: /FastAPI/i, confidence: 80 },
    { type: "header", regex: /uvicorn/i, confidence: 75 },
  ]},
  { name: "Koa", category: "Framework", patterns: [
    { type: "header", regex: /x-powered-by:\s*koa/i, confidence: 90 },
  ]},
  { name: "Hapi", category: "Framework", patterns: [
    { type: "header", regex: /x-powered-by:\s*hapi/i, confidence: 90 },
  ]},
  { name: "CakePHP", category: "Framework", cpe: "cakephp:cakephp", patterns: [
    { type: "cookie", regex: /cakephp/i, confidence: 85 },
  ]},
  { name: "Symfony", category: "Framework", cpe: "sensiolabs:symfony", patterns: [
    { type: "cookie", regex: /symfony/i, confidence: 85 },
    { type: "header", regex: /x-debug-token/i, confidence: 90 },
  ]},
  { name: "CodeIgniter", category: "Framework", cpe: "codeigniter:codeigniter", patterns: [
    { type: "cookie", regex: /ci_session/i, confidence: 85 },
  ]},

  // ═══ CMS ═══
  { name: "WordPress", category: "CMS", cpe: "wordpress:wordpress", patterns: [
    { type: "html", regex: /wp-content|wp-includes/i, confidence: 95 },
    { type: "meta", regex: /generator=WordPress\s*([\d.]+)?/i, versionGroup: 1, confidence: 95 },
    { type: "html", regex: /wp-json/i, confidence: 90 },
    { type: "script", regex: /wp-(?:content|includes)\/js\//i, confidence: 90 },
    { type: "html", regex: /wp-embed\.min\.js\?ver=([\d.]+)/i, versionGroup: 1, confidence: 95 },
  ]},
  { name: "Drupal", category: "CMS", cpe: "drupal:drupal", patterns: [
    { type: "html", regex: /drupal\.js|Drupal\.settings|sites\/default\/files/i, confidence: 90 },
    { type: "header", regex: /x-drupal-cache|x-drupal-dynamic-cache/i, confidence: 95 },
    { type: "meta", regex: /generator=Drupal\s*([\d.]+)?/i, versionGroup: 1, confidence: 95 },
    { type: "html", regex: /drupal\.js\?([a-z0-9]+)/i, confidence: 85 },
  ]},
  { name: "Joomla", category: "CMS", cpe: "joomla:joomla\\!", patterns: [
    { type: "html", regex: /\/media\/jui\/|\/components\/com_/i, confidence: 85 },
    { type: "meta", regex: /generator=Joomla[!]?\s*([\d.]+)?/i, versionGroup: 1, confidence: 95 },
  ]},
  { name: "Magento", category: "CMS", cpe: "magento:magento", patterns: [
    { type: "html", regex: /mage\/cookies|Mage\.Cookies/i, confidence: 90 },
    { type: "cookie", regex: /frontend=|MAGE_/i, confidence: 80 },
    { type: "html", regex: /\/static\/version\d+/i, confidence: 80 },
  ]},
  { name: "Ghost", category: "CMS", patterns: [
    { type: "meta", regex: /generator=Ghost\s*([\d.]+)?/i, versionGroup: 1, confidence: 95 },
    { type: "html", regex: /ghost-(?:url|api)/i, confidence: 85 },
  ]},
  { name: "Squarespace", category: "CMS", patterns: [
    { type: "html", regex: /squarespace\.com|sqsp\.net/i, confidence: 90 },
    { type: "html", regex: /Static\.SQUARESPACE_CONTEXT/i, confidence: 95 },
  ]},
  { name: "Wix", category: "CMS", patterns: [
    { type: "html", regex: /wix\.com|wixsite\.com|_wix_browser_sess/i, confidence: 90 },
    { type: "meta", regex: /generator=Wix\.com/i, confidence: 95 },
  ]},
  { name: "Webflow", category: "CMS", patterns: [
    { type: "html", regex: /webflow\.com|w-webflow/i, confidence: 90 },
    { type: "meta", regex: /generator=Webflow/i, confidence: 95 },
  ]},
  { name: "Hugo", category: "CMS", patterns: [
    { type: "meta", regex: /generator=Hugo\s*([\d.]+)?/i, versionGroup: 1, confidence: 95 },
  ]},
  { name: "Jekyll", category: "CMS", patterns: [
    { type: "meta", regex: /generator=Jekyll\s*v?([\d.]+)?/i, versionGroup: 1, confidence: 95 },
  ]},
  { name: "Contentful", category: "CMS", patterns: [
    { type: "html", regex: /contentful\.com/i, confidence: 80 },
    { type: "script", regex: /contentful/i, confidence: 75 },
  ]},
  { name: "Strapi", category: "CMS", patterns: [
    { type: "header", regex: /x-powered-by:\s*Strapi/i, confidence: 95 },
  ]},

  // ═══ JavaScript Libraries ═══
  { name: "jQuery", category: "JavaScript Library", patterns: [
    { type: "script", regex: /jquery[-.]([\d.]+)(?:\.min)?\.js/i, versionGroup: 1, confidence: 95 },
    { type: "script", regex: /jquery\/([\d.]+)\/jquery/i, versionGroup: 1, confidence: 95 },
    { type: "script", regex: /jquery@([\d.]+)/i, versionGroup: 1, confidence: 95 },
    { type: "html", regex: /jquery(?:\.min)?\.js/i, confidence: 80 },
  ]},
  { name: "jQuery UI", category: "JavaScript Library", patterns: [
    { type: "script", regex: /jquery-ui[-.]([\d.]+)/i, versionGroup: 1, confidence: 90 },
    { type: "script", regex: /jquery\.ui/i, confidence: 85 },
    { type: "html", regex: /ui-widget|ui-dialog|ui-datepicker/i, confidence: 80 },
  ]},
  { name: "Bootstrap", category: "CSS Framework", patterns: [
    { type: "script", regex: /bootstrap[-.]([\d.]+)(?:\.min)?\.js/i, versionGroup: 1, confidence: 90 },
    { type: "html", regex: /bootstrap(?:\.min)?\.css/i, confidence: 85 },
    { type: "script", regex: /bootstrap@([\d.]+)/i, versionGroup: 1, confidence: 95 },
    { type: "html", regex: /class="[^"]*(?:navbar-|btn-|col-(?:sm|md|lg|xl)-)/i, confidence: 70 },
  ]},
  { name: "Tailwind CSS", category: "CSS Framework", patterns: [
    { type: "html", regex: /class="[^"]*(?:flex|grid|text-|bg-|p-|m-|w-|h-)[a-z0-9-]+(?:\s|")/i, confidence: 60 },
    { type: "script", regex: /tailwindcss|tailwind(?:\.min)?\.css/i, confidence: 90 },
  ]},
  { name: "Lodash", category: "JavaScript Library", patterns: [
    { type: "script", regex: /lodash[-.]([\d.]+)(?:\.min)?\.js/i, versionGroup: 1, confidence: 90 },
    { type: "script", regex: /lodash@([\d.]+)/i, versionGroup: 1, confidence: 90 },
  ]},
  { name: "Moment.js", category: "JavaScript Library", patterns: [
    { type: "script", regex: /moment[-.]([\d.]+)(?:\.min)?\.js/i, versionGroup: 1, confidence: 90 },
    { type: "script", regex: /moment@([\d.]+)/i, versionGroup: 1, confidence: 90 },
  ]},
  { name: "D3.js", category: "JavaScript Library", patterns: [
    { type: "script", regex: /d3[-.]([\d.]+)(?:\.min)?\.js/i, versionGroup: 1, confidence: 90 },
    { type: "script", regex: /d3@([\d.]+)/i, versionGroup: 1, confidence: 90 },
  ]},
  { name: "Chart.js", category: "JavaScript Library", patterns: [
    { type: "script", regex: /chart[-.]([\d.]+)(?:\.min)?\.js/i, versionGroup: 1, confidence: 90 },
    { type: "script", regex: /chart\.js@([\d.]+)/i, versionGroup: 1, confidence: 90 },
  ]},
  { name: "Three.js", category: "JavaScript Library", patterns: [
    { type: "script", regex: /three[-.]([\d.]+)(?:\.min)?\.js/i, versionGroup: 1, confidence: 90 },
    { type: "script", regex: /three@([\d.]+)/i, versionGroup: 1, confidence: 90 },
  ]},
  { name: "Socket.io", category: "JavaScript Library", patterns: [
    { type: "script", regex: /socket\.io[-.]([\d.]+)/i, versionGroup: 1, confidence: 90 },
    { type: "script", regex: /socket\.io(?:\.min)?\.js/i, confidence: 85 },
  ]},
  { name: "Axios", category: "JavaScript Library", patterns: [
    { type: "script", regex: /axios[-.]([\d.]+)(?:\.min)?\.js/i, versionGroup: 1, confidence: 85 },
  ]},
  { name: "Underscore.js", category: "JavaScript Library", patterns: [
    { type: "script", regex: /underscore[-.]([\d.]+)(?:\.min)?\.js/i, versionGroup: 1, confidence: 90 },
  ]},
  { name: "Handlebars", category: "JavaScript Library", patterns: [
    { type: "script", regex: /handlebars[-.]([\d.]+)(?:\.min)?\.js/i, versionGroup: 1, confidence: 90 },
  ]},
  { name: "Modernizr", category: "JavaScript Library", patterns: [
    { type: "script", regex: /modernizr[-.]([\d.]+)(?:\.min)?\.js/i, versionGroup: 1, confidence: 90 },
    { type: "html", regex: /class="[^"]*(?:no-)?js\s/i, confidence: 50 },
  ]},
  { name: "RequireJS", category: "JavaScript Library", patterns: [
    { type: "script", regex: /require[-.]([\d.]+)(?:\.min)?\.js/i, versionGroup: 1, confidence: 90 },
    { type: "html", regex: /data-main/i, confidence: 70 },
  ]},
  { name: "Webpack", category: "Build Tool", patterns: [
    { type: "html", regex: /webpackJsonp|__webpack_require__/i, confidence: 85 },
    { type: "script", regex: /webpack/i, confidence: 70 },
  ]},
  { name: "Vite", category: "Build Tool", patterns: [
    { type: "html", regex: /@vite\/client/i, confidence: 95 },
    { type: "script", regex: /vite\/modulepreload-polyfill/i, confidence: 90 },
  ]},

  // ═══ Analytics & Marketing ═══
  { name: "Google Analytics", category: "Analytics", patterns: [
    { type: "script", regex: /google-analytics\.com\/(?:analytics|ga)\.js/i, confidence: 95 },
    { type: "script", regex: /googletagmanager\.com\/gtag/i, confidence: 90 },
    { type: "html", regex: /gtag\(|ga\('create'/i, confidence: 85 },
  ]},
  { name: "Google Tag Manager", category: "Analytics", patterns: [
    { type: "html", regex: /googletagmanager\.com\/gtm\.js/i, confidence: 95 },
    { type: "html", regex: /GTM-[A-Z0-9]+/i, confidence: 90 },
  ]},
  { name: "Hotjar", category: "Analytics", patterns: [
    { type: "script", regex: /hotjar\.com/i, confidence: 90 },
    { type: "html", regex: /hj\('identify'\)|_hjSettings/i, confidence: 90 },
  ]},
  { name: "Mixpanel", category: "Analytics", patterns: [
    { type: "script", regex: /cdn\.mxpnl\.com|mixpanel/i, confidence: 90 },
  ]},
  { name: "Segment", category: "Analytics", patterns: [
    { type: "script", regex: /cdn\.segment\.com|analytics\.js/i, confidence: 85 },
  ]},
  { name: "Heap", category: "Analytics", patterns: [
    { type: "script", regex: /heap-\d+\.js|heapanalytics\.com/i, confidence: 90 },
  ]},
  { name: "Matomo", category: "Analytics", patterns: [
    { type: "script", regex: /matomo\.js|piwik\.js/i, confidence: 90 },
  ]},
  { name: "Facebook Pixel", category: "Analytics", patterns: [
    { type: "script", regex: /connect\.facebook\.net\/.*\/fbevents\.js/i, confidence: 95 },
    { type: "html", regex: /fbq\('init'/i, confidence: 90 },
  ]},
  { name: "HubSpot", category: "Marketing", patterns: [
    { type: "script", regex: /js\.hs-scripts\.com|js\.hubspot\.com/i, confidence: 90 },
    { type: "html", regex: /hubspot/i, confidence: 65 },
  ]},
  { name: "Intercom", category: "Marketing", patterns: [
    { type: "script", regex: /widget\.intercom\.io|intercomcdn\.com/i, confidence: 90 },
    { type: "html", regex: /intercomSettings/i, confidence: 85 },
  ]},
  { name: "Drift", category: "Marketing", patterns: [
    { type: "script", regex: /js\.driftt\.com|drift\.com/i, confidence: 90 },
  ]},
  { name: "Zendesk", category: "Marketing", patterns: [
    { type: "script", regex: /static\.zdassets\.com|zopim/i, confidence: 90 },
  ]},
  { name: "Crisp", category: "Marketing", patterns: [
    { type: "script", regex: /client\.crisp\.chat/i, confidence: 90 },
  ]},
  { name: "Tawk.to", category: "Marketing", patterns: [
    { type: "script", regex: /embed\.tawk\.to/i, confidence: 90 },
  ]},

  // ═══ Security ═══
  { name: "reCAPTCHA", category: "Security", patterns: [
    { type: "script", regex: /google\.com\/recaptcha/i, confidence: 95 },
    { type: "html", regex: /g-recaptcha/i, confidence: 90 },
  ]},
  { name: "hCaptcha", category: "Security", patterns: [
    { type: "script", regex: /hcaptcha\.com/i, confidence: 95 },
  ]},
  { name: "Turnstile", category: "Security", patterns: [
    { type: "script", regex: /challenges\.cloudflare\.com\/turnstile/i, confidence: 95 },
  ]},

  // ═══ E-commerce ═══
  { name: "Shopify", category: "E-commerce", patterns: [
    { type: "html", regex: /cdn\.shopify\.com|Shopify\.theme/i, confidence: 95 },
    { type: "html", regex: /myshopify\.com/i, confidence: 90 },
  ]},
  { name: "WooCommerce", category: "E-commerce", cpe: "woocommerce:woocommerce", patterns: [
    { type: "html", regex: /woocommerce|wc-cart/i, confidence: 90 },
    { type: "html", regex: /wc-block-/i, confidence: 85 },
  ]},
  { name: "Magento", category: "E-commerce", cpe: "magento:magento", patterns: [
    { type: "html", regex: /mage\/cookies|Mage\.Cookies/i, confidence: 90 },
    { type: "cookie", regex: /frontend=|MAGE_/i, confidence: 80 },
  ]},
  { name: "BigCommerce", category: "E-commerce", patterns: [
    { type: "html", regex: /bigcommerce\.com/i, confidence: 85 },
  ]},
  { name: "PrestaShop", category: "E-commerce", cpe: "prestashop:prestashop", patterns: [
    { type: "html", regex: /prestashop/i, confidence: 80 },
    { type: "meta", regex: /generator=PrestaShop/i, confidence: 95 },
  ]},

  // ═══ Hosting / Platform ═══
  { name: "Vercel", category: "Hosting", patterns: [
    { type: "header", regex: /x-vercel-id/i, confidence: 95 },
    { type: "header", regex: /server:\s*vercel/i, confidence: 95 },
  ]},
  { name: "Netlify", category: "Hosting", patterns: [
    { type: "header", regex: /x-nf-request-id/i, confidence: 95 },
    { type: "header", regex: /server:\s*netlify/i, confidence: 95 },
  ]},
  { name: "Heroku", category: "Hosting", patterns: [
    { type: "header", regex: /heroku/i, confidence: 85 },
    { type: "html", regex: /herokuapp\.com/i, confidence: 90 },
  ]},
  { name: "AWS", category: "Hosting", patterns: [
    { type: "header", regex: /x-amz-request-id|AmazonS3/i, confidence: 90 },
    { type: "html", regex: /\.s3\.amazonaws\.com|s3\..*\.amazonaws\.com/i, confidence: 85 },
  ]},
  { name: "Google Cloud", category: "Hosting", patterns: [
    { type: "header", regex: /x-cloud-trace-context/i, confidence: 85 },
    { type: "header", regex: /server:\s*Google Frontend/i, confidence: 90 },
  ]},
  { name: "Azure", category: "Hosting", patterns: [
    { type: "header", regex: /x-azure-ref|x-ms-request-id/i, confidence: 90 },
    { type: "html", regex: /azurewebsites\.net|azure\.com/i, confidence: 85 },
  ]},
  { name: "DigitalOcean", category: "Hosting", patterns: [
    { type: "header", regex: /x-do-/i, confidence: 85 },
    { type: "html", regex: /digitaloceanspaces\.com/i, confidence: 85 },
  ]},
  { name: "Firebase", category: "Hosting", patterns: [
    { type: "html", regex: /firebaseapp\.com|firebase\.js/i, confidence: 90 },
    { type: "script", regex: /firebase[-@]([\d.]+)/i, versionGroup: 1, confidence: 90 },
  ]},
  { name: "GitHub Pages", category: "Hosting", patterns: [
    { type: "header", regex: /server:\s*GitHub\.com/i, confidence: 95 },
    { type: "html", regex: /github\.io/i, confidence: 80 },
  ]},
  { name: "Render", category: "Hosting", patterns: [
    { type: "header", regex: /x-render-origin-server/i, confidence: 95 },
    { type: "html", regex: /onrender\.com/i, confidence: 85 },
  ]},
  { name: "Fly.io", category: "Hosting", patterns: [
    { type: "header", regex: /fly-request-id/i, confidence: 95 },
  ]},
  { name: "Railway", category: "Hosting", patterns: [
    { type: "html", regex: /railway\.app/i, confidence: 80 },
  ]},

  // ═══ Databases (exposed indicators) ═══
  { name: "MongoDB", category: "Database", cpe: "mongodb:mongodb", patterns: [
    { type: "header", regex: /mongodb/i, confidence: 75 },
    { type: "html", regex: /mongodb/i, confidence: 50 },
  ]},
  { name: "Redis", category: "Database", cpe: "redis:redis", patterns: [
    { type: "header", regex: /redis/i, confidence: 75 },
  ]},
  { name: "Elasticsearch", category: "Database", cpe: "elastic:elasticsearch", patterns: [
    { type: "header", regex: /x-elastic-product/i, confidence: 90 },
    { type: "html", regex: /"cluster_name".*"cluster_uuid"/i, confidence: 95 },
  ]},

  // ═══ Crypto / TLS ═══
  { name: "OpenSSL", category: "Security Library", cpe: "openssl:openssl", patterns: [
    { type: "header", regex: /OpenSSL\/?([\d.]+[a-z]?)/i, versionGroup: 1, confidence: 95 },
  ]},
  { name: "mod_ssl", category: "Security Library", patterns: [
    { type: "header", regex: /mod_ssl\/?([\d.]+)?/i, versionGroup: 1, confidence: 90 },
  ]},

  // ═══ Mail ═══
  { name: "Microsoft 365", category: "Email", patterns: [
    { type: "html", regex: /outlook\.office365\.com|protection\.outlook\.com/i, confidence: 85 },
  ]},
  { name: "Google Workspace", category: "Email", patterns: [
    { type: "html", regex: /aspmx\.l\.google\.com|google\.com.*mail/i, confidence: 80 },
  ]},

  // ═══ Font / Icon Services ═══
  { name: "Google Fonts", category: "Font", patterns: [
    { type: "html", regex: /fonts\.googleapis\.com|fonts\.gstatic\.com/i, confidence: 90 },
  ]},
  { name: "Font Awesome", category: "Font", patterns: [
    { type: "html", regex: /font-awesome|fontawesome/i, confidence: 85 },
    { type: "script", regex: /fontawesome[-@]([\d.]+)/i, versionGroup: 1, confidence: 90 },
    { type: "html", regex: /fa-(?:solid|regular|brands|light)/i, confidence: 80 },
  ]},

  // ═══ Payment ═══
  { name: "Stripe", category: "Payment", patterns: [
    { type: "script", regex: /js\.stripe\.com\/v(\d+)/i, versionGroup: 1, confidence: 95 },
    { type: "html", regex: /stripe/i, confidence: 60 },
  ]},
  { name: "PayPal", category: "Payment", patterns: [
    { type: "script", regex: /paypal\.com\/sdk/i, confidence: 95 },
    { type: "html", regex: /paypal/i, confidence: 60 },
  ]},
  { name: "Square", category: "Payment", patterns: [
    { type: "script", regex: /squareup\.com|square\.js/i, confidence: 90 },
  ]},

  // ═══ Reverse Proxy / Load Balancer ═══
  { name: "HAProxy", category: "Load Balancer", cpe: "haproxy:haproxy", patterns: [
    { type: "header", regex: /haproxy/i, confidence: 90 },
    { type: "cookie", regex: /SERVERID/i, confidence: 70 },
  ]},
  { name: "Traefik", category: "Reverse Proxy", patterns: [
    { type: "header", regex: /traefik/i, confidence: 90 },
  ]},

  // ═══ Containerization ═══
  { name: "Docker", category: "Container", patterns: [
    { type: "header", regex: /docker/i, confidence: 75 },
  ]},
  { name: "Kubernetes", category: "Container", patterns: [
    { type: "header", regex: /x-kubernetes/i, confidence: 90 },
  ]},
];

// ─── Enhanced Technology Detection ──────────────────────────────────────────
// Multi-signal detection: tries all patterns per tech and picks the highest-confidence
// match with the best version extraction.

export function detectTechnologies(
  headers: Record<string, string>,
  html: string,
  $: cheerio.CheerioAPI,
): DetectedTechnology[] {
  const detected: DetectedTechnology[] = [];
  const seen = new Map<string, { confidence: number; version?: string }>();

  const headerStr = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n");
  const scripts = $("script[src]").map((_, el) => $(el).attr("src") || "").get().join("\n");
  const metas = $("meta").map((_, el) => {
    const name = $(el).attr("name") || $(el).attr("property") || "";
    const content = $(el).attr("content") || "";
    return `${name}=${content}`;
  }).get().join("\n");
  const cookieStr = headers["set-cookie"] || "";
  // Also extract inline script content for deeper fingerprinting
  const inlineScripts = $("script:not([src])").map((_, el) => $(el).html() || "").get().join("\n").slice(0, 50000);
  // Combine link hrefs for CSS detection
  const linkHrefs = $("link[href]").map((_, el) => $(el).attr("href") || "").get().join("\n");

  for (const tech of TECH_PATTERNS) {
    let bestMatch: { version?: string; confidence: number; evidence: string } | null = null;

    for (const pattern of tech.patterns) {
      let source = "";
      switch (pattern.type) {
        case "header": source = headerStr; break;
        case "html": source = html.slice(0, 200000) + "\n" + inlineScripts; break;
        case "script": source = scripts + "\n" + linkHrefs; break;
        case "meta": source = metas; break;
        case "cookie": source = cookieStr; break;
        case "url": source = scripts + "\n" + linkHrefs; break;
      }

      const match = source.match(pattern.regex);
      if (match) {
        const version = pattern.versionGroup ? match[pattern.versionGroup] || undefined : undefined;
        const conf = pattern.confidence ?? 85;
        // Prefer matches with version info, then higher confidence
        if (!bestMatch ||
            (version && !bestMatch.version) ||
            (version && bestMatch.version && conf > bestMatch.confidence) ||
            (!version && !bestMatch.version && conf > bestMatch.confidence)) {
          bestMatch = {
            version,
            confidence: conf,
            evidence: `Matched ${pattern.type}: ${pattern.regex.source.slice(0, 80)}`,
          };
        }
      }
    }

    if (bestMatch) {
      const existing = seen.get(tech.name);
      if (!existing || bestMatch.confidence > existing.confidence ||
          (bestMatch.version && !existing.version)) {
        seen.set(tech.name, { confidence: bestMatch.confidence, version: bestMatch.version });
        // Remove old entry if upgrading
        const idx = detected.findIndex(d => d.name === tech.name);
        if (idx >= 0) detected.splice(idx, 1);
        detected.push({
          name: tech.name,
          version: bestMatch.version,
          category: tech.category,
          confidence: bestMatch.confidence,
          evidence: bestMatch.evidence,
        });
      }
    }
  }

  // ─── Secondary: Extract versions from inline script globals ───
  // Many libraries expose version via window globals
  const versionGlobals: { name: string; regex: RegExp; category: string }[] = [
    { name: "jQuery", regex: /jQuery\.fn\.jquery\s*=\s*["']([\d.]+)["']/i, category: "JavaScript Library" },
    { name: "jQuery", regex: /jQuery\s*=.*version:\s*["']([\d.]+)["']/i, category: "JavaScript Library" },
    { name: "Lodash", regex: /\.VERSION\s*=\s*["']([\d.]+)["']/i, category: "JavaScript Library" },
    { name: "React", regex: /React(?:DOM)?\.version\s*=\s*["']([\d.]+)["']/i, category: "JavaScript Framework" },
    { name: "Vue.js", regex: /Vue\.version\s*=\s*["']([\d.]+)["']/i, category: "JavaScript Framework" },
    { name: "Angular", regex: /VERSION\s*=.*full:\s*["']([\d.]+)["']/i, category: "JavaScript Framework" },
    { name: "Bootstrap", regex: /Bootstrap\s*v([\d.]+)/i, category: "CSS Framework" },
  ];
  for (const vg of versionGlobals) {
    const m = inlineScripts.match(vg.regex);
    if (m && m[1]) {
      const existing = seen.get(vg.name);
      if (!existing || !existing.version) {
        seen.set(vg.name, { confidence: 90, version: m[1] });
        const idx = detected.findIndex(d => d.name === vg.name);
        if (idx >= 0) {
          detected[idx].version = m[1];
          detected[idx].confidence = Math.max(detected[idx].confidence, 90);
        } else {
          detected.push({
            name: vg.name,
            version: m[1],
            category: vg.category,
            confidence: 90,
            evidence: `Inline script global version: ${vg.regex.source.slice(0, 60)}`,
          });
        }
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
