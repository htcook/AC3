/**
 * Web Crawler Tests
 *
 * Tests the core crawler functions:
 * - Security header analysis & grading
 * - Technology detection
 * - Cookie analysis
 * - Finding generation
 * - URL normalization
 * - Single page crawl (mocked HTTP)
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock axios before imports
const mockAxiosGet = vi.fn();
vi.mock("axios", () => ({
  default: {
    get: (...args: any[]) => mockAxiosGet(...args),
  },
}));

// Mock TLS
vi.mock("node:tls", () => ({
  default: {
    connect: vi.fn((_port, _host, _opts, cb) => {
      const socket = {
        getPeerCertificate: () => ({
          valid_from: "Jan 1 00:00:00 2025 GMT",
          valid_to: "Dec 31 23:59:59 2025 GMT",
          issuer: { O: "Let's Encrypt", CN: "R3" },
          subject: { CN: "example.com" },
          subjectaltname: "DNS:example.com, DNS:*.example.com",
          serialNumber: "ABC123",
          fingerprint256: "AA:BB:CC:DD",
        }),
        getProtocol: () => "TLSv1.3",
        getCipher: () => ({ name: "TLS_AES_256_GCM_SHA384", version: "TLSv1.3" }),
        destroy: vi.fn(),
        on: vi.fn(),
      };
      setTimeout(() => cb(), 10);
      return socket;
    }),
  },
}));

// ─── Test analyzeSecurityHeaders ─────────────────────────────────────────

describe("Security Header Analysis", () => {
  it("should detect all present security headers", async () => {
    // Import after mocks
    const mod = await import("./web-crawler");

    // We test via crawlPage which calls analyzeSecurityHeaders internally
    // But since analyzeSecurityHeaders is not exported, we test through the crawl result
    mockAxiosGet.mockResolvedValueOnce({
      status: 200,
      headers: {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=()",
        "x-xss-protection": "1; mode=block",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-resource-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
        "content-type": "text/html; charset=utf-8",
      },
      data: "<html><head><title>Test</title></head><body></body></html>",
      request: { res: { responseUrl: "https://example.com" } },
    });

    const result = await mod.crawlPage("https://example.com", 1, {
      ...mod.DEFAULT_CRAWL_CONFIG,
      maxDepth: 0,
      maxPages: 1,
      checkExposedPaths: false,
    });

    expect(result).not.toBeNull();
    expect(result!.securityHeaders.present.length).toBe(10);
    expect(result!.securityHeaders.missing.length).toBe(0);
    expect(result!.securityHeaderGrade).toBe("A+");
  });

  it("should detect missing security headers and grade F", async () => {
    const mod = await import("./web-crawler");

    mockAxiosGet.mockResolvedValueOnce({
      status: 200,
      headers: {
        "content-type": "text/html",
        "server": "Apache/2.4.51",
        "x-powered-by": "PHP/7.4.3",
      },
      data: "<html><head><title>Insecure</title></head><body></body></html>",
      request: { res: { responseUrl: "https://insecure.example.com" } },
    });

    const result = await mod.crawlPage("https://insecure.example.com", 1, {
      ...mod.DEFAULT_CRAWL_CONFIG,
      checkExposedPaths: false,
    });

    expect(result).not.toBeNull();
    expect(result!.securityHeaders.missing.length).toBeGreaterThan(5);
    expect(result!.securityHeaders.misconfigured.length).toBeGreaterThan(0);
    // Server version disclosure
    expect(result!.securityHeaders.misconfigured.some(m => m.name === "server")).toBe(true);
    // X-Powered-By disclosure
    expect(result!.securityHeaders.misconfigured.some(m => m.name === "x-powered-by")).toBe(true);
    expect(result!.serverHeader).toBe("Apache/2.4.51");
    expect(result!.poweredBy).toBe("PHP/7.4.3");
    // Grade should be poor
    expect(["D", "F"]).toContain(result!.securityHeaderGrade);
  });

  it("should detect misconfigured HSTS with short max-age", async () => {
    const mod = await import("./web-crawler");

    mockAxiosGet.mockResolvedValueOnce({
      status: 200,
      headers: {
        "strict-transport-security": "max-age=3600",
        "content-type": "text/html",
      },
      data: "<html><head><title>Short HSTS</title></head><body></body></html>",
      request: { res: { responseUrl: "https://example.com" } },
    });

    const result = await mod.crawlPage("https://example.com", 1, {
      ...mod.DEFAULT_CRAWL_CONFIG,
      checkExposedPaths: false,
    });

    expect(result).not.toBeNull();
    const hstsMisconfig = result!.securityHeaders.misconfigured.find(m => m.name === "strict-transport-security");
    expect(hstsMisconfig).toBeDefined();
    expect(hstsMisconfig!.issue).toContain("max-age too short");
  });
});

// ─── Test Technology Detection ───────────────────────────────────────────

describe("Technology Detection", () => {
  it("should detect WordPress from HTML content", async () => {
    const mod = await import("./web-crawler");

    mockAxiosGet.mockResolvedValueOnce({
      status: 200,
      headers: { "content-type": "text/html" },
      data: `<html><head><title>WP Site</title>
        <meta name="generator" content="WordPress 6.4.2">
        <link rel="stylesheet" href="/wp-content/themes/theme/style.css">
        <script src="/wp-includes/js/jquery/jquery.min.js"></script>
      </head><body></body></html>`,
      request: { res: { responseUrl: "https://wp.example.com" } },
    });

    const result = await mod.crawlPage("https://wp.example.com", 1, {
      ...mod.DEFAULT_CRAWL_CONFIG,
      checkExposedPaths: false,
    });

    expect(result).not.toBeNull();
    const techNames = result!.detectedTechnologies.map(t => t.name);
    expect(techNames).toContain("WordPress");
  });

  it("should detect React and Next.js from HTML patterns", async () => {
    const mod = await import("./web-crawler");

    mockAxiosGet.mockResolvedValueOnce({
      status: 200,
      headers: { "content-type": "text/html", "x-powered-by": "Next.js" },
      data: `<html><head><title>Next App</title></head>
        <body><div id="__next"><div data-reactroot="">Content</div></div>
        <script src="/_next/static/chunks/main.js"></script>
      </body></html>`,
      request: { res: { responseUrl: "https://next.example.com" } },
    });

    const result = await mod.crawlPage("https://next.example.com", 1, {
      ...mod.DEFAULT_CRAWL_CONFIG,
      checkExposedPaths: false,
    });

    expect(result).not.toBeNull();
    const techNames = result!.detectedTechnologies.map(t => t.name);
    expect(techNames).toContain("Next.js");
  });

  it("should detect Nginx from server header", async () => {
    const mod = await import("./web-crawler");

    mockAxiosGet.mockResolvedValueOnce({
      status: 200,
      headers: { "content-type": "text/html", "server": "nginx/1.24.0" },
      data: "<html><head><title>Nginx</title></head><body></body></html>",
      request: { res: { responseUrl: "https://nginx.example.com" } },
    });

    const result = await mod.crawlPage("https://nginx.example.com", 1, {
      ...mod.DEFAULT_CRAWL_CONFIG,
      checkExposedPaths: false,
    });

    expect(result).not.toBeNull();
    const nginx = result!.detectedTechnologies.find(t => t.name === "Nginx");
    expect(nginx).toBeDefined();
    expect(nginx!.version).toBe("1.24.0");
    expect(nginx!.category).toBe("Web Server");
  });
});

// ─── Test Link Extraction ────────────────────────────────────────────────

describe("Link Extraction", () => {
  it("should separate internal and external links", async () => {
    const mod = await import("./web-crawler");

    mockAxiosGet.mockResolvedValueOnce({
      status: 200,
      headers: { "content-type": "text/html" },
      data: `<html><head><title>Links</title></head><body>
        <a href="/about">About</a>
        <a href="https://example.com/contact">Contact</a>
        <a href="https://external.com/page">External</a>
        <a href="https://sub.example.com/page">Subdomain</a>
        <a href="mailto:test@example.com">Email</a>
        <a href="javascript:void(0)">JS</a>
        <a href="#section">Anchor</a>
      </body></html>`,
      request: { res: { responseUrl: "https://example.com" } },
    });

    const result = await mod.crawlPage("https://example.com", 1, {
      ...mod.DEFAULT_CRAWL_CONFIG,
      checkExposedPaths: false,
    });

    expect(result).not.toBeNull();
    // /about and /contact are internal
    expect(result!.internalLinks.length).toBeGreaterThanOrEqual(2);
    // external.com is external
    expect(result!.externalLinks.some(l => l.includes("external.com"))).toBe(true);
    // mailto, javascript, # should be excluded
    expect(result!.internalLinks.every(l => !l.includes("mailto:"))).toBe(true);
    expect(result!.externalLinks.every(l => !l.includes("javascript:"))).toBe(true);
  });
});

// ─── Test Form Detection ─────────────────────────────────────────────────

describe("Form Detection", () => {
  it("should detect forms with password fields and file uploads", async () => {
    const mod = await import("./web-crawler");

    mockAxiosGet.mockResolvedValueOnce({
      status: 200,
      headers: { "content-type": "text/html" },
      data: `<html><head><title>Forms</title></head><body>
        <form action="/login" method="POST">
          <input type="text" name="username">
          <input type="password" name="password">
          <button type="submit">Login</button>
        </form>
        <form action="/upload" method="POST" enctype="multipart/form-data">
          <input type="file" name="document">
          <input type="text" name="description">
          <button type="submit">Upload</button>
        </form>
      </body></html>`,
      request: { res: { responseUrl: "https://example.com" } },
    });

    const result = await mod.crawlPage("https://example.com", 1, {
      ...mod.DEFAULT_CRAWL_CONFIG,
      checkExposedPaths: false,
    });

    expect(result).not.toBeNull();
    expect(result!.forms.length).toBe(2);

    const loginForm = result!.forms.find(f => f.action === "/login");
    expect(loginForm).toBeDefined();
    expect(loginForm!.method).toBe("POST");
    expect(loginForm!.hasPasswordField).toBe(true);
    expect(loginForm!.hasFileUpload).toBe(false);

    const uploadForm = result!.forms.find(f => f.action === "/upload");
    expect(uploadForm).toBeDefined();
    expect(uploadForm!.hasFileUpload).toBe(true);
  });
});

// ─── Test Cookie Analysis ────────────────────────────────────────────────

describe("Cookie Analysis", () => {
  it("should detect insecure cookies", async () => {
    const mod = await import("./web-crawler");

    mockAxiosGet.mockResolvedValueOnce({
      status: 200,
      headers: {
        "content-type": "text/html",
        "set-cookie": [
          "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict",
          "tracking=xyz789; Path=/",
        ],
      },
      data: "<html><head><title>Cookies</title></head><body></body></html>",
      request: { res: { responseUrl: "https://example.com" } },
    });

    const result = await mod.crawlPage("https://example.com", 1, {
      ...mod.DEFAULT_CRAWL_CONFIG,
      checkExposedPaths: false,
    });

    expect(result).not.toBeNull();
    expect(result!.cookies.length).toBe(2);

    const secureCookie = result!.cookies.find(c => c.name === "session");
    expect(secureCookie).toBeDefined();
    expect(secureCookie!.secure).toBe(true);
    expect(secureCookie!.httpOnly).toBe(true);
    expect(secureCookie!.issues.length).toBe(0);

    const insecureCookie = result!.cookies.find(c => c.name === "tracking");
    expect(insecureCookie).toBeDefined();
    expect(insecureCookie!.secure).toBe(false);
    expect(insecureCookie!.httpOnly).toBe(false);
    expect(insecureCookie!.issues.length).toBeGreaterThan(0);
  });
});

// ─── Test Finding Generation ─────────────────────────────────────────────

describe("Finding Generation", () => {
  it("should generate findings for missing headers and insecure cookies", async () => {
    const mod = await import("./web-crawler");

    mockAxiosGet.mockResolvedValueOnce({
      status: 200,
      headers: {
        "content-type": "text/html",
        "set-cookie": "session=abc; Path=/",
      },
      data: "<html><head><title>Findings</title></head><body></body></html>",
      request: { res: { responseUrl: "https://example.com" } },
    });

    const result = await mod.crawlPage("https://example.com", 1, {
      ...mod.DEFAULT_CRAWL_CONFIG,
      checkExposedPaths: false,
    });

    expect(result).not.toBeNull();
    expect(result!.findings.length).toBeGreaterThan(0);

    // Should have header findings
    const headerFindings = result!.findings.filter(f => f.category === "Security Headers");
    expect(headerFindings.length).toBeGreaterThan(0);

    // Should have cookie findings
    const cookieFindings = result!.findings.filter(f => f.category === "Cookie Security");
    expect(cookieFindings.length).toBeGreaterThan(0);

    // Finding counts should match
    const totalFromCounts = Object.values(result!.findingCounts).reduce((a, b) => a + b, 0);
    expect(totalFromCounts).toBe(result!.findings.length);
  });
});

// ─── Test Page Metadata ──────────────────────────────────────────────────

describe("Page Metadata", () => {
  it("should extract page title and meta description", async () => {
    const mod = await import("./web-crawler");

    mockAxiosGet.mockResolvedValueOnce({
      status: 200,
      headers: { "content-type": "text/html" },
      data: `<html><head>
        <title>My Secure App - Login</title>
        <meta name="description" content="Secure login portal for enterprise users">
      </head><body></body></html>`,
      request: { res: { responseUrl: "https://example.com" } },
    });

    const result = await mod.crawlPage("https://example.com", 1, {
      ...mod.DEFAULT_CRAWL_CONFIG,
      checkExposedPaths: false,
    });

    expect(result).not.toBeNull();
    expect(result!.pageTitle).toBe("My Secure App - Login");
    expect(result!.metaDescription).toBe("Secure login portal for enterprise users");
  });

  it("should handle HTTP errors gracefully", async () => {
    const mod = await import("./web-crawler");

    mockAxiosGet.mockResolvedValueOnce({
      status: 404,
      headers: { "content-type": "text/html" },
      data: "<html><head><title>Not Found</title></head><body>404</body></html>",
      request: { res: { responseUrl: "https://example.com/missing" } },
    });

    const result = await mod.crawlPage("https://example.com/missing", 1, {
      ...mod.DEFAULT_CRAWL_CONFIG,
      checkExposedPaths: false,
    });

    expect(result).not.toBeNull();
    expect(result!.httpStatus).toBe(404);
  });

  it("should return null on network error", async () => {
    const mod = await import("./web-crawler");

    mockAxiosGet.mockRejectedValueOnce(new Error("ECONNREFUSED"));

    const result = await mod.crawlPage("https://unreachable.example.com", 1, {
      ...mod.DEFAULT_CRAWL_CONFIG,
      checkExposedPaths: false,
    });

    expect(result).toBeNull();
  });
});

// ─── Test Resource Detection ─────────────────────────────────────────────

describe("Resource Detection", () => {
  it("should extract script, stylesheet, and image URLs", async () => {
    const mod = await import("./web-crawler");

    mockAxiosGet.mockResolvedValueOnce({
      status: 200,
      headers: { "content-type": "text/html" },
      data: `<html><head>
        <link rel="stylesheet" href="/css/main.css">
        <script src="/js/app.js"></script>
      </head><body>
        <img src="/images/logo.png">
      </body></html>`,
      request: { res: { responseUrl: "https://example.com" } },
    });

    const result = await mod.crawlPage("https://example.com", 1, {
      ...mod.DEFAULT_CRAWL_CONFIG,
      checkExposedPaths: false,
    });

    expect(result).not.toBeNull();
    expect(result!.resourceUrls.length).toBe(3);
    expect(result!.resourceUrls.some(r => r.includes("main.css"))).toBe(true);
    expect(result!.resourceUrls.some(r => r.includes("app.js"))).toBe(true);
    expect(result!.resourceUrls.some(r => r.includes("logo.png"))).toBe(true);
  });
});

// ─── Test Default Config ─────────────────────────────────────────────────

describe("Default Configuration", () => {
  it("should have sensible defaults", async () => {
    const mod = await import("./web-crawler");

    expect(mod.DEFAULT_CRAWL_CONFIG.maxDepth).toBe(2);
    expect(mod.DEFAULT_CRAWL_CONFIG.maxPages).toBe(50);
    expect(mod.DEFAULT_CRAWL_CONFIG.timeoutMs).toBe(15000);
    expect(mod.DEFAULT_CRAWL_CONFIG.respectRobotsTxt).toBe(true);
    expect(mod.DEFAULT_CRAWL_CONFIG.followRedirects).toBe(true);
    expect(mod.DEFAULT_CRAWL_CONFIG.checkExposedPaths).toBe(true);
  });
});
