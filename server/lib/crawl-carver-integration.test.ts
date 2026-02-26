/**
 * Tests for Crawl → CARVER+Shock Scoring Integration
 */
import { describe, it, expect } from "vitest";
import {
  computeCrawlCarverAdjustment,
  applyCrawlAdjustments,
  aggregateCrawlAdjustments,
  type CrawlCarverAdjustment,
} from "./crawl-carver-integration";

// ─── Test Fixtures ──────────────────────────────────────────────────────────

function makeCrawlResult(overrides: Record<string, any> = {}) {
  return {
    url: "https://example.com",
    finalUrl: "https://example.com",
    httpStatus: 200,
    responseTimeMs: 150,
    contentType: "text/html",
    contentLength: 5000,
    depth: 0,
    securityHeaders: {
      present: [
        { name: "X-Content-Type-Options", value: "nosniff" },
      ],
      missing: [
        { name: "Content-Security-Policy", severity: "high" },
        { name: "Strict-Transport-Security", severity: "high" },
        { name: "X-Frame-Options", severity: "medium" },
      ],
      misconfigured: [],
    },
    securityHeaderGrade: "D",
    detectedTechnologies: [
      { name: "nginx", version: "1.18.0", category: "web-server" },
      { name: "React", version: null, category: "framework" },
    ],
    serverHeader: "nginx/1.18.0",
    poweredBy: null,
    pageTitle: "Example Site",
    metaDescription: "An example site",
    internalLinks: ["https://example.com/about", "https://example.com/contact"],
    externalLinks: ["https://cdn.example.com/lib.js"],
    resourceUrls: ["https://example.com/style.css"],
    forms: [],
    exposedPaths: [],
    robotsTxt: "User-agent: *\nDisallow: /admin",
    securityTxt: null,
    sitemapUrls: [],
    cookies: [],
    tlsInfo: { protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384" },
    findings: [
      { severity: "high", title: "Missing CSP", description: "No Content-Security-Policy header" },
      { severity: "medium", title: "Missing HSTS", description: "No Strict-Transport-Security header" },
    ],
    findingCounts: { critical: 0, high: 1, medium: 1, low: 0, info: 0 },
    rawHeaders: { "content-type": "text/html", "server": "nginx/1.18.0" },
    ...overrides,
  };
}

// ─── computeCrawlCarverAdjustment ───────────────────────────────────────────

describe("computeCrawlCarverAdjustment", () => {
  it("returns a valid CrawlCarverAdjustment for a basic crawl result", () => {
    const result = computeCrawlCarverAdjustment(makeCrawlResult() as any, "example.com");

    // Structure checks
    expect(result).toHaveProperty("carver");
    expect(result).toHaveProperty("shock");
    expect(result).toHaveProperty("likelihoodBoost");
    expect(result).toHaveProperty("contextAdjustment");
    expect(result).toHaveProperty("breakdown");
    expect(result).toHaveProperty("postureFindings");

    // CARVER dimensions should be non-negative numbers
    expect(result.carver.criticality).toBeGreaterThanOrEqual(0);
    expect(result.carver.accessibility).toBeGreaterThanOrEqual(0);
    expect(result.carver.recuperability).toBeGreaterThanOrEqual(0);
    expect(result.carver.vulnerability).toBeGreaterThanOrEqual(0);
    expect(result.carver.effect).toBeGreaterThanOrEqual(0);
    expect(result.carver.recognizability).toBeGreaterThanOrEqual(0);

    // SHOCK dimensions should be non-negative numbers
    expect(result.shock.scope).toBeGreaterThanOrEqual(0);
    expect(result.shock.handling).toBeGreaterThanOrEqual(0);
    expect(result.shock.operationalImpact).toBeGreaterThanOrEqual(0);
    expect(result.shock.cascadingEffects).toBeGreaterThanOrEqual(0);
    expect(result.shock.knowledge).toBeGreaterThanOrEqual(0);
  });

  it("produces higher vulnerability scores for worse security grades", () => {
    const gradeF = computeCrawlCarverAdjustment(
      makeCrawlResult({ securityHeaderGrade: "F" }) as any,
      "example.com"
    );
    const gradeA = computeCrawlCarverAdjustment(
      makeCrawlResult({
        securityHeaderGrade: "A",
        securityHeaders: { present: [], missing: [], misconfigured: [] },
      }) as any,
      "example.com"
    );

    expect(gradeF.carver.vulnerability).toBeGreaterThan(gradeA.carver.vulnerability);
  });

  it("increases accessibility when exposed paths are present", () => {
    const withPaths = computeCrawlCarverAdjustment(
      makeCrawlResult({
        exposedPaths: [
          { path: "/.env", status: 200, severity: "critical", description: "Environment file exposed" },
          { path: "/.git/config", status: 200, severity: "critical", description: "Git config exposed" },
          { path: "/wp-admin", status: 200, severity: "high", description: "WordPress admin exposed" },
        ],
      }) as any,
      "example.com"
    );
    const withoutPaths = computeCrawlCarverAdjustment(
      makeCrawlResult({ exposedPaths: [] }) as any,
      "example.com"
    );

    expect(withPaths.carver.accessibility).toBeGreaterThan(withoutPaths.carver.accessibility);
  });

  it("increases recognizability when server version is disclosed", () => {
    const withServer = computeCrawlCarverAdjustment(
      makeCrawlResult({
        serverHeader: "Apache/2.4.41",
        detectedTechnologies: [
          { name: "Apache", version: "2.4.41", category: "web-server" },
          { name: "PHP", version: "7.4.3", category: "language" },
          { name: "WordPress", version: "5.8", category: "cms" },
        ],
      }) as any,
      "example.com"
    );
    const withoutServer = computeCrawlCarverAdjustment(
      makeCrawlResult({
        serverHeader: null,
        detectedTechnologies: [],
      }) as any,
      "example.com"
    );

    expect(withServer.carver.recognizability).toBeGreaterThan(withoutServer.carver.recognizability);
  });

  it("increases vulnerability when insecure cookies are present", () => {
    const withCookies = computeCrawlCarverAdjustment(
      makeCrawlResult({
        cookies: [
          { name: "session", secure: false, httpOnly: false, sameSite: "none", domain: "example.com" },
          { name: "token", secure: false, httpOnly: true, sameSite: "lax", domain: "example.com" },
        ],
      }) as any,
      "example.com"
    );
    const withoutCookies = computeCrawlCarverAdjustment(
      makeCrawlResult({ cookies: [] }) as any,
      "example.com"
    );

    expect(withCookies.carver.vulnerability).toBeGreaterThan(withoutCookies.carver.vulnerability);
  });

  it("increases criticality when login forms are detected", () => {
    const withForms = computeCrawlCarverAdjustment(
      makeCrawlResult({
        forms: [
          { action: "/login", method: "POST", hasPasswordField: true, hasFileUpload: false, inputs: [] },
        ],
      }) as any,
      "example.com"
    );
    const withoutForms = computeCrawlCarverAdjustment(
      makeCrawlResult({ forms: [] }) as any,
      "example.com"
    );

    expect(withForms.carver.criticality).toBeGreaterThan(withoutForms.carver.criticality);
  });

  it("generates posture findings for missing critical headers", () => {
    const result = computeCrawlCarverAdjustment(
      makeCrawlResult({
        securityHeaders: {
          present: [],
          missing: [
            { name: "Content-Security-Policy", severity: "high" },
            { name: "Strict-Transport-Security", severity: "high" },
          ],
          misconfigured: [],
        },
      }) as any,
      "example.com"
    );

    expect(result.postureFindings.length).toBeGreaterThan(0);
    expect(result.postureFindings.every((f) => f.source === "web_crawler")).toBe(true);
    expect(result.postureFindings.every((f) => f.corroborationTier === "confirmed" || f.corroborationTier === "probable")).toBe(true);
  });

  it("produces a reasonable overallWebVulnScore between 0 and 100", () => {
    const result = computeCrawlCarverAdjustment(makeCrawlResult() as any, "example.com");
    expect(result.breakdown.overallWebVulnScore).toBeGreaterThanOrEqual(0);
    expect(result.breakdown.overallWebVulnScore).toBeLessThanOrEqual(100);
  });

  it("produces an assessmentConfidence between 0 and 1", () => {
    const result = computeCrawlCarverAdjustment(makeCrawlResult() as any, "example.com");
    expect(result.breakdown.assessmentConfidence).toBeGreaterThanOrEqual(0);
    expect(result.breakdown.assessmentConfidence).toBeLessThanOrEqual(1);
  });

  it("handles a maximally vulnerable crawl result", () => {
    const result = computeCrawlCarverAdjustment(
      makeCrawlResult({
        securityHeaderGrade: "F",
        securityHeaders: {
          present: [],
          missing: [
            { name: "Content-Security-Policy" },
            { name: "Strict-Transport-Security" },
            { name: "X-Frame-Options" },
            { name: "X-Content-Type-Options" },
            { name: "Referrer-Policy" },
            { name: "Permissions-Policy" },
          ],
          misconfigured: [{ name: "Access-Control-Allow-Origin", value: "*" }],
        },
        exposedPaths: [
          { path: "/.env", status: 200, severity: "critical" },
          { path: "/.git/config", status: 200, severity: "critical" },
          { path: "/wp-admin", status: 200, severity: "high" },
          { path: "/phpmyadmin", status: 200, severity: "high" },
        ],
        cookies: [
          { name: "session", secure: false, httpOnly: false, sameSite: "none" },
          { name: "csrf", secure: false, httpOnly: false, sameSite: "none" },
        ],
        forms: [
          { action: "/login", method: "POST", hasPasswordField: true, hasFileUpload: false, inputs: [] },
          { action: "/upload", method: "POST", hasPasswordField: false, hasFileUpload: true, inputs: [] },
        ],
        serverHeader: "Apache/2.4.41 (Ubuntu)",
        poweredBy: "PHP/7.4.3",
        detectedTechnologies: [
          { name: "Apache", version: "2.4.41", category: "web-server" },
          { name: "PHP", version: "7.4.3", category: "language" },
          { name: "WordPress", version: "5.8", category: "cms" },
          { name: "jQuery", version: "1.12.4", category: "library" },
        ],
        tlsInfo: { protocol: "TLSv1.0", cipher: "DES-CBC3-SHA" },
        findings: [
          { severity: "critical", title: "Exposed .env" },
          { severity: "critical", title: "Exposed .git" },
          { severity: "high", title: "Missing CSP" },
          { severity: "high", title: "Outdated TLS" },
          { severity: "medium", title: "Insecure cookies" },
        ],
        findingCounts: { critical: 2, high: 2, medium: 1, low: 0, info: 0 },
        internalLinks: Array.from({ length: 20 }, (_, i) => `https://example.com/page${i}`),
        externalLinks: Array.from({ length: 10 }, (_, i) => `https://ext${i}.com`),
      }) as any,
      "example.com"
    );

    // Should have significant scores across all dimensions
    expect(result.carver.vulnerability).toBeGreaterThan(1);
    expect(result.carver.accessibility).toBeGreaterThan(0);
    expect(result.carver.recognizability).toBeGreaterThan(0);
    expect(result.carver.criticality).toBeGreaterThan(0);
    expect(result.shock.knowledge).toBeGreaterThan(0);
    expect(result.breakdown.overallWebVulnScore).toBeGreaterThan(30);
    expect(result.postureFindings.length).toBeGreaterThan(3);
  });

  it("handles a well-secured crawl result with minimal adjustments", () => {
    const result = computeCrawlCarverAdjustment(
      makeCrawlResult({
        securityHeaderGrade: "A+",
        securityHeaders: {
          present: [
            { name: "Content-Security-Policy", value: "default-src 'self'" },
            { name: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
            { name: "X-Frame-Options", value: "DENY" },
            { name: "X-Content-Type-Options", value: "nosniff" },
            { name: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
            { name: "Permissions-Policy", value: "camera=(), microphone=()" },
          ],
          missing: [],
          misconfigured: [],
        },
        exposedPaths: [],
        cookies: [
          { name: "session", secure: true, httpOnly: true, sameSite: "strict" },
        ],
        forms: [],
        serverHeader: null,
        poweredBy: null,
        detectedTechnologies: [],
        tlsInfo: { protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384" },
        findings: [],
        findingCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      }) as any,
      "secure-example.com"
    );

    // Should have very low scores compared to a vulnerable site
    const vulnResult = computeCrawlCarverAdjustment(
      makeCrawlResult({ securityHeaderGrade: "F" }) as any,
      "vuln.example.com"
    );
    expect(result.carver.vulnerability).toBeLessThan(vulnResult.carver.vulnerability);
    expect(result.breakdown.overallWebVulnScore).toBeLessThan(vulnResult.breakdown.overallWebVulnScore);
  });
});

// ─── applyCrawlAdjustments ──────────────────────────────────────────────────

describe("applyCrawlAdjustments", () => {
  it("applies CARVER adjustments to existing scores", () => {
    const existingCarver = {
      criticality: 5, accessibility: 3, recuperability: 4,
      vulnerability: 3, effect: 4, recognizability: 2,
    };
    const existingShock = {
      scope: 3, handling: 4, operationalImpact: 3,
      cascadingEffects: 2, knowledge: 3,
    };
    const adjustment = computeCrawlCarverAdjustment(makeCrawlResult() as any, "example.com");

    const result = applyCrawlAdjustments(existingCarver, existingShock, adjustment);

    // Adjusted scores should be >= original (adjustments are additive)
    expect(result.carver.vulnerability).toBeGreaterThanOrEqual(existingCarver.vulnerability);
    expect(result.shock.handling).toBeGreaterThanOrEqual(existingShock.handling);
  });

  it("caps individual dimension scores at 10", () => {
    const existingCarver = {
      criticality: 9, accessibility: 9, recuperability: 9,
      vulnerability: 9, effect: 9, recognizability: 9,
    };
    const existingShock = {
      scope: 9, handling: 9, operationalImpact: 9,
      cascadingEffects: 9, knowledge: 9,
    };
    const adjustment = computeCrawlCarverAdjustment(
      makeCrawlResult({ securityHeaderGrade: "F" }) as any,
      "example.com"
    );

    const result = applyCrawlAdjustments(existingCarver, existingShock, adjustment);

    // All scores should be capped at 10
    Object.values(result.carver).forEach((v) => expect(v).toBeLessThanOrEqual(10));
    Object.values(result.shock).forEach((v) => expect(v).toBeLessThanOrEqual(10));
  });
});

// ─── aggregateCrawlAdjustments ──────────────────────────────────────────────

describe("aggregateCrawlAdjustments", () => {
  it("returns null for empty array", () => {
    expect(aggregateCrawlAdjustments([])).toBeNull();
  });

  it("returns the single adjustment for array of one", () => {
    const adj = computeCrawlCarverAdjustment(makeCrawlResult() as any, "example.com");
    const result = aggregateCrawlAdjustments([adj]);
    expect(result).toBe(adj);
  });

  it("aggregates multiple adjustments into a combined score", () => {
    const adj1 = computeCrawlCarverAdjustment(
      makeCrawlResult({ securityHeaderGrade: "F" }) as any,
      "site1.example.com"
    );
    const adj2 = computeCrawlCarverAdjustment(
      makeCrawlResult({
        securityHeaderGrade: "D",
        exposedPaths: [
          { path: "/.env", status: 200, severity: "critical" },
        ],
      }) as any,
      "site2.example.com"
    );
    const adj3 = computeCrawlCarverAdjustment(
      makeCrawlResult({ securityHeaderGrade: "A+" }) as any,
      "site3.example.com"
    );

    const result = aggregateCrawlAdjustments([adj1, adj2, adj3]);

    expect(result).not.toBeNull();
    expect(result!.carver).toHaveProperty("vulnerability");
    expect(result!.shock).toHaveProperty("knowledge");
    expect(result!.postureFindings.length).toBeGreaterThan(0);
    expect(result!.breakdown.overallWebVulnScore).toBeGreaterThanOrEqual(0);
  });

  it("aggregated score is influenced by worst-case findings", () => {
    const secure = computeCrawlCarverAdjustment(
      makeCrawlResult({
        securityHeaderGrade: "A+",
        securityHeaders: { present: [], missing: [], misconfigured: [] },
        exposedPaths: [],
        cookies: [],
        findings: [],
        findingCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      }) as any,
      "secure.example.com"
    );
    const vulnerable = computeCrawlCarverAdjustment(
      makeCrawlResult({
        securityHeaderGrade: "F",
        exposedPaths: [
          { path: "/.env", status: 200, severity: "critical" },
          { path: "/.git", status: 200, severity: "critical" },
        ],
      }) as any,
      "vuln.example.com"
    );

    const aggregated = aggregateCrawlAdjustments([secure, vulnerable]);
    // Aggregated should reflect the vulnerable asset's impact
    expect(aggregated!.carver.vulnerability).toBeGreaterThan(secure.carver.vulnerability);
  });
});
