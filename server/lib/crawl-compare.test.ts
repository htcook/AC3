import { describe, it, expect } from "vitest";
import { compareCrawlResults } from "./crawl-compare";

// ─── Mock Data ────────────────────────────────────────────────────────────────

const makeResult = (overrides: Record<string, any> = {}) => ({
  securityHeaders: {
    present: [
      { name: "strict-transport-security", value: "max-age=31536000", status: "good" },
      { name: "x-content-type-options", value: "nosniff", status: "good" },
    ],
    missing: [
      { name: "content-security-policy", severity: "high", description: "CSP not set" },
    ],
    misconfigured: [],
  },
  securityHeaderGrade: "B",
  detectedTechnologies: [
    { name: "Nginx", version: "1.24", category: "Web Server", confidence: 90, evidence: "header" },
    { name: "React", version: "18.2", category: "JavaScript Library", confidence: 80, evidence: "html" },
  ],
  findings: [
    { severity: "high", title: "Missing CSP", category: "Headers", description: "No Content-Security-Policy header" },
    { severity: "medium", title: "Missing X-Frame-Options", category: "Headers", description: "Clickjacking possible" },
    { severity: "low", title: "Server version disclosed", category: "Information Disclosure", description: "Server header reveals version" },
  ],
  exposedPaths: [
    { path: "/robots.txt", status: 200, type: "info_disclosure", severity: "info", description: "Robots.txt accessible" },
  ],
  cookies: [
    { name: "session", secure: true, httpOnly: true, sameSite: "Lax", domain: "example.com", path: "/", issues: [] },
  ],
  tlsInfo: { issuer: "Let's Encrypt", subject: "example.com", validTo: "2026-06-01", protocol: "TLSv1.3", cipher: "AES-256-GCM" },
  responseTimeMs: 250,
  contentLength: 45000,
  internalLinks: ["https://example.com/about", "https://example.com/contact"],
  externalLinks: ["https://cdn.example.com/lib.js"],
  forms: [{ action: "/login", method: "POST", inputs: [{ name: "email", type: "email" }], hasFileUpload: false, hasPasswordField: true }],
  createdAt: new Date("2026-01-15").toISOString(),
  startedAt: Date.now() - 60000,
  ...overrides,
});

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("compareCrawlResults", () => {
  it("should return unchanged when comparing identical results", () => {
    const old = makeResult();
    const result = compareCrawlResults(old, old, "example.com");

    expect(result.domain).toBe("example.com");
    expect(result.overallChange).toBe("unchanged");
    expect(result.totalChanges).toBe(0);
    expect(result.headerDiff.gradeChange.direction).toBe("unchanged");
  });

  it("should detect grade improvement", () => {
    const old = makeResult({ securityHeaderGrade: "C" });
    const newer = makeResult({ securityHeaderGrade: "A" });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.headerDiff.gradeChange.old).toBe("C");
    expect(result.headerDiff.gradeChange.new).toBe("A");
    expect(result.headerDiff.gradeChange.direction).toBe("improved");
    expect(result.changeScore).toBeGreaterThan(0);
  });

  it("should detect grade regression", () => {
    const old = makeResult({ securityHeaderGrade: "A" });
    const newer = makeResult({ securityHeaderGrade: "D" });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.headerDiff.gradeChange.direction).toBe("regressed");
    expect(result.changeScore).toBeLessThan(0);
  });

  it("should detect new findings", () => {
    const old = makeResult();
    const newer = makeResult({
      findings: [
        ...makeResult().findings,
        { severity: "critical", title: "SQL Injection", category: "Vulnerability", description: "Possible SQL injection" },
      ],
    });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.findingDiff.added).toHaveLength(1);
    expect(result.findingDiff.added[0].title).toBe("SQL Injection");
    expect(result.findingDiff.added[0].severity).toBe("critical");
    expect(result.changeScore).toBeLessThan(0); // New critical finding = negative score
  });

  it("should detect removed findings (resolved)", () => {
    const old = makeResult();
    const newer = makeResult({
      findings: [
        { severity: "low", title: "Server version disclosed", category: "Information Disclosure", description: "Server header reveals version" },
      ],
    });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.findingDiff.removed).toHaveLength(2); // Missing CSP and X-Frame-Options removed
    expect(result.findingDiff.removed.some(f => f.title === "Missing CSP")).toBe(true);
    expect(result.changeScore).toBeGreaterThan(0); // Resolved findings = positive score
  });

  it("should detect severity changes in findings", () => {
    const old = makeResult();
    const newer = makeResult({
      findings: [
        { severity: "critical", title: "Missing CSP", category: "Headers", description: "Escalated" },
        { severity: "medium", title: "Missing X-Frame-Options", category: "Headers", description: "Same" },
        { severity: "low", title: "Server version disclosed", category: "Information Disclosure", description: "Same" },
      ],
    });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.findingDiff.severityChanges).toHaveLength(1);
    expect(result.findingDiff.severityChanges[0].title).toBe("Missing CSP");
    expect(result.findingDiff.severityChanges[0].oldSeverity).toBe("high");
    expect(result.findingDiff.severityChanges[0].newSeverity).toBe("critical");
    expect(result.findingDiff.severityChanges[0].direction).toBe("escalated");
  });

  it("should detect new technologies", () => {
    const old = makeResult();
    const newer = makeResult({
      detectedTechnologies: [
        ...makeResult().detectedTechnologies,
        { name: "Cloudflare", version: undefined, category: "CDN", confidence: 95, evidence: "header" },
      ],
    });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.technologyDiff.added).toHaveLength(1);
    expect(result.technologyDiff.added[0].name).toBe("Cloudflare");
    expect(result.technologyDiff.added[0].category).toBe("CDN");
  });

  it("should detect removed technologies", () => {
    const old = makeResult();
    const newer = makeResult({
      detectedTechnologies: [
        { name: "Nginx", version: "1.24", category: "Web Server", confidence: 90, evidence: "header" },
      ],
    });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.technologyDiff.removed).toHaveLength(1);
    expect(result.technologyDiff.removed[0].name).toBe("React");
  });

  it("should detect technology version changes", () => {
    const old = makeResult();
    const newer = makeResult({
      detectedTechnologies: [
        { name: "Nginx", version: "1.26", category: "Web Server", confidence: 90, evidence: "header" },
        { name: "React", version: "19.0", category: "JavaScript Library", confidence: 80, evidence: "html" },
      ],
    });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.technologyDiff.versionChanged).toHaveLength(2);
    expect(result.technologyDiff.versionChanged.find(t => t.name === "Nginx")?.oldVersion).toBe("1.24");
    expect(result.technologyDiff.versionChanged.find(t => t.name === "Nginx")?.newVersion).toBe("1.26");
  });

  it("should detect new exposed paths", () => {
    const old = makeResult();
    const newer = makeResult({
      exposedPaths: [
        ...makeResult().exposedPaths,
        { path: "/.env", status: 200, type: "config_file", severity: "critical", description: "Environment file exposed" },
      ],
    });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.exposedPathDiff.added).toHaveLength(1);
    expect(result.exposedPathDiff.added[0].path).toBe("/.env");
    expect(result.exposedPathDiff.added[0].severity).toBe("critical");
    expect(result.changeScore).toBeLessThan(0); // New critical exposed path = negative score
  });

  it("should detect removed exposed paths (secured)", () => {
    const old = makeResult({
      exposedPaths: [
        { path: "/robots.txt", status: 200, type: "info_disclosure", severity: "info", description: "Robots.txt" },
        { path: "/.git", status: 200, type: "version_control", severity: "high", description: "Git exposed" },
      ],
    });
    const newer = makeResult();
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.exposedPathDiff.removed).toHaveLength(1);
    expect(result.exposedPathDiff.removed[0].path).toBe("/.git");
    expect(result.changeScore).toBeGreaterThan(0); // Removed high-severity path = positive score
  });

  it("should detect new cookies", () => {
    const old = makeResult();
    const newer = makeResult({
      cookies: [
        ...makeResult().cookies,
        { name: "tracking", secure: false, httpOnly: false, sameSite: null, domain: "example.com", path: "/", issues: ["Missing Secure flag"] },
      ],
    });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.cookieDiff.added).toHaveLength(1);
    expect(result.cookieDiff.added[0].name).toBe("tracking");
  });

  it("should detect cookie security changes", () => {
    const old = makeResult();
    const newer = makeResult({
      cookies: [
        { name: "session", secure: false, httpOnly: true, sameSite: "Lax", domain: "example.com", path: "/", issues: ["Missing Secure flag"] },
      ],
    });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.cookieDiff.changed).toHaveLength(1);
    expect(result.cookieDiff.changed[0].name).toBe("session");
    expect(result.cookieDiff.changed[0].changes).toContain("Secure: true → false");
  });

  it("should detect TLS certificate changes", () => {
    const old = makeResult();
    const newer = makeResult({
      tlsInfo: { issuer: "DigiCert", subject: "example.com", validTo: "2027-01-01", protocol: "TLSv1.3", cipher: "AES-256-GCM" },
    });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.tlsChanged).toBe(true);
    expect(result.tlsChanges).toContain("Issuer changed: Let's Encrypt → DigiCert");
    expect(result.tlsChanges).toContain("Expiry changed: 2026-06-01 → 2027-01-01");
  });

  it("should calculate response time delta", () => {
    const old = makeResult({ responseTimeMs: 200 });
    const newer = makeResult({ responseTimeMs: 350 });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.responseTimeDelta.old).toBe(200);
    expect(result.responseTimeDelta.new).toBe(350);
    expect(result.responseTimeDelta.changeMs).toBe(150);
    expect(result.responseTimeDelta.changePct).toBe(75);
  });

  it("should calculate content size delta", () => {
    const old = makeResult({ contentLength: 40000 });
    const newer = makeResult({ contentLength: 50000 });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.contentSizeDelta.old).toBe(40000);
    expect(result.contentSizeDelta.new).toBe(50000);
    expect(result.contentSizeDelta.changeBytes).toBe(10000);
    expect(result.contentSizeDelta.changePct).toBe(25);
  });

  it("should detect header additions (newly present)", () => {
    const old = makeResult();
    const newer = makeResult({
      securityHeaders: {
        present: [
          ...makeResult().securityHeaders.present,
          { name: "content-security-policy", value: "default-src 'self'", status: "good" },
        ],
        missing: [],
        misconfigured: [],
      },
    });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.headerDiff.present.some(h => h.type === "added" && h.label === "content-security-policy")).toBe(true);
  });

  it("should detect header removals", () => {
    const old = makeResult();
    const newer = makeResult({
      securityHeaders: {
        present: [
          { name: "x-content-type-options", value: "nosniff", status: "good" },
        ],
        missing: makeResult().securityHeaders.missing,
        misconfigured: [],
      },
    });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.headerDiff.present.some(h => h.type === "removed" && h.label === "strict-transport-security")).toBe(true);
  });

  it("should calculate link count deltas", () => {
    const old = makeResult({ internalLinks: ["a", "b", "c"], externalLinks: ["x"] });
    const newer = makeResult({ internalLinks: ["a", "b", "c", "d", "e"], externalLinks: ["x", "y", "z"] });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.linkCountDelta.oldInternal).toBe(3);
    expect(result.linkCountDelta.newInternal).toBe(5);
    expect(result.linkCountDelta.oldExternal).toBe(1);
    expect(result.linkCountDelta.newExternal).toBe(3);
  });

  it("should calculate form count deltas", () => {
    const old = makeResult({ forms: [{ action: "/login" }] });
    const newer = makeResult({ forms: [{ action: "/login" }, { action: "/register" }, { action: "/search" }] });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.formCountDelta.old).toBe(1);
    expect(result.formCountDelta.new).toBe(3);
  });

  it("should classify overall change as 'improved' when positive score", () => {
    const old = makeResult({ securityHeaderGrade: "D" });
    const newer = makeResult({
      securityHeaderGrade: "A+",
      findings: [
        { severity: "low", title: "Server version disclosed", category: "Information Disclosure", description: "Minor" },
      ],
    });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.overallChange).toBe("improved");
    expect(result.changeScore).toBeGreaterThan(10);
  });

  it("should classify overall change as 'regressed' when negative score", () => {
    const old = makeResult({ securityHeaderGrade: "A+" });
    const newer = makeResult({
      securityHeaderGrade: "D",
      findings: [
        ...makeResult().findings,
        { severity: "critical", title: "RCE Vulnerability", category: "Vulnerability", description: "Remote code execution" },
      ],
    });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.overallChange).toBe("regressed");
    expect(result.changeScore).toBeLessThan(-10);
  });

  it("should handle empty/null fields gracefully", () => {
    const old = makeResult({
      securityHeaders: null,
      detectedTechnologies: null,
      findings: null,
      exposedPaths: null,
      cookies: null,
      tlsInfo: null,
      internalLinks: null,
      externalLinks: null,
      forms: null,
    });
    const newer = makeResult();
    const result = compareCrawlResults(old, newer, "example.com");

    // Should not throw and should detect all items as new
    expect(result.domain).toBe("example.com");
    expect(result.technologyDiff.added.length).toBeGreaterThan(0);
    expect(result.findingDiff.added.length).toBeGreaterThan(0);
  });

  it("should clamp change score between -100 and 100", () => {
    const old = makeResult({ securityHeaderGrade: "A+" });
    const newer = makeResult({
      securityHeaderGrade: "F",
      findings: Array.from({ length: 20 }, (_, i) => ({
        severity: "critical",
        title: `Critical Finding ${i}`,
        category: "Vulnerability",
        description: `Critical ${i}`,
      })),
    });
    const result = compareCrawlResults(old, newer, "example.com");

    expect(result.changeScore).toBeGreaterThanOrEqual(-100);
    expect(result.changeScore).toBeLessThanOrEqual(100);
  });
});
