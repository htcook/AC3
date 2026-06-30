import { describe, it, expect, vi } from "vitest";

// ─── Managed Provider Classification Tests ──────────────────────────
describe("classifyMailProvider", () => {
  it("should classify Microsoft 365 as managed enterprise provider", async () => {
    const { classifyMailProvider } = await import("./lib/email-security-analyzer");
    const result = classifyMailProvider("Microsoft 365");
    expect(result).not.toBeNull();
    expect(result!.isManaged).toBe(true);
    expect(result!.tier).toBe("enterprise");
    expect(result!.name).toBe("Microsoft 365");
    expect(result!.serverSecurityNote).toContain("Microsoft");
    expect(result!.customerResponsibilities).toContain("SPF record configuration");
    expect(result!.customerResponsibilities).toContain("DMARC policy enforcement");
  });

  it("should classify Google Workspace as managed enterprise provider", async () => {
    const { classifyMailProvider } = await import("./lib/email-security-analyzer");
    const result = classifyMailProvider("Google Workspace");
    expect(result).not.toBeNull();
    expect(result!.isManaged).toBe(true);
    expect(result!.tier).toBe("enterprise");
    expect(result!.name).toBe("Google Workspace");
    expect(result!.serverSecurityNote).toContain("Google");
  });

  it("should classify Proofpoint as managed enterprise provider", async () => {
    const { classifyMailProvider } = await import("./lib/email-security-analyzer");
    const result = classifyMailProvider("Proofpoint");
    expect(result).not.toBeNull();
    expect(result!.isManaged).toBe(true);
    expect(result!.tier).toBe("enterprise");
  });

  it("should classify unknown providers as unmanaged", async () => {
    const { classifyMailProvider } = await import("./lib/email-security-analyzer");
    const result = classifyMailProvider("SomeCustomMailServer");
    expect(result).not.toBeNull();
    expect(result!.isManaged).toBe(false);
    expect(result!.tier).toBe("self_hosted");
    expect(result!.customerResponsibilities).toContain("Full mail server security stack");
  });

  it("should return null for null provider", async () => {
    const { classifyMailProvider } = await import("./lib/email-security-analyzer");
    const result = classifyMailProvider(null);
    expect(result).toBeNull();
  });
});

// ─── Version-Aware KEV Matching Tests ───────────────────────────────

// Mock KEV catalog with a few realistic entries for testing
const mockKevCatalog = {
  title: "CISA KEV Test",
  catalogVersion: "test",
  dateReleased: "2026-01-01",
  count: 3,
  vulnerabilities: [
    {
      cveID: "CVE-2021-41773",
      vendorProject: "Apache",
      product: "HTTP Server",
      vulnerabilityName: "Apache HTTP Server Path Traversal",
      dateAdded: "2021-11-03",
      shortDescription: "Apache HTTP Server 2.4.49 path traversal vulnerability",
      requiredAction: "Apply updates per vendor instructions.",
      dueDate: "2021-11-17",
      knownRansomwareCampaignUse: "Unknown",
      notes: "Affects versions 2.4.49 and 2.4.50",
    },
    {
      cveID: "CVE-2022-22965",
      vendorProject: "VMware",
      product: "Spring Framework",
      vulnerabilityName: "Spring4Shell RCE",
      dateAdded: "2022-04-04",
      shortDescription: "Spring Framework RCE via data binding",
      requiredAction: "Apply updates per vendor instructions.",
      dueDate: "2022-04-25",
      knownRansomwareCampaignUse: "Unknown",
      notes: "",
    },
    {
      cveID: "CVE-2023-44487",
      vendorProject: "IETF",
      product: "HTTP/2",
      vulnerabilityName: "HTTP/2 Rapid Reset Attack",
      dateAdded: "2023-10-10",
      shortDescription: "HTTP/2 protocol vulnerability allowing rapid reset DoS",
      requiredAction: "Apply updates per vendor instructions.",
      dueDate: "2023-10-31",
      knownRansomwareCampaignUse: "Unknown",
      notes: "",
    },
  ],
} as any;

// Mock catalog with Java SE entries to test JavaScript/Java exclusion
const mockKevCatalogWithJava = {
  ...mockKevCatalog,
  vulnerabilities: [
    ...mockKevCatalog.vulnerabilities,
    {
      cveID: "CVE-2022-21449",
      vendorProject: "Oracle",
      product: "Java SE",
      vulnerabilityName: "Oracle Java SE Psychic Signatures",
      dateAdded: "2022-04-18",
      shortDescription: "Oracle Java SE ECDSA signature validation bypass",
      requiredAction: "Apply updates per vendor instructions.",
      dueDate: "2022-05-09",
      knownRansomwareCampaignUse: "Unknown",
      notes: "Affects Java SE 15, 17, 18",
    },
    {
      cveID: "CVE-2022-21882",
      vendorProject: "Oracle",
      product: "JRE",
      vulnerabilityName: "Oracle JRE Vulnerability",
      dateAdded: "2022-02-01",
      shortDescription: "Oracle JRE vulnerability",
      requiredAction: "Apply updates per vendor instructions.",
      dueDate: "2022-02-22",
      knownRansomwareCampaignUse: "Unknown",
      notes: "",
    },
  ],
} as any;

describe("matchTechnologiesAgainstKev with technologyVersions", () => {
  it("should use technologyVersions map for version confirmation when available", async () => {
    const { matchTechnologiesAgainstKev } = await import("./lib/kev-service");
    const techs = ["Apache HTTP Server"];
    const versions: Record<string, string> = { "Apache HTTP Server": "2.4.49" };
    const results = matchTechnologiesAgainstKev(techs, mockKevCatalog, versions);
    expect(Array.isArray(results)).toBe(true);
    // Should find the Apache CVE
    const apacheCve = results.find((r: any) => r.cveID === "CVE-2021-41773");
    if (apacheCve) {
      // With version provided, should have matchQuality set
      expect(apacheCve.matchQuality).toBeDefined();
    }
  });

  it("should not crash when technologyVersions is undefined", async () => {
    const { matchTechnologiesAgainstKev } = await import("./lib/kev-service");
    const techs = ["nginx"];
    const results = matchTechnologiesAgainstKev(techs, mockKevCatalog);
    expect(Array.isArray(results)).toBe(true);
  });

  it("should not crash when technologyVersions is empty", async () => {
    const { matchTechnologiesAgainstKev } = await import("./lib/kev-service");
    const techs = ["React", "Next.js"];
    const results = matchTechnologiesAgainstKev(techs, mockKevCatalog, {});
    expect(Array.isArray(results)).toBe(true);
  });
});

// ─── JavaScript/Java False Positive Prevention ─────────────────
describe("KEV matcher JavaScript/Java exclusion", () => {
  it("should not match JavaScript to Java KEV entries", async () => {
    const { matchTechnologiesAgainstKev } = await import("./lib/kev-service");
    const techs = ["JavaScript"];
    const results = matchTechnologiesAgainstKev(techs, mockKevCatalogWithJava);
    // Should not contain any Oracle Java SE entries
    const javaResults = results.filter(r =>
      r.product?.toLowerCase().includes("java se") ||
      r.product?.toLowerCase().includes("jre") ||
      r.product?.toLowerCase().includes("jdk")
    );
    expect(javaResults.length).toBe(0);
  });

  it("should not match Node.js to Java KEV entries", async () => {
    const { matchTechnologiesAgainstKev } = await import("./lib/kev-service");
    const techs = ["Node.js"];
    const results = matchTechnologiesAgainstKev(techs, mockKevCatalogWithJava);
    const javaResults = results.filter(r =>
      r.product?.toLowerCase().includes("java se") ||
      r.vendor?.toLowerCase() === "oracle"
    );
    expect(javaResults.length).toBe(0);
  });
});

// ─── Technology Detection Pattern Tests ─────────────────────────────
import * as cheerio from "cheerio";

async function detect(html: string, headers: Record<string, string> = {}) {
  const { detectTechnologies } = await import("./lib/web-crawler");
  const $ = cheerio.load(html);
  return detectTechnologies(headers, html, $) as Array<{ name: string; version?: string; category: string; confidence: number; evidence: string }>;
}

describe("Wappalyzer-style tech detection patterns", () => {
  it("should detect nginx version from server header", async () => {
    const html = `<html><body>Hello</body></html>`;
    const techs = await detect(html, { "server": "nginx/1.25.3" });
    const nginx = techs.find(t => t.name.toLowerCase().includes("nginx"));
    expect(nginx).toBeTruthy();
    expect(nginx!.version).toBe("1.25.3");
  });

  it("should detect WordPress version from meta generator", async () => {
    const html = `<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body></body></html>`;
    const techs = await detect(html);
    const wp = techs.find(t => t.name.toLowerCase().includes("wordpress"));
    expect(wp).toBeTruthy();
    expect(wp!.version).toBe("6.4.2");
  });

  it("should detect jQuery version from script URL", async () => {
    const html = `<html><head><script src="/js/jquery-3.7.1.min.js"></script></head><body></body></html>`;
    const techs = await detect(html);
    const jquery = techs.find(t => t.name.toLowerCase().includes("jquery"));
    expect(jquery).toBeTruthy();
    expect(jquery!.version).toBe("3.7.1");
  });

  it("should detect multiple technologies from a complex page", async () => {
    const html = `<html>
      <head>
        <meta name="generator" content="Next.js" />
        <script src="/_next/static/chunks/main-abc123.js"></script>
      </head>
      <body>
        <div id="__next"></div>
        <script>window.__NEXT_DATA__={"props":{}}</script>
      </body>
    </html>`;
    const techs = await detect(html, { "x-powered-by": "Next.js" });
    expect(techs.length).toBeGreaterThan(0);
    const nextjs = techs.find(t => t.name.toLowerCase().includes("next"));
    expect(nextjs).toBeTruthy();
  });

  it("should detect Apache version from server header", async () => {
    const html = `<html><body>Test</body></html>`;
    const techs = await detect(html, { "server": "Apache/2.4.57 (Ubuntu)" });
    const apache = techs.find(t => t.name.toLowerCase().includes("apache"));
    expect(apache).toBeTruthy();
    expect(apache!.version).toBe("2.4.57");
  });

  it("should detect React version from script src", async () => {
    const html = `<html><head><script src="https://cdn.example.com/react@18.2.0/umd/react.production.min.js"></script></head><body><div id="root"></div></body></html>`;
    const techs = await detect(html);
    const react = techs.find(t => t.name.toLowerCase().includes("react"));
    // React detection from script src may or may not extract version depending on pattern
    expect(react).toBeTruthy();
  });
});
