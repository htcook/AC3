import { describe, it, expect } from "vitest";
import {
  mapServiceToTemplates,
  generateServiceScanTasks,
  getServiceBasedTags,
  getTemplateMappingSummary,
} from "./lib/service-template-mapper";
import type { FingerprintResult } from "./lib/service-fingerprinter";

// ─── Helper to build mock fingerprint results ───────────────────────────────

function makeFp(overrides: Partial<FingerprintResult> & { port: number; protocol: string }): FingerprintResult {
  return {
    port: overrides.port,
    protocol: overrides.protocol as any,
    banner: overrides.banner || null,
    product: overrides.product || null,
    version: overrides.version || null,
    os: overrides.os || null,
    securityFlags: overrides.securityFlags || {
      anonymousAccess: false,
      defaultCredentials: false,
      tlsSupported: false,
      encryptionEnabled: false,
    },
    riskIndicators: overrides.riskIndicators || [],
    potentialCves: overrides.potentialCves || [],
    error: overrides.error || undefined,
  } as FingerprintResult;
}

// ─── mapServiceToTemplates ──────────────────────────────────────────────────

describe("mapServiceToTemplates", () => {
  it("maps SSH protocol to ssh-related tags", () => {
    const fp = makeFp({ port: 22, protocol: "ssh" });
    const mapping = mapServiceToTemplates(fp);
    expect(mapping.tags).toContain("ssh");
    expect(mapping.tags).toContain("openssh");
    expect(mapping.tags).toContain("default-login");
    expect(mapping.networkScan).toBe(true);
  });

  it("maps MySQL protocol to database-related tags", () => {
    const fp = makeFp({ port: 3306, protocol: "mysql" });
    const mapping = mapServiceToTemplates(fp);
    expect(mapping.tags).toContain("mysql");
    expect(mapping.tags).toContain("database");
    expect(mapping.tags).toContain("default-login");
    expect(mapping.priority).toBe(1); // Databases are high priority
  });

  it("maps Redis protocol with anonymous access to priority 1", () => {
    const fp = makeFp({
      port: 6379,
      protocol: "redis",
      securityFlags: {
        anonymousAccess: true,
        defaultCredentials: false,
        tlsSupported: false,
        encryptionEnabled: false,
      },
    });
    const mapping = mapServiceToTemplates(fp);
    expect(mapping.tags).toContain("redis");
    expect(mapping.tags).toContain("unauth");
    expect(mapping.priority).toBe(1);
  });

  it("augments tags with product-specific mappings", () => {
    const fp = makeFp({ port: 22, protocol: "ssh", product: "OpenSSH" });
    const mapping = mapServiceToTemplates(fp);
    expect(mapping.tags).toContain("openssh");
  });

  it("augments tags for Elasticsearch product", () => {
    const fp = makeFp({ port: 9200, protocol: "http" as any, product: "Elasticsearch" });
    const mapping = mapServiceToTemplates(fp);
    expect(mapping.tags).toContain("elasticsearch");
    expect(mapping.tags).toContain("elastic");
    expect(mapping.tags).toContain("unauth");
  });

  it("adds version-matched CVE tags for OpenSSH 7.x", () => {
    const fp = makeFp({ port: 22, protocol: "ssh", product: "OpenSSH", version: "7.6p1" });
    const mapping = mapServiceToTemplates(fp);
    expect(mapping.tags).toContain("cve-2018-15473");
    expect(mapping.specificTemplates).toContain("CVE-2018-15473");
    expect(mapping.priority).toBe(1);
  });

  it("adds regreSSHion CVE for OpenSSH 9.x", () => {
    const fp = makeFp({ port: 22, protocol: "ssh", product: "OpenSSH", version: "9.3p1" });
    const mapping = mapServiceToTemplates(fp);
    expect(mapping.tags).toContain("cve-2024-6387");
    expect(mapping.tags).toContain("regresshion");
  });

  it("does NOT add old CVE tags for new OpenSSH versions", () => {
    const fp = makeFp({ port: 22, protocol: "ssh", product: "OpenSSH", version: "9.8p1" });
    const mapping = mapServiceToTemplates(fp);
    expect(mapping.tags).not.toContain("cve-2018-15473");
    expect(mapping.tags).not.toContain("cve-2024-6387");
  });

  it("adds default-creds tag when defaultCredentials flag is set", () => {
    const fp = makeFp({
      port: 3306,
      protocol: "mysql",
      securityFlags: {
        anonymousAccess: false,
        defaultCredentials: true,
        tlsSupported: false,
        encryptionEnabled: false,
      },
    });
    const mapping = mapServiceToTemplates(fp);
    expect(mapping.tags).toContain("default-login");
    expect(mapping.priority).toBe(1);
  });

  it("includes fingerprint-detected CVEs", () => {
    const fp = makeFp({
      port: 445,
      protocol: "smb",
      potentialCves: ["CVE-2017-0144", "CVE-2020-0796"],
    });
    const mapping = mapServiceToTemplates(fp);
    expect(mapping.tags).toContain("cve");
    expect(mapping.specificTemplates).toContain("CVE-2017-0144");
    expect(mapping.specificTemplates).toContain("CVE-2020-0796");
  });

  it("handles unknown protocol gracefully", () => {
    const fp = makeFp({ port: 9999, protocol: "custom-proto" as any });
    const mapping = mapServiceToTemplates(fp);
    expect(mapping.tags).toContain("network");
    expect(mapping.networkScan).toBe(true);
    expect(mapping.priority).toBe(3);
  });

  it("deduplicates tags", () => {
    const fp = makeFp({
      port: 6379,
      protocol: "redis",
      securityFlags: {
        anonymousAccess: true,
        defaultCredentials: false,
        tlsSupported: false,
        encryptionEnabled: false,
      },
    });
    const mapping = mapServiceToTemplates(fp);
    const uniqueTags = [...new Set(mapping.tags)];
    expect(mapping.tags.length).toBe(uniqueTags.length);
  });
});

// ─── generateServiceScanTasks ───────────────────────────────────────────────

describe("generateServiceScanTasks", () => {
  it("generates scan tasks for fingerprinted services", () => {
    const fps = [
      makeFp({ port: 22, protocol: "ssh", product: "OpenSSH", version: "7.6" }),
      makeFp({ port: 3306, protocol: "mysql" }),
    ];
    const tasks = generateServiceScanTasks("10.0.0.1", fps);
    expect(tasks.length).toBe(2);
    expect(tasks[0].nucleiArgs).toContain("-target 10.0.0.1:");
    expect(tasks[0].nucleiArgs).toContain("-tags ");
  });

  it("skips errored fingerprint results", () => {
    const fps = [
      makeFp({ port: 22, protocol: "ssh" }),
      { ...makeFp({ port: 80, protocol: "http" as any }), error: "Connection refused" },
    ];
    const tasks = generateServiceScanTasks("10.0.0.1", fps);
    expect(tasks.length).toBe(1);
    expect(tasks[0].port).toBe(22);
  });

  it("sorts tasks by priority (highest first)", () => {
    const fps = [
      makeFp({ port: 53, protocol: "dns" }), // priority 3
      makeFp({ port: 3306, protocol: "mysql" }), // priority 1
      makeFp({ port: 22, protocol: "ssh" }), // priority 2
    ];
    const tasks = generateServiceScanTasks("10.0.0.1", fps);
    expect(tasks[0].port).toBe(3306); // MySQL first (priority 1)
    expect(tasks[2].port).toBe(53); // DNS last (priority 3)
  });

  it("respects maxTasks limit", () => {
    const fps = Array.from({ length: 30 }, (_, i) =>
      makeFp({ port: 1000 + i, protocol: "ssh" }),
    );
    const tasks = generateServiceScanTasks("10.0.0.1", fps, { maxTasks: 5 });
    expect(tasks.length).toBe(5);
  });

  it("applies custom rate limit", () => {
    const fps = [makeFp({ port: 22, protocol: "ssh" })];
    const tasks = generateServiceScanTasks("10.0.0.1", fps, { rateLimit: 50 });
    expect(tasks[0].nucleiArgs).toContain("-rate-limit 50");
  });
});

// ─── getServiceBasedTags ────────────────────────────────────────────────────

describe("getServiceBasedTags", () => {
  it("returns empty for undefined input", () => {
    const result = getServiceBasedTags(undefined);
    expect(result.tags).toEqual([]);
    expect(result.rationale).toEqual([]);
  });

  it("returns empty for empty array", () => {
    const result = getServiceBasedTags([]);
    expect(result.tags).toEqual([]);
  });

  it("aggregates tags from multiple services", () => {
    const fps = [
      makeFp({ port: 22, protocol: "ssh" }),
      makeFp({ port: 3306, protocol: "mysql" }),
      makeFp({ port: 6379, protocol: "redis" }),
    ];
    const result = getServiceBasedTags(fps);
    expect(result.tags).toContain("ssh");
    expect(result.tags).toContain("mysql");
    expect(result.tags).toContain("redis");
    expect(result.tags).toContain("database");
  });

  it("includes product info in rationale", () => {
    const fps = [
      makeFp({ port: 22, protocol: "ssh", product: "OpenSSH", version: "8.9" }),
    ];
    const result = getServiceBasedTags(fps);
    expect(result.rationale[0]).toContain("OpenSSH");
    expect(result.rationale[0]).toContain("8.9");
  });

  it("skips errored results", () => {
    const fps = [
      { ...makeFp({ port: 22, protocol: "ssh" }), error: "timeout" },
    ];
    const result = getServiceBasedTags(fps);
    expect(result.tags).toEqual([]);
  });
});

// ─── getTemplateMappingSummary ───────────────────────────────────────────────

describe("getTemplateMappingSummary", () => {
  it("summarizes fingerprint-to-template mappings", () => {
    const fps = [
      makeFp({ port: 22, protocol: "ssh", product: "OpenSSH", version: "7.6" }),
      makeFp({ port: 3306, protocol: "mysql" }),
      makeFp({ port: 80, protocol: "http" as any }),
    ];
    const summary = getTemplateMappingSummary(fps);
    expect(summary.totalMapped).toBe(3);
    expect(summary.uniqueTags.length).toBeGreaterThan(0);
    expect(summary.serviceBreakdown.length).toBe(3);
  });

  it("counts high-priority services correctly", () => {
    const fps = [
      makeFp({ port: 3306, protocol: "mysql" }), // priority 1
      makeFp({ port: 6379, protocol: "redis" }), // priority 1
      makeFp({ port: 22, protocol: "ssh" }), // priority 2
    ];
    const summary = getTemplateMappingSummary(fps);
    expect(summary.highPriority).toBe(2);
  });

  it("collects version-matched CVEs", () => {
    const fps = [
      makeFp({ port: 22, protocol: "ssh", product: "OpenSSH", version: "7.6" }),
    ];
    const summary = getTemplateMappingSummary(fps);
    expect(summary.versionMatchedCves).toContain("CVE-2018-15473");
  });

  it("skips errored results in summary", () => {
    const fps = [
      makeFp({ port: 22, protocol: "ssh" }),
      { ...makeFp({ port: 80, protocol: "http" as any }), error: "refused" },
    ];
    const summary = getTemplateMappingSummary(fps);
    expect(summary.totalMapped).toBe(1);
  });
});
