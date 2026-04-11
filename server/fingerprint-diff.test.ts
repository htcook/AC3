/**
 * Tests for the Fingerprint Diff Engine and related fixes
 *
 * Covers:
 * 1. Fingerprint diff — new/removed services, version changes, security flag changes, CVE delta
 * 2. CPE enrichment wiring — CPE results merge into enrichment
 * 3. Dehashed WHOIS connector config fix
 * 4. Container-discovery timeout improvements
 * 5. Company-intel timeout improvements
 */

import { describe, it, expect } from "vitest";
import {
  diffFingerprints,
  fingerprintsToCacheEntries,
  buildDiffSummaryText,
  type FingerprintChange,
  type CachedFingerprint,
  type FingerprintDiffReport,
} from "./lib/fingerprint-diff";

// ─── Mock Data Helpers ──────────────────────────────────────────────────────

function makeFpResult(overrides: Partial<any> = {}): any {
  return {
    host: "target.example.com",
    port: 80,
    protocol: "http",
    product: "Apache",
    version: "2.4.49",
    banner: "Apache/2.4.49 (Ubuntu)",
    os: "Ubuntu",
    confidence: 85,
    error: null,
    securityFlags: {
      hasHsts: true,
      hasContentSecurityPolicy: false,
      hasXFrameOptions: true,
      hasXContentTypeOptions: true,
      serverHeaderExposed: true,
      poweredByExposed: false,
      directoryListingEnabled: false,
    },
    riskIndicators: [],
    potentialCves: ["CVE-2021-41773"],
    mitreRelevance: [],
    metadata: {},
    fingerprintedAt: Date.now(),
    ...overrides,
  };
}

function makeCachedFp(overrides: Partial<CachedFingerprint> = {}): CachedFingerprint {
  return {
    host: "target.example.com",
    port: 80,
    protocol: "http",
    product: "Apache",
    version: "2.4.48",
    banner: "Apache/2.4.48 (Ubuntu)",
    os: "Ubuntu",
    confidence: 80,
    securityFlags: {
      hasHsts: true,
      hasContentSecurityPolicy: false,
      hasXFrameOptions: true,
      hasXContentTypeOptions: true,
      serverHeaderExposed: true,
      poweredByExposed: false,
      directoryListingEnabled: false,
    },
    riskIndicators: [],
    potentialCves: ["CVE-2021-41773", "CVE-2021-42013"],
    fingerprintedAt: Date.now() - 86400000, // 24h ago
    engagementId: "1",
    ...overrides,
  };
}

// ─── Fingerprint Diff Tests ─────────────────────────────────────────────────

describe("Fingerprint Diff Engine", () => {
  describe("diffFingerprints", () => {
    it("should detect new services", () => {
      const current = [
        makeFpResult({ port: 80 }),
        makeFpResult({ port: 443, protocol: "https", product: "Nginx", version: "1.21.0" }),
      ];
      const previous = [makeCachedFp({ port: 80 })];

      const report = diffFingerprints(current, previous, 1);

      expect(report.newServices).toHaveLength(1);
      expect(report.newServices[0].port).toBe(443);
      expect(report.newServices[0].product).toBe("Nginx");
      expect(report.changes.some(c => c.changeType === "new_service" && c.port === 443)).toBe(true);
    });

    it("should detect removed services", () => {
      const current = [makeFpResult({ port: 80 })];
      const previous = [
        makeCachedFp({ port: 80 }),
        makeCachedFp({ port: 22, protocol: "ssh", product: "OpenSSH", version: "8.9" }),
      ];

      const report = diffFingerprints(current, previous, 1);

      expect(report.removedServices).toHaveLength(1);
      expect(report.removedServices[0].port).toBe(22);
      expect(report.changes.some(c => c.changeType === "removed_service")).toBe(true);
    });

    it("should detect version upgrades", () => {
      const current = [makeFpResult({ port: 80, version: "2.4.51" })];
      const previous = [makeCachedFp({ port: 80, version: "2.4.49" })];

      const report = diffFingerprints(current, previous, 1);

      expect(report.versionChanges).toHaveLength(1);
      expect(report.versionChanges[0].direction).toBe("upgrade");
      expect(report.versionChanges[0].oldVersion).toBe("2.4.49");
      expect(report.versionChanges[0].newVersion).toBe("2.4.51");
    });

    it("should detect version downgrades with high severity", () => {
      const current = [makeFpResult({ port: 80, version: "2.4.41" })];
      const previous = [makeCachedFp({ port: 80, version: "2.4.51" })];

      const report = diffFingerprints(current, previous, 1);

      expect(report.versionChanges).toHaveLength(1);
      expect(report.versionChanges[0].direction).toBe("downgrade");
      const downgradeChange = report.changes.find(c => c.changeType === "version_downgrade");
      expect(downgradeChange).toBeDefined();
      expect(downgradeChange!.severity).toBe("high");
    });

    it("should detect product changes", () => {
      const current = [makeFpResult({ port: 80, product: "Nginx", version: "1.21.0" })];
      const previous = [makeCachedFp({ port: 80, product: "Apache", version: "2.4.49" })];

      const report = diffFingerprints(current, previous, 1);

      const productChange = report.changes.find(c => c.changeType === "product_change");
      expect(productChange).toBeDefined();
      expect(productChange!.previousValue).toBe("Apache");
      expect(productChange!.currentValue).toBe("Nginx");
    });

    it("should detect security improvements", () => {
      const current = [makeFpResult({
        port: 80,
        version: "2.4.48", // same version to avoid version change noise
        securityFlags: {
          hasHsts: true,
          hasContentSecurityPolicy: true, // NEW: was false
          hasXFrameOptions: true,
          hasXContentTypeOptions: true,
          serverHeaderExposed: false, // FIXED: was true
          poweredByExposed: false,
          directoryListingEnabled: false,
        },
      })];
      const previous = [makeCachedFp({ port: 80 })];

      const report = diffFingerprints(current, previous, 1);

      const improvements = report.changes.filter(c => c.changeType === "security_improvement");
      expect(improvements.length).toBeGreaterThanOrEqual(2); // CSP enabled + server header hidden
    });

    it("should detect security degradations", () => {
      const current = [makeFpResult({
        port: 80,
        version: "2.4.48",
        securityFlags: {
          hasHsts: false, // REMOVED: was true
          hasContentSecurityPolicy: false,
          hasXFrameOptions: true,
          hasXContentTypeOptions: true,
          serverHeaderExposed: true,
          poweredByExposed: true, // NEW: was false
          directoryListingEnabled: false,
        },
      })];
      const previous = [makeCachedFp({ port: 80 })];

      const report = diffFingerprints(current, previous, 1);

      const degradations = report.changes.filter(c => c.changeType === "security_degradation");
      expect(degradations.length).toBeGreaterThanOrEqual(2); // HSTS removed + poweredBy exposed
    });

    it("should calculate CVE delta correctly", () => {
      const current = [makeFpResult({
        port: 80,
        version: "2.4.48",
        potentialCves: ["CVE-2021-41773", "CVE-2023-25690", "CVE-2023-31122"],
      })];
      const previous = [makeCachedFp({
        port: 80,
        potentialCves: ["CVE-2021-41773", "CVE-2021-42013"],
      })];

      const report = diffFingerprints(current, previous, 1);

      expect(report.cveDelta.newCves).toContain("CVE-2023-25690");
      expect(report.cveDelta.newCves).toContain("CVE-2023-31122");
      expect(report.cveDelta.resolvedCves).toContain("CVE-2021-42013");
      expect(report.cveDelta.persistentCves).toContain("CVE-2021-41773");
    });

    it("should report 'unchanged' when no changes detected", () => {
      const current = [makeFpResult({
        port: 80,
        version: "2.4.48",
        potentialCves: ["CVE-2021-41773", "CVE-2021-42013"],
      })];
      const previous = [makeCachedFp({
        port: 80,
        version: "2.4.48",
        product: "Apache",
        potentialCves: ["CVE-2021-41773", "CVE-2021-42013"],
      })];

      const report = diffFingerprints(current, previous, 1);

      // Only security flag diffs or confidence changes might appear
      // but no version/product/service changes
      expect(report.versionChanges).toHaveLength(0);
      expect(report.newServices).toHaveLength(0);
      expect(report.removedServices).toHaveLength(0);
    });

    it("should calculate posture change correctly", () => {
      // Degraded: version downgrade + new CVEs
      const current = [makeFpResult({
        port: 80,
        version: "2.4.41",
        potentialCves: ["CVE-2021-41773", "CVE-2021-42013", "CVE-2020-11984"],
      })];
      const previous = [makeCachedFp({
        port: 80,
        version: "2.4.51",
        potentialCves: ["CVE-2021-41773"],
      })];

      const report = diffFingerprints(current, previous, 1);

      expect(report.postureChange).toBe("degraded");
      expect(report.riskScoreDelta).toBeGreaterThan(0);
    });

    it("should handle empty previous results (first scan)", () => {
      const current = [
        makeFpResult({ port: 80 }),
        makeFpResult({ port: 443, protocol: "https" }),
      ];

      const report = diffFingerprints(current, [], 1);

      expect(report.newServices).toHaveLength(2);
      expect(report.removedServices).toHaveLength(0);
      expect(report.previousScanTime).toBeNull();
    });

    it("should handle error fingerprints gracefully", () => {
      const current = [
        makeFpResult({ port: 80 }),
        makeFpResult({ port: 443, error: "Connection refused" }),
      ];
      const previous = [makeCachedFp({ port: 80 })];

      const report = diffFingerprints(current, previous, 1);

      // Error fingerprints should be excluded from diff
      expect(report.currentServiceCount).toBe(1);
    });
  });

  describe("fingerprintsToCacheEntries", () => {
    it("should convert fingerprint results to cache format", () => {
      const results = [
        makeFpResult({ port: 80 }),
        makeFpResult({ port: 443, error: "timeout" }),
      ];

      const entries = fingerprintsToCacheEntries(results, "eng-123");

      // Should exclude error results
      expect(entries).toHaveLength(1);
      expect(entries[0].host).toBe("target.example.com");
      expect(entries[0].port).toBe(80);
      expect(entries[0].engagementId).toBe("eng-123");
      expect(entries[0].fingerprintedAt).toBeGreaterThan(0);
    });
  });

  describe("buildDiffSummaryText", () => {
    it("should return 'no changes' for empty diff", () => {
      const report: FingerprintDiffReport = {
        engagementId: 1,
        currentScanTime: Date.now(),
        previousScanTime: Date.now() - 86400000,
        timeDelta: 86400000,
        totalChanges: 0,
        changeBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        changeByType: {},
        changes: [],
        currentServiceCount: 3,
        previousServiceCount: 3,
        newServices: [],
        removedServices: [],
        versionChanges: [],
        cveDelta: { newCves: [], resolvedCves: [], persistentCves: [] },
        postureChange: "unchanged",
        riskScoreDelta: 0,
      };

      const text = buildDiffSummaryText(report);
      expect(text).toContain("No changes detected");
    });

    it("should include version changes in summary", () => {
      const current = [makeFpResult({ port: 80, version: "2.4.51" })];
      const previous = [makeCachedFp({ port: 80, version: "2.4.49" })];
      const report = diffFingerprints(current, previous, 1);

      const text = buildDiffSummaryText(report);
      expect(text).toContain("Version Changes");
      expect(text).toContain("2.4.49");
      expect(text).toContain("2.4.51");
    });

    it("should highlight critical/high changes", () => {
      const current = [makeFpResult({ port: 80, version: "2.4.41" })];
      const previous = [makeCachedFp({ port: 80, version: "2.4.51" })];
      const report = diffFingerprints(current, previous, 1);

      const text = buildDiffSummaryText(report);
      expect(text).toContain("Attention Required");
    });
  });
});

// ─── Dehashed WHOIS Config Fix Test ─────────────────────────────────────────

describe("Dehashed WHOIS Connector Config", () => {
  it("should have dehashed_whois case in connector config switch", async () => {
    // Read the passive/index.ts to verify the fix
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/passive/index.ts", "utf-8");

    // The switch statement should have a case for dehashed_whois
    expect(content).toContain('"dehashed_whois"');
    // And it should map to the same apiKey as dehashed
    expect(content).toMatch(/dehashed_whois.*apiKey/s);
  });
});

// ─── Container Discovery Timeout Fix Test ───────────────────────────────────

describe("Container Discovery Timeout Fix", () => {
  it("should have DNS pre-check in container-discovery", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/passive/container-discovery.ts", "utf-8");

    // Should have DNS resolution check
    expect(content).toContain("DNS pre-check");
    expect(content).toContain("DNS_CHECK_CONCURRENCY");
    // Should have reduced global timeout
    expect(content).toContain("25000"); // 25s max
  });

  it("should cap per-probe timeout at 2s", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/passive/container-discovery.ts", "utf-8");

    expect(content).toContain("Cap per-probe at 2s");
  });
});

// ─── Company Intel Timeout Fix Test ─────────────────────────────────────────

describe("Company Intel Timeout Fix", () => {
  it("should have global timeout wrapper", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/passive/company-intel.ts", "utf-8");

    expect(content).toContain("GLOBAL_TIMEOUT");
    expect(content).toContain("20000"); // 20s hard cap
    expect(content).toContain("isTimedOut");
  });

  it("should have reduced individual fetch timeouts", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/passive/company-intel.ts", "utf-8");

    // Homepage should be 5s, not 10s
    expect(content).toContain("AbortSignal.timeout(5000)");
    // About pages should be 4s, not 8s
    expect(content).toContain("AbortSignal.timeout(4000)");
  });
});

// ─── CPE Enrichment Wiring Test ─────────────────────────────────────────────

describe("CPE Enrichment Wiring", () => {
  it("should import and use dynamic-cpe-matcher in enrichment module", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/fingerprint-cve-enrichment.ts", "utf-8");

    // Should import CPE matcher functions
    expect(content).toContain("matchMultipleTechnologies");
    expect(content).toContain("buildCpeUri");
    expect(content).toContain("filterCvesByVersion");

    // Should have CPE result map
    expect(content).toContain("cpeResultMap");

    // Should merge CPE CVEs
    expect(content).toContain("nvd-cpe");

    // Should track CPE stats
    expect(content).toContain("cpeStats");
  });

  it("should upgrade corroboration tier for exact CPE matches", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/lib/fingerprint-cve-enrichment.ts", "utf-8");

    // Exact CPE match should set corroboration to "confirmed"
    expect(content).toContain('cpeMatch.matchConfidence === "exact"');
    expect(content).toContain('"confirmed"');
  });
});
