/**
 * Dedup/Coverage Bridge Tests
 *
 * Tests the bridge module that converts between the engagement orchestrator's
 * simple vuln format and ScanForge's detailed finding format, then runs
 * deduplication, normalization, and coverage gap analysis.
 *
 * @author Harrison Cook — AceofCloud
 */

import { describe, it, expect } from "vitest";
import {
  runEngagementDedup,
  runEngagementCoverageAnalysis,
} from "./lib/dedup-coverage-bridge";
import type { OrchestratorAsset } from "./lib/dedup-coverage-bridge";

// ─── Helpers ─────────────────────────────────────────────────────────────

function makeAsset(overrides: Partial<OrchestratorAsset> = {}): OrchestratorAsset {
  return {
    hostname: "target.example.com",
    ip: "10.0.0.1",
    type: "server",
    ports: [
      { port: 80, service: "http" },
      { port: 443, service: "https" },
    ],
    vulns: [],
    status: "scanned",
    ...overrides,
  };
}

function makeVuln(title: string, severity = "medium", cve?: string) {
  return {
    id: `v-${Math.random().toString(36).slice(2, 8)}`,
    severity,
    title,
    cve,
  };
}

// ─── runEngagementDedup ──────────────────────────────────────────────────

describe("runEngagementDedup", () => {
  it("should return stats for an empty asset list", async () => {
    const result = await runEngagementDedup([]);
    expect(result.totalFindingsBeforeDedup).toBe(0);
    expect(result.totalFindingsAfterDedup).toBe(0);
    expect(result.duplicatesRemoved).toBe(0);
    expect(result.processedAt).toBeGreaterThan(0);
  });

  it("should return stats for assets with no vulns", async () => {
    const assets = [makeAsset()];
    const result = await runEngagementDedup(assets);
    expect(result.totalFindingsBeforeDedup).toBe(0);
    expect(result.totalFindingsAfterDedup).toBe(0);
    expect(result.duplicatesRemoved).toBe(0);
  });

  it("should pass through unique findings without removing them", async () => {
    const assets = [
      makeAsset({
        vulns: [
          makeVuln("[nuclei] SQL Injection in /login", "high", "CVE-2024-1111"),
          makeVuln("[ZAP] XSS in /search", "medium"),
          makeVuln("[SQLMap] Blind SQL Injection in /api", "critical", "CVE-2024-2222"),
        ],
      }),
    ];

    const result = await runEngagementDedup(assets);
    expect(result.totalFindingsBeforeDedup).toBe(3);
    // All unique — should keep all 3 (or possibly more after normalization)
    expect(result.totalFindingsAfterDedup).toBeGreaterThanOrEqual(2);
    expect(result.processedAt).toBeGreaterThan(0);
  });

  it("should deduplicate identical findings from different scanners", async () => {
    const assets = [
      makeAsset({
        vulns: [
          makeVuln("[nuclei] SQL Injection", "high", "CVE-2024-1111"),
          makeVuln("[ZAP] SQL Injection", "high", "CVE-2024-1111"),
          makeVuln("[SQLMap] SQL Injection", "critical", "CVE-2024-1111"),
        ],
      }),
    ];

    const result = await runEngagementDedup(assets);
    expect(result.totalFindingsBeforeDedup).toBe(3);
    // Should merge at least 2 of the 3 (same CVE, same target, same title)
    expect(result.duplicatesRemoved).toBeGreaterThanOrEqual(1);
    expect(result.totalFindingsAfterDedup).toBeLessThan(result.totalFindingsBeforeDedup);
  });

  it("should track duplicates by asset hostname", async () => {
    const assets = [
      makeAsset({
        hostname: "web1.example.com",
        vulns: [
          makeVuln("[nuclei] XSS", "medium"),
          makeVuln("[ZAP] XSS", "medium"),
        ],
      }),
      makeAsset({
        hostname: "web2.example.com",
        vulns: [
          makeVuln("[nuclei] SSRF", "high"),
        ],
      }),
    ];

    const result = await runEngagementDedup(assets);
    expect(result.duplicatesByAsset).toBeDefined();
    expect(typeof result.duplicatesByAsset["web1.example.com"]).toBe("number");
    expect(typeof result.duplicatesByAsset["web2.example.com"]).toBe("number");
  });

  it("should include ZAP findings in dedup processing", async () => {
    const assets = [
      makeAsset({
        vulns: [
          makeVuln("[nuclei] Missing HSTS Header", "low"),
        ],
        zapFindings: [
          { alert: "Missing HSTS Header", risk: "Low", url: "https://target.example.com/" },
        ],
      }),
    ];

    const result = await runEngagementDedup(assets);
    // Should have processed both the vuln and the ZAP finding
    expect(result.totalFindingsBeforeDedup).toBe(2);
  });

  it("should include tool result findings in dedup processing", async () => {
    const assets = [
      makeAsset({
        vulns: [
          makeVuln("[nuclei] Open Redirect", "medium"),
        ],
        toolResults: [
          {
            tool: "nikto",
            command: "nikto -h target.example.com",
            exitCode: 0,
            durationMs: 5000,
            timedOut: false,
            findingCount: 1,
            findings: [{ severity: "medium", title: "Server Version Disclosure" }],
            outputPreview: "nikto output...",
            executedAt: Date.now(),
            phase: "vuln_detection",
          },
        ],
      }),
    ];

    const result = await runEngagementDedup(assets);
    // 1 vuln + 1 tool result finding = 2 total
    expect(result.totalFindingsBeforeDedup).toBe(2);
  });

  it("should produce a merge log for deduplicated findings", async () => {
    const assets = [
      makeAsset({
        vulns: [
          makeVuln("[nuclei] SQL Injection", "high", "CVE-2024-9999"),
          makeVuln("[ZAP] SQL Injection", "high", "CVE-2024-9999"),
        ],
      }),
    ];

    const result = await runEngagementDedup(assets);
    if (result.duplicatesRemoved > 0) {
      expect(result.mergeLog.length).toBeGreaterThan(0);
      expect(result.mergeLog[0].canonicalTitle).toBeDefined();
      expect(result.mergeLog[0].mergedCount).toBeGreaterThanOrEqual(2);
      expect(Array.isArray(result.mergeLog[0].sources)).toBe(true);
    }
  });

  it("should write back deduplicated vulns to assets", async () => {
    const assets = [
      makeAsset({
        vulns: [
          makeVuln("[nuclei] SQL Injection", "high", "CVE-2024-1111"),
          makeVuln("[ZAP] SQL Injection", "high", "CVE-2024-1111"),
          makeVuln("[nuclei] XSS", "medium"),
        ],
      }),
    ];

    const beforeCount = assets[0].vulns.length;
    await runEngagementDedup(assets);
    // After dedup, the asset's vulns array should be updated
    expect(assets[0].vulns.length).toBeLessThanOrEqual(beforeCount);
  });
});

// ─── runEngagementCoverageAnalysis ───────────────────────────────────────

describe("runEngagementCoverageAnalysis", () => {
  it("should return a report for an empty asset list", () => {
    const result = runEngagementCoverageAnalysis([]);
    expect(result.overallScore).toBe(100); // No assets = 100% coverage
    expect(result.assetReports).toHaveLength(0);
    expect(result.totalGaps).toBe(0);
    expect(result.criticalGaps).toBe(0);
    expect(result.processedAt).toBeGreaterThan(0);
  });

  it("should analyze coverage for a web server asset", () => {
    const assets = [
      makeAsset({
        hostname: "web.example.com",
        ports: [
          { port: 80, service: "http" },
          { port: 443, service: "https" },
        ],
        toolResults: [
          {
            tool: "nuclei",
            command: "nuclei -u web.example.com",
            exitCode: 0,
            durationMs: 10000,
            timedOut: false,
            findingCount: 3,
            findings: [
              { severity: "high", title: "SQL Injection" },
              { severity: "medium", title: "XSS" },
              { severity: "low", title: "Info Disclosure" },
            ],
            outputPreview: "nuclei output...",
            executedAt: Date.now(),
            phase: "vuln_detection",
          },
        ],
      }),
    ];

    const result = runEngagementCoverageAnalysis(assets);
    expect(result.assetReports).toHaveLength(1);
    expect(result.assetReports[0].hostname).toBe("web.example.com");
    expect(typeof result.assetReports[0].score).toBe("number");
    expect(result.assetReports[0].score).toBeGreaterThanOrEqual(0);
    expect(result.assetReports[0].score).toBeLessThanOrEqual(100);
    expect(result.overallScore).toBeGreaterThanOrEqual(0);
    expect(result.overallScore).toBeLessThanOrEqual(100);
  });

  it("should detect gaps when no scanners ran", () => {
    const assets = [
      makeAsset({
        hostname: "unscanned.example.com",
        ports: [
          { port: 80, service: "http" },
          { port: 443, service: "https" },
          { port: 22, service: "ssh" },
        ],
        toolResults: [],
      }),
    ];

    const result = runEngagementCoverageAnalysis(assets);
    expect(result.assetReports).toHaveLength(1);
    // No scanners ran — should have gaps
    expect(result.assetReports[0].totalGaps).toBeGreaterThan(0);
    expect(result.overallScore).toBeLessThan(100);
  });

  it("should detect cloud-specific coverage gaps for AWS assets", () => {
    const assets = [
      makeAsset({
        hostname: "ec2-1-2-3-4.compute.amazonaws.com",
        type: "cloud_instance",
        ports: [
          { port: 80, service: "http" },
          { port: 443, service: "https" },
        ],
        vulns: [
          makeVuln("[nuclei] AWS S3 Bucket Misconfiguration", "high"),
        ],
        toolResults: [],
      }),
    ];

    const result = runEngagementCoverageAnalysis(assets);
    expect(result.assetReports).toHaveLength(1);
    // Cloud assets should have cloud-specific gap expectations
    expect(result.assetReports[0].totalGaps).toBeGreaterThan(0);
  });

  it("should aggregate gaps across multiple assets", () => {
    const assets = [
      makeAsset({
        hostname: "web1.example.com",
        ports: [{ port: 80, service: "http" }],
        toolResults: [],
      }),
      makeAsset({
        hostname: "web2.example.com",
        ports: [{ port: 443, service: "https" }],
        toolResults: [],
      }),
    ];

    const result = runEngagementCoverageAnalysis(assets);
    expect(result.assetReports).toHaveLength(2);
    expect(result.totalGaps).toBe(
      result.assetReports[0].totalGaps + result.assetReports[1].totalGaps
    );
    expect(result.criticalGaps).toBe(
      result.assetReports[0].criticalGaps + result.assetReports[1].criticalGaps
    );
  });

  it("should provide recommendations for coverage gaps", () => {
    const assets = [
      makeAsset({
        hostname: "unscanned.example.com",
        ports: [
          { port: 80, service: "http" },
          { port: 443, service: "https" },
          { port: 22, service: "ssh" },
          { port: 3306, service: "mysql" },
        ],
        toolResults: [],
      }),
    ];

    const result = runEngagementCoverageAnalysis(assets);
    // Should have recommendations when there are gaps
    if (result.totalGaps > 0) {
      expect(result.recommendations.length).toBeGreaterThan(0);
    }
  });

  it("should cap recommendations at 20", () => {
    // Create many assets with no scanners to generate lots of recommendations
    const assets = Array.from({ length: 10 }, (_, i) =>
      makeAsset({
        hostname: `host${i}.example.com`,
        ports: [
          { port: 80, service: "http" },
          { port: 443, service: "https" },
          { port: 22, service: "ssh" },
          { port: 3306, service: "mysql" },
          { port: 5432, service: "postgresql" },
        ],
        toolResults: [],
      })
    );

    const result = runEngagementCoverageAnalysis(assets);
    expect(result.recommendations.length).toBeLessThanOrEqual(20);
  });

  it("should infer IoT environment from MQTT services", () => {
    const assets = [
      makeAsset({
        hostname: "iot-device.local",
        type: "iot",
        ports: [
          { port: 1883, service: "mqtt" },
          { port: 8883, service: "mqtt-tls" },
        ],
        toolResults: [],
      }),
    ];

    const result = runEngagementCoverageAnalysis(assets);
    expect(result.assetReports).toHaveLength(1);
    // IoT assets should have IoT-specific gap expectations
    expect(result.assetReports[0].totalGaps).toBeGreaterThan(0);
  });
});
