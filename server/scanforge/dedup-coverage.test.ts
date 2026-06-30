/**
 * Deduplication, Normalization & Coverage Gap Detection Tests
 *
 * Tests the finding dedup engine, normalization layer, and FN coverage gap detector.
 *
 * @author Harrison Cook — AceofCloud
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  DeduplicationEngine,
  NormalizationEngine,
  CoverageGapDetector,
} from "./intelligence/dedup-coverage";
import type { ScanFinding, ScanTarget, ScanConfig, ScannerResult, ScanTemplate } from "./types";

// ─── Helper: build a minimal ScanFinding ──────────────────────────────────

function makeFinding(overrides: Partial<ScanFinding> & { id: string; source: string; title: string; target: string }): ScanFinding {
  return {
    severity: "medium",
    confidence: 80,
    description: "Test finding",
    evidence: { data: { raw: "test" } },
    timestamp: Date.now(),
    ...overrides,
  } as ScanFinding;
}

// ─── Deduplication Tests ──────────────────────────────────────────────────

describe("DeduplicationEngine", () => {
  let dedup: DeduplicationEngine;

  beforeEach(() => {
    dedup = new DeduplicationEngine();
  });

  it("should generate consistent fingerprints for identical findings", () => {
    const base = {
      id: "f1",
      source: "http-exposure-01",
      target: "example.com",
      port: 443,
      severity: "high" as const,
      title: "SQL Injection",
      description: "SQL injection in login form",
      evidence: { matchedPattern: "' OR 1=1 --" },
      cves: ["CVE-2024-1234"],
      cwes: ["CWE-89"],
      confidence: 90,
      timestamp: Date.now(),
    };

    const fp1 = dedup.computeFingerprint(base as ScanFinding);
    const fp2 = dedup.computeFingerprint({ ...base, id: "f2", timestamp: Date.now() + 1000 } as ScanFinding);
    expect(fp1.hash).toBe(fp2.hash);
  });

  it("should produce different fingerprints for different targets", () => {
    const base = makeFinding({
      id: "f1",
      source: "http-exposure-01",
      target: "example.com",
      port: 443,
      title: "SQL Injection",
    });

    const other = makeFinding({
      id: "f2",
      source: "http-exposure-01",
      target: "other.com",
      port: 443,
      title: "SQL Injection",
    });

    const fp1 = dedup.computeFingerprint(base);
    const fp2 = dedup.computeFingerprint(other);
    expect(fp1.hash).not.toBe(fp2.hash);
  });

  it("should deduplicate findings with identical fingerprints", () => {
    const findings: ScanFinding[] = [
      makeFinding({
        id: "f1",
        source: "http-exposure-01",
        target: "example.com",
        port: 443,
        title: "SQL Injection",
        cves: ["CVE-2024-1234"],
        confidence: 90,
      }),
      makeFinding({
        id: "f2",
        source: "http-exposure-01",
        target: "example.com",
        port: 443,
        title: "SQL Injection",
        cves: ["CVE-2024-1234"],
        confidence: 85,
      }),
      makeFinding({
        id: "f3",
        source: "dns-zone-transfer-01",
        target: "example.com",
        port: 53,
        title: "Zone Transfer Allowed",
        confidence: 95,
      }),
    ];

    const result = dedup.deduplicate(findings);
    expect(result.totalAfter).toBeLessThan(result.totalBefore);
    expect(result.duplicatesRemoved).toBeGreaterThanOrEqual(1);
  });

  it("should return stats about deduplication", () => {
    const findings: ScanFinding[] = [
      makeFinding({ id: "f1", source: "t1", target: "a.com", title: "Test", confidence: 80 }),
    ];

    const result = dedup.deduplicate(findings);
    expect(result.totalAfter).toBe(1);
    expect(result.duplicatesRemoved).toBe(0);
    expect(result.totalBefore).toBe(1);
  });

  it("should handle empty findings array", () => {
    const result = dedup.deduplicate([]);
    expect(result.totalAfter).toBe(0);
    expect(result.duplicatesRemoved).toBe(0);
    expect(result.totalBefore).toBe(0);
  });

  it("should keep the highest-confidence finding as canonical", () => {
    const findings: ScanFinding[] = [
      makeFinding({
        id: "low-conf",
        source: "scanner-a",
        target: "example.com",
        port: 80,
        title: "XSS",
        cves: ["CVE-2024-5555"],
        confidence: 60,
      }),
      makeFinding({
        id: "high-conf",
        source: "scanner-a",
        target: "example.com",
        port: 80,
        title: "XSS",
        cves: ["CVE-2024-5555"],
        confidence: 95,
      }),
    ];

    const result = dedup.deduplicate(findings);
    expect(result.findings.length).toBe(1);
    // Merge logic keeps highest confidence and may boost it via multi-source corroboration
    expect(result.findings[0].confidence).toBeGreaterThanOrEqual(95);
  });
});

// ─── Normalization Tests ──────────────────────────────────────────────────

describe("NormalizationEngine", () => {
  let normalizer: NormalizationEngine;

  beforeEach(() => {
    normalizer = new NormalizationEngine();
  });

  it("should normalize a batch of findings and return result", () => {
    const findings: ScanFinding[] = [
      makeFinding({ id: "f1", source: "t1", target: "a.com", title: "Test 1", severity: "high", confidence: 90 }),
      makeFinding({ id: "f2", source: "t2", target: "b.com", title: "Test 2", severity: "low", confidence: 70 }),
    ];

    const result = normalizer.normalize(findings);
    expect(result.findings.length).toBe(2);
    expect(typeof result.severityAdjustments).toBe("number");
    expect(typeof result.referenceEnrichments).toBe("number");
    expect(typeof result.complianceMappingsAdded).toBe("number");
    expect(Array.isArray(result.log)).toBe(true);
  });

  it("should preserve CVE IDs during normalization", () => {
    const findings: ScanFinding[] = [
      makeFinding({
        id: "f1",
        source: "t1",
        target: "example.com",
        title: "Known Vuln",
        cves: ["CVE-2024-1234", "CVE-2023-5678"],
        confidence: 85,
      }),
    ];

    const result = normalizer.normalize(findings);
    expect(result.findings[0].cves).toBeDefined();
    expect(result.findings[0].cves!.length).toBe(2);
    expect(result.findings[0].cves).toContain("CVE-2024-1234");
    expect(result.findings[0].cves).toContain("CVE-2023-5678");
  });

  it("should preserve CWE IDs during normalization", () => {
    const findings: ScanFinding[] = [
      makeFinding({
        id: "f1",
        source: "t1",
        target: "example.com",
        title: "XSS",
        cwes: ["CWE-79", "CWE-80"],
        confidence: 80,
      }),
    ];

    const result = normalizer.normalize(findings);
    expect(result.findings[0].cwes).toBeDefined();
    expect(result.findings[0].cwes!.length).toBe(2);
    expect(result.findings[0].cwes).toContain("CWE-79");
    expect(result.findings[0].cwes).toContain("CWE-80");
  });

  it("should handle findings with no CVEs or CWEs", () => {
    const findings: ScanFinding[] = [
      makeFinding({ id: "f1", source: "t1", target: "a.com", title: "No refs", confidence: 70 }),
    ];

    const result = normalizer.normalize(findings);
    expect(result.findings.length).toBe(1);
  });

  it("should handle empty findings array", () => {
    const result = normalizer.normalize([]);
    expect(result.findings.length).toBe(0);
    expect(result.severityAdjustments).toBe(0);
  });
});

// ─── Coverage Gap Detection Tests ─────────────────────────────────────────

describe("CoverageGapDetector", () => {
  let detector: CoverageGapDetector;

  // Minimal fixtures for the analyze() signature
  const defaultConfig: ScanConfig = { maxConcurrency: 5, timeoutSeconds: 300 };
  const defaultTemplates: ScanTemplate[] = [
    { id: "http-exposure-01", name: "HTTP Exposure", description: "d", author: "a", severity: "medium", tags: ["http", "web"], protocol: "http", matchers: [] } as any,
    { id: "dns-zone-transfer-01", name: "Zone Transfer", description: "d", author: "a", severity: "high", tags: ["dns", "zone-transfer"], protocol: "dns", matchers: [] } as any,
    { id: "dns-dnssec-misconfig-01", name: "DNSSEC", description: "d", author: "a", severity: "medium", tags: ["dns", "dnssec"], protocol: "dns", matchers: [] } as any,
    { id: "ssl-tls-01", name: "TLS Check", description: "d", author: "a", severity: "low", tags: ["tls", "ssl"], protocol: "tls", matchers: [] } as any,
  ];

  beforeEach(() => {
    detector = new CoverageGapDetector();
  });

  it("should detect coverage gaps for a web server target", () => {
    const target: ScanTarget = {
      value: "example.com",
      type: "domain",
      ports: [80, 443],
      services: { 80: "http", 443: "https" },
    };

    const scannersRun: ScannerResult[] = [
      { scanner: "http", status: "completed", durationMs: 1000, findingCount: 1 },
    ];

    const report = detector.analyze(target, defaultConfig, scannersRun, ["http-exposure-01"], defaultTemplates);
    expect(report).toBeDefined();
    expect(typeof report.coveragePercent).toBe("number");
    expect(report.coveragePercent).toBeGreaterThanOrEqual(0);
    expect(report.coveragePercent).toBeLessThanOrEqual(100);
    expect(Array.isArray(report.gaps)).toBe(true);
  });

  it("should detect DNS-specific coverage gaps when DNS templates are not executed", () => {
    const target: ScanTarget = {
      value: "example.com",
      type: "domain",
      ports: [53],
      services: { 53: "dns" },
    };

    const scannersRun: ScannerResult[] = [];
    const report = detector.analyze(target, defaultConfig, scannersRun, [], defaultTemplates);
    // Should have gaps since no scanners ran
    expect(report.gaps.length).toBeGreaterThan(0);
    expect(report.coveragePercent).toBeLessThan(50);
  });

  it("should detect cloud-specific coverage gaps", () => {
    const target: ScanTarget = {
      value: "ec2-1-2-3-4.compute.amazonaws.com",
      type: "cloud_resource",
      ports: [80, 443, 8080],
      services: { 80: "http", 443: "https" },
      classification: { environment: "cloud", assetType: "cloud_instance", confidence: 90, signals: [] } as any,
    };

    const report = detector.analyze(target, defaultConfig, [], [], defaultTemplates, target.classification);
    expect(report.gaps.length).toBeGreaterThan(0);
    expect(report.coveragePercent).toBeLessThan(50);
  });

  it("should detect IoT-specific coverage gaps", () => {
    const target: ScanTarget = {
      value: "iot-device.local",
      type: "iot_device",
      ports: [1883, 8883],
      services: { 1883: "mqtt" },
      classification: { environment: "iot", assetType: "iot_device", confidence: 85, signals: [] } as any,
    };

    const report = detector.analyze(target, defaultConfig, [], [], defaultTemplates, target.classification);
    expect(report.gaps.length).toBeGreaterThan(0);
  });

  it("should detect ICS/SCADA coverage gaps", () => {
    const target: ScanTarget = {
      value: "10.0.1.50",
      type: "ics_endpoint",
      ports: [502, 20000],
      services: { 502: "modbus" },
      classification: { environment: "ics_ot", assetType: "ics_controller", confidence: 90, signals: [] } as any,
    };

    const report = detector.analyze(target, defaultConfig, [], [], defaultTemplates, target.classification);
    expect(report.gaps.length).toBeGreaterThan(0);
  });

  it("should return higher coverage when more scanners and templates are executed", () => {
    const target: ScanTarget = {
      value: "example.com",
      type: "domain",
      ports: [80, 443],
      services: { 80: "http", 443: "https" },
    };

    const noScanReport = detector.analyze(target, defaultConfig, [], [], defaultTemplates);

    const fullScanReport = detector.analyze(
      target,
      defaultConfig,
      [
        { scanner: "http", status: "completed", durationMs: 1000, findingCount: 3 },
        { scanner: "tls", status: "completed", durationMs: 500, findingCount: 1 },
        { scanner: "dns", status: "completed", durationMs: 800, findingCount: 2 },
      ],
      ["http-exposure-01", "dns-zone-transfer-01", "dns-dnssec-misconfig-01", "ssl-tls-01"],
      defaultTemplates
    );

    expect(fullScanReport.coveragePercent).toBeGreaterThan(noScanReport.coveragePercent);
  });

  it("should handle empty inputs gracefully", () => {
    const target: ScanTarget = { value: "example.com", type: "domain" };
    const report = detector.analyze(target, defaultConfig, [], [], []);
    expect(report).toBeDefined();
    expect(typeof report.coveragePercent).toBe("number");
    expect(Array.isArray(report.gaps)).toBe(true);
  });
});
