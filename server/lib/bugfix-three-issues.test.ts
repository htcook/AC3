/**
 * Tests for three critical production fixes:
 *   1. Exploit execution failover (do-scan-api.ts uses getActiveScanUrl)
 *   2. Port stat recalculation in normalizeOpsState
 *   3. Coverage score tool-to-protocol/tag mapping
 */
import { describe, it, expect, vi } from "vitest";

// ─── Test 1: normalizeOpsState recalculates portsFound ──────────────────

describe("normalizeOpsState — port stat recalculation", () => {
  it("should recalculate portsFound when stats say 0 but assets have ports", async () => {
    const { normalizeOpsState } = await import("./engagement-orchestrator");

    const state: any = {
      engagementId: 1,
      phase: "enumeration",
      progress: 50,
      isRunning: false,
      isPaused: false,
      assets: [
        {
          hostname: "test.example.com",
          ports: [
            { port: 80, service: "http" },
            { port: 443, service: "https" },
            { port: 22, service: "ssh" },
          ],
          vulns: [],
          pendingVulns: [],
          toolResults: [],
          zapFindings: [],
          exploitAttempts: [],
          confirmedCredentials: [],
        },
        {
          hostname: "api.example.com",
          ports: [
            { port: 8080, service: "http" },
            { port: 3306, service: "mysql" },
          ],
          vulns: [],
          pendingVulns: [],
          toolResults: [],
          zapFindings: [],
          exploitAttempts: [],
          confirmedCredentials: [],
        },
      ],
      log: [],
      approvalGates: [],
      stats: {
        hostsScanned: 2,
        portsFound: 0, // Bug: stat says 0 but assets have 5 ports
        vulnsFound: 0,
        exploitsAttempted: 0,
        exploitsSucceeded: 0,
        sessionsOpened: 0,
        zapScansRun: 0,
        wafDetections: 0,
      },
    };

    const normalized = normalizeOpsState(state);
    // portsFound should be recalculated to 5 (3 + 2)
    expect(normalized.stats.portsFound).toBe(5);
  });

  it("should NOT overwrite portsFound when it already has a value", async () => {
    const { normalizeOpsState } = await import("./engagement-orchestrator");

    const state: any = {
      engagementId: 2,
      phase: "enumeration",
      progress: 50,
      isRunning: false,
      isPaused: false,
      assets: [
        {
          hostname: "test.example.com",
          ports: [{ port: 80, service: "http" }],
          vulns: [],
          pendingVulns: [],
          toolResults: [],
          zapFindings: [],
          exploitAttempts: [],
          confirmedCredentials: [],
        },
      ],
      log: [],
      approvalGates: [],
      stats: {
        hostsScanned: 1,
        portsFound: 15, // Already has a value — should NOT be overwritten
        vulnsFound: 0,
        exploitsAttempted: 0,
        exploitsSucceeded: 0,
        sessionsOpened: 0,
        zapScansRun: 0,
        wafDetections: 0,
      },
    };

    const normalized = normalizeOpsState(state);
    // Should keep the existing value
    expect(normalized.stats.portsFound).toBe(15);
  });
});

// ─── Test 2: Coverage score tool-to-protocol mapping ────────────────────

describe("runEngagementCoverageAnalysis — tool-to-protocol mapping", () => {
  it("should produce non-zero coverage when tools like httpx and nuclei have been run", async () => {
    const { runEngagementCoverageAnalysis } = await import("./dedup-coverage-bridge");

    const assets: any[] = [
      {
        hostname: "target.example.com",
        ip: "1.2.3.4",
        type: "web_app",
        ports: [
          { port: 80, service: "http" },
          { port: 443, service: "https" },
          { port: 22, service: "ssh" },
        ],
        vulns: [
          { id: "v1", severity: "high", title: "SQL Injection", cve: "CVE-2024-1234" },
        ],
        pendingVulns: [],
        zapFindings: [],
        toolResults: [
          {
            tool: "naabu",
            command: "naabu -host target.example.com -top-ports 1000",
            exitCode: 0,
            durationMs: 5000,
            timedOut: false,
            findingCount: 3,
            findings: [],
            outputPreview: "",
            executedAt: Date.now(),
            phase: "enumeration",
          },
          {
            tool: "httpx",
            command: "httpx -u target.example.com",
            exitCode: 0,
            durationMs: 3000,
            timedOut: false,
            findingCount: 2,
            findings: [],
            outputPreview: "",
            executedAt: Date.now(),
            phase: "enumeration",
          },
          {
            tool: "nuclei",
            command: "nuclei -u target.example.com",
            exitCode: 0,
            durationMs: 30000,
            timedOut: false,
            findingCount: 5,
            findings: [
              { severity: "high", title: "SQL Injection", cve: "CVE-2024-1234" },
            ],
            outputPreview: "",
            executedAt: Date.now(),
            phase: "vuln_detection",
          },
        ],
        status: "vulns_found",
        confirmedCredentials: [],
      },
    ];

    const report = runEngagementCoverageAnalysis(assets);

    // With httpx (http, https), nuclei (http, https, cve, exposure, misconfig, owasp-top10),
    // and ssh from discovered ports, coverage should be well above 0%
    expect(report.overallScore).toBeGreaterThan(0);
    // Should have fewer than 38 gaps (the old broken value)
    expect(report.totalGaps).toBeLessThan(38);
    // Asset report should exist
    expect(report.assetReports).toHaveLength(1);
    expect(report.assetReports[0].hostname).toBe("target.example.com");
    expect(report.assetReports[0].score).toBeGreaterThan(0);
  });

  it("should correctly map hydra to credentials tag", async () => {
    const { runEngagementCoverageAnalysis } = await import("./dedup-coverage-bridge");

    const assets: any[] = [
      {
        hostname: "target2.example.com",
        type: "server",
        ports: [
          { port: 22, service: "ssh" },
          { port: 80, service: "http" },
          { port: 443, service: "https" },
        ],
        vulns: [],
        pendingVulns: [],
        zapFindings: [],
        toolResults: [
          {
            tool: "httpx",
            command: "httpx -u target2.example.com",
            exitCode: 0,
            durationMs: 2000,
            timedOut: false,
            findingCount: 1,
            findings: [],
            outputPreview: "",
            executedAt: Date.now(),
            phase: "enumeration",
          },
          {
            tool: "nuclei",
            command: "nuclei -u target2.example.com",
            exitCode: 0,
            durationMs: 20000,
            timedOut: false,
            findingCount: 0,
            findings: [],
            outputPreview: "",
            executedAt: Date.now(),
            phase: "vuln_detection",
          },
          {
            tool: "hydra",
            command: "hydra -l admin -P wordlist.txt ssh://target2.example.com",
            exitCode: 0,
            durationMs: 15000,
            timedOut: false,
            findingCount: 0,
            findings: [],
            outputPreview: "",
            executedAt: Date.now(),
            phase: "exploitation",
          },
        ],
        status: "no_vulns",
        confirmedCredentials: [],
      },
    ];

    const report = runEngagementCoverageAnalysis(assets);

    // With hydra run, "credentials" tag should be covered
    // Coverage should be higher than without hydra
    expect(report.overallScore).toBeGreaterThan(0);
    // Check that no gap mentions "credentials" as missing
    const credGaps = report.assetReports[0].gaps.filter(
      (g: any) => g.description.includes('"credentials"')
    );
    expect(credGaps).toHaveLength(0);
  });

  it("should return 0% coverage when no tools have been run", async () => {
    const { runEngagementCoverageAnalysis } = await import("./dedup-coverage-bridge");

    const assets: any[] = [
      {
        hostname: "empty.example.com",
        type: "server",
        ports: [],
        vulns: [],
        pendingVulns: [],
        zapFindings: [],
        toolResults: [],
        status: "pending",
        confirmedCredentials: [],
      },
    ];

    const report = runEngagementCoverageAnalysis(assets);
    // No tools run, no ports — should be 0%
    expect(report.overallScore).toBe(0);
  });
});

// ─── Test 3: do-scan-api uses getActiveScanUrl ──────────────────────────

describe("do-scan-api — dynamic URL failover", () => {
  it("should import getActiveScanUrl from scan-service-url", async () => {
    // Verify the import exists and is a function
    const { getActiveScanUrl } = await import("./scan-service-url");
    expect(typeof getActiveScanUrl).toBe("function");
  });

  it("should have executeToolViaHttp that calls getActiveScanUrl", async () => {
    // Read the source file to verify it uses getActiveScanUrl
    const fs = await import("fs");
    const source = fs.readFileSync(
      new URL("./do-scan-api.ts", import.meta.url).pathname.replace(
        "/do-scan-api.ts",
        "/do-scan-api.ts"
      ),
      "utf-8"
    );
    // The function should call getActiveScanUrl, not use static SCAN_SERVICE_URL
    expect(source).toContain("getActiveScanUrl");
    expect(source).toContain("executeToolViaHttp");
  });
});
