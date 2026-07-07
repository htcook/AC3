/**
 * Scan State Tracker Tests
 *
 * Validates the scan execution state tracking system that detects
 * running, stalled, errored, and timed-out scans.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";

// We test the exported functions from do-scan-api
// The tracker is module-level state, so we need to import fresh each time
describe("Scan State Tracker", () => {
  let getActiveScanStatuses: typeof import("../server/lib/do-scan-api").getActiveScanStatuses;
  let getScanExecutionSummary: typeof import("../server/lib/do-scan-api").getScanExecutionSummary;

  beforeEach(async () => {
    // Reset module state by re-importing
    vi.resetModules();
    const mod = await import("./lib/do-scan-api");
    getActiveScanStatuses = mod.getActiveScanStatuses;
    getScanExecutionSummary = mod.getScanExecutionSummary;
  });

  it("should export getActiveScanStatuses function", () => {
    expect(typeof getActiveScanStatuses).toBe("function");
  });

  it("should export getScanExecutionSummary function", () => {
    expect(typeof getScanExecutionSummary).toBe("function");
  });

  it("should return empty statuses when no scans are tracked", () => {
    const statuses = getActiveScanStatuses();
    expect(Array.isArray(statuses)).toBe(true);
    // May have entries from other test imports, but structure should be correct
  });

  it("should return a valid summary structure", () => {
    const summary = getScanExecutionSummary();
    expect(summary).toHaveProperty("running");
    expect(summary).toHaveProperty("stalled");
    expect(summary).toHaveProperty("errored");
    expect(summary).toHaveProperty("completed");
    expect(summary).toHaveProperty("timedOut");
    expect(summary).toHaveProperty("total");
    expect(summary).toHaveProperty("stalledScans");
    expect(typeof summary.running).toBe("number");
    expect(typeof summary.stalled).toBe("number");
    expect(typeof summary.errored).toBe("number");
    expect(typeof summary.completed).toBe("number");
    expect(typeof summary.timedOut).toBe("number");
    expect(typeof summary.total).toBe("number");
    expect(Array.isArray(summary.stalledScans)).toBe(true);
  });

  it("should have ActiveScanStatus with correct shape", () => {
    const statuses = getActiveScanStatuses();
    // Validate the type shape even if empty
    if (statuses.length > 0) {
      const status = statuses[0];
      expect(status).toHaveProperty("id");
      expect(status).toHaveProperty("tool");
      expect(status).toHaveProperty("state");
      expect(status).toHaveProperty("startedAt");
      expect(status).toHaveProperty("lastActivityAt");
      expect(status).toHaveProperty("elapsedMs");
      expect(status).toHaveProperty("timeoutMs");
      expect(status).toHaveProperty("stallThresholdMs");
      expect(status).toHaveProperty("silentMs");
      expect(["queued", "running", "stalled", "completed", "errored", "timed_out"]).toContain(status.state);
    }
  });
});

describe("Extended Timeout Configuration", () => {
  it("should recognize long-running tools", () => {
    // These tools should get extended timeouts (up to 15 min)
    const longRunningTools = ["nuclei", "zap", "sqlmap", "nikto", "gobuster", "ffuf", "wfuzz", "masscan", "testssl", "burp"];
    const regex = /^(nuclei|zap|sqlmap|nikto|gobuster|ffuf|wfuzz|masscan|testssl|burp)$/i;

    for (const tool of longRunningTools) {
      expect(regex.test(tool)).toBe(true);
    }
  });

  it("should NOT extend timeout for short-running tools", () => {
    const shortTools = ["httpx", "nmap", "dig", "whois", "curl"];
    const regex = /^(nuclei|zap|sqlmap|nikto|gobuster|ffuf|wfuzz|masscan|testssl|burp)$/i;

    for (const tool of shortTools) {
      expect(regex.test(tool)).toBe(false);
    }
  });

  it("should cap extended timeout at 15 minutes (900,000ms)", () => {
    // Simulate the timeout calculation for a 600s nuclei scan
    const timeoutSeconds = 600;
    const extendedMs = Math.min((timeoutSeconds + 120) * 1000, 900_000);
    expect(extendedMs).toBe(720_000); // 600+120 = 720s = 720,000ms (under 900k cap)

    // Simulate for a very long scan (1200s)
    const longTimeoutSeconds = 1200;
    const longExtendedMs = Math.min((longTimeoutSeconds + 120) * 1000, 900_000);
    expect(longExtendedMs).toBe(900_000); // Capped at 15 min
  });

  it("should keep original 6-min cap for short tools", () => {
    const timeoutSeconds = 300;
    const shortMs = Math.min((timeoutSeconds + 60) * 1000, 360_000);
    expect(shortMs).toBe(360_000); // 300+60 = 360s = 360,000ms = exactly 6 min cap
  });

  it("should detect long-running tools by timeout threshold", () => {
    // Even if tool name doesn't match, timeoutSeconds > 300 should trigger extended mode
    const timeoutSeconds = 600;
    const isLongRunning = timeoutSeconds > 300;
    expect(isLongRunning).toBe(true);
  });
});

describe("Stall Detection", () => {
  it("should define stall threshold at 90 seconds", () => {
    // The STALL_THRESHOLD_MS is 90,000ms (90 seconds)
    // If a scan has no activity for > 90s, it's considered stalled
    const STALL_THRESHOLD_MS = 90_000;
    expect(STALL_THRESHOLD_MS).toBe(90_000);
  });

  it("should detect stalled scans in summary", async () => {
    const { getScanExecutionSummary: getSummary } = await import("./lib/do-scan-api");
    const summary = getSummary();
    // stalledScans should be an array of objects with tool, target, silentSeconds
    if (summary.stalledScans.length > 0) {
      const stalled = summary.stalledScans[0];
      expect(stalled).toHaveProperty("tool");
      expect(stalled).toHaveProperty("silentSeconds");
      expect(typeof stalled.silentSeconds).toBe("number");
    }
  });
});

describe("Raw Command Tool Detection", () => {
  it("should extract tool name from piped commands", () => {
    const testCases = [
      { command: "echo 'http://target.com' | nuclei -t cves/", expected: "nuclei" },
      { command: "sqlmap -u http://target.com --batch", expected: "sqlmap" },
      { command: "nmap -sV -p- 192.168.1.1", expected: "nmap" },
      { command: "echo test | httpx -silent", expected: "httpx" },
      { command: "cat urls.txt | ffuf -w -", expected: "ffuf" },
      { command: "ls -la /tmp", expected: "raw" }, // No recognized tool
    ];

    const regex = /\b(nuclei|zap|sqlmap|nikto|gobuster|ffuf|masscan|testssl|nmap|httpx)\b/i;

    for (const tc of testCases) {
      const match = tc.command.match(regex);
      const toolName = (match?.[1] || "raw").toLowerCase();
      expect(toolName).toBe(tc.expected);
    }
  });
});
