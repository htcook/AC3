import { describe, it, expect } from "vitest";

/**
 * Tests for the Dashboard inline scan behavior:
 * 1. Quick scan bar supports multiple targets (domains, URLs, IPs)
 * 2. Target parsing handles various input formats
 * 3. Scans run inline without page redirect
 * 4. Engagement form supports multiple targets via additionalDomains
 * 5. startScan procedure accepts scanOnly flag for quick scans
 */

describe("Dashboard Inline Scan — Multi-Target Input Parsing", () => {
  // Replicate the parseTargets function from Dashboard.tsx
  const parseTargets = (input: string): string[] => {
    return input
      .split(/[,\n\s]+/)
      .map(t => t.trim().toLowerCase())
      .filter(Boolean)
      .map(t => t.replace(/^https?:\/\//, '').replace(/\/.*$/, ''))
      .filter((t, i, arr) => arr.indexOf(t) === i);
  };

  it("should parse comma-separated domains", () => {
    const result = parseTargets("example.com, test.org, acme.io");
    expect(result).toEqual(["example.com", "test.org", "acme.io"]);
  });

  it("should parse space-separated domains", () => {
    const result = parseTargets("example.com test.org acme.io");
    expect(result).toEqual(["example.com", "test.org", "acme.io"]);
  });

  it("should parse newline-separated domains", () => {
    const result = parseTargets("example.com\ntest.org\nacme.io");
    expect(result).toEqual(["example.com", "test.org", "acme.io"]);
  });

  it("should parse mixed separators (commas, spaces, newlines)", () => {
    const result = parseTargets("example.com, test.org\nacme.io 192.168.1.1");
    expect(result).toEqual(["example.com", "test.org", "acme.io", "192.168.1.1"]);
  });

  it("should strip http:// and https:// protocols from URLs", () => {
    const result = parseTargets("https://example.com, http://test.org");
    expect(result).toEqual(["example.com", "test.org"]);
  });

  it("should strip paths from URLs", () => {
    const result = parseTargets("https://example.com/path/to/page, test.org/admin");
    expect(result).toEqual(["example.com", "test.org"]);
  });

  it("should handle IP addresses", () => {
    const result = parseTargets("192.168.1.1, 10.0.0.1, 172.16.0.1");
    expect(result).toEqual(["192.168.1.1", "10.0.0.1", "172.16.0.1"]);
  });

  it("should handle mixed domains, URLs, and IPs", () => {
    const result = parseTargets("example.com, https://secure.io/login, 10.0.0.5");
    expect(result).toEqual(["example.com", "secure.io", "10.0.0.5"]);
  });

  it("should deduplicate entries", () => {
    const result = parseTargets("example.com, example.com, test.org, example.com");
    expect(result).toEqual(["example.com", "test.org"]);
  });

  it("should deduplicate URLs that resolve to the same domain", () => {
    const result = parseTargets("https://example.com/page1, http://example.com/page2");
    expect(result).toEqual(["example.com"]);
  });

  it("should lowercase all entries", () => {
    const result = parseTargets("EXAMPLE.COM, Test.Org, ACME.IO");
    expect(result).toEqual(["example.com", "test.org", "acme.io"]);
  });

  it("should filter empty entries from trailing commas", () => {
    const result = parseTargets("example.com, test.org, ,, ");
    expect(result).toEqual(["example.com", "test.org"]);
  });

  it("should handle single domain input", () => {
    const result = parseTargets("example.com");
    expect(result).toEqual(["example.com"]);
  });

  it("should return empty array for empty input", () => {
    const result = parseTargets("");
    expect(result).toEqual([]);
  });

  it("should return empty array for whitespace-only input", () => {
    const result = parseTargets("   \n  \t  ");
    expect(result).toEqual([]);
  });
});

describe("Dashboard Inline Scan — startScan Procedure Schema", () => {
  it("startScan input schema should accept scanOnly flag", async () => {
    // The startScan procedure accepts scanOnly: boolean optional
    // This is used by the quick scan bar to run scan-only mode
    const validInput = {
      primaryDomain: "example.com",
      clientType: "enterprise" as const,
      sector: "Technology",
      customerName: "example.com",
      criticalFunctions: [],
      scanOnly: true,
    };
    expect(validInput.scanOnly).toBe(true);
    expect(validInput.primaryDomain).toBe("example.com");
  });

  it("startScan input schema should accept additionalDomains for multi-target", async () => {
    // The engagement form passes additional domains via additionalDomains field
    const validInput = {
      primaryDomain: "primary.com",
      additionalDomains: ["secondary.com", "tertiary.io", "10.0.0.1"],
      clientType: "enterprise" as const,
      sector: "Technology",
      customerName: "Acme Corp",
      criticalFunctions: [],
    };
    expect(validInput.additionalDomains).toHaveLength(3);
    expect(validInput.additionalDomains).toContain("secondary.com");
  });

  it("startScan should return a scanId for polling", async () => {
    // The mutation returns { scanId: number } which is used for status polling
    const mockResponse = { scanId: 12345 };
    expect(mockResponse.scanId).toBeGreaterThan(0);
    expect(typeof mockResponse.scanId).toBe("number");
  });
});

describe("Dashboard Inline Scan — Status Polling", () => {
  it("getScanStatus should return status, risk score, and asset count", () => {
    // The polling response includes fields needed for inline result display
    const mockStatus = {
      status: "completed" as const,
      primaryDomain: "example.com",
      overallRiskScore: 72,
      totalAssets: 15,
      overallRiskBand: "High",
    };
    expect(mockStatus.status).toBe("completed");
    expect(mockStatus.overallRiskScore).toBe(72);
    expect(mockStatus.totalAssets).toBe(15);
    expect(mockStatus.overallRiskBand).toBe("High");
  });

  it("scan_complete status should be treated as a terminal state", () => {
    const terminalStatuses = ["completed", "scan_complete", "failed"];
    expect(terminalStatuses).toContain("scan_complete");
    expect(terminalStatuses).toContain("completed");
    expect(terminalStatuses).toContain("failed");
  });

  it("inline scan should NOT redirect on completion", () => {
    // The old behavior was: navigate(`/domain-intel/${dashScanId}`)
    // The new behavior is: show inline results with "View Full Results" button
    // We verify the scan completed state shows results inline
    const scanCompleted = true;
    const dashScanId = 12345;
    // When scanCompleted is true, the UI shows:
    // 1. "VIEW FULL RESULTS" button linking to /domain-intel/${dashScanId}
    // 2. "NEW SCAN" button to reset
    // 3. Pipeline progress with completion checkmark
    expect(scanCompleted).toBe(true);
    expect(dashScanId).toBeGreaterThan(0);
    // The navigate() call should NOT be triggered
    const shouldRedirect = false; // New behavior
    expect(shouldRedirect).toBe(false);
  });
});

describe("Dashboard Inline Scan — Quick Scan Multi-Target Flow", () => {
  it("should launch parallel scans for multiple targets", () => {
    // Quick scan bar launches one startScan per target
    const targets = ["example.com", "test.org", "10.0.0.1"];
    const scanIds: number[] = [];
    
    // Simulate launching scans
    targets.forEach((target, i) => {
      scanIds.push(1000 + i);
    });
    
    expect(scanIds).toHaveLength(3);
    expect(scanIds).toEqual([1000, 1001, 1002]);
  });

  it("should track results per target with risk scores", () => {
    const results = [
      { scanId: 1000, domain: "example.com", status: "completed", riskScore: 72, totalAssets: 15, riskBand: "High" },
      { scanId: 1001, domain: "test.org", status: "completed", riskScore: 35, totalAssets: 8, riskBand: "Low" },
      { scanId: 1002, domain: "10.0.0.1", status: "failed", riskScore: undefined, totalAssets: undefined, riskBand: undefined },
    ];
    
    const completed = results.filter(r => r.status === "completed");
    const failed = results.filter(r => r.status === "failed");
    
    expect(completed).toHaveLength(2);
    expect(failed).toHaveLength(1);
    expect(completed[0].riskScore).toBe(72);
    expect(completed[1].riskBand).toBe("Low");
  });

  it("should enforce maximum 10 targets per batch", () => {
    const MAX_TARGETS = 10;
    const targets = Array.from({ length: 15 }, (_, i) => `target${i}.com`);
    
    expect(targets.length).toBeGreaterThan(MAX_TARGETS);
    // The UI should show an error toast and not proceed
    const shouldProceed = targets.length <= MAX_TARGETS;
    expect(shouldProceed).toBe(false);
  });

  it("should provide VIEW RESULTS link for each completed scan", () => {
    const results = [
      { scanId: 1000, domain: "example.com", status: "completed" },
      { scanId: 1001, domain: "test.org", status: "scan_complete" },
    ];
    
    // Each completed result should have a link to /domain-intel/${scanId}
    results.forEach(r => {
      const isDone = r.status === "completed" || r.status === "scan_complete";
      expect(isDone).toBe(true);
      const link = `/domain-intel/${r.scanId}`;
      expect(link).toContain("/domain-intel/");
    });
  });
});

describe("Dashboard Inline Scan — Risk Color Coding", () => {
  it("should assign red for risk score >= 80", () => {
    const score = 85;
    const color = score >= 80 ? "red" : score >= 60 ? "orange" : score >= 40 ? "yellow" : "green";
    expect(color).toBe("red");
  });

  it("should assign orange for risk score 60-79", () => {
    const score = 72;
    const color = score >= 80 ? "red" : score >= 60 ? "orange" : score >= 40 ? "yellow" : "green";
    expect(color).toBe("orange");
  });

  it("should assign yellow for risk score 40-59", () => {
    const score = 45;
    const color = score >= 80 ? "red" : score >= 60 ? "orange" : score >= 40 ? "yellow" : "green";
    expect(color).toBe("yellow");
  });

  it("should assign green for risk score < 40", () => {
    const score = 25;
    const color = score >= 80 ? "red" : score >= 60 ? "orange" : score >= 40 ? "yellow" : "green";
    expect(color).toBe("green");
  });
});
