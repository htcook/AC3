import { describe, it, expect } from "vitest";

/**
 * Tests for:
 * 1. Compliance evidence mapper integration (mapEngagementToCompliance)
 * 2. Sidebar nav role-based filtering fix (Array.isArray safety)
 */

describe("Compliance Evidence Mapper", () => {
  it("should map engagement state to compliance evidence", async () => {
    const { mapEngagementToCompliance } = await import("./lib/compliance-evidence-mapper");

    const state = {
      engagementId: 1,
      assets: [
        {
          hostname: "test.example.com",
          ip: "10.0.0.1",
          vulns: [
            { title: "SQL Injection", severity: "high", tool: "nuclei", cve: "CVE-2024-1234" },
            { title: "XSS Reflected", severity: "medium", tool: "zap" },
          ],
          ports: [
            { port: 80, service: "http" },
            { port: 443, service: "https" },
          ],
          toolResults: [
            {
              tool: "scanforge-discovery",
              command: "masscan -pV test.example.com",
              exitCode: 0,
              findingCount: 2,
              outputPreview: "PORT   STATE SERVICE\n80/tcp open  http\n443/tcp open  https",
              findings: [
                { title: "Open port 80", severity: "info" },
                { title: "Open port 443", severity: "info" },
              ],
            },
            {
              tool: "nuclei",
              command: "nuclei -u test.example.com",
              exitCode: 0,
              findingCount: 3,
              outputPreview: "Found 3 vulnerabilities",
              findings: [
                { title: "SQL Injection", severity: "high" },
                { title: "Directory Listing", severity: "medium" },
                { title: "Missing Security Headers", severity: "low" },
              ],
            },
          ],
          zapFindings: [
            { alert: "Cross-Site Scripting", risk: "high", url: "https://test.example.com/search" },
          ],
        },
      ],
    };

    const result = mapEngagementToCompliance(state);

    expect(result).toBeDefined();
    expect(result.evidence).toBeInstanceOf(Array);
    expect(result.summaries).toBeInstanceOf(Array);
    expect(result.totalEvidenceItems).toBeGreaterThanOrEqual(0);
    expect(result.frameworksCovered).toBeInstanceOf(Array);
    expect(typeof result.gapCount).toBe("number");

    // Evidence items should have required fields
    if (result.evidence.length > 0) {
      const ev = result.evidence[0];
      expect(ev.id).toBeTruthy();
      expect(ev.controlId).toBeTruthy();
      expect(ev.framework).toBeTruthy();
      expect(ev.source).toBeTruthy();
      expect(ev.asset).toBe("test.example.com");
      expect(ev.engagementId).toBe(1);
      expect(["pass", "fail", "partial", "informational"]).toContain(ev.status);
    }

    // Summaries should have framework posture data
    if (result.summaries.length > 0) {
      const summary = result.summaries[0];
      expect(summary.framework).toBeTruthy();
      expect(typeof summary.complianceScore).toBe("number");
      expect(summary.complianceScore).toBeGreaterThanOrEqual(0);
      expect(summary.complianceScore).toBeLessThanOrEqual(100);
      expect(typeof summary.totalControls).toBe("number");
    }
  });

  it("should handle empty engagement state gracefully", async () => {
    const { mapEngagementToCompliance } = await import("./lib/compliance-evidence-mapper");

    const state = {
      engagementId: 999,
      assets: [],
    };

    const result = mapEngagementToCompliance(state);

    expect(result).toBeDefined();
    expect(result.evidence).toEqual([]);
    expect(result.totalEvidenceItems).toBe(0);
    // Summaries should still exist (framework controls are defined even with no evidence)
    expect(result.summaries.length).toBeGreaterThan(0);
  });

  it("should return supported frameworks", async () => {
    const { getSupportedFrameworks } = await import("./lib/compliance-evidence-mapper");
    const frameworks = getSupportedFrameworks();
    expect(frameworks).toBeInstanceOf(Array);
    expect(frameworks.length).toBeGreaterThan(0);
    for (const fw of frameworks) {
      expect(fw.framework).toBeTruthy();
      expect(fw.controlCount).toBeGreaterThan(0);
    }
  });

  it("should return mapping rules", async () => {
    const { getMappingRules } = await import("./lib/compliance-evidence-mapper");
    const rules = getMappingRules();
    expect(rules).toBeInstanceOf(Array);
    expect(rules.length).toBeGreaterThan(0);
    for (const rule of rules) {
      expect(rule.id).toBeTruthy();
      expect(rule.name).toBeTruthy();
      expect(rule.controlCount).toBeGreaterThan(0);
      expect(rule.frameworks.length).toBeGreaterThan(0);
    }
  });
});

describe("Sidebar Nav Role Filtering Fix", () => {
  it("should handle undefined role without crashing", async () => {
    // Dynamically import to test the actual module
    const mod = await import("../client/src/lib/sidebar-nav");
    const result = mod.getFilteredNavGroups(undefined);
    expect(result).toBeInstanceOf(Array);
    expect(result.length).toBeGreaterThan(0);
  });

  it("should handle 'user' role (Manus default) without crashing", async () => {
    const mod = await import("../client/src/lib/sidebar-nav");
    const result = mod.getFilteredNavGroups("user");
    expect(result).toBeInstanceOf(Array);
    // 'user' is not in ROLE_GROUP_ACCESS, should fall back to viewer
    expect(result.length).toBeGreaterThan(0);
  });

  it("should handle 'admin' role and return all groups", async () => {
    const mod = await import("../client/src/lib/sidebar-nav");
    const result = mod.getFilteredNavGroups("admin");
    expect(result).toBeInstanceOf(Array);
    // Admin should see all groups
    expect(result.length).toBeGreaterThan(5);
  });

  it("should handle 'operator' role correctly", async () => {
    const mod = await import("../client/src/lib/sidebar-nav");
    const result = mod.getFilteredNavGroups("operator");
    expect(result).toBeInstanceOf(Array);
    expect(result.length).toBeGreaterThan(0);
    // Operator should see command-control
    const hasC2 = result.some(g => g.id === "command-control");
    expect(hasC2).toBe(true);
  });

  it("should handle empty string role without crashing", async () => {
    const mod = await import("../client/src/lib/sidebar-nav");
    const result = mod.getFilteredNavGroups("");
    expect(result).toBeInstanceOf(Array);
    expect(result.length).toBeGreaterThan(0);
  });

  it("should handle completely unknown role without crashing", async () => {
    const mod = await import("../client/src/lib/sidebar-nav");
    const result = mod.getFilteredNavGroups("some_random_role_that_doesnt_exist");
    expect(result).toBeInstanceOf(Array);
    // Should fall back to viewer
    expect(result.length).toBeGreaterThan(0);
  });
});
