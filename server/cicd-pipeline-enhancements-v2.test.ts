/**
 * Tests for CI/CD Pipeline Enhancements V2:
 * 1. Scheduled CI/CD Scans (cron parser, matcher, next-run calculator, presets)
 * 2. Threat Actor Drill-Down Links (group ID mapping)
 * 3. PDF Threat Report Export (HTML generation)
 */
import { describe, it, expect, vi } from "vitest";

// ─── Feature 1: Scheduled CI/CD Scans (Cron Engine) ──────────────────────────

describe("CI/CD Cron Scheduler", () => {
  describe("parseCronExpression", () => {
    it("should parse a valid 5-field cron expression", async () => {
      const { parseCronExpression } = await import("./lib/cicd-cron-scheduler");
      const result = parseCronExpression("0 */6 * * *");
      expect(result).not.toBeNull();
      expect(result!.minutes).toEqual([0]);
      expect(result!.hours).toEqual([0, 6, 12, 18]);
      expect(result!.daysOfMonth).toHaveLength(31);
      expect(result!.months).toHaveLength(12);
      expect(result!.daysOfWeek).toHaveLength(7);
    });

    it("should reject invalid cron expressions", async () => {
      const { parseCronExpression } = await import("./lib/cicd-cron-scheduler");
      expect(parseCronExpression("invalid")).toBeNull();
      expect(parseCronExpression("* * *")).toBeNull();
      expect(parseCronExpression("")).toBeNull();
      expect(parseCronExpression("60 * * * *")).toBeNull(); // minute > 59
      expect(parseCronExpression("* 25 * * *")).toBeNull(); // hour > 23
    });

    it("should parse ranges correctly", async () => {
      const { parseCronExpression } = await import("./lib/cicd-cron-scheduler");
      const result = parseCronExpression("0 9 * * 1-5");
      expect(result).not.toBeNull();
      expect(result!.daysOfWeek).toEqual([1, 2, 3, 4, 5]);
      expect(result!.hours).toEqual([9]);
    });

    it("should parse lists correctly", async () => {
      const { parseCronExpression } = await import("./lib/cicd-cron-scheduler");
      const result = parseCronExpression("0,30 * * * *");
      expect(result).not.toBeNull();
      expect(result!.minutes).toEqual([0, 30]);
    });

    it("should parse step values correctly", async () => {
      const { parseCronExpression } = await import("./lib/cicd-cron-scheduler");
      const result = parseCronExpression("*/15 * * * *");
      expect(result).not.toBeNull();
      expect(result!.minutes).toEqual([0, 15, 30, 45]);
    });

    it("should parse combined range with step", async () => {
      const { parseCronExpression } = await import("./lib/cicd-cron-scheduler");
      const result = parseCronExpression("0 8-18/2 * * *");
      expect(result).not.toBeNull();
      expect(result!.hours).toEqual([8, 10, 12, 14, 16, 18]);
    });
  });

  describe("matchesCron", () => {
    it("should match a date against a cron expression", async () => {
      const { parseCronExpression, matchesCron } = await import("./lib/cicd-cron-scheduler");
      const cron = parseCronExpression("0 6 * * *")!;
      // 2026-04-16 06:00 UTC is a Thursday (dow=4)
      const date = new Date("2026-04-16T06:00:00Z");
      expect(matchesCron(date, cron)).toBe(true);
    });

    it("should not match when minute is wrong", async () => {
      const { parseCronExpression, matchesCron } = await import("./lib/cicd-cron-scheduler");
      const cron = parseCronExpression("30 6 * * *")!;
      const date = new Date("2026-04-16T06:00:00Z");
      expect(matchesCron(date, cron)).toBe(false);
    });

    it("should match weekday-only cron on a weekday", async () => {
      const { parseCronExpression, matchesCron } = await import("./lib/cicd-cron-scheduler");
      const cron = parseCronExpression("0 9 * * 1-5")!;
      // 2026-04-16 is Thursday (dow=4)
      const date = new Date("2026-04-16T09:00:00Z");
      expect(matchesCron(date, cron)).toBe(true);
    });

    it("should not match weekday-only cron on a weekend", async () => {
      const { parseCronExpression, matchesCron } = await import("./lib/cicd-cron-scheduler");
      const cron = parseCronExpression("0 9 * * 1-5")!;
      // 2026-04-18 is Saturday (dow=6)
      const date = new Date("2026-04-18T09:00:00Z");
      expect(matchesCron(date, cron)).toBe(false);
    });
  });

  describe("getNextRunTime", () => {
    it("should calculate the next run time for an hourly cron", async () => {
      const { getNextRunTime } = await import("./lib/cicd-cron-scheduler");
      const after = new Date("2026-04-16T06:30:00Z");
      const next = getNextRunTime(after, "0 * * * *");
      expect(next).not.toBeNull();
      expect(next!.getUTCHours()).toBe(7);
      expect(next!.getUTCMinutes()).toBe(0);
    });

    it("should calculate next run for daily at midnight", async () => {
      const { getNextRunTime } = await import("./lib/cicd-cron-scheduler");
      const after = new Date("2026-04-16T00:01:00Z");
      const next = getNextRunTime(after, "0 0 * * *");
      expect(next).not.toBeNull();
      // Should be next day at midnight
      expect(next!.getUTCDate()).toBe(17);
      expect(next!.getUTCHours()).toBe(0);
      expect(next!.getUTCMinutes()).toBe(0);
    });

    it("should return null for invalid cron expression", async () => {
      const { getNextRunTime } = await import("./lib/cicd-cron-scheduler");
      const next = getNextRunTime(new Date(), "invalid");
      expect(next).toBeNull();
    });

    it("should skip weekends for weekday-only cron", async () => {
      const { getNextRunTime } = await import("./lib/cicd-cron-scheduler");
      // Friday 2026-04-17 at 10:00
      const after = new Date("2026-04-17T10:00:00Z");
      const next = getNextRunTime(after, "0 9 * * 1-5");
      expect(next).not.toBeNull();
      // Should be Monday 2026-04-20 at 09:00
      expect(next!.getUTCDay()).toBe(1); // Monday
      expect(next!.getUTCHours()).toBe(9);
    });
  });

  describe("describeCron", () => {
    it("should describe a simple daily cron", async () => {
      const { describeCron } = await import("./lib/cicd-cron-scheduler");
      const desc = describeCron("0 6 * * *");
      expect(desc).not.toBeNull();
      expect(desc).toContain("minute 0");
      expect(desc).toContain("6:00 UTC");
    });

    it("should describe a weekday cron", async () => {
      const { describeCron } = await import("./lib/cicd-cron-scheduler");
      const desc = describeCron("0 9 * * 1-5");
      expect(desc).not.toBeNull();
      expect(desc).toContain("Mon");
      expect(desc).toContain("Fri");
    });

    it("should return null for invalid cron", async () => {
      const { describeCron } = await import("./lib/cicd-cron-scheduler");
      expect(describeCron("invalid")).toBeNull();
    });

    it("should describe every-minute cron", async () => {
      const { describeCron } = await import("./lib/cicd-cron-scheduler");
      const desc = describeCron("* * * * *");
      expect(desc).not.toBeNull();
      expect(desc).toContain("every minute");
    });
  });

  describe("CRON_PRESETS", () => {
    it("should have valid presets with parseable cron expressions", async () => {
      const { CRON_PRESETS, parseCronExpression } = await import("./lib/cicd-cron-scheduler");
      expect(CRON_PRESETS.length).toBeGreaterThanOrEqual(5);
      for (const preset of CRON_PRESETS) {
        expect(preset.label).toBeTruthy();
        expect(preset.cron).toBeTruthy();
        const parsed = parseCronExpression(preset.cron);
        expect(parsed).not.toBeNull();
      }
    });
  });

  describe("startCronScheduler / stopCronScheduler", () => {
    it("should start and stop without errors", async () => {
      const { startCronScheduler, stopCronScheduler } = await import("./lib/cicd-cron-scheduler");
      // Start should not throw
      expect(() => startCronScheduler()).not.toThrow();
      // Stop should not throw
      expect(() => stopCronScheduler()).not.toThrow();
    });
  });
});

// ─── Feature 2: Threat Actor Drill-Down Links ────────────────────────────────

describe("Threat Actor Drill-Down Links", () => {
  it("should generate correct URL for actor group ID", () => {
    const groupId = "apt28";
    const url = `/threat-group/${encodeURIComponent(groupId)}`;
    expect(url).toBe("/threat-group/apt28");
  });

  it("should handle group names with special characters", () => {
    const groupName = "Fancy Bear (APT28)";
    const url = `/threat-group/${encodeURIComponent(groupName)}`;
    expect(url).toBe("/threat-group/Fancy%20Bear%20(APT28)");
  });

  it("should prefer groupId over groupName when both exist", () => {
    const actor = { groupId: "apt28", groupName: "Fancy Bear" };
    const url = `/threat-group/${encodeURIComponent(actor.groupId || actor.groupName)}`;
    expect(url).toBe("/threat-group/apt28");
  });

  it("should fall back to groupName when groupId is empty", () => {
    const actor = { groupId: "", groupName: "Unknown Group" };
    const url = `/threat-group/${encodeURIComponent(actor.groupId || actor.groupName)}`;
    expect(url).toBe("/threat-group/Unknown%20Group");
  });

  it("should handle numeric group IDs", () => {
    const groupId = "12345";
    const url = `/threat-group/${encodeURIComponent(groupId)}`;
    expect(url).toBe("/threat-group/12345");
  });
});

// ─── Feature 3: PDF Threat Report Export ─────────────────────────────────────

describe("CI/CD Threat Report Generator", () => {
  const mockReportData = {
    pipelineName: "Production Pipeline",
    runId: 42,
    branch: "main",
    commitSha: "abc1234567890",
    status: "failed",
    startedAt: "2026-04-16T10:00:00Z",
    completedAt: "2026-04-16T10:03:30Z",
    scanResults: {
      criticalCount: 3,
      highCount: 5,
      mediumCount: 8,
      lowCount: 12,
      maxCvss: 9.8,
      duration: 210000,
      findings: [
        { title: "SQL Injection in /api/users", severity: "critical", url: "https://example.com/api/users", cvss: 9.8 },
        { title: "XSS in search form", severity: "high", url: "https://example.com/search", cvss: 7.5 },
      ],
    },
    threatContext: {
      summary: {
        uniqueActorsMatched: 4,
        severityBoostedCount: 2,
        actorExposureScore: 72,
        killChainCoverage: 45,
        ransomwareRiskFindings: 1,
        aptRiskFindings: 3,
      },
      enrichedFindings: [
        {
          title: "SQL Injection in /api/users",
          severity: "critical",
          originalSeverity: "high",
          severityBoosted: true,
          boostReason: "Exploited by APT28 (critical actor)",
          attributedGroups: [{ groupName: "APT28", groupType: "apt", threatLevel: "critical" }],
          riskTags: ["apt-exploited", "critical-actor"],
          killChainPhases: ["initial-access", "execution"],
        },
        {
          title: "XSS in search form",
          severity: "high",
          originalSeverity: "high",
          severityBoosted: false,
          attributedGroups: [],
          riskTags: [],
          killChainPhases: [],
        },
      ],
      actorExposure: [
        {
          groupId: "apt28",
          groupName: "APT28",
          groupType: "apt",
          threatLevel: "critical",
          findingCount: 3,
          exposureScore: 85,
          active: true,
        },
        {
          groupId: "lockbit",
          groupName: "LockBit",
          groupType: "ransomware",
          threatLevel: "high",
          findingCount: 1,
          exposureScore: 40,
          active: true,
        },
      ],
    },
    sectorContext: "finance",
    gateEscalationReason: "APT threat actor (APT28) linked to critical findings",
  };

  it("should generate valid HTML report", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const html = generateThreatReportHtml(mockReportData);
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("</html>");
  });

  it("should include pipeline name and run ID in report", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const html = generateThreatReportHtml(mockReportData);
    expect(html).toContain("Production Pipeline");
    expect(html).toContain("Run #42");
  });

  it("should include scan result counts", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const html = generateThreatReportHtml(mockReportData);
    expect(html).toContain(">3<"); // critical count
    expect(html).toContain(">5<"); // high count
    expect(html).toContain(">8<"); // medium count
    expect(html).toContain(">12<"); // low count
  });

  it("should include threat intelligence summary", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const html = generateThreatReportHtml(mockReportData);
    expect(html).toContain("Threat Intelligence Summary");
    expect(html).toContain("72"); // exposure score
    expect(html).toContain("45"); // kill chain coverage
  });

  it("should include actor exposure table", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const html = generateThreatReportHtml(mockReportData);
    expect(html).toContain("APT28");
    expect(html).toContain("LockBit");
    expect(html).toContain("85"); // APT28 exposure score
  });

  it("should include severity-boosted findings", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const html = generateThreatReportHtml(mockReportData);
    expect(html).toContain("SQL Injection in /api/users");
    expect(html).toContain("from high"); // severity boost indicator
  });

  it("should include gate escalation banner when present", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const html = generateThreatReportHtml(mockReportData);
    expect(html).toContain("Gate Escalation");
    expect(html).toContain("APT threat actor");
  });

  it("should handle missing threat context gracefully", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const dataWithoutThreat = {
      ...mockReportData,
      threatContext: null,
      gateEscalationReason: undefined,
    };
    const html = generateThreatReportHtml(dataWithoutThreat);
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("Production Pipeline");
    // Should still include scan results
    expect(html).toContain(">3<"); // critical count
  });

  it("should include branch and commit info", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const html = generateThreatReportHtml(mockReportData);
    expect(html).toContain("main");
    expect(html).toContain("abc1234"); // truncated commit sha
  });

  it("should include sector context", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const html = generateThreatReportHtml(mockReportData);
    expect(html).toContain("finance");
  });

  it("should include print-friendly CSS", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const html = generateThreatReportHtml(mockReportData);
    expect(html).toContain("@media print");
    expect(html).toContain("print-color-adjust");
  });

  it("should escape HTML in user-provided strings", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const xssData = {
      ...mockReportData,
      pipelineName: '<script>alert("xss")</script>',
    };
    const html = generateThreatReportHtml(xssData);
    expect(html).not.toContain('<script>alert("xss")</script>');
    expect(html).toContain("&lt;script&gt;");
  });

  it("should include risk tags in findings", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const html = generateThreatReportHtml(mockReportData);
    expect(html).toContain("apt-exploited");
    expect(html).toContain("critical-actor");
  });

  it("should include kill chain phases in findings", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const html = generateThreatReportHtml(mockReportData);
    expect(html).toContain("initial-access");
    expect(html).toContain("execution");
  });

  it("should show FAILED status badge for failed runs", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const html = generateThreatReportHtml(mockReportData);
    expect(html).toContain("FAILED");
  });

  it("should show PASSED status badge for passed runs", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const passedData = { ...mockReportData, status: "passed", gateEscalationReason: undefined };
    const html = generateThreatReportHtml(passedData);
    expect(html).toContain("PASSED");
    // Should NOT contain gate escalation
    expect(html).not.toContain("THREAT ESCALATED");
  });

  it("should handle empty findings array", async () => {
    const { generateThreatReportHtml } = await import("./lib/cicd-threat-report");
    const emptyData = {
      ...mockReportData,
      scanResults: { ...mockReportData.scanResults, findings: [] },
      threatContext: {
        ...mockReportData.threatContext!,
        enrichedFindings: [],
        actorExposure: [],
      },
    };
    const html = generateThreatReportHtml(emptyData);
    expect(html).toContain("<!DOCTYPE html>");
    // Should still have the structure
    expect(html).toContain("Executive Summary");
  });
});
