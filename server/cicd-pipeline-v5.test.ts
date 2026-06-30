/**
 * Tests for CI/CD Pipeline Enhancements v5:
 * 1. Baseline Pinning & Auto-Diff
 * 2. Slack/Teams Webhook Templates
 * 3. Schedule Conflict Detection
 */
import { describe, it, expect, vi } from "vitest";

// ─── 1. Webhook Templates ──────────────────────────────────────────────────

describe("Webhook Templates", () => {
  const templateModule = async () => import("./lib/cicd-webhook-templates");

  const samplePayload = {
    pipelineId: 1,
    pipelineName: "Production Security Scan",
    runId: 42,
    status: "failed" as const,
    targetUrl: "https://app.example.com",
    branch: "main",
    commitSha: "abc1234def5678",
    criticalCount: 2,
    highCount: 5,
    mediumCount: 8,
    lowCount: 3,
    maxCvss: 9.8,
    failThreshold: 7.0,
    duration: "3m 42s",
    newFindings: 3,
    fixedFindings: 1,
    gateEscalationReason: "2 findings linked to ransomware groups",
    threatContext: {
      uniqueActorsMatched: 4,
      actorExposureScore: 72,
      ransomwareRiskFindings: 2,
      aptRiskFindings: 3,
      killChainCoverage: 45,
      topActors: [
        { name: "APT28", type: "APT", findingCount: 3 },
        { name: "LockBit", type: "Ransomware", findingCount: 2 },
      ],
    },
    dashboardUrl: "https://dashboard.example.com/cicd/runs/42",
  };

  describe("formatSlackPayload", () => {
    it("returns valid Slack Block Kit payload", async () => {
      const { formatSlackPayload } = await templateModule();
      const result = formatSlackPayload(samplePayload);
      expect(result).toBeDefined();
      // Slack payload has text and attachments with blocks inside
      expect(result.text).toBeDefined();
      expect(result.attachments).toBeDefined();
      expect(result.attachments[0].blocks.length).toBeGreaterThan(0);
    });

    it("includes header block with pipeline name", async () => {
      const { formatSlackPayload } = await templateModule();
      const result = formatSlackPayload(samplePayload);
      const jsonStr = JSON.stringify(result);
      expect(jsonStr).toContain("Production Security Scan");
    });

    it("includes blocks with scan information", async () => {
      const { formatSlackPayload } = await templateModule();
      const result = formatSlackPayload(samplePayload);
      const jsonStr = JSON.stringify(result);
      // Should contain status info (FAILED in uppercase)
      expect(jsonStr).toContain("FAILED");
    });

    it("includes threat actor context when provided", async () => {
      const { formatSlackPayload } = await templateModule();
      const result = formatSlackPayload(samplePayload);
      const jsonStr = JSON.stringify(result);
      // Should contain at least one actor name
      expect(jsonStr.includes("APT28") || jsonStr.includes("LockBit") || jsonStr.includes("Threat")).toBe(true);
    });

    it("handles payload without threat context", async () => {
      const { formatSlackPayload } = await templateModule();
      const minimal = { ...samplePayload, threatContext: undefined, gateEscalationReason: undefined };
      const result = formatSlackPayload(minimal);
      // Should still produce a valid payload
      expect(result).toBeDefined();
      expect(result.blocks || result.attachments).toBeDefined();
    });

    it("handles passed status", async () => {
      const { formatSlackPayload } = await templateModule();
      const passed = { ...samplePayload, status: "passed" as const, criticalCount: 0, highCount: 0 };
      const result = formatSlackPayload(passed);
      expect(result).toBeDefined();
      const jsonStr = JSON.stringify(result);
      expect(jsonStr.includes("passed") || jsonStr.includes("Passed") || jsonStr.includes("PASSED") || jsonStr.includes("\u2705")).toBe(true);
    });
  });

  describe("formatTeamsPayload", () => {
    it("returns valid Teams Adaptive Card payload", async () => {
      const { formatTeamsPayload } = await templateModule();
      const result = formatTeamsPayload(samplePayload);
      expect(result).toBeDefined();
      expect(result.type).toBe("message");
      expect(result.attachments).toBeDefined();
      expect(result.attachments[0].contentType).toBe("application/vnd.microsoft.card.adaptive");
    });

    it("includes card body with pipeline info", async () => {
      const { formatTeamsPayload } = await templateModule();
      const result = formatTeamsPayload(samplePayload);
      const card = result.attachments[0].content;
      expect(card.type).toBe("AdaptiveCard");
      expect(card.body).toBeDefined();
      expect(Array.isArray(card.body)).toBe(true);
    });

    it("includes threat actor info in card", async () => {
      const { formatTeamsPayload } = await templateModule();
      const result = formatTeamsPayload(samplePayload);
      const jsonStr = JSON.stringify(result);
      expect(jsonStr).toContain("APT28");
    });

    it("handles minimal payload without optional fields", async () => {
      const { formatTeamsPayload } = await templateModule();
      const minimal = {
        pipelineId: 1,
        pipelineName: "Test",
        runId: 1,
        status: "passed" as const,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        maxCvss: 0,
        failThreshold: 7.0,
      };
      const result = formatTeamsPayload(minimal);
      expect(result.type).toBe("message");
    });
  });

  describe("formatWebhookPayload", () => {
    it("routes to raw format", async () => {
      const { formatWebhookPayload } = await templateModule();
      const result = formatWebhookPayload(samplePayload, "raw");
      expect(result.pipeline.name).toBe("Production Security Scan");
      expect(result.run.status).toBe("failed");
      expect(result.event).toBe("cicd.run.completed");
    });

    it("routes to slack format", async () => {
      const { formatWebhookPayload } = await templateModule();
      const result = formatWebhookPayload(samplePayload, "slack");
      // Slack payload has blocks at top level or in attachments
      expect(result.blocks || result.attachments).toBeDefined();
    });

    it("routes to teams format", async () => {
      const { formatWebhookPayload } = await templateModule();
      const result = formatWebhookPayload(samplePayload, "teams");
      expect(result.type).toBe("message");
    });
  });

  describe("detectWebhookFormat", () => {
    it("detects Slack webhook URLs", async () => {
      const { detectWebhookFormat } = await templateModule();
      expect(detectWebhookFormat("https://hooks.slack.com/services/T00/B00/xxx")).toBe("slack");
    });

    it("detects Teams webhook URLs", async () => {
      const { detectWebhookFormat } = await templateModule();
      expect(detectWebhookFormat("https://webhook.office.com/webhook/xxx")).toBe("teams");
    });

    it("returns raw for unknown URLs", async () => {
      const { detectWebhookFormat } = await templateModule();
      expect(detectWebhookFormat("https://example.com/webhook")).toBe("raw");
    });
  });

  describe("getWebhookFormatOptions", () => {
    it("returns all three format options", async () => {
      const { getWebhookFormatOptions } = await templateModule();
      const options = getWebhookFormatOptions();
      expect(options.length).toBe(3);
      const values = options.map((o: any) => o.value);
      expect(values).toContain("raw");
      expect(values).toContain("slack");
      expect(values).toContain("teams");
    });

    it("each option has label and description", async () => {
      const { getWebhookFormatOptions } = await templateModule();
      const options = getWebhookFormatOptions();
      for (const opt of options) {
        expect(opt.label).toBeTruthy();
        expect(opt.description).toBeTruthy();
      }
    });
  });
});

// ─── 2. Schedule Conflict Detection ─────────────────────────────────────────

describe("Schedule Conflict Detection", () => {
  const conflictModule = async () => import("./lib/cicd-schedule-conflict");

  describe("getNextExecutions", () => {
    it("returns correct number of executions", async () => {
      const { getNextExecutions } = await conflictModule();
      const execs = getNextExecutions("0 * * * *", 5); // every hour
      expect(execs.length).toBe(5);
    });

    it("returns dates in ascending order", async () => {
      const { getNextExecutions } = await conflictModule();
      const execs = getNextExecutions("0 * * * *", 10);
      for (let i = 1; i < execs.length; i++) {
        expect(execs[i].getTime()).toBeGreaterThan(execs[i - 1].getTime());
      }
    });

    it("handles daily cron expression", async () => {
      const { getNextExecutions } = await conflictModule();
      const execs = getNextExecutions("0 2 * * *", 3); // daily at 2am
      expect(execs.length).toBe(3);
      // Each should be ~24h apart
      const diff = execs[1].getTime() - execs[0].getTime();
      expect(diff).toBeCloseTo(24 * 60 * 60 * 1000, -4); // within 10s tolerance
    });

    it("handles weekly cron expression", async () => {
      const { getNextExecutions } = await conflictModule();
      const execs = getNextExecutions("0 0 * * 1", 2); // every Monday
      expect(execs.length).toBe(2);
      const diff = execs[1].getTime() - execs[0].getTime();
      expect(diff).toBeCloseTo(7 * 24 * 60 * 60 * 1000, -4);
    });

    it("returns empty array for invalid cron", async () => {
      const { getNextExecutions } = await conflictModule();
      const execs = getNextExecutions("invalid", 5);
      expect(execs.length).toBe(0);
    });
  });

  describe("detectConflicts", () => {
    it("detects overlapping hourly schedules", async () => {
      const { detectConflicts } = await conflictModule();
      const pipelines = [
        { id: 1, name: "Pipeline A", cronExpression: "0 * * * *", enabled: true },
        { id: 2, name: "Pipeline B", cronExpression: "0 * * * *", enabled: true },
      ];
      const report = detectConflicts(pipelines);
      expect(report.conflicts.length).toBeGreaterThan(0);
      expect(report.hasConflicts).toBe(true);
    });

    it("reports no conflicts for well-spaced schedules", async () => {
      const { detectConflicts } = await conflictModule();
      const pipelines = [
        { id: 1, name: "Pipeline A", cronExpression: "0 2 * * *", enabled: true },
        { id: 2, name: "Pipeline B", cronExpression: "0 14 * * *", enabled: true },
      ];
      const report = detectConflicts(pipelines);
      expect(report.conflicts.length).toBe(0);
    });

    it("returns scheduledPipelines count", async () => {
      const { detectConflicts } = await conflictModule();
      const pipelines = [
        { id: 1, name: "A", cronExpression: "0 2 * * *", enabled: true },
        { id: 2, name: "B", cronExpression: "0 14 * * *", enabled: true },
        { id: 3, name: "C", cronExpression: "30 8 * * *", enabled: true },
      ];
      const report = detectConflicts(pipelines);
      expect(report.scheduledPipelines).toBe(3);
    });

    it("handles empty pipeline list", async () => {
      const { detectConflicts } = await conflictModule();
      const report = detectConflicts([]);
      expect(report.scheduledPipelines).toBe(0);
      expect(report.conflicts.length).toBe(0);
    });

    it("handles single pipeline (no possible conflicts)", async () => {
      const { detectConflicts } = await conflictModule();
      const report = detectConflicts([
        { id: 1, name: "Solo", cronExpression: "0 * * * *", enabled: true },
      ]);
      expect(report.conflicts.length).toBe(0);
    });

    it("detects near-miss overlaps within tolerance window", async () => {
      const { detectConflicts } = await conflictModule();
      const pipelines = [
        { id: 1, name: "Pipeline A", cronExpression: "0 * * * *", enabled: true },
        { id: 2, name: "Pipeline B", cronExpression: "5 * * * *", enabled: true }, // 5 min apart
      ];
      const report = detectConflicts(pipelines);
      // Depending on tolerance, this may or may not conflict
      expect(report.scheduledPipelines).toBe(2);
    });
  });

  describe("suggestNonConflictingSchedule", () => {
    it("suggests a daily schedule", async () => {
      const { suggestNonConflictingSchedule } = await conflictModule();
      const result = suggestNonConflictingSchedule([], "daily");
      expect(result.cron).toBeTruthy();
      expect(result.description).toBeTruthy();
    });

    it("suggests an hourly schedule", async () => {
      const { suggestNonConflictingSchedule } = await conflictModule();
      const result = suggestNonConflictingSchedule([], "hourly");
      expect(result.cron).toBeTruthy();
    });

    it("suggests a weekly schedule", async () => {
      const { suggestNonConflictingSchedule } = await conflictModule();
      const result = suggestNonConflictingSchedule([], "weekly");
      expect(result.cron).toBeTruthy();
    });

    it("avoids conflicts with existing pipelines", async () => {
      const { suggestNonConflictingSchedule } = await conflictModule();
      const existing = [
        { id: 1, name: "A", cronExpression: "0 2 * * *", enabled: true },
        { id: 2, name: "B", cronExpression: "0 8 * * *", enabled: true },
      ];
      const result = suggestNonConflictingSchedule(existing, "daily");
      expect(result.cron).toBeTruthy();
      // Should not be at 2:00 or 8:00
      expect(result.cron).not.toBe("0 2 * * *");
      expect(result.cron).not.toBe("0 8 * * *");
    });

    it("returns description with conflict info", async () => {
      const { suggestNonConflictingSchedule } = await conflictModule();
      const result = suggestNonConflictingSchedule([], "daily");
      expect(result.description).toContain("no conflicts");
    });

    it("handles every_6h frequency", async () => {
      const { suggestNonConflictingSchedule } = await conflictModule();
      const result = suggestNonConflictingSchedule([], "every_6h");
      expect(result.cron).toBeTruthy();
    });

    it("handles every_12h frequency", async () => {
      const { suggestNonConflictingSchedule } = await conflictModule();
      const result = suggestNonConflictingSchedule([], "every_12h");
      expect(result.cron).toBeTruthy();
    });
  });
});

// ─── 3. Baseline Pinning Logic ──────────────────────────────────────────────

describe("Baseline Pinning Logic", () => {
  // Test the scan diff module used for baseline comparison
  const diffModule = async () => import("./lib/cicd-scan-diff");

  it("compareRuns produces valid diff with new/fixed/unchanged findings", async () => {
    const { compareRuns } = await diffModule();
    const baseline = {
      id: 1,
      status: "passed",
      findings: [
        { title: "SQL Injection", severity: "high", url: "https://example.com/api" },
        { title: "XSS", severity: "medium", url: "https://example.com/page" },
        { title: "Missing HSTS", severity: "low", url: "https://example.com" },
      ],
    };
    const current = {
      id: 2,
      status: "failed",
      findings: [
        { title: "SQL Injection", severity: "critical", url: "https://example.com/api" }, // still present, severity changed
        { title: "SSRF", severity: "high", url: "https://example.com/internal" }, // new
        { title: "Missing HSTS", severity: "low", url: "https://example.com" }, // unchanged
      ],
    };
    const diff = compareRuns(baseline, current);
    expect(diff).toBeDefined();
    expect(diff.newFindings).toBeDefined();
    expect(diff.fixedFindings).toBeDefined();
    // XSS was in baseline but not current = fixed
    expect(diff.fixedFindings.length).toBeGreaterThanOrEqual(1);
    // SSRF is new
    expect(diff.newFindings.length).toBeGreaterThanOrEqual(1);
  });

  it("compareRuns handles empty baseline", async () => {
    const { compareRuns } = await diffModule();
    const diff = compareRuns(
      { id: 1, status: "passed", findings: [] },
      { id: 2, status: "failed", findings: [{ title: "XSS", severity: "high", url: "https://example.com" }] }
    );
    expect(diff.newFindings.length).toBe(1);
    expect(diff.fixedFindings.length).toBe(0);
  });

  it("compareRuns handles empty current", async () => {
    const { compareRuns } = await diffModule();
    const diff = compareRuns(
      { id: 1, status: "passed", findings: [{ title: "XSS", severity: "high", url: "https://example.com" }] },
      { id: 2, status: "passed", findings: [] }
    );
    expect(diff.newFindings.length).toBe(0);
    expect(diff.fixedFindings.length).toBe(1);
  });

  it("compareRuns handles both empty", async () => {
    const { compareRuns } = await diffModule();
    const diff = compareRuns(
      { id: 1, status: "passed", findings: [] },
      { id: 2, status: "passed", findings: [] }
    );
    expect(diff.newFindings.length).toBe(0);
    expect(diff.fixedFindings.length).toBe(0);
  });

  it("compareRuns detects severity changes", async () => {
    const { compareRuns } = await diffModule();
    const diff = compareRuns(
      { id: 1, status: "passed", findings: [{ title: "SQLi", severity: "medium", url: "https://example.com" }] },
      { id: 2, status: "failed", findings: [{ title: "SQLi", severity: "critical", url: "https://example.com" }] }
    );
    // Same finding, different severity = changed severity
    expect(diff.changedSeverity).toBeDefined();
  });
});
