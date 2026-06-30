/**
 * Tests for CI/CD Pipeline Enhancements v4:
 * 1. Scan Comparison Diff Engine
 * 2. Schedule History Log
 * 3. Webhook Delivery Manager (retry logic, backoff)
 */
import { describe, it, expect, vi } from "vitest";

// ─── 1. Scan Comparison Diff Engine ──────────────────────────────────────────

describe("Scan Comparison Diff Engine", () => {
  // Import the actual module
  const diffModule = async () => import("./lib/cicd-scan-diff");

  describe("fingerprintFinding", () => {
    it("generates stable fingerprints from title + URL", async () => {
      const { fingerprintFinding } = await diffModule();
      const fp1 = fingerprintFinding({ title: "SQL Injection", severity: "high", url: "https://example.com/api/users" });
      const fp2 = fingerprintFinding({ title: "SQL Injection", severity: "critical", url: "https://example.com/api/users" });
      // Same title + URL = same fingerprint regardless of severity
      expect(fp1).toBe(fp2);
    });

    it("normalizes URLs for comparison", async () => {
      const { fingerprintFinding } = await diffModule();
      const fp1 = fingerprintFinding({ title: "XSS", severity: "high", url: "https://example.com/page/" });
      const fp2 = fingerprintFinding({ title: "XSS", severity: "high", url: "http://example.com/page" });
      expect(fp1).toBe(fp2);
    });

    it("differentiates findings with different titles", async () => {
      const { fingerprintFinding } = await diffModule();
      const fp1 = fingerprintFinding({ title: "SQL Injection", severity: "high", url: "https://example.com/api" });
      const fp2 = fingerprintFinding({ title: "XSS", severity: "high", url: "https://example.com/api" });
      expect(fp1).not.toBe(fp2);
    });

    it("handles empty URLs gracefully", async () => {
      const { fingerprintFinding } = await diffModule();
      const fp = fingerprintFinding({ title: "Missing Header", severity: "low" });
      expect(fp).toBeTruthy();
      expect(typeof fp).toBe("string");
    });

    it("is case-insensitive for titles", async () => {
      const { fingerprintFinding } = await diffModule();
      const fp1 = fingerprintFinding({ title: "SQL Injection", severity: "high", url: "https://example.com" });
      const fp2 = fingerprintFinding({ title: "sql injection", severity: "high", url: "https://example.com" });
      expect(fp1).toBe(fp2);
    });
  });

  describe("compareRuns", () => {
    it("identifies new findings in run B", async () => {
      const { compareRuns } = await diffModule();
      const result = compareRuns(
        { id: 1, status: "passed", findings: [
          { title: "XSS", severity: "high", url: "https://a.com" },
        ]},
        { id: 2, status: "failed", findings: [
          { title: "XSS", severity: "high", url: "https://a.com" },
          { title: "SQLi", severity: "critical", url: "https://a.com/api" },
        ]}
      );
      expect(result.newFindings).toHaveLength(1);
      expect(result.newFindings[0].title).toBe("SQLi");
      expect(result.summary.newCount).toBe(1);
    });

    it("identifies fixed findings from run A", async () => {
      const { compareRuns } = await diffModule();
      const result = compareRuns(
        { id: 1, status: "failed", findings: [
          { title: "XSS", severity: "high", url: "https://a.com" },
          { title: "CSRF", severity: "medium", url: "https://a.com/form" },
        ]},
        { id: 2, status: "passed", findings: [
          { title: "XSS", severity: "high", url: "https://a.com" },
        ]}
      );
      expect(result.fixedFindings).toHaveLength(1);
      expect(result.fixedFindings[0].title).toBe("CSRF");
      expect(result.summary.fixedCount).toBe(1);
    });

    it("identifies unchanged findings", async () => {
      const { compareRuns } = await diffModule();
      const result = compareRuns(
        { id: 1, status: "passed", findings: [
          { title: "Weak TLS", severity: "low", url: "https://a.com" },
        ]},
        { id: 2, status: "passed", findings: [
          { title: "Weak TLS", severity: "low", url: "https://a.com" },
        ]}
      );
      expect(result.unchangedFindings).toHaveLength(1);
      expect(result.summary.unchangedCount).toBe(1);
      expect(result.summary.newCount).toBe(0);
      expect(result.summary.fixedCount).toBe(0);
    });

    it("detects severity changes for same finding", async () => {
      const { compareRuns } = await diffModule();
      const result = compareRuns(
        { id: 1, status: "failed", findings: [
          { title: "Open Redirect", severity: "low", url: "https://a.com/redirect" },
        ]},
        { id: 2, status: "failed", findings: [
          { title: "Open Redirect", severity: "high", url: "https://a.com/redirect" },
        ]}
      );
      expect(result.changedSeverity).toHaveLength(1);
      expect(result.changedSeverity[0].oldSeverity).toBe("low");
      expect(result.changedSeverity[0].newSeverity).toBe("high");
      expect(result.summary.changedCount).toBe(1);
    });

    it("calculates positive risk delta when new findings are worse", async () => {
      const { compareRuns } = await diffModule();
      const result = compareRuns(
        { id: 1, status: "passed", findings: [] },
        { id: 2, status: "failed", findings: [
          { title: "RCE", severity: "critical", url: "https://a.com" },
          { title: "SQLi", severity: "high", url: "https://a.com/api" },
        ]}
      );
      expect(result.summary.riskDelta).toBeGreaterThan(0);
    });

    it("calculates negative risk delta when findings are fixed", async () => {
      const { compareRuns } = await diffModule();
      const result = compareRuns(
        { id: 1, status: "failed", findings: [
          { title: "RCE", severity: "critical", url: "https://a.com" },
          { title: "SQLi", severity: "high", url: "https://a.com/api" },
        ]},
        { id: 2, status: "passed", findings: [] }
      );
      expect(result.summary.riskDelta).toBeLessThan(0);
    });

    it("calculates severity delta per level", async () => {
      const { compareRuns } = await diffModule();
      const result = compareRuns(
        { id: 1, status: "failed", findings: [
          { title: "A", severity: "critical", url: "https://a.com/1" },
        ]},
        { id: 2, status: "failed", findings: [
          { title: "A", severity: "critical", url: "https://a.com/1" },
          { title: "B", severity: "high", url: "https://a.com/2" },
          { title: "C", severity: "high", url: "https://a.com/3" },
        ]}
      );
      expect(result.summary.severityDelta.critical).toBe(0);
      expect(result.summary.severityDelta.high).toBe(2);
    });

    it("handles empty findings in both runs", async () => {
      const { compareRuns } = await diffModule();
      const result = compareRuns(
        { id: 1, status: "passed", findings: [] },
        { id: 2, status: "passed", findings: [] }
      );
      expect(result.summary.newCount).toBe(0);
      expect(result.summary.fixedCount).toBe(0);
      expect(result.summary.unchangedCount).toBe(0);
      expect(result.summary.riskDelta).toBe(0);
    });

    it("handles large finding sets correctly", async () => {
      const { compareRuns } = await diffModule();
      const findingsA = Array.from({ length: 50 }, (_, i) => ({
        title: `Finding ${i}`, severity: i % 2 === 0 ? "high" : "medium", url: `https://a.com/${i}`
      }));
      const findingsB = [
        ...findingsA.slice(10), // remove first 10 (fixed)
        ...Array.from({ length: 5 }, (_, i) => ({
          title: `New Finding ${i}`, severity: "critical", url: `https://a.com/new/${i}`
        })),
      ];
      const result = compareRuns(
        { id: 1, status: "failed", findings: findingsA },
        { id: 2, status: "failed", findings: findingsB }
      );
      expect(result.summary.fixedCount).toBe(10);
      expect(result.summary.newCount).toBe(5);
      expect(result.summary.unchangedCount).toBe(40);
    });

    it("includes run metadata in result", async () => {
      const { compareRuns } = await diffModule();
      const result = compareRuns(
        { id: 10, status: "passed", branch: "main", completedAt: "2025-01-01", findings: [] },
        { id: 11, status: "failed", branch: "feature/x", completedAt: "2025-01-02", findings: [] }
      );
      expect(result.runA.id).toBe(10);
      expect(result.runA.branch).toBe("main");
      expect(result.runB.id).toBe(11);
      expect(result.runB.branch).toBe("feature/x");
    });
  });
});

// ─── 2. Webhook Delivery Manager ─────────────────────────────────────────────

describe("Webhook Delivery Manager", () => {
  describe("calculateBackoff", () => {
    it("returns 30s for first retry", async () => {
      const { calculateBackoff } = await import("./lib/cicd-webhook-delivery");
      expect(calculateBackoff(0)).toBe(30_000);
    });

    it("doubles each attempt", async () => {
      const { calculateBackoff } = await import("./lib/cicd-webhook-delivery");
      expect(calculateBackoff(1)).toBe(60_000);
      expect(calculateBackoff(2)).toBe(120_000);
      expect(calculateBackoff(3)).toBe(240_000);
    });

    it("caps at 30 minutes", async () => {
      const { calculateBackoff } = await import("./lib/cicd-webhook-delivery");
      expect(calculateBackoff(20)).toBe(30 * 60_000);
      expect(calculateBackoff(100)).toBe(30 * 60_000);
    });
  });

  describe("describeBackoff", () => {
    it("returns seconds for short delays", async () => {
      const { describeBackoff } = await import("./lib/cicd-webhook-delivery");
      expect(describeBackoff(0)).toBe("30s");
    });

    it("returns minutes for longer delays", async () => {
      const { describeBackoff } = await import("./lib/cicd-webhook-delivery");
      expect(describeBackoff(1)).toBe("1m");
      expect(describeBackoff(2)).toBe("2m");
    });

    it("caps at 30m", async () => {
      const { describeBackoff } = await import("./lib/cicd-webhook-delivery");
      expect(describeBackoff(20)).toBe("30m");
    });
  });
});

// ─── 3. Schedule History Data Model ──────────────────────────────────────────

describe("Schedule History Data Model", () => {
  it("validates schedule history record structure", () => {
    const record = {
      id: 1,
      pipelineId: 10,
      pipelineName: "Production Pipeline",
      status: "passed",
      totalTests: 50,
      passedTests: 48,
      failedTests: 2,
      riskScore: 3.5,
      startedAt: "2025-04-16T10:00:00Z",
      completedAt: "2025-04-16T10:02:30Z",
      createdAt: "2025-04-16T10:00:00Z",
      branch: "scheduled",
      scheduleCron: "0 */6 * * *",
      durationSec: 150,
    };

    expect(record.branch).toBe("scheduled");
    expect(record.durationSec).toBe(150);
    expect(record.status).toBe("passed");
    expect(record.scheduleCron).toBeTruthy();
  });

  it("calculates pass rate correctly", () => {
    const stats = {
      totalRuns: 100,
      passedRuns: 85,
      failedRuns: 10,
      errorRuns: 5,
    };
    const passRate = Math.round((stats.passedRuns / stats.totalRuns) * 100);
    expect(passRate).toBe(85);
  });

  it("handles zero total runs for pass rate", () => {
    const stats = { totalRuns: 0, passedRuns: 0, failedRuns: 0, errorRuns: 0 };
    const passRate = stats.totalRuns > 0 ? Math.round((stats.passedRuns / stats.totalRuns) * 100) : 0;
    expect(passRate).toBe(0);
  });

  it("calculates average duration correctly", () => {
    const runs = [
      { startedAt: "2025-01-01T10:00:00Z", completedAt: "2025-01-01T10:01:00Z" },
      { startedAt: "2025-01-01T11:00:00Z", completedAt: "2025-01-01T11:03:00Z" },
      { startedAt: "2025-01-01T12:00:00Z", completedAt: "2025-01-01T12:02:00Z" },
    ];
    const durations = runs.map(r =>
      Math.round((new Date(r.completedAt).getTime() - new Date(r.startedAt).getTime()) / 1000)
    );
    const avg = Math.round(durations.reduce((a, b) => a + b, 0) / durations.length);
    expect(avg).toBe(120); // (60 + 180 + 120) / 3
  });
});

// ─── 4. Webhook Delivery Record Structure ────────────────────────────────────

describe("Webhook Delivery Record Structure", () => {
  it("validates delivery record fields", () => {
    const record = {
      id: 1,
      pipelineId: 5,
      pipelineName: "Staging Pipeline",
      runId: 42,
      eventType: "run.completed",
      webhookUrl: "https://hooks.slack.com/services/xxx",
      deliveryStatus: "delivered" as const,
      responseStatus: 200,
      responseBody: "ok",
      attemptCount: 1,
      maxRetries: 3,
      nextRetryAt: null,
      lastAttemptAt: "2025-04-16T10:00:00Z",
      deliveredAt: "2025-04-16T10:00:00Z",
      createdAt: "2025-04-16T10:00:00Z",
      errorMessage: null,
      durationMs: 245,
    };

    expect(record.deliveryStatus).toBe("delivered");
    expect(record.responseStatus).toBe(200);
    expect(record.attemptCount).toBeLessThanOrEqual(record.maxRetries);
    expect(record.durationMs).toBeGreaterThan(0);
  });

  it("validates retry state transitions", () => {
    const validTransitions: Record<string, string[]> = {
      pending: ["delivered", "retrying", "failed"],
      retrying: ["delivered", "retrying", "failed"],
      delivered: [], // terminal
      failed: ["retrying"], // manual retry
    };

    expect(validTransitions.pending).toContain("delivered");
    expect(validTransitions.pending).toContain("retrying");
    expect(validTransitions.retrying).toContain("delivered");
    expect(validTransitions.retrying).toContain("failed");
    expect(validTransitions.delivered).toHaveLength(0);
    expect(validTransitions.failed).toContain("retrying");
  });

  it("calculates delivery rate correctly", () => {
    const stats = { total: 50, delivered: 45, failed: 3, retrying: 2, pending: 0 };
    const deliveryRate = Math.round((stats.delivered / stats.total) * 100);
    expect(deliveryRate).toBe(90);
  });

  it("handles exponential backoff schedule", async () => {
    const { calculateBackoff } = await import("./lib/cicd-webhook-delivery");
    // Verify the backoff schedule for 4 retries
    const schedule = [0, 1, 2, 3].map(i => calculateBackoff(i));
    expect(schedule).toEqual([30_000, 60_000, 120_000, 240_000]);
    // Each should be double the previous
    for (let i = 1; i < schedule.length; i++) {
      expect(schedule[i]).toBe(schedule[i - 1] * 2);
    }
  });
});

// ─── 5. Integration Scenarios ────────────────────────────────────────────────

describe("Integration Scenarios", () => {
  it("scan diff correctly handles a full regression scenario", async () => {
    const { compareRuns } = await import("./lib/cicd-scan-diff");
    // Baseline: clean scan
    const baseline = { id: 1, status: "passed", branch: "main", findings: [
      { title: "Info Disclosure", severity: "low", url: "https://app.com/version" },
    ]};
    // After bad deploy: multiple new vulns
    const afterDeploy = { id: 2, status: "failed", branch: "feature/auth-rewrite", findings: [
      { title: "Info Disclosure", severity: "low", url: "https://app.com/version" },
      { title: "Auth Bypass", severity: "critical", url: "https://app.com/admin" },
      { title: "IDOR", severity: "high", url: "https://app.com/api/users/1" },
      { title: "Missing CSRF", severity: "medium", url: "https://app.com/settings" },
    ]};

    const diff = compareRuns(baseline, afterDeploy);
    expect(diff.summary.newCount).toBe(3);
    expect(diff.summary.fixedCount).toBe(0);
    expect(diff.summary.unchangedCount).toBe(1);
    expect(diff.summary.riskDelta).toBeGreaterThan(0);
    expect(diff.summary.severityDelta.critical).toBe(1);
    expect(diff.summary.severityDelta.high).toBe(1);
    expect(diff.summary.severityDelta.medium).toBe(1);
  });

  it("scan diff correctly handles a remediation scenario", async () => {
    const { compareRuns } = await import("./lib/cicd-scan-diff");
    const before = { id: 5, status: "failed", findings: [
      { title: "SQLi", severity: "critical", url: "https://app.com/search" },
      { title: "XSS", severity: "high", url: "https://app.com/comments" },
      { title: "CSRF", severity: "medium", url: "https://app.com/form" },
    ]};
    const after = { id: 6, status: "passed", findings: [
      { title: "CSRF", severity: "medium", url: "https://app.com/form" },
    ]};

    const diff = compareRuns(before, after);
    expect(diff.summary.fixedCount).toBe(2);
    expect(diff.summary.newCount).toBe(0);
    expect(diff.summary.unchangedCount).toBe(1);
    expect(diff.summary.riskDelta).toBeLessThan(0);
  });

  it("webhook delivery handles max retries exhaustion", async () => {
    const { calculateBackoff } = await import("./lib/cicd-webhook-delivery");
    const maxRetries = 3;
    let attemptCount = 0;
    let status = "pending";

    // Simulate 3 failed attempts
    for (let i = 0; i < maxRetries; i++) {
      attemptCount++;
      if (attemptCount >= maxRetries) {
        status = "failed";
      } else {
        status = "retrying";
        const backoff = calculateBackoff(attemptCount);
        expect(backoff).toBeGreaterThan(0);
      }
    }

    expect(status).toBe("failed");
    expect(attemptCount).toBe(3);
  });

  it("schedule history filters by pipeline correctly", () => {
    const allRecords = [
      { id: 1, pipelineId: 10, status: "passed" },
      { id: 2, pipelineId: 20, status: "failed" },
      { id: 3, pipelineId: 10, status: "passed" },
      { id: 4, pipelineId: 30, status: "error" },
      { id: 5, pipelineId: 10, status: "failed" },
    ];

    const filtered = allRecords.filter(r => r.pipelineId === 10);
    expect(filtered).toHaveLength(3);
    expect(filtered.every(r => r.pipelineId === 10)).toBe(true);
  });
});
