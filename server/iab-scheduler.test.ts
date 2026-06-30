import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock node-cron
const mockSchedule = vi.fn().mockReturnValue({ stop: vi.fn() });
vi.mock("node-cron", () => ({
  default: { schedule: mockSchedule },
  schedule: mockSchedule,
}));

// Mock the ingestion and alerting services
vi.mock("./lib/iab-ingestion-service", () => ({
  runIABIngestionPipeline: vi.fn().mockResolvedValue({
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    results: [
      { source: "ransomware_live_groups", fetched: 5, inserted: 3, skipped: 2, durationMs: 100 },
      { source: "cisa_kev_exploits", fetched: 10, inserted: 7, skipped: 3, durationMs: 200 },
    ],
    totalInserted: 10,
    totalErrors: 0,
  }),
}));

vi.mock("./lib/iab-spike-alerting", () => ({
  runIABSpikeCheck: vi.fn().mockResolvedValue({
    checkedAt: new Date().toISOString(),
    alerts: [],
    notificationsSent: 0,
    notificationsFailed: 0,
  }),
  getDefaultThresholds: vi.fn().mockReturnValue({
    monthlyVolumeThreshold: 20,
    govTargetingThreshold: 5,
    highValuePriceThreshold: 50000,
    newBrokerDailyThreshold: 5,
    volumeSpikePercent: 50,
  }),
}));

describe("IAB Ingestion Scheduler", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset module state between tests
    vi.resetModules();
  });

  it("should initialize with two cron jobs", async () => {
    const { initIABIngestionScheduler } = await import("./lib/iab-ingestion-scheduler");
    initIABIngestionScheduler();

    // Should register 2 cron jobs: ingestion + spike check
    expect(mockSchedule).toHaveBeenCalledTimes(2);
  });

  it("should schedule ingestion at 08:45 UTC", async () => {
    const { initIABIngestionScheduler } = await import("./lib/iab-ingestion-scheduler");
    initIABIngestionScheduler();

    const firstCall = mockSchedule.mock.calls[0];
    expect(firstCall[0]).toBe("0 45 8 * * *");
    expect(firstCall[2]).toEqual({ timezone: "UTC" });
  });

  it("should schedule spike detection at 09:15 UTC", async () => {
    const { initIABIngestionScheduler } = await import("./lib/iab-ingestion-scheduler");
    initIABIngestionScheduler();

    const secondCall = mockSchedule.mock.calls[1];
    expect(secondCall[0]).toBe("0 15 9 * * *");
    expect(secondCall[2]).toEqual({ timezone: "UTC" });
  });

  it("should not initialize twice", async () => {
    const { initIABIngestionScheduler } = await import("./lib/iab-ingestion-scheduler");
    initIABIngestionScheduler();
    initIABIngestionScheduler(); // second call should be no-op

    expect(mockSchedule).toHaveBeenCalledTimes(2); // still only 2
  });

  it("should stop all tasks when stopIABIngestionScheduler is called", async () => {
    const mockStop = vi.fn();
    mockSchedule.mockReturnValue({ stop: mockStop });

    const { initIABIngestionScheduler, stopIABIngestionScheduler, isIABSchedulerActive } =
      await import("./lib/iab-ingestion-scheduler");

    initIABIngestionScheduler();
    expect(isIABSchedulerActive()).toBe(true);

    stopIABIngestionScheduler();
    expect(mockStop).toHaveBeenCalledTimes(2);
    expect(isIABSchedulerActive()).toBe(false);
  });

  it("should report active status correctly", async () => {
    const { initIABIngestionScheduler, isIABSchedulerActive } =
      await import("./lib/iab-ingestion-scheduler");

    expect(isIABSchedulerActive()).toBe(false);
    initIABIngestionScheduler();
    expect(isIABSchedulerActive()).toBe(true);
  });
});
