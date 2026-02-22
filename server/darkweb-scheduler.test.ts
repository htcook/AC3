/**
 * Darkweb Feed Scheduler & UI Migration Tests
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("Darkweb Feed Scheduler", () => {
  it("should export initDarkwebFeedScheduler function", async () => {
    const mod = await import("./lib/darkweb-feed-scheduler");
    expect(typeof mod.initDarkwebFeedScheduler).toBe("function");
  });

  it("should export stopDarkwebFeedScheduler function", async () => {
    const mod = await import("./lib/darkweb-feed-scheduler");
    expect(typeof mod.stopDarkwebFeedScheduler).toBe("function");
  });

  it("should export isDarkwebSchedulerActive function", async () => {
    const mod = await import("./lib/darkweb-feed-scheduler");
    expect(typeof mod.isDarkwebSchedulerActive).toBe("function");
  });

  it("should export runFullDarkwebSync function", async () => {
    const mod = await import("./lib/darkweb-feed-scheduler");
    expect(typeof mod.runFullDarkwebSync).toBe("function");
  });

  it("scheduler should report inactive before initialization", async () => {
    const { isDarkwebSchedulerActive, stopDarkwebFeedScheduler } = await import("./lib/darkweb-feed-scheduler");
    // Ensure stopped state
    stopDarkwebFeedScheduler();
    expect(isDarkwebSchedulerActive()).toBe(false);
  });

  it("scheduler should activate after initialization and deactivate after stop", async () => {
    const { initDarkwebFeedScheduler, isDarkwebSchedulerActive, stopDarkwebFeedScheduler } = await import("./lib/darkweb-feed-scheduler");
    // Ensure clean state
    stopDarkwebFeedScheduler();
    expect(isDarkwebSchedulerActive()).toBe(false);

    initDarkwebFeedScheduler();
    expect(isDarkwebSchedulerActive()).toBe(true);

    stopDarkwebFeedScheduler();
    expect(isDarkwebSchedulerActive()).toBe(false);
  });

  it("should not double-initialize the scheduler", async () => {
    const { initDarkwebFeedScheduler, isDarkwebSchedulerActive, stopDarkwebFeedScheduler } = await import("./lib/darkweb-feed-scheduler");
    stopDarkwebFeedScheduler();

    initDarkwebFeedScheduler();
    expect(isDarkwebSchedulerActive()).toBe(true);

    // Second call should be a no-op
    initDarkwebFeedScheduler();
    expect(isDarkwebSchedulerActive()).toBe(true);

    stopDarkwebFeedScheduler();
  });
});

describe("Darkweb Intel Router - Scheduler Endpoints", () => {
  it("darkweb-intel router should export schedulerStatus and triggerFullSync procedures", async () => {
    const { darkwebIntelRouter } = await import("./routers/darkweb-intel");
    const procedures = Object.keys(darkwebIntelRouter._def.procedures);
    expect(procedures).toContain("schedulerStatus");
    expect(procedures).toContain("triggerFullSync");
  });
});

describe("UI Migration - No Bridge References", () => {
  it("DarkwebIntel.tsx should not reference darkwebBridge", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("client/src/pages/DarkwebIntel.tsx", "utf-8");
    expect(content).not.toContain("darkwebBridge");
    expect(content).toContain("darkwebIntel");
  });

  it("ThreatIntelHub.tsx should not reference darkwebBridge", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("client/src/pages/ThreatIntelHub.tsx", "utf-8");
    expect(content).not.toContain("darkwebBridge");
    expect(content).toContain("darkwebIntel");
  });

  it("AlertDetailModal.tsx should not reference darkwebBridge", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("client/src/components/AlertDetailModal.tsx", "utf-8");
    expect(content).not.toContain("darkwebBridge");
    expect(content).toContain("darkwebIntel");
  });

  it("CorroborationPanel.tsx should not reference darkwebBridge", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("client/src/components/CorroborationPanel.tsx", "utf-8");
    expect(content).not.toContain("darkwebBridge");
    expect(content).toContain("darkwebIntel");
  });
});

describe("Darkweb Intel Router - Bridge-equivalent Procedures", () => {
  it("should have all bridge-equivalent procedures", async () => {
    const { darkwebIntelRouter } = await import("./routers/darkweb-intel");
    const procedures = Object.keys(darkwebIntelRouter._def.procedures);

    // All bridge-equivalent procedures that the UI depends on
    const requiredProcedures = [
      "health",
      "escalationAlerts",
      "ransomwareVictimStats",
      "activityRatings",
      "threatFoxIOCs",
      "cisaKEV",
      "otxPulses",
      "malwareBazaar",
      "adaptiveKeywords",
      "recentVictimEvents",
      "accessBrokers",
      "infoOpsCampaigns",
      "syncDarkwebFeeds",
      "syncAll",
      "alertDetail",
      "corroborateAssets",
    ];

    for (const proc of requiredProcedures) {
      expect(procedures, `Missing procedure: ${proc}`).toContain(proc);
    }
  });

  it("should have the new self-contained procedures", async () => {
    const { darkwebIntelRouter } = await import("./routers/darkweb-intel");
    const procedures = Object.keys(darkwebIntelRouter._def.procedures);

    const newProcedures = [
      "feedRegistry",
      "initFeeds",
      "feedHealth",
      "toggleFeed",
      "syncAllFeeds",
      "syncSingleFeed",
      "syncStatus",
      "listEvents",
      "getEvent",
      "eventStats",
      "highPriorityEvents",
      "listNetworkEvents",
      "networkEventStats",
      "listCredentialExposures",
      "credentialStats",
      "listIabActivity",
      "listInfluenceOps",
      "listAffiliates",
      "syncActors",
      "enrichEvent",
      "enrichBatch",
      "enrichmentStats",
      "listEnrichedRecords",
      "sectorProfiles",
      "trends",
      "correlateActor",
      "enrichIoc",
      "enrichIocBatch",
      "schedulerStatus",
      "triggerFullSync",
    ];

    for (const proc of newProcedures) {
      expect(procedures, `Missing new procedure: ${proc}`).toContain(proc);
    }
  });
});
