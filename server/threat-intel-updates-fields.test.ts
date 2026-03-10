/**
 * Tests to verify threatIntelUpdates field name alignment with the Drizzle schema.
 * The schema uses tiuStatus, tiuStartedAt, tiuCompletedAt, tiuSummary, tiuDetails, tiuErrors
 * while code previously used status, startedAt, completedAt, summary, details, errors.
 */
import { describe, it, expect } from "vitest";
import { threatIntelUpdates } from "../drizzle/schema";

describe("threatIntelUpdates schema field alignment", () => {
  it("should have tiuStatus column (not status)", () => {
    expect(threatIntelUpdates.tiuStatus).toBeDefined();
    expect((threatIntelUpdates as any).status).toBeUndefined();
  });

  it("should have tiuStartedAt column (not startedAt)", () => {
    expect(threatIntelUpdates.tiuStartedAt).toBeDefined();
    expect((threatIntelUpdates as any).startedAt).toBeUndefined();
  });

  it("should have tiuCompletedAt column (not completedAt)", () => {
    expect(threatIntelUpdates.tiuCompletedAt).toBeDefined();
    expect((threatIntelUpdates as any).completedAt).toBeUndefined();
  });

  it("should have tiuSummary column (not summary)", () => {
    expect(threatIntelUpdates.tiuSummary).toBeDefined();
    expect((threatIntelUpdates as any).summary).toBeUndefined();
  });

  it("should have tiuDetails column (not details)", () => {
    expect(threatIntelUpdates.tiuDetails).toBeDefined();
    expect((threatIntelUpdates as any).details).toBeUndefined();
  });

  it("should have tiuErrors column (not errors)", () => {
    expect(threatIntelUpdates.tiuErrors).toBeDefined();
    expect((threatIntelUpdates as any).errors).toBeUndefined();
  });

  it("should have sweepType column", () => {
    expect(threatIntelUpdates.sweepType).toBeDefined();
  });

  it("should have groupsScanned column", () => {
    expect(threatIntelUpdates.groupsScanned).toBeDefined();
  });

  it("should have updatesApplied column", () => {
    expect(threatIntelUpdates.updatesApplied).toBeDefined();
  });

  it("should have durationMs column", () => {
    expect(threatIntelUpdates.durationMs).toBeDefined();
  });
});

describe("iocSyncLogs schema field alignment", () => {
  it("should verify iocSyncLogs has correct column names", async () => {
    const { iocSyncLogs } = await import("../drizzle/schema");
    expect(iocSyncLogs.status).toBeDefined();
    expect(iocSyncLogs.startedAt).toBeDefined();
    expect(iocSyncLogs.completedAt).toBeDefined();
    expect(iocSyncLogs.syncType).toBeDefined();
    expect(iocSyncLogs.totalFetched).toBeDefined();
    expect(iocSyncLogs.errorMessage).toBeDefined();
  });
});

describe("threatActors schema field alignment", () => {
  it("should have actorType column (not type)", async () => {
    const { threatActors } = await import("../drizzle/schema");
    expect(threatActors.actorType).toBeDefined();
    expect((threatActors as any).type).toBeUndefined();
  });
});

describe("iocFeeds schema field alignment", () => {
  it("should have feedSeverity column (not severity)", async () => {
    const { iocFeeds } = await import("../drizzle/schema");
    expect(iocFeeds.feedSeverity).toBeDefined();
    expect((iocFeeds as any).severity).toBeUndefined();
  });

  it("should have feedIocType column (not iocType)", async () => {
    const { iocFeeds } = await import("../drizzle/schema");
    expect(iocFeeds.feedIocType).toBeDefined();
    expect((iocFeeds as any).iocType).toBeUndefined();
  });

  it("should have feedTags column (not tags)", async () => {
    const { iocFeeds } = await import("../drizzle/schema");
    expect(iocFeeds.feedTags).toBeDefined();
    expect((iocFeeds as any).tags).toBeUndefined();
  });
});
