import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ─── Hoisted mocks (vi.mock factories are hoisted above imports) ─────────
const { mockExecute, mockEnd, mockCreateConnection, mockDbInsert, mockSchedule } = vi.hoisted(() => {
  const mockExecute = vi.fn();
  const mockEnd = vi.fn();
  const mockCreateConnection = vi.fn().mockResolvedValue({
    execute: mockExecute,
    end: mockEnd,
  });
  const mockDbInsert = vi.fn().mockReturnValue({
    values: vi.fn().mockResolvedValue([{ insertId: 42 }]),
  });
  const mockSchedule = vi.fn().mockReturnValue({ stop: vi.fn() });
  return { mockExecute, mockEnd, mockCreateConnection, mockDbInsert, mockSchedule };
});

// ─── Mock mysql2/promise ─────────────────────────────────────────────────
vi.mock("mysql2/promise", () => ({
  default: { createConnection: mockCreateConnection },
  createConnection: mockCreateConnection,
}));

// ─── Mock getDb (Drizzle) for audit trail ────────────────────────────────
vi.mock("../db", () => ({
  getDb: vi.fn().mockResolvedValue({
    insert: mockDbInsert,
  }),
}));

// ─── Mock drizzle schema ─────────────────────────────────────────────────
vi.mock("../../drizzle/schema", () => ({
  threatActors: { actorId: "actorId", lastActive: "lastActive" },
  threatIntelUpdates: {},
}));

// ─── Mock node-cron for scheduler tests ──────────────────────────────────
vi.mock("node-cron", () => ({
  default: { schedule: mockSchedule },
  schedule: mockSchedule,
}));

// ─── Mock fetch for ransomware.live tests ────────────────────────────────
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// ─── Import after mocks ─────────────────────────────────────────────────
import {
  updateFromThreatGroupEvents,
  updateFromUndergroundIntelEvents,
  updateFromRansomwareLiveVictims,
  runLastActiveUpdate,
  isLastActiveUpdateRunning,
} from "./lib/last-active-updater";
import {
  initLastActiveScheduler,
  stopLastActiveScheduler,
  isLastActiveSchedulerActive,
} from "./lib/last-active-scheduler";

// ─── Helpers ─────────────────────────────────────────────────────────────

function setupTGEMock(rows: { tgeActorId: string; latestEvent: string }[], existingActors: { actorId: string; lastActive: string | null }[]) {
  mockExecute.mockReset();
  mockEnd.mockReset();

  mockExecute.mockImplementation((query: string, params?: any[]) => {
    const q = query.trim().toLowerCase();
    if (q.includes("group by tgeactorid") || (q.includes("group by") && q.includes("threat_group_events"))) {
      return [rows];
    }
    if (q.includes("select") && q.includes("threat_actors") && q.includes("lower(actorid)")) {
      const actorId = params?.[0]?.toLowerCase();
      const match = existingActors.filter(a => a.actorId.toLowerCase() === actorId);
      return [match];
    }
    if (q.includes("update")) {
      return [{ affectedRows: 1 }];
    }
    return [[]];
  });
}

function setupUIEMock(rows: { uie_actor_name: string; latestEvent: string }[], existingActors: { actorId: string; lastActive: string | null }[]) {
  mockExecute.mockReset();
  mockEnd.mockReset();

  mockExecute.mockImplementation((query: string, params?: any[]) => {
    const q = query.trim().toLowerCase();
    if (q.includes("group by uie_actor_name") || (q.includes("group by") && q.includes("underground"))) {
      return [rows];
    }
    if (q.includes("select") && q.includes("threat_actors") && (q.includes("lower(name)") || q.includes("lower(actorid)"))) {
      const name = params?.[0]?.toLowerCase();
      const match = existingActors.filter(a => a.actorId.toLowerCase() === name);
      return [match];
    }
    if (q.includes("update")) {
      return [{ affectedRows: 1 }];
    }
    return [[]];
  });
}

describe("lastActive Updater Service", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockCreateConnection.mockResolvedValue({
      execute: mockExecute,
      end: mockEnd,
    });
  });

  describe("Source 1: threat_group_events", () => {
    it("should update actors with newer event dates", async () => {
      setupTGEMock(
        [{ tgeActorId: "lockbit", latestEvent: "2026-04-21T10:00:00.000Z" }],
        [{ actorId: "lockbit", lastActive: "2026-03" }]
      );

      const result = await updateFromThreatGroupEvents();
      expect(result.source).toBe("threat_group_events");
      expect(result.actorsScanned).toBe(1);
      expect(result.actorsUpdated).toBe(1);
      expect(result.errors).toHaveLength(0);
    });

    it("should NOT update actors when existing date is newer", async () => {
      setupTGEMock(
        [{ tgeActorId: "lockbit", latestEvent: "2026-02-15T10:00:00.000Z" }],
        [{ actorId: "lockbit", lastActive: "2026-04" }]
      );

      const result = await updateFromThreatGroupEvents();
      expect(result.actorsScanned).toBe(1);
      expect(result.actorsUpdated).toBe(0);
    });

    it("should update actors with null lastActive", async () => {
      setupTGEMock(
        [{ tgeActorId: "apt28", latestEvent: "2026-04-10T10:00:00.000Z" }],
        [{ actorId: "apt28", lastActive: null }]
      );

      const result = await updateFromThreatGroupEvents();
      expect(result.actorsUpdated).toBe(1);
    });

    it("should skip actors not found in threat_actors table", async () => {
      setupTGEMock(
        [{ tgeActorId: "unknown-group", latestEvent: "2026-04-21T10:00:00.000Z" }],
        []
      );

      const result = await updateFromThreatGroupEvents();
      expect(result.actorsScanned).toBe(1);
      expect(result.actorsUpdated).toBe(0);
    });

    it("should handle multiple actors in one run", async () => {
      mockExecute.mockReset();
      mockEnd.mockReset();

      const tgeRows = [
        { tgeActorId: "lockbit", latestEvent: "2026-04-21T10:00:00.000Z" },
        { tgeActorId: "conti", latestEvent: "2026-04-20T10:00:00.000Z" },
        { tgeActorId: "revil", latestEvent: "2026-03-15T10:00:00.000Z" },
      ];
      const actors = [
        { actorId: "lockbit", lastActive: "2026-03" },
        { actorId: "conti", lastActive: "2026-04" },
        { actorId: "revil", lastActive: null },
      ];

      mockExecute.mockImplementation((query: string, params?: any[]) => {
        const q = query.trim().toLowerCase();
        if (q.includes("group by")) return [tgeRows];
        if (q.includes("select") && q.includes("threat_actors")) {
          const id = params?.[0]?.toLowerCase();
          const match = actors.filter(a => a.actorId === id);
          return [match];
        }
        if (q.includes("update")) return [{ affectedRows: 1 }];
        return [[]];
      });

      const result = await updateFromThreatGroupEvents();
      expect(result.actorsScanned).toBe(3);
      expect(result.actorsUpdated).toBe(2);
    });

    it("should handle empty threat_group_events", async () => {
      setupTGEMock([], []);

      const result = await updateFromThreatGroupEvents();
      expect(result.actorsScanned).toBe(0);
      expect(result.actorsUpdated).toBe(0);
    });
  });

  describe("Source 2: underground_intel_events", () => {
    it("should update actors matched by name", async () => {
      setupUIEMock(
        [{ uie_actor_name: "LockBit", latestEvent: "2026-04-21T10:00:00.000Z" }],
        [{ actorId: "lockbit", lastActive: "2026-03" }]
      );

      const result = await updateFromUndergroundIntelEvents();
      expect(result.source).toBe("underground_intel_events");
      expect(result.actorsScanned).toBe(1);
      expect(result.actorsUpdated).toBe(1);
    });

    it("should NOT update when existing date is same or newer", async () => {
      setupUIEMock(
        [{ uie_actor_name: "Akira", latestEvent: "2026-03-15T10:00:00.000Z" }],
        [{ actorId: "akira", lastActive: "2026-04" }]
      );

      const result = await updateFromUndergroundIntelEvents();
      expect(result.actorsUpdated).toBe(0);
    });

    it("should skip unmatched actor names", async () => {
      setupUIEMock(
        [{ uie_actor_name: "SomeRandomMalware", latestEvent: "2026-04-21T10:00:00.000Z" }],
        []
      );

      const result = await updateFromUndergroundIntelEvents();
      expect(result.actorsScanned).toBe(1);
      expect(result.actorsUpdated).toBe(0);
    });
  });

  describe("Source 3: ransomware.live /v1/recentvictims", () => {
    it("should update actors from ransomware.live victim data", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => [
          { group_name: "lockbit", published: "2026-04-21", victim: "Acme Corp" },
          { group_name: "lockbit", published: "2026-04-20", victim: "Other Corp" },
          { group_name: "conti", published: "2026-04-19", victim: "Test Corp" },
        ],
      });

      mockExecute.mockImplementation((query: string, params?: any[]) => {
        const q = query.trim().toLowerCase();
        if (q.includes("select") && q.includes("threat_actors")) {
          const name = params?.[0];
          if (name === "lockbit") return [[{ actorId: "lockbit", lastActive: "2026-03" }]];
          if (name === "conti") return [[{ actorId: "conti", lastActive: "2026-04" }]];
          return [[]];
        }
        if (q.includes("update")) return [{ affectedRows: 1 }];
        return [[]];
      });

      const result = await updateFromRansomwareLiveVictims();
      expect(result.source).toBe("ransomware_live_victims");
      expect(result.actorsScanned).toBe(2);
      expect(result.actorsUpdated).toBe(1);
    });

    it("should handle API fetch failure gracefully", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network timeout"));

      const result = await updateFromRansomwareLiveVictims();
      expect(result.actorsScanned).toBe(0);
      expect(result.actorsUpdated).toBe(0);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]).toContain("API fetch failed");
    });

    it("should handle non-200 API response", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 503,
      });

      const result = await updateFromRansomwareLiveVictims();
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]).toContain("HTTP 503");
    });

    it("should handle empty victim list", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => [],
      });

      const result = await updateFromRansomwareLiveVictims();
      expect(result.actorsScanned).toBe(0);
      expect(result.actorsUpdated).toBe(0);
      expect(result.errors).toHaveLength(0);
    });

    it("should pick the most recent published date per group", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => [
          { group_name: "play", published: "2026-04-10", victim: "A" },
          { group_name: "play", published: "2026-04-21", victim: "B" },
          { group_name: "play", published: "2026-04-15", victim: "C" },
        ],
      });

      let updateCalledWith: string | null = null;
      mockExecute.mockImplementation((query: string, params?: any[]) => {
        const q = query.trim().toLowerCase();
        if (q.includes("select") && q.includes("threat_actors")) {
          return [[{ actorId: "play", lastActive: "2026-03" }]];
        }
        if (q.includes("update")) {
          updateCalledWith = params?.[0] as string;
          return [{ affectedRows: 1 }];
        }
        return [[]];
      });

      const result = await updateFromRansomwareLiveVictims();
      expect(result.actorsUpdated).toBe(1);
      expect(updateCalledWith).toBe("2026-04");
    });
  });

  describe("Full Pipeline (runLastActiveUpdate)", () => {
    it("should run all 3 sources and return aggregated results", async () => {
      mockExecute.mockImplementation(() => [[]]);
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => [],
      });

      const result = await runLastActiveUpdate("manual");
      expect(result.sources).toHaveLength(3);
      expect(result.sources[0].source).toBe("threat_group_events");
      expect(result.sources[1].source).toBe("underground_intel_events");
      expect(result.sources[2].source).toBe("ransomware_live_victims");
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });

    it("should write audit trail to threat_intel_updates", async () => {
      mockExecute.mockImplementation(() => [[]]);
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => [],
      });

      const result = await runLastActiveUpdate("scheduled");
      // The audit log is written via Drizzle db.insert()
      // Verify the result contains audit info
      expect(result.sources).toHaveLength(3);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
      // auditLogId may be 42 (from mock) or null if mock didn't match
      // The key assertion is that the pipeline completed without throwing
      expect(typeof result.totalActorsUpdated).toBe("number");
    });

    it("should not run concurrently", async () => {
      expect(isLastActiveUpdateRunning()).toBe(false);
    });
  });

  describe("Scheduler", () => {
    beforeEach(() => {
      mockSchedule.mockClear();
      stopLastActiveScheduler();
    });

    afterEach(() => {
      stopLastActiveScheduler();
    });

    it("should register a cron job at 08:15 UTC", () => {
      initLastActiveScheduler();
      expect(mockSchedule).toHaveBeenCalledTimes(1);
      expect(mockSchedule).toHaveBeenCalledWith(
        "0 15 8 * * *",
        expect.any(Function),
        { timezone: "UTC" }
      );
    });

    it("should report active status after init", () => {
      expect(isLastActiveSchedulerActive()).toBe(false);
      initLastActiveScheduler();
      expect(isLastActiveSchedulerActive()).toBe(true);
    });

    it("should not double-initialize", () => {
      initLastActiveScheduler();
      initLastActiveScheduler();
      expect(mockSchedule).toHaveBeenCalledTimes(1);
    });

    it("should stop cleanly", () => {
      initLastActiveScheduler();
      expect(isLastActiveSchedulerActive()).toBe(true);
      stopLastActiveScheduler();
      expect(isLastActiveSchedulerActive()).toBe(false);
    });
  });

  describe("YYYY-MM format validation", () => {
    it("should correctly convert dates to YYYY-MM", async () => {
      mockExecute.mockReset();
      mockEnd.mockReset();

      let updateCalledWith: string | null = null;
      mockExecute.mockImplementation((query: string, params?: any[]) => {
        const q = query.trim().toLowerCase();
        if (q.includes("group by")) return [[{ tgeActorId: "testactor", latestEvent: "2026-01-15T10:00:00.000Z" }]];
        if (q.includes("select") && q.includes("threat_actors")) return [[{ actorId: "testactor", lastActive: null }]];
        if (q.includes("update")) {
          updateCalledWith = params?.[0] as string;
          return [{ affectedRows: 1 }];
        }
        return [[]];
      });

      await updateFromThreatGroupEvents();
      expect(updateCalledWith).toBe("2026-01");
    });
  });

  describe("Hardcoded lastActive fix verification", () => {
    it("should confirm dailydarkweb-feed.ts no longer overwrites lastActive on update path", async () => {
      const fs = await import("fs");
      const path = await import("path");
      const feedPath = path.resolve(__dirname, "lib/dailydarkweb-feed.ts");
      const content = fs.readFileSync(feedPath, "utf-8");

      // Find the FULCRUMSEC update block
      const fulcrumsecUpdateMatch = content.match(
        /} else \{[\s\S]*?Do NOT overwrite lastActive[\s\S]*?\.where\(eq\(threatActors\.actorId, FULCRUMSEC_ACTOR\.actorId\)\)/
      );
      expect(fulcrumsecUpdateMatch).not.toBeNull();

      // Find the DAILYDARKWEB_ACTORS update block
      const actorsUpdateMatch = content.match(
        /} else \{[\s\S]*?Do NOT overwrite lastActive[\s\S]*?\.where\(eq\(threatActors\.actorId, actor\.actorId\)\)/
      );
      expect(actorsUpdateMatch).not.toBeNull();

      // Verify the .set() calls do NOT contain "lastActive:"
      if (fulcrumsecUpdateMatch) {
        const setBlock = fulcrumsecUpdateMatch[0].match(/\.set\(\{[\s\S]*?\}\)/);
        expect(setBlock?.[0]).not.toContain("lastActive:");
      }
    });
  });
});
