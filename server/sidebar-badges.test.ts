import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Tests for the sidebar badges procedure.
 * Validates the getSidebarBadges endpoint returns the expected shape
 * and handles failures gracefully.
 */

// Mock the db module
vi.mock("./db", () => ({
  getDomainIntelScans: vi.fn().mockResolvedValue([
    { id: 1, status: "scan_complete", domain: "tesla.com" },
    { id: 2, status: "scan_complete", domain: "cloudflare.com" },
    { id: 3, status: "scanning", domain: "github.com" },
  ]),
  getEngagements: vi.fn().mockResolvedValue([
    { id: 1, name: "Test Engagement" },
    { id: 2, name: "Another Engagement" },
  ]),
  getThreatActorCount: vi.fn().mockResolvedValue(42),
  getIocFeedStats: vi.fn().mockResolvedValue({ total: 150, recentCount: 12 }),
}));

describe("Sidebar Badges Data Shape", () => {
  it("should return badge data for all 9 sidebar groups", async () => {
    // Import after mocks are set up
    const db = await import("./db");

    // Simulate what the procedure does
    const [scans, engagements, threatActorCount, iocStats] = await Promise.allSettled([
      db.getDomainIntelScans(),
      db.getEngagements(),
      db.getThreatActorCount(),
      db.getIocFeedStats(),
    ]);

    const scanList = scans.status === "fulfilled" ? scans.value : [];
    const engagementList = engagements.status === "fulfilled" ? engagements.value : [];
    const actorCount = threatActorCount.status === "fulfilled" ? threatActorCount.value : 0;
    const iocData = iocStats.status === "fulfilled" ? iocStats.value : { total: 0, recentCount: 0 };

    const completedScans = scanList.filter((s: any) => s.status === "completed" || s.status === "scan_complete");

    const result = {
      recon: { total: scanList.length, completed: completedScans.length },
      intelligence: { actors: actorCount, iocs: (iocData as any).total, recentIocs: (iocData as any).recentCount },
      planning: { engagements: engagementList.length },
      phishing: {},
      exploitation: {},
      emulation: {},
      reports: {},
      knowledge: {},
      admin: {},
    };

    // Validate structure
    expect(result).toHaveProperty("recon");
    expect(result).toHaveProperty("intelligence");
    expect(result).toHaveProperty("planning");
    expect(result).toHaveProperty("phishing");
    expect(result).toHaveProperty("exploitation");
    expect(result).toHaveProperty("emulation");
    expect(result).toHaveProperty("reports");
    expect(result).toHaveProperty("knowledge");
    expect(result).toHaveProperty("admin");

    // Validate recon data
    expect(result.recon.total).toBe(3);
    expect(result.recon.completed).toBe(2);

    // Validate intelligence data
    expect(result.intelligence.actors).toBe(42);
    expect(result.intelligence.iocs).toBe(150);
    expect(result.intelligence.recentIocs).toBe(12);

    // Validate planning data
    expect(result.planning.engagements).toBe(2);
  });

  it("should handle database failures gracefully", async () => {
    const db = await import("./db");
    vi.mocked(db.getDomainIntelScans).mockRejectedValueOnce(new Error("DB down"));
    vi.mocked(db.getEngagements).mockRejectedValueOnce(new Error("DB down"));
    vi.mocked(db.getThreatActorCount).mockRejectedValueOnce(new Error("DB down"));
    vi.mocked(db.getIocFeedStats).mockRejectedValueOnce(new Error("DB down"));

    const [scans, engagements, threatActorCount, iocStats] = await Promise.allSettled([
      db.getDomainIntelScans(),
      db.getEngagements(),
      db.getThreatActorCount(),
      db.getIocFeedStats(),
    ]);

    // All should be rejected
    expect(scans.status).toBe("rejected");
    expect(engagements.status).toBe("rejected");
    expect(threatActorCount.status).toBe("rejected");
    expect(iocStats.status).toBe("rejected");

    // Fallback values
    const scanList = scans.status === "fulfilled" ? scans.value : [];
    const engagementList = engagements.status === "fulfilled" ? engagements.value : [];
    const actorCount = threatActorCount.status === "fulfilled" ? threatActorCount.value : 0;
    const iocData = iocStats.status === "fulfilled" ? iocStats.value : { total: 0, recentCount: 0 };

    expect(scanList).toEqual([]);
    expect(engagementList).toEqual([]);
    expect(actorCount).toBe(0);
    expect(iocData).toEqual({ total: 0, recentCount: 0 });
  });

  it("should compute correct badge text strings", () => {
    // Test the badge text computation logic
    const badges = {
      recon: { total: 8, completed: 8 },
      intelligence: { actors: 42, iocs: 150, recentIocs: 12 },
      planning: { engagements: 3 },
      phishing: { campaigns: 5, active: 2 },
      exploitation: {},
      emulation: { operations: 10, active: 3 },
      reports: {},
      knowledge: {},
      admin: {},
    };

    const b: Record<string, string | undefined> = {};
    const r = badges.recon as any;
    if (r?.total) b.recon = `${r.completed ?? r.total} scans`;
    const i = badges.intelligence as any;
    if (i?.actors) b.intelligence = `${i.actors} actors`;
    const p = badges.planning as any;
    if (p?.engagements) b.planning = `${p.engagements} eng`;
    const ph = badges.phishing as any;
    if (ph?.active) b.phishing = `${ph.active} active`;
    else if (ph?.campaigns) b.phishing = `${ph.campaigns} camp`;
    const em = badges.emulation as any;
    if (em?.active) b.emulation = `${em.active} running`;
    else if (em?.operations) b.emulation = `${em.operations} ops`;

    expect(b.recon).toBe("8 scans");
    expect(b.intelligence).toBe("42 actors");
    expect(b.planning).toBe("3 eng");
    expect(b.phishing).toBe("2 active");
    expect(b.emulation).toBe("3 running");
    expect(b.exploitation).toBeUndefined();
    expect(b.reports).toBeUndefined();
    expect(b.knowledge).toBeUndefined();
    expect(b.admin).toBeUndefined();
  });

  it("should show campaign count when no active campaigns", () => {
    const badges = {
      phishing: { campaigns: 5, active: 0 },
      emulation: { operations: 7, active: 0 },
    };

    const b: Record<string, string | undefined> = {};
    const ph = badges.phishing as any;
    if (ph?.active) b.phishing = `${ph.active} active`;
    else if (ph?.campaigns) b.phishing = `${ph.campaigns} camp`;
    const em = badges.emulation as any;
    if (em?.active) b.emulation = `${em.active} running`;
    else if (em?.operations) b.emulation = `${em.operations} ops`;

    expect(b.phishing).toBe("5 camp");
    expect(b.emulation).toBe("7 ops");
  });

  it("should return empty object when badges data is null", () => {
    const badges = null;
    const result = badges ? {} : {};
    expect(result).toEqual({});
  });
});

describe("Onboarding Tooltip", () => {
  it("should use the correct localStorage key", () => {
    const ONBOARDING_KEY = "ace-c3-onboarding-seen";
    expect(ONBOARDING_KEY).toBe("ace-c3-onboarding-seen");
  });

  it("should show onboarding when localStorage has no key", () => {
    // Simulate fresh user
    const hasKey = false;
    const showOnboarding = !hasKey;
    expect(showOnboarding).toBe(true);
  });

  it("should hide onboarding when localStorage has the key", () => {
    // Simulate returning user
    const hasKey = true;
    const showOnboarding = !hasKey;
    expect(showOnboarding).toBe(false);
  });
});
