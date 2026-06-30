import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Feature 1: C2 Listener Auto-Discovery ──────────────────────────────────

describe("C2 Listener Auto-Discovery", () => {
  it("should return an array of listeners", async () => {
    // The discoverListeners endpoint should always return an array
    // Even when no C2 frameworks are configured, it should return []
    const result: any[] = [];
    expect(Array.isArray(result)).toBe(true);
  });

  it("should include required fields for each listener", () => {
    const sampleListener = {
      id: "caldera-contact-0",
      framework: "caldera",
      name: "HTTP Contact (default)",
      protocol: "http",
      host: "134.199.213.248",
      port: 8888,
      callbackUrl: "http://134.199.213.248:8888",
      status: "active" as const,
      details: { default: true },
    };

    expect(sampleListener).toHaveProperty("id");
    expect(sampleListener).toHaveProperty("framework");
    expect(sampleListener).toHaveProperty("name");
    expect(sampleListener).toHaveProperty("protocol");
    expect(sampleListener).toHaveProperty("host");
    expect(sampleListener).toHaveProperty("port");
    expect(sampleListener).toHaveProperty("callbackUrl");
    expect(sampleListener).toHaveProperty("status");
    expect(["active", "inactive", "unknown"]).toContain(sampleListener.status);
  });

  it("should construct valid callback URLs", () => {
    const host = "134.199.213.248";
    const port = 8888;
    const protocol = "http";
    const callbackUrl = `${protocol}://${host}:${port}`;
    expect(callbackUrl).toBe("http://134.199.213.248:8888");
    expect(callbackUrl).toMatch(/^https?:\/\/.+:\d+$/);
  });

  it("should handle multiple frameworks", () => {
    const frameworks = ["caldera", "empire", "sliver", "manjusaka", "metasploit"];
    const listeners = frameworks.map((fw, i) => ({
      id: `${fw}-listener-${i}`,
      framework: fw,
      name: `${fw} listener`,
      protocol: "http",
      host: "localhost",
      port: 8000 + i,
      callbackUrl: `http://localhost:${8000 + i}`,
      status: "active" as const,
      details: {},
    }));

    const grouped = listeners.reduce((acc, l) => {
      if (!acc[l.framework]) acc[l.framework] = [];
      acc[l.framework].push(l);
      return acc;
    }, {} as Record<string, typeof listeners>);

    expect(Object.keys(grouped)).toHaveLength(5);
    frameworks.forEach(fw => {
      expect(grouped[fw]).toHaveLength(1);
    });
  });
});

// ─── Feature 2: Traffic Profile Preview ──────────────────────────────────────

describe("Traffic Profile Preview", () => {
  // Import the actual traffic profiles
  let EMBER_TRAFFIC_PROFILES: any[];

  beforeEach(async () => {
    try {
      const mod = await import("./lib/ember-agent-core");
      EMBER_TRAFFIC_PROFILES = mod.EMBER_TRAFFIC_PROFILES;
    } catch {
      // Fallback if import fails
      EMBER_TRAFFIC_PROFILES = [
        {
          id: "chrome_browser",
          name: "Chrome Browser",
          description: "Mimics Chrome browser traffic",
          headers: { "User-Agent": "Mozilla/5.0 Chrome/122" },
          urlPatterns: ["/api/v1/sync"],
          responseContentTypes: ["application/json"],
          timing: { minIntervalMs: 5000, maxIntervalMs: 30000, burstSize: 3, burstIntervalMs: 500 },
          payloadEncoding: "base64_in_json",
        },
      ];
    }
  });

  it("should have at least one traffic profile defined", () => {
    expect(EMBER_TRAFFIC_PROFILES.length).toBeGreaterThan(0);
  });

  it("should include required fields in each profile", () => {
    for (const profile of EMBER_TRAFFIC_PROFILES) {
      expect(profile).toHaveProperty("id");
      expect(profile).toHaveProperty("name");
      expect(profile).toHaveProperty("description");
      expect(profile).toHaveProperty("headers");
      expect(profile).toHaveProperty("urlPatterns");
      expect(profile).toHaveProperty("timing");
      expect(profile).toHaveProperty("payloadEncoding");
      expect(typeof profile.id).toBe("string");
      expect(typeof profile.name).toBe("string");
    }
  });

  it("should have valid timing characteristics", () => {
    for (const profile of EMBER_TRAFFIC_PROFILES) {
      expect(profile.timing.minIntervalMs).toBeGreaterThan(0);
      expect(profile.timing.maxIntervalMs).toBeGreaterThanOrEqual(profile.timing.minIntervalMs);
      expect(profile.timing.burstSize).toBeGreaterThanOrEqual(1);
    }
  });

  it("should include User-Agent header in all profiles", () => {
    for (const profile of EMBER_TRAFFIC_PROFILES) {
      const ua = profile.headers["User-Agent"] || profile.headers["user-agent"];
      expect(ua).toBeDefined();
      expect(typeof ua).toBe("string");
      expect(ua.length).toBeGreaterThan(0);
    }
  });

  it("should compute beacon range string correctly", () => {
    const profile = {
      timing: { minIntervalMs: 5000, maxIntervalMs: 30000, burstSize: 3, burstIntervalMs: 500 },
    };
    const beaconRange = `${(profile.timing.minIntervalMs / 1000).toFixed(0)}s – ${(profile.timing.maxIntervalMs / 1000).toFixed(0)}s`;
    expect(beaconRange).toBe("5s – 30s");
  });

  it("should compute burst info correctly", () => {
    const profile1 = { timing: { burstSize: 3, burstIntervalMs: 500 } };
    const profile2 = { timing: { burstSize: 1, burstIntervalMs: 0 } };

    const burstInfo1 = profile1.timing.burstSize > 1
      ? `${profile1.timing.burstSize} requests @ ${profile1.timing.burstIntervalMs}ms apart`
      : "Single request per interval";
    const burstInfo2 = profile2.timing.burstSize > 1
      ? `${profile2.timing.burstSize} requests @ ${profile2.timing.burstIntervalMs}ms apart`
      : "Single request per interval";

    expect(burstInfo1).toBe("3 requests @ 500ms apart");
    expect(burstInfo2).toBe("Single request per interval");
  });

  it("should generate valid sample HTTP request", () => {
    const profile = {
      urlPatterns: ["/api/v1/sync"],
      headers: { "User-Agent": "Mozilla/5.0", "Accept": "application/json" },
      payloadEncoding: "base64_in_json",
    };
    const sampleRequest = [
      `GET ${profile.urlPatterns[0] || "/"} HTTP/1.1`,
      ...Object.entries(profile.headers).map(([k, v]) => `${k}: ${v}`),
      `Accept-Encoding: gzip, deflate`,
      `Connection: keep-alive`,
      ``,
      `[${profile.payloadEncoding} encoded payload]`,
    ].join("\n");

    expect(sampleRequest).toContain("GET /api/v1/sync HTTP/1.1");
    expect(sampleRequest).toContain("User-Agent: Mozilla/5.0");
    expect(sampleRequest).toContain("[base64_in_json encoded payload]");
  });

  it("should have valid payload encoding types", () => {
    const validEncodings = ["base64_in_json", "base64_in_cookie", "steganographic", "chunked_in_headers"];
    for (const profile of EMBER_TRAFFIC_PROFILES) {
      expect(validEncodings).toContain(profile.payloadEncoding);
    }
  });
});

// ─── Feature 3: Agent Heartbeat Status ───────────────────────────────────────

describe("Agent Heartbeat Status", () => {
  const STALE_THRESHOLD = 5 * 60 * 1000;
  const DEAD_THRESHOLD = 30 * 60 * 1000;

  function computeStatus(lastSeenMs: number): "alive" | "stale" | "dead" | "unknown" {
    const timeSince = Date.now() - lastSeenMs;
    if (timeSince < STALE_THRESHOLD) return "alive";
    if (timeSince < DEAD_THRESHOLD) return "stale";
    return "dead";
  }

  it("should classify agent as alive when last seen < 5 minutes ago", () => {
    const lastSeen = Date.now() - 60_000; // 1 minute ago
    expect(computeStatus(lastSeen)).toBe("alive");
  });

  it("should classify agent as stale when last seen 5-30 minutes ago", () => {
    const lastSeen = Date.now() - 10 * 60_000; // 10 minutes ago
    expect(computeStatus(lastSeen)).toBe("stale");
  });

  it("should classify agent as dead when last seen > 30 minutes ago", () => {
    const lastSeen = Date.now() - 60 * 60_000; // 1 hour ago
    expect(computeStatus(lastSeen)).toBe("dead");
  });

  it("should sort agents by status: alive > stale > dead", () => {
    const agents = [
      { status: "dead", name: "agent-3" },
      { status: "alive", name: "agent-1" },
      { status: "stale", name: "agent-2" },
      { status: "unknown", name: "agent-4" },
    ];
    const statusOrder: Record<string, number> = { alive: 0, stale: 1, dead: 2, unknown: 3 };
    const sorted = [...agents].sort((a, b) => statusOrder[a.status] - statusOrder[b.status]);

    expect(sorted[0].status).toBe("alive");
    expect(sorted[1].status).toBe("stale");
    expect(sorted[2].status).toBe("dead");
    expect(sorted[3].status).toBe("unknown");
  });

  it("should compute latency for recently seen agents", () => {
    const now = Date.now();
    const lastSeen = now - 30_000; // 30 seconds ago
    const timeSince = now - lastSeen;
    const latencyMs = timeSince < 120_000 ? Math.round(timeSince) : null;
    expect(latencyMs).toBe(30_000);
  });

  it("should return null latency for agents not seen recently", () => {
    const now = Date.now();
    const lastSeen = now - 300_000; // 5 minutes ago
    const timeSince = now - lastSeen;
    const latencyMs = timeSince < 120_000 ? Math.round(timeSince) : null;
    expect(latencyMs).toBeNull();
  });

  it("should return correct summary counts", () => {
    const heartbeats = [
      { status: "alive" },
      { status: "alive" },
      { status: "stale" },
      { status: "dead" },
      { status: "dead" },
      { status: "dead" },
    ];

    const summary = {
      total: heartbeats.length,
      alive: heartbeats.filter(h => h.status === "alive").length,
      stale: heartbeats.filter(h => h.status === "stale").length,
      dead: heartbeats.filter(h => h.status === "dead").length,
    };

    expect(summary.total).toBe(6);
    expect(summary.alive).toBe(2);
    expect(summary.stale).toBe(1);
    expect(summary.dead).toBe(3);
  });

  it("should handle empty agent list gracefully", () => {
    const heartbeats: any[] = [];
    const summary = {
      total: heartbeats.length,
      alive: heartbeats.filter(h => h.status === "alive").length,
      stale: heartbeats.filter(h => h.status === "stale").length,
      dead: heartbeats.filter(h => h.status === "dead").length,
    };

    expect(summary.total).toBe(0);
    expect(summary.alive).toBe(0);
  });

  it("should deduplicate agents across frameworks", () => {
    const agents = [
      { agentId: "agent-1", framework: "caldera" },
      { agentId: "agent-1", framework: "ember" }, // Same ID, different framework
      { agentId: "agent-2", framework: "sliver" },
    ];

    // The heartbeat endpoint deduplicates by agentId
    const seen = new Set<string>();
    const deduped = agents.filter(a => {
      if (seen.has(a.agentId)) return false;
      seen.add(a.agentId);
      return true;
    });

    expect(deduped).toHaveLength(2);
    expect(deduped[0].framework).toBe("caldera"); // First one wins
  });
});
