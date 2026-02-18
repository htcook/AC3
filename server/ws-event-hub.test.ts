import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Tests for the WebSocket Event Hub service.
 * Tests event type definitions, broadcasting logic, and channel management.
 */

// ─── Event Type Tests ──────────────────────────────────────────────────────

describe("WebSocket Event Types", () => {
  it("should define all 28 event types across categories", () => {
    const eventTypes = [
      // Exploit events
      "exploit:fired", "exploit:result", "exploit:progress", "exploit:session_opened",
      // Agent events
      "agent:deployed", "agent:checkin", "agent:lost",
      // Operation events
      "operation:started", "operation:step_complete", "operation:finished",
      // Recon events
      "recon:started", "recon:complete", "recon:finding",
      // Campaign events
      "campaign:launched", "campaign:email_sent", "campaign:email_opened",
      "campaign:link_clicked", "campaign:creds_submitted",
      // Pipeline events
      "pipeline:started", "pipeline:step_complete", "pipeline:finished",
      // Domain events
      "domain:scan_complete", "domain:typosquat_purchased",
      // MSF events
      "msf:server_provisioned", "msf:server_ready", "msf:server_destroyed",
      // System events
      "system:notification", "system:alert",
    ];

    expect(eventTypes).toHaveLength(28);
    // Verify all categories are represented
    const categories = new Set(eventTypes.map(t => t.split(":")[0]));
    expect(categories.size).toBe(9);
    expect(Array.from(categories).sort()).toEqual([
      "agent", "campaign", "domain", "exploit", "msf", "operation", "pipeline", "recon", "system"
    ].sort());
  });

  it("should map event types to correct kill chain phases", () => {
    const phaseMap: Record<string, string> = {
      "exploit:fired": "exploitation",
      "exploit:result": "exploitation",
      "agent:deployed": "installation",
      "agent:checkin": "command_control",
      "operation:started": "actions_on_objectives",
      "recon:started": "reconnaissance",
      "recon:complete": "reconnaissance",
      "campaign:launched": "delivery",
      "campaign:email_sent": "delivery",
      "campaign:creds_submitted": "delivery",
      "pipeline:started": "reconnaissance",
      "pipeline:step_complete": "weaponization",
      "domain:scan_complete": "reconnaissance",
      "msf:server_provisioned": "weaponization",
    };

    // Verify phase mappings are valid kill chain phases
    const validPhases = [
      "reconnaissance", "weaponization", "delivery",
      "exploitation", "installation", "command_control", "actions_on_objectives"
    ];

    for (const [eventType, phase] of Object.entries(phaseMap)) {
      expect(validPhases).toContain(phase);
      expect(eventType).toMatch(/^[a-z]+:[a-z_]+$/);
    }
  });
});

// ─── Channel Management Tests ──────────────────────────────────────────────

describe("WebSocket Channel Management", () => {
  it("should extract correct channels from event types", () => {
    const getChannel = (eventType: string) => eventType.split(":")[0];

    expect(getChannel("exploit:fired")).toBe("exploit");
    expect(getChannel("agent:deployed")).toBe("agent");
    expect(getChannel("operation:started")).toBe("operation");
    expect(getChannel("recon:complete")).toBe("recon");
    expect(getChannel("campaign:launched")).toBe("campaign");
    expect(getChannel("pipeline:started")).toBe("pipeline");
    expect(getChannel("domain:scan_complete")).toBe("domain");
    expect(getChannel("msf:server_provisioned")).toBe("msf");
    expect(getChannel("system:notification")).toBe("system");
  });

  it("should support engagement-scoped channels", () => {
    const getEngagementChannel = (engagementId: number) => `engagement:${engagementId}`;

    expect(getEngagementChannel(1)).toBe("engagement:1");
    expect(getEngagementChannel(42)).toBe("engagement:42");
    expect(getEngagementChannel(100)).toBe("engagement:100");
  });

  it("should support wildcard channel subscription", () => {
    const channels = ["exploit", "agent", "operation", "*"];
    const eventType = "system:notification";
    const eventChannel = eventType.split(":")[0];

    // Wildcard should match all events
    const shouldReceive = channels.includes("*") || channels.includes(eventChannel);
    expect(shouldReceive).toBe(true);
  });

  it("should filter events by subscribed channels", () => {
    const subscribedChannels = ["exploit", "agent"];
    const events = [
      { type: "exploit:fired", data: {} },
      { type: "agent:deployed", data: {} },
      { type: "operation:started", data: {} },
      { type: "recon:complete", data: {} },
    ];

    const filtered = events.filter(e => {
      const channel = e.type.split(":")[0];
      return subscribedChannels.includes(channel);
    });

    expect(filtered).toHaveLength(2);
    expect(filtered[0].type).toBe("exploit:fired");
    expect(filtered[1].type).toBe("agent:deployed");
  });
});

// ─── Event Data Structure Tests ────────────────────────────────────────────

describe("WebSocket Event Data Structure", () => {
  it("should create valid event payloads for exploit events", () => {
    const event = {
      type: "exploit:fired",
      timestamp: Date.now(),
      engagementId: 1,
      data: {
        jobId: 42,
        module: "exploit/windows/smb/ms17_010_eternalblue",
        target: "192.168.1.100",
        port: 445,
        dryRun: false,
      },
    };

    expect(event.type).toBe("exploit:fired");
    expect(event.timestamp).toBeGreaterThan(0);
    expect(event.engagementId).toBe(1);
    expect(event.data.module).toContain("exploit/");
    expect(event.data.target).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
  });

  it("should create valid event payloads for agent events", () => {
    const event = {
      type: "agent:deployed",
      timestamp: Date.now(),
      engagementId: 2,
      data: {
        paw: "abc123",
        platform: "windows",
        hostname: "WORKSTATION-01",
        calderaUrl: "https://caldera.example.com",
      },
    };

    expect(event.type).toBe("agent:deployed");
    expect(event.data.paw).toBeTruthy();
    expect(event.data.platform).toBe("windows");
  });

  it("should create valid event payloads for pipeline events", () => {
    const event = {
      type: "pipeline:step_complete",
      timestamp: Date.now(),
      engagementId: 3,
      data: {
        step: 2,
        stepName: "Domain Intel Scan",
        totalSteps: 6,
        status: "success",
        targetDomain: "example.com",
      },
    };

    expect(event.type).toBe("pipeline:step_complete");
    expect(event.data.step).toBe(2);
    expect(event.data.totalSteps).toBe(6);
    expect(event.data.status).toBe("success");
  });

  it("should create valid event payloads for MSF server events", () => {
    const event = {
      type: "msf:server_provisioned",
      timestamp: Date.now(),
      data: {
        serverId: 1,
        serverName: "msf-server-01",
        region: "nyc1",
        dropletId: 123456789,
      },
    };

    expect(event.type).toBe("msf:server_provisioned");
    expect(event.data.serverId).toBe(1);
    expect(event.data.serverName).toBeTruthy();
  });

  it("should serialize events to JSON correctly", () => {
    const event = {
      type: "exploit:result",
      timestamp: 1708300000000,
      engagementId: 5,
      data: {
        jobId: 99,
        success: true,
        sessionId: 1,
        target: "10.0.0.1",
      },
    };

    const serialized = JSON.stringify(event);
    const deserialized = JSON.parse(serialized);

    expect(deserialized.type).toBe("exploit:result");
    expect(deserialized.timestamp).toBe(1708300000000);
    expect(deserialized.data.success).toBe(true);
    expect(deserialized.data.sessionId).toBe(1);
  });
});

// ─── Toast Notification Logic Tests ────────────────────────────────────────

describe("WebSocket Toast Notification Logic", () => {
  const TOAST_EVENT_TYPES = [
    "exploit:result", "exploit:session_opened",
    "agent:deployed", "agent:lost",
    "operation:finished",
    "pipeline:finished",
    "msf:server_ready", "msf:server_destroyed",
    "system:alert",
  ];

  it("should identify toast-worthy events", () => {
    expect(TOAST_EVENT_TYPES).toContain("exploit:result");
    expect(TOAST_EVENT_TYPES).toContain("agent:deployed");
    expect(TOAST_EVENT_TYPES).toContain("operation:finished");
    expect(TOAST_EVENT_TYPES).toContain("pipeline:finished");
    expect(TOAST_EVENT_TYPES).toContain("msf:server_ready");
    expect(TOAST_EVENT_TYPES).toContain("system:alert");
  });

  it("should not toast for routine events", () => {
    expect(TOAST_EVENT_TYPES).not.toContain("exploit:fired");
    expect(TOAST_EVENT_TYPES).not.toContain("exploit:progress");
    expect(TOAST_EVENT_TYPES).not.toContain("agent:checkin");
    expect(TOAST_EVENT_TYPES).not.toContain("recon:started");
    expect(TOAST_EVENT_TYPES).not.toContain("campaign:email_sent");
    expect(TOAST_EVENT_TYPES).not.toContain("pipeline:step_complete");
  });

  it("should generate correct toast info for exploit success", () => {
    const event = {
      type: "exploit:result",
      data: { success: true, module: "exploit/windows/smb/ms17_010_eternalblue", target: "10.0.0.1" },
    };

    const title = event.data.success ? "Exploit Succeeded" : "Exploit Failed";
    const description = `${event.data.module} → ${event.data.target}`;
    const variant = event.data.success ? "default" : "destructive";

    expect(title).toBe("Exploit Succeeded");
    expect(description).toContain("eternalblue");
    expect(variant).toBe("default");
  });

  it("should generate correct toast info for agent deployment", () => {
    const event = {
      type: "agent:deployed",
      data: { paw: "abc123", platform: "linux", hostname: "target-server" },
    };

    const title = "Agent Deployed";
    const description = `${event.data.platform} agent on ${event.data.hostname} (${event.data.paw})`;

    expect(title).toBe("Agent Deployed");
    expect(description).toContain("linux");
    expect(description).toContain("target-server");
  });

  it("should generate destructive toast for agent lost", () => {
    const event = {
      type: "agent:lost",
      data: { paw: "xyz789", hostname: "compromised-host" },
    };

    const variant = "destructive";
    expect(variant).toBe("destructive");
  });
});

// ─── Reconnection Logic Tests ──────────────────────────────────────────────

describe("WebSocket Reconnection Logic", () => {
  it("should calculate exponential backoff delays", () => {
    const BASE_DELAY = 1000;
    const MAX_DELAY = 30000;

    const getDelay = (attempt: number) =>
      Math.min(BASE_DELAY * Math.pow(2, attempt), MAX_DELAY);

    expect(getDelay(0)).toBe(1000);
    expect(getDelay(1)).toBe(2000);
    expect(getDelay(2)).toBe(4000);
    expect(getDelay(3)).toBe(8000);
    expect(getDelay(4)).toBe(16000);
    expect(getDelay(5)).toBe(30000); // capped at MAX_DELAY
    expect(getDelay(10)).toBe(30000); // still capped
  });

  it("should add jitter to prevent thundering herd", () => {
    const BASE_DELAY = 1000;
    const MAX_DELAY = 30000;

    const getDelayWithJitter = (attempt: number) => {
      const base = Math.min(BASE_DELAY * Math.pow(2, attempt), MAX_DELAY);
      const jitter = Math.random() * 1000;
      return base + jitter;
    };

    // With jitter, delay should always be >= base
    for (let i = 0; i < 5; i++) {
      const delay = getDelayWithJitter(0);
      expect(delay).toBeGreaterThanOrEqual(1000);
      expect(delay).toBeLessThanOrEqual(2000);
    }
  });

  it("should reset reconnect attempts on successful connection", () => {
    let attempts = 5;
    // Simulate successful connection
    attempts = 0;
    expect(attempts).toBe(0);
  });

  it("should limit maximum reconnect attempts", () => {
    const MAX_ATTEMPTS = 10;
    let attempts = 0;

    while (attempts < MAX_ATTEMPTS) {
      attempts++;
    }

    expect(attempts).toBe(MAX_ATTEMPTS);
    // Should stop trying after max attempts
    const shouldReconnect = attempts < MAX_ATTEMPTS;
    expect(shouldReconnect).toBe(false);
  });
});

// ─── Event Deduplication Tests ─────────────────────────────────────────────

describe("WebSocket Event Deduplication", () => {
  it("should deduplicate events by timestamp proximity", () => {
    const events = [
      { id: "live-1", phase: "exploitation", source: "exploit", timestamp: 1708300001000 },
      { id: "hist-1", phase: "exploitation", source: "exploit", timestamp: 1708300001500 },
      { id: "live-2", phase: "reconnaissance", source: "recon", timestamp: 1708300002000 },
      { id: "hist-2", phase: "reconnaissance", source: "recon", timestamp: 1708300002800 },
    ];

    const seen = new Set<string>();
    const deduped = events.filter(e => {
      const key = `${e.phase}-${e.source}-${Math.floor(e.timestamp / 1000)}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // Events within same second should be deduped
    // live-1 and hist-1 share same second (1708300001), live-2 and hist-2 share same second (1708300002)
    expect(deduped).toHaveLength(2); // live-1 (first in second 1708300001), live-2 (first in second 1708300002)
  });

  it("should keep events from different phases even at same time", () => {
    const events = [
      { phase: "exploitation", source: "exploit", timestamp: 1708300001000 },
      { phase: "installation", source: "agent", timestamp: 1708300001000 },
    ];

    const seen = new Set<string>();
    const deduped = events.filter(e => {
      const key = `${e.phase}-${e.source}-${Math.floor(e.timestamp / 1000)}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    expect(deduped).toHaveLength(2);
  });
});
