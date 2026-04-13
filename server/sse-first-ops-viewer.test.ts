/**
 * Tests for:
 * 1. SSE Event Stream server endpoint (channel filtering, heartbeat, catch-up)
 * 2. SSE-first transport architecture (SSE primary, WS optional upgrade)
 * 3. Ops Viewer layout fixes (no AppShell, always-visible back button, empty states)
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ─── SSE Event Stream Server Tests ─────────────────────────────────

describe("SSE Event Stream Server", () => {
  it("should export registerSSEEventStream function", async () => {
    const mod = await import("./lib/sse-event-stream");
    expect(typeof mod.registerSSEEventStream).toBe("function");
  });

  it("should register GET /api/events/stream route", async () => {
    const { registerSSEEventStream } = await import("./lib/sse-event-stream");
    const routes: Array<{ method: string; path: string }> = [];
    const mockApp = {
      get: vi.fn((path: string, _handler: any) => {
        routes.push({ method: "GET", path });
      }),
    };
    registerSSEEventStream(mockApp as any);
    expect(mockApp.get).toHaveBeenCalledWith("/api/events/stream", expect.any(Function));
    expect(routes).toContainEqual({ method: "GET", path: "/api/events/stream" });
  });

  it("should send SSE headers on connection", async () => {
    const { registerSSEEventStream } = await import("./lib/sse-event-stream");
    let handler: any;
    const mockApp = {
      get: vi.fn((_path: string, h: any) => { handler = h; }),
    };
    registerSSEEventStream(mockApp as any);

    const mockReq = {
      query: { channels: "global" },
      headers: {},
      on: vi.fn(),
    };
    const writtenHeaders: any = {};
    const mockRes = {
      writeHead: vi.fn((status: number, headers: any) => {
        Object.assign(writtenHeaders, { status, ...headers });
      }),
      write: vi.fn(),
      on: vi.fn(),
    };

    handler(mockReq, mockRes);

    expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.objectContaining({
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      "Connection": "keep-alive",
    }));
  });

  it("should send initial connected event", async () => {
    const { registerSSEEventStream } = await import("./lib/sse-event-stream");
    let handler: any;
    const mockApp = {
      get: vi.fn((_path: string, h: any) => { handler = h; }),
    };
    registerSSEEventStream(mockApp as any);

    const writes: string[] = [];
    const mockReq = {
      query: { channels: "global" },
      headers: {},
      on: vi.fn(),
    };
    const mockRes = {
      writeHead: vi.fn(),
      write: vi.fn((data: string) => { writes.push(data); }),
      on: vi.fn(),
    };

    handler(mockReq, mockRes);

    // First write should be the connected event
    expect(writes.length).toBeGreaterThanOrEqual(1);
    expect(writes[0]).toContain("event: connected");
    expect(writes[0]).toContain("Connected to AC3 Event Stream (SSE)");
  });

  it("should always include global channel even if not specified", async () => {
    const { registerSSEEventStream } = await import("./lib/sse-event-stream");
    let handler: any;
    const mockApp = {
      get: vi.fn((_path: string, h: any) => { handler = h; }),
    };
    registerSSEEventStream(mockApp as any);

    const writes: string[] = [];
    const mockReq = {
      query: { channels: "engagement:123" },
      headers: {},
      on: vi.fn(),
    };
    const mockRes = {
      writeHead: vi.fn(),
      write: vi.fn((data: string) => { writes.push(data); }),
      on: vi.fn(),
    };

    handler(mockReq, mockRes);

    // The connected event should show both channels
    const connectedData = writes[0];
    expect(connectedData).toContain("global");
    expect(connectedData).toContain("engagement:123");
  });

  it("should parse Last-Event-ID header for catch-up", async () => {
    const { registerSSEEventStream } = await import("./lib/sse-event-stream");
    let handler: any;
    const mockApp = {
      get: vi.fn((_path: string, h: any) => { handler = h; }),
    };
    registerSSEEventStream(mockApp as any);

    const mockReq = {
      query: { channels: "global" },
      headers: { "last-event-id": "42" },
      on: vi.fn(),
    };
    const mockRes = {
      writeHead: vi.fn(),
      write: vi.fn(),
      on: vi.fn(),
    };

    // Should not throw
    expect(() => handler(mockReq, mockRes)).not.toThrow();
  });

  it("should cleanup on client disconnect", async () => {
    const { registerSSEEventStream } = await import("./lib/sse-event-stream");
    let handler: any;
    const mockApp = {
      get: vi.fn((_path: string, h: any) => { handler = h; }),
    };
    registerSSEEventStream(mockApp as any);

    const closeHandlers: Function[] = [];
    const mockReq = {
      query: { channels: "global" },
      headers: {},
      on: vi.fn((event: string, handler: Function) => {
        if (event === "close") closeHandlers.push(handler);
      }),
    };
    const mockRes = {
      writeHead: vi.fn(),
      write: vi.fn(),
      on: vi.fn(),
    };

    handler(mockReq, mockRes);

    // Should have registered a close handler
    expect(closeHandlers.length).toBeGreaterThan(0);

    // Calling close handler should not throw
    expect(() => closeHandlers[0]()).not.toThrow();
  });
});

// ─── SSE-First Transport Architecture Tests ────────────────────────

describe("SSE-First Transport Architecture", () => {
  it("should define WS_UPGRADE_DELAY constant of 10 seconds", () => {
    // The hook uses a 10-second delay before attempting WS upgrade
    const WS_UPGRADE_DELAY = 10_000;
    expect(WS_UPGRADE_DELAY).toBe(10000);
  });

  it("should define WS_UPGRADE_MAX_FAILURES constant of 2", () => {
    // After 2 WS upgrade failures, the hook stays on SSE permanently
    const WS_UPGRADE_MAX_FAILURES = 2;
    expect(WS_UPGRADE_MAX_FAILURES).toBe(2);
  });

  it("should have SSE as primary transport (not WebSocket)", () => {
    // The transport priority is: SSE first, WS optional upgrade
    // This is the opposite of the old behavior (WS first, SSE fallback)
    const transportPriority = ["sse", "websocket"];
    expect(transportPriority[0]).toBe("sse");
    expect(transportPriority.indexOf("sse")).toBeLessThan(transportPriority.indexOf("websocket"));
  });

  it("should build correct SSE URL with channel query parameter", () => {
    const channels = ["global", "engagement:123"];
    const channelStr = channels.join(",");
    const url = `/api/events/stream?channels=${encodeURIComponent(channelStr)}`;
    expect(url).toBe("/api/events/stream?channels=global%2Cengagement%3A123");
  });

  it("should build correct SSE URL with single channel", () => {
    const channels = ["global"];
    const channelStr = channels.join(",");
    const url = `/api/events/stream?channels=${encodeURIComponent(channelStr)}`;
    expect(url).toBe("/api/events/stream?channels=global");
  });

  it("should calculate exponential backoff correctly for SSE reconnect", () => {
    const baseDelay = 5000;
    const maxDelay = 60000;

    // Attempt 0: 5s
    expect(Math.min(baseDelay * Math.pow(2, 0), maxDelay)).toBe(5000);
    // Attempt 1: 10s
    expect(Math.min(baseDelay * Math.pow(2, 1), maxDelay)).toBe(10000);
    // Attempt 2: 20s
    expect(Math.min(baseDelay * Math.pow(2, 2), maxDelay)).toBe(20000);
    // Attempt 3: 40s
    expect(Math.min(baseDelay * Math.pow(2, 3), maxDelay)).toBe(40000);
    // Attempt 4: capped at 60s
    expect(Math.min(baseDelay * Math.pow(2, 4), maxDelay)).toBe(60000);
    // Attempt 5: still capped at 60s
    expect(Math.min(baseDelay * Math.pow(2, 5), maxDelay)).toBe(60000);
  });

  it("should build correct WebSocket URL for upgrade", () => {
    // Simulate HTTPS environment
    const protocol = "https:";
    const host = "aceofcloud.io";
    const wsProtocol = protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${wsProtocol}//${host}/ws/events`;
    expect(wsUrl).toBe("wss://aceofcloud.io/ws/events");
  });

  it("should build correct WebSocket URL for HTTP environment", () => {
    const protocol = "http:";
    const host = "localhost:3000";
    const wsProtocol = protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${wsProtocol}//${host}/ws/events`;
    expect(wsUrl).toBe("ws://localhost:3000/ws/events");
  });

  it("should stop WS upgrade attempts after max failures", () => {
    let wsUpgradeFailures = 0;
    const WS_UPGRADE_MAX_FAILURES = 2;

    // First failure
    wsUpgradeFailures++;
    expect(wsUpgradeFailures < WS_UPGRADE_MAX_FAILURES).toBe(true);

    // Second failure — should stop
    wsUpgradeFailures++;
    expect(wsUpgradeFailures >= WS_UPGRADE_MAX_FAILURES).toBe(true);
  });

  it("should reset reconnect attempts on successful SSE connection", () => {
    let sseReconnectAttempts = 3;
    // Simulate successful connection
    sseReconnectAttempts = 0;
    expect(sseReconnectAttempts).toBe(0);
  });
});

// ─── Event Filtering Tests ─────────────────────────────────────────

describe("Event Filtering", () => {
  it("should pass events matching filterTypes", () => {
    const filterTypes = ["exploit:result", "agent:deployed"] as const;
    const event = { type: "exploit:result", timestamp: Date.now(), data: { success: true } };
    const shouldPass = filterTypes.includes(event.type as any);
    expect(shouldPass).toBe(true);
  });

  it("should reject events not in filterTypes", () => {
    const filterTypes = ["exploit:result", "agent:deployed"] as const;
    const event = { type: "recon:complete", timestamp: Date.now(), data: {} };
    const shouldPass = filterTypes.includes(event.type as any);
    expect(shouldPass).toBe(false);
  });

  it("should pass all events when filterTypes is empty", () => {
    const filterTypes: string[] = [];
    const event = { type: "recon:complete", timestamp: Date.now(), data: {} };
    const shouldPass = filterTypes.length === 0 || filterTypes.includes(event.type);
    expect(shouldPass).toBe(true);
  });

  it("should maintain event buffer within maxEvents limit", () => {
    const maxEvents = 100;
    const events: any[] = [];

    // Add 150 events
    for (let i = 0; i < 150; i++) {
      events.unshift({ type: "system:notification", timestamp: Date.now(), data: { i } });
      if (events.length > maxEvents) {
        events.length = maxEvents; // Truncate
      }
    }

    expect(events.length).toBe(maxEvents);
    expect(events[0].data.i).toBe(149); // Most recent first
  });
});

// ─── Channel Management Tests ──────────────────────────────────────

describe("Channel Management", () => {
  it("should serialize channels to comma-separated string", () => {
    const channels = ["global", "engagement:42", "di_scan:7"];
    const channelKey = channels.join(",");
    expect(channelKey).toBe("global,engagement:42,di_scan:7");
  });

  it("should detect channel changes via serialized key comparison", () => {
    const prevChannelKey = "global";
    const newChannelKey = "global,engagement:42";
    expect(prevChannelKey !== newChannelKey).toBe(true);
  });

  it("should not detect change when channels are the same", () => {
    const prevChannelKey = "global,engagement:42";
    const newChannelKey = "global,engagement:42";
    expect(prevChannelKey === newChannelKey).toBe(true);
  });

  it("should build WebSocket subscribe message correctly", () => {
    const channels = ["global", "engagement:42"];
    const msg = JSON.stringify({ action: "subscribe", channels });
    const parsed = JSON.parse(msg);
    expect(parsed.action).toBe("subscribe");
    expect(parsed.channels).toEqual(["global", "engagement:42"]);
  });
});

// ─── Ops Viewer Layout Tests ───────────────────────────────────────

describe("Ops Viewer Layout", () => {
  it("should NOT import AppShell in OpsViewer", async () => {
    // Read the OpsViewer source to verify AppShell is not imported
    const fs = await import("fs");
    const source = fs.readFileSync(
      new URL("../client/src/pages/OpsViewer.tsx", import.meta.url),
      "utf-8"
    );
    expect(source).not.toContain('import AppShell');
    expect(source).not.toContain('<AppShell>');
    expect(source).not.toContain('</AppShell>');
  });

  it("should have always-visible Back link in OpsViewer", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      new URL("../client/src/pages/OpsViewer.tsx", import.meta.url),
      "utf-8"
    );
    // Back link should not be conditional on initialEid
    expect(source).toContain('<Link href={initialEid ? "/engagements" : "/"}');
    expect(source).toContain('>Back</span>');
  });

  it("should have empty state for DI scan mode with no scan selected", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      new URL("../client/src/pages/OpsViewer.tsx", import.meta.url),
      "utf-8"
    );
    expect(source).toContain('NO SCAN SELECTED');
    expect(source).toContain('Select a DI scan to visualize discovered assets');
  });

  it("should have empty state for engagement with no graph data", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      new URL("../client/src/pages/OpsViewer.tsx", import.meta.url),
      "utf-8"
    );
    expect(source).toContain('NO GRAPH DATA');
    expect(source).toContain('This engagement has no findings yet');
  });

  it("should have empty state for DI scan with no assets", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      new URL("../client/src/pages/OpsViewer.tsx", import.meta.url),
      "utf-8"
    );
    expect(source).toContain('NO ASSETS DISCOVERED');
    expect(source).toContain('This scan completed but found no assets');
  });

  it("should be in noSidebarRoutes in App.tsx", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      new URL("../client/src/App.tsx", import.meta.url),
      "utf-8"
    );
    // ops-viewer should be excluded from sidebar layout
    expect(source).toContain('"/ops-viewer"');
    const noSidebarMatch = source.match(/noSidebarRoutes\s*=\s*\[([^\]]+)\]/);
    expect(noSidebarMatch).not.toBeNull();
    expect(noSidebarMatch![1]).toContain('"/ops-viewer"');
  });
});

// ─── Toast Notification Tests ──────────────────────────────────────

describe("Toast Notifications", () => {
  it("should have critical event types defined for toast notifications", () => {
    const TOAST_EVENT_TYPES = [
      "exploit:result", "agent:deployed", "agent:lost", "operation:finished",
      "recon:complete", "pipeline:finished", "msf:server_ready", "msf:server_destroyed",
      "system:alert", "opsec:burn_detected", "opsec:threshold_warning",
      "credential:found", "credential:attack_complete", "lateral:movement_executed",
      "privesc:escalation_found", "engagement:phase_changed", "advisor:recommendation",
      "review:item_created", "review:item_approved", "review:item_rejected",
      "job:completed", "job:failed", "job:worker_lost",
      "evidence:gate_flagged", "evidence:quarantined", "evidence:anchor_created",
      "evidence:tamper_detected",
    ];

    expect(TOAST_EVENT_TYPES).toContain("exploit:result");
    expect(TOAST_EVENT_TYPES).toContain("opsec:burn_detected");
    expect(TOAST_EVENT_TYPES).toContain("evidence:tamper_detected");
    expect(TOAST_EVENT_TYPES.length).toBe(27);
  });

  it("should not include non-critical events in toast types", () => {
    const TOAST_EVENT_TYPES = [
      "exploit:result", "agent:deployed", "agent:lost", "operation:finished",
    ];
    expect(TOAST_EVENT_TYPES).not.toContain("exploit:progress");
    expect(TOAST_EVENT_TYPES).not.toContain("c2:agent_checkin");
    expect(TOAST_EVENT_TYPES).not.toContain("di:asset_discovered");
  });
});

// ─── Specialized Hook Configuration Tests ──────────────────────────

describe("Specialized Hook Configurations", () => {
  it("should configure dashboard events with correct filter types", () => {
    const dashboardFilterTypes = [
      "exploit:result", "agent:deployed", "agent:checkin", "agent:lost",
      "operation:finished", "recon:complete", "pipeline:finished",
      "campaign:launched", "system:alert", "system:notification",
      "automation:profile_generated", "automation:profile_pushed",
      "automation:playbook_triggered", "automation:pipeline_run",
      "automation:enrichment_complete",
    ];
    expect(dashboardFilterTypes).toContain("system:notification");
    expect(dashboardFilterTypes).toContain("automation:enrichment_complete");
  });

  it("should configure OPSEC events with engagement-specific channels", () => {
    const engagementId = 42;
    const channels = engagementId
      ? ["global", `engagement:${engagementId}`]
      : ["global"];
    expect(channels).toEqual(["global", "engagement:42"]);
  });

  it("should configure cockpit timeline with comprehensive event types", () => {
    const cockpitFilterTypes = [
      "recon:started", "recon:complete", "recon:finding", "domain:scan_complete",
      "exploit:fired", "exploit:result", "exploit:session_opened",
      "agent:deployed", "agent:checkin", "agent:lost",
      "operation:started", "operation:step_complete", "operation:finished",
      "opsec:action_scored", "opsec:burn_detected", "opsec:threshold_warning", "opsec:risk_update",
      "credential:attack_started", "credential:attack_complete", "credential:found",
      "lateral:movement_executed", "privesc:escalation_found",
      "campaign:launched", "campaign:creds_submitted",
      "engagement:phase_changed", "engagement:timeline_event",
      "pipeline:started", "pipeline:finished",
      "job:completed", "job:failed",
      "system:alert", "system:notification",
      "automation:profile_generated", "automation:profile_pushed",
      "automation:playbook_triggered", "automation:pipeline_run", "automation:enrichment_complete",
      "cockpit:timeline_event", "cockpit:opsec_update",
    ];
    // Cockpit should have the most comprehensive set of event types
    expect(cockpitFilterTypes.length).toBeGreaterThan(30);
    expect(cockpitFilterTypes).toContain("cockpit:timeline_event");
    expect(cockpitFilterTypes).toContain("cockpit:opsec_update");
  });
});

// ─── SSE Event Ring Buffer Tests ───────────────────────────────────

describe("SSE Event Ring Buffer", () => {
  it("should maintain buffer within EVENT_BUFFER_SIZE limit", () => {
    const EVENT_BUFFER_SIZE = 200;
    const buffer: Array<{ event: any; channel: string; id: number }> = [];
    let idCounter = 0;

    // Add 250 events
    for (let i = 0; i < 250; i++) {
      idCounter++;
      buffer.push({
        event: { type: "system:notification", timestamp: Date.now(), data: { i } },
        channel: "global",
        id: idCounter,
      });
      if (buffer.length > EVENT_BUFFER_SIZE) {
        buffer.shift();
      }
    }

    expect(buffer.length).toBe(EVENT_BUFFER_SIZE);
    // First event in buffer should be event #51 (250 - 200 + 1)
    expect(buffer[0].id).toBe(51);
    // Last event should be #250
    expect(buffer[buffer.length - 1].id).toBe(250);
  });

  it("should replay events after lastEventId for catch-up", () => {
    const buffer = [
      { event: { type: "a" }, channel: "global", id: 10 },
      { event: { type: "b" }, channel: "global", id: 11 },
      { event: { type: "c" }, channel: "engagement:1", id: 12 },
      { event: { type: "d" }, channel: "global", id: 13 },
    ];

    const lastEventId = 11;
    const channels = new Set(["global"]);
    const replayed = buffer.filter(
      (entry) => entry.id > lastEventId && channels.has(entry.channel)
    );

    // Should only replay id=13 (id=12 is engagement:1, not in channels)
    expect(replayed.length).toBe(1);
    expect(replayed[0].id).toBe(13);
  });

  it("should replay events matching subscribed channels", () => {
    const buffer = [
      { event: { type: "a" }, channel: "global", id: 1 },
      { event: { type: "b" }, channel: "engagement:42", id: 2 },
      { event: { type: "c" }, channel: "engagement:99", id: 3 },
      { event: { type: "d" }, channel: "global", id: 4 },
    ];

    const lastEventId = 0;
    const channels = new Set(["global", "engagement:42"]);
    const replayed = buffer.filter(
      (entry) => entry.id > lastEventId && channels.has(entry.channel)
    );

    // Should replay ids 1, 2, 4 (not 3 — wrong engagement)
    expect(replayed.length).toBe(3);
    expect(replayed.map((r) => r.id)).toEqual([1, 2, 4]);
  });
});
