/**
 * C2 Callback Poller & Engagement Resume — Unit Tests
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Tests for:
 *   1. C2 Callback Poller — agent tracking, link dedup, heartbeat miss detection
 *   2. Engagement Resume — phase advancement, state preservation, startPhase logic
 *   3. LiveTrigger resume capability detection
 */
import { describe, it, expect } from "vitest";

// ─── C2 Poller Agent Tracking ─────────────────────────────────────────────

interface C2Agent {
  paw: string;
  host: string;
  platform: string;
  lastSeen: string;
  firstSeenAt: number;
  lastProcessedHeartbeat: string;
}

interface C2PollerState {
  agents: Map<string, C2Agent>;
  processedLinkIds: Set<string>;
  agentHeartbeatMisses: Map<string, number>;
  events: Array<{ timestamp: number; type: string; summary: string }>;
}

function processAgentUpdate(
  state: C2PollerState,
  rawAgent: { paw: string; host: string; platform: string; last_seen: string },
): "new" | "heartbeat" | "stale" {
  const { paw, host, platform, last_seen } = rawAgent;
  const existing = state.agents.get(paw);

  if (!existing) {
    state.agents.set(paw, {
      paw,
      host,
      platform,
      lastSeen: last_seen,
      firstSeenAt: Date.now(),
      lastProcessedHeartbeat: last_seen,
    });
    state.agentHeartbeatMisses.set(paw, 0);
    state.events.push({ timestamp: Date.now(), type: "c2:agent_checkin", summary: `New agent: ${paw}` });
    return "new";
  }

  if (last_seen !== existing.lastProcessedHeartbeat) {
    existing.lastSeen = last_seen;
    existing.lastProcessedHeartbeat = last_seen;
    state.agentHeartbeatMisses.set(paw, 0);
    return "heartbeat";
  }

  const misses = (state.agentHeartbeatMisses.get(paw) || 0) + 1;
  state.agentHeartbeatMisses.set(paw, misses);
  return "stale";
}

function processLink(
  state: C2PollerState,
  link: { id: string; abilityName: string; paw: string; status: number },
): boolean {
  if (state.processedLinkIds.has(link.id)) return false;
  // Only process completed links
  if (link.status === -3 || link.status === -1) return false;
  state.processedLinkIds.add(link.id);
  const statusLabel = link.status === 0 ? "success" : link.status === 1 ? "fail" : "discarded";
  state.events.push({
    timestamp: Date.now(),
    type: "c2:ability_executed",
    summary: `[${statusLabel}] ${link.abilityName} on ${link.paw}`,
  });
  return true;
}

function createPollerState(): C2PollerState {
  return {
    agents: new Map(),
    processedLinkIds: new Set(),
    agentHeartbeatMisses: new Map(),
    events: [],
  };
}

describe("C2 Callback Poller — Agent Tracking", () => {
  it("should detect new agents", () => {
    const state = createPollerState();
    const result = processAgentUpdate(state, {
      paw: "abc123",
      host: "target-01",
      platform: "linux",
      last_seen: "2026-03-18T22:00:00Z",
    });
    expect(result).toBe("new");
    expect(state.agents.size).toBe(1);
    expect(state.agents.get("abc123")?.host).toBe("target-01");
    expect(state.events).toHaveLength(1);
    expect(state.events[0].type).toBe("c2:agent_checkin");
  });

  it("should detect heartbeat updates", () => {
    const state = createPollerState();
    processAgentUpdate(state, { paw: "abc123", host: "target-01", platform: "linux", last_seen: "2026-03-18T22:00:00Z" });
    const result = processAgentUpdate(state, { paw: "abc123", host: "target-01", platform: "linux", last_seen: "2026-03-18T22:00:10Z" });
    expect(result).toBe("heartbeat");
    expect(state.agentHeartbeatMisses.get("abc123")).toBe(0);
  });

  it("should detect stale agents (no new heartbeat)", () => {
    const state = createPollerState();
    processAgentUpdate(state, { paw: "abc123", host: "target-01", platform: "linux", last_seen: "2026-03-18T22:00:00Z" });
    const result = processAgentUpdate(state, { paw: "abc123", host: "target-01", platform: "linux", last_seen: "2026-03-18T22:00:00Z" });
    expect(result).toBe("stale");
    expect(state.agentHeartbeatMisses.get("abc123")).toBe(1);
  });

  it("should accumulate heartbeat misses", () => {
    const state = createPollerState();
    processAgentUpdate(state, { paw: "abc123", host: "target-01", platform: "linux", last_seen: "2026-03-18T22:00:00Z" });
    for (let i = 0; i < 5; i++) {
      processAgentUpdate(state, { paw: "abc123", host: "target-01", platform: "linux", last_seen: "2026-03-18T22:00:00Z" });
    }
    expect(state.agentHeartbeatMisses.get("abc123")).toBe(5);
  });

  it("should reset misses on new heartbeat", () => {
    const state = createPollerState();
    processAgentUpdate(state, { paw: "abc123", host: "target-01", platform: "linux", last_seen: "2026-03-18T22:00:00Z" });
    processAgentUpdate(state, { paw: "abc123", host: "target-01", platform: "linux", last_seen: "2026-03-18T22:00:00Z" });
    processAgentUpdate(state, { paw: "abc123", host: "target-01", platform: "linux", last_seen: "2026-03-18T22:00:00Z" });
    expect(state.agentHeartbeatMisses.get("abc123")).toBe(2);
    processAgentUpdate(state, { paw: "abc123", host: "target-01", platform: "linux", last_seen: "2026-03-18T22:00:30Z" });
    expect(state.agentHeartbeatMisses.get("abc123")).toBe(0);
  });

  it("should track multiple agents independently", () => {
    const state = createPollerState();
    processAgentUpdate(state, { paw: "agent-1", host: "host-a", platform: "linux", last_seen: "2026-03-18T22:00:00Z" });
    processAgentUpdate(state, { paw: "agent-2", host: "host-b", platform: "windows", last_seen: "2026-03-18T22:00:00Z" });
    expect(state.agents.size).toBe(2);
    expect(state.agents.get("agent-1")?.platform).toBe("linux");
    expect(state.agents.get("agent-2")?.platform).toBe("windows");
  });
});

describe("C2 Callback Poller — Link Processing", () => {
  it("should process new completed links", () => {
    const state = createPollerState();
    const processed = processLink(state, { id: "link-1", abilityName: "whoami", paw: "abc123", status: 0 });
    expect(processed).toBe(true);
    expect(state.processedLinkIds.size).toBe(1);
    expect(state.events[0].summary).toContain("[success]");
  });

  it("should skip already-processed links (dedup)", () => {
    const state = createPollerState();
    processLink(state, { id: "link-1", abilityName: "whoami", paw: "abc123", status: 0 });
    const second = processLink(state, { id: "link-1", abilityName: "whoami", paw: "abc123", status: 0 });
    expect(second).toBe(false);
    expect(state.processedLinkIds.size).toBe(1);
    expect(state.events).toHaveLength(1);
  });

  it("should skip queued/collecting links", () => {
    const state = createPollerState();
    expect(processLink(state, { id: "link-q", abilityName: "scan", paw: "abc", status: -3 })).toBe(false);
    expect(processLink(state, { id: "link-c", abilityName: "scan", paw: "abc", status: -1 })).toBe(false);
    expect(state.processedLinkIds.size).toBe(0);
  });

  it("should label failed links correctly", () => {
    const state = createPollerState();
    processLink(state, { id: "link-f", abilityName: "exploit", paw: "abc", status: 1 });
    expect(state.events[0].summary).toContain("[fail]");
  });

  it("should label discarded links correctly", () => {
    const state = createPollerState();
    processLink(state, { id: "link-d", abilityName: "cleanup", paw: "abc", status: -2 });
    expect(state.events[0].summary).toContain("[discarded]");
  });
});

// ─── Engagement Resume Logic ──────────────────────────────────────────────

type OpsPhase = "idle" | "recon" | "enumeration" | "vuln_detection" | "exploitation" | "post_exploit" | "completed" | "error";

const PHASE_ORDER: OpsPhase[] = ["recon", "enumeration", "vuln_detection", "exploitation", "post_exploit"];

interface ResumeInput {
  recoveredPhase: OpsPhase;
  assetCount: number;
  vulnsFound: number;
  explicitStartPhase?: OpsPhase;
}

interface ResumeResult {
  canResume: boolean;
  startPhase: OpsPhase;
  reason: string;
}

function computeResumeTarget(input: ResumeInput): ResumeResult {
  const { recoveredPhase, assetCount, explicitStartPhase } = input;

  // Cannot resume from completed, error, or idle
  if (recoveredPhase === "completed" || recoveredPhase === "error" || recoveredPhase === "idle") {
    return { canResume: false, startPhase: "recon", reason: `Cannot resume from ${recoveredPhase}` };
  }

  // Cannot resume with no assets
  if (assetCount === 0) {
    return { canResume: false, startPhase: "recon", reason: "No assets to resume with" };
  }

  // Use explicit startPhase if provided
  if (explicitStartPhase) {
    return { canResume: true, startPhase: explicitStartPhase, reason: `Explicit start phase: ${explicitStartPhase}` };
  }

  // Advance to next phase
  const lastIdx = PHASE_ORDER.indexOf(recoveredPhase);
  if (lastIdx >= 0 && lastIdx < PHASE_ORDER.length - 1) {
    const nextPhase = PHASE_ORDER[lastIdx + 1];
    return { canResume: true, startPhase: nextPhase, reason: `Advancing from ${recoveredPhase} to ${nextPhase}` };
  }

  // Last phase or unknown — re-run same phase
  return { canResume: true, startPhase: recoveredPhase, reason: `Re-running ${recoveredPhase}` };
}

describe("Engagement Resume — Phase Advancement", () => {
  it("should advance from recon to enumeration", () => {
    const result = computeResumeTarget({ recoveredPhase: "recon", assetCount: 3, vulnsFound: 0 });
    expect(result.canResume).toBe(true);
    expect(result.startPhase).toBe("enumeration");
  });

  it("should advance from enumeration to vuln_detection", () => {
    const result = computeResumeTarget({ recoveredPhase: "enumeration", assetCount: 2, vulnsFound: 5 });
    expect(result.canResume).toBe(true);
    expect(result.startPhase).toBe("vuln_detection");
  });

  it("should advance from vuln_detection to exploitation", () => {
    const result = computeResumeTarget({ recoveredPhase: "vuln_detection", assetCount: 2, vulnsFound: 15 });
    expect(result.canResume).toBe(true);
    expect(result.startPhase).toBe("exploitation");
  });

  it("should advance from exploitation to post_exploit", () => {
    const result = computeResumeTarget({ recoveredPhase: "exploitation", assetCount: 2, vulnsFound: 20 });
    expect(result.canResume).toBe(true);
    expect(result.startPhase).toBe("post_exploit");
  });

  it("should re-run post_exploit (last phase)", () => {
    const result = computeResumeTarget({ recoveredPhase: "post_exploit", assetCount: 1, vulnsFound: 10 });
    expect(result.canResume).toBe(true);
    expect(result.startPhase).toBe("post_exploit");
  });

  it("should not resume from completed", () => {
    const result = computeResumeTarget({ recoveredPhase: "completed", assetCount: 5, vulnsFound: 30 });
    expect(result.canResume).toBe(false);
  });

  it("should not resume from error", () => {
    const result = computeResumeTarget({ recoveredPhase: "error", assetCount: 2, vulnsFound: 10 });
    expect(result.canResume).toBe(false);
  });

  it("should not resume from idle", () => {
    const result = computeResumeTarget({ recoveredPhase: "idle", assetCount: 0, vulnsFound: 0 });
    expect(result.canResume).toBe(false);
  });

  it("should not resume with zero assets", () => {
    const result = computeResumeTarget({ recoveredPhase: "enumeration", assetCount: 0, vulnsFound: 0 });
    expect(result.canResume).toBe(false);
  });

  it("should use explicit startPhase when provided", () => {
    const result = computeResumeTarget({
      recoveredPhase: "recon",
      assetCount: 3,
      vulnsFound: 0,
      explicitStartPhase: "vuln_detection",
    });
    expect(result.canResume).toBe(true);
    expect(result.startPhase).toBe("vuln_detection");
  });
});

// ─── Resume Capability Detection ──────────────────────────────────────────

interface SnapshotState {
  phase: OpsPhase;
  isRunning: boolean;
  assetCount: number;
  vulnsFound: number;
  progress: number;
}

function checkResumeCapability(state: SnapshotState | null): {
  canResume: boolean;
  reason: string;
} {
  if (!state) return { canResume: false, reason: "No saved state found" };
  if (state.isRunning) return { canResume: false, reason: "Engagement is currently running" };
  if (state.phase === "completed") return { canResume: false, reason: "Engagement already completed" };
  if (state.phase === "idle" || state.assetCount === 0) return { canResume: false, reason: "No meaningful progress" };
  return { canResume: true, reason: `Can resume from ${state.phase}` };
}

describe("Resume Capability Detection", () => {
  it("should detect resumable state", () => {
    const result = checkResumeCapability({ phase: "enumeration", isRunning: false, assetCount: 2, vulnsFound: 5, progress: 30 });
    expect(result.canResume).toBe(true);
  });

  it("should reject null state", () => {
    const result = checkResumeCapability(null);
    expect(result.canResume).toBe(false);
    expect(result.reason).toContain("No saved state");
  });

  it("should reject running engagement", () => {
    const result = checkResumeCapability({ phase: "exploitation", isRunning: true, assetCount: 2, vulnsFound: 15, progress: 60 });
    expect(result.canResume).toBe(false);
    expect(result.reason).toContain("currently running");
  });

  it("should reject completed engagement", () => {
    const result = checkResumeCapability({ phase: "completed", isRunning: false, assetCount: 3, vulnsFound: 20, progress: 100 });
    expect(result.canResume).toBe(false);
  });

  it("should reject idle with no assets", () => {
    const result = checkResumeCapability({ phase: "idle", isRunning: false, assetCount: 0, vulnsFound: 0, progress: 0 });
    expect(result.canResume).toBe(false);
  });

  it("should reject non-idle with zero assets", () => {
    const result = checkResumeCapability({ phase: "recon", isRunning: false, assetCount: 0, vulnsFound: 0, progress: 5 });
    expect(result.canResume).toBe(false);
  });
});

// ─── C2 Operation Snapshot Diffing ────────────────────────────────────────

interface OpSnapshot {
  state: string;
  agentCount: number;
  linkCount: number;
  successCount: number;
  failCount: number;
}

function diffOperationSnapshots(prev: OpSnapshot | null, curr: OpSnapshot): {
  stateChanged: boolean;
  newLinks: number;
  newAgents: number;
  newSuccesses: number;
  newFailures: number;
} {
  if (!prev) {
    return {
      stateChanged: true,
      newLinks: curr.linkCount,
      newAgents: curr.agentCount,
      newSuccesses: curr.successCount,
      newFailures: curr.failCount,
    };
  }
  return {
    stateChanged: prev.state !== curr.state,
    newLinks: Math.max(0, curr.linkCount - prev.linkCount),
    newAgents: Math.max(0, curr.agentCount - prev.agentCount),
    newSuccesses: Math.max(0, curr.successCount - prev.successCount),
    newFailures: Math.max(0, curr.failCount - prev.failCount),
  };
}

describe("C2 Operation Snapshot Diffing", () => {
  it("should detect all changes from null previous", () => {
    const diff = diffOperationSnapshots(null, {
      state: "running", agentCount: 2, linkCount: 5, successCount: 3, failCount: 1,
    });
    expect(diff.stateChanged).toBe(true);
    expect(diff.newLinks).toBe(5);
    expect(diff.newAgents).toBe(2);
    expect(diff.newSuccesses).toBe(3);
    expect(diff.newFailures).toBe(1);
  });

  it("should detect state change", () => {
    const prev: OpSnapshot = { state: "running", agentCount: 2, linkCount: 5, successCount: 3, failCount: 1 };
    const curr: OpSnapshot = { state: "finished", agentCount: 2, linkCount: 8, successCount: 6, failCount: 2 };
    const diff = diffOperationSnapshots(prev, curr);
    expect(diff.stateChanged).toBe(true);
    expect(diff.newLinks).toBe(3);
    expect(diff.newSuccesses).toBe(3);
    expect(diff.newFailures).toBe(1);
  });

  it("should detect no changes", () => {
    const snap: OpSnapshot = { state: "running", agentCount: 2, linkCount: 5, successCount: 3, failCount: 1 };
    const diff = diffOperationSnapshots(snap, { ...snap });
    expect(diff.stateChanged).toBe(false);
    expect(diff.newLinks).toBe(0);
    expect(diff.newAgents).toBe(0);
  });

  it("should handle decreasing counts gracefully (clamp to 0)", () => {
    const prev: OpSnapshot = { state: "running", agentCount: 3, linkCount: 10, successCount: 8, failCount: 2 };
    const curr: OpSnapshot = { state: "running", agentCount: 2, linkCount: 8, successCount: 6, failCount: 1 };
    const diff = diffOperationSnapshots(prev, curr);
    expect(diff.newLinks).toBe(0);
    expect(diff.newAgents).toBe(0);
    expect(diff.newSuccesses).toBe(0);
    expect(diff.newFailures).toBe(0);
  });
});

// ─── Phase Label Mapping ──────────────────────────────────────────────────

const PHASE_LABELS: Record<string, string> = {
  idle: "Idle",
  recon: "Phase 1: Recon & Discovery",
  enumeration: "Phase 2: Enumeration & Fingerprinting",
  vuln_detection: "Phase 3: Vulnerability Detection",
  exploitation: "Phase 4: Exploitation",
  post_exploit: "Phase 5: Post-Exploit",
  completed: "Completed",
  error: "Error",
};

describe("Phase Label Mapping", () => {
  it("should map all pipeline phases", () => {
    for (const phase of PHASE_ORDER) {
      expect(PHASE_LABELS[phase]).toBeDefined();
      expect(PHASE_LABELS[phase]).toContain("Phase");
    }
  });

  it("should map terminal states", () => {
    expect(PHASE_LABELS["completed"]).toBe("Completed");
    expect(PHASE_LABELS["error"]).toBe("Error");
    expect(PHASE_LABELS["idle"]).toBe("Idle");
  });
});
