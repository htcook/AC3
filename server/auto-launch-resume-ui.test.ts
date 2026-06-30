/**
 * Auto-Launch, PendingVulns Deferral, Resume UI — Unit Tests
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Tests for:
 *   1. PendingVulns deferral — vulns stored in pendingVulns during recon, promoted in vuln_detection
 *   2. Auto-launch profile selection — prefer deployed profiles, fallback to local
 *   3. Auto-launch operation config — correct naming, planner, autonomous settings
 *   4. Resume capability detection — canResume logic, phase advancement
 *   5. C2 Activity Feed event rendering — event type classification, severity mapping
 */
import { describe, it, expect } from "vitest";

// ─── PendingVulns Deferral ──────────────────────────────────────────────

interface VulnEntry {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  source: string;
}

interface AssetWithPending {
  hostname: string;
  ip: string;
  vulns: VulnEntry[];
  pendingVulns: VulnEntry[];
  status: string;
}

function addPassiveVulnDuringRecon(asset: AssetWithPending, vuln: VulnEntry): void {
  // During recon, vulns go to pendingVulns, NOT vulns
  if (!asset.pendingVulns) asset.pendingVulns = [];
  const isDupe = asset.pendingVulns.some(
    (v) => v.id === vuln.id || (v.title === vuln.title && v.severity === vuln.severity),
  );
  if (!isDupe) {
    asset.pendingVulns.push(vuln);
  }
}

function promotePendingVulns(asset: AssetWithPending): number {
  if (!asset.pendingVulns || asset.pendingVulns.length === 0) return 0;
  const promoted = asset.pendingVulns.length;
  for (const v of asset.pendingVulns) {
    const isDupe = asset.vulns.some(
      (ev) => ev.id === v.id || (ev.title === v.title && ev.severity === v.severity),
    );
    if (!isDupe) {
      asset.vulns.push(v);
    }
  }
  asset.pendingVulns = [];
  return promoted;
}

describe("PendingVulns Deferral", () => {
  it("stores passive vulns in pendingVulns during recon, not vulns", () => {
    const asset: AssetWithPending = {
      hostname: "target.com",
      ip: "1.2.3.4",
      vulns: [],
      pendingVulns: [],
      status: "discovered",
    };
    const vuln: VulnEntry = {
      id: "CVE-2024-1234",
      title: "SSL Weakness",
      severity: "medium",
      source: "passive_recon",
    };
    addPassiveVulnDuringRecon(asset, vuln);
    expect(asset.vulns).toHaveLength(0);
    expect(asset.pendingVulns).toHaveLength(1);
    expect(asset.pendingVulns[0].id).toBe("CVE-2024-1234");
  });

  it("deduplicates pending vulns by ID", () => {
    const asset: AssetWithPending = {
      hostname: "target.com",
      ip: "1.2.3.4",
      vulns: [],
      pendingVulns: [],
      status: "discovered",
    };
    const vuln: VulnEntry = {
      id: "CVE-2024-1234",
      title: "SSL Weakness",
      severity: "medium",
      source: "passive_recon",
    };
    addPassiveVulnDuringRecon(asset, vuln);
    addPassiveVulnDuringRecon(asset, vuln);
    expect(asset.pendingVulns).toHaveLength(1);
  });

  it("deduplicates pending vulns by title+severity", () => {
    const asset: AssetWithPending = {
      hostname: "target.com",
      ip: "1.2.3.4",
      vulns: [],
      pendingVulns: [],
      status: "discovered",
    };
    addPassiveVulnDuringRecon(asset, {
      id: "CVE-2024-1234",
      title: "SSL Weakness",
      severity: "medium",
      source: "passive",
    });
    addPassiveVulnDuringRecon(asset, {
      id: "CVE-2024-9999",
      title: "SSL Weakness",
      severity: "medium",
      source: "other",
    });
    expect(asset.pendingVulns).toHaveLength(1);
  });

  it("promotes all pending vulns to vulns during vuln_detection", () => {
    const asset: AssetWithPending = {
      hostname: "target.com",
      ip: "1.2.3.4",
      vulns: [],
      pendingVulns: [
        { id: "CVE-2024-1", title: "Vuln A", severity: "high", source: "passive" },
        { id: "CVE-2024-2", title: "Vuln B", severity: "critical", source: "passive" },
      ],
      status: "discovered",
    };
    const promoted = promotePendingVulns(asset);
    expect(promoted).toBe(2);
    expect(asset.vulns).toHaveLength(2);
    expect(asset.pendingVulns).toHaveLength(0);
  });

  it("does not create duplicate vulns during promotion", () => {
    const asset: AssetWithPending = {
      hostname: "target.com",
      ip: "1.2.3.4",
      vulns: [{ id: "CVE-2024-1", title: "Vuln A", severity: "high", source: "active" }],
      pendingVulns: [
        { id: "CVE-2024-1", title: "Vuln A", severity: "high", source: "passive" },
        { id: "CVE-2024-3", title: "Vuln C", severity: "low", source: "passive" },
      ],
      status: "discovered",
    };
    promotePendingVulns(asset);
    expect(asset.vulns).toHaveLength(2); // Only Vuln C added, Vuln A deduped
    expect(asset.vulns.map((v) => v.id)).toContain("CVE-2024-3");
  });

  it("handles empty pendingVulns gracefully", () => {
    const asset: AssetWithPending = {
      hostname: "target.com",
      ip: "1.2.3.4",
      vulns: [{ id: "CVE-2024-1", title: "Vuln A", severity: "high", source: "active" }],
      pendingVulns: [],
      status: "discovered",
    };
    const promoted = promotePendingVulns(asset);
    expect(promoted).toBe(0);
    expect(asset.vulns).toHaveLength(1);
  });

  it("initializes pendingVulns if missing", () => {
    const asset = {
      hostname: "target.com",
      ip: "1.2.3.4",
      vulns: [],
      status: "discovered",
    } as any;
    addPassiveVulnDuringRecon(asset, {
      id: "CVE-2024-1",
      title: "Test",
      severity: "info",
      source: "passive",
    });
    expect(asset.pendingVulns).toHaveLength(1);
  });
});

// ─── Auto-Launch Profile Selection ──────────────────────────────────────

interface CalderaProfile {
  adversaryId?: string;
  calderaServerId?: string;
  name: string;
  atomicOrdering: string[];
  deploymentStatus: "local_only" | "pending" | "deployed" | "failed";
}

interface ActorWithProfile {
  actorId: string;
  name: string;
  calderaProfile: CalderaProfile | null;
}

function selectBestProfile(
  actors: ActorWithProfile[],
): { actor: ActorWithProfile; adversaryId: string | null } | null {
  let selectedActor: ActorWithProfile | null = null;
  let selectedAdversaryId: string | null = null;

  for (const actor of actors) {
    const profile = actor.calderaProfile;
    if (!profile) continue;

    if (profile.deploymentStatus === "deployed" && profile.calderaServerId) {
      return { actor, adversaryId: profile.calderaServerId };
    }
    if (!selectedActor && profile.atomicOrdering?.length > 0) {
      selectedActor = actor;
    }
  }

  return selectedActor ? { actor: selectedActor, adversaryId: selectedAdversaryId } : null;
}

describe("Auto-Launch Profile Selection", () => {
  it("prefers already-deployed profiles", () => {
    const actors: ActorWithProfile[] = [
      {
        actorId: "apt28",
        name: "APT28",
        calderaProfile: {
          name: "APT28 Profile",
          atomicOrdering: ["ab1", "ab2"],
          deploymentStatus: "local_only",
        },
      },
      {
        actorId: "apt29",
        name: "APT29",
        calderaProfile: {
          name: "APT29 Profile",
          atomicOrdering: ["ab3"],
          deploymentStatus: "deployed",
          calderaServerId: "caldera-apt29-id",
        },
      },
    ];
    const result = selectBestProfile(actors);
    expect(result).not.toBeNull();
    expect(result!.actor.actorId).toBe("apt29");
    expect(result!.adversaryId).toBe("caldera-apt29-id");
  });

  it("falls back to local profile with abilities if no deployed profile", () => {
    const actors: ActorWithProfile[] = [
      {
        actorId: "apt28",
        name: "APT28",
        calderaProfile: {
          name: "APT28 Profile",
          atomicOrdering: ["ab1", "ab2"],
          deploymentStatus: "local_only",
        },
      },
    ];
    const result = selectBestProfile(actors);
    expect(result).not.toBeNull();
    expect(result!.actor.actorId).toBe("apt28");
    expect(result!.adversaryId).toBeNull(); // Needs push first
  });

  it("returns null when no actors have profiles", () => {
    const actors: ActorWithProfile[] = [
      { actorId: "apt28", name: "APT28", calderaProfile: null },
    ];
    const result = selectBestProfile(actors);
    expect(result).toBeNull();
  });

  it("skips profiles with empty atomicOrdering", () => {
    const actors: ActorWithProfile[] = [
      {
        actorId: "apt28",
        name: "APT28",
        calderaProfile: {
          name: "APT28 Profile",
          atomicOrdering: [],
          deploymentStatus: "local_only",
        },
      },
    ];
    const result = selectBestProfile(actors);
    expect(result).toBeNull();
  });

  it("returns first deployed profile even if later ones exist", () => {
    const actors: ActorWithProfile[] = [
      {
        actorId: "apt28",
        name: "APT28",
        calderaProfile: {
          name: "APT28 Profile",
          atomicOrdering: ["ab1"],
          deploymentStatus: "deployed",
          calderaServerId: "id-28",
        },
      },
      {
        actorId: "apt29",
        name: "APT29",
        calderaProfile: {
          name: "APT29 Profile",
          atomicOrdering: ["ab2", "ab3"],
          deploymentStatus: "deployed",
          calderaServerId: "id-29",
        },
      },
    ];
    const result = selectBestProfile(actors);
    expect(result!.actor.actorId).toBe("apt28");
    expect(result!.adversaryId).toBe("id-28");
  });
});

// ─── Auto-Launch Operation Config ───────────────────────────────────────

interface AutoLaunchConfig {
  name: string;
  adversaryId: string;
  group: string;
  planner: string;
  autonomous: boolean;
  autoClose: boolean;
  jitter: string;
}

function buildAutoLaunchConfig(
  engagementId: number,
  adversaryId: string,
  timestamp: number,
): AutoLaunchConfig {
  return {
    name: `AC3-AutoLaunch-Eng${engagementId}-${timestamp}`,
    adversaryId,
    group: "",
    planner: "batch",
    autonomous: true,
    autoClose: true,
    jitter: "2/8",
  };
}

describe("Auto-Launch Operation Config", () => {
  it("generates correct operation name with engagement ID and timestamp", () => {
    const config = buildAutoLaunchConfig(1770040, "adv-123", 1710799200000);
    expect(config.name).toBe("AC3-AutoLaunch-Eng1770040-1710799200000");
  });

  it("uses batch planner and autonomous mode", () => {
    const config = buildAutoLaunchConfig(1, "adv-1", Date.now());
    expect(config.planner).toBe("batch");
    expect(config.autonomous).toBe(true);
    expect(config.autoClose).toBe(true);
  });

  it("targets all agent groups (empty string)", () => {
    const config = buildAutoLaunchConfig(1, "adv-1", Date.now());
    expect(config.group).toBe("");
  });

  it("uses 2/8 jitter for stealth", () => {
    const config = buildAutoLaunchConfig(1, "adv-1", Date.now());
    expect(config.jitter).toBe("2/8");
  });
});

// ─── Resume Capability Detection ────────────────────────────────────────

type OpsPhase =
  | "idle"
  | "recon"
  | "enumeration"
  | "vuln_detection"
  | "exploitation"
  | "post_exploit"
  | "complete"
  | "error"
  | "recon_complete";

const PHASE_ORDER: OpsPhase[] = [
  "recon",
  "enumeration",
  "vuln_detection",
  "exploitation",
  "post_exploit",
];

const PHASE_LABELS: Record<string, string> = {
  recon: "Phase 1: Reconnaissance",
  enumeration: "Phase 2: Enumeration",
  vuln_detection: "Phase 3: Vulnerability Detection",
  exploitation: "Phase 4: Exploitation",
  post_exploit: "Phase 5: Post-Exploitation",
  complete: "Complete",
  error: "Error",
  idle: "Idle",
  recon_complete: "Recon Complete",
};

interface ResumeCheckResult {
  canResume: boolean;
  reason: string;
  nextPhase?: OpsPhase;
  nextPhaseLabel?: string;
  currentPhaseLabel?: string;
  preservedAssets?: number;
  preservedVulns?: number;
}

function checkResumeCapability(state: {
  phase: OpsPhase;
  assets: any[];
  stats: { vulnsFound: number; portsFound: number };
  logs: any[];
}): ResumeCheckResult {
  if (state.phase === "idle" || state.assets.length === 0) {
    return { canResume: false, reason: "No meaningful progress to resume from" };
  }

  const lastPhaseIdx = PHASE_ORDER.indexOf(state.phase as any);
  const nextPhase =
    lastPhaseIdx >= 0 && lastPhaseIdx < PHASE_ORDER.length - 1
      ? PHASE_ORDER[lastPhaseIdx + 1]
      : state.phase;

  return {
    canResume: true,
    reason: `Can resume from ${PHASE_LABELS[state.phase]} → ${PHASE_LABELS[nextPhase]}`,
    nextPhase,
    nextPhaseLabel: PHASE_LABELS[nextPhase],
    currentPhaseLabel: PHASE_LABELS[state.phase],
    preservedAssets: state.assets.length,
    preservedVulns: state.stats.vulnsFound,
  };
}

describe("Resume Capability Detection", () => {
  it("returns canResume=false for idle state", () => {
    const result = checkResumeCapability({
      phase: "idle",
      assets: [],
      stats: { vulnsFound: 0, portsFound: 0 },
      logs: [],
    });
    expect(result.canResume).toBe(false);
  });

  it("returns canResume=false when no assets discovered", () => {
    const result = checkResumeCapability({
      phase: "recon",
      assets: [],
      stats: { vulnsFound: 0, portsFound: 0 },
      logs: [],
    });
    expect(result.canResume).toBe(false);
  });

  it("returns canResume=true with next phase for recon", () => {
    const result = checkResumeCapability({
      phase: "recon",
      assets: [{ hostname: "target.com" }],
      stats: { vulnsFound: 0, portsFound: 5 },
      logs: [{ msg: "test" }],
    });
    expect(result.canResume).toBe(true);
    expect(result.nextPhase).toBe("enumeration");
    expect(result.nextPhaseLabel).toBe("Phase 2: Enumeration");
  });

  it("advances from enumeration to vuln_detection", () => {
    const result = checkResumeCapability({
      phase: "enumeration",
      assets: [{ hostname: "target.com" }, { hostname: "target2.com" }],
      stats: { vulnsFound: 3, portsFound: 10 },
      logs: [],
    });
    expect(result.canResume).toBe(true);
    expect(result.nextPhase).toBe("vuln_detection");
    expect(result.preservedAssets).toBe(2);
    expect(result.preservedVulns).toBe(3);
  });

  it("advances from vuln_detection to exploitation", () => {
    const result = checkResumeCapability({
      phase: "vuln_detection",
      assets: [{ hostname: "target.com" }],
      stats: { vulnsFound: 22, portsFound: 10 },
      logs: [],
    });
    expect(result.nextPhase).toBe("exploitation");
  });

  it("advances from exploitation to post_exploit", () => {
    const result = checkResumeCapability({
      phase: "exploitation",
      assets: [{ hostname: "target.com" }],
      stats: { vulnsFound: 22, portsFound: 10 },
      logs: [],
    });
    expect(result.nextPhase).toBe("post_exploit");
  });

  it("stays at post_exploit when already at last phase", () => {
    const result = checkResumeCapability({
      phase: "post_exploit",
      assets: [{ hostname: "target.com" }],
      stats: { vulnsFound: 22, portsFound: 10 },
      logs: [],
    });
    expect(result.canResume).toBe(true);
    // post_exploit is the last in PHASE_ORDER, so nextPhase stays the same
  });

  it("handles error phase with assets (can resume)", () => {
    const result = checkResumeCapability({
      phase: "error" as any,
      assets: [{ hostname: "target.com" }],
      stats: { vulnsFound: 5, portsFound: 3 },
      logs: [],
    });
    expect(result.canResume).toBe(true);
    // error is not in PHASE_ORDER, so nextPhase = error (same phase)
    expect(result.nextPhase).toBe("error");
  });
});

// ─── C2 Activity Feed Event Classification ──────────────────────────────

type C2EventType =
  | "c2:agent_checkin"
  | "c2:ability_executed"
  | "c2:operation_update"
  | "c2:agent_lost"
  | "c2:operation_complete";

interface C2FeedEvent {
  type: C2EventType;
  timestamp: number;
  summary: string;
  data?: any;
}

function classifyEventSeverity(
  event: C2FeedEvent,
): "critical" | "warning" | "success" | "info" {
  switch (event.type) {
    case "c2:agent_lost":
      return "warning";
    case "c2:agent_checkin":
      return "success";
    case "c2:ability_executed":
      return event.data?.status === 0 ? "success" : event.data?.status === -1 ? "critical" : "info";
    case "c2:operation_complete":
      return "success";
    case "c2:operation_update":
      return "info";
    default:
      return "info";
  }
}

function getEventIcon(type: C2EventType): string {
  switch (type) {
    case "c2:agent_checkin":
      return "🟢";
    case "c2:agent_lost":
      return "🔴";
    case "c2:ability_executed":
      return "⚡";
    case "c2:operation_update":
      return "📡";
    case "c2:operation_complete":
      return "✅";
    default:
      return "📌";
  }
}

describe("C2 Activity Feed Event Classification", () => {
  it("classifies agent_checkin as success", () => {
    const severity = classifyEventSeverity({
      type: "c2:agent_checkin",
      timestamp: Date.now(),
      summary: "New agent",
    });
    expect(severity).toBe("success");
  });

  it("classifies agent_lost as warning", () => {
    const severity = classifyEventSeverity({
      type: "c2:agent_lost",
      timestamp: Date.now(),
      summary: "Agent lost",
    });
    expect(severity).toBe("warning");
  });

  it("classifies successful ability execution as success", () => {
    const severity = classifyEventSeverity({
      type: "c2:ability_executed",
      timestamp: Date.now(),
      summary: "Ability ran",
      data: { status: 0 },
    });
    expect(severity).toBe("success");
  });

  it("classifies failed ability execution as critical", () => {
    const severity = classifyEventSeverity({
      type: "c2:ability_executed",
      timestamp: Date.now(),
      summary: "Ability failed",
      data: { status: -1 },
    });
    expect(severity).toBe("critical");
  });

  it("classifies pending ability execution as info", () => {
    const severity = classifyEventSeverity({
      type: "c2:ability_executed",
      timestamp: Date.now(),
      summary: "Ability pending",
      data: { status: 1 },
    });
    expect(severity).toBe("info");
  });

  it("classifies operation_complete as success", () => {
    const severity = classifyEventSeverity({
      type: "c2:operation_complete",
      timestamp: Date.now(),
      summary: "Op done",
    });
    expect(severity).toBe("success");
  });

  it("returns correct icons for each event type", () => {
    expect(getEventIcon("c2:agent_checkin")).toBe("🟢");
    expect(getEventIcon("c2:agent_lost")).toBe("🔴");
    expect(getEventIcon("c2:ability_executed")).toBe("⚡");
    expect(getEventIcon("c2:operation_update")).toBe("📡");
    expect(getEventIcon("c2:operation_complete")).toBe("✅");
  });
});
