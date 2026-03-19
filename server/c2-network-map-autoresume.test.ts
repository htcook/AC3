/**
 * Tests for C2 Network Map topology builder and Auto-Resume detection
 */
import { describe, it, expect } from "vitest";

// ─── C2 Network Map Topology Builder ────────────────────────────────────────

describe("C2 Network Map — Topology Builder", () => {
  // Simulate the topology building logic from the C2NetworkMap component

  interface MapNode {
    id: string;
    label: string;
    type: "attacker" | "agent" | "target" | "pivot";
    x: number;
    y: number;
    status: "online" | "offline" | "lost" | "initial";
    platform?: string;
    paw?: string;
    ip?: string;
  }

  interface MapEdge {
    from: string;
    to: string;
    type: "initial_access" | "lateral_movement" | "c2_callback" | "pivot";
    label?: string;
    animated?: boolean;
  }

  function buildTopology(
    agents: { paw: string; host: string; platform: string; executors: string[]; group: string }[],
    assets: { ip: string; hostname: string; type: string }[],
    lostPaws: string[] = []
  ): { nodes: MapNode[]; edges: MapEdge[] } {
    const nodeMap = new Map<string, MapNode>();
    const edgeList: MapEdge[] = [];

    // Attacker node always present
    nodeMap.set("attacker", {
      id: "attacker",
      label: "Operator",
      type: "attacker",
      x: 80,
      y: 300,
      status: "initial",
      platform: "C2 Server",
    });

    // Add agents
    if (agents.length > 0) {
      const startY = Math.max(100, 300 - agents.length * 60);
      agents.forEach((agent, idx) => {
        const nodeId = `agent-${agent.paw}`;
        const yPos = startY + idx * 120;
        const xPos = 350 + (idx % 2 === 0 ? 0 : 60);
        nodeMap.set(nodeId, {
          id: nodeId,
          label: agent.host || agent.paw,
          type: "agent",
          x: xPos,
          y: yPos,
          status: lostPaws.includes(agent.paw) ? "lost" : "online",
          platform: agent.platform,
          paw: agent.paw,
          ip: agent.host,
        });
        edgeList.push({
          from: "attacker",
          to: nodeId,
          type: "c2_callback",
          label: "C2",
          animated: true,
        });
      });
    }

    // Add target assets (not already represented by agents)
    const existingHosts = new Set(Array.from(nodeMap.values()).map((n) => n.ip || n.label));
    const targetAssets = assets.filter((a) => !existingHosts.has(a.ip) && !existingHosts.has(a.hostname));
    const startY = Math.max(80, 300 - targetAssets.length * 40);
    targetAssets.slice(0, 8).forEach((asset, idx) => {
      const nodeId = `target-${asset.ip || asset.hostname}`;
      const yPos = startY + idx * 90;
      nodeMap.set(nodeId, {
        id: nodeId,
        label: asset.hostname || asset.ip,
        type: "target",
        x: 620 + (idx % 2 === 0 ? 0 : 50),
        y: yPos,
        status: "offline",
        platform: asset.type || "unknown",
        ip: asset.ip,
      });
    });

    // Lateral movement edges
    const agentNodes = Array.from(nodeMap.values()).filter((n) => n.type === "agent");
    const targetNodes = Array.from(nodeMap.values()).filter((n) => n.type === "target");
    if (agentNodes.length > 0 && targetNodes.length > 0) {
      edgeList.push({
        from: agentNodes[0].id,
        to: targetNodes[0].id,
        type: "lateral_movement",
        label: "Pivot",
        animated: true,
      });
      for (let i = 1; i < Math.min(agentNodes.length, targetNodes.length); i++) {
        edgeList.push({
          from: agentNodes[i].id,
          to: targetNodes[i].id,
          type: "lateral_movement",
          label: "Lateral",
        });
      }
    }

    // If no agents, show initial access from attacker to targets
    if (agents.length === 0 && targetNodes.length > 0) {
      targetNodes.slice(0, 3).forEach((t) => {
        edgeList.push({
          from: "attacker",
          to: t.id,
          type: "initial_access",
          label: "Scan",
        });
      });
    }

    return { nodes: Array.from(nodeMap.values()), edges: edgeList };
  }

  it("always includes the attacker node", () => {
    const { nodes } = buildTopology([], []);
    expect(nodes).toHaveLength(1);
    expect(nodes[0].id).toBe("attacker");
    expect(nodes[0].type).toBe("attacker");
    expect(nodes[0].label).toBe("Operator");
  });

  it("adds agent nodes with C2 callback edges", () => {
    const agents = [
      { paw: "abc123", host: "10.0.0.5", platform: "linux", executors: ["sh"], group: "red" },
    ];
    const { nodes, edges } = buildTopology(agents, []);
    expect(nodes).toHaveLength(2); // attacker + 1 agent
    const agentNode = nodes.find((n) => n.id === "agent-abc123");
    expect(agentNode).toBeDefined();
    expect(agentNode!.type).toBe("agent");
    expect(agentNode!.status).toBe("online");
    expect(agentNode!.ip).toBe("10.0.0.5");

    const c2Edge = edges.find((e) => e.type === "c2_callback");
    expect(c2Edge).toBeDefined();
    expect(c2Edge!.from).toBe("attacker");
    expect(c2Edge!.to).toBe("agent-abc123");
    expect(c2Edge!.animated).toBe(true);
  });

  it("marks lost agents correctly", () => {
    const agents = [
      { paw: "abc123", host: "10.0.0.5", platform: "linux", executors: ["sh"], group: "red" },
      { paw: "def456", host: "10.0.0.6", platform: "windows", executors: ["psh"], group: "red" },
    ];
    const { nodes } = buildTopology(agents, [], ["def456"]);
    const lostAgent = nodes.find((n) => n.id === "agent-def456");
    expect(lostAgent!.status).toBe("lost");
    const onlineAgent = nodes.find((n) => n.id === "agent-abc123");
    expect(onlineAgent!.status).toBe("online");
  });

  it("adds target nodes for assets not represented by agents", () => {
    const agents = [
      { paw: "abc123", host: "10.0.0.5", platform: "linux", executors: ["sh"], group: "red" },
    ];
    const assets = [
      { ip: "10.0.0.5", hostname: "compromised.local", type: "server" }, // same as agent
      { ip: "10.0.0.10", hostname: "target.local", type: "server" }, // new target
    ];
    const { nodes } = buildTopology(agents, assets);
    // attacker + 1 agent + 1 target (10.0.0.5 is deduplicated)
    expect(nodes).toHaveLength(3);
    const targetNode = nodes.find((n) => n.id === "target-10.0.0.10");
    expect(targetNode).toBeDefined();
    expect(targetNode!.type).toBe("target");
    expect(targetNode!.status).toBe("offline");
  });

  it("creates lateral movement edges between agents and targets", () => {
    const agents = [
      { paw: "abc123", host: "10.0.0.5", platform: "linux", executors: ["sh"], group: "red" },
    ];
    const assets = [
      { ip: "10.0.0.10", hostname: "target.local", type: "server" },
    ];
    const { edges } = buildTopology(agents, assets);
    const lateralEdge = edges.find((e) => e.type === "lateral_movement");
    expect(lateralEdge).toBeDefined();
    expect(lateralEdge!.from).toBe("agent-abc123");
    expect(lateralEdge!.to).toBe("target-10.0.0.10");
    expect(lateralEdge!.label).toBe("Pivot");
  });

  it("creates initial access edges when no agents exist", () => {
    const assets = [
      { ip: "10.0.0.10", hostname: "target1.local", type: "server" },
      { ip: "10.0.0.11", hostname: "target2.local", type: "server" },
    ];
    const { edges } = buildTopology([], assets);
    const initialEdges = edges.filter((e) => e.type === "initial_access");
    expect(initialEdges).toHaveLength(2);
    expect(initialEdges[0].from).toBe("attacker");
    expect(initialEdges[0].label).toBe("Scan");
  });

  it("limits target nodes to 8 maximum", () => {
    const assets = Array.from({ length: 15 }, (_, i) => ({
      ip: `10.0.0.${i + 10}`,
      hostname: `target${i}.local`,
      type: "server",
    }));
    const { nodes } = buildTopology([], assets);
    const targetNodes = nodes.filter((n) => n.type === "target");
    expect(targetNodes).toHaveLength(8);
  });

  it("creates multiple lateral movement edges for multiple agents and targets", () => {
    const agents = [
      { paw: "a1", host: "10.0.0.5", platform: "linux", executors: ["sh"], group: "red" },
      { paw: "a2", host: "10.0.0.6", platform: "windows", executors: ["psh"], group: "red" },
    ];
    const assets = [
      { ip: "10.0.0.20", hostname: "t1.local", type: "server" },
      { ip: "10.0.0.21", hostname: "t2.local", type: "server" },
    ];
    const { edges } = buildTopology(agents, assets);
    const lateralEdges = edges.filter((e) => e.type === "lateral_movement");
    expect(lateralEdges).toHaveLength(2);
    expect(lateralEdges[0].label).toBe("Pivot"); // first is always Pivot
    expect(lateralEdges[1].label).toBe("Lateral"); // subsequent are Lateral
  });

  it("assigns correct positions to nodes", () => {
    const agents = [
      { paw: "a1", host: "10.0.0.5", platform: "linux", executors: ["sh"], group: "red" },
    ];
    const { nodes } = buildTopology(agents, []);
    const attacker = nodes.find((n) => n.id === "attacker")!;
    const agent = nodes.find((n) => n.id === "agent-a1")!;
    expect(attacker.x).toBe(80); // leftmost
    expect(agent.x).toBeGreaterThan(attacker.x); // agents are to the right
  });
});

// ─── Auto-Resume Detection Logic ────────────────────────────────────────────

describe("Auto-Resume — Interrupted Engagement Detection", () => {
  const PHASE_ORDER = ["recon", "enumeration", "vuln_detection", "exploitation", "post_exploit"];

  function detectResumability(snapshot: {
    phase: string;
    assetsCount: number;
    isRunning: boolean;
    progress: number;
  }): { canResume: boolean; reason: string } {
    if (!snapshot.isRunning && snapshot.progress === 0) {
      return { canResume: false, reason: "No progress made" };
    }
    if (snapshot.assetsCount === 0) {
      return { canResume: false, reason: "No assets discovered" };
    }
    if (!PHASE_ORDER.includes(snapshot.phase)) {
      return { canResume: false, reason: `Unknown phase: ${snapshot.phase}` };
    }
    return { canResume: true, reason: "Resumable" };
  }

  function getNextPhase(currentPhase: string): string | null {
    const idx = PHASE_ORDER.indexOf(currentPhase);
    if (idx === -1 || idx >= PHASE_ORDER.length - 1) return null;
    return PHASE_ORDER[idx + 1];
  }

  it("detects resumable engagement with assets and valid phase", () => {
    const result = detectResumability({
      phase: "enumeration",
      assetsCount: 5,
      isRunning: true,
      progress: 35,
    });
    expect(result.canResume).toBe(true);
  });

  it("rejects engagement with no progress", () => {
    const result = detectResumability({
      phase: "recon",
      assetsCount: 0,
      isRunning: false,
      progress: 0,
    });
    expect(result.canResume).toBe(false);
    expect(result.reason).toContain("No progress");
  });

  it("rejects engagement with no assets", () => {
    const result = detectResumability({
      phase: "enumeration",
      assetsCount: 0,
      isRunning: true,
      progress: 20,
    });
    expect(result.canResume).toBe(false);
    expect(result.reason).toContain("No assets");
  });

  it("rejects engagement with unknown phase", () => {
    const result = detectResumability({
      phase: "completed",
      assetsCount: 5,
      isRunning: false,
      progress: 100,
    });
    expect(result.canResume).toBe(false);
    expect(result.reason).toContain("Unknown phase");
  });

  it("correctly identifies next phase for resume", () => {
    expect(getNextPhase("recon")).toBe("enumeration");
    expect(getNextPhase("enumeration")).toBe("vuln_detection");
    expect(getNextPhase("vuln_detection")).toBe("exploitation");
    expect(getNextPhase("exploitation")).toBe("post_exploit");
    expect(getNextPhase("post_exploit")).toBeNull(); // last phase
  });

  it("returns null for unknown phase", () => {
    expect(getNextPhase("completed")).toBeNull();
    expect(getNextPhase("idle")).toBeNull();
  });

  it("detects all valid phases as resumable", () => {
    for (const phase of PHASE_ORDER) {
      const result = detectResumability({
        phase,
        assetsCount: 3,
        isRunning: true,
        progress: 50,
      });
      expect(result.canResume).toBe(true);
    }
  });
});

// ─── Edge Color Classification ──────────────────────────────────────────────

describe("C2 Network Map — Edge Color Classification", () => {
  function getEdgeColor(type: string): string {
    switch (type) {
      case "c2_callback": return "#f97316"; // orange
      case "lateral_movement": return "#ef4444"; // red
      case "initial_access": return "#22d3ee"; // cyan
      case "pivot": return "#a855f7"; // purple
      default: return "#6b7280"; // gray
    }
  }

  it("assigns orange to C2 callbacks", () => {
    expect(getEdgeColor("c2_callback")).toBe("#f97316");
  });

  it("assigns red to lateral movement", () => {
    expect(getEdgeColor("lateral_movement")).toBe("#ef4444");
  });

  it("assigns cyan to initial access", () => {
    expect(getEdgeColor("initial_access")).toBe("#22d3ee");
  });

  it("assigns purple to pivot", () => {
    expect(getEdgeColor("pivot")).toBe("#a855f7");
  });

  it("assigns gray to unknown types", () => {
    expect(getEdgeColor("unknown")).toBe("#6b7280");
  });
});

// ─── Node Status Classification ─────────────────────────────────────────────

describe("C2 Network Map — Node Status Classification", () => {
  function getNodeColor(type: string, status: string): string {
    if (status === "lost") return "#ef4444";
    switch (type) {
      case "attacker": return "#f97316";
      case "agent": return "#22c55e";
      case "target": return "#6b7280";
      case "pivot": return "#a855f7";
      default: return "#6b7280";
    }
  }

  it("lost agents are always red regardless of type", () => {
    expect(getNodeColor("agent", "lost")).toBe("#ef4444");
    expect(getNodeColor("target", "lost")).toBe("#ef4444");
  });

  it("attacker nodes are orange", () => {
    expect(getNodeColor("attacker", "initial")).toBe("#f97316");
  });

  it("online agents are green", () => {
    expect(getNodeColor("agent", "online")).toBe("#22c55e");
  });

  it("targets are gray", () => {
    expect(getNodeColor("target", "offline")).toBe("#6b7280");
  });
});

// ─── InterruptedEngagement Type Validation ──────────────────────────────────

describe("Auto-Resume — InterruptedEngagement shape", () => {
  interface InterruptedEngagement {
    engagementId: number;
    phase: string;
    progress: number;
    assetsCount: number;
    vulnsFound: number;
    portsFound: number;
    lastUpdated: string;
    canResume: boolean;
  }

  function createInterruptedEngagement(overrides: Partial<InterruptedEngagement> = {}): InterruptedEngagement {
    return {
      engagementId: 1770040,
      phase: "vuln_detection",
      progress: 55,
      assetsCount: 3,
      vulnsFound: 22,
      portsFound: 10,
      lastUpdated: "2026-03-18 22:50:39",
      canResume: true,
      ...overrides,
    };
  }

  it("creates valid interrupted engagement with defaults", () => {
    const eng = createInterruptedEngagement();
    expect(eng.engagementId).toBe(1770040);
    expect(eng.canResume).toBe(true);
    expect(eng.phase).toBe("vuln_detection");
  });

  it("allows overriding fields", () => {
    const eng = createInterruptedEngagement({ canResume: false, phase: "recon" });
    expect(eng.canResume).toBe(false);
    expect(eng.phase).toBe("recon");
  });

  it("preserves all required fields", () => {
    const eng = createInterruptedEngagement();
    const keys = Object.keys(eng);
    expect(keys).toContain("engagementId");
    expect(keys).toContain("phase");
    expect(keys).toContain("progress");
    expect(keys).toContain("assetsCount");
    expect(keys).toContain("vulnsFound");
    expect(keys).toContain("portsFound");
    expect(keys).toContain("lastUpdated");
    expect(keys).toContain("canResume");
  });
});
