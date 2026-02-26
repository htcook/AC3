/**
 * Ability Graph Engine — Unit Tests
 *
 * Tests cover:
 * - DAG operations (adjacency list, cycle detection, topological sort, layer assignment)
 * - Precondition evaluation (all types and operators)
 * - Exit criteria evaluation
 * - Safety tier gating
 * - Edge condition evaluation
 * - Graph walk / execution simulation
 */
import { describe, expect, it } from "vitest";
import {
  buildAdjacencyList,
  buildReverseAdjacencyList,
  detectCycle,
  topologicalSort,
  assignLayers,
  evaluatePrecondition,
  evaluateNodePreconditions,
  evaluateExitCriteria,
  isNodeAllowedBySafetyTier,
  filterNodesBySafetyTier,
  computeGraphSafetyTier,
  shouldFollowEdge,
  walkGraph,
  type AbilityNodeData,
  type AbilityEdgeData,
  type EnvironmentContext,
  type Precondition,
  type ExitCriteria,
  type SafetyTier,
  type NodeStatus,
  type EdgeCondition,
} from "./ability-graph-engine";

// ─── Test Fixtures ────────────────────────────────────────────────────

function makeNode(overrides: Partial<AbilityNodeData> & { id: string }): AbilityNodeData {
  return {
    graphId: "test-graph",
    label: `Node ${overrides.id}`,
    description: "",
    techniqueId: "T1059.001",
    techniqueName: "PowerShell",
    tactic: "execution",
    preconditions: [],
    exitCriteria: [],
    safetyTier: "medium_impact",
    timeout: 300,
    retryCount: 1,
    status: "pending",
    order: 0,
    layer: 0,
    ...overrides,
  };
}

function makeEdge(
  source: string,
  target: string,
  overrides: Partial<AbilityEdgeData> = {},
): AbilityEdgeData {
  return {
    id: `edge-${source}-${target}`,
    graphId: "test-graph",
    sourceNodeId: source,
    targetNodeId: target,
    condition: "on_success",
    weight: 1,
    ...overrides,
  };
}

function makeEnv(overrides: Partial<EnvironmentContext> = {}): EnvironmentContext {
  return {
    os: "windows",
    osVersion: "10.0.19041",
    hostname: "WORKSTATION-01",
    privilegeLevel: "user",
    networkAccess: "internal",
    installedSoftware: ["powershell", "cmd", "python3"],
    runningServices: ["sshd", "winrm"],
    openPorts: [22, 80, 443, 5985],
    registryKeys: ["HKLM\\SOFTWARE\\Microsoft\\Windows"],
    files: ["/etc/passwd", "C:\\Windows\\System32\\cmd.exe"],
    customFacts: { domain_joined: true, av_installed: "defender" },
    ...overrides,
  };
}

// ─── DAG Operations ───────────────────────────────────────────────────

describe("buildAdjacencyList", () => {
  it("builds adjacency list from edges", () => {
    const edges = [
      makeEdge("A", "B"),
      makeEdge("A", "C"),
      makeEdge("B", "D"),
    ];
    const adj = buildAdjacencyList(edges);
    expect(adj.get("A")?.length).toBe(2);
    expect(adj.get("B")?.length).toBe(1);
    expect(adj.has("C")).toBe(false);
    expect(adj.has("D")).toBe(false);
  });

  it("handles empty edges", () => {
    const adj = buildAdjacencyList([]);
    expect(adj.size).toBe(0);
  });
});

describe("buildReverseAdjacencyList", () => {
  it("builds reverse adjacency list (incoming edges)", () => {
    const edges = [
      makeEdge("A", "B"),
      makeEdge("A", "C"),
      makeEdge("B", "C"),
    ];
    const rev = buildReverseAdjacencyList(edges);
    expect(rev.has("A")).toBe(false);
    expect(rev.get("B")?.length).toBe(1);
    expect(rev.get("C")?.length).toBe(2);
  });
});

describe("detectCycle", () => {
  it("returns null for acyclic graph", () => {
    const nodes = [makeNode({ id: "A" }), makeNode({ id: "B" }), makeNode({ id: "C" })];
    const edges = [makeEdge("A", "B"), makeEdge("B", "C")];
    expect(detectCycle(nodes, edges)).toBeNull();
  });

  it("detects a simple cycle", () => {
    const nodes = [makeNode({ id: "A" }), makeNode({ id: "B" }), makeNode({ id: "C" })];
    const edges = [makeEdge("A", "B"), makeEdge("B", "C"), makeEdge("C", "A")];
    const cycle = detectCycle(nodes, edges);
    expect(cycle).not.toBeNull();
    expect(cycle!.length).toBeGreaterThanOrEqual(2);
  });

  it("detects a self-loop", () => {
    const nodes = [makeNode({ id: "A" })];
    const edges = [makeEdge("A", "A")];
    const cycle = detectCycle(nodes, edges);
    expect(cycle).not.toBeNull();
  });

  it("handles disconnected components", () => {
    const nodes = [
      makeNode({ id: "A" }),
      makeNode({ id: "B" }),
      makeNode({ id: "C" }),
      makeNode({ id: "D" }),
    ];
    const edges = [makeEdge("A", "B"), makeEdge("C", "D")];
    expect(detectCycle(nodes, edges)).toBeNull();
  });

  it("handles single node with no edges", () => {
    const nodes = [makeNode({ id: "A" })];
    expect(detectCycle(nodes, [])).toBeNull();
  });
});

describe("topologicalSort", () => {
  it("sorts a linear chain correctly", () => {
    const nodes = [makeNode({ id: "C" }), makeNode({ id: "A" }), makeNode({ id: "B" })];
    const edges = [makeEdge("A", "B"), makeEdge("B", "C")];
    const sorted = topologicalSort(nodes, edges);
    const ids = sorted.map(n => n.id);
    expect(ids.indexOf("A")).toBeLessThan(ids.indexOf("B"));
    expect(ids.indexOf("B")).toBeLessThan(ids.indexOf("C"));
  });

  it("sorts a diamond DAG correctly", () => {
    const nodes = [
      makeNode({ id: "A" }),
      makeNode({ id: "B" }),
      makeNode({ id: "C" }),
      makeNode({ id: "D" }),
    ];
    const edges = [
      makeEdge("A", "B"),
      makeEdge("A", "C"),
      makeEdge("B", "D"),
      makeEdge("C", "D"),
    ];
    const sorted = topologicalSort(nodes, edges);
    const ids = sorted.map(n => n.id);
    expect(ids.indexOf("A")).toBeLessThan(ids.indexOf("B"));
    expect(ids.indexOf("A")).toBeLessThan(ids.indexOf("C"));
    expect(ids.indexOf("B")).toBeLessThan(ids.indexOf("D"));
    expect(ids.indexOf("C")).toBeLessThan(ids.indexOf("D"));
  });

  it("throws on cyclic graph", () => {
    const nodes = [makeNode({ id: "A" }), makeNode({ id: "B" })];
    const edges = [makeEdge("A", "B"), makeEdge("B", "A")];
    expect(() => topologicalSort(nodes, edges)).toThrow(/cycle/i);
  });

  it("assigns order indices", () => {
    const nodes = [makeNode({ id: "A" }), makeNode({ id: "B" }), makeNode({ id: "C" })];
    const edges = [makeEdge("A", "B"), makeEdge("B", "C")];
    const sorted = topologicalSort(nodes, edges);
    expect(sorted[0].order).toBe(0);
    expect(sorted[1].order).toBe(1);
    expect(sorted[2].order).toBe(2);
  });

  it("prioritizes passive safety tier nodes first", () => {
    const nodes = [
      makeNode({ id: "A", safetyTier: "high_impact" }),
      makeNode({ id: "B", safetyTier: "passive" }),
    ];
    // No edges — both are root nodes
    const sorted = topologicalSort(nodes, []);
    expect(sorted[0].id).toBe("B"); // passive first
    expect(sorted[1].id).toBe("A"); // high_impact second
  });
});

describe("assignLayers", () => {
  it("assigns layers based on depth from root", () => {
    const nodes = [
      makeNode({ id: "A" }),
      makeNode({ id: "B" }),
      makeNode({ id: "C" }),
      makeNode({ id: "D" }),
    ];
    const edges = [
      makeEdge("A", "B"),
      makeEdge("A", "C"),
      makeEdge("B", "D"),
      makeEdge("C", "D"),
    ];
    assignLayers(nodes, edges);
    const nodeMap = new Map(nodes.map(n => [n.id, n]));
    expect(nodeMap.get("A")!.layer).toBe(0);
    expect(nodeMap.get("B")!.layer).toBe(1);
    expect(nodeMap.get("C")!.layer).toBe(1);
    expect(nodeMap.get("D")!.layer).toBe(2);
  });

  it("handles single node", () => {
    const nodes = [makeNode({ id: "A" })];
    assignLayers(nodes, []);
    expect(nodes[0].layer).toBe(0);
  });

  it("handles multiple root nodes", () => {
    const nodes = [
      makeNode({ id: "A" }),
      makeNode({ id: "B" }),
      makeNode({ id: "C" }),
    ];
    const edges = [makeEdge("A", "C"), makeEdge("B", "C")];
    assignLayers(nodes, edges);
    const nodeMap = new Map(nodes.map(n => [n.id, n]));
    expect(nodeMap.get("A")!.layer).toBe(0);
    expect(nodeMap.get("B")!.layer).toBe(0);
    expect(nodeMap.get("C")!.layer).toBe(1);
  });
});

// ─── Precondition Evaluation ──────────────────────────────────────────

describe("evaluatePrecondition", () => {
  const env = makeEnv();

  it("evaluates OS family equality", () => {
    const pre: Precondition = {
      type: "os",
      key: "os_family",
      operator: "eq",
      value: "windows",
      description: "Requires Windows",
      required: true,
    };
    expect(evaluatePrecondition(pre, env)).toBe(true);
    expect(evaluatePrecondition(pre, makeEnv({ os: "linux" }))).toBe(false);
  });

  it("evaluates OS version", () => {
    const pre: Precondition = {
      type: "os",
      key: "os_version",
      operator: "contains",
      value: "19041",
      description: "Requires build 19041",
      required: true,
    };
    expect(evaluatePrecondition(pre, env)).toBe(true);
  });

  it("evaluates privilege level equality", () => {
    const pre: Precondition = {
      type: "privilege",
      key: "privilege_level",
      operator: "eq",
      value: "local_admin",
      description: "Requires local admin",
      required: true,
    };
    expect(evaluatePrecondition(pre, env)).toBe(false);
    expect(evaluatePrecondition(pre, makeEnv({ privilegeLevel: "local_admin" }))).toBe(true);
  });

  it("evaluates privilege level with 'in' operator", () => {
    const pre: Precondition = {
      type: "privilege",
      key: "privilege_level",
      operator: "in",
      value: ["local_admin", "domain_admin", "system"],
      description: "Requires elevated privileges",
      required: true,
    };
    expect(evaluatePrecondition(pre, env)).toBe(false);
    expect(evaluatePrecondition(pre, makeEnv({ privilegeLevel: "domain_admin" }))).toBe(true);
  });

  it("evaluates network access", () => {
    const pre: Precondition = {
      type: "network",
      key: "network_access",
      operator: "eq",
      value: "external",
      description: "Requires external access",
      required: true,
    };
    expect(evaluatePrecondition(pre, env)).toBe(false);
    expect(evaluatePrecondition(pre, makeEnv({ networkAccess: "external" }))).toBe(true);
  });

  it("evaluates software contains", () => {
    const pre: Precondition = {
      type: "software",
      key: "installed",
      operator: "contains",
      value: "powershell",
      description: "Requires PowerShell",
      required: true,
    };
    expect(evaluatePrecondition(pre, env)).toBe(true);
  });

  it("evaluates service exists", () => {
    const pre: Precondition = {
      type: "service",
      key: "running",
      operator: "contains",
      value: "sshd",
      description: "Requires SSH",
      required: true,
    };
    expect(evaluatePrecondition(pre, env)).toBe(true);
    expect(evaluatePrecondition(pre, makeEnv({ runningServices: ["httpd"] }))).toBe(false);
  });

  it("evaluates file exists", () => {
    const pre: Precondition = {
      type: "file",
      key: "path",
      operator: "contains",
      value: "cmd.exe",
      description: "Requires cmd.exe",
      required: true,
    };
    expect(evaluatePrecondition(pre, env)).toBe(true);
  });

  it("evaluates custom facts", () => {
    const pre: Precondition = {
      type: "custom",
      key: "domain_joined",
      operator: "eq",
      value: "true",
      description: "Must be domain joined",
      required: true,
    };
    expect(evaluatePrecondition(pre, env)).toBe(true);
  });

  it("evaluates neq operator", () => {
    const pre: Precondition = {
      type: "os",
      key: "os_family",
      operator: "neq",
      value: "linux",
      description: "Not Linux",
      required: true,
    };
    expect(evaluatePrecondition(pre, env)).toBe(true);
  });

  it("evaluates regex operator", () => {
    const pre: Precondition = {
      type: "os",
      key: "os_version",
      operator: "regex",
      value: "^10\\.0",
      description: "Windows 10",
      required: true,
    };
    expect(evaluatePrecondition(pre, env)).toBe(true);
  });

  it("returns true for non-required undefined values", () => {
    const pre: Precondition = {
      type: "custom",
      key: "nonexistent_key",
      operator: "eq",
      value: "anything",
      description: "Optional check",
      required: false,
    };
    expect(evaluatePrecondition(pre, env)).toBe(true);
  });

  it("returns false for required undefined values", () => {
    const pre: Precondition = {
      type: "custom",
      key: "nonexistent_key",
      operator: "eq",
      value: "anything",
      description: "Required check",
      required: true,
    };
    expect(evaluatePrecondition(pre, env)).toBe(false);
  });
});

describe("evaluateNodePreconditions", () => {
  const env = makeEnv();

  it("returns met=true when all required preconditions pass", () => {
    const node = makeNode({
      id: "A",
      preconditions: [
        { type: "os", key: "os_family", operator: "eq", value: "windows", description: "Windows", required: true },
        { type: "privilege", key: "level", operator: "eq", value: "user", description: "User", required: true },
      ],
    });
    const result = evaluateNodePreconditions(node, env);
    expect(result.met).toBe(true);
    expect(result.unmet.length).toBe(0);
  });

  it("returns met=false when required precondition fails", () => {
    const node = makeNode({
      id: "A",
      preconditions: [
        { type: "privilege", key: "level", operator: "eq", value: "root", description: "Root", required: true },
      ],
    });
    const result = evaluateNodePreconditions(node, env);
    expect(result.met).toBe(false);
    expect(result.unmet.length).toBe(1);
  });

  it("returns met=true when only optional preconditions fail", () => {
    const node = makeNode({
      id: "A",
      preconditions: [
        { type: "os", key: "os_family", operator: "eq", value: "windows", description: "Windows", required: true },
        { type: "custom", key: "av_installed", operator: "eq", value: "crowdstrike", description: "Optional AV check", required: false },
      ],
    });
    const result = evaluateNodePreconditions(node, env);
    expect(result.met).toBe(true);
    expect(result.unmet.length).toBe(1); // optional still reported as unmet
  });

  it("returns met=true for node with no preconditions", () => {
    const node = makeNode({ id: "A", preconditions: [] });
    const result = evaluateNodePreconditions(node, env);
    expect(result.met).toBe(true);
    expect(result.unmet.length).toBe(0);
  });
});

// ─── Exit Criteria Evaluation ─────────────────────────────────────────

describe("evaluateExitCriteria", () => {
  it("evaluates exit code equality", () => {
    const criteria: ExitCriteria = {
      type: "exit_code",
      key: "code",
      operator: "eq",
      value: 0,
      description: "Success",
    };
    expect(evaluateExitCriteria(criteria, { exitCode: 0, stdout: "", stderr: "" })).toBe(true);
    expect(evaluateExitCriteria(criteria, { exitCode: 1, stdout: "", stderr: "" })).toBe(false);
  });

  it("evaluates output contains", () => {
    const criteria: ExitCriteria = {
      type: "output_contains",
      key: "output",
      operator: "contains",
      value: "success",
      description: "Output contains success",
    };
    expect(evaluateExitCriteria(criteria, { exitCode: 0, stdout: "Operation success!", stderr: "" })).toBe(true);
    expect(evaluateExitCriteria(criteria, { exitCode: 0, stdout: "failed", stderr: "" })).toBe(false);
  });

  it("evaluates output with regex", () => {
    const criteria: ExitCriteria = {
      type: "output_contains",
      key: "output",
      operator: "regex",
      value: "\\d+ files? found",
      description: "Files found",
    };
    expect(evaluateExitCriteria(criteria, { exitCode: 0, stdout: "3 files found", stderr: "" })).toBe(true);
    expect(evaluateExitCriteria(criteria, { exitCode: 0, stdout: "no results", stderr: "" })).toBe(false);
  });

  it("evaluates exit code gt", () => {
    const criteria: ExitCriteria = {
      type: "exit_code",
      key: "code",
      operator: "gt",
      value: 0,
      description: "Non-zero exit",
    };
    expect(evaluateExitCriteria(criteria, { exitCode: 1, stdout: "", stderr: "" })).toBe(true);
    expect(evaluateExitCriteria(criteria, { exitCode: 0, stdout: "", stderr: "" })).toBe(false);
  });

  it("returns true for file_exists type (optimistic)", () => {
    const criteria: ExitCriteria = {
      type: "file_exists",
      key: "path",
      operator: "eq",
      value: "/tmp/payload",
      description: "Payload dropped",
    };
    expect(evaluateExitCriteria(criteria, { exitCode: 0, stdout: "", stderr: "" })).toBe(true);
  });
});

// ─── Safety Tier Gating ───────────────────────────────────────────────

describe("isNodeAllowedBySafetyTier", () => {
  it("allows passive nodes in passive mode", () => {
    const node = makeNode({ id: "A", safetyTier: "passive" });
    expect(isNodeAllowedBySafetyTier(node, "passive")).toBe(true);
  });

  it("blocks medium_impact nodes in passive mode", () => {
    const node = makeNode({ id: "A", safetyTier: "medium_impact" });
    expect(isNodeAllowedBySafetyTier(node, "passive")).toBe(false);
  });

  it("allows medium_impact nodes in active-standard mode", () => {
    const node = makeNode({ id: "A", safetyTier: "medium_impact" });
    expect(isNodeAllowedBySafetyTier(node, "active-standard")).toBe(true);
  });

  it("allows high_impact nodes in active-aggressive mode", () => {
    const node = makeNode({ id: "A", safetyTier: "high_impact" });
    expect(isNodeAllowedBySafetyTier(node, "active-aggressive")).toBe(true);
  });

  it("blocks high_impact nodes in active-standard mode", () => {
    const node = makeNode({ id: "A", safetyTier: "high_impact" });
    expect(isNodeAllowedBySafetyTier(node, "active-standard")).toBe(false);
  });

  it("allows low_impact in active-low mode", () => {
    const node = makeNode({ id: "A", safetyTier: "low_impact" });
    expect(isNodeAllowedBySafetyTier(node, "active-low")).toBe(true);
  });
});

describe("filterNodesBySafetyTier", () => {
  it("splits nodes into allowed and blocked", () => {
    const nodes = [
      makeNode({ id: "A", safetyTier: "passive" }),
      makeNode({ id: "B", safetyTier: "medium_impact" }),
      makeNode({ id: "C", safetyTier: "high_impact" }),
    ];
    const { allowed, blocked } = filterNodesBySafetyTier(nodes, "active-standard");
    expect(allowed.length).toBe(2);
    expect(blocked.length).toBe(1);
    expect(blocked[0].id).toBe("C");
    expect(blocked[0].status).toBe("blocked");
  });

  it("allows all nodes in aggressive mode", () => {
    const nodes = [
      makeNode({ id: "A", safetyTier: "passive" }),
      makeNode({ id: "B", safetyTier: "critical_impact" }),
    ];
    const { allowed, blocked } = filterNodesBySafetyTier(nodes, "active-aggressive");
    expect(allowed.length).toBe(2);
    expect(blocked.length).toBe(0);
  });

  it("blocks all non-passive in passive mode", () => {
    const nodes = [
      makeNode({ id: "A", safetyTier: "passive" }),
      makeNode({ id: "B", safetyTier: "low_impact" }),
      makeNode({ id: "C", safetyTier: "medium_impact" }),
    ];
    const { allowed, blocked } = filterNodesBySafetyTier(nodes, "passive");
    expect(allowed.length).toBe(1);
    expect(blocked.length).toBe(2);
  });
});

describe("computeGraphSafetyTier", () => {
  it("returns the highest safety tier across nodes", () => {
    const nodes = [
      makeNode({ id: "A", safetyTier: "passive" }),
      makeNode({ id: "B", safetyTier: "medium_impact" }),
      makeNode({ id: "C", safetyTier: "high_impact" }),
    ];
    expect(computeGraphSafetyTier(nodes)).toBe("high_impact");
  });

  it("returns passive for all-passive graph", () => {
    const nodes = [
      makeNode({ id: "A", safetyTier: "passive" }),
      makeNode({ id: "B", safetyTier: "passive" }),
    ];
    expect(computeGraphSafetyTier(nodes)).toBe("passive");
  });

  it("returns critical_impact when present", () => {
    const nodes = [
      makeNode({ id: "A", safetyTier: "low_impact" }),
      makeNode({ id: "B", safetyTier: "critical_impact" }),
    ];
    expect(computeGraphSafetyTier(nodes)).toBe("critical_impact");
  });
});

// ─── Edge Condition Evaluation ────────────────────────────────────────

describe("shouldFollowEdge", () => {
  const successResult = { exitCode: 0, stdout: "done", stderr: "" };
  const failResult = { exitCode: 1, stdout: "", stderr: "error" };

  it("follows 'always' edge on success", () => {
    const edge = makeEdge("A", "B", { condition: "always" });
    expect(shouldFollowEdge(edge, successResult, "success")).toBe(true);
  });

  it("follows 'always' edge on failure", () => {
    const edge = makeEdge("A", "B", { condition: "always" });
    expect(shouldFollowEdge(edge, failResult, "failed")).toBe(true);
  });

  it("does not follow 'always' edge on pending", () => {
    const edge = makeEdge("A", "B", { condition: "always" });
    expect(shouldFollowEdge(edge, null, "pending")).toBe(false);
  });

  it("follows 'on_success' edge only on success", () => {
    const edge = makeEdge("A", "B", { condition: "on_success" });
    expect(shouldFollowEdge(edge, successResult, "success")).toBe(true);
    expect(shouldFollowEdge(edge, failResult, "failed")).toBe(false);
  });

  it("follows 'on_failure' edge only on failure", () => {
    const edge = makeEdge("A", "B", { condition: "on_failure" });
    expect(shouldFollowEdge(edge, failResult, "failed")).toBe(true);
    expect(shouldFollowEdge(edge, successResult, "success")).toBe(false);
  });

  it("follows 'on_output_match' when pattern matches stdout", () => {
    const edge = makeEdge("A", "B", {
      condition: "on_output_match",
      outputMatchPattern: "done",
    });
    expect(shouldFollowEdge(edge, successResult, "success")).toBe(true);
  });

  it("does not follow 'on_output_match' when pattern doesn't match", () => {
    const edge = makeEdge("A", "B", {
      condition: "on_output_match",
      outputMatchPattern: "secret_found",
    });
    expect(shouldFollowEdge(edge, successResult, "success")).toBe(false);
  });

  it("does not follow 'on_output_match' without result", () => {
    const edge = makeEdge("A", "B", {
      condition: "on_output_match",
      outputMatchPattern: "test",
    });
    expect(shouldFollowEdge(edge, null, "success")).toBe(false);
  });

  it("follows 'on_precondition' when target preconditions are met", () => {
    const env = makeEnv();
    const targetNode = makeNode({
      id: "B",
      preconditions: [
        { type: "os", key: "os_family", operator: "eq", value: "windows", description: "Windows", required: true },
      ],
    });
    const edge = makeEdge("A", "B", { condition: "on_precondition" });
    expect(shouldFollowEdge(edge, successResult, "success", env, targetNode)).toBe(true);
  });

  it("does not follow 'on_precondition' when target preconditions fail", () => {
    const env = makeEnv({ os: "linux" });
    const targetNode = makeNode({
      id: "B",
      preconditions: [
        { type: "os", key: "os_family", operator: "eq", value: "windows", description: "Windows", required: true },
      ],
    });
    const edge = makeEdge("A", "B", { condition: "on_precondition" });
    expect(shouldFollowEdge(edge, successResult, "success", env, targetNode)).toBe(false);
  });

  it("follows 'on_precondition' optimistically without env", () => {
    const edge = makeEdge("A", "B", { condition: "on_precondition" });
    expect(shouldFollowEdge(edge, successResult, "success")).toBe(true);
  });
});

// ─── Graph Walk (Execution Simulation) ────────────────────────────────

describe("walkGraph", () => {
  const env = makeEnv();

  it("walks a simple linear graph", () => {
    const nodes = [
      makeNode({ id: "A", safetyTier: "passive" }),
      makeNode({ id: "B", safetyTier: "low_impact" }),
      makeNode({ id: "C", safetyTier: "medium_impact" }),
    ];
    const edges = [makeEdge("A", "B"), makeEdge("B", "C")];
    const result = walkGraph(nodes, edges, env, "active-standard");
    expect(result.completedNodes.length).toBe(3);
    expect(result.blockedNodes.length).toBe(0);
    expect(result.skippedNodes.length).toBe(0);
    expect(result.totalSteps).toBe(3);
  });

  it("blocks nodes exceeding safety tier", () => {
    const nodes = [
      makeNode({ id: "A", safetyTier: "passive" }),
      makeNode({ id: "B", safetyTier: "high_impact" }),
    ];
    const edges = [makeEdge("A", "B")];
    const result = walkGraph(nodes, edges, env, "active-standard");
    expect(result.completedNodes).toContain("A");
    expect(result.blockedNodes).toContain("B");
    expect(result.safetyViolations.length).toBeGreaterThan(0);
  });

  it("skips nodes with failed preconditions", () => {
    const nodes = [
      makeNode({ id: "A", safetyTier: "passive" }),
      makeNode({
        id: "B",
        safetyTier: "passive",
        preconditions: [
          { type: "os", key: "os_family", operator: "eq", value: "linux", description: "Linux only", required: true },
        ],
      }),
    ];
    const edges = [makeEdge("A", "B")];
    const result = walkGraph(nodes, edges, env, "active-standard");
    expect(result.completedNodes).toContain("A");
    expect(result.skippedNodes).toContain("B");
  });

  it("propagates skip when all sources are blocked", () => {
    const nodes = [
      makeNode({ id: "A", safetyTier: "critical_impact" }),
      makeNode({ id: "B", safetyTier: "passive" }),
    ];
    const edges = [makeEdge("A", "B")];
    const result = walkGraph(nodes, edges, env, "passive");
    expect(result.blockedNodes).toContain("A");
    expect(result.skippedNodes).toContain("B");
  });

  it("handles diamond DAG correctly", () => {
    const nodes = [
      makeNode({ id: "A", safetyTier: "passive" }),
      makeNode({ id: "B", safetyTier: "low_impact" }),
      makeNode({ id: "C", safetyTier: "low_impact" }),
      makeNode({ id: "D", safetyTier: "medium_impact" }),
    ];
    const edges = [
      makeEdge("A", "B"),
      makeEdge("A", "C"),
      makeEdge("B", "D"),
      makeEdge("C", "D"),
    ];
    const result = walkGraph(nodes, edges, env, "active-standard");
    expect(result.completedNodes.length).toBe(4);
    expect(result.totalSteps).toBe(4);
  });

  it("handles graph with no edges (independent nodes)", () => {
    const nodes = [
      makeNode({ id: "A", safetyTier: "passive" }),
      makeNode({ id: "B", safetyTier: "passive" }),
    ];
    const result = walkGraph(nodes, [], env, "active-standard");
    expect(result.completedNodes.length).toBe(2);
  });

  it("reports cycle as safety violation", () => {
    const nodes = [makeNode({ id: "A" }), makeNode({ id: "B" })];
    const edges = [makeEdge("A", "B"), makeEdge("B", "A")];
    const result = walkGraph(nodes, edges, env, "active-standard");
    expect(result.safetyViolations.length).toBeGreaterThan(0);
    expect(result.safetyViolations[0]).toContain("cycle");
  });

  it("handles mixed safety tiers in aggressive mode", () => {
    const nodes = [
      makeNode({ id: "A", safetyTier: "passive" }),
      makeNode({ id: "B", safetyTier: "high_impact" }),
      makeNode({ id: "C", safetyTier: "critical_impact" }),
    ];
    const edges = [makeEdge("A", "B"), makeEdge("B", "C")];
    const result = walkGraph(nodes, edges, env, "active-aggressive");
    expect(result.completedNodes.length).toBe(3);
    expect(result.blockedNodes.length).toBe(0);
  });
});
