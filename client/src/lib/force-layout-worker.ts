/**
 * D3-Force Layout WebWorker
 * ═══════════════════════════════════════════════════════════════════════
 * Runs the d3-force simulation off the main thread so the Canvas render
 * loop never stalls while the physics engine is computing positions.
 *
 * Protocol:
 *   Main → Worker:
 *     { type: "init", nodes, edges, config }   — bootstrap simulation
 *     { type: "addNodes", nodes, edges }        — incremental add
 *     { type: "reheat", alpha }                 — restart with alpha
 *     { type: "pinNode", id, x, y }             — fix node position (drag)
 *     { type: "unpinNode", id }                 — release node
 *     { type: "stop" }                          — stop simulation
 *
 *   Worker → Main:
 *     { type: "tick", positions, alpha }         — position update batch
 *     { type: "settled" }                        — alpha < min, simulation done
 */

import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  forceCollide,
  forceX,
  forceY,
  type Simulation,
  type SimulationNodeDatum,
  type SimulationLinkDatum,
} from "d3-force";

// ── Types ────────────────────────────────────────────────────────────

interface WorkerNode extends SimulationNodeDatum {
  id: string;
  type: string;
  baseSize: number;
  clusterId?: string;
}

interface WorkerEdge extends SimulationLinkDatum<WorkerNode> {
  id: string;
}

interface SimConfig {
  linkDistance: number;
  linkStrength: number;
  chargeStrength: number;
  chargeDistanceMax: number;
  centerStrength: number;
  collideStrength: number;
  xStrength: number;
  yStrength: number;
  alphaDecay: number;
  velocityDecay: number;
  clusterStrength: number;
}

const DEFAULT_CONFIG: SimConfig = {
  linkDistance: 160,
  linkStrength: 0.35,
  chargeStrength: -600,
  chargeDistanceMax: 800,
  centerStrength: 0.05,
  collideStrength: 0.8,
  xStrength: 0.015,
  yStrength: 0.015,
  alphaDecay: 0.01,
  velocityDecay: 0.3,
  clusterStrength: 0.03,
};

// ── State ────────────────────────────────────────────────────────────

let simulation: Simulation<WorkerNode, WorkerEdge> | null = null;
let nodes: WorkerNode[] = [];
let edges: WorkerEdge[] = [];
let nodeMap = new Map<string, WorkerNode>();
let config: SimConfig = DEFAULT_CONFIG;
let tickCounter = 0;

// Throttle: send positions every N ticks to avoid flooding the message channel
const TICK_SEND_INTERVAL = 3;

// ── Cluster force (mirrors main-thread version) ─────────────────────

function clusterForce(alpha: number): void {
  if (config.clusterStrength <= 0) return;

  // Group nodes by clusterId
  const clusters = new Map<string, WorkerNode[]>();
  for (const n of nodes) {
    if (!n.clusterId) continue;
    let arr = clusters.get(n.clusterId);
    if (!arr) {
      arr = [];
      clusters.set(n.clusterId, arr);
    }
    arr.push(n);
  }

  for (const members of clusters.values()) {
    if (members.length < 2) continue;
    let sumX = 0, sumY = 0;
    for (const n of members) {
      sumX += n.x || 0;
      sumY += n.y || 0;
    }
    const cx = sumX / members.length;
    const cy = sumY / members.length;
    for (const n of members) {
      if (n.fx != null) continue;
      n.vx = (n.vx || 0) + (cx - (n.x || 0)) * config.clusterStrength * alpha;
      n.vy = (n.vy || 0) + (cy - (n.y || 0)) * config.clusterStrength * alpha;
    }
  }
}

// ── Build simulation ─────────────────────────────────────────────────

function buildSimulation(): void {
  if (simulation) simulation.stop();

  simulation = forceSimulation<WorkerNode>(nodes)
    .force(
      "link",
      forceLink<WorkerNode, WorkerEdge>(edges)
        .id((d) => d.id)
        .distance(config.linkDistance)
        .strength(config.linkStrength)
    )
    .force("charge", forceManyBody().strength(config.chargeStrength).distanceMax(config.chargeDistanceMax))
    .force("center", forceCenter(0, 0).strength(config.centerStrength))
    .force(
      "collide",
      forceCollide<WorkerNode>().radius((d) => d.baseSize + 14).strength(config.collideStrength)
    )
    .force("x", forceX(0).strength(config.xStrength))
    .force("y", forceY(0).strength(config.yStrength))
    .force("cluster", clusterForce)
    .alphaDecay(config.alphaDecay)
    .velocityDecay(config.velocityDecay)
    .on("tick", onTick)
    .on("end", onEnd);
}

// ── Tick handler ─────────────────────────────────────────────────────

function onTick(): void {
  tickCounter++;
  if (tickCounter % TICK_SEND_INTERVAL !== 0) return;

  const positions: Array<{ id: string; x: number; y: number }> = new Array(nodes.length);
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    positions[i] = { id: n.id, x: n.x || 0, y: n.y || 0 };
  }

  self.postMessage({
    type: "tick",
    positions,
    alpha: simulation?.alpha() ?? 0,
  });
}

function onEnd(): void {
  // Send final positions
  onTick();
  self.postMessage({ type: "settled" });
}

// ── Message handler ──────────────────────────────────────────────────

self.onmessage = (e: MessageEvent) => {
  const msg = e.data;

  switch (msg.type) {
    case "init": {
      config = { ...DEFAULT_CONFIG, ...(msg.config || {}) };
      nodes = (msg.nodes || []).map((n: any) => ({
        ...n,
        x: n.x ?? (Math.random() - 0.5) * 800,
        y: n.y ?? (Math.random() - 0.5) * 600,
      }));
      nodeMap = new Map(nodes.map((n) => [n.id, n]));

      edges = (msg.edges || []).map((e: any) => ({
        id: e.id,
        source: e.source,
        target: e.target,
      }));

      tickCounter = 0;
      buildSimulation();
      break;
    }

    case "addNodes": {
      const newNodes: WorkerNode[] = [];
      for (const n of msg.nodes || []) {
        if (nodeMap.has(n.id)) continue;
        const wn: WorkerNode = {
          ...n,
          x: n.x ?? (Math.random() - 0.5) * 800,
          y: n.y ?? (Math.random() - 0.5) * 600,
        };
        nodes.push(wn);
        nodeMap.set(wn.id, wn);
        newNodes.push(wn);
      }

      for (const e of msg.edges || []) {
        const src = nodeMap.get(typeof e.source === "string" ? e.source : e.source?.id);
        const tgt = nodeMap.get(typeof e.target === "string" ? e.target : e.target?.id);
        if (src && tgt) {
          edges.push({ id: e.id, source: src, target: tgt });
        }
      }

      if (simulation) {
        simulation.nodes(nodes);
        (simulation.force("link") as any)?.links(edges);
        simulation.alpha(0.3).restart();
      } else {
        buildSimulation();
      }
      break;
    }

    case "reheat": {
      if (simulation) {
        simulation.alpha(msg.alpha ?? 0.3).restart();
      }
      break;
    }

    case "pinNode": {
      const n = nodeMap.get(msg.id);
      if (n) {
        n.fx = msg.x;
        n.fy = msg.y;
        if (simulation) simulation.alpha(0.1).restart();
      }
      break;
    }

    case "unpinNode": {
      const n = nodeMap.get(msg.id);
      if (n) {
        n.fx = null;
        n.fy = null;
      }
      break;
    }

    case "stop": {
      if (simulation) {
        simulation.stop();
        simulation = null;
      }
      break;
    }
  }
};
