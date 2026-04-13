/**
 * Battlespace Visualization Engine
 * ═══════════════════════════════════════════════════════════════════════
 * High-resolution Canvas 2D rendering engine + D3-force simulation.
 * Brutalist design system with MIL-STD-2525D inspired symbology.
 *
 * Features:
 *  - HiDPI Canvas 2D rendering (devicePixelRatio aware)
 *  - D3-force physics simulation with custom forces
 *  - Zoom-dependent detail levels (MACRO/MESO/MICRO)
 *  - Directional particle animations along edges
 *  - Progressive node reveal animation
 *  - Pan/zoom camera with inertia
 *  - Node selection and hover detail panels
 *  - Ember C2 real-time event processing
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
import {
  type BattlespaceNode,
  type BattlespaceEdge,
  type BattlespaceGraphData,
  type ZoomLevel,
  NODE_VISUAL_CONFIG,
  EDGE_VISUAL_CONFIG,
  SEVERITY_COLORS,
  KILL_CHAIN_COLORS,
  TECH_ICONS,
  DEFENSE_ICONS,
  PLATFORM_ICONS,
  getZoomLevel,
} from "./battlespace-types";

// ── Types ───────────────────────────────────────────────────────────
interface SimNode extends SimulationNodeDatum, BattlespaceNode {
  _revealProgress?: number;  // 0→1 reveal animation
  _flashColor?: string;
  _flashAlpha?: number;
  _pulsePhase?: number;
}

interface SimEdge extends SimulationLinkDatum<SimNode> {
  id: string;
  type: BattlespaceEdge["type"];
  weight?: number;
  probability?: number;
  protocol?: BattlespaceEdge["protocol"];
  dataFlow?: string;
  killChainPhase?: BattlespaceEdge["killChainPhase"];
  isHighlighted?: boolean;
  isIntercepted?: boolean;
  interceptionType?: "logged" | "inline" | "ssl_decrypted" | "mirrored";
  interceptedBy?: string;
  isBypassOpportunity?: boolean;
  bypassesProxy?: string;
  particles: Array<{ progress: number; speed: number }>;
}

export interface EngineCallbacks {
  onNodeHover?: (node: BattlespaceNode | null, x: number, y: number) => void;
  onNodeClick?: (node: BattlespaceNode) => void;
  onNodeDoubleClick?: (node: BattlespaceNode) => void;
  onZoomChange?: (scale: number, level: ZoomLevel) => void;
  onStatsUpdate?: (stats: EngineStats) => void;
}

export interface EngineStats {
  nodeCount: number;
  edgeCount: number;
  fps: number;
  zoomLevel: ZoomLevel;
  scale: number;
  simulationAlpha: number;
}

export interface EngineOptions {
  resolution?: number;
  backgroundColor?: string;
  gridEnabled?: boolean;
  particlesEnabled?: boolean;
  glowEnabled?: boolean;
}

const DEFAULT_OPTIONS: Required<EngineOptions> = {
  resolution: 2,
  backgroundColor: "#0A0E14",
  gridEnabled: true,
  particlesEnabled: true,
  glowEnabled: true,
};

// ── Helper: parse hex color to rgba components ─────────────────────
function hexToRgb(hex: string): [number, number, number] {
  const h = hex.replace("#", "");
  return [
    parseInt(h.substring(0, 2), 16),
    parseInt(h.substring(2, 4), 16),
    parseInt(h.substring(4, 6), 16),
  ];
}

function rgbaStr(hex: string, alpha: number): string {
  const [r, g, b] = hexToRgb(hex);
  return `rgba(${r},${g},${b},${alpha})`;
}

// ── Edge dash patterns per protocol ────────────────────────────────
const PROTOCOL_DASH: Record<string, number[]> = {
  tcp: [],
  udp: [8, 4],
  icmp: [2, 4],
  http: [12, 3, 3, 3],
  https: [12, 3, 3, 3],
  dns: [6, 3],
  ssh: [10, 5],
  smb: [4, 2, 4, 2],
  rdp: [14, 4],
  default: [],
};

// ── Node shape drawing functions ───────────────────────────────────
type ShapeFn = (ctx: CanvasRenderingContext2D, x: number, y: number, r: number) => void;

const SHAPES: Record<string, ShapeFn> = {
  diamond(ctx, x, y, r) {
    ctx.beginPath();
    ctx.moveTo(x, y - r);
    ctx.lineTo(x + r, y);
    ctx.lineTo(x, y + r);
    ctx.lineTo(x - r, y);
    ctx.closePath();
  },
  hexagon(ctx, x, y, r) {
    ctx.beginPath();
    for (let i = 0; i < 6; i++) {
      const angle = (Math.PI / 3) * i - Math.PI / 2;
      const px = x + r * Math.cos(angle);
      const py = y + r * Math.sin(angle);
      if (i === 0) ctx.moveTo(px, py);
      else ctx.lineTo(px, py);
    }
    ctx.closePath();
  },
  square(ctx, x, y, r) {
    ctx.beginPath();
    ctx.rect(x - r * 0.8, y - r * 0.8, r * 1.6, r * 1.6);
  },
  triangle(ctx, x, y, r) {
    ctx.beginPath();
    ctx.moveTo(x, y - r);
    ctx.lineTo(x + r * 0.87, y + r * 0.5);
    ctx.lineTo(x - r * 0.87, y + r * 0.5);
    ctx.closePath();
  },
  circle(ctx, x, y, r) {
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
  },
  pentagon(ctx, x, y, r) {
    ctx.beginPath();
    for (let i = 0; i < 5; i++) {
      const angle = (Math.PI * 2 / 5) * i - Math.PI / 2;
      const px = x + r * Math.cos(angle);
      const py = y + r * Math.sin(angle);
      if (i === 0) ctx.moveTo(px, py);
      else ctx.lineTo(px, py);
    }
    ctx.closePath();
  },
  octagon(ctx, x, y, r) {
    ctx.beginPath();
    for (let i = 0; i < 8; i++) {
      const angle = (Math.PI * 2 / 8) * i - Math.PI / 8;
      const px = x + r * Math.cos(angle);
      const py = y + r * Math.sin(angle);
      if (i === 0) ctx.moveTo(px, py);
      else ctx.lineTo(px, py);
    }
    ctx.closePath();
  },
  star(ctx, x, y, r) {
    ctx.beginPath();
    for (let i = 0; i < 10; i++) {
      const angle = (Math.PI * 2 / 10) * i - Math.PI / 2;
      const rad = i % 2 === 0 ? r : r * 0.5;
      const px = x + rad * Math.cos(angle);
      const py = y + rad * Math.sin(angle);
      if (i === 0) ctx.moveTo(px, py);
      else ctx.lineTo(px, py);
    }
    ctx.closePath();
  },
};

function getShape(name: string): ShapeFn {
  return SHAPES[name] || SHAPES.circle;
}

// ── Engine Class ────────────────────────────────────────────────────
export class BattlespaceEngine {
  private canvas: HTMLCanvasElement | null = null;
  private ctx: CanvasRenderingContext2D | null = null;
  private dpr = 1;
  private width = 0;
  private height = 0;

  private simulation: Simulation<SimNode, SimEdge> | null = null;
  private simNodes: SimNode[] = [];
  private simEdges: SimEdge[] = [];
  private nodeMap = new Map<string, SimNode>();
  private hiddenNodeTypes = new Set<string>();

  private scale = 0.6;
  private panX = 0;
  private panY = 0;
  private isDragging = false;
  private isPanning = false;
  private dragStartX = 0;
  private dragStartY = 0;
  private panStartX = 0;
  private panStartY = 0;
  private draggedNode: SimNode | null = null;
  private hoveredNode: SimNode | null = null;
  private selectedNodeId: string | null = null;

  private currentZoomLevel: ZoomLevel = "MESO";
  private animationTime = 0;
  private frameCount = 0;
  private lastFpsTime = 0;
  private currentFps = 60;
  private options: Required<EngineOptions>;
  private callbacks: EngineCallbacks;
  private destroyed = false;
  private rafId = 0;

  constructor(callbacks: EngineCallbacks = {}, options: EngineOptions = {}) {
    this.callbacks = callbacks;
    this.options = { ...DEFAULT_OPTIONS, ...options };
  }

  // ── Lifecycle ─────────────────────────────────────────────────────
  async init(container: HTMLElement): Promise<void> {
    if (this.destroyed) return;

    this.width = container.clientWidth || 1200;
    this.height = container.clientHeight || 800;
    this.dpr = Math.min(window.devicePixelRatio || 1, this.options.resolution);

    this.canvas = document.createElement("canvas");
    this.canvas.width = this.width * this.dpr;
    this.canvas.height = this.height * this.dpr;
    this.canvas.style.width = "100%";
    this.canvas.style.height = "100%";
    this.canvas.style.display = "block";
    this.canvas.style.cursor = "grab";

    this.ctx = this.canvas.getContext("2d", { alpha: false })!;
    this.ctx.scale(this.dpr, this.dpr);

    container.appendChild(this.canvas);

    this.panX = this.width / 2;
    this.panY = this.height / 2;

    this.setupInputHandlers();
    this.lastFpsTime = performance.now();
    this.tick();
  }

  destroy(): void {
    this.destroyed = true;
    if (this.rafId) cancelAnimationFrame(this.rafId);
    if (this.simulation) {
      this.simulation.stop();
      this.simulation = null;
    }
    if (this.canvas?.parentElement) {
      this.canvas.parentElement.removeChild(this.canvas);
    }
    this.canvas = null;
    this.ctx = null;
  }

  resize(width: number, height: number): void {
    if (!this.canvas || !this.ctx) return;
    this.width = width;
    this.height = height;
    this.canvas.width = width * this.dpr;
    this.canvas.height = height * this.dpr;
    this.ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
  }

  // ── Data Loading ──────────────────────────────────────────────────
  loadGraph(data: BattlespaceGraphData): void {
    this.clearGraph();

    this.simNodes = data.nodes.map((n) => ({
      ...n,
      x: n.x ?? (Math.random() - 0.5) * 800,
      y: n.y ?? (Math.random() - 0.5) * 600,
      _revealProgress: 0,
    }));

    this.nodeMap.clear();
    for (const sn of this.simNodes) this.nodeMap.set(sn.id, sn);

    this.simEdges = [];
    for (const e of data.edges) {
      const src = this.nodeMap.get(e.source);
      const tgt = this.nodeMap.get(e.target);
      if (src && tgt) {
        this.simEdges.push({
          source: src,
          target: tgt,
          id: e.id,
          type: e.type,
          weight: e.weight,
          probability: e.probability,
          protocol: e.protocol,
          dataFlow: e.dataFlow,
          killChainPhase: e.killChainPhase,
          isIntercepted: e.isIntercepted,
          interceptionType: e.interceptionType,
          interceptedBy: e.interceptedBy,
          isBypassOpportunity: e.isBypassOpportunity,
          bypassesProxy: e.bypassesProxy,
          particles: this.options.particlesEnabled
            ? Array.from({ length: 2 + Math.floor(Math.random() * 3) }, () => ({
                progress: Math.random(),
                speed: 0.001 + Math.random() * 0.002,
              }))
            : [],
        });
      }
    }

    this.startSimulation();
  }

  private clearGraph(): void {
    if (this.simulation) {
      this.simulation.stop();
      this.simulation = null;
    }
    this.simNodes = [];
    this.simEdges = [];
    this.nodeMap.clear();
  }

  addNodes(newNodes: BattlespaceNode[], newEdges: BattlespaceEdge[]): void {
    for (const n of newNodes) {
      if (this.nodeMap.has(n.id)) continue;
      const sn: SimNode = {
        ...n,
        x: n.x ?? (Math.random() - 0.5) * 800,
        y: n.y ?? (Math.random() - 0.5) * 600,
        _revealProgress: 0,
      };
      this.simNodes.push(sn);
      this.nodeMap.set(sn.id, sn);
    }

    for (const e of newEdges) {
      const src = this.nodeMap.get(e.source);
      const tgt = this.nodeMap.get(e.target);
      if (src && tgt) {
        this.simEdges.push({
          source: src,
          target: tgt,
          id: e.id,
          type: e.type,
          weight: e.weight,
          probability: e.probability,
          protocol: e.protocol,
          dataFlow: e.dataFlow,
          killChainPhase: e.killChainPhase,
          isIntercepted: e.isIntercepted,
          interceptionType: e.interceptionType,
          interceptedBy: e.interceptedBy,
          isBypassOpportunity: e.isBypassOpportunity,
          bypassesProxy: e.bypassesProxy,
          particles: this.options.particlesEnabled
            ? Array.from({ length: 2 }, () => ({
                progress: Math.random(),
                speed: 0.001 + Math.random() * 0.002,
              }))
            : [],
        });
      }
    }

    if (this.simulation) {
      this.simulation.nodes(this.simNodes);
      (this.simulation.force("link") as any)?.links(this.simEdges);
      this.simulation.alpha(0.3).restart();
    } else {
      this.startSimulation();
    }
  }

  highlightPath(nodeIds: string[]): void {
    const pathSet = new Set(nodeIds);
    for (const sn of this.simNodes) (sn as any)._isHighlighted = pathSet.has(sn.id);
    for (const se of this.simEdges) {
      const srcId = typeof se.source === "object" ? (se.source as SimNode).id : se.source;
      const tgtId = typeof se.target === "object" ? (se.target as SimNode).id : se.target;
      se.isHighlighted = pathSet.has(srcId) && pathSet.has(tgtId);
    }
  }

  clearHighlight(): void {
    for (const sn of this.simNodes) (sn as any)._isHighlighted = undefined;
    for (const se of this.simEdges) se.isHighlighted = false;
  }

  fitToView(): void {
    if (this.simNodes.length === 0) return;
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    for (const n of this.simNodes) {
      if (n.x! < minX) minX = n.x!;
      if (n.x! > maxX) maxX = n.x!;
      if (n.y! < minY) minY = n.y!;
      if (n.y! > maxY) maxY = n.y!;
    }
    const graphW = maxX - minX + 200;
    const graphH = maxY - minY + 200;
    this.scale = Math.min(this.width / graphW, this.height / graphH, 2);
    this.panX = this.width / 2 - ((minX + maxX) / 2) * this.scale;
    this.panY = this.height / 2 - ((minY + maxY) / 2) * this.scale;
    this.updateZoomLevel();
  }

  zoomIn(): void {
    this.scale = Math.min(this.scale * 1.3, 8);
    this.updateZoomLevel();
  }

  zoomOut(): void {
    this.scale = Math.max(this.scale / 1.3, 0.05);
    this.updateZoomLevel();
  }

  getNodeCount(): number { return this.simNodes.length; }
  getEdgeCount(): number { return this.simEdges.length; }

  // ── Node Type Visibility (Topology Filters) ──────────────────────
  setNodeTypeVisibility(nodeType: string, visible: boolean): void {
    if (visible) {
      this.hiddenNodeTypes.delete(nodeType);
    } else {
      this.hiddenNodeTypes.add(nodeType);
    }
  }

  getHiddenNodeTypes(): Set<string> {
    return new Set(this.hiddenNodeTypes);
  }

  // ── Simulation ────────────────────────────────────────────────────
  private startSimulation(): void {
    this.simulation = forceSimulation<SimNode>(this.simNodes)
      .force("link", forceLink<SimNode, SimEdge>(this.simEdges)
        .id((d) => d.id)
        .distance(120)
        .strength(0.4))
      .force("charge", forceManyBody().strength(-400).distanceMax(600))
      .force("center", forceCenter(0, 0).strength(0.05))
      .force("collide", forceCollide<SimNode>().radius((d) => {
        const config = NODE_VISUAL_CONFIG[d.type] || NODE_VISUAL_CONFIG.host;
        return config.baseRadius + 10;
      }).strength(0.7))
      .force("x", forceX(0).strength(0.02))
      .force("y", forceY(0).strength(0.02))
      .alphaDecay(0.01)
      .velocityDecay(0.3);
  }

  private updateZoomLevel(): void {
    const level = getZoomLevel(this.scale);
    if (level !== this.currentZoomLevel) {
      this.currentZoomLevel = level;
      this.callbacks.onZoomChange?.(this.scale, level);
    }
  }

  // ── Input Handling ────────────────────────────────────────────────
  private setupInputHandlers(): void {
    if (!this.canvas) return;
    const c = this.canvas;

    c.addEventListener("wheel", (e) => {
      e.preventDefault();
      const factor = e.deltaY < 0 ? 1.08 : 1 / 1.08;
      const rect = c.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      // Zoom toward cursor
      this.panX = mx - (mx - this.panX) * factor;
      this.panY = my - (my - this.panY) * factor;
      this.scale *= factor;
      this.scale = Math.max(0.05, Math.min(8, this.scale));
      this.updateZoomLevel();
    }, { passive: false });

    c.addEventListener("pointerdown", (e) => {
      const [wx, wy] = this.screenToWorld(e.offsetX, e.offsetY);
      const hit = this.hitTest(wx, wy);
      if (hit) {
        this.draggedNode = hit;
        hit.fx = hit.x;
        hit.fy = hit.y;
        this.dragStartX = e.offsetX;
        this.dragStartY = e.offsetY;
        this.isDragging = true;
        c.style.cursor = "grabbing";
      } else {
        this.isPanning = true;
        this.panStartX = this.panX;
        this.panStartY = this.panY;
        this.dragStartX = e.offsetX;
        this.dragStartY = e.offsetY;
        c.style.cursor = "grabbing";
      }
      c.setPointerCapture(e.pointerId);
    });

    c.addEventListener("pointermove", (e) => {
      if (this.isDragging && this.draggedNode) {
        const [wx, wy] = this.screenToWorld(e.offsetX, e.offsetY);
        this.draggedNode.fx = wx;
        this.draggedNode.fy = wy;
        this.simulation?.alpha(0.1).restart();
      } else if (this.isPanning) {
        this.panX = this.panStartX + (e.offsetX - this.dragStartX);
        this.panY = this.panStartY + (e.offsetY - this.dragStartY);
      } else {
        // Hover detection
        const [wx, wy] = this.screenToWorld(e.offsetX, e.offsetY);
        const hit = this.hitTest(wx, wy);
        if (hit !== this.hoveredNode) {
          this.hoveredNode = hit;
          c.style.cursor = hit ? "pointer" : "grab";
          this.callbacks.onNodeHover?.(hit || null, e.offsetX, e.offsetY);
        }
      }
    });

    c.addEventListener("pointerup", (e) => {
      if (this.isDragging && this.draggedNode) {
        // If barely moved, treat as click
        const dx = e.offsetX - this.dragStartX;
        const dy = e.offsetY - this.dragStartY;
        if (Math.abs(dx) < 4 && Math.abs(dy) < 4) {
          this.selectedNodeId = this.draggedNode.id;
          this.callbacks.onNodeClick?.(this.draggedNode);
        }
        this.draggedNode.fx = null;
        this.draggedNode.fy = null;
        this.draggedNode = null;
      }
      this.isDragging = false;
      this.isPanning = false;
      c.style.cursor = "grab";
    });

    c.addEventListener("dblclick", (e) => {
      const [wx, wy] = this.screenToWorld(e.offsetX, e.offsetY);
      const hit = this.hitTest(wx, wy);
      if (hit) this.callbacks.onNodeDoubleClick?.(hit);
    });
  }

  private screenToWorld(sx: number, sy: number): [number, number] {
    return [(sx - this.panX) / this.scale, (sy - this.panY) / this.scale];
  }

  private worldToScreen(wx: number, wy: number): [number, number] {
    return [wx * this.scale + this.panX, wy * this.scale + this.panY];
  }

  private hitTest(wx: number, wy: number): SimNode | null {
    // Reverse order so top-rendered nodes are hit first
    for (let i = this.simNodes.length - 1; i >= 0; i--) {
      const n = this.simNodes[i];
      const config = NODE_VISUAL_CONFIG[n.type] || NODE_VISUAL_CONFIG.host;
      const r = config.baseRadius * (1 + (n.weaknessLevel || 0) * 0.5);
      const dx = (n.x || 0) - wx;
      const dy = (n.y || 0) - wy;
      if (dx * dx + dy * dy < r * r * 1.5) return n;
    }
    return null;
  }

  // ── Render Loop ───────────────────────────────────────────────────
  private tick = (): void => {
    if (this.destroyed) return;
    this.rafId = requestAnimationFrame(this.tick);
    this.animationTime += 0.016;

    // FPS counter
    this.frameCount++;
    const now = performance.now();
    if (now - this.lastFpsTime > 1000) {
      this.currentFps = this.frameCount;
      this.frameCount = 0;
      this.lastFpsTime = now;
    }

    // Update reveal animations
    for (const n of this.simNodes) {
      if ((n._revealProgress ?? 0) < 1) {
        n._revealProgress = Math.min(1, (n._revealProgress || 0) + 0.03);
      }
      if (n._flashAlpha && n._flashAlpha > 0) {
        n._flashAlpha -= 0.015;
      }
    }

    // Update particles
    for (const e of this.simEdges) {
      for (const p of e.particles) {
        p.progress += p.speed;
        if (p.progress > 1) p.progress -= 1;
      }
    }

    this.draw();

    // Stats callback (throttled)
    if (this.frameCount === 0) {
      this.callbacks.onStatsUpdate?.({
        nodeCount: this.simNodes.length,
        edgeCount: this.simEdges.length,
        fps: this.currentFps,
        zoomLevel: this.currentZoomLevel,
        scale: this.scale,
        simulationAlpha: this.simulation?.alpha() || 0,
      });
    }
  };

  // ── Drawing ───────────────────────────────────────────────────────
  private draw(): void {
    const ctx = this.ctx;
    if (!ctx) return;

    // Clear
    ctx.fillStyle = this.options.backgroundColor;
    ctx.fillRect(0, 0, this.width, this.height);

    ctx.save();
    ctx.translate(this.panX, this.panY);
    ctx.scale(this.scale, this.scale);

    // Grid
    if (this.options.gridEnabled) this.drawGrid(ctx);

    // Edges (skip edges connected to hidden node types)
    for (const e of this.simEdges) {
      const srcType = (e.source as SimNode).type;
      const tgtType = (e.target as SimNode).type;
      if (this.hiddenNodeTypes.has(srcType) || this.hiddenNodeTypes.has(tgtType)) continue;
      this.drawEdge(ctx, e);
    }

    // Nodes (skip hidden node types)
    for (const n of this.simNodes) {
      if (this.hiddenNodeTypes.has(n.type)) continue;
      this.drawNode(ctx, n);
    }

    ctx.restore();

    // Scanline overlay (brutalist CRT effect)
    this.drawScanlines(ctx);
  }

  private drawGrid(ctx: CanvasRenderingContext2D): void {
    const gridSize = 80;
    const extent = 4000;
    ctx.strokeStyle = "rgba(26,35,50,0.4)";
    ctx.lineWidth = 0.5;
    for (let x = -extent; x <= extent; x += gridSize) {
      ctx.beginPath();
      ctx.moveTo(x, -extent);
      ctx.lineTo(x, extent);
      ctx.stroke();
    }
    for (let y = -extent; y <= extent; y += gridSize) {
      ctx.beginPath();
      ctx.moveTo(-extent, y);
      ctx.lineTo(extent, y);
      ctx.stroke();
    }
    // Major grid lines
    ctx.strokeStyle = "rgba(26,35,50,0.7)";
    ctx.lineWidth = 1;
    const majorSize = gridSize * 4;
    for (let x = -extent; x <= extent; x += majorSize) {
      ctx.beginPath();
      ctx.moveTo(x, -extent);
      ctx.lineTo(x, extent);
      ctx.stroke();
    }
    for (let y = -extent; y <= extent; y += majorSize) {
      ctx.beginPath();
      ctx.moveTo(-extent, y);
      ctx.lineTo(extent, y);
      ctx.stroke();
    }
    // Origin crosshair
    ctx.strokeStyle = "rgba(0,229,204,0.15)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(-extent, 0);
    ctx.lineTo(extent, 0);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(0, -extent);
    ctx.lineTo(0, extent);
    ctx.stroke();
  }

  private drawEdge(ctx: CanvasRenderingContext2D, e: SimEdge): void {
    const src = e.source as SimNode;
    const tgt = e.target as SimNode;
    if (!src.x || !src.y || !tgt.x || !tgt.y) return;

    const config = EDGE_VISUAL_CONFIG[e.type] || EDGE_VISUAL_CONFIG.enables;
    const alpha = e.isHighlighted ? 1 : 0.5;
    const lineWidth = e.isHighlighted ? 2.5 : (e.weight || 1) * 1.2;

    // Protocol-based dash pattern
    const dash = PROTOCOL_DASH[e.protocol || "default"] || PROTOCOL_DASH.default;

    ctx.save();

    // ── Interception visual: pulsing red/blue stripe pattern ──────
    if (e.isIntercepted) {
      const pulse = Math.sin(this.animationTime * 3) * 0.2 + 0.8;
      const dx = tgt.x - src.x;
      const dy = tgt.y - src.y;
      const edgeLen = Math.sqrt(dx * dx + dy * dy);
      const stripeWidth = 12;
      const numStripes = Math.max(2, Math.floor(edgeLen / stripeWidth));
      const angle = Math.atan2(dy, dx);

      // Determine interception colors based on type
      const interceptColors = {
        ssl_decrypted: { primary: "#FF4444", secondary: "#2196F3" },  // Red/Blue
        inline: { primary: "#FF6600", secondary: "#2196F3" },          // Orange/Blue
        logged: { primary: "#FFAA00", secondary: "#4A90D9" },          // Amber/Blue
        mirrored: { primary: "#E040FB", secondary: "#4A90D9" },        // Purple/Blue
      };
      const colors = interceptColors[e.interceptionType || "logged"];

      // Draw alternating stripe segments along the edge
      for (let i = 0; i < numStripes; i++) {
        const t0 = i / numStripes;
        const t1 = (i + 1) / numStripes;
        const x0 = src.x + dx * t0;
        const y0 = src.y + dy * t0;
        const x1 = src.x + dx * t1;
        const y1 = src.y + dy * t1;
        const isEven = i % 2 === 0;
        ctx.strokeStyle = rgbaStr(isEven ? colors.primary : colors.secondary, alpha * pulse);
        ctx.lineWidth = lineWidth + 1.5;
        ctx.setLineDash([]);
        ctx.beginPath();
        ctx.moveTo(x0, y0);
        ctx.lineTo(x1, y1);
        ctx.stroke();
      }

      // Outer glow for intercepted edge
      ctx.strokeStyle = rgbaStr(colors.primary, 0.15 * pulse);
      ctx.lineWidth = lineWidth + 6;
      ctx.setLineDash([]);
      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      ctx.stroke();

      // Eye icon at midpoint (interception indicator)
      const mx = (src.x + tgt.x) / 2;
      const my = (src.y + tgt.y) / 2;
      ctx.font = "12px sans-serif";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillStyle = rgbaStr(colors.primary, pulse);
      ctx.fillText("\uD83D\uDC41", mx, my); // 👁 eye emoji

      // Interception label at MESO/MICRO zoom
      if (this.currentZoomLevel !== "MACRO" && e.interceptedBy) {
        ctx.font = "bold 7px 'JetBrains Mono', monospace";
        ctx.fillStyle = rgbaStr(colors.primary, 0.9);
        ctx.textAlign = "center";
        const label = e.interceptedBy.length > 25 ? e.interceptedBy.slice(0, 23) + "…" : e.interceptedBy;
        ctx.fillText(label, mx, my + 10);
      }
    } else if (e.isBypassOpportunity) {
      // ── Bypass opportunity: pulsing gold dashed line with warning ──
      const pulse = Math.sin(this.animationTime * 4) * 0.3 + 0.7;
      const dx = tgt.x - src.x;
      const dy = tgt.y - src.y;

      // Outer glow — gold warning
      ctx.strokeStyle = rgbaStr("#FFD600", 0.2 * pulse);
      ctx.lineWidth = lineWidth + 8;
      ctx.setLineDash([]);
      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      ctx.stroke();

      // Main bypass line — gold dashed
      ctx.strokeStyle = rgbaStr("#FFD600", alpha * pulse);
      ctx.lineWidth = lineWidth + 1;
      ctx.setLineDash([8, 4, 2, 4]);
      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      ctx.stroke();
      ctx.setLineDash([]);

      // Warning triangle at midpoint
      const mx = (src.x + tgt.x) / 2;
      const my = (src.y + tgt.y) / 2;
      ctx.font = "14px sans-serif";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillStyle = rgbaStr("#FFD600", pulse);
      ctx.fillText("\u26A0", mx, my); // ⚠ warning

      // Bypass label at MESO/MICRO zoom
      if (this.currentZoomLevel !== "MACRO" && e.label) {
        ctx.font = "bold 7px 'JetBrains Mono', monospace";
        ctx.fillStyle = rgbaStr("#FFD600", 0.9);
        ctx.textAlign = "center";
        const label = e.label.length > 30 ? e.label.slice(0, 28) + "\u2026" : e.label;
        ctx.fillText(label, mx, my + 12);
      }
    } else {
      // Normal edge rendering
      ctx.strokeStyle = rgbaStr(config.color, alpha);
      ctx.lineWidth = lineWidth;
      ctx.setLineDash(dash);

      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // Arrow head
    const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x);
    const arrowLen = 8;
    const ax = tgt.x - Math.cos(angle) * 15;
    const ay = tgt.y - Math.sin(angle) * 15;
    const arrowColor = e.isIntercepted ? "#FF4444" : config.color;
    ctx.fillStyle = rgbaStr(arrowColor, alpha);
    ctx.beginPath();
    ctx.moveTo(ax + Math.cos(angle) * arrowLen, ay + Math.sin(angle) * arrowLen);
    ctx.lineTo(ax + Math.cos(angle + 2.5) * arrowLen * 0.5, ay + Math.sin(angle + 2.5) * arrowLen * 0.5);
    ctx.lineTo(ax + Math.cos(angle - 2.5) * arrowLen * 0.5, ay + Math.sin(angle - 2.5) * arrowLen * 0.5);
    ctx.closePath();
    ctx.fill();

    // Directional particles
    if (this.options.particlesEnabled && e.particles.length > 0) {
      const killColor = e.killChainPhase ? KILL_CHAIN_COLORS[e.killChainPhase] : config.color;
      for (const p of e.particles) {
        const px = src.x + (tgt.x - src.x) * p.progress;
        const py = src.y + (tgt.y - src.y) * p.progress;
        ctx.fillStyle = rgbaStr(killColor, 0.9);
        ctx.beginPath();
        ctx.arc(px, py, 2.5, 0, Math.PI * 2);
        ctx.fill();
        // Particle trail
        const trailLen = 0.04;
        const tx = src.x + (tgt.x - src.x) * Math.max(0, p.progress - trailLen);
        const ty = src.y + (tgt.y - src.y) * Math.max(0, p.progress - trailLen);
        ctx.strokeStyle = rgbaStr(killColor, 0.3);
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(tx, ty);
        ctx.lineTo(px, py);
        ctx.stroke();
      }
    }

    // Edge label at MICRO zoom
    if (this.currentZoomLevel === "MICRO" && e.protocol && !e.isIntercepted) {
      const mx = (src.x + tgt.x) / 2;
      const my = (src.y + tgt.y) / 2;
      ctx.font = "bold 7px 'JetBrains Mono', monospace";
      ctx.fillStyle = rgbaStr(config.color, 0.7);
      ctx.textAlign = "center";
      ctx.fillText(e.protocol.toUpperCase(), mx, my - 4);
    }

    ctx.restore();
  }

  private drawNode(ctx: CanvasRenderingContext2D, n: SimNode): void {
    if (!n.x || !n.y) return;
    const config = NODE_VISUAL_CONFIG[n.type] || NODE_VISUAL_CONFIG.host;
    const reveal = n._revealProgress ?? 1;
    if (reveal <= 0) return;

    const baseR = config.baseRadius * (1 + (n.weaknessLevel || 0) * 0.5);
    const r = baseR * reveal;
    const isSelected = n.id === this.selectedNodeId;
    const isHovered = n === this.hoveredNode;
    const isHighlighted = (n as any)._isHighlighted;
    const sevColor = n.severity ? SEVERITY_COLORS[n.severity] : config.strokeColor;

    ctx.save();
    ctx.globalAlpha = reveal;

    // Glow effect for high-severity or selected nodes
    if (this.options.glowEnabled && (n.severity === "critical" || n.severity === "high" || isSelected || isHighlighted)) {
      const glowR = r * 2.5;
      const pulse = Math.sin(this.animationTime * 2 + (n._pulsePhase || 0)) * 0.15 + 0.85;
      const gradient = ctx.createRadialGradient(n.x, n.y, r * 0.5, n.x, n.y, glowR * pulse);
      gradient.addColorStop(0, rgbaStr(sevColor, 0.25));
      gradient.addColorStop(1, rgbaStr(sevColor, 0));
      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(n.x, n.y, glowR * pulse, 0, Math.PI * 2);
      ctx.fill();
    }

    // ── Blue team tap point: pulsing blue glow with scanning ring ───
    if (this.options.glowEnabled && n.type === "tap_point") {
      const tapPulse = Math.sin(this.animationTime * 4 + (n._pulsePhase || 0)) * 0.3 + 0.7;
      const glowR = r * 3;
      // Blue team glow
      const tapGrad = ctx.createRadialGradient(n.x, n.y, r * 0.3, n.x, n.y, glowR * tapPulse);
      tapGrad.addColorStop(0, rgbaStr("#2196F3", 0.35));
      tapGrad.addColorStop(0.5, rgbaStr("#2196F3", 0.12));
      tapGrad.addColorStop(1, rgbaStr("#2196F3", 0));
      ctx.fillStyle = tapGrad;
      ctx.beginPath();
      ctx.arc(n.x, n.y, glowR * tapPulse, 0, Math.PI * 2);
      ctx.fill();
      // Rotating scanning ring
      const scanAngle = this.animationTime * 1.5;
      ctx.strokeStyle = rgbaStr("#2196F3", 0.5 * tapPulse);
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 6, scanAngle, scanAngle + Math.PI * 0.6);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 6, scanAngle + Math.PI, scanAngle + Math.PI * 1.6);
      ctx.stroke();
    }

    // ── Proxy/CDN/LB node: shield arc with vendor label ───────────
    if (this.options.glowEnabled && n.type === "proxy") {
      const proxyPulse = Math.sin(this.animationTime * 1.5) * 0.1 + 0.9;
      const proxyGlowR = r * 2.2;
      const proxyGrad = ctx.createRadialGradient(n.x, n.y, r * 0.5, n.x, n.y, proxyGlowR * proxyPulse);
      proxyGrad.addColorStop(0, rgbaStr("#FF9800", 0.2));
      proxyGrad.addColorStop(1, rgbaStr("#FF9800", 0));
      ctx.fillStyle = proxyGrad;
      ctx.beginPath();
      ctx.arc(n.x, n.y, proxyGlowR * proxyPulse, 0, Math.PI * 2);
      ctx.fill();
    }

    // ── C2 server node: red command glow ─────────────────────
    if (this.options.glowEnabled && n.type === "c2_server") {
      const c2Pulse = Math.sin(this.animationTime * 2) * 0.15 + 0.85;
      const c2GlowR = r * 2.5;
      const c2Grad = ctx.createRadialGradient(n.x, n.y, r * 0.5, n.x, n.y, c2GlowR * c2Pulse);
      c2Grad.addColorStop(0, rgbaStr("#FF1744", 0.3));
      c2Grad.addColorStop(1, rgbaStr("#FF1744", 0));
      ctx.fillStyle = c2Grad;
      ctx.beginPath();
      ctx.arc(n.x, n.y, c2GlowR * c2Pulse, 0, Math.PI * 2);
      ctx.fill();
    }

    // ── Gateway hop: subtle network pulse ────────────────────
    if (this.options.glowEnabled && n.type === "gateway") {
      const gwPulse = Math.sin(this.animationTime * 1.2 + (n._pulsePhase || 0)) * 0.1 + 0.9;
      const gwGlowR = r * 1.8;
      const gwGrad = ctx.createRadialGradient(n.x, n.y, r * 0.5, n.x, n.y, gwGlowR * gwPulse);
      gwGrad.addColorStop(0, rgbaStr("#78909C", 0.15));
      gwGrad.addColorStop(1, rgbaStr("#78909C", 0));
      ctx.fillStyle = gwGrad;
      ctx.beginPath();
      ctx.arc(n.x, n.y, gwGlowR * gwPulse, 0, Math.PI * 2);
      ctx.fill();
    }

    // Node shape
    const shapeFn = getShape(config.shape);
    shapeFn(ctx, n.x, n.y, r);

    // Fill
    ctx.fillStyle = rgbaStr(config.fillColor, 0.85);
    ctx.fill();

    // Border — thickness encodes weakness level
    const borderWidth = 1 + (n.weaknessLevel || 0) * 3;
    ctx.strokeStyle = isSelected ? "#FFFFFF" : isHovered ? "#00E5CC" : sevColor;
    ctx.lineWidth = borderWidth;
    ctx.stroke();

    // Flash overlay
    if (n._flashColor && n._flashAlpha && n._flashAlpha > 0) {
      shapeFn(ctx, n.x, n.y, r);
      ctx.fillStyle = rgbaStr(n._flashColor, n._flashAlpha);
      ctx.fill();
    }

    // Icon in center
    ctx.font = `${r * 0.8}px sans-serif`;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillStyle = config.strokeColor;
    ctx.fillText(config.icon, n.x, n.y);

    // Label (MESO and MICRO zoom)
    if (this.currentZoomLevel !== "MACRO") {
      ctx.font = "bold 9px 'JetBrains Mono', monospace";
      ctx.fillStyle = "#E8EAED";
      ctx.textAlign = "center";
      ctx.fillText(
        n.label.length > 20 ? n.label.slice(0, 18) + "…" : n.label,
        n.x,
        n.y + r + 12,
      );
    }

    // Badges at MICRO zoom
    if (this.currentZoomLevel === "MICRO") {
      this.drawNodeBadges(ctx, n, r);
    }

    // Priority target indicator
    if (n.isPriorityTarget) {
      ctx.strokeStyle = "#FF0040";
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 8, 0, Math.PI * 2);
      ctx.stroke();
      ctx.setLineDash([]);
      // Rotating crosshair
      const angle = this.animationTime * 0.5;
      ctx.strokeStyle = rgbaStr("#FF0040", 0.6);
      ctx.lineWidth = 1;
      for (let i = 0; i < 4; i++) {
        const a = angle + (Math.PI / 2) * i;
        ctx.beginPath();
        ctx.moveTo(n.x + Math.cos(a) * (r + 10), n.y + Math.sin(a) * (r + 10));
        ctx.lineTo(n.x + Math.cos(a) * (r + 16), n.y + Math.sin(a) * (r + 16));
        ctx.stroke();
      }
    }

    // Defense shield overlay
    if (n.defenses && n.defenses.length > 0) {
      ctx.strokeStyle = rgbaStr("#4A90D9", 0.4);
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 5, -Math.PI * 0.7, Math.PI * 0.7);
      ctx.stroke();
      // Defense count badge
      ctx.fillStyle = "#4A90D9";
      ctx.font = "bold 7px 'JetBrains Mono', monospace";
      ctx.textAlign = "center";
      ctx.fillText(`🛡${n.defenses.length}`, n.x + r + 8, n.y - r);
    }

    ctx.restore();
  }

  private drawNodeBadges(ctx: CanvasRenderingContext2D, n: SimNode, r: number): void {
    const badges: string[] = [];

    // Tech stack badges
    if (n.technologies) {
      for (const t of n.technologies.slice(0, 3)) {
        const icon = TECH_ICONS[t.toLowerCase()] || TECH_ICONS.default;
        badges.push(icon);
      }
    }

    // Platform badge
    if (n.platform) {
      const icon = PLATFORM_ICONS[n.platform] || PLATFORM_ICONS.onprem;
      badges.push(icon);
    }

    // Exposed services badges
    if (n.exposedServices) {
      for (const s of n.exposedServices.slice(0, 2)) {
        badges.push(s.port ? `⚡${s.port}` : "⚡");
      }
    }

    if (badges.length === 0) return;

    // Draw badges in a row above the node
    const badgeY = (n.y || 0) - r - 16;
    const startX = (n.x || 0) - (badges.length * 12) / 2;
    ctx.font = "8px sans-serif";
    for (let i = 0; i < badges.length; i++) {
      const bx = startX + i * 14;
      ctx.fillStyle = "rgba(10,14,20,0.9)";
      ctx.fillRect(bx - 5, badgeY - 5, 12, 12);
      ctx.strokeStyle = "rgba(26,35,50,0.8)";
      ctx.lineWidth = 0.5;
      ctx.strokeRect(bx - 5, badgeY - 5, 12, 12);
      ctx.fillStyle = "#E8EAED";
      ctx.textAlign = "center";
      ctx.fillText(badges[i], bx + 1, badgeY + 4);
    }
  }

  private drawScanlines(ctx: CanvasRenderingContext2D): void {
    ctx.save();
    ctx.globalAlpha = 0.03;
    ctx.fillStyle = "#000000";
    for (let y = 0; y < this.height; y += 3) {
      ctx.fillRect(0, y, this.width, 1);
    }
    ctx.restore();
  }

  // ── Ember Event Handlers ──────────────────────────────────────────
  processWsEvent(event: { type: string; data: any }): void {
    const { type, data } = event;
    switch (type) {
      case "ember:agent_registered": this.handleEmberAgentRegistered(data); break;
      case "ember:beacon": this.handleEmberBeacon(data); break;
      case "ember:task_complete": this.handleEmberTaskComplete(data); break;
      case "ember:lateral_movement": this.handleEmberLateralMovement(data); break;
      case "ember:network_discovered": this.handleEmberNetworkDiscovered(data); break;
      case "ember:credential_harvested": this.handleEmberCredentialHarvested(data); break;
      case "ember:data_exfiltrated": this.handleEmberDataExfiltrated(data); break;
      case "ember:persistence_established": this.handleEmberPersistenceEstablished(data); break;
      case "ember:burn_response": this.handleEmberBurnResponse(data); break;
      case "ember:opsec_scored": this.handleEmberOpsecScored(data); break;
    }
  }

  private handleEmberAgentRegistered(data: {
    agentId: string; hostname?: string; platform?: string; username?: string;
  }): void {
    const id = `agent-${data.agentId}`;
    if (this.nodeMap.has(id)) return;

    const hostNode = this.simNodes.find(n => n.hostname === data.hostname);
    this.addNodes([{
      id,
      type: "agent",
      label: data.agentId.slice(0, 8),
      hostname: data.hostname,
      platform: data.platform as any,
      severity: "info",
      isNew: true,
      discoveredAt: Date.now(),
      x: hostNode ? (hostNode.x || 0) + 40 : undefined,
      y: hostNode ? (hostNode.y || 0) + 40 : undefined,
    }], hostNode ? [{
      id: `edge-agent-${data.agentId}`,
      source: hostNode.id,
      target: id,
      type: "controls",
      protocol: "https",
    }] : []);

    // Flash the new agent green
    const agent = this.nodeMap.get(id);
    if (agent) {
      agent._flashColor = "#00E5CC";
      agent._flashAlpha = 0.8;
    }
  }

  private handleEmberBeacon(data: {
    agentId: string; status?: string; hostname?: string;
  }): void {
    const agent = this.nodeMap.get(`agent-${data.agentId}`);
    if (!agent) return;
    const color = data.status === "active" ? "#00E5CC"
      : data.status === "dormant" ? "#FFB800"
      : data.status === "burned" ? "#FF0040" : "#00E5CC";
    agent._flashColor = color;
    agent._flashAlpha = 0.6;
    agent._pulsePhase = this.animationTime;
  }

  private handleEmberTaskComplete(data: {
    agentId: string; taskType?: string; opsecRisk?: number;
  }): void {
    const agent = this.nodeMap.get(`agent-${data.agentId}`);
    if (!agent) return;
    const risk = data.opsecRisk || 0;
    agent._flashColor = risk > 0.7 ? "#FF0040" : risk > 0.4 ? "#FFB800" : "#00E5CC";
    agent._flashAlpha = 0.5;
  }

  private handleEmberLateralMovement(data: {
    agentId: string; sourceHost?: string; targetHost?: string;
    technique?: string; newAgentId?: string;
  }): void {
    const newNodes: BattlespaceNode[] = [];
    const newEdges: BattlespaceEdge[] = [];

    // Ensure target host node exists
    const targetId = `host-${(data.targetHost || "unknown").replace(/\./g, "-")}`;
    if (!this.nodeMap.has(targetId)) {
      newNodes.push({
        id: targetId,
        type: "host",
        label: data.targetHost || "Unknown Host",
        hostname: data.targetHost,
        isNew: true,
        discoveredAt: Date.now(),
        severity: "medium",
      });
    }

    // Pivot edge from source agent to target host
    const sourceAgent = this.nodeMap.get(`agent-${data.agentId}`);
    if (sourceAgent) {
      newEdges.push({
        id: `pivot-${Date.now()}`,
        source: sourceAgent.id,
        target: targetId,
        type: "pivots_to",
        protocol: "smb",
        killChainPhase: "lateral_movement",
      });
    }

    // New agent on target
    if (data.newAgentId) {
      const newAgentId = `agent-${data.newAgentId}`;
      newNodes.push({
        id: newAgentId,
        type: "agent",
        label: data.newAgentId.slice(0, 8),
        hostname: data.targetHost,
        isNew: true,
        discoveredAt: Date.now(),
      });
      newEdges.push({
        id: `edge-newagent-${Date.now()}`,
        source: targetId,
        target: newAgentId,
        type: "controls",
        protocol: "https",
      });
    }

    if (newNodes.length > 0 || newEdges.length > 0) {
      this.addNodes(newNodes, newEdges);
    }
  }

  private handleEmberNetworkDiscovered(data: {
    agentId: string; subnet?: string; hosts?: Array<{ ip: string; hostname?: string; os?: string; services?: any[] }>;
  }): void {
    const newNodes: BattlespaceNode[] = [];
    const newEdges: BattlespaceEdge[] = [];

    // Subnet node
    if (data.subnet) {
      const subnetId = `subnet-${data.subnet.replace(/[./]/g, "-")}`;
      if (!this.nodeMap.has(subnetId)) {
        newNodes.push({
          id: subnetId,
          type: "subnet",
          label: data.subnet,
          isNew: true,
          discoveredAt: Date.now(),
        });
      }
    }

    // Host nodes
    for (const host of (data.hosts || [])) {
      const hostId = `host-${host.ip.replace(/\./g, "-")}`;
      if (!this.nodeMap.has(hostId)) {
        newNodes.push({
          id: hostId,
          type: "host",
          label: host.hostname || host.ip,
          hostname: host.hostname || host.ip,
          ip: host.ip,
          os: host.os,
          isNew: true,
          discoveredAt: Date.now(),
        });

        // Service nodes
        for (const svc of (host.services || []).slice(0, 5)) {
          const svcId = `svc-${host.ip}-${svc.port}`;
          newNodes.push({
            id: svcId,
            type: "service",
            label: `${svc.name || "svc"}:${svc.port}`,
            isNew: true,
            discoveredAt: Date.now(),
          });
          newEdges.push({
            id: `edge-svc-${svcId}`,
            source: hostId,
            target: svcId,
            type: "exposes",
            protocol: svc.protocol || "tcp",
          });
        }

        // Link to subnet
        if (data.subnet) {
          newEdges.push({
            id: `edge-subnet-${hostId}`,
            source: `subnet-${data.subnet.replace(/[./]/g, "-")}`,
            target: hostId,
            type: "contains",
          });
        }
      }
    }

    if (newNodes.length > 0) this.addNodes(newNodes, newEdges);
  }

  private handleEmberCredentialHarvested(data: {
    agentId: string; credentialType?: string; username?: string; domain?: string;
  }): void {
    const agent = this.nodeMap.get(`agent-${data.agentId}`);
    if (!agent) return;

    const credId = `cred-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    this.addNodes([{
      id: credId,
      type: "credential",
      label: data.username ? `${data.domain || ""}\\${data.username}` : data.credentialType || "Credential",
      isNew: true,
      discoveredAt: Date.now(),
      severity: "high",
      x: (agent.x || 0) + 30,
      y: (agent.y || 0) - 30,
    }], [{
      id: `edge-cred-${credId}`,
      source: agent.id,
      target: credId,
      type: "harvested",
      killChainPhase: "credential_access",
    }]);
  }

  private handleEmberDataExfiltrated(data: {
    agentId: string; destination?: string; dataType?: string; sizeBytes?: number;
  }): void {
    const agent = this.nodeMap.get(`agent-${data.agentId}`);
    if (!agent) return;

    const exfilId = `exfil-${Date.now()}`;
    this.addNodes([{
      id: exfilId,
      type: "exfil_target",
      label: data.destination || "C2 Server",
      isNew: true,
      discoveredAt: Date.now(),
    }], [{
      id: `edge-exfil-${exfilId}`,
      source: agent.id,
      target: exfilId,
      type: "data_flow",
      protocol: "https",
      dataFlow: data.dataType,
      killChainPhase: "exfiltration",
    }]);

    // Cyan flash on agent
    agent._flashColor = "#00BCD4";
    agent._flashAlpha = 0.7;
  }

  private handleEmberPersistenceEstablished(data: {
    agentId: string; mechanism?: string; hostname?: string;
  }): void {
    const hostNode = this.simNodes.find(n => n.hostname === data.hostname) ||
                     this.nodeMap.get(`agent-${data.agentId}`);
    if (hostNode) {
      hostNode._flashColor = "#E040FB";
      hostNode._flashAlpha = 0.6;
    }
  }

  private handleEmberBurnResponse(data: {
    agentId: string; severity?: string; action?: string;
  }): void {
    const agent = this.nodeMap.get(`agent-${data.agentId}`);
    if (!agent) return;
    const color = data.severity === "critical" ? "#FF0040"
      : data.severity === "high" ? "#FF6B00" : "#FFB800";
    agent._flashColor = color;
    agent._flashAlpha = 1.0;
  }

  private handleEmberOpsecScored(data: {
    agentId: string; riskScore?: number;
  }): void {
    const agent = this.nodeMap.get(`agent-${data.agentId}`);
    if (!agent) return;
    const risk = data.riskScore || 0;
    agent._flashColor = risk > 0.7 ? "#FF0040" : risk > 0.4 ? "#FFB800" : "#00E5CC";
    agent._flashAlpha = 0.4;
  }
}
