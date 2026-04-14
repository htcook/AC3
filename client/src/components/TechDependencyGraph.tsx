/**
 * TechDependencyGraph — Interactive force-directed graph showing technology
 * relationships. Renders on a <canvas> element with zoom/pan support.
 */
import { useEffect, useRef, useCallback, useState } from "react";
import type {
  TechDepGraph,
  TechDepNode,
  TechCategory,
} from "@/lib/tech-dependency-graph";
import { CATEGORY_COLORS, CATEGORY_LABELS } from "@/lib/tech-dependency-graph";

interface Props {
  graph: TechDepGraph;
  width?: number;
  height?: number;
  onNodeClick?: (node: TechDepNode) => void;
}

// Force simulation node — guaranteed x/y/vx/vy
interface SimNode {
  id: string;
  name: string;
  category: TechCategory;
  assetCount: number;
  detected: boolean;
  version?: string;
  isOutdated?: boolean;
  x: number;
  y: number;
  vx: number;
  vy: number;
  fx: number | null;
  fy: number | null;
}

interface SimEdge {
  source: SimNode;
  target: SimNode;
  type: "depends_on" | "implied";
}

export function TechDependencyGraph({ graph, width = 800, height = 600, onNodeClick }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const nodesRef = useRef<SimNode[]>([]);
  const edgesRef = useRef<SimEdge[]>([]);
  const [hoveredNode, setHoveredNode] = useState<SimNode | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<TechCategory | null>(null);

  // Transform / pan / zoom state
  const scaleRef = useRef(1);
  const offsetRef = useRef({ x: 0, y: 0 });
  const isPanningRef = useRef(false);
  const lastMouseRef = useRef({ x: 0, y: 0 });
  const dragNodeRef = useRef<SimNode | null>(null);

  // Initialize simulation nodes/edges
  useEffect(() => {
    const nodeMap = new Map<string, SimNode>();
    const cx = width / 2;
    const cy = height / 2;

    const simNodes: SimNode[] = graph.nodes.map((n, i) => {
      const angle = (i / graph.nodes.length) * Math.PI * 2;
      const radius = 150 + Math.random() * 100;
      const sn: SimNode = {
        id: n.id,
        name: n.name,
        category: n.category,
        assetCount: n.assetCount,
        detected: n.detected,
        version: n.version,
        isOutdated: n.isOutdated,
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius,
        vx: 0,
        vy: 0,
        fx: null,
        fy: null,
      };
      nodeMap.set(n.id, sn);
      return sn;
    });

    const simEdges: SimEdge[] = [];
    for (const e of graph.edges) {
      const src = nodeMap.get(e.source);
      const tgt = nodeMap.get(e.target);
      if (src && tgt) {
        simEdges.push({ source: src, target: tgt, type: e.type });
      }
    }

    nodesRef.current = simNodes;
    edgesRef.current = simEdges;

    // Reset transform
    scaleRef.current = 1;
    offsetRef.current = { x: 0, y: 0 };
  }, [graph, width, height]);

  // Force simulation tick
  const tick = useCallback(() => {
    const nodes = nodesRef.current;
    const edges = edgesRef.current;
    const cx = width / 2;
    const cy = height / 2;
    const alpha = 0.15;
    const friction = 0.85;

    for (const n of nodes) {
      if (n.fx != null) { n.x = n.fx; n.vx = 0; }
      if (n.fy != null) { n.y = n.fy; n.vy = 0; }
      if (n.fx != null && n.fy != null) continue;
      // Gravity toward center
      n.vx += (cx - n.x) * 0.001 * alpha;
      n.vy += (cy - n.y) * 0.001 * alpha;
    }

    // Repulsion between nodes
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const minDist = 80;
        if (dist < minDist) {
          const force = ((minDist - dist) / dist) * alpha * 2;
          const fx = dx * force;
          const fy = dy * force;
          if (a.fx == null) a.vx -= fx;
          if (a.fy == null) a.vy -= fy;
          if (b.fx == null) b.vx += fx;
          if (b.fy == null) b.vy += fy;
        }
      }
    }

    // Edge spring force
    for (const e of edges) {
      const dx = e.target.x - e.source.x;
      const dy = e.target.y - e.source.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const idealDist = 120;
      const force = (dist - idealDist) / dist * alpha * 0.5;
      const fx = dx * force;
      const fy = dy * force;
      if (e.source.fx == null) e.source.vx += fx;
      if (e.source.fy == null) e.source.vy += fy;
      if (e.target.fx == null) e.target.vx -= fx;
      if (e.target.fy == null) e.target.vy -= fy;
    }

    // Apply velocity with friction
    for (const n of nodes) {
      if (n.fx != null && n.fy != null) continue;
      n.vx *= friction;
      n.vy *= friction;
      if (n.fx == null) n.x += n.vx;
      if (n.fy == null) n.y += n.vy;
    }
  }, [width, height]);

  // Draw
  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const nodes = nodesRef.current;
    const edges = edgesRef.current;
    const scale = scaleRef.current;
    const offset = offsetRef.current;

    // Clear
    ctx.fillStyle = "#0A0E14";
    ctx.fillRect(0, 0, width, height);

    ctx.save();
    ctx.translate(offset.x, offset.y);
    ctx.scale(scale, scale);

    // Grid dots
    const gridSize = 40;
    ctx.fillStyle = "rgba(255,255,255,0.03)";
    const startX = Math.floor(-offset.x / scale / gridSize) * gridSize - gridSize;
    const startY = Math.floor(-offset.y / scale / gridSize) * gridSize - gridSize;
    const endX = startX + (width / scale) + gridSize * 2;
    const endY = startY + (height / scale) + gridSize * 2;
    for (let gx = startX; gx < endX; gx += gridSize) {
      for (let gy = startY; gy < endY; gy += gridSize) {
        ctx.fillRect(gx - 1, gy - 1, 2, 2);
      }
    }

    // Draw edges
    for (const e of edges) {
      const dimmed = selectedCategory &&
        e.source.category !== selectedCategory &&
        e.target.category !== selectedCategory;

      ctx.beginPath();
      ctx.moveTo(e.source.x, e.source.y);
      ctx.lineTo(e.target.x, e.target.y);

      if (e.type === "implied") {
        ctx.setLineDash([4, 4]);
        ctx.strokeStyle = dimmed ? "rgba(75,85,99,0.1)" : "rgba(75,85,99,0.3)";
      } else {
        ctx.setLineDash([]);
        ctx.strokeStyle = dimmed ? "rgba(0,229,204,0.05)" : "rgba(0,229,204,0.2)";
      }
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.setLineDash([]);

      // Arrow head
      const angle = Math.atan2(e.target.y - e.source.y, e.target.x - e.source.x);
      const nodeRadius = e.target.detected ? 20 + Math.min(e.target.assetCount * 2, 15) : 14;
      const arrowX = e.target.x - Math.cos(angle) * (nodeRadius + 4);
      const arrowY = e.target.y - Math.sin(angle) * (nodeRadius + 4);
      const arrowSize = 6;
      ctx.beginPath();
      ctx.moveTo(arrowX, arrowY);
      ctx.lineTo(
        arrowX - arrowSize * Math.cos(angle - Math.PI / 6),
        arrowY - arrowSize * Math.sin(angle - Math.PI / 6)
      );
      ctx.lineTo(
        arrowX - arrowSize * Math.cos(angle + Math.PI / 6),
        arrowY - arrowSize * Math.sin(angle + Math.PI / 6)
      );
      ctx.closePath();
      ctx.fillStyle = dimmed ? "rgba(75,85,99,0.1)" : "rgba(0,229,204,0.3)";
      ctx.fill();
    }

    // Draw nodes
    for (const n of nodes) {
      const catColor = CATEGORY_COLORS[n.category] || CATEGORY_COLORS.other;
      const isHovered = hoveredNode?.id === n.id;
      const isDimmed = selectedCategory != null && n.category !== selectedCategory;
      const radius = n.detected ? 20 + Math.min(n.assetCount * 2, 15) : 14;
      const alpha = isDimmed ? 0.15 : 1;

      ctx.globalAlpha = alpha;

      // Outer glow for detected nodes
      if (n.detected && !isDimmed) {
        const glow = ctx.createRadialGradient(n.x, n.y, radius, n.x, n.y, radius + 12);
        glow.addColorStop(0, catColor + "40");
        glow.addColorStop(1, catColor + "00");
        ctx.fillStyle = glow;
        ctx.beginPath();
        ctx.arc(n.x, n.y, radius + 12, 0, Math.PI * 2);
        ctx.fill();
      }

      // Outdated warning ring
      if (n.isOutdated && !isDimmed) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, radius + 4, 0, Math.PI * 2);
        ctx.strokeStyle = "#FF0040";
        ctx.lineWidth = 2;
        ctx.setLineDash([3, 3]);
        ctx.stroke();
        ctx.setLineDash([]);
      }

      // Node circle
      ctx.beginPath();
      ctx.arc(n.x, n.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = n.detected ? catColor + "30" : "#1A2332";
      ctx.fill();
      ctx.strokeStyle = isHovered ? "#FFFFFF" : catColor;
      ctx.lineWidth = isHovered ? 3 : (n.detected ? 2 : 1);
      ctx.stroke();

      // Initials in center
      ctx.fillStyle = n.detected ? "#FFFFFF" : "#6B7280";
      ctx.font = `bold ${n.detected ? 14 : 11}px 'JetBrains Mono', monospace`;
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      const initials = n.name.split(/[\s.]+/).map(w => w[0]).join("").slice(0, 2).toUpperCase();
      ctx.fillText(initials, n.x, n.y);

      // Label below
      ctx.font = `${n.detected ? "bold " : ""}${n.detected ? 11 : 9}px 'Inter', sans-serif`;
      ctx.fillStyle = n.detected ? "#E8EAED" : "#6B7280";
      ctx.fillText(n.name, n.x, n.y + radius + 14);

      // Asset count badge
      if (n.assetCount > 0 && n.detected) {
        const badgeX = n.x + radius - 4;
        const badgeY = n.y - radius + 4;
        ctx.beginPath();
        ctx.arc(badgeX, badgeY, 10, 0, Math.PI * 2);
        ctx.fillStyle = catColor;
        ctx.fill();
        ctx.fillStyle = "#FFFFFF";
        ctx.font = "bold 9px 'JetBrains Mono', monospace";
        ctx.fillText(`${n.assetCount}`, badgeX, badgeY);
      }

      // Version label
      if (n.version) {
        ctx.font = "9px 'JetBrains Mono', monospace";
        ctx.fillStyle = n.isOutdated ? "#FF0040" : "#6B7280";
        ctx.fillText(`v${n.version}`, n.x, n.y + radius + 26);
      }

      ctx.globalAlpha = 1;
    }

    ctx.restore();

    // Legend (top-right)
    const legendX = width - 180;
    let legendY = 20;
    ctx.fillStyle = "rgba(10,14,20,0.85)";
    ctx.fillRect(legendX - 12, legendY - 8, 180, graph.categories.length * 22 + 16);
    ctx.fillStyle = "#00E5CC";
    ctx.fillRect(legendX - 12, legendY - 8, 3, graph.categories.length * 22 + 16);

    ctx.font = "bold 10px 'JetBrains Mono', monospace";
    ctx.textAlign = "left";
    ctx.textBaseline = "middle";

    for (const { category, count } of graph.categories) {
      const color = CATEGORY_COLORS[category];
      const isActive = !selectedCategory || selectedCategory === category;

      ctx.beginPath();
      ctx.arc(legendX + 4, legendY + 6, 5, 0, Math.PI * 2);
      ctx.fillStyle = isActive ? color : color + "40";
      ctx.fill();

      ctx.fillStyle = isActive ? "#E8EAED" : "#4A5568";
      ctx.fillText(`${CATEGORY_LABELS[category]} (${count})`, legendX + 16, legendY + 6);

      legendY += 22;
    }

    // Title
    ctx.font = "bold 13px 'JetBrains Mono', monospace";
    ctx.fillStyle = "#00E5CC";
    ctx.textAlign = "left";
    ctx.fillText("TECH DEPENDENCY GRAPH", 16, 24);
    ctx.font = "10px 'Inter', sans-serif";
    ctx.fillStyle = "#6B7280";
    ctx.fillText(`${graph.nodes.filter(n => n.detected).length} detected \u00B7 ${graph.edges.length} dependencies`, 16, 42);
  }, [graph, width, height, hoveredNode, selectedCategory]);

  // Animation loop
  useEffect(() => {
    let running = true;
    const loop = () => {
      if (!running) return;
      tick();
      draw();
      animRef.current = requestAnimationFrame(loop);
    };
    loop();
    return () => {
      running = false;
      cancelAnimationFrame(animRef.current);
    };
  }, [tick, draw]);

  // Mouse helpers
  const screenToWorld = useCallback((sx: number, sy: number) => {
    return {
      x: (sx - offsetRef.current.x) / scaleRef.current,
      y: (sy - offsetRef.current.y) / scaleRef.current,
    };
  }, []);

  const findNodeAt = useCallback((wx: number, wy: number): SimNode | null => {
    const nodes = nodesRef.current;
    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i];
      const r = n.detected ? 20 + Math.min(n.assetCount * 2, 15) : 14;
      const dx = wx - n.x;
      const dy = wy - n.y;
      if (dx * dx + dy * dy < r * r) return n;
    }
    return null;
  }, []);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const sx = e.clientX - rect.left;
    const sy = e.clientY - rect.top;
    const { x, y } = screenToWorld(sx, sy);
    const node = findNodeAt(x, y);

    if (node) {
      dragNodeRef.current = node;
      node.fx = node.x;
      node.fy = node.y;
    } else {
      isPanningRef.current = true;
    }
    lastMouseRef.current = { x: sx, y: sy };
  }, [screenToWorld, findNodeAt]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const sx = e.clientX - rect.left;
    const sy = e.clientY - rect.top;

    if (dragNodeRef.current) {
      const { x, y } = screenToWorld(sx, sy);
      dragNodeRef.current.fx = x;
      dragNodeRef.current.fy = y;
      dragNodeRef.current.x = x;
      dragNodeRef.current.y = y;
    } else if (isPanningRef.current) {
      const dx = sx - lastMouseRef.current.x;
      const dy = sy - lastMouseRef.current.y;
      offsetRef.current.x += dx;
      offsetRef.current.y += dy;
    } else {
      const { x, y } = screenToWorld(sx, sy);
      const node = findNodeAt(x, y);
      setHoveredNode(node);
      if (canvasRef.current) {
        canvasRef.current.style.cursor = node ? "pointer" : "grab";
      }
    }
    lastMouseRef.current = { x: sx, y: sy };
  }, [screenToWorld, findNodeAt]);

  const handleMouseUp = useCallback(() => {
    if (dragNodeRef.current) {
      dragNodeRef.current.fx = null;
      dragNodeRef.current.fy = null;
      dragNodeRef.current = null;
    }
    isPanningRef.current = false;
  }, []);

  const handleClick = useCallback((e: React.MouseEvent) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const sx = e.clientX - rect.left;
    const sy = e.clientY - rect.top;
    const { x, y } = screenToWorld(sx, sy);
    const node = findNodeAt(x, y);
    if (node && onNodeClick) {
      // Convert SimNode back to TechDepNode for the callback
      onNodeClick({
        id: node.id,
        name: node.name,
        category: node.category,
        assetCount: node.assetCount,
        detected: node.detected,
        version: node.version,
        isOutdated: node.isOutdated,
      });
    }

    // Check legend click
    const legendX = width - 180;
    let legendY = 20;
    for (const { category } of graph.categories) {
      if (sx >= legendX - 12 && sx <= legendX + 168 && sy >= legendY - 4 && sy <= legendY + 18) {
        setSelectedCategory(prev => prev === category ? null : category);
        return;
      }
      legendY += 22;
    }
  }, [screenToWorld, findNodeAt, onNodeClick, width, graph.categories]);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const sx = e.clientX - rect.left;
    const sy = e.clientY - rect.top;

    const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
    const newScale = Math.max(0.2, Math.min(5, scaleRef.current * zoomFactor));

    // Zoom toward mouse position
    offsetRef.current.x = sx - (sx - offsetRef.current.x) * (newScale / scaleRef.current);
    offsetRef.current.y = sy - (sy - offsetRef.current.y) * (newScale / scaleRef.current);
    scaleRef.current = newScale;
  }, []);

  return (
    <canvas
      ref={canvasRef}
      width={width}
      height={height}
      className="rounded-lg border border-[#1A2332] cursor-grab"
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
      onClick={handleClick}
      onWheel={handleWheel}
    />
  );
}
