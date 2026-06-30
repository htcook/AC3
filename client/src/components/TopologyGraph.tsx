/**
 * TopologyGraph — Interactive D3.js force-directed network topology visualizer.
 *
 * Renders nodes (hosts, routers, scanners, DNS servers) and edges (scan traffic,
 * route hops, DNS queries, HTTP/TLS connections) as a draggable, zoomable SVG graph.
 * Nodes are sized by traffic volume and colored by type/severity. Edges are styled
 * by protocol type with animated dashes for active connections.
 */
import { useEffect, useRef, useState, useCallback } from "react";
import * as d3 from "d3";

// ── Types ──────────────────────────────────────────────────────

interface TopologyNode {
  id: string;
  label: string;
  type: string;
  ip: string;
  hostname?: string;
  os?: string;
  ports: number[];
  services: string[];
  findingCount: number;
  maxSeverity: string;
  size: number;
  color: string;
  group?: string;
}

interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  label?: string;
  protocol: string;
  port?: number;
  bytes: number;
  packets: number;
  findingCount: number;
  width: number;
  color: string;
  dashed: boolean;
  animated: boolean;
}

interface TopologyStats {
  totalNodes: number;
  totalEdges: number;
  totalHosts: number;
  totalRouters: number;
  totalFindings: number;
  protocols: string[];
  maxHopDistance: number;
}

interface TopologyGraphProps {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  stats: TopologyStats;
  width?: number;
  height?: number;
}

// ── Node icon paths (SVG) ──────────────────────────────────────

const NODE_ICONS: Record<string, string> = {
  scanner:
    "M15.5 14h-.79l-.28-.27A6.471 6.471 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z",
  target:
    "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm0-14c-3.31 0-6 2.69-6 6s2.69 6 6 6 6-2.69 6-6-2.69-6-6-6zm0 10c-2.21 0-4-1.79-4-4s1.79-4 4-4 4 1.79 4 4-1.79 4-4 4zm0-6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z",
  router:
    "M20 2H4c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zM8 20H4v-4h4v4zm0-6H4v-4h4v4zm0-6H4V4h4v4zm6 12h-4v-4h4v4zm0-6h-4v-4h4v4zm0-6h-4V4h4v4zm6 12h-4v-4h4v4zm0-6h-4v-4h4v4zm0-6h-4V4h4v4z",
  dns_server:
    "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z",
  external:
    "M19 19H5V5h7V3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z",
  cdn:
    "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z",
  unknown:
    "M11 18h2v-2h-2v2zm1-16C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm0-14c-2.21 0-4 1.79-4 4h2c0-1.1.9-2 2-2s2 .9 2 2c0 2-3 1.75-3 5h2c0-2.25 3-2.5 3-5 0-2.21-1.79-4-4-4z",
};

const SEVERITY_GLOW: Record<string, string> = {
  critical: "rgba(239,68,68,0.6)",
  high: "rgba(248,113,113,0.5)",
  medium: "rgba(251,191,36,0.4)",
  low: "rgba(96,165,250,0.3)",
  info: "rgba(156,163,175,0.2)",
  none: "rgba(100,100,100,0.1)",
};

// ── Component ──────────────────────────────────────────────────

export default function TopologyGraph({ nodes, edges, stats, width: propWidth, height: propHeight }: TopologyGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<TopologyEdge | null>(null);
  const [dimensions, setDimensions] = useState({ width: propWidth || 1000, height: propHeight || 600 });

  // Responsive sizing
  useEffect(() => {
    if (propWidth && propHeight) return;
    const container = containerRef.current;
    if (!container) return;
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width } = entry.contentRect;
        setDimensions({ width: Math.max(width, 400), height: Math.max(Math.min(width * 0.6, 700), 400) });
      }
    });
    observer.observe(container);
    return () => observer.disconnect();
  }, [propWidth, propHeight]);

  // D3 force simulation
  useEffect(() => {
    if (!svgRef.current || nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const { width, height } = dimensions;

    // Prepare simulation data (D3 mutates these)
    type SimNode = TopologyNode & d3.SimulationNodeDatum;
    type SimEdge = TopologyEdge & { source: any; target: any };

    const simNodes: SimNode[] = nodes.map((n) => ({ ...n }));
    const simEdges: SimEdge[] = edges
      .filter((e) => {
        const srcExists = simNodes.some((n) => n.id === e.source);
        const tgtExists = simNodes.some((n) => n.id === e.target);
        return srcExists && tgtExists;
      })
      .map((e) => ({ ...e }));

    // Defs for markers and filters
    const defs = svg.append("defs");

    // Arrow markers per edge color
    const uniqueColors = [...new Set(simEdges.map((e) => e.color))];
    uniqueColors.forEach((color) => {
      defs
        .append("marker")
        .attr("id", `arrow-${color.replace("#", "")}`)
        .attr("viewBox", "0 -5 10 10")
        .attr("refX", 20)
        .attr("refY", 0)
        .attr("markerWidth", 6)
        .attr("markerHeight", 6)
        .attr("orient", "auto")
        .append("path")
        .attr("d", "M0,-5L10,0L0,5")
        .attr("fill", color)
        .attr("opacity", 0.7);
    });

    // Glow filter for nodes with findings
    const glowFilter = defs.append("filter").attr("id", "glow").attr("x", "-50%").attr("y", "-50%").attr("width", "200%").attr("height", "200%");
    glowFilter.append("feGaussianBlur").attr("stdDeviation", "3").attr("result", "coloredBlur");
    const feMerge = glowFilter.append("feMerge");
    feMerge.append("feMergeNode").attr("in", "coloredBlur");
    feMerge.append("feMergeNode").attr("in", "SourceGraphic");

    // Container group for zoom/pan
    const g = svg.append("g");

    // Zoom behavior
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });
    svg.call(zoom);

    // Force simulation
    const simulation = d3
      .forceSimulation<SimNode>(simNodes)
      .force(
        "link",
        d3
          .forceLink<SimNode, SimEdge>(simEdges)
          .id((d) => d.id)
          .distance((d) => {
            if (d.type === "route_hop") return 80;
            if (d.type === "dns_query") return 120;
            return 150;
          })
      )
      .force("charge", d3.forceManyBody().strength(-400).distanceMax(500))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius((d: any) => (d.size || 20) + 10))
      .force("x", d3.forceX(width / 2).strength(0.05))
      .force("y", d3.forceY(height / 2).strength(0.05));

    // Edge lines
    const edgeGroup = g.append("g").attr("class", "edges");
    const edgePaths = edgeGroup
      .selectAll("line")
      .data(simEdges)
      .join("line")
      .attr("stroke", (d) => d.color)
      .attr("stroke-width", (d) => Math.max(d.width, 1))
      .attr("stroke-opacity", 0.6)
      .attr("stroke-dasharray", (d) => (d.dashed ? "6,3" : "none"))
      .attr("marker-end", (d) => `url(#arrow-${d.color.replace("#", "")})`)
      .style("cursor", "pointer")
      .on("click", (_event, d) => {
        setSelectedEdge(d);
        setSelectedNode(null);
      });

    // Edge labels (for important edges)
    const edgeLabels = edgeGroup
      .selectAll("text")
      .data(simEdges.filter((e) => e.label || e.findingCount > 0))
      .join("text")
      .attr("font-size", "9px")
      .attr("fill", "#9ca3af")
      .attr("text-anchor", "middle")
      .attr("dy", -4)
      .text((d) => d.label || `${d.findingCount} findings`);

    // Node groups
    const nodeGroup = g.append("g").attr("class", "nodes");
    const nodeGs = nodeGroup
      .selectAll("g")
      .data(simNodes)
      .join("g")
      .style("cursor", "pointer")
      .on("click", (_event, d) => {
        setSelectedNode(d);
        setSelectedEdge(null);
      })
      .call(
        d3
          .drag<SVGGElement, SimNode>()
          .on("start", (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      );

    // Node circles with glow
    nodeGs
      .append("circle")
      .attr("r", (d) => Math.max(d.size * 1.5, 12))
      .attr("fill", (d) => d.color)
      .attr("fill-opacity", 0.15)
      .attr("stroke", (d) => d.color)
      .attr("stroke-width", 2)
      .attr("stroke-opacity", 0.8)
      .attr("filter", (d) => (d.findingCount > 0 ? "url(#glow)" : "none"));

    // Severity ring for nodes with findings
    nodeGs
      .filter((d) => d.findingCount > 0)
      .append("circle")
      .attr("r", (d) => Math.max(d.size * 1.5, 12) + 4)
      .attr("fill", "none")
      .attr("stroke", (d) => SEVERITY_GLOW[d.maxSeverity] || SEVERITY_GLOW.none)
      .attr("stroke-width", 2)
      .attr("stroke-dasharray", "3,2")
      .attr("opacity", 0.8);

    // Node icon
    nodeGs
      .append("path")
      .attr("d", (d) => NODE_ICONS[d.type] || NODE_ICONS.unknown)
      .attr("fill", (d) => d.color)
      .attr("opacity", 0.9)
      .attr("transform", (d) => {
        const s = Math.max(d.size * 0.08, 0.5);
        return `scale(${s}) translate(-12,-12)`;
      });

    // Node label
    nodeGs
      .append("text")
      .attr("dy", (d) => Math.max(d.size * 1.5, 12) + 14)
      .attr("text-anchor", "middle")
      .attr("font-size", "10px")
      .attr("fill", "#e5e7eb")
      .attr("font-family", "monospace")
      .text((d) => d.hostname || d.ip);

    // Node type badge
    nodeGs
      .append("text")
      .attr("dy", (d) => Math.max(d.size * 1.5, 12) + 26)
      .attr("text-anchor", "middle")
      .attr("font-size", "8px")
      .attr("fill", "#6b7280")
      .text((d) => {
        const parts: string[] = [d.type];
        if (d.ports.length > 0) parts.push(`${d.ports.length} ports`);
        if (d.findingCount > 0) parts.push(`${d.findingCount} findings`);
        return parts.join(" · ");
      });

    // Finding count badge
    nodeGs
      .filter((d) => d.findingCount > 0)
      .append("g")
      .attr("transform", (d) => {
        const r = Math.max(d.size * 1.5, 12);
        return `translate(${r * 0.7}, ${-r * 0.7})`;
      })
      .each(function (d) {
        const badge = d3.select(this);
        badge
          .append("circle")
          .attr("r", 8)
          .attr("fill", d.maxSeverity === "critical" ? "#ef4444" : d.maxSeverity === "high" ? "#f87171" : "#fbbf24")
          .attr("stroke", "#1f2937")
          .attr("stroke-width", 1.5);
        badge
          .append("text")
          .attr("text-anchor", "middle")
          .attr("dy", "0.35em")
          .attr("font-size", "8px")
          .attr("fill", "#fff")
          .attr("font-weight", "bold")
          .text(d.findingCount);
      });

    // Tick
    simulation.on("tick", () => {
      edgePaths
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);

      edgeLabels
        .attr("x", (d: any) => (d.source.x + d.target.x) / 2)
        .attr("y", (d: any) => (d.source.y + d.target.y) / 2);

      nodeGs.attr("transform", (d: any) => `translate(${d.x},${d.y})`);
    });

    // Initial zoom to fit
    setTimeout(() => {
      const bounds = (g.node() as SVGGElement)?.getBBox();
      if (bounds && bounds.width > 0) {
        const scale = Math.min(width / (bounds.width + 100), height / (bounds.height + 100), 1.5);
        const tx = width / 2 - (bounds.x + bounds.width / 2) * scale;
        const ty = height / 2 - (bounds.y + bounds.height / 2) * scale;
        svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
      }
    }, 1500);

    return () => {
      simulation.stop();
    };
  }, [nodes, edges, dimensions]);

  const handleZoomIn = useCallback(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.transition().duration(300).call(d3.zoom<SVGSVGElement, unknown>().scaleBy as any, 1.3);
  }, []);

  const handleZoomOut = useCallback(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.transition().duration(300).call(d3.zoom<SVGSVGElement, unknown>().scaleBy as any, 0.7);
  }, []);

  const handleReset = useCallback(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.transition().duration(500).call(d3.zoom<SVGSVGElement, unknown>().transform as any, d3.zoomIdentity);
  }, []);

  return (
    <div ref={containerRef} className="relative w-full">
      {/* Graph Canvas */}
      <div className="relative bg-[#0a0f1a] border border-border/30 rounded-lg overflow-hidden" style={{ height: dimensions.height }}>
        {/* Controls overlay */}
        <div className="absolute top-3 right-3 z-10 flex flex-col gap-1">
          <button
            onClick={handleZoomIn}
            className="w-8 h-8 bg-gray-800/80 hover:bg-gray-700/80 border border-gray-600/50 rounded text-gray-300 text-sm flex items-center justify-center backdrop-blur-sm"
          >
            +
          </button>
          <button
            onClick={handleZoomOut}
            className="w-8 h-8 bg-gray-800/80 hover:bg-gray-700/80 border border-gray-600/50 rounded text-gray-300 text-sm flex items-center justify-center backdrop-blur-sm"
          >
            -
          </button>
          <button
            onClick={handleReset}
            className="w-8 h-8 bg-gray-800/80 hover:bg-gray-700/80 border border-gray-600/50 rounded text-gray-300 text-[9px] flex items-center justify-center backdrop-blur-sm"
          >
            FIT
          </button>
        </div>

        {/* Legend overlay */}
        <div className="absolute bottom-3 left-3 z-10 bg-gray-900/90 backdrop-blur-sm border border-gray-700/50 rounded-lg p-3 text-xs space-y-1.5">
          <div className="text-gray-400 font-semibold mb-1">Node Types</div>
          {[
            { type: "scanner", color: "#3b82f6", label: "Scanner" },
            { type: "target", color: "#ef4444", label: "Target" },
            { type: "router", color: "#a855f7", label: "Router" },
            { type: "dns_server", color: "#06b6d4", label: "DNS Server" },
            { type: "external", color: "#6b7280", label: "External" },
          ].map((item) => (
            <div key={item.type} className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full border" style={{ borderColor: item.color, backgroundColor: item.color + "30" }} />
              <span className="text-gray-300">{item.label}</span>
            </div>
          ))}
          <div className="text-gray-400 font-semibold mt-2 mb-1">Edge Types</div>
          {[
            { color: "#ef4444", label: "Scan Traffic", dashed: false },
            { color: "#a855f7", label: "Route Hop", dashed: true },
            { color: "#06b6d4", label: "DNS Query", dashed: false },
            { color: "#22c55e", label: "HTTP", dashed: false },
            { color: "#3b82f6", label: "TLS", dashed: false },
          ].map((item) => (
            <div key={item.label} className="flex items-center gap-2">
              <div className="w-4 h-0 border-t-2" style={{ borderColor: item.color, borderStyle: item.dashed ? "dashed" : "solid" }} />
              <span className="text-gray-300">{item.label}</span>
            </div>
          ))}
        </div>

        {/* Stats overlay */}
        <div className="absolute top-3 left-3 z-10 bg-gray-900/90 backdrop-blur-sm border border-gray-700/50 rounded-lg px-3 py-2 text-xs">
          <div className="flex items-center gap-4 text-gray-300">
            <span>
              <span className="text-blue-400 font-mono font-bold">{stats.totalNodes}</span> nodes
            </span>
            <span>
              <span className="text-violet-400 font-mono font-bold">{stats.totalEdges}</span> edges
            </span>
            <span>
              <span className="text-amber-400 font-mono font-bold">{stats.totalFindings}</span> findings
            </span>
            <span>
              <span className="text-emerald-400 font-mono font-bold">{stats.protocols.length}</span> protocols
            </span>
          </div>
        </div>

        <svg ref={svgRef} width={dimensions.width} height={dimensions.height} className="w-full h-full" />
      </div>

      {/* Detail Panel */}
      {(selectedNode || selectedEdge) && (
        <div className="mt-3 bg-card/50 border border-border/50 rounded-lg p-4">
          {selectedNode && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full" style={{ backgroundColor: selectedNode.color }} />
                  <span className="font-mono font-semibold text-sm">{selectedNode.ip}</span>
                  {selectedNode.hostname && <span className="text-muted-foreground text-sm">({selectedNode.hostname})</span>}
                </div>
                <button onClick={() => setSelectedNode(null)} className="text-muted-foreground hover:text-foreground text-xs">
                  Close
                </button>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                <div>
                  <span className="text-muted-foreground">Type: </span>
                  <span className="font-mono">{selectedNode.type}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">OS: </span>
                  <span className="font-mono">{selectedNode.os || "Unknown"}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Findings: </span>
                  <span className="font-mono text-amber-400">{selectedNode.findingCount}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Severity: </span>
                  <span
                    className={`font-mono font-semibold ${
                      selectedNode.maxSeverity === "critical"
                        ? "text-red-500"
                        : selectedNode.maxSeverity === "high"
                        ? "text-red-400"
                        : selectedNode.maxSeverity === "medium"
                        ? "text-amber-400"
                        : "text-blue-400"
                    }`}
                  >
                    {selectedNode.maxSeverity}
                  </span>
                </div>
              </div>
              {selectedNode.ports.length > 0 && (
                <div className="text-xs">
                  <span className="text-muted-foreground">Ports: </span>
                  <span className="font-mono">{selectedNode.ports.join(", ")}</span>
                </div>
              )}
              {selectedNode.services.length > 0 && (
                <div className="text-xs">
                  <span className="text-muted-foreground">Services: </span>
                  <span className="font-mono">{selectedNode.services.filter(Boolean).join(", ")}</span>
                </div>
              )}
            </div>
          )}
          {selectedEdge && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm">
                  <span className="font-mono">{selectedEdge.source}</span>
                  <span className="text-muted-foreground">→</span>
                  <span className="font-mono">{selectedEdge.target}</span>
                  <div className="px-2 py-0.5 rounded text-xs border" style={{ borderColor: selectedEdge.color + "50", color: selectedEdge.color }}>
                    {selectedEdge.type}
                  </div>
                </div>
                <button onClick={() => setSelectedEdge(null)} className="text-muted-foreground hover:text-foreground text-xs">
                  Close
                </button>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
                <div>
                  <span className="text-muted-foreground">Protocol: </span>
                  <span className="font-mono">{selectedEdge.protocol}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Port: </span>
                  <span className="font-mono">{selectedEdge.port || "—"}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Packets: </span>
                  <span className="font-mono">{selectedEdge.packets.toLocaleString()}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Bytes: </span>
                  <span className="font-mono">{selectedEdge.bytes.toLocaleString()}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Findings: </span>
                  <span className="font-mono text-amber-400">{selectedEdge.findingCount}</span>
                </div>
              </div>
              {selectedEdge.label && (
                <div className="text-xs">
                  <span className="text-muted-foreground">Label: </span>
                  <span className="font-mono">{selectedEdge.label}</span>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
