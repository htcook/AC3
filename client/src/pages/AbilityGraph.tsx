// @ts-nocheck
import { useState, useMemo, useCallback, useRef, useEffect } from "react";
import { useRoute, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import {
  GitBranch,
  Plus,
  Play,
  Trash2,
  Eye,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Shield,
  Zap,
  Target,
  ArrowRight,
  RefreshCw,
  Download,
  Settings,
  Brain,
  Network,
  Layers,
  ChevronRight,
  Lock,
  Unlock,
  BarChart3,
  Users,
  ArrowLeftRight,
} from "lucide-react";

// ─── Safety tier colors ─────────────────────────────────────────────────
const SAFETY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  passive: { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/30" },
  low_impact: { bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/30" },
  medium_impact: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
  high_impact: { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/30" },
  critical_impact: { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/30" },
};

const STATUS_COLORS: Record<string, { bg: string; text: string; icon: any }> = {
  pending: { bg: "bg-muted/50", text: "text-muted-foreground", icon: Clock },
  ready: { bg: "bg-blue-500/10", text: "text-blue-400", icon: Zap },
  running: { bg: "bg-amber-500/10", text: "text-amber-400", icon: RefreshCw },
  success: { bg: "bg-emerald-500/10", text: "text-emerald-400", icon: CheckCircle2 },
  failed: { bg: "bg-red-500/10", text: "text-red-400", icon: XCircle },
  skipped: { bg: "bg-muted/30", text: "text-muted-foreground", icon: ArrowRight },
  blocked: { bg: "bg-red-500/5", text: "text-red-300", icon: Lock },
};

const TACTIC_COLORS: Record<string, string> = {
  "reconnaissance": "#60a5fa",
  "resource-development": "#818cf8",
  "initial-access": "#f472b6",
  "execution": "#fb923c",
  "persistence": "#a78bfa",
  "privilege-escalation": "#e879f9",
  "defense-evasion": "#34d399",
  "credential-access": "#fbbf24",
  "discovery": "#22d3ee",
  "lateral-movement": "#f87171",
  "collection": "#c084fc",
  "command-and-control": "#94a3b8",
  "exfiltration": "#ef4444",
  "impact": "#dc2626",
};

// ─── Graph Visualizer Component ─────────────────────────────────────────

function GraphVisualizer({
  nodes,
  edges,
  allowedNodes = [],
  blockedNodes = [],
  selectedNodeId,
  onNodeClick,
}: {
  nodes: any[];
  edges: any[];
  allowedNodes?: string[];
  blockedNodes?: string[];
  selectedNodeId?: string | null;
  onNodeClick?: (nodeId: string) => void;
}) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [viewBox, setViewBox] = useState({ x: 0, y: 0, w: 1200, h: 800 });
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });

  // Compute layout
  const layout = useMemo(() => {
    if (!nodes.length) return { nodes: [], edges: [], width: 1200, height: 800 };

    const NODE_W = 220;
    const NODE_H = 72;
    const LAYER_GAP = 160;
    const NODE_GAP = 40;

    // Group by layer
    const layers = new Map<number, any[]>();
    for (const n of nodes) {
      const layer = n.layer ?? n.order ?? 0;
      if (!layers.has(layer)) layers.set(layer, []);
      layers.get(layer)!.push(n);
    }

    const sortedLayers = Array.from(layers.entries()).sort((a, b) => a[0] - b[0]);
    const maxNodesInLayer = Math.max(...sortedLayers.map(([, ns]) => ns.length), 1);
    const totalWidth = Math.max(maxNodesInLayer * (NODE_W + NODE_GAP), 800);
    const totalHeight = Math.max(sortedLayers.length * (NODE_H + LAYER_GAP) + 100, 600);

    const positionedNodes = nodes.map(n => {
      const layer = n.layer ?? n.order ?? 0;
      const layerNodes = layers.get(layer) || [];
      const idx = layerNodes.indexOf(n);
      const layerWidth = layerNodes.length * (NODE_W + NODE_GAP) - NODE_GAP;
      const startX = (totalWidth - layerWidth) / 2;

      return {
        ...n,
        px: startX + idx * (NODE_W + NODE_GAP) + NODE_W / 2,
        py: 60 + layer * (NODE_H + LAYER_GAP) + NODE_H / 2,
        w: NODE_W,
        h: NODE_H,
      };
    });

    const nodePositions = new Map(positionedNodes.map(n => [n.id, n]));

    const positionedEdges = edges.map(e => {
      const source = nodePositions.get(e.sourceNodeId);
      const target = nodePositions.get(e.targetNodeId);
      if (!source || !target) return null;
      return {
        ...e,
        x1: source.px,
        y1: source.py + NODE_H / 2,
        x2: target.px,
        y2: target.py - NODE_H / 2,
      };
    }).filter(Boolean);

    return { nodes: positionedNodes, edges: positionedEdges, width: totalWidth, height: totalHeight };
  }, [nodes, edges]);

  // Set initial viewBox
  useEffect(() => {
    if (layout.width && layout.height) {
      setViewBox({ x: -20, y: -20, w: layout.width + 40, h: layout.height + 40 });
    }
  }, [layout.width, layout.height]);

  // Pan handlers
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button === 0 && !e.target?.closest?.(".graph-node")) {
      setIsPanning(true);
      setPanStart({ x: e.clientX, y: e.clientY });
    }
  }, []);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!isPanning) return;
    const dx = (e.clientX - panStart.x) * (viewBox.w / (svgRef.current?.clientWidth || 1));
    const dy = (e.clientY - panStart.y) * (viewBox.h / (svgRef.current?.clientHeight || 1));
    setViewBox(v => ({ ...v, x: v.x - dx, y: v.y - dy }));
    setPanStart({ x: e.clientX, y: e.clientY });
  }, [isPanning, panStart, viewBox]);

  const handleMouseUp = useCallback(() => setIsPanning(false), []);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const scale = e.deltaY > 0 ? 1.1 : 0.9;
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;
    const mx = ((e.clientX - rect.left) / rect.width) * viewBox.w + viewBox.x;
    const my = ((e.clientY - rect.top) / rect.height) * viewBox.h + viewBox.y;
    setViewBox(v => ({
      x: mx - (mx - v.x) * scale,
      y: my - (my - v.y) * scale,
      w: v.w * scale,
      h: v.h * scale,
    }));
  }, [viewBox]);

  const blockedSet = useMemo(() => new Set(blockedNodes), [blockedNodes]);

  return (
    <div className="relative w-full h-full min-h-[500px] bg-background/50 rounded-lg border border-border/50 overflow-hidden">
      <svg
        ref={svgRef}
        className="w-full h-full cursor-grab active:cursor-grabbing"
        viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
      >
        <defs>
          <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="oklch(0.7 0.05 200)" />
          </marker>
          <marker id="arrowhead-success" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="oklch(0.75 0.15 160)" />
          </marker>
          <marker id="arrowhead-failure" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="oklch(0.65 0.2 25)" />
          </marker>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Edges */}
        {layout.edges.map((edge: any) => {
          if (!edge) return null;
          const isFailure = edge.condition === "on_failure";
          const isConditional = edge.condition === "on_output_match" || edge.condition === "conditional";
          const color = isFailure
            ? "oklch(0.65 0.2 25)"
            : isConditional
              ? "oklch(0.7 0.15 280)"
              : "oklch(0.55 0.05 200)";
          const markerId = isFailure ? "arrowhead-failure" : "arrowhead-success";

          // Curved path
          const midY = (edge.y1 + edge.y2) / 2;
          const dx = edge.x2 - edge.x1;
          const curve = Math.abs(dx) > 10 ? dx * 0.3 : 0;

          return (
            <g key={edge.id}>
              <path
                d={`M ${edge.x1} ${edge.y1} C ${edge.x1 + curve} ${midY}, ${edge.x2 - curve} ${midY}, ${edge.x2} ${edge.y2}`}
                fill="none"
                stroke={color}
                strokeWidth="2"
                strokeDasharray={isConditional ? "6 4" : isFailure ? "4 4" : "none"}
                markerEnd={`url(#${markerId})`}
                opacity={0.7}
              />
              {edge.label && (
                <text
                  x={(edge.x1 + edge.x2) / 2}
                  y={midY - 8}
                  textAnchor="middle"
                  fill="oklch(0.6 0.02 250)"
                  fontSize="10"
                  fontFamily="JetBrains Mono, monospace"
                >
                  {edge.label.length > 30 ? edge.label.slice(0, 30) + "…" : edge.label}
                </text>
              )}
            </g>
          );
        })}

        {/* Nodes */}
        {layout.nodes.map((node: any) => {
          const isBlocked = blockedSet.has(node.id);
          const isSelected = node.id === selectedNodeId;
          const tacticColor = TACTIC_COLORS[node.tactic] || "#94a3b8";
          const statusInfo = STATUS_COLORS[node.status] || STATUS_COLORS.pending;

          return (
            <g
              key={node.id}
              className="graph-node cursor-pointer"
              onClick={() => onNodeClick?.(node.id)}
              style={{ transition: "transform 0.2s" }}
            >
              {/* Selection glow */}
              {isSelected && (
                <rect
                  x={node.px - node.w / 2 - 4}
                  y={node.py - node.h / 2 - 4}
                  width={node.w + 8}
                  height={node.h + 8}
                  rx="12"
                  fill="none"
                  stroke="oklch(0.85 0.18 175)"
                  strokeWidth="2"
                  filter="url(#glow)"
                  opacity="0.8"
                />
              )}

              {/* Node background */}
              <rect
                x={node.px - node.w / 2}
                y={node.py - node.h / 2}
                width={node.w}
                height={node.h}
                rx="10"
                fill={isBlocked ? "oklch(0.15 0.02 0)" : "oklch(0.18 0.02 250)"}
                stroke={isSelected ? "oklch(0.85 0.18 175)" : isBlocked ? "oklch(0.3 0.08 25)" : tacticColor}
                strokeWidth={isSelected ? "2" : "1"}
                opacity={isBlocked ? 0.5 : 1}
              />

              {/* Tactic color bar */}
              <rect
                x={node.px - node.w / 2}
                y={node.py - node.h / 2}
                width="4"
                height={node.h}
                rx="2"
                fill={tacticColor}
                opacity={isBlocked ? 0.3 : 0.8}
              />

              {/* Label */}
              <text
                x={node.px - node.w / 2 + 14}
                y={node.py - 10}
                fill={isBlocked ? "oklch(0.5 0.02 250)" : "oklch(0.9 0.02 250)"}
                fontSize="12"
                fontWeight="600"
                fontFamily="Inter, sans-serif"
              >
                {node.label.length > 24 ? node.label.slice(0, 24) + "…" : node.label}
              </text>

              {/* Technique ID */}
              <text
                x={node.px - node.w / 2 + 14}
                y={node.py + 8}
                fill="oklch(0.6 0.05 200)"
                fontSize="10"
                fontFamily="JetBrains Mono, monospace"
              >
                {node.techniqueId}
              </text>

              {/* Tactic label */}
              <text
                x={node.px - node.w / 2 + 14}
                y={node.py + 24}
                fill={tacticColor}
                fontSize="9"
                fontFamily="JetBrains Mono, monospace"
                opacity="0.7"
              >
                {node.tactic}
              </text>

              {/* Safety tier indicator */}
              <circle
                cx={node.px + node.w / 2 - 16}
                cy={node.py - node.h / 2 + 16}
                r="6"
                fill={
                  node.safetyTier === "passive" ? "oklch(0.75 0.15 160)"
                    : node.safetyTier === "low_impact" ? "oklch(0.7 0.15 240)"
                      : node.safetyTier === "medium_impact" ? "oklch(0.7 0.15 85)"
                        : node.safetyTier === "high_impact" ? "oklch(0.65 0.18 50)"
                          : "oklch(0.6 0.2 25)"
                }
                opacity={isBlocked ? 0.3 : 0.8}
              />

              {/* Blocked overlay */}
              {isBlocked && (
                <>
                  <line
                    x1={node.px - node.w / 2 + 8}
                    y1={node.py - node.h / 2 + 8}
                    x2={node.px + node.w / 2 - 8}
                    y2={node.py + node.h / 2 - 8}
                    stroke="oklch(0.5 0.15 25)"
                    strokeWidth="1.5"
                    opacity="0.5"
                  />
                  <text
                    x={node.px + node.w / 2 - 16}
                    y={node.py + node.h / 2 - 8}
                    fill="oklch(0.6 0.15 25)"
                    fontSize="8"
                    fontFamily="JetBrains Mono, monospace"
                    textAnchor="end"
                  >
                    BLOCKED
                  </text>
                </>
              )}
            </g>
          );
        })}
      </svg>

      {/* Zoom controls */}
      <div className="absolute bottom-3 right-3 flex gap-1">
        <Button
          variant="outline"
          size="sm"
          className="h-7 w-7 p-0 bg-background/80"
          onClick={() => setViewBox(v => ({ ...v, w: v.w * 0.8, h: v.h * 0.8 }))}
        >
          +
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="h-7 w-7 p-0 bg-background/80"
          onClick={() => setViewBox(v => ({ ...v, w: v.w * 1.2, h: v.h * 1.2 }))}
        >
          −
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="h-7 px-2 bg-background/80"
          onClick={() => setViewBox({ x: -20, y: -20, w: layout.width + 40, h: layout.height + 40 })}
        >
          Fit
        </Button>
      </div>

      {/* Legend */}
      <div className="absolute top-3 left-3 bg-background/90 border border-border/50 rounded-lg p-2 text-xs space-y-1">
        <div className="font-semibold text-foreground/80 mb-1">Edge Types</div>
        <div className="flex items-center gap-2">
          <div className="w-6 h-0.5 bg-[oklch(0.55_0.05_200)]" />
          <span className="text-muted-foreground">Success</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-6 h-0.5 bg-[oklch(0.65_0.2_25)] border-dashed" style={{ borderTop: "2px dashed oklch(0.65 0.2 25)", height: 0 }} />
          <span className="text-muted-foreground">Failure</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-6 h-0.5" style={{ borderTop: "2px dashed oklch(0.7 0.15 280)", height: 0 }} />
          <span className="text-muted-foreground">Conditional</span>
        </div>
      </div>
    </div>
  );
}

// ─── Node Detail Panel ──────────────────────────────────────────────────

function NodeDetailPanel({ node, onClose }: { node: any; onClose: () => void }) {
  if (!node) return null;
  const safetyStyle = SAFETY_COLORS[node.safetyTier] || SAFETY_COLORS.medium_impact;
  const statusStyle = STATUS_COLORS[node.status] || STATUS_COLORS.pending;
  const StatusIcon = statusStyle.icon;

  return (
    <Card className="border-border/50 bg-card/80 backdrop-blur">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-base">{node.label}</CardTitle>
            <CardDescription className="font-mono text-xs mt-1">
              {node.techniqueId} — {node.tactic}
            </CardDescription>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} className="h-7 w-7 p-0">
            ×
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        {/* Status & Safety */}
        <div className="flex gap-2">
          <Badge variant="outline" className={`${statusStyle.bg} ${statusStyle.text} border-0`}>
            <StatusIcon className="w-3 h-3 mr-1" />
            {node.status}
          </Badge>
          <Badge variant="outline" className={`${safetyStyle.bg} ${safetyStyle.text} ${safetyStyle.border}`}>
            <Shield className="w-3 h-3 mr-1" />
            {node.safetyTier.replace("_", " ")}
          </Badge>
        </div>

        {/* Description */}
        {node.description && (
          <div>
            <Label className="text-xs text-muted-foreground">Description</Label>
            <p className="text-foreground/80 mt-1">{node.description}</p>
          </div>
        )}

        {/* Execution details */}
        <div className="grid grid-cols-2 gap-3">
          {node.executor && (
            <div>
              <Label className="text-xs text-muted-foreground">Executor</Label>
              <p className="font-mono text-xs">{node.executor}</p>
            </div>
          )}
          {node.platform && (
            <div>
              <Label className="text-xs text-muted-foreground">Platform</Label>
              <p className="font-mono text-xs">{node.platform}</p>
            </div>
          )}
          <div>
            <Label className="text-xs text-muted-foreground">Timeout</Label>
            <p className="font-mono text-xs">{node.timeout}s</p>
          </div>
          <div>
            <Label className="text-xs text-muted-foreground">Retries</Label>
            <p className="font-mono text-xs">{node.retryCount}</p>
          </div>
        </div>

        {/* Command */}
        {node.command && (
          <div>
            <Label className="text-xs text-muted-foreground">Command</Label>
            <pre className="mt-1 p-2 bg-muted/30 rounded text-xs font-mono overflow-x-auto max-h-24 overflow-y-auto">
              {node.command}
            </pre>
          </div>
        )}

        {/* Caldera ability */}
        {node.calderaAbilityId && (
          <div>
            <Label className="text-xs text-muted-foreground">Caldera Ability</Label>
            <p className="font-mono text-xs text-primary">{node.calderaAbilityId}</p>
          </div>
        )}

        {/* Preconditions */}
        {node.preconditions?.length > 0 && (
          <div>
            <Label className="text-xs text-muted-foreground">Preconditions ({node.preconditions.length})</Label>
            <div className="mt-1 space-y-1">
              {node.preconditions.map((p: any, i: number) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  {p.required ? (
                    <Lock className="w-3 h-3 text-amber-400" />
                  ) : (
                    <Unlock className="w-3 h-3 text-muted-foreground" />
                  )}
                  <span className="text-muted-foreground">{p.description}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Exit criteria */}
        {node.exitCriteria?.length > 0 && (
          <div>
            <Label className="text-xs text-muted-foreground">Exit Criteria ({node.exitCriteria.length})</Label>
            <div className="mt-1 space-y-1">
              {node.exitCriteria.map((e: any, i: number) => (
                <div key={i} className="text-xs text-muted-foreground">
                  {e.type}: {e.key} {e.operator} {String(e.value)} — {e.description}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Execution result */}
        {node.executionResult && (
          <div>
            <Label className="text-xs text-muted-foreground">Execution Result</Label>
            <div className="mt-1 p-2 bg-muted/30 rounded space-y-1">
              <div className="text-xs">
                <span className="text-muted-foreground">Exit code:</span>{" "}
                <span className={node.executionResult.exitCode === 0 ? "text-emerald-400" : "text-red-400"}>
                  {node.executionResult.exitCode}
                </span>
              </div>
              {node.executionResult.stdout && (
                <pre className="text-xs font-mono max-h-20 overflow-auto">{node.executionResult.stdout}</pre>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Create Graph Dialog ────────────────────────────────────────────────

function CreateGraphDialog({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [techniqueIds, setTechniqueIds] = useState("");
  const [targetEnv, setTargetEnv] = useState("hybrid");
  const [actorName, setActorName] = useState("");
  const [scanMode, setScanMode] = useState("active-standard");
  const [mode, setMode] = useState<"chain" | "llm">("chain");
  const [objective, setObjective] = useState("");

  const generateFromChain = trpc.abilityGraph.generateFromChain.useMutation({
    onSuccess: (data) => {
      toast.success(`Graph created with ${data.nodeCount} nodes and ${data.edgeCount} edges`);
      setOpen(false);
      resetForm();
      onCreated();
    },
    onError: (err) => toast.error(`Failed: ${err.message}`),
  });

  const generateFromLLM = trpc.abilityGraph.generateFromLLM.useMutation({
    onSuccess: (data) => {
      toast.success(`Graph created with ${data.nodeCount} nodes and ${data.edgeCount} edges`);
      setOpen(false);
      resetForm();
      onCreated();
    },
    onError: (err) => toast.error(`Failed: ${err.message}`),
  });

  const resetForm = () => {
    setName("");
    setTechniqueIds("");
    setTargetEnv("hybrid");
    setActorName("");
    setObjective("");
  };

  const handleCreate = () => {
    const ids = techniqueIds.split(/[,\n]/).map(s => s.trim()).filter(Boolean);
    if (!name || ids.length === 0) {
      toast.error("Name and at least one technique ID are required");
      return;
    }

    if (mode === "chain") {
      generateFromChain.mutate({
        name,
        techniqueIds: ids,
        targetEnvironment: targetEnv,
        actorName: actorName || undefined,
        scanMode: scanMode as any,
      });
    } else {
      generateFromLLM.mutate({
        name,
        techniques: ids.map(id => ({ id, name: id, tactic: "unknown" })),
        targetEnvironment: targetEnv,
        actorName: actorName || undefined,
        objective: objective || undefined,
        scanMode: scanMode as any,
      });
    }
  };

  const isLoading = generateFromChain.isPending || generateFromLLM.isPending;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button className="gap-2">
          <Plus className="w-4 h-4" />
          New Graph
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Create Ability Graph</DialogTitle>
          <DialogDescription>
            Generate a DAG from MITRE ATT&CK technique chains or LLM decomposition.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <Tabs value={mode} onValueChange={(v) => setMode(v as "chain" | "llm")}>
            <TabsList className="w-full">
              <TabsTrigger value="chain" className="flex-1">TTP Chain</TabsTrigger>
              <TabsTrigger value="llm" className="flex-1">LLM Decompose</TabsTrigger>
            </TabsList>
          </Tabs>

          <div>
            <Label>Graph Name</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. APT29 Initial Access Chain"
            />
          </div>

          <div>
            <Label>Technique IDs (comma or newline separated)</Label>
            <Textarea
              value={techniqueIds}
              onChange={(e) => setTechniqueIds(e.target.value)}
              placeholder="T1566.001, T1059.001, T1053.005, T1003.001"
              rows={3}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label>Target Environment</Label>
              <Select value={targetEnv} onValueChange={setTargetEnv}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="hybrid">Hybrid</SelectItem>
                  <SelectItem value="windows-ad">Windows AD</SelectItem>
                  <SelectItem value="linux-cloud">Linux Cloud</SelectItem>
                  <SelectItem value="macos">macOS</SelectItem>
                  <SelectItem value="kubernetes">Kubernetes</SelectItem>
                  <SelectItem value="aws">AWS</SelectItem>
                  <SelectItem value="azure">Azure</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Scan Mode</Label>
              <Select value={scanMode} onValueChange={setScanMode}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="passive">Passive</SelectItem>
                  <SelectItem value="active-low">Active Low</SelectItem>
                  <SelectItem value="active-standard">Active Standard</SelectItem>
                  <SelectItem value="active-aggressive">Active Aggressive</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div>
            <Label>Actor Name (optional)</Label>
            <Input
              value={actorName}
              onChange={(e) => setActorName(e.target.value)}
              placeholder="e.g. APT29, Lazarus Group"
            />
          </div>

          {mode === "llm" && (
            <div>
              <Label>Objective (optional)</Label>
              <Textarea
                value={objective}
                onChange={(e) => setObjective(e.target.value)}
                placeholder="e.g. Gain domain admin access via phishing and lateral movement"
                rows={2}
              />
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={handleCreate} disabled={isLoading}>
            {isLoading ? (
              <>
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                Generating…
              </>
            ) : (
              <>
                <Brain className="w-4 h-4 mr-2" />
                Generate Graph
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Simulation Dialog ──────────────────────────────────────────────────

function SimulationDialog({ graphId, onSimulated }: { graphId: string; onSimulated?: () => void }) {
  const [open, setOpen] = useState(false);
  const [os, setOs] = useState("windows");
  const [privilegeLevel, setPrivilegeLevel] = useState("user");
  const [networkAccess, setNetworkAccess] = useState("internal");
  const [scanMode, setScanMode] = useState("active-standard");
  const [result, setResult] = useState<any>(null);

  const simulate = trpc.abilityGraph.simulate.useMutation({
    onSuccess: (data) => {
      setResult(data);
      toast.success(`Simulation complete: ${data.completedNodes.length} executable, ${data.blockedNodes.length} blocked`);
      onSimulated?.();
    },
    onError: (err) => toast.error(`Simulation failed: ${err.message}`),
  });

  const handleSimulate = () => {
    simulate.mutate({
      graphId,
      environment: {
        os,
        privilegeLevel,
        networkAccess,
        installedSoftware: [],
        runningServices: [],
        openPorts: [],
        customFacts: {},
      },
      scanMode: scanMode as any,
    });
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="gap-1.5">
          <Play className="w-3.5 h-3.5" />
          Simulate
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Simulate Execution</DialogTitle>
          <DialogDescription>
            Walk the graph with a target environment to preview the execution plan.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label>Operating System</Label>
              <Select value={os} onValueChange={setOs}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="darwin">macOS</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Privilege Level</Label>
              <Select value={privilegeLevel} onValueChange={setPrivilegeLevel}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="user">User</SelectItem>
                  <SelectItem value="local_admin">Local Admin</SelectItem>
                  <SelectItem value="domain_admin">Domain Admin</SelectItem>
                  <SelectItem value="system">SYSTEM</SelectItem>
                  <SelectItem value="root">Root</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Network Access</Label>
              <Select value={networkAccess} onValueChange={setNetworkAccess}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="local">Local Only</SelectItem>
                  <SelectItem value="internal">Internal</SelectItem>
                  <SelectItem value="external">External</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Scan Mode</Label>
              <Select value={scanMode} onValueChange={setScanMode}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="passive">Passive</SelectItem>
                  <SelectItem value="active-low">Active Low</SelectItem>
                  <SelectItem value="active-standard">Active Standard</SelectItem>
                  <SelectItem value="active-aggressive">Active Aggressive</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <Button onClick={handleSimulate} disabled={simulate.isPending} className="w-full">
            {simulate.isPending ? (
              <><RefreshCw className="w-4 h-4 mr-2 animate-spin" /> Simulating…</>
            ) : (
              <><Play className="w-4 h-4 mr-2" /> Run Simulation</>
            )}
          </Button>

          {result && (
            <div className="space-y-3 border-t border-border/50 pt-3">
              <div className="text-sm font-semibold">Simulation Results</div>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>{result.completedNodes.length} executable</span>
                </div>
                <div className="flex items-center gap-2">
                  <Lock className="w-4 h-4 text-red-400" />
                  <span>{result.blockedNodes.length} blocked</span>
                </div>
                <div className="flex items-center gap-2">
                  <ArrowRight className="w-4 h-4 text-muted-foreground" />
                  <span>{result.skippedNodes.length} skipped</span>
                </div>
                <div className="flex items-center gap-2">
                  <Target className="w-4 h-4 text-primary" />
                  <span>{result.totalSteps} total steps</span>
                </div>
              </div>
              {result.safetyViolations.length > 0 && (
                <div className="space-y-1">
                  <div className="text-xs font-semibold text-amber-400 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" /> Safety Violations
                  </div>
                  {result.safetyViolations.map((v: string, i: number) => (
                    <div key={i} className="text-xs text-muted-foreground pl-4">{v}</div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Execute on Caldera Dialog ──────────────────────────────────────────

function ExecuteDialog({ graphId, onExecuted }: { graphId: string; onExecuted?: () => void }) {
  const [open, setOpen] = useState(false);
  const [agentPaw, setAgentPaw] = useState("");
  const [scanMode, setScanMode] = useState("active-standard");
  const [dryRun, setDryRun] = useState(true);
  const [result, setResult] = useState<any>(null);

  const agents = trpc.abilityGraph.agents.useQuery(undefined, { enabled: open });

  const execute = trpc.abilityGraph.execute.useMutation({
    onSuccess: (data) => {
      setResult(data);
      if (data.status === "completed") {
        toast.success(`Execution completed: ${data.nodesCompleted.length} succeeded`);
      } else if (data.status === "failed") {
        toast.warning(`Execution finished with ${data.nodesFailed.length} failure(s)`);
      }
      onExecuted?.();
    },
    onError: (err) => toast.error(`Execution failed: ${err.message}`),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="default" size="sm" className="gap-1.5">
          <Zap className="w-3.5 h-3.5" />
          Execute
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Execute on Caldera Agent</DialogTitle>
          <DialogDescription>
            Dispatch this graph's abilities to a live Caldera agent for execution.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div>
            <Label>Target Agent</Label>
            <Select value={agentPaw} onValueChange={setAgentPaw}>
              <SelectTrigger>
                <SelectValue placeholder="Select agent…" />
              </SelectTrigger>
              <SelectContent>
                {(agents.data || []).map((a: any) => (
                  <SelectItem key={a.paw} value={a.paw}>
                    {a.host} ({a.platform}) — {a.paw}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {agents.data?.length === 0 && (
              <p className="text-xs text-amber-400 mt-1">No agents available. Deploy a Caldera agent first.</p>
            )}
          </div>

          <div>
            <Label>Scan Mode</Label>
            <Select value={scanMode} onValueChange={setScanMode}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="passive">Passive</SelectItem>
                <SelectItem value="active-low">Active Low</SelectItem>
                <SelectItem value="active-standard">Active Standard</SelectItem>
                <SelectItem value="active-aggressive">Active Aggressive</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="dryRun"
              checked={dryRun}
              onChange={(e) => setDryRun(e.target.checked)}
              className="rounded border-border"
            />
            <Label htmlFor="dryRun" className="text-sm cursor-pointer">
              Dry Run (simulate without dispatching)
            </Label>
          </div>

          <Button
            onClick={() => execute.mutate({ graphId, agentPaw, scanMode: scanMode as any, dryRun })}
            disabled={execute.isPending || !agentPaw}
            className="w-full"
          >
            {execute.isPending ? (
              <><RefreshCw className="w-4 h-4 mr-2 animate-spin" /> Executing…</>
            ) : (
              <><Zap className="w-4 h-4 mr-2" /> {dryRun ? "Dry Run" : "Execute Live"}</>
            )}
          </Button>

          {result && (
            <div className="space-y-3 border-t border-border/50 pt-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold">Execution Results</span>
                <Badge variant="outline" className={`text-xs ${
                  result.status === "completed" ? "text-emerald-400 border-emerald-500/30" :
                  result.status === "failed" ? "text-red-400 border-red-500/30" :
                  "text-amber-400 border-amber-500/30"
                }`}>
                  {result.status}
                </Badge>
              </div>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>{result.nodesCompleted.length} completed</span>
                </div>
                <div className="flex items-center gap-2">
                  <XCircle className="w-4 h-4 text-red-400" />
                  <span>{result.nodesFailed.length} failed</span>
                </div>
                <div className="flex items-center gap-2">
                  <ArrowRight className="w-4 h-4 text-muted-foreground" />
                  <span>{result.nodesSkipped.length} skipped</span>
                </div>
                <div className="flex items-center gap-2">
                  <Lock className="w-4 h-4 text-amber-400" />
                  <span>{result.nodesBlocked.length} blocked</span>
                </div>
              </div>
              {result.operationId && (
                <div className="text-xs text-muted-foreground">
                  Caldera Operation: <span className="font-mono">{result.operationId}</span>
                </div>
              )}
              {result.executionLog?.length > 0 && (
                <div className="max-h-40 overflow-y-auto space-y-1 text-xs">
                  {result.executionLog.slice(-10).map((entry: any, i: number) => (
                    <div key={i} className="flex items-start gap-2 text-muted-foreground">
                      <span className="font-mono text-[10px] shrink-0">
                        {new Date(entry.timestamp).toLocaleTimeString()}
                      </span>
                      <span className={`${
                        entry.event === "success" ? "text-emerald-400" :
                        entry.event === "failure" ? "text-red-400" :
                        entry.event === "block" ? "text-amber-400" :
                        ""
                      }`}>
                        {entry.message}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Generate from Actor Dialog ─────────────────────────────────────────

function GenerateFromActorDialog({ onCreated }: { onCreated?: () => void }) {
  const [open, setOpen] = useState(false);
  const [actorId, setActorId] = useState("");
  const [targetEnv, setTargetEnv] = useState("enterprise-windows");
  const [result, setResult] = useState<any>(null);
  const [, navigate] = useLocation();

  const templates = trpc.abilityGraph.actorTemplates.useQuery(
    { limit: 50 },
    { enabled: open },
  );

  const generate = trpc.abilityGraph.generateFromActor.useMutation({
    onSuccess: (data) => {
      setResult(data);
      toast.success(`Generated ${data.name}: ${data.nodeCount} nodes, ${data.edgeCount} edges`);
      onCreated?.();
    },
    onError: (err) => toast.error(`Generation failed: ${err.message}`),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => { setOpen(v); if (!v) setResult(null); }}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="gap-1.5">
          <Users className="w-3.5 h-3.5" />
          From Actor
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Generate from Threat Actor</DialogTitle>
          <DialogDescription>
            Auto-generate an ability graph from a threat actor's known techniques.
          </DialogDescription>
        </DialogHeader>

        {!result ? (
          <div className="space-y-4">
            <div>
              <Label>Threat Actor</Label>
              <Select value={actorId} onValueChange={setActorId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select actor…" />
                </SelectTrigger>
                <SelectContent className="max-h-60">
                  {(templates.data || []).map((a: any) => (
                    <SelectItem key={a.actorId} value={a.actorId}>
                      <span className="flex items-center gap-2">
                        <Badge variant="outline" className="text-[10px] px-1">
                          {a.type}
                        </Badge>
                        {a.name}
                        <span className="text-muted-foreground text-xs">({a.techniqueCount} TTPs)</span>
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {templates.isLoading && (
                <p className="text-xs text-muted-foreground mt-1">Loading actors…</p>
              )}
              {templates.data?.length === 0 && (
                <p className="text-xs text-amber-400 mt-1">
                  No actors with techniques found. Seed the threat catalog first.
                </p>
              )}
            </div>

            <div>
              <Label>Target Environment</Label>
              <Select value={targetEnv} onValueChange={setTargetEnv}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="enterprise-windows">Enterprise Windows</SelectItem>
                  <SelectItem value="enterprise-linux">Enterprise Linux</SelectItem>
                  <SelectItem value="cloud-aws">Cloud (AWS)</SelectItem>
                  <SelectItem value="cloud-azure">Cloud (Azure)</SelectItem>
                  <SelectItem value="hybrid">Hybrid</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
              <Button
                onClick={() => generate.mutate({ actorId, targetEnvironment: targetEnv })}
                disabled={generate.isPending || !actorId}
              >
                {generate.isPending ? (
                  <><RefreshCw className="w-4 h-4 mr-2 animate-spin" /> Generating…</>
                ) : (
                  <><Brain className="w-4 h-4 mr-2" /> Generate Graph</>
                )}
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-4">
              <div className="flex items-center gap-2 text-emerald-400 font-semibold mb-2">
                <CheckCircle2 className="w-4 h-4" />
                Graph Generated
              </div>
              <div className="text-sm space-y-1">
                <div><span className="text-muted-foreground">Name:</span> {result.name}</div>
                <div><span className="text-muted-foreground">Nodes:</span> {result.nodeCount}</div>
                <div><span className="text-muted-foreground">Edges:</span> {result.edgeCount}</div>
                <div><span className="text-muted-foreground">Tactics:</span> {result.tactics?.join(", ")}</div>
                <div><span className="text-muted-foreground">Safety Tier:</span> {result.safetyTier?.replace("_", " ")}</div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => { setOpen(false); setResult(null); }}>Close</Button>
              <Button onClick={() => { setOpen(false); navigate(`/ability-graph/${result.graphId}`); }}>
                <Eye className="w-4 h-4 mr-2" />
                View Graph
              </Button>
            </DialogFooter>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────

export default function AbilityGraph() {
  const [, navigate] = useLocation();
  const [match, params] = useRoute("/ability-graph/:graphId");
  const selectedGraphId = match ? params?.graphId : null;
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [listFilter, setListFilter] = useState<string>("");

  // Queries
  const graphList = trpc.abilityGraph.list.useQuery({ limit: 100 });
  const stats = trpc.abilityGraph.stats.useQuery();
  const graphDetail = trpc.abilityGraph.get.useQuery(
    { graphId: selectedGraphId! },
    { enabled: !!selectedGraphId },
  );
  const visualization = trpc.abilityGraph.visualize.useQuery(
    { graphId: selectedGraphId!, scanMode: "active-standard" },
    { enabled: !!selectedGraphId },
  );

  // Mutations
  const deleteGraph = trpc.abilityGraph.delete.useMutation({
    onSuccess: () => {
      toast.success("Graph deleted");
      navigate("/ability-graph");
      graphList.refetch();
    },
    onError: (err) => toast.error(`Delete failed: ${err.message}`),
  });

  const validateGraph = trpc.abilityGraph.validate.useMutation({
    onSuccess: (data) => {
      if (data.valid) {
        toast.success("Graph validated successfully");
      } else {
        toast.warning(`Validation found ${data.issues.length} issue(s)`);
      }
      graphDetail.refetch();
    },
    onError: (err) => toast.error(`Validation failed: ${err.message}`),
  });

  const selectedNode = useMemo(() => {
    if (!selectedNodeId || !graphDetail.data) return null;
    return graphDetail.data.nodes.find(n => n.id === selectedNodeId) || null;
  }, [selectedNodeId, graphDetail.data]);

  const filteredGraphs = useMemo(() => {
    if (!graphList.data?.items) return [];
    if (!listFilter) return graphList.data.items;
    const q = listFilter.toLowerCase();
    return graphList.data.items.filter(g =>
      g.name.toLowerCase().includes(q) ||
      g.actorName?.toLowerCase().includes(q) ||
      g.status.toLowerCase().includes(q),
    );
  }, [graphList.data, listFilter]);

  // ─── Detail View ────────────────────────────────────────────────────
  if (selectedGraphId && graphDetail.data) {
    const { graph, nodes, edges } = graphDetail.data;

    return (
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="sm" onClick={() => navigate("/ability-graph")}>
              ← Back
            </Button>
            <div>
              <h1 className="text-xl font-bold flex items-center gap-2">
                <GitBranch className="w-5 h-5 text-primary" />
                {graph.name}
              </h1>
              <p className="text-sm text-muted-foreground mt-0.5">{graph.description}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <ExecuteDialog graphId={selectedGraphId} onExecuted={() => graphDetail.refetch()} />
            <SimulationDialog graphId={selectedGraphId} onSimulated={() => graphDetail.refetch()} />
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5"
              onClick={() => validateGraph.mutate({ graphId: selectedGraphId })}
              disabled={validateGraph.isPending}
            >
              {validateGraph.isPending ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <CheckCircle2 className="w-3.5 h-3.5" />
              )}
              Validate
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5 text-destructive hover:text-destructive"
              onClick={() => {
                if (confirm("Delete this graph?")) {
                  deleteGraph.mutate({ graphId: selectedGraphId });
                }
              }}
            >
              <Trash2 className="w-3.5 h-3.5" />
              Delete
            </Button>
          </div>
        </div>

        {/* Stats bar */}
        <div className="grid grid-cols-6 gap-3">
          {[
            { label: "Nodes", value: graph.nodeCount, icon: Network },
            { label: "Edges", value: graph.edgeCount, icon: ArrowRight },
            { label: "Techniques", value: graph.techniqueCount, icon: Target },
            { label: "Status", value: graph.status, icon: graph.status === "validated" ? CheckCircle2 : Clock },
            { label: "Safety Tier", value: graph.safetyTier.replace("_", " "), icon: Shield },
            { label: "Scan Mode", value: graph.scanMode, icon: Zap },
          ].map((stat) => (
            <Card key={stat.label} className="border-border/30 bg-card/50">
              <CardContent className="p-3">
                <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1">
                  <stat.icon className="w-3.5 h-3.5" />
                  {stat.label}
                </div>
                <div className="text-sm font-semibold capitalize">{stat.value}</div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Graph + Detail panel */}
        <div className="grid grid-cols-[1fr_320px] gap-4" style={{ minHeight: 500 }}>
          <GraphVisualizer
            nodes={visualization.data?.nodes || nodes}
            edges={visualization.data?.edges || edges}
            allowedNodes={visualization.data?.allowedNodes}
            blockedNodes={visualization.data?.blockedNodes}
            selectedNodeId={selectedNodeId}
            onNodeClick={setSelectedNodeId}
          />
          <div className="space-y-4">
            {selectedNode ? (
              <NodeDetailPanel node={selectedNode} onClose={() => setSelectedNodeId(null)} />
            ) : (
              <Card className="border-border/30 bg-card/50">
                <CardContent className="p-6 text-center text-muted-foreground">
                  <Network className="w-8 h-8 mx-auto mb-2 opacity-40" />
                  <p className="text-sm">Click a node to view details</p>
                </CardContent>
              </Card>
            )}

            {/* Tactics covered */}
            <Card className="border-border/30 bg-card/50">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Tactics Covered</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-wrap gap-1.5">
                {(graph.tactics || []).map((t: string) => (
                  <Badge
                    key={t}
                    variant="outline"
                    className="text-xs"
                    style={{ borderColor: TACTIC_COLORS[t] || "#94a3b8", color: TACTIC_COLORS[t] || "#94a3b8" }}
                  >
                    {t}
                  </Badge>
                ))}
              </CardContent>
            </Card>

            {/* Node list */}
            <Card className="border-border/30 bg-card/50">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Execution Order</CardTitle>
              </CardHeader>
              <CardContent className="space-y-1 max-h-60 overflow-y-auto">
                {nodes
                  .sort((a, b) => (a.order || 0) - (b.order || 0))
                  .map((node, idx) => {
                    const statusStyle = STATUS_COLORS[node.status] || STATUS_COLORS.pending;
                    return (
                      <button
                        key={node.id}
                        className={`w-full text-left px-2 py-1.5 rounded text-xs flex items-center gap-2 hover:bg-muted/30 transition-colors ${
                          selectedNodeId === node.id ? "bg-muted/50 ring-1 ring-primary/30" : ""
                        }`}
                        onClick={() => setSelectedNodeId(node.id)}
                      >
                        <span className="text-muted-foreground font-mono w-5">{idx + 1}.</span>
                        <span className="flex-1 truncate">{node.label}</span>
                        <span className={`font-mono ${statusStyle.text}`}>{node.techniqueId}</span>
                      </button>
                    );
                  })}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    );
  }

  // ─── List View ──────────────────────────────────────────────────────
  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <GitBranch className="w-6 h-6 text-primary" />
            Ability Graph Engine
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Compose, visualize, and simulate attack emulation DAGs from MITRE ATT&CK technique chains
          </p>
        </div>
        <div className="flex items-center gap-2">
          <GenerateFromActorDialog onCreated={() => graphList.refetch()} />
          <Button variant="outline" size="sm" className="gap-1.5" onClick={() => navigate("/ability-graph-compare")}>
            <ArrowLeftRight className="w-3.5 h-3.5" />
            Compare
          </Button>
          <CreateGraphDialog onCreated={() => graphList.refetch()} />
        </div>
      </div>

      {/* Stats */}
      {stats.data && (
        <div className="grid grid-cols-5 gap-3">
          {[
            { label: "Total Graphs", value: stats.data.totalGraphs, icon: GitBranch },
            { label: "Total Nodes", value: stats.data.totalNodes, icon: Network },
            { label: "Total Edges", value: stats.data.totalEdges, icon: ArrowRight },
            { label: "Avg Nodes/Graph", value: stats.data.avgNodesPerGraph, icon: BarChart3 },
            { label: "Draft", value: stats.data.byStatus?.draft || 0, icon: Clock },
          ].map((stat) => (
            <Card key={stat.label} className="border-border/30 bg-card/50">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1">
                  <stat.icon className="w-3.5 h-3.5" />
                  {stat.label}
                </div>
                <div className="text-xl font-bold">{stat.value}</div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Search */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Input
            value={listFilter}
            onChange={(e) => setListFilter(e.target.value)}
            placeholder="Search graphs…"
            className="pl-9"
          />
          <Target className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        </div>
        <Button variant="outline" size="sm" onClick={() => graphList.refetch()}>
          <RefreshCw className="w-4 h-4" />
        </Button>
      </div>

      {/* Graph list */}
      {graphList.isLoading ? (
        <div className="text-center py-12 text-muted-foreground">Loading graphs…</div>
      ) : filteredGraphs.length === 0 ? (
        <Card className="border-border/30 bg-card/50">
          <CardContent className="p-12 text-center">
            <GitBranch className="w-12 h-12 mx-auto mb-3 text-muted-foreground/30" />
            <h3 className="text-lg font-semibold mb-1">No Ability Graphs Yet</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Create your first graph by decomposing MITRE ATT&CK technique chains into executable DAGs.
            </p>
            <CreateGraphDialog onCreated={() => graphList.refetch()} />
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredGraphs.map((graph) => {
            const safetyStyle = SAFETY_COLORS[graph.safetyTier] || SAFETY_COLORS.medium_impact;
            return (
              <Card
                key={graph.id}
                className="border-border/30 bg-card/50 hover:border-primary/30 transition-colors cursor-pointer group"
                onClick={() => navigate(`/ability-graph/${graph.id}`)}
              >
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm group-hover:text-primary transition-colors">
                      {graph.name}
                    </CardTitle>
                    <Badge
                      variant="outline"
                      className={`text-xs ${
                        graph.status === "validated"
                          ? "border-emerald-500/30 text-emerald-400"
                          : graph.status === "running"
                            ? "border-amber-500/30 text-amber-400"
                            : graph.status === "completed"
                              ? "border-emerald-500/30 text-emerald-400"
                              : "border-border text-muted-foreground"
                      }`}
                    >
                      {graph.status}
                    </Badge>
                  </div>
                  {graph.actorName && (
                    <CardDescription className="text-xs">{graph.actorName}</CardDescription>
                  )}
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-3 gap-2 text-xs">
                    <div className="text-center">
                      <div className="text-muted-foreground">Nodes</div>
                      <div className="font-semibold">{graph.nodeCount}</div>
                    </div>
                    <div className="text-center">
                      <div className="text-muted-foreground">Edges</div>
                      <div className="font-semibold">{graph.edgeCount}</div>
                    </div>
                    <div className="text-center">
                      <div className="text-muted-foreground">Techniques</div>
                      <div className="font-semibold">{graph.techniqueCount}</div>
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 flex-wrap">
                    <Badge variant="outline" className={`text-xs ${safetyStyle.text} ${safetyStyle.border}`}>
                      <Shield className="w-3 h-3 mr-1" />
                      {graph.safetyTier.replace("_", " ")}
                    </Badge>
                    <Badge variant="outline" className="text-xs">
                      {graph.scanMode}
                    </Badge>
                  </div>

                  {(graph.tactics || []).length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {(graph.tactics as string[]).slice(0, 4).map((t: string) => (
                        <span
                          key={t}
                          className="text-[10px] px-1.5 py-0.5 rounded-full"
                          style={{
                            backgroundColor: `${TACTIC_COLORS[t] || "#94a3b8"}15`,
                            color: TACTIC_COLORS[t] || "#94a3b8",
                          }}
                        >
                          {t}
                        </span>
                      ))}
                      {(graph.tactics as string[]).length > 4 && (
                        <span className="text-[10px] text-muted-foreground">
                          +{(graph.tactics as string[]).length - 4} more
                        </span>
                      )}
                    </div>
                  )}

                  <div className="flex items-center justify-between text-xs text-muted-foreground pt-1 border-t border-border/30">
                    <span>{graph.sourceType}</span>
                    <span>{new Date(graph.createdAt).toLocaleDateString()}</span>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
