import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import { useState, useMemo, useRef, useEffect, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { safeJsonParse } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import {
  GitBranch, Plus, Search, Trash2, ZoomIn, ZoomOut,
  Maximize2, Target, Shield, AlertTriangle, Crosshair
} from "lucide-react";
import AppShell from "@/components/AppShell";

// Node type colors
const NODE_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  entry: { bg: "#ef4444", border: "#dc2626", text: "#fff" },
  asset: { bg: "#3b82f6", border: "#2563eb", text: "#fff" },
  vulnerability: { bg: "#f59e0b", border: "#d97706", text: "#000" },
  technique: { bg: "#8b5cf6", border: "#7c3aed", text: "#fff" },
  objective: { bg: "#10b981", border: "#059669", text: "#fff" },
  pivot: { bg: "#ec4899", border: "#db2777", text: "#fff" },
};

// Simple force-directed graph renderer
function AttackPathGraph({ nodes: rawNodes, edges: rawEdges }: { nodes: any[]; edges: any[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [zoom, setZoom] = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  // Position nodes in a layered layout
  const positionedNodes = useMemo(() => {
    if (!rawNodes?.length) return [];
    const layers: Record<string, number> = {
      entry: 0, asset: 1, vulnerability: 2, technique: 3, pivot: 4, objective: 5,
    };
    const layerNodes = new Map<number, any[]>();
    const nodes = rawNodes.map((n: any) => ({
      ...n,
      layer: layers[n.type] ?? 2,
    }));
    for (const n of nodes) {
      if (!layerNodes.has(n.layer)) layerNodes.set(n.layer, []);
      layerNodes.get(n.layer)!.push(n);
    }
    const maxLayer = Math.max(...Array.from(layerNodes.keys()));
    for (const [layer, lnodes] of Array.from(layerNodes.entries())) {
      const spacing = 600 / (lnodes.length + 1);
      lnodes.forEach((n: any, i: number) => {
        n.x = n.x ?? spacing * (i + 1);
        n.y = n.y ?? (layer / Math.max(maxLayer, 1)) * 400 + 60;
      });
    }
    return nodes;
  }, [rawNodes]);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * 2;
    canvas.height = rect.height * 2;
    ctx.scale(2, 2);

    ctx.clearRect(0, 0, rect.width, rect.height);
    ctx.save();
    ctx.translate(offset.x, offset.y);
    ctx.scale(zoom, zoom);

    // Draw edges
    for (const edge of (rawEdges || [])) {
      const source = positionedNodes.find((n: any) => n.id === edge.source);
      const target = positionedNodes.find((n: any) => n.id === edge.target);
      if (!source || !target) continue;

      ctx.beginPath();
      ctx.moveTo(source.x, source.y);
      ctx.lineTo(target.x, target.y);
      ctx.strokeStyle = "#555";
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Arrow
      const angle = Math.atan2(target.y - source.y, target.x - source.x);
      const arrowLen = 8;
      const endX = target.x - Math.cos(angle) * 20;
      const endY = target.y - Math.sin(angle) * 20;
      ctx.beginPath();
      ctx.moveTo(endX, endY);
      ctx.lineTo(endX - arrowLen * Math.cos(angle - 0.4), endY - arrowLen * Math.sin(angle - 0.4));
      ctx.lineTo(endX - arrowLen * Math.cos(angle + 0.4), endY - arrowLen * Math.sin(angle + 0.4));
      ctx.closePath();
      ctx.fillStyle = "#555";
      ctx.fill();

      // Edge label
      if (edge.label) {
        const midX = (source.x + target.x) / 2;
        const midY = (source.y + target.y) / 2;
        ctx.font = "9px sans-serif";
        ctx.fillStyle = "#888";
        ctx.textAlign = "center";
        ctx.fillText(edge.label, midX, midY - 5);
      }
    }

    // Draw nodes
    for (const node of positionedNodes) {
      const colors = NODE_COLORS[node.type] || NODE_COLORS.asset;
      const isHovered = hoveredNode === node.id;
      const radius = isHovered ? 22 : 18;

      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = colors.bg;
      ctx.fill();
      ctx.strokeStyle = isHovered ? "#fff" : colors.border;
      ctx.lineWidth = isHovered ? 3 : 2;
      ctx.stroke();

      // Label
      ctx.font = `${isHovered ? "bold " : ""}10px sans-serif`;
      ctx.fillStyle = "#e5e7eb";
      ctx.textAlign = "center";
      const label = node.label.length > 20 ? node.label.slice(0, 18) + "..." : node.label;
      ctx.fillText(label, node.x, node.y + radius + 14);

      // Type badge
      ctx.font = "8px sans-serif";
      ctx.fillStyle = "#9ca3af";
      ctx.fillText(node.type, node.x, node.y + radius + 24);
    }

    ctx.restore();
  }, [positionedNodes, rawEdges, zoom, offset, hoveredNode]);

  useEffect(() => {
    draw();
  }, [draw]);

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (dragging) {
      setOffset(prev => ({
        x: prev.x + e.movementX,
        y: prev.y + e.movementY,
      }));
      return;
    }
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left - offset.x) / zoom;
    const my = (e.clientY - rect.top - offset.y) / zoom;
    const found = positionedNodes.find((n: any) => {
      const dx = n.x - mx;
      const dy = n.y - my;
      return dx * dx + dy * dy < 400;
    });
    setHoveredNode(found?.id || null);
  };

  return (
    <div className="relative">
      <canvas
        ref={canvasRef}
        className="w-full h-[500px] bg-zinc-950 rounded-lg border cursor-grab"
        onMouseDown={(e) => { setDragging(true); setDragStart({ x: e.clientX, y: e.clientY }); }}
        onMouseUp={() => setDragging(false)}
        onMouseLeave={() => setDragging(false)}
        onMouseMove={handleMouseMove}
      />
      <div className="absolute top-3 right-3 flex gap-1">
        <Button size="icon" variant="outline" className="h-8 w-8" onClick={() => setZoom(z => Math.min(z + 0.2, 3))}>
          <ZoomIn className="h-4 w-4" />
        </Button>
        <Button size="icon" variant="outline" className="h-8 w-8" onClick={() => setZoom(z => Math.max(z - 0.2, 0.3))}>
          <ZoomOut className="h-4 w-4" />
        </Button>
        <Button size="icon" variant="outline" className="h-8 w-8" onClick={() => { setZoom(1); setOffset({ x: 0, y: 0 }); }}>
          <Maximize2 className="h-4 w-4" />
        </Button>
      </div>
      {/* Legend */}
      <div className="absolute bottom-3 left-3 flex flex-wrap gap-2">
        {Object.entries(NODE_COLORS).map(([type, colors]) => (
          <div key={type} className="flex items-center gap-1 text-xs">
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: colors.bg }} />
            <span className="text-muted-foreground capitalize">{type}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function AttackPaths() {
  const [search, setSearch] = useState("");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);

  const [newName, setNewName] = useState("");
  const [newDescription, setNewDescription] = useState("");

  const searchInput = useMemo(() => ({ search: search || undefined }), [search]);
  const { data: paths, isLoading, refetch } = trpc.attackPaths.list.useQuery(searchInput);
  const { data: stats } = trpc.attackPaths.stats.useQuery();
  const { data: selectedAp } = trpc.attackPaths.get.useQuery(
    { pathId: selectedPath! },
    { enabled: !!selectedPath }
  );

  const createMutation = trpc.attackPaths.create.useMutation({
    onSuccess: (data) => {
      toast.success("Attack path created");
      setShowCreateDialog(false);
      setNewName("");
      setNewDescription("");
      setSelectedPath(data.pathId);
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const deleteMutation = trpc.attackPaths.delete.useMutation({
    onSuccess: () => {
      toast.success("Attack path deleted");
      setSelectedPath(null);
      refetch();
    },
  });

  const getRiskColor = (score: number | null) => {
    if (!score) return "text-zinc-400";
    if (score >= 70) return "text-red-400";
    if (score >= 50) return "text-orange-400";
    if (score >= 30) return "text-yellow-400";
    return "text-green-400";
  };

  return (
    <AppShell activePath="/attack-paths">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <GitBranch className="h-6 w-6 text-purple-400" />
            Attack Path Visualization
          </h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">View and interact with computed attack path graphs. Each path shows the step-by-step chain an attacker could follow — from initial access through privilege escalation to objective completion. Click on nodes to see details about each hop, the techniques involved, and the likelihood of success. Use these paths to guide your penetration testing priorities.</p>
          <p className="text-muted-foreground mt-1">
            Map and visualize attack paths showing how vulnerabilities chain across assets
          </p>
        </div>
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="h-4 w-4" />
              New Attack Path
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Attack Path</DialogTitle>
              <DialogDescription>Create a new attack path graph</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div>
                <Label>Name</Label>
                <Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Attack path name..." />
              </div>
              <div>
                <Label>Description</Label>
                <Textarea value={newDescription} onChange={(e) => setNewDescription(e.target.value)} placeholder="Describe the attack path..." />
              </div>
            </div>
            <DialogFooter>
              <Button
                onClick={() => createMutation.mutate({ name: newName, description: newDescription })}
                disabled={!newName || createMutation.isPending}
              >
                Create
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold">{stats?.total ?? 0}</div>
            <div className="text-xs text-muted-foreground">Total Attack Paths</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-purple-400">
              {paths?.items?.filter((p: any) => p.status === "generated").length ?? 0}
            </div>
            <div className="text-xs text-muted-foreground">Auto-Generated</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-blue-400">
              {paths?.items?.filter((p: any) => p.status === "draft").length ?? 0}
            </div>
            <div className="text-xs text-muted-foreground">Drafts</div>
          </CardContent>
        </Card>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input placeholder="Search attack paths..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9" />
      </div>

      {/* Path List + Visualization */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* List */}
        <div className="lg:col-span-1 space-y-3 max-h-[600px] overflow-y-auto">
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">Loading...</div>
          ) : !paths?.items?.length ? (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                <GitBranch className="h-10 w-10 mx-auto mb-3 opacity-40" />
                <p>No attack paths yet</p>
                <p className="text-sm mt-1">Create one or generate from a scan</p>
              </CardContent>
            </Card>
          ) : (
            paths.items.map((path: any) => (
              <Card
                key={path.pathId}
                className={`cursor-pointer transition-colors hover:border-purple-500/50 ${
                  selectedPath === path.pathId ? "border-purple-500" : ""
                }`}
                onClick={() => setSelectedPath(path.pathId)}
              >
                <CardContent className="p-4">
                  <h3 className="font-semibold text-sm truncate">{path.name}</h3>
                  <div className="flex items-center gap-2 mt-2">
                    <Badge variant="outline" className="text-[10px]">{path.status}</Badge>
                    {path.riskScore !== null && (
                      <span className={`text-xs font-bold ${getRiskColor(path.riskScore)}`}>
                        Risk: {path.riskScore}
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {(() => {
                      const nodes = typeof path.nodes === "string" ? safeJsonParse<any[]>(path.nodes, []) : path.nodes;
                      return `${Array.isArray(nodes) ? nodes.length : 0} nodes`;
                    })()}
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>

        {/* Visualization */}
        <div className="lg:col-span-3">
          {selectedAp ? (
            <Card>
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <GitBranch className="h-5 w-5 text-purple-400" />
                      {selectedAp.name}
                    </CardTitle>
                    <CardDescription>{selectedAp.description}</CardDescription>
                  </div>
                  <div className="flex gap-2">
                    {selectedAp.riskScore !== null && (
                      <Badge className={`${getRiskColor(selectedAp.riskScore)} bg-zinc-800`}>
                        Risk Score: {selectedAp.riskScore}
                      </Badge>
                    )}
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => deleteMutation.mutate({ pathId: selectedAp.pathId })}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <AttackPathGraph
                  nodes={typeof selectedAp.nodes === "string" ? safeJsonParse<any[]>(selectedAp.nodes as string, []) : (selectedAp.nodes as any[] || [])}
                  edges={typeof selectedAp.edges === "string" ? safeJsonParse<any[]>(selectedAp.edges as string, []) : (selectedAp.edges as any[] || [])}
                />
                {/* Node summary */}
                <div className="mt-4 grid grid-cols-2 sm:grid-cols-3 gap-3">
                  {(() => {
                    const nodes = typeof selectedAp.nodes === "string" ? safeJsonParse<any[]>(selectedAp.nodes as string, []) : (selectedAp.nodes || []);
                    const typeCounts: Record<string, number> = {};
                    for (const n of (nodes as any[])) {
                      typeCounts[n.type] = (typeCounts[n.type] || 0) + 1;
                    }
                    return Object.entries(typeCounts).map(([type, count]) => (
                      <div key={type} className="flex items-center gap-2 text-sm">
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: NODE_COLORS[type]?.bg || "#666" }} />
                        <span className="capitalize">{type}</span>
                        <span className="text-muted-foreground ml-auto">{count}</span>
                      </div>
                    ));
                  })()}
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="py-16 text-center text-muted-foreground">
                <GitBranch className="h-12 w-12 mx-auto mb-4 opacity-30" />
                <p className="text-lg">Select an attack path to visualize</p>
                <p className="text-sm mt-1">Or generate one from a domain intelligence scan</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
    </AppShell>
  );
}
