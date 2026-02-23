import { useState, useRef, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { GitBranch, ZoomIn, ZoomOut, Maximize2, Search, Target, Network } from "lucide-react";
import AppShell from "@/components/AppShell";

const nodeColors: Record<string, { fill: string; stroke: string; text: string }> = {
  user: { fill: "#1e40af", stroke: "#3b82f6", text: "#93c5fd" },
  group: { fill: "#065f46", stroke: "#10b981", text: "#6ee7b7" },
  computer: { fill: "#7c2d12", stroke: "#f97316", text: "#fdba74" },
  gpo: { fill: "#581c87", stroke: "#a855f7", text: "#d8b4fe" },
  ou: { fill: "#374151", stroke: "#6b7280", text: "#d1d5db" },
  domain: { fill: "#991b1b", stroke: "#ef4444", text: "#fca5a5" },
  trust: { fill: "#854d0e", stroke: "#eab308", text: "#fde68a" },
};

const edgeColors: Record<string, string> = {
  memberOf: "#3b82f6",
  adminTo: "#ef4444",
  canRDP: "#f97316",
  hasSession: "#a855f7",
  gpLink: "#8b5cf6",
  trustedBy: "#10b981",
  owns: "#eab308",
  default: "#6b7280",
};

export default function ADAttackPathGraph() {
  const [activeTab, setActiveTab] = useState("graph");
  const [selectedEnvId, setSelectedEnvId] = useState<string>("");
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [sourceNodeId, setSourceNodeId] = useState("");
  const [targetNodeId, setTargetNodeId] = useState("");
  const svgRef = useRef<SVGSVGElement>(null);

  const envId = selectedEnvId ? parseInt(selectedEnvId) : 0;

  const envsQuery = trpc.adAttackPathGraph.listEnvironments.useQuery({});
  const graphQuery = trpc.adAttackPathGraph.buildGraph.useQuery(
    { environmentId: envId },
    { enabled: envId > 0 }
  );
  const statsQuery = trpc.adAttackPathGraph.getStats.useQuery(
    { environmentId: envId },
    { enabled: envId > 0 }
  );
  const pathQuery = trpc.adAttackPathGraph.findPath.useQuery(
    { environmentId: envId, sourceNodeId, targetNodeId },
    { enabled: envId > 0 && !!sourceNodeId && !!targetNodeId }
  );

  const environments = envsQuery.data || [];
  const graph = graphQuery.data;
  const stats = statsQuery.data;
  const foundPath = pathQuery.data;

  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];
  const attackPaths = graph?.paths || [];

  const filteredNodes = searchQuery
    ? nodes.filter((n: any) => n.label?.toLowerCase().includes(searchQuery.toLowerCase()) || n.id?.toLowerCase().includes(searchQuery.toLowerCase()))
    : nodes;

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.target === svgRef.current || (e.target as Element).tagName === "rect") {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  }, [pan]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (isDragging) {
      setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    }
  }, [isDragging, dragStart]);

  const handleMouseUp = useCallback(() => { setIsDragging(false); }, []);

  const handleFindPath = () => {
    if (!sourceNodeId || !targetNodeId) {
      toast.error("Select both source and target nodes");
      return;
    }
    pathQuery.refetch();
  };

  return (
    <AppShell>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <GitBranch className="h-6 w-6 text-purple-400" />
              AD Attack Path Graph
            </h1>
            <p className="text-muted-foreground mt-1">Interactive visualization of Active Directory attack escalation paths</p>
          </div>
          <div className="flex items-center gap-3">
            <Select value={selectedEnvId} onValueChange={setSelectedEnvId}>
              <SelectTrigger className="w-64">
                <SelectValue placeholder="Select AD Environment" />
              </SelectTrigger>
              <SelectContent>
                {environments.map((env: any) => (
                  <SelectItem key={env.id} value={String(env.id)}>{env.environmentName || env.domainName}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {!selectedEnvId ? (
          <Card className="bg-card/50 border-border/50">
            <CardContent className="py-16 text-center">
              <Network className="h-16 w-16 mx-auto text-muted-foreground/30 mb-4" />
              <h3 className="text-lg font-medium mb-2">Select an AD Environment</h3>
              <p className="text-muted-foreground">Choose an Active Directory environment from the dropdown above to build and visualize attack paths.</p>
              <p className="text-sm text-muted-foreground mt-2">Environments are created via the AD Domain Connector page after LDAP enumeration.</p>
            </CardContent>
          </Card>
        ) : (
          <>
            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <Card className="bg-card/50 border-border/50">
                <CardContent className="pt-4 pb-3 px-4">
                  <div className="text-2xl font-bold">{nodes.length}</div>
                  <div className="text-xs text-muted-foreground">Total Nodes</div>
                </CardContent>
              </Card>
              <Card className="bg-card/50 border-border/50">
                <CardContent className="pt-4 pb-3 px-4">
                  <div className="text-2xl font-bold">{edges.length}</div>
                  <div className="text-xs text-muted-foreground">Relationships</div>
                </CardContent>
              </Card>
              <Card className="bg-card/50 border-border/50">
                <CardContent className="pt-4 pb-3 px-4">
                  <div className="text-2xl font-bold text-red-400">{attackPaths.length}</div>
                  <div className="text-xs text-muted-foreground">Attack Paths</div>
                </CardContent>
              </Card>
              <Card className="bg-card/50 border-border/50">
                <CardContent className="pt-4 pb-3 px-4">
                  <div className="text-2xl font-bold text-amber-400">{stats?.totalObjects ?? 0}</div>
                  <div className="text-xs text-muted-foreground">AD Objects</div>
                </CardContent>
              </Card>
              <Card className="bg-card/50 border-border/50">
                <CardContent className="pt-4 pb-3 px-4">
                  <div className="text-2xl font-bold text-purple-400">{stats?.privilegedObjects ?? 0}</div>
                  <div className="text-xs text-muted-foreground">Privileged Objects</div>
                </CardContent>
              </Card>
            </div>

            <Tabs value={activeTab} onValueChange={setActiveTab}>
              <TabsList>
                <TabsTrigger value="graph">Graph View</TabsTrigger>
                <TabsTrigger value="paths">Attack Paths ({attackPaths.length})</TabsTrigger>
                <TabsTrigger value="pathfinder">Path Finder</TabsTrigger>
                <TabsTrigger value="nodes">Node List ({nodes.length})</TabsTrigger>
              </TabsList>

              <TabsContent value="graph">
                <Card className="bg-card/50 border-border/50">
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-base">Attack Path Graph</CardTitle>
                      <div className="flex items-center gap-2">
                        <div className="relative">
                          <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                          <Input className="pl-8 w-48 h-9" placeholder="Search nodes..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} />
                        </div>
                        <Button variant="outline" size="sm" onClick={() => setZoom(z => Math.min(z + 0.2, 3))}><ZoomIn className="h-4 w-4" /></Button>
                        <Button variant="outline" size="sm" onClick={() => setZoom(z => Math.max(z - 0.2, 0.3))}><ZoomOut className="h-4 w-4" /></Button>
                        <Button variant="outline" size="sm" onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}><Maximize2 className="h-4 w-4" /></Button>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="border border-border/50 rounded-lg overflow-hidden bg-black/20" style={{ height: "500px" }}>
                      <svg
                        ref={svgRef}
                        width="100%"
                        height="100%"
                        viewBox="0 0 1200 500"
                        onMouseDown={handleMouseDown}
                        onMouseMove={handleMouseMove}
                        onMouseUp={handleMouseUp}
                        onMouseLeave={handleMouseUp}
                        style={{ cursor: isDragging ? "grabbing" : "grab" }}
                      >
                        <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
                          {/* Edges */}
                          {edges.map((edge: any, i: number) => {
                            const source = nodes.find((n: any) => n.id === edge.source);
                            const target = nodes.find((n: any) => n.id === edge.target);
                            if (!source || !target || source.x == null || source.y == null || target.x == null || target.y == null) return null;
                            const color = edgeColors[edge.relationship] || edgeColors.default;
                            return (
                              <g key={`edge-${i}`}>
                                <line
                                  x1={source.x} y1={source.y}
                                  x2={target.x} y2={target.y}
                                  stroke={edge.isAttackPath ? "#ef4444" : color}
                                  strokeWidth={edge.isAttackPath ? 2.5 : 1.5}
                                  strokeDasharray={edge.isAttackPath ? "6,3" : "none"}
                                  opacity={0.6}
                                />
                                <text
                                  x={(source.x + target.x) / 2}
                                  y={(source.y + target.y) / 2 - 6}
                                  fill={color}
                                  fontSize="8"
                                  textAnchor="middle"
                                  opacity={0.7}
                                >
                                  {edge.relationship}
                                </text>
                              </g>
                            );
                          })}
                          {/* Nodes */}
                          {filteredNodes.map((node: any) => {
                            const colors = nodeColors[node.type] || nodeColors.user;
                            const isSelected = selectedNode?.id === node.id;
                            return (
                              <g key={node.id} onClick={() => setSelectedNode(node)} style={{ cursor: "pointer" }}>
                                <circle
                                  cx={node.x} cy={node.y}
                                  r={isSelected ? 22 : 18}
                                  fill={colors.fill}
                                  stroke={isSelected ? "#fff" : colors.stroke}
                                  strokeWidth={isSelected ? 3 : 2}
                                />
                                {node.risk === "critical" && (
                                  <circle cx={node.x + 14} cy={node.y - 14} r={5} fill="#ef4444" stroke="#991b1b" strokeWidth={1} />
                                )}
                                <text x={node.x} y={node.y + 30} fill={colors.text} fontSize="9" textAnchor="middle" fontWeight="500">
                                  {(node.label || node.id).length > 16 ? (node.label || node.id).slice(0, 14) + "..." : (node.label || node.id)}
                                </text>
                                <text x={node.x} y={node.y + 4} fill="#fff" fontSize="10" textAnchor="middle" fontWeight="bold">
                                  {node.type.charAt(0).toUpperCase()}
                                </text>
                              </g>
                            );
                          })}
                          {nodes.length === 0 && (
                            <text x="600" y="250" fill="#64748b" fontSize="14" textAnchor="middle">
                              No AD objects found. Run LDAP enumeration from the AD Domain Connector.
                            </text>
                          )}
                        </g>
                      </svg>
                    </div>

                    {/* Legend */}
                    <div className="flex flex-wrap gap-4 mt-3">
                      {Object.entries(nodeColors).map(([type, colors]) => (
                        <div key={type} className="flex items-center gap-1.5">
                          <div className="w-3 h-3 rounded-full" style={{ backgroundColor: colors.stroke }} />
                          <span className="text-xs text-muted-foreground capitalize">{type}</span>
                        </div>
                      ))}
                      <div className="flex items-center gap-1.5 ml-4">
                        <div className="w-6 h-0 border-t-2 border-dashed border-red-500" />
                        <span className="text-xs text-muted-foreground">Attack Path</span>
                      </div>
                    </div>

                    {/* Selected Node Detail */}
                    {selectedNode && (
                      <Card className="mt-4 bg-card/30 border-border/30">
                        <CardContent className="py-3 px-4">
                          <div className="flex items-center justify-between">
                            <div>
                              <div className="font-medium">{selectedNode.label || selectedNode.id}</div>
                              <div className="text-sm text-muted-foreground capitalize">{selectedNode.type}</div>
                            </div>
                            {selectedNode.risk && (
                              <Badge className={selectedNode.risk === "critical" ? "bg-red-500/20 text-red-400" : selectedNode.risk === "high" ? "bg-orange-500/20 text-orange-400" : "bg-yellow-500/20 text-yellow-400"}>
                                {selectedNode.risk} risk
                              </Badge>
                            )}
                          </div>
                          {selectedNode.properties && (
                            <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
                              {Object.entries(selectedNode.properties).map(([k, v]) => (
                                <div key={k}><span className="text-muted-foreground">{k}:</span> {String(v)}</div>
                              ))}
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="paths" className="space-y-4">
                {attackPaths.length === 0 ? (
                  <Card className="bg-card/50 border-border/50">
                    <CardContent className="py-12 text-center">
                      <Target className="h-12 w-12 mx-auto text-muted-foreground/50 mb-4" />
                      <p className="text-muted-foreground">No attack paths discovered. Enumerate AD objects to build the graph.</p>
                    </CardContent>
                  </Card>
                ) : (
                  attackPaths.map((path: any, i: number) => (
                    <Card key={i} className="bg-card/50 border-border/50">
                      <CardContent className="py-4 px-5">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <Badge className={path.riskScore >= 8 ? "bg-red-500/20 text-red-400" : path.riskScore >= 5 ? "bg-orange-500/20 text-orange-400" : "bg-yellow-500/20 text-yellow-400"}>
                              Risk: {path.riskScore}/10
                            </Badge>
                            <span className="font-medium">{path.description || `Path ${i + 1}`}</span>
                          </div>
                          <span className="text-xs text-muted-foreground">{path.nodeIds?.length || 0} hops</span>
                        </div>
                        <div className="flex items-center gap-2 text-sm text-muted-foreground flex-wrap">
                          {path.nodeIds?.map((nodeId: string, j: number) => (
                            <span key={j} className="flex items-center gap-1">
                              {j > 0 && <span className="text-red-400">→</span>}
                              <span>{nodeId}</span>
                            </span>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  ))
                )}
              </TabsContent>

              <TabsContent value="pathfinder">
                <Card className="bg-card/50 border-border/50">
                  <CardHeader><CardTitle className="text-base">Shortest Path Finder</CardTitle></CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-sm text-muted-foreground">Find the shortest attack path between any two AD objects in the graph.</p>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div>
                        <label className="text-sm font-medium">Source Node</label>
                        <Select value={sourceNodeId} onValueChange={setSourceNodeId}>
                          <SelectTrigger><SelectValue placeholder="Select source" /></SelectTrigger>
                          <SelectContent>
                            {nodes.map((n: any) => (
                              <SelectItem key={n.id} value={n.id}>{n.label || n.id} ({n.type})</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <div>
                        <label className="text-sm font-medium">Target Node</label>
                        <Select value={targetNodeId} onValueChange={setTargetNodeId}>
                          <SelectTrigger><SelectValue placeholder="Select target" /></SelectTrigger>
                          <SelectContent>
                            {nodes.map((n: any) => (
                              <SelectItem key={n.id} value={n.id}>{n.label || n.id} ({n.type})</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="flex items-end">
                        <Button onClick={handleFindPath} disabled={!sourceNodeId || !targetNodeId} className="w-full">
                          <Search className="h-4 w-4 mr-2" />Find Path
                        </Button>
                      </div>
                    </div>

                    {foundPath && (
                      <Card className="bg-card/30 border-border/30 mt-4">
                        <CardContent className="py-4 px-5">
                          <div className="flex items-center gap-2 mb-3">
                            <Badge className="bg-green-500/20 text-green-400">Path Found</Badge>
                            <span className="text-sm text-muted-foreground">{foundPath.hops} hops, Risk: {foundPath.riskLevel}</span>
                          </div>
                          <div className="flex items-center gap-2 text-sm flex-wrap">
                            {foundPath.nodes.map((nodeId: string, j: number) => (
                              <span key={j} className="flex items-center gap-1">
                                {j > 0 && <span className="text-red-400">→</span>}
                                <Badge variant="outline">{nodeId}</Badge>
                              </span>
                            ))}
                          </div>
                          {foundPath.techniques && foundPath.techniques.length > 0 && (
                            <div className="mt-3">
                              <span className="text-xs font-medium text-muted-foreground">Techniques:</span>
                              <div className="flex flex-wrap gap-1 mt-1">
                                {foundPath.techniques.map((t: string, j: number) => (
                                  <Badge key={j} variant="outline" className="text-xs">{t}</Badge>
                                ))}
                              </div>
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="nodes" className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {filteredNodes.map((node: any) => {
                    const colors = nodeColors[node.type] || nodeColors.user;
                    return (
                      <Card key={node.id} className="bg-card/50 border-border/50 cursor-pointer hover:border-primary/30" onClick={() => { setSelectedNode(node); setActiveTab("graph"); }}>
                        <CardContent className="py-3 px-4">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold text-white" style={{ backgroundColor: colors.fill, border: `2px solid ${colors.stroke}` }}>
                              {node.type.charAt(0).toUpperCase()}
                            </div>
                            <div className="min-w-0 flex-1">
                              <div className="font-medium text-sm truncate">{node.label || node.id}</div>
                              <div className="text-xs text-muted-foreground capitalize">{node.type}</div>
                            </div>
                            {node.risk && (
                              <Badge className={`shrink-0 ${node.risk === "critical" ? "bg-red-500/20 text-red-400" : node.risk === "high" ? "bg-orange-500/20 text-orange-400" : "bg-yellow-500/20 text-yellow-400"}`}>
                                {node.risk}
                              </Badge>
                            )}
                          </div>
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>
              </TabsContent>
            </Tabs>
          </>
        )}
      </div>
    </AppShell>
  );
}
