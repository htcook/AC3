import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { TreePine, Globe, ShieldAlert, Shield, Link2, Plus, Trash2, AlertTriangle, CheckCircle2 } from "lucide-react";
import AppShell from "@/components/AppShell";

const trustTypeColors: Record<string, string> = {
  parent_child: "#3b82f6",
  tree_root: "#8b5cf6",
  shortcut: "#f97316",
  forest: "#10b981",
  external: "#ef4444",
  realm: "#eab308",
};

const severityBadge: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

export default function ForestMapper() {
  const [activeTab, setActiveTab] = useState("topology");
  const [showAddDomainDialog, setShowAddDomainDialog] = useState(false);
  const [showAddTrustDialog, setShowAddTrustDialog] = useState(false);
  const [newDomain, setNewDomain] = useState({ forestName: "", domainName: "", isForestRoot: false, domainFunctionalLevel: "", forestFunctionalLevel: "" });
  const [newTrust, setNewTrust] = useState({ sourceDomainId: "", targetDomainId: "", direction: "bidirectional", trustType: "parent_child", isTransitive: true, sidFilteringEnabled: true, selectiveAuth: false });

  const topologyQuery = trpc.forestMapper.getTopology.useQuery();
  const statsQuery = trpc.forestMapper.getStats.useQuery();
  const domainsQuery = trpc.forestMapper.listDomains.useQuery();
  const trustsQuery = trpc.forestMapper.listTrusts.useQuery();

  const addDomainMut = trpc.forestMapper.addDomain.useMutation({
    onSuccess: () => { toast.success("Domain added"); domainsQuery.refetch(); topologyQuery.refetch(); statsQuery.refetch(); setShowAddDomainDialog(false); },
    onError: (e) => toast.error(e.message),
  });
  const deleteDomainMut = trpc.forestMapper.deleteDomain.useMutation({
    onSuccess: () => { toast.success("Domain deleted"); domainsQuery.refetch(); topologyQuery.refetch(); statsQuery.refetch(); },
  });
  const addTrustMut = trpc.forestMapper.addTrust.useMutation({
    onSuccess: (data) => {
      if (data.isVulnerable) {
        toast.warning(`Trust added with vulnerabilities: ${data.vulnerabilityNotes}`);
      } else {
        toast.success("Trust relationship added");
      }
      trustsQuery.refetch(); topologyQuery.refetch(); statsQuery.refetch(); setShowAddTrustDialog(false);
    },
    onError: (e) => toast.error(e.message),
  });
  const deleteTrustMut = trpc.forestMapper.deleteTrust.useMutation({
    onSuccess: () => { toast.success("Trust deleted"); trustsQuery.refetch(); topologyQuery.refetch(); statsQuery.refetch(); },
  });

  const topology = topologyQuery.data;
  const stats = statsQuery.data;
  const domains = domainsQuery.data || [];
  const trusts = trustsQuery.data || [];

  return (
    <AppShell>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <TreePine className="h-6 w-6 text-emerald-400" />
              Multi-Domain Forest Mapper
            </h1>
            <p className="text-muted-foreground mt-1">Map AD forest hierarchies and analyze cross-forest trust relationships</p>
          </div>
          <div className="flex gap-2">
            <Dialog open={showAddDomainDialog} onOpenChange={setShowAddDomainDialog}>
              <DialogTrigger asChild><Button variant="outline"><Plus className="h-4 w-4 mr-2" />Add Domain</Button></DialogTrigger>
              <DialogContent>
                <DialogHeader><DialogTitle>Add Forest Domain</DialogTitle></DialogHeader>
                <div className="space-y-4">
                  <div>
                    <label className="text-sm font-medium">Forest Name</label>
                    <Input value={newDomain.forestName} onChange={e => setNewDomain(p => ({ ...p, forestName: e.target.value }))} placeholder="e.g., corp.example.com" />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Domain Name</label>
                    <Input value={newDomain.domainName} onChange={e => setNewDomain(p => ({ ...p, domainName: e.target.value }))} placeholder="e.g., na.corp.example.com" />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Domain Functional Level</label>
                    <Select value={newDomain.domainFunctionalLevel} onValueChange={v => setNewDomain(p => ({ ...p, domainFunctionalLevel: v }))}>
                      <SelectTrigger><SelectValue placeholder="Select level" /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="2016">Windows Server 2016</SelectItem>
                        <SelectItem value="2019">Windows Server 2019</SelectItem>
                        <SelectItem value="2022">Windows Server 2022</SelectItem>
                        <SelectItem value="2025">Windows Server 2025</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch checked={newDomain.isForestRoot} onCheckedChange={v => setNewDomain(p => ({ ...p, isForestRoot: v }))} />
                    <label className="text-sm">This is the forest root domain</label>
                  </div>
                </div>
                <DialogFooter>
                  <Button onClick={() => addDomainMut.mutate({
                    forestName: newDomain.forestName,
                    domainName: newDomain.domainName,
                    isForestRoot: newDomain.isForestRoot,
                    domainFunctionalLevel: newDomain.domainFunctionalLevel || null,
                    forestFunctionalLevel: newDomain.isForestRoot ? newDomain.domainFunctionalLevel || null : null,
                  })} disabled={!newDomain.forestName || !newDomain.domainName}>
                    Add Domain
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
            <Dialog open={showAddTrustDialog} onOpenChange={setShowAddTrustDialog}>
              <DialogTrigger asChild><Button><Link2 className="h-4 w-4 mr-2" />Add Trust</Button></DialogTrigger>
              <DialogContent className="max-w-lg">
                <DialogHeader><DialogTitle>Add Trust Relationship</DialogTitle></DialogHeader>
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium">Source Domain</label>
                      <Select value={newTrust.sourceDomainId} onValueChange={v => setNewTrust(p => ({ ...p, sourceDomainId: v }))}>
                        <SelectTrigger><SelectValue placeholder="Select source" /></SelectTrigger>
                        <SelectContent>
                          {domains.map((d: any) => <SelectItem key={d.id} value={String(d.id)}>{d.domainName}</SelectItem>)}
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <label className="text-sm font-medium">Target Domain</label>
                      <Select value={newTrust.targetDomainId} onValueChange={v => setNewTrust(p => ({ ...p, targetDomainId: v }))}>
                        <SelectTrigger><SelectValue placeholder="Select target" /></SelectTrigger>
                        <SelectContent>
                          {domains.map((d: any) => <SelectItem key={d.id} value={String(d.id)}>{d.domainName}</SelectItem>)}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium">Direction</label>
                      <Select value={newTrust.direction} onValueChange={v => setNewTrust(p => ({ ...p, direction: v }))}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="inbound">Inbound</SelectItem>
                          <SelectItem value="outbound">Outbound</SelectItem>
                          <SelectItem value="bidirectional">Bidirectional</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <label className="text-sm font-medium">Trust Type</label>
                      <Select value={newTrust.trustType} onValueChange={v => setNewTrust(p => ({ ...p, trustType: v }))}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="parent_child">Parent-Child</SelectItem>
                          <SelectItem value="tree_root">Tree Root</SelectItem>
                          <SelectItem value="shortcut">Shortcut</SelectItem>
                          <SelectItem value="forest">Forest</SelectItem>
                          <SelectItem value="external">External</SelectItem>
                          <SelectItem value="realm">Realm</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <label className="text-sm">Transitive</label>
                      <Switch checked={newTrust.isTransitive} onCheckedChange={v => setNewTrust(p => ({ ...p, isTransitive: v }))} />
                    </div>
                    <div className="flex items-center justify-between">
                      <label className="text-sm">SID Filtering Enabled</label>
                      <Switch checked={newTrust.sidFilteringEnabled} onCheckedChange={v => setNewTrust(p => ({ ...p, sidFilteringEnabled: v }))} />
                    </div>
                    <div className="flex items-center justify-between">
                      <label className="text-sm">Selective Authentication</label>
                      <Switch checked={newTrust.selectiveAuth} onCheckedChange={v => setNewTrust(p => ({ ...p, selectiveAuth: v }))} />
                    </div>
                  </div>
                  {!newTrust.sidFilteringEnabled && (
                    <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 flex items-start gap-2">
                      <AlertTriangle className="h-4 w-4 text-red-400 mt-0.5 shrink-0" />
                      <p className="text-xs text-red-300">Disabling SID filtering creates a critical vulnerability allowing SID history injection attacks.</p>
                    </div>
                  )}
                </div>
                <DialogFooter>
                  <Button onClick={() => addTrustMut.mutate({
                    sourceDomainId: parseInt(newTrust.sourceDomainId),
                    targetDomainId: parseInt(newTrust.targetDomainId),
                    direction: newTrust.direction as any,
                    trustType: newTrust.trustType as any,
                    isTransitive: newTrust.isTransitive,
                    sidFilteringEnabled: newTrust.sidFilteringEnabled,
                    selectiveAuth: newTrust.selectiveAuth,
                  })} disabled={!newTrust.sourceDomainId || !newTrust.targetDomainId}>
                    Add Trust
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3 px-4">
              <div className="text-2xl font-bold">{stats?.totalForests ?? 0}</div>
              <div className="text-xs text-muted-foreground">Forests</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3 px-4">
              <div className="text-2xl font-bold">{stats?.totalDomains ?? 0}</div>
              <div className="text-xs text-muted-foreground">Domains</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3 px-4">
              <div className="text-2xl font-bold">{stats?.totalTrusts ?? 0}</div>
              <div className="text-xs text-muted-foreground">Trust Relationships</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3 px-4">
              <div className="text-2xl font-bold text-red-400">{stats?.vulnerableTrusts ?? 0}</div>
              <div className="text-xs text-muted-foreground">Vulnerable Trusts</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3 px-4">
              <div className="text-2xl font-bold text-blue-400">{stats?.totalUsers ?? 0}</div>
              <div className="text-xs text-muted-foreground">Total Users</div>
            </CardContent>
          </Card>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="topology">Forest Topology</TabsTrigger>
            <TabsTrigger value="domains">Domains</TabsTrigger>
            <TabsTrigger value="trusts">Trust Relationships</TabsTrigger>
            <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
          </TabsList>

          <TabsContent value="topology">
            <Card className="bg-card/50 border-border/50">
              <CardHeader><CardTitle className="text-base">Forest Topology Map</CardTitle></CardHeader>
              <CardContent>
                <div className="border border-border/50 rounded-lg overflow-hidden bg-black/20" style={{ height: "450px" }}>
                  <svg width="100%" height="100%" viewBox="0 0 1200 450">
                    {topology?.layout?.edges?.map((edge: any, i: number) => {
                      const source = topology.layout.nodes.find((n: any) => n.id === edge.source);
                      const target = topology.layout.nodes.find((n: any) => n.id === edge.target);
                      if (!source || !target) return null;
                      const color = trustTypeColors[edge.type] || "#6b7280";
                      return (
                        <g key={`edge-${i}`}>
                          <line x1={source.x} y1={source.y} x2={target.x} y2={target.y}
                            stroke={edge.isVulnerable ? "#ef4444" : color}
                            strokeWidth={edge.isVulnerable ? 3 : 2}
                            strokeDasharray={edge.isVulnerable ? "6,3" : "none"}
                            opacity={0.7}
                          />
                          <text x={(source.x + target.x) / 2} y={(source.y + target.y) / 2 - 8}
                            fill={color} fontSize="9" textAnchor="middle" opacity={0.8}>
                            {edge.label}
                          </text>
                        </g>
                      );
                    })}
                    {topology?.layout?.nodes?.map((node: any) => {
                      const isRoot = node.type === "root";
                      const r = isRoot ? 28 : 22;
                      return (
                        <g key={node.id}>
                          <circle cx={node.x} cy={node.y} r={r}
                            fill={isRoot ? "#1e3a5f" : "#1e293b"}
                            stroke={isRoot ? "#3b82f6" : "#475569"}
                            strokeWidth={isRoot ? 3 : 2}
                          />
                          {isRoot && <text x={node.x} y={node.y - 4} fill="#fbbf24" fontSize="10" textAnchor="middle" fontWeight="bold">ROOT</text>}
                          <text x={node.x} y={node.y + (isRoot ? 10 : 4)} fill="#e2e8f0" fontSize="9" textAnchor="middle" fontWeight="500">
                            {node.label.length > 18 ? node.label.slice(0, 16) + "..." : node.label}
                          </text>
                          <text x={node.x} y={node.y + r + 16} fill="#94a3b8" fontSize="8" textAnchor="middle">
                            {node.stats.users}U / {node.stats.computers}C
                          </text>
                        </g>
                      );
                    })}
                    {(!topology?.layout?.nodes || topology.layout.nodes.length === 0) && (
                      <text x="600" y="225" fill="#64748b" fontSize="14" textAnchor="middle">
                        No domains mapped yet. Add domains and trust relationships to build the topology.
                      </text>
                    )}
                  </svg>
                </div>
                {/* Legend */}
                <div className="flex flex-wrap gap-4 mt-3">
                  {Object.entries(trustTypeColors).map(([type, color]) => (
                    <div key={type} className="flex items-center gap-1.5">
                      <div className="w-4 h-0.5" style={{ backgroundColor: color }} />
                      <span className="text-xs text-muted-foreground capitalize">{type.replace("_", " ")}</span>
                    </div>
                  ))}
                  <div className="flex items-center gap-1.5 ml-4">
                    <div className="w-4 h-0.5 border-t-2 border-dashed border-red-500" />
                    <span className="text-xs text-muted-foreground">Vulnerable</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="domains" className="space-y-4">
            {domains.length === 0 ? (
              <Card className="bg-card/50 border-border/50">
                <CardContent className="py-12 text-center">
                  <Globe className="h-12 w-12 mx-auto text-muted-foreground/50 mb-4" />
                  <p className="text-muted-foreground">No domains mapped. Add a domain to start building the forest topology.</p>
                </CardContent>
              </Card>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {domains.map((domain: any) => (
                  <Card key={domain.id} className="bg-card/50 border-border/50">
                    <CardContent className="py-4 px-5">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          {domain.isForestRoot ? (
                            <TreePine className="h-5 w-5 text-emerald-400" />
                          ) : (
                            <Globe className="h-5 w-5 text-blue-400" />
                          )}
                          <div>
                            <div className="font-medium">{domain.domainName}</div>
                            <div className="text-xs text-muted-foreground">Forest: {domain.forestName}</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          {domain.isForestRoot && <Badge className="bg-emerald-500/20 text-emerald-400">Root</Badge>}
                          <Button variant="ghost" size="sm" onClick={() => deleteDomainMut.mutate({ domainId: domain.id })}>
                            <Trash2 className="h-4 w-4 text-red-400" />
                          </Button>
                        </div>
                      </div>
                      <div className="grid grid-cols-4 gap-2 text-xs mt-3">
                        <div><span className="text-muted-foreground">Users:</span> {domain.totalUsers || 0}</div>
                        <div><span className="text-muted-foreground">Groups:</span> {domain.totalGroups || 0}</div>
                        <div><span className="text-muted-foreground">Computers:</span> {domain.totalComputers || 0}</div>
                        <div><span className="text-muted-foreground">Privileged:</span> {domain.privilegedUsers || 0}</div>
                      </div>
                      {domain.domainFunctionalLevel && (
                        <div className="text-xs text-muted-foreground mt-2">Level: {domain.domainFunctionalLevel}</div>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </TabsContent>

          <TabsContent value="trusts" className="space-y-4">
            {trusts.length === 0 ? (
              <Card className="bg-card/50 border-border/50">
                <CardContent className="py-12 text-center">
                  <Link2 className="h-12 w-12 mx-auto text-muted-foreground/50 mb-4" />
                  <p className="text-muted-foreground">No trust relationships defined. Add trusts to map domain connections.</p>
                </CardContent>
              </Card>
            ) : (
              <div className="space-y-3">
                {trusts.map((trust: any) => {
                  const sourceDomain = domains.find((d: any) => d.id === trust.sourceDomainId);
                  const targetDomain = domains.find((d: any) => d.id === trust.targetDomainId);
                  return (
                    <Card key={trust.id} className={`bg-card/50 ${trust.isVulnerable ? "border-red-500/50" : "border-border/50"}`}>
                      <CardContent className="py-4 px-5">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: trustTypeColors[trust.trustType] || "#6b7280" }} />
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="font-medium text-sm">{sourceDomain?.domainName || `#${trust.sourceDomainId}`}</span>
                                <span className="text-muted-foreground">
                                  {trust.trustDirection === "bidirectional" ? "↔" : trust.trustDirection === "outbound" ? "→" : "←"}
                                </span>
                                <span className="font-medium text-sm">{targetDomain?.domainName || `#${trust.targetDomainId}`}</span>
                              </div>
                              <div className="flex items-center gap-2 mt-1">
                                <Badge variant="outline" className="text-xs capitalize">{trust.trustType.replace("_", " ")}</Badge>
                                {trust.isTransitive && <Badge variant="outline" className="text-xs">Transitive</Badge>}
                                {!trust.sidFilteringEnabled && <Badge className="bg-red-500/20 text-red-400 text-xs">No SID Filter</Badge>}
                                {trust.selectiveAuth && <Badge className="bg-green-500/20 text-green-400 text-xs">Selective Auth</Badge>}
                                {trust.isVulnerable && <Badge className="bg-red-500/20 text-red-400 text-xs"><ShieldAlert className="h-3 w-3 mr-1" />Vulnerable</Badge>}
                              </div>
                            </div>
                          </div>
                          <Button variant="ghost" size="sm" onClick={() => deleteTrustMut.mutate({ trustId: trust.id })}>
                            <Trash2 className="h-4 w-4 text-red-400" />
                          </Button>
                        </div>
                        {trust.vulnerabilityNotes && (
                          <p className="text-xs text-red-300 mt-2 ml-6">{trust.vulnerabilityNotes}</p>
                        )}
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            )}
          </TabsContent>

          <TabsContent value="vulnerabilities" className="space-y-4">
            {(!topology?.vulnerabilities || topology.vulnerabilities.length === 0) ? (
              <Card className="bg-card/50 border-border/50">
                <CardContent className="py-12 text-center">
                  <CheckCircle2 className="h-12 w-12 mx-auto text-green-400/50 mb-4" />
                  <p className="text-muted-foreground">No trust vulnerabilities detected. All trust configurations appear secure.</p>
                </CardContent>
              </Card>
            ) : (
              topology.vulnerabilities.map((vuln: any, i: number) => (
                <Card key={i} className="bg-card/50 border-border/50">
                  <CardContent className="py-4 px-5">
                    <div className="flex items-start gap-3">
                      <ShieldAlert className="h-5 w-5 text-red-400 mt-0.5 shrink-0" />
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge className={severityBadge[vuln.severity]}>{vuln.severity}</Badge>
                          <span className="font-medium text-sm">{vuln.vulnerabilityType}</span>
                        </div>
                        <p className="text-sm text-muted-foreground">{vuln.description}</p>
                        <div className="text-xs text-muted-foreground mt-2">
                          <span className="font-medium">Affected:</span> {vuln.sourceDomain} → {vuln.targetDomain}
                        </div>
                        <div className="bg-emerald-500/10 border border-emerald-500/20 rounded p-2 mt-2">
                          <span className="text-xs text-emerald-300 font-medium">Remediation:</span>
                          <p className="text-xs text-emerald-200 mt-0.5">{vuln.remediation}</p>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
