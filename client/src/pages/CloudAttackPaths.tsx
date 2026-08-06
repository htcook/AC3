import { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import {
  Cloud, Plus, Search, Shield, AlertTriangle, Server,
  ArrowRight, RefreshCw, TrendingUp, Activity, GitBranch, Network
} from "lucide-react";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-slate-500/20 text-slate-400 border-slate-500/30",
};

const PROVIDER_ICONS: Record<string, string> = {
  aws: "🔶",
  azure: "🔷",
  gcp: "🔴",
};

export default function CloudAttackPaths() {
  const [activeTab, setActiveTab] = useState("overview");
  const [searchQuery, setSearchQuery] = useState("");
  const [providerFilter, setProviderFilter] = useState<string>("all");
  const [showAddProvider, setShowAddProvider] = useState(false);
  const [showAddPath, setShowAddPath] = useState(false);

  // Form state for adding a provider
  const [newProvider, setNewProvider] = useState({
    provider: "aws" as "aws" | "azure" | "gcp",
    accountId: "",
    accountAlias: "",
    region: "",
  });

  // Form state for adding an attack path
  const [newPath, setNewPath] = useState({
    providerId: 0,
    pathName: "",
    attackType: "privilege_escalation" as const,
    provider: "aws" as "aws" | "azure" | "gcp",
    severity: "medium" as "critical" | "high" | "medium" | "low" | "info",
    sourceIdentity: "",
    targetResource: "",
    description: "",
    riskScore: 0,
  });

  const catalog = trpc.cloudAttackPaths.getCatalog.useQuery({});
  const providers = trpc.cloudAttackPaths.listProviders.useQuery({});
  const attackPaths = trpc.cloudAttackPaths.listAttackPaths.useQuery({});
  const stats = trpc.cloudAttackPaths.getStats.useQuery({});

  // Derive selected provider ID from providers list for the new path form
  const selectedProviderId = newPath.providerId > 0
    ? newPath.providerId
    : providers.data?.find(p => p.provider === newPath.provider)?.id ?? providers.data?.[0]?.id ?? 0;

  const addProviderMut = trpc.cloudAttackPaths.addProvider.useMutation({
    onSuccess: () => {
      toast.success("Cloud provider configuration saved.");
      setShowAddProvider(false);
      providers.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const addPathMut = trpc.cloudAttackPaths.createAttackPath.useMutation({
    onSuccess: () => {
      toast.success("Cloud attack path recorded.");
      setShowAddPath(false);
      attackPaths.refetch();
      stats.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const filteredCatalog = useMemo(() => {
    if (!catalog.data) return [] as NonNullable<typeof catalog.data>["attacks"];
    let items = [...catalog.data.attacks];
    if (providerFilter !== "all") {
      items = items.filter((a) => a.provider === providerFilter);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      items = items.filter((a) =>
        (a.name || '').toLowerCase().includes(q) || a.description.toLowerCase().includes(q)
      );
    }
    return items;
  }, [catalog.data, providerFilter, searchQuery]);

  const filteredPaths = useMemo(() => {
    if (!attackPaths.data) return [];
    let items = attackPaths.data;
    if (providerFilter !== "all") {
      items = items.filter((p) => p.provider === providerFilter);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      items = items.filter((p) =>
        (p.pathName || '').toLowerCase().includes(q) || (p.description ?? "").toLowerCase().includes(q)
      );
    }
    return items;
  }, [attackPaths.data, providerFilter, searchQuery]);

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
              <Cloud className="h-7 w-7 text-cyan-400" />
              Cloud Attack Paths
            </h1>
            <p className="text-muted-foreground mt-1">
              AWS IAM, Azure Entra ID, and GCP IAM privilege escalation and lateral movement analysis
            </p>
          </div>
          <div className="flex gap-2">
            <Dialog open={showAddProvider} onOpenChange={setShowAddProvider}>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm">
                  <Plus className="h-4 w-4 mr-1" /> Add Provider
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Add Cloud Provider</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <Label>Provider</Label>
                    <Select value={newProvider.provider} onValueChange={(v) => setNewProvider(p => ({ ...p, provider: v as "aws" | "azure" | "gcp" }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="aws">AWS</SelectItem>
                        <SelectItem value="azure">Azure</SelectItem>
                        <SelectItem value="gcp">GCP</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Account ID</Label>
                    <Input value={newProvider.accountId} onChange={(e) => setNewProvider(p => ({ ...p, accountId: e.target.value }))} placeholder="123456789012" />
                  </div>
                  <div>
                    <Label>Account Alias</Label>
                    <Input value={newProvider.accountAlias} onChange={(e) => setNewProvider(p => ({ ...p, accountAlias: e.target.value }))} placeholder="production-account" />
                  </div>
                  <div>
                    <Label>Region</Label>
                    <Input value={newProvider.region} onChange={(e) => setNewProvider(p => ({ ...p, region: e.target.value }))} placeholder="us-east-1" />
                  </div>
                  <Button className="w-full" onClick={() => addProviderMut.mutate(newProvider)} disabled={addProviderMut.isPending || !newProvider.accountId}>
                    {addProviderMut.isPending ? "Adding..." : "Add Provider"}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
            <Dialog open={showAddPath} onOpenChange={setShowAddPath}>
              <DialogTrigger asChild>
                <Button size="sm">
                  <GitBranch className="h-4 w-4 mr-1" /> Record Attack Path
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-lg">
                <DialogHeader>
                  <DialogTitle>Record Cloud Attack Path</DialogTitle>
                </DialogHeader>
                <div className="space-y-3 max-h-[60vh] overflow-y-auto pr-2">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <Label>Provider</Label>
                      <Select value={newPath.provider} onValueChange={(v) => setNewPath(p => ({ ...p, provider: v as "aws" | "azure" | "gcp" }))}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="aws">AWS</SelectItem>
                          <SelectItem value="azure">Azure</SelectItem>
                          <SelectItem value="gcp">GCP</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <Label>Severity</Label>
                      <Select value={newPath.severity} onValueChange={(v) => setNewPath(p => ({ ...p, severity: v as "critical" | "high" | "medium" | "low" | "info" }))}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="critical">Critical</SelectItem>
                          <SelectItem value="high">High</SelectItem>
                          <SelectItem value="medium">Medium</SelectItem>
                          <SelectItem value="low">Low</SelectItem>
                          <SelectItem value="info">Info</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div>
                    <Label>Path Name</Label>
                    <Input value={newPath.pathName} onChange={(e) => setNewPath(p => ({ ...p, pathName: e.target.value }))} placeholder="S3 bucket to admin role escalation" />
                  </div>
                  <div>
                    <Label>Attack Type</Label>
                    <Select value={newPath.attackType} onValueChange={(v) => setNewPath(p => ({ ...p, attackType: v as typeof newPath.attackType }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {["privilege_escalation", "role_chaining", "cross_account", "service_account_impersonation", "org_policy_bypass", "consent_grant_abuse", "app_registration_abuse", "pim_escalation", "s3_public_access", "storage_misconfiguration", "iam_misconfiguration", "lateral_movement", "data_exfiltration"].map(t => (
                          <SelectItem key={t} value={t}>{t.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Source Identity</Label>
                    <Input value={newPath.sourceIdentity} onChange={(e) => setNewPath(p => ({ ...p, sourceIdentity: e.target.value }))} placeholder="arn:aws:iam::123456789012:user/dev-user" />
                  </div>
                  <div>
                    <Label>Target Resource</Label>
                    <Input value={newPath.targetResource} onChange={(e) => setNewPath(p => ({ ...p, targetResource: e.target.value }))} placeholder="arn:aws:iam::123456789012:role/admin" />
                  </div>
                  <div>
                    <Label>Description</Label>
                    <Textarea value={newPath.description} onChange={(e) => setNewPath(p => ({ ...p, description: e.target.value }))} rows={3} />
                  </div>
                  <div>
                    <Label>Risk Score (0-10)</Label>
                    <Input type="number" min={0} max={10} step={0.1} value={newPath.riskScore} onChange={(e) => setNewPath(p => ({ ...p, riskScore: parseFloat(e.target.value) || 0 }))} />
                  </div>
                  {/* Provider selection for the attack path */}
                  {providers.data && providers.data.length > 1 && (
                    <div>
                      <Label>Target Provider Account</Label>
                      <Select
                        value={String(newPath.providerId || "")}
                        onValueChange={(v) => setNewPath(p => ({ ...p, providerId: parseInt(v) || 0 }))}
                      >
                        <SelectTrigger><SelectValue placeholder="Auto-select by provider type" /></SelectTrigger>
                        <SelectContent>
                          {providers.data.map(prov => (
                            <SelectItem key={prov.id} value={String(prov.id)}>
                              {PROVIDER_ICONS[prov.provider]} {prov.accountAlias || prov.accountId}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  )}
                  <Button className="w-full" onClick={() => {
                    if (!newPath.pathName) return;
                    if (selectedProviderId === 0 && (!providers.data || providers.data.length === 0)) {
                      toast.error("Add a cloud provider configuration first before recording attack paths.");
                      return;
                    }
                    addPathMut.mutate({
                      providerId: selectedProviderId,
                      pathName: newPath.pathName,
                      attackType: newPath.attackType,
                      provider: newPath.provider,
                      severity: newPath.severity,
                      sourceIdentity: newPath.sourceIdentity || undefined,
                      targetResource: newPath.targetResource || undefined,
                      description: newPath.description || undefined,
                      riskScore: newPath.riskScore || undefined,
                    });
                  }} disabled={addPathMut.isPending || !newPath.pathName}>
                    {addPathMut.isPending ? "Recording..." : "Record Attack Path"}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">Providers</p>
                  <p className="text-2xl font-bold text-foreground">{stats.data?.totalProviders ?? 0}</p>
                </div>
                <Server className="h-8 w-8 text-cyan-400/60" />
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">Attack Paths</p>
                  <p className="text-2xl font-bold text-foreground">{stats.data?.totalAttackPaths ?? 0}</p>
                </div>
                <GitBranch className="h-8 w-8 text-red-400/60" />
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">Misconfigs</p>
                  <p className="text-2xl font-bold text-foreground">{stats.data?.misconfigCheckCount ?? 0}</p>
                </div>
                <AlertTriangle className="h-8 w-8 text-purple-400/60" />
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">Catalog Attacks</p>
                  <p className="text-2xl font-bold text-foreground">{catalog.data?.total ?? 0}</p>
                </div>
                <AlertTriangle className="h-8 w-8 text-yellow-400/60" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Filters */}
        <div className="flex gap-3 items-center">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input placeholder="Search attacks or paths..." className="pl-9" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} />
          </div>
          <Select value={providerFilter} onValueChange={setProviderFilter}>
            <SelectTrigger className="w-40"><SelectValue placeholder="Provider" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Providers</SelectItem>
              <SelectItem value="aws">AWS</SelectItem>
              <SelectItem value="azure">Azure</SelectItem>
              <SelectItem value="gcp">GCP</SelectItem>
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" onClick={() => { catalog.refetch(); providers.refetch(); attackPaths.refetch(); stats.refetch(); }}>
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="catalog">Attack Catalog ({catalog.data?.total ?? 0})</TabsTrigger>
            <TabsTrigger value="paths">Discovered Paths ({filteredPaths.length})</TabsTrigger>
            <TabsTrigger value="providers">Providers ({providers.data?.length ?? 0})</TabsTrigger>
            <TabsTrigger value="graph"><Network className="h-4 w-4 mr-1" /> Attack Graph</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4">
            <div className="grid md:grid-cols-3 gap-4">
              {["aws", "azure", "gcp"].map(provider => {
                const providerAttacks = catalog.data?.attacks.filter((a) => a.provider === provider) ?? [];
                const providerPaths = attackPaths.data?.filter(p => p.provider === provider) ?? [];
                return (
                  <Card key={provider} className="bg-card/50 border-border/50">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-lg flex items-center gap-2">
                        <span className="text-xl">{PROVIDER_ICONS[provider]}</span>
                        {provider.toUpperCase()}
                      </CardTitle>
                      <CardDescription>{providerAttacks.length} attack vectors defined</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Discovered Paths</span>
                          <span className="font-mono text-foreground">{providerPaths.length}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Critical</span>
                          <span className="font-mono text-red-400">{providerPaths.filter(p => p.severity === "critical").length}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">High</span>
                          <span className="font-mono text-orange-400">{providerPaths.filter(p => p.severity === "high").length}</span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </TabsContent>

          <TabsContent value="catalog" className="space-y-3">
            {filteredCatalog.map((attack: (typeof filteredCatalog)[number]) => (
              <Card key={attack.id} className="bg-card/50 border-border/50 hover:border-cyan-500/30 transition-colors">
                <CardContent className="py-4">
                  <div className="flex items-start justify-between">
                    <div className="space-y-1 flex-1">
                      <div className="flex items-center gap-2">
                        <span>{PROVIDER_ICONS[attack.provider]}</span>
                        <h3 className="font-semibold text-foreground">{attack.name}</h3>
                        <Badge variant="outline" className={SEVERITY_COLORS[attack.severity]}>{attack.severity}</Badge>
                        <Badge variant="outline" className="text-xs">{attack.attackType.replace(/_/g, " ")}</Badge>
                      </div>
                      <p className="text-sm text-muted-foreground">{attack.description}</p>
                      <div className="flex gap-1 mt-1 flex-wrap">
                        {attack.mitreTechniques?.map((t: string) => (
                          <Badge key={t} variant="secondary" className="text-xs font-mono">{t}</Badge>
                        ))}
                      </div>
                    </div>
                    <div className="text-right ml-4">
                      <div className="text-xs text-muted-foreground">Severity</div>
                      <div className="text-lg font-bold text-foreground capitalize">{attack.severity}</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
            {filteredCatalog.length === 0 && (
              <div className="text-center py-12 text-muted-foreground">
                <Cloud className="h-12 w-12 mx-auto mb-3 opacity-40" />
                <p>No attack vectors match your filters</p>
              </div>
            )}
          </TabsContent>

          <TabsContent value="paths" className="space-y-3">
            {filteredPaths.map((path) => (
              <Card key={path.id} className="bg-card/50 border-border/50">
                <CardContent className="py-4">
                  <div className="flex items-start justify-between">
                    <div className="space-y-1 flex-1">
                      <div className="flex items-center gap-2">
                        <span>{PROVIDER_ICONS[path.provider]}</span>
                        <h3 className="font-semibold text-foreground">{path.pathName}</h3>
                        <Badge variant="outline" className={SEVERITY_COLORS[path.severity ?? "medium"]}>{path.severity}</Badge>
                        <Badge variant="outline" className="text-xs">{path.status}</Badge>
                      </div>
                      {path.sourceIdentity && path.targetResource && (
                        <div className="flex items-center gap-2 text-sm text-muted-foreground font-mono">
                          <span className="truncate max-w-[200px]">{path.sourceIdentity}</span>
                          <ArrowRight className="h-3 w-3 flex-shrink-0" />
                          <span className="truncate max-w-[200px]">{path.targetResource}</span>
                        </div>
                      )}
                      {path.description && <p className="text-sm text-muted-foreground">{path.description}</p>}
                    </div>
                    <div className="text-right ml-4">
                      <div className="text-xs text-muted-foreground">Risk</div>
                      <div className="text-lg font-bold text-foreground">{path.riskScore?.toFixed(1) ?? "—"}</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
            {filteredPaths.length === 0 && (
              <div className="text-center py-12 text-muted-foreground">
                <GitBranch className="h-12 w-12 mx-auto mb-3 opacity-40" />
                <p>No attack paths discovered yet</p>
                <Button variant="outline" size="sm" className="mt-3" onClick={() => setShowAddPath(true)}>
                  <Plus className="h-4 w-4 mr-1" /> Record First Path
                </Button>
              </div>
            )}
          </TabsContent>

          <TabsContent value="providers" className="space-y-3">
            {providers.data?.map((prov) => (
              <Card key={prov.id} className="bg-card/50 border-border/50">
                <CardContent className="py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className="text-2xl">{PROVIDER_ICONS[prov.provider]}</span>
                      <div>
                        <h3 className="font-semibold text-foreground">{prov.accountAlias || prov.accountId}</h3>
                        <p className="text-sm text-muted-foreground font-mono">{prov.accountId} · {prov.region || "global"}</p>
                      </div>
                    </div>
                    <Badge variant="outline" className={prov.status === "active" ? "text-green-400 border-green-500/30" : "text-yellow-400 border-yellow-500/30"}>
                      {prov.status}
                    </Badge>
                  </div>
                </CardContent>
              </Card>
            ))}
            {(!providers.data || providers.data.length === 0) && (
              <div className="text-center py-12 text-muted-foreground">
                <Server className="h-12 w-12 mx-auto mb-3 opacity-40" />
                <p>No cloud providers configured</p>
                <Button variant="outline" size="sm" className="mt-3" onClick={() => setShowAddProvider(true)}>
                  <Plus className="h-4 w-4 mr-1" /> Add First Provider
                </Button>
              </div>
            )}
          </TabsContent>

          {/* ── Attack Graph Tab ── */}
          <TabsContent value="graph">
            <AttackPathGraph
              attackPaths={attackPaths.data ?? []}
              catalog={catalog.data?.attacks ?? []}
              providers={providers.data ?? []}
            />
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}

// ── Attack Path Graph Visualization ──────────────────────────────────────
interface AttackPathGraphProps {
  attackPaths: any[];
  catalog: any[];
  providers: any[];
}

function AttackPathGraph({ attackPaths, catalog, providers }: AttackPathGraphProps) {
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [graphProvider, setGraphProvider] = useState<string>("all");

  // Build graph data from attack paths + catalog
  const graphData = useMemo(() => {
    const nodes: { id: string; type: string; data: any; position: { x: number; y: number } }[] = [];
    const edges: { id: string; source: string; target: string; animated?: boolean; style?: any; label?: string }[] = [];
    const nodeSet = new Set<string>();

    // Add provider nodes as root nodes
    const activeProviders = graphProvider === "all"
      ? ["aws", "azure", "gcp"]
      : [graphProvider];

    activeProviders.forEach((prov, pi) => {
      const provId = `provider-${prov}`;
      if (!nodeSet.has(provId)) {
        nodeSet.add(provId);
        nodes.push({
          id: provId,
          type: "provider",
          data: {
            label: prov.toUpperCase(),
            provider: prov,
            icon: prov === "aws" ? "\uD83D\uDD36" : prov === "azure" ? "\uD83D\uDD37" : "\uD83D\uDD34",
            accountCount: providers.filter(p => p.provider === prov).length,
          },
          position: { x: 400 * pi + 100, y: 50 },
        });
      }
    });

    // Add discovered attack paths as nodes and edges
    const pathsByProvider: Record<string, any[]> = {};
    const filteredPaths = graphProvider === "all" ? attackPaths : attackPaths.filter(p => p.provider === graphProvider);
    filteredPaths.forEach(path => {
      if (!pathsByProvider[path.provider]) pathsByProvider[path.provider] = [];
      pathsByProvider[path.provider].push(path);
    });

    Object.entries(pathsByProvider).forEach(([prov, paths]) => {
      paths.forEach((path, idx) => {
        // Source identity node
        const sourceId = `source-${path.id}-${path.sourceIdentity || "unknown"}`;
        if (!nodeSet.has(sourceId)) {
          nodeSet.add(sourceId);
          nodes.push({
            id: sourceId,
            type: "identity",
            data: {
              label: path.sourceIdentity || "Unknown Identity",
              identityType: path.attackType?.includes("service_account") ? "service_account" : "user",
              severity: path.severity,
              path,
            },
            position: { x: 100 + (idx % 4) * 250, y: 200 + Math.floor(idx / 4) * 200 },
          });
        }

        // Attack type node
        const attackId = `attack-${path.id}`;
        nodes.push({
          id: attackId,
          type: "attack",
          data: {
            label: path.pathName || path.attackType?.replace(/_/g, " "),
            attackType: path.attackType,
            severity: path.severity,
            riskScore: path.riskScore,
            mitreTechniques: path.mitreTechniques,
            description: path.description,
            path,
          },
          position: { x: 100 + (idx % 4) * 250, y: 400 + Math.floor(idx / 4) * 200 },
        });

        // Target resource node
        const targetId = `target-${path.id}-${path.targetResource || "unknown"}`;
        if (!nodeSet.has(targetId)) {
          nodeSet.add(targetId);
          nodes.push({
            id: targetId,
            type: "resource",
            data: {
              label: path.targetResource || "Target Resource",
              severity: path.severity,
              path,
            },
            position: { x: 100 + (idx % 4) * 250, y: 600 + Math.floor(idx / 4) * 200 },
          });
        }

        // Edges: provider -> source -> attack -> target
        edges.push({
          id: `e-prov-${prov}-${sourceId}`,
          source: `provider-${prov}`,
          target: sourceId,
          style: { stroke: "#64748b" },
        });
        edges.push({
          id: `e-${sourceId}-${attackId}`,
          source: sourceId,
          target: attackId,
          animated: path.severity === "critical" || path.severity === "high",
          style: {
            stroke: path.severity === "critical" ? "#ef4444"
              : path.severity === "high" ? "#f97316"
              : path.severity === "medium" ? "#eab308" : "#3b82f6",
          },
          label: path.attackType?.replace(/_/g, " "),
        });
        edges.push({
          id: `e-${attackId}-${targetId}`,
          source: attackId,
          target: targetId,
          animated: path.severity === "critical",
          style: {
            stroke: path.severity === "critical" ? "#ef4444"
              : path.severity === "high" ? "#f97316" : "#64748b",
          },
        });
      });
    });

    // If no discovered paths, show catalog items as potential paths
    if (filteredPaths.length === 0) {
      const catalogItems = graphProvider === "all" ? catalog.slice(0, 12) : catalog.filter(c => c.provider === graphProvider).slice(0, 8);
      catalogItems.forEach((item, idx) => {
        const prov = item.provider;
        const itemId = `catalog-${item.id}`;
        nodes.push({
          id: itemId,
          type: "catalog",
          data: {
            label: item.name,
            attackType: item.attackType,
            severity: item.severity,
            description: item.description,
            mitreTechniques: item.mitreTechniques,
            prerequisites: item.prerequisites,
            remediationSteps: item.remediationSteps,
          },
          position: { x: 80 + (idx % 4) * 280, y: 200 + Math.floor(idx / 4) * 160 },
        });
        edges.push({
          id: `e-prov-${prov}-${itemId}`,
          source: `provider-${prov}`,
          target: itemId,
          style: { stroke: "#475569", strokeDasharray: "5 5" },
        });
      });
    }

    return { nodes, edges };
  }, [attackPaths, catalog, providers, graphProvider]);

  const sevColor = (sev: string) =>
    sev === "critical" ? "border-red-500 bg-red-500/10"
    : sev === "high" ? "border-orange-500 bg-orange-500/10"
    : sev === "medium" ? "border-yellow-500 bg-yellow-500/10"
    : "border-blue-500 bg-blue-500/10";

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <Network className="h-5 w-5 text-cyan-400" />
            Attack Path Graph
          </h3>
          <p className="text-sm text-muted-foreground">
            Interactive visualization of discovered attack paths and privilege escalation chains.
            {attackPaths.length === 0 && " Showing potential attack patterns from the catalog."}
          </p>
        </div>
        <Select value={graphProvider} onValueChange={setGraphProvider}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Provider" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Providers</SelectItem>
            <SelectItem value="aws">AWS</SelectItem>
            <SelectItem value="azure">Azure</SelectItem>
            <SelectItem value="gcp">GCP</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Graph Canvas */}
      <Card className="border-border/50">
        <CardContent className="p-0">
          <div className="h-[600px] bg-background/50 rounded-lg overflow-hidden relative">
            {/* SVG-based graph rendering */}
            <svg width="100%" height="100%" viewBox={`0 0 ${Math.max(1200, graphData.nodes.length * 100)} ${Math.max(800, graphData.nodes.length * 60)}`} className="select-none">
              <defs>
                <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
                  <polygon points="0 0, 10 3.5, 0 7" fill="#64748b" />
                </marker>
                <marker id="arrowhead-red" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
                  <polygon points="0 0, 10 3.5, 0 7" fill="#ef4444" />
                </marker>
                <marker id="arrowhead-orange" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
                  <polygon points="0 0, 10 3.5, 0 7" fill="#f97316" />
                </marker>
              </defs>

              {/* Edges */}
              {graphData.edges.map(edge => {
                const source = graphData.nodes.find(n => n.id === edge.source);
                const target = graphData.nodes.find(n => n.id === edge.target);
                if (!source || !target) return null;
                const sx = source.position.x + 60;
                const sy = source.position.y + 30;
                const tx = target.position.x + 60;
                const ty = target.position.y;
                const mid = (sy + ty) / 2;
                return (
                  <g key={edge.id}>
                    <path
                      d={`M ${sx} ${sy} C ${sx} ${mid}, ${tx} ${mid}, ${tx} ${ty}`}
                      fill="none"
                      stroke={edge.style?.stroke || "#64748b"}
                      strokeWidth={edge.animated ? 2 : 1.5}
                      strokeDasharray={edge.style?.strokeDasharray}
                      markerEnd={edge.style?.stroke === "#ef4444" ? "url(#arrowhead-red)" : edge.style?.stroke === "#f97316" ? "url(#arrowhead-orange)" : "url(#arrowhead)"}
                      opacity={0.7}
                    />
                    {edge.animated && (
                      <circle r="3" fill={edge.style?.stroke || "#ef4444"}>
                        <animateMotion dur="2s" repeatCount="indefinite" path={`M ${sx} ${sy} C ${sx} ${mid}, ${tx} ${mid}, ${tx} ${ty}`} />
                      </circle>
                    )}
                  </g>
                );
              })}

              {/* Nodes */}
              {graphData.nodes.map(node => {
                const x = node.position.x;
                const y = node.position.y;
                const isSelected = selectedNode?.id === node.id;

                if (node.type === "provider") {
                  return (
                    <g key={node.id} onClick={() => setSelectedNode(node)} className="cursor-pointer">
                      <rect x={x} y={y} width={120} height={50} rx={8}
                        fill={node.data.provider === "aws" ? "#1a1a2e" : node.data.provider === "azure" ? "#1a1a2e" : "#1a1a2e"}
                        stroke={node.data.provider === "aws" ? "#f97316" : node.data.provider === "azure" ? "#3b82f6" : "#ef4444"}
                        strokeWidth={isSelected ? 3 : 2} />
                      <text x={x + 60} y={y + 22} textAnchor="middle" fill="white" fontSize="14" fontWeight="bold">
                        {node.data.icon} {node.data.label}
                      </text>
                      <text x={x + 60} y={y + 40} textAnchor="middle" fill="#94a3b8" fontSize="11">
                        {node.data.accountCount} account{node.data.accountCount !== 1 ? "s" : ""}
                      </text>
                    </g>
                  );
                }

                if (node.type === "identity") {
                  return (
                    <g key={node.id} onClick={() => setSelectedNode(node)} className="cursor-pointer">
                      <rect x={x} y={y} width={200} height={45} rx={6}
                        fill="#0f172a" stroke={isSelected ? "#22d3ee" : "#334155"} strokeWidth={isSelected ? 2 : 1} />
                      <text x={x + 10} y={y + 18} fill="#e2e8f0" fontSize="12" fontWeight="600">
                        \uD83D\uDC64 {(node.data.label || "").substring(0, 25)}
                      </text>
                      <text x={x + 10} y={y + 35} fill="#94a3b8" fontSize="10">
                        {node.data.identityType}
                      </text>
                    </g>
                  );
                }

                if (node.type === "attack") {
                  const sev = node.data.severity || "medium";
                  const borderColor = sev === "critical" ? "#ef4444" : sev === "high" ? "#f97316" : sev === "medium" ? "#eab308" : "#3b82f6";
                  return (
                    <g key={node.id} onClick={() => setSelectedNode(node)} className="cursor-pointer">
                      <rect x={x} y={y} width={220} height={55} rx={6}
                        fill="#1e1b2e" stroke={isSelected ? "#a855f7" : borderColor} strokeWidth={isSelected ? 2.5 : 1.5} />
                      <text x={x + 10} y={y + 20} fill="white" fontSize="12" fontWeight="bold">
                        \u26A0\uFE0F {(node.data.label || "").substring(0, 28)}
                      </text>
                      <text x={x + 10} y={y + 36} fill="#94a3b8" fontSize="10">
                        Risk: {node.data.riskScore ?? "N/A"} | {sev.toUpperCase()}
                      </text>
                      {node.data.mitreTechniques?.length > 0 && (
                        <text x={x + 10} y={y + 50} fill="#64748b" fontSize="9">
                          MITRE: {node.data.mitreTechniques.slice(0, 3).join(", ")}
                        </text>
                      )}
                    </g>
                  );
                }

                if (node.type === "resource") {
                  return (
                    <g key={node.id} onClick={() => setSelectedNode(node)} className="cursor-pointer">
                      <rect x={x} y={y} width={200} height={40} rx={6}
                        fill="#0f172a" stroke={isSelected ? "#22d3ee" : "#1e293b"} strokeWidth={isSelected ? 2 : 1} />
                      <text x={x + 10} y={y + 25} fill="#cbd5e1" fontSize="11">
                        \uD83C\uDFAF {(node.data.label || "").substring(0, 28)}
                      </text>
                    </g>
                  );
                }

                if (node.type === "catalog") {
                  const sev = node.data.severity || "medium";
                  const borderColor = sev === "critical" ? "#ef4444" : sev === "high" ? "#f97316" : sev === "medium" ? "#eab308" : "#3b82f6";
                  return (
                    <g key={node.id} onClick={() => setSelectedNode(node)} className="cursor-pointer" opacity={0.8}>
                      <rect x={x} y={y} width={240} height={55} rx={6}
                        fill="#0f172a" stroke={borderColor} strokeWidth={1} strokeDasharray="4 2" />
                      <text x={x + 10} y={y + 20} fill="#e2e8f0" fontSize="12" fontWeight="500">
                        {(node.data.label || "").substring(0, 30)}
                      </text>
                      <text x={x + 10} y={y + 36} fill="#94a3b8" fontSize="10">
                        {node.data.attackType?.replace(/_/g, " ")} | {sev}
                      </text>
                      {node.data.mitreTechniques?.length > 0 && (
                        <text x={x + 10} y={y + 50} fill="#64748b" fontSize="9">
                          MITRE: {node.data.mitreTechniques.slice(0, 3).join(", ")}
                        </text>
                      )}
                    </g>
                  );
                }

                return null;
              })}
            </svg>

            {/* Legend */}
            <div className="absolute bottom-3 left-3 bg-background/90 border border-border/50 rounded-lg p-3 text-xs space-y-1">
              <div className="font-semibold text-foreground mb-1">Legend</div>
              <div className="flex items-center gap-2"><span className="w-3 h-3 rounded border-2 border-orange-500 bg-orange-500/20" /> Provider</div>
              <div className="flex items-center gap-2"><span className="w-3 h-3 rounded border-2 border-slate-500 bg-slate-500/20" /> Identity</div>
              <div className="flex items-center gap-2"><span className="w-3 h-3 rounded border-2 border-purple-500 bg-purple-500/20" /> Attack Path</div>
              <div className="flex items-center gap-2"><span className="w-3 h-3 rounded border-2 border-cyan-500 bg-cyan-500/20" /> Target Resource</div>
              <div className="flex items-center gap-2"><span className="w-3 h-3 rounded border-2 border-slate-600 bg-slate-600/10" style={{ borderStyle: "dashed" }} /> Catalog (Potential)</div>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-red-400">\u25CF</span> Animated = Critical/High severity
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Selected Node Detail Panel */}
      {selectedNode && (
        <Card className="border-border/50">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base">
                {selectedNode.data.label}
              </CardTitle>
              <Button variant="ghost" size="sm" onClick={() => setSelectedNode(null)}>\u2715</Button>
            </div>
            {selectedNode.data.severity && (
              <Badge className={SEVERITY_COLORS[selectedNode.data.severity]}>
                {selectedNode.data.severity}
              </Badge>
            )}
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            {selectedNode.data.description && (
              <div>
                <span className="font-medium text-muted-foreground">Description:</span>
                <p className="mt-1 text-foreground">{selectedNode.data.description}</p>
              </div>
            )}
            {selectedNode.data.attackType && (
              <div>
                <span className="font-medium text-muted-foreground">Attack Type:</span>
                <span className="ml-2 text-foreground">{selectedNode.data.attackType.replace(/_/g, " ")}</span>
              </div>
            )}
            {selectedNode.data.riskScore != null && (
              <div>
                <span className="font-medium text-muted-foreground">Risk Score:</span>
                <span className="ml-2 text-foreground font-mono">{selectedNode.data.riskScore}</span>
              </div>
            )}
            {selectedNode.data.mitreTechniques?.length > 0 && (
              <div>
                <span className="font-medium text-muted-foreground">MITRE Techniques:</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedNode.data.mitreTechniques.map((t: string) => (
                    <Badge key={t} variant="outline" className="text-xs">{t}</Badge>
                  ))}
                </div>
              </div>
            )}
            {selectedNode.data.prerequisites?.length > 0 && (
              <div>
                <span className="font-medium text-muted-foreground">Prerequisites:</span>
                <ul className="list-disc list-inside mt-1 text-foreground">
                  {selectedNode.data.prerequisites.map((p: string, i: number) => <li key={i}>{p}</li>)}
                </ul>
              </div>
            )}
            {selectedNode.data.remediationSteps?.length > 0 && (
              <div>
                <span className="font-medium text-muted-foreground">Remediation:</span>
                <ul className="list-disc list-inside mt-1 text-foreground">
                  {selectedNode.data.remediationSteps.map((r: string, i: number) => <li key={i}>{r}</li>)}
                </ul>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
