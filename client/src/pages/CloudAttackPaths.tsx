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
  ArrowRight, RefreshCw, TrendingUp, Activity, GitBranch
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
        a.name.toLowerCase().includes(q) || a.description.toLowerCase().includes(q)
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
        p.pathName.toLowerCase().includes(q) || (p.description ?? "").toLowerCase().includes(q)
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
        </Tabs>
      </div>
    </AppShell>
  );
}
