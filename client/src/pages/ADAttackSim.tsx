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
  Shield, Plus, Search, Network, Key, Lock, Crown,
  RefreshCw, AlertTriangle, Users, Server, Swords
} from "lucide-react";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

const STATUS_COLORS: Record<string, string> = {
  pending: "bg-slate-500/20 text-slate-400",
  running: "bg-blue-500/20 text-blue-400",
  success: "bg-green-500/20 text-green-400",
  failed: "bg-red-500/20 text-red-400",
  blocked: "bg-purple-500/20 text-purple-400",
};

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  kerberos: <Key className="h-4 w-4" />,
  credential: <Lock className="h-4 w-4" />,
  persistence: <Crown className="h-4 w-4" />,
  delegation: <Network className="h-4 w-4" />,
};

export default function ADAttackSim() {
  const [activeTab, setActiveTab] = useState("catalog");
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [showAddEnv, setShowAddEnv] = useState(false);
  const [showAddSim, setShowAddSim] = useState(false);

  const [newEnv, setNewEnv] = useState({
    domainName: "",
    domainController: "",
    forestName: "",
    functionalLevel: "",
  });

  const catalog = trpc.adAttackSim.getCatalog.useQuery({});
  const environments = trpc.adAttackSim.listEnvironments.useQuery({});
  const simulations = trpc.adAttackSim.listSimulations.useQuery({});
  const stats = trpc.adAttackSim.getStats.useQuery({});

  const addEnvMut = trpc.adAttackSim.addEnvironment.useMutation({
    onSuccess: () => {
      toast.success("AD environment configured.");
      setShowAddEnv(false);
      environments.refetch();
      stats.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const addSimMut = trpc.adAttackSim.createSimulation.useMutation({
    onSuccess: () => {
      toast.success("AD attack simulation recorded.");
      setShowAddSim(false);
      simulations.refetch();
      stats.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const filteredCatalog = useMemo(() => {
    if (!catalog.data) return [];
    let items = catalog.data.attacks;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      items = items.filter((a: { name: string; description: string }) =>
        (a.name || '').toLowerCase().includes(q) || a.description.toLowerCase().includes(q)
      );
    }
    return items;
  }, [catalog.data, searchQuery]);

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
              <Shield className="h-7 w-7 text-purple-400" />
              Active Directory Attack Simulation
            </h1>
            <p className="text-muted-foreground mt-1">
              Kerberoasting, DCSync, Golden Ticket, Pass-the-Hash, delegation abuse, and more
            </p>
          </div>
          <div className="flex gap-2">
            <Dialog open={showAddEnv} onOpenChange={setShowAddEnv}>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm">
                  <Plus className="h-4 w-4 mr-1" /> Add Environment
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Add AD Environment</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <Label>Domain Name</Label>
                    <Input value={newEnv.domainName} onChange={(e) => setNewEnv(p => ({ ...p, domainName: e.target.value }))} placeholder="corp.example.com" />
                  </div>
                  <div>
                    <Label>Domain Controller</Label>
                    <Input value={newEnv.domainController} onChange={(e) => setNewEnv(p => ({ ...p, domainController: e.target.value }))} placeholder="dc01.corp.example.com" />
                  </div>
                  <div>
                    <Label>Forest Name</Label>
                    <Input value={newEnv.forestName} onChange={(e) => setNewEnv(p => ({ ...p, forestName: e.target.value }))} placeholder="example.com" />
                  </div>
                  <div>
                    <Label>Functional Level</Label>
                    <Select value={newEnv.functionalLevel} onValueChange={(v) => setNewEnv(p => ({ ...p, functionalLevel: v }))}>
                      <SelectTrigger><SelectValue placeholder="Select level" /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="2016">Windows Server 2016</SelectItem>
                        <SelectItem value="2019">Windows Server 2019</SelectItem>
                        <SelectItem value="2022">Windows Server 2022</SelectItem>
                        <SelectItem value="2025">Windows Server 2025</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <Button className="w-full" onClick={() => addEnvMut.mutate(newEnv)} disabled={addEnvMut.isPending || !newEnv.domainName}>
                    {addEnvMut.isPending ? "Adding..." : "Add Environment"}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
            <Dialog open={showAddSim} onOpenChange={setShowAddSim}>
              <DialogTrigger asChild>
                <Button size="sm">
                  <Swords className="h-4 w-4 mr-1" /> New Simulation
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Create Attack Simulation</DialogTitle>
                </DialogHeader>
                <div className="space-y-3">
                  <div>
                    <Label>Environment</Label>
                    <Select onValueChange={(v) => {}}>
                      <SelectTrigger><SelectValue placeholder="Select environment" /></SelectTrigger>
                      <SelectContent>
                        {environments.data?.map(env => (
                          <SelectItem key={env.id} value={String(env.id)}>{env.domainName}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <p className="text-sm text-muted-foreground">Select an attack from the catalog to configure and launch a simulation.</p>
                  <Button variant="outline" className="w-full" onClick={() => { setShowAddSim(false); setActiveTab("catalog"); }}>
                    Browse Attack Catalog
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Environments</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.totalEnvironments ?? 0}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">AD Objects</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.totalObjects ?? 0}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Simulations</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.totalSimulations ?? 0}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Attack Paths</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.totalAttackPaths ?? 0}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Catalog Size</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.catalogSize ?? 0}</p>
            </CardContent>
          </Card>
        </div>

        {/* Search */}
        <div className="flex gap-3 items-center">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input placeholder="Search attacks..." className="pl-9" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} />
          </div>
          <Button variant="outline" size="sm" onClick={() => { catalog.refetch(); environments.refetch(); simulations.refetch(); stats.refetch(); }}>
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="catalog">Attack Catalog ({catalog.data?.total ?? 0})</TabsTrigger>
            <TabsTrigger value="simulations">Simulations ({simulations.data?.length ?? 0})</TabsTrigger>
            <TabsTrigger value="environments">Environments ({environments.data?.length ?? 0})</TabsTrigger>
          </TabsList>

          <TabsContent value="catalog" className="space-y-3">
            {/* Category cards */}
            {catalog.data?.categories && (
              <div className="grid md:grid-cols-4 gap-3 mb-4">
                {(catalog.data.categories as string[]).map(cat => {
                  const catAttacks = catalog.data!.attacks.filter((a: { attackType: string }) => a.attackType === cat);
                  return (
                    <Card key={cat} className="bg-card/50 border-border/50 cursor-pointer hover:border-purple-500/30 transition-colors">
                      <CardContent className="py-3">
                        <div className="flex items-center gap-2">
                          <div className="text-purple-400">{CATEGORY_ICONS[cat] ?? <Shield className="h-4 w-4" />}</div>
                          <div>
                            <p className="font-semibold text-sm text-foreground capitalize">{cat.replace(/_/g, " ")}</p>
                            <p className="text-xs text-muted-foreground">{catAttacks.length} attacks</p>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            )}

            {filteredCatalog.map((attack: { id: string; name: string; attackType: string; severity: string; description: string; mitreTechniques: string[]; riskScore: number; prerequisites: string[]; detectionMethods: string[] }) => (
              <Card key={attack.id} className="bg-card/50 border-border/50 hover:border-purple-500/30 transition-colors">
                <CardContent className="py-4">
                  <div className="flex items-start justify-between">
                    <div className="space-y-2 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="font-semibold text-foreground">{attack.name}</h3>
                        <Badge variant="outline" className={SEVERITY_COLORS[attack.severity]}>{attack.severity}</Badge>
                        <Badge variant="outline" className="text-xs capitalize">{attack.attackType.replace(/_/g, " ")}</Badge>
                      </div>
                      <p className="text-sm text-muted-foreground">{attack.description}</p>
                      <div className="flex gap-1 flex-wrap">
                        {attack.mitreTechniques?.map((t: string) => (
                          <Badge key={t} variant="secondary" className="text-xs font-mono">{t}</Badge>
                        ))}
                      </div>
                      {attack.prerequisites?.length > 0 && (
                        <div className="text-xs text-muted-foreground">
                          <span className="font-medium text-foreground/70">Prerequisites:</span> {attack.prerequisites.join(", ")}
                        </div>
                      )}
                    </div>
                    <div className="text-right ml-4 flex-shrink-0">
                      <div className="text-xs text-muted-foreground">Risk</div>
                      <div className="text-lg font-bold text-foreground">{attack.riskScore}</div>
                      <Button variant="outline" size="sm" className="mt-2 text-xs" onClick={() => {
                        if (!environments.data?.length) {
                          toast.error("Add an AD environment first.");
                          return;
                        }
                        addSimMut.mutate({
                          environmentId: environments.data[0].id,
                          attackType: attack.attackType as Parameters<typeof addSimMut.mutate>[0]["attackType"],
                          description: attack.description,
                          riskScore: attack.riskScore,
                          severity: attack.severity as "critical" | "high" | "medium" | "low",
                          mitreTechniques: attack.mitreTechniques,
                          prerequisites: attack.prerequisites,
                        });
                      }}>
                        <Swords className="h-3 w-3 mr-1" /> Simulate
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </TabsContent>

          <TabsContent value="simulations" className="space-y-3">
            {simulations.data?.map((sim) => (
              <Card key={sim.id} className="bg-card/50 border-border/50">
                <CardContent className="py-4">
                  <div className="flex items-center justify-between">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold text-foreground capitalize">{sim.attackType.replace(/_/g, " ")}</h3>
                        <Badge variant="outline" className={STATUS_COLORS[sim.status]}>{sim.status}</Badge>
                        <Badge variant="outline" className={SEVERITY_COLORS[sim.severity ?? "high"]}>{sim.severity}</Badge>
                      </div>
                      {sim.targetObject && <p className="text-sm text-muted-foreground font-mono">Target: {sim.targetObject}</p>}
                      {sim.description && <p className="text-sm text-muted-foreground">{sim.description}</p>}
                    </div>
                    <div className="text-right">
                      <div className="text-xs text-muted-foreground">Risk</div>
                      <div className="text-lg font-bold">{sim.riskScore?.toFixed(1) ?? "—"}</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
            {(!simulations.data || simulations.data.length === 0) && (
              <div className="text-center py-12 text-muted-foreground">
                <Swords className="h-12 w-12 mx-auto mb-3 opacity-40" />
                <p>No simulations run yet</p>
                <p className="text-sm mt-1">Select an attack from the catalog to begin</p>
              </div>
            )}
          </TabsContent>

          <TabsContent value="environments" className="space-y-3">
            {environments.data?.map((env) => (
              <Card key={env.id} className="bg-card/50 border-border/50">
                <CardContent className="py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Server className="h-8 w-8 text-purple-400/60" />
                      <div>
                        <h3 className="font-semibold text-foreground">{env.domainName}</h3>
                        <p className="text-sm text-muted-foreground">
                          {env.domainController && `DC: ${env.domainController}`}
                          {env.forestName && ` · Forest: ${env.forestName}`}
                          {env.functionalLevel && ` · Level: ${env.functionalLevel}`}
                        </p>
                      </div>
                    </div>
                    <Badge variant="outline" className={env.status === "connected" ? "text-green-400 border-green-500/30" : "text-yellow-400 border-yellow-500/30"}>
                      {env.status}
                    </Badge>
                  </div>
                </CardContent>
              </Card>
            ))}
            {(!environments.data || environments.data.length === 0) && (
              <div className="text-center py-12 text-muted-foreground">
                <Network className="h-12 w-12 mx-auto mb-3 opacity-40" />
                <p>No AD environments configured</p>
                <Button variant="outline" size="sm" className="mt-3" onClick={() => setShowAddEnv(true)}>
                  <Plus className="h-4 w-4 mr-1" /> Add First Environment
                </Button>
              </div>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
