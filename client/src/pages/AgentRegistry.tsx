import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { toast } from "sonner";
import {
  Bot, Search, Shield, Eye, Sword, PenTool, FileText, Cpu,
  ChevronRight, CheckCircle2, XCircle, Zap, Target,
  Layers, ArrowRight, RefreshCw, ToggleLeft, ToggleRight,
} from "lucide-react";

const CATEGORY_ICONS: Record<string, any> = {
  osint_analyst: Eye,
  pentester: Sword,
  social_engineer: PenTool,
  red_team_operator: Target,
  report_writer: FileText,
  recon_analyst: Search,
  exploit_selector: Zap,
  evasion_optimizer: Shield,
  lateral_planner: ArrowRight,
  persistence_engineer: Cpu,
  custom: Bot,
};

const CATEGORY_COLORS: Record<string, string> = {
  osint_analyst: "text-cyan-400 bg-cyan-400/10",
  pentester: "text-red-400 bg-red-400/10",
  social_engineer: "text-amber-400 bg-amber-400/10",
  red_team_operator: "text-orange-400 bg-orange-400/10",
  report_writer: "text-blue-400 bg-blue-400/10",
  recon_analyst: "text-teal-400 bg-teal-400/10",
  exploit_selector: "text-rose-400 bg-rose-400/10",
  evasion_optimizer: "text-violet-400 bg-violet-400/10",
  lateral_planner: "text-indigo-400 bg-indigo-400/10",
  persistence_engineer: "text-emerald-400 bg-emerald-400/10",
  custom: "text-zinc-400 bg-zinc-400/10",
};

function parseJsonSafe(val: unknown): any[] {
  if (Array.isArray(val)) return val;
  if (typeof val === "string") {
    try { return JSON.parse(val); } catch { return []; }
  }
  return [];
}

export default function AgentRegistry() {
  const [search, setSearch] = useState("");
  const [selectedAgent, setSelectedAgent] = useState<any>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [activeTab, setActiveTab] = useState("all");

  const { data, isLoading, refetch } = trpc.agentRegistry.listAgents.useQuery(undefined);
  const agents = data?.agents ?? [];

  const seedMutation = trpc.agentRegistry.seedAgents.useMutation({
    onSuccess: (result) => {
      toast.success(`Seeded ${result.created} agents, updated ${result.updated}`);
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const statusMutation = trpc.agentRegistry.setAgentStatus.useMutation({
    onSuccess: (result) => {
      toast.success(`Agent ${result.agentId} set to ${result.newStatus}`);
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const filteredAgents = useMemo(() => {
    let filtered = agents;
    if (activeTab !== "all") {
      filtered = filtered.filter((a: any) => a.category === activeTab);
    }
    if (search) {
      const q = search.toLowerCase();
      filtered = filtered.filter((a: any) =>
        a.name?.toLowerCase().includes(q) ||
        a.persona?.toLowerCase().includes(q) ||
        a.mission?.toLowerCase().includes(q)
      );
    }
    return filtered;
  }, [agents, activeTab, search]);

  const categories = useMemo(() => {
    const cats = new Set(agents.map((a: any) => a.category));
    return Array.from(cats);
  }, [agents]);

  const stats = useMemo(() => ({
    total: agents.length,
    active: agents.filter((a: any) => a.status === "active").length,
    inactive: agents.filter((a: any) => a.status !== "active").length,
    categories: new Set(agents.map((a: any) => a.category)).size,
  }), [agents]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Bot className="h-7 w-7 text-purple-400" />
            Agent Registry
          </h1>
          <p className="text-muted-foreground mt-1">
            Manage offensive security agent definitions for LLM specialist routing and the NEXUS graduation pipeline
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isLoading}>
            <RefreshCw className="h-4 w-4 mr-1" /> Refresh
          </Button>
          <Button size="sm" onClick={() => seedMutation.mutate()} disabled={seedMutation.isPending}>
            <Zap className="h-4 w-4 mr-1" />
            {seedMutation.isPending ? "Seeding..." : "Seed Agents"}
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Total Agents", value: stats.total, icon: Bot, color: "text-purple-400/40" },
          { label: "Active", value: stats.active, icon: CheckCircle2, color: "text-emerald-400/40", textColor: "text-emerald-400" },
          { label: "Inactive", value: stats.inactive, icon: XCircle, color: "text-zinc-400/40", textColor: "text-zinc-400" },
          { label: "Categories", value: stats.categories, icon: Layers, color: "text-blue-400/40", textColor: "text-blue-400" },
        ].map(({ label, value, icon: Icon, color, textColor }) => (
          <Card key={label} className="bg-card/50">
            <CardContent className="pt-4 pb-3 px-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">{label}</p>
                  <p className={`text-2xl font-bold ${textColor || ""}`}>{value}</p>
                </div>
                <Icon className={`h-8 w-8 ${color}`} />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input placeholder="Search agents by name, persona, or mission..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-10" />
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="flex-wrap h-auto gap-1">
          <TabsTrigger value="all">All ({agents.length})</TabsTrigger>
          {categories.map((cat: any) => (
            <TabsTrigger key={cat} value={cat} className="capitalize">
              {cat.replace(/_/g, " ")} ({agents.filter((a: any) => a.category === cat).length})
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value={activeTab} className="mt-4">
          {isLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {[1, 2, 3, 4, 5].map((i) => (
                <Card key={i} className="animate-pulse bg-card/30"><CardContent className="h-48" /></Card>
              ))}
            </div>
          ) : filteredAgents.length === 0 ? (
            <Card className="bg-card/30 border-dashed">
              <CardContent className="flex flex-col items-center justify-center py-12">
                <Bot className="h-12 w-12 text-muted-foreground/30 mb-3" />
                <p className="text-muted-foreground">
                  {agents.length === 0 ? "No agents found. Click 'Seed Agents' to populate the registry." : "No agents match your search."}
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredAgents.map((agent: any) => {
                const CatIcon = CATEGORY_ICONS[agent.category] || Bot;
                const catColor = CATEGORY_COLORS[agent.category] || "text-zinc-400 bg-zinc-400/10";
                const rules = parseJsonSafe(agent.coreRules);
                const workflow = parseJsonSafe(agent.workflowSteps);
                return (
                  <Card key={agent.id} className={`cursor-pointer hover:border-purple-400/50 transition-colors ${agent.status !== "active" ? "opacity-60" : ""}`} onClick={() => { setSelectedAgent(agent); setDetailOpen(true); }}>
                    <CardHeader className="pb-2">
                      <div className="flex items-start justify-between">
                        <div className="flex items-center gap-2">
                          <div className={`p-2 rounded-lg ${catColor}`}><CatIcon className="h-5 w-5" /></div>
                          <div>
                            <CardTitle className="text-base">{agent.name}</CardTitle>
                            <CardDescription className="text-xs capitalize">{agent.category?.replace(/_/g, " ")}</CardDescription>
                          </div>
                        </div>
                        <Badge variant={agent.status === "active" ? "default" : "secondary"} className="text-xs">{agent.status}</Badge>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <p className="text-sm text-muted-foreground line-clamp-2">{agent.mission}</p>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <Shield className="h-3 w-3" /><span>{rules.length} rules</span>
                        <span className="text-muted-foreground/30">|</span>
                        <ArrowRight className="h-3 w-3" /><span>{workflow.length} steps</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <p className="text-xs text-muted-foreground italic line-clamp-1">&ldquo;{agent.persona?.slice(0, 80)}...&rdquo;</p>
                        <ChevronRight className="h-4 w-4 text-muted-foreground/50" />
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* Agent Detail Dialog */}
      <Dialog open={detailOpen} onOpenChange={setDetailOpen}>
        <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
          {selectedAgent && <AgentDetailContent agent={selectedAgent} onToggle={(agentId, newStatus) => {
            statusMutation.mutate({ agentId, status: newStatus as any });
            setSelectedAgent({ ...selectedAgent, status: newStatus });
          }} togglePending={statusMutation.isPending} onClose={() => setDetailOpen(false)} />}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function AgentDetailContent({ agent, onToggle, togglePending, onClose }: { agent: any; onToggle: (agentId: string, status: string) => void; togglePending: boolean; onClose: () => void }) {
  const CatIcon = CATEGORY_ICONS[agent.category] || Bot;
  const catColor = CATEGORY_COLORS[agent.category] || "text-zinc-400 bg-zinc-400/10";
  const rules = parseJsonSafe(agent.coreRules);
  const workflow = parseJsonSafe(agent.workflowSteps);
  const deliverables = parseJsonSafe(agent.deliverableTemplates);
  const mitre = parseJsonSafe(agent.mitreTactics);
  const tools = parseJsonSafe(agent.toolAccess);

  return (
    <>
      <DialogHeader>
        <div className="flex items-center gap-3">
          <div className={`p-3 rounded-xl ${catColor}`}><CatIcon className="h-6 w-6" /></div>
          <div>
            <DialogTitle className="text-xl">{agent.name}</DialogTitle>
            <DialogDescription className="capitalize">{agent.category?.replace(/_/g, " ")} Agent &middot; v{agent.version}</DialogDescription>
          </div>
        </div>
      </DialogHeader>

      <div className="space-y-5 mt-2">
        {/* Status & Toggle */}
        <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30">
          <div className="flex items-center gap-2">
            <Badge variant={agent.status === "active" ? "default" : "secondary"}>{agent.status}</Badge>
            <span className="text-sm text-muted-foreground">Priority: {agent.priority}</span>
            {agent.llmCallerPrefix && <Badge variant="outline" className="text-xs font-mono">{agent.llmCallerPrefix}</Badge>}
          </div>
          <Button variant="outline" size="sm" onClick={() => onToggle(agent.agentId, agent.status === "active" ? "deprecated" : "active")} disabled={togglePending}>
            {agent.status === "active" ? <><ToggleRight className="h-4 w-4 mr-1" /> Deactivate</> : <><ToggleLeft className="h-4 w-4 mr-1" /> Activate</>}
          </Button>
        </div>

        {/* Persona */}
        <div>
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-2">Persona</h3>
          <p className="text-sm leading-relaxed whitespace-pre-line">{agent.persona}</p>
        </div>

        {/* Mission */}
        <div>
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-2">Mission</h3>
          <p className="text-sm leading-relaxed whitespace-pre-line">{agent.mission}</p>
        </div>

        {/* Rules */}
        {rules.length > 0 && (
          <div>
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-2">Core Rules ({rules.length})</h3>
            <div className="space-y-1.5">
              {rules.map((rule: string, i: number) => (
                <div key={i} className="flex items-start gap-2 text-sm">
                  <Shield className="h-3.5 w-3.5 mt-0.5 text-amber-400 shrink-0" /><span>{rule}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Workflow */}
        {workflow.length > 0 && (
          <div>
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-2">Workflow Steps ({workflow.length})</h3>
            <div className="space-y-2">
              {workflow.map((step: any, i: number) => (
                <div key={i} className="flex items-start gap-3 p-2 rounded-lg bg-muted/20">
                  <div className="flex items-center justify-center h-6 w-6 rounded-full bg-purple-400/20 text-purple-400 text-xs font-bold shrink-0">{step.step || i + 1}</div>
                  <div>
                    <p className="text-sm font-medium">{step.name}</p>
                    {step.description && <p className="text-xs text-muted-foreground mt-0.5">{step.description}</p>}
                    {step.qualityGate && <Badge variant="outline" className="mt-1 text-xs">Gate: {step.qualityGate}</Badge>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* MITRE */}
        {mitre.length > 0 && (
          <div>
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-2">MITRE ATT&CK ({mitre.length})</h3>
            <div className="flex flex-wrap gap-1.5">{mitre.map((t: string, i: number) => <Badge key={i} variant="outline" className="text-xs">{t}</Badge>)}</div>
          </div>
        )}

        {/* Tools */}
        {tools.length > 0 && (
          <div>
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-2">Tool Access ({tools.length})</h3>
            <div className="flex flex-wrap gap-1.5">{tools.map((t: string, i: number) => <Badge key={i} variant="secondary" className="text-xs font-mono">{t}</Badge>)}</div>
          </div>
        )}

        {/* Deliverables */}
        {deliverables.length > 0 && (
          <div>
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-2">Deliverables ({deliverables.length})</h3>
            <div className="grid grid-cols-2 gap-2">
              {deliverables.map((d: any, i: number) => (
                <div key={i} className="p-2 rounded-lg bg-muted/20 text-sm">
                  <p className="font-medium">{d.name}</p>
                  {d.format && <Badge variant="outline" className="mt-1 text-xs">{d.format}</Badge>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <DialogFooter className="mt-4">
        <Button variant="outline" onClick={onClose}>Close</Button>
      </DialogFooter>
    </>
  );
}
