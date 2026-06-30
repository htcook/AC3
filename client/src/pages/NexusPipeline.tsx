import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Workflow, Play, Search, CheckCircle2, XCircle, Clock,
  ArrowRight, RefreshCw, BarChart3, Layers, Shield,
  ChevronRight, Zap, TrendingUp, FileText, Code2, Eye,
  FlaskConical, Plus, Trash2, Settings, Scale,
} from "lucide-react";

const STAGE_ICONS: Record<string, any> = {
  requirement_analysis: FileText,
  architecture: Layers,
  code_generation: Code2,
  qa_validation: Shield,
  security_review: Eye,
  integration_test: Zap,
};

const STATUS_COLORS: Record<string, string> = {
  pending: "bg-zinc-500/20 text-zinc-400",
  running: "bg-blue-500/20 text-blue-400",
  completed: "bg-emerald-500/20 text-emerald-400",
  failed: "bg-red-500/20 text-red-400",
  rolled_back: "bg-amber-500/20 text-amber-400",
  paused: "bg-yellow-500/20 text-yellow-400",
};

const VERDICT_COLORS: Record<string, string> = {
  primary_better: "bg-blue-500/20 text-blue-400",
  experimental_better: "bg-emerald-500/20 text-emerald-400",
  tie: "bg-amber-500/20 text-amber-400",
  error: "bg-red-500/20 text-red-400",
};

const STAGE_ORDER = [
  "requirement_analysis", "architecture", "code_generation",
  "qa_validation", "security_review", "integration_test",
];

export default function NexusPipeline() {
  const [activeTab, setActiveTab] = useState("pipeline");

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Workflow className="h-7 w-7 text-purple-400" />
          NEXUS Pipeline
        </h1>
        <p className="text-muted-foreground mt-1">
          Multi-stage code generation pipeline with LLM-as-Judge quality gates and A/B shadow testing
        </p>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="pipeline" className="gap-1.5"><Workflow className="h-3.5 w-3.5" /> Pipeline</TabsTrigger>
          <TabsTrigger value="shadow" className="gap-1.5"><FlaskConical className="h-3.5 w-3.5" /> Shadow Testing</TabsTrigger>
        </TabsList>

        <TabsContent value="pipeline" className="mt-4">
          <PipelineTab />
        </TabsContent>

        <TabsContent value="shadow" className="mt-4">
          <ShadowTestingTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Pipeline Tab (existing functionality)
// ═══════════════════════════════════════════════════════════════════════════

function PipelineTab() {
  const [search, setSearch] = useState("");
  const [selectedExecution, setSelectedExecution] = useState<any>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [newPipelineOpen, setNewPipelineOpen] = useState(false);
  const [newPipeline, setNewPipeline] = useState({
    callerName: "",
    graduationTier: "3",
    constraints: "",
  });

  const { data, isLoading, refetch } = trpc.agentRegistry.listPipelines.useQuery(undefined);
  const executions = data?.executions ?? [];
  const summary = data?.summary;

  const { data: analyticsData } = trpc.agentRegistry.getPipelineAnalytics.useQuery(undefined);

  const triggerMutation = trpc.agentRegistry.triggerPipeline.useMutation({
    onSuccess: (result) => {
      toast.success(`Pipeline started: ${result.executionId}`);
      setNewPipelineOpen(false);
      setNewPipeline({ callerName: "", graduationTier: "3", constraints: "" });
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const filteredExecutions = useMemo(() => {
    if (!search) return executions;
    const q = search.toLowerCase();
    return executions.filter((e: any) =>
      e.callerName?.toLowerCase().includes(q) ||
      e.status?.toLowerCase().includes(q) ||
      e.currentStage?.toLowerCase().includes(q)
    );
  }, [executions, search]);

  return (
    <div className="space-y-6">
      {/* Actions */}
      <div className="flex justify-end gap-2">
        <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isLoading}>
          <RefreshCw className="h-4 w-4 mr-1" /> Refresh
        </Button>
        <Button size="sm" onClick={() => setNewPipelineOpen(true)}>
          <Play className="h-4 w-4 mr-1" /> New Execution
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-4">
        {[
          { label: "Total Runs", value: summary?.total ?? 0, icon: Workflow, color: "text-purple-400/40" },
          { label: "Completed", value: summary?.byStatus?.completed ?? 0, icon: CheckCircle2, color: "text-emerald-400/40", textColor: "text-emerald-400" },
          { label: "Failed", value: summary?.byStatus?.failed ?? 0, icon: XCircle, color: "text-red-400/40", textColor: "text-red-400" },
          { label: "Running", value: summary?.byStatus?.running ?? 0, icon: Clock, color: "text-blue-400/40", textColor: "text-blue-400" },
          { label: "Avg Score", value: summary?.avgScore ?? "N/A", icon: TrendingUp, color: "text-amber-400/40", textColor: "text-amber-400" },
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
        <Input placeholder="Search executions by caller, status, or stage..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-10" />
      </div>

      {/* Pipeline Architecture Diagram */}
      <Card className="bg-card/30">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Pipeline Architecture</CardTitle>
          <CardDescription>NEXUS-Micro: 6-stage code generation with quality gates</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between gap-1 overflow-x-auto py-2">
            {["Requirement Analysis", "Architecture", "Code Generation", "QA Validation", "Security Review", "Integration Test"].map((stage, i) => {
              const stageKey = STAGE_ORDER[i];
              const StageIcon = STAGE_ICONS[stageKey] || Workflow;
              const gateStats = analyticsData?.gateStats?.find((g: any) => g.gateType === stageKey.replace(/_/g, "_"));
              return (
                <div key={stage} className="flex items-center gap-1">
                  <div className="flex flex-col items-center gap-1 min-w-[100px]">
                    <div className="p-2 rounded-lg bg-purple-400/10">
                      <StageIcon className="h-5 w-5 text-purple-400" />
                    </div>
                    <span className="text-xs text-center text-muted-foreground">{stage}</span>
                    <Badge variant="outline" className="text-[10px]">Gate {i + 1}</Badge>
                    {gateStats && (
                      <span className="text-[10px] text-muted-foreground">{gateStats.passRate}% pass</span>
                    )}
                  </div>
                  {i < 5 && <ArrowRight className="h-4 w-4 text-muted-foreground/30 shrink-0" />}
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Top Graduated Callers */}
      {analyticsData?.topGraduated && analyticsData.topGraduated.length > 0 && (
        <Card className="bg-card/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Top Graduated Callers</CardTitle>
            <CardDescription>Highest-scoring completed pipeline executions</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {analyticsData.topGraduated.slice(0, 5).map((g: any, i: number) => (
                <div key={i} className="flex items-center justify-between p-2 rounded-lg bg-muted/20 text-sm">
                  <div className="flex items-center gap-2">
                    <div className="flex items-center justify-center h-6 w-6 rounded-full bg-amber-400/20 text-amber-400 text-xs font-bold">{i + 1}</div>
                    <span className="font-mono">{g.callerName}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <Badge variant="default">{g.overallScore}/100</Badge>
                    {g.costSaved && <span className="text-xs text-emerald-400">${parseFloat(g.costSaved).toFixed(2)} saved</span>}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Executions List */}
      {isLoading ? (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <Card key={i} className="animate-pulse bg-card/30"><CardContent className="h-24" /></Card>
          ))}
        </div>
      ) : filteredExecutions.length === 0 ? (
        <Card className="bg-card/30 border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Workflow className="h-12 w-12 text-muted-foreground/30 mb-3" />
            <p className="text-muted-foreground">
              {executions.length === 0 ? "No pipeline executions yet. Click 'New Execution' to start one." : "No executions match your search."}
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {filteredExecutions.map((execution: any) => {
            const stageHistory = Array.isArray(execution.stageHistory) ? execution.stageHistory : [];
            return (
              <Card key={execution.id} className="cursor-pointer hover:border-purple-400/50 transition-colors" onClick={() => { setSelectedExecution(execution); setDetailOpen(true); }}>
                <CardContent className="py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className={`px-3 py-1 rounded-full text-xs font-medium ${STATUS_COLORS[execution.status] || STATUS_COLORS.pending}`}>
                        {execution.status}
                      </div>
                      <div>
                        <p className="font-medium font-mono">{execution.callerName}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          Tier {execution.graduationTier} &middot; Stage: {execution.currentStage?.replace(/_/g, " ")}
                          {execution.tokensConsumed > 0 && ` \u00b7 ${execution.tokensConsumed.toLocaleString()} tokens`}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      {execution.overallScore > 0 && (
                        <div className="text-right">
                          <p className="text-lg font-bold text-amber-400">{execution.overallScore}</p>
                          <p className="text-[10px] text-muted-foreground">Score</p>
                        </div>
                      )}
                      {/* Stage progress dots */}
                      <div className="flex items-center gap-1">
                        {STAGE_ORDER.map((s) => {
                          const stageData = stageHistory.find((st: any) => st.stage === s);
                          let color = "bg-zinc-700";
                          if (stageData?.status === "passed") color = "bg-emerald-400";
                          else if (stageData?.status === "failed") color = "bg-red-400";
                          else if (execution.currentStage === s && execution.status === "running") color = "bg-blue-400 animate-pulse";
                          return <div key={s} className={`h-2 w-2 rounded-full ${color}`} />;
                        })}
                      </div>
                      <ChevronRight className="h-4 w-4 text-muted-foreground/50" />
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Execution Detail Dialog */}
      <Dialog open={detailOpen} onOpenChange={setDetailOpen}>
        <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
          {selectedExecution && <ExecutionDetail execution={selectedExecution} onClose={() => setDetailOpen(false)} />}
        </DialogContent>
      </Dialog>

      {/* New Pipeline Dialog */}
      <Dialog open={newPipelineOpen} onOpenChange={setNewPipelineOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>New Pipeline Execution</DialogTitle>
            <DialogDescription>Trigger the NEXUS-Micro code generation pipeline for a caller</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 mt-2">
            <div className="space-y-2">
              <Label>Caller Name</Label>
              <Input placeholder="e.g., specialist:osint-analyst:domain-enum" value={newPipeline.callerName} onChange={(e) => setNewPipeline({ ...newPipeline, callerName: e.target.value })} />
              <p className="text-xs text-muted-foreground">The LLM caller identifier to generate code for</p>
            </div>
            <div className="space-y-2">
              <Label>Graduation Tier</Label>
              <Select value={newPipeline.graduationTier} onValueChange={(v) => setNewPipeline({ ...newPipeline, graduationTier: v })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">Tier 1 - Basic</SelectItem>
                  <SelectItem value="2">Tier 2 - Intermediate</SelectItem>
                  <SelectItem value="3">Tier 3 - Advanced</SelectItem>
                  <SelectItem value="4">Tier 4 - Expert</SelectItem>
                  <SelectItem value="5">Tier 5 - Master</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Constraints (optional, one per line)</Label>
              <Textarea placeholder="Must handle rate limiting\nMax 100ms latency" value={newPipeline.constraints} onChange={(e) => setNewPipeline({ ...newPipeline, constraints: e.target.value })} rows={3} />
            </div>
          </div>
          <DialogFooter className="mt-4">
            <Button variant="outline" onClick={() => setNewPipelineOpen(false)}>Cancel</Button>
            <Button
              onClick={() => triggerMutation.mutate({
                callerName: newPipeline.callerName,
                graduationTier: Number(newPipeline.graduationTier),
                triggerType: "manual",
                constraints: newPipeline.constraints ? newPipeline.constraints.split("\n").filter(Boolean) : undefined,
              })}
              disabled={!newPipeline.callerName || triggerMutation.isPending}
            >
              <Play className="h-4 w-4 mr-1" />
              {triggerMutation.isPending ? "Starting..." : "Execute Pipeline"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Shadow Testing Tab
// ═══════════════════════════════════════════════════════════════════════════

function ShadowTestingTab() {
  const [configDialogOpen, setConfigDialogOpen] = useState(false);
  const [editingConfig, setEditingConfig] = useState<any>(null);

  const utils = trpc.useUtils();
  const { data: configsData, isLoading: configsLoading } = trpc.agentRegistry.listShadowConfigs.useQuery();
  const configs = configsData?.configs ?? [];

  const { data: analyticsData } = trpc.agentRegistry.getShadowAnalytics.useQuery(undefined);
  const { data: testsData } = trpc.agentRegistry.listShadowTests.useQuery(undefined);
  const recentTests = testsData?.tests ?? [];

  const upsertMutation = trpc.agentRegistry.upsertShadowConfig.useMutation({
    onSuccess: (result) => {
      toast.success(`Shadow config ${result.action}`);
      utils.agentRegistry.listShadowConfigs.invalidate();
      setConfigDialogOpen(false);
      setEditingConfig(null);
    },
    onError: (err) => toast.error(err.message),
  });

  const toggleMutation = trpc.agentRegistry.toggleShadowConfig.useMutation({
    onSuccess: (result) => {
      toast.success(`Shadow testing ${result.enabled ? "enabled" : "disabled"}`);
      utils.agentRegistry.listShadowConfigs.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const deleteMutation = trpc.agentRegistry.deleteShadowConfig.useMutation({
    onSuccess: () => {
      toast.success("Shadow config deleted");
      utils.agentRegistry.listShadowConfigs.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  // Compute verdict summary
  const verdictSummary = useMemo(() => {
    if (!analyticsData?.verdicts) return { primaryWins: 0, experimentalWins: 0, ties: 0, errors: 0, total: 0 };
    let primaryWins = 0, experimentalWins = 0, ties = 0, errors = 0;
    for (const v of analyticsData.verdicts) {
      if (v.verdict === 'primary_better') primaryWins = v.count;
      else if (v.verdict === 'experimental_better') experimentalWins = v.count;
      else if (v.verdict === 'tie') ties = v.count;
      else if (v.verdict === 'error') errors = v.count;
    }
    return { primaryWins, experimentalWins, ties, errors, total: primaryWins + experimentalWins + ties + errors };
  }, [analyticsData]);

  return (
    <div className="space-y-6">
      {/* Shadow Testing Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <FlaskConical className="h-5 w-5 text-cyan-400" />
            Shadow Testing — A/B Model Comparison
          </h2>
          <p className="text-sm text-muted-foreground mt-0.5">
            Route a percentage of LLM requests to experimental models for side-by-side quality comparison
          </p>
        </div>
        <Button size="sm" onClick={() => { setEditingConfig(null); setConfigDialogOpen(true); }}>
          <Plus className="h-4 w-4 mr-1" /> New Config
        </Button>
      </div>

      {/* Verdict Summary Stats */}
      <div className="grid grid-cols-5 gap-4">
        {[
          { label: "Total Tests", value: verdictSummary.total, icon: FlaskConical, color: "text-cyan-400/40" },
          { label: "Primary Wins", value: verdictSummary.primaryWins, icon: Shield, color: "text-blue-400/40", textColor: "text-blue-400" },
          { label: "Experimental Wins", value: verdictSummary.experimentalWins, icon: Zap, color: "text-emerald-400/40", textColor: "text-emerald-400" },
          { label: "Ties", value: verdictSummary.ties, icon: Scale, color: "text-amber-400/40", textColor: "text-amber-400" },
          { label: "Errors", value: verdictSummary.errors, icon: XCircle, color: "text-red-400/40", textColor: "text-red-400" },
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

      {/* Active Shadow Configs */}
      <Card className="bg-card/30">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Settings className="h-4 w-4" /> Shadow Test Configurations
          </CardTitle>
          <CardDescription>Manage which LLM calls get shadow-tested and against which experimental models</CardDescription>
        </CardHeader>
        <CardContent>
          {configsLoading ? (
            <div className="space-y-2">
              {[1, 2].map(i => <div key={i} className="h-16 bg-muted/20 rounded animate-pulse" />)}
            </div>
          ) : configs.length === 0 ? (
            <div className="flex flex-col items-center py-8 text-muted-foreground">
              <FlaskConical className="h-10 w-10 mb-2 opacity-30" />
              <p>No shadow test configurations yet.</p>
              <p className="text-xs mt-1">Create one to start A/B testing your LLM models.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {configs.map((config: any) => (
                <div key={config.id} className="flex items-center justify-between p-3 rounded-lg bg-muted/20 border border-border/30">
                  <div className="flex items-center gap-4">
                    <Switch
                      checked={config.enabled === 1}
                      onCheckedChange={(checked) => toggleMutation.mutate({ id: config.id, enabled: checked })}
                    />
                    <div>
                      <p className="font-medium text-sm">{config.configName}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        {config.primaryModel} vs {config.experimentalModel} &middot; {config.shadowPercentage}% traffic
                        {config.callerFilter ? ` \u00b7 Filter: ${config.callerFilter}` : ""}
                        {config.priorityFilter !== "all" ? ` \u00b7 Priority: ${config.priorityFilter}` : ""}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="text-right text-xs text-muted-foreground">
                      <p>{config.totalRuns} runs</p>
                      <p>{config.activeShadowTests} active</p>
                    </div>
                    <Badge variant={config.enabled === 1 ? "default" : "outline"}>
                      {config.enabled === 1 ? "Active" : "Paused"}
                    </Badge>
                    <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => { setEditingConfig(config); setConfigDialogOpen(true); }}>
                      <Settings className="h-3.5 w-3.5" />
                    </Button>
                    <Button variant="ghost" size="icon" className="h-8 w-8 text-red-400 hover:text-red-300" onClick={() => {
                      if (confirm(`Delete shadow config "${config.configName}"?`)) {
                        deleteMutation.mutate({ id: config.id });
                      }
                    }}>
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Latency & Token Comparison */}
      {analyticsData?.latencyComparison && (
        <Card className="bg-card/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <BarChart3 className="h-4 w-4" /> Performance Comparison
            </CardTitle>
            <CardDescription>Average latency and token usage across shadow tests</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-6">
              <div className="space-y-3">
                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Latency (ms)</h4>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-blue-400">Primary</span>
                    <span className="font-mono text-sm">{analyticsData.latencyComparison.avgPrimaryLatency}ms</span>
                  </div>
                  <div className="h-2 rounded-full bg-muted/30 overflow-hidden">
                    <div className="h-full bg-blue-400 rounded-full" style={{
                      width: `${Math.min(100, (analyticsData.latencyComparison.avgPrimaryLatency / Math.max(analyticsData.latencyComparison.avgPrimaryLatency, analyticsData.latencyComparison.avgExperimentalLatency, 1)) * 100)}%`
                    }} />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-emerald-400">Experimental</span>
                    <span className="font-mono text-sm">{analyticsData.latencyComparison.avgExperimentalLatency}ms</span>
                  </div>
                  <div className="h-2 rounded-full bg-muted/30 overflow-hidden">
                    <div className="h-full bg-emerald-400 rounded-full" style={{
                      width: `${Math.min(100, (analyticsData.latencyComparison.avgExperimentalLatency / Math.max(analyticsData.latencyComparison.avgPrimaryLatency, analyticsData.latencyComparison.avgExperimentalLatency, 1)) * 100)}%`
                    }} />
                  </div>
                </div>
              </div>
              <div className="space-y-3">
                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Avg Tokens</h4>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div className="p-2 rounded bg-muted/20 text-center">
                    <p className="text-xs text-muted-foreground">Primary In</p>
                    <p className="font-mono text-blue-400">{analyticsData.latencyComparison.avgPrimaryTokensIn}</p>
                  </div>
                  <div className="p-2 rounded bg-muted/20 text-center">
                    <p className="text-xs text-muted-foreground">Primary Out</p>
                    <p className="font-mono text-blue-400">{analyticsData.latencyComparison.avgPrimaryTokensOut}</p>
                  </div>
                  <div className="p-2 rounded bg-muted/20 text-center">
                    <p className="text-xs text-muted-foreground">Experimental In</p>
                    <p className="font-mono text-emerald-400">{analyticsData.latencyComparison.avgExperimentalTokensIn}</p>
                  </div>
                  <div className="p-2 rounded bg-muted/20 text-center">
                    <p className="text-xs text-muted-foreground">Experimental Out</p>
                    <p className="font-mono text-emerald-400">{analyticsData.latencyComparison.avgExperimentalTokensOut}</p>
                  </div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Top Callers by Shadow Test */}
      {analyticsData?.topCallers && analyticsData.topCallers.length > 0 && (
        <Card className="bg-card/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Top Callers by Shadow Test Volume</CardTitle>
            <CardDescription>Which LLM callers are being shadow-tested most frequently</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {analyticsData.topCallers.slice(0, 8).map((c: any, i: number) => (
                <div key={i} className="flex items-center justify-between p-2 rounded-lg bg-muted/20 text-sm">
                  <span className="font-mono truncate max-w-[300px]">{c.caller}</span>
                  <div className="flex items-center gap-3 text-xs">
                    <span>{c.total} tests</span>
                    <Badge variant="outline" className="text-blue-400">{c.primaryWins}P</Badge>
                    <Badge variant="outline" className="text-emerald-400">{c.experimentalWins}E</Badge>
                    <span className="text-muted-foreground">
                      Avg: {c.avgPrimaryScore} vs {c.avgExperimentalScore}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Recent Shadow Tests */}
      <Card className="bg-card/30">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Recent Shadow Test Results</CardTitle>
          <CardDescription>Latest LLM-as-Judge comparisons between primary and experimental models</CardDescription>
        </CardHeader>
        <CardContent>
          {recentTests.length === 0 ? (
            <div className="flex flex-col items-center py-8 text-muted-foreground">
              <Scale className="h-10 w-10 mb-2 opacity-30" />
              <p>No shadow test results yet.</p>
              <p className="text-xs mt-1">Enable a shadow config and make LLM calls to see results here.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {recentTests.map((test: any) => (
                <div key={test.id} className="flex items-center justify-between p-3 rounded-lg bg-muted/20 text-sm">
                  <div className="flex items-center gap-3">
                    <div className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${VERDICT_COLORS[test.judgeVerdict] || VERDICT_COLORS.error}`}>
                      {test.judgeVerdict?.replace(/_/g, " ")}
                    </div>
                    <div>
                      <p className="font-mono text-xs truncate max-w-[250px]">{test.caller}</p>
                      <p className="text-[10px] text-muted-foreground mt-0.5">
                        {test.primaryModel} vs {test.experimentalModel}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="text-right">
                      <div className="flex items-center gap-2 text-xs">
                        <span className="text-blue-400">{test.primaryScore ?? "—"}</span>
                        <span className="text-muted-foreground">vs</span>
                        <span className="text-emerald-400">{test.experimentalScore ?? "—"}</span>
                      </div>
                      {test.experimentalLatencyMs && (
                        <p className="text-[10px] text-muted-foreground">{test.experimentalLatencyMs}ms</p>
                      )}
                    </div>
                    <Badge variant={test.status === 'completed' ? 'default' : test.status === 'error' ? 'destructive' : 'outline'} className="text-[10px]">
                      {test.status}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Config Dialog */}
      <ShadowConfigDialog
        open={configDialogOpen}
        onOpenChange={setConfigDialogOpen}
        editingConfig={editingConfig}
        onSubmit={(data) => upsertMutation.mutate(data)}
        isPending={upsertMutation.isPending}
      />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Shadow Config Dialog
// ═══════════════════════════════════════════════════════════════════════════

function ShadowConfigDialog({
  open,
  onOpenChange,
  editingConfig,
  onSubmit,
  isPending,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editingConfig: any;
  onSubmit: (data: any) => void;
  isPending: boolean;
}) {
  const [form, setForm] = useState({
    configName: "",
    enabled: false,
    shadowPercentage: 5,
    primaryModel: "gemini-2.5-flash",
    experimentalModel: "gpt-4o",
    callerFilter: "",
    priorityFilter: "all",
    maxConcurrent: 10,
  });

  // Reset form when dialog opens
  useState(() => {
    if (editingConfig) {
      setForm({
        configName: editingConfig.configName || "",
        enabled: editingConfig.enabled === 1,
        shadowPercentage: editingConfig.shadowPercentage || 5,
        primaryModel: editingConfig.primaryModel || "gemini-2.5-flash",
        experimentalModel: editingConfig.experimentalModel || "gpt-4o",
        callerFilter: editingConfig.callerFilter || "",
        priorityFilter: editingConfig.priorityFilter || "all",
        maxConcurrent: editingConfig.maxConcurrent || 10,
      });
    } else {
      setForm({
        configName: "",
        enabled: false,
        shadowPercentage: 5,
        primaryModel: "gemini-2.5-flash",
        experimentalModel: "gpt-4o",
        callerFilter: "",
        priorityFilter: "all",
        maxConcurrent: 10,
      });
    }
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{editingConfig ? "Edit" : "New"} Shadow Test Configuration</DialogTitle>
          <DialogDescription>
            Configure which LLM calls to shadow-test and against which experimental model
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 mt-2">
          <div className="space-y-2">
            <Label>Config Name</Label>
            <Input
              placeholder="e.g., GPT-4o vs Gemini Flash"
              value={form.configName}
              onChange={(e) => setForm({ ...form, configName: e.target.value })}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Primary Model</Label>
              <Select value={form.primaryModel} onValueChange={(v) => setForm({ ...form, primaryModel: v })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="gemini-2.5-flash">Gemini 2.5 Flash</SelectItem>
                  <SelectItem value="gpt-4o">GPT-4o</SelectItem>
                  <SelectItem value="gpt-4o-mini">GPT-4o Mini</SelectItem>
                  <SelectItem value="claude-3.5-sonnet">Claude 3.5 Sonnet</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Experimental Model</Label>
              <Select value={form.experimentalModel} onValueChange={(v) => setForm({ ...form, experimentalModel: v })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="gemini-2.5-flash">Gemini 2.5 Flash</SelectItem>
                  <SelectItem value="gpt-4o">GPT-4o</SelectItem>
                  <SelectItem value="gpt-4o-mini">GPT-4o Mini</SelectItem>
                  <SelectItem value="claude-3.5-sonnet">Claude 3.5 Sonnet</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Shadow Percentage ({form.shadowPercentage}%)</Label>
              <Input
                type="range"
                min={1}
                max={100}
                value={form.shadowPercentage}
                onChange={(e) => setForm({ ...form, shadowPercentage: Number(e.target.value) })}
                className="cursor-pointer"
              />
              <p className="text-xs text-muted-foreground">{form.shadowPercentage}% of matching LLM calls will be shadow-tested</p>
            </div>
            <div className="space-y-2">
              <Label>Max Concurrent</Label>
              <Input
                type="number"
                min={1}
                max={50}
                value={form.maxConcurrent}
                onChange={(e) => setForm({ ...form, maxConcurrent: Number(e.target.value) })}
              />
              <p className="text-xs text-muted-foreground">Limit concurrent shadow tests to avoid overload</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Caller Filter (optional)</Label>
              <Input
                placeholder="e.g., specialist:osint"
                value={form.callerFilter}
                onChange={(e) => setForm({ ...form, callerFilter: e.target.value })}
              />
              <p className="text-xs text-muted-foreground">Only shadow-test callers starting with this prefix</p>
            </div>
            <div className="space-y-2">
              <Label>Priority Filter</Label>
              <Select value={form.priorityFilter} onValueChange={(v) => setForm({ ...form, priorityFilter: v })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Priorities</SelectItem>
                  <SelectItem value="essential">Essential Only</SelectItem>
                  <SelectItem value="standard">Standard Only</SelectItem>
                  <SelectItem value="bulk">Bulk Only</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Switch
              checked={form.enabled}
              onCheckedChange={(checked) => setForm({ ...form, enabled: checked })}
            />
            <Label>Enable immediately</Label>
          </div>
        </div>

        <DialogFooter className="mt-4">
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            onClick={() => onSubmit({
              ...(editingConfig?.id ? { id: editingConfig.id } : {}),
              ...form,
            })}
            disabled={!form.configName || isPending}
          >
            <FlaskConical className="h-4 w-4 mr-1" />
            {isPending ? "Saving..." : editingConfig ? "Update Config" : "Create Config"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Execution Detail (unchanged from before)
// ═══════════════════════════════════════════════════════════════════════════

function ExecutionDetail({ execution, onClose }: { execution: any; onClose: () => void }) {
  const stageHistory = Array.isArray(execution.stageHistory) ? execution.stageHistory : [];

  const { data: statusData } = trpc.agentRegistry.getPipelineStatus.useQuery(
    { executionId: execution.executionId },
    { enabled: !!execution.executionId }
  );
  const qualityGates = statusData?.qualityGates ?? [];

  return (
    <>
      <DialogHeader>
        <DialogTitle>Pipeline Execution Detail</DialogTitle>
        <DialogDescription className="font-mono">{execution.callerName}</DialogDescription>
      </DialogHeader>

      <div className="space-y-5 mt-2">
        {/* Status Bar */}
        <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30">
          <div className="flex items-center gap-3">
            <div className={`px-3 py-1 rounded-full text-xs font-medium ${STATUS_COLORS[execution.status] || STATUS_COLORS.pending}`}>
              {execution.status}
            </div>
            <span className="text-sm text-muted-foreground">Tier {execution.graduationTier} &middot; {execution.triggerType}</span>
          </div>
          <div className="flex items-center gap-4 text-sm">
            {execution.overallScore > 0 && <span className="font-bold text-amber-400">Score: {execution.overallScore}/100</span>}
            {execution.tokensConsumed > 0 && <span className="text-muted-foreground">{execution.tokensConsumed.toLocaleString()} tokens</span>}
            {execution.costSaved && <span className="text-emerald-400">${parseFloat(execution.costSaved).toFixed(2)} saved</span>}
          </div>
        </div>

        {/* Stage Results */}
        <div>
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">Stage Results</h3>
          <div className="space-y-3">
            {stageHistory.length > 0 ? stageHistory.map((stage: any, i: number) => {
              const StageIcon = STAGE_ICONS[stage.stage] || Workflow;
              const statusColor = stage.status === "passed" ? "bg-emerald-500/20 text-emerald-400" : stage.status === "failed" ? "bg-red-500/20 text-red-400" : "bg-zinc-500/20 text-zinc-400";
              return (
                <Card key={i} className="bg-muted/20">
                  <CardContent className="py-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <StageIcon className="h-4 w-4 text-purple-400" />
                        <span className="font-medium text-sm capitalize">{stage.stage?.replace(/_/g, " ")}</span>
                        <div className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${statusColor}`}>{stage.status}</div>
                      </div>
                      <div className="flex items-center gap-3 text-xs text-muted-foreground">
                        {stage.score != null && stage.score > 0 && <span className="font-bold text-amber-400">{stage.score}/100</span>}
                        {stage.retries > 0 && <span>{stage.retries} retries</span>}
                        {stage.agentUsed && <Badge variant="outline" className="text-[10px]">{stage.agentUsed}</Badge>}
                      </div>
                    </div>
                    {stage.evidence && (
                      <pre className="mt-2 text-xs text-muted-foreground bg-background/50 p-2 rounded max-h-32 overflow-y-auto whitespace-pre-wrap">
                        {stage.evidence.slice(0, 500)}
                      </pre>
                    )}
                  </CardContent>
                </Card>
              );
            }) : (
              <p className="text-sm text-muted-foreground">No stage results yet.</p>
            )}
          </div>
        </div>

        {/* Quality Gates */}
        {qualityGates.length > 0 && (
          <div>
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">Quality Gates</h3>
            <div className="space-y-2">
              {qualityGates.map((gate: any, i: number) => (
                <div key={i} className="flex items-center justify-between p-2 rounded-lg bg-muted/20 text-sm">
                  <div className="flex items-center gap-2">
                    {gate.passed ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : <XCircle className="h-4 w-4 text-red-400" />}
                    <span>{gate.gateName} ({gate.gateType?.replace(/_/g, " ")})</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold">{gate.score}/{gate.maxScore || 100}</span>
                    <Badge variant={gate.passed ? "default" : "destructive"} className="text-xs">{gate.passed ? "PASS" : "FAIL"}</Badge>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Generated Code Preview */}
        {execution.generatedCode && (
          <div>
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-2">Generated Code</h3>
            <pre className="text-xs bg-background/50 p-3 rounded max-h-48 overflow-y-auto whitespace-pre-wrap font-mono">
              {execution.generatedCode.slice(0, 2000)}
            </pre>
          </div>
        )}

        {/* Error Message */}
        {execution.errorMessage && (
          <div>
            <h3 className="text-sm font-semibold text-red-400 uppercase tracking-wider mb-2">Error</h3>
            <pre className="text-xs bg-red-500/10 text-red-300 p-3 rounded whitespace-pre-wrap">{execution.errorMessage}</pre>
          </div>
        )}

        {/* Metadata */}
        <div className="text-xs text-muted-foreground space-y-1">
          <p>Execution ID: <span className="font-mono">{execution.executionId}</span></p>
          <p>Started: {new Date(execution.startedAt).toLocaleString()}</p>
          {execution.completedAt && <p>Completed: {new Date(execution.completedAt).toLocaleString()}</p>}
          {execution.llmCallsCount > 0 && <p>LLM Calls: {execution.llmCallsCount}</p>}
        </div>
      </div>

      <DialogFooter className="mt-4">
        <Button variant="outline" onClick={onClose}>Close</Button>
      </DialogFooter>
    </>
  );
}
