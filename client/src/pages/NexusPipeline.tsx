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
import { toast } from "sonner";
import {
  Workflow, Play, Search, CheckCircle2, XCircle, Clock,
  ArrowRight, RefreshCw, BarChart3, Layers, Shield,
  ChevronRight, Zap, TrendingUp, FileText, Code2, Eye,
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

const STAGE_ORDER = [
  "requirement_analysis", "architecture", "code_generation",
  "qa_validation", "security_review", "integration_test",
];

export default function NexusPipeline() {
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
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Workflow className="h-7 w-7 text-purple-400" />
            NEXUS Pipeline
          </h1>
          <p className="text-muted-foreground mt-1">
            Multi-stage code generation pipeline with LLM-as-Judge quality gates — converts AI skills into executable code
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isLoading}>
            <RefreshCw className="h-4 w-4 mr-1" /> Refresh
          </Button>
          <Button size="sm" onClick={() => setNewPipelineOpen(true)}>
            <Play className="h-4 w-4 mr-1" /> New Execution
          </Button>
        </div>
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
                      <div className="flex gap-1">
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

function ExecutionDetail({ execution, onClose }: { execution: any; onClose: () => void }) {
  const stageHistory = Array.isArray(execution.stageHistory) ? execution.stageHistory : [];

  // Fetch quality gates for this execution
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
