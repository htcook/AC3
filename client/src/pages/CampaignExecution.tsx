import { useState, useEffect, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { toast } from "sonner";
import {
  Play,
  Pause,
  Square,
  RefreshCw,
  Zap,
  Shield,
  Target,
  Activity,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Cpu,
  Link2,
  ChevronDown,
  ChevronRight,
  Loader2,
  Wand2,
  Brain,
  BarChart3,
  Timer,
  Eye,
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
  Download,
} from "lucide-react";

// Kill chain phase ordering
const TACTIC_ORDER = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
];

function tacticLabel(t: string) {
  return t
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

export default function CampaignExecution() {
  const [selectedOp, setSelectedOp] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const operations = trpc.calderaProxy.getOperations.useQuery(undefined, {
    refetchInterval: autoRefresh ? 5000 : false,
  });
  const agents = trpc.calderaProxy.getAgents.useQuery(undefined, {
    refetchInterval: autoRefresh ? 10000 : false,
  });
  const opDetail = trpc.calderaProxy.getOperationDetail.useQuery(
    { operationId: selectedOp! },
    { enabled: !!selectedOp, refetchInterval: autoRefresh ? 3000 : false }
  );

  const controlOp = trpc.calderaProxy.controlOperation.useMutation({
    onSuccess: (data) => {
      toast.success(`Operation ${data.newState}`);
      operations.refetch();
      if (selectedOp) opDetail.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const buildChain = trpc.calderaProxy.buildChain.useMutation({
    onSuccess: (data) => {
      toast.success(
        `Chain built: ${data.totalAbilities} abilities across ${data.techniquesCovered.length} techniques`
      );
      operations.refetch();
      if (selectedOp) opDetail.refetch();
    },
    onError: (err) => toast.error(`Chain build failed: ${err.message}`),
  });

  const autoBuildAll = trpc.calderaProxy.autoBuildAllChains.useMutation({
    onSuccess: (data) => {
      toast.success(`Built chains for ${data.totalOperations} operations`);
      operations.refetch();
    },
    onError: (err) => toast.error(`Auto-build failed: ${err.message}`),
  });

  const buildWithLLM = trpc.calderaProxy.buildChainWithLLM.useMutation({
    onSuccess: (data) => {
      toast.success(
        `LLM chain: ${data.totalAbilities} abilities (${data.method})`
      );
      operations.refetch();
      if (selectedOp) opDetail.refetch();
    },
    onError: (err) => toast.error(`LLM build failed: ${err.message}`),
  });

  const ops = operations.data || [];
  const agentList = agents.data || [];
  const detail = opDetail.data;

  const runningOps = ops.filter((o: any) => o.state === "running");
  const pausedOps = ops.filter((o: any) => o.state === "paused");
  const finishedOps = ops.filter(
    (o: any) => o.state === "finished" || o.state === "cleanup"
  );

  const activeAgents = agentList.filter((a: any) => {
    if (!a.last_seen) return false;
    const lastSeen = new Date(a.last_seen).getTime();
    return Date.now() - lastSeen < 300000;
  });

  // Total chain steps across all operations
  const totalChainSteps = ops.reduce(
    (sum: number, o: any) => sum + (o.chain?.length || 0),
    0
  );
  const totalAbilities = ops.reduce(
    (sum: number, o: any) =>
      sum + (o.adversary?.atomic_ordering?.length || 0),
    0
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Campaign Execution Dashboard</h1>
          <p className="text-muted-foreground mt-1">
            Real-time monitoring of Caldera operations, agent status, and
            technique progress
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={autoRefresh ? "border-green-500 text-green-500" : ""}
          >
            <Activity className="h-4 w-4 mr-1" />
            {autoRefresh ? "Live" : "Paused"}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              operations.refetch();
              agents.refetch();
            }}
          >
            <RefreshCw className="h-4 w-4 mr-1" />
            Refresh
          </Button>
          <Button
            size="sm"
            onClick={() => autoBuildAll.mutate({ scanId: 30122 })}
            disabled={autoBuildAll.isPending}
          >
            {autoBuildAll.isPending ? (
              <Loader2 className="h-4 w-4 mr-1 animate-spin" />
            ) : (
              <Wand2 className="h-4 w-4 mr-1" />
            )}
            Auto-Build All Chains
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/10">
                <Play className="h-5 w-5 text-green-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{runningOps.length}</p>
                <p className="text-xs text-muted-foreground">Running</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-yellow-500/10">
                <Pause className="h-5 w-5 text-yellow-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{pausedOps.length}</p>
                <p className="text-xs text-muted-foreground">Paused</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Cpu className="h-5 w-5 text-blue-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {activeAgents.length}/{agentList.length}
                </p>
                <p className="text-xs text-muted-foreground">Active Agents</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/10">
                <CheckCircle className="h-5 w-5 text-purple-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{finishedOps.length}</p>
                <p className="text-xs text-muted-foreground">Completed</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-orange-500/10">
                <Zap className="h-5 w-5 text-orange-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {totalChainSteps}/{totalAbilities}
                </p>
                <p className="text-xs text-muted-foreground">Steps/Abilities</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Operations List */}
        <div className="lg:col-span-1 space-y-3">
          <h2 className="text-lg font-semibold">Operations</h2>
          {ops.length === 0 && (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                No operations found
              </CardContent>
            </Card>
          )}
          {ops.map((op: any) => {
            const chainLen = op.chain?.length || 0;
            const abilityCount = op.adversary?.atomic_ordering?.length || 0;
            const progress =
              abilityCount > 0
                ? Math.round((chainLen / abilityCount) * 100)
                : 0;
            return (
              <Card
                key={op.id}
                className={`cursor-pointer transition-colors hover:border-primary/50 ${
                  selectedOp === op.id ? "border-primary bg-primary/5" : ""
                }`}
                onClick={() => setSelectedOp(op.id)}
              >
                <CardContent className="py-3 px-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-medium text-sm truncate max-w-[200px]">
                      {op.name}
                    </span>
                    <OperationStateBadge state={op.state} />
                  </div>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Target className="h-3 w-3" />
                    <span className="truncate">
                      {op.adversary?.name || "No adversary"}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground mt-1">
                    <Link2 className="h-3 w-3" />
                    <span>
                      {chainLen} steps executed
                    </span>
                    {abilityCount > 0 && (
                      <span className="ml-auto">{abilityCount} abilities</span>
                    )}
                  </div>
                  {abilityCount > 0 && (
                    <Progress value={progress} className="h-1 mt-2" />
                  )}
                  {op.state === "paused" &&
                    (!op.chain || op.chain.length === 0) && (
                      <div className="mt-2 flex gap-1">
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-6 text-xs"
                          onClick={(e) => {
                            e.stopPropagation();
                            buildChain.mutate({
                              operationId: op.id,
                              scanId: 30122,
                            });
                          }}
                          disabled={buildChain.isPending}
                        >
                          {buildChain.isPending ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            <Zap className="h-3 w-3 mr-1" />
                          )}
                          Build Chain
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-6 text-xs"
                          onClick={(e) => {
                            e.stopPropagation();
                            buildWithLLM.mutate({
                              operationId: op.id,
                              scanId: 30122,
                              campaignIndex: 0,
                            });
                          }}
                          disabled={buildWithLLM.isPending}
                        >
                          {buildWithLLM.isPending ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            <Brain className="h-3 w-3 mr-1" />
                          )}
                          LLM Build
                        </Button>
                      </div>
                    )}
                </CardContent>
              </Card>
            );
          })}
        </div>

        {/* Operation Detail */}
        <div className="lg:col-span-2">
          {!selectedOp ? (
            <Card>
              <CardContent className="py-16 text-center text-muted-foreground">
                <Target className="h-12 w-12 mx-auto mb-4 opacity-30" />
                <p>Select an operation to view details</p>
              </CardContent>
            </Card>
          ) : opDetail.isLoading ? (
            <Card>
              <CardContent className="py-16 text-center">
                <Loader2 className="h-8 w-8 mx-auto animate-spin text-muted-foreground" />
              </CardContent>
            </Card>
          ) : detail ? (
            <OperationDetailView
              detail={detail}
              onControl={(action) =>
                controlOp.mutate({ operationId: selectedOp, action })
              }
              controlPending={controlOp.isPending}
            />
          ) : (
            <Card>
              <CardContent className="py-16 text-center text-muted-foreground">
                Failed to load operation details
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* Agents Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Cpu className="h-5 w-5" />
            Connected Agents ({agentList.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {agentList.length === 0 ? (
            <p className="text-muted-foreground text-center py-4">
              No agents connected. Deploy an agent to begin operations.
            </p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {agentList.map((agent: any) => {
                const lastSeen = agent.last_seen
                  ? new Date(agent.last_seen)
                  : null;
                const isActive =
                  lastSeen && Date.now() - lastSeen.getTime() < 300000;
                return (
                  <div
                    key={agent.paw}
                    className="border rounded-lg p-3 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-sm">{agent.paw}</span>
                      <Badge variant={isActive ? "default" : "secondary"}>
                        {isActive ? "Active" : "Inactive"}
                      </Badge>
                    </div>
                    <div className="text-xs text-muted-foreground space-y-1">
                      <div className="flex justify-between">
                        <span>Platform:</span>
                        <span>{agent.platform || "Unknown"}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Host:</span>
                        <span className="truncate max-w-[150px]">
                          {agent.host || "Unknown"}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span>Privilege:</span>
                        <span>{agent.privilege || "User"}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Executors:</span>
                        <span>
                          {Array.isArray(agent.executors)
                            ? agent.executors.join(", ")
                            : "N/A"}
                        </span>
                      </div>
                      {lastSeen && (
                        <div className="flex justify-between">
                          <span>Last Seen:</span>
                          <span>{lastSeen.toLocaleTimeString()}</span>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function OperationStateBadge({ state }: { state: string }) {
  const variants: Record<
    string,
    {
      variant: "default" | "secondary" | "destructive" | "outline";
      icon: any;
    }
  > = {
    running: { variant: "default", icon: Play },
    paused: { variant: "secondary", icon: Pause },
    finished: { variant: "outline", icon: CheckCircle },
    cleanup: { variant: "outline", icon: Square },
  };
  const config = variants[state] || variants.paused;
  const Icon = config.icon;
  return (
    <Badge variant={config.variant} className="text-xs">
      <Icon className="h-3 w-3 mr-1" />
      {state}
    </Badge>
  );
}

function OperationDetailView({
  detail,
  onControl,
  controlPending,
}: {
  detail: any;
  onControl: (action: "pause" | "resume" | "stop" | "cleanup") => void;
  controlPending: boolean;
}) {
  const [expandedSteps, setExpandedSteps] = useState<Set<number>>(new Set());

  const toggleStep = (idx: number) => {
    setExpandedSteps((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const metrics = detail.metrics || {};
  const techniques = detail.techniques || [];
  const timeline = detail.timeline || [];

  // Group techniques by tactic for the ATT&CK overlay
  const tacticMap = useMemo(() => {
    const map: Record<string, { total: number; success: number; failed: number; partial: number; pending: number; techniques: any[] }> = {};
    for (const tech of techniques) {
      // Try to determine tactic from technique steps
      const tactic = tech.steps?.[0]?.tactic || "unknown";
      if (!map[tactic]) {
        map[tactic] = { total: 0, success: 0, failed: 0, partial: 0, pending: 0, techniques: [] };
      }
      map[tactic].total++;
      map[tactic].techniques.push(tech);
      if (tech.status === "success") map[tactic].success++;
      else if (tech.status === "failed") map[tactic].failed++;
      else if (tech.status === "partial") map[tactic].partial++;
      else map[tactic].pending++;
    }
    return map;
  }, [techniques]);

  const exportResults = () => {
    const data = {
      operation: detail.name,
      state: detail.state,
      adversary: detail.adversary?.name,
      metrics: detail.metrics,
      techniques: detail.techniques,
      timeline: detail.timeline,
      exportedAt: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `operation-${detail.name.replace(/\s+/g, "-")}-results.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Results exported");
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <CardTitle className="text-lg">{detail.name}</CardTitle>
            <p className="text-sm text-muted-foreground mt-1">
              Adversary: {detail.adversary?.name || "None"} | Planner:{" "}
              {detail.planner?.name || "atomic"} | Group: {detail.group || "Any"}
            </p>
          </div>
          <div className="flex gap-2 flex-wrap">
            <Button size="sm" variant="outline" onClick={exportResults}>
              <Download className="h-4 w-4 mr-1" />
              Export
            </Button>
            {detail.state === "paused" && (
              <Button
                size="sm"
                onClick={() => onControl("resume")}
                disabled={controlPending}
              >
                <Play className="h-4 w-4 mr-1" />
                Resume
              </Button>
            )}
            {detail.state === "running" && (
              <Button
                size="sm"
                variant="secondary"
                onClick={() => onControl("pause")}
                disabled={controlPending}
              >
                <Pause className="h-4 w-4 mr-1" />
                Pause
              </Button>
            )}
            {(detail.state === "running" || detail.state === "paused") && (
              <Button
                size="sm"
                variant="destructive"
                onClick={() => onControl("stop")}
                disabled={controlPending}
              >
                <Square className="h-4 w-4 mr-1" />
                Stop
              </Button>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="border rounded-lg p-3 text-center">
            <p className="text-2xl font-bold">{metrics.totalSteps || 0}</p>
            <p className="text-xs text-muted-foreground">Total Steps</p>
          </div>
          <div className="border rounded-lg p-3 text-center">
            <p className="text-2xl font-bold text-green-500">
              {metrics.successRate || 0}%
            </p>
            <p className="text-xs text-muted-foreground">Success Rate</p>
          </div>
          <div className="border rounded-lg p-3 text-center">
            <p className="text-2xl font-bold text-red-500">
              {metrics.detectionRate || 0}%
            </p>
            <p className="text-xs text-muted-foreground">Detection Rate</p>
          </div>
          <div className="border rounded-lg p-3 text-center">
            <p className="text-2xl font-bold text-blue-500">
              {metrics.progress || 0}%
            </p>
            <p className="text-xs text-muted-foreground">Progress</p>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span>Execution Progress</span>
            <span className="font-mono">{metrics.progress || 0}%</span>
          </div>
          <Progress value={metrics.progress || 0} className="h-2" />
          <div className="flex gap-4 text-xs text-muted-foreground flex-wrap">
            <span className="flex items-center gap-1">
              <CheckCircle className="h-3 w-3 text-green-500" />
              {metrics.successSteps || 0} success
            </span>
            <span className="flex items-center gap-1">
              <XCircle className="h-3 w-3 text-red-500" />
              {metrics.failedSteps || 0} failed
            </span>
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3 text-yellow-500" />
              {metrics.pendingSteps || 0} pending
            </span>
            <span className="ml-auto">
              {techniques.length} unique techniques
            </span>
          </div>
        </div>

        <Separator />

        <Tabs defaultValue="techniques">
          <TabsList className="flex-wrap">
            <TabsTrigger value="techniques">Techniques</TabsTrigger>
            <TabsTrigger value="attack-flow">ATT&CK Flow</TabsTrigger>
            <TabsTrigger value="timeline">Timeline</TabsTrigger>
            <TabsTrigger value="detection">Detection</TabsTrigger>
          </TabsList>

          {/* Techniques Tab */}
          <TabsContent value="techniques" className="space-y-2 mt-4">
            {techniques.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-30" />
                <p>
                  No technique data yet. Build a chain or start the operation.
                </p>
              </div>
            ) : (
              <div className="space-y-1 max-h-[500px] overflow-y-auto">
                {techniques.map((tech: any, idx: number) => {
                  const isExpanded = expandedSteps.has(idx);
                  const statusIcon =
                    tech.status === "success" ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : tech.status === "failed" ? (
                      <XCircle className="h-4 w-4 text-red-500" />
                    ) : tech.status === "partial" ? (
                      <AlertTriangle className="h-4 w-4 text-yellow-500" />
                    ) : tech.status === "running" ? (
                      <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />
                    ) : (
                      <Clock className="h-4 w-4 text-muted-foreground" />
                    );

                  return (
                    <div key={idx} className="border rounded-lg">
                      <div
                        className="flex items-center gap-3 p-3 cursor-pointer hover:bg-muted/50"
                        onClick={() => toggleStep(idx)}
                      >
                        {isExpanded ? (
                          <ChevronDown className="h-4 w-4 shrink-0" />
                        ) : (
                          <ChevronRight className="h-4 w-4 shrink-0" />
                        )}
                        {statusIcon}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs text-muted-foreground">
                              {tech.id}
                            </span>
                            <span className="text-sm font-medium truncate">
                              {tech.name}
                            </span>
                          </div>
                        </div>
                        <Badge variant="outline" className="text-xs shrink-0">
                          {tech.steps?.length || 0} steps
                        </Badge>
                      </div>
                      {isExpanded && tech.steps && (
                        <div className="px-3 pb-3 pt-0 border-t space-y-2">
                          {tech.steps.map((step: any, si: number) => (
                            <div
                              key={si}
                              className="text-xs space-y-1 p-2 bg-muted/30 rounded"
                            >
                              <div className="flex items-center justify-between">
                                <span className="font-medium">
                                  {step.abilityName || "Unknown"}
                                </span>
                                <Badge
                                  variant={
                                    step.status === "success"
                                      ? "default"
                                      : step.status === "failed"
                                      ? "destructive"
                                      : "secondary"
                                  }
                                  className="text-xs"
                                >
                                  {step.status}
                                </Badge>
                              </div>
                              {step.command && (
                                <pre className="p-2 bg-muted rounded text-xs overflow-x-auto max-h-[100px]">
                                  {step.command}
                                </pre>
                              )}
                              {step.output && (
                                <pre className="p-2 bg-muted rounded text-xs overflow-x-auto max-h-[100px]">
                                  {typeof step.output === "string"
                                    ? step.output
                                    : JSON.stringify(step.output, null, 2)}
                                </pre>
                              )}
                              <div className="flex gap-3 text-muted-foreground">
                                {step.paw && <span>Agent: {step.paw}</span>}
                                {step.executor && (
                                  <span>Executor: {step.executor}</span>
                                )}
                                {step.finish && (
                                  <span>
                                    {new Date(step.finish).toLocaleTimeString()}
                                  </span>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </TabsContent>

          {/* ATT&CK Flow Tab - Kill Chain Visualization */}
          <TabsContent value="attack-flow" className="mt-4">
            <AttackFlowView techniques={techniques} />
          </TabsContent>

          {/* Timeline Tab */}
          <TabsContent value="timeline" className="mt-4">
            <TimelineView timeline={timeline} />
          </TabsContent>

          {/* Detection Tab */}
          <TabsContent value="detection" className="mt-4">
            <DetectionRateView techniques={techniques} metrics={metrics} />
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}

function AttackFlowView({ techniques }: { techniques: any[] }) {
  // Group techniques by their tactic position in the kill chain
  const tacticGroups = useMemo(() => {
    const groups: Record<string, any[]> = {};
    for (const tech of techniques) {
      // Determine tactic from the technique ID or steps
      let tactic = "unknown";
      if (tech.steps?.[0]?.tactic) {
        tactic = tech.steps[0].tactic;
      }
      if (!groups[tactic]) groups[tactic] = [];
      groups[tactic].push(tech);
    }
    // Sort by kill chain order
    const sorted: [string, any[]][] = [];
    for (const t of TACTIC_ORDER) {
      if (groups[t]) sorted.push([t, groups[t]]);
    }
    // Add any remaining
    for (const [k, v] of Object.entries(groups)) {
      if (!TACTIC_ORDER.includes(k)) sorted.push([k, v]);
    }
    return sorted;
  }, [techniques]);

  if (techniques.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <Shield className="h-8 w-8 mx-auto mb-2 opacity-30" />
        <p>No technique data available. Run the operation to see the ATT&CK flow.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        MITRE ATT&CK Kill Chain progression showing technique execution status
        by tactic phase.
      </p>
      <div className="space-y-3">
        {tacticGroups.map(([tactic, techs]) => {
          const success = techs.filter((t: any) => t.status === "success").length;
          const failed = techs.filter((t: any) => t.status === "failed").length;
          const partial = techs.filter((t: any) => t.status === "partial").length;
          const total = techs.length;
          const pct = total > 0 ? Math.round((success / total) * 100) : 0;

          return (
            <div key={tactic} className="border rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div
                    className={`w-3 h-3 rounded-full ${
                      success === total && total > 0
                        ? "bg-green-500"
                        : failed > 0
                        ? "bg-red-500"
                        : partial > 0
                        ? "bg-yellow-500"
                        : "bg-muted-foreground"
                    }`}
                  />
                  <span className="font-medium text-sm">
                    {tacticLabel(tactic)}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">
                    {success}/{total} techniques
                  </span>
                  <Badge
                    variant={pct === 100 ? "default" : pct > 0 ? "secondary" : "outline"}
                    className="text-xs"
                  >
                    {pct}%
                  </Badge>
                </div>
              </div>
              <Progress value={pct} className="h-1.5 mb-3" />
              <div className="flex flex-wrap gap-2">
                {techs.map((tech: any, i: number) => (
                  <div
                    key={i}
                    className={`text-xs px-2 py-1 rounded border ${
                      tech.status === "success"
                        ? "bg-green-500/10 border-green-500/30 text-green-600 dark:text-green-400"
                        : tech.status === "failed"
                        ? "bg-red-500/10 border-red-500/30 text-red-600 dark:text-red-400"
                        : tech.status === "partial"
                        ? "bg-yellow-500/10 border-yellow-500/30 text-yellow-600 dark:text-yellow-400"
                        : tech.status === "running"
                        ? "bg-blue-500/10 border-blue-500/30 text-blue-600 dark:text-blue-400"
                        : "bg-muted border-border"
                    }`}
                    title={tech.name}
                  >
                    <span className="font-mono">{tech.id}</span>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function TimelineView({ timeline }: { timeline: any[] }) {
  if (timeline.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <Timer className="h-8 w-8 mx-auto mb-2 opacity-30" />
        <p>No timeline events yet. Start the operation to see execution timeline.</p>
      </div>
    );
  }

  return (
    <div className="space-y-1 max-h-[500px] overflow-y-auto">
      {timeline.map((event: any, idx: number) => {
        const time = event.time ? new Date(event.time) : null;
        const finishTime = event.finishTime ? new Date(event.finishTime) : null;
        const duration =
          time && finishTime
            ? Math.round((finishTime.getTime() - time.getTime()) / 1000)
            : null;

        return (
          <div
            key={idx}
            className="flex items-start gap-3 p-2 hover:bg-muted/50 rounded"
          >
            <div className="flex flex-col items-center">
              <div
                className={`w-2.5 h-2.5 rounded-full mt-1.5 ${
                  event.status === "success"
                    ? "bg-green-500"
                    : event.status === "failed"
                    ? "bg-red-500"
                    : "bg-blue-500 animate-pulse"
                }`}
              />
              {idx < timeline.length - 1 && (
                <div className="w-px h-8 bg-border mt-1" />
              )}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium truncate">
                  {event.abilityName}
                </span>
                <Badge
                  variant={
                    event.status === "success"
                      ? "default"
                      : event.status === "failed"
                      ? "destructive"
                      : "secondary"
                  }
                  className="text-xs shrink-0"
                >
                  {event.status}
                </Badge>
              </div>
              <div className="flex items-center gap-3 text-xs text-muted-foreground mt-0.5">
                <span className="font-mono">{event.techniqueId}</span>
                {event.paw && <span>Agent: {event.paw}</span>}
                {duration !== null && <span>{duration}s</span>}
                {time && <span>{time.toLocaleTimeString()}</span>}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function DetectionRateView({
  techniques,
  metrics,
}: {
  techniques: any[];
  metrics: any;
}) {
  const successTechs = techniques.filter((t: any) => t.status === "success");
  const failedTechs = techniques.filter((t: any) => t.status === "failed");
  const partialTechs = techniques.filter((t: any) => t.status === "partial");
  const pendingTechs = techniques.filter(
    (t: any) => t.status === "pending" || t.status === "running"
  );

  const total = techniques.length;
  const bypassRate = total > 0 ? Math.round((successTechs.length / total) * 100) : 0;
  const detectionRate = total > 0 ? Math.round((failedTechs.length / total) * 100) : 0;
  const partialRate = total > 0 ? Math.round((partialTechs.length / total) * 100) : 0;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card>
          <CardContent className="pt-4 pb-3 text-center">
            <ShieldAlert className="h-5 w-5 mx-auto mb-1 text-green-500" />
            <p className="text-2xl font-bold text-green-500">{bypassRate}%</p>
            <p className="text-xs text-muted-foreground">Bypass Rate</p>
            <p className="text-xs text-muted-foreground">
              {successTechs.length} techniques
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 text-center">
            <ShieldCheck className="h-5 w-5 mx-auto mb-1 text-red-500" />
            <p className="text-2xl font-bold text-red-500">{detectionRate}%</p>
            <p className="text-xs text-muted-foreground">Blocked</p>
            <p className="text-xs text-muted-foreground">
              {failedTechs.length} techniques
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 text-center">
            <Eye className="h-5 w-5 mx-auto mb-1 text-yellow-500" />
            <p className="text-2xl font-bold text-yellow-500">{partialRate}%</p>
            <p className="text-xs text-muted-foreground">Partial</p>
            <p className="text-xs text-muted-foreground">
              {partialTechs.length} techniques
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 text-center">
            <Clock className="h-5 w-5 mx-auto mb-1 text-muted-foreground" />
            <p className="text-2xl font-bold">{pendingTechs.length}</p>
            <p className="text-xs text-muted-foreground">Pending</p>
            <p className="text-xs text-muted-foreground">
              {total} total techniques
            </p>
          </CardContent>
        </Card>
      </div>

      {techniques.length > 0 ? (
        <div className="border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/50">
              <tr>
                <th className="text-left p-2">Technique</th>
                <th className="text-left p-2 hidden sm:table-cell">Name</th>
                <th className="text-center p-2">Steps</th>
                <th className="text-center p-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {techniques.map((t: any, i: number) => (
                <tr key={i} className="border-t">
                  <td className="p-2">
                    <span className="font-mono text-xs">{t.id}</span>
                  </td>
                  <td className="p-2 hidden sm:table-cell">
                    <span className="text-xs text-muted-foreground truncate block max-w-[200px]">
                      {t.name}
                    </span>
                  </td>
                  <td className="p-2 text-center text-xs">
                    {t.steps?.length || 0}
                  </td>
                  <td className="p-2 text-center">
                    {t.status === "success" ? (
                      <Badge className="bg-green-500/10 text-green-500 border-green-500/20 text-xs">
                        Bypassed
                      </Badge>
                    ) : t.status === "failed" ? (
                      <Badge className="bg-red-500/10 text-red-500 border-red-500/20 text-xs">
                        Blocked
                      </Badge>
                    ) : t.status === "partial" ? (
                      <Badge className="bg-yellow-500/10 text-yellow-500 border-yellow-500/20 text-xs">
                        Partial
                      </Badge>
                    ) : t.status === "running" ? (
                      <Badge className="bg-blue-500/10 text-blue-500 border-blue-500/20 text-xs">
                        Running
                      </Badge>
                    ) : (
                      <Badge variant="secondary" className="text-xs">
                        Pending
                      </Badge>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="text-center py-8 text-muted-foreground">
          <Shield className="h-8 w-8 mx-auto mb-2 opacity-30" />
          <p>
            No technique data available yet. Run the operation to see detection
            metrics.
          </p>
        </div>
      )}
    </div>
  );
}
