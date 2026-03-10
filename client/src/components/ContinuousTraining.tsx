/**
 * ContinuousTraining — Automated scan-until-100% accuracy loop
 *
 * Allows operators to start a continuous training loop that:
 * 1. Runs LLM analysis against a training target
 * 2. Scores results against ground truth
 * 3. Auto-generates learning entries from misses
 * 4. Re-runs analysis with enriched context
 * 5. Repeats until F1 reaches 100% or max iterations
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Brain,
  Play,
  Square,
  Target,
  TrendingUp,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Loader2,
  RefreshCw,
  Zap,
  Activity,
  Sparkles,
  BarChart3,
  ArrowRight,
  Trophy,
  Repeat,
  CircleDot,
} from "lucide-react";
import { toast } from "sonner";

// ─── Types ─────────────────────────────────────────────────────────────────

interface IterationResult {
  iteration: number;
  f1Score: number;
  precision: number;
  recall: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  feedbackGenerated: number;
  timestamp: number;
}

interface TrainingRunStatus {
  targetPreset: string;
  sessionId: string;
  status: "running" | "completed" | "stopped" | "failed";
  currentIteration: number;
  maxIterations: number;
  targetF1: number;
  iterations: IterationResult[];
  startedAt: number;
  completedAt?: number;
  bestF1: number;
  error?: string;
}

// ─── Component ─────────────────────────────────────────────────────────────

export default function ContinuousTraining() {
  const [selectedTarget, setSelectedTarget] = useState<string>("");
  const [maxIterations, setMaxIterations] = useState(10);

  // Queries
  const { data: targets } = trpc.trainingLab.listTargets.useQuery();
  const { data: statusData, refetch: refetchStatus } = trpc.trainingLab.continuousTrainingStatus.useQuery(undefined, {
    refetchInterval: 3000, // Poll every 3s while running
  });

  // Mutations
  const startMutation = trpc.trainingLab.startContinuousTraining.useMutation({
    onSuccess: (data) => {
      toast.success(`Continuous training started for ${data.targetPreset}`);
      refetchStatus();
    },
    onError: (err) => {
      toast.error(`Failed to start: ${err.message}`);
    },
  });

  const stopMutation = trpc.trainingLab.stopContinuousTraining.useMutation({
    onSuccess: () => {
      toast.info("Training loop stopped");
      refetchStatus();
    },
    onError: (err) => {
      toast.error(`Failed to stop: ${err.message}`);
    },
  });

  // Derived state
  const isRunning = statusData?.status === "running";
  const hasCompleted = statusData?.status === "completed";
  const hasFailed = statusData?.status === "failed";
  const iterations = statusData?.iterations || [];
  const bestF1 = statusData?.bestF1 || 0;
  const currentIteration = statusData?.currentIteration || 0;
  const maxIter = statusData?.maxIterations || maxIterations;

  // Filter targets that have ground truth
  const eligibleTargets = useMemo(() => {
    if (!targets) return [];
    return targets.filter((t: any) =>
      t.id !== "custom" && t.knownVulns && t.knownVulns.length > 0
    );
  }, [targets]);

  const handleStart = () => {
    if (!selectedTarget) {
      toast.error("Select a training target first");
      return;
    }
    startMutation.mutate({
      targetPreset: selectedTarget,
      maxIterations,
      targetF1: 1.0,
    });
  };

  const handleStop = () => {
    stopMutation.mutate();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Repeat className="w-6 h-6 text-primary" />
          <div>
            <h2 className="text-lg font-semibold text-foreground">Continuous Training Loop</h2>
            <p className="text-xs text-muted-foreground">
              Automatically re-scan and re-analyze until the LLM achieves 100% accuracy on vulnerability detection.
            </p>
          </div>
        </div>
        {isRunning && (
          <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30 animate-pulse">
            <Activity className="w-3 h-3 mr-1" /> Training Active
          </Badge>
        )}
        {hasCompleted && bestF1 >= 1.0 && (
          <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
            <Trophy className="w-3 h-3 mr-1" /> 100% Achieved
          </Badge>
        )}
      </div>

      {/* Controls */}
      <Card className="border-border">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Target className="w-4 h-4 text-primary" /> Training Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Target Selection */}
            <div className="space-y-1.5">
              <label className="text-xs text-muted-foreground uppercase tracking-wider">Target</label>
              <Select
                value={selectedTarget}
                onValueChange={setSelectedTarget}
                disabled={isRunning}
              >
                <SelectTrigger className="bg-card border-border">
                  <SelectValue placeholder="Select training target..." />
                </SelectTrigger>
                <SelectContent>
                  {eligibleTargets.map((t: any) => (
                    <SelectItem key={t.id} value={t.id}>
                      {t.name} ({t.knownVulns?.length || 0} vulns)
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Max Iterations */}
            <div className="space-y-1.5">
              <label className="text-xs text-muted-foreground uppercase tracking-wider">Max Iterations</label>
              <Select
                value={String(maxIterations)}
                onValueChange={(v) => setMaxIterations(Number(v))}
                disabled={isRunning}
              >
                <SelectTrigger className="bg-card border-border">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="5">5 iterations</SelectItem>
                  <SelectItem value="10">10 iterations</SelectItem>
                  <SelectItem value="15">15 iterations</SelectItem>
                  <SelectItem value="20">20 iterations</SelectItem>
                  <SelectItem value="30">30 iterations</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Action Button */}
            <div className="space-y-1.5">
              <label className="text-xs text-muted-foreground uppercase tracking-wider">&nbsp;</label>
              {isRunning ? (
                <Button
                  variant="destructive"
                  className="w-full"
                  onClick={handleStop}
                  disabled={stopMutation.isPending}
                >
                  {stopMutation.isPending ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Square className="w-4 h-4 mr-2" />
                  )}
                  Stop Training
                </Button>
              ) : (
                <Button
                  className="w-full"
                  onClick={handleStart}
                  disabled={!selectedTarget || startMutation.isPending}
                >
                  {startMutation.isPending ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Play className="w-4 h-4 mr-2" />
                  )}
                  Start Training Loop
                </Button>
              )}
            </div>
          </div>

          {/* How it works */}
          <div className="p-3 rounded bg-muted/30 border border-border">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2 font-medium">How It Works</p>
            <div className="flex items-center gap-2 text-xs text-muted-foreground flex-wrap">
              <span className="flex items-center gap-1 bg-card px-2 py-1 rounded border border-border">
                <Zap className="w-3 h-3 text-blue-400" /> Analyze
              </span>
              <ArrowRight className="w-3 h-3 text-muted-foreground/50" />
              <span className="flex items-center gap-1 bg-card px-2 py-1 rounded border border-border">
                <BarChart3 className="w-3 h-3 text-amber-400" /> Score
              </span>
              <ArrowRight className="w-3 h-3 text-muted-foreground/50" />
              <span className="flex items-center gap-1 bg-card px-2 py-1 rounded border border-border">
                <Brain className="w-3 h-3 text-purple-400" /> Learn
              </span>
              <ArrowRight className="w-3 h-3 text-muted-foreground/50" />
              <span className="flex items-center gap-1 bg-card px-2 py-1 rounded border border-border">
                <RefreshCw className="w-3 h-3 text-green-400" /> Re-analyze
              </span>
              <ArrowRight className="w-3 h-3 text-muted-foreground/50" />
              <span className="flex items-center gap-1 bg-card px-2 py-1 rounded border border-border">
                <Trophy className="w-3 h-3 text-primary" /> 100%
              </span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Progress & Status */}
      {(isRunning || hasCompleted || hasFailed) && statusData && (
        <>
          {/* Overall Progress */}
          <Card className="border-border">
            <CardContent className="p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CircleDot className={`w-4 h-4 ${isRunning ? "text-blue-400 animate-pulse" : hasCompleted ? "text-green-400" : "text-red-400"}`} />
                  <span className="text-sm font-medium text-foreground">
                    {statusData.targetPreset?.replace(/-/g, " ")}
                  </span>
                  <Badge variant="outline" className="text-[10px]">
                    {statusData.status}
                  </Badge>
                </div>
                <span className="text-sm font-mono text-primary">
                  Iteration {currentIteration}/{maxIter}
                </span>
              </div>

              <Progress
                value={(currentIteration / maxIter) * 100}
                className="h-2"
              />

              {/* Stats Row */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="text-center p-2 rounded bg-muted/30 border border-border">
                  <p className="text-lg font-bold text-primary">{(bestF1 * 100).toFixed(1)}%</p>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Best F1</p>
                </div>
                <div className="text-center p-2 rounded bg-muted/30 border border-border">
                  <p className="text-lg font-bold text-foreground">
                    {iterations.length > 0 ? (iterations[iterations.length - 1].precision * 100).toFixed(1) : "—"}%
                  </p>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Precision</p>
                </div>
                <div className="text-center p-2 rounded bg-muted/30 border border-border">
                  <p className="text-lg font-bold text-foreground">
                    {iterations.length > 0 ? (iterations[iterations.length - 1].recall * 100).toFixed(1) : "—"}%
                  </p>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Recall</p>
                </div>
                <div className="text-center p-2 rounded bg-muted/30 border border-border">
                  <p className="text-lg font-bold text-foreground">
                    {iterations.reduce((sum: number, i: IterationResult) => sum + i.feedbackGenerated, 0)}
                  </p>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Corrections</p>
                </div>
              </div>

              {/* Error */}
              {statusData.error && (
                <div className="p-3 rounded bg-red-500/10 border border-red-500/20 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                  <p className="text-xs text-red-300">{statusData.error}</p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Iteration History */}
          <Card className="border-border">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-primary" /> Iteration History
              </CardTitle>
            </CardHeader>
            <CardContent>
              {iterations.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground text-sm">
                  <Loader2 className="w-6 h-6 mx-auto mb-2 animate-spin" />
                  Waiting for first iteration to complete...
                </div>
              ) : (
                <ScrollArea className="max-h-[400px]">
                  <div className="space-y-2">
                    {/* Header */}
                    <div className="grid grid-cols-8 gap-2 px-3 py-1.5 text-[10px] text-muted-foreground uppercase tracking-wider bg-muted/30 rounded">
                      <div>#</div>
                      <div>F1 Score</div>
                      <div>Precision</div>
                      <div>Recall</div>
                      <div>TP</div>
                      <div>FP</div>
                      <div>FN</div>
                      <div>Corrections</div>
                    </div>

                    {/* Rows */}
                    {iterations.map((iter, idx) => {
                      const f1Pct = (iter.f1Score * 100).toFixed(1);
                      const isPerfect = iter.f1Score >= 1.0;
                      const isBest = iter.f1Score === bestF1;
                      const improved = idx > 0 && iter.f1Score > iterations[idx - 1].f1Score;
                      const declined = idx > 0 && iter.f1Score < iterations[idx - 1].f1Score;

                      return (
                        <div
                          key={iter.iteration}
                          className={`grid grid-cols-8 gap-2 px-3 py-2 text-xs rounded transition-colors ${
                            isPerfect
                              ? "bg-green-500/10 border border-green-500/30"
                              : isBest
                              ? "bg-primary/5 border border-primary/20"
                              : "hover:bg-muted/30"
                          }`}
                        >
                          <div className="font-mono text-muted-foreground flex items-center gap-1">
                            {iter.iteration}
                            {isPerfect && <Trophy className="w-3 h-3 text-green-400" />}
                            {isBest && !isPerfect && <Sparkles className="w-3 h-3 text-primary" />}
                          </div>
                          <div className={`font-bold ${isPerfect ? "text-green-400" : "text-foreground"}`}>
                            {f1Pct}%
                            {improved && <TrendingUp className="w-3 h-3 text-green-400 inline ml-1" />}
                            {declined && <XCircle className="w-3 h-3 text-red-400 inline ml-1" />}
                          </div>
                          <div className="text-muted-foreground">{(iter.precision * 100).toFixed(1)}%</div>
                          <div className="text-muted-foreground">{(iter.recall * 100).toFixed(1)}%</div>
                          <div className="text-green-400">{iter.truePositives}</div>
                          <div className={iter.falsePositives > 0 ? "text-red-400" : "text-muted-foreground"}>
                            {iter.falsePositives}
                          </div>
                          <div className={iter.falseNegatives > 0 ? "text-amber-400" : "text-muted-foreground"}>
                            {iter.falseNegatives}
                          </div>
                          <div className="text-purple-400">{iter.feedbackGenerated}</div>
                        </div>
                      );
                    })}
                  </div>
                </ScrollArea>
              )}
            </CardContent>
          </Card>

          {/* Accuracy Trend Visualization */}
          {iterations.length >= 2 && (
            <Card className="border-border">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-primary" /> Accuracy Trend
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="h-32 flex items-end gap-1">
                  {iterations.map((iter) => {
                    const height = Math.max(iter.f1Score * 100, 2);
                    const isPerfect = iter.f1Score >= 1.0;
                    return (
                      <div
                        key={iter.iteration}
                        className="flex-1 flex flex-col items-center gap-1"
                      >
                        <span className="text-[9px] text-muted-foreground">
                          {(iter.f1Score * 100).toFixed(0)}%
                        </span>
                        <div
                          className={`w-full rounded-t transition-all ${
                            isPerfect
                              ? "bg-green-500"
                              : iter.f1Score >= 0.8
                              ? "bg-primary"
                              : iter.f1Score >= 0.5
                              ? "bg-amber-500"
                              : "bg-red-500"
                          }`}
                          style={{ height: `${height}%` }}
                        />
                        <span className="text-[9px] text-muted-foreground">
                          #{iter.iteration}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Empty State */}
      {!isRunning && !hasCompleted && !hasFailed && (
        <Card className="border-border border-dashed">
          <CardContent className="p-12 text-center">
            <Brain className="w-12 h-12 text-muted-foreground/30 mx-auto mb-4" />
            <h3 className="text-sm font-medium text-foreground mb-2">No Active Training Loop</h3>
            <p className="text-xs text-muted-foreground max-w-md mx-auto">
              Select a training target with known vulnerabilities and start the continuous training loop.
              The system will automatically re-analyze and learn from each iteration until it achieves
              100% accuracy on vulnerability detection and exploit identification.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
