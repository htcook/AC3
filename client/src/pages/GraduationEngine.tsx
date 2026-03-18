/**
 * Graduation Engine Dashboard
 *
 * Monitors which LLM tasks are approaching graduation thresholds —
 * the point where they can be replaced with deterministic code.
 * Shows real-time readiness scores, cost projections, tier distribution,
 * specialist model states, and engagement-level tracking.
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  GraduationCap,
  Brain,
  Zap,
  TrendingUp,
  DollarSign,
  Clock,
  CheckCircle2,
  AlertTriangle,
  ArrowUpRight,
  ArrowRight,
  Activity,
  BarChart3,
  Target,
  Cpu,
  Gauge,
  ChevronDown,
  ChevronUp,
  XCircle,
  RefreshCw,
  Shield,
  Network,
  Crosshair,
  Eye,
  Route,
  Lock,
  Layers,
  FileText,
  Play,
  Star,
  Info,
} from "lucide-react";
import AppShell from "@/components/AppShell";

// ─── Tier Config ────────────────────────────────────────────────────────────

const TIER_CONFIG = {
  1: { label: "Ready to Graduate", color: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/20", badge: "bg-emerald-500/20 text-emerald-300", icon: GraduationCap },
  2: { label: "Near Graduation", color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/20", badge: "bg-blue-500/20 text-blue-300", icon: TrendingUp },
  3: { label: "Emerging Pattern", color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/20", badge: "bg-yellow-500/20 text-yellow-300", icon: Activity },
  4: { label: "Still Training", color: "text-zinc-400", bg: "bg-zinc-500/10 border-zinc-500/20", badge: "bg-zinc-500/20 text-zinc-300", icon: Brain },
  5: { label: "Keep LLM", color: "text-purple-400", bg: "bg-purple-500/10 border-purple-500/20", badge: "bg-purple-500/20 text-purple-300", icon: Cpu },
} as const;

const MODEL_ICONS: Record<string, any> = {
  recon_analyst: Eye,
  exploit_selector: Crosshair,
  evasion_optimizer: Shield,
  lateral_planner: Route,
  persistence_engineer: Lock,
  cognitive_core: Brain,
};

const MODEL_LABELS: Record<string, string> = {
  recon_analyst: "Recon Analyst",
  exploit_selector: "Exploit Selector",
  evasion_optimizer: "Evasion Optimizer",
  lateral_planner: "Lateral Planner",
  persistence_engineer: "Persistence Engineer",
  cognitive_core: "Cognitive Core",
};

const ACCESS_LEVEL_COLORS: Record<string, string> = {
  basic: "bg-zinc-500/20 text-zinc-300",
  operational: "bg-yellow-500/20 text-yellow-300",
  advanced: "bg-blue-500/20 text-blue-300",
  full: "bg-emerald-500/20 text-emerald-300",
};

// ─── Summary Cards ──────────────────────────────────────────────────────────

function SummaryCards({ summary }: { summary: any }) {
  if (!summary) return null;
  const cards = [
    { label: "Total LLM Tasks", value: summary.totalCallers, icon: Brain, color: "text-blue-400" },
    { label: "Ready to Graduate", value: summary.tier1Count, icon: GraduationCap, color: "text-emerald-400" },
    { label: "Near Graduation", value: summary.tier2Count, icon: TrendingUp, color: "text-cyan-400" },
    { label: "Est. Monthly Cost", value: `$${summary.totalMonthlyCost.toFixed(2)}`, icon: DollarSign, color: "text-amber-400" },
    { label: "Potential Savings", value: `$${summary.potentialSavings.toFixed(2)}`, icon: Zap, color: "text-emerald-400" },
    { label: "Total Calls (Period)", value: summary.totalCalls.toLocaleString(), icon: Activity, color: "text-violet-400" },
  ];
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map((c) => (
        <Card key={c.label} className="border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <c.icon className={`h-4 w-4 ${c.color}`} />
              <span className="text-xs text-muted-foreground">{c.label}</span>
            </div>
            <p className="text-2xl font-bold text-foreground">{c.value}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ─── Tier Distribution ──────────────────────────────────────────────────────

function TierDistribution({ summary }: { summary: any }) {
  if (!summary) return null;
  const total = summary.totalCallers || 1;
  const tiers = [
    { tier: 1, count: summary.tier1Count, ...TIER_CONFIG[1] },
    { tier: 2, count: summary.tier2Count, ...TIER_CONFIG[2] },
    { tier: 3, count: summary.tier3Count, ...TIER_CONFIG[3] },
    { tier: 4, count: summary.tier4Count, ...TIER_CONFIG[4] },
    { tier: 5, count: summary.tier5Count, ...TIER_CONFIG[5] },
  ];
  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <BarChart3 className="h-4 w-4 text-blue-400" /> Tier Distribution
        </CardTitle>
        <CardDescription>How LLM tasks are distributed across graduation tiers</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {tiers.map((t) => {
          const pct = Math.round((t.count / total) * 100);
          return (
            <div key={t.tier} className="space-y-1">
              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <t.icon className={`h-3.5 w-3.5 ${t.color}`} />
                  <span className={t.color}>Tier {t.tier}: {t.label}</span>
                </div>
                <span className="text-muted-foreground">{t.count} ({pct}%)</span>
              </div>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${
                    t.tier === 1 ? "bg-emerald-500" :
                    t.tier === 2 ? "bg-blue-500" :
                    t.tier === 3 ? "bg-yellow-500" :
                    t.tier === 4 ? "bg-zinc-500" :
                    "bg-purple-500"
                  }`}
                  style={{ width: `${Math.max(pct, 2)}%` }}
                />
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

// ─── Candidate Detail Row ───────────────────────────────────────────────────

function CandidateRow({ candidate, onExpand, expanded }: {
  candidate: any;
  onExpand: () => void;
  expanded: boolean;
}) {
  const tierCfg = TIER_CONFIG[candidate.tier as keyof typeof TIER_CONFIG];
  const scoreColor =
    candidate.graduationScore >= 80 ? "text-emerald-400" :
    candidate.graduationScore >= 60 ? "text-blue-400" :
    candidate.graduationScore >= 40 ? "text-yellow-400" :
    "text-zinc-400";

  return (
    <>
      <TableRow
        className="cursor-pointer hover:bg-muted/30 transition-colors"
        onClick={onExpand}
      >
        <TableCell>
          <div className="flex items-center gap-2">
            {expanded ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />}
            <code className="text-xs font-mono text-foreground">{candidate.caller}</code>
          </div>
        </TableCell>
        <TableCell>
          <Badge className={`${tierCfg.badge} border-0 text-[10px]`}>
            Tier {candidate.tier}
          </Badge>
        </TableCell>
        <TableCell>
          <div className="flex items-center gap-2">
            <span className={`text-sm font-bold ${scoreColor}`}>{candidate.graduationScore}</span>
            <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${
                  candidate.graduationScore >= 80 ? "bg-emerald-500" :
                  candidate.graduationScore >= 60 ? "bg-blue-500" :
                  candidate.graduationScore >= 40 ? "bg-yellow-500" :
                  "bg-zinc-500"
                }`}
                style={{ width: `${candidate.graduationScore}%` }}
              />
            </div>
          </div>
        </TableCell>
        <TableCell className="text-sm">{candidate.totalCalls.toLocaleString()}</TableCell>
        <TableCell>
          <span className={`text-sm ${candidate.successRate >= 97 ? "text-emerald-400" : candidate.successRate >= 90 ? "text-blue-400" : "text-yellow-400"}`}>
            {candidate.successRate}%
          </span>
        </TableCell>
        <TableCell className="text-sm text-muted-foreground">
          {candidate.avgLatencyMs >= 1000
            ? `${(candidate.avgLatencyMs / 1000).toFixed(1)}s`
            : `${candidate.avgLatencyMs}ms`}
        </TableCell>
        <TableCell className="text-sm">{candidate.avgTokensPerCall.toLocaleString()}</TableCell>
        <TableCell>
          <span className={`text-sm ${candidate.estimatedMonthlyCost > 10 ? "text-amber-400" : "text-muted-foreground"}`}>
            ${candidate.estimatedMonthlyCost.toFixed(2)}
          </span>
        </TableCell>
        <TableCell>
          <div className="flex items-center gap-1">
            <Gauge className="h-3 w-3 text-muted-foreground" />
            <span className={`text-sm ${candidate.outputStability >= 80 ? "text-emerald-400" : candidate.outputStability >= 50 ? "text-yellow-400" : "text-red-400"}`}>
              {candidate.outputStability}%
            </span>
          </div>
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow className="bg-muted/10">
          <TableCell colSpan={9} className="p-4">
            <CandidateDetail caller={candidate.caller} candidate={candidate} />
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

// ─── Candidate Detail Panel ─────────────────────────────────────────────────

function CandidateDetail({ caller, candidate }: { caller: string; candidate: any }) {
  const { data: detail, isLoading } = trpc.graduationEngine.getCallerDetail.useQuery({
    caller,
    windowDays: 30,
  });

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-muted-foreground">
        <RefreshCw className="h-4 w-4 animate-spin" /> Loading detail...
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      <Card className="border-border/30">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Target className="h-3.5 w-3.5 text-blue-400" /> Graduation Assessment
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="flex justify-between">
            <span className="text-muted-foreground">Replacement Type</span>
            <Badge variant="outline" className="text-[10px]">{candidate.replacementType}</Badge>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Error Rate</span>
            <span className={candidate.errorRate > 5 ? "text-red-400" : "text-emerald-400"}>{candidate.errorRate}%</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Retry Rate</span>
            <span className={candidate.retryRate > 10 ? "text-yellow-400" : "text-emerald-400"}>{candidate.retryRate}%</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">First Seen</span>
            <span className="text-muted-foreground">{candidate.firstSeen ? new Date(candidate.firstSeen).toLocaleDateString() : "—"}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Last Seen</span>
            <span className="text-muted-foreground">{candidate.lastSeen ? new Date(candidate.lastSeen).toLocaleDateString() : "—"}</span>
          </div>
          {detail?.isKeepLlm && (
            <div className="mt-2 p-2 rounded bg-purple-500/10 border border-purple-500/20 text-purple-300 text-xs">
              This task requires creative reasoning and should remain LLM-powered.
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="border-border/30">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Activity className="h-3.5 w-3.5 text-emerald-400" /> Recent Performance
          </CardTitle>
        </CardHeader>
        <CardContent>
          {detail?.daily && detail.daily.length > 0 ? (
            <div className="space-y-1.5 max-h-48 overflow-y-auto">
              {detail.daily.slice(-14).map((d: any) => (
                <div key={d.day} className="flex items-center gap-2 text-xs">
                  <span className="text-muted-foreground w-20 shrink-0">{d.day.slice(5)}</span>
                  <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${d.successRate >= 97 ? "bg-emerald-500" : d.successRate >= 90 ? "bg-blue-500" : "bg-yellow-500"}`}
                      style={{ width: `${d.successRate}%` }}
                    />
                  </div>
                  <span className="w-12 text-right text-muted-foreground">{d.calls} calls</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">No daily data available</p>
          )}
        </CardContent>
      </Card>

      <Card className="border-border/30">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <AlertTriangle className="h-3.5 w-3.5 text-red-400" /> Recent Errors
          </CardTitle>
        </CardHeader>
        <CardContent>
          {detail?.recentErrors && detail.recentErrors.length > 0 ? (
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {detail.recentErrors.slice(0, 5).map((e: any, i: number) => (
                <div key={i} className="p-2 rounded bg-red-500/5 border border-red-500/10 text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <Badge variant="outline" className="text-[9px] text-red-400 border-red-500/20">{e.llmStatus}</Badge>
                    <span className="text-muted-foreground">{e.calledAt ? new Date(e.calledAt).toLocaleString() : ""}</span>
                  </div>
                  <p className="text-muted-foreground line-clamp-2">{e.errorMessage || "No error message"}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center gap-2 text-xs text-emerald-400">
              <CheckCircle2 className="h-3.5 w-3.5" /> No recent errors
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Graduation Pipeline Visual ─────────────────────────────────────────────

function GraduationPipeline({ summary }: { summary: any }) {
  if (!summary) return null;
  const stages = [
    { label: "Observe", desc: "Collect telemetry", icon: Activity, count: summary.totalCallers, color: "text-zinc-400", bg: "bg-zinc-500/10" },
    { label: "Evaluate", desc: "Score readiness", icon: Gauge, count: summary.tier3Count + summary.tier2Count + summary.tier1Count, color: "text-yellow-400", bg: "bg-yellow-500/10" },
    { label: "Codegen", desc: "Generate replacement", icon: Cpu, count: summary.tier2Count + summary.tier1Count, color: "text-blue-400", bg: "bg-blue-500/10" },
    { label: "Validate", desc: "Shadow mode testing", icon: CheckCircle2, count: summary.tier1Count, color: "text-cyan-400", bg: "bg-cyan-500/10" },
    { label: "Promote", desc: "Replace LLM call", icon: GraduationCap, count: 0, color: "text-emerald-400", bg: "bg-emerald-500/10" },
  ];
  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <GraduationCap className="h-4 w-4 text-emerald-400" /> Graduation Pipeline
        </CardTitle>
        <CardDescription>5-stage pipeline: Observe → Evaluate → Codegen → Validate → Promote</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-between gap-1">
          {stages.map((s, i) => (
            <div key={s.label} className="flex items-center flex-1">
              <div className={`flex-1 rounded-lg border ${s.bg} border-border/30 p-3 text-center`}>
                <s.icon className={`h-5 w-5 mx-auto mb-1 ${s.color}`} />
                <p className={`text-xs font-medium ${s.color}`}>{s.label}</p>
                <p className="text-[10px] text-muted-foreground">{s.desc}</p>
                <p className="text-lg font-bold text-foreground mt-1">{s.count}</p>
              </div>
              {i < stages.length - 1 && (
                <ArrowRight className="h-4 w-4 text-muted-foreground/50 shrink-0 mx-1" />
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Model States Tab ──────────────────────────────────────────────────────

function ModelStatesTab() {
  const { data: modelStates, isLoading: statesLoading } = trpc.testLab.getAllModelStates.useQuery();
  const { data: summary, isLoading: summaryLoading } = trpc.testLab.getGraduationSummary.useQuery();
  const { data: events, isLoading: eventsLoading } = trpc.testLab.getGraduationEvents.useQuery({ limit: 30 });
  const { data: mappings } = trpc.testLab.getCallerMappings.useQuery();

  const isLoading = statesLoading || summaryLoading;

  if (isLoading) {
    return (
      <div className="space-y-4">
        {[...Array(3)].map((_, i) => (
          <Card key={i} className="animate-pulse border-border/50">
            <CardContent className="p-6"><div className="h-24 bg-muted rounded" /></CardContent>
          </Card>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Summary Bar */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
          <Card className="border-border/50">
            <CardContent className="p-3 text-center">
              <p className="text-xs text-muted-foreground">Overall Readiness</p>
              <p className="text-2xl font-bold text-foreground">{summary.overallReadinessScore}%</p>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="p-3 text-center">
              <p className="text-xs text-muted-foreground">Tier 1 (Ready)</p>
              <p className="text-2xl font-bold text-emerald-400">{summary.modelsAtTier1}</p>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="p-3 text-center">
              <p className="text-xs text-muted-foreground">Tier 2 (Near)</p>
              <p className="text-2xl font-bold text-blue-400">{summary.modelsAtTier2}</p>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="p-3 text-center">
              <p className="text-xs text-muted-foreground">Tier 3 (Emerging)</p>
              <p className="text-2xl font-bold text-yellow-400">{summary.modelsAtTier3}</p>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="p-3 text-center">
              <p className="text-xs text-muted-foreground">Tier 4 (Training)</p>
              <p className="text-2xl font-bold text-zinc-400">{summary.modelsAtTier4}</p>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="p-3 text-center">
              <p className="text-xs text-muted-foreground">Scenarios Run</p>
              <p className="text-2xl font-bold text-foreground">{summary.totalScenariosRun}</p>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="p-3 text-center">
              <p className="text-xs text-muted-foreground">Training Examples</p>
              <p className="text-2xl font-bold text-foreground">{summary.totalTrainingExamples}</p>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="p-3 text-center">
              <p className="text-xs text-muted-foreground">Fine-Tune Runs</p>
              <p className="text-2xl font-bold text-foreground">{summary.totalFineTuneRuns}</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Recommended Action */}
      {summary?.nextRecommendedAction && (
        <Card className="border-amber-500/20 bg-amber-500/5">
          <CardContent className="p-4 flex items-start gap-3">
            <Info className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-amber-300">Recommended Next Action</p>
              <p className="text-sm text-muted-foreground mt-1">{summary.nextRecommendedAction}</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Model Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {modelStates?.map((ms: any) => {
          const tierCfg = TIER_CONFIG[ms.currentTier as keyof typeof TIER_CONFIG];
          const IconComp = MODEL_ICONS[ms.model] || Brain;
          const passRate = ms.scenariosCompleted > 0
            ? Math.round((ms.scenariosPassed / ms.scenariosCompleted) * 100)
            : 0;

          return (
            <Card key={ms.model} className={`border-border/50 ${tierCfg.bg}`}>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <IconComp className={`h-5 w-5 ${tierCfg.color}`} />
                    <CardTitle className="text-sm">{MODEL_LABELS[ms.model] || ms.model}</CardTitle>
                  </div>
                  <Badge className={`${tierCfg.badge} border-0 text-[10px]`}>
                    Tier {ms.currentTier}
                  </Badge>
                </div>
                <CardDescription className="text-xs">
                  Lab Access: <Badge className={`${ACCESS_LEVEL_COLORS[ms.labAccessLevel] || ""} border-0 text-[9px] ml-1`}>
                    {ms.labAccessLevel}
                  </Badge>
                  {" · "}v{ms.currentModelVersion}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {/* Scenario Stats */}
                <div className="grid grid-cols-3 gap-2 text-center">
                  <div>
                    <p className="text-lg font-bold text-foreground">{ms.scenariosCompleted}</p>
                    <p className="text-[10px] text-muted-foreground">Scenarios</p>
                  </div>
                  <div>
                    <p className={`text-lg font-bold ${passRate >= 80 ? "text-emerald-400" : passRate >= 50 ? "text-yellow-400" : "text-red-400"}`}>
                      {passRate}%
                    </p>
                    <p className="text-[10px] text-muted-foreground">Pass Rate</p>
                  </div>
                  <div>
                    <p className="text-lg font-bold text-foreground">{ms.trainingExamples}</p>
                    <p className="text-[10px] text-muted-foreground">Examples</p>
                  </div>
                </div>

                {/* Benchmark Score */}
                <div className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Benchmark Score</span>
                    <span className={ms.lastBenchmarkScore >= 80 ? "text-emerald-400" : ms.lastBenchmarkScore >= 50 ? "text-yellow-400" : "text-zinc-400"}>
                      {ms.lastBenchmarkScore}/100
                    </span>
                  </div>
                  <Progress value={ms.lastBenchmarkScore} className="h-1.5" />
                </div>

                {/* Average Score */}
                <div className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Avg Scenario Score</span>
                    <span className="text-muted-foreground">{ms.averageScore}/100</span>
                  </div>
                  <Progress value={ms.averageScore} className="h-1.5" />
                </div>

                {/* Fine-tune Runs */}
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Fine-Tune Runs</span>
                  <span className="text-foreground">{ms.fineTuneRuns}</span>
                </div>

                {/* Feedback */}
                {ms.feedback && (
                  <div className="p-2 rounded bg-muted/30 border border-border/30 text-xs text-muted-foreground">
                    {ms.feedback.recommendation}
                  </div>
                )}

                {/* Recommendations */}
                {ms.recommendations && ms.recommendations.length > 0 && (
                  <div className="space-y-1">
                    <p className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">Next Steps</p>
                    {ms.recommendations.slice(0, 2).map((r: any, i: number) => (
                      <div key={i} className="flex items-start gap-1.5 text-xs">
                        <Badge variant="outline" className={`text-[8px] shrink-0 mt-0.5 ${
                          r.priority === "high" ? "border-red-500/30 text-red-400" :
                          r.priority === "medium" ? "border-yellow-500/30 text-yellow-400" :
                          "border-zinc-500/30 text-zinc-400"
                        }`}>{r.priority}</Badge>
                        <span className="text-muted-foreground">{r.reason}</span>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Caller → Model Mappings */}
      {mappings && (
        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Network className="h-4 w-4 text-cyan-400" /> Caller → Model Mappings
            </CardTitle>
            <CardDescription>How LLM callers map to specialist models for graduation tracking</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="bg-muted/30">
                    <TableHead className="text-xs">Caller Pattern</TableHead>
                    <TableHead className="text-xs">Specialist Model</TableHead>
                    <TableHead className="text-xs">Description</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {mappings.mappings.map((m: any, i: number) => (
                    <TableRow key={i}>
                      <TableCell>
                        <code className="text-xs font-mono text-cyan-400">{m.callerPattern}</code>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-[10px]">{MODEL_LABELS[m.specialistModel] || m.specialistModel}</Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{m.description}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Graduation Events */}
      <Card className="border-border/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <FileText className="h-4 w-4 text-violet-400" /> Graduation Events
          </CardTitle>
          <CardDescription>Recent model graduation events and state changes</CardDescription>
        </CardHeader>
        <CardContent>
          {!eventsLoading && events && events.length > 0 ? (
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {events.map((ev: any) => {
                const evColor =
                  ev.eventType === "model_promoted" ? "border-emerald-500/20 bg-emerald-500/5" :
                  ev.eventType === "tier_change" ? "border-blue-500/20 bg-blue-500/5" :
                  ev.eventType === "benchmark_passed" ? "border-cyan-500/20 bg-cyan-500/5" :
                  ev.eventType === "model_rollback" ? "border-red-500/20 bg-red-500/5" :
                  "border-border/30 bg-muted/10";
                return (
                  <div key={ev.id} className={`p-3 rounded-lg border ${evColor}`}>
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-[9px]">{ev.eventType.replace(/_/g, " ")}</Badge>
                        <span className="text-xs text-muted-foreground">{MODEL_LABELS[ev.specialistModel] || ev.specialistModel}</span>
                      </div>
                      <span className="text-[10px] text-muted-foreground">
                        {new Date(ev.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground">{ev.details}</p>
                    {ev.previousTier && ev.newTier && (
                      <div className="flex items-center gap-2 mt-1 text-xs">
                        <Badge className={`${TIER_CONFIG[ev.previousTier as keyof typeof TIER_CONFIG]?.badge || ""} border-0 text-[9px]`}>
                          Tier {ev.previousTier}
                        </Badge>
                        <ArrowRight className="h-3 w-3 text-muted-foreground" />
                        <Badge className={`${TIER_CONFIG[ev.newTier as keyof typeof TIER_CONFIG]?.badge || ""} border-0 text-[9px]`}>
                          Tier {ev.newTier}
                        </Badge>
                      </div>
                    )}
                    {ev.score !== undefined && ev.score !== null && (
                      <span className="text-[10px] text-muted-foreground">Score: {ev.score}</span>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground text-sm">
              <FileText className="h-8 w-8 mx-auto mb-2 opacity-30" />
              No graduation events recorded yet. Run lab scenarios to generate events.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Engagement Tracking Tab ───────────────────────────────────────────────

function EngagementTrackingTab() {
  const { data: engagements, isLoading: engLoading } = trpc.engagementTimeline.listEngagementsWithStats.useQuery({ limit: 50 });
  const { data: allCosts, isLoading: costsLoading } = trpc.llmTelemetry.allEngagementCosts.useQuery();
  const { data: gradData } = trpc.graduationEngine.getCandidates.useQuery({ windowDays: 30 });

  const isLoading = engLoading || costsLoading;

  // Merge engagement data with LLM costs
  const enrichedEngagements = useMemo(() => {
    if (!engagements) return [];
    const costMap = new Map<number, any>();
    if (allCosts && Array.isArray(allCosts)) {
      allCosts.forEach((c: any) => costMap.set(c.engagementId, c));
    }
    return engagements.map((eng: any) => ({
      ...eng,
      llmCost: costMap.get(eng.id),
    }));
  }, [engagements, allCosts]);

  // Summary stats
  const totalEngagements = enrichedEngagements.length;
  const activeEngagements = enrichedEngagements.filter((e: any) => e.status === "active" || e.status === "in_progress").length;
  const totalLlmCost = enrichedEngagements.reduce((s: number, e: any) => s + (e.llmCost?.totalCost || 0), 0);
  const totalEvents = enrichedEngagements.reduce((s: number, e: any) => s + (e.stats?.totalEvents || 0), 0);
  const totalFindings = enrichedEngagements.reduce((s: number, e: any) => s + (e.stats?.totalFindings || 0), 0);

  if (isLoading) {
    return (
      <div className="space-y-4">
        {[...Array(3)].map((_, i) => (
          <Card key={i} className="animate-pulse border-border/50">
            <CardContent className="p-6"><div className="h-24 bg-muted rounded" /></CardContent>
          </Card>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-xs text-muted-foreground">Total Engagements</p>
            <p className="text-2xl font-bold text-foreground">{totalEngagements}</p>
          </CardContent>
        </Card>
        <Card className="border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-xs text-muted-foreground">Active</p>
            <p className="text-2xl font-bold text-emerald-400">{activeEngagements}</p>
          </CardContent>
        </Card>
        <Card className="border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-xs text-muted-foreground">Total LLM Cost</p>
            <p className="text-2xl font-bold text-amber-400">${totalLlmCost.toFixed(2)}</p>
          </CardContent>
        </Card>
        <Card className="border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-xs text-muted-foreground">Timeline Events</p>
            <p className="text-2xl font-bold text-blue-400">{totalEvents.toLocaleString()}</p>
          </CardContent>
        </Card>
        <Card className="border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-xs text-muted-foreground">Findings</p>
            <p className="text-2xl font-bold text-red-400">{totalFindings}</p>
          </CardContent>
        </Card>
      </div>

      {/* Graduation Impact on Engagements */}
      {gradData?.summary && (
        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Zap className="h-4 w-4 text-amber-400" /> Graduation Impact on Engagement Costs
            </CardTitle>
            <CardDescription>
              If Tier 1 & 2 tasks were graduated, engagement LLM costs would decrease by ~${gradData.summary.potentialSavings.toFixed(2)}/month
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4">
              <div className="p-3 rounded-lg bg-muted/20 border border-border/30 text-center">
                <p className="text-xs text-muted-foreground">Current Monthly</p>
                <p className="text-xl font-bold text-foreground">${gradData.summary.totalMonthlyCost.toFixed(2)}</p>
              </div>
              <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-center">
                <p className="text-xs text-muted-foreground">After Graduation</p>
                <p className="text-xl font-bold text-emerald-400">
                  ${(gradData.summary.totalMonthlyCost - gradData.summary.potentialSavings).toFixed(2)}
                </p>
              </div>
              <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-center">
                <p className="text-xs text-muted-foreground">Savings</p>
                <p className="text-xl font-bold text-amber-400">
                  ${gradData.summary.potentialSavings.toFixed(2)}
                  <span className="text-xs font-normal text-muted-foreground ml-1">
                    ({gradData.summary.totalMonthlyCost > 0 ? Math.round((gradData.summary.potentialSavings / gradData.summary.totalMonthlyCost) * 100) : 0}%)
                  </span>
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Engagement Table */}
      <Card className="border-border/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Layers className="h-4 w-4 text-blue-400" /> Engagement Performance & LLM Usage
          </CardTitle>
          <CardDescription>
            Per-engagement metrics with LLM cost tracking and timeline event counts
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/30">
                  <TableHead className="text-xs">Engagement</TableHead>
                  <TableHead className="text-xs">Customer</TableHead>
                  <TableHead className="text-xs">Type</TableHead>
                  <TableHead className="text-xs">Status</TableHead>
                  <TableHead className="text-xs">Events</TableHead>
                  <TableHead className="text-xs">Findings</TableHead>
                  <TableHead className="text-xs">LLM Cost</TableHead>
                  <TableHead className="text-xs">LLM Calls</TableHead>
                  <TableHead className="text-xs">Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {enrichedEngagements.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={9} className="text-center text-muted-foreground py-8">
                      No engagements found. Create an engagement to start tracking.
                    </TableCell>
                  </TableRow>
                ) : (
                  enrichedEngagements.map((eng: any) => {
                    const statusColor =
                      eng.status === "active" || eng.status === "in_progress" ? "bg-emerald-500/20 text-emerald-300" :
                      eng.status === "completed" ? "bg-blue-500/20 text-blue-300" :
                      eng.status === "paused" ? "bg-yellow-500/20 text-yellow-300" :
                      "bg-zinc-500/20 text-zinc-300";
                    return (
                      <TableRow key={eng.id} className="hover:bg-muted/20">
                        <TableCell>
                          <div className="max-w-[200px]">
                            <p className="text-sm font-medium text-foreground truncate">{eng.name}</p>
                            <p className="text-[10px] text-muted-foreground">ID: {eng.id}</p>
                          </div>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{eng.customerName || "—"}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-[10px]">{eng.engagementType || "pentest"}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge className={`${statusColor} border-0 text-[10px]`}>{eng.status || "draft"}</Badge>
                        </TableCell>
                        <TableCell className="text-sm">{eng.stats?.totalEvents?.toLocaleString() || 0}</TableCell>
                        <TableCell>
                          <span className={`text-sm ${(eng.stats?.totalFindings || 0) > 0 ? "text-red-400" : "text-muted-foreground"}`}>
                            {eng.stats?.totalFindings || 0}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className={`text-sm ${(eng.llmCost?.totalCost || 0) > 5 ? "text-amber-400" : "text-muted-foreground"}`}>
                            ${(eng.llmCost?.totalCost || 0).toFixed(2)}
                          </span>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {eng.llmCost?.totalCalls?.toLocaleString() || 0}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {eng.createdAt ? new Date(eng.createdAt).toLocaleDateString() : "—"}
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Phase Distribution */}
      {enrichedEngagements.length > 0 && (
        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Activity className="h-4 w-4 text-violet-400" /> Engagement Phase Distribution
            </CardTitle>
            <CardDescription>Distribution of events across kill chain phases</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
              {(() => {
                const phases: Record<string, number> = {};
                enrichedEngagements.forEach((eng: any) => {
                  if (eng.stats?.phaseBreakdown) {
                    Object.entries(eng.stats.phaseBreakdown).forEach(([phase, count]: [string, any]) => {
                      phases[phase] = (phases[phase] || 0) + (typeof count === "number" ? count : 0);
                    });
                  }
                });
                const sorted = Object.entries(phases).sort(([, a], [, b]) => (b as number) - (a as number));
                if (sorted.length === 0) {
                  return (
                    <div className="col-span-full text-center py-4 text-muted-foreground text-sm">
                      No phase data available yet. Run engagements to collect phase metrics.
                    </div>
                  );
                }
                return sorted.map(([phase, count]) => (
                  <div key={phase} className="p-3 rounded-lg bg-muted/20 border border-border/30">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider truncate">{phase.replace(/_/g, " ")}</p>
                    <p className="text-lg font-bold text-foreground">{(count as number).toLocaleString()}</p>
                  </div>
                ));
              })()}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function GraduationEnginePage() {
  const [windowDays, setWindowDays] = useState(30);
  const [tierFilter, setTierFilter] = useState<number | undefined>(undefined);
  const [expandedCaller, setExpandedCaller] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<"score" | "calls" | "cost" | "success">("score");
  const [activeTab, setActiveTab] = useState("candidates");

  const { data, isLoading, refetch } = trpc.graduationEngine.getCandidates.useQuery({
    windowDays,
    tierFilter,
  });

  const sortedCandidates = useMemo(() => {
    if (!data?.candidates) return [];
    const sorted = [...data.candidates];
    switch (sortBy) {
      case "score": sorted.sort((a, b) => b.graduationScore - a.graduationScore); break;
      case "calls": sorted.sort((a, b) => b.totalCalls - a.totalCalls); break;
      case "cost": sorted.sort((a, b) => b.estimatedMonthlyCost - a.estimatedMonthlyCost); break;
      case "success": sorted.sort((a, b) => b.successRate - a.successRate); break;
    }
    return sorted;
  }, [data?.candidates, sortBy]);

  return (
    <AppShell>
      <div className="space-y-6 p-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground flex items-center gap-3">
              <GraduationCap className="h-7 w-7 text-emerald-400" />
              Graduation Engine
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Monitor LLM tasks, specialist model states, and engagement-level performance
            </p>
          </div>
          <div className="flex items-center gap-3">
            {activeTab === "candidates" && (
              <Select value={String(windowDays)} onValueChange={(v) => setWindowDays(Number(v))}>
                <SelectTrigger className="w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="7">Last 7 days</SelectItem>
                  <SelectItem value="14">Last 14 days</SelectItem>
                  <SelectItem value="30">Last 30 days</SelectItem>
                  <SelectItem value="60">Last 60 days</SelectItem>
                  <SelectItem value="90">Last 90 days</SelectItem>
                </SelectContent>
              </Select>
            )}
            <Button variant="outline" size="sm" onClick={() => refetch()}>
              <RefreshCw className="h-3.5 w-3.5 mr-2" /> Refresh
            </Button>
          </div>
        </div>

        {/* Main Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-muted/30">
            <TabsTrigger value="candidates" className="gap-2">
              <Brain className="h-3.5 w-3.5" /> Graduation Candidates
            </TabsTrigger>
            <TabsTrigger value="model-states" className="gap-2">
              <Cpu className="h-3.5 w-3.5" /> Model States
            </TabsTrigger>
            <TabsTrigger value="engagements" className="gap-2">
              <Layers className="h-3.5 w-3.5" /> Engagement Tracking
            </TabsTrigger>
          </TabsList>

          {/* Candidates Tab */}
          <TabsContent value="candidates" className="space-y-6 mt-4">
            {isLoading ? (
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                {[...Array(6)].map((_, i) => (
                  <Card key={i} className="animate-pulse border-border/50">
                    <CardContent className="p-4">
                      <div className="h-4 bg-muted rounded w-20 mb-2" />
                      <div className="h-8 bg-muted rounded w-16" />
                    </CardContent>
                  </Card>
                ))}
              </div>
            ) : (
              <>
                <SummaryCards summary={data?.summary} />

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                  <div className="lg:col-span-2">
                    <GraduationPipeline summary={data?.summary} />
                  </div>
                  <TierDistribution summary={data?.summary} />
                </div>

                <Card className="border-border/50">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="flex items-center gap-2 text-base">
                          <Brain className="h-4 w-4 text-blue-400" /> LLM Task Candidates
                        </CardTitle>
                        <CardDescription>
                          {sortedCandidates.length} tasks analyzed — Click to expand details
                        </CardDescription>
                      </div>
                      <div className="flex items-center gap-2">
                        <Select
                          value={tierFilter ? String(tierFilter) : "all"}
                          onValueChange={(v) => setTierFilter(v === "all" ? undefined : Number(v))}
                        >
                          <SelectTrigger className="w-36">
                            <SelectValue placeholder="All Tiers" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="all">All Tiers</SelectItem>
                            <SelectItem value="1">Tier 1 — Ready</SelectItem>
                            <SelectItem value="2">Tier 2 — Near</SelectItem>
                            <SelectItem value="3">Tier 3 — Emerging</SelectItem>
                            <SelectItem value="4">Tier 4 — Training</SelectItem>
                            <SelectItem value="5">Tier 5 — Keep LLM</SelectItem>
                          </SelectContent>
                        </Select>
                        <Select value={sortBy} onValueChange={(v: any) => setSortBy(v)}>
                          <SelectTrigger className="w-32">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="score">By Score</SelectItem>
                            <SelectItem value="calls">By Volume</SelectItem>
                            <SelectItem value="cost">By Cost</SelectItem>
                            <SelectItem value="success">By Success</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="overflow-x-auto">
                      <Table>
                        <TableHeader>
                          <TableRow className="bg-muted/30">
                            <TableHead className="text-xs">Caller</TableHead>
                            <TableHead className="text-xs">Tier</TableHead>
                            <TableHead className="text-xs">Score</TableHead>
                            <TableHead className="text-xs">Calls</TableHead>
                            <TableHead className="text-xs">Success</TableHead>
                            <TableHead className="text-xs">Avg Latency</TableHead>
                            <TableHead className="text-xs">Tokens/Call</TableHead>
                            <TableHead className="text-xs">$/Month</TableHead>
                            <TableHead className="text-xs">Stability</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {sortedCandidates.length === 0 ? (
                            <TableRow>
                              <TableCell colSpan={9} className="text-center text-muted-foreground py-8">
                                No LLM telemetry data found for the selected period
                              </TableCell>
                            </TableRow>
                          ) : (
                            sortedCandidates.map((c) => (
                              <CandidateRow
                                key={c.caller}
                                candidate={c}
                                expanded={expandedCaller === c.caller}
                                onExpand={() => setExpandedCaller(expandedCaller === c.caller ? null : c.caller)}
                              />
                            ))
                          )}
                        </TableBody>
                      </Table>
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-border/50">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-sm">
                      <Target className="h-4 w-4 text-cyan-400" /> Graduation Criteria Reference
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
                      {[
                        { tier: 1, sr: "≥97%", calls: "≥500", latency: "<5s", action: "Generate deterministic replacement code" },
                        { tier: 2, sr: "≥90%", calls: "≥200", latency: "<10s", action: "Begin shadow mode validation" },
                        { tier: 3, sr: "≥80%", calls: "≥50", latency: "Any", action: "Monitor for pattern stabilization" },
                        { tier: 4, sr: "<80%", calls: "<50", latency: "Any", action: "Continue LLM training and observation" },
                        { tier: 5, sr: "N/A", calls: "N/A", latency: "N/A", action: "Creative/reasoning — keep LLM-powered" },
                      ].map((t) => {
                        const cfg = TIER_CONFIG[t.tier as keyof typeof TIER_CONFIG];
                        return (
                          <div key={t.tier} className={`rounded-lg border p-3 ${cfg.bg}`}>
                            <div className="flex items-center gap-2 mb-2">
                              <Badge className={`${cfg.badge} border-0 text-[10px]`}>Tier {t.tier}</Badge>
                            </div>
                            <div className="space-y-1 text-xs">
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Success</span>
                                <span className={cfg.color}>{t.sr}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Min Calls</span>
                                <span className={cfg.color}>{t.calls}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Latency</span>
                                <span className={cfg.color}>{t.latency}</span>
                              </div>
                              <p className="text-muted-foreground mt-2 pt-2 border-t border-border/30">{t.action}</p>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>
              </>
            )}
          </TabsContent>

          {/* Model States Tab */}
          <TabsContent value="model-states" className="mt-4">
            <ModelStatesTab />
          </TabsContent>

          {/* Engagement Tracking Tab */}
          <TabsContent value="engagements" className="mt-4">
            <EngagementTrackingTab />
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
