import { useState, useMemo } from "react";
import { Link } from "wouter";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import {
  Sparkles,
  Brain,
  Shield,
  Target,
  Eye,
  FlaskConical,
  TrendingUp,
  TrendingDown,
  Minus,
  Activity,
  BarChart3,
  Crosshair,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Zap,
  Users,
  FileText,
  RefreshCw,
  ChevronRight,
  Layers,
  Network,
  Globe2,
} from "lucide-react";
import { toast } from "sonner";

// ─── Helpers ────────────────────────────────────────────────────────────────
function pct(n: number) { return Math.round(n * 100); }
function fmtDate(iso: string) {
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
function trendIcon(current: number, prev: number) {
  if (current > prev + 0.02) return <TrendingUp className="h-3.5 w-3.5 text-green-400" />;
  if (current < prev - 0.02) return <TrendingDown className="h-3.5 w-3.5 text-red-400" />;
  return <Minus className="h-3.5 w-3.5 text-muted-foreground" />;
}
function severityColor(sev: string) {
  switch (sev?.toLowerCase()) {
    case "critical": return "text-red-400 bg-red-500/10 border-red-500/20";
    case "high": return "text-orange-400 bg-orange-500/10 border-orange-500/20";
    case "medium": return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20";
    case "low": return "text-blue-400 bg-blue-500/10 border-blue-500/20";
    default: return "text-gray-400 bg-gray-500/10 border-gray-500/20";
  }
}

// ─── Main Page ──────────────────────────────────────────────────────────────
export default function LlmLearning() {
  const [activeTab, setActiveTab] = useState("overview");
  const [selectedTarget, setSelectedTarget] = useState<string>("all");

  // ── Queries ──
  const { data: health, isLoading: healthLoading } = trpc.learningEngine.health.useQuery(undefined, {
    retry: 1,
    refetchInterval: 30000,
  });
  const { data: dashboard, isLoading: dashLoading } = trpc.learningEngine.dashboard.useQuery(undefined, {
    retry: 1,
    refetchInterval: 30000,
  });
  const { data: accuracyTrend } = trpc.learningEngine.trainingLab.accuracyTrend.useQuery(
    { target: selectedTarget === "all" ? undefined : selectedTarget, limit: 20 },
    { retry: 1 }
  );
  const { data: vulnAccuracy } = trpc.learningEngine.trainingLab.vulnAccuracy.useQuery(undefined, { retry: 1 });
  const { data: threatStats } = trpc.learningEngine.threatActor.threatStats.useQuery(undefined, { retry: 1 });
  const { data: threatTrend } = trpc.learningEngine.threatActor.attributionTrend.useQuery({ limit: 20 }, { retry: 1 });
  const { data: groundTruth } = trpc.learningEngine.trainingLab.groundTruth.useQuery(undefined, { retry: 1 });
  const { data: engagementRuns } = trpc.learningEngine.trainingLab.engagementRuns.useQuery(
    { target: selectedTarget === "all" ? undefined : selectedTarget, limit: 10 },
    { retry: 1 }
  );
  const { data: learningEvents } = trpc.learningEngine.trainingLab.learningEvents.useQuery(
    { target: selectedTarget === "all" ? undefined : selectedTarget, limit: 20 },
    { retry: 1 }
  );

  const isOnline = health?.status === "healthy" || health?.status === "ok";
  const labStats = dashboard?.trainingLab;
  const threatDash = dashboard?.threatActor;

  // Build target list from ground truth
  const targetList = useMemo(() => {
    if (!groundTruth?.targets) return [];
    return Object.keys(groundTruth.targets).sort();
  }, [groundTruth]);

  return (
    <div className="space-y-6">
      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Sparkles className="h-6 w-6 text-amber-400" />
            LLM Learning Engine
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Dual-stream continuous learning — training labs + threat actor catalog
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Badge variant="outline" className={isOnline ? "text-green-400 border-green-500/30 bg-green-500/10" : "text-red-400 border-red-500/30 bg-red-500/10"}>
            <Activity className={`h-3 w-3 mr-1 ${isOnline ? "animate-pulse" : ""}`} />
            {isOnline ? "Engine Online" : "Engine Offline"}
          </Badge>
          {health && (
            <Badge variant="outline" className="text-muted-foreground">
              {health.groundTruthTargets} targets · {health.totalVulns} vulns
            </Badge>
          )}
        </div>
      </div>

      {/* ── Stat Cards ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <StatCard
          label="Lab Targets"
          value={labStats?.groundTruthTargets ?? 0}
          icon={FlaskConical}
          color="text-blue-400"
          loading={dashLoading}
        />
        <StatCard
          label="Total Vulns"
          value={labStats?.totalVulns ?? 0}
          icon={Shield}
          color="text-amber-400"
          loading={dashLoading}
        />
        <StatCard
          label="Engagement Runs"
          value={labStats?.engagementRuns ?? 0}
          icon={Target}
          color="text-green-400"
          loading={dashLoading}
        />
        <StatCard
          label="Threat Groups"
          value={threatDash?.totalGroups ?? 0}
          icon={Users}
          color="text-red-400"
          loading={dashLoading}
        />
        <StatCard
          label="TTPs Tracked"
          value={threatDash?.totalTTPs ?? 0}
          icon={Crosshair}
          color="text-purple-400"
          loading={dashLoading}
        />
        <StatCard
          label="CVEs Tracked"
          value={threatDash?.totalCVEs ?? 0}
          icon={AlertTriangle}
          color="text-orange-400"
          loading={dashLoading}
        />
      </div>

      {/* ── Tabs ── */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <div className="flex items-center justify-between">
          <TabsList className="bg-muted/50">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="training-labs">Training Labs</TabsTrigger>
            <TabsTrigger value="threat-actors">Threat Actors</TabsTrigger>
            <TabsTrigger value="events">Learning Events</TabsTrigger>
            <TabsTrigger value="ground-truth">Ground Truth</TabsTrigger>
          </TabsList>
          {(activeTab === "training-labs" || activeTab === "events") && (
            <Select value={selectedTarget} onValueChange={setSelectedTarget}>
              <SelectTrigger className="w-48">
                <SelectValue placeholder="Filter by target" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Targets</SelectItem>
                {targetList.map(t => (
                  <SelectItem key={t} value={t}>{t}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </div>

        {/* ═══ OVERVIEW TAB ═══ */}
        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Training Lab Summary */}
            <Card className="border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <FlaskConical className="h-4 w-4 text-blue-400" />
                  Training Lab Stream
                </CardTitle>
                <CardDescription>LLM accuracy against known vulnerabilities</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {labStats?.avgAccuracy != null ? (
                  <>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Average Accuracy</span>
                      <span className="text-2xl font-bold text-green-400">{pct(labStats.avgAccuracy)}%</span>
                    </div>
                    <Progress value={pct(labStats.avgAccuracy)} className="h-2" />
                    <div className="grid grid-cols-3 gap-3 text-center">
                      <div>
                        <p className="text-xs text-muted-foreground">Precision</p>
                        <p className="text-lg font-semibold">{pct(labStats.avgPrecision ?? 0)}%</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Recall</p>
                        <p className="text-lg font-semibold">{pct(labStats.avgRecall ?? 0)}%</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">F1 Score</p>
                        <p className="text-lg font-semibold">{pct(labStats.avgF1 ?? 0)}%</p>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <FlaskConical className="h-8 w-8 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">No engagement runs yet</p>
                    <p className="text-xs mt-1">Run a training lab scan to start collecting accuracy data</p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Threat Actor Summary */}
            <Card className="border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Users className="h-4 w-4 text-red-400" />
                  Threat Actor Stream
                </CardTitle>
                <CardDescription>TTP detection against threat group catalog</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {threatDash?.attributionRuns != null && threatDash.attributionRuns > 0 ? (
                  <>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Attribution Runs</span>
                      <span className="text-2xl font-bold text-red-400">{threatDash.attributionRuns}</span>
                    </div>
                    <div className="grid grid-cols-3 gap-3 text-center">
                      <div>
                        <p className="text-xs text-muted-foreground">Groups</p>
                        <p className="text-lg font-semibold">{threatDash.totalGroups}</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">TTPs</p>
                        <p className="text-lg font-semibold">{threatDash.totalTTPs}</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">CVEs</p>
                        <p className="text-lg font-semibold">{threatDash.totalCVEs}</p>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Users className="h-8 w-8 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">No attribution runs yet</p>
                    <p className="text-xs mt-1">Run scans to start building threat attribution data</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Recent Accuracy Trend */}
          {accuracyTrend?.trend && accuracyTrend.trend.length > 0 && (
            <Card className="border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-green-400" />
                  Accuracy Trend
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {accuracyTrend.trend.map((entry: any, i: number) => (
                    <div key={i} className="flex items-center gap-3 py-2 border-b border-border/50 last:border-0">
                      <Badge variant="outline" className="text-xs min-w-[100px] justify-center">
                        {entry.target}
                      </Badge>
                      <div className="flex-1">
                        <Progress value={pct(entry.f1Score)} className="h-1.5" />
                      </div>
                      <span className="text-sm font-mono w-12 text-right">{pct(entry.f1Score)}%</span>
                      <span className="text-xs text-muted-foreground w-24">{fmtDate(entry.timestamp)}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ═══ TRAINING LABS TAB ═══ */}
        <TabsContent value="training-labs" className="space-y-6">
          {/* Engagement Runs */}
          <Card className="border-border">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Target className="h-4 w-4 text-green-400" />
                Engagement Runs
              </CardTitle>
              <CardDescription>Scored scan results against ground truth</CardDescription>
            </CardHeader>
            <CardContent>
              {engagementRuns?.runs && engagementRuns.runs.length > 0 ? (
                <div className="space-y-3">
                  {engagementRuns.runs.map((run: any, i: number) => (
                    <div key={i} className="flex items-center gap-4 p-3 rounded-lg bg-muted/30 border border-border/50">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="text-xs">{run.targetPreset}</Badge>
                          <span className="text-xs text-muted-foreground">{run.scanType || "full"}</span>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1 truncate">{run.targetUrl || "—"}</p>
                      </div>
                      <div className="grid grid-cols-4 gap-4 text-center">
                        <div>
                          <p className="text-[10px] text-muted-foreground">Precision</p>
                          <p className="text-sm font-semibold">{pct(run.precision)}%</p>
                        </div>
                        <div>
                          <p className="text-[10px] text-muted-foreground">Recall</p>
                          <p className="text-sm font-semibold">{pct(run.recall)}%</p>
                        </div>
                        <div>
                          <p className="text-[10px] text-muted-foreground">F1</p>
                          <p className="text-sm font-semibold text-green-400">{pct(run.f1Score)}%</p>
                        </div>
                        <div>
                          <p className="text-[10px] text-muted-foreground">Found</p>
                          <p className="text-sm font-semibold">{run.truePositives}/{run.truePositives + run.falseNegatives}</p>
                        </div>
                      </div>
                      <span className="text-xs text-muted-foreground whitespace-nowrap">{fmtDate(run.timestamp)}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState icon={Target} message="No engagement runs yet" hint="Score findings from a training lab scan to see results here" />
              )}
            </CardContent>
          </Card>

          {/* Vuln Type Accuracy Breakdown */}
          <Card className="border-border">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-amber-400" />
                Vulnerability Type Accuracy
              </CardTitle>
              <CardDescription>Detection accuracy broken down by vulnerability category</CardDescription>
            </CardHeader>
            <CardContent>
              {vulnAccuracy?.breakdown && vulnAccuracy.breakdown.length > 0 ? (
                <div className="space-y-2">
                  {vulnAccuracy.breakdown.map((entry: any, i: number) => (
                    <div key={i} className="flex items-center gap-3 py-2 border-b border-border/50 last:border-0">
                      <span className="text-sm font-medium min-w-[180px] truncate">{entry.vulnType}</span>
                      <div className="flex-1">
                        <Progress value={pct(entry.avgF1)} className="h-1.5" />
                      </div>
                      <div className="flex items-center gap-3 text-xs text-muted-foreground">
                        <span className="w-10 text-right font-mono">{pct(entry.avgF1)}%</span>
                        <span className="w-16 text-right">{entry.totalRuns} runs</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState icon={BarChart3} message="No accuracy data yet" hint="Run training lab scans to build accuracy breakdown" />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ═══ THREAT ACTORS TAB ═══ */}
        <TabsContent value="threat-actors" className="space-y-6">
          {/* Threat Stats */}
          <Card className="border-border">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Users className="h-4 w-4 text-red-400" />
                Threat Group Attribution
              </CardTitle>
              <CardDescription>How well the AI identifies threat actor techniques during scans</CardDescription>
            </CardHeader>
            <CardContent>
              {threatStats?.topGroups && threatStats.topGroups.length > 0 ? (
                <div className="space-y-3">
                  {threatStats.topGroups.map((group: any, i: number) => (
                    <Link key={i} href={`/threat-actors/${group.groupId}`}>
                      <div className="flex items-center gap-4 p-3 rounded-lg bg-muted/30 border border-border/50 hover:bg-muted/50 transition-colors cursor-pointer">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-semibold hover:text-primary transition-colors">{group.groupName || group.groupId}</span>
                            <Badge variant="outline" className="text-[10px]">{group.matchCount} matches</Badge>
                          </div>
                        </div>
                        <div className="text-right">
                          <p className="text-sm font-semibold text-red-400">{pct(group.avgConfidence)}%</p>
                          <p className="text-[10px] text-muted-foreground">avg confidence</p>
                        </div>
                      </div>
                    </Link>
                  ))}
                </div>
              ) : (
                <EmptyState icon={Users} message="No threat attribution data yet" hint="Run scans with TTP detection to build attribution data" />
              )}
            </CardContent>
          </Card>

          {/* Threat Trend */}
          {threatTrend?.trend && threatTrend.trend.length > 0 && (
            <Card className="border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-purple-400" />
                  Attribution Trend
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {threatTrend.trend.map((entry: any, i: number) => (
                    <div key={i} className="flex items-center gap-3 py-2 border-b border-border/50 last:border-0">
                      <Badge variant="outline" className="text-xs min-w-[120px] justify-center">
                        {entry.topGroup || "—"}
                      </Badge>
                      <div className="flex-1 grid grid-cols-3 gap-2 text-center text-xs">
                        <div>
                          <span className="text-muted-foreground">TTPs: </span>
                          <span className="font-semibold">{entry.ttpsMatched}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">CVEs: </span>
                          <span className="font-semibold">{entry.cvesMatched}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Confidence: </span>
                          <span className="font-semibold text-red-400">{pct(entry.confidence)}%</span>
                        </div>
                      </div>
                      <span className="text-xs text-muted-foreground w-24">{fmtDate(entry.timestamp)}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ═══ LEARNING EVENTS TAB ═══ */}
        <TabsContent value="events" className="space-y-6">
          <Card className="border-border">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Zap className="h-4 w-4 text-amber-400" />
                Learning Events
              </CardTitle>
              <CardDescription>Decisions, context usage, and knowledge module activations during scans</CardDescription>
            </CardHeader>
            <CardContent>
              {learningEvents?.events && learningEvents.events.length > 0 ? (
                <ScrollArea className="h-[500px]">
                  <div className="space-y-2">
                    {learningEvents.events.map((evt: any, i: number) => (
                      <div key={i} className="p-3 rounded-lg bg-muted/30 border border-border/50 space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className={`text-[10px] ${evt.eventType === "decision" ? "text-blue-400 border-blue-500/30" : evt.eventType === "context_injection" ? "text-purple-400 border-purple-500/30" : "text-amber-400 border-amber-500/30"}`}>
                              {evt.eventType}
                            </Badge>
                            <Badge variant="outline" className="text-[10px]">{evt.targetPreset}</Badge>
                            {evt.phase && <Badge variant="outline" className="text-[10px] text-muted-foreground">{evt.phase}</Badge>}
                          </div>
                          <span className="text-xs text-muted-foreground">{fmtDate(evt.timestamp)}</span>
                        </div>
                        {evt.decision && <p className="text-xs text-foreground">{evt.decision}</p>}
                        {evt.contextUsed && <p className="text-xs text-muted-foreground">Context: {evt.contextUsed}</p>}
                        {evt.knowledgeModules && evt.knowledgeModules.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {evt.knowledgeModules.map((mod: string) => (
                              <Badge key={mod} variant="outline" className="text-[10px] text-cyan-400 border-cyan-500/30">
                                {mod}
                              </Badge>
                            ))}
                          </div>
                        )}
                        <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                          {evt.confidence != null && <span>Confidence: {pct(evt.confidence)}%</span>}
                          {evt.groundTruthMatch != null && (
                            <span className={evt.groundTruthMatch ? "text-green-400" : "text-red-400"}>
                              {evt.groundTruthMatch ? "✓ Ground truth match" : "✗ Ground truth miss"}
                            </span>
                          )}
                          {evt.outcome && <span>Outcome: {evt.outcome}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              ) : (
                <EmptyState icon={Zap} message="No learning events recorded yet" hint="Events are recorded during scan execution when the AI makes decisions" />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ═══ GROUND TRUTH TAB ═══ */}
        <TabsContent value="ground-truth" className="space-y-6">
          <Card className="border-border">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Shield className="h-4 w-4 text-amber-400" />
                Ground Truth Library
              </CardTitle>
              <CardDescription>Known vulnerabilities for each training target — used to score LLM accuracy</CardDescription>
            </CardHeader>
            <CardContent>
              {groundTruth?.targets ? (
                <div className="space-y-4">
                  {Object.entries(groundTruth.targets).map(([target, vulns]: [string, any]) => (
                    <div key={target} className="border border-border/50 rounded-lg overflow-hidden">
                      <div className="flex items-center justify-between px-4 py-3 bg-muted/30">
                        <div className="flex items-center gap-2">
                          <FlaskConical className="h-4 w-4 text-blue-400" />
                          <span className="font-semibold text-sm">{target}</span>
                        </div>
                        <Badge variant="outline" className="text-xs">{Array.isArray(vulns) ? vulns.length : 0} vulns</Badge>
                      </div>
                      {Array.isArray(vulns) && vulns.length > 0 && (
                        <div className="divide-y divide-border/30">
                          {vulns.map((v: any, i: number) => (
                            <div key={i} className="flex items-center gap-3 px-4 py-2 text-xs">
                              <Badge variant="outline" className={`text-[10px] min-w-[60px] justify-center ${severityColor(v.severity)}`}>
                                {v.severity}
                              </Badge>
                              <span className="flex-1 font-medium">{v.title || v.name}</span>
                              {v.owasp && <Badge variant="outline" className="text-[10px] text-muted-foreground">{v.owasp}</Badge>}
                              {v.cwe && <span className="text-muted-foreground">{v.cwe}</span>}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState icon={Shield} message="Loading ground truth..." hint="Ground truth data is loaded from the learning engine" />
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ─── Sub-Components ─────────────────────────────────────────────────────────
function StatCard({ label, value, icon: Icon, color, loading }: {
  label: string; value: number; icon: React.ElementType; color: string; loading?: boolean;
}) {
  return (
    <Card className="border-border">
      <CardContent className="py-3 px-4">
        {loading ? (
          <Skeleton className="h-12 w-full" />
        ) : (
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">{label}</p>
              <p className="text-xl font-bold mt-0.5">{value.toLocaleString()}</p>
            </div>
            <div className={`p-2 rounded-lg bg-muted/50 ${color}`}>
              <Icon className="h-4 w-4" />
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function EmptyState({ icon: Icon, message, hint }: { icon: React.ElementType; message: string; hint: string }) {
  return (
    <div className="text-center py-12 text-muted-foreground">
      <Icon className="h-10 w-10 mx-auto mb-3 opacity-20" />
      <p className="text-sm font-medium">{message}</p>
      <p className="text-xs mt-1 opacity-60">{hint}</p>
    </div>
  );
}
