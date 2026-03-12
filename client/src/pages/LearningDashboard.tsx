/**
 * Learning Dashboard — Unified Learning Hub
 * ───────────────────────────────────────────
 * This page provides a single, consolidated view of the platform's learning
 * capabilities. It merges data from the LLM Learning Engine (training labs,
 * threat actor catalog, accuracy metrics) and the Knowledge Base (module stats,
 * phase mapping, module effectiveness) into cross-linked sections that show
 * how knowledge modules impact scan accuracy, how threat attribution improves
 * over time, and the overall learning progress of the platform.
 */
import { useState, useMemo } from "react";
import { Link } from "wouter";
import { trpc } from "@/lib/trpc";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  Legend, ResponsiveContainer, RadarChart, Radar, PolarGrid,
  PolarAngleAxis, PolarRadiusAxis, BarChart, Bar, Cell,
  PieChart, Pie,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Brain, Shield, Target, Zap, TrendingUp, TrendingDown,
  Minus, Library, Sparkles, ArrowRight, ChevronRight,
  Activity, Crosshair, BarChart3, Globe2, Cpu, Network,
  AlertTriangle, CheckCircle2, XCircle, Eye, Layers,
} from "lucide-react";
import { toast } from "sonner";

// ─── Color Palette ─────────────────────────────────────────────────────────

const COLORS = {
  emerald: "#34d399",
  blue: "#60a5fa",
  amber: "#fbbf24",
  red: "#f87171",
  purple: "#a78bfa",
  cyan: "#22d3ee",
  pink: "#f472b6",
  orange: "#fb923c",
};

const PHASE_COLORS: Record<string, string> = {
  recon: COLORS.blue,
  enumeration: COLORS.cyan,
  vuln_detection: COLORS.amber,
  exploitation: COLORS.red,
  post_exploitation: COLORS.purple,
  reporting: COLORS.emerald,
};

const TARGET_COLORS: Record<string, string> = {
  dvwa: COLORS.red,
  juice_shop: COLORS.amber,
  webgoat: COLORS.emerald,
  hackazon: COLORS.blue,
  metasploitable: COLORS.purple,
  vulnhub_kioptrix: COLORS.cyan,
};

// ─── Sub-components ────────────────────────────────────────────────────────

function StatCard({ label, value, icon: Icon, trend, subtitle, color = "text-foreground" }: {
  label: string;
  value: string | number;
  icon: React.ElementType;
  trend?: "improving" | "declining" | "stable" | "insufficient_data";
  subtitle?: string;
  color?: string;
}) {
  return (
    <Card className="border-border hover:border-primary/30 transition-colors">
      <CardContent className="py-4 px-5">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-xs text-muted-foreground font-medium uppercase tracking-wide">{label}</p>
            <div className="flex items-center gap-2 mt-1">
              <p className={`text-2xl font-bold ${color}`}>{value}</p>
              {trend && <TrendBadge trend={trend} />}
            </div>
            {subtitle && <p className="text-xs text-muted-foreground mt-1">{subtitle}</p>}
          </div>
          <div className="p-2 rounded-lg bg-primary/10">
            <Icon className="h-4 w-4 text-primary" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function TrendBadge({ trend }: { trend: string }) {
  if (trend === "improving") return <Badge variant="outline" className="text-emerald-400 border-emerald-500/30 text-xs gap-1"><TrendingUp className="h-3 w-3" />Up</Badge>;
  if (trend === "declining") return <Badge variant="outline" className="text-red-400 border-red-500/30 text-xs gap-1"><TrendingDown className="h-3 w-3" />Down</Badge>;
  if (trend === "stable") return <Badge variant="outline" className="text-amber-400 border-amber-500/30 text-xs gap-1"><Minus className="h-3 w-3" />Stable</Badge>;
  return null;
}

function SectionHeader({ title, description, icon: Icon, action }: {
  title: string;
  description: string;
  icon: React.ElementType;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between mb-4">
      <div className="flex items-start gap-3">
        <div className="p-2 rounded-lg bg-primary/10 mt-0.5">
          <Icon className="h-5 w-5 text-primary" />
        </div>
        <div>
          <h2 className="text-lg font-semibold">{title}</h2>
          <p className="text-sm text-muted-foreground mt-0.5">{description}</p>
        </div>
      </div>
      {action}
    </div>
  );
}

function LoadingGrid({ count = 4 }: { count?: number }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      {Array.from({ length: count }).map((_, i) => (
        <Skeleton key={i} className="h-24 rounded-xl" />
      ))}
    </div>
  );
}

// ─── Main Component ────────────────────────────────────────────────────────

export default function LearningDashboard() {
  // ── Data Queries ──
  const { data: engineHealth, isLoading: healthLoading, isError: healthError } = trpc.learningEngine.health.useQuery(undefined, { retry: 1, retryDelay: 2000 });
  const { data: dashboard, isLoading: dashboardLoading, isError: dashboardError } = trpc.learningEngine.dashboard.useQuery(undefined, { retry: 1, retryDelay: 2000 });
  const { data: accuracySummary, isLoading: accLoading, isError: accError } = trpc.accuracyFeedback.summary.useQuery(undefined, { retry: 1 });
  const { data: accuracyHistory } = trpc.accuracyFeedback.history.useQuery({ limit: 100 }, { retry: 1 });
  const { data: latestPerTarget } = trpc.accuracyFeedback.latestPerTarget.useQuery(undefined, { retry: 1 });
  const { data: aggregateVulnAccuracy } = trpc.accuracyFeedback.aggregateVulnAccuracy.useQuery({}, { retry: 1 });
  const { data: kbStats } = trpc.knowledgeBase.getStats.useQuery(undefined, { retry: 1 });
  const { data: kbModules } = trpc.knowledgeBase.listModules.useQuery(undefined, { retry: 1 });
  const { data: phaseMapping } = trpc.knowledgeBase.getPhaseMapping.useQuery(undefined, { retry: 1 });

  // Don't block rendering if queries error out — show available data
  const isLoading = (healthLoading && !healthError) || (accLoading && !accError);
  const engineOffline = dashboardError || healthError;

  // ── Computed Data ──

  // Accuracy trend chart data
  const trendChartData = useMemo(() => {
    if (!accuracyHistory || accuracyHistory.length === 0) return [];
    const waveMap = new Map<number, any>();
    const targetWaveCounts = new Map<string, number>();
    for (const row of [...accuracyHistory].reverse()) {
      const target = (row as any).target_preset ?? (row as any).targetPreset ?? "unknown";
      const count = (targetWaveCounts.get(target) ?? 0) + 1;
      targetWaveCounts.set(target, count);
      if (!waveMap.has(count)) waveMap.set(count, { wave: `Wave ${count}` });
      const entry = waveMap.get(count)!;
      const f1 = Number((row as any).f1_score ?? (row as any).f1Score ?? 0);
      entry[`${target}_f1`] = Math.round(f1 * 1000) / 10;
    }
    return Array.from(waveMap.values());
  }, [accuracyHistory]);

  const trendTargets = useMemo(() => {
    if (!accuracyHistory) return [];
    const targets = new Set<string>();
    for (const row of accuracyHistory) {
      targets.add((row as any).target_preset ?? (row as any).targetPreset ?? "unknown");
    }
    return Array.from(targets);
  }, [accuracyHistory]);

  // Phase coverage radar data
  const radarData = useMemo(() => {
    if (!phaseMapping) return [];
    const phases = ["recon", "enumeration", "vuln_detection", "exploitation", "post_exploitation", "reporting"];
    return phases.map(phase => ({
      phase: phase.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
      modules: (phaseMapping as any)?.[phase]?.length ?? 0,
      fullMark: 20,
    }));
  }, [phaseMapping]);

  // Module effectiveness (top modules by accuracy impact)
  const moduleEffectiveness = useMemo(() => {
    if (!kbModules) return [];
    return (kbModules as any[])
      .filter(m => m.itemCount > 0)
      .sort((a, b) => (b.mitreTechniques?.length ?? 0) - (a.mitreTechniques?.length ?? 0))
      .slice(0, 8)
      .map(m => ({
        name: m.name.length > 20 ? m.name.slice(0, 18) + "…" : m.name,
        fullName: m.name,
        techniques: m.mitreTechniques?.length ?? 0,
        items: m.itemCount ?? 0,
        category: m.category,
      }));
  }, [kbModules]);

  // Vuln detection heatmap data
  const vulnDetectionData = useMemo(() => {
    if (!aggregateVulnAccuracy || !Array.isArray(aggregateVulnAccuracy)) return [];
    return (aggregateVulnAccuracy as any[])
      .map(v => ({
        name: (v.vuln_type ?? v.vulnType ?? "Unknown").replace(/_/g, " "),
        detectionRate: Math.round(Number(v.avg_detection_rate ?? v.avgDetectionRate ?? 0) * 100),
        samples: Number(v.sample_count ?? v.sampleCount ?? 0),
      }))
      .sort((a, b) => b.detectionRate - a.detectionRate)
      .slice(0, 12);
  }, [aggregateVulnAccuracy]);

  // Training lab stats
  const trainingLab = dashboard?.trainingLab;
  const threatActor = dashboard?.threatActor;

  // Per-target summary for the target grid
  const targetGrid = useMemo(() => {
    if (!latestPerTarget || !Array.isArray(latestPerTarget)) return [];
    return (latestPerTarget as any[]).map(t => ({
      target: t.target_preset ?? t.targetPreset ?? "unknown",
      f1: Number(t.f1_score ?? t.f1Score ?? 0),
      precision: Number(t.precision ?? 0),
      recall: Number(t.recall ?? 0),
      tp: Number(t.true_positives ?? t.truePositives ?? 0),
      fp: Number(t.false_positives ?? t.falsePositives ?? 0),
      fn: Number(t.false_negatives ?? t.falseNegatives ?? 0),
      f1Delta: Number(t.f1_delta ?? t.f1Delta ?? 0),
    })).sort((a, b) => b.f1 - a.f1);
  }, [latestPerTarget]);

  // ── Render ──

  if (isLoading) {
    return (
      <div className="p-6 space-y-6 max-w-[1600px] mx-auto">
        <Skeleton className="h-10 w-80" />
        <LoadingGrid count={6} />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Skeleton className="h-80" />
          <Skeleton className="h-80" />
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-8 max-w-[1600px] mx-auto">
      {/* ── Header ── */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-primary/20 to-purple-500/20">
              <Brain className="h-6 w-6 text-primary" />
            </div>
            Learning Dashboard
          </h1>
          <p className="text-sm text-muted-foreground mt-2 max-w-2xl">
            Unified view of the platform's learning capabilities — combining training lab accuracy, threat actor attribution, knowledge module effectiveness, and scan improvement trends into a single operational picture.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link href="/knowledge-base">
            <Button variant="outline" size="sm" className="gap-2">
              <Library className="h-4 w-4" /> Knowledge Base
            </Button>
          </Link>
          <Link href="/llm-learning">
            <Button variant="outline" size="sm" className="gap-2">
              <Sparkles className="h-4 w-4" /> Learning Engine
            </Button>
          </Link>
        </div>
      </div>

      {/* ── Engine Offline Banner ── */}
      {engineOffline && (
        <div className="flex items-center gap-3 p-3 rounded-lg border border-amber-500/30 bg-amber-500/10">
          <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0" />
          <div>
            <p className="text-sm font-medium text-amber-300">Learning Engine Unavailable</p>
            <p className="text-xs text-muted-foreground">The DO learning engine is temporarily offline. Accuracy data from local comparisons and knowledge base stats are still available below.</p>
          </div>
        </div>
      )}

      {/* ── Top-Level KPIs ── */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <StatCard
          label="Engine Status"
          value={engineHealth?.status === "healthy" ? "Online" : "Offline"}
          icon={Activity}
          color={engineHealth?.status === "healthy" ? "text-emerald-400" : "text-red-400"}
          subtitle={engineHealth?.uptime ? `Uptime: ${engineHealth.uptime}` : undefined}
        />
        <StatCard
          label="Avg F1 Score"
          value={accuracySummary ? `${(accuracySummary.avgF1 * 100).toFixed(1)}%` : "—"}
          icon={Crosshair}
          trend={accuracySummary?.f1Trend}
          subtitle={`Best: ${accuracySummary ? (accuracySummary.bestF1 * 100).toFixed(1) : 0}%`}
        />
        <StatCard
          label="Knowledge Modules"
          value={kbStats?.totalModules ?? 0}
          icon={Library}
          subtitle={`${kbStats?.totalItems?.toLocaleString() ?? 0} items`}
        />
        <StatCard
          label="Training Labs"
          value={trainingLab?.engagementRuns ?? 0}
          icon={Target}
          subtitle={`${trainingLab?.groundTruthTargets ?? 0} targets with ground truth`}
        />
        <StatCard
          label="Threat Groups"
          value={threatActor?.totalGroups ?? 0}
          icon={Shield}
          subtitle={`${threatActor?.topGroups?.length ?? 0} actively tracked`}
        />
        <StatCard
          label="Comparisons"
          value={accuracySummary?.totalComparisons ?? 0}
          icon={BarChart3}
          subtitle={`${accuracySummary?.targetCount ?? 0} targets scored`}
        />
      </div>

      {/* ── Row 1: Accuracy Trend + Phase Coverage ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* F1 Score Trend — 2/3 width */}
        <Card className="border-border lg:col-span-2">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-emerald-400" />
                  Accuracy Trend
                </CardTitle>
                <CardDescription className="text-xs">F1 score progression across scan waves per target</CardDescription>
              </div>
              <Link href="/knowledge-base">
                <Button variant="ghost" size="sm" className="text-xs gap-1">
                  Full Details <ChevronRight className="h-3 w-3" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent>
            {trendChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={280}>
                <LineChart data={trendChartData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                  <XAxis dataKey="wave" tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} tickFormatter={(v) => `${v}%`} />
                  <Tooltip
                    contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: 12 }}
                    formatter={(value: number, name: string) => [`${value}%`, name.replace(/_f1$/, "")]}
                  />
                  <Legend wrapperStyle={{ fontSize: 11 }} formatter={(v) => v.replace(/_f1$/, "")} />
                  {trendTargets.map((target) => (
                    <Line
                      key={target}
                      type="monotone"
                      dataKey={`${target}_f1`}
                      stroke={TARGET_COLORS[target] || "#94a3b8"}
                      strokeWidth={2}
                      dot={{ r: 4, fill: TARGET_COLORS[target] || "#94a3b8" }}
                      activeDot={{ r: 6 }}
                      connectNulls
                    />
                  ))}
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[280px] flex items-center justify-center text-sm text-muted-foreground">
                <div className="text-center">
                  <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-40" />
                  <p>No accuracy data yet. Run training lab scans to populate.</p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Phase Coverage Radar — 1/3 width */}
        <Card className="border-border">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Layers className="h-4 w-4 text-blue-400" />
              Phase Coverage
            </CardTitle>
            <CardDescription className="text-xs">Knowledge module distribution across attack phases</CardDescription>
          </CardHeader>
          <CardContent>
            {radarData.length > 0 ? (
              <ResponsiveContainer width="100%" height={280}>
                <RadarChart cx="50%" cy="50%" outerRadius="70%" data={radarData}>
                  <PolarGrid stroke="hsl(var(--border))" opacity={0.3} />
                  <PolarAngleAxis dataKey="phase" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                  <PolarRadiusAxis tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }} />
                  <Radar name="Modules" dataKey="modules" stroke={COLORS.blue} fill={COLORS.blue} fillOpacity={0.2} strokeWidth={2} />
                </RadarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[280px] flex items-center justify-center text-sm text-muted-foreground">
                No phase mapping data
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* ── Row 2: Target Accuracy Grid + Vuln Detection Rates ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Target Accuracy Grid */}
        <div>
          <SectionHeader
            title="Target Accuracy Breakdown"
            description="Latest F1 score per training lab target with delta from previous scan"
            icon={Target}
            action={
              <Link href="/knowledge-base">
                <Button variant="ghost" size="sm" className="text-xs gap-1">
                  Rescore <ChevronRight className="h-3 w-3" />
                </Button>
              </Link>
            }
          />
          {targetGrid.length > 0 ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {targetGrid.map((t) => (
                <Card key={t.target} className="border-border hover:border-primary/30 transition-colors">
                  <CardContent className="py-3 px-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-sm">{t.target.replace(/_/g, " ")}</span>
                      <div className="flex items-center gap-1.5">
                        <span className={`text-lg font-bold ${t.f1 >= 0.7 ? "text-emerald-400" : t.f1 >= 0.4 ? "text-amber-400" : "text-red-400"}`}>
                          {(t.f1 * 100).toFixed(1)}%
                        </span>
                        {t.f1Delta !== 0 && (
                          <Badge variant="outline" className={`text-xs ${t.f1Delta > 0 ? "text-emerald-400 border-emerald-500/30" : "text-red-400 border-red-500/30"}`}>
                            {t.f1Delta > 0 ? "+" : ""}{(t.f1Delta * 100).toFixed(1)}%
                          </Badge>
                        )}
                      </div>
                    </div>
                    <Progress value={t.f1 * 100} className="h-1.5 mb-2" />
                    <div className="flex items-center gap-3 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1"><CheckCircle2 className="h-3 w-3 text-emerald-400" /> {t.tp} TP</span>
                      <span className="flex items-center gap-1"><XCircle className="h-3 w-3 text-red-400" /> {t.fp} FP</span>
                      <span className="flex items-center gap-1"><AlertTriangle className="h-3 w-3 text-amber-400" /> {t.fn} FN</span>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card className="border-border">
              <CardContent className="py-8 text-center text-sm text-muted-foreground">
                <Target className="h-8 w-8 mx-auto mb-2 opacity-40" />
                No target accuracy data yet
              </CardContent>
            </Card>
          )}
        </div>

        {/* Vuln Detection Rates */}
        <div>
          <SectionHeader
            title="Vulnerability Detection Rates"
            description="Average detection rate per vulnerability type across all scans"
            icon={Eye}
          />
          {vulnDetectionData.length > 0 ? (
            <Card className="border-border">
              <CardContent className="py-4">
                <ResponsiveContainer width="100%" height={Math.max(280, vulnDetectionData.length * 32)}>
                  <BarChart data={vulnDetectionData} layout="vertical" margin={{ top: 5, right: 30, left: 10, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} horizontal={false} />
                    <XAxis type="number" domain={[0, 100]} tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} tickFormatter={(v) => `${v}%`} />
                    <YAxis dataKey="name" type="category" width={140} tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                    <Tooltip
                      contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: 12 }}
                      formatter={(value: number) => [`${value}%`, "Detection Rate"]}
                    />
                    <Bar dataKey="detectionRate" radius={[0, 4, 4, 0]}>
                      {vulnDetectionData.map((entry, index) => (
                        <Cell key={index} fill={entry.detectionRate >= 70 ? COLORS.emerald : entry.detectionRate >= 40 ? COLORS.amber : COLORS.red} fillOpacity={0.8} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          ) : (
            <Card className="border-border">
              <CardContent className="py-8 text-center text-sm text-muted-foreground">
                <Eye className="h-8 w-8 mx-auto mb-2 opacity-40" />
                No vuln detection data yet
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* ── Row 3: Module Effectiveness + Threat Attribution ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Module Effectiveness */}
        <div>
          <SectionHeader
            title="Module Effectiveness"
            description="Top knowledge modules ranked by MITRE technique coverage and item count"
            icon={Cpu}
            action={
              <Link href="/knowledge-base">
                <Button variant="ghost" size="sm" className="text-xs gap-1">
                  Browse All <ChevronRight className="h-3 w-3" />
                </Button>
              </Link>
            }
          />
          <Card className="border-border">
            <CardContent className="py-4">
              {moduleEffectiveness.length > 0 ? (
                <div className="space-y-3">
                  {moduleEffectiveness.map((m, i) => (
                    <div key={i} className="flex items-center gap-3">
                      <span className="text-xs text-muted-foreground w-5 text-right font-mono">{i + 1}</span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm font-medium truncate" title={m.fullName}>{m.name}</span>
                          <div className="flex items-center gap-2 shrink-0">
                            <Badge variant="outline" className="text-xs">{m.techniques} TTPs</Badge>
                            <span className="text-xs text-muted-foreground">{m.items} items</span>
                          </div>
                        </div>
                        <Progress value={Math.min(100, (m.techniques / 15) * 100)} className="h-1" />
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-8 text-center text-sm text-muted-foreground">
                  No module data available
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Threat Attribution Summary */}
        <div>
          <SectionHeader
            title="Threat Attribution"
            description="Top threat groups from the learning engine with attribution confidence"
            icon={Shield}
            action={
              <Link href="/llm-learning">
                <Button variant="ghost" size="sm" className="text-xs gap-1">
                  Full Catalog <ChevronRight className="h-3 w-3" />
                </Button>
              </Link>
            }
          />
          <Card className="border-border">
            <CardContent className="py-4">
              {threatActor?.topGroups && threatActor.topGroups.length > 0 ? (
                <div className="space-y-3">
                  {threatActor.topGroups.slice(0, 8).map((group: any, i: number) => (
                    <Link key={i} href={`/threat-actors/${group.groupId ?? group.name?.toLowerCase().replace(/\s+/g, "-")}`}>
                      <div className="flex items-center gap-3 p-2 rounded-lg hover:bg-accent/50 transition-colors cursor-pointer">
                        <div className="w-8 h-8 rounded-full bg-red-500/10 border border-red-500/20 flex items-center justify-center shrink-0">
                          <Shield className="h-4 w-4 text-red-400" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-medium">{group.name ?? group.groupId}</span>
                            <div className="flex items-center gap-2 shrink-0">
                              {group.confidence != null && (
                                <Badge variant="outline" className={`text-xs ${
                                  group.confidence >= 0.7 ? "text-emerald-400 border-emerald-500/30" :
                                  group.confidence >= 0.4 ? "text-amber-400 border-amber-500/30" :
                                  "text-red-400 border-red-500/30"
                                }`}>
                                  {(group.confidence * 100).toFixed(0)}% conf
                                </Badge>
                              )}
                              <span className="text-xs text-muted-foreground">{group.ttpCount ?? group.techniques?.length ?? 0} TTPs</span>
                            </div>
                          </div>
                          {group.origin && (
                            <span className="text-xs text-muted-foreground">{group.origin}</span>
                          )}
                        </div>
                        <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
                      </div>
                    </Link>
                  ))}
                </div>
              ) : (
                <div className="py-8 text-center text-sm text-muted-foreground">
                  <Shield className="h-8 w-8 mx-auto mb-2 opacity-40" />
                  <p>No threat attribution data available</p>
                  <p className="text-xs mt-1">The learning engine may be offline</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* ── Row 4: Learning Streams Summary ── */}
      <div>
        <SectionHeader
          title="Learning Streams"
          description="Cross-linked metrics from training labs and threat actor catalog"
          icon={Network}
        />
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Card className="border-border bg-gradient-to-br from-emerald-500/5 to-transparent">
            <CardContent className="py-4 px-5">
              <div className="flex items-center gap-2 mb-3">
                <Target className="h-4 w-4 text-emerald-400" />
                <p className="text-sm font-medium">Training Labs</p>
              </div>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Engagement Runs</span>
                  <span className="font-medium">{trainingLab?.engagementRuns ?? 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Avg Precision</span>
                  <span className="font-medium">{trainingLab?.avgPrecision != null ? `${(trainingLab.avgPrecision * 100).toFixed(1)}%` : "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Avg F1</span>
                  <span className="font-medium">{trainingLab?.avgF1 != null ? `${(trainingLab.avgF1 * 100).toFixed(1)}%` : "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Ground Truth Vulns</span>
                  <span className="font-medium">{trainingLab?.totalGroundTruthVulns ?? 0}</span>
                </div>
              </div>
              <Link href="/llm-learning">
                <Button variant="ghost" size="sm" className="w-full mt-3 text-xs gap-1">
                  View Details <ArrowRight className="h-3 w-3" />
                </Button>
              </Link>
            </CardContent>
          </Card>

          <Card className="border-border bg-gradient-to-br from-red-500/5 to-transparent">
            <CardContent className="py-4 px-5">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="h-4 w-4 text-red-400" />
                <p className="text-sm font-medium">Threat Catalog</p>
              </div>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Total Groups</span>
                  <span className="font-medium">{threatActor?.totalGroups ?? 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Avg Confidence</span>
                  <span className="font-medium">{threatActor?.avgConfidence != null ? `${(threatActor.avgConfidence * 100).toFixed(1)}%` : "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">TTP Detections</span>
                  <span className="font-medium">{threatActor?.ttpDetections ?? 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">CVE Coverage</span>
                  <span className="font-medium">{threatActor?.cveCoverage ?? 0}</span>
                </div>
              </div>
              <Link href="/llm-learning">
                <Button variant="ghost" size="sm" className="w-full mt-3 text-xs gap-1">
                  View Details <ArrowRight className="h-3 w-3" />
                </Button>
              </Link>
            </CardContent>
          </Card>

          <Card className="border-border bg-gradient-to-br from-blue-500/5 to-transparent">
            <CardContent className="py-4 px-5">
              <div className="flex items-center gap-2 mb-3">
                <Library className="h-4 w-4 text-blue-400" />
                <p className="text-sm font-medium">Knowledge Base</p>
              </div>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Total Modules</span>
                  <span className="font-medium">{kbStats?.totalModules ?? 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Total Items</span>
                  <span className="font-medium">{kbStats?.totalItems?.toLocaleString() ?? 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">MITRE Techniques</span>
                  <span className="font-medium">{kbStats?.totalMitreTechniques ?? 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Active Phases</span>
                  <span className="font-medium">{radarData.filter(r => r.modules > 0).length}/6</span>
                </div>
              </div>
              <Link href="/knowledge-base">
                <Button variant="ghost" size="sm" className="w-full mt-3 text-xs gap-1">
                  Browse Modules <ArrowRight className="h-3 w-3" />
                </Button>
              </Link>
            </CardContent>
          </Card>

          <Card className="border-border bg-gradient-to-br from-amber-500/5 to-transparent">
            <CardContent className="py-4 px-5">
              <div className="flex items-center gap-2 mb-3">
                <Crosshair className="h-4 w-4 text-amber-400" />
                <p className="text-sm font-medium">Accuracy Feedback</p>
              </div>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Comparisons</span>
                  <span className="font-medium">{accuracySummary?.totalComparisons ?? 0}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Avg Precision</span>
                  <span className="font-medium">{accuracySummary ? `${(accuracySummary.avgPrecision * 100).toFixed(1)}%` : "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Avg Recall</span>
                  <span className="font-medium">{accuracySummary ? `${(accuracySummary.avgRecall * 100).toFixed(1)}%` : "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Trend</span>
                  <TrendBadge trend={accuracySummary?.f1Trend ?? "insufficient_data"} />
                </div>
              </div>
              <Link href="/knowledge-base">
                <Button variant="ghost" size="sm" className="w-full mt-3 text-xs gap-1">
                  View Accuracy <ArrowRight className="h-3 w-3" />
                </Button>
              </Link>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
