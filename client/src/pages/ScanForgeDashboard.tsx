// @ts-nocheck
/**
 * ScanForge Dashboard — Self-Improving Vulnerability Scanner Analytics
 *
 * Visualizes accuracy metrics, template performance, engagement comparison reports,
 * auto-generated templates, and TI research activity from the ScanForge engine.
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { toast } from "sonner";
import {
  Activity, BarChart3, Brain, Bug, CheckCircle, ChevronRight,
  Clock, Database, Eye, FileText, FlaskConical, Gauge, GitMerge,
  Layers, Microscope, RefreshCw, Rocket, Search, Shield, ShieldCheck,
  Skull, Sparkles, Target, TrendingUp, Zap, AlertTriangle, XCircle,
  ArrowUpRight, ArrowDownRight, Minus, BookOpen, Beaker, Cpu, Crosshair,
  CircleDot, ChevronDown, ChevronUp, ExternalLink
} from "lucide-react";
import { sanitizeErrorForToast } from "@/lib/error-sanitizer";

// ── Severity color helpers ──────────────────────────────────────────────────
const severityColor = (s: string) => {
  switch (s) {
    case "critical": return "text-red-400 bg-red-500/10 border-red-500/30";
    case "high": return "text-orange-400 bg-orange-500/10 border-orange-500/30";
    case "medium": return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
    case "low": return "text-blue-400 bg-blue-500/10 border-blue-500/30";
    case "info": return "text-gray-400 bg-gray-500/10 border-gray-500/30";
    default: return "text-muted-foreground bg-muted/50 border-border";
  }
};

const verdictBadge = (v: string) => {
  switch (v) {
    case "TP": return { label: "True Positive", color: "text-green-400 bg-green-500/10 border-green-500/30", icon: <CheckCircle className="h-3 w-3" /> };
    case "FP": return { label: "False Positive", color: "text-red-400 bg-red-500/10 border-red-500/30", icon: <XCircle className="h-3 w-3" /> };
    case "FN": return { label: "False Negative", color: "text-orange-400 bg-orange-500/10 border-orange-500/30", icon: <AlertTriangle className="h-3 w-3" /> };
    case "PENDING": return { label: "Pending", color: "text-gray-400 bg-gray-500/10 border-gray-500/30", icon: <Clock className="h-3 w-3" /> };
    default: return { label: v, color: "text-muted-foreground bg-muted/50 border-border", icon: <CircleDot className="h-3 w-3" /> };
  }
};

const pct = (n: number) => `${(n * 100).toFixed(1)}%`;
const f2 = (n: number) => n.toFixed(2);

// ── Metric Card ─────────────────────────────────────────────────────────────
function MetricCard({ label, value, subtitle, icon, color, trend }: {
  label: string; value: string | number; subtitle?: string;
  icon: React.ReactNode; color?: string; trend?: "up" | "down" | "neutral";
}) {
  return (
    <Card className="bg-card/80 border-border/50 hover:border-primary/30 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground uppercase tracking-wider font-medium">{label}</p>
            <p className={`text-2xl font-bold ${color || "text-foreground"}`}>{value}</p>
            {subtitle && <p className="text-[11px] text-muted-foreground">{subtitle}</p>}
          </div>
          <div className="p-2 rounded-lg bg-muted/50">
            {icon}
          </div>
        </div>
        {trend && (
          <div className="mt-2 flex items-center gap-1 text-[10px]">
            {trend === "up" && <ArrowUpRight className="h-3 w-3 text-green-400" />}
            {trend === "down" && <ArrowDownRight className="h-3 w-3 text-red-400" />}
            {trend === "neutral" && <Minus className="h-3 w-3 text-muted-foreground" />}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── Gauge Ring ──────────────────────────────────────────────────────────────
function GaugeRing({ value, label, color }: { value: number; label: string; color: string }) {
  const pctVal = Math.round(value * 100);
  const circumference = 2 * Math.PI * 36;
  const dashOffset = circumference - (pctVal / 100) * circumference;
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="88" height="88" viewBox="0 0 88 88" className="transform -rotate-90">
        <circle cx="44" cy="44" r="36" fill="none" stroke="currentColor" strokeWidth="6"
          className="text-muted/30" />
        <circle cx="44" cy="44" r="36" fill="none" stroke="currentColor" strokeWidth="6"
          className={color} strokeDasharray={circumference} strokeDashoffset={dashOffset}
          strokeLinecap="round" style={{ transition: "stroke-dashoffset 0.8s ease-in-out" }} />
      </svg>
      <div className="absolute flex flex-col items-center justify-center" style={{ width: 88, height: 88 }}>
        <span className="text-lg font-bold text-foreground">{pctVal}%</span>
      </div>
      <span className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium mt-1">{label}</span>
    </div>
  );
}

// ── Overview Tab ─────────────────────────────────────────────────────────────
function OverviewTab() {
  const { data: summary, isLoading: summaryLoading } = trpc.scanforge.dashboardSummary.useQuery();
  const { data: health, isLoading: healthLoading } = trpc.scanforge.healthMetrics.useQuery();
  const { data: stats } = trpc.scanforge.stats.useQuery();

  if (summaryLoading || healthLoading) {
    return (
      <div className="space-y-4">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="h-24 bg-muted/20 rounded-lg animate-pulse" />
        ))}
      </div>
    );
  }

  const s = summary || {} as any;
  const h = health || {} as any;

  return (
    <div className="space-y-6">
      {/* KPI Strip */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
        <MetricCard label="Template Library" value={s.templateLibrarySize || 0}
          subtitle={`${s.protocolCount || 0} protocol scanners`}
          icon={<Layers className="h-4 w-4 text-primary" />} color="text-primary" />
        <MetricCard label="Total Findings" value={s.totalFindings || 0}
          subtitle={`${s.verdictDistribution?.TP || 0} confirmed`}
          icon={<Bug className="h-4 w-4 text-yellow-400" />} color="text-yellow-400" />
        <MetricCard label="Engagement Reports" value={s.totalReports || 0}
          subtitle="comparison analyses"
          icon={<BarChart3 className="h-4 w-4 text-blue-400" />} color="text-blue-400" />
        <MetricCard label="Generated Templates" value={s.totalGeneratedTemplates || 0}
          subtitle={`${s.generatedTemplateStatuses?.promoted || 0} promoted`}
          icon={<Sparkles className="h-4 w-4 text-purple-400" />} color="text-purple-400" />
        <MetricCard label="Research Entries" value={s.totalResearchEntries || 0}
          subtitle="TI feed analyses"
          icon={<Microscope className="h-4 w-4 text-emerald-400" />} color="text-emerald-400" />
      </div>

      {/* Accuracy Gauges */}
      <Card className="bg-card/80 border-border/50">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Gauge className="h-4 w-4 text-primary" /> Aggregate Accuracy Metrics
          </CardTitle>
          <CardDescription className="text-xs">
            Precision, Recall, and F1 Score across all templates with sufficient scan data
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-around py-4">
            <div className="relative flex flex-col items-center">
              <GaugeRing value={h.avgPrecision || 0} label="Precision" color="text-green-400" />
            </div>
            <div className="relative flex flex-col items-center">
              <GaugeRing value={h.avgRecall || 0} label="Recall" color="text-blue-400" />
            </div>
            <div className="relative flex flex-col items-center">
              <GaugeRing value={h.avgF1 || 0} label="F1 Score" color="text-primary" />
            </div>
          </div>
          <Separator className="my-3" />
          <div className="grid grid-cols-3 gap-4 text-center text-xs">
            <div>
              <span className="text-green-400 font-bold text-lg">{h.truePositives || 0}</span>
              <p className="text-muted-foreground mt-0.5">True Positives</p>
            </div>
            <div>
              <span className="text-red-400 font-bold text-lg">{h.falsePositives || 0}</span>
              <p className="text-muted-foreground mt-0.5">False Positives</p>
            </div>
            <div>
              <span className="text-orange-400 font-bold text-lg">{h.falseNegatives || 0}</span>
              <p className="text-muted-foreground mt-0.5">False Negatives</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Verdict Distribution + Research Types */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Verdict Distribution */}
        <Card className="bg-card/80 border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-green-400" /> Finding Verdicts
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {Object.entries(s.verdictDistribution || {}).map(([verdict, count]: [string, any]) => {
              const vb = verdictBadge(verdict);
              const total = Object.values(s.verdictDistribution || {}).reduce((a: number, b: any) => a + (Number(b) || 0), 0) as number;
              const pctVal = total > 0 ? ((Number(count) || 0) / total) * 100 : 0;
              return (
                <div key={verdict} className="flex items-center gap-3">
                  <Badge variant="outline" className={`text-[10px] ${vb.color} min-w-[90px] justify-center gap-1`}>
                    {vb.icon} {vb.label}
                  </Badge>
                  <div className="flex-1">
                    <Progress value={pctVal} className="h-2" />
                  </div>
                  <span className="text-xs text-foreground font-mono w-10 text-right">{count}</span>
                </div>
              );
            })}
            {Object.keys(s.verdictDistribution || {}).length === 0 && (
              <p className="text-xs text-muted-foreground text-center py-4">No findings assessed yet. Run an engagement to generate data.</p>
            )}
          </CardContent>
        </Card>

        {/* Research Type Distribution */}
        <Card className="bg-card/80 border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Brain className="h-4 w-4 text-purple-400" /> Research Activity
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {Object.entries(s.researchTypeDistribution || {}).map(([type, count]: [string, any]) => {
              const total = Object.values(s.researchTypeDistribution || {}).reduce((a: number, b: any) => a + (Number(b) || 0), 0) as number;
              const pctVal = total > 0 ? ((Number(count) || 0) / total) * 100 : 0;
              return (
                <div key={type} className="flex items-center gap-3">
                  <span className="text-[10px] text-muted-foreground uppercase tracking-wider min-w-[100px]">{type.replace(/_/g, " ")}</span>
                  <div className="flex-1">
                    <Progress value={pctVal} className="h-2" />
                  </div>
                  <span className="text-xs text-foreground font-mono w-10 text-right">{count}</span>
                </div>
              );
            })}
            {Object.keys(s.researchTypeDistribution || {}).length === 0 && (
              <p className="text-xs text-muted-foreground text-center py-4">No research activity yet. The deep research agent runs after engagements.</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Top / Worst Performers */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="bg-card/80 border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-green-400" /> Top Performing Templates
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {(h.topPerformers || []).map((t: any, i: number) => (
              <div key={t.templateId} className="flex items-center gap-2 p-2 rounded bg-muted/20">
                <span className="text-xs font-bold text-primary w-5">#{i + 1}</span>
                <span className="text-xs text-foreground font-mono flex-1 truncate">{t.templateId}</span>
                <Badge variant="outline" className="text-[10px] text-green-400 border-green-500/30">
                  F1: {f2(t.f1)}
                </Badge>
                <span className="text-[10px] text-muted-foreground">{t.findings} findings</span>
              </div>
            ))}
            {(h.topPerformers || []).length === 0 && (
              <p className="text-xs text-muted-foreground text-center py-4">No template performance data yet.</p>
            )}
          </CardContent>
        </Card>

        <Card className="bg-card/80 border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-400" /> Highest False Positive Rate
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {(h.worstPerformers || []).map((t: any, i: number) => (
              <div key={t.templateId} className="flex items-center gap-2 p-2 rounded bg-muted/20">
                <span className="text-xs font-bold text-red-400 w-5">#{i + 1}</span>
                <span className="text-xs text-foreground font-mono flex-1 truncate">{t.templateId}</span>
                <Badge variant="outline" className="text-[10px] text-red-400 border-red-500/30">
                  FP: {pct(t.fpRate)}
                </Badge>
                <span className="text-[10px] text-muted-foreground">{t.findings} findings</span>
              </div>
            ))}
            {(h.worstPerformers || []).length === 0 && (
              <p className="text-xs text-muted-foreground text-center py-4">No template performance data yet.</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ── Template Performance Tab ────────────────────────────────────────────────
function TemplatePerformanceTab() {
  const { data: templates, isLoading } = trpc.scanforge.templateEffectiveness.useQuery({ minScans: 1 });
  const [sortBy, setSortBy] = useState<"f1Score" | "effectivenessScore" | "precision" | "recall">("effectivenessScore");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const sorted = useMemo(() => {
    if (!templates) return [];
    return [...templates].sort((a: any, b: any) => {
      const av = a[sortBy] || 0;
      const bv = b[sortBy] || 0;
      return sortDir === "desc" ? bv - av : av - bv;
    });
  }, [templates, sortBy, sortDir]);

  const toggleSort = (col: typeof sortBy) => {
    if (sortBy === col) setSortDir(d => d === "desc" ? "asc" : "desc");
    else { setSortBy(col); setSortDir("desc"); }
  };

  const SortIcon = ({ col }: { col: typeof sortBy }) => {
    if (sortBy !== col) return null;
    return sortDir === "desc" ? <ChevronDown className="h-3 w-3" /> : <ChevronUp className="h-3 w-3" />;
  };

  if (isLoading) {
    return <div className="space-y-2">{[...Array(5)].map((_, i) => <div key={i} className="h-12 bg-muted/20 rounded animate-pulse" />)}</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">{sorted.length} templates with accuracy data</p>
      </div>
      <div className="rounded-lg border border-border/50 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-muted/30 border-b border-border/50">
                <th className="text-left px-3 py-2 text-muted-foreground font-medium">Template ID</th>
                <th className="text-center px-3 py-2 text-muted-foreground font-medium cursor-pointer hover:text-foreground" onClick={() => toggleSort("precision")}>
                  <span className="flex items-center justify-center gap-1">Precision <SortIcon col="precision" /></span>
                </th>
                <th className="text-center px-3 py-2 text-muted-foreground font-medium cursor-pointer hover:text-foreground" onClick={() => toggleSort("recall")}>
                  <span className="flex items-center justify-center gap-1">Recall <SortIcon col="recall" /></span>
                </th>
                <th className="text-center px-3 py-2 text-muted-foreground font-medium cursor-pointer hover:text-foreground" onClick={() => toggleSort("f1Score")}>
                  <span className="flex items-center justify-center gap-1">F1 <SortIcon col="f1Score" /></span>
                </th>
                <th className="text-center px-3 py-2 text-muted-foreground font-medium cursor-pointer hover:text-foreground" onClick={() => toggleSort("effectivenessScore")}>
                  <span className="flex items-center justify-center gap-1">Effectiveness <SortIcon col="effectivenessScore" /></span>
                </th>
                <th className="text-center px-3 py-2 text-muted-foreground font-medium">TP / FP / FN</th>
                <th className="text-center px-3 py-2 text-muted-foreground font-medium">Confidence</th>
                <th className="text-center px-3 py-2 text-muted-foreground font-medium">Scans</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((t: any) => {
                const effColor = t.effectivenessScore >= 70 ? "text-green-400" : t.effectivenessScore >= 40 ? "text-yellow-400" : "text-red-400";
                return (
                  <tr key={t.templateId} className="border-b border-border/30 hover:bg-muted/10 transition-colors">
                    <td className="px-3 py-2 font-mono text-foreground max-w-[200px] truncate">{t.templateId}</td>
                    <td className="px-3 py-2 text-center">
                      <span className={t.precision >= 0.8 ? "text-green-400" : t.precision >= 0.5 ? "text-yellow-400" : "text-red-400"}>
                        {pct(t.precision)}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-center">
                      <span className={t.recall >= 0.8 ? "text-green-400" : t.recall >= 0.5 ? "text-yellow-400" : "text-red-400"}>
                        {pct(t.recall)}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-center">
                      <span className={t.f1Score >= 0.8 ? "text-green-400" : t.f1Score >= 0.5 ? "text-yellow-400" : "text-red-400"}>
                        {f2(t.f1Score)}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-center">
                      <div className="flex items-center gap-2 justify-center">
                        <Progress value={t.effectivenessScore} className="h-1.5 w-16" />
                        <span className={`font-mono ${effColor}`}>{Math.round(t.effectivenessScore)}</span>
                      </div>
                    </td>
                    <td className="px-3 py-2 text-center font-mono">
                      <span className="text-green-400">{t.truePositives}</span>
                      <span className="text-muted-foreground mx-0.5">/</span>
                      <span className="text-red-400">{t.falsePositives}</span>
                      <span className="text-muted-foreground mx-0.5">/</span>
                      <span className="text-orange-400">{t.falseNegatives}</span>
                    </td>
                    <td className="px-3 py-2 text-center font-mono text-muted-foreground">{f2(t.calibratedConfidence)}</td>
                    <td className="px-3 py-2 text-center font-mono text-muted-foreground">{t.totalScans}</td>
                  </tr>
                );
              })}
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-muted-foreground">
                    No template metrics available yet. Run engagements with ScanForge to generate accuracy data.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── Engagement Reports Tab ──────────────────────────────────────────────────
function EngagementReportsTab() {
  const { data: reports, isLoading } = trpc.scanforge.engagementReports.useQuery({ limit: 50 });
  const [expanded, setExpanded] = useState<number | null>(null);

  if (isLoading) {
    return <div className="space-y-2">{[...Array(3)].map((_, i) => <div key={i} className="h-20 bg-muted/20 rounded animate-pulse" />)}</div>;
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-muted-foreground">{(reports || []).length} engagement comparison reports</p>
      {(reports || []).length === 0 && (
        <Card className="bg-card/80 border-border/50">
          <CardContent className="py-12 text-center">
            <BarChart3 className="h-8 w-8 text-muted-foreground mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">No engagement reports yet.</p>
            <p className="text-xs text-muted-foreground mt-1">Reports are generated after engagements complete with ScanForge enabled.</p>
          </CardContent>
        </Card>
      )}
      {(reports || []).map((r: any) => (
        <Card key={r.id} className="bg-card/80 border-border/50 hover:border-primary/20 transition-colors">
          <CardContent className="p-4">
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <Badge variant="outline" className="text-[10px] text-primary border-primary/30">
                    Engagement #{r.engagementId}
                  </Badge>
                  <span className="text-[10px] text-muted-foreground">
                    {r.createdAt ? new Date(r.createdAt).toLocaleString() : "—"}
                  </span>
                </div>
                {/* Finding Counts */}
                <div className="flex items-center gap-4 mt-2">
                  <div className="text-center">
                    <span className="text-lg font-bold text-primary">{r.scanforgeFindings || 0}</span>
                    <p className="text-[9px] text-muted-foreground">ScanForge</p>
                  </div>
                  <span className="text-muted-foreground text-xs">vs</span>
                  <div className="text-center">
                    <span className="text-lg font-bold text-blue-400">{r.nucleiFindings || 0}</span>
                    <p className="text-[9px] text-muted-foreground">Nuclei</p>
                  </div>
                  <span className="text-muted-foreground text-xs">+</span>
                  <div className="text-center">
                    <span className="text-lg font-bold text-orange-400">{r.zapFindings || 0}</span>
                    <p className="text-[9px] text-muted-foreground">ZAP</p>
                  </div>
                  <Separator orientation="vertical" className="h-8 mx-2" />
                  <div className="text-center">
                    <span className="text-lg font-bold text-green-400">{r.sharedFindings || 0}</span>
                    <p className="text-[9px] text-muted-foreground">Shared</p>
                  </div>
                  <div className="text-center">
                    <span className="text-lg font-bold text-purple-400">{r.scanforgeOnly || 0}</span>
                    <p className="text-[9px] text-muted-foreground">SF Only</p>
                  </div>
                  <div className="text-center">
                    <span className="text-lg font-bold text-yellow-400">{r.legacyOnly || 0}</span>
                    <p className="text-[9px] text-muted-foreground">Legacy Only</p>
                  </div>
                </div>
              </div>
              <Button variant="ghost" size="sm" onClick={() => setExpanded(expanded === r.id ? null : r.id)}>
                {expanded === r.id ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </Button>
            </div>

            {/* Quality Scores */}
            <div className="grid grid-cols-2 gap-3 mt-3">
              <div className="p-2 rounded bg-muted/20">
                <p className="text-[9px] text-muted-foreground uppercase mb-1">ScanForge Quality</p>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-green-400">P: {r.scanforgePrecision != null ? pct(r.scanforgePrecision) : "—"}</span>
                  <span className="text-blue-400">R: {r.scanforgeRecall != null ? pct(r.scanforgeRecall) : "—"}</span>
                  <span className="text-primary">F1: {r.scanforgeF1 != null ? f2(r.scanforgeF1) : "—"}</span>
                </div>
              </div>
              <div className="p-2 rounded bg-muted/20">
                <p className="text-[9px] text-muted-foreground uppercase mb-1">Legacy Tool Quality</p>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-green-400">P: {r.legacyPrecision != null ? pct(r.legacyPrecision) : "—"}</span>
                  <span className="text-blue-400">R: {r.legacyRecall != null ? pct(r.legacyRecall) : "—"}</span>
                  <span className="text-primary">F1: {r.legacyF1 != null ? f2(r.legacyF1) : "—"}</span>
                </div>
              </div>
            </div>

            {/* Expanded Details */}
            {expanded === r.id && (
              <div className="mt-3 space-y-2 border-t border-border/30 pt-3">
                {r.reassessmentSummary && (
                  <div>
                    <p className="text-[9px] text-muted-foreground uppercase mb-1">LLM Reassessment Summary</p>
                    <p className="text-xs text-foreground/80">{r.reassessmentSummary}</p>
                  </div>
                )}
                {r.coverageGaps && (
                  <div>
                    <p className="text-[9px] text-muted-foreground uppercase mb-1">Coverage Gaps</p>
                    <pre className="text-[10px] text-foreground/70 bg-muted/20 p-2 rounded overflow-x-auto max-h-40">
                      {JSON.stringify(r.coverageGaps, null, 2)}
                    </pre>
                  </div>
                )}
                {r.templateImprovements && (
                  <div>
                    <p className="text-[9px] text-muted-foreground uppercase mb-1">Template Improvements</p>
                    <pre className="text-[10px] text-foreground/70 bg-muted/20 p-2 rounded overflow-x-auto max-h-40">
                      {JSON.stringify(r.templateImprovements, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ── Generated Templates Tab ─────────────────────────────────────────────────
function GeneratedTemplatesTab() {
  const [statusFilter, setStatusFilter] = useState<string | undefined>(undefined);
  const { data: templates, isLoading, refetch } = trpc.scanforge.generatedTemplates.useQuery(
    statusFilter ? { status: statusFilter as any, limit: 100 } : { limit: 100 }
  );
  const promoteMutation = trpc.scanforge.promoteGeneratedTemplate.useMutation({
    onSuccess: () => { toast.success("Template promoted to production"); refetch(); },
    onError: (err) => toast.error(sanitizeErrorForToast(err.message)),
  });

  const statusColors: Record<string, string> = {
    draft: "text-gray-400 bg-gray-500/10 border-gray-500/30",
    review: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
    approved: "text-green-400 bg-green-500/10 border-green-500/30",
    rejected: "text-red-400 bg-red-500/10 border-red-500/30",
    promoted: "text-primary bg-primary/10 border-primary/30",
  };

  if (isLoading) {
    return <div className="space-y-2">{[...Array(3)].map((_, i) => <div key={i} className="h-16 bg-muted/20 rounded animate-pulse" />)}</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <p className="text-xs text-muted-foreground flex-1">{(templates || []).length} generated templates</p>
        {["draft", "review", "approved", "rejected", "promoted"].map(s => (
          <Button key={s} variant={statusFilter === s ? "default" : "outline"} size="sm"
            className="text-[10px] h-6 px-2" onClick={() => setStatusFilter(statusFilter === s ? undefined : s)}>
            {s}
          </Button>
        ))}
      </div>

      <ScrollArea className="h-[600px]">
        <div className="space-y-2 pr-2">
          {(templates || []).map((t: any) => (
            <Card key={t.id} className="bg-card/80 border-border/50">
              <CardContent className="p-3">
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge variant="outline" className={`text-[10px] ${statusColors[t.status] || ""}`}>
                        {t.status}
                      </Badge>
                      <Badge variant="outline" className="text-[10px] text-muted-foreground border-border">
                        {t.generationSource?.replace(/_/g, " ")}
                      </Badge>
                      {t.generationConfidence != null && (
                        <span className="text-[10px] text-muted-foreground">
                          Confidence: {pct(t.generationConfidence)}
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-foreground font-medium truncate">{t.name}</p>
                    <p className="text-[10px] text-muted-foreground font-mono truncate">{t.templateId}</p>
                    {t.sourceReference && (
                      <p className="text-[10px] text-muted-foreground mt-0.5">Source: {t.sourceReference}</p>
                    )}
                    {t.reviewNotes && (
                      <p className="text-[10px] text-foreground/70 mt-1 italic">{t.reviewNotes}</p>
                    )}
                  </div>
                  {(t.status === "draft" || t.status === "approved") && (
                    <Button variant="outline" size="sm" className="text-[10px] h-6 text-primary border-primary/30"
                      onClick={() => promoteMutation.mutate({ templateId: t.templateId })}
                      disabled={promoteMutation.isPending}>
                      <Rocket className="h-3 w-3 mr-1" /> Promote
                    </Button>
                  )}
                </div>
                <div className="flex items-center gap-2 mt-1 text-[10px] text-muted-foreground">
                  <Clock className="h-3 w-3" />
                  {t.createdAt ? new Date(t.createdAt).toLocaleString() : "—"}
                </div>
              </CardContent>
            </Card>
          ))}
          {(templates || []).length === 0 && (
            <Card className="bg-card/80 border-border/50">
              <CardContent className="py-12 text-center">
                <Sparkles className="h-8 w-8 text-muted-foreground mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">No generated templates yet.</p>
                <p className="text-xs text-muted-foreground mt-1">The deep research agent generates templates from TI feeds and missed findings.</p>
              </CardContent>
            </Card>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}

// ── Research Activity Tab ───────────────────────────────────────────────────
function ResearchActivityTab() {
  const [feedFilter, setFeedFilter] = useState<string | undefined>(undefined);
  const { data: logs, isLoading } = trpc.scanforge.researchLog.useQuery(
    feedFilter ? { feedSource: feedFilter, limit: 200 } : { limit: 200 }
  );

  const feedSources = useMemo(() => {
    if (!logs) return [];
    const sources = new Set(logs.map((l: any) => l.feedSource));
    return Array.from(sources).sort();
  }, [logs]);

  const feedIcons: Record<string, React.ReactNode> = {
    nvd: <Database className="h-3 w-3 text-blue-400" />,
    hackerone: <Bug className="h-3 w-3 text-green-400" />,
    shodan: <Eye className="h-3 w-3 text-orange-400" />,
    censys: <Search className="h-3 w-3 text-purple-400" />,
    spicy_tip: <Skull className="h-3 w-3 text-red-400" />,
    abuse_ch: <Shield className="h-3 w-3 text-yellow-400" />,
    cisa_kev: <AlertTriangle className="h-3 w-3 text-red-400" />,
    securitytrails: <Crosshair className="h-3 w-3 text-cyan-400" />,
    urlscan: <ExternalLink className="h-3 w-3 text-blue-400" />,
    abuseipdb: <Target className="h-3 w-3 text-orange-400" />,
  };

  if (isLoading) {
    return <div className="space-y-2">{[...Array(5)].map((_, i) => <div key={i} className="h-12 bg-muted/20 rounded animate-pulse" />)}</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 flex-wrap">
        <p className="text-xs text-muted-foreground">{(logs || []).length} research entries</p>
        <div className="flex-1" />
        <Button variant={!feedFilter ? "default" : "outline"} size="sm" className="text-[10px] h-6 px-2"
          onClick={() => setFeedFilter(undefined)}>All</Button>
        {feedSources.map(s => (
          <Button key={s} variant={feedFilter === s ? "default" : "outline"} size="sm"
            className="text-[10px] h-6 px-2 gap-1" onClick={() => setFeedFilter(feedFilter === s ? undefined : s)}>
            {feedIcons[s] || <CircleDot className="h-3 w-3" />} {s}
          </Button>
        ))}
      </div>

      <ScrollArea className="h-[600px]">
        <div className="space-y-1.5 pr-2">
          {(logs || []).map((l: any) => (
            <div key={l.id} className="flex items-start gap-3 p-2.5 rounded bg-card/60 border border-border/30 hover:border-border/50 transition-colors">
              <div className="p-1.5 rounded bg-muted/30 mt-0.5">
                {feedIcons[l.feedSource] || <CircleDot className="h-3 w-3 text-muted-foreground" />}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-xs font-medium text-foreground truncate">{l.researchSubject}</span>
                  {l.actionable && (
                    <Badge variant="outline" className="text-[9px] text-green-400 border-green-500/30">Actionable</Badge>
                  )}
                </div>
                <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                  <span className="uppercase">{l.feedSource}</span>
                  <span>·</span>
                  <span>{l.researchType?.replace(/_/g, " ")}</span>
                  <span>·</span>
                  <span>{l.createdAt ? new Date(l.createdAt).toLocaleString() : "—"}</span>
                </div>
                {l.generatedTemplateIds && Array.isArray(l.generatedTemplateIds) && l.generatedTemplateIds.length > 0 && (
                  <div className="flex items-center gap-1 mt-1">
                    <Sparkles className="h-3 w-3 text-purple-400" />
                    <span className="text-[10px] text-purple-400">{l.generatedTemplateIds.length} template(s) generated</span>
                  </div>
                )}
              </div>
            </div>
          ))}
          {(logs || []).length === 0 && (
            <div className="text-center py-12">
              <Microscope className="h-8 w-8 text-muted-foreground mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">No research activity yet.</p>
              <p className="text-xs text-muted-foreground mt-1">The deep research agent analyzes TI feeds after engagements.</p>
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}

// ── Auto-Promotion Tab ────────────────────────────────────────────────────
function AutoPromotionTab() {
  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = trpc.scanforge.getPromotionStats.useQuery();
  const { data: history, isLoading: historyLoading, refetch: refetchHistory } = trpc.scanforge.getPromotionHistory.useQuery({ limit: 50 });
  const { data: rules } = trpc.scanforge.getPromotionRules.useQuery();
  const runPromotion = trpc.scanforge.runAutoPromotion.useMutation({
    onSuccess: (data) => {
      toast.success(`Evaluated ${data.evaluated} templates: ${data.promoted} promoted, ${data.deferred} deferred, ${data.rejected} rejected`);
      refetchStats();
      refetchHistory();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err.message)),
  });
  const manualPromote = trpc.scanforge.manualPromoteTemplate.useMutation({
    onSuccess: () => { toast.success("Template promoted"); refetchStats(); refetchHistory(); },
    onError: (err) => toast.error(sanitizeErrorForToast(err.message)),
  });
  const manualReject = trpc.scanforge.manualRejectTemplate.useMutation({
    onSuccess: () => { toast.success("Template rejected"); refetchStats(); refetchHistory(); },
    onError: (err) => toast.error(sanitizeErrorForToast(err.message)),
  });

  const [showRules, setShowRules] = useState(false);

  if (statsLoading || historyLoading) {
    return <div className="space-y-2">{[...Array(4)].map((_, i) => <div key={i} className="h-16 bg-muted/20 rounded animate-pulse" />)}</div>;
  }

  const s = stats || { totalEvaluated: 0, promoted: 0, deferred: 0, rejected: 0, pendingReview: 0, avgPrecisionAtPromotion: 0, avgF1AtPromotion: 0 };
  const defaultRules = rules?.default;
  const fastTrackRules = rules?.fastTrack;

  return (
    <div className="space-y-6">
      {/* Action Bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <Button size="sm" className="text-xs gap-1.5" onClick={() => runPromotion.mutate({ fastTrack: false })}
          disabled={runPromotion.isPending}>
          <Rocket className="h-3.5 w-3.5" /> {runPromotion.isPending ? "Evaluating..." : "Run Auto-Promotion"}
        </Button>
        <Button size="sm" variant="outline" className="text-xs gap-1.5 border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10"
          onClick={() => runPromotion.mutate({ fastTrack: true })} disabled={runPromotion.isPending}>
          <Zap className="h-3.5 w-3.5" /> Fast-Track Evaluation
        </Button>
        <div className="flex-1" />
        <Button size="sm" variant="ghost" className="text-[10px] gap-1" onClick={() => setShowRules(!showRules)}>
          {showRules ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
          {showRules ? "Hide Rules" : "Show Rules"}
        </Button>
      </div>

      {/* Promotion KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
        <MetricCard label="Total Evaluated" value={s.totalEvaluated} icon={<Activity className="h-4 w-4 text-blue-400" />} color="text-blue-400" />
        <MetricCard label="Promoted" value={s.promoted} icon={<Rocket className="h-4 w-4 text-green-400" />} color="text-green-400" />
        <MetricCard label="Deferred" value={s.deferred} icon={<Clock className="h-4 w-4 text-yellow-400" />} color="text-yellow-400" />
        <MetricCard label="Rejected" value={s.rejected} icon={<XCircle className="h-4 w-4 text-red-400" />} color="text-red-400" />
        <MetricCard label="Pending Review" value={s.pendingReview} icon={<Eye className="h-4 w-4 text-orange-400" />} color="text-orange-400" />
        <MetricCard label="Avg Precision" value={pct(s.avgPrecisionAtPromotion)} subtitle="at promotion"
          icon={<Target className="h-4 w-4 text-emerald-400" />} color="text-emerald-400" />
        <MetricCard label="Avg F1" value={pct(s.avgF1AtPromotion)} subtitle="at promotion"
          icon={<Gauge className="h-4 w-4 text-primary" />} color="text-primary" />
      </div>

      {/* Promotion Rules (Collapsible) */}
      {showRules && defaultRules && fastTrackRules && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[{ title: "Default Rules", rules: defaultRules, color: "text-primary" }, { title: "Fast-Track Rules", rules: fastTrackRules, color: "text-yellow-400" }].map(({ title, rules: r, color }) => (
            <Card key={title} className="bg-card/80 border-border/50">
              <CardHeader className="pb-2">
                <CardTitle className={`text-sm flex items-center gap-2 ${color}`}>
                  {title === "Default Rules" ? <Shield className="h-4 w-4" /> : <Zap className="h-4 w-4" />} {title}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="flex justify-between"><span className="text-muted-foreground">Min Engagements</span><span className="font-mono">{r.minEngagements}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Min Total Scans</span><span className="font-mono">{r.minTotalScans}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Min Precision</span><span className="font-mono">{pct(r.minPrecision)}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Min Recall</span><span className="font-mono">{pct(r.minRecall)}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Min F1 Score</span><span className="font-mono">{pct(r.minF1Score)}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Max FP Rate</span><span className="font-mono">{pct(r.maxFalsePositiveRate)}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Min Effectiveness</span><span className="font-mono">{r.minEffectivenessScore}/100</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Min Confidence</span><span className="font-mono">{pct(r.minGenerationConfidence)}</span></div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Promotion History */}
      <Card className="bg-card/80 border-border/50">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <GitMerge className="h-4 w-4 text-primary" /> Promotion History
          </CardTitle>
          <CardDescription className="text-xs">
            Chronological log of all promotion evaluations with decision rationale
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[400px]">
            <div className="space-y-2 pr-2">
              {(history || []).map((h: any) => {
                const decisionColor = h.decision === "promoted" ? "text-green-400 bg-green-500/10 border-green-500/30"
                  : h.decision === "rejected" ? "text-red-400 bg-red-500/10 border-red-500/30"
                  : "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
                const decisionIcon = h.decision === "promoted" ? <Rocket className="h-3 w-3" />
                  : h.decision === "rejected" ? <XCircle className="h-3 w-3" />
                  : <Clock className="h-3 w-3" />;
                const snap = h.metricsSnapshot as any;
                return (
                  <div key={h.id} className="p-3 rounded bg-card/60 border border-border/30 hover:border-border/50 transition-colors">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge variant="outline" className={`text-[10px] gap-1 ${decisionColor}`}>
                            {decisionIcon} {h.decision?.toUpperCase()}
                          </Badge>
                          <span className="text-xs font-mono text-foreground truncate">{h.templateId}</span>
                          <Badge variant="outline" className="text-[9px] text-muted-foreground">
                            {h.previousStatus} → {h.newStatus}
                          </Badge>
                        </div>
                        <p className="text-[11px] text-muted-foreground leading-relaxed">{h.reason}</p>
                        {snap && (
                          <div className="flex items-center gap-3 mt-1.5 text-[10px]">
                            <span className="text-green-400">P: {pct(snap.precision || 0)}</span>
                            <span className="text-blue-400">R: {pct(snap.recall || 0)}</span>
                            <span className="text-primary">F1: {pct(snap.f1Score || 0)}</span>
                            <span className="text-muted-foreground">Scans: {snap.totalScans || 0}</span>
                            <span className="text-muted-foreground">Engagements: {snap.engagementCount || 0}</span>
                          </div>
                        )}
                      </div>
                      <div className="text-[10px] text-muted-foreground whitespace-nowrap">
                        {h.evaluatedBy === "auto" ? (
                          <Badge variant="outline" className="text-[9px] text-blue-400 border-blue-500/30 gap-1">
                            <Cpu className="h-2.5 w-2.5" /> Auto
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-[9px] text-purple-400 border-purple-500/30 gap-1">
                            <Brain className="h-2.5 w-2.5" /> Manual
                          </Badge>
                        )}
                        <p className="mt-1 text-right">{h.createdAt ? new Date(h.createdAt).toLocaleString() : "—"}</p>
                      </div>
                    </div>
                  </div>
                );
              })}
              {(history || []).length === 0 && (
                <div className="text-center py-12">
                  <Rocket className="h-8 w-8 text-muted-foreground mx-auto mb-3" />
                  <p className="text-sm text-muted-foreground">No promotion history yet.</p>
                  <p className="text-xs text-muted-foreground mt-1">Run auto-promotion or manually promote templates to see history here.</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}

// ── Main Dashboard ──────────────────────────────────────────────────────────
export default function ScanForgeDashboard() {
  const [activeTab, setActiveTab] = useState("overview");

  return (
    <AppShell>
      <div className="flex flex-col h-full">
        {/* Header */}
        <div className="flex-none border-b border-border/50 bg-card/30 px-6 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-lg font-bold text-foreground flex items-center gap-2">
                <FlaskConical className="h-5 w-5 text-primary" />
                ScanForge Analytics
              </h1>
              <p className="text-xs text-muted-foreground mt-0.5">
                Self-improving vulnerability scanner — accuracy metrics, template performance, and TI research activity
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-[10px] text-primary border-primary/30 gap-1">
                <Cpu className="h-3 w-3" /> Engine Active
              </Badge>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex-1 overflow-hidden">
          <Tabs value={activeTab} onValueChange={setActiveTab} className="h-full flex flex-col">
            <div className="flex-none border-b border-border/50 px-6">
              <TabsList className="bg-transparent h-10 gap-1">
                <TabsTrigger value="overview" className="text-xs data-[state=active]:bg-primary/10 data-[state=active]:text-primary gap-1">
                  <Activity className="h-3.5 w-3.5" /> Overview
                </TabsTrigger>
                <TabsTrigger value="templates" className="text-xs data-[state=active]:bg-primary/10 data-[state=active]:text-primary gap-1">
                  <Layers className="h-3.5 w-3.5" /> Template Performance
                </TabsTrigger>
                <TabsTrigger value="engagements" className="text-xs data-[state=active]:bg-primary/10 data-[state=active]:text-primary gap-1">
                  <BarChart3 className="h-3.5 w-3.5" /> Engagement Reports
                </TabsTrigger>
                <TabsTrigger value="generated" className="text-xs data-[state=active]:bg-primary/10 data-[state=active]:text-primary gap-1">
                  <Sparkles className="h-3.5 w-3.5" /> Generated Templates
                </TabsTrigger>
                <TabsTrigger value="research" className="text-xs data-[state=active]:bg-primary/10 data-[state=active]:text-primary gap-1">
                  <Microscope className="h-3.5 w-3.5" /> Research Activity
                </TabsTrigger>
                <TabsTrigger value="promotion" className="text-xs data-[state=active]:bg-primary/10 data-[state=active]:text-primary gap-1">
                  <Rocket className="h-3.5 w-3.5" /> Auto-Promotion
                </TabsTrigger>
              </TabsList>
            </div>
            <div className="flex-1 overflow-auto">
              <div className="p-6">
                <TabsContent value="overview" className="mt-0"><OverviewTab /></TabsContent>
                <TabsContent value="templates" className="mt-0"><TemplatePerformanceTab /></TabsContent>
                <TabsContent value="engagements" className="mt-0"><EngagementReportsTab /></TabsContent>
                <TabsContent value="generated" className="mt-0"><GeneratedTemplatesTab /></TabsContent>
                <TabsContent value="research" className="mt-0"><ResearchActivityTab /></TabsContent>
                <TabsContent value="promotion" className="mt-0"><AutoPromotionTab /></TabsContent>
              </div>
            </div>
          </Tabs>
        </div>
      </div>
    </AppShell>
  );
}
