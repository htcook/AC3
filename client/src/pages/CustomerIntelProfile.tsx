/**
 * Customer Intelligence Profile Page
 * 
 * Displays cumulative cross-engagement intelligence for a customer:
 *   - Overall posture score and grade with trend
 *   - Findings distribution over time
 *   - Recurring weakness patterns
 *   - Technology stack changes
 *   - Attack surface size trending
 *   - Strategic recommendations
 *   - Persistent intelligence gaps
 */

import { useState, useMemo } from "react";
import { useRoute, Link } from "wouter";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Shield, ShieldCheck, ShieldAlert, ShieldX,
  TrendingUp, TrendingDown, Minus, ArrowLeft,
  AlertTriangle, CheckCircle2, Target, Activity,
  Server, Globe, Layers, BarChart3, Lightbulb,
  Clock, ChevronRight, Cpu, Eye, XCircle,
  ArrowUpRight, ArrowDownRight,
} from "lucide-react";

// ── Grade Display ──────────────────────────────────────────────────────────

function PostureGradeCard({ score, grade, trend }: {
  score: number | null;
  grade: string | null;
  trend: string | null;
}) {
  const gradeColors: Record<string, string> = {
    A: "text-emerald-400 border-emerald-500/30 bg-emerald-500/5",
    B: "text-blue-400 border-blue-500/30 bg-blue-500/5",
    C: "text-yellow-400 border-yellow-500/30 bg-yellow-500/5",
    D: "text-orange-400 border-orange-500/30 bg-orange-500/5",
    F: "text-red-400 border-red-500/30 bg-red-500/5",
  };

  const trendIcon = trend === "improving"
    ? <TrendingUp className="h-4 w-4 text-emerald-400" />
    : trend === "declining"
      ? <TrendingDown className="h-4 w-4 text-red-400" />
      : <Minus className="h-4 w-4 text-zinc-400" />;

  const trendLabel = trend === "improving" ? "Improving" : trend === "declining" ? "Declining" : "Stable";

  if (score === null) {
    return (
      <Card className="border-zinc-700/50 bg-zinc-900/50">
        <CardContent className="p-6 text-center">
          <div className="text-zinc-500 text-sm">No assessment data yet</div>
          <div className="text-zinc-600 text-xs mt-1">Complete an engagement to generate posture score</div>
        </CardContent>
      </Card>
    );
  }

  const g = grade || "F";
  const colorClass = gradeColors[g] || gradeColors.F;

  return (
    <Card className={`border ${colorClass}`}>
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-xs uppercase tracking-wider text-zinc-400 mb-1">Overall Posture</div>
            <div className="flex items-baseline gap-3">
              <span className={`text-5xl font-bold ${colorClass.split(" ")[0]}`}>{g}</span>
              <span className="text-2xl text-zinc-300">{score}/100</span>
            </div>
          </div>
          <div className="text-right">
            <div className="flex items-center gap-1.5 text-sm">
              {trendIcon}
              <span className="text-zinc-300">{trendLabel}</span>
            </div>
            <Progress value={score} className="w-32 mt-2 h-2" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Stats Row ──────────────────────────────────────────────────────────────

function StatCard({ icon, label, value, sublabel, color }: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  sublabel?: string;
  color?: string;
}) {
  return (
    <div className="bg-zinc-900/50 border border-zinc-700/40 rounded-lg p-3 flex-1 min-w-[140px]">
      <div className="flex items-center gap-2 mb-1">
        {icon}
        <span className="text-[10px] uppercase tracking-wider text-zinc-400">{label}</span>
      </div>
      <div className={`text-xl font-bold ${color || "text-zinc-200"}`}>{value}</div>
      {sublabel && <div className="text-[10px] text-zinc-500 mt-0.5">{sublabel}</div>}
    </div>
  );
}

// ── Findings Distribution ──────────────────────────────────────────────────

function FindingsDistribution({ critical, high, medium, low }: {
  critical: number; high: number; medium: number; low: number;
}) {
  const total = critical + high + medium + low;
  if (total === 0) return <div className="text-zinc-500 text-xs">No findings recorded</div>;

  const bars = [
    { label: "Critical", count: critical, color: "bg-red-500", textColor: "text-red-400" },
    { label: "High", count: high, color: "bg-orange-500", textColor: "text-orange-400" },
    { label: "Medium", count: medium, color: "bg-yellow-500", textColor: "text-yellow-400" },
    { label: "Low", count: low, color: "bg-blue-500", textColor: "text-blue-400" },
  ];

  return (
    <div className="space-y-2">
      {bars.map((b) => (
        <div key={b.label} className="flex items-center gap-3">
          <span className={`text-[10px] w-14 text-right ${b.textColor}`}>{b.label}</span>
          <div className="flex-1 h-4 bg-zinc-800 rounded overflow-hidden">
            <div
              className={`h-full ${b.color} rounded transition-all`}
              style={{ width: `${Math.max((b.count / total) * 100, b.count > 0 ? 2 : 0)}%` }}
            />
          </div>
          <span className="text-xs text-zinc-300 w-10 text-right font-mono">{b.count}</span>
        </div>
      ))}
    </div>
  );
}

// ── Posture Trend Chart (simple text-based) ────────────────────────────────

function PostureTrendList({ data }: {
  data: Array<{ date: string; score: number; engagementId?: number }>;
}) {
  if (data.length === 0) {
    return <div className="text-zinc-500 text-xs">No trend data available</div>;
  }

  return (
    <div className="space-y-1.5">
      {data.slice(-10).map((d, i) => {
        const prev = i > 0 ? data[i - 1].score : d.score;
        const delta = d.score - prev;
        return (
          <div key={i} className="flex items-center gap-2 text-xs">
            <span className="text-zinc-500 w-20 font-mono text-[10px]">
              {new Date(d.date).toLocaleDateString()}
            </span>
            <div className="flex-1 h-3 bg-zinc-800 rounded overflow-hidden">
              <div
                className={`h-full rounded ${d.score >= 80 ? "bg-emerald-500" : d.score >= 60 ? "bg-yellow-500" : "bg-red-500"}`}
                style={{ width: `${d.score}%` }}
              />
            </div>
            <span className="text-zinc-300 w-10 text-right font-mono">{d.score}</span>
            {i > 0 && (
              <span className={`w-10 text-right font-mono text-[10px] ${delta > 0 ? "text-emerald-400" : delta < 0 ? "text-red-400" : "text-zinc-500"}`}>
                {delta > 0 ? "+" : ""}{delta.toFixed(1)}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Recurring Weaknesses ───────────────────────────────────────────────────

function RecurringWeaknessesList({ weaknesses }: {
  weaknesses: Array<{ category: string; count: number; lastSeen: string; trend: string }>;
}) {
  if (weaknesses.length === 0) {
    return <div className="text-zinc-500 text-xs">No recurring weaknesses detected</div>;
  }

  const sorted = [...weaknesses].sort((a, b) => b.count - a.count);

  return (
    <div className="space-y-2">
      {sorted.map((w) => (
        <div key={w.category} className="flex items-center gap-2 p-2 bg-zinc-800/50 rounded border border-zinc-700/30">
          <div className="flex-1">
            <div className="text-xs text-zinc-200">{w.category}</div>
            <div className="text-[10px] text-zinc-500">
              Last seen: {new Date(w.lastSeen).toLocaleDateString()} · {w.count} occurrence{w.count !== 1 ? "s" : ""}
            </div>
          </div>
          <Badge variant="outline" className={
            w.trend === "persistent" ? "border-red-500/30 text-red-400 text-[10px]" :
            w.trend === "recurring" ? "border-orange-500/30 text-orange-400 text-[10px]" :
            "border-zinc-600 text-zinc-400 text-[10px]"
          }>
            {w.trend}
          </Badge>
          <span className="text-lg font-bold text-zinc-300 w-8 text-center">{w.count}</span>
        </div>
      ))}
    </div>
  );
}

// ── Technology Stack ───────────────────────────────────────────────────────

function TechnologyStack({ technologies, changes }: {
  technologies: string[];
  changes: Array<{ date: string; added?: string[]; removed?: string[] }>;
}) {
  if (technologies.length === 0 && changes.length === 0) {
    return <div className="text-zinc-500 text-xs">No technology data collected</div>;
  }

  return (
    <div className="space-y-3">
      {technologies.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {technologies.map((t) => (
            <Badge key={t} variant="outline" className="border-cyan-500/30 text-cyan-400 text-[10px]">
              <Cpu className="h-2.5 w-2.5 mr-1" />
              {t}
            </Badge>
          ))}
        </div>
      )}
      {changes.length > 0 && (
        <div className="space-y-1.5 mt-2">
          <div className="text-[10px] uppercase tracking-wider text-zinc-400">Recent Changes</div>
          {changes.slice(-5).reverse().map((c, i) => (
            <div key={i} className="text-[10px] flex items-start gap-2 p-1.5 bg-zinc-800/30 rounded">
              <span className="text-zinc-500 font-mono w-16 shrink-0">
                {new Date(c.date).toLocaleDateString()}
              </span>
              <div className="flex flex-wrap gap-1">
                {c.added?.map((a) => (
                  <span key={a} className="text-emerald-400">+{a}</span>
                ))}
                {c.removed?.map((r) => (
                  <span key={r} className="text-red-400">-{r}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Attack Surface Trend ───────────────────────────────────────────────────

function AttackSurfaceTrend({ data }: {
  data: Array<{ date: string; hosts: number; services: number; exposedPorts: number }>;
}) {
  if (data.length === 0) {
    return <div className="text-zinc-500 text-xs">No attack surface data</div>;
  }

  const latest = data[data.length - 1];
  const prev = data.length >= 2 ? data[data.length - 2] : null;

  function TrendArrow({ current, previous }: { current: number; previous: number | null }) {
    if (previous === null) return null;
    const delta = current - previous;
    if (delta > 0) return <ArrowUpRight className="h-3 w-3 text-red-400" />;
    if (delta < 0) return <ArrowDownRight className="h-3 w-3 text-emerald-400" />;
    return <Minus className="h-3 w-3 text-zinc-500" />;
  }

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-2">
        <div className="bg-zinc-800/50 rounded p-2 text-center">
          <div className="text-[10px] text-zinc-400">Hosts</div>
          <div className="text-lg font-bold text-zinc-200 flex items-center justify-center gap-1">
            {latest.hosts}
            <TrendArrow current={latest.hosts} previous={prev?.hosts ?? null} />
          </div>
        </div>
        <div className="bg-zinc-800/50 rounded p-2 text-center">
          <div className="text-[10px] text-zinc-400">Services</div>
          <div className="text-lg font-bold text-zinc-200 flex items-center justify-center gap-1">
            {latest.services}
            <TrendArrow current={latest.services} previous={prev?.services ?? null} />
          </div>
        </div>
        <div className="bg-zinc-800/50 rounded p-2 text-center">
          <div className="text-[10px] text-zinc-400">Exposed Ports</div>
          <div className="text-lg font-bold text-zinc-200 flex items-center justify-center gap-1">
            {latest.exposedPorts}
            <TrendArrow current={latest.exposedPorts} previous={prev?.exposedPorts ?? null} />
          </div>
        </div>
      </div>
      {data.length > 1 && (
        <div className="space-y-1">
          {data.slice(-5).map((d, i) => (
            <div key={i} className="flex items-center gap-2 text-[10px]">
              <span className="text-zinc-500 font-mono w-20">{new Date(d.date).toLocaleDateString()}</span>
              <span className="text-zinc-300">{d.hosts}h</span>
              <span className="text-zinc-500">·</span>
              <span className="text-zinc-300">{d.services}s</span>
              <span className="text-zinc-500">·</span>
              <span className="text-zinc-300">{d.exposedPorts}p</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Strategic Recommendations ──────────────────────────────────────────────

function StrategicRecommendations({ recommendations }: {
  recommendations: Array<{ priority: string; title: string; rationale: string; effort: string; impact: string }>;
}) {
  if (recommendations.length === 0) {
    return <div className="text-zinc-500 text-xs">No strategic recommendations generated yet</div>;
  }

  const priorityColors: Record<string, string> = {
    critical: "border-red-500/30 bg-red-500/5",
    high: "border-orange-500/30 bg-orange-500/5",
    medium: "border-yellow-500/30 bg-yellow-500/5",
    low: "border-blue-500/30 bg-blue-500/5",
  };

  const priorityBadge: Record<string, string> = {
    critical: "border-red-500/40 text-red-400",
    high: "border-orange-500/40 text-orange-400",
    medium: "border-yellow-500/40 text-yellow-400",
    low: "border-blue-500/40 text-blue-400",
  };

  return (
    <div className="space-y-2">
      {recommendations.map((r, i) => (
        <div key={i} className={`border rounded-lg p-3 ${priorityColors[r.priority] || priorityColors.medium}`}>
          <div className="flex items-start gap-2">
            <Lightbulb className="h-4 w-4 text-amber-400 mt-0.5 shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-medium text-zinc-200">{r.title}</span>
                <Badge variant="outline" className={`text-[9px] ${priorityBadge[r.priority] || ""}`}>
                  {r.priority}
                </Badge>
              </div>
              <p className="text-[10px] text-zinc-400 leading-relaxed">{r.rationale}</p>
              <div className="flex items-center gap-4 mt-1.5 text-[10px]">
                <span className="text-zinc-500">Effort: <span className="text-zinc-300">{r.effort}</span></span>
                <span className="text-zinc-500">Impact: <span className="text-zinc-300">{r.impact}</span></span>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Main Page Component ────────────────────────────────────────────────────

export default function CustomerIntelProfile() {
  const [, params] = useRoute("/customer-intel/:customerId");
  const customerId = params?.customerId || "";

  const profileQ = trpc.customerIntelProfile.getProfile.useQuery(
    { customerId, customerName: customerId },
    { enabled: !!customerId }
  );

  const profile = profileQ.data?.profile;

  if (!customerId) {
    return (
      <AppShell>
        <div className="p-6">
          <div className="text-zinc-400">No customer ID provided</div>
        </div>
      </AppShell>
    );
  }

  if (profileQ.isLoading) {
    return (
      <AppShell>
        <div className="p-6 flex items-center gap-2 text-zinc-400">
          <Activity className="h-4 w-4 animate-spin" />
          Loading customer intelligence profile...
        </div>
      </AppShell>
    );
  }

  if (!profile) {
    return (
      <AppShell>
        <div className="p-6">
          <div className="text-zinc-400">No profile found for customer: {customerId}</div>
          <Link href="/engagements">
            <Button variant="outline" size="sm" className="mt-4">
              <ArrowLeft className="h-3 w-3 mr-1" /> Back to Engagements
            </Button>
          </Link>
        </div>
      </AppShell>
    );
  }

  const postureTrend = (profile.postureTrendData as any[]) || [];
  const findingsTrend = (profile.findingsTrendData as any[]) || [];
  const recurringWeaknesses = (profile.recurringWeaknesses as any[]) || [];
  const technologies = (profile.knownTechnologies as string[]) || [];
  const techChanges = (profile.technologyChanges as any[]) || [];
  const surfaceTrend = (profile.attackSurfaceTrend as any[]) || [];
  const recommendations = (profile.strategicRecommendations as any[]) || [];
  const persistentGaps = (profile.persistentGaps as any[]) || [];

  return (
    <AppShell>
      <ScrollArea className="h-[calc(100vh-64px)]">
        <div className="p-4 sm:p-6 max-w-7xl mx-auto space-y-6">
          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <Link href="/engagements">
                <Button variant="ghost" size="sm" className="text-zinc-400 hover:text-zinc-200 -ml-2 mb-1">
                  <ArrowLeft className="h-3 w-3 mr-1" /> Back
                </Button>
              </Link>
              <h1 className="text-xl font-bold text-zinc-100 flex items-center gap-2">
                <Shield className="h-5 w-5 text-cyan-400" />
                {profile.customerName || customerId}
              </h1>
              <p className="text-xs text-zinc-400 mt-0.5">
                Customer Intelligence Profile · Cross-engagement cumulative analysis
              </p>
            </div>
            <div className="flex items-center gap-2 text-[10px] text-zinc-500">
              <Clock className="h-3 w-3" />
              Last updated: {new Date(profile.lastUpdated).toLocaleString()}
            </div>
          </div>

          {/* Posture Grade */}
          <PostureGradeCard
            score={profile.overallPostureScore}
            grade={profile.postureGrade}
            trend={profile.postureTrend}
          />

          {/* Stats Row */}
          <div className="flex flex-wrap gap-3">
            <StatCard
              icon={<Target className="h-3.5 w-3.5 text-cyan-400" />}
              label="Engagements"
              value={profile.totalEngagements || 0}
              sublabel={profile.lastEngagementDate ? `Last: ${new Date(profile.lastEngagementDate).toLocaleDateString()}` : undefined}
            />
            <StatCard
              icon={<Eye className="h-3.5 w-3.5 text-purple-400" />}
              label="DI Scans"
              value={profile.totalDIScans || 0}
            />
            <StatCard
              icon={<AlertTriangle className="h-3.5 w-3.5 text-red-400" />}
              label="Total Findings"
              value={profile.totalFindings || 0}
              sublabel={`${profile.totalCritical || 0}C / ${profile.totalHigh || 0}H / ${profile.totalMedium || 0}M / ${profile.totalLow || 0}L`}
              color="text-orange-400"
            />
            <StatCard
              icon={<Globe className="h-3.5 w-3.5 text-emerald-400" />}
              label="Attack Surface"
              value={profile.attackSurfaceSize ?? "—"}
              sublabel="Total assets"
            />
            <StatCard
              icon={<XCircle className="h-3.5 w-3.5 text-amber-400" />}
              label="Open Gaps"
              value={profile.openGapsCount || 0}
              sublabel={`${profile.resolvedGapsCount || 0} resolved`}
            />
          </div>

          {/* Two-column layout */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Left Column */}
            <div className="space-y-4">
              {/* Posture Trend */}
              <Card className="border-zinc-700/50 bg-zinc-900/50">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <BarChart3 className="h-4 w-4 text-emerald-400" />
                    Posture Score Trend
                  </CardTitle>
                  <CardDescription className="text-[10px]">
                    Score progression across engagements
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <PostureTrendList data={postureTrend} />
                </CardContent>
              </Card>

              {/* Findings Distribution */}
              <Card className="border-zinc-700/50 bg-zinc-900/50">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-orange-400" />
                    Cumulative Findings Distribution
                  </CardTitle>
                  <CardDescription className="text-[10px]">
                    All-time findings by severity
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <FindingsDistribution
                    critical={profile.totalCritical || 0}
                    high={profile.totalHigh || 0}
                    medium={profile.totalMedium || 0}
                    low={profile.totalLow || 0}
                  />
                </CardContent>
              </Card>

              {/* Attack Surface */}
              <Card className="border-zinc-700/50 bg-zinc-900/50">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Globe className="h-4 w-4 text-cyan-400" />
                    Attack Surface Trend
                  </CardTitle>
                  <CardDescription className="text-[10px]">
                    Hosts, services, and exposed ports over time
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <AttackSurfaceTrend data={surfaceTrend} />
                </CardContent>
              </Card>
            </div>

            {/* Right Column */}
            <div className="space-y-4">
              {/* Recurring Weaknesses */}
              <Card className="border-zinc-700/50 bg-zinc-900/50">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-amber-400" />
                    Recurring Weakness Patterns
                  </CardTitle>
                  <CardDescription className="text-[10px]">
                    Weakness categories that appear across multiple engagements
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <RecurringWeaknessesList weaknesses={recurringWeaknesses} />
                </CardContent>
              </Card>

              {/* Technology Stack */}
              <Card className="border-zinc-700/50 bg-zinc-900/50">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Cpu className="h-4 w-4 text-purple-400" />
                    Known Technology Stack
                  </CardTitle>
                  <CardDescription className="text-[10px]">
                    Technologies observed across engagements and DI scans
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <TechnologyStack technologies={technologies} changes={techChanges} />
                </CardContent>
              </Card>

              {/* Persistent Gaps */}
              {persistentGaps.length > 0 && (
                <Card className="border-amber-500/20 bg-amber-500/5">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Eye className="h-4 w-4 text-amber-400" />
                      Persistent Intelligence Gaps
                    </CardTitle>
                    <CardDescription className="text-[10px]">
                      Gaps that recur across engagements — systemic blind spots
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-1.5">
                      {persistentGaps.map((g: any) => (
                        <div key={g.gapId} className="flex items-center gap-2 text-xs p-1.5 bg-zinc-800/30 rounded">
                          <AlertTriangle className="h-3 w-3 text-amber-400 shrink-0" />
                          <span className="text-zinc-200 flex-1">{g.title}</span>
                          <span className="text-zinc-500 text-[10px]">{g.occurrences}x</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </div>

          {/* Strategic Recommendations — Full Width */}
          <Card className="border-zinc-700/50 bg-zinc-900/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Lightbulb className="h-4 w-4 text-amber-400" />
                Strategic Recommendations
              </CardTitle>
              <CardDescription className="text-[10px]">
                Prioritized actions based on cumulative intelligence analysis
              </CardDescription>
            </CardHeader>
            <CardContent>
              <StrategicRecommendations recommendations={recommendations} />
            </CardContent>
          </Card>
        </div>
      </ScrollArea>
    </AppShell>
  );
}
