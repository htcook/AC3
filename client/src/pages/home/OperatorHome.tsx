/**
 * Operator Cockpit — Wired to Real Data
 * 
 * Your real-time command center. View live operations, active scans,
 * engagement status, and OPSEC exposure at a glance.
 * 
 * 3-column layout:
 *   Left   — Live Activity Timeline (real events from audit logs)
 *   Center — Scan Queue + Engagements (active operations)
 *   Right  — OPSEC Gauge (real score) + Campaign Advisor + Quick Launch
 */
import { useMemo, useState } from "react";
import { Link, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  ShieldAlert, Activity, Crosshair, Zap, ArrowRight, Clock,
  AlertTriangle, CheckCircle2, Target, Brain, Network, Lock,
  Scan, Globe, Play, Plus, Loader2, Radar, Eye, Briefcase,
  ChevronRight, BarChart3, RefreshCw, TrendingDown, TrendingUp,
  Radio, Shield, Flame
} from "lucide-react";

// ─── OPSEC Risk Gauge ─────────────────────────────────────────────────────────

function OpsecGauge({ score, noiseLevel, detectionChance }: {
  score: number; noiseLevel: string; detectionChance: number;
}) {
  // Score is 0-100 where 100 = fully stealthy. Invert for display (exposure = 100 - stealth)
  const exposure = 100 - Math.min(100, Math.max(0, score));
  const color = exposure > 70 ? "text-red-500" : exposure > 40 ? "text-amber-500" : "text-emerald-500";
  const label = exposure > 70 ? "HIGH RISK" : exposure > 40 ? "MODERATE" : "LOW RISK";
  const circumference = 2 * Math.PI * 45;
  const dashOffset = circumference - (exposure / 100) * circumference * 0.75;

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-28 h-28">
        <svg className="w-full h-full -rotate-[135deg]" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="45" fill="none" stroke="currentColor"
            className="text-secondary" strokeWidth="8" strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`} strokeLinecap="round" />
          <circle cx="50" cy="50" r="45" fill="none" stroke="currentColor"
            className={color} strokeWidth="8" strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
            strokeDashoffset={dashOffset} strokeLinecap="round" style={{ transition: "stroke-dashoffset 1s ease" }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-2xl font-display font-bold ${color}`}>{exposure}</span>
          <span className="text-[8px] font-display tracking-widest text-muted-foreground">{label}</span>
        </div>
      </div>
      <div className="flex items-center gap-3 text-[9px]">
        <div className="flex items-center gap-1">
          <Radio className="w-3 h-3 text-muted-foreground" />
          <span className="text-muted-foreground">Noise:</span>
          <span className={`font-display tracking-wider ${
            noiseLevel === "critical" || noiseLevel === "elevated" ? "text-red-400" :
            noiseLevel === "moderate" ? "text-amber-400" : "text-emerald-400"
          }`}>{(noiseLevel || "stealth").toUpperCase()}</span>
        </div>
        <div className="flex items-center gap-1">
          <Eye className="w-3 h-3 text-muted-foreground" />
          <span className="text-muted-foreground">Detect:</span>
          <span className={`font-display tracking-wider ${
            detectionChance > 50 ? "text-red-400" : detectionChance > 20 ? "text-amber-400" : "text-emerald-400"
          }`}>{detectionChance}%</span>
        </div>
      </div>
    </div>
  );
}

// ─── Status helpers ──────────────────────────────────────────────────────────

const SCAN_STATUS_CONFIG: Record<string, { color: string; icon: React.ComponentType<{ className?: string }>; label: string }> = {
  discovering: { color: "bg-blue-500/20 text-blue-400 border-blue-500/30", icon: Radar, label: "DISCOVERING" },
  passive_recon: { color: "bg-purple-500/20 text-purple-400 border-purple-500/30", icon: Eye, label: "RECON" },
  analyzing: { color: "bg-amber-500/20 text-amber-400 border-amber-500/30", icon: Brain, label: "ANALYZING" },
  scoring: { color: "bg-orange-500/20 text-orange-400 border-orange-500/30", icon: BarChart3, label: "SCORING" },
  recommending: { color: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30", icon: Target, label: "RECOMMENDING" },
  completed: { color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30", icon: CheckCircle2, label: "COMPLETED" },
  scan_complete: { color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30", icon: CheckCircle2, label: "SCAN COMPLETE" },
  engagement_running: { color: "bg-red-500/20 text-red-400 border-red-500/30", icon: Crosshair, label: "ENGAGEMENT" },
  failed: { color: "bg-red-500/20 text-red-400 border-red-500/30", icon: AlertTriangle, label: "FAILED" },
};

const ENGAGEMENT_STATUS_CONFIG: Record<string, { color: string; label: string }> = {
  planning: { color: "bg-blue-500/20 text-blue-400", label: "PLANNING" },
  active: { color: "bg-emerald-500/20 text-emerald-400", label: "ACTIVE" },
  completed: { color: "bg-gray-500/20 text-gray-400", label: "COMPLETED" },
  paused: { color: "bg-amber-500/20 text-amber-400", label: "PAUSED" },
};

const SEVERITY_CONFIG: Record<string, { dot: string; bg: string }> = {
  critical: { dot: "bg-red-500", bg: "bg-red-500/20 border-red-500/50" },
  high: { dot: "bg-orange-500", bg: "bg-orange-500/20 border-orange-500/50" },
  medium: { dot: "bg-amber-500", bg: "bg-amber-500/20 border-amber-500/50" },
  low: { dot: "bg-blue-500", bg: "bg-blue-500/20 border-blue-500/50" },
  info: { dot: "bg-slate-400", bg: "bg-slate-500/20 border-slate-500/50" },
};

const CATEGORY_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  scan: Scan,
  engagement: Crosshair,
  opsec: ShieldAlert,
  agent: Radio,
  system: Activity,
};

// ─── Main Component ───────────────────────────────────────────────────────────

export default function OperatorHome() {
  const [, navigate] = useLocation();
  const [timelineHours, setTimelineHours] = useState(24);

  // ── Real data queries ──
  const scansQuery = trpc.domainIntel.listScans.useQuery(undefined, {
    refetchInterval: 15000,
  });
  const engagementsQuery = trpc.engagements.list.useQuery();

  // Activity timeline from real audit logs
  const timelineQuery = trpc.operatorCockpit.activityTimeline.useQuery(
    { limit: 25, hoursBack: timelineHours },
    { refetchInterval: 30000 }
  );

  // OPSEC gauge from real engagement data
  const opsecQuery = trpc.operatorCockpit.opsecGauge.useQuery(undefined, {
    refetchInterval: 60000,
  });

  // Quick stats
  const statsQuery = trpc.operatorCockpit.quickStats.useQuery(undefined, {
    refetchInterval: 30000,
  });

  const recentScans = useMemo(() => {
    return (scansQuery.data || []).slice(0, 6);
  }, [scansQuery.data]);

  const activeEngagements = useMemo(() => {
    return (engagementsQuery.data || [])
      .filter((e: any) => e.status === "active" || e.status === "planning")
      .slice(0, 5);
  }, [engagementsQuery.data]);

  const totalScans = scansQuery.data?.length || 0;
  const runningScans = (scansQuery.data || []).filter((s: any) =>
    ["discovering", "passive_recon", "analyzing", "scoring", "recommending"].includes(s.status)
  ).length;

  const opsec = opsecQuery.data;
  const stats = statsQuery.data;
  const timeline = timelineQuery.data;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-display tracking-wider font-bold">OPERATOR COCKPIT</h1>
          <p className="text-xs text-muted-foreground mt-1">
            Real-time command center for active operations, scans, and engagement status
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link href="/domain-intel">
            <Button size="sm" className="text-[10px] font-display tracking-wider h-8 gap-1.5">
              <Plus className="w-3.5 h-3.5" />
              NEW SCAN
            </Button>
          </Link>
          <Link href="/engagements/new">
            <Button variant="outline" size="sm" className="text-[10px] font-display tracking-wider h-8 gap-1.5">
              <Briefcase className="w-3.5 h-3.5" />
              NEW ENGAGEMENT
            </Button>
          </Link>
        </div>
      </div>

      {/* ═══ 3-COLUMN LAYOUT ═══ */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">

        {/* ─── LEFT: Live Activity Timeline ─────────────────────────────── */}
        <div className="xl:col-span-3 space-y-4">
          <Card className="h-full">
            <CardHeader className="pb-2 pt-4 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-display tracking-widest flex items-center gap-2">
                  <Activity className="w-3.5 h-3.5 text-primary" />
                  LIVE ACTIVITY
                  {timeline && timeline.totalCount > 0 && (
                    <span className="text-[8px] bg-primary/20 text-primary border border-primary/30 px-1.5 py-0.5 rounded-full font-display tracking-widest">
                      {timeline.totalCount}
                    </span>
                  )}
                </CardTitle>
                <div className="flex items-center gap-1">
                  {[24, 72, 168].map(h => (
                    <button
                      key={h}
                      onClick={() => setTimelineHours(h)}
                      className={`text-[8px] font-display tracking-wider px-1.5 py-0.5 rounded transition-colors ${
                        timelineHours === h ? "bg-primary/20 text-primary" : "text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      {h === 24 ? "24H" : h === 72 ? "3D" : "7D"}
                    </button>
                  ))}
                </div>
              </div>
            </CardHeader>
            <CardContent className="px-4 pb-4">
              {timelineQuery.isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                </div>
              ) : !timeline || timeline.events.length === 0 ? (
                <div className="text-center py-8">
                  <Activity className="w-6 h-6 text-muted-foreground/40 mx-auto mb-2" />
                  <p className="text-[10px] text-muted-foreground">No activity in the last {timelineHours}h</p>
                  <p className="text-[9px] text-muted-foreground/60 mt-1">Start a scan or engagement to see events here</p>
                </div>
              ) : (
                <div className="relative">
                  {/* Timeline spine */}
                  <div className="absolute left-[7px] top-0 bottom-0 w-px bg-border" />
                  <div className="space-y-0">
                    {timeline.events.map((event) => {
                      const sevCfg = SEVERITY_CONFIG[event.severity] || SEVERITY_CONFIG.info;
                      const CatIcon = CATEGORY_ICONS[event.category] || Activity;
                      const timeAgo = getTimeAgo(new Date(event.timestamp));

                      return (
                        <div key={event.id} className="flex items-start gap-3 py-2 pl-0 relative group">
                          <TooltipProvider delayDuration={200}>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <div className={`w-[15px] h-[15px] rounded-full shrink-0 z-10 flex items-center justify-center border ${sevCfg.bg}`}>
                                  <div className={`w-[5px] h-[5px] rounded-full ${sevCfg.dot}`} />
                                </div>
                              </TooltipTrigger>
                              <TooltipContent side="right" className="text-[10px] max-w-[200px]">
                                <p className="font-medium">{event.category.toUpperCase()} — {event.severity.toUpperCase()}</p>
                                <p className="text-muted-foreground mt-1">{event.description}</p>
                              </TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                          <div className="flex-1 min-w-0 -mt-0.5">
                            <div className="flex items-center gap-2">
                              <CatIcon className="w-3 h-3 text-muted-foreground shrink-0" />
                              <span className="text-[10px] font-display tracking-wider font-medium truncate">{event.title}</span>
                              <span className="text-[9px] text-muted-foreground/60 font-mono shrink-0">{timeAgo}</span>
                            </div>
                            <p className="text-[10px] text-muted-foreground truncate mt-0.5">{event.description}</p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* ─── CENTER: Scan Queue + Engagements ─────────────────────────── */}
        <div className="xl:col-span-5 space-y-4">
          {/* Scan Queue */}
          <Card>
            <CardHeader className="pb-2 pt-4 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-display tracking-widest flex items-center gap-2">
                  <Scan className="w-3.5 h-3.5 text-primary" />
                  SCAN QUEUE
                  {runningScans > 0 && (
                    <span className="text-[8px] bg-blue-500/20 text-blue-400 border border-blue-500/30 px-1.5 py-0.5 rounded-full font-display tracking-widest animate-pulse">
                      {runningScans} LIVE
                    </span>
                  )}
                </CardTitle>
                <div className="flex items-center gap-2">
                  <span className="text-[9px] text-muted-foreground font-display tracking-wider">{totalScans} total</span>
                  <Link href="/domain-intel">
                    <Button variant="ghost" size="sm" className="text-[9px] font-display tracking-wider h-6 px-2">
                      ALL <ArrowRight className="w-3 h-3 ml-1" />
                    </Button>
                  </Link>
                </div>
              </div>
            </CardHeader>
            <CardContent className="px-4 pb-4 space-y-1.5">
              {scansQuery.isLoading ? (
                <div className="flex items-center justify-center py-6">
                  <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                </div>
              ) : recentScans.length === 0 ? (
                <div className="text-center py-6">
                  <Globe className="w-6 h-6 text-muted-foreground/40 mx-auto mb-2" />
                  <p className="text-[10px] text-muted-foreground">No scans yet</p>
                  <Link href="/domain-intel">
                    <Button variant="outline" size="sm" className="mt-2 text-[9px] font-display tracking-wider h-6 gap-1">
                      <Plus className="w-3 h-3" /> START SCAN
                    </Button>
                  </Link>
                </div>
              ) : (
                recentScans.map((scan: any) => {
                  const statusCfg = SCAN_STATUS_CONFIG[scan.status] || SCAN_STATUS_CONFIG.discovering;
                  const StatusIcon = statusCfg.icon;
                  const isRunning = ["discovering", "passive_recon", "analyzing", "scoring", "recommending"].includes(scan.status);
                  const updatedAt = scan.updatedAt ? new Date(scan.updatedAt) : new Date(scan.createdAt);

                  return (
                    <div
                      key={scan.id}
                      className="flex items-center gap-2.5 p-2.5 rounded-lg bg-secondary/20 hover:bg-secondary/40 cursor-pointer transition-colors group"
                      onClick={() => navigate(`/domain-intel/${scan.id}`)}
                    >
                      <div className={`w-7 h-7 rounded flex items-center justify-center shrink-0 border ${statusCfg.color}`}>
                        <StatusIcon className={`w-3.5 h-3.5 ${isRunning ? "animate-pulse" : ""}`} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-display tracking-wider font-medium truncate">
                            {scan.primaryDomain}
                          </span>
                          <Badge variant="outline" className={`text-[7px] font-display tracking-widest px-1 py-0 h-3.5 border ${statusCfg.color}`}>
                            {statusCfg.label}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-[9px] text-muted-foreground">{(scan.orgProfile as any)?.customerName || scan.sector}</span>
                          <span className="text-[9px] text-muted-foreground/40">·</span>
                          <span className="text-[9px] text-muted-foreground">{getTimeAgo(updatedAt)}</span>
                        </div>
                      </div>
                      <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/30 group-hover:text-primary transition-colors shrink-0" />
                    </div>
                  );
                })
              )}
            </CardContent>
          </Card>

          {/* Active Engagements */}
          <Card>
            <CardHeader className="pb-2 pt-4 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-display tracking-widest flex items-center gap-2">
                  <Briefcase className="w-3.5 h-3.5 text-amber-400" />
                  ENGAGEMENTS
                </CardTitle>
                <Link href="/engagements">
                  <Button variant="ghost" size="sm" className="text-[9px] font-display tracking-wider h-6 px-2">
                    MANAGE <ArrowRight className="w-3 h-3 ml-1" />
                  </Button>
                </Link>
              </div>
            </CardHeader>
            <CardContent className="px-4 pb-4 space-y-1.5">
              {engagementsQuery.isLoading ? (
                <div className="flex items-center justify-center py-6">
                  <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                </div>
              ) : activeEngagements.length === 0 ? (
                <div className="text-center py-6">
                  <Briefcase className="w-6 h-6 text-muted-foreground/40 mx-auto mb-2" />
                  <p className="text-[10px] text-muted-foreground">No active engagements</p>
                  <Link href="/engagements/new">
                    <Button variant="outline" size="sm" className="mt-2 text-[9px] font-display tracking-wider h-6 gap-1">
                      <Plus className="w-3 h-3" /> CREATE
                    </Button>
                  </Link>
                </div>
              ) : (
                activeEngagements.map((eng: any) => {
                  const statusCfg = ENGAGEMENT_STATUS_CONFIG[eng.status] || ENGAGEMENT_STATUS_CONFIG.planning;
                  const scanCount = eng.scanCount || 0;
                  return (
                    <div
                      key={eng.id}
                      className="p-2.5 rounded-lg bg-secondary/20 hover:bg-secondary/40 cursor-pointer transition-colors group"
                      onClick={() => navigate("/engagements")}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-display tracking-wider font-medium truncate">{eng.name}</span>
                        <Badge variant="outline" className={`text-[7px] font-display tracking-widest px-1 py-0 h-3.5 ${statusCfg.color}`}>
                          {statusCfg.label}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 text-[9px] text-muted-foreground">
                        <span>{eng.customerName}</span>
                        <span className="text-muted-foreground/40">·</span>
                        <span>{scanCount} scan{scanCount !== 1 ? "s" : ""}</span>
                        {eng.startDate && (
                          <>
                            <span className="text-muted-foreground/40">·</span>
                            <span>{new Date(eng.startDate).toLocaleDateString()}</span>
                          </>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </CardContent>
          </Card>
        </div>

        {/* ─── RIGHT: Context Inspector ─────────────────────────────────── */}
        <div className="xl:col-span-4 space-y-4">
          {/* Stats Row */}
          <div className="grid grid-cols-2 gap-3">
            <StatMini
              label="ENGAGEMENTS"
              value={stats?.activeEngagements ?? activeEngagements.length}
              icon={Crosshair}
              color="text-red-400"
            />
            <StatMini
              label="RUNNING SCANS"
              value={stats?.runningScans ?? runningScans}
              icon={Scan}
              color="text-blue-400"
            />
            <StatMini
              label="CRITICAL FINDINGS"
              value={stats?.criticalFindings ?? 0}
              icon={AlertTriangle}
              color="text-amber-400"
            />
            <StatMini
              label="OPSEC ALERTS"
              value={opsec?.recentAlerts ?? 0}
              icon={ShieldAlert}
              color={opsec && opsec.recentAlerts > 3 ? "text-red-400" : "text-emerald-400"}
            />
          </div>

          {/* OPSEC Gauge */}
          <Card>
            <CardHeader className="pb-0 pt-3 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-[10px] font-display tracking-widest text-muted-foreground flex items-center gap-2">
                  <ShieldAlert className="w-3 h-3" /> OPSEC EXPOSURE
                </CardTitle>
                {opsec && opsec.activeEngagements > 0 && (
                  <span className="text-[8px] font-display tracking-wider text-muted-foreground">
                    {opsec.activeEngagements} active op{opsec.activeEngagements !== 1 ? "s" : ""}
                  </span>
                )}
              </div>
            </CardHeader>
            <CardContent className="p-3">
              {opsecQuery.isLoading ? (
                <div className="flex items-center justify-center py-6">
                  <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                </div>
              ) : (
                <>
                  <div className="flex justify-center">
                    <OpsecGauge
                      score={opsec?.overallScore ?? 100}
                      noiseLevel={opsec?.noiseLevel ?? "stealth"}
                      detectionChance={opsec?.detectionChance ?? 0}
                    />
                  </div>

                  {/* Score Breakdown */}
                  {opsec && (
                    <div className="mt-3 space-y-1.5">
                      <ScoreBar label="STEALTH" value={opsec.breakdown.stealthScore} />
                      <ScoreBar label="EXPOSURE" value={opsec.breakdown.exposureScore} />
                      <ScoreBar label="ASSET HEALTH" value={opsec.breakdown.assetHealthScore} />
                      <ScoreBar label="EVENT VELOCITY" value={opsec.breakdown.eventVelocityScore} />
                    </div>
                  )}

                  {/* Burned Assets */}
                  {opsec && opsec.burnedAssets.length > 0 && (
                    <div className="mt-3 p-2 bg-red-500/10 border border-red-500/20 rounded-lg">
                      <div className="flex items-center gap-1.5 mb-1.5">
                        <Flame className="w-3 h-3 text-red-400" />
                        <span className="text-[9px] font-display tracking-wider text-red-400">BURNED ASSETS ({opsec.burnedAssets.length})</span>
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {opsec.burnedAssets.slice(0, 5).map((asset, i) => (
                          <span key={i} className="text-[8px] bg-red-500/20 text-red-300 px-1.5 py-0.5 rounded font-mono">{asset}</span>
                        ))}
                        {opsec.burnedAssets.length > 5 && (
                          <span className="text-[8px] text-red-400">+{opsec.burnedAssets.length - 5} more</span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Recommendations */}
                  {opsec && opsec.recommendations.length > 0 && (
                    <div className="mt-3 space-y-1">
                      {opsec.recommendations.slice(0, 3).map((rec, i) => (
                        <div key={i} className="flex items-start gap-1.5 text-[9px]">
                          <Shield className="w-3 h-3 text-muted-foreground shrink-0 mt-0.5" />
                          <span className="text-muted-foreground leading-relaxed">{rec}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </CardContent>
          </Card>

          {/* Campaign Advisor */}
          <Card>
            <CardHeader className="pb-2 pt-4 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-display tracking-widest flex items-center gap-2">
                  <Brain className="w-3.5 h-3.5 text-purple-400" />
                  CAMPAIGN ADVISOR
                </CardTitle>
                <Link href="/campaign-advisor">
                  <Button variant="ghost" size="sm" className="text-[9px] font-display tracking-wider h-6 px-2">
                    CHAT <ArrowRight className="w-3 h-3 ml-1" />
                  </Button>
                </Link>
              </div>
            </CardHeader>
            <CardContent className="px-4 pb-4 space-y-2">
              <div className="p-3 bg-purple-500/10 border border-purple-500/20 rounded-lg">
                <p className="text-[9px] text-purple-300 font-display tracking-wider mb-1.5">OPERATIONAL SUMMARY</p>
                <p className="text-xs leading-relaxed">
                  {opsec && opsec.activeEngagements > 0
                    ? `${opsec.activeEngagements} active engagement${opsec.activeEngagements !== 1 ? "s" : ""} with ${opsec.totalOpsecEvents} OPSEC events tracked. ${
                        opsec.highRiskEvents > 0
                          ? `${opsec.highRiskEvents} high-risk events require attention.`
                          : "Operations running within acceptable risk parameters."
                      }`
                    : "No active engagements. Launch a scan or engagement to get AI-powered operational recommendations."
                  }
                </p>
                {opsec && opsec.activeEngagements > 0 && (
                  <div className="flex items-center gap-1.5 mt-2">
                    <span className={`text-[8px] px-1.5 py-0.5 rounded font-display tracking-wider ${
                      opsec.overallScore > 70 ? "bg-emerald-500/20 text-emerald-400" :
                      opsec.overallScore > 40 ? "bg-amber-500/20 text-amber-400" :
                      "bg-red-500/20 text-red-400"
                    }`}>
                      OPSEC: {opsec.overallScore > 70 ? "CLEAN" : opsec.overallScore > 40 ? "MODERATE" : "ELEVATED"}
                    </span>
                    <span className="text-[8px] bg-purple-500/20 text-purple-400 px-1.5 py-0.5 rounded font-display tracking-wider">
                      {opsec.noiseLevel.toUpperCase()} NOISE
                    </span>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Quick Launch */}
          <Card>
            <CardHeader className="pb-2 pt-4 px-4">
              <CardTitle className="text-xs font-display tracking-widest flex items-center gap-2">
                <Zap className="w-3.5 h-3.5 text-yellow-400" />
                QUICK LAUNCH
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4">
              <div className="grid grid-cols-2 gap-2">
                {[
                  { href: "/credential-attacks", icon: Lock, label: "CRED ATTACKS", color: "bg-red-500/80" },
                  { href: "/exploitation-bridge", icon: Crosshair, label: "EXPLOIT BRIDGE", color: "bg-orange-500/80" },
                  { href: "/lateral-movement", icon: Network, label: "LATERAL MOVE", color: "bg-blue-500/80" },
                  { href: "/privilege-escalation", icon: Zap, label: "PRIVESC", color: "bg-purple-500/80" },
                  { href: "/nuclei-scanner", icon: Target, label: "VULN SCAN", color: "bg-emerald-500/80" },
                  { href: "/opsec-dashboard", icon: ShieldAlert, label: "OPSEC", color: "bg-amber-500/80" },
                ].map(action => (
                  <Link key={action.href} href={action.href}>
                    <button className="w-full flex items-center gap-2 p-2 rounded-lg bg-secondary/30 hover:bg-secondary/50 transition-colors text-left group">
                      <div className={`w-7 h-7 rounded flex items-center justify-center shrink-0 ${action.color}`}>
                        <action.icon className="w-3.5 h-3.5 text-white" />
                      </div>
                      <span className="text-[9px] font-display tracking-wider font-medium truncate">{action.label}</span>
                    </button>
                  </Link>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

// ─── Score Bar Component ────────────────────────────────────────────────────

function ScoreBar({ label, value }: { label: string; value: number }) {
  const color = value > 70 ? "bg-emerald-500" : value > 40 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <span className="text-[8px] font-display tracking-wider text-muted-foreground w-20 shrink-0">{label}</span>
      <div className="flex-1 bg-secondary rounded-full h-1.5">
        <div className={`${color} h-full rounded-full transition-all duration-700`} style={{ width: `${value}%` }} />
      </div>
      <span className="text-[9px] font-display font-medium w-6 text-right">{value}</span>
    </div>
  );
}

// ─── Mini Stat Card ──────────────────────────────────────────────────────────

function StatMini({ label, value, icon: Icon, color }: {
  label: string; value: string | number; icon: React.ComponentType<{ className?: string }>; color: string;
}) {
  return (
    <Card>
      <CardContent className="p-3">
        <div className="flex items-center gap-2 mb-1">
          <Icon className={`w-3.5 h-3.5 ${color}`} />
          <span className="text-[9px] font-display tracking-widest text-muted-foreground">{label}</span>
        </div>
        <p className="text-xl font-display font-bold">{value}</p>
      </CardContent>
    </Card>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getTimeAgo(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 7) return `${diffDay}d ago`;
  return date.toLocaleDateString();
}
