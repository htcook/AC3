/**
 * Operator Cockpit — Real-Time Command Center
 * 
 * Your real-time command center. View live operations, active scans,
 * engagement status, and OPSEC exposure at a glance.
 * 
 * Features:
 *   - WebSocket real-time timeline events (merged with DB history)
 *   - Category filter toggles (scan/engagement/opsec/agent/system)
 *   - LLM-powered Campaign Advisor with contextual recommendations
 *   - OPSEC Gauge with score breakdown
 * 
 * 3-column layout:
 *   Left   — Live Activity Timeline (real-time + historical)
 *   Center — Scan Queue + Engagements (active operations)
 *   Right  — OPSEC Gauge + Campaign Advisor + Quick Launch
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { useEngagement } from "@/contexts/EngagementContext";
import { useCockpitTimeline } from "@/hooks/useWebSocket";
import type { WsEvent } from "@/hooks/useWebSocket";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  ShieldAlert, Activity, Crosshair, Zap, ArrowRight, Clock,
  AlertTriangle, CheckCircle2, Target, Brain, Network, Lock,
  Scan, Globe, Play, Plus, Loader2, Radar, Eye, Briefcase,
  ChevronRight, BarChart3, RefreshCw, TrendingDown, TrendingUp,
  Radio, Shield, Flame, Filter, Sparkles, ChevronDown, ChevronUp, Bot
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

type TimelineCategory = "scan" | "engagement" | "opsec" | "agent" | "system" | "automation";

interface UnifiedTimelineEvent {
  id: string;
  category: TimelineCategory;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  timestamp: Date;
  source: "db" | "ws";
}

interface LlmRecommendation {
  priority: "high" | "medium" | "low";
  action: string;
  detail: string;
  technique: string;
}

// ─── OPSEC Risk Gauge ─────────────────────────────────────────────────────────

function OpsecGauge({ score, noiseLevel, detectionChance }: {
  score: number; noiseLevel: string; detectionChance: number;
}) {
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
          <span className="text-[7px] font-display tracking-widest text-muted-foreground">{label}</span>
        </div>
      </div>
      <div className="flex items-center gap-3 text-[10px]">
        <div className="flex items-center gap-1">
          <Radio className={`w-3 h-3 ${
            noiseLevel === "critical" ? "text-red-400" : noiseLevel === "elevated" ? "text-orange-400" :
            noiseLevel === "moderate" ? "text-amber-400" : "text-emerald-400"
          }`} />
          <span className={`font-display tracking-wider ${
            noiseLevel === "critical" ? "text-red-400" : noiseLevel === "elevated" ? "text-orange-400" :
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
  automation: Bot,
};

const CATEGORY_COLORS: Record<string, string> = {
  scan: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  engagement: "bg-red-500/20 text-red-400 border-red-500/30",
  opsec: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  agent: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  system: "bg-slate-500/20 text-slate-400 border-slate-500/30",
  automation: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
};

// ─── WebSocket event to timeline event converter ──────────────────────────────

function wsEventToTimeline(wsEvent: WsEvent): UnifiedTimelineEvent {
  const type = wsEvent.type;
  let category: TimelineCategory = "system";
  let severity: UnifiedTimelineEvent["severity"] = "info";
  let title = type.replace(/[_:]/g, " ").replace(/\b\w/g, c => c.toUpperCase());
  let description = "";

  if (type.startsWith("recon:") || type.startsWith("domain:")) {
    category = "scan";
    severity = type === "recon:complete" || type === "domain:scan_complete" ? "medium" : "low";
    title = type === "recon:complete" ? "Recon Complete" : type === "recon:started" ? "Recon Started" :
            type === "domain:scan_complete" ? "Domain Scan Complete" : "Recon Finding";
    description = wsEvent.data?.domain || wsEvent.data?.target || JSON.stringify(wsEvent.data).slice(0, 80);
  } else if (type.startsWith("exploit:") || type.startsWith("agent:")) {
    category = "agent";
    if (type === "exploit:result") {
      severity = wsEvent.data?.success ? "high" : "medium";
      title = wsEvent.data?.success ? "Exploit Succeeded" : "Exploit Failed";
      description = `${wsEvent.data?.module || "Module"} on ${wsEvent.data?.targetIp || "target"}`;
    } else if (type === "agent:deployed") {
      severity = "high";
      title = "Agent Deployed";
      description = `${wsEvent.data?.paw || "agent"} on ${wsEvent.data?.host || "host"}`;
    } else if (type === "agent:lost") {
      severity = "critical";
      title = "Agent Lost";
      description = `${wsEvent.data?.paw || "agent"} on ${wsEvent.data?.host || "host"}`;
    } else {
      title = type.split(":")[1]?.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()) || title;
      description = wsEvent.data?.paw || wsEvent.data?.module || "";
    }
  } else if (type.startsWith("opsec:")) {
    category = "opsec";
    severity = type === "opsec:burn_detected" ? "critical" : type === "opsec:threshold_warning" ? "high" : "medium";
    title = type === "opsec:burn_detected" ? "BURN DETECTED" : type === "opsec:threshold_warning" ? "Threshold Warning" :
            type === "opsec:risk_update" ? "Risk Update" : "Action Scored";
    description = wsEvent.data?.description || wsEvent.data?.indicator || wsEvent.data?.recommendation || "";
  } else if (type.startsWith("credential:") || type.startsWith("lateral:") || type.startsWith("privesc:")) {
    category = "engagement";
    severity = type.includes("found") || type.includes("executed") || type.includes("escalation") ? "high" : "medium";
    title = type.split(":")[1]?.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()) || title;
    description = wsEvent.data?.target || wsEvent.data?.technique || wsEvent.data?.username || "";
  } else if (type.startsWith("operation:") || type.startsWith("engagement:") || type.startsWith("campaign:") || type.startsWith("pipeline:")) {
    category = "engagement";
    severity = type.includes("finished") || type.includes("complete") ? "medium" : "low";
    title = type.split(":")[1]?.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()) || title;
    description = wsEvent.data?.name || wsEvent.data?.phase || "";
  } else if (type.startsWith("automation:")) {
    category = "automation";
    if (type === "automation:profile_generated") {
      severity = "high";
      title = "Adversary Profile Generated";
      description = `${wsEvent.data?.actorName || wsEvent.data?.actorId || "Actor"} (score: ${wsEvent.data?.completenessScore || "?"}/100)`;
    } else if (type === "automation:profile_pushed") {
      severity = wsEvent.data?.success ? "high" : "medium";
      title = wsEvent.data?.success ? "Profile Pushed to Caldera" : "Profile Push Failed";
      description = wsEvent.data?.actorName || wsEvent.data?.actorId || "";
    } else if (type === "automation:playbook_triggered") {
      severity = "critical";
      title = "Post-Exploit Playbook Triggered";
      description = `${wsEvent.data?.targetHost || "target"} (${wsEvent.data?.targetPlatform || ""}, ${wsEvent.data?.privilegeLevel || ""}) — ${wsEvent.data?.playbookSteps || 0} steps`;
    } else if (type === "automation:pipeline_run") {
      severity = wsEvent.data?.status === "failed" ? "high" : wsEvent.data?.status === "completed" ? "medium" : "low";
      title = `Pipeline ${wsEvent.data?.status === "started" ? "Started" : wsEvent.data?.status === "completed" ? "Completed" : "Failed"}`;
      description = wsEvent.data?.status === "completed"
        ? `${wsEvent.data?.profilesGenerated || 0} generated, ${wsEvent.data?.profilesPushed || 0} pushed`
        : wsEvent.data?.error || `Run ${wsEvent.data?.runId || ""}`;
    } else if (type === "automation:enrichment_complete") {
      severity = wsEvent.data?.profileGenerated ? "high" : "low";
      title = "Threat Intel Enrichment";
      description = `${wsEvent.data?.actorName || "Actor"}: ${wsEvent.data?.previousScore || 0} → ${wsEvent.data?.newScore || 0}${wsEvent.data?.thresholdMet ? " (threshold met)" : ""}`;
    }
  } else if (type.startsWith("job:")) {
    category = "system";
    severity = type === "job:failed" ? "high" : "low";
    title = type === "job:completed" ? "Job Completed" : type === "job:failed" ? "Job Failed" : title;
    description = wsEvent.data?.type || wsEvent.data?.error || "";
  } else {
    severity = wsEvent.data?.severity === "critical" ? "critical" : wsEvent.data?.severity === "error" ? "high" : "info";
    description = wsEvent.data?.message || wsEvent.data?.title || "";
  }

  return {
    id: `ws-${wsEvent.type}-${wsEvent.timestamp}-${Math.random().toString(36).slice(2, 6)}`,
    category,
    severity,
    title,
    description: description.slice(0, 120),
    timestamp: new Date(wsEvent.timestamp),
    source: "ws",
  };
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function OperatorHome() {
  const [, navigate] = useLocation();
  const { activeEngagement } = useEngagement();
  const [timelineHours, setTimelineHours] = useState(24);
  const [activeFilters, setActiveFilters] = useState<Set<TimelineCategory>>(
    new Set(["scan", "engagement", "opsec", "agent", "automation", "system"])
  );
  const [showFilters, setShowFilters] = useState(false);
  const [advisorExpanded, setAdvisorExpanded] = useState(false);

  // Engagement-scoped filter
  const engId = activeEngagement?.id;

  // ── Real data queries (scoped to active engagement when selected) ──
  const scansQuery = trpc.domainIntel.listScans.useQuery(undefined, {
    refetchInterval: 15000,
  });
  const engagementsQuery = trpc.engagements.list.useQuery();

  // Activity timeline from real audit logs — filtered by engagement
  const timelineQuery = trpc.operatorCockpit.activityTimeline.useQuery(
    { limit: 50, hoursBack: timelineHours, engagementId: engId ?? undefined },
    { refetchInterval: 30000 }
  );

  // OPSEC gauge from real engagement data — filtered by engagement
  const opsecQuery = trpc.operatorCockpit.opsecGauge.useQuery(
    { engagementId: engId ?? undefined },
    { refetchInterval: 60000 }
  );

  // Quick stats — filtered by engagement
  const statsQuery = trpc.operatorCockpit.quickStats.useQuery(
    { engagementId: engId ?? undefined },
    { refetchInterval: 30000 }
  );

  // ── WebSocket real-time events ──
  const { events: wsEvents, status: wsStatus } = useCockpitTimeline();

  // ── LLM Campaign Advisor ──
  const advisorMutation = trpc.operatorCockpit.campaignAdvice.useMutation();
  const [advisorResult, setAdvisorResult] = useState<{
    summary: string;
    recommendations: LlmRecommendation[];
    generatedAt: string;
  } | null>(null);

  const generateAdvice = useCallback(() => {
    const opsec = opsecQuery.data;
    const timeline = timelineQuery.data;

    advisorMutation.mutate({
      opsecScore: opsec?.overallScore,
      noiseLevel: opsec?.noiseLevel,
      detectionChance: opsec?.detectionChance,
      activeEngagements: opsec?.activeEngagements,
      highRiskEvents: opsec?.highRiskEvents,
      burnedAssets: opsec?.burnedAssets,
      recentEvents: timeline?.events.slice(0, 10).map(e => ({
        category: e.category,
        severity: e.severity,
        title: e.title,
        description: e.description,
      })),
    }, {
      onSuccess: (data) => {
        if (data.success) {
          setAdvisorResult({
            summary: data.summary,
            recommendations: data.recommendations,
            generatedAt: data.generatedAt,
          });
          setAdvisorExpanded(true);
        }
      },
    });
  }, [opsecQuery.data, timelineQuery.data, advisorMutation]);

  // ── Merge DB timeline + WebSocket events ──
  const mergedTimeline = useMemo(() => {
    const dbEvents: UnifiedTimelineEvent[] = (timelineQuery.data?.events || []).map((e: any) => ({
      id: e.id,
      category: e.category as TimelineCategory,
      severity: e.severity,
      title: e.title,
      description: e.description,
      timestamp: new Date(e.timestamp),
      source: "db" as const,
    }));

    const wsConverted: UnifiedTimelineEvent[] = wsEvents.map(wsEventToTimeline);

    // Merge and deduplicate (WS events that match recent DB events by title+time within 5s)
    const merged = [...wsConverted];
    for (const dbEvt of dbEvents) {
      const isDuplicate = wsConverted.some(ws =>
        ws.title === dbEvt.title &&
        Math.abs(ws.timestamp.getTime() - dbEvt.timestamp.getTime()) < 5000
      );
      if (!isDuplicate) merged.push(dbEvt);
    }

    // Sort by timestamp descending
    merged.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    // Apply category filters
    return merged.filter(e => activeFilters.has(e.category));
  }, [timelineQuery.data, wsEvents, activeFilters]);

  // ── Derived data (filtered by active engagement when selected) ──
  const recentScans = useMemo(() => {
    const all = scansQuery.data || [];
    if (engId) {
      return all.filter((s: any) => s.engagementId === engId).slice(0, 6);
    }
    return all.slice(0, 6);
  }, [scansQuery.data, engId]);

  const activeEngagementsList = useMemo(() => {
    const all = (engagementsQuery.data || [])
      .filter((e: any) => e.status === "active" || e.status === "planning");
    if (engId) {
      return all.filter((e: any) => e.id === engId).slice(0, 5);
    }
    return all.slice(0, 5);
  }, [engagementsQuery.data, engId]);

  const totalScans = scansQuery.data?.length || 0;
  const runningScans = (scansQuery.data || []).filter((s: any) =>
    ["discovering", "passive_recon", "analyzing", "scoring", "recommending"].includes(s.status)
  ).length;

  const opsec = opsecQuery.data;
  const stats = statsQuery.data;

  // ── Filter toggle ──
  const toggleFilter = useCallback((cat: TimelineCategory) => {
    setActiveFilters(prev => {
      const next = new Set(prev);
      if (next.has(cat)) {
        if (next.size > 1) next.delete(cat); // Don't allow empty
      } else {
        next.add(cat);
      }
      return next;
    });
  }, []);

  // Count WS events for live indicator
  const liveCount = wsEvents.length;

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
          {/* WS Connection Status */}
          <TooltipProvider delayDuration={200}>
            <Tooltip>
              <TooltipTrigger asChild>
                <div className={`flex items-center gap-1.5 px-2 py-1 rounded-md text-[9px] font-display tracking-wider ${
                  wsStatus === "connected" ? "bg-emerald-500/10 text-emerald-400" :
                  wsStatus === "connecting" ? "bg-amber-500/10 text-amber-400" :
                  "bg-red-500/10 text-red-400"
                }`}>
                  <div className={`w-1.5 h-1.5 rounded-full ${
                    wsStatus === "connected" ? "bg-emerald-500 animate-pulse" :
                    wsStatus === "connecting" ? "bg-amber-500 animate-pulse" :
                    "bg-red-500"
                  }`} />
                  {wsStatus === "connected" ? "LIVE" : wsStatus === "connecting" ? "CONNECTING" : "OFFLINE"}
                  {liveCount > 0 && wsStatus === "connected" && (
                    <span className="text-[8px] opacity-60">({liveCount})</span>
                  )}
                </div>
              </TooltipTrigger>
              <TooltipContent side="bottom" className="text-[10px]">
                WebSocket {wsStatus} — {liveCount} real-time events received this session
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>

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
                  {mergedTimeline.length > 0 && (
                    <span className="text-[8px] bg-primary/20 text-primary border border-primary/30 px-1.5 py-0.5 rounded-full font-display tracking-widest">
                      {mergedTimeline.length}
                    </span>
                  )}
                  {liveCount > 0 && (
                    <span className="text-[8px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded-full font-display tracking-widest animate-pulse">
                      {liveCount} LIVE
                    </span>
                  )}
                </CardTitle>
              </div>

              {/* Time range + Filter toggle */}
              <div className="flex items-center justify-between mt-2">
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
                <button
                  onClick={() => setShowFilters(!showFilters)}
                  className={`flex items-center gap-1 text-[8px] font-display tracking-wider px-1.5 py-0.5 rounded transition-colors ${
                    showFilters ? "bg-primary/20 text-primary" : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <Filter className="w-3 h-3" />
                  FILTER
                  {activeFilters.size < 5 && (
                    <span className="text-[7px] bg-primary/30 px-1 rounded">{activeFilters.size}</span>
                  )}
                </button>
              </div>

              {/* Category Filter Toggles */}
              {showFilters && (
                <div className="flex flex-wrap gap-1.5 mt-2 pt-2 border-t border-border/50">
                  {(["scan", "engagement", "opsec", "agent", "automation", "system"] as TimelineCategory[]).map(cat => {
                    const CatIcon = CATEGORY_ICONS[cat];
                    const isActive = activeFilters.has(cat);
                    const catColor = CATEGORY_COLORS[cat];
                    return (
                      <button
                        key={cat}
                        onClick={() => toggleFilter(cat)}
                        className={`flex items-center gap-1 text-[8px] font-display tracking-wider px-2 py-1 rounded-md border transition-all ${
                          isActive ? catColor : "bg-secondary/20 text-muted-foreground/40 border-transparent"
                        }`}
                      >
                        <CatIcon className="w-2.5 h-2.5" />
                        {cat.toUpperCase()}
                      </button>
                    );
                  })}
                </div>
              )}
            </CardHeader>
            <CardContent className="px-4 pb-4">
              {timelineQuery.isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                </div>
              ) : mergedTimeline.length === 0 ? (
                <div className="text-center py-8">
                  <Activity className="w-6 h-6 text-muted-foreground/40 mx-auto mb-2" />
                  <p className="text-[10px] text-muted-foreground">No activity in the last {timelineHours}h</p>
                  <p className="text-[9px] text-muted-foreground/60 mt-1">Start a scan or engagement to see events here</p>
                </div>
              ) : (
                <div className="relative max-h-[600px] overflow-y-auto scrollbar-thin">
                  {/* Timeline spine */}
                  <div className="absolute left-[7px] top-0 bottom-0 w-px bg-border" />
                  <div className="space-y-0">
                    {mergedTimeline.slice(0, 40).map((event) => {
                      const sevCfg = SEVERITY_CONFIG[event.severity] || SEVERITY_CONFIG.info;
                      const CatIcon = CATEGORY_ICONS[event.category] || Activity;
                      const timeAgo = getTimeAgo(event.timestamp);
                      const isLive = event.source === "ws";

                      return (
                        <div key={event.id} className={`flex items-start gap-3 py-2 pl-0 relative group ${
                          isLive ? "animate-in fade-in slide-in-from-left-2 duration-300" : ""
                        }`}>
                          <TooltipProvider delayDuration={200}>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <div className={`w-[15px] h-[15px] rounded-full shrink-0 z-10 flex items-center justify-center border ${sevCfg.bg} ${
                                  isLive ? "ring-1 ring-emerald-500/50" : ""
                                }`}>
                                  <div className={`w-[5px] h-[5px] rounded-full ${sevCfg.dot} ${isLive ? "animate-pulse" : ""}`} />
                                </div>
                              </TooltipTrigger>
                              <TooltipContent side="right" className="text-[10px] max-w-[200px]">
                                <p className="font-medium">{event.category.toUpperCase()} — {event.severity.toUpperCase()}</p>
                                <p className="text-muted-foreground mt-1">{event.description}</p>
                                {isLive && <p className="text-emerald-400 mt-1 text-[9px]">Real-time event</p>}
                              </TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                          <div className="flex-1 min-w-0 -mt-0.5">
                            <div className="flex items-center gap-2">
                              <CatIcon className="w-3 h-3 text-muted-foreground shrink-0" />
                              <span className="text-[10px] font-display tracking-wider font-medium truncate">{event.title}</span>
                              {isLive && (
                                <span className="text-[7px] bg-emerald-500/20 text-emerald-400 px-1 py-0 rounded font-display">LIVE</span>
                              )}
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
              ) : activeEngagementsList.length === 0 ? (
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
                activeEngagementsList.map((eng: any) => {
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
              value={stats?.activeEngagements ?? activeEngagementsList.length}
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

          {/* LLM Campaign Advisor */}
          <Card className="border-purple-500/20">
            <CardHeader className="pb-2 pt-4 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-display tracking-widest flex items-center gap-2">
                  <Brain className="w-3.5 h-3.5 text-purple-400" />
                  CAMPAIGN ADVISOR
                  <Badge variant="outline" className="text-[7px] font-display tracking-widest px-1 py-0 h-3.5 border-purple-500/30 text-purple-400 bg-purple-500/10">
                    AI
                  </Badge>
                </CardTitle>
                <div className="flex items-center gap-1.5">
                  {advisorResult && (
                    <button
                      onClick={() => setAdvisorExpanded(!advisorExpanded)}
                      className="text-[8px] text-muted-foreground hover:text-foreground transition-colors"
                    >
                      {advisorExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </button>
                  )}
                  <Button
                    variant="outline"
                    size="sm"
                    className="text-[9px] font-display tracking-wider h-6 px-2 gap-1 border-purple-500/30 text-purple-400 hover:bg-purple-500/10"
                    onClick={generateAdvice}
                    disabled={advisorMutation.isPending}
                  >
                    {advisorMutation.isPending ? (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    ) : (
                      <Sparkles className="w-3 h-3" />
                    )}
                    {advisorMutation.isPending ? "ANALYZING..." : advisorResult ? "REFRESH" : "GENERATE"}
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="px-4 pb-4 space-y-2">
              {!advisorResult && !advisorMutation.isPending ? (
                <div className="p-3 bg-purple-500/5 border border-purple-500/10 rounded-lg">
                  <p className="text-[10px] text-muted-foreground leading-relaxed">
                    {opsec && opsec.activeEngagements > 0
                      ? `${opsec.activeEngagements} active engagement${opsec.activeEngagements !== 1 ? "s" : ""} detected. Click "GENERATE" for AI-powered tactical recommendations based on your current OPSEC posture and recent activity.`
                      : "Launch a scan or engagement, then click \"GENERATE\" for AI-powered tactical recommendations."
                    }
                  </p>
                </div>
              ) : advisorMutation.isPending ? (
                <div className="flex flex-col items-center justify-center py-4 gap-2">
                  <div className="relative">
                    <Brain className="w-6 h-6 text-purple-400 animate-pulse" />
                    <Sparkles className="w-3 h-3 text-purple-300 absolute -top-1 -right-1 animate-bounce" />
                  </div>
                  <p className="text-[10px] text-purple-400 font-display tracking-wider">ANALYZING OPERATIONAL STATE...</p>
                </div>
              ) : advisorResult && (
                <>
                  {/* Summary */}
                  <div className="p-2.5 bg-purple-500/10 border border-purple-500/20 rounded-lg">
                    <p className="text-[9px] text-purple-300 font-display tracking-wider mb-1">OPERATIONAL SUMMARY</p>
                    <p className="text-[10px] leading-relaxed">{advisorResult.summary}</p>
                    <div className="flex items-center gap-2 mt-1.5">
                      <span className="text-[8px] text-muted-foreground/50 font-mono">
                        {new Date(advisorResult.generatedAt).toLocaleTimeString()}
                      </span>
                      {opsec && (
                        <span className={`text-[8px] px-1.5 py-0.5 rounded font-display tracking-wider ${
                          opsec.overallScore > 70 ? "bg-emerald-500/20 text-emerald-400" :
                          opsec.overallScore > 40 ? "bg-amber-500/20 text-amber-400" :
                          "bg-red-500/20 text-red-400"
                        }`}>
                          OPSEC: {opsec.overallScore > 70 ? "CLEAN" : opsec.overallScore > 40 ? "MODERATE" : "ELEVATED"}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Recommendations */}
                  {advisorExpanded && advisorResult.recommendations.length > 0 && (
                    <div className="space-y-1.5">
                      {advisorResult.recommendations.map((rec, i) => {
                        const priorityColor = rec.priority === "high" ? "border-red-500/30 bg-red-500/5" :
                          rec.priority === "medium" ? "border-amber-500/30 bg-amber-500/5" :
                          "border-blue-500/30 bg-blue-500/5";
                        const priorityBadge = rec.priority === "high" ? "bg-red-500/20 text-red-400" :
                          rec.priority === "medium" ? "bg-amber-500/20 text-amber-400" :
                          "bg-blue-500/20 text-blue-400";

                        return (
                          <div key={i} className={`p-2.5 rounded-lg border ${priorityColor}`}>
                            <div className="flex items-center gap-2 mb-1">
                              <Badge className={`text-[7px] font-display tracking-widest px-1 py-0 h-3.5 ${priorityBadge}`}>
                                {rec.priority.toUpperCase()}
                              </Badge>
                              <span className="text-[10px] font-display tracking-wider font-medium">{rec.action}</span>
                              {rec.technique && (
                                <span className="text-[8px] font-mono text-muted-foreground/60">{rec.technique}</span>
                              )}
                            </div>
                            <p className="text-[9px] text-muted-foreground leading-relaxed">{rec.detail}</p>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </>
              )}
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
