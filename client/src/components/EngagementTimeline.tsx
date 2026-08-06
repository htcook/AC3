/**
 * EngagementTimeline — Visual replay of the full scan lifecycle
 *
 * Plots recon, enumeration, vuln detection, exploitation phases on a timeline.
 * Shows evasion escalation events as warning markers, tool execution results
 * with duration bars, finding discoveries as severity-colored markers,
 * and phase transitions as milestone markers.
 */

import { useMemo, useState, useRef, useEffect, useCallback } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Tooltip, TooltipContent, TooltipProvider, TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Radar, Target, Bug, Skull, Radio, Shield, ShieldAlert, ShieldOff,
  AlertTriangle, CheckCircle2, XCircle, Zap, Clock, ChevronDown, ChevronUp,
  Search, FileText, FileCheck, Crosshair, Activity, Filter, Layers,
  Play, Pause, Square, FastForward, SkipForward, SkipBack, Rewind,
} from "lucide-react";

// ─── Types ──────────────────────────────────────────────────────────────────

interface OpsLogEntry {
  id: string;
  timestamp: number;
  phase: string;
  type: string;
  title: string;
  detail: string;
  data?: Record<string, any>;
  riskTier?: "yellow" | "orange" | "red";
}

interface ToolResult {
  tool: string;
  command: string;
  exitCode: number;
  durationMs: number;
  timedOut: boolean;
  findingCount: number;
  findings: Array<{ severity: string; title: string; cve?: string }>;
  outputPreview: string;
  executedAt: number;
  phase: string;
}

interface AssetStatus {
  hostname: string;
  ip?: string;
  vulns: Array<{ severity: string; title: string; cve?: string }>;
  zapFindings: Array<{ alert: string; risk: string; url: string }>;
  exploitAttempts: Array<{ module: string; success: boolean; timestamp?: number }>;
  toolResults: ToolResult[];
  status: string;
}

interface TimelineEvent {
  id: string;
  timestamp: number;
  type: "phase_start" | "phase_end" | "tool_exec" | "finding" | "evasion" | "approval" | "exploit" | "milestone";
  phase: string;
  title: string;
  detail: string;
  severity?: "critical" | "high" | "medium" | "low" | "info";
  riskTier?: "yellow" | "orange" | "red";
  durationMs?: number;
  asset?: string;
  tool?: string;
  success?: boolean;
}

interface EngagementTimelineProps {
  log: OpsLogEntry[];
  assets: AssetStatus[];
  startedAt?: number;
  completedAt?: number;
  currentPhase: string;
}

// ─── Phase Config ──────────────────────────────────────────────────────────

const PHASE_CONFIG: Record<string, { label: string; icon: typeof Radar; color: string; bgColor: string }> = {
  recon: { label: "Domain Recon", icon: Radar, color: "text-blue-400", bgColor: "bg-blue-500/10" },
  passive_discovery: { label: "Passive Discovery", icon: Search, color: "text-blue-300", bgColor: "bg-blue-400/10" },
  scoping: { label: "Scoping & RoE", icon: FileCheck, color: "text-indigo-400", bgColor: "bg-indigo-500/10" },
  test_plan: { label: "Test Plan", icon: FileText, color: "text-indigo-300", bgColor: "bg-indigo-400/10" },
  test_plan_approval: { label: "Plan Approval", icon: CheckCircle2, color: "text-indigo-200", bgColor: "bg-indigo-300/10" },
  enumeration: { label: "Active Discovery", icon: Target, color: "text-cyan-400", bgColor: "bg-cyan-500/10" },
  vuln_detection: { label: "Vuln Scan", icon: Bug, color: "text-yellow-400", bgColor: "bg-yellow-500/10" },
  social_engineering: { label: "Social Eng.", icon: Zap, color: "text-orange-400", bgColor: "bg-orange-500/10" },
  exploitation: { label: "Exploit", icon: Skull, color: "text-red-400", bgColor: "bg-red-500/10" },
  post_exploit: { label: "Post-Exploit", icon: Radio, color: "text-purple-400", bgColor: "bg-purple-500/10" },
  reporting: { label: "Reporting", icon: FileText, color: "text-emerald-400", bgColor: "bg-emerald-500/10" },
  completed: { label: "Complete", icon: CheckCircle2, color: "text-green-400", bgColor: "bg-green-500/10" },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  info: "bg-gray-500",
};

// ─── Timeline Data Transformation ──────────────────────────────────────────

export function buildTimelineEvents(
  log: OpsLogEntry[],
  assets: AssetStatus[]
): TimelineEvent[] {
  const events: TimelineEvent[] = [];
  let lastPhase = "";

  // Process log entries
  for (const entry of log) {
    // Phase transitions
    if (entry.phase !== lastPhase) {
      if (lastPhase) {
        events.push({
          id: `phase_end_${lastPhase}_${entry.timestamp}`,
          timestamp: entry.timestamp,
          type: "phase_end",
          phase: lastPhase,
          title: `${PHASE_CONFIG[lastPhase]?.label || lastPhase} completed`,
          detail: "",
        });
      }
      events.push({
        id: `phase_start_${entry.phase}_${entry.timestamp}`,
        timestamp: entry.timestamp,
        type: "phase_start",
        phase: entry.phase,
        title: `${PHASE_CONFIG[entry.phase]?.label || entry.phase} started`,
        detail: "",
      });
      lastPhase = entry.phase;
    }

    // Evasion escalation events
    if (entry.title.includes("Evasion") || entry.title.includes("evasion") ||
        entry.title.includes("EVA") || entry.title.includes("blocked") ||
        entry.title.includes("Blocked") || entry.title.includes("escalat")) {
      events.push({
        id: `evasion_${entry.id}`,
        timestamp: entry.timestamp,
        type: "evasion",
        phase: entry.phase,
        title: entry.title,
        detail: entry.detail,
        riskTier: entry.riskTier || "yellow",
      });
    }

    // Approval gates
    if (entry.type === "approval_required" || entry.type === "approval_gate") {
      events.push({
        id: `approval_${entry.id}`,
        timestamp: entry.timestamp,
        type: "approval",
        phase: entry.phase,
        title: entry.title,
        detail: entry.detail,
        riskTier: entry.riskTier,
      });
    }

    // Tool execution events
    if (entry.data?.tool && entry.data?.durationMs !== undefined) {
      events.push({
        id: `tool_${entry.id}`,
        timestamp: entry.timestamp,
        type: "tool_exec",
        phase: entry.phase,
        title: entry.title,
        detail: entry.detail,
        tool: entry.data.tool,
        durationMs: entry.data.durationMs,
        asset: entry.data.target || entry.data.hostname,
        success: entry.data.exitCode === 0,
      });
    }

    // Finding discoveries
    if (entry.type === "finding" || entry.type === "vuln_found" || entry.type === "vuln" ||
        (entry.data?.severity && (entry.data?.cve || entry.data?.title))) {
      const sev = (entry.data?.severity || "info").toLowerCase();
      events.push({
        id: `finding_${entry.id}`,
        timestamp: entry.timestamp,
        type: "finding",
        phase: entry.phase,
        title: entry.title,
        detail: entry.detail,
        severity: sev as TimelineEvent["severity"],
        asset: entry.data?.target || entry.data?.hostname,
      });
    }

    // Exploit events
    if (entry.phase === "exploitation" && (entry.type === "exploit_result" || entry.type === "exploit_success" || entry.type === "exploit_failure" || entry.type === "exploit_fail")) {
      const failureCategory = entry.data?.failureAnalysis?.category;
      events.push({
        id: `exploit_${entry.id}`,
        timestamp: entry.timestamp,
        type: "exploit",
        phase: entry.phase,
        title: entry.title,
        detail: failureCategory
          ? `[${failureCategory.replace(/_/g, ' ').toUpperCase()}] ${entry.data?.failureAnalysis?.description || entry.detail}`
          : entry.detail,
        success: entry.type === "exploit_success" || entry.data?.success === true,
        asset: entry.data?.target,
        riskTier: entry.riskTier,
      });
    }
  }

  // Add tool results from assets as supplementary events
  for (const asset of assets) {
    for (const tr of (asset.toolResults || [])) {
      const existingTool = events.find(e =>
        e.type === "tool_exec" && e.tool === tr.tool && e.asset === asset.hostname &&
        Math.abs((e.timestamp || 0) - tr.executedAt) < 5000
      );
      if (!existingTool && tr.executedAt) {
        events.push({
          id: `asset_tool_${asset.hostname}_${tr.tool}_${tr.executedAt}`,
          timestamp: tr.executedAt,
          type: "tool_exec",
          phase: tr.phase || "enumeration",
          title: `${tr.tool} → ${asset.hostname}`,
          detail: `Exit: ${tr.exitCode}, Duration: ${formatDuration(tr.durationMs)}, Findings: ${tr.findingCount}`,
          tool: tr.tool,
          durationMs: tr.durationMs,
          asset: asset.hostname,
          success: tr.exitCode === 0 && !tr.timedOut,
        });
      }
    }

    // Add exploit attempts from assets
    for (const ea of (asset.exploitAttempts || [])) {
      if (ea.timestamp) {
        const existingExploit = events.find(e =>
          e.type === "exploit" && e.asset === asset.hostname &&
          Math.abs((e.timestamp || 0) - (ea.timestamp || 0)) < 5000
        );
        if (!existingExploit) {
          events.push({
            id: `asset_exploit_${asset.hostname}_${ea.module}_${ea.timestamp}`,
            timestamp: ea.timestamp,
            type: "exploit",
            phase: "exploitation",
            title: `${ea.module} → ${asset.hostname}`,
            detail: ea.success ? "Exploit succeeded" : "Exploit failed",
            success: ea.success,
            asset: asset.hostname,
            riskTier: ea.success ? "red" : "orange",
          });
        }
      }
    }
  }

  // Sort by timestamp
  events.sort((a, b) => a.timestamp - b.timestamp);
  return events;
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${s % 60}s`;
}

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// ─── Event Type Icons ──────────────────────────────────────────────────────

function EventIcon({ event }: { event: TimelineEvent }) {
  switch (event.type) {
    case "phase_start":
    case "phase_end": {
      const cfg = PHASE_CONFIG[event.phase];
      const Icon = cfg?.icon || Activity;
      return <Icon className={`h-3.5 w-3.5 ${cfg?.color || "text-muted-foreground"}`} />;
    }
    case "tool_exec":
      return event.success
        ? <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />
        : <XCircle className="h-3.5 w-3.5 text-red-400" />;
    case "finding":
      return <Bug className="h-3.5 w-3.5 text-yellow-400" />;
    case "evasion":
      return <ShieldAlert className="h-3.5 w-3.5 text-orange-400" />;
    case "approval":
      return <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />;
    case "exploit":
      return event.success
        ? <Skull className="h-3.5 w-3.5 text-red-500" />
        : <Skull className="h-3.5 w-3.5 text-gray-500" />;
    default:
      return <Activity className="h-3.5 w-3.5 text-muted-foreground" />;
  }
}

// ─── Filter Controls ───────────────────────────────────────────────────────

type EventFilter = "all" | "phase" | "tool" | "finding" | "evasion" | "exploit" | "approval";

const FILTER_OPTIONS: Array<{ value: EventFilter; label: string; icon: typeof Activity }> = [
  { value: "all", label: "All", icon: Layers },
  { value: "phase", label: "Phases", icon: Activity },
  { value: "tool", label: "Tools", icon: Target },
  { value: "finding", label: "Findings", icon: Bug },
  { value: "evasion", label: "Evasion", icon: ShieldAlert },
  { value: "exploit", label: "Exploits", icon: Skull },
  { value: "approval", label: "Approvals", icon: AlertTriangle },
];

// ─── Phase Duration Bar ────────────────────────────────────────────────────

interface PhaseDuration {
  phase: string;
  startTime: number;
  endTime: number;
  durationMs: number;
  eventCount: number;
}

function computePhaseDurations(events: TimelineEvent[]): PhaseDuration[] {
  const phases: PhaseDuration[] = [];
  let currentPhase: PhaseDuration | null = null;

  for (const event of events) {
    if (event.type === "phase_start") {
      if (currentPhase) {
        currentPhase.endTime = event.timestamp;
        currentPhase.durationMs = currentPhase.endTime - currentPhase.startTime;
        phases.push(currentPhase);
      }
      currentPhase = {
        phase: event.phase,
        startTime: event.timestamp,
        endTime: event.timestamp,
        durationMs: 0,
        eventCount: 0,
      };
    } else if (currentPhase) {
      currentPhase.eventCount++;
      currentPhase.endTime = event.timestamp;
    }
  }
  if (currentPhase) {
    currentPhase.durationMs = currentPhase.endTime - currentPhase.startTime;
    phases.push(currentPhase);
  }
  return phases;
}

// ─── Main Component ────────────────────────────────────────────────────────

// ─── Replay Speed Options ─────────────────────────────────────────────────

const SPEED_OPTIONS = [
  { value: 1, label: "1x" },
  { value: 2, label: "2x" },
  { value: 5, label: "5x" },
  { value: 10, label: "10x" },
  { value: 25, label: "25x" },
];

export default function EngagementTimeline({ log, assets, startedAt, completedAt, currentPhase }: EngagementTimelineProps) {
  const [filter, setFilter] = useState<EventFilter>("all");
  const [expandedEvents, setExpandedEvents] = useState<Set<string>>(new Set());
  const scrollRef = useRef<HTMLDivElement>(null);

  // Replay state
  const [replayActive, setReplayActive] = useState(false);
  const [replayPaused, setReplayPaused] = useState(false);
  const [replaySpeed, setReplaySpeed] = useState(5);
  const [replayIndex, setReplayIndex] = useState(-1);
  const [replayElapsed, setReplayElapsed] = useState(0);
  const replayTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const eventRefs = useRef<Map<string, HTMLDivElement>>(new Map());

  const events = useMemo(() => buildTimelineEvents(log, assets), [log, assets]);
  const phaseDurations = useMemo(() => computePhaseDurations(events), [events]);

  const filteredEvents = useMemo(() => {
    if (filter === "all") return events;
    return events.filter(e => {
      switch (filter) {
        case "phase": return e.type === "phase_start" || e.type === "phase_end";
        case "tool": return e.type === "tool_exec";
        case "finding": return e.type === "finding";
        case "evasion": return e.type === "evasion";
        case "exploit": return e.type === "exploit";
        case "approval": return e.type === "approval";
        default: return true;
      }
    });
  }, [events, filter]);

  // Stats
  const stats = useMemo(() => {
    const toolExecs = events.filter(e => e.type === "tool_exec");
    const findings = events.filter(e => e.type === "finding");
    const evasions = events.filter(e => e.type === "evasion");
    const exploits = events.filter(e => e.type === "exploit");
    return {
      totalEvents: events.length,
      toolExecs: toolExecs.length,
      toolSuccess: toolExecs.filter(e => e.success).length,
      findings: findings.length,
      criticalFindings: findings.filter(e => e.severity === "critical").length,
      evasions: evasions.length,
      exploits: exploits.length,
      exploitSuccess: exploits.filter(e => e.success).length,
      totalDuration: startedAt ? ((completedAt || Date.now()) - startedAt) : 0,
    };
  }, [events, startedAt, completedAt]);

  const toggleExpand = (id: string) => {
    setExpandedEvents(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // ── Replay Controls ──
  const startReplay = useCallback(() => {
    setReplayActive(true);
    setReplayPaused(false);
    setReplayIndex(0);
    setReplayElapsed(0);
    setExpandedEvents(new Set());
  }, []);

  const pauseReplay = useCallback(() => {
    setReplayPaused(prev => !prev);
  }, []);

  const stopReplay = useCallback(() => {
    setReplayActive(false);
    setReplayPaused(false);
    setReplayIndex(-1);
    setReplayElapsed(0);
    if (replayTimerRef.current) {
      clearInterval(replayTimerRef.current);
      replayTimerRef.current = null;
    }
  }, []);

  const skipForward = useCallback(() => {
    setReplayIndex(prev => Math.min(prev + 1, filteredEvents.length - 1));
  }, [filteredEvents.length]);

  const skipBackward = useCallback(() => {
    setReplayIndex(prev => Math.max(prev - 1, 0));
  }, []);

  // Replay timer effect
  useEffect(() => {
    if (!replayActive || replayPaused || filteredEvents.length === 0) {
      if (replayTimerRef.current) {
        clearInterval(replayTimerRef.current);
        replayTimerRef.current = null;
      }
      return;
    }

    // Calculate interval between events based on speed
    const baseInterval = 1000; // 1 second base
    const interval = Math.max(50, baseInterval / replaySpeed);

    replayTimerRef.current = setInterval(() => {
      setReplayIndex(prev => {
        const next = prev + 1;
        if (next >= filteredEvents.length) {
          // Replay complete
          setReplayActive(false);
          setReplayPaused(false);
          if (replayTimerRef.current) clearInterval(replayTimerRef.current);
          return prev;
        }
        return next;
      });
      setReplayElapsed(prev => prev + interval);
    }, interval);

    return () => {
      if (replayTimerRef.current) {
        clearInterval(replayTimerRef.current);
        replayTimerRef.current = null;
      }
    };
  }, [replayActive, replayPaused, replaySpeed, filteredEvents.length]);

  // Auto-scroll to current replay event
  useEffect(() => {
    if (replayActive && replayIndex >= 0 && replayIndex < filteredEvents.length) {
      const event = filteredEvents[replayIndex];
      const el = eventRefs.current.get(event.id);
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }
  }, [replayIndex, replayActive, filteredEvents]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (replayTimerRef.current) clearInterval(replayTimerRef.current);
    };
  }, []);

  if (events.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
        <Clock className="h-10 w-10 mb-3 opacity-40" />
        <p className="text-sm">No timeline data available yet.</p>
        <p className="text-xs mt-1">Start an engagement to see the scan lifecycle here.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Description */}
      <p className="text-xs text-muted-foreground">
        Visual replay of the engagement lifecycle — phase transitions, tool executions, vulnerability discoveries, evasion escalations, and exploit attempts plotted chronologically.
      </p>

      {/* Stats Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
        <StatCard label="Duration" value={formatDuration(stats.totalDuration)} />
        <StatCard label="Events" value={String(stats.totalEvents)} />
        <StatCard label="Tools Run" value={`${stats.toolSuccess}/${stats.toolExecs}`} color={stats.toolSuccess === stats.toolExecs ? "text-green-400" : "text-yellow-400"} />
        <StatCard label="Findings" value={String(stats.findings)} color={stats.criticalFindings > 0 ? "text-red-400" : "text-yellow-400"} />
        <StatCard label="Critical" value={String(stats.criticalFindings)} color="text-red-400" />
        <StatCard label="Evasions" value={String(stats.evasions)} color={stats.evasions > 0 ? "text-orange-400" : "text-muted-foreground"} />
        <StatCard label="Exploits" value={`${stats.exploitSuccess}/${stats.exploits}`} color={stats.exploitSuccess > 0 ? "text-red-400" : "text-muted-foreground"} />
        <StatCard label="Phases" value={String(phaseDurations.length)} />
      </div>

      {/* Phase Duration Bar */}
      {phaseDurations.length > 0 && (
        <Card className="border-border/50 bg-card/50">
          <CardContent className="p-3">
            <div className="text-[10px] text-muted-foreground mb-1.5 font-medium">Phase Timeline</div>
            <div className="flex h-6 rounded-md overflow-hidden border border-border/30">
              <TooltipProvider>
                {phaseDurations.map((pd, i) => {
                  const totalMs = stats.totalDuration || 1;
                  const widthPct = Math.max(2, (pd.durationMs / totalMs) * 100);
                  const cfg = PHASE_CONFIG[pd.phase];
                  return (
                    <Tooltip key={i}>
                      <TooltipTrigger asChild>
                        <div
                          className={`${cfg?.bgColor || "bg-gray-500/10"} border-r border-border/20 flex items-center justify-center cursor-help transition-opacity hover:opacity-80`}
                          style={{ width: `${widthPct}%` }}
                        >
                          <span className={`text-[8px] font-medium ${cfg?.color || "text-muted-foreground"} truncate px-0.5`}>
                            {cfg?.label?.slice(0, 6) || pd.phase.slice(0, 6)}
                          </span>
                        </div>
                      </TooltipTrigger>
                      <TooltipContent side="bottom">
                        <div className="text-xs space-y-0.5">
                          <p className="font-semibold">{cfg?.label || pd.phase}</p>
                          <p>Duration: {formatDuration(pd.durationMs)}</p>
                          <p>Events: {pd.eventCount}</p>
                        </div>
                      </TooltipContent>
                    </Tooltip>
                  );
                })}
              </TooltipProvider>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Replay Controls */}
      <Card className="border-border/40 bg-card/40">
        <CardContent className="p-2.5 flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1">
            {!replayActive ? (
              <Button
                variant="outline"
                size="sm"
                className="h-7 px-2.5 text-[10px] gap-1 bg-green-500/10 border-green-500/30 text-green-400 hover:bg-green-500/20"
                onClick={startReplay}
                disabled={filteredEvents.length === 0}
              >
                <Play className="h-3 w-3" />
                Replay
              </Button>
            ) : (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  className={`h-7 w-7 p-0 text-[10px] ${replayPaused ? "bg-green-500/10 border-green-500/30 text-green-400" : "bg-yellow-500/10 border-yellow-500/30 text-yellow-400"}`}
                  onClick={pauseReplay}
                >
                  {replayPaused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 w-7 p-0 text-[10px] bg-red-500/10 border-red-500/30 text-red-400 hover:bg-red-500/20"
                  onClick={stopReplay}
                >
                  <Square className="h-3 w-3" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 w-7 p-0 text-[10px] border-border/50"
                  onClick={skipBackward}
                  disabled={replayIndex <= 0}
                >
                  <SkipBack className="h-3 w-3" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 w-7 p-0 text-[10px] border-border/50"
                  onClick={skipForward}
                  disabled={replayIndex >= filteredEvents.length - 1}
                >
                  <SkipForward className="h-3 w-3" />
                </Button>
              </>
            )}
          </div>

          {/* Speed selector */}
          <div className="flex items-center gap-0.5 border-l border-border/30 pl-2">
            <FastForward className="h-3 w-3 text-muted-foreground" />
            {SPEED_OPTIONS.map(opt => (
              <Button
                key={opt.value}
                variant={replaySpeed === opt.value ? "default" : "ghost"}
                size="sm"
                className={`h-6 px-1.5 text-[9px] min-w-[28px] ${replaySpeed === opt.value ? "" : "text-muted-foreground"}`}
                onClick={() => setReplaySpeed(opt.value)}
              >
                {opt.label}
              </Button>
            ))}
          </div>

          {/* Progress & elapsed time */}
          {replayActive && (
            <div className="flex items-center gap-2 border-l border-border/30 pl-2 ml-auto">
              <div className="flex items-center gap-1">
                <Clock className="h-3 w-3 text-muted-foreground" />
                <span className="text-[10px] font-mono text-muted-foreground">
                  {formatDuration(replayElapsed)}
                </span>
              </div>
              <div className="text-[10px] text-muted-foreground">
                Event {replayIndex + 1}/{filteredEvents.length}
              </div>
              {/* Progress bar */}
              <div className="w-24 h-1.5 bg-border/30 rounded-full overflow-hidden">
                <div
                  className="h-full bg-cyan-500 rounded-full transition-all duration-200"
                  style={{ width: `${((replayIndex + 1) / Math.max(1, filteredEvents.length)) * 100}%` }}
                />
              </div>
              {replayPaused && (
                <Badge variant="outline" className="text-[8px] text-yellow-400 border-yellow-500/30 animate-pulse">
                  PAUSED
                </Badge>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Filter Bar */}
      <div className="flex items-center gap-1 flex-wrap">
        <Filter className="h-3.5 w-3.5 text-muted-foreground mr-1" />
        {FILTER_OPTIONS.map(opt => {
          const Icon = opt.icon;
          const count = opt.value === "all" ? events.length :
            events.filter(e => {
              switch (opt.value) {
                case "phase": return e.type === "phase_start" || e.type === "phase_end";
                case "tool": return e.type === "tool_exec";
                case "finding": return e.type === "finding";
                case "evasion": return e.type === "evasion";
                case "exploit": return e.type === "exploit";
                case "approval": return e.type === "approval";
                default: return true;
              }
            }).length;
          return (
            <Button
              key={opt.value}
              variant={filter === opt.value ? "default" : "outline"}
              size="sm"
              className={`text-[10px] h-6 px-2 ${filter === opt.value ? "" : "border-border/50"}`}
              onClick={() => setFilter(opt.value)}
            >
              <Icon className="h-3 w-3 mr-0.5" />
              {opt.label} ({count})
            </Button>
          );
        })}
      </div>

      {/* Event List */}
      <ScrollArea className="h-[600px]" ref={scrollRef}>
        <div className="relative pl-6">
          {/* Vertical timeline line */}
          <div className="absolute left-[11px] top-0 bottom-0 w-px bg-border/30" />

          {filteredEvents.map((event, idx) => {
            const isExpanded = expandedEvents.has(event.id);
            const isPhaseTransition = event.type === "phase_start" || event.type === "phase_end";
            const cfg = PHASE_CONFIG[event.phase];
            const isReplayCurrent = replayActive && idx === replayIndex;
            const isReplayPast = replayActive && idx < replayIndex;
            const isReplayFuture = replayActive && idx > replayIndex;

            return (
              <div
                key={event.id}
                ref={(el) => { if (el) eventRefs.current.set(event.id, el); }}
                className={`relative mb-1.5 transition-all duration-300 ${
                  isReplayCurrent ? "scale-[1.01] z-10" :
                  isReplayFuture ? "opacity-20" :
                  isReplayPast ? "opacity-60" : ""
                }`}
              >
                {/* Timeline dot */}
                <div className={`absolute -left-6 top-1.5 w-[22px] flex items-center justify-center`}>
                  <div className={`w-2 h-2 rounded-full ${
                    event.type === "phase_start" ? (cfg?.bgColor?.replace("/10", "") || "bg-gray-500") :
                    event.type === "evasion" ? "bg-orange-500" :
                    event.type === "finding" ? (SEVERITY_COLORS[event.severity || "info"] || "bg-gray-500") :
                    event.type === "exploit" ? (event.success ? "bg-red-500" : "bg-gray-500") :
                    event.type === "tool_exec" ? (event.success ? "bg-green-500" : "bg-red-500") :
                    "bg-gray-500"
                  } ${event.type === "phase_start" ? "w-3 h-3" : ""}`} />
                </div>

                {/* Event card */}
                <div
                  className={`rounded-md border transition-colors cursor-pointer ${
                    isReplayCurrent
                      ? "ring-2 ring-cyan-500/60 border-cyan-500/40 bg-cyan-500/10 shadow-lg shadow-cyan-500/10"
                      : isPhaseTransition
                        ? `${cfg?.bgColor || "bg-card/50"} border-border/30`
                        : event.type === "evasion"
                          ? "bg-orange-500/5 border-orange-500/20 hover:border-orange-500/40"
                          : event.type === "finding"
                            ? "bg-yellow-500/5 border-yellow-500/20 hover:border-yellow-500/40"
                            : event.type === "exploit" && event.success
                              ? "bg-red-500/5 border-red-500/20 hover:border-red-500/40"
                              : "bg-card/30 border-border/20 hover:border-border/40"
                  } p-2`}
                  onClick={() => !isPhaseTransition && toggleExpand(event.id)}
                >
                  <div className="flex items-center gap-2">
                    <EventIcon event={event} />
                    <span className="text-[10px] font-mono text-muted-foreground flex-none">
                      {formatTime(event.timestamp)}
                    </span>
                    <span className={`text-xs font-medium truncate ${
                      isPhaseTransition ? (cfg?.color || "text-foreground") : "text-foreground"
                    }`}>
                      {event.title}
                    </span>
                    <div className="flex items-center gap-1 ml-auto flex-none">
                      {event.severity && (
                        <Badge variant="outline" className={`text-[8px] ${
                          event.severity === "critical" ? "text-red-400 border-red-500/30" :
                          event.severity === "high" ? "text-orange-400 border-orange-500/30" :
                          event.severity === "medium" ? "text-yellow-400 border-yellow-500/30" :
                          "text-blue-400 border-blue-500/30"
                        }`}>
                          {event.severity.toUpperCase()}
                        </Badge>
                      )}
                      {event.riskTier && !event.severity && (
                        <Badge variant="outline" className={`text-[8px] ${
                          event.riskTier === "red" ? "text-red-400 border-red-500/30" :
                          event.riskTier === "orange" ? "text-orange-400 border-orange-500/30" :
                          "text-yellow-400 border-yellow-500/30"
                        }`}>
                          {event.riskTier.toUpperCase()}
                        </Badge>
                      )}
                      {event.durationMs !== undefined && (
                        <span className="text-[9px] text-muted-foreground font-mono">
                          {formatDuration(event.durationMs)}
                        </span>
                      )}
                      {event.asset && (
                        <span className="text-[9px] text-muted-foreground font-mono truncate max-w-[120px]">
                          {event.asset}
                        </span>
                      )}
                      {!isPhaseTransition && (
                        isExpanded ? <ChevronUp className="h-3 w-3 text-muted-foreground" /> : <ChevronDown className="h-3 w-3 text-muted-foreground" />
                      )}
                    </div>
                  </div>

                  {/* Expanded detail */}
                  {isExpanded && event.detail && (
                    <div className="mt-2 pt-2 border-t border-border/20">
                      <p className="text-[11px] text-muted-foreground whitespace-pre-wrap break-words">
                        {event.detail}
                      </p>
                      {event.tool && (
                        <Badge variant="outline" className="text-[9px] mt-1 text-cyan-400 border-cyan-500/30">
                          {event.tool}
                        </Badge>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </ScrollArea>
    </div>
  );
}

// ─── Stat Card ─────────────────────────────────────────────────────────────

function StatCard({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div className="rounded-md border border-border/30 bg-card/30 p-2 text-center">
      <div className={`text-sm font-bold ${color || "text-foreground"}`}>{value}</div>
      <div className="text-[9px] text-muted-foreground">{label}</div>
    </div>
  );
}
