import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Activity, Radio, Brain, Zap, Clock, AlertTriangle, CheckCircle2,
  XCircle, Pause, Play, Target, Shield, Eye, Crosshair, Network,
  Lock, Bot, Cpu, TrendingUp, Wifi, WifiOff, ChevronRight,
} from "lucide-react";

// ─── Constants ──────────────────────────────────────────────────────────────

const STATUS_COLORS: Record<string, string> = {
  success: "text-emerald-400",
  error: "text-red-400",
  timeout: "text-amber-400",
  retried_success: "text-yellow-400",
  failure: "text-red-400",
  partial: "text-amber-400",
  pending: "text-blue-400",
};

const STATUS_ICONS: Record<string, typeof CheckCircle2> = {
  success: CheckCircle2,
  error: XCircle,
  timeout: Clock,
  retried_success: CheckCircle2,
  failure: XCircle,
  partial: AlertTriangle,
  pending: Clock,
};

const SEVERITY_COLORS: Record<string, string> = {
  info: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  low: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
};

const EVENT_TYPE_ICONS: Record<string, typeof Activity> = {
  phase_started: Play,
  phase_completed: CheckCircle2,
  finding_discovered: Eye,
  exploit_attempted: Crosshair,
  exploit_succeeded: Target,
  shell_obtained: Cpu,
  credential_found: Lock,
  pivot_established: Network,
  scan_completed: Shield,
  opsec_alert: AlertTriangle,
  tool_executed: Zap,
  objective_completed: CheckCircle2,
};

// ─── WebSocket Event Types ──────────────────────────────────────────────────

interface WsEvent {
  type: string;
  timestamp: number;
  engagementId?: number | null;
  data: Record<string, any>;
}

interface WsLiveEvent {
  id: string;
  type: string;
  timestamp: number;
  engagementId?: number | null;
  data: Record<string, any>;
}

// ─── WebSocket Hook ─────────────────────────────────────────────────────────

function useWebSocket(isPaused: boolean) {
  const [wsStatus, setWsStatus] = useState<"connecting" | "connected" | "disconnected">("disconnected");
  const [liveEvents, setLiveEvents] = useState<WsLiveEvent[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttempts = useRef(0);
  const maxEvents = 200;

  const connect = useCallback(() => {
    if (isPaused) return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${protocol}//${window.location.host}/ws/events`;
      setWsStatus("connecting");

      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setWsStatus("connected");
        reconnectAttempts.current = 0;
        // Subscribe to LLM monitor channel + global
        ws.send(JSON.stringify({ action: "subscribe", channels: ["global", "llm:monitor"] }));
      };

      ws.onmessage = (event) => {
        try {
          const parsed: WsEvent = JSON.parse(event.data);
          // Filter for relevant event types
          const relevantTypes = [
            "llm:decision", "llm:delegation", "llm:stealth_alert",
            "llm:training_captured", "llm:shadow_test_result", "llm:engagement_progress",
            "engagement:phase_changed", "engagement:timeline_event", "engagement:progress_update",
            "exploit:fired", "exploit:result", "agent:deployed", "agent:checkin",
            "operation:started", "operation:step_complete", "operation:finished",
            "recon:complete", "opsec:burn_detected", "opsec:threshold_warning",
            "credential:found", "lateral:movement_executed", "privesc:escalation_found",
            "ember:agent_registered", "ember:task_complete", "ember:burn_response",
            "job:completed", "job:failed",
          ];

          if (relevantTypes.includes(parsed.type) || parsed.type.startsWith("llm:")) {
            const liveEvent: WsLiveEvent = {
              id: `ws_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
              type: parsed.type,
              timestamp: parsed.timestamp,
              engagementId: parsed.engagementId,
              data: parsed.data,
            };
            setLiveEvents((prev) => [liveEvent, ...prev].slice(0, maxEvents));
          }
        } catch {
          // Ignore malformed messages
        }
      };

      ws.onclose = () => {
        setWsStatus("disconnected");
        wsRef.current = null;
        // Exponential backoff reconnect
        if (!isPaused) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000);
          reconnectAttempts.current++;
          reconnectTimerRef.current = setTimeout(connect, delay);
        }
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch {
      setWsStatus("disconnected");
    }
  }, [isPaused]);

  useEffect(() => {
    if (!isPaused) {
      connect();
    } else {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      setWsStatus("disconnected");
    }

    return () => {
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [isPaused, connect]);

  const clearEvents = useCallback(() => setLiveEvents([]), []);

  return { wsStatus, liveEvents, clearEvents };
}

// ─── Event Formatting Helpers ───────────────────────────────────────────────

function getEventIcon(type: string) {
  if (type.startsWith("llm:decision")) return Brain;
  if (type.startsWith("llm:delegation")) return Bot;
  if (type.startsWith("llm:stealth")) return Shield;
  if (type.startsWith("llm:training")) return TrendingUp;
  if (type.startsWith("llm:shadow")) return Eye;
  if (type.startsWith("llm:engagement")) return Target;
  if (type.startsWith("exploit:")) return Crosshair;
  if (type.startsWith("agent:")) return Cpu;
  if (type.startsWith("credential:")) return Lock;
  if (type.startsWith("lateral:")) return Network;
  if (type.startsWith("opsec:")) return AlertTriangle;
  if (type.startsWith("ember:")) return Zap;
  if (type.startsWith("engagement:")) return Activity;
  if (type.startsWith("job:")) return Clock;
  return Radio;
}

function getEventColor(type: string) {
  if (type === "llm:stealth_alert" || type.includes("burn")) return "text-red-400";
  if (type === "llm:decision") return "text-purple-400";
  if (type === "llm:delegation") return "text-cyan-400";
  if (type.includes("error") || type.includes("failed")) return "text-red-400";
  if (type.includes("success") || type.includes("complete")) return "text-emerald-400";
  if (type.includes("credential")) return "text-amber-400";
  return "text-blue-400";
}

function formatEventTitle(evt: WsLiveEvent): string {
  const d = evt.data;
  switch (evt.type) {
    case "llm:decision":
      return `${d.agent || "LLM"} → ${d.decisionType || d.action || "decision"} (${(d.confidence * 100).toFixed(0)}% conf)`;
    case "llm:delegation":
      return `${d.fromAgent} delegated to ${d.toAgent}: ${d.taskType}`;
    case "llm:stealth_alert":
      return `STEALTH ALERT: ${d.agent} score ${(d.stealthScore * 100).toFixed(0)}% (threshold ${(d.threshold * 100).toFixed(0)}%)`;
    case "llm:training_captured":
      return `Training captured: ${d.exampleCount} examples from ${d.agent} (${d.quality})`;
    case "llm:shadow_test_result":
      return `Shadow test: ${d.configName} → ${d.winner} wins (${d.metric})`;
    case "llm:engagement_progress":
      return `${d.engagementName}: ${d.phase} (${d.progress}%) — ${d.findingsCount} findings`;
    case "exploit:fired":
      return `Exploit fired: ${d.module} → ${d.targetIp}:${d.targetPort}`;
    case "exploit:result":
      return `Exploit ${d.success ? "SUCCESS" : "FAILED"}: ${d.module} → ${d.targetIp}`;
    case "agent:deployed":
      return `Agent deployed: ${d.paw} on ${d.host} (${d.platform})`;
    case "credential:found":
      return `Credential found: ${d.username}@${d.target} via ${d.tool}`;
    case "ember:task_complete":
      return `Ember task: ${d.taskType} on ${d.agentId} → ${d.status}`;
    case "ember:burn_response":
      return `BURN: ${d.agentId} detected ${d.burnIndicator} → ${d.action}`;
    case "opsec:burn_detected":
      return `OPSEC burn: ${d.indicator} (${d.severity})`;
    case "engagement:phase_changed":
      return `Phase: ${d.previousPhase} → ${d.newPhase}`;
    case "job:completed":
      return `Job complete: ${d.type} in ${d.durationMs}ms (${d.findingsCount ?? 0} findings)`;
    case "job:failed":
      return `Job failed: ${d.type} — ${d.error}`;
    default:
      return `${evt.type}: ${JSON.stringify(d).slice(0, 80)}`;
  }
}

function formatEventDetail(evt: WsLiveEvent): string | null {
  const d = evt.data;
  switch (evt.type) {
    case "llm:decision":
      return d.reasoning || null;
    case "llm:delegation":
      return d.reason || null;
    case "llm:stealth_alert":
      return d.recommendation || null;
    default:
      return null;
  }
}

// ─── Component ──────────────────────────────────────────────────────────────

export default function RealtimeMonitor() {
  const [isPaused, setIsPaused] = useState(false);
  const [selectedEngagement, setSelectedEngagement] = useState<number | null>(null);
  const [wsEventFilter, setWsEventFilter] = useState<"all" | "llm" | "ops" | "stealth">("all");

  const { wsStatus, liveEvents, clearEvents } = useWebSocket(isPaused);

  // Polling queries as data backbone — WS events overlay in real-time
  const { data: activeData } = trpc.realtimeMonitor.getActiveEngagements.useQuery(
    undefined,
    { refetchInterval: isPaused ? false : 10000 }
  );

  const { data: decisionFeed } = trpc.realtimeMonitor.getLiveDecisionFeed.useQuery(
    { limit: 50, engagementId: selectedEngagement ?? undefined },
    { refetchInterval: isPaused ? false : 8000 }
  );

  const { data: telemetryFeed } = trpc.realtimeMonitor.getLiveTelemetryFeed.useQuery(
    { limit: 30 },
    { refetchInterval: isPaused ? false : 8000 }
  );

  const { data: delegationFeed } = trpc.realtimeMonitor.getAgentDelegationFeed.useQuery(
    { limit: 30 },
    { refetchInterval: isPaused ? false : 8000 }
  );

  const { data: timelineData } = trpc.realtimeMonitor.getEngagementTimeline.useQuery(
    { engagementId: selectedEngagement ?? 0, limit: 50 },
    { enabled: !!selectedEngagement, refetchInterval: isPaused ? false : 8000 }
  );

  const liveStats = telemetryFeed?.liveStats;

  // Filter WS events
  const filteredWsEvents = useMemo(() => {
    let filtered = liveEvents;
    if (selectedEngagement) {
      filtered = filtered.filter(
        (e) => !e.engagementId || e.engagementId === selectedEngagement
      );
    }
    switch (wsEventFilter) {
      case "llm":
        return filtered.filter((e) => e.type.startsWith("llm:"));
      case "ops":
        return filtered.filter(
          (e) =>
            e.type.startsWith("exploit:") ||
            e.type.startsWith("agent:") ||
            e.type.startsWith("ember:") ||
            e.type.startsWith("credential:") ||
            e.type.startsWith("lateral:") ||
            e.type.startsWith("job:")
        );
      case "stealth":
        return filtered.filter(
          (e) =>
            e.type === "llm:stealth_alert" ||
            e.type.startsWith("opsec:") ||
            e.type === "ember:burn_response"
        );
      default:
        return filtered;
    }
  }, [liveEvents, selectedEngagement, wsEventFilter]);

  // WS status indicator
  const wsStatusColor =
    wsStatus === "connected"
      ? "text-emerald-400"
      : wsStatus === "connecting"
      ? "text-amber-400"
      : "text-red-400";
  const wsStatusLabel =
    wsStatus === "connected"
      ? "WS Connected"
      : wsStatus === "connecting"
      ? "Connecting..."
      : "WS Disconnected";

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Radio className="h-6 w-6 text-emerald-400 animate-pulse" />
            Real-Time Engagement Monitor
          </h1>
          <p className="text-muted-foreground mt-1">
            Live WebSocket feed — LLM decisions, agent delegations, and engagement events stream in real time
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* WS Status */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-card border border-border/50">
            <div className={`w-2 h-2 rounded-full ${
              wsStatus === "connected" ? "bg-emerald-400 animate-pulse" :
              wsStatus === "connecting" ? "bg-amber-400 animate-pulse" :
              "bg-red-400"
            }`} />
            <span className={`text-xs font-medium ${wsStatusColor}`}>{wsStatusLabel}</span>
          </div>
          {/* Live/Paused */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-card border border-border/50">
            {isPaused ? (
              <WifiOff className="h-4 w-4 text-red-400" />
            ) : (
              <Wifi className="h-4 w-4 text-emerald-400 animate-pulse" />
            )}
            <span className="text-xs font-medium">{isPaused ? "Paused" : "Live"}</span>
          </div>
          <Button variant="outline" size="sm" onClick={() => setIsPaused(!isPaused)}>
            {isPaused ? <Play className="h-4 w-4 mr-1" /> : <Pause className="h-4 w-4 mr-1" />}
            {isPaused ? "Resume" : "Pause"}
          </Button>
        </div>
      </div>

      {/* Live Stats Bar */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-3 flex items-center justify-between">
            <div>
              <p className="text-[10px] text-muted-foreground uppercase">Active Engagements</p>
              <p className="text-xl font-bold">{activeData?.totalActive ?? 0}</p>
            </div>
            <Target className="h-6 w-6 text-cyan-400 opacity-60" />
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-3 flex items-center justify-between">
            <div>
              <p className="text-[10px] text-muted-foreground uppercase">LLM Calls (5min)</p>
              <p className="text-xl font-bold">{liveStats?.callsLast5min ?? 0}</p>
            </div>
            <Brain className="h-6 w-6 text-purple-400 opacity-60" />
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-3 flex items-center justify-between">
            <div>
              <p className="text-[10px] text-muted-foreground uppercase">Success Rate</p>
              <p className="text-xl font-bold text-emerald-400">{liveStats?.successRate ?? 0}%</p>
            </div>
            <TrendingUp className="h-6 w-6 text-emerald-400 opacity-60" />
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-3 flex items-center justify-between">
            <div>
              <p className="text-[10px] text-muted-foreground uppercase">WS Events</p>
              <p className="text-xl font-bold text-cyan-400">{liveEvents.length}</p>
            </div>
            <Radio className="h-6 w-6 text-cyan-400 opacity-60" />
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-3 flex items-center justify-between">
            <div>
              <p className="text-[10px] text-muted-foreground uppercase">Avg Latency</p>
              <p className="text-xl font-bold">{liveStats?.avgLatency ?? 0}ms</p>
            </div>
            <Clock className="h-6 w-6 text-blue-400 opacity-60" />
          </CardContent>
        </Card>
      </div>

      {/* Main Content: 3-column layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left: Active Engagements */}
        <Card className="border-border/50 lg:col-span-1">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Target className="h-4 w-4 text-cyan-400" />
              Active Engagements
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <ScrollArea className="h-[250px]">
              <div className="space-y-1 p-3">
                {activeData?.engagements.map((eng) => (
                  <div
                    key={eng.id}
                    className={`p-3 rounded-lg border cursor-pointer transition-all ${
                      selectedEngagement === eng.id
                        ? "border-cyan-500/50 bg-cyan-500/10"
                        : "border-border/30 bg-card/30 hover:bg-card/50"
                    }`}
                    onClick={() => setSelectedEngagement(selectedEngagement === eng.id ? null : eng.id)}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium truncate flex-1">{eng.name}</span>
                      <Badge
                        variant={eng.status === "active" ? "default" : "secondary"}
                        className="text-[10px] ml-2"
                      >
                        {eng.status}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <span className="capitalize">{eng.currentPhase?.replace(/_/g, " ")}</span>
                      <span>|</span>
                      <span>{eng.stats.findings} findings</span>
                      <span>|</span>
                      <span>{eng.stats.shells} shells</span>
                    </div>
                    {eng.latestEvent && (
                      <div className="mt-1.5 flex items-center gap-1.5">
                        <div className={`w-1.5 h-1.5 rounded-full ${
                          eng.latestEvent.severity === "critical" ? "bg-red-400 animate-pulse" :
                          eng.latestEvent.severity === "high" ? "bg-orange-400" :
                          "bg-blue-400"
                        }`} />
                        <span className="text-[10px] text-muted-foreground truncate">
                          {eng.latestEvent.title}
                        </span>
                      </div>
                    )}
                  </div>
                ))}
                {(!activeData?.engagements || activeData.engagements.length === 0) && (
                  <div className="text-center py-8 text-muted-foreground text-sm">
                    No active engagements
                  </div>
                )}
              </div>
            </ScrollArea>

            {/* Live WS Event Stream (below engagements) */}
            <div className="border-t border-border/30">
              <div className="p-3 pb-1 flex items-center justify-between">
                <h4 className="text-xs font-medium text-muted-foreground uppercase flex items-center gap-1.5">
                  <Radio className={`h-3 w-3 ${wsStatus === "connected" ? "text-emerald-400 animate-pulse" : "text-red-400"}`} />
                  Live WS Stream
                </h4>
                <div className="flex items-center gap-1">
                  {(["all", "llm", "ops", "stealth"] as const).map((f) => (
                    <button
                      key={f}
                      className={`text-[10px] px-2 py-0.5 rounded-full border transition-colors ${
                        wsEventFilter === f
                          ? "bg-cyan-500/20 border-cyan-500/50 text-cyan-400"
                          : "border-border/30 text-muted-foreground hover:text-foreground"
                      }`}
                      onClick={() => setWsEventFilter(f)}
                    >
                      {f.toUpperCase()}
                    </button>
                  ))}
                  {liveEvents.length > 0 && (
                    <button
                      className="text-[10px] px-2 py-0.5 rounded-full border border-red-500/30 text-red-400 hover:bg-red-500/10 ml-1"
                      onClick={clearEvents}
                    >
                      Clear
                    </button>
                  )}
                </div>
              </div>
              <ScrollArea className="h-[200px]">
                <div className="space-y-0.5 px-3 pb-3">
                  {filteredWsEvents.map((evt) => {
                    const Icon = getEventIcon(evt.type);
                    const color = getEventColor(evt.type);
                    const detail = formatEventDetail(evt);
                    return (
                      <div key={evt.id} className="flex items-start gap-2 p-1.5 rounded hover:bg-muted/20 transition-colors">
                        <Icon className={`h-3.5 w-3.5 mt-0.5 shrink-0 ${color}`} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="text-[10px] text-muted-foreground font-mono">
                              {new Date(evt.timestamp).toLocaleTimeString()}
                            </span>
                            {evt.engagementId && (
                              <Badge variant="outline" className="text-[9px] h-4 px-1">
                                #{evt.engagementId}
                              </Badge>
                            )}
                          </div>
                          <p className="text-xs truncate">{formatEventTitle(evt)}</p>
                          {detail && (
                            <p className="text-[10px] text-muted-foreground truncate">{detail}</p>
                          )}
                        </div>
                      </div>
                    );
                  })}
                  {filteredWsEvents.length === 0 && (
                    <div className="text-center py-6 text-muted-foreground text-xs">
                      {wsStatus === "connected"
                        ? "Waiting for live events..."
                        : "WebSocket disconnected — using polling fallback"}
                    </div>
                  )}
                </div>
              </ScrollArea>
            </div>
          </CardContent>
        </Card>

        {/* Center & Right: Tabbed Data Feeds */}
        <Card className="border-border/50 lg:col-span-2">
          <Tabs defaultValue="decisions" className="h-full">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Activity className="h-4 w-4 text-emerald-400" />
                  Live Feed
                  {selectedEngagement && (
                    <Badge variant="outline" className="text-[10px] ml-2">
                      Engagement #{selectedEngagement}
                      <button
                        className="ml-1 text-muted-foreground hover:text-foreground"
                        onClick={() => setSelectedEngagement(null)}
                      >
                        ×
                      </button>
                    </Badge>
                  )}
                </CardTitle>
                <TabsList className="h-8">
                  <TabsTrigger value="decisions" className="text-xs h-7 px-3">
                    <Brain className="h-3 w-3 mr-1" /> Decisions
                  </TabsTrigger>
                  <TabsTrigger value="delegations" className="text-xs h-7 px-3">
                    <Bot className="h-3 w-3 mr-1" /> Delegations
                  </TabsTrigger>
                  <TabsTrigger value="telemetry" className="text-xs h-7 px-3">
                    <Zap className="h-3 w-3 mr-1" /> Telemetry
                  </TabsTrigger>
                  {selectedEngagement && (
                    <TabsTrigger value="timeline" className="text-xs h-7 px-3">
                      <Clock className="h-3 w-3 mr-1" /> Timeline
                    </TabsTrigger>
                  )}
                </TabsList>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {/* Decisions Feed */}
              <TabsContent value="decisions" className="m-0">
                <ScrollArea className="h-[460px]">
                  <div className="space-y-0.5 p-3">
                    {decisionFeed?.decisions.map((dec) => {
                      const StatusIcon = STATUS_ICONS[dec.outcome ?? "pending"] || Clock;
                      const statusColor = STATUS_COLORS[dec.outcome ?? "pending"] || "text-gray-400";
                      return (
                        <div key={dec.id} className="flex items-start gap-3 p-2.5 rounded-lg hover:bg-muted/20 transition-colors border-l-2 border-transparent hover:border-cyan-500/30">
                          <StatusIcon className={`h-4 w-4 mt-0.5 shrink-0 ${statusColor}`} />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-0.5">
                              <Badge variant={dec.isSpecialist ? "default" : "secondary"} className="text-[10px]">
                                {dec.agentName}
                              </Badge>
                              <span className="text-[10px] text-muted-foreground capitalize">{dec.phase}</span>
                              {dec.stealthScore != null && (
                                <span className="text-[10px] text-muted-foreground">
                                  stealth: {(Number(dec.stealthScore) * 100).toFixed(0)}%
                                </span>
                              )}
                              <span className="text-[10px] text-muted-foreground ml-auto">
                                {dec.latencyMs}ms | Eng #{dec.engagementId}
                              </span>
                            </div>
                            <p className="text-xs truncate">{dec.decision}</p>
                            {dec.reasoning && (
                              <p className="text-[10px] text-muted-foreground mt-0.5 truncate">{dec.reasoning}</p>
                            )}
                          </div>
                        </div>
                      );
                    })}
                    {(!decisionFeed?.decisions || decisionFeed.decisions.length === 0) && (
                      <div className="text-center py-12 text-muted-foreground text-sm">
                        No decisions recorded yet
                      </div>
                    )}
                  </div>
                </ScrollArea>
              </TabsContent>

              {/* Delegations Feed */}
              <TabsContent value="delegations" className="m-0">
                <ScrollArea className="h-[460px]">
                  <div className="p-3 space-y-4">
                    {delegationFeed?.agentFrequency && delegationFeed.agentFrequency.length > 0 && (
                      <div className="space-y-2">
                        <h4 className="text-xs font-medium text-muted-foreground uppercase">Agent Activity (24h)</h4>
                        {delegationFeed.agentFrequency.map((agent) => {
                          const maxCount = delegationFeed.agentFrequency[0]?.count ?? 1;
                          const pct = (agent.count / maxCount) * 100;
                          return (
                            <div key={agent.caller} className="flex items-center gap-3">
                              <span className="text-xs w-28 truncate">{agent.agentName}</span>
                              <div className="flex-1 h-4 bg-muted/30 rounded overflow-hidden">
                                <div
                                  className="h-full bg-gradient-to-r from-cyan-500/60 to-cyan-400/40 rounded transition-all duration-500"
                                  style={{ width: `${pct}%` }}
                                />
                              </div>
                              <span className="text-xs font-mono w-8 text-right">{agent.count}</span>
                              <span className={`text-xs w-10 text-right ${agent.successRate >= 80 ? "text-emerald-400" : "text-amber-400"}`}>
                                {agent.successRate}%
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    )}
                    <div className="space-y-1">
                      <h4 className="text-xs font-medium text-muted-foreground uppercase">Recent Delegations</h4>
                      {delegationFeed?.delegations.map((del) => {
                        const StatusIcon = STATUS_ICONS[del.outcome ?? "pending"] || Clock;
                        const statusColor = STATUS_COLORS[del.outcome ?? "pending"] || "text-gray-400";
                        return (
                          <div key={del.id} className="flex items-center gap-2 p-2 rounded hover:bg-muted/20 text-xs">
                            <StatusIcon className={`h-3.5 w-3.5 shrink-0 ${statusColor}`} />
                            <Badge variant={del.isSpecialist ? "default" : "outline"} className="text-[10px]">
                              {del.agentName}
                            </Badge>
                            <ChevronRight className="h-3 w-3 text-muted-foreground" />
                            <span className="capitalize text-muted-foreground">{del.phase}</span>
                            <span className="flex-1 truncate">{del.decision}</span>
                            <span className="text-muted-foreground shrink-0">Eng #{del.engagementId}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </ScrollArea>
              </TabsContent>

              {/* Telemetry Feed */}
              <TabsContent value="telemetry" className="m-0">
                <ScrollArea className="h-[460px]">
                  <div className="p-3 space-y-0.5">
                    {telemetryFeed?.telemetry.map((t) => {
                      const StatusIcon = STATUS_ICONS[t.llmStatus] || Clock;
                      const statusColor = STATUS_COLORS[t.llmStatus] || "text-gray-400";
                      return (
                        <div key={t.id} className="flex items-center gap-3 p-2 rounded hover:bg-muted/20 text-xs">
                          <StatusIcon className={`h-3.5 w-3.5 shrink-0 ${statusColor}`} />
                          <span className="font-mono text-[10px] text-muted-foreground w-14 shrink-0">{t.model?.split("-").slice(0, 2).join("-")}</span>
                          <Badge variant="outline" className="text-[10px]">{t.agentName}</Badge>
                          <span className={`font-mono shrink-0 ${
                            (t.latencyMs ?? 0) <= 2000 ? "text-emerald-400" :
                            (t.latencyMs ?? 0) <= 5000 ? "text-amber-400" : "text-red-400"
                          }`}>
                            {t.latencyMs}ms
                          </span>
                          <span className="text-muted-foreground">{t.tokensIn}→{t.tokensOut} tok</span>
                          {t.errorMessage && (
                            <span className="text-red-400 truncate flex-1">{t.errorMessage}</span>
                          )}
                          {t.retryCount != null && t.retryCount > 0 && (
                            <Badge variant="destructive" className="text-[10px]">retry×{t.retryCount}</Badge>
                          )}
                          <span className="text-muted-foreground ml-auto shrink-0">
                            {t.calledAt ? new Date(t.calledAt).toLocaleTimeString() : ""}
                          </span>
                        </div>
                      );
                    })}
                    {(!telemetryFeed?.telemetry || telemetryFeed.telemetry.length === 0) && (
                      <div className="text-center py-12 text-muted-foreground text-sm">
                        No telemetry data yet
                      </div>
                    )}
                  </div>
                </ScrollArea>
              </TabsContent>

              {/* Engagement Timeline */}
              {selectedEngagement && (
                <TabsContent value="timeline" className="m-0">
                  <ScrollArea className="h-[460px]">
                    <div className="p-3 space-y-1">
                      {timelineData?.events.map((evt) => {
                        const EvtIcon = EVENT_TYPE_ICONS[evt.eventType] || Activity;
                        const sevClass = SEVERITY_COLORS[evt.severity ?? "info"] || SEVERITY_COLORS.info;
                        return (
                          <div key={evt.id} className="flex items-start gap-3 p-2.5 rounded-lg hover:bg-muted/20">
                            <div className={`p-1 rounded border ${sevClass}`}>
                              <EvtIcon className="h-3.5 w-3.5" />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-0.5">
                                <span className="text-xs font-medium">{evt.title}</span>
                                <Badge variant="outline" className="text-[10px] capitalize">{evt.phase}</Badge>
                                {evt.attackTechnique && (
                                  <Badge variant="secondary" className="text-[10px]">{evt.attackTechnique}</Badge>
                                )}
                              </div>
                              {evt.description && (
                                <p className="text-[10px] text-muted-foreground">{evt.description}</p>
                              )}
                              <div className="flex items-center gap-2 mt-1 text-[10px] text-muted-foreground">
                                {evt.targetHost && <span>{evt.targetHost}{evt.targetPort ? `:${evt.targetPort}` : ""}</span>}
                                {evt.sourceModule && <span>via {evt.sourceModule}</span>}
                                <span className="ml-auto">{new Date(evt.timestamp).toLocaleString()}</span>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                      {(!timelineData?.events || timelineData.events.length === 0) && (
                        <div className="text-center py-12 text-muted-foreground text-sm">
                          No timeline events for this engagement
                        </div>
                      )}
                    </div>
                  </ScrollArea>
                </TabsContent>
              )}
            </CardContent>
          </Tabs>
        </Card>
      </div>
    </div>
  );
}
