import { useState, useMemo, useEffect } from "react";
import { trpc } from "@/lib/trpc";
import { useTimelineEvents, type WsEvent } from "@/hooks/useWebSocket";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  Search, Radar, FileCode, Mail, Globe, Zap, Bot, Radio,
  Download, Workflow, Play, ChevronRight, Filter, RefreshCw,
  Clock, Target, Shield, AlertTriangle, Activity, Eye,
  ArrowRight, CheckCircle2, Circle, XCircle, Loader2,
  ChevronDown, ChevronUp, BarChart3, TrendingUp
} from "lucide-react";
import AppShell from "@/components/AppShell";

// ─── Types ───────────────────────────────────────────────────────────────────

type KillChainPhase =
  | "reconnaissance"
  | "weaponization"
  | "delivery"
  | "exploitation"
  | "installation"
  | "command_control"
  | "actions_on_objectives";

interface TimelineEvent {
  id: string;
  engagementId: number | null;
  timestamp: number;
  phase: KillChainPhase;
  source: string;
  severity: string;
  title: string;
  description: string;
  icon: string;
  color: string;
  sourceRecordId: number | string;
  targetDomain?: string;
  cveId?: string;
  msfModule?: string;
  calderaOperationId?: string;
  gophishCampaignId?: number;
  status: string;
  details: Record<string, any>;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const PHASES: { key: KillChainPhase; label: string; shortLabel: string; icon: any; color: string }[] = [
  { key: "reconnaissance", label: "Reconnaissance", shortLabel: "Recon", icon: Search, color: "cyan" },
  { key: "weaponization", label: "Weaponization", shortLabel: "Weapon", icon: FileCode, color: "yellow" },
  { key: "delivery", label: "Delivery", shortLabel: "Deliver", icon: Mail, color: "emerald" },
  { key: "exploitation", label: "Exploitation", shortLabel: "Exploit", icon: Zap, color: "orange" },
  { key: "installation", label: "Installation", shortLabel: "Install", icon: Bot, color: "red" },
  { key: "command_control", label: "Command & Control", shortLabel: "C2", icon: Radio, color: "violet" },
  { key: "actions_on_objectives", label: "Actions on Objectives", shortLabel: "Actions", icon: Target, color: "amber" },
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

const STATUS_ICONS: Record<string, any> = {
  success: CheckCircle2,
  running: Loader2,
  pending: Circle,
  failed: XCircle,
  info: Eye,
};

const ICON_MAP: Record<string, any> = {
  Search, Radar, FileCode, Mail, Globe, Zap, Bot, Radio,
  Download, Workflow, Play, Activity, Shield, Target,
};

function getIcon(name: string) {
  return ICON_MAP[name] || Activity;
}

function formatDuration(ms: number | null): string {
  if (!ms) return "—";
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${minutes % 60}m`;
  const days = Math.floor(hours / 24);
  return `${days}d ${hours % 24}h`;
}

function formatTimestamp(ts: number): string {
  return new Date(ts).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit"
  });
}

// ─── Component ───────────────────────────────────────────────────────────────

export default function EngagementTimeline() {
  // Filters
  const [selectedEngagement, setSelectedEngagement] = useState<number | undefined>();
  const [selectedPhases, setSelectedPhases] = useState<KillChainPhase[]>([]);
  const [selectedSeverity, setSelectedSeverity] = useState<string[]>([]);
  const [targetDomain, setTargetDomain] = useState("");
  const [showFilters, setShowFilters] = useState(false);

  // Detail modal
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null);

  // Engagement summary
  const [summaryEngagementId, setSummaryEngagementId] = useState<number | null>(null);

  // Data queries
  const timelineQuery = trpc.engagementTimeline.getTimeline.useQuery({
    engagementId: selectedEngagement,
    phases: selectedPhases.length > 0 ? selectedPhases : undefined,
    severity: selectedSeverity.length > 0 ? selectedSeverity as any : undefined,
    targetDomain: targetDomain || undefined,
    limit: 500,
  }, { refetchInterval: 30000 });

  const engagementsQuery = trpc.engagementTimeline.listEngagementsWithStats.useQuery(
    { limit: 20 },
    { refetchInterval: 60000 }
  );

  const summaryQuery = trpc.engagementTimeline.getEngagementSummary.useQuery(
    { engagementId: summaryEngagementId! },
    { enabled: !!summaryEngagementId }
  );

  // Real-time WebSocket events
  const { events: wsEvents, status: wsStatus, isConnected, clearEvents: clearWsEvents } = useTimelineEvents(selectedEngagement);

  // Convert WS events to timeline events for live display
  const liveEvents = useMemo(() => {
    return wsEvents.map((ws: WsEvent, i: number): TimelineEvent => {
      const phaseMap: Record<string, KillChainPhase> = {
        'exploit:fired': 'exploitation', 'exploit:result': 'exploitation', 'exploit:progress': 'exploitation', 'exploit:session_opened': 'exploitation',
        'agent:deployed': 'installation', 'agent:checkin': 'command_control', 'agent:lost': 'command_control',
        'operation:started': 'actions_on_objectives', 'operation:step_complete': 'actions_on_objectives', 'operation:finished': 'actions_on_objectives',
        'recon:started': 'reconnaissance', 'recon:complete': 'reconnaissance', 'recon:finding': 'reconnaissance',
        'campaign:launched': 'delivery', 'campaign:email_sent': 'delivery', 'campaign:email_opened': 'delivery', 'campaign:link_clicked': 'delivery', 'campaign:creds_submitted': 'delivery',
        'pipeline:started': 'reconnaissance', 'pipeline:step_complete': 'weaponization', 'pipeline:finished': 'weaponization',
        'domain:scan_complete': 'reconnaissance', 'domain:typosquat_purchased': 'weaponization',
        'msf:server_provisioned': 'weaponization', 'msf:server_ready': 'weaponization', 'msf:server_destroyed': 'weaponization',
        'system:notification': 'reconnaissance', 'system:alert': 'reconnaissance',
      };
      return {
        id: `live-${i}-${ws.timestamp}`,
        engagementId: ws.engagementId ?? null,
        timestamp: ws.timestamp,
        phase: phaseMap[ws.type] || 'reconnaissance',
        source: ws.type.split(':')[0],
        severity: ws.data?.severity || 'info',
        title: ws.data?.title || ws.type.replace(/[:.]/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase()),
        description: ws.data?.message || ws.data?.description || JSON.stringify(ws.data).slice(0, 200),
        icon: ws.type.includes('exploit') ? 'Zap' : ws.type.includes('agent') ? 'Bot' : ws.type.includes('recon') ? 'Search' : ws.type.includes('campaign') ? 'Mail' : 'Activity',
        color: ws.type.includes('exploit') ? 'orange' : ws.type.includes('agent') ? 'red' : ws.type.includes('recon') ? 'cyan' : ws.type.includes('campaign') ? 'emerald' : 'violet',
        sourceRecordId: ws.data?.jobId || ws.data?.scanId || ws.data?.campaignId || 0,
        status: ws.data?.success === false ? 'failed' : ws.data?.success === true ? 'success' : 'info',
        details: ws.data,
      };
    });
  }, [wsEvents]);

  const allEvents = useMemo(() => {
    const historical = timelineQuery.data?.events || [];
    // Merge live events at the top, dedup by timestamp proximity
    const merged = [...liveEvents, ...historical];
    const seen = new Set<string>();
    return merged.filter(e => {
      const key = `${e.phase}-${e.source}-${Math.floor(e.timestamp / 1000)}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [liveEvents, timelineQuery.data?.events]);

  // Auto-refetch when new WS events arrive
  useEffect(() => {
    if (wsEvents.length > 0) {
      timelineQuery.refetch();
    }
  }, [wsEvents.length]);

  const events = allEvents;
  const stats = timelineQuery.data?.stats;
  const engagementsList = engagementsQuery.data || [];

  // Group events by date
  const groupedEvents = useMemo(() => {
    const groups: Record<string, TimelineEvent[]> = {};
    for (const event of events) {
      const dateKey = new Date(event.timestamp).toLocaleDateString(undefined, {
        weekday: "long", year: "numeric", month: "long", day: "numeric"
      });
      if (!groups[dateKey]) groups[dateKey] = [];
      groups[dateKey].push(event);
    }
    return groups;
  }, [events]);

  const togglePhase = (phase: KillChainPhase) => {
    setSelectedPhases(prev =>
      prev.includes(phase) ? prev.filter(p => p !== phase) : [...prev, phase]
    );
  };

  const toggleSeverity = (sev: string) => {
    setSelectedSeverity(prev =>
      prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]
    );
  };

  return (
    <AppShell activePath="/engagement-timeline">
      <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">Engagement Timeline</h1>
        <div className="flex items-center gap-3 mt-1">
          <p className="text-sm text-muted-foreground">
            Unified kill chain visualization — events from OSINT, phishing, exploit frameworks, and adversary emulation.
          </p>
          <div className="flex items-center gap-1.5 ml-auto">
            <span className={`h-2 w-2 rounded-full ${isConnected ? 'bg-emerald-500 animate-pulse' : wsStatus === 'connecting' ? 'bg-yellow-500 animate-pulse' : 'bg-red-500'}`} />
            <span className="text-xs text-muted-foreground">
              {isConnected ? 'Live' : wsStatus === 'connecting' ? 'Connecting...' : 'Offline'}
            </span>
            {liveEvents.length > 0 && (
              <Badge variant="secondary" className="text-[10px] px-1.5 py-0 h-4 bg-emerald-500/20 text-emerald-400">
                {liveEvents.length} new
              </Badge>
            )}
          </div>
        </div>
      </div>

      {/* Kill Chain Progress Bar */}
      {stats && (
        <Card className="border-border/50 bg-card/50 backdrop-blur">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-foreground uppercase tracking-wider">Kill Chain Coverage</h3>
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <Activity className="h-3 w-3" />
                  {stats.totalEvents} events
                </span>
                {stats.timeToFirstExploit && (
                  <span className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    Recon→Exploit: {formatDuration(stats.timeToFirstExploit)}
                  </span>
                )}
                {stats.timeToFirstAgent && (
                  <span className="flex items-center gap-1">
                    <Bot className="h-3 w-3" />
                    Recon→Agent: {formatDuration(stats.timeToFirstAgent)}
                  </span>
                )}
              </div>
            </div>

            {/* Phase Progress */}
            <div className="flex items-stretch gap-1">
              {PHASES.map((phase, idx) => {
                const count = stats.byPhase[phase.key] || 0;
                const isReached = count > 0;
                const isSelected = selectedPhases.includes(phase.key);
                const PhaseIcon = phase.icon;

                return (
                  <button
                    key={phase.key}
                    onClick={() => togglePhase(phase.key)}
                    className={`flex-1 relative group transition-all duration-200 rounded-lg border p-3 text-center
                      ${isReached
                        ? `border-${phase.color}-500/40 bg-${phase.color}-500/10 hover:bg-${phase.color}-500/20`
                        : "border-border/30 bg-muted/20 hover:bg-muted/30 opacity-50"
                      }
                      ${isSelected ? `ring-2 ring-${phase.color}-500/60` : ""}
                    `}
                  >
                    <PhaseIcon className={`h-5 w-5 mx-auto mb-1 ${isReached ? `text-${phase.color}-400` : "text-muted-foreground"}`} />
                    <div className={`text-xs font-medium ${isReached ? "text-foreground" : "text-muted-foreground"}`}>
                      {phase.shortLabel}
                    </div>
                    <div className={`text-lg font-bold ${isReached ? `text-${phase.color}-400` : "text-muted-foreground"}`}>
                      {count}
                    </div>
                    {idx < PHASES.length - 1 && (
                      <ArrowRight className={`absolute -right-2.5 top-1/2 -translate-y-1/2 h-4 w-4 z-10 ${isReached ? `text-${phase.color}-500/60` : "text-border/40"}`} />
                    )}
                  </button>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Engagement Selector + Filters */}
      <div className="flex flex-col lg:flex-row gap-4">
        {/* Engagement Cards */}
        <div className="lg:w-72 shrink-0 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-foreground">Engagements</h3>
            <Button variant="ghost" size="sm" onClick={() => setSelectedEngagement(undefined)}
              className={!selectedEngagement ? "text-cyan-400" : "text-muted-foreground"}>
              All
            </Button>
          </div>

          <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1">
            {engagementsList.map((item: any) => (
              <button
                key={item.engagement.id}
                onClick={() => {
                  setSelectedEngagement(item.engagement.id);
                  setSummaryEngagementId(item.engagement.id);
                }}
                className={`w-full text-left rounded-lg border p-3 transition-all duration-150
                  ${selectedEngagement === item.engagement.id
                    ? "border-cyan-500/50 bg-cyan-500/10"
                    : "border-border/30 bg-card/50 hover:bg-card/80"
                  }
                `}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-foreground truncate">{item.engagement.name}</span>
                  <Badge variant="outline" className="text-[10px] shrink-0 ml-2">
                    {item.engagement.status}
                  </Badge>
                </div>
                <div className="text-xs text-muted-foreground truncate">{item.engagement.targetDomain || item.engagement.customerName}</div>
                <div className="flex items-center gap-2 mt-2">
                  {/* Mini phase indicators */}
                  {PHASES.map(phase => {
                    const count = item.stats.byPhase?.[phase.key] || 0;
                    return (
                      <div
                        key={phase.key}
                        className={`h-1.5 flex-1 rounded-full ${count > 0 ? `bg-${phase.color}-500` : "bg-muted/30"}`}
                        title={`${phase.label}: ${count} events`}
                      />
                    );
                  })}
                </div>
                <div className="text-[10px] text-muted-foreground mt-1">
                  {item.stats.totalEvents} events · {(item.stats.phasesReached || []).length}/7 phases
                </div>
              </button>
            ))}
            {engagementsList.length === 0 && (
              <div className="text-sm text-muted-foreground text-center py-8">
                No engagements found. Create one from the Engagements page.
              </div>
            )}
          </div>
        </div>

        {/* Main Timeline */}
        <div className="flex-1 min-w-0 space-y-4">
          {/* Toolbar */}
          <div className="flex items-center gap-2 flex-wrap">
            <Button variant="outline" size="sm" onClick={() => setShowFilters(!showFilters)}
              className="gap-1">
              <Filter className="h-3.5 w-3.5" />
              Filters
              {(selectedPhases.length > 0 || selectedSeverity.length > 0 || targetDomain) && (
                <Badge className="ml-1 bg-cyan-500/20 text-cyan-400 text-[10px]">
                  {selectedPhases.length + selectedSeverity.length + (targetDomain ? 1 : 0)}
                </Badge>
              )}
            </Button>
            <Button variant="outline" size="sm" onClick={() => timelineQuery.refetch()} className="gap-1">
              <RefreshCw className={`h-3.5 w-3.5 ${timelineQuery.isFetching ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            <div className="flex-1" />
            <span className="text-xs text-muted-foreground">
              {events.length} events
              {stats?.furthestPhase && (
                <> · Furthest: <span className="text-foreground font-medium">
                  {PHASES.find(p => p.key === stats.furthestPhase)?.label || stats.furthestPhase}
                </span></>
              )}
            </span>
          </div>

          {/* Filter Panel */}
          {showFilters && (
            <Card className="border-border/50 bg-card/50">
              <CardContent className="pt-4 space-y-3">
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">Target Domain</label>
                  <input
                    type="text"
                    value={targetDomain}
                    onChange={e => setTargetDomain(e.target.value)}
                    placeholder="e.g., example.com"
                    className="w-full bg-background border border-border rounded px-3 py-1.5 text-sm text-foreground"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">Severity</label>
                  <div className="flex gap-1 flex-wrap">
                    {["critical", "high", "medium", "low", "info"].map(sev => (
                      <button
                        key={sev}
                        onClick={() => toggleSeverity(sev)}
                        className={`px-2 py-0.5 rounded text-xs border transition-all
                          ${selectedSeverity.includes(sev)
                            ? SEVERITY_COLORS[sev]
                            : "border-border/30 text-muted-foreground hover:text-foreground"
                          }
                        `}
                      >
                        {sev}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <Button variant="ghost" size="sm" onClick={() => {
                    setSelectedPhases([]);
                    setSelectedSeverity([]);
                    setTargetDomain("");
                  }} className="text-xs">
                    Clear All
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Engagement Summary Panel */}
          {summaryEngagementId && summaryQuery.data && (
            <EngagementSummaryPanel
              summary={summaryQuery.data}
              onClose={() => setSummaryEngagementId(null)}
            />
          )}

          {/* Timeline Events */}
          {timelineQuery.isLoading ? (
            <div className="flex items-center justify-center py-20">
              <Loader2 className="h-8 w-8 animate-spin text-cyan-500" />
            </div>
          ) : events.length === 0 ? (
            <Card className="border-border/30 bg-card/30">
              <CardContent className="py-16 text-center">
                <Activity className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-foreground mb-2">No Timeline Events</h3>
                <p className="text-sm text-muted-foreground max-w-md mx-auto">
                  Events will appear here as you run OSINT scans, launch phishing campaigns,
                  execute exploits, and deploy adversary operations.
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-6">
              {Object.entries(groupedEvents).map(([dateLabel, dayEvents]) => (
                <div key={dateLabel}>
                  <div className="sticky top-0 z-10 bg-background/80 backdrop-blur py-2 mb-3">
                    <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                      {dateLabel}
                    </h4>
                  </div>

                  <div className="relative pl-6 border-l-2 border-border/30 space-y-3">
                    {dayEvents.map((event) => {
                      const EventIcon = getIcon(event.icon);
                      const StatusIcon = STATUS_ICONS[event.status] || Circle;
                      const phaseInfo = PHASES.find(p => p.key === event.phase);

                      return (
                        <button
                          key={event.id}
                          onClick={() => setSelectedEvent(event)}
                          className="w-full text-left group relative"
                        >
                          {/* Timeline dot */}
                          <div className={`absolute -left-[calc(1.5rem+5px)] w-2.5 h-2.5 rounded-full border-2 border-background
                            ${event.status === "success" ? "bg-emerald-500" :
                              event.status === "failed" ? "bg-red-500" :
                              event.status === "running" ? "bg-yellow-500 animate-pulse" :
                              "bg-muted-foreground/40"
                            }
                          `} />

                          <div className={`rounded-lg border p-3 transition-all duration-150
                            border-border/30 bg-card/50 hover:bg-card/80 hover:border-border/60
                            group-hover:shadow-lg group-hover:shadow-black/10
                          `}>
                            <div className="flex items-start gap-3">
                              {/* Icon */}
                              <div className={`shrink-0 w-9 h-9 rounded-lg flex items-center justify-center
                                bg-${phaseInfo?.color || "gray"}-500/15
                              `}>
                                <EventIcon className={`h-4.5 w-4.5 text-${phaseInfo?.color || "gray"}-400`} />
                              </div>

                              {/* Content */}
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 mb-0.5">
                                  <span className="text-sm font-medium text-foreground truncate">{event.title}</span>
                                  <Badge variant="outline" className={`text-[10px] shrink-0 ${SEVERITY_COLORS[event.severity] || ""}`}>
                                    {event.severity}
                                  </Badge>
                                  <StatusIcon className={`h-3.5 w-3.5 shrink-0
                                    ${event.status === "success" ? "text-emerald-400" :
                                      event.status === "failed" ? "text-red-400" :
                                      event.status === "running" ? "text-yellow-400 animate-spin" :
                                      "text-muted-foreground"
                                    }
                                  `} />
                                </div>
                                <p className="text-xs text-muted-foreground line-clamp-2">{event.description}</p>
                                <div className="flex items-center gap-3 mt-1.5 text-[10px] text-muted-foreground">
                                  <span>{formatTimestamp(event.timestamp)}</span>
                                  <Badge variant="outline" className="text-[9px] py-0">
                                    {phaseInfo?.label || event.phase}
                                  </Badge>
                                  {event.targetDomain && (
                                    <span className="text-cyan-400/70">{event.targetDomain}</span>
                                  )}
                                  {event.cveId && (
                                    <span className="text-orange-400/70">{event.cveId}</span>
                                  )}
                                </div>
                              </div>

                              <ChevronRight className="h-4 w-4 text-muted-foreground/30 group-hover:text-muted-foreground shrink-0 mt-1" />
                            </div>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Event Detail Modal */}
      <EventDetailModal event={selectedEvent} onClose={() => setSelectedEvent(null)} />
    </div>
    </AppShell>
  );
}

// ─── Engagement Summary Panel ────────────────────────────────────────────────

function EngagementSummaryPanel({ summary, onClose }: { summary: any; onClose: () => void }) {
  const [expanded, setExpanded] = useState(true);

  return (
    <Card className="border-cyan-500/30 bg-cyan-500/5">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-cyan-400" />
            {summary.engagement.name}
            <Badge variant="outline" className="text-[10px]">{summary.engagement.status}</Badge>
          </CardTitle>
          <div className="flex items-center gap-1">
            <Button variant="ghost" size="sm" onClick={() => setExpanded(!expanded)} className="h-7 w-7 p-0">
              {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </Button>
            <Button variant="ghost" size="sm" onClick={onClose} className="h-7 w-7 p-0 text-muted-foreground">
              ×
            </Button>
          </div>
        </div>
      </CardHeader>

      {expanded && (
        <CardContent className="space-y-4">
          {/* Key Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
            {[
              { label: "Recon Findings", value: summary.reconFindings, icon: Search, color: "cyan" },
              { label: "Exploits Tried", value: summary.exploitsAttempted, icon: Zap, color: "orange" },
              { label: "Exploits Won", value: summary.exploitsSucceeded, icon: CheckCircle2, color: "emerald" },
              { label: "Agents Deployed", value: summary.agentsDeployed, icon: Bot, color: "red" },
              { label: "Phishing Campaigns", value: summary.phishingCampaigns, icon: Mail, color: "yellow" },
              { label: "Typosquat Domains", value: summary.typosquatDomains, icon: Globe, color: "purple" },
            ].map(metric => {
              const MetricIcon = metric.icon;
              return (
                <div key={metric.label} className="text-center">
                  <MetricIcon className={`h-4 w-4 mx-auto mb-1 text-${metric.color}-400`} />
                  <div className={`text-xl font-bold text-${metric.color}-400`}>{metric.value}</div>
                  <div className="text-[10px] text-muted-foreground">{metric.label}</div>
                </div>
              );
            })}
          </div>

          {/* Kill Chain Progress */}
          <div>
            <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Kill Chain Progress</h4>
            <div className="space-y-1.5">
              {(summary.killChainProgress || []).map((phase: any) => {
                const phaseInfo = PHASES.find(p => p.key === phase.phase);
                const PhaseIcon = phaseInfo?.icon || Circle;
                return (
                  <div key={phase.phase} className="flex items-center gap-2">
                    <PhaseIcon className={`h-3.5 w-3.5 shrink-0 ${
                      phase.status === "completed" ? `text-${phaseInfo?.color || "gray"}-400` :
                      phase.status === "in_progress" ? "text-yellow-400 animate-pulse" :
                      "text-muted-foreground/30"
                    }`} />
                    <span className={`text-xs w-28 truncate ${phase.eventCount > 0 ? "text-foreground" : "text-muted-foreground/50"}`}>
                      {phase.label}
                    </span>
                    <div className="flex-1 h-1.5 bg-muted/20 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          phase.status === "completed" ? `bg-${phaseInfo?.color || "gray"}-500` :
                          phase.status === "in_progress" ? "bg-yellow-500" : ""
                        }`}
                        style={{ width: phase.eventCount > 0 ? `${Math.min(100, phase.eventCount * 10)}%` : "0%" }}
                      />
                    </div>
                    <span className="text-xs text-muted-foreground w-8 text-right">{phase.eventCount}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Timing Metrics */}
          {summary.timeline && (
            <div className="flex items-center gap-6 text-xs text-muted-foreground">
              {summary.timeline.timeToFirstExploit && (
                <span className="flex items-center gap-1">
                  <TrendingUp className="h-3 w-3 text-orange-400" />
                  Time to Exploit: <span className="text-foreground font-medium">{formatDuration(summary.timeline.timeToFirstExploit)}</span>
                </span>
              )}
              {summary.timeline.timeToFirstAgent && (
                <span className="flex items-center gap-1">
                  <Bot className="h-3 w-3 text-red-400" />
                  Time to Agent: <span className="text-foreground font-medium">{formatDuration(summary.timeline.timeToFirstAgent)}</span>
                </span>
              )}
              {summary.timeline.timeToObjective && (
                <span className="flex items-center gap-1">
                  <Target className="h-3 w-3 text-amber-400" />
                  Time to Objective: <span className="text-foreground font-medium">{formatDuration(summary.timeline.timeToObjective)}</span>
                </span>
              )}
            </div>
          )}
        </CardContent>
      )}
    </Card>
  );
}

// ─── Event Detail Modal ──────────────────────────────────────────────────────

function EventDetailModal({ event, onClose }: { event: TimelineEvent | null; onClose: () => void }) {
  if (!event) return null;

  const phaseInfo = PHASES.find(p => p.key === event.phase);
  const EventIcon = getIcon(event.icon);
  const StatusIcon = STATUS_ICONS[event.status] || Circle;

  return (
    <Dialog open={!!event} onOpenChange={() => onClose()}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto bg-card border-border">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center bg-${phaseInfo?.color || "gray"}-500/15`}>
              <EventIcon className={`h-5 w-5 text-${phaseInfo?.color || "gray"}-400`} />
            </div>
            <div>
              <div className="text-lg">{event.title}</div>
              <div className="flex items-center gap-2 mt-0.5">
                <Badge variant="outline" className={`text-[10px] ${SEVERITY_COLORS[event.severity]}`}>
                  {event.severity}
                </Badge>
                <Badge variant="outline" className="text-[10px]">
                  {phaseInfo?.label || event.phase}
                </Badge>
                <span className="flex items-center gap-1 text-xs text-muted-foreground">
                  <StatusIcon className={`h-3 w-3 ${
                    event.status === "success" ? "text-emerald-400" :
                    event.status === "failed" ? "text-red-400" :
                    "text-muted-foreground"
                  }`} />
                  {event.status}
                </span>
              </div>
            </div>
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 mt-4">
          {/* Description */}
          <div>
            <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Description</h4>
            <p className="text-sm text-foreground">{event.description}</p>
          </div>

          {/* Metadata */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Timestamp</h4>
              <p className="text-sm text-foreground">{new Date(event.timestamp).toLocaleString()}</p>
            </div>
            <div>
              <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Source</h4>
              <p className="text-sm text-foreground">{event.source.replace(/_/g, " ")}</p>
            </div>
            {event.targetDomain && (
              <div>
                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Target Domain</h4>
                <p className="text-sm text-cyan-400">{event.targetDomain}</p>
              </div>
            )}
            {event.cveId && (
              <div>
                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">CVE</h4>
                <p className="text-sm text-orange-400">{event.cveId}</p>
              </div>
            )}
            {event.msfModule && (
              <div className="col-span-2">
                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Exploit Module</h4>
                <p className="text-sm text-red-400 font-mono">{event.msfModule}</p>
              </div>
            )}
            {event.calderaOperationId && (
              <div>
                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Adversary Operation</h4>
                <p className="text-sm text-violet-400">{event.calderaOperationId}</p>
              </div>
            )}
            {event.gophishCampaignId && (
              <div>
                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Phishing Campaign</h4>
                <p className="text-sm text-emerald-400">#{event.gophishCampaignId}</p>
              </div>
            )}
          </div>

          {/* Detail Data */}
          {event.details && Object.keys(event.details).length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Event Details</h4>
              <div className="rounded-lg border border-border/50 bg-muted/20 p-3 space-y-2">
                {Object.entries(event.details).map(([key, value]) => {
                  if (value === null || value === undefined) return null;
                  const displayValue = typeof value === "object" ? JSON.stringify(value, null, 2) : String(value);
                  const isLong = displayValue.length > 100;

                  return (
                    <div key={key} className={isLong ? "" : "flex items-start gap-2"}>
                      <span className="text-xs font-medium text-muted-foreground shrink-0 min-w-[120px]">
                        {key.replace(/([A-Z])/g, " $1").replace(/^./, s => s.toUpperCase())}:
                      </span>
                      {isLong ? (
                        <pre className="text-xs text-foreground/80 mt-1 overflow-x-auto bg-background/50 rounded p-2 max-h-40 overflow-y-auto">
                          {displayValue}
                        </pre>
                      ) : (
                        <span className="text-xs text-foreground">{displayValue}</span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
