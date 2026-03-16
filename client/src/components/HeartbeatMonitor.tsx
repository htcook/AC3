// @ts-nocheck
import { useState, useEffect, useRef, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Activity, Heart, HeartPulse, Skull, AlertTriangle, Wifi, WifiOff,
  RefreshCw, Search, Filter, Radio, Clock, Zap, Server,
  ChevronDown, ChevronUp, Loader2, Monitor, Cpu
} from "lucide-react";

const STATUS_CONFIG = {
  alive: {
    label: "Alive",
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/30",
    badge: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
    icon: HeartPulse,
    pulseColor: "bg-emerald-400",
  },
  stale: {
    label: "Stale",
    color: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/30",
    badge: "bg-amber-500/20 text-amber-300 border-amber-500/30",
    icon: AlertTriangle,
    pulseColor: "bg-amber-400",
  },
  dead: {
    label: "Dead",
    color: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/30",
    badge: "bg-red-500/20 text-red-300 border-red-500/30",
    icon: Skull,
    pulseColor: "bg-red-400",
  },
  unknown: {
    label: "Unknown",
    color: "text-zinc-400",
    bg: "bg-zinc-500/10",
    border: "border-zinc-500/30",
    badge: "bg-zinc-500/20 text-zinc-300 border-zinc-500/30",
    icon: AlertTriangle,
    pulseColor: "bg-zinc-400",
  },
};

const FRAMEWORK_COLORS: Record<string, string> = {
  caldera: "text-red-400",
  ember: "text-amber-400",
  sliver: "text-emerald-400",
  msf: "text-blue-400",
  empire: "text-purple-400",
  manjusaka: "text-orange-400",
  cobaltstrike: "text-cyan-400",
  metasploit: "text-blue-400",
};

function timeAgo(ts: number): string {
  const diff = Date.now() - ts;
  if (diff < 5_000) return "just now";
  if (diff < 60_000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function PulsingDot({ status }: { status: string }) {
  const config = STATUS_CONFIG[status as keyof typeof STATUS_CONFIG] || STATUS_CONFIG.unknown;
  return (
    <span className="relative flex h-3 w-3">
      {status === "alive" && (
        <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${config.pulseColor} opacity-75`} />
      )}
      <span className={`relative inline-flex rounded-full h-3 w-3 ${config.pulseColor} ${status !== "alive" ? "opacity-50" : ""}`} />
    </span>
  );
}

interface HeartbeatMonitorProps {
  /** If true, shows compact inline version */
  compact?: boolean;
  /** If provided, only show agents for this framework */
  frameworkFilter?: string;
}

export default function HeartbeatMonitor({ compact = false, frameworkFilter }: HeartbeatMonitorProps) {
  const [expanded, setExpanded] = useState(!compact);
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [fwFilter, setFwFilter] = useState(frameworkFilter || "all");
  const lastUpdateRef = useRef<number>(0);

  // Poll every 15 seconds for live heartbeat data
  const heartbeatQuery = trpc.ember.getHeartbeatStatus.useQuery(undefined, {
    refetchInterval: 15_000,
    refetchOnWindowFocus: true,
  });

  const data = heartbeatQuery.data;
  const agents = data?.agents || [];

  // Track when data last changed
  useEffect(() => {
    if (data?.timestamp) {
      lastUpdateRef.current = data.timestamp;
    }
  }, [data?.timestamp]);

  // Filtered agents
  const filteredAgents = useMemo(() => {
    return agents.filter((a) => {
      if (statusFilter !== "all" && a.status !== statusFilter) return false;
      if (fwFilter !== "all" && a.framework !== fwFilter) return false;
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        return (
          a.name.toLowerCase().includes(term) ||
          a.host.toLowerCase().includes(term) ||
          a.agentId.toLowerCase().includes(term) ||
          a.framework.toLowerCase().includes(term)
        );
      }
      return true;
    });
  }, [agents, statusFilter, fwFilter, searchTerm]);

  // Unique frameworks for filter
  const frameworks = useMemo(() => {
    return [...new Set(agents.map(a => a.framework))];
  }, [agents]);

  // Compact summary bar
  if (compact) {
    return (
      <Card className="bg-zinc-900/40 border-border/40">
        <CardHeader
          className="py-2.5 px-4 cursor-pointer"
          onClick={() => setExpanded(!expanded)}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Activity className="w-4 h-4 text-amber-400" />
              <span className="text-sm font-medium">Heartbeat Monitor</span>
              {data && (
                <div className="flex items-center gap-2 ml-2">
                  <Badge variant="outline" className={STATUS_CONFIG.alive.badge}>
                    <HeartPulse className="w-3 h-3 mr-1" /> {data.alive}
                  </Badge>
                  {data.stale > 0 && (
                    <Badge variant="outline" className={STATUS_CONFIG.stale.badge}>
                      <AlertTriangle className="w-3 h-3 mr-1" /> {data.stale}
                    </Badge>
                  )}
                  {data.dead > 0 && (
                    <Badge variant="outline" className={STATUS_CONFIG.dead.badge}>
                      <Skull className="w-3 h-3 mr-1" /> {data.dead}
                    </Badge>
                  )}
                </div>
              )}
            </div>
            <div className="flex items-center gap-2">
              {heartbeatQuery.isFetching && (
                <Loader2 className="w-3 h-3 animate-spin text-muted-foreground" />
              )}
              {expanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
            </div>
          </div>
        </CardHeader>
        {expanded && (
          <CardContent className="px-4 pb-4 border-t border-border/30 pt-3">
            <AgentGrid agents={filteredAgents} />
          </CardContent>
        )}
      </Card>
    );
  }

  // Full monitor view
  return (
    <Card className="bg-card/50 border-border/50">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-gradient-to-br from-emerald-500/20 to-cyan-600/20 border border-emerald-500/30">
              <Activity className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <CardTitle className="text-base">Agent Heartbeat Monitor</CardTitle>
              <p className="text-xs text-muted-foreground mt-0.5">
                Real-time beacon status across all C2 frameworks
                {data && ` — ${data.total} agent${data.total !== 1 ? "s" : ""} tracked`}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => heartbeatQuery.refetch()}
              disabled={heartbeatQuery.isFetching}
            >
              <RefreshCw className={`w-4 h-4 ${heartbeatQuery.isFetching ? "animate-spin" : ""}`} />
            </Button>
          </div>
        </div>

        {/* Status Summary Strip */}
        {data && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
            <div className="flex items-center gap-3 p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
              <PulsingDot status="alive" />
              <div>
                <p className="text-lg font-bold text-emerald-400">{data.alive}</p>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Alive</p>
              </div>
            </div>
            <div className="flex items-center gap-3 p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
              <PulsingDot status="stale" />
              <div>
                <p className="text-lg font-bold text-amber-400">{data.stale}</p>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Stale</p>
              </div>
            </div>
            <div className="flex items-center gap-3 p-3 rounded-lg bg-red-500/5 border border-red-500/20">
              <PulsingDot status="dead" />
              <div>
                <p className="text-lg font-bold text-red-400">{data.dead}</p>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Dead</p>
              </div>
            </div>
            <div className="flex items-center gap-3 p-3 rounded-lg bg-zinc-500/5 border border-zinc-500/20">
              <Server className="w-4 h-4 text-zinc-400" />
              <div>
                <p className="text-lg font-bold text-zinc-300">{data.total}</p>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total</p>
              </div>
            </div>
          </div>
        )}

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3 mt-4">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search agents..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9 h-9 text-sm"
            />
          </div>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-[140px] h-9">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="alive">Alive</SelectItem>
              <SelectItem value="stale">Stale</SelectItem>
              <SelectItem value="dead">Dead</SelectItem>
            </SelectContent>
          </Select>
          {!frameworkFilter && (
            <Select value={fwFilter} onValueChange={setFwFilter}>
              <SelectTrigger className="w-[150px] h-9">
                <SelectValue placeholder="Framework" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Frameworks</SelectItem>
                {frameworks.map(fw => (
                  <SelectItem key={fw} value={fw}>{fw.charAt(0).toUpperCase() + fw.slice(1)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </div>
      </CardHeader>

      <CardContent>
        {heartbeatQuery.isLoading ? (
          <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
            <Loader2 className="w-5 h-5 animate-spin" />
            Polling C2 frameworks for agent heartbeats...
          </div>
        ) : filteredAgents.length === 0 ? (
          <div className="text-center py-12 text-muted-foreground">
            <Radio className="w-10 h-10 mx-auto mb-3 opacity-20" />
            <p className="text-sm">No agents found</p>
            <p className="text-xs mt-1">
              {agents.length > 0
                ? "Try adjusting your filters"
                : "Deploy agents to see their heartbeat status here"}
            </p>
          </div>
        ) : (
          <AgentGrid agents={filteredAgents} />
        )}
      </CardContent>
    </Card>
  );
}

function AgentGrid({ agents }: { agents: any[] }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
      {agents.map((agent) => {
        const config = STATUS_CONFIG[agent.status as keyof typeof STATUS_CONFIG] || STATUS_CONFIG.unknown;
        const StatusIcon = config.icon;
        return (
          <div
            key={agent.agentId}
            className={`p-3 rounded-lg border transition-all ${config.bg} ${config.border}`}
          >
            {/* Header row */}
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center gap-2 min-w-0">
                <PulsingDot status={agent.status} />
                <span className="text-sm font-medium text-foreground truncate">{agent.name}</span>
              </div>
              <Badge variant="outline" className={`text-[9px] shrink-0 ${config.badge}`}>
                {config.label}
              </Badge>
            </div>

            {/* Details */}
            <div className="space-y-1.5 text-xs">
              <div className="flex items-center gap-2">
                <Monitor className="w-3 h-3 text-muted-foreground shrink-0" />
                <span className="text-muted-foreground truncate">{agent.host}</span>
                <Badge variant="outline" className={`text-[8px] ml-auto shrink-0 ${FRAMEWORK_COLORS[agent.framework] || ""}`}>
                  {agent.framework}
                </Badge>
              </div>

              <div className="flex items-center gap-2">
                <Cpu className="w-3 h-3 text-muted-foreground shrink-0" />
                <span className="text-muted-foreground">{agent.platform}</span>
              </div>

              <div className="flex items-center gap-2">
                <Clock className="w-3 h-3 text-muted-foreground shrink-0" />
                <span className="text-muted-foreground">Last seen: {timeAgo(agent.lastSeen)}</span>
                {agent.latencyMs !== null && (
                  <span className="text-[10px] text-muted-foreground/60 ml-auto">
                    {agent.latencyMs < 1000 ? `${agent.latencyMs}ms` : `${(agent.latencyMs / 1000).toFixed(1)}s`}
                  </span>
                )}
              </div>

              {/* Beacon info */}
              {(agent.beaconInterval || agent.channel) && (
                <div className="flex items-center gap-2 pt-1 border-t border-border/20">
                  {agent.beaconInterval && (
                    <span className="flex items-center gap-1 text-[10px] text-muted-foreground">
                      <Zap className="w-2.5 h-2.5" />
                      {agent.beaconInterval}s
                      {agent.jitter ? ` ±${agent.jitter}%` : ""}
                    </span>
                  )}
                  {agent.channel && (
                    <Badge variant="outline" className="text-[8px] ml-auto">
                      {agent.channel}
                    </Badge>
                  )}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
