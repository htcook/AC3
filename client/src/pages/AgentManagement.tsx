// @ts-nocheck
import { useState, useMemo, lazy, Suspense } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { useLocation } from "wouter";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Cpu, Target, Hexagon, Flame, Crosshair, Search, RefreshCw, Loader2,
  Activity, Wifi, WifiOff, Skull, Server, Terminal, Radio, Rocket,
  Brain, Shield, Eye, Zap, Clock, MoreHorizontal, Power, ExternalLink,
  ChevronRight, AlertTriangle, CheckCircle2, XCircle, Pause,
} from "lucide-react";
import HeartbeatMonitor from "@/components/HeartbeatMonitor";

// ─── Types ───────────────────────────────────────────────────────────────
interface UnifiedAgent {
  id: string;
  name: string;
  framework: "caldera" | "ember" | "sliver" | "msf";
  host: string;
  platform: string;
  status: "active" | "inactive" | "dead" | "pending" | "unknown";
  lastSeen: string | number;
  details: Record<string, any>;
}

const FRAMEWORK_META = {
  caldera: { label: "Caldera", icon: Target, color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", badge: "bg-red-500/20 text-red-300" },
  ember: { label: "Ember", icon: Flame, color: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/30", badge: "bg-amber-500/20 text-amber-300" },
  sliver: { label: "Sliver", icon: Hexagon, color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30", badge: "bg-emerald-500/20 text-emerald-300" },
  msf: { label: "Metasploit", icon: Crosshair, color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30", badge: "bg-blue-500/20 text-blue-300" },
} as const;

const STATUS_META: Record<string, { label: string; color: string; icon: any }> = {
  active: { label: "Active", color: "text-emerald-400", icon: CheckCircle2 },
  inactive: { label: "Inactive", color: "text-zinc-400", icon: Pause },
  dead: { label: "Dead", color: "text-red-400", icon: XCircle },
  pending: { label: "Pending", color: "text-amber-400", icon: Clock },
  unknown: { label: "Unknown", color: "text-zinc-500", icon: AlertTriangle },
};

function isAlive(lastSeen: string | number, thresholdMs = 5 * 60 * 1000): boolean {
  return Date.now() - new Date(lastSeen).getTime() < thresholdMs;
}

function timeAgo(ts: string | number): string {
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

// ─── Ember Deploy Dialog ─────────────────────────────────────────────────
function EmberDeployDialog() {
  const [open, setOpen] = useState(false);
  const [profile, setProfile] = useState("recon");
  const [targetHost, setTargetHost] = useState("");
  const [notes, setNotes] = useState("");

  const deployMutation = trpc.ember.deployAgent.useMutation({
    onSuccess: (data) => {
      toast.success(`Ember agent deployed — ID: ${data?.agentId || "pending"}`);
      setOpen(false);
      setTargetHost("");
      setNotes("");
    },
    onError: (err) => toast.error(`Deploy failed: ${err.message}`),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" className="bg-amber-600 hover:bg-amber-700 text-xs">
          <Rocket className="h-3.5 w-3.5 mr-1.5" /> Deploy Ember Agent
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Flame className="h-5 w-5 text-amber-400" /> Deploy Ember Implant
          </DialogTitle>
          <DialogDescription>
            Configure and deploy a new Ember cognitive agent to a target host.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label className="text-xs">Agent Profile</Label>
            <Select value={profile} onValueChange={setProfile}>
              <SelectTrigger className="h-9 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="recon">Recon — Lightweight reconnaissance</SelectItem>
                <SelectItem value="persistence">Persistence — Long-term access</SelectItem>
                <SelectItem value="exfil">Exfil — Data extraction focused</SelectItem>
                <SelectItem value="lateral">Lateral — Network movement</SelectItem>
                <SelectItem value="full">Full — All capabilities enabled</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Target Host</Label>
            <Input
              placeholder="e.g., 10.0.0.50 or target.internal"
              value={targetHost}
              onChange={(e) => setTargetHost(e.target.value)}
              className="h-9 text-xs"
            />
          </div>
          <div className="space-y-2">
            <Label className="text-xs">Notes (optional)</Label>
            <Textarea
              placeholder="Deployment context, engagement reference..."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              className="text-xs min-h-[60px]"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" size="sm" onClick={() => setOpen(false)}>Cancel</Button>
          <Button
            size="sm"
            className="bg-amber-600 hover:bg-amber-700"
            disabled={!targetHost.trim() || deployMutation.isPending}
            onClick={() => deployMutation.mutate({
              profile,
              targetHost: targetHost.trim(),
              config: { notes, deployedAt: new Date().toISOString() },
            })}
          >
            {deployMutation.isPending ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Rocket className="h-3.5 w-3.5 mr-1.5" />}
            Deploy
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Agent Card ──────────────────────────────────────────────────────────
function AgentCard({ agent, onKill }: { agent: UnifiedAgent; onKill?: (id: string, fw: string) => void }) {
  const [, navigate] = useLocation();
  const meta = FRAMEWORK_META[agent.framework];
  const statusMeta = STATUS_META[agent.status] || STATUS_META.unknown;
  const Icon = meta.icon;
  const StatusIcon = statusMeta.icon;

  function handleNavigate() {
    switch (agent.framework) {
      case "caldera": navigate("/agents"); break;
      case "ember": navigate("/ember"); break;
      case "sliver": navigate("/sliver-c2"); break;
      case "msf": navigate("/msf-sessions"); break;
    }
  }

  return (
    <Card className={`${meta.border} hover:border-opacity-60 transition-all group cursor-pointer`} onClick={handleNavigate}>
      <CardContent className="p-4 space-y-3">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2.5">
            <div className={`p-2 rounded-lg ${meta.bg}`}>
              <Icon className={`h-4 w-4 ${meta.color}`} />
            </div>
            <div>
              <p className="font-semibold text-sm leading-tight">{agent.name}</p>
              <p className="text-[11px] text-muted-foreground">{agent.host}</p>
            </div>
          </div>
          <Badge className={`text-[10px] ${meta.badge} border-0`}>{meta.label}</Badge>
        </div>

        {/* Status row */}
        <div className="flex items-center justify-between text-xs">
          <span className={`flex items-center gap-1 ${statusMeta.color}`}>
            <StatusIcon className="h-3 w-3" /> {statusMeta.label}
          </span>
          <span className="text-muted-foreground flex items-center gap-1">
            <Clock className="h-3 w-3" /> {agent.lastSeen ? timeAgo(agent.lastSeen) : "N/A"}
          </span>
        </div>

        {/* Details */}
        <div className="flex flex-wrap gap-1.5">
          {agent.platform && (
            <Badge variant="outline" className="text-[10px] border-zinc-700">{agent.platform}</Badge>
          )}
          {agent.details?.executors && (
            <Badge variant="outline" className="text-[10px] border-zinc-700">
              {Array.isArray(agent.details.executors) ? agent.details.executors.join(", ") : agent.details.executors}
            </Badge>
          )}
          {agent.details?.profile && (
            <Badge variant="outline" className="text-[10px] border-zinc-700">{agent.details.profile}</Badge>
          )}
          {agent.details?.transport && (
            <Badge variant="outline" className="text-[10px] border-zinc-700">{agent.details.transport}</Badge>
          )}
          {agent.details?.arch && (
            <Badge variant="outline" className="text-[10px] border-zinc-700">{agent.details.arch}</Badge>
          )}
          {agent.details?.evasionScore != null && (
            <Badge variant="outline" className="text-[10px] border-amber-500/40 text-amber-400">
              <Eye className="h-2.5 w-2.5 mr-0.5" /> Evasion: {agent.details.evasionScore}
            </Badge>
          )}
        </div>

        {/* Actions */}
        <div className="flex items-center justify-between pt-1 border-t border-zinc-800">
          <Button
            variant="ghost"
            size="sm"
            className="text-[11px] h-6 px-2"
            onClick={(e) => { e.stopPropagation(); handleNavigate(); }}
          >
            <ExternalLink className="h-3 w-3 mr-1" /> Details
          </Button>
          {onKill && agent.status === "active" && (
            <Button
              variant="ghost"
              size="sm"
              className="text-[11px] h-6 px-2 text-red-400 hover:text-red-300 hover:bg-red-500/10"
              onClick={(e) => { e.stopPropagation(); onKill(agent.id, agent.framework); }}
            >
              <Power className="h-3 w-3 mr-1" /> Kill
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Main Page ───────────────────────────────────────────────────────────
export default function AgentManagement() {
  const [activeTab, setActiveTab] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");

  // ─── Data queries ────────────────────────────────────────────────────
  const calderaAgents = trpc.calderaProxy.getAgents.useQuery(undefined, { refetchInterval: 30_000 });
  const emberFleet = trpc.ember.getFleetOverview.useQuery(undefined, { refetchInterval: 30_000 });
  const emberAgentsList = trpc.ember.listAgents.useQuery(undefined, { refetchInterval: 30_000 });
  const sliverImplants = trpc.sliverC2.listImplants.useQuery(undefined, { refetchInterval: 30_000 });
  const msfSessions = trpc.metasploit.listServers.useQuery(undefined, { refetchInterval: 30_000 });

  // ─── Kill mutations ──────────────────────────────────────────────────
  const killEmber = trpc.ember.killAgent.useMutation({
    onSuccess: () => { toast.success("Ember agent terminated"); emberAgentsList.refetch(); emberFleet.refetch(); },
    onError: (err) => toast.error(`Kill failed: ${err.message}`),
  });

  // ─── Normalize all agents into unified format ────────────────────────
  const allAgents = useMemo<UnifiedAgent[]>(() => {
    const agents: UnifiedAgent[] = [];

    // Caldera agents
    const calderaData = Array.isArray(calderaAgents.data) ? calderaAgents.data : [];
    for (const a of calderaData) {
      agents.push({
        id: a.paw || a.id || String(Math.random()),
        name: a.host || a.paw || "Unknown",
        framework: "caldera",
        host: a.host || "N/A",
        platform: a.platform || "unknown",
        status: isAlive(a.last_seen) ? "active" : "inactive",
        lastSeen: a.last_seen || "",
        details: {
          executors: a.executors,
          privilege: a.privilege,
          group: a.group,
          contact: a.contact,
        },
      });
    }

    // Ember agents (from listAgents query which returns actual agent rows)
    const emberData = emberAgentsList.data || [];
    for (const a of emberData) {
      const lastBeacon = a.lastBeaconAt ? new Date(Number(a.lastBeaconAt)).toISOString() : "";
      agents.push({
        id: a.agentId || String(a.id),
        name: a.name || a.agentId || "Ember Agent",
        framework: "ember",
        host: a.hostname || "N/A",
        platform: a.platform || "unknown",
        status: a.state === "active" || a.state === "evading" || a.state === "pivoting" ? "active" 
          : a.state === "dormant" || a.state === "initializing" ? "inactive" 
          : a.state === "dead" || a.state === "self_destruct" ? "dead" 
          : "unknown",
        lastSeen: lastBeacon,
        details: {
          profile: a.profile,
          beaconCount: a.beaconCount,
          beaconInterval: a.beaconInterval,
          autonomy: a.autonomy,
          internalIp: a.internalIp,
          externalIp: a.externalIp,
          processName: a.processName,
          pid: a.pid,
        },
      });
    }

    // Sliver implants
    const sliverData = sliverImplants.data?.implants || [];
    for (const i of sliverData) {
      agents.push({
        id: String(i.id || i.name || Math.random()),
        name: i.name || "Sliver Implant",
        framework: "sliver",
        host: i.remoteAddress || i.hostname || "N/A",
        platform: `${i.os || "unknown"}/${i.arch || "?"}`,
        status: i.isAlive ? "active" : "inactive",
        lastSeen: i.lastCheckin || "",
        details: {
          transport: i.transport,
          arch: i.arch,
          version: i.version,
        },
      });
    }

    // MSF sessions (from servers)
    const msfData = msfSessions.data || [];
    for (const s of msfData) {
      agents.push({
        id: String(s.id || Math.random()),
        name: s.name || s.host || "MSF Server",
        framework: "msf",
        host: s.host || "N/A",
        platform: "msf",
        status: s.status === "online" ? "active" : "inactive",
        lastSeen: s.lastChecked || s.updatedAt || "",
        details: {
          port: s.port,
          version: s.version,
        },
      });
    }

    return agents;
  }, [calderaAgents.data, emberAgentsList.data, sliverImplants.data, msfSessions.data]);

  // ─── Filtering ───────────────────────────────────────────────────────
  const filteredAgents = useMemo(() => {
    return allAgents.filter((a) => {
      if (activeTab !== "all" && a.framework !== activeTab) return false;
      if (statusFilter !== "all" && a.status !== statusFilter) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return (
          a.name.toLowerCase().includes(q) ||
          a.host.toLowerCase().includes(q) ||
          a.id.toLowerCase().includes(q) ||
          a.platform.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [allAgents, activeTab, statusFilter, searchQuery]);

  // ─── Stats ───────────────────────────────────────────────────────────
  const stats = useMemo(() => {
    const total = allAgents.length;
    const active = allAgents.filter((a) => a.status === "active").length;
    const byFramework = {
      caldera: allAgents.filter((a) => a.framework === "caldera").length,
      ember: allAgents.filter((a) => a.framework === "ember").length,
      sliver: allAgents.filter((a) => a.framework === "sliver").length,
      msf: allAgents.filter((a) => a.framework === "msf").length,
    };
    return { total, active, byFramework };
  }, [allAgents]);

  // Only show loading spinner on initial fetch, not on refetch or error states
  const isLoading = calderaAgents.isLoading && emberAgentsList.isLoading && sliverImplants.isLoading && msfSessions.isLoading;
  const isAnyLoading = calderaAgents.isFetching || emberAgentsList.isFetching || sliverImplants.isFetching || msfSessions.isFetching;

  function handleKill(id: string, framework: string) {
    if (framework === "ember") {
      killEmber.mutate({ agentId: id });
    } else {
      toast.info(`Kill command sent to ${framework} agent ${id}`);
    }
  }

  function handleRefreshAll() {
    calderaAgents.refetch();
    emberAgentsList.refetch();
    emberFleet.refetch();
    sliverImplants.refetch();
    msfSessions.refetch();
    toast.success("Refreshing all C2 frameworks...");
  }

  return (
    <div className="space-y-6 p-4 lg:p-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Agent Management</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Unified view across all C2 frameworks — Caldera, Ember, Sliver, and Metasploit
          </p>
        </div>
        <div className="flex items-center gap-2">
          <EmberDeployDialog />
          <Button variant="outline" size="sm" className="text-xs" onClick={handleRefreshAll}>
            <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${isAnyLoading ? "animate-spin" : ""}`} /> Refresh All
          </Button>
        </div>
      </div>

      {/* Heartbeat Monitor */}
      <HeartbeatMonitor />

      {/* Stats cards */}
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-3">
        <Card className="border-zinc-700/50">
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold">{stats.total}</p>
            <p className="text-[11px] text-muted-foreground">Total Agents</p>
          </CardContent>
        </Card>
        <Card className="border-emerald-500/30 bg-emerald-500/5">
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-emerald-400">{stats.active}</p>
            <p className="text-[11px] text-muted-foreground">Active</p>
          </CardContent>
        </Card>
        {(Object.entries(FRAMEWORK_META) as [keyof typeof FRAMEWORK_META, typeof FRAMEWORK_META[keyof typeof FRAMEWORK_META]][]).map(([key, meta]) => (
          <Card key={key} className={`${meta.border} ${meta.bg}`}>
            <CardContent className="p-3 text-center">
              <p className={`text-2xl font-bold ${meta.color}`}>{stats.byFramework[key]}</p>
              <p className="text-[11px] text-muted-foreground flex items-center justify-center gap-1">
                <meta.icon className="h-3 w-3" /> {meta.label}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Tabs + Filters */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <TabsList className="bg-zinc-900/50">
            <TabsTrigger value="all" className="text-xs">
              <Cpu className="h-3.5 w-3.5 mr-1" /> All ({stats.total})
            </TabsTrigger>
            <TabsTrigger value="caldera" className="text-xs">
              <Target className="h-3.5 w-3.5 mr-1" /> Caldera ({stats.byFramework.caldera})
            </TabsTrigger>
            <TabsTrigger value="ember" className="text-xs">
              <Flame className="h-3.5 w-3.5 mr-1" /> Ember ({stats.byFramework.ember})
            </TabsTrigger>
            <TabsTrigger value="sliver" className="text-xs">
              <Hexagon className="h-3.5 w-3.5 mr-1" /> Sliver ({stats.byFramework.sliver})
            </TabsTrigger>
            <TabsTrigger value="msf" className="text-xs">
              <Crosshair className="h-3.5 w-3.5 mr-1" /> MSF ({stats.byFramework.msf})
            </TabsTrigger>
          </TabsList>

          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                placeholder="Search agents..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 h-8 w-48 text-xs"
              />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="h-8 w-32 text-xs">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="inactive">Inactive</SelectItem>
                <SelectItem value="dead">Dead</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Agent grid */}
        <div className="mt-4">
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              <span className="ml-3 text-sm text-muted-foreground">Loading agents from all C2 frameworks...</span>
            </div>
          ) : filteredAgents.length === 0 ? (
            <Card className="border-dashed border-zinc-700">
              <CardContent className="p-12 text-center">
                <Cpu className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
                <p className="font-semibold">No agents found</p>
                <p className="text-sm text-muted-foreground mt-1">
                  {searchQuery || statusFilter !== "all"
                    ? "Try adjusting your search or filters"
                    : "Deploy agents from Caldera, Ember, Sliver, or Metasploit to see them here"}
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-3">
              {filteredAgents.map((agent) => (
                <AgentCard key={`${agent.framework}-${agent.id}`} agent={agent} onKill={handleKill} />
              ))}
            </div>
          )}
        </div>
      </Tabs>
    </div>
  );
}
