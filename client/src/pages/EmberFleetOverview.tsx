import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Progress } from "@/components/ui/progress";
import {
  Flame, Activity, Cpu, Shield, Terminal, Radio, Wifi, Eye,
  Search, RefreshCw, Zap, Globe, Clock, AlertTriangle,
  ChevronRight, Server, Network, Brain, Boxes, Rocket,
  BarChart3, TrendingUp, Lock, Skull, CircuitBoard
} from "lucide-react";
import { Link } from "wouter";

const STATE_COLORS: Record<string, string> = {
  initializing: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  dormant: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  active: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  evading: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  pivoting: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  exfiltrating: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  self_destruct: "bg-red-500/20 text-red-400 border-red-500/30",
  dead: "bg-zinc-600/20 text-zinc-500 border-zinc-600/30",
};

const PROFILE_COLORS: Record<string, string> = {
  ghost: "bg-zinc-500/20 text-zinc-300 border-zinc-500/30",
  scout: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  striker: "bg-red-500/20 text-red-400 border-red-500/30",
  sentinel: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  hydra: "bg-purple-500/20 text-purple-400 border-purple-500/30",
};

const PROFILE_ICONS: Record<string, React.ReactNode> = {
  ghost: <Eye className="w-3.5 h-3.5" />,
  scout: <Search className="w-3.5 h-3.5" />,
  striker: <Zap className="w-3.5 h-3.5" />,
  sentinel: <Shield className="w-3.5 h-3.5" />,
  hydra: <Boxes className="w-3.5 h-3.5" />,
};

const PLATFORM_LABELS: Record<string, string> = {
  windows_x64: "Win x64",
  windows_x86: "Win x86",
  linux_x64: "Linux x64",
  linux_arm64: "Linux ARM64",
  macos_x64: "macOS x64",
  macos_arm64: "macOS ARM64",
};

export default function EmberFleetOverview() {
  const [activeTab, setActiveTab] = useState("fleet");
  const [searchFilter, setSearchFilter] = useState("");
  const [stateFilter, setStateFilter] = useState<string>("all");
  const [profileFilter, setProfileFilter] = useState<string>("all");

  const metadataQuery = trpc.ember.getMetadata.useQuery(undefined, { refetchInterval: 30000 });
  const dashboardQuery = trpc.ember.getDashboard.useQuery(undefined, { refetchInterval: 5000 });
  const agentsQuery = trpc.ember.listAgents.useQuery({
    state: stateFilter !== "all" ? stateFilter as any : undefined,
    profile: profileFilter !== "all" ? profileFilter as any : undefined,
    limit: 100,
  }, { refetchInterval: 5000 });

  const killAgent = trpc.ember.killAgent.useMutation({
    onSuccess: () => { toast.success("Kill command sent"); agentsQuery.refetch(); },
    onError: (e) => toast.error(`Kill failed: ${e.message}`),
  });

  const meta = metadataQuery.data;
  const dash = dashboardQuery.data;
  const agents = agentsQuery.data || [];

  const filteredAgents = useMemo(() => {
    if (!searchFilter) return agents;
    const q = searchFilter.toLowerCase();
    return agents.filter((a: any) =>
      a.name?.toLowerCase().includes(q) ||
      a.agentId?.toLowerCase().includes(q) ||
      a.hostname?.toLowerCase().includes(q) ||
      a.externalIp?.toLowerCase().includes(q)
    );
  }, [agents, searchFilter]);

  const stateDistribution = useMemo(() => {
    const dist: Record<string, number> = {};
    agents.forEach((a: any) => { dist[a.state] = (dist[a.state] || 0) + 1; });
    return dist;
  }, [agents]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-amber-500/20 to-orange-600/20 border border-amber-500/30">
            <Flame className="w-6 h-6 text-amber-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Ember Agent Fleet</h1>
            <p className="text-sm text-muted-foreground">
              {meta ? `v${meta.version} "${meta.codename}"` : "Loading..."} — AC3 Proprietary Agent System
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Link href="/ember/deploy">
            <Button className="bg-amber-600 hover:bg-amber-700 text-white">
              <Rocket className="w-4 h-4 mr-2" /> Deploy Agent
            </Button>
          </Link>
          <Button variant="outline" size="icon" onClick={() => { agentsQuery.refetch(); dashboardQuery.refetch(); }}>
            <RefreshCw className="w-4 h-4" />
          </Button>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Total Agents</p>
                <p className="text-2xl font-bold text-foreground">{dash?.totalAgents ?? 0}</p>
              </div>
              <Cpu className="w-8 h-8 text-amber-400/40" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Active</p>
                <p className="text-2xl font-bold text-emerald-400">{dash?.activeAgents ?? 0}</p>
              </div>
              <Activity className="w-8 h-8 text-emerald-400/40" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Pending Tasks</p>
                <p className="text-2xl font-bold text-blue-400">{dash?.pendingTasks ?? 0}</p>
              </div>
              <Terminal className="w-8 h-8 text-blue-400/40" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Swarms</p>
                <p className="text-2xl font-bold text-purple-400">{dash?.totalSwarms ?? 0}</p>
              </div>
              <Boxes className="w-8 h-8 text-purple-400/40" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Intel Items</p>
                <p className="text-2xl font-bold text-cyan-400">{dash?.totalIntel ?? 0}</p>
              </div>
              <Brain className="w-8 h-8 text-cyan-400/40" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Payloads</p>
                <p className="text-2xl font-bold text-orange-400">{dash?.totalPayloads ?? 0}</p>
              </div>
              <CircuitBoard className="w-8 h-8 text-orange-400/40" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-muted/50">
          <TabsTrigger value="fleet">Fleet View</TabsTrigger>
          <TabsTrigger value="map">Network Map</TabsTrigger>
          <TabsTrigger value="timeline">Activity Timeline</TabsTrigger>
        </TabsList>

        <TabsContent value="fleet" className="space-y-4">
          {/* Filters */}
          <div className="flex items-center gap-3">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search agents..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={stateFilter} onValueChange={setStateFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="State" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All States</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="dormant">Dormant</SelectItem>
                <SelectItem value="evading">Evading</SelectItem>
                <SelectItem value="pivoting">Pivoting</SelectItem>
                <SelectItem value="initializing">Initializing</SelectItem>
                <SelectItem value="dead">Dead</SelectItem>
              </SelectContent>
            </Select>
            <Select value={profileFilter} onValueChange={setProfileFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Profile" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Profiles</SelectItem>
                <SelectItem value="ghost">Ghost</SelectItem>
                <SelectItem value="scout">Scout</SelectItem>
                <SelectItem value="striker">Striker</SelectItem>
                <SelectItem value="sentinel">Sentinel</SelectItem>
                <SelectItem value="hydra">Hydra</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* State Distribution Bar */}
          {Object.keys(stateDistribution).length > 0 && (
            <Card className="bg-card/30 border-border/30">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-2">
                  <BarChart3 className="w-4 h-4 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground uppercase tracking-wider">State Distribution</span>
                </div>
                <div className="flex h-3 rounded-full overflow-hidden gap-0.5">
                  {Object.entries(stateDistribution).map(([state, count]) => (
                    <TooltipProvider key={state}>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <div
                            className={`h-full transition-all ${state === "active" ? "bg-emerald-500" : state === "dormant" ? "bg-gray-500" : state === "evading" ? "bg-amber-500" : state === "pivoting" ? "bg-purple-500" : state === "dead" ? "bg-zinc-600" : "bg-blue-500"}`}
                            style={{ width: `${(count / agents.length) * 100}%`, minWidth: "4px" }}
                          />
                        </TooltipTrigger>
                        <TooltipContent>
                          <p className="capitalize">{state}: {count}</p>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Agent Grid */}
          {agentsQuery.isLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {[...Array(6)].map((_, i) => (
                <Card key={i} className="bg-card/30 border-border/30 animate-pulse">
                  <CardContent className="p-5 h-48" />
                </Card>
              ))}
            </div>
          ) : filteredAgents.length === 0 ? (
            <Card className="bg-card/30 border-border/30">
              <CardContent className="p-12 text-center">
                <Flame className="w-12 h-12 text-amber-400/30 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-foreground mb-2">No Agents Deployed</h3>
                <p className="text-sm text-muted-foreground mb-4">
                  Deploy your first Ember agent to begin operations.
                </p>
                <Link href="/ember/deploy">
                  <Button className="bg-amber-600 hover:bg-amber-700 text-white">
                    <Rocket className="w-4 h-4 mr-2" /> Deploy First Agent
                  </Button>
                </Link>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {filteredAgents.map((agent: any) => (
                <Card key={agent.agentId} className="bg-card/50 border-border/50 hover:border-amber-500/30 transition-colors group">
                  <CardContent className="p-4 space-y-3">
                    {/* Agent Header */}
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${agent.state === "active" ? "bg-emerald-400 animate-pulse" : agent.state === "dead" ? "bg-zinc-600" : "bg-amber-400"}`} />
                        <span className="font-mono text-sm font-medium text-foreground truncate max-w-[180px]">
                          {agent.name || agent.agentId.slice(0, 12)}
                        </span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <Badge variant="outline" className={`text-[10px] ${STATE_COLORS[agent.state] || ""}`}>
                          {agent.state}
                        </Badge>
                        <Badge variant="outline" className={`text-[10px] ${PROFILE_COLORS[agent.profile] || ""}`}>
                          {PROFILE_ICONS[agent.profile]} {agent.profile}
                        </Badge>
                      </div>
                    </div>

                    {/* Agent Details */}
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div className="flex items-center gap-1.5 text-muted-foreground">
                        <Server className="w-3 h-3" />
                        <span className="truncate">{agent.hostname || "Unknown"}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-muted-foreground">
                        <Globe className="w-3 h-3" />
                        <span className="truncate">{agent.externalIp || "—"}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-muted-foreground">
                        <Cpu className="w-3 h-3" />
                        <span>{PLATFORM_LABELS[agent.platform] || agent.platform}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-muted-foreground">
                        <Radio className="w-3 h-3" />
                        <span>{agent.primaryChannel?.replace("_", " ") || "—"}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-muted-foreground">
                        <Clock className="w-3 h-3" />
                        <span>{agent.lastSeen ? new Date(agent.lastSeen).toLocaleTimeString() : "Never"}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-muted-foreground">
                        <Lock className="w-3 h-3" />
                        <span className="capitalize">{agent.integrity || "medium"}</span>
                      </div>
                    </div>

                    {/* Beacon Progress */}
                    <div className="space-y-1">
                      <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                        <span>Beacon: {agent.beaconInterval || 60}s ±{agent.jitterPercent || 15}%</span>
                        <span>Seq #{agent.beaconSequence || 0}</span>
                      </div>
                      <Progress
                        value={Math.min(100, ((agent.beaconSequence || 0) % 100))}
                        className="h-1"
                      />
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-1.5 pt-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <Link href={`/ember/tasks?agent=${agent.agentId}`}>
                        <Button variant="outline" size="sm" className="h-7 text-xs">
                          <Terminal className="w-3 h-3 mr-1" /> Task
                        </Button>
                      </Link>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7 text-xs text-red-400 hover:text-red-300 hover:border-red-500/50"
                        onClick={() => {
                          if (confirm(`Kill agent ${agent.name || agent.agentId.slice(0, 8)}?`)) {
                            killAgent.mutate({ agentId: agent.agentId });
                          }
                        }}
                      >
                        <Skull className="w-3 h-3 mr-1" /> Kill
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="map">
          <Card className="bg-card/30 border-border/30">
            <CardContent className="p-12 text-center">
              <Network className="w-16 h-16 text-amber-400/20 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-foreground mb-2">Network Topology Map</h3>
              <p className="text-sm text-muted-foreground">
                Visual network map showing agent positions, pivot paths, and lateral movement routes.
                Populates automatically as agents report network intelligence.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="timeline">
          <Card className="bg-card/30 border-border/30">
            <CardContent className="p-12 text-center">
              <Activity className="w-16 h-16 text-amber-400/20 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-foreground mb-2">Activity Timeline</h3>
              <p className="text-sm text-muted-foreground">
                Real-time timeline of all agent activity — beacons, task execution, intelligence collection, and state changes.
                Populates as agents check in.
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Capability Catalog Preview */}
      {meta?.capabilities && (
        <Card className="bg-card/30 border-border/30">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base flex items-center gap-2">
                <CircuitBoard className="w-4 h-4 text-amber-400" />
                Capability Catalog
              </CardTitle>
              <Link href="/ember/capabilities">
                <Button variant="ghost" size="sm" className="text-xs text-muted-foreground">
                  View All <ChevronRight className="w-3 h-3 ml-1" />
                </Button>
              </Link>
            </div>
            <CardDescription>
              {meta.capabilities.length} modules across {new Set(meta.capabilities.map((c: any) => c.category)).size} categories
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2">
              {meta.capabilities.slice(0, 12).map((cap: any) => (
                <div key={cap.id} className="p-2.5 rounded-lg bg-muted/30 border border-border/30 hover:border-amber-500/30 transition-colors">
                  <p className="text-xs font-medium text-foreground truncate">{cap.name}</p>
                  <p className="text-[10px] text-muted-foreground capitalize">{cap.category.replace("_", " ")}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
