import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { Link } from "wouter";
import { 
  Cpu, Monitor, Server, Clock, Shield, ShieldOff, Trash2,
  RefreshCw, Terminal, Wifi, WifiOff, Copy, ChevronDown,
  ChevronUp, Folder, Flame, Eye, Search, Zap, Boxes,
  Radio, Brain, Globe, Lock, Network, Activity, Users
} from "lucide-react";
import { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel,
  AlertDialogContent, AlertDialogDescription, AlertDialogFooter,
  AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  Collapsible, CollapsibleContent, CollapsibleTrigger,
} from "@/components/ui/collapsible";

// ─── Caldera Agent Types ────────────────────────────────────────────────────
interface CalderaAgent {
  paw: string;
  host: string;
  username: string;
  platform: string;
  server: string;
  contact: string;
  pid: number;
  ppid: number;
  architecture: string;
  executors: string[];
  privilege: string;
  exe_name: string;
  location: string;
  trusted: boolean;
  sleep_min: number;
  sleep_max: number;
  watchdog: number;
  created: string;
  last_seen: string;
  links: any[];
  deadman_enabled: boolean;
  available_contacts: string[];
  host_ip_addrs: string[];
  group: string;
  upstream_dest: string;
  pending_contact: string;
}

// ─── Helpers ────────────────────────────────────────────────────────────────
function formatTimeAgo(dateString: string | number): string {
  const date = typeof dateString === "number" ? new Date(dateString) : new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);
  if (diffSecs < 60) return `${diffSecs}s ago`;
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
}

function getPlatformIcon(platform: string) {
  const p = platform.toLowerCase();
  if (p.includes("windows")) return <Monitor className="h-5 w-5" />;
  if (p.includes("linux")) return <Terminal className="h-5 w-5" />;
  if (p.includes("darwin") || p.includes("macos")) return <Cpu className="h-5 w-5" />;
  return <Server className="h-5 w-5" />;
}

function getCalderaStatusColor(lastSeen: string): 'default' | 'secondary' | 'destructive' {
  const diffMins = Math.floor((Date.now() - new Date(lastSeen).getTime()) / 60000);
  if (diffMins < 5) return 'default';
  if (diffMins < 30) return 'secondary';
  return 'destructive';
}

function getCalderaStatusText(lastSeen: string): string {
  const diffMins = Math.floor((Date.now() - new Date(lastSeen).getTime()) / 60000);
  if (diffMins < 5) return 'Active';
  if (diffMins < 30) return 'Idle';
  return 'Stale';
}

// ─── Ember State Colors ─────────────────────────────────────────────────────
const EMBER_STATE_COLORS: Record<string, string> = {
  initializing: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  dormant: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  active: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  evading: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  pivoting: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  exfiltrating: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  self_destruct: "bg-red-500/20 text-red-400 border-red-500/30",
  dead: "bg-zinc-600/20 text-zinc-500 border-zinc-600/30",
};

const EMBER_PROFILE_ICONS: Record<string, React.ReactNode> = {
  ghost: <Eye className="w-3.5 h-3.5" />,
  scout: <Search className="w-3.5 h-3.5" />,
  striker: <Zap className="w-3.5 h-3.5" />,
  sentinel: <Shield className="w-3.5 h-3.5" />,
  hydra: <Boxes className="w-3.5 h-3.5" />,
};

const EMBER_PROFILE_COLORS: Record<string, string> = {
  ghost: "bg-zinc-500/20 text-zinc-300 border-zinc-500/30",
  scout: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  striker: "bg-red-500/20 text-red-400 border-red-500/30",
  sentinel: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  hydra: "bg-purple-500/20 text-purple-400 border-purple-500/30",
};

// ─── Main Component ─────────────────────────────────────────────────────────
export default function Agents() {
  const [expandedAgents, setExpandedAgents] = useState<Set<string>>(new Set());
  const [activeTab, setActiveTab] = useState("all");

  // Caldera agents
  const { data: calderaAgents, isLoading: calderaLoading, refetch: refetchCaldera } = trpc.calderaProxy.getAgents.useQuery(undefined, {
    refetchInterval: 30000,
  });

  // Ember agents
  const { data: emberAgentsList, isLoading: emberLoading, refetch: refetchEmber } = trpc.ember.listAgents.useQuery({ limit: 100 }, {
    refetchInterval: 15000,
  });

  const killCalderaMutation = trpc.calderaProxy.killAgent.useMutation({
    onSuccess: () => { toast.success("Caldera agent terminated"); refetchCaldera(); },
    onError: () => { toast.error("Failed to terminate agent"); },
  });

  const updateTrustMutation = trpc.calderaProxy.updateAgentTrust.useMutation({
    onSuccess: (_, variables) => { toast.success(variables.trusted ? "Agent trusted" : "Agent untrusted"); refetchCaldera(); },
    onError: () => { toast.error("Failed to update agent trust"); },
  });

  const killEmberMutation = trpc.ember.killAgent.useMutation({
    onSuccess: () => { toast.success("Ember implant terminated"); refetchEmber(); },
    onError: (e) => { toast.error(`Failed to terminate: ${e.message}`); },
  });

  const toggleExpanded = (id: string) => {
    const next = new Set(expandedAgents);
    next.has(id) ? next.delete(id) : next.add(id);
    setExpandedAgents(next);
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied`);
  };

  const refetchAll = () => { refetchCaldera(); refetchEmber(); };

  const calderaList = (calderaAgents as CalderaAgent[]) || [];
  const emberList = (emberAgentsList as any[]) || [];
  const isLoading = calderaLoading && emberLoading;

  // Stats
  const calderaActive = calderaList.filter(a => getCalderaStatusText(a.last_seen) === 'Active').length;
  const calderaIdle = calderaList.filter(a => getCalderaStatusText(a.last_seen) === 'Idle').length;
  const calderaStale = calderaList.filter(a => getCalderaStatusText(a.last_seen) === 'Stale').length;
  const emberActive = emberList.filter(a => ['active', 'evading', 'pivoting', 'exfiltrating'].includes(a.state)).length;
  const emberDormant = emberList.filter(a => a.state === 'dormant' || a.state === 'initializing').length;
  const emberDead = emberList.filter(a => a.state === 'dead' || a.state === 'self_destruct').length;

  if (isLoading) {
    return (
      <AppShell activePath="/agents">
        <div className="p-4 sm:p-6 lg:p-8">
          <Skeleton className="h-12 w-64 mb-8" />
          <div className="grid gap-6">
            {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-48 w-full" />)}
          </div>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell activePath="/agents">
      <div className="p-4 sm:p-6 lg:p-8">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6 sm:mb-8">
          <div>
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold tracking-tight mb-1 sm:mb-2">DEPLOYED AGENTS</h1>
            <p className="text-sm sm:text-base text-muted-foreground">
              Unified view of Caldera emulation agents and Ember implants
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={refetchAll} className="gap-2">
              <RefreshCw className="h-4 w-4" />
              <span className="hidden sm:inline">Refresh</span>
            </Button>
            <Link href="/agents/deploy">
              <Button variant="outline" size="sm" className="gap-2">
                <Terminal className="h-4 w-4" />
                Deploy Caldera
              </Button>
            </Link>
            <Link href="/ember/deploy">
              <Button variant="default" size="sm" className="gap-2 bg-orange-600 hover:bg-orange-700">
                <Flame className="h-4 w-4" />
                Deploy Ember
              </Button>
            </Link>
          </div>
        </div>

        {/* Red divider */}
        <div className="h-1 bg-gradient-to-r from-red-600 via-orange-500 to-red-600 mb-8" />

        {/* Stats Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-8">
          <Card className="bg-card/50">
            <CardContent className="p-3 sm:p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground">Caldera</p>
                  <p className="text-2xl font-bold">{calderaList.length}</p>
                </div>
                <Cpu className="h-6 w-6 text-primary" />
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 sm:p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground">Ember</p>
                  <p className="text-2xl font-bold text-orange-500">{emberList.length}</p>
                </div>
                <Flame className="h-6 w-6 text-orange-500" />
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 sm:p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground">Active</p>
                  <p className="text-2xl font-bold text-green-500">{calderaActive + emberActive}</p>
                </div>
                <Wifi className="h-6 w-6 text-green-500" />
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 sm:p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground">Idle/Dormant</p>
                  <p className="text-2xl font-bold text-yellow-500">{calderaIdle + emberDormant}</p>
                </div>
                <Clock className="h-6 w-6 text-yellow-500" />
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 sm:p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground">Stale/Dead</p>
                  <p className="text-2xl font-bold text-red-500">{calderaStale + emberDead}</p>
                </div>
                <WifiOff className="h-6 w-6 text-red-500" />
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 sm:p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground">Total</p>
                  <p className="text-2xl font-bold">{calderaList.length + emberList.length}</p>
                </div>
                <Network className="h-6 w-6 text-primary" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Tabbed Agent Lists */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="mb-6">
            <TabsTrigger value="all">
              All Agents ({calderaList.length + emberList.length})
            </TabsTrigger>
            <TabsTrigger value="caldera">
              <Cpu className="h-3.5 w-3.5 mr-1.5" />
              Caldera ({calderaList.length})
            </TabsTrigger>
            <TabsTrigger value="ember">
              <Flame className="h-3.5 w-3.5 mr-1.5" />
              Ember ({emberList.length})
            </TabsTrigger>
          </TabsList>

          {/* All Agents */}
          <TabsContent value="all" className="space-y-4">
            {calderaList.length === 0 && emberList.length === 0 ? (
              <EmptyState />
            ) : (
              <>
                {/* Ember agents first (proprietary) */}
                {emberList.map((agent: any) => (
                  <EmberAgentCard
                    key={`ember-${agent.agentId}`}
                    agent={agent}
                    expanded={expandedAgents.has(`ember-${agent.agentId}`)}
                    onToggle={() => toggleExpanded(`ember-${agent.agentId}`)}
                    onKill={() => killEmberMutation.mutate({ agentId: agent.agentId })}
                    onCopy={copyToClipboard}
                    killPending={killEmberMutation.isPending}
                  />
                ))}
                {/* Caldera agents */}
                {calderaList.map((agent: CalderaAgent) => (
                  <CalderaAgentCard
                    key={`caldera-${agent.paw}`}
                    agent={agent}
                    expanded={expandedAgents.has(`caldera-${agent.paw}`)}
                    onToggle={() => toggleExpanded(`caldera-${agent.paw}`)}
                    onKill={() => killCalderaMutation.mutate({ paw: agent.paw })}
                    onTrust={() => updateTrustMutation.mutate({ paw: agent.paw, trusted: !agent.trusted })}
                    onCopy={copyToClipboard}
                    killPending={killCalderaMutation.isPending}
                    trustPending={updateTrustMutation.isPending}
                  />
                ))}
              </>
            )}
          </TabsContent>

          {/* Caldera Only */}
          <TabsContent value="caldera" className="space-y-4">
            {calderaList.length === 0 ? (
              <EmptyState type="caldera" />
            ) : (
              calderaList.map((agent: CalderaAgent) => (
                <CalderaAgentCard
                  key={agent.paw}
                  agent={agent}
                  expanded={expandedAgents.has(`caldera-${agent.paw}`)}
                  onToggle={() => toggleExpanded(`caldera-${agent.paw}`)}
                  onKill={() => killCalderaMutation.mutate({ paw: agent.paw })}
                  onTrust={() => updateTrustMutation.mutate({ paw: agent.paw, trusted: !agent.trusted })}
                  onCopy={copyToClipboard}
                  killPending={killCalderaMutation.isPending}
                  trustPending={updateTrustMutation.isPending}
                />
              ))
            )}
          </TabsContent>

          {/* Ember Only */}
          <TabsContent value="ember" className="space-y-4">
            {emberList.length === 0 ? (
              <EmptyState type="ember" />
            ) : (
              emberList.map((agent: any) => (
                <EmberAgentCard
                  key={agent.agentId}
                  agent={agent}
                  expanded={expandedAgents.has(`ember-${agent.agentId}`)}
                  onToggle={() => toggleExpanded(`ember-${agent.agentId}`)}
                  onKill={() => killEmberMutation.mutate({ agentId: agent.agentId })}
                  onCopy={copyToClipboard}
                  killPending={killEmberMutation.isPending}
                />
              ))
            )}
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}

// ─── Empty State ────────────────────────────────────────────────────────────
function EmptyState({ type }: { type?: "caldera" | "ember" }) {
  return (
    <Card className="bg-card/50">
      <CardContent className="p-4 sm:p-8 lg:p-12 text-center">
        {type === "ember" ? (
          <Flame className="h-16 w-16 mx-auto mb-4 text-orange-500/40" />
        ) : (
          <Cpu className="h-16 w-16 mx-auto mb-4 text-muted-foreground" />
        )}
        <h3 className="text-xl font-semibold mb-2">
          {type === "ember" ? "No Ember Implants Deployed" : type === "caldera" ? "No Caldera Agents Deployed" : "No Agents Deployed"}
        </h3>
        <p className="text-muted-foreground mb-6">
          {type === "ember"
            ? "Deploy Ember implants for advanced red team operations with cognitive autonomy."
            : type === "caldera"
            ? "Deploy Sandcat agents to your target systems to begin emulation."
            : "Deploy agents to begin red team operations."}
        </p>
        <div className="flex justify-center gap-3">
          {(!type || type === "caldera") && (
            <Link href="/agents/deploy">
              <Button variant="outline" className="gap-2">
                <Terminal className="h-4 w-4" />
                Deploy Caldera Agent
              </Button>
            </Link>
          )}
          {(!type || type === "ember") && (
            <Link href="/ember/deploy">
              <Button className="gap-2 bg-orange-600 hover:bg-orange-700">
                <Flame className="h-4 w-4" />
                Deploy Ember Implant
              </Button>
            </Link>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Caldera Agent Card ─────────────────────────────────────────────────────
function CalderaAgentCard({
  agent, expanded, onToggle, onKill, onTrust, onCopy, killPending, trustPending,
}: {
  agent: CalderaAgent;
  expanded: boolean;
  onToggle: () => void;
  onKill: () => void;
  onTrust: () => void;
  onCopy: (text: string, label: string) => void;
  killPending: boolean;
  trustPending: boolean;
}) {
  return (
    <Collapsible open={expanded} onOpenChange={onToggle}>
      <Card className="bg-card/50 overflow-hidden border-l-4 border-l-primary/60">
        <CollapsibleTrigger asChild>
          <CardHeader className="cursor-pointer hover:bg-accent/50 transition-colors py-3 sm:py-4">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-3 min-w-0">
                <div className="p-2 rounded-lg bg-primary/10 shrink-0">
                  {getPlatformIcon(agent.platform)}
                </div>
                <div className="min-w-0">
                  <CardTitle className="flex flex-wrap items-center gap-1.5 text-sm sm:text-base">
                    <span className="truncate">{agent.host}</span>
                    <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-primary/40 text-primary shrink-0">
                      CALDERA
                    </Badge>
                    <Badge variant={getCalderaStatusColor(agent.last_seen)} className="shrink-0">
                      {getCalderaStatusText(agent.last_seen)}
                    </Badge>
                    {agent.trusted ? (
                      <Badge variant="outline" className="text-green-500 border-green-500 shrink-0">
                        <Shield className="h-3 w-3 mr-0.5" />Trusted
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="text-yellow-500 border-yellow-500 shrink-0">
                        <ShieldOff className="h-3 w-3 mr-0.5" />Untrusted
                      </Badge>
                    )}
                  </CardTitle>
                  <CardDescription className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-1 text-xs">
                    <span className="flex items-center gap-1">
                      <Monitor className="h-3 w-3" />{agent.platform} ({agent.architecture})
                    </span>
                    <span className="flex items-center gap-1">
                      <Users className="h-3 w-3" />{agent.username}
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />Last seen: {formatTimeAgo(agent.last_seen)}
                    </span>
                  </CardDescription>
                </div>
              </div>
              <div className="shrink-0">
                {expanded ? <ChevronUp className="h-5 w-5 text-muted-foreground" /> : <ChevronDown className="h-5 w-5 text-muted-foreground" />}
              </div>
            </div>
          </CardHeader>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <CardContent className="border-t border-border pt-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h4 className="font-semibold text-sm text-muted-foreground uppercase tracking-wider">Agent Details</h4>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-muted-foreground">Agent ID (PAW)</p>
                    <div className="flex items-center gap-2">
                      <code className="font-mono text-xs bg-muted px-2 py-1 rounded truncate">{agent.paw}</code>
                      <Button variant="ghost" size="sm" className="h-6 w-6 p-0 shrink-0" onClick={() => onCopy(agent.paw, 'Agent ID')}>
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Group</p>
                    <p className="font-medium">{agent.group || 'red'}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Process ID</p>
                    <p className="font-medium">{agent.pid} (Parent: {agent.ppid})</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Privilege</p>
                    <Badge variant={agent.privilege === 'Elevated' ? 'default' : 'secondary'}>{agent.privilege}</Badge>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Contact Method</p>
                    <p className="font-medium">{agent.contact}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Sleep Interval</p>
                    <p className="font-medium">{agent.sleep_min}s - {agent.sleep_max}s</p>
                  </div>
                </div>
                <div>
                  <p className="text-muted-foreground text-sm mb-2">Executable Location</p>
                  <div className="flex items-center gap-2">
                    <Folder className="h-4 w-4 text-muted-foreground shrink-0" />
                    <code className="font-mono text-xs bg-muted px-2 py-1 rounded flex-1 overflow-hidden text-ellipsis">{agent.location}</code>
                    <Button variant="ghost" size="sm" className="h-6 w-6 p-0 shrink-0" onClick={() => onCopy(agent.location, 'Location')}>
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
                <div>
                  <p className="text-muted-foreground text-sm mb-2">IP Addresses</p>
                  <div className="flex flex-wrap gap-2">
                    {agent.host_ip_addrs?.map((ip, i) => (
                      <Badge key={i} variant="outline" className="font-mono text-xs">{ip}</Badge>
                    )) || <span className="text-muted-foreground text-sm">No IPs</span>}
                  </div>
                </div>
              </div>
              <div className="space-y-4">
                <h4 className="font-semibold text-sm text-muted-foreground uppercase tracking-wider">Capabilities</h4>
                <div>
                  <p className="text-muted-foreground text-sm mb-2">Available Executors</p>
                  <div className="flex flex-wrap gap-2">
                    {agent.executors?.map((exec, i) => (
                      <Badge key={i} variant="secondary"><Terminal className="h-3 w-3 mr-1" />{exec}</Badge>
                    )) || <span className="text-muted-foreground text-sm">No executors</span>}
                  </div>
                </div>
                <div>
                  <p className="text-muted-foreground text-sm mb-2">Timestamps</p>
                  <div className="text-sm space-y-1">
                    <p><span className="text-muted-foreground">Created:</span> {new Date(agent.created).toLocaleString()}</p>
                    <p><span className="text-muted-foreground">Last Seen:</span> {new Date(agent.last_seen).toLocaleString()}</p>
                  </div>
                </div>
                <div className="pt-4 border-t border-border">
                  <h4 className="font-semibold text-sm text-muted-foreground uppercase tracking-wider mb-3">Actions</h4>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="outline" size="sm" onClick={onTrust} disabled={trustPending}>
                      {agent.trusted ? <><ShieldOff className="h-4 w-4 mr-1" />Untrust</> : <><Shield className="h-4 w-4 mr-1" />Trust</>}
                    </Button>
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button variant="destructive" size="sm"><Trash2 className="h-4 w-4 mr-1" />Kill Agent</Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>Kill Agent?</AlertDialogTitle>
                          <AlertDialogDescription>
                            This will terminate the Caldera agent on {agent.host}. This action cannot be undone.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>Cancel</AlertDialogCancel>
                          <AlertDialogAction onClick={onKill} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
                            Kill Agent
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </div>
                </div>
              </div>
            </div>
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}

// ─── Ember Agent Card ───────────────────────────────────────────────────────
function EmberAgentCard({
  agent, expanded, onToggle, onKill, onCopy, killPending,
}: {
  agent: any;
  expanded: boolean;
  onToggle: () => void;
  onKill: () => void;
  onCopy: (text: string, label: string) => void;
  killPending: boolean;
}) {
  const stateClass = EMBER_STATE_COLORS[agent.state] || EMBER_STATE_COLORS.dead;
  const profileClass = EMBER_PROFILE_COLORS[agent.profile] || "";
  const profileIcon = EMBER_PROFILE_ICONS[agent.profile] || <Flame className="w-3.5 h-3.5" />;

  return (
    <Collapsible open={expanded} onOpenChange={onToggle}>
      <Card className="bg-card/50 overflow-hidden border-l-4 border-l-orange-500/60">
        <CollapsibleTrigger asChild>
          <CardHeader className="cursor-pointer hover:bg-accent/50 transition-colors py-3 sm:py-4">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-3 min-w-0">
                <div className="p-2 rounded-lg bg-orange-500/10 shrink-0">
                  <Flame className="h-5 w-5 text-orange-500" />
                </div>
                <div className="min-w-0">
                  <CardTitle className="flex flex-wrap items-center gap-1.5 text-sm sm:text-base">
                    <span className="truncate">{agent.name || agent.hostname || agent.agentId}</span>
                    <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-orange-500/40 text-orange-400 shrink-0">
                      EMBER
                    </Badge>
                    <Badge className={`text-[10px] px-1.5 py-0 border ${stateClass} shrink-0`}>
                      {agent.state}
                    </Badge>
                    <Badge className={`text-[10px] px-1.5 py-0 border ${profileClass} shrink-0`}>
                      {profileIcon}
                      <span className="ml-1">{agent.profile}</span>
                    </Badge>
                    {agent.cognitiveEnabled && (
                      <Badge variant="outline" className="text-purple-400 border-purple-400/40 shrink-0">
                        <Brain className="h-3 w-3 mr-0.5" />Cognitive
                      </Badge>
                    )}
                  </CardTitle>
                  <CardDescription className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-1 text-xs">
                    <span className="flex items-center gap-1">
                      {getPlatformIcon(agent.platform)}{agent.platform?.replace("_", " ")}
                    </span>
                    <span className="flex items-center gap-1">
                      <Radio className="h-3 w-3" />{agent.primaryChannel?.replace("_", " ") || "N/A"}
                    </span>
                    <span className="flex items-center gap-1">
                      <Activity className="h-3 w-3" />Beacons: {agent.beaconCount || 0}
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {agent.lastBeaconAt ? formatTimeAgo(agent.lastBeaconAt) : "Never"}
                    </span>
                  </CardDescription>
                </div>
              </div>
              <div className="shrink-0">
                {expanded ? <ChevronUp className="h-5 w-5 text-muted-foreground" /> : <ChevronDown className="h-5 w-5 text-muted-foreground" />}
              </div>
            </div>
          </CardHeader>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <CardContent className="border-t border-border pt-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h4 className="font-semibold text-sm text-muted-foreground uppercase tracking-wider">Implant Details</h4>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-muted-foreground">Agent ID</p>
                    <div className="flex items-center gap-2">
                      <code className="font-mono text-xs bg-muted px-2 py-1 rounded truncate">{agent.agentId}</code>
                      <Button variant="ghost" size="sm" className="h-6 w-6 p-0 shrink-0" onClick={() => onCopy(agent.agentId, 'Agent ID')}>
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Hostname</p>
                    <p className="font-medium">{agent.hostname || "N/A"}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Profile</p>
                    <Badge className={`border ${profileClass}`}>
                      {profileIcon}<span className="ml-1 capitalize">{agent.profile}</span>
                    </Badge>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Autonomy</p>
                    <Badge variant="outline" className="capitalize">{agent.autonomyLevel?.replace("_", " ") || "manual"}</Badge>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Beacon Interval</p>
                    <p className="font-medium">{agent.beaconInterval || 60}s (jitter: {agent.jitterPercent || 20}%)</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Beacon Count</p>
                    <p className="font-medium">{agent.beaconCount || 0}</p>
                  </div>
                </div>
                {agent.callbackUrls && (
                  <div>
                    <p className="text-muted-foreground text-sm mb-2">Callback URLs</p>
                    <div className="space-y-1">
                      {(typeof agent.callbackUrls === 'string' ? JSON.parse(agent.callbackUrls) : agent.callbackUrls)?.map?.((url: string, i: number) => (
                        <code key={i} className="block font-mono text-xs bg-muted px-2 py-1 rounded truncate">{url}</code>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              <div className="space-y-4">
                <h4 className="font-semibold text-sm text-muted-foreground uppercase tracking-wider">Evasion & Comms</h4>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div className="flex items-center gap-2">
                    <Lock className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="text-muted-foreground">Memory Encryption</span>
                    <Badge variant={agent.memoryEncryption ? "default" : "outline"} className="text-[10px] ml-auto">
                      {agent.memoryEncryption ? "ON" : "OFF"}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-2">
                    <Eye className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="text-muted-foreground">Sleep Obfuscation</span>
                    <Badge variant={agent.sleepObfuscation ? "default" : "outline"} className="text-[10px] ml-auto">
                      {agent.sleepObfuscation ? "ON" : "OFF"}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-2">
                    <Shield className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="text-muted-foreground">EDR Evasion</span>
                    <Badge variant={agent.edrEvasion ? "default" : "outline"} className="text-[10px] ml-auto">
                      {agent.edrEvasion ? "ON" : "OFF"}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-2">
                    <Globe className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="text-muted-foreground">Traffic Mimicry</span>
                    <Badge variant={agent.trafficMimicry ? "default" : "outline"} className="text-[10px] ml-auto">
                      {agent.trafficMimicry ? "ON" : "OFF"}
                    </Badge>
                  </div>
                </div>
                <div>
                  <p className="text-muted-foreground text-sm mb-2">Channels</p>
                  <div className="flex flex-wrap gap-2">
                    <Badge variant="secondary">
                      <Radio className="h-3 w-3 mr-1" />
                      {agent.primaryChannel?.replace(/_/g, " ") || "https beacon"}
                    </Badge>
                    {agent.fallbackChannels && (typeof agent.fallbackChannels === 'string' ? JSON.parse(agent.fallbackChannels) : agent.fallbackChannels)?.map?.((ch: string, i: number) => (
                      <Badge key={i} variant="outline" className="text-xs">
                        {ch.replace(/_/g, " ")}
                      </Badge>
                    ))}
                  </div>
                </div>
                <div className="pt-4 border-t border-border">
                  <h4 className="font-semibold text-sm text-muted-foreground uppercase tracking-wider mb-3">Actions</h4>
                  <div className="flex flex-wrap gap-2">
                    <Link href={`/ember/tasks`}>
                      <Button variant="outline" size="sm" className="gap-1">
                        <Terminal className="h-4 w-4" />Task Console
                      </Button>
                    </Link>
                    <Link href="/ember">
                      <Button variant="outline" size="sm" className="gap-1">
                        <Activity className="h-4 w-4" />Fleet Overview
                      </Button>
                    </Link>
                    {agent.state !== "dead" && (
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="destructive" size="sm"><Trash2 className="h-4 w-4 mr-1" />Kill Implant</Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Kill Ember Implant?</AlertDialogTitle>
                            <AlertDialogDescription>
                              This will send a termination signal to the Ember implant ({agent.name || agent.agentId}). The implant will clean traces and self-destruct.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction onClick={onKill} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
                              Kill Implant
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}
