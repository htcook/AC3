import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { Link } from "wouter";
import { 
  Cloud, 
  LayoutDashboard, 
  Key, 
  Users, 
  Target, 
  Activity,
  Cpu,
  Monitor,
  Server,
  Clock,
  Shield,
  ShieldOff,
  Trash2,
  RefreshCw,
  Terminal,
  Wifi,
  WifiOff,
  Copy,
  ChevronDown,
  ChevronUp,
  Folder,
  ExternalLink
} from "lucide-react";
import { useState } from "react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";

interface Agent {
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

function formatTimeAgo(dateString: string): string {
  const date = new Date(dateString);
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
  switch (platform.toLowerCase()) {
    case 'windows':
      return <Monitor className="h-5 w-5" />;
    case 'linux':
      return <Terminal className="h-5 w-5" />;
    case 'darwin':
      return <Cpu className="h-5 w-5" />;
    default:
      return <Server className="h-5 w-5" />;
  }
}

function getStatusColor(lastSeen: string): 'default' | 'secondary' | 'destructive' | 'outline' {
  const date = new Date(lastSeen);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 1000 / 60);

  if (diffMins < 5) return 'default'; // Active - green/teal
  if (diffMins < 30) return 'secondary'; // Idle
  return 'destructive'; // Stale/Dead
}

function getStatusText(lastSeen: string): string {
  const date = new Date(lastSeen);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 1000 / 60);

  if (diffMins < 5) return 'Active';
  if (diffMins < 30) return 'Idle';
  return 'Stale';
}

export default function Agents() {
  const [expandedAgents, setExpandedAgents] = useState<Set<string>>(new Set());
  
  const { data: agents, isLoading, refetch } = trpc.calderaProxy.getAgents.useQuery(undefined, {
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const killAgentMutation = trpc.calderaProxy.killAgent.useMutation({
    onSuccess: () => {
      toast.success("Agent terminated successfully");
      refetch();
    },
    onError: () => {
      toast.error("Failed to terminate agent");
    },
  });

  const updateTrustMutation = trpc.calderaProxy.updateAgentTrust.useMutation({
    onSuccess: (_, variables) => {
      toast.success(variables.trusted ? "Agent trusted" : "Agent untrusted");
      refetch();
    },
    onError: () => {
      toast.error("Failed to update agent trust");
    },
  });

  const toggleExpanded = (paw: string) => {
    const newExpanded = new Set(expandedAgents);
    if (newExpanded.has(paw)) {
      newExpanded.delete(paw);
    } else {
      newExpanded.add(paw);
    }
    setExpandedAgents(newExpanded);
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard`);
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background">
        <div className="flex">
          {/* Sidebar skeleton */}
          <div className="w-64 min-h-screen bg-card border-r border-border p-6">
            <Skeleton className="h-8 w-32 mb-8" />
            <div className="space-y-4">
              {[...Array(6)].map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          </div>
          {/* Main content skeleton */}
          <div className="flex-1 p-8">
            <Skeleton className="h-12 w-64 mb-8" />
            <div className="grid gap-6">
              {[...Array(3)].map((_, i) => (
                <Skeleton key={i} className="h-48 w-full" />
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  const agentList = (agents as Agent[]) || [];
  const activeAgents = agentList.filter(a => getStatusText(a.last_seen) === 'Active').length;
  const idleAgents = agentList.filter(a => getStatusText(a.last_seen) === 'Idle').length;
  const staleAgents = agentList.filter(a => getStatusText(a.last_seen) === 'Stale').length;

  return (
    <div className="min-h-screen bg-background">
      <div className="flex">
        {/* Sidebar */}
        <div className="w-64 min-h-screen bg-card border-r border-border">
          <div className="p-6">
            <Link href="/" className="flex items-center gap-2 mb-8">
              <Cloud className="h-8 w-8 text-primary" />
              <span className="font-bold text-xl tracking-tight">ACE OF CLOUD</span>
            </Link>
            
            <nav className="space-y-2">
              <Link href="/dashboard">
                <Button variant="ghost" className="w-full justify-start gap-2">
                  <LayoutDashboard className="h-4 w-4" />
                  Dashboard
                </Button>
              </Link>
              <Link href="/credentials">
                <Button variant="ghost" className="w-full justify-start gap-2">
                  <Key className="h-4 w-4" />
                  Credentials
                </Button>
              </Link>
              <Link href="/adversaries">
                <Button variant="ghost" className="w-full justify-start gap-2">
                  <Target className="h-4 w-4" />
                  Adversaries
                </Button>
              </Link>
              <Link href="/agents">
                <Button variant="default" className="w-full justify-start gap-2">
                  <Cpu className="h-4 w-4" />
                  Agents
                </Button>
              </Link>
              <Link href="/campaigns">
                <Button variant="ghost" className="w-full justify-start gap-2">
                  <Activity className="h-4 w-4" />
                  Campaigns
                </Button>
              </Link>
              <Link href="/team">
                <Button variant="ghost" className="w-full justify-start gap-2">
                  <Users className="h-4 w-4" />
                  Team
                </Button>
              </Link>
            </nav>
          </div>
          
          <div className="absolute bottom-0 w-64 p-6 border-t border-border">
            <div className="text-sm text-muted-foreground">
              <p>Signed in as</p>
              <p className="font-medium text-foreground">Admin</p>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 p-8">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div>
              <h1 className="text-4xl font-bold tracking-tight mb-2">DEPLOYED AGENTS</h1>
              <p className="text-muted-foreground">Monitor and manage Caldera agents across your infrastructure</p>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => refetch()} className="gap-2">
                <RefreshCw className="h-4 w-4" />
                Refresh
              </Button>
              <Link href="/agents/deploy">
                <Button 
                  variant="default" 
                  className="gap-2"
                >
                  <Terminal className="h-4 w-4" />
                  Deploy New Agent
                </Button>
              </Link>
            </div>
          </div>

          {/* Red divider */}
          <div className="h-1 bg-red-600 mb-8" />

          {/* Stats Cards */}
          <div className="grid grid-cols-4 gap-4 mb-8">
            <Card className="bg-card/50">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Total Agents</p>
                    <p className="text-3xl font-bold">{agentList.length}</p>
                  </div>
                  <Cpu className="h-8 w-8 text-primary" />
                </div>
              </CardContent>
            </Card>
            <Card className="bg-card/50">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Active</p>
                    <p className="text-3xl font-bold text-green-500">{activeAgents}</p>
                  </div>
                  <Wifi className="h-8 w-8 text-green-500" />
                </div>
              </CardContent>
            </Card>
            <Card className="bg-card/50">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Idle</p>
                    <p className="text-3xl font-bold text-yellow-500">{idleAgents}</p>
                  </div>
                  <Clock className="h-8 w-8 text-yellow-500" />
                </div>
              </CardContent>
            </Card>
            <Card className="bg-card/50">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Stale</p>
                    <p className="text-3xl font-bold text-red-500">{staleAgents}</p>
                  </div>
                  <WifiOff className="h-8 w-8 text-red-500" />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Agents List */}
          {agentList.length === 0 ? (
            <Card className="bg-card/50">
              <CardContent className="p-12 text-center">
                <Cpu className="h-16 w-16 mx-auto mb-4 text-muted-foreground" />
                <h3 className="text-xl font-semibold mb-2">No Agents Deployed</h3>
                <p className="text-muted-foreground mb-6">
                  Deploy Sandcat agents to your target systems to begin red team operations.
                </p>
                <Button 
                  variant="default"
                  onClick={() => window.open('https://dashboard.aceofcloud.io', '_blank')}
                >
                  Open Caldera to Deploy Agents
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {agentList.map((agent: Agent) => (
                <Collapsible 
                  key={agent.paw} 
                  open={expandedAgents.has(agent.paw)}
                  onOpenChange={() => toggleExpanded(agent.paw)}
                >
                  <Card className="bg-card/50 overflow-hidden">
                    <CollapsibleTrigger asChild>
                      <CardHeader className="cursor-pointer hover:bg-accent/50 transition-colors">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-4">
                            <div className="p-2 rounded-lg bg-primary/10">
                              {getPlatformIcon(agent.platform)}
                            </div>
                            <div>
                              <CardTitle className="flex items-center gap-2">
                                {agent.host}
                                <Badge variant={getStatusColor(agent.last_seen)}>
                                  {getStatusText(agent.last_seen)}
                                </Badge>
                                {agent.trusted ? (
                                  <Badge variant="outline" className="text-green-500 border-green-500">
                                    <Shield className="h-3 w-3 mr-1" />
                                    Trusted
                                  </Badge>
                                ) : (
                                  <Badge variant="outline" className="text-yellow-500 border-yellow-500">
                                    <ShieldOff className="h-3 w-3 mr-1" />
                                    Untrusted
                                  </Badge>
                                )}
                              </CardTitle>
                              <CardDescription className="flex items-center gap-4 mt-1">
                                <span className="flex items-center gap-1">
                                  <Monitor className="h-3 w-3" />
                                  {agent.platform} ({agent.architecture})
                                </span>
                                <span className="flex items-center gap-1">
                                  <Users className="h-3 w-3" />
                                  {agent.username}
                                </span>
                                <span className="flex items-center gap-1">
                                  <Clock className="h-3 w-3" />
                                  Last seen: {formatTimeAgo(agent.last_seen)}
                                </span>
                              </CardDescription>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            {expandedAgents.has(agent.paw) ? (
                              <ChevronUp className="h-5 w-5 text-muted-foreground" />
                            ) : (
                              <ChevronDown className="h-5 w-5 text-muted-foreground" />
                            )}
                          </div>
                        </div>
                      </CardHeader>
                    </CollapsibleTrigger>
                    
                    <CollapsibleContent>
                      <CardContent className="border-t border-border pt-6">
                        <div className="grid grid-cols-2 gap-6">
                          {/* Left Column - Agent Details */}
                          <div className="space-y-4">
                            <h4 className="font-semibold text-sm text-muted-foreground uppercase tracking-wider">Agent Details</h4>
                            
                            <div className="grid grid-cols-2 gap-4 text-sm">
                              <div>
                                <p className="text-muted-foreground">Agent ID (PAW)</p>
                                <div className="flex items-center gap-2">
                                  <code className="font-mono text-xs bg-muted px-2 py-1 rounded">{agent.paw}</code>
                                  <Button 
                                    variant="ghost" 
                                    size="sm" 
                                    className="h-6 w-6 p-0"
                                    onClick={() => copyToClipboard(agent.paw, 'Agent ID')}
                                  >
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
                                <Badge variant={agent.privilege === 'Elevated' ? 'default' : 'secondary'}>
                                  {agent.privilege}
                                </Badge>
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
                                <Folder className="h-4 w-4 text-muted-foreground" />
                                <code className="font-mono text-xs bg-muted px-2 py-1 rounded flex-1 overflow-hidden text-ellipsis">
                                  {agent.location}
                                </code>
                                <Button 
                                  variant="ghost" 
                                  size="sm" 
                                  className="h-6 w-6 p-0"
                                  onClick={() => copyToClipboard(agent.location, 'Location')}
                                >
                                  <Copy className="h-3 w-3" />
                                </Button>
                              </div>
                            </div>

                            <div>
                              <p className="text-muted-foreground text-sm mb-2">IP Addresses</p>
                              <div className="flex flex-wrap gap-2">
                                {agent.host_ip_addrs?.map((ip, i) => (
                                  <Badge key={i} variant="outline" className="font-mono text-xs">
                                    {ip}
                                  </Badge>
                                )) || <span className="text-muted-foreground text-sm">No IPs available</span>}
                              </div>
                            </div>
                          </div>

                          {/* Right Column - Executors & Actions */}
                          <div className="space-y-4">
                            <h4 className="font-semibold text-sm text-muted-foreground uppercase tracking-wider">Capabilities</h4>
                            
                            <div>
                              <p className="text-muted-foreground text-sm mb-2">Available Executors</p>
                              <div className="flex flex-wrap gap-2">
                                {agent.executors?.map((exec, i) => (
                                  <Badge key={i} variant="secondary">
                                    <Terminal className="h-3 w-3 mr-1" />
                                    {exec}
                                  </Badge>
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
                              <div className="flex gap-2">
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => updateTrustMutation.mutate({ paw: agent.paw, trusted: !agent.trusted })}
                                  disabled={updateTrustMutation.isPending}
                                >
                                  {agent.trusted ? (
                                    <>
                                      <ShieldOff className="h-4 w-4 mr-1" />
                                      Untrust
                                    </>
                                  ) : (
                                    <>
                                      <Shield className="h-4 w-4 mr-1" />
                                      Trust
                                    </>
                                  )}
                                </Button>
                                
                                <AlertDialog>
                                  <AlertDialogTrigger asChild>
                                    <Button variant="destructive" size="sm">
                                      <Trash2 className="h-4 w-4 mr-1" />
                                      Kill Agent
                                    </Button>
                                  </AlertDialogTrigger>
                                  <AlertDialogContent>
                                    <AlertDialogHeader>
                                      <AlertDialogTitle>Kill Agent?</AlertDialogTitle>
                                      <AlertDialogDescription>
                                        This will terminate the agent on {agent.host}. The agent process will be killed and removed from Caldera. This action cannot be undone.
                                      </AlertDialogDescription>
                                    </AlertDialogHeader>
                                    <AlertDialogFooter>
                                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                                      <AlertDialogAction
                                        onClick={() => killAgentMutation.mutate({ paw: agent.paw })}
                                        className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                      >
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
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
