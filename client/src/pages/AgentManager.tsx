import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
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
  Fingerprint,
  Server,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Activity,
  Cpu,
  Monitor,
  Terminal,
  Clock,
  Pause,
  Play,
  Trash2,
  Plus,
  RefreshCw,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Copy,
  Lock,
  Key,
  Network,
  Eye,
} from "lucide-react";

// ─── Helpers ──────────────────────────────────────────────────────────────

function formatTimestamp(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts).toLocaleString();
}

function formatRelativeTime(ts: number | null | undefined): string {
  if (!ts) return "Never";
  const diff = Date.now() - ts;
  const secs = Math.floor(diff / 1000);
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function statusBadge(status: string | null) {
  const s = status ?? "unknown";
  const variants: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
    active: "default",
    connected: "default",
    approved: "default",
    completed: "secondary",
    pending_approval: "outline",
    deploying: "outline",
    paused: "secondary",
    disconnected: "secondary",
    lost: "destructive",
    terminated: "destructive",
    failed: "destructive",
    error: "destructive",
  };
  return (
    <Badge variant={variants[s] ?? "outline"} className="text-xs uppercase">
      {s.replace(/_/g, " ")}
    </Badge>
  );
}

function platformIcon(platform: string) {
  switch (platform) {
    case "windows": return <Monitor className="h-4 w-4" />;
    case "linux": return <Terminal className="h-4 w-4" />;
    case "darwin": return <Cpu className="h-4 w-4" />;
    default: return <Server className="h-4 w-4" />;
  }
}

function c2Badge(protocol: string) {
  const colors: Record<string, string> = {
    caldera: "bg-red-500/10 text-red-400 border-red-500/20",
    sliver: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    metasploit: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    native: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${colors[protocol] ?? "bg-zinc-500/10 text-zinc-400 border-zinc-500/20"}`}>
      {protocol.toUpperCase()}
    </span>
  );
}

// ─── Stats Cards ──────────────────────────────────────────────────────────

function StatsOverview() {
  const { data, isLoading } = trpc.agentManager.dashboardStats.useQuery();

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Card key={i} className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-4">
              <Skeleton className="h-8 w-16 mb-2" />
              <Skeleton className="h-4 w-24" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  const stats = data ?? {
    agents: { total: 0, active: 0, pending: 0, paused: 0, lost: 0, terminated: 0, completed: 0 },
    c2Servers: { total: 0, connected: 0 },
    tasks: { total: 0, queued: 0, executing: 0, completed: 0, failed: 0 },
    fips: { providerActive: false, complianceLevel: "software-only", opensslVersion: "" },
  };

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-emerald-400">{stats.agents.active}</p>
              <p className="text-xs text-zinc-400 mt-1">Active Agents</p>
            </div>
            <Activity className="h-8 w-8 text-emerald-500/30" />
          </div>
          <div className="flex gap-2 mt-2 text-xs text-zinc-500">
            <span>{stats.agents.pending} pending</span>
            <span>·</span>
            <span>{stats.agents.total} total</span>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-blue-400">{stats.c2Servers.connected}</p>
              <p className="text-xs text-zinc-400 mt-1">C2 Servers</p>
            </div>
            <Server className="h-8 w-8 text-blue-500/30" />
          </div>
          <div className="flex gap-2 mt-2 text-xs text-zinc-500">
            <span>{stats.c2Servers.total} configured</span>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-amber-400">{stats.tasks.executing}</p>
              <p className="text-xs text-zinc-400 mt-1">Running Tasks</p>
            </div>
            <Cpu className="h-8 w-8 text-amber-500/30" />
          </div>
          <div className="flex gap-2 mt-2 text-xs text-zinc-500">
            <span>{stats.tasks.queued} queued</span>
            <span>·</span>
            <span>{stats.tasks.completed} done</span>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className={`text-2xl font-bold ${stats.fips.complianceLevel === "full" ? "text-emerald-400" : "text-amber-400"}`}>
                {stats.fips.complianceLevel === "full" ? "FIPS" : "SOFT"}
              </p>
              <p className="text-xs text-zinc-400 mt-1">Crypto Mode</p>
            </div>
            <Lock className="h-8 w-8 text-zinc-500/30" />
          </div>
          <div className="flex gap-2 mt-2 text-xs text-zinc-500">
            <span>{stats.fips.opensslVersion || "OpenSSL"}</span>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Agent List ───────────────────────────────────────────────────────────

function AgentList() {
  const [statusFilter, setStatusFilter] = useState<string | undefined>(undefined);
  const utils = trpc.useUtils();

  const { data, isLoading } = trpc.agentManager.listAgents.useQuery({
    status: statusFilter as any,
    limit: 50,
    offset: 0,
  });

  const approveMut = trpc.agentManager.approveDeployment.useMutation({
    onSuccess: () => { utils.agentManager.listAgents.invalidate(); utils.agentManager.dashboardStats.invalidate(); toast.success("Agent approved"); },
    onError: (e) => toast.error(e.message),
  });

  const pauseMut = trpc.agentManager.pauseAgent.useMutation({
    onSuccess: () => { utils.agentManager.listAgents.invalidate(); utils.agentManager.dashboardStats.invalidate(); toast.success("Agent paused"); },
    onError: (e) => toast.error(e.message),
  });

  const resumeMut = trpc.agentManager.resumeAgent.useMutation({
    onSuccess: () => { utils.agentManager.listAgents.invalidate(); utils.agentManager.dashboardStats.invalidate(); toast.success("Agent resumed"); },
    onError: (e) => toast.error(e.message),
  });

  const terminateMut = trpc.agentManager.terminateAgent.useMutation({
    onSuccess: () => { utils.agentManager.listAgents.invalidate(); utils.agentManager.dashboardStats.invalidate(); toast.success("Agent terminated"); },
    onError: (e) => toast.error(e.message),
  });

  const watchdogMut = trpc.agentManager.runWatchdog.useMutation({
    onSuccess: (result) => {
      utils.agentManager.listAgents.invalidate();
      utils.agentManager.dashboardStats.invalidate();
      if (result.markedLost > 0) {
        toast.warning(`Watchdog: ${result.markedLost} agent(s) marked as lost`);
      } else {
        toast.success(`Watchdog sweep: ${result.scannedAgents} agents scanned, all healthy`);
      }
    },
    onError: (e) => toast.error(e.message),
  });

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i} className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-4">
              <Skeleton className="h-6 w-48 mb-2" />
              <Skeleton className="h-4 w-32" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  const agents = data?.agents ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Select value={statusFilter ?? "all"} onValueChange={(v) => setStatusFilter(v === "all" ? undefined : v)}>
          <SelectTrigger className="w-48 bg-zinc-900 border-zinc-700">
            <SelectValue placeholder="Filter by status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="pending_approval">Pending Approval</SelectItem>
            <SelectItem value="paused">Paused</SelectItem>
            <SelectItem value="lost">Lost</SelectItem>
            <SelectItem value="terminated">Terminated</SelectItem>
            <SelectItem value="completed">Completed</SelectItem>
          </SelectContent>
        </Select>
        <span className="text-xs text-zinc-500">{data?.total ?? 0} agents</span>
        <Button
          size="sm"
          variant="outline"
          className="ml-auto text-amber-400 border-amber-500/30 hover:bg-amber-500/10"
          onClick={() => watchdogMut.mutate()}
          disabled={watchdogMut.isPending}
        >
          <Activity className="h-3.5 w-3.5 mr-1" />
          {watchdogMut.isPending ? "Sweeping..." : "Run Watchdog"}
        </Button>
      </div>

      {agents.length === 0 ? (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-8 text-center">
            <Fingerprint className="h-12 w-12 text-zinc-600 mx-auto mb-3" />
            <p className="text-zinc-400">No agents found</p>
            <p className="text-xs text-zinc-600 mt-1">Deploy a new agent to get started</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {agents.map((agent) => (
            <Card key={agent.id} className="bg-zinc-900/50 border-zinc-800 hover:border-zinc-700 transition-colors">
              <CardContent className="p-4">
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-3">
                    <div className="mt-1 text-zinc-500">{platformIcon(agent.targetPlatform)}</div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-zinc-200">{agent.name}</span>
                        {statusBadge(agent.status)}
                        {c2Badge(agent.c2Protocol)}
                      </div>
                      <div className="flex items-center gap-4 mt-1 text-xs text-zinc-500">
                        {agent.targetHostname && <span>{agent.targetHostname}</span>}
                        {agent.targetIp && <span>{agent.targetIp}</span>}
                        <span className="flex items-center gap-1">
                          {agent.status === "active" && agent.lastHeartbeat && (Date.now() - agent.lastHeartbeat) < (agent.beaconIntervalSeconds ?? 60) * 2000 ? (
                            <span className="relative flex h-2 w-2">
                              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                            </span>
                          ) : agent.status === "lost" ? (
                            <span className="h-2 w-2 rounded-full bg-red-500"></span>
                          ) : (
                            <Clock className="h-3 w-3" />
                          )}
                          {formatRelativeTime(agent.lastHeartbeat)}
                        </span>
                        <span>TTL: {Math.floor((agent.ttlSeconds ?? 0) / 3600)}h</span>
                        <span className="text-zinc-600">WD: {Math.floor((agent.watchdogSeconds ?? 14400) / 3600)}h</span>
                      </div>
                      {agent.description && (
                        <p className="text-xs text-zinc-600 mt-1 max-w-lg truncate">{agent.description}</p>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-1">
                    {agent.status === "pending_approval" && (
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/10"
                        onClick={() => approveMut.mutate({ id: agent.id })}
                        disabled={approveMut.isPending}
                      >
                        <CheckCircle className="h-3.5 w-3.5 mr-1" />
                        Approve
                      </Button>
                    )}
                    {agent.status === "active" && (
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-amber-400 border-amber-500/30 hover:bg-amber-500/10"
                        onClick={() => pauseMut.mutate({ id: agent.id })}
                        disabled={pauseMut.isPending}
                      >
                        <Pause className="h-3.5 w-3.5" />
                      </Button>
                    )}
                    {agent.status === "paused" && (
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/10"
                        onClick={() => resumeMut.mutate({ id: agent.id })}
                        disabled={resumeMut.isPending}
                      >
                        <Play className="h-3.5 w-3.5" />
                      </Button>
                    )}
                    {(agent.status === "active" || agent.status === "paused") && (
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button size="sm" variant="outline" className="text-red-400 border-red-500/30 hover:bg-red-500/10">
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent className="bg-zinc-900 border-zinc-700">
                          <AlertDialogHeader>
                            <AlertDialogTitle>Terminate Agent</AlertDialogTitle>
                            <AlertDialogDescription>
                              This will send a remote kill signal to <strong>{agent.name}</strong>. This action cannot be undone.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel className="bg-zinc-800 border-zinc-700">Cancel</AlertDialogCancel>
                            <AlertDialogAction
                              className="bg-red-600 hover:bg-red-700"
                              onClick={() => terminateMut.mutate({ id: agent.id })}
                            >
                              Terminate
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Deploy Agent Dialog ──────────────────────────────────────────────────

function DeployAgentDialog() {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [platform, setPlatform] = useState<"windows" | "linux" | "darwin">("linux");
  const [protocol, setProtocol] = useState<"caldera" | "sliver" | "metasploit" | "native">("caldera");
  const [ttl, setTtl] = useState("86400");
  const [beacon, setBeacon] = useState("60");
  const [targetHost, setTargetHost] = useState("");
  const [targetIp, setTargetIp] = useState("");

  const utils = trpc.useUtils();
  const deployMut = trpc.agentManager.requestDeployment.useMutation({
    onSuccess: (data) => {
      toast.success("Agent deployment requested", { description: `ID: ${data.id.slice(0, 8)}...` });
      utils.agentManager.listAgents.invalidate();
      utils.agentManager.dashboardStats.invalidate();
      setOpen(false);
      resetForm();
    },
    onError: (e) => toast.error(e.message),
  });

  function resetForm() {
    setName(""); setDescription(""); setPlatform("linux"); setProtocol("caldera");
    setTtl("86400"); setBeacon("60"); setTargetHost(""); setTargetIp("");
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button className="bg-emerald-600 hover:bg-emerald-700">
          <Plus className="h-4 w-4 mr-2" />
          Deploy Agent
        </Button>
      </DialogTrigger>
      <DialogContent className="bg-zinc-900 border-zinc-700 max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Fingerprint className="h-5 w-5 text-emerald-400" />
            Request Agent Deployment
          </DialogTitle>
          <DialogDescription>
            Submit a deployment request. An admin must approve before the agent activates.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-xs text-zinc-400">Agent Name</Label>
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="recon-agent-01"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
            <div>
              <Label className="text-xs text-zinc-400">Platform</Label>
              <Select value={platform} onValueChange={(v) => setPlatform(v as any)}>
                <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="darwin">macOS</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div>
            <Label className="text-xs text-zinc-400">Description</Label>
            <Input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Lateral movement recon on DMZ segment"
              className="bg-zinc-800 border-zinc-700 mt-1"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-xs text-zinc-400">C2 Protocol</Label>
              <Select value={protocol} onValueChange={(v) => setProtocol(v as any)}>
                <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="caldera">CALDERA</SelectItem>
                  <SelectItem value="sliver">Sliver</SelectItem>
                  <SelectItem value="metasploit">Metasploit</SelectItem>
                  <SelectItem value="native">Native (Ace C3)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs text-zinc-400">Beacon Interval (sec)</Label>
              <Input
                type="number"
                value={beacon}
                onChange={(e) => setBeacon(e.target.value)}
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-xs text-zinc-400">Target Hostname</Label>
              <Input
                value={targetHost}
                onChange={(e) => setTargetHost(e.target.value)}
                placeholder="dc01.corp.local"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
            <div>
              <Label className="text-xs text-zinc-400">Target IP</Label>
              <Input
                value={targetIp}
                onChange={(e) => setTargetIp(e.target.value)}
                placeholder="10.0.1.50"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
          </div>

          <div>
            <Label className="text-xs text-zinc-400">TTL (seconds)</Label>
            <Input
              type="number"
              value={ttl}
              onChange={(e) => setTtl(e.target.value)}
              className="bg-zinc-800 border-zinc-700 mt-1"
            />
            <p className="text-xs text-zinc-600 mt-1">Agent self-destructs after TTL expires. Default: 24h</p>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)} className="border-zinc-700">
            Cancel
          </Button>
          <Button
            className="bg-emerald-600 hover:bg-emerald-700"
            disabled={!name || deployMut.isPending}
            onClick={() =>
              deployMut.mutate({
                name,
                description: description || undefined,
                targetPlatform: platform,
                c2Protocol: protocol,
                ttlSeconds: parseInt(ttl) || 86400,
                beaconIntervalSeconds: parseInt(beacon) || 60,
                targetHostname: targetHost || undefined,
                targetIp: targetIp || undefined,
              })
            }
          >
            {deployMut.isPending ? "Submitting..." : "Request Deployment"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── C2 Servers Tab ───────────────────────────────────────────────────────

function C2ServersTab() {
  const [addOpen, setAddOpen] = useState(false);
  const [name, setName] = useState("");
  const [type, setType] = useState<"caldera" | "sliver" | "metasploit">("caldera");
  const [baseUrl, setBaseUrl] = useState("");
  const [apiKey, setApiKey] = useState("");

  const utils = trpc.useUtils();
  const { data: servers, isLoading } = trpc.agentManager.listC2Servers.useQuery();

  const addMut = trpc.agentManager.addC2Server.useMutation({
    onSuccess: () => {
      toast.success("C2 server added");
      utils.agentManager.listC2Servers.invalidate();
      utils.agentManager.dashboardStats.invalidate();
      setAddOpen(false);
      setName(""); setBaseUrl(""); setApiKey("");
    },
    onError: (e) => toast.error(e.message),
  });

  const testMut = trpc.agentManager.testC2Connection.useMutation({
    onSuccess: (data) => {
      if (data.status === "connected") {
        toast.success(data.message);
      } else {
        toast.error(data.message);
      }
      utils.agentManager.listC2Servers.invalidate();
    },
    onError: (e) => toast.error(e.message),
  });

  const removeMut = trpc.agentManager.removeC2Server.useMutation({
    onSuccess: () => {
      toast.success("C2 server removed");
      utils.agentManager.listC2Servers.invalidate();
      utils.agentManager.dashboardStats.invalidate();
    },
    onError: (e) => toast.error(e.message),
  });

  if (isLoading) {
    return <div className="space-y-3">{Array.from({ length: 2 }).map((_, i) => <Skeleton key={i} className="h-20 w-full" />)}</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-zinc-300">Configured C2 Servers</h3>
        <Dialog open={addOpen} onOpenChange={setAddOpen}>
          <DialogTrigger asChild>
            <Button size="sm" variant="outline" className="border-zinc-700">
              <Plus className="h-3.5 w-3.5 mr-1" />
              Add Server
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-zinc-900 border-zinc-700">
            <DialogHeader>
              <DialogTitle>Add C2 Server</DialogTitle>
              <DialogDescription>Configure a new C2 server connection.</DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label className="text-xs text-zinc-400">Name</Label>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Primary CALDERA" className="bg-zinc-800 border-zinc-700 mt-1" />
              </div>
              <div>
                <Label className="text-xs text-zinc-400">Type</Label>
                <Select value={type} onValueChange={(v) => setType(v as any)}>
                  <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="caldera">CALDERA</SelectItem>
                    <SelectItem value="sliver">Sliver</SelectItem>
                    <SelectItem value="metasploit">Metasploit</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs text-zinc-400">Base URL</Label>
                <Input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://caldera.internal:8443" className="bg-zinc-800 border-zinc-700 mt-1" />
              </div>
              <div>
                <Label className="text-xs text-zinc-400">API Key / Token</Label>
                <Input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="••••••••" className="bg-zinc-800 border-zinc-700 mt-1" />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setAddOpen(false)} className="border-zinc-700">Cancel</Button>
              <Button
                className="bg-blue-600 hover:bg-blue-700"
                disabled={!name || !baseUrl || addMut.isPending}
                onClick={() => addMut.mutate({ name, type, baseUrl, authConfig: { apiKey } })}
              >
                {addMut.isPending ? "Adding..." : "Add Server"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {(servers ?? []).length === 0 ? (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-8 text-center">
            <Server className="h-12 w-12 text-zinc-600 mx-auto mb-3" />
            <p className="text-zinc-400">No C2 servers configured</p>
            <p className="text-xs text-zinc-600 mt-1">Add a CALDERA, Sliver, or Metasploit server</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {(servers ?? []).map((server) => (
            <Card key={server.id} className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Server className="h-5 w-5 text-zinc-500" />
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-zinc-200">{server.name}</span>
                        {statusBadge(server.status)}
                        {c2Badge(server.type)}
                      </div>
                      <p className="text-xs text-zinc-500 mt-0.5">{server.baseUrl}</p>
                      {server.lastHealthCheck && (
                        <p className="text-xs text-zinc-600 mt-0.5">Last check: {formatRelativeTime(server.lastHealthCheck)}</p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-zinc-700"
                      onClick={() => testMut.mutate({ id: server.id })}
                      disabled={testMut.isPending}
                    >
                      <RefreshCw className={`h-3.5 w-3.5 ${testMut.isPending ? "animate-spin" : ""}`} />
                    </Button>
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button size="sm" variant="outline" className="text-red-400 border-red-500/30 hover:bg-red-500/10">
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent className="bg-zinc-900 border-zinc-700">
                        <AlertDialogHeader>
                          <AlertDialogTitle>Remove C2 Server</AlertDialogTitle>
                          <AlertDialogDescription>Remove <strong>{server.name}</strong> from the configuration?</AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel className="bg-zinc-800 border-zinc-700">Cancel</AlertDialogCancel>
                          <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => removeMut.mutate({ id: server.id })}>
                            Remove
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Audit Log Tab ────────────────────────────────────────────────────────

function AuditLogTab() {
  const { data: logs, isLoading } = trpc.agentManager.getAuditLog.useQuery({ limit: 100 });

  if (isLoading) {
    return <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}</div>;
  }

  const entries = logs ?? [];

  return (
    <div className="space-y-2">
      {entries.length === 0 ? (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-8 text-center">
            <Eye className="h-12 w-12 text-zinc-600 mx-auto mb-3" />
            <p className="text-zinc-400">No audit events yet</p>
          </CardContent>
        </Card>
      ) : (
        entries.map((entry) => (
          <div key={entry.id} className="flex items-start gap-3 p-3 rounded-lg bg-zinc-900/30 border border-zinc-800/50">
            <div className="mt-0.5">
              {entry.eventType.includes("terminated") || entry.eventType.includes("failed") ? (
                <XCircle className="h-4 w-4 text-red-400" />
              ) : entry.eventType.includes("approved") || entry.eventType.includes("completed") ? (
                <CheckCircle className="h-4 w-4 text-emerald-400" />
              ) : entry.eventType.includes("paused") ? (
                <Pause className="h-4 w-4 text-amber-400" />
              ) : (
                <Activity className="h-4 w-4 text-blue-400" />
              )}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-xs font-medium text-zinc-300 uppercase">{entry.eventType.replace(/_/g, " ")}</span>
                <Badge variant="outline" className="text-xs">{entry.actorType}</Badge>
              </div>
              <p className="text-xs text-zinc-500 mt-0.5">
                Agent: {entry.agentId.slice(0, 8)}... · {formatTimestamp(entry.createdAt)}
              </p>
            </div>
            <div className="text-xs text-zinc-600 font-mono" title="HMAC chain hash">
              #{entry.recordHash.slice(0, 8)}
            </div>
          </div>
        ))
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────

export default function AgentManager() {
  return (
    <AppShell>
      <div className="p-6 max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-3">
              <Fingerprint className="h-7 w-7 text-emerald-400" />
              Agent Manager
            </h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Monitor and manage all deployed agents across your infrastructure. View real-time agent status, heartbeat timing, and platform details. Use this page to check which agents are online, deploy new agents to target systems, or remove stale agents. Agents are the execution endpoints for adversary emulation operations.</p>
            <p className="text-sm text-zinc-500 mt-1">
              Multi-C2 agent lifecycle management with FIPS 140-3 cryptographic operations
            </p>
          </div>
          <DeployAgentDialog />
        </div>

        {/* Stats */}
        <StatsOverview />

        {/* Tabs */}
        <Tabs defaultValue="agents" className="w-full">
          <TabsList className="bg-zinc-900 border border-zinc-800">
            <TabsTrigger value="agents" className="data-[state=active]:bg-zinc-800">
              <Cpu className="h-4 w-4 mr-2" />
              Agents
            </TabsTrigger>
            <TabsTrigger value="c2servers" className="data-[state=active]:bg-zinc-800">
              <Server className="h-4 w-4 mr-2" />
              C2 Servers
            </TabsTrigger>
            <TabsTrigger value="audit" className="data-[state=active]:bg-zinc-800">
              <Eye className="h-4 w-4 mr-2" />
              Audit Log
            </TabsTrigger>
          </TabsList>

          <TabsContent value="agents" className="mt-4">
            <AgentList />
          </TabsContent>

          <TabsContent value="c2servers" className="mt-4">
            <C2ServersTab />
          </TabsContent>

          <TabsContent value="audit" className="mt-4">
            <AuditLogTab />
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
