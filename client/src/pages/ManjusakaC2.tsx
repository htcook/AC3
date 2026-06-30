import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import {
  Loader2, Play, Square, Terminal, Server, Cpu,
  Activity, Shield, Network, Radio, Lock, Eye,
  MonitorSmartphone, Unplug, ArrowUpDown, Flame, Bug
} from "lucide-react";

const TRANSPORT_COLORS: Record<string, string> = {
  tcp: "bg-slate-500/20 text-slate-400 border-slate-500/30",
  http: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  https: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  websocket: "bg-violet-500/20 text-violet-400 border-violet-500/30",
  kcp: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  ssh: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
};

const PLATFORM_ICONS: Record<string, string> = {
  windows: "🪟",
  linux: "🐧",
};

export default function ManjusakaC2() {
  const [activeTab, setActiveTab] = useState("agents");
  const [showGenerate, setShowGenerate] = useState(false);
  const [showListener, setShowListener] = useState(false);

  // Implant form state
  const [implantName, setImplantName] = useState("");
  const [implantPlatform, setImplantPlatform] = useState("windows");
  const [implantArch, setImplantArch] = useState("x64");
  const [implantTransport, setImplantTransport] = useState("https");
  const [implantFormat, setImplantFormat] = useState("exe");
  const [implantHost, setImplantHost] = useState("");
  const [implantPort, setImplantPort] = useState("443");
  const [noiseEncryption, setNoiseEncryption] = useState(true);
  const [autoLoadNpc2, setAutoLoadNpc2] = useState(false);
  const [antiDebug, setAntiDebug] = useState(false);
  const [antiSandbox, setAntiSandbox] = useState(false);

  // Listener form state
  const [listenerName, setListenerName] = useState("");
  const [listenerProtocol, setListenerProtocol] = useState("https");
  const [listenerHost, setListenerHost] = useState("0.0.0.0");
  const [listenerPort, setListenerPort] = useState("443");
  const [listenerNoise, setListenerNoise] = useState(true);

  // Queries
  const statsQuery = trpc.manjusakaC2.getStats.useQuery(undefined, { refetchInterval: 5000 });
  const agentsQuery = trpc.manjusakaC2.listAgents.useQuery(undefined, { refetchInterval: 5000 });
  const implantsQuery = trpc.manjusakaC2.listImplants.useQuery(undefined, { refetchInterval: 10000 });
  const listenersQuery = trpc.manjusakaC2.listListeners.useQuery(undefined, { refetchInterval: 10000 });
  const tunnelsQuery = trpc.manjusakaC2.listTunnels.useQuery(undefined, { refetchInterval: 10000 });
  const vncQuery = trpc.manjusakaC2.listVncSessions.useQuery(undefined, { refetchInterval: 5000 });

  // Mutations
  const generateImplant = trpc.manjusakaC2.generateImplant.useMutation({
    onSuccess: () => { toast.success("NPC1 implant generated"); setShowGenerate(false); implantsQuery.refetch(); },
    onError: (e) => toast.error(`Generation failed: ${e.message}`),
  });

  const createListener = trpc.manjusakaC2.createListener.useMutation({
    onSuccess: () => { toast.success("Listener started"); setShowListener(false); listenersQuery.refetch(); statsQuery.refetch(); },
    onError: (e) => toast.error(`Listener failed: ${e.message}`),
  });

  const stopListener = trpc.manjusakaC2.stopListener.useMutation({
    onSuccess: () => { toast.success("Listener stopped"); listenersQuery.refetch(); statsQuery.refetch(); },
    onError: (e) => toast.error(`Stop failed: ${e.message}`),
  });

  const loadNpc2 = trpc.manjusakaC2.loadNpc2.useMutation({
    onSuccess: () => { toast.success("NPC2 loaded — full capabilities unlocked"); agentsQuery.refetch(); statsQuery.refetch(); },
    onError: (e) => toast.error(`NPC2 load failed: ${e.message}`),
  });

  const killAgent = trpc.manjusakaC2.killAgent.useMutation({
    onSuccess: () => { toast.success("Agent terminated"); agentsQuery.refetch(); statsQuery.refetch(); },
    onError: (e) => toast.error(`Kill failed: ${e.message}`),
  });

  const startVnc = trpc.manjusakaC2.startVnc.useMutation({
    onSuccess: () => { toast.success("VNC session started"); vncQuery.refetch(); agentsQuery.refetch(); },
    onError: (e) => toast.error(`VNC failed: ${e.message}`),
  });

  const stopVnc = trpc.manjusakaC2.stopVnc.useMutation({
    onSuccess: () => { toast.success("VNC session stopped"); vncQuery.refetch(); agentsQuery.refetch(); },
    onError: (e) => toast.error(`VNC stop failed: ${e.message}`),
  });

  const stopTunnel = trpc.manjusakaC2.stopTunnel.useMutation({
    onSuccess: () => { toast.success("Tunnel closed"); tunnelsQuery.refetch(); },
    onError: (e) => toast.error(`Tunnel stop failed: ${e.message}`),
  });

  const stats = statsQuery.data;
  const agents = agentsQuery.data?.agents || [];
  const implants = implantsQuery.data?.implants || [];
  const listeners = listenersQuery.data || [];
  const tunnels = tunnelsQuery.data || [];
  const vncSessions = vncQuery.data || [];

  return (
    <div className="space-y-6 p-1">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-3">
            <Flame className="w-7 h-7 text-rose-400" />
            Manjusaka C2 Framework
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Rust-native C2 with staged NPC1/NPC2 implants, Noise encryption, VNC remote desktop, and multi-protocol transport.
          </p>
        </div>
        <div className="flex gap-2">
          {/* Generate Implant Dialog */}
          <Dialog open={showGenerate} onOpenChange={setShowGenerate}>
            <DialogTrigger asChild>
              <Button className="bg-rose-600 hover:bg-rose-700">
                <Bug className="w-4 h-4 mr-2" /> Generate NPC1
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-lg">
              <DialogHeader>
                <DialogTitle>Generate NPC1 Implant</DialogTitle>
                <DialogDescription>Configure a Rust-native NPC1 stager. Optionally auto-load NPC2 for full capabilities.</DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label>Implant Name</Label>
                  <Input value={implantName} onChange={e => setImplantName(e.target.value)} placeholder="npc1-target-01" />
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <Label>Platform</Label>
                    <Select value={implantPlatform} onValueChange={setImplantPlatform}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="windows">Windows</SelectItem>
                        <SelectItem value="linux">Linux</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Arch</Label>
                    <Select value={implantArch} onValueChange={setImplantArch}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="x64">x64</SelectItem>
                        <SelectItem value="x86">x86</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Format</Label>
                    <Select value={implantFormat} onValueChange={setImplantFormat}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="exe">EXE</SelectItem>
                        <SelectItem value="dll">DLL</SelectItem>
                        <SelectItem value="elf">ELF</SelectItem>
                        <SelectItem value="shellcode">Shellcode</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div>
                  <Label>Transport</Label>
                  <Select value={implantTransport} onValueChange={setImplantTransport}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="tcp">TCP (Raw)</SelectItem>
                      <SelectItem value="http">HTTP</SelectItem>
                      <SelectItem value="https">HTTPS</SelectItem>
                      <SelectItem value="websocket">WebSocket</SelectItem>
                      <SelectItem value="kcp">KCP (UDP)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label>Callback Host</Label>
                    <Input value={implantHost} onChange={e => setImplantHost(e.target.value)} placeholder="c2.example.com" />
                  </div>
                  <div>
                    <Label>Port</Label>
                    <Input value={implantPort} onChange={e => setImplantPort(e.target.value)} placeholder="443" />
                  </div>
                </div>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <Switch checked={noiseEncryption} onCheckedChange={setNoiseEncryption} />
                    <Label>Noise Protocol Encryption</Label>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch checked={autoLoadNpc2} onCheckedChange={setAutoLoadNpc2} />
                    <Label>Auto-load NPC2 on callback</Label>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch checked={antiDebug} onCheckedChange={setAntiDebug} />
                    <Label>Anti-Debug</Label>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch checked={antiSandbox} onCheckedChange={setAntiSandbox} />
                    <Label>Anti-Sandbox</Label>
                  </div>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setShowGenerate(false)}>Cancel</Button>
                <Button
                  className="bg-rose-600 hover:bg-rose-700"
                  disabled={!implantName || !implantHost || generateImplant.isPending}
                  onClick={() => generateImplant.mutate({
                    name: implantName,
                    platform: implantPlatform as any,
                    arch: implantArch as any,
                    transport: implantTransport as any,
                    format: implantFormat as any,
                    callbackHost: implantHost,
                    callbackPort: parseInt(implantPort) || 443,
                    noiseEncryption,
                    autoLoadNpc2,
                    evasion: { antiDebug, antiSandbox, processHollowing: false, sleepObfuscation: false },
                  })}
                >
                  {generateImplant.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Bug className="w-4 h-4 mr-2" />}
                  Generate
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* Create Listener Dialog */}
          <Dialog open={showListener} onOpenChange={setShowListener}>
            <DialogTrigger asChild>
              <Button variant="outline" className="border-rose-500/30 text-rose-400 hover:bg-rose-500/10">
                <Radio className="w-4 h-4 mr-2" /> New Listener
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-md">
              <DialogHeader>
                <DialogTitle>Create Listener</DialogTitle>
                <DialogDescription>Start a new listener for NPC1 callbacks.</DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label>Name</Label>
                  <Input value={listenerName} onChange={e => setListenerName(e.target.value)} placeholder="https-listener-01" />
                </div>
                <div>
                  <Label>Protocol</Label>
                  <Select value={listenerProtocol} onValueChange={setListenerProtocol}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="tcp">TCP</SelectItem>
                      <SelectItem value="http">HTTP</SelectItem>
                      <SelectItem value="https">HTTPS</SelectItem>
                      <SelectItem value="websocket">WebSocket</SelectItem>
                      <SelectItem value="kcp">KCP</SelectItem>
                      <SelectItem value="ssh">SSH</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label>Bind Host</Label>
                    <Input value={listenerHost} onChange={e => setListenerHost(e.target.value)} placeholder="0.0.0.0" />
                  </div>
                  <div>
                    <Label>Port</Label>
                    <Input value={listenerPort} onChange={e => setListenerPort(e.target.value)} placeholder="443" />
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Switch checked={listenerNoise} onCheckedChange={setListenerNoise} />
                  <Label>Noise Encryption</Label>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setShowListener(false)}>Cancel</Button>
                <Button
                  className="bg-rose-600 hover:bg-rose-700"
                  disabled={!listenerName || createListener.isPending}
                  onClick={() => createListener.mutate({
                    name: listenerName,
                    protocol: listenerProtocol as any,
                    host: listenerHost,
                    port: parseInt(listenerPort) || 443,
                    noiseEncryption: listenerNoise,
                  })}
                >
                  {createListener.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Play className="w-4 h-4 mr-2" />}
                  Start
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <Card className="border-border/50">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Active Agents</p>
                <p className="text-2xl font-bold text-rose-400">{stats?.activeAgents || 0}</p>
              </div>
              <Terminal className="w-8 h-8 text-rose-400/30" />
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/50">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">NPC2 Loaded</p>
                <p className="text-2xl font-bold text-amber-400">{stats?.npc2Agents || 0}</p>
              </div>
              <Shield className="w-8 h-8 text-amber-400/30" />
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/50">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Implants</p>
                <p className="text-2xl font-bold text-blue-400">{stats?.totalImplants || 0}</p>
              </div>
              <Bug className="w-8 h-8 text-blue-400/30" />
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/50">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Listeners</p>
                <p className="text-2xl font-bold text-purple-400">{stats?.activeListeners || 0}</p>
              </div>
              <Radio className="w-8 h-8 text-purple-400/30" />
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/50">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">VNC Sessions</p>
                <p className="text-2xl font-bold text-emerald-400">{stats?.activeVncSessions || 0}</p>
              </div>
              <MonitorSmartphone className="w-8 h-8 text-emerald-400/30" />
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/50">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Tunnels</p>
                <p className="text-2xl font-bold text-cyan-400">{stats?.activeTunnels || 0}</p>
              </div>
              <ArrowUpDown className="w-8 h-8 text-cyan-400/30" />
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-card border border-border">
          <TabsTrigger value="agents">Agents</TabsTrigger>
          <TabsTrigger value="implants">Implants</TabsTrigger>
          <TabsTrigger value="listeners">Listeners</TabsTrigger>
          <TabsTrigger value="vnc">VNC</TabsTrigger>
          <TabsTrigger value="tunnels">Tunnels</TabsTrigger>
        </TabsList>

        {/* Agents */}
        <TabsContent value="agents" className="space-y-3">
          {agents.length === 0 ? (
            <Card className="border-dashed border-border/50">
              <CardContent className="flex flex-col items-center justify-center py-16 text-center">
                <Terminal className="w-12 h-12 text-muted-foreground/30 mb-4" />
                <p className="text-muted-foreground">No active agents. Deploy an NPC1 implant to establish a connection.</p>
              </CardContent>
            </Card>
          ) : (
            agents.map((a: any) => (
              <Card key={a.id} className="border-border/50 hover:border-rose-500/30 transition-colors">
                <CardContent className="py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-lg">
                        {PLATFORM_ICONS[a.platform] || "💻"}
                      </div>
                      <div>
                        <p className="font-medium">
                          {a.hostname} <span className="text-muted-foreground text-xs">({a.username})</span>
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {a.remoteAddress} · PID {a.pid || "?"} · {a.platform} {a.arch}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className={TRANSPORT_COLORS[a.transport] || "border-border"}>
                        {a.transport?.toUpperCase()}
                      </Badge>
                      <Badge variant="outline" className={a.agentType === "npc2" ? "text-amber-400 border-amber-500/30 bg-amber-500/10" : "text-slate-400 border-slate-500/30"}>
                        {a.agentType?.toUpperCase()}
                      </Badge>
                      <Badge variant="outline" className={a.status === "active" ? "text-emerald-400 border-emerald-500/30" : "text-red-400 border-red-500/30"}>
                        {a.status}
                      </Badge>
                      {a.agentType === "npc1" && a.status === "active" && (
                        <Button size="sm" variant="outline" className="border-amber-500/30 text-amber-400 hover:bg-amber-500/10"
                          disabled={loadNpc2.isPending}
                          onClick={() => loadNpc2.mutate({ agentId: a.id })}>
                          <Shield className="w-3 h-3 mr-1" /> Load NPC2
                        </Button>
                      )}
                      {a.npc2Loaded && a.status === "active" && !a.vncActive && (
                        <Button size="sm" variant="outline" className="border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10"
                          disabled={startVnc.isPending}
                          onClick={() => startVnc.mutate({ agentId: a.id })}>
                          <MonitorSmartphone className="w-3 h-3 mr-1" /> VNC
                        </Button>
                      )}
                      {a.vncActive && (
                        <Button size="sm" variant="outline" className="border-red-500/30 text-red-400 hover:bg-red-500/10"
                          onClick={() => stopVnc.mutate({ agentId: a.id })}>
                          <Eye className="w-3 h-3 mr-1" /> Stop VNC
                        </Button>
                      )}
                      <Button size="sm" variant="outline" className="border-red-500/30 text-red-400 hover:bg-red-500/10"
                        onClick={() => killAgent.mutate({ agentId: a.id })}>
                        <Square className="w-3 h-3 mr-1" /> Kill
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        {/* Implants */}
        <TabsContent value="implants" className="space-y-3">
          {implants.length === 0 ? (
            <Card className="border-dashed border-border/50">
              <CardContent className="flex flex-col items-center justify-center py-16 text-center">
                <Bug className="w-12 h-12 text-muted-foreground/30 mb-4" />
                <p className="text-muted-foreground">No implants generated yet. Click "Generate NPC1" to create one.</p>
              </CardContent>
            </Card>
          ) : (
            implants.map((imp: any) => (
              <Card key={imp.id} className="border-border/50">
                <CardContent className="py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-lg">
                        {PLATFORM_ICONS[imp.platform] || "💻"}
                      </div>
                      <div>
                        <p className="font-medium">{imp.name}</p>
                        <p className="text-xs text-muted-foreground">
                          {imp.platform}/{imp.arch} · {imp.format?.toUpperCase()} · {imp.callbackHost}:{imp.callbackPort}
                          {imp.noiseEncryption && " · 🔐 Noise"}
                          {imp.autoLoadNpc2 && " · Auto-NPC2"}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className={TRANSPORT_COLORS[imp.transport] || "border-border"}>
                        {imp.transport?.toUpperCase()}
                      </Badge>
                      <span className="text-xs text-muted-foreground">
                        {imp.size ? `${(imp.size / 1024).toFixed(0)} KB` : ""}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        {/* Listeners */}
        <TabsContent value="listeners" className="space-y-3">
          {listeners.length === 0 ? (
            <Card className="border-dashed border-border/50">
              <CardContent className="flex flex-col items-center justify-center py-16 text-center">
                <Radio className="w-12 h-12 text-muted-foreground/30 mb-4" />
                <p className="text-muted-foreground">No listeners configured. Click "New Listener" to start one.</p>
              </CardContent>
            </Card>
          ) : (
            listeners.map((l: any) => (
              <Card key={l.id} className="border-border/50">
                <CardContent className="py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center">
                        <Radio className="w-5 h-5 text-purple-400" />
                      </div>
                      <div>
                        <p className="font-medium">{l.name || `${l.protocol?.toUpperCase()} Listener`}</p>
                        <p className="text-xs text-muted-foreground">
                          {l.host}:{l.port} · {l.connections} connections
                          {l.noiseEncryption && " · 🔐 Noise"}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className={TRANSPORT_COLORS[l.protocol] || "border-border"}>
                        {l.protocol?.toUpperCase()}
                      </Badge>
                      <Badge variant="outline" className={l.status === "active" ? "text-emerald-400 border-emerald-500/30" : "text-gray-400 border-gray-500/30"}>
                        {l.status}
                      </Badge>
                      {l.status === "active" && (
                        <Button size="sm" variant="outline" className="border-red-500/30 text-red-400 hover:bg-red-500/10"
                          onClick={() => stopListener.mutate({ id: l.id })}>
                          <Square className="w-3 h-3 mr-1" /> Stop
                        </Button>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        {/* VNC Sessions */}
        <TabsContent value="vnc" className="space-y-3">
          {vncSessions.length === 0 ? (
            <Card className="border-dashed border-border/50">
              <CardContent className="flex flex-col items-center justify-center py-16 text-center">
                <MonitorSmartphone className="w-12 h-12 text-muted-foreground/30 mb-4" />
                <p className="text-muted-foreground">No active VNC sessions. Load NPC2 on an agent, then start VNC.</p>
              </CardContent>
            </Card>
          ) : (
            vncSessions.map((v: any) => {
              const agent = agents.find((a: any) => a.id === v.agentId);
              return (
                <Card key={v.id} className="border-border/50 hover:border-emerald-500/30 transition-colors">
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center">
                          <MonitorSmartphone className="w-5 h-5 text-emerald-400" />
                        </div>
                        <div>
                          <p className="font-medium">VNC → {agent?.hostname || `Agent #${v.agentId}`}</p>
                          <p className="text-xs text-muted-foreground">
                            Quality: {v.quality} · Frames: {v.framesReceived}
                            {v.resolution && ` · ${v.resolution}`}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-emerald-400 border-emerald-500/30">
                          <Activity className="w-3 h-3 mr-1" /> Live
                        </Badge>
                        <Button size="sm" variant="outline" className="border-red-500/30 text-red-400 hover:bg-red-500/10"
                          onClick={() => stopVnc.mutate({ agentId: v.agentId })}>
                          <Square className="w-3 h-3 mr-1" /> Stop
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })
          )}
        </TabsContent>

        {/* Tunnels */}
        <TabsContent value="tunnels" className="space-y-3">
          {tunnels.length === 0 ? (
            <Card className="border-dashed border-border/50">
              <CardContent className="flex flex-col items-center justify-center py-16 text-center">
                <ArrowUpDown className="w-12 h-12 text-muted-foreground/30 mb-4" />
                <p className="text-muted-foreground">No active tunnels. Create a tunnel through an NPC2 agent for pivoting.</p>
              </CardContent>
            </Card>
          ) : (
            tunnels.map((t: any) => {
              const agent = agents.find((a: any) => a.id === t.agentId);
              return (
                <Card key={t.id} className="border-border/50">
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
                          <ArrowUpDown className="w-5 h-5 text-cyan-400" />
                        </div>
                        <div>
                          <p className="font-medium">{t.type?.toUpperCase()} Tunnel via {agent?.hostname || `Agent #${t.agentId}`}</p>
                          <p className="text-xs text-muted-foreground">
                            :{t.localPort} → {t.remoteHost}:{t.remotePort} · {t.bytesTransferred || 0} bytes
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={t.status === "active" ? "text-cyan-400 border-cyan-500/30" : "text-gray-400 border-gray-500/30"}>
                          {t.status}
                        </Badge>
                        {t.status === "active" && (
                          <Button size="sm" variant="outline" className="border-red-500/30 text-red-400 hover:bg-red-500/10"
                            onClick={() => stopTunnel.mutate({ id: t.id })}>
                            <Unplug className="w-3 h-3 mr-1" /> Close
                          </Button>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
