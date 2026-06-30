import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import {
  Loader2, Hexagon, Play, Square, Terminal, Server, Cpu,
  Activity, Shield, Network, Radio, Wifi, Lock, Eye,
  Download, Upload, Camera, MonitorSmartphone
} from "lucide-react";
import AppShell from "@/components/AppShell";

const TRANSPORT_COLORS: Record<string, string> = {
  mtls: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  https: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  dns: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  wg: "bg-amber-500/20 text-amber-400 border-amber-500/30",
};

const OS_ICONS: Record<string, string> = {
  windows: "🪟",
  linux: "🐧",
  macos: "🍎",
};

export default function SliverC2() {
  const [activeTab, setActiveTab] = useState("sessions");
  const [showGenerate, setShowGenerate] = useState(false);
  const [implantName, setImplantName] = useState("");
  const [implantOs, setImplantOs] = useState("windows");
  const [implantArch, setImplantArch] = useState("amd64");
  const [implantTransport, setImplantTransport] = useState("mtls");
  const [implantFormat, setImplantFormat] = useState("exe");
  const [implantHost, setImplantHost] = useState("");
  const [implantPort, setImplantPort] = useState("443");
  const [obfuscation, setObfuscation] = useState(false);

  const statsQuery = trpc.sliverC2.getStats.useQuery(undefined, { refetchInterval: 5000 });
  const sessionsQuery = trpc.sliverC2.listSessions.useQuery(undefined, { refetchInterval: 5000 });
  const implantsQuery = trpc.sliverC2.listImplants.useQuery(undefined, { refetchInterval: 10000 });
  const listenersQuery = trpc.sliverC2.listListeners.useQuery(undefined, { refetchInterval: 10000 });

  const generateImplant = trpc.sliverC2.generateImplant.useMutation({
    onSuccess: () => {
      toast.success("Implant generated successfully");
      setShowGenerate(false);
      implantsQuery.refetch();
    },
    onError: (e) => toast.error(`Generation failed: ${e.message}`),
  });

  const startListener = trpc.sliverC2.startListener.useMutation({
    onSuccess: () => { toast.success("Listener started"); listenersQuery.refetch(); statsQuery.refetch(); },
    onError: (e) => toast.error(`Listener failed: ${e.message}`),
  });

  const stopListener = trpc.sliverC2.stopListener.useMutation({
    onSuccess: () => { toast.success("Listener stopped"); listenersQuery.refetch(); statsQuery.refetch(); },
    onError: (e) => toast.error(`Stop failed: ${e.message}`),
  });

  const stats = statsQuery.data;
  const sessions = sessionsQuery.data?.sessions || [];
  const implants = implantsQuery.data?.implants || [];
  const listeners = listenersQuery.data || [];

  return (
    <AppShell activePath="/sliver-c2">
      <div className="space-y-6 p-1">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight flex items-center gap-3">
              <Hexagon className="w-7 h-7 text-emerald-400" />
              Implant C2 Framework
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Manage implants, sessions, and listeners for the C2 framework. Generate cross-platform implants with mTLS, HTTPS, DNS, or WireGuard transport.
            </p>
          </div>
          <Dialog open={showGenerate} onOpenChange={setShowGenerate}>
            <DialogTrigger asChild>
              <Button className="bg-emerald-600 hover:bg-emerald-700">
                <Cpu className="w-4 h-4 mr-2" /> Generate Implant
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-lg">
              <DialogHeader>
                <DialogTitle>Generate Implant</DialogTitle>
                <DialogDescription>Configure and generate a new C2 implant.</DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label>Implant Name</Label>
                  <Input value={implantName} onChange={e => setImplantName(e.target.value)} placeholder="beacon-01" />
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <Label>OS</Label>
                    <Select value={implantOs} onValueChange={setImplantOs}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="windows">Windows</SelectItem>
                        <SelectItem value="linux">Linux</SelectItem>
                        <SelectItem value="macos">macOS</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Arch</Label>
                    <Select value={implantArch} onValueChange={setImplantArch}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="amd64">amd64</SelectItem>
                        <SelectItem value="arm64">arm64</SelectItem>
                        <SelectItem value="386">386</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Format</Label>
                    <Select value={implantFormat} onValueChange={setImplantFormat}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="exe">EXE</SelectItem>
                        <SelectItem value="shared">Shared Lib</SelectItem>
                        <SelectItem value="service">Service</SelectItem>
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
                      <SelectItem value="mtls">mTLS (Mutual TLS)</SelectItem>
                      <SelectItem value="https">HTTPS</SelectItem>
                      <SelectItem value="dns">DNS</SelectItem>
                      <SelectItem value="wg">WireGuard</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label>C2 Host</Label>
                    <Input value={implantHost} onChange={e => setImplantHost(e.target.value)} placeholder="c2.example.com" />
                  </div>
                  <div>
                    <Label>Port</Label>
                    <Input value={implantPort} onChange={e => setImplantPort(e.target.value)} placeholder="443" />
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Switch checked={obfuscation} onCheckedChange={setObfuscation} />
                  <Label>Enable Obfuscation (Garble)</Label>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setShowGenerate(false)}>Cancel</Button>
                <Button
                  className="bg-emerald-600 hover:bg-emerald-700"
                  disabled={!implantName || !implantHost || generateImplant.isPending}
                  onClick={() => generateImplant.mutate({
                    name: implantName,
                    os: implantOs as any,
                    arch: implantArch as any,
                    transport: implantTransport as any,
                    format: implantFormat as any,
                    host: implantHost,
                    port: parseInt(implantPort) || 443,
                    obfuscation,
                  })}
                >
                  {generateImplant.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Cpu className="w-4 h-4 mr-2" />}
                  Generate
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card className="border-border/50">
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground">Active Sessions</p>
                  <p className="text-2xl font-bold text-emerald-400">{stats?.activeSessions || 0}</p>
                </div>
                <Terminal className="w-8 h-8 text-emerald-400/30" />
              </div>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground">Total Implants</p>
                  <p className="text-2xl font-bold text-blue-400">{stats?.totalImplants || 0}</p>
                </div>
                <Cpu className="w-8 h-8 text-blue-400/30" />
              </div>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground">Active Listeners</p>
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
                  <p className="text-xs text-muted-foreground">Total Sessions</p>
                  <p className="text-2xl font-bold text-amber-400">{stats?.totalSessions || 0}</p>
                </div>
                <Network className="w-8 h-8 text-amber-400/30" />
              </div>
            </CardContent>
          </Card>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-card border border-border">
            <TabsTrigger value="sessions">Sessions</TabsTrigger>
            <TabsTrigger value="implants">Implants</TabsTrigger>
            <TabsTrigger value="listeners">Listeners</TabsTrigger>
          </TabsList>

          {/* Sessions */}
          <TabsContent value="sessions" className="space-y-3">
            {sessions.length === 0 ? (
              <Card className="border-dashed border-border/50">
                <CardContent className="flex flex-col items-center justify-center py-16 text-center">
                  <Terminal className="w-12 h-12 text-muted-foreground/30 mb-4" />
                  <p className="text-muted-foreground">No active sessions. Deploy an implant to establish a session.</p>
                </CardContent>
              </Card>
            ) : (
              sessions.map((s: any) => (
                <Card key={s.id} className="border-border/50 hover:border-emerald-500/30 transition-colors">
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-lg">
                          {OS_ICONS[s.os] || "💻"}
                        </div>
                        <div>
                          <p className="font-medium">{s.hostname} <span className="text-muted-foreground text-xs">({s.username})</span></p>
                          <p className="text-xs text-muted-foreground">{s.remoteAddress} · PID {s.pid || "?"} · {s.os} {s.arch}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={TRANSPORT_COLORS[s.transport] || "border-border"}>
                          {s.transport?.toUpperCase()}
                        </Badge>
                        <Badge variant="outline" className={s.status === "active" ? "text-emerald-400 border-emerald-500/30" : "text-red-400 border-red-500/30"}>
                          {s.status}
                        </Badge>
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
                  <Cpu className="w-12 h-12 text-muted-foreground/30 mb-4" />
                  <p className="text-muted-foreground">No implants generated yet. Click "Generate Implant" to create one.</p>
                </CardContent>
              </Card>
            ) : (
              implants.map((imp: any) => (
                <Card key={imp.id} className="border-border/50">
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-medium">{imp.name}</p>
                        <p className="text-xs text-muted-foreground">
                          {imp.os}/{imp.arch} · {imp.format} · {imp.host}:{imp.port}
                          {imp.obfuscation && " · Obfuscated"}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={TRANSPORT_COLORS[imp.transport] || "border-border"}>
                          {imp.transport?.toUpperCase()}
                        </Badge>
                        <span className="text-xs text-muted-foreground">{imp.size ? `${(imp.size / 1024 / 1024).toFixed(1)} MB` : ""}</span>
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
                  <p className="text-muted-foreground">No listeners configured. Start a listener to receive callbacks.</p>
                </CardContent>
              </Card>
            ) : (
              listeners.map((l: any) => (
                <Card key={l.id} className="border-border/50">
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-medium">{l.transport?.toUpperCase()} Listener</p>
                        <p className="text-xs text-muted-foreground">{l.host}:{l.port} · {l.connections} connections</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={l.status === "active" ? "text-emerald-400 border-emerald-500/30" : "text-gray-400 border-gray-500/30"}>
                          {l.status}
                        </Badge>
                        {l.status === "active" ? (
                          <Button size="sm" variant="outline" className="border-red-500/30 text-red-400 hover:bg-red-500/10" onClick={() => stopListener.mutate({ id: l.id })}>
                            <Square className="w-3 h-3 mr-1" /> Stop
                          </Button>
                        ) : null}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
