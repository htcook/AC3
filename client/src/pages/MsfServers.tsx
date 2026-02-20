import { useState, useEffect } from "react";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { toast } from "sonner";
import {
  Server, Plus, RefreshCw, Trash2, Activity, CheckCircle2, XCircle, Clock,
  Loader2, Terminal, Globe, Shield, Cpu, HardDrive, AlertTriangle, Power, Zap
} from "lucide-react";
import { useWebSocket } from "@/hooks/useWebSocket";

import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
export default function MsfServers() {
  // Real-time MSF server events
  const { events: wsEvents, isConnected: wsConnected } = useWebSocket({
    channels: ['msf'],
    showToasts: true,
  });

  const [provisionOpen, setProvisionOpen] = useState(false);
  const [serverName, setServerName] = useState("msf-server-01");
  const [region, setRegion] = useState("nyc1");
  const [size, setSize] = useState("s-2vcpu-4gb");
  const [confirmDestroyId, setConfirmDestroyId] = useState<number | null>(null);

  const serversQuery = trpc.metasploit.listServers.useQuery();

  // Auto-refetch when MSF server events arrive
  useEffect(() => {
    if (wsEvents.length > 0) {
      serversQuery.refetch();
    }
  }, [wsEvents.length]);

  const provisionMut = trpc.metasploit.provisionServer.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Server provisioning started! Droplet ID: ${data.dropletId || "pending"}`);
      setProvisionOpen(false);
      serversQuery.refetch();
    },
    onError: (err: any) => toast.error(`Provisioning failed: ${sanitizeErrorForToast(err)}`),
  });

  const healthCheckMut = trpc.metasploit.checkServerHealth.useMutation({
    onSuccess: (data: any) => {
      if (data.status === "online") {
        toast.success(`Server is online — MSF ${data.version?.version || "connected"}`);
      } else {
        toast.warning(`Server is offline: ${data.error || "unreachable"}`);
      }
      serversQuery.refetch();
    },
    onError: (err: any) => toast.error(`Health check failed: ${sanitizeErrorForToast(err)}`),
  });

  const destroyMut = trpc.metasploit.destroyServer.useMutation({
    onSuccess: () => {
      toast.success("Server destroyed successfully");
      setConfirmDestroyId(null);
      serversQuery.refetch();
    },
    onError: (err: any) => toast.error(`Destroy failed: ${sanitizeErrorForToast(err)}`),
  });

  const servers = serversQuery.data || [];

  function getStatusBadge(status: string) {
    switch (status) {
      case "online": return <span className="flex items-center gap-1 text-green-400 text-xs font-bold"><CheckCircle2 className="w-3.5 h-3.5" />ONLINE</span>;
      case "provisioning": return <span className="flex items-center gap-1 text-yellow-400 text-xs font-bold"><Loader2 className="w-3.5 h-3.5 animate-spin" />PROVISIONING</span>;
      case "offline": return <span className="flex items-center gap-1 text-red-400 text-xs font-bold"><XCircle className="w-3.5 h-3.5" />OFFLINE</span>;
      case "destroyed": return <span className="flex items-center gap-1 text-zinc-500 text-xs font-bold"><Trash2 className="w-3.5 h-3.5" />DESTROYED</span>;
      default: return <span className="flex items-center gap-1 text-zinc-500 text-xs font-bold"><Clock className="w-3.5 h-3.5" />{status.toUpperCase()}</span>;
    }
  }

  return (
    <AppShell>
      <div className="min-h-screen bg-background text-foreground">
        <div className="max-w-[1400px] mx-auto px-4 py-6 space-y-6">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold flex items-center gap-2">
                <Server className="w-6 h-6 text-purple-500" />
                Exploit Servers
              </h1>
              <p className="text-sm text-muted-foreground mt-1">
                Provision and manage Exploit Framework instances on cloud provider
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Button size="sm" onClick={() => setProvisionOpen(true)} className="bg-purple-600 hover:bg-purple-700">
                <Plus className="w-4 h-4 mr-1" />Provision Server
              </Button>
              <Button variant="outline" size="sm" onClick={() => serversQuery.refetch()}>
                <RefreshCw className="w-4 h-4" />
              </Button>
            </div>
          </div>

          {/* Server Cards */}
          {serversQuery.isLoading ? (
            <div className="flex items-center justify-center py-20">
              <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
            </div>
          ) : servers.length === 0 ? (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="py-16 text-center">
                <Server className="w-12 h-12 mx-auto mb-4 text-zinc-600" />
                <h3 className="text-lg font-semibold text-zinc-300 mb-2">No Exploit Servers</h3>
                <p className="text-sm text-zinc-500 mb-4">Provision a cloud provider droplet with Exploit Framework pre-installed and MSGRPC auto-configured.</p>
                <Button onClick={() => setProvisionOpen(true)} className="bg-purple-600 hover:bg-purple-700">
                  <Plus className="w-4 h-4 mr-1" />Provision Your First Server
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {servers.map((server: any) => (
                <Card key={server.id} className="bg-zinc-900/50 border-zinc-800 hover:border-zinc-700 transition-colors">
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-base flex items-center gap-2">
                        <Terminal className="w-4 h-4 text-purple-400" />
                        {server.name}
                      </CardTitle>
                      {getStatusBadge(server.status)}
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div className="bg-zinc-800/50 rounded p-2">
                        <div className="text-xs text-zinc-500">IP Address</div>
                        <div className="text-zinc-200 font-mono text-xs">{server.ipAddress || "Pending..."}</div>
                      </div>
                      <div className="bg-zinc-800/50 rounded p-2">
                        <div className="text-xs text-zinc-500">Region</div>
                        <div className="text-zinc-200 text-xs">{server.region || "—"}</div>
                      </div>
                      <div className="bg-zinc-800/50 rounded p-2">
                        <div className="text-xs text-zinc-500">RPC Port</div>
                        <div className="text-zinc-200 font-mono text-xs">{server.rpcPort || 55553}</div>
                      </div>
                      <div className="bg-zinc-800/50 rounded p-2">
                        <div className="text-xs text-zinc-500">MSF Version</div>
                        <div className="text-zinc-200 text-xs">{server.msfVersion || "—"}</div>
                      </div>
                    </div>

                    {server.dropletId && (
                      <div className="bg-zinc-800/50 rounded p-2 text-xs">
                        <span className="text-zinc-500">Droplet ID:</span>{" "}
                        <span className="text-zinc-300 font-mono">{server.dropletId}</span>
                      </div>
                    )}

                    {server.lastHealthCheck && (
                      <div className="text-xs text-zinc-500">
                        Last checked: {new Date(server.lastHealthCheck).toLocaleString()}
                      </div>
                    )}

                    <div className="flex items-center gap-2 pt-2 border-t border-zinc-800">
                      <Button
                        variant="outline"
                        size="sm"
                        className="flex-1 text-xs"
                        onClick={() => healthCheckMut.mutate({ id: server.id })}
                        disabled={healthCheckMut.isPending}
                      >
                        {healthCheckMut.isPending ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : <Activity className="w-3 h-3 mr-1" />}
                        Health Check
                      </Button>
                      {server.status !== "destroyed" && (
                        <Button
                          variant="outline"
                          size="sm"
                          className="text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10 border-red-500/30"
                          onClick={() => setConfirmDestroyId(server.id)}
                        >
                          <Trash2 className="w-3 h-3" />
                        </Button>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          {/* Architecture Info */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2 text-zinc-400">
                <Shield className="w-4 h-4" />
                How It Works
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid md:grid-cols-4 gap-4 text-sm">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-purple-400 font-semibold">
                    <div className="w-6 h-6 rounded-full bg-purple-500/20 flex items-center justify-center text-xs font-bold">1</div>
                    Provision
                  </div>
                  <p className="text-zinc-500 text-xs">Spin up a cloud provider droplet with Docker-based Exploit Framework and MSGRPC daemon auto-configured.</p>
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-blue-400 font-semibold">
                    <div className="w-6 h-6 rounded-full bg-blue-500/20 flex items-center justify-center text-xs font-bold">2</div>
                    Connect
                  </div>
                  <p className="text-zinc-500 text-xs">Platform auto-connects via MSGRPC API. Search modules, configure payloads, and manage sessions remotely.</p>
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-red-400 font-semibold">
                    <div className="w-6 h-6 rounded-full bg-red-500/20 flex items-center justify-center text-xs font-bold">3</div>
                    Exploit
                  </div>
                  <p className="text-zinc-500 text-xs">Fire exploits from the Exploit Arsenal against authorized targets. Sessions auto-deploy emulation agents.</p>
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-green-400 font-semibold">
                    <div className="w-6 h-6 rounded-full bg-green-500/20 flex items-center justify-center text-xs font-bold">4</div>
                    Handoff
                  </div>
                  <p className="text-zinc-500 text-xs">Once emulation agent is running, post-exploitation chains execute automatically. Destroy the MSF droplet when done.</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Provision Dialog */}
        <Dialog open={provisionOpen} onOpenChange={setProvisionOpen}>
          <DialogContent className="max-w-md bg-zinc-950 border-zinc-800">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Plus className="w-5 h-5 text-purple-400" />
                Provision Exploit Server
              </DialogTitle>
              <DialogDescription>
                Creates a cloud provider droplet with Exploit Framework pre-installed via Docker.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 mt-4">
              <div>
                <label className="text-xs font-semibold text-zinc-400 uppercase block mb-1">Server Name</label>
                <Input value={serverName} onChange={e => setServerName(e.target.value)} placeholder="msf-server-01" className="bg-zinc-900 border-zinc-700" />
              </div>
              <div>
                <label className="text-xs font-semibold text-zinc-400 uppercase block mb-1">Region</label>
                <select value={region} onChange={e => setRegion(e.target.value)} className="w-full bg-zinc-900 border border-zinc-700 rounded px-3 py-2 text-sm text-zinc-300">
                  <option value="nyc1">New York 1 (NYC1)</option>
                  <option value="nyc3">New York 3 (NYC3)</option>
                  <option value="sfo3">San Francisco 3 (SFO3)</option>
                  <option value="ams3">Amsterdam 3 (AMS3)</option>
                  <option value="sgp1">Singapore 1 (SGP1)</option>
                  <option value="lon1">London 1 (LON1)</option>
                  <option value="fra1">Frankfurt 1 (FRA1)</option>
                  <option value="tor1">Toronto 1 (TOR1)</option>
                  <option value="blr1">Bangalore 1 (BLR1)</option>
                  <option value="syd1">Sydney 1 (SYD1)</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-semibold text-zinc-400 uppercase block mb-1">Droplet Size</label>
                <select value={size} onChange={e => setSize(e.target.value)} className="w-full bg-zinc-900 border border-zinc-700 rounded px-3 py-2 text-sm text-zinc-300">
                  <option value="s-2vcpu-4gb">2 vCPU / 4 GB RAM ($24/mo) — Minimum</option>
                  <option value="s-4vcpu-8gb">4 vCPU / 8 GB RAM ($48/mo) — Recommended</option>
                  <option value="s-8vcpu-16gb">8 vCPU / 16 GB RAM ($96/mo) — Heavy Use</option>
                </select>
              </div>
              <div className="bg-zinc-800/50 border border-zinc-700 rounded p-3 text-xs text-zinc-400 space-y-1">
                <p><strong className="text-zinc-300">What gets installed:</strong></p>
                <ul className="list-disc list-inside space-y-0.5">
                  <li>Docker + Exploit Framework (latest)</li>
                  <li>MSGRPC daemon on port 55553 (SSL enabled)</li>
                  <li>UFW firewall (SSH + MSGRPC only)</li>
                  <li>Auto-registered in platform with connection details</li>
                </ul>
              </div>
            </div>
            <DialogFooter className="mt-4">
              <Button variant="outline" onClick={() => setProvisionOpen(false)}>Cancel</Button>
              <Button
                className="bg-purple-600 hover:bg-purple-700"
                disabled={!serverName || provisionMut.isPending}
                onClick={() => provisionMut.mutate({ name: serverName, region, size })}
              >
                {provisionMut.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : <Zap className="w-4 h-4 mr-1" />}
                Provision Server
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Confirm Destroy Dialog */}
        <Dialog open={confirmDestroyId !== null} onOpenChange={() => setConfirmDestroyId(null)}>
          <DialogContent className="max-w-sm bg-zinc-950 border-zinc-800">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2 text-red-400">
                <AlertTriangle className="w-5 h-5" />
                Destroy Server
              </DialogTitle>
              <DialogDescription>
                This will permanently destroy the cloud provider droplet and all data on it. This action cannot be undone.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter className="mt-4">
              <Button variant="outline" onClick={() => setConfirmDestroyId(null)}>Cancel</Button>
              <Button
                className="bg-red-600 hover:bg-red-700"
                disabled={destroyMut.isPending}
                onClick={() => { if (confirmDestroyId) destroyMut.mutate({ id: confirmDestroyId }); }}
              >
                {destroyMut.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : <Trash2 className="w-4 h-4 mr-1" />}
                Destroy Server
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </AppShell>
  );
}
