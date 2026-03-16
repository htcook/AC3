import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { Network, Scan, Shield, Activity, Server, GitBranch, Crosshair, Brain, RefreshCw, ChevronRight, AlertTriangle, CheckCircle2, XCircle, Clock, Wifi } from "lucide-react";

export default function AgentInternalScanning() {
  const [selectedAgent, setSelectedAgent] = useState("agent-001");
  const [selectedScanType, setSelectedScanType] = useState("network_discovery");
  const [targetCidr, setTargetCidr] = useState("auto");
  const [safetyLevel, setSafetyLevel] = useState("standard");
  const [activeTab, setActiveTab] = useState("scans");

  const scanTypes = trpc.agentInternalScanning.getScanTypes.useQuery();
  const scans = trpc.agentInternalScanning.listScans.useQuery();
  const meshTopology = trpc.agentInternalScanning.getMeshTopology.useQuery();
  const stats = trpc.agentInternalScanning.dashboardStats.useQuery();
  const recommendations = trpc.agentInternalScanning.getSmartScanRecommendation.useMutation();

  const launchScan = trpc.agentInternalScanning.launchScan.useMutation({
    onSuccess: (data) => {
      if (data.status === "failed") {
        toast.error(`Scan failed: ${data.error}`);
      } else {
        toast.success(`Scan launched: ${data.scanType} from ${data.agentName}`);
      }
      scans.refetch();
      stats.refetch();
    },
  });

  const cancelScan = trpc.agentInternalScanning.cancelScan.useMutation({
    onSuccess: () => { toast.info("Scan cancelled"); scans.refetch(); },
  });

  const mockAgents = useMemo(() => [
    { id: "agent-001", name: "DC-Scanner-01", subnet: "10.0.1.0/24", os: "Ubuntu 22.04", status: "active" },
    { id: "agent-002", name: "DMZ-Relay-01", subnet: "172.16.0.0/24", os: "Debian 12", status: "active" },
    { id: "agent-003", name: "Workstation-Probe", subnet: "192.168.1.0/24", os: "Windows 11", status: "active" },
  ], []);

  const statusIcon = (status: string) => {
    switch (status) {
      case "completed": return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
      case "running": return <RefreshCw className="h-4 w-4 text-blue-400 animate-spin" />;
      case "failed": return <XCircle className="h-4 w-4 text-red-400" />;
      case "cancelled": return <XCircle className="h-4 w-4 text-zinc-400" />;
      default: return <Clock className="h-4 w-4 text-amber-400" />;
    }
  };

  const severityColor = (sev: string) => {
    switch (sev) {
      case "critical": return "bg-red-500/20 text-red-300 border-red-500/30";
      case "high": return "bg-orange-500/20 text-orange-300 border-orange-500/30";
      case "medium": return "bg-amber-500/20 text-amber-300 border-amber-500/30";
      case "low": return "bg-blue-500/20 text-blue-300 border-blue-500/30";
      default: return "bg-zinc-500/20 text-zinc-300 border-zinc-500/30";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Network className="h-7 w-7 text-cyan-400" />
            Agent Internal Scanning
          </h1>
          <p className="text-muted-foreground mt-1">Deploy agents inside target networks for internal reconnaissance, vulnerability scanning, and lateral path discovery</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => recommendations.mutate({ agentId: selectedAgent })}>
          <Brain className="h-4 w-4 mr-2" /> Smart Recommendations
        </Button>
      </div>

      {/* KPI Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
        {[
          { label: "Total Scans", value: stats.data?.totalScans ?? 0, icon: Scan, color: "text-blue-400" },
          { label: "Active", value: stats.data?.activeScans ?? 0, icon: Activity, color: "text-emerald-400" },
          { label: "Mesh Nodes", value: stats.data?.meshNodes ?? 0, icon: Wifi, color: "text-purple-400" },
          { label: "Subnets", value: stats.data?.totalSubnets ?? 0, icon: Network, color: "text-cyan-400" },
          { label: "Hosts Found", value: stats.data?.hostsDiscovered ?? 0, icon: Server, color: "text-amber-400" },
          { label: "Vulns", value: stats.data?.vulnsFound ?? 0, icon: AlertTriangle, color: "text-red-400" },
          { label: "Credentials", value: stats.data?.credentialsFound ?? 0, icon: Shield, color: "text-orange-400" },
          { label: "Lateral Paths", value: stats.data?.lateralPaths ?? 0, icon: GitBranch, color: "text-pink-400" },
        ].map((kpi) => (
          <Card key={kpi.label} className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-3 text-center">
              <kpi.icon className={`h-5 w-5 mx-auto mb-1 ${kpi.color}`} />
              <div className="text-xl font-bold">{kpi.value}</div>
              <div className="text-xs text-muted-foreground">{kpi.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Smart Recommendations */}
      {recommendations.data && recommendations.data.recommendations.length > 0 && (
        <Card className="bg-gradient-to-r from-cyan-950/30 to-blue-950/30 border-cyan-800/40">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2"><Brain className="h-4 w-4 text-cyan-400" /> AI Scan Recommendations</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {recommendations.data.recommendations.map((rec, i) => (
              <div key={i} className="flex items-center justify-between p-2 rounded bg-zinc-900/50">
                <div className="flex items-center gap-3">
                  <Badge variant="outline" className={rec.priority === "high" ? "border-red-500 text-red-400" : rec.priority === "medium" ? "border-amber-500 text-amber-400" : "border-zinc-500 text-zinc-400"}>
                    {rec.priority}
                  </Badge>
                  <span className="text-sm">{rec.reason}</span>
                </div>
                <Button size="sm" variant="ghost" onClick={() => { setSelectedScanType(rec.scanType); toast.info(`Selected: ${rec.scanType}`); }}>
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Launch Panel */}
      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-lg">Launch Internal Scan</CardTitle>
          <CardDescription>Select an agent, scan type, and target to begin internal reconnaissance</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 items-end">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Agent</label>
              <Select value={selectedAgent} onValueChange={setSelectedAgent}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {mockAgents.map(a => (
                    <SelectItem key={a.id} value={a.id}>{a.name} ({a.subnet})</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Scan Type</label>
              <Select value={selectedScanType} onValueChange={setSelectedScanType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {scanTypes.data?.map(st => (
                    <SelectItem key={st.type} value={st.type}>{st.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Target (CIDR or "auto")</label>
              <Input value={targetCidr} onChange={e => setTargetCidr(e.target.value)} placeholder="auto" />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Safety Level</label>
              <Select value={safetyLevel} onValueChange={setSafetyLevel}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="passive_only">Passive Only</SelectItem>
                  <SelectItem value="low_impact">Low Impact</SelectItem>
                  <SelectItem value="standard">Standard</SelectItem>
                  <SelectItem value="full_exploitation">Full Exploitation</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button
              onClick={() => {
                const agent = mockAgents.find(a => a.id === selectedAgent);
                launchScan.mutate({
                  agentId: selectedAgent,
                  agentName: agent?.name,
                  scanType: selectedScanType as any,
                  target: targetCidr,
                  safetyLevel: safetyLevel as any,
                });
              }}
              disabled={launchScan.isPending}
              className="bg-cyan-600 hover:bg-cyan-700"
            >
              <Crosshair className="h-4 w-4 mr-2" /> Launch Scan
            </Button>
          </div>
          {scanTypes.data && (
            <div className="mt-3 p-3 rounded bg-zinc-800/50 text-sm text-muted-foreground">
              {scanTypes.data.find(st => st.type === selectedScanType)?.description || "Select a scan type"}
              {" — Tools: "}
              {scanTypes.data.find(st => st.type === selectedScanType)?.toolsUsed.join(", ")}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="scans">Scan Results</TabsTrigger>
          <TabsTrigger value="mesh">Mesh Topology</TabsTrigger>
          <TabsTrigger value="agents">Deployed Agents</TabsTrigger>
        </TabsList>

        <TabsContent value="scans" className="space-y-3 mt-4">
          {(!scans.data || scans.data.length === 0) ? (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-12 text-center text-muted-foreground">
                <Network className="h-12 w-12 mx-auto mb-4 opacity-30" />
                <p>No scans yet. Launch a scan to begin internal reconnaissance.</p>
              </CardContent>
            </Card>
          ) : (
            scans.data.map(scan => (
              <Card key={scan.id} className="bg-zinc-900/50 border-zinc-800">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      {statusIcon(scan.status)}
                      <div>
                        <span className="font-medium">{SCAN_TYPE_CONFIG_LABELS[scan.scanType] || scan.scanType}</span>
                        <span className="text-muted-foreground text-sm ml-2">from {scan.agentName} → {scan.target}</span>
                      </div>
                      <Badge variant="outline" className="text-xs">{scan.safetyLevel}</Badge>
                    </div>
                    <div className="flex items-center gap-2">
                      {scan.status === "running" && (
                        <Button size="sm" variant="ghost" onClick={() => cancelScan.mutate({ taskId: scan.id })}>Cancel</Button>
                      )}
                      <Badge variant={scan.status === "completed" ? "default" : scan.status === "running" ? "secondary" : "destructive"}>
                        {scan.status}
                      </Badge>
                    </div>
                  </div>
                  {scan.status === "running" && <Progress value={scan.progress} className="h-1.5 mb-3" />}
                  {scan.results.length > 0 && (
                    <div className="space-y-1 mt-2">
                      <div className="text-xs text-muted-foreground mb-1">{scan.results.length} findings</div>
                      {scan.results.slice(0, 8).map((r, i) => (
                        <div key={i} className="flex items-center gap-2 text-sm p-1.5 rounded bg-zinc-800/50">
                          {r.severity && <Badge variant="outline" className={`text-xs ${severityColor(r.severity)}`}>{r.severity}</Badge>}
                          <span className="text-muted-foreground font-mono text-xs">{r.ip}{r.port ? `:${r.port}` : ""}</span>
                          <span className="truncate">{r.description}</span>
                        </div>
                      ))}
                      {scan.results.length > 8 && (
                        <div className="text-xs text-muted-foreground text-center pt-1">+ {scan.results.length - 8} more findings</div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        <TabsContent value="mesh" className="mt-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2"><Wifi className="h-5 w-5 text-purple-400" /> Mesh Network Topology</CardTitle>
              <CardDescription>Agent mesh network showing subnet coverage and inter-agent connectivity</CardDescription>
            </CardHeader>
            <CardContent>
              {meshTopology.data && meshTopology.data.nodes.length > 0 ? (
                <div className="space-y-3">
                  <div className="text-sm text-muted-foreground">{meshTopology.data.nodes.length} nodes, {meshTopology.data.totalSubnets} subnets, {meshTopology.data.edges.length} connections</div>
                  {meshTopology.data.nodes.map(node => (
                    <div key={node.agentId} className="flex items-center gap-4 p-3 rounded bg-zinc-800/50">
                      <Server className="h-5 w-5 text-cyan-400" />
                      <div>
                        <div className="font-medium">{node.agentName}</div>
                        <div className="text-xs text-muted-foreground">{node.subnet} | {node.os} | {node.role}</div>
                      </div>
                      <div className="ml-auto flex gap-1">
                        {node.capabilities.map(cap => (
                          <Badge key={cap} variant="outline" className="text-xs">{cap}</Badge>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center text-muted-foreground p-8">
                  <Wifi className="h-12 w-12 mx-auto mb-4 opacity-30" />
                  <p>No mesh nodes registered. Deploy agents and register them to build the mesh network.</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="agents" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {mockAgents.map(agent => (
              <Card key={agent.id} className="bg-zinc-900/50 border-zinc-800">
                <CardContent className="p-4">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                    <span className="font-medium">{agent.name}</span>
                  </div>
                  <div className="space-y-1 text-sm text-muted-foreground">
                    <div>Subnet: <span className="text-foreground font-mono">{agent.subnet}</span></div>
                    <div>OS: <span className="text-foreground">{agent.os}</span></div>
                    <div>Status: <Badge variant="outline" className="text-emerald-400 border-emerald-500/30">{agent.status}</Badge></div>
                  </div>
                  <Button size="sm" variant="outline" className="mt-3 w-full" onClick={() => { setSelectedAgent(agent.id); setActiveTab("scans"); toast.info(`Selected agent: ${agent.name}`); }}>
                    Select for Scanning
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

const SCAN_TYPE_CONFIG_LABELS: Record<string, string> = {
  network_discovery: "Network Discovery",
  port_scan: "Port Scan",
  vuln_scan: "Vulnerability Scan",
  service_enum: "Service Enumeration",
  lateral_path: "Lateral Movement Path Analysis",
  credential_spray: "Credential Spray",
  smb_enum: "SMB Enumeration",
  ad_recon: "Active Directory Reconnaissance",
};
