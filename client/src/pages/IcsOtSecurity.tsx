import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
// Auth handled by ProtectedRoute wrapper
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import {
  Shield, Server, Network, Search, AlertTriangle, Activity,
  Radio, Cpu, Eye, Plus, Trash2, RefreshCw, Zap, Target,
  Globe, Lock, Unlock, ChevronRight, BarChart3, Bug,
  Fingerprint, Radar, Skull, Factory, Gauge, Database,
} from "lucide-react";
import AppShell from "@/components/AppShell";

// ─── Types ────────────────────────────────────────────────────────────────────

interface IcsDevice {
  id: number;
  ipAddress: string;
  hostname: string | null;
  deviceType: string;
  vendor: string | null;
  model: string | null;
  firmwareVersion: string | null;
  protocols: string[] | null;
  openPorts: number[] | null;
  criticality: string | null;
  exposedToInternet: boolean | null;
  hasDefaultCredentials: boolean | null;
  hasKnownVulns: boolean | null;
  riskScore: number | null;
  discoverySource: string | null;
  sector: string | null;
  purdueLevel: string | null;
  networkSegment: string | null;
  facilityName: string | null;
  lastSeen: string | null;
  createdAt: string;
}

// ─── Helper Components ────────────────────────────────────────────────────────

function CriticalityBadge({ level }: { level: string | null }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-green-500/20 text-green-400 border-green-500/30",
  };
  return (
    <Badge variant="outline" className={colors[level || "medium"] || colors.medium}>
      {(level || "medium").toUpperCase()}
    </Badge>
  );
}

function ThreatLevelBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-green-500/20 text-green-400 border-green-500/30",
  };
  return (
    <Badge variant="outline" className={colors[level] || colors.medium}>
      <Skull className="w-3 h-3 mr-1" />
      {level.toUpperCase()}
    </Badge>
  );
}

function DeviceTypeIcon({ type }: { type: string }) {
  const icons: Record<string, React.ReactNode> = {
    plc: <Cpu className="w-4 h-4 text-blue-400" />,
    rtu: <Radio className="w-4 h-4 text-green-400" />,
    hmi: <Gauge className="w-4 h-4 text-purple-400" />,
    dcs: <Server className="w-4 h-4 text-orange-400" />,
    scada_server: <Database className="w-4 h-4 text-red-400" />,
    historian: <BarChart3 className="w-4 h-4 text-cyan-400" />,
    engineering_workstation: <Cpu className="w-4 h-4 text-yellow-400" />,
    safety_system: <Shield className="w-4 h-4 text-red-500" />,
    gateway: <Network className="w-4 h-4 text-teal-400" />,
    sensor: <Activity className="w-4 h-4 text-emerald-400" />,
    iot_device: <Globe className="w-4 h-4 text-indigo-400" />,
    camera: <Eye className="w-4 h-4 text-pink-400" />,
  };
  return icons[type] || <Server className="w-4 h-4 text-gray-400" />;
}

function RiskScoreBar({ score }: { score: number | null }) {
  const s = score ?? 0;
  const color = s >= 80 ? "bg-red-500" : s >= 60 ? "bg-orange-500" : s >= 40 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-24 h-2 bg-muted rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${Math.min(100, s)}%` }} />
      </div>
      <span className="text-xs text-muted-foreground">{s.toFixed(0)}</span>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function IcsOtSecurity() {
  const [activeTab, setActiveTab] = useState("dashboard");

  return (
    <AppShell activePath="/ics-ot-security">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Factory className="w-6 h-6 text-orange-400" />
            ICS/OT Security
          </h1>
          <p className="text-muted-foreground mt-1">
            Industrial Control Systems & Operational Technology security assessment platform
          </p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid grid-cols-6 w-full max-w-4xl">
          <TabsTrigger value="dashboard" className="flex items-center gap-1">
            <BarChart3 className="w-3.5 h-3.5" /> Dashboard
          </TabsTrigger>
          <TabsTrigger value="discovery" className="flex items-center gap-1">
            <Radar className="w-3.5 h-3.5" /> Discovery
          </TabsTrigger>
          <TabsTrigger value="devices" className="flex items-center gap-1">
            <Cpu className="w-3.5 h-3.5" /> Devices
          </TabsTrigger>
          <TabsTrigger value="apt" className="flex items-center gap-1">
            <Skull className="w-3.5 h-3.5" /> APT Threats
          </TabsTrigger>
          <TabsTrigger value="protocols" className="flex items-center gap-1">
            <Radio className="w-3.5 h-3.5" /> Protocols
          </TabsTrigger>
          <TabsTrigger value="exploits" className="flex items-center gap-1">
            <Bug className="w-3.5 h-3.5" /> ICS Exploits
          </TabsTrigger>
        </TabsList>

        {/* ─── Dashboard Tab ─────────────────────────────────────────────── */}
        <TabsContent value="dashboard" className="space-y-6">
          <DashboardTab />
        </TabsContent>

        {/* ─── Discovery Tab ─────────────────────────────────────────────── */}
        <TabsContent value="discovery" className="space-y-6">
          <DiscoveryTab />
        </TabsContent>

        {/* ─── Devices Tab ───────────────────────────────────────────────── */}
        <TabsContent value="devices" className="space-y-6">
          <DevicesTab />
        </TabsContent>

        {/* ─── APT Threats Tab ───────────────────────────────────────────── */}
        <TabsContent value="apt" className="space-y-6">
          <AptThreatsTab />
        </TabsContent>

        {/* ─── Protocols Tab ─────────────────────────────────────────────── */}
        <TabsContent value="protocols" className="space-y-6">
          <ProtocolsTab />
        </TabsContent>

        {/* ─── ICS Exploits Tab ──────────────────────────────────────────── */}
        <TabsContent value="exploits" className="space-y-6">
          <IcsExploitsTab />
        </TabsContent>
      </Tabs>
    </div>
    </AppShell>
  );
}

// ─── Dashboard Tab ────────────────────────────────────────────────────────────

function DashboardTab() {
  const stats = trpc.icsOtSecurity.getDashboardStats.useQuery();

  const statCards = [
    { label: "Total Devices", value: stats.data?.totalDevices ?? 0, icon: Cpu, color: "text-blue-400" },
    { label: "OT Networks", value: stats.data?.totalNetworks ?? 0, icon: Network, color: "text-green-400" },
    { label: "ICS Exploits", value: stats.data?.totalExploits ?? 0, icon: Bug, color: "text-red-400" },
    { label: "Assessments", value: stats.data?.totalAssessments ?? 0, icon: Shield, color: "text-purple-400" },
    { label: "Protocol Findings", value: stats.data?.totalFindings ?? 0, icon: AlertTriangle, color: "text-orange-400" },
    { label: "Critical Findings", value: stats.data?.criticalFindings ?? 0, icon: Zap, color: "text-red-500" },
    { label: "APT Groups Tracked", value: stats.data?.aptGroupsTracked ?? 0, icon: Skull, color: "text-amber-400" },
    { label: "Protocols Covered", value: stats.data?.protocolsCovered ?? 0, icon: Radio, color: "text-cyan-400" },
  ];

  return (
    <>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {statCards.map((stat) => (
          <Card key={stat.label} className="bg-card/50 border-border/50">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground">{stat.label}</p>
                  <p className="text-2xl font-bold mt-1">{stat.value}</p>
                </div>
                <stat.icon className={`w-8 h-8 ${stat.color} opacity-60`} />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* MITRE ATT&CK ICS Quick Reference */}
      <Card className="bg-card/50 border-border/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Target className="w-5 h-5 text-red-400" />
            MITRE ATT&CK for ICS — Tactic Coverage
          </CardTitle>
          <CardDescription>
            12 tactics covering the full ICS attack lifecycle from initial access to physical impact
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
            {[
              { name: "Initial Access", id: "TA0108", color: "border-blue-500/30 bg-blue-500/10" },
              { name: "Execution", id: "TA0104", color: "border-purple-500/30 bg-purple-500/10" },
              { name: "Persistence", id: "TA0110", color: "border-indigo-500/30 bg-indigo-500/10" },
              { name: "Evasion", id: "TA0103", color: "border-teal-500/30 bg-teal-500/10" },
              { name: "Discovery", id: "TA0102", color: "border-cyan-500/30 bg-cyan-500/10" },
              { name: "Lateral Movement", id: "TA0109", color: "border-green-500/30 bg-green-500/10" },
              { name: "Collection", id: "TA0100", color: "border-yellow-500/30 bg-yellow-500/10" },
              { name: "C&C", id: "TA0101", color: "border-orange-500/30 bg-orange-500/10" },
              { name: "Inhibit Response", id: "TA0107", color: "border-red-500/30 bg-red-500/10" },
              { name: "Impair Process", id: "TA0106", color: "border-rose-500/30 bg-rose-500/10" },
              { name: "Impact", id: "TA0105", color: "border-red-600/30 bg-red-600/10" },
              { name: "Physical Impact", id: "TA0111", color: "border-red-700/30 bg-red-700/10" },
            ].map((tactic) => (
              <div key={tactic.id} className={`p-3 rounded-lg border ${tactic.color}`}>
                <p className="text-xs font-mono text-muted-foreground">{tactic.id}</p>
                <p className="text-sm font-medium mt-1">{tactic.name}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Purdue Model Reference */}
      <Card className="bg-card/50 border-border/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Factory className="w-5 h-5 text-orange-400" />
            Purdue Model — Network Segmentation Reference
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {[
              { level: "Level 5", name: "Enterprise Network", desc: "Internet, cloud, external services", color: "bg-blue-500/20 border-blue-500/30" },
              { level: "Level 4", name: "Business Planning & Logistics", desc: "ERP, email, business apps", color: "bg-indigo-500/20 border-indigo-500/30" },
              { level: "Level 3.5", name: "DMZ / IT-OT Boundary", desc: "Firewalls, data diodes, jump servers", color: "bg-yellow-500/20 border-yellow-500/30" },
              { level: "Level 3", name: "Site Operations", desc: "SCADA servers, historians, engineering workstations", color: "bg-orange-500/20 border-orange-500/30" },
              { level: "Level 2", name: "Area Supervisory", desc: "HMI, operator workstations, alarm systems", color: "bg-orange-600/20 border-orange-600/30" },
              { level: "Level 1", name: "Basic Control", desc: "PLCs, RTUs, DCS controllers", color: "bg-red-500/20 border-red-500/30" },
              { level: "Level 0", name: "Physical Process", desc: "Sensors, actuators, field devices", color: "bg-red-600/20 border-red-600/30" },
            ].map((l) => (
              <div key={l.level} className={`flex items-center gap-4 p-3 rounded-lg border ${l.color}`}>
                <span className="text-sm font-mono font-bold w-20">{l.level}</span>
                <span className="text-sm font-medium w-48">{l.name}</span>
                <span className="text-xs text-muted-foreground">{l.desc}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </>
  );
}

// ─── Discovery Tab ────────────────────────────────────────────────────────────

function DiscoveryTab() {
  const [searchQuery, setSearchQuery] = useState("");
  const [searchSource, setSearchSource] = useState("shodan");
  const [discoveredDevices, setDiscoveredDevices] = useState<any[]>([]);

  const shodanDiscover = trpc.icsOtSecurity.discoverDevicesShodan.useMutation({
    onSuccess: (data) => {
      setDiscoveredDevices(data.devices);
      toast.success(`Discovery Complete: Found ${data.count} ICS devices via Shodan`);
    },
    onError: (err: any) => toast.error(`Discovery Failed: ${err.message}`),
  });

  const censysDiscover = trpc.icsOtSecurity.discoverDevicesCensys.useMutation({
    onSuccess: (data) => {
      setDiscoveredDevices(data.devices);
      toast.success(`Discovery Complete: Found ${data.count} ICS devices via Censys`);
    },
    onError: (err: any) => toast.error(`Discovery Failed: ${err.message}`),
  });

  const importDevices = trpc.icsOtSecurity.importDiscoveredDevices.useMutation({
    onSuccess: (data) => {
      toast.success(`Import Complete: Imported ${data.imported} new, updated ${data.updated} existing devices`);
    },
  });

  const handleDiscover = () => {
    if (!searchQuery.trim()) return;
    if (searchSource === "shodan") {
      shodanDiscover.mutate({ query: searchQuery, limit: 50 });
    } else {
      censysDiscover.mutate({ query: searchQuery, limit: 50 });
    }
  };

  const isSearching = shodanDiscover.isPending || censysDiscover.isPending;

  return (
    <>
      {/* Search Panel */}
      <Card className="bg-card/50 border-border/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Radar className="w-5 h-5 text-cyan-400" />
            ICS Device Discovery
          </CardTitle>
          <CardDescription>
            Search for exposed ICS/SCADA devices using Shodan or Censys. Common queries:
            <code className="ml-1 text-xs bg-muted px-1 py-0.5 rounded">port:502 modbus</code>,
            <code className="ml-1 text-xs bg-muted px-1 py-0.5 rounded">tag:scada country:US</code>,
            <code className="ml-1 text-xs bg-muted px-1 py-0.5 rounded">"Siemens" port:102</code>
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-3">
            <Select value={searchSource} onValueChange={setSearchSource}>
              <SelectTrigger className="w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="shodan">Shodan</SelectItem>
                <SelectItem value="censys">Censys</SelectItem>
              </SelectContent>
            </Select>
            <Input
              placeholder="Enter search query (e.g., port:502 modbus country:US)"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleDiscover()}
              className="flex-1"
            />
            <Button onClick={handleDiscover} disabled={isSearching || !searchQuery.trim()}>
              {isSearching ? <RefreshCw className="w-4 h-4 animate-spin mr-2" /> : <Search className="w-4 h-4 mr-2" />}
              Discover
            </Button>
          </div>

          {/* Preset Queries */}
          <div className="flex flex-wrap gap-2">
            <p className="text-xs text-muted-foreground mr-2 self-center">Quick searches:</p>
            {[
              { label: "Modbus TCP", query: "port:502" },
              { label: "S7comm (Siemens)", query: "port:102" },
              { label: "BACnet", query: "port:47808" },
              { label: "DNP3", query: "port:20000" },
              { label: "EtherNet/IP", query: "port:44818" },
              { label: "MQTT", query: "port:1883" },
              { label: "OPC-UA", query: "port:4840" },
              { label: "IEC 104", query: "port:2404" },
              { label: "Niagara Fox", query: "port:1911" },
            ].map((preset) => (
              <Button
                key={preset.label}
                variant="outline"
                size="sm"
                className="text-xs"
                onClick={() => { setSearchQuery(preset.query); }}
              >
                {preset.label}
              </Button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      {discoveredDevices.length > 0 && (
        <Card className="bg-card/50 border-border/50">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg">
                Discovered Devices ({discoveredDevices.length})
              </CardTitle>
              <Button
                size="sm"
                onClick={() => importDevices.mutate({
                  devices: discoveredDevices.map((d: any) => ({
                    ipAddress: d.ip_str || d.ip || "unknown",
                    hostname: d.hostnames?.[0] || d.hostname || undefined,
                    deviceType: "unknown",
                    vendor: d.org || undefined,
                    protocols: d.protocols || [],
                    openPorts: d.ports || [d.port] || [],
                  })),
                })}
                disabled={importDevices.isPending}
              >
                <Plus className="w-4 h-4 mr-1" />
                Import All to Inventory
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {discoveredDevices.map((device: any, idx: number) => (
                <div key={idx} className="flex items-center justify-between p-3 bg-muted/30 rounded-lg border border-border/30">
                  <div className="flex items-center gap-3">
                    <Server className="w-4 h-4 text-cyan-400" />
                    <div>
                      <p className="text-sm font-mono">{device.ip_str || device.ip}</p>
                      <p className="text-xs text-muted-foreground">
                        {device.org || "Unknown"} • Port {device.port || "N/A"} • {device.product || "Unknown service"}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {device.vulns && (
                      <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-500/30 text-xs">
                        {Object.keys(device.vulns).length} CVEs
                      </Badge>
                    )}
                    <Badge variant="outline" className="text-xs">
                      {device.country_code || "??"}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Fingerprint Tool */}
      <FingerprintPanel />
    </>
  );
}

function FingerprintPanel() {
  const [bannerText, setBannerText] = useState("");
  const [port, setPort] = useState("502");
  const [result, setResult] = useState<any>(null);

  const fingerprint = trpc.icsOtSecurity.fingerprintDevice.useMutation({
    onSuccess: (data) => {
      setResult(data);
      toast.success("Fingerprint Complete");
    },
  });

  return (
    <Card className="bg-card/50 border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <Fingerprint className="w-5 h-5 text-purple-400" />
          Device Fingerprinting
        </CardTitle>
        <CardDescription>
          Paste a service banner or response data to identify the ICS device type, vendor, and risk factors
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-4 gap-3">
          <div className="col-span-3">
            <Label>Banner / Response Data</Label>
            <Textarea
              placeholder="Paste banner data, Modbus response, or service identification string..."
              value={bannerText}
              onChange={(e) => setBannerText(e.target.value)}
              rows={3}
            />
          </div>
          <div>
            <Label>Port</Label>
            <Input value={port} onChange={(e) => setPort(e.target.value)} type="number" />
            <Button
              className="w-full mt-2"
              onClick={() => fingerprint.mutate({ ip: bannerText, port: parseInt(port) || 502 })}
              disabled={fingerprint.isPending || !bannerText.trim()}
            >
              <Fingerprint className="w-4 h-4 mr-1" />
              Identify
            </Button>
          </div>
        </div>

        {result && (
          <div className="p-4 bg-muted/30 rounded-lg border border-border/30 space-y-3">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div>
                <p className="text-xs text-muted-foreground">Device Type</p>
                <p className="text-sm font-medium flex items-center gap-1">
                  <DeviceTypeIcon type={result.deviceType} />
                  {result.deviceType}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Vendor</p>
                <p className="text-sm font-medium">{result.vendor || "Unknown"}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Purdue Level</p>
                <p className="text-sm font-medium">{result.purdueLevel}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Criticality</p>
                <CriticalityBadge level={result.criticality} />
              </div>
            </div>
            {result.riskFactors?.length > 0 && (
              <div>
                <p className="text-xs text-muted-foreground mb-1">Risk Factors</p>
                <div className="flex flex-wrap gap-1">
                  {result.riskFactors.map((rf: string, i: number) => (
                    <Badge key={i} variant="outline" className="text-xs bg-red-500/10 text-red-400 border-red-500/20">
                      {rf}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
            {result.protocols?.length > 0 && (
              <div>
                <p className="text-xs text-muted-foreground mb-1">Detected Protocols</p>
                <div className="flex flex-wrap gap-1">
                  {result.protocols.map((p: string, i: number) => (
                    <Badge key={i} variant="outline" className="text-xs">{p}</Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Devices Tab ──────────────────────────────────────────────────────────────

function DevicesTab() {
  const devices = trpc.icsOtSecurity.listDevices.useQuery({ limit: 100, offset: 0 });
  const deleteDevice = trpc.icsOtSecurity.deleteDevice.useMutation({
    onSuccess: () => {
      devices.refetch();
      toast.success("Device removed");
    },
  });

  const [showAddDialog, setShowAddDialog] = useState(false);
  const [newDevice, setNewDevice] = useState({
    ipAddress: "", hostname: "", deviceType: "plc", vendor: "", model: "",
    firmwareVersion: "", protocols: [] as string[], openPorts: [] as number[],
    criticality: "medium",
  });

  const addDevice = trpc.icsOtSecurity.addDevice.useMutation({
    onSuccess: () => {
      devices.refetch();
      setShowAddDialog(false);
      toast.success("Device added to inventory");
    },
  });

  const deviceList = (devices.data?.devices || []) as unknown as IcsDevice[];

  return (
    <>
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Device Inventory</h2>
          <p className="text-sm text-muted-foreground">{devices.data?.total || 0} devices tracked</p>
        </div>
        <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
          <DialogTrigger asChild>
            <Button size="sm"><Plus className="w-4 h-4 mr-1" /> Add Device</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add ICS Device</DialogTitle>
              <DialogDescription>Manually add an ICS/OT device to the inventory</DialogDescription>
            </DialogHeader>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>IP Address *</Label>
                <Input value={newDevice.ipAddress} onChange={(e) => setNewDevice({ ...newDevice, ipAddress: e.target.value })} />
              </div>
              <div>
                <Label>Hostname</Label>
                <Input value={newDevice.hostname} onChange={(e) => setNewDevice({ ...newDevice, hostname: e.target.value })} />
              </div>
              <div>
                <Label>Device Type</Label>
                <Select value={newDevice.deviceType} onValueChange={(v) => setNewDevice({ ...newDevice, deviceType: v })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {["plc", "rtu", "hmi", "dcs", "scada_server", "historian", "engineering_workstation",
                      "safety_system", "gateway", "switch", "sensor", "actuator", "iot_device", "camera",
                      "building_automation", "medical_device", "smart_meter"].map((t) => (
                      <SelectItem key={t} value={t}>{t.replace(/_/g, " ").toUpperCase()}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Criticality</Label>
                <Select value={newDevice.criticality} onValueChange={(v) => setNewDevice({ ...newDevice, criticality: v })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Vendor</Label>
                <Input value={newDevice.vendor} onChange={(e) => setNewDevice({ ...newDevice, vendor: e.target.value })} />
              </div>
              <div>
                <Label>Model</Label>
                <Input value={newDevice.model} onChange={(e) => setNewDevice({ ...newDevice, model: e.target.value })} />
              </div>
            </div>
            <Button
              className="w-full mt-2"
              onClick={() => addDevice.mutate(newDevice)}
              disabled={addDevice.isPending || !newDevice.ipAddress}
            >
              Add Device
            </Button>
          </DialogContent>
        </Dialog>
      </div>

      {deviceList.length === 0 ? (
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-12 text-center">
            <Cpu className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-40" />
            <p className="text-muted-foreground">No devices in inventory yet.</p>
            <p className="text-sm text-muted-foreground mt-1">Use the Discovery tab to find ICS devices, or add them manually.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {deviceList.map((device) => (
            <Card key={device.id} className="bg-card/50 border-border/50 hover:border-border transition-colors">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <DeviceTypeIcon type={device.deviceType} />
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-mono font-medium">{device.ipAddress}</p>
                        {device.hostname && <span className="text-xs text-muted-foreground">({device.hostname})</span>}
                      </div>
                      <div className="flex items-center gap-2 mt-1">
                        <Badge variant="outline" className="text-xs">{device.deviceType.replace(/_/g, " ")}</Badge>
                        {device.vendor && <span className="text-xs text-muted-foreground">{device.vendor} {device.model || ""}</span>}
                        {device.discoverySource && (
                          <Badge variant="outline" className="text-xs bg-blue-500/10 text-blue-400 border-blue-500/20">
                            {device.discoverySource}
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="text-right">
                      <CriticalityBadge level={device.criticality} />
                      <RiskScoreBar score={device.riskScore} />
                    </div>
                    <div className="flex items-center gap-1">
                      {device.exposedToInternet && (
                        <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-500/30 text-xs">
                          <Globe className="w-3 h-3 mr-1" /> Internet
                        </Badge>
                      )}
                      {device.hasDefaultCredentials && (
                        <Badge variant="outline" className="bg-orange-500/20 text-orange-400 border-orange-500/30 text-xs">
                          <Unlock className="w-3 h-3 mr-1" /> Default Creds
                        </Badge>
                      )}
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="text-destructive hover:text-destructive"
                      onClick={() => deleteDevice.mutate({ id: device.id })}
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
                {/* Protocols row */}
                {device.protocols && (device.protocols as string[]).length > 0 && (
                  <div className="flex items-center gap-1 mt-2">
                    <Radio className="w-3 h-3 text-muted-foreground" />
                    {(device.protocols as string[]).map((p, i) => (
                      <Badge key={i} variant="outline" className="text-xs">{p}</Badge>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </>
  );
}

// ─── APT Threats Tab ──────────────────────────────────────────────────────────

function AptThreatsTab() {
  const aptGroups = trpc.icsOtSecurity.listAptGroups.useQuery();
  const [selectedGroup, setSelectedGroup] = useState<string | null>(null);
  const groupDetail = trpc.icsOtSecurity.getAptGroupDetail.useQuery(
    { name: selectedGroup! },
    { enabled: !!selectedGroup }
  );

  const seedDb = trpc.icsOtSecurity.seedAptDatabase.useMutation({
    onSuccess: (data) => {
      aptGroups.refetch();
      toast.success(`APT Database Seeded: ${data.seeded} groups loaded`);
    },
  });

  const groups = aptGroups.data || [];

  return (
    <>
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Skull className="w-5 h-5 text-amber-400" />
            ICS-Targeting APT Groups
          </h2>
          <p className="text-sm text-muted-foreground">
            {groups.length} APT groups tracked with ICS-specific TTPs and campaign intelligence
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={() => seedDb.mutate()} disabled={seedDb.isPending}>
          <Database className="w-4 h-4 mr-1" />
          Seed APT Database
        </Button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* APT Group List */}
        <div className="lg:col-span-1 space-y-2 max-h-[70vh] overflow-y-auto">
          {groups.map((group: any) => (
            <Card
              key={group.aptGroupName}
              className={`bg-card/50 border-border/50 cursor-pointer hover:border-amber-500/30 transition-colors ${
                selectedGroup === group.aptGroupName ? "border-amber-500/50 bg-amber-500/5" : ""
              }`}
              onClick={() => setSelectedGroup(group.aptGroupName)}
            >
              <CardContent className="p-3">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium">{group.aptGroupName}</p>
                    <p className="text-xs text-muted-foreground">{group.attribution || "Unknown attribution"}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <ThreatLevelBadge level={group.threatLevel} />
                    <ChevronRight className="w-4 h-4 text-muted-foreground" />
                  </div>
                </div>
                <div className="flex items-center gap-2 mt-2">
                  <span className="text-xs text-muted-foreground">{group.malwareCount} malware</span>
                  <span className="text-xs text-muted-foreground">•</span>
                  <span className="text-xs text-muted-foreground">{group.campaignCount} campaigns</span>
                </div>
              </CardContent>
            </Card>
          ))}
          {groups.length === 0 && (
            <Card className="bg-card/50 border-border/50">
              <CardContent className="p-8 text-center">
                <Skull className="w-10 h-10 text-muted-foreground mx-auto mb-3 opacity-40" />
                <p className="text-sm text-muted-foreground">No APT groups loaded yet.</p>
                <p className="text-xs text-muted-foreground mt-1">Click "Seed APT Database" to load 11 ICS-targeting APT groups.</p>
              </CardContent>
            </Card>
          )}
        </div>

        {/* APT Group Detail */}
        <div className="lg:col-span-2">
          {selectedGroup && groupDetail.data ? (
            <Card className="bg-card/50 border-border/50">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>{groupDetail.data.aptGroupName}</CardTitle>
                    <CardDescription>
                      {(groupDetail.data.aliases as string[])?.join(", ") || "No known aliases"}
                    </CardDescription>
                  </div>
                  <ThreatLevelBadge level={groupDetail.data.threatLevel || "medium"} />
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm">{groupDetail.data.description}</p>

                {/* Attribution & Status */}
                <div className="grid grid-cols-3 gap-3">
                  <div className="p-3 bg-muted/30 rounded-lg">
                    <p className="text-xs text-muted-foreground">Attribution</p>
                    <p className="text-sm font-medium">{groupDetail.data.attribution || "Unknown"}</p>
                  </div>
                  <div className="p-3 bg-muted/30 rounded-lg">
                    <p className="text-xs text-muted-foreground">Status</p>
                    <p className="text-sm font-medium">{groupDetail.data.activeStatus || "Unknown"}</p>
                  </div>
                  <div className="p-3 bg-muted/30 rounded-lg">
                    <p className="text-xs text-muted-foreground">Last Activity</p>
                    <p className="text-sm font-medium">{groupDetail.data.lastKnownActivity || "Unknown"}</p>
                  </div>
                </div>

                {/* Targeted Sectors */}
                {(groupDetail.data.targetedSectors as string[])?.length > 0 && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Targeted Sectors</p>
                    <div className="flex flex-wrap gap-1">
                      {(groupDetail.data.targetedSectors as string[]).map((s, i) => (
                        <Badge key={i} variant="outline" className="text-xs">{s}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Targeted Protocols */}
                {(groupDetail.data.targetedProtocols as string[])?.length > 0 && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Targeted Protocols</p>
                    <div className="flex flex-wrap gap-1">
                      {(groupDetail.data.targetedProtocols as string[]).map((p, i) => (
                        <Badge key={i} variant="outline" className="text-xs bg-cyan-500/10 text-cyan-400 border-cyan-500/20">{p}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Malware & Tools */}
                {(groupDetail.data.malwareTools as any[])?.length > 0 && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-2">Malware & Tools</p>
                    <div className="space-y-2">
                      {(groupDetail.data.malwareTools as any[]).map((m, i) => (
                        <div key={i} className="p-2 bg-red-500/5 border border-red-500/20 rounded-lg">
                          <div className="flex items-center gap-2">
                            <Bug className="w-3 h-3 text-red-400" />
                            <span className="text-sm font-medium">{m.name}</span>
                            <Badge variant="outline" className="text-xs">{m.type}</Badge>
                          </div>
                          <p className="text-xs text-muted-foreground mt-1">{m.description}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Known Campaigns */}
                {(groupDetail.data.knownCampaigns as any[])?.length > 0 && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-2">Known Campaigns</p>
                    <div className="space-y-2">
                      {(groupDetail.data.knownCampaigns as any[]).map((c, i) => (
                        <div key={i} className="p-2 bg-amber-500/5 border border-amber-500/20 rounded-lg">
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-medium">{c.name}</span>
                            <Badge variant="outline" className="text-xs">{c.year}</Badge>
                          </div>
                          <p className="text-xs text-muted-foreground mt-1">{c.description}</p>
                          <p className="text-xs text-red-400 mt-1">Impact: {c.impact}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* MITRE Techniques */}
                {(groupDetail.data.resolvedTechniques as any[])?.length > 0 && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-2">MITRE ATT&CK for ICS Techniques</p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {(groupDetail.data.resolvedTechniques as any[]).map((t: any, i: number) => (
                        <div key={i} className="p-2 bg-muted/30 rounded-lg">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono text-cyan-400">{t.id}</span>
                            <span className="text-xs font-medium">{t.name}</span>
                          </div>
                          <p className="text-xs text-muted-foreground mt-1">{t.description}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ) : (
            <Card className="bg-card/50 border-border/50">
              <CardContent className="p-12 text-center">
                <Target className="w-10 h-10 text-muted-foreground mx-auto mb-3 opacity-40" />
                <p className="text-muted-foreground">Select an APT group to view detailed intelligence</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </>
  );
}

// ─── Protocols Tab ────────────────────────────────────────────────────────────

function ProtocolsTab() {
  const protocols = trpc.icsOtSecurity.getSupportedProtocols.useQuery();

  return (
    <>
      <div>
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Radio className="w-5 h-5 text-cyan-400" />
          ICS/OT Protocol Analysis
        </h2>
        <p className="text-sm text-muted-foreground">
          Protocol-specific vulnerability assessment for industrial control systems
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {(protocols.data || []).map((proto: any) => (
          <Card key={proto.name} className="bg-card/50 border-border/50 hover:border-cyan-500/30 transition-colors">
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Radio className="w-4 h-4 text-cyan-400" />
                  <span className="text-sm font-medium">{proto.name}</span>
                </div>
                <Badge variant="outline" className="text-xs">
                  Port {proto.defaultPort}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground mb-3">{proto.description}</p>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1">
                  {proto.encrypted ? (
                    <Badge variant="outline" className="text-xs bg-green-500/10 text-green-400 border-green-500/20">
                      <Lock className="w-3 h-3 mr-1" /> Encrypted
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="text-xs bg-red-500/10 text-red-400 border-red-500/20">
                      <Unlock className="w-3 h-3 mr-1" /> Plaintext
                    </Badge>
                  )}
                </div>
                {proto.hasAuthentication ? (
                  <Badge variant="outline" className="text-xs bg-green-500/10 text-green-400 border-green-500/20">Auth</Badge>
                ) : (
                  <Badge variant="outline" className="text-xs bg-orange-500/10 text-orange-400 border-orange-500/20">No Auth</Badge>
                )}
              </div>
              {proto.commonVulnerabilities && (
                <div className="mt-3">
                  <p className="text-xs text-muted-foreground mb-1">Common Vulnerabilities</p>
                  <div className="flex flex-wrap gap-1">
                    {(proto.commonVulnerabilities as string[])?.slice(0, 3).map((v: string, i: number) => (
                      <Badge key={i} variant="outline" className="text-xs bg-red-500/5 text-red-400 border-red-500/10">{v}</Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </>
  );
}

// ─── ICS Exploits Tab ─────────────────────────────────────────────────────────

function IcsExploitsTab() {
  const [searchTerm, setSearchTerm] = useState("");
  const exploits = trpc.icsOtSecurity.searchExploits.useQuery({ vendor: searchTerm || undefined, limit: 50 });

  const seedExploits = trpc.icsOtSecurity.seedAptDatabase.useMutation({
    onSuccess: (data: { seeded: number; total: number }) => {
      exploits.refetch();
      toast.success(`ICS database seeded: ${data.seeded} APT groups loaded`);
    },
  });

  const exploitList = exploits.data || [];

  return (
    <>
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Bug className="w-5 h-5 text-red-400" />
            ICS Exploit Catalog
          </h2>
          <p className="text-sm text-muted-foreground">
            ICS-CERT advisories and ICS-specific exploits with safety impact analysis
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" onClick={() => seedExploits.mutate()} disabled={seedExploits.isPending}>
            <Database className="w-4 h-4 mr-1" />
            Seed ICS Exploits
          </Button>
        </div>
      </div>

      <div className="flex gap-3">
        <Input
          placeholder="Search by CVE, vendor, product, or keyword..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="max-w-md"
        />
      </div>

      {exploitList.length === 0 ? (
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-12 text-center">
            <Bug className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-40" />
            <p className="text-muted-foreground">No ICS exploits loaded yet.</p>
            <p className="text-sm text-muted-foreground mt-1">Click "Seed ICS Exploits" to load the built-in ICS vulnerability catalog.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {exploitList.map((exploit: any) => (
            <Card key={exploit.id} className="bg-card/50 border-border/50 hover:border-red-500/20 transition-colors">
              <CardContent className="p-4">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      {exploit.cveId && (
                        <Badge variant="outline" className="text-xs font-mono bg-red-500/10 text-red-400 border-red-500/20">
                          {exploit.cveId}
                        </Badge>
                      )}
                      {exploit.icsCertAdvisoryId && (
                        <Badge variant="outline" className="text-xs font-mono bg-amber-500/10 text-amber-400 border-amber-500/20">
                          {exploit.icsCertAdvisoryId}
                        </Badge>
                      )}
                      <span className="text-sm font-medium">{exploit.title}</span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{exploit.description}</p>
                    <div className="flex items-center gap-3 mt-2">
                      {exploit.affectedVendor && (
                        <span className="text-xs text-muted-foreground">
                          <strong>Vendor:</strong> {exploit.affectedVendor}
                        </span>
                      )}
                      {exploit.affectedProduct && (
                        <span className="text-xs text-muted-foreground">
                          <strong>Product:</strong> {exploit.affectedProduct}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-2 ml-4">
                    {exploit.cvssScore && (
                      <Badge variant="outline" className={`text-xs font-mono ${
                        exploit.cvssScore >= 9 ? "bg-red-500/20 text-red-400 border-red-500/30" :
                        exploit.cvssScore >= 7 ? "bg-orange-500/20 text-orange-400 border-orange-500/30" :
                        "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
                      }`}>
                        CVSS {exploit.cvssScore}
                      </Badge>
                    )}
                    <div className="flex items-center gap-1">
                      {exploit.safetyImpact && exploit.safetyImpact !== "none" && (
                        <Badge variant="outline" className="text-xs bg-red-600/20 text-red-400 border-red-600/30">
                          Safety: {exploit.safetyImpact}
                        </Badge>
                      )}
                      {exploit.physicalImpact && (
                        <Badge variant="outline" className="text-xs bg-red-700/20 text-red-300 border-red-700/30">
                          Physical Impact
                        </Badge>
                      )}
                    </div>
                    {exploit.exploitAvailable && (
                      <Badge variant="outline" className="text-xs bg-red-500/10 text-red-400 border-red-500/20">
                        <Zap className="w-3 h-3 mr-1" /> Exploit Available
                      </Badge>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </>
  );
}
