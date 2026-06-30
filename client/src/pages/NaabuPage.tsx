import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import {
  Network, Search, Loader2, Copy, Download,
  ChevronDown, ChevronUp, Server, Shield, Lock, Unlock
} from "lucide-react";

export default function NaabuPage() {
  const [targetsText, setTargetsText] = useState("");
  const [ports, setPorts] = useState("");
  const [topPorts, setTopPorts] = useState("100");
  const [scanType, setScanType] = useState<"syn" | "connect">("connect");
  const [serviceDiscovery, setServiceDiscovery] = useState(true);
  const [serviceVersion, setServiceVersion] = useState(false);
  const [sortField, setSortField] = useState<"host" | "port" | "service">("host");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [filter, setFilter] = useState("");
  const [expandedHost, setExpandedHost] = useState<string | null>(null);

  const statusQuery = trpc.projectDiscovery.getStatus.useQuery();
  const scanMutation = trpc.projectDiscovery.naabu.run.useMutation({
    onSuccess: (data) => {
      toast.success(`Found ${data.stats.totalOpenPorts} open ports across ${data.stats.hostsWithOpenPorts} hosts`);
    },
    onError: (err) => {
      toast.error(`Scan failed: ${err.message}`);
    },
  });

  const result = scanMutation.data;

  // Flatten all ports for the table view
  const flatPorts = useMemo(() => {
    if (!result?.targets) return [];
    const items: Array<{
      host: string; ip: string; port: number; protocol: string;
      state: string; service?: string; version?: string; banner?: string;
      tls?: boolean; os?: string;
    }> = [];
    for (const host of result.targets) {
      for (const port of host.ports) {
        items.push({
          host: host.host,
          ip: host.ip,
          port: port.port,
          protocol: port.protocol,
          state: port.state,
          service: port.service,
          version: port.version,
          banner: port.banner,
          tls: port.tls,
          os: host.os,
        });
      }
    }
    if (filter) {
      const f = filter.toLowerCase();
      return items.filter(
        (p) =>
          (p.host || '').toLowerCase().includes(f) ||
          p.ip.includes(f) ||
          p.port.toString().includes(f) ||
          (p.service && (p.service || '').toLowerCase().includes(f)) ||
          (p.banner && (p.banner || '').toLowerCase().includes(f))
      );
    }
    items.sort((a, b) => {
      let cmp = 0;
      if (sortField === "host") cmp = a.host.localeCompare(b.host) || a.port - b.port;
      else if (sortField === "port") cmp = a.port - b.port;
      else if (sortField === "service") cmp = (a.service || "").localeCompare(b.service || "");
      return sortDir === "asc" ? cmp : -cmp;
    });
    return items;
  }, [result?.targets, filter, sortField, sortDir]);

  const handleScan = () => {
    const targets = targetsText
      .split(/[\n,]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    if (targets.length === 0) {
      toast.error("Please enter at least one target");
      return;
    }
    scanMutation.mutate({
      targets,
      ports: ports || undefined,
      topPorts: ports ? undefined : Number(topPorts),
      scanType,
      serviceDiscovery,
      serviceVersion,
    });
  };

  const handleExportCSV = () => {
    if (!flatPorts.length) return;
    const header = "host,ip,port,protocol,state,service,version,banner,tls\n";
    const rows = flatPorts
      .map((p) =>
        `"${p.host}","${p.ip}",${p.port},"${p.protocol}","${p.state}","${p.service || ""}","${p.version || ""}","${(p.banner || "").replace(/"/g, '""')}",${p.tls || false}`
      )
      .join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `naabu-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Exported CSV");
  };

  const toggleSort = (field: typeof sortField) => {
    if (sortField === field) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortField(field); setSortDir("asc"); }
  };

  const SortIcon = ({ field }: { field: typeof sortField }) => {
    if (sortField !== field) return <ChevronDown className="h-3 w-3 opacity-30" />;
    return sortDir === "asc" ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />;
  };

  const serviceColor = (service?: string) => {
    if (!service) return "text-muted-foreground/50";
    const risky = ["ftp", "telnet", "smb", "rdp", "vnc", "mssql", "mysql", "postgresql", "mongodb", "redis", "elasticsearch"];
    if (risky.includes(service)) return "text-orange-400";
    if (service === "ssh" || service === "https" || service === "imaps" || service === "pop3s") return "text-green-400";
    return "text-cyan-400";
  };

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
              <Network className="h-6 w-6 text-orange-400" />
              Naabu
            </h1>
            <p className="text-muted-foreground mt-1">
              Fast port scanner — discovers open ports, identifies services, and maps the network attack surface
            </p>
          </div>
          <Badge variant="outline" className={
            statusQuery.data?.mode === "cloud"
              ? "border-green-500/50 text-green-400"
              : "border-yellow-500/50 text-yellow-400"
          }>
            {statusQuery.data?.mode === "cloud" ? "PDCP Cloud" : "Local Mode"}
          </Badge>
        </div>

        {/* Scan Form */}
        <Card className="border-orange-500/20 bg-card/50">
          <CardHeader>
            <CardTitle className="text-sm font-medium">New Port Scan</CardTitle>
            <CardDescription>Enter targets (one per line or comma-separated)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label className="text-xs text-muted-foreground mb-1 block">Targets</Label>
                  <Textarea
                    placeholder="example.com&#10;10.0.0.0/24&#10;192.168.1.1"
                    value={targetsText}
                    onChange={(e) => setTargetsText(e.target.value)}
                    className="bg-background/50 font-mono text-xs min-h-[100px]"
                  />
                </div>
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <Label className="text-xs text-muted-foreground mb-1 block">Custom Ports</Label>
                      <Input
                        value={ports}
                        onChange={(e) => setPorts(e.target.value)}
                        placeholder="22,80,443,8080"
                        className="bg-background/50 font-mono text-xs"
                      />
                    </div>
                    <div>
                      <Label className="text-xs text-muted-foreground mb-1 block">Top Ports</Label>
                      <Select value={topPorts} onValueChange={setTopPorts}>
                        <SelectTrigger className="bg-background/50 text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="100">Top 100</SelectItem>
                          <SelectItem value="1000">Top 1000</SelectItem>
                          <SelectItem value="full">Full (65535)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div>
                    <Label className="text-xs text-muted-foreground mb-1 block">Scan Type</Label>
                    <Select value={scanType} onValueChange={(v) => setScanType(v as "syn" | "connect")}>
                      <SelectTrigger className="bg-background/50 text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="connect">TCP Connect</SelectItem>
                        <SelectItem value="syn">SYN Scan</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="flex items-center gap-2">
                      <Switch id="svc" checked={serviceDiscovery} onCheckedChange={setServiceDiscovery} />
                      <Label htmlFor="svc" className="text-xs">Service Detection</Label>
                    </div>
                    <div className="flex items-center gap-2">
                      <Switch id="ver" checked={serviceVersion} onCheckedChange={setServiceVersion} />
                      <Label htmlFor="ver" className="text-xs">Version Detection</Label>
                    </div>
                  </div>
                </div>
              </div>
              <Button
                onClick={handleScan}
                disabled={scanMutation.isPending || !targetsText.trim()}
                className="bg-orange-600 hover:bg-orange-700 text-white"
              >
                {scanMutation.isPending ? (
                  <><Loader2 className="h-4 w-4 animate-spin mr-2" /> Scanning...</>
                ) : (
                  <><Search className="h-4 w-4 mr-2" /> Run Naabu</>
                )}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Results */}
        {result && (
          <>
            {/* Stats Row */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <Card className="border-orange-500/10 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-orange-400">{result.stats.totalHosts}</div>
                  <div className="text-xs text-muted-foreground">Total Hosts</div>
                </CardContent>
              </Card>
              <Card className="border-green-500/10 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-green-400">{result.stats.hostsWithOpenPorts}</div>
                  <div className="text-xs text-muted-foreground">Hosts w/ Open Ports</div>
                </CardContent>
              </Card>
              <Card className="border-cyan-500/10 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-cyan-400">{result.stats.totalOpenPorts}</div>
                  <div className="text-xs text-muted-foreground">Open Ports</div>
                </CardContent>
              </Card>
              <Card className="border-yellow-500/10 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-yellow-400">{(result.stats.duration / 1000).toFixed(1)}s</div>
                  <div className="text-xs text-muted-foreground">Duration</div>
                </CardContent>
              </Card>
            </div>

            {/* Service + Port Breakdown */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card className="border-orange-500/10 bg-card/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Server className="h-4 w-4 text-cyan-400" /> Top Ports
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(result.stats.byPort)
                      .sort(([, a], [, b]) => (b as number) - (a as number))
                      .slice(0, 15)
                      .map(([port, count]) => (
                        <Badge key={port} variant="outline" className="border-cyan-500/30 text-cyan-300 text-xs font-mono">
                          {port}: {count as number}
                        </Badge>
                      ))}
                  </div>
                </CardContent>
              </Card>
              <Card className="border-orange-500/10 bg-card/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Shield className="h-4 w-4 text-orange-400" /> Services
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(result.stats.byService)
                      .sort(([, a], [, b]) => (b as number) - (a as number))
                      .map(([svc, count]) => (
                        <Badge key={svc} variant="outline" className={`text-xs ${
                          ["ftp", "telnet", "smb", "rdp", "vnc"].includes(svc)
                            ? "border-orange-500/30 text-orange-300"
                            : "border-green-500/30 text-green-300"
                        }`}>
                          {svc}: {count as number}
                        </Badge>
                      ))}
                    {Object.keys(result.stats.byService).length === 0 && (
                      <span className="text-xs text-muted-foreground">Service detection not enabled</span>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Results Table */}
            <Card className="border-orange-500/10 bg-card/50">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-medium">
                    Open Ports ({flatPorts.length})
                  </CardTitle>
                  <div className="flex items-center gap-2">
                    <Input
                      placeholder="Filter..."
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                      className="w-48 h-8 text-xs bg-background/50"
                    />
                    <Button variant="outline" size="sm" onClick={handleExportCSV} className="h-8">
                      <Download className="h-3 w-3 mr-1" /> CSV
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="border rounded-lg overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="bg-muted/30 border-b">
                        <th className="text-left p-3 font-medium cursor-pointer hover:bg-muted/50 select-none" onClick={() => toggleSort("host")}>
                          <span className="flex items-center gap-1">Host <SortIcon field="host" /></span>
                        </th>
                        <th className="text-center p-3 font-medium cursor-pointer hover:bg-muted/50 select-none" onClick={() => toggleSort("port")}>
                          <span className="flex items-center justify-center gap-1">Port <SortIcon field="port" /></span>
                        </th>
                        <th className="text-center p-3 font-medium">Proto</th>
                        <th className="text-left p-3 font-medium cursor-pointer hover:bg-muted/50 select-none" onClick={() => toggleSort("service")}>
                          <span className="flex items-center gap-1">Service <SortIcon field="service" /></span>
                        </th>
                        <th className="text-left p-3 font-medium">Version</th>
                        <th className="text-left p-3 font-medium">Banner</th>
                        <th className="text-center p-3 font-medium">TLS</th>
                      </tr>
                    </thead>
                    <tbody>
                      {flatPorts.map((entry, i) => (
                        <tr key={`${entry.host}-${entry.port}-${i}`} className="border-b last:border-0 hover:bg-muted/20">
                          <td className="p-3">
                            <div className="font-mono text-xs text-orange-300">{entry.host}</div>
                            <div className="text-xs text-muted-foreground">{entry.ip}{entry.os ? ` (${entry.os})` : ""}</div>
                          </td>
                          <td className="p-3 text-center">
                            <span className="font-mono font-bold text-cyan-400">{entry.port}</span>
                          </td>
                          <td className="p-3 text-center">
                            <Badge variant="outline" className="text-[10px] border-muted-foreground/30">{entry.protocol}</Badge>
                          </td>
                          <td className="p-3">
                            <span className={`text-xs font-medium ${serviceColor(entry.service)}`}>
                              {entry.service || "—"}
                            </span>
                          </td>
                          <td className="p-3 text-xs font-mono text-muted-foreground max-w-[150px] truncate">
                            {entry.version || "—"}
                          </td>
                          <td className="p-3 text-xs font-mono text-muted-foreground max-w-[200px] truncate">
                            {entry.banner || "—"}
                          </td>
                          <td className="p-3 text-center">
                            {entry.tls ? (
                              <Lock className="h-4 w-4 text-green-400 inline" />
                            ) : (
                              <Unlock className="h-4 w-4 text-muted-foreground/30 inline" />
                            )}
                          </td>
                        </tr>
                      ))}
                      {flatPorts.length === 0 && (
                        <tr>
                          <td colSpan={7} className="p-8 text-center text-muted-foreground">
                            {filter ? "No ports match filter" : "No open ports found"}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </>
        )}

        {/* Empty State */}
        {!result && !scanMutation.isPending && (
          <Card className="border-dashed border-muted-foreground/20 bg-card/30">
            <CardContent className="py-16 text-center">
              <Network className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-muted-foreground mb-2">No Scan Results</h3>
              <p className="text-sm text-muted-foreground/60 max-w-md mx-auto">
                Enter targets above and click Run Naabu to discover open ports and services.
                Results are automatically ingested into the SSIL observation pipeline for cross-scanner correlation.
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </AppShell>
  );
}
