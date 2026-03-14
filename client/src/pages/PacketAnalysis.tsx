import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import {
  Wifi,
  Play,
  Download,
  Trash2,
  RefreshCw,
  Shield,
  Target,
  Activity,
  Radio,
  Crosshair,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Zap,
  Network,
  Eye,
} from "lucide-react";

// ═══════════════════════════════════════════════════════════════
// PROBE TEMPLATES TAB
// ═══════════════════════════════════════════════════════════════

function ProbeTemplatesTab() {
  const [selectedTemplate, setSelectedTemplate] = useState<string>("");
  const [target, setTarget] = useState("");
  const [ports, setPorts] = useState("80,443,22,8080");
  const templates = trpc.packetAnalysis.probeTemplates.useQuery();
  const runProbe = trpc.packetAnalysis.runProbe.useMutation({
    onSuccess: () => toast.success("Probe complete — results ready below"),
    onError: (e) => toast.error(`Probe failed: ${e.message}`),
  });

  const selectedInfo = templates.data?.find((t) => t.id === selectedTemplate);

  const categoryColors: Record<string, string> = {
    port_scan: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    firewall: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    recon: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    vulnerability: "bg-red-500/20 text-red-400 border-red-500/30",
    exfiltration: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  };

  return (
    <div className="space-y-6">
      {/* Template Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
        {templates.data?.map((t) => (
          <Card
            key={t.id}
            className={`cursor-pointer transition-all duration-200 hover:border-cyan-500/50 ${
              selectedTemplate === t.id ? "border-cyan-500 bg-cyan-500/5" : "border-border/50"
            }`}
            onClick={() => setSelectedTemplate(t.id)}
          >
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-mono">{t.name}</CardTitle>
                <Badge variant="outline" className={categoryColors[t.category] || ""}>
                  {t.category}
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">{t.description}</p>
              <div className="mt-2 flex items-center gap-2">
                <Badge variant="outline" className="text-[10px] font-mono">
                  {t.mitre}
                </Badge>
                {t.requiresPorts && (
                  <Badge variant="outline" className="text-[10px]">
                    Ports required
                  </Badge>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Execution Panel */}
      {selectedTemplate && (
        <Card className="border-cyan-500/30">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-cyan-400">
              <Crosshair className="h-5 w-5" />
              Execute: {selectedInfo?.name}
            </CardTitle>
            <CardDescription>{selectedInfo?.description}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Target IP / Hostname</Label>
                <Input
                  placeholder="e.g. 192.168.1.1 or demo.testfire.net"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="font-mono"
                />
              </div>
              {selectedInfo?.requiresPorts && (
                <div className="space-y-2">
                  <Label>Ports (comma-separated)</Label>
                  <Input
                    placeholder="80,443,22,8080"
                    value={ports}
                    onChange={(e) => setPorts(e.target.value)}
                    className="font-mono"
                  />
                </div>
              )}
            </div>
            <Button
              onClick={() =>
                runProbe.mutate({
                  template: selectedTemplate as any,
                  target,
                  ports: selectedInfo?.requiresPorts
                    ? ports
                        .split(",")
                        .map((p) => parseInt(p.trim()))
                        .filter((n) => !isNaN(n))
                    : undefined,
                })
              }
              disabled={!target || runProbe.isPending}
              className="bg-cyan-600 hover:bg-cyan-700"
            >
              {runProbe.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  Executing probe...
                </>
              ) : (
                <>
                  <Play className="h-4 w-4 mr-2" />
                  Launch Probe
                </>
              )}
            </Button>

            {/* Results */}
            {runProbe.data && <ProbeResults data={runProbe.data} />}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function ProbeResults({ data }: { data: any }) {
  const portStateColors: Record<string, string> = {
    open: "text-emerald-400",
    closed: "text-red-400",
    filtered: "text-amber-400",
    "open|filtered": "text-yellow-400",
    unfiltered: "text-blue-400",
  };

  return (
    <div className="space-y-4 mt-4">
      {/* Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-card/50 rounded-lg p-3 border border-border/50">
          <div className="text-xs text-muted-foreground">Packets Sent</div>
          <div className="text-2xl font-mono font-bold text-cyan-400">{data.packetsSent}</div>
        </div>
        <div className="bg-card/50 rounded-lg p-3 border border-border/50">
          <div className="text-xs text-muted-foreground">Responses</div>
          <div className="text-2xl font-mono font-bold text-emerald-400">{data.responsesReceived}</div>
        </div>
        <div className="bg-card/50 rounded-lg p-3 border border-border/50">
          <div className="text-xs text-muted-foreground">Duration</div>
          <div className="text-2xl font-mono font-bold">{data.durationMs}ms</div>
        </div>
        <div className="bg-card/50 rounded-lg p-3 border border-border/50">
          <div className="text-xs text-muted-foreground">Probe Type</div>
          <div className="text-sm font-mono font-bold text-purple-400">{data.probeType}</div>
        </div>
      </div>

      {/* Analysis */}
      {data.analysis && (
        <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-4">
          <div className="text-xs font-semibold text-emerald-400 mb-1">ANALYSIS</div>
          <p className="text-sm text-foreground/90">{data.analysis}</p>
        </div>
      )}

      {/* Per-packet results */}
      <div className="border border-border/50 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-muted/30">
            <tr>
              <th className="text-left px-3 py-2 font-mono text-xs">Port</th>
              <th className="text-left px-3 py-2 font-mono text-xs">State</th>
              <th className="text-left px-3 py-2 font-mono text-xs">Response</th>
              <th className="text-left px-3 py-2 font-mono text-xs">Flags</th>
              <th className="text-left px-3 py-2 font-mono text-xs">TTL</th>
              <th className="text-left px-3 py-2 font-mono text-xs">Hint</th>
            </tr>
          </thead>
          <tbody>
            {data.results?.map((r: any, i: number) => (
              <tr key={i} className="border-t border-border/30 hover:bg-muted/10">
                <td className="px-3 py-2 font-mono text-cyan-400">{r.dstPort || "-"}</td>
                <td className="px-3 py-2">
                  <span className={`font-mono font-semibold ${portStateColors[r.portState] || "text-muted-foreground"}`}>
                    {r.portState || "-"}
                  </span>
                </td>
                <td className="px-3 py-2 font-mono text-xs">{r.responseType || (r.responded ? "yes" : "no response")}</td>
                <td className="px-3 py-2 font-mono text-xs">{r.responseFlags || "-"}</td>
                <td className="px-3 py-2 font-mono">{r.responseTtl || "-"}</td>
                <td className="px-3 py-2 text-xs text-muted-foreground max-w-[200px] truncate">{r.osHint || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// CUSTOM PACKET CRAFTER TAB
// ═══════════════════════════════════════════════════════════════

function CustomCrafterTab() {
  const [target, setTarget] = useState("");
  const [protocol, setProtocol] = useState("tcp");
  const [ports, setPorts] = useState("80");
  const [tcpFlags, setTcpFlags] = useState("S");
  const [ttl, setTtl] = useState("64");
  const [payload, setPayload] = useState("");
  const [count, setCount] = useState("1");
  const [captureResponses, setCaptureResponses] = useState(true);

  const craftPacket = trpc.packetAnalysis.craftPacket.useMutation({
    onSuccess: () => toast.success("Packet sent — results ready"),
    onError: (e) => toast.error(`Failed: ${e.message}`),
  });

  return (
    <div className="space-y-6">
      <Card className="border-purple-500/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-purple-400">
            <Zap className="h-5 w-5" />
            Custom Packet Crafter (Scapy)
          </CardTitle>
          <CardDescription>
            Construct and send custom packets via Python/Scapy on the scan server. Requires root privileges.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label>Target</Label>
              <Input placeholder="IP or hostname" value={target} onChange={(e) => setTarget(e.target.value)} className="font-mono" />
            </div>
            <div className="space-y-2">
              <Label>Protocol</Label>
              <Select value={protocol} onValueChange={setProtocol}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                  <SelectItem value="icmp">ICMP</SelectItem>
                  <SelectItem value="arp">ARP</SelectItem>
                  <SelectItem value="dns">DNS</SelectItem>
                  <SelectItem value="raw">Raw IP</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Ports (comma-separated)</Label>
              <Input placeholder="80,443" value={ports} onChange={(e) => setPorts(e.target.value)} className="font-mono" />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {protocol === "tcp" && (
              <div className="space-y-2">
                <Label>TCP Flags</Label>
                <Select value={tcpFlags} onValueChange={setTcpFlags}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="S">SYN (S)</SelectItem>
                    <SelectItem value="SA">SYN-ACK (SA)</SelectItem>
                    <SelectItem value="A">ACK (A)</SelectItem>
                    <SelectItem value="F">FIN (F)</SelectItem>
                    <SelectItem value="FA">FIN-ACK (FA)</SelectItem>
                    <SelectItem value="R">RST (R)</SelectItem>
                    <SelectItem value="P">PSH (P)</SelectItem>
                    <SelectItem value="PA">PSH-ACK (PA)</SelectItem>
                    <SelectItem value="FPU">XMAS (FPU)</SelectItem>
                    <SelectItem value="">NULL (none)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
            <div className="space-y-2">
              <Label>TTL</Label>
              <Input type="number" min="1" max="255" value={ttl} onChange={(e) => setTtl(e.target.value)} className="font-mono" />
            </div>
            <div className="space-y-2">
              <Label>Count</Label>
              <Input type="number" min="1" max="1000" value={count} onChange={(e) => setCount(e.target.value)} className="font-mono" />
            </div>
            <div className="space-y-2">
              <Label>Capture Responses</Label>
              <div className="pt-2">
                <Switch checked={captureResponses} onCheckedChange={setCaptureResponses} />
              </div>
            </div>
          </div>

          <div className="space-y-2">
            <Label>Payload (optional)</Label>
            <Textarea
              placeholder="Raw payload data or DNS query name for DNS protocol"
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              className="font-mono h-20"
            />
          </div>

          <Button
            onClick={() =>
              craftPacket.mutate({
                target,
                protocol: protocol as any,
                ports: ports
                  .split(",")
                  .map((p) => parseInt(p.trim()))
                  .filter((n) => !isNaN(n) && n > 0),
                tcpFlags: protocol === "tcp" ? tcpFlags : undefined,
                ttl: parseInt(ttl) || undefined,
                payload: payload || undefined,
                count: parseInt(count) || 1,
                captureResponses,
              })
            }
            disabled={!target || craftPacket.isPending}
            className="bg-purple-600 hover:bg-purple-700"
          >
            {craftPacket.isPending ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
                Sending packets...
              </>
            ) : (
              <>
                <Zap className="h-4 w-4 mr-2" />
                Send Packet
              </>
            )}
          </Button>

          {craftPacket.data && <ProbeResults data={craftPacket.data} />}
        </CardContent>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// LIVE CAPTURE TAB
// ═══════════════════════════════════════════════════════════════

function LiveCaptureTab() {
  const [iface, setIface] = useState("eth0");
  const [filter, setFilter] = useState("");
  const [duration, setDuration] = useState("30");
  const [maxPackets, setMaxPackets] = useState("10000");
  const [targetFilter, setTargetFilter] = useState("");

  const captures = trpc.packetAnalysis.listCaptures.useQuery(undefined, { refetchInterval: 10000 });
  const startCapture = trpc.packetAnalysis.startCapture.useMutation({
    onSuccess: (data) => {
      toast.success(`Capture complete — ${data.metadata?.packetCount || 0} packets captured`);
      captures.refetch();
    },
    onError: (e) => toast.error(`Capture failed: ${e.message}`),
  });
  const deleteCapture = trpc.packetAnalysis.deleteCapture.useMutation({
    onSuccess: () => {
      toast.success("Deleted");
      captures.refetch();
    },
  });

  return (
    <div className="space-y-6">
      <Card className="border-amber-500/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-amber-400">
            <Activity className="h-5 w-5" />
            Live Packet Capture (tcpdump)
          </CardTitle>
          <CardDescription>
            Run tcpdump on the scan server to capture live traffic. Results are saved as PCAP files for analysis.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="space-y-2">
              <Label>Interface</Label>
              <Input value={iface} onChange={(e) => setIface(e.target.value)} className="font-mono" />
            </div>
            <div className="space-y-2">
              <Label>BPF Filter (optional)</Label>
              <Input
                placeholder="e.g. tcp port 80"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className="font-mono"
              />
            </div>
            <div className="space-y-2">
              <Label>Duration (seconds)</Label>
              <Input type="number" min="1" max="300" value={duration} onChange={(e) => setDuration(e.target.value)} className="font-mono" />
            </div>
            <div className="space-y-2">
              <Label>Max Packets</Label>
              <Input
                type="number"
                min="0"
                max="100000"
                value={maxPackets}
                onChange={(e) => setMaxPackets(e.target.value)}
                className="font-mono"
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label>Target Host (optional, auto-adds to BPF filter)</Label>
            <Input
              placeholder="e.g. 192.168.1.1"
              value={targetFilter}
              onChange={(e) => setTargetFilter(e.target.value)}
              className="font-mono"
            />
          </div>
          <Button
            onClick={() =>
              startCapture.mutate({
                interface: iface,
                filter: filter || undefined,
                durationSeconds: parseInt(duration) || 30,
                maxPackets: parseInt(maxPackets) || 10000,
                target: targetFilter || undefined,
              })
            }
            disabled={startCapture.isPending}
            className="bg-amber-600 hover:bg-amber-700"
          >
            {startCapture.isPending ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
                Capturing...
              </>
            ) : (
              <>
                <Radio className="h-4 w-4 mr-2" />
                Start Capture
              </>
            )}
          </Button>

          {/* Capture results */}
          {startCapture.data && (
            <div className="space-y-3 mt-4">
              <div className="bg-card/50 border border-border/50 rounded-lg p-4">
                <div className="text-xs font-semibold text-amber-400 mb-2">CAPTURE RESULTS</div>
                <div className="grid grid-cols-3 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">Packets: </span>
                    <span className="font-mono text-amber-400">{startCapture.data.metadata?.packetCount || 0}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">File: </span>
                    <span className="font-mono text-xs">{startCapture.data.metadata?.filePath || "N/A"}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Size: </span>
                    <span className="font-mono">{startCapture.data.metadata?.fileSize || "N/A"}</span>
                  </div>
                </div>
              </div>
              {startCapture.data.protocolStats && Object.keys(startCapture.data.protocolStats).length > 0 && (
                <div className="bg-card/50 border border-border/50 rounded-lg p-4">
                  <div className="text-xs font-semibold text-emerald-400 mb-2">PROTOCOL DISTRIBUTION</div>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(startCapture.data.protocolStats).map(([proto, count]) => (
                      <Badge key={proto} variant="outline" className="font-mono">
                        {proto}: {count as number}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Saved Captures */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">Saved Captures</CardTitle>
            <Button variant="ghost" size="sm" onClick={() => captures.refetch()}>
              <RefreshCw className="h-3 w-3" />
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {captures.data?.files && captures.data.files.length > 0 ? (
            <div className="space-y-2">
              {captures.data.files.map((f, i) => (
                <div key={i} className="flex items-center justify-between bg-muted/20 rounded-lg px-3 py-2">
                  <div className="flex items-center gap-3">
                    <Network className="h-4 w-4 text-muted-foreground" />
                    <span className="font-mono text-sm">{f.path}</span>
                    <Badge variant="outline" className="text-xs">
                      {f.size}
                    </Badge>
                    <span className="text-xs text-muted-foreground">{f.date}</span>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => deleteCapture.mutate({ pcapPath: f.path })}
                    className="text-red-400 hover:text-red-300"
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No capture files found on scan server.</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// TOOL STATUS TAB
// ═══════════════════════════════════════════════════════════════

function ToolStatusTab() {
  const toolStatus = trpc.packetAnalysis.toolStatus.useQuery();
  const provision = trpc.packetAnalysis.provisionTools.useMutation({
    onSuccess: (data) => {
      const msg = `${data.success ? "Tools installed" : "Partial install"}: ${data.installed.join(", ")}${data.failed.length ? ` | Failed: ${data.failed.join(", ")}` : ""}`;
      data.success ? toast.success(msg) : toast.warning(msg);
      toolStatus.refetch();
    },
    onError: (e) => toast.error(`Install failed: ${e.message}`),
  });

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-cyan-400" />
                Scan Server Tool Status
              </CardTitle>
              <CardDescription>Packet analysis tools installed on the remote scan server</CardDescription>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => toolStatus.refetch()}>
                <RefreshCw className="h-3 w-3 mr-1" />
                Refresh
              </Button>
              <Button
                size="sm"
                onClick={() => provision.mutate()}
                disabled={provision.isPending}
                className="bg-cyan-600 hover:bg-cyan-700"
              >
                {provision.isPending ? (
                  <>
                    <Loader2 className="h-3 w-3 animate-spin mr-1" />
                    Installing...
                  </>
                ) : (
                  <>
                    <Download className="h-3 w-3 mr-1" />
                    Install All
                  </>
                )}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {toolStatus.data?.map((tool) => (
              <div
                key={tool.name}
                className={`flex items-center gap-3 p-3 rounded-lg border ${
                  tool.installed ? "border-emerald-500/30 bg-emerald-500/5" : "border-red-500/30 bg-red-500/5"
                }`}
              >
                {tool.installed ? (
                  <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
                ) : (
                  <XCircle className="h-5 w-5 text-red-400 shrink-0" />
                )}
                <div>
                  <div className="font-mono font-semibold text-sm">{tool.name}</div>
                  <div className="text-xs text-muted-foreground">{tool.version}</div>
                </div>
              </div>
            ))}
            {toolStatus.isLoading && (
              <div className="col-span-full flex items-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Provision output */}
      {provision.data && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Installation Output</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="bg-black/50 rounded-lg p-4 text-xs font-mono text-green-400 overflow-x-auto max-h-60 overflow-y-auto whitespace-pre-wrap">
              {provision.data.output}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// MAIN PAGE
// ═══════════════════════════════════════════════════════════════

export default function PacketAnalysis() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
            <Wifi className="h-6 w-6 text-cyan-400" />
          </div>
          Packet Analysis & Manipulation
        </h1>
        <p className="text-muted-foreground mt-1">
          Live packet capture, protocol analysis, and custom packet crafting via tcpdump, tshark, and Scapy
        </p>
      </div>

      <Tabs defaultValue="probes" className="space-y-4">
        <TabsList className="bg-muted/30">
          <TabsTrigger value="probes" className="flex items-center gap-1.5">
            <Target className="h-3.5 w-3.5" />
            Probe Templates
          </TabsTrigger>
          <TabsTrigger value="crafter" className="flex items-center gap-1.5">
            <Zap className="h-3.5 w-3.5" />
            Packet Crafter
          </TabsTrigger>
          <TabsTrigger value="capture" className="flex items-center gap-1.5">
            <Radio className="h-3.5 w-3.5" />
            Live Capture
          </TabsTrigger>
          <TabsTrigger value="tools" className="flex items-center gap-1.5">
            <Shield className="h-3.5 w-3.5" />
            Tool Status
          </TabsTrigger>
        </TabsList>

        <TabsContent value="probes">
          <ProbeTemplatesTab />
        </TabsContent>
        <TabsContent value="crafter">
          <CustomCrafterTab />
        </TabsContent>
        <TabsContent value="capture">
          <LiveCaptureTab />
        </TabsContent>
        <TabsContent value="tools">
          <ToolStatusTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
