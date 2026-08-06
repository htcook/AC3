import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogClose } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { Textarea } from "@/components/ui/textarea";
import {
  Radio, Shield, AlertTriangle, Download, Send, Activity,
  CheckCircle2, XCircle, Wifi, WifiOff, FileText, Zap,
  BarChart3, Eye, Copy, ArrowRight, HeartPulse, Server,
  Plus, Trash2, Loader2, Settings, PlugZap, RefreshCw,
  Search, Play, Database, Code2, Clock, ChevronDown, ChevronRight,
  Target, Crosshair
} from "lucide-react";

/* ─── Alert Export Panel ─── */
function AlertExportPanel() {
  const [format, setFormat] = useState<string>("cef");
  const { data: demoData } = trpc.socIntegrationHub.getDemoData.useQuery();

  const exportMutation = trpc.socIntegrationHub.exportFindings.useMutation({
    onSuccess: (data) => {
      const blob = new Blob(
        [data.map((a: any) => a.raw).join("\n\n")],
        { type: "text/plain" }
      );
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `alerts-export.${format === "json" ? "json" : "txt"}`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`${data.length} alerts exported as ${format.toUpperCase()}`);
    },
  });

  const findings = demoData?.sampleFindings ?? [];

  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><Download className="h-4 w-4 text-primary" /> Alert Export</CardTitle>
        <CardDescription>Export findings in SIEM-compatible formats for ingestion</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-5 gap-2">
          {["cef", "leef", "json", "syslog", "csv"].map(f => (
            <Button key={f} variant={format === f ? "default" : "outline"} size="sm" onClick={() => setFormat(f)} className="uppercase text-xs font-mono">{f}</Button>
          ))}
        </div>
        <div className="rounded-md bg-muted/30 p-3 space-y-2">
          <p className="text-xs text-muted-foreground font-medium">Sample findings to export:</p>
          {findings.map((f: any) => (
            <div key={f.id} className="flex items-center gap-2 text-xs">
              <Badge variant={f.severity === "critical" ? "destructive" : f.severity === "high" ? "destructive" : "secondary"} className="text-[10px]">{f.severity}</Badge>
              <span className="text-foreground">{f.title}</span>
              <span className="text-muted-foreground ml-auto font-mono">{f.targetHost}:{f.targetPort}</span>
            </div>
          ))}
        </div>
        <Button onClick={() => { if (findings.length) exportMutation.mutate({ findings, format: format as any }); }} disabled={exportMutation.isPending || !findings.length} className="w-full">
          <Send className="h-4 w-4 mr-2" />
          {exportMutation.isPending ? "Exporting..." : `Export ${findings.length} Findings as ${format.toUpperCase()}`}
        </Button>
      </CardContent>
    </Card>
  );
}

/* ─── Detection Gap Analysis Panel ─── */
function DetectionGapPanel() {
  const [results, setResults] = useState<any>(null);
  const { data: demoData } = trpc.socIntegrationHub.getDemoData.useQuery();

  const gapMutation = trpc.socIntegrationHub.analyzeGaps.useMutation({
    onSuccess: (data) => setResults(data),
  });

  const runAnalysis = () => {
    const attacks = demoData?.sampleAttacks ?? [];
    const siemAlerts = [
      { alertId: "s1", backend: "wazuh" as const, timestamp: Date.now() - 55000, severity: "critical" as const, severityScore: 90, title: "SQL Injection Detected", description: "WAF alert for SQL injection", mitreTechniques: ["T1190"], mitreTactics: ["initial-access"], ruleId: "R1", ruleName: "WAF SQL Injection", agentName: "waf-agent-1", rawData: {} },
      { alertId: "s2", backend: "elastic" as const, timestamp: Date.now() - 35000, severity: "high" as const, severityScore: 75, title: "Suspicious PowerShell", description: "EDR detected PowerShell execution", mitreTechniques: ["T1059.001"], mitreTactics: ["execution"], ruleId: "R2", ruleName: "EDR PowerShell Alert", agentName: "edr-agent-1", rawData: {} },
      { alertId: "s3", backend: "splunk" as const, timestamp: Date.now() - 15000, severity: "critical" as const, severityScore: 95, title: "LSASS Access Detected", description: "Sysmon LSASS access alert", mitreTechniques: ["T1003.001"], mitreTactics: ["credential-access"], ruleId: "R3", ruleName: "Sysmon LSASS", agentName: "sysmon-agent-1", rawData: {} },
    ];
    gapMutation.mutate({ attacks, siemAlerts });
  };

  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><Eye className="h-4 w-4 text-orange-400" /> Detection Gap Analysis</CardTitle>
        <CardDescription>Compare attack actions against SIEM detections to find blind spots</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Button onClick={runAnalysis} disabled={gapMutation.isPending} className="w-full">
          <BarChart3 className="h-4 w-4 mr-2" />
          {gapMutation.isPending ? "Analyzing..." : "Run Gap Analysis (5 TTPs vs 3 SIEM Alerts)"}
        </Button>
        {results && (
          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div className="rounded-md bg-green-500/10 border border-green-500/20 p-3 text-center">
                <p className="text-2xl font-bold text-green-400">{results.totalDetected ?? 0}</p>
                <p className="text-xs text-muted-foreground">Detected</p>
              </div>
              <div className="rounded-md bg-red-500/10 border border-red-500/20 p-3 text-center">
                <p className="text-2xl font-bold text-red-400">{(results.totalAttacks ?? 0) - (results.totalDetected ?? 0)}</p>
                <p className="text-xs text-muted-foreground">Missed</p>
              </div>
              <div className="rounded-md bg-yellow-500/10 border border-yellow-500/20 p-3 text-center">
                <p className="text-2xl font-bold text-yellow-400">{((results.overallDetectionRate ?? 0) * 100).toFixed(0)}%</p>
                <p className="text-xs text-muted-foreground">Coverage</p>
              </div>
            </div>
            {results.gaps?.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs font-medium text-muted-foreground">Detection Gaps:</p>
                {results.gaps.map((g: any, i: number) => (
                  <div key={i} className="flex items-center gap-2 rounded-md bg-red-500/5 border border-red-500/10 p-2">
                    <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" />
                    <Badge variant={g.gapSeverity === "critical" ? "destructive" : "secondary"} className="text-[10px]">{g.gapSeverity}</Badge>
                    <span className="text-xs font-mono text-red-300">{g.techniqueId}</span>
                    <span className="text-xs text-foreground">{g.techniqueName}</span>
                    <span className="text-[10px] text-muted-foreground ml-auto">{g.detectionRate === 0 ? "0% detected" : `${(g.detectionRate * 100).toFixed(0)}% detected`}</span>
                  </div>
                ))}
              </div>
            )}
            {results.coveredTechniques?.length > 0 && (
              <div className="space-y-1">
                <p className="text-xs font-medium text-muted-foreground">Covered Techniques:</p>
                <div className="flex flex-wrap gap-1">
                  {results.coveredTechniques.map((t: string) => (
                    <Badge key={t} variant="outline" className="text-[10px] text-green-400 border-green-500/30">{t}</Badge>
                  ))}
                </div>
              </div>
            )}
            {results.meanTimeToDetect != null && (
              <div className="text-xs text-muted-foreground">
                Mean Time to Detect: <span className="font-mono text-foreground">{(results.meanTimeToDetect / 1000).toFixed(1)}s</span>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/* ─── SOC Health Dashboard ─── */
function SocHealthPanel() {
  const { data: demoData } = trpc.socIntegrationHub.getDemoData.useQuery();
  const connectors = demoData?.sampleConnectors ?? [];

  const statusIcon = (status: string) => {
    switch (status) {
      case "connected": return <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />;
      case "degraded": return <AlertTriangle className="h-3.5 w-3.5 text-yellow-400" />;
      case "disconnected": return <XCircle className="h-3.5 w-3.5 text-red-400" />;
      default: return <Activity className="h-3.5 w-3.5 text-muted-foreground" />;
    }
  };

  const totalAlerts = connectors.reduce((sum: number, c: any) => sum + c.alertsLast24h, 0);
  const connectedCount = connectors.filter((c: any) => c.status === "connected").length;
  const avgLatency = connectors.length > 0 ? Math.round(connectors.reduce((sum: number, c: any) => sum + c.latencyMs, 0) / connectors.length) : 0;

  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><HeartPulse className="h-4 w-4 text-green-400" /> SOC Health Dashboard</CardTitle>
        <CardDescription>Monitor SIEM connector status, alert volume, and detection rates</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-4 gap-3">
          <div className="rounded-md bg-green-500/10 border border-green-500/20 p-3 text-center">
            <p className="text-xl font-bold text-green-400">{connectedCount}/{connectors.length}</p>
            <p className="text-[10px] text-muted-foreground">Connected</p>
          </div>
          <div className="rounded-md bg-blue-500/10 border border-blue-500/20 p-3 text-center">
            <p className="text-xl font-bold text-blue-400">{totalAlerts.toLocaleString()}</p>
            <p className="text-[10px] text-muted-foreground">Alerts (24h)</p>
          </div>
          <div className="rounded-md bg-purple-500/10 border border-purple-500/20 p-3 text-center">
            <p className="text-xl font-bold text-purple-400">{avgLatency}ms</p>
            <p className="text-[10px] text-muted-foreground">Avg Latency</p>
          </div>
          <div className="rounded-md bg-primary/10 border border-primary/20 p-3 text-center">
            <p className="text-xl font-bold text-primary">{connectors.length > 0 ? ((connectedCount / connectors.length) * 100).toFixed(0) : 0}%</p>
            <p className="text-[10px] text-muted-foreground">Coverage</p>
          </div>
        </div>
        <div className="space-y-2">
          {connectors.map((c: any) => (
            <div key={c.id} className="flex items-center gap-3 rounded-md border border-border/50 p-3">
              {statusIcon(c.status)}
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium">{c.name}</p>
                <p className="text-[10px] text-muted-foreground">{c.backend} &middot; {c.alertsLast24h.toLocaleString()} alerts/24h</p>
              </div>
              <Badge variant={c.status === "connected" ? "default" : c.status === "degraded" ? "secondary" : "destructive"} className="text-[10px]">{c.status}</Badge>
              <span className="text-xs font-mono text-muted-foreground">{c.latencyMs}ms</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

/* ─── SIEM Connections Manager Panel ─── */
function SiemConnectionsPanel() {
  const utils = trpc.useUtils();
  const { data: connections, isLoading } = trpc.socIntegrationHub.listConnections.useQuery();
  const { data: demoData } = trpc.socIntegrationHub.getDemoData.useQuery();

  const [showAddDialog, setShowAddDialog] = useState(false);
  const [newConn, setNewConn] = useState({ name: "", provider: "splunk" as string, baseUrl: "", apiKey: "" });
  const [testResult, setTestResult] = useState<any>(null);
  const [pushConnectionId, setPushConnectionId] = useState<number | null>(null);
  const [pushFormat, setPushFormat] = useState("json");

  const createMutation = trpc.socIntegrationHub.createConnection.useMutation({
    onSuccess: () => {
      utils.socIntegrationHub.listConnections.invalidate();
      setShowAddDialog(false);
      setNewConn({ name: "", provider: "splunk", baseUrl: "", apiKey: "" });
      toast.success("SIEM connection saved");
    },
    onError: (err) => toast.error(`Failed to save: ${err.message}`),
  });

  const deleteMutation = trpc.socIntegrationHub.deleteConnection.useMutation({
    onSuccess: () => {
      utils.socIntegrationHub.listConnections.invalidate();
      toast.success("Connection deleted");
    },
  });

  const testMutation = trpc.socIntegrationHub.testConnection.useMutation({
    onSuccess: (result) => {
      setTestResult(result);
      if (result.status === "connected") toast.success(`Connected! ${result.message} (${result.latencyMs}ms)`);
      else if (result.status === "degraded") toast.warning(`Degraded: ${result.message}`);
      else toast.error(`Disconnected: ${result.message}`);
    },
    onError: (err) => toast.error(`Test failed: ${err.message}`),
  });

  const pushMutation = trpc.socIntegrationHub.pushToConnection.useMutation({
    onSuccess: (result) => {
      if (result.success) {
        toast.success(`Pushed ${result.alertsSent} alerts in ${result.durationMs}ms`);
      } else {
        toast.error(`Push completed with ${result.alertsFailed} failures: ${result.errors.join(", ")}`);
      }
      setPushConnectionId(null);
    },
    onError: (err) => toast.error(`Push failed: ${err.message}`),
  });

  const providerInfo: Record<string, { label: string; icon: string; color: string; placeholder: string }> = {
    splunk: { label: "Splunk", icon: "S", color: "text-green-400 bg-green-500/20", placeholder: "https://splunk.corp.io:8088/services/collector" },
    elastic: { label: "Elastic", icon: "E", color: "text-yellow-400 bg-yellow-500/20", placeholder: "https://elastic.corp.io:9200" },
    sentinel: { label: "Sentinel", icon: "A", color: "text-blue-400 bg-blue-500/20", placeholder: "https://<workspace-id>.ods.opinsights.azure.com/api/logs" },
    qradar: { label: "QRadar", icon: "Q", color: "text-purple-400 bg-purple-500/20", placeholder: "https://qradar.corp.io" },
    custom: { label: "Custom", icon: "C", color: "text-gray-400 bg-gray-500/20", placeholder: "https://siem.corp.io/api/events" },
  };

  const findings = demoData?.sampleFindings ?? [];

  return (
    <div className="space-y-4">
      {/* Header with Add button */}
      <Card className="border-border/50">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2 text-base"><PlugZap className="h-4 w-4 text-primary" /> SIEM Connections</CardTitle>
              <CardDescription className="mt-1">Manage and test connections to your SIEM platforms. Push alerts directly from engagements.</CardDescription>
            </div>
            <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
              <DialogTrigger asChild>
                <Button size="sm"><Plus className="h-4 w-4 mr-1" /> Add Connection</Button>
              </DialogTrigger>
              <DialogContent className="sm:max-w-lg">
                <DialogHeader>
                  <DialogTitle>Add SIEM Connection</DialogTitle>
                </DialogHeader>
                <div className="space-y-4 py-2">
                  <div className="space-y-2">
                    <Label>Connection Name</Label>
                    <Input placeholder="Production Splunk" value={newConn.name} onChange={e => setNewConn(p => ({ ...p, name: e.target.value }))} />
                  </div>
                  <div className="space-y-2">
                    <Label>SIEM Provider</Label>
                    <Select value={newConn.provider} onValueChange={v => setNewConn(p => ({ ...p, provider: v }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="splunk">Splunk (HEC)</SelectItem>
                        <SelectItem value="elastic">Elastic SIEM</SelectItem>
                        <SelectItem value="sentinel">Microsoft Sentinel</SelectItem>
                        <SelectItem value="qradar">IBM QRadar</SelectItem>
                        <SelectItem value="custom">Custom / Wazuh</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Base URL / Endpoint</Label>
                    <Input
                      placeholder={providerInfo[newConn.provider]?.placeholder || "https://..."}
                      value={newConn.baseUrl}
                      onChange={e => setNewConn(p => ({ ...p, baseUrl: e.target.value }))}
                    />
                    <p className="text-[10px] text-muted-foreground">
                      {newConn.provider === "splunk" && "Splunk HEC endpoint (port 8088 by default)"}
                      {newConn.provider === "elastic" && "Elasticsearch cluster URL (port 9200 by default)"}
                      {newConn.provider === "sentinel" && "Azure Log Analytics Data Collector API endpoint"}
                      {newConn.provider === "qradar" && "QRadar console URL"}
                      {newConn.provider === "custom" && "Any HTTP endpoint that accepts JSON events"}
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Label>API Key / Token</Label>
                    <Input
                      type="password"
                      placeholder={newConn.provider === "splunk" ? "HEC Token" : newConn.provider === "elastic" ? "API Key" : newConn.provider === "sentinel" ? "Shared Key" : "API Token"}
                      value={newConn.apiKey}
                      onChange={e => setNewConn(p => ({ ...p, apiKey: e.target.value }))}
                    />
                  </div>

                  {/* Test connection button */}
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => testMutation.mutate({ provider: newConn.provider as any, baseUrl: newConn.baseUrl, apiKey: newConn.apiKey || undefined })}
                      disabled={!newConn.baseUrl || testMutation.isPending}
                    >
                      {testMutation.isPending ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Zap className="h-3 w-3 mr-1" />}
                      Test Connection
                    </Button>
                    {testResult && (
                      <Badge variant={testResult.status === "connected" ? "default" : testResult.status === "degraded" ? "secondary" : "destructive"} className="text-[10px]">
                        {testResult.status} ({testResult.latencyMs}ms)
                      </Badge>
                    )}
                  </div>
                  {testResult && (
                    <div className={`rounded-md p-2 text-xs ${testResult.status === "connected" ? "bg-green-500/10 text-green-400" : testResult.status === "degraded" ? "bg-yellow-500/10 text-yellow-400" : "bg-red-500/10 text-red-400"}`}>
                      {testResult.message}
                    </div>
                  )}
                </div>
                <DialogFooter>
                  <DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
                  <Button
                    onClick={() => createMutation.mutate({ name: newConn.name, provider: newConn.provider as any, baseUrl: newConn.baseUrl, apiKey: newConn.apiKey || undefined })}
                    disabled={!newConn.name || !newConn.baseUrl || createMutation.isPending}
                  >
                    {createMutation.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Plus className="h-4 w-4 mr-1" />}
                    Save Connection
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8 text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin mr-2" /> Loading connections...
            </div>
          ) : !connections?.length ? (
            <div className="text-center py-8 text-muted-foreground">
              <Server className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No SIEM connections configured</p>
              <p className="text-xs mt-1">Add a connection to start pushing alerts to your SIEM platform</p>
            </div>
          ) : (
            <div className="space-y-3">
              {connections.map((conn: any) => {
                const info = providerInfo[conn.provider] || providerInfo.custom;
                return (
                  <div key={conn.id} className="flex items-center gap-3 rounded-lg border border-border/50 p-4 hover:border-border transition-colors">
                    <div className={`rounded-md h-10 w-10 flex items-center justify-center font-bold text-sm ${info.color}`}>
                      {info.icon}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-medium truncate">{conn.name}</p>
                        <Badge variant={conn.isActive ? "default" : "secondary"} className="text-[10px]">
                          {conn.isActive ? "Active" : "Disabled"}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground truncate mt-0.5">{conn.baseUrl}</p>
                      <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground">
                        <span>{info.label}</span>
                        {conn.hasApiKey && <span className="flex items-center gap-0.5"><CheckCircle2 className="h-2.5 w-2.5 text-green-400" /> Key configured</span>}
                        {conn.lastTested && <span>Tested: {new Date(conn.lastTested).toLocaleDateString()}</span>}
                      </div>
                    </div>
                    <div className="flex items-center gap-1">
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-8 text-xs"
                        onClick={() => testMutation.mutate({ provider: conn.provider, baseUrl: conn.baseUrl, apiKey: undefined })}
                        disabled={testMutation.isPending}
                      >
                        {testMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Zap className="h-3 w-3" />}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-8 text-xs"
                        onClick={() => setPushConnectionId(conn.id)}
                        disabled={!conn.isActive}
                      >
                        <Send className="h-3 w-3 mr-1" /> Push
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-8 text-xs text-destructive hover:text-destructive"
                        onClick={() => { if (confirm("Delete this SIEM connection?")) deleteMutation.mutate({ id: conn.id }); }}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Push Dialog */}
      <Dialog open={pushConnectionId !== null} onOpenChange={(open) => { if (!open) setPushConnectionId(null); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Push Alerts to SIEM</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label>Export Format</Label>
              <Select value={pushFormat} onValueChange={setPushFormat}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="json">JSON</SelectItem>
                  <SelectItem value="cef">CEF (Common Event Format)</SelectItem>
                  <SelectItem value="leef">LEEF (Log Event Extended Format)</SelectItem>
                  <SelectItem value="syslog">Syslog (RFC 5424)</SelectItem>
                  <SelectItem value="csv">CSV</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="rounded-md bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">
                This will export {findings.length} sample findings in {pushFormat.toUpperCase()} format and push them to the selected SIEM connection via its native API.
              </p>
            </div>
          </div>
          <DialogFooter>
            <DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
            <Button
              onClick={() => {
                if (pushConnectionId && findings.length) {
                  pushMutation.mutate({
                    connectionId: pushConnectionId,
                    findings,
                    format: pushFormat as any,
                  });
                }
              }}
              disabled={pushMutation.isPending || !findings.length}
            >
              {pushMutation.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Send className="h-4 w-4 mr-1" />}
              Push {findings.length} Alerts
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Ad-hoc Push Panel */}
      <AdHocPushPanel />
    </div>
  );
}

/* ─── Ad-hoc SIEM Push Panel (manual endpoint entry) ─── */
function AdHocPushPanel() {
  const [target, setTarget] = useState("splunk_hec");
  const [endpoint, setEndpoint] = useState("");
  const [authToken, setAuthToken] = useState("");
  const [index, setIndex] = useState("");
  const [pushFormat, setPushFormat] = useState("json");
  const { data: demoData } = trpc.socIntegrationHub.getDemoData.useQuery();

  const exportMutation = trpc.socIntegrationHub.exportFindings.useMutation();
  const pushMutation = trpc.socIntegrationHub.pushAlerts.useMutation({
    onSuccess: (result) => {
      if (result.success) {
        toast.success(`Pushed ${result.alertsSent} alerts in ${result.durationMs}ms`);
      } else {
        toast.error(`Push had ${result.alertsFailed} failures: ${result.errors.slice(0, 2).join(", ")}`);
      }
    },
    onError: (err) => toast.error(`Push failed: ${err.message}`),
  });

  const testMutation = trpc.socIntegrationHub.testConnection.useMutation({
    onSuccess: (result) => {
      if (result.status === "connected") toast.success(`Connected! ${result.message} (${result.latencyMs}ms)`);
      else if (result.status === "degraded") toast.warning(`Degraded: ${result.message}`);
      else toast.error(`Disconnected: ${result.message}`);
    },
    onError: (err) => toast.error(`Test failed: ${err.message}`),
  });

  const findings = demoData?.sampleFindings ?? [];

  const targetToProvider = (t: string) => {
    if (t === "splunk_hec") return "splunk";
    if (t === "wazuh") return "custom";
    return t;
  };

  const handlePush = async () => {
    if (!endpoint || !findings.length) return;
    // First export findings, then push
    exportMutation.mutate(
      { findings, format: pushFormat as any },
      {
        onSuccess: (exported) => {
          pushMutation.mutate({
            alerts: exported as any,
            config: {
              target: target as any,
              endpoint,
              authToken: authToken || undefined,
              index: index || undefined,
            },
          });
        },
      }
    );
  };

  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><Send className="h-4 w-4 text-blue-400" /> Ad-hoc SIEM Push</CardTitle>
        <CardDescription>Push alerts to any SIEM endpoint without saving the connection</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">Target SIEM</label>
            <Select value={target} onValueChange={setTarget}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="splunk_hec">Splunk HEC</SelectItem>
                <SelectItem value="elastic">Elastic SIEM</SelectItem>
                <SelectItem value="sentinel">Microsoft Sentinel</SelectItem>
                <SelectItem value="qradar">IBM QRadar</SelectItem>
                <SelectItem value="wazuh">Wazuh</SelectItem>
                <SelectItem value="syslog">Syslog (RFC 5424)</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">Export Format</label>
            <Select value={pushFormat} onValueChange={setPushFormat}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="json">JSON</SelectItem>
                <SelectItem value="cef">CEF</SelectItem>
                <SelectItem value="leef">LEEF</SelectItem>
                <SelectItem value="syslog">Syslog</SelectItem>
                <SelectItem value="csv">CSV</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Endpoint URL</label>
          <Input placeholder="https://splunk.corp.io:8088/services/collector" value={endpoint} onChange={e => setEndpoint(e.target.value)} />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">Auth Token / API Key</label>
            <Input type="password" placeholder="Token or API key" value={authToken} onChange={e => setAuthToken(e.target.value)} />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">Index (optional)</label>
            <Input placeholder="main" value={index} onChange={e => setIndex(e.target.value)} />
          </div>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            className="flex-1"
            onClick={() => testMutation.mutate({ provider: targetToProvider(target) as any, baseUrl: endpoint, apiKey: authToken || undefined })}
            disabled={!endpoint || testMutation.isPending}
          >
            {testMutation.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Zap className="h-4 w-4 mr-1" />}
            Test Connection
          </Button>
          <Button
            className="flex-1"
            onClick={handlePush}
            disabled={!endpoint || !findings.length || pushMutation.isPending || exportMutation.isPending}
          >
            {(pushMutation.isPending || exportMutation.isPending) ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Send className="h-4 w-4 mr-1" />}
            Push {findings.length} Alerts
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

/* ─── SIEM Query Panel ─── */
function SiemQueryPanel() {
  const { data: connections } = trpc.socIntegrationHub.listConnections.useQuery();
  const { data: demoData } = trpc.socIntegrationHub.getDemoData.useQuery();

  const [mode, setMode] = useState<"template" | "custom">("template");
  const [selectedProvider, setSelectedProvider] = useState<string>("splunk");
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>("");
  const [selectedConnectionId, setSelectedConnectionId] = useState<string>("");
  const [customQuery, setCustomQuery] = useState("");
  const [variables, setVariables] = useState<Record<string, string>>({});
  const [timeRange, setTimeRange] = useState("24");
  const [maxResults, setMaxResults] = useState("100");
  const [queryResult, setQueryResult] = useState<any>(null);
  const [expandedAlert, setExpandedAlert] = useState<string | null>(null);
  const [gapResult, setGapResult] = useState<any>(null);

  // Ad-hoc fields
  const [adHocUrl, setAdHocUrl] = useState("");
  const [adHocKey, setAdHocKey] = useState("");

  const { data: templates } = trpc.socIntegrationHub.getQueryTemplates.useQuery(
    { provider: selectedProvider as any },
    { enabled: !!selectedProvider }
  );

  const { data: langInfo } = trpc.socIntegrationHub.getQueryLanguageInfo.useQuery(
    { provider: selectedProvider as any },
    { enabled: !!selectedProvider }
  );

  const executeQueryMutation = trpc.socIntegrationHub.executeQuery.useMutation({
    onSuccess: (data) => {
      setQueryResult(data);
      if (data.success) {
        toast.success(`Query returned ${data.totalResults} results in ${data.durationMs}ms`);
      } else {
        toast.error(`Query failed: ${data.error}`);
      }
    },
    onError: (err) => toast.error(`Query error: ${err.message}`),
  });

  const queryConnectionMutation = trpc.socIntegrationHub.queryConnection.useMutation({
    onSuccess: (data) => {
      setQueryResult(data);
      if (data.success) {
        toast.success(`Query returned ${data.totalResults} results in ${data.durationMs}ms`);
      } else {
        toast.error(`Query failed: ${data.error}`);
      }
    },
    onError: (err) => toast.error(`Query error: ${err.message}`),
  });

  const pullAndAnalyzeMutation = trpc.socIntegrationHub.pullAndAnalyzeGaps.useMutation({
    onSuccess: (data) => {
      if (data.queryResult?.success) {
        setQueryResult(data.queryResult);
        setGapResult(data.gapAnalysis);
        toast.success(`Pulled ${data.queryResult.totalResults} alerts and analyzed gaps`);
      } else {
        toast.error(`Pull failed: ${data.error || data.queryResult?.error}`);
      }
    },
    onError: (err) => toast.error(`Pull & analyze error: ${err.message}`),
  });

  // When template changes, extract variables
  const selectedTemplate = templates?.find((t: any) => t.id === selectedTemplateId);
  const queryText = mode === "template" ? (selectedTemplate?.query || "") : customQuery;

  // Extract variable placeholders from query
  const queryVars = queryText.match(/\{\{(\w+)\}\}/g)?.map((m: string) => m.replace(/\{\{|\}\}/g, "")) || [];
  const uniqueVars = [...new Set(queryVars)].filter(v => v !== "time_range" && v !== "max_results");

  const buildFinalQuery = () => {
    const allVars = { ...variables, time_range: timeRange, max_results: maxResults };
    let q = queryText;
    for (const [key, value] of Object.entries(allVars)) {
      q = q.replace(new RegExp(`\\{\\{${key}\\}\\}`, "g"), value);
    }
    return q;
  };

  const handleExecute = () => {
    const finalQuery = buildFinalQuery();
    if (selectedConnectionId) {
      queryConnectionMutation.mutate({
        connectionId: parseInt(selectedConnectionId),
        query: finalQuery,
        timeRangeHours: parseInt(timeRange),
        maxResults: parseInt(maxResults),
      });
    } else {
      executeQueryMutation.mutate({
        provider: selectedProvider as any,
        baseUrl: adHocUrl,
        apiKey: adHocKey || undefined,
        query: finalQuery,
        timeRangeHours: parseInt(timeRange),
        maxResults: parseInt(maxResults),
      });
    }
  };

  const handlePullAndAnalyze = () => {
    if (!selectedConnectionId) {
      toast.error("Select a saved connection to use Pull & Analyze");
      return;
    }
    const attacks = demoData?.sampleAttacks ?? [];
    const finalQuery = buildFinalQuery();
    pullAndAnalyzeMutation.mutate({
      connectionId: parseInt(selectedConnectionId),
      query: finalQuery,
      attacks,
      timeRangeHours: parseInt(timeRange),
    });
  };

  const isQuerying = executeQueryMutation.isPending || queryConnectionMutation.isPending || pullAndAnalyzeMutation.isPending;

  const severityColor = (sev: string) => {
    switch (sev) {
      case "critical": return "text-red-400 bg-red-500/10 border-red-500/20";
      case "high": return "text-orange-400 bg-orange-500/10 border-orange-500/20";
      case "medium": return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20";
      default: return "text-blue-400 bg-blue-500/10 border-blue-500/20";
    }
  };

  return (
    <div className="space-y-4">
      {/* Query Builder */}
      <Card className="border-border/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Search className="h-4 w-4 text-primary" /> SIEM Query Builder</CardTitle>
          <CardDescription>Search your SIEM for alerts and feed results into detection gap analysis</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Connection / Provider Selection */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">Connection Source</label>
              <Select value={selectedConnectionId || "adhoc"} onValueChange={v => {
                if (v === "adhoc") {
                  setSelectedConnectionId("");
                } else {
                  setSelectedConnectionId(v);
                  const conn = connections?.find((c: any) => c.id === parseInt(v));
                  if (conn) setSelectedProvider(conn.provider);
                }
              }}>
                <SelectTrigger><SelectValue placeholder="Select connection..." /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="adhoc">Ad-hoc (enter URL manually)</SelectItem>
                  {connections?.map((c: any) => (
                    <SelectItem key={c.id} value={c.id.toString()}>{c.name} ({c.provider})</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">Provider / Query Language</label>
              <Select value={selectedProvider} onValueChange={v => { setSelectedProvider(v); setSelectedTemplateId(""); }}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="splunk">Splunk (SPL)</SelectItem>
                  <SelectItem value="elastic">Elastic (Query DSL)</SelectItem>
                  <SelectItem value="sentinel">Sentinel (KQL)</SelectItem>
                  <SelectItem value="qradar">QRadar (AQL)</SelectItem>
                  <SelectItem value="custom">Custom / Wazuh</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Ad-hoc URL/Key if no saved connection */}
          {!selectedConnectionId && (
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">SIEM URL</label>
                <Input placeholder="https://splunk.corp.io:8089" value={adHocUrl} onChange={e => setAdHocUrl(e.target.value)} />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">API Key / Token</label>
                <Input type="password" placeholder="Token or API key" value={adHocKey} onChange={e => setAdHocKey(e.target.value)} />
              </div>
            </div>
          )}

          {/* Query Mode Toggle */}
          <div className="flex items-center gap-2">
            <Button variant={mode === "template" ? "default" : "outline"} size="sm" onClick={() => setMode("template")}>
              <FileText className="h-3 w-3 mr-1" /> Templates
            </Button>
            <Button variant={mode === "custom" ? "default" : "outline"} size="sm" onClick={() => setMode("custom")}>
              <Code2 className="h-3 w-3 mr-1" /> Custom Query
            </Button>
            {langInfo && (
              <span className="text-[10px] text-muted-foreground ml-auto">
                Language: {langInfo.language}
              </span>
            )}
          </div>

          {/* Template Selection */}
          {mode === "template" && (
            <div className="space-y-3">
              <Select value={selectedTemplateId} onValueChange={setSelectedTemplateId}>
                <SelectTrigger><SelectValue placeholder="Select a query template..." /></SelectTrigger>
                <SelectContent>
                  {templates?.map((t: any) => (
                    <SelectItem key={t.id} value={t.id}>{t.name} — {t.description}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {selectedTemplate && (
                <div className="rounded-md bg-muted/30 p-3">
                  <p className="text-[10px] text-muted-foreground mb-1 font-medium">Query Template:</p>
                  <pre className="text-xs font-mono text-foreground/80 whitespace-pre-wrap break-all">{selectedTemplate.query}</pre>
                </div>
              )}
            </div>
          )}

          {/* Custom Query Editor */}
          {mode === "custom" && (
            <div className="space-y-2">
              <Textarea
                placeholder={langInfo?.syntaxHint || "Enter your query..."}
                value={customQuery}
                onChange={e => setCustomQuery(e.target.value)}
                className="font-mono text-xs min-h-[120px]"
              />
              {langInfo?.syntaxHint && (
                <p className="text-[10px] text-muted-foreground">Hint: {langInfo.syntaxHint}</p>
              )}
            </div>
          )}

          {/* Variable Substitution */}
          {uniqueVars.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-medium text-muted-foreground">Query Variables:</p>
              <div className="grid grid-cols-2 gap-2">
                {uniqueVars.map(v => (
                  <div key={v} className="space-y-1">
                    <label className="text-[10px] text-muted-foreground font-mono">{`{{${v}}}`}</label>
                    <Input
                      placeholder={v === "technique_id" ? "T1190" : v === "host" ? "10.0.1.5" : v}
                      value={variables[v] || ""}
                      onChange={e => setVariables(prev => ({ ...prev, [v]: e.target.value }))}
                      className="h-8 text-xs"
                    />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Time Range & Max Results */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground flex items-center gap-1"><Clock className="h-3 w-3" /> Time Range (hours)</label>
              <Select value={timeRange} onValueChange={setTimeRange}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">Last 1 hour</SelectItem>
                  <SelectItem value="6">Last 6 hours</SelectItem>
                  <SelectItem value="24">Last 24 hours</SelectItem>
                  <SelectItem value="72">Last 3 days</SelectItem>
                  <SelectItem value="168">Last 7 days</SelectItem>
                  <SelectItem value="720">Last 30 days</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground flex items-center gap-1"><Database className="h-3 w-3" /> Max Results</label>
              <Select value={maxResults} onValueChange={setMaxResults}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="25">25 results</SelectItem>
                  <SelectItem value="50">50 results</SelectItem>
                  <SelectItem value="100">100 results</SelectItem>
                  <SelectItem value="250">250 results</SelectItem>
                  <SelectItem value="500">500 results</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-2">
            <Button
              className="flex-1"
              onClick={handleExecute}
              disabled={isQuerying || !queryText || (!selectedConnectionId && !adHocUrl)}
            >
              {isQuerying ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Play className="h-4 w-4 mr-1" />}
              Execute Query
            </Button>
            <Button
              variant="outline"
              className="flex-1"
              onClick={handlePullAndAnalyze}
              disabled={isQuerying || !queryText || !selectedConnectionId}
              title={!selectedConnectionId ? "Requires a saved connection" : ""}
            >
              {pullAndAnalyzeMutation.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Crosshair className="h-4 w-4 mr-1" />}
              Pull & Analyze Gaps
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Query Results */}
      {queryResult && (
        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Database className="h-4 w-4 text-primary" />
              Query Results
              <Badge variant={queryResult.success ? "default" : "destructive"} className="text-[10px] ml-2">
                {queryResult.success ? `${queryResult.totalResults} alerts` : "Failed"}
              </Badge>
              <span className="text-xs text-muted-foreground ml-auto font-mono">{queryResult.durationMs}ms</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {queryResult.error && (
              <div className="rounded-md bg-red-500/10 border border-red-500/20 p-3 text-xs text-red-400">
                {queryResult.error}
              </div>
            )}
            {queryResult.alerts?.length > 0 ? (
              <div className="space-y-2 max-h-[400px] overflow-y-auto">
                {queryResult.alerts.map((alert: any, i: number) => (
                  <div key={alert.alertId || i} className="rounded-md border border-border/50 hover:border-border transition-colors">
                    <button
                      className="w-full flex items-center gap-2 p-3 text-left"
                      onClick={() => setExpandedAlert(expandedAlert === alert.alertId ? null : alert.alertId)}
                    >
                      {expandedAlert === alert.alertId ? <ChevronDown className="h-3 w-3 text-muted-foreground shrink-0" /> : <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />}
                      <Badge variant="outline" className={`text-[10px] shrink-0 ${severityColor(alert.severity)}`}>{alert.severity}</Badge>
                      <span className="text-xs font-medium truncate flex-1">{alert.title}</span>
                      <span className="text-[10px] text-muted-foreground font-mono shrink-0">{alert.backend}</span>
                      {alert.mitreTechniques?.length > 0 && (
                        <Badge variant="outline" className="text-[10px] font-mono shrink-0">{alert.mitreTechniques[0]}</Badge>
                      )}
                      <span className="text-[10px] text-muted-foreground shrink-0">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </span>
                    </button>
                    {expandedAlert === alert.alertId && (
                      <div className="px-3 pb-3 space-y-2 border-t border-border/30 pt-2">
                        <div className="grid grid-cols-2 gap-2 text-xs">
                          <div><span className="text-muted-foreground">Rule:</span> {alert.ruleName || "N/A"}</div>
                          <div><span className="text-muted-foreground">Agent:</span> {alert.agentName || "N/A"}</div>
                          <div><span className="text-muted-foreground">Rule ID:</span> <span className="font-mono">{alert.ruleId || "N/A"}</span></div>
                          {alert.agentIp && <div><span className="text-muted-foreground">Agent IP:</span> <span className="font-mono">{alert.agentIp}</span></div>}
                          {alert.processName && <div><span className="text-muted-foreground">Process:</span> <span className="font-mono">{alert.processName}</span></div>}
                        </div>
                        {alert.description && (
                          <p className="text-xs text-muted-foreground">{alert.description}</p>
                        )}
                        {alert.mitreTechniques?.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            <span className="text-[10px] text-muted-foreground">MITRE:</span>
                            {alert.mitreTechniques.map((t: string) => (
                              <Badge key={t} variant="outline" className="text-[10px] font-mono">{t}</Badge>
                            ))}
                          </div>
                        )}
                        <details className="text-[10px]">
                          <summary className="text-muted-foreground cursor-pointer hover:text-foreground">Raw Data</summary>
                          <pre className="mt-1 p-2 rounded bg-muted/30 overflow-x-auto text-[10px] font-mono max-h-[200px]">
                            {JSON.stringify(alert.rawData, null, 2)}
                          </pre>
                        </details>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : queryResult.success ? (
              <div className="text-center py-6 text-muted-foreground">
                <Search className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p className="text-sm">No alerts found matching your query</p>
                <p className="text-xs mt-1">Try adjusting the time range or query parameters</p>
              </div>
            ) : null}
          </CardContent>
        </Card>
      )}

      {/* Gap Analysis Results (from Pull & Analyze) */}
      {gapResult && (
        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Target className="h-4 w-4 text-orange-400" /> Detection Gap Analysis (Live SIEM Data)
            </CardTitle>
            <CardDescription>Gaps identified by comparing attack actions against alerts pulled from your SIEM</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div className="rounded-md bg-green-500/10 border border-green-500/20 p-3 text-center">
                <p className="text-2xl font-bold text-green-400">{gapResult.totalDetected ?? 0}</p>
                <p className="text-xs text-muted-foreground">Detected</p>
              </div>
              <div className="rounded-md bg-red-500/10 border border-red-500/20 p-3 text-center">
                <p className="text-2xl font-bold text-red-400">{(gapResult.totalAttacks ?? 0) - (gapResult.totalDetected ?? 0)}</p>
                <p className="text-xs text-muted-foreground">Missed</p>
              </div>
              <div className="rounded-md bg-yellow-500/10 border border-yellow-500/20 p-3 text-center">
                <p className="text-2xl font-bold text-yellow-400">{((gapResult.overallDetectionRate ?? 0) * 100).toFixed(0)}%</p>
                <p className="text-xs text-muted-foreground">Coverage</p>
              </div>
            </div>
            {gapResult.gaps?.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs font-medium text-muted-foreground">Undetected Techniques:</p>
                {gapResult.gaps.map((g: any, i: number) => (
                  <div key={i} className="flex items-center gap-2 rounded-md bg-red-500/5 border border-red-500/10 p-2">
                    <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" />
                    <Badge variant={g.gapSeverity === "critical" ? "destructive" : "secondary"} className="text-[10px]">{g.gapSeverity}</Badge>
                    <span className="text-xs font-mono text-red-300">{g.techniqueId}</span>
                    <span className="text-xs text-foreground">{g.techniqueName}</span>
                    <span className="text-[10px] text-muted-foreground ml-auto">{g.recommendation}</span>
                  </div>
                ))}
              </div>
            )}
            {gapResult.coveredTechniques?.length > 0 && (
              <div className="space-y-1">
                <p className="text-xs font-medium text-muted-foreground">Covered Techniques:</p>
                <div className="flex flex-wrap gap-1">
                  {gapResult.coveredTechniques.map((t: string) => (
                    <Badge key={t} variant="outline" className="text-[10px] text-green-400 border-green-500/30">{t}</Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/* ─── Main Page ─── */
export default function SocIntegrationHub() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">SOC Integration Hub</h1>
        <p className="text-muted-foreground mt-1">
          Manage SIEM connections, query alerts, export findings, analyze detection gaps, and monitor connector health.
        </p>
      </div>

      <div className="grid grid-cols-5 gap-4">
        <Card className="border-primary/20 bg-primary/5">
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="rounded-full bg-primary/20 p-2"><Radio className="h-5 w-5 text-primary" /></div>
            <div>
              <p className="text-2xl font-bold">6</p>
              <p className="text-xs text-muted-foreground">SIEM Targets</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-green-500/20 bg-green-500/5">
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="rounded-full bg-green-500/20 p-2"><Shield className="h-5 w-5 text-green-400" /></div>
            <div>
              <p className="text-2xl font-bold">5</p>
              <p className="text-xs text-muted-foreground">Export Formats</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-orange-500/20 bg-orange-500/5">
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="rounded-full bg-orange-500/20 p-2"><AlertTriangle className="h-5 w-5 text-orange-400" /></div>
            <div>
              <p className="text-2xl font-bold">Gap</p>
              <p className="text-xs text-muted-foreground">Analysis Engine</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-cyan-500/20 bg-cyan-500/5">
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="rounded-full bg-cyan-500/20 p-2"><Search className="h-5 w-5 text-cyan-400" /></div>
            <div>
              <p className="text-2xl font-bold">Query</p>
              <p className="text-xs text-muted-foreground">SIEM Search</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-blue-500/20 bg-blue-500/5">
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="rounded-full bg-blue-500/20 p-2"><HeartPulse className="h-5 w-5 text-blue-400" /></div>
            <div>
              <p className="text-2xl font-bold">Health</p>
              <p className="text-xs text-muted-foreground">SOC Monitor</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="connections" className="space-y-4">
        <TabsList>
          <TabsTrigger value="connections">SIEM Connections</TabsTrigger>
          <TabsTrigger value="query">Query SIEM</TabsTrigger>
          <TabsTrigger value="health">SOC Health</TabsTrigger>
          <TabsTrigger value="export">Alert Export</TabsTrigger>
          <TabsTrigger value="gaps">Detection Gaps</TabsTrigger>
        </TabsList>
        <TabsContent value="connections"><SiemConnectionsPanel /></TabsContent>
        <TabsContent value="query"><SiemQueryPanel /></TabsContent>
        <TabsContent value="health"><SocHealthPanel /></TabsContent>
        <TabsContent value="export"><AlertExportPanel /></TabsContent>
        <TabsContent value="gaps"><DetectionGapPanel /></TabsContent>
      </Tabs>
    </div>
  );
}
