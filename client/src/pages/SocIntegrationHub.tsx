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
import {
  Radio, Shield, AlertTriangle, Download, Send, Activity,
  CheckCircle2, XCircle, Wifi, WifiOff, FileText, Zap,
  BarChart3, Eye, Copy, ArrowRight, HeartPulse, Server,
  Plus, Trash2, Loader2, Settings, PlugZap, RefreshCw
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

/* ─── Main Page ─── */
export default function SocIntegrationHub() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">SOC Integration Hub</h1>
        <p className="text-muted-foreground mt-1">
          Manage SIEM connections, export findings, analyze detection gaps, monitor connector health, and push alerts in real-time.
        </p>
      </div>

      <div className="grid grid-cols-4 gap-4">
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
          <TabsTrigger value="health">SOC Health</TabsTrigger>
          <TabsTrigger value="export">Alert Export</TabsTrigger>
          <TabsTrigger value="gaps">Detection Gaps</TabsTrigger>
        </TabsList>
        <TabsContent value="connections"><SiemConnectionsPanel /></TabsContent>
        <TabsContent value="health"><SocHealthPanel /></TabsContent>
        <TabsContent value="export"><AlertExportPanel /></TabsContent>
        <TabsContent value="gaps"><DetectionGapPanel /></TabsContent>
      </Tabs>
    </div>
  );
}
