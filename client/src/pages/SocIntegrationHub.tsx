import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Radio, Shield, AlertTriangle, Download, Send, Activity,
  CheckCircle2, XCircle, Wifi, WifiOff, FileText, Zap,
  BarChart3, Eye, Copy, ArrowRight, HeartPulse, Server
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
    // Simulate SIEM alerts that detected some but not all attacks
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

/* ─── SIEM Push Panel ─── */
function SiemPushPanel() {
  const [target, setTarget] = useState("splunk_hec");
  const [endpoint, setEndpoint] = useState("");
  

  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><Send className="h-4 w-4 text-blue-400" /> SIEM Push</CardTitle>
        <CardDescription>Push alerts directly to your SIEM platform via API</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Target SIEM</label>
            <Select value={target} onValueChange={setTarget}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="splunk_hec">Splunk HEC</SelectItem>
                <SelectItem value="qradar">IBM QRadar</SelectItem>
                <SelectItem value="sentinel">Microsoft Sentinel</SelectItem>
                <SelectItem value="elastic">Elastic SIEM</SelectItem>
                <SelectItem value="syslog">Syslog (RFC 5424)</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="text-xs text-muted-foreground mb-1 block">Endpoint URL</label>
            <Input placeholder="https://splunk.corp.io:8088/services/collector" value={endpoint} onChange={e => setEndpoint(e.target.value)} />
          </div>
        </div>
        <div className="rounded-md bg-muted/30 p-3">
          <p className="text-xs text-muted-foreground">Configure your SIEM endpoint and API credentials. Alerts from completed engagements will be pushed in the platform's native format (CEF for Splunk/QRadar, JSON for Elastic/Sentinel, RFC 5424 for Syslog).</p>
        </div>
        <Button className="w-full" variant="outline" onClick={() => toast.success(`Testing connection to ${target}... Configure your endpoint above to enable push.`)}>
          <Zap className="h-4 w-4 mr-2" /> Test Connection
        </Button>
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
          Export engagement findings to your SIEM, analyze detection gaps, monitor connector health, and push alerts in real-time.
        </p>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <Card className="border-primary/20 bg-primary/5">
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="rounded-full bg-primary/20 p-2"><Radio className="h-5 w-5 text-primary" /></div>
            <div>
              <p className="text-2xl font-bold">5</p>
              <p className="text-xs text-muted-foreground">SIEM Platforms</p>
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

      <Tabs defaultValue="health" className="space-y-4">
        <TabsList>
          <TabsTrigger value="health">SOC Health</TabsTrigger>
          <TabsTrigger value="export">Alert Export</TabsTrigger>
          <TabsTrigger value="gaps">Detection Gaps</TabsTrigger>
          <TabsTrigger value="push">SIEM Push</TabsTrigger>
        </TabsList>
        <TabsContent value="health"><SocHealthPanel /></TabsContent>
        <TabsContent value="export"><AlertExportPanel /></TabsContent>
        <TabsContent value="gaps"><DetectionGapPanel /></TabsContent>
        <TabsContent value="push"><SiemPushPanel /></TabsContent>
      </Tabs>
    </div>
  );
}
