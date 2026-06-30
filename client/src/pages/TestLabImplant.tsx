import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Skull, Radio, Shield, Target, Zap, CheckCircle2, XCircle,
  RefreshCw, AlertTriangle, ArrowRight, Server, Lock, Activity,
  Bug, Crosshair, Wifi, Eye, Clock, BarChart3, FileText,
} from "lucide-react";

/** Known vulnerability types for the exploit pipeline */
const VULN_TYPES = [
  { id: "command_injection", label: "OS Command Injection", severity: "critical", icon: "💉" },
  { id: "file_upload", label: "Unrestricted File Upload", severity: "critical", icon: "📁" },
  { id: "file_inclusion", label: "Local/Remote File Inclusion", severity: "critical", icon: "📂" },
  { id: "sql_injection", label: "SQL Injection", severity: "high", icon: "🗄️" },
  { id: "xss", label: "Cross-Site Scripting (XSS)", severity: "high", icon: "🌐" },
  { id: "deserialization", label: "Insecure Deserialization", severity: "critical", icon: "🔓" },
  { id: "ssrf", label: "Server-Side Request Forgery", severity: "high", icon: "🔗" },
  { id: "rce_generic", label: "Remote Code Execution", severity: "critical", icon: "⚡" },
];

const C2_CHANNELS = [
  { id: "https", label: "HTTPS/TLS", icon: Lock, color: "text-emerald-400" },
  { id: "dns_covert", label: "DNS Covert", icon: Wifi, color: "text-blue-400" },
  { id: "doh_tunnel", label: "DoH Tunnel", icon: Shield, color: "text-cyan-400" },
  { id: "websocket", label: "WebSocket", icon: Activity, color: "text-purple-400" },
  { id: "icmp_covert", label: "ICMP Covert", icon: Radio, color: "text-amber-400" },
  { id: "smb_pipe", label: "SMB Named Pipe", icon: Server, color: "text-orange-400" },
  { id: "steganography", label: "Steganography", icon: Eye, color: "text-pink-400" },
  { id: "p2p_mesh", label: "P2P Mesh", icon: Crosshair, color: "text-indigo-400" },
];

const PIPELINE_STEPS = [
  { icon: Target, label: "Scan Target", color: "text-amber-400", phase: "scanning" },
  { icon: Bug, label: "Find RCE", color: "text-red-400", phase: "analyzing_vuln" },
  { icon: Skull, label: "Gen Payload", color: "text-purple-400", phase: "generating_payload" },
  { icon: Zap, label: "Exploit", color: "text-orange-400", phase: "exploiting" },
  { icon: Radio, label: "Beacon", color: "text-blue-400", phase: "validating_beacon" },
  { icon: CheckCircle2, label: "Validate", color: "text-emerald-400", phase: "validating_c2" },
];

export default function TestLabImplant() {
  const [selectedEnv, setSelectedEnv] = useState("");
  const [selectedVuln, setSelectedVuln] = useState("command_injection");
  const [selectedChannel, setSelectedChannel] = useState("https");
  const [activeTab, setActiveTab] = useState("pipeline");

  const { data: environments } = trpc.testLab.listEnvironments.useQuery();
  const { data: implantTests, refetch: refetchTests } = trpc.testLab.listImplantTests.useQuery();
  const runningEnvs = environments?.filter((e: any) => e.state === "running") ?? [];

  const deployViaExploit = trpc.testLab.runExploitToImplant.useMutation({
    onSuccess: (data) => {
      toast.success(`Exploit pipeline started — Test ID: ${data.testId}`);
      refetchTests();
    },
    onError: (err) => toast.error(err.message),
  });

  const testC2 = trpc.testLab.testC2Channel.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        toast.success(`C2 Channel OK: ${data.channel} — ${data.latencyMs}ms latency, detection risk: ${data.detectionRisk}`);
      } else {
        toast.error(`C2 Channel Failed: ${data.channel}`);
      }
    },
    onError: (err) => toast.error(err.message),
  });

  const validateAll = trpc.testLab.validateAllC2Channels.useMutation({
    onSuccess: (data) => {
      const passed = data.passedChannels ?? 0;
      const total = data.totalChannels ?? 0;
      toast.success(`C2 Validation: ${passed}/${total} channels passed — Overall score: ${data.overallScore ?? 0}%`);
    },
    onError: (err) => toast.error(err.message),
  });

  // Recent test results
  const recentTests = useMemo(() => {
    if (!implantTests) return [];
    return [...implantTests].sort((a: any, b: any) => (b.createdAt || 0) - (a.createdAt || 0)).slice(0, 10);
  }, [implantTests]);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-red-500/10 rounded-xl border border-red-500/20">
            <Skull className="h-7 w-7 text-red-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Ember Implant Testing</h1>
            <p className="text-muted-foreground text-sm">
              End-to-end exploit-to-implant pipeline with C2 channel validation
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="border-emerald-500/30 text-emerald-400">
            <Activity className="h-3 w-3 mr-1" />
            {runningEnvs.length} Lab{runningEnvs.length !== 1 ? "s" : ""} Active
          </Badge>
          <Badge variant="outline" className="border-blue-500/30 text-blue-400">
            {C2_CHANNELS.length} C2 Channels
          </Badge>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-muted/30">
          <TabsTrigger value="pipeline" className="gap-1.5">
            <Zap className="h-3.5 w-3.5" /> Exploit Pipeline
          </TabsTrigger>
          <TabsTrigger value="c2" className="gap-1.5">
            <Radio className="h-3.5 w-3.5" /> C2 Validation
          </TabsTrigger>
          <TabsTrigger value="history" className="gap-1.5">
            <FileText className="h-3.5 w-3.5" /> Test History
          </TabsTrigger>
        </TabsList>

        {/* ═══ EXPLOIT PIPELINE TAB ═══ */}
        <TabsContent value="pipeline" className="space-y-4 mt-4">
          <Card className="border-red-500/20">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-lg">
                <Zap className="h-5 w-5 text-red-400" />
                Exploit-to-Implant Pipeline
              </CardTitle>
              <CardDescription>
                Select a target environment and vulnerability type to execute the full exploit chain:
                scan, exploit, deploy Ember payload, validate beacon, and test C2 communications.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              {/* Pipeline Step Visualization */}
              <div className="flex items-center justify-between p-4 bg-muted/20 rounded-xl border border-border/50 overflow-x-auto">
                {PIPELINE_STEPS.map((step, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <div className="flex flex-col items-center gap-1.5 min-w-[64px]">
                      <div className={`p-2 rounded-lg bg-background/80 border border-border/50 ${
                        deployViaExploit.isPending ? "animate-pulse" : ""
                      }`}>
                        <step.icon className={`h-5 w-5 ${step.color}`} />
                      </div>
                      <span className="text-[10px] text-muted-foreground whitespace-nowrap font-medium">
                        {step.label}
                      </span>
                    </div>
                    {idx < PIPELINE_STEPS.length - 1 && (
                      <ArrowRight className="h-3.5 w-3.5 text-muted-foreground/50 mx-1" />
                    )}
                  </div>
                ))}
              </div>

              {/* Configuration */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                    Target Environment
                  </label>
                  <Select value={selectedEnv} onValueChange={setSelectedEnv}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select lab environment..." />
                    </SelectTrigger>
                    <SelectContent>
                      {runningEnvs.map((env: any) => (
                        <SelectItem key={env.id} value={env.id}>
                          <div className="flex items-center gap-2">
                            <Server className="h-3.5 w-3.5 text-emerald-400" />
                            {env.name}
                          </div>
                        </SelectItem>
                      ))}
                      {runningEnvs.length === 0 && (
                        <SelectItem value="__none__" disabled>
                          No running environments — provision one first
                        </SelectItem>
                      )}
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                    Target Vulnerability
                  </label>
                  <Select value={selectedVuln} onValueChange={setSelectedVuln}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {VULN_TYPES.map(v => (
                        <SelectItem key={v.id} value={v.id}>
                          <div className="flex items-center gap-2">
                            <span>{v.icon}</span>
                            <span>{v.label}</span>
                            <Badge variant={v.severity === "critical" ? "destructive" : "secondary"} className="text-[10px] h-4 ml-auto">
                              {v.severity}
                            </Badge>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="flex items-end">
                  <Button
                    className="w-full bg-red-600 hover:bg-red-700 text-white"
                    disabled={!selectedEnv || selectedEnv === "__none__" || deployViaExploit.isPending}
                    onClick={() => deployViaExploit.mutate({
                      environmentId: selectedEnv,
                      targetVulnerability: selectedVuln,
                      autoSelectPayload: true,
                      validateBeacon: true,
                      validateC2: true,
                    })}
                  >
                    {deployViaExploit.isPending ? (
                      <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <Skull className="h-4 w-4 mr-2" />
                    )}
                    Deploy Ember via Exploit
                  </Button>
                </div>
              </div>

              {/* Pipeline Result */}
              {deployViaExploit.data && (
                <div className="p-4 rounded-xl border bg-muted/10 border-border/50">
                  <div className="flex items-center gap-2 mb-3">
                    <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                    <span className="font-semibold">Pipeline Initiated</span>
                    <Badge variant="outline" className="ml-auto font-mono text-xs">
                      {deployViaExploit.data.testId}
                    </Badge>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                    <div className="p-2.5 bg-background/60 rounded-lg border border-border/30">
                      <span className="text-muted-foreground block mb-0.5">Status</span>
                      <Badge variant="secondary">{deployViaExploit.data.status}</Badge>
                    </div>
                    <div className="p-2.5 bg-background/60 rounded-lg border border-border/30">
                      <span className="text-muted-foreground block mb-0.5">Vulnerability</span>
                      <span className="font-medium">{selectedVuln.replace(/_/g, " ")}</span>
                    </div>
                    <div className="p-2.5 bg-background/60 rounded-lg border border-border/30">
                      <span className="text-muted-foreground block mb-0.5">Environment</span>
                      <span className="font-medium">{runningEnvs.find((e: any) => e.id === selectedEnv)?.name ?? selectedEnv}</span>
                    </div>
                    <div className="p-2.5 bg-background/60 rounded-lg border border-border/30">
                      <span className="text-muted-foreground block mb-0.5">Test ID</span>
                      <span className="font-mono">{deployViaExploit.data.testId?.slice(0, 12)}</span>
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground mt-3">
                    Pipeline is running asynchronously. Check the Test History tab for real-time status updates.
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Quick Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: "Total Tests", value: implantTests?.length ?? 0, icon: BarChart3, color: "text-blue-400" },
              { label: "Successful Deploys", value: implantTests?.filter((t: any) => t.deploymentSucceeded).length ?? 0, icon: CheckCircle2, color: "text-emerald-400" },
              { label: "Failed Exploits", value: implantTests?.filter((t: any) => t.status === "exploit_failed" || t.status === "failed").length ?? 0, icon: XCircle, color: "text-red-400" },
              { label: "Avg OPSEC Score", value: implantTests?.length ? Math.round((implantTests as any[]).reduce((s: number, t: any) => s + (t.opsecScore || 0), 0) / implantTests.length) + "%" : "N/A", icon: Shield, color: "text-amber-400" },
            ].map((stat, i) => (
              <Card key={i} className="border-border/30">
                <CardContent className="p-4 flex items-center gap-3">
                  <stat.icon className={`h-8 w-8 ${stat.color} opacity-60`} />
                  <div>
                    <div className="text-xl font-bold">{stat.value}</div>
                    <div className="text-xs text-muted-foreground">{stat.label}</div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* ═══ C2 VALIDATION TAB ═══ */}
        <TabsContent value="c2" className="space-y-4 mt-4">
          <Card className="border-blue-500/20">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-lg">
                <Radio className="h-5 w-5 text-blue-400" />
                C2 Channel Validation
              </CardTitle>
              <CardDescription>
                Test individual C2 channels or validate all 8 channels against a target environment.
                Measures latency, encryption, detection risk, and throughput.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                    Target Environment
                  </label>
                  <Select value={selectedEnv} onValueChange={setSelectedEnv}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select environment..." />
                    </SelectTrigger>
                    <SelectContent>
                      {runningEnvs.map((env: any) => (
                        <SelectItem key={env.id} value={env.id}>
                          <div className="flex items-center gap-2">
                            <Server className="h-3.5 w-3.5 text-emerald-400" />
                            {env.name}
                          </div>
                        </SelectItem>
                      ))}
                      {runningEnvs.length === 0 && (
                        <SelectItem value="__none__" disabled>No running environments</SelectItem>
                      )}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                    Single Channel Test
                  </label>
                  <Select value={selectedChannel} onValueChange={setSelectedChannel}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {C2_CHANNELS.map(ch => (
                        <SelectItem key={ch.id} value={ch.id}>
                          <div className="flex items-center gap-2">
                            <ch.icon className={`h-3.5 w-3.5 ${ch.color}`} />
                            {ch.label}
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex items-end gap-2">
                  <Button
                    variant="outline"
                    className="flex-1"
                    disabled={!selectedEnv || selectedEnv === "__none__" || testC2.isPending}
                    onClick={() => testC2.mutate({
                      environmentId: selectedEnv,
                      channel: selectedChannel,
                    })}
                  >
                    <Radio className="h-4 w-4 mr-1.5" /> Test Channel
                  </Button>
                  <Button
                    className="flex-1 bg-blue-600 hover:bg-blue-700"
                    disabled={!selectedEnv || selectedEnv === "__none__" || validateAll.isPending}
                    onClick={() => validateAll.mutate({ environmentId: selectedEnv })}
                  >
                    {validateAll.isPending ? (
                      <RefreshCw className="h-4 w-4 mr-1.5 animate-spin" />
                    ) : (
                      <Shield className="h-4 w-4 mr-1.5" />
                    )}
                    Validate All
                  </Button>
                </div>
              </div>

              {/* Channel Results Grid */}
              {validateAll.data?.results && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">
                      Channel Results — {validateAll.data.passedChannels}/{validateAll.data.totalChannels} passed
                    </span>
                    <Badge variant={
                      (validateAll.data.overallScore ?? 0) >= 75 ? "default" :
                      (validateAll.data.overallScore ?? 0) >= 50 ? "secondary" : "destructive"
                    }>
                      Score: {validateAll.data.overallScore ?? 0}%
                    </Badge>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {validateAll.data.results.map((result: any) => {
                      const chInfo = C2_CHANNELS.find(c => c.id === result.channel);
                      const ChIcon = chInfo?.icon ?? Radio;
                      return (
                        <div
                          key={result.channel}
                          className={`p-3.5 rounded-xl border transition-colors ${
                            result.success
                              ? "bg-emerald-500/5 border-emerald-500/20 hover:border-emerald-500/40"
                              : "bg-red-500/5 border-red-500/20 hover:border-red-500/40"
                          }`}
                        >
                          <div className="flex items-center justify-between mb-2.5">
                            <div className="flex items-center gap-1.5">
                              <ChIcon className={`h-4 w-4 ${chInfo?.color ?? "text-muted-foreground"}`} />
                              <span className="text-xs font-semibold">
                                {chInfo?.label ?? result.channel}
                              </span>
                            </div>
                            {result.success ? (
                              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                            ) : (
                              <XCircle className="h-4 w-4 text-red-400" />
                            )}
                          </div>
                          <div className="space-y-1.5 text-xs">
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Latency</span>
                              <span className="font-mono">{result.latencyMs ?? 0}ms</span>
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-muted-foreground">Detection</span>
                              <Badge variant={
                                result.detectionRisk === "none" || result.detectionRisk === "low" ? "default" :
                                result.detectionRisk === "medium" ? "secondary" : "destructive"
                              } className="text-[10px] h-4">
                                {result.detectionRisk ?? "unknown"}
                              </Badge>
                            </div>
                            {result.encryptionVerified && (
                              <div className="flex items-center gap-1 text-emerald-400 pt-0.5">
                                <Lock className="h-3 w-3" />
                                <span>Encrypted</span>
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Single Channel Result */}
              {testC2.data && !validateAll.data && (
                <div className={`p-4 rounded-xl border ${
                  testC2.data.success
                    ? "bg-emerald-500/10 border-emerald-500/20"
                    : "bg-red-500/10 border-red-500/20"
                }`}>
                  <div className="flex items-center gap-2 mb-2">
                    {testC2.data.success ? (
                      <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                    ) : (
                      <XCircle className="h-5 w-5 text-red-400" />
                    )}
                    <span className="font-medium">
                      {testC2.data.channel} — {testC2.data.success ? "Connected" : "Failed"}
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-3 text-xs">
                    <div className="p-2 bg-background/50 rounded">
                      <span className="text-muted-foreground">Latency:</span> {testC2.data.latencyMs}ms
                    </div>
                    <div className="p-2 bg-background/50 rounded">
                      <span className="text-muted-foreground">Detection:</span> {testC2.data.detectionRisk}
                    </div>
                    <div className="p-2 bg-background/50 rounded">
                      <span className="text-muted-foreground">Encrypted:</span> {testC2.data.encryptionVerified ? "Yes" : "No"}
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ═══ TEST HISTORY TAB ═══ */}
        <TabsContent value="history" className="space-y-4 mt-4">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Clock className="h-5 w-5 text-muted-foreground" />
                  Test History
                </CardTitle>
                <Button variant="ghost" size="sm" onClick={() => refetchTests()}>
                  <RefreshCw className="h-3.5 w-3.5 mr-1.5" /> Refresh
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {recentTests.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Skull className="h-12 w-12 mx-auto mb-3 opacity-20" />
                  <p className="font-medium">No implant tests yet</p>
                  <p className="text-sm mt-1">Run an exploit-to-implant pipeline to see results here</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {recentTests.map((test: any) => (
                    <div
                      key={test.id}
                      className="flex items-center gap-3 p-3 rounded-lg border border-border/30 hover:border-border/60 transition-colors"
                    >
                      <div className={`p-1.5 rounded-lg ${
                        test.status === "completed" && test.deploymentSucceeded
                          ? "bg-emerald-500/10"
                          : test.status === "failed" || test.status === "exploit_failed"
                          ? "bg-red-500/10"
                          : "bg-amber-500/10"
                      }`}>
                        {test.status === "completed" && test.deploymentSucceeded ? (
                          <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                        ) : test.status === "failed" || test.status === "exploit_failed" ? (
                          <XCircle className="h-4 w-4 text-red-400" />
                        ) : (
                          <RefreshCw className="h-4 w-4 text-amber-400 animate-spin" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs">{test.id}</span>
                          <Badge variant="outline" className="text-[10px]">
                            {test.exploitVector?.replace(/_/g, " ") ?? "unknown"}
                          </Badge>
                        </div>
                        <div className="text-xs text-muted-foreground mt-0.5">
                          {test.deliveryMethod ?? "exploit_pipeline"} • {test.payloadFormat ?? "auto"}
                        </div>
                      </div>
                      <div className="text-right">
                        <Badge variant={
                          test.status === "completed" ? "default" :
                          test.status === "failed" || test.status === "exploit_failed" ? "destructive" : "secondary"
                        } className="text-[10px]">
                          {test.status}
                        </Badge>
                        {test.opsecScore != null && (
                          <div className="text-[10px] text-muted-foreground mt-1">
                            OPSEC: {test.opsecScore}%
                          </div>
                        )}
                      </div>
                      {test.c2ChannelsPassed && (
                        <div className="text-xs text-muted-foreground">
                          C2: {test.c2ChannelsPassed.length}/{test.c2ChannelsTested?.length ?? 0}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Safety Notice */}
      <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl">
        <div className="flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-amber-400 mt-0.5 flex-shrink-0" />
          <div>
            <p className="font-medium text-amber-400 text-sm">Safety Engine Active</p>
            <p className="text-xs text-muted-foreground mt-1">
              All exploit-to-implant operations are gated by the AC3 Safety Engine. Deployment is only allowed
              against authorized test lab environments with signed Rules of Engagement. The safety level must be
              set to "full_exploitation" or higher for live exploit testing. All C2 communications are logged
              and monitored.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
