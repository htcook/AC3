import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import {
  Upload, Shield, AlertTriangle, CheckCircle2, XCircle,
  Play, Loader2, Eye, EyeOff, Wifi, Globe, Database,
  Mail, Cloud, Lock, BarChart3, FileWarning, FileText, Layers
} from "lucide-react";

const CHANNEL_ICONS: Record<string, any> = {
  dns_tunnel: Globe,
  https_exfil: Lock,
  icmp_tunnel: Wifi,
  smtp_exfil: Mail,
  cloud_storage: Cloud,
  steganography: Eye,
  protocol_abuse: Database,
};

const CHANNEL_COLORS: Record<string, string> = {
  dns_tunnel: "text-blue-400",
  https_exfil: "text-green-400",
  icmp_tunnel: "text-cyan-400",
  smtp_exfil: "text-orange-400",
  cloud_storage: "text-purple-400",
  steganography: "text-pink-400",
  protocol_abuse: "text-yellow-400",
};

const DIFFICULTY_COLORS: Record<string, string> = {
  basic: "text-green-400 border-green-500/30",
  intermediate: "text-yellow-400 border-yellow-500/30",
  advanced: "text-orange-400 border-orange-500/30",
  expert: "text-red-400 border-red-500/30",
};

/* ─── Scenario Browser ─── */
function ScenarioBrowser() {
  const [difficulty, setDifficulty] = useState<string>("all");
  const { data: scenarios } = trpc.dataExfilSimulation.listScenarios.useQuery(
    difficulty !== "all" ? { difficulty: difficulty as any } : undefined
  );

  return (
    <Card className="border-border/50">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-base"><Layers className="h-4 w-4 text-primary" /> Exfiltration Scenarios</CardTitle>
            <CardDescription>Pre-built scenarios across multiple covert channels and difficulty levels</CardDescription>
          </div>
          <Select value={difficulty} onValueChange={setDifficulty}>
            <SelectTrigger className="w-40"><SelectValue placeholder="Filter" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Difficulties</SelectItem>
              <SelectItem value="basic">Basic</SelectItem>
              <SelectItem value="intermediate">Intermediate</SelectItem>
              <SelectItem value="advanced">Advanced</SelectItem>
              <SelectItem value="expert">Expert</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </CardHeader>
      <CardContent>
        {scenarios && scenarios.length > 0 ? (
          <div className="space-y-2 max-h-[500px] overflow-y-auto">
            {scenarios.map((s: any) => {
              const Icon = CHANNEL_ICONS[s.channel] ?? Globe;
              const color = CHANNEL_COLORS[s.channel] ?? "text-muted-foreground";
              return (
                <div key={s.id} className="flex items-center gap-3 p-3 rounded-md bg-muted/20 border border-border/30">
                  <Icon className={`h-4 w-4 shrink-0 ${color}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium">{s.name}</p>
                    <p className="text-xs text-muted-foreground truncate">{s.description}</p>
                  </div>
                  <Badge variant="outline" className={`text-[10px] ${DIFFICULTY_COLORS[s.difficulty] ?? ""}`}>{s.difficulty}</Badge>
                  <Badge variant="outline" className="text-[10px] capitalize">{s.channel?.replace(/_/g, " ")}</Badge>
                  {s.mitreTechnique && <span className="text-[10px] font-mono text-primary">{s.mitreTechnique}</span>}
                </div>
              );
            })}
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">Loading scenarios...</p>
        )}
      </CardContent>
    </Card>
  );
}

/* ─── Simulation Runner ─── */
function SimulationRunner() {
  
  const { data: scenarios } = trpc.dataExfilSimulation.listScenarios.useQuery();
  const [scenarioId, setScenarioId] = useState("");
  const [targetHost, setTargetHost] = useState("");
  const [dataSizeKb, setDataSizeKb] = useState(100);
  const [durationSeconds, setDurationSeconds] = useState(60);
  const [chunkSizeBytes, setChunkSizeBytes] = useState(1024);
  const [chunkDelayMs, setChunkDelayMs] = useState(100);
  const [encrypted, setEncrypted] = useState(true);
  const [encoded, setEncoded] = useState(false);

  const runMutation = trpc.dataExfilSimulation.runSimulation.useMutation({
    onSuccess: (data) => {
      const wasDetected = data.status === "detected" || data.status === "blocked";
      toast.success(`Exfiltration simulation finished — ${wasDetected ? "DETECTED" : "UNDETECTED"} (${data.status})`);
    },
  });

  const selectedScenario = useMemo(() => scenarios?.find((s: any) => s.id === scenarioId), [scenarios, scenarioId]);

  const handleRun = () => {
    if (!scenarioId) {
      toast.error("Select a scenario first");
      return;
    }
    if (!targetHost) {
      toast.error("Target host is required");
      return;
    }
    runMutation.mutate({
      scenarioId,
      targetHost,
      dataSizeKb,
      durationSeconds,
      encrypted,
      encoded,
      chunkSizeBytes,
      chunkDelayMs,
    });
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-4">
        <Card className="col-span-2 border-border/50">
          <CardHeader>
            <CardTitle className="text-base">Simulation Parameters</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="col-span-2">
                <Label className="text-xs">Scenario</Label>
                <Select value={scenarioId} onValueChange={setScenarioId}>
                  <SelectTrigger><SelectValue placeholder="Select a scenario..." /></SelectTrigger>
                  <SelectContent>
                    {scenarios?.map((s: any) => (
                      <SelectItem key={s.id} value={s.id}>{s.name} ({s.channel?.replace(/_/g, " ")})</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Target Host</Label>
                <Input placeholder="target.example.com" value={targetHost} onChange={e => setTargetHost(e.target.value)} />
              </div>
              <div>
                <Label className="text-xs">Data Size (KB)</Label>
                <Input type="number" value={dataSizeKb} onChange={e => setDataSizeKb(parseInt(e.target.value) || 100)} />
              </div>
              <div>
                <Label className="text-xs">Duration (seconds)</Label>
                <Input type="number" value={durationSeconds} onChange={e => setDurationSeconds(parseInt(e.target.value) || 60)} />
              </div>
              <div>
                <Label className="text-xs">Chunk Size (bytes)</Label>
                <Input type="number" value={chunkSizeBytes} onChange={e => setChunkSizeBytes(parseInt(e.target.value) || 1024)} />
              </div>
              <div>
                <Label className="text-xs">Chunk Delay (ms)</Label>
                <Input type="number" value={chunkDelayMs} onChange={e => setChunkDelayMs(parseInt(e.target.value) || 100)} />
              </div>
            </div>
            <div className="flex gap-6">
              <div className="flex items-center gap-2">
                <Switch checked={encrypted} onCheckedChange={setEncrypted} />
                <Label className="text-xs">Encrypt Payload</Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch checked={encoded} onCheckedChange={setEncoded} />
                <Label className="text-xs">Base64 Encode</Label>
              </div>
            </div>
            <Button onClick={handleRun} disabled={runMutation.isPending} className="w-full">
              {runMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Play className="h-4 w-4 mr-2" />}
              Run Exfiltration Simulation
            </Button>
          </CardContent>
        </Card>

        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="text-base">Scenario Details</CardTitle>
          </CardHeader>
          <CardContent>
            {selectedScenario ? (
              <div className="space-y-3">
                <p className="text-sm font-medium">{selectedScenario.name}</p>
                <p className="text-xs text-muted-foreground">{selectedScenario.description}</p>
                <div className="space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Channel</span>
                    <Badge variant="outline" className="capitalize">{selectedScenario.channel?.replace(/_/g, " ")}</Badge>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Difficulty</span>
                    <Badge variant="outline" className={DIFFICULTY_COLORS[selectedScenario.difficulty] ?? ""}>{selectedScenario.difficulty}</Badge>
                  </div>
                  {selectedScenario.mitreTechnique && (
                    <div className="flex justify-between text-xs">
                      <span className="text-muted-foreground">MITRE Technique</span>
                      <span className="font-mono text-primary">{selectedScenario.mitreTechnique}</span>
                    </div>
                  )}
                </div>
                {selectedScenario.detectionIndicators?.length > 0 && (
                  <div>
                    <p className="text-xs font-medium mb-1">Detection Indicators:</p>
                    {selectedScenario.detectionIndicators.map((ind: string, i: number) => (
                      <div key={i} className="flex items-center gap-2 text-[11px] text-muted-foreground">
                        <AlertTriangle className="h-3 w-3 text-yellow-400 shrink-0" />
                        <span>{ind}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">Select a scenario to view details.</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Results */}
      {runMutation.data && (
        <Card className="border-primary/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><BarChart3 className="h-4 w-4 text-green-400" /> Simulation Results</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-5 gap-3">
              <div className="rounded-md bg-green-500/10 border border-green-500/20 p-3 text-center">
                <p className="text-xl font-bold text-green-400">{runMutation.data.chunksSent ?? 0}</p>
                <p className="text-[10px] text-muted-foreground">Chunks Sent</p>
              </div>
              <div className="rounded-md bg-blue-500/10 border border-blue-500/20 p-3 text-center">
                <p className="text-xl font-bold text-blue-400">{(runMutation.data.dataExfiltratedKb ?? 0).toFixed(1)}</p>
                <p className="text-[10px] text-muted-foreground">KB Transferred</p>
              </div>
              <div className="rounded-md bg-purple-500/10 border border-purple-500/20 p-3 text-center">
                <p className="text-xl font-bold text-purple-400">{((runMutation.data.durationMs ?? 0) / 1000).toFixed(1)}s</p>
                <p className="text-[10px] text-muted-foreground">Duration</p>
              </div>
              <div className="rounded-md bg-cyan-500/10 border border-cyan-500/20 p-3 text-center">
                <p className="text-xl font-bold text-cyan-400">{runMutation.data.transferRateKbps?.toFixed(1) ?? 0}</p>
                <p className="text-[10px] text-muted-foreground">KB/s Throughput</p>
              </div>
              <div className={`rounded-md p-3 text-center ${(runMutation.data.status === "detected" || runMutation.data.status === "blocked") ? "bg-red-500/10 border border-red-500/20" : "bg-green-500/10 border border-green-500/20"}`}>
                {(runMutation.data.status === "detected" || runMutation.data.status === "blocked") ? <XCircle className="h-5 w-5 text-red-400 mx-auto" /> : <EyeOff className="h-5 w-5 text-green-400 mx-auto" />}
                <p className="text-[10px] text-muted-foreground mt-1">{runMutation.data.status}</p>
              </div>
            </div>
            {runMutation.data.detectionEvents?.length > 0 && (
              <div>
                <p className="text-xs font-medium mb-2">Detection Events:</p>
                <div className="space-y-1">
                  {runMutation.data.detectionEvents.map((e: any, i: number) => (
                    <div key={i} className="flex items-center gap-2 text-xs p-2 rounded-md bg-red-500/10 border border-red-500/20">
                      <FileWarning className="h-3.5 w-3.5 text-red-400 shrink-0" />
                      <Badge variant="secondary" className="text-[10px]">{e.severity}</Badge>
                      <span>{e.rule} ({e.source})</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {runMutation.data.assessment && (
              <div>
                <p className="text-xs font-medium mb-2">Assessment:</p>
                <div className="space-y-1">
                  {runMutation.data.assessment.recommendations?.map((r: string, i: number) => (
                    <div key={i} className="flex items-start gap-2 text-xs p-2 rounded-md bg-muted/20">
                      <Shield className="h-3.5 w-3.5 text-blue-400 shrink-0 mt-0.5" />
                      <span>{r}</span>
                    </div>
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

/* ─── Test Data Preview ─── */
function TestDataPreview() {
  const [dataType, setDataType] = useState("pii_sample");
  const [sizeKb, setSizeKb] = useState(5);
  const { data, isLoading } = trpc.dataExfilSimulation.previewTestData.useQuery({ dataType: dataType as any, sizeKb });

  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><FileText className="h-4 w-4 text-orange-400" /> Test Data Preview</CardTitle>
        <CardDescription>Preview sample data payloads used in exfiltration simulations</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-3">
          <Select value={dataType} onValueChange={setDataType}>
            <SelectTrigger className="w-56"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="pii_sample">PII Sample</SelectItem>
              <SelectItem value="credit_card_sample">Credit Card Sample</SelectItem>
              <SelectItem value="credentials_sample">Credentials Sample</SelectItem>
              <SelectItem value="source_code_sample">Source Code Sample</SelectItem>
              <SelectItem value="database_dump_sample">Database Dump Sample</SelectItem>
              <SelectItem value="document_sample">Document Sample</SelectItem>
            </SelectContent>
          </Select>
          <Input type="number" className="w-24" value={sizeKb} onChange={e => setSizeKb(parseInt(e.target.value) || 5)} />
          <span className="text-xs text-muted-foreground self-center">KB</span>
        </div>
        {isLoading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Generating...</div>
        ) : data ? (
          <div>
            <div className="flex items-center gap-3 mb-2 text-xs text-muted-foreground">
              <span>Type: <code className="font-mono">{data.type}</code></span>
              <span>Size: {(data.sizeBytes / 1024).toFixed(1)} KB</span>
            </div>
            <pre className="text-[11px] font-mono bg-muted/30 rounded-md p-4 overflow-x-auto max-h-80 overflow-y-auto whitespace-pre-wrap">{data.preview}</pre>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

/* ─── Campaign Runner ─── */
function CampaignRunner() {
  
  const { data: scenarios } = trpc.dataExfilSimulation.listScenarios.useQuery();
  const [name, setName] = useState("Full Channel Assessment");
  const [targetHost, setTargetHost] = useState("");
  const [selectedIds, setSelectedIds] = useState<string[]>([]);

  const campaignMutation = trpc.dataExfilSimulation.runCampaign.useMutation({
    onSuccess: (data) => {
      toast.success(`${data.scenarioCount} scenarios tested — see results below`);
    },
  });

  const toggleScenario = (id: string) => {
    setSelectedIds(prev => prev.includes(id) ? prev.filter(x => x !== id) : prev.length < 9 ? [...prev, id] : prev);
  };

  return (
    <div className="space-y-4">
      <Card className="border-border/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Layers className="h-4 w-4 text-purple-400" /> Campaign Configuration</CardTitle>
          <CardDescription>Run multiple exfiltration scenarios in sequence and get an aggregate assessment</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-xs">Campaign Name</Label>
              <Input value={name} onChange={e => setName(e.target.value)} />
            </div>
            <div>
              <Label className="text-xs">Target Host</Label>
              <Input placeholder="target.example.com" value={targetHost} onChange={e => setTargetHost(e.target.value)} />
            </div>
          </div>
          <div>
            <Label className="text-xs mb-2 block">Select Scenarios ({selectedIds.length}/9 max)</Label>
            <div className="grid grid-cols-3 gap-2 max-h-48 overflow-y-auto">
              {scenarios?.map((s: any) => (
                <div key={s.id} className={`flex items-center gap-2 p-2 rounded-md cursor-pointer text-xs border transition-all ${selectedIds.includes(s.id) ? "border-primary bg-primary/10" : "border-border/30 bg-muted/10 hover:border-border/50"}`} onClick={() => toggleScenario(s.id)}>
                  {selectedIds.includes(s.id) ? <CheckCircle2 className="h-3.5 w-3.5 text-primary shrink-0" /> : <div className="h-3.5 w-3.5 rounded-full border border-border/50 shrink-0" />}
                  <span className="truncate">{s.name}</span>
                </div>
              ))}
            </div>
          </div>
          <Button onClick={() => {
            if (!targetHost) { toast.error("Target host is required"); return; }
            if (selectedIds.length === 0) { toast.error("Select at least one scenario"); return; }
            campaignMutation.mutate({ name, targetHost, scenarioIds: selectedIds });
          }} disabled={campaignMutation.isPending} className="w-full">
            {campaignMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Play className="h-4 w-4 mr-2" />}
            Run Campaign ({selectedIds.length} scenarios)
          </Button>
        </CardContent>
      </Card>

      {campaignMutation.data && (
        <Card className="border-primary/20">
          <CardHeader>
            <CardTitle className="text-base">Campaign Results: {campaignMutation.data.name}</CardTitle>
            <CardDescription>{campaignMutation.data.scenarioCount} scenarios completed</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {campaignMutation.data.overallAssessment && (
              <div className="grid grid-cols-4 gap-3">
                <div className="rounded-md bg-blue-500/10 border border-blue-500/20 p-3 text-center">
                  <p className="text-xl font-bold text-blue-400">{campaignMutation.data.scenarioCount}</p>
                  <p className="text-[10px] text-muted-foreground">Total Simulations</p>
                </div>
                <div className="rounded-md bg-red-500/10 border border-red-500/20 p-3 text-center">
                  <p className="text-xl font-bold text-red-400">{campaignMutation.data.overallAssessment.overallRisk}</p>
                  <p className="text-[10px] text-muted-foreground">Risk Level</p>
                </div>
                <div className="rounded-md bg-green-500/10 border border-green-500/20 p-3 text-center">
                  <p className="text-xl font-bold text-green-400">{campaignMutation.data.overallAssessment.dlpEffectiveness}%</p>
                  <p className="text-[10px] text-muted-foreground">DLP Effectiveness</p>
                </div>
                <div className="rounded-md bg-purple-500/10 border border-purple-500/20 p-3 text-center">
                  <p className="text-xl font-bold text-purple-400">{campaignMutation.data.overallAssessment.detectionCoverage}%</p>
                  <p className="text-[10px] text-muted-foreground">Detection Coverage</p>
                </div>
              </div>
            )}
            <div className="space-y-2">
              {campaignMutation.data.results?.map((r: any, i: number) => (
                <div key={i} className="flex items-center gap-3 p-2 rounded-md bg-muted/20 border border-border/30">
                  {(r.status === "detected" || r.status === "blocked") ? <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" /> : <CheckCircle2 className="h-3.5 w-3.5 text-green-400 shrink-0" />}
                  <span className="text-xs font-medium">{r.scenarioName || r.scenarioId}</span>
                  <span className="text-[10px] text-muted-foreground">{(r.dataExfiltratedKb ?? 0).toFixed(1)} KB in {((r.durationMs ?? 0) / 1000).toFixed(1)}s</span>
                  <Badge variant={(r.status === "detected" || r.status === "blocked") ? "destructive" : "default"} className="ml-auto text-[10px]">{r.status}</Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/* ─── Main Page ─── */
export default function DataExfilSimulation() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Data Exfiltration Simulation</h1>
        <p className="text-muted-foreground mt-1">
          Simulate data exfiltration across covert channels to test DLP controls, SIEM detection rules, and network monitoring effectiveness.
        </p>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <Card className="border-red-500/20 bg-red-500/5">
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="rounded-full bg-red-500/20 p-2"><Upload className="h-5 w-5 text-red-400" /></div>
            <div>
              <p className="text-sm font-bold">Multi-Channel</p>
              <p className="text-xs text-muted-foreground">DNS, HTTPS, ICMP, SMTP, Cloud, Stego</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-yellow-500/20 bg-yellow-500/5">
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="rounded-full bg-yellow-500/20 p-2"><Eye className="h-5 w-5 text-yellow-400" /></div>
            <div>
              <p className="text-sm font-bold">Detection Testing</p>
              <p className="text-xs text-muted-foreground">Validate SIEM rules catch exfil attempts</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-purple-500/20 bg-purple-500/5">
          <CardContent className="pt-4 flex items-center gap-3">
            <div className="rounded-full bg-purple-500/20 p-2"><Layers className="h-5 w-5 text-purple-400" /></div>
            <div>
              <p className="text-sm font-bold">Campaign Mode</p>
              <p className="text-xs text-muted-foreground">Run multi-scenario campaigns with assessment</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="scenarios" className="space-y-4">
        <TabsList>
          <TabsTrigger value="scenarios">Scenarios</TabsTrigger>
          <TabsTrigger value="simulate">Run Simulation</TabsTrigger>
          <TabsTrigger value="campaign">Campaign</TabsTrigger>
          <TabsTrigger value="testdata">Test Data</TabsTrigger>
        </TabsList>
        <TabsContent value="scenarios"><ScenarioBrowser /></TabsContent>
        <TabsContent value="simulate"><SimulationRunner /></TabsContent>
        <TabsContent value="campaign"><CampaignRunner /></TabsContent>
        <TabsContent value="testdata"><TestDataPreview /></TabsContent>
      </Tabs>
    </div>
  );
}
