import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import {
  Radar, Shield, Globe, Server, AlertTriangle, CheckCircle,
  Play, Clock, Target, Activity, Crosshair, Eye, Lock,
  ChevronDown, ChevronRight, Skull, Zap, BarChart3, FileText,
  Search, Plus, X, Loader2
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";

// ─── Types ──────────────────────────────────────────────────────────
interface ScanTarget {
  value: string;
  type: "domain" | "ip" | "cidr";
}

interface ScanResult {
  target: string;
  classified: any;
  discovery: {
    subdomains: number;
    openPorts: number;
    technologies: number;
    services: number;
  };
  stackProfile: any;
  threatActors: Array<{ name: string; confidence: number; techniques: number }>;
  recommendedTools: string[];
  riskIndicators: {
    exposedServices: number;
    outdatedTech: number;
    missingHttps: number;
  };
}

interface ScanResponse {
  scanId: string;
  engagementId: number;
  scanType: string;
  initiatedBy: string;
  initiatedAt: string;
  status: string;
  targetCount: number;
  results: ScanResult[];
  summary: {
    totalSubdomains: number;
    totalOpenPorts: number;
    totalTechnologies: number;
    topThreats: Array<{ name: string; confidence: number; techniques: number }>;
    riskScore: number;
  };
}

// ─── Helpers ────────────────────────────────────────────────────────
function riskColor(score: number): string {
  if (score >= 75) return "text-red-400";
  if (score >= 50) return "text-orange-400";
  if (score >= 25) return "text-yellow-400";
  return "text-green-400";
}

function riskBg(score: number): string {
  if (score >= 75) return "bg-red-500/10 border-red-500/30";
  if (score >= 50) return "bg-orange-500/10 border-orange-500/30";
  if (score >= 25) return "bg-yellow-500/10 border-yellow-500/30";
  return "bg-green-500/10 border-green-500/30";
}

function riskLabel(score: number): string {
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Medium";
  return "Low";
}

function classifyInput(value: string): "domain" | "ip" | "cidr" {
  if (value.includes("/")) return "cidr";
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) return "ip";
  return "domain";
}

// ─── Main Component ─────────────────────────────────────────────────
export default function AttackSurfaceAnalysis() {
  const [targets, setTargets] = useState<ScanTarget[]>([]);
  const [inputValue, setInputValue] = useState("");
  const [scanType, setScanType] = useState<"passive" | "light" | "full">("passive");
  const [engagementId, setEngagementId] = useState<number | null>(null);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [activeTab, setActiveTab] = useState("launch");

  // Fetch engagements for the dropdown
  const engagementsQuery = trpc.engagements.list.useQuery(
    { page: 1, pageSize: 50, status: "active" },
    { retry: 1 }
  );

  const launchScan = trpc.clientPortal.attackSurfaceScan.launch.useMutation({
    onSuccess: (data) => {
      setScanResult(data as unknown as ScanResponse);
      setIsScanning(false);
      setActiveTab("results");
      toast.success(`Attack Surface Analysis complete — ${data.targetCount} target(s) analyzed`);
    },
    onError: (err) => {
      setIsScanning(false);
      toast.error(err.message || "Scan failed");
    },
  });

  const addTarget = () => {
    const trimmed = inputValue.trim();
    if (!trimmed) return;
    if (targets.length >= 10) {
      toast.error("Maximum 10 targets per scan");
      return;
    }
    if (targets.some(t => t.value === trimmed)) {
      toast.error("Target already added");
      return;
    }
    setTargets([...targets, { value: trimmed, type: classifyInput(trimmed) }]);
    setInputValue("");
  };

  const removeTarget = (idx: number) => {
    setTargets(targets.filter((_, i) => i !== idx));
  };

  const handleLaunch = () => {
    if (!engagementId) {
      toast.error("Select an engagement first");
      return;
    }
    if (targets.length === 0) {
      toast.error("Add at least one target");
      return;
    }
    setIsScanning(true);
    launchScan.mutate({
      engagementId,
      targets: targets.map(t => t.value),
      scanType,
      notifyOnComplete: true,
    });
  };

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <div className="p-2 rounded-lg bg-teal-500/10">
                <Radar className="w-6 h-6 text-teal-400" />
              </div>
              Attack Surface Analysis
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Client-initiated reconnaissance and exposure assessment — scoped to your approved Rules of Engagement
            </p>
          </div>
          {scanResult && (
            <Badge className={`text-lg px-4 py-2 ${riskBg(scanResult.summary.riskScore)}`}>
              <span className={riskColor(scanResult.summary.riskScore)}>
                Risk Score: {scanResult.summary.riskScore}/100 — {riskLabel(scanResult.summary.riskScore)}
              </span>
            </Badge>
          )}
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-slate-800/50 border border-slate-700/50">
            <TabsTrigger value="launch" className="data-[state=active]:bg-teal-600/20 data-[state=active]:text-teal-300">
              <Play className="w-4 h-4 mr-2" /> Launch Scan
            </TabsTrigger>
            <TabsTrigger value="results" className="data-[state=active]:bg-teal-600/20 data-[state=active]:text-teal-300" disabled={!scanResult}>
              <BarChart3 className="w-4 h-4 mr-2" /> Results
            </TabsTrigger>
            <TabsTrigger value="threats" className="data-[state=active]:bg-teal-600/20 data-[state=active]:text-teal-300" disabled={!scanResult}>
              <Skull className="w-4 h-4 mr-2" /> Threat Actors
            </TabsTrigger>
            <TabsTrigger value="history" className="data-[state=active]:bg-teal-600/20 data-[state=active]:text-teal-300">
              <Clock className="w-4 h-4 mr-2" /> History
            </TabsTrigger>
          </TabsList>

          {/* ─── Launch Tab ─── */}
          <TabsContent value="launch" className="space-y-6 mt-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left: Configuration */}
              <div className="lg:col-span-2 space-y-4">
                <Card className="bg-slate-900/60 border-slate-700/50">
                  <CardHeader>
                    <CardTitle className="text-white flex items-center gap-2">
                      <Target className="w-5 h-5 text-teal-400" />
                      Scan Configuration
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {/* Engagement Selector */}
                    <div>
                      <label className="text-sm text-slate-400 mb-1 block">Active Engagement</label>
                      <Select onValueChange={(v) => setEngagementId(Number(v))}>
                        <SelectTrigger className="bg-slate-800 border-slate-600 text-white">
                          <SelectValue placeholder="Select engagement with approved RoE..." />
                        </SelectTrigger>
                        <SelectContent>
                          {engagementsQuery.data?.engagements?.map((eng: any) => (
                            <SelectItem key={eng.id} value={String(eng.id)}>
                              {eng.name} — {eng.clientName || "No client"}
                            </SelectItem>
                          )) || <SelectItem value="none" disabled>No active engagements</SelectItem>}
                        </SelectContent>
                      </Select>
                    </div>

                    {/* Scan Type */}
                    <div>
                      <label className="text-sm text-slate-400 mb-1 block">Analysis Depth</label>
                      <div className="grid grid-cols-3 gap-3">
                        {[
                          { value: "passive" as const, label: "Passive", desc: "OSINT only — no direct contact", icon: Eye },
                          { value: "light" as const, label: "Light", desc: "Port scan + banner grab", icon: Search },
                          { value: "full" as const, label: "Full", desc: "Vulnerability detection", icon: Crosshair },
                        ].map((opt) => (
                          <button
                            key={opt.value}
                            onClick={() => setScanType(opt.value)}
                            className={`p-3 rounded-lg border text-left transition-all ${
                              scanType === opt.value
                                ? "border-teal-500/50 bg-teal-500/10 text-teal-300"
                                : "border-slate-700 bg-slate-800/50 text-slate-400 hover:border-slate-600"
                            }`}
                          >
                            <opt.icon className="w-4 h-4 mb-1" />
                            <div className="text-sm font-medium">{opt.label}</div>
                            <div className="text-xs opacity-70">{opt.desc}</div>
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Target Input */}
                    <div>
                      <label className="text-sm text-slate-400 mb-1 block">Targets (domains, IPs, or CIDR — max 10)</label>
                      <div className="flex gap-2">
                        <Input
                          value={inputValue}
                          onChange={(e) => setInputValue(e.target.value)}
                          onKeyDown={(e) => e.key === "Enter" && addTarget()}
                          placeholder="e.g. example.com, 192.168.1.0/24, 10.0.0.1"
                          className="bg-slate-800 border-slate-600 text-white flex-1"
                        />
                        <Button onClick={addTarget} variant="outline" className="border-teal-500/50 text-teal-400 hover:bg-teal-500/10">
                          <Plus className="w-4 h-4" />
                        </Button>
                      </div>
                    </div>

                    {/* Target List */}
                    {targets.length > 0 && (
                      <div className="space-y-2">
                        {targets.map((t, i) => (
                          <div key={i} className="flex items-center justify-between bg-slate-800/50 rounded-lg px-3 py-2 border border-slate-700/50">
                            <div className="flex items-center gap-3">
                              {t.type === "domain" && <Globe className="w-4 h-4 text-blue-400" />}
                              {t.type === "ip" && <Server className="w-4 h-4 text-purple-400" />}
                              {t.type === "cidr" && <Activity className="w-4 h-4 text-orange-400" />}
                              <span className="text-white font-mono text-sm">{t.value}</span>
                              <Badge variant="outline" className="text-xs">{t.type.toUpperCase()}</Badge>
                            </div>
                            <button onClick={() => removeTarget(i)} className="text-slate-500 hover:text-red-400">
                              <X className="w-4 h-4" />
                            </button>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Launch Button */}
                    <Button
                      onClick={handleLaunch}
                      disabled={isScanning || !engagementId || targets.length === 0}
                      className="w-full bg-teal-600 hover:bg-teal-700 text-white h-12 text-base"
                    >
                      {isScanning ? (
                        <>
                          <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                          Analyzing Attack Surface...
                        </>
                      ) : (
                        <>
                          <Radar className="w-5 h-5 mr-2" />
                          Launch Attack Surface Analysis
                        </>
                      )}
                    </Button>
                  </CardContent>
                </Card>
              </div>

              {/* Right: Info Panel */}
              <div className="space-y-4">
                <Card className="bg-slate-900/60 border-slate-700/50">
                  <CardHeader>
                    <CardTitle className="text-white text-sm flex items-center gap-2">
                      <Shield className="w-4 h-4 text-teal-400" />
                      Scope Enforcement
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3 text-xs text-slate-400">
                    <div className="flex items-start gap-2">
                      <Lock className="w-3 h-3 text-teal-400 mt-0.5 shrink-0" />
                      <span>Scans are restricted to targets within your approved Rules of Engagement</span>
                    </div>
                    <div className="flex items-start gap-2">
                      <CheckCircle className="w-3 h-3 text-green-400 mt-0.5 shrink-0" />
                      <span>RoE must be signed and approved before scanning</span>
                    </div>
                    <div className="flex items-start gap-2">
                      <Eye className="w-3 h-3 text-blue-400 mt-0.5 shrink-0" />
                      <span>All scan activity is logged and auditable</span>
                    </div>
                    <div className="flex items-start gap-2">
                      <AlertTriangle className="w-3 h-3 text-yellow-400 mt-0.5 shrink-0" />
                      <span>Out-of-scope targets will be rejected</span>
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-slate-900/60 border-slate-700/50">
                  <CardHeader>
                    <CardTitle className="text-white text-sm flex items-center gap-2">
                      <Zap className="w-4 h-4 text-yellow-400" />
                      What Gets Analyzed
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2 text-xs text-slate-400">
                    <div className="flex items-center gap-2">
                      <Globe className="w-3 h-3 text-blue-400" />
                      <span>Subdomain enumeration & DNS records</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Server className="w-3 h-3 text-purple-400" />
                      <span>Open port detection & service fingerprinting</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Activity className="w-3 h-3 text-green-400" />
                      <span>Technology stack profiling</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Skull className="w-3 h-3 text-red-400" />
                      <span>Threat actor correlation</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="w-3 h-3 text-orange-400" />
                      <span>Risk scoring & exposure assessment</span>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          </TabsContent>

          {/* ─── Results Tab ─── */}
          <TabsContent value="results" className="space-y-6 mt-6">
            {scanResult && (
              <>
                {/* Summary Cards */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  <Card className={`border ${riskBg(scanResult.summary.riskScore)}`}>
                    <CardContent className="p-4 text-center">
                      <div className={`text-2xl font-bold ${riskColor(scanResult.summary.riskScore)}`}>
                        {scanResult.summary.riskScore}
                      </div>
                      <div className="text-xs text-slate-400 mt-1">Risk Score</div>
                    </CardContent>
                  </Card>
                  <Card className="bg-slate-900/60 border-slate-700/50">
                    <CardContent className="p-4 text-center">
                      <div className="text-2xl font-bold text-blue-400">{scanResult.summary.totalSubdomains}</div>
                      <div className="text-xs text-slate-400 mt-1">Subdomains</div>
                    </CardContent>
                  </Card>
                  <Card className="bg-slate-900/60 border-slate-700/50">
                    <CardContent className="p-4 text-center">
                      <div className="text-2xl font-bold text-purple-400">{scanResult.summary.totalOpenPorts}</div>
                      <div className="text-xs text-slate-400 mt-1">Open Ports</div>
                    </CardContent>
                  </Card>
                  <Card className="bg-slate-900/60 border-slate-700/50">
                    <CardContent className="p-4 text-center">
                      <div className="text-2xl font-bold text-green-400">{scanResult.summary.totalTechnologies}</div>
                      <div className="text-xs text-slate-400 mt-1">Technologies</div>
                    </CardContent>
                  </Card>
                  <Card className="bg-slate-900/60 border-slate-700/50">
                    <CardContent className="p-4 text-center">
                      <div className="text-2xl font-bold text-orange-400">{scanResult.summary.topThreats.length}</div>
                      <div className="text-xs text-slate-400 mt-1">Threat Actors</div>
                    </CardContent>
                  </Card>
                </div>

                {/* Per-Target Results */}
                <div className="space-y-4">
                  {scanResult.results.map((result, idx) => (
                    <Card key={idx} className="bg-slate-900/60 border-slate-700/50">
                      <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                          <CardTitle className="text-white flex items-center gap-2 text-base">
                            <Globe className="w-4 h-4 text-teal-400" />
                            {result.target}
                          </CardTitle>
                          <div className="flex gap-2">
                            <Badge variant="outline" className="text-xs">
                              {result.discovery.subdomains} subdomains
                            </Badge>
                            <Badge variant="outline" className="text-xs">
                              {result.discovery.openPorts} ports
                            </Badge>
                            <Badge variant="outline" className="text-xs">
                              {result.discovery.technologies} tech
                            </Badge>
                          </div>
                        </div>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          {/* Risk Indicators */}
                          <div className="space-y-2">
                            <div className="text-xs text-slate-500 uppercase font-medium">Risk Indicators</div>
                            <div className="space-y-1">
                              <div className="flex justify-between text-sm">
                                <span className="text-slate-400">Exposed Services</span>
                                <span className={result.riskIndicators.exposedServices > 0 ? "text-red-400" : "text-green-400"}>
                                  {result.riskIndicators.exposedServices}
                                </span>
                              </div>
                              <div className="flex justify-between text-sm">
                                <span className="text-slate-400">Outdated Tech</span>
                                <span className={result.riskIndicators.outdatedTech > 0 ? "text-orange-400" : "text-green-400"}>
                                  {result.riskIndicators.outdatedTech}
                                </span>
                              </div>
                              <div className="flex justify-between text-sm">
                                <span className="text-slate-400">Missing HTTPS</span>
                                <span className={result.riskIndicators.missingHttps > 0 ? "text-yellow-400" : "text-green-400"}>
                                  {result.riskIndicators.missingHttps}
                                </span>
                              </div>
                            </div>
                          </div>

                          {/* Recommended Tools */}
                          <div className="space-y-2">
                            <div className="text-xs text-slate-500 uppercase font-medium">Recommended Tools</div>
                            <div className="flex flex-wrap gap-1">
                              {result.recommendedTools.map((tool, i) => (
                                <Badge key={i} variant="outline" className="text-xs bg-slate-800/50">
                                  {tool}
                                </Badge>
                              ))}
                            </div>
                          </div>

                          {/* Threat Actors */}
                          <div className="space-y-2">
                            <div className="text-xs text-slate-500 uppercase font-medium">Threat Actor Matches</div>
                            <div className="space-y-1">
                              {result.threatActors.map((actor, i) => (
                                <div key={i} className="flex items-center justify-between text-sm">
                                  <span className="text-slate-300 flex items-center gap-1">
                                    <Skull className="w-3 h-3 text-red-400" />
                                    {actor.name}
                                  </span>
                                  <span className="text-xs text-slate-500">{actor.confidence}%</span>
                                </div>
                              ))}
                              {result.threatActors.length === 0 && (
                                <span className="text-xs text-slate-500">No known actors matched</span>
                              )}
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </>
            )}
          </TabsContent>

          {/* ─── Threat Actors Tab ─── */}
          <TabsContent value="threats" className="space-y-6 mt-6">
            {scanResult && (
              <div className="space-y-4">
                <Card className="bg-slate-900/60 border-slate-700/50">
                  <CardHeader>
                    <CardTitle className="text-white flex items-center gap-2">
                      <Skull className="w-5 h-5 text-red-400" />
                      Threat Actor Correlation
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-slate-400 mb-4">
                      Based on your technology stack and sector, these threat actors are most likely to target your infrastructure:
                    </p>
                    <div className="space-y-3">
                      {scanResult.summary.topThreats.map((actor, i) => (
                        <div key={i} className="flex items-center justify-between bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-full bg-red-500/10 flex items-center justify-center">
                              <Skull className="w-4 h-4 text-red-400" />
                            </div>
                            <div>
                              <div className="text-white font-medium">{actor.name}</div>
                              <div className="text-xs text-slate-500">{actor.techniques} known techniques</div>
                            </div>
                          </div>
                          <div className="flex items-center gap-3">
                            <div className="text-right">
                              <div className={`text-sm font-medium ${actor.confidence >= 70 ? "text-red-400" : actor.confidence >= 40 ? "text-orange-400" : "text-yellow-400"}`}>
                                {actor.confidence}% match
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                      {scanResult.summary.topThreats.length === 0 && (
                        <div className="text-center py-8 text-slate-500">
                          <Shield className="w-8 h-8 mx-auto mb-2 opacity-50" />
                          <p>No threat actors matched your current attack surface</p>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}
          </TabsContent>

          {/* ─── History Tab ─── */}
          <TabsContent value="history" className="space-y-6 mt-6">
            <Card className="bg-slate-900/60 border-slate-700/50">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Clock className="w-5 h-5 text-slate-400" />
                  Scan History
                </CardTitle>
              </CardHeader>
              <CardContent>
                {scanResult ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
                      <div className="flex items-center gap-3">
                        <CheckCircle className="w-4 h-4 text-green-400" />
                        <div>
                          <div className="text-white text-sm font-medium">
                            {scanResult.scanId}
                          </div>
                          <div className="text-xs text-slate-500">
                            {scanResult.targetCount} target(s) • {scanResult.scanType} • {new Date(scanResult.initiatedAt).toLocaleString()}
                          </div>
                        </div>
                      </div>
                      <Badge className={riskBg(scanResult.summary.riskScore)}>
                        <span className={riskColor(scanResult.summary.riskScore)}>
                          Score: {scanResult.summary.riskScore}
                        </span>
                      </Badge>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-slate-500">
                    <Clock className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p>No scans completed yet. Launch your first Attack Surface Analysis above.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
