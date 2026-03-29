import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Bug, Search, RefreshCw, Plus, ExternalLink, Shield,
  AlertTriangle, Link2, TrendingUp, Globe, Zap, Target,
  ChevronRight, Clock, DollarSign, Users, BarChart3,
  Key, CheckCircle2, XCircle, Loader2, Trash2, Eye, EyeOff, Unplug,
  Database, Activity, Layers, FileText, Crosshair, Radar,
  Brain, Download, Sparkles, FlaskConical, ArrowRightLeft, BookOpen
} from "lucide-react";
import AppShell from "@/components/AppShell";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  none: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

const CORRELATION_COLORS: Record<string, string> = {
  cve_match: "bg-red-500/20 text-red-400",
  asset_match: "bg-cyan-500/20 text-cyan-400",
  cwe_match: "bg-purple-500/20 text-purple-400",
};

export default function BugBountyHub() {
  const [activeTab, setActiveTab] = useState("intelligence");
  const [search, setSearch] = useState("");
  const [platform, setPlatform] = useState<"all" | "hackerone" | "bugcrowd" | "manual">("all");
  const [severity, setSeverity] = useState<string>("");
  const [showAddProgramDialog, setShowAddProgramDialog] = useState(false);
  const [showAddFindingDialog, setShowAddFindingDialog] = useState(false);
  const [showSyncDialog, setShowSyncDialog] = useState(false);
  const [showAddCredentialDialog, setShowAddCredentialDialog] = useState(false);
  const [showApiKey, setShowApiKey] = useState(false);
  const [selectedScopeProgram, setSelectedScopeProgram] = useState<string>("");
  const [trainingCategory, setTrainingCategory] = useState<string>("all");
  const [newCredential, setNewCredential] = useState({
    platform: "hackerone" as "hackerone" | "bugcrowd" | "intigriti" | "synack" | "yeswehack" | "custom",
    displayName: "",
    apiUsername: "",
    apiKey: "",
    baseUrl: "",
  });

  // Form state
  const [newProgram, setNewProgram] = useState({ platform: "manual" as const, handle: "", name: "", url: "", minBounty: 0, maxBounty: 0 });
  const [newFinding, setNewFinding] = useState({ platform: "manual" as const, title: "", severityRating: "medium" as const, cveIds: "", cweId: "", assetIdentifier: "", summary: "" });
  const [syncQuery, setSyncQuery] = useState("severity_rating:critical OR severity_rating:high");
  const [syncPages, setSyncPages] = useState(3);

  // ─── Queries ───
  const { data: stats } = trpc.bugBounty.stats.useQuery(undefined);
  const { data: intelSummary } = trpc.bugBounty.intelligenceSummary.useQuery(undefined);
  const { data: cweAnalytics } = trpc.bugBounty.cweAnalytics.useQuery({ limit: 20 });

  const programsInput = useMemo(() => ({ platform, search: search || undefined, limit: 50 }), [platform, search]);
  const { data: programsData, isLoading: programsLoading, refetch: refetchPrograms } = trpc.bugBounty.listPrograms.useQuery(programsInput);
  const findingsInput = useMemo(() => ({ platform, severity: severity || undefined, search: search || undefined, limit: 50 }), [platform, severity, search]);
  const { data: findingsData, isLoading: findingsLoading, refetch: refetchFindings } = trpc.bugBounty.listFindings.useQuery(findingsInput);
  const correlationsInput = useMemo(() => ({ limit: 50 }), []);
  const { data: correlations, refetch: refetchCorrelations } = trpc.bugBounty.listCorrelations.useQuery(correlationsInput);
  const syncHistoryInput = useMemo(() => ({ limit: 20 }), []);
  const { data: syncHistory } = trpc.bugBounty.syncHistory.useQuery(syncHistoryInput);

  // Scopes & Weaknesses
  const scopesInput = useMemo(() => ({ programHandle: selectedScopeProgram || undefined, limit: 100 }), [selectedScopeProgram]);
  const { data: scopesData } = trpc.bugBounty.listProgramScopes.useQuery(scopesInput);
  const weaknessesInput = useMemo(() => ({ programHandle: selectedScopeProgram || undefined, limit: 100 }), [selectedScopeProgram]);
  const { data: weaknessesData } = trpc.bugBounty.listProgramWeaknesses.useQuery(weaknessesInput);

  // ─── LLM Training & ScanForge Bridge Queries ───
  const { data: trainingStats, refetch: refetchTrainingStats } = trpc.bugBounty.trainingStats.useQuery(undefined);
  const { data: bountyROI } = trpc.bugBounty.bountyROI.useQuery(undefined);
  const { data: bridgeStats, refetch: refetchBridgeStats } = trpc.bugBounty.scanForgeBridgeStats.useQuery(undefined);

  const extractH1 = trpc.bugBounty.extractH1Training.useMutation({
    onSuccess: (d: any) => { toast.success(`Extracted ${d.extracted} training samples from HackerOne (${d.skipped} skipped)`); refetchTrainingStats(); },
    onError: (e: any) => toast.error(e.message),
  });
  const extractEngagement = trpc.bugBounty.extractEngagementTraining.useMutation({
    onSuccess: (d: any) => { toast.success(`Extracted ${d.extracted} samples from engagements — Nuclei: ${d.sources.nuclei}, ZAP: ${d.sources.zap}, Exploits: ${d.sources.exploit}, Reports: ${d.sources.report}`); refetchTrainingStats(); },
    onError: (e: any) => toast.error(e.message),
  });
  const enrichTraining = trpc.bugBounty.enrichTraining.useMutation({
    onSuccess: (d: any) => { toast.success(`Enriched ${d.enriched} samples (${d.failed} failed)`); refetchTrainingStats(); },
    onError: (e: any) => toast.error(e.message),
  });
  const exportJSONL = trpc.bugBounty.exportTrainingJSONL.useMutation({
    onSuccess: (d: any) => {
      if (d.count === 0) { toast.info("No samples to export"); return; }
      const blob = new Blob([d.lines.join("\n")], { type: "application/jsonl" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = `ac3-training-${Date.now()}.jsonl`; a.click();
      URL.revokeObjectURL(url);
      toast.success(`Exported ${d.count} samples as JSONL`);
      refetchTrainingStats();
    },
    onError: (e: any) => toast.error(e.message),
  });
  const generateTemplates = trpc.bugBounty.generateScanForgeTemplates.useMutation({
    onSuccess: (d: any) => { toast.success(`Generated ${d.generated} ScanForge templates (${d.skipped} skipped, ${d.failed} failed)`); refetchBridgeStats(); },
    onError: (e: any) => toast.error(e.message),
  });
  const runIntelPipeline = trpc.bugBounty.runIntelPipeline.useMutation({
    onSuccess: (d: any) => {
      const ok = d.stages?.filter((s: any) => s.status === "ok").length || 0;
      const err = d.stages?.filter((s: any) => s.status === "error").length || 0;
      toast.success(`Intel pipeline complete: ${ok} stages ok, ${err} errors (${(d.totalDurationMs / 1000).toFixed(1)}s)`);
      refetchTrainingStats(); refetchBridgeStats(); refetchFindings(); refetchPrograms();
    },
    onError: (e: any) => toast.error(`Pipeline failed: ${e.message}`),
  });

  // Platform Credentials
  const { data: credentials, refetch: refetchCredentials } = trpc.platformCredentials.list.useQuery(undefined);
  const addCredential = trpc.platformCredentials.add.useMutation({
    onSuccess: () => { toast.success("Platform credentials saved"); setShowAddCredentialDialog(false); setNewCredential({ platform: "hackerone", displayName: "", apiUsername: "", apiKey: "", baseUrl: "" }); refetchCredentials(); },
    onError: (e: any) => toast.error(e.message),
  });
  const deleteCredential = trpc.platformCredentials.delete.useMutation({
    onSuccess: () => { toast.success("Credentials removed"); refetchCredentials(); },
    onError: (e: any) => toast.error(e.message),
  });
  const verifyCredential = trpc.platformCredentials.verify.useMutation({
    onSuccess: (result: any) => {
      if (result.valid) toast.success(result.message);
      else toast.error(result.message);
      refetchCredentials();
    },
    onError: (e: any) => toast.error(e.message),
  });
  const toggleCredential = trpc.platformCredentials.update.useMutation({
    onSuccess: () => { refetchCredentials(); },
  });

  // ─── Mutations ───
  const syncHacktivity = trpc.bugBounty.syncHackerOneHacktivity.useMutation({
    onSuccess: (d: any) => { toast.success(`Synced ${d.synced} findings (${d.updated} updated) from HackerOne`); refetchFindings(); },
    onError: (e: any) => toast.error(e.message),
  });
  const syncPrograms = trpc.bugBounty.syncHackerOnePrograms.useMutation({
    onSuccess: (d: any) => { toast.success(`Synced ${d.synced} programs from HackerOne`); refetchPrograms(); },
    onError: (e: any) => toast.error(e.message),
  });
  const syncAll = trpc.bugBounty.syncAll.useMutation({
    onSuccess: (d: any) => {
      const r = d.results;
      toast.success(`Full sync complete: ${r.hacktivity.synced} findings, ${r.programs.synced} programs, ${r.scopes.synced} scopes, ${r.weaknesses.synced} weaknesses`);
      if (r.errors.length > 0) toast.warning(`${r.errors.length} sync errors: ${r.errors[0]}`);
      refetchFindings();
      refetchPrograms();
    },
    onError: (e: any) => toast.error(e.message),
  });
  const syncScopes = trpc.bugBounty.syncHackerOneScopes.useMutation({
    onSuccess: (d: any) => { toast.success(`Synced ${d.synced} scopes for ${d.programHandle}`); },
    onError: (e: any) => toast.error(e.message),
  });
  const syncWeaknesses = trpc.bugBounty.syncHackerOneWeaknesses.useMutation({
    onSuccess: (d: any) => { toast.success(`Synced ${d.synced} weaknesses for ${d.programHandle}`); },
    onError: (e: any) => toast.error(e.message),
  });
  const addProgram = trpc.bugBounty.addProgram.useMutation({
    onSuccess: () => { toast.success("Program added"); setShowAddProgramDialog(false); refetchPrograms(); },
    onError: (e: any) => toast.error(e.message),
  });
  const addFinding = trpc.bugBounty.addFinding.useMutation({
    onSuccess: () => { toast.success("Finding added"); setShowAddFindingDialog(false); refetchFindings(); },
    onError: (e: any) => toast.error(e.message),
  });
  const runCorrelation = trpc.bugBounty.runCorrelation.useMutation({
    onSuccess: (d: any) => { toast.success(`Found ${d.total} correlations (${d.newCorrelations} new)`); refetchCorrelations(); },
    onError: (e: any) => toast.error(e.message),
  });
  const deleteProgram = trpc.bugBounty.deleteProgram.useMutation({
    onSuccess: () => { toast.success("Program deleted"); refetchPrograms(); },
  });
  const deleteFinding = trpc.bugBounty.deleteFinding.useMutation({
    onSuccess: () => { toast.success("Finding deleted"); refetchFindings(); refetchCorrelations(); },
  });

  const utils = trpc.useUtils();

  return (
    <AppShell activePath="/bug-bounty">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Bug className="h-6 w-6 text-emerald-400" />
            Bug Bounty Intelligence Hub
          </h1>
          <p className="text-muted-foreground mt-1 text-sm max-w-2xl">
            Ingest and correlate disclosed vulnerability data from HackerOne with your threat intelligence, vulnerability intelligence, and attack surface mapping pipelines. Sync hacktivity feeds, program scopes, CWE taxonomies, and cross-reference findings against your discovered assets and IOC feeds.
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <Button variant="outline" size="sm" className="border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10" onClick={() => runIntelPipeline.mutate()} disabled={runIntelPipeline.isPending}>
            <Brain className={`h-4 w-4 mr-1 ${runIntelPipeline.isPending ? "animate-pulse" : ""}`} />
            {runIntelPipeline.isPending ? "Running Pipeline..." : "Intel Pipeline"}
          </Button>
          <Button variant="outline" size="sm" onClick={() => runCorrelation.mutate({})} disabled={runCorrelation.isPending}>
            <Zap className="h-4 w-4 mr-1" />
            {runCorrelation.isPending ? "Correlating..." : "Run Correlation"}
          </Button>
          <Button variant="outline" size="sm" onClick={() => syncAll.mutate({ hacktivityPages: 5, programPages: 5 })} disabled={syncAll.isPending}>
            <RefreshCw className={`h-4 w-4 mr-1 ${syncAll.isPending ? "animate-spin" : ""}`} />
            {syncAll.isPending ? "Full Sync..." : "Full Sync"}
          </Button>
          <Button variant="outline" size="sm" onClick={() => setShowSyncDialog(true)}>
            <RefreshCw className="h-4 w-4 mr-1" />
            Custom Sync
          </Button>
          <Button size="sm" onClick={() => setShowAddFindingDialog(true)}>
            <Plus className="h-4 w-4 mr-1" />
            Add Finding
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Findings</p>
                <p className="text-xl font-bold">{intelSummary?.totals?.findings ?? stats?.findings ?? 0}</p>
              </div>
              <Bug className="h-6 w-6 text-emerald-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Programs</p>
                <p className="text-xl font-bold">{intelSummary?.totals?.programs ?? stats?.programs ?? 0}</p>
              </div>
              <Globe className="h-6 w-6 text-blue-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Scopes</p>
                <p className="text-xl font-bold">{intelSummary?.totals?.scopes ?? 0}</p>
              </div>
              <Crosshair className="h-6 w-6 text-cyan-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Weaknesses</p>
                <p className="text-xl font-bold">{intelSummary?.totals?.weaknesses ?? 0}</p>
              </div>
              <AlertTriangle className="h-6 w-6 text-yellow-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Correlations</p>
                <p className="text-xl font-bold">{intelSummary?.totals?.correlations ?? stats?.correlations ?? 0}</p>
              </div>
              <Link2 className="h-6 w-6 text-purple-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">With CVE</p>
                <p className="text-xl font-bold">{intelSummary?.totals?.findingsWithCVE ?? 0}</p>
              </div>
              <Database className="h-6 w-6 text-red-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-zinc-900 border border-zinc-800 flex-wrap h-auto gap-1 p-1">
          <TabsTrigger value="intelligence" className="text-xs">
            <Radar className="h-3.5 w-3.5 mr-1" />
            Intelligence
          </TabsTrigger>
          <TabsTrigger value="findings" className="text-xs">Findings</TabsTrigger>
          <TabsTrigger value="programs" className="text-xs">Programs</TabsTrigger>
          <TabsTrigger value="scopes" className="text-xs">
            <Crosshair className="h-3.5 w-3.5 mr-1" />
            Scopes
          </TabsTrigger>
          <TabsTrigger value="weaknesses" className="text-xs">
            <AlertTriangle className="h-3.5 w-3.5 mr-1" />
            CWE Taxonomy
          </TabsTrigger>
          <TabsTrigger value="correlations" className="text-xs">Correlations</TabsTrigger>
          <TabsTrigger value="sync" className="text-xs">Sync History</TabsTrigger>
          <TabsTrigger value="accounts" className="text-xs">
            <Key className="h-3.5 w-3.5 mr-1" />
            Accounts
          </TabsTrigger>
          <TabsTrigger value="training" className="text-xs">
            <Brain className="h-3.5 w-3.5 mr-1" />
            LLM Training
          </TabsTrigger>
          <TabsTrigger value="scanforge-bridge" className="text-xs">
            <ArrowRightLeft className="h-3.5 w-3.5 mr-1" />
            ScanForge Bridge
          </TabsTrigger>
        </TabsList>

        {/* ─── Intelligence Overview Tab ─── */}
        <TabsContent value="intelligence" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* CWE Distribution from Findings */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Activity className="h-4 w-4 text-emerald-400" />
                  Top CWEs in Disclosed Findings
                </CardTitle>
                <CardDescription className="text-xs">Weakness categories from HackerOne hacktivity — maps to vulnerability intelligence pipeline</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {(cweAnalytics?.cweDistribution || []).slice(0, 10).map((c: any, i: number) => {
                    const maxCount = cweAnalytics?.cweDistribution?.[0]?.count || 1;
                    const pct = Math.round((c.count / maxCount) * 100);
                    return (
                      <div key={c.cweId || i} className="flex items-center gap-3">
                        <span className="text-xs text-muted-foreground w-6">{i + 1}.</span>
                        <Badge variant="outline" className="text-xs w-24 justify-center shrink-0">{c.cweId || "Unknown"}</Badge>
                        <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                          <div className="h-full rounded-full bg-emerald-500/70" style={{ width: `${pct}%` }} />
                        </div>
                        <span className="text-xs text-muted-foreground w-8 text-right">{c.count}</span>
                        {c.avgBounty > 0 && (
                          <span className="text-xs text-emerald-400 w-16 text-right">${Math.round(c.avgBounty).toLocaleString()}</span>
                        )}
                      </div>
                    );
                  })}
                  {(!cweAnalytics?.cweDistribution || cweAnalytics.cweDistribution.length === 0) && (
                    <p className="text-sm text-muted-foreground text-center py-4">No CWE data yet. Sync hacktivity to populate.</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Severity Distribution */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <BarChart3 className="h-4 w-4 text-red-400" />
                  Severity Distribution
                </CardTitle>
                <CardDescription className="text-xs">Finding severity breakdown with bounty totals</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {(cweAnalytics?.severityDistribution || []).map((s: any) => {
                    const total = (cweAnalytics?.severityDistribution || []).reduce((acc: number, x: any) => acc + (x.count || 0), 0) || 1;
                    const pct = Math.round(((s.count || 0) / total) * 100);
                    return (
                      <div key={s.severity || "unknown"} className="flex items-center gap-3">
                        <Badge className={`w-20 justify-center text-xs ${SEVERITY_COLORS[s.severity || "none"] || SEVERITY_COLORS.none}`}>
                          {s.severity || "none"}
                        </Badge>
                        <div className="flex-1 h-2.5 bg-zinc-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${s.severity === "critical" ? "bg-red-500" : s.severity === "high" ? "bg-orange-500" : s.severity === "medium" ? "bg-yellow-500" : s.severity === "low" ? "bg-blue-500" : "bg-zinc-500"}`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <span className="text-sm w-10 text-right">{s.count}</span>
                        <span className="text-xs text-muted-foreground w-8 text-right">{pct}%</span>
                        {s.totalBounty > 0 && (
                          <span className="text-xs text-emerald-400 w-20 text-right">${Number(s.totalBounty).toLocaleString()}</span>
                        )}
                      </div>
                    );
                  })}
                  {(!cweAnalytics?.severityDistribution || cweAnalytics.severityDistribution.length === 0) && (
                    <p className="text-sm text-muted-foreground text-center py-4">No findings yet. Sync from HackerOne.</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Program CWE Distribution */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Layers className="h-4 w-4 text-yellow-400" />
                  CWE Taxonomy Across Programs
                </CardTitle>
                <CardDescription className="text-xs">Weakness categories reported across bug bounty programs — maps to threat pattern analysis</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {(cweAnalytics?.programCweDistribution || []).slice(0, 10).map((c: any, i: number) => (
                    <div key={c.cweId || i} className="flex items-center justify-between p-2 bg-zinc-800/30 rounded-lg">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-xs">{c.cweId || "N/A"}</Badge>
                        <span className="text-sm truncate max-w-[200px]">{c.name}</span>
                      </div>
                      <Badge className="bg-yellow-500/20 text-yellow-400 text-xs">{c.programCount} programs</Badge>
                    </div>
                  ))}
                  {(!cweAnalytics?.programCweDistribution || cweAnalytics.programCweDistribution.length === 0) && (
                    <p className="text-sm text-muted-foreground text-center py-4">No weakness data yet. Sync program weaknesses.</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Asset Type Distribution */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Target className="h-4 w-4 text-cyan-400" />
                  Attack Surface by Asset Type
                </CardTitle>
                <CardDescription className="text-xs">Scope asset categories from bug bounty programs — maps to attack surface intelligence</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {(cweAnalytics?.assetTypeDistribution || []).map((a: any, i: number) => (
                    <div key={a.assetType || i} className="flex items-center justify-between p-2 bg-zinc-800/30 rounded-lg">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-xs">{a.assetType}</Badge>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-sm">{a.count} assets</span>
                        {a.bountyEligible > 0 && (
                          <Badge className="bg-emerald-500/20 text-emerald-400 text-xs">{a.bountyEligible} bounty-eligible</Badge>
                        )}
                      </div>
                    </div>
                  ))}
                  {(!cweAnalytics?.assetTypeDistribution || cweAnalytics.assetTypeDistribution.length === 0) && (
                    <p className="text-sm text-muted-foreground text-center py-4">No scope data yet. Sync program scopes.</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Top Programs */}
            <Card className="bg-zinc-900/50 border-zinc-800 lg:col-span-2">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-blue-400" />
                  Top Programs by Disclosed Findings
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {(intelSummary?.topPrograms || stats?.topPrograms || []).map((p: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-3 bg-zinc-800/30 rounded-lg">
                      <div className="flex items-center gap-3">
                        <span className="text-sm text-muted-foreground w-6">{i + 1}.</span>
                        <div>
                          <p className="font-medium text-sm">{p.programName || p.programHandle || "Unknown"}</p>
                          <p className="text-xs text-muted-foreground">{p.programHandle}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        {(p.criticalCount > 0 || p.highCount > 0) && (
                          <div className="flex gap-1">
                            {p.criticalCount > 0 && <Badge className="bg-red-500/20 text-red-400 text-xs">{p.criticalCount} crit</Badge>}
                            {p.highCount > 0 && <Badge className="bg-orange-500/20 text-orange-400 text-xs">{p.highCount} high</Badge>}
                          </div>
                        )}
                        <div className="text-right">
                          <p className="text-sm font-medium">{p.count} findings</p>
                          {p.totalAwarded > 0 && (
                            <p className="text-xs text-emerald-400">${Number(p.totalAwarded).toLocaleString()}</p>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                  {(!(intelSummary?.topPrograms || stats?.topPrograms) || (intelSummary?.topPrograms || stats?.topPrograms || []).length === 0) && (
                    <p className="text-sm text-muted-foreground text-center py-4">No program data yet.</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Correlation Breakdown */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Correlation Types</CardTitle>
                <CardDescription className="text-xs">Cross-references between findings and your intelligence data</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {(stats?.correlationBreakdown || []).map((c: any) => (
                    <div key={c.type} className="flex items-center justify-between p-3 bg-zinc-800/50 rounded-lg">
                      <Badge className={CORRELATION_COLORS[c.type] || "bg-zinc-500/20 text-zinc-400"}>
                        {c.type === "cve_match" ? "CVE Match" : c.type === "asset_match" ? "Asset Match" : "CWE Match"}
                      </Badge>
                      <span className="text-lg font-semibold">{c.count}</span>
                    </div>
                  ))}
                  {(!stats?.correlationBreakdown || stats.correlationBreakdown.length === 0) && (
                    <p className="text-sm text-muted-foreground text-center py-4">Run correlation engine to find matches.</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Last Sync Info */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Clock className="h-4 w-4 text-zinc-400" />
                  Last Sync
                </CardTitle>
              </CardHeader>
              <CardContent>
                {intelSummary?.lastSync ? (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Type</span>
                      <Badge variant="outline" className="text-xs">{intelSummary.lastSync.platform} / {intelSummary.lastSync.syncType}</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Status</span>
                      <Badge variant={intelSummary.lastSync.status === "completed" ? "default" : "destructive"} className="text-xs">{intelSummary.lastSync.status}</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Items</span>
                      <span className="text-sm">{intelSummary.lastSync.itemsSynced ?? 0}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">When</span>
                      <span className="text-xs">{intelSummary.lastSync.startedAt ? new Date(intelSummary.lastSync.startedAt).toLocaleString() : "Unknown"}</span>
                    </div>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground text-center py-4">No syncs yet. Click "Full Sync" to start.</p>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ─── Findings Feed Tab ─── */}
        <TabsContent value="findings" className="space-y-4">
          <div className="flex gap-3 items-center flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Search findings by title..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-10 bg-zinc-900 border-zinc-800" />
            </div>
            <Select value={platform} onValueChange={(v) => setPlatform(v as any)}>
              <SelectTrigger className="w-40 bg-zinc-900 border-zinc-800"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Platforms</SelectItem>
                <SelectItem value="hackerone">HackerOne</SelectItem>
                <SelectItem value="bugcrowd">Bugcrowd</SelectItem>
                <SelectItem value="manual">Manual</SelectItem>
              </SelectContent>
            </Select>
            <Select value={severity || "all_severities"} onValueChange={(v) => setSeverity(v === "all_severities" ? "" : v)}>
              <SelectTrigger className="w-36 bg-zinc-900 border-zinc-800"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all_severities">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {findingsLoading ? (
            <div className="text-center py-12 text-muted-foreground"><Loader2 className="h-6 w-6 animate-spin mx-auto mb-2" />Loading findings...</div>
          ) : (
            <div className="space-y-2">
              {(findingsData?.findings || []).map((f: any) => (
                <Card key={f.id} className="bg-zinc-900/50 border-zinc-800 hover:border-zinc-700 transition-colors">
                  <CardContent className="py-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <Badge className={`text-xs ${SEVERITY_COLORS[f.severityRating || "none"] || SEVERITY_COLORS.none}`}>{f.severityRating || "none"}</Badge>
                          <Badge variant="outline" className="text-xs">{f.platform}</Badge>
                          {f.programHandle && <span className="text-xs text-muted-foreground">{f.programHandle}</span>}
                          {((f.cveIds as string[]) || []).length > 0 && (
                            <Badge className="bg-red-500/10 text-red-400 text-xs">{(f.cveIds as string[]).join(", ")}</Badge>
                          )}
                        </div>
                        <p className="font-medium truncate">{f.title}</p>
                        {f.summary && <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{f.summary}</p>}
                        <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground flex-wrap">
                          {f.reporterUsername && <span>by {f.reporterUsername}</span>}
                          {f.disclosedAt && <span>{new Date(f.disclosedAt).toLocaleDateString()}</span>}
                          {f.awardedAmount != null && f.awardedAmount > 0 && <span className="text-emerald-400">${Number(f.awardedAmount).toLocaleString()}</span>}
                          {f.cweId && <span className="text-purple-400">CWE: {f.cweId}</span>}
                          {f.assetIdentifier && <span className="text-cyan-400">{f.assetIdentifier}</span>}
                          {f.assetType && <span className="text-zinc-500">[{f.assetType}]</span>}
                        </div>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        {f.reportUrl && (
                          <Button variant="ghost" size="sm" asChild>
                            <a href={f.reportUrl} target="_blank" rel="noopener noreferrer"><ExternalLink className="h-4 w-4" /></a>
                          </Button>
                        )}
                        <Button variant="ghost" size="sm" className="text-red-400" onClick={() => deleteFinding.mutate({ id: f.id })}>&times;</Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
              {findingsData?.findings?.length === 0 && (
                <div className="text-center py-12 text-muted-foreground">
                  <Bug className="h-12 w-12 mx-auto mb-3 opacity-30" />
                  <p>No findings yet. Sync from HackerOne or add manually.</p>
                </div>
              )}
              {findingsData && findingsData.total > 50 && (
                <p className="text-center text-sm text-muted-foreground">Showing 50 of {findingsData.total} findings</p>
              )}
            </div>
          )}
        </TabsContent>

        {/* ─── Programs Tab ─── */}
        <TabsContent value="programs" className="space-y-4">
          <div className="flex gap-3 items-center flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Search programs..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-10 bg-zinc-900 border-zinc-800" />
            </div>
            <Button variant="outline" size="sm" onClick={() => syncPrograms.mutate({ pages: 5 })} disabled={syncPrograms.isPending}>
              <RefreshCw className={`h-4 w-4 mr-1 ${syncPrograms.isPending ? "animate-spin" : ""}`} />
              Sync H1 Programs
            </Button>
            <Button size="sm" onClick={() => setShowAddProgramDialog(true)}>
              <Plus className="h-4 w-4 mr-1" />
              Add Program
            </Button>
          </div>

          {programsLoading ? (
            <div className="text-center py-12 text-muted-foreground"><Loader2 className="h-6 w-6 animate-spin mx-auto mb-2" />Loading programs...</div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {(programsData?.programs || []).map((p: any) => (
                <Card key={p.id} className="bg-zinc-900/50 border-zinc-800 hover:border-zinc-700 transition-colors">
                  <CardContent className="pt-4 pb-3">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        {p.logoUrl ? (
                          <img src={p.logoUrl} alt="" className="h-8 w-8 rounded" />
                        ) : (
                          <div className="h-8 w-8 rounded bg-zinc-800 flex items-center justify-center"><Shield className="h-4 w-4 text-zinc-500" /></div>
                        )}
                        <div>
                          <p className="font-medium text-sm">{p.name}</p>
                          <p className="text-xs text-muted-foreground">{p.handle}</p>
                        </div>
                      </div>
                      <Badge variant="outline" className="text-xs">{p.platform}</Badge>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-muted-foreground mt-2 flex-wrap">
                      {p.state && <Badge variant={p.state === "open" ? "default" : "secondary"} className="text-xs">{p.state}</Badge>}
                      {p.submissionState && <span>{p.submissionState}</span>}
                    </div>
                    <div className="flex items-center justify-between mt-3 gap-1">
                      <div className="flex gap-1">
                        {p.url && (
                          <Button variant="ghost" size="sm" className="text-xs h-7" asChild>
                            <a href={p.url} target="_blank" rel="noopener noreferrer"><ExternalLink className="h-3 w-3 mr-1" /> View</a>
                          </Button>
                        )}
                        <Button variant="ghost" size="sm" className="text-xs h-7" onClick={() => { syncScopes.mutate({ programHandle: p.handle }); }} disabled={syncScopes.isPending}>
                          <Crosshair className="h-3 w-3 mr-1" /> Scopes
                        </Button>
                        <Button variant="ghost" size="sm" className="text-xs h-7" onClick={() => { syncWeaknesses.mutate({ programHandle: p.handle }); }} disabled={syncWeaknesses.isPending}>
                          <AlertTriangle className="h-3 w-3 mr-1" /> CWEs
                        </Button>
                      </div>
                      <Button variant="ghost" size="sm" className="text-xs h-7 text-red-400" onClick={() => deleteProgram.mutate({ id: p.id })}>
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
              {programsData?.programs?.length === 0 && (
                <div className="col-span-full text-center py-12 text-muted-foreground">
                  <Globe className="h-12 w-12 mx-auto mb-3 opacity-30" />
                  <p>No programs tracked yet. Sync from HackerOne or add manually.</p>
                </div>
              )}
            </div>
          )}
        </TabsContent>

        {/* ─── Scopes Tab ─── */}
        <TabsContent value="scopes" className="space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div>
              <p className="text-sm text-muted-foreground">
                Structured scopes define the attack surface for each bug bounty program. These map directly to your asset intelligence pipeline.
              </p>
            </div>
            <div className="flex gap-2">
              <Select value={selectedScopeProgram || "all_programs"} onValueChange={(v) => setSelectedScopeProgram(v === "all_programs" ? "" : v)}>
                <SelectTrigger className="w-48 bg-zinc-900 border-zinc-800"><SelectValue placeholder="Filter by program" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all_programs">All Programs</SelectItem>
                  {(programsData?.programs || []).map((p: any) => (
                    <SelectItem key={p.handle} value={p.handle}>{p.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            {(scopesData?.scopes || []).map((s: any) => (
              <Card key={s.id} className="bg-zinc-900/50 border-zinc-800">
                <CardContent className="py-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-3 min-w-0">
                      <Badge variant="outline" className="text-xs shrink-0">{s.assetType}</Badge>
                      <div className="min-w-0">
                        <p className="font-medium text-sm truncate">{s.assetIdentifier}</p>
                        <p className="text-xs text-muted-foreground">{s.programHandle}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {s.eligibleForBounty ? (
                        <Badge className="bg-emerald-500/20 text-emerald-400 text-xs">Bounty</Badge>
                      ) : (
                        <Badge className="bg-zinc-500/20 text-zinc-400 text-xs">No Bounty</Badge>
                      )}
                      {s.maxSeverity && s.maxSeverity !== "none" && (
                        <Badge className={`text-xs ${SEVERITY_COLORS[s.maxSeverity] || SEVERITY_COLORS.none}`}>Max: {s.maxSeverity}</Badge>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
            {(!scopesData?.scopes || scopesData.scopes.length === 0) && (
              <div className="text-center py-12 text-muted-foreground">
                <Crosshair className="h-12 w-12 mx-auto mb-3 opacity-30" />
                <p>No scopes synced yet. Go to Programs tab and click "Scopes" on a program, or run Full Sync.</p>
              </div>
            )}
            {scopesData && scopesData.total > 100 && (
              <p className="text-center text-sm text-muted-foreground">Showing 100 of {scopesData.total} scopes</p>
            )}
          </div>
        </TabsContent>

        {/* ─── CWE Taxonomy Tab ─── */}
        <TabsContent value="weaknesses" className="space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div>
              <p className="text-sm text-muted-foreground">
                CWE weakness categories reported per program. Maps to vulnerability intelligence and threat pattern analysis pipelines.
              </p>
            </div>
            <div className="flex gap-2">
              <Select value={selectedScopeProgram || "all_programs"} onValueChange={(v) => setSelectedScopeProgram(v === "all_programs" ? "" : v)}>
                <SelectTrigger className="w-48 bg-zinc-900 border-zinc-800"><SelectValue placeholder="Filter by program" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all_programs">All Programs</SelectItem>
                  {(programsData?.programs || []).map((p: any) => (
                    <SelectItem key={p.handle} value={p.handle}>{p.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            {(weaknessesData?.weaknesses || []).map((w: any) => (
              <Card key={w.id} className="bg-zinc-900/50 border-zinc-800">
                <CardContent className="py-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-3 min-w-0">
                      <Badge variant="outline" className="text-xs shrink-0">{w.cweId || "N/A"}</Badge>
                      <div className="min-w-0">
                        <p className="font-medium text-sm truncate">{w.name}</p>
                        {w.description && <p className="text-xs text-muted-foreground line-clamp-1">{w.description}</p>}
                      </div>
                    </div>
                    <span className="text-xs text-muted-foreground shrink-0">{w.programHandle}</span>
                  </div>
                </CardContent>
              </Card>
            ))}
            {(!weaknessesData?.weaknesses || weaknessesData.weaknesses.length === 0) && (
              <div className="text-center py-12 text-muted-foreground">
                <AlertTriangle className="h-12 w-12 mx-auto mb-3 opacity-30" />
                <p>No weaknesses synced yet. Go to Programs tab and click "CWEs" on a program, or run Full Sync.</p>
              </div>
            )}
            {weaknessesData && weaknessesData.total > 100 && (
              <p className="text-center text-sm text-muted-foreground">Showing 100 of {weaknessesData.total} weaknesses</p>
            )}
          </div>
        </TabsContent>

        {/* ─── Correlations Tab ─── */}
        <TabsContent value="correlations" className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Showing {correlations?.length || 0} correlations between bug bounty findings and your intelligence data
            </p>
            <Button variant="outline" size="sm" onClick={() => runCorrelation.mutate({})} disabled={runCorrelation.isPending}>
              <Zap className={`h-4 w-4 mr-1 ${runCorrelation.isPending ? "animate-spin" : ""}`} />
              {runCorrelation.isPending ? "Running..." : "Re-run Engine"}
            </Button>
          </div>

          <div className="space-y-2">
            {(correlations || []).map((c: any) => (
              <Card key={c.id} className="bg-zinc-900/50 border-zinc-800">
                <CardContent className="py-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Badge className={CORRELATION_COLORS[c.correlationType] || "bg-zinc-500/20 text-zinc-400"}>
                        {c.correlationType === "cve_match" ? "CVE" : c.correlationType === "asset_match" ? "Asset" : "CWE"}
                      </Badge>
                      <div>
                        <p className="font-medium text-sm">
                          Finding #{c.findingId} <ChevronRight className="inline h-3 w-3" /> {c.matchedEntityName}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {c.matchedEntityType} &middot; Confidence: {Math.round((c.confidenceScore || 0) * 100)}%
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-16 rounded-full overflow-hidden bg-zinc-800">
                        <div
                          className={`h-full rounded-full ${(c.confidenceScore || 0) > 0.8 ? "bg-emerald-500" : (c.confidenceScore || 0) > 0.5 ? "bg-yellow-500" : "bg-red-500"}`}
                          style={{ width: `${(c.confidenceScore || 0) * 100}%` }}
                        />
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
            {(!correlations || correlations.length === 0) && (
              <div className="text-center py-12 text-muted-foreground">
                <Link2 className="h-12 w-12 mx-auto mb-3 opacity-30" />
                <p>No correlations found. Add findings and run the correlation engine.</p>
              </div>
            )}
          </div>
        </TabsContent>

        {/* ─── Sync History Tab ─── */}
        <TabsContent value="sync" className="space-y-4">
          <div className="space-y-2">
            {(syncHistory || []).map((s: any) => (
              <Card key={s.id} className="bg-zinc-900/50 border-zinc-800">
                <CardContent className="py-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Badge variant={s.status === "completed" ? "default" : s.status === "failed" ? "destructive" : "secondary"}>
                        {s.status}
                      </Badge>
                      <div>
                        <p className="font-medium text-sm">{s.platform} / {s.syncType}</p>
                        <p className="text-xs text-muted-foreground">
                          {s.startedAt ? new Date(s.startedAt).toLocaleString() : "Unknown"}
                          {s.itemsSynced != null && ` \u00b7 ${s.itemsSynced} items`}
                        </p>
                      </div>
                    </div>
                    {s.errorMessage && (
                      <p className="text-xs text-red-400 max-w-xs truncate">{s.errorMessage}</p>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
            {(!syncHistory || syncHistory.length === 0) && (
              <div className="text-center py-12 text-muted-foreground">
                <Clock className="h-12 w-12 mx-auto mb-3 opacity-30" />
                <p>No sync history yet.</p>
              </div>
            )}
          </div>
        </TabsContent>

        {/* ─── Linked Accounts Tab ─── */}
        <TabsContent value="accounts" className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Link your bug bounty platform accounts to enable automatic syncing of findings, programs, and intelligence data.
            </p>
            <Button size="sm" onClick={() => setShowAddCredentialDialog(true)}>
              <Plus className="h-4 w-4 mr-1" />
              Link Account
            </Button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {["hackerone", "bugcrowd", "intigriti", "synack", "yeswehack"].map((plat) => {
              const linked = (credentials || []).filter((c: any) => c.platform === plat);
              const platformNames: Record<string, string> = { hackerone: "HackerOne", bugcrowd: "Bugcrowd", intigriti: "Intigriti", synack: "Synack", yeswehack: "YesWeHack" };
              const platformColors: Record<string, string> = { hackerone: "text-emerald-400 border-emerald-500/30", bugcrowd: "text-orange-400 border-orange-500/30", intigriti: "text-blue-400 border-blue-500/30", synack: "text-red-400 border-red-500/30", yeswehack: "text-yellow-400 border-yellow-500/30" };
              return (
                <Card key={plat} className={`bg-zinc-900/50 border-zinc-800 ${linked.length > 0 ? "ring-1 ring-emerald-500/20" : ""}`}>
                  <CardContent className="pt-5 pb-4">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <div className={`h-10 w-10 rounded-lg border flex items-center justify-center ${platformColors[plat] || "text-zinc-400 border-zinc-700"}`}>
                          <Bug className="h-5 w-5" />
                        </div>
                        <div>
                          <p className="font-semibold">{platformNames[plat]}</p>
                          <p className="text-xs text-muted-foreground">{linked.length > 0 ? `${linked.length} account${linked.length > 1 ? "s" : ""} linked` : "Not connected"}</p>
                        </div>
                      </div>
                      {linked.length > 0 ? <CheckCircle2 className="h-5 w-5 text-emerald-400" /> : <Unplug className="h-5 w-5 text-zinc-600" />}
                    </div>

                    {linked.map((cred: any) => (
                      <div key={cred.id} className="mt-2 p-3 bg-zinc-800/50 rounded-lg border border-zinc-700/50">
                        <div className="flex items-center justify-between mb-2">
                          <div>
                            <p className="text-sm font-medium">{cred.displayName}</p>
                            {cred.apiUsername && <p className="text-xs text-muted-foreground">User: {cred.apiUsername}</p>}
                          </div>
                          <div className="flex items-center gap-1">
                            {cred.syncStatus === "success" && <Badge className="bg-emerald-500/20 text-emerald-400 text-xs">Verified</Badge>}
                            {cred.syncStatus === "failed" && <Badge className="bg-red-500/20 text-red-400 text-xs">Failed</Badge>}
                            {cred.syncStatus === "syncing" && <Badge className="bg-blue-500/20 text-blue-400 text-xs">Syncing</Badge>}
                            {(cred.syncStatus === "idle" || !cred.syncStatus) && <Badge className="bg-zinc-500/20 text-zinc-400 text-xs">Unverified</Badge>}
                          </div>
                        </div>
                        {cred.errorMessage && <p className="text-xs text-red-400 mb-2 truncate">{cred.errorMessage}</p>}
                        {cred.lastVerifiedAt && <p className="text-xs text-muted-foreground mb-2">Last verified: {new Date(cred.lastVerifiedAt).toLocaleString()}</p>}
                        <div className="flex items-center gap-2">
                          <Button variant="outline" size="sm" className="text-xs h-7" onClick={() => verifyCredential.mutate({ id: cred.id })} disabled={verifyCredential.isPending}>
                            {verifyCredential.isPending ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <CheckCircle2 className="h-3 w-3 mr-1" />}
                            Verify
                          </Button>
                          <Button variant="outline" size="sm" className="text-xs h-7" onClick={() => toggleCredential.mutate({ id: cred.id, isActive: !cred.isActive })}>
                            {cred.isActive ? "Disable" : "Enable"}
                          </Button>
                          <Button variant="ghost" size="sm" className="text-xs h-7 text-red-400 hover:text-red-300" onClick={() => { if (confirm("Remove this credential?")) deleteCredential.mutate({ id: cred.id }); }}>
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    ))}

                    {linked.length === 0 && (
                      <Button variant="outline" size="sm" className="w-full mt-2 text-xs" onClick={() => { setNewCredential({ ...newCredential, platform: plat as any, displayName: platformNames[plat] + " Account" }); setShowAddCredentialDialog(true); }}>
                        <Key className="h-3 w-3 mr-1" />
                        Connect {platformNames[plat]}
                      </Button>
                    )}
                  </CardContent>
                </Card>
              );
            })}

            <Card className="bg-zinc-900/50 border-zinc-800 border-dashed">
              <CardContent className="pt-5 pb-4 flex flex-col items-center justify-center text-center min-h-[120px]">
                <Plus className="h-8 w-8 text-zinc-600 mb-2" />
                <p className="text-sm font-medium text-muted-foreground">Custom Platform</p>
                <p className="text-xs text-muted-foreground mb-3">Connect any platform with an API</p>
                <Button variant="outline" size="sm" className="text-xs" onClick={() => { setNewCredential({ ...newCredential, platform: "custom", displayName: "" }); setShowAddCredentialDialog(true); }}>
                  Add Custom
                </Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
        {/* ─── LLM Training Tab ─── */}
        <TabsContent value="training" className="space-y-4">
          {/* Automated Pipeline Status */}
          <Card className="bg-emerald-950/30 border-emerald-500/20">
            <CardContent className="py-3 px-4">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-3">
                  <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                  <div>
                    <p className="text-sm font-medium text-emerald-300">Automated Intel Pipeline Active</p>
                    <p className="text-xs text-emerald-400/60">Runs every 6h (04:00, 10:00, 16:00, 22:00 UTC) — syncs H1 hacktivity, extracts training data, enriches samples, generates ScanForge templates, and runs cross-correlation</p>
                  </div>
                </div>
                <Button size="sm" variant="outline" className="border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10" onClick={() => runIntelPipeline.mutate()} disabled={runIntelPipeline.isPending}>
                  {runIntelPipeline.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Activity className="h-4 w-4 mr-1" />}
                  {runIntelPipeline.isPending ? "Running..." : "Run Now"}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Pipeline Controls */}
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" onClick={() => extractH1.mutate({ limit: 100 })} disabled={extractH1.isPending}>
              {extractH1.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Bug className="h-4 w-4 mr-1" />}
              Extract from HackerOne
            </Button>
            <Button size="sm" variant="outline" onClick={() => extractEngagement.mutate({ limit: 200 })} disabled={extractEngagement.isPending}>
              {extractEngagement.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Crosshair className="h-4 w-4 mr-1" />}
              Extract from Engagements
            </Button>
            <Button size="sm" variant="outline" onClick={() => enrichTraining.mutate({ limit: 20 })} disabled={enrichTraining.isPending}>
              {enrichTraining.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Sparkles className="h-4 w-4 mr-1" />}
              Enrich with LLM
            </Button>
            <Button size="sm" variant="outline" onClick={() => exportJSONL.mutate({ minQuality: 0.3 })} disabled={exportJSONL.isPending}>
              {exportJSONL.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Download className="h-4 w-4 mr-1" />}
              Export JSONL
            </Button>
          </div>

          {/* Training Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="pt-4 pb-3 text-center">
                <p className="text-2xl font-bold text-emerald-400">{trainingStats?.totalSamples || 0}</p>
                <p className="text-xs text-muted-foreground">Total Samples</p>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="pt-4 pb-3 text-center">
                <p className="text-2xl font-bold text-cyan-400">{trainingStats?.hackeroneSources || 0}</p>
                <p className="text-xs text-muted-foreground">HackerOne</p>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="pt-4 pb-3 text-center">
                <p className="text-2xl font-bold text-orange-400">{trainingStats?.engagementSources || 0}</p>
                <p className="text-xs text-muted-foreground">Engagements</p>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="pt-4 pb-3 text-center">
                <p className="text-2xl font-bold text-red-400">{trainingStats?.novelFindings || 0}</p>
                <p className="text-xs text-muted-foreground">Novel Findings</p>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="pt-4 pb-3 text-center">
                <p className="text-2xl font-bold text-yellow-400">{typeof trainingStats?.avgQuality === 'number' ? (trainingStats.avgQuality * 100).toFixed(0) : '0'}%</p>
                <p className="text-xs text-muted-foreground">Avg Quality</p>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="pt-4 pb-3 text-center">
                <p className="text-2xl font-bold text-purple-400">{trainingStats?.byEnrichmentStatus?.enriched || 0}</p>
                <p className="text-xs text-muted-foreground">Enriched</p>
              </CardContent>
            </Card>
          </div>

          {/* Category Breakdown */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <BookOpen className="h-4 w-4 text-emerald-400" />
                  Training Categories
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {Object.entries(trainingStats?.byCategory || {}).map(([cat, count]) => {
                    const catColors: Record<string, string> = { vuln_pattern: "bg-blue-500", exploit_chain: "bg-red-500", report_template: "bg-green-500", scope_recon: "bg-cyan-500", cwe_analysis: "bg-purple-500", bounty_strategy: "bg-yellow-500", novel_finding: "bg-orange-500" };
                    const total = trainingStats?.totalSamples || 1;
                    return (
                      <div key={cat} className="flex items-center gap-3">
                        <span className="text-xs text-muted-foreground w-28 truncate">{cat.replace(/_/g, ' ')}</span>
                        <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                          <div className={`h-full rounded-full ${catColors[cat] || 'bg-zinc-500'}`} style={{ width: `${Math.max(2, (Number(count) / Number(total)) * 100)}%` }} />
                        </div>
                        <span className="text-xs font-mono text-muted-foreground w-8 text-right">{String(count)}</span>
                      </div>
                    );
                  })}
                  {Object.keys(trainingStats?.byCategory || {}).length === 0 && <p className="text-xs text-muted-foreground text-center py-4">No training data yet. Extract from HackerOne or engagements to begin.</p>}
                </div>
              </CardContent>
            </Card>

            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <FlaskConical className="h-4 w-4 text-purple-400" />
                  Enrichment Pipeline
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {Object.entries(trainingStats?.byEnrichmentStatus || {}).map(([status, count]) => {
                    const statusColors: Record<string, string> = { raw: "text-zinc-400", enriched: "text-emerald-400", reviewed: "text-blue-400", exported: "text-yellow-400" };
                    const statusIcons: Record<string, string> = { raw: "○", enriched: "●", reviewed: "✔", exported: "⬆" };
                    return (
                      <div key={status} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className={statusColors[status] || 'text-zinc-400'}>{statusIcons[status] || '○'}</span>
                          <span className="text-sm capitalize">{status}</span>
                        </div>
                        <Badge variant="outline" className="text-xs">{String(count)}</Badge>
                      </div>
                    );
                  })}
                  {Object.keys(trainingStats?.byEnrichmentStatus || {}).length === 0 && <p className="text-xs text-muted-foreground text-center py-4">Pipeline empty</p>}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Bounty ROI Analytics */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <DollarSign className="h-4 w-4 text-yellow-400" />
                Bounty ROI — Highest-Paying CWEs
              </CardTitle>
              <CardDescription className="text-xs">Which vulnerability classes earn the most on bug bounty programs</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-zinc-800">
                      <th className="text-left py-2 px-2 text-muted-foreground">CWE</th>
                      <th className="text-right py-2 px-2 text-muted-foreground">Count</th>
                      <th className="text-right py-2 px-2 text-muted-foreground">Avg Bounty</th>
                      <th className="text-right py-2 px-2 text-muted-foreground">Max Bounty</th>
                      <th className="text-right py-2 px-2 text-muted-foreground">Total</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(bountyROI?.byCwe || []).map((row: any) => (
                      <tr key={row.cweId} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                        <td className="py-2 px-2 font-mono text-cyan-400">{row.cweId}</td>
                        <td className="py-2 px-2 text-right">{row.count}</td>
                        <td className="py-2 px-2 text-right text-emerald-400">${Number(row.avgBounty).toLocaleString(undefined, { maximumFractionDigits: 0 })}</td>
                        <td className="py-2 px-2 text-right text-yellow-400">${Number(row.maxBounty).toLocaleString(undefined, { maximumFractionDigits: 0 })}</td>
                        <td className="py-2 px-2 text-right font-medium">${Number(row.totalBounty).toLocaleString(undefined, { maximumFractionDigits: 0 })}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {(!bountyROI?.byCwe || bountyROI.byCwe.length === 0) && <p className="text-xs text-muted-foreground text-center py-4">Sync HackerOne findings first to see ROI analytics</p>}
              </div>
            </CardContent>
          </Card>

          {/* Top Programs by Payout */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-emerald-400" />
                Top Programs by Average Payout
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-zinc-800">
                      <th className="text-left py-2 px-2 text-muted-foreground">Program</th>
                      <th className="text-right py-2 px-2 text-muted-foreground">Findings</th>
                      <th className="text-right py-2 px-2 text-muted-foreground">Avg Bounty</th>
                      <th className="text-right py-2 px-2 text-muted-foreground">Total</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(bountyROI?.byProgram || []).map((row: any) => (
                      <tr key={row.programHandle} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                        <td className="py-2 px-2">{row.programName || row.programHandle}</td>
                        <td className="py-2 px-2 text-right">{row.count}</td>
                        <td className="py-2 px-2 text-right text-emerald-400">${Number(row.avgBounty).toLocaleString(undefined, { maximumFractionDigits: 0 })}</td>
                        <td className="py-2 px-2 text-right font-medium">${Number(row.totalBounty).toLocaleString(undefined, { maximumFractionDigits: 0 })}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {(!bountyROI?.byProgram || bountyROI.byProgram.length === 0) && <p className="text-xs text-muted-foreground text-center py-4">No program data yet</p>}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ─── ScanForge Bridge Tab ─── */}
        <TabsContent value="scanforge-bridge" className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" onClick={() => generateTemplates.mutate({ limit: 25 })} disabled={generateTemplates.isPending}>
              {generateTemplates.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <ArrowRightLeft className="h-4 w-4 mr-1" />}
              Generate Templates from Findings
            </Button>
            <p className="text-xs text-muted-foreground">Converts disclosed HackerOne vulnerabilities into ScanForge detection templates via LLM analysis</p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="pt-4 pb-3 text-center">
                <p className="text-2xl font-bold text-cyan-400">{bridgeStats?.totalFindings || 0}</p>
                <p className="text-xs text-muted-foreground">H1 Findings</p>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="pt-4 pb-3 text-center">
                <p className="text-2xl font-bold text-emerald-400">{bridgeStats?.templatesGenerated || 0}</p>
                <p className="text-xs text-muted-foreground">Templates Generated</p>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="pt-4 pb-3 text-center">
                <p className="text-2xl font-bold text-yellow-400">{bridgeStats?.templatesByStatus?.draft || 0}</p>
                <p className="text-xs text-muted-foreground">Drafts</p>
              </CardContent>
            </Card>
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="pt-4 pb-3 text-center">
                <p className="text-2xl font-bold text-purple-400">{bridgeStats?.templatesByStatus?.promoted || 0}</p>
                <p className="text-xs text-muted-foreground">Promoted</p>
              </CardContent>
            </Card>
          </div>

          {/* Recent Templates */}
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Zap className="h-4 w-4 text-yellow-400" />
                Recent Bug Bounty → ScanForge Templates
              </CardTitle>
              <CardDescription className="text-xs">Detection templates auto-generated from disclosed vulnerabilities</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {(bridgeStats?.recentTemplates || []).map((t: any) => (
                  <div key={t.templateId} className="flex items-center justify-between p-3 bg-zinc-800/50 rounded-lg border border-zinc-700/50">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{t.name}</p>
                      <p className="text-xs text-muted-foreground font-mono">{t.templateId}</p>
                    </div>
                    <div className="flex items-center gap-2 ml-3">
                      <Badge variant="outline" className={`text-xs ${t.status === 'promoted' ? 'text-emerald-400 border-emerald-500/30' : t.status === 'review' ? 'text-blue-400 border-blue-500/30' : 'text-zinc-400 border-zinc-600'}`}>{t.status}</Badge>
                      <span className="text-xs text-muted-foreground">{t.createdAt ? new Date(t.createdAt).toLocaleDateString() : ''}</span>
                    </div>
                  </div>
                ))}
                {(!bridgeStats?.recentTemplates || bridgeStats.recentTemplates.length === 0) && (
                  <p className="text-xs text-muted-foreground text-center py-6">No templates generated yet. Click "Generate Templates from Findings" to convert disclosed HackerOne vulnerabilities into ScanForge detection templates.</p>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* ─── Dialogs ─── */}

      {/* Add Credential Dialog */}
      <Dialog open={showAddCredentialDialog} onOpenChange={setShowAddCredentialDialog}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><Key className="h-5 w-5 text-emerald-400" />Link Platform Account</DialogTitle>
            <DialogDescription>Enter your API credentials to connect your bug bounty platform account. Credentials are encrypted at rest.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Platform</Label>
              <Select value={newCredential.platform} onValueChange={(v) => setNewCredential({ ...newCredential, platform: v as any })}>
                <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="hackerone">HackerOne</SelectItem>
                  <SelectItem value="bugcrowd">Bugcrowd</SelectItem>
                  <SelectItem value="intigriti">Intigriti</SelectItem>
                  <SelectItem value="synack">Synack</SelectItem>
                  <SelectItem value="yeswehack">YesWeHack</SelectItem>
                  <SelectItem value="custom">Custom Platform</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Display Name</Label>
              <Input value={newCredential.displayName} onChange={(e) => setNewCredential({ ...newCredential, displayName: e.target.value })} placeholder="My HackerOne Account" className="bg-zinc-800 border-zinc-700 mt-1" />
            </div>
            {(newCredential.platform === "hackerone" || newCredential.platform === "custom") && (
              <div>
                <Label>API Username / Identifier</Label>
                <Input value={newCredential.apiUsername} onChange={(e) => setNewCredential({ ...newCredential, apiUsername: e.target.value })} placeholder={newCredential.platform === "hackerone" ? "Your HackerOne API identifier" : "Username or identifier"} className="bg-zinc-800 border-zinc-700 mt-1" />
                {newCredential.platform === "hackerone" && <p className="text-xs text-muted-foreground mt-1">Found under Settings &rarr; API Token in HackerOne</p>}
              </div>
            )}
            <div>
              <Label>API Key / Token</Label>
              <div className="relative">
                <Input type={showApiKey ? "text" : "password"} value={newCredential.apiKey} onChange={(e) => setNewCredential({ ...newCredential, apiKey: e.target.value })} placeholder="Enter your API key" className="bg-zinc-800 border-zinc-700 mt-1 pr-10" />
                <Button type="button" variant="ghost" size="sm" className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 p-0" onClick={() => setShowApiKey(!showApiKey)}>
                  {showApiKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                </Button>
              </div>
            </div>
            {newCredential.platform === "custom" && (
              <div>
                <Label>Base URL (optional)</Label>
                <Input value={newCredential.baseUrl} onChange={(e) => setNewCredential({ ...newCredential, baseUrl: e.target.value })} placeholder="https://api.example.com" className="bg-zinc-800 border-zinc-700 mt-1" />
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddCredentialDialog(false)}>Cancel</Button>
            <Button onClick={() => addCredential.mutate({ platform: newCredential.platform, displayName: newCredential.displayName, apiUsername: newCredential.apiUsername || undefined, apiKey: newCredential.apiKey, baseUrl: newCredential.baseUrl || undefined })} disabled={addCredential.isPending || !newCredential.displayName || !newCredential.apiKey}>
              {addCredential.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Key className="h-4 w-4 mr-1" />}
              {addCredential.isPending ? "Saving..." : "Save & Connect"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Sync Dialog */}
      <Dialog open={showSyncDialog} onOpenChange={setShowSyncDialog}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle>Custom HackerOne Sync</DialogTitle>
            <DialogDescription>Pull specific data from HackerOne with custom filters</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Hacktivity Query (Lucene syntax)</Label>
              <Input value={syncQuery} onChange={(e) => setSyncQuery(e.target.value)} className="bg-zinc-800 border-zinc-700 mt-1" placeholder="severity_rating:critical OR severity_rating:high" />
              <p className="text-xs text-muted-foreground mt-1">Filters: severity_rating, asset_type, cwe, cve_ids, reporter, team</p>
            </div>
            <div>
              <Label>Pages to Fetch (25 items/page)</Label>
              <Input type="number" value={syncPages} onChange={(e) => setSyncPages(Number(e.target.value))} min={1} max={10} className="bg-zinc-800 border-zinc-700 mt-1" />
            </div>
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => syncPrograms.mutate({ pages: syncPages })} disabled={syncPrograms.isPending}>
              {syncPrograms.isPending ? "Syncing..." : "Sync Programs"}
            </Button>
            <Button onClick={() => { syncHacktivity.mutate({ queryString: syncQuery, pages: syncPages }); setShowSyncDialog(false); }} disabled={syncHacktivity.isPending}>
              {syncHacktivity.isPending ? "Syncing..." : "Sync Hacktivity"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Add Program Dialog */}
      <Dialog open={showAddProgramDialog} onOpenChange={setShowAddProgramDialog}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader><DialogTitle>Add Bug Bounty Program</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div>
              <Label>Platform</Label>
              <Select value={newProgram.platform} onValueChange={(v) => setNewProgram({ ...newProgram, platform: v as any })}>
                <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="hackerone">HackerOne</SelectItem>
                  <SelectItem value="bugcrowd">Bugcrowd</SelectItem>
                  <SelectItem value="manual">Manual</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div><Label>Handle / Slug</Label><Input value={newProgram.handle} onChange={(e) => setNewProgram({ ...newProgram, handle: e.target.value })} className="bg-zinc-800 border-zinc-700 mt-1" /></div>
            <div><Label>Program Name</Label><Input value={newProgram.name} onChange={(e) => setNewProgram({ ...newProgram, name: e.target.value })} className="bg-zinc-800 border-zinc-700 mt-1" /></div>
            <div><Label>URL</Label><Input value={newProgram.url} onChange={(e) => setNewProgram({ ...newProgram, url: e.target.value })} className="bg-zinc-800 border-zinc-700 mt-1" /></div>
          </div>
          <DialogFooter>
            <Button onClick={() => addProgram.mutate(newProgram)} disabled={addProgram.isPending || !newProgram.handle || !newProgram.name}>
              {addProgram.isPending ? "Adding..." : "Add Program"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Add Finding Dialog */}
      <Dialog open={showAddFindingDialog} onOpenChange={setShowAddFindingDialog}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader><DialogTitle>Add Bug Bounty Finding</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div><Label>Title</Label><Input value={newFinding.title} onChange={(e) => setNewFinding({ ...newFinding, title: e.target.value })} className="bg-zinc-800 border-zinc-700 mt-1" /></div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>Severity</Label>
                <Select value={newFinding.severityRating} onValueChange={(v) => setNewFinding({ ...newFinding, severityRating: v as any })}>
                  <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="none">None</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div><Label>CWE ID</Label><Input value={newFinding.cweId} onChange={(e) => setNewFinding({ ...newFinding, cweId: e.target.value })} placeholder="CWE-79" className="bg-zinc-800 border-zinc-700 mt-1" /></div>
            </div>
            <div><Label>CVE IDs (comma-separated)</Label><Input value={newFinding.cveIds} onChange={(e) => setNewFinding({ ...newFinding, cveIds: e.target.value })} placeholder="CVE-2024-1234, CVE-2024-5678" className="bg-zinc-800 border-zinc-700 mt-1" /></div>
            <div><Label>Asset Identifier (domain/URL)</Label><Input value={newFinding.assetIdentifier} onChange={(e) => setNewFinding({ ...newFinding, assetIdentifier: e.target.value })} placeholder="api.example.com" className="bg-zinc-800 border-zinc-700 mt-1" /></div>
            <div><Label>Summary</Label><Input value={newFinding.summary} onChange={(e) => setNewFinding({ ...newFinding, summary: e.target.value })} className="bg-zinc-800 border-zinc-700 mt-1" /></div>
          </div>
          <DialogFooter>
            <Button onClick={() => addFinding.mutate({ ...newFinding, cveIds: newFinding.cveIds ? newFinding.cveIds.split(",").map((s) => s.trim()).filter(Boolean) : undefined })} disabled={addFinding.isPending || !newFinding.title}>
              {addFinding.isPending ? "Adding..." : "Add Finding"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
    </AppShell>
  );
}
