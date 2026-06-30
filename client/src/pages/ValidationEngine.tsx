import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { toast } from "sonner";
import {
  FlaskConical,
  Play,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Target,
  Crosshair,
  Server,
  RefreshCw,
  Eye,
  ChevronDown,
  ChevronRight,
  FileText,
  Activity,
  Loader2,
  Ban,
  HelpCircle,
  Fingerprint,
  Network,
  TrendingUp,
  Gauge,
  Scan,
  ShieldOff,
} from "lucide-react";
import { exportToCsv, exportToPdf } from "@/lib/export-utils";
import ROEWarningBanner from "@/components/ROEWarningBanner";
import AppShell from "@/components/AppShell";

// ─── Status helpers ─────────────────────────────────────────────────────────
function statusBadge(status: string) {
  const map: Record<string, { variant: "default" | "secondary" | "destructive" | "outline"; icon: React.ReactNode; label: string }> = {
    validated: { variant: "destructive", icon: <ShieldAlert className="w-3 h-3" />, label: "Exploitable" },
    not_vulnerable: { variant: "default", icon: <ShieldCheck className="w-3 h-3" />, label: "Not Vulnerable" },
    inconclusive: { variant: "secondary", icon: <HelpCircle className="w-3 h-3" />, label: "Inconclusive" },
    error: { variant: "outline", icon: <XCircle className="w-3 h-3" />, label: "Error" },
    skipped: { variant: "outline", icon: <Ban className="w-3 h-3" />, label: "Skipped" },
    pending: { variant: "secondary", icon: <Clock className="w-3 h-3" />, label: "Pending" },
    running: { variant: "secondary", icon: <Loader2 className="w-3 h-3 animate-spin" />, label: "Running" },
    approved_pending: { variant: "outline", icon: <Eye className="w-3 h-3" />, label: "Awaiting Approval" },
  };
  const s = map[status] || { variant: "outline" as const, icon: <HelpCircle className="w-3 h-3" />, label: status };
  return (
    <Badge variant={s.variant} className="gap-1 text-xs">
      {s.icon} {s.label}
    </Badge>
  );
}

function runStatusBadge(status: string) {
  const map: Record<string, { color: string; icon: React.ReactNode; label: string }> = {
    pending: { color: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20", icon: <Clock className="w-3.5 h-3.5" />, label: "Pending" },
    running: { color: "bg-blue-500/10 text-blue-500 border-blue-500/20", icon: <Loader2 className="w-3.5 h-3.5 animate-spin" />, label: "Running" },
    completed: { color: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20", icon: <CheckCircle2 className="w-3.5 h-3.5" />, label: "Completed" },
    failed: { color: "bg-red-500/10 text-red-500 border-red-500/20", icon: <XCircle className="w-3.5 h-3.5" />, label: "Failed" },
    cancelled: { color: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20", icon: <Ban className="w-3.5 h-3.5" />, label: "Cancelled" },
  };
  const s = map[status] || { color: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20", icon: <HelpCircle className="w-3.5 h-3.5" />, label: status };
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${s.color}`}>
      {s.icon} {s.label}
    </span>
  );
}

function modeBadge(mode: string) {
  const map: Record<string, { color: string; label: string }> = {
    check_only: { color: "bg-sky-500/10 text-sky-400 border-sky-500/20", label: "Check Only" },
    auxiliary_scan: { color: "bg-amber-500/10 text-amber-400 border-amber-500/20", label: "Auxiliary Scan" },
    safe_exploit: { color: "bg-red-500/10 text-red-400 border-red-500/20", label: "Safe Exploit" },
  };
  const s = map[mode] || { color: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20", label: mode };
  return <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${s.color}`}>{s.label}</span>;
}

// ─── Main Component ─────────────────────────────────────────────────────────
export default function ValidationEngine() {
  const [activeTab, setActiveTab] = useState("launch");
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [selectedMsfServer, setSelectedMsfServer] = useState<string>("");
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);
  const [mode, setMode] = useState<"check_only" | "auxiliary_scan" | "safe_exploit">("check_only");
  const [maxCandidates, setMaxCandidates] = useState(10);
  const [timeout, setTimeout] = useState(60);
  const [requireApproval, setRequireApproval] = useState(true);
  const [expandedResult, setExpandedResult] = useState<number | null>(null);

  // Data queries
  const scansQuery = trpc.domainIntel.listScans.useQuery();
  const msfServersQuery = trpc.metasploit.listServers.useQuery();
  const completedScans = useMemo(() =>
    (scansQuery.data || []).filter((s: any) => s.status === "completed" || s.status === "scan_complete"),
    [scansQuery.data]
  );

  const candidatesQuery = trpc.validation.getCandidates.useQuery(
    { scanId: Number(selectedScanId), maxCandidates },
    { enabled: !!selectedScanId }
  );

  const runsQuery = trpc.validation.listRuns.useQuery(
    { scanId: selectedScanId ? Number(selectedScanId) : undefined, limit: 20 },
    { enabled: true }
  );

  const runDetailQuery = trpc.validation.getRun.useQuery(
    { runId: selectedRunId! },
    { enabled: !!selectedRunId, refetchInterval: (data) => data?.state?.data?.run?.status === "running" ? 3000 : false }
  );

  // Mutations
  const startRunMutation = trpc.validation.startRun.useMutation({
    onSuccess: (data) => {
      toast.success(`Run #${data.runId} launched with ${data.totalCandidates} candidates in ${data.mode} mode.`);
      setSelectedRunId(data.runId);
      setActiveTab("results");
      runsQuery.refetch();
    },
    onError: (err) => {
      toast.error(`Failed to start: ${err.message}`);
    },
  });

  const cancelRunMutation = trpc.validation.cancelRun.useMutation({
    onSuccess: () => {
      toast.success("Run Cancelled");
      runDetailQuery.refetch();
      runsQuery.refetch();
    },
  });

  const approveMutation = trpc.validation.approveCandidate.useMutation({
    onSuccess: () => {
      toast.success("Candidate Approved");
      runDetailQuery.refetch();
    },
  });

  const handleStartRun = () => {
    if (!selectedScanId || !selectedMsfServer) {
      toast.error("Select a scan and exploit server first.");
      return;
    }
    startRunMutation.mutate({
      scanId: Number(selectedScanId),
      msfServerId: Number(selectedMsfServer),
      mode,
      maxCandidates,
      timeoutPerCandidate: timeout,
      requireApproval,
    });
  };

  const runData = runDetailQuery.data;
  const run = runData?.run;
  const results = runData?.results || [];

  return (
    <AppShell activePath="/validation-engine">
      <div className="space-y-6">
      {/* ROE Warning Banner */}
      <ROEWarningBanner riskTier="orange" operationName="Vulnerability Validation" />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <FlaskConical className="w-6 h-6 text-purple-400" />
            Autonomous Validation Engine
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Safe, non-destructive exploitation validation of discovered vulnerabilities. Targets KEV-confirmed CVEs with known exploit modules.
          </p>
        </div>
        {results.length > 0 && (
          <Button variant="outline" size="sm" onClick={() => {
            const rows = results.map((r: any) => ({
              CVE: r.validationCveId || r.cveId,
              Host: r.validationHostname || r.hostname,
              Module: r.validationMsfModule || r.msfModule || "N/A",
              Status: r.status || r.validationResultStatus,
              Exploitable: r.exploitable ? "Yes" : "No",
              "Score Δ": r.scoreAdjustment || 0,
              Duration: r.validationDurationMs ? `${r.validationDurationMs}ms` : "N/A",
            }));
            const cols = Object.keys(rows[0] || {}).map(k => ({ header: k, accessor: (r: any) => String(r[k] ?? "") }));
            exportToCsv(`validation-run-${selectedRunId}`, cols, rows);
            toast.success("Exported CSV");
          }}>
            <FileText className="w-4 h-4 mr-1" /> Export CSV
          </Button>
        )}
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-zinc-900/50 border border-zinc-800">
          <TabsTrigger value="launch" className="gap-1.5"><Play className="w-3.5 h-3.5" /> Launch</TabsTrigger>
          <TabsTrigger value="results" className="gap-1.5"><Target className="w-3.5 h-3.5" /> Results</TabsTrigger>
          <TabsTrigger value="preflight" className="gap-1.5"><Scan className="w-3.5 h-3.5" /> Pre-Flight</TabsTrigger>
          <TabsTrigger value="accuracy" className="gap-1.5"><Gauge className="w-3.5 h-3.5" /> Accuracy</TabsTrigger>
          <TabsTrigger value="history" className="gap-1.5"><Activity className="w-3.5 h-3.5" /> History</TabsTrigger>
        </TabsList>

        {/* ─── Launch Tab ──────────────────────────────────────────────────── */}
        <TabsContent value="launch" className="space-y-4 mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Configuration Panel */}
            <Card className="lg:col-span-1 bg-zinc-950/60 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Server className="w-4 h-4 text-blue-400" /> Run Configuration
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Scan Selector */}
                <div className="space-y-1.5">
                  <Label className="text-xs text-muted-foreground">Target Scan</Label>
                  <Select value={selectedScanId} onValueChange={setSelectedScanId}>
                    <SelectTrigger className="bg-zinc-900 border-zinc-700">
                      <SelectValue placeholder="Select a completed scan..." />
                    </SelectTrigger>
                    <SelectContent>
                      {completedScans.map((s: any) => (
                        <SelectItem key={s.id} value={String(s.id)}>
                          #{s.id} — {s.targetDomain || s.target} ({s.totalAssets || 0} assets)
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                {/* Exploit Server Selector */}
                <div className="space-y-1.5">
                  <Label className="text-xs text-muted-foreground">C2 Server</Label>
                  <Select value={selectedMsfServer} onValueChange={setSelectedMsfServer}>
                    <SelectTrigger className="bg-zinc-900 border-zinc-700">
                      <SelectValue placeholder="Select exploit server..." />
                    </SelectTrigger>
                    <SelectContent>
                      {(msfServersQuery.data || []).map((s: any) => (
                        <SelectItem key={s.id} value={String(s.id)}>
                          {s.name || s.host} {s.status === "online" ? "🟢" : "🔴"}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <Separator className="bg-zinc-800" />

                {/* Mode Selector */}
                <div className="space-y-1.5">
                  <Label className="text-xs text-muted-foreground">Validation Mode</Label>
                  <Select value={mode} onValueChange={(v) => setMode(v as any)}>
                    <SelectTrigger className="bg-zinc-900 border-zinc-700">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="check_only">Check Only (safest)</SelectItem>
                      <SelectItem value="auxiliary_scan">Auxiliary Scan</SelectItem>
                      <SelectItem value="safe_exploit">Safe Exploit</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-[10px] text-muted-foreground">
                    {mode === "check_only" && "Uses exploit 'check' command — no payload execution. Lowest risk."}
                    {mode === "auxiliary_scan" && "Runs auxiliary scanner modules — may trigger IDS. Medium risk."}
                    {mode === "safe_exploit" && "Attempts exploitation with benign payloads. Requires approval per candidate."}
                  </p>
                </div>

                {/* Max Candidates */}
                <div className="space-y-1.5">
                  <Label className="text-xs text-muted-foreground">Max Candidates: {maxCandidates}</Label>
                  <Slider
                    value={[maxCandidates]}
                    onValueChange={([v]) => setMaxCandidates(v)}
                    min={1}
                    max={50}
                    step={1}
                    className="py-2"
                  />
                </div>

                {/* Timeout */}
                <div className="space-y-1.5">
                  <Label className="text-xs text-muted-foreground">Timeout per Candidate: {timeout}s</Label>
                  <Slider
                    value={[timeout]}
                    onValueChange={([v]) => setTimeout(v)}
                    min={10}
                    max={300}
                    step={10}
                    className="py-2"
                  />
                </div>

                {/* Require Approval */}
                <div className="flex items-center justify-between">
                  <Label className="text-xs text-muted-foreground">Require Approval (safe_exploit)</Label>
                  <Switch checked={requireApproval} onCheckedChange={setRequireApproval} />
                </div>

                <Separator className="bg-zinc-800" />

                <Button
                  className="w-full bg-purple-600 hover:bg-purple-700"
                  onClick={handleStartRun}
                  disabled={!selectedScanId || !selectedMsfServer || startRunMutation.isPending}
                >
                  {startRunMutation.isPending ? (
                    <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Starting...</>
                  ) : (
                    <><FlaskConical className="w-4 h-4 mr-2" /> Launch Validation</>
                  )}
                </Button>
              </CardContent>
            </Card>

            {/* Candidate Preview */}
            <Card className="lg:col-span-2 bg-zinc-950/60 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Crosshair className="w-4 h-4 text-amber-400" /> Candidate Preview
                  {candidatesQuery.data && (
                    <Badge variant="secondary" className="ml-2 text-xs">
                      {candidatesQuery.data.candidates.length} candidates from {candidatesQuery.data.totalAssets} assets
                    </Badge>
                  )}
                </CardTitle>
                <CardDescription className="text-xs">
                  Highest-confidence targets ranked by KEV confirmation, CVSS score, and exploit module availability.
                </CardDescription>
              </CardHeader>
              <CardContent>
                {!selectedScanId ? (
                  <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                    <Target className="w-10 h-10 mb-3 opacity-30" />
                    <p className="text-sm">Select a scan to preview validation candidates</p>
                  </div>
                ) : candidatesQuery.isLoading ? (
                  <div className="flex items-center justify-center py-12">
                    <Loader2 className="w-6 h-6 animate-spin text-purple-400" />
                  </div>
                ) : candidatesQuery.data?.candidates.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                    <ShieldCheck className="w-10 h-10 mb-3 opacity-30" />
                    <p className="text-sm">No validation candidates found</p>
                    <p className="text-xs mt-1">This scan has no assets with KEV-confirmed CVEs or known exploit modules.</p>
                  </div>
                ) : (
                  <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
                    {candidatesQuery.data?.candidates.map((c: any, i: number) => (
                      <div
                        key={`${c.assetId}-${c.cveId}`}
                        className="flex items-center gap-3 p-3 rounded-lg bg-zinc-900/50 border border-zinc-800 hover:border-zinc-700 transition-colors"
                      >
                        <div className="flex items-center justify-center w-7 h-7 rounded-full bg-purple-500/10 text-purple-400 text-xs font-bold">
                          {i + 1}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-mono font-medium truncate">{c.hostname}</span>
                            <Badge variant="outline" className="text-[10px] shrink-0">{c.cveId}</Badge>
                            {c.isKev && <Badge className="bg-red-500/10 text-red-400 border-red-500/20 text-[10px]">KEV</Badge>}
                          </div>
                          <div className="flex items-center gap-2 mt-1 text-[10px] text-muted-foreground">
                            <span>CVSS {c.cvssScore?.toFixed(1) || "N/A"}</span>
                            <span>·</span>
                            <span className="font-mono truncate max-w-[200px]">{c.msfModule || "No exploit module"}</span>
                            <span>·</span>
                            <span>Risk: {c.currentRiskScore?.toFixed(0) || "?"}</span>
                          </div>
                        </div>
                        <div className="text-right shrink-0">
                          <div className="text-xs font-medium text-amber-400">{c.priorityScore?.toFixed(0) || "?"}</div>
                          <div className="text-[10px] text-muted-foreground">priority</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ─── Results Tab ─────────────────────────────────────────────────── */}
        <TabsContent value="results" className="space-y-4 mt-4">
          {!selectedRunId ? (
            <Card className="bg-zinc-950/60 border-zinc-800">
              <CardContent className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <FlaskConical className="w-12 h-12 mb-4 opacity-20" />
                <p className="text-sm">No validation run selected</p>
                <p className="text-xs mt-1">Launch a new run or select one from History.</p>
              </CardContent>
            </Card>
          ) : runDetailQuery.isLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="w-8 h-8 animate-spin text-purple-400" />
            </div>
          ) : run ? (
            <>
              {/* Run Summary */}
              <Card className="bg-zinc-950/60 border-zinc-800">
                <CardContent className="pt-5">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <h2 className="text-lg font-semibold">Run #{run.id}</h2>
                      {runStatusBadge(run.status)}
                      {modeBadge(run.mode)}
                    </div>
                    <div className="flex items-center gap-2">
                      {run.status === "running" && (
                        <Button variant="outline" size="sm" onClick={() => cancelRunMutation.mutate({ runId: run.id })}>
                          <Ban className="w-3.5 h-3.5 mr-1" /> Cancel
                        </Button>
                      )}
                      <Button variant="ghost" size="sm" onClick={() => runDetailQuery.refetch()}>
                        <RefreshCw className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </div>

                  {/* Progress bar for running */}
                  {run.status === "running" && (
                    <div className="mb-4">
                      <div className="flex justify-between text-xs text-muted-foreground mb-1">
                        <span>Progress</span>
                        <span>{results.length} / {run.totalCandidates}</span>
                      </div>
                      <Progress value={(results.length / run.totalCandidates) * 100} className="h-2" />
                    </div>
                  )}

                  {/* Summary stats */}
                  <div className="grid grid-cols-2 sm:grid-cols-6 gap-3">
                    <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold text-purple-400">{run.totalCandidates}</div>
                      <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Total</div>
                    </div>
                    <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold text-red-400">{run.validated || 0}</div>
                      <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Exploitable</div>
                    </div>
                    <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold text-emerald-400">{run.notVulnerable || 0}</div>
                      <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Not Vuln</div>
                    </div>
                    <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold text-amber-400">{run.inconclusive || 0}</div>
                      <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Inconclusive</div>
                    </div>
                    <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold text-zinc-400">{run.errors || 0}</div>
                      <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Errors</div>
                    </div>
                    <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold text-blue-400">{run.avgScoreAdjustment?.toFixed(1) || "0"}</div>
                      <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Avg Δ Score</div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Individual Results */}
              <div className="space-y-2">
                {results.map((r: any) => {
                  const isExpanded = expandedResult === r.id;
                  const cve = r.validationCveId || r.cveId;
                  const host = r.validationHostname || r.hostname;
                  const mod = r.validationMsfModule || r.msfModule;
                  const st = r.validationResultStatus || r.status;
                  const evidence = r.validationEvidence || r.evidence;

                  return (
                    <Card key={r.id} className={`bg-zinc-950/60 border-zinc-800 ${r.exploitable ? "border-l-2 border-l-red-500" : ""}`}>
                      <CardContent className="pt-4 pb-3">
                        <div
                          className="flex items-center gap-3 cursor-pointer"
                          onClick={() => setExpandedResult(isExpanded ? null : r.id)}
                        >
                          {isExpanded ? <ChevronDown className="w-4 h-4 text-muted-foreground shrink-0" /> : <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-sm font-mono font-medium">{host}</span>
                              <Badge variant="outline" className="text-[10px]">{cve}</Badge>
                              {statusBadge(st)}
                              {modeBadge(r.resultMode || r.mode)}
                            </div>
                            <div className="text-[10px] text-muted-foreground mt-1 font-mono truncate">
                              {mod || "No module"}
                            </div>
                          </div>
                          <div className="text-right shrink-0 space-y-0.5">
                            {r.scoreAdjustment !== 0 && r.scoreAdjustment != null && (
                              <div className={`text-xs font-bold ${r.scoreAdjustment > 0 ? "text-red-400" : "text-emerald-400"}`}>
                                {r.scoreAdjustment > 0 ? "+" : ""}{r.scoreAdjustment.toFixed(1)} risk
                              </div>
                            )}
                            {r.validationDurationMs != null && (
                              <div className="text-[10px] text-muted-foreground">{r.validationDurationMs}ms</div>
                            )}
                          </div>
                          {st === "approved_pending" && (
                            <Button
                              variant="outline"
                              size="sm"
                              className="shrink-0 text-xs border-amber-500/30 text-amber-400 hover:bg-amber-500/10"
                              onClick={(e) => { e.stopPropagation(); approveMutation.mutate({ resultId: r.id }); }}
                            >
                              Approve
                            </Button>
                          )}
                        </div>

                        {isExpanded && (
                          <div className="mt-3 pt-3 border-t border-zinc-800 space-y-3">
                            {/* Evidence */}
                            {evidence && (
                              <div className="space-y-2">
                                <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Evidence</h4>
                                <div className="grid grid-cols-2 gap-2 text-xs">
                                  {evidence.checkResult != null && (
                                    <div className="bg-zinc-900/50 rounded p-2">
                                      <span className="text-muted-foreground">Check Result:</span>{" "}
                                      <span className={evidence.checkResult ? "text-red-400" : "text-emerald-400"}>
                                        {evidence.checkResult ? "Vulnerable" : "Not Vulnerable"}
                                      </span>
                                    </div>
                                  )}
                                  {evidence.sessionOpened != null && (
                                    <div className="bg-zinc-900/50 rounded p-2">
                                      <span className="text-muted-foreground">Session:</span>{" "}
                                      <span className={evidence.sessionOpened ? "text-red-400" : "text-emerald-400"}>
                                        {evidence.sessionOpened ? "Opened" : "None"}
                                      </span>
                                    </div>
                                  )}
                                  {evidence.bannerGrab && (
                                    <div className="bg-zinc-900/50 rounded p-2 col-span-2">
                                      <span className="text-muted-foreground">Banner:</span>{" "}
                                      <span className="font-mono text-[10px]">{evidence.bannerGrab}</span>
                                    </div>
                                  )}
                                  {evidence.versionDetected && (
                                    <div className="bg-zinc-900/50 rounded p-2">
                                      <span className="text-muted-foreground">Version:</span>{" "}
                                      <span className="font-mono">{evidence.versionDetected}</span>
                                    </div>
                                  )}
                                  {evidence.confidenceLevel && (
                                    <div className="bg-zinc-900/50 rounded p-2">
                                      <span className="text-muted-foreground">Confidence:</span>{" "}
                                      <span className="capitalize">{evidence.confidenceLevel}</span>
                                    </div>
                                  )}
                                </div>
                              </div>
                            )}

                            {/* Raw Output */}
                            {(r.validationRawOutput || r.rawOutput) && (
                              <div className="space-y-1">
                                <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Raw Output</h4>
                                <pre className="bg-black/50 rounded p-3 text-[10px] font-mono text-zinc-400 max-h-[200px] overflow-y-auto whitespace-pre-wrap">
                                  {r.validationRawOutput || r.rawOutput}
                                </pre>
                              </div>
                            )}

                            {/* Score Impact */}
                            {r.previousRiskScore != null && r.newRiskScore != null && (
                              <div className="flex items-center gap-3 text-xs">
                                <span className="text-muted-foreground">Score Impact:</span>
                                <span className="font-mono">{r.previousRiskScore.toFixed(1)}</span>
                                <span className="text-muted-foreground">→</span>
                                <span className={`font-mono font-bold ${(r.newRiskScore > r.previousRiskScore) ? "text-red-400" : "text-emerald-400"}`}>
                                  {r.newRiskScore.toFixed(1)}
                                </span>
                              </div>
                            )}

                            {/* Error */}
                            {(r.validationResultError || r.errorMessage) && (
                              <div className="bg-red-500/5 border border-red-500/20 rounded p-2 text-xs text-red-400">
                                <AlertTriangle className="w-3.5 h-3.5 inline mr-1" />
                                {r.validationResultError || r.errorMessage}
                              </div>
                            )}
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </>
          ) : null}
        </TabsContent>

        {/* ─── Pre-Flight Tab ─────────────────────────────────────────────── */}
        <TabsContent value="preflight" className="space-y-4 mt-4">
          <PreFlightTab scanId={selectedScanId ? Number(selectedScanId) : undefined} />
        </TabsContent>

        {/* ─── Accuracy Tab ──────────────────────────────────────────────────── */}
        <TabsContent value="accuracy" className="space-y-4 mt-4">
          <ValidationAccuracyTab scanId={selectedScanId ? Number(selectedScanId) : undefined} />
        </TabsContent>

        {/* ─── History Tab ─────────────────────────────────────────────────── */}
        <TabsContent value="history" className="space-y-4 mt-4">
          <Card className="bg-zinc-950/60 border-zinc-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Activity className="w-4 h-4 text-blue-400" /> Validation History
              </CardTitle>
            </CardHeader>
            <CardContent>
              {runsQuery.isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-6 h-6 animate-spin text-purple-400" />
                </div>
              ) : (runsQuery.data || []).length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <FlaskConical className="w-10 h-10 mb-3 opacity-20" />
                  <p className="text-sm">No validation runs yet</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {(runsQuery.data || []).map((r: any) => (
                    <div
                      key={r.id}
                      className={`flex items-center gap-3 p-3 rounded-lg border transition-colors cursor-pointer ${
                        selectedRunId === r.id
                          ? "bg-purple-500/5 border-purple-500/30"
                          : "bg-zinc-900/30 border-zinc-800 hover:border-zinc-700"
                      }`}
                      onClick={() => { setSelectedRunId(r.id); setActiveTab("results"); }}
                    >
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium">Run #{r.id}</span>
                          {runStatusBadge(r.status)}
                          {modeBadge(r.mode)}
                        </div>
                        <div className="text-[10px] text-muted-foreground mt-1">
                          Scan #{r.scanId} · {r.totalCandidates} candidates · {new Date(r.startedAt).toLocaleString()}
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <div className="flex items-center gap-3 text-xs">
                          {r.validated > 0 && (
                            <span className="text-red-400 font-medium">{r.validated} exploitable</span>
                          )}
                          {r.notVulnerable > 0 && (
                            <span className="text-emerald-400">{r.notVulnerable} safe</span>
                          )}
                          {r.errors > 0 && (
                            <span className="text-zinc-500">{r.errors} errors</span>
                          )}
                        </div>
                        {r.avgScoreAdjustment != null && r.avgScoreAdjustment !== 0 && (
                          <div className="text-[10px] text-muted-foreground mt-0.5">
                            Avg Δ: {r.avgScoreAdjustment > 0 ? "+" : ""}{r.avgScoreAdjustment.toFixed(1)}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
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


// ─── Pre-Flight Tab Component ───────────────────────────────────────────────
function PreFlightTab({ scanId }: { scanId?: number }) {
  const preflightQuery = trpc.accuracyEngine.preFlight.batchCheck.useQuery(
    { scanId: scanId!, targetHost: "*" },
    { enabled: !!scanId }
  );

  const controlsQuery = trpc.accuracyEngine.controls.assessScan.useQuery(
    { scanId: scanId! },
    { enabled: !!scanId }
  );

  if (!scanId) {
    return (
      <Card className="bg-zinc-950/60 border-zinc-800">
        <CardContent className="flex flex-col items-center justify-center py-16 text-muted-foreground">
          <Scan className="w-12 h-12 mb-4 opacity-20" />
          <p className="text-sm">Select a scan from the Launch tab to run pre-flight checks</p>
          <p className="text-xs mt-1">Pre-flight checks verify version banners, endpoint reachability, and fingerprints before exploitation.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Pre-Flight Results */}
      <Card className="bg-zinc-950/60 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Fingerprint className="w-4 h-4 text-cyan-400" /> Exploit Pre-Flight Checks
          </CardTitle>
          <p className="text-xs text-muted-foreground">
            Version banner verification, endpoint reachability, and fingerprint matching run before any exploitation attempt.
          </p>
        </CardHeader>
        <CardContent>
          {preflightQuery.isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
            </div>
          ) : preflightQuery.error ? (
            <div className="bg-red-500/5 border border-red-500/20 rounded p-3 text-xs text-red-400">
              <AlertTriangle className="w-3.5 h-3.5 inline mr-1" />
              {preflightQuery.error.message}
            </div>
          ) : preflightQuery.data ? (
            <div className="space-y-3">
              {/* Summary Stats */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-cyan-400">{preflightQuery.data.totalModules ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Checked</div>
                </div>
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-emerald-400">
                    {preflightQuery.data.totalViable ?? 0}
                  </div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Viable</div>
                </div>
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-amber-400">
                    {preflightQuery.data.results?.filter((r: any) => r.verdict === "caution").length ?? 0}
                  </div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Caution</div>
                </div>
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-red-400">
                    {preflightQuery.data.results?.filter((r: any) => r.verdict === "no-go" || r.verdict === "abort").length ?? 0}
                  </div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Blocked</div>
                </div>
              </div>

              {/* Individual Results */}
              <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1">
                {(preflightQuery.data.results || []).map((r: any, i: number) => (
                  <div
                    key={i}
                    className={`flex items-center gap-3 p-3 rounded-lg border transition-colors ${
                      r.verdict === "go"
                        ? "bg-emerald-500/5 border-emerald-500/20"
                        : r.verdict === "caution"
                        ? "bg-amber-500/5 border-amber-500/20"
                        : "bg-red-500/5 border-red-500/20"
                    }`}
                  >
                    <div className={`w-2 h-2 rounded-full shrink-0 ${
                      r.verdict === "go" ? "bg-emerald-400" : r.verdict === "caution" ? "bg-amber-400" : "bg-red-400"
                    }`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-mono font-medium truncate">{r.exploitModule || `Module ${i + 1}`}</span>
                        <Badge variant="outline" className="text-[10px]">
                          {(r.overallConfidence * 100).toFixed(0)}% confidence
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 mt-1 text-[10px] text-muted-foreground">
                        <span className="text-emerald-400">{r.passedChecks} passed</span>
                        <span className="text-muted-foreground">/</span>
                        <span>{r.totalChecks} checks</span>
                        <span className="text-muted-foreground">·</span>
                        <span>Est. success: {r.estimatedSuccessRate}%</span>
                      </div>
                    </div>
                    <Badge variant={r.verdict === "go" ? "default" : "secondary"} className="text-[10px] shrink-0">
                      {r.verdict?.toUpperCase() || "UNKNOWN"}
                    </Badge>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>

      {/* Compensating Controls */}
      <Card className="bg-zinc-950/60 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <ShieldOff className="w-4 h-4 text-amber-400" /> Compensating Controls Detected
          </CardTitle>
          <p className="text-xs text-muted-foreground">
            WAF, CDN, IPS, and other defensive controls detected that may affect exploit success rates and severity scoring.
          </p>
        </CardHeader>
        <CardContent>
          {controlsQuery.isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="w-6 h-6 animate-spin text-amber-400" />
            </div>
          ) : controlsQuery.error ? (
            <div className="bg-red-500/5 border border-red-500/20 rounded p-3 text-xs text-red-400">
              <AlertTriangle className="w-3.5 h-3.5 inline mr-1" />
              {controlsQuery.error.message}
            </div>
          ) : controlsQuery.data ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-amber-400">{controlsQuery.data.totalControls ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Controls Found</div>
                </div>
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-purple-400">
                    {controlsQuery.data.assessment?.adjustedSeverityLabel ?? "N/A"}
                  </div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Adjusted Severity</div>
                </div>
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-cyan-400">
                    {controlsQuery.data.assessment?.severityAdjustment ? `${Math.abs(controlsQuery.data.assessment.severityAdjustment)}pts` : "0pts"}
                  </div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Severity Reduction</div>
                </div>
              </div>

              {Object.keys(controlsQuery.data.controlsByCategory || {}).length > 0 && (
                <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                  {Object.entries(controlsQuery.data.controlsByCategory).map(([category, count]: [string, any], i: number) => (
                    <div key={i} className="flex items-center gap-3 p-3 rounded-lg bg-zinc-900/30 border border-zinc-800">
                      <Shield className="w-4 h-4 text-amber-400 shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium capitalize">{category.replace(/_/g, " ")}</span>
                          <Badge variant="outline" className="text-[10px]">{count} detected</Badge>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Validation Accuracy Tab Component ──────────────────────────────────────
function ValidationAccuracyTab({ scanId }: { scanId?: number }) {
  const temporalQuery = trpc.accuracyEngine.temporal.scanScores.useQuery(
    { scanId: scanId! },
    { enabled: !!scanId }
  );

  const attackChainsQuery = trpc.accuracyEngine.attackChains.analyze.useQuery(
    { scanId: scanId! },
    { enabled: !!scanId }
  );

  const feedbackQuery = trpc.accuracyEngine.feedback.rankModules.useQuery(
    { targetService: "*" },
    { enabled: true }
  );

  const remediationQuery = trpc.accuracyEngine.remediation.summary.useQuery(
    undefined,
    { enabled: true }
  );

  if (!scanId) {
    return (
      <Card className="bg-zinc-950/60 border-zinc-800">
        <CardContent className="flex flex-col items-center justify-center py-16 text-muted-foreground">
          <Gauge className="w-12 h-12 mb-4 opacity-20" />
          <p className="text-sm">Select a scan from the Launch tab to view accuracy metrics</p>
          <p className="text-xs mt-1">Temporal decay scores, attack chain analysis, exploit feedback, and remediation tracking.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Temporal Decay Scores */}
      <Card className="bg-zinc-950/60 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Clock className="w-4 h-4 text-blue-400" /> Temporal Decay Scoring
          </CardTitle>
          <p className="text-xs text-muted-foreground">
            Time-based urgency multipliers factoring KEV deadlines, patch negligence, and data staleness into risk scores.
          </p>
        </CardHeader>
        <CardContent>
          {temporalQuery.isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="w-6 h-6 animate-spin text-blue-400" />
            </div>
          ) : temporalQuery.error ? (
            <div className="bg-red-500/5 border border-red-500/20 rounded p-3 text-xs text-red-400">
              <AlertTriangle className="w-3.5 h-3.5 inline mr-1" />
              {temporalQuery.error.message}
            </div>
          ) : temporalQuery.data ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { label: "Critical Urgency", value: temporalQuery.data.scores?.filter((s: any) => s.urgencyLevel === "critical").length ?? 0, color: "text-red-400" },
                  { label: "High Urgency", value: temporalQuery.data.scores?.filter((s: any) => s.urgencyLevel === "high").length ?? 0, color: "text-orange-400" },
                  { label: "Medium Urgency", value: temporalQuery.data.scores?.filter((s: any) => s.urgencyLevel === "medium").length ?? 0, color: "text-amber-400" },
                  { label: "Low Urgency", value: temporalQuery.data.scores?.filter((s: any) => s.urgencyLevel === "low").length ?? 0, color: "text-emerald-400" },
                ].map(item => (
                  <div key={item.label} className="bg-zinc-900/50 rounded-lg p-3 text-center">
                    <div className={`text-2xl font-bold ${item.color}`}>{item.value}</div>
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider">{item.label}</div>
                  </div>
                ))}
              </div>

              {/* Top urgent findings */}
              <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                {(temporalQuery.data.scores || [])
                  .filter((s: any) => s.urgencyLevel === "critical" || s.urgencyLevel === "high")
                  .slice(0, 10)
                  .map((s: any, i: number) => (
                    <div key={i} className="flex items-center gap-3 p-2 rounded-lg bg-zinc-900/30 border border-zinc-800">
                      <div className={`w-2 h-2 rounded-full shrink-0 ${
                        s.urgencyLevel === "critical" ? "bg-red-400" : "bg-orange-400"
                      }`} />
                      <div className="flex-1 min-w-0">
                        <span className="text-xs font-mono">{s.cveId || s.findingId || `Finding ${i + 1}`}</span>
                      </div>
                      <div className="text-right shrink-0">
                        <span className="text-xs font-medium">{s.temporalMultiplier?.toFixed(2) || "1.00"}x</span>
                        <span className="text-[10px] text-muted-foreground ml-1">multiplier</span>
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>

      {/* Attack Chain Analysis */}
      <Card className="bg-zinc-950/60 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Network className="w-4 h-4 text-purple-400" /> Attack Chain Analysis
          </CardTitle>
          <p className="text-xs text-muted-foreground">
            Multi-step exploit chains where individually low-severity findings combine into critical attack paths.
          </p>
        </CardHeader>
        <CardContent>
          {attackChainsQuery.isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="w-6 h-6 animate-spin text-purple-400" />
            </div>
          ) : attackChainsQuery.error ? (
            <div className="bg-red-500/5 border border-red-500/20 rounded p-3 text-xs text-red-400">
              <AlertTriangle className="w-3.5 h-3.5 inline mr-1" />
              {attackChainsQuery.error.message}
            </div>
          ) : attackChainsQuery.data ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-purple-400">{attackChainsQuery.data.chains?.length ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Chains Found</div>
                </div>
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-red-400">
                    {attackChainsQuery.data.chains?.filter((c: any) => c.severity === "critical").length ?? 0}
                  </div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Critical Chains</div>
                </div>
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-amber-400">
                    {attackChainsQuery.data.chains?.reduce((max: number, c: any) => Math.max(max, c.links?.length ?? 0), 0) ?? 0}
                  </div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Max Chain Depth</div>
                </div>
              </div>

              {(attackChainsQuery.data.chains || []).length > 0 && (
                <div className="space-y-3 max-h-[400px] overflow-y-auto pr-1">
                  {attackChainsQuery.data.chains.map((chain: any, i: number) => (
                    <div key={i} className="p-3 rounded-lg bg-zinc-900/30 border border-zinc-800">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Network className="w-3.5 h-3.5 text-purple-400" />
                          <span className="text-sm font-medium">{chain.name || `Chain ${i + 1}`}</span>
                          <Badge variant={chain.severity === "critical" ? "destructive" : "secondary"} className="text-[10px]">
                            {chain.severity || "unknown"}
                          </Badge>
                        </div>
                        <span className="text-xs text-muted-foreground">{chain.links?.length ?? 0} steps</span>
                      </div>
                      {/* Chain visualization */}
                      <div className="flex items-center gap-1 overflow-x-auto pb-1">
                        {(chain.links || []).map((link: any, j: number) => (
                          <div key={j} className="flex items-center gap-1 shrink-0">
                            <div className="bg-zinc-800 rounded px-2 py-1 text-[10px] font-mono">
                              {link.cveId || link.technique || link.label || `Step ${j + 1}`}
                            </div>
                            {j < (chain.links?.length ?? 0) - 1 && (
                              <ChevronRight className="w-3 h-3 text-muted-foreground shrink-0" />
                            )}
                          </div>
                        ))}
                      </div>
                      {chain.impact && (
                        <p className="text-[10px] text-muted-foreground mt-1.5">{chain.impact}</p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : null}
        </CardContent>
      </Card>

      {/* Exploit Feedback Loop */}
      <Card className="bg-zinc-950/60 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-emerald-400" /> Exploit Module Performance
          </CardTitle>
          <p className="text-xs text-muted-foreground">
            Historical success/failure rates for exploit modules. Low-performing modules are auto-retired from future runs.
          </p>
        </CardHeader>
        <CardContent>
          {feedbackQuery.isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="w-6 h-6 animate-spin text-emerald-400" />
            </div>
          ) : feedbackQuery.error ? (
            <div className="bg-red-500/5 border border-red-500/20 rounded p-3 text-xs text-red-400">
              <AlertTriangle className="w-3.5 h-3.5 inline mr-1" />
              {feedbackQuery.error.message}
            </div>
          ) : feedbackQuery.data ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-emerald-400">{feedbackQuery.data.length ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Modules Tracked</div>
                </div>
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-blue-400">
                    {feedbackQuery.data.filter((r: any) => r.successRate > 0.7).length ?? 0}
                  </div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">High Performers</div>
                </div>
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-amber-400">
                    {feedbackQuery.data.filter((r: any) => r.successRate >= 0.3 && r.successRate <= 0.7).length ?? 0}
                  </div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Moderate</div>
                </div>
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-red-400">
                    {feedbackQuery.data.filter((r: any) => r.retired || r.successRate < 0.3).length ?? 0}
                  </div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Retired</div>
                </div>
              </div>

              {feedbackQuery.data.length > 0 && (
                <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                  {feedbackQuery.data.slice(0, 15).map((r: any, i: number) => (
                    <div key={i} className="flex items-center gap-3 p-2 rounded-lg bg-zinc-900/30 border border-zinc-800">
                      <div className="w-6 text-center text-xs font-bold text-muted-foreground">#{i + 1}</div>
                      <div className="flex-1 min-w-0">
                        <span className="text-xs font-mono truncate block">{r.moduleId || r.moduleName}</span>
                        <span className="text-[10px] text-muted-foreground">{r.totalAttempts ?? 0} attempts</span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <div className="w-20 bg-zinc-800 rounded-full h-1.5">
                          <div
                            className={`h-1.5 rounded-full ${
                              (r.successRate ?? 0) > 0.7 ? "bg-emerald-400" : (r.successRate ?? 0) > 0.3 ? "bg-amber-400" : "bg-red-400"
                            }`}
                            style={{ width: `${(r.successRate ?? 0) * 100}%` }}
                          />
                        </div>
                        <span className="text-xs font-medium w-10 text-right">
                          {((r.successRate ?? 0) * 100).toFixed(0)}%
                        </span>
                        {r.retired && <Badge variant="outline" className="text-[10px] text-red-400 border-red-500/20">Retired</Badge>}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : null}
        </CardContent>
      </Card>

      {/* Remediation Verification Summary */}
      <Card className="bg-zinc-950/60 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" /> Remediation Verification
          </CardTitle>
          <p className="text-xs text-muted-foreground">
            Closed-loop verification: re-run exploits after remediation to confirm fixes are effective. SLA compliance tracking included.
          </p>
        </CardHeader>
        <CardContent>
          {remediationQuery.isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
            </div>
          ) : remediationQuery.error ? (
            <div className="bg-red-500/5 border border-red-500/20 rounded p-3 text-xs text-red-400">
              <AlertTriangle className="w-3.5 h-3.5 inline mr-1" />
              {remediationQuery.error.message}
            </div>
          ) : remediationQuery.data ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-cyan-400">{remediationQuery.data.totalFindings ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Tracked</div>
                </div>
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-emerald-400">{remediationQuery.data.verifiedFixed ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Verified Fixed</div>
                </div>
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-red-400">{remediationQuery.data.stillVulnerable ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Still Vulnerable</div>
                </div>
                <div className="bg-zinc-900/50 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-purple-400">
                    {remediationQuery.data.slaCompliance != null ? `${(remediationQuery.data.slaCompliance * 100).toFixed(0)}%` : "N/A"}
                  </div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">SLA Compliance</div>
                </div>
              </div>

              {/* Fix Rate Progress */}
              <div className="bg-zinc-900/50 rounded-lg p-3">
                <div className="flex justify-between text-xs text-muted-foreground mb-1.5">
                  <span>Fix Rate</span>
                  <span>{remediationQuery.data.fixRate != null ? `${(remediationQuery.data.fixRate * 100).toFixed(1)}%` : "N/A"}</span>
                </div>
                <Progress value={(remediationQuery.data.fixRate ?? 0) * 100} className="h-2" />
              </div>

              {/* Additional stats */}
              <div className="grid grid-cols-3 gap-2">
                <div className="bg-zinc-900/30 rounded p-2 text-center">
                  <div className="text-sm font-bold text-amber-400">{remediationQuery.data.remediationPending ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground">Pending</div>
                </div>
                <div className="bg-zinc-900/30 rounded p-2 text-center">
                  <div className="text-sm font-bold text-blue-400">{remediationQuery.data.verificationQueued ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground">Queued</div>
                </div>
                <div className="bg-zinc-900/30 rounded p-2 text-center">
                  <div className="text-sm font-bold text-orange-400">{remediationQuery.data.overdueFindingsCount ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground">Overdue</div>
                </div>
              </div>

              {remediationQuery.data.meanTimeToRemediate != null && (
                <div className="text-center text-xs text-muted-foreground">
                  Mean Time to Remediate: <span className="font-medium text-foreground">{remediationQuery.data.meanTimeToRemediate.toFixed(1)} hours</span>
                </div>
              )}
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
