import { useState, useMemo, useEffect } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Loader2, AlertTriangle, Trash2, PlusCircle, Eye, Brain, Target,
  Shield, Crosshair, Zap, ChevronRight, Clock, CheckCircle2, XCircle,
  BarChart3, Network, Globe, Search, Play, Square, FileDown,
  Radar, Bug, Code, Server, Lock, Unlock, RefreshCw, Sparkles,
  ArrowRight, ExternalLink, ShieldAlert, Cpu, Activity
} from "lucide-react";
import { exportToPdf } from "@/lib/export-pdf";

// ─── Severity Colors ──────────────────────────────────────────────────────────
const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  high: "bg-red-500/20 text-red-400 border-red-500/30",
  medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-purple-400",
  high: "bg-red-400",
  medium: "bg-amber-400",
  low: "bg-blue-400",
  info: "bg-gray-400",
};

const TRIAGE_COLORS: Record<string, string> = {
  true_positive: "bg-red-500/20 text-red-400",
  likely_positive: "bg-orange-500/20 text-orange-400",
  needs_review: "bg-amber-500/20 text-amber-400",
  likely_false_positive: "bg-emerald-500/20 text-emerald-400",
  false_positive: "bg-green-500/20 text-green-400",
};

const MODE_CONFIG = {
  passive: {
    label: "Passive Recon",
    icon: Search,
    color: "text-cyan-400",
    bg: "bg-cyan-500/10 border-cyan-500/30",
    description: "Spider crawling + passive vulnerability detection. Safe for domain intelligence — no active attacks.",
  },
  active: {
    label: "Active DAST",
    icon: Zap,
    color: "text-red-400",
    bg: "bg-red-500/10 border-red-500/30",
    description: "Full active scanning with exploit detection. Coordinates with Metasploit/Caldera attack chains.",
  },
};

// ─── Main Component ───────────────────────────────────────────────────────────
export default function WebAppScanner() {
  const [activeTab, setActiveTab] = useState("scans");
  const [showNewScan, setShowNewScan] = useState(false);
  const [pollingScanId, setPollingScanId] = useState<number | null>(null);

  // Queries
  const scansQuery = trpc.webAppScanning.listScans.useQuery(undefined, { refetchInterval: 10000 });
  const statsQuery = trpc.webAppScanning.stats.useQuery(undefined, { refetchInterval: 30000 });
  const healthQuery = trpc.webAppScanning.health.useQuery(undefined, { refetchInterval: 60000 });

  // Polling for active scan
  const pollQuery = trpc.webAppScanning.pollProgress.useQuery(
    { scanId: pollingScanId! },
    { enabled: !!pollingScanId, refetchInterval: 3000 }
  );

  useEffect(() => {
    if (pollQuery.data?.status === "completed" || pollQuery.data?.status === "error") {
      setPollingScanId(null);
      scansQuery.refetch();
      statsQuery.refetch();
      if (pollQuery.data.status === "completed") {
        toast.success("Scan completed successfully");
      }
    }
  }, [pollQuery.data?.status]);

  // Mutations
  const seedDemo = trpc.webAppScanning.seedDemo.useMutation({
    onSuccess: () => { toast.success("Demo data seeded"); scansQuery.refetch(); statsQuery.refetch(); },
    onError: (e) => toast.error(`Seed failed: ${e.message}`),
  });
  const clearDemo = trpc.webAppScanning.clearDemo.useMutation({
    onSuccess: (d) => { toast.success(`Cleared ${d.deletedScans} demo scans`); scansQuery.refetch(); statsQuery.refetch(); },
    onError: (e) => toast.error(`Clear failed: ${e.message}`),
  });

  const stats = statsQuery.data;
  const scans = scansQuery.data || [];

  return (
    <div className="space-y-6 p-1">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-3">
            <Globe className="w-7 h-7 text-cyan-400" />
            Web Application Scanner
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            OWASP ZAP dual-mode scanning with LLM-powered intelligent orchestration
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className={healthQuery.data?.available ? "border-emerald-500/50 text-emerald-400" : "border-red-500/50 text-red-400"}>
            <div className={`w-2 h-2 rounded-full mr-1.5 ${healthQuery.data?.available ? "bg-emerald-400 animate-pulse" : "bg-red-400"}`} />
            ZAP {healthQuery.data?.available ? `v${healthQuery.data.version}` : "Offline"}
          </Badge>
          <Button variant="outline" size="sm" onClick={() => seedDemo.mutate()} disabled={seedDemo.isPending}>
            {seedDemo.isPending ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : <PlusCircle className="w-3 h-3 mr-1" />}
            Seed Demo
          </Button>
          <Button variant="outline" size="sm" onClick={() => clearDemo.mutate()} disabled={clearDemo.isPending}>
            <Trash2 className="w-3 h-3 mr-1" />
            Clear Demo
          </Button>
          <Button onClick={() => setShowNewScan(true)} className="bg-cyan-600 hover:bg-cyan-700">
            <PlusCircle className="w-4 h-4 mr-2" />
            New Scan
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          <StatCard label="Total Scans" value={stats.totalScans} icon={<Globe className="w-4 h-4 text-cyan-400" />} />
          <StatCard label="Completed" value={stats.completedScans} icon={<CheckCircle2 className="w-4 h-4 text-emerald-400" />} />
          <StatCard label="Total Findings" value={stats.totalFindings} icon={<Bug className="w-4 h-4 text-amber-400" />} />
          <StatCard label="High Severity" value={stats.findingsBySeverity.high} icon={<ShieldAlert className="w-4 h-4 text-red-400" />} />
          <StatCard label="Exploitable" value={stats.exploitableFindings} icon={<Crosshair className="w-4 h-4 text-red-400" />} />
          <StatCard label="ATT&CK Techniques" value={stats.mitreAttackCoverage.length} icon={<Target className="w-4 h-4 text-purple-400" />} />
        </div>
      )}

      {/* Mode Distribution */}
      {stats && (stats.scansByMode.passive > 0 || stats.scansByMode.active > 0) && (
        <div className="grid grid-cols-2 gap-3">
          <Card className="border-cyan-500/20">
            <CardContent className="p-4 flex items-center gap-3">
              <Search className="w-5 h-5 text-cyan-400" />
              <div>
                <div className="text-lg font-bold">{stats.scansByMode.passive}</div>
                <div className="text-xs text-muted-foreground">Passive Recon Scans</div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-red-500/20">
            <CardContent className="p-4 flex items-center gap-3">
              <Zap className="w-5 h-5 text-red-400" />
              <div>
                <div className="text-lg font-bold">{stats.scansByMode.active}</div>
                <div className="text-xs text-muted-foreground">Active DAST Scans</div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Active Scan Progress */}
      {pollingScanId && pollQuery.data && (
        <Card className="border-cyan-500/30 bg-cyan-500/5">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />
                <span className="font-medium">Scan in Progress</span>
                <Badge variant="outline" className="text-xs">{pollQuery.data.status}</Badge>
              </div>
              <span className="text-sm text-muted-foreground">{pollQuery.data.urlsFound} URLs found</span>
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="text-xs w-24 text-muted-foreground">Spider</span>
                <Progress value={pollQuery.data.spiderProgress} className="flex-1 h-2" />
                <span className="text-xs w-10 text-right">{pollQuery.data.spiderProgress}%</span>
              </div>
              {pollQuery.data.activeScanProgress > 0 && (
                <div className="flex items-center gap-2">
                  <span className="text-xs w-24 text-muted-foreground">Active Scan</span>
                  <Progress value={pollQuery.data.activeScanProgress} className="flex-1 h-2" />
                  <span className="text-xs w-10 text-right">{pollQuery.data.activeScanProgress}%</span>
                </div>
              )}
            </div>
            <div className="flex gap-2 mt-2">
              {Object.entries(pollQuery.data.alertCounts).map(([sev, count]) => (
                <Badge key={sev} variant="outline" className={SEVERITY_COLORS[sev] || ""}>
                  {sev}: {count as number}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-muted/30">
          <TabsTrigger value="scans">Scan History</TabsTrigger>
          <TabsTrigger value="findings">All Findings</TabsTrigger>
          <TabsTrigger value="mitre">MITRE ATT&CK Map</TabsTrigger>
          <TabsTrigger value="exploits">Exploit Correlation</TabsTrigger>
        </TabsList>

        {/* Scan History Tab */}
        <TabsContent value="scans" className="space-y-3">
          {scans.length === 0 ? (
            <Card>
              <CardContent className="p-8 text-center text-muted-foreground">
                <Globe className="w-12 h-12 mx-auto mb-3 opacity-30" />
                <p>No scans yet. Click "New Scan" or "Seed Demo" to get started.</p>
              </CardContent>
            </Card>
          ) : (
            scans.map((scan: any) => (
              <ScanCard key={scan.id} scan={scan} onPoll={(id) => setPollingScanId(id)} onRefresh={() => { scansQuery.refetch(); statsQuery.refetch(); }} />
            ))
          )}
        </TabsContent>

        {/* All Findings Tab */}
        <TabsContent value="findings">
          <AllFindingsView scans={scans} />
        </TabsContent>

        {/* MITRE ATT&CK Tab */}
        <TabsContent value="mitre">
          <MitreAttackView stats={stats} />
        </TabsContent>

        {/* Exploit Correlation Tab */}
        <TabsContent value="exploits">
          <ExploitCorrelationView scans={scans} />
        </TabsContent>
      </Tabs>

      {/* New Scan Dialog */}
      <NewScanDialog
        open={showNewScan}
        onOpenChange={setShowNewScan}
        onScanStarted={(scanId) => {
          setPollingScanId(scanId);
          scansQuery.refetch();
        }}
      />
    </div>
  );
}

// ─── Stat Card ────────────────────────────────────────────────────────────────
function StatCard({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) {
  return (
    <Card>
      <CardContent className="p-3 flex items-center gap-2">
        {icon}
        <div>
          <div className="text-lg font-bold tabular-nums">{value}</div>
          <div className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Scan Card ────────────────────────────────────────────────────────────────
function ScanCard({ scan, onPoll, onRefresh }: { scan: any; onPoll: (id: number) => void; onRefresh: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const [showFindings, setShowFindings] = useState(false);

  const deleteScan = trpc.webAppScanning.deleteScan.useMutation({
    onSuccess: () => { toast.success("Scan deleted"); onRefresh(); },
  });
  const stopScan = trpc.webAppScanning.stopScan.useMutation({
    onSuccess: () => { toast.success("Scan stopped"); onRefresh(); },
  });
  const exportReport = trpc.webAppScanning.exportReport.useQuery(
    { scanId: scan.id },
    { enabled: false }
  );

  const alertCounts = scan.alertCounts ? JSON.parse(scan.alertCounts) : { high: 0, medium: 0, low: 0, info: 0 };
  const techStack = scan.detectedTechStack ? JSON.parse(scan.detectedTechStack) : [];
  const modeConfig = MODE_CONFIG[scan.scanMode as keyof typeof MODE_CONFIG] || MODE_CONFIG.passive;
  const ModeIcon = modeConfig.icon;
  const isRunning = !["completed", "error"].includes(scan.status);

  const handleExport = async () => {
    const result = await exportReport.refetch();
    if (result.data) {
      exportToPdf(result.data, `zap-scan-${scan.id}.pdf`);
    }
  };

  return (
    <Card className={`${modeConfig.bg} transition-all`}>
      <CardContent className="p-4">
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className={`p-2 rounded-lg bg-background/50 ${modeConfig.color}`}>
              <ModeIcon className="w-5 h-5" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="font-semibold truncate">{scan.scanName || scan.targetUrl}</h3>
                <Badge variant="outline" className="text-[10px]">{modeConfig.label}</Badge>
                <Badge variant="outline" className={`text-[10px] ${scan.status === "completed" ? "border-emerald-500/50 text-emerald-400" : scan.status === "error" ? "border-red-500/50 text-red-400" : "border-amber-500/50 text-amber-400"}`}>
                  {scan.status}
                </Badge>
              </div>
              <div className="text-xs text-muted-foreground mt-1 truncate">{scan.targetUrl}</div>
              <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground flex-wrap">
                <span className="flex items-center gap-1"><Globe className="w-3 h-3" />{scan.urlsDiscovered || 0} URLs</span>
                <span className="flex items-center gap-1"><Bug className="w-3 h-3" />{scan.totalAlerts || 0} findings</span>
                {scan.startedAt && <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{new Date(scan.startedAt).toLocaleString()}</span>}
                {techStack.length > 0 && <span className="flex items-center gap-1"><Cpu className="w-3 h-3" />{techStack.slice(0, 3).join(", ")}</span>}
                {scan.attackChainId && <span className="flex items-center gap-1"><Network className="w-3 h-3" />Chain: {scan.attackChainId}</span>}
              </div>
              {/* Alert severity badges */}
              <div className="flex gap-1.5 mt-2">
                {alertCounts.high > 0 && <Badge className="bg-red-500/20 text-red-400 border-red-500/30 text-[10px]">High: {alertCounts.high}</Badge>}
                {alertCounts.medium > 0 && <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/30 text-[10px]">Med: {alertCounts.medium}</Badge>}
                {alertCounts.low > 0 && <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30 text-[10px]">Low: {alertCounts.low}</Badge>}
                {alertCounts.info > 0 && <Badge className="bg-gray-500/20 text-gray-400 border-gray-500/30 text-[10px]">Info: {alertCounts.info}</Badge>}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-1 shrink-0">
            {isRunning && (
              <>
                <Button variant="ghost" size="sm" onClick={() => onPoll(scan.id)}>
                  <RefreshCw className="w-3 h-3 mr-1" />Poll
                </Button>
                <Button variant="ghost" size="sm" onClick={() => stopScan.mutate({ scanId: scan.id })}>
                  <Square className="w-3 h-3 mr-1" />Stop
                </Button>
              </>
            )}
            {scan.status === "completed" && (
              <>
                <Button variant="ghost" size="sm" onClick={() => setShowFindings(!showFindings)}>
                  <Eye className="w-3 h-3 mr-1" />{showFindings ? "Hide" : "View"}
                </Button>
                <Button variant="ghost" size="sm" onClick={handleExport} disabled={exportReport.isFetching}>
                  <FileDown className="w-3 h-3 mr-1" />PDF
                </Button>
              </>
            )}
            <Button variant="ghost" size="sm" onClick={() => deleteScan.mutate({ scanId: scan.id })} disabled={deleteScan.isPending}>
              <Trash2 className="w-3 h-3 text-red-400" />
            </Button>
          </div>
        </div>

        {/* Expanded findings */}
        {showFindings && <ScanFindingsPanel scanId={scan.id} scanMode={scan.scanMode} />}
      </CardContent>
    </Card>
  );
}

// ─── Scan Findings Panel ──────────────────────────────────────────────────────
function ScanFindingsPanel({ scanId, scanMode }: { scanId: number; scanMode: string }) {
  const findingsQuery = trpc.webAppScanning.getFindings.useQuery({ scanId, limit: 200 });
  const batchTriage = trpc.webAppScanning.batchTriage.useMutation({
    onSuccess: (d) => { toast.success(`Triaged ${d.triaged} findings`); findingsQuery.refetch(); },
    onError: (e) => toast.error(`Triage failed: ${e.message}`),
  });

  const findings = findingsQuery.data || [];

  return (
    <div className="mt-4 border-t border-border/30 pt-4 space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold flex items-center gap-2">
          <Bug className="w-4 h-4" /> Findings ({findings.length})
        </h4>
        <Button variant="outline" size="sm" onClick={() => batchTriage.mutate({ scanId })} disabled={batchTriage.isPending}>
          {batchTriage.isPending ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : <Sparkles className="w-3 h-3 mr-1" />}
          AI Triage
        </Button>
      </div>

      {findingsQuery.isLoading ? (
        <div className="flex items-center justify-center p-4"><Loader2 className="w-5 h-5 animate-spin" /></div>
      ) : findings.length === 0 ? (
        <p className="text-sm text-muted-foreground text-center py-4">No findings for this scan.</p>
      ) : (
        <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
          {findings.map((f: any) => (
            <FindingRow key={f.id} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Finding Row ──────────────────────────────────────────────────────────────
function FindingRow({ finding }: { finding: any }) {
  const [expanded, setExpanded] = useState(false);
  const triageMutation = trpc.webAppScanning.triageFinding.useMutation({
    onSuccess: () => toast.success("Finding triaged"),
  });

  return (
    <div className="border border-border/30 rounded-lg p-3 bg-background/30 hover:bg-background/50 transition-colors">
      <div className="flex items-start justify-between cursor-pointer" onClick={() => setExpanded(!expanded)}>
        <div className="flex items-start gap-2 min-w-0 flex-1">
          <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${SEVERITY_DOT[finding.severity] || SEVERITY_DOT.info}`} />
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-medium text-sm truncate">{finding.alertName}</span>
              <Badge className={`text-[10px] ${SEVERITY_COLORS[finding.severity] || ""}`}>{finding.severity}</Badge>
              {finding.mitreAttackId && (
                <Badge variant="outline" className="text-[10px] border-purple-500/30 text-purple-400">
                  {finding.mitreAttackId}
                </Badge>
              )}
              {finding.exploitAvailable && (
                <Badge className="text-[10px] bg-red-500/20 text-red-400 border-red-500/30">
                  <Crosshair className="w-2.5 h-2.5 mr-0.5" />Exploit
                </Badge>
              )}
              {finding.aiTriageVerdict && (
                <Badge className={`text-[10px] ${TRIAGE_COLORS[finding.aiTriageVerdict] || ""}`}>
                  AI: {finding.aiTriageVerdict.replace(/_/g, " ")}
                </Badge>
              )}
            </div>
            <div className="text-[11px] text-muted-foreground mt-0.5 truncate">{finding.url}</div>
          </div>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <span className="text-[10px] text-muted-foreground">{Math.round((finding.confidence || 0) * 100)}%</span>
          <ChevronRight className={`w-3 h-3 transition-transform ${expanded ? "rotate-90" : ""}`} />
        </div>
      </div>

      {expanded && (
        <div className="mt-3 pl-4 space-y-2 text-xs">
          {finding.description && (
            <div><span className="font-semibold text-muted-foreground">Description:</span> <span className="text-foreground/80">{finding.description.substring(0, 300)}</span></div>
          )}
          {finding.solution && (
            <div><span className="font-semibold text-muted-foreground">Solution:</span> <span className="text-foreground/80">{finding.solution.substring(0, 300)}</span></div>
          )}
          {finding.param && (
            <div><span className="font-semibold text-muted-foreground">Parameter:</span> <code className="bg-muted/50 px-1 rounded">{finding.param}</code></div>
          )}
          {finding.attack && (
            <div><span className="font-semibold text-muted-foreground">Attack:</span> <code className="bg-muted/50 px-1 rounded text-red-400">{finding.attack.substring(0, 200)}</code></div>
          )}
          {finding.evidence && (
            <div><span className="font-semibold text-muted-foreground">Evidence:</span> <code className="bg-muted/50 px-1 rounded">{finding.evidence.substring(0, 200)}</code></div>
          )}
          {finding.cweId && (
            <div><span className="font-semibold text-muted-foreground">CWE:</span> <a href={`https://cwe.mitre.org/data/definitions/${finding.cweId}.html`} target="_blank" rel="noopener" className="text-cyan-400 hover:underline">CWE-{finding.cweId}</a></div>
          )}
          {finding.mitreAttackId && (
            <div><span className="font-semibold text-muted-foreground">MITRE ATT&CK:</span> <span className="text-purple-400">{finding.mitreAttackId} — {finding.mitreAttackName}</span> <span className="text-muted-foreground">({finding.mitreTactic})</span></div>
          )}
          {finding.exploitModulePath && (
            <div><span className="font-semibold text-muted-foreground">Metasploit Module:</span> <code className="bg-red-500/10 text-red-400 px-1 rounded">{finding.exploitModulePath}</code></div>
          )}
          {finding.aiTriageReason && (
            <div className="p-2 rounded bg-muted/20 border border-border/30">
              <span className="font-semibold text-muted-foreground flex items-center gap-1"><Sparkles className="w-3 h-3" /> AI Triage:</span>
              <span className="text-foreground/80 ml-1">{finding.aiTriageReason}</span>
              {finding.falsePositiveScore !== null && (
                <span className="ml-2 text-muted-foreground">(FP Score: {Math.round(finding.falsePositiveScore * 100)}%)</span>
              )}
            </div>
          )}
          {!finding.aiTriageVerdict && (
            <Button variant="outline" size="sm" onClick={() => triageMutation.mutate({ findingId: finding.id })} disabled={triageMutation.isPending}>
              {triageMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : <Sparkles className="w-3 h-3 mr-1" />}
              AI Triage This Finding
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

// ─── All Findings View ────────────────────────────────────────────────────────
function AllFindingsView({ scans }: { scans: any[] }) {
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  const completedScans = scans.filter((s: any) => s.status === "completed");
  const scanId = selectedScanId || completedScans[0]?.id;

  const findingsQuery = trpc.webAppScanning.getFindings.useQuery(
    { scanId: scanId!, limit: 500 },
    { enabled: !!scanId }
  );

  const findings = useMemo(() => {
    const all = findingsQuery.data || [];
    if (severityFilter === "all") return all;
    return all.filter((f: any) => f.severity === severityFilter);
  }, [findingsQuery.data, severityFilter]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Select value={scanId ? String(scanId) : ""} onValueChange={(v) => setSelectedScanId(Number(v))}>
          <SelectTrigger className="w-[300px]">
            <SelectValue placeholder="Select a scan" />
          </SelectTrigger>
          <SelectContent>
            {completedScans.map((s: any) => (
              <SelectItem key={s.id} value={String(s.id)}>{s.scanName || s.targetUrl}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-[150px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="info">Info</SelectItem>
          </SelectContent>
        </Select>
        <span className="text-sm text-muted-foreground">{findings.length} findings</span>
      </div>

      {findingsQuery.isLoading ? (
        <div className="flex items-center justify-center p-8"><Loader2 className="w-6 h-6 animate-spin" /></div>
      ) : findings.length === 0 ? (
        <Card><CardContent className="p-8 text-center text-muted-foreground">No findings match the current filter.</CardContent></Card>
      ) : (
        <div className="space-y-2">
          {findings.map((f: any) => <FindingRow key={f.id} finding={f} />)}
        </div>
      )}
    </div>
  );
}

// ─── MITRE ATT&CK Map View ───────────────────────────────────────────────────
function MitreAttackView({ stats }: { stats: any }) {
  if (!stats?.mitreAttackCoverage?.length) {
    return (
      <Card><CardContent className="p-8 text-center text-muted-foreground">
        <Target className="w-12 h-12 mx-auto mb-3 opacity-30" />
        <p>No MITRE ATT&CK mappings yet. Run scans to populate technique coverage.</p>
      </CardContent></Card>
    );
  }

  // Group by tactic
  const byTactic = new Map<string, any[]>();
  for (const item of stats.mitreAttackCoverage) {
    if (!byTactic.has(item.tactic)) byTactic.set(item.tactic, []);
    byTactic.get(item.tactic)!.push(item);
  }

  const tacticOrder = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
  ];

  const sortedTactics = Array.from(byTactic.entries()).sort((a, b) => {
    const ai = tacticOrder.indexOf(a[0]);
    const bi = tacticOrder.indexOf(b[0]);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });

  return (
    <div className="space-y-4">
      <div className="text-sm text-muted-foreground">
        Web vulnerability findings mapped to MITRE ATT&CK framework techniques. {stats.mitreAttackCoverage.length} techniques detected across {sortedTactics.length} tactics.
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {sortedTactics.map(([tactic, techniques]) => (
          <Card key={tactic} className="border-purple-500/20">
            <CardHeader className="p-3 pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Target className="w-4 h-4 text-purple-400" />
                {tactic}
              </CardTitle>
            </CardHeader>
            <CardContent className="p-3 pt-0 space-y-1">
              {techniques.map((t: any) => (
                <div key={t.techniqueId} className="flex items-center justify-between text-xs p-1.5 rounded bg-muted/20">
                  <div className="flex items-center gap-1.5">
                    <code className="text-purple-400">{t.techniqueId}</code>
                    <span className="text-muted-foreground truncate max-w-[150px]">{t.techniqueName}</span>
                  </div>
                  <Badge variant="outline" className="text-[10px]">{t.count}</Badge>
                </div>
              ))}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ─── Exploit Correlation View ─────────────────────────────────────────────────
function ExploitCorrelationView({ scans }: { scans: any[] }) {
  const completedScans = scans.filter((s: any) => s.status === "completed");

  // Get findings from all completed scans
  const allFindingsQueries = completedScans.slice(0, 5).map((s: any) =>
    trpc.webAppScanning.getFindings.useQuery({ scanId: s.id, limit: 100 })
  );

  const allFindings = allFindingsQueries.flatMap(q => q.data || []);
  const exploitableFindings = allFindings.filter((f: any) => f.exploitAvailable);

  if (exploitableFindings.length === 0) {
    return (
      <Card><CardContent className="p-8 text-center text-muted-foreground">
        <Crosshair className="w-12 h-12 mx-auto mb-3 opacity-30" />
        <p>No exploitable findings detected. Run active DAST scans to identify vulnerabilities with known exploit modules.</p>
      </CardContent></Card>
    );
  }

  return (
    <div className="space-y-4">
      <Alert className="border-red-500/30 bg-red-500/5">
        <ShieldAlert className="w-4 h-4 text-red-400" />
        <AlertDescription className="text-sm">
          <strong>{exploitableFindings.length} findings</strong> have known Metasploit exploit modules. These represent the highest-priority attack vectors for coordinated exploitation.
        </AlertDescription>
      </Alert>

      <div className="space-y-2">
        {exploitableFindings.map((f: any) => (
          <Card key={f.id} className="border-red-500/20">
            <CardContent className="p-3">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <Crosshair className="w-4 h-4 text-red-400" />
                    <span className="font-semibold text-sm">{f.alertName}</span>
                    <Badge className={`text-[10px] ${SEVERITY_COLORS[f.severity] || ""}`}>{f.severity}</Badge>
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">{f.url}</div>
                  <div className="mt-2 flex items-center gap-4 text-xs">
                    <div>
                      <span className="text-muted-foreground">Metasploit: </span>
                      <code className="text-red-400 bg-red-500/10 px-1 rounded">{f.exploitModulePath}</code>
                    </div>
                    {f.mitreAttackId && (
                      <div>
                        <span className="text-muted-foreground">ATT&CK: </span>
                        <span className="text-purple-400">{f.mitreAttackId}</span>
                      </div>
                    )}
                    {f.cweId && (
                      <div>
                        <span className="text-muted-foreground">CWE: </span>
                        <span>CWE-{f.cweId}</span>
                      </div>
                    )}
                  </div>
                </div>
                <Button variant="outline" size="sm" className="border-red-500/30 text-red-400 hover:bg-red-500/10" onClick={() => toast.info("Metasploit handoff — configure MSF RPC connection to launch exploit")}>
                  <ArrowRight className="w-3 h-3 mr-1" />Launch in MSF
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ─── New Scan Dialog ──────────────────────────────────────────────────────────
function NewScanDialog({ open, onOpenChange, onScanStarted }: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onScanStarted: (scanId: number) => void;
}) {
  const [targetUrl, setTargetUrl] = useState("");
  const [scanMode, setScanMode] = useState<"passive" | "active">("passive");
  const [scanName, setScanName] = useState("");
  const [useLLM, setUseLLM] = useState(true);
  const [techHints, setTechHints] = useState("");
  const [attackChainId, setAttackChainId] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [llmConfig, setLlmConfig] = useState<any>(null);
  const [configLoading, setConfigLoading] = useState(false);

  const startScan = trpc.webAppScanning.startScan.useMutation({
    onSuccess: (data) => {
      toast.success(`Scan started (ID: ${data.scanId})`);
      onScanStarted(data.scanId);
      onOpenChange(false);
      resetForm();
    },
    onError: (e) => toast.error(`Failed to start scan: ${e.message}`),
  });

  const generateConfig = trpc.webAppScanning.generateScanConfig.useMutation({
    onSuccess: (data) => {
      setLlmConfig(data);
      setConfigLoading(false);
      toast.success("AI scan configuration generated");
    },
    onError: (e) => {
      setConfigLoading(false);
      toast.error(`Config generation failed: ${e.message}`);
    },
  });

  const resetForm = () => {
    setTargetUrl("");
    setScanMode("passive");
    setScanName("");
    setUseLLM(true);
    setTechHints("");
    setAttackChainId("");
    setLlmConfig(null);
    setShowAdvanced(false);
  };

  const handleGenerateConfig = () => {
    if (!targetUrl) { toast.error("Enter a target URL first"); return; }
    setConfigLoading(true);
    generateConfig.mutate({
      targetUrl,
      scanMode,
      techStackHints: techHints ? techHints.split(",").map(s => s.trim()) : undefined,
    });
  };

  const handleStartScan = () => {
    if (!targetUrl) { toast.error("Enter a target URL"); return; }
    startScan.mutate({
      targetUrl,
      scanMode,
      scanType: scanMode === "passive" ? "spider_only" : "full",
      scanName: scanName || undefined,
      useLLMConfig: useLLM,
      techStackHints: techHints ? techHints.split(",").map(s => s.trim()) : undefined,
      attackChainId: attackChainId || undefined,
    });
  };

  const modeConfig = MODE_CONFIG[scanMode];
  const ModeIcon = modeConfig.icon;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Globe className="w-5 h-5 text-cyan-400" />
            New Web Application Scan
          </DialogTitle>
          <DialogDescription>
            Configure and launch an OWASP ZAP scan with AI-powered optimization.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-5">
          {/* Scan Mode Selection */}
          <div className="grid grid-cols-2 gap-3">
            {(["passive", "active"] as const).map((mode) => {
              const cfg = MODE_CONFIG[mode];
              const Icon = cfg.icon;
              return (
                <button
                  key={mode}
                  onClick={() => setScanMode(mode)}
                  className={`p-4 rounded-lg border-2 text-left transition-all ${scanMode === mode ? cfg.bg + " border-opacity-100" : "border-border/30 hover:border-border/60"}`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Icon className={`w-5 h-5 ${cfg.color}`} />
                    <span className="font-semibold text-sm">{cfg.label}</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground">{cfg.description}</p>
                </button>
              );
            })}
          </div>

          {/* Target URL */}
          <div className="space-y-2">
            <Label>Target URL</Label>
            <Input
              placeholder="https://target-webapp.example.com"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
            />
          </div>

          {/* Scan Name */}
          <div className="space-y-2">
            <Label>Scan Name (optional)</Label>
            <Input
              placeholder={`${scanMode === "passive" ? "[RECON]" : "[DAST]"} target-webapp.example.com`}
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
            />
          </div>

          {/* LLM Toggle */}
          <div className="flex items-center justify-between p-3 rounded-lg bg-muted/20 border border-border/30">
            <div className="flex items-center gap-2">
              <Brain className="w-4 h-4 text-purple-400" />
              <div>
                <div className="text-sm font-medium">AI-Powered Configuration</div>
                <div className="text-[11px] text-muted-foreground">LLM analyzes target and auto-tunes ZAP scan settings</div>
              </div>
            </div>
            <Switch checked={useLLM} onCheckedChange={setUseLLM} />
          </div>

          {/* Tech Stack Hints */}
          <div className="space-y-2">
            <Label>Technology Hints (optional, comma-separated)</Label>
            <Input
              placeholder="React, Node.js, Express, PostgreSQL"
              value={techHints}
              onChange={(e) => setTechHints(e.target.value)}
            />
            <p className="text-[10px] text-muted-foreground">Help the AI configure scan rules for specific technologies</p>
          </div>

          {/* Attack Chain ID (active mode only) */}
          {scanMode === "active" && (
            <div className="space-y-2">
              <Label>Attack Chain ID (optional)</Label>
              <Input
                placeholder="chain-001"
                value={attackChainId}
                onChange={(e) => setAttackChainId(e.target.value)}
              />
              <p className="text-[10px] text-muted-foreground">Link this scan to an existing attack chain for coordinated exploitation</p>
            </div>
          )}

          {/* AI Config Preview */}
          {useLLM && (
            <div className="space-y-2">
              <Button variant="outline" size="sm" onClick={handleGenerateConfig} disabled={configLoading || !targetUrl}>
                {configLoading ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : <Sparkles className="w-3 h-3 mr-1" />}
                Preview AI Configuration
              </Button>

              {llmConfig && (
                <Card className="border-purple-500/20 bg-purple-500/5">
                  <CardContent className="p-3 space-y-2 text-xs">
                    <div className="flex items-center gap-2 mb-2">
                      <Brain className="w-4 h-4 text-purple-400" />
                      <span className="font-semibold">AI Scan Configuration</span>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <div><span className="text-muted-foreground">Policy:</span> {llmConfig.scanPolicy}</div>
                      <div><span className="text-muted-foreground">AJAX Spider:</span> {llmConfig.useAjaxSpider ? "Yes" : "No"}</div>
                      <div><span className="text-muted-foreground">Spider Depth:</span> {llmConfig.spiderConfig?.maxDepth}</div>
                      <div><span className="text-muted-foreground">Threads:</span> {llmConfig.activeScanConfig?.threadPerHost}</div>
                      <div><span className="text-muted-foreground">Auth:</span> {llmConfig.authStrategy}</div>
                      <div><span className="text-muted-foreground">Anti-CSRF:</span> {llmConfig.activeScanConfig?.handleAntiCSRFTokens ? "Yes" : "No"}</div>
                    </div>
                    {llmConfig.technologies?.length > 0 && (
                      <div className="flex items-center gap-1 flex-wrap">
                        <span className="text-muted-foreground">Technologies:</span>
                        {llmConfig.technologies.map((t: string) => (
                          <Badge key={t} variant="outline" className="text-[10px]">{t}</Badge>
                        ))}
                      </div>
                    )}
                    <div className="p-2 rounded bg-muted/20 text-muted-foreground italic">
                      {llmConfig.rationale}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </div>

        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            onClick={handleStartScan}
            disabled={startScan.isPending || !targetUrl}
            className={scanMode === "passive" ? "bg-cyan-600 hover:bg-cyan-700" : "bg-red-600 hover:bg-red-700"}
          >
            {startScan.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <ModeIcon className="w-4 h-4 mr-2" />}
            {scanMode === "passive" ? "Start Passive Recon" : "Launch Active DAST"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
