import { useState, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  PlayCircle,
  PlusCircle,
  Trash2,
  Loader2,
  AlertCircle,
  GitBranch,
  Github,
  Gitlab,
  Settings,
  Copy,
  Check,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Code2,
  Webhook,
  Cloud,
  Search,
  FileCode,
  KeyRound,
  Eye,
  EyeOff,
  Link2,
  Unlink,
  Download,
  TrendingUp,
  TrendingDown,
  Zap,
} from "lucide-react";
import AppShell from "@/components/AppShell";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  LineChart,
  Line,
  AreaChart,
  Area,
  ReferenceLine,
} from "recharts";
import { Link, useLocation } from "wouter";
import { Clock, FileText, ExternalLink, Calendar } from "lucide-react";

// ─── Constants ───────────────────────────────────────────────────────────────

const providerIcons: Record<string, React.ReactNode> = {
  custom: <Settings className="h-4 w-4" />,
  github_actions: <Github className="h-4 w-4" />,
  jenkins: <Code2 className="h-4 w-4" />,
  gitlab_ci: <Gitlab className="h-4 w-4" />,
  azure_devops: <Cloud className="h-4 w-4" />,
};

const statusConfig: Record<string, { color: string; icon: React.ReactNode; label: string }> = {
  passed: { color: "bg-emerald-500", icon: <ShieldCheck className="h-3.5 w-3.5" />, label: "PASSED" },
  failed: { color: "bg-red-500", icon: <ShieldAlert className="h-3.5 w-3.5" />, label: "FAILED" },
  pending: { color: "bg-amber-500", icon: <Loader2 className="h-3.5 w-3.5 animate-spin" />, label: "PENDING" },
  running: { color: "bg-blue-500", icon: <Loader2 className="h-3.5 w-3.5 animate-spin" />, label: "RUNNING" },
  error: { color: "bg-red-700", icon: <AlertCircle className="h-3.5 w-3.5" />, label: "ERROR" },
};

// ─── Copy Button ─────────────────────────────────────────────────────────────

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    toast.success(label ? `${label} copied` : "Copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  }, [text, label]);

  return (
    <Button size="icon" variant="ghost" onClick={handleCopy} className="h-7 w-7 shrink-0">
      {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
    </Button>
  );
}

// ─── Run History Chart ────────────────────────────────────────────────────────

function RunHistoryChart({ pipelineId }: { pipelineId: number | null }) {
  const historyQuery = trpc.cicdPipeline.getRunHistory.useQuery(
    { pipelineId: pipelineId || undefined, days: 30 },
    { refetchInterval: 60000 }
  );

  const data = useMemo(() => historyQuery.data || [], [historyQuery.data]);

  if (!data.length && !historyQuery.isLoading) return null;

  return (
    <Card className="bg-muted/10 border-muted/20">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-sm font-medium">Pipeline Run History</CardTitle>
            <CardDescription className="text-xs">
              {pipelineId ? "Selected pipeline" : "All pipelines"} — last 30 days
            </CardDescription>
          </div>
          {historyQuery.isLoading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
        </div>
      </CardHeader>
      <CardContent className="pb-4">
        {data.length > 0 ? (
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--muted)/0.3)" vertical={false} />
              <XAxis
                dataKey="date"
                tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                tickFormatter={(v: string) => {
                  const d = new Date(v + "T00:00:00");
                  return `${d.getMonth() + 1}/${d.getDate()}`;
                }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                axisLine={false}
                tickLine={false}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "8px",
                  fontSize: "12px",
                  color: "hsl(var(--card-foreground))",
                }}
                labelFormatter={(v: string) => {
                  const d = new Date(v + "T00:00:00");
                  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
                }}
              />
              <Legend
                wrapperStyle={{ fontSize: "11px", paddingTop: "8px" }}
                iconType="circle"
                iconSize={8}
              />
              <Bar dataKey="passed" name="Passed" fill="#34d399" radius={[2, 2, 0, 0]} stackId="stack" />
              <Bar dataKey="failed" name="Failed" fill="#f87171" radius={[0, 0, 0, 0]} stackId="stack" />
              <Bar dataKey="errors" name="Errors" fill="#991b1b" radius={[2, 2, 0, 0]} stackId="stack" />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-[200px] text-muted-foreground text-sm">
            No run data yet
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Create Pipeline Dialog ──────────────────────────────────────────────────

function CreatePipelineForm({ setOpen }: { setOpen: (v: boolean) => void }) {
  const utils = trpc.useUtils();
  const [name, setName] = useState("");
  const [provider, setProvider] = useState<string>("github_actions");
  const [triggerOn, setTriggerOn] = useState<string>("push");
  const [targetUrl, setTargetUrl] = useState("");
  const [failThreshold, setFailThreshold] = useState("7.0");
  const [allowedDomains, setAllowedDomains] = useState("");
  const [scanTypes, setScanTypes] = useState<string[]>(["nuclei", "config"]);

  const createPipeline = trpc.cicdPipeline.createPipeline.useMutation({
    onSuccess: () => {
      utils.cicdPipeline.listPipelines.invalidate();
      utils.cicdPipeline.getStats.invalidate();
      toast.success("Pipeline created successfully.");
      setOpen(false);
    },
    onError: (error: any) => toast.error(`Failed: ${error.message}`),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name) { toast.error("Pipeline name is required."); return; }
    createPipeline.mutate({
      name,
      provider: provider as any,
      triggerOn: triggerOn as any,
      failThreshold: parseFloat(failThreshold) || 7.0,
      targetUrl: targetUrl || undefined,
      allowedDomains: allowedDomains ? allowedDomains.split(",").map(d => d.trim()).filter(Boolean) : undefined,
      scanTypes: scanTypes.length > 0 ? scanTypes : undefined,
    } as any);
  };

  return (
    <form onSubmit={handleSubmit} className="grid gap-4 py-4">
      <div className="grid grid-cols-4 items-center gap-4">
        <Label htmlFor="pl-name" className="text-right text-xs">Name</Label>
        <Input id="pl-name" value={name} onChange={(e) => setName(e.target.value)} className="col-span-3" placeholder="Production Security Gate" autoComplete="off" />
      </div>
      <div className="grid grid-cols-4 items-center gap-4">
        <Label className="text-right text-xs">Provider</Label>
        <Select onValueChange={setProvider} defaultValue={provider}>
          <SelectTrigger className="col-span-3"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="github_actions">GitHub Actions</SelectItem>
            <SelectItem value="gitlab_ci">GitLab CI</SelectItem>
            <SelectItem value="jenkins">Jenkins</SelectItem>
            <SelectItem value="azure_devops">Azure DevOps</SelectItem>
            <SelectItem value="custom">Custom / CodePipeline</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="grid grid-cols-4 items-center gap-4">
        <Label className="text-right text-xs">Trigger</Label>
        <Select onValueChange={setTriggerOn} defaultValue={triggerOn}>
          <SelectTrigger className="col-span-3"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="push">Push</SelectItem>
            <SelectItem value="pull_request">Pull Request</SelectItem>
            <SelectItem value="release">Release</SelectItem>
            <SelectItem value="manual">Manual</SelectItem>
            <SelectItem value="schedule">Schedule</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="grid grid-cols-4 items-center gap-4">
        <Label className="text-right text-xs">Target URL</Label>
        <Input value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} className="col-span-3" placeholder="https://staging.example.com" />
      </div>
      <div className="grid grid-cols-4 items-center gap-4">
        <Label className="text-right text-xs">CVSS Gate</Label>
        <Input type="number" step="0.1" min="0" max="10" value={failThreshold} onChange={(e) => setFailThreshold(e.target.value)} className="col-span-3" />
      </div>
      <div className="grid grid-cols-4 items-center gap-4">
        <Label className="text-right text-xs">Allowed Domains</Label>
        <Input value={allowedDomains} onChange={(e) => setAllowedDomains(e.target.value)} className="col-span-3" placeholder="*.example.com, staging.app.io" />
      </div>
      <div className="grid grid-cols-4 items-start gap-4">
        <Label className="text-right text-xs pt-2">Scan Types</Label>
        <div className="col-span-3 flex flex-wrap gap-1.5">
          {["nuclei", "zap", "burp", "config", "cspm", "container", "iac", "secrets"].map(st => (
            <Badge
              key={st}
              variant={scanTypes.includes(st) ? "default" : "outline"}
              className="cursor-pointer text-[10px]"
              onClick={() => setScanTypes(prev => prev.includes(st) ? prev.filter(s => s !== st) : [...prev, st])}
            >{st}</Badge>
          ))}
        </div>
      </div>
      <DialogFooter>
        <Button type="submit" disabled={createPipeline.isPending}>
          {createPipeline.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} Create Pipeline
        </Button>
      </DialogFooter>
    </form>
  );
}

// ─── Scan Results Panel ──────────────────────────────────────────────────────

function ScanResultsPanel({ run }: { run: any }) {
  if (!run) return null;
  const results = run.scanResults;
  const sc = statusConfig[run.status] || statusConfig.pending;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className={`h-10 w-10 rounded-lg ${sc.color} flex items-center justify-center text-white`}>
          {sc.icon}
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-semibold text-sm">{sc.label}</span>
            {run.branch && <Badge variant="outline" className="text-xs"><GitBranch className="h-3 w-3 mr-1" />{run.branch}</Badge>}
            {run.commitSha && <span className="font-mono text-xs text-muted-foreground">{run.commitSha.substring(0, 7)}</span>}
          </div>
          <p className="text-xs text-muted-foreground">
            {run.completedAt ? new Date(run.completedAt).toLocaleString() : run.createdAt ? new Date(run.createdAt).toLocaleString() : "\u2014"}
          </p>
        </div>
      </div>

      {results && (
        <div className="grid grid-cols-4 gap-2">
          <div className="bg-red-950/30 border border-red-900/30 rounded-lg p-3 text-center">
            <p className="text-2xl font-bold text-red-400">{results.criticalCount || 0}</p>
            <p className="text-[10px] uppercase tracking-wider text-red-400/70">Critical</p>
          </div>
          <div className="bg-orange-950/30 border border-orange-900/30 rounded-lg p-3 text-center">
            <p className="text-2xl font-bold text-orange-400">{results.highCount || 0}</p>
            <p className="text-[10px] uppercase tracking-wider text-orange-400/70">High</p>
          </div>
          <div className="bg-amber-950/30 border border-amber-900/30 rounded-lg p-3 text-center">
            <p className="text-2xl font-bold text-amber-400">{results.mediumCount || 0}</p>
            <p className="text-[10px] uppercase tracking-wider text-amber-400/70">Medium</p>
          </div>
          <div className="bg-blue-950/30 border border-blue-900/30 rounded-lg p-3 text-center">
            <p className="text-2xl font-bold text-blue-400">{results.lowCount || 0}</p>
            <p className="text-[10px] uppercase tracking-wider text-blue-400/70">Low</p>
          </div>
        </div>
      )}

      {results?.maxCvss !== undefined && (
        <div className="flex items-center justify-between bg-muted/30 rounded-lg px-4 py-2">
          <span className="text-xs text-muted-foreground">Max CVSS Score</span>
          <span className={`font-mono font-bold ${results.maxCvss >= 7 ? "text-red-400" : results.maxCvss >= 4 ? "text-amber-400" : "text-emerald-400"}`}>
            {results.maxCvss.toFixed(1)}
          </span>
        </div>
      )}

      {/* Baseline Comparison */}
      {results?.baselineCompared && (
        <div className="grid grid-cols-2 gap-2">
          <div className="bg-rose-950/20 border border-rose-900/30 rounded-lg p-3 text-center">
            <p className="text-xl font-bold text-rose-400">{results.newFindings ?? 0}</p>
            <p className="text-[10px] uppercase tracking-wider text-rose-400/70">New Findings</p>
          </div>
          <div className="bg-emerald-950/20 border border-emerald-900/30 rounded-lg p-3 text-center">
            <p className="text-xl font-bold text-emerald-400">{results.fixedFindings ?? 0}</p>
            <p className="text-[10px] uppercase tracking-wider text-emerald-400/70">Fixed Since Baseline</p>
          </div>
        </div>
      )}

      {/* SBOM Artifact */}
      {results?.sbomUrl && (
        <div className="flex items-center justify-between bg-muted/30 rounded-lg px-4 py-2">
          <div>
            <span className="text-xs text-muted-foreground">SBOM Artifact</span>
            {results.sbomPackageCount && <span className="text-[10px] text-muted-foreground ml-2">({results.sbomPackageCount} packages)</span>}
          </div>
          <a href={results.sbomUrl} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-400 hover:underline">Download CycloneDX JSON</a>
        </div>
      )}

      {results?.findings?.length > 0 && (
        <div className="space-y-1 max-h-64 overflow-y-auto">
          <p className="text-xs font-medium text-muted-foreground mb-2">Findings ({results.findings.length})</p>
          {results.findings.slice(0, 20).map((f: any, i: number) => (
            <div key={i} className="flex items-start gap-2 p-2 rounded bg-muted/20 hover:bg-muted/40 transition-colors">
              <Badge variant="outline" className={`text-[10px] shrink-0 ${
                f.severity === "critical" ? "border-red-500 text-red-400" :
                f.severity === "high" ? "border-orange-500 text-orange-400" :
                f.severity === "medium" ? "border-amber-500 text-amber-400" :
                "border-blue-500 text-blue-400"
              }`}>{f.severity?.toUpperCase()}</Badge>
              <div className="min-w-0">
                <p className="text-xs font-medium truncate">{f.title}</p>
                <p className="text-[10px] text-muted-foreground truncate">{f.url}</p>
              </div>
              <Badge variant="outline" className="text-[10px] shrink-0 ml-auto">{f.scanner}</Badge>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Webhook Config Panel ────────────────────────────────────────────────────

function WebhookConfigPanel({ pipelineId }: { pipelineId: number }) {
  const [showSecret, setShowSecret] = useState(false);
  const webhookQuery = trpc.cicdPipeline.getWebhookConfig.useQuery({ pipelineId });
  const regenMutation = trpc.cicdPipeline.regenerateWebhookSecret.useMutation({
    onSuccess: () => {
      webhookQuery.refetch();
      toast.success("Webhook secret regenerated");
    },
  });

  if (webhookQuery.isLoading) return <div className="flex justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>;
  if (webhookQuery.isError) return <Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>{webhookQuery.error.message}</AlertDescription></Alert>;

  const config = webhookQuery.data;
  if (!config) return null;

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label className="text-xs text-muted-foreground">Webhook URL</Label>
        <div className="flex items-center gap-2 bg-muted/30 rounded-lg px-3 py-2">
          <Webhook className="h-4 w-4 text-muted-foreground shrink-0" />
          <code className="text-xs font-mono flex-1 truncate">{config.webhookUrl || "Configure your app URL first"}</code>
          <CopyButton text={config.webhookUrl} label="Webhook URL" />
        </div>
      </div>

      <div className="space-y-2">
        <Label className="text-xs text-muted-foreground">Webhook Secret (HMAC-SHA256)</Label>
        <div className="flex items-center gap-2 bg-muted/30 rounded-lg px-3 py-2">
          <KeyRound className="h-4 w-4 text-muted-foreground shrink-0" />
          <code className="text-xs font-mono flex-1 truncate">
            {showSecret ? config.webhookSecret : "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"}
          </code>
          <Button size="icon" variant="ghost" className="h-7 w-7 shrink-0" onClick={() => setShowSecret(!showSecret)}>
            {showSecret ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
          </Button>
          <CopyButton text={config.webhookSecret} label="Secret" />
          <Button size="icon" variant="ghost" className="h-7 w-7 shrink-0" onClick={() => regenMutation.mutate({ pipelineId })} disabled={regenMutation.isPending}>
            <RefreshCw className={`h-3.5 w-3.5 ${regenMutation.isPending ? "animate-spin" : ""}`} />
          </Button>
        </div>
      </div>

      <Alert className="border-amber-900/30 bg-amber-950/20">
        <AlertCircle className="h-4 w-4 text-amber-400" />
        <AlertTitle className="text-amber-400 text-xs">Signature Verification</AlertTitle>
        <AlertDescription className="text-xs text-amber-400/70">
          Include the HMAC-SHA256 signature in the <code className="bg-amber-900/30 px-1 rounded">X-Hub-Signature-256</code> header.
          Compute: <code className="bg-amber-900/30 px-1 rounded">sha256=HMAC(secret, payload)</code>
        </AlertDescription>
      </Alert>
    </div>
  );
}

// ─── YAML Snippet Panel ──────────────────────────────────────────────────────

function YamlSnippetPanel({ pipelineId }: { pipelineId: number }) {
  const [provider, setProvider] = useState<"github_actions" | "gitlab_ci" | "codepipeline" | "jenkins" | "azure_devops">("github_actions");

  const snippetQuery = trpc.cicdPipeline.generateYamlSnippet.useQuery(
    { pipelineId, provider },
    { enabled: !!pipelineId }
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {([
          { id: "github_actions" as const, label: "GitHub Actions", icon: <Github className="h-3.5 w-3.5" /> },
          { id: "gitlab_ci" as const, label: "GitLab CI", icon: <Gitlab className="h-3.5 w-3.5" /> },
          { id: "codepipeline" as const, label: "CodePipeline", icon: <Cloud className="h-3.5 w-3.5" /> },
          { id: "jenkins" as const, label: "Jenkins", icon: <Code2 className="h-3.5 w-3.5" /> },
          { id: "azure_devops" as const, label: "Azure DevOps", icon: <Cloud className="h-3.5 w-3.5" /> },
        ]).map((p) => (
          <Button
            key={p.id}
            size="sm"
            variant={provider === p.id ? "default" : "outline"}
            onClick={() => setProvider(p.id)}
            className="text-xs gap-1.5"
          >
            {p.icon} {p.label}
          </Button>
        ))}
      </div>

      {snippetQuery.isLoading ? (
        <div className="flex justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>
      ) : snippetQuery.isError ? (
        <Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>{snippetQuery.error.message}</AlertDescription></Alert>
      ) : (
        <div className="relative">
          <div className="absolute top-2 right-2 z-10">
            <CopyButton text={snippetQuery.data?.yaml || ""} label="YAML snippet" />
          </div>
          <pre className="bg-zinc-950 border border-zinc-800 rounded-lg p-4 text-xs font-mono text-zinc-300 overflow-x-auto max-h-96 whitespace-pre-wrap">
            {snippetQuery.data?.yaml || "No snippet available"}
          </pre>
        </div>
      )}
    </div>
  );
}// ─── Threat Intelligence Panel (P3) ─────────────────────────────────────────────

const SECTOR_OPTIONS = [
  "financial", "healthcare", "government", "defense", "energy",
  "technology", "telecommunications", "manufacturing", "retail",
  "education", "transportation", "media", "legal", "aerospace",
];

const KILL_CHAIN_COLORS: Record<string, string> = {
  "Reconnaissance": "bg-slate-600",
  "Resource Development": "bg-slate-500",
  "Initial Access": "bg-red-600",
  "Execution": "bg-red-500",
  "Persistence": "bg-orange-600",
  "Privilege Escalation": "bg-orange-500",
  "Defense Evasion": "bg-amber-600",
  "Credential Access": "bg-amber-500",
  "Discovery": "bg-yellow-600",
  "Lateral Movement": "bg-cyan-600",
  "Collection": "bg-blue-600",
  "Command and Control": "bg-indigo-600",
  "Exfiltration": "bg-violet-600",
  "Impact": "bg-rose-700",
};

function ThreatIntelPanel({
  pipelineId,
  selectedRun,
  sectorContext,
}: {
  pipelineId: number;
  selectedRun: any;
  sectorContext?: string | null;
}) {
  const [sector, setSector] = useState(sectorContext || "");
  const utils = trpc.useUtils();

  // P2: Sector context mutation
  const updateSector = trpc.cicdPipeline.updateSectorContext.useMutation({
    onSuccess: () => {
      utils.cicdPipeline.listPipelines.invalidate();
      toast.success(`Sector context updated to "${sector}"`);
    },
    onError: (e: any) => toast.error(`Failed: ${e.message}`),
  });

  // P3: Run-level threat context
  const threatCtxQuery = trpc.cicdPipeline.getRunThreatContext.useQuery(
    { runId: selectedRun?.id || 0 },
    { enabled: !!selectedRun?.id }
  );

  // P3: Cross-run threat summary
  const summaryQuery = trpc.cicdPipeline.getThreatSummaryAcrossRuns.useQuery(
    { pipelineId, days: 30 },
    { enabled: !!pipelineId }
  );

  // P1: Pre-scan template recommendations
  const templatesQuery = trpc.cicdPipeline.getPreScanTemplates.useQuery(
    { pipelineId, sector: sector || undefined },
    { enabled: !!pipelineId }
  );

  // Threat Trend Sparklines
  const trendQuery = trpc.cicdPipeline.getThreatTrendData.useQuery(
    { pipelineId, days: 30 },
    { enabled: !!pipelineId && !selectedRun }
  );

  // Gate Escalation Config
  const gateConfigQuery = trpc.cicdPipeline.getGateEscalationConfig.useQuery(
    { pipelineId },
    { enabled: !!pipelineId }
  );
  const [gateConfig, setGateConfig] = useState<{
    escalateOnRansomware: boolean;
    escalateOnApt: boolean;
    escalateOnActorCount: number;
    escalateOnExposureScore: number;
  } | null>(null);

  // Sync gate config from query
  React.useEffect(() => {
    if (gateConfigQuery.data && !gateConfig) {
      setGateConfig(gateConfigQuery.data);
    }
  }, [gateConfigQuery.data]);

  const updateGateConfig = trpc.cicdPipeline.updateGateEscalationConfig.useMutation({
    onSuccess: () => {
      utils.cicdPipeline.getGateEscalationConfig.invalidate();
      toast.success("Gate escalation config updated");
    },
    onError: (e: any) => toast.error(`Failed: ${e.message}`),
  });

  // Engagement Auto-Import
  const [importEngagementId, setImportEngagementId] = useState("");
  const autoImport = trpc.cicdPipeline.autoImportToEngagement.useMutation({
    onSuccess: (data: any) => {
      toast.success(data.message || `Imported ${data.imported} findings`);
    },
    onError: (e: any) => toast.error(`Import failed: ${e.message}`),
  });

  const tc = threatCtxQuery.data;
  const summary = summaryQuery.data;
  const templates = templatesQuery.data;
  const trend = trendQuery.data;

  return (
    <div className="space-y-5">
      {/* Sector Context Config */}
      <div className="flex items-end gap-3 p-3 rounded-lg border border-border/50 bg-muted/20">
        <div className="flex-1 min-w-0">
          <Label className="text-xs text-muted-foreground mb-1 block">Industry Sector (for threat-informed scanning)</Label>
          <Select value={sector} onValueChange={setSector}>
            <SelectTrigger className="h-8 text-xs">
              <SelectValue placeholder="Select sector..." />
            </SelectTrigger>
            <SelectContent>
              {SECTOR_OPTIONS.map(s => (
                <SelectItem key={s} value={s} className="text-xs capitalize">{s}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <Button
          size="sm"
          variant="outline"
          className="text-xs h-8"
          disabled={!sector || updateSector.isPending}
          onClick={() => updateSector.mutate({ pipelineId, sector })}
        >
          {updateSector.isPending ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : null}
          Apply
        </Button>
      </div>

      {/* Run-Level Threat Context */}
      {selectedRun ? (
        threatCtxQuery.isLoading ? (
          <div className="flex justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>
        ) : tc ? (
          <div className="space-y-4">
            {/* Summary Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              <div className="bg-red-950/20 border border-red-900/30 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-red-400">{tc.summary?.uniqueActorsMatched || 0}</p>
                <p className="text-[10px] uppercase tracking-wider text-red-400/70">Actors Matched</p>
              </div>
              <div className="bg-amber-950/20 border border-amber-900/30 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-amber-400">{tc.summary?.severityBoostedCount || 0}</p>
                <p className="text-[10px] uppercase tracking-wider text-amber-400/70">Severity Boosted</p>
              </div>
              <div className="bg-violet-950/20 border border-violet-900/30 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-violet-400">{tc.summary?.actorExposureScore || 0}</p>
                <p className="text-[10px] uppercase tracking-wider text-violet-400/70">Exposure Score</p>
              </div>
              <div className="bg-cyan-950/20 border border-cyan-900/30 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-cyan-400">{tc.summary?.killChainCoverage || 0}%</p>
                <p className="text-[10px] uppercase tracking-wider text-cyan-400/70">Kill Chain Coverage</p>
              </div>
            </div>

            {/* Risk Flags */}
            {(tc.summary?.ransomwareRiskFindings > 0 || tc.summary?.aptRiskFindings > 0) && (
              <div className="flex gap-2">
                {tc.summary.ransomwareRiskFindings > 0 && (
                  <Alert className="border-rose-900/40 bg-rose-950/20 flex-1">
                    <ShieldAlert className="h-4 w-4 text-rose-400" />
                    <AlertTitle className="text-rose-400 text-xs">Ransomware Risk</AlertTitle>
                    <AlertDescription className="text-[10px] text-rose-400/70">
                      {tc.summary.ransomwareRiskFindings} finding(s) linked to known ransomware groups
                    </AlertDescription>
                  </Alert>
                )}
                {tc.summary.aptRiskFindings > 0 && (
                  <Alert className="border-violet-900/40 bg-violet-950/20 flex-1">
                    <Shield className="h-4 w-4 text-violet-400" />
                    <AlertTitle className="text-violet-400 text-xs">APT Risk</AlertTitle>
                    <AlertDescription className="text-[10px] text-violet-400/70">
                      {tc.summary.aptRiskFindings} finding(s) linked to APT groups
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            )}

            {/* Actor Exposure Table */}
            {tc.actorExposure?.length > 0 && (
              <div>
                <p className="text-xs font-medium mb-2 flex items-center gap-1.5">
                  <ShieldAlert className="h-3.5 w-3.5 text-red-400" />
                  Threat Actor Exposure ({tc.actorExposure.length} groups)
                </p>
                <div className="max-h-56 overflow-y-auto rounded-lg border border-border/50">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="text-[10px]">Group</TableHead>
                        <TableHead className="text-[10px]">Type</TableHead>
                        <TableHead className="text-[10px]">Level</TableHead>
                        <TableHead className="text-[10px]">Origin</TableHead>
                        <TableHead className="text-[10px] text-right">Findings</TableHead>
                        <TableHead className="text-[10px] text-right">Score</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {tc.actorExposure.slice(0, 15).map((actor: any) => (
                        <TableRow key={actor.groupId} className="hover:bg-muted/20">
                          <TableCell className="text-xs font-medium">
                            <Link href={`/threat-group/${encodeURIComponent(actor.groupId || actor.groupName)}`} className="hover:underline hover:text-violet-400 transition-colors cursor-pointer inline-flex items-center gap-1">
                              {actor.groupName}
                              <ExternalLink className="h-2.5 w-2.5 opacity-50" />
                            </Link>
                            {actor.active && <Badge variant="outline" className="ml-1.5 text-[8px] border-emerald-500 text-emerald-400">ACTIVE</Badge>}
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className={`text-[9px] ${
                              actor.groupType === "apt" ? "border-violet-500 text-violet-400" :
                              actor.groupType === "ransomware" ? "border-rose-500 text-rose-400" :
                              actor.groupType === "cybercrime" ? "border-amber-500 text-amber-400" :
                              "border-blue-500 text-blue-400"
                            }`}>{actor.groupType?.toUpperCase()}</Badge>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className={`text-[9px] ${
                              actor.threatLevel === "critical" ? "border-red-500 text-red-400" :
                              actor.threatLevel === "high" ? "border-orange-500 text-orange-400" :
                              actor.threatLevel === "medium" ? "border-amber-500 text-amber-400" :
                              "border-blue-500 text-blue-400"
                            }`}>{actor.threatLevel?.toUpperCase()}</Badge>
                          </TableCell>
                          <TableCell className="text-[10px] text-muted-foreground">{actor.origin}</TableCell>
                          <TableCell className="text-xs text-right font-mono">{actor.findingCount}</TableCell>
                          <TableCell className="text-right">
                            <span className={`text-xs font-bold ${
                              actor.exposureScore >= 70 ? "text-red-400" :
                              actor.exposureScore >= 40 ? "text-amber-400" :
                              "text-emerald-400"
                            }`}>{actor.exposureScore}</span>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            )}

            {/* Kill Chain Coverage Map */}
            {tc.killChainMap?.length > 0 && (
              <div>
                <p className="text-xs font-medium mb-2 flex items-center gap-1.5">
                  <Shield className="h-3.5 w-3.5 text-cyan-400" />
                  MITRE ATT&CK Kill Chain Coverage
                </p>
                <div className="grid grid-cols-7 gap-1">
                  {tc.killChainMap.map((kc: any) => {
                    const hasFindings = kc.findingCount > 0;
                    const bgColor = hasFindings
                      ? (KILL_CHAIN_COLORS[kc.phase] || "bg-gray-600")
                      : "bg-muted/20";
                    return (
                      <div
                        key={kc.phase}
                        className={`rounded-lg p-2 text-center transition-all ${
                          hasFindings
                            ? `${bgColor} text-white shadow-sm`
                            : "bg-muted/20 text-muted-foreground/40"
                        }`}
                        title={`${kc.phase} (${kc.tacticId})\n${kc.findingCount} findings\n${kc.activeGroups?.join(", ") || "No groups"}`}
                      >
                        <p className="text-[8px] font-medium leading-tight truncate">{kc.phase}</p>
                        <p className="text-sm font-bold mt-0.5">{kc.findingCount}</p>
                        <p className="text-[7px] opacity-70">{kc.tacticId}</p>
                        {kc.hasBoostedFindings && (
                          <div className="w-1.5 h-1.5 rounded-full bg-amber-400 mx-auto mt-0.5" title="Contains severity-boosted findings" />
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Severity-Boosted Findings */}
            {tc.enrichedFindings?.filter((f: any) => f.severityBoosted)?.length > 0 && (
              <div>
                <p className="text-xs font-medium mb-2 flex items-center gap-1.5">
                  <AlertCircle className="h-3.5 w-3.5 text-amber-400" />
                  Severity-Boosted Findings ({tc.enrichedFindings.filter((f: any) => f.severityBoosted).length})
                </p>
                <div className="space-y-1 max-h-48 overflow-y-auto">
                  {tc.enrichedFindings.filter((f: any) => f.severityBoosted).slice(0, 10).map((f: any, i: number) => (
                    <div key={i} className="flex items-start gap-2 p-2 rounded bg-amber-950/20 border border-amber-900/20">
                      <div className="flex items-center gap-1 shrink-0">
                        <Badge variant="outline" className="text-[9px] border-muted text-muted-foreground line-through">{f.originalSeverity?.toUpperCase()}</Badge>
                        <span className="text-[10px] text-muted-foreground">&rarr;</span>
                        <Badge variant="outline" className={`text-[9px] ${
                          f.severity === "critical" ? "border-red-500 text-red-400" :
                          f.severity === "high" ? "border-orange-500 text-orange-400" :
                          "border-amber-500 text-amber-400"
                        }`}>{f.severity?.toUpperCase()}</Badge>
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-[10px] font-medium truncate">{f.title}</p>
                        <p className="text-[9px] text-amber-400/70 truncate">{f.boostReason}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="text-center text-muted-foreground py-6 text-sm">
            <Shield className="h-8 w-8 mx-auto mb-2 opacity-20" />
            No threat intelligence data for this run.
            <p className="text-[10px] mt-1">Threat correlation runs automatically during scans.</p>
          </div>
        )
      ) : (
        /* No run selected — show cross-run summary */
        <div className="space-y-4">
          {summaryQuery.isLoading ? (
            <div className="flex justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>
          ) : summary && summary.runsAnalyzed > 0 ? (
            <>
              <Alert className="border-cyan-900/30 bg-cyan-950/20">
                <Shield className="h-4 w-4 text-cyan-400" />
                <AlertTitle className="text-cyan-400 text-xs">Cross-Run Threat Summary (Last 30 Days)</AlertTitle>
                <AlertDescription className="text-[10px] text-cyan-400/70">
                  Aggregated threat intelligence across {summary.runsAnalyzed} runs. Select a specific run from the Runs tab for detailed per-finding analysis.
                </AlertDescription>
              </Alert>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <div className="bg-red-950/20 border border-red-900/30 rounded-lg p-3 text-center">
                  <p className="text-xl font-bold text-red-400">{summary.totalActorsMatched}</p>
                  <p className="text-[10px] uppercase tracking-wider text-red-400/70">Total Actor Hits</p>
                </div>
                <div className="bg-amber-950/20 border border-amber-900/30 rounded-lg p-3 text-center">
                  <p className="text-xl font-bold text-amber-400">{summary.totalBoosted}</p>
                  <p className="text-[10px] uppercase tracking-wider text-amber-400/70">Severity Boosts</p>
                </div>
                <div className="bg-rose-950/20 border border-rose-900/30 rounded-lg p-3 text-center">
                  <p className="text-xl font-bold text-rose-400">{summary.totalRansomwareRisk}</p>
                  <p className="text-[10px] uppercase tracking-wider text-rose-400/70">Ransomware Flags</p>
                </div>
                <div className="bg-violet-950/20 border border-violet-900/30 rounded-lg p-3 text-center">
                  <p className="text-xl font-bold text-violet-400">{summary.totalAptRisk}</p>
                  <p className="text-[10px] uppercase tracking-wider text-violet-400/70">APT Flags</p>
                </div>
              </div>

              {/* Threat Trend Sparklines */}
              {trend && trend.trendPoints.length >= 2 && (
                <div>
                  <p className="text-xs font-medium mb-3 flex items-center gap-1.5">
                    <TrendingUp className="h-3.5 w-3.5 text-cyan-400" />
                    Threat Trends (Last 30 Days — {trend.totalRuns} runs)
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {/* Actor Exposure Score Trend */}
                    <div className="rounded-lg border border-border/50 bg-muted/10 p-3">
                      <p className="text-[10px] uppercase tracking-wider text-red-400/70 mb-2">Actor Exposure Score</p>
                      <ResponsiveContainer width="100%" height={80}>
                        <AreaChart data={trend.trendPoints}>
                          <defs>
                            <linearGradient id="exposureGrad" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#f87171" stopOpacity={0.3} />
                              <stop offset="95%" stopColor="#f87171" stopOpacity={0} />
                            </linearGradient>
                          </defs>
                          <Area type="monotone" dataKey="actorExposureScore" stroke="#f87171" fill="url(#exposureGrad)" strokeWidth={1.5} dot={false} />
                          <ReferenceLine y={60} stroke="#ef4444" strokeDasharray="3 3" strokeOpacity={0.4} />
                          <Tooltip
                            contentStyle={{ background: '#1a1a2e', border: '1px solid #333', borderRadius: '8px', fontSize: '10px' }}
                            labelFormatter={(_, payload) => {
                              const p = payload?.[0]?.payload;
                              return p ? `Run #${p.runId} — ${new Date(p.date).toLocaleDateString()}` : '';
                            }}
                          />
                        </AreaChart>
                      </ResponsiveContainer>
                      <div className="flex justify-between text-[9px] text-muted-foreground mt-1">
                        <span>Latest: <span className={`font-bold ${(trend.trendPoints[trend.trendPoints.length - 1]?.actorExposureScore || 0) >= 60 ? 'text-red-400' : 'text-emerald-400'}`}>{trend.trendPoints[trend.trendPoints.length - 1]?.actorExposureScore || 0}</span></span>
                        <span className="opacity-50">Threshold: 60</span>
                      </div>
                    </div>

                    {/* Kill Chain Coverage Trend */}
                    <div className="rounded-lg border border-border/50 bg-muted/10 p-3">
                      <p className="text-[10px] uppercase tracking-wider text-cyan-400/70 mb-2">Kill Chain Coverage %</p>
                      <ResponsiveContainer width="100%" height={80}>
                        <AreaChart data={trend.trendPoints}>
                          <defs>
                            <linearGradient id="kcGrad" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.3} />
                              <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                            </linearGradient>
                          </defs>
                          <Area type="monotone" dataKey="killChainCoverage" stroke="#22d3ee" fill="url(#kcGrad)" strokeWidth={1.5} dot={false} />
                          <Tooltip
                            contentStyle={{ background: '#1a1a2e', border: '1px solid #333', borderRadius: '8px', fontSize: '10px' }}
                            labelFormatter={(_, payload) => {
                              const p = payload?.[0]?.payload;
                              return p ? `Run #${p.runId} — ${new Date(p.date).toLocaleDateString()}` : '';
                            }}
                          />
                        </AreaChart>
                      </ResponsiveContainer>
                      <div className="flex justify-between text-[9px] text-muted-foreground mt-1">
                        <span>Latest: <span className="font-bold text-cyan-400">{trend.trendPoints[trend.trendPoints.length - 1]?.killChainCoverage || 0}%</span></span>
                        <span className="opacity-50">{trend.totalRuns} data points</span>
                      </div>
                    </div>

                    {/* Unique Actors Trend */}
                    <div className="rounded-lg border border-border/50 bg-muted/10 p-3">
                      <p className="text-[10px] uppercase tracking-wider text-violet-400/70 mb-2">Unique Actors Matched</p>
                      <ResponsiveContainer width="100%" height={80}>
                        <LineChart data={trend.trendPoints}>
                          <Line type="monotone" dataKey="uniqueActors" stroke="#a78bfa" strokeWidth={1.5} dot={{ r: 2, fill: '#a78bfa' }} />
                          <Tooltip
                            contentStyle={{ background: '#1a1a2e', border: '1px solid #333', borderRadius: '8px', fontSize: '10px' }}
                            labelFormatter={(_, payload) => {
                              const p = payload?.[0]?.payload;
                              return p ? `Run #${p.runId} — ${new Date(p.date).toLocaleDateString()}` : '';
                            }}
                          />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>

                    {/* Ransomware + APT Risk Trend */}
                    <div className="rounded-lg border border-border/50 bg-muted/10 p-3">
                      <p className="text-[10px] uppercase tracking-wider text-rose-400/70 mb-2">Risk Flags per Run</p>
                      <ResponsiveContainer width="100%" height={80}>
                        <BarChart data={trend.trendPoints} barGap={0} barCategoryGap="20%">
                          <Bar dataKey="ransomwareRisk" fill="#fb7185" radius={[2, 2, 0, 0]} name="Ransomware" />
                          <Bar dataKey="aptRisk" fill="#a78bfa" radius={[2, 2, 0, 0]} name="APT" />
                          <Tooltip
                            contentStyle={{ background: '#1a1a2e', border: '1px solid #333', borderRadius: '8px', fontSize: '10px' }}
                            labelFormatter={(_, payload) => {
                              const p = payload?.[0]?.payload;
                              return p ? `Run #${p.runId} — ${new Date(p.date).toLocaleDateString()}` : '';
                            }}
                          />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                </div>
              )}

              {/* Top Actors Across Runs */}
              {summary.topActors?.length > 0 && (
                <div>
                  <p className="text-xs font-medium mb-2">Most Frequently Matched Actors</p>
                  <div className="space-y-1">
                    {summary.topActors.slice(0, 8).map((actor: any, i: number) => (
                      <div key={i} className="flex items-center gap-2 p-2 rounded bg-muted/20 hover:bg-muted/30 transition-colors">
                        <span className="text-[10px] text-muted-foreground w-5 text-right">#{i + 1}</span>
                        <span className="text-xs font-medium flex-1">{actor.name}</span>
                        <Badge variant="outline" className={`text-[8px] ${
                          actor.type === "apt" ? "border-violet-500 text-violet-400" :
                          actor.type === "ransomware" ? "border-rose-500 text-rose-400" :
                          "border-amber-500 text-amber-400"
                        }`}>{actor.type?.toUpperCase()}</Badge>
                        <Badge variant="outline" className={`text-[8px] ${
                          actor.threatLevel === "critical" ? "border-red-500 text-red-400" :
                          actor.threatLevel === "high" ? "border-orange-500 text-orange-400" :
                          "border-amber-500 text-amber-400"
                        }`}>{actor.threatLevel}</Badge>
                        <span className="text-xs font-mono text-muted-foreground">{actor.count} hits</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Kill Chain Summary */}
              {summary.killChainSummary?.length > 0 && (
                <div>
                  <p className="text-xs font-medium mb-2">Kill Chain Phase Frequency</p>
                  <div className="space-y-1">
                    {summary.killChainSummary.map((kc: any, i: number) => {
                      const maxCount = summary.killChainSummary[0]?.count || 1;
                      const pct = Math.round((kc.count / maxCount) * 100);
                      return (
                        <div key={i} className="flex items-center gap-2">
                          <span className="text-[10px] text-muted-foreground w-28 text-right truncate">{kc.phase}</span>
                          <div className="flex-1 h-4 bg-muted/20 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${KILL_CHAIN_COLORS[kc.phase] || "bg-gray-600"}`}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                          <span className="text-[10px] font-mono text-muted-foreground w-8 text-right">{kc.count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="text-center text-muted-foreground py-6 text-sm">
              <Shield className="h-8 w-8 mx-auto mb-2 opacity-20" />
              No threat intelligence data yet.
              <p className="text-[10px] mt-1">Run a scan to generate threat actor correlation data.</p>
            </div>
          )}
        </div>
      )}

      {/* P1: Template Recommendations */}
      {templates && (templates.priorityCVEs?.length > 0 || templates.templateTags?.length > 0) && (
        <div className="border-t border-border/30 pt-4">
          <p className="text-xs font-medium mb-2 flex items-center gap-1.5">
            <Search className="h-3.5 w-3.5 text-emerald-400" />
            Threat-Informed Template Recommendations
          </p>
          <p className="text-[10px] text-muted-foreground mb-3">
            Based on {templates.targetedGroups?.length || 0} active threat groups{sector ? ` targeting the ${sector} sector` : ""}.
          </p>

          {templates.templateTags?.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mb-3">
              {templates.templateTags.map((tag: string) => (
                <Badge key={tag} variant="outline" className="text-[9px] border-emerald-500/50 text-emerald-400">{tag}</Badge>
              ))}
            </div>
          )}

          {templates.priorityCVEs?.length > 0 && (
            <div className="max-h-40 overflow-y-auto space-y-1">
              {templates.priorityCVEs.slice(0, 15).map((cve: string) => (
                <div key={cve} className="flex items-center gap-2 p-1.5 rounded bg-muted/20 hover:bg-muted/30 transition-colors">
                  <Badge variant="outline" className="text-[9px] font-mono border-red-500/50 text-red-400">{cve}</Badge>
                  <span className="text-[10px] text-muted-foreground">Priority scan target</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Gate Escalation Configuration */}
      <div className="border-t border-border/30 pt-4">
        <p className="text-xs font-medium mb-3 flex items-center gap-1.5">
          <Zap className="h-3.5 w-3.5 text-amber-400" />
          Auto-Gate Escalation Rules
        </p>
        <p className="text-[10px] text-muted-foreground mb-3">
          Automatically fail pipelines that pass CVSS threshold but have findings linked to active threat groups.
        </p>
        {gateConfig && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <label className="flex items-center gap-2 p-2.5 rounded-lg border border-border/50 bg-muted/10 cursor-pointer hover:bg-muted/20 transition-colors">
                <input
                  type="checkbox"
                  checked={gateConfig.escalateOnRansomware}
                  onChange={(e) => setGateConfig({ ...gateConfig, escalateOnRansomware: e.target.checked })}
                  className="rounded border-rose-500 text-rose-500 focus:ring-rose-500"
                />
                <div>
                  <p className="text-[11px] font-medium text-rose-400">Ransomware Risk</p>
                  <p className="text-[9px] text-muted-foreground">Fail if findings linked to ransomware groups</p>
                </div>
              </label>
              <label className="flex items-center gap-2 p-2.5 rounded-lg border border-border/50 bg-muted/10 cursor-pointer hover:bg-muted/20 transition-colors">
                <input
                  type="checkbox"
                  checked={gateConfig.escalateOnApt}
                  onChange={(e) => setGateConfig({ ...gateConfig, escalateOnApt: e.target.checked })}
                  className="rounded border-violet-500 text-violet-500 focus:ring-violet-500"
                />
                <div>
                  <p className="text-[11px] font-medium text-violet-400">APT Risk</p>
                  <p className="text-[9px] text-muted-foreground">Fail if findings linked to APT groups</p>
                </div>
              </label>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="p-2.5 rounded-lg border border-border/50 bg-muted/10">
                <Label className="text-[10px] text-muted-foreground">Actor Count Threshold</Label>
                <Input
                  type="number"
                  min={0}
                  max={50}
                  value={gateConfig.escalateOnActorCount}
                  onChange={(e) => setGateConfig({ ...gateConfig, escalateOnActorCount: parseInt(e.target.value) || 0 })}
                  className="h-7 text-xs mt-1"
                />
                <p className="text-[9px] text-muted-foreground mt-1">Fail if N+ actors matched (0 = disabled)</p>
              </div>
              <div className="p-2.5 rounded-lg border border-border/50 bg-muted/10">
                <Label className="text-[10px] text-muted-foreground">Exposure Score Threshold</Label>
                <Input
                  type="number"
                  min={0}
                  max={100}
                  value={gateConfig.escalateOnExposureScore}
                  onChange={(e) => setGateConfig({ ...gateConfig, escalateOnExposureScore: parseInt(e.target.value) || 0 })}
                  className="h-7 text-xs mt-1"
                />
                <p className="text-[9px] text-muted-foreground mt-1">Fail if score >= N (0 = disabled)</p>
              </div>
            </div>
            <Button
              size="sm"
              variant="outline"
              className="text-xs h-8 w-full border-amber-500/30 text-amber-400 hover:bg-amber-950/20"
              disabled={updateGateConfig.isPending}
              onClick={() => updateGateConfig.mutate({
                pipelineId,
                ...gateConfig,
              })}
            >
              {updateGateConfig.isPending ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <Zap className="h-3 w-3 mr-1" />}
              Save Escalation Rules
            </Button>
          </div>
        )}
      </div>

      {/* Engagement Auto-Import */}
      {/* Scheduled Scans Configuration */}
      <ScheduleConfigPanel pipelineId={pipelineId} />

      {/* PDF Threat Report Export */}
      {selectedRun && (
        <div className="border-t border-border/30 pt-4">
          <p className="text-xs font-medium mb-2 flex items-center gap-1.5">
            <FileText className="h-3.5 w-3.5 text-cyan-400" />
            Export Threat Assessment Report
          </p>
          <p className="text-[10px] text-muted-foreground mb-3">
            Generate a formatted PDF threat assessment report for this CI/CD run, including actor exposure, severity boosts, and kill chain analysis.
          </p>
          <ThreatReportExportButton runId={selectedRun.id} />
        </div>
      )}

      {selectedRun && (
        <div className="border-t border-border/30 pt-4">
          <p className="text-xs font-medium mb-2 flex items-center gap-1.5">
            <Download className="h-3.5 w-3.5 text-blue-400" />
            Import Findings to Engagement
          </p>
          <p className="text-[10px] text-muted-foreground mb-3">
            Push threat-enriched findings from this run into an engagement report. Includes actor attribution, severity boosts, and kill chain context.
          </p>
          <div className="flex items-end gap-2">
            <div className="flex-1">
              <Label className="text-[10px] text-muted-foreground mb-1 block">Engagement ID</Label>
              <Input
                type="number"
                placeholder="Enter engagement ID..."
                value={importEngagementId}
                onChange={(e) => setImportEngagementId(e.target.value)}
                className="h-8 text-xs"
              />
            </div>
            <Button
              size="sm"
              variant="outline"
              className="text-xs h-8 border-blue-500/30 text-blue-400 hover:bg-blue-950/20"
              disabled={!importEngagementId || autoImport.isPending}
              onClick={() => autoImport.mutate({
                runId: selectedRun.id,
                engagementId: parseInt(importEngagementId),
              })}
            >
              {autoImport.isPending ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <Download className="h-3 w-3 mr-1" />}
              Import
            </Button>
          </div>
          {autoImport.data && (
            <Alert className="mt-2 border-emerald-900/30 bg-emerald-950/20">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              <AlertTitle className="text-emerald-400 text-xs">Import Complete</AlertTitle>
              <AlertDescription className="text-[10px] text-emerald-400/70">
                {autoImport.data.message}
              </AlertDescription>
            </Alert>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Schedule Config Panel ──────────────────────────────────────────────────────

function ScheduleConfigPanel({ pipelineId }: { pipelineId: number }) {
  const utils = trpc.useUtils();
  const scheduleQuery = trpc.cicdPipeline.getScheduleConfig.useQuery(
    { pipelineId },
    { enabled: !!pipelineId }
  );

  const [cronExpr, setCronExpr] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [enabled, setEnabled] = useState(false);
  const [initialized, setInitialized] = useState(false);

  React.useEffect(() => {
    if (scheduleQuery.data && !initialized) {
      setCronExpr(scheduleQuery.data.cronExpression || "");
      setTargetUrl(scheduleQuery.data.targetUrl || "");
      setEnabled(scheduleQuery.data.enabled);
      setInitialized(true);
    }
  }, [scheduleQuery.data, initialized]);

  const updateSchedule = trpc.cicdPipeline.updateSchedule.useMutation({
    onSuccess: (data: any) => {
      utils.cicdPipeline.getScheduleConfig.invalidate();
      utils.cicdPipeline.listPipelines.invalidate();
      toast.success(data.cronDescription
        ? `Schedule updated: ${data.cronDescription}`
        : "Schedule updated"
      );
    },
    onError: (e: any) => toast.error(`Failed: ${e.message}`),
  });

  const presets = scheduleQuery.data?.presets || [];

  return (
    <div className="border-t border-border/30 pt-4">
      <p className="text-xs font-medium mb-3 flex items-center gap-1.5">
        <Clock className="h-3.5 w-3.5 text-cyan-400" />
        Scheduled Scans
      </p>
      <p className="text-[10px] text-muted-foreground mb-3">
        Configure cron-based recurring scans. The scheduler checks every 60 seconds for due pipelines.
      </p>

      {/* Enable/Disable Toggle */}
      <div className="flex items-center gap-2 mb-3">
        <button
          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
            enabled ? 'bg-cyan-600' : 'bg-muted'
          }`}
          onClick={() => setEnabled(!enabled)}
        >
          <span
            className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
              enabled ? 'translate-x-4.5' : 'translate-x-0.5'
            }`}
          />
        </button>
        <span className="text-xs text-muted-foreground">{enabled ? "Enabled" : "Disabled"}</span>
      </div>

      {/* Preset Selector */}
      <div className="mb-3">
        <Label className="text-[10px] text-muted-foreground mb-1 block">Schedule Preset</Label>
        <Select value={cronExpr} onValueChange={(val) => setCronExpr(val)}>
          <SelectTrigger className="h-8 text-xs">
            <SelectValue placeholder="Choose a preset or enter custom..." />
          </SelectTrigger>
          <SelectContent>
            {presets.map((p: any) => (
              <SelectItem key={p.cron} value={p.cron} className="text-xs">
                {p.label} <span className="text-muted-foreground ml-1">({p.cron})</span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Custom Cron Input */}
      <div className="mb-3">
        <Label className="text-[10px] text-muted-foreground mb-1 block">Cron Expression (5-field: min hour dom mon dow)</Label>
        <Input
          placeholder="0 */6 * * *"
          value={cronExpr}
          onChange={(e) => setCronExpr(e.target.value)}
          className="h-8 text-xs font-mono"
        />
        {scheduleQuery.data?.cronDescription && (
          <p className="text-[9px] text-cyan-400/70 mt-1">{scheduleQuery.data.cronDescription}</p>
        )}
      </div>

      {/* Target URL */}
      <div className="mb-3">
        <Label className="text-[10px] text-muted-foreground mb-1 block">Target URL</Label>
        <Input
          placeholder="https://example.com"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          className="h-8 text-xs"
        />
      </div>

      {/* Status Info */}
      {scheduleQuery.data?.lastRun && (
        <div className="flex items-center gap-3 text-[10px] text-muted-foreground mb-3">
          <span>Last: {new Date(scheduleQuery.data.lastRun).toLocaleString()}</span>
          {scheduleQuery.data.nextRun && (
            <span>Next: <span className="text-cyan-400">{new Date(scheduleQuery.data.nextRun).toLocaleString()}</span></span>
          )}
        </div>
      )}

      {/* Save Button */}
      <Button
        size="sm"
        variant="outline"
        className="text-xs h-8 w-full border-cyan-500/30 text-cyan-400 hover:bg-cyan-950/20"
        disabled={!cronExpr || !targetUrl || updateSchedule.isPending}
        onClick={() => updateSchedule.mutate({
          pipelineId,
          cronExpression: cronExpr,
          enabled,
          targetUrl,
        })}
      >
        {updateSchedule.isPending ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <Calendar className="h-3 w-3 mr-1" />}
        Save Schedule
      </Button>
    </div>
  );
}

// ─── Threat Report Export Button ────────────────────────────────────────────────

function ThreatReportExportButton({ runId }: { runId: number }) {
  const reportQuery = trpc.cicdPipeline.generateThreatReport.useQuery(
    { runId },
    { enabled: false } // Manual fetch only
  );
  const [loading, setLoading] = useState(false);

  const handleExport = async () => {
    setLoading(true);
    try {
      const result = await reportQuery.refetch();
      if (result.data?.html) {
        // Open in new window for print-to-PDF
        const win = window.open('', '_blank');
        if (win) {
          win.document.write(result.data.html);
          win.document.close();
          toast.success(`Threat report generated for Run #${runId}. Use browser Print (Ctrl+P) to save as PDF.`);
        } else {
          // Fallback: download as HTML
          const blob = new Blob([result.data.html], { type: 'text/html' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `threat-report-run-${runId}.html`;
          a.click();
          URL.revokeObjectURL(url);
          toast.success(`Report downloaded as HTML. Open and print to PDF.`);
        }
      }
    } catch (err: any) {
      toast.error(`Failed to generate report: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Button
      size="sm"
      variant="outline"
      className="text-xs h-8 border-cyan-500/30 text-cyan-400 hover:bg-cyan-950/20"
      disabled={loading}
      onClick={handleExport}
    >
      {loading ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <FileText className="h-3 w-3 mr-1" />}
      Download Threat Report
    </Button>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────────

export default function CicdPipelinePage() { const [isCreateOpen, setCreateOpen] = useState(false);
  const [selectedPipelineId, setSelectedPipelineId] = useState<number | null>(null);
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState("pipelines");

  const statsQuery = trpc.cicdPipeline.getStats.useQuery();
  const pipelinesQuery = trpc.cicdPipeline.listPipelines.useQuery();
  const runsQuery = trpc.cicdPipeline.listRuns.useQuery(
    { pipelineId: selectedPipelineId || undefined } as any,
    { enabled: !!selectedPipelineId, refetchInterval: 10000 }
  );

  const selectedRun = useMemo(() => {
    if (!selectedRunId || !runsQuery.data) return null;
    return runsQuery.data.find((r: any) => r.id === selectedRunId) || null;
  }, [selectedRunId, runsQuery.data]);

  const utils = trpc.useUtils();

  const deletePipeline = trpc.cicdPipeline.deletePipeline.useMutation({
    onSuccess: () => {
      utils.cicdPipeline.listPipelines.invalidate();
      utils.cicdPipeline.getStats.invalidate();
      toast.success("Pipeline deleted.");
      if (selectedPipelineId) setSelectedPipelineId(null);
    },
    onError: (error: any) => toast.error(`Deletion failed: ${error.message}`),
  });

  const triggerRun = trpc.cicdPipeline.triggerRun.useMutation({
    onSuccess: () => {
      utils.cicdPipeline.listRuns.invalidate();
      utils.cicdPipeline.getStats.invalidate();
      toast.success("Pipeline run triggered.");
    },
    onError: (error: any) => toast.error(`Trigger failed: ${error.message}`),
  });

  const stats = useMemo(() => statsQuery.data, [statsQuery.data]);
  const selectedPipeline = useMemo(() => {
    if (!selectedPipelineId || !pipelinesQuery.data) return null;
    return pipelinesQuery.data.find((p: any) => p.id === selectedPipelineId) || null;
  }, [selectedPipelineId, pipelinesQuery.data]);

  return (
    <AppShell activePath="/cicd-pipeline">
      <div className="min-h-screen bg-background text-foreground p-4 sm:p-6 lg:p-8">
        <div className="max-w-[1600px] mx-auto space-y-6">
          {/* Header */}
          <header className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
                <GitBranch className="h-6 w-6 text-cyan-400" />
                CI/CD Security Pipeline
              </h1>
              <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
                Integrate automated security scanning into your CI/CD workflows. Trigger DAST (ZAP, Burp, Nuclei), configuration audits, CSPM cloud posture checks, container image scans, and IaC analysis with pass/fail gates.
              </p>
            </div>
            <Dialog open={isCreateOpen} onOpenChange={setCreateOpen}>
              <DialogTrigger asChild>
                <Button size="sm" className="gap-1.5"><PlusCircle className="h-4 w-4" /> New Pipeline</Button>
              </DialogTrigger>
              <DialogContent className="sm:max-w-[480px]">
                <DialogHeader>
                  <DialogTitle>Create Security Pipeline</DialogTitle>
                  <DialogDescription>Configure a new CI/CD security scanning pipeline.</DialogDescription>
                </DialogHeader>
                <CreatePipelineForm setOpen={setCreateOpen} />
              </DialogContent>
            </Dialog>
          </header>

          {/* Stats Row */}
          {stats && (
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              <Card className="bg-muted/20 border-muted/30">
                <CardContent className="p-4">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Pipelines</p>
                  <p className="text-2xl font-bold mt-1">{stats.totalPipelines}</p>
                </CardContent>
              </Card>
              <Card className="bg-muted/20 border-muted/30">
                <CardContent className="p-4">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Total Runs</p>
                  <p className="text-2xl font-bold mt-1">{stats.totalRuns}</p>
                </CardContent>
              </Card>
              <Card className="bg-emerald-950/20 border-emerald-900/30">
                <CardContent className="p-4">
                  <p className="text-[10px] uppercase tracking-wider text-emerald-400/70">Passed</p>
                  <p className="text-2xl font-bold mt-1 text-emerald-400">{stats.passedRuns}</p>
                </CardContent>
              </Card>
              <Card className="bg-red-950/20 border-red-900/30">
                <CardContent className="p-4">
                  <p className="text-[10px] uppercase tracking-wider text-red-400/70">Failed</p>
                  <p className="text-2xl font-bold mt-1 text-red-400">{stats.failedRuns}</p>
                </CardContent>
              </Card>
              <Card className="bg-muted/20 border-muted/30">
                <CardContent className="p-4">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Pass Rate</p>
                  <p className="text-2xl font-bold mt-1">{stats.passRate}%</p>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Run History Chart */}
          <RunHistoryChart pipelineId={selectedPipelineId} />

          {/* Main Content */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left Column: Pipelines List */}
            <Card className="lg:col-span-1">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm">Pipelines</CardTitle>
                <CardDescription className="text-xs">Security scanning pipelines configured for CI/CD integration.</CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                {pipelinesQuery.isLoading ? (
                  <div className="flex justify-center p-10"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>
                ) : pipelinesQuery.isError ? (
                  <div className="p-4"><Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>{pipelinesQuery.error.message}</AlertDescription></Alert></div>
                ) : !pipelinesQuery.data?.length ? (
                  <div className="text-center text-muted-foreground py-10 text-sm">
                    <GitBranch className="h-8 w-8 mx-auto mb-2 opacity-30" />
                    No pipelines configured yet.
                  </div>
                ) : (
                  <div className="divide-y divide-border">
                    {pipelinesQuery.data.map((p: any) => (
                      <div
                        key={p.id}
                        className={`flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-muted/30 transition-colors ${selectedPipelineId === p.id ? "bg-muted/40 border-l-2 border-cyan-400" : ""}`}
                        onClick={() => { setSelectedPipelineId(p.id); setSelectedRunId(null); }}
                      >
                        <div className="shrink-0">{providerIcons[p.provider] || <Settings className="h-4 w-4" />}</div>
                        <div className="min-w-0 flex-1">
                          <p className="text-sm font-medium truncate">{p.name}</p>
                          <p className="text-[10px] text-muted-foreground capitalize">
                            {p.provider?.replace("_", " ")} &middot; {p.triggerOn?.replace("_", " ")}
                            {p.scheduleEnabled && <span className="ml-1 text-cyan-400"><Clock className="h-2.5 w-2.5 inline" /> {p.scheduleCron}</span>}
                          </p>
                        </div>
                        <div className="flex items-center gap-1 shrink-0">
                          <Badge variant={p.isActive ? "default" : "outline"} className="text-[10px]">
                            {p.isActive ? "Active" : "Off"}
                          </Badge>
                          <Button size="icon" variant="ghost" className="h-7 w-7" onClick={(e) => { e.stopPropagation(); triggerRun.mutate({ pipelineId: p.id }); }}>
                            <PlayCircle className="h-3.5 w-3.5" />
                          </Button>
                          <Button size="icon" variant="ghost" className="h-7 w-7 text-destructive" onClick={(e) => { e.stopPropagation(); deletePipeline.mutate({ id: p.id }); }}>
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Right Column: Pipeline Detail */}
            <Card className="lg:col-span-2">
              {!selectedPipelineId ? (
                <div className="flex flex-col items-center justify-center h-full min-h-[400px] text-muted-foreground">
                  <Shield className="h-12 w-12 mb-3 opacity-20" />
                  <p className="text-sm">Select a pipeline to view details</p>
                  <p className="text-xs mt-1">or create a new one to get started</p>
                </div>
              ) : (
                <>
                  <CardHeader className="pb-0">
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="text-sm flex items-center gap-2">
                          {providerIcons[selectedPipeline?.provider || "custom"]}
                          {selectedPipeline?.name || "Pipeline"}
                        </CardTitle>
                        <CardDescription className="text-xs">
                          CVSS Fail Threshold: {selectedPipeline?.failThreshold ?? 7.0}
                        </CardDescription>
                      </div>
                    </div>
                  </CardHeader>

                  <CardContent className="pt-4">
                    <Tabs value={activeTab} onValueChange={setActiveTab}>
                      <TabsList className="mb-4">
                        <TabsTrigger value="pipelines" className="text-xs gap-1.5"><GitBranch className="h-3.5 w-3.5" /> Runs</TabsTrigger>
                        <TabsTrigger value="webhook" className="text-xs gap-1.5"><Webhook className="h-3.5 w-3.5" /> Webhook</TabsTrigger>
                        <TabsTrigger value="yaml" className="text-xs gap-1.5"><FileCode className="h-3.5 w-3.5" /> YAML Snippets</TabsTrigger>
                        <TabsTrigger value="results" className="text-xs gap-1.5"><Shield className="h-3.5 w-3.5" /> Results</TabsTrigger>
                        <TabsTrigger value="scan-types" className="text-xs gap-1.5"><Settings className="h-3.5 w-3.5" /> Scan Types</TabsTrigger>
                        <TabsTrigger value="threat-intel" className="text-xs gap-1.5"><ShieldAlert className="h-3.5 w-3.5" /> Threat Intel</TabsTrigger>
                      </TabsList>

                      {/* Runs Tab */}
                      <TabsContent value="pipelines" className="mt-0">
                        {runsQuery.isLoading ? (
                          <div className="flex justify-center p-10"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>
                        ) : runsQuery.isError ? (
                          <Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>{runsQuery.error.message}</AlertDescription></Alert>
                        ) : !runsQuery.data?.length ? (
                          <div className="text-center text-muted-foreground py-10 text-sm">
                            <PlayCircle className="h-8 w-8 mx-auto mb-2 opacity-30" />
                            No runs yet. Trigger a run or send a webhook.
                          </div>
                        ) : (
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead className="text-xs">Status</TableHead>
                                <TableHead className="text-xs">Branch</TableHead>
                                <TableHead className="text-xs">Commit</TableHead>
                                <TableHead className="text-xs">Findings</TableHead>
                                <TableHead className="text-xs">CVSS</TableHead>
                                <TableHead className="text-xs text-right">Completed</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {runsQuery.data.map((run: any) => {
                                const sc = statusConfig[run.status] || statusConfig.pending;
                                return (
                                  <TableRow
                                    key={run.id}
                                    className={`cursor-pointer ${selectedRunId === run.id ? "bg-muted/40" : ""}`}
                                    onClick={() => { setSelectedRunId(run.id); setActiveTab("results"); }}
                                  >
                                    <TableCell>
                                      <div className="flex items-center gap-1.5">
                                        <span className={`h-2 w-2 rounded-full ${sc.color}`} />
                                        <span className="text-xs font-medium">{sc.label}</span>
                                      </div>
                                    </TableCell>
                                    <TableCell className="text-xs">{run.branch || "\u2014"}</TableCell>
                                    <TableCell className="font-mono text-xs">{run.commitSha?.substring(0, 7) || "\u2014"}</TableCell>
                                    <TableCell className="text-xs">{run.totalTests || 0}</TableCell>
                                    <TableCell>
                                      {run.riskScore != null ? (
                                        <span className={`text-xs font-mono font-bold ${run.riskScore >= 7 ? "text-red-400" : run.riskScore >= 4 ? "text-amber-400" : "text-emerald-400"}`}>
                                          {run.riskScore.toFixed(1)}
                                        </span>
                                      ) : "\u2014"}
                                    </TableCell>
                                    <TableCell className="text-right text-xs text-muted-foreground">
                                      {run.completedAt ? new Date(run.completedAt).toLocaleString() : "\u2014"}
                                    </TableCell>
                                  </TableRow>
                                );
                              })}
                            </TableBody>
                          </Table>
                        )}
                      </TabsContent>

                      {/* Webhook Tab */}
                      <TabsContent value="webhook" className="mt-0">
                        <WebhookConfigPanel pipelineId={selectedPipelineId} />
                      </TabsContent>

                      {/* YAML Snippets Tab */}
                      <TabsContent value="yaml" className="mt-0">
                        <YamlSnippetPanel pipelineId={selectedPipelineId} />
                      </TabsContent>

                      {/* Results Tab */}
                      <TabsContent value="results" className="mt-0">
                        {selectedRun ? (
                          <ScanResultsPanel run={selectedRun} />
                        ) : (
                          <div className="text-center text-muted-foreground py-10 text-sm">
                            <Search className="h-8 w-8 mx-auto mb-2 opacity-30" />
                            Select a run from the Runs tab to view detailed results.
                          </div>
                        )}
                      </TabsContent>

                      {/* Threat Intel Tab */}
                      <TabsContent value="threat-intel" className="mt-0">
                        <ThreatIntelPanel
                          pipelineId={selectedPipelineId}
                          selectedRun={selectedRun}
                          sectorContext={selectedPipeline?.sectorContext}
                        />
                      </TabsContent>

                      {/* Scan Types Tab */}
                      <TabsContent value="scan-types" className="mt-0">
                        <div className="space-y-3">
                          <p className="text-xs text-muted-foreground">Available scan types that can be triggered via the webhook <code className="bg-muted px-1 py-0.5 rounded">scan_types</code> payload field or the <code className="bg-muted px-1 py-0.5 rounded">triggerRun</code> mutation.</p>
                          <div className="grid gap-2">
                            {[
                              { id: "nuclei", label: "Nuclei (DAST)", desc: "Template-based vulnerability scanner. Detects CVEs, misconfigurations, exposed panels, and default credentials against live targets.", color: "text-red-400" },
                              { id: "zap", label: "ZAP (DAST)", desc: "OWASP ZAP active scanner with spider. Crawls the target and tests for XSS, SQLi, CSRF, and other OWASP Top 10 vulnerabilities.", color: "text-orange-400" },
                              { id: "burp", label: "Burp Suite (DAST)", desc: "Burp Suite Professional active scan. Enterprise-grade web application security testing with crawl-and-audit.", color: "text-amber-400" },
                              { id: "config", label: "Config Audit", desc: "HTTP security header analysis, TLS certificate validation, cookie security flags, and server version disclosure checks.", color: "text-cyan-400" },
                              { id: "cspm", label: "CSPM (Cloud Posture)", desc: "Cloud Security Posture Management. CIS Benchmark checks for AWS/Azure/GCP covering IAM, networking, storage, compute, and logging.", color: "text-blue-400" },
                              { id: "container", label: "Container Scan", desc: "Trivy-based container image vulnerability scanning. Detects CVEs in OS packages and application dependencies within Docker images.", color: "text-purple-400" },
                              { id: "iac", label: "IaC Analysis", desc: "Infrastructure-as-Code scanning via Checkov and tfsec. Analyzes Terraform, CloudFormation, Kubernetes manifests, and Dockerfiles for misconfigurations. Supports incremental mode (changed files only).", color: "text-emerald-400" },
                              { id: "secrets", label: "Secret Scanning", desc: "Regex-based secret detection across source code. Catches AWS keys, GitHub tokens, Slack webhooks, private keys, database URIs, and 20+ other credential patterns.", color: "text-rose-400" },
                            ].map(s => (
                              <div key={s.id} className="flex items-start gap-3 p-3 rounded-lg border border-border/50 bg-muted/30">
                                <Badge variant="outline" className={`shrink-0 mt-0.5 text-[10px] font-mono ${s.color}`}>{s.id}</Badge>
                                <div className="min-w-0">
                                  <p className="text-xs font-medium">{s.label}</p>
                                  <p className="text-[10px] text-muted-foreground mt-0.5 leading-relaxed">{s.desc}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                          <div className="mt-4 p-3 rounded-lg border border-dashed border-border/50 bg-muted/20">
                            <p className="text-xs font-medium mb-1">Webhook Payload Example</p>
                            <pre className="text-[10px] text-muted-foreground font-mono whitespace-pre overflow-x-auto">{`{\n  "event": "deployment",\n  "target_url": "https://staging.app.com",\n  "scan_types": ["nuclei", "config", "container", "secrets"],\n  "container_image": "myapp:latest",\n  "iac_repo_url": "https://github.com/org/infra",\n  "cloud_provider": "aws",\n  "generate_sbom": true,\n  "incremental_only": false\n}`}</pre>
                          </div>
                          <div className="mt-3 space-y-2">
                            <p className="text-xs font-medium">Additional Capabilities</p>
                            <div className="grid gap-2">
                              <div className="flex items-start gap-3 p-2.5 rounded-lg border border-border/50 bg-muted/20">
                                <Badge variant="outline" className="shrink-0 mt-0.5 text-[10px] font-mono text-sky-400">P0</Badge>
                                <div><p className="text-xs font-medium">Pre-flight Health Check</p><p className="text-[10px] text-muted-foreground">Verifies scan server is reachable before dispatching. Returns "error" immediately if infrastructure is down.</p></div>
                              </div>
                              <div className="flex items-start gap-3 p-2.5 rounded-lg border border-border/50 bg-muted/20">
                                <Badge variant="outline" className="shrink-0 mt-0.5 text-[10px] font-mono text-sky-400">P0</Badge>
                                <div><p className="text-xs font-medium">Target URL Allowlist</p><p className="text-[10px] text-muted-foreground">Restricts which domains each pipeline can scan. Prevents abuse if a webhook secret is compromised. Configure via pipeline settings.</p></div>
                              </div>
                              <div className="flex items-start gap-3 p-2.5 rounded-lg border border-border/50 bg-muted/20">
                                <Badge variant="outline" className="shrink-0 mt-0.5 text-[10px] font-mono text-indigo-400">P1</Badge>
                                <div><p className="text-xs font-medium">Baseline Comparison</p><p className="text-[10px] text-muted-foreground">Compares findings against a saved baseline to surface only new/worsened vulnerabilities and track fixed issues.</p></div>
                              </div>
                              <div className="flex items-start gap-3 p-2.5 rounded-lg border border-border/50 bg-muted/20">
                                <Badge variant="outline" className="shrink-0 mt-0.5 text-[10px] font-mono text-violet-400">P2</Badge>
                                <div><p className="text-xs font-medium">SBOM Generation</p><p className="text-[10px] text-muted-foreground">Generates a Software Bill of Materials (CycloneDX JSON) during container scans. Stored as a downloadable artifact.</p></div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </TabsContent>
                    </Tabs>
                  </CardContent>
                </>
              )}
            </Card>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
