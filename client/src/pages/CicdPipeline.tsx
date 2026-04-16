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
} from "lucide-react";
import AppShell from "@/components/AppShell";

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

// ─── Create Pipeline Dialog ──────────────────────────────────────────────────

function CreatePipelineForm({ setOpen }: { setOpen: (v: boolean) => void }) {
  const utils = trpc.useUtils();
  const [name, setName] = useState("");
  const [provider, setProvider] = useState<string>("github_actions");
  const [triggerOn, setTriggerOn] = useState<string>("push");
  const [targetUrl, setTargetUrl] = useState("");
  const [failThreshold, setFailThreshold] = useState("7.0");

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
    });
  };

  return (
    <form onSubmit={handleSubmit} className="grid gap-4 py-4">
      <div className="grid grid-cols-4 items-center gap-4">
        <Label htmlFor="pl-name" className="text-right text-xs">Name</Label>
        <Input id="pl-name" value={name} onChange={(e) => setName(e.target.value)} className="col-span-3" placeholder="Production Security Gate" />
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
  const [provider, setProvider] = useState<"github_actions" | "gitlab_ci" | "codepipeline">("github_actions");

  const snippetQuery = trpc.cicdPipeline.generateYamlSnippet.useQuery(
    { pipelineId, provider },
    { enabled: !!pipelineId }
  );

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        {([
          { id: "github_actions" as const, label: "GitHub Actions", icon: <Github className="h-3.5 w-3.5" /> },
          { id: "gitlab_ci" as const, label: "GitLab CI", icon: <Gitlab className="h-3.5 w-3.5" /> },
          { id: "codepipeline" as const, label: "CodePipeline", icon: <Cloud className="h-3.5 w-3.5" /> },
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
}

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function CicdPipelinePage() {
  const [isCreateOpen, setCreateOpen] = useState(false);
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
                Integrate automated security scanning into your CI/CD workflows. Receive webhooks from GitHub Actions, GitLab CI, or AWS CodePipeline to trigger ZAP, Burp, and Nuclei scans with pass/fail gates.
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
                          <p className="text-[10px] text-muted-foreground capitalize">{p.provider?.replace("_", " ")} &middot; {p.triggerOn?.replace("_", " ")}</p>
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
