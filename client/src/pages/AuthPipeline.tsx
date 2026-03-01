import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Workflow,
  Play,
  Pause,
  SkipForward,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Loader2,
  Lock,
  Eye,
  FileText,
  Gauge,
  Fingerprint,
  ChevronRight,
  Radio,
  XCircle,
  Info,
} from "lucide-react";
import { toast } from "sonner";

// ─── Types ──────────────────────────────────────────────────────────────────

interface PipelineStep {
  id: string;
  tool: string;
  description: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped" | "blocked";
  startedAt?: number;
  completedAt?: number;
  error?: string;
}

interface PipelineState {
  id: string;
  name: string;
  description: string;
  mode: "strict" | "standard";
  status: "draft" | "running" | "paused" | "completed" | "failed";
  steps: PipelineStep[];
  guardrails: {
    maxRps: number;
    maxAttemptsPerAccount: number;
    stopOnLockoutSignal: boolean;
    requireScopeAllowlist: boolean;
    requireChangeWindow: boolean;
    requireEvidenceCapture: boolean;
  };
  findings: any[];
  createdAt: number;
  startedAt?: number;
  completedAt?: number;
}

interface PipelineTemplate {
  id: string;
  name: string;
  description: string;
  stepCount: number;
}

// ─── Step Status Icon ───────────────────────────────────────────────────────

function StepStatusIcon({ status }: { status: string }) {
  switch (status) {
    case "completed": return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
    case "running": return <Loader2 className="h-4 w-4 text-blue-400 animate-spin" />;
    case "failed": return <XCircle className="h-4 w-4 text-red-400" />;
    case "blocked": return <Lock className="h-4 w-4 text-amber-400" />;
    case "skipped": return <SkipForward className="h-4 w-4 text-zinc-400" />;
    default: return <Clock className="h-4 w-4 text-zinc-500" />;
  }
}

// ─── Pipeline Templates ─────────────────────────────────────────────────────

const TEMPLATES: PipelineTemplate[] = [
  { id: "auth-recon-flow-capture", name: "Auth Recon + Flow Capture", description: "Discover endpoints, fingerprint services, capture auth flow", stepCount: 3 },
  { id: "enumeration-signals-safe", name: "Enumeration Signals (Safe)", description: "Probe for username enumeration without triggering lockouts", stepCount: 1 },
  { id: "session-token-checks", name: "Session & Token Checks", description: "Cookie audit, JWT inspection, TLS configuration", stepCount: 3 },
  { id: "oauth-oidc-assessment", name: "OAuth/OIDC Assessment", description: "Redirect URI, PKCE, state parameter, scope analysis", stepCount: 4 },
  { id: "saml-assessment", name: "SAML Assessment", description: "Signature wrapping, replay, audience restriction", stepCount: 3 },
  { id: "full-auth-pipeline", name: "Full Auth Pipeline", description: "Complete 6-phase auth testing workflow", stepCount: 6 },
];

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function AuthPipeline() {
  const [targetUrl, setTargetUrl] = useState("");
  const [mode, setMode] = useState<"strict" | "standard">("standard");
  const [selectedTemplate, setSelectedTemplate] = useState("auth-recon-flow-capture");
  const [pipeline, setPipeline] = useState<PipelineState | null>(null);
  const [activeTab, setActiveTab] = useState("configure");

  // tRPC mutations
  const initPipeline = trpc.authAssessment.initPipeline.useMutation({
    onSuccess: (data: any) => {
      setPipeline(data);
      setActiveTab("monitor");
      toast.success(`Pipeline Initialized — ${data.name} ready in ${data.mode} mode`);
    },
    onError: (err: any) => {
      toast.error(`Init Error: ${err.message}`);
    },
  });

  const advancePipeline = trpc.authAssessment.advancePipeline.useMutation({
    onSuccess: (data: any) => {
      setPipeline(data);
      if (data.status === "completed") {
        toast.success(`Pipeline Complete — All steps finished, ${data.findings.length} findings`);
      } else if (data.status === "paused") {
        toast.info("Human Approval Required — review and approve to continue");
      }
    },
    onError: (err: any) => {
      toast.error(`Advance Error: ${err.message}`);
    },
  });

  const handleInit = () => {
    if (!targetUrl.trim()) {
      toast.error("Enter a target URL");
      return;
    }
    initPipeline.mutate({ templateId: selectedTemplate, targetUrl: targetUrl.trim(), mode });
  };

  const handleAdvance = () => {
    if (!pipeline) return;
    advancePipeline.mutate({ pipelineId: pipeline.id });
  };

  const progress = pipeline
    ? Math.round((pipeline.steps.filter(s => s.status === "completed").length / pipeline.steps.length) * 100)
    : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Workflow className="h-6 w-6 text-primary" />
            Auth Pipeline
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Orchestrated auth testing workflows with guardrails, evidence capture, and human-in-the-loop gates
          </p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="configure">Configure</TabsTrigger>
          <TabsTrigger value="monitor" disabled={!pipeline}>
            Monitor {pipeline && <Badge variant="secondary" className="ml-1 text-[10px]">{pipeline.status}</Badge>}
          </TabsTrigger>
          <TabsTrigger value="guardrails">Guardrails</TabsTrigger>
          <TabsTrigger value="templates">Templates</TabsTrigger>
        </TabsList>

        {/* ── Configure Tab ── */}
        <TabsContent value="configure" className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Pipeline Configuration</CardTitle>
              <CardDescription>Select a template, target, and mode to initialize the auth testing pipeline.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Target URL</label>
                  <Input
                    placeholder="https://target.example.com/login"
                    value={targetUrl}
                    onChange={e => setTargetUrl(e.target.value)}
                    className="font-mono text-sm"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Assessment Mode</label>
                  <Select value={mode} onValueChange={(v: "strict" | "standard") => setMode(v)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="standard">Standard Mode (0.5 RPS)</SelectItem>
                      <SelectItem value="strict">Federal Auth Strict (0.1 RPS)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Pipeline Template</label>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {TEMPLATES.map(tmpl => (
                    <div
                      key={tmpl.id}
                      className={`border rounded-lg p-3 cursor-pointer transition-all ${
                        selectedTemplate === tmpl.id
                          ? "border-primary bg-primary/5"
                          : "border-border/50 hover:border-border"
                      }`}
                      onClick={() => setSelectedTemplate(tmpl.id)}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-medium text-foreground">{tmpl.name}</span>
                        <Badge variant="outline" className="text-[10px]">{tmpl.stepCount} steps</Badge>
                      </div>
                      <p className="text-[10px] text-muted-foreground">{tmpl.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              <Button onClick={handleInit} disabled={initPipeline.isPending} className="gap-2 w-full sm:w-auto">
                {initPipeline.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                Initialize Pipeline
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Monitor Tab ── */}
        <TabsContent value="monitor" className="space-y-4">
          {pipeline && (
            <>
              {/* Status Bar */}
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <Badge
                        variant="outline"
                        className={
                          pipeline.status === "running" ? "bg-blue-500/15 text-blue-400 border-blue-500/30" :
                          pipeline.status === "completed" ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30" :
                          pipeline.status === "paused" ? "bg-amber-500/15 text-amber-400 border-amber-500/30" :
                          pipeline.status === "failed" ? "bg-red-500/15 text-red-400 border-red-500/30" :
                          "bg-zinc-500/15 text-zinc-400 border-zinc-500/30"
                        }
                      >
                        {pipeline.status === "running" && <Radio className="h-3 w-3 mr-1 animate-pulse" />}
                        {pipeline.status.toUpperCase()}
                      </Badge>
                      <span className="text-sm font-medium">{pipeline.name}</span>
                      <Badge variant="outline" className="text-[10px] font-mono">{pipeline.mode}</Badge>
                    </div>
                    <div className="flex gap-2">
                      {(pipeline.status === "draft" || pipeline.status === "running" || pipeline.status === "paused") && (
                        <Button size="sm" onClick={handleAdvance} disabled={advancePipeline.isPending} className="gap-1">
                          {advancePipeline.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <SkipForward className="h-3 w-3" />}
                          {pipeline.status === "paused" ? "Approve & Continue" : "Advance"}
                        </Button>
                      )}
                    </div>
                  </div>
                  <Progress value={progress} className="h-2" />
                  <p className="text-xs text-muted-foreground mt-1.5">
                    {pipeline.steps.filter(s => s.status === "completed").length} / {pipeline.steps.length} steps complete · {pipeline.findings.length} findings
                  </p>
                </CardContent>
              </Card>

              {/* Paused Warning */}
              {pipeline.status === "paused" && (
                <Card className="border-amber-500/30 bg-amber-500/5">
                  <CardContent className="p-4 flex items-center gap-3">
                    <Pause className="h-5 w-5 text-amber-400" />
                    <div>
                      <p className="text-sm font-medium text-amber-400">Human Approval Required</p>
                      <p className="text-xs text-muted-foreground">
                        The next step requires manual review before execution. Review the guardrails and click "Approve & Continue" to proceed.
                      </p>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Step List */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm">Pipeline Steps</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  {pipeline.steps.map((step, idx) => (
                    <div
                      key={step.id}
                      className={`flex items-center gap-3 p-3 rounded-lg border transition-colors ${
                        step.status === "running" ? "border-blue-500/30 bg-blue-500/5" :
                        step.status === "completed" ? "border-emerald-500/20 bg-emerald-500/5" :
                        step.status === "blocked" ? "border-amber-500/20 bg-amber-500/5" :
                        step.status === "failed" ? "border-red-500/20 bg-red-500/5" :
                        "border-border/50"
                      }`}
                    >
                      <div className="flex items-center justify-center w-6 h-6 rounded-full bg-muted text-xs font-mono">
                        {idx + 1}
                      </div>
                      <StepStatusIcon status={step.status} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-foreground">{step.description}</span>
                          <Badge variant="outline" className="text-[10px] font-mono">{step.tool}</Badge>
                        </div>
                        {step.error && (
                          <p className="text-xs text-red-400 mt-0.5">{step.error}</p>
                        )}
                      </div>
                      <Badge variant="outline" className="text-[10px] uppercase">{step.status}</Badge>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </>
          )}

          {!pipeline && (
            <Card className="border-dashed">
              <CardContent className="py-12 text-center">
                <Workflow className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
                <h3 className="text-sm font-medium text-muted-foreground">No Active Pipeline</h3>
                <p className="text-xs text-muted-foreground/70 mt-1">Go to Configure to initialize a pipeline.</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── Guardrails Tab ── */}
        <TabsContent value="guardrails" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Shield className="h-4 w-4 text-amber-400" />
                  Federal Auth Strict Mode
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {[
                  { label: "Max RPS", value: "0.1 req/sec", icon: Gauge },
                  { label: "Max Attempts/Account", value: "1", icon: Lock },
                  { label: "Stop on Lockout Signal", value: "Yes", icon: AlertTriangle },
                  { label: "Scope Allowlist Required", value: "Yes", icon: Eye },
                  { label: "Change Window Required", value: "Yes", icon: Clock },
                  { label: "Evidence Capture Required", value: "Yes", icon: FileText },
                ].map(g => (
                  <div key={g.label} className="flex items-center justify-between py-1.5 border-b border-border/30 last:border-0">
                    <span className="text-xs text-muted-foreground flex items-center gap-1.5">
                      <g.icon className="h-3 w-3" /> {g.label}
                    </span>
                    <span className="text-xs font-mono text-foreground">{g.value}</span>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Fingerprint className="h-4 w-4 text-blue-400" />
                  Standard Mode
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {[
                  { label: "Max RPS", value: "0.5 req/sec", icon: Gauge },
                  { label: "Max Attempts/Account", value: "3", icon: Lock },
                  { label: "Stop on Lockout Signal", value: "Yes", icon: AlertTriangle },
                  { label: "Scope Allowlist Required", value: "Yes", icon: Eye },
                  { label: "Change Window Required", value: "No", icon: Clock },
                  { label: "Evidence Capture Required", value: "No", icon: FileText },
                ].map(g => (
                  <div key={g.label} className="flex items-center justify-between py-1.5 border-b border-border/30 last:border-0">
                    <span className="text-xs text-muted-foreground flex items-center gap-1.5">
                      <g.icon className="h-3 w-3" /> {g.label}
                    </span>
                    <span className="text-xs font-mono text-foreground">{g.value}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Federal Auth Controls</CardTitle>
              <CardDescription className="text-xs">
                Controls enforced during federal auth strict mode assessments (mapped to NIST 800-53)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {[
                  { id: "FA-01", title: "Rate Limit Enforcement", desc: "Maximum 0.1 RPS against auth endpoints" },
                  { id: "FA-02", title: "Evidence Chain Integrity", desc: "SHA-256 hashed evidence for every test action" },
                  { id: "FA-03", title: "Scope Boundary Enforcement", desc: "All targets must be on the approved allowlist" },
                  { id: "FA-04", title: "Human Approval Gates", desc: "Credential testing requires operator approval" },
                  { id: "FA-05", title: "Lockout Detection & Stop", desc: "Automatic halt on account lockout signals" },
                ].map(ctrl => (
                  <div key={ctrl.id} className="flex items-start gap-3 p-3 rounded-lg border border-border/50">
                    <Badge variant="outline" className="text-[10px] font-mono shrink-0 mt-0.5">{ctrl.id}</Badge>
                    <div>
                      <p className="text-sm font-medium text-foreground">{ctrl.title}</p>
                      <p className="text-xs text-muted-foreground">{ctrl.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Templates Tab ── */}
        <TabsContent value="templates" className="space-y-3">
          {TEMPLATES.map(tmpl => (
            <Card key={tmpl.id} className="hover:border-border transition-colors">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-medium text-foreground">{tmpl.name}</h4>
                    <p className="text-xs text-muted-foreground mt-0.5">{tmpl.description}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-[10px]">{tmpl.stepCount} steps</Badge>
                    <Button
                      size="sm"
                      variant="outline"
                      className="gap-1"
                      onClick={() => {
                        setSelectedTemplate(tmpl.id);
                        setActiveTab("configure");
                      }}
                    >
                      <ChevronRight className="h-3 w-3" /> Use
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>
      </Tabs>
    </div>
  );
}
