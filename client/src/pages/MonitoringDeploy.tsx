/**
 * Monitoring Deployment Wizard
 *
 * Guided deployment page for the AC3 CloudWatch monitoring stack.
 * Generates copy-paste AWS CLI commands based on user configuration.
 */
import { useState, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Slider } from "@/components/ui/slider";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import {
  Activity, AlertTriangle, CheckCircle2, Copy, Terminal, Server,
  Shield, Bell, Mail, MessageSquare, Gauge, Clock, Loader2,
  ChevronRight, ExternalLink, FileCode, Zap, Eye, Download,
  BarChart3, Cpu, HardDrive, Globe, ArrowRight, Info,
  CircleDot, Rocket, CheckCheck, XCircle, TriangleAlert,
} from "lucide-react";

// ─── Types ─────────────────────────────────────────────────────────────────────

interface GeneratedCommand {
  id: string;
  label: string;
  description: string;
  command: string;
  phase: "prerequisite" | "deploy" | "verify" | "test";
  required: boolean;
}

type DeployPhase = "configure" | "review" | "deploy" | "verify";

const PHASE_LABELS: Record<DeployPhase, { label: string; icon: React.ReactNode }> = {
  configure: { label: "Configure", icon: <Gauge className="h-4 w-4" /> },
  review: { label: "Review", icon: <Eye className="h-4 w-4" /> },
  deploy: { label: "Deploy", icon: <Rocket className="h-4 w-4" /> },
  verify: { label: "Verify", icon: <CheckCheck className="h-4 w-4" /> },
};

const AWS_REGIONS = [
  "us-east-1", "us-east-2", "us-west-1", "us-west-2",
  "eu-west-1", "eu-west-2", "eu-central-1",
  "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
];

// ─── Command Block Component ───────────────────────────────────────────────────

function CommandBlock({
  command,
  completed,
  onToggleComplete,
}: {
  command: GeneratedCommand;
  completed: boolean;
  onToggleComplete: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(command.command);
    setCopied(true);
    toast.success(`Copied: ${command.label}`);
    setTimeout(() => setCopied(false), 2000);
  }, [command]);

  return (
    <div
      className={`rounded-lg border transition-all ${
        completed
          ? "border-emerald-500/30 bg-emerald-500/5"
          : "border-border bg-card"
      }`}
    >
      <div className="flex items-start justify-between p-4 pb-2">
        <div className="flex items-start gap-3">
          <button
            onClick={onToggleComplete}
            className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border-2 transition-colors ${
              completed
                ? "border-emerald-500 bg-emerald-500 text-white"
                : "border-muted-foreground/40 hover:border-primary"
            }`}
          >
            {completed && <CheckCircle2 className="h-3 w-3" />}
          </button>
          <div>
            <div className="flex items-center gap-2">
              <span className={`font-medium text-sm ${completed ? "line-through text-muted-foreground" : ""}`}>
                {command.label}
              </span>
              {command.required ? (
                <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-amber-500/40 text-amber-500">
                  Required
                </Badge>
              ) : (
                <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-muted-foreground">
                  Optional
                </Badge>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">{command.description}</p>
          </div>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={handleCopy}
          className="shrink-0 h-8 px-2"
        >
          {copied ? (
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
          ) : (
            <Copy className="h-3.5 w-3.5" />
          )}
          <span className="ml-1.5 text-xs">{copied ? "Copied" : "Copy"}</span>
        </Button>
      </div>
      <div className="px-4 pb-4">
        <pre className="rounded-md bg-zinc-950 p-3 text-xs text-emerald-400 font-mono overflow-x-auto whitespace-pre-wrap">
          <code>{command.command}</code>
        </pre>
      </div>
    </div>
  );
}

// ─── Resource Table ────────────────────────────────────────────────────────────

function ResourceTable({ resources }: { resources: { type: string; name: string; purpose: string; conditional?: boolean }[] }) {
  return (
    <div className="rounded-lg border overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-muted/50 border-b">
            <th className="text-left px-4 py-2 font-medium text-muted-foreground">Resource</th>
            <th className="text-left px-4 py-2 font-medium text-muted-foreground">Name</th>
            <th className="text-left px-4 py-2 font-medium text-muted-foreground">Purpose</th>
          </tr>
        </thead>
        <tbody>
          {resources.map((r, i) => (
            <tr key={i} className="border-b last:border-0 hover:bg-muted/30">
              <td className="px-4 py-2">
                <Badge variant="outline" className="text-[10px] font-mono">
                  {r.type}
                </Badge>
              </td>
              <td className="px-4 py-2 font-medium text-xs">
                {r.name}
                {r.conditional && (
                  <span className="ml-1.5 text-muted-foreground text-[10px]">(conditional)</span>
                )}
              </td>
              <td className="px-4 py-2 text-xs text-muted-foreground">{r.purpose}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function MonitoringDeploy() {
  // ── State ──
  const [phase, setPhase] = useState<DeployPhase>("configure");
  const [completedSteps, setCompletedSteps] = useState<Set<string>>(new Set());

  // Config state
  const [environment, setEnvironment] = useState<"dev" | "staging" | "prod">("dev");
  const [region, setRegion] = useState("us-east-1");
  const [ecsClusterName, setEcsClusterName] = useState("");
  const [ecsServiceName, setEcsServiceName] = useState("");
  const [cpuThreshold, setCpuThreshold] = useState(80);
  const [memoryThreshold, setMemoryThreshold] = useState(85);
  const [alb5xxThreshold, setAlb5xxThreshold] = useState(10);
  const [alb4xxThreshold, setAlb4xxThreshold] = useState(50);
  const [responseTimeThreshold, setResponseTimeThreshold] = useState(3);
  const [slackWebhookUrl, setSlackWebhookUrl] = useState("");
  const [alertEmail, setAlertEmail] = useState("");

  // ── Queries ──
  const resourcesQuery = trpc.monitoringDeploy.getStackResources.useQuery();

  // ── Mutations ──
  const generateMutation = trpc.monitoringDeploy.generateCommands.useMutation({
    onSuccess: () => {
      setPhase("review");
      toast.success("Commands generated successfully");
    },
    onError: (err) => toast.error(err.message),
  });

  const validateMutation = trpc.monitoringDeploy.validateConfig.useMutation();

  // ── Derived ──
  const commands = generateMutation.data?.commands ?? [];
  const prereqCommands = useMemo(() => commands.filter(c => c.phase === "prerequisite"), [commands]);
  const deployCommands = useMemo(() => commands.filter(c => c.phase === "deploy"), [commands]);
  const verifyCommands = useMemo(() => commands.filter(c => c.phase === "verify"), [commands]);
  const testCommands = useMemo(() => commands.filter(c => c.phase === "test"), [commands]);

  const requiredComplete = useMemo(() => {
    const required = commands.filter(c => c.required);
    return required.every(c => completedSteps.has(c.id));
  }, [commands, completedSteps]);

  const toggleStep = useCallback((id: string) => {
    setCompletedSteps(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const handleGenerate = () => {
    generateMutation.mutate({
      environment,
      region,
      ecsClusterName: ecsClusterName || undefined,
      ecsServiceName: ecsServiceName || undefined,
      cpuThreshold,
      memoryThreshold,
      alb5xxThreshold,
      alb4xxThreshold,
      responseTimeThreshold,
      slackWebhookUrl,
      alertEmail,
    });
  };

  const handleValidate = () => {
    validateMutation.mutate({
      environment,
      region,
      ecsClusterName: ecsClusterName || `ac3-${environment}`,
      ecsServiceName: ecsServiceName || `ac3-${environment}-caldera-dashboard`,
      cpuThreshold,
      memoryThreshold,
      slackWebhookUrl: slackWebhookUrl || undefined,
      alertEmail: alertEmail || undefined,
    });
  };

  const copyAllCommands = () => {
    const allText = commands.map(c => `# ${c.label}\n${c.command}`).join("\n\n");
    navigator.clipboard.writeText(allText);
    toast.success("All commands copied to clipboard");
  };

  // ── Phase stepper ──
  const phases: DeployPhase[] = ["configure", "review", "deploy", "verify"];
  const phaseIndex = phases.indexOf(phase);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Activity className="h-6 w-6 text-primary" />
          Monitoring Stack Deployment
        </h1>
        <p className="text-muted-foreground mt-1">
          Deploy CloudWatch monitoring and alerting for the AC3 Caldera Dashboard ECS infrastructure.
          Configure alarm thresholds, notification channels, and generate ready-to-run AWS CLI commands.
        </p>
      </div>

      {/* Phase Stepper */}
      <div className="flex items-center gap-1 p-1 rounded-lg bg-muted/50 w-fit">
        {phases.map((p, i) => (
          <button
            key={p}
            onClick={() => {
              if (p === "configure" || (generateMutation.data && i <= 3)) {
                setPhase(p);
              }
            }}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
              phase === p
                ? "bg-background text-foreground shadow-sm"
                : i <= phaseIndex
                ? "text-foreground/70 hover:text-foreground"
                : "text-muted-foreground cursor-not-allowed"
            }`}
          >
            {PHASE_LABELS[p].icon}
            {PHASE_LABELS[p].label}
            {i < phases.length - 1 && (
              <ChevronRight className="h-3 w-3 text-muted-foreground ml-1" />
            )}
          </button>
        ))}
      </div>

      {/* ═══ CONFIGURE PHASE ═══ */}
      {phase === "configure" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left: Configuration Form */}
          <div className="lg:col-span-2 space-y-6">
            {/* Environment & Region */}
            <Card>
              <CardHeader className="pb-4">
                <CardTitle className="text-base flex items-center gap-2">
                  <Globe className="h-4 w-4 text-blue-500" />
                  Environment & Region
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Environment</Label>
                    <Select value={environment} onValueChange={(v) => setEnvironment(v as "dev" | "staging" | "prod")}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="dev">Development</SelectItem>
                        <SelectItem value="staging">Staging</SelectItem>
                        <SelectItem value="prod">Production</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>AWS Region</Label>
                    <Select value={region} onValueChange={setRegion}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {AWS_REGIONS.map(r => (
                          <SelectItem key={r} value={r}>{r}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>ECS Cluster Name</Label>
                    <Input
                      placeholder={`ac3-${environment}`}
                      value={ecsClusterName}
                      onChange={(e) => setEcsClusterName(e.target.value)}
                    />
                    <p className="text-[11px] text-muted-foreground">Leave blank for default: ac3-{environment}</p>
                  </div>
                  <div className="space-y-2">
                    <Label>ECS Service Name</Label>
                    <Input
                      placeholder={`ac3-${environment}-caldera-dashboard`}
                      value={ecsServiceName}
                      onChange={(e) => setEcsServiceName(e.target.value)}
                    />
                    <p className="text-[11px] text-muted-foreground">Leave blank for default</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Alarm Thresholds */}
            <Card>
              <CardHeader className="pb-4">
                <CardTitle className="text-base flex items-center gap-2">
                  <Gauge className="h-4 w-4 text-amber-500" />
                  Alarm Thresholds
                </CardTitle>
                <CardDescription>
                  Set the thresholds that trigger CloudWatch alarms. Lower values catch issues earlier but may cause false positives.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <Label className="flex items-center gap-2">
                      <Cpu className="h-3.5 w-3.5 text-blue-500" />
                      CPU Utilization
                    </Label>
                    <span className="text-sm font-mono font-medium">{cpuThreshold}%</span>
                  </div>
                  <Slider
                    value={[cpuThreshold]}
                    onValueChange={([v]) => setCpuThreshold(v)}
                    min={50}
                    max={99}
                    step={5}
                    className="w-full"
                  />
                  <div className="flex justify-between text-[10px] text-muted-foreground">
                    <span>50% (aggressive)</span>
                    <span>99% (lenient)</span>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <Label className="flex items-center gap-2">
                      <HardDrive className="h-3.5 w-3.5 text-purple-500" />
                      Memory Utilization
                    </Label>
                    <span className="text-sm font-mono font-medium">{memoryThreshold}%</span>
                  </div>
                  <Slider
                    value={[memoryThreshold]}
                    onValueChange={([v]) => setMemoryThreshold(v)}
                    min={50}
                    max={99}
                    step={5}
                    className="w-full"
                  />
                </div>

                <Separator />

                <div className="grid grid-cols-3 gap-4">
                  <div className="space-y-2">
                    <Label className="text-xs">5xx Error Threshold</Label>
                    <Input
                      type="number"
                      value={alb5xxThreshold}
                      onChange={(e) => setAlb5xxThreshold(Number(e.target.value))}
                      min={1}
                    />
                    <p className="text-[10px] text-muted-foreground">per 5 min</p>
                  </div>
                  <div className="space-y-2">
                    <Label className="text-xs">4xx Error Threshold</Label>
                    <Input
                      type="number"
                      value={alb4xxThreshold}
                      onChange={(e) => setAlb4xxThreshold(Number(e.target.value))}
                      min={1}
                    />
                    <p className="text-[10px] text-muted-foreground">per 5 min</p>
                  </div>
                  <div className="space-y-2">
                    <Label className="text-xs">Response Time (s)</Label>
                    <Input
                      type="number"
                      value={responseTimeThreshold}
                      onChange={(e) => setResponseTimeThreshold(Number(e.target.value))}
                      min={0.5}
                      step={0.5}
                    />
                    <p className="text-[10px] text-muted-foreground">seconds avg</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Notifications */}
            <Card>
              <CardHeader className="pb-4">
                <CardTitle className="text-base flex items-center gap-2">
                  <Bell className="h-4 w-4 text-emerald-500" />
                  Notification Channels
                </CardTitle>
                <CardDescription>
                  Configure where alarm notifications are sent. At least one channel is recommended.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label className="flex items-center gap-2">
                    <MessageSquare className="h-3.5 w-3.5" />
                    Slack Webhook URL
                  </Label>
                  <Input
                    type="url"
                    placeholder="https://hooks.slack.com/services/T.../B.../..."
                    value={slackWebhookUrl}
                    onChange={(e) => setSlackWebhookUrl(e.target.value)}
                  />
                  <p className="text-[11px] text-muted-foreground">
                    Create at{" "}
                    <a
                      href="https://api.slack.com/messaging/webhooks"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary hover:underline"
                    >
                      api.slack.com/messaging/webhooks
                    </a>
                  </p>
                </div>
                <div className="space-y-2">
                  <Label className="flex items-center gap-2">
                    <Mail className="h-3.5 w-3.5" />
                    Alert Email
                  </Label>
                  <Input
                    type="email"
                    placeholder="team@aceofcloud.com"
                    value={alertEmail}
                    onChange={(e) => setAlertEmail(e.target.value)}
                  />
                  <p className="text-[11px] text-muted-foreground">
                    A confirmation email will be sent that must be accepted before notifications arrive.
                  </p>
                </div>
              </CardContent>
            </Card>

            {/* Validation Results */}
            {validateMutation.data && (
              <Card className={validateMutation.data.valid ? "border-emerald-500/30" : "border-amber-500/30"}>
                <CardContent className="pt-4">
                  <div className="flex items-center gap-2 mb-3">
                    {validateMutation.data.valid ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                    ) : (
                      <AlertTriangle className="h-4 w-4 text-amber-500" />
                    )}
                    <span className="font-medium text-sm">
                      {validateMutation.data.valid ? "Configuration valid" : "Issues found"}
                    </span>
                  </div>
                  {validateMutation.data.issues.length > 0 && (
                    <div className="space-y-2">
                      {validateMutation.data.issues.map((issue, i) => (
                        <div key={i} className="flex items-start gap-2 text-xs">
                          {issue.severity === "error" ? (
                            <XCircle className="h-3.5 w-3.5 text-red-500 mt-0.5 shrink-0" />
                          ) : (
                            <TriangleAlert className="h-3.5 w-3.5 text-amber-500 mt-0.5 shrink-0" />
                          )}
                          <span>
                            <span className="font-medium">{issue.field}:</span> {issue.message}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* Actions */}
            <div className="flex gap-3">
              <Button variant="outline" onClick={handleValidate} disabled={validateMutation.isPending}>
                {validateMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                ) : (
                  <Shield className="h-4 w-4 mr-2" />
                )}
                Validate
              </Button>
              <Button onClick={handleGenerate} disabled={generateMutation.isPending}>
                {generateMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                ) : (
                  <Terminal className="h-4 w-4 mr-2" />
                )}
                Generate Commands
                <ArrowRight className="h-4 w-4 ml-2" />
              </Button>
            </div>
          </div>

          {/* Right: What Gets Deployed */}
          <div className="space-y-6">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Server className="h-4 w-4 text-primary" />
                  What Gets Deployed
                </CardTitle>
                <CardDescription>
                  {resourcesQuery.data?.length ?? 0} AWS resources created by the monitoring stack
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[500px]">
                  <div className="space-y-2">
                    {(resourcesQuery.data ?? []).map((r, i) => (
                      <div key={i} className="flex items-start gap-2 p-2 rounded-md hover:bg-muted/50">
                        <CircleDot className={`h-3 w-3 mt-1 shrink-0 ${r.conditional ? "text-muted-foreground" : "text-emerald-500"}`} />
                        <div>
                          <div className="flex items-center gap-1.5">
                            <span className="text-xs font-medium">{r.name}</span>
                            <Badge variant="outline" className="text-[9px] px-1 py-0 font-mono">
                              {r.type}
                            </Badge>
                          </div>
                          <p className="text-[11px] text-muted-foreground">{r.purpose}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Info className="h-4 w-4 text-blue-500" />
                  Prerequisites
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2 text-xs text-muted-foreground">
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="h-3 w-3 mt-0.5 shrink-0 text-emerald-500" />
                    AWS CLI v2 installed and configured
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="h-3 w-3 mt-0.5 shrink-0 text-emerald-500" />
                    ECS cluster and service deployed
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="h-3 w-3 mt-0.5 shrink-0 text-emerald-500" />
                    Application Load Balancer provisioned
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="h-3 w-3 mt-0.5 shrink-0 text-emerald-500" />
                    IAM permissions for CloudFormation, CloudWatch, SNS, Lambda
                  </li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </div>
      )}

      {/* ═══ REVIEW PHASE ═══ */}
      {phase === "review" && generateMutation.data && (
        <div className="space-y-6">
          {/* Summary Card */}
          <Card className="border-primary/20">
            <CardContent className="pt-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <p className="text-xs text-muted-foreground">Stack Name</p>
                  <p className="font-mono text-sm font-medium">{generateMutation.data.stackName}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Environment</p>
                  <Badge variant={
                    generateMutation.data.config.environment === "prod" ? "destructive" :
                    generateMutation.data.config.environment === "staging" ? "default" : "secondary"
                  }>
                    {generateMutation.data.config.environment}
                  </Badge>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Region</p>
                  <p className="font-mono text-sm">{generateMutation.data.config.region}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Total Commands</p>
                  <p className="text-sm font-medium">{commands.length}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Config Summary */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Configuration Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground">ECS Cluster</p>
                  <p className="font-mono text-xs">{generateMutation.data.config.ecsClusterName}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground">ECS Service</p>
                  <p className="font-mono text-xs">{generateMutation.data.config.ecsServiceName}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground">CPU Alarm</p>
                  <p className="font-mono text-xs">&gt;{generateMutation.data.config.cpuThreshold}%</p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground">Memory Alarm</p>
                  <p className="font-mono text-xs">&gt;{generateMutation.data.config.memoryThreshold}%</p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground">5xx Threshold</p>
                  <p className="font-mono text-xs">&gt;{generateMutation.data.config.alb5xxThreshold}/5min</p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground">Response Time</p>
                  <p className="font-mono text-xs">&gt;{generateMutation.data.config.responseTimeThreshold}s</p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground">Slack</p>
                  <p className="font-mono text-xs truncate">
                    {generateMutation.data.config.slackWebhookUrl || "(not configured)"}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground">Email</p>
                  <p className="font-mono text-xs">
                    {generateMutation.data.config.alertEmail || "(not configured)"}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="flex gap-3">
            <Button variant="outline" onClick={() => setPhase("configure")}>
              Back to Configure
            </Button>
            <Button onClick={() => setPhase("deploy")}>
              <Rocket className="h-4 w-4 mr-2" />
              Proceed to Deploy
              <ArrowRight className="h-4 w-4 ml-2" />
            </Button>
            <Button variant="ghost" onClick={copyAllCommands}>
              <Download className="h-4 w-4 mr-2" />
              Copy All Commands
            </Button>
          </div>
        </div>
      )}

      {/* ═══ DEPLOY PHASE ═══ */}
      {phase === "deploy" && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Run these commands in your terminal. Check off each step as you complete it.
            </p>
            <Button variant="ghost" size="sm" onClick={copyAllCommands}>
              <Copy className="h-3.5 w-3.5 mr-1.5" />
              Copy All
            </Button>
          </div>

          {/* Prerequisites */}
          <Accordion type="multiple" defaultValue={["prerequisites", "deploy-commands"]}>
            <AccordionItem value="prerequisites">
              <AccordionTrigger className="text-sm font-medium">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-blue-500" />
                  Prerequisites ({prereqCommands.filter(c => completedSteps.has(c.id)).length}/{prereqCommands.length})
                </div>
              </AccordionTrigger>
              <AccordionContent>
                <div className="space-y-3 pt-2">
                  {prereqCommands.map(cmd => (
                    <CommandBlock
                      key={cmd.id}
                      command={cmd}
                      completed={completedSteps.has(cmd.id)}
                      onToggleComplete={() => toggleStep(cmd.id)}
                    />
                  ))}
                </div>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="deploy-commands">
              <AccordionTrigger className="text-sm font-medium">
                <div className="flex items-center gap-2">
                  <Rocket className="h-4 w-4 text-emerald-500" />
                  Deploy ({deployCommands.filter(c => completedSteps.has(c.id)).length}/{deployCommands.length})
                </div>
              </AccordionTrigger>
              <AccordionContent>
                <div className="space-y-3 pt-2">
                  {deployCommands.map(cmd => (
                    <CommandBlock
                      key={cmd.id}
                      command={cmd}
                      completed={completedSteps.has(cmd.id)}
                      onToggleComplete={() => toggleStep(cmd.id)}
                    />
                  ))}
                </div>
              </AccordionContent>
            </AccordionItem>
          </Accordion>

          <div className="flex gap-3">
            <Button variant="outline" onClick={() => setPhase("review")}>
              Back to Review
            </Button>
            <Button onClick={() => setPhase("verify")}>
              <CheckCheck className="h-4 w-4 mr-2" />
              Proceed to Verify
              <ArrowRight className="h-4 w-4 ml-2" />
            </Button>
          </div>
        </div>
      )}

      {/* ═══ VERIFY PHASE ═══ */}
      {phase === "verify" && (
        <div className="space-y-6">
          <p className="text-sm text-muted-foreground">
            Verify the deployment was successful and test alarm notifications.
          </p>

          <Accordion type="multiple" defaultValue={["verify-commands", "test-commands"]}>
            <AccordionItem value="verify-commands">
              <AccordionTrigger className="text-sm font-medium">
                <div className="flex items-center gap-2">
                  <CheckCheck className="h-4 w-4 text-emerald-500" />
                  Verification ({verifyCommands.filter(c => completedSteps.has(c.id)).length}/{verifyCommands.length})
                </div>
              </AccordionTrigger>
              <AccordionContent>
                <div className="space-y-3 pt-2">
                  {verifyCommands.map(cmd => (
                    <CommandBlock
                      key={cmd.id}
                      command={cmd}
                      completed={completedSteps.has(cmd.id)}
                      onToggleComplete={() => toggleStep(cmd.id)}
                    />
                  ))}
                </div>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="test-commands">
              <AccordionTrigger className="text-sm font-medium">
                <div className="flex items-center gap-2">
                  <Zap className="h-4 w-4 text-amber-500" />
                  Test Alarms ({testCommands.filter(c => completedSteps.has(c.id)).length}/{testCommands.length})
                </div>
              </AccordionTrigger>
              <AccordionContent>
                <div className="space-y-3 pt-2">
                  {testCommands.map(cmd => (
                    <CommandBlock
                      key={cmd.id}
                      command={cmd}
                      completed={completedSteps.has(cmd.id)}
                      onToggleComplete={() => toggleStep(cmd.id)}
                    />
                  ))}
                </div>
              </AccordionContent>
            </AccordionItem>
          </Accordion>

          {/* Resource Table */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-primary" />
                Deployed Resources
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ResourceTable resources={resourcesQuery.data ?? []} />
            </CardContent>
          </Card>

          {/* Completion */}
          <Card className={requiredComplete ? "border-emerald-500/30 bg-emerald-500/5" : "border-border"}>
            <CardContent className="pt-4">
              <div className="flex items-center gap-3">
                {requiredComplete ? (
                  <CheckCircle2 className="h-6 w-6 text-emerald-500" />
                ) : (
                  <Clock className="h-6 w-6 text-muted-foreground" />
                )}
                <div>
                  <p className="font-medium text-sm">
                    {requiredComplete
                      ? "Monitoring stack deployed successfully!"
                      : `${commands.filter(c => c.required && !completedSteps.has(c.id)).length} required steps remaining`}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {requiredComplete
                      ? "CloudWatch alarms are active. Notifications will fire within 5 minutes of threshold breach."
                      : "Complete all required steps to finish deployment."}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="flex gap-3">
            <Button variant="outline" onClick={() => setPhase("deploy")}>
              Back to Deploy
            </Button>
            <Button variant="outline" onClick={() => {
              setPhase("configure");
              setCompletedSteps(new Set());
            }}>
              Start Over
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
