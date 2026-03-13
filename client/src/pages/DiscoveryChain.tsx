import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import { useState, useMemo, useEffect, useCallback } from "react";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import {
  GitMerge, Globe, Search, Shield, ScanLine, Play, Square,
  Clock, AlertTriangle, ArrowRight, ArrowDown,
  Loader2, CheckCircle2, XCircle, SkipForward,
  BarChart3, Target, Fingerprint, Network,
  ChevronDown, ChevronRight, RefreshCw, Trash2,
  Eye, Zap, Activity, Info, Filter, ExternalLink,
} from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

// ─── Types ──────────────────────────────────────────────────────────

interface StageStatus {
  stageId: string;
  status: string;
  startedAt?: number;
  completedAt?: number | null;
  durationMs?: number | null;
  inputTargetCount: number;
  outputCount: number;
  findingCount: number;
  errors: string[];
}

// ─── Constants ──────────────────────────────────────────────────────

const STAGE_META: Record<string, { label: string; icon: React.ComponentType<{ className?: string }>; color: string; description: string }> = {
  amass: {
    label: "Amass",
    icon: Globe,
    color: "text-blue-400",
    description: "Subdomain enumeration & DNS discovery",
  },
  nmap: {
    label: "Nmap",
    icon: Search,
    color: "text-emerald-400",
    description: "Port scanning & service detection",
  },
  service_fingerprinter: {
    label: "Fingerprinter",
    icon: Fingerprint,
    color: "text-amber-400",
    description: "Deep service version & vulnerability fingerprinting",
  },
  nuclei: {
    label: "Nuclei",
    icon: ScanLine,
    color: "text-red-400",
    description: "Template-based vulnerability scanning",
  },
  service_audit: {
    label: "Service Audit",
    icon: Shield,
    color: "text-purple-400",
    description: "SSH/FTP/SMTP/SNMP/RDP/DNS/HTTP/TLS deep security audits",
  },
};

const STATUS_STYLES: Record<string, { bg: string; text: string; icon: React.ComponentType<{ className?: string }> }> = {
  pending: { bg: "bg-muted/50", text: "text-muted-foreground", icon: Clock },
  running: { bg: "bg-blue-500/10", text: "text-blue-400", icon: Loader2 },
  completed: { bg: "bg-emerald-500/10", text: "text-emerald-400", icon: CheckCircle2 },
  failed: { bg: "bg-red-500/10", text: "text-red-400", icon: XCircle },
  skipped: { bg: "bg-muted/30", text: "text-muted-foreground", icon: SkipForward },
  cancelled: { bg: "bg-amber-500/10", text: "text-amber-400", icon: Square },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-blue-500",
  info: "bg-slate-500",
};

// ─── Component ──────────────────────────────────────────────────────

export default function DiscoveryChain() {
  // Form state
  const [domains, setDomains] = useState("");
  const [engagementId, setEngagementId] = useState<string>("");
  const [nmapProfile, setNmapProfile] = useState("standard");
  const [amassMode, setAmassMode] = useState("passive");
  const [skipAmass, setSkipAmass] = useState(false);
  const [skipNmap, setSkipNmap] = useState(false);
  const [skipFingerprint, setSkipFingerprint] = useState(false);
  const [skipNuclei, setSkipNuclei] = useState(false);
  const [enableServiceAudit, setEnableServiceAudit] = useState(true);
  const [continueOnFailure, setContinueOnFailure] = useState(false);

  // Active chain tracking
  const [activeChainId, setActiveChainId] = useState<string | null>(null);
  const [showHistory, setShowHistory] = useState(false);
  const [expandedRun, setExpandedRun] = useState<string | null>(null);
  const [showConfig, setShowConfig] = useState(false);
  const [findingsStageFilter, setFindingsStageFilter] = useState<string>("all");
  const [findingsSeverityFilter, setFindingsSeverityFilter] = useState<string>("all");
  const [findingsPage, setFindingsPage] = useState(0);

  // tRPC queries
  const startMutation = trpc.discoveryChain.start.useMutation();
  const cancelMutation = trpc.discoveryChain.cancel.useMutation();
  const deleteMutation = trpc.discoveryChain.delete.useMutation();
  const utils = trpc.useUtils();

  const statusQuery = trpc.discoveryChain.getStatus.useQuery(
    { chainId: activeChainId! },
    { enabled: !!activeChainId, refetchInterval: activeChainId ? 3000 : false }
  );

  const findingsQuery = trpc.discoveryChain.getFindings.useQuery(
    {
      chainId: activeChainId!,
      stageId: findingsStageFilter !== "all" ? findingsStageFilter as any : undefined,
      severity: findingsSeverityFilter !== "all" ? findingsSeverityFilter as any : undefined,
      limit: 50,
      offset: findingsPage * 50,
    },
    { enabled: !!activeChainId && !!chainStatus, refetchInterval: activeChainId ? 5000 : false }
  );

  const dataFlowQuery = trpc.discoveryChain.getDataFlow.useQuery(
    { chainId: activeChainId! },
    { enabled: !!activeChainId && statusQuery.data?.status !== "pending" }
  );

  const historyQuery = trpc.discoveryChain.getHistory.useQuery(
    { limit: 20 },
    { enabled: showHistory }
  );

  const stageDefsQuery = trpc.discoveryChain.getStageDefinitions.useQuery();

  // Stop polling when chain completes
  useEffect(() => {
    if (statusQuery.data && ["completed", "failed", "cancelled"].includes(statusQuery.data.status)) {
      // Final refetch then stop
      utils.discoveryChain.getStatus.invalidate({ chainId: activeChainId! });
      utils.discoveryChain.getDataFlow.invalidate({ chainId: activeChainId! });
    }
  }, [statusQuery.data?.status]);

  // ─── Handlers ───────────────────────────────────────────────────

  const handleStart = useCallback(async () => {
    const domainList = domains.split(/[\s,;]+/).filter(Boolean).map(d => d.trim().toLowerCase());
    if (domainList.length === 0) {
      toast.error("Enter at least one domain");
      return;
    }

    const skipStages: string[] = [];
    if (skipAmass) skipStages.push("amass");
    if (skipNmap) skipStages.push("nmap");
    if (skipFingerprint) skipStages.push("service_fingerprinter");
    if (skipNuclei) skipStages.push("nuclei");
    if (!enableServiceAudit) skipStages.push("service_audit");

    if (skipStages.length >= 5) {
      toast.error("Cannot skip all stages");
      return;
    }

    try {
      const result = await startMutation.mutateAsync({
        domains: domainList,
        engagementId: engagementId ? Number(engagementId) : undefined,
        skipStages: skipStages as any,
        stageConfig: {
          amass: { mode: amassMode as any },
          nmap: { profile: nmapProfile as any },
        },
        serviceAudit: enableServiceAudit ? {
          enable: true,
          scanners: ['ssh_audit', 'ftp_audit', 'smtp_audit', 'snmp_audit', 'rdp_audit', 'dns_audit', 'http_header_audit', 'tls_deep_scan'],
        } : undefined,
        continueOnPartialFailure: continueOnFailure,
      });
      setActiveChainId(result.chainId);
      toast.success("Discovery chain started");
    } catch (err: any) {
      toast.error(sanitizeErrorForToast(err?.message || "Failed to start chain"));
    }
  }, [domains, engagementId, nmapProfile, amassMode, skipAmass, skipNmap, skipFingerprint, skipNuclei, enableServiceAudit, continueOnFailure]);

  const handleCancel = useCallback(async () => {
    if (!activeChainId) return;
    try {
      await cancelMutation.mutateAsync({ chainId: activeChainId });
      toast.info("Chain cancelled");
    } catch (err: any) {
      toast.error(sanitizeErrorForToast(err?.message || "Failed to cancel"));
    }
  }, [activeChainId]);

  const handleDelete = useCallback(async (chainId: string) => {
    try {
      await deleteMutation.mutateAsync({ chainId });
      toast.success("Chain run deleted");
      utils.discoveryChain.getHistory.invalidate();
      if (activeChainId === chainId) setActiveChainId(null);
    } catch (err: any) {
      toast.error(sanitizeErrorForToast(err?.message || "Failed to delete"));
    }
  }, [activeChainId]);

  const handleViewRun = useCallback((chainId: string) => {
    setActiveChainId(chainId);
    setShowHistory(false);
  }, []);

  // ─── Derived state ─────────────────────────────────────────────

  const isRunning = statusQuery.data?.status === "running" || statusQuery.data?.status === "pending";
  const chainStatus = statusQuery.data;
  const dataFlow = dataFlowQuery.data;

  const severityTotals = useMemo(() => {
    if (!chainStatus?.summary?.findingsBySeverity) return {};
    return chainStatus.summary.findingsBySeverity as Record<string, number>;
  }, [chainStatus?.summary?.findingsBySeverity]);

  // ─── Render ─────────────────────────────────────────────────────

  return (
    <AppShell>
      <div className="p-6 space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <GitMerge className="w-7 h-7 text-primary" />
              <h1 className="text-2xl font-bold tracking-tight">Discovery Chain</h1>
            </div>
            <p className="text-muted-foreground text-sm max-w-2xl">
              Automated reconnaissance pipeline that sequences Amass subdomain discovery, Nmap port scanning,
              service fingerprinting, and Nuclei vulnerability scanning — each stage feeds its output into the next.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowHistory(!showHistory)}
              className="gap-1.5"
            >
              <Activity className="w-4 h-4" />
              History
            </Button>
          </div>
        </div>

        {/* History Panel */}
        {showHistory && (
          <Card className="border-border/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Activity className="w-4 h-4" />
                Chain Run History
              </CardTitle>
            </CardHeader>
            <CardContent>
              {historyQuery.isLoading ? (
                <div className="flex items-center gap-2 text-muted-foreground text-sm py-4">
                  <Loader2 className="w-4 h-4 animate-spin" /> Loading history...
                </div>
              ) : !historyQuery.data?.runs?.length ? (
                <p className="text-muted-foreground text-sm py-4">No chain runs yet. Start one above.</p>
              ) : (
                <div className="space-y-2">
                  {historyQuery.data.runs.map((run: any) => (
                    <div
                      key={run.id}
                      className="flex items-center justify-between p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <StatusIcon status={run.status} />
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs text-muted-foreground">{run.id.slice(0, 16)}...</span>
                            <Badge variant="outline" className="text-xs">
                              {run.stagesCompleted}/{run.stagesTotal} stages
                            </Badge>
                          </div>
                          <div className="flex items-center gap-2 text-xs text-muted-foreground mt-0.5">
                            <span>{(run.domains as string[])?.join(", ")}</span>
                            {run.startedAt && (
                              <>
                                <span>·</span>
                                <span>{new Date(run.startedAt).toLocaleString()}</span>
                              </>
                            )}
                            {run.durationMs && (
                              <>
                                <span>·</span>
                                <span>{formatDuration(run.durationMs)}</span>
                              </>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-1">
                        <SeverityPills counts={run.findingsBySeverity || {}} compact />
                        <Button variant="ghost" size="sm" onClick={() => handleViewRun(run.id)} className="gap-1">
                          <Eye className="w-3.5 h-3.5" /> View
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDelete(run.id)}
                          className="text-destructive hover:text-destructive"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Configuration Panel */}
        <Card className="border-border/50">
          <CardHeader className="pb-3 cursor-pointer" onClick={() => setShowConfig(!showConfig)}>
            <CardTitle className="text-base flex items-center gap-2">
              {showConfig ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
              <Zap className="w-4 h-4 text-primary" />
              Launch New Chain
            </CardTitle>
          </CardHeader>
          {showConfig && (
            <CardContent className="space-y-4">
              {/* Domain Input */}
              <div className="space-y-2">
                <Label className="text-sm font-medium">Target Domains</Label>
                <Input
                  placeholder="example.com, target.org (comma or space separated)"
                  value={domains}
                  onChange={(e) => setDomains(e.target.value)}
                  className="font-mono text-sm"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Engagement ID */}
                <div className="space-y-2">
                  <Label className="text-sm font-medium">Engagement ID (optional)</Label>
                  <Input
                    placeholder="e.g. 42"
                    value={engagementId}
                    onChange={(e) => setEngagementId(e.target.value)}
                    type="number"
                    className="font-mono text-sm"
                  />
                </div>

                {/* Amass Mode */}
                <div className="space-y-2">
                  <Label className="text-sm font-medium">Amass Mode</Label>
                  <Select value={amassMode} onValueChange={setAmassMode}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="passive">Passive</SelectItem>
                      <SelectItem value="active">Active</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {/* Nmap Profile */}
                <div className="space-y-2">
                  <Label className="text-sm font-medium">Nmap Profile</Label>
                  <Select value={nmapProfile} onValueChange={setNmapProfile}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="quick">Quick (Top 100)</SelectItem>
                      <SelectItem value="standard">Standard (Top 1000)</SelectItem>
                      <SelectItem value="deep">Deep (All 65535)</SelectItem>
                      <SelectItem value="stealth">Stealth (SYN)</SelectItem>
                      <SelectItem value="service">Service Detection</SelectItem>
                      <SelectItem value="vuln">Vulnerability</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* Skip Stages */}
              <div className="space-y-3">
                <Label className="text-sm font-medium">Stage Controls</Label>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {Object.entries(STAGE_META).map(([id, meta]) => {
                    // service_audit uses "enable" logic (inverted from skip)
                    const isEnabled =
                      id === "amass" ? !skipAmass :
                      id === "nmap" ? !skipNmap :
                      id === "service_fingerprinter" ? !skipFingerprint :
                      id === "nuclei" ? !skipNuclei :
                      id === "service_audit" ? enableServiceAudit :
                      true;
                    const handleToggle = (checked: boolean) => {
                      if (id === "amass") setSkipAmass(!checked);
                      else if (id === "nmap") setSkipNmap(!checked);
                      else if (id === "service_fingerprinter") setSkipFingerprint(!checked);
                      else if (id === "nuclei") setSkipNuclei(!checked);
                      else if (id === "service_audit") setEnableServiceAudit(checked);
                    };
                    return (
                      <div key={id} className="flex items-center gap-2 p-2 rounded-md bg-muted/30">
                        <Switch
                          checked={isEnabled}
                          onCheckedChange={handleToggle}
                          id={`skip-${id}`}
                        />
                        <Label htmlFor={`skip-${id}`} className="text-xs cursor-pointer flex items-center gap-1.5">
                          <meta.icon className={`w-3.5 h-3.5 ${!isEnabled ? "text-muted-foreground" : meta.color}`} />
                          {meta.label}
                        </Label>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Continue on Failure */}
              <div className="flex items-center gap-2 p-2 rounded-md bg-muted/30 w-fit">
                <Switch
                  checked={continueOnFailure}
                  onCheckedChange={setContinueOnFailure}
                  id="continue-on-failure"
                />
                <Label htmlFor="continue-on-failure" className="text-xs cursor-pointer">
                  Continue on partial stage failure
                </Label>
              </div>

              {/* Launch Button */}
              <div className="flex items-center gap-3 pt-2">
                <Button
                  onClick={handleStart}
                  disabled={startMutation.isPending || isRunning}
                  className="gap-2"
                >
                  {startMutation.isPending ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Play className="w-4 h-4" />
                  )}
                  Launch Discovery Chain
                </Button>
                {isRunning && (
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={handleCancel}
                    disabled={cancelMutation.isPending}
                    className="gap-1.5"
                  >
                    <Square className="w-3.5 h-3.5" /> Cancel
                  </Button>
                )}
              </div>
            </CardContent>
          )}
        </Card>

        {/* Pipeline Visualization */}
        {chainStatus && (
          <>
            {/* Summary Bar */}
            <div className="grid grid-cols-2 md:grid-cols-5 lg:grid-cols-10 gap-3">
              <SummaryCard label="Status" value={chainStatus.status} icon={Activity} highlight />
              <SummaryCard
                label="Progress"
                value={`${chainStatus.progress}%`}
                icon={BarChart3}
              />
              <SummaryCard
                label="Subdomains"
                value={String(chainStatus.summary?.totalSubdomains || 0)}
                icon={Globe}
              />
              <SummaryCard
                label="Hosts"
                value={String(chainStatus.summary?.totalHosts || 0)}
                icon={Network}
              />
              <SummaryCard
                label="Open Ports"
                value={String(chainStatus.summary?.totalOpenPorts || 0)}
                icon={Target}
              />
              <SummaryCard
                label="Services"
                value={String(chainStatus.summary?.totalServices || 0)}
                icon={Fingerprint}
              />
              <SummaryCard
                label="Findings"
                value={String(chainStatus.summary?.totalFindings || 0)}
                icon={AlertTriangle}
              />
              <SummaryCard
                label="Vulns"
                value={String(chainStatus.summary?.totalVulnerabilities || 0)}
                icon={Zap}
              />
              <SummaryCard
                label="CVEs"
                value={String(chainStatus.summary?.uniqueCves?.length || 0)}
                icon={Shield}
              />
              <SummaryCard
                label="Duration"
                value={chainStatus.durationMs ? formatDuration(chainStatus.durationMs) : "—"}
                icon={Clock}
              />
            </div>

            {/* Severity Breakdown */}
            {Object.keys(severityTotals).length > 0 && (
              <Card className="border-border/50">
                <CardContent className="py-4">
                  <div className="flex items-center gap-4 flex-wrap">
                    <span className="text-sm font-medium text-muted-foreground">Findings by Severity:</span>
                    <SeverityPills counts={severityTotals} />
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Stage Pipeline Diagram */}
            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <GitMerge className="w-4 h-4 text-primary" />
                  Pipeline Stages
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-1">
                  {(chainStatus.stages || []).map((stage: StageStatus, idx: number) => {
                    const meta = STAGE_META[stage.stageId] || {
                      label: stage.stageId,
                      icon: Info,
                      color: "text-muted-foreground",
                      description: "",
                    };
                    const style = STATUS_STYLES[stage.status] || STATUS_STYLES.pending;
                    const StatusIconComp = style.icon;
                    const flow = dataFlow?.flows?.find((f: any) => f.to === stage.stageId);

                    return (
                      <div key={stage.stageId}>
                        {/* Flow Arrow */}
                        {idx > 0 && flow && flow.targetCount > 0 && (
                          <div className="flex items-center gap-2 pl-8 py-1">
                            <ArrowDown className="w-4 h-4 text-muted-foreground/50" />
                            <span className="text-xs text-muted-foreground font-mono">
                              {flow.targetCount} target{flow.targetCount !== 1 ? "s" : ""} extracted
                            </span>
                          </div>
                        )}

                        {/* Stage Card */}
                        <div
                          className={`flex items-center gap-4 p-4 rounded-lg border transition-all ${style.bg} border-border/30`}
                        >
                          {/* Status Icon */}
                          <div className={`flex-shrink-0 ${style.text}`}>
                            <StatusIconComp
                              className={`w-5 h-5 ${stage.status === "running" ? "animate-spin" : ""}`}
                            />
                          </div>

                          {/* Stage Icon */}
                          <div className={`flex-shrink-0 ${meta.color}`}>
                            <meta.icon className="w-6 h-6" />
                          </div>

                          {/* Stage Info */}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-semibold text-sm">{meta.label}</span>
                              <Badge variant="outline" className="text-xs capitalize">
                                {stage.status}
                              </Badge>
                            </div>
                            <p className="text-xs text-muted-foreground mt-0.5">{meta.description}</p>
                          </div>

                          {/* Stage Metrics */}
                          <div className="flex items-center gap-4 text-xs text-muted-foreground">
                            <div className="text-center">
                              <div className="font-mono font-bold text-foreground">{stage.inputTargetCount}</div>
                              <div>In</div>
                            </div>
                            <ArrowRight className="w-3.5 h-3.5" />
                            <div className="text-center">
                              <div className="font-mono font-bold text-foreground">{stage.outputCount}</div>
                              <div>Out</div>
                            </div>
                            <div className="text-center pl-2 border-l border-border/30">
                              <div className="font-mono font-bold text-foreground">{stage.findingCount}</div>
                              <div>Findings</div>
                            </div>
                            {stage.durationMs != null && stage.durationMs > 0 && (
                              <div className="text-center pl-2 border-l border-border/30">
                                <div className="font-mono font-bold text-foreground">
                                  {formatDuration(stage.durationMs)}
                                </div>
                                <div>Time</div>
                              </div>
                            )}
                          </div>

                          {/* Errors */}
                          {stage.errors?.length > 0 && (
                            <div className="flex-shrink-0">
                              <Badge variant="destructive" className="text-xs">
                                {stage.errors.length} error{stage.errors.length !== 1 ? "s" : ""}
                              </Badge>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>

            {/* Data Flow Visualization */}
            {dataFlow && (
              <Card className="border-border/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Network className="w-4 h-4 text-primary" />
                    Data Flow
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {dataFlow.flows?.map((flow: any, idx: number) => (
                      <div key={idx} className="flex items-center gap-3">
                        <Badge variant="outline" className="font-mono text-xs min-w-[100px] justify-center">
                          {flow.from}
                        </Badge>
                        <div className="flex items-center gap-1 text-muted-foreground">
                          <ArrowRight className="w-4 h-4" />
                          <span className="text-xs font-mono">{flow.targetCount}</span>
                          <ArrowRight className="w-4 h-4" />
                        </div>
                        <Badge variant="outline" className="font-mono text-xs min-w-[100px] justify-center">
                          {flow.to}
                        </Badge>
                        {flow.targets?.length > 0 && (
                          <span className="text-xs text-muted-foreground truncate max-w-[300px]">
                            {flow.targets.slice(0, 3).join(", ")}
                            {flow.targets.length > 3 ? ` +${flow.targets.length - 3} more` : ""}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>

                  {/* Nuclei Template Selection */}
                  {dataFlow.nucleiTemplateSelection && (
                    <div className="mt-4 pt-4 border-t border-border/30">
                      <h4 className="text-sm font-medium mb-2 flex items-center gap-1.5">
                        <ScanLine className="w-3.5 h-3.5 text-red-400" />
                        Nuclei Template Selection
                      </h4>
                      <div className="flex flex-wrap gap-1.5">
                        {(dataFlow.nucleiTemplateSelection.categories || []).map((cat: string) => (
                          <Badge key={cat} variant="secondary" className="text-xs">
                            {cat}
                          </Badge>
                        ))}
                      </div>
                      {dataFlow.nucleiTemplateSelection.tags?.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {dataFlow.nucleiTemplateSelection.tags.slice(0, 20).map((tag: string) => (
                            <Badge key={tag} variant="outline" className="text-xs font-mono">
                              {tag}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* ─── Findings Detail Section ─── */}
            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Eye className="w-4 h-4 text-primary" />
                    Discovery Findings
                    {findingsQuery.data && (
                      <Badge variant="secondary" className="ml-1 text-xs">
                        {findingsQuery.data.total}
                      </Badge>
                    )}
                  </CardTitle>
                  <div className="flex items-center gap-2">
                    <Select value={findingsStageFilter} onValueChange={(v) => { setFindingsStageFilter(v); setFindingsPage(0); }}>
                      <SelectTrigger className="h-8 w-[140px] text-xs">
                        <Filter className="w-3 h-3 mr-1" />
                        <SelectValue placeholder="Stage" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Stages</SelectItem>
                        {Object.entries(STAGE_META).map(([id, meta]) => (
                          <SelectItem key={id} value={id}>{meta.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Select value={findingsSeverityFilter} onValueChange={(v) => { setFindingsSeverityFilter(v); setFindingsPage(0); }}>
                      <SelectTrigger className="h-8 w-[120px] text-xs">
                        <SelectValue placeholder="Severity" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Severity</SelectItem>
                        <SelectItem value="critical">Critical</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="low">Low</SelectItem>
                        <SelectItem value="info">Info</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                {findingsQuery.isLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
                  </div>
                ) : findingsQuery.data && findingsQuery.data.findings.length > 0 ? (
                  <div className="space-y-2">
                    {findingsQuery.data.findings.map((f: any, idx: number) => (
                      <FindingRow key={`${f.host}-${f.port}-${f.tool}-${idx}`} finding={f} />
                    ))}

                    {/* Pagination */}
                    {findingsQuery.data.total > 50 && (
                      <div className="flex items-center justify-between pt-3 border-t border-border/30">
                        <span className="text-xs text-muted-foreground">
                          Showing {findingsPage * 50 + 1}–{Math.min((findingsPage + 1) * 50, findingsQuery.data.total)} of {findingsQuery.data.total}
                        </span>
                        <div className="flex gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            disabled={findingsPage === 0}
                            onClick={() => setFindingsPage(p => p - 1)}
                          >
                            Previous
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            disabled={(findingsPage + 1) * 50 >= findingsQuery.data.total}
                            onClick={() => setFindingsPage(p => p + 1)}
                          >
                            Next
                          </Button>
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Search className="w-8 h-8 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">
                      {chainStatus?.status === "running" ? "Findings will appear as stages complete..." : "No findings match the current filters."}
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </>
        )}

        {/* Empty State */}
        {!chainStatus && !showHistory && (
          <Card className="border-border/50 border-dashed">
            <CardContent className="py-12 text-center">
              <GitMerge className="w-12 h-12 text-muted-foreground/30 mx-auto mb-4" />
              <h3 className="text-lg font-medium mb-1">No Active Chain</h3>
              <p className="text-sm text-muted-foreground max-w-md mx-auto">
                Configure and launch a discovery chain above to automatically sequence
                reconnaissance tools across your target domains.
              </p>
              <Button
                variant="outline"
                className="mt-4 gap-1.5"
                onClick={() => setShowConfig(true)}
              >
                <Play className="w-4 h-4" /> Configure Chain
              </Button>
            </CardContent>
          </Card>
        )}
      </div>
    </AppShell>
  );
}

// ─── Sub-Components ─────────────────────────────────────────────────

function SummaryCard({
  label,
  value,
  icon: Icon,
  highlight,
}: {
  label: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
  highlight?: boolean;
}) {
  return (
    <Card className="border-border/30">
      <CardContent className="py-3 px-4">
        <div className="flex items-center gap-2">
          <Icon className={`w-4 h-4 ${highlight ? "text-primary" : "text-muted-foreground"}`} />
          <span className="text-xs text-muted-foreground">{label}</span>
        </div>
        <div className="font-bold text-lg mt-1 capitalize">{value}</div>
      </CardContent>
    </Card>
  );
}

function StatusIcon({ status }: { status: string }) {
  const style = STATUS_STYLES[status] || STATUS_STYLES.pending;
  const Icon = style.icon;
  return (
    <div className={`${style.text}`}>
      <Icon className={`w-4 h-4 ${status === "running" ? "animate-spin" : ""}`} />
    </div>
  );
}

function SeverityPills({ counts, compact }: { counts: Record<string, number>; compact?: boolean }) {
  return (
    <div className="flex items-center gap-1.5">
      {["critical", "high", "medium", "low", "info"].map((sev) => {
        const count = counts[sev] || 0;
        if (count === 0 && compact) return null;
        return (
          <div
            key={sev}
            className="flex items-center gap-1 text-xs"
          >
            <div className={`w-2 h-2 rounded-full ${SEVERITY_COLORS[sev]}`} />
            <span className="font-mono">{count}</span>
            {!compact && <span className="text-muted-foreground capitalize">{sev}</span>}
          </div>
        );
      })}
    </div>
  );
}

function FindingRow({ finding: f }: { finding: any }) {
  const [expanded, setExpanded] = useState(false);
  const sevColor = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.info;
  const stageMeta = STAGE_META[toolToStageUI(f.tool)] || { label: f.tool, icon: Info, color: "text-muted-foreground" };
  const StageIcon = stageMeta.icon;

  return (
    <div
      className="rounded-lg border border-border/40 bg-card/50 hover:bg-card/80 transition-colors cursor-pointer"
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-center gap-3 px-4 py-3">
        {/* Severity dot */}
        <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${sevColor}`} />

        {/* Title + host */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium truncate">{f.title}</span>
            {f.cveId && (
              <Badge variant="destructive" className="text-[10px] px-1.5 py-0 h-4 shrink-0">
                {f.cveId}
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="text-xs font-mono text-muted-foreground">
              {f.host}{f.port ? `:${f.port}` : ""}
            </span>
            {f.evidence?.service && (
              <Badge variant="outline" className="text-[10px] px-1.5 py-0 h-4">
                {f.evidence.service}
              </Badge>
            )}
          </div>
        </div>

        {/* Type badge */}
        <Badge variant="secondary" className="text-[10px] capitalize shrink-0">
          {f.type}
        </Badge>

        {/* Stage icon */}
        <div className={`flex items-center gap-1 shrink-0 ${stageMeta.color}`}>
          <StageIcon className="w-3.5 h-3.5" />
          <span className="text-xs">{stageMeta.label}</span>
        </div>

        {/* Severity label */}
        <Badge
          className={`text-[10px] capitalize shrink-0 ${
            f.severity === "critical" ? "bg-red-500/20 text-red-400 border-red-500/30" :
            f.severity === "high" ? "bg-orange-500/20 text-orange-400 border-orange-500/30" :
            f.severity === "medium" ? "bg-amber-500/20 text-amber-400 border-amber-500/30" :
            f.severity === "low" ? "bg-blue-500/20 text-blue-400 border-blue-500/30" :
            "bg-slate-500/20 text-slate-400 border-slate-500/30"
          }`}
          variant="outline"
        >
          {f.severity}
        </Badge>

        {/* Confidence */}
        {f.confidence != null && (
          <span className="text-xs text-muted-foreground font-mono shrink-0">
            {Math.round(f.confidence * 100)}%
          </span>
        )}

        {/* Expand chevron */}
        {expanded ? (
          <ChevronDown className="w-4 h-4 text-muted-foreground shrink-0" />
        ) : (
          <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />
        )}
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 pb-3 pt-1 border-t border-border/30 space-y-2">
          {f.description && (
            <p className="text-xs text-muted-foreground leading-relaxed">{f.description}</p>
          )}
          <div className="flex flex-wrap gap-2 text-xs">
            {f.tool && (
              <span className="font-mono bg-muted/50 px-2 py-0.5 rounded">tool: {f.tool}</span>
            )}
            {f.cweId && (
              <span className="font-mono bg-muted/50 px-2 py-0.5 rounded">{f.cweId}</span>
            )}
            {f.attackTechnique && (
              <span className="font-mono bg-muted/50 px-2 py-0.5 rounded">{f.attackTechnique}</span>
            )}
            {f.evidence?.assetType && (
              <span className="font-mono bg-muted/50 px-2 py-0.5 rounded">asset: {f.evidence.assetType}</span>
            )}
            {f.evidence?.protocol && (
              <span className="font-mono bg-muted/50 px-2 py-0.5 rounded">proto: {f.evidence.protocol}</span>
            )}
            {f.evidence?.ports && f.evidence.ports.length > 0 && (
              <span className="font-mono bg-muted/50 px-2 py-0.5 rounded">
                ports: {f.evidence.ports.join(", ")}
              </span>
            )}
          </div>
          {f.corroborated && f.corroboratingTools?.length > 0 && (
            <div className="flex items-center gap-1.5 text-xs text-emerald-400">
              <CheckCircle2 className="w-3 h-3" />
              Corroborated by: {f.corroboratingTools.join(", ")}
            </div>
          )}
          {f.crossRefs?.length > 0 && (
            <div className="text-xs text-muted-foreground">
              Cross-refs: {f.crossRefs.join(", ")}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function toolToStageUI(tool: string): string {
  switch (tool) {
    case "amass": return "amass";
    case "nmap": return "nmap";
    case "service_fingerprinter": return "service_fingerprinter";
    case "nuclei_info":
    case "nuclei_vuln":
    case "nuclei_critical":
      return "nuclei";
    case "ssh_audit":
    case "ftp_audit":
    case "smtp_audit":
    case "snmp_audit":
    case "rdp_audit":
    case "dns_audit":
    case "http_header_audit":
    case "tls_deep_scan":
    case "nikto":
    case "wapiti":
    case "arachni":
      return "service_audit";
    default:
      return tool;
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  if (minutes < 60) return `${minutes}m ${remainingSeconds}s`;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return `${hours}h ${remainingMinutes}m`;
}
