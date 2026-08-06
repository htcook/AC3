import { useState, useMemo, useCallback, useEffect } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogClose } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Plus, Play, Pause, Square, Trash2, Edit, Eye, ArrowRight, ArrowDown,
  ChevronRight, ChevronDown, Clock, AlertTriangle, CheckCircle2, XCircle,
  Zap, Target, Shield, Brain, Layers, Rocket, RefreshCw, SkipForward,
  GitBranch, Workflow, Activity, Search, Filter, MoreHorizontal, Copy,
  Crosshair, Bug, Globe, Radio, ChevronUp, GripVertical, Sparkles,
  AlertCircle, Timer, ArrowUpDown, RotateCcw, Settings2, FileText,
  ClipboardList, ExternalLink
} from "lucide-react";
import { useLocation, useRoute } from "wouter";
import AppShell from "@/components/AppShell";
import { toast } from "sonner";
import { sanitizeErrorForToast } from "@/lib/error-sanitizer";

// ─── Types ──────────────────────────────────────────────────────────────────

type CampaignStatus = "draft" | "ready" | "running" | "paused" | "completed" | "failed" | "aborted";
type StageStatus = "pending" | "waiting" | "running" | "completed" | "failed" | "skipped" | "timed_out" | "aborted";
type StageType = "recon" | "enumeration" | "vuln_scan" | "phishing" | "exploitation" | "post_exploit" | "lateral_move" | "c2_deploy" | "exfiltration" | "cleanup" | "custom";

interface Condition {
  field: string;
  operator: string;
  value: string | number | boolean;
}

// ─── Constants ──────────────────────────────────────────────────────────────

const STAGE_TYPES: { value: StageType; label: string; icon: React.ReactNode; color: string }[] = [
  { value: "recon", label: "Reconnaissance", icon: <Search className="w-3.5 h-3.5" />, color: "text-blue-400" },
  { value: "enumeration", label: "Enumeration", icon: <Target className="w-3.5 h-3.5" />, color: "text-cyan-400" },
  { value: "vuln_scan", label: "Vulnerability Scan", icon: <Bug className="w-3.5 h-3.5" />, color: "text-yellow-400" },
  { value: "phishing", label: "Phishing", icon: <Globe className="w-3.5 h-3.5" />, color: "text-orange-400" },
  { value: "exploitation", label: "Exploitation", icon: <Zap className="w-3.5 h-3.5" />, color: "text-red-400" },
  { value: "post_exploit", label: "Post-Exploitation", icon: <Shield className="w-3.5 h-3.5" />, color: "text-purple-400" },
  { value: "lateral_move", label: "Lateral Movement", icon: <ArrowRight className="w-3.5 h-3.5" />, color: "text-pink-400" },
  { value: "c2_deploy", label: "C2 Deployment", icon: <Radio className="w-3.5 h-3.5" />, color: "text-emerald-400" },
  { value: "exfiltration", label: "Exfiltration", icon: <FileText className="w-3.5 h-3.5" />, color: "text-amber-400" },
  { value: "cleanup", label: "Cleanup", icon: <RotateCcw className="w-3.5 h-3.5" />, color: "text-gray-400" },
  { value: "custom", label: "Custom", icon: <Settings2 className="w-3.5 h-3.5" />, color: "text-indigo-400" },
];

const STATUS_CONFIG: Record<string, { label: string; color: string; bg: string; icon: React.ReactNode }> = {
  draft: { label: "Draft", color: "text-gray-400", bg: "bg-gray-500/10 border-gray-500/20", icon: <Edit className="w-3 h-3" /> },
  ready: { label: "Ready", color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/20", icon: <CheckCircle2 className="w-3 h-3" /> },
  running: { label: "Running", color: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/20", icon: <Activity className="w-3 h-3 animate-pulse" /> },
  paused: { label: "Paused", color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/20", icon: <Pause className="w-3 h-3" /> },
  completed: { label: "Completed", color: "text-green-400", bg: "bg-green-500/10 border-green-500/20", icon: <CheckCircle2 className="w-3 h-3" /> },
  failed: { label: "Failed", color: "text-red-400", bg: "bg-red-500/10 border-red-500/20", icon: <XCircle className="w-3 h-3" /> },
  aborted: { label: "Aborted", color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/20", icon: <Square className="w-3 h-3" /> },
  pending: { label: "Pending", color: "text-gray-400", bg: "bg-gray-500/10 border-gray-500/20", icon: <Clock className="w-3 h-3" /> },
  waiting: { label: "Waiting", color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/20", icon: <Timer className="w-3 h-3" /> },
  skipped: { label: "Skipped", color: "text-gray-500", bg: "bg-gray-500/10 border-gray-500/20", icon: <SkipForward className="w-3 h-3" /> },
  timed_out: { label: "Timed Out", color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/20", icon: <Timer className="w-3 h-3" /> },
};

const CONDITION_FIELDS = [
  { value: "total_vulns", label: "Total Vulnerabilities" },
  { value: "critical_vulns", label: "Critical Vulnerabilities" },
  { value: "high_vulns", label: "High Vulnerabilities" },
  { value: "exploits_succeeded", label: "Successful Exploits" },
  { value: "exploits_attempted", label: "Exploits Attempted" },
  { value: "c2_agents", label: "C2 Agents Deployed" },
  { value: "sessions_opened", label: "Sessions Opened" },
  { value: "hosts_scanned", label: "Hosts Scanned" },
  { value: "ports_found", label: "Ports Found" },
  { value: "stages_completed", label: "Stages Completed" },
  { value: "phishing_clicks", label: "Phishing Clicks" },
  { value: "creds_harvested", label: "Credentials Harvested" },
];

const CONDITION_OPERATORS = [
  { value: ">", label: ">" },
  { value: ">=", label: ">=" },
  { value: "<", label: "<" },
  { value: "<=", label: "<=" },
  { value: "==", label: "==" },
  { value: "!=", label: "!=" },
  { value: "exists", label: "exists" },
];

// ─── Status Badge Component ────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.draft;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs font-mono rounded border ${config.bg} ${config.color}`}>
      {config.icon}
      {config.label}
    </span>
  );
}

// ─── Stage Type Badge ──────────────────────────────────────────────────────

function StageTypeBadge({ type }: { type: string }) {
  const config = STAGE_TYPES.find((t) => t.value === type) || STAGE_TYPES[STAGE_TYPES.length - 1];
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-mono ${config.color}`}>
      {config.icon}
      {config.label}
    </span>
  );
}

// ─── Condition Editor ──────────────────────────────────────────────────────

function ConditionEditor({
  conditions,
  onChange,
  label,
}: {
  conditions: Condition[];
  onChange: (conditions: Condition[]) => void;
  label: string;
}) {
  const addCondition = () => {
    onChange([...conditions, { field: "total_vulns", operator: ">", value: 0 }]);
  };
  const removeCondition = (idx: number) => {
    onChange(conditions.filter((_, i) => i !== idx));
  };
  const updateCondition = (idx: number, updates: Partial<Condition>) => {
    const next = [...conditions];
    next[idx] = { ...next[idx], ...updates };
    onChange(next);
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <Label className="text-xs text-muted-foreground uppercase tracking-wider">{label}</Label>
        <Button variant="ghost" size="sm" onClick={addCondition} className="h-6 text-xs gap-1">
          <Plus className="w-3 h-3" /> Add
        </Button>
      </div>
      {conditions.length === 0 && (
        <p className="text-xs text-muted-foreground italic">No conditions — stage will always {label.includes("Entry") ? "execute" : "pass"}</p>
      )}
      {conditions.map((c, idx) => (
        <div key={idx} className="flex items-center gap-1.5">
          <Select value={c.field} onValueChange={(v) => updateCondition(idx, { field: v })}>
            <SelectTrigger className="h-7 text-xs flex-1 min-w-0">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {CONDITION_FIELDS.map((f) => (
                <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={c.operator} onValueChange={(v) => updateCondition(idx, { operator: v })}>
            <SelectTrigger className="h-7 text-xs w-16">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {CONDITION_OPERATORS.map((o) => (
                <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          {c.operator !== "exists" && (
            <Input
              type="number"
              value={String(c.value)}
              onChange={(e) => updateCondition(idx, { value: Number(e.target.value) })}
              className="h-7 text-xs w-16"
            />
          )}
          <Button variant="ghost" size="sm" onClick={() => removeCondition(idx)} className="h-7 w-7 p-0 text-red-400 hover:text-red-300">
            <Trash2 className="w-3 h-3" />
          </Button>
        </div>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// CAMPAIGN LIST VIEW
// ═══════════════════════════════════════════════════════════════════════════

function CampaignListView({ onSelect, onNew }: { onSelect: (id: number) => void; onNew: () => void }) {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");

  const { data, isLoading, refetch } = trpc.campaignOrchestrator.list.useQuery({
    status: statusFilter as any,
    limit: 50,
  }, { refetchInterval: 10000 });

  const deleteMut = trpc.campaignOrchestrator.delete.useMutation({
    onSuccess: () => { toast.success("Campaign deleted"); refetch(); },
    onError: (e) => toast.error(sanitizeErrorForToast(e)),
  });

  const campaigns = useMemo(() => {
    if (!data?.campaigns) return [];
    if (!searchQuery) return data.campaigns;
    const q = searchQuery.toLowerCase();
    return data.campaigns.filter((c: any) =>
      c.name.toLowerCase().includes(q) ||
      c.description?.toLowerCase().includes(q) ||
      c.customerName?.toLowerCase().includes(q)
    );
  }, [data?.campaigns, searchQuery]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <Workflow className="w-6 h-6 text-primary" />
            Campaign Orchestrator
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Chain multi-stage red team operations with conditional logic and automated execution
          </p>
        </div>
        <Button onClick={onNew} className="gap-2">
          <Plus className="w-4 h-4" /> New Campaign
        </Button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search campaigns..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 h-9"
          />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40 h-9">
            <Filter className="w-3.5 h-3.5 mr-1.5" />
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="draft">Draft</SelectItem>
            <SelectItem value="ready">Ready</SelectItem>
            <SelectItem value="running">Running</SelectItem>
            <SelectItem value="paused">Paused</SelectItem>
            <SelectItem value="completed">Completed</SelectItem>
            <SelectItem value="failed">Failed</SelectItem>
            <SelectItem value="aborted">Aborted</SelectItem>
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" onClick={() => refetch()} className="h-9 gap-1.5">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </Button>
      </div>

      {/* Campaign Cards */}
      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <Card key={i} className="animate-pulse bg-card/50">
              <CardContent className="p-6 space-y-3">
                <div className="h-5 bg-muted rounded w-3/4" />
                <div className="h-4 bg-muted rounded w-1/2" />
                <div className="h-3 bg-muted rounded w-full" />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : campaigns.length === 0 ? (
        <Card className="bg-card/30 border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-16 text-center">
            <Workflow className="w-12 h-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold text-foreground mb-2">No Campaigns Yet</h3>
            <p className="text-sm text-muted-foreground mb-6 max-w-md">
              Create your first multi-stage campaign to chain reconnaissance, exploitation, and post-exploitation phases with conditional logic.
            </p>
            <Button onClick={onNew} className="gap-2">
              <Plus className="w-4 h-4" /> Create Campaign
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {campaigns.map((campaign: any) => {
            const stageInfo = campaign.stages || { total: 0, completed: 0, failed: 0, running: 0 };
            const progress = stageInfo.total > 0 ? Math.round((stageInfo.completed / stageInfo.total) * 100) : 0;
            return (
              <Card
                key={campaign.id}
                className="bg-card/60 hover:bg-card/80 transition-colors cursor-pointer group border-border/50 hover:border-primary/30"
                onClick={() => onSelect(campaign.id)}
              >
                <CardContent className="p-5 space-y-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <h3 className="font-semibold text-foreground truncate group-hover:text-primary transition-colors">
                        {campaign.name}
                      </h3>
                      {campaign.customerName && (
                        <p className="text-xs text-muted-foreground mt-0.5">{campaign.customerName}</p>
                      )}
                    </div>
                    <StatusBadge status={campaign.status} />
                  </div>

                  {campaign.description && (
                    <p className="text-xs text-muted-foreground line-clamp-2">{campaign.description}</p>
                  )}

                  {/* Stage progress */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">
                        {stageInfo.completed}/{stageInfo.total} stages
                      </span>
                      <span className="font-mono text-muted-foreground">{progress}%</span>
                    </div>
                    <Progress value={progress} className="h-1.5" />
                  </div>

                  {/* Meta info */}
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <div className="flex items-center gap-3">
                      <span className="flex items-center gap-1">
                        <Shield className="w-3 h-3" />
                        {campaign.safetyLevel?.replace("_", " ") || "standard"}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {campaign.maxDurationHours || 72}h
                      </span>
                    </div>
                    {stageInfo.running > 0 && (
                      <span className="flex items-center gap-1 text-emerald-400">
                        <Activity className="w-3 h-3 animate-pulse" />
                        {stageInfo.running} active
                      </span>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 pt-1">
                    <Button
                      variant="outline"
                      size="sm"
                      className="flex-1 h-7 text-xs"
                      onClick={(e) => { e.stopPropagation(); onSelect(campaign.id); }}
                    >
                      <Eye className="w-3 h-3 mr-1" /> View
                    </Button>
                    {campaign.status === "draft" && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 w-7 p-0 text-red-400 hover:text-red-300"
                        onClick={(e) => {
                          e.stopPropagation();
                          if (confirm("Delete this campaign?")) {
                            deleteMut.mutate({ id: campaign.id });
                          }
                        }}
                      >
                        <Trash2 className="w-3 h-3" />
                      </Button>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Stats bar */}
      {data && data.total > 0 && (
        <div className="flex items-center justify-between text-xs text-muted-foreground border-t border-border/30 pt-4">
          <span>{data.total} campaign{data.total !== 1 ? "s" : ""} total</span>
          <span>Showing {campaigns.length} result{campaigns.length !== 1 ? "s" : ""}</span>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// CAMPAIGN DETAIL VIEW (Builder + Monitor)
// ═══════════════════════════════════════════════════════════════════════════

function CampaignDetailView({ campaignId, onBack }: { campaignId: number; onBack: () => void }) {
  const [activeTab, setActiveTab] = useState("stages");
  const [addStageOpen, setAddStageOpen] = useState(false);
  const [editStageId, setEditStageId] = useState<number | null>(null);
  const [aiPlanOpen, setAiPlanOpen] = useState(false);
  const [cloneOpen, setCloneOpen] = useState(false);
  const [cloneName, setCloneName] = useState("");
  const [cloneCustomer, setCloneCustomer] = useState("");
  const [reportOpen, setReportOpen] = useState(false);
  const [reportName, setReportName] = useState("");
  const [reportType, setReportType] = useState<string>("red_team");

  // Form state for new/edit stage
  const [stageName, setStageName] = useState("");
  const [stageDesc, setStageDesc] = useState("");
  const [stageType, setStageType] = useState<StageType>("recon");
  const [stageEngagementId, setStageEngagementId] = useState<number | null>(null);
  const [stageOnSuccess, setStageOnSuccess] = useState("next");
  const [stageOnSuccessTarget, setStageOnSuccessTarget] = useState<number | null>(null);
  const [stageOnFailure, setStageOnFailure] = useState("pause");
  const [stageOnFailureTarget, setStageOnFailureTarget] = useState<number | null>(null);
  const [stageMaxRetries, setStageMaxRetries] = useState(1);
  const [stageTimeout, setStageTimeout] = useState(60);
  const [stageEntryConditions, setStageEntryConditions] = useState<Condition[]>([]);
  const [stageExitConditions, setStageExitConditions] = useState<Condition[]>([]);

  // AI plan form
  const [aiTarget, setAiTarget] = useState("");
  const [aiObjective, setAiObjective] = useState("");
  const [aiEngType, setAiEngType] = useState("red_team");
  const [aiSafety, setAiSafety] = useState("standard");
  const [aiPlan, setAiPlan] = useState<any>(null);

  const utils = trpc.useUtils();

  const { data: campaign, isLoading, refetch } = trpc.campaignOrchestrator.getById.useQuery(
    { id: campaignId },
    { refetchInterval: campaign?.status === "running" ? 5000 : 15000 }
  );

  const { data: statusData } = trpc.campaignOrchestrator.getStatus.useQuery(
    { id: campaignId },
    { refetchInterval: campaign?.status === "running" ? 3000 : 15000 }
  );

  const { data: logsData, refetch: refetchLogs } = trpc.campaignOrchestrator.getLogs.useQuery(
    { campaignId, limit: 200 },
    { refetchInterval: campaign?.status === "running" ? 5000 : 30000 }
  );

  const { data: engagementsList } = trpc.campaignOrchestrator.listEngagements.useQuery({});

  // Mutations
  const addStageMut = trpc.campaignOrchestrator.addStage.useMutation({
    onSuccess: () => {
      toast.success("Stage added");
      setAddStageOpen(false);
      resetStageForm();
      refetch();
    },
    onError: (e) => toast.error(sanitizeErrorForToast(e)),
  });

  const updateStageMut = trpc.campaignOrchestrator.updateStage.useMutation({
    onSuccess: () => {
      toast.success("Stage updated");
      setEditStageId(null);
      resetStageForm();
      refetch();
    },
    onError: (e) => toast.error(sanitizeErrorForToast(e)),
  });

  const removeStageMut = trpc.campaignOrchestrator.removeStage.useMutation({
    onSuccess: () => { toast.success("Stage removed"); refetch(); },
    onError: (e) => toast.error(sanitizeErrorForToast(e)),
  });

  const executeMut = trpc.campaignOrchestrator.execute.useMutation({
    onSuccess: () => { toast.success("Campaign execution started"); refetch(); },
    onError: (e) => toast.error(sanitizeErrorForToast(e)),
  });

  const pauseMut = trpc.campaignOrchestrator.pause.useMutation({
    onSuccess: () => { toast.success("Campaign paused"); refetch(); },
    onError: (e) => toast.error(sanitizeErrorForToast(e)),
  });

  const resumeMut = trpc.campaignOrchestrator.resume.useMutation({
    onSuccess: () => { toast.success("Campaign resumed"); refetch(); },
    onError: (e) => toast.error(sanitizeErrorForToast(e)),
  });

  const abortMut = trpc.campaignOrchestrator.abort.useMutation({
    onSuccess: () => { toast.success("Campaign aborted"); refetch(); },
    onError: (e) => toast.error(sanitizeErrorForToast(e)),
  });

  const generatePlanMut = trpc.campaignOrchestrator.generatePlan.useMutation({
    onSuccess: (plan) => { setAiPlan(plan); toast.success("AI plan generated"); },
    onError: (e) => toast.error(sanitizeErrorForToast(e)),
  });

  const applyPlanMut = trpc.campaignOrchestrator.applyPlan.useMutation({
    onSuccess: () => {
      toast.success("AI plan applied to campaign");
      setAiPlanOpen(false);
      setAiPlan(null);
      refetch();
    },
    onError: (e) => toast.error(sanitizeErrorForToast(e)),
  });

  const updateCampaignMut = trpc.campaignOrchestrator.update.useMutation({
    onSuccess: () => { toast.success("Campaign updated"); refetch(); },
    onError: (e) => toast.error(sanitizeErrorForToast(e)),
  });

  const cloneMut = trpc.campaignOrchestrator.clone.useMutation({
    onSuccess: (data) => {
      toast.success(`Campaign cloned with ${data.stagesCloned} stages`);
      setCloneOpen(false);
      onBack();
    },
    onError: (e) => toast.error(sanitizeErrorForToast(e)),
  });

  const generateReportMut = trpc.campaignOrchestrator.generateReport.useMutation({
    onSuccess: (data) => {
      toast.success(`Report created with ${data.findingsCreated} findings`);
      setReportOpen(false);
    },
    onError: (e) => toast.error(sanitizeErrorForToast(e)),
  });

  function resetStageForm() {
    setStageName("");
    setStageDesc("");
    setStageType("recon");
    setStageEngagementId(null);
    setStageOnSuccess("next");
    setStageOnSuccessTarget(null);
    setStageOnFailure("pause");
    setStageOnFailureTarget(null);
    setStageMaxRetries(1);
    setStageTimeout(60);
    setStageEntryConditions([]);
    setStageExitConditions([]);
  }

  function openEditStage(stage: any) {
    setEditStageId(stage.id);
    setStageName(stage.name);
    setStageDesc(stage.description || "");
    setStageType(stage.stageType);
    setStageEngagementId(stage.engagementId);
    setStageOnSuccess(stage.onSuccess || "next");
    setStageOnSuccessTarget(stage.onSuccessTarget);
    setStageOnFailure(stage.onFailure || "pause");
    setStageOnFailureTarget(stage.onFailureTarget);
    setStageMaxRetries(stage.maxRetries || 1);
    setStageTimeout(stage.timeoutMinutes || 60);
    setStageEntryConditions(Array.isArray(stage.entryConditions) ? stage.entryConditions : []);
    setStageExitConditions(Array.isArray(stage.exitConditions) ? stage.exitConditions : []);
  }

  function handleSaveStage() {
    if (editStageId) {
      updateStageMut.mutate({
        stageId: editStageId,
        name: stageName,
        description: stageDesc || undefined,
        stageType: stageType as any,
        engagementId: stageEngagementId,
        entryConditions: stageEntryConditions,
        exitConditions: stageExitConditions,
        onSuccess: stageOnSuccess as any,
        onSuccessTarget: stageOnSuccessTarget,
        onFailure: stageOnFailure as any,
        onFailureTarget: stageOnFailureTarget,
        maxRetries: stageMaxRetries,
        timeoutMinutes: stageTimeout,
      });
    } else {
      addStageMut.mutate({
        campaignId,
        name: stageName,
        description: stageDesc || undefined,
        stageType: stageType as any,
        engagementId: stageEngagementId || undefined,
        entryConditions: stageEntryConditions,
        exitConditions: stageExitConditions,
        onSuccess: stageOnSuccess as any,
        onSuccessTarget: stageOnSuccessTarget || undefined,
        onFailure: stageOnFailure as any,
        onFailureTarget: stageOnFailureTarget || undefined,
        maxRetries: stageMaxRetries,
        timeoutMinutes: stageTimeout,
      });
    }
  }

  const isDraft = campaign?.status === "draft" || campaign?.status === "ready";
  const isRunning = campaign?.status === "running";
  const isPaused = campaign?.status === "paused";
  const isFinished = campaign?.status === "completed" || campaign?.status === "failed" || campaign?.status === "aborted";

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="h-8 bg-muted rounded w-1/3 animate-pulse" />
        <div className="h-64 bg-muted rounded animate-pulse" />
      </div>
    );
  }

  if (!campaign) {
    return (
      <div className="text-center py-16">
        <AlertCircle className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
        <p className="text-muted-foreground">Campaign not found</p>
        <Button variant="outline" onClick={onBack} className="mt-4">Back to List</Button>
      </div>
    );
  }

  const stages = campaign.stages || [];
  const logs = logsData?.logs || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={onBack} className="h-8 px-2">
            <ChevronRight className="w-4 h-4 rotate-180" />
          </Button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-bold tracking-tight text-foreground">{campaign.name}</h1>
              <StatusBadge status={campaign.status} />
            </div>
            <p className="text-sm text-muted-foreground mt-0.5">
              {campaign.customerName && <span>{campaign.customerName} &middot; </span>}
              {stages.length} stage{stages.length !== 1 ? "s" : ""} &middot;
              Safety: {campaign.safetyLevel?.replace("_", " ")} &middot;
              Max: {campaign.maxDurationHours}h
            </p>
          </div>
        </div>

        {/* Campaign Controls */}
        <div className="flex items-center gap-2">
          {isDraft && stages.length > 0 && (
            <Button
              onClick={() => executeMut.mutate({ campaignId })}
              disabled={executeMut.isPending}
              className="gap-2 bg-emerald-600 hover:bg-emerald-700"
            >
              <Play className="w-4 h-4" /> Execute
            </Button>
          )}
          {isRunning && (
            <>
              <Button
                variant="outline"
                onClick={() => pauseMut.mutate({ campaignId })}
                disabled={pauseMut.isPending}
                className="gap-2 text-yellow-400 border-yellow-500/30"
              >
                <Pause className="w-4 h-4" /> Pause
              </Button>
              <Button
                variant="outline"
                onClick={() => { if (confirm("Abort this campaign?")) abortMut.mutate({ campaignId }); }}
                disabled={abortMut.isPending}
                className="gap-2 text-red-400 border-red-500/30"
              >
                <Square className="w-4 h-4" /> Abort
              </Button>
            </>
          )}
          {isPaused && (
            <>
              <Button
                onClick={() => resumeMut.mutate({ campaignId })}
                disabled={resumeMut.isPending}
                className="gap-2 bg-emerald-600 hover:bg-emerald-700"
              >
                <Play className="w-4 h-4" /> Resume
              </Button>
              <Button
                variant="outline"
                onClick={() => { if (confirm("Abort this campaign?")) abortMut.mutate({ campaignId }); }}
                disabled={abortMut.isPending}
                className="gap-2 text-red-400 border-red-500/30"
              >
                <Square className="w-4 h-4" /> Abort
              </Button>
            </>
          )}
          {/* Clone Button */}
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setCloneName(`${campaign?.name || "Campaign"} (Copy)`);
              setCloneCustomer(campaign?.customerName || "");
              setCloneOpen(true);
            }}
            className="gap-1.5 text-blue-400 border-blue-500/30"
          >
            <Copy className="w-3.5 h-3.5" /> Clone
          </Button>
          {/* Generate Report — for finished campaigns */}
          {isFinished && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setReportName(`${campaign?.name || "Campaign"} \u2014 Assessment Report`);
                setReportOpen(true);
              }}
              className="gap-1.5 text-cyan-400 border-cyan-500/30"
            >
              <ClipboardList className="w-3.5 h-3.5" /> Generate Report
            </Button>
          )}
        </div>
      </div>

      {/* Clone Campaign Dialog */}
      <Dialog open={cloneOpen} onOpenChange={setCloneOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Copy className="w-5 h-5 text-blue-400" /> Clone Campaign
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label className="text-xs text-muted-foreground uppercase tracking-wider">New Campaign Name</Label>
              <Input value={cloneName} onChange={(e) => setCloneName(e.target.value)} className="mt-1" placeholder="Campaign name" />
            </div>
            <div>
              <Label className="text-xs text-muted-foreground uppercase tracking-wider">Customer (optional)</Label>
              <Input value={cloneCustomer} onChange={(e) => setCloneCustomer(e.target.value)} className="mt-1" placeholder="Customer name" />
            </div>
            <p className="text-xs text-muted-foreground">All stages and their conditions will be duplicated. The new campaign will be created as a draft.</p>
          </div>
          <DialogFooter>
            <DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
            <Button
              onClick={() => cloneMut.mutate({ campaignId, name: cloneName, customerName: cloneCustomer || undefined })}
              disabled={!cloneName || cloneMut.isPending}
              className="gap-2"
            >
              <Copy className="w-4 h-4" /> Clone
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Generate Report Dialog */}
      <Dialog open={reportOpen} onOpenChange={setReportOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ClipboardList className="w-5 h-5 text-cyan-400" /> Generate AC3 Report
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label className="text-xs text-muted-foreground uppercase tracking-wider">Report Name</Label>
              <Input value={reportName} onChange={(e) => setReportName(e.target.value)} className="mt-1" placeholder="Report name" />
            </div>
            <div>
              <Label className="text-xs text-muted-foreground uppercase tracking-wider">Assessment Type</Label>
              <Select value={reportType} onValueChange={setReportType}>
                <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="red_team">Red Team</SelectItem>
                  <SelectItem value="penetration_test">Penetration Test</SelectItem>
                  <SelectItem value="purple_team">Purple Team</SelectItem>
                  <SelectItem value="vulnerability_assessment">Vulnerability Assessment</SelectItem>
                  <SelectItem value="hybrid">Hybrid</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <p className="text-xs text-muted-foreground">This will create a new AC3 report with findings auto-generated from each completed campaign stage, including ATT&CK technique mappings and NIST control references.</p>
          </div>
          <DialogFooter>
            <DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
            <Button
              onClick={() => generateReportMut.mutate({
                campaignId,
                reportName: reportName || undefined,
                assessmentType: reportType as any,
              })}
              disabled={generateReportMut.isPending}
              className="gap-2 bg-cyan-600 hover:bg-cyan-700"
            >
              {generateReportMut.isPending ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ClipboardList className="w-4 h-4" />}
              Generate Report
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Progress bar for running campaigns */}
      {(isRunning || isPaused) && statusData && (
        <Card className="bg-card/60 border-primary/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-foreground flex items-center gap-2">
                <Activity className="w-4 h-4 text-primary animate-pulse" />
                Campaign Progress
              </span>
              <span className="text-sm font-mono text-muted-foreground">{statusData.progress}%</span>
            </div>
            <Progress value={statusData.progress} className="h-2" />
            <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
              {statusData.stagesSummary?.map((s: any) => (
                <span key={s.id} className="flex items-center gap-1">
                  <StatusBadge status={s.status} />
                  <span className="truncate max-w-[100px]">{s.name}</span>
                </span>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Results summary for completed campaigns */}
      {isFinished && campaign.resultsSummary && (
        <Card className="bg-card/60 border-green-500/20">
          <CardContent className="p-4">
            <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-green-400" /> Campaign Results
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-4">
              {[
                { label: "Duration", value: `${(campaign.resultsSummary as any).durationMinutes || 0}m` },
                { label: "Stages", value: `${(campaign.resultsSummary as any).completedStages || 0}/${(campaign.resultsSummary as any).totalStages || 0}` },
                { label: "Vulns", value: (campaign.resultsSummary as any).totalVulns || 0 },
                { label: "Critical", value: (campaign.resultsSummary as any).criticalVulns || 0 },
                { label: "Exploits", value: `${(campaign.resultsSummary as any).successfulExploits || 0}/${(campaign.resultsSummary as any).totalExploits || 0}` },
                { label: "C2 Agents", value: (campaign.resultsSummary as any).c2Agents || 0 },
              ].map((stat) => (
                <div key={stat.label} className="text-center">
                  <p className="text-lg font-bold font-mono text-foreground">{stat.value}</p>
                  <p className="text-xs text-muted-foreground">{stat.label}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-muted/50">
          <TabsTrigger value="stages" className="gap-1.5">
            <Layers className="w-3.5 h-3.5" /> Stages ({stages.length})
          </TabsTrigger>
          <TabsTrigger value="logs" className="gap-1.5">
            <FileText className="w-3.5 h-3.5" /> Logs ({logs.length})
          </TabsTrigger>
          <TabsTrigger value="settings" className="gap-1.5">
            <Settings2 className="w-3.5 h-3.5" /> Settings
          </TabsTrigger>
        </TabsList>

        {/* ═══ STAGES TAB ═══════════════════════════════════════════════ */}
        <TabsContent value="stages" className="space-y-4 mt-4">
          {isDraft && (
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => { resetStageForm(); setAddStageOpen(true); }}
                className="gap-1.5"
              >
                <Plus className="w-3.5 h-3.5" /> Add Stage
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setAiPlanOpen(true)}
                className="gap-1.5 text-purple-400 border-purple-500/30"
              >
                <Brain className="w-3.5 h-3.5" /> AI Generate Plan
              </Button>
            </div>
          )}

          {stages.length === 0 ? (
            <Card className="bg-card/30 border-dashed">
              <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                <Layers className="w-10 h-10 text-muted-foreground mb-3" />
                <p className="text-sm text-muted-foreground mb-4">
                  No stages defined. Add stages manually or use AI to generate a plan.
                </p>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => { resetStageForm(); setAddStageOpen(true); }} className="gap-1.5">
                    <Plus className="w-3.5 h-3.5" /> Add Stage
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setAiPlanOpen(true)} className="gap-1.5 text-purple-400 border-purple-500/30">
                    <Brain className="w-3.5 h-3.5" /> AI Plan
                  </Button>
                </div>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-1">
              {stages.map((stage: any, idx: number) => {
                const stageTypeConfig = STAGE_TYPES.find((t) => t.value === stage.stageType);
                const isCurrentStage = statusData?.currentStageId === stage.id;
                const entryConditions = Array.isArray(stage.entryConditions) ? stage.entryConditions : [];
                const exitConditions = Array.isArray(stage.exitConditions) ? stage.exitConditions : [];

                return (
                  <div key={stage.id}>
                    {/* Connector line */}
                    {idx > 0 && (
                      <div className="flex items-center justify-center py-1">
                        <div className="flex flex-col items-center">
                          <ArrowDown className="w-4 h-4 text-muted-foreground" />
                          {stages[idx - 1]?.onSuccess !== "next" && (
                            <span className="text-[10px] font-mono text-muted-foreground">
                              {stages[idx - 1]?.onSuccess === "skip_to" ? `skip→${stages[idx - 1]?.onSuccessTarget}` : stages[idx - 1]?.onSuccess}
                            </span>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Stage card */}
                    <Card className={`bg-card/60 border-border/50 transition-all ${
                      isCurrentStage ? "border-primary/50 ring-1 ring-primary/20" :
                      stage.status === "completed" ? "border-green-500/20" :
                      stage.status === "failed" || stage.status === "timed_out" ? "border-red-500/20" :
                      stage.status === "running" ? "border-emerald-500/30 ring-1 ring-emerald-500/10" :
                      ""
                    }`}>
                      <CardContent className="p-4">
                        <div className="flex items-start gap-3">
                          {/* Stage number */}
                          <div className={`flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold ${
                            stage.status === "completed" ? "bg-green-500/20 text-green-400" :
                            stage.status === "running" ? "bg-emerald-500/20 text-emerald-400" :
                            stage.status === "failed" || stage.status === "timed_out" ? "bg-red-500/20 text-red-400" :
                            "bg-muted text-muted-foreground"
                          }`}>
                            {stage.stageOrder}
                          </div>

                          {/* Stage info */}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="font-semibold text-sm text-foreground">{stage.name}</span>
                              <StageTypeBadge type={stage.stageType} />
                              <StatusBadge status={stage.status} />
                            </div>

                            {stage.description && (
                              <p className="text-xs text-muted-foreground mb-2">{stage.description}</p>
                            )}

                            {/* Conditions summary */}
                            <div className="flex flex-wrap gap-2 text-[10px] font-mono">
                              {entryConditions.length > 0 && (
                                <span className="px-1.5 py-0.5 bg-blue-500/10 text-blue-400 rounded">
                                  ENTRY: {entryConditions.map((c: Condition) => `${c.field} ${c.operator} ${c.value}`).join(" AND ")}
                                </span>
                              )}
                              {exitConditions.length > 0 && (
                                <span className="px-1.5 py-0.5 bg-purple-500/10 text-purple-400 rounded">
                                  EXIT: {exitConditions.map((c: Condition) => `${c.field} ${c.operator} ${c.value}`).join(" AND ")}
                                </span>
                              )}
                              <span className="px-1.5 py-0.5 bg-muted text-muted-foreground rounded">
                                OK→{stage.onSuccess} FAIL→{stage.onFailure}
                              </span>
                              <span className="px-1.5 py-0.5 bg-muted text-muted-foreground rounded">
                                {stage.timeoutMinutes}min timeout
                              </span>
                              {stage.engagementId && (
                                <span className="px-1.5 py-0.5 bg-cyan-500/10 text-cyan-400 rounded">
                                  ENG#{stage.engagementId}
                                </span>
                              )}
                            </div>

                            {/* Stage results (if completed) */}
                            {stage.results && typeof stage.results === "object" && (
                              <div className="flex flex-wrap gap-3 mt-2 text-xs">
                                {Object.entries(stage.results as Record<string, any>)
                                  .filter(([, v]) => v !== undefined && v !== null && v !== 0)
                                  .map(([k, v]) => (
                                    <span key={k} className="text-muted-foreground">
                                      <span className="text-foreground font-mono">{String(v)}</span> {k.replace(/([A-Z])/g, " $1").toLowerCase()}
                                    </span>
                                  ))}
                              </div>
                            )}

                            {/* Error message */}
                            {stage.errorMessage && (
                              <p className="text-xs text-red-400 mt-1 font-mono">{stage.errorMessage}</p>
                            )}
                          </div>

                          {/* Stage actions */}
                          {isDraft && (
                            <div className="flex items-center gap-1">
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-7 w-7 p-0"
                                onClick={() => openEditStage(stage)}
                              >
                                <Edit className="w-3 h-3" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-7 w-7 p-0 text-red-400 hover:text-red-300"
                                onClick={() => {
                                  if (confirm(`Remove stage "${stage.name}"?`)) {
                                    removeStageMut.mutate({ stageId: stage.id });
                                  }
                                }}
                              >
                                <Trash2 className="w-3 h-3" />
                              </Button>
                            </div>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                );
              })}
            </div>
          )}
        </TabsContent>

        {/* ═══ LOGS TAB ═══════════════════════════════════════════════════ */}
        <TabsContent value="logs" className="mt-4">
          <Card className="bg-card/60">
            <CardContent className="p-0">
              <ScrollArea className="h-[500px]">
                {logs.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-center">
                    <FileText className="w-10 h-10 text-muted-foreground mb-3" />
                    <p className="text-sm text-muted-foreground">No logs yet. Execute the campaign to see activity logs.</p>
                  </div>
                ) : (
                  <div className="divide-y divide-border/30">
                    {logs.map((log: any) => {
                      const logColor =
                        log.logType?.includes("error") || log.logType?.includes("fail") || log.logType?.includes("abort") ? "text-red-400" :
                        log.logType?.includes("complete") || log.logType?.includes("start") ? "text-emerald-400" :
                        log.logType?.includes("warning") || log.logType?.includes("pause") ? "text-yellow-400" :
                        log.logType?.includes("condition") || log.logType?.includes("branch") ? "text-purple-400" :
                        log.logType?.includes("ai") ? "text-cyan-400" :
                        "text-muted-foreground";

                      return (
                        <div key={log.id} className="px-4 py-2.5 hover:bg-muted/30 transition-colors">
                          <div className="flex items-start gap-3">
                            <span className={`text-xs font-mono mt-0.5 ${logColor}`}>
                              {log.logType?.replace(/_/g, " ").toUpperCase()}
                            </span>
                            <div className="flex-1 min-w-0">
                              <p className="text-sm text-foreground">{log.title}</p>
                              {log.detail && (
                                <p className="text-xs text-muted-foreground mt-0.5 font-mono break-all">{log.detail}</p>
                              )}
                            </div>
                            <span className="text-[10px] text-muted-foreground font-mono whitespace-nowrap">
                              {log.createdAt ? new Date(log.createdAt).toLocaleTimeString() : ""}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ═══ SETTINGS TAB ═══════════════════════════════════════════════ */}
        <TabsContent value="settings" className="mt-4">
          <Card className="bg-card/60">
            <CardContent className="p-6 space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div>
                    <Label className="text-xs text-muted-foreground uppercase tracking-wider">Campaign Name</Label>
                    <Input
                      defaultValue={campaign.name}
                      onBlur={(e) => {
                        if (e.target.value !== campaign.name) {
                          updateCampaignMut.mutate({ id: campaignId, name: e.target.value });
                        }
                      }}
                      disabled={!isDraft}
                      className="mt-1"
                    />
                  </div>
                  <div>
                    <Label className="text-xs text-muted-foreground uppercase tracking-wider">Customer Name</Label>
                    <Input
                      defaultValue={campaign.customerName || ""}
                      onBlur={(e) => {
                        if (e.target.value !== (campaign.customerName || "")) {
                          updateCampaignMut.mutate({ id: campaignId, customerName: e.target.value });
                        }
                      }}
                      disabled={!isDraft}
                      className="mt-1"
                    />
                  </div>
                  <div>
                    <Label className="text-xs text-muted-foreground uppercase tracking-wider">Objective</Label>
                    <Textarea
                      defaultValue={campaign.objective || ""}
                      onBlur={(e) => {
                        if (e.target.value !== (campaign.objective || "")) {
                          updateCampaignMut.mutate({ id: campaignId, objective: e.target.value });
                        }
                      }}
                      disabled={!isDraft}
                      className="mt-1"
                      rows={3}
                    />
                  </div>
                  <div>
                    <Label className="text-xs text-muted-foreground uppercase tracking-wider">Description</Label>
                    <Textarea
                      defaultValue={campaign.description || ""}
                      onBlur={(e) => {
                        if (e.target.value !== (campaign.description || "")) {
                          updateCampaignMut.mutate({ id: campaignId, description: e.target.value });
                        }
                      }}
                      disabled={!isDraft}
                      className="mt-1"
                      rows={3}
                    />
                  </div>
                </div>
                <div className="space-y-4">
                  <div>
                    <Label className="text-xs text-muted-foreground uppercase tracking-wider">Safety Level</Label>
                    <Select
                      defaultValue={campaign.safetyLevel || "standard"}
                      onValueChange={(v) => updateCampaignMut.mutate({ id: campaignId, safetyLevel: v as any })}
                      disabled={!isDraft}
                    >
                      <SelectTrigger className="mt-1">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="passive_only">Passive Only</SelectItem>
                        <SelectItem value="low_impact">Low Impact</SelectItem>
                        <SelectItem value="standard">Standard</SelectItem>
                        <SelectItem value="full_exploitation">Full Exploitation</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label className="text-xs text-muted-foreground uppercase tracking-wider">Max Duration (hours)</Label>
                    <Input
                      type="number"
                      defaultValue={campaign.maxDurationHours || 72}
                      onBlur={(e) => {
                        const val = Number(e.target.value);
                        if (val > 0 && val !== campaign.maxDurationHours) {
                          updateCampaignMut.mutate({ id: campaignId, maxDurationHours: val });
                        }
                      }}
                      disabled={!isDraft}
                      className="mt-1"
                    />
                  </div>
                  <div className="space-y-3 pt-2">
                    <div className="flex items-center justify-between">
                      <Label className="text-sm">Auto-advance stages</Label>
                      <Switch
                        checked={!!campaign.autoAdvance}
                        onCheckedChange={(v) => updateCampaignMut.mutate({ id: campaignId, autoAdvance: v })}
                        disabled={!isDraft}
                      />
                    </div>
                    <div className="flex items-center justify-between">
                      <Label className="text-sm">Notify on stage complete</Label>
                      <Switch
                        checked={!!campaign.notifyOnStageComplete}
                        onCheckedChange={(v) => updateCampaignMut.mutate({ id: campaignId, notifyOnStageComplete: v })}
                        disabled={!isDraft}
                      />
                    </div>
                    <div className="flex items-center justify-between">
                      <Label className="text-sm">Notify on campaign complete</Label>
                      <Switch
                        checked={!!campaign.notifyOnCampaignComplete}
                        onCheckedChange={(v) => updateCampaignMut.mutate({ id: campaignId, notifyOnCampaignComplete: v })}
                        disabled={!isDraft}
                      />
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* ═══ ADD/EDIT STAGE DIALOG ═══════════════════════════════════════ */}
      <Dialog open={addStageOpen || editStageId !== null} onOpenChange={(open) => {
        if (!open) { setAddStageOpen(false); setEditStageId(null); resetStageForm(); }
      }}>
        <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Layers className="w-5 h-5 text-primary" />
              {editStageId ? "Edit Stage" : "Add Stage"}
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-5">
            {/* Basic info */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label className="text-xs text-muted-foreground uppercase tracking-wider">Stage Name</Label>
                <Input
                  value={stageName}
                  onChange={(e) => setStageName(e.target.value)}
                  placeholder="e.g., External Recon"
                  className="mt-1"
                />
              </div>
              <div>
                <Label className="text-xs text-muted-foreground uppercase tracking-wider">Stage Type</Label>
                <Select value={stageType} onValueChange={(v) => setStageType(v as StageType)}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {STAGE_TYPES.map((t) => (
                      <SelectItem key={t.value} value={t.value}>
                        <span className="flex items-center gap-2">
                          <span className={t.color}>{t.icon}</span>
                          {t.label}
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div>
              <Label className="text-xs text-muted-foreground uppercase tracking-wider">Description</Label>
              <Textarea
                value={stageDesc}
                onChange={(e) => setStageDesc(e.target.value)}
                placeholder="What this stage does..."
                className="mt-1"
                rows={2}
              />
            </div>

            {/* Engagement link */}
            <div>
              <Label className="text-xs text-muted-foreground uppercase tracking-wider">Link to Engagement (optional)</Label>
              <Select
                value={stageEngagementId ? String(stageEngagementId) : "none"}
                onValueChange={(v) => setStageEngagementId(v === "none" ? null : Number(v))}
              >
                <SelectTrigger className="mt-1">
                  <SelectValue placeholder="Select engagement..." />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">No engagement linked</SelectItem>
                  {engagementsList?.map((eng: any) => (
                    <SelectItem key={eng.id} value={String(eng.id)}>
                      #{eng.id} — {eng.name} ({eng.engagementType})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <Separator />

            {/* Conditions */}
            <ConditionEditor
              conditions={stageEntryConditions}
              onChange={setStageEntryConditions}
              label="Entry Conditions (all must pass to start)"
            />

            <ConditionEditor
              conditions={stageExitConditions}
              onChange={setStageExitConditions}
              label="Exit Conditions (all must pass for success)"
            />

            <Separator />

            {/* Branching logic */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label className="text-xs text-muted-foreground uppercase tracking-wider">On Success</Label>
                <Select value={stageOnSuccess} onValueChange={setStageOnSuccess}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="next">Next Stage</SelectItem>
                    <SelectItem value="skip_to">Skip to Stage #</SelectItem>
                    <SelectItem value="complete">Complete Campaign</SelectItem>
                    <SelectItem value="pause">Pause Campaign</SelectItem>
                  </SelectContent>
                </Select>
                {stageOnSuccess === "skip_to" && (
                  <Input
                    type="number"
                    value={stageOnSuccessTarget || ""}
                    onChange={(e) => setStageOnSuccessTarget(Number(e.target.value) || null)}
                    placeholder="Target stage order #"
                    className="mt-1"
                  />
                )}
              </div>
              <div>
                <Label className="text-xs text-muted-foreground uppercase tracking-wider">On Failure</Label>
                <Select value={stageOnFailure} onValueChange={setStageOnFailure}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="abort">Abort Campaign</SelectItem>
                    <SelectItem value="skip">Skip Stage</SelectItem>
                    <SelectItem value="retry">Retry Stage</SelectItem>
                    <SelectItem value="pause">Pause Campaign</SelectItem>
                    <SelectItem value="fallback">Fallback to Stage #</SelectItem>
                  </SelectContent>
                </Select>
                {stageOnFailure === "fallback" && (
                  <Input
                    type="number"
                    value={stageOnFailureTarget || ""}
                    onChange={(e) => setStageOnFailureTarget(Number(e.target.value) || null)}
                    placeholder="Fallback stage order #"
                    className="mt-1"
                  />
                )}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label className="text-xs text-muted-foreground uppercase tracking-wider">Max Retries</Label>
                <Input
                  type="number"
                  value={stageMaxRetries}
                  onChange={(e) => setStageMaxRetries(Number(e.target.value))}
                  min={0}
                  max={5}
                  className="mt-1"
                />
              </div>
              <div>
                <Label className="text-xs text-muted-foreground uppercase tracking-wider">Timeout (minutes)</Label>
                <Input
                  type="number"
                  value={stageTimeout}
                  onChange={(e) => setStageTimeout(Number(e.target.value))}
                  min={1}
                  max={1440}
                  className="mt-1"
                />
              </div>
            </div>
          </div>

          <DialogFooter className="mt-4">
            <DialogClose asChild>
              <Button variant="outline">Cancel</Button>
            </DialogClose>
            <Button
              onClick={handleSaveStage}
              disabled={!stageName || addStageMut.isPending || updateStageMut.isPending}
              className="gap-2"
            >
              {editStageId ? "Update Stage" : "Add Stage"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ═══ AI PLAN DIALOG ═══════════════════════════════════════════════ */}
      <Dialog open={aiPlanOpen} onOpenChange={(open) => { if (!open) { setAiPlanOpen(false); setAiPlan(null); } }}>
        <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Brain className="w-5 h-5 text-purple-400" />
              AI Campaign Plan Generator
            </DialogTitle>
          </DialogHeader>

          {!aiPlan ? (
            <div className="space-y-4">
              <div>
                <Label className="text-xs text-muted-foreground uppercase tracking-wider">Target Description</Label>
                <Textarea
                  value={aiTarget}
                  onChange={(e) => setAiTarget(e.target.value)}
                  placeholder="e.g., Mid-size financial services company with public web apps, VPN, and Active Directory environment"
                  className="mt-1"
                  rows={3}
                />
              </div>
              <div>
                <Label className="text-xs text-muted-foreground uppercase tracking-wider">Campaign Objective</Label>
                <Textarea
                  value={aiObjective}
                  onChange={(e) => setAiObjective(e.target.value)}
                  placeholder="e.g., Achieve domain admin access and demonstrate data exfiltration capability"
                  className="mt-1"
                  rows={2}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-xs text-muted-foreground uppercase tracking-wider">Engagement Type</Label>
                  <Select value={aiEngType} onValueChange={setAiEngType}>
                    <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="red_team">Red Team</SelectItem>
                      <SelectItem value="pentest">Penetration Test</SelectItem>
                      <SelectItem value="purple_team">Purple Team</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground uppercase tracking-wider">Safety Level</Label>
                  <Select value={aiSafety} onValueChange={setAiSafety}>
                    <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="passive_only">Passive Only</SelectItem>
                      <SelectItem value="low_impact">Low Impact</SelectItem>
                      <SelectItem value="standard">Standard</SelectItem>
                      <SelectItem value="full_exploitation">Full Exploitation</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <DialogFooter>
                <DialogClose asChild>
                  <Button variant="outline">Cancel</Button>
                </DialogClose>
                <Button
                  onClick={() => generatePlanMut.mutate({
                    targetDescription: aiTarget,
                    objective: aiObjective,
                    engagementType: aiEngType as any,
                    safetyLevel: aiSafety as any,
                  })}
                  disabled={!aiTarget || !aiObjective || generatePlanMut.isPending}
                  className="gap-2 bg-purple-600 hover:bg-purple-700"
                >
                  {generatePlanMut.isPending ? (
                    <><RefreshCw className="w-4 h-4 animate-spin" /> Generating...</>
                  ) : (
                    <><Sparkles className="w-4 h-4" /> Generate Plan</>
                  )}
                </Button>
              </DialogFooter>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="bg-muted/30 rounded-lg p-4 space-y-3">
                <h3 className="font-semibold text-foreground">{aiPlan.name}</h3>
                <p className="text-sm text-muted-foreground">{aiPlan.objective}</p>
                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" /> Est. {aiPlan.estimatedDurationHours}h
                  </span>
                  <span className="flex items-center gap-1">
                    <Layers className="w-3 h-3" /> {aiPlan.stages?.length || 0} stages
                  </span>
                </div>
                {aiPlan.riskAssessment && (
                  <div className="text-xs text-yellow-400 bg-yellow-500/10 rounded p-2">
                    <AlertTriangle className="w-3 h-3 inline mr-1" />
                    {aiPlan.riskAssessment}
                  </div>
                )}
              </div>

              {/* Stage preview */}
              <div className="space-y-2">
                <Label className="text-xs text-muted-foreground uppercase tracking-wider">Planned Stages</Label>
                {aiPlan.stages?.map((s: any, i: number) => (
                  <div key={i} className="flex items-center gap-3 bg-card/60 rounded-lg p-3 border border-border/30">
                    <span className="w-6 h-6 rounded bg-muted flex items-center justify-center text-xs font-bold text-muted-foreground">
                      {i + 1}
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-foreground">{s.name}</p>
                      <p className="text-xs text-muted-foreground">{s.description}</p>
                    </div>
                    <StageTypeBadge type={s.stageType} />
                  </div>
                ))}
              </div>

              <DialogFooter>
                <Button variant="outline" onClick={() => setAiPlan(null)}>
                  Regenerate
                </Button>
                <Button
                  onClick={() => applyPlanMut.mutate({ campaignId, plan: aiPlan })}
                  disabled={applyPlanMut.isPending}
                  className="gap-2 bg-purple-600 hover:bg-purple-700"
                >
                  {applyPlanMut.isPending ? (
                    <><RefreshCw className="w-4 h-4 animate-spin" /> Applying...</>
                  ) : (
                    <><CheckCircle2 className="w-4 h-4" /> Apply Plan</>
                  )}
                </Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// CREATE CAMPAIGN DIALOG
// ═══════════════════════════════════════════════════════════════════════════

function CreateCampaignDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (id: number) => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [customerName, setCustomerName] = useState("");
  const [objective, setObjective] = useState("");
  const [safetyLevel, setSafetyLevel] = useState("standard");
  const [maxDuration, setMaxDuration] = useState(72);

  const createMut = trpc.campaignOrchestrator.create.useMutation({
    onSuccess: (data) => {
      toast.success("Campaign created");
      onCreated(data.id);
      onClose();
      // Reset form
      setName("");
      setDescription("");
      setCustomerName("");
      setObjective("");
      setSafetyLevel("standard");
      setMaxDuration(72);
    },
    onError: (e) => toast.error(sanitizeErrorForToast(e)),
  });

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Workflow className="w-5 h-5 text-primary" />
            New Campaign
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div>
            <Label className="text-xs text-muted-foreground uppercase tracking-wider">Campaign Name *</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Q1 Red Team — Acme Corp"
              className="mt-1"
            />
          </div>
          <div>
            <Label className="text-xs text-muted-foreground uppercase tracking-wider">Customer Name</Label>
            <Input
              value={customerName}
              onChange={(e) => setCustomerName(e.target.value)}
              placeholder="e.g., Acme Corporation"
              className="mt-1"
            />
          </div>
          <div>
            <Label className="text-xs text-muted-foreground uppercase tracking-wider">Objective</Label>
            <Textarea
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              placeholder="Campaign objective..."
              className="mt-1"
              rows={2}
            />
          </div>
          <div>
            <Label className="text-xs text-muted-foreground uppercase tracking-wider">Description</Label>
            <Textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Campaign description..."
              className="mt-1"
              rows={2}
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-xs text-muted-foreground uppercase tracking-wider">Safety Level</Label>
              <Select value={safetyLevel} onValueChange={setSafetyLevel}>
                <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="passive_only">Passive Only</SelectItem>
                  <SelectItem value="low_impact">Low Impact</SelectItem>
                  <SelectItem value="standard">Standard</SelectItem>
                  <SelectItem value="full_exploitation">Full Exploitation</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs text-muted-foreground uppercase tracking-wider">Max Duration (hours)</Label>
              <Input
                type="number"
                value={maxDuration}
                onChange={(e) => setMaxDuration(Number(e.target.value))}
                min={1}
                max={720}
                className="mt-1"
              />
            </div>
          </div>
        </div>

        <DialogFooter className="mt-4">
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button
            onClick={() => createMut.mutate({
              name,
              description: description || undefined,
              customerName: customerName || undefined,
              objective: objective || undefined,
              safetyLevel: safetyLevel as any,
              maxDurationHours: maxDuration,
            })}
            disabled={!name || createMut.isPending}
            className="gap-2"
          >
            <Plus className="w-4 h-4" /> Create Campaign
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN PAGE COMPONENT
// ═══════════════════════════════════════════════════════════════════════════

export default function CampaignOrchestrator() {
  const [, navigate] = useLocation();
  const [, params] = useRoute("/campaign-orchestrator/:id");
  const [selectedCampaignId, setSelectedCampaignId] = useState<number | null>(
    params?.id ? Number(params.id) : null
  );
  const [createOpen, setCreateOpen] = useState(false);

  // Sync URL param
  useEffect(() => {
    if (params?.id) {
      setSelectedCampaignId(Number(params.id));
    }
  }, [params?.id]);

  const handleSelect = useCallback((id: number) => {
    setSelectedCampaignId(id);
    navigate(`/campaign-orchestrator/${id}`);
  }, [navigate]);

  const handleBack = useCallback(() => {
    setSelectedCampaignId(null);
    navigate("/campaign-orchestrator");
  }, [navigate]);

  const handleCreated = useCallback((id: number) => {
    handleSelect(id);
  }, [handleSelect]);

  return (
    <AppShell activePath="/campaign-orchestrator">
      {selectedCampaignId ? (
        <CampaignDetailView campaignId={selectedCampaignId} onBack={handleBack} />
      ) : (
        <CampaignListView onSelect={handleSelect} onNew={() => setCreateOpen(true)} />
      )}
      <CreateCampaignDialog open={createOpen} onClose={() => setCreateOpen(false)} onCreated={handleCreated} />
    </AppShell>
  );
}
