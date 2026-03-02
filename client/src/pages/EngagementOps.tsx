/**
 * EngagementOps — Unified Engagement Operations Console
 *
 * Single-page operator console for running entire engagements:
 * - One-click autonomous execution with LLM orchestration
 * - Live event feed with real-time WebSocket updates
 * - Inline approval gates for high-risk actions
 * - RoE scope enforcement display
 * - Asset status tracking with per-asset drill-down
 * - Phase progress visualization
 * - Pentest vs Red Team branching
 */
import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { useRoute } from "wouter";
import { trpc } from "@/lib/trpc";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useAuth } from "@/_core/hooks/useAuth";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { toast } from "sonner";
import {
  Play, Square, Shield, ShieldAlert, ShieldCheck, ShieldX,
  Target, Crosshair, Radar, Bug, Skull, Radio, Globe,
  Server, Database, MonitorSmartphone, AlertTriangle, CheckCircle2,
  XCircle, Clock, Loader2, ChevronRight, Eye, FileText,
  Zap, Lock, Unlock, Activity, Terminal, Network, Wifi,
} from "lucide-react";

// ─── Types (mirror server) ──────────────────────────────────────────────────

type OpsPhase = "idle" | "recon" | "enumeration" | "vuln_detection" | "exploitation" | "post_exploit" | "reporting" | "completed" | "paused" | "error";
type ApprovalStatus = "pending" | "approved" | "denied";

interface ApprovalGate {
  id: string;
  phase: OpsPhase;
  riskTier: "yellow" | "orange" | "red";
  title: string;
  description: string;
  target: string;
  module?: string;
  detail: Record<string, any>;
  status: ApprovalStatus;
  createdAt: number;
  resolvedAt?: number;
  resolvedBy?: string;
}

interface OpsLogEntry {
  id: string;
  timestamp: number;
  phase: OpsPhase;
  type: string;
  title: string;
  detail: string;
  data?: Record<string, any>;
  riskTier?: "yellow" | "orange" | "red";
}

interface AssetStatus {
  hostname: string;
  ip?: string;
  type: string;
  ports: Array<{ port: number; service: string; version?: string }>;
  vulns: Array<{ id: string; severity: string; title: string; cve?: string }>;
  zapFindings: Array<{ alert: string; risk: string; url: string; cweId?: number }>;
  exploitAttempts: Array<{ module: string; success: boolean; sessionId?: string }>;
  status: string;
  wafDetected?: string;
}

interface OpsState {
  engagementId: number;
  engagementType: string;
  phase: OpsPhase;
  progress: number;
  isRunning: boolean;
  isPaused: boolean;
  startedAt?: number;
  completedAt?: number;
  assets: AssetStatus[];
  log: OpsLogEntry[];
  approvalGates: ApprovalGate[];
  llmPlan?: string;
  currentAction?: string;
  error?: string;
  stats: {
    hostsScanned: number;
    portsFound: number;
    vulnsFound: number;
    exploitsAttempted: number;
    exploitsSucceeded: number;
    sessionsOpened: number;
    zapScansRun: number;
    wafDetections: number;
  };
}

// ─── Phase Config ───────────────────────────────────────────────────────────

const PHASES: Array<{ id: OpsPhase; label: string; icon: React.ReactNode; color: string }> = [
  { id: "recon", label: "Recon", icon: <Radar className="h-4 w-4" />, color: "text-blue-400" },
  { id: "enumeration", label: "Enumerate", icon: <Target className="h-4 w-4" />, color: "text-cyan-400" },
  { id: "vuln_detection", label: "Vuln Detect", icon: <Bug className="h-4 w-4" />, color: "text-yellow-400" },
  { id: "exploitation", label: "Exploit", icon: <Skull className="h-4 w-4" />, color: "text-red-400" },
  { id: "post_exploit", label: "Post-Exploit", icon: <Radio className="h-4 w-4" />, color: "text-purple-400" },
  { id: "completed", label: "Complete", icon: <CheckCircle2 className="h-4 w-4" />, color: "text-green-400" },
];

function getPhaseIndex(phase: OpsPhase): number {
  const idx = PHASES.findIndex(p => p.id === phase);
  return idx >= 0 ? idx : -1;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatDuration(ms: number): string {
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function riskBadge(tier?: string) {
  if (!tier) return null;
  const colors: Record<string, string> = {
    yellow: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    orange: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    red: "bg-red-500/20 text-red-400 border-red-500/30",
  };
  return <Badge variant="outline" className={`text-[10px] ${colors[tier] || ""}`}>{tier.toUpperCase()}</Badge>;
}

function logIcon(type: string) {
  switch (type) {
    case "scan_start": return <Radar className="h-3.5 w-3.5 text-blue-400" />;
    case "scan_result": return <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />;
    case "finding": return <Bug className="h-3.5 w-3.5 text-yellow-400" />;
    case "exploit_attempt": return <Crosshair className="h-3.5 w-3.5 text-red-400" />;
    case "exploit_success": return <Skull className="h-3.5 w-3.5 text-red-500" />;
    case "exploit_fail": return <XCircle className="h-3.5 w-3.5 text-gray-400" />;
    case "approval_request": return <Lock className="h-3.5 w-3.5 text-orange-400" />;
    case "approval_response": return <Unlock className="h-3.5 w-3.5 text-green-400" />;
    case "c2_deploy": return <Radio className="h-3.5 w-3.5 text-purple-400" />;
    case "llm_decision": return <Zap className="h-3.5 w-3.5 text-cyan-400" />;
    case "zap_scan": return <Globe className="h-3.5 w-3.5 text-blue-400" />;
    case "waf_detected": return <ShieldAlert className="h-3.5 w-3.5 text-orange-400" />;
    case "phase_complete": return <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />;
    case "error": return <AlertTriangle className="h-3.5 w-3.5 text-red-400" />;
    case "evidence": return <FileText className="h-3.5 w-3.5 text-blue-300" />;
    default: return <Activity className="h-3.5 w-3.5 text-gray-400" />;
  }
}

function assetIcon(type: string) {
  switch (type) {
    case "web_app": return <Globe className="h-4 w-4 text-blue-400" />;
    case "server": return <Server className="h-4 w-4 text-cyan-400" />;
    case "database": return <Database className="h-4 w-4 text-yellow-400" />;
    case "api": return <Terminal className="h-4 w-4 text-green-400" />;
    case "network_device": return <Network className="h-4 w-4 text-purple-400" />;
    default: return <MonitorSmartphone className="h-4 w-4 text-gray-400" />;
  }
}

function assetStatusBadge(status: string) {
  const map: Record<string, { label: string; className: string }> = {
    pending: { label: "Pending", className: "bg-gray-500/20 text-gray-400" },
    scanning: { label: "Scanning", className: "bg-blue-500/20 text-blue-400" },
    enumerated: { label: "Enumerated", className: "bg-cyan-500/20 text-cyan-400" },
    vulns_found: { label: "Vulns Found", className: "bg-yellow-500/20 text-yellow-400" },
    exploiting: { label: "Exploiting", className: "bg-orange-500/20 text-orange-400" },
    compromised: { label: "Compromised", className: "bg-red-500/20 text-red-400" },
    no_vulns: { label: "Clean", className: "bg-green-500/20 text-green-400" },
  };
  const cfg = map[status] || { label: status, className: "bg-gray-500/20 text-gray-400" };
  return <Badge variant="outline" className={`text-[10px] ${cfg.className}`}>{cfg.label}</Badge>;
}

// ─── Component ──────────────────────────────────────────────────────────────

export default function EngagementOps() {
  const [, params] = useRoute("/engagement-ops/:id");
  const engagementId = params?.id ? Number(params.id) : 0;
  const { user } = useAuth();
  const feedEndRef = useRef<HTMLDivElement>(null);
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null);
  const [confirmStop, setConfirmStop] = useState(false);
  const [activeTab, setActiveTab] = useState("feed");

  // ── Data fetching ──
  const engagementQ = trpc.engagements.get.useQuery(
    { id: engagementId },
    { enabled: engagementId > 0 }
  );
  const opsStateQ = trpc.engagementOps.getState.useQuery(
    { engagementId },
    { enabled: engagementId > 0, refetchInterval: 2000 }
  );

  const executeMut = trpc.engagementOps.execute.useMutation({
    onSuccess: () => {
      toast.success("Execution Started — LLM orchestrator is running the engagement autonomously.");
      opsStateQ.refetch();
    },
    onError: (e) => toast.error(e.message),
  });

  const stopMut = trpc.engagementOps.stop.useMutation({
    onSuccess: () => {
      toast.success("Execution Stopped");
      opsStateQ.refetch();
      setConfirmStop(false);
    },
  });

  const approveMut = trpc.engagementOps.resolveApproval.useMutation({
    onSuccess: () => opsStateQ.refetch(),
    onError: (e) => toast.error(e.message),
  });

  // ── WebSocket live feed ──
  const wsChannels = useMemo(
    () => engagementId ? ["global", `engagement:${engagementId}`] : ["global"],
    [engagementId]
  );
  const { events: wsEvents, isConnected: wsConnected } = useWebSocket({
    channels: wsChannels,
    maxEvents: 200,
  });

  const ops: OpsState | null = opsStateQ.data || null;
  const engagement = engagementQ.data;

  // Auto-scroll feed
  useEffect(() => {
    if (feedEndRef.current && activeTab === "feed") {
      feedEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [ops?.log?.length, activeTab]);

  // Pending approvals
  const pendingApprovals = useMemo(
    () => (ops?.approvalGates || []).filter(g => g.status === "pending"),
    [ops?.approvalGates]
  );

  const selectedAssetData = useMemo(
    () => ops?.assets?.find(a => a.hostname === selectedAsset) || null,
    [ops?.assets, selectedAsset]
  );

  if (!engagementId) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <p>No engagement selected. Go to Engagements and click Launch.</p>
      </div>
    );
  }

  const isLoading = engagementQ.isLoading;
  const roeStatus = engagement?.roeStatus || "none";
  const roeSigned = roeStatus === "signed" || roeStatus === "pending";

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* ── Header ── */}
      <div className="flex-none border-b border-border/50 bg-card/50 backdrop-blur-sm px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-red-500/20 to-orange-500/20 flex items-center justify-center">
              <Crosshair className="h-5 w-5 text-red-400" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-foreground">
                {isLoading ? "Loading..." : engagement?.name || `Engagement #${engagementId}`}
              </h1>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Badge variant="outline" className="text-[10px]">
                  {engagement?.engagementType?.replace("_", " ").toUpperCase() || "PENTEST"}
                </Badge>
                <span>{engagement?.customerName}</span>
                <span className="text-border">|</span>
                <span className="flex items-center gap-1">
                  {roeSigned ? <ShieldCheck className="h-3 w-3 text-green-400" /> : <ShieldX className="h-3 w-3 text-red-400" />}
                  RoE: {roeStatus}
                </span>
                <span className="text-border">|</span>
                <span className="flex items-center gap-1">
                  <Wifi className={`h-3 w-3 ${wsConnected ? "text-green-400" : "text-red-400"}`} />
                  {wsConnected ? "Live" : "Disconnected"}
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {ops?.isRunning ? (
              <>
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />
                  <span className="max-w-[200px] truncate">{ops.currentAction || "Running..."}</span>
                </div>
                <Button variant="destructive" size="sm" onClick={() => setConfirmStop(true)}>
                  <Square className="h-4 w-4 mr-1" /> Stop
                </Button>
              </>
            ) : (
              <Button
                size="sm"
                onClick={() => executeMut.mutate({ engagementId })}
                disabled={executeMut.isPending || ops?.phase === "completed"}
                className="bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500"
              >
                {executeMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Play className="h-4 w-4 mr-1" />}
                {ops?.phase === "completed" ? "Completed" : "Execute"}
              </Button>
            )}
          </div>
        </div>

        {/* ── Phase Progress ── */}
        <div className="mt-4 flex items-center gap-1">
          {PHASES.map((phase, idx) => {
            const currentIdx = getPhaseIndex(ops?.phase || "idle");
            const isActive = phase.id === ops?.phase;
            const isComplete = currentIdx > idx;
            const isPending = currentIdx < idx;
            return (
              <div key={phase.id} className="flex items-center flex-1">
                <div className={`flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-medium transition-all ${
                  isActive ? "bg-primary/20 text-primary ring-1 ring-primary/30" :
                  isComplete ? "bg-green-500/10 text-green-400" :
                  "bg-muted/30 text-muted-foreground/50"
                }`}>
                  {isComplete ? <CheckCircle2 className="h-3.5 w-3.5 text-green-500" /> :
                   isActive && ops?.isRunning ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> :
                   phase.icon}
                  <span className="hidden sm:inline">{phase.label}</span>
                </div>
                {idx < PHASES.length - 1 && (
                  <ChevronRight className={`h-3 w-3 mx-0.5 flex-none ${isComplete ? "text-green-500/50" : "text-muted-foreground/20"}`} />
                )}
              </div>
            );
          })}
        </div>
        <Progress value={ops?.progress || 0} className="mt-2 h-1.5" />
      </div>

      {/* ── Approval Banner ── */}
      {pendingApprovals.length > 0 && (
        <div className="flex-none bg-orange-500/10 border-b border-orange-500/30 px-6 py-3">
          <div className="flex items-center gap-2 text-orange-400 text-sm font-medium mb-2">
            <ShieldAlert className="h-4 w-4" />
            {pendingApprovals.length} Approval{pendingApprovals.length > 1 ? "s" : ""} Required
          </div>
          <div className="space-y-2">
            {pendingApprovals.map(gate => (
              <div key={gate.id} className="flex items-center justify-between bg-card/50 rounded-lg px-4 py-3 border border-orange-500/20">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    {riskBadge(gate.riskTier)}
                    <span className="text-sm font-medium text-foreground">{gate.title}</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5 truncate">{gate.description}</p>
                </div>
                <div className="flex items-center gap-2 ml-4 flex-none">
                  <Button
                    size="sm"
                    variant="outline"
                    className="border-red-500/30 text-red-400 hover:bg-red-500/10"
                    onClick={() => approveMut.mutate({ gateId: gate.id, approved: false })}
                    disabled={approveMut.isPending}
                  >
                    <XCircle className="h-3.5 w-3.5 mr-1" /> Deny
                  </Button>
                  <Button
                    size="sm"
                    className="bg-green-600 hover:bg-green-500"
                    onClick={() => approveMut.mutate({ gateId: gate.id, approved: true })}
                    disabled={approveMut.isPending}
                  >
                    <CheckCircle2 className="h-3.5 w-3.5 mr-1" /> Approve
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Main Content ── */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left: Live Feed + Tabs */}
        <div className="flex-1 flex flex-col overflow-hidden">
          <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 flex flex-col overflow-hidden">
            <div className="flex-none px-6 pt-3">
              <TabsList className="bg-muted/30">
                <TabsTrigger value="feed" className="text-xs">
                  <Activity className="h-3.5 w-3.5 mr-1" /> Live Feed
                  {ops?.log?.length ? <Badge variant="secondary" className="ml-1 text-[9px] h-4 px-1">{ops.log.length}</Badge> : null}
                </TabsTrigger>
                <TabsTrigger value="assets" className="text-xs">
                  <Target className="h-3.5 w-3.5 mr-1" /> Assets
                  {ops?.assets?.length ? <Badge variant="secondary" className="ml-1 text-[9px] h-4 px-1">{ops.assets.length}</Badge> : null}
                </TabsTrigger>
                <TabsTrigger value="scope" className="text-xs">
                  <Shield className="h-3.5 w-3.5 mr-1" /> RoE & Scope
                </TabsTrigger>
              </TabsList>
            </div>

            {/* ── Live Feed Tab ── */}
            <TabsContent value="feed" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="space-y-1 py-3">
                  {(!ops || ops.log.length === 0) && (
                    <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                      <Crosshair className="h-12 w-12 mb-4 opacity-20" />
                      <p className="text-sm">No activity yet. Click <strong>Execute</strong> to start the engagement.</p>
                      {!roeSigned && (
                        <p className="text-xs text-orange-400 mt-2">⚠️ RoE must be signed for active operations</p>
                      )}
                    </div>
                  )}
                  {ops?.log.map(entry => (
                    <div
                      key={entry.id}
                      className={`flex items-start gap-2 px-3 py-2 rounded-md text-sm transition-colors ${
                        entry.type === "phase_complete" ? "bg-green-500/5 border border-green-500/10" :
                        entry.type === "approval_request" ? "bg-orange-500/5 border border-orange-500/10" :
                        entry.type === "exploit_success" ? "bg-red-500/5 border border-red-500/10" :
                        entry.type === "error" ? "bg-red-500/5 border border-red-500/10" :
                        entry.type === "llm_decision" ? "bg-cyan-500/5 border border-cyan-500/10" :
                        "hover:bg-muted/20"
                      }`}
                    >
                      <span className="flex-none mt-0.5">{logIcon(entry.type)}</span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-foreground">{entry.title}</span>
                          {riskBadge(entry.riskTier)}
                        </div>
                        <p className="text-xs text-muted-foreground mt-0.5">{entry.detail}</p>
                        {entry.data && entry.type === "llm_decision" && entry.data.reasoning && (
                          <p className="text-xs text-cyan-400/70 mt-1 italic">💡 {entry.data.reasoning}</p>
                        )}
                      </div>
                      <span className="flex-none text-[10px] text-muted-foreground/50 tabular-nums">
                        {formatTime(entry.timestamp)}
                      </span>
                    </div>
                  ))}
                  <div ref={feedEndRef} />
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ── Assets Tab ── */}
            <TabsContent value="assets" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <div className="flex h-full gap-4 py-3">
                {/* Asset List */}
                <ScrollArea className="w-1/2 border border-border/30 rounded-lg">
                  <div className="p-2 space-y-1">
                    {(!ops || ops.assets.length === 0) && (
                      <p className="text-sm text-muted-foreground text-center py-10">No assets discovered yet</p>
                    )}
                    {ops?.assets.map(asset => (
                      <button
                        key={asset.hostname}
                        onClick={() => setSelectedAsset(asset.hostname)}
                        className={`w-full text-left px-3 py-2.5 rounded-md transition-colors ${
                          selectedAsset === asset.hostname ? "bg-primary/10 ring-1 ring-primary/30" : "hover:bg-muted/20"
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          {assetIcon(asset.type)}
                          <span className="text-sm font-medium text-foreground truncate">{asset.hostname}</span>
                          {assetStatusBadge(asset.status)}
                        </div>
                        <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground">
                          {asset.ip && <span>IP: {asset.ip}</span>}
                          <span>{asset.ports.length} ports</span>
                          <span>{asset.vulns.length} vulns</span>
                          {asset.zapFindings.length > 0 && <span>{asset.zapFindings.length} ZAP</span>}
                          {asset.wafDetected && (
                            <span className="text-orange-400">WAF: {asset.wafDetected}</span>
                          )}
                        </div>
                      </button>
                    ))}
                  </div>
                </ScrollArea>

                {/* Asset Detail */}
                <ScrollArea className="w-1/2 border border-border/30 rounded-lg">
                  {selectedAssetData ? (
                    <div className="p-4 space-y-4">
                      <div className="flex items-center gap-2">
                        {assetIcon(selectedAssetData.type)}
                        <h3 className="font-semibold text-foreground">{selectedAssetData.hostname}</h3>
                        {assetStatusBadge(selectedAssetData.status)}
                      </div>
                      {selectedAssetData.ip && (
                        <p className="text-xs text-muted-foreground">IP: {selectedAssetData.ip}</p>
                      )}
                      {selectedAssetData.wafDetected && (
                        <div className="flex items-center gap-2 text-xs text-orange-400 bg-orange-500/10 rounded px-2 py-1">
                          <ShieldAlert className="h-3.5 w-3.5" />
                          WAF Detected: {selectedAssetData.wafDetected}
                        </div>
                      )}

                      {/* Ports */}
                      {selectedAssetData.ports.length > 0 && (
                        <div>
                          <h4 className="text-xs font-medium text-muted-foreground mb-1">Open Ports</h4>
                          <div className="space-y-0.5">
                            {selectedAssetData.ports.map((p, i) => (
                              <div key={i} className="flex items-center gap-2 text-xs px-2 py-1 bg-muted/10 rounded">
                                <span className="font-mono text-cyan-400 w-12">{p.port}</span>
                                <span className="text-foreground">{p.service}</span>
                                {p.version && <span className="text-muted-foreground">{p.version}</span>}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Vulns */}
                      {selectedAssetData.vulns.length > 0 && (
                        <div>
                          <h4 className="text-xs font-medium text-muted-foreground mb-1">Vulnerabilities</h4>
                          <div className="space-y-0.5">
                            {selectedAssetData.vulns.map((v, i) => (
                              <div key={i} className="flex items-center gap-2 text-xs px-2 py-1 bg-muted/10 rounded">
                                <Badge variant="outline" className={`text-[9px] ${
                                  v.severity === "critical" ? "text-red-400 border-red-500/30" :
                                  v.severity === "high" ? "text-orange-400 border-orange-500/30" :
                                  v.severity === "medium" ? "text-yellow-400 border-yellow-500/30" :
                                  "text-blue-400 border-blue-500/30"
                                }`}>{v.severity}</Badge>
                                <span className="text-foreground truncate">{v.title}</span>
                                {v.cve && <span className="text-muted-foreground font-mono">{v.cve}</span>}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* ZAP Findings */}
                      {selectedAssetData.zapFindings.length > 0 && (
                        <div>
                          <h4 className="text-xs font-medium text-muted-foreground mb-1">ZAP Web App Findings</h4>
                          <div className="space-y-0.5">
                            {selectedAssetData.zapFindings.map((f, i) => (
                              <div key={i} className="flex items-center gap-2 text-xs px-2 py-1 bg-muted/10 rounded">
                                <Badge variant="outline" className={`text-[9px] ${
                                  f.risk === "High" ? "text-red-400 border-red-500/30" :
                                  f.risk === "Medium" ? "text-yellow-400 border-yellow-500/30" :
                                  "text-blue-400 border-blue-500/30"
                                }`}>{f.risk}</Badge>
                                <span className="text-foreground truncate">{f.alert}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Exploit Attempts */}
                      {selectedAssetData.exploitAttempts.length > 0 && (
                        <div>
                          <h4 className="text-xs font-medium text-muted-foreground mb-1">Exploit Attempts</h4>
                          <div className="space-y-0.5">
                            {selectedAssetData.exploitAttempts.map((e, i) => (
                              <div key={i} className="flex items-center gap-2 text-xs px-2 py-1 bg-muted/10 rounded">
                                {e.success ? <CheckCircle2 className="h-3 w-3 text-green-400" /> : <XCircle className="h-3 w-3 text-red-400" />}
                                <span className="text-foreground">{e.module}</span>
                                {e.sessionId && <span className="text-green-400 font-mono">{e.sessionId}</span>}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
                      Select an asset to view details
                    </div>
                  )}
                </ScrollArea>
              </div>
            </TabsContent>

            {/* ── RoE & Scope Tab ── */}
            <TabsContent value="scope" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="py-3 space-y-4">
                  <Card className="bg-card/50 border-border/30">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Shield className="h-4 w-4" /> Rules of Engagement
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="grid grid-cols-2 gap-3 text-sm">
                        <div>
                          <span className="text-muted-foreground text-xs">Status</span>
                          <div className="flex items-center gap-1.5 mt-0.5">
                            {roeSigned ? <ShieldCheck className="h-4 w-4 text-green-400" /> : <ShieldX className="h-4 w-4 text-red-400" />}
                            <span className={roeSigned ? "text-green-400" : "text-red-400"}>
                              {roeStatus === "signed" ? "Signed" : roeStatus === "pending" ? "Pending" : "Not Signed"}
                            </span>
                          </div>
                        </div>
                        <div>
                          <span className="text-muted-foreground text-xs">Engagement Type</span>
                          <p className="mt-0.5 font-medium">{engagement?.engagementType?.replace("_", " ").toUpperCase()}</p>
                        </div>
                        {engagement?.roeSignerName && (
                          <div>
                            <span className="text-muted-foreground text-xs">Signer</span>
                            <p className="mt-0.5">{engagement.roeSignerName}</p>
                          </div>
                        )}
                        {engagement?.roeSignedDate && (
                          <div>
                            <span className="text-muted-foreground text-xs">Signed Date</span>
                            <p className="mt-0.5">{new Date(engagement.roeSignedDate).toLocaleDateString()}</p>
                          </div>
                        )}
                      </div>

                      <Separator />

                      <div>
                        <h4 className="text-xs font-medium text-muted-foreground mb-2">In-Scope Targets</h4>
                        <div className="space-y-1">
                          {engagement?.targetDomain?.split(/[,;\s]+/).filter(Boolean).map((d: string, i: number) => (
                            <div key={i} className="flex items-center gap-2 text-sm px-2 py-1 bg-green-500/5 rounded border border-green-500/10">
                              <Globe className="h-3.5 w-3.5 text-green-400" />
                              <span>{d}</span>
                            </div>
                          ))}
                          {engagement?.targetIpRange?.split(/[,;\s]+/).filter(Boolean).map((ip: string, i: number) => (
                            <div key={i} className="flex items-center gap-2 text-sm px-2 py-1 bg-green-500/5 rounded border border-green-500/10">
                              <Network className="h-3.5 w-3.5 text-green-400" />
                              <span>{ip}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {!roeSigned && (
                        <div className="bg-orange-500/10 border border-orange-500/20 rounded-lg px-4 py-3">
                          <div className="flex items-center gap-2 text-orange-400 text-sm font-medium">
                            <AlertTriangle className="h-4 w-4" />
                            RoE Must Be Signed
                          </div>
                          <p className="text-xs text-muted-foreground mt-1">
                            Active operations (enumeration, exploitation, C2 deployment) are blocked until the Rules of Engagement are signed by the team lead. Only passive recon is allowed.
                          </p>
                        </div>
                      )}
                    </CardContent>
                  </Card>

                  {/* Scope Enforcement Log */}
                  <Card className="bg-card/50 border-border/30">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Eye className="h-4 w-4" /> Scope Enforcement
                      </CardTitle>
                      <CardDescription className="text-xs">All active operations are validated against RoE scope before execution</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-1">
                        {ops?.log.filter(l => l.type === "approval_request" || l.type === "approval_response").map(entry => (
                          <div key={entry.id} className="flex items-center gap-2 text-xs px-2 py-1.5 bg-muted/10 rounded">
                            {logIcon(entry.type)}
                            <span className="text-foreground">{entry.title}</span>
                            <span className="text-muted-foreground ml-auto">{formatTime(entry.timestamp)}</span>
                          </div>
                        ))}
                        {(!ops || ops.log.filter(l => l.type === "approval_request" || l.type === "approval_response").length === 0) && (
                          <p className="text-xs text-muted-foreground text-center py-4">No scope enforcement events yet</p>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </ScrollArea>
            </TabsContent>
          </Tabs>
        </div>

        {/* Right: Stats Panel */}
        <div className="w-64 flex-none border-l border-border/30 bg-card/30 overflow-y-auto p-4 space-y-4 hidden lg:block">
          <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Stats</h3>

          <div className="space-y-3">
            <StatCard icon={<Server className="h-4 w-4 text-cyan-400" />} label="Hosts Scanned" value={ops?.stats.hostsScanned || 0} />
            <StatCard icon={<Activity className="h-4 w-4 text-blue-400" />} label="Open Ports" value={ops?.stats.portsFound || 0} />
            <StatCard icon={<Bug className="h-4 w-4 text-yellow-400" />} label="Vulns Found" value={ops?.stats.vulnsFound || 0} />
            <StatCard icon={<Globe className="h-4 w-4 text-blue-400" />} label="ZAP Scans" value={ops?.stats.zapScansRun || 0} />
            <StatCard icon={<ShieldAlert className="h-4 w-4 text-orange-400" />} label="WAFs Detected" value={ops?.stats.wafDetections || 0} />
            <StatCard icon={<Crosshair className="h-4 w-4 text-red-400" />} label="Exploits Tried" value={ops?.stats.exploitsAttempted || 0} />
            <StatCard icon={<Skull className="h-4 w-4 text-red-500" />} label="Exploits Succeeded" value={ops?.stats.exploitsSucceeded || 0} />
            <StatCard icon={<Terminal className="h-4 w-4 text-green-400" />} label="Sessions Opened" value={ops?.stats.sessionsOpened || 0} />
          </div>

          <Separator />

          {ops?.startedAt && (
            <div className="text-xs text-muted-foreground space-y-1">
              <div className="flex justify-between">
                <span>Started</span>
                <span>{formatTime(ops.startedAt)}</span>
              </div>
              {ops.completedAt ? (
                <div className="flex justify-between">
                  <span>Duration</span>
                  <span>{formatDuration(ops.completedAt - ops.startedAt)}</span>
                </div>
              ) : ops.isRunning ? (
                <div className="flex justify-between">
                  <span>Elapsed</span>
                  <span>{formatDuration(Date.now() - ops.startedAt)}</span>
                </div>
              ) : null}
            </div>
          )}

          {ops?.llmPlan && (
            <>
              <Separator />
              <div>
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">LLM Strategy</h3>
                <p className="text-xs text-cyan-400/80">{ops.llmPlan}</p>
              </div>
            </>
          )}

          {/* Approval History */}
          {ops && ops.approvalGates.length > 0 && (
            <>
              <Separator />
              <div>
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Approvals</h3>
                <div className="space-y-1">
                  {ops.approvalGates.map(gate => (
                    <div key={gate.id} className="flex items-center gap-1.5 text-[10px]">
                      {gate.status === "approved" ? <CheckCircle2 className="h-3 w-3 text-green-400" /> :
                       gate.status === "denied" ? <XCircle className="h-3 w-3 text-red-400" /> :
                       <Clock className="h-3 w-3 text-orange-400 animate-pulse" />}
                      <span className="truncate text-muted-foreground">{gate.title}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {/* ── Stop Confirmation Dialog ── */}
      <AlertDialog open={confirmStop} onOpenChange={setConfirmStop}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Stop Engagement Execution?</AlertDialogTitle>
            <AlertDialogDescription>
              This will halt the autonomous execution pipeline. Any pending scans will be abandoned. You can restart execution later.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground"
              onClick={() => stopMut.mutate({ engagementId })}
            >
              Stop Execution
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function StatCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
  return (
    <div className="flex items-center gap-2.5">
      {icon}
      <div className="flex-1 flex justify-between items-baseline">
        <span className="text-xs text-muted-foreground">{label}</span>
        <span className="text-sm font-semibold text-foreground tabular-nums">{value}</span>
      </div>
    </div>
  );
}
