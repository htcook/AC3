/**
 * EngagementOps — Unified Engagement Operations Console
 *
 * Operator workflow:
 * 1. Paste in-scope assets (domains, IPs, URLs)
 * 2. Run Passive Discovery (OSINT, domain intel)
 * 3. Review discovered assets → Click "Start Active Scan"
 * 4. LLM orchestrates: nmap → tool matching (ZAP for web, nuclei for CVEs) → credential testing → exploit approval
 * 5. Operator approves high-risk actions inline
 * 6. Pentest: per-asset unauthorized access evidence → report
 * 7. Red Team: C2 agent deploy → Caldera callback → pivot
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
import { Textarea } from "@/components/ui/textarea";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";
import {
  Play, Square, Shield, ShieldAlert, ShieldCheck, ShieldX,
  Target, Crosshair, Radar, Bug, Skull, Radio, Globe,
  Server, Database, MonitorSmartphone, AlertTriangle, CheckCircle2,
  XCircle, Clock, Loader2, ChevronRight, Eye, FileText,
  Zap, Lock, Unlock, Activity, Terminal, Network, Wifi,
  Plus, Search, ArrowRight, Swords, RotateCcw,
} from "lucide-react";

// ─── Types (mirror server) ──────────────────────────────────────────────────

type OpsPhase = "idle" | "recon" | "recon_complete" | "enumeration" | "vuln_detection" | "exploitation" | "post_exploit" | "reporting" | "completed" | "paused" | "error";
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

interface AssetPassiveRecon {
  services: Array<{ port: number; service: string; product?: string; version?: string; source: string }>;
  technologies: string[];
  certificates: Array<{ subject: string; issuer: string; expiry?: string }>;
  riskSignals: Array<{ signal: string; severity: string; source: string }>;
  subdomains: string[];
  osDetected?: string;
}

interface ToolResult {
  tool: string;
  command: string;
  exitCode: number;
  durationMs: number;
  timedOut: boolean;
  findingCount: number;
  findings: Array<{ severity: string; title: string; cve?: string }>;
  outputPreview: string;
  executedAt: number;
  phase: string;
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
  passiveRecon?: AssetPassiveRecon;
  toolResults: ToolResult[];
}

interface AssetScanPlan {
  hostname: string;
  ip?: string;
  assetType: string;
  discoveryNmapFlags: string;
  discoveryNmapRationale: string;
  nmapFlags: string;
  nmapRationale: string;
  evasionTechniques: string[];
  activeTools: Array<{
    tool: string;
    command: string;
    rationale: string;
    priority: number;
  }>;
  riskNotes: string;
}
interface ScanPlan {
  generatedAt: number;
  overallStrategy: string;
  discoveryStrategy: string;
  discoveryEvasionProfile: {
    timing: string;
    fragmentation: boolean;
    decoys: boolean;
    randomizeHosts: boolean;
    dataLengthPadding: boolean;
    sourcePortSpoofing: boolean;
    rationale: string;
  };
  assetPlans: AssetScanPlan[];
  estimatedDuration: string;
  riskAssessment: string;
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
  scanPlan?: ScanPlan;
  passiveReconResults?: Record<string, any>;
  scanProfile?: 'quick' | 'standard' | 'deep' | 'stealth';
  currentAction?: string;
  currentDomain?: string;
  currentDomainStartedAt?: number;
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

const PHASES: Array<{ id: string; label: string; icon: React.ReactNode; color: string }> = [
  { id: "recon", label: "Recon", icon: <Radar className="h-4 w-4" />, color: "text-blue-400" },
  { id: "enumeration", label: "Nmap Enum", icon: <Target className="h-4 w-4" />, color: "text-cyan-400" },
  { id: "vuln_detection", label: "Vuln Scan", icon: <Bug className="h-4 w-4" />, color: "text-yellow-400" },
  { id: "exploitation", label: "Exploit", icon: <Skull className="h-4 w-4" />, color: "text-red-400" },
  { id: "post_exploit", label: "Post-Exploit", icon: <Radio className="h-4 w-4" />, color: "text-purple-400" },
  { id: "completed", label: "Complete", icon: <CheckCircle2 className="h-4 w-4" />, color: "text-green-400" },
];

function getPhaseIndex(phase: string): number {
  if (phase === "recon_complete") return 0; // still in recon area
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
    case "credential_test": return <Lock className="h-3.5 w-3.5 text-yellow-400" />;
    case "nmap_result": return <Target className="h-3.5 w-3.5 text-cyan-400" />;
    case "tool_match": return <Swords className="h-3.5 w-3.5 text-purple-400" />;
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
    discovered: { label: "Discovered", className: "bg-blue-500/20 text-blue-400" },
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
  const [selectedProfile, setSelectedProfile] = useState<'quick' | 'standard' | 'deep' | 'stealth'>('standard');
  const [showProfileDetails, setShowProfileDetails] = useState(false);

  // ── Target paste-in state ──
  const [targetInput, setTargetInput] = useState("");
  const [showTargetInput, setShowTargetInput] = useState(false);

  // ── Data fetching ──
  const engagementsListQ = trpc.engagements.list.useQuery(
    undefined,
    { enabled: !engagementId }
  );
  const engagementQ = trpc.engagements.get.useQuery(
    { id: engagementId },
    { enabled: engagementId > 0 }
  );
  const utils = trpc.useUtils();
  const [isRunning, setIsRunning] = useState(false);
  const opsStateQ = trpc.engagementOps.getState.useQuery(
    { engagementId },
    { enabled: engagementId > 0, refetchInterval: isRunning ? 3000 : 10000 }
  );

  // Track running state for adaptive polling
  useEffect(() => {
    if (opsStateQ.data) setIsRunning(!!opsStateQ.data.isRunning);
  }, [opsStateQ.data?.isRunning]);

  // Exploit matching query — fires when vulns are found
  const exploitsQ = trpc.engagementOps.loadExploits.useQuery(
    { engagementId },
    { enabled: engagementId > 0 && (opsStateQ.data?.stats?.vulnsFound || 0) > 0, refetchInterval: isRunning ? 5000 : 30000 }
  );

  // ── Mutations ──
  const addTargetsMut = trpc.engagementOps.addTargets.useMutation({
    onSuccess: (data) => {
      toast.success(`Added ${data.added} targets (${data.totalAssets} total assets)`);
      setTargetInput("");
      setShowTargetInput(false);
      opsStateQ.refetch();
      engagementQ.refetch();
    },
    onError: (e) => toast.error(e.message),
  });

  const passiveScanMut = trpc.engagementOps.startPassiveScan.useMutation({
    onSuccess: () => {
      toast.success("Passive Discovery Started — running OSINT and domain intel on all targets");
      setActiveTab("feed");
      opsStateQ.refetch();
    },
    onError: (e) => toast.error(e.message),
  });

  const scanProfilesQ = trpc.engagementOps.listScanProfiles.useQuery(
    undefined,
    { enabled: engagementId > 0 }
  );

  const activeScanMut = trpc.engagementOps.startActiveScan.useMutation({
    onSuccess: (data) => {
      toast.success(`Active Scan Started (${selectedProfile.toUpperCase()}) — LLM orchestrating scan plan → nmap → tool matching → exploit on ${data.assetsCount} assets`);
      setActiveTab("feed");
      opsStateQ.refetch();
    },
    onError: (e) => toast.error(e.message),
  });

  const [showScanPlan, setShowScanPlan] = useState(false);
  const generatePlanMut = trpc.engagementOps.generateScanPlan.useMutation({
    onSuccess: (data) => {
      toast.success(`Scan Plan Generated — ${data?.scanPlan?.assetPlans?.length || 0} assets analyzed`);
      setShowScanPlan(true);
      opsStateQ.refetch();
    },
    onError: (e) => toast.error(e.message),
  });

  const executeMut = trpc.engagementOps.execute.useMutation({
    onSuccess: () => {
      toast.success("Full Execution Started — LLM orchestrator running all phases");
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

  const skipDomainMut = trpc.engagementOps.skipCurrentDomain.useMutation({
    onSuccess: (data) => {
      toast.success(`Skip requested for ${data.domain} — will advance after current stage`);
      opsStateQ.refetch();
    },
    onError: (e) => toast.error(e.message),
  });

  // ── Elapsed timer (ticks every second while scan is running) ──
  const [elapsedNow, setElapsedNow] = useState(Date.now());
  useEffect(() => {
    if (!isRunning) return;
    const interval = setInterval(() => setElapsedNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, [isRunning]);

  const formatElapsed = (startMs: number) => {
    const secs = Math.max(0, Math.floor((elapsedNow - startMs) / 1000));
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${s.toString().padStart(2, '0')}`;
  };

  const resetMut = trpc.engagementOps.resetOps.useMutation({
    onSuccess: (data) => {
      toast.success(`Ops state reset. ${data.assetsPreserved} assets preserved.`);
      opsStateQ.refetch();
    },
    onError: (e) => toast.error(e.message),
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
  const { events: wsEvents, lastEvent: wsLastEvent, isConnected: wsConnected } = useWebSocket({
    channels: wsChannels,
    maxEvents: 200,
  });

  // ── Merge WS events into ops state for instant feed updates ──
  const [wsLogBuffer, setWsLogBuffer] = useState<OpsLogEntry[]>([]);
  const lastProcessedWsRef = useRef<number>(0);

  // Process incoming WS events and extract log entries
  useEffect(() => {
    if (!wsLastEvent || wsLastEvent.type !== "engagement:progress_update") return;
    if (wsLastEvent.timestamp <= lastProcessedWsRef.current) return;
    lastProcessedWsRef.current = wsLastEvent.timestamp;

    const evtData = wsLastEvent.data;
    if (!evtData) return;

    // Log entry pushed via WS
    if (evtData.type === "log" && evtData.entry) {
      const entry = evtData.entry as OpsLogEntry;
      setWsLogBuffer(prev => {
        // Deduplicate by id
        if (prev.some(e => e.id === entry.id)) return prev;
        const next = [...prev, entry].slice(-100);
        return next;
      });
    }

    // Phase change — immediately refetch full state
    if (evtData.type === "phase_change" || evtData.type === "approval_request" || evtData.type === "stopped") {
      utils.engagementOps.getState.invalidate({ engagementId });
      utils.engagementOps.loadExploits.invalidate({ engagementId });
    }

    // Stats update — refetch
    if (evtData.type === "stats_update") {
      utils.engagementOps.getState.invalidate({ engagementId });
    }
  }, [wsLastEvent, engagementId, utils]);

  // Clear WS buffer when polled state refreshes (polled state is authoritative)
  useEffect(() => {
    if (opsStateQ.data) {
      setWsLogBuffer([]);
    }
  }, [opsStateQ.dataUpdatedAt]);

  // Merge: polled ops state + any WS log entries that arrived since last poll
  const ops: OpsState | null = useMemo(() => {
    const base = opsStateQ.data || null;
    if (!base) return null;
    // Ensure required arrays exist (defensive against empty DB state)
    if (!base.log) base.log = [];
    if (!base.assets) base.assets = [];
    if (!base.approvalGates) base.approvalGates = [];
    if (!base.stats) base.stats = { hostsScanned: 0, portsFound: 0, vulnsFound: 0, exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0, zapScansRun: 0, wafDetections: 0 };
    if (wsLogBuffer.length === 0) return base;
    const existingIds = new Set(base.log.map(l => l.id));
    const newEntries = wsLogBuffer.filter(e => !existingIds.has(e.id));
    if (newEntries.length === 0) return base;
    return { ...base, log: [...base.log, ...newEntries] };
  }, [opsStateQ.data, wsLogBuffer]);
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

  // Derived state
  const roeStatus = engagement?.roeStatus || "none";
  const roeSigned = roeStatus === "signed" || roeStatus === "pending";
  const hasTargets = (ops?.assets?.length || 0) > 0 || !!(engagement?.targetDomain || engagement?.targetIpRange);
  const isReconComplete = ops?.phase === "recon_complete" || (getPhaseIndex(ops?.phase || "idle") > 0 && ops?.phase !== "recon");
  const isIdle = !ops || ops.phase === "idle";
  const isErrorState = ops?.phase === "error";
  const canStartPassive = hasTargets && !ops?.isRunning && (isIdle || ops?.phase === "idle" || isErrorState);
  const canStartActive = isReconComplete && !ops?.isRunning && roeSigned;

  if (!engagementId) {
    const activeEngagements = (engagementsListQ.data || []).filter(
      (e: any) => e.status === "active" || e.status === "in_progress" || e.status === "planning"
    );
    return (
      <div className="flex flex-col items-center justify-center h-full gap-6 px-4">
        <div className="text-center">
          <Crosshair className="h-12 w-12 mx-auto mb-4 text-red-400 opacity-60" />
          <h2 className="text-lg font-bold text-foreground mb-1">Engagement Operations Console</h2>
          <p className="text-sm text-muted-foreground">Select an engagement to begin operations</p>
        </div>
        {engagementsListQ.isLoading ? (
          <div className="flex items-center gap-2 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span className="text-sm">Loading engagements...</span>
          </div>
        ) : activeEngagements.length === 0 ? (
          <div className="text-center">
            <p className="text-sm text-muted-foreground mb-3">No active engagements found.</p>
            <a href="/engagements">
              <Button variant="outline" className="font-display tracking-wider">
                <Plus className="h-4 w-4 mr-2" /> Create Engagement
              </Button>
            </a>
          </div>
        ) : (
          <div className="grid gap-3 w-full max-w-2xl">
            {activeEngagements.map((eng: any) => (
              <a key={eng.id} href={`/engagement-ops/${eng.id}`} className="block">
                <Card className="hover:border-red-500/40 hover:bg-red-500/5 transition-all cursor-pointer group">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <Crosshair className="h-4 w-4 text-red-400 flex-none" />
                          <span className="font-bold text-foreground truncate">{eng.name}</span>
                          <Badge variant="outline" className="text-[10px] flex-none">{eng.engagementType || 'pentest'}</Badge>
                          <Badge variant="outline" className={`text-[10px] flex-none ${
                            eng.roeStatus === 'signed' ? 'text-green-400 border-green-500/30' :
                            eng.roeStatus === 'pending' ? 'text-yellow-400 border-yellow-500/30' :
                            'text-muted-foreground'
                          }`}>RoE: {eng.roeStatus || 'none'}</Badge>
                        </div>
                        <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground">
                          {eng.customerName && <span>{eng.customerName}</span>}
                          {eng.targetDomain && <span className="truncate max-w-[300px]">{eng.targetDomain}</span>}
                          {eng.targetIpRange && <span>{eng.targetIpRange}</span>}
                        </div>
                      </div>
                      <ArrowRight className="h-5 w-5 text-muted-foreground group-hover:text-red-400 transition-colors flex-none" />
                    </div>
                  </CardContent>
                </Card>
              </a>
            ))}
          </div>
        )}
      </div>
    );
  }

  const isLoading = engagementQ.isLoading;

  return (
    <AppShell activePath="/engagement-ops">
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

          <div className="flex items-center gap-2">
            {ops?.isRunning ? (
              <>
                <div className="flex items-center gap-2 text-sm">
                  <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />
                  <div className="flex flex-col gap-0.5">
                    <span className="max-w-[280px] truncate text-muted-foreground">{ops.currentAction || "Running..."}</span>
                    <div className="flex items-center gap-2 text-xs">
                      {ops.startedAt && (
                        <span className="text-cyan-400 font-mono">
                          <Clock className="h-3 w-3 inline mr-0.5" />
                          Total: {formatElapsed(ops.startedAt)}
                        </span>
                      )}
                      {ops.currentDomain && ops.currentDomainStartedAt && (
                        <span className="text-amber-400 font-mono">
                          {ops.currentDomain}: {formatElapsed(ops.currentDomainStartedAt)}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  {ops.currentDomain && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => skipDomainMut.mutate({ engagementId })}
                      disabled={skipDomainMut.isPending}
                      className="border-amber-500/30 text-amber-400 hover:bg-amber-500/10 text-xs"
                      title={`Skip ${ops.currentDomain} and move to next domain`}
                    >
                      {skipDomainMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ChevronRight className="h-3.5 w-3.5" />}
                      Skip Domain
                    </Button>
                  )}
                  <Button variant="destructive" size="sm" onClick={() => setConfirmStop(true)}>
                    <Square className="h-4 w-4 mr-1" /> Stop
                  </Button>
                </div>
              </>
            ) : (
              <div className="flex items-center gap-2">
                {/* Step 1: Add Targets */}
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setShowTargetInput(!showTargetInput)}
                  className="border-blue-500/30 text-blue-400 hover:bg-blue-500/10"
                >
                  <Plus className="h-4 w-4 mr-1" /> Add Targets
                </Button>

                {/* Step 2: Passive Discovery */}
                {canStartPassive && (
                  <Button
                    size="sm"
                    onClick={() => passiveScanMut.mutate({ engagementId })}
                    disabled={passiveScanMut.isPending}
                    className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500"
                  >
                    {passiveScanMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Search className="h-4 w-4 mr-1" />}
                    Passive Discovery
                  </Button>
                )}

                {/* Step 3: Start Active Scan (appears after passive complete) */}
                {canStartActive && (
                  <Button
                    size="sm"
                    onClick={() => activeScanMut.mutate({ engagementId, scanProfile: selectedProfile })}
                    disabled={activeScanMut.isPending}
                    className="bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500"
                  >
                    {activeScanMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Play className="h-4 w-4 mr-1" />}
                    Start Active Scan
                  </Button>
                )}

                {/* Completed state */}
                {ops?.phase === "completed" && (
                  <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                    <CheckCircle2 className="h-3.5 w-3.5 mr-1" /> Completed
                  </Badge>
                )}

                {/* Error state */}
                {isErrorState && (
                  <div className="flex items-center gap-2">
                    <Badge className="bg-red-500/20 text-red-400 border-red-500/30">
                      <AlertTriangle className="h-3.5 w-3.5 mr-1" /> Error
                    </Badge>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => resetMut.mutate({ engagementId })}
                      disabled={resetMut.isPending}
                      className="border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10"
                    >
                      {resetMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <RotateCcw className="h-4 w-4 mr-1" />}
                      Reset
                    </Button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* ── Target Paste-In Panel ── */}
        {showTargetInput && (
          <div className="mt-4 p-4 bg-muted/20 rounded-lg border border-border/30">
            <div className="flex items-center gap-2 mb-2">
              <Target className="h-4 w-4 text-blue-400" />
              <h3 className="text-sm font-medium text-foreground">Add In-Scope Targets</h3>
            </div>
            <p className="text-xs text-muted-foreground mb-3">
              Paste domains, IPs, or URLs — one per line or comma-separated. These will be added to the engagement scope.
            </p>
            <Textarea
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder={"example.com\n192.168.1.0/24\nhttps://app.example.com\n10.0.0.1"}
              className="font-mono text-sm bg-background/50 min-h-[100px]"
            />
            <div className="flex items-center justify-between mt-3">
              <span className="text-xs text-muted-foreground">
                {targetInput.split(/[\n,;]+/).filter(t => t.trim()).length} target(s) detected
              </span>
              <div className="flex items-center gap-2">
                <Button size="sm" variant="ghost" onClick={() => { setShowTargetInput(false); setTargetInput(""); }}>
                  Cancel
                </Button>
                <Button
                  size="sm"
                  onClick={() => addTargetsMut.mutate({ engagementId, targets: targetInput })}
                  disabled={!targetInput.trim() || addTargetsMut.isPending}
                  className="bg-blue-600 hover:bg-blue-500"
                >
                  {addTargetsMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Plus className="h-4 w-4 mr-1" />}
                  Add to Scope
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* ── Phase Progress ── */}
        <div className="mt-4 flex items-center gap-1">
          {PHASES.map((phase, idx) => {
            const currentIdx = getPhaseIndex(ops?.phase || "idle");
            const isActive = phase.id === ops?.phase || (ops?.phase === "recon_complete" && phase.id === "recon");
            const isComplete = currentIdx > idx;
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

      {/* ── Error Banner ── */}
      {isErrorState && (
        <div className="flex-none border-b border-red-500/30">
          <div className="bg-red-500/10 px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-full bg-red-500/20">
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-red-300">Scan Error</h3>
                  <p className="text-xs text-red-400/80 mt-0.5 max-w-[500px] truncate">
                    {ops?.error || 'An unexpected error occurred during the scan pipeline.'}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => resetMut.mutate({ engagementId })}
                  disabled={resetMut.isPending}
                  className="border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10"
                >
                  {resetMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <RotateCcw className="h-4 w-4 mr-1" />}
                  Reset State
                </Button>
                <Button
                  size="sm"
                  onClick={() => passiveScanMut.mutate({ engagementId })}
                  disabled={passiveScanMut.isPending}
                  className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500"
                >
                  {passiveScanMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Search className="h-4 w-4 mr-1" />}
                  Retry Passive Scan
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Recon Complete Banner — Start Active Scan Prompt ── */}
      {ops?.phase === "recon_complete" && !ops.isRunning && (
        <div className="flex-none border-b border-cyan-500/30">
          {/* Top bar: status + buttons */}
          <div className="bg-cyan-500/10 px-6 py-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2 text-cyan-400 text-sm font-medium">
                  <CheckCircle2 className="h-4 w-4" />
                  Passive Discovery Complete — {ops?.assets?.length || 0} Assets Found
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {ops.scanPlan
                    ? "Scan plan generated. Review the LLM's recommended nmap flags and tools per asset below, then start the active scan."
                    : "Generate a scan plan to let the LLM analyze each asset and recommend specific nmap flags and active tools before scanning."}
                </p>
              </div>
              <div className="flex items-center gap-2 flex-none ml-4">
                {!roeSigned && (
                  <Badge variant="outline" className="text-orange-400 border-orange-500/30 text-xs">
                    <ShieldX className="h-3 w-3 mr-1" /> RoE Required
                  </Badge>
                )}
                {!ops.scanPlan && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => generatePlanMut.mutate({ engagementId })}
                    disabled={generatePlanMut.isPending || !roeSigned}
                    className="border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10"
                  >
                    {generatePlanMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Search className="h-4 w-4 mr-1" />}
                    Generate Scan Plan
                  </Button>
                )}
                {/* Scan Profile Selector */}
                <div className="relative">
                  <select
                    value={selectedProfile}
                    onChange={(e) => setSelectedProfile(e.target.value as any)}
                    className="h-9 rounded-md border border-border bg-background px-3 py-1 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-cyan-500/50 cursor-pointer"
                  >
                    <option value="quick">⚡ Quick</option>
                    <option value="standard">🎯 Standard</option>
                    <option value="deep">🔬 Deep</option>
                    <option value="stealth">🥷 Stealth</option>
                  </select>
                </div>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setShowProfileDetails(!showProfileDetails)}
                  className="text-xs text-muted-foreground hover:text-cyan-400 px-2"
                >
                  {showProfileDetails ? "Hide" : "Details"}
                </Button>
                <Button
                  size="sm"
                  onClick={() => activeScanMut.mutate({ engagementId, scanProfile: selectedProfile })}
                  disabled={activeScanMut.isPending || !roeSigned}
                  className="bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500"
                >
                  {activeScanMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Play className="h-4 w-4 mr-1" />}
                  Start Active Scan ({selectedProfile.charAt(0).toUpperCase() + selectedProfile.slice(1)})
                  <ArrowRight className="h-4 w-4 ml-1" />
                </Button>
              </div>
            </div>
          </div>

          {/* Scan Profile Details Panel */}
          {showProfileDetails && scanProfilesQ.data && (() => {
            const profile = scanProfilesQ.data.find(p => p.name === selectedProfile);
            if (!profile) return null;
            return (
              <div className="bg-slate-900/70 border-b border-border px-6 py-3">
                <div className="flex items-start gap-6">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-medium text-foreground">{profile.displayName}</span>
                      <Badge variant="outline" className="text-[10px] text-muted-foreground">
                        {profile.estimatedTimePerAsset}/asset
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mb-2">{profile.description}</p>
                    <div className="grid grid-cols-3 gap-4 text-[10px]">
                      <div>
                        <span className="text-muted-foreground">Ports:</span>{" "}
                        <span className="text-cyan-400 font-mono">{profile.nmapPorts}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Timing:</span>{" "}
                        <span className="text-cyan-400 font-mono">{profile.nmapTiming}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Nuclei:</span>{" "}
                        <span className="text-yellow-400 font-mono">{profile.nucleiSeverity}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex-none">
                    <div className="text-[10px] text-muted-foreground mb-1">Tools</div>
                    <div className="flex flex-wrap gap-1">
                      {Object.entries(profile.tools).filter(([, v]) => v).map(([tool]) => (
                        <Badge key={tool} variant="outline" className="text-[9px] text-green-400 border-green-500/30">
                          {tool}
                        </Badge>
                      ))}
                    </div>
                    {Object.values(profile.evasion).some(v => v) && (
                      <div className="mt-1">
                        <div className="text-[10px] text-muted-foreground mb-0.5">Evasion</div>
                        <div className="flex flex-wrap gap-1">
                          {Object.entries(profile.evasion).filter(([, v]) => v).map(([tech]) => (
                            <Badge key={tech} variant="outline" className="text-[9px] text-orange-400 border-orange-500/30">
                              {tech.replace(/([A-Z])/g, ' $1').trim()}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })()}

          {/* Scan Plan Details */}
          {ops.scanPlan && (
            <div className="bg-slate-900/50 px-6 py-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm font-medium text-cyan-300">
                  <FileText className="h-4 w-4" />
                  LLM Scan Plan
                  <Badge variant="outline" className="text-xs text-green-400 border-green-500/30 ml-2">
                    {ops?.scanPlan?.assetPlans?.length || 0} assets
                  </Badge>
                  <Badge variant="outline" className="text-xs text-muted-foreground border-border ml-1">
                    Est. {ops?.scanPlan?.estimatedDuration || 'N/A'}
                  </Badge>
                </div>
                <Button size="sm" variant="ghost" className="text-xs" onClick={() => setShowScanPlan(!showScanPlan)}>
                  {showScanPlan ? "Collapse" : "Expand"}
                </Button>
              </div>

              <p className="text-xs text-muted-foreground">{ops?.scanPlan?.overallStrategy || ''}</p>
              <p className="text-xs text-yellow-400/80">
                <AlertTriangle className="h-3 w-3 inline mr-1" />
                {ops?.scanPlan?.riskAssessment || ''}
              </p>

              {showScanPlan && (
                <div className="space-y-3 mt-2">
                  {(ops?.scanPlan?.assetPlans || []).map((ap, i) => (
                    <div key={i} className="bg-slate-800/60 rounded-lg p-3 border border-slate-700/50">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          {ap.assetType === "web_app" ? <Globe className="h-4 w-4 text-blue-400" /> :
                           ap.assetType === "server" ? <Server className="h-4 w-4 text-green-400" /> :
                           <Network className="h-4 w-4 text-gray-400" />}
                          <span className="text-sm font-mono text-foreground">{ap.hostname}</span>
                          {ap.ip && <span className="text-xs text-muted-foreground">({ap.ip})</span>}
                        </div>
                        <Badge variant="outline" className="text-xs">{ap.assetType}</Badge>
                      </div>

                      {/* Nmap flags */}
                      <div className="mb-2">
                        <div className="text-xs text-cyan-400 font-medium mb-1">Nmap Flags:</div>
                        <code className="text-xs bg-black/40 px-2 py-1 rounded font-mono text-green-300 block">
                          nmap {ap.nmapFlags} {ap.ip || ap.hostname}
                        </code>
                        <p className="text-xs text-muted-foreground mt-1 italic">{ap.nmapRationale}</p>
                      </div>

                      {/* Active tools */}
                      <div className="mb-2">
                        <div className="text-xs text-orange-400 font-medium mb-1">Active Tools ({ap.activeTools?.length || 0}):</div>
                        <div className="space-y-1">
                          {(ap.activeTools || []).map((t, j) => (
                            <div key={j} className="flex items-start gap-2 text-xs">
                              <Badge variant="outline" className={`text-[10px] flex-none ${
                                t.priority === 1 ? "border-red-500/30 text-red-400" :
                                t.priority === 2 ? "border-orange-500/30 text-orange-400" :
                                "border-gray-500/30 text-gray-400"
                              }`}>
                                P{t.priority}
                              </Badge>
                              <code className="font-mono text-green-300/80 bg-black/30 px-1 rounded flex-none">{t.tool}</code>
                              <span className="text-muted-foreground">{t.rationale}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Risk notes */}
                      {ap.riskNotes && (
                        <p className="text-xs text-yellow-400/70 flex items-start gap-1">
                          <AlertTriangle className="h-3 w-3 flex-none mt-0.5" />
                          {ap.riskNotes}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

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
                <TabsTrigger value="discovery" className="text-xs">
                  <Radar className="h-3.5 w-3.5 mr-1" /> Discovery
                  {(() => {
                    const toolCount = (ops?.assets || []).reduce((sum: number, a: any) => sum + (a.toolResults?.length || 0), 0);
                    return toolCount > 0 ? <Badge variant="secondary" className="ml-1 text-[9px] h-4 px-1 bg-cyan-500/20 text-cyan-400">{toolCount}</Badge> : null;
                  })()}
                </TabsTrigger>
                <TabsTrigger value="exploits" className="text-xs">
                  <Swords className="h-3.5 w-3.5 mr-1" /> Exploit Match
                  {(exploitsQ.data?.exploits?.length || 0) > 0 && (
                    <Badge variant="secondary" className="ml-1 text-[9px] h-4 px-1 bg-red-500/20 text-red-400">{exploitsQ.data!.exploits.length}</Badge>
                  )}
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
                  {(!ops || !ops.log || ops.log.length === 0) && (
                    <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                      <Crosshair className="h-12 w-12 mb-4 opacity-20" />
                      <p className="text-sm font-medium mb-2">Ready to Begin</p>
                      <div className="text-xs text-center max-w-md space-y-2">
                        <p><strong>Step 1:</strong> Click <strong>Add Targets</strong> to paste in-scope domains, IPs, or URLs</p>
                        <p><strong>Step 2:</strong> Click <strong>Passive Discovery</strong> to run OSINT on all targets</p>
                        <p><strong>Step 3:</strong> Review assets, then click <strong>Start Active Scan</strong> to hand off to the LLM</p>
                        <p className="text-cyan-400">The LLM will run nmap first, then match tools to discovered services automatically</p>
                      </div>
                      {!roeSigned && (
                        <p className="text-xs text-orange-400 mt-4">⚠️ RoE must be signed before active scanning (passive recon is allowed)</p>
                      )}
                    </div>
                  )}
                  {(ops?.log || []).map(entry => (
                    <div
                      key={entry.id}
                      className={`flex items-start gap-2 px-3 py-2 rounded-md text-sm transition-colors ${
                        entry.type === "phase_complete" ? "bg-green-500/5 border border-green-500/10" :
                        entry.type === "approval_request" ? "bg-orange-500/5 border border-orange-500/10" :
                        entry.type === "exploit_success" ? "bg-red-500/5 border border-red-500/10" :
                        entry.type === "error" ? "bg-red-500/5 border border-red-500/10" :
                        entry.type === "llm_decision" ? "bg-cyan-500/5 border border-cyan-500/10" :
                        entry.type === "tool_match" ? "bg-purple-500/5 border border-purple-500/10" :
                        entry.type === "credential_test" ? "bg-yellow-500/5 border border-yellow-500/10" :
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
                        {entry.data && entry.type === "tool_match" && entry.data.tools && (
                          <div className="flex flex-wrap gap-1 mt-1">
                            {(entry.data.tools as string[]).map((tool, i) => (
                              <Badge key={i} variant="outline" className="text-[9px] text-purple-400 border-purple-500/30">{tool}</Badge>
                            ))}
                          </div>
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
                    {(!ops || !ops.assets || ops.assets.length === 0) && (
                      <div className="text-center py-10">
                        <p className="text-sm text-muted-foreground">No assets discovered yet</p>
                        <p className="text-xs text-muted-foreground mt-1">Add targets and run passive discovery</p>
                      </div>
                    )}
                    {(ops?.assets || []).map(asset => (
                      <button
                        key={asset.hostname}
                        onClick={() => setSelectedAsset(asset.hostname)}
                        className={`w-full text-left px-3 py-2.5 rounded-md transition-colors ${
                          selectedAsset === asset.hostname ? "bg-primary/10 ring-1 ring-primary/30" : "hover:bg-muted/20"
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          {assetIcon(asset.type)}
                          <span className="text-sm font-medium text-foreground truncate">{asset.hostname}{asset.ip && asset.ip !== asset.hostname && <span className="text-muted-foreground text-xs ml-1">({asset.ip})</span>}</span>
                          {assetStatusBadge(asset.status)}
                        </div>
                        <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground flex-wrap">
                          <span>{(asset.ports || []).length} ports</span>
                          <span>{(asset.vulns || []).length} vulns</span>
                          {asset.toolResults?.length > 0 && <span className="text-emerald-400">{asset.toolResults.length} tools</span>}
                          {asset.passiveRecon && <span className="text-indigo-400">OSINT</span>}
                          {(asset.zapFindings || []).length > 0 && <span className="text-blue-400">{asset.zapFindings.length} ZAP</span>}
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
                        <h3 className="font-semibold text-foreground">{selectedAssetData.hostname}{selectedAssetData.ip && selectedAssetData.ip !== selectedAssetData.hostname && <span className="text-sm font-normal text-muted-foreground ml-2">({selectedAssetData.ip})</span>}</h3>
                        {assetStatusBadge(selectedAssetData.status)}
                      </div>
                      {selectedAssetData.wafDetected && (
                        <div className="flex items-center gap-2 text-xs text-orange-400 bg-orange-500/10 rounded px-2 py-1">
                          <ShieldAlert className="h-3.5 w-3.5" />
                          WAF Detected: {selectedAssetData.wafDetected}
                        </div>
                      )}

                      {/* Ports */}
                      {(selectedAssetData.ports || []).length > 0 && (
                        <div>
                          <h4 className="text-xs font-medium text-muted-foreground mb-1">Open Ports ({(selectedAssetData.ports || []).length})</h4>
                          <div className="space-y-0.5">
                            {(selectedAssetData.ports || []).map((p, i) => (
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
                      {(selectedAssetData.vulns || []).length > 0 && (
                        <div>
                          <h4 className="text-xs font-medium text-muted-foreground mb-1">Vulnerabilities ({(selectedAssetData.vulns || []).length})</h4>
                          <div className="space-y-0.5">
                            {(selectedAssetData.vulns || []).map((v, i) => (
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
                      {(selectedAssetData.zapFindings || []).length > 0 && (
                        <div>
                          <h4 className="text-xs font-medium text-muted-foreground mb-1">ZAP Web App Findings ({(selectedAssetData.zapFindings || []).length})</h4>
                          <div className="space-y-0.5">
                            {(selectedAssetData.zapFindings || []).map((f, i) => (
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

                      {/* Passive Recon */}
                      {selectedAssetData.passiveRecon && (
                        <div>
                          <h4 className="text-xs font-medium text-indigo-400 mb-2 flex items-center gap-1">
                            <Search className="h-3 w-3" /> Passive Recon (OSINT)
                          </h4>

                          {/* Technologies */}
                          {(selectedAssetData.passiveRecon?.technologies || []).length > 0 && (
                            <div className="mb-2">
                              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Tech Stack</span>
                              <div className="flex flex-wrap gap-1 mt-0.5">
                                {(selectedAssetData.passiveRecon?.technologies || []).map((t, i) => (
                                  <Badge key={i} variant="outline" className="text-[9px] text-indigo-300 border-indigo-500/30">{t}</Badge>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* OS Detection */}
                          {selectedAssetData.passiveRecon.osDetected && (
                            <div className="mb-2">
                              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">OS Detected</span>
                              <p className="text-xs text-foreground mt-0.5">{selectedAssetData.passiveRecon.osDetected}</p>
                            </div>
                          )}

                          {/* Services from passive recon */}
                          {(selectedAssetData.passiveRecon?.services || []).length > 0 && (
                            <div className="mb-2">
                              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Passive Services ({(selectedAssetData.passiveRecon?.services || []).length})</span>
                              <div className="space-y-0.5 mt-0.5">
                                {(selectedAssetData.passiveRecon?.services || []).slice(0, 10).map((s, i) => (
                                  <div key={i} className="flex items-center gap-2 text-[10px] px-2 py-0.5 bg-indigo-500/5 rounded">
                                    <span className="font-mono text-indigo-400 w-10">{s.port}</span>
                                    <span className="text-foreground">{s.service}</span>
                                    {s.product && <span className="text-muted-foreground">{s.product} {s.version || ''}</span>}
                                    <span className="text-muted-foreground/50 ml-auto">{s.source}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Certificates */}
                          {(selectedAssetData.passiveRecon?.certificates || []).length > 0 && (
                            <div className="mb-2">
                              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Certificates ({(selectedAssetData.passiveRecon?.certificates || []).length})</span>
                              <div className="space-y-0.5 mt-0.5">
                                {(selectedAssetData.passiveRecon?.certificates || []).slice(0, 5).map((c, i) => (
                                  <div key={i} className="text-[10px] px-2 py-0.5 bg-indigo-500/5 rounded">
                                    <span className="text-foreground">{c.subject}</span>
                                    <span className="text-muted-foreground"> — {c.issuer}</span>
                                    {c.expiry && <span className="text-muted-foreground/50"> (exp: {c.expiry})</span>}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Subdomains */}
                          {(selectedAssetData.passiveRecon?.subdomains || []).length > 0 && (
                            <div className="mb-2">
                              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Subdomains ({(selectedAssetData.passiveRecon?.subdomains || []).length})</span>
                              <div className="flex flex-wrap gap-1 mt-0.5">
                                {(selectedAssetData.passiveRecon?.subdomains || []).slice(0, 20).map((s, i) => (
                                  <Badge key={i} variant="outline" className="text-[9px] text-cyan-300 border-cyan-500/30 font-mono">{s}</Badge>
                                ))}
                                {(selectedAssetData.passiveRecon?.subdomains || []).length > 20 && (
                                  <Badge variant="outline" className="text-[9px] text-muted-foreground">+{(selectedAssetData.passiveRecon?.subdomains || []).length - 20} more</Badge>
                                )}
                              </div>
                            </div>
                          )}

                          {/* Risk Signals */}
                          {(selectedAssetData.passiveRecon?.riskSignals || []).length > 0 && (
                            <div className="mb-2">
                              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Risk Signals ({(selectedAssetData.passiveRecon?.riskSignals || []).length})</span>
                              <div className="space-y-0.5 mt-0.5">
                                {(selectedAssetData.passiveRecon?.riskSignals || []).map((r, i) => (
                                  <div key={i} className="flex items-center gap-2 text-[10px] px-2 py-0.5 bg-red-500/5 rounded">
                                    <Badge variant="outline" className={`text-[8px] ${
                                      r.severity === 'critical' ? 'text-red-400 border-red-500/30' :
                                      r.severity === 'high' ? 'text-orange-400 border-orange-500/30' :
                                      r.severity === 'medium' ? 'text-yellow-400 border-yellow-500/30' :
                                      'text-blue-400 border-blue-500/30'
                                    }`}>{r.severity}</Badge>
                                    <span className="text-foreground">{r.signal}</span>
                                    <span className="text-muted-foreground/50 ml-auto">{r.source}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Tool Results */}
                      {selectedAssetData.toolResults?.length > 0 && (
                        <div>
                          <h4 className="text-xs font-medium text-emerald-400 mb-2 flex items-center gap-1">
                            <Terminal className="h-3 w-3" /> Tool Results ({(selectedAssetData.toolResults || []).length})
                          </h4>
                          <div className="space-y-2">
                            {(selectedAssetData.toolResults || []).map((tr, i) => (
                              <div key={i} className="border border-border/20 rounded-md p-2 bg-muted/5">
                                <div className="flex items-center gap-2 mb-1">
                                  <Badge variant="outline" className="text-[9px] text-emerald-300 border-emerald-500/30">{tr.tool}</Badge>
                                  <Badge variant="outline" className={`text-[8px] ${
                                    tr.phase === 'discovery' ? 'text-blue-300 border-blue-500/30' :
                                    tr.phase === 'targeted_enum' ? 'text-cyan-300 border-cyan-500/30' :
                                    tr.phase === 'vuln_detection' ? 'text-yellow-300 border-yellow-500/30' :
                                    tr.phase === 'credential_testing' ? 'text-orange-300 border-orange-500/30' :
                                    'text-muted-foreground border-border/30'
                                  }`}>{tr.phase.replace(/_/g, ' ')}</Badge>
                                  <span className={`text-[9px] ${tr.exitCode === 0 ? 'text-green-400' : 'text-red-400'}`}>
                                    exit:{tr.exitCode}
                                  </span>
                                  <span className="text-[9px] text-muted-foreground">{Math.round(tr.durationMs / 1000)}s</span>
                                  {tr.timedOut && <Badge variant="outline" className="text-[8px] text-red-400 border-red-500/30">TIMEOUT</Badge>}
                                  <span className="text-[9px] text-muted-foreground ml-auto">{new Date(tr.executedAt).toLocaleTimeString()}</span>
                                </div>
                                <p className="text-[10px] text-muted-foreground font-mono truncate mb-1" title={tr.command}>{tr.command}</p>
                               {(tr.findings || []).length > 0 && (
                                   <div className="space-y-0.5">
                                     {(tr.findings || []).slice(0, 8).map((f, fi) => (
                                      <div key={fi} className="flex items-center gap-1 text-[10px]">
                                        <Badge variant="outline" className={`text-[7px] px-1 ${
                                          f.severity === 'critical' ? 'text-red-400 border-red-500/30' :
                                          f.severity === 'high' ? 'text-orange-400 border-orange-500/30' :
                                          f.severity === 'medium' ? 'text-yellow-400 border-yellow-500/30' :
                                          'text-blue-400 border-blue-500/30'
                                        }`}>{f.severity}</Badge>
                                        <span className="text-foreground truncate">{f.title}</span>
                                        {f.cve && <span className="text-muted-foreground font-mono">{f.cve}</span>}
                                      </div>
                                    ))}
{(tr.findings || []).length > 8 && (
                                       <p className="text-[9px] text-muted-foreground">+{(tr.findings || []).length - 8} more findings</p>
                                    )}
                                  </div>
                                )}
                                {(tr.findings || []).length === 0 && tr.outputPreview && (
                                  <pre className="text-[9px] text-muted-foreground/70 font-mono whitespace-pre-wrap max-h-20 overflow-hidden">{tr.outputPreview.slice(0, 300)}</pre>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Exploit Attempts */}
                      {(selectedAssetData.exploitAttempts || []).length > 0 && (
                        <div>
                          <h4 className="text-xs font-medium text-muted-foreground mb-1">Exploit Attempts ({(selectedAssetData.exploitAttempts || []).length})</h4>
                          <div className="space-y-0.5">
                            {(selectedAssetData.exploitAttempts || []).map((e, i) => (
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

            {/* ── Discovery Results Tab ── */}
            <TabsContent value="discovery" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="py-3 space-y-4">
                  <p className="text-xs text-muted-foreground">Aggregated discovery results from naabu, nmap, and httpx across all assets. Click any row to view the full asset detail.</p>
                  {(() => {
                    const assets = ops?.assets || [];
                    const allToolResults = assets.flatMap((a: any) => (a.toolResults || []).map((tr: any) => ({ ...tr, assetHostname: a.hostname })));
                    const nmapResults = allToolResults.filter((tr: any) => tr.tool === 'nmap' || tr.tool === 'nmap-discovery');
                    const nucleiResults = allToolResults.filter((tr: any) => tr.tool === 'nuclei');
                    const httpxResults = allToolResults.filter((tr: any) => tr.tool === 'httpx');

                    // Aggregate ports across all assets
                    const portMap = new Map<number, { count: number; services: Set<string>; assets: Set<string> }>();
                    for (const a of assets) {
                      for (const p of (a.knownPorts || [])) {
                        const port = typeof p === 'number' ? p : (p.port || 0);
                        const svc = typeof p === 'object' ? (p.service || 'unknown') : 'unknown';
                        if (!portMap.has(port)) portMap.set(port, { count: 0, services: new Set(), assets: new Set() });
                        const entry = portMap.get(port)!;
                        entry.count++;
                        entry.services.add(svc);
                        entry.assets.add(a.hostname);
                      }
                    }
                    const sortedPorts = Array.from(portMap.entries()).sort((a, b) => b[1].count - a[1].count);

                    // Aggregate technologies from httpx and passive recon
                    const techMap = new Map<string, { count: number; assets: Set<string> }>();
                    for (const a of assets) {
                      const techs: string[] = [];
                      // From passive recon
                      if (a.passiveRecon?.technologies) techs.push(...a.passiveRecon.technologies);
                      // From httpx tool results
                      for (const tr of (a.toolResults || [])) {
                        if (tr.tool === 'httpx' && tr.findings) {
                          for (const f of tr.findings) {
                            const fStr = typeof f === 'string' ? f : (f?.title || '');
                            if (fStr.includes('Tech:') || fStr.includes('tech:') || fStr.includes('Technology:')) {
                              const t = fStr.replace(/^.*[Tt]ech(nology)?:\s*/, '').trim();
                              if (t) techs.push(t);
                            }
                          }
                        }
                      }
                      for (const t of techs) {
                        if (!techMap.has(t)) techMap.set(t, { count: 0, assets: new Set() });
                        const entry = techMap.get(t)!;
                        entry.count++;
                        entry.assets.add(a.hostname);
                      }
                    }
                    const sortedTech = Array.from(techMap.entries()).sort((a, b) => b[1].count - a[1].count);

                    // Aggregate services
                    const serviceMap = new Map<string, { count: number; ports: Set<number>; assets: Set<string> }>();
                    for (const a of assets) {
                      for (const p of (a.knownPorts || [])) {
                        if (typeof p === 'object' && p.service) {
                          if (!serviceMap.has(p.service)) serviceMap.set(p.service, { count: 0, ports: new Set(), assets: new Set() });
                          const entry = serviceMap.get(p.service)!;
                          entry.count++;
                          entry.ports.add(p.port || 0);
                          entry.assets.add(a.hostname);
                        }
                      }
                      // Also from passive recon services
                      for (const svc of (a.passiveRecon?.services || [])) {
                        const name = svc.service || svc.name || 'unknown';
                        if (!serviceMap.has(name)) serviceMap.set(name, { count: 0, ports: new Set(), assets: new Set() });
                        const entry = serviceMap.get(name)!;
                        entry.count++;
                        if (svc.port) entry.ports.add(svc.port);
                        entry.assets.add(a.hostname);
                      }
                    }
                    const sortedServices = Array.from(serviceMap.entries()).sort((a, b) => b[1].count - a[1].count);

                    // CDN/WAF detection
                    const cdnWafMap = new Map<string, Set<string>>();
                    for (const a of assets) {
                      for (const tr of (a.toolResults || [])) {
                        if (tr.tool === 'httpx' && tr.findings) {
                          for (const f of tr.findings) {
                            const fStr = typeof f === 'string' ? f : (f?.title || '');
                            if (fStr.includes('CDN:') || fStr.includes('WAF:') || fStr.includes('cdn:') || fStr.includes('waf:') || fStr.includes('CDN/WAF:')) {
                              const val = fStr.replace(/^.*(?:[Cc][Dd][Nn]|[Ww][Aa][Ff]|CDN\/WAF):\s*/, '').trim();
                              if (val && val !== 'none' && val !== 'unknown') {
                                if (!cdnWafMap.has(val)) cdnWafMap.set(val, new Set());
                                cdnWafMap.get(val)!.add(a.hostname);
                              }
                            }
                          }
                        }
                      }
                    }

                    // TLS versions
                    const tlsMap = new Map<string, Set<string>>();
                    for (const a of assets) {
                      if (a.passiveRecon?.certificates) {
                        for (const cert of a.passiveRecon.certificates) {
                          const ver = cert.version || cert.protocol || 'TLS';
                          if (!tlsMap.has(ver)) tlsMap.set(ver, new Set());
                          tlsMap.get(ver)!.add(a.hostname);
                        }
                      }
                    }

                    const totalPorts = sortedPorts.length;
                    const totalServices = sortedServices.length;
                    const totalTech = sortedTech.length;
                    const totalToolRuns = allToolResults.length;

                    if (totalToolRuns === 0 && assets.every((a: any) => !a.passiveRecon)) {
                      return (
                        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                          <Radar className="h-12 w-12 mb-4 opacity-20" />
                          <p className="text-sm">No discovery results yet</p>
                          <p className="text-xs mt-1">Run a passive or active scan to populate discovery data</p>
                        </div>
                      );
                    }

                    return (
                      <>
                        {/* Summary Stats */}
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                          <Card className="bg-card/50">
                            <CardContent className="p-3 text-center">
                              <div className="text-2xl font-bold text-cyan-400">{totalPorts}</div>
                              <div className="text-[10px] text-muted-foreground">Unique Ports</div>
                            </CardContent>
                          </Card>
                          <Card className="bg-card/50">
                            <CardContent className="p-3 text-center">
                              <div className="text-2xl font-bold text-blue-400">{totalServices}</div>
                              <div className="text-[10px] text-muted-foreground">Unique Services</div>
                            </CardContent>
                          </Card>
                          <Card className="bg-card/50">
                            <CardContent className="p-3 text-center">
                              <div className="text-2xl font-bold text-purple-400">{totalTech}</div>
                              <div className="text-[10px] text-muted-foreground">Technologies</div>
                            </CardContent>
                          </Card>
                          <Card className="bg-card/50">
                            <CardContent className="p-3 text-center">
                              <div className="text-2xl font-bold text-green-400">{totalToolRuns}</div>
                              <div className="text-[10px] text-muted-foreground">Tool Runs</div>
                            </CardContent>
                          </Card>
                        </div>

                        {/* Tool Run Summary */}
                        <div className="grid grid-cols-3 gap-3">
                          <Card className="bg-card/50 border-red-500/20">
                            <CardContent className="p-3">
                              <div className="flex items-center gap-2 mb-2">
                                <Bug className="h-4 w-4 text-red-400" />
                                <span className="text-xs font-medium">Nuclei</span>
                                <Badge variant="secondary" className="ml-auto text-[9px] h-4">{nucleiResults.length} runs</Badge>
                              </div>
                              <p className="text-[10px] text-muted-foreground">Vulnerability scanning with 9800+ templates</p>
                            </CardContent>
                          </Card>
                          <Card className="bg-card/50 border-blue-500/20">
                            <CardContent className="p-3">
                              <div className="flex items-center gap-2 mb-2">
                                <Search className="h-4 w-4 text-blue-400" />
                                <span className="text-xs font-medium">Nmap</span>
                                <Badge variant="secondary" className="ml-auto text-[9px] h-4">{nmapResults.length} runs</Badge>
                              </div>
                              <p className="text-[10px] text-muted-foreground">Service fingerprinting & OS detection</p>
                            </CardContent>
                          </Card>
                          <Card className="bg-card/50 border-purple-500/20">
                            <CardContent className="p-3">
                              <div className="flex items-center gap-2 mb-2">
                                <Globe className="h-4 w-4 text-purple-400" />
                                <span className="text-xs font-medium">Httpx</span>
                                <Badge variant="secondary" className="ml-auto text-[9px] h-4">{httpxResults.length} runs</Badge>
                              </div>
                              <p className="text-[10px] text-muted-foreground">
                                {httpxResults.reduce((sum: number, tr: any) => sum + (tr.findings?.length || tr.findingCount || 0), 0)} findings &mdash; HTTP probing, tech & CDN/WAF
                              </p>
                            </CardContent>
                          </Card>
                        </div>

                        {/* Port Frequency Heat Map */}
                        {sortedPorts.length > 0 && (
                          <Card className="bg-card/50">
                            <CardHeader className="pb-2 pt-3 px-4">
                              <CardTitle className="text-sm flex items-center gap-2">
                                <Network className="h-4 w-4 text-cyan-400" /> Port Frequency Map
                              </CardTitle>
                              <CardDescription className="text-[10px]">Most common open ports across all assets — darker = more prevalent</CardDescription>
                            </CardHeader>
                            <CardContent className="px-4 pb-3">
                              <div className="flex flex-wrap gap-1.5">
                                {sortedPorts.slice(0, 40).map(([port, data]) => {
                                  const maxCount = sortedPorts[0]?.[1]?.count || 1;
                                  const intensity = Math.max(0.2, data.count / maxCount);
                                  return (
                                    <div
                                      key={port}
                                      className="rounded px-2 py-1 text-[10px] font-mono cursor-default border border-cyan-500/20"
                                      style={{ backgroundColor: `rgba(34, 211, 238, ${intensity * 0.3})`, color: intensity > 0.5 ? '#22d3ee' : '#94a3b8' }}
                                      title={`Port ${port}: ${Array.from(data.services).join(', ')} — ${data.count} asset(s): ${Array.from(data.assets).join(', ')}`}
                                    >
                                      {port}
                                      <span className="ml-1 opacity-60">({data.count})</span>
                                    </div>
                                  );
                                })}
                              </div>
                              {sortedPorts.length > 40 && <p className="text-[10px] text-muted-foreground mt-2">+{sortedPorts.length - 40} more ports</p>}
                            </CardContent>
                          </Card>
                        )}

                        {/* Service Distribution */}
                        {sortedServices.length > 0 && (
                          <Card className="bg-card/50">
                            <CardHeader className="pb-2 pt-3 px-4">
                              <CardTitle className="text-sm flex items-center gap-2">
                                <Server className="h-4 w-4 text-blue-400" /> Service Distribution
                              </CardTitle>
                              <CardDescription className="text-[10px]">Services detected across all assets with associated ports</CardDescription>
                            </CardHeader>
                            <CardContent className="px-4 pb-3">
                              <div className="space-y-1.5">
                                {sortedServices.slice(0, 20).map(([svc, data]) => {
                                  const maxCount = sortedServices[0]?.[1]?.count || 1;
                                  const pct = Math.round((data.count / maxCount) * 100);
                                  return (
                                    <div key={svc} className="flex items-center gap-2">
                                      <span className="text-[10px] font-mono w-24 truncate text-blue-300" title={svc}>{svc}</span>
                                      <div className="flex-1 h-4 bg-muted/30 rounded overflow-hidden">
                                        <div className="h-full bg-blue-500/40 rounded" style={{ width: `${pct}%` }} />
                                      </div>
                                      <span className="text-[10px] text-muted-foreground w-8 text-right">{data.count}</span>
                                      <span className="text-[9px] text-muted-foreground/60 w-20 truncate" title={Array.from(data.ports).sort((a,b) => a-b).join(', ')}>:{Array.from(data.ports).sort((a,b) => a-b).join(', ')}</span>
                                    </div>
                                  );
                                })}
                              </div>
                            </CardContent>
                          </Card>
                        )}

                        {/* Technology Stack Heat Map */}
                        {sortedTech.length > 0 && (
                          <Card className="bg-card/50">
                            <CardHeader className="pb-2 pt-3 px-4">
                              <CardTitle className="text-sm flex items-center gap-2">
                                <MonitorSmartphone className="h-4 w-4 text-purple-400" /> Technology Stack
                              </CardTitle>
                              <CardDescription className="text-[10px]">Technologies detected via httpx probing and passive reconnaissance</CardDescription>
                            </CardHeader>
                            <CardContent className="px-4 pb-3">
                              <div className="flex flex-wrap gap-1.5">
                                {sortedTech.slice(0, 30).map(([tech, data]) => {
                                  const maxCount = sortedTech[0]?.[1]?.count || 1;
                                  const intensity = Math.max(0.2, data.count / maxCount);
                                  return (
                                    <div
                                      key={tech}
                                      className="rounded-full px-2.5 py-0.5 text-[10px] border border-purple-500/20 cursor-default"
                                      style={{ backgroundColor: `rgba(168, 85, 247, ${intensity * 0.25})`, color: intensity > 0.5 ? '#c084fc' : '#94a3b8' }}
                                      title={`${tech}: ${data.count} asset(s) — ${Array.from(data.assets).join(', ')}`}
                                    >
                                      {tech}
                                      <span className="ml-1 opacity-60">({data.count})</span>
                                    </div>
                                  );
                                })}
                              </div>
                              {sortedTech.length > 30 && <p className="text-[10px] text-muted-foreground mt-2">+{sortedTech.length - 30} more technologies</p>}
                            </CardContent>
                          </Card>
                        )}

                        {/* CDN/WAF and TLS side by side */}
                        <div className="grid grid-cols-2 gap-3">
                          {cdnWafMap.size > 0 && (
                            <Card className="bg-card/50">
                              <CardHeader className="pb-2 pt-3 px-4">
                                <CardTitle className="text-sm flex items-center gap-2">
                                  <Shield className="h-4 w-4 text-amber-400" /> CDN / WAF Detection
                                </CardTitle>
                              </CardHeader>
                              <CardContent className="px-4 pb-3">
                                <div className="space-y-1.5">
                                  {Array.from(cdnWafMap.entries()).map(([name, assetSet]) => (
                                    <div key={name} className="flex items-center justify-between">
                                      <span className="text-[10px] font-medium text-amber-300">{name}</span>
                                      <Badge variant="secondary" className="text-[9px] h-4">{assetSet.size} asset{assetSet.size > 1 ? 's' : ''}</Badge>
                                    </div>
                                  ))}
                                </div>
                              </CardContent>
                            </Card>
                          )}
                          {tlsMap.size > 0 && (
                            <Card className="bg-card/50">
                              <CardHeader className="pb-2 pt-3 px-4">
                                <CardTitle className="text-sm flex items-center gap-2">
                                  <Lock className="h-4 w-4 text-green-400" /> TLS Versions
                                </CardTitle>
                              </CardHeader>
                              <CardContent className="px-4 pb-3">
                                <div className="space-y-1.5">
                                  {Array.from(tlsMap.entries()).map(([ver, assetSet]) => (
                                    <div key={ver} className="flex items-center justify-between">
                                      <span className="text-[10px] font-medium text-green-300">{ver}</span>
                                      <Badge variant="secondary" className="text-[9px] h-4">{assetSet.size} asset{assetSet.size > 1 ? 's' : ''}</Badge>
                                    </div>
                                  ))}
                                </div>
                              </CardContent>
                            </Card>
                          )}
                        </div>

                        {/* Per-Asset Discovery Summary */}
                        <Card className="bg-card/50">
                          <CardHeader className="pb-2 pt-3 px-4">
                            <CardTitle className="text-sm flex items-center gap-2">
                              <Target className="h-4 w-4 text-orange-400" /> Per-Asset Discovery Summary
                            </CardTitle>
                            <CardDescription className="text-[10px]">Click any row to view full asset details in the Assets tab</CardDescription>
                          </CardHeader>
                          <CardContent className="px-4 pb-3">
                            <div className="overflow-x-auto">
                              <table className="w-full text-[10px]">
                                <thead>
                                  <tr className="border-b border-border/30">
                                    <th className="text-left py-1.5 px-2 font-medium text-muted-foreground">Asset</th>
                                    <th className="text-center py-1.5 px-2 font-medium text-muted-foreground">Ports</th>
                                    <th className="text-center py-1.5 px-2 font-medium text-muted-foreground">Services</th>
                                    <th className="text-center py-1.5 px-2 font-medium text-muted-foreground">Tech</th>
                                    <th className="text-center py-1.5 px-2 font-medium text-muted-foreground">Tools Run</th>
                                    <th className="text-center py-1.5 px-2 font-medium text-muted-foreground">Findings</th>
                                    <th className="text-left py-1.5 px-2 font-medium text-muted-foreground">Status</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {assets.map((a: any, i: number) => {
                                    const ports = (a.knownPorts || []).length;
                                    const svcs = new Set((a.knownPorts || []).filter((p: any) => typeof p === 'object' && p.service).map((p: any) => p.service)).size;
                                    const tech = (a.passiveRecon?.technologies || []).length;
                                    const tools = (a.toolResults || []).length;
                                    const findings = (a.toolResults || []).reduce((sum: number, tr: any) => sum + (tr.findings?.length || 0), 0);
                                    return (
                                      <tr
                                        key={i}
                                        className="border-b border-border/10 hover:bg-muted/20 cursor-pointer transition-colors"
                                        onClick={() => { setActiveTab('assets'); setSelectedAsset(a.hostname); }}
                                      >
                                        <td className="py-1.5 px-2 font-mono text-foreground">{a.hostname}{a.ip && a.ip !== a.hostname && <span className="text-muted-foreground ml-1">({a.ip})</span>}</td>
                                        <td className="py-1.5 px-2 text-center">
                                          <span className={ports > 0 ? 'text-cyan-400' : 'text-muted-foreground'}>{ports}</span>
                                        </td>
                                        <td className="py-1.5 px-2 text-center">
                                          <span className={svcs > 0 ? 'text-blue-400' : 'text-muted-foreground'}>{svcs}</span>
                                        </td>
                                        <td className="py-1.5 px-2 text-center">
                                          <span className={tech > 0 ? 'text-purple-400' : 'text-muted-foreground'}>{tech}</span>
                                        </td>
                                        <td className="py-1.5 px-2 text-center">
                                          <span className={tools > 0 ? 'text-green-400' : 'text-muted-foreground'}>{tools}</span>
                                        </td>
                                        <td className="py-1.5 px-2 text-center">
                                          <span className={findings > 0 ? 'text-red-400 font-medium' : 'text-muted-foreground'}>{findings}</span>
                                        </td>
                                        <td className="py-1.5 px-2">
                                          <Badge variant="secondary" className={`text-[8px] h-3.5 ${
                                            a.status === 'compromised' ? 'bg-red-500/20 text-red-400' :
                                            a.status === 'vulnerable' ? 'bg-amber-500/20 text-amber-400' :
                                            a.status === 'scanned' ? 'bg-blue-500/20 text-blue-400' :
                                            a.status === 'discovered' ? 'bg-green-500/20 text-green-400' :
                                            'bg-muted/50 text-muted-foreground'
                                          }`}>{a.status}</Badge>
                                        </td>
                                      </tr>
                                    );
                                  })}
                                </tbody>
                              </table>
                            </div>
                          </CardContent>
                        </Card>

                        {/* All Tool Execution Log */}
                        <Card className="bg-card/50">
                          <CardHeader className="pb-2 pt-3 px-4">
                            <CardTitle className="text-sm flex items-center gap-2">
                              <Terminal className="h-4 w-4 text-green-400" /> Tool Execution Log
                            </CardTitle>
                            <CardDescription className="text-[10px]">All tool runs across all assets with commands and results</CardDescription>
                          </CardHeader>
                          <CardContent className="px-4 pb-3">
                            <div className="space-y-2 max-h-80 overflow-y-auto">
                              {allToolResults.length === 0 ? (
                                <p className="text-[10px] text-muted-foreground py-4 text-center">No tool executions recorded yet</p>
                              ) : (
                                allToolResults.slice(0, 50).map((tr: any, i: number) => (
                                  <div key={i} className="border border-border/20 rounded p-2 space-y-1">
                                    <div className="flex items-center gap-2">
                                      <Badge variant="secondary" className={`text-[8px] h-3.5 ${
                                        tr.tool === 'nmap' || tr.tool === 'nmap-discovery' ? 'bg-blue-500/20 text-blue-400' :
                                        tr.tool === 'naabu' ? 'bg-cyan-500/20 text-cyan-400' :
                                        tr.tool === 'httpx' ? 'bg-purple-500/20 text-purple-400' :
                                        tr.tool === 'nuclei' ? 'bg-red-500/20 text-red-400' :
                                        'bg-muted/50 text-muted-foreground'
                                      }`}>{tr.tool}</Badge>
                                      <span className="text-[10px] font-mono text-muted-foreground">{tr.assetHostname}</span>
                                      <span className="ml-auto text-[9px] text-muted-foreground">
                                        {tr.exitCode === 0 ? <CheckCircle2 className="h-3 w-3 text-green-400 inline" /> : <XCircle className="h-3 w-3 text-red-400 inline" />}
                                        {tr.duration ? ` ${tr.duration}` : ''}
                                      </span>
                                    </div>
                                    {tr.command && (
                                      <div className="bg-black/30 rounded px-2 py-1 font-mono text-[9px] text-green-300/80 overflow-x-auto whitespace-nowrap">
                                        $ {tr.command}
                                      </div>
                                    )}
                                    {tr.findings && (tr.findings || []).length > 0 && (
                                      <div className="space-y-0.5">
                                        {(tr.findings || []).slice(0, 5).map((f: any, fi: number) => {
                                          const fStr = typeof f === 'string' ? f : (f?.title || JSON.stringify(f));
                                          return (
                                            <div key={fi} className="text-[9px] text-amber-300/80 flex items-start gap-1">
                                              <Zap className="h-2.5 w-2.5 mt-0.5 shrink-0" />
                                              <span className="break-all">{fStr}</span>
                                            </div>
                                          );
                                        })}
                                        {(tr.findings || []).length > 5 && <p className="text-[9px] text-muted-foreground">+{(tr.findings || []).length - 5} more findings</p>}
                                      </div>
                                    )}
                                  </div>
                                ))
                              )}
                              {allToolResults.length > 50 && <p className="text-[10px] text-muted-foreground text-center">Showing 50 of {allToolResults.length} tool runs</p>}
                            </div>
                          </CardContent>
                        </Card>
                      </>
                    );
                  })()}
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ── Exploit Match Tab ── */}
            <TabsContent value="exploits" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="py-3 space-y-3">
                  {(!exploitsQ.data || !exploitsQ.data.exploits || exploitsQ.data.exploits.length === 0) ? (
                    <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                      <Swords className="h-12 w-12 mb-4 opacity-20" />
                      <p className="text-sm">No exploit matches yet</p>
                      <p className="text-xs mt-1">Exploit matching activates when vulnerabilities are discovered during active scanning</p>
                    </div>
                  ) : (
                    <>
                      <div className="flex items-center justify-between">
                        <h3 className="text-sm font-medium text-foreground">
                          {(exploitsQ.data?.exploits || []).length} Exploit Matches for {exploitsQ.data?.totalVulns || 0} Vulnerabilities
                        </h3>
                        <Badge variant="outline" className="text-[10px] text-muted-foreground">
                          MSF + ZAP + Exploitation Bridge
                        </Badge>
                      </div>
                      {(exploitsQ.data?.exploits || []).map((match: any, idx: number) => (
                        <Card key={idx} className="bg-card/50 border-border/30">
                          <CardContent className="p-4">
                            <div className="flex items-center gap-2 mb-2">
                              <Badge variant="outline" className={`text-[9px] ${
                                match.severity === "critical" ? "text-red-400 border-red-500/30" :
                                match.severity === "high" ? "text-orange-400 border-orange-500/30" :
                                "text-yellow-400 border-yellow-500/30"
                              }`}>{match.severity}</Badge>
                              <span className="text-sm font-medium text-foreground">{match.vuln}</span>
                              {match.cve && <span className="text-xs font-mono text-muted-foreground">{match.cve}</span>}
                            </div>
                            <p className="text-xs text-muted-foreground mb-2">Target: {match.asset}</p>

                            {/* Exploitation Bridge Modules (preferred source) */}
                            {match.exploitBridgeModules && match.exploitBridgeModules.length > 0 && (
                              <div className="mb-2">
                                <h5 className="text-[10px] font-medium text-purple-400 uppercase tracking-wider mb-1 flex items-center gap-1">
                                  <Swords className="h-3 w-3" /> Exploitation Bridge Modules
                                </h5>
                                <div className="space-y-0.5">
                                  {match.exploitBridgeModules.map((mod: string, i: number) => (
                                    <div key={i} className="flex items-center gap-2 text-xs px-2 py-1 bg-purple-500/5 rounded border border-purple-500/10">
                                      <Skull className="h-3 w-3 text-purple-400" />
                                      <span className="font-mono text-foreground">{mod}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {(match.msfModules || []).length > 0 && (
                              <div className="mb-2">
                                <h5 className="text-[10px] font-medium text-red-400 uppercase tracking-wider mb-1 flex items-center gap-1">
                                  <Skull className="h-3 w-3" /> Metasploit Modules
                                </h5>
                                <div className="space-y-0.5">
                                  {(match.msfModules || []).map((mod: string, i: number) => (
                                    <div key={i} className="flex items-center gap-2 text-xs px-2 py-1 bg-red-500/5 rounded border border-red-500/10">
                                      <Skull className="h-3 w-3 text-red-400" />
                                      <span className="font-mono text-foreground">{mod}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {(match.zapRules || []).length > 0 && (
                              <div>
                                <h5 className="text-[10px] font-medium text-blue-400 uppercase tracking-wider mb-1 flex items-center gap-1">
                                  <Globe className="h-3 w-3" /> ZAP Active Scan Rules
                                </h5>
                                <div className="flex flex-wrap gap-1">
                                  {(match.zapRules || []).map((rule: string, i: number) => (
                                    <Badge key={i} variant="outline" className="text-[9px] text-blue-400 border-blue-500/30">{rule}</Badge>
                                  ))}
                                </div>
                              </div>
                            )}
                          </CardContent>
                        </Card>
                      ))}
                    </>
                  )}
                </div>
              </ScrollArea>
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
                          {!engagement?.targetDomain && !engagement?.targetIpRange && (
                            <p className="text-xs text-muted-foreground">No targets defined yet. Use "Add Targets" to paste in-scope assets.</p>
                          )}
                        </div>
                      </div>

                      {!roeSigned && (
                        <div className="bg-orange-500/10 border border-orange-500/20 rounded-lg px-4 py-3">
                          <div className="flex items-center gap-2 text-orange-400 text-sm font-medium">
                            <AlertTriangle className="h-4 w-4" />
                            RoE Must Be Signed
                          </div>
                          <p className="text-xs text-muted-foreground mt-1">
                            Active operations (enumeration, exploitation, C2 deployment) are blocked until the Rules of Engagement are signed. Only passive recon is allowed.
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
                        {(ops?.log || []).filter(l => l.type === "approval_request" || l.type === "approval_response").map(entry => (
                          <div key={entry.id} className="flex items-center gap-2 text-xs px-2 py-1.5 bg-muted/10 rounded">
                            {logIcon(entry.type)}
                            <span className="text-foreground">{entry.title}</span>
                            <span className="text-muted-foreground ml-auto">{formatTime(entry.timestamp)}</span>
                          </div>
                        ))}
                        {(!ops || !(ops.log || []).filter(l => l.type === "approval_request" || l.type === "approval_response").length) && (
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
            <StatCard icon={<Globe className="h-4 w-4 text-emerald-400" />} label="Assets Discovered" value={ops?.assets?.length || 0} />
            <StatCard icon={<Server className="h-4 w-4 text-cyan-400" />} label="Hosts Scanned" value={ops?.stats?.hostsScanned || 0} />
            <StatCard icon={<Activity className="h-4 w-4 text-blue-400" />} label="Open Ports" value={ops?.stats?.portsFound || 0} />
            <StatCard icon={<Bug className="h-4 w-4 text-yellow-400" />} label="Vulns Found" value={ops?.stats?.vulnsFound || 0} />
            <StatCard icon={<Globe className="h-4 w-4 text-blue-400" />} label="ZAP Scans" value={ops?.stats?.zapScansRun || 0} />
            <StatCard icon={<ShieldAlert className="h-4 w-4 text-orange-400" />} label="WAFs Detected" value={ops?.stats?.wafDetections || 0} />
            <StatCard icon={<Crosshair className="h-4 w-4 text-red-400" />} label="Exploits Tried" value={ops?.stats?.exploitsAttempted || 0} />
            <StatCard icon={<Skull className="h-4 w-4 text-red-500" />} label="Exploits OK" value={ops?.stats?.exploitsSucceeded || 0} />
            <StatCard icon={<Terminal className="h-4 w-4 text-green-400" />} label="Sessions" value={ops?.stats?.sessionsOpened || 0} />
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
          {ops && (ops.approvalGates || []).length > 0 && (
            <>
              <Separator />
              <div>
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Approvals</h3>
                <div className="space-y-1">
                  {(ops.approvalGates || []).map(gate => (
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
    </AppShell>
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
