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
import { useRoute, useLocation } from "wouter";
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
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
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
  Plus, Search, ArrowRight, Swords, RotateCcw, CircleDollarSign, Coins,
  Sparkles, ClipboardList, Key, KeyRound,
  Cloud, CloudOff, Brain, GitBranch, Layers, RefreshCw, Gauge,
  ExternalLink, ChevronDown, ChevronUp, Wrench, Timer,
  ScanEye, ShieldOff, Bolt,
} from "lucide-react";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";

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

function formatTokenCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

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
  const feedScrollRef = useRef<HTMLDivElement>(null);
  const [isAutoScroll, setIsAutoScroll] = useState(true);
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null);
  const [confirmStop, setConfirmStop] = useState(false);
  const [activeTab, setActiveTab] = useState("feed");
  const [selectedProfile, setSelectedProfile] = useState<'quick' | 'standard' | 'deep' | 'stealth'>('standard');
  const [showProfileDetails, setShowProfileDetails] = useState(false);

  // ── Target paste-in state ──
  const [targetInput, setTargetInput] = useState("");
  const [showTargetInput, setShowTargetInput] = useState(false);
  const [, navigate] = useLocation();
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);

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

  // Attack chains, cloud misconfigs, and feedback loop queries
  const attackChainsQ = trpc.engagementOps.getAttackChains.useQuery(
    { engagementId },
    { enabled: engagementId > 0 && (opsStateQ.data?.stats?.vulnsFound || 0) > 0, refetchInterval: isRunning ? 8000 : 30000 }
  );
  const cloudMisconfigsQ = trpc.engagementOps.getCloudMisconfigs.useQuery(
    { engagementId },
    { enabled: engagementId > 0, refetchInterval: isRunning ? 8000 : 30000 }
  );
  const feedbackLoopQ = trpc.engagementOps.getFeedbackLoopState.useQuery(
    { engagementId },
    { enabled: engagementId > 0, refetchInterval: isRunning ? 5000 : 30000 }
  );

  // LLM Cost tracking for this engagement
  const llmCostQ = trpc.llmTelemetry.engagementCost.useQuery(
    { engagementId },
    { enabled: engagementId > 0, refetchInterval: isRunning ? 10000 : 60000 }
  );
  const llmCostBreakdownQ = trpc.llmTelemetry.engagementCostBreakdown.useQuery(
    { engagementId },
    { enabled: engagementId > 0, refetchInterval: isRunning ? 10000 : 60000 }
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
  const [selectedScanMode, setSelectedScanMode] = useState<'strict_passive' | 'standard' | 'active'>(
    (engagement as any)?.scanMode || 'strict_passive'
  );
  const [showScanModePopover, setShowScanModePopover] = useState(false);

  // Sync scan mode from engagement data
  useEffect(() => {
    if ((engagement as any)?.scanMode) {
      setSelectedScanMode((engagement as any).scanMode);
    }
  }, [(engagement as any)?.scanMode]);

  const scanModesQ = trpc.engagementOps.getScanModes.useQuery(undefined, { enabled: engagementId > 0 });
  const updateScanModeMut = trpc.engagementOps.updateScanMode.useMutation({
    onSuccess: (data) => {
      toast.success(`Scan mode updated to ${data.scanMode.replace('_', ' ')}`);
      engagementQ.refetch();
    },
    onError: (e) => toast.error(e.message),
  });
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

  // ── Report generation ──
  const generateReportMut = trpc.reports.generate.useMutation({
    onSuccess: (data) => {
      setIsGeneratingReport(false);
      toast.success('Report generated! Opening report viewer...');
      navigate('/reports/generate');
    },
    onError: (e) => {
      setIsGeneratingReport(false);
      toast.error(`Report generation failed: ${e.message}`);
    },
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

    // LLM feedback loop progress — refetch feedback state and switch to feedback tab
    if (evtData.type === "action" && evtData.action === "llm_feedback_progress") {
      utils.engagementOps.getFeedbackLoopState.invalidate({ engagementId });
    }

    // LLM scan feedback started — auto-switch to feedback tab
    if (evtData.type === "action" && evtData.action === "llm_scan_feedback") {
      utils.engagementOps.getFeedbackLoopState.invalidate({ engagementId });
    }

    // Attack chain design complete — refetch attack chains
    if (evtData.type === "action" && evtData.action === "attack_chain_design") {
      utils.engagementOps.getAttackChains.invalidate({ engagementId });
    }

    // Cloud detection events — refetch cloud misconfigs
    if (evtData.type === "action" && (evtData.action === "cloud_detection" || evtData.action === "cloud_scan")) {
      utils.engagementOps.getCloudMisconfigs.invalidate({ engagementId });
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

  // Auto-scroll feed — scroll the viewport container, not the page
  useEffect(() => {
    if (!isAutoScroll || activeTab !== "feed") return;
    const viewport = feedScrollRef.current;
    if (viewport) {
      requestAnimationFrame(() => {
        viewport.scrollTop = viewport.scrollHeight;
      });
    }
  }, [ops?.log?.length, activeTab, isAutoScroll]);

  // Detect manual scroll-up to pause auto-scroll
  useEffect(() => {
    const viewport = feedScrollRef.current;
    if (!viewport) return;
    const handleScroll = () => {
      const atBottom = viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight < 60;
      setIsAutoScroll(atBottom);
    };
    viewport.addEventListener("scroll", handleScroll, { passive: true });
    return () => viewport.removeEventListener("scroll", handleScroll);
  }, []);

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

                {/* Step 2: Scan Mode Selector + Passive Discovery */}
                {canStartPassive && (
                  <div className="flex items-center gap-1.5">
                    {/* Scan Mode Selector */}
                    <Popover open={showScanModePopover} onOpenChange={setShowScanModePopover}>
                      <PopoverTrigger asChild>
                        <Button
                          size="sm"
                          variant="outline"
                          className={`border-border/50 text-xs gap-1.5 ${
                            selectedScanMode === 'strict_passive' ? 'text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/10' :
                            selectedScanMode === 'standard' ? 'text-blue-400 border-blue-500/30 hover:bg-blue-500/10' :
                            'text-orange-400 border-orange-500/30 hover:bg-orange-500/10'
                          }`}
                        >
                          {selectedScanMode === 'strict_passive' ? <Shield className="h-3.5 w-3.5" /> :
                           selectedScanMode === 'standard' ? <ScanEye className="h-3.5 w-3.5" /> :
                           <Bolt className="h-3.5 w-3.5" />}
                          {selectedScanMode === 'strict_passive' ? 'Strict Passive' :
                           selectedScanMode === 'standard' ? 'Standard' : 'Active'}
                          <ChevronDown className="h-3 w-3 opacity-50" />
                        </Button>
                      </PopoverTrigger>
                      <PopoverContent className="w-[420px] p-0" align="start" side="bottom">
                        <div className="p-3 border-b border-border/30">
                          <h4 className="text-sm font-semibold text-foreground">Scan Mode</h4>
                          <p className="text-xs text-muted-foreground mt-0.5">Controls which passive recon connectors are activated</p>
                        </div>
                        <RadioGroup
                          value={selectedScanMode}
                          onValueChange={(val) => {
                            const mode = val as 'strict_passive' | 'standard' | 'active';
                            setSelectedScanMode(mode);
                            updateScanModeMut.mutate({ engagementId, scanMode: mode });
                            setShowScanModePopover(false);
                          }}
                          className="p-2 gap-1"
                        >
                          {(scanModesQ.data?.modes || [
                            { value: 'strict_passive', label: 'Strict Passive', description: 'Only queries third-party databases. Zero target contact.', connectorCount: 23, techniques: [], restrictions: [] },
                            { value: 'standard', label: 'Standard', description: 'Passive + DNS resolution + registration lookups.', connectorCount: 28, techniques: [], restrictions: [] },
                            { value: 'active', label: 'Active', description: 'Full recon including direct target connections.', connectorCount: 31, techniques: [], restrictions: [] },
                          ]).map((mode) => {
                            const isSelected = selectedScanMode === mode.value;
                            const modeColors = {
                              strict_passive: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', text: 'text-emerald-400', ring: 'ring-emerald-500/20' },
                              standard: { bg: 'bg-blue-500/10', border: 'border-blue-500/30', text: 'text-blue-400', ring: 'ring-blue-500/20' },
                              active: { bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400', ring: 'ring-orange-500/20' },
                            };
                            const colors = modeColors[mode.value as keyof typeof modeColors];
                            const modeIcons = {
                              strict_passive: <Shield className="h-4 w-4" />,
                              standard: <ScanEye className="h-4 w-4" />,
                              active: <Bolt className="h-4 w-4" />,
                            };
                            return (
                              <label
                                key={mode.value}
                                className={`flex items-start gap-3 p-3 rounded-lg cursor-pointer transition-all border ${
                                  isSelected ? `${colors.bg} ${colors.border} ring-1 ${colors.ring}` : 'border-transparent hover:bg-muted/30'
                                }`}
                              >
                                <RadioGroupItem value={mode.value} className="mt-0.5" />
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2">
                                    <span className={`${isSelected ? colors.text : 'text-muted-foreground'}`}>
                                      {modeIcons[mode.value as keyof typeof modeIcons]}
                                    </span>
                                    <span className={`text-sm font-medium ${isSelected ? 'text-foreground' : 'text-muted-foreground'}`}>
                                      {mode.label}
                                    </span>
                                    <Badge variant="outline" className={`text-[9px] ${isSelected ? colors.text + ' ' + colors.border : 'text-muted-foreground'}`}>
                                      {mode.connectorCount} connectors
                                    </Badge>
                                  </div>
                                  <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{mode.description}</p>
                                  {mode.value === 'active' && (
                                    <div className="flex items-center gap-1 mt-1.5">
                                      <AlertTriangle className="h-3 w-3 text-orange-400" />
                                      <span className="text-[10px] text-orange-400">Touches target infrastructure — requires RoE awareness</span>
                                    </div>
                                  )}
                                </div>
                              </label>
                            );
                          })}
                        </RadioGroup>
                        {/* Connector breakdown */}
                        <div className="p-3 border-t border-border/30 bg-muted/10">
                          <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                            <span>Selected: <strong className="text-foreground">{selectedScanMode.replace('_', ' ')}</strong></span>
                            <span className="font-mono">
                              {selectedScanMode === 'strict_passive' ? '23' : selectedScanMode === 'standard' ? '28' : '31'} connectors active
                            </span>
                          </div>
                        </div>
                      </PopoverContent>
                    </Popover>

                    {/* Passive Discovery Button */}
                    <Button
                      size="sm"
                      onClick={() => passiveScanMut.mutate({ engagementId, scanMode: selectedScanMode })}
                      disabled={passiveScanMut.isPending}
                      className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500"
                    >
                      {passiveScanMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Search className="h-4 w-4 mr-1" />}
                      Passive Discovery
                    </Button>
                  </div>
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
                  <>
                    <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                      <CheckCircle2 className="h-3.5 w-3.5 mr-1" /> Completed
                    </Badge>
                    <Button
                      size="sm"
                      onClick={() => {
                        setIsGeneratingReport(true);
                        generateReportMut.mutate({
                          engagementId,
                          reportType: 'full_engagement',
                          clientType: 'enterprise',
                          title: `${engagement?.name || 'Engagement'} - Security Assessment Report`,
                          preparedFor: engagement?.customerName || undefined,
                          preparedBy: user?.name || 'Ace C3',
                        });
                      }}
                      disabled={isGeneratingReport}
                      className="bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500"
                    >
                      {isGeneratingReport ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Sparkles className="h-4 w-4 mr-1" />}
                      Generate Report
                    </Button>
                  </>
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
                  onClick={() => passiveScanMut.mutate({ engagementId, scanMode: selectedScanMode })}
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
                <TabsTrigger value="credentials" className="text-xs">
                  <KeyRound className="h-3.5 w-3.5 mr-1" /> Credentials
                  {(() => {
                    const credTests = (ops?.assets || []).flatMap((a: any) => (a.toolResults || []).filter((tr: any) => tr.phase === 'credential_testing'));
                    const found = credTests.filter((tr: any) => tr.findings?.length > 0).length;
                    return credTests.length > 0 ? (
                      <Badge variant="secondary" className={`ml-1 text-[9px] h-4 px-1 ${found > 0 ? 'bg-red-500/20 text-red-400' : 'bg-yellow-500/20 text-yellow-400'}`}>
                        {found > 0 ? `${found} found` : credTests.length}
                      </Badge>
                    ) : null;
                  })()}
                </TabsTrigger>
                <TabsTrigger value="scope" className="text-xs">
                  <Shield className="h-3.5 w-3.5 mr-1" /> RoE & Scope
                </TabsTrigger>
                <TabsTrigger value="attackchains" className="text-xs">
                  <GitBranch className="h-3.5 w-3.5 mr-1" /> Attack Chains
                  {(attackChainsQ.data?.chains?.length || 0) > 0 && (
                    <Badge variant="secondary" className="ml-1 text-[9px] h-4 px-1 bg-red-500/20 text-red-400">{attackChainsQ.data!.chains.length}</Badge>
                  )}
                </TabsTrigger>
                <TabsTrigger value="cloud" className="text-xs">
                  <Cloud className="h-3.5 w-3.5 mr-1" /> Cloud
                  {(cloudMisconfigsQ.data?.stats?.total || 0) > 0 && (
                    <Badge variant="secondary" className="ml-1 text-[9px] h-4 px-1 bg-orange-500/20 text-orange-400">{cloudMisconfigsQ.data!.stats.total}</Badge>
                  )}
                </TabsTrigger>
                <TabsTrigger value="feedback" className="text-xs">
                  <RefreshCw className="h-3.5 w-3.5 mr-1" /> Feedback Loop
                  {feedbackLoopQ.data && (
                    <Badge variant="secondary" className="ml-1 text-[9px] h-4 px-1 bg-purple-500/20 text-purple-400">{feedbackLoopQ.data.totalScansExecuted}</Badge>
                  )}
                </TabsTrigger>
              </TabsList>
            </div>

            {/* ── Live Feed Tab ── */}
            <TabsContent value="feed" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <div className="relative h-full flex flex-col">
              <div
                ref={feedScrollRef}
                className="flex-1 overflow-y-auto min-h-0 max-h-[calc(100vh-280px)] border border-border/30 rounded-lg bg-background/50"
                style={{ scrollBehavior: "smooth" }}
              >
                <div className="space-y-1 p-3">
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
              </div>
              {/* Scroll-to-bottom button */}
              {!isAutoScroll && (ops?.log?.length || 0) > 5 && (
                <button
                  onClick={() => {
                    setIsAutoScroll(true);
                    const viewport = feedScrollRef.current;
                    if (viewport) viewport.scrollTop = viewport.scrollHeight;
                  }}
                  className="absolute bottom-6 right-8 z-10 flex items-center gap-1.5 px-3 py-1.5 bg-primary text-primary-foreground text-xs font-display tracking-wider rounded-full shadow-lg hover:bg-primary/90 transition-all animate-in fade-in slide-in-from-bottom-2"
                >
                  <ArrowRight className="h-3 w-3 rotate-90" /> LATEST
                </button>
              )}
              {/* Log count indicator */}
              <div className="flex-none flex items-center justify-between pt-2 text-[10px] text-muted-foreground font-display tracking-wider">
                <span>{ops?.log?.length || 0} log entries</span>
                {isAutoScroll && <span className="flex items-center gap-1 text-green-400"><Activity className="h-3 w-3" /> AUTO-SCROLL</span>}
              </div>
              </div>
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
                            {(selectedAssetData.vulns || []).map((v: any, i: number) => (
                              <div key={i} className="text-xs px-2 py-1.5 bg-muted/10 rounded space-y-1">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <Badge variant="outline" className={`text-[9px] ${
                                    v.severity === "critical" ? "text-red-400 border-red-500/30" :
                                    v.severity === "high" ? "text-orange-400 border-orange-500/30" :
                                    v.severity === "medium" ? "text-yellow-400 border-yellow-500/30" :
                                    "text-blue-400 border-blue-500/30"
                                  }`}>{v.severity}</Badge>
                                  <span className="text-foreground truncate flex-1">{v.title}</span>
                                  {v.cve && <span className="text-muted-foreground font-mono text-[10px]">{v.cve}</span>}
                                </div>
                                {/* ESS Enrichment Badges */}
                                {v.essEnrichment && (
                                  <div className="flex items-center gap-1.5 flex-wrap ml-0.5">
                                    {v.essEnrichment.cisaKev && (
                                      <Badge variant="outline" className="text-[8px] bg-red-500/20 text-red-300 border-red-500/40 font-bold">CISA KEV</Badge>
                                    )}
                                    {v.essEnrichment.metasploitCount > 0 && (
                                      <Badge variant="outline" className="text-[8px] bg-purple-500/20 text-purple-300 border-purple-500/40">
                                        MSF:{v.essEnrichment.metasploitCount}
                                      </Badge>
                                    )}
                                    {v.essEnrichment.exploitdbCount > 0 && (
                                      <Badge variant="outline" className="text-[8px] bg-orange-500/20 text-orange-300 border-orange-500/40">
                                        EDB:{v.essEnrichment.exploitdbCount}
                                      </Badge>
                                    )}
                                    {v.essEnrichment.githubPocs > 0 && (
                                      <Badge variant="outline" className="text-[8px] bg-green-500/20 text-green-300 border-green-500/40">
                                        PoC:{v.essEnrichment.githubPocs}
                                      </Badge>
                                    )}
                                    <span className="text-[9px] text-muted-foreground" title="CESS exploit probability">
                                      CESS:{(v.essEnrichment.cessScore * 100).toFixed(0)}%
                                    </span>
                                    {v.essEnrichment.epssScore > 0 && (
                                      <span className="text-[9px] text-muted-foreground" title="EPSS score">
                                        EPSS:{(v.essEnrichment.epssScore * 100).toFixed(1)}%
                                      </span>
                                    )}
                                    {v.essEnrichment.cvssBase > 0 && (
                                      <span className={`text-[9px] font-mono ${
                                        v.essEnrichment.cvssBase >= 9 ? 'text-red-400' :
                                        v.essEnrichment.cvssBase >= 7 ? 'text-orange-400' :
                                        v.essEnrichment.cvssBase >= 4 ? 'text-yellow-400' : 'text-blue-400'
                                      }`} title={v.essEnrichment.cvssVector || 'CVSS base score'}>
                                        CVSS:{v.essEnrichment.cvssBase}
                                      </span>
                                    )}
                                  </div>
                                )}
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

                            {/* ESS Intelligence for this CVE */}
                            {match.cve && (() => {
                              // Find ESS enrichment from the asset's vulns
                              const assetData = (ops?.assets || []).find((a: any) => a.hostname === match.asset);
                              const vulnData = assetData?.vulns?.find((v: any) => v.cve === match.cve && v.essEnrichment);
                              if (!vulnData?.essEnrichment) return null;
                              const ess = vulnData.essEnrichment;
                              return (
                                <div className="flex items-center gap-1.5 flex-wrap mb-2 px-2 py-1.5 bg-cyan-500/5 rounded border border-cyan-500/10">
                                  <span className="text-[9px] font-medium text-cyan-400 mr-1">ESS:</span>
                                  {ess.cisaKev && <Badge variant="outline" className="text-[8px] bg-red-500/20 text-red-300 border-red-500/40 font-bold">CISA KEV</Badge>}
                                  <span className="text-[9px] text-muted-foreground">CESS:{(ess.cessScore * 100).toFixed(0)}%</span>
                                  {ess.epssScore > 0 && <span className="text-[9px] text-muted-foreground">EPSS:{(ess.epssScore * 100).toFixed(1)}%</span>}
                                  {ess.cvssBase > 0 && <span className={`text-[9px] font-mono ${ess.cvssBase >= 9 ? 'text-red-400' : ess.cvssBase >= 7 ? 'text-orange-400' : 'text-yellow-400'}`}>CVSS:{ess.cvssBase}</span>}
                                  {ess.metasploitCount > 0 && <Badge variant="outline" className="text-[8px] bg-purple-500/20 text-purple-300 border-purple-500/40">MSF:{ess.metasploitCount}</Badge>}
                                  {ess.exploitdbCount > 0 && <Badge variant="outline" className="text-[8px] bg-orange-500/20 text-orange-300 border-orange-500/40">EDB:{ess.exploitdbCount}</Badge>}
                                  {ess.githubPocs > 0 && <Badge variant="outline" className="text-[8px] bg-green-500/20 text-green-300 border-green-500/40">PoC:{ess.githubPocs}</Badge>}
                                </div>
                              );
                            })()}

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

            {/* ── Credential Testing Summary Tab ── */}
            <TabsContent value="credentials" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="py-3 space-y-4">
                  {(() => {
                    // Aggregate credential testing data from all assets
                    const allCredTests = (ops?.assets || []).flatMap((a: any) =>
                      (a.toolResults || []).filter((tr: any) => tr.phase === 'credential_testing').map((tr: any) => ({ ...tr, asset: a }))
                    );
                    const totalTests = allCredTests.length;
                    const successfulTests = allCredTests.filter((t: any) => t.findings?.length > 0);
                    const failedTests = allCredTests.filter((t: any) => !t.findings?.length);
                    const uniqueAssets = new Set(allCredTests.map((t: any) => t.asset.hostname)).size;
                    const uniqueServices = new Set(allCredTests.map((t: any) => {
                      const m = t.command?.match(/hydra.*?\s(\S+)\s*$/); return m ? m[1] : t.tool;
                    })).size;
                    // Extract OEM credential info from passive recon
                    const oemCreds: any[] = [];
                    if (ops?.passiveReconResults) {
                      Object.values(ops.passiveReconResults).forEach((d: any) => {
                        if (d?.oemCredentials) oemCreds.push(...d.oemCredentials);
                      });
                    }

                    if (totalTests === 0) {
                      return (
                        <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                          <KeyRound className="h-12 w-12 mb-4 opacity-20" />
                          <p className="text-sm">No credential tests executed yet</p>
                          <p className="text-xs mt-1">Credential testing activates during the vulnerability detection phase on discovered login services</p>
                          {oemCreds.length > 0 && (
                            <div className="mt-6 w-full max-w-md">
                              <p className="text-xs font-medium text-yellow-400 mb-2 flex items-center gap-1"><Key className="h-3 w-3" /> {oemCreds.length} Vendor Default Credentials Identified (Pending Test)</p>
                              <div className="space-y-1">
                                {oemCreds.slice(0, 8).map((c: any, i: number) => (
                                  <div key={i} className="flex items-center gap-2 text-xs px-2 py-1 bg-yellow-500/5 rounded border border-yellow-500/10">
                                    <Lock className="h-3 w-3 text-yellow-400" />
                                    <span className="text-foreground">{c.vendor} {c.product}</span>
                                    <span className="text-muted-foreground">:{c.port} ({c.protocol})</span>
                                  </div>
                                ))}
                                {oemCreds.length > 8 && <p className="text-[10px] text-muted-foreground pl-2">+{oemCreds.length - 8} more</p>}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    }

                    return (
                      <>
                        {/* Summary Stats */}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                          <Card className="bg-card/50 border-border/30">
                            <CardContent className="p-3 text-center">
                              <p className="text-2xl font-bold text-foreground">{totalTests}</p>
                              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Tests</p>
                            </CardContent>
                          </Card>
                          <Card className={`border-border/30 ${successfulTests.length > 0 ? 'bg-red-500/5 border-red-500/20' : 'bg-card/50'}`}>
                            <CardContent className="p-3 text-center">
                              <p className={`text-2xl font-bold ${successfulTests.length > 0 ? 'text-red-400' : 'text-foreground'}`}>{successfulTests.length}</p>
                              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Creds Found</p>
                            </CardContent>
                          </Card>
                          <Card className="bg-card/50 border-border/30">
                            <CardContent className="p-3 text-center">
                              <p className="text-2xl font-bold text-foreground">{uniqueAssets}</p>
                              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Assets Tested</p>
                            </CardContent>
                          </Card>
                          <Card className="bg-card/50 border-border/30">
                            <CardContent className="p-3 text-center">
                              <p className="text-2xl font-bold text-foreground">{uniqueServices}</p>
                              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Services</p>
                            </CardContent>
                          </Card>
                        </div>

                        {/* Valid Credentials Found */}
                        {successfulTests.length > 0 && (
                          <Card className="bg-red-500/5 border-red-500/20">
                            <CardHeader className="pb-2">
                              <CardTitle className="text-sm flex items-center gap-2 text-red-400">
                                <Unlock className="h-4 w-4" /> Valid Credentials Discovered
                              </CardTitle>
                              <CardDescription className="text-xs">These credentials were successfully authenticated against live services</CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-2">
                              {successfulTests.map((test: any, idx: number) => (
                                <div key={idx} className="p-3 bg-red-500/5 rounded-lg border border-red-500/10">
                                  <div className="flex items-center justify-between mb-2">
                                    <div className="flex items-center gap-2">
                                      <Unlock className="h-3.5 w-3.5 text-red-400" />
                                      <span className="text-sm font-medium text-foreground">{test.asset.hostname}</span>
                                      {test.asset.ip && test.asset.ip !== test.asset.hostname && (
                                        <span className="text-xs text-muted-foreground">({test.asset.ip})</span>
                                      )}
                                    </div>
                                    <Badge variant="outline" className="text-[9px] text-red-400 border-red-500/30">
                                      {test.findings.length} credential{test.findings.length !== 1 ? 's' : ''}
                                    </Badge>
                                  </div>
                                  {test.findings.map((f: any, fi: number) => (
                                    <div key={fi} className="flex items-center gap-2 text-xs px-2 py-1.5 bg-background/50 rounded">
                                      <Key className="h-3 w-3 text-red-400" />
                                      <span className="text-foreground font-mono">{f.title}</span>
                                      <Badge variant="outline" className={`text-[8px] ml-auto ${
                                        f.severity === 'critical' ? 'text-red-400 border-red-500/30' :
                                        f.severity === 'high' ? 'text-orange-400 border-orange-500/30' :
                                        'text-yellow-400 border-yellow-500/30'
                                      }`}>{f.severity}</Badge>
                                    </div>
                                  ))}
                                  <div className="flex items-center gap-3 mt-2 text-[10px] text-muted-foreground">
                                    <span className="flex items-center gap-1"><Terminal className="h-2.5 w-2.5" /> {test.tool}</span>
                                    <span className="flex items-center gap-1"><Clock className="h-2.5 w-2.5" /> {(test.durationMs / 1000).toFixed(1)}s</span>
                                  </div>
                                </div>
                              ))}
                            </CardContent>
                          </Card>
                        )}

                        {/* OEM Default Credentials Tested */}
                        {oemCreds.length > 0 && (
                          <Card className="bg-card/50 border-border/30">
                            <CardHeader className="pb-2">
                              <CardTitle className="text-sm flex items-center gap-2 text-yellow-400">
                                <Key className="h-4 w-4" /> Vendor/OEM Default Credentials
                              </CardTitle>
                              <CardDescription className="text-xs">{oemCreds.length} vendor-specific default credentials were identified and prioritized for testing</CardDescription>
                            </CardHeader>
                            <CardContent>
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                {oemCreds.map((c: any, i: number) => (
                                  <div key={i} className="flex items-center gap-2 text-xs px-3 py-2 bg-yellow-500/5 rounded border border-yellow-500/10">
                                    <Lock className="h-3 w-3 text-yellow-400 flex-none" />
                                    <div className="flex-1 min-w-0">
                                      <span className="text-foreground font-medium">{c.vendor} {c.product}</span>
                                      <span className="text-muted-foreground ml-1">:{c.port} ({c.protocol})</span>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </CardContent>
                          </Card>
                        )}

                        {/* Per-Asset Credential Test Results */}
                        <Card className="bg-card/50 border-border/30">
                          <CardHeader className="pb-2">
                            <CardTitle className="text-sm flex items-center gap-2">
                              <ClipboardList className="h-4 w-4 text-muted-foreground" /> Per-Asset Test Results
                            </CardTitle>
                          </CardHeader>
                          <CardContent className="space-y-2">
                            {(ops?.assets || []).filter((a: any) => (a.toolResults || []).some((tr: any) => tr.phase === 'credential_testing')).map((asset: any, ai: number) => {
                              const assetCredTests = (asset.toolResults || []).filter((tr: any) => tr.phase === 'credential_testing');
                              const assetFound = assetCredTests.some((t: any) => t.findings?.length > 0);
                              return (
                                <div key={ai} className={`p-3 rounded-lg border ${assetFound ? 'bg-red-500/5 border-red-500/10' : 'bg-background/50 border-border/20'}`}>
                                  <div className="flex items-center justify-between mb-2">
                                    <div className="flex items-center gap-2">
                                      {assetFound ? <Unlock className="h-3.5 w-3.5 text-red-400" /> : <Lock className="h-3.5 w-3.5 text-emerald-400" />}
                                      <span className="text-sm font-medium text-foreground">{asset.hostname}</span>
                                      {asset.ip && asset.ip !== asset.hostname && <span className="text-xs text-muted-foreground">({asset.ip})</span>}
                                    </div>
                                    <Badge variant="outline" className={`text-[9px] ${assetFound ? 'text-red-400 border-red-500/30' : 'text-emerald-400 border-emerald-500/30'}`}>
                                      {assetFound ? 'CREDENTIALS FOUND' : 'NO VALID CREDS'}
                                    </Badge>
                                  </div>
                                  <div className="space-y-1">
                                    {assetCredTests.map((test: any, ti: number) => {
                                      const svcMatch = test.command?.match(/hydra.*?\s(\S+)\s*$/);
                                      const service = svcMatch ? svcMatch[1] : test.tool;
                                      const hasFindings = test.findings?.length > 0;
                                      return (
                                        <div key={ti} className="flex items-center gap-2 text-xs">
                                          {hasFindings ? <XCircle className="h-3 w-3 text-red-400 flex-none" /> : <CheckCircle2 className="h-3 w-3 text-emerald-400 flex-none" />}
                                          <span className="text-muted-foreground w-16 flex-none font-mono">{service}</span>
                                          <span className={hasFindings ? 'text-red-400' : 'text-muted-foreground'}>
                                            {hasFindings ? `${test.findings.length} valid credential${test.findings.length !== 1 ? 's' : ''}` : 'No valid credentials'}
                                          </span>
                                          <span className="text-muted-foreground/50 ml-auto text-[10px]">{(test.durationMs / 1000).toFixed(1)}s</span>
                                          {test.timedOut && <Badge variant="outline" className="text-[8px] text-orange-400 border-orange-500/30">TIMEOUT</Badge>}
                                        </div>
                                      );
                                    })}
                                  </div>
                                </div>
                              );
                            })}
                          </CardContent>
                        </Card>
                      </>
                    );
                  })()}
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

            {/* ── Attack Chains Tab ── */}
            <TabsContent value="attackchains" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-[calc(100vh-280px)]">
                <div className="space-y-4 py-3">
                  {/* Summary Cards */}
                  {attackChainsQ.data?.summary && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      <Card className="bg-card/50 border-red-500/20">
                        <CardContent className="p-3">
                          <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Highest Risk</div>
                          <div className="text-2xl font-bold text-red-400 tabular-nums">{attackChainsQ.data.summary.highestRisk}<span className="text-xs text-muted-foreground">/10</span></div>
                        </CardContent>
                      </Card>
                      <Card className="bg-card/50 border-cyan-500/20">
                        <CardContent className="p-3">
                          <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Steps</div>
                          <div className="text-2xl font-bold text-cyan-400 tabular-nums">{attackChainsQ.data.summary.totalSteps}</div>
                        </CardContent>
                      </Card>
                      <Card className="bg-card/50 border-purple-500/20">
                        <CardContent className="p-3">
                          <div className="text-[10px] text-muted-foreground uppercase tracking-wider">MITRE Techniques</div>
                          <div className="text-2xl font-bold text-purple-400 tabular-nums">{attackChainsQ.data.summary.uniqueTechniques}</div>
                        </CardContent>
                      </Card>
                      <Card className="bg-card/50 border-orange-500/20">
                        <CardContent className="p-3">
                          <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Cloud Chains</div>
                          <div className="text-2xl font-bold text-orange-400 tabular-nums">{attackChainsQ.data.summary.cloudChainsCount}</div>
                        </CardContent>
                      </Card>
                    </div>
                  )}

                  {/* Cloud Risk Assessment */}
                  {attackChainsQ.data?.cloudRiskAssessment && (
                    <Card className="bg-card/50 border-orange-500/30">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm flex items-center gap-2">
                          <Cloud className="h-4 w-4 text-orange-400" />
                          Cloud Risk Assessment
                          <Badge variant="outline" className={`ml-auto text-[10px] ${
                            attackChainsQ.data.cloudRiskAssessment.overallRisk === 'critical' ? 'border-red-500 text-red-400' :
                            attackChainsQ.data.cloudRiskAssessment.overallRisk === 'high' ? 'border-orange-500 text-orange-400' :
                            attackChainsQ.data.cloudRiskAssessment.overallRisk === 'medium' ? 'border-yellow-500 text-yellow-400' :
                            'border-green-500 text-green-400'
                          }`}>
                            {attackChainsQ.data.cloudRiskAssessment.overallRisk.toUpperCase()} — Score: {attackChainsQ.data.cloudRiskAssessment.riskScore}/100
                          </Badge>
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-2">
                        <div className="flex gap-4 text-xs">
                          <span className="text-muted-foreground">Providers: <span className="text-foreground">{(attackChainsQ.data.cloudRiskAssessment.exposedProviders || []).join(', ') || 'None'}</span></span>
                          <span className="text-muted-foreground">Public Storage: <span className="text-orange-400 font-semibold">{attackChainsQ.data.cloudRiskAssessment.publicStorageCount}</span></span>
                        </div>
                      </CardContent>
                    </Card>
                  )}

                  {/* Individual Attack Chains */}
                  {(attackChainsQ.data?.chains || []).map((chain: any, idx: number) => (
                    <AttackChainCard key={chain.id || idx} chain={chain} index={idx} />
                  ))}

                  {(!attackChainsQ.data || attackChainsQ.data.chains.length === 0) && (
                    <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                      <GitBranch className="h-12 w-12 mb-4 opacity-20" />
                      <p className="text-sm">No attack chains generated yet</p>
                      <p className="text-xs mt-1">Attack chains are designed after vulnerability detection completes</p>
                    </div>
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ── Cloud Misconfigs Tab ── */}
            <TabsContent value="cloud" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-[calc(100vh-280px)]">
                <div className="space-y-4 py-3">
                  {/* Stats Row */}
                  {cloudMisconfigsQ.data && cloudMisconfigsQ.data.stats.total > 0 && (
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                      <Card className="bg-card/50 border-red-500/20">
                        <CardContent className="p-3 text-center">
                          <div className="text-[10px] text-muted-foreground uppercase">Critical</div>
                          <div className="text-xl font-bold text-red-400">{cloudMisconfigsQ.data.stats.critical}</div>
                        </CardContent>
                      </Card>
                      <Card className="bg-card/50 border-orange-500/20">
                        <CardContent className="p-3 text-center">
                          <div className="text-[10px] text-muted-foreground uppercase">High</div>
                          <div className="text-xl font-bold text-orange-400">{cloudMisconfigsQ.data.stats.high}</div>
                        </CardContent>
                      </Card>
                      <Card className="bg-card/50 border-yellow-500/20">
                        <CardContent className="p-3 text-center">
                          <div className="text-[10px] text-muted-foreground uppercase">Medium</div>
                          <div className="text-xl font-bold text-yellow-400">{cloudMisconfigsQ.data.stats.medium}</div>
                        </CardContent>
                      </Card>
                      <Card className="bg-card/50 border-blue-500/20">
                        <CardContent className="p-3 text-center">
                          <div className="text-[10px] text-muted-foreground uppercase">Low/Info</div>
                          <div className="text-xl font-bold text-blue-400">{cloudMisconfigsQ.data.stats.low}</div>
                        </CardContent>
                      </Card>
                      <Card className="bg-card/50 border-purple-500/20">
                        <CardContent className="p-3 text-center">
                          <div className="text-[10px] text-muted-foreground uppercase">Providers</div>
                          <div className="text-xl font-bold text-purple-400">{cloudMisconfigsQ.data.stats.providers.length}</div>
                        </CardContent>
                      </Card>
                    </div>
                  )}

                  {/* Cloud Assets */}
                  {cloudMisconfigsQ.data?.assetCloudInfo && cloudMisconfigsQ.data.assetCloudInfo.length > 0 && (
                    <Card className="bg-card/50 border-cyan-500/20">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm flex items-center gap-2">
                          <Layers className="h-4 w-4 text-cyan-400" /> Cloud-Hosted Assets
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-1">
                          {cloudMisconfigsQ.data.assetCloudInfo.map((asset: any, i: number) => (
                            <div key={i} className="flex items-center gap-2 text-xs py-1 border-b border-border/20 last:border-0">
                              <Server className="h-3 w-3 text-muted-foreground" />
                              <span className="font-mono text-cyan-400">{asset.hostname}</span>
                              {asset.ip && <span className="text-muted-foreground">({asset.ip})</span>}
                              <div className="flex gap-1 ml-auto">
                                {(asset.providers || []).map((p: string) => (
                                  <Badge key={p} variant="outline" className={`text-[9px] px-1.5 ${
                                    p.toLowerCase().includes('aws') ? 'border-orange-500/50 text-orange-400' :
                                    p.toLowerCase().includes('azure') ? 'border-blue-500/50 text-blue-400' :
                                    p.toLowerCase().includes('gcp') || p.toLowerCase().includes('google') ? 'border-red-500/50 text-red-400' :
                                    'border-muted-foreground/50 text-muted-foreground'
                                  }`}>{p}</Badge>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  )}

                  {/* Misconfiguration Findings */}
                  {(cloudMisconfigsQ.data?.findings || []).map((finding: any, idx: number) => (
                    <CloudFindingCard key={idx} finding={finding} />
                  ))}

                  {(!cloudMisconfigsQ.data || cloudMisconfigsQ.data.stats.total === 0) && (
                    <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                      <Cloud className="h-12 w-12 mb-4 opacity-20" />
                      <p className="text-sm">No cloud misconfigurations detected</p>
                      <p className="text-xs mt-1">Cloud detection runs during the enumeration phase</p>
                    </div>
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ── Feedback Loop Tab ── */}
            <TabsContent value="feedback" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-[calc(100vh-280px)]">
                <div className="space-y-4 py-3">
                  {feedbackLoopQ.data ? (
                    <>
                      {/* Feedback Loop Summary */}
                      <Card className="bg-card/50 border-purple-500/20">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm flex items-center gap-2">
                            <Brain className="h-4 w-4 text-purple-400" /> LLM Adaptive Re-Scanning
                            <Badge variant="outline" className={`ml-auto text-[10px] ${
                              feedbackLoopQ.data.satisfied ? 'border-green-500 text-green-400' : 'border-yellow-500 text-yellow-400'
                            }`}>
                              {feedbackLoopQ.data.satisfied ? 'Satisfied' : 'In Progress'}
                            </Badge>
                          </CardTitle>
                          <CardDescription className="text-xs">
                            The LLM analyzed findings and requested targeted re-scans to fill information gaps.
                          </CardDescription>
                        </CardHeader>
                        <CardContent>
                          <div className="grid grid-cols-3 gap-4 mb-4">
                            <div className="text-center">
                              <div className="text-[10px] text-muted-foreground uppercase">Iterations</div>
                              <div className="text-lg font-bold text-purple-400">{feedbackLoopQ.data.iteration + 1}</div>
                            </div>
                            <div className="text-center">
                              <div className="text-[10px] text-muted-foreground uppercase">Scans Run</div>
                              <div className="text-lg font-bold text-cyan-400">{feedbackLoopQ.data.totalScansExecuted}</div>
                            </div>
                            <div className="text-center">
                              <div className="text-[10px] text-muted-foreground uppercase">Budget Left</div>
                              <div className="text-lg font-bold text-emerald-400">{feedbackLoopQ.data.budgetRemaining}</div>
                            </div>
                          </div>
                          {/* Budget Progress Bar */}
                          <div className="space-y-1">
                            <div className="flex justify-between text-[10px] text-muted-foreground">
                              <span>Scan Budget Usage</span>
                              <span>{feedbackLoopQ.data.totalScansExecuted} / {feedbackLoopQ.data.totalScansExecuted + feedbackLoopQ.data.budgetRemaining}</span>
                            </div>
                            <Progress
                              value={feedbackLoopQ.data.totalScansExecuted / Math.max(1, feedbackLoopQ.data.totalScansExecuted + feedbackLoopQ.data.budgetRemaining) * 100}
                              className="h-2"
                            />
                          </div>
                        </CardContent>
                      </Card>

                      {/* Final Analysis */}
                      {feedbackLoopQ.data.finalAnalysis && (
                        <Card className="bg-card/50 border-cyan-500/20">
                          <CardHeader className="pb-2">
                            <CardTitle className="text-sm flex items-center gap-2">
                              <Sparkles className="h-4 w-4 text-cyan-400" /> LLM Final Analysis
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <p className="text-xs text-muted-foreground whitespace-pre-wrap leading-relaxed">{feedbackLoopQ.data.finalAnalysis}</p>
                          </CardContent>
                        </Card>
                      )}

                      {/* Scan History */}
                      <div className="space-y-2">
                        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider px-1">Re-Scan History</h3>
                        {(feedbackLoopQ.data.history || []).map((scan: any, idx: number) => (
                          <FeedbackScanCard key={idx} scan={scan} index={idx} />
                        ))}
                      </div>
                    </>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                      <RefreshCw className="h-12 w-12 mb-4 opacity-20" />
                      <p className="text-sm">No feedback loop data yet</p>
                      <p className="text-xs mt-1">The LLM feedback loop runs after vulnerability detection to request targeted re-scans</p>
                    </div>
                  )}
                </div>
              </ScrollArea>
            </TabsContent>
          </Tabs>
        </div>

        {/* Right: Stats Panel */}
        <div className="w-64 flex-none border-l border-border/30 bg-card/30 overflow-y-auto p-4 space-y-4 hidden lg:block">
          {/* Scan Mode Indicator */}
          <div className={`rounded-lg p-3 border ${
            selectedScanMode === 'strict_passive' ? 'bg-emerald-500/5 border-emerald-500/20' :
            selectedScanMode === 'standard' ? 'bg-blue-500/5 border-blue-500/20' :
            'bg-orange-500/5 border-orange-500/20'
          }`}>
            <div className="flex items-center gap-2">
              {selectedScanMode === 'strict_passive' ? <Shield className="h-4 w-4 text-emerald-400" /> :
               selectedScanMode === 'standard' ? <ScanEye className="h-4 w-4 text-blue-400" /> :
               <Bolt className="h-4 w-4 text-orange-400" />}
              <div>
                <div className={`text-xs font-semibold ${
                  selectedScanMode === 'strict_passive' ? 'text-emerald-400' :
                  selectedScanMode === 'standard' ? 'text-blue-400' : 'text-orange-400'
                }`}>
                  {selectedScanMode === 'strict_passive' ? 'Strict Passive' :
                   selectedScanMode === 'standard' ? 'Standard' : 'Active'}
                </div>
                <div className="text-[10px] text-muted-foreground">
                  {selectedScanMode === 'strict_passive' ? '23' : selectedScanMode === 'standard' ? '28' : '31'} connectors
                </div>
              </div>
            </div>
          </div>

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

          {/* Attack Chain & Cloud Stats */}
          {((attackChainsQ.data?.chains?.length || 0) > 0 || (cloudMisconfigsQ.data?.stats?.total || 0) > 0 || feedbackLoopQ.data) && (
            <>
              <div>
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">AI Analysis</h3>
                <div className="space-y-3">
                  <StatCard icon={<GitBranch className="h-4 w-4 text-red-400" />} label="Attack Chains" value={attackChainsQ.data?.chains?.length || 0} />
                  <StatCard icon={<Cloud className="h-4 w-4 text-orange-400" />} label="Cloud Findings" value={cloudMisconfigsQ.data?.stats?.total || 0} />
                  <StatCard icon={<RefreshCw className="h-4 w-4 text-purple-400" />} label="Re-Scans" value={feedbackLoopQ.data?.totalScansExecuted || 0} />
                  {attackChainsQ.data?.summary && (
                    <StatCard icon={<Gauge className="h-4 w-4 text-red-500" />} label="Max Risk" value={`${attackChainsQ.data.summary.highestRisk}/10`} />
                  )}
                  {/* ESS Intelligence */}
                  {(opsStateQ.data as any)?.essIntelligence && (
                    <>
                      <StatCard icon={<ShieldAlert className="h-4 w-4 text-cyan-400" />} label="CVEs Enriched" value={(opsStateQ.data as any).essIntelligence.totalCvesEnriched || 0} />
                      {(opsStateQ.data as any).essIntelligence.cisaKevCount > 0 && (
                        <StatCard icon={<AlertTriangle className="h-4 w-4 text-red-500" />} label="CISA KEV" value={(opsStateQ.data as any).essIntelligence.cisaKevCount} />
                      )}
                      {(opsStateQ.data as any).essIntelligence.metasploitCount > 0 && (
                        <StatCard icon={<Crosshair className="h-4 w-4 text-purple-400" />} label="Metasploit" value={(opsStateQ.data as any).essIntelligence.metasploitCount} />
                      )}
                    </>
                  )}
                </div>
              </div>
              <Separator />
            </>
          )}

          {/* LLM Cost Tracking */}
          <div>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">LLM Cost</h3>
            <div className="space-y-3">
              <StatCard icon={<CircleDollarSign className="h-4 w-4 text-emerald-400" />} label="Est. Cost" value={`$${(Number(llmCostQ.data?.estimated_cost_usd) || 0).toFixed(4)}`} />
              <StatCard icon={<Coins className="h-4 w-4 text-amber-400" />} label="Total Tokens" value={formatTokenCount(Number(llmCostQ.data?.total_tokens) || 0)} />
              <StatCard icon={<Zap className="h-4 w-4 text-purple-400" />} label="LLM Calls" value={Number(llmCostQ.data?.total_calls) || 0} />
            </div>
            {llmCostBreakdownQ.data && llmCostBreakdownQ.data.length > 0 && (
              <div className="mt-3 space-y-1">
                <p className="text-[10px] text-muted-foreground font-medium">Cost by Pipeline Stage</p>
                {llmCostBreakdownQ.data.slice(0, 5).map((item: any) => (
                  <div key={item.caller} className="flex items-center justify-between text-[10px]">
                    <span className="truncate text-muted-foreground max-w-[120px]" title={item.caller}>
                      {item.caller?.split(':').pop() || item.caller}
                    </span>
                    <span className="text-emerald-400 font-mono">${(Number(item.estimated_cost_usd) || 0).toFixed(4)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <Separator />

          {/* Report Generation */}
          <div>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Reports</h3>
            <div className="space-y-2">
              <Button
                size="sm"
                variant="outline"
                className="w-full justify-start text-xs border-purple-500/30 text-purple-400 hover:bg-purple-500/10"
                onClick={() => {
                  setIsGeneratingReport(true);
                  generateReportMut.mutate({
                    engagementId,
                    reportType: 'full_engagement',
                    clientType: 'enterprise',
                    title: `${engagement?.name || 'Engagement'} - Security Assessment Report`,
                    preparedFor: engagement?.customerName || undefined,
                    preparedBy: user?.name || 'Ace C3',
                  });
                }}
                disabled={isGeneratingReport || generateReportMut.isPending}
              >
                {isGeneratingReport ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5 mr-1.5" />}
                Generate Full Report
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="w-full justify-start text-xs border-blue-500/30 text-blue-400 hover:bg-blue-500/10"
                onClick={() => navigate('/reports/generate')}
              >
                <ClipboardList className="h-3.5 w-3.5 mr-1.5" />
                All Reports
              </Button>
            </div>
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

function StatCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: number | string }) {
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

// ─── Attack Chain Card ────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-blue-400 bg-blue-500/10 border-blue-500/30",
  info: "text-muted-foreground bg-muted/30 border-muted-foreground/30",
};

function getRiskColor(risk: number): string {
  if (risk >= 9) return "text-red-500";
  if (risk >= 7) return "text-red-400";
  if (risk >= 5) return "text-orange-400";
  if (risk >= 3) return "text-yellow-400";
  return "text-green-400";
}

function AttackChainCard({ chain, index }: { chain: any; index: number }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card className="bg-card/50 border-border/40 hover:border-border/60 transition-colors">
      <Collapsible open={expanded} onOpenChange={setExpanded}>
        <CollapsibleTrigger asChild>
          <CardHeader className="pb-2 cursor-pointer group">
            <div className="flex items-start gap-3">
              <div className={`flex items-center justify-center w-8 h-8 rounded-lg text-sm font-bold ${getRiskColor(chain.overallRisk)} bg-current/10 border border-current/20`}>
                {chain.overallRisk}
              </div>
              <div className="flex-1 min-w-0">
                <CardTitle className="text-sm flex items-center gap-2">
                  <span className="truncate">{chain.name}</span>
                  <ChevronDown className={`h-3.5 w-3.5 text-muted-foreground transition-transform ${expanded ? 'rotate-180' : ''}`} />
                </CardTitle>
                <CardDescription className="text-xs mt-0.5 line-clamp-2">{chain.description}</CardDescription>
              </div>
              <div className="flex gap-1.5 flex-shrink-0">
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Badge variant="outline" className="text-[9px] border-red-500/40 text-red-400">
                        <Gauge className="h-2.5 w-2.5 mr-0.5" /> {chain.overallRisk}/10
                      </Badge>
                    </TooltipTrigger>
                    <TooltipContent><p className="text-xs">Overall Risk Score</p></TooltipContent>
                  </Tooltip>
                </TooltipProvider>
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Badge variant="outline" className="text-[9px] border-cyan-500/40 text-cyan-400">
                        <Wrench className="h-2.5 w-2.5 mr-0.5" /> {chain.feasibility}/10
                      </Badge>
                    </TooltipTrigger>
                    <TooltipContent><p className="text-xs">Feasibility Score</p></TooltipContent>
                  </Tooltip>
                </TooltipProvider>
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Badge variant="outline" className="text-[9px] border-purple-500/40 text-purple-400">
                        <Eye className="h-2.5 w-2.5 mr-0.5" /> {chain.stealthRating}/10
                      </Badge>
                    </TooltipTrigger>
                    <TooltipContent><p className="text-xs">Stealth Rating</p></TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </div>
            </div>
          </CardHeader>
        </CollapsibleTrigger>

        <CollapsibleContent>
          <CardContent className="space-y-4 pt-0">
            {/* MITRE Techniques */}
            {chain.mitreTechniques && chain.mitreTechniques.length > 0 && (
              <div>
                <h4 className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">MITRE ATT&CK Techniques</h4>
                <div className="flex flex-wrap gap-1">
                  {chain.mitreTechniques.map((t: string, i: number) => (
                    <Badge key={i} variant="outline" className="text-[9px] px-1.5 py-0 border-purple-500/30 text-purple-400 font-mono">
                      {t}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {/* Attack Steps */}
            {chain.steps && chain.steps.length > 0 && (
              <div>
                <h4 className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Attack Steps ({chain.steps.length})</h4>
                <div className="space-y-1.5">
                  {chain.steps.map((step: any, i: number) => (
                    <div key={i} className="flex items-start gap-2 text-xs">
                      <div className="flex-shrink-0 w-5 h-5 rounded-full bg-muted/50 border border-border/50 flex items-center justify-center text-[9px] font-bold text-muted-foreground mt-0.5">
                        {i + 1}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span className="font-medium text-foreground">{step.name || step.title}</span>
                          {step.technique && (
                            <Badge variant="outline" className="text-[8px] px-1 py-0 border-purple-500/20 text-purple-400 font-mono">{step.technique}</Badge>
                          )}
                        </div>
                        {step.description && <p className="text-muted-foreground mt-0.5 line-clamp-2">{step.description}</p>}
                        {step.tool && <span className="text-cyan-400 text-[10px] font-mono">Tool: {step.tool}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Cloud Exploit Paths */}
            {chain.cloudExploitPaths && chain.cloudExploitPaths.length > 0 && (
              <div>
                <h4 className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5 flex items-center gap-1">
                  <Cloud className="h-3 w-3 text-orange-400" /> Cloud Exploit Paths
                </h4>
                <div className="space-y-1">
                  {chain.cloudExploitPaths.map((cp: any, i: number) => (
                    <div key={i} className="flex items-center gap-2 text-xs py-1 px-2 rounded bg-orange-500/5 border border-orange-500/10">
                      <Badge variant="outline" className={`text-[9px] px-1 ${
                        cp.severity === 'critical' ? 'border-red-500/40 text-red-400' :
                        cp.severity === 'high' ? 'border-orange-500/40 text-orange-400' :
                        'border-yellow-500/40 text-yellow-400'
                      }`}>{cp.severity || 'high'}</Badge>
                      <span className="text-foreground">{cp.name || cp.title || cp.id}</span>
                      {cp.provider && <Badge variant="secondary" className="text-[8px] px-1 ml-auto">{cp.provider}</Badge>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recommendations */}
            {chain.recommendations && chain.recommendations.length > 0 && (
              <div>
                <h4 className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">Recommendations</h4>
                <ul className="space-y-0.5">
                  {chain.recommendations.map((rec: string, i: number) => (
                    <li key={i} className="text-xs text-muted-foreground flex items-start gap-1.5">
                      <ShieldCheck className="h-3 w-3 text-green-400 mt-0.5 flex-shrink-0" />
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </CardContent>
        </CollapsibleContent>
      </Collapsible>
    </Card>
  );
}

// ─── Cloud Finding Card ───────────────────────────────────────────────────────

function CloudFindingCard({ finding }: { finding: any }) {
  const sevClass = SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.info;

  return (
    <Card className={`bg-card/50 border-l-2 ${sevClass.split(' ').pop()}`}>
      <CardContent className="p-3">
        <div className="flex items-start gap-3">
          <div className="flex-shrink-0 mt-0.5">
            {finding.severity === 'critical' || finding.severity === 'high' ? (
              <ShieldAlert className="h-4 w-4 text-red-400" />
            ) : finding.severity === 'medium' ? (
              <AlertTriangle className="h-4 w-4 text-yellow-400" />
            ) : (
              <Cloud className="h-4 w-4 text-blue-400" />
            )}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-foreground">{finding.title}</span>
              <Badge variant="outline" className={`text-[9px] px-1.5 ${
                finding.severity === 'critical' ? 'border-red-500/40 text-red-400' :
                finding.severity === 'high' ? 'border-orange-500/40 text-orange-400' :
                finding.severity === 'medium' ? 'border-yellow-500/40 text-yellow-400' :
                'border-blue-500/40 text-blue-400'
              }`}>{finding.severity?.toUpperCase()}</Badge>
            </div>
            <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
              {finding.provider && (
                <span className="flex items-center gap-1">
                  <Cloud className="h-3 w-3" />
                  {finding.provider}
                </span>
              )}
              {finding.service && (
                <span className="flex items-center gap-1">
                  <Layers className="h-3 w-3" />
                  {finding.service}
                </span>
              )}
              {finding.asset && (
                <span className="flex items-center gap-1 font-mono text-cyan-400">
                  <Server className="h-3 w-3" />
                  {finding.asset}
                </span>
              )}
            </div>
            {finding.description && (
              <p className="text-xs text-muted-foreground mt-1.5 line-clamp-3">{finding.description}</p>
            )}
            {finding.remediation && (
              <div className="mt-2 text-xs flex items-start gap-1.5 text-green-400/80">
                <ShieldCheck className="h-3 w-3 mt-0.5 flex-shrink-0" />
                <span>{finding.remediation}</span>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Feedback Scan Card ───────────────────────────────────────────────────────

const TOOL_COLORS: Record<string, string> = {
  nmap: "text-cyan-400 border-cyan-500/30",
  nikto: "text-yellow-400 border-yellow-500/30",
  nuclei: "text-purple-400 border-purple-500/30",
  gobuster: "text-orange-400 border-orange-500/30",
  ffuf: "text-orange-400 border-orange-500/30",
  sslscan: "text-green-400 border-green-500/30",
  testssl: "text-green-400 border-green-500/30",
  whatweb: "text-blue-400 border-blue-500/30",
  subfinder: "text-cyan-400 border-cyan-500/30",
  httpx: "text-blue-400 border-blue-500/30",
  curl: "text-muted-foreground border-muted-foreground/30",
  wpscan: "text-indigo-400 border-indigo-500/30",
  cloud_enum: "text-orange-400 border-orange-500/30",
  s3scanner: "text-orange-400 border-orange-500/30",
  trufflehog: "text-red-400 border-red-500/30",
  aws: "text-orange-400 border-orange-500/30",
  dig: "text-cyan-400 border-cyan-500/30",
  whois: "text-muted-foreground border-muted-foreground/30",
  katana: "text-red-400 border-red-500/30",
  gospider: "text-blue-400 border-blue-500/30",
  waybackurls: "text-amber-400 border-amber-500/30",
  gau: "text-amber-400 border-amber-500/30",
  naabu: "text-cyan-400 border-cyan-500/30",
};

function FeedbackScanCard({ scan, index }: { scan: any; index: number }) {
  const [showOutput, setShowOutput] = useState(false);
  const toolColor = TOOL_COLORS[scan.tool] || "text-muted-foreground border-muted-foreground/30";
  const success = scan.exitCode === 0;

  return (
    <Card className={`bg-card/50 ${success ? 'border-green-500/10' : 'border-red-500/10'}`}>
      <Collapsible open={showOutput} onOpenChange={setShowOutput}>
        <CollapsibleTrigger asChild>
          <CardContent className="p-3 cursor-pointer hover:bg-muted/10 transition-colors">
            <div className="flex items-center gap-2">
              <div className={`flex items-center justify-center w-6 h-6 rounded text-[10px] font-bold ${success ? 'bg-green-500/10 text-green-400 border border-green-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                {index + 1}
              </div>
              <Badge variant="outline" className={`text-[10px] font-mono px-1.5 ${toolColor}`}>
                <Wrench className="h-2.5 w-2.5 mr-0.5" />
                {scan.tool}
              </Badge>
              <span className="text-xs font-mono text-cyan-400 truncate">{scan.target}</span>
              {scan.depth && (
                <Badge variant="secondary" className="text-[9px] px-1">{scan.depth}</Badge>
              )}
              <div className="ml-auto flex items-center gap-2">
                {scan.durationMs && (
                  <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                    <Timer className="h-2.5 w-2.5" />
                    {(scan.durationMs / 1000).toFixed(1)}s
                  </span>
                )}
                {success ? (
                  <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />
                ) : (
                  <XCircle className="h-3.5 w-3.5 text-red-400" />
                )}
                <ChevronDown className={`h-3 w-3 text-muted-foreground transition-transform ${showOutput ? 'rotate-180' : ''}`} />
              </div>
            </div>
            {scan.rationale && (
              <p className="text-[11px] text-muted-foreground mt-1.5 ml-8 line-clamp-2">
                <Brain className="h-3 w-3 inline mr-1 text-purple-400" />
                {scan.rationale}
              </p>
            )}
          </CardContent>
        </CollapsibleTrigger>

        <CollapsibleContent>
          <div className="px-3 pb-3 space-y-2">
            {scan.args && (
              <div className="text-[10px]">
                <span className="text-muted-foreground">Command args: </span>
                <code className="text-cyan-400 font-mono bg-muted/30 px-1 py-0.5 rounded">{scan.args}</code>
              </div>
            )}
            {scan.outputPreview && (
              <div className="bg-black/30 rounded border border-border/20 p-2 max-h-48 overflow-y-auto">
                <pre className="text-[10px] text-green-400/80 font-mono whitespace-pre-wrap break-all">{scan.outputPreview}</pre>
              </div>
            )}
            {scan.stderrPreview && (
              <div className="bg-red-500/5 rounded border border-red-500/10 p-2 max-h-24 overflow-y-auto">
                <pre className="text-[10px] text-red-400/80 font-mono whitespace-pre-wrap break-all">{scan.stderrPreview}</pre>
              </div>
            )}
          </div>
        </CollapsibleContent>
      </Collapsible>
    </Card>
  );
}
