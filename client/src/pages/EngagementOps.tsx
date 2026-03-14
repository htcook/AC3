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
 * 7. Red Team: C2 agent deploy → Cyber C2 callback → pivot
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
import { CodeViewer } from "@/components/CodeViewer";
import { VulnTrendChart } from "@/components/VulnTrendChart";
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
  ScanEye, ShieldOff, Bolt, TrendingUp, BarChart3, Scan, Microscope,
} from "lucide-react";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Checkbox } from "@/components/ui/checkbox";
import { KpiStrip } from "@/components/KpiStrip";
import type { KpiItem } from "@/components/KpiStrip";
import { TabGroupNav } from "@/components/TabGroupNav";
import type { TabGroup } from "@/components/TabGroupNav";
import { FindingStateBadge } from "@/components/FindingStateBadge";
import { VulnDetailDrawer, ZapFindingDetailDrawer } from "@/components/FindingDetailDrawer";
import type { VulnFinding, ZapFinding as ZapFindingType } from "@/components/FindingDetailDrawer";
import EngagementTerminal from "@/components/EngagementTerminal";

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
  vulns: Array<{
    id: string; severity: string; title: string; cve?: string;
    corroborationTier?: string; detectedVersion?: string | null;
    affectedVersions?: string | null; versionMatchConfirmed?: boolean;
    evidenceDetail?: string | null; cvssScore?: number | null;
  }>;
  zapFindings: Array<{ alert: string; risk: string; url: string; cweId?: number }>;
  exploitAttempts: Array<{
    module: string; success: boolean; sessionId?: string;
    cve?: string; service?: string; port?: number; target?: string;
    confidence?: number; reasoning?: string;
    selectedExploit?: { modulePath?: string; payload?: string; options?: Record<string, any> };
    timestamp?: number; durationMs?: number; errorDetail?: string;
  }>;
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

// ─── Exploit Plan Review Card (with Modify Plan) ─────────────────────────────

function ExploitPlanReviewCard({
  gate,
  planActions,
  approveMut,
}: {
  gate: any;
  planActions: Array<{ target: string; port: string | number; cve?: string; module?: string; service?: string }>;
  approveMut: any;
}) {
  const [isModifying, setIsModifying] = useState(false);
  const [enabledTargets, setEnabledTargets] = useState<boolean[]>(() => planActions.map(() => true));

  const enabledCount = enabledTargets.filter(Boolean).length;
  const removedCount = planActions.length - enabledCount;
  const allEnabled = enabledCount === planActions.length;
  const noneEnabled = enabledCount === 0;

  const toggleTarget = (index: number) => {
    setEnabledTargets(prev => {
      const next = [...prev];
      next[index] = !next[index];
      return next;
    });
  };

  const toggleAll = () => {
    if (allEnabled) {
      setEnabledTargets(planActions.map(() => false));
    } else {
      setEnabledTargets(planActions.map(() => true));
    }
  };

  const handleApproveSelected = () => {
    const removedIndices = enabledTargets
      .map((enabled, i) => (!enabled ? i : -1))
      .filter(i => i !== -1);
    approveMut.mutate({
      gateId: gate.id,
      approved: true,
      removedTargetIndices: removedIndices.length > 0 ? removedIndices : undefined,
    });
  };

  return (
    <div className="bg-card/60 rounded-xl border border-red-500/30 overflow-hidden">
      {/* Header */}
      <div className="px-5 py-3 bg-red-500/10 border-b border-red-500/20 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Swords className="h-4 w-4 text-red-400" />
          {riskBadge(gate.riskTier)}
          <span className="text-sm font-semibold text-foreground">{gate.title}</span>
        </div>
        <span className="text-xs text-muted-foreground">{formatTime(gate.createdAt)}</span>
      </div>

      {/* LLM Reasoning */}
      {gate.detail?.reasoning && (
        <div className="px-5 py-3 border-b border-border/30">
          <div className="flex items-center gap-1.5 text-xs text-cyan-400 font-medium mb-1">
            <Brain className="h-3 w-3" /> LLM Reasoning
          </div>
          <p className="text-xs text-muted-foreground leading-relaxed">{gate.detail.reasoning}</p>
        </div>
      )}

      {/* Exploit Actions Table */}
      <div className="px-5 py-3">
        <div className="flex items-center justify-between mb-2">
          <div className="text-xs text-muted-foreground font-medium">
            {isModifying ? (
              <span>
                <span className="text-green-400">{enabledCount}</span> of {planActions.length} targets selected
                {removedCount > 0 && <span className="text-red-400 ml-1">({removedCount} removed)</span>}
              </span>
            ) : (
              <span>{planActions.length} exploit action{planActions.length !== 1 ? "s" : ""} selected:</span>
            )}
          </div>
          {isModifying && (
            <button
              className="text-[10px] text-cyan-400 hover:text-cyan-300 underline"
              onClick={toggleAll}
            >
              {allEnabled ? "Deselect All" : "Select All"}
            </button>
          )}
        </div>
        <div className="space-y-1.5">
          {planActions.map((a, i) => {
            const isEnabled = enabledTargets[i];
            return (
              <div
                key={i}
                className={`flex items-center gap-3 rounded-lg px-3 py-2 border transition-all ${
                  isModifying
                    ? isEnabled
                      ? "bg-background/50 border-border/30 cursor-pointer hover:border-green-500/30"
                      : "bg-red-500/5 border-red-500/20 opacity-60 cursor-pointer hover:border-red-500/40"
                    : "bg-background/50 border-border/30"
                }`}
                onClick={isModifying ? () => toggleTarget(i) : undefined}
              >
                {isModifying && (
                  <Checkbox
                    checked={isEnabled}
                    onCheckedChange={() => toggleTarget(i)}
                    className="data-[state=checked]:bg-green-600 data-[state=checked]:border-green-600"
                  />
                )}
                <span className="text-xs font-mono text-muted-foreground w-5">{i + 1}.</span>
                <div className="flex items-center gap-1.5 min-w-0 flex-1">
                  <Crosshair className={`h-3 w-3 flex-none ${isModifying && !isEnabled ? 'text-red-400/50' : 'text-red-400'}`} />
                  <span className={`text-xs font-mono truncate ${isModifying && !isEnabled ? 'text-muted-foreground line-through' : 'text-foreground'}`}>
                    {a.target}:{a.port}
                  </span>
                </div>
                {(a.cve || a.module) && (
                  <Badge variant="outline" className={`text-[10px] flex-none ${isModifying && !isEnabled ? 'bg-gray-500/10 text-gray-500 border-gray-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20'}`}>
                    {a.cve || a.module}
                  </Badge>
                )}
                {a.service && (
                  <span className={`text-[10px] flex-none ${isModifying && !isEnabled ? 'text-muted-foreground/50' : 'text-muted-foreground'}`}>{a.service}</span>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Action Buttons */}
      <div className="px-5 py-3 bg-muted/20 border-t border-border/30">
        {isModifying ? (
          <div className="flex items-center justify-between">
            <p className="text-[10px] text-muted-foreground">
              Toggle targets on/off. Disabled targets will be skipped during exploitation.
            </p>
            <div className="flex items-center gap-2 ml-4 flex-none">
              <Button
                size="sm"
                variant="outline"
                className="border-border/50 text-muted-foreground hover:bg-muted/30"
                onClick={() => {
                  setIsModifying(false);
                  setEnabledTargets(planActions.map(() => true));
                }}
              >
                Cancel
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="border-red-500/30 text-red-400 hover:bg-red-500/10"
                onClick={() => approveMut.mutate({ gateId: gate.id, approved: false })}
                disabled={approveMut.isPending}
              >
                <XCircle className="h-3.5 w-3.5 mr-1" /> Reject All
              </Button>
              <Button
                size="sm"
                className="bg-green-600 hover:bg-green-500 text-white"
                onClick={handleApproveSelected}
                disabled={approveMut.isPending || noneEnabled}
              >
                <CheckCircle2 className="h-3.5 w-3.5 mr-1" />
                {allEnabled ? "Approve All" : `Approve ${enabledCount} Target${enabledCount !== 1 ? 's' : ''}`}
              </Button>
            </div>
          </div>
        ) : (
          <div className="flex items-center justify-between">
            <p className="text-[10px] text-muted-foreground">Review the plan above. Approving will execute all listed exploits against in-scope targets.</p>
            <div className="flex items-center gap-2 ml-4 flex-none">
              <Button
                size="sm"
                variant="outline"
                className="border-red-500/30 text-red-400 hover:bg-red-500/10"
                onClick={() => approveMut.mutate({ gateId: gate.id, approved: false })}
                disabled={approveMut.isPending}
              >
                <XCircle className="h-3.5 w-3.5 mr-1" /> Reject Plan
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="border-amber-500/30 text-amber-400 hover:bg-amber-500/10"
                onClick={() => setIsModifying(true)}
              >
                <Wrench className="h-3.5 w-3.5 mr-1" /> Modify Plan
              </Button>
              <Button
                size="sm"
                className="bg-red-600 hover:bg-red-500 text-white"
                onClick={() => approveMut.mutate({ gateId: gate.id, approved: true })}
                disabled={approveMut.isPending}
              >
                <Swords className="h-3.5 w-3.5 mr-1" /> Approve & Execute
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Feed Entry Renderer ──────────────────────────────────────────────────────────────

function renderFeedEntry(entry: OpsLogEntry) {
  const hasEvidence = entry.data && (
    entry.type === 'llm_decision' || entry.type === 'tool_match' ||
    entry.type === 'exploit_success' || entry.type === 'credential_test' ||
    entry.type === 'phase_complete' || entry.data.output || entry.data.command ||
    entry.data.findings || entry.data.reasoning || entry.data.tools
  );
  return (
    <Collapsible key={entry.id}>
      <div
        className={`rounded-md text-sm transition-colors ${
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
        <CollapsibleTrigger className="w-full text-left">
          <div className="flex items-start gap-2 px-3 py-2">
            <span className="flex-none mt-0.5">{logIcon(entry.type)}</span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-medium text-foreground">{entry.title}</span>
                {riskBadge(entry.riskTier)}
                {entry.data?.target && (
                  <Badge variant="outline" className="text-[9px] text-muted-foreground border-border/50 font-mono">{entry.data.target}</Badge>
                )}
                {hasEvidence && (
                  <ChevronDown className="h-3 w-3 text-muted-foreground/50 ml-auto flex-none" />
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">{entry.detail}</p>
            </div>
            <span className="flex-none text-[10px] text-muted-foreground/50 tabular-nums">
              {formatTime(entry.timestamp)}
            </span>
          </div>
        </CollapsibleTrigger>
        {hasEvidence && (
          <CollapsibleContent>
            <div className="px-3 pb-2 ml-6 space-y-1.5 border-t border-border/20 pt-1.5">
              {entry.data?.reasoning && (
                <div className="text-xs text-cyan-400/80 bg-cyan-500/5 rounded px-2 py-1">
                  <span className="text-[10px] text-muted-foreground uppercase font-medium block mb-0.5">LLM Reasoning</span>
                  {entry.data.reasoning}
                </div>
              )}
              {entry.data?.tools && (
                <div className="flex flex-wrap gap-1">
                  <span className="text-[10px] text-muted-foreground mr-1">Tools:</span>
                  {(entry.data.tools as string[]).map((tool, i) => (
                    <Badge key={i} variant="outline" className="text-[9px] text-purple-400 border-purple-500/30">{tool}</Badge>
                  ))}
                </div>
              )}
              {entry.data?.command && (
                <div className="bg-black/30 rounded px-2 py-1">
                  <span className="text-[10px] text-muted-foreground uppercase font-medium block mb-0.5">Command</span>
                  <code className="text-[10px] text-green-400 font-mono break-all">{entry.data.command}</code>
                </div>
              )}
              {entry.data?.output && (
                <div className="bg-black/30 rounded px-2 py-1 max-h-32 overflow-y-auto">
                  <span className="text-[10px] text-muted-foreground uppercase font-medium block mb-0.5">Output</span>
                  <pre className="text-[10px] text-green-400/80 font-mono whitespace-pre-wrap break-all">{String(entry.data.output).slice(0, 500)}</pre>
                </div>
              )}
              {entry.data?.findings && Array.isArray(entry.data.findings) && entry.data.findings.length > 0 && (
                <div>
                  <span className="text-[10px] text-muted-foreground uppercase font-medium block mb-0.5">Findings ({entry.data.findings.length})</span>
                  <div className="space-y-0.5">
                    {(entry.data.findings as Array<{severity?: string; title?: string; cve?: string}>).slice(0, 5).map((f, i) => (
                      <div key={i} className="flex items-center gap-1.5 text-[10px]">
                        {f.severity && <FindingStateBadge state={f.severity} size="sm" />}
                        <span className="text-foreground">{f.title || 'Unnamed finding'}</span>
                        {f.cve && <code className="text-red-400 font-mono">{f.cve}</code>}
                      </div>
                    ))}
                    {entry.data.findings.length > 5 && (
                      <span className="text-[10px] text-muted-foreground">...and {entry.data.findings.length - 5} more</span>
                    )}
                  </div>
                </div>
              )}
              {entry.data?.durationMs && (
                <span className="text-[10px] text-muted-foreground font-mono">Duration: {entry.data.durationMs}ms</span>
              )}
            </div>
          </CollapsibleContent>
        )}
      </div>
    </Collapsible>
  );
}

// ─── Component ────────────────────────────────────────────────────────────────────────

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

  // ── Finding detail drawer state ──
  const [selectedVulnDetail, setSelectedVulnDetail] = useState<VulnFinding | null>(null);
  const [selectedZapDetail, setSelectedZapDetail] = useState<ZapFindingType | null>(null);
  const [detailAssetHostname, setDetailAssetHostname] = useState<string | undefined>(undefined);

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
  const [selectedScanMode, setSelectedScanMode] = useState<'strict_passive' | 'standard' | 'active'>('strict_passive');
  const [feedGroupBy, setFeedGroupBy] = useState<'none' | 'host' | 'phase' | 'type'>('none');
  const [feedFilter, setFeedFilter] = useState<string>('all');
  const [showScanModePopover, setShowScanModePopover] = useState(false);

  // Sync scan mode from engagement data once loaded
  useEffect(() => {
    if ((engagementQ.data as any)?.scanMode) {
      setSelectedScanMode((engagementQ.data as any).scanMode);
    }
  }, [(engagementQ.data as any)?.scanMode]);

  const scanModesQ = trpc.engagementOps.getScanModes.useQuery(undefined, { enabled: engagementId > 0 });
  const planHistoryQ = trpc.engagementOps.getExploitPlanHistory.useQuery({ engagementId }, { enabled: engagementId > 0 });
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

  // ── Full Pipeline Re-Run ──
  const [showRerunDialog, setShowRerunDialog] = useState(false);
  const [rerunPhases, setRerunPhases] = useState({ passive: true, active: true, llmAnalysis: true, exploitGeneration: true });
  const rerunMut = trpc.engagementOps.rerunFullPipeline.useMutation({
    onSuccess: (data) => {
      toast.success(`Full pipeline re-run started for engagement #${data.engagementId}`);
      setShowRerunDialog(false);
      opsStateQ.refetch();
    },
    onError: (e) => toast.error(`Re-run failed: ${e.message}`),
  });

  // ── Functional Exploit Generation ──
  const [showExploitGen, setShowExploitGen] = useState(false);
  const [selectedExploitAsset, setSelectedExploitAsset] = useState('');
  const [selectedVulnIdx, setSelectedVulnIdx] = useState<number | undefined>(undefined);
  const [exploitLang, setExploitLang] = useState<'python' | 'bash' | 'powershell' | 'ruby'>('python');
  const [includeEvasion, setIncludeEvasion] = useState(false);
  const generatedExploitsQ = trpc.engagementOps.getGeneratedExploits.useQuery(
    { engagementId },
    { enabled: engagementId > 0 }
  );
  const genExploitMut = trpc.engagementOps.generateFunctionalExploit.useMutation({
    onSuccess: (data) => {
      toast.success(`Exploit generated: ${data.filename} (${data.confidence}% confidence)`);
      generatedExploitsQ.refetch();
    },
    onError: (e) => toast.error(`Exploit generation failed: ${e.message}`),
  });
  const validateExploitMut = trpc.engagementOps.validateExploit.useMutation({
    onSuccess: (data) => {
      if (data.isValid) {
        toast.success(`Exploit validated: ${data.overallAssessment}`);
      } else {
        toast.error(`Validation issues found: ${data.issues?.length || 0} issues`);
      }
    },
    onError: (e) => toast.error(`Validation failed: ${e.message}`),
  });
  const improveExploitMut = trpc.engagementOps.improveExploit.useMutation({
    onSuccess: () => {
      toast.success('Exploit improved successfully');
      generatedExploitsQ.refetch();
    },
    onError: (e) => toast.error(`Improvement failed: ${e.message}`),
  });
  const [viewingExploitIdx, setViewingExploitIdx] = useState<number | null>(null);
  const exploitDetailQ = trpc.engagementOps.getExploitDetail.useQuery(
    { engagementId, exploitIndex: viewingExploitIdx ?? 0 },
    { enabled: viewingExploitIdx !== null }
  );

  // ── Targeted Re-Synthesis ──
  const [resynthTarget, setResynthTarget] = useState<string | null>(null);
  const [execExploitIdx, setExecExploitIdx] = useState<number | null>(null);
  const [execDryRun, setExecDryRun] = useState(true);
  const [execResult, setExecResult] = useState<any>(null);
  // ── Terminal ──
  const [terminalOpen, setTerminalOpen] = useState(false);
  const [exploitShellContext, setExploitShellContext] = useState<any>(null);
  const executeExploitMut = trpc.engagementOps.executeExploit.useMutation({
    onSuccess: (data) => { setExecResult(data); toast({ title: data.status === 'success' ? 'Exploit executed successfully' : `Execution ${data.status}`, description: `Exit code: ${data.exitCode} | Duration: ${data.durationMs}ms${data.dryRun ? ' (dry run)' : ''}` }); },
    onError: (err) => toast({ title: 'Execution failed', description: err.message, variant: 'destructive' }),
  });
  const execHistoryQ = trpc.engagementOps.getExploitExecutionHistory.useQuery({ engagementId }, { enabled: !!engagementId });
  const [resynthCategories, setResynthCategories] = useState<string[]>([]);
  const [resynthReplace, setResynthReplace] = useState(false);
  const resynthMut = trpc.engagementOps.resynthesizeAssetVulns.useMutation({
    onSuccess: (data) => {
      toast.success(`Re-synthesis complete: ${data.newVulns.length} new vulns for ${data.hostname} (${data.totalVulns} total)`);
      opsQ.refetch();
      setResynthTarget(null);
      setResynthCategories([]);
    },
    onError: (e) => toast.error(`Re-synthesis failed: ${e.message}`),
  });

  // ── Vulnerability Trend Tracking ──
  const vulnTrendQ = trpc.engagementOps.getVulnTrend.useQuery(
    { engagementId },
    { enabled: engagementId > 0, refetchInterval: 30000 }
  );
  const recordSnapshotMut = trpc.engagementOps.recordScanSnapshot.useMutation({
    onSuccess: (data) => {
      toast.success(`Snapshot recorded: ${data.totalVulns} vulns (${data.newVulnsFound} new, ${data.resolvedVulns} resolved)`);
      vulnTrendQ.refetch();
    },
    onError: (e) => toast.error(`Snapshot failed: ${e.message}`),
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
  const [liveOwaspCoverage, setLiveOwaspCoverage] = useState<any>(null);
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

    // OWASP coverage real-time update
    if (evtData.type === "owasp_coverage_update" && evtData.owaspCoverage) {
      setLiveOwaspCoverage(evtData.owaspCoverage);
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
    // Ensure required arrays exist (defensive against stale DB snapshots)
    if (!Array.isArray(base.log)) base.log = [];
    if (!Array.isArray(base.assets)) base.assets = [];
    if (!Array.isArray(base.approvalGates)) base.approvalGates = [];
    // Ensure stats object with all required fields
    const defaultStats = { hostsScanned: 0, portsFound: 0, vulnsFound: 0, exploitsAttempted: 0, exploitsSucceeded: 0, sessionsOpened: 0, zapScansRun: 0, wafDetections: 0 };
    base.stats = { ...defaultStats, ...(base.stats || {}) };
    // Ensure each asset has required sub-arrays (prevents .map/.filter crashes)
    for (const asset of base.assets) {
      if (!Array.isArray((asset as any).vulns)) (asset as any).vulns = [];
      if (!Array.isArray((asset as any).toolResults)) (asset as any).toolResults = [];
      if (!Array.isArray((asset as any).ports)) (asset as any).ports = [];
      if (!Array.isArray((asset as any).zapFindings)) (asset as any).zapFindings = [];
      if (!Array.isArray((asset as any).exploitAttempts)) (asset as any).exploitAttempts = [];
    }
    // Ensure boolean/string fields
    if (typeof base.isRunning !== 'boolean') base.isRunning = false;
    if (typeof base.isPaused !== 'boolean') base.isPaused = false;
    if (!base.phase) base.phase = 'idle';
    if (typeof base.progress !== 'number') base.progress = 0;
    // Merge WS log entries
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

            {/* ── Supplemental Scan Tools ── */}
            <div className="flex items-center gap-1 ml-2 border-l border-border/30 pl-2">
              <a href={`/web-app-scanner?engagementId=${engagementId}`}>
                <Button variant="ghost" size="sm" className="text-emerald-400 hover:text-emerald-300 hover:bg-emerald-500/10 text-xs h-8" title="Open Web App Scanner for supplemental testing">
                  <Scan className="h-3.5 w-3.5 mr-1" /> Scan Tools
                </Button>
              </a>
              <a href={`/nuclei-scanner?engagementId=${engagementId}`}>
                <Button variant="ghost" size="sm" className="text-emerald-400 hover:text-emerald-300 hover:bg-emerald-500/10 text-xs h-8" title="Run Nuclei templates against targets">
                  <Microscope className="h-3.5 w-3.5 mr-1" /> Nuclei
                </Button>
              </a>
            </div>
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

      {/* ── KPI Mission Posture Strip ── */}
      {ops && (() => {
        // Compute actual vuln counts from asset data (more accurate than stats counter which can desync)
        const actualVulnCount = (ops.assets || []).reduce((sum: number, a: any) => sum + (a.vulns || []).length, 0);
        const zapFindingCount = (ops.assets || []).reduce((sum: number, a: any) => sum + (a.zapFindings || []).length, 0);
        const totalVulns = actualVulnCount + zapFindingCount;
        const criticalVulns = (ops.assets || []).reduce((sum: number, a: any) => sum + (a.vulns || []).filter((v: any) => v.severity === 'critical').length, 0) + (ops.assets || []).reduce((sum: number, a: any) => sum + (a.zapFindings || []).filter((f: any) => f.risk === 'High').length, 0);
        const highVulns = (ops.assets || []).reduce((sum: number, a: any) => sum + (a.vulns || []).filter((v: any) => v.severity === 'high').length, 0) + (ops.assets || []).reduce((sum: number, a: any) => sum + (a.zapFindings || []).filter((f: any) => f.risk === 'Medium').length, 0);

        // Delta comparison: use the last vuln trend snapshot as the baseline
        const trendData = vulnTrendQ.data as any[] | undefined;
        const lastSnapshot = trendData && trendData.length > 0 ? trendData[trendData.length - 1] : null;
        const prevVulns = lastSnapshot?.totalVulns ?? null;
        const prevAssets = lastSnapshot?.assets ?? null;
        const prevPorts = lastSnapshot?.ports ?? null;
        const prevExploits = lastSnapshot?.exploits ?? null;

        // Compute deltas (current - previous snapshot)
        const vulnDelta = prevVulns != null ? totalVulns - prevVulns : null;
        const vulnDeltaPct = prevVulns != null && prevVulns > 0 ? ((vulnDelta! / prevVulns) * 100) : null;
        const assetCount = ops.assets?.length || 0;
        const assetDelta = prevAssets != null ? assetCount - prevAssets : null;
        const assetDeltaPct = prevAssets != null && prevAssets > 0 ? ((assetDelta! / prevAssets) * 100) : null;
        const portDelta = prevPorts != null ? (ops.stats?.portsFound || 0) - prevPorts : null;
        const exploitDelta = prevExploits != null ? (ops.stats?.exploitsSucceeded || 0) - prevExploits : null;

        const snapshotLabel = lastSnapshot ? `vs. snapshot ${new Date(lastSnapshot.date).toLocaleTimeString()}` : undefined;

        const kpiItems: KpiItem[] = [
          { label: 'Assets Discovered', value: assetCount, icon: <Globe className="h-4 w-4 text-emerald-400" />, color: 'text-emerald-400', delta: assetDelta, deltaPercent: assetDeltaPct, subtitle: snapshotLabel },
          { label: 'Hosts Scanned', value: ops.stats?.hostsScanned || 0, icon: <Server className="h-4 w-4 text-cyan-400" />, color: 'text-cyan-400' },
          { label: 'Open Ports', value: (ops.assets || []).reduce((sum: number, a: any) => sum + (a.ports || []).length, 0) || ops.stats?.portsFound || 0, icon: <Network className="h-4 w-4 text-blue-400" />, color: 'text-blue-400', delta: portDelta },
          { label: 'Total Vulns', value: totalVulns, icon: <Bug className="h-4 w-4 text-yellow-400" />, color: totalVulns > 0 ? 'text-yellow-400' : 'text-foreground', delta: vulnDelta, deltaPercent: vulnDeltaPct, deltaInverted: true, subtitle: criticalVulns > 0 ? `${criticalVulns} critical, ${highVulns} high` : snapshotLabel },
          { label: 'Exploits Succeeded', value: ops.stats?.exploitsSucceeded || 0, icon: <Skull className="h-4 w-4 text-red-500" />, color: (ops.stats?.exploitsSucceeded || 0) > 0 ? 'text-red-400' : 'text-foreground', delta: exploitDelta, deltaInverted: true, subtitle: `${ops.stats?.exploitsAttempted || 0} attempted` },
          { label: 'Sessions', value: ops.stats?.sessionsOpened || 0, icon: <Terminal className="h-4 w-4 text-green-400" />, color: (ops.stats?.sessionsOpened || 0) > 0 ? 'text-green-400' : 'text-foreground' },
          ...(liveOwaspCoverage ? [{ label: 'OWASP Score', value: liveOwaspCoverage.overallScore, suffix: '%', icon: <ShieldCheck className="h-4 w-4 text-purple-400" />, color: liveOwaspCoverage.overallScore >= 70 ? 'text-green-400' : liveOwaspCoverage.overallScore >= 40 ? 'text-yellow-400' : 'text-red-400', progress: liveOwaspCoverage.overallScore, progressColor: liveOwaspCoverage.overallScore >= 70 ? 'bg-green-500' : liveOwaspCoverage.overallScore >= 40 ? 'bg-yellow-500' : 'bg-red-500' }] : []),
          { label: 'WAFs Detected', value: ops.stats?.wafDetections || 0, icon: <ShieldAlert className="h-4 w-4 text-orange-400" />, color: (ops.stats?.wafDetections || 0) > 0 ? 'text-orange-400' : 'text-foreground' },
        ];
        return <KpiStrip items={kpiItems} />;
      })()}

      {/* Page Purpose Description */}
      <div className="flex-none px-6">
        <p className="page-purpose">
          Active engagement operations console for <strong className="text-foreground">{engagement?.name || 'this engagement'}</strong>. 
          This view orchestrates the full scan pipeline — from passive reconnaissance through active enumeration, 
          vulnerability detection, and exploitation — with LLM-driven decision-making and human approval gates.
        </p>
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
            {pendingApprovals.map(gate => {
              const isExploitPlan = gate.title.startsWith("Exploit Plan Review");
              const planActions = gate.detail?.actions as Array<{ target: string; port: string | number; cve?: string; module?: string; service?: string }> | undefined;

              if (isExploitPlan && planActions && planActions.length > 0) {
                // ── Rich Exploit Plan Review Card with Modify Plan ──
                return <ExploitPlanReviewCard key={gate.id} gate={gate} planActions={planActions} approveMut={approveMut} />;
              }

              // ── Standard Approval Card (per-exploit or other gates) ──
              return (
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
              );
            })}
          </div>
        </div>
      )}

      {/* ── Main Content: Three-Column Operational View ── */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left: Event Stream (always visible) + Grouped Tabs below */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Grouped Tab Navigation */}
          {(() => {
            const toolCount = (ops?.assets || []).reduce((sum: number, a: any) => sum + (a.toolResults?.length || 0), 0);
            const credTests = (ops?.assets || []).flatMap((a: any) => (a.toolResults || []).filter((tr: any) => tr.phase === 'credential_testing'));
            const credFound = credTests.filter((tr: any) => tr.findings?.length > 0).length;
            const synthCount = (ops?.assets || []).reduce((sum: number, a: any) => sum + (a.vulns || []).filter((v: any) => v.tool === 'llm-synthesis').length, 0);
            const tabGroups: TabGroup[] = [
              {
                id: 'operations',
                label: 'Operations',
                icon: <Activity className="h-3.5 w-3.5" />,
                color: 'text-cyan-400',
                subTabs: [
                  { value: 'feed', label: 'Live Feed', icon: <Activity className="h-3 w-3" />, count: ops?.log?.length || 0 },
                  { value: 'assets', label: 'Assets', icon: <Target className="h-3 w-3" />, count: ops?.assets?.length || 0 },
                  { value: 'scope', label: 'RoE & Scope', icon: <Shield className="h-3 w-3" /> },
                  { value: 'trends', label: 'Trends', icon: <TrendingUp className="h-3 w-3" /> },
                  { value: 'planhistory', label: 'Plan History', icon: <ClipboardList className="h-3 w-3" /> },
                ],
              },
              {
                id: 'discovery',
                label: 'Discovery',
                icon: <Radar className="h-3.5 w-3.5" />,
                color: 'text-purple-400',
                subTabs: [
                  { value: 'discovery', label: 'Tool Results', icon: <Radar className="h-3 w-3" />, count: toolCount },
                  { value: 'credentials', label: 'Credentials', icon: <KeyRound className="h-3 w-3" />, count: credTests.length },
                  { value: 'cloud', label: 'Cloud', icon: <Cloud className="h-3 w-3" />, count: cloudMisconfigsQ.data?.stats?.total || 0 },
                ],
              },
              {
                id: 'exploitation',
                label: 'Exploitation',
                icon: <Swords className="h-3.5 w-3.5" />,
                color: 'text-red-400',
                subTabs: [
                  { value: 'exploits', label: 'Exploit Match', icon: <Swords className="h-3 w-3" />, count: exploitsQ.data?.exploits?.length || 0 },
                  { value: 'attackchains', label: 'Attack Chains', icon: <GitBranch className="h-3 w-3" />, count: attackChainsQ.data?.chains?.length || 0 },
                  { value: 'genexploits', label: 'Exploit Code', icon: <Bolt className="h-3 w-3" />, count: generatedExploitsQ.data?.length || 0 },
                ],
              },
              {
                id: 'analysis',
                label: 'AI Analysis',
                icon: <Brain className="h-3.5 w-3.5" />,
                color: 'text-emerald-400',
                subTabs: [
                  { value: 'llmsynthesis', label: 'LLM Synthesis', icon: <Brain className="h-3 w-3" />, count: synthCount },
                  { value: 'feedback', label: 'Feedback Loop', icon: <RefreshCw className="h-3 w-3" />, count: feedbackLoopQ.data?.totalScansExecuted || 0 },
                ],
              },
            ];
            return (
              <div className="flex-none px-4 pt-2">
                <TabGroupNav groups={tabGroups} activeTab={activeTab} onTabChange={setActiveTab} />
              </div>
            );
          })()}

          <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 flex flex-col overflow-hidden">

            {/* ── Live Feed Tab ── */}
            <TabsContent value="feed" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <div className="relative h-full flex flex-col">
              {/* Event Grouping & Filter Controls */}
              <div className="flex-none flex items-center gap-2 py-2">
                <span className="text-[10px] text-muted-foreground uppercase font-medium tracking-wider">Group:</span>
                {(['none', 'host', 'phase', 'type'] as const).map(g => (
                  <button
                    key={g}
                    onClick={() => setFeedGroupBy(g)}
                    className={`text-[10px] px-2 py-0.5 rounded-md transition-colors ${
                      feedGroupBy === g ? 'bg-primary/15 text-primary ring-1 ring-primary/30' : 'text-muted-foreground hover:text-foreground hover:bg-muted/20'
                    }`}
                  >
                    {g === 'none' ? 'Timeline' : g.charAt(0).toUpperCase() + g.slice(1)}
                  </button>
                ))}
                <div className="flex-1" />
                <span className="text-[10px] text-muted-foreground uppercase font-medium tracking-wider">Filter:</span>
                <select
                  value={feedFilter}
                  onChange={(e) => setFeedFilter(e.target.value)}
                  className="text-[10px] bg-muted/20 border border-border/30 rounded px-1.5 py-0.5 text-foreground"
                >
                  <option value="all">All Events</option>
                  <option value="phase_complete">Phase Changes</option>
                  <option value="llm_decision">LLM Decisions</option>
                  <option value="tool_match">Tool Matches</option>
                  <option value="exploit_success">Exploits</option>
                  <option value="credential_test">Credentials</option>
                  <option value="error">Errors</option>
                  <option value="approval_request">Approvals</option>
                </select>
              </div>
              <div
                ref={feedScrollRef}
                className="flex-1 overflow-y-auto min-h-0 max-h-[calc(100vh-320px)] border border-border/30 rounded-lg bg-background/50"
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
                  {(() => {
                    const filtered = (ops?.log || []).filter(e => feedFilter === 'all' || e.type === feedFilter);
                    if (feedGroupBy !== 'none' && filtered.length > 0) {
                      const groups = new Map<string, typeof filtered>();
                      for (const e of filtered) {
                        const key = feedGroupBy === 'host' ? (e.data?.target || e.data?.hostname || 'Unknown')
                          : feedGroupBy === 'phase' ? (e.data?.phase || 'General')
                          : e.type;
                        if (!groups.has(key)) groups.set(key, []);
                        groups.get(key)!.push(e);
                      }
                      return Array.from(groups.entries()).map(([groupName, entries]) => (
                        <Collapsible key={groupName} defaultOpen>
                          <CollapsibleTrigger className="w-full text-left">
                            <div className="flex items-center gap-2 px-2 py-1.5 bg-muted/20 rounded-md border border-border/20 mb-1">
                              <ChevronRight className="h-3 w-3 text-muted-foreground transition-transform group-data-[state=open]:rotate-90" />
                              <span className="text-xs font-medium text-foreground">{groupName}</span>
                              <Badge variant="secondary" className="text-[9px] h-4 px-1">{entries.length}</Badge>
                            </div>
                          </CollapsibleTrigger>
                          <CollapsibleContent>
                            <div className="space-y-1 ml-3 mb-2">
                              {entries.map(entry => renderFeedEntry(entry))}
                            </div>
                          </CollapsibleContent>
                        </Collapsible>
                      ));
                    }
                    return filtered.map(entry => renderFeedEntry(entry));
                  })()}

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
                          <span>{(asset.vulns || []).length + (asset.zapFindings || []).length} findings</span>
                          {(asset.vulns || []).length > 0 && <span className="text-yellow-400">{(asset.vulns || []).length} vulns</span>}
                          {(asset.zapFindings || []).length > 0 && <span className="text-blue-400">{(asset.zapFindings || []).length} ZAP</span>}
                          {asset.toolResults?.length > 0 && <span className="text-emerald-400">{asset.toolResults.length} tools</span>}
                          {asset.passiveRecon && <span className="text-indigo-400">OSINT</span>}
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

                      {/* Vulns — sorted by most recent CVE first (year desc, number desc), then by severity */}
                      {(selectedAssetData.vulns || []).length > 0 && (
                        <div>
                          <h4 className="text-xs font-medium text-muted-foreground mb-1">Vulnerabilities ({(selectedAssetData.vulns || []).length})</h4>
                          <div className="space-y-0.5">
                            {[...(selectedAssetData.vulns || [])].sort((a: any, b: any) => {
                              // Parse CVE-YYYY-NNNNN format for sorting
                              const parseCve = (cve?: string) => {
                                if (!cve) return { year: 0, num: 0 };
                                const m = cve.match(/CVE-(\d{4})-(\d+)/i);
                                return m ? { year: parseInt(m[1]), num: parseInt(m[2]) } : { year: 0, num: 0 };
                              };
                              const aCve = parseCve(a.cve);
                              const bCve = parseCve(b.cve);
                              // Sort by year descending first
                              if (bCve.year !== aCve.year) return bCve.year - aCve.year;
                              // Then by CVE number descending (higher = more recent)
                              if (bCve.num !== aCve.num) return bCve.num - aCve.num;
                              // Fallback: severity order (critical > high > medium > low)
                              const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                              return (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5);
                            }).map((v: any, i: number) => (
                              <div key={i} className="text-xs px-2 py-1.5 bg-muted/10 rounded space-y-1 cursor-pointer hover:bg-muted/30 hover:ring-1 hover:ring-primary/20 transition-all" onClick={() => { setSelectedVulnDetail(v); setDetailAssetHostname(selectedAssetData?.hostname); }}>
                                <div className="flex items-center gap-2 flex-wrap">
                                  <Badge variant="outline" className={`text-[9px] ${
                                    v.severity === "critical" ? "text-red-400 border-red-500/30" :
                                    v.severity === "high" ? "text-orange-400 border-orange-500/30" :
                                    v.severity === "medium" ? "text-yellow-400 border-yellow-500/30" :
                                    "text-blue-400 border-blue-500/30"
                                  }`}>{v.severity}</Badge>
                                  <span className="text-foreground truncate flex-1">{v.title}</span>
                                  {v.cve && <span className="text-muted-foreground font-mono text-[10px]">{v.cve}</span>}
                                  <ChevronRight className="h-3 w-3 text-muted-foreground flex-none" />
                                </div>
                                {/* Version Confidence Indicator */}
                                {v.corroborationTier && (
                                  <div className="flex items-center gap-1.5 flex-wrap ml-0.5">
                                    <Badge variant="outline" className={`text-[8px] font-semibold ${
                                      v.corroborationTier === 'confirmed' ? 'bg-green-500/20 text-green-300 border-green-500/40' :
                                      v.corroborationTier === 'probable' ? 'bg-blue-500/20 text-blue-300 border-blue-500/40' :
                                      'bg-zinc-500/20 text-zinc-400 border-zinc-500/40'
                                    }`}>
                                      {v.corroborationTier === 'confirmed' ? '\u2713 CONFIRMED' :
                                       v.corroborationTier === 'probable' ? '\u223c PROBABLE' : '? POTENTIAL'}
                                    </Badge>
                                    {v.detectedVersion && (
                                      <span className="text-[9px] font-mono text-emerald-400" title={v.evidenceDetail || undefined}>
                                        v{v.detectedVersion}
                                        {v.affectedVersions && (
                                          <span className="text-muted-foreground"> in {v.affectedVersions}</span>
                                        )}
                                      </span>
                                    )}
                                    {v.cvssScore != null && v.cvssScore > 0 && !v.essEnrichment && (
                                      <span className={`text-[9px] font-mono ${
                                        v.cvssScore >= 9 ? 'text-red-400' :
                                        v.cvssScore >= 7 ? 'text-orange-400' :
                                        v.cvssScore >= 4 ? 'text-yellow-400' : 'text-blue-400'
                                      }`} title="CVSS base score">
                                        CVSS:{v.cvssScore}
                                      </span>
                                    )}
                                  </div>
                                )}
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
                            {(selectedAssetData.zapFindings || []).map((f: any, i: number) => (
                              <div key={i} className="flex items-center gap-2 text-xs px-2 py-1 bg-muted/10 rounded cursor-pointer hover:bg-muted/30 hover:ring-1 hover:ring-primary/20 transition-all" onClick={() => { setSelectedZapDetail(f); setDetailAssetHostname(selectedAssetData?.hostname); }}>
                                <Badge variant="outline" className={`text-[9px] ${
                                  f.risk === "High" ? "text-red-400 border-red-500/30" :
                                  f.risk === "Medium" ? "text-yellow-400 border-yellow-500/30" :
                                  "text-blue-400 border-blue-500/30"
                                }`}>{f.risk}</Badge>
                                <span className="text-foreground truncate flex-1">{f.alert}</span>
                                <ChevronRight className="h-3 w-3 text-muted-foreground flex-none" />
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
                                     {[...(tr.findings || [])].sort((a: any, b: any) => {
                                       const parseCve = (cve?: string) => { if (!cve) return { year: 0, num: 0 }; const m = cve.match(/CVE-(\d{4})-(\d+)/i); return m ? { year: parseInt(m[1]), num: parseInt(m[2]) } : { year: 0, num: 0 }; };
                                       const ac = parseCve(a.cve), bc = parseCve(b.cve);
                                       if (bc.year !== ac.year) return bc.year - ac.year;
                                       if (bc.num !== ac.num) return bc.num - ac.num;
                                       const so: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                                       return (so[a.severity] ?? 5) - (so[b.severity] ?? 5);
                                     }).slice(0, 8).map((f, fi) => (
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
                          <h4 className="text-xs font-medium text-red-400 mb-2 flex items-center gap-1">
                            <Crosshair className="h-3 w-3" /> Exploit Attempts ({(selectedAssetData.exploitAttempts || []).length})
                          </h4>
                          <div className="space-y-2">
                            {(selectedAssetData.exploitAttempts || []).map((e, i) => (
                              <div key={i} className="border border-border/20 rounded-md p-2 bg-muted/5 space-y-1">
                                <div className="flex items-center gap-2 flex-wrap">
                                  {e.success ? <CheckCircle2 className="h-3 w-3 text-green-400" /> : <XCircle className="h-3 w-3 text-red-400" />}
                                  <span className="text-xs text-foreground font-medium">{e.module}</span>
                                  {e.cve && <span className="text-[10px] text-muted-foreground font-mono">{e.cve}</span>}
                                  {e.sessionId && <Badge variant="outline" className="text-[8px] bg-green-500/20 text-green-300 border-green-500/40">{e.sessionId}</Badge>}
                                  {e.confidence != null && (
                                    <Badge variant="outline" className={`text-[8px] ${
                                      e.confidence >= 0.7 ? 'text-green-300 border-green-500/30' :
                                      e.confidence >= 0.4 ? 'text-yellow-300 border-yellow-500/30' :
                                      'text-red-300 border-red-500/30'
                                    }`}>
                                      conf:{Math.round(e.confidence * 100)}%
                                    </Badge>
                                  )}
                                  {e.timestamp && <span className="text-[9px] text-muted-foreground ml-auto">{new Date(e.timestamp).toLocaleTimeString()}</span>}
                                </div>
                                {/* Evidence details */}
                                <div className="flex items-center gap-2 flex-wrap text-[10px]">
                                  {e.service && <span className="text-cyan-400">svc:{e.service}</span>}
                                  {e.port && <span className="text-muted-foreground font-mono">:{e.port}</span>}
                                  {e.target && <span className="text-muted-foreground">→ {e.target}</span>}
                                  {e.durationMs != null && e.durationMs > 0 && <span className="text-muted-foreground">{Math.round(e.durationMs / 1000)}s</span>}
                                </div>
                                {e.selectedExploit?.modulePath && (
                                  <p className="text-[9px] text-purple-400 font-mono truncate" title={e.selectedExploit.modulePath}>
                                    MSF: {e.selectedExploit.modulePath}
                                  </p>
                                )}
                                {e.reasoning && (
                                  <p className="text-[9px] text-muted-foreground/70 line-clamp-2">{e.reasoning}</p>
                                )}
                                {e.errorDetail && (
                                  <p className="text-[9px] text-red-400/70 line-clamp-2">⚠ {e.errorDetail}</p>
                                )}
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
                                      <div className="bg-black/30 rounded px-2 py-1 font-mono text-[9px] text-green-300/80 whitespace-pre-wrap break-all">
                                        $ {tr.command}
                                      </div>
                                    )}
                                    {tr.findings && (tr.findings || []).length > 0 && (
                                      <div className="space-y-0.5">
                                        {[...(tr.findings || [])].sort((a: any, b: any) => {
                                          if (typeof a === 'string' || typeof b === 'string') return 0;
                                          const parseCve = (cve?: string) => { if (!cve) return { year: 0, num: 0 }; const m = cve.match(/CVE-(\d{4})-(\d+)/i); return m ? { year: parseInt(m[1]), num: parseInt(m[2]) } : { year: 0, num: 0 }; };
                                          const ac = parseCve(a?.cve), bc = parseCve(b?.cve);
                                          if (bc.year !== ac.year) return bc.year - ac.year;
                                          return bc.num - ac.num;
                                        }).slice(0, 5).map((f: any, fi: number) => {
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
                            {(attackChainsQ.data.cloudRiskAssessment.overallRisk || '').toUpperCase()} — Score: {attackChainsQ.data.cloudRiskAssessment.riskScore}/100
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

            {/* ── Plan History Tab ── */}
            {/* ── LLM Vulnerability Synthesis Tab ── */}
            <TabsContent value="llmsynthesis" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-[calc(100vh-280px)]">
                <div className="space-y-4 py-3">
                  <p className="text-xs text-muted-foreground">
                    AI-synthesized vulnerabilities derived from passive reconnaissance risk signals, port/service data, and technology fingerprints. Each vulnerability is assigned a confidence score and OWASP category.
                  </p>

                  {/* LLM Analysis Summary (attack paths + blind spots) */}
                  {(ops as any)?.llmAnalysis && (
                    <Card className="bg-card/50 border-cyan-500/20">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm flex items-center gap-2">
                          <Sparkles className="h-4 w-4 text-cyan-400" /> LLM Post-Enrichment Analysis
                        </CardTitle>
                        <CardDescription className="text-xs">
                          AI-identified attack paths and coverage blind spots from the combined scan data.
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-3">
                        {((ops as any).llmAnalysis.attackPaths || []).length > 0 && (
                          <div>
                            <h4 className="text-[10px] font-semibold text-red-400 uppercase tracking-wider mb-1">Attack Paths ({(ops as any).llmAnalysis.attackPaths.length})</h4>
                            <div className="space-y-1">
                              {((ops as any).llmAnalysis.attackPaths || []).map((ap: any, i: number) => (
                                <div key={i} className="text-xs px-3 py-2 bg-red-500/5 rounded border border-red-500/10">
                                  <div className="flex items-center gap-2 mb-1">
                                    <Badge variant="outline" className={`text-[8px] ${
                                      ap.riskLevel === 'critical' ? 'text-red-400 border-red-500/30' :
                                      ap.riskLevel === 'high' ? 'text-orange-400 border-orange-500/30' :
                                      'text-yellow-400 border-yellow-500/30'
                                    }`}>{ap.riskLevel}</Badge>
                                    <span className="font-medium text-foreground">{ap.name || ap.title || `Attack Path ${i+1}`}</span>
                                  </div>
                                  <p className="text-muted-foreground text-[10px]">{ap.description || ap.steps?.join(' → ') || ''}</p>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        {((ops as any).llmAnalysis.blindSpots || []).length > 0 && (
                          <div>
                            <h4 className="text-[10px] font-semibold text-yellow-400 uppercase tracking-wider mb-1">Coverage Blind Spots ({(ops as any).llmAnalysis.blindSpots.length})</h4>
                            <div className="space-y-1">
                              {((ops as any).llmAnalysis.blindSpots || []).map((bs: any, i: number) => (
                                <div key={i} className="flex items-center gap-2 text-xs px-3 py-1.5 bg-yellow-500/5 rounded border border-yellow-500/10">
                                  <AlertTriangle className="h-3 w-3 text-yellow-400 flex-none" />
                                  <span className="text-foreground">{typeof bs === 'string' ? bs : bs.description || bs.area || JSON.stringify(bs)}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  )}

                  {/* Per-Asset Synthesized Vulnerabilities */}
                  {(ops?.assets || []).map((asset: any) => {
                    const synthVulns = (asset.vulns || []).filter((v: any) => v.tool === 'llm-synthesis');
                    if (synthVulns.length === 0) return null;
                    return (
                      <Card key={asset.hostname} className="bg-card/50 border-emerald-500/20">
                        <CardHeader className="pb-2">
                          <div className="flex items-center justify-between">
                            <CardTitle className="text-sm flex items-center gap-2">
                              {assetIcon(asset.type)}
                              <span>{asset.hostname}</span>
                              <Badge variant="secondary" className="text-[9px] bg-emerald-500/20 text-emerald-400">
                                {synthVulns.length} synthesized
                              </Badge>
                            </CardTitle>
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 text-[10px] border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10"
                              onClick={() => {
                                setResynthTarget(asset.hostname);
                                setResynthCategories([]);
                                setResynthReplace(false);
                              }}
                            >
                              <Target className="h-3 w-3 mr-1" />
                              Re-Synthesize
                            </Button>
                          </div>
                          <CardDescription className="text-xs">
                            {(asset.passiveRecon?.riskSignals || []).length} risk signals analyzed, {(asset.ports || []).length} ports, {(asset.passiveRecon?.technologies || []).length} technologies
                          </CardDescription>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-1.5">
                            {synthVulns.sort((a: any, b: any) => {
                              const sev: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
                              return (sev[b.severity] || 0) - (sev[a.severity] || 0);
                            }).map((v: any, i: number) => (
                              <div key={i} className="text-xs px-3 py-2 bg-muted/10 rounded border border-border/20 space-y-1">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <Badge variant="outline" className={`text-[9px] ${
                                    v.severity === 'critical' ? 'text-red-400 border-red-500/30' :
                                    v.severity === 'high' ? 'text-orange-400 border-orange-500/30' :
                                    v.severity === 'medium' ? 'text-yellow-400 border-yellow-500/30' :
                                    'text-blue-400 border-blue-500/30'
                                  }`}>{v.severity}</Badge>
                                  <span className="font-medium text-foreground flex-1">{v.title}</span>
                                  {v.cve && <span className="text-muted-foreground font-mono text-[10px]">{v.cve}</span>}
                                  <Badge variant="outline" className={`text-[8px] ${
                                    v.confidence >= 90 ? 'text-green-400 border-green-500/30' :
                                    v.confidence >= 70 ? 'text-emerald-400 border-emerald-500/30' :
                                    v.confidence >= 50 ? 'text-yellow-400 border-yellow-500/30' :
                                    'text-orange-400 border-orange-500/30'
                                  }`}>{v.confidence}% conf</Badge>
                                </div>
                                <div className="flex items-center gap-2 flex-wrap">
                                  {v.confirmedByActiveScan && (
                                    <Badge variant="outline" className="text-[8px] text-green-300 border-green-500/30 bg-green-500/10">✓ confirmed</Badge>
                                  )}
                                  {v.corroborationTier && (
                                    <Badge variant="outline" className={`text-[8px] font-semibold ${
                                      v.corroborationTier === 'confirmed' ? 'bg-green-500/20 text-green-300 border-green-500/40' :
                                      v.corroborationTier === 'probable' ? 'bg-blue-500/20 text-blue-300 border-blue-500/40' :
                                      'bg-zinc-500/20 text-zinc-400 border-zinc-500/40'
                                    }`}>
                                      {v.corroborationTier === 'confirmed' ? '\u2713 VER' :
                                       v.corroborationTier === 'probable' ? '\u223c VER' : '? VER'}
                                    </Badge>
                                  )}
                                  {v.detectedVersion && (
                                    <span className="text-[9px] font-mono text-emerald-400" title={v.evidenceDetail || undefined}>
                                      v{v.detectedVersion}{v.affectedVersions ? ` in ${v.affectedVersions}` : ''}
                                    </span>
                                  )}
                                  {v.category && (
                                    <Badge variant="outline" className="text-[8px] text-cyan-300 border-cyan-500/20">{v.category.replace(/_/g, ' ')}</Badge>
                                  )}
                                  <span className="text-[10px] text-muted-foreground">{v.description?.slice(0, 120)}{v.description?.length > 120 ? '...' : ''}</span>
                                </div>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    );
                  })}

                  {/* Empty state */}
                  {(ops?.assets || []).every((a: any) => (a.vulns || []).filter((v: any) => v.tool === 'llm-synthesis').length === 0) && (
                    <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                      <Brain className="h-12 w-12 mb-4 opacity-20" />
                      <p className="text-sm">No LLM-synthesized vulnerabilities yet</p>
                      <p className="text-xs mt-1">Run the full pipeline with LLM Analysis enabled to synthesize vulnerabilities from passive recon data</p>
                    </div>
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ── Generated Exploit Code Tab ── */}
            <TabsContent value="genexploits" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-[calc(100vh-280px)]">
                <div className="space-y-4 py-3">
                  <p className="text-xs text-muted-foreground">
                    LLM-generated functional exploit scripts targeting discovered vulnerabilities. Each exploit includes confidence scoring, MITRE ATT&CK technique mapping, and can be validated or improved.
                  </p>

                  {(generatedExploitsQ.data?.length || 0) > 0 ? (
                    <>
                      {/* Summary Stats */}
                      <div className="grid grid-cols-4 gap-3">
                        <Card className="bg-card/50 border-border/30">
                          <CardContent className="p-3 text-center">
                            <div className="text-[10px] text-muted-foreground uppercase">Total Exploits</div>
                            <div className="text-lg font-bold text-red-400">{generatedExploitsQ.data!.length}</div>
                          </CardContent>
                        </Card>
                        <Card className="bg-card/50 border-border/30">
                          <CardContent className="p-3 text-center">
                            <div className="text-[10px] text-muted-foreground uppercase">Avg Confidence</div>
                            <div className="text-lg font-bold text-emerald-400">
                              {Math.round(generatedExploitsQ.data!.reduce((s: number, e: any) => s + (e.confidence || 0), 0) / generatedExploitsQ.data!.length)}%
                            </div>
                          </CardContent>
                        </Card>
                        <Card className="bg-card/50 border-border/30">
                          <CardContent className="p-3 text-center">
                            <div className="text-[10px] text-muted-foreground uppercase">Assets Covered</div>
                            <div className="text-lg font-bold text-cyan-400">
                              {new Set(generatedExploitsQ.data!.map((e: any) => e.asset)).size}
                            </div>
                          </CardContent>
                        </Card>
                        <Card className="bg-card/50 border-border/30">
                          <CardContent className="p-3 text-center">
                            <div className="text-[10px] text-muted-foreground uppercase">Languages</div>
                            <div className="text-lg font-bold text-purple-400">
                              {new Set(generatedExploitsQ.data!.map((e: any) => e.language)).size}
                            </div>
                          </CardContent>
                        </Card>
                      </div>

                      {/* Exploit Cards */}
                      {generatedExploitsQ.data!.map((exploit: any, idx: number) => (
                        <Card key={idx} className="bg-card/50 border-red-500/10 hover:border-red-500/20 transition-colors">
                          <CardContent className="p-4">
                            <div className="flex items-center justify-between mb-2">
                              <div className="flex items-center gap-2">
                                <Skull className="h-4 w-4 text-red-400" />
                                <span className="text-sm font-medium text-foreground">{exploit.filename}</span>
                                <Badge variant="outline" className={`text-[9px] ${
                                  exploit.confidence >= 80 ? 'text-green-400 border-green-500/30' :
                                  exploit.confidence >= 50 ? 'text-yellow-400 border-yellow-500/30' :
                                  'text-red-400 border-red-500/30'
                                }`}>{exploit.confidence}%</Badge>
                              </div>
                              <div className="flex items-center gap-1">
                                <Button size="sm" variant="outline" className="h-6 text-[10px] border-border/30" onClick={() => setViewingExploitIdx(idx)}>
                                  <Eye className="h-3 w-3 mr-1" /> View Code
                                </Button>
                                <Button size="sm" variant="outline" className="h-6 text-[10px] border-green-500/30 text-green-400 hover:bg-green-500/10"
                                  onClick={() => { setExecExploitIdx(idx); setExecDryRun(true); setExecResult(null); }}
                                >
                                  <Play className="h-3 w-3 mr-1" /> Execute
                                </Button>
                                <Button size="sm" variant="outline" className="h-6 text-[10px] border-border/30"
                                  onClick={() => validateExploitMut.mutate({ engagementId, exploitIndex: idx })}
                                  disabled={validateExploitMut.isPending}
                                >
                                  <Shield className="h-3 w-3 mr-1" /> Validate
                                </Button>
                                <Button size="sm" variant="outline" className="h-6 text-[10px] border-border/30"
                                  onClick={() => improveExploitMut.mutate({ engagementId, exploitIndex: idx, feedback: 'Improve reliability and add better error handling' })}
                                  disabled={improveExploitMut.isPending}
                                >
                                  <Wrench className="h-3 w-3 mr-1" /> Improve
                                </Button>
                              </div>
                            </div>
                            <div className="flex items-center gap-2 text-[10px] text-muted-foreground mb-2">
                              <span>Target: <span className="text-foreground">{exploit.asset}</span></span>
                              <span>|</span>
                              <span>Language: <span className="text-foreground">{exploit.language}</span></span>
                              {exploit.isChained && <Badge variant="outline" className="text-[8px] text-purple-400 border-purple-500/30">Chained</Badge>}
                              {exploit.generatedAt && <span className="ml-auto">{new Date(exploit.generatedAt).toLocaleString()}</span>}
                            </div>
                            <p className="text-xs text-muted-foreground">{exploit.description}</p>
                            {(exploit.mitreTechniques || []).length > 0 && (
                              <div className="flex flex-wrap gap-1 mt-2">
                                {(exploit.mitreTechniques || []).map((t: string, i: number) => (
                                  <Badge key={i} variant="outline" className="text-[8px] text-orange-300 border-orange-500/20">{t}</Badge>
                                ))}
                              </div>
                            )}
                          </CardContent>
                        </Card>
                      ))}
                    </>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
                      <Bolt className="h-12 w-12 mb-4 opacity-20" />
                      <p className="text-sm">No exploit code generated yet</p>
                      <p className="text-xs mt-1">Run the full pipeline with Exploit Generation enabled, or use the Exploit Generator in the sidebar</p>
                    </div>
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ── Vulnerability Trends Tab ── */}
            <TabsContent value="trends" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="space-y-4 py-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-semibold flex items-center gap-2">
                        <TrendingUp className="h-4 w-4 text-cyan-400" /> Vulnerability Trend Tracking
                      </h3>
                      <p className="text-[10px] text-muted-foreground mt-0.5">Track how vulnerabilities change across scan runs. Snapshots are recorded automatically after each pipeline completion.</p>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-xs"
                      onClick={() => recordSnapshotMut.mutate({ engagementId })}
                      disabled={recordSnapshotMut.isPending}
                    >
                      {recordSnapshotMut.isPending ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <BarChart3 className="h-3 w-3 mr-1" />}
                      Record Snapshot
                    </Button>
                  </div>

                  {/* Trend Chart */}
                  {vulnTrendQ.data && vulnTrendQ.data.length > 0 ? (
                    <Card className="bg-card/50 border-border/30">
                      <CardContent className="p-4">
                        <div className="h-[250px]">
                          <VulnTrendChart data={vulnTrendQ.data} />
                        </div>
                      </CardContent>
                    </Card>
                  ) : (
                    <Card className="bg-card/50 border-border/30">
                      <CardContent className="p-8 text-center">
                        <BarChart3 className="h-8 w-8 text-muted-foreground/30 mx-auto mb-2" />
                        <p className="text-xs text-muted-foreground">No trend data yet. Run the pipeline to generate the first snapshot.</p>
                      </CardContent>
                    </Card>
                  )}

                  {/* Snapshot History */}
                  {vulnTrendQ.data && vulnTrendQ.data.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-medium text-muted-foreground uppercase">Snapshot History</h4>
                      {vulnTrendQ.data.slice().reverse().map((snap: any, i: number) => (
                        <Card key={snap.id} className="bg-card/30 border-border/20">
                          <CardContent className="p-3">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <Badge variant="outline" className="text-[9px]">{snap.type.replace('_', ' ')}</Badge>
                                <span className="text-[10px] text-muted-foreground">{new Date(snap.date).toLocaleString()}</span>
                              </div>
                              <div className="flex items-center gap-3 text-[10px]">
                                <span className="text-foreground font-medium">{snap.totalVulns} vulns</span>
                                {snap.newFound > 0 && <span className="text-green-400">+{snap.newFound} new</span>}
                                {snap.resolved > 0 && <span className="text-blue-400">-{snap.resolved} resolved</span>}
                              </div>
                            </div>
                            <div className="flex gap-3 mt-2">
                              <div className="flex items-center gap-1">
                                <div className="w-2 h-2 rounded-full bg-red-500" />
                                <span className="text-[9px] text-muted-foreground">Critical: {snap.critical}</span>
                              </div>
                              <div className="flex items-center gap-1">
                                <div className="w-2 h-2 rounded-full bg-orange-500" />
                                <span className="text-[9px] text-muted-foreground">High: {snap.high}</span>
                              </div>
                              <div className="flex items-center gap-1">
                                <div className="w-2 h-2 rounded-full bg-yellow-500" />
                                <span className="text-[9px] text-muted-foreground">Medium: {snap.medium}</span>
                              </div>
                              <div className="flex items-center gap-1">
                                <div className="w-2 h-2 rounded-full bg-blue-500" />
                                <span className="text-[9px] text-muted-foreground">Low: {snap.low}</span>
                              </div>
                              <span className="text-[9px] text-muted-foreground ml-auto">{snap.ports} ports | {snap.exploits} exploits | {snap.assets} assets</span>
                            </div>
                            {/* Asset breakdown */}
                            {snap.assetBreakdown && Array.isArray(snap.assetBreakdown) && (
                              <div className="mt-2 grid grid-cols-3 gap-1">
                                {(snap.assetBreakdown as any[]).slice(0, 6).map((ab: any, j: number) => (
                                  <div key={j} className="text-[9px] bg-muted/20 rounded px-1.5 py-0.5 truncate">
                                    <span className="text-muted-foreground">{ab.hostname}:</span> {ab.vulnCount}v {ab.portCount}p
                                  </div>
                                ))}
                              </div>
                            )}
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ── Plan History Tab ── */}
            <TabsContent value="planhistory" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="space-y-4 py-4">
                  <div className="text-xs text-muted-foreground mb-2">
                    Audit trail of all exploit plans generated by the LLM, including operator decisions and modifications.
                  </div>
                  {planHistoryQ.isLoading && (
                    <div className="flex items-center justify-center py-12">
                      <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                      <span className="ml-2 text-sm text-muted-foreground">Loading plan history...</span>
                    </div>
                  )}
                  {planHistoryQ.data && planHistoryQ.data.length === 0 && (
                    <div className="text-center py-12">
                      <ClipboardList className="h-8 w-8 text-muted-foreground/30 mx-auto mb-2" />
                      <p className="text-sm text-muted-foreground">No exploit plans have been reviewed yet.</p>
                      <p className="text-xs text-muted-foreground/60 mt-1">Plans will appear here after the LLM generates an exploit strategy and you approve or reject it.</p>
                    </div>
                  )}
                  {planHistoryQ.data && planHistoryQ.data.length > 0 && (
                    <div className="space-y-3">
                      {planHistoryQ.data.map((plan: any) => {
                        const statusConfig: Record<string, { label: string; className: string; icon: React.ReactNode }> = {
                          approved: { label: "Approved", className: "bg-green-500/20 text-green-400 border-green-500/20", icon: <CheckCircle2 className="h-3 w-3" /> },
                          rejected: { label: "Rejected", className: "bg-red-500/20 text-red-400 border-red-500/20", icon: <XCircle className="h-3 w-3" /> },
                          modified: { label: "Modified", className: "bg-amber-500/20 text-amber-400 border-amber-500/20", icon: <Wrench className="h-3 w-3" /> },
                        };
                        const sc = statusConfig[plan.status] || statusConfig.approved;
                        const actions = (plan.modifiedPlan || plan.originalPlan || []) as Array<{ target: string; port: string | number; cve?: string; module?: string; service?: string }>;
                        const removedTargets = (plan.removedTargets || []) as Array<{ target: string; port: string | number; cve?: string; module?: string; service?: string }>;
                        const reviewSecs = plan.reviewDurationMs ? Math.round(plan.reviewDurationMs / 1000) : null;

                        return (
                          <div key={plan.id} className="bg-card/60 rounded-xl border border-border/30 overflow-hidden">
                            {/* Plan Header */}
                            <div className="px-4 py-3 border-b border-border/20 flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <Badge variant="outline" className={`text-[10px] ${sc.className} flex items-center gap-1`}>
                                  {sc.icon} {sc.label}
                                </Badge>
                                <span className="text-xs text-foreground font-medium">
                                  {plan.originalTargetCount} target{plan.originalTargetCount !== 1 ? 's' : ''}
                                  {plan.status === 'modified' && (
                                    <span className="text-amber-400"> → {plan.finalTargetCount} kept</span>
                                  )}
                                </span>
                              </div>
                              <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                                {reviewSecs !== null && (
                                  <span className="flex items-center gap-1"><Timer className="h-3 w-3" /> {reviewSecs}s review</span>
                                )}
                                <span>{plan.operatorName || 'Unknown'}</span>
                                <span>{plan.resolvedAt ? formatTime(new Date(plan.resolvedAt).getTime()) : formatTime(new Date(plan.createdAt).getTime())}</span>
                              </div>
                            </div>

                            {/* LLM Reasoning */}
                            {plan.llmReasoning && (
                              <div className="px-4 py-2 border-b border-border/10">
                                <div className="flex items-center gap-1.5 text-[10px] text-cyan-400 font-medium mb-1">
                                  <Brain className="h-3 w-3" /> LLM Reasoning
                                </div>
                                <p className="text-[11px] text-muted-foreground leading-relaxed">{plan.llmReasoning}</p>
                              </div>
                            )}

                            {/* Target List */}
                            <div className="px-4 py-2">
                              <div className="space-y-1">
                                {actions.map((a: any, i: number) => (
                                  <div key={i} className="flex items-center gap-2 text-xs">
                                    <Crosshair className="h-3 w-3 text-green-400 flex-none" />
                                    <span className="font-mono text-foreground">{a.target}:{a.port}</span>
                                    {(a.cve || a.module) && (
                                      <Badge variant="outline" className="text-[9px] bg-red-500/10 text-red-400 border-red-500/20">{a.cve || a.module}</Badge>
                                    )}
                                    {a.service && <span className="text-[10px] text-muted-foreground">{a.service}</span>}
                                  </div>
                                ))}
                                {removedTargets.length > 0 && (
                                  <>
                                    <div className="text-[10px] text-red-400/70 font-medium mt-2 mb-1">Removed by operator:</div>
                                    {removedTargets.map((a: any, i: number) => (
                                      <div key={`rm-${i}`} className="flex items-center gap-2 text-xs opacity-50">
                                        <XCircle className="h-3 w-3 text-red-400 flex-none" />
                                        <span className="font-mono text-muted-foreground line-through">{a.target}:{a.port}</span>
                                        {(a.cve || a.module) && (
                                          <Badge variant="outline" className="text-[9px] bg-gray-500/10 text-gray-500 border-gray-500/20">{a.cve || a.module}</Badge>
                                        )}
                                      </div>
                                    ))}
                                  </>
                                )}
                              </div>
                            </div>
                          </div>
                        );
                      })}
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
            <StatCard icon={<Activity className="h-4 w-4 text-blue-400" />} label="Open Ports" value={(ops?.assets || []).reduce((sum: number, a: any) => sum + (a.ports || []).length, 0) || ops?.stats?.portsFound || 0} />
            <StatCard icon={<Bug className="h-4 w-4 text-yellow-400" />} label="Vulns Found" value={(ops?.assets || []).reduce((sum: number, a: any) => sum + (a.vulns || []).length + (a.zapFindings || []).length, 0) || ops?.stats?.vulnsFound || 0} />
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

          {/* OWASP Coverage (live) */}
          {liveOwaspCoverage && (
            <>
              <div>
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">OWASP Coverage</h3>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">Score</span>
                    <Badge variant="outline" className={`text-xs font-mono ${
                      liveOwaspCoverage.overallScore >= 70 ? 'text-green-400 border-green-500/30' :
                      liveOwaspCoverage.overallScore >= 40 ? 'text-yellow-400 border-yellow-500/30' :
                      'text-red-400 border-red-500/30'
                    }`}>
                      {liveOwaspCoverage.overallScore}% ({liveOwaspCoverage.grade})
                    </Badge>
                  </div>
                  <div className="w-full bg-muted rounded-full h-1.5">
                    <div
                      className={`h-1.5 rounded-full transition-all duration-500 ${
                        liveOwaspCoverage.overallScore >= 70 ? 'bg-green-500' :
                        liveOwaspCoverage.overallScore >= 40 ? 'bg-yellow-500' :
                        'bg-red-500'
                      }`}
                      style={{ width: `${liveOwaspCoverage.overallScore}%` }}
                    />
                  </div>
                  <div className="grid grid-cols-3 gap-1 text-center">
                    <div className="p-1 rounded bg-green-500/10">
                      <div className="text-xs font-bold text-green-400">{liveOwaspCoverage.totalTested}</div>
                      <div className="text-[9px] text-muted-foreground">Tested</div>
                    </div>
                    <div className="p-1 rounded bg-yellow-500/10">
                      <div className="text-xs font-bold text-yellow-400">{liveOwaspCoverage.totalPartial}</div>
                      <div className="text-[9px] text-muted-foreground">Partial</div>
                    </div>
                    <div className="p-1 rounded bg-red-500/10">
                      <div className="text-xs font-bold text-red-400">{liveOwaspCoverage.totalGaps}</div>
                      <div className="text-[9px] text-muted-foreground">Gaps</div>
                    </div>
                  </div>
                  {liveOwaspCoverage.criticalGaps > 0 && (
                    <div className="text-[10px] text-red-400 flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" />
                      {liveOwaspCoverage.criticalGaps} critical gap{liveOwaspCoverage.criticalGaps > 1 ? 's' : ''}
                    </div>
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

          {/* Pipeline Re-Run */}
          <div>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Pipeline Control</h3>
            <div className="space-y-2">
              <Button
                size="sm"
                variant="outline"
                className="w-full justify-start text-xs border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10"
                onClick={() => setShowRerunDialog(true)}
                disabled={ops?.isRunning || rerunMut.isPending}
              >
                {rerunMut.isPending ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5 mr-1.5" />}
                Re-Run Full Pipeline
              </Button>
              <p className="text-[10px] text-muted-foreground leading-relaxed">
                Reset and re-execute: passive scan → LLM analysis → active scan → LLM re-scan → exploit generation
              </p>
            </div>
          </div>

          <Separator />

          {/* Functional Exploit Generator */}
          <div>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Exploit Generator</h3>
            <div className="space-y-2">
              <Button
                size="sm"
                variant="outline"
                className="w-full justify-start text-xs border-red-500/30 text-red-400 hover:bg-red-500/10"
                onClick={() => setShowExploitGen(!showExploitGen)}
              >
                <Swords className="h-3.5 w-3.5 mr-1.5" />
                {showExploitGen ? 'Hide Generator' : 'Generate Exploit Code'}
              </Button>
              {showExploitGen && (
                <div className="space-y-2 p-2 rounded-lg bg-red-500/5 border border-red-500/10">
                  <div>
                    <label className="text-[10px] text-muted-foreground block mb-1">Target Asset</label>
                    <select
                      value={selectedExploitAsset}
                      onChange={(e) => { setSelectedExploitAsset(e.target.value); setSelectedVulnIdx(undefined); }}
                      className="w-full text-xs bg-background border border-border rounded px-2 py-1.5"
                    >
                      <option value="">Select asset...</option>
                      {(ops?.assets || []).filter(a => a.vulns.length > 0).map(a => (
                        <option key={a.hostname} value={a.hostname}>{a.hostname} ({a.vulns.length} vulns)</option>
                      ))}
                    </select>
                  </div>
                  {selectedExploitAsset && (() => {
                    const asset = ops?.assets?.find(a => a.hostname === selectedExploitAsset);
                    if (!asset) return null;
                    return (
                      <div>
                        <label className="text-[10px] text-muted-foreground block mb-1">Vulnerability (optional)</label>
                        <select
                          value={selectedVulnIdx ?? ''}
                          onChange={(e) => setSelectedVulnIdx(e.target.value ? Number(e.target.value) : undefined)}
                          className="w-full text-xs bg-background border border-border rounded px-2 py-1.5"
                        >
                          <option value="">All vulns (auto-select best)</option>
                          {[...asset.vulns].map((v, origIdx) => ({ ...v, origIdx })).sort((a: any, b: any) => {
                            const parseCve = (cve?: string) => {
                              if (!cve) return { year: 0, num: 0 };
                              const m = cve.match(/CVE-(\d{4})-(\d+)/i);
                              return m ? { year: parseInt(m[1]), num: parseInt(m[2]) } : { year: 0, num: 0 };
                            };
                            const aCve = parseCve(a.cve);
                            const bCve = parseCve(b.cve);
                            if (bCve.year !== aCve.year) return bCve.year - aCve.year;
                            if (bCve.num !== aCve.num) return bCve.num - aCve.num;
                            const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                            return (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5);
                          }).map((v) => (
                            <option key={v.origIdx} value={v.origIdx}>{(v.severity || '').toUpperCase()}: {v.title}{v.cve ? ` (${v.cve})` : ''}{v.corroborationTier === 'confirmed' ? ' \u2713' : v.corroborationTier === 'probable' ? ' \u223c' : ''}{v.detectedVersion ? ` [v${v.detectedVersion}]` : ''}</option>
                          ))}
                        </select>
                      </div>
                    );
                  })()}
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="text-[10px] text-muted-foreground block mb-1">Language</label>
                      <select
                        value={exploitLang}
                        onChange={(e) => setExploitLang(e.target.value as any)}
                        className="w-full text-xs bg-background border border-border rounded px-2 py-1.5"
                      >
                        <option value="python">Python</option>
                        <option value="bash">Bash</option>
                        <option value="powershell">PowerShell</option>
                        <option value="ruby">Ruby</option>
                      </select>
                    </div>
                    <div className="flex items-end">
                      <label className="flex items-center gap-1.5 text-[10px] text-muted-foreground cursor-pointer">
                        <Checkbox
                          checked={includeEvasion}
                          onCheckedChange={(c) => setIncludeEvasion(!!c)}
                        />
                        Evasion
                      </label>
                    </div>
                  </div>
                  <Button
                    size="sm"
                    className="w-full bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-xs"
                    onClick={() => genExploitMut.mutate({
                      engagementId,
                      targetAsset: selectedExploitAsset,
                      vulnIndex: selectedVulnIdx,
                      language: exploitLang,
                      includeEvasion,
                    })}
                    disabled={!selectedExploitAsset || genExploitMut.isPending}
                  >
                    {genExploitMut.isPending ? <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" /> : <Zap className="h-3.5 w-3.5 mr-1" />}
                    Generate Exploit
                  </Button>
                </div>
              )}
              {/* Generated Exploits List */}
              {(generatedExploitsQ.data?.exploits?.length || 0) > 0 && (
                <div className="space-y-1 mt-2">
                  <span className="text-[10px] text-muted-foreground">{generatedExploitsQ.data!.exploits.length} exploit(s) generated</span>
                  {generatedExploitsQ.data!.exploits.map((ex: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-1.5 rounded bg-muted/30 border border-border/30">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <Skull className="h-3 w-3 text-red-400 flex-none" />
                        <span className="text-[10px] truncate">{ex.filename}</span>
                        <Badge variant="outline" className={`text-[8px] flex-none ${
                          ex.confidence >= 80 ? 'text-green-400 border-green-500/30' :
                          ex.confidence >= 50 ? 'text-yellow-400 border-yellow-500/30' :
                          'text-red-400 border-red-500/30'
                        }`}>{ex.confidence}%</Badge>
                      </div>
                      <div className="flex items-center gap-0.5">
                        <Button size="sm" variant="ghost" className="h-5 w-5 p-0" onClick={() => setViewingExploitIdx(i)} title="View code">
                          <Eye className="h-3 w-3" />
                        </Button>
                        <Button size="sm" variant="ghost" className="h-5 w-5 p-0"
                          onClick={() => validateExploitMut.mutate({ engagementId, exploitIndex: i })}
                          disabled={validateExploitMut.isPending}
                          title="Validate"
                        >
                          <Shield className="h-3 w-3" />
                        </Button>
                        <Button size="sm" variant="ghost" className="h-5 w-5 p-0"
                          onClick={() => improveExploitMut.mutate({ engagementId, exploitIndex: i, feedback: 'Improve reliability and add better error handling' })}
                          disabled={improveExploitMut.isPending}
                          title="Improve"
                        >
                          <Wrench className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
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

      {/* ── Re-Run Pipeline Dialog ── */}
      <AlertDialog open={showRerunDialog} onOpenChange={setShowRerunDialog}>
        <AlertDialogContent className="max-w-md">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <RefreshCw className="h-5 w-5 text-cyan-400" />
              Re-Run Full Pipeline
            </AlertDialogTitle>
            <AlertDialogDescription>
              This will reset the engagement state and re-execute all selected phases. Existing findings will be preserved in history.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="space-y-3 py-2">
            <div className="space-y-2">
              <h4 className="text-sm font-medium">Select Phases</h4>
              {[
                { key: 'passive' as const, label: 'Passive Reconnaissance', desc: 'OSINT, domain intel, certificate transparency', icon: <Search className="h-4 w-4" /> },
                { key: 'active' as const, label: 'Active Scanning', desc: 'Nmap, Nuclei, ZAP, Nikto via scan server', icon: <Target className="h-4 w-4" /> },
                { key: 'llmAnalysis' as const, label: 'LLM Analysis & Re-Scan', desc: 'AI-driven gap analysis, targeted re-scans', icon: <Brain className="h-4 w-4" /> },
                { key: 'exploitGeneration' as const, label: 'Exploit Generation', desc: 'LLM-generated exploit plans and functional code', icon: <Skull className="h-4 w-4" /> },
              ].map(phase => (
                <label key={phase.key} className={`flex items-start gap-3 p-3 rounded-lg cursor-pointer border transition-all ${
                  rerunPhases[phase.key] ? 'bg-cyan-500/5 border-cyan-500/20' : 'border-transparent hover:bg-muted/30'
                }`}>
                  <Checkbox
                    checked={rerunPhases[phase.key]}
                    onCheckedChange={(c) => setRerunPhases(prev => ({ ...prev, [phase.key]: !!c }))}
                    className="mt-0.5"
                  />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-cyan-400">{phase.icon}</span>
                      <span className="text-sm font-medium">{phase.label}</span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">{phase.desc}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-gradient-to-r from-cyan-600 to-blue-600"
              onClick={() => rerunMut.mutate({
                engagementId,
                phases: rerunPhases,
              })}
              disabled={rerunMut.isPending || !Object.values(rerunPhases).some(Boolean)}
            >
              {rerunMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Play className="h-4 w-4 mr-1" />}
              Start Re-Run
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ── Exploit Execution Sandbox Dialog ── */}
      <AlertDialog open={execExploitIdx !== null} onOpenChange={(open) => { if (!open) { setExecExploitIdx(null); setExecResult(null); } }}>
        <AlertDialogContent className="max-w-3xl max-h-[80vh] overflow-hidden flex flex-col">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <Terminal className="h-5 w-5 text-green-400" />
              Exploit Execution Sandbox
            </AlertDialogTitle>
            <AlertDialogDescription>
              Execute exploit scripts in a sandboxed environment on the scan server with resource limits and isolation.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="flex-1 overflow-auto space-y-4 py-2">
            {execExploitIdx !== null && generatedExploitsQ.data?.[execExploitIdx] && (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="text-[10px] text-muted-foreground uppercase">Target</label>
                    <div className="text-sm font-mono text-foreground bg-muted/30 rounded px-2 py-1">{generatedExploitsQ.data[execExploitIdx].asset}</div>
                  </div>
                  <div className="space-y-1">
                    <label className="text-[10px] text-muted-foreground uppercase">Language</label>
                    <div className="text-sm font-mono text-foreground bg-muted/30 rounded px-2 py-1">{generatedExploitsQ.data[execExploitIdx].language}</div>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={execDryRun} onChange={(e) => setExecDryRun(e.target.checked)} className="rounded" />
                    <span className="text-xs">Dry Run</span>
                    <span className="text-[10px] text-muted-foreground">(validate syntax only, no network connections)</span>
                  </label>
                </div>
                {!execDryRun && (
                  <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
                    <div className="flex items-center gap-2 text-red-400 text-xs font-medium">
                      <ShieldAlert className="h-4 w-4" /> Live Execution Warning
                    </div>
                    <p className="text-[10px] text-red-300/80 mt-1">This will execute the exploit against the real target. Ensure you have authorization and the target is in scope.</p>
                  </div>
                )}
              </>
            )}
            {execResult && (
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className={`text-[10px] ${
                    execResult.status === 'success' ? 'text-green-400 border-green-500/30' :
                    execResult.status === 'timeout' ? 'text-yellow-400 border-yellow-500/30' :
                    'text-red-400 border-red-500/30'
                  }`}>{(execResult.status || '').toUpperCase()}</Badge>
                  <span className="text-[10px] text-muted-foreground">Exit: {execResult.exitCode} | {execResult.durationMs}ms{execResult.dryRun ? ' | Dry Run' : ''}</span>
                </div>
                <div className="bg-black/40 rounded-lg p-3 font-mono text-[11px] max-h-[300px] overflow-auto">
                  <div className="text-[9px] text-muted-foreground uppercase mb-1">Output</div>
                  <pre className="text-green-300 whitespace-pre-wrap">{execResult.stdout || '(no output)'}</pre>
                  {execResult.stderr && (
                    <>
                      <div className="text-[9px] text-muted-foreground uppercase mt-2 mb-1">Stderr</div>
                      <pre className="text-red-300 whitespace-pre-wrap">{execResult.stderr}</pre>
                    </>
                  )}
                </div>
                <div className="text-[10px] text-muted-foreground">
                  Sandbox: {execResult.sandboxInfo?.memoryLimitMb}MB RAM | {execResult.sandboxInfo?.cpuTimeLimitSec}s CPU | {execResult.sandboxInfo?.timeoutSec}s timeout
                </div>
                {execResult.status === 'success' && execResult.exitCode === 0 && !execResult.dryRun && (
                  <Button
                    size="sm"
                    className="bg-green-600 hover:bg-green-700 text-white mt-2"
                    onClick={() => {
                      const exploit = execExploitIdx !== null ? generatedExploitsQ.data?.[execExploitIdx] : null;
                      setExploitShellContext({
                        shellType: exploit?.exploit?.shellType || 'reverse_shell',
                        targetHost: exploit?.asset || '',
                        targetPort: exploit?.exploit?.targetPort,
                        shellPayload: exploit?.exploit?.shellPayload,
                        stabilizationCmds: exploit?.exploit?.shellStabilization,
                        exploitName: exploit?.exploit?.filename || 'exploit',
                      });
                      setTerminalOpen(true);
                      setExecExploitIdx(null);
                      setExecResult(null);
                    }}
                  >
                    <Terminal className="h-3.5 w-3.5 mr-1.5" /> Open Shell Session
                  </Button>
                )}
              </div>
            )}
            {(execHistoryQ.data?.length || 0) > 0 && !execResult && (
              <div className="space-y-2">
                <div className="text-[10px] text-muted-foreground uppercase">Recent Executions</div>
                {(execHistoryQ.data || []).slice(-5).reverse().map((h: any, i: number) => (
                  <div key={i} className="flex items-center gap-2 text-[10px] bg-muted/20 rounded px-2 py-1">
                    <Badge variant="outline" className={`text-[8px] ${
                      h.status === 'success' ? 'text-green-400 border-green-500/30' : 'text-red-400 border-red-500/30'
                    }`}>{h.status}</Badge>
                    <span className="font-mono">{h.exploitId}</span>
                    <span className="text-muted-foreground">{h.durationMs}ms</span>
                    <span className="text-muted-foreground ml-auto">{new Date(h.executedAt).toLocaleTimeString()}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>Close</AlertDialogCancel>
            <Button
              onClick={() => execExploitIdx !== null && executeExploitMut.mutate({ engagementId, exploitIndex: execExploitIdx, dryRun: execDryRun })}
              disabled={executeExploitMut.isPending || execExploitIdx === null}
              className={execDryRun ? 'bg-green-600 hover:bg-green-700' : 'bg-red-600 hover:bg-red-700'}
            >
              {executeExploitMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Play className="h-4 w-4 mr-1" />}
              {execDryRun ? 'Run Dry Test' : 'Execute Live'}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ── Exploit Code Viewer Dialog ── */}
      <AlertDialog open={viewingExploitIdx !== null} onOpenChange={(open) => { if (!open) setViewingExploitIdx(null); }}>
        <AlertDialogContent className="max-w-3xl max-h-[80vh] overflow-hidden flex flex-col">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <Skull className="h-5 w-5 text-red-400" />
              {exploitDetailQ.data?.filename || 'Exploit Code'}
              {exploitDetailQ.data?.confidence && (
                <Badge variant="outline" className={`text-xs ${
                  exploitDetailQ.data.confidence >= 80 ? 'text-green-400 border-green-500/30' :
                  exploitDetailQ.data.confidence >= 50 ? 'text-yellow-400 border-yellow-500/30' :
                  'text-red-400 border-red-500/30'
                }`}>{exploitDetailQ.data.confidence}% confidence</Badge>
              )}
            </AlertDialogTitle>
            {exploitDetailQ.data && (
              <AlertDialogDescription className="text-left">
                <span className="font-medium">{exploitDetailQ.data.targetAsset}</span>
                {exploitDetailQ.data.cve && <span> — {exploitDetailQ.data.cve}</span>}
                {exploitDetailQ.data.attackVector && <span> — {exploitDetailQ.data.attackVector}</span>}
              </AlertDialogDescription>
            )}
          </AlertDialogHeader>
          <div className="flex-1 overflow-auto">
            {exploitDetailQ.isLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : exploitDetailQ.data?.code ? (
              <div className="space-y-3">
                {exploitDetailQ.data.description && (
                  <p className="text-xs text-muted-foreground bg-muted/30 p-3 rounded">{exploitDetailQ.data.description}</p>
                )}
                <CodeViewer
                  code={exploitDetailQ.data.code}
                  title={exploitDetailQ.data.title || 'Exploit Code'}
                  filename={exploitDetailQ.data.filename}
                  maxHeight="400px"
                />
                {exploitDetailQ.data.usage && (
                  <div>
                    <h4 className="text-xs font-semibold text-muted-foreground mb-1">Usage</h4>
                    <CodeViewer
                      code={exploitDetailQ.data.usage}
                      language="bash"
                      title="Usage Instructions"
                      showLineNumbers={false}
                      maxHeight="150px"
                    />
                  </div>
                )}
                {exploitDetailQ.data.mitigations && exploitDetailQ.data.mitigations.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-muted-foreground mb-1">Mitigations</h4>
                    <ul className="text-xs text-muted-foreground space-y-1">
                      {exploitDetailQ.data.mitigations.map((m: string, i: number) => (
                        <li key={i} className="flex items-start gap-1.5">
                          <Shield className="h-3 w-3 text-green-400 mt-0.5 flex-none" />
                          {m}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground py-4">No exploit code available.</p>
            )}
          </div>
          <AlertDialogFooter>
            <div className="flex items-center gap-2 w-full">
              <Button
                size="sm"
                variant="outline"
                className="border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10"
                onClick={() => {
                  if (viewingExploitIdx !== null) {
                    validateExploitMut.mutate({ engagementId, exploitIndex: viewingExploitIdx });
                  }
                }}
                disabled={validateExploitMut.isPending}
              >
                {validateExploitMut.isPending ? <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" /> : <Shield className="h-3.5 w-3.5 mr-1" />}
                Validate
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="border-purple-500/30 text-purple-400 hover:bg-purple-500/10"
                onClick={() => {
                  if (viewingExploitIdx !== null) {
                    improveExploitMut.mutate({ engagementId, exploitIndex: viewingExploitIdx, feedback: 'Improve reliability, error handling, and stealth' });
                  }
                }}
                disabled={improveExploitMut.isPending}
              >
                {improveExploitMut.isPending ? <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" /> : <Wrench className="h-3.5 w-3.5 mr-1" />}
                Improve
              </Button>
              <div className="flex-1" />
              <AlertDialogCancel>Close</AlertDialogCancel>
            </div>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ── Targeted Re-Synthesis Dialog ── */}
      <AlertDialog open={resynthTarget !== null} onOpenChange={(open) => { if (!open) { setResynthTarget(null); setResynthCategories([]); } }}>
        <AlertDialogContent className="max-w-lg">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <Target className="h-5 w-5 text-emerald-400" />
              Re-Synthesize Vulnerabilities
            </AlertDialogTitle>
            <AlertDialogDescription>
              Target specific vulnerability categories for <span className="font-medium text-foreground">{resynthTarget}</span>. Select categories to focus on, or leave all unchecked to scan all categories.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="space-y-4 py-2">
            <div className="grid grid-cols-2 gap-2">
              {[
                { id: 'injection', label: 'SQL Injection' },
                { id: 'xss', label: 'Cross-Site Scripting (XSS)' },
                { id: 'directory_traversal', label: 'Directory Traversal' },
                { id: 'crlf_injection', label: 'CRLF Injection' },
                { id: 'file_inclusion', label: 'File Inclusion (LFI/RFI)' },
                { id: 'auth_bypass', label: 'Broken Authentication' },
                { id: 'sensitive_data', label: 'Sensitive Data Exposure' },
                { id: 'broken_access', label: 'Broken Access Control' },
                { id: 'ssrf', label: 'SSRF' },
                { id: 'misconfig', label: 'Security Misconfiguration' },
              ].map(cat => (
                <label key={cat.id} className="flex items-center gap-2 text-xs p-2 rounded border border-border/30 hover:bg-muted/20 cursor-pointer">
                  <Checkbox
                    checked={resynthCategories.includes(cat.id)}
                    onCheckedChange={(checked) => {
                      if (checked) {
                        setResynthCategories(prev => [...prev, cat.id]);
                      } else {
                        setResynthCategories(prev => prev.filter(c => c !== cat.id));
                      }
                    }}
                  />
                  <span>{cat.label}</span>
                </label>
              ))}
            </div>
            <label className="flex items-center gap-2 text-xs p-2 rounded border border-yellow-500/20 bg-yellow-500/5">
              <Checkbox
                checked={resynthReplace}
                onCheckedChange={(checked) => setResynthReplace(!!checked)}
              />
              <span className="text-yellow-400">Replace existing LLM-synthesized vulns (keep active scan findings)</span>
            </label>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <Button
              onClick={() => {
                if (resynthTarget) {
                  resynthMut.mutate({
                    engagementId,
                    hostname: resynthTarget,
                    targetCategories: resynthCategories.length > 0 ? resynthCategories : undefined,
                    replaceExisting: resynthReplace,
                  });
                }
              }}
              disabled={resynthMut.isPending}
              className="bg-emerald-600 hover:bg-emerald-700"
            >
              {resynthMut.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Brain className="h-4 w-4 mr-2" />}
              {resynthCategories.length > 0 ? `Re-Synthesize ${resynthCategories.length} Categories` : 'Re-Synthesize All Categories'}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>

      {/* Finding Detail Drawers */}
      <VulnDetailDrawer
        vuln={selectedVulnDetail}
        open={!!selectedVulnDetail}
        onClose={() => setSelectedVulnDetail(null)}
        assetHostname={detailAssetHostname}
      />
      <ZapFindingDetailDrawer
        finding={selectedZapDetail}
        open={!!selectedZapDetail}
        onClose={() => setSelectedZapDetail(null)}
        assetHostname={detailAssetHostname}
      />
      {/* ── Floating Terminal Button ── */}
      {!terminalOpen && (
        <button
          onClick={() => setTerminalOpen(true)}
          className="fixed bottom-4 right-4 z-40 flex items-center gap-2 px-4 py-2.5 bg-zinc-900 border border-green-500/40 rounded-full shadow-lg shadow-green-500/10 hover:bg-green-900/30 hover:border-green-500/60 transition-all group"
          title="Open Pentest Terminal"
        >
          <Terminal className="h-4 w-4 text-green-400" />
          <span className="text-xs font-mono text-green-400 group-hover:text-green-300">Terminal</span>
          {exploitShellContext && (
            <span className="absolute -top-1 -right-1 h-3 w-3 bg-green-500 rounded-full animate-pulse" />
          )}
        </button>
      )}
      {/* ── Engagement Terminal ── */}
      <EngagementTerminal
        engagementId={engagementId}
        assets={(ops?.assets || []).map(a => ({ hostname: a.hostname, ip: a.ip, ports: a.ports?.map(p => p.port) }))}
        exploitContext={exploitShellContext}
        open={terminalOpen}
        onOpenChange={setTerminalOpen}
      />
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
