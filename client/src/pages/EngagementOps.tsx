/**
 * EngagementOps — Unified Engagement Operations Console
 *
 * Operator workflow:
 * 1. Paste in-scope assets (domains, IPs, URLs)
 * 2. Run Passive Discovery (OSINT, domain intel)
 * 3. Review discovered assets → Click "Start Active Scan"
 * 4. LLM orchestrates: port discovery (naabu/Nerva) → tool matching (ZAP for web, nuclei for CVEs) → credential testing → exploit approval
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
import ManualFindingsPanel from "@/components/ManualFindingsPanel";
import BurpAutoScanPanel from "@/components/BurpAutoScanPanel";
import { NextcloudTestLabPanel } from "@/components/NextcloudTestLabPanel";
import { AttackPlaybookPanel } from "@/components/AttackPlaybookPanel";
import { LabDeployerPanel } from "@/components/LabDeployerPanel";
import AdjustmentEffectivenessWidget from "@/components/AdjustmentEffectivenessWidget";
import CommsProtocolPanel from "@/components/CommsProtocolPanel";
import FingerprintDiffPanel from "@/components/FingerprintDiffPanel";
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
  ScanEye, ShieldOff, Bolt, TrendingUp, BarChart3, Scan, Microscope, Scissors,
  FileUp, Upload, Filter, FilterX, ToggleLeft, ToggleRight,
  X, FileCheck, Fingerprint, Edit2, BookOpen, Rocket,
} from "lucide-react";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { KpiStrip } from "@/components/KpiStrip";
import type { KpiItem } from "@/components/KpiStrip";
import { TabGroupNav } from "@/components/TabGroupNav";
import type { TabGroup } from "@/components/TabGroupNav";
import { FindingStateBadge } from "@/components/FindingStateBadge";
import { VulnDetailDrawer, ZapFindingDetailDrawer } from "@/components/FindingDetailDrawer";
import type { VulnFinding, ZapFinding as ZapFindingType } from "@/components/FindingDetailDrawer";
import EngagementTerminal from "@/components/EngagementTerminal";
import TestPlanGate from "@/components/TestPlanGate";
import { CoverageQuality } from "@/components/CoverageQuality";
import ExploitEvidencePanel from "@/components/ExploitEvidencePanel";
import TargetProfilePanel from "@/components/TargetProfilePanel";
import { EvasionStatusIndicator } from "@/components/EvasionStatusIndicator";
import EngagementTimeline from "@/components/EngagementTimeline";
import ScanCoverageHeatmap, { computeCoverage } from "@/components/ScanCoverageHeatmap";

// ─── Types (mirror server) ──────────────────────────────────────────────────

type OpsPhase = "idle" | "recon" | "recon_complete" | "passive_discovery" | "scoping" | "test_plan" | "test_plan_approval" | "enumeration" | "vuln_detection" | "social_engineering" | "exploitation" | "post_exploit" | "reporting" | "completed" | "paused" | "error";
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
  { id: "recon", label: "Domain Recon", icon: <Radar className="h-4 w-4" />, color: "text-blue-400" },
  { id: "passive_discovery", label: "Passive Discovery", icon: <Search className="h-4 w-4" />, color: "text-blue-300" },
  { id: "scoping", label: "Scoping & RoE", icon: <FileCheck className="h-4 w-4" />, color: "text-indigo-400" },
  { id: "test_plan", label: "Test Plan", icon: <FileText className="h-4 w-4" />, color: "text-indigo-300" },
  { id: "test_plan_approval", label: "Plan Approval", icon: <CheckCircle2 className="h-4 w-4" />, color: "text-indigo-200" },
  { id: "enumeration", label: "Active Discovery", icon: <Target className="h-4 w-4" />, color: "text-cyan-400" },
  { id: "vuln_detection", label: "Vuln Scan", icon: <Bug className="h-4 w-4" />, color: "text-yellow-400" },
  { id: "social_engineering", label: "Social Eng.", icon: <Zap className="h-4 w-4" />, color: "text-orange-400" },
  { id: "exploitation", label: "Exploit", icon: <Skull className="h-4 w-4" />, color: "text-red-400" },
  { id: "post_exploit", label: "Post-Exploit", icon: <Radio className="h-4 w-4" />, color: "text-purple-400" },
  { id: "completed", label: "Complete", icon: <CheckCircle2 className="h-4 w-4" />, color: "text-green-400" },
];

function getPhaseIndex(phase: string): number {
  if (phase === "recon_complete") return 0; // still in recon area
  if (phase === "complete") return PHASES.findIndex(p => p.id === "completed"); // normalize 'complete' → 'completed'
  if (phase === "test_plan_approval") return PHASES.findIndex(p => p.id === "test_plan_approval");
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
    entry.data.findings || entry.data.reasoning || entry.data.tools ||
    entry.data.failureAnalysis || entry.data.adjustmentsApplied || entry.data.adjustmentsToApply
  );
  const retryAdj = entry.data?.adjustmentsApplied as Array<{ type: string; description: string; modification?: string }> | undefined;
  const retryMeta = entry.data as { retryNumber?: number; strategy?: string; codeModified?: boolean; failureCategory?: string; backoffMs?: number; adjustmentsToApply?: Array<{ type: string; description: string; priority: number }> } | undefined;
  const fa = entry.data?.failureAnalysis as { category?: string; description?: string; indicators?: string[]; retryable?: boolean; retryConfidence?: number; suggestedAdjustments?: Array<{ type: string; description: string; priority: number }> } | undefined;
  return (
    <Collapsible key={entry.id}>
      <div
        className={`rounded-md text-sm transition-colors ${
          entry.type === "phase_complete" ? "bg-green-500/5 border border-green-500/10" :
          entry.type === "approval_request" ? "bg-orange-500/5 border border-orange-500/10" :
          entry.type === "exploit_success" ? "bg-red-500/5 border border-red-500/10" :
          (entry.type === "exploit_fail" && fa) ? "bg-amber-500/5 border border-amber-500/10" :
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
                {fa?.category && (
                  <Badge variant="outline" className={`text-[9px] font-mono uppercase tracking-wide ${
                    fa.category === 'waf_blocked' ? 'text-orange-400 border-orange-500/40 bg-orange-500/10' :
                    fa.category === 'payload_detected' ? 'text-red-400 border-red-500/40 bg-red-500/10' :
                    fa.category === 'auth_required' ? 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10' :
                    fa.category === 'timeout' ? 'text-blue-400 border-blue-500/40 bg-blue-500/10' :
                    fa.category === 'network_error' || fa.category === 'port_closed' || fa.category === 'service_unavailable' ? 'text-slate-400 border-slate-500/40 bg-slate-500/10' :
                    fa.category === 'version_mismatch' ? 'text-purple-400 border-purple-500/40 bg-purple-500/10' :
                    fa.category === 'exploit_error' || fa.category === 'dependency_missing' ? 'text-pink-400 border-pink-500/40 bg-pink-500/10' :
                    fa.category === 'defense_active' ? 'text-cyan-400 border-cyan-500/40 bg-cyan-500/10' :
                    'text-muted-foreground border-border/50'
                  }`}>{fa.category.replace(/_/g, ' ')}</Badge>
                )}
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
              {entry.data?.tools && Array.isArray(entry.data.tools) && (
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
              {/* Retry Adjustments Applied Panel */}
              {retryAdj && retryAdj.length > 0 && (
                <div className="bg-blue-500/5 border border-blue-500/10 rounded px-2 py-1.5 space-y-1">
                  <div className="flex items-center gap-2">
                    <Wrench className="h-3 w-3 text-blue-400" />
                    <span className="text-[10px] text-blue-400 uppercase font-semibold tracking-wider">Adjustments Applied</span>
                    {retryMeta?.retryNumber && (
                      <Badge variant="outline" className="text-[9px] text-blue-300 border-blue-500/30 bg-blue-500/10">Retry #{retryMeta.retryNumber}</Badge>
                    )}
                    {retryMeta?.strategy && (
                      <Badge variant="outline" className="text-[9px] text-cyan-300 border-cyan-500/30 bg-cyan-500/10 font-mono">{retryMeta.strategy}</Badge>
                    )}
                    {retryMeta?.codeModified && (
                      <Badge variant="outline" className="text-[9px] text-green-300 border-green-500/30 bg-green-500/10">code modified</Badge>
                    )}
                  </div>
                  <div className="space-y-0.5 mt-1">
                    {retryAdj.map((adj, i) => (
                      <div key={i} className="flex items-start gap-1.5 text-[10px]">
                        <span className="text-blue-400 font-mono flex-none min-w-[90px]">{adj.type}</span>
                        <span className="text-foreground/80">{adj.description}</span>
                        {adj.modification && (
                          <span className="text-muted-foreground/60 italic ml-1">— {adj.modification}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {/* Pending Adjustments (pre-retry) */}
              {retryMeta?.adjustmentsToApply && retryMeta.adjustmentsToApply.length > 0 && !retryAdj && (
                <div className="bg-indigo-500/5 border border-indigo-500/10 rounded px-2 py-1.5 space-y-1">
                  <div className="flex items-center gap-2">
                    <RefreshCw className="h-3 w-3 text-indigo-400" />
                    <span className="text-[10px] text-indigo-400 uppercase font-semibold tracking-wider">Queued Adjustments</span>
                    {retryMeta.retryNumber && (
                      <Badge variant="outline" className="text-[9px] text-indigo-300 border-indigo-500/30 bg-indigo-500/10">Retry #{retryMeta.retryNumber}</Badge>
                    )}
                    {retryMeta.backoffMs && (
                      <span className="text-[10px] text-muted-foreground font-mono ml-auto">{retryMeta.backoffMs}ms backoff</span>
                    )}
                  </div>
                  <div className="space-y-0.5 mt-1">
                    {retryMeta.adjustmentsToApply.map((adj, i) => (
                      <div key={i} className="flex items-start gap-1.5 text-[10px]">
                        <span className="text-indigo-400 font-mono flex-none">P{adj.priority}</span>
                        <span className="text-indigo-300 font-mono flex-none min-w-[90px]">{adj.type}</span>
                        <span className="text-foreground/80">{adj.description}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {/* Failure Analysis Panel */}
              {fa && (
                <div className="bg-amber-500/5 border border-amber-500/10 rounded px-2 py-1.5 space-y-1">
                  <span className="text-[10px] text-amber-400 uppercase font-semibold tracking-wider block">Failure Analysis</span>
                  {fa.description && (
                    <p className="text-[11px] text-foreground/90">{fa.description}</p>
                  )}
                  {fa.indicators && fa.indicators.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-0.5">
                      <span className="text-[10px] text-muted-foreground">Indicators:</span>
                      {fa.indicators.map((ind, i) => (
                        <Badge key={i} variant="outline" className="text-[9px] text-amber-300 border-amber-500/30 bg-amber-500/5">{ind}</Badge>
                      ))}
                    </div>
                  )}
                  <div className="flex items-center gap-3 mt-1">
                    <span className={`text-[10px] font-medium ${fa.retryable ? 'text-green-400' : 'text-red-400'}`}>
                      {fa.retryable ? `Retryable (${Math.round((fa.retryConfidence || 0) * 100)}% confidence)` : 'Not retryable'}
                    </span>
                  </div>
                  {fa.suggestedAdjustments && fa.suggestedAdjustments.length > 0 && (
                    <div className="mt-1">
                      <span className="text-[10px] text-muted-foreground uppercase font-medium block mb-0.5">Suggested Adjustments</span>
                      <div className="space-y-0.5">
                        {fa.suggestedAdjustments.slice(0, 4).map((adj, i) => (
                          <div key={i} className="flex items-start gap-1.5 text-[10px]">
                            <span className="text-amber-400 font-mono flex-none">P{adj.priority}</span>
                            <span className="text-foreground/80">{adj.description}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
              {/* Banner WAF/IDS Detection Panel */}
              {entry.data?.detections && Array.isArray(entry.data.detections) && entry.data.detections.length > 0 && (
                <div className="bg-orange-500/5 border border-orange-500/10 rounded px-2 py-1.5 space-y-1">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="h-3 w-3 text-orange-400" />
                    <span className="text-[10px] text-orange-400 uppercase font-semibold tracking-wider">Banner WAF/IDS Detections</span>
                    {entry.data.posture && (
                      <Badge variant="outline" className={`text-[9px] ${
                        entry.data.posture === 'high_security' ? 'text-red-300 border-red-500/30 bg-red-500/10' :
                        entry.data.posture === 'moderate_security' ? 'text-orange-300 border-orange-500/30 bg-orange-500/10' :
                        'text-yellow-300 border-yellow-500/30 bg-yellow-500/10'
                      }`}>{String(entry.data.posture).replace(/_/g, ' ')}</Badge>
                    )}
                  </div>
                  <div className="space-y-0.5 mt-1">
                    {(entry.data.detections as Array<{vendor: string; product: string; category: string; port: number; confidence: number; matchedPattern: string}>).map((d, i) => (
                      <div key={i} className="flex items-center gap-1.5 text-[10px]">
                        <Badge variant="outline" className={`text-[9px] flex-none ${
                          d.category === 'waf' ? 'text-red-300 border-red-500/30' :
                          d.category === 'ids_ips' ? 'text-orange-300 border-orange-500/30' :
                          d.category === 'firewall' ? 'text-yellow-300 border-yellow-500/30' :
                          'text-blue-300 border-blue-500/30'
                        }`}>{d.category.replace(/_/g, ' ')}</Badge>
                        <span className="text-orange-300 font-mono flex-none">{d.port}</span>
                        <span className="text-foreground/90 font-medium">{d.vendor} {d.product}</span>
                        <span className="text-muted-foreground/60 ml-auto">{d.confidence}%</span>
                      </div>
                    ))}
                  </div>
                  {entry.data.evasionProfile && (
                    <div className="flex flex-wrap gap-1.5 mt-1 pt-1 border-t border-orange-500/10">
                      <span className="text-[10px] text-muted-foreground">Evasion:</span>
                      {(entry.data.evasionProfile as any).useFragmentation && <Badge variant="outline" className="text-[9px] text-orange-300 border-orange-500/20">fragment</Badge>}
                      {(entry.data.evasionProfile as any).useEncryption && <Badge variant="outline" className="text-[9px] text-orange-300 border-orange-500/20">encrypt</Badge>}
                      {(entry.data.evasionProfile as any).skipAggressive && <Badge variant="outline" className="text-[9px] text-red-300 border-red-500/20">skip aggressive</Badge>}
                      <span className="text-[10px] text-muted-foreground font-mono ml-auto">rate: {(entry.data.evasionProfile as any).rateMultiplier}x</span>
                    </div>
                  )}
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
    { enabled: engagementId > 0, refetchInterval: isRunning ? 8000 : 30000 }
  );

  // Track running state for adaptive polling
  useEffect(() => {
    if (opsStateQ.data) setIsRunning(!!opsStateQ.data.isRunning);
  }, [opsStateQ.data?.isRunning]);

  // Exploit matching query — fires when vulns are found
  const exploitsQ = trpc.engagementOps.loadExploits.useQuery(
    { engagementId },
    { enabled: engagementId > 0 && (opsStateQ.data?.stats?.vulnsFound || 0) > 0, refetchInterval: isRunning ? 15000 : 60000 }
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
    { enabled: engagementId > 0 && (opsStateQ.data?.stats?.vulnsFound || 0) > 0, refetchInterval: isRunning ? 20000 : 60000 }
  );
  const cloudMisconfigsQ = trpc.engagementOps.getCloudMisconfigs.useQuery(
    { engagementId },
    { enabled: engagementId > 0, refetchInterval: isRunning ? 20000 : 60000 }
  );
  const feedbackLoopQ = trpc.engagementOps.getFeedbackLoopState.useQuery(
    { engagementId },
    { enabled: engagementId > 0, refetchInterval: isRunning ? 15000 : 60000 }
  );
  const targetProfilesQ = trpc.engagementOps.getTargetProfiles.useQuery(
    { engagementId },
    { enabled: engagementId > 0, refetchInterval: isRunning ? 15000 : 60000 }
  );

  const manualFindingsQ = trpc.engagementOps.listManualFindings.useQuery(
    { engagementId },
    { enabled: engagementId > 0, refetchInterval: 15000 }
  );

  // LLM Cost tracking for this engagement
  const llmCostQ = trpc.llmTelemetry.engagementCost.useQuery(
    { engagementId },
    { enabled: engagementId > 0, refetchInterval: isRunning ? 30000 : 120000 }
  );
  const llmCostBreakdownQ = trpc.llmTelemetry.engagementCostBreakdown.useQuery(
    { engagementId },
    { enabled: engagementId > 0, refetchInterval: isRunning ? 30000 : 120000 }
  );

  const activeScanMut = trpc.engagementOps.startActiveScan.useMutation({
    onSuccess: (data) => {
      toast.success(`Active Scan Started (${selectedProfile.toUpperCase()}) — LLM orchestrating scan plan → port discovery → tool matching → exploit on ${data.assetsCount} assets`);
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
    onError: (e) => {
      // If the gate is stale (no resolver), offer to dismiss it
      if (e.message.includes('not found') || e.message.includes('already resolved')) {
        toast.error('This approval gate is stale (server restarted). Use "Dismiss" to clear it.');
      } else {
        toast.error(e.message);
      }
    },
  });

  const dismissStaleMut = trpc.engagementOps.dismissStaleApproval.useMutation({
    onSuccess: () => { toast.success('Stale approval gate dismissed'); opsStateQ.refetch(); },
    onError: (e) => toast.error(e.message),
  });

  const dismissAllStaleMut = trpc.engagementOps.dismissAllStaleApprovals.useMutation({
    onSuccess: (data) => { toast.success(`Dismissed ${data.dismissed} stale approval gate(s)`); opsStateQ.refetch(); },
    onError: (e) => toast.error(e.message),
  });

  // ── Full Pipeline Re-Run ──
  const [showRerunDialog, setShowRerunDialog] = useState(false);
  const [rerunPhases, setRerunPhases] = useState({ passive: true, active: true, llmAnalysis: true, exploitGeneration: true });
  const [resetScope, setResetScope] = useState({ recon: true, scanning: true, analysis: true, exploitation: true, logs: true });
  const allResetChecked = Object.values(resetScope).every(Boolean);
  const noneResetChecked = Object.values(resetScope).every(v => !v);
  const rerunMut = trpc.engagementOps.rerunFullPipeline.useMutation({
    onSuccess: (data) => {
      toast.success(`Full pipeline re-run started for engagement #${data.engagementId}`);
      setShowRerunDialog(false);
      opsStateQ.refetch();
    },
    onError: (e) => toast.error(`Re-run failed: ${e.message}`),
  });

  // ── Re-run From Specific Phase ──
  const [showRerunFromPhaseDialog, setShowRerunFromPhaseDialog] = useState(false);
  const [rerunTargetPhase, setRerunTargetPhase] = useState<'recon' | 'enumeration' | 'vuln_detection' | 'social_engineering' | 'exploitation' | 'post_exploit'>('exploitation');
  const rerunFromPhaseMut = trpc.engagementOps.rerunFromPhase.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      setShowRerunFromPhaseDialog(false);
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
    { enabled: engagementId > 0, refetchInterval: 60000 }
  );
  const recordSnapshotMut = trpc.engagementOps.recordScanSnapshot.useMutation({
    onSuccess: (data) => {
      toast.success(`Snapshot recorded: ${data.totalVulns} vulns (${data.newVulnsFound} new, ${data.resolvedVulns} resolved)`);
      vulnTrendQ.refetch();
    },
    onError: (e) => toast.error(`Snapshot failed: ${e.message}`),
  });

  // ── Resume Engagement (state only — queries moved after `ops` is defined) ──
  const [showResumeDialog, setShowResumeDialog] = useState(false);

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
    // Helper: coerce any non-array to array (handles numeric-keyed objects from JSON round-trip)
    const ensureArray = (v: any): any[] => {
      if (Array.isArray(v)) return v;
      if (v && typeof v === 'object') try { return Object.values(v); } catch { return []; }
      return [];
    };
    // Ensure each asset has required sub-arrays (prevents .map/.filter crashes)
    for (const asset of base.assets) {
      const a = asset as any;
      a.vulns = ensureArray(a.vulns);
      a.pendingVulns = ensureArray(a.pendingVulns);
      a.toolResults = ensureArray(a.toolResults);
      a.ports = ensureArray(a.ports);
      a.zapFindings = ensureArray(a.zapFindings);
      a.exploitAttempts = ensureArray(a.exploitAttempts);
      a.confirmedCredentials = ensureArray(a.confirmedCredentials);
      a.riskSignals = ensureArray(a.riskSignals);
      a.knownPorts = ensureArray(a.knownPorts);
      a.scanHistory = ensureArray(a.scanHistory);
      a.notes = ensureArray(a.notes);
      // Normalize toolResult sub-fields
      for (const tr of a.toolResults) {
        tr.findings = ensureArray(tr.findings);
      }
      // Normalize passiveRecon sub-arrays
      if (a.passiveRecon && typeof a.passiveRecon === 'object') {
        for (const key of ['technologies', 'subdomains', 'services', 'dnsRecords', 'certificates', 'ipAddresses', 'historicalUrls', 'headers', 'cookies', 'riskSignals', 'oemCredentials', 'knownPorts', 'whoisData', 'socialProfiles']) {
          a.passiveRecon[key] = ensureArray(a.passiveRecon[key]);
        }
      }
    }
    // Normalize log entry data sub-arrays
    for (const entry of base.log) {
      if (entry.data && typeof entry.data === 'object') {
        const d = entry.data as any;
        d.tools = ensureArray(d.tools);
        d.findings = ensureArray(d.findings);
        d.vulns = ensureArray(d.vulns);
        d.assets = ensureArray(d.assets);
        d.ports = ensureArray(d.ports);
      }
    }
    // Normalize passiveReconResults sub-arrays
    if (base.passiveReconResults && typeof base.passiveReconResults === 'object') {
      for (const domain of Object.keys(base.passiveReconResults)) {
        const pr = (base.passiveReconResults as any)[domain];
        if (pr && typeof pr === 'object') {
          for (const key of ['technologies', 'subdomains', 'services', 'dnsRecords', 'oemCredentials', 'certificates', 'ipAddresses', 'riskSignals', 'knownPorts', 'historicalUrls', 'headers', 'cookies', 'whoisData', 'socialProfiles']) {
            pr[key] = ensureArray(pr[key]);
          }
        }
      }
    }
    // Normalize roeScopeGuard sub-arrays
    if (base.roeScopeGuard && typeof base.roeScopeGuard === 'object') {
      const rsg = base.roeScopeGuard as any;
      if (rsg.authorizedDomains && !Array.isArray(rsg.authorizedDomains)) rsg.authorizedDomains = ensureArray(rsg.authorizedDomains);
      if (rsg.authorizedIps && !Array.isArray(rsg.authorizedIps)) rsg.authorizedIps = ensureArray(rsg.authorizedIps);
    }
    // Normalize skippedDomains (Set serialized as array or object)
    if (base.skippedDomains && !Array.isArray(base.skippedDomains)) {
      (base as any).skippedDomains = ensureArray(base.skippedDomains);
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

  // ── Resume Engagement (queries — must be after `ops` is defined) ──
  const resumeCapabilityQ = trpc.liveTrigger.checkResumeCapability.useQuery(
    { engagementId },
    { enabled: engagementId > 0 && (ops?.phase === 'error' || (ops?.phase !== 'idle' && !ops?.isRunning)) }
  );
  const resumeMut = trpc.liveTrigger.triggerExecution.useMutation({
    onSuccess: (data) => {
      toast.success(`Engagement resumed from ${data.resumedFrom || 'last phase'}`);
      setShowResumeDialog(false);
      opsStateQ.refetch();
    },
    onError: (e) => toast.error(`Resume failed: ${e.message}`),
  });

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
  const isCompleted = ops?.phase === "completed" || ops?.phase === "complete";
  const canStartPassive = hasTargets && !ops?.isRunning && (isIdle || ops?.phase === "idle" || isErrorState || isCompleted);
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
        <div className="flex items-start justify-between gap-4 flex-wrap">
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
                {targetProfilesQ.data && Object.keys(targetProfilesQ.data).length > 0 && (
                  <>
                    <span className="text-border">|</span>
                    <EvasionStatusIndicator targetProfiles={targetProfilesQ.data} compact />
                  </>
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap flex-shrink-0">
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
                {isCompleted && (
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
                          reportType: 'pentest_assessment',
                          clientType: 'enterprise',
                          title: `${engagement?.name || 'Engagement'} - Security Assessment Report`,
                          preparedFor: engagement?.customerName ?? undefined,
                          preparedBy: user?.name ?? 'AC3',
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
          { label: 'Assets Discovered', value: assetCount, icon: <Globe className="h-4 w-4 text-emerald-400" />, color: 'text-emerald-400', delta: assetDelta, deltaPercent: assetDeltaPct, subtitle: snapshotLabel, onClick: () => setActiveTab('assets') },
          { label: 'Hosts Scanned', value: ops.stats?.hostsScanned || 0, icon: <Server className="h-4 w-4 text-cyan-400" />, color: 'text-cyan-400', onClick: () => setActiveTab('discovery') },
          { label: 'Open Ports', value: (() => { const seen = new Set<string>(); (ops.assets || []).forEach((a: any) => (a.ports || []).forEach((p: any) => seen.add(`${a.hostname || a.ip}:${p.port}`))); return seen.size || ops.stats?.portsFound || 0; })(), icon: <Network className="h-4 w-4 text-blue-400" />, color: 'text-blue-400', delta: portDelta, onClick: () => setActiveTab('assets') },
          { label: 'Total Vulns', value: totalVulns, icon: <Bug className="h-4 w-4 text-yellow-400" />, color: totalVulns > 0 ? 'text-yellow-400' : 'text-foreground', delta: vulnDelta, deltaPercent: vulnDeltaPct, deltaInverted: true, subtitle: criticalVulns > 0 ? `${criticalVulns} critical, ${highVulns} high` : snapshotLabel, onClick: () => setActiveTab('assets') },
          { label: 'Exploits Succeeded', value: ops.stats?.exploitsSucceeded || 0, icon: <Skull className="h-4 w-4 text-red-500" />, color: (ops.stats?.exploitsSucceeded || 0) > 0 ? 'text-red-400' : 'text-foreground', delta: exploitDelta, deltaInverted: true, subtitle: `${ops.stats?.exploitsAttempted || 0} attempted`, onClick: () => setActiveTab('evidence') },
          { label: 'Sessions', value: ops.stats?.sessionsOpened || 0, icon: <Terminal className="h-4 w-4 text-green-400" />, color: (ops.stats?.sessionsOpened || 0) > 0 ? 'text-green-400' : 'text-foreground', onClick: () => setActiveTab('evidence') },
          ...(liveOwaspCoverage ? [{ label: 'OWASP Score', value: liveOwaspCoverage.overallScore, suffix: '%', icon: <ShieldCheck className="h-4 w-4 text-purple-400" />, color: liveOwaspCoverage.overallScore >= 70 ? 'text-green-400' : liveOwaspCoverage.overallScore >= 40 ? 'text-yellow-400' : 'text-red-400', progress: liveOwaspCoverage.overallScore, progressColor: liveOwaspCoverage.overallScore >= 70 ? 'bg-green-500' : liveOwaspCoverage.overallScore >= 40 ? 'bg-yellow-500' : 'bg-red-500', onClick: () => setActiveTab('scope') }] : []),
          { label: 'WAFs Detected', value: ops.stats?.wafDetections || 0, icon: <ShieldAlert className="h-4 w-4 text-orange-400" />, color: (ops.stats?.wafDetections || 0) > 0 ? 'text-orange-400' : 'text-foreground', onClick: () => setActiveTab('discovery') },
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
                {resumeCapabilityQ.data?.canResume && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setShowResumeDialog(true)}
                    className="border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10"
                  >
                    <Play className="h-4 w-4 mr-1" />
                    Resume from {resumeCapabilityQ.data.nextPhaseLabel || 'Last Phase'}
                  </Button>
                )}
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

      {/* ── Interrupted Engagement Banner (Auto-Resume) ── */}
      <InterruptedEngagementBanner engagementId={engagementId} />

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
                    ? "Scan plan generated. Review the LLM's recommended scan configuration and tools per asset below, then start the active scan."
                    : "Generate a scan plan to let the LLM analyze each asset and recommend specific scan profiles and active tools before scanning."}
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

                      {/* Scan Configuration */}
                      <div className="mb-2">
                        <div className="text-xs text-cyan-400 font-medium mb-1">Scan Configuration:</div>
                        <code className="text-xs bg-black/40 px-2 py-1 rounded font-mono text-green-300 block">
                          naabu {ap.nmapFlags} -host {ap.ip || ap.hostname} | nerva
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
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2 text-orange-400 text-sm font-medium">
              <ShieldAlert className="h-4 w-4" />
              {pendingApprovals.length} Approval{pendingApprovals.length > 1 ? "s" : ""} Required
            </div>
            {pendingApprovals.length > 1 && engagementId && (
              <Button
                size="sm"
                variant="outline"
                className="border-muted-foreground/30 text-muted-foreground hover:bg-muted/50 text-xs"
                onClick={() => dismissAllStaleMut.mutate({ engagementId })}
                disabled={dismissAllStaleMut.isPending}
              >
                Dismiss All Stale
              </Button>
            )}
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
                      variant="ghost"
                      className="text-muted-foreground hover:text-foreground text-xs"
                      onClick={() => dismissStaleMut.mutate({ gateId: gate.id })}
                      disabled={dismissStaleMut.isPending}
                      title="Dismiss this stale approval gate (server restarted, action context lost)"
                    >
                      Dismiss
                    </Button>
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
            const coverage = computeCoverage(ops?.assets || []);
            const credFound = credTests.filter((tr: any) => Array.isArray(tr.findings) && tr.findings.length > 0).length;
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
                  { value: 'testplan', label: 'Test Plan', icon: <FileText className="h-3 w-3" /> },
                  { value: 'timeline', label: 'Timeline', icon: <Clock className="h-3 w-3" /> },
                ],
              },
              {
                id: 'discovery',
                label: 'Discovery',
                icon: <Radar className="h-3.5 w-3.5" />,
                color: 'text-purple-400',
                subTabs: [
                  { value: 'discovery', label: 'Tool Results', icon: <Radar className="h-3 w-3" />, count: toolCount },
                  { value: 'targetprofiles', label: 'Target Profiles', icon: <Fingerprint className="h-3 w-3" />, count: targetProfilesQ.data?.hasProfiles ? Object.keys(targetProfilesQ.data.profiles).length : 0 },
                  { value: 'credentials', label: 'Credentials', icon: <KeyRound className="h-3 w-3" />, count: credTests.length },
                  { value: 'cloud', label: 'Cloud', icon: <Cloud className="h-3 w-3" />, count: cloudMisconfigsQ.data?.stats?.total || 0 },
                  { value: 'scanimports', label: 'Scan Reports', icon: <FileUp className="h-3 w-3" /> },
                  { value: 'burpautoscan', label: 'Burp Suite', icon: <Scan className="h-3 w-3" /> },
                  { value: 'testlab', label: 'Test Lab', icon: <Server className="h-3 w-3" /> },
                  { value: 'attackplaybook', label: 'Attack Playbook', icon: <BookOpen className="h-3 w-3" /> },
                  { value: 'labdeployer', label: 'Deploy Lab', icon: <Rocket className="h-3 w-3" /> },
                  { value: 'coverageheatmap', label: 'Coverage Map', icon: <BarChart3 className="h-3 w-3" />, count: coverage.totalGaps || undefined },
                  { value: 'manualfindings', label: 'Manual Findings', icon: <Edit2 className="h-3 w-3" />, count: manualFindingsQ.data?.findings?.length || 0 },
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
                  { value: 'evidence', label: 'Evidence', icon: <Shield className="h-3 w-3" />, count: 0 },
                ],
              },
              {
                id: 'c2ops',
                label: 'C2 Ops',
                icon: <Radio className="h-3.5 w-3.5" />,
                color: 'text-orange-400',
                subTabs: [
                  { value: 'c2feed', label: 'C2 Activity', icon: <Radio className="h-3 w-3" /> },
                  { value: 'c2map', label: 'Network Map', icon: <Network className="h-3 w-3" /> },
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
                  { value: 'fpsuppression', label: 'FP Suppression', icon: <Filter className="h-3 w-3" /> },
                  { value: 'coverage', label: 'Coverage & Quality', icon: <Scissors className="h-3 w-3" /> },
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
                        <p className="text-cyan-400">The LLM will run port discovery (naabu/Nerva) first, then match tools to discovered services automatically</p>
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
                          <h4 className="text-xs font-medium text-muted-foreground mb-1">Open Ports ({(() => { const seen = new Set<number>(); (selectedAssetData.ports || []).forEach((p: any) => seen.add(p.port)); return seen.size; })()})</h4>
                          <div className="space-y-0.5">
                            {(() => {
                              // Deduplicate ports: prefer fingerprinted > identified > inferred, keep richest metadata
                              const portMap = new Map<number, any>();
                              for (const p of (selectedAssetData.ports || [])) {
                                const existing = portMap.get(p.port);
                                if (!existing) { portMap.set(p.port, p); continue; }
                                const srcPriority = (s: any) => (s as any)?.serviceSource === 'fingerprinted' ? 3 : (s?.service && s.service !== 'unknown') ? 2 : 1;
                                if (srcPriority(p) > srcPriority(existing)) portMap.set(p.port, { ...existing, ...p });
                                else if ((p as any).banner && !(existing as any).banner) portMap.set(p.port, { ...existing, banner: (p as any).banner, product: (p as any).product || existing.product });
                              }
                              return Array.from(portMap.values()).sort((a, b) => a.port - b.port);
                            })().map((p, i) => {
                              // Client-side fallback: resolve "unknown" services using well-known port map
                              const COMMON_PORTS: Record<number, string> = {
                                21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',80:'http',110:'pop3',
                                111:'rpcbind',135:'msrpc',139:'netbios',143:'imap',443:'https',445:'smb',
                                465:'smtps',587:'submission',636:'ldaps',993:'imaps',995:'pop3s',
                                1433:'mssql',1521:'oracle',1883:'mqtt',2049:'nfs',2222:'ssh',
                                3000:'http-alt',3306:'mysql',3389:'rdp',4000:'http-alt',4443:'https-alt',
                                5000:'http-alt',5432:'postgresql',5672:'amqp',5900:'vnc',5984:'couchdb',
                                6379:'redis',6443:'kubernetes',6667:'irc',8000:'http-alt',8080:'http-proxy',
                                8081:'http-alt',8090:'http-alt',8443:'https-alt',8888:'http-alt',
                                9000:'http-alt',9090:'http-alt',9092:'kafka',9200:'elasticsearch',
                                9443:'https-alt',10250:'kubelet',11211:'memcached',27017:'mongodb',
                                50000:'jenkins-agent',
                              };
                              const displayService = (p.service && p.service !== 'unknown') ? p.service : (COMMON_PORTS[p.port] || 'unknown');
                              const serviceSource = (p as any).serviceSource;
                              const isFingerprinted = serviceSource === 'fingerprinted';
                              const isInferred = !isFingerprinted && (p.service === 'unknown' || !p.service);
                              const isResolved = displayService !== 'unknown';
                              const banner = (p as any).banner;
                              const product = (p as any).product;
                              const secFlags = (p as any).securityFlags;
                              const riskIndicators = (p as any).riskIndicators;
                              const potentialCves = (p as any).potentialCves;
                              return (
                                <div key={i} className="text-xs px-2 py-1.5 bg-muted/10 rounded space-y-1">
                                  <div className="flex items-center gap-2">
                                    <span className="font-mono text-cyan-400 w-12">{p.port}</span>
                                    <span className={isFingerprinted ? 'text-foreground font-medium' : isInferred && isResolved ? 'text-yellow-300/90 italic' : isInferred ? 'text-muted-foreground italic' : 'text-foreground'}>
                                      {displayService}
                                    </span>
                                    {isFingerprinted && (
                                      <span className="text-[9px] text-blue-400/80 border border-blue-400/30 rounded px-1 bg-blue-500/10">fingerprinted</span>
                                    )}
                                    {!isFingerprinted && isInferred && isResolved && (
                                      <span className="text-[9px] text-yellow-500/60 border border-yellow-500/20 rounded px-1">inferred</span>
                                    )}
                                    {!isFingerprinted && !isInferred && (
                                      <span className="text-[9px] text-emerald-500/60 border border-emerald-500/20 rounded px-1">identified</span>
                                    )}
                                    {p.version && <span className="text-muted-foreground">{p.version}</span>}
                                    {/* Security risk indicators */}
                                    {secFlags?.anonymousAccess && (
                                      <span className="text-[9px] text-red-400/80 border border-red-400/30 rounded px-1 bg-red-500/10">⚠ anon</span>
                                    )}
                                    {secFlags?.defaultCredentials && (
                                      <span className="text-[9px] text-orange-400/80 border border-orange-400/30 rounded px-1 bg-orange-500/10">🔑 default-creds</span>
                                    )}
                                  </div>
                                  {/* Expanded fingerprint details */}
                                  {isFingerprinted && (product || banner) && (
                                    <div className="ml-14 space-y-0.5">
                                      {product && <div className="text-[10px] text-muted-foreground">Product: <span className="text-foreground/80">{product}{(p as any).os ? ` (${(p as any).os})` : ''}</span></div>}
                                      {banner && <div className="text-[10px] text-muted-foreground font-mono truncate max-w-[300px]" title={banner}>Banner: {banner.slice(0, 80)}{banner.length > 80 ? '...' : ''}</div>}
                                      {potentialCves && potentialCves.length > 0 && (
                                        <div className="text-[10px] text-red-400/80">
                                          CVEs: {potentialCves.slice(0, 5).join(', ')}{potentialCves.length > 5 ? ` (+${potentialCves.length - 5})` : ''}
                                        </div>
                                      )}
                                      {riskIndicators && riskIndicators.length > 0 && (
                                        <div className="flex gap-1 flex-wrap">
                                          {riskIndicators.slice(0, 3).map((r: any, ri: number) => (
                                            <span key={ri} className={`text-[8px] rounded px-1 ${
                                              r.severity === 'critical' ? 'text-red-300 bg-red-500/15 border border-red-500/20' :
                                              r.severity === 'high' ? 'text-orange-300 bg-orange-500/15 border border-orange-500/20' :
                                              'text-yellow-300 bg-yellow-500/15 border border-yellow-500/20'
                                            }`} title={r.description}>{r.indicator}</span>
                                          ))}
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </div>
                              );
                            })}
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
                                {/* CWE inline badge (from vuln data if available) */}
                                {(v.cwe || (v.cwes && Array.isArray(v.cwes) && v.cwes.length > 0)) && (
                                  <div className="flex items-center gap-1 flex-wrap ml-0.5">
                                    {(() => {
                                      const cweList: string[] = v.cwes && Array.isArray(v.cwes) ? v.cwes : v.cwe ? [v.cwe] : [];
                                      return cweList.slice(0, 3).map((cweId: string) => (
                                        <Badge key={cweId} variant="outline" className="text-[8px] font-mono text-amber-400 border-amber-500/30 bg-amber-500/10">
                                          {cweId}
                                        </Badge>
                                      ));
                                    })()}
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
                                {(selectedAssetData.passiveRecon?.riskSignals || []).map((r: any, i: number) => {
                                  // Handle multiple formats: string, {signal,severity,source}, {severity,type,rationale}
                                  const sev = typeof r === 'string' ? 'medium' : (r.severity || 'medium');
                                  const label = typeof r === 'string' ? r : (r.signal || r.rationale || r.type || String(r));
                                  const source = typeof r === 'string' ? '' : (r.source || r.type || '');
                                  return (
                                  <div key={i} className="flex items-center gap-2 text-[10px] px-2 py-0.5 bg-red-500/5 rounded">
                                    <Badge variant="outline" className={`text-[8px] ${
                                      sev === 'critical' ? 'text-red-400 border-red-500/30' :
                                      sev === 'high' ? 'text-orange-400 border-orange-500/30' :
                                      sev === 'medium' ? 'text-yellow-400 border-yellow-500/30' :
                                      'text-blue-400 border-blue-500/30'
                                    }`}>{sev}</Badge>
                                    <span className="text-foreground">{label}</span>
                                    {source && <span className="text-muted-foreground/50 ml-auto">{source}</span>}
                                  </div>
                                  );
                                })}
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
                               {(Array.isArray(tr.findings) ? tr.findings.length : 0) > 0 && (
                                   <div className="space-y-0.5">
                                     {[...(Array.isArray(tr.findings) ? tr.findings : [])].sort((a: any, b: any) => {
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
{(Array.isArray(tr.findings) ? tr.findings.length : 0) > 8 && (
                                       <p className="text-[9px] text-muted-foreground">+{(Array.isArray(tr.findings) ? tr.findings.length : 0) - 8} more findings</p>
                                    )}
                                  </div>
                                )}
                                {(Array.isArray(tr.findings) ? tr.findings.length : 0) === 0 && tr.outputPreview && (
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
                  <p className="text-xs text-muted-foreground">Aggregated discovery results from naabu, Nerva, and httpx across all assets. Click any row to view the full asset detail.</p>
                  {(() => {
                    const assets = ops?.assets || [];
                    const allToolResults = assets.flatMap((a: any) => (a.toolResults || []).map((tr: any) => ({ ...tr, assetHostname: a.hostname })));
                    const portScanResults = allToolResults.filter((tr: any) => tr.tool === 'nmap' || tr.tool === 'nmap-discovery' || tr.tool === 'nerva' || tr.tool === 'naabu');
                    const nucleiResults = allToolResults.filter((tr: any) => tr.tool === 'nuclei');
                    const httpxResults = allToolResults.filter((tr: any) => tr.tool === 'httpx');

                    // Well-known port fallback map for resolving "unknown" services
                    const COMMON_PORTS: Record<number, string> = {
                      21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',80:'http',110:'pop3',
                      111:'rpcbind',135:'msrpc',139:'netbios',143:'imap',443:'https',445:'smb',
                      465:'smtps',587:'submission',636:'ldaps',993:'imaps',995:'pop3s',
                      1433:'mssql',1521:'oracle',1883:'mqtt',2049:'nfs',2222:'ssh',
                      3000:'http-alt',3306:'mysql',3389:'rdp',4000:'http-alt',4443:'https-alt',
                      5000:'http-alt',5432:'postgresql',5672:'amqp',5900:'vnc',5984:'couchdb',
                      6379:'redis',6443:'kubernetes',6667:'irc',8000:'http-alt',8080:'http-proxy',
                      8081:'http-alt',8090:'http-alt',8443:'https-alt',8888:'http-alt',
                      9000:'http-alt',9090:'http-alt',9092:'kafka',9200:'elasticsearch',
                      9443:'https-alt',10250:'kubelet',11211:'memcached',27017:'mongodb',
                      50000:'jenkins-agent',
                    };
                    const resolveService = (port: number, svc: string) => {
                      if (svc && svc !== 'unknown') return svc;
                      return COMMON_PORTS[port] || 'unknown';
                    };

                    // Aggregate ports across all assets
                    const portMap = new Map<number, { count: number; services: Set<string>; assets: Set<string> }>();
                    for (const a of assets) {
                      for (const p of (a.knownPorts || [])) {
                        const port = typeof p === 'number' ? p : (p.port || 0);
                        const rawSvc = typeof p === 'object' ? (p.service || 'unknown') : 'unknown';
                        const svc = resolveService(port, rawSvc);
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
                      if (Array.isArray(a.passiveRecon?.technologies)) techs.push(...a.passiveRecon.technologies);
                      // From httpx tool results
                      for (const tr of (a.toolResults || [])) {
                        if (tr.tool === 'httpx' && Array.isArray(tr.findings)) {
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

                    // Aggregate services (with fallback resolution)
                    const serviceMap = new Map<string, { count: number; ports: Set<number>; assets: Set<string> }>();
                    for (const a of assets) {
                      for (const p of (a.knownPorts || [])) {
                        if (typeof p === 'object') {
                          const port = p.port || 0;
                          const svcName = resolveService(port, p.service || 'unknown');
                          if (!serviceMap.has(svcName)) serviceMap.set(svcName, { count: 0, ports: new Set(), assets: new Set() });
                          const entry = serviceMap.get(svcName)!;
                          entry.count++;
                          entry.ports.add(port);
                          entry.assets.add(a.hostname);
                        }
                      }
                      // Also from passive recon services
                      for (const svc of (a.passiveRecon?.services || [])) {
                        const name = resolveService(svc.port || 0, svc.service || svc.name || 'unknown');
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
                        if (tr.tool === 'httpx' && Array.isArray(tr.findings)) {
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
                                <span className="text-xs font-medium">Port Discovery</span>
                                <Badge variant="secondary" className="ml-auto text-[9px] h-4">{portScanResults.length} runs</Badge>
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
                                {httpxResults.reduce((sum: number, tr: any) => sum + (Array.isArray(tr.findings) ? tr.findings.length : (tr.findingCount || 0)), 0)} findings &mdash; HTTP probing, tech & CDN/WAF
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
                                    const findings = (a.toolResults || []).reduce((sum: number, tr: any) => sum + (Array.isArray(tr.findings) ? tr.findings.length : 0), 0);
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
                                        tr.tool === 'nmap' || tr.tool === 'nmap-discovery' || tr.tool === 'nerva' ? 'bg-blue-500/20 text-blue-400' :
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
                                    {Array.isArray(tr.findings) && tr.findings.length > 0 && (
                                      <div className="space-y-0.5">
                                        {[...(Array.isArray(tr.findings) ? tr.findings : [])].sort((a: any, b: any) => {
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
                                        {(Array.isArray(tr.findings) ? tr.findings.length : 0) > 5 && <p className="text-[9px] text-muted-foreground">+{(Array.isArray(tr.findings) ? tr.findings.length : 0) - 5} more findings</p>}
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
                            {Array.isArray(match.exploitBridgeModules) && match.exploitBridgeModules.length > 0 && (
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

            {/* ── Target Profiles Tab ── */}
            <TabsContent value="targetprofiles" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="py-3">
                  <TargetProfilePanel engagementId={engagementId} isRunning={isRunning} />
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
                    const successfulTests = allCredTests.filter((t: any) => Array.isArray(t.findings) && t.findings.length > 0);
                    const failedTests = allCredTests.filter((t: any) => !Array.isArray(t.findings) || t.findings.length === 0);
                    const uniqueAssets = new Set(allCredTests.map((t: any) => t.asset.hostname)).size;
                    const uniqueServices = new Set(allCredTests.map((t: any) => {
                      const m = t.command?.match(/hydra.*?\s(\S+)\s*$/); return m ? m[1] : t.tool;
                    })).size;
                    // Extract OEM credential info from passive recon
                    const oemCreds: any[] = [];
                    if (ops?.passiveReconResults) {
                      Object.values(ops.passiveReconResults).forEach((d: any) => {
                        if (Array.isArray(d?.oemCredentials)) oemCreds.push(...d.oemCredentials);
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
                              const assetFound = assetCredTests.some((t: any) => Array.isArray(t.findings) && t.findings.length > 0);
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
                                      const hasFindings = Array.isArray(test.findings) && test.findings.length > 0;
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

                  {/* Comms Protocol & Scope Constraints from Uploaded Doc */}
                  {engagement?.id && <FingerprintDiffPanel engagementId={engagement.id} />}
                  {engagement?.id && <CommsProtocolPanel engagementId={engagement.id} />}

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
                  {Array.isArray(cloudMisconfigsQ.data?.assetCloudInfo) && cloudMisconfigsQ.data.assetCloudInfo.length > 0 && (
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

                  {/* Potential Findings Disclaimer */}
                  {(ops?.assets || []).some((a: any) => (a.vulns || []).some((v: any) => v.tool === 'llm-synthesis')) && (
                    <div className="flex items-start gap-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs">
                      <AlertTriangle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                      <div>
                        <p className="font-semibold">Potential Findings — Not Confirmed</p>
                        <p className="text-amber-300/70 mt-0.5">These vulnerabilities were identified by LLM analysis of passive reconnaissance signals. They have NOT been confirmed by active scanning tools (nuclei, Hydra, ZAP). Treat as hypotheses requiring validation through active testing.</p>
                      </div>
                    </div>
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
                                  {synthVulns.length} potential (unconfirmed)
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
                                    <Badge variant="outline" className="text-[8px] text-green-300 border-green-500/30 bg-green-500/10">✓ active scan confirmed</Badge>
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

            {/* ── Exploit Evidence Tab ── */}
            <TabsContent value="evidence" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-[calc(100vh-280px)]">
                <ExploitEvidencePanel engagementId={engagementId} />
              </ScrollArea>
            </TabsContent>

            {/* ── FP Suppression Tab ── */}
            <TabsContent value="fpsuppression" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <FPSuppressionPanel engagementId={engagementId} />
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
                  {Array.isArray(vulnTrendQ.data) && vulnTrendQ.data.length > 0 ? (
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

                  {/* Adjustment Effectiveness Feedback Loop */}
                  <AdjustmentEffectivenessWidget />

                  {/* Snapshot History */}
                  {Array.isArray(vulnTrendQ.data) && vulnTrendQ.data.length > 0 && (
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

            {/* ── Test Plan Approval Gate Tab ── */}
            <TabsContent value="testplan" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="space-y-4 py-4">
                  <TestPlanGate engagementId={engagementId} engagementName={ops?.name || `Engagement #${engagementId}`} />
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
                  {Array.isArray(planHistoryQ.data) && planHistoryQ.data.length === 0 && (
                    <div className="text-center py-12">
                      <ClipboardList className="h-8 w-8 text-muted-foreground/30 mx-auto mb-2" />
                      <p className="text-sm text-muted-foreground">No exploit plans have been reviewed yet.</p>
                      <p className="text-xs text-muted-foreground/60 mt-1">Plans will appear here after the LLM generates an exploit strategy and you approve or reject it.</p>
                    </div>
                  )}
                  {Array.isArray(planHistoryQ.data) && planHistoryQ.data.length > 0 && (
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

            {/* ── Engagement Timeline Tab ── */}
            <TabsContent value="timeline" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="py-4">
                  <EngagementTimeline
                    log={ops?.log || []}
                    assets={ops?.assets || []}
                    startedAt={ops?.startedAt}
                    completedAt={ops?.completedAt}
                    currentPhase={ops?.phase || 'idle'}
                  />
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ── Scan Report Imports Tab ── */}
            <TabsContent value="scanimports" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <ScanReportImportPanel engagementId={engagementId} />
              </ScrollArea>
            </TabsContent>

            {/* ── Burp Suite Auto-Scan Tab ── */}
            <TabsContent value="burpautoscan" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="py-4">
                  <BurpAutoScanPanel engagementId={engagementId} />
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ── Nextcloud Test Lab Tab ── */}
            <TabsContent value="testlab" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="py-4">
                  <NextcloudTestLabPanel engagementId={engagementId} engagementName={ops?.engagement?.name} />
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ── Attack Playbook Tab ── */}
            <TabsContent value="attackplaybook" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="py-4">
                  <AttackPlaybookPanel engagementId={engagementId} />
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ── Lab Deployer Tab ── */}
            <TabsContent value="labdeployer" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="py-4">
                  <LabDeployerPanel engagementId={engagementId} />
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ── Coverage Heatmap Tab ── */}
            <TabsContent value="coverageheatmap" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="py-4">
                  <ScanCoverageHeatmap assets={ops?.assets || []} />
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ═══ Manual Findings ═══ */}
            <TabsContent value="manualfindings" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <div className="py-4">
                  <ManualFindingsPanel
                    engagementId={String(engagementId)}
                    assets={(ops?.assets || []).map((a: any) => ({ hostname: a.hostname, ip: a.ip }))}
                  />
                </div>
              </ScrollArea>
            </TabsContent>

            {/* ═══ C2 Activity Feed ═══ */}
            <TabsContent value="c2feed" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-full">
                <C2ActivityFeed engagementId={engagementId} />
              </ScrollArea>
            </TabsContent>
            <TabsContent value="c2map" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <C2NetworkMap engagementId={engagementId} />
            </TabsContent>

            {/* ── Coverage & Quality Tab ── */}
            <TabsContent value="coverage" className="flex-1 overflow-hidden m-0 px-6 pb-4">
              <ScrollArea className="h-[calc(100vh-280px)]">
                <div className="py-3">
                  <CoverageQuality
                    dedupStats={(ops as any)?.dedupStats}
                    coverageReport={(ops as any)?.coverageReport}
                    engagementPhase={ops?.phase}
                  />
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
            <StatCard icon={<Globe className="h-4 w-4 text-emerald-400" />} label="Assets Discovered" value={ops?.assets?.length || 0} onClick={() => setActiveTab('assets')} />
            <StatCard icon={<Server className="h-4 w-4 text-cyan-400" />} label="Hosts Scanned" value={ops?.stats?.hostsScanned || 0} onClick={() => setActiveTab('discovery')} />
            <StatCard icon={<Activity className="h-4 w-4 text-blue-400" />} label="Open Ports" value={(() => { const seen = new Set<string>(); (ops?.assets || []).forEach((a: any) => (a.ports || []).forEach((p: any) => seen.add(`${a.hostname || a.ip}:${p.port}`))); return seen.size || ops?.stats?.portsFound || 0; })()} onClick={() => setActiveTab('assets')} />
            <StatCard icon={<Bug className="h-4 w-4 text-yellow-400" />} label="Vulns Found" value={(ops?.assets || []).reduce((sum: number, a: any) => sum + (a.vulns || []).length + (a.zapFindings || []).length, 0) || ops?.stats?.vulnsFound || 0} onClick={() => setActiveTab('assets')} />
            <StatCard icon={<Globe className="h-4 w-4 text-blue-400" />} label="ZAP Scans" value={ops?.stats?.zapScansRun || 0} onClick={() => setActiveTab('discovery')} />
            <StatCard icon={<ShieldAlert className="h-4 w-4 text-orange-400" />} label="WAFs Detected" value={ops?.stats?.wafDetections || 0} onClick={() => setActiveTab('discovery')} />
            <StatCard icon={<Crosshair className="h-4 w-4 text-red-400" />} label="Exploits Tried" value={ops?.stats?.exploitsAttempted || 0} onClick={() => setActiveTab('exploits')} />
            <StatCard icon={<Skull className="h-4 w-4 text-red-500" />} label="Exploits OK" value={ops?.stats?.exploitsSucceeded || 0} onClick={() => setActiveTab('exploits')} />
            <StatCard icon={<Terminal className="h-4 w-4 text-green-400" />} label="Sessions" value={ops?.stats?.sessionsOpened || 0} onClick={() => setActiveTab('exploits')} />
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
            {Array.isArray(llmCostBreakdownQ.data) && llmCostBreakdownQ.data.length > 0 && (
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
              <Button
                size="sm"
                variant="outline"
                className="w-full justify-start text-xs border-amber-500/30 text-amber-400 hover:bg-amber-500/10 mt-2"
                onClick={() => {
                  if (!engagementId) return;
                  rerunMut.mutate({
                    engagementId,
                    phases: { passive: false, active: true, llmAnalysis: true, exploitGeneration: false },
                    resetScope: { recon: false, scanning: true, analysis: false, exploitation: false, logs: false },
                  });
                }}
                disabled={ops?.isRunning || rerunMut.isPending}
              >
                {rerunMut.isPending ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Scan className="h-3.5 w-3.5 mr-1.5" />}
                Quick Re-Scan
              </Button>
              <p className="text-[10px] text-muted-foreground leading-relaxed">
                Re-run active scanning + LLM analysis only. Keeps recon data, exploitation history, and logs.
              </p>
            </div>
          </div>

          {/* Auto-Resume Toggle */}
          <div className="mt-3">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Auto-Resume on Restart</h3>
            <AutoResumeToggle engagementId={engagementId} />
          </div>

          {/* Re-run From Specific Phase */}
          <div className="mt-2">
            <Button
              size="sm"
              variant="outline"
              className="w-full justify-start text-xs border-amber-500/30 text-amber-400 hover:bg-amber-500/10"
              onClick={() => setShowRerunFromPhaseDialog(true)}
              disabled={ops?.isRunning}
            >
              <RotateCcw className="h-3.5 w-3.5 mr-1.5" />
              Re-run From Phase
            </Button>
            <p className="text-[10px] text-muted-foreground leading-relaxed mt-1">
              Restart from a specific phase, preserving all data from earlier phases.
            </p>
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
                          {[...(Array.isArray(asset.vulns) ? asset.vulns : [])].map((v, origIdx) => ({ ...v, origIdx })).sort((a: any, b: any) => {
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
                      assetHostname: selectedExploitAsset,
                      vulnIndex: selectedVulnIdx,
                      preferredLanguage: exploitLang,
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
                    reportType: 'pentest_assessment',
                    clientType: 'enterprise',
                    title: `${engagement?.name || 'Engagement'} - Security Assessment Report`,
                    preparedFor: engagement?.customerName ?? undefined,
                    preparedBy: user?.name ?? 'AC3',
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
        <AlertDialogContent className="max-w-md max-h-[85vh] flex flex-col p-0">
          <AlertDialogHeader className="px-6 pt-6 pb-2 shrink-0">
            <AlertDialogTitle className="flex items-center gap-2">
              <RefreshCw className="h-5 w-5 text-cyan-400" />
              Re-Run Full Pipeline
            </AlertDialogTitle>
            <AlertDialogDescription>
              Select which phases to run and which data to reset. Uncheck data categories to preserve them across the re-run.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="flex-1 overflow-y-auto px-6 min-h-0">
            <div className="space-y-3 py-2">
              <div className="space-y-2">
                <h4 className="text-sm font-medium">Select Phases</h4>
                {[
                  { key: 'passive' as const, label: 'Passive Reconnaissance', desc: 'OSINT, domain intel, certificate transparency', icon: <Search className="h-4 w-4" /> },
                  { key: 'active' as const, label: 'Active Scanning', desc: 'naabu/Nerva, Nuclei, ZAP, Nikto via scan server', icon: <Target className="h-4 w-4" /> },
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
            {/* ── Data Reset Scope ── */}
            <div className="space-y-3 py-2 border-t border-border/50">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-medium flex items-center gap-1.5">
                    <RotateCcw className="h-3.5 w-3.5 text-amber-400" />
                    Data Reset Scope
                  </h4>
                  <button
                    type="button"
                    className="text-xs text-muted-foreground hover:text-foreground transition-colors"
                    onClick={() => {
                      const newVal = !allResetChecked;
                      setResetScope({ recon: newVal, scanning: newVal, analysis: newVal, exploitation: newVal, logs: newVal });
                    }}
                  >
                    {allResetChecked ? 'Uncheck all' : 'Check all'}
                  </button>
                </div>
                <p className="text-xs text-muted-foreground">Uncheck categories to preserve their data across the re-run.</p>
                {[
                  { key: 'recon' as const, label: 'Reconnaissance', desc: 'Assets, domain intel, host/port data, OSINT', icon: <Search className="h-3.5 w-3.5" /> },
                  { key: 'scanning' as const, label: 'Scan Results', desc: 'ZAP, Nuclei, Burp, web app scans, test plans', icon: <Scan className="h-3.5 w-3.5" /> },
                  { key: 'analysis' as const, label: 'LLM Analysis', desc: 'Findings, vuln snapshots, decision log, feedback loop', icon: <Brain className="h-3.5 w-3.5" /> },
                  { key: 'exploitation' as const, label: 'Exploitation', desc: 'Exploit attempts, plans, sessions, chains', icon: <Skull className="h-3.5 w-3.5" /> },
                  { key: 'logs' as const, label: 'Timeline & Logs', desc: 'Timeline events, ops log, approval gates', icon: <Activity className="h-3.5 w-3.5" /> },
                ].map(scope => (
                  <label key={scope.key} className={`flex items-start gap-3 p-2.5 rounded-lg cursor-pointer border transition-all ${
                    resetScope[scope.key] ? 'bg-amber-500/5 border-amber-500/20' : 'border-transparent hover:bg-muted/30'
                  }`}>
                    <Checkbox
                      checked={resetScope[scope.key]}
                      onCheckedChange={(c) => setResetScope(prev => ({ ...prev, [scope.key]: !!c }))}
                      className="mt-0.5"
                    />
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-amber-400">{scope.icon}</span>
                        <span className="text-sm font-medium">{scope.label}</span>
                        {!resetScope[scope.key] && <Badge variant="outline" className="text-[10px] px-1.5 py-0 h-4 border-green-500/30 text-green-400">Preserved</Badge>}
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5">{scope.desc}</p>
                    </div>
                  </label>
                ))}
              </div>
            </div>
          </div>
          <AlertDialogFooter className="px-6 pb-6 pt-4 shrink-0 border-t border-border/50">
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-gradient-to-r from-cyan-600 to-blue-600"
              onClick={() => rerunMut.mutate({
                engagementId,
                phases: rerunPhases,
                resetScope,
              })}
              disabled={rerunMut.isPending || !Object.values(rerunPhases).some(Boolean)}
            >
              {rerunMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Play className="h-4 w-4 mr-1" />}
              {allResetChecked ? 'Full Reset & Re-Run' : noneResetChecked ? 'Re-Run (Keep All Data)' : 'Partial Reset & Re-Run'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ── Re-run From Phase Dialog ── */}
      <AlertDialog open={showRerunFromPhaseDialog} onOpenChange={setShowRerunFromPhaseDialog}>
        <AlertDialogContent className="max-w-md max-h-[85vh] flex flex-col p-0">
          <AlertDialogHeader className="px-6 pt-6 pb-2 shrink-0">
            <AlertDialogTitle className="flex items-center gap-2">
              <RotateCcw className="h-5 w-5 text-amber-400" />
              Re-run From Phase
            </AlertDialogTitle>
            <AlertDialogDescription>
              Restart the pipeline from a specific phase. All data from earlier phases will be preserved; data from the selected phase onward will be cleared and re-generated.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="flex-1 overflow-y-auto px-6 min-h-0">
            <div className="space-y-3 py-2">
              <div className="space-y-1.5">
                {[
                  { id: 'recon' as const, label: 'Domain Recon', desc: 'Clears all data and starts fresh from passive OSINT', icon: <Radar className="h-4 w-4" />, preserves: 'Nothing' },
                  { id: 'passive_discovery' as const, label: 'Passive Discovery', desc: 'Re-runs passive enumeration (DNS, certs, tech fingerprinting)', icon: <Search className="h-4 w-4" />, preserves: 'Domain recon data' },
                  { id: 'scoping' as const, label: 'Scoping & RoE Review', desc: 'Re-validates scope and RoE checklist', icon: <FileCheck className="h-4 w-4" />, preserves: 'Recon + passive discovery' },
                  { id: 'test_plan' as const, label: 'Test Plan Generation', desc: 'Re-generates the NIST 800-115 aligned test plan', icon: <FileText className="h-4 w-4" />, preserves: 'Recon + passive + scope' },
                  { id: 'enumeration' as const, label: 'Active Discovery', desc: 'Re-runs port discovery (naabu/Nerva) and service fingerprinting', icon: <Network className="h-4 w-4" />, preserves: 'Recon + passive + scope + plan' },
                  { id: 'vuln_detection' as const, label: 'Vulnerability Scanning', desc: 'Re-runs vuln scanning (Nuclei, ZAP, LLM analysis)', icon: <ShieldOff className="h-4 w-4" />, preserves: 'All through active discovery' },
                  { id: 'exploitation' as const, label: 'Exploitation', desc: 'Re-runs exploit generation and execution', icon: <Swords className="h-4 w-4" />, preserves: 'All through vuln scan' },
                  { id: 'post_exploit' as const, label: 'Post-Exploitation', desc: 'Re-runs post-exploit analysis and reporting prep', icon: <Key className="h-4 w-4" />, preserves: 'All prior phases' },
                ].map(phase => (
                  <label
                    key={phase.id}
                    className={`flex items-start gap-3 p-3 rounded-lg cursor-pointer border transition-all ${
                      rerunTargetPhase === phase.id
                        ? 'bg-amber-500/10 border-amber-500/30 ring-1 ring-amber-500/20'
                        : 'border-transparent hover:bg-muted/30'
                    }`}
                    onClick={() => setRerunTargetPhase(phase.id)}
                  >
                    <div className={`mt-0.5 h-4 w-4 rounded-full border-2 flex items-center justify-center ${
                      rerunTargetPhase === phase.id ? 'border-amber-400' : 'border-muted-foreground/30'
                    }`}>
                      {rerunTargetPhase === phase.id && <div className="h-2 w-2 rounded-full bg-amber-400" />}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-amber-400">{phase.icon}</span>
                        <span className="text-sm font-medium">{phase.label}</span>
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5">{phase.desc}</p>
                      <p className="text-[10px] text-muted-foreground/70 mt-0.5">Preserves: {phase.preserves}</p>
                    </div>
                  </label>
                ))}
              </div>
              {ops && (
                <div className="p-2.5 rounded-lg bg-muted/20 border border-border/30">
                  <div className="text-[10px] text-muted-foreground">Current state: {ops.assets?.length || 0} assets, {ops.stats?.vulnsFound || 0} vulns, {ops.stats?.exploitsSucceeded || 0} exploits</div>
                </div>
              )}
            </div>
          </div>
          <AlertDialogFooter className="px-6 pb-6 pt-4 shrink-0 border-t border-border/50">
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500"
              onClick={() => rerunFromPhaseMut.mutate({
                engagementId,
                targetPhase: rerunTargetPhase,
              })}
              disabled={rerunFromPhaseMut.isPending}
            >
              {rerunFromPhaseMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Play className="h-4 w-4 mr-1" />}
              Re-run from {rerunTargetPhase.replace(/_/g, ' ')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ── Resume Engagement Dialog ── */}
      <AlertDialog open={showResumeDialog} onOpenChange={setShowResumeDialog}>
        <AlertDialogContent className="max-w-md">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <Play className="h-5 w-5 text-emerald-400" />
              Resume Engagement
            </AlertDialogTitle>
            <AlertDialogDescription>
              Resume the engagement from where it was interrupted. All previously collected data will be preserved.
            </AlertDialogDescription>
          </AlertDialogHeader>
          {resumeCapabilityQ.data && (
            <div className="space-y-3 py-2">
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
                  <div className="text-lg font-bold text-emerald-400">{resumeCapabilityQ.data.preservedAssets ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground">Assets Preserved</div>
                </div>
                <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/20">
                  <div className="text-lg font-bold text-red-400">{resumeCapabilityQ.data.preservedVulns ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground">Vulns Found</div>
                </div>
                <div className="p-3 rounded-lg bg-blue-500/5 border border-blue-500/20">
                  <div className="text-lg font-bold text-blue-400">{resumeCapabilityQ.data.preservedPorts ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground">Ports Discovered</div>
                </div>
                <div className="p-3 rounded-lg bg-purple-500/5 border border-purple-500/20">
                  <div className="text-lg font-bold text-purple-400">{resumeCapabilityQ.data.logCount ?? 0}</div>
                  <div className="text-[10px] text-muted-foreground">Log Entries</div>
                </div>
              </div>
              <div className="p-3 rounded-lg bg-card/50 border border-border/30">
                <div className="flex items-center gap-2">
                  <ArrowRight className="h-4 w-4 text-cyan-400" />
                  <div>
                    <div className="text-sm font-medium">Next Phase: <span className="text-cyan-400">{resumeCapabilityQ.data.nextPhaseLabel || 'Unknown'}</span></div>
                    <div className="text-[10px] text-muted-foreground">Last completed: {resumeCapabilityQ.data.currentPhaseLabel || 'None'}</div>
                  </div>
                </div>
              </div>
            </div>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-gradient-to-r from-emerald-600 to-cyan-600"
              onClick={() => resumeMut.mutate({
                engagementId,
                resume: true,
                startPhase: resumeCapabilityQ.data?.nextPhase as any,
              })}
              disabled={resumeMut.isPending}
            >
              {resumeMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Play className="h-4 w-4 mr-1" />}
              Resume Engagement
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
                {Array.isArray(exploitDetailQ.data.mitigations) && exploitDetailQ.data.mitigations.length > 0 && (
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

function StatCard({ icon, label, value, onClick }: { icon: React.ReactNode; label: string; value: number | string; onClick?: () => void }) {
  return (
    <div
      className={`flex items-center gap-2.5 rounded-md px-2 py-1 -mx-2 transition-all duration-150 ${onClick ? 'cursor-pointer hover:bg-primary/5 hover:text-primary active:scale-[0.98]' : ''}`}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (e: React.KeyboardEvent) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick(); } } : undefined}
    >
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
            {Array.isArray(chain.mitreTechniques) && chain.mitreTechniques.length > 0 && (
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
            {Array.isArray(chain.steps) && chain.steps.length > 0 && (
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
            {Array.isArray(chain.cloudExploitPaths) && chain.cloudExploitPaths.length > 0 && (
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
            {Array.isArray(chain.recommendations) && chain.recommendations.length > 0 && (
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
  nmap: "text-cyan-400 border-cyan-500/30",  // legacy — kept for backward compat
  nerva: "text-cyan-400 border-cyan-500/30",
  naabu: "text-cyan-400 border-cyan-500/30",
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


/**
 * ScanReportImportPanel — Upload and import vulnerability scan reports
 * from commercial scanners (Nessus, Qualys, Burp Suite, ZAP, OpenVAS, Rapid7)
 * into the engagement ops state with LLM validation.
 */
function ScanReportImportPanel({ engagementId }: { engagementId: number }) {
  const [file, setFile] = useState<File | null>(null);
  const [fileContent, setFileContent] = useState<string>("");
  const [scannerType, setScannerType] = useState<string>("custom");
  const [previewData, setPreviewData] = useState<any>(null);
  const [selectedIndices, setSelectedIndices] = useState<Set<number>>(new Set());
  const [importResult, setImportResult] = useState<any>(null);
  const [step, setStep] = useState<"upload" | "preview" | "result">("upload");
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Queries
  const importsQ = trpc.engagementScanImports.listImports.useQuery(
    { engagementId },
    { enabled: engagementId > 0 }
  );
  const formatsQ = trpc.engagementScanImports.getSupportedFormats.useQuery();

  // Mutations
  const parseMut = trpc.engagementScanImports.parsePreview.useMutation();
  const importMut = trpc.engagementScanImports.importFindings.useMutation();
  const llmValidateMut = trpc.engagementScanImports.runLlmValidation.useMutation();

  const handleFileSelect = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    setFile(f);
    const text = await f.text();
    setFileContent(text);

    // Auto-detect format from first 500 chars
    const snippet = text.substring(0, 500);
    if (snippet.includes("<NessusClientData") || snippet.includes("<NessusClientData_v2")) {
      setScannerType("nessus");
    } else if (snippet.includes("<OWASPZAPReport") || snippet.includes('"@generated"')) {
      setScannerType("zap");
    } else if (snippet.includes("<issues") && snippet.includes("burpVersion")) {
      setScannerType("burp");
    } else if (snippet.includes("<report") && (snippet.includes("openvas") || snippet.includes("OpenVAS"))) {
      setScannerType("openvas");
    } else if (f.name.endsWith(".csv")) {
      // Check for Qualys vs Rapid7 patterns
      if (snippet.includes("QID") || snippet.includes("Qualys")) {
        setScannerType("qualys");
      } else {
        setScannerType("rapid7");
      }
    }
  }, []);

  const handleParse = useCallback(async () => {
    if (!fileContent || !file) return;
    try {
      const result = await parseMut.mutateAsync({
        engagementId,
        scannerType: scannerType as any,
        fileContent,
        fileName: file.name,
      });
      setPreviewData(result);
      // Select all non-duplicate findings by default
      const indices = new Set<number>();
      result.findings.forEach((f: any) => {
        if (!f.isDuplicate) indices.add(f.index);
      });
      setSelectedIndices(indices);
      setStep("preview");
    } catch (err: any) {
      toast.error(`Parse failed: ${err.message}`);
    }
  }, [fileContent, file, scannerType, engagementId, parseMut]);

  const handleImport = useCallback(async () => {
    if (!fileContent || !file) return;
    try {
      const result = await importMut.mutateAsync({
        engagementId,
        scannerType: scannerType as any,
        fileContent,
        fileName: file.name,
        selectedIndices: Array.from(selectedIndices),
        runLlmValidation: true,
      });
      setImportResult(result);
      setStep("result");
      importsQ.refetch();
      toast.success(`Imported ${result.added} findings (${result.skipped} duplicates skipped)`);
    } catch (err: any) {
      toast.error(`Import failed: ${err.message}`);
    }
  }, [fileContent, file, scannerType, selectedIndices, engagementId, importMut, importsQ]);

  const handleReset = useCallback(() => {
    setFile(null);
    setFileContent("");
    setScannerType("custom");
    setPreviewData(null);
    setSelectedIndices(new Set());
    setImportResult(null);
    setStep("upload");
    if (fileInputRef.current) fileInputRef.current.value = "";
  }, []);

  const toggleFinding = useCallback((idx: number) => {
    setSelectedIndices(prev => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  }, []);

  const selectAll = useCallback(() => {
    if (!previewData) return;
    const all = new Set<number>();
    previewData.findings.forEach((f: any) => all.add(f.index));
    setSelectedIndices(all);
  }, [previewData]);

  const selectNew = useCallback(() => {
    if (!previewData) return;
    const newOnes = new Set<number>();
    previewData.findings.forEach((f: any) => {
      if (!f.isDuplicate) newOnes.add(f.index);
    });
    setSelectedIndices(newOnes);
  }, [previewData]);

  const sevColor: Record<string, string> = {
    critical: "text-red-400 bg-red-500/10 border-red-500/30",
    high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
    medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
    low: "text-blue-400 bg-blue-500/10 border-blue-500/30",
    info: "text-gray-400 bg-gray-500/10 border-gray-500/30",
  };

  const verdictColor: Record<string, string> = {
    confirmed: "text-green-400 bg-green-500/10",
    likely: "text-emerald-400 bg-emerald-500/10",
    unverified: "text-yellow-400 bg-yellow-500/10",
    likely_false_positive: "text-red-400 bg-red-500/10",
  };

  return (
    <div className="space-y-4 py-2">
      {/* ── Upload Step ── */}
      {step === "upload" && (
        <div className="space-y-4">
          <Card className="border-dashed border-2 border-border/50 bg-card/30">
            <CardContent className="p-6">
              <div className="flex flex-col items-center gap-4">
                <div className="p-4 rounded-full bg-purple-500/10 border border-purple-500/20">
                  <Upload className="h-8 w-8 text-purple-400" />
                </div>
                <div className="text-center">
                  <h3 className="text-sm font-semibold text-foreground">Upload Scan Report</h3>
                  <p className="text-xs text-muted-foreground mt-1">
                    Import vulnerability findings from Nessus, Qualys, Burp Suite, OWASP ZAP, OpenVAS, or Rapid7
                  </p>
                </div>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".xml,.csv,.json,.nessus"
                  onChange={handleFileSelect}
                  className="hidden"
                />
                <Button
                  variant="outline"
                  onClick={() => fileInputRef.current?.click()}
                  className="gap-2"
                >
                  <FileUp className="h-4 w-4" />
                  Choose File
                </Button>
                {file && (
                  <div className="w-full space-y-3">
                    <div className="flex items-center gap-2 text-xs bg-muted/30 rounded-lg px-3 py-2">
                      <FileText className="h-3.5 w-3.5 text-muted-foreground" />
                      <span className="text-foreground font-medium truncate">{file.name}</span>
                      <span className="text-muted-foreground">({(file.size / 1024).toFixed(1)} KB)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <label className="text-xs text-muted-foreground whitespace-nowrap">Scanner:</label>
                      <select
                        value={scannerType}
                        onChange={e => setScannerType(e.target.value)}
                        className="flex-1 text-xs bg-background border border-border rounded-md px-2 py-1.5 text-foreground"
                      >
                        {(formatsQ.data || []).map(f => (
                          <option key={f.value} value={f.value}>{f.label} ({f.formats})</option>
                        ))}
                      </select>
                    </div>
                    <Button
                      onClick={handleParse}
                      disabled={parseMut.isPending}
                      className="w-full gap-2"
                      size="sm"
                    >
                      {parseMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
                      Parse & Preview
                    </Button>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Previous imports */}
          {(importsQ.data?.length || 0) > 0 && (
            <Card className="bg-card/30 border-border/30">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Previous Imports
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {importsQ.data!.map((imp: any) => (
                  <div key={imp.id} className="flex items-center justify-between text-xs bg-muted/20 rounded-lg px-3 py-2 border border-border/20">
                    <div className="flex items-center gap-2 min-w-0">
                      <Badge variant="outline" className="text-[10px] shrink-0">{imp.vsiScannerType}</Badge>
                      <span className="text-foreground truncate">{imp.vsiFileName.replace(`[eng-${engagementId}] `, "")}</span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-muted-foreground">{imp.vsiTotalVulns} vulns</span>
                      <span className="text-muted-foreground">{new Date(imp.vsiImportedAt).toLocaleDateString()}</span>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* ── Preview Step ── */}
      {step === "preview" && previewData && (
        <div className="space-y-4">
          {/* Summary stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            <Card className="bg-card/30 border-border/30 p-3">
              <div className="text-[10px] text-muted-foreground uppercase">Scanner</div>
              <div className="text-sm font-semibold text-foreground">{previewData.scannerLabel}</div>
            </Card>
            <Card className="bg-card/30 border-border/30 p-3">
              <div className="text-[10px] text-muted-foreground uppercase">Total Findings</div>
              <div className="text-sm font-semibold text-foreground">{previewData.totalFindings}</div>
            </Card>
            <Card className="bg-card/30 border-border/30 p-3">
              <div className="text-[10px] text-muted-foreground uppercase">New</div>
              <div className="text-sm font-semibold text-green-400">{previewData.newFindings}</div>
            </Card>
            <Card className="bg-card/30 border-border/30 p-3">
              <div className="text-[10px] text-muted-foreground uppercase">Duplicates</div>
              <div className="text-sm font-semibold text-yellow-400">{previewData.duplicateFindings}</div>
            </Card>
          </div>

          {/* Severity breakdown */}
          <div className="flex gap-2 flex-wrap">
            {previewData.criticalCount > 0 && <Badge className={sevColor.critical}>{previewData.criticalCount} Critical</Badge>}
            {previewData.highCount > 0 && <Badge className={sevColor.high}>{previewData.highCount} High</Badge>}
            {previewData.mediumCount > 0 && <Badge className={sevColor.medium}>{previewData.mediumCount} Medium</Badge>}
            {previewData.lowCount > 0 && <Badge className={sevColor.low}>{previewData.lowCount} Low</Badge>}
          </div>

          {/* Selection controls */}
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={selectAll} className="text-xs h-7">Select All</Button>
            <Button variant="outline" size="sm" onClick={selectNew} className="text-xs h-7">Select New Only</Button>
            <Button variant="outline" size="sm" onClick={() => setSelectedIndices(new Set())} className="text-xs h-7">Deselect All</Button>
            <span className="text-xs text-muted-foreground ml-auto">{selectedIndices.size} selected</span>
          </div>

          {/* Findings list */}
          <div className="space-y-1 max-h-[400px] overflow-y-auto pr-1">
            {previewData.findings.map((f: any) => (
              <div
                key={f.index}
                className={`flex items-start gap-2 text-xs rounded-lg px-3 py-2 border cursor-pointer transition-colors ${
                  f.isDuplicate
                    ? "bg-yellow-500/5 border-yellow-500/10 opacity-60"
                    : selectedIndices.has(f.index)
                    ? "bg-purple-500/10 border-purple-500/30"
                    : "bg-muted/10 border-border/20 hover:bg-muted/20"
                }`}
                onClick={() => toggleFinding(f.index)}
              >
                <Checkbox
                  checked={selectedIndices.has(f.index)}
                  onCheckedChange={() => toggleFinding(f.index)}
                  className="mt-0.5 shrink-0"
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <Badge className={`text-[9px] px-1 py-0 ${sevColor[f.severity] || sevColor.info}`}>
                      {f.severity}
                    </Badge>
                    <span className="font-medium text-foreground truncate">{f.title}</span>
                    {f.isDuplicate && (
                      <Badge variant="outline" className="text-[9px] text-yellow-400 border-yellow-500/30">DUP</Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-2 mt-0.5 text-muted-foreground">
                    {f.cveId && <span className="font-mono text-cyan-400">{f.cveId}</span>}
                    {f.hostIp && <span>{f.hostIp}</span>}
                    {f.port && <span>:{f.port}</span>}
                    {f.cvssScore != null && <span>CVSS {f.cvssScore}</span>}
                    {f.exploitAvailable && <Badge className="text-[8px] bg-red-500/10 text-red-400 px-1 py-0">Exploit</Badge>}
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Action buttons */}
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={handleReset} className="gap-1">
              <RotateCcw className="h-3 w-3" /> Back
            </Button>
            <Button
              size="sm"
              onClick={handleImport}
              disabled={importMut.isPending || selectedIndices.size === 0}
              className="flex-1 gap-1"
            >
              {importMut.isPending ? (
                <><Loader2 className="h-3.5 w-3.5 animate-spin" /> Importing & Validating...</>
              ) : (
                <><ArrowRight className="h-3.5 w-3.5" /> Import {selectedIndices.size} Findings</>
              )}
            </Button>
          </div>
        </div>
      )}

      {/* ── Result Step ── */}
      {step === "result" && importResult && (
        <div className="space-y-4">
          <Card className="bg-emerald-500/5 border-emerald-500/20">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                <h3 className="text-sm font-semibold text-emerald-400">Import Complete</h3>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                <div>
                  <div className="text-muted-foreground">Added</div>
                  <div className="text-lg font-bold text-green-400">{importResult.added}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Skipped (Dup)</div>
                  <div className="text-lg font-bold text-yellow-400">{importResult.skipped}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">New Assets</div>
                  <div className="text-lg font-bold text-purple-400">{importResult.newAssetsCreated}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Assets Matched</div>
                  <div className="text-lg font-bold text-cyan-400">{importResult.assetsMatched}</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Corroboration results */}
          {importResult.corroboration && (
            <Card className="bg-card/30 border-border/30">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                  <Layers className="h-3.5 w-3.5" /> Cross-Source Corroboration
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div className="bg-muted/20 rounded-lg p-2 text-center">
                    <div className="text-muted-foreground">Analyzed</div>
                    <div className="text-sm font-semibold">{importResult.corroboration.totalAnalyzed}</div>
                  </div>
                  <div className="bg-green-500/10 rounded-lg p-2 text-center">
                    <div className="text-green-400">Corroborated</div>
                    <div className="text-sm font-semibold text-green-400">{importResult.corroboration.corroborated}</div>
                  </div>
                  <div className="bg-orange-500/10 rounded-lg p-2 text-center">
                    <div className="text-orange-400">Suppressed</div>
                    <div className="text-sm font-semibold text-orange-400">{importResult.corroboration.suppressed}</div>
                  </div>
                </div>
                {importResult.corroboration.estimatedFPReduction > 0 && (
                  <div className="text-xs text-emerald-400 bg-emerald-500/5 rounded-lg px-3 py-1.5 border border-emerald-500/10">
                    Estimated false positive reduction: {importResult.corroboration.estimatedFPReduction}%
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* LLM Validation results */}
          {importResult.llmValidation && (
            <Card className="bg-card/30 border-border/30">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                  <Brain className="h-3.5 w-3.5" /> LLM Validation
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="grid grid-cols-4 gap-2 text-xs">
                  <div className="bg-green-500/10 rounded-lg p-2 text-center">
                    <div className="text-green-400">Confirmed</div>
                    <div className="text-sm font-semibold text-green-400">{importResult.llmValidation.summary.confirmed}</div>
                  </div>
                  <div className="bg-emerald-500/10 rounded-lg p-2 text-center">
                    <div className="text-emerald-400">Likely</div>
                    <div className="text-sm font-semibold text-emerald-400">{importResult.llmValidation.summary.likely}</div>
                  </div>
                  <div className="bg-yellow-500/10 rounded-lg p-2 text-center">
                    <div className="text-yellow-400">Unverified</div>
                    <div className="text-sm font-semibold text-yellow-400">{importResult.llmValidation.summary.unverified}</div>
                  </div>
                  <div className="bg-red-500/10 rounded-lg p-2 text-center">
                    <div className="text-red-400">Likely FP</div>
                    <div className="text-sm font-semibold text-red-400">{importResult.llmValidation.summary.likelyFalsePositive}</div>
                  </div>
                </div>

                {/* Individual validations */}
                <div className="space-y-1 max-h-[250px] overflow-y-auto">
                  {importResult.llmValidation.validations.map((v: any, i: number) => (
                    <div key={i} className="flex items-start gap-2 text-xs bg-muted/10 rounded-lg px-3 py-2 border border-border/20">
                      <Badge className={`text-[9px] px-1.5 py-0 shrink-0 ${verdictColor[v.verdict] || ""}`}>
                        {v.verdict.replace("_", " ")}
                      </Badge>
                      <div className="min-w-0 flex-1">
                        <div className="font-medium text-foreground truncate">{v.title}</div>
                        <div className="text-muted-foreground mt-0.5">{v.reasoning}</div>
                      </div>
                      <span className="text-muted-foreground shrink-0">{v.confidence}%</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          <Button variant="outline" size="sm" onClick={handleReset} className="gap-1 w-full">
            <Plus className="h-3 w-3" /> Import Another Report
          </Button>
        </div>
      )}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════
// C2 Network Map — SVG-based network topology showing C2 agents as nodes
// with lateral movement paths between compromised hosts
// ═══════════════════════════════════════════════════════════════════════════

interface MapNode {
  id: string;
  label: string;
  type: 'attacker' | 'agent' | 'target' | 'pivot';
  x: number;
  y: number;
  status: 'online' | 'offline' | 'lost' | 'initial';
  platform?: string;
  paw?: string;
  executors?: string[];
  group?: string;
  ip?: string;
}

interface MapEdge {
  from: string;
  to: string;
  type: 'initial_access' | 'lateral_movement' | 'c2_callback' | 'pivot';
  label?: string;
  animated?: boolean;
}

function C2NetworkMap({ engagementId }: { engagementId: number }) {
  const [selectedNode, setSelectedNode] = useState<MapNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  // Get C2 poller state for live agent data
  const pollerStateQ = trpc.liveTrigger.getC2PollerState.useQuery(
    { engagementId },
    { refetchInterval: 15000, enabled: engagementId > 0 }
  );

  // Get engagement ops state for asset data
  const opsStateQ = trpc.liveTrigger.getState.useQuery(
    { engagementId },
    { refetchInterval: 30000, enabled: engagementId > 0 }
  );

  // WebSocket events for real-time updates
  const { events: c2Events } = useWebSocket({
    channels: [`engagement:${engagementId}`],
    filterTypes: ['c2:agent_checkin', 'c2:agent_lost', 'c2:ability_executed'],
    maxEvents: 50,
    enabled: engagementId > 0,
  });

  // Build topology from poller + ops data
  const { nodes, edges } = useMemo(() => {
    const nodeMap = new Map<string, MapNode>();
    const edgeList: MapEdge[] = [];

    const pollerData = pollerStateQ.data;
    const opsData = opsStateQ.data as any;

    // Attacker node (always present)
    nodeMap.set('attacker', {
      id: 'attacker',
      label: 'Operator',
      type: 'attacker',
      x: 80,
      y: 300,
      status: 'initial',
      platform: 'C2 Server',
    });

    // Add agents from poller data
    if (Array.isArray(pollerData?.agents) && pollerData.agents.length > 0) {
      const agentCount = pollerData.agents.length;
      const startY = Math.max(100, 300 - (agentCount * 60));
      pollerData.agents.forEach((agent: any, idx: number) => {
        const nodeId = `agent-${agent.paw}`;
        const yPos = startY + idx * 120;
        const xPos = 350 + (idx % 2 === 0 ? 0 : 60);
        nodeMap.set(nodeId, {
          id: nodeId,
          label: agent.host || agent.paw,
          type: 'agent',
          x: xPos,
          y: yPos,
          status: 'online',
          platform: agent.platform,
          paw: agent.paw,
          executors: agent.executors,
          group: agent.group,
          ip: agent.host,
        });
        // C2 callback from attacker to agent
        edgeList.push({
          from: 'attacker',
          to: nodeId,
          type: 'c2_callback',
          label: 'C2',
          animated: true,
        });
      });
    }

    // Add target assets from ops state
    if (Array.isArray(opsData?.assets) && opsData.assets.length > 0) {
      const existingHosts = new Set(
        Array.from(nodeMap.values()).map(n => n.ip || n.label)
      );
      const targetAssets = opsData.assets.filter(
        (a: any) => !existingHosts.has(a.ip) && !existingHosts.has(a.hostname)
      );
      const startY = Math.max(80, 300 - (targetAssets.length * 40));
      targetAssets.slice(0, 8).forEach((asset: any, idx: number) => {
        const nodeId = `target-${asset.ip || asset.hostname}`;
        const yPos = startY + idx * 90;
        nodeMap.set(nodeId, {
          id: nodeId,
          label: asset.hostname || asset.ip,
          type: 'target',
          x: 620 + (idx % 2 === 0 ? 0 : 50),
          y: yPos,
          status: 'offline',
          platform: asset.type || 'unknown',
          ip: asset.ip,
        });
      });

      // Lateral movement edges between agents and targets
      const agentNodes = Array.from(nodeMap.values()).filter(n => n.type === 'agent');
      const targetNodes = Array.from(nodeMap.values()).filter(n => n.type === 'target');
      if (agentNodes.length > 0 && targetNodes.length > 0) {
        // First agent connects to first target as initial pivot
        edgeList.push({
          from: agentNodes[0].id,
          to: targetNodes[0].id,
          type: 'lateral_movement',
          label: 'Pivot',
          animated: true,
        });
        // Additional agents may connect to other targets
        for (let i = 1; i < Math.min(agentNodes.length, targetNodes.length); i++) {
          edgeList.push({
            from: agentNodes[i].id,
            to: targetNodes[i].id,
            type: 'lateral_movement',
            label: 'Lateral',
          });
        }
      }
    }

    // If no agents, show targets with initial access from attacker
    if (!(Array.isArray(pollerData?.agents) && pollerData.agents.length) && Array.isArray(opsData?.assets) && opsData.assets.length > 0) {
      const targetNodes = Array.from(nodeMap.values()).filter(n => n.type === 'target');
      targetNodes.slice(0, 3).forEach(t => {
        edgeList.push({
          from: 'attacker',
          to: t.id,
          type: 'initial_access',
          label: 'Scan',
        });
      });
    }

    // Process WebSocket events for lost agents
    c2Events.forEach(evt => {
      if (evt.type === 'c2:agent_lost' && evt.data?.paw) {
        const nodeId = `agent-${evt.data.paw}`;
        const node = nodeMap.get(nodeId);
        if (node) node.status = 'lost';
      }
    });

    return { nodes: Array.from(nodeMap.values()), edges: edgeList };
  }, [pollerStateQ.data, opsStateQ.data, c2Events]);

  // Edge color by type
  const getEdgeColor = (type: MapEdge['type']) => {
    switch (type) {
      case 'c2_callback': return '#f97316'; // orange
      case 'lateral_movement': return '#ef4444'; // red
      case 'initial_access': return '#22d3ee'; // cyan
      case 'pivot': return '#a855f7'; // purple
      default: return '#6b7280';
    }
  };

  // Node color by type/status
  const getNodeColor = (node: MapNode) => {
    if (node.status === 'lost') return '#ef4444';
    switch (node.type) {
      case 'attacker': return '#f97316';
      case 'agent': return '#22c55e';
      case 'target': return '#6b7280';
      case 'pivot': return '#a855f7';
      default: return '#6b7280';
    }
  };

  const getNodeGlow = (node: MapNode) => {
    if (node.status === 'lost') return 'rgba(239,68,68,0.3)';
    if (node.type === 'attacker') return 'rgba(249,115,22,0.3)';
    if (node.type === 'agent') return 'rgba(34,197,94,0.3)';
    return 'rgba(107,114,128,0.15)';
  };

  const getNodeIcon = (node: MapNode) => {
    switch (node.type) {
      case 'attacker': return '⚔️';
      case 'agent': return node.status === 'lost' ? '💀' : '🤖';
      case 'target': return '🎯';
      case 'pivot': return '🔄';
      default: return '📌';
    }
  };

  const svgWidth = 820;
  const svgHeight = Math.max(600, nodes.length * 80 + 100);

  return (
    <div className="space-y-4 p-2">
      <p className="text-sm text-muted-foreground">
        Interactive network topology showing C2 agents, compromised hosts, and lateral movement paths. Nodes update in real-time as agents check in or are lost.
      </p>

      {/* Legend */}
      <div className="flex flex-wrap gap-4 text-[10px] text-muted-foreground">
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-full bg-orange-500" /> Operator (C2 Server)
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-full bg-green-500" /> Active Agent
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-full bg-red-500" /> Lost Agent
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-full bg-gray-500" /> Target (Uncompromised)
        </div>
        <div className="flex items-center gap-1.5">
          <svg width="24" height="2"><line x1="0" y1="1" x2="24" y2="1" stroke="#f97316" strokeWidth="2" strokeDasharray="4 2" /></svg> C2 Callback
        </div>
        <div className="flex items-center gap-1.5">
          <svg width="24" height="2"><line x1="0" y1="1" x2="24" y2="1" stroke="#ef4444" strokeWidth="2" /></svg> Lateral Movement
        </div>
        <div className="flex items-center gap-1.5">
          <svg width="24" height="2"><line x1="0" y1="1" x2="24" y2="1" stroke="#22d3ee" strokeWidth="2" strokeDasharray="6 3" /></svg> Initial Access
        </div>
      </div>

      {/* SVG Network Map */}
      <Card className="border-border/30 overflow-hidden">
        <div className="relative" style={{ minHeight: '500px' }}>
          {nodes.length <= 1 ? (
            <div className="flex flex-col items-center justify-center h-[500px] text-muted-foreground">
              <Network className="h-12 w-12 mb-3 opacity-20" />
              <p className="text-sm">No C2 agents or targets detected yet.</p>
              <p className="text-[10px] mt-1">Agents will appear when the C2 poller detects check-ins during Phase 5.</p>
            </div>
          ) : (
            <svg
              ref={svgRef}
              viewBox={`0 0 ${svgWidth} ${svgHeight}`}
              className="w-full h-auto"
              style={{ minHeight: '500px', background: 'radial-gradient(circle at 50% 50%, rgba(249,115,22,0.02) 0%, transparent 70%)' }}
            >
              {/* Grid background */}
              <defs>
                <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="0.5" />
                </pattern>
                {/* Animated dash for C2 callbacks */}
                <style>{`
                  @keyframes dash { to { stroke-dashoffset: -20; } }
                  .animated-edge { animation: dash 1.5s linear infinite; }
                  @keyframes pulse-glow { 0%, 100% { opacity: 0.3; } 50% { opacity: 0.7; } }
                  .node-glow { animation: pulse-glow 2s ease-in-out infinite; }
                `}</style>
              </defs>
              <rect width={svgWidth} height={svgHeight} fill="url(#grid)" />

              {/* Edges */}
              {edges.map((edge, idx) => {
                const fromNode = nodes.find(n => n.id === edge.from);
                const toNode = nodes.find(n => n.id === edge.to);
                if (!fromNode || !toNode) return null;

                const color = getEdgeColor(edge.type);
                const isDashed = edge.type === 'c2_callback' || edge.type === 'initial_access';
                const midX = (fromNode.x + toNode.x) / 2;
                const midY = (fromNode.y + toNode.y) / 2 - 10;

                return (
                  <g key={`edge-${idx}`}>
                    <line
                      x1={fromNode.x}
                      y1={fromNode.y}
                      x2={toNode.x}
                      y2={toNode.y}
                      stroke={color}
                      strokeWidth={edge.animated ? 2.5 : 1.5}
                      strokeDasharray={isDashed ? '8 4' : 'none'}
                      className={edge.animated ? 'animated-edge' : ''}
                      opacity={0.7}
                    />
                    {/* Arrow head */}
                    <circle
                      cx={toNode.x - (toNode.x - fromNode.x) * 0.15}
                      cy={toNode.y - (toNode.y - fromNode.y) * 0.15}
                      r={3}
                      fill={color}
                    />
                    {/* Edge label */}
                    {edge.label && (
                      <text
                        x={midX}
                        y={midY}
                        textAnchor="middle"
                        fill={color}
                        fontSize={9}
                        fontWeight="bold"
                        opacity={0.8}
                      >
                        {edge.label}
                      </text>
                    )}
                  </g>
                );
              })}

              {/* Nodes */}
              {nodes.map((node) => {
                const color = getNodeColor(node);
                const glow = getNodeGlow(node);
                const isHovered = hoveredNode === node.id;
                const isSelected = selectedNode?.id === node.id;
                const radius = node.type === 'attacker' ? 28 : 22;

                return (
                  <g
                    key={node.id}
                    className="cursor-pointer"
                    onClick={() => setSelectedNode(isSelected ? null : node)}
                    onMouseEnter={() => setHoveredNode(node.id)}
                    onMouseLeave={() => setHoveredNode(null)}
                  >
                    {/* Glow */}
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={radius + 8}
                      fill={glow}
                      className={node.type === 'agent' && node.status === 'online' ? 'node-glow' : ''}
                    />
                    {/* Node circle */}
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={radius}
                      fill="rgba(0,0,0,0.6)"
                      stroke={color}
                      strokeWidth={isHovered || isSelected ? 3 : 2}
                    />
                    {/* Icon */}
                    <text
                      x={node.x}
                      y={node.y + 5}
                      textAnchor="middle"
                      fontSize={node.type === 'attacker' ? 18 : 14}
                    >
                      {getNodeIcon(node)}
                    </text>
                    {/* Label */}
                    <text
                      x={node.x}
                      y={node.y + radius + 16}
                      textAnchor="middle"
                      fill="white"
                      fontSize={10}
                      fontWeight="600"
                    >
                      {node.label.length > 20 ? node.label.substring(0, 18) + '...' : node.label}
                    </text>
                    {/* Platform badge */}
                    {node.platform && (
                      <text
                        x={node.x}
                        y={node.y + radius + 28}
                        textAnchor="middle"
                        fill="rgba(255,255,255,0.5)"
                        fontSize={8}
                      >
                        {node.platform}
                      </text>
                    )}
                    {/* Status indicator */}
                    {node.type === 'agent' && (
                      <circle
                        cx={node.x + radius - 4}
                        cy={node.y - radius + 4}
                        r={5}
                        fill={node.status === 'online' ? '#22c55e' : node.status === 'lost' ? '#ef4444' : '#6b7280'}
                        stroke="rgba(0,0,0,0.5)"
                        strokeWidth={1.5}
                      />
                    )}
                  </g>
                );
              })}
            </svg>
          )}
        </div>
      </Card>

      {/* Selected Node Detail Panel */}
      {selectedNode && (
        <Card className="border-border/30">
          <CardHeader className="py-3 px-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-lg">{getNodeIcon(selectedNode)}</span>
                <CardTitle className="text-sm">{selectedNode.label}</CardTitle>
                <Badge
                  variant="outline"
                  className={`text-[10px] ${
                    selectedNode.status === 'online' ? 'text-green-400 border-green-500/30' :
                    selectedNode.status === 'lost' ? 'text-red-400 border-red-500/30' :
                    'text-muted-foreground border-border/30'
                  }`}
                >
                  {selectedNode.status}
                </Badge>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSelectedNode(null)}
                className="h-6 w-6 p-0"
              >
                <X className="h-3 w-3" />
              </Button>
            </div>
          </CardHeader>
          <CardContent className="px-4 pb-3 pt-0">
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <span className="text-muted-foreground">Type:</span>{' '}
                <span className="font-semibold capitalize">{selectedNode.type}</span>
              </div>
              {selectedNode.ip && (
                <div>
                  <span className="text-muted-foreground">IP:</span>{' '}
                  <span className="font-mono">{selectedNode.ip}</span>
                </div>
              )}
              {selectedNode.paw && (
                <div>
                  <span className="text-muted-foreground">Paw:</span>{' '}
                  <span className="font-mono">{selectedNode.paw}</span>
                </div>
              )}
              {selectedNode.platform && (
                <div>
                  <span className="text-muted-foreground">Platform:</span>{' '}
                  <span>{selectedNode.platform}</span>
                </div>
              )}
              {selectedNode.group && (
                <div>
                  <span className="text-muted-foreground">Group:</span>{' '}
                  <span>{selectedNode.group}</span>
                </div>
              )}
              {Array.isArray(selectedNode.executors) && selectedNode.executors.length > 0 && (
                <div className="col-span-2">
                  <span className="text-muted-foreground">Executors:</span>{' '}
                  <span>{selectedNode.executors.join(', ')}</span>
                </div>
              )}
            </div>
            {/* Show edges connected to this node */}
            <div className="mt-2 pt-2 border-t border-border/20">
              <span className="text-[10px] text-muted-foreground font-semibold">Connections:</span>
              <div className="mt-1 space-y-1">
                {edges
                  .filter(e => e.from === selectedNode.id || e.to === selectedNode.id)
                  .map((edge, idx) => {
                    const otherNodeId = edge.from === selectedNode.id ? edge.to : edge.from;
                    const otherNode = nodes.find(n => n.id === otherNodeId);
                    const direction = edge.from === selectedNode.id ? '→' : '←';
                    return (
                      <div key={idx} className="flex items-center gap-2 text-[10px]">
                        <div
                          className="w-2 h-2 rounded-full"
                          style={{ backgroundColor: getEdgeColor(edge.type) }}
                        />
                        <span>{direction} {otherNode?.label || otherNodeId}</span>
                        <Badge variant="outline" className="text-[9px] h-4">
                          {edge.type.replace(/_/g, ' ')}
                        </Badge>
                      </div>
                    );
                  })}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Stats Summary */}
      <div className="grid grid-cols-4 gap-3">
        <Card className="border-border/30 p-3 text-center">
          <div className="text-lg font-bold text-green-400">
            {nodes.filter(n => n.type === 'agent' && n.status === 'online').length}
          </div>
          <div className="text-[10px] text-muted-foreground">Active Agents</div>
        </Card>
        <Card className="border-border/30 p-3 text-center">
          <div className="text-lg font-bold text-red-400">
            {nodes.filter(n => n.type === 'agent' && n.status === 'lost').length}
          </div>
          <div className="text-[10px] text-muted-foreground">Lost Agents</div>
        </Card>
        <Card className="border-border/30 p-3 text-center">
          <div className="text-lg font-bold text-gray-400">
            {nodes.filter(n => n.type === 'target').length}
          </div>
          <div className="text-[10px] text-muted-foreground">Targets</div>
        </Card>
        <Card className="border-border/30 p-3 text-center">
          <div className="text-lg font-bold text-orange-400">
            {edges.filter(e => e.type === 'lateral_movement').length}
          </div>
          <div className="text-[10px] text-muted-foreground">Lateral Moves</div>
        </Card>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// C2 Activity Feed — Live Caldera C2 agent check-ins, ability executions,
// and operation progress via WebSocket events and tRPC polling
// ═══════════════════════════════════════════════════════════════════════════

function C2ActivityFeed({ engagementId }: { engagementId: number }) {
  const [isStarting, setIsStarting] = useState(false);
  const [operationIdInput, setOperationIdInput] = useState("");

  // Query C2 poller state
  const pollerStateQ = trpc.liveTrigger.getC2PollerState.useQuery(
    { engagementId },
    { refetchInterval: 15000, enabled: engagementId > 0 }
  );
  const activePollers = trpc.liveTrigger.listC2Pollers.useQuery(
    undefined,
    { refetchInterval: 30000 }
  );

  // Mutations
  const startMut = trpc.liveTrigger.startC2Poller.useMutation({
    onSuccess: () => {
      toast.success("C2 poller started");
      pollerStateQ.refetch();
    },
    onError: (err) => toast.error(`Failed to start poller: ${err.message}`),
  });
  const stopMut = trpc.liveTrigger.stopC2Poller.useMutation({
    onSuccess: () => {
      toast.success("C2 poller stopped");
      pollerStateQ.refetch();
    },
    onError: (err) => toast.error(`Failed to stop poller: ${err.message}`),
  });

  // WebSocket events for real-time C2 updates
  const { events: c2Events } = useWebSocket({
    channels: [`engagement:${engagementId}`],
    filterTypes: [
      "c2:agent_checkin",
      "c2:ability_executed",
      "c2:operation_update",
      "c2:agent_lost",
      "c2:operation_complete",
      "operation:started",
      "operation:step_complete",
      "operation:finished",
    ],
    maxEvents: 200,
    enabled: engagementId > 0,
  });

  const pollerData = pollerStateQ.data;
  const isPolling = pollerData?.isPolling ?? false;

  const handleStart = () => {
    if (!operationIdInput.trim()) {
      toast.error("Enter a Caldera operation ID");
      return;
    }
    setIsStarting(true);
    startMut.mutate(
      { engagementId, operationId: operationIdInput.trim() },
      { onSettled: () => setIsStarting(false) }
    );
  };

  const handleStop = () => {
    stopMut.mutate({ engagementId });
  };

  // C2 event type styling
  const getEventStyle = (type: string) => {
    switch (type) {
      case "c2:agent_checkin": return { icon: <Wifi className="h-3.5 w-3.5 text-green-400" />, color: "text-green-400", bg: "bg-green-500/10 border-green-500/20" };
      case "c2:ability_executed": return { icon: <Zap className="h-3.5 w-3.5 text-cyan-400" />, color: "text-cyan-400", bg: "bg-cyan-500/10 border-cyan-500/20" };
      case "c2:operation_update": return { icon: <Activity className="h-3.5 w-3.5 text-blue-400" />, color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/20" };
      case "c2:agent_lost": return { icon: <ShieldX className="h-3.5 w-3.5 text-red-400" />, color: "text-red-400", bg: "bg-red-500/10 border-red-500/20" };
      case "c2:operation_complete": return { icon: <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />, color: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/20" };
      case "operation:step_complete": return { icon: <Terminal className="h-3.5 w-3.5 text-purple-400" />, color: "text-purple-400", bg: "bg-purple-500/10 border-purple-500/20" };
      default: return { icon: <Radio className="h-3.5 w-3.5 text-orange-400" />, color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/20" };
    }
  };

  const formatTimestamp = (ts: number) => {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  return (
    <div className="space-y-4 p-2">
      {/* Page description */}
      <p className="text-sm text-muted-foreground">
        Live Caldera C2 activity feed. Monitor agent check-ins, ability executions, and operation progress in real-time via WebSocket events from the C2 callback poller.
      </p>

      {/* Poller Controls */}
      <Card className="border-orange-500/20 bg-orange-500/5">
        <CardHeader className="py-3 px-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Radio className="h-4 w-4 text-orange-400" />
              <CardTitle className="text-sm">C2 Callback Poller</CardTitle>
              {isPolling ? (
                <Badge variant="outline" className="text-green-400 border-green-500/30 text-[10px]">
                  <div className="w-1.5 h-1.5 rounded-full bg-green-400 mr-1 animate-pulse" />
                  Polling
                </Badge>
              ) : (
                <Badge variant="outline" className="text-muted-foreground border-border/30 text-[10px]">
                  Stopped
                </Badge>
              )}
            </div>
            {isPolling && (
              <Button variant="outline" size="sm" onClick={handleStop} className="h-7 text-xs gap-1 text-red-400 border-red-500/30 hover:bg-red-500/10">
                <Square className="h-3 w-3" /> Stop
              </Button>
            )}
          </div>
        </CardHeader>
        {!isPolling && (
          <CardContent className="px-4 pb-3 pt-0">
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Caldera Operation ID"
                value={operationIdInput}
                onChange={(e) => setOperationIdInput(e.target.value)}
                className="flex-1 h-8 px-3 text-xs rounded-md border border-border/30 bg-background/50 text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-orange-500/50"
              />
              <Button
                variant="outline"
                size="sm"
                onClick={handleStart}
                disabled={isStarting || !operationIdInput.trim()}
                className="h-8 text-xs gap-1 text-orange-400 border-orange-500/30 hover:bg-orange-500/10"
              >
                {isStarting ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
                Start Polling
              </Button>
            </div>
          </CardContent>
        )}
      </Card>

      {/* Operation Snapshot */}
      {pollerData?.operationSnapshot && (
        <Card className="border-border/30">
          <CardHeader className="py-3 px-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Crosshair className="h-4 w-4 text-cyan-400" />
                <CardTitle className="text-sm">Operation: {pollerData.operationSnapshot.name}</CardTitle>
              </div>
              <Badge
                variant="outline"
                className={`text-[10px] ${
                  pollerData.operationSnapshot.state === "running" ? "text-blue-400 border-blue-500/30" :
                  pollerData.operationSnapshot.state === "finished" ? "text-emerald-400 border-emerald-500/30" :
                  "text-yellow-400 border-yellow-500/30"
                }`}
              >
                {pollerData.operationSnapshot.state}
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="px-4 pb-3 pt-0">
            <div className="grid grid-cols-4 gap-3">
              <div className="text-center">
                <div className="text-lg font-bold text-cyan-400">{pollerData.operationSnapshot.agentCount}</div>
                <div className="text-[10px] text-muted-foreground">Agents</div>
              </div>
              <div className="text-center">
                <div className="text-lg font-bold text-blue-400">{pollerData.operationSnapshot.linkCount}</div>
                <div className="text-[10px] text-muted-foreground">Abilities</div>
              </div>
              <div className="text-center">
                <div className="text-lg font-bold text-green-400">{pollerData.operationSnapshot.successCount}</div>
                <div className="text-[10px] text-muted-foreground">Success</div>
              </div>
              <div className="text-center">
                <div className="text-lg font-bold text-red-400">{pollerData.operationSnapshot.failCount}</div>
                <div className="text-[10px] text-muted-foreground">Failed</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Agents List */}
      {Array.isArray(pollerData?.agents) && pollerData.agents.length > 0 && (
        <Card className="border-border/30">
          <CardHeader className="py-3 px-4">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-green-400" />
              <CardTitle className="text-sm">Active Agents ({pollerData.agents.length})</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="px-4 pb-3 pt-0">
            <div className="space-y-2">
              {pollerData.agents.map((agent: any) => (
                <div key={agent.paw} className="flex items-center justify-between p-2 rounded-md bg-card/50 border border-border/20">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                    <div>
                      <div className="text-xs font-mono font-semibold">{agent.paw}</div>
                      <div className="text-[10px] text-muted-foreground">{agent.host} ({agent.platform})</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <Badge variant="outline" className="text-[10px]">{agent.group}</Badge>
                    <div className="text-[10px] text-muted-foreground mt-0.5">
                      {agent.executors?.join(", ")}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Live Event Feed */}
      <Card className="border-border/30">
        <CardHeader className="py-3 px-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-orange-400" />
              <CardTitle className="text-sm">Live C2 Events</CardTitle>
              {c2Events.length > 0 && (
                <Badge variant="outline" className="text-[10px] text-orange-400 border-orange-500/30">
                  {c2Events.length}
                </Badge>
              )}
            </div>
            {pollerData?.pollCount != null && (
              <span className="text-[10px] text-muted-foreground">
                {pollerData.pollCount} polls | {pollerData.consecutiveErrors} errors
              </span>
            )}
          </div>
        </CardHeader>
        <CardContent className="px-4 pb-3 pt-0">
          {/* WebSocket events */}
          {c2Events.length > 0 ? (
            <div className="space-y-1.5 max-h-[400px] overflow-y-auto">
              {[...c2Events].reverse().map((evt, idx) => {
                const style = getEventStyle(evt.type);
                return (
                  <div key={idx} className={`flex items-start gap-2 p-2 rounded-md border ${style.bg}`}>
                    {style.icon}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-semibold ${style.color}`}>
                          {evt.type.replace("c2:", "").replace("operation:", "").replace(/_/g, " ")}
                        </span>
                        <span className="text-[10px] text-muted-foreground">{formatTimestamp(evt.timestamp)}</span>
                      </div>
                      {evt.data?.paw && (
                        <div className="text-[10px] text-muted-foreground font-mono">Agent: {evt.data.paw}</div>
                      )}
                      {evt.data?.abilityName && (
                        <div className="text-[10px] text-muted-foreground">Ability: {evt.data.abilityName}</div>
                      )}
                      {evt.data?.status && (
                        <div className="text-[10px] text-muted-foreground">Status: {evt.data.status}</div>
                      )}
                      {evt.data?.output && (
                        <pre className="text-[10px] text-muted-foreground mt-1 font-mono bg-black/20 p-1 rounded overflow-x-auto max-h-20">
                          {evt.data.output.substring(0, 500)}
                        </pre>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Radio className="h-8 w-8 mx-auto mb-2 opacity-30" />
              <p className="text-xs">No C2 events yet.</p>
              <p className="text-[10px] mt-1">
                {isPolling
                  ? "Poller is active — events will appear when agents check in or abilities execute."
                  : "Start the C2 poller to begin monitoring Caldera operations."}
              </p>
            </div>
          )}

          {/* Poller event log (from server-side) */}
          {Array.isArray(pollerData?.recentEvents) && pollerData.recentEvents.length > 0 && (
            <Collapsible>
              <CollapsibleTrigger className="flex items-center gap-1 text-[10px] text-muted-foreground mt-3 hover:text-foreground cursor-pointer">
                <ChevronRight className="h-3 w-3" />
                Poller Log ({pollerData.recentEvents.length} entries)
              </CollapsibleTrigger>
              <CollapsibleContent>
                <div className="mt-2 space-y-1 max-h-[200px] overflow-y-auto">
                  {[...pollerData.recentEvents].reverse().map((evt: any, idx: number) => (
                    <div key={idx} className="flex items-start gap-2 text-[10px] text-muted-foreground">
                      <span className="font-mono shrink-0">{formatTimestamp(evt.timestamp)}</span>
                      <Badge variant="outline" className="text-[9px] h-4 shrink-0">{evt.type}</Badge>
                      <span className="truncate">{evt.summary}</span>
                    </div>
                  ))}
                </div>
              </CollapsibleContent>
            </Collapsible>
          )}
        </CardContent>
      </Card>

      {/* Active Pollers Summary */}
      {Array.isArray(activePollers.data) && activePollers.data.length > 0 && (
        <Card className="border-border/30">
          <CardHeader className="py-3 px-4">
            <div className="flex items-center gap-2">
              <Gauge className="h-4 w-4 text-blue-400" />
              <CardTitle className="text-sm">All Active Pollers ({activePollers.data.length})</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="px-4 pb-3 pt-0">
            <div className="space-y-1">
              {activePollers.data.map((p: any) => (
                <div key={p.engagementId} className="flex items-center justify-between text-xs p-1.5 rounded bg-card/50">
                  <span className="font-mono">Eng #{p.engagementId}</span>
                  <span className="text-muted-foreground">Op: {p.operationId}</span>
                  <span className="text-muted-foreground">{p.agentCount} agents, {p.linkCount} links</span>
                  <Badge variant="outline" className={`text-[9px] ${p.isPolling ? "text-green-400" : "text-muted-foreground"}`}>
                    {p.isPolling ? "Active" : "Stopped"}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════
// Interrupted Engagement Banner — Auto-Resume notification on server restart
// ═══════════════════════════════════════════════════════════════════════════

function InterruptedEngagementBanner({ engagementId }: { engagementId: number }) {
  const [dismissed, setDismissed] = useState(false);

  const interruptedQ = trpc.liveTrigger.getInterruptedEngagements.useQuery(
    undefined,
    { refetchInterval: 60000 }
  );

  const dismissMut = trpc.liveTrigger.dismissInterruptions.useMutation({
    onSuccess: () => {
      setDismissed(true);
      interruptedQ.refetch();
    },
  });

  const resumeMut = trpc.liveTrigger.autoResumeEngagement.useMutation({
    onSuccess: (result) => {
      if (result.success) {
        toast.success(result.message);
        interruptedQ.refetch();
      } else {
        toast.error(result.message);
      }
    },
    onError: (err) => toast.error(`Resume failed: ${err.message}`),
  });

  const interrupted = interruptedQ.data || [];
  const thisEngagement = interrupted.find(e => e.engagementId === engagementId);
  const otherEngagements = interrupted.filter(e => e.engagementId !== engagementId);

  if (dismissed || interrupted.length === 0) return null;

  const PHASE_LABELS: Record<string, string> = {
    recon: 'Phase 1: Domain Recon',
    passive_discovery: 'Phase 2: Passive Discovery',
    scoping: 'Phase 3: Scoping & RoE',
    test_plan: 'Phase 4: Test Plan',
    test_plan_approval: 'Phase 4b: Plan Approval',
    enumeration: 'Phase 5: Active Discovery',
    vuln_detection: 'Phase 6: Vuln Scan',
    exploitation: 'Phase 7: Exploitation',
    post_exploit: 'Phase 8: Post-Exploit',
  };

  return (
    <div className="flex-none border-b border-amber-500/30">
      <div className="bg-amber-500/10 px-6 py-3">
        {/* This engagement was interrupted */}
        {thisEngagement && (
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-3">
              <div className="p-1.5 rounded-full bg-amber-500/20">
                <AlertTriangle className="h-4 w-4 text-amber-400" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-amber-300">
                  Engagement Interrupted — Server Restarted
                </h3>
                <p className="text-xs text-amber-400/80 mt-0.5">
                  This engagement was in <strong>{PHASE_LABELS[thisEngagement.phase] || thisEngagement.phase}</strong> ({thisEngagement.progress}% complete) 
                  with {thisEngagement.assetsCount} assets and {thisEngagement.vulnsFound} vulnerabilities when the server restarted.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 flex-none ml-4">
              {thisEngagement.canResume && (
                <Button
                  size="sm"
                  onClick={() => resumeMut.mutate({ engagementId: thisEngagement.engagementId })}
                  disabled={resumeMut.isPending}
                  className="bg-gradient-to-r from-emerald-600 to-green-600 hover:from-emerald-500 hover:to-green-500"
                >
                  {resumeMut.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Play className="h-4 w-4 mr-1" />}
                  Resume Engagement
                </Button>
              )}
              <Button
                size="sm"
                variant="outline"
                onClick={() => dismissMut.mutate()}
                className="border-amber-500/30 text-amber-400 hover:bg-amber-500/10"
              >
                <X className="h-4 w-4 mr-1" />
                Dismiss
              </Button>
            </div>
          </div>
        )}

        {/* Other interrupted engagements */}
        {otherEngagements.length > 0 && (
          <div className={thisEngagement ? "pt-2 border-t border-amber-500/20 mt-2" : ""}>
            <div className="flex items-center gap-2 text-xs text-amber-400/80 mb-1.5">
              <AlertTriangle className="h-3 w-3" />
              <span>{otherEngagements.length} other interrupted engagement{otherEngagements.length > 1 ? 's' : ''} detected:</span>
            </div>
            <div className="space-y-1">
              {otherEngagements.map(eng => (
                <div key={eng.engagementId} className="flex items-center justify-between text-xs p-1.5 rounded bg-amber-500/5 border border-amber-500/10">
                  <span className="font-mono text-amber-300">
                    Engagement #{eng.engagementId}
                  </span>
                  <span className="text-amber-400/70">
                    {PHASE_LABELS[eng.phase] || eng.phase} · {eng.progress}% · {eng.assetsCount} assets · {eng.vulnsFound} vulns
                  </span>
                  {eng.canResume && (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => resumeMut.mutate({ engagementId: eng.engagementId })}
                      disabled={resumeMut.isPending}
                      className="h-6 text-[10px] border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10"
                    >
                      <Play className="h-3 w-3 mr-0.5" /> Resume
                    </Button>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}


// ── FP Suppression Panel ────────────────────────────────────────────────────

function FPSuppressionPanel({ engagementId }: { engagementId: number }) {
  const [selectedProfile, setSelectedProfile] = useState("balanced");
  const [showSuppressed, setShowSuppressed] = useState(false);
  const [customRules, setCustomRules] = useState<Record<string, boolean>>({});
  const [isCustom, setIsCustom] = useState(false);

  const profilesQ = trpc.engagementOps.getSuppressionProfiles.useQuery();
  const rulesQ = trpc.engagementOps.getSuppressionRules.useQuery();
  const statsQ = trpc.engagementOps.getSuppressionStats.useQuery({ engagementId });
  const utils = trpc.useUtils();

  const applyMut = trpc.engagementOps.applySuppressionToEngagement.useMutation({
    onSuccess: (stats) => {
      toast.success(`FP Suppression applied: ${stats.suppressed} findings filtered`, {
        description: `Kept: ${stats.kept} | Profile: ${selectedProfile}`,
      });
      utils.engagementOps.getSuppressionStats.invalidate({ engagementId });
      utils.engagementOps.getState.invalidate({ engagementId });
    },
    onError: (e) => toast.error(`Failed to apply suppression: ${e.message}`),
  });

  // Initialize custom rules from the balanced profile
  useEffect(() => {
    if (rulesQ.data && Object.keys(customRules).length === 0) {
      const defaults: Record<string, boolean> = {};
      rulesQ.data.forEach(r => { defaults[r.id] = r.enabledByDefault; });
      setCustomRules(defaults);
    }
  }, [rulesQ.data]);

  const handleApply = () => {
    applyMut.mutate({
      engagementId,
      profileName: isCustom ? "balanced" : selectedProfile,
      customRules: isCustom ? customRules : undefined,
    });
  };

  const CATEGORY_LABELS: Record<string, string> = {
    informational_noise: "Informational Noise",
    tool_artifact: "Tool Artifacts",
    config_observation: "Config Observations",
    duplicate_finding: "Duplicate Findings",
  };

  const TP_RISK_COLORS: Record<string, string> = {
    low: "text-green-400 bg-green-500/10 border-green-500/20",
    medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
    high: "text-red-400 bg-red-500/10 border-red-500/20",
  };

  return (
    <ScrollArea className="h-[calc(100vh-280px)]">
      <div className="space-y-4 py-3">
        <p className="text-xs text-muted-foreground">
          Configure false positive suppression to reduce noise in vulnerability findings. Rules are based on analysis of previous engagement results and known tool artifacts.
        </p>

        {/* Current Stats */}
        {statsQ.data?.stats && (
          <Card className="bg-card/50 border-cyan-500/20">
            <CardContent className="p-4">
              <div className="grid grid-cols-4 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-foreground">{statsQ.data.stats.total}</div>
                  <div className="text-[10px] text-muted-foreground">Total Findings</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-emerald-400">{statsQ.data.stats.kept}</div>
                  <div className="text-[10px] text-muted-foreground">Kept</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-orange-400">{statsQ.data.stats.suppressed}</div>
                  <div className="text-[10px] text-muted-foreground">Suppressed</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-cyan-400">
                    {statsQ.data.stats.total > 0
                      ? Math.round((statsQ.data.stats.suppressed / statsQ.data.stats.total) * 100)
                      : 0}%
                  </div>
                  <div className="text-[10px] text-muted-foreground">Reduction</div>
                </div>
              </div>

              {/* Per-rule breakdown */}
              {Object.keys(statsQ.data.stats.byRule || {}).length > 0 && (
                <div className="mt-3 pt-3 border-t border-border/30">
                  <div className="text-[10px] text-muted-foreground mb-1.5 uppercase tracking-wider">Suppression by Rule</div>
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(statsQ.data.stats.byRule).sort((a, b) => b[1] - a[1]).map(([rule, count]) => (
                      <Badge key={rule} variant="outline" className="text-[10px] bg-orange-500/5 border-orange-500/20 text-orange-300">
                        {rule}: {count}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Per-category breakdown */}
              {Object.keys(statsQ.data.stats.byCategory || {}).length > 0 && (
                <div className="mt-2">
                  <div className="text-[10px] text-muted-foreground mb-1.5 uppercase tracking-wider">By Category</div>
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(statsQ.data.stats.byCategory).map(([cat, count]) => (
                      <Badge key={cat} variant="outline" className="text-[10px] bg-purple-500/5 border-purple-500/20 text-purple-300">
                        {CATEGORY_LABELS[cat] || cat}: {count}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Profile Selector */}
        <Card className="bg-card/50 border-border/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Filter className="h-4 w-4 text-cyan-400" /> Suppression Profile
            </CardTitle>
            <CardDescription className="text-xs">
              Choose a preset profile or customize individual rules.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-2">
              {(profilesQ.data || []).map(profile => (
                <button
                  key={profile.id}
                  onClick={() => { setSelectedProfile(profile.id); setIsCustom(false); }}
                  className={`text-left p-3 rounded-lg border transition-all ${
                    !isCustom && selectedProfile === profile.id
                      ? "border-cyan-500/50 bg-cyan-500/10 ring-1 ring-cyan-500/30"
                      : "border-border/30 bg-card/30 hover:bg-card/50"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium">{profile.name}</span>
                    <Badge variant="outline" className="text-[10px]">
                      {profile.enabledCount}/{profile.totalRules}
                    </Badge>
                  </div>
                  <p className="text-[10px] text-muted-foreground mt-1">{profile.description}</p>
                </button>
              ))}
            </div>

            {/* Custom toggle */}
            <button
              onClick={() => setIsCustom(!isCustom)}
              className={`w-full text-left p-3 rounded-lg border transition-all ${
                isCustom
                  ? "border-purple-500/50 bg-purple-500/10 ring-1 ring-purple-500/30"
                  : "border-border/30 bg-card/30 hover:bg-card/50"
              }`}
            >
              <div className="flex items-center gap-2">
                <Wrench className="h-3.5 w-3.5 text-purple-400" />
                <span className="text-xs font-medium">Custom Rules</span>
                <Badge variant="outline" className="text-[10px] ml-auto">
                  {Object.values(customRules).filter(Boolean).length}/{Object.keys(customRules).length}
                </Badge>
              </div>
              <p className="text-[10px] text-muted-foreground mt-1">Toggle individual suppression rules.</p>
            </button>

            {/* Custom Rules List */}
            {isCustom && rulesQ.data && (
              <div className="space-y-1.5 max-h-[300px] overflow-y-auto pr-1">
                {rulesQ.data.map(rule => (
                  <div
                    key={rule.id}
                    className={`flex items-start gap-2 p-2 rounded-md border transition-all ${
                      customRules[rule.id]
                        ? "border-cyan-500/20 bg-cyan-500/5"
                        : "border-border/20 bg-card/20 opacity-60"
                    }`}
                  >
                    <button
                      onClick={() => setCustomRules(prev => ({ ...prev, [rule.id]: !prev[rule.id] }))}
                      className="mt-0.5 flex-none"
                    >
                      {customRules[rule.id]
                        ? <ToggleRight className="h-4 w-4 text-cyan-400" />
                        : <ToggleLeft className="h-4 w-4 text-muted-foreground" />
                      }
                    </button>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="text-xs font-medium truncate">{rule.name}</span>
                        <Badge variant="outline" className={`text-[9px] ${TP_RISK_COLORS[rule.tpRisk] || ""}`}>
                          TP Risk: {rule.tpRisk}
                        </Badge>
                        <Badge variant="outline" className="text-[9px]">
                          ~{rule.estimatedSuppression} FPs
                        </Badge>
                      </div>
                      <p className="text-[10px] text-muted-foreground mt-0.5">{rule.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Apply Button */}
            <Button
              onClick={handleApply}
              disabled={applyMut.isPending}
              className="w-full"
              size="sm"
            >
              {applyMut.isPending ? (
                <><Loader2 className="h-3 w-3 mr-1.5 animate-spin" /> Applying...</>
              ) : (
                <><FilterX className="h-3 w-3 mr-1.5" /> Apply Suppression</>
              )}
            </Button>
          </CardContent>
        </Card>

        {/* Suppressed Findings Preview */}
        {statsQ.data && statsQ.data.suppressedCount > 0 && (
          <Card className="bg-card/50 border-border/30">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Eye className="h-4 w-4 text-orange-400" /> Suppressed Findings ({statsQ.data.suppressedCount})
                </CardTitle>
                <Button
                  variant="outline"
                  size="sm"
                  className="text-[10px] h-6"
                  onClick={() => setShowSuppressed(!showSuppressed)}
                >
                  {showSuppressed ? "Hide" : "Show"} Details
                </Button>
              </div>
              <CardDescription className="text-xs">
                These findings were filtered by the active suppression profile. Review to ensure no true positives were removed.
              </CardDescription>
            </CardHeader>
            {showSuppressed && (
              <CardContent className="space-y-1 max-h-[300px] overflow-y-auto">
                <p className="text-[10px] text-muted-foreground italic">
                  Suppressed findings are still stored and can be restored by switching to the "None" profile.
                </p>
              </CardContent>
            )}
          </Card>
        )}
      </div>
    </ScrollArea>
  );
}

/** Auto-Resume Toggle — allows operator to enable/disable auto-resume on server restart */
function AutoResumeToggle({ engagementId }: { engagementId: number | null }) {
  const statusQ = trpc.engagementOps.getAutoResumeStatus.useQuery(
    { engagementId: engagementId! },
    { enabled: !!engagementId, refetchInterval: 30000 }
  );
  const setAutoResumeMut = trpc.engagementOps.setAutoResume.useMutation({
    onSuccess: (data) => {
      toast.success(`Auto-resume ${data.enabled ? 'enabled' : 'disabled'}`);
      statusQ.refetch();
    },
    onError: (err) => toast.error(`Failed: ${err.message}`),
  });

  if (!engagementId) return null;

  const status = statusQ.data;
  const isEnabled = status?.enabled ?? false;
  const isCrashLoopBlocked = status?.crashLoopBlocked ?? false;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Switch
            checked={isEnabled}
            onCheckedChange={(checked) => {
              setAutoResumeMut.mutate({ engagementId, enabled: checked });
            }}
            disabled={setAutoResumeMut.isPending || isCrashLoopBlocked}
            className={isEnabled ? "data-[state=checked]:bg-emerald-500" : ""}
          />
          <span className="text-xs font-medium">
            {isEnabled ? "Enabled" : "Disabled"}
          </span>
        </div>
        {setAutoResumeMut.isPending && <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />}
      </div>
      {isCrashLoopBlocked && (
        <div className="flex items-start gap-1.5 text-[10px] text-amber-400 bg-amber-500/10 rounded px-2 py-1.5">
          <AlertTriangle className="h-3 w-3 mt-0.5 shrink-0" />
          <span>
            Crash loop detected ({status?.interruptCount} interrupts in 24h). Auto-resume is blocked until the engagement stabilizes.
          </span>
        </div>
      )}
      {!isCrashLoopBlocked && (
        <p className="text-[10px] text-muted-foreground leading-relaxed">
          {isEnabled
            ? "This engagement will automatically resume from its last phase if the server restarts."
            : "Enable to automatically resume scanning after a server restart instead of requiring manual re-start."}
        </p>
      )}
      {status?.interruptCount != null && status.interruptCount > 0 && !isCrashLoopBlocked && (
        <p className="text-[10px] text-muted-foreground">
          Interrupt history: {status.interruptCount} restart{status.interruptCount !== 1 ? 's' : ''} detected
        </p>
      )}
    </div>
  );
}
