// @ts-nocheck
import AppShell from "@/components/AppShell";
import { useState, useEffect, useMemo, lazy, Suspense } from "react";
import { trpc } from "@/lib/trpc";
import { safeJsonParse } from "@/lib/utils";
import { useParams, useLocation, Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Streamdown } from "streamdown";
import {
  ArrowLeft, Shield, Target, AlertTriangle, Brain, Globe, Server,
  ChevronDown, ChevronUp, Crosshair, Zap, FileText, ExternalLink,
  Activity, Lock, Eye, Network, Loader2, BarChart3, Bug, Skull, Database, Cpu,
  TrendingUp, Fingerprint, Radar, Info, Search, Radio, Scan, Flag, Undo2, MessageSquare,
  Download, FlaskConical, Mail, ShieldAlert, ShieldCheck, ShieldX, CheckCircle2, XCircle, RefreshCw,
  Layers, Play, Pause, Settings2, GitBranch, Link2, Users, Hash, Clock, Unplug, Wifi,
  Workflow, Lightbulb, Route, Telescope, ShieldQuestion, ArrowRightLeft, KeyRound,
  Box, ClipboardCheck, PackageSearch, GitCompareArrows, HeartPulse, Stethoscope, MailCheck, ListChecks, Trash2,
  SendHorizontal, Calendar, BookOpen, Microscope
} from "lucide-react";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Slider } from "@/components/ui/slider";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger, DropdownMenuLabel } from "@/components/ui/dropdown-menu";
import CorroborationPanel from "@/components/CorroborationPanel";

import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import { exportScanAssets, exportFindings, exportThreatActors, exportExecutiveSummary, exportExecutiveSummaryWithValidation, exportValidationReportPdf, exportValidationResultsCsv } from "@/lib/export-utils";
import { exportDiReport } from "@/lib/export-di-report";
import { KpiStrip } from "@/components/KpiStrip";
import type { KpiItem } from "@/components/KpiStrip";
import { TabGroupNav } from "@/components/TabGroupNav";
import type { TabGroup } from "@/components/TabGroupNav";
import { FindingStateBadge } from "@/components/FindingStateBadge";
import { CorroborationTierBadge } from "@/components/CorroborationTierBadge";
import { ConfidenceBadge } from "@/components/ConfidenceBadge";
import type { ValidationResultExport, ValidationRunExport } from "@/lib/export-utils";

// Lazy-loaded sub-tabs (split from monolithic file for bundle optimization)
const ScanMethodsTab = lazy(() => import("./domain-intel-tabs/ScanMethodsTab"));
const IncidentSearchTab = lazy(() => import("./domain-intel-tabs/IncidentSearchTab"));
const AffiliatedDomainsTab = lazy(() => import("./domain-intel-tabs/AffiliatedDomainsTab"));
const VulnIntelSection = lazy(() => import("./domain-intel-tabs/VulnIntelSection"));
const ValidateTop10Banner = lazy(() => import("./domain-intel-tabs/ValidateTop10Banner"));
const AccuracyInsightsTab = lazy(() => import("./domain-intel-tabs/AccuracyInsightsTab"));
const DiscoveryCoverageTab = lazy(() => import("./domain-intel-tabs/DiscoveryCoverageTab"));
const EmailSecurityTab = lazy(() => import("./domain-intel-tabs/EmailSecurityTab"));
const OsintSourcesTab = lazy(() => import("./domain-intel-tabs/OsintSourcesTab"));
const RecursiveDiscoveryTab = lazy(() => import("./domain-intel-tabs/RecursiveDiscoveryTab"));
const ChangeDetectionTab = lazy(() => import("./domain-intel-tabs/ChangeDetectionTab"));
const TechVulnsTab = lazy(() => import("./domain-intel-tabs/TechVulnsTab"));
const TakeoverTab = lazy(() => import("./domain-intel-tabs/TakeoverTab"));
const CveActorEnrichmentTab = lazy(() => import("./domain-intel-tabs/CveActorEnrichmentTab"));
const TakeoverPocTab = lazy(() => import("./domain-intel-tabs/TakeoverPocTab"));
const WebCrawlResultsTab = lazy(() => import("./domain-intel-tabs/WebCrawlResultsTab"));
const EntityProfileTab = lazy(() => import("./domain-intel-tabs/EntityProfileTab"));
const VendorAlertCorrelationTab = lazy(() => import("./domain-intel-tabs/VendorAlertCorrelationTab"));
const DomainHealthTab = lazy(() => import("./domain-intel-tabs/DomainHealthTab"));
const DnsSecurityTab = lazy(() => import("./domain-intel-tabs/DnsSecurityTab"));
const InfrastructureMapTab = lazy(() => import("./domain-intel-tabs/InfrastructureMapTab"));
const DiscoveryContextTab = lazy(() => import("./domain-intel-tabs/DiscoveryContextTab"));
const VendorRiskTab = lazy(() => import("./domain-intel-tabs/VendorRiskTab"));
import ComplianceFrameworkSelector from "@/components/ComplianceFrameworkSelector";

const RISK_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/20 border-red-500/40",
  high: "text-orange-400 bg-orange-500/20 border-orange-500/40",
  medium: "text-yellow-400 bg-yellow-500/20 border-yellow-500/40",
  low: "text-emerald-400 bg-emerald-500/20 border-emerald-500/40",
};

const RISK_BAR_COLORS: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-emerald-500",
};

function RiskGauge({ score, band, size = "lg" }: { score: number; band: string; size?: "sm" | "lg" }) {
  const radius = size === "lg" ? 60 : 35;
  const stroke = size === "lg" ? 8 : 5;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const color = band === "critical" ? "#ef4444" : band === "high" ? "#f97316" : band === "medium" ? "#eab308" : "#22c55e";

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={(radius + stroke) * 2} height={(radius + stroke) * 2} className="-rotate-90">
        <circle cx={radius + stroke} cy={radius + stroke} r={radius} fill="none" stroke="currentColor" strokeWidth={stroke} className="text-muted/30" />
        <circle cx={radius + stroke} cy={radius + stroke} r={radius} fill="none" stroke={color} strokeWidth={stroke}
          strokeDasharray={circumference} strokeDashoffset={circumference - progress} strokeLinecap="round" className="transition-all duration-1000" />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={`font-bold ${size === "lg" ? "text-3xl" : "text-lg"}`} style={{ color }}>{score}</span>
        {size === "lg" && <span className="text-xs text-muted-foreground uppercase">{band}</span>}
      </div>
    </div>
  );
}

function CarverRadar({ scores }: { scores: Record<string, number> }) {
  const labels = ["Criticality", "Accessibility", "Recuperability", "Vulnerability", "Effect", "Recognizability"];
  const keys = ["criticality", "accessibility", "recuperability", "vulnerability", "effect", "recognizability"];
  const cx = 100, cy = 100, r = 70;

  const points = keys.map((k, i) => {
    const angle = (Math.PI * 2 * i) / keys.length - Math.PI / 2;
    const val = (scores[k] || 0) / 10;
    return {
      x: cx + r * val * Math.cos(angle),
      y: cy + r * val * Math.sin(angle),
      lx: cx + (r + 18) * Math.cos(angle),
      ly: cy + (r + 18) * Math.sin(angle),
      label: labels[i],
      value: scores[k] || 0,
    };
  });

  const polygon = points.map(p => `${p.x},${p.y}`).join(" ");

  return (
    <svg viewBox="0 0 200 200" className="w-full max-w-[220px]">
      {[0.25, 0.5, 0.75, 1].map(scale => (
        <polygon key={scale} points={keys.map((_, i) => {
          const angle = (Math.PI * 2 * i) / keys.length - Math.PI / 2;
          return `${cx + r * scale * Math.cos(angle)},${cy + r * scale * Math.sin(angle)}`;
        }).join(" ")} fill="none" stroke="currentColor" strokeWidth="0.5" className="text-muted/30" />
      ))}
      {keys.map((_, i) => {
        const angle = (Math.PI * 2 * i) / keys.length - Math.PI / 2;
        return <line key={i} x1={cx} y1={cy} x2={cx + r * Math.cos(angle)} y2={cy + r * Math.sin(angle)} stroke="currentColor" strokeWidth="0.5" className="text-muted/30" />;
      })}
      <polygon points={polygon} fill="rgba(168,85,247,0.2)" stroke="rgb(168,85,247)" strokeWidth="1.5" />
      {points.map((p, i) => (
        <g key={i}>
          <circle cx={p.x} cy={p.y} r="3" fill="rgb(168,85,247)" />
          <text x={p.lx} y={p.ly} textAnchor="middle" dominantBaseline="middle" className="fill-muted-foreground text-[6px]">{p.label.slice(0, 4)}</text>
        </g>
      ))}
    </svg>
  );
}

export default function DomainIntelResults() {
  const params = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const scanId = Number(params.id);
  const utils = trpc.useUtils();

  // Delete scan mutation
  const deleteScanMut = trpc.domainIntel.deleteScan.useMutation({
    onSuccess: () => { toast.success('Scan deleted'); navigate('/domain-intel'); },
    onError: (err: any) => { toast.error(`Delete failed: ${sanitizeErrorForToast(err)}`); },
  });
  const [expandedAsset, setExpandedAsset] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [expandedCampaign, setExpandedCampaign] = useState<string | null>(null);
  const [heatmapExpandedAsset, setHeatmapExpandedAsset] = useState<number | null>(null);
  const [fpDialogOpen, setFpDialogOpen] = useState(false);
  const [fpTarget, setFpTarget] = useState<{ finding: any; assetId: number; findingIndex: number } | null>(null);
  const [fpReasonTemplate, setFpReasonTemplate] = useState<string>("");
  const [fpReasonCustom, setFpReasonCustom] = useState<string>("");
  // Fetch existing FPs for this scan
  const fpQuery = trpc.domainIntel.listFalsePositives.useQuery({ scanId }, { enabled: !!scanId });
  const fpHashes = new Set((fpQuery.data || []).filter((fp: any) => fp.status === 'false_positive').map((fp: any) => fp.findingHash));

  const markFPMutation = trpc.domainIntel.markFalsePositive.useMutation({
    onSuccess: () => {
      toast.success("Marked as False Positive — the LLM will learn from your feedback on future scans.");
      fpQuery.refetch();
      setFpDialogOpen(false);
      setFpTarget(null);
      setFpReasonTemplate("");
      setFpReasonCustom("");
    },
    onError: (err) => {
      toast.error(`Error: ${sanitizeErrorForToast(err)}`);
    },
  });

  const reinstateMutation = trpc.domainIntel.reinstateFinding.useMutation({
    onSuccess: () => {
      toast.success("Finding reinstated — removed from false positive list.");
      fpQuery.refetch();
    },
  });

  // State declarations that must come before queries that reference them
  const [refreshing, setRefreshing] = useState(false);
  const [engagementRunning, setEngagementRunning] = useState(false);
  const [exploitDeploying, setExploitDeploying] = useState(false);
  const [matchingRunning, setMatchingRunning] = useState(false);
  const [testPlanGenerating, setTestPlanGenerating] = useState(false);
  const [testPlanDialogOpen, setTestPlanDialogOpen] = useState(false);
  const [testPlanResult, setTestPlanResult] = useState<any>(null);
  const [showCreateStackProfile, setShowCreateStackProfile] = useState(false);
  const [stackProfileName, setStackProfileName] = useState('');

  const FP_REASON_TEMPLATES = [
    { value: "patched", label: "Already patched / remediated" },
    { value: "internal", label: "Internal-only service, not exposed" },
    { value: "compensating", label: "Compensating controls in place" },
    { value: "scanner_error", label: "Scanner/detection error (wrong product)" },
    { value: "version_mismatch", label: "Version mismatch (detected version is wrong)" },
    { value: "accepted_risk", label: "Accepted risk (documented exception)" },
    { value: "duplicate", label: "Duplicate of another finding" },
    { value: "not_applicable", label: "Not applicable to our environment" },
    { value: "custom", label: "Custom reason (type below)" },
  ];

  const { data, isLoading, error, refetch } = trpc.domainIntel.getScan.useQuery({ id: scanId }, {
    enabled: !!scanId,
    // Auto-refetch during refresh so the page picks up new results when pipeline completes
    refetchInterval: refreshing ? 5000 : false,
  });

  // Fetch validation data for this scan
  const validationSummary = trpc.validation.getScanValidationSummary.useQuery({ scanId }, { enabled: !!scanId });
  const validationRun: ValidationRunExport | null = validationSummary.data?.run ? {
    id: validationSummary.data.run.id,
    scanId: validationSummary.data.run.scanId,
    mode: validationSummary.data.run.mode,
    status: validationSummary.data.run.status,
    totalCandidates: validationSummary.data.run.totalCandidates,
    validated: validationSummary.data.totalValidated ?? 0,
    exploitable: validationSummary.data.exploitableCount ?? 0,
    notVulnerable: (validationSummary.data.results || []).filter((r: any) => r.status === 'not_vulnerable').length,
    errors: (validationSummary.data.results || []).filter((r: any) => r.status === 'error').length,
    startedAt: validationSummary.data.run.startedAt instanceof Date ? validationSummary.data.run.startedAt.toISOString() : String(validationSummary.data.run.startedAt),
    completedAt: validationSummary.data.run.completedAt instanceof Date ? validationSummary.data.run.completedAt.toISOString() : validationSummary.data.run.completedAt ? String(validationSummary.data.run.completedAt) : null,
  } : null;
  const validationResults: ValidationResultExport[] = (validationSummary.data?.results || []).map((r: any) => ({
    assetHostname: r.assetHostname || r.hostname || 'unknown',
    cveId: r.cveId || '',
    msfModule: r.msfModule,
    status: r.status,
    exploitable: r.exploitable ?? false,
    scoreAdjustment: r.scoreAdjustment ?? 0,
    durationMs: r.durationMs ?? 0,
    evidence: r.evidence ? (typeof r.evidence === 'string' ? safeJsonParse(r.evidence, null) : r.evidence) : null,
    errorMessage: r.errorMessage,
    timestamp: r.completedAt ? String(r.completedAt) : r.startedAt ? String(r.startedAt) : '',
    evidenceUrl: r.evidenceUrl ?? null,
    evidenceArtifacts: r.evidenceArtifacts ?? null,
  }));

  // Engagement mutation for scan_complete scans
  const startEngagement = trpc.domainIntel.startEngagement.useMutation({
    onSuccess: () => {
      toast.success('Engagement started — threat actor profiling and campaign design in progress...');
      setEngagementRunning(true);
    },
    onError: (err: any) => {
      toast.error(`Failed to start engagement: ${sanitizeErrorForToast(err)}`);
    },
  });
  const createStackProfileMut = trpc.stackProfile.createFromScan.useMutation({
    onSuccess: (result) => {
      setShowCreateStackProfile(false);
      setStackProfileName('');
      toast.success(`Stack profile created with ${result.technologiesDetected} technologies detected, ${result.matchedScanners?.length || 0} scanners matched (${result.coveragePercent}% coverage)`);
    },
    onError: (err: any) => {
      toast.error(`Failed to create stack profile: ${sanitizeErrorForToast(err)}`);
    },
  });
  const deployExploitsMutation = trpc.domainIntel.deployExploits.useMutation({
    onSuccess: (result) => {
      setExploitDeploying(false);
      if (result.success) {
        toast.success(`Deployed ${result.deployed?.length || 0} exploit abilities to the emulation framework`);
      } else {
        toast.error(result.error || 'Failed to deploy exploits');
      }
    },
    onError: (err) => {
      setExploitDeploying(false);
      toast.error(`Deploy failed: ${sanitizeErrorForToast(err)}`);
    },
  });

  const [subSearch, setSubSearch] = useState('');
  const [subSourceFilter, setSubSourceFilter] = useState('all');
  const [portSearch, setPortSearch] = useState('');
  const [portProtocolFilter, setPortProtocolFilter] = useState('all');
  const [portSortBy, setPortSortBy] = useState<'port' | 'ip' | 'product'>('port');
  const [inventorySearch, setInventorySearch] = useState('');
  const [inventoryTypeFilter, setInventoryTypeFilter] = useState('all');
  const [inventorySortBy, setInventorySortBy] = useState<'risk' | 'hostname' | 'ports' | 'tech'>('risk');
  const matchThreatActorsMutation = trpc.domainIntel.matchThreatActors.useMutation({
    onSuccess: () => {
      toast.success('Threat actor matching complete — refreshing results...');
      setMatchingRunning(false);
      refetch();
    },
    onError: (err) => {
      toast.error(`Matching failed: ${sanitizeErrorForToast(err)}`);
      setMatchingRunning(false);
    },
  });

  // Refresh scan mutation
  const refreshScanMutation = trpc.domainIntel.refreshScan.useMutation({
    onSuccess: () => {
      toast.success('Scan refresh started — re-running full pipeline with latest features...');
      setRefreshing(true);
    },
    onError: (err: any) => {
      toast.error(`Failed to start refresh: ${sanitizeErrorForToast(err)}`);
    },
  });

  // Poll for refresh completion
  const refreshPoll = trpc.domainIntel.getScanStatus.useQuery(
    { scanId },
    {
      enabled: refreshing,
      refetchInterval: 3000,
    }
  );

  useEffect(() => {
    if (!refreshPoll.data || !refreshing) return;
    if (refreshPoll.data.status === 'completed' || refreshPoll.data.status === 'scan_complete') {
      setRefreshing(false);
      toast.success('Scan refresh complete — results updated with latest features.');
      refetch();
    } else if (refreshPoll.data.status === 'failed') {
      setRefreshing(false);
      toast.error('Scan refresh failed. Original results have been preserved.');
      refetch();
    }
  }, [refreshPoll.data, refreshing]);

  // Harvest credentials from breach data into engagement credential list
  const harvestCredentialsMut = trpc.engagementOps.harvestCredentials.useMutation({
    onSuccess: (result) => {
      const total = (result.inserted || 0) + (result.duplicates || 0);
      if (result.inserted > 0) {
        toast.success(`Sent ${result.inserted} credential${result.inserted !== 1 ? 's' : ''} to credential testing${result.duplicates > 0 ? ` (${result.duplicates} already existed)` : ''}`);
      } else if (result.duplicates > 0) {
        toast.info(`All ${result.duplicates} credential${result.duplicates !== 1 ? 's' : ''} already in the testing queue`);
      } else {
        toast.info('No credentials found to harvest — breach data may not contain extractable credentials');
      }
    },
    onError: (err: any) => {
      toast.error(`Credential harvest failed: ${sanitizeErrorForToast(err)}`);
    },
  });

  const createAdversaryMutation = trpc.domainIntel.createExploitAdversary.useMutation({
    onSuccess: (result: any) => {
      if (result.success) {
        toast.success(`Created adversary profile "${result.adversary?.name || 'exploit-adversary'}" in the emulation framework`);
      } else {
        toast.error(result.error || 'Failed to create adversary');
      }
    },
    onError: (err) => {
      toast.error(`Failed: ${sanitizeErrorForToast(err)}`);
    },
  });

  // Poll for engagement completion
  const engagementPoll = trpc.domainIntel.getScanStatus.useQuery(
    { scanId },
    {
      enabled: engagementRunning,
      refetchInterval: 3000,
    }
  );

  useEffect(() => {
    if (!engagementPoll.data || !engagementRunning) return;
    if (engagementPoll.data.status === 'completed') {
      setEngagementRunning(false);
      toast.success('Engagement complete — campaigns and threat actors are now available.');
      refetch();
    } else if (engagementPoll.data.status === 'failed') {
      setEngagementRunning(false);
      toast.error('Engagement failed. You can retry from the results page.');
      refetch();
    }
  }, [engagementPoll.data, engagementRunning]);

  // Detect refresh-in-progress from scan status (handles race condition where
  // getScan refetches before the mutation onSuccess sets refreshing=true)
  // NOTE: These computations must be above the early returns so the useEffect below
  // always runs on every render (React hooks rule: same number of hooks every render)
  const _pipeline = data?.scan?.pipelineOutput as any;
  const serverRefreshing = !!(_pipeline?.refreshing === true && (
    data?.scan?.status === 'discovering' || data?.scan?.status === 'passive_recon' ||
    data?.scan?.status === 'analyzing' || data?.scan?.status === 'scoring' || data?.scan?.status === 'recommending'
  ));
  const isRefreshInProgress = refreshing || serverRefreshing;

  // Sync local refreshing state with server state
  useEffect(() => {
    if (serverRefreshing && !refreshing) {
      setRefreshing(true);
    }
  }, [serverRefreshing]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-purple-400" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="h-12 w-12 text-destructive mx-auto mb-4" />
        <p className="text-lg font-semibold">Scan not found</p>
        <Button variant="outline" className="mt-4" onClick={() => navigate("/domain-intel")}>
          <ArrowLeft className="h-4 w-4 mr-2" /> Back to Domain Intel
        </Button>
      </div>
    );
  }

  const { scan, assets } = data;
  const pipeline = scan.pipelineOutput as any;
  const campaigns = (scan.campaignRecommendations || []) as any[];
  const threatActorMatches = pipeline?.threatActorMatches as any;
  const llmThreatAnalysis = pipeline?.llmThreatActorAnalysis as any;
  const breachData = pipeline?.breachData as any;
  const dehashedResult = pipeline?.passiveRecon?.connectorResults?.find((r: any) => r.connector === 'dehashed') as any;
  const exploitMatches = pipeline?.exploitMatches as any;
  const crossModuleEnrichment = pipeline?.crossModuleEnrichment as any;
  const postEnrichmentAnalysis = pipeline?.postEnrichmentAnalysis as any;
  const credentialTestSummary = pipeline?.credentialTestSummary as any;
  const oemCredentials = pipeline?.oemCredentials as any;
  const domainHealth = pipeline?.domainHealth as any;
  const incidentSearch = pipeline?.incidentSearch as any;
  const affiliatedDomains = pipeline?.affiliatedDomains as any;
  const scanDelta = pipeline?.scanDelta as { previousScanId: number; previousScanDate: string; scanNumber: number; riskDelta: number | null; previousRiskScore: number | null; assetDelta: number | null; previousTotalAssets: number | null; findingsDelta: number | null; previousTotalFindings: number | null; newAssets: string[]; removedAssets: string[]; persistentAssets: string[] } | undefined;

  // Build unified asset list: DB assets + pipeline subdomains not already in DB assets
  const dbAssetHostnames = new Set((assets as any[]).map((a: any) => (a.hostname || '').toLowerCase()));
  const pipelineSubdomains = ((pipeline?.discoveredSubdomains || []) as any[]).filter(
    (s: any) => s.name && !dbAssetHostnames.has((s.name || '').toLowerCase())
  );
  const pipelinePorts = (pipeline?.discoveredPorts || []) as any[];

  // Convert pipeline subdomains to asset-like objects with REAL risk scoring and weakness analysis
  const HIGH_RISK_PORTS: Record<number, { name: string; risk: string; severity: 'critical' | 'high' | 'medium' }> = {
    21: { name: 'FTP', risk: 'Cleartext file transfer — credentials and data exposed in transit', severity: 'high' },
    23: { name: 'Telnet', risk: 'Cleartext remote access — full credential interception possible', severity: 'critical' },
    25: { name: 'SMTP', risk: 'Open mail relay — potential for spam/phishing abuse', severity: 'medium' },
    110: { name: 'POP3', risk: 'Cleartext email retrieval — credentials exposed', severity: 'high' },
    135: { name: 'MSRPC', risk: 'Windows RPC — lateral movement and remote code execution vector', severity: 'high' },
    139: { name: 'NetBIOS', risk: 'SMB/NetBIOS — information disclosure and lateral movement', severity: 'high' },
    143: { name: 'IMAP', risk: 'Cleartext email access — credentials exposed', severity: 'medium' },
    445: { name: 'SMB', risk: 'SMB file sharing — EternalBlue, ransomware propagation vector', severity: 'critical' },
    1433: { name: 'MSSQL', risk: 'Database exposed to internet — SQL injection and credential brute force', severity: 'critical' },
    1521: { name: 'Oracle DB', risk: 'Database exposed to internet — credential brute force and TNS poisoning', severity: 'critical' },
    3306: { name: 'MySQL', risk: 'Database exposed to internet — credential brute force and data exfiltration', severity: 'critical' },
    3389: { name: 'RDP', risk: 'Remote Desktop exposed — BlueKeep, credential stuffing, ransomware entry', severity: 'critical' },
    5432: { name: 'PostgreSQL', risk: 'Database exposed to internet — credential brute force', severity: 'critical' },
    5900: { name: 'VNC', risk: 'Remote desktop without encryption — screen capture and control', severity: 'critical' },
    6379: { name: 'Redis', risk: 'In-memory store often unauthenticated — data theft and RCE', severity: 'critical' },
    8080: { name: 'HTTP-Alt', risk: 'Alternative HTTP — may expose admin panels or dev servers', severity: 'medium' },
    9200: { name: 'Elasticsearch', risk: 'Search engine often unauthenticated — bulk data exposure', severity: 'high' },
    11211: { name: 'Memcached', risk: 'Cache service — DDoS amplification and data leakage', severity: 'high' },
    27017: { name: 'MongoDB', risk: 'NoSQL database often unauthenticated — full data exposure', severity: 'critical' },
  };

  const subdomainAssets = pipelineSubdomains.map((s: any) => {
    const subPorts = pipelinePorts.filter((p: any) =>
      p.hostname?.toLowerCase() === s.name.toLowerCase() || (s.ip && p.ip === s.ip)
    );
    const techFromTags = (s.tags || []).filter((t: string) => t.startsWith('product:')).map((t: string) => t.replace('product:', ''));
    const versionFromTags = (s.tags || []).filter((t: string) => t.startsWith('version:')).map((t: string) => t.replace('version:', ''));

    // === RISK SCORING ENGINE FOR SUBDOMAINS ===
    let riskScore = 0;
    const findings: Array<{ finding: string; severity: string; category?: string; remediation?: string }> = [];
    const testVectors: Array<{ vector: string; technique: string; priority: string }> = [];
    const contextIndicators: string[] = [];

    // 1. Port-based risk assessment
    for (const p of subPorts) {
      const portNum = Number(p.port);
      const highRisk = HIGH_RISK_PORTS[portNum];
      if (highRisk) {
        riskScore += highRisk.severity === 'critical' ? 25 : highRisk.severity === 'high' ? 15 : 8;
        findings.push({
          finding: `High-risk port ${portNum} (${highRisk.name}) exposed: ${highRisk.risk}`,
          severity: highRisk.severity,
          category: 'network_exposure',
          remediation: `Close port ${portNum} or restrict access via firewall rules. If required, enforce encryption (TLS/SSH tunnel).`,
        });
        testVectors.push({
          vector: `Port ${portNum} ${highRisk.name} exploitation`,
          technique: portNum === 3389 ? 'T1021.001' : portNum === 445 ? 'T1021.002' : portNum === 22 ? 'T1021.004' : 'T1046',
          priority: highRisk.severity,
        });
      }

      // CVE-based findings from port scan
      if (p.vulns && Array.isArray(p.vulns)) {
        for (const cve of p.vulns) {
          riskScore += 20;
          findings.push({
            finding: `Known vulnerability ${cve} on port ${portNum} (${p.product || 'unknown service'} ${p.version || ''})`,
            severity: 'critical',
            category: 'vulnerability',
            remediation: `Patch ${p.product || 'service'} to latest version. Apply vendor security advisory for ${cve}.`,
          });
          testVectors.push({
            vector: `Exploit ${cve} on ${p.product || 'service'}:${portNum}`,
            technique: 'T1190',
            priority: 'critical',
          });
        }
      }

      // Service version analysis
      if (p.product && p.version) {
        contextIndicators.push(`${p.product} ${p.version} on port ${portNum}`);
      }
    }

    // 2. HTTPS/TLS assessment
    const hasPort443 = subPorts.some((p: any) => Number(p.port) === 443);
    const hasPort80 = subPorts.some((p: any) => Number(p.port) === 80);
    if (hasPort80 && !hasPort443) {
      riskScore += 12;
      findings.push({
        finding: 'HTTP-only service (port 80) without HTTPS (port 443) — data transmitted in cleartext',
        severity: 'high',
        category: 'encryption',
        remediation: 'Deploy TLS certificate and enforce HTTPS redirect. Consider HSTS header.',
      });
    }

    // 3. Technology-based risk
    for (const tech of techFromTags) {
      const techLower = tech.toLowerCase();
      if (techLower.includes('wordpress')) {
        riskScore += 8;
        findings.push({
          finding: `WordPress detected — common target for plugin vulnerabilities, brute force, and XML-RPC attacks`,
          severity: 'medium',
          category: 'technology',
          remediation: 'Ensure WordPress core and all plugins are updated. Disable XML-RPC if not needed. Use WAF.',
        });
      }
      if (techLower.includes('apache') || techLower.includes('nginx') || techLower.includes('iis')) {
        contextIndicators.push(`Web server: ${tech}`);
      }
      if (techLower.includes('php')) {
        riskScore += 5;
        findings.push({
          finding: `PHP detected — verify version is current and not end-of-life`,
          severity: 'medium',
          category: 'technology',
          remediation: 'Upgrade to latest stable PHP version. Disable dangerous functions in php.ini.',
        });
      }
    }

    // 4. Version staleness check
    for (const ver of versionFromTags) {
      const verParts = ver.split('.');
      if (verParts.length >= 2) {
        const major = parseInt(verParts[0]);
        if (!isNaN(major) && major > 0) {
          contextIndicators.push(`Detected version: ${ver}`);
        }
      }
    }

    // 5. Exposure assessment — publicly reachable subdomain
    if (s.ip) {
      riskScore += 5; // Base risk for being publicly resolvable
      contextIndicators.push(`Publicly resolvable IP: ${s.ip}`);
    }
    if (subPorts.length > 5) {
      riskScore += 10;
      findings.push({
        finding: `Excessive port exposure: ${subPorts.length} open ports detected — increases attack surface significantly`,
        severity: 'high',
        category: 'network_exposure',
        remediation: 'Review all open ports and close unnecessary services. Implement network segmentation.',
      });
    }

    // 6. Wildcard/catch-all subdomain detection
    if (s.name.startsWith('*.')) {
      riskScore += 8;
      findings.push({
        finding: 'Wildcard DNS record detected — any subdomain resolves, enabling subdomain takeover attacks',
        severity: 'high',
        category: 'dns_configuration',
        remediation: 'Remove wildcard DNS records unless explicitly required. Monitor for subdomain takeover.',
      });
    }

    // Cap and compute risk band
    riskScore = Math.min(riskScore, 100);
    const riskBand = riskScore >= 70 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 25 ? 'medium' : 'low';
    const vulnRiskScore = findings.filter(f => f.category === 'vulnerability').length * 20;
    const vulnRiskBand = vulnRiskScore >= 60 ? 'critical' : vulnRiskScore >= 40 ? 'high' : vulnRiskScore >= 20 ? 'medium' : 'low';
    const impactScore = Math.min(subPorts.length * 10 + findings.length * 5 + (s.ip ? 10 : 0), 100);
    const likelihoodScore = Math.min(findings.filter(f => f.severity === 'critical').length * 25 + findings.filter(f => f.severity === 'high').length * 15 + subPorts.length * 5, 100);

    return {
      id: `sub-${s.name}`,
      hostname: s.name,
      assetType: 'subdomain',
      technologies: techFromTags,
      technologyVersions: Object.fromEntries(techFromTags.map((t: string, i: number) => [t, versionFromTags[i] || ''])),
      dnsRecords: s.ip ? { A: [s.ip] } : {},
      hybridRiskScore: riskScore,
      riskBand,
      discoveryMethod: 'passive_recon',
      dnsStatus: s.ip ? 'dns_verified' : 'unresolved',
      postureFindings: findings,
      testVectors,
      contextIndicators,
      carverScores: null,
      shockScores: null,
      missionImpactScore: impactScore,
      suggestedTier: riskScore >= 50 ? 'tier1' : riskScore >= 25 ? 'tier2' : 'tier3',
      cvssEstimate: Math.min(findings.filter(f => f.severity === 'critical').length * 2.5 + findings.filter(f => f.severity === 'high').length * 1.5 + findings.length * 0.5, 10),
      confidence: s.ip ? 0.85 : 0.6,
      impactScore,
      likelihoodScore,
      assetCriticalityScore: Math.min(subPorts.length * 8 + techFromTags.length * 5, 100),
      assetCriticalityBand: subPorts.length > 5 ? 'high' : subPorts.length > 2 ? 'medium' : 'low',
      vulnRiskScore,
      vulnRiskBand,
      _isSubdomainAsset: true,
      _source: s.source || 'passive_recon',
      _ip: s.ip || '',
      _ports: subPorts,
      _tags: s.tags || [],
    };
  });

  const allAssets = [...(assets as any[]), ...subdomainAssets];

  // Sort ALL assets (DB + subdomains) by risk score descending
  const sortedAssets = [...allAssets].sort((a: any, b: any) => (b.hybridRiskScore || 0) - (a.hybridRiskScore || 0));

  // Risk distribution (includes subdomains)
  const riskDist = { critical: 0, high: 0, medium: 0, low: 0 };
  allAssets.forEach((a: any) => {
    const band = a.riskBand || "low";
    if (band in riskDist) riskDist[band as keyof typeof riskDist]++;
  });

  return (
    <AppShell>
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={() => navigate("/domain-intel")}>
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div className="flex-1">
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Brain className="h-7 w-7 text-purple-400" />
            <span className="font-mono">{scan.primaryDomain}</span>
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            {scan.clientType?.toUpperCase()} &middot; {scan.sector} &middot; {assets.length} assets discovered &middot; Scanned {new Date(scan.createdAt).toLocaleDateString()}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            size="sm"
            className="h-8 w-8 p-0 text-red-400 hover:text-red-300 hover:bg-red-500/10"
            disabled={deleteScanMut.isPending}
            onClick={() => {
              if (confirm(`Delete scan for ${scan.primaryDomain}? This will remove all associated data and cannot be undone.`)) {
                deleteScanMut.mutate({ scanId: scan.id });
              }
            }}
            title="Delete scan"
          >
            {deleteScanMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
          </Button>
          {(scan.status === 'completed' || scan.status === 'scan_complete') && (
            <Button
              size="sm"
              className="text-xs bg-purple-600 hover:bg-purple-700 text-white"
              onClick={async () => {
                let entityOverride = null;
                try {
                  entityOverride = await utils.domainIntel.getEntityOverride.fetch({ scanId: scan.id });
                } catch { /* optional */ }
                const fullScanData = { ...scan, ...pipeline, assets, observations: pipeline?.observations || [], entityOverride };
                toast.info('Generating Domain Intelligence report PDF — this may take a moment...');
                let evidenceData;
                try {
                  evidenceData = await utils.domainIntel.getReportEvidence.fetch({ scanId: scan.id });
                } catch { /* optional */ }
                let infraMapData = null;
                try {
                  infraMapData = await utils.calderaProxy.inferInfrastructure.fetch({ scanId: scan.id });
                } catch { /* optional — infra map enriches but isn't required */ }
                let vrHistory = null;
                try {
                  const vrData = await utils.calderaProxy.getVendorRiskHistory.fetch({ scanId: scan.id });
                  vrHistory = (vrData as any)?.history || null;
                } catch { /* optional */ }
                exportDiReport(scan.primaryDomain, fullScanData, undefined, evidenceData, infraMapData, vrHistory);
              }}
            >
              <FileText className="h-3.5 w-3.5 mr-1.5" />
              Report
            </Button>
          )}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="text-xs">
                <Download className="h-3.5 w-3.5 mr-1.5" />
                Export
                <ChevronDown className="h-3 w-3 ml-1" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuLabel>Export Data</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={async () => {
                let entityOverride2 = null;
                try {
                  entityOverride2 = await utils.domainIntel.getEntityOverride.fetch({ scanId: scan.id });
                } catch { /* optional */ }
                const fullScanData = { ...scan, ...pipeline, assets, observations: pipeline?.observations || [], entityOverride: entityOverride2 };
                toast.info('Domain Intelligence report export started — this may take a moment...');
                let evidenceData;
                try {
                  evidenceData = await utils.domainIntel.getReportEvidence.fetch({ scanId: scan.id });
                } catch { /* optional */ }
                let infraMapData = null;
                try {
                  infraMapData = await utils.calderaProxy.inferInfrastructure.fetch({ scanId: scan.id });
                } catch { /* optional */ }
                let vrHistory2 = null;
                try {
                  const vrData2 = await utils.calderaProxy.getVendorRiskHistory.fetch({ scanId: scan.id });
                  vrHistory2 = (vrData2 as any)?.history || null;
                } catch { /* optional */ }
                exportDiReport(scan.primaryDomain, fullScanData, undefined, evidenceData, infraMapData, vrHistory2);
              }}>
                <ShieldAlert className="h-4 w-4 mr-2" /> Full DI Report (PDF)
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => {
                // Check if validation data is available for enhanced export
                if (validationRun && validationResults.length > 0) {
                  exportExecutiveSummaryWithValidation(scan.primaryDomain, { ...scan, ...pipeline }, validationRun, validationResults);
                  toast.success('Executive summary with validation evidence exported');
                } else {
                  exportExecutiveSummary(scan.primaryDomain, { ...scan, ...pipeline });
                  toast.success('Executive summary PDF exported');
                }
              }}>
                <FileText className="h-4 w-4 mr-2" /> Executive Summary (PDF)
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => {
                exportScanAssets(scan.primaryDomain, assets, 'csv');
                toast.success(`Exported ${assets.length} assets as CSV`);
              }}>
                <Database className="h-4 w-4 mr-2" /> Assets (CSV)
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => {
                exportScanAssets(scan.primaryDomain, assets, 'pdf');
                toast.success(`Exported ${assets.length} assets as PDF`);
              }}>
                <Database className="h-4 w-4 mr-2" /> Assets (PDF)
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => {
                const allFindings = assets.flatMap((a: any) => {
                  const findings = a.postureFindings || (a.analysis ? safeJsonParse<any>(a.analysis, {})?.postureFindings : []) || [];
                  return findings;
                });
                exportFindings(scan.primaryDomain, allFindings, 'csv');
                toast.success(`Exported ${allFindings.length} findings as CSV`);
              }}>
                <AlertTriangle className="h-4 w-4 mr-2" /> Findings (CSV)
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => {
                const allFindings = assets.flatMap((a: any) => {
                  const findings = a.postureFindings || (a.analysis ? safeJsonParse<any>(a.analysis, {})?.postureFindings : []) || [];
                  return findings;
                });
                exportFindings(scan.primaryDomain, allFindings, 'pdf');
                toast.success(`Exported ${allFindings.length} findings as PDF`);
              }}>
                <AlertTriangle className="h-4 w-4 mr-2" /> Findings (PDF)
              </DropdownMenuItem>
              {threatActorMatches?.actors?.length > 0 && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => {
                    exportThreatActors(scan.primaryDomain, threatActorMatches.actors, 'csv');
                    toast.success(`Exported ${threatActorMatches.actors.length} threat actors`);
                  }}>
                    <Skull className="h-4 w-4 mr-2" /> Threat Actors (CSV)
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => {
                    exportThreatActors(scan.primaryDomain, threatActorMatches.actors, 'pdf');
                    toast.success(`Exported ${threatActorMatches.actors.length} threat actors`);
                  }}>
                    <Skull className="h-4 w-4 mr-2" /> Threat Actors (PDF)
                  </DropdownMenuItem>
                </>
              )}
              {validationResults.length > 0 && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => {
                    exportValidationResultsCsv(scan.primaryDomain, validationResults);
                    toast.success(`Exported ${validationResults.length} validation results as CSV`);
                  }}>
                    <FlaskConical className="h-4 w-4 mr-2" /> Validation Results (CSV)
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => {
                    if (validationRun) {
                      exportValidationReportPdf(scan.primaryDomain, validationRun, validationResults);
                      toast.success('Validation evidence report exported as PDF');
                    }
                  }}>
                    <FlaskConical className="h-4 w-4 mr-2" /> Validation Evidence (PDF)
                  </DropdownMenuItem>
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
          {/* Generate Test Plan Button */}
          {(scan.status === 'completed' || scan.status === 'scan_complete') && (
            <Button
              variant="outline"
              size="sm"
              className="text-xs border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10"
              onClick={async () => {
                setTestPlanGenerating(true);
                toast.info('Generating PTES/NIST test plan — this may take 30-60 seconds...');
                try {
                  // Map DI scan data to the test plan generator's expected input shape
                  const mappedAssets = (assets as any[]).map((a: any) => ({
                    hostname: a.hostname || '',
                    ip: a.ip || a.ipAddress || undefined,
                    ports: a.ports || [],
                    technologies: a.technologies || [],
                    hybridRiskScore: a.hybridRiskScore || a.riskScore || 0,
                    carverScores: a.carverScores || {},
                    missionFunction: a.missionFunction,
                    essentialService: a.essentialService,
                    type: a.type || 'web_server',
                    services: a.services || (a.ports || []).map((p: number) => ({ port: p, service: `port-${p}` })),
                    cloudProvider: a.cloudProvider,
                    wafDetected: a.wafDetected,
                    certificates: a.certificates || [],
                  }));
                  const result = await (trpc as any).testPlanGenerator.generate.mutate({
                    scanId,
                    domain: scan.domain,
                    orgName: (scan as any).orgName || undefined,
                    planType: 'penetration_test',
                    assets: mappedAssets,
                    observations: pipeline?.observations || [],
                    domainHealthData: pipeline?.domainHealth || undefined,
                    wafNgfwData: pipeline?.wafNgfwData || undefined,
                    breachData: pipeline?.breachData || undefined,
                    threatActorData: pipeline?.threatActorMatches || undefined,
                    dnsAssessmentData: pipeline?.dnsAssessment || undefined,
                    llmAnalysis: pipeline?.postEnrichmentAnalysis || undefined,
                    carverFeedback: pipeline?.carverFeedback || undefined,
                    passiveRecon: pipeline?.passiveRecon || undefined,
                  });
                  setTestPlanResult(result);
                  setTestPlanDialogOpen(true);
                  toast.success('Test plan generated successfully');
                } catch (err: any) {
                  toast.error(`Test plan generation failed: ${sanitizeErrorForToast(err)}`);
                } finally {
                  setTestPlanGenerating(false);
                }
              }}
              disabled={testPlanGenerating}
            >
              {testPlanGenerating ? (
                <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
              ) : (
                <ClipboardCheck className="h-3.5 w-3.5 mr-1.5" />
              )}
              {testPlanGenerating ? 'Generating...' : 'Test Plan'}
            </Button>
          )}
          {/* Refresh Scan Button — only for completed scans */}
          {(scan.status === 'completed' || scan.status === 'scan_complete') && (
            <Button
              variant="outline"
              size="sm"
              className="text-xs border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10"
              onClick={() => {
                if (confirm('Refresh this scan? This will re-run the full pipeline (discovery, analysis, scoring, entity resolution, BIA) with the latest platform features. Original results will be preserved as a snapshot for comparison.')) {
                  refreshScanMutation.mutate({ scanId });
                }
              }}
              disabled={refreshScanMutation.isPending || refreshing}
            >
              {refreshScanMutation.isPending || refreshing ? (
                <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
              ) : (
                <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
              )}
              {refreshing ? 'Refreshing...' : 'Refresh Scan'}
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            className="text-xs"
            onClick={() => navigate(`/domain-intel/curate/${scanId}`)}
          >
            <Eye className="h-3.5 w-3.5 mr-1.5" />
            Review & Curate Findings
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="text-xs border-green-500/30 text-green-400 hover:bg-green-500/10"
            onClick={() => navigate(`/ops-viewer?di=${scanId}`)}
          >
            <Network className="h-3.5 w-3.5 mr-1.5" />
            Ops Viewer
          </Button>
          <div className="flex items-center gap-4">
            <div className="flex flex-col items-center">
              <RiskGauge score={scan.overallRiskScore || 0} band={scan.overallRiskBand || "low"} />
              <span className="text-[9px] text-muted-foreground mt-1">AC3 Hybrid</span>
            </div>
            {(() => {
              const assetList = (assets || []) as any[];
              const cvssValues = assetList.map((a: any) => (a.cvssEstimate || 0) / 10).filter((v: number) => v > 0);
              const avgCvss = cvssValues.length > 0 ? cvssValues.reduce((s: number, v: number) => s + v, 0) / cvssValues.length : 0;
              const maxCvss = cvssValues.length > 0 ? Math.max(...cvssValues) : 0;
              return (
                <div className="flex flex-col items-center gap-1">
                  <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/5 px-4 py-2 text-center">
                    <span className="text-2xl font-bold text-cyan-400">{avgCvss.toFixed(1)}</span>
                    <span className="text-xs text-cyan-400/70">/10</span>
                  </div>
                  <span className="text-[9px] text-cyan-400/60">Avg CVSS</span>
                  <span className="text-[8px] text-muted-foreground/50">Max: {maxCvss.toFixed(1)}</span>
                </div>
              );
            })()}
          </div>
        </div>
      </div>

      {/* ── KPI Mission Posture Strip ── */}
      {(() => {
        const criticalCount = (assets as any[]).filter((a: any) => a.riskBand === 'critical').length;
        const highCount = (assets as any[]).filter((a: any) => a.riskBand === 'high').length;
        const verifiedCount = validationSummary.data?.results?.filter((r: any) => r.exploitable)?.length || 0;
        const breachExposures = (pipeline?.breachData?.totalExposures || 0) as number;
        const coverageScore = (scan as any).discoveryCoverageScore || 0;
        const coverageBand = (scan as any).discoveryCoverageBand || 'unknown';
        const prevRisk = scanDelta?.previousRiskScore ?? pipeline?.previousSnapshot?.overallRiskScore ?? null;
        const riskDelta = prevRisk != null ? (scan.overallRiskScore || 0) - prevRisk : null;
        const riskDeltaPct = prevRisk != null && prevRisk > 0 ? ((riskDelta! / prevRisk) * 100) : null;
        const prevAssets = scanDelta?.previousTotalAssets ?? pipeline?.previousSnapshot?.totalAssets ?? null;
        const totalAssets = assets.length + subdomainAssets.length;
        const assetDelta = prevAssets != null ? totalAssets - prevAssets : null;
        const assetDeltaPct = prevAssets != null && prevAssets > 0 ? ((assetDelta! / prevAssets) * 100) : null;
        const prevFindings = scanDelta?.previousTotalFindings ?? null;
        const findingsDelta = scanDelta?.findingsDelta ?? null;
        const findingsDeltaPct = prevFindings != null && prevFindings > 0 && findingsDelta != null ? ((findingsDelta / prevFindings) * 100) : null;

        const kpiItems: KpiItem[] = [
          {
            label: "Assets in Scope",
            value: totalAssets,
            icon: <Target className="h-4 w-4 text-cyan-400" />,
            color: "text-cyan-400",
            delta: assetDelta,
            deltaPercent: assetDeltaPct,
            subtitle: subdomainAssets.length > 0 ? `${assets.length} analyzed + ${subdomainAssets.length} subs` : (scanDelta ? `vs. ${prevAssets ?? '?'} prev` : undefined),
            onClick: () => setActiveTab('assets'),
          },
          {
            label: "Critical Findings",
            value: criticalCount,
            icon: <Skull className="h-4 w-4 text-red-400" />,
            color: criticalCount > 0 ? "text-red-400" : "text-muted-foreground",
            deltaInverted: true,
            onClick: () => setActiveTab('vulns'),
          },
          {
            label: "High Findings",
            value: highCount,
            icon: <AlertTriangle className="h-4 w-4 text-orange-400" />,
            color: highCount > 0 ? "text-orange-400" : "text-muted-foreground",
            deltaInverted: true,
            onClick: () => setActiveTab('vulns'),
          },
          {
            label: "Risk Score",
            value: scan.overallRiskScore || 0,
            icon: <Shield className="h-4 w-4 text-purple-400" />,
            onClick: () => setActiveTab('overview'),
            color: (scan.overallRiskBand === 'critical' ? 'text-red-400' : scan.overallRiskBand === 'high' ? 'text-orange-400' : scan.overallRiskBand === 'medium' ? 'text-yellow-400' : 'text-emerald-400'),
            delta: riskDelta,
            deltaPercent: riskDeltaPct,
            deltaInverted: true,
            suffix: "/100",
            subtitle: scanDelta ? `prev: ${prevRisk ?? '?'}` : undefined,
          },
          {
            label: "Verified Exploitable",
            value: verifiedCount,
            icon: <Crosshair className="h-4 w-4 text-red-500" />,
            color: verifiedCount > 0 ? "text-red-500" : "text-muted-foreground",
            deltaInverted: true,
            onClick: () => setActiveTab('vulns'),
          },
          {
            label: "Breach Sources",
            value: pipeline?.breachData?.uniqueBreachSources || 0,
            icon: <Lock className="h-4 w-4 text-amber-400" />,
            color: breachExposures > 0 ? "text-amber-400" : "text-muted-foreground",
            deltaInverted: true,
            onClick: () => setActiveTab('breaches'),
          },
          {
            label: "Recon Coverage",
            value: coverageScore,
            icon: <Radar className="h-4 w-4 text-emerald-400" />,
            color: coverageScore >= 70 ? "text-emerald-400" : coverageScore >= 40 ? "text-yellow-400" : "text-red-400",
            suffix: "%",
            progress: coverageScore,
            progressColor: coverageScore >= 70 ? "bg-emerald-500" : coverageScore >= 40 ? "bg-yellow-500" : "bg-red-500",
            subtitle: coverageBand,
            onClick: () => setActiveTab('coverage'),
          },
          {
            label: "Unique Findings",
            value: scan.totalFindings || 0,
            icon: <Bug className="h-4 w-4 text-yellow-400" />,
            delta: findingsDelta,
            deltaPercent: findingsDeltaPct,
            deltaInverted: true,
            subtitle: (pipeline?.uniqueCveSummary as any)?.totalFindingInstances
              ? `${(pipeline.uniqueCveSummary as any).totalFindingInstances.toLocaleString()} instances across assets`
              : scanDelta ? `prev: ${prevFindings ?? '?'}` : undefined,
            onClick: () => setActiveTab('vulns'),
          },
        ];

        return <KpiStrip items={kpiItems} />;
      })()}

      {/* Page Purpose Description */}
      <div className="px-1">
        <p className="page-purpose">
          Passive domain intelligence results for <strong className="text-foreground">{scan.primaryDomain}</strong>. 
          This view presents discovered assets, risk scores, vulnerability findings, breach exposures, and threat actor 
          correlations gathered from open-source intelligence (OSINT) sources — no packets were sent to the target infrastructure.
        </p>
      </div>

      {/* Refresh In Progress Banner */}
      {isRefreshInProgress && (
        <Card className="border-cyan-500/30 bg-cyan-500/5">
          <CardContent className="p-5 flex items-center gap-4">
            <div className="p-3 rounded-lg bg-cyan-500/10">
              <RefreshCw className="h-6 w-6 text-cyan-400 animate-spin" />
            </div>
            <div className="flex-1">
              <p className="font-semibold text-sm text-cyan-400">Scan Refresh In Progress</p>
              <p className="text-xs text-muted-foreground mt-0.5">
                Re-running the full pipeline with latest features (entity resolution, BIA enrichment, crawl-to-phish analysis). 
                Stage: <span className="font-mono text-cyan-400">{refreshPoll.data?.status || 'initializing'}</span>
              </p>
              <Progress value={(() => {
                const stages: Record<string, number> = { discovering: 15, passive_recon: 25, analyzing: 45, scoring: 65, recommending: 80 };
                return stages[refreshPoll.data?.status || ''] || 10;
              })()} className="mt-2 h-1.5" />
            </div>
          </CardContent>
        </Card>
      )}

      {/* Previous Snapshot Comparison Banner */}
      {pipeline?.previousSnapshot && pipeline?.refreshedAt && !isRefreshInProgress && (
        <Card className="border-indigo-500/30 bg-indigo-500/5">
          <CardContent className="p-4">
            <div className="flex items-center gap-3 mb-3">
              <RefreshCw className="h-4 w-4 text-indigo-400" />
              <span className="text-sm font-semibold text-indigo-400">Refreshed Scan Results</span>
              <Badge variant="outline" className="text-[10px] border-indigo-500/30 text-indigo-400">
                Refreshed {new Date(pipeline.refreshedAt).toLocaleString()}
              </Badge>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              {(() => {
                const prev = pipeline.previousSnapshot;
                const deltaAssets = (scan.totalAssets || 0) - (prev.totalAssets || 0);
                const deltaFindings = (scan.totalFindings || 0) - (prev.totalFindings || 0);
                const deltaRisk = (scan.overallRiskScore || 0) - (prev.overallRiskScore || 0);
                const deltaCoverage = (scan.discoveryCoverageScore || 0) - (prev.discoveryCoverageScore || 0);
                const fmt = (n: number) => n > 0 ? `+${n}` : String(n);
                const color = (n: number, invert = false) => {
                  if (n === 0) return 'text-muted-foreground';
                  return (invert ? n < 0 : n > 0) ? 'text-emerald-400' : 'text-red-400';
                };
                return (
                  <>
                    <div className="rounded-lg border border-border/50 p-2.5 text-center">
                      <p className="text-muted-foreground mb-1">Assets</p>
                      <p className="font-bold text-base">{scan.totalAssets || 0}</p>
                      {deltaAssets !== 0 && <p className={`text-[10px] ${color(deltaAssets)}`}>{fmt(deltaAssets)} from previous</p>}
                    </div>
                    <div className="rounded-lg border border-border/50 p-2.5 text-center">
                      <p className="text-muted-foreground mb-1">Unique Findings</p>
                      <p className="font-bold text-base">{scan.totalFindings || 0}</p>
                      {deltaFindings !== 0 && <p className={`text-[10px] ${color(deltaFindings)}`}>{fmt(deltaFindings)} from previous</p>}
                    </div>
                    <div className="rounded-lg border border-border/50 p-2.5 text-center">
                      <p className="text-muted-foreground mb-1">Risk Score</p>
                      <p className="font-bold text-base">{scan.overallRiskScore || 0}</p>
                      {deltaRisk !== 0 && <p className={`text-[10px] ${color(deltaRisk, true)}`}>{fmt(deltaRisk)} from previous</p>}
                    </div>
                    <div className="rounded-lg border border-border/50 p-2.5 text-center">
                      <p className="text-muted-foreground mb-1">Coverage</p>
                      <p className="font-bold text-base">{scan.discoveryCoverageScore || 0}%</p>
                      {deltaCoverage !== 0 && <p className={`text-[10px] ${color(deltaCoverage)}`}>{fmt(deltaCoverage)}% from previous</p>}
                    </div>
                  </>
                );
              })()}
            </div>
            <p className="text-[10px] text-muted-foreground mt-2">
              Previous scan: {pipeline.previousSnapshot?.snapshotAt ? new Date(pipeline.previousSnapshot.snapshotAt).toLocaleString() : 'N/A'} — 
              {pipeline.previousSnapshot?.totalAssets || 0} assets, {pipeline.previousSnapshot?.totalFindings || 0} findings, 
              risk score {pipeline.previousSnapshot?.overallRiskScore || 0}
            </p>
          </CardContent>
        </Card>
      )}

      {/* Validate Top 10 Quick Action */}
      {scan.status !== 'pending' && scan.status !== 'discovering' && (
        <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><ValidateTop10Banner scanId={scanId} validationSummary={validationSummary.data} /></Suspense>
      )}

      {/* Validation Coverage Metric */}
      {validationSummary.data?.run && validationSummary.data.results?.length > 0 && (() => {
        const totalFindings = scan.totalFindings ?? validationSummary.data.results.length;
        const validated = validationSummary.data.results.filter((r: any) => r.status === 'validated' || r.status === 'not_vulnerable').length;
        const exploitableCount = validationSummary.data.results.filter((r: any) => r.exploitable).length;
        const coveragePct = totalFindings > 0 ? Math.round((validated / totalFindings) * 100) : 0;
        const exploitablePct = validated > 0 ? Math.round((exploitableCount / validated) * 100) : 0;
        const barColor = coveragePct >= 80 ? 'bg-emerald-500' : coveragePct >= 50 ? 'bg-amber-500' : 'bg-red-500';
        const borderColor = coveragePct >= 80 ? 'border-emerald-500/30' : coveragePct >= 50 ? 'border-amber-500/30' : 'border-red-500/30';
        const bgColor = coveragePct >= 80 ? 'bg-emerald-500/5' : coveragePct >= 50 ? 'bg-amber-500/5' : 'bg-red-500/5';
        return (
          <Card className={`${borderColor} ${bgColor}`}>
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <FlaskConical className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm font-semibold">Validation Coverage</span>
                </div>
                <span className="text-xs text-muted-foreground">
                  {validated} of {totalFindings} findings validated
                </span>
              </div>
              <div className="flex items-center gap-4">
                <div className="flex-1">
                  <div className="h-3 bg-zinc-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${barColor} rounded-full transition-all duration-500`}
                      style={{ width: `${Math.max(2, coveragePct)}%` }}
                    />
                  </div>
                </div>
                <span className="text-sm font-bold tabular-nums w-12 text-right">{coveragePct}%</span>
              </div>
              <div className="flex items-center gap-6 mt-2 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-red-500" />
                  {exploitableCount} exploitable ({exploitablePct}%)
                </span>
                <span className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-emerald-500" />
                  {validated - exploitableCount} not vulnerable
                </span>
                <span className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-zinc-500" />
                  {totalFindings - validated} unconfirmed
                </span>
              </div>
            </CardContent>
          </Card>
        );
      })()}

      {/* Passive Discovery Disclaimer */}
      {(scan.status === 'scan_complete' || scan.status === 'engagement_complete') && (
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardContent className="p-4 flex items-start gap-3">
            <Info className="h-5 w-5 text-amber-400 mt-0.5 flex-shrink-0" />
            <div>
              <p className="text-sm font-semibold text-amber-400">Passive Discovery Results</p>
              <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                These results are based on <strong>passive discovery and open-source intelligence (OSINT)</strong> — no active scanning, probing, or exploitation was performed against the target. 
                Findings include publicly available DNS records, certificate transparency logs, Shodan data, WHOIS records, and technology fingerprinting from HTTP headers. 
                Port and service data comes from third-party databases and may not reflect the current live state of the target infrastructure.
              </p>
              <p className="text-xs text-muted-foreground mt-2 leading-relaxed">
                To confirm these findings with <strong>active scanning and vulnerability enumeration</strong>, create a formal engagement with a signed Rules of Engagement (ROE) document authorizing direct interaction with the target.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Scan Complete — Start Engagement Banner */}
      {scan.status === 'scan_complete' && !engagementRunning && (
        <Card className="border-cyan-500/30 bg-cyan-500/5">
          <CardContent className="p-5 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-lg bg-cyan-500/10">
                <Search className="h-6 w-6 text-cyan-400" />
              </div>
              <div>
                <p className="font-semibold text-sm">Reconnaissance Scan Complete</p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Review the discovered assets, risk scores, and posture findings below. When ready, start a full engagement to add threat actor profiling and campaign design.
                </p>
              </div>
            </div>
            <div className="flex gap-2 shrink-0">
              <Button
                variant="outline"
                className="border-amber-500/30 text-amber-400 hover:bg-amber-500/10"
                onClick={() => setShowCreateStackProfile(true)}
              >
                <Layers className="h-4 w-4 mr-2" />
                Create Stack Profile
              </Button>
              <Link href="/engagements">
                <Button variant="outline" className="border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10">
                  <FileText className="h-4 w-4 mr-2" />
                  Create Engagement & ROE
                </Button>
              </Link>
              <Button
                className="bg-purple-600 hover:bg-purple-700"
                onClick={() => startEngagement.mutate({ scanId })}
                disabled={startEngagement.isPending}
              >
                {startEngagement.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Zap className="h-4 w-4 mr-2" />
                )}
                Start Full Engagement
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Engagement Running Banner */}
      {engagementRunning && (
        <Card className="border-purple-500/30 bg-purple-500/5">
          <CardContent className="p-5 flex items-center gap-4">
            <Loader2 className="h-6 w-6 animate-spin text-purple-400" />
            <div>
              <p className="font-semibold text-sm">Engagement in Progress</p>
              <p className="text-xs text-muted-foreground mt-0.5">
                Running threat actor profiling and campaign design. This typically takes 30-60 seconds...
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Summary Cards */}
      <div className={`grid grid-cols-2 ${breachData ? 'md:grid-cols-6' : 'md:grid-cols-5'} gap-3`}>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold">{assets.length}</p>
            <p className="text-xs text-muted-foreground mt-1">Assets Discovered</p>
            {subdomainAssets.length > 0 && (
              <p className="text-[10px] text-muted-foreground">{assets.length} analyzed + {subdomainAssets.length} subdomains</p>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold">{(scan as any).confirmedFindings ?? scan.totalFindings ?? 0}</p>
            <p className="text-xs text-muted-foreground mt-1">Unique Confirmed Findings</p>
            {(pipeline?.uniqueCveSummary as any)?.totalFindingInstances > 0 && (
              <p className="text-[10px] text-muted-foreground">{(pipeline.uniqueCveSummary as any).totalFindingInstances.toLocaleString()} total instances across {scan.totalAssets} assets</p>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold">{campaigns.length}</p>
            <p className="text-xs text-muted-foreground mt-1">Campaigns Designed</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="space-y-1">
              {Object.entries(riskDist).map(([band, count]) => (
                <div key={band} className="flex items-center gap-2 text-xs">
                  <div className={`w-2 h-2 rounded-full ${RISK_BAR_COLORS[band]}`} />
                  <span className="capitalize flex-1">{band}</span>
                  <span className="font-mono">{count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
        <Card className={`border-${((scan as any).discoveryCoverageBand === 'comprehensive' ? 'emerald' : (scan as any).discoveryCoverageBand === 'good' ? 'blue' : (scan as any).discoveryCoverageBand === 'partial' ? 'amber' : 'red')}-500/20`}>
          <CardContent className="p-4 text-center">
            <p className={`text-3xl font-bold ${((scan as any).discoveryCoverageBand === 'comprehensive' ? 'text-emerald-400' : (scan as any).discoveryCoverageBand === 'good' ? 'text-blue-400' : (scan as any).discoveryCoverageBand === 'partial' ? 'text-amber-400' : 'text-red-400')}`}>{(scan as any).discoveryCoverageScore ?? 0}%</p>
            <p className="text-xs text-muted-foreground mt-1">Recon Coverage</p>
            <p className="text-[10px] text-muted-foreground capitalize">{(scan as any).discoveryCoverageBand || 'unknown'}</p>
          </CardContent>
        </Card>
        {breachData && (
          <Card className="border-red-500/20">
            <CardContent className="p-4 text-center">
              <p className="text-3xl font-bold text-red-400">{breachData.totalExposures?.toLocaleString() || 0}</p>
              <p className="text-xs text-muted-foreground mt-1">Exposed Records</p>
              {breachData.credentialPairs > 0 && (
                <p className="text-[10px] text-red-400/80 mt-0.5">{breachData.credentialPairs} credentials</p>
              )}
            </CardContent>
          </Card>
        )}
        {(credentialTestSummary || oemCredentials) && (
          <Card className={`border-${credentialTestSummary?.confirmed > 0 ? 'red' : 'amber'}-500/20`}>
            <CardContent className="p-4 text-center">
              <p className={`text-3xl font-bold ${credentialTestSummary?.confirmed > 0 ? 'text-red-400' : 'text-amber-400'}`}>
                {credentialTestSummary?.confirmed || 0}
              </p>
              <p className="text-xs text-muted-foreground mt-1">Default Creds Confirmed</p>
              {credentialTestSummary?.tested > 0 && (
                <p className="text-[10px] text-muted-foreground mt-0.5">
                  {credentialTestSummary.tested} tested, {credentialTestSummary.failed || 0} failed
                </p>
              )}
              {!credentialTestSummary && oemCredentials?.length > 0 && (
                <p className="text-[10px] text-amber-400/80 mt-0.5">{oemCredentials.length} OEM creds matched</p>
              )}
            </CardContent>
          </Card>
        )}
      </div>

      {/* Grouped Tab Navigation */}
      {(() => {
        const isEngagement = scan.status !== 'scan_complete';
        const tabGroups: TabGroup[] = [
          {
            id: 'overview',
            label: 'Overview',
            icon: <BarChart3 className="h-3.5 w-3.5" />,
            color: 'text-cyan-400',
            subTabs: [
              { value: 'overview', label: 'Dashboard', icon: <BarChart3 className="h-3 w-3" /> },
              { value: 'findings', label: 'Findings', icon: <AlertTriangle className="h-3 w-3" />, count: scan.totalFindings || 0 },
              { value: 'coverage', label: 'Coverage', icon: <Radar className="h-3 w-3" /> },
              { value: 'changes', label: 'Changes', icon: <GitCompareArrows className="h-3 w-3" /> },
            ],
          },
          {
            id: 'attack-surface',
            label: 'Attack Surface',
            icon: <Target className="h-3.5 w-3.5" />,
            color: 'text-purple-400',
            subTabs: [
              { value: 'assets', label: 'Assets', icon: <Server className="h-3 w-3" />, count: assets.length },
              { value: 'subdomains', label: 'Subdomains', icon: <Globe className="h-3 w-3" />, count: subdomainAssets.length },
              { value: 'inventory', label: 'Inventory', icon: <Database className="h-3 w-3" /> },
              { value: 'ports', label: 'Ports & Services', icon: <Network className="h-3 w-3" /> },
              { value: 'spider', label: 'Web Crawl', icon: <Route className="h-3 w-3" /> },
              { value: 'web-crawl', label: 'Crawl Data', icon: <Telescope className="h-3 w-3" /> },
              { value: 'email-security', label: 'Email Security', icon: <Mail className="h-3 w-3" /> },
              { value: 'dns-security', label: 'DNS Security', icon: <Shield className="h-3 w-3" /> },
            ],
          },
          {
            id: 'vulnerabilities',
            label: 'Vulnerabilities',
            icon: <Bug className="h-3.5 w-3.5" />,
            color: 'text-red-400',
            subTabs: [
              { value: 'vulns', label: 'CVEs & Vulns', icon: <Bug className="h-3 w-3" /> },
              { value: 'tech-vulns', label: 'Tech Vulns', icon: <Cpu className="h-3 w-3" /> },
              { value: 'takeover', label: 'Takeover Risk', icon: <Flag className="h-3 w-3" /> },
              { value: 'takeover-poc', label: 'Takeover PoC', icon: <Play className="h-3 w-3" /> },
              { value: 'credentials', label: 'Default Creds', icon: <KeyRound className="h-3 w-3" />, hidden: !(credentialTestSummary || oemCredentials) },
              { value: 'breaches', label: 'Breaches', icon: <Lock className="h-3 w-3" />, count: breachData?.uniqueBreachSources || 0 },
            ],
          },
          {
            id: 'threat-intel',
            label: 'Threat Intel',
            icon: <Skull className="h-3.5 w-3.5" />,
            color: 'text-amber-400',
            subTabs: [
              { value: 'adversaries', label: 'Adversaries', icon: <Users className="h-3 w-3" />, hidden: isEngagement ? false : true },
              { value: 'campaigns', label: 'Campaigns', icon: <Crosshair className="h-3 w-3" />, count: campaigns.length, hidden: isEngagement ? false : true },
              { value: 'threat-model', label: 'Threat Model', icon: <ShieldAlert className="h-3 w-3" />, hidden: isEngagement ? false : true },
              { value: 'cve-actors', label: 'CVE Actors', icon: <Fingerprint className="h-3 w-3" /> },
              { value: 'incidents', label: 'Incidents', icon: <Activity className="h-3 w-3" />, count: incidentSearch?.totalMatches || 0 },
              { value: 'affiliated-domains', label: 'Affiliated Domains', icon: <Globe className="h-3 w-3" />, count: affiliatedDomains?.totalDiscovered || 0 },
              { value: 'entity-profile', label: 'Entity Profile', icon: <Box className="h-3 w-3" />, hidden: !pipeline?.entityProfile },
              { value: 'vendor-alerts', label: 'Vendor Alerts', icon: <ShieldQuestion className="h-3 w-3" />, hidden: !pipeline?.vendorCorrelation },
            ],
          },
          {
            id: 'domain-health',
            label: 'Domain Health',
            icon: <HeartPulse className="h-3.5 w-3.5" />,
            color: 'text-green-400',
            subTabs: [
              { value: 'health-overview', label: 'Health Score', icon: <HeartPulse className="h-3 w-3" /> },
              { value: 'health-blacklist', label: 'Blacklist', icon: <ShieldX className="h-3 w-3" /> },
              { value: 'health-mail', label: 'Mail Server', icon: <MailCheck className="h-3 w-3" /> },
              { value: 'health-mail-security', label: 'SPF/DMARC', icon: <Shield className="h-3 w-3" /> },
              { value: 'health-mail-ports', label: 'Mail Ports', icon: <Network className="h-3 w-3" /> },
              { value: 'health-dns', label: 'DNS Health', icon: <Stethoscope className="h-3 w-3" /> },
              { value: 'health-connectivity', label: 'Connectivity', icon: <Wifi className="h-3 w-3" /> },
              { value: 'health-all', label: 'All Checks', icon: <ListChecks className="h-3 w-3" /> },
              { value: 'health-registration', label: 'Registration', icon: <Globe className="h-3 w-3" /> },
            ],
          },
          {
            id: 'analysis',
            label: 'Analysis',
            icon: <Brain className="h-3.5 w-3.5" />,
            color: 'text-emerald-400',
            subTabs: [
              { value: 'corroboration', label: 'Corroboration', icon: <CheckCircle2 className="h-3 w-3" /> },
              { value: 'accuracy', label: 'Accuracy', icon: <ClipboardCheck className="h-3 w-3" /> },
              { value: 'enrichment', label: 'Enrichment', icon: <Layers className="h-3 w-3" />, hidden: !crossModuleEnrichment },
              { value: 'analysis', label: 'AI Analysis', icon: <Lightbulb className="h-3 w-3" />, hidden: !postEnrichmentAnalysis },
              { value: 'methods', label: 'Methods', icon: <Workflow className="h-3 w-3" /> },
              { value: 'osint-sources', label: 'OSINT Sources', icon: <Radio className="h-3 w-3" /> },
              { value: 'vendor-risk', label: 'Vendor Risk', icon: <ShieldAlert className="h-3 w-3" /> },
              { value: 'infra-map', label: 'Infrastructure Map', icon: <Network className="h-3 w-3" /> },
              { value: 'discovery-context', label: 'Discovery Context', icon: <Microscope className="h-3 w-3" /> },
            ],
          },
          {
            id: 'compliance',
            label: 'Compliance',
            icon: <Shield className="h-3.5 w-3.5" />,
            color: 'text-indigo-400',
            subTabs: [
              { value: 'frameworkmapping', label: 'Framework Mapping', icon: <Shield className="h-3 w-3" /> },
            ],
          },
        ];
        return <TabGroupNav groups={tabGroups} activeTab={activeTab} onTabChange={setActiveTab} />;
      })()}

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">

        <TabsContent value="overview" className="space-y-6">
          {/* Cross-Session Scan Delta Banner */}
          {scanDelta && (
            <Card className="border-blue-500/30 bg-blue-950/20">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <GitCompareArrows className="h-4 w-4 text-blue-400" />
                  Scan Comparison — Scan #{scanDelta.scanNumber} vs Previous (#{scanDelta.previousScanId})
                  <span className="text-xs text-muted-foreground ml-auto">Previous scan: {new Date(scanDelta.previousScanDate).toLocaleDateString()}</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-3 gap-4 mb-4">
                  {/* Risk Delta */}
                  <div className="rounded-lg border border-zinc-700/50 p-3 text-center">
                    <div className="text-xs text-muted-foreground mb-1">Risk Score</div>
                    <div className="flex items-center justify-center gap-2">
                      <span className="text-lg font-mono text-zinc-400">{scanDelta.previousRiskScore ?? '—'}</span>
                      <span className="text-zinc-500">→</span>
                      <span className="text-lg font-mono">{scan.overallRiskScore ?? '—'}</span>
                    </div>
                    {scanDelta.riskDelta != null && (
                      <div className={`text-xs mt-1 font-medium ${scanDelta.riskDelta > 0 ? 'text-red-400' : scanDelta.riskDelta < 0 ? 'text-emerald-400' : 'text-zinc-400'}`}>
                        {scanDelta.riskDelta > 0 ? '▲' : scanDelta.riskDelta < 0 ? '▼' : '—'} {Math.abs(scanDelta.riskDelta)} pts {scanDelta.riskDelta > 0 ? '(regressed)' : scanDelta.riskDelta < 0 ? '(improved)' : '(unchanged)'}
                      </div>
                    )}
                  </div>
                  {/* Asset Delta */}
                  <div className="rounded-lg border border-zinc-700/50 p-3 text-center">
                    <div className="text-xs text-muted-foreground mb-1">Assets Discovered</div>
                    <div className="flex items-center justify-center gap-2">
                      <span className="text-lg font-mono text-zinc-400">{scanDelta.previousTotalAssets ?? '—'}</span>
                      <span className="text-zinc-500">→</span>
                      <span className="text-lg font-mono">{scan.totalAssets ?? '—'}</span>
                    </div>
                    {scanDelta.assetDelta != null && (
                      <div className={`text-xs mt-1 font-medium ${scanDelta.assetDelta > 0 ? 'text-amber-400' : scanDelta.assetDelta < 0 ? 'text-blue-400' : 'text-zinc-400'}`}>
                        {scanDelta.assetDelta > 0 ? '+' : ''}{scanDelta.assetDelta} assets
                      </div>
                    )}
                  </div>
                  {/* Findings Delta */}
                  <div className="rounded-lg border border-zinc-700/50 p-3 text-center">
                    <div className="text-xs text-muted-foreground mb-1">Unique Findings</div>
                    <div className="flex items-center justify-center gap-2">
                      <span className="text-lg font-mono text-zinc-400">{scanDelta.previousTotalFindings ?? '—'}</span>
                      <span className="text-zinc-500">→</span>
                      <span className="text-lg font-mono">{scan.totalFindings ?? '—'}</span>
                    </div>
                    {scanDelta.findingsDelta != null && (
                      <div className={`text-xs mt-1 font-medium ${scanDelta.findingsDelta > 0 ? 'text-red-400' : scanDelta.findingsDelta < 0 ? 'text-emerald-400' : 'text-zinc-400'}`}>
                        {scanDelta.findingsDelta > 0 ? '+' : ''}{scanDelta.findingsDelta} unique findings
                      </div>
                    )}
                    {scanDelta.previousTotalFindings != null && scan.totalFindings != null && scanDelta.previousTotalFindings > scan.totalFindings * 5 && (
                      <div className="text-[9px] text-muted-foreground mt-1 italic">Previous count used raw instances; current uses unique CVEs</div>
                    )}
                  </div>
                </div>
                {/* New / Removed / Persistent asset breakdown */}
                <div className="flex gap-4 text-xs">
                  {scanDelta.newAssets.length > 0 && (
                    <div className="flex items-center gap-1">
                      <span className="inline-block w-2 h-2 rounded-full bg-emerald-400" />
                      <span className="text-emerald-400 font-medium">{scanDelta.newAssets.length} new</span>
                      <span className="text-muted-foreground">({scanDelta.newAssets.slice(0, 3).join(', ')}{scanDelta.newAssets.length > 3 ? '...' : ''})</span>
                    </div>
                  )}
                  {scanDelta.removedAssets.length > 0 && (
                    <div className="flex items-center gap-1">
                      <span className="inline-block w-2 h-2 rounded-full bg-red-400" />
                      <span className="text-red-400 font-medium">{scanDelta.removedAssets.length} removed</span>
                      <span className="text-muted-foreground">({scanDelta.removedAssets.slice(0, 3).join(', ')}{scanDelta.removedAssets.length > 3 ? '...' : ''})</span>
                    </div>
                  )}
                  {scanDelta.persistentAssets.length > 0 && (
                    <div className="flex items-center gap-1">
                      <span className="inline-block w-2 h-2 rounded-full bg-blue-400" />
                      <span className="text-blue-400 font-medium">{scanDelta.persistentAssets.length} persistent</span>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Executive Summary */}
          {scan.executiveSummary && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <FileText className="h-4 w-4 text-purple-400" />
                  Executive Summary
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="prose prose-sm prose-invert max-w-none">
                  <Streamdown>{scan.executiveSummary}</Streamdown>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Passive Recon Risk Signals */}
          {pipeline?.passiveRecon?.riskSignals && pipeline.passiveRecon.riskSignals.length > 0 && (
            <Card className="border-amber-500/20">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-amber-400" />
                  OSINT Risk Signals
                  <Badge variant="outline" className="ml-auto text-amber-400 border-amber-500/40 text-[10px]">
                    {pipeline.passiveRecon.riskSignals.length} signal{pipeline.passiveRecon.riskSignals.length !== 1 ? 's' : ''}
                  </Badge>
                </CardTitle>
                <CardDescription className="text-xs">Passive reconnaissance risk indicators discovered across WHOIS, DNS, certificates, and OSINT sources</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {pipeline.passiveRecon.riskSignals.map((signal: any, idx: number) => {
                    const sev = typeof signal === 'string' ? 'medium' : (signal.severity || 'medium');
                    // Extract human-readable text: prefer rationale > signal > description > title, never fall back to JSON.stringify
                    let text: string;
                    if (typeof signal === 'string') {
                      text = signal;
                    } else {
                      text = signal.rationale || signal.signal || signal.description || signal.title || '';
                      // If still empty, build a summary from known fields
                      if (!text && signal.signalType) {
                        const typeLabel = String(signal.signalType).replace(/_/g, ' ');
                        text = `${typeLabel}${signal.assetId ? ` detected on ${signal.assetId}` : ''}`;
                      }
                      if (!text) text = 'Risk signal detected';
                    }
                    const source = typeof signal === 'string' ? null : (signal.source || signal.connector || null);
                    const signalType = typeof signal === 'object' ? signal.signalType : null;
                    const confidence = typeof signal === 'object' && signal.confidence != null ? signal.confidence : null;
                    const corroboration = typeof signal === 'object' ? signal.corroboration : null;
                    const credEvidence = typeof signal === 'object' ? signal.credentialEvidence : null;
                    const isCredentialSignal = signalType === 'credential_exposure' || signalType === 'high_volume_breach';
                    const sevColors: Record<string, string> = {
                      critical: 'border-red-500/40 bg-red-500/10 text-red-300',
                      high: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
                      medium: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-300',
                      low: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
                      info: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
                    };
                    const sevBadgeColors: Record<string, string> = {
                      critical: 'bg-red-500/20 text-red-300 border-red-500/40',
                      high: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
                      medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
                      low: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
                      info: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
                    };
                    const colorClass = sevColors[sev] || sevColors.medium;
                    return (
                      <div key={idx} className={`rounded-md border px-3 py-2.5 ${colorClass}`}>
                        <div className="flex items-start gap-2">
                          <AlertTriangle className="h-3.5 w-3.5 mt-0.5 shrink-0 opacity-70" />
                          <div className="min-w-0 flex-1">
                            {/* Signal type label + severity badge */}
                            <div className="flex items-center gap-1.5 mb-1 flex-wrap">
                              {signalType && (
                                <span className="text-[10px] font-semibold uppercase tracking-wider opacity-80">
                                  {String(signalType).replace(/_/g, ' ')}
                                </span>
                              )}
                              <span className={`text-[9px] px-1.5 py-0.5 rounded-full border font-medium uppercase ${sevBadgeColors[sev] || sevBadgeColors.medium}`}>
                                {sev}
                              </span>
                              {confidence != null && (
                                <ConfidenceBadge score={confidence} size="xs" showScore showTooltip />
                              )}
                              {corroboration && (
                                <CorroborationTierBadge tier={corroboration} size="xs" showTooltip={true} />
                              )}
                            </div>
                            {/* Rationale / description */}
                            <p className="text-xs leading-snug">{text}</p>
                            {/* Credential evidence details for breach/credential signals */}
                            {isCredentialSignal && credEvidence && (
                              <div className="mt-2 pt-2 border-t border-current/10 space-y-1">
                                {credEvidence.breachName && (
                                  <div className="flex items-center gap-1.5">
                                    <span className="text-[10px] opacity-50 shrink-0">Breach:</span>
                                    <span className="text-[10px] font-medium truncate">{credEvidence.breachName}</span>
                                  </div>
                                )}
                                {credEvidence.breachDate && (
                                  <div className="flex items-center gap-1.5">
                                    <span className="text-[10px] opacity-50 shrink-0">Date:</span>
                                    <span className="text-[10px] font-mono">{credEvidence.breachDate}</span>
                                  </div>
                                )}
                                {credEvidence.totalRecords != null && (
                                  <div className="flex items-center gap-1.5">
                                    <span className="text-[10px] opacity-50 shrink-0">Records:</span>
                                    <span className="text-[10px] font-mono">{credEvidence.totalRecords.toLocaleString()}</span>
                                  </div>
                                )}
                                {credEvidence.uniqueBreaches != null && (
                                  <div className="flex items-center gap-1.5">
                                    <span className="text-[10px] opacity-50 shrink-0">Breach Sources:</span>
                                    <span className="text-[10px] font-mono">{credEvidence.uniqueBreaches}</span>
                                  </div>
                                )}
                                {credEvidence.emails && credEvidence.emails.length > 0 && (
                                  <div className="flex items-start gap-1.5">
                                    <span className="text-[10px] opacity-50 shrink-0 mt-0.5">Emails:</span>
                                    <div className="flex flex-wrap gap-1">
                                      {credEvidence.emails.slice(0, 5).map((email: string, ei: number) => (
                                        <span key={ei} className="text-[9px] px-1.5 py-0.5 rounded bg-current/5 border border-current/10 font-mono truncate max-w-[180px]">{email}</span>
                                      ))}
                                      {credEvidence.emails.length > 5 && (
                                        <span className="text-[9px] px-1.5 py-0.5 opacity-50">+{credEvidence.emails.length - 5} more</span>
                                      )}
                                    </div>
                                  </div>
                                )}
                                {credEvidence.usernames && credEvidence.usernames.length > 0 && (
                                  <div className="flex items-start gap-1.5">
                                    <span className="text-[10px] opacity-50 shrink-0 mt-0.5">Users:</span>
                                    <div className="flex flex-wrap gap-1">
                                      {credEvidence.usernames.slice(0, 5).map((user: string, ui: number) => (
                                        <span key={ui} className="text-[9px] px-1.5 py-0.5 rounded bg-current/5 border border-current/10 font-mono truncate max-w-[180px]">{user}</span>
                                      ))}
                                      {credEvidence.usernames.length > 5 && (
                                        <span className="text-[9px] px-1.5 py-0.5 opacity-50">+{credEvidence.usernames.length - 5} more</span>
                                      )}
                                    </div>
                                  </div>
                                )}
                                {credEvidence.hashTypes && credEvidence.hashTypes.length > 0 && (
                                  <div className="flex items-center gap-1.5">
                                    <span className="text-[10px] opacity-50 shrink-0">Hash Types:</span>
                                    <div className="flex flex-wrap gap-1">
                                      {credEvidence.hashTypes.map((ht: string, hi: number) => (
                                        <span key={hi} className="text-[9px] px-1.5 py-0.5 rounded bg-current/5 border border-current/10 font-mono uppercase">{ht}</span>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {credEvidence.hasPlaintextPasswords && (
                                  <div className="flex items-center gap-1.5">
                                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/20 border border-red-500/30 text-red-300 font-semibold uppercase">Plaintext Passwords Found</span>
                                  </div>
                                )}
                                {credEvidence.domain && (
                                  <div className="flex items-center gap-1.5">
                                    <span className="text-[10px] opacity-50 shrink-0">Domain:</span>
                                    <span className="text-[10px] font-mono">{credEvidence.domain}</span>
                                  </div>
                                )}
                                {/* Send to Credential Testing button */}
                                {scan.engagementId && (
                                  <div className="mt-2 pt-1.5">
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      className="h-6 text-[10px] px-2 gap-1 border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10 hover:text-cyan-200"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        harvestCredentialsMut.mutate({
                                          engagementId: scan.engagementId!,
                                          domain: scan.primaryDomain,
                                        });
                                      }}
                                      disabled={harvestCredentialsMut.isPending}
                                    >
                                      {harvestCredentialsMut.isPending ? (
                                        <Loader2 className="h-2.5 w-2.5 animate-spin" />
                                      ) : (
                                        <SendHorizontal className="h-2.5 w-2.5" />
                                      )}
                                      Send to Credential Testing
                                    </Button>
                                  </div>
                                )}
                              </div>
                            )}
                            {/* NIST 800-53 Control References */}
                            {typeof signal === 'object' && signal.nistControls && signal.nistControls.length > 0 && (
                              <div className="mt-2 pt-2 border-t border-current/10">
                                <div className="flex items-center gap-1 mb-1">
                                  <BookOpen className="h-2.5 w-2.5 text-indigo-400 opacity-70" />
                                  <span className="text-[9px] font-semibold uppercase tracking-wider text-indigo-400/80">NIST 800-53</span>
                                </div>
                                <TooltipProvider delayDuration={200}>
                                  <div className="flex flex-wrap gap-1">
                                    {signal.nistControls.map((ctrl: any, ci: number) => (
                                      <Tooltip key={ci}>
                                        <TooltipTrigger asChild>
                                          <span className="text-[9px] px-1.5 py-0.5 rounded border border-indigo-500/30 bg-indigo-500/10 text-indigo-300 font-mono cursor-help hover:bg-indigo-500/20 transition-colors">
                                            {ctrl.controlId}
                                          </span>
                                        </TooltipTrigger>
                                        <TooltipContent side="top" className="max-w-xs">
                                          <p className="text-xs font-medium">{ctrl.controlId} — {ctrl.controlName || ctrl.title}</p>
                                          <p className="text-[10px] text-muted-foreground">Family: {ctrl.family}</p>
                                        </TooltipContent>
                                      </Tooltip>
                                    ))}
                                  </div>
                                </TooltipProvider>
                                {signal.fedrampDeadline && (
                                  <div className="flex items-center gap-1 mt-1">
                                    <Clock className="h-2.5 w-2.5 text-amber-400/60" />
                                    <span className="text-[9px] text-amber-400/70">FedRAMP remediation by {new Date(signal.fedrampDeadline).toLocaleDateString()}</span>
                                  </div>
                                )}
                              </div>
                            )}
                            {/* Source + evidence refs */}
                            <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                              {source && <span className="text-[10px] opacity-50">Source: {source}</span>}
                              {signal.evidenceRefs?.length > 0 && (
                                <span className="text-[10px] opacity-40">{signal.evidenceRefs.length} evidence ref{signal.evidenceRefs.length !== 1 ? 's' : ''}</span>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
                {pipeline.passiveRecon.connectorResults && (
                  <div className="mt-3 pt-3 border-t border-zinc-700/50">
                    <p className="text-[10px] text-muted-foreground">
                      Collected from {pipeline.passiveRecon.connectorResults.length} OSINT connector{pipeline.passiveRecon.connectorResults.length !== 1 ? 's' : ''}: {pipeline.passiveRecon.connectorResults.map((c: any) => c.connector).join(', ')}
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Risk Heatmap */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-purple-400" />
                Asset Risk Heatmap
              </CardTitle>
              <CardDescription className="text-xs">Click any asset to see the supporting details behind its risk score</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-5 lg:grid-cols-6 xl:grid-cols-8 gap-1.5">
                {sortedAssets.map((asset: any) => {
                  const band = asset.riskBand || "low";
                  const isHeatmapExpanded = heatmapExpandedAsset === asset.id;
                  return (
                    <div
                      key={asset.id}
                      className={`px-2 py-1.5 rounded-md border cursor-pointer transition-all hover:scale-[1.03] ${RISK_COLORS[band]} ${isHeatmapExpanded ? 'ring-2 ring-purple-500 scale-[1.03]' : ''}`}
                      onClick={() => setHeatmapExpandedAsset(isHeatmapExpanded ? null : asset.id)}
                    >
                      <p className="font-mono text-[10px] truncate leading-tight">{asset.hostname}</p>
                      <div className="flex items-center justify-between mt-0.5">
                        <span className="text-[9px] opacity-60 truncate mr-1">{asset.assetType}</span>
                        <span className="text-xs font-bold shrink-0" title="Hybrid Risk Score">{asset.hybridRiskScore}</span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Expanded Asset Detail Panel */}
              {heatmapExpandedAsset && (() => {
                const _asset = sortedAssets.find((a: any) => a.id === heatmapExpandedAsset);
                if (!_asset) return null;
                const asset = _asset as any;
                const band = asset.riskBand || "low";
                const carver = (asset.carverScores || {}) as Record<string, number>;
                const shock = (asset.shockScores || {}) as Record<string, number>;
                const findings = (asset.postureFindings || []) as any[];
                const vectors = (asset.testVectors || []) as any[];
                const technologies = (asset.technologies || []) as string[];
                const isSubdomainAsset = !!(asset as any)._isSubdomainAsset;
                const confirmedFindings = isSubdomainAsset
                  ? findings.filter((f: any) => f.severity === 'critical' || f.severity === 'high')
                  : findings.filter((f: any) => f.corroborationTier === 'confirmed');
                const probableFindings = isSubdomainAsset
                  ? findings.filter((f: any) => f.severity === 'medium')
                  : findings.filter((f: any) => f.corroborationTier === 'probable');
                const potentialFindings = isSubdomainAsset
                  ? findings.filter((f: any) => f.severity === 'low')
                  : findings.filter((f: any) => f.corroborationTier === 'potential');
                const kevFindings = isSubdomainAsset
                  ? findings.filter((f: any) => f.category === 'vulnerability')
                  : findings.filter((f: any) => f.kevListed);

                return (
                  <div className="border border-purple-500/30 rounded-lg bg-card/80 p-3 space-y-3 animate-in fade-in slide-in-from-top-2 duration-200">
                    {/* Header */}
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className={`w-9 h-9 rounded flex items-center justify-center ${RISK_COLORS[band]}`} title="Hybrid Risk Score">
                          <span className="text-sm font-bold">{asset.hybridRiskScore}</span>
                        </div>
                        <div className="flex flex-col items-center px-1.5 py-0.5 rounded border border-cyan-500/30 bg-cyan-500/5" title="CVSS Estimate">
                          <span className="text-sm font-bold text-cyan-400">{((asset.cvssEstimate || 0) / 10).toFixed(1)}</span>
                          <span className="text-[7px] text-cyan-400/70 uppercase">CVSS</span>
                        </div>
                        <div>
                          <p className="font-mono text-sm font-semibold">{asset.hostname}</p>
                          <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
                            <Badge variant="outline" className="text-[9px] py-0">{asset.assetType}</Badge>
                            <Badge className={`text-[9px] py-0 ${RISK_COLORS[band]}`}>{band}</Badge>
                            {asset.discoveryMethod && (
                              <Badge variant="outline" className={`text-[9px] py-0 ${
                                asset.discoveryMethod === 'inferred' ? 'text-purple-400 border-purple-500/40' :
                                asset.discoveryMethod === 'dns_verified' ? 'text-emerald-400 border-emerald-500/40' :
                                'text-blue-400 border-blue-500/40'
                              }`}>
                                {asset.discoveryMethod === 'inferred' ? 'Inferred' : asset.discoveryMethod === 'dns_verified' ? 'DNS Verified' : asset.discoveryMethod}
                              </Badge>
                            )}
                            {asset.suggestedTier && <Badge variant="outline" className="text-[9px] py-0">{asset.suggestedTier.replace('_', ' ')}</Badge>}
                          </div>
                        </div>
                      </div>
                      <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setHeatmapExpandedAsset(null)}>
                        <ChevronUp className="h-3.5 w-3.5" />
                      </Button>
                    </div>

                    {/* Score Breakdown */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                      {/* Impact Scores */}
                      <div className="space-y-1.5">
                        <p className="text-[10px] font-medium text-muted-foreground flex items-center gap-1 uppercase tracking-wider">
                          <Target className="h-2.5 w-2.5" /> Impact Scores
                        </p>
                        <div className="space-y-1">
                          {Object.entries(carver).map(([k, v]) => (
                            <div key={k} className="flex items-center gap-2">
                              <span className="text-[10px] text-muted-foreground w-20 capitalize">{k}</span>
                              <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                                <div className={`h-full rounded-full ${(v as number) >= 7 ? 'bg-red-500' : (v as number) >= 4 ? 'bg-yellow-500' : 'bg-emerald-500'}`} style={{ width: `${(v as number) * 10}%` }} />
                              </div>
                              <span className="text-[10px] font-mono w-4 text-right">{v as number}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Disruption Scores */}
                      <div className="space-y-1.5">
                        <p className="text-[10px] font-medium text-muted-foreground flex items-center gap-1 uppercase tracking-wider">
                          <Zap className="h-2.5 w-2.5" /> Disruption Scores
                        </p>
                        <div className="space-y-1">
                          {Object.entries(shock).map(([k, v]) => (
                            <div key={k} className="flex items-center gap-2">
                              <span className="text-[10px] text-muted-foreground w-24 capitalize">{k.replace(/([A-Z])/g, ' $1').trim()}</span>
                              <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                                <div className={`h-full rounded-full ${(v as number) >= 7 ? 'bg-red-500' : (v as number) >= 4 ? 'bg-yellow-500' : 'bg-emerald-500'}`} style={{ width: `${(v as number) * 10}%` }} />
                              </div>
                              <span className="text-[10px] font-mono w-4 text-right">{v as number}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Risk Composition */}
                      <div className="space-y-1.5">
                        <p className="text-[10px] font-medium text-muted-foreground flex items-center gap-1 uppercase tracking-wider">
                          <Activity className="h-2.5 w-2.5" /> Risk Composition
                        </p>
                        <div className="space-y-1.5">
                          {/* Impact × Likelihood — the two dimensions that compose the risk score */}
                          <div className="flex justify-between text-[11px]">
                            <span className="text-sky-400 font-medium">Mission Impact</span>
                            <span className={`font-bold ${(asset.impactScore || 0) >= 70 ? 'text-sky-400' : (asset.impactScore || 0) >= 40 ? 'text-sky-300' : 'text-slate-400'}`}>{asset.impactScore || 0}/100</span>
                          </div>
                          <div className="flex justify-between text-[11px]">
                            <span className="text-amber-400 font-medium">Likelihood (CVSS+Exposure)</span>
                            <span className={`font-bold ${(asset.likelihoodScore || 0) >= 70 ? 'text-amber-400' : (asset.likelihoodScore || 0) >= 40 ? 'text-amber-300' : 'text-slate-400'}`}>{asset.likelihoodScore || 0}/100</span>
                          </div>
                          <div className="pt-1.5 border-t border-border/50 space-y-1">
                            <div className="flex justify-between text-[10px]">
                              <span className="text-muted-foreground">Mission Impact</span>
                              <span className="font-bold">{((asset.missionImpactScore || 0) / 10).toFixed(1)}/10</span>
                            </div>
                            <div className="flex justify-between text-[10px]">
                              <span className="text-muted-foreground">Confidence</span>
                              <ConfidenceBadge score={(asset.confidence || 0) / 100} size="xs" />
                            </div>
                            <div className="flex justify-between text-[10px]">
                              <span className="text-muted-foreground">Criticality</span>
                              <span className={`font-bold ${(asset.assetCriticalityBand || 'low') === 'critical' ? 'text-purple-400' : (asset.assetCriticalityBand || 'low') === 'high' ? 'text-blue-400' : (asset.assetCriticalityBand || 'low') === 'medium' ? 'text-cyan-400' : 'text-slate-400'}`}>
                                {asset.assetCriticalityScore || 0} ({(asset.assetCriticalityBand || 'low').toUpperCase()})
                              </span>
                            </div>
                            <div className="flex justify-between text-[10px]">
                              <span className="text-muted-foreground">Vuln Risk</span>
                              <span className={`font-bold ${(asset.vulnRiskBand || 'low') === 'critical' ? 'text-red-400' : (asset.vulnRiskBand || 'low') === 'high' ? 'text-orange-400' : (asset.vulnRiskBand || 'low') === 'medium' ? 'text-yellow-400' : 'text-emerald-400'}`}>
                                {asset.vulnRiskScore || 0} ({(asset.vulnRiskBand || 'low').toUpperCase()})
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Technologies */}
                    {technologies.length > 0 && (
                      <div>
                        <p className="text-[10px] font-medium text-muted-foreground mb-1 flex items-center gap-1 uppercase tracking-wider">
                          <Server className="h-2.5 w-2.5" /> Technologies ({technologies.length})
                        </p>
                        <div className="flex flex-wrap gap-0.5">
                          {technologies.slice(0, 12).map((t: string, i: number) => (
                            <Badge key={i} variant="secondary" className="text-[9px] py-0">{t}</Badge>
                          ))}
                          {technologies.length > 12 && <Badge variant="outline" className="text-[9px] py-0">+{technologies.length - 12}</Badge>}
                        </div>
                      </div>
                    )}

                    {/* Finding Summary */}
                    {findings.length > 0 && (() => {
                      if (isSubdomainAsset) {
                        // Subdomain-specific findings display with category, severity, and remediation
                        const SCAT_COLORS: Record<string, string> = {
                          network_exposure: 'bg-red-500/20 text-red-300 border-red-500/40',
                          vulnerability: 'bg-rose-600/20 text-rose-300 border-rose-500/40',
                          encryption: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
                          technology: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
                          dns_configuration: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
                        };
                        const SSEV_COLORS: Record<string, string> = {
                          critical: 'bg-red-600/30 text-red-300 border-red-500/50',
                          high: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
                          medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
                          low: 'bg-green-500/20 text-green-300 border-green-500/40',
                        };
                        const criticalFindings = findings.filter((f: any) => f.severity === 'critical');
                        const highFindings = findings.filter((f: any) => f.severity === 'high');
                        const mediumFindings = findings.filter((f: any) => f.severity === 'medium');
                        return (
                          <div>
                            <p className="text-xs font-medium text-muted-foreground mb-1.5 flex items-center gap-1">
                              <AlertTriangle className="h-3 w-3" /> Risks & Weaknesses ({findings.length})
                            </p>
                            <div className="flex gap-2 mb-2 flex-wrap">
                              {criticalFindings.length > 0 && <Badge className="text-[10px] bg-red-600/30 text-red-300 border-red-500/50">{criticalFindings.length} Critical</Badge>}
                              {highFindings.length > 0 && <Badge className="text-[10px] bg-orange-500/20 text-orange-300 border-orange-500/40">{highFindings.length} High</Badge>}
                              {mediumFindings.length > 0 && <Badge className="text-[10px] bg-yellow-500/20 text-yellow-300 border-yellow-500/40">{mediumFindings.length} Medium</Badge>}
                            </div>
                            <div className="space-y-1.5 max-h-48 overflow-y-auto">
                              {[...findings].sort((a: any, b: any) => {
                                // Sort by confirmation tier first (confirmed > probable > potential)
                                const tierOrder: Record<string, number> = { confirmed: 3, probable: 2, potential: 1 };
                                const tierA = tierOrder[a.corroborationTier] || 0;
                                const tierB = tierOrder[b.corroborationTier] || 0;
                                if (tierB !== tierA) return tierB - tierA;
                                // Then by severity (critical > high > medium > low)
                                const sevOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
                                return (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0);
                              }).map((f: any, i: number) => (
                                <div key={i} className={`p-2 rounded border text-xs ${f.severity === 'critical' ? 'bg-red-500/5 border-red-500/30' : f.severity === 'high' ? 'bg-orange-500/5 border-orange-500/20' : 'bg-muted/20 border-border'}`}>
                                  <div className="flex items-center gap-1.5 flex-wrap mb-1">
                                    <Badge className={`text-[9px] px-1 py-0 ${SSEV_COLORS[f.severity] || SSEV_COLORS.medium}`}>{(f.severity || 'medium').toUpperCase()}</Badge>
                                    {f.category && <Badge className={`text-[9px] px-1 py-0 ${SCAT_COLORS[f.category] || 'bg-muted text-muted-foreground border-border'}`}>{(f.category || '').replace(/_/g, ' ').toUpperCase()}</Badge>}
                                    {f.corroborationTier && <CorroborationTierBadge tier={f.corroborationTier} size="xs" showTooltip={false} />}
                                  </div>
                                  <p className="font-medium text-foreground/90 mb-1">{f.finding}</p>
                                  {f.remediation && (
                                    <div className="mt-1.5 p-1.5 rounded bg-emerald-500/5 border border-emerald-500/20">
                                      <p className="text-[10px] text-emerald-400"><span className="font-semibold">Remediation:</span> {f.remediation}</p>
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                            {/* Test Vectors for subdomain */}
                            {vectors.length > 0 && (
                              <div className="mt-3">
                                <p className="text-xs font-medium text-muted-foreground mb-1.5 flex items-center gap-1">
                                  <Target className="h-3 w-3" /> Attack Vectors ({vectors.length})
                                </p>
                                <div className="space-y-1">
                                  {vectors.map((v: any, i: number) => (
                                    <div key={i} className="flex items-center gap-2 text-[11px] p-1.5 rounded bg-muted/20 border border-border">
                                      <Badge className={`text-[9px] px-1 py-0 ${v.priority === 'critical' ? 'bg-red-600/30 text-red-300' : v.priority === 'high' ? 'bg-orange-500/20 text-orange-300' : 'bg-yellow-500/20 text-yellow-300'}`}>{v.priority?.toUpperCase()}</Badge>
                                      <span className="font-medium">{v.vector}</span>
                                      {v.technique && <span className="ml-auto font-mono text-[10px] text-cyan-400">{v.technique}</span>}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                            {/* Context Indicators */}
                            {(asset.contextIndicators || []).length > 0 && (
                              <div className="mt-3">
                                <p className="text-xs font-medium text-muted-foreground mb-1 flex items-center gap-1">
                                  <Info className="h-3 w-3" /> Context Indicators
                                </p>
                                <div className="flex gap-1.5 flex-wrap">
                                  {(asset.contextIndicators as string[]).map((c: string, i: number) => (
                                    <Badge key={i} variant="outline" className="text-[10px] text-muted-foreground">{c}</Badge>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      }
                      // Standard LLM-analyzed asset findings display
                      const confirmedOnly = [...confirmedFindings];
                      return (
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-1.5 flex items-center gap-1">
                            <AlertTriangle className="h-3 w-3" /> Confirmed Findings ({confirmedOnly.length})
                          </p>
                          <div className="flex gap-2 mb-2 flex-wrap">
                            {kevFindings.length > 0 && <Badge className="text-[10px] bg-red-600/30 text-red-300 border-red-500/50">{kevFindings.length} KEV-listed</Badge>}
                            {confirmedFindings.length > 0 && <Badge className="text-[10px] bg-emerald-500/20 text-emerald-400 border-emerald-500/40">{confirmedFindings.length} Confirmed</Badge>}
                          </div>
                          {confirmedOnly.length > 0 ? (
                            <div className="space-y-1 max-h-36 overflow-y-auto">
                              {confirmedOnly.slice(0, 5).map((f: any, i: number) => (
                                  <div key={i} className={`p-2 rounded border text-xs ${f.kevListed ? 'bg-red-500/5 border-red-500/30' : 'bg-muted/20 border-border'}`}>
                                    <div className="flex items-center gap-1.5 flex-wrap">
                                      <Badge className="text-[9px] px-1 py-0 text-emerald-400 bg-emerald-500/20 border-emerald-500/40">CONFIRMED</Badge>
                                      {f.kevListed && <Badge className="text-[9px] px-1 py-0 bg-red-600/30 text-red-300 border-red-500/50">KEV</Badge>}
                                      {f.detectedVersion && <Badge className="text-[9px] px-1 py-0 bg-cyan-600/30 text-cyan-300 border-cyan-500/50">Ver: {f.detectedVersion}</Badge>}
                                      {(() => { const t = (f.title || '').toLowerCase(); return (t.includes('remote code') || t.includes('rce') || t.includes('auth bypass') || t.includes('authentication bypass') || t.includes('ssrf') || t.includes('unauthenticated') || t.includes('pre-auth') || t.includes('command injection') || t.includes('sql injection')) ? <Badge className="text-[9px] px-1 py-0 bg-rose-600/30 text-rose-300 border-rose-500/50 animate-pulse">REMOTE ACCESS</Badge> : null; })()}
                                      <span className="font-medium">{f.title}</span>
                                      <span className="text-muted-foreground ml-auto">Sev: {f.severity}/10</span>
                                    </div>
                                    {f.cveIds?.length > 0 && (
                                      <div className="flex gap-1 mt-0.5 flex-wrap">
                                        {f.cveIds.slice(0, 3).map((cve: string) => (
                                          <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer"
                                            className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 underline decoration-dotted">{cve}</a>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                              ))}
                              {confirmedOnly.length > 8 && (
                                <p className="text-[10px] text-muted-foreground text-center pt-1">+ {confirmedOnly.length - 8} more — see Findings tab for full details</p>
                              )}
                            </div>
                          ) : (
                            <p className="text-[10px] text-muted-foreground">No confirmed findings for this asset.</p>
                          )}
                          {/* Probable + Potential collapsed */}
                          {probableFindings.length > 0 && (
                            <Collapsible className="mt-1.5">
                              <CollapsibleTrigger className="flex items-center gap-1 text-[10px] text-yellow-400 hover:text-yellow-300 cursor-pointer">
                                <ChevronDown className="h-2.5 w-2.5" />
                                <span className="underline decoration-dotted">Probable ({probableFindings.length})</span>
                              </CollapsibleTrigger>
                              <CollapsibleContent className="mt-1 space-y-1 max-h-28 overflow-y-auto">
                                {probableFindings.slice(0, 3).map((f: any, i: number) => (
                                  <div key={`prob-${i}`} className="px-2 py-1 rounded border text-[10px] bg-yellow-500/5 border-yellow-500/20 opacity-70 flex items-center gap-1.5">
                                    <Badge className="text-[8px] px-1 py-0 text-yellow-400 bg-yellow-500/20 border-yellow-500/40 shrink-0">PROBABLE</Badge>
                                    <span className="font-medium truncate">{f.title}</span>
                                  </div>
                                ))}
                                {probableFindings.length > 3 && <p className="text-[9px] text-muted-foreground text-center">+{probableFindings.length - 3} more</p>}
                              </CollapsibleContent>
                            </Collapsible>
                          )}
                          {potentialFindings.length > 0 && (
                            <Collapsible className="mt-1">
                              <CollapsibleTrigger className="flex items-center gap-1 text-[10px] text-purple-400 hover:text-purple-300 cursor-pointer">
                                <ChevronDown className="h-2.5 w-2.5" />
                                <span className="underline decoration-dotted">Potential ({potentialFindings.length})</span>
                              </CollapsibleTrigger>
                              <CollapsibleContent className="mt-1 space-y-1 max-h-28 overflow-y-auto">
                                {potentialFindings.slice(0, 3).map((f: any, i: number) => (
                                  <div key={`pot-${i}`} className="px-2 py-1 rounded border text-[10px] bg-purple-500/5 border-purple-500/20 opacity-60 flex items-center gap-1.5">
                                    <Badge className="text-[8px] px-1 py-0 text-purple-400 bg-purple-500/20 border-purple-500/40 shrink-0">POTENTIAL</Badge>
                                    <span className="font-medium text-muted-foreground truncate">{f.title}</span>
                                  </div>
                                ))}
                                {potentialFindings.length > 3 && <p className="text-[9px] text-muted-foreground text-center">+{potentialFindings.length - 3} more</p>}
                              </CollapsibleContent>
                            </Collapsible>
                          )}
                        </div>
                      );
                    })()}

                    {/* Test Vectors Preview */}
                    {vectors.length > 0 && (
                      <div>
                        <p className="text-[10px] font-medium text-muted-foreground mb-1 flex items-center gap-1 uppercase tracking-wider">
                          <Crosshair className="h-2.5 w-2.5" /> Vectors ({vectors.length})
                        </p>
                        <div className="flex flex-wrap gap-0.5">
                          {vectors.slice(0, 4).map((v: any, i: number) => (
                            <Badge key={i} variant="outline" className="text-[9px] py-0">
                              {v.vectorType}
                              {v.suggestedEmulation?.technique && <span className="ml-0.5 text-purple-400">{v.suggestedEmulation.technique}</span>}
                            </Badge>
                          ))}
                          {vectors.length > 4 && <Badge variant="outline" className="text-[9px] py-0">+{vectors.length - 4}</Badge>}
                        </div>
                      </div>
                    )}

                    {/* View Full Details Button */}
                    <div className="flex justify-end pt-1">
                      <Button variant="outline" size="sm" className="text-xs" onClick={() => {
                        setExpandedAsset(asset.id);
                        setActiveTab("assets");
                      }}>
                        <Eye className="h-3 w-3 mr-1" />
                        View Full Asset Details
                      </Button>
                    </div>
                  </div>
                );
              })()}
            </CardContent>
          </Card>


          {/* Entity Information & Hybrid Scoring Context */}
          {(() => {
            const orgP = scan.orgProfile as any;
            const ep = pipeline?.entityProfile as any;
            const entity = ep || orgP;
            if (!entity) return null;

            // BIA distribution from assets
            const biaLevels: Record<string, number> = {};
            const missionFunctions: Record<string, number> = {};
            const essentialServices: Record<string, number> = {};
            (assets || []).forEach((a: any) => {
              const bil = a.businessImpactLevel || 'unknown';
              biaLevels[bil] = (biaLevels[bil] || 0) + 1;
              const mf = a.missionFunction || 'unclassified';
              missionFunctions[mf] = (missionFunctions[mf] || 0) + 1;
              const es = a.essentialService || 'unclassified';
              essentialServices[es] = (essentialServices[es] || 0) + 1;
            });

            const totalAssets = (assets || []).length;
            const biaColors: Record<string, string> = {
              critical: 'bg-red-500/20 text-red-400 border-red-500/40',
              high: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
              moderate: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
              low: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
              unknown: 'bg-zinc-500/20 text-zinc-400 border-zinc-500/40',
            };

            const fmtLabel = (s: string) => s.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
            const fmtCurrency = (v: number) => v >= 1e9 ? `$${(v/1e9).toFixed(1)}B` : v >= 1e6 ? `$${(v/1e6).toFixed(0)}M` : `$${(v/1e3).toFixed(0)}K`;

            return (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Database className="h-4 w-4 text-cyan-400" />
                    Entity Information & Hybrid Scoring Context
                  </CardTitle>
                  <CardDescription className="text-xs">Organization profile, business impact analysis, and key inputs to the hybrid risk scoring engine</CardDescription>
                </CardHeader>
                <CardContent className="space-y-5">
                  {/* Entity Profile Row */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {/* Org Identity */}
                    <div className="space-y-2 p-3 rounded-lg bg-muted/30 border border-border/50">
                      <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Globe className="h-3.5 w-3.5" /> Organization
                      </h4>
                      <div className="space-y-1">
                        <p className="text-sm font-bold">{entity.orgName || entity.customerName || scan.primaryDomain}</p>
                        {(entity.industry || entity.sector) && (
                          <p className="text-xs text-muted-foreground">{entity.industry || entity.sector}{entity.subSector ? ` — ${entity.subSector}` : ''}</p>
                        )}
                        {entity.headquarters && <p className="text-xs text-muted-foreground">HQ: {entity.headquarters}</p>}
                        {entity.companySize && <p className="text-xs text-muted-foreground">Size: {fmtLabel(entity.companySize)}{entity.estimatedEmployees ? ` (~${entity.estimatedEmployees.toLocaleString()} employees)` : ''}</p>}
                        {entity.foundedYear && <p className="text-xs text-muted-foreground">Founded: {entity.foundedYear}</p>}
                        {entity.isPublicCompany && entity.stockTicker && <p className="text-xs text-muted-foreground">Ticker: {entity.stockTicker}</p>}
                      </div>
                    </div>

                    {/* Key Products & Functions */}
                    <div className="space-y-2 p-3 rounded-lg bg-muted/30 border border-border/50">
                      <h4 className="text-xs font-semibold text-purple-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Layers className="h-3.5 w-3.5" /> Key Products & Functions
                      </h4>
                      {entity.keyProducts && entity.keyProducts.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {entity.keyProducts.slice(0, 6).map((p: string, i: number) => (
                            <Badge key={i} variant="outline" className="text-[10px] bg-purple-500/10 border-purple-500/30 text-purple-300">{p}</Badge>
                          ))}
                        </div>
                      ) : entity.criticalFunctions && entity.criticalFunctions.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {entity.criticalFunctions.map((f: string, i: number) => (
                            <Badge key={i} variant="outline" className="text-[10px] bg-purple-500/10 border-purple-500/30 text-purple-300">{fmtLabel(f)}</Badge>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-muted-foreground italic">No products/functions identified</p>
                      )}
                      {entity.complianceFlags && entity.complianceFlags.length > 0 && (
                        <div className="mt-2">
                          <p className="text-[10px] text-muted-foreground mb-1">Compliance Frameworks:</p>
                          <div className="flex flex-wrap gap-1">
                            {entity.complianceFlags.map((c: string, i: number) => (
                              <Badge key={i} variant="outline" className="text-[10px] bg-blue-500/10 border-blue-500/30 text-blue-300">{c}</Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Financial Context */}
                    <div className="space-y-2 p-3 rounded-lg bg-muted/30 border border-border/50">
                      <h4 className="text-xs font-semibold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                        <TrendingUp className="h-3.5 w-3.5" /> Financial & Impact Context
                      </h4>
                      <div className="space-y-1">
                        {entity.estimatedRevenue && <p className="text-xs"><span className="text-muted-foreground">Est. Revenue:</span> <span className="font-semibold">{fmtCurrency(entity.estimatedRevenue)}</span></p>}
                        {entity.estimatedValuation && <p className="text-xs"><span className="text-muted-foreground">Est. Valuation:</span> <span className="font-semibold">{fmtCurrency(entity.estimatedValuation)}</span></p>}
                        {entity.clientType && <p className="text-xs"><span className="text-muted-foreground">Client Type:</span> <span className="font-semibold">{fmtLabel(entity.clientType)}</span></p>}
                        {entity.confidence && <p className="text-xs flex items-center gap-1.5"><span className="text-muted-foreground">Entity Confidence:</span> <ConfidenceBadge score={entity.confidence / 100} size="xs" showScore /></p>}
                      </div>
                      <p className="text-[10px] text-muted-foreground italic mt-1">Financial context informs CARVER Criticality and Shock Effect scoring weights</p>
                    </div>
                  </div>

                  {/* BIA Distribution */}
                  {totalAssets > 0 && (
                    <div className="space-y-3">
                      <h4 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Activity className="h-3.5 w-3.5" /> Business Impact Analysis Distribution
                        <span className="text-muted-foreground font-normal">— {totalAssets} assets classified</span>
                      </h4>
                      <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                        {['critical', 'high', 'moderate', 'low', 'unknown'].map(level => {
                          const count = biaLevels[level] || 0;
                          const pct = totalAssets > 0 ? Math.round((count / totalAssets) * 100) : 0;
                          return (
                            <div key={level} className={`p-2 rounded-lg border ${biaColors[level] || biaColors.unknown}`}>
                              <p className="text-[10px] uppercase font-semibold">{level}</p>
                              <p className="text-lg font-bold">{count}</p>
                              <p className="text-[10px] opacity-70">{pct}% of assets</p>
                            </div>
                          );
                        })}
                      </div>

                      {/* Mission Function Breakdown */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div className="p-3 rounded-lg bg-muted/20 border border-border/30">
                          <p className="text-[10px] font-semibold text-muted-foreground uppercase mb-2">Mission Functions</p>
                          <div className="space-y-1">
                            {Object.entries(missionFunctions).sort(([,a],[,b]) => (b as number) - (a as number)).slice(0, 6).map(([fn, count]) => (
                              <div key={fn} className="flex items-center justify-between text-xs">
                                <span className="text-muted-foreground">{fmtLabel(fn)}</span>
                                <div className="flex items-center gap-2">
                                  <div className="w-20 h-1.5 bg-muted/30 rounded-full overflow-hidden">
                                    <div className="h-full bg-cyan-500/60 rounded-full" style={{ width: `${Math.round(((count as number) / totalAssets) * 100)}%` }} />
                                  </div>
                                  <span className="font-mono text-[10px] w-6 text-right">{count as number}</span>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                        <div className="p-3 rounded-lg bg-muted/20 border border-border/30">
                          <p className="text-[10px] font-semibold text-muted-foreground uppercase mb-2">Essential Services</p>
                          <div className="space-y-1">
                            {Object.entries(essentialServices).sort(([,a],[,b]) => (b as number) - (a as number)).slice(0, 6).map(([svc, count]) => (
                              <div key={svc} className="flex items-center justify-between text-xs">
                                <span className="text-muted-foreground">{fmtLabel(svc)}</span>
                                <div className="flex items-center gap-2">
                                  <div className="w-20 h-1.5 bg-muted/30 rounded-full overflow-hidden">
                                    <div className="h-full bg-purple-500/60 rounded-full" style={{ width: `${Math.round(((count as number) / totalAssets) * 100)}%` }} />
                                  </div>
                                  <span className="font-mono text-[10px] w-6 text-right">{count as number}</span>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Hybrid Scoring Methodology */}
                  <div className="p-3 rounded-lg bg-gradient-to-r from-cyan-500/5 via-purple-500/5 to-amber-500/5 border border-border/30">
                    <h4 className="text-xs font-semibold uppercase tracking-wider flex items-center gap-1.5 mb-2">
                      <Brain className="h-3.5 w-3.5 text-purple-400" /> Hybrid Risk Scoring Components
                    </h4>
                    <p className="text-[10px] text-muted-foreground mb-3">Each asset's risk score is computed from four weighted components, contextualized by the entity profile above:</p>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                      <div className="p-2 rounded bg-red-500/10 border border-red-500/20">
                        <p className="text-[10px] font-bold text-red-400">CARVER (30%)</p>
                        <p className="text-[10px] text-muted-foreground">Criticality, Accessibility, Recuperability, Vulnerability, Effect, Recognizability — military-grade target analysis</p>
                      </div>
                      <div className="p-2 rounded bg-orange-500/10 border border-orange-500/20">
                        <p className="text-[10px] font-bold text-orange-400">Shock 2.0 (25%)</p>
                        <p className="text-[10px] text-muted-foreground">Scope, Handling, Operational Impact, Cascading Effects, Knowledge — psychological & societal disruption</p>
                      </div>
                      <div className="p-2 rounded bg-blue-500/10 border border-blue-500/20">
                        <p className="text-[10px] font-bold text-blue-400">CVSS v4 (25%)</p>
                        <p className="text-[10px] text-muted-foreground">Technical vulnerability severity from posture findings, KEV matches, and CVE correlation</p>
                      </div>
                      <div className="p-2 rounded bg-emerald-500/10 border border-emerald-500/20">
                        <p className="text-[10px] font-bold text-emerald-400">AI-BIA (20%)</p>
                        <p className="text-[10px] text-muted-foreground">Mission function weighting, essential service classification, and business impact level from entity context</p>
                      </div>
                    </div>
                    <p className="text-[10px] text-muted-foreground mt-2 italic">Entity sector ({entity.industry || entity.sector || 'unknown'}), compliance requirements ({(entity.complianceFlags || []).join(', ') || 'none'}), and financial scale ({entity.estimatedRevenue ? fmtCurrency(entity.estimatedRevenue) + ' revenue' : 'unknown'}) directly influence CARVER Criticality and Shock Effect weights.</p>
                  </div>
                </CardContent>
              </Card>
            );
          })()}

          {/* Org Discovery — Related Domains */}
          {(() => {
            const orgDisc = pipeline?.orgDiscovery as any;
            if (!orgDisc) return null;
            const allDomains = [...(orgDisc.verifiedDomains || []), ...(orgDisc.unverifiedDomains || [])];
            if (allDomains.length === 0) return null;

            const missionColors: Record<string, string> = {
              product: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
              service: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40',
              infrastructure: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
              marketing: 'bg-pink-500/20 text-pink-400 border-pink-500/40',
              corporate: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
              unknown: 'bg-zinc-500/20 text-zinc-400 border-zinc-500/40',
            };

            const confidenceColor = (c: number) =>
              c >= 80 ? 'text-emerald-400' : c >= 60 ? 'text-yellow-400' : c >= 40 ? 'text-orange-400' : 'text-red-400';
            const confidenceBar = (c: number) =>
              c >= 80 ? 'bg-emerald-500' : c >= 60 ? 'bg-yellow-500' : c >= 40 ? 'bg-orange-500' : 'bg-red-500';

            return (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Network className="h-4 w-4 text-purple-400" />
                    Org Domain Discovery
                    <Badge variant="outline" className="text-[10px] ml-auto">{allDomains.length} domains</Badge>
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Related domains discovered via WHOIS, certificate transparency, DNS infrastructure pivoting, and SPF record analysis for <span className="font-mono text-foreground">{orgDisc.orgName || orgDisc.seedDomain}</span>
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Discovery Stats Summary */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div className="p-2.5 rounded-lg bg-muted/30 border border-border/50 text-center">
                      <p className="text-lg font-bold text-purple-400">{orgDisc.totalCandidatesFound || 0}</p>
                      <p className="text-[10px] text-muted-foreground">Candidates Found</p>
                    </div>
                    <div className="p-2.5 rounded-lg bg-muted/30 border border-border/50 text-center">
                      <p className="text-lg font-bold text-emerald-400">{(orgDisc.verifiedDomains || []).length}</p>
                      <p className="text-[10px] text-muted-foreground">Verified Owned</p>
                    </div>
                    <div className="p-2.5 rounded-lg bg-muted/30 border border-border/50 text-center">
                      <p className="text-lg font-bold text-amber-400">{(orgDisc.unverifiedDomains || []).length}</p>
                      <p className="text-[10px] text-muted-foreground">Unverified</p>
                    </div>
                    <div className="p-2.5 rounded-lg bg-muted/30 border border-border/50 text-center">
                      <p className="text-lg font-bold text-cyan-400">{orgDisc.durationMs ? `${(orgDisc.durationMs / 1000).toFixed(1)}s` : '—'}</p>
                      <p className="text-[10px] text-muted-foreground">Discovery Time</p>
                    </div>
                  </div>

                  {/* Discovery Source Stats */}
                  {orgDisc.discoveryStats && orgDisc.discoveryStats.length > 0 && (
                    <div className="p-3 rounded-lg bg-muted/20 border border-border/30">
                      <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-2">Discovery Sources</p>
                      <div className="flex flex-wrap gap-2">
                        {orgDisc.discoveryStats.map((stat: any, idx: number) => (
                          <Badge key={idx} variant="outline" className={`text-[10px] ${
                            stat.status === 'success' ? 'text-emerald-400 border-emerald-500/40' :
                            stat.status === 'failed' ? 'text-red-400 border-red-500/40' :
                            'text-zinc-400 border-zinc-500/40'
                          }`}>
                            {stat.source}: {stat.domainsFound} found
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Verified Domains */}
                  {(orgDisc.verifiedDomains || []).length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-emerald-400 mb-2 flex items-center gap-1.5">
                        <CheckCircle2 className="h-3.5 w-3.5" /> Verified Domains ({(orgDisc.verifiedDomains || []).length})
                      </p>
                      <div className="space-y-1.5 max-h-64 overflow-y-auto">
                        {(orgDisc.verifiedDomains || []).map((d: any, idx: number) => (
                          <div key={idx} className="p-2.5 rounded-lg border border-emerald-500/20 bg-emerald-500/5">
                            <div className="flex items-center justify-between gap-2">
                              <div className="flex items-center gap-2 min-w-0">
                                <Globe className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                                <span className="font-mono text-sm font-medium truncate">{d.domain}</span>
                                <Badge className={`text-[9px] px-1.5 py-0 ${missionColors[d.missionRelevance] || missionColors.unknown}`}>
                                  {(d.missionRelevance || 'unknown').toUpperCase()}
                                </Badge>
                              </div>
                              <div className="flex items-center gap-2 shrink-0">
                                <div className="flex items-center gap-1">
                                  <div className="w-16 h-1.5 rounded-full bg-muted/50 overflow-hidden">
                                    <div className={`h-full rounded-full ${confidenceBar(d.ownershipConfidence)}`} style={{ width: `${d.ownershipConfidence}%` }} />
                                  </div>
                                  <span className={`text-[10px] font-mono font-bold ${confidenceColor(d.ownershipConfidence)}`}>{d.ownershipConfidence}%</span>
                                </div>
                              </div>
                            </div>
                            {d.ownershipSignals && d.ownershipSignals.length > 0 && (
                              <div className="flex gap-1 mt-1.5 flex-wrap">
                                {d.ownershipSignals.slice(0, 4).map((sig: any, si: number) => (
                                  <Badge key={si} variant="outline" className="text-[9px] text-muted-foreground">
                                    {sig.type.replace(/_/g, ' ')}: {sig.value?.substring(0, 30)}
                                  </Badge>
                                ))}
                              </div>
                            )}
                            {d.discoverySource && d.discoverySource.length > 0 && (
                              <div className="flex gap-1 mt-1 flex-wrap">
                                {d.discoverySource.map((src: string, si: number) => (
                                  <span key={si} className="text-[9px] text-muted-foreground/60 bg-muted/30 px-1.5 py-0.5 rounded">{src}</span>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Unverified Domains */}
                  {(orgDisc.unverifiedDomains || []).length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-amber-400 mb-2 flex items-center gap-1.5">
                        <ShieldQuestion className="h-3.5 w-3.5" /> Unverified Domains ({(orgDisc.unverifiedDomains || []).length})
                      </p>
                      <div className="space-y-1.5 max-h-48 overflow-y-auto">
                        {(orgDisc.unverifiedDomains || []).map((d: any, idx: number) => (
                          <div key={idx} className="p-2 rounded-lg border border-amber-500/15 bg-amber-500/5">
                            <div className="flex items-center justify-between gap-2">
                              <div className="flex items-center gap-2 min-w-0">
                                <Globe className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                                <span className="font-mono text-xs truncate">{d.domain}</span>
                                <Badge className={`text-[9px] px-1.5 py-0 ${missionColors[d.missionRelevance] || missionColors.unknown}`}>
                                  {(d.missionRelevance || 'unknown').toUpperCase()}
                                </Badge>
                              </div>
                              <div className="flex items-center gap-1 shrink-0">
                                <div className="w-12 h-1.5 rounded-full bg-muted/50 overflow-hidden">
                                  <div className={`h-full rounded-full ${confidenceBar(d.ownershipConfidence)}`} style={{ width: `${d.ownershipConfidence}%` }} />
                                </div>
                                <span className={`text-[10px] font-mono ${confidenceColor(d.ownershipConfidence)}`}>{d.ownershipConfidence}%</span>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <p className="text-[10px] text-muted-foreground italic">
                    Ownership confidence is calculated from WHOIS registrant match, SSL certificate org field, shared DNS infrastructure, ASN correlation, and web content branding signals.
                  </p>
                </CardContent>
              </Card>
            );
          })()}

          {/* Container Infrastructure Exposure */}
          {(() => {
            const containerData = pipeline?.containerExposure as any;
            if (!containerData || containerData.totalHits === 0) return null;
            const sevColors: Record<string, string> = {
              critical: 'bg-red-500/20 text-red-400 border-red-500/40',
              high: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
              medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
              low: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
            };
            const catIcons: Record<string, string> = {
              registry: '📦', orchestrator: '☸️', dashboard: '🖥️', runtime: '⚙️', storage: '💾',
            };
            return (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Box className="h-4 w-4 text-orange-400" />
                    Container Infrastructure Exposure
                    <Badge variant="outline" className="text-[10px] ml-auto text-red-400 border-red-500/40">
                      {containerData.totalHits} exposed
                    </Badge>
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Exposed container registries, orchestrators, dashboards, and runtime APIs detected during external reconnaissance
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div className="p-2.5 rounded-lg bg-muted/30 border border-border/50 text-center">
                      <p className="text-lg font-bold text-orange-400">{containerData.totalProbes}</p>
                      <p className="text-[10px] text-muted-foreground">Endpoints Probed</p>
                    </div>
                    <div className="p-2.5 rounded-lg bg-muted/30 border border-border/50 text-center">
                      <p className="text-lg font-bold text-red-400">{containerData.totalHits}</p>
                      <p className="text-[10px] text-muted-foreground">Services Exposed</p>
                    </div>
                    <div className="p-2.5 rounded-lg bg-muted/30 border border-border/50 text-center">
                      <p className="text-lg font-bold text-red-500">{containerData.criticalFindings}</p>
                      <p className="text-[10px] text-muted-foreground">Critical</p>
                    </div>
                    <div className="p-2.5 rounded-lg bg-muted/30 border border-border/50 text-center">
                      <p className="text-lg font-bold text-orange-500">{containerData.highFindings}</p>
                      <p className="text-[10px] text-muted-foreground">High</p>
                    </div>
                  </div>
                  <div className="space-y-2 max-h-72 overflow-y-auto">
                    {(containerData.findings || []).map((f: any, idx: number) => (
                      <div key={idx} className="p-3 rounded-lg border border-border/40 bg-muted/10">
                        <div className="flex items-center justify-between gap-2 mb-1.5">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="text-base">{catIcons[f.category] || '📡'}</span>
                            <span className="text-sm font-medium truncate">{f.service}</span>
                            <Badge className={`text-[9px] px-1.5 py-0 ${sevColors[f.severity] || sevColors.medium}`}>
                              {(f.severity || '').toUpperCase()}
                            </Badge>
                            {f.authenticated && (
                              <Badge className="text-[9px] px-1.5 py-0 bg-red-600/30 text-red-300 border-red-500/50">UNAUTHENTICATED</Badge>
                            )}
                          </div>
                          <span className="text-[10px] font-mono text-muted-foreground shrink-0">:{f.port}{f.path}</span>
                        </div>
                        <p className="text-[11px] text-muted-foreground leading-relaxed">{f.riskDescription}</p>
                        {f.version && <p className="text-[10px] text-cyan-400 mt-1">Version: {f.version}</p>}
                        {f.cveRefs && f.cveRefs.length > 0 && (
                          <div className="flex gap-1 mt-1.5 flex-wrap">
                            {f.cveRefs.map((cve: string, ci: number) => (
                              <Badge key={ci} variant="outline" className="text-[9px] text-red-400 border-red-500/30">{cve}</Badge>
                            ))}
                          </div>
                        )}
                        {f.mitreTechniques && f.mitreTechniques.length > 0 && (
                          <div className="flex gap-1 mt-1 flex-wrap">
                            {f.mitreTechniques.map((t: string, ti: number) => (
                              <span key={ti} className="text-[9px] text-muted-foreground/60 bg-muted/30 px-1.5 py-0.5 rounded">{t}</span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                  <p className="text-[10px] text-muted-foreground italic">
                    Probed {containerData.subdomainsProbed?.length || 0} hostnames including registry.*, k8s.*, docker.*, and container-related subdomains in {((containerData.durationMs || 0) / 1000).toFixed(1)}s.
                  </p>
                </CardContent>
              </Card>
            );
          })()}

          {/* SCAP/STIG Compliance Scan */}
          {(() => {
            const compliance = pipeline?.complianceScan as any;
            if (!compliance) return null;
            const scoreColor = compliance.complianceScore >= 80 ? 'text-emerald-400' : compliance.complianceScore >= 60 ? 'text-yellow-400' : compliance.complianceScore >= 40 ? 'text-orange-400' : 'text-red-400';
            const scoreBar = compliance.complianceScore >= 80 ? 'bg-emerald-500' : compliance.complianceScore >= 60 ? 'bg-yellow-500' : compliance.complianceScore >= 40 ? 'bg-orange-500' : 'bg-red-500';
            const statusColors: Record<string, string> = {
              fail: 'bg-red-500/20 text-red-400',
              pass: 'bg-emerald-500/20 text-emerald-400',
              manual_review: 'bg-yellow-500/20 text-yellow-400',
              not_applicable: 'bg-zinc-500/20 text-zinc-400',
              error: 'bg-orange-500/20 text-orange-400',
            };
            const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
            const failedChecks = (compliance.checks || []).filter((c: any) => c.status === 'fail').sort((a: any, b: any) => (sevOrder[a.severity] || 5) - (sevOrder[b.severity] || 5));
            return (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <ClipboardCheck className="h-4 w-4 text-cyan-400" />
                    SCAP/STIG Compliance
                    <Badge variant="outline" className={`text-[10px] ml-auto ${scoreColor}`}>
                      {compliance.complianceScore}% compliant
                    </Badge>
                  </CardTitle>
                  <CardDescription className="text-xs">
                    External configuration compliance checks against {compliance.benchmarkProfile || 'security baselines'} for <span className="font-mono text-foreground">{compliance.target}</span>
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Compliance Score Bar */}
                  <div className="space-y-1.5">
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-muted-foreground">Overall Compliance</span>
                      <span className={`text-sm font-bold ${scoreColor}`}>{compliance.complianceScore}%</span>
                    </div>
                    <div className="w-full h-2.5 rounded-full bg-muted/50 overflow-hidden">
                      <div className={`h-full rounded-full ${scoreBar} transition-all`} style={{ width: `${compliance.complianceScore}%` }} />
                    </div>
                  </div>
                  {/* Stats Grid */}
                  <div className="grid grid-cols-3 sm:grid-cols-5 gap-2">
                    <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-center">
                      <p className="text-lg font-bold text-emerald-400">{compliance.passed}</p>
                      <p className="text-[10px] text-muted-foreground">Passed</p>
                    </div>
                    <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20 text-center">
                      <p className="text-lg font-bold text-red-400">{compliance.failed}</p>
                      <p className="text-[10px] text-muted-foreground">Failed</p>
                    </div>
                    <div className="p-2 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-center">
                      <p className="text-lg font-bold text-yellow-400">{compliance.manualReview}</p>
                      <p className="text-[10px] text-muted-foreground">Manual Review</p>
                    </div>
                    <div className="p-2 rounded-lg bg-zinc-500/10 border border-zinc-500/20 text-center">
                      <p className="text-lg font-bold text-zinc-400">{compliance.notApplicable}</p>
                      <p className="text-[10px] text-muted-foreground">N/A</p>
                    </div>
                    <div className="p-2 rounded-lg bg-muted/30 border border-border/50 text-center">
                      <p className="text-lg font-bold text-cyan-400">{compliance.totalChecks}</p>
                      <p className="text-[10px] text-muted-foreground">Total Checks</p>
                    </div>
                  </div>
                  {/* Failed Checks */}
                  {failedChecks.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-red-400 mb-2 flex items-center gap-1.5">
                        <XCircle className="h-3.5 w-3.5" /> Failed Checks ({failedChecks.length})
                      </p>
                      <div className="space-y-1.5 max-h-64 overflow-y-auto">
                        {failedChecks.map((check: any, idx: number) => (
                          <div key={idx} className="p-2.5 rounded-lg border border-red-500/15 bg-red-500/5">
                            <div className="flex items-center gap-2 mb-1">
                              <Badge className={`text-[9px] px-1.5 py-0 ${
                                check.severity === 'critical' ? 'bg-red-600/30 text-red-300' :
                                check.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                                'bg-yellow-500/20 text-yellow-400'
                              }`}>{(check.severity || '').toUpperCase()}</Badge>
                              <span className="text-xs font-medium truncate">{check.title}</span>
                              <span className="text-[9px] font-mono text-muted-foreground ml-auto shrink-0">{check.checkId}</span>
                            </div>
                            <p className="text-[11px] text-muted-foreground">{check.evidence}</p>
                            <p className="text-[10px] text-cyan-400/80 mt-1">Fix: {check.remediation}</p>
                            {check.nistControls && check.nistControls.length > 0 && (
                              <div className="flex gap-1 mt-1 flex-wrap">
                                {check.nistControls.map((ctrl: string, ci: number) => (
                                  <span key={ci} className="text-[9px] text-muted-foreground/60 bg-muted/30 px-1.5 py-0.5 rounded">{ctrl}</span>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  <p className="text-[10px] text-muted-foreground italic">
                    {compliance.scanType === 'external' ? 'External' : 'Authenticated'} compliance scan completed in {((compliance.durationMs || 0) / 1000).toFixed(1)}s using {compliance.benchmarkProfile}.
                  </p>
                </CardContent>
              </Card>
            );
          })()}

          {/* WAF/NGFW Detection */}
          {(() => {
            const waf = pipeline?.wafNgfwAssessment as any;
            if (!waf) return null;
            const wafDetected = waf.wafDetected || [];
            const ngfwDetected = waf.ngfwDetected || [];
            const totalDetected = wafDetected.length + ngfwDetected.length;
            if (totalDetected === 0 && !waf.scanTuning) return null;
            const confColors: Record<string, string> = {
              high: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
              medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
              low: 'bg-zinc-500/20 text-zinc-400 border-zinc-500/40',
            };
            return (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-amber-400" />
                    WAF / NGFW Detection
                    <Badge variant="outline" className={`text-[10px] ml-auto ${totalDetected > 0 ? 'text-amber-400 border-amber-500/40' : 'text-emerald-400 border-emerald-500/40'}`}>
                      {totalDetected > 0 ? `${totalDetected} detected` : 'None detected'}
                    </Badge>
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Web Application Firewall and Next-Generation Firewall detection for scan tuning and evasion planning
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Detection Summary */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div className="p-2.5 rounded-lg bg-muted/30 border border-border/50 text-center">
                      <p className="text-lg font-bold text-amber-400">{wafDetected.length}</p>
                      <p className="text-[10px] text-muted-foreground">WAFs Detected</p>
                    </div>
                    <div className="p-2.5 rounded-lg bg-muted/30 border border-border/50 text-center">
                      <p className="text-lg font-bold text-orange-400">{ngfwDetected.length}</p>
                      <p className="text-[10px] text-muted-foreground">NGFWs Detected</p>
                    </div>
                    <div className="p-2.5 rounded-lg bg-muted/30 border border-border/50 text-center">
                      <p className="text-lg font-bold text-cyan-400">{waf.probesRun || 0}</p>
                      <p className="text-[10px] text-muted-foreground">Probes Run</p>
                    </div>
                    <div className="p-2.5 rounded-lg bg-muted/30 border border-border/50 text-center">
                      <p className="text-lg font-bold text-purple-400">{((waf.durationMs || 0) / 1000).toFixed(1)}s</p>
                      <p className="text-[10px] text-muted-foreground">Scan Time</p>
                    </div>
                  </div>

                  {/* WAF Detections */}
                  {wafDetected.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-amber-400 mb-2 flex items-center gap-1.5">
                        <Shield className="h-3.5 w-3.5" /> WAF Detections
                      </p>
                      <div className="space-y-2">
                        {wafDetected.map((w: any, idx: number) => (
                          <div key={idx} className="p-3 rounded-lg border border-amber-500/20 bg-amber-500/5">
                            <div className="flex items-center justify-between gap-2 mb-1.5">
                              <span className="text-sm font-medium">{w.vendor || w.name}</span>
                              <ConfidenceBadge level={w.confidence || 'moderate'} size="xs" />
                            </div>
                            {w.evidence && w.evidence.length > 0 && (
                              <div className="flex gap-1 flex-wrap mt-1">
                                {w.evidence.slice(0, 5).map((e: string, ei: number) => (
                                  <span key={ei} className="text-[9px] text-muted-foreground bg-muted/30 px-1.5 py-0.5 rounded">{e}</span>
                                ))}
                              </div>
                            )}
                            {w.bypassDifficulty && (
                              <p className="text-[10px] text-muted-foreground mt-1">Bypass difficulty: <span className="text-foreground">{w.bypassDifficulty}</span></p>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* NGFW Detections */}
                  {ngfwDetected.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-orange-400 mb-2 flex items-center gap-1.5">
                        <Wifi className="h-3.5 w-3.5" /> NGFW Detections
                      </p>
                      <div className="space-y-2">
                        {ngfwDetected.map((n: any, idx: number) => (
                          <div key={idx} className="p-3 rounded-lg border border-orange-500/20 bg-orange-500/5">
                            <div className="flex items-center justify-between gap-2 mb-1.5">
                              <span className="text-sm font-medium">{n.vendor || n.name}</span>
                              <ConfidenceBadge level={n.confidence || 'moderate'} size="xs" />
                            </div>
                            {n.evidence && n.evidence.length > 0 && (
                              <div className="flex gap-1 flex-wrap mt-1">
                                {n.evidence.slice(0, 5).map((e: string, ei: number) => (
                                  <span key={ei} className="text-[9px] text-muted-foreground bg-muted/30 px-1.5 py-0.5 rounded">{e}</span>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Scan Tuning Recommendations */}
                  {waf.scanTuning && (
                    <div>
                      <p className="text-xs font-medium text-cyan-400 mb-2 flex items-center gap-1.5">
                        <Settings2 className="h-3.5 w-3.5" /> Scan Tuning Recommendations
                      </p>
                      <div className="p-3 rounded-lg border border-cyan-500/20 bg-cyan-500/5 space-y-2">
                        {waf.scanTuning.nmapFlags && (
                          <div>
                            <p className="text-[10px] text-muted-foreground">Scanner Flags (naabu/Nerva)</p>
                            <p className="text-xs font-mono text-cyan-400">{waf.scanTuning.nmapFlags}</p>
                          </div>
                        )}
                        {waf.scanTuning.nucleiFlags && (
                          <div>
                            <p className="text-[10px] text-muted-foreground">Nuclei Flags</p>
                            <p className="text-xs font-mono text-cyan-400">{waf.scanTuning.nucleiFlags}</p>
                          </div>
                        )}
                        {waf.scanTuning.zapSettings && (
                          <div>
                            <p className="text-[10px] text-muted-foreground">ZAP Settings</p>
                            <p className="text-xs font-mono text-cyan-400">{typeof waf.scanTuning.zapSettings === 'string' ? waf.scanTuning.zapSettings : JSON.stringify(waf.scanTuning.zapSettings)}</p>
                          </div>
                        )}
                        {waf.scanTuning.recommendations && waf.scanTuning.recommendations.length > 0 && (
                          <div className="space-y-1 mt-2">
                            {waf.scanTuning.recommendations.map((rec: string, ri: number) => (
                              <p key={ri} className="text-[11px] text-muted-foreground flex items-start gap-1.5">
                                <Lightbulb className="h-3 w-3 text-yellow-400 shrink-0 mt-0.5" />
                                {rec}
                              </p>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  <p className="text-[10px] text-muted-foreground italic">
                    WAF/NGFW detection completed in {((waf.durationMs || 0) / 1000).toFixed(1)}s. Scan tuning recommendations are based on detected security appliances.
                  </p>
                </CardContent>
              </Card>
            );
          })()}


          {/* Top Campaigns Preview */}
          {campaigns.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <Crosshair className="h-4 w-4 text-purple-400" />
                  Recommended Campaigns
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {campaigns.slice(0, 4).map((c: any) => (
                    <div key={c.id} className="p-3 rounded-lg border border-border bg-muted/30">
                      <div className="flex items-center justify-between mb-2">
                        <p className="font-semibold text-sm">{c.name}</p>
                        <Badge className={RISK_COLORS[c.priority] || RISK_COLORS.medium}>{c.priority}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground line-clamp-2">{c.description}</p>
                      <div className="flex gap-1 mt-2 flex-wrap">
                        <Badge variant="outline" className="text-[10px]">{c.type}</Badge>
                        {(c.mitreTactics || []).slice(0, 3).map((t: string) => (
                          <Badge key={t} variant="secondary" className="text-[10px]">{t}</Badge>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Assets Tab */}
        <TabsContent value="assets" className="space-y-3">
          {sortedAssets.map((asset: any) => {
            const isExpanded = expandedAsset === asset.id;
            const band = asset.riskBand || "low";
            const carver = (asset.carverScores || {}) as Record<string, number>;
            const shock = (asset.shockScores || {}) as Record<string, number>;
            const findings = (asset.postureFindings || []) as any[];
            const vectors = (asset.testVectors || []) as any[];

            return (
              <Card key={asset.id} className={`transition-all ${isExpanded ? "ring-1 ring-purple-500/40" : ""}`}>
                <div
                  className="p-4 cursor-pointer flex items-center gap-4"
                  onClick={() => setExpandedAsset(isExpanded ? null : asset.id)}
                >
                  <div className="flex items-center gap-1.5 shrink-0">
                    <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${RISK_COLORS[band]}`} title="AC3 Hybrid Risk Score">
                      <span className="text-sm font-bold">{asset.hybridRiskScore}</span>
                    </div>
                    <div className="flex flex-col items-center w-8" title="CVSS Estimate (0-10)">
                      <span className="text-xs font-bold text-cyan-400">{((asset.cvssEstimate || 0) / 10).toFixed(1)}</span>
                      <span className="text-[7px] text-cyan-400/60">CVSS</span>
                    </div>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="font-mono font-semibold text-sm truncate">{asset.hostname}</p>
                      <Badge variant="outline" className="text-[10px] shrink-0">{asset.assetType}</Badge>
                      {asset.discoveryMethod && (
                        <Badge variant="outline" className={`text-[10px] shrink-0 ${
                          asset.discoveryMethod === "inferred" ? "text-purple-400 border-purple-500/40" :
                          asset.discoveryMethod === "dns_verified" ? "text-emerald-400 border-emerald-500/40" :
                          "text-blue-400 border-blue-500/40"
                        }`}>
                          {asset.discoveryMethod === "inferred" ? "Inferred" : asset.discoveryMethod === "dns_verified" ? "DNS Verified" : asset.discoveryMethod}
                        </Badge>
                      )}
                    </div>
                    {/* Inline IP + Technologies + Ports */}
                    <div className="flex gap-1.5 mt-1 flex-wrap items-center">
                      {(() => {
                        const dns = (asset.dnsRecords || {}) as Record<string, any>;
                        let ip = '';
                        if (dns.A && Array.isArray(dns.A) && dns.A.length > 0) {
                          ip = typeof dns.A[0] === 'string' ? dns.A[0] : dns.A[0]?.address || '';
                        }
                        return ip ? <Badge variant="outline" className="text-[10px] font-mono text-emerald-400 border-emerald-500/30">{ip}</Badge> : null;
                      })()}
                      {((asset.technologies || []) as string[]).slice(0, 3).map((t: string) => (
                        <Badge key={t} variant="secondary" className="text-[10px]">{t}</Badge>
                      ))}
                      {((asset.technologies || []) as string[]).length > 3 && (
                        <Badge variant="secondary" className="text-[10px]">+{((asset.technologies || []) as string[]).length - 3} tech</Badge>
                      )}
                      {(() => {
                        const assetPorts = (pipeline?.discoveredPorts || []).filter((p: any) => {
                          const hostname = asset.hostname?.toLowerCase();
                          const dns = (asset.dnsRecords || {}) as Record<string, any>;
                          let ip = '';
                          if (dns.A && Array.isArray(dns.A) && dns.A.length > 0) {
                            ip = typeof dns.A[0] === 'string' ? dns.A[0] : dns.A[0]?.address || '';
                          }
                          return p.hostname?.toLowerCase() === hostname || (ip && p.ip === ip);
                        });
                        if (assetPorts.length === 0) return null;
                        return <Badge variant="outline" className="text-[10px] text-sky-400 border-sky-500/30"><Network className="h-2.5 w-2.5 mr-0.5 inline" />{assetPorts.length} port{assetPorts.length !== 1 ? 's' : ''}</Badge>;
                      })()}
                      {/* Credential indicator badge */}
                      {(() => {
                        const hostname = asset.hostname?.toLowerCase() || '';
                        const dns = (asset.dnsRecords || {}) as Record<string, any>;
                        let ip = '';
                        if (dns.A && Array.isArray(dns.A) && dns.A.length > 0) {
                          ip = typeof dns.A[0] === 'string' ? dns.A[0] : dns.A[0]?.address || '';
                        }
                        // Check credential test results
                        const confirmedCreds = credentialTestSummary?.results?.filter((r: any) =>
                          r.status === 'confirmed' && (r.host === hostname || r.host === ip)
                        ) || [];
                        // Check OEM matches
                        const matchedOem = oemCredentials?.filter((c: any) => {
                          const techs = ((asset.technologies || []) as string[]).map((t: string) => t.toLowerCase());
                          return techs.some((t: string) => 
                            t.includes(c.vendor?.toLowerCase() || '') || 
                            t.includes(c.product?.toLowerCase() || '')
                          );
                        }) || [];
                        if (confirmedCreds.length > 0) {
                          return (
                            <Badge variant="destructive" className="text-[10px] gap-0.5" title={`${confirmedCreds.length} confirmed default credential(s): ${confirmedCreds.map((c: any) => c.username).join(', ')}`}>
                              <KeyRound className="h-2.5 w-2.5" /> {confirmedCreds.length} cred{confirmedCreds.length !== 1 ? 's' : ''} confirmed
                            </Badge>
                          );
                        }
                        if (matchedOem.length > 0) {
                          return (
                            <Badge variant="outline" className="text-[10px] text-amber-400 border-amber-500/30 gap-0.5" title={`${matchedOem.length} OEM default credential(s) matched: ${matchedOem.slice(0,3).map((c: any) => `${c.vendor} ${c.username}`).join(', ')}${matchedOem.length > 3 ? '...' : ''}`}>
                              <KeyRound className="h-2.5 w-2.5" /> {matchedOem.length} default cred{matchedOem.length !== 1 ? 's' : ''}
                            </Badge>
                          );
                        }
                        return null;
                      })()}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <Badge className={`${RISK_COLORS[band]} text-xs`}>{band}</Badge>
                    <Badge variant="outline" className={`text-[10px] ${(asset.impactScore || 0) >= 70 ? 'text-sky-400 border-sky-500/40' : (asset.impactScore || 0) >= 40 ? 'text-sky-300 border-sky-500/30' : 'text-slate-400 border-slate-500/40'}`}>IMP: {asset.impactScore || 0}</Badge>
                    <Badge variant="outline" className={`text-[10px] ${(asset.likelihoodScore || 0) >= 70 ? 'text-amber-400 border-amber-500/40' : (asset.likelihoodScore || 0) >= 40 ? 'text-amber-300 border-amber-500/30' : 'text-slate-400 border-slate-500/40'}`}>LKH: {asset.likelihoodScore || 0}</Badge>
                    <Badge variant="outline" className={`text-[10px] ${
                      (asset.assetCriticalityBand || 'low') === 'critical' ? 'text-purple-400 border-purple-500/40' :
                      (asset.assetCriticalityBand || 'low') === 'high' ? 'text-blue-400 border-blue-500/40' :
                      'text-slate-400 border-slate-500/40'
                    }`}>CRIT: {asset.assetCriticalityScore || 0}</Badge>
                    <Badge variant="outline" className={`text-[10px] ${
                      (asset.vulnRiskBand || 'low') === 'critical' ? 'text-red-400 border-red-500/40' :
                      (asset.vulnRiskBand || 'low') === 'high' ? 'text-orange-400 border-orange-500/40' :
                      (asset.vulnRiskBand || 'low') === 'medium' ? 'text-yellow-400 border-yellow-500/40' :
                      'text-emerald-400 border-emerald-500/40'
                    }`}>VULN: {asset.vulnRiskScore || 0}</Badge>
                    {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </div>
                </div>

                {isExpanded && (
                  <CardContent className="pt-0 pb-4 space-y-4 border-t border-border">
                    {/* Impact + Disruption Scores */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-2">Impact Scores</p>
                        <div className="flex items-center gap-4">
                          <CarverRadar scores={carver} />
                          <div className="space-y-1.5 flex-1">
                            {Object.entries(carver).map(([k, v]) => (
                              <div key={k} className="flex items-center gap-2">
                                <span className="text-[10px] text-muted-foreground w-20 capitalize">{k}</span>
                                <Progress value={(v as number) * 10} className="h-1.5 flex-1" />
                                <span className="text-xs font-mono w-6 text-right">{v as number}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-2">Disruption Scores</p>
                        <div className="space-y-1.5">
                          {Object.entries(shock).map(([k, v]) => (
                            <div key={k} className="flex items-center gap-2">
                              <span className="text-[10px] text-muted-foreground w-28 capitalize">{k.replace(/([A-Z])/g, " $1").trim()}</span>
                              <Progress value={(v as number) * 10} className="h-1.5 flex-1" />
                              <span className="text-xs font-mono w-6 text-right">{v as number}</span>
                            </div>
                          ))}
                        </div>
                        <div className="mt-3 space-y-2">
                          <div className="flex gap-3 items-start">
                            <div className="rounded-md border border-cyan-500/30 bg-cyan-500/5 px-3 py-1.5 text-center" title="CVSS Estimate — Industry-standard vulnerability severity">
                              <span className="text-base font-bold text-cyan-400">{((asset.cvssEstimate || 0) / 10).toFixed(1)}</span>
                              <span className="text-[9px] text-cyan-400/70">/10</span>
                              <p className="text-[8px] text-cyan-400/60">CVSS</p>
                            </div>
                            <div className={`rounded-md border px-3 py-1.5 text-center ${band === 'critical' ? 'border-red-500/30 bg-red-500/5' : band === 'high' ? 'border-orange-500/30 bg-orange-500/5' : band === 'medium' ? 'border-yellow-500/30 bg-yellow-500/5' : 'border-emerald-500/30 bg-emerald-500/5'}`} title="AC3 Hybrid Risk Score — Proprietary score">
                              <span className={`text-base font-bold ${band === 'critical' ? 'text-red-400' : band === 'high' ? 'text-orange-400' : band === 'medium' ? 'text-yellow-400' : 'text-emerald-400'}`}>{asset.hybridRiskScore}</span>
                              <span className="text-[9px] text-muted-foreground">/100</span>
                              <p className={`text-[8px] ${band === 'critical' ? 'text-red-400/60' : band === 'high' ? 'text-orange-400/60' : band === 'medium' ? 'text-yellow-400/60' : 'text-emerald-400/60'}`}>Hybrid</p>
                            </div>
                            <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs flex-1">
                              <div>
                                <span className="text-sky-400 font-medium">Impact:</span>{" "}
                                <span className="font-bold">{asset.impactScore || 0}/100</span>
                              </div>
                              <div>
                                <span className="text-amber-400 font-medium">Likelihood:</span>{" "}
                                <span className="font-bold">{asset.likelihoodScore || 0}/100</span>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Mission Impact:</span>{" "}
                                <span className="font-bold">{((asset.missionImpactScore || 0) / 10).toFixed(1)}/10</span>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Confidence:</span>{" "}
                                <ConfidenceBadge score={(asset.confidence || 0) / 100} size="xs" />
                              </div>
                            </div>
                          </div>
                          <div className="text-[8px] text-muted-foreground/60 italic">CVSS = vulnerability severity estimate · Hybrid = √(Impact × Likelihood)</div>
                        </div>
                      </div>
                    </div>

                    {/* Posture Findings — Confirmed shown, Probable & Potential behind collapsibles */}
                    {findings.length > 0 && (() => {
                      const confirmedOnlyFindings = findings.filter((f: any) => f.corroborationTier === 'confirmed');
                      const probableOnlyFindings = findings.filter((f: any) => f.corroborationTier === 'probable');
                      const potentialOnlyFindings = findings.filter((f: any) => !f.corroborationTier || f.corroborationTier === 'potential');
                      const informationalFindings = findings.filter((f: any) => f.corroborationTier === 'informational');
                      const renderFinding = (f: any, i: number) => {
                        const tierColor = f.corroborationTier === "confirmed" ? "text-emerald-400 bg-emerald-500/20 border-emerald-500/40"
                          : f.corroborationTier === "probable" ? "text-yellow-400 bg-yellow-500/20 border-yellow-500/40"
                          : f.corroborationTier === "informational" ? "text-slate-400 bg-slate-500/20 border-slate-500/40"
                          : "text-purple-400 bg-purple-500/20 border-purple-500/40";
                        const tierLabel = f.corroborationTier === "confirmed" ? "CONFIRMED" : f.corroborationTier === "probable" ? "PROBABLE" : f.corroborationTier === "informational" ? "INFORMATIONAL" : "POTENTIAL";
                        return (
                          <div key={i} className={`p-2 rounded border ${f.kevListed ? "bg-red-500/5 border-red-500/30" : f.corroborationTier === "potential" ? "bg-muted/20 border-purple-500/20 opacity-75" : "bg-muted/30 border-border"}`}>
                            <div className="flex items-start justify-between gap-2">
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-1.5 mb-0.5 flex-wrap">
                                  <Badge className={`text-[9px] px-1 py-0 ${tierColor}`}>{tierLabel}</Badge>
                                  {(() => { const t = (f.title || '').toLowerCase(); return (f.corroborationTier !== 'potential' && (t.includes('remote code') || t.includes('rce') || t.includes('auth bypass') || t.includes('authentication bypass') || t.includes('ssrf') || t.includes('unauthenticated') || t.includes('pre-auth') || t.includes('command injection') || t.includes('sql injection'))) ? <Badge className="text-[9px] px-1 py-0 bg-rose-600/30 text-rose-300 border-rose-500/50 animate-pulse">REMOTE ACCESS</Badge> : null; })()}
                                  <p className="text-sm font-medium">{f.title}</p>
                                </div>
                                {f.cveIds?.length > 0 && (
                                  <div className="flex gap-1 mt-0.5 flex-wrap">
                                    {f.cveIds.map((cve: string) => (
                                      <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer"
                                        className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 underline decoration-dotted">{cve}</a>
                                    ))}
                                  </div>
                                )}
                                {f.detectedVersion && (
                                  <p className="text-[10px] text-emerald-400 font-mono mt-0.5">
                                    Version: {f.detectedVersion} {f.versionMatchConfirmed ? "✔ matched" : ""}
                                    {f.affectedVersions && <span className="text-muted-foreground/70"> (affected range: {f.affectedVersions})</span>}
                                  </p>
                                )}
                                {!f.detectedVersion && f.corroborationTier === "probable" && (
                                   <div className="mt-1 space-y-0.5">
                                     <p className="text-[10px] text-yellow-400">Version unconfirmed — severity capped</p>
                                     <div className="flex items-center gap-1 bg-yellow-500/10 rounded px-1.5 py-0.5 border border-yellow-500/20">
                                       <Search className="h-2.5 w-2.5 text-yellow-400 shrink-0" />
                                       <p className="text-[9px] text-yellow-300">Version enumeration recommended — run active scan (Nmap, banner grab) to confirm version and upgrade to confirmed finding</p>
                                     </div>
                                   </div>
                                 )}
                                {f.nvdDescription && (
                                  <p className="text-[10px] text-muted-foreground mt-1 leading-relaxed">{f.nvdDescription}</p>
                                )}
                                {f.evidenceDetail && (
                                  <p className="text-[10px] text-muted-foreground/70 mt-0.5 italic">{f.evidenceDetail}</p>
                                )}
                              </div>
                              <div className="flex gap-1 shrink-0 flex-wrap">
                                {f.kevListed && <Badge className="text-[10px] bg-red-600/30 text-red-300 border-red-500/50">KEV</Badge>}
                                {f.kevListed && f.versionMatchConfirmed && <Badge className="text-[10px] bg-emerald-600/30 text-emerald-300 border-emerald-500/50">CONFIRMED</Badge>}
                                {f.kevListed && !f.versionMatchConfirmed && <Badge className="text-[10px] bg-amber-600/30 text-amber-300 border-amber-500/50">POTENTIAL</Badge>}
                                {f.exploitAvailable && !f.kevListed && <Badge className="text-[10px] bg-orange-600/30 text-orange-300 border-orange-500/50">Exploit</Badge>}
                                {f.corroborationTier === 'potential' || f.corroborationTier === 'informational' ? (
                                  <Badge variant="outline" className="text-[10px] text-muted-foreground/60 border-muted-foreground/30">{f.corroborationTier === 'informational' ? 'INFORMATIONAL' : 'NOT RATED'}</Badge>
                                ) : (
                                  <>
                                    <Badge variant="outline" className="text-[10px]">Sev: {f.severity}/10{f.corroborationTier === "probable" ? " (cap)" : ""}</Badge>
                                    {f.cvssScore && <Badge variant="outline" className="text-[10px] text-cyan-400 border-cyan-500/40">CVSS: {f.cvssScore}</Badge>}
                                    <Badge variant="outline" className="text-[10px]">Likely: {f.likelihood}/10</Badge>
                                  </>
                                )}
                              </div>
                            </div>
                            {f.recommendedControls && f.recommendedControls.length > 0 && (
                              <div className="mt-1 flex gap-1 flex-wrap">
                                {f.recommendedControls.map((c: string, j: number) => (
                                  <Badge key={j} variant="secondary" className="text-[10px]">{c}</Badge>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      };
                      return (
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-2">Confirmed Findings ({confirmedOnlyFindings.length})</p>
                          {confirmedOnlyFindings.length > 0 ? (
                            <div className="space-y-2">
                              {confirmedOnlyFindings.map(renderFinding)}
                            </div>
                          ) : (
                            <p className="text-[11px] text-muted-foreground">No confirmed findings for this asset.</p>
                          )}
                          {probableOnlyFindings.length > 0 && (
                            <Collapsible className="mt-3">
                              <CollapsibleTrigger className="flex items-center gap-1.5 text-[11px] text-yellow-400 hover:text-yellow-300 transition-colors cursor-pointer">
                                <ChevronDown className="h-3 w-3" />
                                <span className="underline decoration-dotted">Probable Matches ({probableOnlyFindings.length})</span>
                                <span className="text-[9px] text-muted-foreground no-underline ml-1">version unconfirmed</span>
                              </CollapsibleTrigger>
                              <CollapsibleContent className="mt-2 space-y-2">
                                {probableOnlyFindings.map(renderFinding)}
                              </CollapsibleContent>
                            </Collapsible>
                          )}
                          {potentialOnlyFindings.length > 0 && (
                            <Collapsible className="mt-3">
                              <CollapsibleTrigger className="flex items-center gap-1.5 text-[11px] text-purple-400 hover:text-purple-300 transition-colors cursor-pointer">
                                <ChevronDown className="h-3 w-3" />
                                <span className="underline decoration-dotted">Potential Matches ({potentialOnlyFindings.length})</span>
                              </CollapsibleTrigger>
                              <CollapsibleContent className="mt-2 space-y-2">
                                {potentialOnlyFindings.map(renderFinding)}
                              </CollapsibleContent>
                            </Collapsible>
                          )}
                        </div>
                      );
                    })()}

                    {/* DNS Records */}
                    {asset.dnsRecords && Object.keys(asset.dnsRecords).some((k: string) => (asset.dnsRecords as any)[k]?.length > 0) && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-2 flex items-center gap-1">
                          <Globe className="h-3 w-3" /> DNS Records
                        </p>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          {Object.entries(asset.dnsRecords as Record<string, string[]>).filter(([, v]) => v && v.length > 0).map(([type, records]) => (
                            <div key={type} className="p-2 rounded bg-muted/20 border border-border">
                              <p className="text-[10px] font-medium text-sky-400 mb-1">{type} Records</p>
                              <div className="space-y-0.5">
                                {(records as string[]).map((r: string, ri: number) => (
                                  <p key={ri} className="text-[10px] font-mono text-muted-foreground truncate">{r}</p>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Open Ports & Services on this asset */}
                    {(() => {
                      const assetPorts = (pipeline?.discoveredPorts || []).filter((p: any) => {
                        const hostname = asset.hostname?.toLowerCase();
                        return p.hostname?.toLowerCase() === hostname || p.ip === asset.resolvedIps?.[0];
                      });
                      if (assetPorts.length === 0) return null;
                      const commonPorts: Record<number, string> = {
                        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
                        110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
                        995: 'POP3S', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
                        5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
                        9200: 'Elasticsearch', 27017: 'MongoDB',
                      };
                      return (
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-2 flex items-center gap-1">
                            <Network className="h-3 w-3" /> Open Ports & Services ({assetPorts.length})
                          </p>
                          <div className="border rounded-lg overflow-auto">
                            <table className="w-full text-xs">
                              <thead className="bg-muted/50">
                                <tr>
                                  <th className="text-left px-2 py-1.5 font-medium">Port</th>
                                  <th className="text-left px-2 py-1.5 font-medium">Protocol</th>
                                  <th className="text-left px-2 py-1.5 font-medium">Service</th>
                                  <th className="text-left px-2 py-1.5 font-medium">Version</th>
                                  <th className="text-left px-2 py-1.5 font-medium">CVEs</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-border">
                                {assetPorts.sort((a: any, b: any) => a.port - b.port).map((p: any, pi: number) => (
                                  <tr key={pi} className={`${p.vulns?.length > 0 ? 'bg-red-500/5' : ''}`}>
                                    <td className="px-2 py-1.5 font-mono">
                                      <Badge variant="outline" className={`text-[10px] ${
                                        [21, 23, 3389, 5900].includes(p.port) ? 'text-red-400 border-red-500/40' :
                                        [22, 443, 993, 995].includes(p.port) ? 'text-emerald-400 border-emerald-500/40' :
                                        'text-sky-400 border-sky-500/40'
                                      }`}>
                                        {p.port}{commonPorts[p.port] ? ` (${commonPorts[p.port]})` : ''}
                                      </Badge>
                                    </td>
                                    <td className="px-2 py-1.5 text-muted-foreground uppercase">{p.transport}</td>
                                    <td className="px-2 py-1.5">{p.product || <span className="text-muted-foreground italic">unknown</span>}</td>
                                    <td className="px-2 py-1.5 font-mono text-muted-foreground">{p.version || '—'}</td>
                                    <td className="px-2 py-1.5">
                                      <div className="flex flex-wrap gap-1">
                                        {(p.vulns || []).slice(0, 3).map((v: string, vi: number) => (
                                          <Badge key={vi} variant="destructive" className="text-[10px]">{v}</Badge>
                                        ))}
                                        {(p.vulns || []).length > 3 && <Badge variant="destructive" className="text-[10px]">+{p.vulns.length - 3}</Badge>}
                                      </div>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Test Vectors */}
                    {vectors.length > 0 && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-2">Test Vectors ({vectors.length})</p>
                        <div className="space-y-2">
                          {vectors.map((v: any, i: number) => (
                            <div key={i} className="p-2 rounded bg-purple-500/5 border border-purple-500/20">
                              <div className="flex items-center gap-2 mb-1">
                                <Crosshair className="h-3 w-3 text-purple-400" />
                                <span className="text-sm font-medium">{v.vectorType}</span>
                                {v.suggestedEmulation?.technique && (
                                  <Badge className="bg-purple-500/20 text-purple-400 text-[10px]">{v.suggestedEmulation.technique}</Badge>
                                )}
                              </div>
                              <p className="text-xs text-muted-foreground">{v.hypothesis}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                )}
              </Card>
            );
          })}
        </TabsContent>

        {/* Subdomains Tab */}
        <TabsContent value="subdomains" className="space-y-4">
          {(() => {
            const subdomains = (pipeline?.discoveredSubdomains || []) as any[];
            const allPorts = (pipeline?.discoveredPorts || []) as any[];
            // Also extract subdomains from assets
            const assetSubdomains = assets.filter((a: any) => a.assetType === 'subdomain' || (a.hostname && a.hostname !== scan.primaryDomain));
            // Merge: pipeline subdomains + asset subdomains (deduplicated)
            const allSubdomainMap = new Map<string, any>();
            for (const s of subdomains) {
              allSubdomainMap.set((s.name || '').toLowerCase(), { ...s });
            }
            for (const a of assetSubdomains) {
              const key = (a as any).hostname?.toLowerCase();
              if (key && !allSubdomainMap.has(key)) {
                allSubdomainMap.set(key, {
                  name: (a as any).hostname,
                  ip: (a as any).resolvedIps?.[0] || null,
                  source: 'asset_discovery',
                  tags: ((a as any).tags || []).filter((t: string) => t.startsWith('port:') || t.startsWith('product:')),
                });
              }
            }

            // Enrich each subdomain with IP from matching asset, technologies, and ports
            const assetMap = new Map<string, any>();
            for (const a of assets as any[]) {
              assetMap.set((a.hostname || '').toLowerCase(), a);
            }

            const commonPorts: Record<number, string> = {
              21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
              110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
              995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
              5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
              9200: 'Elasticsearch', 27017: 'MongoDB',
            };

            const enrichedSubdomains = Array.from(allSubdomainMap.values()).map(s => {
              const key = (s.name || '').toLowerCase();
              const matchedAsset = assetMap.get(key);
              // Resolve IP: from subdomain, from asset DNS, or from port data
              let ip = s.ip || '';
              if (!ip && matchedAsset) {
                const dns = (matchedAsset.dnsRecords || {}) as Record<string, any>;
                if (dns.A && Array.isArray(dns.A) && dns.A.length > 0) {
                  ip = typeof dns.A[0] === 'string' ? dns.A[0] : dns.A[0]?.address || '';
                } else if (dns.AAAA && Array.isArray(dns.AAAA) && dns.AAAA.length > 0) {
                  ip = typeof dns.AAAA[0] === 'string' ? dns.AAAA[0] : dns.AAAA[0]?.address || '';
                }
              }
              if (!ip) {
                const portMatch = allPorts.find((p: any) => p.hostname?.toLowerCase() === key);
                if (portMatch) ip = portMatch.ip || '';
              }
              // Technologies from matched asset
              const technologies: string[] = matchedAsset ? (Array.isArray(matchedAsset.technologies) ? matchedAsset.technologies : []) : [];
              const techVersions: Record<string, string> = matchedAsset?.technologyVersions || {};
              // Also extract product tags
              const tagTech = (s.tags || []).filter((t: string) => t.startsWith('product:')).map((t: string) => t.replace('product:', ''));
              const allTech = [...new Set([...technologies, ...tagTech])];
              // Ports for this subdomain
              const subPorts = allPorts.filter((p: any) => p.hostname?.toLowerCase() === key || (ip && p.ip === ip)).map((p: any) => ({
                port: p.port as number,
                transport: p.transport || 'tcp',
                service: p.product || commonPorts[p.port as number] || '',
                version: p.version || '',
                vulns: (p.vulns || []) as string[],
              }));
              // Compute risk score: use matched asset score, or calculate from ports/CVEs
              let riskScore = matchedAsset?.hybridRiskScore || 0;
              if (!matchedAsset && subPorts.length > 0) {
                const HR: Record<number, number> = { 23: 25, 445: 25, 1433: 25, 1521: 25, 3306: 25, 3389: 25, 5432: 25, 5900: 25, 6379: 25, 27017: 25, 21: 15, 110: 15, 135: 15, 139: 15, 9200: 15, 11211: 15, 25: 8, 143: 8, 8080: 8 };
                for (const sp of subPorts) { riskScore += HR[sp.port] || 0; for (const _v of sp.vulns) riskScore += 20; }
                const h80 = subPorts.some(p => p.port === 80), h443 = subPorts.some(p => p.port === 443);
                if (h80 && !h443) riskScore += 12;
                if (subPorts.length > 5) riskScore += 10;
                if (ip) riskScore += 5;
                riskScore = Math.min(riskScore, 100);
              }
              const riskBand = matchedAsset?.riskBand || (riskScore >= 70 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 25 ? 'medium' : 'low');
              // Count findings
              let findingsCount = 0;
              for (const sp of subPorts) {
                const HR: Record<number, boolean> = { 23: true, 445: true, 1433: true, 3306: true, 3389: true, 5432: true, 5900: true, 6379: true, 27017: true, 21: true, 110: true, 135: true, 139: true, 9200: true, 11211: true };
                if (HR[sp.port]) findingsCount++;
                findingsCount += sp.vulns.length;
              }
              const h80 = subPorts.some(p => p.port === 80), h443 = subPorts.some(p => p.port === 443);
              if (h80 && !h443) findingsCount++;

              return {
                ...s,
                ip,
                technologies: allTech,
                technologyVersions: techVersions,
                ports: subPorts,
                riskScore,
                riskBand,
                findingsCount,
                assetType: matchedAsset?.assetType || 'subdomain',
              };
            });

            const sources = Array.from(new Set(enrichedSubdomains.map(s => s.source)));
            const filtered = enrichedSubdomains.filter(s => {
              if (subSearch) {
                const q = subSearch.toLowerCase();
                if (!(s.name || '').toLowerCase().includes(q) && !(s.ip || '').includes(q) && !s.technologies.some((t: string) => t.toLowerCase().includes(q)) && !s.ports.some((p: any) => String(p.port).includes(q) || p.service.toLowerCase().includes(q))) return false;
              }
              if (subSourceFilter !== 'all' && s.source !== subSourceFilter) return false;
              return true;
            });

            const withTech = enrichedSubdomains.filter(s => s.technologies.length > 0).length;
            const withPorts = enrichedSubdomains.filter(s => s.ports.length > 0).length;
            const uniqueTechs = new Set(enrichedSubdomains.flatMap(s => s.technologies));

            return (
              <>
                <Card className="bg-card/50">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Globe className="h-5 w-5 text-purple-400" />
                      Discovered Subdomains & Assets ({enrichedSubdomains.length})
                    </CardTitle>
                    <CardDescription>
                      All subdomains and assets discovered across passive recon connectors, enriched with resolved IPs, detected technologies, open ports, and running services.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {/* Stats */}
                    {(() => {
                      const critCount = enrichedSubdomains.filter(s => s.riskBand === 'critical').length;
                      const highCount = enrichedSubdomains.filter(s => s.riskBand === 'high').length;
                      const medCount = enrichedSubdomains.filter(s => s.riskBand === 'medium').length;
                      const totalFindings = enrichedSubdomains.reduce((sum, s) => sum + (s.findingsCount || 0), 0);
                      return (
                        <div className="space-y-3">
                          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
                            <div className="p-3 rounded-lg bg-muted/30 border border-border">
                              <p className="text-2xl font-bold text-purple-400">{enrichedSubdomains.length}</p>
                              <p className="text-xs text-muted-foreground">Total Subdomains</p>
                            </div>
                            <div className="p-3 rounded-lg bg-muted/30 border border-border">
                              <p className="text-2xl font-bold text-emerald-400">{enrichedSubdomains.filter(s => s.ip).length}</p>
                              <p className="text-xs text-muted-foreground">With Resolved IPs</p>
                            </div>
                            <div className="p-3 rounded-lg bg-muted/30 border border-border">
                              <p className="text-2xl font-bold text-cyan-400">{withTech}</p>
                              <p className="text-xs text-muted-foreground">With Technologies</p>
                            </div>
                            <div className="p-3 rounded-lg bg-muted/30 border border-border">
                              <p className="text-2xl font-bold text-amber-400">{withPorts}</p>
                              <p className="text-xs text-muted-foreground">With Open Ports</p>
                            </div>
                            <div className="p-3 rounded-lg bg-muted/30 border border-border">
                              <p className="text-2xl font-bold text-sky-400">{uniqueTechs.size}</p>
                              <p className="text-xs text-muted-foreground">Unique Technologies</p>
                            </div>
                          </div>
                          {/* Risk Distribution Bar */}
                          {(critCount + highCount + medCount) > 0 && (
                            <div className="p-3 rounded-lg bg-muted/30 border border-border">
                              <p className="text-xs font-medium text-muted-foreground mb-2">Risk Distribution ({totalFindings} total findings)</p>
                              <div className="flex gap-4 items-center">
                                {critCount > 0 && (
                                  <div className="flex items-center gap-1.5">
                                    <div className="w-3 h-3 rounded-full bg-red-500" />
                                    <span className="text-xs font-medium text-red-400">{critCount} Critical</span>
                                  </div>
                                )}
                                {highCount > 0 && (
                                  <div className="flex items-center gap-1.5">
                                    <div className="w-3 h-3 rounded-full bg-orange-500" />
                                    <span className="text-xs font-medium text-orange-400">{highCount} High</span>
                                  </div>
                                )}
                                {medCount > 0 && (
                                  <div className="flex items-center gap-1.5">
                                    <div className="w-3 h-3 rounded-full bg-yellow-500" />
                                    <span className="text-xs font-medium text-yellow-400">{medCount} Medium</span>
                                  </div>
                                )}
                                <div className="flex items-center gap-1.5">
                                  <div className="w-3 h-3 rounded-full bg-emerald-500" />
                                  <span className="text-xs font-medium text-emerald-400">{enrichedSubdomains.length - critCount - highCount - medCount} Low</span>
                                </div>
                              </div>
                              {/* Visual bar */}
                              <div className="flex h-2 rounded-full overflow-hidden mt-2 bg-muted/50">
                                {critCount > 0 && <div className="bg-red-500" style={{ width: `${(critCount / enrichedSubdomains.length) * 100}%` }} />}
                                {highCount > 0 && <div className="bg-orange-500" style={{ width: `${(highCount / enrichedSubdomains.length) * 100}%` }} />}
                                {medCount > 0 && <div className="bg-yellow-500" style={{ width: `${(medCount / enrichedSubdomains.length) * 100}%` }} />}
                                <div className="bg-emerald-500 flex-1" />
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })()}

                    {/* Filters */}
                    <div className="flex flex-wrap gap-3">
                      <div className="flex-1 min-w-[200px]">
                        <input
                          type="text"
                          placeholder="Search by subdomain, IP, technology, port, or service..."
                          value={subSearch}
                          onChange={(e) => setSubSearch(e.target.value)}
                          className="w-full px-3 py-2 text-sm rounded-md border border-border bg-background"
                        />
                      </div>
                      <select
                        value={subSourceFilter}
                        onChange={(e) => setSubSourceFilter(e.target.value)}
                        className="px-3 py-2 text-sm rounded-md border border-border bg-background"
                      >
                        <option value="all">All Sources</option>
                        {sources.map(s => <option key={s} value={s}>{s}</option>)}
                      </select>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          const csv = ['Subdomain,IP Address,Asset Type,Risk Score,Risk Band,Findings,Technologies,Technology Versions,Open Ports,Services,Source'];
                          enrichedSubdomains.forEach(s => {
                            const techVerStr = Object.entries(s.technologyVersions || {}).map(([k, v]) => `${k}/${v}`).join('; ');
                            const portsStr = s.ports.map((p: any) => String(p.port)).join('; ');
                            const servicesStr = s.ports.map((p: any) => p.service || commonPorts[p.port] || `port-${p.port}`).join('; ');
                            csv.push(`"${s.name}","${s.ip || ''}","${s.assetType}",${s.riskScore},"${s.riskBand}",${s.findingsCount || 0},"${s.technologies.join('; ')}","${techVerStr}","${portsStr}","${servicesStr}","${s.source}"`);
                          });
                          const blob = new Blob([csv.join('\n')], { type: 'text/csv' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url; a.download = `${scan.primaryDomain}_subdomains_full.csv`; a.click();
                          URL.revokeObjectURL(url);
                          toast.success(`Exported ${enrichedSubdomains.length} subdomains with full details`);
                        }}
                      >
                        <Download className="h-3 w-3 mr-1" /> Export Full CSV
                      </Button>
                    </div>

                    {/* Enhanced Subdomain Table */}
                    <div className="border rounded-lg overflow-auto max-h-[700px]">
                      <table className="w-full text-sm">
                        <thead className="bg-muted/50 sticky top-0 z-10">
                          <tr>
                            <th className="text-left px-3 py-2 font-medium">Subdomain</th>
                            <th className="text-left px-3 py-2 font-medium">IP Address</th>
                            <th className="text-center px-3 py-2 font-medium">Risk</th>
                            <th className="text-center px-3 py-2 font-medium">Findings</th>
                            <th className="text-left px-3 py-2 font-medium">Technologies / Apps</th>
                            <th className="text-left px-3 py-2 font-medium">Ports & Services</th>
                            <th className="text-left px-3 py-2 font-medium">Source</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {filtered.length === 0 ? (
                            <tr><td colSpan={11} className="px-3 py-8 text-center text-muted-foreground">No subdomains found matching your filters</td></tr>
                          ) : filtered.map((s: any, i: number) => (
                            <tr key={i} className={`hover:bg-muted/20 ${s.riskBand === 'critical' ? 'bg-red-500/5' : s.riskBand === 'high' ? 'bg-orange-500/5' : ''}`}>
                              <td className="px-3 py-2">
                                <p className="font-mono text-xs font-medium">{s.name}</p>
                              </td>
                              <td className="px-3 py-2">
                                {s.ip ? (
                                  <span className="font-mono text-xs">{s.ip}</span>
                                ) : (
                                  <span className="text-xs text-muted-foreground italic">unresolved</span>
                                )}
                              </td>
                              <td className="px-3 py-2 text-center">
                                <div className="flex flex-col items-center gap-0.5">
                                  <span className={`text-xs font-bold ${
                                    s.riskBand === 'critical' ? 'text-red-400' :
                                    s.riskBand === 'high' ? 'text-orange-400' :
                                    s.riskBand === 'medium' ? 'text-yellow-400' :
                                    'text-emerald-400'
                                  }`}>{s.riskScore}</span>
                                  <Badge className={`text-[9px] px-1 py-0 ${
                                    s.riskBand === 'critical' ? 'bg-red-500/20 text-red-400 border-red-500/40' :
                                    s.riskBand === 'high' ? 'bg-orange-500/20 text-orange-400 border-orange-500/40' :
                                    s.riskBand === 'medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40' :
                                    'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                                  }`}>{s.riskBand}</Badge>
                                </div>
                              </td>
                              <td className="px-3 py-2 text-center">
                                {s.findingsCount > 0 ? (
                                  <Badge className={`text-[10px] ${
                                    s.findingsCount >= 3 ? 'bg-red-500/20 text-red-400 border-red-500/40' :
                                    s.findingsCount >= 1 ? 'bg-amber-500/20 text-amber-400 border-amber-500/40' :
                                    'bg-muted text-muted-foreground'
                                  }`}>{s.findingsCount} issue{s.findingsCount !== 1 ? 's' : ''}</Badge>
                                ) : (
                                  <span className="text-[10px] text-muted-foreground">clean</span>
                                )}
                              </td>
                              <td className="px-3 py-2">
                                <div className="flex flex-wrap gap-1 max-w-[250px]">
                                  {s.technologies.length > 0 ? (
                                    <>
                                      {s.technologies.slice(0, 4).map((t: string, j: number) => {
                                        const ver = s.technologyVersions?.[t];
                                        return (
                                          <Badge key={j} variant="secondary" className="text-[10px]">
                                            {t}{ver ? `/${ver}` : ''}
                                          </Badge>
                                        );
                                      })}
                                      {s.technologies.length > 4 && (
                                        <Badge variant="secondary" className="text-[10px]">+{s.technologies.length - 4}</Badge>
                                      )}
                                    </>
                                  ) : (
                                    <span className="text-[10px] text-muted-foreground italic">none detected</span>
                                  )}
                                </div>
                              </td>
                              <td className="px-3 py-2">
                                <div className="flex flex-wrap gap-1 max-w-[250px]">
                                  {s.ports.length > 0 ? (
                                    <>
                                      {s.ports.sort((a: any, b: any) => a.port - b.port).slice(0, 5).map((p: any, j: number) => {
                                        const label = p.service || commonPorts[p.port] || `port-${p.port}`;
                                        const isHighRisk = [21, 23, 3389, 5900, 445].includes(p.port);
                                        const hasVulns = p.vulns?.length > 0;
                                        return (
                                          <Badge key={j} variant={hasVulns ? 'destructive' : 'outline'} className={`text-[10px] font-mono ${
                                            isHighRisk ? 'text-red-400 border-red-500/40' :
                                            hasVulns ? '' :
                                            'text-sky-400 border-sky-500/40'
                                          }`}>
                                            {p.port}/{label}
                                          </Badge>
                                        );
                                      })}
                                      {s.ports.length > 5 && (
                                        <Badge variant="outline" className="text-[10px]">+{s.ports.length - 5}</Badge>
                                      )}
                                    </>
                                  ) : (
                                    <span className="text-[10px] text-muted-foreground italic">no ports</span>
                                  )}
                                </div>
                              </td>
                              <td className="px-3 py-2">
                                <Badge variant="outline" className="text-[10px]">{s.source}</Badge>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {filtered.length < enrichedSubdomains.length && (
                      <p className="text-xs text-muted-foreground">Showing {filtered.length} of {enrichedSubdomains.length} subdomains</p>
                    )}
                  </CardContent>
                </Card>
              </>
            );
          })()}
        </TabsContent>

        {/* Asset Inventory Tab — Comprehensive view of all assets with domain, IP, tech, ports, services */}
        <TabsContent value="inventory" className="space-y-4">
          {(() => {
            const ports = (pipeline?.discoveredPorts || []) as any[];
            const subdomains = (pipeline?.discoveredSubdomains || []) as any[];

            // Build a unified inventory from DB assets + pipeline subdomains
            interface InventoryItem {
              hostname: string;
              ip: string;
              assetType: string;
              technologies: string[];
              technologyVersions: Record<string, string>;
              ports: Array<{ port: number; transport: string; service: string; version: string; vulns: string[] }>;
              riskScore: number;
              riskBand: string;
              discoveryMethod: string;
              source: string;
              dnsRecords: Record<string, string[]>;
              missionFunction: string;
              essentialService: string;
            }

            const inventoryMap = new Map<string, InventoryItem>();

            // 1. Add all DB assets
            for (const a of assets as any[]) {
              const hostname = (a.hostname || '').toLowerCase();
              const techArr = Array.isArray(a.technologies) ? a.technologies as string[] : [];
              const techVersions = (a.technologyVersions || {}) as Record<string, string>;
              // Resolve IPs from DNS records
              let ip = '';
              const dns = (a.dnsRecords || {}) as Record<string, any>;
              if (dns.A && Array.isArray(dns.A) && dns.A.length > 0) {
                ip = typeof dns.A[0] === 'string' ? dns.A[0] : dns.A[0]?.address || '';
              } else if (dns.AAAA && Array.isArray(dns.AAAA) && dns.AAAA.length > 0) {
                ip = typeof dns.AAAA[0] === 'string' ? dns.AAAA[0] : dns.AAAA[0]?.address || '';
              }
              // Find ports for this asset
              const assetPorts = ports.filter((p: any) => {
                return p.hostname?.toLowerCase() === hostname || (ip && p.ip === ip);
              }).map((p: any) => ({
                port: p.port,
                transport: p.transport || 'tcp',
                service: p.product || '',
                version: p.version || '',
                vulns: p.vulns || [],
              }));

              inventoryMap.set(hostname, {
                hostname: a.hostname,
                ip,
                assetType: a.assetType || 'unknown',
                technologies: techArr,
                technologyVersions: techVersions,
                ports: assetPorts,
                riskScore: a.hybridRiskScore || 0,
                riskBand: a.riskBand || 'low',
                discoveryMethod: a.discoveryMethod || 'inferred',
                source: 'asset_discovery',
                dnsRecords: dns,
                missionFunction: a.missionFunction || '',
                essentialService: a.essentialService || '',
              });
            }

            // 2. Add subdomains not already in assets
            for (const s of subdomains) {
              const key = (s.name || '').toLowerCase();
              if (!key || inventoryMap.has(key)) continue;
              const subPorts = ports.filter((p: any) => p.hostname?.toLowerCase() === key || (s.ip && p.ip === s.ip)).map((p: any) => ({
                port: p.port,
                transport: p.transport || 'tcp',
                service: p.product || '',
                version: p.version || '',
                vulns: p.vulns || [],
              }));
              const techFromTags = (s.tags || []).filter((t: string) => t.startsWith('product:')).map((t: string) => t.replace('product:', ''));
              // Compute real risk score for subdomain in inventory
              let subRisk = 0;
              const HR: Record<number, number> = { 23: 25, 445: 25, 1433: 25, 1521: 25, 3306: 25, 3389: 25, 5432: 25, 5900: 25, 6379: 25, 27017: 25, 21: 15, 110: 15, 135: 15, 139: 15, 9200: 15, 11211: 15, 25: 8, 143: 8, 8080: 8 };
              for (const sp of subPorts) {
                subRisk += HR[sp.port] || 0;
                for (const _v of sp.vulns) subRisk += 20;
              }
              const has80 = subPorts.some(p => p.port === 80);
              const has443 = subPorts.some(p => p.port === 443);
              if (has80 && !has443) subRisk += 12;
              if (subPorts.length > 5) subRisk += 10;
              if (s.ip) subRisk += 5;
              subRisk = Math.min(subRisk, 100);
              const subBand = subRisk >= 70 ? 'critical' : subRisk >= 50 ? 'high' : subRisk >= 25 ? 'medium' : 'low';

              inventoryMap.set(key, {
                hostname: s.name,
                ip: s.ip || '',
                assetType: 'subdomain',
                technologies: techFromTags,
                technologyVersions: {},
                ports: subPorts,
                riskScore: subRisk,
                riskBand: subBand,
                discoveryMethod: 'passive_recon',
                source: s.source || 'recon',
                dnsRecords: {},
                missionFunction: '',
                essentialService: '',
              });
            }

            const allItems = Array.from(inventoryMap.values());
            const assetTypes = Array.from(new Set(allItems.map(i => i.assetType)));

            // Filter
            const filtered = allItems.filter(item => {
              if (inventorySearch) {
                const q = inventorySearch.toLowerCase();
                if (!(item.hostname || '').toLowerCase().includes(q) && !item.ip.includes(q) && !item.technologies.some(t => t.toLowerCase().includes(q)) && !item.ports.some(p => String(p.port).includes(q) || p.service.toLowerCase().includes(q))) return false;
              }
              if (inventoryTypeFilter !== 'all' && item.assetType !== inventoryTypeFilter) return false;
              return true;
            });

            // Sort
            const sorted = [...filtered].sort((a, b) => {
              if (inventorySortBy === 'risk') return b.riskScore - a.riskScore;
              if (inventorySortBy === 'hostname') return a.hostname.localeCompare(b.hostname);
              if (inventorySortBy === 'ports') return b.ports.length - a.ports.length;
              if (inventorySortBy === 'tech') return b.technologies.length - a.technologies.length;
              return 0;
            });

            const totalWithIPs = allItems.filter(i => i.ip).length;
            const totalWithPorts = allItems.filter(i => i.ports.length > 0).length;
            const totalWithTech = allItems.filter(i => i.technologies.length > 0).length;
            const allTechs = new Set(allItems.flatMap(i => i.technologies));
            const totalUniquePorts = new Set(allItems.flatMap(i => i.ports.map(p => p.port))).size;

            const commonPorts: Record<number, string> = {
              21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
              110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
              995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
              3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
              8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch', 27017: 'MongoDB',
            };

            return (
              <>
                <Card className="bg-card/50">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Cpu className="h-5 w-5 text-cyan-400" />
                      Complete Asset Inventory ({allItems.length})
                    </CardTitle>
                    <CardDescription>
                      Unified view of all discovered assets, subdomains, and infrastructure — showing domain names, resolved IPs, detected technologies and applications, open ports, and running services.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {/* Stats Row */}
                    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-cyan-400">{allItems.length}</p>
                        <p className="text-xs text-muted-foreground">Total Assets</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-emerald-400">{totalWithIPs}</p>
                        <p className="text-xs text-muted-foreground">With Resolved IPs</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-purple-400">{totalWithTech}</p>
                        <p className="text-xs text-muted-foreground">With Technologies</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-sky-400">{allTechs.size}</p>
                        <p className="text-xs text-muted-foreground">Unique Technologies</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-amber-400">{totalWithPorts}</p>
                        <p className="text-xs text-muted-foreground">With Open Ports</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-red-400">{totalUniquePorts}</p>
                        <p className="text-xs text-muted-foreground">Unique Ports</p>
                      </div>
                    </div>

                    {/* Filters */}
                    <div className="flex flex-wrap gap-3">
                      <div className="flex-1 min-w-[200px]">
                        <input
                          type="text"
                          placeholder="Search by hostname, IP, technology, port, or service..."
                          value={inventorySearch}
                          onChange={(e) => setInventorySearch(e.target.value)}
                          className="w-full px-3 py-2 text-sm rounded-md border border-border bg-background"
                        />
                      </div>
                      <select
                        value={inventoryTypeFilter}
                        onChange={(e) => setInventoryTypeFilter(e.target.value)}
                        className="px-3 py-2 text-sm rounded-md border border-border bg-background"
                      >
                        <option value="all">All Types</option>
                        {assetTypes.map(t => <option key={t} value={t}>{t}</option>)}
                      </select>
                      <select
                        value={inventorySortBy}
                        onChange={(e) => setInventorySortBy(e.target.value as any)}
                        className="px-3 py-2 text-sm rounded-md border border-border bg-background"
                      >
                        <option value="risk">Sort by Risk</option>
                        <option value="hostname">Sort by Hostname</option>
                        <option value="ports">Sort by Port Count</option>
                        <option value="tech">Sort by Tech Count</option>
                      </select>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          const csv = ['Domain Name,IP Address,Asset Type,Risk Score,Risk Band,Technologies,Technology Versions,Open Ports,Services,Discovery Method,Mission Function'];
                          allItems.forEach(item => {
                            const techVersionStr = Object.entries(item.technologyVersions).map(([k, v]) => `${k}/${v}`).join('; ');
                            const portsStr = item.ports.map(p => String(p.port)).join('; ');
                            const servicesStr = item.ports.map(p => p.service || commonPorts[p.port] || `port-${p.port}`).join('; ');
                            csv.push(`"${item.hostname}","${item.ip}","${item.assetType}",${item.riskScore},"${item.riskBand}","${item.technologies.join('; ')}","${techVersionStr}","${portsStr}","${servicesStr}","${item.discoveryMethod}","${item.missionFunction}"`);
                          });
                          const blob = new Blob([csv.join('\n')], { type: 'text/csv' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url; a.download = `${scan.primaryDomain}_asset_inventory.csv`; a.click();
                          URL.revokeObjectURL(url);
                          toast.success(`Exported ${allItems.length} assets to CSV`);
                        }}
                      >
                        <Download className="h-3 w-3 mr-1" /> Export Full Inventory
                      </Button>
                    </div>

                    {/* Inventory Table */}
                    <div className="border rounded-lg overflow-auto max-h-[700px]">
                      <table className="w-full text-sm">
                        <thead className="bg-muted/50 sticky top-0 z-10">
                          <tr>
                            <th className="text-left px-3 py-2 font-medium">Domain Name</th>
                            <th className="text-left px-3 py-2 font-medium">IP Address</th>
                            <th className="text-left px-3 py-2 font-medium">Type</th>
                            <th className="text-left px-3 py-2 font-medium">Risk</th>
                            <th className="text-left px-3 py-2 font-medium">Technologies / Apps</th>
                            <th className="text-left px-3 py-2 font-medium">Ports & Services</th>
                            <th className="text-left px-3 py-2 font-medium">Creds</th>
                            <th className="text-left px-3 py-2 font-medium">Discovery</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {sorted.length === 0 ? (
                            <tr><td colSpan={11} className="px-3 py-8 text-center text-muted-foreground">No assets matching your filters</td></tr>
                          ) : sorted.map((item, i) => (
                            <tr key={i} className={`hover:bg-muted/20 ${item.riskBand === 'critical' ? 'bg-red-500/5' : item.riskBand === 'high' ? 'bg-orange-500/5' : ''}`}>
                              <td className="px-3 py-2">
                                <div>
                                  <p className="font-mono text-xs font-medium">{item.hostname}{item.ip && item.ip !== item.hostname && <span className="text-muted-foreground font-normal ml-1">({item.ip})</span>}</p>
                                  {item.essentialService && (
                                    <p className="text-[10px] text-muted-foreground mt-0.5">{item.essentialService}</p>
                                  )}
                                </div>
                              </td>
                              <td className="px-3 py-2">
                                {item.ip ? (
                                  <span className="font-mono text-xs">{item.ip}</span>
                                ) : (
                                  <span className="text-xs text-muted-foreground italic">unresolved</span>
                                )}
                              </td>
                              <td className="px-3 py-2">
                                <Badge variant="outline" className="text-[10px]">{item.assetType}</Badge>
                              </td>
                              <td className="px-3 py-2">
                                {item.riskScore > 0 ? (
                                  <Badge className={`text-[10px] ${
                                    item.riskBand === 'critical' ? 'bg-red-500/20 text-red-400 border-red-500/40' :
                                    item.riskBand === 'high' ? 'bg-orange-500/20 text-orange-400 border-orange-500/40' :
                                    item.riskBand === 'medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40' :
                                    'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                                  }`}>{item.riskScore} ({item.riskBand})</Badge>
                                ) : (
                                  <span className="text-xs text-muted-foreground">—</span>
                                )}
                              </td>
                              <td className="px-3 py-2">
                                <div className="flex flex-wrap gap-1 max-w-[280px]">
                                  {item.technologies.length > 0 ? (
                                    <>
                                      {item.technologies.slice(0, 5).map((t, j) => {
                                        const ver = item.technologyVersions[t];
                                        return (
                                          <Badge key={j} variant="secondary" className="text-[10px]">
                                            {t}{ver ? `/${ver}` : ''}
                                          </Badge>
                                        );
                                      })}
                                      {item.technologies.length > 5 && (
                                        <Badge variant="secondary" className="text-[10px]">+{item.technologies.length - 5}</Badge>
                                      )}
                                    </>
                                  ) : (
                                    <span className="text-[10px] text-muted-foreground italic">none detected</span>
                                  )}
                                </div>
                              </td>
                              <td className="px-3 py-2">
                                <div className="flex flex-wrap gap-1 max-w-[280px]">
                                  {item.ports.length > 0 ? (
                                    <>
                                      {item.ports.sort((a, b) => a.port - b.port).slice(0, 6).map((p, j) => {
                                        const label = p.service || commonPorts[p.port] || `port-${p.port}`;
                                        const isHighRisk = [21, 23, 3389, 5900, 445].includes(p.port);
                                        const hasVulns = p.vulns.length > 0;
                                        return (
                                          <Badge key={j} variant={hasVulns ? 'destructive' : 'outline'} className={`text-[10px] font-mono ${
                                            isHighRisk ? 'text-red-400 border-red-500/40' :
                                            hasVulns ? '' :
                                            'text-sky-400 border-sky-500/40'
                                          }`}>
                                            {p.port}/{label}{p.version ? ` (${p.version})` : ''}
                                          </Badge>
                                        );
                                      })}
                                      {item.ports.length > 6 && (
                                        <Badge variant="outline" className="text-[10px]">+{item.ports.length - 6}</Badge>
                                      )}
                                    </>
                                  ) : (
                                    <span className="text-[10px] text-muted-foreground italic">no ports</span>
                                  )}
                                </div>
                              </td>
                              <td className="px-3 py-2">
                                {(() => {
                                  const h = item.hostname?.toLowerCase() || '';
                                  const ip = item.ip || '';
                                  const confirmed = credentialTestSummary?.results?.filter((r: any) =>
                                    r.status === 'confirmed' && (r.host === h || r.host === ip)
                                  ) || [];
                                  const oem = oemCredentials?.filter((c: any) => {
                                    const techs = item.technologies.map((t: string) => t.toLowerCase());
                                    return techs.some((t: string) => t.includes(c.vendor?.toLowerCase() || '') || t.includes(c.product?.toLowerCase() || ''));
                                  }) || [];
                                  if (confirmed.length > 0) return <Badge variant="destructive" className="text-[10px] gap-0.5"><KeyRound className="h-2.5 w-2.5" />{confirmed.length}</Badge>;
                                  if (oem.length > 0) return <Badge variant="outline" className="text-[10px] text-amber-400 border-amber-500/30 gap-0.5"><KeyRound className="h-2.5 w-2.5" />{oem.length}</Badge>;
                                  return <span className="text-[10px] text-muted-foreground">—</span>;
                                })()}
                              </td>
                              <td className="px-3 py-2">
                                <Badge variant="outline" className={`text-[10px] ${
                                  item.discoveryMethod === 'dns_verified' ? 'text-emerald-400 border-emerald-500/40' :
                                  item.discoveryMethod === 'passive_recon' ? 'text-sky-400 border-sky-500/40' :
                                  item.discoveryMethod === 'header_detected' ? 'text-blue-400 border-blue-500/40' :
                                  'text-purple-400 border-purple-500/40'
                                }`}>
                                  {item.discoveryMethod === 'dns_verified' ? 'DNS Verified' :
                                   item.discoveryMethod === 'passive_recon' ? 'Passive Recon' :
                                   item.discoveryMethod === 'header_detected' ? 'Header Detected' :
                                   item.discoveryMethod === 'cert_transparency' ? 'Cert Transparency' :
                                   'Inferred'}
                                </Badge>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {sorted.length < allItems.length && (
                      <p className="text-xs text-muted-foreground">Showing {sorted.length} of {allItems.length} assets</p>
                    )}
                  </CardContent>
                </Card>
              </>
            );
          })()}
        </TabsContent>

        {/* Ports & Services Tab */}
        <TabsContent value="ports" className="space-y-4">
          {(() => {
            const ports = (pipeline?.discoveredPorts || []) as any[];
            // Also extract port info from asset DNS records and technologies
            // portSearch, portProtocolFilter, portSortBy are declared at component level

            // Group by IP for summary
            const ipGroups = new Map<string, any[]>();
            for (const p of ports) {
              const existing = ipGroups.get(p.ip) || [];
              existing.push(p);
              ipGroups.set(p.ip, existing);
            }

            const allVulns = new Set<string>();
            ports.forEach(p => (p.vulns || []).forEach((v: string) => allVulns.add(v)));

            const filtered = ports.filter(p => {
              if (portSearch) {
                const q = portSearch.toLowerCase();
                if (!p.ip.includes(q) && !(p.hostname || '').toLowerCase().includes(q) && !String(p.port).includes(q) && !(p.product || '').toLowerCase().includes(q)) return false;
              }
              if (portProtocolFilter !== 'all' && p.transport !== portProtocolFilter) return false;
              return true;
            }).sort((a: any, b: any) => {
              if (portSortBy === 'port') return a.port - b.port;
              if (portSortBy === 'ip') return a.ip.localeCompare(b.ip);
              return a.product.localeCompare(b.product);
            });

            const commonPorts: Record<number, string> = {
              21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
              110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
              995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
              3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
              8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch', 27017: 'MongoDB',
            };

            return (
              <>
                <Card className="bg-card/50">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Network className="h-5 w-5 text-sky-400" />
                      Open Ports & Services ({ports.length})
                    </CardTitle>
                    <CardDescription>
                      All open ports and running services identified across discovered assets via internet scan databases, InternetDB, and banner verification
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {/* Stats */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-sky-400">{ports.length}</p>
                        <p className="text-xs text-muted-foreground">Open Ports</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-purple-400">{ipGroups.size}</p>
                        <p className="text-xs text-muted-foreground">Unique IPs</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-emerald-400">{ports.filter(p => p.product).length}</p>
                        <p className="text-xs text-muted-foreground">Identified Services</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-amber-400">{ports.filter(p => p.version).length}</p>
                        <p className="text-xs text-muted-foreground">With Versions</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-red-400">{allVulns.size}</p>
                        <p className="text-xs text-muted-foreground">Associated CVEs</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-purple-400">{ports.filter((p: any) => p.cpes?.length > 0).length}</p>
                        <p className="text-xs text-muted-foreground">With CPE IDs</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-cyan-400">{ports.filter((p: any) => p.os).length}</p>
                        <p className="text-xs text-muted-foreground">OS Detected</p>
                      </div>
                    </div>

                    {/* IP Summary Cards */}
                    {ipGroups.size > 0 && ipGroups.size <= 20 && (
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                        {Array.from(ipGroups.entries()).map(([ip, ipPorts]) => (
                          <div key={ip} className="p-3 rounded-lg border border-border bg-muted/20">
                            <p className="font-mono text-xs font-semibold">{ip}</p>
                            <p className="text-[10px] text-muted-foreground mt-0.5">{ipPorts[0]?.hostname !== ip ? ipPorts[0]?.hostname : ''}</p>
                            <div className="flex flex-wrap gap-1 mt-1.5">
                              {ipPorts.sort((a: any, b: any) => a.port - b.port).map((p: any) => (
                                <Badge key={p.port} variant={p.vulns?.length > 0 ? 'destructive' : 'secondary'} className="text-[10px]">
                                  {p.port}{p.product ? `/${p.product}` : commonPorts[p.port] ? `/${commonPorts[p.port]}` : ''}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Filters */}
                    <div className="flex flex-wrap gap-3">
                      <div className="flex-1 min-w-[200px]">
                        <input
                          type="text"
                          placeholder="Search by IP, hostname, port, or service..."
                          value={portSearch}
                          onChange={(e) => setPortSearch(e.target.value)}
                          className="w-full px-3 py-2 text-sm rounded-md border border-border bg-background"
                        />
                      </div>
                      <select
                        value={portProtocolFilter}
                        onChange={(e) => setPortProtocolFilter(e.target.value)}
                        className="px-3 py-2 text-sm rounded-md border border-border bg-background"
                      >
                        <option value="all">All Protocols</option>
                        <option value="tcp">TCP</option>
                        <option value="udp">UDP</option>
                      </select>
                      <select
                        value={portSortBy}
                        onChange={(e) => setPortSortBy(e.target.value as any)}
                        className="px-3 py-2 text-sm rounded-md border border-border bg-background"
                      >
                        <option value="port">Sort by Port</option>
                        <option value="ip">Sort by IP</option>
                        <option value="product">Sort by Service</option>
                      </select>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          const csv = ['IP,Port,Transport,Service,Version,Hostname,Source,CVEs,CPEs,Banner,OS'];
                          ports.forEach(p => csv.push(`${p.ip},${p.port},${p.transport},${p.product},${p.version},${p.hostname},${p.source},"${(p.vulns || []).join('; ')}","${(p.cpes || []).join('; ')}","${(p.banner || '').replace(/"/g, '""')}",${p.os || ''}`));
                          const blob = new Blob([csv.join('\n')], { type: 'text/csv' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url; a.download = `${scan.primaryDomain}_ports.csv`; a.click();
                          URL.revokeObjectURL(url);
                          toast.success(`Exported ${ports.length} port entries`);
                        }}
                      >
                        <FileText className="h-3 w-3 mr-1" /> Export CSV
                      </Button>
                    </div>

                    {/* Port Table */}
                    <div className="border rounded-lg overflow-auto max-h-[600px]">
                      <table className="w-full text-sm">
                        <thead className="bg-muted/50 sticky top-0">
                          <tr>
                            <th className="text-left px-3 py-2 font-medium">IP Address</th>
                            <th className="text-left px-3 py-2 font-medium">Port</th>
                            <th className="text-left px-3 py-2 font-medium">Protocol</th>
                            <th className="text-left px-3 py-2 font-medium">Service</th>
                            <th className="text-left px-3 py-2 font-medium">Version</th>
                            <th className="text-left px-3 py-2 font-medium">Hostname</th>
                            <th className="text-left px-3 py-2 font-medium">CVEs</th>
                            <th className="text-left px-3 py-2 font-medium">CPE</th>
                            <th className="text-left px-3 py-2 font-medium">Banner</th>
                            <th className="text-left px-3 py-2 font-medium">OS</th>
                            <th className="text-left px-3 py-2 font-medium">Source</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {filtered.length === 0 ? (
                            <tr><td colSpan={11} className="px-3 py-8 text-center text-muted-foreground">
                              {ports.length === 0 ? 'No port data available. Port scanning requires internet scan databases API key or InternetDB data.' : 'No ports matching your filters'}
                            </td></tr>
                          ) : filtered.map((p: any, i: number) => (
                            <tr key={i} className={`hover:bg-muted/20 ${p.vulns?.length > 0 ? 'bg-red-500/5' : ''}`}>
                              <td className="px-3 py-2 font-mono text-xs">{p.ip}</td>
                              <td className="px-3 py-2">
                                <Badge variant="outline" className={`font-mono text-[10px] ${
                                  [21, 23, 3389, 5900].includes(p.port) ? 'text-red-400 border-red-500/40' :
                                  [22, 443, 993, 995].includes(p.port) ? 'text-emerald-400 border-emerald-500/40' :
                                  'text-sky-400 border-sky-500/40'
                                }`}>
                                  {p.port}{commonPorts[p.port] ? ` (${commonPorts[p.port]})` : ''}
                                </Badge>
                              </td>
                              <td className="px-3 py-2 text-xs text-muted-foreground uppercase">{p.transport}</td>
                              <td className="px-3 py-2 text-xs">{p.product || <span className="text-muted-foreground italic">unknown</span>}</td>
                              <td className="px-3 py-2 font-mono text-xs text-muted-foreground">{p.version || '—'}</td>
                              <td className="px-3 py-2 font-mono text-xs text-muted-foreground truncate max-w-[200px]">{p.hostname}</td>
                              <td className="px-3 py-2">
                                <div className="flex flex-wrap gap-1">
                                  {(p.vulns || []).slice(0, 3).map((v: string, j: number) => (
                                    <Badge key={j} variant="destructive" className="text-[10px]">{v}</Badge>
                                  ))}
                                  {(p.vulns || []).length > 3 && (
                                    <Badge variant="destructive" className="text-[10px]">+{p.vulns.length - 3}</Badge>
                                  )}
                                </div>
                              </td>
                              <td className="px-3 py-2">
                                <div className="flex flex-wrap gap-1">
                                  {(p.cpes || []).slice(0, 2).map((c: string, j: number) => (
                                    <Badge key={j} variant="outline" className="text-[9px] font-mono text-purple-400 border-purple-500/30">{c}</Badge>
                                  ))}
                                  {(p.cpes || []).length > 2 && (
                                    <span className="text-[9px] text-muted-foreground">+{p.cpes.length - 2}</span>
                                  )}
                                  {(!p.cpes || p.cpes.length === 0) && <span className="text-muted-foreground text-[10px]">—</span>}
                                </div>
                              </td>
                              <td className="px-3 py-2">
                                {p.banner ? (
                                  <span className="font-mono text-[9px] text-amber-400/80 truncate block max-w-[150px]" title={p.banner}>{p.banner.slice(0, 60)}{p.banner.length > 60 ? '…' : ''}</span>
                                ) : <span className="text-muted-foreground text-[10px]">—</span>}
                              </td>
                              <td className="px-3 py-2">
                                {p.os ? (
                                  <Badge variant="outline" className="text-[9px] text-cyan-400 border-cyan-500/30">{p.os}</Badge>
                                ) : <span className="text-muted-foreground text-[10px]">—</span>}
                              </td>
                              <td className="px-3 py-2">
                                <Badge variant="outline" className="text-[10px]">{p.source}</Badge>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {filtered.length < ports.length && (
                      <p className="text-xs text-muted-foreground">Showing {filtered.length} of {ports.length} port entries</p>
                    )}
                  </CardContent>
                </Card>
              </>
            );
          })()}
        </TabsContent>

        {/* Campaigns Tab */}
        {/* Recommended Adversaries Tab */}
        <TabsContent value="adversaries" className="space-y-4">
          {threatActorMatches ? (
            <>
              <Card className="bg-card/50">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="w-5 h-5 text-red-400" />
                    Threat Actor Analysis
                  </CardTitle>
                  <CardDescription>
                    {threatActorMatches.matchSummary}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-3 gap-4 text-center">
                    <div>
                      <div className="text-2xl font-bold text-red-400">{threatActorMatches.topMatches?.length || 0}</div>
                      <div className="text-xs text-muted-foreground">Matched Actors</div>
                    </div>
                    <div>
                      <div className="text-2xl font-bold text-amber-400">{threatActorMatches.totalCandidates || 0}</div>
                      <div className="text-xs text-muted-foreground">Total Analyzed</div>
                    </div>
                    <div>
                      <div className="text-2xl font-bold text-purple-400">
                        {threatActorMatches.topMatches?.filter((m: any) => m.matchScore >= 50).length || 0}
                      </div>
                      <div className="text-xs text-muted-foreground">High Relevance</div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {llmThreatAnalysis?.overallAssessment && (
                <Card className="bg-purple-500/5 border-purple-500/20">
                  <CardContent className="p-4">
                    <div className="flex items-start gap-2">
                      <Brain className="w-5 h-5 text-purple-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-sm font-semibold text-purple-400 mb-1">AI Threat Assessment</div>
                        <p className="text-sm text-muted-foreground">{llmThreatAnalysis.overallAssessment}</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              <div className="space-y-4">
                {(threatActorMatches.topMatches || []).map((actor: any, idx: number) => {
                  const llmMatch = llmThreatAnalysis?.enhancedMatches?.find((m: any) => m.actorId === actor.actorId || m.name === actor.name);
                  // Cross-reference with exploit matches
                  const actorTechIds = (actor.relevantTechniques || []).map((t: any) => t.id);
                  const matchedExploitTechs = exploitMatches?.matches?.filter((em: any) =>
                    em.techniques?.some((t: string) => actorTechIds.includes(t))
                  ) || [];
                  // Kill chain phases from actor's techniques
                  const killChainPhases = ['Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation', 'Installation', 'C2', 'Actions'];
                  const actorTactics = (actor.relevantTechniques || []).map((t: any) => t.tactic?.toLowerCase() || '');
                  const phaseMapping: Record<string, string[]> = {
                    'Reconnaissance': ['reconnaissance', 'discovery'],
                    'Weaponization': ['resource-development'],
                    'Delivery': ['initial-access'],
                    'Exploitation': ['execution', 'privilege-escalation'],
                    'Installation': ['persistence', 'defense-evasion'],
                    'C2': ['command-and-control', 'lateral-movement'],
                    'Actions': ['collection', 'exfiltration', 'impact'],
                  };
                  const activePhases = killChainPhases.filter(phase =>
                    phaseMapping[phase]?.some(tactic => actorTactics.includes(tactic))
                  );
                  // Sophistication level
                  const sophistication = actor.matchScore >= 70 ? 'Advanced' : actor.matchScore >= 40 ? 'Moderate' : 'Basic';
                  const sophColor = sophistication === 'Advanced' ? 'text-red-400 bg-red-500/10' : sophistication === 'Moderate' ? 'text-amber-400 bg-amber-500/10' : 'text-green-400 bg-green-500/10';

                  return (
                    <Card key={actor.actorId} className="bg-card/50 hover:bg-card/80 transition-colors border-l-2" style={{ borderLeftColor: actor.matchScore >= 70 ? '#ef4444' : actor.matchScore >= 50 ? '#f97316' : actor.matchScore >= 30 ? '#eab308' : '#22c55e' }}>
                      <CardContent className="p-4 space-y-3">
                        {/* Header Row */}
                        <div className="flex items-start justify-between">
                          <div className="flex items-center gap-3">
                            <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-red-500/20 text-red-400 font-bold text-lg">
                              {idx + 1}
                            </div>
                            <div>
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="font-bold text-base cursor-pointer hover:text-primary" onClick={() => navigate(`/threat-actors/${actor.actorId}`)}>
                                  {actor.name}
                                </span>
                                <Badge variant="outline" className={`text-[10px] ${
                                  actor.type === 'apt' ? 'text-red-400 border-red-500/30' :
                                  actor.type === 'ransomware' ? 'text-purple-400 border-purple-500/30' :
                                  actor.type === 'cybercrime' ? 'text-amber-400 border-amber-500/30' :
                                  'text-cyan-400 border-cyan-500/30'
                                }`}>{actor.type?.toUpperCase()}</Badge>
                                {actor.origin && (
                                  <Badge variant="outline" className="text-[10px]">
                                    <Globe className="w-3 h-3 mr-1" />{actor.origin}
                                  </Badge>
                                )}
                                <Badge className={`text-[10px] ${sophColor}`}>
                                  <Radar className="w-3 h-3 mr-1" />{sophistication}
                                </Badge>
                                <Badge className={`text-[10px] font-bold ${
                                  actor.matchScore >= 70 ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                                  actor.matchScore >= 50 ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40' :
                                  actor.matchScore >= 30 ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40' :
                                  'bg-green-500/20 text-green-400 border border-green-500/40'
                                }`}>
                                  {actor.matchScore}% Match
                                </Badge>
                              </div>
                              {/* Confidence Breakdown */}
                              <div className="flex gap-3 mt-1.5">
                                {actor.sectorScore != null && (
                                  <span className="text-[10px] text-muted-foreground">Sector: <span className="text-cyan-400 font-medium">{actor.sectorScore}%</span></span>
                                )}
                                {actor.techScore != null && (
                                  <span className="text-[10px] text-muted-foreground">Tech: <span className="text-purple-400 font-medium">{actor.techScore}%</span></span>
                                )}
                                {actor.regionScore != null && (
                                  <span className="text-[10px] text-muted-foreground">Region: <span className="text-amber-400 font-medium">{actor.regionScore}%</span></span>
                                )}
                                {actor.recencyScore != null && (
                                  <span className="text-[10px] text-muted-foreground">Recency: <span className="text-green-400 font-medium">{actor.recencyScore}%</span></span>
                                )}
                              </div>
                              <div className="flex flex-wrap gap-1 mt-1">
                                {actor.matchReasons?.map((reason: string, i: number) => (
                                  <span key={i} className="text-xs text-muted-foreground">
                                    {i > 0 && " · "}{reason}
                                  </span>
                                ))}
                              </div>
                            </div>
                          </div>
                          <div className="flex gap-2 shrink-0">
                            <Button size="sm" variant="outline" onClick={() => navigate(`/threat-actors/${actor.actorId}`)}>
                              <Eye className="w-3 h-3 mr-1" /> Intel
                            </Button>
                            <Button size="sm" className="bg-red-600 hover:bg-red-700" onClick={() => {
                              toast.info('Deploying adversary profile to emulation framework...');
                              navigate(`/threat-actors/${actor.actorId}`);
                            }}>
                              <Crosshair className="w-3 h-3 mr-1" /> Deploy Campaign
                            </Button>
                          </div>
                        </div>

                        {/* Kill Chain Visualization */}
                        <div className="bg-background/50 rounded-lg p-3">
                          <div className="text-[10px] text-muted-foreground mb-2 font-medium flex items-center gap-1">
                            <Activity className="w-3 h-3" /> CYBER KILL CHAIN COVERAGE
                          </div>
                          <div className="flex gap-0.5">
                            {killChainPhases.map((phase) => {
                              const isActive = activePhases.includes(phase);
                              return (
                                <div key={phase} className="flex-1 text-center">
                                  <div className={`h-2 rounded-sm transition-all ${
                                    isActive ? 'bg-red-500 shadow-sm shadow-red-500/30' : 'bg-muted/30'
                                  }`} />
                                  <div className={`text-[9px] mt-1 ${isActive ? 'text-red-400 font-medium' : 'text-muted-foreground/50'}`}>
                                    {phase}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                          <div className="text-[10px] text-muted-foreground mt-1.5">
                            {activePhases.length}/{killChainPhases.length} phases covered — {activePhases.length >= 5 ? 'Full lifecycle threat' : activePhases.length >= 3 ? 'Multi-phase capability' : 'Targeted capability'}
                          </div>
                        </div>

                        {/* AI Analysis */}
                        {llmMatch && (
                          <div className="space-y-2 bg-purple-500/5 rounded-lg p-3">
                            <div className="text-xs">
                              <span className="text-purple-400 font-medium flex items-center gap-1 mb-1"><Brain className="w-3 h-3" /> AI Rationale</span>
                              <span className="text-muted-foreground">{llmMatch.llmRationale}</span>
                            </div>
                            {llmMatch.attackScenario && (
                              <div className="text-xs">
                                <span className="text-orange-400 font-medium flex items-center gap-1 mb-1"><Target className="w-3 h-3" /> Predicted Attack Scenario</span>
                                <span className="text-muted-foreground">{llmMatch.attackScenario}</span>
                              </div>
                            )}
                          </div>
                        )}

                        {/* Exploit Cross-Reference */}
                        {matchedExploitTechs.length > 0 && (
                          <div className="bg-red-500/5 rounded-lg p-3">
                            <div className="text-[10px] text-red-400 font-medium mb-2 flex items-center gap-1">
                              <Bug className="w-3 h-3" /> {matchedExploitTechs.length} EXPLOIT{matchedExploitTechs.length > 1 ? 'S' : ''} AVAILABLE FOR THIS ACTOR'S TECHNIQUES
                            </div>
                            <div className="flex flex-wrap gap-1">
                              {matchedExploitTechs.slice(0, 4).map((em: any, i: number) => (
                                <Badge key={i} className="text-[10px] bg-red-500/10 text-red-400 border border-red-500/20">
                                  <Zap className="w-2.5 h-2.5 mr-1" />
                                  {em.cveId}: {em.metasploitCount || 0} exploits + {em.exploitDbCount || 0} EDB
                                </Badge>
                              ))}
                              {matchedExploitTechs.length > 4 && (
                                <Badge className="text-[10px] bg-red-500/10 text-red-300">+{matchedExploitTechs.length - 4} more</Badge>
                              )}
                            </div>
                          </div>
                        )}

                        {/* Techniques */}
                        {actor.relevantTechniques?.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {actor.relevantTechniques.slice(0, 8).map((t: any, i: number) => (
                              <Badge key={i} variant="secondary" className="text-[10px]">
                                {t.id}: {t.name}
                              </Badge>
                            ))}
                            {actor.relevantTechniques.length > 8 && (
                              <Badge variant="secondary" className="text-[10px]">+{actor.relevantTechniques.length - 8} more</Badge>
                            )}
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </>
          ) : (
            <Card className="bg-card/50">
              <CardContent className="p-8 text-center">
                <Shield className="w-12 h-12 text-muted-foreground mx-auto mb-3" />
                <h3 className="text-lg font-semibold">Threat Actor Matching</h3>
                <p className="text-muted-foreground text-sm mt-1 mb-4">
                  Threat actor matching was not available for this scan. Click below to run matching now.
                </p>
                <div className="flex gap-3 justify-center">
                  <Button
                    variant="outline"
                    className="border-red-500/30 text-red-400 hover:bg-red-500/10"
                    disabled={matchingRunning || matchThreatActorsMutation.isPending}
                    onClick={() => {
                      setMatchingRunning(true);
                      matchThreatActorsMutation.mutate({ scanId, useLLM: false });
                    }}
                  >
                    {matchingRunning ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Crosshair className="h-4 w-4 mr-2" />}
                    Run Threat Actor Matching
                  </Button>
                  <Button
                    className="bg-purple-600 hover:bg-purple-700"
                    disabled={matchingRunning || matchThreatActorsMutation.isPending}
                    onClick={() => {
                      setMatchingRunning(true);
                      matchThreatActorsMutation.mutate({ scanId, useLLM: true });
                    }}
                  >
                    {matchingRunning ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Brain className="h-4 w-4 mr-2" />}
                    Run with AI Enhancement
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="campaigns" className="space-y-4">
          {/* Exploit Arsenal */}
          {exploitMatches && exploitMatches.matches && exploitMatches.matches.length > 0 && (
            <Card className="border-red-500/30 bg-red-500/5">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Bug className="h-4 w-4 text-red-400" />
                    Exploit Arsenal
                    <Badge className="bg-red-500/20 text-red-400 text-[10px]">{exploitMatches.matches.length} CVEs matched</Badge>
                    {exploitMatches.remoteAccessCount > 0 && (
                      <Badge className="bg-orange-500/20 text-orange-400 text-[10px] animate-pulse">
                        <Zap className="h-3 w-3 mr-1" />
                        {exploitMatches.remoteAccessCount} Remote Access
                      </Badge>
                    )}
                  </CardTitle>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-xs border-red-500/30 text-red-400 hover:bg-red-500/10"
                      disabled={exploitDeploying || deployExploitsMutation.isPending}
                      onClick={() => {
                        setExploitDeploying(true);
                        deployExploitsMutation.mutate({ scanId });
                      }}
                    >
                      {exploitDeploying ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Target className="h-3 w-3 mr-1" />}
                      Deploy All to the emulation framework
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-xs border-purple-500/30 text-purple-400 hover:bg-purple-500/10"
                      disabled={createAdversaryMutation.isPending}
                      onClick={() => createAdversaryMutation.mutate({ scanId })}
                    >
                      {createAdversaryMutation.isPending ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Skull className="h-3 w-3 mr-1" />}
                      Create Adversary Profile
                    </Button>
                  </div>
                </div>
                <div className="flex gap-4 mt-2">
                  <div className="text-center">
                    <div className="text-lg font-bold text-red-400">{exploitMatches.totalMetasploit}</div>
                    <div className="text-[10px] text-muted-foreground">Exploit Modules</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-bold text-amber-400">{exploitMatches.totalExploitDb}</div>
                    <div className="text-[10px] text-muted-foreground">Public Exploit DB Entries</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-bold text-purple-400">{exploitMatches.totalCalderaAbilities}</div>
                    <div className="text-[10px] text-muted-foreground">Adversary Abilities</div>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-2 max-h-[400px] overflow-y-auto">
                {exploitMatches.matches.map((m: any) => (
                  <div key={m.cveId} className={`p-3 rounded-lg border ${m.isRemoteAccess ? 'border-orange-500/40 bg-orange-500/5' : 'border-border/50 bg-card/50'}`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge className={m.isRemoteAccess ? 'bg-orange-500/20 text-orange-400' : 'bg-red-500/20 text-red-400'} >
                          {m.cveId}
                        </Badge>
                        {m.isRemoteAccess && (
                          <Badge className="bg-orange-500/30 text-orange-300 text-[10px] animate-pulse">
                            <Zap className="h-3 w-3 mr-0.5" /> REMOTE ACCESS
                          </Badge>
                        )}
                        {m.corroborationTier && (
                          <CorroborationTierBadge tier={m.corroborationTier} size="xs" showTooltip={true} />
                        )}
                      </div>
                      <div className="flex items-center gap-1">
                        {m.metasploitModules?.length > 0 && (
                          <Badge className="bg-red-500/20 text-red-400 text-[10px]">
                            <Target className="h-3 w-3 mr-0.5" /> {m.metasploitModules.length} EXP
                          </Badge>
                        )}
                        {m.exploitDbEntries?.length > 0 && (
                          <Badge className="bg-amber-500/20 text-amber-400 text-[10px]">
                            <Database className="h-3 w-3 mr-0.5" /> {m.exploitDbEntries.length} EDB
                          </Badge>
                        )}
                      </div>
                    </div>
                    {/* Exploit Framework modules */}
                    {m.metasploitModules?.length > 0 && (
                      <div className="mt-2 space-y-1">
                        {m.metasploitModules.slice(0, 3).map((mod: any, i: number) => (
                          <div key={i} className="flex items-center gap-2 text-xs">
                            <span className="text-red-400 font-mono">{mod.modulePath}</span>
                            <Badge variant="outline" className="text-[10px]">{mod.moduleType}</Badge>
                            {mod.rank && <Badge variant="secondary" className="text-[10px]">{mod.rank}</Badge>}
                          </div>
                        ))}
                      </div>
                    )}
                    {/* public exploit databases entries */}
                    {m.exploitDbEntries?.length > 0 && (
                      <div className="mt-1 space-y-1">
                        {m.exploitDbEntries.slice(0, 2).map((edb: any, i: number) => (
                          <div key={i} className="flex items-center gap-2 text-xs">
                            <a href={edb.url} target="_blank" rel="noopener noreferrer" className="text-amber-400 hover:underline font-mono">
                              EDB-{edb.edbId}
                            </a>
                            <span className="text-muted-foreground truncate max-w-[300px]">{edb.description}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    {/* Emulation abilities */}
                    {m.calderaAbilities?.length > 0 && (
                      <div className="mt-1 flex gap-1 flex-wrap">
                        {m.calderaAbilities.map((ab: any, i: number) => (
                          <Badge key={i} className="bg-purple-500/20 text-purple-400 text-[10px]">
                            <Shield className="h-3 w-3 mr-0.5" /> {ab.name}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {campaigns.length === 0 ? (
            <Card>
              <CardContent className="p-8 text-center text-muted-foreground">
                No campaign recommendations generated.
              </CardContent>
            </Card>
          ) : (
            campaigns.map((c: any) => {
              const isExpanded = expandedCampaign === c.id;
              return (
                <Card key={c.id} className={`transition-all ${isExpanded ? "ring-1 ring-purple-500/40" : ""}`}>
                  <div
                    className="p-4 cursor-pointer"
                    onClick={() => setExpandedCampaign(isExpanded ? null : c.id)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${RISK_COLORS[c.priority] || RISK_COLORS.medium}`}>
                          <Crosshair className="h-4 w-4" />
                        </div>
                        <div>
                          <p className="font-semibold">{c.name}</p>
                          <p className="text-xs text-muted-foreground mt-0.5">{c.description?.slice(0, 120)}...</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <Badge className={RISK_COLORS[c.priority]}>{c.priority}</Badge>
                        <Badge variant="outline">{c.type?.replace("_", " ")}</Badge>
                        {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                      </div>
                    </div>
                  </div>

                  {isExpanded && (
                    <CardContent className="pt-0 pb-4 space-y-4 border-t border-border">
                      <p className="text-sm text-muted-foreground mt-3">{c.description}</p>

                      {/* Target Assets */}
                      {c.targetAssets?.length > 0 && (
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-2">Target Assets</p>
                          <div className="flex gap-1 flex-wrap">
                            {c.targetAssets.map((a: string) => (
                              <Badge key={a} variant="secondary" className="font-mono text-[10px]">{a}</Badge>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* MITRE Tactics */}
                      {c.mitreTactics?.length > 0 && (
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-2">MITRE ATT&CK Tactics</p>
                          <div className="flex gap-1 flex-wrap">
                            {c.mitreTactics.map((t: string) => (
                              <Badge key={t} className="bg-purple-500/20 text-purple-400 text-[10px]">{t}</Badge>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Attack Chain */}
                      {c.attackChain?.length > 0 && (
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-2">Attack Chain</p>
                          <div className="space-y-2">
                            {c.attackChain.map((step: any, i: number) => (
                              <div key={i} className="flex items-start gap-3">
                                <div className="w-6 h-6 rounded-full bg-purple-500/20 flex items-center justify-center shrink-0 mt-0.5">
                                  <span className="text-[10px] font-bold text-purple-400">{step.step}</span>
                                </div>
                                <div className="flex-1">
                                  <div className="flex items-center gap-2">
                                    <span className="text-sm font-medium">{step.phase}</span>
                                    <Badge variant="outline" className="text-[10px]">{step.technique}</Badge>
                                  </div>
                                  <p className="text-xs text-muted-foreground">{step.action}</p>
                                  <Badge variant="secondary" className="text-[10px] mt-1">{step.tool}</Badge>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Emulation Abilities */}
                      {c.calderaAbilities?.length > 0 && (
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-2">
                            <Shield className="h-3 w-3 inline mr-1" />
                            Adversary Abilities
                          </p>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {c.calderaAbilities.map((a: any, i: number) => (
                              <div key={i} className="p-2 rounded bg-red-500/5 border border-red-500/20">
                                <div className="flex items-center gap-2">
                                  <Target className="h-3 w-3 text-red-400" />
                                  <span className="text-sm font-medium">{a.name}</span>
                                </div>
                                <div className="flex gap-1 mt-1">
                                  <Badge variant="outline" className="text-[10px]">{a.tactic}</Badge>
                                  <Badge className="bg-red-500/20 text-red-400 text-[10px]">{a.technique}</Badge>
                                </div>
                                <p className="text-xs text-muted-foreground mt-1">{a.rationale}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Phishing Templates */}
                      {c.gophishTemplates?.length > 0 && (
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-2">
                            <Zap className="h-3 w-3 inline mr-1" />
                            Phishing Templates
                          </p>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {c.gophishTemplates.map((t: any, i: number) => (
                              <div key={i} className="p-2 rounded bg-blue-500/5 border border-blue-500/20">
                                <p className="text-sm font-medium">{t.name}</p>
                                <p className="text-xs text-muted-foreground mt-0.5">Subject: {t.subject}</p>
                                <div className="flex gap-1 mt-1">
                                  <Badge variant="outline" className="text-[10px]">{t.theme}</Badge>
                                  <Badge variant="secondary" className="text-[10px]">{t.targetPersona}</Badge>
                                </div>
                                <p className="text-xs text-muted-foreground mt-1">{t.rationale}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Create Engagement Button */}
                      <div className="pt-2">
                        <Button
                          size="sm"
                          className="bg-purple-600 hover:bg-purple-700"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/engagements/new?fromIntel=${scanId}&campaign=${c.id}`);
                          }}
                        >
                          <Zap className="h-4 w-4 mr-2" />
                          Create Engagement from This Campaign
                        </Button>
                      </div>
                    </CardContent>
                  )}
                </Card>
              );
            })
          )}
        </TabsContent>

        {/* Threat Model Tab */}
        <TabsContent value="threat-model" className="space-y-4">
          {scan.threatModelSummary && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <Brain className="h-4 w-4 text-purple-400" />
                  Threat Model Analysis
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="prose prose-sm prose-invert max-w-none">
                  <Streamdown>{scan.threatModelSummary}</Streamdown>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Tier Distribution */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Asset Tier Distribution</CardTitle>
              <CardDescription>Mission impact-based prioritization tiers</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-4 gap-3">
                {["tier0_critical", "tier1_high", "tier2_medium", "tier3_low"].map(tier => {
                  const count = assets.filter((a: any) => a.suggestedTier === tier).length;
                  const label = tier.replace("_", " ").replace("tier", "Tier ");
                  const colors: Record<string, string> = {
                    tier0_critical: "bg-red-500/20 text-red-400 border-red-500/40",
                    tier1_high: "bg-orange-500/20 text-orange-400 border-orange-500/40",
                    tier2_medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40",
                    tier3_low: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40",
                  };
                  return (
                    <div key={tier} className={`p-3 rounded-lg border text-center ${colors[tier]}`}>
                      <p className="text-2xl font-bold">{count}</p>
                      <p className="text-xs capitalize mt-1">{label}</p>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Attack Surface Summary */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Attack Surface by Asset Type</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {Object.entries(
                  assets.reduce((acc: Record<string, number>, a: any) => {
                    const t = a.assetType || "unknown";
                    acc[t] = (acc[t] || 0) + 1;
                    return acc;
                  }, {} as Record<string, number>)
                ).sort(([, a], [, b]) => (b as number) - (a as number)).map(([type, count]) => (
                  <div key={type} className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground w-32 capitalize">{type.replace(/_/g, " ")}</span>
                    <Progress value={((count as number) / assets.length) * 100} className="h-2 flex-1" />
                    <span className="text-xs font-mono w-6 text-right">{count as number}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Vulnerability Intelligence Tab */}
        <TabsContent value="vulns" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><VulnIntelSection scanId={scanId} /></Suspense>
        </TabsContent>

        {/* Breach Intelligence Tab */}
        <TabsContent value="breaches" className="space-y-4">
          {breachData ? (
            <>
              {/* Breach Summary Cards */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <Card className="border-red-500/30 bg-red-500/5">
                  <CardContent className="p-4 text-center">
                    <p className="text-3xl font-bold text-red-400">{breachData.totalExposures?.toLocaleString() || 0}</p>
                    <p className="text-xs text-muted-foreground mt-1">Total Breach Records</p>
                  </CardContent>
                </Card>
                <Card className="border-orange-500/30 bg-orange-500/5">
                  <CardContent className="p-4 text-center">
                    <p className="text-3xl font-bold text-orange-400">{breachData.credentialPairs || 0}</p>
                    <p className="text-xs text-muted-foreground mt-1">Credentials Exposed</p>
                  </CardContent>
                </Card>
                <Card className="border-yellow-500/30 bg-yellow-500/5">
                  <CardContent className="p-4 text-center">
                    <p className="text-3xl font-bold text-yellow-400">{breachData.uniqueBreachSources || 0}</p>
                    <p className="text-xs text-muted-foreground mt-1">Breach Sources</p>
                  </CardContent>
                </Card>
                <Card className="border-cyan-500/30 bg-cyan-500/5">
                  <CardContent className="p-4 text-center">
                    <p className="text-3xl font-bold text-cyan-400">{breachData.subdomainsDiscovered || 0}</p>
                    <p className="text-xs text-muted-foreground mt-1">Subdomains Found</p>
                  </CardContent>
                </Card>
                <Card className="border-purple-500/30 bg-purple-500/5">
                  <CardContent className="p-4 text-center">
                    <p className="text-3xl font-bold text-purple-400">{breachData.ipsDiscovered || 0}</p>
                    <p className="text-xs text-muted-foreground mt-1">IPs Discovered</p>
                  </CardContent>
                </Card>
              </div>

              {/* Credential Spray Status Indicator */}
              {scan.engagementId && (() => {
                const credQuery = trpc.engagementOps.getHarvestedCredentials.useQuery(
                  { engagementId: scan.engagementId! },
                  { enabled: !!scan.engagementId }
                );
                const stats = credQuery.data?.stats;
                if (!stats || stats.total === 0) return (
                  <Card className="border-zinc-500/30 bg-zinc-500/5">
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Crosshair className="h-5 w-5 text-zinc-400" />
                        <div className="flex-1">
                          <p className="text-sm font-semibold text-zinc-300">Credential Testing Queue</p>
                          <p className="text-xs text-muted-foreground">No credentials harvested yet. Use the "Send to Credential Testing" button on risk signals above to queue breach credentials for spray testing.</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
                const testedPct = stats.total > 0 ? Math.round((stats.tested / stats.total) * 100) : 0;
                const successPct = stats.tested > 0 ? Math.round((stats.successful / stats.tested) * 100) : 0;
                return (
                  <Card className={`border-${stats.successful > 0 ? 'red' : stats.tested > 0 ? 'emerald' : 'amber'}-500/30 bg-${stats.successful > 0 ? 'red' : stats.tested > 0 ? 'emerald' : 'amber'}-500/5`}>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-base flex items-center gap-2">
                        <Crosshair className={`h-4 w-4 ${stats.successful > 0 ? 'text-red-400' : stats.tested > 0 ? 'text-emerald-400' : 'text-amber-400'}`} />
                        Credential Spray Status
                        {stats.successful > 0 && <Badge className="text-[10px] bg-red-600/30 text-red-300 border-red-500/50 ml-2">{stats.successful} Valid</Badge>}
                      </CardTitle>
                      <CardDescription>{stats.total} credentials harvested from breach data — {stats.tested} tested, {stats.total - stats.tested} pending</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                        <div className="bg-muted/30 rounded-lg p-3 text-center">
                          <p className="text-xl font-bold">{stats.total}</p>
                          <p className="text-[10px] text-muted-foreground">Total Harvested</p>
                        </div>
                        <div className="bg-muted/30 rounded-lg p-3 text-center">
                          <p className="text-xl font-bold text-blue-400">{stats.withPasswords}</p>
                          <p className="text-[10px] text-muted-foreground">With Passwords</p>
                        </div>
                        <div className="bg-muted/30 rounded-lg p-3 text-center">
                          <p className="text-xl font-bold text-purple-400">{stats.withHashes}</p>
                          <p className="text-[10px] text-muted-foreground">With Hashes</p>
                        </div>
                        <div className="bg-muted/30 rounded-lg p-3 text-center">
                          <p className="text-xl font-bold text-amber-400">{stats.tested}</p>
                          <p className="text-[10px] text-muted-foreground">Tested</p>
                        </div>
                        <div className="bg-muted/30 rounded-lg p-3 text-center">
                          <p className={`text-xl font-bold ${stats.successful > 0 ? 'text-red-400' : 'text-emerald-400'}`}>{stats.successful}</p>
                          <p className="text-[10px] text-muted-foreground">Successful</p>
                        </div>
                      </div>
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-muted-foreground">Testing Progress</span>
                          <span className="font-mono">{testedPct}%</span>
                        </div>
                        <Progress value={testedPct} className="h-2" />
                      </div>
                      {stats.successful > 0 && (
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between text-xs">
                            <span className="text-red-400 font-medium">Success Rate (of tested)</span>
                            <span className="font-mono text-red-400">{successPct}%</span>
                          </div>
                          <Progress value={successPct} className="h-2" />
                        </div>
                      )}
                      {Object.keys(stats.bySource).length > 0 && (
                        <div className="text-xs text-muted-foreground">
                          <span className="font-medium">Sources:</span>{' '}
                          {Object.entries(stats.bySource).map(([src, cnt], i) => (
                            <span key={src}>{i > 0 ? ', ' : ''}{src} ({cnt as number})</span>
                          ))}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })()}

              {/* Breach Sources Table */}
              {breachData.breachSources?.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <Database className="h-4 w-4 text-red-400" />
                      Breach Database Sources
                    </CardTitle>
                    <CardDescription>Databases where {scan.primaryDomain} credentials and records were found</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {breachData.breachSources.map((source: string, i: number) => {
                        const breachObs = dehashedResult?.observations?.find((o: any) => o.name === source && o.tags?.includes('breach_database'));
                        const records = breachObs?.evidence?.total_records || '—';
                        const creds = breachObs?.evidence?.credentials_exposed || 0;
                        const hasPasswords = breachObs?.evidence?.has_passwords;
                        const hasHashes = breachObs?.evidence?.has_hashed_passwords;
                        return (
                          <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border/50">
                            <div className="flex items-center gap-3">
                              <div className={`w-2 h-2 rounded-full ${creds > 0 ? 'bg-red-500' : 'bg-yellow-500'}`} />
                              <div>
                                <p className="font-mono text-sm font-medium">{source}</p>
                                <p className="text-xs text-muted-foreground">
                                  {records} records
                                  {creds > 0 && <span className="text-red-400 ml-2">{creds} credentials exposed</span>}
                                </p>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              {hasPasswords && <Badge variant="outline" className="text-red-400 border-red-500/40 text-[10px]">Plaintext</Badge>}
                              {hasHashes && <Badge variant="outline" className="text-orange-400 border-orange-500/40 text-[10px]">Hashed</Badge>}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Breach Timeline Visualization */}
              {(() => {
                // Collect breach events with dates from all available connector results
                const allConnectorResults = pipeline?.passiveRecon?.connectorResults || [];
                const timelineEvents: Array<{
                  name: string;
                  date: string;
                  dateObj: Date;
                  records: number;
                  credentials: number;
                  hasPasswords: boolean;
                  hasHashes: boolean;
                  source: string;
                  classification: string;
                  severity: string;
                }> = [];
                const seenBreaches = new Set<string>();

                for (const cr of allConnectorResults) {
                  if (!cr.observations) continue;
                  for (const obs of cr.observations) {
                    const ev = obs.evidence || {};
                    // Extract breach date from various field names across connectors
                    const rawDate = ev.breach_date || ev.breachDate || ev.BreachDate || obs.firstSeen;
                    const breachName = ev.breach_name || ev.breachName || ev.database_name || ev.title || ev.Title || obs.name;
                    if (!rawDate || !breachName) continue;
                    // Skip non-breach observations
                    if (!obs.tags?.some((t: string) => ['breach_database', 'credential_breach', 'breach_summary', 'credentials_exposed', 'email-breach'].includes(t))) continue;
                    // Deduplicate by breach name
                    const key = breachName.toLowerCase().replace(/[^a-z0-9]/g, '');
                    if (seenBreaches.has(key)) continue;
                    seenBreaches.add(key);

                    const dateObj = new Date(rawDate);
                    if (isNaN(dateObj.getTime())) continue;

                    // Determine classification from tags
                    let classification = 'unknown';
                    if (obs.tags?.includes('first_party_breach')) classification = 'first_party';
                    else if (obs.tags?.includes('third_party_breach')) classification = 'third_party';
                    else if (obs.tags?.includes('credential_reuse')) classification = 'third_party';

                    timelineEvents.push({
                      name: breachName.replace(/^[🔴🟡] /, '').replace(/^(1st-Party|3rd-Party|Unclassified) Breach: /, ''),
                      date: rawDate,
                      dateObj,
                      records: ev.total_records || ev.credentials_exposed || ev.emailCount || ev.breachCount || 0,
                      credentials: ev.credentials_exposed || ev.email_count || 0,
                      hasPasswords: !!ev.has_passwords || !!ev.has_plaintext,
                      hasHashes: !!ev.has_hashed_passwords || !!ev.hash_types?.length,
                      source: cr.connector || 'unknown',
                      classification,
                      severity: ev.severity || obs.attribution?.severity_label || 'medium',
                    });
                  }
                }

                // Also extract from HIBP breach list observations
                const hibpResult = allConnectorResults.find((r: any) => r.connector === 'hibp');
                if (hibpResult?.observations) {
                  for (const obs of hibpResult.observations) {
                    const ev = obs.evidence || {};
                    if (ev.breachDate || ev.BreachDate) {
                      const breachName = ev.title || ev.Title || obs.name;
                      if (!breachName) continue;
                      const key = breachName.toLowerCase().replace(/[^a-z0-9]/g, '');
                      if (seenBreaches.has(key)) continue;
                      seenBreaches.add(key);
                      const dateObj = new Date(ev.breachDate || ev.BreachDate);
                      if (isNaN(dateObj.getTime())) continue;
                      timelineEvents.push({
                        name: breachName,
                        date: ev.breachDate || ev.BreachDate,
                        dateObj,
                        records: ev.pwnCount || ev.recordCount || 0,
                        credentials: 0,
                        hasPasswords: (ev.dataClasses || ev.DataClasses || []).some((dc: string) => /password/i.test(dc)),
                        hasHashes: (ev.dataClasses || ev.DataClasses || []).some((dc: string) => /hash/i.test(dc)),
                        source: 'hibp',
                        classification: 'third_party',
                        severity: ev.isSensitive ? 'critical' : 'medium',
                      });
                    }
                  }
                }

                if (timelineEvents.length === 0) return null;

                // Sort chronologically
                timelineEvents.sort((a, b) => a.dateObj.getTime() - b.dateObj.getTime());

                // Calculate timeline range
                const earliest = timelineEvents[0].dateObj;
                const latest = timelineEvents[timelineEvents.length - 1].dateObj;
                const rangeMs = latest.getTime() - earliest.getTime();
                const rangeYears = rangeMs / (365.25 * 24 * 60 * 60 * 1000);

                // Group by year for the year markers
                const yearGroups = new Map<number, typeof timelineEvents>();
                for (const ev of timelineEvents) {
                  const year = ev.dateObj.getFullYear();
                  if (!yearGroups.has(year)) yearGroups.set(year, []);
                  yearGroups.get(year)!.push(ev);
                }
                const sortedYears = [...yearGroups.keys()].sort();

                const classColor = (c: string) => c === 'first_party' ? 'text-red-400 border-red-500/40 bg-red-500/10' : c === 'third_party' ? 'text-amber-400 border-amber-500/40 bg-amber-500/10' : 'text-zinc-400 border-zinc-500/40 bg-zinc-500/10';
                const classLabel = (c: string) => c === 'first_party' ? '1st Party' : c === 'third_party' ? '3rd Party' : 'Unclassified';
                const dotColor = (c: string) => c === 'first_party' ? 'bg-red-500' : c === 'third_party' ? 'bg-amber-500' : 'bg-zinc-500';

                return (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base flex items-center gap-2">
                        <Calendar className="h-4 w-4 text-cyan-400" />
                        Breach Timeline
                        <Badge variant="outline" className="text-[10px] ml-2">{timelineEvents.length} breaches</Badge>
                      </CardTitle>
                      <CardDescription>
                        Chronological view of breach events affecting {scan.primaryDomain} — spanning {rangeYears < 1 ? 'less than a year' : `${Math.round(rangeYears)} year${Math.round(rangeYears) !== 1 ? 's' : ''}`}
                        {' '}({earliest.getFullYear()}–{latest.getFullYear()})
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      {/* Timeline summary stats */}
                      <div className="grid grid-cols-3 gap-3 mb-5">
                        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-center">
                          <p className="text-xl font-bold text-red-400">{timelineEvents.filter(e => e.classification === 'first_party').length}</p>
                          <p className="text-[10px] text-muted-foreground">1st Party Breaches</p>
                        </div>
                        <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3 text-center">
                          <p className="text-xl font-bold text-amber-400">{timelineEvents.filter(e => e.classification === 'third_party').length}</p>
                          <p className="text-[10px] text-muted-foreground">3rd Party Breaches</p>
                        </div>
                        <div className="bg-cyan-500/10 border border-cyan-500/20 rounded-lg p-3 text-center">
                          <p className="text-xl font-bold text-cyan-400">{timelineEvents.filter(e => e.hasPasswords).length}</p>
                          <p className="text-[10px] text-muted-foreground">With Passwords</p>
                        </div>
                      </div>

                      {/* Visual timeline */}
                      <div className="relative">
                        {/* Vertical line */}
                        <div className="absolute left-[18px] top-0 bottom-0 w-px bg-gradient-to-b from-cyan-500/50 via-amber-500/30 to-red-500/50" />

                        <div className="space-y-1">
                          {sortedYears.map((year) => {
                            const events = yearGroups.get(year)!;
                            return (
                              <div key={year}>
                                {/* Year marker */}
                                <div className="flex items-center gap-3 py-2">
                                  <div className="w-[37px] flex justify-center">
                                    <div className="w-3 h-3 rounded-full bg-cyan-500/30 border-2 border-cyan-500 z-10" />
                                  </div>
                                  <span className="text-xs font-bold text-cyan-400 font-mono">{year}</span>
                                  <div className="flex-1 h-px bg-cyan-500/20" />
                                  <span className="text-[10px] text-muted-foreground">{events.length} breach{events.length !== 1 ? 'es' : ''}</span>
                                </div>

                                {/* Events in this year */}
                                {events.map((ev, i) => (
                                  <div key={`${year}-${i}`} className="flex items-start gap-3 py-1.5 pl-1">
                                    {/* Timeline dot */}
                                    <div className="w-[37px] flex justify-center pt-1.5">
                                      <div className={`w-2.5 h-2.5 rounded-full ${dotColor(ev.classification)} z-10 ring-2 ring-background`} />
                                    </div>
                                    {/* Event card */}
                                    <div className={`flex-1 rounded-lg border p-3 ${ev.classification === 'first_party' ? 'border-red-500/30 bg-red-500/5' : ev.classification === 'third_party' ? 'border-amber-500/20 bg-amber-500/5' : 'border-zinc-500/20 bg-zinc-500/5'}`}>
                                      <div className="flex items-start justify-between gap-2">
                                        <div className="flex-1 min-w-0">
                                          <div className="flex items-center gap-2 flex-wrap">
                                            <p className="font-mono text-sm font-semibold truncate">{ev.name}</p>
                                            <Badge variant="outline" className={`text-[9px] px-1.5 py-0 ${classColor(ev.classification)}`}>
                                              {classLabel(ev.classification)}
                                            </Badge>
                                            {ev.hasPasswords && <Badge variant="outline" className="text-[9px] px-1.5 py-0 text-red-400 border-red-500/40">Plaintext</Badge>}
                                            {ev.hasHashes && <Badge variant="outline" className="text-[9px] px-1.5 py-0 text-orange-400 border-orange-500/40">Hashed</Badge>}
                                          </div>
                                          <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                                            <span className="font-mono">{ev.dateObj.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</span>
                                            {ev.records > 0 && <span>{ev.records.toLocaleString()} records</span>}
                                            {ev.credentials > 0 && <span className="text-red-400">{ev.credentials.toLocaleString()} credentials</span>}
                                            <span className="text-muted-foreground/60">via {ev.source}</span>
                                          </div>
                                        </div>
                                      </div>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            );
                          })}
                        </div>
                      </div>

                      {/* Timeline legend */}
                      <div className="flex items-center gap-4 mt-4 pt-3 border-t border-border/50 text-[10px] text-muted-foreground">
                        <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-red-500" /><span>1st Party (direct breach)</span></div>
                        <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-amber-500" /><span>3rd Party (credential reuse)</span></div>
                        <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-zinc-500" /><span>Unclassified</span></div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })()}

              {/* Dehashed Observations Detail */}
              {dehashedResult?.observations?.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <Fingerprint className="h-4 w-4 text-purple-400" />
                      Breach-Derived Intelligence
                    </CardTitle>
                    <CardDescription>Subdomains, IPs, and email patterns discovered from breach records</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {/* Subdomains from breaches */}
                      {(() => {
                        const subs = dehashedResult.observations.filter((o: any) => o.assetType === 'subdomain');
                        if (subs.length === 0) return null;
                        return (
                          <div>
                            <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                              <Globe className="h-3.5 w-3.5 text-cyan-400" />
                              Subdomains Discovered ({subs.length})
                            </h4>
                            <div className="flex flex-wrap gap-2">
                              {subs.map((s: any, i: number) => (
                                <Badge key={i} variant="outline" className="text-cyan-400 border-cyan-500/40 font-mono text-xs">
                                  {s.name}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        );
                      })()}

                      {/* IPs from breaches */}
                      {(() => {
                        const ips = dehashedResult.observations.filter((o: any) => o.assetType === 'ip');
                        if (ips.length === 0) return null;
                        return (
                          <div>
                            <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                              <Network className="h-3.5 w-3.5 text-orange-400" />
                              IP Addresses Associated ({ips.length})
                            </h4>
                            <div className="flex flex-wrap gap-2">
                              {ips.map((ip: any, i: number) => (
                                <Badge key={i} variant="outline" className="text-orange-400 border-orange-500/40 font-mono text-xs">
                                  {ip.name}
                                  {ip.evidence?.database_name && (
                                    <span className="text-muted-foreground ml-1">({ip.evidence.database_name})</span>
                                  )}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        );
                      })()}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Attribution */}
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <Shield className="h-3.5 w-3.5" />
                      <span>Data sourced from <a href="https://dehashed.com" target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:underline">Dehashed</a> — 15B+ breach records</span>
                    </div>
                    <span>Queried: {breachData.queriedAt ? new Date(breachData.queriedAt).toLocaleString() : '—'}</span>
                  </div>
                </CardContent>
              </Card>
            </>
          ) : (
            <Card>
              <CardContent className="p-12 text-center">
                <Database className="h-12 w-12 text-muted-foreground/50 mx-auto mb-4" />
                <p className="text-lg font-semibold">No Breach Data Available</p>
                <p className="text-sm text-muted-foreground mt-2">
                  {dehashedResult?.errors?.length > 0 ? (
                    <span className="text-yellow-400">{dehashedResult.errors[0]}</span>
                  ) : (
                    'Dehashed breach intelligence will be available on the next scan. Ensure DEHASHED_API_KEY and DEHASHED_EMAIL are configured.'
                  )}
                </p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Incident Intelligence Tab */}
        <TabsContent value="incidents" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><IncidentSearchTab incidentSearch={incidentSearch} /></Suspense>
        </TabsContent>

        {/* Affiliated Domains Tab */}
        <TabsContent value="affiliated-domains" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><AffiliatedDomainsTab affiliatedDomains={affiliatedDomains} scanId={scanId} /></Suspense>
        </TabsContent>

        {/* Discovery Coverage Tab */}
        <TabsContent value="coverage" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><DiscoveryCoverageTab scan={scan} pipeline={pipeline} /></Suspense>
        </TabsContent>

        {/* Scan Methods Tab */}
        <TabsContent value="methods" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><ScanMethodsTab assets={assets} scan={scan} /></Suspense>
        </TabsContent>

        {/* OSINT Sources Tab */}
        <TabsContent value="osint-sources" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><OsintSourcesTab /></Suspense>
        </TabsContent>

        {/* Vendor Risk Tab */}
        <TabsContent value="vendor-risk" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><VendorRiskTab scanId={scan.id} domain={scan.primaryDomain} pipeline={pipeline} assets={[...assets, ...subdomainAssets]} /></Suspense>
        </TabsContent>
        {/* Infrastructure Map Tab */}
        <TabsContent value="infra-map" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><InfrastructureMapTab scanId={scan.id} domain={scan.primaryDomain} /></Suspense>
        </TabsContent>
        {/* Discovery Context — 5-specialist asset intelligence enrichment */}
        <TabsContent value="discovery-context" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><DiscoveryContextTab scanId={scan.id} assets={assets} domain={scan.primaryDomain} sector={scan.sector} /></Suspense>
        </TabsContent>
        {/* Spider / Recursive Discovery Tab */}
        <TabsContent value="spider" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><RecursiveDiscoveryTab scanId={scan.id} domain={scan.primaryDomain} /></Suspense>
        </TabsContent>

        {/* Findings Tab */}
        <TabsContent value="findings" className="space-y-3">
          {(() => {
            const allFindings = assets.flatMap((a: any) =>
              ((a.postureFindings || []) as any[]).map((f: any) => ({ ...f, assetHostname: f.assetHostname || a.asset?.hostname || a.hostname, assetRisk: a.hybridRiskScore }))
            ).sort((a: any, b: any) => {
              // Sort: Confirmed first, then probable, then potential; within each tier by severity
              const tierOrder: Record<string, number> = { confirmed: 0, probable: 1, potential: 2, informational: 3 };
              const aTier = tierOrder[a.corroborationTier || "potential"] ?? 2;
              const bTier = tierOrder[b.corroborationTier || "potential"] ?? 2;
              if (aTier !== bTier) return aTier - bTier;
              if (a.kevListed && !b.kevListed) return -1;
              if (!a.kevListed && b.kevListed) return 1;
              if ((b.severity || 0) !== (a.severity || 0)) return (b.severity || 0) - (a.severity || 0);
              return (b.confidence || 0) - (a.confidence || 0);
            });

            if (allFindings.length === 0) {
              return (
                <Card>
                  <CardContent className="p-8 text-center text-muted-foreground">
                    No posture findings detected.
                  </CardContent>
                </Card>
              );
            }

            // Corroboration tier labels
            const tierLabels: Record<string, { label: string; icon: string; color: string; desc: string }> = {
              confirmed: { label: "CONFIRMED", icon: "✅", color: "text-emerald-400 bg-emerald-500/20 border-emerald-500/40", desc: "Version detected and matched to CVE affected range" },
              probable: { label: "PROBABLE", icon: "⚠️", color: "text-yellow-400 bg-yellow-500/20 border-yellow-500/40", desc: "Product detected but version unconfirmed — CVE exists for this product family" },
              potential: { label: "POTENTIAL", icon: "❓", color: "text-purple-400 bg-purple-500/20 border-purple-500/40", desc: "LLM-inferred risk — no CVE evidence, advisory only" },
              informational: { label: "INFORMATIONAL", icon: "ℹ️", color: "text-slate-400 bg-slate-500/20 border-slate-500/40", desc: "Out of scope or downgraded — informational only" },
            };

            // Summary counts by tier
            const confirmed = allFindings.filter((f: any) => f.corroborationTier === "confirmed");
            const probable = allFindings.filter((f: any) => f.corroborationTier === "probable");
            const potential = allFindings.filter((f: any) => !f.corroborationTier || f.corroborationTier === "potential");
            const informational = allFindings.filter((f: any) => f.corroborationTier === "informational");

            return (
              <>
                {/* Corroboration Summary */}
                <div className="grid grid-cols-4 gap-3 mb-4">
                  <Card className="border-emerald-500/30">
                    <CardContent className="p-3 text-center">
                      <p className="text-2xl font-bold text-emerald-400">{confirmed.length}</p>
                      <p className="text-[10px] text-emerald-400/80 font-semibold">CONFIRMED</p>
                      <p className="text-[9px] text-muted-foreground mt-0.5">Version-matched CVEs</p>
                    </CardContent>
                  </Card>
                  <Card className="border-yellow-500/30">
                    <CardContent className="p-3 text-center">
                      <p className="text-2xl font-bold text-yellow-400">{probable.length}</p>
                      <p className="text-[10px] text-yellow-400/80 font-semibold">PROBABLE</p>
                      <p className="text-[9px] text-muted-foreground mt-0.5">Product-match, version unconfirmed</p>
                    </CardContent>
                  </Card>
                  <Card className="border-purple-500/30">
                    <CardContent className="p-3 text-center">
                      <p className="text-2xl font-bold text-purple-400">{potential.length}</p>
                      <p className="text-[10px] text-purple-400/80 font-semibold">POTENTIAL</p>
                      <p className="text-[9px] text-muted-foreground mt-0.5">LLM-inferred, advisory only</p>
                    </CardContent>
                  </Card>
                  <Card className="border-slate-500/30">
                    <CardContent className="p-3 text-center">
                      <p className="text-2xl font-bold text-slate-400">{informational.length}</p>
                      <p className="text-[10px] text-slate-400/80 font-semibold">INFORMATIONAL</p>
                      <p className="text-[9px] text-muted-foreground mt-0.5">Out of scope / downgraded</p>
                    </CardContent>
                  </Card>
                </div>

                {/* Confirmed findings shown by default */}
                {(() => {
                  if (confirmed.length === 0) return null;
                  const info = tierLabels["confirmed"];
                  return (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 mt-2 mb-1">
                        <span className="text-sm">{info.icon}</span>
                        <Badge className={`text-[10px] ${info.color}`}>{info.label}</Badge>
                        <span className="text-[10px] text-muted-foreground">{info.desc}</span>
                        <span className="text-[10px] text-muted-foreground ml-auto">({confirmed.length} finding{confirmed.length !== 1 ? "s" : ""})</span>
                      </div>
                      {confirmed.map((f: any, i: number) => {
                        const confidencePct = Math.round((f.confidence || 0) * 100);
                        const findingKey = `${f.title}|${f.assetHostname || f.assetRef || ''}|${f.category || ''}`;
                        const isFP = fpHashes.has(findingKey) || f.previouslyMarkedFP || f.fpAutoFlagged;
                        return (
                          <Card key={`confirmed-${i}`} className={`${isFP ? "border-amber-500/40 opacity-60" : f.kevListed ? "border-red-500/40" : ""}`}>
                            <CardContent className="p-4">
                              {/* FP Auto-flag Banner */}
                              {isFP && (
                                <div className="flex items-center gap-2 mb-2 p-2 rounded-md bg-amber-500/10 border border-amber-500/30">
                                  <Flag className="h-4 w-4 text-amber-400 shrink-0" />
                                  <span className="text-[11px] text-amber-400 font-medium">Previously marked as False Positive by analyst</span>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    className="ml-auto h-6 px-2 text-[10px] text-emerald-400 hover:text-emerald-300"
                                    onClick={() => {
                                      // Find the asset for this finding
                                      const assetMatch = assets.find((a: any) => {
                                        const hostname = a.asset?.hostname || a.hostname;
                                        return hostname === f.assetHostname || hostname === f.assetRef;
                                      });
                                      // Find the FP record for this finding
                                      const fpRecord = (fpQuery.data || []).find((fp: any) => fp.findingHash === findingKey && fp.status === 'false_positive');
                                      if (fpRecord) {
                                        reinstateMutation.mutate({
                                          fpId: fpRecord.id,
                                          reason: 'Reinstated by analyst — finding is valid',
                                        });
                                      } else {
                                        toast.info('Could not find the FP record to reinstate.');
                                      }
                                    }}
                                    disabled={reinstateMutation.isPending}
                                  >
                                    <Undo2 className="h-3 w-3 mr-1" /> Reinstate
                                  </Button>
                                </div>
                              )}

                              {/* Header row with corroboration tier badge */}
                              <div className="flex items-start justify-between gap-3">
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                                    <Badge className="text-[9px] px-1.5 py-0 text-emerald-400 bg-emerald-500/20 border-emerald-500/40">CONFIRMED</Badge>
                                    <AlertTriangle className={`h-4 w-4 shrink-0 ${
                                      f.severity >= 8 ? "text-red-400" : f.severity >= 6 ? "text-orange-400" : f.severity >= 4 ? "text-yellow-400" : "text-emerald-400"
                                    }`} />
                                    {(() => { const t = (f.title || '').toLowerCase(); return (t.includes('remote code') || t.includes('rce') || t.includes('auth bypass') || t.includes('authentication bypass') || t.includes('ssrf') || t.includes('unauthenticated') || t.includes('pre-auth') || t.includes('command injection') || t.includes('sql injection')) ? <Badge className="text-[10px] bg-rose-600/30 text-rose-300 border-rose-500/50 animate-pulse"><ExternalLink className="h-3 w-3 mr-0.5" /> REMOTE ACCESS</Badge> : null; })()}
                                    <p className="font-semibold text-sm">{f.title}</p>
                                  </div>

                                  {/* CVE IDs as clickable links */}
                                  {f.cveIds?.length > 0 && (
                                    <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                                      <Bug className="h-3 w-3 text-cyan-400" />
                                      {f.cveIds.map((cve: string) => (
                                        <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer"
                                          className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 underline decoration-dotted">
                                          {cve}
                                        </a>
                                      ))}
                                    </div>
                                  )}

                                  {/* Version detection info */}
                                  {f.detectedVersion && (
                                    <div className="flex items-center gap-1 mt-1">
                                      <Database className="h-3 w-3 text-emerald-400" />
                                      <span className="text-[11px] text-emerald-400 font-mono">
                                        Detected version: {f.detectedVersion}
                                        {f.affectedVersions && <span className="text-muted-foreground/70"> (affected range: {f.affectedVersions})</span>}
                                      </span>
                                      {f.versionMatchConfirmed && <Badge className="text-[9px] bg-emerald-600/30 text-emerald-300 border-emerald-500/50 ml-1">VERSION MATCH</Badge>}
                                    </div>
                                  )}
                                  {/* NVD vulnerability description */}
                                  {f.nvdDescription && (
                                    <p className="text-[11px] text-muted-foreground mt-1 leading-relaxed">{f.nvdDescription}</p>
                                  )}
                                   {!f.detectedVersion && f.corroborationTier === "probable" && (
                                     <div className="mt-1 space-y-1">
                                       <div className="flex items-center gap-1">
                                         <AlertTriangle className="h-3 w-3 text-yellow-400" />
                                         <span className="text-[11px] text-yellow-400">Version not detected — product-family match only (severity capped)</span>
                                       </div>
                                       <div className="flex items-center gap-1.5 bg-yellow-500/10 rounded px-2 py-1 border border-yellow-500/20">
                                         <Search className="h-3 w-3 text-yellow-400 shrink-0" />
                                         <span className="text-[10px] text-yellow-300">Version enumeration recommended — run Nerva service scan, httpx banner grab, or authenticated version check to confirm and upgrade this finding</span>
                                       </div>
                                     </div>
                                   )}
                                </div>

                                <div className="flex gap-1.5 shrink-0 flex-wrap justify-end">
                                  {f.kevListed && (
                                    <Badge className="text-[10px] bg-red-600/30 text-red-300 border-red-500/50">
                                      <Skull className="h-3 w-3 mr-0.5" /> KEV
                                    </Badge>
                                  )}
                                  {f.kevListed && f.versionMatchConfirmed && (
                                    <Badge className="text-[10px] bg-emerald-600/30 text-emerald-300 border-emerald-500/50">
                                      <CheckCircle2 className="h-3 w-3 mr-0.5" /> CONFIRMED
                                    </Badge>
                                  )}
                                  {f.kevListed && !f.versionMatchConfirmed && (
                                    <Badge className="text-[10px] bg-amber-600/30 text-amber-300 border-amber-500/50">
                                      <ShieldQuestion className="h-3 w-3 mr-0.5" /> POTENTIAL
                                    </Badge>
                                  )}
                                  {f.exploitAvailable && !f.kevListed && (
                                    <Badge className="text-[10px] bg-orange-600/30 text-orange-300 border-orange-500/50">
                                      <Zap className="h-3 w-3 mr-0.5" /> Exploit
                                    </Badge>
                                  )}
                                  <Badge variant="outline" className="text-[10px]">Severity: {f.severity}/10</Badge>
                                  {f.cvssScore && <Badge variant="outline" className="text-[10px] text-cyan-400 border-cyan-500/40">CVSS: {f.cvssScore}</Badge>}
                                  <Badge variant="outline" className="text-[10px]">Likelihood: {f.likelihood}/10</Badge>
                                  {(() => {
                                    const isRemoteUnauth = f.cveIds?.some((cve: string) => {
                                      const t = (f.title || '').toLowerCase();
                                      return t.includes('remote code') || t.includes('rce') || t.includes('auth bypass') || t.includes('authentication bypass') || t.includes('ssrf') || t.includes('server-side request') || t.includes('unauthenticated') || t.includes('pre-auth') || t.includes('remote execution') || t.includes('command injection') || t.includes('sql injection');
                                    }) || (() => {
                                      const t = (f.title || '').toLowerCase();
                                      return t.includes('remote code') || t.includes('rce') || t.includes('auth bypass') || t.includes('authentication bypass') || t.includes('ssrf') || t.includes('server-side request') || t.includes('unauthenticated') || t.includes('pre-auth') || t.includes('remote execution') || t.includes('command injection') || t.includes('sql injection');
                                    })();
                                    return isRemoteUnauth ? (
                                      <Badge className="text-[10px] bg-rose-600/30 text-rose-300 border-rose-500/50 animate-pulse">
                                        <ExternalLink className="h-3 w-3 mr-0.5" /> REMOTE ACCESS
                                      </Badge>
                                    ) : null;
                                  })()}
                                </div>
                              </div>

                              {/* Affected assets */}
                              <div className="mt-2 flex items-center gap-3 flex-wrap text-[11px]">
                                <div className="flex items-center gap-1">
                                  <Server className="h-3 w-3 text-muted-foreground" />
                                  <span className="text-muted-foreground">Affected assets:</span>
                                  {(f.affectedAssets || [f.assetHostname || f.assetRef]).map((h: string, j: number) => (
                                    <span key={j} className="font-mono text-foreground bg-muted/50 px-1 rounded">{h}</span>
                                  ))}
                                </div>
                                <ConfidenceBadge score={f.confidence || 0} size="xs" showScore />
                              </div>

                              {/* ─── Source Attribution Block ─── */}
                              <div className="mt-3 p-2.5 rounded-lg bg-muted/20 border border-border/50 space-y-2">
                                <p className="text-[10px] font-bold text-foreground/80 flex items-center gap-1.5">
                                  <Fingerprint className="h-3 w-3 text-cyan-400" />
                                  Finding Attribution & Verification
                                </p>

                                {/* Source Method */}
                                <div className="flex items-start gap-2">
                                  <Badge className="text-[8px] bg-emerald-500/20 text-emerald-400 border-emerald-500/40 shrink-0 mt-0.5">SOURCE</Badge>
                                  <span className="text-[10px] text-muted-foreground">
                                    {f.corroborationTier === "confirmed"
                                      ? "DNS Verification + HTTP Banner Analysis → Vulnerability Feed Match (version-confirmed CVE)"
                                      : f.corroborationTier === "probable"
                                      ? "DNS Verification + Product Detection → Vulnerability Feed Match (product-family, version unconfirmed)"
                                      : f.corroborationTier === "informational"
                                      ? "Technology fingerprint only — downgraded to informational (out of scope or not exploitable)"
                                      : "LLM Passive Reconnaissance → Risk Inference (no CVE evidence)"}
                                  </span>
                                </div>

                                {/* Evidence Chain */}
                                {f.evidenceChain?.length > 0 && (
                                  <div className="flex items-start gap-2">
                                    <Badge className="text-[8px] bg-cyan-500/20 text-cyan-400 border-cyan-500/40 shrink-0 mt-0.5">EVIDENCE</Badge>
                                    <div className="space-y-0.5">
                                      {f.evidenceChain.map((step: string, j: number) => (
                                        <div key={j} className="flex items-start gap-1.5 text-[10px] text-muted-foreground">
                                          <span className="text-cyan-500/60 shrink-0 font-mono">{j + 1}.</span>
                                          <span>{step}</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {(!f.evidenceChain || f.evidenceChain.length === 0) && f.evidenceDetail && (
                                  <div className="flex items-start gap-2">
                                    <Badge className="text-[8px] bg-cyan-500/20 text-cyan-400 border-cyan-500/40 shrink-0 mt-0.5">EVIDENCE</Badge>
                                    <span className="text-[10px] text-muted-foreground italic">{f.evidenceDetail}</span>
                                  </div>
                                )}

                                {/* Verification Instructions */}
                                <div className="flex items-start gap-2">
                                  <Badge className="text-[8px] bg-purple-500/20 text-purple-400 border-purple-500/40 shrink-0 mt-0.5">VERIFY</Badge>
                                  <span className="text-[10px] text-muted-foreground">
                                    {f.cveIds?.length > 0
                                      ? `Verify CVE at NVD: ${f.cveIds.map((c: string) => `https://nvd.nist.gov/vuln/detail/${c}`).join(" | ")}${f.detectedVersion ? `. Confirm version ${f.detectedVersion} with: curl -I https://${f.assetHostname || f.assetRef || 'target'}` : ". Run active scan to confirm version."}`
                                      : f.kevListed
                                      ? `Verify at the KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog`
                                      : `This is an LLM-inferred risk. Perform manual assessment or active scanning to confirm.`}
                                  </span>
                                </div>

                                {/* False Positive Risk */}
                                <div className="flex items-start gap-2">
                                  <Badge className="text-[8px] bg-orange-500/20 text-orange-400 border-orange-500/40 shrink-0 mt-0.5">FP RISK</Badge>
                                  <span className="text-[10px] text-muted-foreground">
                                    {f.corroborationTier === "confirmed"
                                      ? "Low — version was detected and matched to CVE affected range. Server may have been patched without changing version string."
                                      : f.corroborationTier === "probable"
                                      ? "Medium — product was detected but version is unconfirmed. The running version may not be in the CVE's affected range."
                                      : f.corroborationTier === "informational"
                                      ? "N/A — this finding has been downgraded to informational. No exploitation expected."
                                      : "High — this risk was inferred by LLM analysis without specific CVE evidence. Treat as advisory only."}
                                  </span>
                                </div>
                              </div>

                              {/* Controls */}
                              {f.recommendedControls?.length > 0 && (
                                <div className="mt-2 flex gap-1 flex-wrap">
                                  <span className="text-[10px] text-muted-foreground mr-1">Controls:</span>
                                  {f.recommendedControls.map((c: string, j: number) => (
                                    <Badge key={j} variant="secondary" className="text-[10px]">{c}</Badge>
                                  ))}
                                </div>
                              )}

                              {/* Mark as False Positive Button */}
                              {!isFP && (
                                <div className="mt-3 pt-3 border-t border-border/30 flex items-center justify-between">
                                  <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                                    <MessageSquare className="h-3 w-3" />
                                    Is this finding incorrect? Help the LLM learn.
                                  </span>
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    className="h-7 px-3 text-[11px] text-amber-400 border-amber-500/40 hover:bg-amber-500/10"
                                    onClick={() => {
                                      const assetMatch = assets.find((a: any) => {
                                        const hostname = a.asset?.hostname || a.hostname;
                                        return hostname === f.assetHostname || hostname === f.assetRef;
                                      });
                                      setFpTarget({
                                        finding: f,
                                        assetId: assetMatch?.id || 0,
                                        findingIndex: i,
                                      });
                                      setFpDialogOpen(true);
                                    }}
                                  >
                                    <Flag className="h-3 w-3 mr-1" /> Mark as False Positive
                                  </Button>
                                </div>
                              )}
                            </CardContent>
                          </Card>
                        );
                      })}
                    </div>
                  );
                })()}

                {/* Probable Matches — behind collapsible */}
                {probable.length > 0 && (
                  <Collapsible className="mt-4">
                    <CollapsibleTrigger className="flex items-center gap-2 text-sm text-yellow-400 hover:text-yellow-300 transition-colors cursor-pointer group">
                      <ChevronDown className="h-4 w-4 transition-transform group-data-[state=open]:rotate-180" />
                      <span className="underline decoration-dotted underline-offset-4">Probable Matches ({probable.length})</span>
                      <span className="text-[10px] text-muted-foreground no-underline ml-1">Product detected, version unconfirmed — severity capped</span>
                    </CollapsibleTrigger>
                    <CollapsibleContent className="mt-3 space-y-2">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm">{tierLabels.probable.icon}</span>
                        <Badge className={`text-[10px] ${tierLabels.probable.color}`}>{tierLabels.probable.label}</Badge>
                        <span className="text-[10px] text-muted-foreground">{tierLabels.probable.desc}</span>
                        <span className="text-[10px] text-muted-foreground ml-auto">({probable.length} finding{probable.length !== 1 ? "s" : ""})</span>
                      </div>
                      <div className="flex items-start gap-2 bg-yellow-500/10 rounded-md px-3 py-2 border border-yellow-500/20 mb-2">
                        <Search className="h-4 w-4 text-yellow-400 shrink-0 mt-0.5" />
                        <div>
                          <p className="text-[11px] text-yellow-300 font-medium">Version Enumeration Recommended</p>
                          <p className="text-[10px] text-yellow-300/80 mt-0.5">These findings matched a known product but the specific version could not be confirmed passively. Run active version enumeration (Nerva service scan, httpx banner grab, or authenticated scan) to confirm versions and upgrade findings to confirmed tier.</p>
                        </div>
                      </div>
                      {probable.map((f: any, i: number) => {
                        const confidencePct = Math.round((f.confidence || 0) * 100);
                        const findingKey = `${f.title}|${f.assetHostname || f.assetRef || ''}|${f.category || ''}`;
                        const isFP = fpHashes.has(findingKey) || f.previouslyMarkedFP || f.fpAutoFlagged;
                        const pInfo = tierLabels.probable;
                        return (
                          <Card key={`probable-${i}`} className={`${isFP ? "border-amber-500/40 opacity-60" : "border-yellow-500/20 opacity-80"}`}>
                            <CardContent className="p-4">
                              {isFP && (
                                <div className="flex items-center gap-2 mb-2 p-2 rounded-md bg-amber-500/10 border border-amber-500/30">
                                  <Flag className="h-4 w-4 text-amber-400 shrink-0" />
                                  <span className="text-[11px] text-amber-400 font-medium">Previously marked as False Positive</span>
                                </div>
                              )}
                              <div className="flex items-start justify-between gap-3">
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                                    <Badge className={`text-[9px] px-1.5 py-0 ${pInfo.color}`}>{pInfo.label}</Badge>
                                    <AlertTriangle className="h-4 w-4 shrink-0 text-yellow-400/60" />
                                    <p className="font-semibold text-sm">{f.title}</p>
                                  </div>
                                  {f.cveIds?.length > 0 && (
                                    <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                                      <Bug className="h-3 w-3 text-cyan-400" />
                                      {f.cveIds.map((cve: string) => (
                                        <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer"
                                          className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 underline decoration-dotted">{cve}</a>
                                      ))}
                                    </div>
                                  )}
                                  <div className="flex items-center gap-1 mt-1">
                                    <AlertTriangle className="h-3 w-3 text-yellow-400" />
                                    <span className="text-[11px] text-yellow-400">Version not detected — product-family match only (severity capped)</span>
                                  </div>
                                  {f.nvdDescription && (
                                    <p className="text-[11px] text-muted-foreground mt-1 leading-relaxed">{f.nvdDescription}</p>
                                  )}
                                </div>
                                <div className="flex gap-1.5 shrink-0 flex-wrap justify-end">
                                  {f.kevListed && <Badge className="text-[10px] bg-red-600/30 text-red-300 border-red-500/50"><Skull className="h-3 w-3 mr-0.5" /> KEV</Badge>}
                                  {f.kevListed && f.versionMatchConfirmed && <Badge className="text-[10px] bg-emerald-600/30 text-emerald-300 border-emerald-500/50"><CheckCircle2 className="h-3 w-3 mr-0.5" /> CONFIRMED</Badge>}
                                  {f.kevListed && !f.versionMatchConfirmed && <Badge className="text-[10px] bg-amber-600/30 text-amber-300 border-amber-500/50"><ShieldQuestion className="h-3 w-3 mr-0.5" /> POTENTIAL</Badge>}
                                  <Badge variant="outline" className="text-[10px] text-yellow-400/70 border-yellow-500/30">Sev: {f.severity}/10 (capped)</Badge>
                                  <Badge variant="outline" className="text-[10px] text-muted-foreground/60">Likelihood: {f.likelihood}/10</Badge>
                                </div>
                              </div>
                              <div className="mt-2 flex items-center gap-3 flex-wrap text-[11px]">
                                <div className="flex items-center gap-1">
                                  <Server className="h-3 w-3 text-muted-foreground" />
                                  <span className="text-muted-foreground">Affected:</span>
                                  {(f.affectedAssets || [f.assetHostname || f.assetRef]).map((h: string, j: number) => (
                                    <span key={j} className="font-mono text-foreground bg-muted/50 px-1 rounded">{h}</span>
                                  ))}
                                </div>
                                <ConfidenceBadge score={f.confidence || 0} size="xs" showScore />
                              </div>
                              {!isFP && (
                                <div className="mt-3 pt-3 border-t border-border/30 flex items-center justify-between">
                                  <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                                    <MessageSquare className="h-3 w-3" /> Is this finding incorrect?
                                  </span>
                                  <Button variant="outline" size="sm" className="h-7 px-3 text-[11px] text-amber-400 border-amber-500/40 hover:bg-amber-500/10"
                                    onClick={() => {
                                      const assetMatch = assets.find((a: any) => { const hostname = a.asset?.hostname || a.hostname; return hostname === f.assetHostname || hostname === f.assetRef; });
                                      setFpTarget({ finding: f, assetId: assetMatch?.id || 0, findingIndex: i });
                                      setFpDialogOpen(true);
                                    }}>
                                    <Flag className="h-3 w-3 mr-1" /> Mark as False Positive
                                  </Button>
                                </div>
                              )}
                            </CardContent>
                          </Card>
                        );
                      })}
                    </CollapsibleContent>
                  </Collapsible>
                )}

                {/* Potential Matches — hidden behind collapsible hyperlink */}
                {potential.length > 0 && (
                  <Collapsible className="mt-4">
                    <CollapsibleTrigger className="flex items-center gap-2 text-sm text-purple-400 hover:text-purple-300 transition-colors cursor-pointer group">
                      <ChevronDown className="h-4 w-4 transition-transform group-data-[state=open]:rotate-180" />
                      <span className="underline decoration-dotted underline-offset-4">Potential Matches ({potential.length})</span>
                      <span className="text-[10px] text-muted-foreground no-underline ml-1">LLM-inferred, advisory only — not confirmed by CVE or version data</span>
                    </CollapsibleTrigger>
                    <CollapsibleContent className="mt-3 space-y-2">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm">{tierLabels.potential.icon}</span>
                        <Badge className={`text-[10px] ${tierLabels.potential.color}`}>{tierLabels.potential.label}</Badge>
                        <span className="text-[10px] text-muted-foreground">{tierLabels.potential.desc}</span>
                        <span className="text-[10px] text-muted-foreground ml-auto">({potential.length} finding{potential.length !== 1 ? "s" : ""})</span>
                      </div>
                      {potential.map((f: any, i: number) => {
                        const confidencePct = Math.round((f.confidence || 0) * 100);
                        const findingKey = `${f.title}|${f.assetHostname || f.assetRef || ''}|${f.category || ''}`;
                        const isFP = fpHashes.has(findingKey) || f.previouslyMarkedFP || f.fpAutoFlagged;
                        const info = tierLabels.potential;
                        return (
                          <Card key={`potential-${i}`} className={`${isFP ? "border-amber-500/40 opacity-60" : "border-purple-500/20 opacity-75"}`}>
                            <CardContent className="p-4">
                              {isFP && (
                                <div className="flex items-center gap-2 mb-2 p-2 rounded-md bg-amber-500/10 border border-amber-500/30">
                                  <Flag className="h-4 w-4 text-amber-400 shrink-0" />
                                  <span className="text-[11px] text-amber-400 font-medium">Previously marked as False Positive by analyst</span>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    className="ml-auto h-6 px-2 text-[10px] text-emerald-400 hover:text-emerald-300"
                                    onClick={() => {
                                      const assetMatch = assets.find((a: any) => {
                                        const hostname = a.asset?.hostname || a.hostname;
                                        return hostname === f.assetHostname || hostname === f.assetRef;
                                      });
                                      const fpRecord = (fpQuery.data || []).find((fp: any) => fp.findingHash === findingKey && fp.status === 'false_positive');
                                      if (fpRecord) {
                                        reinstateMutation.mutate({
                                          fpId: fpRecord.id,
                                          reason: 'Reinstated by analyst \u2014 finding is valid',
                                        });
                                      } else {
                                        toast.info('Could not find the FP record to reinstate.');
                                      }
                                    }}
                                    disabled={reinstateMutation.isPending}
                                  >
                                    <Undo2 className="h-3 w-3 mr-1" /> Reinstate
                                  </Button>
                                </div>
                              )}
                              <div className="flex items-start justify-between gap-3">
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                                    <Badge className={`text-[9px] px-1.5 py-0 ${info.color}`}>{info.label}</Badge>
                                    <AlertTriangle className="h-4 w-4 shrink-0 text-purple-400/50" />
                                    <p className="font-semibold text-sm">{f.title}</p>
                                  </div>
                                  {f.cveIds?.length > 0 && (
                                    <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                                      <Bug className="h-3 w-3 text-cyan-400" />
                                      {f.cveIds.map((cve: string) => (
                                        <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer"
                                          className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 underline decoration-dotted">
                                          {cve}
                                        </a>
                                      ))}
                                    </div>
                                  )}
                                </div>
                                <div className="flex gap-1.5 shrink-0 flex-wrap justify-end">
                                  <Badge variant="outline" className="text-[10px] text-muted-foreground/60 border-muted-foreground/30">NOT RATED</Badge>
                                  <Badge variant="outline" className="text-[10px] text-muted-foreground/50 border-muted-foreground/20">Advisory Only</Badge>
                                </div>
                              </div>
                              <div className="mt-2 flex items-center gap-3 flex-wrap text-[11px]">
                                <div className="flex items-center gap-1">
                                  <Server className="h-3 w-3 text-muted-foreground" />
                                  <span className="text-muted-foreground">Affected assets:</span>
                                  {(f.affectedAssets || [f.assetHostname || f.assetRef]).map((h: string, j: number) => (
                                    <span key={j} className="font-mono text-foreground bg-muted/50 px-1 rounded">{h}</span>
                                  ))}
                                </div>
                                <ConfidenceBadge score={f.confidence || 0} size="xs" showScore />
                              </div>
                              {!isFP && (
                                <div className="mt-3 pt-3 border-t border-border/30 flex items-center justify-between">
                                  <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                                    <MessageSquare className="h-3 w-3" />
                                    Is this finding incorrect? Help the LLM learn.
                                  </span>
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    className="h-7 px-3 text-[11px] text-amber-400 border-amber-500/40 hover:bg-amber-500/10"
                                    onClick={() => {
                                      const assetMatch = assets.find((a: any) => {
                                        const hostname = a.asset?.hostname || a.hostname;
                                        return hostname === f.assetHostname || hostname === f.assetRef;
                                      });
                                      setFpTarget({
                                        finding: f,
                                        assetId: assetMatch?.id || 0,
                                        findingIndex: i,
                                      });
                                      setFpDialogOpen(true);
                                    }}
                                  >
                                    <Flag className="h-3 w-3 mr-1" /> Mark as False Positive
                                  </Button>
                                </div>
                              )}
                            </CardContent>
                          </Card>
                        );
                      })}
                    </CollapsibleContent>
                  </Collapsible>
                )}

                {/* Informational — downgraded / out-of-scope findings */}
                {informational.length > 0 && (
                  <Collapsible className="mt-4">
                    <CollapsibleTrigger className="flex items-center gap-2 text-sm text-slate-400 hover:text-slate-300 transition-colors cursor-pointer group">
                      <ChevronDown className="h-4 w-4 transition-transform group-data-[state=open]:rotate-180" />
                      <span className="underline decoration-dotted underline-offset-4">Informational ({informational.length})</span>
                      <span className="text-[10px] text-muted-foreground no-underline ml-1">Downgraded or out-of-scope — informational only</span>
                    </CollapsibleTrigger>
                    <CollapsibleContent className="mt-3 space-y-2">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm">{tierLabels.informational.icon}</span>
                        <Badge className={`text-[10px] ${tierLabels.informational.color}`}>{tierLabels.informational.label}</Badge>
                        <span className="text-[10px] text-muted-foreground">{tierLabels.informational.desc}</span>
                        <span className="text-[10px] text-muted-foreground ml-auto">({informational.length} finding{informational.length !== 1 ? "s" : ""})</span>
                      </div>
                      {informational.map((f: any, i: number) => {
                        const info = tierLabels.informational;
                        return (
                          <Card key={`informational-${i}`} className="border-slate-500/20 opacity-60">
                            <CardContent className="p-4">
                              <div className="flex items-start justify-between gap-3">
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                                    <Badge className={`text-[9px] px-1.5 py-0 ${info.color}`}>{info.label}</Badge>
                                    <p className="font-semibold text-sm text-muted-foreground">{f.title}</p>
                                  </div>
                                  {f.analystNote && (
                                    <div className="mt-1 p-2 rounded bg-slate-500/10 border border-slate-500/20">
                                      <p className="text-[10px] text-slate-400 italic">
                                        <span className="font-semibold not-italic">Analyst Note:</span> {f.analystNote}
                                      </p>
                                    </div>
                                  )}
                                  {f.evidenceDetail && (
                                    <p className="text-[10px] text-muted-foreground/70 mt-1 italic">{f.evidenceDetail}</p>
                                  )}
                                </div>
                                <div className="flex gap-1.5 shrink-0 flex-wrap justify-end">
                                  <Badge variant="outline" className="text-[10px] text-slate-400/60 border-slate-500/30">INFORMATIONAL</Badge>
                                  <Badge variant="outline" className="text-[10px] text-muted-foreground/50 border-muted-foreground/20">Sev: {f.severity || 1}/10</Badge>
                                </div>
                              </div>
                              <div className="mt-2 flex items-center gap-3 flex-wrap text-[11px]">
                                <div className="flex items-center gap-1">
                                  <Server className="h-3 w-3 text-muted-foreground" />
                                  <span className="text-muted-foreground">Asset:</span>
                                  <span className="font-mono text-foreground bg-muted/50 px-1 rounded">{f.assetHostname || f.assetRef || 'N/A'}</span>
                                </div>
                              </div>
                            </CardContent>
                          </Card>
                        );
                      })}
                    </CollapsibleContent>
                  </Collapsible>
                )}
              </>
            );
          })()}
        </TabsContent>
        {/* Corroboration Tab */}
        <TabsContent value="corroboration" className="space-y-4">
          <CorroborationPanel assets={assets} scanId={scanId} autoRun={false} />
        </TabsContent>

        {/* Email Security Tab */}
        <TabsContent value="email-security" className="space-y-6">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><EmailSecurityTab pipeline={pipeline} domain={scan.primaryDomain} /></Suspense>
        </TabsContent>

        {/* DNS Security Tab */}
        <TabsContent value="dns-security" className="space-y-6">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><DnsSecurityTab pipeline={pipeline} domain={scan.primaryDomain} /></Suspense>
        </TabsContent>

        {/* Accuracy Insights Tab */}
        <TabsContent value="accuracy" className="space-y-6">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><AccuracyInsightsTab scanId={scanId} /></Suspense>
        </TabsContent>

        {/* ─── Changes Tab: Subdomain Change Detection ─── */}
        <TabsContent value="changes" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><ChangeDetectionTab scanId={scanId} /></Suspense>
        </TabsContent>

        {/* ─── Tech Vulns Tab: Technology Vulnerability CVE Cross-Reference ─── */}
        <TabsContent value="tech-vulns" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><TechVulnsTab scanId={scanId} /></Suspense>
        </TabsContent>

        {/* ─── Takeover Tab: Subdomain Takeover Detection ─── */}
        <TabsContent value="takeover" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><TakeoverTab scanId={scanId} /></Suspense>
        </TabsContent>

        {/* ─── CVE-to-Threat-Actor Enrichment Tab ─── */}
        <TabsContent value="cve-actors" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><CveActorEnrichmentTab scanId={scanId} /></Suspense>
        </TabsContent>

        {/* ─── Takeover PoC Validation Tab ─── */}
        <TabsContent value="takeover-poc" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><TakeoverPocTab scanId={scanId} /></Suspense>
        </TabsContent>

        {/* Default Credentials Tab */}
        {(credentialTestSummary || oemCredentials) && (
          <TabsContent value="credentials" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <KeyRound className="h-4 w-4 text-amber-400" />
                  OEM / Default Credential Test Results
                </CardTitle>
                <CardDescription>
                  Automated testing of manufacturer default credentials against discovered services.
                  Confirmed credentials represent verified access using factory-default username/password combinations.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Summary Stats */}
                {credentialTestSummary && (
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-muted/30 rounded-lg p-3 text-center">
                      <p className="text-2xl font-bold">{credentialTestSummary.tested || 0}</p>
                      <p className="text-[10px] text-muted-foreground">Services Tested</p>
                    </div>
                    <div className="bg-muted/30 rounded-lg p-3 text-center">
                      <p className={`text-2xl font-bold ${credentialTestSummary.confirmed > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                        {credentialTestSummary.confirmed || 0}
                      </p>
                      <p className="text-[10px] text-muted-foreground">Confirmed Access</p>
                    </div>
                    <div className="bg-muted/30 rounded-lg p-3 text-center">
                      <p className="text-2xl font-bold text-amber-400">{credentialTestSummary.failed || 0}</p>
                      <p className="text-[10px] text-muted-foreground">Auth Rejected</p>
                    </div>
                    <div className="bg-muted/30 rounded-lg p-3 text-center">
                      <p className="text-2xl font-bold text-zinc-400">{credentialTestSummary.errors || 0}</p>
                      <p className="text-[10px] text-muted-foreground">Connection Errors</p>
                    </div>
                  </div>
                )}

                {/* Confirmed Credentials Table */}
                {credentialTestSummary?.results?.filter((r: any) => r.status === 'confirmed').length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-red-400 tracking-wider mb-2 flex items-center gap-1.5">
                      <AlertTriangle className="h-3.5 w-3.5" /> CONFIRMED DEFAULT CREDENTIALS
                    </h4>
                    <div className="border border-red-500/20 rounded-lg overflow-hidden">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="bg-red-500/10 text-left">
                            <th className="px-3 py-2 font-medium">Service</th>
                            <th className="px-3 py-2 font-medium">Host</th>
                            <th className="px-3 py-2 font-medium">Port</th>
                            <th className="px-3 py-2 font-medium">Username</th>
                            <th className="px-3 py-2 font-medium">Vendor</th>
                            <th className="px-3 py-2 font-medium">Risk</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border/50">
                          {credentialTestSummary.results
                            .filter((r: any) => r.status === 'confirmed')
                            .map((r: any, i: number) => (
                              <tr key={i} className="hover:bg-red-500/5">
                                <td className="px-3 py-2 font-mono">{r.service || r.protocol}</td>
                                <td className="px-3 py-2 font-mono">{r.host}</td>
                                <td className="px-3 py-2 font-mono">{r.port}</td>
                                <td className="px-3 py-2 font-mono text-red-400">{r.username}</td>
                                <td className="px-3 py-2">{r.vendor || 'Unknown'}</td>
                                <td className="px-3 py-2">
                                  <Badge variant="destructive" className="text-[9px]">CRITICAL</Badge>
                                </td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* OEM Credential Matches (not yet tested or no test results) */}
                {oemCredentials?.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-amber-400 tracking-wider mb-2 flex items-center gap-1.5">
                      <KeyRound className="h-3.5 w-3.5" /> OEM CREDENTIAL MATCHES ({oemCredentials.length})
                    </h4>
                    <div className="border border-amber-500/20 rounded-lg overflow-hidden">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="bg-amber-500/10 text-left">
                            <th className="px-3 py-2 font-medium">Vendor</th>
                            <th className="px-3 py-2 font-medium">Product</th>
                            <th className="px-3 py-2 font-medium">Protocol</th>
                            <th className="px-3 py-2 font-medium">Username</th>
                            <th className="px-3 py-2 font-medium">Source</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border/50">
                          {oemCredentials.slice(0, 50).map((cred: any, i: number) => (
                            <tr key={i} className="hover:bg-amber-500/5">
                              <td className="px-3 py-2">{cred.vendor}</td>
                              <td className="px-3 py-2">{cred.product || cred.model || '-'}</td>
                              <td className="px-3 py-2 font-mono">{cred.protocol || cred.service || '-'}</td>
                              <td className="px-3 py-2 font-mono text-amber-400">{cred.username}</td>
                              <td className="px-3 py-2 text-muted-foreground">{cred.source || 'OEM Database'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      {oemCredentials.length > 50 && (
                        <p className="px-3 py-2 text-[10px] text-muted-foreground border-t border-border/50">
                          Showing 50 of {oemCredentials.length} matched credentials
                        </p>
                      )}
                    </div>
                  </div>
                )}

                {/* All Test Results */}
                {credentialTestSummary?.results?.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-muted-foreground tracking-wider mb-2">ALL TEST RESULTS</h4>
                    <div className="border border-border rounded-lg overflow-hidden">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="bg-muted/30 text-left">
                            <th className="px-3 py-2 font-medium">Status</th>
                            <th className="px-3 py-2 font-medium">Service</th>
                            <th className="px-3 py-2 font-medium">Host</th>
                            <th className="px-3 py-2 font-medium">Port</th>
                            <th className="px-3 py-2 font-medium">Username</th>
                            <th className="px-3 py-2 font-medium">Details</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border/50">
                          {credentialTestSummary.results.map((r: any, i: number) => (
                            <tr key={i} className="hover:bg-muted/20">
                              <td className="px-3 py-2">
                                <Badge
                                  variant={r.status === 'confirmed' ? 'destructive' : 'outline'}
                                  className={`text-[9px] ${
                                    r.status === 'confirmed' ? '' :
                                    r.status === 'failed' ? 'border-emerald-500/50 text-emerald-400' :
                                    'border-zinc-500/50 text-zinc-400'
                                  }`}
                                >
                                  {r.status?.toUpperCase()}
                                </Badge>
                              </td>
                              <td className="px-3 py-2 font-mono">{r.service || r.protocol}</td>
                              <td className="px-3 py-2 font-mono">{r.host}</td>
                              <td className="px-3 py-2 font-mono">{r.port}</td>
                              <td className="px-3 py-2 font-mono">{r.username}</td>
                              <td className="px-3 py-2 text-muted-foreground truncate max-w-[200px]">{r.error || r.details || '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {!credentialTestSummary && !oemCredentials?.length && (
                  <div className="text-center py-8">
                    <KeyRound className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-sm text-muted-foreground">No credential test data available for this scan</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        )}

        {/* Cross-Module Enrichment Tab */}
        {crossModuleEnrichment && (
          <TabsContent value="enrichment" className="space-y-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Card>
                <CardContent className="pt-4 pb-3">
                  <div className="text-xs text-muted-foreground">Modules Run</div>
                  <div className="text-2xl font-bold text-blue-400">{crossModuleEnrichment.summary?.modulesSucceeded || 0}/{crossModuleEnrichment.summary?.modulesRun || 0}</div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-4 pb-3">
                  <div className="text-xs text-muted-foreground">Correlations</div>
                  <div className="text-2xl font-bold text-purple-400">{crossModuleEnrichment.summary?.totalCorrelations || 0}</div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-4 pb-3">
                  <div className="text-xs text-muted-foreground">New Findings</div>
                  <div className="text-2xl font-bold text-amber-400">{crossModuleEnrichment.summary?.totalNewFindings || 0}</div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-4 pb-3">
                  <div className="text-xs text-muted-foreground">Risk Adjustments</div>
                  <div className="text-2xl font-bold text-red-400">{crossModuleEnrichment.summary?.totalRiskAdjustments || 0}</div>
                </CardContent>
              </Card>
            </div>

            {/* Bug Bounty Enrichment */}
            {crossModuleEnrichment.bugBounty?.status === "success" && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Bug className="h-4 w-4 text-green-400" />
                    Bug Bounty Intelligence
                    {crossModuleEnrichment.bugBounty.hasBugBountyProgram && (
                      <Badge variant="outline" className="text-green-400 border-green-400/30">Active Program</Badge>
                    )}
                  </CardTitle>
                  {crossModuleEnrichment.bugBounty.programName && (
                    <CardDescription>{crossModuleEnrichment.bugBounty.programName}</CardDescription>
                  )}
                </CardHeader>
                <CardContent className="space-y-4">
                  {crossModuleEnrichment.bugBounty.inScopeAssets?.length > 0 && (
                    <div>
                      <div className="text-xs text-muted-foreground mb-2">In-Scope Assets ({crossModuleEnrichment.bugBounty.inScopeAssets.length})</div>
                      <div className="flex flex-wrap gap-1">
                        {crossModuleEnrichment.bugBounty.inScopeAssets.map((a: string, i: number) => (
                          <Badge key={i} variant="outline" className="text-xs">{a}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {crossModuleEnrichment.bugBounty.historicalVulnPatterns?.length > 0 && (
                    <div>
                      <div className="text-xs text-muted-foreground mb-2">Historical Vulnerability Patterns</div>
                      <div className="space-y-1">
                        {crossModuleEnrichment.bugBounty.historicalVulnPatterns.slice(0, 8).map((p: any, i: number) => (
                          <div key={i} className="flex items-center justify-between text-xs">
                            <span className="font-mono text-blue-300">{p.cwe}</span>
                            <span className="text-muted-foreground">{p.count} reports</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* Threat Intelligence Enrichment */}
            {crossModuleEnrichment.threatIntel?.status === "success" && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Skull className="h-4 w-4 text-red-400" />
                    Threat Intelligence Correlation
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {crossModuleEnrichment.threatIntel.matchingThreatActors?.length > 0 && (
                    <div>
                      <div className="text-xs text-muted-foreground mb-2">Matching Threat Actors</div>
                      <div className="space-y-2">
                        {crossModuleEnrichment.threatIntel.matchingThreatActors.map((a: any, i: number) => (
                          <div key={i} className="flex items-center gap-2 p-2 rounded bg-red-500/5 border border-red-500/10">
                            <Target className="h-3 w-3 text-red-400" />
                            <span className="text-sm font-medium">{a.name}</span>
                            <Badge variant="outline" className="text-xs">{a.relevance}</Badge>
                            <div className="flex gap-1 ml-auto">
                              {a.techniques?.slice(0, 3).map((t: string, j: number) => (
                                <Badge key={j} variant="secondary" className="text-[10px]">{t}</Badge>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {crossModuleEnrichment.threatIntel.exploitPatternsMatched?.length > 0 && (
                    <div>
                      <div className="text-xs text-muted-foreground mb-2">Exploit Patterns Matched</div>
                      <div className="space-y-1">
                        {crossModuleEnrichment.threatIntel.exploitPatternsMatched.map((p: any, i: number) => (
                          <div key={i} className="text-xs p-2 rounded bg-amber-500/5 border border-amber-500/10">
                            <span className="text-amber-300">{p.pattern}</span>
                            <span className="text-muted-foreground ml-2">— {p.matchedAssets?.length || 0} assets affected</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* OpSec Enrichment */}
            {crossModuleEnrichment.opsec?.status === "success" && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <ShieldQuestion className="h-4 w-4 text-amber-400" />
                    OpSec & Defensive Gap Analysis
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {crossModuleEnrichment.opsec.defensiveGaps?.length > 0 && (
                    <div>
                      <div className="text-xs text-muted-foreground mb-2">Defensive Gaps ({crossModuleEnrichment.opsec.defensiveGaps.length})</div>
                      <div className="space-y-2">
                        {crossModuleEnrichment.opsec.defensiveGaps.map((g: any, i: number) => (
                          <div key={i} className="p-2 rounded bg-amber-500/5 border border-amber-500/10">
                            <div className="flex items-center gap-2">
                              <Badge variant={g.severity === 'critical' ? 'destructive' : g.severity === 'high' ? 'destructive' : 'outline'} className="text-[10px]">{g.severity}</Badge>
                              <span className="text-sm font-medium">{g.category}</span>
                            </div>
                            <p className="text-xs text-muted-foreground mt-1">{g.description}</p>
                            {g.affectedAssets?.length > 0 && (
                              <div className="flex gap-1 mt-1">
                                {g.affectedAssets.slice(0, 3).map((a: string, j: number) => (
                                  <Badge key={j} variant="secondary" className="text-[10px]">{a}</Badge>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {crossModuleEnrichment.opsec.misconfigurations?.length > 0 && (
                    <div>
                      <div className="text-xs text-muted-foreground mb-2">Common Misconfigurations</div>
                      <div className="space-y-1">
                        {crossModuleEnrichment.opsec.misconfigurations.map((m: any, i: number) => (
                          <div key={i} className="flex items-center justify-between text-xs p-1.5 rounded bg-muted/30">
                            <span>{m.type}</span>
                            <Badge variant="outline" className="text-[10px]">{m.impactLevel}</Badge>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* Discovery Deep Dive */}
            {crossModuleEnrichment.discoveryDeepDive?.status === "success" && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Telescope className="h-4 w-4 text-cyan-400" />
                    Discovery Deep Dive
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {crossModuleEnrichment.discoveryDeepDive.additionalSubdomains?.length > 0 && (
                    <div>
                      <div className="text-xs text-muted-foreground mb-2">Additional Subdomains ({crossModuleEnrichment.discoveryDeepDive.additionalSubdomains.length})</div>
                      <div className="flex flex-wrap gap-1">
                        {crossModuleEnrichment.discoveryDeepDive.additionalSubdomains.slice(0, 20).map((s: string, i: number) => (
                          <Badge key={i} variant="outline" className="text-xs font-mono">{s}</Badge>
                        ))}
                        {crossModuleEnrichment.discoveryDeepDive.additionalSubdomains.length > 20 && (
                          <Badge variant="secondary" className="text-xs">+{crossModuleEnrichment.discoveryDeepDive.additionalSubdomains.length - 20} more</Badge>
                        )}
                      </div>
                    </div>
                  )}
                  {crossModuleEnrichment.discoveryDeepDive.dnsHistory?.length > 0 && (
                    <div>
                      <div className="text-xs text-muted-foreground mb-2">DNS History Changes ({crossModuleEnrichment.discoveryDeepDive.dnsHistory.length})</div>
                      <div className="max-h-48 overflow-y-auto space-y-1">
                        {crossModuleEnrichment.discoveryDeepDive.dnsHistory.map((h: any, i: number) => (
                          <div key={i} className="flex items-center gap-2 text-xs p-1.5 rounded bg-muted/30">
                            <span className="font-mono text-cyan-300">{h.type || 'A'}</span>
                            <ArrowRightLeft className="h-3 w-3 text-muted-foreground" />
                            <span className="font-mono">{h.value || h.ip}</span>
                            {h.firstSeen && <span className="text-muted-foreground ml-auto">{h.firstSeen}</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {crossModuleEnrichment.discoveryDeepDive.certificateFindings?.length > 0 && (
                    <div>
                      <div className="text-xs text-muted-foreground mb-2">Certificate Findings ({crossModuleEnrichment.discoveryDeepDive.certificateFindings.length})</div>
                      <div className="space-y-1">
                        {crossModuleEnrichment.discoveryDeepDive.certificateFindings.slice(0, 10).map((c: any, i: number) => (
                          <div key={i} className="text-xs p-1.5 rounded bg-muted/30">
                            <span className="font-mono">{c.subject || c.cn}</span>
                            {c.issuer && <span className="text-muted-foreground ml-2">issued by {c.issuer}</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* Correlations */}
            {crossModuleEnrichment.correlations?.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <ArrowRightLeft className="h-4 w-4 text-purple-400" />
                    Cross-Module Correlations ({crossModuleEnrichment.correlations.length})
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {crossModuleEnrichment.correlations.map((c: any, i: number) => (
                      <div key={i} className="p-2 rounded border border-purple-500/10 bg-purple-500/5">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge variant="outline" className="text-[10px]">{c.sourceModule}</Badge>
                          <ArrowRightLeft className="h-3 w-3 text-muted-foreground" />
                          <Badge variant="outline" className="text-[10px]">{c.targetModule}</Badge>
                          <Badge variant={c.correlationType === 'confirms' ? 'default' : c.correlationType === 'contradicts' ? 'destructive' : 'secondary'} className="text-[10px] ml-auto">{c.correlationType}</Badge>
                        </div>
                        <p className="text-xs text-muted-foreground">{c.description}</p>
                        {c.relatedAssets?.length > 0 && (
                          <div className="flex gap-1 mt-1">
                            {c.relatedAssets.slice(0, 3).map((a: string, j: number) => (
                              <Badge key={j} variant="secondary" className="text-[10px] font-mono">{a}</Badge>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>
        )}

        {/* Post-Enrichment Analysis Tab */}
        {postEnrichmentAnalysis && (
          <TabsContent value="analysis" className="space-y-6">
            {/* Executive Analysis */}
            {postEnrichmentAnalysis.executiveAnalysis && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Brain className="h-4 w-4 text-purple-400" />
                    LLM Executive Analysis
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="prose prose-invert prose-sm max-w-none">
                    <Streamdown>{postEnrichmentAnalysis.executiveAnalysis}</Streamdown>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Attack Paths */}
            {postEnrichmentAnalysis.attackPaths?.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Route className="h-4 w-4 text-red-400" />
                    Attack Paths ({postEnrichmentAnalysis.attackPaths.length})
                  </CardTitle>
                  <CardDescription>LLM-identified attack chains through the discovered infrastructure</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  {postEnrichmentAnalysis.attackPaths.map((path: any, i: number) => (
                    <div key={i} className="p-3 rounded-lg border border-red-500/10 bg-red-500/5">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm font-medium">{path.name}</span>
                        <div className="flex items-center gap-2">
                          <Badge variant={path.likelihood === 'high' ? 'destructive' : path.likelihood === 'medium' ? 'default' : 'secondary'} className="text-[10px]">
                            {path.likelihood} likelihood
                          </Badge>
                          <Badge variant="outline" className="text-[10px]">
                            Impact: {path.impact}/10
                          </Badge>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground mb-2">{path.description}</p>
                      {path.steps?.length > 0 && (
                        <div className="space-y-1">
                          {path.steps.map((step: any, j: number) => (
                            <div key={j} className="flex items-center gap-2 text-xs">
                              <span className="text-red-400 font-mono w-5">{j + 1}.</span>
                              <span>{typeof step === 'string' ? step : step.description || step.action}</span>
                              {step.technique && <Badge variant="secondary" className="text-[10px] ml-auto">{step.technique}</Badge>}
                            </div>
                          ))}
                        </div>
                      )}
                      {path.mitigations?.length > 0 && (
                        <div className="mt-2 pt-2 border-t border-red-500/10">
                          <div className="text-[10px] text-muted-foreground mb-1">Mitigations:</div>
                          <div className="space-y-0.5">
                            {path.mitigations.map((m: string, j: number) => (
                              <div key={j} className="text-xs text-green-400/80 flex items-center gap-1">
                                <ShieldCheck className="h-3 w-3" />{m}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* Blind Spots */}
            {postEnrichmentAnalysis.blindSpots?.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Eye className="h-4 w-4 text-amber-400" />
                    Blind Spots ({postEnrichmentAnalysis.blindSpots.length})
                  </CardTitle>
                  <CardDescription>Areas where current scanning may have missed critical information</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  {postEnrichmentAnalysis.blindSpots.map((spot: any, i: number) => (
                    <div key={i} className="p-2 rounded border border-amber-500/10 bg-amber-500/5">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm font-medium">{spot.area || spot.name}</span>
                        <Badge variant={spot.severity === 'critical' ? 'destructive' : spot.severity === 'high' ? 'destructive' : 'outline'} className="text-[10px] ml-auto">{spot.severity}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground">{spot.description}</p>
                      {spot.recommendation && (
                        <p className="text-xs text-blue-400/80 mt-1">Recommendation: {spot.recommendation}</p>
                      )}
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* Prioritized Recommendations */}
            {postEnrichmentAnalysis.prioritizedRecommendations?.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Lightbulb className="h-4 w-4 text-green-400" />
                    Prioritized Recommendations ({postEnrichmentAnalysis.prioritizedRecommendations.length})
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  {postEnrichmentAnalysis.prioritizedRecommendations.map((rec: any, i: number) => (
                    <div key={i} className="p-2 rounded border border-green-500/10 bg-green-500/5">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-mono text-green-400 w-5">#{i + 1}</span>
                        <span className="text-sm font-medium">{rec.title || rec.recommendation}</span>
                        <Badge variant={rec.priority === 'critical' ? 'destructive' : rec.priority === 'high' ? 'destructive' : 'outline'} className="text-[10px] ml-auto">{rec.priority}</Badge>
                      </div>
                      {rec.description && <p className="text-xs text-muted-foreground pl-6">{rec.description}</p>}
                      {rec.affectedAssets?.length > 0 && (
                        <div className="flex gap-1 mt-1 pl-6">
                          {rec.affectedAssets.slice(0, 4).map((a: string, j: number) => (
                            <Badge key={j} variant="secondary" className="text-[10px] font-mono">{a}</Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* Enrichment Sources */}
            {postEnrichmentAnalysis.enrichmentSources?.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Workflow className="h-4 w-4 text-blue-400" />
                    Enrichment Sources Used
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-1">
                    {postEnrichmentAnalysis.enrichmentSources.map((s: string, i: number) => (
                      <Badge key={i} variant="outline" className="text-xs">{s}</Badge>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>
        )}

        {/* ─── Web Crawl Results Tab ─── */}
        <TabsContent value="web-crawl" className="space-y-4">
          <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><WebCrawlResultsTab scanId={scanId} /></Suspense>
        </TabsContent>

        {/* ─── Entity Profile & BIA Tab ─── */}
        {pipeline?.entityProfile && (
          <TabsContent value="entity-profile" className="space-y-4">
            <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><EntityProfileTab entityProfile={pipeline.entityProfile} financialImpact={pipeline.financialImpact} scanId={scanId} domain={scan.primaryDomain} /></Suspense>
          </TabsContent>
        )}

        {/* ─── Vendor Alert Correlation Tab ─── */}
        {pipeline?.vendorCorrelation && (
          <TabsContent value="vendor-alerts" className="space-y-4">
            <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}><VendorAlertCorrelationTab correlation={pipeline.vendorCorrelation} domain={scan.domain} /></Suspense>
          </TabsContent>
        )}

        {/* ─── Domain Health Tabs ─── */}
        {['health-overview', 'health-blacklist', 'health-mail', 'health-mail-security', 'health-mail-ports', 'health-dns', 'health-connectivity', 'health-all', 'health-registration'].map(tab => (
          <TabsContent key={tab} value={tab} className="space-y-4">
            <Suspense fallback={<div className="flex items-center justify-center p-8"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>}>
              <DomainHealthTab report={domainHealth} activeSubTab={tab} domainRegistration={pipeline?.domainRegistration} />
            </Suspense>
          </TabsContent>
        ))}

        {/* ─── Framework Mapping Tab ─── */}
        <TabsContent value="frameworkmapping" className="space-y-4">
          <ComplianceFrameworkSelector
            scanSource="di"
            scanId={scanId}
          />
        </TabsContent>

      </Tabs>

      {/* ─── False Positive Reason Dialog ─── */}
      <Dialog open={fpDialogOpen} onOpenChange={setFpDialogOpen}>
        <DialogContent className="sm:max-w-[520px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Flag className="h-5 w-5 text-amber-400" />
              Mark Finding as False Positive
            </DialogTitle>
            <DialogDescription>
              Your feedback helps the LLM learn. On future scans, findings matching this pattern will have reduced confidence or be auto-flagged.
            </DialogDescription>
          </DialogHeader>

          {fpTarget && (
            <div className="space-y-4">
              {/* Finding being marked */}
              <div className="p-3 rounded-lg bg-muted/30 border border-border/50">
                <p className="text-sm font-semibold">{fpTarget.finding.title}</p>
                <div className="flex items-center gap-2 mt-1 text-[11px] text-muted-foreground">
                  <span>Severity: {fpTarget.finding.severity}/10</span>
                  <span>·</span>
                  <span>Asset: {fpTarget.finding.assetHostname || fpTarget.finding.assetRef || 'Unknown'}</span>
                  {fpTarget.finding.cveIds?.length > 0 && (
                    <><span>·</span><span>{fpTarget.finding.cveIds.join(', ')}</span></>
                  )}
                </div>
              </div>

              {/* Reason Template Selector */}
              <div className="space-y-2">
                <label className="text-sm font-medium">Why is this a false positive?</label>
                <Select value={fpReasonTemplate} onValueChange={setFpReasonTemplate}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select a reason..." />
                  </SelectTrigger>
                  <SelectContent>
                    {FP_REASON_TEMPLATES.map(t => (
                      <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Custom Reason Text */}
              <div className="space-y-2">
                <label className="text-sm font-medium">
                  {fpReasonTemplate === 'custom' ? 'Describe why this is a false positive:' : 'Additional details (optional):'}
                </label>
                <Textarea
                  placeholder="e.g., We patched this last week but the banner still shows the old version string. Internal ticket #SEC-1234."
                  value={fpReasonCustom}
                  onChange={(e) => setFpReasonCustom(e.target.value)}
                  rows={3}
                  className="text-sm"
                />
                <p className="text-[10px] text-muted-foreground">
                  💡 The more detail you provide, the better the LLM learns. Include ticket numbers, dates, or specific technical context.
                </p>
              </div>
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => { setFpDialogOpen(false); setFpTarget(null); setFpReasonTemplate(''); setFpReasonCustom(''); }}>
              Cancel
            </Button>
            <Button
              className="bg-amber-600 hover:bg-amber-700 text-white"
              disabled={!fpReasonTemplate || (fpReasonTemplate === 'custom' && !fpReasonCustom.trim()) || markFPMutation.isPending}
              onClick={() => {
                if (!fpTarget) return;
                const templateLabel = FP_REASON_TEMPLATES.find(t => t.value === fpReasonTemplate)?.label || fpReasonTemplate;
                const fullReason = fpReasonTemplate === 'custom'
                  ? fpReasonCustom.trim()
                  : fpReasonCustom.trim()
                    ? `${templateLabel}: ${fpReasonCustom.trim()}`
                    : templateLabel;
                markFPMutation.mutate({
                  scanId,
                  assetId: fpTarget.assetId,
                  findingIndex: fpTarget.findingIndex,
                  findingTitle: fpTarget.finding.title,
                  findingType: fpTarget.finding.category || undefined,
                  findingSeverity: fpTarget.finding.severity?.toString() || null,
                  reason: fullReason,
                });
              }}
            >
              {markFPMutation.isPending ? (
                <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Submitting...</>
              ) : (
                <><Flag className="h-4 w-4 mr-2" /> Confirm False Positive</>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Test Plan Dialog ── */}
      <Dialog open={testPlanDialogOpen} onOpenChange={setTestPlanDialogOpen}>
        <DialogContent className="max-w-4xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ClipboardCheck className="h-5 w-5 text-emerald-400" />
              PTES/NIST Test Plan
            </DialogTitle>
            <DialogDescription>
              Automated test plan generated from domain intelligence findings, structured per PTES phases and NIST SP 800-115.
            </DialogDescription>
          </DialogHeader>
          {testPlanResult && (
            <div className="space-y-4">
              {/* Summary metrics */}
              <div className="grid grid-cols-4 gap-3">
                <div className="rounded-lg border bg-card p-3 text-center">
                  <div className="text-2xl font-bold text-emerald-400">{testPlanResult.structuredData?.schedule?.totalDays || '—'}</div>
                  <div className="text-xs text-muted-foreground">Est. Days</div>
                </div>
                <div className="rounded-lg border bg-card p-3 text-center">
                  <div className="text-2xl font-bold text-cyan-400">{testPlanResult.structuredData?.attackVectors?.length || 0}</div>
                  <div className="text-xs text-muted-foreground">Attack Vectors</div>
                </div>
                <div className="rounded-lg border bg-card p-3 text-center">
                  <div className="text-2xl font-bold text-amber-400">{testPlanResult.structuredData?.tools?.length || 0}</div>
                  <div className="text-xs text-muted-foreground">Tools</div>
                </div>
                <div className="rounded-lg border bg-card p-3 text-center">
                  <div className="text-2xl font-bold text-purple-400">{testPlanResult.sections?.length || 0}</div>
                  <div className="text-xs text-muted-foreground">PTES Sections</div>
                </div>
              </div>

              {/* PTES sections */}
              {testPlanResult.sections?.map((section: any, idx: number) => (
                <Collapsible key={idx} defaultOpen={idx < 3}>
                  <CollapsibleTrigger className="flex items-center justify-between w-full p-3 rounded-lg border bg-card hover:bg-accent/50 transition-colors">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-xs">{section.ptesPhase || `Phase ${idx + 1}`}</Badge>
                      <span className="font-medium text-sm">{section.title}</span>
                      {section.nistReference && (
                        <Badge variant="secondary" className="text-[10px]">{section.nistReference}</Badge>
                      )}
                    </div>
                    <ChevronDown className="h-4 w-4 text-muted-foreground" />
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-2 pl-4 border-l-2 border-emerald-500/20">
                    <div className="prose prose-sm prose-invert max-w-none text-sm text-muted-foreground whitespace-pre-wrap">
                      <Streamdown>{section.content || 'Content pending...'}</Streamdown>
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              ))}

              {/* Attack vectors table */}
              {testPlanResult.structuredData?.attackVectors?.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-sm font-semibold flex items-center gap-2">
                    <Crosshair className="h-4 w-4 text-red-400" /> Attack Vectors
                  </h4>
                  <div className="border rounded-lg overflow-auto max-h-[300px]">
                    <table className="w-full text-xs">
                      <thead className="bg-muted/50 sticky top-0">
                        <tr>
                          <th className="p-2 text-left">Vector</th>
                          <th className="p-2 text-left">Category</th>
                          <th className="p-2 text-left">MITRE ATT&CK</th>
                          <th className="p-2 text-center">Priority</th>
                          <th className="p-2 text-left">Tools</th>
                          <th className="p-2 text-left">Evidence Required</th>
                        </tr>
                      </thead>
                      <tbody>
                        {testPlanResult.structuredData.attackVectors.map((av: any, i: number) => (
                          <tr key={i} className="border-t hover:bg-muted/30">
                            <td className="p-2 font-medium">{av.name}</td>
                            <td className="p-2">{av.category}</td>
                            <td className="p-2"><Badge variant="outline" className="text-[10px]">{av.mitreTechnique || '—'}</Badge></td>
                            <td className="p-2 text-center">
                              <Badge className={`text-[10px] ${
                                av.priority === 'critical' ? 'bg-red-500/20 text-red-400' :
                                av.priority === 'high' ? 'bg-orange-500/20 text-orange-400' :
                                av.priority === 'medium' ? 'bg-amber-500/20 text-amber-400' :
                                'bg-green-500/20 text-green-400'
                              }`}>{av.priority}</Badge>
                            </td>
                            <td className="p-2">{(av.tools || []).join(', ')}</td>
                            <td className="p-2 text-muted-foreground">{av.evidenceRequired || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Risk mitigation */}
              {testPlanResult.structuredData?.riskMitigation?.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-sm font-semibold flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-emerald-400" /> Risk Mitigation During Testing
                  </h4>
                  <div className="grid grid-cols-1 gap-2">
                    {testPlanResult.structuredData.riskMitigation.map((rm: any, i: number) => (
                      <div key={i} className="flex items-start gap-2 p-2 rounded border bg-card">
                        <Badge variant="outline" className={`text-[10px] shrink-0 ${
                          rm.severity === 'high' ? 'border-red-500/50 text-red-400' :
                          rm.severity === 'medium' ? 'border-amber-500/50 text-amber-400' :
                          'border-green-500/50 text-green-400'
                        }`}>{rm.severity}</Badge>
                        <div>
                          <span className="text-xs font-medium">{rm.risk}</span>
                          <span className="text-xs text-muted-foreground ml-2">{rm.mitigation}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
          <DialogFooter className="gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                if (!testPlanResult?.markdown) return;
                const blob = new Blob([testPlanResult.markdown], { type: 'text/markdown' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${scan?.primaryDomain || 'domain'}_test_plan_PTES_NIST.md`;
                a.click();
                URL.revokeObjectURL(url);
                toast.success('Test plan exported as Markdown');
              }}
            >
              <Download className="h-4 w-4 mr-2" /> Export Markdown
            </Button>
            <Button
              variant="default"
              size="sm"
              className="bg-emerald-600 hover:bg-emerald-700"
              onClick={() => setTestPlanDialogOpen(false)}
            >
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>

    {/* Create Stack Profile from Scan Dialog */}
    <Dialog open={showCreateStackProfile} onOpenChange={setShowCreateStackProfile}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Create Stack Profile from Scan</DialogTitle>
          <DialogDescription>
            Auto-generate a Customer Stack Profile from the technologies detected in this DI scan. The profile will include all detected technologies, versions, and matched scanner modules.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-4">
          <div>
            <label className="text-sm font-medium">Customer / Profile Name</label>
            <input
              className="w-full mt-1.5 px-3 py-2 rounded-md border border-border bg-background text-sm"
              placeholder={scan?.primaryDomain || 'Customer name...'}
              value={stackProfileName}
              onChange={(e) => setStackProfileName(e.target.value)}
            />
            <p className="text-xs text-muted-foreground mt-1">Defaults to the scan domain if left empty.</p>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setShowCreateStackProfile(false)}>Cancel</Button>
          <Button
            className="bg-amber-600 hover:bg-amber-700"
            onClick={() => createStackProfileMut.mutate({
              scanId,
              customerName: stackProfileName || scan?.primaryDomain || 'Unknown',
            })}
            disabled={createStackProfileMut.isPending}
          >
            {createStackProfileMut.isPending ? (
              <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Creating...</>
            ) : (
              <><Layers className="h-4 w-4 mr-2" /> Create Profile</>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
    </AppShell>
  );
}
