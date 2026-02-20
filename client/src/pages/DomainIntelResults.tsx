import AppShell from "@/components/AppShell";
import { useState, useEffect } from "react";
import { trpc } from "@/lib/trpc";
import { useParams, useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Streamdown } from "streamdown";
import {
  ArrowLeft, Shield, Target, AlertTriangle, Brain, Globe, Server,
  ChevronDown, ChevronUp, Crosshair, Zap, FileText, ExternalLink,
  Activity, Lock, Eye, Network, Loader2, BarChart3, Bug, Skull, Database,
  TrendingUp, Fingerprint, Radar, Info, Search, Radio, Scan, Flag, Undo2, MessageSquare,
  Download, FlaskConical
} from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger, DropdownMenuLabel } from "@/components/ui/dropdown-menu";
import CorroborationPanel from "@/components/CorroborationPanel";

import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import { exportScanAssets, exportFindings, exportThreatActors, exportExecutiveSummary, exportExecutiveSummaryWithValidation, exportValidationReportPdf, exportValidationResultsCsv } from "@/lib/export-utils";
import type { ValidationResultExport, ValidationRunExport } from "@/lib/export-utils";
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
  const [expandedAsset, setExpandedAsset] = useState<number | null>(null);
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

  const { data, isLoading, error, refetch } = trpc.domainIntel.getScan.useQuery({ id: scanId }, { enabled: !!scanId });

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
    evidence: r.evidence ? (typeof r.evidence === 'string' ? JSON.parse(r.evidence) : r.evidence) : null,
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
  const [engagementRunning, setEngagementRunning] = useState(false);
  const [exploitDeploying, setExploitDeploying] = useState(false);

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

  const [matchingRunning, setMatchingRunning] = useState(false);
  const [subSearch, setSubSearch] = useState('');
  const [subSourceFilter, setSubSourceFilter] = useState('all');
  const [portSearch, setPortSearch] = useState('');
  const [portProtocolFilter, setPortProtocolFilter] = useState('all');
  const [portSortBy, setPortSortBy] = useState<'port' | 'ip' | 'product'>('port');
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

  // Sort assets by risk score descending
  const sortedAssets = [...assets].sort((a: any, b: any) => (b.hybridRiskScore || 0) - (a.hybridRiskScore || 0));

  // Risk distribution
  const riskDist = { critical: 0, high: 0, medium: 0, low: 0 };
  assets.forEach((a: any) => {
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
                  const findings = a.postureFindings || (a.analysis ? JSON.parse(a.analysis)?.postureFindings : []) || [];
                  return findings;
                });
                exportFindings(scan.primaryDomain, allFindings, 'csv');
                toast.success(`Exported ${allFindings.length} findings as CSV`);
              }}>
                <AlertTriangle className="h-4 w-4 mr-2" /> Findings (CSV)
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => {
                const allFindings = assets.flatMap((a: any) => {
                  const findings = a.postureFindings || (a.analysis ? JSON.parse(a.analysis)?.postureFindings : []) || [];
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
          <Button
            variant="outline"
            size="sm"
            className="text-xs"
            onClick={() => navigate(`/domain-intel/curate/${scanId}`)}
          >
            <Eye className="h-3.5 w-3.5 mr-1.5" />
            Review & Curate Findings
          </Button>
          <RiskGauge score={scan.overallRiskScore || 0} band={scan.overallRiskBand || "low"} />
        </div>
      </div>

      {/* Validate Top 10 Quick Action */}
      {scan.status !== 'pending' && scan.status !== 'discovering' && (
        <ValidateTop10Banner scanId={scanId} validationSummary={validationSummary.data} />
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
            <Button
              className="bg-purple-600 hover:bg-purple-700 shrink-0"
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
      <div className={`grid grid-cols-2 ${breachData ? 'md:grid-cols-5' : 'md:grid-cols-4'} gap-3`}>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold">{assets.length}</p>
            <p className="text-xs text-muted-foreground mt-1">Assets Discovered</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold">{scan.totalFindings || 0}</p>
            <p className="text-xs text-muted-foreground mt-1">Posture Findings</p>
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
        {breachData && (
          <Card className="border-red-500/20">
            <CardContent className="p-4 text-center">
              <p className="text-3xl font-bold text-red-400">{breachData.totalExposures?.toLocaleString() || 0}</p>
              <p className="text-xs text-muted-foreground mt-1">Breach Exposures</p>
              {breachData.credentialPairs > 0 && (
                <p className="text-[10px] text-red-400/80 mt-0.5">{breachData.credentialPairs} credentials</p>
              )}
            </CardContent>
          </Card>
        )}
      </div>

      {/* Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        {scan.status === 'scan_complete' ? (
          <TabsList className="flex flex-wrap gap-1 w-full max-w-5xl">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="assets">Assets</TabsTrigger>
            <TabsTrigger value="subdomains">Subdomains</TabsTrigger>
            <TabsTrigger value="ports">Ports & Services</TabsTrigger>
            <TabsTrigger value="vulns">Vulns</TabsTrigger>
            <TabsTrigger value="breaches">Breaches</TabsTrigger>
            <TabsTrigger value="corroboration">Corroboration</TabsTrigger>
            <TabsTrigger value="findings">Findings</TabsTrigger>
            <TabsTrigger value="methods">Methods</TabsTrigger>
          </TabsList>
        ) : (
          <TabsList className="flex flex-wrap gap-1 w-full max-w-6xl">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="assets">Assets</TabsTrigger>
            <TabsTrigger value="subdomains">Subdomains</TabsTrigger>
            <TabsTrigger value="ports">Ports & Services</TabsTrigger>
            <TabsTrigger value="vulns">Vulns</TabsTrigger>
            <TabsTrigger value="breaches">Breaches</TabsTrigger>
            <TabsTrigger value="adversaries">Adversaries</TabsTrigger>
            <TabsTrigger value="campaigns">Campaigns</TabsTrigger>
            <TabsTrigger value="threat-model">Threat Model</TabsTrigger>
            <TabsTrigger value="corroboration">Corroboration</TabsTrigger>
            <TabsTrigger value="findings">Findings</TabsTrigger>
            <TabsTrigger value="methods">Methods</TabsTrigger>
          </TabsList>
        )}

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6">
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
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-2">
                {sortedAssets.map((asset: any) => {
                  const band = asset.riskBand || "low";
                  const isHeatmapExpanded = heatmapExpandedAsset === asset.id;
                  return (
                    <div
                      key={asset.id}
                      className={`p-2 rounded-lg border cursor-pointer transition-all hover:scale-105 ${RISK_COLORS[band]} ${isHeatmapExpanded ? 'ring-2 ring-purple-500 scale-105' : ''}`}
                      onClick={() => setHeatmapExpandedAsset(isHeatmapExpanded ? null : asset.id)}
                    >
                      <p className="font-mono text-xs truncate">{asset.hostname}</p>
                      <div className="flex items-center justify-between mt-1">
                        <span className="text-xs opacity-70">{asset.assetType}</span>
                        <span className="text-sm font-bold">{asset.hybridRiskScore}</span>
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
                const confirmedFindings = findings.filter((f: any) => f.corroborationTier === 'confirmed');
                const probableFindings = findings.filter((f: any) => f.corroborationTier === 'probable');
                const potentialFindings = findings.filter((f: any) => f.corroborationTier === 'potential');
                const kevFindings = findings.filter((f: any) => f.kevListed);

                return (
                  <div className="border border-purple-500/30 rounded-lg bg-card/80 p-4 space-y-4 animate-in fade-in slide-in-from-top-2 duration-200">
                    {/* Header */}
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${RISK_COLORS[band]}`}>
                          <span className="text-lg font-bold">{asset.hybridRiskScore}</span>
                        </div>
                        <div>
                          <p className="font-mono font-semibold">{asset.hostname}</p>
                          <div className="flex items-center gap-2 mt-0.5">
                            <Badge variant="outline" className="text-[10px]">{asset.assetType}</Badge>
                            <Badge className={`text-[10px] ${RISK_COLORS[band]}`}>{band}</Badge>
                            {asset.discoveryMethod && (
                              <Badge variant="outline" className={`text-[10px] ${
                                asset.discoveryMethod === 'inferred' ? 'text-purple-400 border-purple-500/40' :
                                asset.discoveryMethod === 'dns_verified' ? 'text-emerald-400 border-emerald-500/40' :
                                'text-blue-400 border-blue-500/40'
                              }`}>
                                {asset.discoveryMethod === 'inferred' ? 'Inferred' : asset.discoveryMethod === 'dns_verified' ? 'DNS Verified' : asset.discoveryMethod}
                              </Badge>
                            )}
                            {asset.suggestedTier && <Badge variant="outline" className="text-[10px]">{asset.suggestedTier.replace('_', ' ')}</Badge>}
                          </div>
                        </div>
                      </div>
                      <Button variant="ghost" size="sm" onClick={() => setHeatmapExpandedAsset(null)}>
                        <ChevronUp className="h-4 w-4" />
                      </Button>
                    </div>

                    {/* Score Breakdown */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      {/* Impact Scores */}
                      <div className="space-y-2">
                        <p className="text-xs font-medium text-muted-foreground flex items-center gap-1">
                          <Target className="h-3 w-3" /> Impact Scores
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
                      <div className="space-y-2">
                        <p className="text-xs font-medium text-muted-foreground flex items-center gap-1">
                          <Zap className="h-3 w-3" /> Disruption Scores
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
                      <div className="space-y-2">
                        <p className="text-xs font-medium text-muted-foreground flex items-center gap-1">
                          <Activity className="h-3 w-3" /> Risk Composition
                        </p>
                        <div className="space-y-2">
                          {/* Impact × Likelihood — the two dimensions that compose the risk score */}
                          <div className="flex justify-between text-[11px]">
                            <span className="text-sky-400 font-medium">Mission Impact</span>
                            <span className={`font-bold ${(asset.impactScore || 0) >= 70 ? 'text-sky-400' : (asset.impactScore || 0) >= 40 ? 'text-sky-300' : 'text-slate-400'}`}>{asset.impactScore || 0}/100</span>
                          </div>
                          <div className="flex justify-between text-[11px]">
                            <span className="text-amber-400 font-medium">Likelihood (CVSS+Exposure)</span>
                            <span className={`font-bold ${(asset.likelihoodScore || 0) >= 70 ? 'text-amber-400' : (asset.likelihoodScore || 0) >= 40 ? 'text-amber-300' : 'text-slate-400'}`}>{asset.likelihoodScore || 0}/100</span>
                          </div>
                          <div className="flex justify-between text-[11px] pt-1 border-t border-border">
                            <span className="text-muted-foreground">Hybrid Risk Score</span>
                            <span className={`font-bold ${band === 'critical' ? 'text-red-400' : band === 'high' ? 'text-orange-400' : band === 'medium' ? 'text-yellow-400' : 'text-emerald-400'}`}>{asset.hybridRiskScore}/100</span>
                          </div>
                          <div className="text-[9px] text-muted-foreground italic">Risk = √(Impact × Likelihood)</div>
                          <div className="flex justify-between text-[11px] pt-1 border-t border-border/50">
                            <span className="text-muted-foreground">Mission Impact</span>
                            <span className="font-bold">{((asset.missionImpactScore || 0) / 10).toFixed(1)}/10</span>
                          </div>
                          <div className="flex justify-between text-[11px]">
                            <span className="text-muted-foreground">CVSS Estimate</span>
                            <span className="font-bold">{((asset.cvssEstimate || 0) / 10).toFixed(1)}/10</span>
                          </div>
                          <div className="flex justify-between text-[11px]">
                            <span className="text-muted-foreground">Confidence</span>
                            <span className="font-bold">{asset.confidence || 0}%</span>
                          </div>
                          <div className="flex justify-between text-[11px]">
                            <span className="text-muted-foreground">Asset Criticality</span>
                            <span className={`font-bold ${(asset.assetCriticalityBand || 'low') === 'critical' ? 'text-purple-400' : (asset.assetCriticalityBand || 'low') === 'high' ? 'text-blue-400' : (asset.assetCriticalityBand || 'low') === 'medium' ? 'text-cyan-400' : 'text-slate-400'}`}>
                              {asset.assetCriticalityScore || 0}/100 ({(asset.assetCriticalityBand || 'low').toUpperCase()})
                            </span>
                          </div>
                          <div className="flex justify-between text-[11px]">
                            <span className="text-muted-foreground">Vuln Risk (Scan-Confirmed)</span>
                            <span className={`font-bold ${(asset.vulnRiskBand || 'low') === 'critical' ? 'text-red-400' : (asset.vulnRiskBand || 'low') === 'high' ? 'text-orange-400' : (asset.vulnRiskBand || 'low') === 'medium' ? 'text-yellow-400' : 'text-emerald-400'}`}>
                              {asset.vulnRiskScore || 0}/100 ({(asset.vulnRiskBand || 'low').toUpperCase()})
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Technologies */}
                    {technologies.length > 0 && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1.5 flex items-center gap-1">
                          <Server className="h-3 w-3" /> Detected Technologies ({technologies.length})
                        </p>
                        <div className="flex flex-wrap gap-1">
                          {technologies.map((t: string, i: number) => (
                            <Badge key={i} variant="secondary" className="text-[10px]">{t}</Badge>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Finding Summary */}
                    {findings.length > 0 && (() => {
                      const confirmedOnly = [...kevFindings, ...confirmedFindings.filter((f: any) => !f.kevListed)];
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
                            <div className="space-y-1.5 max-h-48 overflow-y-auto">
                              {confirmedOnly.slice(0, 8).map((f: any, i: number) => (
                                  <div key={i} className={`p-2 rounded border text-xs ${f.kevListed ? 'bg-red-500/5 border-red-500/30' : 'bg-muted/20 border-border'}`}>
                                    <div className="flex items-center gap-1.5 flex-wrap">
                                      <Badge className="text-[9px] px-1 py-0 text-emerald-400 bg-emerald-500/20 border-emerald-500/40">CONFIRMED</Badge>
                                      {f.kevListed && <Badge className="text-[9px] px-1 py-0 bg-red-600/30 text-red-300 border-red-500/50">KEV</Badge>}
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
                          {/* Probable findings in their own collapsible */}
                          {probableFindings.length > 0 && (
                            <Collapsible className="mt-2">
                              <CollapsibleTrigger className="flex items-center gap-1.5 text-[11px] text-yellow-400 hover:text-yellow-300 transition-colors cursor-pointer">
                                <ChevronDown className="h-3 w-3" />
                                <span className="underline decoration-dotted">Probable Matches ({probableFindings.length})</span>
                                <span className="text-[9px] text-muted-foreground no-underline ml-1">version unconfirmed</span>
                              </CollapsibleTrigger>
                              <CollapsibleContent className="mt-1.5 space-y-1.5 max-h-36 overflow-y-auto">
                                {probableFindings.slice(0, 5).map((f: any, i: number) => (
                                  <div key={`prob-${i}`} className="p-2 rounded border text-xs bg-yellow-500/5 border-yellow-500/20 opacity-70">
                                    <div className="flex items-center gap-1.5 flex-wrap">
                                      <Badge className="text-[9px] px-1 py-0 text-yellow-400 bg-yellow-500/20 border-yellow-500/40">PROBABLE</Badge>
                                      <span className="font-medium">{f.title}</span>
                                      <Badge variant="outline" className="text-[9px] px-1 py-0 text-muted-foreground/60 border-muted-foreground/30 ml-auto">Sev: {f.severity}/10 (capped)</Badge>
                                    </div>
                                  </div>
                                ))}
                                {probableFindings.length > 5 && (
                                  <p className="text-[10px] text-muted-foreground text-center">+ {probableFindings.length - 5} more probable matches</p>
                                )}
                              </CollapsibleContent>
                            </Collapsible>
                          )}
                          {potentialFindings.length > 0 && (
                            <Collapsible className="mt-2">
                              <CollapsibleTrigger className="flex items-center gap-1.5 text-[11px] text-purple-400 hover:text-purple-300 transition-colors cursor-pointer">
                                <ChevronDown className="h-3 w-3" />
                                <span className="underline decoration-dotted">Potential Matches ({potentialFindings.length})</span>
                              </CollapsibleTrigger>
                              <CollapsibleContent className="mt-1.5 space-y-1.5 max-h-36 overflow-y-auto">
                                {potentialFindings.slice(0, 5).map((f: any, i: number) => (
                                  <div key={`pot-${i}`} className="p-2 rounded border text-xs bg-purple-500/5 border-purple-500/20 opacity-60">
                                    <div className="flex items-center gap-1.5 flex-wrap">
                                      <Badge className="text-[9px] px-1 py-0 text-purple-400 bg-purple-500/20 border-purple-500/40">POTENTIAL</Badge>
                                      <span className="font-medium text-muted-foreground">{f.title}</span>
                                      <Badge variant="outline" className="text-[9px] px-1 py-0 text-muted-foreground/60 border-muted-foreground/30 ml-auto">NOT RATED</Badge>
                                    </div>
                                  </div>
                                ))}
                                {potentialFindings.length > 5 && (
                                  <p className="text-[10px] text-muted-foreground text-center">+ {potentialFindings.length - 5} more potential matches</p>
                                )}
                              </CollapsibleContent>
                            </Collapsible>
                          )}
                        </div>
                      );
                    })()}

                    {/* Test Vectors Preview */}
                    {vectors.length > 0 && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground mb-1.5 flex items-center gap-1">
                          <Crosshair className="h-3 w-3" /> Test Vectors ({vectors.length})
                        </p>
                        <div className="flex flex-wrap gap-1">
                          {vectors.slice(0, 5).map((v: any, i: number) => (
                            <Badge key={i} variant="outline" className="text-[10px]">
                              {v.vectorType}
                              {v.suggestedEmulation?.technique && <span className="ml-1 text-purple-400">{v.suggestedEmulation.technique}</span>}
                            </Badge>
                          ))}
                          {vectors.length > 5 && <Badge variant="outline" className="text-[10px]">+{vectors.length - 5} more</Badge>}
                        </div>
                      </div>
                    )}

                    {/* View Full Details Button */}
                    <div className="flex justify-end pt-1">
                      <Button variant="outline" size="sm" className="text-xs" onClick={() => {
                        setExpandedAsset(asset.id);
                        const tabsTrigger = document.querySelector('[data-value="assets"]') as HTMLElement;
                        if (tabsTrigger) tabsTrigger.click();
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
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${RISK_COLORS[band]}`}>
                    <span className="text-sm font-bold">{asset.hybridRiskScore}</span>
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
                    <div className="flex gap-1 mt-1 flex-wrap">
                      {((asset.tags || []) as string[]).slice(0, 4).map((t: string) => (
                        <Badge key={t} variant="secondary" className="text-[10px]">{t}</Badge>
                      ))}
                      {((asset.tags || []) as string[]).length > 4 && (
                        <Badge variant="secondary" className="text-[10px]">+{((asset.tags || []) as string[]).length - 4}</Badge>
                      )}
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
                        <div className="mt-3 flex gap-4 text-xs flex-wrap">
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
                            <span className="font-bold">{(asset.missionImpactScore || 0) / 10}/10</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">CVSS Est:</span>{" "}
                            <span className="font-bold">{(asset.cvssEstimate || 0) / 10}/10</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Confidence:</span>{" "}
                            <span className="font-bold">{asset.confidence || 0}%</span>
                          </div>
                          <div className="w-full text-[9px] text-muted-foreground italic">Risk = √(Impact × Likelihood)</div>
                        </div>
                      </div>
                    </div>

                    {/* Posture Findings — Confirmed shown, Probable & Potential behind collapsibles */}
                    {findings.length > 0 && (() => {
                      const confirmedOnlyFindings = findings.filter((f: any) => f.corroborationTier === 'confirmed');
                      const probableOnlyFindings = findings.filter((f: any) => f.corroborationTier === 'probable');
                      const potentialOnlyFindings = findings.filter((f: any) => !f.corroborationTier || f.corroborationTier === 'potential');
                      const renderFinding = (f: any, i: number) => {
                        const tierColor = f.corroborationTier === "confirmed" ? "text-emerald-400 bg-emerald-500/20 border-emerald-500/40"
                          : f.corroborationTier === "probable" ? "text-yellow-400 bg-yellow-500/20 border-yellow-500/40"
                          : "text-purple-400 bg-purple-500/20 border-purple-500/40";
                        const tierLabel = f.corroborationTier === "confirmed" ? "CONFIRMED" : f.corroborationTier === "probable" ? "PROBABLE" : "POTENTIAL";
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
                                  <p className="text-[10px] text-emerald-400 font-mono mt-0.5">Version: {f.detectedVersion} {f.versionMatchConfirmed ? "✔ matched" : ""}</p>
                                )}
                                {!f.detectedVersion && f.corroborationTier === "probable" && (
                                  <p className="text-[10px] text-yellow-400 mt-0.5">Version unconfirmed — severity capped</p>
                                )}
                                {f.evidenceDetail && (
                                  <p className="text-[10px] text-muted-foreground/70 mt-0.5 italic">{f.evidenceDetail}</p>
                                )}
                              </div>
                              <div className="flex gap-1 shrink-0 flex-wrap">
                                {f.kevListed && <Badge className="text-[10px] bg-red-600/30 text-red-300 border-red-500/50">KEV</Badge>}
                                {f.exploitAvailable && !f.kevListed && <Badge className="text-[10px] bg-orange-600/30 text-orange-300 border-orange-500/50">Exploit</Badge>}
                                {f.corroborationTier === 'potential' ? (
                                  <Badge variant="outline" className="text-[10px] text-muted-foreground/60 border-muted-foreground/30">NOT RATED</Badge>
                                ) : (
                                  <>
                                    <Badge variant="outline" className="text-[10px]">Sev: {f.severity}/10{f.corroborationTier === "probable" ? " (cap)" : ""}</Badge>
                                    {f.cvssScore && <Badge variant="outline" className="text-[10px]">CVSS: {f.cvssScore}</Badge>}
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
            // Also extract subdomains from assets
            const assetSubdomains = assets.filter((a: any) => a.assetType === 'subdomain' || (a.hostname && a.hostname !== scan.primaryDomain));
            // Merge: pipeline subdomains + asset subdomains (deduplicated)
            const allSubdomainMap = new Map<string, any>();
            for (const s of subdomains) {
              allSubdomainMap.set(s.name.toLowerCase(), s);
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
            const allSubdomains = Array.from(allSubdomainMap.values());
            // subSearch and subSourceFilter are declared at component level
            const sources = Array.from(new Set(allSubdomains.map(s => s.source)));
            const filtered = allSubdomains.filter(s => {
              if (subSearch && !s.name.toLowerCase().includes(subSearch.toLowerCase())) return false;
              if (subSourceFilter !== 'all' && s.source !== subSourceFilter) return false;
              return true;
            });

            return (
              <>
                <Card className="bg-card/50">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Globe className="h-5 w-5 text-purple-400" />
                      Discovered Subdomains ({allSubdomains.length})
                    </CardTitle>
                    <CardDescription>
                      All subdomains discovered across passive recon connectors (crt.sh, internet scan databases, SecurityTrails, Censys, URLScan, Wayback, Dehashed)
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {/* Stats */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-purple-400">{allSubdomains.length}</p>
                        <p className="text-xs text-muted-foreground">Total Subdomains</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-emerald-400">{allSubdomains.filter(s => s.ip).length}</p>
                        <p className="text-xs text-muted-foreground">With Resolved IPs</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-sky-400">{sources.length}</p>
                        <p className="text-xs text-muted-foreground">Discovery Sources</p>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/30 border border-border">
                        <p className="text-2xl font-bold text-amber-400">{allSubdomains.filter(s => s.tags?.some((t: string) => t.startsWith('port:'))).length}</p>
                        <p className="text-xs text-muted-foreground">With Open Ports</p>
                      </div>
                    </div>

                    {/* Filters */}
                    <div className="flex flex-wrap gap-3">
                      <div className="flex-1 min-w-[200px]">
                        <input
                          type="text"
                          placeholder="Search subdomains..."
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
                          const csv = ['Subdomain,IP,Source,Tags'];
                          allSubdomains.forEach(s => csv.push(`${s.name},${s.ip || ''},${s.source},"${(s.tags || []).join('; ')}"`));
                          const blob = new Blob([csv.join('\n')], { type: 'text/csv' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url; a.download = `${scan.primaryDomain}_subdomains.csv`; a.click();
                          URL.revokeObjectURL(url);
                          toast.success(`Exported ${allSubdomains.length} subdomains`);
                        }}
                      >
                        <FileText className="h-3 w-3 mr-1" /> Export CSV
                      </Button>
                    </div>

                    {/* Subdomain Table */}
                    <div className="border rounded-lg overflow-auto max-h-[600px]">
                      <table className="w-full text-sm">
                        <thead className="bg-muted/50 sticky top-0">
                          <tr>
                            <th className="text-left px-3 py-2 font-medium">Subdomain</th>
                            <th className="text-left px-3 py-2 font-medium">IP Address</th>
                            <th className="text-left px-3 py-2 font-medium">Source</th>
                            <th className="text-left px-3 py-2 font-medium">Tags</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {filtered.length === 0 ? (
                            <tr><td colSpan={4} className="px-3 py-8 text-center text-muted-foreground">No subdomains found matching your filters</td></tr>
                          ) : filtered.map((s: any, i: number) => (
                            <tr key={i} className="hover:bg-muted/20">
                              <td className="px-3 py-2 font-mono text-xs">{s.name}</td>
                              <td className="px-3 py-2 font-mono text-xs text-muted-foreground">{s.ip || '—'}</td>
                              <td className="px-3 py-2">
                                <Badge variant="outline" className="text-[10px]">{s.source}</Badge>
                              </td>
                              <td className="px-3 py-2">
                                <div className="flex flex-wrap gap-1">
                                  {(s.tags || []).slice(0, 3).map((t: string, j: number) => (
                                    <Badge key={j} variant="secondary" className="text-[10px]">{t}</Badge>
                                  ))}
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {filtered.length < allSubdomains.length && (
                      <p className="text-xs text-muted-foreground">Showing {filtered.length} of {allSubdomains.length} subdomains</p>
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
                if (!p.ip.includes(q) && !p.hostname.toLowerCase().includes(q) && !String(p.port).includes(q) && !p.product.toLowerCase().includes(q)) return false;
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
                    <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
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
                          const csv = ['IP,Port,Transport,Service,Version,Hostname,Source,CVEs'];
                          ports.forEach(p => csv.push(`${p.ip},${p.port},${p.transport},${p.product},${p.version},${p.hostname},${p.source},"${(p.vulns || []).join('; ')}"`));
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
                            <th className="text-left px-3 py-2 font-medium">Source</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {filtered.length === 0 ? (
                            <tr><td colSpan={8} className="px-3 py-8 text-center text-muted-foreground">
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
                                  {em.cveId}: {em.metasploitCount || 0} MSF + {em.exploitDbCount || 0} EDB
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
                    <div className="text-[10px] text-muted-foreground">public exploit databases Entries</div>
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
                          <Badge variant="outline" className="text-[10px]">{m.corroborationTier}</Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-1">
                        {m.metasploitModules?.length > 0 && (
                          <Badge className="bg-red-500/20 text-red-400 text-[10px]">
                            <Target className="h-3 w-3 mr-0.5" /> {m.metasploitModules.length} MSF
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
          <VulnIntelSection scanId={scanId} />
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
                    <p className="text-xs text-muted-foreground mt-1">Total Exposures</p>
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

        {/* Scan Methods Tab */}
        <TabsContent value="methods" className="space-y-4">
          <ScanMethodsTab assets={assets} scan={scan} />
        </TabsContent>

        {/* Findings Tab */}
        <TabsContent value="findings" className="space-y-3">
          {(() => {
            const allFindings = assets.flatMap((a: any) =>
              ((a.postureFindings || []) as any[]).map((f: any) => ({ ...f, assetHostname: f.assetHostname || a.asset?.hostname || a.hostname, assetRisk: a.hybridRiskScore }))
            ).sort((a: any, b: any) => {
              // Sort: Confirmed first, then probable, then potential; within each tier by severity
              const tierOrder: Record<string, number> = { confirmed: 0, probable: 1, potential: 2 };
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
            };

            // Summary counts by tier
            const confirmed = allFindings.filter((f: any) => f.corroborationTier === "confirmed");
            const probable = allFindings.filter((f: any) => f.corroborationTier === "probable");
            const potential = allFindings.filter((f: any) => !f.corroborationTier || f.corroborationTier === "potential");

            return (
              <>
                {/* Corroboration Summary */}
                <div className="grid grid-cols-3 gap-3 mb-4">
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
                                      <span className="text-[11px] text-emerald-400 font-mono">Detected version: {f.detectedVersion}</span>
                                      {f.versionMatchConfirmed && <Badge className="text-[9px] bg-emerald-600/30 text-emerald-300 border-emerald-500/50 ml-1">VERSION MATCH</Badge>}
                                    </div>
                                  )}
                                  {!f.detectedVersion && f.corroborationTier === "probable" && (
                                    <div className="flex items-center gap-1 mt-1">
                                      <AlertTriangle className="h-3 w-3 text-yellow-400" />
                                      <span className="text-[11px] text-yellow-400">Version not detected — product-family match only (severity capped)</span>
                                    </div>
                                  )}
                                </div>

                                <div className="flex gap-1.5 shrink-0 flex-wrap justify-end">
                                  {f.kevListed && (
                                    <Badge className="text-[10px] bg-red-600/30 text-red-300 border-red-500/50">
                                      <Skull className="h-3 w-3 mr-0.5" /> KEV
                                    </Badge>
                                  )}
                                  {f.exploitAvailable && !f.kevListed && (
                                    <Badge className="text-[10px] bg-orange-600/30 text-orange-300 border-orange-500/50">
                                      <Zap className="h-3 w-3 mr-0.5" /> Exploit
                                    </Badge>
                                  )}
                                  <Badge variant="outline" className="text-[10px]">Severity: {f.severity}/10</Badge>
                                  {f.cvssScore && <Badge variant="outline" className="text-[10px]">CVSS: {f.cvssScore}</Badge>}
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
                                <span className="text-muted-foreground">
                                  Confidence: <span className={confidencePct >= 80 ? "text-emerald-400" : confidencePct >= 50 ? "text-yellow-400" : "text-red-400"}>{confidencePct}%</span>
                                </span>
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
                                </div>
                                <div className="flex gap-1.5 shrink-0 flex-wrap justify-end">
                                  {f.kevListed && <Badge className="text-[10px] bg-red-600/30 text-red-300 border-red-500/50"><Skull className="h-3 w-3 mr-0.5" /> KEV</Badge>}
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
                                <span className="text-muted-foreground">
                                  Confidence: <span className={confidencePct >= 80 ? "text-emerald-400" : confidencePct >= 50 ? "text-yellow-400" : "text-red-400"}>{confidencePct}%</span>
                                </span>
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
                                <span className="text-muted-foreground">
                                  Confidence: <span className={confidencePct >= 80 ? "text-emerald-400" : confidencePct >= 50 ? "text-yellow-400" : "text-red-400"}>{confidencePct}%</span>
                                </span>
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
              </>
            );
          })()}
        </TabsContent>
        {/* Corroboration Tab */}
        <TabsContent value="corroboration" className="space-y-4">
          <CorroborationPanel assets={assets} scanId={scanId} autoRun={false} />
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
    </div>
    </AppShell>
  );
}

// ─── Scan Methods Tab Component ───
function ScanMethodsTab({ assets, scan }: { assets: any[]; scan: any }) {
  // Compute stats from the scan data
  const dnsVerifiedCount = assets.filter((a: any) => {
    const dm = a.discoveryMethod || (a.asset as any)?.discoveryMethod;
    return dm === 'dns_verified' || dm === 'header_detected';
  }).length;
  const inferredCount = assets.filter((a: any) => {
    const dm = a.discoveryMethod || (a.asset as any)?.discoveryMethod;
    return dm === 'inferred' || !dm;
  }).length;
  const headerDetectedCount = assets.filter((a: any) => {
    const dm = a.discoveryMethod || (a.asset as any)?.discoveryMethod;
    return dm === 'header_detected';
  }).length;
  const allFindings = assets.flatMap((a: any) => (a.postureFindings || []) as any[]);
  const confirmedFindings = allFindings.filter((f: any) => f.corroborationTier === 'confirmed');
  const probableFindings = allFindings.filter((f: any) => f.corroborationTier === 'probable');
  const potentialFindings = allFindings.filter((f: any) => !f.corroborationTier || f.corroborationTier === 'potential');
  const kevFindings = allFindings.filter((f: any) => f.kevListed);

  const METHODS = [
    {
      id: "llm_passive_recon",
      name: "LLM-Powered Passive Reconnaissance",
      icon: Brain,
      category: "Discovery",
      status: "completed",
      description: "Used a large language model to infer likely subdomains, services, and technology stacks based on the organization's sector, client type, and domain patterns. No active probing was performed.",
      outputs: `Discovered ${assets.length} total assets (${inferredCount} inferred, ${dnsVerifiedCount} verified)`,
      attribution: 'Findings labeled as "Inferred" are hypotheses. Verify by checking DNS records or visiting the URL.',
      fpRisk: "Medium — the LLM may suggest subdomains that don't exist.",
      verifyCmd: "nslookup <hostname> or dig <hostname>",
    },
    {
      id: "dns_verification",
      name: "Active DNS Resolution",
      icon: Globe,
      category: "Discovery",
      status: dnsVerifiedCount > 0 ? "completed" : "no_results",
      description: "Resolved each inferred hostname via DNS (A, AAAA, CNAME, MX, TXT, NS records) to confirm whether the asset actually exists.",
      outputs: `${dnsVerifiedCount} of ${assets.length} assets confirmed via DNS resolution`,
      attribution: 'Findings labeled "DNS Verified" resolved to an IP address.',
      fpRisk: "Low — DNS resolution is deterministic.",
      verifyCmd: "nslookup <hostname> or dig <hostname>",
    },
    {
      id: "banner_grabbing",
      name: "HTTP Banner & Header Analysis",
      icon: Fingerprint,
      category: "Discovery",
      status: headerDetectedCount > 0 ? "completed" : "no_results",
      description: "Sent HTTP/HTTPS requests to resolved hostnames and parsed response headers (Server, X-Powered-By, X-Generator, Set-Cookie) to detect technology names and versions.",
      outputs: `${headerDetectedCount} assets with header-detected technologies`,
      attribution: 'Findings labeled "Header Detected" — version extracted from HTTP response headers.',
      fpRisk: "Low — headers come directly from the server (but can be spoofed).",
      verifyCmd: "curl -I https://<hostname>",
    },
    {
      id: "internetdb_enrichment",
      name: "internet scan databases InternetDB Fast-Path",
      icon: Radar,
      category: "Passive Data Collection",
      status: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "no_results";
        const c = pr.connectorResults.find((r: any) => r.connector === "shodan_internetdb");
        return c && c.observations?.length > 0 ? "completed" : "no_results";
      })(),
      description: "Queried internet scan databases's free InternetDB API for instant IP enrichment — open ports, CVEs, CPEs, hostnames, and tags — without consuming API credits.",
      outputs: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "Not executed";
        const c = pr.connectorResults.find((r: any) => r.connector === "shodan_internetdb");
        if (!c) return "Not executed";
        return `${c.observations?.length || 0} observations from InternetDB`;
      })(),
      attribution: 'Data from Internet Scan Database (internetdb.shodan.io). Free, no API key required.',
      fpRisk: "Low — based on real internet scan databases scan data.",
      verifyCmd: "curl https://internetdb.shodan.io/<IP>",
    },
    {
      id: "binaryedge_enrichment",
      name: "BinaryEdge Host Intelligence",
      icon: Scan,
      category: "Passive Data Collection",
      status: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "no_results";
        const c = pr.connectorResults.find((r: any) => r.connector === "binaryedge");
        return c && c.observations?.length > 0 ? "completed" : "no_results";
      })(),
      description: "Queried BinaryEdge's internet-wide scanning database for independent validation of open ports, service banners, and CVEs. Provides multi-source corroboration with ~3,500 port coverage.",
      outputs: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "Not executed";
        const c = pr.connectorResults.find((r: any) => r.connector === "binaryedge");
        if (!c) return "Not executed";
        if (c.errors?.some((e: string) => e.includes("Skipped"))) return "Skipped — no API key configured";
        return `${c.observations?.length || 0} observations from BinaryEdge`;
      })(),
      attribution: 'Data from BinaryEdge (binaryedge.io). Independent scanning source.',
      fpRisk: "Low — based on real scan data from an independent source.",
      verifyCmd: "Visit https://app.binaryedge.io/services/query",
    },
    {
      id: "greynoise_enrichment",
      name: "GreyNoise Threat Pressure Context",
      icon: Radio,
      category: "Passive Data Collection",
      status: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "no_results";
        const c = pr.connectorResults.find((r: any) => r.connector === "greynoise");
        return c && c.observations?.length > 0 ? "completed" : "no_results";
      })(),
      description: "Queried GreyNoise to classify IPs as benign, malicious, or unknown. Identifies assets under active attack and IPs being mass-scanned. Provides unique threat pressure context.",
      outputs: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "Not executed";
        const c = pr.connectorResults.find((r: any) => r.connector === "greynoise");
        if (!c) return "Not executed";
        if (c.errors?.some((e: string) => e.includes("Skipped"))) return "Skipped — no API key or DNS resolution required";
        return `${c.observations?.length || 0} observations from GreyNoise`;
      })(),
      attribution: 'Data from GreyNoise (greynoise.io). Verify at: https://viz.greynoise.io/ip/<IP>',
      fpRisk: "Low — classifications based on observed internet traffic behavior.",
      verifyCmd: "Visit https://viz.greynoise.io/ip/<IP>",
    },
    {
      id: "dehashed_breach",
      name: "Dehashed Breach Intelligence",
      icon: Lock,
      category: "Passive Data Collection",
      status: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "no_results";
        const dh = pr.connectorResults.find((r: any) => r.connector === "dehashed");
        return dh && dh.observations?.length > 0 ? "completed" : "no_results";
      })(),
      description: "Queried Dehashed's 15B+ breach record database for domain and subdomain mapping through leaked email addresses, credential exposure detection, IP associations, and breach database attribution.",
      outputs: (() => {
        const pr = (scan.pipelineOutput as any)?.passiveRecon;
        if (!pr?.connectorResults) return "Not executed";
        const dh = pr.connectorResults.find((r: any) => r.connector === "dehashed");
        if (!dh) return "Not executed";
        const breachObs = dh.observations?.filter((o: any) => o.assetType === "breach") || [];
        const subdomainObs = dh.observations?.filter((o: any) => o.assetType === "subdomain") || [];
        const ipObs = dh.observations?.filter((o: any) => o.assetType === "ip") || [];
        return `${dh.observations?.length || 0} observations: ${subdomainObs.length} subdomains, ${ipObs.length} IPs, ${breachObs.length} breach records`;
      })(),
      attribution: 'Data from Dehashed (dehashed.com). Breach records aggregated from public and private data wells.',
      fpRisk: "Low — breach records are real artifacts. Subdomains from email domains are highly reliable.",
      verifyCmd: "Search dehashed.com for domain:<domain>",
    },
    {
      id: "kev_enrichment",
      name: "KEV Matching",
      icon: Shield,
      category: "Vulnerability Intelligence",
      status: kevFindings.length > 0 ? "completed" : "no_results",
      description: "Cross-referenced detected technologies against the CISA Known Exploited Vulnerabilities catalog — CVEs confirmed to be actively exploited in the wild.",
      outputs: `${kevFindings.length} KEV-listed findings matched`,
      attribution: 'Verify at: https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      fpRisk: "Low for product match, Medium for version match.",
      verifyCmd: "Search KEV by CVE ID",
    },
    {
      id: "vuln_feed",
      name: "Multi-Source Vulnerability Feed Matching",
      icon: Bug,
      category: "Vulnerability Intelligence",
      status: confirmedFindings.length + probableFindings.length > 0 ? "completed" : "no_results",
      description: "Matched technologies against NVD, zero-day research programs, vulnerability advisory feeds, and public exploit databases. Provides CVSS scores and exploit availability.",
      outputs: `${confirmedFindings.length} confirmed + ${probableFindings.length} probable CVE matches`,
      attribution: 'Each CVE links to NVD: https://nvd.nist.gov/vuln/detail/<CVE-ID>',
      fpRisk: "Medium — product-family matches may not apply to the specific version.",
      verifyCmd: "Visit NVD page for each CVE ID",
    },
    {
      id: "carver_shock",
      name: "Business Impact Analysis",
      icon: Target,
      category: "Risk Scoring",
      status: "completed",
      description: "Applied proprietary multi-dimensional targeting methodology to score each asset's mission importance and cascading risk.",
      outputs: `Scored ${assets.length} assets across 11 impact dimensions`,
      attribution: 'Scores are LLM-generated analytical estimates based on asset type and sector context.',
      fpRisk: "N/A — risk scores, not binary findings.",
      verifyCmd: "Review individual asset impact scores in Assets tab",
    },
    {
      id: "hybrid_risk",
      name: "Hybrid Risk Score Computation",
      icon: Radar,
      category: "Risk Scoring",
      status: "completed",
      description: "Combined vulnerability severity with mission impact analysis into a hybrid risk score. Also provides separated Asset Criticality (mission importance) and Vulnerability Risk (confirmed/probable scan findings only) scores.",
      outputs: `Overall risk: ${scan.overallRiskScore || 'N/A'} (${scan.overallRiskBand || 'N/A'}). Asset criticality and vuln risk are now separated — high criticality does NOT imply high vulnerability risk.`,
      attribution: 'Deterministic formula — same inputs always produce the same score. Vuln risk only counts confirmed/probable findings.',
      fpRisk: "N/A — composite score. Vuln risk requires scan evidence.",
      verifyCmd: "Compare CRIT vs VULN scores in the Assets tab",
    },
    {
      id: "threat_actors",
      name: "Threat Actor Profiling",
      icon: Crosshair,
      category: "Threat Intelligence",
      status: (scan.pipelineOutput as any)?.threatActorMatches ? "completed" : "no_results",
      description: "Matched the organization's sector, technology stack, and risk profile against known threat actor groups (APTs, cybercrime groups).",
      outputs: `${(scan.pipelineOutput as any)?.threatActorMatches?.topMatches?.length || 0} threat actors matched`,
      attribution: 'Verify actor profiles at: https://attack.mitre.org/groups/',
      fpRisk: "Medium — threat actor targeting is probabilistic.",
      verifyCmd: "Search MITRE ATT&CK Groups by name",
    },
    {
      id: "campaign_design",
      name: "Automated Campaign Design",
      icon: Zap,
      category: "Offensive Planning",
      status: ((scan.campaignRecommendations || []) as any[]).length > 0 ? "completed" : "no_results",
      description: "Auto-generated red team, phishing, and purple team campaign recommendations based on discovered assets, vulnerabilities, and threat actor TTPs.",
      outputs: `${((scan.campaignRecommendations || []) as any[]).length} campaigns designed`,
      attribution: 'emulation framework abilities reference real ATT&CK technique IDs. Verify at: https://attack.mitre.org/techniques/<ID>',
      fpRisk: "N/A — recommendations, not findings.",
      verifyCmd: "Review campaigns in the Campaigns tab",
    },
  ];

  const categories = ["Passive Data Collection", "Discovery", "Vulnerability Intelligence", "Risk Scoring", "Threat Intelligence", "Offensive Planning"];

  return (
    <>
      {/* Page description */}
      <Card className="bg-purple-500/5 border-purple-500/20">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            <Info className="h-5 w-5 text-purple-400 mt-0.5 shrink-0" />
            <div>
              <p className="text-sm font-semibold">Scan Methods & Attribution</p>
              <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                This tab shows every method that was executed during this full-scope domain intelligence scan.
                Each method includes what it found, how to verify the results independently, and the false positive risk level.
                Use this information to validate findings before acting on them.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-purple-400">{METHODS.length}</p>
            <p className="text-[10px] text-muted-foreground">Methods Executed</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-emerald-400">{METHODS.filter(m => m.status === 'completed').length}</p>
            <p className="text-[10px] text-muted-foreground">Produced Results</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-cyan-400">{categories.length}</p>
            <p className="text-[10px] text-muted-foreground">Categories Covered</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-yellow-400">{allFindings.length}</p>
            <p className="text-[10px] text-muted-foreground">Total Findings</p>
          </CardContent>
        </Card>
      </div>

      {/* Methods by category */}
      {categories.map(category => {
        const methods = METHODS.filter(m => m.category === category);
        if (methods.length === 0) return null;
        return (
          <div key={category}>
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">{category}</p>
            <div className="space-y-2">
              {methods.map(method => {
                const Icon = method.icon;
                const isCompleted = method.status === 'completed';
                return (
                  <Card key={method.id} className={isCompleted ? "border-emerald-500/20" : "border-border/40 opacity-60"}>
                    <CardContent className="p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <div className={`p-1.5 rounded-lg ${isCompleted ? 'bg-emerald-500/10' : 'bg-muted'}`}>
                            <Icon className={`h-4 w-4 ${isCompleted ? 'text-emerald-400' : 'text-muted-foreground'}`} />
                          </div>
                          <div>
                            <p className="font-semibold text-sm">{method.name}</p>
                            <p className="text-[10px] text-muted-foreground">{method.category}</p>
                          </div>
                        </div>
                        <Badge className={isCompleted
                          ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/40 text-[10px]"
                          : "bg-muted text-muted-foreground text-[10px]"
                        }>
                          {isCompleted ? "Results Found" : "No Results"}
                        </Badge>
                      </div>

                      <p className="text-xs text-muted-foreground leading-relaxed">{method.description}</p>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-border/40">
                        <div className="space-y-1.5">
                          <div className="flex items-start gap-2">
                            <Badge className="text-[8px] bg-emerald-500/20 text-emerald-400 border-emerald-500/40 shrink-0">OUTPUT</Badge>
                            <span className="text-[10px] text-foreground/80">{method.outputs}</span>
                          </div>
                          <div className="flex items-start gap-2">
                            <Badge className="text-[8px] bg-orange-500/20 text-orange-400 border-orange-500/40 shrink-0">FP RISK</Badge>
                            <span className="text-[10px] text-muted-foreground">{method.fpRisk}</span>
                          </div>
                        </div>
                        <div className="space-y-1.5">
                          <div className="flex items-start gap-2">
                            <Badge className="text-[8px] bg-cyan-500/20 text-cyan-400 border-cyan-500/40 shrink-0">VERIFY</Badge>
                            <span className="text-[10px] text-muted-foreground">{method.attribution}</span>
                          </div>
                          <div className="flex items-start gap-2">
                            <Badge className="text-[8px] bg-purple-500/20 text-purple-400 border-purple-500/40 shrink-0">CMD</Badge>
                            <code className="text-[10px] text-purple-400/80 font-mono bg-muted/30 px-1 rounded">{method.verifyCmd}</code>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </div>
        );
      })}

      {/* Corroboration Tiers Explanation */}
      <div>
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Finding Corroboration Tiers</p>
        <p className="text-xs text-muted-foreground mb-3">
          Every finding is assigned a corroboration tier that indicates how much evidence supports it.
          Severity scores are capped based on the tier to prevent inflated risk from unverified findings.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {[
            { tier: "CONFIRMED", count: confirmedFindings.length, color: "text-emerald-400 bg-emerald-500/20 border-emerald-500/40", desc: "Technology version detected AND matched to CVE affected range. Severity uncapped.", verify: "Check CVE affected version range against detected version." },
            { tier: "PROBABLE", count: probableFindings.length, color: "text-yellow-400 bg-yellow-500/20 border-yellow-500/40", desc: "Product detected but version unknown. CVE exists for product family. Severity capped at 6/10.", verify: "Confirm actual version to determine if it falls within CVE range." },
            { tier: "POTENTIAL", count: potentialFindings.length, color: "text-purple-400 bg-purple-500/20 border-purple-500/40", desc: "LLM-inferred risk with no CVE backing. Severity capped at 4/10. Advisory only.", verify: "Perform manual assessment or active scanning." },
          ].map(t => (
            <Card key={t.tier} className={`border ${t.color.split(' ').filter(c => c.startsWith('border-')).join(' ')}`}>
              <CardContent className="p-3 space-y-2">
                <div className="flex items-center justify-between">
                  <Badge className={`text-[10px] ${t.color}`}>{t.tier}</Badge>
                  <span className="text-lg font-bold">{t.count}</span>
                </div>
                <p className="text-[10px] text-muted-foreground">{t.desc}</p>
                <p className="text-[10px] text-cyan-400/80"><span className="font-medium">Verify:</span> {t.verify}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </>
  );
}

// ─── Vulnerability Intelligence Section for Domain Intel ───
function VulnIntelSection({ scanId }: { scanId: number }) {
  const [expandedTech, setExpandedTech] = useState<string | null>(null);
  const [expandedCve, setExpandedCve] = useState<string | null>(null);

  const { data, isLoading, error } = trpc.calderaProxy.matchTechVulns.useQuery(
    { scanId },
    { enabled: !!scanId }
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-purple-400 mr-2" />
        <span className="text-muted-foreground">Matching discovered technologies against vulnerability feeds...</span>
      </div>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-8 text-center text-muted-foreground">
          <AlertTriangle className="h-8 w-8 mx-auto mb-2 text-destructive" />
          <p>Failed to load vulnerability intelligence. Feeds may still be loading.</p>
        </CardContent>
      </Card>
    );
  }

  if (!data || data.matches.length === 0) {
    return (
      <Card>
        <CardContent className="p-8 text-center text-muted-foreground">
          <Shield className="h-8 w-8 mx-auto mb-2 text-green-400" />
          <p className="font-semibold">No known vulnerabilities matched</p>
          <p className="text-xs mt-1">No discovered technologies matched against known exploited vulnerabilities (KEV), zero-day research, NVD, advisory feeds, or public exploit databases feeds.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="border-red-500/30 bg-red-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <Bug className="h-3.5 w-3.5 text-red-500" />
              <span className="text-[10px] text-muted-foreground">Total Vulns</span>
            </div>
            <div className="text-xl font-bold text-red-400 mt-0.5">{data.totalVulns}</div>
          </CardContent>
        </Card>
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <Crosshair className="h-3.5 w-3.5 text-amber-500" />
              <span className="text-[10px] text-muted-foreground">Exploits</span>
            </div>
            <div className="text-xl font-bold text-amber-400 mt-0.5">{data.totalExploits}</div>
          </CardContent>
        </Card>
        <Card className="border-orange-500/30 bg-orange-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5 text-orange-500" />
              <span className="text-[10px] text-muted-foreground">KEV</span>
            </div>
            <div className="text-xl font-bold text-orange-400 mt-0.5">{data.totalKev}</div>
          </CardContent>
        </Card>
        <Card className="border-purple-500/30 bg-purple-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <Zap className="h-3.5 w-3.5 text-purple-500" />
              <span className="text-[10px] text-muted-foreground">0-Day</span>
            </div>
            <div className="text-xl font-bold text-purple-400 mt-0.5">{data.totalZeroDay}</div>
          </CardContent>
        </Card>
        <Card className="border-blue-500/30 bg-blue-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <TrendingUp className="h-3.5 w-3.5 text-blue-500" />
              <span className="text-[10px] text-muted-foreground">Risk Boost</span>
            </div>
            <div className="text-xl font-bold text-blue-400 mt-0.5">+{data.overallRiskBoost}</div>
          </CardContent>
        </Card>
      </div>

      {/* Technology Matches */}
      <div className="space-y-2">
        {data.matches.map((match: any) => {
          const isExpanded = expandedTech === match.technology;
          const sevColors: Record<string, string> = {
            critical: "border-red-500/40 bg-red-500/5",
            high: "border-orange-500/40 bg-orange-500/5",
            medium: "border-yellow-500/40 bg-yellow-500/5",
            low: "border-blue-500/40 bg-blue-500/5",
            unknown: "border-border",
          };

          return (
            <Card
              key={match.technology}
              className={`transition-all ${sevColors[match.maxSeverity] || sevColors.unknown} ${isExpanded ? "ring-1 ring-accent/30" : ""}`}
            >
              <div
                className="p-3 cursor-pointer flex items-center gap-3"
                onClick={() => setExpandedTech(isExpanded ? null : match.technology)}
              >
                <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-muted/50 shrink-0">
                  <span className="text-sm font-bold">{match.riskScore}</span>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <Database className="h-3.5 w-3.5 text-accent" />
                    <span className="font-semibold text-sm">{match.technology}</span>
                  </div>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-[10px] text-muted-foreground">{match.vulns.length} CVEs</span>
                    {match.exploitCount > 0 && (
                      <Badge className="bg-amber-600/80 text-white text-[8px] h-4">{match.exploitCount} exploits</Badge>
                    )}
                    {match.kevCount > 0 && (
                      <Badge className="bg-red-600/80 text-white text-[8px] h-4">{match.kevCount} KEV</Badge>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <Badge className={`text-[9px] capitalize ${
                    match.maxSeverity === "critical" ? "bg-red-600/80 text-white" :
                    match.maxSeverity === "high" ? "bg-orange-600/80 text-white" :
                    match.maxSeverity === "medium" ? "bg-yellow-600/80 text-white" :
                    "bg-blue-600/80 text-white"
                  }`}>{match.maxSeverity}</Badge>
                  {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                </div>
              </div>

              {isExpanded && (
                <CardContent className="pt-0 pb-3 border-t border-border/50">
                  <div className="space-y-1.5 mt-3">
                    {match.vulns.map((vuln: any) => (
                      <div
                        key={vuln.cveId}
                        className={`p-2.5 rounded border border-border/50 cursor-pointer transition-all hover:border-accent/40 ${expandedCve === vuln.cveId ? "bg-muted/30" : ""}`}
                        onClick={() => setExpandedCve(expandedCve === vuln.cveId ? null : vuln.cveId)}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="font-mono text-xs font-bold text-accent">{vuln.cveId}</span>
                            <Badge className={`text-[8px] ${
                              vuln.severity === "critical" ? "bg-red-600/80 text-white" :
                              vuln.severity === "high" ? "bg-orange-600/80 text-white" :
                              vuln.severity === "medium" ? "bg-yellow-600/80 text-white" :
                              "bg-blue-600/80 text-white"
                            }`}>{vuln.severity?.toUpperCase()}</Badge>
                            {vuln.cvssScore && <Badge variant="outline" className="text-[8px] font-mono">CVSS {vuln.cvssScore}</Badge>}
                            {vuln.kevListed && <Badge className="bg-red-600/80 text-white text-[8px]">KEV</Badge>}
                            {vuln.inTheWild && <Badge className="bg-purple-600/80 text-white text-[8px]">0-DAY</Badge>}
                            {vuln.exploitAvailable && !vuln.inTheWild && <Badge className="bg-amber-600/80 text-white text-[8px]">EXPLOIT</Badge>}
                            {vuln.ransomwareLinked && <Badge className="bg-pink-600/80 text-white text-[8px]">RANSOMWARE</Badge>}
                          </div>
                          <span className="text-[10px] text-muted-foreground">{vuln.datePublished?.slice(0, 10)}</span>
                        </div>
                        {expandedCve === vuln.cveId && (
                          <div className="mt-2 pt-2 border-t border-border/30">
                            <p className="text-xs text-muted-foreground">{vuln.description}</p>
                            <div className="flex gap-2 mt-2">
                              {vuln.sources?.map((s: string) => {
                                const labels: Record<string, string> = {
                                  cisa_kev: "KEV", project_zero: "zero-day research", nvd: "NVD", circl: "advisory feeds", exploit_db: "public exploit databases",
                                };
                                return <Badge key={s} variant="outline" className="text-[8px]">{labels[s] || s}</Badge>;
                              })}
                            </div>
                            <div className="flex gap-2 mt-2">
                              <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cveId}`} target="_blank" rel="noopener noreferrer" className="text-[10px] text-blue-400 hover:underline flex items-center gap-0.5" onClick={e => e.stopPropagation()}>
                                <ExternalLink className="h-2.5 w-2.5" /> NVD
                              </a>
                              {vuln.exploitDbId && (
                                <a href={`https://www.exploit-db.com/exploits/${vuln.exploitDbId}`} target="_blank" rel="noopener noreferrer" className="text-[10px] text-amber-400 hover:underline flex items-center gap-0.5" onClick={e => e.stopPropagation()}>
                                  <ExternalLink className="h-2.5 w-2.5" /> public exploit databases
                                </a>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </CardContent>
              )}
            </Card>
          );
        })}
      </div>
    </>
  );
}


/** Validate Top 10 — quick-action banner for launching targeted validation from scan results */
function ValidateTop10Banner({ scanId, validationSummary }: { scanId: number; validationSummary: any }) {
  const [showMsfSelect, setShowMsfSelect] = useState(false);
  const [selectedMsf, setSelectedMsf] = useState<string>("");
  const msfServersQuery = trpc.metasploit.listServers.useQuery(undefined, { enabled: showMsfSelect });
  const startRunMutation = trpc.validation.startRun.useMutation({
    onSuccess: (data) => {
      toast.success(`Validation run #${data.runId} started — validating ${data.totalCandidates} candidates in ${data.mode} mode`);
      setShowMsfSelect(false);
    },
    onError: (err) => {
      toast.error(`Validation failed: ${err.message}`);
    },
  });

  // If validation already exists for this scan, show summary instead
  if (validationSummary?.hasValidation) {
    const run = validationSummary.run;
    return (
      <Card className="border-emerald-500/30 bg-emerald-500/5">
        <CardContent className="p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-emerald-500/10">
              <FlaskConical className="h-5 w-5 text-emerald-400" />
            </div>
            <div>
              <p className="font-semibold text-sm flex items-center gap-2">
                Exploit Validation Complete
                <Badge variant="outline" className="text-xs border-emerald-500/40 text-emerald-400">
                  {validationSummary.exploitableCount} exploitable
                </Badge>
                <Badge variant="outline" className="text-xs border-zinc-500/40 text-zinc-400">
                  {validationSummary.totalValidated} validated
                </Badge>
              </p>
              <p className="text-xs text-muted-foreground mt-0.5">
                {run?.mode === 'check_only' ? 'Non-destructive check' : run?.mode === 'safe_exploit' ? 'Safe exploit' : 'Auxiliary scan'} mode
                {run?.completedAt ? ` — completed ${new Date(run.completedAt).toLocaleString()}` : ''}
              </p>
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="text-xs"
            onClick={() => window.location.href = '/validation-engine'}
          >
            <FlaskConical className="h-3.5 w-3.5 mr-1.5" /> View Full Results
          </Button>
        </CardContent>
      </Card>
    );
  }

  // Show the launch button
  return (
    <Card className="border-amber-500/30 bg-amber-500/5">
      <CardContent className="p-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-amber-500/10">
            <FlaskConical className="h-5 w-5 text-amber-400" />
          </div>
          <div>
            <p className="font-semibold text-sm">Validate Top 10 Critical Findings</p>
            <p className="text-xs text-muted-foreground mt-0.5">
              Run safe, non-destructive exploit validation against the highest-confidence KEV matches and MSF module targets. Results feed directly into risk scores.
            </p>
          </div>
        </div>
        {!showMsfSelect ? (
          <Button
            className="bg-amber-600 hover:bg-amber-700 shrink-0 text-xs"
            size="sm"
            onClick={() => setShowMsfSelect(true)}
          >
            <FlaskConical className="h-3.5 w-3.5 mr-1.5" /> Validate Top 10
          </Button>
        ) : (
          <div className="flex items-center gap-2 shrink-0">
            <Select value={selectedMsf} onValueChange={setSelectedMsf}>
              <SelectTrigger className="w-44 h-8 text-xs">
                <SelectValue placeholder="Select C2 Server" />
              </SelectTrigger>
              <SelectContent>
                {(msfServersQuery.data || []).map((s: any) => (
                  <SelectItem key={s.id} value={String(s.id)}>
                    {s.name || s.host}
                  </SelectItem>
                ))}
                {(msfServersQuery.data || []).length === 0 && (
                  <SelectItem value="none" disabled>No servers configured</SelectItem>
                )}
              </SelectContent>
            </Select>
            <Button
              size="sm"
              className="bg-amber-600 hover:bg-amber-700 text-xs"
              disabled={!selectedMsf || selectedMsf === 'none' || startRunMutation.isPending}
              onClick={() => {
                startRunMutation.mutate({
                  scanId,
                  msfServerId: Number(selectedMsf),
                  mode: 'check_only',
                  maxCandidates: 10,
                });
              }}
            >
              {startRunMutation.isPending ? (
                <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
              ) : (
                <Zap className="h-3.5 w-3.5 mr-1.5" />
              )}
              Launch
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="text-xs"
              onClick={() => setShowMsfSelect(false)}
            >
              Cancel
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
