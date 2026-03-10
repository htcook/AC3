import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import HubTabs from "@/components/HubTabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { toast } from "sonner";
import {
  BarChart3, CheckCircle2, Download, Globe2, Landmark, Link,
  ShieldCheck, Activity, AlertTriangle, FileOutput, Loader2,
  ChevronDown, Zap, RefreshCw, Clock, Shield, Hash
} from "lucide-react";
import React, { lazy, useMemo } from "react";

const KsiDashboard = lazy(() => import("./KsiDashboard"));
const KsiEvidenceChain = lazy(() => import("./KsiEvidenceChain"));
const KsiAutoCollector = lazy(() => import("./KsiAutoCollector"));
const KsiThreatMap = lazy(() => import("./KsiThreatMap"));
const KsiValidation = lazy(() => import("./KsiValidation"));
const FedRAMP20xReadiness = lazy(() => import("./FedRAMP20xReadiness"));

const tabs = [
  { id: 'dashboard', label: 'Indicators', icon: BarChart3, component: KsiDashboard },
  { id: 'evidence', label: 'Evidence Chain', icon: Link, component: KsiEvidenceChain },
  { id: 'collector', label: 'Auto-Collection', icon: Download, component: KsiAutoCollector },
  { id: 'threats', label: 'Threat Map', icon: Globe2, component: KsiThreatMap },
  { id: 'validation', label: 'Validation', icon: CheckCircle2, component: KsiValidation },
  { id: 'fedramp', label: 'FedRAMP 20x', icon: Landmark, component: FedRAMP20xReadiness },
];

function ReadinessGauge({ score }: { score: number }) {
  const color = score >= 80 ? "text-emerald-500" : score >= 50 ? "text-amber-500" : "text-red-500";
  const bgColor = score >= 80 ? "bg-emerald-500/10" : score >= 50 ? "bg-amber-500/10" : "bg-red-500/10";
  const ringColor = score >= 80 ? "stroke-emerald-500" : score >= 50 ? "stroke-amber-500" : "stroke-red-500";
  const circumference = 2 * Math.PI * 28;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className={`relative flex items-center justify-center w-20 h-20 rounded-full ${bgColor}`}>
      <svg className="absolute w-20 h-20 -rotate-90" viewBox="0 0 64 64">
        <circle cx="32" cy="32" r="28" fill="none" stroke="currentColor" strokeWidth="4" className="text-muted/30" />
        <circle
          cx="32" cy="32" r="28" fill="none" strokeWidth="4"
          className={ringColor}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
        />
      </svg>
      <span className={`text-lg font-bold ${color}`}>{score}</span>
    </div>
  );
}

export default function KsiHub() {
  const coverageSummary = trpc.ksiEvidenceChain.getCoverageSummary.useQuery();
  const evidenceStats = trpc.ksiEvidenceChain.getDashboardStats.useQuery();
  const validationDashboard = trpc.ksiValidationScheduler.getDashboard.useQuery();

  const seedMutation = trpc.ksiEvidenceChain.seedCatalog.useMutation({
    onSuccess: (data) => {
      toast.success(`Catalog seeded: ${data.seeded} of ${data.total} KSIs added`);
      coverageSummary.refetch();
    },
    onError: (err) => toast.error("Seed failed: " + err.message),
  });

  const initSchedulesMutation = trpc.ksiValidationScheduler.initializeSchedules.useMutation({
    onSuccess: (data) => {
      toast.success(`${data.created} validation schedules initialized`);
      validationDashboard.refetch();
    },
  });

  const coverage = coverageSummary.data;
  const evStats = evidenceStats.data;
  const valDash = validationDashboard.data;

  // Compute readiness score: weighted composite of coverage, validation pass rate, evidence freshness, chain integrity
  const readinessScore = useMemo(() => {
    const coveragePct = coverage?.overallCoverage || 0;
    const passRate = valDash?.passRate || 0;
    const evidenceCount = evStats?.totalEvidence || 0;
    const validChains = evStats?.validChains || 0;
    const brokenChains = evStats?.brokenChains || 0;
    const chainIntegrity = (validChains + brokenChains) > 0
      ? (validChains / (validChains + brokenChains)) * 100
      : (evidenceCount > 0 ? 50 : 0);
    const evidenceScore = Math.min(evidenceCount * 2, 100); // cap at 50 items = 100%

    // Weighted: coverage 40%, validation 25%, evidence 20%, chain integrity 15%
    return Math.round(coveragePct * 0.4 + passRate * 0.25 + evidenceScore * 0.2 + chainIntegrity * 0.15);
  }, [coverage, valDash, evStats]);

  const overdueCount = valDash?.overdueSchedules || 0;
  const failedCount = valDash?.failedRuns || 0;

  const isLoading = coverageSummary.isLoading || evidenceStats.isLoading || validationDashboard.isLoading;

  return (
    <AppShell activePath="/ksi-dashboard">
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-7 h-7 text-blue-500" />
          <div>
            <h1 className="font-display tracking-wider text-xl">Key Security Indicators (KSI)</h1>
            <p className="text-sm text-muted-foreground">
              Continuous monitoring of evidence chains, threat mapping, and validation across 13 FedRAMP 20x security themes
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm">
                <Zap className="h-4 w-4 mr-1" />
                Quick Actions
                <ChevronDown className="h-3 w-3 ml-1" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => seedMutation.mutate()} disabled={seedMutation.isPending}>
                {seedMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Activity className="h-4 w-4 mr-2" />}
                Seed Indicator Catalog
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => initSchedulesMutation.mutate({})}>
                <Clock className="h-4 w-4 mr-2" />
                Initialize Schedules
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => {
                coverageSummary.refetch();
                evidenceStats.refetch();
                validationDashboard.refetch();
                toast.success("Refreshing all KSI data...");
              }}>
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh All Data
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => toast.info("Navigate to FedRAMP 20x tab to export OSCAL")}>
                <FileOutput className="h-4 w-4 mr-2" />
                Export OSCAL
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Health Summary Bar */}
      <div className="grid grid-cols-1 lg:grid-cols-[auto_1fr] gap-4 mb-6">
        {/* Readiness Score Gauge */}
        <div className="flex items-center gap-4 bg-card border rounded-lg px-5 py-4">
          <ReadinessGauge score={readinessScore} />
          <div>
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Readiness Score</div>
            <div className="text-sm font-medium mt-0.5">
              {readinessScore >= 80 ? "Strong posture" : readinessScore >= 50 ? "Needs attention" : "Action required"}
            </div>
            <div className="text-xs text-muted-foreground mt-0.5">
              Coverage + Validation + Evidence + Integrity
            </div>
          </div>
        </div>

        {/* KPI Strip */}
        <TooltipProvider>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="bg-card border rounded-lg px-4 py-3 flex items-center gap-3">
                  <div className="h-9 w-9 rounded-full bg-blue-500/10 flex items-center justify-center">
                    <BarChart3 className="h-4 w-4 text-blue-500" />
                  </div>
                  <div>
                    <div className="text-xl font-bold">{isLoading ? "—" : `${coverage?.overallCoverage || 0}%`}</div>
                    <div className="text-xs text-muted-foreground">Coverage</div>
                  </div>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <p>{coverage?.directCount || 0} direct + {coverage?.supportingCount || 0} supporting of {coverage?.totalKSIs || 0} KSIs</p>
              </TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <div className="bg-card border rounded-lg px-4 py-3 flex items-center gap-3">
                  <div className="h-9 w-9 rounded-full bg-purple-500/10 flex items-center justify-center">
                    <Hash className="h-4 w-4 text-purple-500" />
                  </div>
                  <div>
                    <div className="text-xl font-bold">{isLoading ? "—" : (evStats?.totalEvidence || 0)}</div>
                    <div className="text-xs text-muted-foreground">Evidence</div>
                  </div>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <p>{evStats?.autoCollected || 0} auto-collected, {evStats?.manualCount || 0} manual</p>
              </TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <div className="bg-card border rounded-lg px-4 py-3 flex items-center gap-3">
                  <div className="h-9 w-9 rounded-full bg-emerald-500/10 flex items-center justify-center">
                    <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                  </div>
                  <div>
                    <div className="text-xl font-bold">{isLoading ? "—" : `${valDash?.passRate || 0}%`}</div>
                    <div className="text-xs text-muted-foreground">Pass Rate</div>
                  </div>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <p>{valDash?.passedRuns || 0} passed of {valDash?.totalRuns || 0} total runs</p>
              </TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <div className={`bg-card border rounded-lg px-4 py-3 flex items-center gap-3 ${overdueCount > 0 ? "border-amber-500/50" : ""}`}>
                  <div className={`h-9 w-9 rounded-full flex items-center justify-center ${overdueCount > 0 ? "bg-amber-500/10" : "bg-muted"}`}>
                    <AlertTriangle className={`h-4 w-4 ${overdueCount > 0 ? "text-amber-500" : "text-muted-foreground"}`} />
                  </div>
                  <div>
                    <div className="text-xl font-bold">{isLoading ? "—" : overdueCount}</div>
                    <div className="text-xs text-muted-foreground">Overdue</div>
                  </div>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <p>{overdueCount} validation schedules are past due</p>
              </TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <div className="bg-card border rounded-lg px-4 py-3 flex items-center gap-3">
                  <div className={`h-9 w-9 rounded-full flex items-center justify-center ${(evStats?.brokenChains || 0) > 0 ? "bg-red-500/10" : "bg-emerald-500/10"}`}>
                    <Shield className={`h-4 w-4 ${(evStats?.brokenChains || 0) > 0 ? "text-red-500" : "text-emerald-500"}`} />
                  </div>
                  <div>
                    <div className="text-xl font-bold">{isLoading ? "—" : `${evStats?.validChains || 0}/${(evStats?.validChains || 0) + (evStats?.brokenChains || 0)}`}</div>
                    <div className="text-xs text-muted-foreground">Chain Integrity</div>
                  </div>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <p>{evStats?.validChains || 0} valid, {evStats?.brokenChains || 0} broken chains</p>
              </TooltipContent>
            </Tooltip>
          </div>
        </TooltipProvider>
      </div>

      <HubTabs tabs={tabs} storageKey="ksi-hub" />
    </AppShell>
  );
}
