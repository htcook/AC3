/**
 * Coverage & Quality Panel — Displays deduplication stats, coverage gap analysis,
 * and NIST 800-53 / MITRE ATT&CK / CWE compliance enrichment for an engagement.
 *
 * Shows:
 *   1. Dedup summary — duplicates removed, merge log, severity changes
 *   2. Compliance Enrichment — NIST controls, MITRE techniques, CWEs mapped to findings
 *   3. Coverage score — overall and per-asset scan completeness
 *   4. Coverage gaps — missing checks with NIST/MITRE cross-references
 *
 * @author Harrison Cook — AceofCloud
 */

import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  AlertTriangle,
  CheckCircle2,
  Scissors,
  ShieldAlert,
  ShieldCheck,
  BarChart3,
  Info,
  Target,
  Bug,
  FileWarning,
  Download,
  FileJson,
  FileText,
  Loader2,
  Search,
} from "lucide-react";
import { trpc } from "@/lib/trpc";
import { useToast } from "@/hooks/use-toast";

// ─── Types ───────────────────────────────────────────────────────────────

interface NistControl {
  controlId: string;
  controlTitle: string;
  family: string;
  familyCode: string;
  baseline: string;
}

interface MitreTechnique {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  parentId?: string;
}

interface CweEntry {
  cweId: string;
  cweName: string;
  category: string;
}

interface FindingEnrichment {
  cwes: CweEntry[];
  nistControls: NistControl[];
  mitreTechniques: MitreTechnique[];
  nistPriority: string;
}

interface ComplianceEnrichmentSummary {
  totalNistControlsImpacted: number;
  impactedNistFamilies: Array<{ familyCode: string; familyName: string; controlCount: number }>;
  totalMitreTechniques: number;
  mitreTechniquesByTactic: Record<string, Array<{ techniqueId: string; techniqueName: string }>>;
  totalCwes: number;
  cwesByCategory: Record<string, CweEntry[]>;
  nistGapSummary: {
    totalControlsImpacted: number;
    criticalGaps: NistControl[];
    coverageScore: number;
    byFamily: Array<{ familyCode: string; familyName: string; controls: string[]; highestPriority: string }>;
  };
  findingEnrichments: Record<string, FindingEnrichment>;
}

interface DedupStats {
  totalFindingsBeforeDedup: number;
  totalFindingsAfterDedup: number;
  duplicatesRemoved: number;
  duplicatesByAsset: Record<string, number>;
  mergeLog: Array<{
    canonicalTitle: string;
    mergedCount: number;
    sources: string[];
  }>;
  normalizedSeverityChanges: number;
  processedAt: number;
  complianceEnrichment?: ComplianceEnrichmentSummary;
}

interface CoverageReport {
  overallScore: number;
  assetReports: Array<{
    hostname: string;
    score: number;
    gaps: Array<{
      category: string;
      description: string;
      severity: string;
      recommendation: string;
      missingChecks: string[];
      relatedNistControls?: string[];
      relatedMitreTechniques?: string[];
    }>;
    totalGaps: number;
    criticalGaps: number;
  }>;
  totalGaps: number;
  criticalGaps: number;
  recommendations: string[];
  processedAt: number;
}

interface CoverageQualityProps {
  dedupStats?: DedupStats | null;
  coverageReport?: CoverageReport | null;
  engagementPhase?: string;
  /** Engagement name for report metadata */
  engagementName?: string;
  /** Organization name for report metadata */
  organizationName?: string;
  /** Raw findings for export (id, title, severity, cwes, cves, techniqueIds) */
  findings?: Array<{
    id: string;
    title: string;
    severity: string;
    cwes?: string[];
    cves?: string[];
    techniqueIds?: string[];
    target?: string;
    source?: string;
  }>;
}

// ─── Helpers ─────────────────────────────────────────────────────────────

function getScoreColor(score: number): string {
  if (score >= 80) return "text-green-400";
  if (score >= 60) return "text-yellow-400";
  return "text-red-400";
}

function getScoreProgressColor(score: number): string {
  if (score >= 80) return "bg-green-500";
  if (score >= 60) return "bg-yellow-500";
  return "bg-red-500";
}

function getSeverityBadge(severity: string) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  };
  return (
    <Badge variant="outline" className={colors[severity] || colors.info}>
      {severity}
    </Badge>
  );
}

function getPriorityBadge(priority: string) {
  const colors: Record<string, string> = {
    P1: "bg-red-500/20 text-red-400 border-red-500/30",
    P2: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    P3: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    P4: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  };
  return (
    <Badge variant="outline" className={`text-xs ${colors[priority] || colors.P4}`}>
      {priority}
    </Badge>
  );
}

function formatTimestamp(ts: number): string {
  return new Date(ts).toLocaleString();
}

const TACTIC_ORDER = [
  "Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact",
];

function getTacticColor(tactic: string): string {
  const colors: Record<string, string> = {
    "Initial Access": "text-red-400 border-red-500/30",
    "Execution": "text-orange-400 border-orange-500/30",
    "Persistence": "text-yellow-400 border-yellow-500/30",
    "Privilege Escalation": "text-amber-400 border-amber-500/30",
    "Defense Evasion": "text-lime-400 border-lime-500/30",
    "Credential Access": "text-green-400 border-green-500/30",
    "Discovery": "text-teal-400 border-teal-500/30",
    "Lateral Movement": "text-cyan-400 border-cyan-500/30",
    "Collection": "text-blue-400 border-blue-500/30",
    "Command and Control": "text-indigo-400 border-indigo-500/30",
    "Exfiltration": "text-violet-400 border-violet-500/30",
    "Impact": "text-purple-400 border-purple-500/30",
  };
  return colors[tactic] || "text-gray-400 border-gray-500/30";
}

// ─── Component ───────────────────────────────────────────────────────────

export function CoverageQuality({ dedupStats, coverageReport, engagementPhase, engagementName, organizationName, findings }: CoverageQualityProps) {
  const hasData = dedupStats || coverageReport;
  const isPreVulnPhase = !engagementPhase || ["idle", "recon", "passive_discovery", "scoping_roe", "test_plan", "enumeration"].includes(engagementPhase);
  const enrichment = dedupStats?.complianceEnrichment;
  const { toast } = useToast();

  // Export state
  const [nistReportLoading, setNistReportLoading] = useState(false);
  const [navigatorLoading, setNavigatorLoading] = useState(false);
  const [cveSearchLoading, setCveSearchLoading] = useState(false);
  const [cveSearchId, setCveSearchId] = useState("");

  const nistReportMutation = trpc.complianceExports.generateNistReport.useMutation();
  const navigatorMutation = trpc.complianceExports.generateAttackNavigatorLayer.useMutation();
  const cveLookup = trpc.complianceExports.lookupCve.useQuery(
    { cveId: cveSearchId },
    { enabled: false }
  );

  // Download helper
  const downloadJson = (data: any, filename: string) => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleNistReportExport = async () => {
    if (!findings || findings.length === 0) {
      toast({ title: "No findings available", description: "Findings data is required to generate the NIST report.", variant: "destructive" });
      return;
    }
    setNistReportLoading(true);
    try {
      const report = await nistReportMutation.mutateAsync({
        findings,
        baseline: "moderate",
        organizationName: organizationName || "Organization",
        engagementName: engagementName || "Security Assessment",
      });
      downloadJson(report, `nist-800-53-report-${new Date().toISOString().split("T")[0]}.json`);
      toast({ title: "NIST 800-53 Report Generated", description: `Report includes ${report.executiveSummary.totalNistControlsImpacted} controls across ${report.executiveSummary.nistFamiliesImpacted} families.` });
    } catch (err: any) {
      toast({ title: "Report generation failed", description: err.message, variant: "destructive" });
    } finally {
      setNistReportLoading(false);
    }
  };

  const handleNavigatorExport = async () => {
    if (!findings || findings.length === 0) {
      toast({ title: "No findings available", description: "Findings data is required to generate the ATT&CK Navigator layer.", variant: "destructive" });
      return;
    }
    setNavigatorLoading(true);
    try {
      const result = await navigatorMutation.mutateAsync({
        findings,
        engagementName: engagementName || "Assessment",
        colorScheme: "severity",
      });
      downloadJson(result.layer, `attack-navigator-${new Date().toISOString().split("T")[0]}.json`);
      toast({ title: "ATT&CK Navigator Layer Exported", description: `Layer includes ${result.summary.totalTechniques} techniques across ${result.summary.tacticCoverage.length} tactics. Import into ATT\u00AE&CK Navigator at mitre-attack.github.io/attack-navigator/` });
    } catch (err: any) {
      toast({ title: "Navigator export failed", description: err.message, variant: "destructive" });
    } finally {
      setNavigatorLoading(false);
    }
  };

  if (!hasData) {
    return (
      <div className="space-y-4">
        <Card className="border-border/50 bg-card/50">
          <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <BarChart3 className="h-12 w-12 mb-4 opacity-40" />
            <p className="text-lg font-medium">Coverage & Quality Analysis</p>
            <p className="text-sm mt-1">
              {isPreVulnPhase
                ? "This analysis runs automatically after the vulnerability detection phase completes."
                : "Waiting for deduplication and coverage analysis to complete..."}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* ── Dedup Summary ── */}
      {dedupStats && (
        <Card className="border-border/50">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <Scissors className="h-5 w-5 text-blue-400" />
              <CardTitle className="text-lg">Finding Deduplication</CardTitle>
            </div>
            <CardDescription>
              Cross-scanner duplicate detection and severity normalization
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="rounded-lg border border-border/50 p-3 text-center">
                <div className="text-2xl font-bold text-foreground">{dedupStats.totalFindingsBeforeDedup}</div>
                <div className="text-xs text-muted-foreground mt-1">Raw Findings</div>
              </div>
              <div className="rounded-lg border border-border/50 p-3 text-center">
                <div className="text-2xl font-bold text-green-400">{dedupStats.totalFindingsAfterDedup}</div>
                <div className="text-xs text-muted-foreground mt-1">After Dedup</div>
              </div>
              <div className="rounded-lg border border-border/50 p-3 text-center">
                <div className="text-2xl font-bold text-orange-400">{dedupStats.duplicatesRemoved}</div>
                <div className="text-xs text-muted-foreground mt-1">Duplicates Removed</div>
              </div>
              <div className="rounded-lg border border-border/50 p-3 text-center">
                <div className="text-2xl font-bold text-purple-400">{dedupStats.normalizedSeverityChanges}</div>
                <div className="text-xs text-muted-foreground mt-1">Severity Normalizations</div>
              </div>
            </div>

            {/* Per-Asset Dedup */}
            {Object.keys(dedupStats.duplicatesByAsset).length > 0 && (
              <Accordion type="single" collapsible>
                <AccordionItem value="per-asset" className="border-border/50">
                  <AccordionTrigger className="text-sm hover:no-underline">
                    Duplicates by Asset ({Object.keys(dedupStats.duplicatesByAsset).length} assets)
                  </AccordionTrigger>
                  <AccordionContent>
                    <div className="space-y-2">
                      {Object.entries(dedupStats.duplicatesByAsset)
                        .sort(([, a], [, b]) => b - a)
                        .map(([hostname, count]) => (
                          <div key={hostname} className="flex items-center justify-between text-sm py-1">
                            <span className="font-mono text-xs text-muted-foreground">{hostname}</span>
                            <Badge variant="outline" className={count > 0 ? "text-orange-400 border-orange-500/30" : "text-green-400 border-green-500/30"}>
                              {count} duplicates
                            </Badge>
                          </div>
                        ))}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            )}

            {/* Merge Log */}
            {dedupStats.mergeLog.length > 0 && (
              <Accordion type="single" collapsible>
                <AccordionItem value="merge-log" className="border-border/50">
                  <AccordionTrigger className="text-sm hover:no-underline">
                    Merge Log ({dedupStats.mergeLog.length} merges)
                  </AccordionTrigger>
                  <AccordionContent>
                    <Table>
                      <TableHeader>
                        <TableRow className="border-border/50">
                          <TableHead className="text-xs">Finding</TableHead>
                          <TableHead className="text-xs text-center">Merged</TableHead>
                          <TableHead className="text-xs">Sources</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {dedupStats.mergeLog.slice(0, 20).map((entry, i) => (
                          <TableRow key={i} className="border-border/30">
                            <TableCell className="text-xs font-mono max-w-[300px] truncate">
                              {entry.canonicalTitle}
                            </TableCell>
                            <TableCell className="text-center">
                              <Badge variant="outline" className="text-orange-400 border-orange-500/30">
                                {entry.mergedCount}x
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <div className="flex gap-1 flex-wrap">
                                {entry.sources.map((s, j) => (
                                  <Badge key={j} variant="outline" className="text-xs text-blue-400 border-blue-500/30">
                                    {s}
                                  </Badge>
                                ))}
                              </div>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                    {dedupStats.mergeLog.length > 20 && (
                      <p className="text-xs text-muted-foreground mt-2 text-center">
                        Showing 20 of {dedupStats.mergeLog.length} merges
                      </p>
                    )}
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            )}

            <p className="text-xs text-muted-foreground">
              Processed at {formatTimestamp(dedupStats.processedAt)}
            </p>
          </CardContent>
        </Card>
      )}

      {/* ── Compliance Export Actions ── */}
      {(enrichment || (findings && findings.length > 0)) && (
        <Card className="border-border/50 border-sky-500/20">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <Download className="h-5 w-5 text-sky-400" />
              <CardTitle className="text-lg">Compliance Exports</CardTitle>
            </div>
            <CardDescription>
              Download compliance reports and ATT&CK Navigator layers for audit and analysis
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {/* NIST 800-53 Report */}
              <Button
                variant="outline"
                className="h-auto py-3 px-4 justify-start gap-3 border-emerald-500/30 hover:bg-emerald-500/10"
                onClick={handleNistReportExport}
                disabled={nistReportLoading || !findings || findings.length === 0}
              >
                {nistReportLoading ? (
                  <Loader2 className="h-5 w-5 animate-spin text-emerald-400" />
                ) : (
                  <FileText className="h-5 w-5 text-emerald-400" />
                )}
                <div className="text-left">
                  <div className="text-sm font-medium">NIST 800-53 Report</div>
                  <div className="text-xs text-muted-foreground">Structured JSON for audit submission</div>
                </div>
              </Button>

              {/* MITRE ATT&CK Navigator Layer */}
              <Button
                variant="outline"
                className="h-auto py-3 px-4 justify-start gap-3 border-rose-500/30 hover:bg-rose-500/10"
                onClick={handleNavigatorExport}
                disabled={navigatorLoading || !findings || findings.length === 0}
              >
                {navigatorLoading ? (
                  <Loader2 className="h-5 w-5 animate-spin text-rose-400" />
                ) : (
                  <FileJson className="h-5 w-5 text-rose-400" />
                )}
                <div className="text-left">
                  <div className="text-sm font-medium">ATT&CK Navigator Layer</div>
                  <div className="text-xs text-muted-foreground">Import into MITRE ATT&CK Navigator</div>
                </div>
              </Button>
            </div>

            {(!findings || findings.length === 0) && (
              <p className="text-xs text-muted-foreground mt-3">
                Exports require finding data. Complete the vulnerability detection phase to enable exports.
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {/* ── NIST 800-53 / MITRE ATT&CK / CWE Compliance Enrichment ── */}
      {enrichment && (
        <Card className="border-border/50">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-emerald-400" />
              <CardTitle className="text-lg">Compliance Mapping</CardTitle>
            </div>
            <CardDescription>
              NIST 800-53 Rev 5 controls, MITRE ATT&CK techniques, and CWE classifications mapped to findings
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            {/* Summary Stats */}
            <div className="grid grid-cols-3 gap-4">
              <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 text-center">
                <div className="text-2xl font-bold text-emerald-400">{enrichment.totalNistControlsImpacted}</div>
                <div className="text-xs text-muted-foreground mt-1">NIST 800-53 Controls</div>
              </div>
              <div className="rounded-lg border border-rose-500/20 bg-rose-500/5 p-3 text-center">
                <div className="text-2xl font-bold text-rose-400">{enrichment.totalMitreTechniques}</div>
                <div className="text-xs text-muted-foreground mt-1">MITRE ATT&CK Techniques</div>
              </div>
              <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-center">
                <div className="text-2xl font-bold text-amber-400">{enrichment.totalCwes}</div>
                <div className="text-xs text-muted-foreground mt-1">CWE Classifications</div>
              </div>
            </div>

            {/* NIST 800-53 Control Families */}
            {enrichment.impactedNistFamilies.length > 0 && (
              <Accordion type="single" collapsible>
                <AccordionItem value="nist-families" className="border-border/50">
                  <AccordionTrigger className="text-sm hover:no-underline">
                    <div className="flex items-center gap-2">
                      <ShieldCheck className="h-4 w-4 text-emerald-400" />
                      NIST 800-53 Control Families ({enrichment.impactedNistFamilies.length} impacted)
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <Table>
                      <TableHeader>
                        <TableRow className="border-border/50">
                          <TableHead className="text-xs">Family</TableHead>
                          <TableHead className="text-xs">Name</TableHead>
                          <TableHead className="text-xs text-center">Controls</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {enrichment.impactedNistFamilies.map((fam) => (
                          <TableRow key={fam.familyCode} className="border-border/30">
                            <TableCell>
                              <Badge variant="outline" className="text-xs text-emerald-400 border-emerald-500/30 font-mono">
                                {fam.familyCode}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-xs">{fam.familyName}</TableCell>
                            <TableCell className="text-center">
                              <span className="text-sm font-bold text-emerald-400">{fam.controlCount}</span>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            )}

            {/* NIST Gap Summary */}
            {enrichment.nistGapSummary.byFamily.length > 0 && (
              <Accordion type="single" collapsible>
                <AccordionItem value="nist-gaps" className="border-border/50">
                  <AccordionTrigger className="text-sm hover:no-underline">
                    <div className="flex items-center gap-2">
                      <FileWarning className="h-4 w-4 text-yellow-400" />
                      NIST Control Gap Analysis
                      {enrichment.nistGapSummary.criticalGaps.length > 0 && (
                        <Badge variant="outline" className="text-xs text-red-400 border-red-500/30 ml-2">
                          {enrichment.nistGapSummary.criticalGaps.length} critical gaps
                        </Badge>
                      )}
                    </div>
                  </AccordionTrigger>
                  <AccordionContent className="space-y-3">
                    {/* Critical Gaps */}
                    {enrichment.nistGapSummary.criticalGaps.length > 0 && (
                      <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-3 space-y-2">
                        <div className="text-xs font-medium text-red-400 uppercase tracking-wider">
                          Critical / High Priority Gaps
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                          {enrichment.nistGapSummary.criticalGaps.map((ctrl) => (
                            <Tooltip key={ctrl.controlId}>
                              <TooltipTrigger>
                                <Badge variant="outline" className="text-xs text-red-400 border-red-500/30 font-mono cursor-help">
                                  {ctrl.controlId}
                                </Badge>
                              </TooltipTrigger>
                              <TooltipContent side="top" className="max-w-xs">
                                <p className="font-medium">{ctrl.controlTitle}</p>
                                <p className="text-xs text-muted-foreground">{ctrl.family}</p>
                              </TooltipContent>
                            </Tooltip>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* By Family */}
                    <Table>
                      <TableHeader>
                        <TableRow className="border-border/50">
                          <TableHead className="text-xs">Family</TableHead>
                          <TableHead className="text-xs">Controls</TableHead>
                          <TableHead className="text-xs text-center">Priority</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {enrichment.nistGapSummary.byFamily.map((fam) => (
                          <TableRow key={fam.familyCode} className="border-border/30">
                            <TableCell>
                              <div className="flex items-center gap-2">
                                <Badge variant="outline" className="text-xs font-mono text-emerald-400 border-emerald-500/30">
                                  {fam.familyCode}
                                </Badge>
                                <span className="text-xs text-muted-foreground">{fam.familyName}</span>
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="flex flex-wrap gap-1">
                                {fam.controls.map((ctrl) => (
                                  <Badge key={ctrl} variant="outline" className="text-xs font-mono text-muted-foreground border-border/50">
                                    {ctrl}
                                  </Badge>
                                ))}
                              </div>
                            </TableCell>
                            <TableCell className="text-center">
                              {getPriorityBadge(fam.highestPriority)}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            )}

            {/* MITRE ATT&CK Techniques by Tactic */}
            {Object.keys(enrichment.mitreTechniquesByTactic).length > 0 && (
              <Accordion type="single" collapsible>
                <AccordionItem value="mitre-tactics" className="border-border/50">
                  <AccordionTrigger className="text-sm hover:no-underline">
                    <div className="flex items-center gap-2">
                      <Target className="h-4 w-4 text-rose-400" />
                      MITRE ATT&CK Techniques by Tactic ({enrichment.totalMitreTechniques} techniques)
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <div className="space-y-3">
                      {TACTIC_ORDER
                        .filter(tactic => enrichment.mitreTechniquesByTactic[tactic])
                        .map(tactic => (
                          <div key={tactic} className="space-y-1.5">
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" className={`text-xs ${getTacticColor(tactic)}`}>
                                {tactic}
                              </Badge>
                              <span className="text-xs text-muted-foreground">
                                ({enrichment.mitreTechniquesByTactic[tactic].length} technique{enrichment.mitreTechniquesByTactic[tactic].length !== 1 ? "s" : ""})
                              </span>
                            </div>
                            <div className="flex flex-wrap gap-1.5 pl-2">
                              {enrichment.mitreTechniquesByTactic[tactic].map(tech => (
                                <Tooltip key={tech.techniqueId}>
                                  <TooltipTrigger>
                                    <Badge variant="outline" className="text-xs font-mono text-muted-foreground border-border/50 cursor-help hover:text-foreground transition-colors">
                                      {tech.techniqueId}
                                    </Badge>
                                  </TooltipTrigger>
                                  <TooltipContent side="top">
                                    <p className="font-medium">{tech.techniqueName}</p>
                                    <p className="text-xs text-muted-foreground">{tech.techniqueId}</p>
                                  </TooltipContent>
                                </Tooltip>
                              ))}
                            </div>
                          </div>
                        ))}
                      {/* Any tactics not in the standard order */}
                      {Object.keys(enrichment.mitreTechniquesByTactic)
                        .filter(t => !TACTIC_ORDER.includes(t))
                        .map(tactic => (
                          <div key={tactic} className="space-y-1.5">
                            <Badge variant="outline" className="text-xs text-gray-400 border-gray-500/30">
                              {tactic}
                            </Badge>
                            <div className="flex flex-wrap gap-1.5 pl-2">
                              {enrichment.mitreTechniquesByTactic[tactic].map(tech => (
                                <Tooltip key={tech.techniqueId}>
                                  <TooltipTrigger>
                                    <Badge variant="outline" className="text-xs font-mono text-muted-foreground border-border/50 cursor-help">
                                      {tech.techniqueId}
                                    </Badge>
                                  </TooltipTrigger>
                                  <TooltipContent side="top">
                                    <p className="font-medium">{tech.techniqueName}</p>
                                  </TooltipContent>
                                </Tooltip>
                              ))}
                            </div>
                          </div>
                        ))}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            )}

            {/* CWE Classifications */}
            {Object.keys(enrichment.cwesByCategory).length > 0 && (
              <Accordion type="single" collapsible>
                <AccordionItem value="cwe-categories" className="border-border/50">
                  <AccordionTrigger className="text-sm hover:no-underline">
                    <div className="flex items-center gap-2">
                      <Bug className="h-4 w-4 text-amber-400" />
                      CWE Classifications ({enrichment.totalCwes} weaknesses)
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <div className="space-y-3">
                      {Object.entries(enrichment.cwesByCategory)
                        .sort(([, a], [, b]) => b.length - a.length)
                        .map(([category, cwes]) => (
                          <div key={category} className="space-y-1.5">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-medium text-amber-400">{category}</span>
                              <span className="text-xs text-muted-foreground">({cwes.length})</span>
                            </div>
                            <div className="space-y-1 pl-2">
                              {cwes.map(cwe => (
                                <div key={cwe.cweId} className="flex items-start gap-2 text-xs">
                                  <Badge variant="outline" className="text-xs font-mono text-amber-400 border-amber-500/30 shrink-0">
                                    {cwe.cweId}
                                  </Badge>
                                  <span className="text-muted-foreground">{cwe.cweName}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        ))}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            )}
          </CardContent>
        </Card>
      )}

      {/* ── Coverage Score ── */}
      {coverageReport && (
        <Card className="border-border/50">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-purple-400" />
              <CardTitle className="text-lg">Scan Coverage Analysis</CardTitle>
            </div>
            <CardDescription>
              Scan completeness against expected coverage matrix per asset environment
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Overall Score */}
            <div className="flex items-center gap-4">
              <div className={`text-4xl font-bold ${getScoreColor(coverageReport.overallScore)}`}>
                {coverageReport.overallScore}%
              </div>
              <div className="flex-1">
                <div className="h-3 rounded-full bg-muted overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${getScoreProgressColor(coverageReport.overallScore)}`}
                    style={{ width: `${coverageReport.overallScore}%` }}
                  />
                </div>
                <div className="flex justify-between mt-1">
                  <span className="text-xs text-muted-foreground">
                    {coverageReport.totalGaps} gaps found
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {coverageReport.criticalGaps} critical
                  </span>
                </div>
              </div>
            </div>

            {/* Per-Asset Coverage */}
            {coverageReport.assetReports.length > 0 && (
              <Accordion type="multiple" defaultValue={
                coverageReport.assetReports
                  .filter(r => r.criticalGaps > 0)
                  .map(r => r.hostname)
              }>
                {coverageReport.assetReports.map((ar) => (
                  <AccordionItem key={ar.hostname} value={ar.hostname} className="border-border/50">
                    <AccordionTrigger className="text-sm hover:no-underline">
                      <div className="flex items-center gap-3 w-full pr-4">
                        <span className="font-mono text-xs">{ar.hostname}</span>
                        <div className="flex-1" />
                        <span className={`text-sm font-bold ${getScoreColor(ar.score)}`}>
                          {ar.score}%
                        </span>
                        {ar.criticalGaps > 0 && (
                          <Badge variant="outline" className="text-red-400 border-red-500/30">
                            {ar.criticalGaps} critical
                          </Badge>
                        )}
                        {ar.totalGaps > 0 && (
                          <Badge variant="outline" className="text-yellow-400 border-yellow-500/30">
                            {ar.totalGaps} gaps
                          </Badge>
                        )}
                        {ar.totalGaps === 0 && (
                          <Badge variant="outline" className="text-green-400 border-green-500/30">
                            <CheckCircle2 className="h-3 w-3 mr-1" /> Complete
                          </Badge>
                        )}
                      </div>
                    </AccordionTrigger>
                    <AccordionContent>
                      {ar.gaps.length === 0 ? (
                        <div className="flex items-center gap-2 text-sm text-green-400 py-2">
                          <CheckCircle2 className="h-4 w-4" />
                          All expected checks were executed for this asset.
                        </div>
                      ) : (
                        <div className="space-y-3">
                          {ar.gaps.map((gap, gi) => (
                            <div key={gi} className="rounded-lg border border-border/30 p-3 space-y-2">
                              <div className="flex items-center gap-2">
                                {getSeverityBadge(gap.severity)}
                                <span className="text-sm font-medium">{gap.category}</span>
                              </div>
                              <p className="text-xs text-muted-foreground">{gap.description}</p>
                              {gap.missingChecks.length > 0 && (
                                <div className="flex flex-wrap gap-1">
                                  {gap.missingChecks.map((check, ci) => (
                                    <Badge key={ci} variant="outline" className="text-xs text-muted-foreground border-border/50">
                                      {check}
                                    </Badge>
                                  ))}
                                </div>
                              )}
                              {/* NIST/MITRE Cross-References */}
                              {(gap.relatedNistControls?.length || gap.relatedMitreTechniques?.length) ? (
                                <div className="flex flex-wrap gap-1 pt-1 border-t border-border/20">
                                  {gap.relatedNistControls?.map(ctrl => (
                                    <Badge key={ctrl} variant="outline" className="text-xs font-mono text-emerald-400 border-emerald-500/20">
                                      {ctrl}
                                    </Badge>
                                  ))}
                                  {gap.relatedMitreTechniques?.map(tech => (
                                    <Badge key={tech} variant="outline" className="text-xs font-mono text-rose-400 border-rose-500/20">
                                      {tech}
                                    </Badge>
                                  ))}
                                </div>
                              ) : null}
                              <div className="flex items-start gap-1.5 text-xs text-blue-400">
                                <Info className="h-3 w-3 mt-0.5 shrink-0" />
                                {gap.recommendation}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
            )}

            {/* Top Recommendations */}
            {coverageReport.recommendations.length > 0 && (
              <Accordion type="single" collapsible>
                <AccordionItem value="recommendations" className="border-border/50">
                  <AccordionTrigger className="text-sm hover:no-underline">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-yellow-400" />
                      Top Recommendations ({coverageReport.recommendations.length})
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <ul className="space-y-2">
                      {coverageReport.recommendations.map((rec, i) => (
                        <li key={i} className="flex items-start gap-2 text-xs text-muted-foreground">
                          <span className="text-yellow-400 font-bold shrink-0">{i + 1}.</span>
                          {rec}
                        </li>
                      ))}
                    </ul>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            )}

            <p className="text-xs text-muted-foreground">
              Analyzed at {formatTimestamp(coverageReport.processedAt)}
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
