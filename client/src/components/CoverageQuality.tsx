/**
 * Coverage & Quality Panel — Displays deduplication stats and coverage gap analysis
 * for an engagement's vulnerability detection phase.
 *
 * Shows:
 *   1. Dedup summary — how many duplicates were removed, merge log, severity changes
 *   2. Coverage score — overall and per-asset scan completeness
 *   3. Coverage gaps — missing checks with severity, recommendations
 *
 * @author Harrison Cook — AceofCloud
 */

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
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
import { AlertTriangle, CheckCircle2, Scissors, ShieldAlert, BarChart3, Info } from "lucide-react";

// ─── Types ───────────────────────────────────────────────────────────────

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

function formatTimestamp(ts: number): string {
  return new Date(ts).toLocaleString();
}

// ─── Component ───────────────────────────────────────────────────────────

export function CoverageQuality({ dedupStats, coverageReport, engagementPhase }: CoverageQualityProps) {
  // Show placeholder if data isn't available yet
  const hasData = dedupStats || coverageReport;
  const isPreVulnPhase = !engagementPhase || ["idle", "recon", "passive_discovery", "scoping_roe", "test_plan", "enumeration"].includes(engagementPhase);

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
