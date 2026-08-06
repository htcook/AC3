/**
 * CalibrationDashboardWidget — Real-time drift status and top rejection patterns
 * Embeds into the Bug Bounty Hub page as a collapsible card widget.
 */
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  TrendingDown,
  TrendingUp,
  XCircle,
  BarChart3,
  RefreshCw,
} from "lucide-react";

export function CalibrationDashboardWidget() {
  const [expanded, setExpanded] = useState(true);

  const driftQuery = trpc.bountySubmissionPrep.getCalibrationStatus.useQuery(undefined, {
    refetchInterval: 30_000,
    retry: 1,
  });

  const drift = driftQuery.data?.drift;
  const negativeStats = driftQuery.data?.negativeStats;
  const topPatterns = driftQuery.data?.topPatterns;

  const driftSeverity = drift?.isDrifting
    ? drift.driftMagnitude > 0.3 ? "critical" : "warning"
    : "healthy";

  const driftColor = {
    critical: "text-red-500",
    warning: "text-amber-500",
    healthy: "text-emerald-500",
  }[driftSeverity];

  const driftBadge = {
    critical: <Badge variant="destructive" className="gap-1"><AlertTriangle className="h-3 w-3" /> Critical Drift</Badge>,
    warning: <Badge className="gap-1 bg-amber-500/15 text-amber-500 border-amber-500/30"><TrendingDown className="h-3 w-3" /> Drifting</Badge>,
    healthy: <Badge className="gap-1 bg-emerald-500/15 text-emerald-500 border-emerald-500/30"><CheckCircle2 className="h-3 w-3" /> Calibrated</Badge>,
  }[driftSeverity];

  return (
    <Card className="border-border/50">
      <CardHeader className="pb-2 cursor-pointer" onClick={() => setExpanded(!expanded)}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${driftSeverity === "critical" ? "bg-red-500/10" : driftSeverity === "warning" ? "bg-amber-500/10" : "bg-emerald-500/10"}`}>
              <Activity className={`h-4 w-4 ${driftColor}`} />
            </div>
            <div>
              <CardTitle className="text-sm font-semibold">Confidence Calibration</CardTitle>
              <CardDescription className="text-xs">LLM hypothesis accuracy drift monitor</CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {driftBadge}
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6"
              onClick={(e) => { e.stopPropagation(); driftQuery.refetch(); }}
            >
              <RefreshCw className={`h-3 w-3 ${driftQuery.isFetching ? "animate-spin" : ""}`} />
            </Button>
            {expanded ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
          </div>
        </div>
      </CardHeader>

      {expanded && (
        <CardContent className="pt-0 space-y-4">
          {driftQuery.isLoading ? (
            <div className="space-y-2">
              <div className="h-4 bg-muted rounded animate-pulse" />
              <div className="h-4 bg-muted rounded animate-pulse w-3/4" />
              <div className="h-4 bg-muted rounded animate-pulse w-1/2" />
            </div>
          ) : driftQuery.isError ? (
            <p className="text-xs text-muted-foreground">Calibration data unavailable</p>
          ) : (
            <>
              {/* Drift Metrics Row */}
              <div className="grid grid-cols-3 gap-3">
                <div className="space-y-1">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Drift Magnitude</p>
                  <p className={`text-lg font-bold ${driftColor}`}>
                    {drift ? `${(drift.driftMagnitude * 100).toFixed(1)}%` : "—"}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Total Records</p>
                  <p className="text-lg font-bold text-foreground">
                    {drift?.totalRecords ?? 0}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Accuracy</p>
                  <div className="flex items-center gap-1">
                    <p className="text-lg font-bold text-foreground">
                      {drift?.totalRecords ? `${((1 - (drift.driftMagnitude || 0)) * 100).toFixed(0)}%` : "—"}
                    </p>
                    {drift && !drift.isDrifting && <TrendingUp className="h-3 w-3 text-emerald-500" />}
                    {drift?.isDrifting && <TrendingDown className="h-3 w-3 text-red-500" />}
                  </div>
                </div>
              </div>

              {/* Drift Progress Bar */}
              {drift && (
                <div className="space-y-1">
                  <div className="flex justify-between text-[10px] text-muted-foreground">
                    <span>Drift Threshold</span>
                    <span>{(drift.driftMagnitude * 100).toFixed(1)}% / 20%</span>
                  </div>
                  <Progress
                    value={Math.min((drift.driftMagnitude / 0.2) * 100, 100)}
                    className={`h-1.5 ${driftSeverity === "critical" ? "[&>div]:bg-red-500" : driftSeverity === "warning" ? "[&>div]:bg-amber-500" : "[&>div]:bg-emerald-500"}`}
                  />
                </div>
              )}

              <Separator />

              {/* Negative Example Stats */}
              {negativeStats && (
                <div className="grid grid-cols-2 gap-3">
                  <div className="flex items-center gap-2">
                    <XCircle className="h-3.5 w-3.5 text-red-400" />
                    <div>
                      <p className="text-xs font-medium">{negativeStats.totalExamples ?? 0} Rejections</p>
                      <p className="text-[10px] text-muted-foreground">Total recorded</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <BarChart3 className="h-3.5 w-3.5 text-blue-400" />
                    <div>
                      <p className="text-xs font-medium">{negativeStats.uniquePatterns ?? 0} Patterns</p>
                      <p className="text-[10px] text-muted-foreground">Distinct failure modes</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Top Rejection Patterns */}
              {topPatterns && topPatterns.length > 0 && (
                <div className="space-y-2">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Top Rejection Patterns</p>
                  <div className="space-y-1.5">
                    {topPatterns.slice(0, 3).map((pattern: any, i: number) => (
                      <div key={i} className="flex items-center justify-between text-xs bg-muted/30 rounded-md px-2.5 py-1.5">
                        <span className="text-foreground truncate max-w-[70%]">{pattern.pattern || pattern.reason || `Pattern ${i + 1}`}</span>
                        <Badge variant="outline" className="text-[10px] h-5">{pattern.count || pattern.frequency || 0}x</Badge>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      )}
    </Card>
  );
}
