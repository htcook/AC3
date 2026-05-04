/**
 * SubmissionHistoryTab — Win-rate charts, platform breakdown, rejection trends
 * Uses the submissionHistory.analytics tRPC procedure.
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import {
  Trophy,
  XCircle,
  Clock,
  TrendingUp,
  BarChart3,
  Target,
  Shield,
  DollarSign,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  FileText,
} from "lucide-react";

type TimeRange = "7d" | "30d" | "90d" | "all";

export function SubmissionHistoryTab() {
  const [timeRange, setTimeRange] = useState<TimeRange>("30d");

  const analyticsQuery = trpc.submissionHistory.analytics.useQuery(
    { timeRange },
    { refetchInterval: 60_000, retry: 1 }
  );

  const listQuery = trpc.submissionHistory.list.useQuery(
    { limit: 20, offset: 0 },
    { retry: 1 }
  );

  const analytics = analyticsQuery.data;
  const submissions = listQuery.data;

  const winRate = analytics?.winRate ?? 0;
  const winRateColor = winRate >= 50 ? "text-emerald-500" : winRate >= 25 ? "text-amber-500" : "text-red-500";

  const statusIcon = (status: string) => {
    switch (status) {
      case "accepted": return <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />;
      case "rejected": return <XCircle className="h-3.5 w-3.5 text-red-500" />;
      case "duplicate": return <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />;
      case "pending": return <Clock className="h-3.5 w-3.5 text-blue-500" />;
      default: return <FileText className="h-3.5 w-3.5 text-muted-foreground" />;
    }
  };

  const severityColor = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case "critical": return "bg-red-500/15 text-red-500 border-red-500/30";
      case "high": return "bg-orange-500/15 text-orange-500 border-orange-500/30";
      case "medium": return "bg-amber-500/15 text-amber-500 border-amber-500/30";
      case "low": return "bg-blue-500/15 text-blue-500 border-blue-500/30";
      default: return "bg-muted text-muted-foreground";
    }
  };

  return (
    <div className="space-y-4">
      {/* Time Range Selector */}
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <BarChart3 className="h-4 w-4" /> Submission Analytics
        </h3>
        <div className="flex items-center gap-2">
          <Select value={timeRange} onValueChange={(v) => setTimeRange(v as TimeRange)}>
            <SelectTrigger className="w-[120px] h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7d">Last 7 days</SelectItem>
              <SelectItem value="30d">Last 30 days</SelectItem>
              <SelectItem value="90d">Last 90 days</SelectItem>
              <SelectItem value="all">All time</SelectItem>
            </SelectContent>
          </Select>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            onClick={() => { analyticsQuery.refetch(); listQuery.refetch(); }}
          >
            <RefreshCw className={`h-3.5 w-3.5 ${analyticsQuery.isFetching ? "animate-spin" : ""}`} />
          </Button>
        </div>
      </div>

      {analyticsQuery.isLoading ? (
        <div className="grid grid-cols-4 gap-3">
          {[...Array(4)].map((_, i) => (
            <Card key={i}><CardContent className="p-4"><div className="h-12 bg-muted rounded animate-pulse" /></CardContent></Card>
          ))}
        </div>
      ) : analyticsQuery.isError ? (
        <Card>
          <CardContent className="p-6 text-center text-sm text-muted-foreground">
            No submission history data available yet. Submit findings to bug bounty programs to start tracking.
          </CardContent>
        </Card>
      ) : (
        <>
          {/* KPI Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Card className="border-border/50">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Trophy className="h-4 w-4 text-amber-500" />
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Win Rate</p>
                </div>
                <p className={`text-2xl font-bold ${winRateColor}`}>{winRate.toFixed(1)}%</p>
                <p className="text-[10px] text-muted-foreground mt-1">
                  {analytics?.accepted ?? 0} accepted / {analytics?.totalSubmissions ?? 0} total
                </p>
              </CardContent>
            </Card>

            <Card className="border-border/50">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-2">
                  <DollarSign className="h-4 w-4 text-emerald-500" />
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Total Bounty</p>
                </div>
                <p className="text-2xl font-bold text-foreground">
                  ${(analytics?.totalBounty ?? 0).toLocaleString()}
                </p>
                <p className="text-[10px] text-muted-foreground mt-1">
                  Avg ${(analytics?.avgBounty ?? 0).toFixed(0)} per accepted
                </p>
              </CardContent>
            </Card>

            <Card className="border-border/50">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Target className="h-4 w-4 text-blue-500" />
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Submissions</p>
                </div>
                <p className="text-2xl font-bold text-foreground">{analytics?.totalSubmissions ?? 0}</p>
                <p className="text-[10px] text-muted-foreground mt-1">
                  {analytics?.pending ?? 0} pending review
                </p>
              </CardContent>
            </Card>

            <Card className="border-border/50">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="h-4 w-4 text-purple-500" />
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Unique Vulns</p>
                </div>
                <p className="text-2xl font-bold text-foreground">{analytics?.uniqueVulnClasses ?? 0}</p>
                <p className="text-[10px] text-muted-foreground mt-1">
                  {analytics?.uniquePlatforms ?? 0} platforms targeted
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Breakdown Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Platform Breakdown */}
            <Card className="border-border/50">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-semibold">By Platform</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {(analytics?.byPlatform ?? []).length === 0 ? (
                  <p className="text-xs text-muted-foreground">No platform data</p>
                ) : (
                  analytics?.byPlatform?.slice(0, 5).map((p: any, i: number) => (
                    <div key={i} className="space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="capitalize">{p.platform}</span>
                        <span className="text-muted-foreground">{p.count} ({p.winRate?.toFixed(0) ?? 0}%)</span>
                      </div>
                      <Progress value={p.winRate ?? 0} className="h-1" />
                    </div>
                  ))
                )}
              </CardContent>
            </Card>

            {/* Severity Breakdown */}
            <Card className="border-border/50">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-semibold">By Severity</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {(analytics?.bySeverity ?? []).length === 0 ? (
                  <p className="text-xs text-muted-foreground">No severity data</p>
                ) : (
                  analytics?.bySeverity?.map((s: any, i: number) => (
                    <div key={i} className="flex items-center justify-between text-xs">
                      <Badge className={`text-[10px] ${severityColor(s.severity)}`}>{s.severity}</Badge>
                      <span className="text-muted-foreground">{s.count} ({s.winRate?.toFixed(0) ?? 0}% win)</span>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>

            {/* Top Rejection Reasons */}
            <Card className="border-border/50">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-semibold">Top Rejections</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {(analytics?.topRejections ?? []).length === 0 ? (
                  <p className="text-xs text-muted-foreground">No rejection data</p>
                ) : (
                  analytics?.topRejections?.slice(0, 5).map((r: any, i: number) => (
                    <div key={i} className="flex items-center justify-between text-xs bg-muted/30 rounded-md px-2 py-1.5">
                      <span className="truncate max-w-[70%]">{r.reason}</span>
                      <Badge variant="outline" className="text-[10px] h-5">{r.count}x</Badge>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>
          </div>
        </>
      )}

      <Separator />

      {/* Recent Submissions Table */}
      <div className="space-y-2">
        <h3 className="text-sm font-semibold">Recent Submissions</h3>
        {listQuery.isLoading ? (
          <div className="space-y-2">
            {[...Array(5)].map((_, i) => <div key={i} className="h-10 bg-muted rounded animate-pulse" />)}
          </div>
        ) : !submissions?.items?.length ? (
          <Card>
            <CardContent className="p-6 text-center text-sm text-muted-foreground">
              No submissions recorded yet.
            </CardContent>
          </Card>
        ) : (
          <ScrollArea className="h-[300px]">
            <div className="space-y-1.5">
              {submissions.items.map((sub: any) => (
                <div
                  key={sub.id}
                  className="flex items-center justify-between bg-muted/20 border border-border/30 rounded-md px-3 py-2 hover:bg-muted/40 transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    {statusIcon(sub.status)}
                    <div className="min-w-0">
                      <p className="text-xs font-medium truncate max-w-[250px]">{sub.title || "Untitled"}</p>
                      <p className="text-[10px] text-muted-foreground">
                        {sub.platform} · {sub.vulnClass || "Unknown"} · {sub.engagementId ? `Eng #${sub.engagementId}` : "Manual"}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <Badge className={`text-[10px] ${severityColor(sub.severity)}`}>{sub.severity}</Badge>
                    {sub.bountyAmount > 0 && (
                      <Badge variant="outline" className="text-[10px] text-emerald-500 border-emerald-500/30">
                        ${sub.bountyAmount}
                      </Badge>
                    )}
                    <span className="text-[10px] text-muted-foreground">
                      {sub.submittedAt ? new Date(sub.submittedAt).toLocaleDateString() : "—"}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
        )}
      </div>
    </div>
  );
}
