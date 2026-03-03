/**
 * LLM Telemetry Dashboard — Monitor LLM API usage, latency, errors, and token consumption.
 *
 * Surfaces success/failure rates, latency distribution, retry frequency,
 * top callers, model usage, and recent error events so operators can
 * spot API degradation patterns before they impact engagements.
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  BarChart3,
  Activity,
  Clock,
  Zap,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  TrendingUp,
  Brain,
  Timer,
  Hash,
  XCircle,
} from "lucide-react";
import AppShell from "@/components/AppShell";

// ─── Helpers ────────────────────────────────────────────────────────────────
function formatNumber(n: number | string | null | undefined): string {
  const num = Number(n ?? 0);
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(1)}M`;
  if (num >= 1_000) return `${(num / 1_000).toFixed(1)}K`;
  return num.toLocaleString();
}

function formatMs(ms: number | string | null | undefined): string {
  const num = Number(ms ?? 0);
  if (num >= 60_000) return `${(num / 60_000).toFixed(1)}m`;
  if (num >= 1_000) return `${(num / 1_000).toFixed(1)}s`;
  return `${num}ms`;
}

function successRate(success: number, total: number): string {
  if (total === 0) return "—";
  return `${((success / total) * 100).toFixed(1)}%`;
}

// ─── Stat Card ──────────────────────────────────────────────────────────────
function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  color,
}: {
  icon: any;
  label: string;
  value: string;
  sub?: string;
  color: string;
}) {
  return (
    <Card className="border-border/50">
      <CardContent className="p-4">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg ${color} flex items-center justify-center`}>
            <Icon className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <p className="text-2xl font-bold truncate">{value}</p>
            <p className="text-xs text-muted-foreground">{label}</p>
            {sub && <p className="text-[10px] text-muted-foreground/70 mt-0.5">{sub}</p>}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Simple Bar (CSS-only) ──────────────────────────────────────────────────
function MiniBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.min((value / max) * 100, 100) : 0;
  return (
    <div className="w-full h-2 rounded-full bg-muted overflow-hidden">
      <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

// ─── Time Series Chart (CSS grid bars) ──────────────────────────────────────
function TimeSeriesChart({
  data,
}: {
  data: Array<{
    hour_bucket: string;
    total_calls: number | string;
    success_count: number | string;
    failure_count: number | string;
    avg_latency_ms: number | string;
  }>;
}) {
  if (!data || data.length === 0) {
    return (
      <div className="h-48 flex items-center justify-center text-muted-foreground text-sm">
        No data yet — LLM calls will appear here once telemetry starts recording.
      </div>
    );
  }

  const maxCalls = Math.max(...data.map((d) => Number(d.total_calls)));

  return (
    <div className="space-y-2">
      <div className="flex items-end gap-1 h-40">
        {data.map((d, i) => {
          const total = Number(d.total_calls);
          const success = Number(d.success_count);
          const failure = Number(d.failure_count);
          const height = maxCalls > 0 ? (total / maxCalls) * 100 : 0;
          const successPct = total > 0 ? (success / total) * 100 : 100;

          return (
            <div
              key={i}
              className="flex-1 flex flex-col items-center justify-end group relative"
            >
              {/* Tooltip */}
              <div className="absolute bottom-full mb-2 hidden group-hover:block z-10">
                <div className="bg-popover text-popover-foreground text-xs rounded-md shadow-lg border p-2 whitespace-nowrap">
                  <p className="font-medium">{d.hour_bucket?.slice(11, 16) || "?"}</p>
                  <p className="text-green-400">{success} success</p>
                  {failure > 0 && <p className="text-red-400">{failure} failed</p>}
                  <p className="text-muted-foreground">Avg: {formatMs(d.avg_latency_ms)}</p>
                </div>
              </div>
              {/* Bar */}
              <div
                className="w-full rounded-t-sm overflow-hidden transition-all"
                style={{ height: `${Math.max(height, 2)}%` }}
              >
                <div
                  className="bg-emerald-500/80 w-full"
                  style={{ height: `${successPct}%` }}
                />
                <div
                  className="bg-red-500/80 w-full"
                  style={{ height: `${100 - successPct}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
      {/* X-axis labels (show every 4th) */}
      <div className="flex gap-1">
        {data.map((d, i) => (
          <div key={i} className="flex-1 text-center">
            {i % Math.max(1, Math.floor(data.length / 6)) === 0 ? (
              <span className="text-[9px] text-muted-foreground">
                {d.hour_bucket?.slice(11, 16)}
              </span>
            ) : null}
          </div>
        ))}
      </div>
      <div className="flex items-center gap-4 text-xs text-muted-foreground">
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-emerald-500" /> Success
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-red-500" /> Failed
        </span>
      </div>
    </div>
  );
}

// ─── Latency Distribution ───────────────────────────────────────────────────
function LatencyDistribution({
  data,
}: {
  data: Array<{ latency_bucket: string; count: number | string }>;
}) {
  if (!data || data.length === 0) {
    return (
      <div className="h-32 flex items-center justify-center text-muted-foreground text-sm">
        No latency data available.
      </div>
    );
  }

  const maxCount = Math.max(...data.map((d) => Number(d.count)));
  const BUCKET_COLORS: Record<string, string> = {
    "<1s": "bg-emerald-500",
    "1-3s": "bg-green-500",
    "3-5s": "bg-yellow-500",
    "5-10s": "bg-amber-500",
    "10-30s": "bg-orange-500",
    "30-60s": "bg-red-400",
    ">60s": "bg-red-600",
  };

  return (
    <div className="space-y-2">
      {data.map((d) => {
        const count = Number(d.count);
        const color = BUCKET_COLORS[d.latency_bucket] || "bg-primary";
        return (
          <div key={d.latency_bucket} className="flex items-center gap-3">
            <span className="text-xs text-muted-foreground w-14 text-right font-mono">
              {d.latency_bucket}
            </span>
            <div className="flex-1">
              <MiniBar value={count} max={maxCount} color={color} />
            </div>
            <span className="text-xs font-medium w-10 text-right">{count}</span>
          </div>
        );
      })}
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────
export default function LlmTelemetry() {
  const [windowHours, setWindowHours] = useState(24);

  const summaryQ = trpc.llmTelemetry.summary.useQuery({ windowHours });
  const timeSeriesQ = trpc.llmTelemetry.timeSeries.useQuery({ windowHours });
  const topCallersQ = trpc.llmTelemetry.topCallers.useQuery({ windowHours, limit: 15 });
  const recentErrorsQ = trpc.llmTelemetry.recentErrors.useQuery({ limit: 20 });
  const latencyDistQ = trpc.llmTelemetry.latencyDistribution.useQuery({ windowHours });
  const modelUsageQ = trpc.llmTelemetry.modelUsage.useQuery({ windowHours });

  const summary = summaryQ.data || {} as any;
  const totalCalls = Number(summary.total_calls ?? 0);
  const successCount = Number(summary.success_count ?? 0) + Number(summary.retried_success_count ?? 0);
  const errorCount = Number(summary.error_count ?? 0);
  const timeoutCount = Number(summary.timeout_count ?? 0);
  const avgLatency = Number(summary.avg_latency_ms ?? 0);
  const totalTokens = Number(summary.total_tokens ?? 0);
  const avgRetries = Number(summary.avg_retries ?? 0);

  const isLoading = summaryQ.isLoading;

  const refetchAll = () => {
    summaryQ.refetch();
    timeSeriesQ.refetch();
    topCallersQ.refetch();
    recentErrorsQ.refetch();
    latencyDistQ.refetch();
    modelUsageQ.refetch();
  };

  return (
    <AppShell activePath="/llm-telemetry">
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
              <Brain className="w-6 h-6 text-purple-500" />
              LLM Telemetry
            </h1>
            <p className="text-muted-foreground mt-1">
              Monitor LLM API usage, latency, errors, and token consumption across the platform.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Select
              value={String(windowHours)}
              onValueChange={(v) => setWindowHours(Number(v))}
            >
              <SelectTrigger className="w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1">Last 1 hour</SelectItem>
                <SelectItem value="6">Last 6 hours</SelectItem>
                <SelectItem value="24">Last 24 hours</SelectItem>
                <SelectItem value="72">Last 3 days</SelectItem>
                <SelectItem value="168">Last 7 days</SelectItem>
                <SelectItem value="720">Last 30 days</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" size="icon" onClick={refetchAll}>
              <RefreshCw className="w-4 h-4" />
            </Button>
          </div>
        </div>

        {/* Summary Stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-3">
          <StatCard
            icon={BarChart3}
            label="Total Calls"
            value={isLoading ? "..." : formatNumber(totalCalls)}
            color="bg-blue-500/10 text-blue-500"
          />
          <StatCard
            icon={CheckCircle2}
            label="Success Rate"
            value={isLoading ? "..." : successRate(successCount, totalCalls)}
            sub={`${successCount} of ${totalCalls}`}
            color="bg-emerald-500/10 text-emerald-500"
          />
          <StatCard
            icon={AlertTriangle}
            label="Errors"
            value={isLoading ? "..." : formatNumber(errorCount)}
            color="bg-red-500/10 text-red-500"
          />
          <StatCard
            icon={Timer}
            label="Timeouts"
            value={isLoading ? "..." : formatNumber(timeoutCount)}
            color="bg-orange-500/10 text-orange-500"
          />
          <StatCard
            icon={Clock}
            label="Avg Latency"
            value={isLoading ? "..." : formatMs(avgLatency)}
            sub={`Max: ${formatMs(summary.max_latency_ms)}`}
            color="bg-purple-500/10 text-purple-500"
          />
          <StatCard
            icon={Zap}
            label="Total Tokens"
            value={isLoading ? "..." : formatNumber(totalTokens)}
            sub={`In: ${formatNumber(summary.total_tokens_in)} / Out: ${formatNumber(summary.total_tokens_out)}`}
            color="bg-amber-500/10 text-amber-500"
          />
          <StatCard
            icon={RefreshCw}
            label="Avg Retries"
            value={isLoading ? "..." : avgRetries.toFixed(2)}
            color="bg-cyan-500/10 text-cyan-500"
          />
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Time Series */}
          <Card className="lg:col-span-2 border-border/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-emerald-500" />
                Usage Over Time
              </CardTitle>
            </CardHeader>
            <CardContent>
              <TimeSeriesChart data={timeSeriesQ.data || []} />
            </CardContent>
          </Card>

          {/* Latency Distribution */}
          <Card className="border-border/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Clock className="w-4 h-4 text-purple-500" />
                Latency Distribution
              </CardTitle>
            </CardHeader>
            <CardContent>
              <LatencyDistribution data={latencyDistQ.data || []} />
            </CardContent>
          </Card>
        </div>

        {/* Tables Row */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Top Callers */}
          <Card className="border-border/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Hash className="w-4 h-4 text-blue-500" />
                Top Callers
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="max-h-80 overflow-y-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="text-xs">Caller</TableHead>
                      <TableHead className="text-xs text-right">Calls</TableHead>
                      <TableHead className="text-xs text-right">Avg Latency</TableHead>
                      <TableHead className="text-xs text-right">Success</TableHead>
                      <TableHead className="text-xs text-right">Tokens</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(topCallersQ.data || []).length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={5} className="text-center text-muted-foreground text-sm py-8">
                          No caller data yet.
                        </TableCell>
                      </TableRow>
                    ) : (
                      (topCallersQ.data || []).map((c: any, i: number) => (
                        <TableRow key={i}>
                          <TableCell className="font-mono text-xs max-w-[200px] truncate">
                            {c.caller}
                          </TableCell>
                          <TableCell className="text-right text-xs">{formatNumber(c.call_count)}</TableCell>
                          <TableCell className="text-right text-xs">{formatMs(c.avg_latency_ms)}</TableCell>
                          <TableCell className="text-right text-xs">
                            <Badge
                              variant="outline"
                              className={
                                Number(c.success_rate) >= 95
                                  ? "text-emerald-500 border-emerald-500/30"
                                  : Number(c.success_rate) >= 80
                                  ? "text-yellow-500 border-yellow-500/30"
                                  : "text-red-500 border-red-500/30"
                              }
                            >
                              {Number(c.success_rate).toFixed(0)}%
                            </Badge>
                          </TableCell>
                          <TableCell className="text-right text-xs">{formatNumber(c.total_tokens)}</TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>

          {/* Model Usage */}
          <Card className="border-border/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Brain className="w-4 h-4 text-purple-500" />
                Model Usage
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="max-h-80 overflow-y-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="text-xs">Model</TableHead>
                      <TableHead className="text-xs text-right">Calls</TableHead>
                      <TableHead className="text-xs text-right">Avg Latency</TableHead>
                      <TableHead className="text-xs text-right">Success</TableHead>
                      <TableHead className="text-xs text-right">Tokens In</TableHead>
                      <TableHead className="text-xs text-right">Tokens Out</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(modelUsageQ.data || []).length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={6} className="text-center text-muted-foreground text-sm py-8">
                          No model data yet.
                        </TableCell>
                      </TableRow>
                    ) : (
                      (modelUsageQ.data || []).map((m: any, i: number) => (
                        <TableRow key={i}>
                          <TableCell className="font-mono text-xs">{m.model}</TableCell>
                          <TableCell className="text-right text-xs">{formatNumber(m.call_count)}</TableCell>
                          <TableCell className="text-right text-xs">{formatMs(m.avg_latency_ms)}</TableCell>
                          <TableCell className="text-right text-xs">
                            <Badge
                              variant="outline"
                              className={
                                Number(m.success_rate) >= 95
                                  ? "text-emerald-500 border-emerald-500/30"
                                  : "text-yellow-500 border-yellow-500/30"
                              }
                            >
                              {Number(m.success_rate).toFixed(0)}%
                            </Badge>
                          </TableCell>
                          <TableCell className="text-right text-xs">{formatNumber(m.total_tokens_in)}</TableCell>
                          <TableCell className="text-right text-xs">{formatNumber(m.total_tokens_out)}</TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Recent Errors */}
        <Card className="border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <XCircle className="w-4 h-4 text-red-500" />
              Recent Errors
              {recentErrorsQ.data && recentErrorsQ.data.length > 0 && (
                <Badge variant="destructive" className="ml-2 text-[10px]">
                  {recentErrorsQ.data.length}
                </Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="max-h-96 overflow-y-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs">Time</TableHead>
                    <TableHead className="text-xs">Caller</TableHead>
                    <TableHead className="text-xs">Status</TableHead>
                    <TableHead className="text-xs text-right">HTTP</TableHead>
                    <TableHead className="text-xs text-right">Latency</TableHead>
                    <TableHead className="text-xs text-right">Retries</TableHead>
                    <TableHead className="text-xs">Error</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(recentErrorsQ.data || []).length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center text-muted-foreground text-sm py-8">
                        <div className="flex flex-col items-center gap-2">
                          <CheckCircle2 className="w-8 h-8 text-emerald-500/50" />
                          <span>No recent errors — all LLM calls are healthy.</span>
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    (recentErrorsQ.data || []).map((e: any) => (
                      <TableRow key={e.id}>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          {e.called_at ? new Date(e.called_at).toLocaleString() : "—"}
                        </TableCell>
                        <TableCell className="font-mono text-xs max-w-[150px] truncate">
                          {e.caller}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={
                              e.llm_status === "timeout"
                                ? "text-orange-500 border-orange-500/30"
                                : "text-red-500 border-red-500/30"
                            }
                          >
                            {e.llm_status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right text-xs font-mono">
                          {e.http_status || "—"}
                        </TableCell>
                        <TableCell className="text-right text-xs">
                          {formatMs(e.latency_ms)}
                        </TableCell>
                        <TableCell className="text-right text-xs">
                          {e.retry_count}
                        </TableCell>
                        <TableCell className="text-xs max-w-[300px] truncate text-red-400/80">
                          {e.error_message || "—"}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
