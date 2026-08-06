import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Brain, Activity, Shield, AlertTriangle, CheckCircle2, XCircle,
  Zap, RotateCcw, Trash2, Settings, BarChart3, Clock, Gauge
} from "lucide-react";

function CircuitBreakerCard() {
  const { data, refetch } = trpc.llmReliability.getCircuitBreaker.useQuery();
  const resetMutation = trpc.llmReliability.resetCircuitBreaker.useMutation({
    onSuccess: () => refetch(),
  });

  const stateColor = data?.state === "closed" ? "text-green-400" : data?.state === "open" ? "text-red-400" : "text-yellow-400";
  const stateBg = data?.state === "closed" ? "bg-green-500/10 border-green-500/20" : data?.state === "open" ? "bg-red-500/10 border-red-500/20" : "bg-yellow-500/10 border-yellow-500/20";

  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><Shield className="h-4 w-4 text-blue-400" /> Circuit Breaker</CardTitle>
        <CardDescription>Protects the system from cascading LLM failures</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className={`rounded-md border p-4 text-center ${stateBg}`}>
          <p className={`text-3xl font-bold uppercase ${stateColor}`}>{data?.state ?? "unknown"}</p>
          <p className="text-xs text-muted-foreground mt-1">Circuit State</p>
        </div>
        {data?.stats && (
          <div className="grid grid-cols-3 gap-3">
            <div className="text-center">
              <p className="text-lg font-bold text-foreground">{data.stats.recentFailures ?? 0}</p>
              <p className="text-[10px] text-muted-foreground">Recent Failures</p>
            </div>
            <div className="text-center">
              <p className="text-lg font-bold text-foreground">{data.stats.totalTrips ?? 0}</p>
              <p className="text-[10px] text-muted-foreground">Total Trips</p>
            </div>
            <div className="text-center">
              <p className="text-lg font-bold text-foreground">{data.stats.totalCallsBlocked ?? 0}</p>
              <p className="text-[10px] text-muted-foreground">Calls Blocked</p>
            </div>
          </div>
        )}
        <Button variant="outline" size="sm" onClick={() => resetMutation.mutate()} disabled={resetMutation.isPending || data?.state === "closed"} className="w-full">
          <RotateCcw className="h-3.5 w-3.5 mr-2" /> Reset Circuit Breaker
        </Button>
      </CardContent>
    </Card>
  );
}

function CacheStatsCard() {
  const { data, refetch } = trpc.llmReliability.getCacheStats.useQuery();
  const clearMutation = trpc.llmReliability.clearCache.useMutation({
    onSuccess: () => refetch(),
  });

  const hitRate = data && (data.hits + data.misses) > 0
    ? ((data.hits / (data.hits + data.misses)) * 100).toFixed(1)
    : "0.0";

  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><Zap className="h-4 w-4 text-yellow-400" /> Prompt Cache</CardTitle>
        <CardDescription>Caches identical prompts to reduce latency and cost</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <div className="rounded-md bg-green-500/10 border border-green-500/20 p-3 text-center">
            <p className="text-2xl font-bold text-green-400">{data?.hits ?? 0}</p>
            <p className="text-xs text-muted-foreground">Cache Hits</p>
          </div>
          <div className="rounded-md bg-orange-500/10 border border-orange-500/20 p-3 text-center">
            <p className="text-2xl font-bold text-orange-400">{data?.misses ?? 0}</p>
            <p className="text-xs text-muted-foreground">Cache Misses</p>
          </div>
        </div>
        <div>
          <div className="flex justify-between text-xs mb-1">
            <span className="text-muted-foreground">Hit Rate</span>
            <span className="font-mono">{hitRate}%</span>
          </div>
          <Progress value={parseFloat(hitRate)} className="h-2" />
        </div>
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>Entries: {data?.size ?? 0} / {data?.maxSize ?? 0}</span>
          <span>Evictions: {data?.evictions ?? 0}</span>
        </div>
        <Button variant="outline" size="sm" onClick={() => clearMutation.mutate()} disabled={clearMutation.isPending} className="w-full">
          <Trash2 className="h-3.5 w-3.5 mr-2" /> Clear Cache
        </Button>
      </CardContent>
    </Card>
  );
}

function HealthMetricsCard() {
  const { data } = trpc.llmReliability.getHealthMetrics.useQuery();

  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><Activity className="h-4 w-4 text-primary" /> Health Metrics</CardTitle>
        <CardDescription>Real-time LLM performance and reliability metrics</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {data ? (
          <>
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-md bg-muted/30 p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Avg Latency</span>
                </div>
                <p className="text-xl font-bold">{data.recentPerformance?.avgLatencyMs?.toFixed(0) ?? 0}<span className="text-xs text-muted-foreground ml-1">ms</span></p>
              </div>
              <div className="rounded-md bg-muted/30 p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Gauge className="h-3.5 w-3.5 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">P95 Latency</span>
                </div>
                <p className="text-xl font-bold">{data.recentPerformance?.p95LatencyMs?.toFixed(0) ?? 0}<span className="text-xs text-muted-foreground ml-1">ms</span></p>
              </div>
              <div className="rounded-md bg-muted/30 p-3">
                <div className="flex items-center gap-2 mb-1">
                  <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />
                  <span className="text-xs text-muted-foreground">Success Rate</span>
                </div>
                <p className="text-xl font-bold">{((data.recentPerformance?.successRate ?? 0) * 100).toFixed(1)}<span className="text-xs text-muted-foreground ml-1">%</span></p>
              </div>
              <div className="rounded-md bg-muted/30 p-3">
                <div className="flex items-center gap-2 mb-1">
                  <BarChart3 className="h-3.5 w-3.5 text-blue-400" />
                  <span className="text-xs text-muted-foreground">Total Calls</span>
                </div>
                <p className="text-xl font-bold">{data.recentPerformance?.totalCalls ?? 0}</p>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3 text-center">
              <div>
                <p className="text-sm font-bold text-red-400">{((data.recentPerformance?.errorRate ?? 0) * 100).toFixed(1)}%</p>
                <p className="text-[10px] text-muted-foreground">Error Rate</p>
              </div>
              <div>
                <p className="text-sm font-bold text-yellow-400">{((data.recentPerformance?.timeoutRate ?? 0) * 100).toFixed(1)}%</p>
                <p className="text-[10px] text-muted-foreground">Timeout Rate</p>
              </div>
              <div>
                <p className="text-sm font-bold text-orange-400">{data.status ?? "unknown"}</p>
                <p className="text-[10px] text-muted-foreground">Status</p>
              </div>
            </div>
          </>
        ) : (
          <p className="text-sm text-muted-foreground">Loading health metrics...</p>
        )}
      </CardContent>
    </Card>
  );
}

function AvailabilityCard() {
  const { data } = trpc.llmReliability.isAvailable.useQuery(undefined, { refetchInterval: 10000 });

  return (
    <Card className={`border-2 ${data?.available ? "border-green-500/30 bg-green-500/5" : "border-red-500/30 bg-red-500/5"}`}>
      <CardContent className="pt-6 flex flex-col items-center gap-3">
        {data?.available ? (
          <CheckCircle2 className="h-12 w-12 text-green-400" />
        ) : (
          <XCircle className="h-12 w-12 text-red-400" />
        )}
        <div className="text-center">
          <p className="text-xl font-bold">{data?.available ? "LLM Available" : "LLM Unavailable"}</p>
          <p className="text-xs text-muted-foreground mt-1">
            Circuit: <span className="font-mono">{data?.circuitState ?? "unknown"}</span>
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

/* ─── Main Page ─── */
export default function LlmReliabilityDashboard() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">LLM Reliability Dashboard</h1>
        <p className="text-muted-foreground mt-1">
          Monitor LLM health, circuit breaker state, prompt cache performance, and configure reliability settings.
        </p>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <AvailabilityCard />
        <Card className="border-border/50 col-span-3">
          <CardContent className="pt-4">
            <div className="grid grid-cols-3 gap-4">
              <div className="flex items-center gap-3">
                <div className="rounded-full bg-blue-500/20 p-2"><Shield className="h-5 w-5 text-blue-400" /></div>
                <div>
                  <p className="text-sm font-medium">Circuit Breaker</p>
                  <p className="text-xs text-muted-foreground">Auto-trip on cascading failures</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="rounded-full bg-yellow-500/20 p-2"><Zap className="h-5 w-5 text-yellow-400" /></div>
                <div>
                  <p className="text-sm font-medium">Prompt Cache</p>
                  <p className="text-xs text-muted-foreground">Reduce latency for repeated prompts</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="rounded-full bg-green-500/20 p-2"><Activity className="h-5 w-5 text-green-400" /></div>
                <div>
                  <p className="text-sm font-medium">Health Monitor</p>
                  <p className="text-xs text-muted-foreground">Real-time latency and error tracking</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <HealthMetricsCard />
        <CircuitBreakerCard />
        <CacheStatsCard />
      </div>
    </div>
  );
}
