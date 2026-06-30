import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Flame, TrendingDown, Zap, Brain, BarChart3, AlertTriangle, RefreshCw } from "lucide-react";

/**
 * LLM Hot Path Analyzer Dashboard
 * 
 * Visualizes which LLM call sites consume the most resources and provides
 * graduation recommendations for converting high-volume deterministic calls
 * to static code.
 */
export default function LLMHotPaths() {
  const [refreshKey, setRefreshKey] = useState(0);
  
  // Fetch LLM cache stats and hot path data
  const { data: cacheStats, isLoading } = trpc.system.getLLMCacheStats.useQuery(
    undefined,
    { refetchInterval: 30000, queryKey: ['llm-cache-stats', refreshKey] as any }
  );

  const handleRefresh = () => setRefreshKey(k => k + 1);

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Flame className="h-6 w-6 text-orange-500" />
            LLM Hot Path Analyzer
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Identify high-volume call sites, graduation candidates, and optimization opportunities
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={handleRefresh}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-xs text-muted-foreground">Cache Entries</p>
                <p className="text-2xl font-bold">{cacheStats?.cache?.entries ?? 0}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <Zap className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-xs text-muted-foreground">Cache Hit Rate</p>
                <p className="text-2xl font-bold">
                  {cacheStats?.cache?.hitRate != null ? `${(cacheStats.cache.hitRate * 100).toFixed(1)}%` : '—'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <TrendingDown className="h-5 w-5 text-purple-500" />
              <div>
                <p className="text-xs text-muted-foreground">Tokens Saved</p>
                <p className="text-2xl font-bold">
                  {cacheStats?.cache?.tokensSaved != null ? cacheStats.cache.tokensSaved.toLocaleString() : '—'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <Brain className="h-5 w-5 text-orange-500" />
              <div>
                <p className="text-xs text-muted-foreground">Graduation Candidates</p>
                <p className="text-2xl font-bold">{cacheStats?.graduationCandidates?.length ?? 0}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Top Call Sites */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Flame className="h-5 w-5 text-orange-500" />
            Top Call Sites by Volume
          </CardTitle>
          <CardDescription>
            Call sites ranked by total invocations. High-volume sites with stable outputs are graduation candidates.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-3">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="h-12 bg-muted/50 rounded animate-pulse" />
              ))}
            </div>
          ) : cacheStats?.callSites && cacheStats.callSites.length > 0 ? (
            <div className="space-y-2">
              {cacheStats.callSites.map((site: any, idx: number) => (
                <div
                  key={site.caller || idx}
                  className="flex items-center justify-between p-3 rounded-lg border bg-card hover:bg-accent/50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono text-muted-foreground w-6">#{idx + 1}</span>
                    <div>
                      <p className="text-sm font-medium font-mono">{site.caller}</p>
                      <p className="text-xs text-muted-foreground">
                        {site.totalCalls} calls | {site.totalTokensIn?.toLocaleString()} tokens in | {site.totalTokensOut?.toLocaleString()} tokens out
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {site.errorRate > 0.1 && (
                      <Badge variant="destructive" className="text-xs">
                        <AlertTriangle className="h-3 w-3 mr-1" />
                        {(site.errorRate * 100).toFixed(0)}% errors
                      </Badge>
                    )}
                    <Badge
                      variant="outline"
                      className={`text-xs ${
                        site.totalCalls > 100 ? 'border-orange-500 text-orange-500' :
                        site.totalCalls > 50 ? 'border-yellow-500 text-yellow-500' :
                        'border-muted-foreground'
                      }`}
                    >
                      {site.totalCalls} calls
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Flame className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No call site data available yet. Data populates as LLM calls are made during engagements.</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Graduation Candidates */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="h-5 w-5 text-purple-500" />
            Graduation Candidates
          </CardTitle>
          <CardDescription>
            High-frequency prompts with stable outputs that could be replaced with deterministic code.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {cacheStats?.graduationCandidates && cacheStats.graduationCandidates.length > 0 ? (
            <div className="space-y-3">
              {cacheStats.graduationCandidates.map((candidate: any, idx: number) => (
                <div key={idx} className="p-4 rounded-lg border bg-purple-500/5 border-purple-500/20">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-sm font-medium">{candidate.caller || candidate.hash?.slice(0, 16)}</span>
                    <Badge className="bg-purple-500/20 text-purple-400 border-purple-500/30">
                      {candidate.hitCount || candidate.frequency} hits
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Tokens saved per graduation: ~{candidate.tokensSaved || candidate.avgTokens || 0} per call.
                    {candidate.stability && ` Stability: ${(candidate.stability * 100).toFixed(0)}%`}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Brain className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No graduation candidates identified yet. Candidates emerge after repeated similar prompts are cached.</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Anomalies */}
      {cacheStats?.anomalies && cacheStats.anomalies.length > 0 && (
        <Card className="border-yellow-500/30">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-yellow-500">
              <AlertTriangle className="h-5 w-5" />
              Detected Anomalies
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {cacheStats.anomalies.map((anomaly: any, idx: number) => (
                <div key={idx} className="p-3 rounded border border-yellow-500/20 bg-yellow-500/5">
                  <p className="text-sm font-medium">{anomaly.caller}</p>
                  <p className="text-xs text-muted-foreground">{anomaly.reason || anomaly.description}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
