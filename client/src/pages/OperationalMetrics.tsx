import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Activity, DollarSign, Clock, Target, TrendingUp, AlertTriangle, RefreshCw, BarChart3, Zap } from "lucide-react";

/**
 * Operational Metrics Dashboard
 * 
 * Visualizes per-engagement cost attribution, finding lineage,
 * and detection rule effectiveness metrics.
 */
export default function OperationalMetrics() {
  const [refreshKey, setRefreshKey] = useState(0);

  const { data: metrics, isLoading } = trpc.system.getOperationalMetrics.useQuery(
    undefined,
    { refetchInterval: 60000, queryKey: ['operational-metrics', refreshKey] as any }
  );

  const handleRefresh = () => setRefreshKey(k => k + 1);

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Activity className="h-6 w-6 text-teal-500" />
            Operational Metrics
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Per-engagement cost attribution, finding lineage, and detection rule effectiveness
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
              <DollarSign className="h-5 w-5 text-green-500" />
              <div>
                <p className="text-xs text-muted-foreground">Avg Cost/Engagement</p>
                <p className="text-2xl font-bold">
                  ${metrics?.avgCostPerEngagement?.toFixed(2) ?? '—'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <Clock className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-xs text-muted-foreground">Avg Duration</p>
                <p className="text-2xl font-bold">
                  {metrics?.avgDurationMinutes ? `${metrics.avgDurationMinutes.toFixed(0)}m` : '—'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <Target className="h-5 w-5 text-red-500" />
              <div>
                <p className="text-xs text-muted-foreground">Total Findings</p>
                <p className="text-2xl font-bold">{metrics?.totalFindings ?? 0}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5 text-purple-500" />
              <div>
                <p className="text-xs text-muted-foreground">True Positive Rate</p>
                <p className="text-2xl font-bold">
                  {metrics?.truePositiveRate != null ? `${(metrics.truePositiveRate * 100).toFixed(1)}%` : '—'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Engagement Cost Breakdown */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <DollarSign className="h-5 w-5 text-green-500" />
            Recent Engagement Costs
          </CardTitle>
          <CardDescription>
            LLM token usage and cost attribution per engagement
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-3">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="h-12 bg-muted/50 rounded animate-pulse" />
              ))}
            </div>
          ) : metrics?.recentEngagements && metrics.recentEngagements.length > 0 ? (
            <div className="space-y-2">
              {metrics.recentEngagements.map((eng: any, idx: number) => (
                <div
                  key={eng.id || idx}
                  className="flex items-center justify-between p-3 rounded-lg border bg-card hover:bg-accent/50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono text-muted-foreground w-6">#{idx + 1}</span>
                    <div>
                      <p className="text-sm font-medium">{eng.name || eng.id}</p>
                      <p className="text-xs text-muted-foreground">
                        {eng.llmCalls} LLM calls | {eng.totalTokens?.toLocaleString()} tokens | {eng.findings} findings
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs">
                      ${eng.cost?.toFixed(2) ?? '0.00'}
                    </Badge>
                    <Badge
                      variant="outline"
                      className={`text-xs ${
                        eng.fpRate > 0.3 ? 'border-red-500 text-red-500' :
                        eng.fpRate > 0.15 ? 'border-yellow-500 text-yellow-500' :
                        'border-green-500 text-green-500'
                      }`}
                    >
                      FP: {((eng.fpRate || 0) * 100).toFixed(0)}%
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <BarChart3 className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No engagement metrics available yet. Data populates after engagements complete.</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Detection Rule Effectiveness */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-yellow-500" />
            Detection Rule Effectiveness
          </CardTitle>
          <CardDescription>
            Rules ranked by true positive rate with keep/tune/disable recommendations
          </CardDescription>
        </CardHeader>
        <CardContent>
          {metrics?.ruleEffectiveness && metrics.ruleEffectiveness.length > 0 ? (
            <div className="space-y-2">
              {metrics.ruleEffectiveness.map((rule: any, idx: number) => (
                <div
                  key={rule.ruleId || idx}
                  className="flex items-center justify-between p-3 rounded-lg border bg-card"
                >
                  <div>
                    <p className="text-sm font-medium font-mono">{rule.ruleId}</p>
                    <p className="text-xs text-muted-foreground">
                      TP: {rule.truePositives} | FP: {rule.falsePositives} | Alerts: {rule.totalAlerts}
                    </p>
                  </div>
                  <Badge
                    className={`text-xs ${
                      rule.recommendation === 'keep' ? 'bg-green-500/20 text-green-400 border-green-500/30' :
                      rule.recommendation === 'promote' ? 'bg-blue-500/20 text-blue-400 border-blue-500/30' :
                      rule.recommendation === 'tune' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                      'bg-red-500/20 text-red-400 border-red-500/30'
                    }`}
                  >
                    {rule.recommendation}
                  </Badge>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Zap className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No detection rule data available yet.</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Finding Lineage */}
      {metrics?.findingLineage && metrics.findingLineage.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Target className="h-5 w-5 text-red-500" />
              Finding Lineage (Recent)
            </CardTitle>
            <CardDescription>
              Trace each finding back to its source scanner, LLM call, and confidence evolution
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {metrics.findingLineage.map((finding: any, idx: number) => (
                <div key={idx} className="p-3 rounded-lg border bg-card">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium">{finding.title}</span>
                    <Badge variant="outline" className="text-xs">
                      {finding.source} → {finding.stage}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Confidence: {(finding.confidence * 100).toFixed(0)}% | 
                    Scanner: {finding.scanner} | 
                    Outcome: {finding.outcome || 'pending'}
                  </p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
