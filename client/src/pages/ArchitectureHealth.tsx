import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { HeartPulse, AlertTriangle, Shield, Code2, Eye, Layers, RefreshCw, CheckCircle } from "lucide-react";

/**
 * Architecture Health Dashboard
 * 
 * Visualizes architectural debt, error patterns, module coupling,
 * and feature flag hygiene from the ArchitecturalDebtRegistry.
 */
export default function ArchitectureHealth() {
  const [refreshKey, setRefreshKey] = useState(0);

  const { data: report, isLoading } = trpc.system.getArchitectureHealth.useQuery(
    undefined,
    { refetchInterval: 120000, queryKey: ['arch-health', refreshKey] as any }
  );

  const handleRefresh = () => setRefreshKey(k => k + 1);

  const getHealthColor = (score: number) => {
    if (score >= 80) return 'text-green-500';
    if (score >= 60) return 'text-yellow-500';
    if (score >= 40) return 'text-orange-500';
    return 'text-red-500';
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'dead_code': return <Code2 className="h-4 w-4" />;
      case 'swallowed_error': case 'inconsistent_error': return <AlertTriangle className="h-4 w-4" />;
      case 'god_module': case 'circular_dep': return <Layers className="h-4 w-4" />;
      case 'stale_feature_flag': case 'config_hygiene': return <Eye className="h-4 w-4" />;
      case 'missing_test': return <Shield className="h-4 w-4" />;
      default: return <AlertTriangle className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <HeartPulse className="h-6 w-6 text-pink-500" />
            Architecture Health
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Architectural debt tracking, error pattern analysis, and module coupling health
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={handleRefresh}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Health Score */}
      <Card className="border-2" style={{ borderColor: report?.healthScore != null ? (report.healthScore >= 80 ? '#22c55e' : report.healthScore >= 60 ? '#eab308' : '#ef4444') : undefined }}>
        <CardContent className="pt-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className={`text-5xl font-bold ${report?.healthScore != null ? getHealthColor(report.healthScore) : 'text-muted-foreground'}`}>
                {report?.healthScore ?? '—'}
              </div>
              <div>
                <p className="text-lg font-medium">Health Score</p>
                <p className="text-sm text-muted-foreground">
                  {report?.totalItems ?? 0} debt items | Maintenance burden: {report?.totalMaintenanceBurden?.toFixed(1) ?? '0'}
                </p>
              </div>
            </div>
            {report?.healthScore != null && report.healthScore >= 80 && (
              <CheckCircle className="h-8 w-8 text-green-500" />
            )}
          </div>
        </CardContent>
      </Card>

      {/* Severity & Category Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">By Severity</CardTitle>
          </CardHeader>
          <CardContent>
            {report?.bySeverity ? (
              <div className="space-y-2">
                {Object.entries(report.bySeverity).map(([severity, count]) => (
                  <div key={severity} className="flex items-center justify-between">
                    <Badge className={getSeverityColor(severity)}>{severity}</Badge>
                    <span className="text-sm font-mono">{count as number}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No data available</p>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">By Category</CardTitle>
          </CardHeader>
          <CardContent>
            {report?.byCategory ? (
              <div className="space-y-2">
                {Object.entries(report.byCategory).map(([category, count]) => (
                  <div key={category} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {getCategoryIcon(category)}
                      <span className="text-xs font-mono">{category.replace(/_/g, ' ')}</span>
                    </div>
                    <span className="text-sm font-mono">{count as number}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No data available</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Top Priority Debt Items */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-yellow-500" />
            Top Priority Debt Items
          </CardTitle>
          <CardDescription>
            Ranked by combined maintenance burden and risk score
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-3">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="h-16 bg-muted/50 rounded animate-pulse" />
              ))}
            </div>
          ) : report?.topPriority && report.topPriority.length > 0 ? (
            <div className="space-y-3">
              {report.topPriority.map((item: any, idx: number) => (
                <div
                  key={item.id || idx}
                  className="p-4 rounded-lg border bg-card hover:bg-accent/30 transition-colors"
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      {getCategoryIcon(item.category)}
                      <span className="text-sm font-medium">{item.title}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge className={getSeverityColor(item.severity)}>
                        {item.severity}
                      </Badge>
                      <Badge variant="outline" className="text-xs">
                        Score: {item.priorityScore?.toFixed(2)}
                      </Badge>
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground mb-1">{item.description}</p>
                  <p className="text-xs text-teal-500 font-medium">→ {item.recommendation}</p>
                  <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                    <span>File: <code className="text-xs">{item.location?.file}</code></span>
                    {item.location?.line && <span>Line: {item.location.line}</span>}
                    <span>Burden: {(item.maintenanceBurden * 100).toFixed(0)}%</span>
                    <span>Risk: {(item.riskScore * 100).toFixed(0)}%</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <HeartPulse className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No architectural debt items detected. The codebase is healthy!</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
