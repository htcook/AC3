import { useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Activity, CheckCircle2, AlertTriangle, Clock, XCircle,
  TrendingUp, Zap, Shield
} from "lucide-react";

type SourceStat = {
  sourceModule: string | null;
  count: number;
  lastCollected?: string | null;
};

type Props = {
  stats: {
    totalEvidence: number;
    autoCollected: number;
    manualCollected: number;
    sourceMappingCount: number;
    bySource: SourceStat[];
  } | undefined;
  mappings: Array<{
    sourceModule: string;
    ksiIds: string[];
    description: string;
    evidenceType: string;
  }> | undefined;
};

export default function CollectionHealthPanel({ stats, mappings }: Props) {
  const health = useMemo(() => {
    if (!stats || !mappings) return null;

    const totalSources = mappings.length;
    const activeSources = stats.bySource.filter(s => (s.count || 0) > 0).length;
    const dormantSources = totalSources - activeSources;

    // Calculate freshness — sources with evidence in last 24h, 7d, 30d
    const now = Date.now();
    const fresh24h = stats.bySource.filter(s => {
      if (!s.lastCollected) return false;
      return (now - new Date(s.lastCollected).getTime()) < 24 * 60 * 60 * 1000;
    }).length;
    const fresh7d = stats.bySource.filter(s => {
      if (!s.lastCollected) return false;
      return (now - new Date(s.lastCollected).getTime()) < 7 * 24 * 60 * 60 * 1000;
    }).length;

    // Coverage: how many unique KSIs have evidence
    const coveredKsis = new Set<string>();
    for (const m of mappings) {
      const sourceHasEvidence = stats.bySource.some(
        s => s.sourceModule === m.sourceModule && (s.count || 0) > 0
      );
      if (sourceHasEvidence) {
        m.ksiIds.forEach(id => coveredKsis.add(id));
      }
    }
    const allKsis = new Set(mappings.flatMap(m => m.ksiIds));

    // Auto vs manual ratio
    const autoRatio = stats.totalEvidence > 0
      ? Math.round((stats.autoCollected / stats.totalEvidence) * 100)
      : 0;

    // Overall health score (0-100)
    const sourceScore = totalSources > 0 ? (activeSources / totalSources) * 30 : 0;
    const freshnessScore = totalSources > 0 ? (fresh7d / totalSources) * 25 : 0;
    const coverageScore = allKsis.size > 0 ? (coveredKsis.size / allKsis.size) * 25 : 0;
    const autoScore = autoRatio >= 80 ? 20 : autoRatio >= 50 ? 15 : autoRatio >= 20 ? 10 : 5;
    const overallScore = Math.round(sourceScore + freshnessScore + coverageScore + autoScore);

    return {
      totalSources,
      activeSources,
      dormantSources,
      fresh24h,
      fresh7d,
      coveredKsis: coveredKsis.size,
      totalKsis: allKsis.size,
      autoRatio,
      overallScore,
    };
  }, [stats, mappings]);

  if (!health) return null;

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-emerald-400";
    if (score >= 60) return "text-amber-400";
    return "text-red-400";
  };

  const getScoreLabel = (score: number) => {
    if (score >= 90) return "Excellent";
    if (score >= 75) return "Good";
    if (score >= 60) return "Fair";
    if (score >= 40) return "Needs Attention";
    return "Critical";
  };

  const getScoreBg = (score: number) => {
    if (score >= 80) return "border-emerald-500/30 bg-emerald-500/5";
    if (score >= 60) return "border-amber-500/30 bg-amber-500/5";
    return "border-red-500/30 bg-red-500/5";
  };

  return (
    <Card className={`${getScoreBg(health.overallScore)}`}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" />
            <CardTitle className="text-base">Collection Health</CardTitle>
          </div>
          <div className="flex items-center gap-2">
            <span className={`font-display text-2xl font-bold ${getScoreColor(health.overallScore)}`}>
              {health.overallScore}
            </span>
            <Badge variant="outline" className={getScoreColor(health.overallScore)}>
              {getScoreLabel(health.overallScore)}
            </Badge>
          </div>
        </div>
        <CardDescription>Pipeline health across {health.totalSources} configured evidence sources</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {/* Source Activity */}
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Zap className="w-3.5 h-3.5" />
              Source Activity
            </div>
            <div className="flex items-baseline gap-1">
              <span className="text-2xl font-bold">{health.activeSources}</span>
              <span className="text-sm text-muted-foreground">/ {health.totalSources}</span>
            </div>
            <Progress value={(health.activeSources / Math.max(health.totalSources, 1)) * 100} className="h-1.5" />
            {health.dormantSources > 0 && (
              <div className="flex items-center gap-1 text-xs text-amber-500">
                <AlertTriangle className="w-3 h-3" />
                {health.dormantSources} dormant
              </div>
            )}
          </div>

          {/* Freshness */}
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Clock className="w-3.5 h-3.5" />
              Freshness
            </div>
            <div className="flex items-baseline gap-1">
              <span className="text-2xl font-bold">{health.fresh24h}</span>
              <span className="text-sm text-muted-foreground">last 24h</span>
            </div>
            <div className="text-xs text-muted-foreground">
              {health.fresh7d} in last 7 days
            </div>
          </div>

          {/* KSI Coverage */}
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Shield className="w-3.5 h-3.5" />
              KSI Coverage
            </div>
            <div className="flex items-baseline gap-1">
              <span className="text-2xl font-bold">{health.coveredKsis}</span>
              <span className="text-sm text-muted-foreground">/ {health.totalKsis}</span>
            </div>
            <Progress value={(health.coveredKsis / Math.max(health.totalKsis, 1)) * 100} className="h-1.5" />
          </div>

          {/* Automation Ratio */}
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <TrendingUp className="w-3.5 h-3.5" />
              Automation
            </div>
            <div className="flex items-baseline gap-1">
              <span className="text-2xl font-bold">{health.autoRatio}%</span>
              <span className="text-sm text-muted-foreground">auto</span>
            </div>
            <div className="h-1.5 bg-muted rounded-full overflow-hidden flex">
              <div className="h-full bg-emerald-500 rounded-l-full" style={{ width: `${health.autoRatio}%` }} />
              <div className="h-full bg-blue-500 rounded-r-full" style={{ width: `${100 - health.autoRatio}%` }} />
            </div>
            <div className="flex justify-between text-[10px] text-muted-foreground">
              <span>Auto: {stats?.autoCollected}</span>
              <span>Manual: {stats?.manualCollected}</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
