/**
 * AdjustmentEffectivenessWidget
 *
 * Dashboard widget showing which exploit adjustments work best against
 * specific defense configurations. Displays Bayesian-smoothed success rates,
 * priority modifiers, and trends from the feedback loop.
 */

import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import {
  TrendingUp, TrendingDown, Minus, BarChart3, Shield, Wrench,
  ChevronDown, Activity, Zap, AlertTriangle, CheckCircle2, XCircle,
} from "lucide-react";

// ─── Helpers ──────────────────────────────────────────────────────────────

function trendIcon(trend: string) {
  switch (trend) {
    case "improving": return <TrendingUp className="h-3 w-3 text-green-400" />;
    case "degrading": return <TrendingDown className="h-3 w-3 text-red-400" />;
    case "stable": return <Minus className="h-3 w-3 text-blue-400" />;
    default: return <Activity className="h-3 w-3 text-muted-foreground" />;
  }
}

function rateColor(rate: number): string {
  if (rate >= 0.7) return "text-green-400";
  if (rate >= 0.5) return "text-blue-400";
  if (rate >= 0.3) return "text-yellow-400";
  return "text-red-400";
}

function rateBg(rate: number): string {
  if (rate >= 0.7) return "bg-green-500";
  if (rate >= 0.5) return "bg-blue-500";
  if (rate >= 0.3) return "bg-yellow-500";
  return "bg-red-500";
}

function modifierBadge(mod: number) {
  if (mod > 0) return <Badge variant="outline" className="text-[9px] text-green-400 border-green-500/30 bg-green-500/10">+{mod}</Badge>;
  if (mod < 0) return <Badge variant="outline" className="text-[9px] text-red-400 border-red-500/30 bg-red-500/10">{mod}</Badge>;
  return <Badge variant="outline" className="text-[9px] text-muted-foreground border-border/50">0</Badge>;
}

function categoryIcon(cat: string) {
  if (cat.includes("waf")) return <Shield className="h-3.5 w-3.5 text-orange-400" />;
  if (cat.includes("payload") || cat.includes("defense")) return <AlertTriangle className="h-3.5 w-3.5 text-red-400" />;
  if (cat.includes("timeout") || cat.includes("network")) return <Activity className="h-3.5 w-3.5 text-blue-400" />;
  if (cat.includes("auth")) return <Zap className="h-3.5 w-3.5 text-yellow-400" />;
  return <Wrench className="h-3.5 w-3.5 text-muted-foreground" />;
}

// ─── Ranking Row ──────────────────────────────────────────────────────────

function RankingRow({ ranking, index }: { ranking: any; index: number }) {
  return (
    <div className="flex items-center gap-2 py-1.5 px-2 rounded hover:bg-muted/20 transition-colors">
      <span className="text-[10px] text-muted-foreground font-mono w-4 text-right">{index + 1}</span>
      <Badge variant="outline" className="text-[9px] font-mono min-w-[100px] justify-center">
        {ranking.adjustmentType.replace(/_/g, " ")}
      </Badge>
      <div className="flex-1 flex items-center gap-2">
        <div className="flex-1 max-w-[120px]">
          <Progress value={ranking.bayesianRate * 100} className={`h-1.5 ${rateBg(ranking.bayesianRate)}`} />
        </div>
        <span className={`text-[11px] font-mono font-medium min-w-[36px] ${rateColor(ranking.bayesianRate)}`}>
          {Math.round(ranking.bayesianRate * 100)}%
        </span>
      </div>
      {modifierBadge(ranking.priorityModifier)}
      <span className="text-[10px] text-muted-foreground font-mono min-w-[28px] text-right">
        n={ranking.totalAttempts}
      </span>
      {trendIcon(ranking.trend)}
    </div>
  );
}

// ─── Category Section ─────────────────────────────────────────────────────

function CategorySection({ category, rankings }: { category: string; rankings: any[] }) {
  const [open, setOpen] = useState(false);
  const avgRate = rankings.length > 0
    ? rankings.reduce((sum: number, r: any) => sum + r.bayesianRate, 0) / rankings.length
    : 0;

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger className="w-full">
        <div className="flex items-center gap-2 py-1.5 px-2 rounded hover:bg-muted/20 transition-colors">
          {categoryIcon(category)}
          <span className="text-xs font-medium text-foreground">{category.replace(/_/g, " ")}</span>
          <span className={`text-[10px] font-mono ${rateColor(avgRate)}`}>{Math.round(avgRate * 100)}% avg</span>
          <Badge variant="outline" className="text-[9px] text-muted-foreground border-border/50 ml-auto">
            {rankings.length} adj{rankings.length !== 1 ? "s" : ""}
          </Badge>
          <ChevronDown className={`h-3 w-3 text-muted-foreground transition-transform ${open ? "rotate-180" : ""}`} />
        </div>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="ml-4 border-l border-border/30 pl-2 space-y-0.5">
          {rankings.map((r: any, i: number) => (
            <RankingRow key={r.adjustmentType} ranking={r} index={i} />
          ))}
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}

// ─── Main Widget ──────────────────────────────────────────────────────────

export default function AdjustmentEffectivenessWidget() {
  const { data: summary, isLoading, error } = trpc.adjustmentEffectiveness.getSummary.useQuery(
    undefined,
    { refetchInterval: 60_000 }
  );

  if (isLoading) {
    return (
      <Card className="bg-card/50 border-border/30">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-blue-400" />
            Adjustment Effectiveness
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-6 bg-muted/20 rounded animate-pulse" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error || !summary) {
    return (
      <Card className="bg-card/50 border-border/30">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-blue-400" />
            Adjustment Effectiveness
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground">No effectiveness data yet. Run exploit retries to start collecting.</p>
        </CardContent>
      </Card>
    );
  }

  const hasData = summary.totalRecords > 0;

  return (
    <Card className="bg-card/50 border-border/30">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          <BarChart3 className="h-4 w-4 text-blue-400" />
          Adjustment Effectiveness
        </CardTitle>
        <CardDescription className="text-[10px]">
          {hasData
            ? `${summary.totalRecords} outcomes across ${summary.uniqueCombinations} adjustment combinations`
            : "Collecting data from exploit retries..."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {!hasData ? (
          <div className="text-center py-4">
            <Wrench className="h-8 w-8 text-muted-foreground/30 mx-auto mb-2" />
            <p className="text-xs text-muted-foreground">
              No adjustment outcomes recorded yet. The system will start tracking effectiveness
              once exploit retries with adjustments are executed.
            </p>
          </div>
        ) : (
          <Tabs defaultValue="top" className="w-full">
            <TabsList className="h-7 mb-2">
              <TabsTrigger value="top" className="text-[10px] h-5 px-2">
                <CheckCircle2 className="h-3 w-3 mr-1" /> Top
              </TabsTrigger>
              <TabsTrigger value="worst" className="text-[10px] h-5 px-2">
                <XCircle className="h-3 w-3 mr-1" /> Worst
              </TabsTrigger>
              <TabsTrigger value="by-defense" className="text-[10px] h-5 px-2">
                <Shield className="h-3 w-3 mr-1" /> By Defense
              </TabsTrigger>
              <TabsTrigger value="by-service" className="text-[10px] h-5 px-2">
                <Activity className="h-3 w-3 mr-1" /> By Service
              </TabsTrigger>
            </TabsList>

            <TabsContent value="top" className="space-y-0.5 mt-0">
              {summary.topPerformers.slice(0, 8).map((r: any, i: number) => (
                <RankingRow key={`${r.adjustmentType}-${i}`} ranking={r} index={i} />
              ))}
            </TabsContent>

            <TabsContent value="worst" className="space-y-0.5 mt-0">
              {summary.worstPerformers.slice(0, 8).map((r: any, i: number) => (
                <RankingRow key={`${r.adjustmentType}-${i}`} ranking={r} index={i} />
              ))}
            </TabsContent>

            <TabsContent value="by-defense" className="space-y-1 mt-0">
              {Object.entries(summary.byFailureCategory).map(([cat, rankings]) => (
                <CategorySection key={cat} category={cat} rankings={rankings as any[]} />
              ))}
              {Object.keys(summary.byFailureCategory).length === 0 && (
                <p className="text-xs text-muted-foreground text-center py-2">No defense category data yet.</p>
              )}
            </TabsContent>

            <TabsContent value="by-service" className="space-y-1 mt-0">
              {Object.entries(summary.byService).map(([svc, rankings]) => (
                <CategorySection key={svc} category={svc} rankings={rankings as any[]} />
              ))}
              {Object.keys(summary.byService).length === 0 && (
                <p className="text-xs text-muted-foreground text-center py-2">No service data yet.</p>
              )}
            </TabsContent>
          </Tabs>
        )}

        {/* Recent Trends */}
        {summary.recentTrends.length > 0 && (
          <div className="mt-3 pt-2 border-t border-border/20">
            <span className="text-[10px] text-muted-foreground uppercase font-medium block mb-1">Recent Trends</span>
            <div className="space-y-0.5">
              {summary.recentTrends.slice(0, 5).map((t: any, i: number) => (
                <div key={i} className="flex items-center gap-2 text-[10px]">
                  {trendIcon(t.trend)}
                  <span className="font-mono text-foreground/80">{t.adjustmentType.replace(/_/g, " ")}</span>
                  <span className="text-muted-foreground">{t.failureCategory.replace(/_/g, " ")}</span>
                  <span className="text-muted-foreground/60">{t.service}</span>
                  <span className={`ml-auto font-mono ${rateColor(t.bayesianRate)}`}>{Math.round(t.bayesianRate * 100)}%</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
