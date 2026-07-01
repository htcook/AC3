import { trpc } from "@/lib/trpc";
import { Loader2, Link2, TrendingUp, Activity, Target } from "lucide-react";
import { Link } from "wouter";

export default function ChainTelemetryWidget() {
  const { data: telemetry, isLoading } = trpc.correlationThresholds.getChainTelemetry.useQuery(undefined, {
    refetchInterval: 300000,
    staleTime: 120000,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8 text-muted-foreground">
        <Loader2 className="w-4 h-4 mr-2 animate-pulse" />
        Loading chain telemetry...
      </div>
    );
  }

  if (!telemetry) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <Link2 className="w-8 h-8 mx-auto mb-2 opacity-50" />
        <p className="text-sm">No chain telemetry data yet.</p>
        <p className="text-xs mt-1">Run engagements with cross-correlation enabled to generate telemetry.</p>
      </div>
    );
  }

  const { totalChains, successRate, topPatterns, recentResults } = telemetry;

  if (totalChains === 0 && topPatterns.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <Link2 className="w-8 h-8 mx-auto mb-2 opacity-50" />
        <p className="text-sm">No chain telemetry data yet.</p>
        <p className="text-xs mt-1">Run engagements with cross-correlation enabled to generate telemetry.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Stats row */}
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-card/50 border border-border/50 rounded-md p-3 text-center">
          <div className="text-lg font-bold text-primary">{totalChains}</div>
          <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Chains</div>
        </div>
        <div className="bg-card/50 border border-border/50 rounded-md p-3 text-center">
          <div className="text-lg font-bold text-green-400">{successRate}%</div>
          <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Correlation Rate</div>
        </div>
        <div className="bg-card/50 border border-border/50 rounded-md p-3 text-center">
          <div className="text-lg font-bold text-amber-400">{topPatterns.length}</div>
          <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Patterns</div>
        </div>
      </div>

      {/* Top patterns */}
      {topPatterns.length > 0 && (
        <div className="space-y-1.5">
          <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-1">
            <TrendingUp className="w-3 h-3" /> Top Attack Patterns
          </h4>
          {topPatterns.slice(0, 5).map((pattern, idx) => (
            <div key={idx} className="flex items-center justify-between p-2 rounded bg-card/30 border border-border/30">
              <div className="flex items-center gap-2">
                <Target className="w-3 h-3 text-primary/60" />
                <span className="text-xs">{pattern.name}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-muted-foreground">{pattern.count}x</span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                  pattern.severity === 'critical' ? 'bg-red-500/20 text-red-300' :
                  pattern.severity === 'high' ? 'bg-orange-500/20 text-orange-300' :
                  pattern.severity === 'moderate' ? 'bg-yellow-500/20 text-yellow-300' :
                  'bg-zinc-500/20 text-zinc-300'
                }`}>{pattern.severity}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Recent results */}
      {recentResults.length > 0 && (
        <div className="space-y-1.5">
          <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-1">
            <Activity className="w-3 h-3" /> Recent Correlations
          </h4>
          {recentResults.slice(0, 4).map((result, idx) => (
            <Link key={idx} href="/attack-chains">
              <div className="flex items-center justify-between p-2 rounded bg-card/30 border border-border/30 hover:border-primary/30 transition-colors cursor-pointer">
                <span className="text-xs truncate max-w-[200px]">{result.chainName}</span>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-muted-foreground">{result.steps} steps</span>
                  <span className={`text-[10px] font-mono ${
                    (result.score || 0) >= 8 ? 'text-red-400' :
                    (result.score || 0) >= 6 ? 'text-orange-400' :
                    'text-yellow-400'
                  }`}>{result.score?.toFixed(1)}</span>
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
