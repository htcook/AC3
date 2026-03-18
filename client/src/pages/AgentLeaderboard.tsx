import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Progress } from "@/components/ui/progress";
import {
  Trophy, Medal, TrendingUp, Zap, Clock, Brain, Shield, Target,
  ChevronDown, ChevronUp, ArrowUpDown, Activity, BarChart3, Cpu,
  Crosshair, Eye, Swords, Network, Lock, FileText, Bot,
} from "lucide-react";

// ─── Category → Icon mapping ────────────────────────────────────────────────
const CATEGORY_ICONS: Record<string, typeof Trophy> = {
  intelligence: Eye,
  exploitation: Crosshair,
  social_engineering: Swords,
  red_team: Target,
  reporting: FileText,
  reconnaissance: Network,
  evasion: Shield,
  post_exploitation: Lock,
  persistence: Lock,
};

const CATEGORY_COLORS: Record<string, string> = {
  intelligence: "text-blue-400",
  exploitation: "text-red-400",
  social_engineering: "text-amber-400",
  red_team: "text-orange-400",
  reporting: "text-emerald-400",
  reconnaissance: "text-cyan-400",
  evasion: "text-purple-400",
  post_exploitation: "text-pink-400",
  persistence: "text-indigo-400",
};

const RANK_STYLES = [
  { bg: "bg-amber-500/20", border: "border-amber-500/50", text: "text-amber-400", icon: Trophy },
  { bg: "bg-slate-300/20", border: "border-slate-300/50", text: "text-slate-300", icon: Medal },
  { bg: "bg-orange-600/20", border: "border-orange-600/50", text: "text-orange-500", icon: Medal },
];

type SortField = "composite" | "delegations" | "success_rate" | "confidence" | "latency" | "tokens";

export default function AgentLeaderboard() {
  const [windowDays, setWindowDays] = useState(30);
  const [sortBy, setSortBy] = useState<SortField>("composite");
  const [expandedAgent, setExpandedAgent] = useState<string | null>(null);

  const { data, isLoading } = trpc.agentLeaderboard.getLeaderboard.useQuery(
    { windowDays, sortBy },
    { refetchInterval: 30000 }
  );

  const { data: heatmapData } = trpc.agentLeaderboard.getDelegationHeatmap.useQuery(
    { windowDays },
    { refetchInterval: 60000 }
  );

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div className="h-8 w-64 bg-muted animate-pulse rounded" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-24 bg-muted animate-pulse rounded-lg" />
          ))}
        </div>
        <div className="space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-20 bg-muted animate-pulse rounded-lg" />
          ))}
        </div>
      </div>
    );
  }

  const leaderboard = data?.leaderboard ?? [];
  const summary = data?.summary;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Trophy className="h-6 w-6 text-amber-400" />
            Agent Performance Leaderboard
          </h1>
          <p className="text-muted-foreground mt-1">
            Ranking {summary?.totalAgents ?? 0} specialist agents by delegation frequency, success rate, and operational efficiency
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Select value={String(windowDays)} onValueChange={(v) => setWindowDays(Number(v))}>
            <SelectTrigger className="w-[140px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7">Last 7 days</SelectItem>
              <SelectItem value="14">Last 14 days</SelectItem>
              <SelectItem value="30">Last 30 days</SelectItem>
              <SelectItem value="90">Last 90 days</SelectItem>
            </SelectContent>
          </Select>
          <Select value={sortBy} onValueChange={(v) => setSortBy(v as SortField)}>
            <SelectTrigger className="w-[160px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="composite">Composite Score</SelectItem>
              <SelectItem value="delegations">Delegations</SelectItem>
              <SelectItem value="success_rate">Success Rate</SelectItem>
              <SelectItem value="confidence">Confidence</SelectItem>
              <SelectItem value="latency">Latency (best)</SelectItem>
              <SelectItem value="tokens">Token Efficiency</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Total Delegations</p>
                <p className="text-2xl font-bold mt-1">{summary?.totalDelegations?.toLocaleString() ?? 0}</p>
              </div>
              <Activity className="h-8 w-8 text-cyan-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Avg Success Rate</p>
                <p className="text-2xl font-bold mt-1">{summary?.avgSuccessRate ?? 0}%</p>
              </div>
              <TrendingUp className="h-8 w-8 text-emerald-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Total Tokens</p>
                <p className="text-2xl font-bold mt-1">{(summary?.totalTokens ?? 0).toLocaleString()}</p>
              </div>
              <Zap className="h-8 w-8 text-amber-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Top Agent</p>
                <p className="text-lg font-bold mt-1 truncate">{summary?.topAgent ?? "N/A"}</p>
              </div>
              <Trophy className="h-8 w-8 text-amber-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Leaderboard Table */}
      <Card className="border-border/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-lg flex items-center gap-2">
            <BarChart3 className="h-5 w-5 text-cyan-400" />
            Agent Rankings
          </CardTitle>
          <CardDescription>Click any agent to expand detailed metrics</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/50 text-muted-foreground">
                  <th className="text-left p-3 w-12">#</th>
                  <th className="text-left p-3">Agent</th>
                  <th className="text-left p-3">Category</th>
                  <th className="text-right p-3">Delegations</th>
                  <th className="text-right p-3">Success Rate</th>
                  <th className="text-right p-3">Confidence</th>
                  <th className="text-right p-3">Avg Latency</th>
                  <th className="text-right p-3">Tokens/Op</th>
                  <th className="text-right p-3">Composite</th>
                </tr>
              </thead>
              <tbody>
                {leaderboard.map((agent) => {
                  const rankStyle = agent.rank <= 3 ? RANK_STYLES[agent.rank - 1] : null;
                  const CatIcon = CATEGORY_ICONS[agent.category] || Bot;
                  const catColor = CATEGORY_COLORS[agent.category] || "text-gray-400";
                  const isExpanded = expandedAgent === agent.agentId;

                  return (
                    <>
                      <tr
                        key={agent.agentId}
                        className={`border-b border-border/30 cursor-pointer transition-colors hover:bg-muted/30 ${
                          rankStyle ? `${rankStyle.bg}` : ""
                        }`}
                        onClick={() => setExpandedAgent(isExpanded ? null : agent.agentId)}
                      >
                        <td className="p-3">
                          {rankStyle ? (
                            <div className={`flex items-center justify-center w-8 h-8 rounded-full ${rankStyle.bg} ${rankStyle.border} border`}>
                              <span className={`text-sm font-bold ${rankStyle.text}`}>{agent.rank}</span>
                            </div>
                          ) : (
                            <span className="text-muted-foreground ml-2">{agent.rank}</span>
                          )}
                        </td>
                        <td className="p-3">
                          <div className="flex items-center gap-2">
                            <CatIcon className={`h-4 w-4 ${catColor}`} />
                            <span className="font-medium">{agent.name}</span>
                            {agent.priority === "critical" && (
                              <Badge variant="destructive" className="text-[10px] px-1.5 py-0">CRITICAL</Badge>
                            )}
                          </div>
                        </td>
                        <td className="p-3">
                          <Badge variant="outline" className="text-xs capitalize">
                            {agent.category?.replace(/_/g, " ")}
                          </Badge>
                        </td>
                        <td className="p-3 text-right font-mono">{agent.delegations.toLocaleString()}</td>
                        <td className="p-3 text-right">
                          <span className={agent.successRate >= 80 ? "text-emerald-400" : agent.successRate >= 50 ? "text-amber-400" : "text-red-400"}>
                            {agent.successRate}%
                          </span>
                        </td>
                        <td className="p-3 text-right">
                          <span className={agent.avgConfidence >= 70 ? "text-emerald-400" : agent.avgConfidence >= 40 ? "text-amber-400" : "text-red-400"}>
                            {agent.avgConfidence}%
                          </span>
                        </td>
                        <td className="p-3 text-right font-mono">
                          <span className={agent.avgLatencyMs <= 2000 ? "text-emerald-400" : agent.avgLatencyMs <= 5000 ? "text-amber-400" : "text-red-400"}>
                            {agent.avgLatencyMs.toLocaleString()}ms
                          </span>
                        </td>
                        <td className="p-3 text-right font-mono">{agent.tokensPerDecision.toLocaleString()}</td>
                        <td className="p-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <div className="w-16">
                              <Progress value={agent.compositeScore} className="h-2" />
                            </div>
                            <span className="font-bold text-cyan-400 w-10 text-right">{agent.compositeScore}</span>
                            {isExpanded ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                          </div>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr key={`${agent.agentId}-detail`}>
                          <td colSpan={9} className="p-0">
                            <AgentDetailPanel agentId={agent.agentId} windowDays={windowDays} agent={agent} />
                          </td>
                        </tr>
                      )}
                    </>
                  );
                })}
                {leaderboard.length === 0 && (
                  <tr>
                    <td colSpan={9} className="p-8 text-center text-muted-foreground">
                      No agent data available for the selected time window.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Delegation Heatmap */}
      {heatmapData && heatmapData.heatmap.length > 0 && (
        <Card className="border-border/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-lg flex items-center gap-2">
              <Brain className="h-5 w-5 text-purple-400" />
              Delegation Heatmap by Phase
            </CardTitle>
            <CardDescription>Which agents are invoked most in each engagement phase</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <div className="space-y-2">
                {heatmapData.heatmap.map((row) => (
                  <div key={row.phase} className="flex items-center gap-3">
                    <div className="w-32 text-xs font-medium text-muted-foreground capitalize shrink-0">
                      {row.phase.replace(/_/g, " ")}
                    </div>
                    <div className="flex-1 flex items-center gap-1 flex-wrap">
                      {row.agents
                        .sort((a, b) => b.count - a.count)
                        .slice(0, 6)
                        .map((agent) => {
                          const intensity = Math.min(1, agent.count / Math.max(1, row.total));
                          return (
                            <TooltipProvider key={agent.agentId}>
                              <Tooltip>
                                <TooltipTrigger>
                                  <div
                                    className="px-2 py-1 rounded text-[10px] font-medium border border-cyan-500/30 transition-all"
                                    style={{
                                      backgroundColor: `rgba(6, 182, 212, ${0.1 + intensity * 0.5})`,
                                      color: intensity > 0.3 ? "white" : "rgba(6, 182, 212, 0.8)",
                                    }}
                                  >
                                    {agent.name.split(" ").slice(0, 2).join(" ")} ({agent.count})
                                  </div>
                                </TooltipTrigger>
                                <TooltipContent>
                                  <p>{agent.name}: {agent.count} delegations in {row.phase}</p>
                                </TooltipContent>
                              </Tooltip>
                            </TooltipProvider>
                          );
                        })}
                    </div>
                    <div className="text-xs text-muted-foreground w-12 text-right shrink-0">{row.total}</div>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Agent Detail Panel (expanded row) ──────────────────────────────────────

function AgentDetailPanel({
  agentId,
  windowDays,
  agent,
}: {
  agentId: string;
  windowDays: number;
  agent: any;
}) {
  const { data, isLoading } = trpc.agentLeaderboard.getAgentPerformance.useQuery(
    { agentId, windowDays },
    { refetchInterval: 60000 }
  );

  if (isLoading) {
    return (
      <div className="p-4 bg-muted/10 border-t border-border/30">
        <div className="flex gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-20 flex-1 bg-muted animate-pulse rounded" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 bg-muted/10 border-t border-border/30 space-y-4">
      {/* Agent Info */}
      <div className="flex items-start gap-6">
        <div className="flex-1 space-y-1">
          <h3 className="font-semibold text-lg">{data?.agent.name}</h3>
          <p className="text-sm text-muted-foreground">{data?.agent.mission}</p>
          {data?.agent.mitreTactics && (data.agent.mitreTactics as string[]).length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {(data.agent.mitreTactics as string[]).slice(0, 5).map((tactic: string) => (
                <Badge key={tactic} variant="outline" className="text-[10px]">{tactic}</Badge>
              ))}
            </div>
          )}
        </div>

        {/* Metric Cards */}
        <div className="grid grid-cols-4 gap-3">
          <div className="text-center p-2 rounded bg-card/50 border border-border/30">
            <p className="text-xs text-muted-foreground">Calls</p>
            <p className="text-lg font-bold">{agent.totalCalls}</p>
          </div>
          <div className="text-center p-2 rounded bg-card/50 border border-border/30">
            <p className="text-xs text-muted-foreground">Decisions</p>
            <p className="text-lg font-bold">{agent.totalDecisions}</p>
          </div>
          <div className="text-center p-2 rounded bg-card/50 border border-border/30">
            <p className="text-xs text-muted-foreground">Stealth</p>
            <p className="text-lg font-bold">{agent.avgStealthScore}</p>
          </div>
          <div className="text-center p-2 rounded bg-card/50 border border-border/30">
            <p className="text-xs text-muted-foreground">Tokens</p>
            <p className="text-lg font-bold">{agent.totalTokens.toLocaleString()}</p>
          </div>
        </div>
      </div>

      {/* Phase Distribution */}
      {data?.phaseDistribution && data.phaseDistribution.length > 0 && (
        <div>
          <h4 className="text-sm font-medium text-muted-foreground mb-2">Phase Distribution</h4>
          <div className="flex gap-2 flex-wrap">
            {data.phaseDistribution.map((p) => (
              <div key={p.phase} className="flex items-center gap-1.5 px-2 py-1 rounded bg-card/50 border border-border/30">
                <span className="text-xs capitalize">{p.phase.replace(/_/g, " ")}</span>
                <Badge variant="secondary" className="text-[10px]">{p.count}</Badge>
                <span className="text-[10px] text-muted-foreground">({p.avgStealth} stealth)</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent Decisions */}
      {data?.recentDecisions && data.recentDecisions.length > 0 && (
        <div>
          <h4 className="text-sm font-medium text-muted-foreground mb-2">Recent Decisions</h4>
          <div className="space-y-1 max-h-48 overflow-y-auto">
            {data.recentDecisions.slice(0, 8).map((dec) => (
              <div key={dec.id} className="flex items-center gap-3 px-3 py-1.5 rounded bg-card/30 text-xs">
                <Badge
                  variant={dec.outcome === "success" ? "default" : dec.outcome === "failure" ? "destructive" : "secondary"}
                  className="text-[10px] w-16 justify-center"
                >
                  {dec.outcome}
                </Badge>
                <span className="capitalize text-muted-foreground w-20">{dec.phase}</span>
                <span className="flex-1 truncate">{dec.decision}</span>
                <span className="text-muted-foreground">{dec.latencyMs}ms</span>
                <span className="text-muted-foreground">{dec.stealthScore ? `${(Number(dec.stealthScore) * 100).toFixed(0)}%` : "-"}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
