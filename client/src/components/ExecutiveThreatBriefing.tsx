import { trpc } from "@/lib/trpc";
import { useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Shield, ShieldAlert, Target, Globe, Brain, TrendingUp, TrendingDown,
  Minus, ChevronDown, ChevronRight, AlertTriangle, Crosshair, Eye,
  RefreshCw, BarChart3, Activity, Loader2, Zap, ArrowUpRight
} from "lucide-react";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  ResponsiveContainer, Tooltip as RechartsTooltip, Legend
} from "recharts";
import { Link } from "wouter";

// ─── Threat Level Colors ──────────────────────────────────────────────────────
const THREAT_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  elevated: "text-amber-400 bg-amber-500/10 border-amber-500/30",
  moderate: "text-blue-400 bg-blue-500/10 border-blue-500/30",
  low: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
  unknown: "text-zinc-400 bg-zinc-500/10 border-zinc-500/30",
};

const THREAT_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  medium: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  low: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
};

const TREND_ICON = {
  rising: <TrendingUp className="w-3.5 h-3.5 text-red-400" />,
  stable: <Minus className="w-3.5 h-3.5 text-zinc-400" />,
  declining: <TrendingDown className="w-3.5 h-3.5 text-emerald-400" />,
};

// ─── Relevance Score Bar ──────────────────────────────────────────────────────
function RelevanceBar({ score }: { score: number }) {
  const color = score >= 80 ? "bg-red-500" : score >= 60 ? "bg-orange-500" : score >= 40 ? "bg-amber-500" : "bg-blue-500";
  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color} transition-all`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs font-mono text-zinc-400 w-8 text-right">{score}</span>
    </div>
  );
}

// ─── CARVER Radar (simple bar display) ────────────────────────────────────────
function CarverProfile({ profile }: { profile: any }) {
  if (!profile) return null;
  const dimensions = [
    { key: "avgCriticality", label: "Criticality", color: "bg-red-500" },
    { key: "avgAccessibility", label: "Accessibility", color: "bg-orange-500" },
    { key: "avgRecuperability", label: "Recuperability", color: "bg-amber-500" },
    { key: "avgVulnerability", label: "Vulnerability", color: "bg-yellow-500" },
    { key: "avgEffect", label: "Effect", color: "bg-blue-500" },
    { key: "avgRecognizability", label: "Recognizability", color: "bg-purple-500" },
  ];
  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">CARVER Profile</h4>
      {dimensions.map(d => (
        <div key={d.key} className="flex items-center gap-2">
          <span className="text-xs text-zinc-500 w-28 truncate">{d.label}</span>
          <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
            <div className={`h-full rounded-full ${d.color}`} style={{ width: `${Math.min(100, (profile[d.key] / 10) * 100)}%` }} />
          </div>
          <span className="text-xs font-mono text-zinc-500 w-8 text-right">{profile[d.key]?.toFixed(1)}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Threat Likelihood Bars ───────────────────────────────────────────────────
function ThreatLikelihoods({ likelihoods }: { likelihoods: Array<{ threat: string; likelihood: number }> }) {
  if (!likelihoods?.length) return null;
  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Threat Likelihood</h4>
      {likelihoods.map(t => (
        <div key={t.threat} className="flex items-center gap-2">
          <span className="text-xs text-zinc-500 w-36 truncate">{t.threat}</span>
          <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
            <div className="h-full rounded-full bg-red-500/70" style={{ width: `${t.likelihood * 100}%` }} />
          </div>
          <span className="text-xs font-mono text-zinc-500 w-10 text-right">{(t.likelihood * 100).toFixed(0)}%</span>
        </div>
      ))}
    </div>
  );
}

// ─── Actor Card ───────────────────────────────────────────────────────────────
function ActorCard({ actor, rank }: { actor: any; rank: number }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="border border-zinc-800 rounded-lg bg-zinc-900/50 hover:bg-zinc-900/80 transition-colors">
      <button
        className="w-full text-left p-3 flex items-start gap-3"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex-shrink-0 w-7 h-7 rounded-full bg-zinc-800 flex items-center justify-center text-xs font-bold text-zinc-400">
          {rank}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <Link href={`/threat-catalog/${actor.actorId}`} onClick={(e: React.MouseEvent) => e.stopPropagation()}>
              <span className="font-semibold text-sm text-zinc-100 hover:text-blue-400 transition-colors">
                {actor.name}
              </span>
            </Link>
            <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${THREAT_BADGE[actor.threatLevel] || THREAT_BADGE.medium}`}>
              {actor.threatLevel?.toUpperCase()}
            </Badge>
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-zinc-700 text-zinc-400">
              {actor.actorType?.toUpperCase()}
            </Badge>
            {actor.origin && (
              <span className="text-[10px] text-zinc-500 flex items-center gap-0.5">
                <Globe className="w-3 h-3" />{actor.origin}
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 mt-1">
            <RelevanceBar score={actor.relevanceScore} />
            {actor.matchedSectors?.length > 0 && (
              <span className="text-[10px] text-zinc-500">
                Sectors: {actor.matchedSectors.slice(0, 3).join(", ")}
              </span>
            )}
          </div>
        </div>
        <div className="flex-shrink-0 text-zinc-500">
          {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </div>
      </button>

      {expanded && (
        <div className="px-3 pb-3 pt-0 border-t border-zinc-800 space-y-3">
          {/* Relevance Breakdown */}
          <div className="grid grid-cols-5 gap-2 pt-2">
            {[
              { label: "Sector", val: actor.relevanceFactors?.sectorMatch, max: 40 },
              { label: "Threat Level", val: actor.relevanceFactors?.threatLevelWeight, max: 20 },
              { label: "CARVER Align", val: actor.relevanceFactors?.carverAlignment, max: 20 },
              { label: "Activity", val: actor.relevanceFactors?.recentActivity, max: 10 },
              { label: "IOC Density", val: actor.relevanceFactors?.iocOverlap, max: 10 },
            ].map(f => (
              <div key={f.label} className="text-center">
                <div className="text-[10px] text-zinc-500">{f.label}</div>
                <div className="text-xs font-mono text-zinc-300">{f.val}/{f.max}</div>
              </div>
            ))}
          </div>

          {/* Attack Vectors */}
          {actor.attackVectors?.length > 0 && (
            <div>
              <div className="text-[10px] text-zinc-500 mb-1 uppercase tracking-wider">Attack Vectors</div>
              <div className="flex flex-wrap gap-1">
                {actor.attackVectors.map((v: string) => (
                  <Badge key={v} variant="outline" className="text-[10px] px-1.5 py-0 border-zinc-700 text-zinc-400">{v}</Badge>
                ))}
              </div>
            </div>
          )}

          {/* Top Techniques */}
          {actor.topTechniques?.length > 0 && (
            <div>
              <div className="text-[10px] text-zinc-500 mb-1 uppercase tracking-wider">Key Techniques</div>
              <div className="flex flex-wrap gap-1">
                {actor.topTechniques.map((t: any) => (
                  <Badge key={t.id} variant="outline" className="text-[10px] px-1.5 py-0 border-zinc-700 text-zinc-400">
                    {t.id}: {t.name}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Recent Events */}
          {actor.recentEvents?.length > 0 && (
            <div>
              <div className="text-[10px] text-zinc-500 mb-1 uppercase tracking-wider">Recent Activity</div>
              {actor.recentEvents.map((e: any, i: number) => (
                <div key={i} className="flex items-center gap-2 text-xs text-zinc-400 py-0.5">
                  <Badge variant="outline" className={`text-[9px] px-1 py-0 ${THREAT_BADGE[e.severity] || THREAT_BADGE.medium}`}>
                    {e.severity}
                  </Badge>
                  <span className="truncate">{e.title}</span>
                  {e.date && <span className="text-zinc-600 flex-shrink-0">{new Date(e.date).toLocaleDateString()}</span>}
                </div>
              ))}
            </div>
          )}

          {/* Recommended Actions */}
          {actor.recommendedActions?.length > 0 && (
            <div>
              <div className="text-[10px] text-zinc-500 mb-1 uppercase tracking-wider">Recommended Actions</div>
              <ul className="space-y-0.5">
                {actor.recommendedActions.map((a: string, i: number) => (
                  <li key={i} className="text-xs text-zinc-400 flex items-start gap-1.5">
                    <Zap className="w-3 h-3 text-amber-500 flex-shrink-0 mt-0.5" />
                    {a}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* IOC Count + Link */}
          <div className="flex items-center gap-4 text-xs text-zinc-500 pt-1">
            <span>{actor.iocCount} IOCs tracked</span>
            <Link href={`/threat-catalog/${actor.actorId}`}>
              <span className="text-blue-400 hover:text-blue-300 flex items-center gap-0.5 cursor-pointer">
                View Full Profile <ArrowUpRight className="w-3 h-3" />
              </span>
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function ExecutiveThreatBriefing() {
  const [selectedScanId, setSelectedScanId] = useState<number | undefined>(undefined);

  const briefingInput = useMemo(() => ({
    scanId: selectedScanId,
    limit: 15,
  }), [selectedScanId]);

  const { data: briefing, isLoading, refetch, isFetching } = trpc.executiveDashboard.threatBriefing.useQuery(
    briefingInput,
    { staleTime: 60_000, refetchInterval: 5 * 60_000 }
  );
  const { data: scans } = trpc.executiveDashboard.briefingScans.useQuery(undefined, { staleTime: 120_000 });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 animate-spin text-zinc-500" />
        <span className="ml-2 text-sm text-zinc-500">Computing threat briefing...</span>
      </div>
    );
  }

  if (!briefing) return null;

  const { summary, matchedActors, trends, carverProfile, scan } = briefing;
  const riskColor = THREAT_COLORS[summary.sectorRiskLevel] || THREAT_COLORS.unknown;

  return (
    <div className="space-y-4">
      {/* ── Header: Scan Selector + Summary ── */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <select
            className="bg-zinc-900 border border-zinc-700 rounded-md px-3 py-1.5 text-sm text-zinc-300 focus:outline-none focus:ring-1 focus:ring-blue-500"
            value={selectedScanId || ""}
            onChange={(e) => setSelectedScanId(e.target.value ? Number(e.target.value) : undefined)}
          >
            <option value="">Latest Scan (Auto)</option>
            {scans?.map((s: any) => (
              <option key={s.id} value={s.id}>
                {s.domain} — {s.sector || "N/A"} ({s.riskBand || "?"})
              </option>
            ))}
          </select>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
            className="text-zinc-400 hover:text-zinc-200"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? "animate-spin" : ""}`} />
          </Button>
        </div>
        {scan && (
          <div className="flex items-center gap-2 text-xs text-zinc-500">
            <Globe className="w-3.5 h-3.5" />
            <span>{scan.domain}</span>
            {scan.sector && <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-zinc-700">{scan.sector}</Badge>}
            {scan.riskBand && (
              <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${THREAT_BADGE[scan.riskBand] || ""}`}>
                Risk: {scan.riskBand}
              </Badge>
            )}
            <span>{scan.totalAssets} assets · {scan.totalFindings} findings</span>
          </div>
        )}
      </div>

      {/* ── Summary Cards ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="p-3">
            <div className="flex items-center gap-2">
              <div className={`p-1.5 rounded-md border ${riskColor}`}>
                <ShieldAlert className="w-4 h-4" />
              </div>
              <div>
                <div className="text-[10px] text-zinc-500 uppercase">Sector Risk</div>
                <div className="text-sm font-bold text-zinc-100 capitalize">{summary.sectorRiskLevel}</div>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="p-3">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-md border border-red-500/30 bg-red-500/10">
                <Target className="w-4 h-4 text-red-400" />
              </div>
              <div>
                <div className="text-[10px] text-zinc-500 uppercase">Matched Actors</div>
                <div className="text-sm font-bold text-zinc-100">
                  {summary.totalMatched}
                  <span className="text-xs font-normal text-zinc-500 ml-1">
                    ({summary.criticalActors} crit · {summary.highActors} high)
                  </span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="p-3">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-md border border-blue-500/30 bg-blue-500/10">
                <Brain className="w-4 h-4 text-blue-400" />
              </div>
              <div>
                <div className="text-[10px] text-zinc-500 uppercase">Avg Relevance</div>
                <div className="text-sm font-bold text-zinc-100">{summary.avgRelevanceScore}/100</div>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="p-3">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-md border border-amber-500/30 bg-amber-500/10">
                <Crosshair className="w-4 h-4 text-amber-400" />
              </div>
              <div>
                <div className="text-[10px] text-zinc-500 uppercase">Top Vector</div>
                <div className="text-sm font-bold text-zinc-100 truncate max-w-[140px]">
                  {summary.topAttackVectors?.[0] || "N/A"}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* ── Main Content: 2-column layout ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left: Matched Actors List */}
        <div className="lg:col-span-2 space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider flex items-center gap-1.5">
              <Target className="w-3.5 h-3.5" />
              Matched Threat Actors (Ranked by Relevance)
            </h3>
            <span className="text-[10px] text-zinc-600">
              Updated {new Date(briefing.lastUpdated).toLocaleTimeString()}
            </span>
          </div>
          <div className="space-y-1.5 max-h-[600px] overflow-y-auto pr-1 custom-scrollbar">
            {matchedActors.map((actor: any, i: number) => (
              <ActorCard key={actor.actorId} actor={actor} rank={i + 1} />
            ))}
            {matchedActors.length === 0 && (
              <div className="text-center py-8 text-zinc-500 text-sm">
                No threat actors matched the current scan profile.
              </div>
            )}
          </div>
        </div>

        {/* Right: CARVER Profile + Trends + Activity */}
        <div className="space-y-4">
          {/* CARVER Profile */}
          {carverProfile && (
            <Card className="bg-zinc-900/60 border-zinc-800">
              <CardContent className="p-3 space-y-3">
                <CarverProfile profile={carverProfile} />
                {carverProfile.priorityBreakdown && (
                  <div className="flex items-center gap-2 text-xs">
                    {Object.entries(carverProfile.priorityBreakdown).sort().map(([tier, count]) => (
                      <Badge key={tier} variant="outline" className="text-[10px] border-zinc-700 text-zinc-400">
                        {tier}: {count as number}
                      </Badge>
                    ))}
                  </div>
                )}
                <ThreatLikelihoods likelihoods={carverProfile.topThreatLikelihoods} />
              </CardContent>
            </Card>
          )}

          {/* Threat Event Trends */}
          {trends.eventsByMonth?.length > 0 && (
            <Card className="bg-zinc-900/60 border-zinc-800">
              <CardContent className="p-3">
                <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <BarChart3 className="w-3.5 h-3.5" />
                  Threat Event Trends (90d)
                </h4>
                <ResponsiveContainer width="100%" height={160}>
                  <AreaChart data={trends.eventsByMonth}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                    <XAxis dataKey="month" tick={{ fontSize: 10, fill: "#71717a" }} />
                    <YAxis tick={{ fontSize: 10, fill: "#71717a" }} />
                    <RechartsTooltip
                      contentStyle={{ backgroundColor: "#18181b", border: "1px solid #3f3f46", borderRadius: "6px", fontSize: "11px" }}
                      labelStyle={{ color: "#a1a1aa" }}
                    />
                    <Area type="monotone" dataKey="count" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.1} name="Total" />
                    <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="#ef4444" fillOpacity={0.1} name="Critical" />
                    <Area type="monotone" dataKey="high" stroke="#f97316" fill="#f97316" fillOpacity={0.1} name="High" />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          )}

          {/* Actor Activity Trend */}
          {trends.actorActivityTrend?.length > 0 && (
            <Card className="bg-zinc-900/60 border-zinc-800">
              <CardContent className="p-3">
                <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5" />
                  Actor Activity Momentum
                </h4>
                <div className="space-y-1.5">
                  {trends.actorActivityTrend.map((a: any) => (
                    <div key={a.actorId} className="flex items-center gap-2 text-xs">
                      <span className="w-24 truncate text-zinc-400">{a.name}</span>
                      <div className="flex-1 flex items-center gap-1">
                        <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${a.trend === "rising" ? "bg-red-500" : a.trend === "declining" ? "bg-emerald-500" : "bg-zinc-600"}`}
                            style={{ width: `${Math.min(100, a.eventsLast90d * 3)}%` }}
                          />
                        </div>
                        {TREND_ICON[a.trend as keyof typeof TREND_ICON]}
                      </div>
                      <span className="text-zinc-500 font-mono w-16 text-right">{a.eventsLast30d}/{a.eventsLast90d}</span>
                    </div>
                  ))}
                </div>
                <div className="text-[10px] text-zinc-600 mt-1.5">30d / 90d event counts</div>
              </CardContent>
            </Card>
          )}

          {/* Top Attack Vectors */}
          {summary.topAttackVectors?.length > 0 && (
            <Card className="bg-zinc-900/60 border-zinc-800">
              <CardContent className="p-3">
                <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <Crosshair className="w-3.5 h-3.5" />
                  Top Attack Vectors
                </h4>
                <div className="flex flex-wrap gap-1.5">
                  {summary.topAttackVectors.map((v: string, i: number) => (
                    <Badge key={v} variant="outline" className={`text-[10px] px-2 py-0.5 ${i === 0 ? "border-red-500/40 text-red-300" : "border-zinc-700 text-zinc-400"}`}>
                      {v}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
