import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { safeUpper } from "@/lib/utils-safe";
import { useState } from "react";
import { Link } from "wouter";
import {
  AlertTriangle, Eye, Globe2, Shield, Skull, Clock,
  Activity, TrendingUp, Search, ExternalLink, Radio,
  Database, Loader2, RefreshCw, Crosshair, FileText,
} from "lucide-react";

const EVENT_TYPE_COLORS: Record<string, string> = {
  attack: "text-red-400 bg-red-500/10",
  campaign: "text-orange-400 bg-orange-500/10",
  data_leak: "text-amber-400 bg-amber-500/10",
  infrastructure_change: "text-blue-400 bg-blue-500/10",
  malware_update: "text-purple-400 bg-purple-500/10",
  law_enforcement: "text-green-400 bg-green-500/10",
  ttp_evolution: "text-cyan-400 bg-cyan-500/10",
  group_rebrand: "text-pink-400 bg-pink-500/10",
  new_tool: "text-indigo-400 bg-indigo-500/10",
  zero_day: "text-red-500 bg-red-500/15",
  affiliate_change: "text-yellow-400 bg-yellow-500/10",
  group_merger: "text-violet-400 bg-violet-500/10",
};

const ACTOR_TYPE_COLORS: Record<string, string> = {
  apt: "text-red-400",
  ransomware: "text-amber-400",
  cybercrime: "text-purple-400",
  hacktivist: "text-cyan-400",
  access_broker: "text-orange-400",
  influence_ops: "text-pink-400",
};

export default function DarkwebIntel() {
  const [eventTypeFilter, setEventTypeFilter] = useState<string>("all");
  const [limit, setLimit] = useState(100);

  const { data: events, isLoading: eventsLoading, refetch: refetchEvents } = trpc.threatIntel.recentEvents.useQuery({
    limit,
    eventType: eventTypeFilter !== "all" ? eventTypeFilter : undefined,
  });

  const { data: syncHistory, isLoading: syncLoading } = trpc.threatIntel.syncHistory.useQuery({ limit: 10 });
  const { data: stats } = trpc.threatIntel.stats.useQuery();
  const { data: coverage } = trpc.threatIntel.techniqueCoverage.useQuery();

  const monitoringSweep = trpc.threatIntel.runMonitoringSweep.useMutation({
    onSuccess: () => refetchEvents(),
  });

  const eventTypes = [
    "all", "attack", "campaign", "data_leak", "infrastructure_change",
    "malware_update", "law_enforcement", "ttp_evolution", "zero_day", "new_tool",
  ];

  return (
    <AppShell activePath="/darkweb-intel">
      <div className="max-w-[1600px] mx-auto space-y-6">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <Eye className="w-8 h-8 text-emerald-400" />
              <h1 className="text-2xl lg:text-3xl font-display tracking-wider">DARKWEB INTELLIGENCE</h1>
            </div>
            <p className="text-muted-foreground text-sm">
              Threat event feed, LLM monitoring sweeps, MITRE ATT&CK technique coverage, and sync history
            </p>
          </div>
          <button
            onClick={() => monitoringSweep.mutate({})}
            disabled={monitoringSweep.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-display tracking-wider hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
          >
            {monitoringSweep.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Radio className="w-3 h-3" />}
            RUN LLM MONITORING SWEEP
          </button>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="bg-card border border-emerald-500/20 p-3">
            <div className="flex items-center gap-2 mb-1">
              <Database className="w-4 h-4 text-emerald-400" />
              <span className="text-[10px] text-muted-foreground tracking-wider">CATALOG ACTORS</span>
            </div>
            <p className="text-xl font-display text-emerald-400">{stats?.totalActors ?? 0}</p>
          </div>
          <div className="bg-card border border-primary/20 p-3">
            <div className="flex items-center gap-2 mb-1">
              <Crosshair className="w-4 h-4 text-primary" />
              <span className="text-[10px] text-muted-foreground tracking-wider">TECHNIQUES MAPPED</span>
            </div>
            <p className="text-xl font-display text-primary">{coverage?.totalTechniques ?? 0}</p>
          </div>
          <div className="bg-card border border-amber-500/20 p-3">
            <div className="flex items-center gap-2 mb-1">
              <Activity className="w-4 h-4 text-amber-400" />
              <span className="text-[10px] text-muted-foreground tracking-wider">EVENTS TRACKED</span>
            </div>
            <p className="text-xl font-display text-amber-400">{events?.length ?? 0}</p>
          </div>
          <div className="bg-card border border-blue-500/20 p-3">
            <div className="flex items-center gap-2 mb-1">
              <Clock className="w-4 h-4 text-blue-400" />
              <span className="text-[10px] text-muted-foreground tracking-wider">LAST SYNC</span>
            </div>
            <p className="text-xs font-display text-blue-400 mt-1">
              {stats?.lastSync ? new Date(stats.lastSync).toLocaleString() : "Never"}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Event Feed (2/3) */}
          <div className="lg:col-span-2 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" /> THREAT EVENT FEED
              </h2>
              <button onClick={() => refetchEvents()} className="text-[10px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1">
                <RefreshCw className="w-3 h-3" /> REFRESH
              </button>
            </div>

            {/* Event Type Filters */}
            <div className="flex gap-1 flex-wrap">
              {eventTypes.map(t => (
                <button key={t} onClick={() => setEventTypeFilter(t)}
                  className={`px-2 py-1 text-[10px] font-display tracking-wider border transition-colors ${
                    eventTypeFilter === t ? "bg-emerald-500/20 border-emerald-500/50 text-emerald-400"
                      : "bg-card border-border text-muted-foreground hover:text-foreground"}`}>
                  {t === "all" ? "ALL" : safeUpper(t.replace(/_/g, " "))}
                </button>
              ))}
            </div>

            {/* Events List */}
            {eventsLoading ? (
              <div className="space-y-3">
                {Array.from({ length: 8 }).map((_, i) => (
                  <div key={i} className="bg-card border border-border p-4 animate-pulse">
                    <div className="h-4 bg-muted rounded w-1/3 mb-2" />
                    <div className="h-3 bg-muted rounded w-full" />
                  </div>
                ))}
              </div>
            ) : !events || events.length === 0 ? (
              <div className="bg-card border border-border p-8 text-center">
                <AlertTriangle className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">No threat events recorded yet. Run a monitoring sweep or sync the catalog.</p>
              </div>
            ) : (
              <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                {events.map((evt: any) => {
                  const evtColor = EVENT_TYPE_COLORS[evt.eventType] || "text-gray-400 bg-gray-500/10";
                  const actorColor = ACTOR_TYPE_COLORS[evt.actorType || ""] || "text-muted-foreground";
                  return (
                    <div key={evt.id} className="bg-card border border-border p-3 hover:bg-accent/5 transition-colors">
                      <div className="flex items-start justify-between mb-1.5">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`text-[10px] px-2 py-0.5 ${evtColor} tracking-wider`}>
                            {safeUpper(evt.eventType?.replace(/_/g, " "))}
                          </span>
                          {evt.actorName && (
                            <Link href={`/threat-catalog/${evt.actorId}`} className={`text-[10px] ${actorColor} hover:underline`}>
                              {evt.actorName}
                            </Link>
                          )}
                        </div>
                        <span className="text-[10px] text-muted-foreground shrink-0">
                          {evt.eventDate ? new Date(evt.eventDate).toLocaleDateString() : "—"}
                        </span>
                      </div>
                      <h4 className="text-xs font-display tracking-wider mb-1">{evt.title}</h4>
                      {evt.description && <p className="text-[11px] text-muted-foreground line-clamp-2">{evt.description}</p>}
                      <div className="flex items-center gap-3 mt-1.5 text-[10px] text-muted-foreground">
                        {evt.victimName && <span>Target: {evt.victimName}</span>}
                        {evt.mitreTechniques?.length > 0 && <span className="text-primary">{evt.mitreTechniques.length} TTPs</span>}
                        {evt.iocs?.length > 0 && <span className="text-red-400">{evt.iocs.length} IOCs</span>}
                        {evt.source && <span className="ml-auto">{evt.source}</span>}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Sidebar (1/3) */}
          <div className="space-y-6">
            {/* Technique Coverage */}
            <div className="bg-card border border-border p-4">
              <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                <Crosshair className="w-4 h-4 text-primary" /> TOP MITRE TECHNIQUES
              </h3>
              {coverage?.topTechniques && coverage.topTechniques.length > 0 ? (
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {coverage.topTechniques.slice(0, 15).map((t: any) => (
                    <div key={t.id} className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="font-mono text-primary shrink-0">{t.id}</span>
                        <span className="text-muted-foreground truncate">{t.name}</span>
                      </div>
                      <span className="text-[10px] text-muted-foreground shrink-0">{t.actors.length} actors</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">No techniques mapped yet.</p>
              )}
            </div>

            {/* Tactic Distribution */}
            {coverage?.byTactic && coverage.byTactic.length > 0 && (
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-cyan-400" /> TACTIC DISTRIBUTION
                </h3>
                <div className="space-y-2">
                  {coverage.byTactic.slice(0, 12).map((t: any) => (
                    <div key={t.tactic} className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground capitalize">{t.tactic.replace(/-/g, " ")}</span>
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-muted overflow-hidden">
                          <div className="h-full bg-cyan-400" style={{ width: `${Math.min(100, (t.count / (coverage.byTactic[0]?.count || 1)) * 100)}%` }} />
                        </div>
                        <span className="text-[10px] text-muted-foreground w-6 text-right">{t.count}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Sync History */}
            <div className="bg-card border border-border p-4">
              <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                <Clock className="w-4 h-4 text-blue-400" /> SYNC HISTORY
              </h3>
              {syncLoading ? (
                <div className="animate-pulse space-y-2">
                  {[1, 2, 3].map(i => <div key={i} className="h-8 bg-muted rounded" />)}
                </div>
              ) : !syncHistory || syncHistory.length === 0 ? (
                <p className="text-xs text-muted-foreground">No sync history yet.</p>
              ) : (
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {syncHistory.map((s: any) => (
                    <div key={s.id} className="flex items-center justify-between text-[11px] border-b border-border/50 pb-1.5">
                      <div>
                        <span className={`px-1.5 py-0.5 text-[10px] tracking-wider ${
                          s.status === "completed" ? "text-green-400 bg-green-500/10"
                            : s.status === "failed" ? "text-red-400 bg-red-500/10"
                            : "text-yellow-400 bg-yellow-500/10"}`}>
                          {safeUpper(s.status)}
                        </span>
                        <span className="text-muted-foreground ml-2">{s.sweepType}</span>
                      </div>
                      <span className="text-muted-foreground">
                        {s.startedAt ? new Date(s.startedAt).toLocaleDateString() : "—"}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Actor Type Distribution */}
            {stats?.byType && Object.keys(stats.byType).length > 0 && (
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <Database className="w-4 h-4 text-emerald-400" /> ACTOR DISTRIBUTION
                </h3>
                <div className="space-y-2">
                  {Object.entries(stats.byType).sort((a, b) => (b[1] as number) - (a[1] as number)).map(([type, count]) => (
                    <div key={type} className="flex items-center justify-between text-xs">
                      <span className={`capitalize ${ACTOR_TYPE_COLORS[type] || "text-muted-foreground"}`}>
                        {type.replace(/_/g, " ")}
                      </span>
                      <span className="text-muted-foreground">{count as number}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </AppShell>
  );
}
