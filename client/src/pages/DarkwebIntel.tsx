import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { safeUpper } from "@/lib/utils-safe";
import { useState, useMemo } from "react";
import { Link } from "wouter";
import {
  AlertTriangle, Eye, Globe2, Shield, Skull, Clock,
  Activity, TrendingUp, Search, ExternalLink, Radio,
  Database, Loader2, RefreshCw, Crosshair, FileText,
  Zap, Bug, Key, Tag, Wifi, WifiOff, ChevronDown, ChevronUp,
} from "lucide-react";
import { toast } from "sonner";

// ─── Color Maps ──────────────────────────────────────────────────────────

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

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-amber-400 bg-amber-500/10 border-amber-500/30",
  low: "text-blue-400 bg-blue-500/10 border-blue-500/30",
};

// ─── Component ───────────────────────────────────────────────────────────

export default function DarkwebIntel() {

  const [eventTypeFilter, setEventTypeFilter] = useState<string>("all");
  const [limit, setLimit] = useState(100);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    alerts: true, iocs: true, kev: true, otx: false, malware: false, keywords: false,
  });

  const toggleSection = (key: string) =>
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));

  // ─── Existing local queries ────────────────────────────────────────────
  const { data: events, isLoading: eventsLoading, refetch: refetchEvents } = trpc.threatIntel.recentEvents.useQuery({
    limit,
    eventType: eventTypeFilter !== "all" ? eventTypeFilter : undefined,
  });
  const { data: syncHistory, isLoading: syncLoading } = trpc.threatIntel.syncHistory.useQuery({ limit: 10 });
  const { data: stats } = trpc.threatIntel.stats.useQuery();
  const { data: coverage } = trpc.threatIntel.techniqueCoverage.useQuery();

  // ─── SpicyTIP Bridge queries ───────────────────────────────────────────
  const { data: bridgeHealth } = trpc.darkwebBridge.health.useQuery();
  const { data: escalationAlerts, isLoading: alertsLoading } = trpc.darkwebBridge.escalationAlerts.useQuery({});
  const { data: ransomwareVictimStats } = trpc.darkwebBridge.ransomwareVictimStats.useQuery({});
  const { data: activityRatings } = trpc.darkwebBridge.activityRatings.useQuery();
  const { data: threatFoxIOCs, isLoading: iocsLoading } = trpc.darkwebBridge.threatFoxIOCs.useQuery({});
  const { data: cisaKEV, isLoading: kevLoading } = trpc.darkwebBridge.cisaKEV.useQuery({});
  const { data: otxPulses, isLoading: otxLoading } = trpc.darkwebBridge.otxPulses.useQuery({});
  const { data: malwareBazaar, isLoading: malwareLoading } = trpc.darkwebBridge.malwareBazaar.useQuery({});
  const { data: adaptiveKeywords } = trpc.darkwebBridge.adaptiveKeywords.useQuery();
  const { data: recentVictimEvents } = trpc.darkwebBridge.recentVictimEvents.useQuery({});

  // ─── Mutations ─────────────────────────────────────────────────────────
  const monitoringSweep = trpc.threatIntel.runMonitoringSweep.useMutation({
    onSuccess: () => refetchEvents(),
  });

  const syncAll = trpc.darkwebBridge.syncAll.useMutation({
    onSuccess: (result) => {
      toast.success("Darkweb Sync Complete", {
        description: `Imported: ${result.actorsImported} actors, ${result.iocsImported} IOCs, ${result.eventsImported} events. ${result.errors.length > 0 ? `Errors: ${result.errors.length}` : ""}`,
      });
      refetchEvents();
    },
    onError: (err) => {
      toast.error("Sync Failed", { description: err.message });
    },
  });

  const eventTypes = [
    "all", "attack", "campaign", "data_leak", "infrastructure_change",
    "malware_update", "law_enforcement", "ttp_evolution", "zero_day", "new_tool",
  ];

  // Merge bridge victim events into the local event feed
  const bridgeVictimCount = recentVictimEvents?.data?.length ?? 0;
  const bridgeIOCCount = threatFoxIOCs?.data?.length ?? 0;
  const bridgeAlertCount = escalationAlerts?.data?.length ?? 0;

  return (
    <AppShell activePath="/darkweb-intel">
      <div className="max-w-[1600px] mx-auto space-y-6">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <Eye className="w-8 h-8 text-emerald-400" />
              <h1 className="text-2xl lg:text-3xl font-display tracking-wider">DARKWEB INTELLIGENCE</h1>
              {/* Bridge Status Indicator */}
              {bridgeHealth && (
                <span className={`flex items-center gap-1 px-2 py-0.5 text-[10px] tracking-wider border ${
                  bridgeHealth.reachable
                    ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
                    : (bridgeHealth as any).hasFallback
                    ? "text-cyan-400 bg-cyan-500/10 border-cyan-500/30"
                    : bridgeHealth.configured
                    ? "text-amber-400 bg-amber-500/10 border-amber-500/30"
                    : "text-red-400 bg-red-500/10 border-red-500/30"
                }`}>
                  {bridgeHealth.reachable ? <Wifi className="w-3 h-3" /> : (bridgeHealth as any).hasFallback ? <Radio className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
                  {bridgeHealth.reachable ? "BRIDGE LIVE" : (bridgeHealth as any).hasFallback ? "DIRECT FEEDS ACTIVE" : bridgeHealth.configured ? "BRIDGE OFFLINE" : "BRIDGE NOT CONFIGURED"}
                </span>
              )}
            </div>
            <p className="text-muted-foreground text-sm">
              Live darkweb intelligence from local threat database, event feed, MITRE ATT&CK coverage, and IOC corroboration
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => syncAll.mutate()}
              disabled={syncAll.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-primary/10 border border-primary/20 text-primary text-xs font-display tracking-wider hover:bg-primary/20 transition-colors disabled:opacity-50"
            >
              {syncAll.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Database className="w-3 h-3" />}
              SYNC DARKWEB DATA
            </button>
            <button
              onClick={() => monitoringSweep.mutate({})}
              disabled={monitoringSweep.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-display tracking-wider hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
            >
              {monitoringSweep.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Radio className="w-3 h-3" />}
              RUN LLM SWEEP
            </button>
          </div>
        </div>

        {/* Quick Stats — 6 cards */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
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
              <span className="text-[10px] text-muted-foreground tracking-wider">TECHNIQUES</span>
            </div>
            <p className="text-xl font-display text-primary">{coverage?.totalTechniques ?? 0}</p>
          </div>
          <div className="bg-card border border-amber-500/20 p-3">
            <div className="flex items-center gap-2 mb-1">
              <Activity className="w-4 h-4 text-amber-400" />
              <span className="text-[10px] text-muted-foreground tracking-wider">LOCAL EVENTS</span>
            </div>
            <p className="text-xl font-display text-amber-400">{events?.length ?? 0}</p>
          </div>
          <div className="bg-card border border-red-500/20 p-3">
            <div className="flex items-center gap-2 mb-1">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              <span className="text-[10px] text-muted-foreground tracking-wider">ALERTS</span>
            </div>
            <p className="text-xl font-display text-red-400">{bridgeAlertCount}</p>
          </div>
          <div className="bg-card border border-purple-500/20 p-3">
            <div className="flex items-center gap-2 mb-1">
              <Bug className="w-4 h-4 text-purple-400" />
              <span className="text-[10px] text-muted-foreground tracking-wider">THREATFOX IOCs</span>
            </div>
            <p className="text-xl font-display text-purple-400">{bridgeIOCCount}</p>
          </div>
          <div className="bg-card border border-cyan-500/20 p-3">
            <div className="flex items-center gap-2 mb-1">
              <Skull className="w-4 h-4 text-cyan-400" />
              <span className="text-[10px] text-muted-foreground tracking-wider">VICTIM EVENTS</span>
            </div>
            <p className="text-xl font-display text-cyan-400">{bridgeVictimCount}</p>
          </div>
        </div>

        {/* ─── Escalation Alerts Banner ─────────────────────────────────── */}
        {escalationAlerts && escalationAlerts.data.length > 0 && (
          <div className="bg-red-500/5 border border-red-500/20 p-4">
            <button onClick={() => toggleSection("alerts")} className="flex items-center justify-between w-full">
              <h2 className="text-sm font-display tracking-wider flex items-center gap-2 text-red-400">
                <Zap className="w-4 h-4" /> ESCALATION ALERTS ({escalationAlerts.data.length})
              </h2>
              {expandedSections.alerts ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
            </button>
            {expandedSections.alerts && (
              <div className="mt-3 space-y-2 max-h-48 overflow-y-auto">
                {escalationAlerts.data.map((alert: any, i: number) => (
                  <div key={i} className={`flex items-start gap-3 p-2 border ${SEVERITY_COLORS[alert.severity] || "text-gray-400 bg-gray-500/10 border-gray-500/30"}`}>
                    <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-[10px] tracking-wider">{safeUpper(alert.severity)}</span>
                        {alert.timestamp && <span className="text-[10px] text-muted-foreground">{new Date(alert.timestamp).toLocaleString()}</span>}
                      </div>
                      <p className="text-xs">{alert.title || alert.message || "Alert"}</p>
                      {alert.description && <p className="text-[11px] text-muted-foreground mt-0.5 line-clamp-2">{alert.description}</p>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* ─── Main Content (2/3) ──────────────────────────────────────── */}
          <div className="lg:col-span-2 space-y-6">

            {/* Threat Event Feed */}
            <div className="space-y-4">
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

            {/* ─── Ransomware Victim Events (from bridge) ────────────────── */}
            {recentVictimEvents && recentVictimEvents.data.length > 0 && (
              <div className="space-y-3">
                <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Skull className="w-4 h-4 text-cyan-400" /> RANSOMWARE VICTIM EVENTS
                  <span className="text-[10px] text-muted-foreground">LOCAL DB</span>
                </h2>
                <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1">
                  {recentVictimEvents.data.slice(0, 25).map((evt: any, i: number) => (
                    <div key={i} className="bg-card border border-border p-3 hover:bg-accent/5 transition-colors">
                      <div className="flex items-start justify-between mb-1">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] px-2 py-0.5 text-amber-400 bg-amber-500/10 tracking-wider">RANSOMWARE</span>
                          {evt.groupName && <span className="text-[10px] text-red-400 font-display">{evt.groupName}</span>}
                        </div>
                        <span className="text-[10px] text-muted-foreground">{evt.publishedDate ? new Date(evt.publishedDate).toLocaleDateString() : "—"}</span>
                      </div>
                      <h4 className="text-xs font-display tracking-wider mb-0.5">{evt.victimName || evt.title || "Unknown Victim"}</h4>
                      <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                        {evt.country && <span className="flex items-center gap-1"><Globe2 className="w-3 h-3" />{evt.country}</span>}
                        {evt.sector && <span>{evt.sector}</span>}
                        {evt.website && (
                          <a href={evt.website} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline flex items-center gap-1">
                            <ExternalLink className="w-3 h-3" /> Site
                          </a>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ─── ThreatFox IOCs (from bridge) ──────────────────────────── */}
            <div className="space-y-3">
              <button onClick={() => toggleSection("iocs")} className="flex items-center justify-between w-full">
                <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Bug className="w-4 h-4 text-purple-400" /> THREATFOX IOCs ({threatFoxIOCs?.data?.length ?? 0})
                  <span className="text-[10px] text-muted-foreground">{threatFoxIOCs?.source === 'local_database' ? 'LOCAL DB' : 'DIRECT FEED'}</span>
                </h2>
                {expandedSections.iocs ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSections.iocs && (
                iocsLoading ? (
                  <div className="space-y-2">{[1,2,3].map(i => <div key={i} className="h-10 bg-muted animate-pulse rounded" />)}</div>
                ) : !threatFoxIOCs || threatFoxIOCs.data.length === 0 ? (
                  <div className="bg-card border border-border p-6 text-center">
                    <Bug className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-xs text-muted-foreground">No ThreatFox IOCs available. Fetching from direct feed...</p>
                  </div>
                ) : (
                  <div className="space-y-1 max-h-[300px] overflow-y-auto pr-1">
                    {threatFoxIOCs.data.slice(0, 50).map((ioc: any, i: number) => (
                      <div key={i} className="bg-card border border-border p-2 flex items-center justify-between text-xs">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-[10px] px-1.5 py-0.5 bg-purple-500/10 text-purple-400 tracking-wider shrink-0">
                            {safeUpper(ioc.iocType || ioc.type || "UNK")}
                          </span>
                          <span className="font-mono text-muted-foreground truncate">{ioc.value || ioc.ioc || "—"}</span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          {ioc.malwareFamily && <span className="text-[10px] text-red-400">{ioc.malwareFamily}</span>}
                          {ioc.confidence && <span className="text-[10px] text-muted-foreground">{ioc.confidence}%</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                )
              )}
            </div>

            {/* ─── CISA KEV (from bridge) ────────────────────────────────── */}
            <div className="space-y-3">
              <button onClick={() => toggleSection("kev")} className="flex items-center justify-between w-full">
                <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Shield className="w-4 h-4 text-red-400" /> CISA KEV ({cisaKEV?.data?.length ?? 0})
                  <span className="text-[10px] text-muted-foreground">Known Exploited Vulnerabilities</span>
                </h2>
                {expandedSections.kev ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSections.kev && (
                kevLoading ? (
                  <div className="space-y-2">{[1,2,3].map(i => <div key={i} className="h-10 bg-muted animate-pulse rounded" />)}</div>
                ) : !cisaKEV || cisaKEV.data.length === 0 ? (
                  <div className="bg-card border border-border p-6 text-center">
                    <Shield className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-xs text-muted-foreground">No CISA KEV entries available.</p>
                  </div>
                ) : (
                  <div className="space-y-1 max-h-[300px] overflow-y-auto pr-1">
                    {cisaKEV.data.slice(0, 30).map((kev: any, i: number) => (
                      <div key={i} className="bg-card border border-border p-2">
                        <div className="flex items-center justify-between mb-0.5">
                          <span className="font-mono text-xs text-red-400">{kev.cveId || kev.cveID || "—"}</span>
                          <span className="text-[10px] text-muted-foreground">{kev.dateAdded ? new Date(kev.dateAdded).toLocaleDateString() : "—"}</span>
                        </div>
                        <p className="text-[11px] text-muted-foreground line-clamp-1">{kev.vulnerabilityName || kev.shortDescription || "—"}</p>
                        {kev.vendorProject && <span className="text-[10px] text-cyan-400">{kev.vendorProject} — {kev.product || ""}</span>}
                      </div>
                    ))}
                  </div>
                )
              )}
            </div>

            {/* ─── OTX Pulses (from bridge) ──────────────────────────────── */}
            <div className="space-y-3">
              <button onClick={() => toggleSection("otx")} className="flex items-center justify-between w-full">
                <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Globe2 className="w-4 h-4 text-blue-400" /> OTX PULSES ({otxPulses?.data?.length ?? 0})
                  <span className="text-[10px] text-muted-foreground">AlienVault Open Threat Exchange</span>
                </h2>
                {expandedSections.otx ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSections.otx && (
                otxLoading ? (
                  <div className="space-y-2">{[1,2,3].map(i => <div key={i} className="h-10 bg-muted animate-pulse rounded" />)}</div>
                ) : !otxPulses || otxPulses.data.length === 0 ? (
                  <div className="bg-card border border-border p-6 text-center">
                    <Globe2 className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-xs text-muted-foreground">No OTX pulses available.</p>
                  </div>
                ) : (
                  <div className="space-y-1 max-h-[300px] overflow-y-auto pr-1">
                    {otxPulses.data.slice(0, 25).map((pulse: any, i: number) => (
                      <div key={i} className="bg-card border border-border p-2">
                        <div className="flex items-center justify-between mb-0.5">
                          <h4 className="text-xs font-display tracking-wider truncate">{pulse.name || pulse.title || "Pulse"}</h4>
                          <span className="text-[10px] text-muted-foreground shrink-0">{pulse.created ? new Date(pulse.created).toLocaleDateString() : "—"}</span>
                        </div>
                        <p className="text-[11px] text-muted-foreground line-clamp-1">{pulse.description || "—"}</p>
                        <div className="flex items-center gap-2 mt-0.5 text-[10px]">
                          {pulse.indicatorCount && <span className="text-purple-400">{pulse.indicatorCount} indicators</span>}
                          {pulse.tags && pulse.tags.length > 0 && (
                            <span className="text-muted-foreground flex items-center gap-1"><Tag className="w-3 h-3" />{pulse.tags.slice(0, 3).join(", ")}</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )
              )}
            </div>

            {/* ─── Malware Bazaar (from bridge) ──────────────────────────── */}
            <div className="space-y-3">
              <button onClick={() => toggleSection("malware")} className="flex items-center justify-between w-full">
                <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Skull className="w-4 h-4 text-orange-400" /> MALWARE BAZAAR ({malwareBazaar?.data?.length ?? 0})
                  <span className="text-[10px] text-muted-foreground">abuse.ch</span>
                </h2>
                {expandedSections.malware ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSections.malware && (
                malwareLoading ? (
                  <div className="space-y-2">{[1,2,3].map(i => <div key={i} className="h-10 bg-muted animate-pulse rounded" />)}</div>
                ) : !malwareBazaar || malwareBazaar.data.length === 0 ? (
                  <div className="bg-card border border-border p-6 text-center">
                    <Skull className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-xs text-muted-foreground">No Malware Bazaar entries available.</p>
                  </div>
                ) : (
                  <div className="space-y-1 max-h-[300px] overflow-y-auto pr-1">
                    {malwareBazaar.data.slice(0, 30).map((entry: any, i: number) => (
                      <div key={i} className="bg-card border border-border p-2 flex items-center justify-between text-xs">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="font-mono text-muted-foreground truncate">{entry.sha256 || entry.sha256_hash || "—"}</span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          {entry.signature && <span className="text-[10px] text-orange-400">{entry.signature}</span>}
                          {entry.fileType && <span className="text-[10px] text-muted-foreground">{entry.fileType}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                )
              )}
            </div>
          </div>

          {/* ─── Sidebar (1/3) ───────────────────────────────────────────── */}
          <div className="space-y-6">

            {/* Activity Ratings */}
            {activityRatings && activityRatings.data.length > 0 && (
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-amber-400" /> ACTIVITY RATINGS
                  <span className="text-[10px] text-muted-foreground/60">LOCAL DB</span>
                </h3>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {activityRatings.data.slice(0, 15).map((r: any, i: number) => (
                    <div key={i} className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground truncate">{r.groupName || r.name || "—"}</span>
                      <div className="flex items-center gap-1.5">
                        <div className="w-12 h-1.5 bg-muted overflow-hidden">
                          <div className={`h-full ${(r.rating || r.score || 0) > 7 ? "bg-red-400" : (r.rating || r.score || 0) > 4 ? "bg-amber-400" : "bg-green-400"}`}
                            style={{ width: `${Math.min(100, ((r.rating || r.score || 0) / 10) * 100)}%` }} />
                        </div>
                        <span className="text-[10px] text-muted-foreground w-6 text-right">{r.rating || r.score || 0}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Ransomware Victim Stats */}
            {ransomwareVictimStats && ransomwareVictimStats.data.length > 0 && (
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <Skull className="w-4 h-4 text-red-400" /> VICTIM STATS BY GROUP
                  <span className="text-[10px] text-muted-foreground/60">LOCAL DB</span>
                </h3>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {ransomwareVictimStats.data.slice(0, 15).map((g: any, i: number) => (
                    <div key={i} className="flex items-center justify-between text-xs">
                      <span className="text-amber-400 truncate">{g.groupName}</span>
                      <span className="text-muted-foreground">{g.totalVictims ?? g.victimCount ?? 0} victims</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Adaptive Keywords */}
            {adaptiveKeywords && adaptiveKeywords.data.length > 0 && (
              <div className="bg-card border border-border p-4">
                <button onClick={() => toggleSection("keywords")} className="flex items-center justify-between w-full mb-3">
                  <h3 className="text-xs font-display tracking-wider text-muted-foreground flex items-center gap-2">
                    <Key className="w-4 h-4 text-emerald-400" /> ADAPTIVE KEYWORDS
                  </h3>
                  {expandedSections.keywords ? <ChevronUp className="w-3 h-3 text-muted-foreground" /> : <ChevronDown className="w-3 h-3 text-muted-foreground" />}
                </button>
                {expandedSections.keywords && (
                  <div className="flex flex-wrap gap-1.5">
                    {adaptiveKeywords.data.slice(0, 30).map((kw: any, i: number) => (
                      <span key={i} className="px-2 py-0.5 text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 tracking-wider">
                        {typeof kw === "string" ? kw : kw.keyword || kw.term || "—"}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

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
