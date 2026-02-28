import { useState } from "react";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import {
  Shield, Skull, AlertTriangle, Globe2, Database, TrendingUp,
  ChevronRight, ChevronDown, ChevronUp, Activity, Zap, Eye,
  Target, Crosshair, Clock, RefreshCw, Loader2, ExternalLink,
  BarChart3, Users, Lock, Megaphone, Key, Bug, FileText, Layers, FileJson
} from "lucide-react";
import { Link } from "wouter";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 border-red-500/30 bg-red-500/10",
  high: "text-orange-400 border-orange-500/30 bg-orange-500/10",
  medium: "text-amber-400 border-amber-500/30 bg-amber-500/10",
  low: "text-green-400 border-green-500/30 bg-green-500/10",
};

function safeUpper(s: string | null | undefined): string {
  return (s || "").toUpperCase();
}

export default function ThreatIntelHub() {
  const [expandedSection, setExpandedSection] = useState<string | null>("ransomware");

  // Threat Intel stats
  const { data: tiStats } = trpc.threatIntel.stats.useQuery();
  const { data: ransomwareStats } = trpc.threatIntel.ransomwareStats.useQuery();
  const { data: ransomwareList } = trpc.threatIntel.ransomwareList.useQuery({ page: 1, pageSize: 20 });
  const { data: coverage } = trpc.threatIntel.techniqueCoverage.useQuery();
  const { data: recentEvents } = trpc.threatIntel.recentEvents.useQuery();

  // Darkweb Intel feeds (self-contained, no bridge dependency)
  const { data: cisaKEV, isLoading: kevLoading } = trpc.darkwebIntel.cisaKEV.useQuery({ limit: 15 });
  const { data: victimStats, isLoading: victimLoading } = trpc.darkwebIntel.ransomwareVictimStats.useQuery({ limit: 20 });
  const { data: escalations } = trpc.darkwebIntel.escalationAlerts.useQuery();
  const { data: activityRatings } = trpc.darkwebIntel.activityRatings.useQuery();
  const { data: accessBrokers, isLoading: iabLoading } = trpc.darkwebIntel.accessBrokers.useQuery();
  const { data: threatFox, isLoading: iocLoading } = trpc.darkwebIntel.threatFoxIOCs.useQuery({ limit: 15 });

  // Sync
  const syncAll = trpc.darkwebIntel.syncAll.useMutation();
  const syncCatalog = trpc.threatIntel.syncCatalog.useMutation();

  const toggle = (s: string) => setExpandedSection(expandedSection === s ? null : s);

  const totalActors = tiStats?.totalActors || 0;
  const ransomwareCount = ransomwareStats?.totalGroups || 0;
  const totalVictims = ransomwareStats?.totalVictims || 0;
  const activeKEV = cisaKEV?.data?.length || 0;
  const iabCount = accessBrokers?.length || 0;
  const iocCount = threatFox?.data?.length || 0;
  const escalationCount = escalations?.data?.length || 0;

  return (
    <AppShell>
      <div className="space-y-6 p-6">
        {/* ─── Header ─────────────────────────────────────────────── */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <h1 className="text-2xl font-display tracking-wider flex items-center gap-3">
              <Shield className="w-7 h-7 text-red-400" />
              THREAT INTELLIGENCE HUB
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Unified view of ransomware groups, darkweb monitoring, vulnerability feeds, and threat actor intelligence
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => { syncAll.mutate(); syncCatalog.mutate({}); }}
              disabled={syncAll.isPending || syncCatalog.isPending}
              className="flex items-center gap-2 px-3 py-2 text-xs font-display tracking-wider border border-red-500/30 bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors"
            >
              {(syncAll.isPending || syncCatalog.isPending) ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
              SYNC ALL FEEDS
            </button>
            <Link href="/stix-export">
              <button className="flex items-center gap-2 px-3 py-2 text-xs font-display tracking-wider border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition-colors">
                <FileJson className="w-3.5 h-3.5" />
                STIX EXPORT
              </button>
            </Link>
          </div>
        </div>

        {/* ─── Stats Bar ──────────────────────────────────────────── */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-7 gap-2 sm:gap-3">
          {[
            { label: "THREAT ACTORS", value: totalActors, icon: Users, color: "text-cyan-400", bg: "bg-cyan-500/10 border-cyan-500/20" },
            { label: "RANSOMWARE GROUPS", value: ransomwareCount, icon: Skull, color: "text-red-400", bg: "bg-red-500/10 border-red-500/20" },
            { label: "TOTAL VICTIMS", value: totalVictims, icon: Target, color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/20" },
            { label: "known exploited vulnerabilities (KEV)", value: activeKEV, icon: Shield, color: "text-red-400", bg: "bg-red-500/10 border-red-500/20" },
            { label: "ACCESS BROKERS", value: iabCount, icon: Key, color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/20" },
            { label: "THREATFOX IOCs", value: iocCount, icon: Bug, color: "text-purple-400", bg: "bg-purple-500/10 border-purple-500/20" },
            { label: "ESCALATIONS", value: escalationCount, icon: AlertTriangle, color: "text-red-400", bg: "bg-red-500/10 border-red-500/20" },
          ].map((s) => (
            <div key={s.label} className={`border p-3 ${s.bg}`}>
              <div className="flex items-center gap-2 mb-1">
                <s.icon className={`w-4 h-4 ${s.color}`} />
                <span className="text-[10px] font-display tracking-wider text-muted-foreground">{s.label}</span>
              </div>
              <span className={`text-2xl font-display ${s.color}`}>{s.value.toLocaleString()}</span>
            </div>
          ))}
        </div>

        {/* ─── Escalation Alerts ──────────────────────────────────── */}
        {escalations?.data && escalations.data.length > 0 && (
          <div className="border border-red-500/30 bg-red-500/5 p-4">
            <h2 className="text-sm font-display tracking-wider text-red-400 flex items-center gap-2 mb-3">
              <AlertTriangle className="w-4 h-4 animate-pulse" /> ACTIVE ESCALATION ALERTS ({escalations.data.length})
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {[...escalations.data].sort((a: any, b: any) => {
                const da = a.eventDate || a.timestamp ? new Date(a.eventDate || a.timestamp).getTime() : 0;
                const db2 = b.eventDate || b.timestamp ? new Date(b.eventDate || b.timestamp).getTime() : 0;
                return db2 - da;
              }).slice(0, 6).map((alert: any, i: number) => (
                <div key={i} className="border border-red-500/20 bg-card p-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-display text-red-400 tracking-wider">{alert.title || alert.type || "ALERT"}</span>
                    <span className={`text-[9px] px-1.5 py-0.5 border ${SEVERITY_COLORS[alert.severity || "high"]}`}>
                      {safeUpper(alert.severity || "HIGH")}
                    </span>
                  </div>
                  <p className="text-[11px] text-muted-foreground line-clamp-2">{alert.description || alert.message || "—"}</p>
                  {alert.timestamp && (
                    <span className="text-[10px] text-muted-foreground mt-1 block">
                      {new Date(alert.timestamp).toLocaleString()}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ─── Main Content Grid ──────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* ─── Left Column (2/3) ─────────────────────────────────── */}
          <div className="lg:col-span-2 space-y-6">

            {/* ─── Ransomware Groups Catalog ────────────────────────── */}
            <div className="border border-border bg-card">
              <button onClick={() => toggle("ransomware")} className="flex items-center justify-between w-full p-4">
                <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Skull className="w-5 h-5 text-red-400" /> RANSOMWARE GROUPS CATALOG
                  <span className="text-[10px] text-muted-foreground">({ransomwareCount} groups, {totalVictims.toLocaleString()} victims)</span>
                </h2>
                {expandedSection === "ransomware" ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSection === "ransomware" && (
                <div className="px-4 pb-4 space-y-3">
                  {/* Victim Stats by Group */}
                  {victimLoading ? (
                    <div className="flex items-center justify-center py-8"><Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /></div>
                  ) : victimStats?.data && victimStats.data.length > 0 ? (
                    <div className="space-y-2">
                      {/* Header row */}
                      <div className="grid grid-cols-12 gap-2 text-[10px] font-display tracking-wider text-muted-foreground px-2 pb-1 border-b border-border">
                        <span className="col-span-3">GROUP</span>
                        <span className="col-span-2 text-center">VICTIMS</span>
                        <span className="col-span-1 text-center">7D</span>
                        <span className="col-span-1 text-center">30D</span>
                        <span className="col-span-2 text-center">THREAT</span>
                        <span className="col-span-2 text-center">TREND</span>
                        <span className="col-span-1 text-center">SCORE</span>
                      </div>
                      {[...victimStats.data].sort((a: any, b: any) => {
                        // Sort by recent activity: 7d victims first, then 30d, then score
                        const a7 = a.victims7d || 0;
                        const b7 = b.victims7d || 0;
                        if (b7 !== a7) return b7 - a7;
                        return (b.activityScore || 0) - (a.activityScore || 0);
                      }).slice(0, 20).map((g: any, i: number) => (
                        <div key={i} className="grid grid-cols-12 gap-2 items-center px-2 py-1.5 hover:bg-muted/30 transition-colors text-xs">
                          <Link href={`/threat-catalog/${encodeURIComponent(g.groupName)}`} className="col-span-3 text-red-400 font-display tracking-wider hover:underline cursor-pointer truncate">
                            {safeUpper(g.groupName)}
                          </Link>
                          <span className="col-span-2 text-center font-mono">{(g.totalVictims || 0).toLocaleString()}</span>
                          <span className={`col-span-1 text-center font-mono ${(g.victims7d || 0) > 0 ? "text-red-400" : "text-muted-foreground"}`}>
                            {g.victims7d || 0}
                          </span>
                          <span className={`col-span-1 text-center font-mono ${(g.victims30d || 0) > 0 ? "text-orange-400" : "text-muted-foreground"}`}>
                            {g.victims30d || 0}
                          </span>
                          <span className="col-span-2 flex justify-center">
                            <span className={`text-[9px] px-1.5 py-0.5 border ${SEVERITY_COLORS[g.threatLevel || "medium"]}`}>
                              {safeUpper(g.threatLevel || "MEDIUM")}
                            </span>
                          </span>
                          <span className="col-span-2 flex justify-center">
                            <span className={`text-[10px] flex items-center gap-1 ${
                              g.trend === "increasing" ? "text-red-400" : g.trend === "decreasing" ? "text-green-400" : "text-muted-foreground"
                            }`}>
                              {g.trend === "increasing" ? <TrendingUp className="w-3 h-3" /> : g.trend === "decreasing" ? <TrendingUp className="w-3 h-3 rotate-180" /> : <Activity className="w-3 h-3" />}
                              {safeUpper(g.trend || "STABLE")}
                            </span>
                          </span>
                          <span className="col-span-1 text-center">
                            <span className={`font-mono text-[11px] ${(g.activityScore || 0) > 7 ? "text-red-400" : (g.activityScore || 0) > 4 ? "text-amber-400" : "text-green-400"}`}>
                              {g.activityScore || 0}
                            </span>
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <Skull className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                      <p className="text-xs text-muted-foreground">No ransomware group data. Click "Sync All Feeds" to populate.</p>
                    </div>
                  )}
                  <div className="flex justify-end pt-2">
                    <Link href="/threat-catalog" className="text-[10px] font-display tracking-wider text-cyan-400 hover:underline flex items-center gap-1">
                      VIEW FULL CATALOG <ChevronRight className="w-3 h-3" />
                    </Link>
                  </div>
                </div>
              )}
            </div>

            {/* ─── KEV & Active Vulnerabilities ───────────────── */}
            <div className="border border-border bg-card">
              <button onClick={() => toggle("kev")} className="flex items-center justify-between w-full p-4">
                <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Shield className="w-5 h-5 text-red-400" /> ACTIVE VULNERABILITY FEEDS
                  <span className="text-[10px] text-muted-foreground">(known exploited vulnerabilities (KEV) + malware indicator feeds IOCs)</span>
                </h2>
                {expandedSection === "kev" ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSection === "kev" && (
                <div className="px-4 pb-4 space-y-4">
                  {/* KEV */}
                  <div>
                    <h3 className="text-xs font-display tracking-wider text-red-400 mb-2 flex items-center gap-2">
                      <Shield className="w-3.5 h-3.5" /> CISA KNOWN EXPLOITED VULNERABILITIES
                    </h3>
                    {kevLoading ? (
                      <div className="space-y-2">{[1,2,3].map(i => <div key={i} className="h-10 bg-muted animate-pulse rounded" />)}</div>
                    ) : cisaKEV?.data && cisaKEV.data.length > 0 ? (
                      <div className="space-y-1 max-h-[300px] overflow-y-auto">
                        {[...cisaKEV.data].sort((a: any, b: any) => {
                        const da = a.dateAdded ? new Date(a.dateAdded).getTime() : 0;
                        const db2 = b.dateAdded ? new Date(b.dateAdded).getTime() : 0;
                        return db2 - da;
                      }).map((kev: any, i: number) => (
                          <div key={i} className="border border-border p-2 hover:bg-muted/30 transition-colors">
                            <div className="flex items-center justify-between mb-0.5">
                              <span className="font-mono text-xs text-red-400">{kev.cveId || kev.cveID || "—"}</span>
                              <div className="flex items-center gap-2">
                                {kev.knownRansomwareCampaignUse === "Known" && (
                                  <span className="text-[9px] px-1.5 py-0.5 bg-red-500/20 border border-red-500/30 text-red-400 animate-pulse">RANSOMWARE</span>
                                )}
                                <span className="text-[10px] text-muted-foreground">{kev.dateAdded ? new Date(kev.dateAdded).toLocaleDateString() : "—"}</span>
                              </div>
                            </div>
                            <p className="text-[11px] text-muted-foreground line-clamp-1">{kev.vulnerabilityName || kev.shortDescription || "—"}</p>
                            {kev.vendorProject && <span className="text-[10px] text-cyan-400">{kev.vendorProject} — {kev.product || ""}</span>}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-muted-foreground text-center py-4">No known exploited vulnerabilities (KEV) entries available.</p>
                    )}
                  </div>

                  {/* malware indicator feeds IOCs */}
                  <div>
                    <h3 className="text-xs font-display tracking-wider text-purple-400 mb-2 flex items-center gap-2">
                      <Bug className="w-3.5 h-3.5" /> THREATFOX INDICATORS OF COMPROMISE
                    </h3>
                    {iocLoading ? (
                      <div className="space-y-2">{[1,2,3].map(i => <div key={i} className="h-10 bg-muted animate-pulse rounded" />)}</div>
                    ) : threatFox?.data && threatFox.data.length > 0 ? (
                      <div className="space-y-1 max-h-[250px] overflow-y-auto">
                        {[...threatFox.data].sort((a: any, b: any) => {
                        const da = a.firstSeen ? new Date(a.firstSeen).getTime() : 0;
                        const db2 = b.firstSeen ? new Date(b.firstSeen).getTime() : 0;
                        return db2 - da;
                      }).slice(0, 15).map((ioc: any, i: number) => (
                          <div key={i} className="border border-border p-2 hover:bg-muted/30 transition-colors">
                            <div className="flex items-center justify-between">
                              <span className="font-mono text-[11px] text-purple-400 truncate max-w-[60%]">{ioc.ioc || ioc.indicator || "—"}</span>
                              <div className="flex items-center gap-2">
                                <span className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">{ioc.iocType || ioc.type || "—"}</span>
                                {ioc.malware && <span className="text-[9px] text-orange-400">{ioc.malware}</span>}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-muted-foreground text-center py-4">No malware indicator feeds IOCs available.</p>
                    )}
                  </div>

                  <div className="flex justify-between pt-2">
                    <Link href="/kev-dashboard" className="text-[10px] font-display tracking-wider text-cyan-400 hover:underline flex items-center gap-1">
                      KEV DASHBOARD <ExternalLink className="w-3 h-3" />
                    </Link>
                    <Link href="/darkweb-intel" className="text-[10px] font-display tracking-wider text-cyan-400 hover:underline flex items-center gap-1">
                      FULL DARKWEB INTEL <ChevronRight className="w-3 h-3" />
                    </Link>
                  </div>
                </div>
              )}
            </div>

            {/* ─── Access Brokers & Darkweb Monitoring ──────────────── */}
            <div className="border border-border bg-card">
              <button onClick={() => toggle("darkweb")} className="flex items-center justify-between w-full p-4">
                <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Eye className="w-5 h-5 text-amber-400" /> DARKWEB MONITORING
                  <span className="text-[10px] text-muted-foreground">({iabCount} brokers tracked)</span>
                </h2>
                {expandedSection === "darkweb" ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSection === "darkweb" && (
                <div className="px-4 pb-4 space-y-3">
                  {iabLoading ? (
                    <div className="flex items-center justify-center py-8"><Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /></div>
                  ) : accessBrokers && accessBrokers.length > 0 ? (
                    <div className="space-y-2 max-h-[400px] overflow-y-auto">
                      {[...accessBrokers].sort((a: any, b: any) => {
                        const da = a.postedAt ? new Date(a.postedAt).getTime() : a.createdAt ? new Date(a.createdAt).getTime() : 0;
                        const db2 = b.postedAt ? new Date(b.postedAt).getTime() : b.createdAt ? new Date(b.createdAt).getTime() : 0;
                        return db2 - da;
                      }).slice(0, 12).map((iab: any) => (
                        <div key={iab.id} className="border border-orange-500/20 bg-orange-500/5 p-3">
                          <div className="flex items-start justify-between">
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-display text-orange-400 tracking-wide">{safeUpper(iab.brokerName)}</span>
                                <span className={`text-[9px] px-1.5 py-0.5 border ${
                                  iab.status === "active" ? "text-green-400 border-green-500/30 bg-green-500/10"
                                  : iab.status === "law_enforcement" ? "text-blue-400 border-blue-500/30 bg-blue-500/10"
                                  : "text-muted-foreground border-border bg-muted/30"
                                }`}>{safeUpper(iab.status?.replace(/_/g, " ") || "UNKNOWN")}</span>
                              </div>
                              {iab.aliases && (iab.aliases as string[]).length > 0 && (
                                <p className="text-[10px] text-muted-foreground mt-0.5">AKA: {(iab.aliases as string[]).join(", ")}</p>
                              )}
                            </div>
                            <span className={`text-[9px] px-1.5 py-0.5 border ${
                              iab.brokerReputation === "established" ? "text-red-400 border-red-500/30 bg-red-500/10"
                              : iab.brokerReputation === "rising" ? "text-amber-400 border-amber-500/30 bg-amber-500/10"
                              : "text-muted-foreground border-border"
                            }`}>{safeUpper(iab.brokerReputation || "UNKNOWN")}</span>
                          </div>
                          <p className="text-[11px] text-muted-foreground leading-relaxed line-clamp-2 mt-1">{iab.description}</p>
                          <div className="flex flex-wrap gap-1.5 mt-1.5">
                            <span className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                              <Key className="w-2.5 h-2.5 inline mr-1" />{iab.accessType || "—"}
                            </span>
                            {iab.victimSector && (
                              <span className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                                <Target className="w-2.5 h-2.5 inline mr-1" />{iab.victimSector}
                              </span>
                            )}
                            {iab.linkedRansomwareGroups && (iab.linkedRansomwareGroups as string[]).length > 0 && (
                              (iab.linkedRansomwareGroups as string[]).map((g: string) => (
                                <span key={g} className="text-[9px] px-1 py-0.5 bg-red-500/10 border border-red-500/20 text-red-400">{g}</span>
                              ))
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <Eye className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                      <p className="text-xs text-muted-foreground">No access broker data. Click "Sync All Feeds" to populate.</p>
                    </div>
                  )}
                  <div className="flex justify-end pt-2">
                    <Link href="/darkweb-intel" className="text-[10px] font-display tracking-wider text-cyan-400 hover:underline flex items-center gap-1">
                      FULL DARKWEB INTEL <ChevronRight className="w-3 h-3" />
                    </Link>
                  </div>
                </div>
              )}
            </div>

            {/* ─── Recent Threat Events ─────────────────────────────── */}
            <div className="border border-border bg-card">
              <button onClick={() => toggle("events")} className="flex items-center justify-between w-full p-4">
                <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Clock className="w-5 h-5 text-blue-400" /> RECENT THREAT EVENTS
                </h2>
                {expandedSection === "events" ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSection === "events" && (
                <div className="px-4 pb-4">
                  {recentEvents && recentEvents.length > 0 ? (
                    <div className="space-y-2 max-h-[400px] overflow-y-auto">
                      {[...recentEvents].sort((a: any, b: any) => {
                        const da = a.eventDate || a.timestamp ? new Date(a.eventDate || a.timestamp).getTime() : 0;
                        const db2 = b.eventDate || b.timestamp ? new Date(b.eventDate || b.timestamp).getTime() : 0;
                        return db2 - da;
                      }).slice(0, 20).map((event: any, i: number) => (
                        <div key={i} className="border border-border p-2 hover:bg-muted/30 transition-colors">
                          <div className="flex items-center justify-between mb-0.5">
                            <span className="text-xs font-display tracking-wider">{event.title || event.type || "Event"}</span>
                            <div className="flex items-center gap-2">
                              <span className={`text-[9px] px-1.5 py-0.5 border ${SEVERITY_COLORS[event.severity || "medium"]}`}>
                                {safeUpper(event.severity || "MEDIUM")}
                              </span>
                              <span className="text-[10px] text-muted-foreground">
                                {event.timestamp ? new Date(event.timestamp).toLocaleDateString() : "—"}
                              </span>
                            </div>
                          </div>
                          <p className="text-[11px] text-muted-foreground line-clamp-2">{event.description || event.summary || "—"}</p>
                          {event.actors && event.actors.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-1">
                              {event.actors.map((a: string) => (
                                <span key={a} className="text-[9px] px-1 py-0.5 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">{a}</span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground text-center py-4">No recent threat events. Sync feeds to populate.</p>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* ─── Right Sidebar (1/3) ───────────────────────────────── */}
          <div className="space-y-6">

            {/* Quick Navigation */}
            <div className="border border-border bg-card p-4">
              <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                <Layers className="w-4 h-4 text-primary" /> QUICK NAVIGATION
              </h3>
              <div className="space-y-1.5">
                {[
                  { href: "/threat-catalog", icon: Database, label: "THREAT CATALOG", desc: "Full actor database", color: "text-cyan-400" },
                  { href: "/darkweb-intel", icon: AlertTriangle, label: "DARKWEB INTEL", desc: "Live feed monitoring", color: "text-red-400" },
                  { href: "/kev-dashboard", icon: Shield, label: "KEV DASHBOARD", desc: "Exploited vulnerabilities", color: "text-orange-400" },
                  { href: "/ioc-feed", icon: Bug, label: "IOC FEED", desc: "Indicators of compromise", color: "text-purple-400" },
                  { href: "/campaign-archetypes", icon: Crosshair, label: "ARCHETYPES", desc: "Attack patterns", color: "text-amber-400" },
                  { href: "/ttp-knowledge", icon: Zap, label: "TTP KNOWLEDGE", desc: "Techniques & procedures", color: "text-emerald-400" },
                  { href: "/phishing-exploit-catalog", icon: Lock, label: "PHISHING EXPLOITS", desc: "15 exploit techniques", color: "text-pink-400" },
                ].map((nav) => (
                  <Link key={nav.href} href={nav.href} className="flex items-center gap-3 p-2 hover:bg-muted/30 transition-colors cursor-pointer group">
                    <nav.icon className={`w-4 h-4 ${nav.color}`} />
                    <div className="min-w-0">
                      <span className="text-xs font-display tracking-wider group-hover:text-primary transition-colors">{nav.label}</span>
                      <p className="text-[10px] text-muted-foreground">{nav.desc}</p>
                    </div>
                    <ChevronRight className="w-3 h-3 text-muted-foreground ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
                  </Link>
                ))}
              </div>
            </div>

            {/* Activity Ratings */}
            {activityRatings && activityRatings.data && activityRatings.data.length > 0 && (
              <div className="border border-border bg-card p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-amber-400" /> ACTIVITY RATINGS
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

            {/* Technique Coverage */}
            {coverage?.topTechniques && coverage.topTechniques.length > 0 && (
              <div className="border border-border bg-card p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <Crosshair className="w-4 h-4 text-primary" /> TOP MITRE TECHNIQUES
                </h3>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {coverage.topTechniques.slice(0, 12).map((t: any) => (
                    <div key={t.id} className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="font-mono text-primary shrink-0">{t.id}</span>
                        <span className="text-muted-foreground truncate">{t.name}</span>
                      </div>
                      <span className="text-[10px] text-muted-foreground shrink-0">{t.actors?.length || 0} actors</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Tactic Distribution */}
            {coverage?.byTactic && coverage.byTactic.length > 0 && (
              <div className="border border-border bg-card p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-cyan-400" /> TACTIC DISTRIBUTION
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

            {/* Actor Type Distribution */}
            {tiStats?.byType && Object.keys(tiStats.byType).length > 0 && (
              <div className="border border-border bg-card p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <Users className="w-4 h-4 text-emerald-400" /> ACTOR DISTRIBUTION
                </h3>
                <div className="space-y-2">
                  {Object.entries(tiStats.byType).sort((a, b) => (b[1] as number) - (a[1] as number)).map(([type, count]) => (
                    <div key={type} className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground capitalize">{type.replace(/_/g, " ")}</span>
                      <span className="font-mono text-muted-foreground">{count as number}</span>
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
