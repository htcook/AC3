import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { useState, useMemo } from "react";
import { Link } from "wouter";
import {
  Swords,
  Shield,
  Skull,
  AlertTriangle,
  Globe2,
  Target,
  Clock,
  ChevronRight,
  Users,
  Activity,
  Crosshair,
  BarChart3,
  Zap,
  Key,
  Megaphone,
  TrendingUp,
} from "lucide-react";

/* ─── Conflict Definitions ─────────────────────────────────────────────── */
const CONFLICTS = [
  {
    id: "russia-ukraine",
    label: "Russia-Ukraine War",
    shortLabel: "RU-UA",
    color: "text-blue-400",
    bg: "bg-blue-500/10 border-blue-500/30",
    bgSolid: "bg-blue-500",
    accent: "border-blue-500",
    parties: ["Russia", "Ukraine", "Belarus"],
    description: "Ongoing cyber operations tied to the Russia-Ukraine conflict, including state-sponsored APTs, hacktivists, and influence operations from both sides.",
  },
  {
    id: "israel-hamas-iran",
    label: "Israel-Hamas/Iran Conflict",
    shortLabel: "IL-Hamas/IR",
    color: "text-amber-400",
    bg: "bg-amber-500/10 border-amber-500/30",
    bgSolid: "bg-amber-500",
    accent: "border-amber-500",
    parties: ["Israel", "Iran", "Palestine", "Lebanon"],
    description: "Cyber operations linked to the Israel-Hamas war and broader Iran-Israel tensions, including IRGC-linked APTs and hacktivist groups.",
  },
  {
    id: "china-taiwan",
    label: "China-Taiwan Tensions",
    shortLabel: "CN-TW",
    color: "text-red-400",
    bg: "bg-red-500/10 border-red-500/30",
    bgSolid: "bg-red-500",
    accent: "border-red-500",
    parties: ["China", "Taiwan"],
    description: "Chinese state-sponsored cyber espionage and pre-positioning operations targeting Taiwan and cross-strait interests.",
  },
  {
    id: "north-korea",
    label: "North Korea Cyber Ops",
    shortLabel: "DPRK",
    color: "text-purple-400",
    bg: "bg-purple-500/10 border-purple-500/30",
    bgSolid: "bg-purple-500",
    accent: "border-purple-500",
    parties: ["North Korea", "DPRK"],
    description: "DPRK-linked cyber operations focused on financial theft, espionage, and sanctions evasion through cryptocurrency heists and supply chain attacks.",
  },
  {
    id: "iran-us-gulf",
    label: "Iran-US/Gulf Tensions",
    shortLabel: "IR-US/Gulf",
    color: "text-emerald-400",
    bg: "bg-emerald-500/10 border-emerald-500/30",
    bgSolid: "bg-emerald-500",
    accent: "border-emerald-500",
    parties: ["Iran", "United States", "Saudi Arabia", "UAE"],
    description: "Iranian cyber operations targeting US infrastructure, Gulf states, and Western interests, often linked to IRGC and proxy groups.",
  },
];

const TYPE_ICONS: Record<string, typeof Shield> = {
  apt: Shield,
  ransomware: Skull,
  cybercrime: AlertTriangle,
  hacktivist: Globe2,
  access_broker: Key,
  influence_ops: Megaphone,
  unknown: Zap,
};

const TYPE_COLORS: Record<string, string> = {
  apt: "text-red-400",
  ransomware: "text-amber-400",
  cybercrime: "text-purple-400",
  hacktivist: "text-cyan-400",
  access_broker: "text-orange-400",
  influence_ops: "text-pink-400",
  unknown: "text-gray-400",
};

const THREAT_LEVEL_COLORS: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-green-400 bg-green-500/10 border-green-500/30",
};

export default function ConflictTheater() {
  const [selectedConflict, setSelectedConflict] = useState(CONFLICTS[0].id);
  const conflict = CONFLICTS.find(c => c.id === selectedConflict) || CONFLICTS[0];

  // Fetch actors for the selected conflict
  const { data: listData, isLoading } = trpc.threatIntel.list.useQuery({
    conflict: selectedConflict,
    pageSize: 200,
    sortBy: "lastActive",
    sortOrder: "desc",
  });

  const actors = listData?.actors || [];

  // Compute analytics from actors
  const analytics = useMemo(() => {
    if (!actors.length) return null;

    // Type breakdown
    const byType: Record<string, number> = {};
    actors.forEach((a: any) => {
      const t = a.type || a.actorType || "unknown";
      byType[t] = (byType[t] || 0) + 1;
    });

    // Threat level breakdown
    const byThreatLevel: Record<string, number> = {};
    actors.forEach((a: any) => {
      const tl = a.threatLevel || a.rwThreatLevel || "medium";
      byThreatLevel[tl] = (byThreatLevel[tl] || 0) + 1;
    });

    // Sector targeting
    const sectorCounts: Record<string, number> = {};
    actors.forEach((a: any) => {
      const sectors = Array.isArray(a.targetSectors) ? a.targetSectors : [];
      sectors.forEach((s: string) => {
        sectorCounts[s] = (sectorCounts[s] || 0) + 1;
      });
    });
    const topSectors = Object.entries(sectorCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

    // Origin breakdown
    const byOrigin: Record<string, number> = {};
    actors.forEach((a: any) => {
      const o = a.origin || "Unknown";
      byOrigin[o] = (byOrigin[o] || 0) + 1;
    });
    const topOrigins = Object.entries(byOrigin)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);

    // Activity timeline (by month from lastActive)
    const monthCounts: Record<string, number> = {};
    actors.forEach((a: any) => {
      if (a.lastActive) {
        const month = String(a.lastActive).substring(0, 7);
        if (month.match(/^\d{4}-\d{2}$/)) {
          monthCounts[month] = (monthCounts[month] || 0) + 1;
        }
      }
    });
    const activityTimeline = Object.entries(monthCounts)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .slice(-12);

    // Recently active (last 90 days)
    const now = new Date();
    const d90 = new Date(now.getTime() - 90 * 86400000);
    const d90Str = d90.toISOString().substring(0, 10);
    const recentlyActive = actors.filter((a: any) => a.lastActive && a.lastActive >= d90Str);

    // Top techniques
    const techCounts: Record<string, number> = {};
    actors.forEach((a: any) => {
      const techs = Array.isArray(a.techniques) ? a.techniques : [];
      techs.forEach((t: string) => {
        techCounts[t] = (techCounts[t] || 0) + 1;
      });
    });
    const topTechniques = Object.entries(techCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);

    return {
      total: actors.length,
      byType,
      byThreatLevel,
      topSectors,
      topOrigins,
      activityTimeline,
      recentlyActive: recentlyActive.length,
      topTechniques,
    };
  }, [actors]);

  // Find max for bar charts
  const maxSectorCount = analytics?.topSectors[0]?.[1] || 1;
  const maxTimelineCount = analytics?.activityTimeline.reduce((m, [, c]) => Math.max(m, c), 0) || 1;

  return (
    <AppShell title="CONFLICT THEATER" subtitle="Threat actor analytics by geopolitical conflict">
      <div className="space-y-6">
        {/* Conflict Selector */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {CONFLICTS.map(c => (
            <button
              key={c.id}
              onClick={() => setSelectedConflict(c.id)}
              className={`p-4 border text-left transition-all ${
                selectedConflict === c.id
                  ? `${c.bg} ${c.accent} border-2`
                  : "bg-card border-border hover:bg-accent/5"
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                <Swords className={`w-4 h-4 ${c.color}`} />
                <span className={`text-xs font-display tracking-wider ${selectedConflict === c.id ? c.color : "text-muted-foreground"}`}>
                  {c.shortLabel}
                </span>
              </div>
              <p className={`text-sm font-display tracking-wider ${selectedConflict === c.id ? "text-foreground" : "text-muted-foreground"}`}>
                {c.label}
              </p>
            </button>
          ))}
        </div>

        {/* Conflict Overview Banner */}
        <div className={`border-l-4 ${conflict.accent} bg-card border border-border p-4`}>
          <div className="flex items-start justify-between">
            <div>
              <h2 className={`text-lg font-display tracking-wider ${conflict.color} mb-1`}>
                {conflict.label}
              </h2>
              <p className="text-sm text-muted-foreground">{conflict.description}</p>
              <div className="flex gap-2 mt-2">
                {conflict.parties.map(p => (
                  <span key={p} className="text-[10px] px-2 py-0.5 bg-muted text-muted-foreground tracking-wider">
                    {p.toUpperCase()}
                  </span>
                ))}
              </div>
            </div>
            <div className="text-right shrink-0 ml-4">
              <p className={`text-3xl font-display ${conflict.color}`}>{analytics?.total ?? "—"}</p>
              <p className="text-[10px] text-muted-foreground tracking-wider">THREAT ACTORS</p>
            </div>
          </div>
        </div>

        {isLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="bg-card border border-border p-4 animate-pulse">
                <div className="h-5 bg-muted rounded w-2/3 mb-3" />
                <div className="h-8 bg-muted rounded w-1/2 mb-2" />
                <div className="h-3 bg-muted rounded w-full" />
              </div>
            ))}
          </div>
        ) : analytics ? (
          <>
            {/* Summary Stats */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-card border border-border p-4">
                <div className="flex items-center gap-2 mb-1">
                  <Users className={`w-4 h-4 ${conflict.color}`} />
                  <span className="text-[10px] text-muted-foreground tracking-wider">TOTAL ACTORS</span>
                </div>
                <p className={`text-2xl font-display ${conflict.color}`}>{analytics.total}</p>
              </div>
              <div className="bg-card border border-border p-4">
                <div className="flex items-center gap-2 mb-1">
                  <Activity className="w-4 h-4 text-green-400" />
                  <span className="text-[10px] text-muted-foreground tracking-wider">ACTIVE (90D)</span>
                </div>
                <p className="text-2xl font-display text-green-400">{analytics.recentlyActive}</p>
              </div>
              <div className="bg-card border border-border p-4">
                <div className="flex items-center gap-2 mb-1">
                  <AlertTriangle className="w-4 h-4 text-red-500" />
                  <span className="text-[10px] text-muted-foreground tracking-wider">CRITICAL THREAT</span>
                </div>
                <p className="text-2xl font-display text-red-500">{analytics.byThreatLevel.critical || 0}</p>
              </div>
              <div className="bg-card border border-border p-4">
                <div className="flex items-center gap-2 mb-1">
                  <Target className="w-4 h-4 text-cyan-400" />
                  <span className="text-[10px] text-muted-foreground tracking-wider">SECTORS TARGETED</span>
                </div>
                <p className="text-2xl font-display text-cyan-400">{analytics.topSectors.length}</p>
              </div>
            </div>

            {/* Main Analytics Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* Actor Type Breakdown */}
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-4 flex items-center gap-2">
                  <Shield className="w-3.5 h-3.5" />
                  ACTOR TYPE BREAKDOWN
                </h3>
                <div className="space-y-3">
                  {Object.entries(analytics.byType)
                    .sort((a, b) => b[1] - a[1])
                    .map(([type, count]) => {
                      const Icon = TYPE_ICONS[type] || Zap;
                      const color = TYPE_COLORS[type] || "text-gray-400";
                      const pct = Math.round((count / analytics.total) * 100);
                      return (
                        <div key={type}>
                          <div className="flex items-center justify-between mb-1">
                            <span className={`text-xs flex items-center gap-1.5 ${color}`}>
                              <Icon className="w-3 h-3" />
                              {type.replace(/_/g, " ").toUpperCase()}
                            </span>
                            <span className="text-xs text-muted-foreground">{count} ({pct}%)</span>
                          </div>
                          <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${conflict.bgSolid}`}
                              style={{ width: `${pct}%`, opacity: 0.7 }}
                            />
                          </div>
                        </div>
                      );
                    })}
                </div>
              </div>

              {/* Threat Level Distribution */}
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-4 flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  THREAT LEVEL DISTRIBUTION
                </h3>
                <div className="space-y-3">
                  {["critical", "high", "medium", "low"].map(level => {
                    const count = analytics.byThreatLevel[level] || 0;
                    const pct = analytics.total > 0 ? Math.round((count / analytics.total) * 100) : 0;
                    const cls = THREAT_LEVEL_COLORS[level] || "";
                    return (
                      <div key={level}>
                        <div className="flex items-center justify-between mb-1">
                          <span className={`text-xs tracking-wider px-2 py-0.5 border ${cls}`}>
                            {level.toUpperCase()}
                          </span>
                          <span className="text-xs text-muted-foreground">{count} ({pct}%)</span>
                        </div>
                        <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              level === "critical" ? "bg-red-500" :
                              level === "high" ? "bg-orange-500" :
                              level === "medium" ? "bg-yellow-500" : "bg-green-500"
                            }`}
                            style={{ width: `${pct}%`, opacity: 0.7 }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Origin Breakdown */}
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mt-6 mb-3 flex items-center gap-2">
                  <Globe2 className="w-3.5 h-3.5" />
                  ORIGIN BREAKDOWN
                </h3>
                <div className="space-y-2">
                  {analytics.topOrigins.map(([origin, count]) => (
                    <div key={origin} className="flex items-center justify-between">
                      <span className="text-xs text-muted-foreground">{origin}</span>
                      <span className={`text-xs font-display ${conflict.color}`}>{count}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Sector Targeting */}
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-4 flex items-center gap-2">
                  <Target className="w-3.5 h-3.5" />
                  TOP TARGETED SECTORS
                </h3>
                <div className="space-y-2">
                  {analytics.topSectors.map(([sector, count]) => (
                    <div key={sector}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs text-muted-foreground truncate mr-2">{sector}</span>
                        <span className={`text-xs font-display ${conflict.color} shrink-0`}>{count}</span>
                      </div>
                      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${conflict.bgSolid}`}
                          style={{ width: `${(count / maxSectorCount) * 100}%`, opacity: 0.6 }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Activity Timeline + Top TTPs */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Activity Timeline */}
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-4 flex items-center gap-2">
                  <BarChart3 className="w-3.5 h-3.5" />
                  ACTIVITY TIMELINE (LAST ACTIVE BY MONTH)
                </h3>
                {analytics.activityTimeline.length > 0 ? (
                  <div className="flex items-end gap-1 h-32">
                    {analytics.activityTimeline.map(([month, count]) => (
                      <div key={month} className="flex-1 flex flex-col items-center gap-1">
                        <span className="text-[9px] text-muted-foreground">{count}</span>
                        <div
                          className={`w-full rounded-t ${conflict.bgSolid}`}
                          style={{
                            height: `${(count / maxTimelineCount) * 100}%`,
                            minHeight: "4px",
                            opacity: 0.7,
                          }}
                        />
                        <span className="text-[8px] text-muted-foreground -rotate-45 origin-top-left whitespace-nowrap">
                          {month.substring(2)}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground">No activity timeline data available.</p>
                )}
              </div>

              {/* Top TTPs */}
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-4 flex items-center gap-2">
                  <Crosshair className="w-3.5 h-3.5" />
                  TOP TTPs ACROSS CONFLICT
                </h3>
                <div className="space-y-2">
                  {analytics.topTechniques.length > 0 ? analytics.topTechniques.map(([tech, count]) => (
                    <div key={tech} className="flex items-center justify-between">
                      <span className="text-xs text-muted-foreground truncate mr-2">{tech}</span>
                      <span className={`text-xs font-display ${conflict.color} shrink-0`}>{count} actors</span>
                    </div>
                  )) : (
                    <p className="text-xs text-muted-foreground">No TTP data available for this conflict.</p>
                  )}
                </div>
              </div>
            </div>

            {/* Actor List */}
            <div className="bg-card border border-border">
              <div className="p-4 border-b border-border flex items-center justify-between">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground flex items-center gap-2">
                  <Users className="w-3.5 h-3.5" />
                  THREAT ACTORS — {conflict.label.toUpperCase()} ({actors.length})
                </h3>
                <Link href={`/threat-catalog?conflict=${selectedConflict}`}>
                  <span className={`text-xs ${conflict.color} hover:underline cursor-pointer flex items-center gap-1`}>
                    View in Catalog <ChevronRight className="w-3 h-3" />
                  </span>
                </Link>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs" style={{ minWidth: "800px" }}>
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left p-3 text-muted-foreground font-display tracking-wider whitespace-nowrap">ACTOR</th>
                      <th className="text-left p-3 text-muted-foreground font-display tracking-wider whitespace-nowrap">TYPE</th>
                      <th className="text-left p-3 text-muted-foreground font-display tracking-wider whitespace-nowrap">ORIGIN</th>
                      <th className="text-left p-3 text-muted-foreground font-display tracking-wider whitespace-nowrap">THREAT</th>
                      <th className="text-left p-3 text-muted-foreground font-display tracking-wider whitespace-nowrap">LAST ACTIVE</th>
                      <th className="text-left p-3 text-muted-foreground font-display tracking-wider whitespace-nowrap">SECTORS</th>
                      <th className="text-left p-3 text-muted-foreground font-display tracking-wider whitespace-nowrap">TTPs</th>
                    </tr>
                  </thead>
                  <tbody>
                    {actors.slice(0, 50).map((actor: any) => {
                      const typeColor = TYPE_COLORS[actor.type || "unknown"] || "text-gray-400";
                      const TypeIcon = TYPE_ICONS[actor.type || "unknown"] || Zap;
                      const tlClass = THREAT_LEVEL_COLORS[actor.threatLevel || actor.rwThreatLevel || "medium"] || "";
                      const sectors = Array.isArray(actor.targetSectors) ? actor.targetSectors : [];
                      const techniques = Array.isArray(actor.techniques) ? actor.techniques : [];
                      return (
                        <tr key={actor.actorId} className="border-b border-border/50 hover:bg-accent/5 transition-colors">
                          <td className="p-3">
                            <Link href={`/threat-catalog/${actor.actorId}`}>
                              <span className="text-foreground hover:text-primary cursor-pointer font-display tracking-wider">
                                {actor.name}
                              </span>
                            </Link>
                          </td>
                          <td className="p-3">
                            <span className={`flex items-center gap-1 ${typeColor}`}>
                              <TypeIcon className="w-3 h-3" />
                              {(actor.type || "unknown").replace(/_/g, " ").toUpperCase()}
                            </span>
                          </td>
                          <td className="p-3 text-muted-foreground whitespace-nowrap">{actor.origin || "Unknown"}</td>
                          <td className="p-3">
                            <span className={`text-[10px] px-1.5 py-0.5 border tracking-wider ${tlClass}`}>
                              {(actor.threatLevel || actor.rwThreatLevel || "MEDIUM").toUpperCase()}
                            </span>
                          </td>
                          <td className="p-3 text-muted-foreground whitespace-nowrap">
                            {actor.lastActive || "—"}
                          </td>
                          <td className="p-3">
                            <div className="flex flex-wrap gap-1 max-w-[200px]">
                              {sectors.slice(0, 3).map((s: string) => (
                                <span key={s} className="text-[9px] px-1 py-0.5 bg-muted text-muted-foreground">
                                  {s}
                                </span>
                              ))}
                              {sectors.length > 3 && (
                                <span className="text-[9px] text-muted-foreground">+{sectors.length - 3}</span>
                              )}
                            </div>
                          </td>
                          <td className="p-3 text-muted-foreground">
                            {techniques.length > 0 ? `${techniques.length} TTPs` : "—"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              {actors.length > 50 && (
                <div className="p-3 text-center border-t border-border">
                  <Link href={`/threat-catalog?conflict=${selectedConflict}`}>
                    <span className={`text-xs ${conflict.color} hover:underline cursor-pointer`}>
                      View all {actors.length} actors in Threat Catalog →
                    </span>
                  </Link>
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="bg-card border border-border p-12 text-center">
            <Swords className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-display tracking-wider mb-2">NO ACTORS FOUND</h3>
            <p className="text-muted-foreground text-sm">
              No threat actors are currently tagged for this conflict.
            </p>
          </div>
        )}
      </div>
    </AppShell>
  );
}
