import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { useState } from "react";
import { Link } from "wouter";
import { toast } from "sonner";
import {
  Skull, Search, TrendingUp, TrendingDown, Minus,
  AlertTriangle, ChevronRight, Users, Download,
  Loader2, Activity, Flame, Shield,
} from "lucide-react";

type TrendFilter = "all" | "surging" | "active" | "declining" | "dormant";
type SortBy = "activityScore" | "totalVictims" | "victims30d" | "groupName";

const TREND_CONFIG: Record<string, { icon: typeof TrendingUp; color: string; label: string }> = {
  surging: { icon: Flame, color: "text-red-500", label: "SURGING" },
  active: { icon: TrendingUp, color: "text-green-400", label: "ACTIVE" },
  declining: { icon: TrendingDown, color: "text-yellow-400", label: "DECLINING" },
  dormant: { icon: Minus, color: "text-gray-500", label: "DORMANT" },
};

const THREAT_LEVEL_COLORS: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-green-400 bg-green-500/10 border-green-500/30",
};

export default function RansomwareGroups() {
  const [search, setSearch] = useState("");
  const [trendFilter, setTrendFilter] = useState<TrendFilter>("all");
  const [sortBy, setSortBy] = useState<SortBy>("activityScore");
  const [page, setPage] = useState(1);

  const { data: stats } = trpc.threatIntel.ransomwareStats.useQuery();
  const { data: listData, isLoading, refetch } = trpc.threatIntel.ransomwareList.useQuery({
    trend: trendFilter, search: search || undefined, page, pageSize: 48, sortBy, sortOrder: "desc",
  });

  const syncCatalog = trpc.threatIntel.syncCatalog.useMutation({
    onSuccess: () => { toast.success("Ransomware data synced"); refetch(); },
    onError: (err) => toast.error(`Sync failed: ${err.message}`),
  });

  const groups = listData?.groups ?? [];
  const total = listData?.total ?? 0;
  const totalPages = Math.ceil(total / 48);

  return (
    <AppShell activePath="/ransomware-groups">
      <div className="max-w-[1600px] mx-auto space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <Skull className="w-8 h-8 text-amber-400" />
              <h1 className="text-2xl lg:text-3xl font-display tracking-wider">RANSOMWARE GROUPS</h1>
            </div>
            <p className="text-muted-foreground text-sm">
              Real-time ransomware group tracking with victim statistics, activity scoring, and infrastructure intelligence
            </p>
          </div>
          <button
            onClick={() => syncCatalog.mutate({ sources: ["ransomware-live"] })}
            disabled={syncCatalog.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs font-display tracking-wider hover:bg-amber-500/20 transition-colors disabled:opacity-50"
          >
            {syncCatalog.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
            SYNC RANSOMWARE.LIVE
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {[
            { label: "TOTAL GROUPS", value: stats?.totalGroups ?? 0, icon: Skull, color: "text-amber-400", border: "border-amber-500/20" },
            { label: "ACTIVE", value: stats?.activeGroups ?? 0, icon: Activity, color: "text-green-400", border: "border-green-500/20" },
            { label: "TOTAL VICTIMS", value: stats?.totalVictims ?? 0, icon: Users, color: "text-red-400", border: "border-red-500/20" },
            { label: "7D ATTACKS", value: stats?.recentAttacks7d ?? 0, icon: AlertTriangle, color: "text-orange-400", border: "border-orange-500/20" },
            { label: "SURGING", value: stats?.surgingGroups?.length ?? 0, icon: Flame, color: "text-red-500", border: "border-red-500/20" },
          ].map(s => (
            <div key={s.label} className={`bg-card border ${s.border} p-3`}>
              <div className="flex items-center gap-2 mb-1">
                <s.icon className={`w-4 h-4 ${s.color}`} />
                <span className="text-[10px] text-muted-foreground tracking-wider">{s.label}</span>
              </div>
              <p className={`text-xl font-display ${s.color}`}>{s.value}</p>
            </div>
          ))}
        </div>

        {/* Surging Alert */}
        {stats?.surgingGroups && stats.surgingGroups.length > 0 && (
          <div className="bg-red-500/5 border border-red-500/20 p-4">
            <h3 className="text-xs font-display tracking-wider text-red-400 mb-3 flex items-center gap-2">
              <Flame className="w-4 h-4" /> SURGING THREAT GROUPS
            </h3>
            <div className="flex flex-wrap gap-3">
              {stats.surgingGroups.map((g: any) => (
                <div key={g.name} className="bg-red-500/10 border border-red-500/20 px-3 py-2">
                  <span className="text-sm font-display text-red-400">{g.name}</span>
                  <div className="flex items-center gap-3 text-[10px] text-muted-foreground mt-1">
                    <span>Score: {g.activityScore}</span>
                    <span>30d: {g.victims30d}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Filters */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input type="text" value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              placeholder="Search ransomware groups..."
              className="w-full pl-10 pr-4 py-2.5 bg-card border border-border text-sm focus:outline-none focus:border-amber-500/50 transition-colors" />
          </div>
          <div className="flex gap-2 flex-wrap">
            {(["all", "surging", "active", "declining", "dormant"] as TrendFilter[]).map(t => (
              <button key={t} onClick={() => { setTrendFilter(t); setPage(1); }}
                className={`px-3 py-2 text-xs font-display tracking-wider border transition-colors ${
                  trendFilter === t ? "bg-amber-500/20 border-amber-500/50 text-amber-400"
                    : "bg-card border-border text-muted-foreground hover:text-foreground"}`}>
                {t.toUpperCase()}
              </button>
            ))}
          </div>
          <select value={sortBy} onChange={(e) => setSortBy(e.target.value as SortBy)}
            className="px-3 py-2 bg-card border border-border text-sm text-muted-foreground focus:outline-none">
            <option value="activityScore">Sort: Activity Score</option>
            <option value="totalVictims">Sort: Total Victims</option>
            <option value="victims30d">Sort: 30D Victims</option>
            <option value="groupName">Sort: Name</option>
          </select>
        </div>

        {/* Grid */}
        {isLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {Array.from({ length: 12 }).map((_, i) => (
              <div key={i} className="bg-card border border-border p-4 animate-pulse">
                <div className="h-5 bg-muted rounded w-2/3 mb-3" />
                <div className="h-3 bg-muted rounded w-full mb-2" />
              </div>
            ))}
          </div>
        ) : groups.length === 0 ? (
          <div className="bg-card border border-border p-12 text-center">
            <Skull className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-display tracking-wider mb-2">NO RANSOMWARE GROUPS FOUND</h3>
            <p className="text-muted-foreground text-sm">{search ? "No groups match your search." : "Sync from Ransomware.live to populate."}</p>
          </div>
        ) : (
          <>
            <p className="text-xs text-muted-foreground">
              Showing {groups.length} of {total} groups{totalPages > 1 && ` — Page ${page} of ${totalPages}`}
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {groups.map((g: any) => {
                const trendConf = TREND_CONFIG[g.trend || "active"] || TREND_CONFIG.active;
                const TrendIcon = trendConf.icon;
                const threatClass = THREAT_LEVEL_COLORS[g.threatLevel || "medium"] || THREAT_LEVEL_COLORS.medium;
                const sectors: string[] = Array.isArray(g.topSectors) ? g.topSectors : [];
                const countries: string[] = Array.isArray(g.topCountries) ? g.topCountries : [];
                return (
                  <Link key={g.groupName} href={`/ransomware-groups/${encodeURIComponent(g.groupName)}`} className="block">
                    <div className="bg-card border border-amber-500/10 p-4 hover:border-amber-500/30 hover:bg-accent/5 transition-all cursor-pointer group h-full">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <Skull className="w-5 h-5 text-amber-400 shrink-0" />
                          <h3 className="font-display tracking-wider text-sm">{g.groupName}</h3>
                        </div>
                        <div className="flex items-center gap-2">
                          <TrendIcon className={`w-4 h-4 ${trendConf.color}`} />
                          <ChevronRight className="w-4 h-4 text-muted-foreground group-hover:text-amber-400 transition-colors" />
                        </div>
                      </div>
                      <div className="flex items-center gap-2 mb-3 flex-wrap">
                        <span className={`text-[10px] px-2 py-0.5 ${trendConf.color} tracking-wider`}>{trendConf.label}</span>
                        <span className={`text-[10px] px-2 py-0.5 border tracking-wider ${threatClass}`}>{(g.threatLevel || "MEDIUM").toUpperCase()}</span>
                        {g.extortionModel && g.extortionModel !== "unknown" && (
                          <span className="text-[10px] px-2 py-0.5 bg-secondary text-muted-foreground tracking-wider">{g.extortionModel.toUpperCase()} EXTORTION</span>
                        )}
                        {g.affiliateProgram && <span className="text-[10px] px-2 py-0.5 bg-purple-500/10 text-purple-400 tracking-wider">RAAS</span>}
                      </div>
                      {g.description && <p className="text-xs text-muted-foreground line-clamp-2 mb-3">{g.description}</p>}
                      <div className="grid grid-cols-3 gap-2 mb-3">
                        <div className="text-center">
                          <p className="text-lg font-display text-amber-400">{g.activityScore || 0}</p>
                          <span className="text-[10px] text-muted-foreground">SCORE</span>
                        </div>
                        <div className="text-center">
                          <p className="text-lg font-display text-red-400">{g.totalVictims || 0}</p>
                          <span className="text-[10px] text-muted-foreground">VICTIMS</span>
                        </div>
                        <div className="text-center">
                          <p className="text-lg font-display text-orange-400">{g.victims30d || 0}</p>
                          <span className="text-[10px] text-muted-foreground">30D</span>
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-1 border-t border-border/50 pt-2">
                        {sectors.slice(0, 3).map((s: string) => (
                          <span key={s} className="text-[10px] px-1.5 py-0.5 bg-muted text-muted-foreground">{s}</span>
                        ))}
                        {countries.slice(0, 2).map((c: string) => (
                          <span key={c} className="text-[10px] px-1.5 py-0.5 bg-blue-500/10 text-blue-400">{c}</span>
                        ))}
                      </div>
                    </div>
                  </Link>
                );
              })}
            </div>
            {totalPages > 1 && (
              <div className="flex justify-center gap-2 pt-4">
                <button onClick={() => setPage(Math.max(1, page - 1))} disabled={page <= 1}
                  className="px-4 py-2 text-xs bg-card border border-border disabled:opacity-30 hover:bg-accent/10 transition-colors font-display tracking-wider">PREVIOUS</button>
                <span className="px-4 py-2 text-xs text-muted-foreground">{page} / {totalPages}</span>
                <button onClick={() => setPage(Math.min(totalPages, page + 1))} disabled={page >= totalPages}
                  className="px-4 py-2 text-xs bg-card border border-border disabled:opacity-30 hover:bg-accent/10 transition-colors font-display tracking-wider">NEXT</button>
              </div>
            )}
          </>
        )}
      </div>
    </AppShell>
  );
}
