import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { useState, useMemo } from "react";
import { Link } from "wouter";
import { toast } from "sonner";
import {
  Database,
  Search,
  RefreshCw,
  Shield,
  Skull,
  AlertTriangle,
  Globe2,
  ChevronRight,
  Clock,
  Target,
  Download,
  Loader2,
  Crosshair,
  Radio,
  Zap,
  Key,
  Megaphone,
} from "lucide-react";

type GroupType = "all" | "apt" | "ransomware" | "cybercrime" | "hacktivist" | "access_broker" | "influence_ops" | "unknown";
type SortBy = "name" | "threatLevel" | "lastActive" | "confidence";

const TYPE_CONFIG: Record<string, { icon: typeof Shield; color: string; bg: string; label: string }> = {
  apt: { icon: Shield, color: "text-red-400", bg: "bg-red-500/10 border-red-500/20", label: "APT / Nation-State" },
  ransomware: { icon: Skull, color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/20", label: "Ransomware" },
  cybercrime: { icon: AlertTriangle, color: "text-purple-400", bg: "bg-purple-500/10 border-purple-500/20", label: "Cybercrime" },
  hacktivist: { icon: Globe2, color: "text-cyan-400", bg: "bg-cyan-500/10 border-cyan-500/20", label: "Hacktivist" },
  access_broker: { icon: Key, color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/20", label: "Access Broker" },
  influence_ops: { icon: Megaphone, color: "text-pink-400", bg: "bg-pink-500/10 border-pink-500/20", label: "Influence Ops" },
  unknown: { icon: Zap, color: "text-gray-400", bg: "bg-gray-500/10 border-gray-500/20", label: "Unknown" },
};

const CONFIDENCE_COLORS: Record<string, string> = {
  high: "text-green-400",
  medium: "text-yellow-400",
  low: "text-red-400",
};

const THREAT_LEVEL_COLORS: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-green-400 bg-green-500/10 border-green-500/30",
};

export default function ThreatCatalog() {
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<GroupType>("all");
  const [sortBy, setSortBy] = useState<SortBy>("name");
  const [page, setPage] = useState(1);
  const [syncing, setSyncing] = useState(false);
  const [syncSource, setSyncSource] = useState<string | null>(null);

  const { data: stats } = trpc.threatIntel.stats.useQuery();
  const { data: listData, isLoading, refetch } = trpc.threatIntel.list.useQuery({
    type: typeFilter,
    search: search || undefined,
    page,
    pageSize: 60,
    sortBy,
    sortOrder: "asc",
  });

  const syncCatalog = trpc.threatIntel.syncCatalog.useMutation({
    onSuccess: (result: any) => {
      const totalNew = result.totalNew ?? result.results?.reduce((s: number, r: any) => s + (r.groupsIngested || 0), 0) ?? 0;
      const totalUpdated = result.totalUpdated ?? result.results?.reduce((s: number, r: any) => s + (r.groupsUpdated || 0), 0) ?? 0;
      toast.success(`Sync complete: ${totalNew} imported, ${totalUpdated} updated`);
      refetch();
      setSyncing(false);
      setSyncSource(null);
    },
    onError: (err: any) => {
      toast.error(`Sync failed: ${err.message}`);
      setSyncing(false);
      setSyncSource(null);
    },
  });

  const enrichActor = trpc.threatIntel.enrichActor.useMutation({
    onSuccess: () => {
      toast.success("Profile enriched via LLM");
      refetch();
    },
    onError: (err: any) => toast.error(`Enrichment failed: ${err.message}`),
  });

  const handleSync = (source: string) => {
    setSyncing(true);
    setSyncSource(source);
    if (source === "all") {
      syncCatalog.mutate({});
    } else {
      syncCatalog.mutate({ sources: [source as any] });
    }
  };

  const actors = listData?.actors ?? [];
  const total = listData?.total ?? 0;
  const totalPages = Math.ceil(total / 60);

  return (
    <AppShell activePath="/threat-catalog">
      <div className="max-w-[1600px] mx-auto space-y-6">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <Database className="w-8 h-8 text-primary" />
              <h1 className="text-2xl lg:text-3xl font-display tracking-wider">
                MASTER THREAT CATALOG
              </h1>
            </div>
            <p className="text-muted-foreground text-sm">
              Unified source of truth for all threat groups, actors, and adversary profiles across the platform
            </p>
          </div>

          {/* Sync Controls */}
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => handleSync("mitre-attack")}
              disabled={syncing}
              className="flex items-center gap-2 px-3 py-2 bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-display tracking-wider hover:bg-red-500/20 transition-colors disabled:opacity-50"
            >
              {syncing && syncSource === "mitre-attack" ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
              SYNC MITRE ATT&CK
            </button>
            <button
              onClick={() => handleSync("ransomware-live")}
              disabled={syncing}
              className="flex items-center gap-2 px-3 py-2 bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs font-display tracking-wider hover:bg-amber-500/20 transition-colors disabled:opacity-50"
            >
              {syncing && syncSource === "ransomware-live" ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
              SYNC RANSOMWARE.LIVE
            </button>
            <button
              onClick={() => handleSync("caldera")}
              disabled={syncing}
              className="flex items-center gap-2 px-3 py-2 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-display tracking-wider hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
            >
              {syncing && syncSource === "caldera" ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
              SYNC CALDERA
            </button>
            <button
              onClick={() => handleSync("all")}
              disabled={syncing}
              className="flex items-center gap-2 px-3 py-2 bg-primary/10 border border-primary/20 text-primary text-xs font-display tracking-wider hover:bg-primary/20 transition-colors disabled:opacity-50"
            >
              {syncing && syncSource === "all" ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
              SYNC ALL SOURCES
            </button>
          </div>
        </div>

        {/* Stats Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-9 gap-3">
          {[
            { label: "TOTAL ACTORS", value: stats?.totalActors ?? 0, icon: Database, color: "text-primary" },
            { label: "APT / NATION-STATE", value: stats?.byType?.apt ?? 0, icon: Shield, color: "text-red-400" },
            { label: "RANSOMWARE", value: stats?.byType?.ransomware ?? 0, icon: Skull, color: "text-amber-400" },
            { label: "CYBERCRIME", value: stats?.byType?.cybercrime ?? 0, icon: AlertTriangle, color: "text-purple-400" },
            { label: "HACKTIVIST", value: stats?.byType?.hacktivist ?? 0, icon: Globe2, color: "text-cyan-400" },
            { label: "ACCESS BROKERS", value: stats?.byType?.access_broker ?? 0, icon: Key, color: "text-orange-400" },
            { label: "INFLUENCE OPS", value: stats?.byType?.influence_ops ?? 0, icon: Megaphone, color: "text-pink-400" },
            { label: "CRITICAL THREAT", value: stats?.byThreatLevel?.critical ?? 0, icon: Target, color: "text-red-500" },
            { label: "LAST 24H UPDATES", value: stats?.recentUpdates ?? 0, icon: Clock, color: "text-green-400" },
          ].map((stat) => (
            <div key={stat.label} className="bg-card border border-border p-3">
              <div className="flex items-center gap-2 mb-1">
                <stat.icon className={`w-4 h-4 ${stat.color}`} />
                <span className="text-[10px] text-muted-foreground tracking-wider">{stat.label}</span>
              </div>
              <p className={`text-xl font-display ${stat.color}`}>{stat.value}</p>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              placeholder="Search threat groups by name, alias, or ID..."
              className="w-full pl-10 pr-4 py-2.5 bg-card border border-border text-sm focus:outline-none focus:border-primary/50 transition-colors"
            />
          </div>
          <div className="flex gap-2 flex-wrap">
            {(["all", "apt", "ransomware", "cybercrime", "hacktivist", "access_broker", "influence_ops"] as GroupType[]).map((type) => (
              <button
                key={type}
                onClick={() => { setTypeFilter(type); setPage(1); }}
                className={`px-3 py-2 text-xs font-display tracking-wider border transition-colors ${
                  typeFilter === type
                    ? "bg-primary/20 border-primary/50 text-primary"
                    : "bg-card border-border text-muted-foreground hover:text-foreground"
                }`}
              >
                {type === "all" ? "ALL" : type.toUpperCase()}
              </button>
            ))}
          </div>
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as SortBy)}
            className="px-3 py-2 bg-card border border-border text-sm text-muted-foreground focus:outline-none"
          >
            <option value="name">Sort: Name</option>
            <option value="threatLevel">Sort: Threat Level</option>
            <option value="confidence">Sort: Confidence</option>
            <option value="lastActive">Sort: Last Active</option>
          </select>
        </div>

        {/* Group Grid */}
        {isLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {Array.from({ length: 12 }).map((_, i) => (
              <div key={i} className="bg-card border border-border p-4 animate-pulse">
                <div className="h-5 bg-muted rounded w-2/3 mb-3" />
                <div className="h-3 bg-muted rounded w-full mb-2" />
                <div className="h-3 bg-muted rounded w-4/5" />
              </div>
            ))}
          </div>
        ) : actors.length === 0 ? (
          <div className="bg-card border border-border p-12 text-center">
            <Database className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-display tracking-wider mb-2">NO THREAT GROUPS FOUND</h3>
            <p className="text-muted-foreground text-sm mb-4">
              {search ? "No groups match your search criteria." : "The catalog is empty. Sync from external sources to populate it."}
            </p>
            {!search && (
              <button
                onClick={() => handleSync("all")}
                disabled={syncing}
                className="px-4 py-2 bg-primary text-primary-foreground text-sm font-display tracking-wider hover:bg-primary/90 transition-colors"
              >
                SYNC ALL SOURCES TO GET STARTED
              </button>
            )}
          </div>
        ) : (
          <>
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                Showing {actors.length} of {total} threat actor{total !== 1 ? "s" : ""}
                {totalPages > 1 && ` — Page ${page} of ${totalPages}`}
              </p>
              {totalPages > 1 && (
                <div className="flex gap-2">
                  <button
                    onClick={() => setPage(Math.max(1, page - 1))}
                    disabled={page <= 1}
                    className="px-3 py-1 text-xs bg-card border border-border disabled:opacity-30 hover:bg-accent/10 transition-colors"
                  >
                    PREV
                  </button>
                  <button
                    onClick={() => setPage(Math.min(totalPages, page + 1))}
                    disabled={page >= totalPages}
                    className="px-3 py-1 text-xs bg-card border border-border disabled:opacity-30 hover:bg-accent/10 transition-colors"
                  >
                    NEXT
                  </button>
                </div>
              )}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {actors.map((actor: any) => {
                const typeConf = TYPE_CONFIG[actor.type || "unknown"] || TYPE_CONFIG.unknown;
                const TypeIcon = typeConf.icon;
                const aliases: string[] = Array.isArray(actor.aliases) ? actor.aliases : [];
                const sectors: string[] = Array.isArray(actor.targetSectors) ? actor.targetSectors : [];
                const techniques: string[] = Array.isArray(actor.techniques) ? actor.techniques : [];
                const threatLevelClass = THREAT_LEVEL_COLORS[actor.threatLevel || "medium"] || THREAT_LEVEL_COLORS.medium;

                return (
                  <Link
                    key={actor.actorId}
                    href={`/threat-catalog/${actor.actorId}`}
                    className="block"
                  >
                    <div className={`bg-card border ${typeConf.bg} p-4 hover:bg-accent/5 transition-all cursor-pointer group h-full`}>
                      {/* Header */}
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-2 min-w-0">
                          <TypeIcon className={`w-5 h-5 ${typeConf.color} shrink-0`} />
                          <h3 className="font-display tracking-wider text-sm truncate">
                            {actor.name}
                          </h3>
                        </div>
                        <ChevronRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors shrink-0" />
                      </div>

                      {/* Type, Origin & Threat Level */}
                      <div className="flex items-center gap-2 mb-2 flex-wrap">
                        <span className={`text-[10px] px-2 py-0.5 border ${typeConf.bg} ${typeConf.color} tracking-wider`}>
                          {typeConf.label.toUpperCase()}
                        </span>
                        {actor.origin && (
                          <span className="text-[10px] px-2 py-0.5 bg-secondary text-muted-foreground tracking-wider">
                            {actor.origin.toUpperCase()}
                          </span>
                        )}
                        {actor.threatLevel && (
                          <span className={`text-[10px] px-2 py-0.5 border tracking-wider ${threatLevelClass}`}>
                            {actor.threatLevel.toUpperCase()}
                          </span>
                        )}
                        {actor.confidence != null && (
                          <span className={`text-[10px] tracking-wider ${actor.confidence >= 80 ? "text-green-400" : actor.confidence >= 50 ? "text-yellow-400" : "text-red-400"}`}>
                            {actor.confidence}% CONF
                          </span>
                        )}
                      </div>

                      {/* Description */}
                      {actor.description && (
                        <p className="text-xs text-muted-foreground line-clamp-2 mb-3">
                          {actor.description}
                        </p>
                      )}

                      {/* Aliases */}
                      {aliases.length > 0 && (
                        <div className="flex flex-wrap gap-1 mb-3">
                          {aliases.slice(0, 4).map((alias: string) => (
                            <span key={alias} className="text-[10px] px-1.5 py-0.5 bg-muted text-muted-foreground">
                              {alias}
                            </span>
                          ))}
                          {aliases.length > 4 && (
                            <span className="text-[10px] text-muted-foreground">+{aliases.length - 4} more</span>
                          )}
                        </div>
                      )}

                      {/* Footer Stats */}
                      <div className="flex items-center gap-4 text-[10px] text-muted-foreground border-t border-border/50 pt-2 mt-auto">
                        {techniques.length > 0 && (
                          <span className="flex items-center gap-1">
                            <Crosshair className="w-3 h-3" />
                            {techniques.length} TTPs
                          </span>
                        )}
                        {sectors.length > 0 && (
                          <span className="flex items-center gap-1">
                            <Target className="w-3 h-3" />
                            {sectors.length} sectors
                          </span>
                        )}
                        {actor.lastActive && (
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {actor.lastActive}
                          </span>
                        )}
                        {actor.dataSource && (
                          <span className="flex items-center gap-1 ml-auto">
                            <Radio className="w-3 h-3" />
                            {actor.dataSource}
                          </span>
                        )}
                      </div>
                    </div>
                  </Link>
                );
              })}
            </div>
            {/* Bottom Pagination */}
            {totalPages > 1 && (
              <div className="flex justify-center gap-2 pt-4">
                <button
                  onClick={() => setPage(Math.max(1, page - 1))}
                  disabled={page <= 1}
                  className="px-4 py-2 text-xs bg-card border border-border disabled:opacity-30 hover:bg-accent/10 transition-colors font-display tracking-wider"
                >
                  PREVIOUS
                </button>
                <span className="px-4 py-2 text-xs text-muted-foreground">
                  {page} / {totalPages}
                </span>
                <button
                  onClick={() => setPage(Math.min(totalPages, page + 1))}
                  disabled={page >= totalPages}
                  className="px-4 py-2 text-xs bg-card border border-border disabled:opacity-30 hover:bg-accent/10 transition-colors font-display tracking-wider"
                >
                  NEXT
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </AppShell>
  );
}
