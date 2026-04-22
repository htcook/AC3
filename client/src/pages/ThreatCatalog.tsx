import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { safeUpper } from "@/lib/utils-safe";
import { useState, useMemo, useCallback } from "react";
import { Link, useSearch, useLocation } from "wouter";
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
  FileJson,
  Crosshair,
  Radio,
  Zap,
  Key,
  Megaphone,
  Swords,
  Sparkles,
  FileText,
  FileDown,
} from "lucide-react";

type GroupType = "all" | "apt" | "ransomware" | "cybercrime" | "hacktivist" | "access_broker" | "influence_ops" | "unknown";
type SortBy = "name" | "threatLevel" | "lastActive" | "confidence";
type LastActiveFilter = "all" | "30d" | "90d" | "6m" | "1y" | "stale";
type ThreatLevelFilter = "all" | "critical" | "high" | "medium" | "low";

const CONFLICT_OPTIONS = [
  { id: "all", label: "All Conflicts", color: "" },
  { id: "russia-ukraine", label: "Russia-Ukraine", color: "text-blue-400 bg-blue-500/10 border-blue-500/30" },
  { id: "israel-hamas-iran", label: "Israel-Hamas/Iran", color: "text-amber-400 bg-amber-500/10 border-amber-500/30" },
  { id: "china-taiwan", label: "China-Taiwan", color: "text-red-400 bg-red-500/10 border-red-500/30" },
  { id: "north-korea", label: "North Korea", color: "text-purple-400 bg-purple-500/10 border-purple-500/30" },
  { id: "iran-us-gulf", label: "Iran-US/Gulf", color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30" },
] as const;

const CONFLICT_COLOR_MAP: Record<string, string> = {
  "russia-ukraine": "text-blue-400 bg-blue-500/10 border-blue-500/20",
  "israel-hamas-iran": "text-amber-400 bg-amber-500/10 border-amber-500/20",
  "china-taiwan": "text-red-400 bg-red-500/10 border-red-500/20",
  "north-korea": "text-purple-400 bg-purple-500/10 border-purple-500/20",
  "iran-us-gulf": "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
};

const CONFLICT_LABEL_MAP: Record<string, string> = {
  "russia-ukraine": "RU-UA",
  "israel-hamas-iran": "IL-Hamas/IR",
  "china-taiwan": "CN-TW",
  "north-korea": "DPRK",
  "iran-us-gulf": "IR-US/Gulf",
};

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

/** Parse URL search params into filter state */
function parseFiltersFromURL(searchString: string) {
  const p = new URLSearchParams(searchString);
  return {
    search: p.get("q") || "",
    type: (p.get("type") || "all") as GroupType,
    sortBy: (p.get("sort") || "lastActive") as SortBy,
    page: parseInt(p.get("page") || "1", 10) || 1,
    lastActive: (p.get("activity") || "all") as LastActiveFilter,
    threatLevel: (p.get("threat") || "all") as ThreatLevelFilter,
    conflict: p.get("conflict") || "all",
    statCard: p.get("card") || null,
    updatedLast24h: p.get("last24h") === "1",
  };
}

/** Build URL search string from filter state (omits defaults) */
function buildFilterURL(filters: {
  search?: string; type?: string; sortBy?: string; page?: number;
  lastActive?: string; threatLevel?: string; conflict?: string;
  statCard?: string | null; updatedLast24h?: boolean;
}): string {
  const p = new URLSearchParams();
  if (filters.search) p.set("q", filters.search);
  if (filters.type && filters.type !== "all") p.set("type", filters.type);
  if (filters.sortBy && filters.sortBy !== "lastActive") p.set("sort", filters.sortBy);
  if (filters.page && filters.page > 1) p.set("page", String(filters.page));
  if (filters.lastActive && filters.lastActive !== "all") p.set("activity", filters.lastActive);
  if (filters.threatLevel && filters.threatLevel !== "all") p.set("threat", filters.threatLevel);
  if (filters.conflict && filters.conflict !== "all") p.set("conflict", filters.conflict);
  if (filters.statCard) p.set("card", filters.statCard);
  if (filters.updatedLast24h) p.set("last24h", "1");
  const s = p.toString();
  return s ? `?${s}` : "";
}

export default function ThreatCatalog() {
  const searchString = useSearch();
  const [, navigate] = useLocation();
  const urlFilters = useMemo(() => parseFiltersFromURL(searchString), [searchString]);

  // Derive state from URL
  const search = urlFilters.search;
  const typeFilter = urlFilters.type;
  const sortBy = urlFilters.sortBy;
  const page = urlFilters.page;
  const lastActiveFilter = urlFilters.lastActive;
  const threatLevelFilter = urlFilters.threatLevel;
  const conflictFilter = urlFilters.conflict;
  const activeStatCard = urlFilters.statCard;
  const updatedLast24h = urlFilters.updatedLast24h;

  const [syncing, setSyncing] = useState(false);
  const [syncSource, setSyncSource] = useState<string | null>(null);
  const [exportingCsv, setExportingCsv] = useState(false);
  const [exportingStix, setExportingStix] = useState(false);
  const [showBulkEnrich, setShowBulkEnrich] = useState(false);
  const [bulkEnriching, setBulkEnriching] = useState(false);
  const [bulkProgress, setBulkProgress] = useState<{ current: number; total: number; results: any[] } | null>(null);

  /** Update URL params — merges new values with current state */
  const updateFilters = useCallback((updates: Record<string, any>) => {
    const merged = {
      search: updates.search !== undefined ? updates.search : urlFilters.search,
      type: updates.type !== undefined ? updates.type : urlFilters.type,
      sortBy: updates.sortBy !== undefined ? updates.sortBy : urlFilters.sortBy,
      page: updates.page !== undefined ? updates.page : urlFilters.page,
      lastActive: updates.lastActive !== undefined ? updates.lastActive : urlFilters.lastActive,
      threatLevel: updates.threatLevel !== undefined ? updates.threatLevel : urlFilters.threatLevel,
      conflict: updates.conflict !== undefined ? updates.conflict : urlFilters.conflict,
      statCard: updates.statCard !== undefined ? updates.statCard : urlFilters.statCard,
      updatedLast24h: updates.updatedLast24h !== undefined ? updates.updatedLast24h : urlFilters.updatedLast24h,
    };
    navigate("/threat-catalog" + buildFilterURL(merged), { replace: true });
  }, [urlFilters, navigate]);

  const { data: stats } = trpc.threatIntel.stats.useQuery();
  const { data: listData, isLoading, refetch } = trpc.threatIntel.list.useQuery({
    type: typeFilter,
    search: search || undefined,
    conflict: conflictFilter !== "all" ? conflictFilter : undefined,
    threatLevel: threatLevelFilter !== "all" ? threatLevelFilter : undefined,
    updatedLast24h: updatedLast24h || undefined,
    page,
    pageSize: 60,
    sortBy,
    sortOrder: sortBy === "lastActive" ? "desc" : "asc",
  });

  /** Handle stat card click — sets appropriate filters */
  const handleStatCardClick = (label: string) => {
    const clearAll = { type: "all", threatLevel: "all", lastActive: "all", updatedLast24h: false, page: 1, statCard: null as string | null };
    // If clicking the already-active card, clear it
    if (activeStatCard === label) {
      updateFilters(clearAll);
      return;
    }
    if (label === "TOTAL ACTORS") {
      updateFilters(clearAll);
      return;
    }
    const base = { ...clearAll, statCard: label };
    switch (label) {
      case "APT / NATION-STATE": updateFilters({ ...base, type: "apt" }); break;
      case "RANSOMWARE": updateFilters({ ...base, type: "ransomware" }); break;
      case "CYBERCRIME": updateFilters({ ...base, type: "cybercrime" }); break;
      case "HACKTIVIST": updateFilters({ ...base, type: "hacktivist" }); break;
      case "ACCESS BROKERS": updateFilters({ ...base, type: "access_broker" }); break;
      case "INFLUENCE OPS": updateFilters({ ...base, type: "influence_ops" }); break;
      case "CRITICAL THREAT": updateFilters({ ...base, threatLevel: "critical" }); break;
      case "LAST 24H UPDATES": updateFilters({ ...base, updatedLast24h: true, sortBy: "lastActive" }); break;
    }
  };

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
      toast.error(`Sync failed: ${sanitizeErrorForToast(err)}`);
      setSyncing(false);
      setSyncSource(null);
    },
  });

  const enrichActor = trpc.threatIntel.enrichActor.useMutation({
    onSuccess: () => {
      toast.success("Profile enriched via LLM");
      refetch();
    },
    onError: (err: any) => toast.error(`Enrichment failed: ${sanitizeErrorForToast(err)}`),
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

  // Export queries (enabled on demand)
  const exportCsvQuery = trpc.threatIntel.exportCsv.useQuery({
    type: typeFilter !== 'all' ? typeFilter : 'all',
    threatLevel: threatLevelFilter !== 'all' ? threatLevelFilter : 'all',
    updatedLast24h: updatedLast24h || undefined,
    conflict: conflictFilter !== 'all' ? conflictFilter : undefined,
    search: search || undefined,
  }, { enabled: false });

  const exportStixQuery = trpc.threatIntel.exportStix.useQuery({
    type: typeFilter !== 'all' ? typeFilter : 'all',
    threatLevel: threatLevelFilter !== 'all' ? threatLevelFilter : 'all',
    updatedLast24h: updatedLast24h || undefined,
    conflict: conflictFilter !== 'all' ? conflictFilter : undefined,
    search: search || undefined,
  }, { enabled: false });

  const incompleteQuery = trpc.threatIntel.incompleteActors.useQuery({ threshold: 60, limit: 50 }, { enabled: showBulkEnrich });
  const bulkEnrichMutation = trpc.threatIntel.bulkEnrich.useMutation({
    onSuccess: (result) => {
      toast.success(`Bulk enrichment complete: ${result.succeeded} succeeded, ${result.failed} failed`);
      setBulkEnriching(false);
      refetch();
    },
    onError: (err: any) => {
      toast.error(`Bulk enrichment failed: ${sanitizeErrorForToast(err)}`);
      setBulkEnriching(false);
    },
  });

  const handleExportCsv = async () => {
    setExportingCsv(true);
    try {
      const result = await exportCsvQuery.refetch();
      if (result.data?.csv) {
        const blob = new Blob([result.data.csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `threat-actors-${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success(`Exported ${result.data.count} actors to CSV`);
      }
    } catch (err: any) {
      toast.error(`CSV export failed: ${sanitizeErrorForToast(err)}`);
    }
    setExportingCsv(false);
  };

  const handleExportStix = async () => {
    setExportingStix(true);
    try {
      const result = await exportStixQuery.refetch();
      if (result.data?.stix) {
        const blob = new Blob([result.data.stix], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `threat-actors-stix-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success(`Exported ${result.data.actorCount} actors (${result.data.objectCount} STIX objects)`);
      }
    } catch (err: any) {
      toast.error(`STIX export failed: ${sanitizeErrorForToast(err)}`);
    }
    setExportingStix(false);
  };

  const handleBulkEnrich = (actorIds: string[]) => {
    setBulkEnriching(true);
    bulkEnrichMutation.mutate({ actorIds });
  };

  const allActors = listData?.actors ?? [];
  const total = listData?.total ?? 0;

  // Client-side lastActive recency filter
  const actors = useMemo(() => {
    if (lastActiveFilter === "all") return allActors;
    const now = new Date();
    return allActors.filter((actor: any) => {
      if (!actor.lastActive) return lastActiveFilter === "stale";
      // Normalize lastActive to a comparable date
      const la = String(actor.lastActive).trim();
      let actorDate: Date | null = null;
      // Handle YYYY-MM format
      if (/^\d{4}-\d{2}$/.test(la)) {
        actorDate = new Date(la + "-15"); // mid-month
      } else if (/^\d{4}-\d{2}-\d{2}/.test(la)) {
        actorDate = new Date(la);
      } else {
        actorDate = new Date(la);
      }
      if (isNaN(actorDate.getTime())) return lastActiveFilter === "stale";
      const diffMs = now.getTime() - actorDate.getTime();
      const diffDays = diffMs / (1000 * 60 * 60 * 24);
      switch (lastActiveFilter) {
        case "30d": return diffDays <= 30;
        case "90d": return diffDays <= 90;
        case "6m": return diffDays <= 183;
        case "1y": return diffDays <= 365;
        case "stale": return diffDays > 365 || !actor.lastActive;
        default: return true;
      }
    });
  }, [allActors, lastActiveFilter]);

  const totalPages = Math.ceil(total / 60);

  /** Format lastActive for display with recency color */
  function formatLastActive(la: string | null | undefined): { text: string; colorClass: string; isRecent: boolean } {
    if (!la) return { text: "UNKNOWN", colorClass: "text-gray-500", isRecent: false };
    const s = String(la).trim();
    let d: Date | null = null;
    let displayText = s;
    if (/^\d{4}-\d{2}$/.test(s)) {
      d = new Date(s + "-15");
      displayText = s;
    } else if (/^\d{4}-\d{2}-\d{2}/.test(s)) {
      d = new Date(s);
      displayText = s.substring(0, 10);
    } else {
      d = new Date(s);
      if (!isNaN(d.getTime())) {
        displayText = d.toISOString().substring(0, 7); // YYYY-MM
      }
    }
    if (!d || isNaN(d.getTime())) return { text: s.substring(0, 10), colorClass: "text-gray-500", isRecent: false };
    const diffDays = (Date.now() - d.getTime()) / (1000 * 60 * 60 * 24);
    if (diffDays <= 30) return { text: displayText, colorClass: "text-green-400", isRecent: true };
    if (diffDays <= 90) return { text: displayText, colorClass: "text-emerald-400", isRecent: false };
    if (diffDays <= 183) return { text: displayText, colorClass: "text-yellow-400", isRecent: false };
    if (diffDays <= 365) return { text: displayText, colorClass: "text-orange-400", isRecent: false };
    return { text: displayText, colorClass: "text-red-400", isRecent: false };
  }

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
              SYNC EMULATION
            </button>
            <button
              onClick={() => handleSync("all")}
              disabled={syncing}
              className="flex items-center gap-2 px-3 py-2 bg-primary/10 border border-primary/20 text-primary text-xs font-display tracking-wider hover:bg-primary/20 transition-colors disabled:opacity-50"
            >
              {syncing && syncSource === "all" ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
              SYNC ALL SOURCES
            </button>
            <Link href="/stix-export">
              <button className="flex items-center gap-2 px-3 py-2 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-display tracking-wider hover:bg-emerald-500/20 transition-colors">
                <FileJson className="w-3 h-3" />
                STIX EXPORT
              </button>
            </Link>
            <button
              onClick={() => handleExportCsv()}
              disabled={exportingCsv}
              className="flex items-center gap-2 px-3 py-2 bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-display tracking-wider hover:bg-blue-500/20 transition-colors disabled:opacity-50"
            >
              {exportingCsv ? <Loader2 className="w-3 h-3 animate-spin" /> : <FileDown className="w-3 h-3" />}
              EXPORT CSV
            </button>
            <button
              onClick={() => handleExportStix()}
              disabled={exportingStix}
              className="flex items-center gap-2 px-3 py-2 bg-teal-500/10 border border-teal-500/20 text-teal-400 text-xs font-display tracking-wider hover:bg-teal-500/20 transition-colors disabled:opacity-50"
            >
              {exportingStix ? <Loader2 className="w-3 h-3 animate-spin" /> : <FileText className="w-3 h-3" />}
              EXPORT STIX
            </button>
            <button
              onClick={() => setShowBulkEnrich(true)}
              className="flex items-center gap-2 px-3 py-2 bg-violet-500/10 border border-violet-500/20 text-violet-400 text-xs font-display tracking-wider hover:bg-violet-500/20 transition-colors"
            >
              <Sparkles className="w-3 h-3" />
              BULK ENRICH
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
            { label: "LAST 24H UPDATES", value: stats?.recentlyUpdatedActors ?? 0, icon: Clock, color: "text-green-400" },
          ].map((stat) => {
            const isActive = activeStatCard === stat.label;
            return (
              <button
                key={stat.label}
                onClick={() => handleStatCardClick(stat.label)}
                className={`text-left bg-card border p-3 transition-all duration-200 group cursor-pointer ${
                  isActive
                    ? "border-primary/60 ring-1 ring-primary/30 bg-primary/5"
                    : "border-border hover:border-primary/30 hover:bg-card/80"
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <stat.icon className={`w-4 h-4 ${stat.color} ${isActive ? "animate-pulse" : ""}`} />
                  <span className={`text-[10px] tracking-wider transition-colors ${
                    isActive ? "text-foreground" : "text-muted-foreground group-hover:text-foreground/80"
                  }`}>{stat.label}</span>
                </div>
                <p className={`text-xl font-display ${stat.color}`}>{stat.value}</p>
                {isActive && (
                  <div className="mt-1 text-[9px] text-primary/70 tracking-wider">FILTERED ✕</div>
                )}
              </button>
            );
          })}
        </div>

        {/* Filters */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              value={search}
              onChange={(e) => updateFilters({ search: e.target.value, page: 1, statCard: null, updatedLast24h: false })}
              placeholder="Search threat groups by name, alias, or ID..."
              className="w-full pl-10 pr-4 py-2.5 bg-card border border-border text-sm focus:outline-none focus:border-primary/50 transition-colors"
            />
          </div>
          <div className="flex gap-2 flex-wrap">
            {(["all", "apt", "ransomware", "cybercrime", "hacktivist", "access_broker", "influence_ops"] as GroupType[]).map((type) => (
              <button
                key={type}
                onClick={() => updateFilters({ type, page: 1, statCard: null, updatedLast24h: false })}
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
            value={conflictFilter}
            onChange={(e) => updateFilters({ conflict: e.target.value, page: 1, statCard: null, updatedLast24h: false })}
            className="px-3 py-2 bg-card border border-border text-sm text-muted-foreground focus:outline-none"
          >
            {CONFLICT_OPTIONS.map(c => (
              <option key={c.id} value={c.id}>{c.id === "all" ? "Conflict: All" : c.label}</option>
            ))}
          </select>
          <select
            value={lastActiveFilter}
            onChange={(e) => updateFilters({ lastActive: e.target.value, page: 1, statCard: null, updatedLast24h: false })}
            className="px-3 py-2 bg-card border border-border text-sm text-muted-foreground focus:outline-none"
          >
            <option value="all">Activity: All</option>
            <option value="30d">Active (30d)</option>
            <option value="90d">Active (90d)</option>
            <option value="6m">Active (6mo)</option>
            <option value="1y">Active (1yr)</option>
            <option value="stale">Stale (&gt;1yr / Unknown)</option>
          </select>
          <select
            value={sortBy}
            onChange={(e) => updateFilters({ sortBy: e.target.value })}
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
                    onClick={() => updateFilters({ page: Math.max(1, page - 1) })}
                    disabled={page <= 1}
                    className="px-3 py-1 text-xs bg-card border border-border disabled:opacity-30 hover:bg-accent/10 transition-colors"
                  >
                    PREV
                  </button>
                  <button
                    onClick={() => updateFilters({ page: Math.min(totalPages, page + 1) })}
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
                          {(typeConf.label || '').toUpperCase()}
                        </span>
                        {actor.origin && (
                          <span className="text-[10px] px-2 py-0.5 bg-secondary text-muted-foreground tracking-wider">
                            {safeUpper(actor.origin)}
                          </span>
                        )}
                        {actor.threatLevel && (
                          <span className={`text-[10px] px-2 py-0.5 border tracking-wider ${threatLevelClass}`}>
                            {safeUpper(actor.threatLevel, "MEDIUM")}
                          </span>
                        )}
                        {actor.confidence != null && (
                          <span className={`text-[10px] tracking-wider ${actor.confidence >= 80 ? "text-green-400" : actor.confidence >= 50 ? "text-yellow-400" : "text-red-400"}`}>
                            {actor.confidence}% CONF
                          </span>
                        )}
                      </div>

                      {/* Conflict Tags */}
                      {actor.conflicts && (
                        <div className="flex flex-wrap gap-1 mb-2">
                          {(actor.conflicts as string).split(',').filter(Boolean).map((c: string) => (
                            <span
                              key={c}
                              className={`text-[10px] px-1.5 py-0.5 border flex items-center gap-1 ${CONFLICT_COLOR_MAP[c] || 'text-gray-400 bg-gray-500/10 border-gray-500/20'}`}
                            >
                              <Swords className="w-2.5 h-2.5" />
                              {CONFLICT_LABEL_MAP[c] || c}
                            </span>
                          ))}
                        </div>
                      )}

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
                        {(() => {
                          const la = formatLastActive(actor.lastActive);
                          return (
                            <span className={`flex items-center gap-1 ${la.colorClass}`}>
                              <Clock className="w-3 h-3" />
                              {la.text}
                              {la.isRecent && (
                                <span className="inline-block w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" title="Active in last 30 days" />
                              )}
                            </span>
                          );
                        })()}
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
                  onClick={() => updateFilters({ page: Math.max(1, page - 1) })}
                  disabled={page <= 1}
                  className="px-4 py-2 text-xs bg-card border border-border disabled:opacity-30 hover:bg-accent/10 transition-colors font-display tracking-wider"
                >
                  PREVIOUS
                </button>
                <span className="px-4 py-2 text-xs text-muted-foreground">
                  {page} / {totalPages}
                </span>
                <button
                  onClick={() => updateFilters({ page: Math.min(totalPages, page + 1) })}
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

      {/* Bulk Enrich Dialog */}
      {showBulkEnrich && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => !bulkEnriching && setShowBulkEnrich(false)}>
          <div className="bg-card border border-border w-full max-w-2xl max-h-[80vh] overflow-auto m-4" onClick={e => e.stopPropagation()}>
            <div className="p-6 border-b border-border">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Sparkles className="w-5 h-5 text-violet-400" />
                  <h2 className="text-lg font-display tracking-wider">BULK ENRICHMENT</h2>
                </div>
                <button onClick={() => !bulkEnriching && setShowBulkEnrich(false)} className="text-muted-foreground hover:text-foreground text-xl">&times;</button>
              </div>
              <p className="text-sm text-muted-foreground mt-2">
                Enrich actors below 60% data completeness using LLM-powered keyword search across OSINT sources.
              </p>
            </div>
            <div className="p-6">
              {incompleteQuery.isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
                  <span className="ml-2 text-sm text-muted-foreground">Scanning actors...</span>
                </div>
              ) : incompleteQuery.data ? (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">
                      <span className="text-violet-400 font-bold">{incompleteQuery.data.total}</span> actors below {incompleteQuery.data.threshold}% completeness
                    </span>
                    <button
                      onClick={() => {
                        const ids = (incompleteQuery.data?.actors || []).slice(0, 20).map((a: any) => a.actorId);
                        if (ids.length > 0) handleBulkEnrich(ids);
                      }}
                      disabled={bulkEnriching || !incompleteQuery.data?.actors?.length}
                      className="flex items-center gap-2 px-4 py-2 bg-violet-500/20 border border-violet-500/30 text-violet-400 text-xs font-display tracking-wider hover:bg-violet-500/30 transition-colors disabled:opacity-50"
                    >
                      {bulkEnriching ? <Loader2 className="w-3 h-3 animate-spin" /> : <Sparkles className="w-3 h-3" />}
                      {bulkEnriching ? 'ENRICHING...' : `ENRICH TOP ${Math.min(20, incompleteQuery.data?.actors?.length || 0)}`}
                    </button>
                  </div>
                  {bulkEnrichMutation.data && (
                    <div className="p-3 bg-green-500/10 border border-green-500/20 text-sm">
                      <span className="text-green-400 font-bold">Complete:</span> {bulkEnrichMutation.data.succeeded} succeeded, {bulkEnrichMutation.data.failed} failed
                    </div>
                  )}
                  <div className="space-y-2 max-h-[40vh] overflow-auto">
                    {(incompleteQuery.data?.actors || []).slice(0, 30).map((actor: any) => (
                      <div key={actor.actorId} className="flex items-center justify-between p-3 bg-background/50 border border-border/50">
                        <div>
                          <span className="text-sm font-medium">{actor.name}</span>
                          <span className="text-xs text-muted-foreground ml-2">{actor.actorType?.toUpperCase()}</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <div className="w-24 h-2 bg-background rounded-full overflow-hidden">
                            <div
                              className={`h-full transition-all ${
                                actor.completeness < 30 ? 'bg-red-500' : actor.completeness < 50 ? 'bg-amber-500' : 'bg-yellow-500'
                              }`}
                              style={{ width: `${actor.completeness}%` }}
                            />
                          </div>
                          <span className="text-xs text-muted-foreground w-10 text-right">{actor.completeness}%</span>
                        </div>
                      </div>
                    ))}
                  </div>
                  {(incompleteQuery.data?.actors || []).length > 30 && (
                    <p className="text-xs text-muted-foreground text-center">
                      ...and {(incompleteQuery.data?.total || 0) - 30} more actors below threshold
                    </p>
                  )}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-8">No data available</p>
              )}
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}
