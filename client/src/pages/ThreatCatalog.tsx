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
  Settings2,
  Calendar,
  Map,
  ShieldCheck,
  Play,
  Pause,
  Save,
  Radar,
  Wand2,
  Brain,
  CheckCircle2,
  XCircle,
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
    sortBy: (p.get("sort") || "name") as SortBy,
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
  if (filters.sortBy && filters.sortBy !== "name") p.set("sort", filters.sortBy);
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
  const [showClassifier, setShowClassifier] = useState(false);
  const [classifierAutoApply, setClassifierAutoApply] = useState(75);
  const [classifierBatchSize, setClassifierBatchSize] = useState(5);
  const [bulkEnriching, setBulkEnriching] = useState(false);
  const [bulkProgress, setBulkProgress] = useState<{ current: number; total: number; results: any[] } | null>(null);
  const [batchSize, setBatchSize] = useState(50);
  const BATCH_SIZE_OPTIONS = [20, 50, 100, 250, 500, 1000];
  const [showScheduler, setShowScheduler] = useState(false);
  const [showGuardrails, setShowGuardrails] = useState(false);
  const [showNavigator, setShowNavigator] = useState(false);
  const [exportingNavigator, setExportingNavigator] = useState(false);
  const [guardrailDraft, setGuardrailDraft] = useState<Record<string, number>>({});
  const [schedulerDraft, setSchedulerDraft] = useState<Record<string, any>>({});

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

  const incompleteQuery = trpc.threatIntel.incompleteActors.useQuery({ threshold: 60, limit: 2000 }, { enabled: showBulkEnrich });

  // Scheduler, Guardrails, Navigator queries
  const schedulerStatus = trpc.threatIntel.catalogEnrichmentStatus.useQuery(undefined, { enabled: showScheduler, refetchInterval: showScheduler ? 5000 : false });
  const schedulerTrigger = trpc.threatIntel.catalogEnrichmentTrigger.useMutation({
    onSuccess: () => { toast.success('Manual enrichment started'); schedulerStatus.refetch(); },
    onError: (err: any) => toast.error(`Failed: ${sanitizeErrorForToast(err)}`),
  });
  const schedulerConfigMut = trpc.threatIntel.catalogEnrichmentConfig.useMutation({
    onSuccess: (data) => { toast.success('Scheduler config updated'); schedulerStatus.refetch(); setSchedulerDraft({}); },
    onError: (err: any) => toast.error(`Failed: ${sanitizeErrorForToast(err)}`),
  });
  const guardrailConfig = trpc.threatIntel.guardrailConfig.useQuery(undefined, { enabled: showGuardrails });
  const guardrailConfigMut = trpc.threatIntel.guardrailConfigUpdate.useMutation({
    onSuccess: () => { toast.success('Guardrail thresholds updated'); guardrailConfig.refetch(); setGuardrailDraft({}); },
    onError: (err: any) => toast.error(`Failed: ${sanitizeErrorForToast(err)}`),
  });
  const navigatorQuery = trpc.threatIntel.navigatorLayer.useQuery({
    type: typeFilter !== 'all' ? typeFilter : undefined,
    threatLevel: threatLevelFilter !== 'all' ? threatLevelFilter : undefined,
    conflict: conflictFilter !== 'all' ? conflictFilter : undefined,
  }, { enabled: false });
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

  const handleBulkEnrich = async (actorIds: string[]) => {
    setBulkEnriching(true);
    setBulkProgress({ current: 0, total: actorIds.length, results: [] });
    
    // Process in server-side batches of 10 to avoid timeout
    const CHUNK_SIZE = 10;
    const allResults: any[] = [];
    let succeeded = 0;
    let failed = 0;
    
    for (let i = 0; i < actorIds.length; i += CHUNK_SIZE) {
      const chunk = actorIds.slice(i, i + CHUNK_SIZE);
      try {
        const result = await bulkEnrichMutation.mutateAsync({ actorIds: chunk });
        succeeded += result.succeeded;
        failed += result.failed;
        allResults.push(...(result.results || []));
      } catch (err: any) {
        failed += chunk.length;
        allResults.push(...chunk.map(id => ({ actorId: id, status: 'failed', error: err?.message })));
      }
      setBulkProgress({ current: Math.min(i + CHUNK_SIZE, actorIds.length), total: actorIds.length, results: allResults });
    }
    
    toast.success(`Bulk enrichment complete: ${succeeded} succeeded, ${failed} failed`);
    setBulkEnriching(false);
    refetch();
  };

  const handleExportNavigator = async () => {
    setExportingNavigator(true);
    try {
      const result = await navigatorQuery.refetch();
      if (result.data?.layer) {
        const blob = new Blob([result.data.layer], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `attack-navigator-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success(`Navigator layer exported: ${result.data.actorCount} actors, ${result.data.techniqueCount} techniques`);
      }
    } catch (err: any) {
      toast.error(`Navigator export failed: ${sanitizeErrorForToast(err)}`);
    }
    setExportingNavigator(false);
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
            <button
              onClick={() => handleExportNavigator()}
              disabled={exportingNavigator}
              className="flex items-center gap-2 px-3 py-2 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs font-display tracking-wider hover:bg-rose-500/20 transition-colors disabled:opacity-50"
            >
              {exportingNavigator ? <Loader2 className="w-3 h-3 animate-spin" /> : <Map className="w-3 h-3" />}
              ATT&CK NAV
            </button>
            <button
              onClick={() => setShowScheduler(true)}
              className="flex items-center gap-2 px-3 py-2 bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-display tracking-wider hover:bg-indigo-500/20 transition-colors"
            >
              <Calendar className="w-3 h-3" />
              SCHEDULER
            </button>
            <button
              onClick={() => setShowGuardrails(true)}
              className="flex items-center gap-2 px-3 py-2 bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs font-display tracking-wider hover:bg-amber-500/20 transition-colors"
            >
              <ShieldCheck className="w-3 h-3" />
              GUARDRAILS
            </button>
            <button
              onClick={() => navigate("/threat-catalog/discover")}
              className="flex items-center gap-2 px-3 py-2 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-display tracking-wider hover:bg-cyan-500/20 transition-colors"
            >
              <Radar className="w-3 h-3" />
              DISCOVER
            </button>
            <button
              onClick={() => setShowClassifier(true)}
              className="flex items-center gap-2 px-3 py-2 bg-violet-500/10 border border-violet-500/20 text-violet-400 text-xs font-display tracking-wider hover:bg-violet-500/20 transition-colors"
            >
              <Brain className="w-3 h-3" />
              CLASSIFY
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
                Hallucination guardrails validate all LLM output before writing to the database.
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
                  {/* Stats + Batch Size Selector */}
                  <div className="flex items-center justify-between flex-wrap gap-3">
                    <span className="text-sm">
                      <span className="text-violet-400 font-bold">{incompleteQuery.data.total}</span> actors below {incompleteQuery.data.threshold}% completeness
                    </span>
                    <div className="flex items-center gap-3">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">Batch:</span>
                        <select
                          value={batchSize}
                          onChange={(e) => setBatchSize(Number(e.target.value))}
                          disabled={bulkEnriching}
                          className="bg-background border border-border text-xs px-2 py-1 text-foreground"
                        >
                          {BATCH_SIZE_OPTIONS.map(size => (
                            <option key={size} value={size}>{size}</option>
                          ))}
                          {incompleteQuery.data.total > 0 && (
                            <option value={incompleteQuery.data.total}>ALL ({incompleteQuery.data.total})</option>
                          )}
                        </select>
                      </div>
                      <button
                        onClick={() => {
                          const ids = (incompleteQuery.data?.actors || []).slice(0, batchSize).map((a: any) => a.actorId);
                          if (ids.length > 0) handleBulkEnrich(ids);
                        }}
                        disabled={bulkEnriching || !incompleteQuery.data?.actors?.length}
                        className="flex items-center gap-2 px-4 py-2 bg-violet-500/20 border border-violet-500/30 text-violet-400 text-xs font-display tracking-wider hover:bg-violet-500/30 transition-colors disabled:opacity-50"
                      >
                        {bulkEnriching ? <Loader2 className="w-3 h-3 animate-spin" /> : <Sparkles className="w-3 h-3" />}
                        {bulkEnriching ? 'ENRICHING...' : `ENRICH ${Math.min(batchSize, incompleteQuery.data?.actors?.length || 0)} ACTORS`}
                      </button>
                    </div>
                  </div>

                  {/* Guardrail Info Banner */}
                  <div className="p-3 bg-blue-500/10 border border-blue-500/20 text-xs">
                    <div className="flex items-center gap-2 mb-1">
                      <svg className="w-3.5 h-3.5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
                      <span className="text-blue-400 font-bold">GUARDRAILS ACTIVE</span>
                    </div>
                    <span className="text-muted-foreground">
                      MITRE T-code validation &middot; Source citation verification &middot; Confidence thresholds &middot; Local DB cross-reference &middot; Suspicious source detection
                    </span>
                  </div>

                  {/* Progress Bar */}
                  {bulkProgress && bulkEnriching && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-muted-foreground">Processing: {bulkProgress.current} / {bulkProgress.total}</span>
                        <span className="text-violet-400 font-bold">{Math.round((bulkProgress.current / bulkProgress.total) * 100)}%</span>
                      </div>
                      <div className="w-full h-2 bg-background rounded-full overflow-hidden">
                        <div
                          className="h-full bg-violet-500 transition-all duration-500"
                          style={{ width: `${(bulkProgress.current / bulkProgress.total) * 100}%` }}
                        />
                      </div>
                      {bulkProgress.results.length > 0 && (
                        <div className="flex gap-4 text-xs">
                          <span className="text-green-400">{bulkProgress.results.filter((r: any) => r.status === 'success').length} succeeded</span>
                          <span className="text-red-400">{bulkProgress.results.filter((r: any) => r.status === 'failed').length} failed</span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Completion Summary */}
                  {bulkProgress && !bulkEnriching && bulkProgress.results.length > 0 && (
                    <div className="p-3 bg-green-500/10 border border-green-500/20 text-sm">
                      <span className="text-green-400 font-bold">Complete:</span>{' '}
                      {bulkProgress.results.filter((r: any) => r.status === 'success').length} succeeded,{' '}
                      {bulkProgress.results.filter((r: any) => r.status === 'failed').length} failed
                      <div className="mt-2 text-xs text-muted-foreground">
                        Total fields updated: {bulkProgress.results.reduce((sum: number, r: any) => sum + (r.fieldsUpdated || 0), 0)} &middot;
                        Fields discovered: {bulkProgress.results.reduce((sum: number, r: any) => sum + (r.fieldsDiscovered || 0), 0)}
                      </div>
                    </div>
                  )}

                  {/* Actor List */}
                  <div className="space-y-2 max-h-[35vh] overflow-auto">
                    {(incompleteQuery.data?.actors || []).slice(0, Math.max(50, batchSize)).map((actor: any, idx: number) => {
                      const isInBatch = idx < batchSize;
                      const result = bulkProgress?.results?.find((r: any) => r.actorId === actor.actorId);
                      return (
                        <div key={actor.actorId} className={`flex items-center justify-between p-3 border border-border/50 ${
                          result?.status === 'success' ? 'bg-green-500/5 border-green-500/20' :
                          result?.status === 'failed' ? 'bg-red-500/5 border-red-500/20' :
                          isInBatch ? 'bg-background/50' : 'bg-background/20 opacity-50'
                        }`}>
                          <div className="flex items-center gap-2">
                            {result?.status === 'success' && <span className="text-green-400 text-xs">&#10003;</span>}
                            {result?.status === 'failed' && <span className="text-red-400 text-xs">&#10007;</span>}
                            <span className="text-sm font-medium">{actor.name}</span>
                            <span className="text-xs text-muted-foreground">{actor.actorType?.toUpperCase()}</span>
                          </div>
                          <div className="flex items-center gap-3">
                            {result && (
                              <span className="text-xs text-muted-foreground">
                                {result.fieldsUpdated || 0}u / {result.fieldsDiscovered || 0}d
                              </span>
                            )}
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
                      );
                    })}
                  </div>
                  {(incompleteQuery.data?.total || 0) > Math.max(50, batchSize) && (
                    <p className="text-xs text-muted-foreground text-center">
                      ...and {(incompleteQuery.data?.total || 0) - Math.max(50, batchSize)} more actors below threshold
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

      {/* Scheduler Dialog */}
      {showScheduler && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setShowScheduler(false)}>
          <div className="bg-card border border-border w-full max-w-lg max-h-[80vh] overflow-auto m-4" onClick={e => e.stopPropagation()}>
            <div className="p-6 border-b border-border">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Calendar className="w-5 h-5 text-indigo-400" />
                  <h2 className="text-lg font-display tracking-wider">ENRICHMENT SCHEDULER</h2>
                </div>
                <button onClick={() => setShowScheduler(false)} className="text-muted-foreground hover:text-foreground text-xl">&times;</button>
              </div>
              <p className="text-sm text-muted-foreground mt-2">
                Automated daily enrichment of low-completeness actors with hallucination guardrails.
              </p>
            </div>
            <div className="p-6 space-y-5">
              {schedulerStatus.isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
                </div>
              ) : schedulerStatus.data ? (
                <>
                  {/* Status Card */}
                  <div className="p-4 bg-background border border-border space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-display tracking-wider text-muted-foreground">STATUS</span>
                      <span className={`text-xs font-bold px-2 py-0.5 ${schedulerStatus.data.enabled ? 'bg-green-500/20 text-green-400 border border-green-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'}`}>
                        {schedulerStatus.data.enabled ? 'ACTIVE' : 'DISABLED'}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div>
                        <span className="text-muted-foreground">Schedule:</span>
                        <span className="ml-2 text-foreground">Daily @ {String(schedulerStatus.data.config?.cronHourUtc ?? 3).padStart(2, '0')}:00 UTC</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Batch Size:</span>
                        <span className="ml-2 text-foreground">{schedulerStatus.data.config?.batchSize ?? 10} actors</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Threshold:</span>
                        <span className="ml-2 text-foreground">&lt; {schedulerStatus.data.config?.completenessThreshold ?? 60}% completeness</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Total Runs:</span>
                        <span className="ml-2 text-foreground">{schedulerStatus.data.totalRuns ?? 0}</span>
                      </div>
                    </div>
                    {schedulerStatus.data.lastRun && (
                      <div className="text-xs">
                        <span className="text-muted-foreground">Last Run:</span>
                        <span className="ml-2 text-foreground">{new Date(schedulerStatus.data.lastRun.startedAt).toLocaleString()}</span>
                        <span className="ml-2">
                          <span className="text-green-400">{schedulerStatus.data.lastRun.succeeded}&#10003;</span>
                          {schedulerStatus.data.lastRun.failed > 0 && <span className="ml-1 text-red-400">{schedulerStatus.data.lastRun.failed}&#10007;</span>}
                        </span>
                      </div>
                    )}
                    {schedulerStatus.data.nextRunAt && (
                      <div className="text-xs">
                        <span className="text-muted-foreground">Next Run:</span>
                        <span className="ml-2 text-foreground">{new Date(schedulerStatus.data.nextRunAt).toLocaleString()}</span>
                      </div>
                    )}
                  </div>

                  {/* Config Controls */}
                  <div className="space-y-3">
                    <h3 className="text-xs font-display tracking-wider text-muted-foreground">CONFIGURATION</h3>
                    <div className="grid grid-cols-3 gap-3">
                      <div>
                        <label className="text-xs text-muted-foreground block mb-1">Hour (UTC)</label>
                        <input
                          type="number"
                          min={0} max={23}
                          defaultValue={schedulerStatus.data.config?.cronHourUtc ?? 3}
                          onChange={e => setSchedulerDraft(d => ({ ...d, cronHourUtc: Number(e.target.value) }))}
                          className="w-full bg-background border border-border text-xs px-2 py-1.5 text-foreground"
                        />
                      </div>
                      <div>
                        <label className="text-xs text-muted-foreground block mb-1">Batch Size</label>
                        <input
                          type="number"
                          min={1} max={100}
                          defaultValue={schedulerStatus.data.config?.batchSize ?? 10}
                          onChange={e => setSchedulerDraft(d => ({ ...d, batchSize: Number(e.target.value) }))}
                          className="w-full bg-background border border-border text-xs px-2 py-1.5 text-foreground"
                        />
                      </div>
                      <div>
                        <label className="text-xs text-muted-foreground block mb-1">Threshold %</label>
                        <input
                          type="number"
                          min={10} max={100}
                          defaultValue={schedulerStatus.data.config?.completenessThreshold ?? 60}
                          onChange={e => setSchedulerDraft(d => ({ ...d, completenessThreshold: Number(e.target.value) }))}
                          className="w-full bg-background border border-border text-xs px-2 py-1.5 text-foreground"
                        />
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <button
                        onClick={() => schedulerConfigMut.mutate(schedulerDraft)}
                        disabled={Object.keys(schedulerDraft).length === 0}
                        className="flex items-center gap-2 px-3 py-2 bg-indigo-500/20 border border-indigo-500/30 text-indigo-400 text-xs font-display tracking-wider hover:bg-indigo-500/30 transition-colors disabled:opacity-50"
                      >
                        <Save className="w-3 h-3" />
                        SAVE CONFIG
                      </button>
                      <button
                        onClick={() => schedulerConfigMut.mutate({ enabled: !schedulerStatus.data?.enabled })}
                        className={`flex items-center gap-2 px-3 py-2 border text-xs font-display tracking-wider transition-colors ${
                          schedulerStatus.data?.enabled
                            ? 'bg-red-500/20 border-red-500/30 text-red-400 hover:bg-red-500/30'
                            : 'bg-green-500/20 border-green-500/30 text-green-400 hover:bg-green-500/30'
                        }`}
                      >
                        {schedulerStatus.data?.enabled ? <><Pause className="w-3 h-3" /> DISABLE</> : <><Play className="w-3 h-3" /> ENABLE</>}
                      </button>
                      <button
                        onClick={() => schedulerTrigger.mutate()}
                        disabled={schedulerTrigger.isPending}
                        className="flex items-center gap-2 px-3 py-2 bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 text-xs font-display tracking-wider hover:bg-cyan-500/30 transition-colors disabled:opacity-50"
                      >
                        {schedulerTrigger.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                        RUN NOW
                      </button>
                    </div>
                  </div>

                  {/* Auto-Discovery Status */}
                  {schedulerStatus.data.discovery && (
                    <div className="p-4 bg-background border border-purple-500/20 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-display tracking-wider text-purple-400">AUTO-DISCOVERY</span>
                        <span className={`text-xs font-bold px-2 py-0.5 ${schedulerStatus.data.discovery.enabled ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'bg-muted text-muted-foreground border border-border'}`}>
                          {schedulerStatus.data.discovery.enabled ? 'ENABLED' : 'DISABLED'}
                        </span>
                      </div>
                      <p className="text-[10px] text-muted-foreground">
                        Automatically discovers new threat actors using LLM with rotating strategies after each enrichment run.
                      </p>
                      <div className="grid grid-cols-2 gap-3 text-xs">
                        <div>
                          <span className="text-muted-foreground">Next Strategy:</span>
                          <span className="ml-2 text-purple-300">{schedulerStatus.data.discovery.nextStrategy?.replace(/_/g, ' ')}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Total Discovered:</span>
                          <span className="ml-2 text-foreground">{schedulerStatus.data.discovery.totalDiscovered ?? 0}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Pending Review:</span>
                          <span className="ml-2 text-amber-400 font-bold">{schedulerStatus.data.discovery.pendingReview ?? 0}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Total Runs:</span>
                          <span className="ml-2 text-foreground">{schedulerStatus.data.discovery.totalRuns ?? 0}</span>
                        </div>
                      </div>
                      {(schedulerStatus.data.discovery.pendingReview ?? 0) > 0 && (
                        <a
                          href="/threat-actor-discovery"
                          className="inline-flex items-center gap-2 px-3 py-1.5 bg-purple-500/20 border border-purple-500/30 text-purple-400 text-xs font-display tracking-wider hover:bg-purple-500/30 transition-colors"
                        >
                          REVIEW DISCOVERIES →
                        </a>
                      )}
                      {schedulerStatus.data.discovery.lastResult && (
                        <div className="text-[10px] text-muted-foreground border-t border-border/50 pt-2 mt-2">
                          Last discovery: {schedulerStatus.data.discovery.lastResult.strategy?.replace(/_/g, ' ')} — {schedulerStatus.data.discovery.lastResult.actorsDiscovered} found, {schedulerStatus.data.discovery.lastResult.actorsAlreadyKnown} already known
                          {schedulerStatus.data.discovery.lastResult.error && (
                            <span className="text-red-400 ml-2">Error: {schedulerStatus.data.discovery.lastResult.error}</span>
                          )}
                        </div>
                      )}
                      <button
                        onClick={() => schedulerConfigMut.mutate({ discoveryEnabled: !schedulerStatus.data?.discovery?.enabled })}
                        className={`flex items-center gap-2 px-3 py-1.5 border text-xs font-display tracking-wider transition-colors ${
                          schedulerStatus.data.discovery.enabled
                            ? 'bg-red-500/20 border-red-500/30 text-red-400 hover:bg-red-500/30'
                            : 'bg-purple-500/20 border-purple-500/30 text-purple-400 hover:bg-purple-500/30'
                        }`}
                      >
                        {schedulerStatus.data.discovery.enabled ? 'DISABLE DISCOVERY' : 'ENABLE DISCOVERY'}
                      </button>
                    </div>
                  )}

                  {/* Recent Runs */}
                  {schedulerStatus.data.recentRuns && schedulerStatus.data.recentRuns.length > 0 && (
                    <div className="space-y-2">
                      <h3 className="text-xs font-display tracking-wider text-muted-foreground">RECENT RUNS</h3>
                      <div className="space-y-1">
                        {schedulerStatus.data.recentRuns.slice(0, 5).map((run: any, i: number) => (
                          <div key={i} className="flex items-center justify-between p-2 bg-background/50 border border-border/50 text-xs">
                            <span className="text-muted-foreground">{new Date(run.startedAt).toLocaleString()}</span>
                            <div className="flex items-center gap-3">
                              <span className="text-green-400">{run.succeeded}&#10003;</span>
                              {run.failed > 0 && <span className="text-red-400">{run.failed}&#10007;</span>}
                              <span className="text-muted-foreground">{run.trigger}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-8">No scheduler data available</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Guardrails Dialog */}
      {showGuardrails && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setShowGuardrails(false)}>
          <div className="bg-card border border-border w-full max-w-lg max-h-[80vh] overflow-auto m-4" onClick={e => e.stopPropagation()}>
            <div className="p-6 border-b border-border">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <ShieldCheck className="w-5 h-5 text-amber-400" />
                  <h2 className="text-lg font-display tracking-wider">GUARDRAIL THRESHOLDS</h2>
                </div>
                <button onClick={() => setShowGuardrails(false)} className="text-muted-foreground hover:text-foreground text-xl">&times;</button>
              </div>
              <p className="text-sm text-muted-foreground mt-2">
                Tune confidence thresholds that control when LLM-enriched fields are accepted, flagged, or rejected.
              </p>
            </div>
            <div className="p-6 space-y-5">
              {guardrailConfig.isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
                </div>
              ) : guardrailConfig.data ? (
                <>
                  {/* Threshold Sliders */}
                  {[
                    { key: 'confidenceAcceptThreshold', label: 'ACCEPT THRESHOLD', desc: 'Fields above this confidence are accepted (green)', color: 'text-green-400', min: 30, max: 100 },
                    { key: 'confidenceRejectThreshold', label: 'REJECT THRESHOLD', desc: 'Fields below this confidence are rejected (red)', color: 'text-red-400', min: 0, max: 60 },
                    { key: 'llmOnlyMinConfidence', label: 'LLM-ONLY MINIMUM', desc: 'Minimum confidence for fields sourced only from LLM knowledge', color: 'text-amber-400', min: 30, max: 100 },
                  ].map(({ key, label, desc, color, min, max }) => {
                    const current = guardrailDraft[key] ?? (guardrailConfig.data as any)?.[key] ?? 50;
                    return (
                      <div key={key} className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className={`text-xs font-display tracking-wider ${color}`}>{label}</span>
                          <span className="text-sm font-bold text-foreground">{current}%</span>
                        </div>
                        <p className="text-xs text-muted-foreground">{desc}</p>
                        <input
                          type="range"
                          min={min} max={max}
                          value={current}
                          onChange={e => setGuardrailDraft(d => ({ ...d, [key]: Number(e.target.value) }))}
                          className="w-full h-1.5 bg-background rounded-full appearance-none cursor-pointer accent-primary"
                        />
                        <div className="flex justify-between text-[10px] text-muted-foreground">
                          <span>{min}%</span>
                          <span>{max}%</span>
                        </div>
                      </div>
                    );
                  })}

                  {/* Validation Toggles */}
                  <div className="space-y-2">
                    <h3 className="text-xs font-display tracking-wider text-muted-foreground">ACTIVE VALIDATIONS</h3>
                    <div className="grid grid-cols-2 gap-2">
                      {[
                        { label: 'MITRE T-Code Validation', active: guardrailConfig.data.mitreValidation },
                        { label: 'Source Citation Check', active: guardrailConfig.data.sourceCitationCheck },
                        { label: 'Local DB Cross-Reference', active: guardrailConfig.data.localDbCrossRef },
                        { label: 'Suspicious Source Detection', active: guardrailConfig.data.suspiciousSourceDetection },
                      ].map(({ label, active }) => (
                        <div key={label} className={`flex items-center gap-2 p-2 border text-xs ${
                          active ? 'border-green-500/30 bg-green-500/10 text-green-400' : 'border-border bg-background/50 text-muted-foreground'
                        }`}>
                          <span className={active ? 'text-green-400' : 'text-muted-foreground'}>{active ? '●' : '○'}</span>
                          {label}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Save Button */}
                  <button
                    onClick={() => guardrailConfigMut.mutate(guardrailDraft)}
                    disabled={Object.keys(guardrailDraft).length === 0 || guardrailConfigMut.isPending}
                    className="flex items-center gap-2 px-4 py-2 bg-amber-500/20 border border-amber-500/30 text-amber-400 text-xs font-display tracking-wider hover:bg-amber-500/30 transition-colors disabled:opacity-50"
                  >
                    {guardrailConfigMut.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
                    SAVE THRESHOLDS
                  </button>
                </>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-8">No guardrail data available</p>
              )}
            </div>
          </div>
        </div>
      )}
      {/* Auto-Classification Dialog */}
      {showClassifier && <ClassifierDialog
        onClose={() => setShowClassifier(false)}
        autoApplyThreshold={classifierAutoApply}
        setAutoApplyThreshold={setClassifierAutoApply}
        batchSize={classifierBatchSize}
        setBatchSize={setClassifierBatchSize}
        onComplete={() => { refetch(); }}
      />}
    </AppShell>
  );
}

/** Classification Dialog Component */
function ClassifierDialog({ onClose, autoApplyThreshold, setAutoApplyThreshold, batchSize, setBatchSize, onComplete }: {
  onClose: () => void;
  autoApplyThreshold: number;
  setAutoApplyThreshold: (v: number) => void;
  batchSize: number;
  setBatchSize: (v: number) => void;
  onComplete: () => void;
}) {
  const progressQuery = trpc.threatIntel.classifyProgress.useQuery(undefined, { refetchInterval: 2000 });
  const startMutation = trpc.threatIntel.classifyBatchStart.useMutation({
    onSuccess: (data) => {
      if (data.started) toast.success(data.message);
      else toast.info(data.message);
    },
    onError: (err: any) => toast.error(`Classification failed: ${err.message}`),
  });
  const cancelMutation = trpc.threatIntel.classifyCancel.useMutation({
    onSuccess: () => toast.info("Classification cancelled"),
  });
  const applyMutation = trpc.threatIntel.classifyApply.useMutation({
    onSuccess: () => { toast.success("Classification applied"); onComplete(); },
  });
  const reviewQuery = trpc.threatIntel.classifyReview.useQuery(undefined, { refetchInterval: 5000 });

  const progress = progressQuery.data;
  const isRunning = progress?.status === "running";
  const pct = progress && progress.total > 0 ? Math.round((progress.processed / progress.total) * 100) : 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-card border border-border rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Brain className="w-5 h-5 text-violet-400" />
            <h2 className="text-lg font-display tracking-wider text-foreground">AI THREAT ACTOR CLASSIFIER</h2>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground text-xl">&times;</button>
        </div>

        <p className="text-sm text-muted-foreground mb-4">
          Uses LLM structured output to classify "unknown" threat actors into proper categories
          (APT, Ransomware, Cybercrime, Hacktivist, Access Broker, Influence Ops) based on their
          descriptions, TTPs, tools, and target sectors.
        </p>

        {/* Configuration */}
        <div className="grid grid-cols-2 gap-4 mb-4">
          <div>
            <label className="text-xs text-muted-foreground font-display tracking-wider">AUTO-APPLY THRESHOLD</label>
            <div className="flex items-center gap-2 mt-1">
              <input type="range" min={50} max={95} value={autoApplyThreshold}
                onChange={e => setAutoApplyThreshold(Number(e.target.value))}
                className="flex-1 accent-violet-500" />
              <span className="text-sm font-mono text-violet-400 w-10">{autoApplyThreshold}%</span>
            </div>
            <p className="text-xs text-muted-foreground mt-1">Classifications above this confidence are auto-applied</p>
          </div>
          <div>
            <label className="text-xs text-muted-foreground font-display tracking-wider">BATCH SIZE</label>
            <select value={batchSize} onChange={e => setBatchSize(Number(e.target.value))}
              className="mt-1 w-full bg-background border border-border rounded px-3 py-2 text-sm">
              {[3, 5, 10, 15, 20].map(s => <option key={s} value={s}>{s} actors/batch</option>)}
            </select>
            <p className="text-xs text-muted-foreground mt-1">Concurrent LLM calls per batch</p>
          </div>
        </div>

        {/* Progress */}
        {progress && progress.status !== "idle" && (
          <div className="mb-4 p-3 bg-violet-500/5 border border-violet-500/20 rounded">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-display tracking-wider text-violet-400">
                {progress.status === "running" ? "CLASSIFYING..." : progress.status === "completed" ? "COMPLETED" : "CANCELLED"}
              </span>
              <span className="text-xs text-muted-foreground">
                {progress.processed}/{progress.total} ({pct}%)
              </span>
            </div>
            <div className="w-full h-2 bg-violet-500/10 rounded-full overflow-hidden">
              <div className="h-full bg-violet-500 transition-all duration-300" style={{ width: `${pct}%` }} />
            </div>
            <div className="flex gap-4 mt-2 text-xs text-muted-foreground">
              <span className="flex items-center gap-1"><CheckCircle2 className="w-3 h-3 text-green-400" />{progress.succeeded} classified</span>
              <span className="flex items-center gap-1"><XCircle className="w-3 h-3 text-red-400" />{progress.failed} failed</span>
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="flex gap-3 mb-4">
          {!isRunning ? (
            <button
              onClick={() => startMutation.mutate({ targetType: "unknown", batchSize, autoApplyThreshold, limit: 928 })}
              disabled={startMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-violet-500/20 border border-violet-500/30 text-violet-400 text-xs font-display tracking-wider hover:bg-violet-500/30 transition-colors disabled:opacity-50"
            >
              {startMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Wand2 className="w-3 h-3" />}
              CLASSIFY UNKNOWN ACTORS
            </button>
          ) : (
            <button
              onClick={() => cancelMutation.mutate()}
              className="flex items-center gap-2 px-4 py-2 bg-red-500/20 border border-red-500/30 text-red-400 text-xs font-display tracking-wider hover:bg-red-500/30 transition-colors"
            >
              <XCircle className="w-3 h-3" />
              CANCEL
            </button>
          )}
        </div>

        {/* Results Summary */}
        {progress && progress.results.length > 0 && (
          <div className="mb-4">
            <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-2">CLASSIFICATION RESULTS</h3>
            <div className="grid grid-cols-3 gap-2 mb-3">
              {Object.entries(
                progress.results.reduce((acc, r) => {
                  acc[r.classifiedType] = (acc[r.classifiedType] || 0) + 1;
                  return acc;
                }, {} as Record<string, number>)
              ).sort((a, b) => b[1] - a[1]).map(([type, count]) => (
                <div key={type} className="p-2 bg-background border border-border rounded text-center">
                  <div className="text-lg font-mono text-foreground">{count}</div>
                  <div className="text-xs text-muted-foreground uppercase">{type.replace("_", " ")}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Low-Confidence Review */}
        {reviewQuery.data && reviewQuery.data.items.length > 0 && (
          <div>
            <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-2">
              NEEDS REVIEW ({reviewQuery.data.items.length} low-confidence)
            </h3>
            <div className="max-h-48 overflow-y-auto space-y-2">
              {reviewQuery.data.items.slice(0, 20).map(item => (
                <div key={item.actorId} className="flex items-center justify-between p-2 bg-background border border-border rounded text-xs">
                  <div className="flex-1">
                    <span className="text-foreground font-medium">{item.name}</span>
                    <span className="text-muted-foreground ml-2">→ {item.classifiedType} ({item.confidence}%)</span>
                    <p className="text-muted-foreground mt-0.5 line-clamp-1">{item.reasoning}</p>
                  </div>
                  <div className="flex gap-1 ml-2">
                    <button
                      onClick={() => applyMutation.mutate({ actorId: item.actorId, classifiedType: item.classifiedType })}
                      className="p-1 text-green-400 hover:bg-green-500/10 rounded" title="Accept"
                    >
                      <CheckCircle2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
