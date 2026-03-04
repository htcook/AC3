import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AlertTriangle, Bell, Shield, Search, RefreshCw, ExternalLink, Globe, Building2, Calendar, Filter, TrendingUp, Skull, FileWarning, Database } from "lucide-react";
import { toast } from "sonner";

// ─── Types ───────────────────────────────────────────────────────────────────

interface BreachEvent {
  id: number;
  type: "ransomware" | "data_breach" | "data_leak" | "unauthorized_access" | "incident";
  groupName: string;
  victimName: string;
  country: string | null;
  sector: string | null;
  description: string | null;
  publishedAt: string;
  source: string;
  sourceUrl?: string | null;
  verified: boolean;
  severity?: string | null;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function severityColor(severity: string | null | undefined): string {
  switch (severity?.toLowerCase()) {
    case "critical": return "bg-red-500/20 text-red-400 border-red-500/50";
    case "high": return "bg-orange-500/20 text-orange-400 border-orange-500/50";
    case "medium": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/50";
    case "low": return "bg-blue-500/20 text-blue-400 border-blue-500/50";
    default: return "bg-zinc-500/20 text-zinc-400 border-zinc-500/50";
  }
}

function typeIcon(type: string) {
  switch (type) {
    case "ransomware": return <Skull className="h-4 w-4 text-red-400" />;
    case "data_breach": return <FileWarning className="h-4 w-4 text-orange-400" />;
    case "data_leak": return <Database className="h-4 w-4 text-yellow-400" />;
    case "unauthorized_access": return <Shield className="h-4 w-4 text-purple-400" />;
    case "incident": return <AlertTriangle className="h-4 w-4 text-amber-400" />;
    default: return <Bell className="h-4 w-4 text-zinc-400" />;
  }
}

function typeLabel(type: string) {
  switch (type) {
    case "ransomware": return "Ransomware";
    case "data_breach": return "Data Breach";
    case "data_leak": return "Data Leak";
    case "unauthorized_access": return "Unauthorized Access";
    case "incident": return "Incident Report";
    default: return type;
  }
}

function relativeTime(dateStr: string): string {
  const now = new Date();
  const then = new Date(dateStr);
  const diffMs = now.getTime() - then.getTime();
  const diffH = Math.floor(diffMs / 3600000);
  if (diffH < 1) return "Just now";
  if (diffH < 24) return `${diffH}h ago`;
  const diffD = Math.floor(diffH / 24);
  if (diffD < 7) return `${diffD}d ago`;
  if (diffD < 30) return `${Math.floor(diffD / 7)}w ago`;
  return `${Math.floor(diffD / 30)}mo ago`;
}

// ─── Component ───────────────────────────────────────────────────────────────

export default function BreachEvents() {

  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [sectorFilter, setSectorFilter] = useState<string>("all");
  const [countryFilter, setCountryFilter] = useState<string>("all");
  const [tab, setTab] = useState("all");

  // Fetch breach events from all sources
  const breachEventsQ = trpc.darkwebIntel.getBreachEvents.useQuery(undefined, {
    refetchInterval: 120_000, // auto-refresh every 2 minutes
  });

  const syncMutation = trpc.darkwebIntel.syncDailyDarkWeb.useMutation({
    onSuccess: () => {
      toast.success("Sync Complete", { description: "Breach events feed refreshed from all sources." });
      breachEventsQ.refetch();
    },
    onError: (err) => {
      toast.error("Sync Failed", { description: err.message });
    },
  });

  const events: BreachEvent[] = breachEventsQ.data ?? [];

  // Derive filter options from data
  const sectors = useMemo(() => {
    const s = new Set<string>();
    events.forEach(e => e.sector && s.add(e.sector));
    return Array.from(s).sort();
  }, [events]);

  const countries = useMemo(() => {
    const c = new Set<string>();
    events.forEach(e => e.country && c.add(e.country));
    return Array.from(c).sort();
  }, [events]);

  // Filter events
  const filtered = useMemo(() => {
    return events.filter(e => {
      if (tab !== "all" && e.type !== tab) return false;
      if (typeFilter !== "all" && e.type !== typeFilter) return false;
      if (sectorFilter !== "all" && e.sector !== sectorFilter) return false;
      if (countryFilter !== "all" && e.country !== countryFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          e.victimName?.toLowerCase().includes(q) ||
          e.groupName?.toLowerCase().includes(q) ||
          e.description?.toLowerCase().includes(q) ||
          e.sector?.toLowerCase().includes(q) ||
          e.country?.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [events, tab, typeFilter, sectorFilter, countryFilter, search]);

  // Stats
  const stats = useMemo(() => {
    const now = new Date();
    const last24h = events.filter(e => (now.getTime() - new Date(e.publishedAt).getTime()) < 86400000).length;
    const last7d = events.filter(e => (now.getTime() - new Date(e.publishedAt).getTime()) < 604800000).length;
    const ransomwareCount = events.filter(e => e.type === "ransomware").length;
    const dataBreachCount = events.filter(e => e.type === "data_breach" || e.type === "data_leak").length;
    const uniqueGroups = new Set(events.map(e => e.groupName)).size;
    const uniqueCountries = new Set(events.filter(e => e.country).map(e => e.country)).size;
    return { total: events.length, last24h, last7d, ransomwareCount, dataBreachCount, uniqueGroups, uniqueCountries };
  }, [events]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Bell className="h-6 w-6 text-red-400" />
            Breach Events
          </h1>
          <p className="text-muted-foreground mt-1">
            Aggregated breach notifications and ransomware events from all intelligence sources
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => syncMutation.mutate()}
          disabled={syncMutation.isPending}
        >
          <RefreshCw className={`h-4 w-4 mr-2 ${syncMutation.isPending ? "animate-spin" : ""}`} />
          {syncMutation.isPending ? "Syncing..." : "Refresh Feed"}
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-white">{stats.total}</div>
            <div className="text-xs text-muted-foreground">Total Events</div>
          </CardContent>
        </Card>
        <Card className="bg-red-950/30 border-red-900/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-red-400">{stats.last24h}</div>
            <div className="text-xs text-muted-foreground">Last 24h</div>
          </CardContent>
        </Card>
        <Card className="bg-orange-950/30 border-orange-900/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-orange-400">{stats.last7d}</div>
            <div className="text-xs text-muted-foreground">Last 7 Days</div>
          </CardContent>
        </Card>
        <Card className="bg-red-950/30 border-red-900/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-red-400">{stats.ransomwareCount}</div>
            <div className="text-xs text-muted-foreground">Ransomware</div>
          </CardContent>
        </Card>
        <Card className="bg-yellow-950/30 border-yellow-900/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-yellow-400">{stats.dataBreachCount}</div>
            <div className="text-xs text-muted-foreground">Data Breaches</div>
          </CardContent>
        </Card>
        <Card className="bg-purple-950/30 border-purple-900/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-purple-400">{stats.uniqueGroups}</div>
            <div className="text-xs text-muted-foreground">Threat Groups</div>
          </CardContent>
        </Card>
        <Card className="bg-blue-950/30 border-blue-900/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-blue-400">{stats.uniqueCountries}</div>
            <div className="text-xs text-muted-foreground">Countries</div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={tab} onValueChange={setTab}>
        <div className="flex flex-col md:flex-row items-start md:items-center gap-3 mb-4">
          <TabsList className="bg-zinc-900/50">
            <TabsTrigger value="all">All Events</TabsTrigger>
            <TabsTrigger value="ransomware">Ransomware</TabsTrigger>
            <TabsTrigger value="data_breach">Data Breach</TabsTrigger>
            <TabsTrigger value="data_leak">Data Leak</TabsTrigger>
            <TabsTrigger value="incident">Incidents</TabsTrigger>
          </TabsList>

          {/* Filters */}
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search events..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9 w-[200px] bg-zinc-900/50 border-zinc-800"
              />
            </div>
            <Select value={sectorFilter} onValueChange={setSectorFilter}>
              <SelectTrigger className="w-[150px] bg-zinc-900/50 border-zinc-800">
                <SelectValue placeholder="Sector" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Sectors</SelectItem>
                {sectors.map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={countryFilter} onValueChange={setCountryFilter}>
              <SelectTrigger className="w-[150px] bg-zinc-900/50 border-zinc-800">
                <SelectValue placeholder="Country" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Countries</SelectItem>
                {countries.map(c => <SelectItem key={c} value={c}>{c}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Event List */}
        <TabsContent value={tab} className="mt-0">
          {breachEventsQ.isLoading ? (
            <div className="space-y-3">
              {[1,2,3,4,5].map(i => (
                <Card key={i} className="bg-zinc-900/50 border-zinc-800 animate-pulse">
                  <CardContent className="p-4 h-24" />
                </Card>
              ))}
            </div>
          ) : filtered.length === 0 ? (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-12 text-center">
                <Bell className="h-12 w-12 text-muted-foreground mx-auto mb-4 opacity-30" />
                <p className="text-muted-foreground">No breach events match your filters.</p>
                <p className="text-xs text-muted-foreground mt-2">Try adjusting your search or click "Refresh Feed" to sync latest data.</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              <p className="text-xs text-muted-foreground mb-2">{filtered.length} events</p>
              {filtered.map((event) => (
                <Card key={`${event.type}-${event.id}`} className="bg-zinc-900/50 border-zinc-800 hover:border-zinc-700 transition-colors cursor-pointer">
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-start gap-3 flex-1 min-w-0">
                        <div className="mt-1">{typeIcon(event.type)}</div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-semibold text-white truncate">{event.victimName}</span>
                            <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-red-500/50 text-red-400">
                              {event.groupName}
                            </Badge>
                            <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${severityColor(event.severity)}`}>
                              {typeLabel(event.type)}
                            </Badge>
                            {event.verified && (
                              <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-green-500/50 text-green-400">
                                Verified
                              </Badge>
                            )}
                          </div>
                          {event.description && (
                            <p className="text-sm text-muted-foreground mt-1 line-clamp-2">{event.description}</p>
                          )}
                          <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                            {event.sector && (
                              <span className="flex items-center gap-1">
                                <Building2 className="h-3 w-3" /> {event.sector}
                              </span>
                            )}
                            {event.country && (
                              <span className="flex items-center gap-1">
                                <Globe className="h-3 w-3" /> {event.country}
                              </span>
                            )}
                            <span className="flex items-center gap-1">
                              <Calendar className="h-3 w-3" /> {relativeTime(event.publishedAt)}
                            </span>
                            <span className="text-zinc-600">
                              {event.source}
                            </span>
                            {event.sourceUrl && (
                              <a
                                href={event.sourceUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="flex items-center gap-1 text-blue-400 hover:text-blue-300"
                                onClick={(e) => e.stopPropagation()}
                              >
                                <ExternalLink className="h-3 w-3" /> Source
                              </a>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="text-xs text-muted-foreground whitespace-nowrap">
                        {new Date(event.publishedAt).toLocaleDateString()}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
