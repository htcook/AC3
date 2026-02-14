import { useState, useMemo } from "react";
import { useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Shield,
  Search,
  Globe,
  Target,
  ChevronRight,
  Loader2,
  Users,
  AlertTriangle,
  Crosshair,
  Filter,
  RefreshCw,
} from "lucide-react";
import { toast } from "sonner";

function ThreatLevelBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-green-500/20 text-green-400 border-green-500/30",
  };
  return (
    <Badge className={`${colors[level] || colors.medium} border text-[10px]`}>
      {level?.toUpperCase()}
    </Badge>
  );
}

function ActorTypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    apt: "bg-red-500/20 text-red-400 border-red-500/30",
    cybercrime: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    ransomware: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    hacktivist: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
    unknown: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  };
  return (
    <Badge className={`${colors[type] || colors.unknown} border text-[10px]`}>
      {type?.toUpperCase()}
    </Badge>
  );
}

const ACTOR_ICON_COLORS: Record<string, string> = {
  apt: "bg-red-500/20 text-red-400",
  cybercrime: "bg-amber-500/20 text-amber-400",
  ransomware: "bg-purple-500/20 text-purple-400",
  hacktivist: "bg-cyan-500/20 text-cyan-400",
  unknown: "bg-gray-500/20 text-gray-400",
};

export default function ThreatActors() {
  const [, setLocation] = useLocation();
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [originFilter, setOriginFilter] = useState("all");
  const [threatFilter, setThreatFilter] = useState("all");
  const [page, setPage] = useState(0);
  const pageSize = 50;

  const utils = trpc.useUtils();
  const { data: stats } = trpc.threatActorDb.stats.useQuery();
  const syncCaldera = trpc.threatActorDb.syncCaldera.useMutation({
    onSuccess: (result) => {
      toast.success(`Caldera Sync Complete: ${result.created} created, ${result.updated} updated, ${result.abilitiesSynced} abilities synced from ${result.totalCalderaAdversaries} adversaries`);
      utils.threatActorDb.list.invalidate();
      utils.threatActorDb.stats.invalidate();
    },
    onError: (err) => {
      toast.error(`Sync Failed: ${err.message}`);
    },
  });
  const { data: actors, isLoading } = trpc.threatActorDb.list.useQuery({
    type: typeFilter !== "all" ? typeFilter : undefined,
    origin: originFilter !== "all" ? originFilter : undefined,
    threatLevel: threatFilter !== "all" ? threatFilter : undefined,
    search: search || undefined,
    limit: pageSize,
    offset: page * pageSize,
  });

  // Extract unique origins from stats
  const origins = useMemo(() => {
    if (!stats?.byOrigin) return [];
    return (stats.byOrigin as Array<{ origin: string; count: number }>)
      .sort((a, b) => b.count - a.count)
      .map(o => o.origin)
      .filter(Boolean);
  }, [stats]);

  const totalActors = actors?.total ?? stats?.total ?? 0;
  const totalPages = Math.ceil(totalActors / pageSize);

  return (
    <AppShell>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Shield className="w-6 h-6 text-red-400" />
              Threat Actor Database
            </h1>
            <p className="text-muted-foreground mt-1">
              {totalActors} threat actors from MITRE ATT&CK, CrowdStrike, Unit 42, Mandiant, and more
            </p>
          </div>
          <Button
            onClick={() => syncCaldera.mutate()}
            disabled={syncCaldera.isPending}
            className="bg-teal-600 hover:bg-teal-700"
          >
            {syncCaldera.isPending ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <RefreshCw className="w-4 h-4 mr-2" />
            )}
            Sync Caldera
          </Button>
        </div>

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <Card className="bg-card/50">
              <CardContent className="p-3 text-center">
                <div className="text-2xl font-bold">{stats.total}</div>
                <div className="text-xs text-muted-foreground">Total Actors</div>
              </CardContent>
            </Card>
            {(stats.byType as Array<{ type: string; count: number }>)?.map((t) => (
              <Card key={t.type} className="bg-card/50">
                <CardContent className="p-3 text-center">
                  <div className={`text-2xl font-bold ${
                    t.type === "apt" ? "text-red-400" :
                    t.type === "cybercrime" ? "text-amber-400" :
                    t.type === "ransomware" ? "text-purple-400" :
                    t.type === "hacktivist" ? "text-cyan-400" : ""
                  }`}>{t.count}</div>
                  <div className="text-xs text-muted-foreground capitalize">{t.type}</div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Filters */}
        <div className="flex flex-wrap gap-3 items-center">
          <div className="relative flex-1 min-w-[250px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search by name, alias, or description..."
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(0); }}
              className="pl-10"
            />
          </div>
          <Select value={typeFilter} onValueChange={(v) => { setTypeFilter(v); setPage(0); }}>
            <SelectTrigger className="w-[150px]">
              <Filter className="w-4 h-4 mr-1" />
              <SelectValue placeholder="Type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Types</SelectItem>
              <SelectItem value="apt">APT</SelectItem>
              <SelectItem value="cybercrime">Cybercrime</SelectItem>
              <SelectItem value="ransomware">Ransomware</SelectItem>
              <SelectItem value="hacktivist">Hacktivist</SelectItem>
            </SelectContent>
          </Select>
          <Select value={originFilter} onValueChange={(v) => { setOriginFilter(v); setPage(0); }}>
            <SelectTrigger className="w-[150px]">
              <Globe className="w-4 h-4 mr-1" />
              <SelectValue placeholder="Origin" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Origins</SelectItem>
              {origins.map(o => (
                <SelectItem key={o} value={o}>{o}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={threatFilter} onValueChange={(v) => { setThreatFilter(v); setPage(0); }}>
            <SelectTrigger className="w-[150px]">
              <AlertTriangle className="w-4 h-4 mr-1" />
              <SelectValue placeholder="Threat Level" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Levels</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Actor Grid */}
        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
          </div>
        ) : (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {actors?.actors?.map((actor) => {
                const aliases = (actor.aliases as string[]) || [];
                const sectors = (actor.targetSectors as string[]) || [];
                const techniques = (actor.techniques as any[]) || [];
                return (
                  <Card
                    key={actor.actorId}
                    className="bg-card/50 hover:bg-card/80 cursor-pointer transition-all group border-border/50 hover:border-primary/30"
                    onClick={() => setLocation(`/threat-actors/${actor.actorId}`)}
                  >
                    <CardContent className="p-4">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${ACTOR_ICON_COLORS[actor.type] || ACTOR_ICON_COLORS.unknown}`}>
                            <Shield className="w-4 h-4" />
                          </div>
                          <div>
                            <h3 className="font-semibold text-sm group-hover:text-primary transition-colors">
                              {actor.name}
                            </h3>
                            <div className="flex items-center gap-1 mt-0.5">
                              <ActorTypeBadge type={actor.type} />
                              <ThreatLevelBadge level={actor.threatLevel || "medium"} />
                            </div>
                          </div>
                        </div>
                        <ChevronRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
                      </div>

                      {aliases.length > 0 && (
                        <div className="flex flex-wrap gap-1 mb-2">
                          {aliases.slice(0, 3).map((a, i) => (
                            <Badge key={i} variant="secondary" className="text-[10px]">{a}</Badge>
                          ))}
                          {aliases.length > 3 && (
                            <Badge variant="secondary" className="text-[10px]">+{aliases.length - 3}</Badge>
                          )}
                        </div>
                      )}

                      <p className="text-xs text-muted-foreground line-clamp-2 mb-2">
                        {actor.description?.substring(0, 120) || "No description available"}
                        {(actor.description?.length || 0) > 120 ? "..." : ""}
                      </p>

                      <div className="flex items-center justify-between text-xs text-muted-foreground">
                        <div className="flex items-center gap-3">
                          {actor.origin && (
                            <span className="flex items-center gap-1">
                              <Globe className="w-3 h-3" /> {actor.origin}
                            </span>
                          )}
                          {techniques.length > 0 && (
                            <span className="flex items-center gap-1">
                              <Target className="w-3 h-3" /> {techniques.length} techniques
                            </span>
                          )}
                        </div>
                        {sectors.length > 0 && (
                          <span className="flex items-center gap-1">
                            <Crosshair className="w-3 h-3" /> {sectors.length} sectors
                          </span>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page === 0}
                  onClick={() => setPage(p => p - 1)}
                >
                  Previous
                </Button>
                <span className="text-sm text-muted-foreground">
                  Page {page + 1} of {totalPages}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page >= totalPages - 1}
                  onClick={() => setPage(p => p + 1)}
                >
                  Next
                </Button>
              </div>
            )}

            {actors?.actors?.length === 0 && (
              <div className="text-center py-20">
                <Users className="w-12 h-12 text-muted-foreground mx-auto mb-3" />
                <h3 className="text-lg font-semibold">No threat actors found</h3>
                <p className="text-muted-foreground">Try adjusting your search or filters</p>
              </div>
            )}
          </>
        )}
      </div>
    </AppShell>
  );
}
