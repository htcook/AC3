import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import {
  Shield, Globe, Target, AlertTriangle, ChevronRight, X,
  Crosshair, Eye, Clock, Fingerprint, Cpu, Layers
} from "lucide-react";
import { Button } from "@/components/ui/button";

// ─── Threat Level Badge ────────────────────────────────────────────
function ThreatBadge({ level }: { level: string | null }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/40",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/40",
    medium: "bg-amber-500/20 text-amber-400 border-amber-500/40",
    low: "bg-green-500/20 text-green-400 border-green-500/40",
  };
  const cls = colors[level || "medium"] || colors.medium;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 text-[10px] font-display tracking-wider border ${cls}`}>
      {(level || "MEDIUM").toUpperCase()}
    </span>
  );
}

// ─── Type Badge ────────────────────────────────────────────────────
function TypeBadge({ type }: { type: string }) {
  const labels: Record<string, string> = {
    apt: "APT",
    cybercrime: "CYBERCRIME",
    ransomware: "RANSOMWARE",
    hacktivist: "HACKTIVIST",
    access_broker: "ACCESS BROKER",
    influence_ops: "INFLUENCE OPS",
    unknown: "UNKNOWN",
  };
  const colors: Record<string, string> = {
    apt: "text-red-400",
    cybercrime: "text-purple-400",
    ransomware: "text-orange-400",
    hacktivist: "text-green-400",
    access_broker: "text-amber-400",
    influence_ops: "text-blue-400",
    unknown: "text-muted-foreground",
  };
  return (
    <span className={`text-[10px] font-display tracking-widest ${colors[type] || colors.unknown}`}>
      {labels[type] || type.toUpperCase()}
    </span>
  );
}

// ─── Actor Detail Modal (public, self-contained, no dashboard links) ────
function ActorDetailModal({ actorId, onClose }: { actorId: string; onClose: () => void }) {
  const { data: actor, isLoading } = trpc.platformStats.publicActorDetail.useQuery(
    { actorId },
    { staleTime: 10 * 60 * 1000 }
  );

  const techniques = useMemo(() => {
    if (!actor?.techniques || !Array.isArray(actor.techniques)) return [];
    return (actor.techniques as any[]).slice(0, 12);
  }, [actor]);

  const tools = useMemo(() => {
    if (!actor?.tools || !Array.isArray(actor.tools)) return [];
    return actor.tools as string[];
  }, [actor]);

  const malware = useMemo(() => {
    if (!actor?.malware || !Array.isArray(actor.malware)) return [];
    return actor.malware as string[];
  }, [actor]);

  const aliases = useMemo(() => {
    if (!actor?.aliases || !Array.isArray(actor.aliases)) return [];
    return actor.aliases as string[];
  }, [actor]);

  const sectors = useMemo(() => {
    if (!actor?.targetSectors || !Array.isArray(actor.targetSectors)) return [];
    return actor.targetSectors as string[];
  }, [actor]);

  const regions = useMemo(() => {
    if (!actor?.targetRegions || !Array.isArray(actor.targetRegions)) return [];
    return actor.targetRegions as string[];
  }, [actor]);

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-card border-2 border-primary/50 w-full max-w-2xl mx-4 max-h-[85vh] overflow-hidden flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-border">
          <div className="flex items-center gap-3 min-w-0">
            <Shield className="w-6 h-6 text-primary flex-shrink-0" />
            <div className="min-w-0">
              <h3 className="font-display text-xl tracking-wider truncate">
                {isLoading ? "Loading..." : actor?.name || "Unknown"}
              </h3>
              {actor && (
                <div className="flex items-center gap-2 mt-1">
                  <TypeBadge type={actor.type} />
                  <ThreatBadge level={actor.threatLevel} />
                  {actor.origin && (
                    <span className="text-[10px] text-muted-foreground font-display tracking-wider">
                      <Globe className="w-3 h-3 inline mr-1" />{actor.origin}
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors p-1 flex-shrink-0">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="overflow-y-auto p-6 space-y-6">
          {isLoading ? (
            <div className="space-y-3">
              {[1, 2, 3].map(i => (
                <div key={i} className="h-4 bg-muted animate-pulse rounded" style={{ width: `${80 - i * 15}%` }} />
              ))}
            </div>
          ) : actor ? (
            <>
              {/* Description */}
              {actor.description && (
                <div>
                  <p className="text-sm text-muted-foreground leading-relaxed">{actor.description}</p>
                </div>
              )}

              {/* Key Info Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {actor.sophistication && (
                  <div className="p-3 border border-border/50 bg-background/50">
                    <div className="text-[10px] font-display tracking-widest text-muted-foreground mb-1">SOPHISTICATION</div>
                    <div className="text-sm font-display tracking-wider">{actor.sophistication.toUpperCase()}</div>
                  </div>
                )}
                {actor.motivation && (
                  <div className="p-3 border border-border/50 bg-background/50">
                    <div className="text-[10px] font-display tracking-widest text-muted-foreground mb-1">MOTIVATION</div>
                    <div className="text-sm font-display tracking-wider">{actor.motivation.toUpperCase()}</div>
                  </div>
                )}
                {actor.firstSeen && (
                  <div className="p-3 border border-border/50 bg-background/50">
                    <div className="text-[10px] font-display tracking-widest text-muted-foreground mb-1">FIRST SEEN</div>
                    <div className="text-sm font-display tracking-wider">{actor.firstSeen}</div>
                  </div>
                )}
                {actor.lastActive && (
                  <div className="p-3 border border-border/50 bg-background/50">
                    <div className="text-[10px] font-display tracking-widest text-muted-foreground mb-1">LAST ACTIVE</div>
                    <div className="text-sm font-display tracking-wider">{actor.lastActive}</div>
                  </div>
                )}
              </div>

              {/* Aliases */}
              {aliases.length > 0 && (
                <div>
                  <h4 className="text-xs font-display tracking-[0.25em] text-muted-foreground mb-2">
                    <Fingerprint className="w-3 h-3 inline mr-1" />ALSO KNOWN AS
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {aliases.map((a, i) => (
                      <span key={i} className="px-2 py-0.5 text-[10px] font-display tracking-wider bg-muted/50 border border-border/50">
                        {a}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Target Sectors */}
              {sectors.length > 0 && (
                <div>
                  <h4 className="text-xs font-display tracking-[0.25em] text-muted-foreground mb-2">
                    <Target className="w-3 h-3 inline mr-1" />TARGET SECTORS
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {sectors.map((s, i) => (
                      <span key={i} className="px-2 py-0.5 text-[10px] font-display tracking-wider bg-primary/10 text-primary border border-primary/20">
                        {s}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Target Regions */}
              {regions.length > 0 && (
                <div>
                  <h4 className="text-xs font-display tracking-[0.25em] text-muted-foreground mb-2">
                    <Globe className="w-3 h-3 inline mr-1" />TARGET REGIONS
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {regions.map((r, i) => (
                      <span key={i} className="px-2 py-0.5 text-[10px] font-display tracking-wider bg-blue-500/10 text-blue-400 border border-blue-500/20">
                        {r}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* ATT&CK Techniques */}
              {techniques.length > 0 && (
                <div>
                  <h4 className="text-xs font-display tracking-[0.25em] text-muted-foreground mb-2">
                    <Crosshair className="w-3 h-3 inline mr-1" />MITRE ATT&CK TECHNIQUES ({techniques.length}{techniques.length >= 12 ? "+" : ""})
                  </h4>
                  <div className="grid grid-cols-2 gap-1.5">
                    {techniques.map((t: any, i: number) => (
                      <div key={i} className="flex items-center gap-2 px-2 py-1 bg-background/50 border border-border/30 text-[10px]">
                        <span className="text-primary font-mono">{t.id || t.technique_id}</span>
                        <span className="text-muted-foreground truncate">{t.name || t.technique_name}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Tools & Malware */}
              {(tools.length > 0 || malware.length > 0) && (
                <div className="grid sm:grid-cols-2 gap-4">
                  {tools.length > 0 && (
                    <div>
                      <h4 className="text-xs font-display tracking-[0.25em] text-muted-foreground mb-2">
                        <Cpu className="w-3 h-3 inline mr-1" />TOOLS
                      </h4>
                      <div className="flex flex-wrap gap-1.5">
                        {tools.map((t, i) => (
                          <span key={i} className="px-2 py-0.5 text-[10px] font-display tracking-wider bg-amber-500/10 text-amber-400 border border-amber-500/20">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {malware.length > 0 && (
                    <div>
                      <h4 className="text-xs font-display tracking-[0.25em] text-muted-foreground mb-2">
                        <AlertTriangle className="w-3 h-3 inline mr-1" />MALWARE
                      </h4>
                      <div className="flex flex-wrap gap-1.5">
                        {malware.map((m, i) => (
                          <span key={i} className="px-2 py-0.5 text-[10px] font-display tracking-wider bg-red-500/10 text-red-400 border border-red-500/20">
                            {m}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </>
          ) : (
            <p className="text-sm text-muted-foreground">Threat actor not found.</p>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-border text-center">
          <p className="text-[10px] text-muted-foreground font-display tracking-wider">
            THREAT INTELLIGENCE FROM ACE C3 — {(actor?.techniques as any[])?.length || 0} TECHNIQUES MAPPED
          </p>
        </div>
      </div>
    </div>
  );
}

// ─── Actor Card ────────────────────────────────────────────────────
function ActorCard({ actor, onClick }: {
  actor: {
    actorId: string;
    name: string;
    type: string;
    origin: string | null;
    threatLevel: string | null;
    sophistication: string | null;
    motivation: string | null;
    description: string | null;
    techniques: any;
  };
  onClick: () => void;
}) {
  const techniqueCount = Array.isArray(actor.techniques) ? actor.techniques.length : 0;

  return (
    <button
      onClick={onClick}
      className="w-full text-left p-4 border-2 border-border hover:border-primary/50 bg-card/50 hover:bg-card transition-all group"
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="min-w-0">
          <h4 className="font-display text-sm tracking-wider truncate group-hover:text-primary transition-colors">
            {actor.name}
          </h4>
          <div className="flex items-center gap-2 mt-1">
            <TypeBadge type={actor.type} />
            {actor.origin && (
              <span className="text-[10px] text-muted-foreground">
                <Globe className="w-3 h-3 inline mr-0.5" />{actor.origin}
              </span>
            )}
          </div>
        </div>
        <ThreatBadge level={actor.threatLevel} />
      </div>

      {actor.description && (
        <p className="text-[11px] text-muted-foreground leading-relaxed line-clamp-2 mb-2">
          {actor.description}
        </p>
      )}

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
          {techniqueCount > 0 && (
            <span><Crosshair className="w-3 h-3 inline mr-0.5" />{techniqueCount} TTPs</span>
          )}
          {actor.sophistication && (
            <span className="capitalize">{actor.sophistication}</span>
          )}
        </div>
        <ChevronRight className="w-3.5 h-3.5 text-muted-foreground group-hover:text-primary transition-colors" />
      </div>
    </button>
  );
}

// ─── Filter Tabs ───────────────────────────────────────────────────
const FILTER_TABS = [
  { value: "all", label: "ALL" },
  { value: "apt", label: "APT" },
  { value: "ransomware", label: "RANSOMWARE" },
  { value: "cybercrime", label: "CYBERCRIME" },
  { value: "hacktivist", label: "HACKTIVIST" },
];

// ═══════════════════════════════════════════════════════════════════
//  MAIN FEED COMPONENT
// ═══════════════════════════════════════════════════════════════════
export default function ThreatActorFeed() {
  const [activeFilter, setActiveFilter] = useState("all");
  const [selectedActorId, setSelectedActorId] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);

  const { data, isLoading } = trpc.platformStats.recentThreatActors.useQuery(
    { limit: 50 },
    { staleTime: 5 * 60 * 1000, refetchOnWindowFocus: false }
  );

  const filteredActors = useMemo(() => {
    if (!data?.actors) return [];
    let actors = data.actors;
    if (activeFilter !== "all") {
      actors = actors.filter(a => a.type === activeFilter);
    }
    // Sort by threat level: critical first, then high, medium, low
    const levelOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    actors = [...actors].sort((a, b) => (levelOrder[a.threatLevel || "medium"] ?? 3) - (levelOrder[b.threatLevel || "medium"] ?? 3));
    return showAll ? actors : actors.slice(0, 12);
  }, [data, activeFilter, showAll]);

  const totalFiltered = useMemo(() => {
    if (!data?.actors) return 0;
    if (activeFilter === "all") return data.total;
    return data.actors.filter(a => a.type === activeFilter).length;
  }, [data, activeFilter]);

  return (
    <section className="py-20">
      <div className="container">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 mb-8">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 border border-primary/40 text-primary text-xs font-display tracking-widest mb-4">
              <Eye className="w-3.5 h-3.5" />
              LIVE INTELLIGENCE
            </div>
            <h2 className="text-4xl sm:text-5xl font-display mb-2">THREAT ACTOR FEED</h2>
            <p className="text-lg text-muted-foreground max-w-2xl">
              Browse {data?.total?.toLocaleString() || "1,700"}+ threat actor profiles from our continuously enriched intelligence database.
              Click any actor for full details including ATT&CK techniques, tools, and malware.
            </p>
          </div>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Layers className="w-4 h-4 text-primary" />
            <span className="font-display tracking-wider">{totalFiltered.toLocaleString()} ACTORS</span>
          </div>
        </div>

        {/* Filter Tabs */}
        <div className="flex flex-wrap gap-2 mb-8">
          {FILTER_TABS.map(tab => (
            <button
              key={tab.value}
              onClick={() => { setActiveFilter(tab.value); setShowAll(false); }}
              className={`px-4 py-2 text-xs font-display tracking-widest border-2 transition-colors ${
                activeFilter === tab.value
                  ? "border-primary bg-primary/10 text-primary"
                  : "border-border text-muted-foreground hover:border-primary/40 hover:text-foreground"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Actor Grid */}
        {isLoading ? (
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="p-4 border-2 border-border bg-card/30 animate-pulse">
                <div className="h-4 bg-muted rounded w-3/4 mb-3" />
                <div className="h-3 bg-muted rounded w-1/2 mb-2" />
                <div className="h-3 bg-muted rounded w-full mb-1" />
                <div className="h-3 bg-muted rounded w-2/3" />
              </div>
            ))}
          </div>
        ) : (
          <>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
              {filteredActors.map(actor => (
                <ActorCard
                  key={actor.actorId}
                  actor={actor}
                  onClick={() => setSelectedActorId(actor.actorId)}
                />
              ))}
            </div>

            {/* Show More */}
            {!showAll && totalFiltered > 12 && (
              <div className="text-center mt-8">
                <Button
                  variant="outline"
                  onClick={() => setShowAll(true)}
                  className="font-display tracking-wider border-2 border-primary text-primary hover:bg-primary hover:text-white"
                >
                  SHOW ALL {totalFiltered.toLocaleString()} {activeFilter === "all" ? "THREAT ACTORS" : activeFilter.toUpperCase() + " ACTORS"}
                  <ChevronRight className="w-4 h-4 ml-1" />
                </Button>
              </div>
            )}
          </>
        )}

        {/* Detail Modal */}
        {selectedActorId && (
          <ActorDetailModal
            actorId={selectedActorId}
            onClose={() => setSelectedActorId(null)}
          />
        )}
      </div>
    </section>
  );
}
