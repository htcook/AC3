import { trpc } from "@/lib/trpc";
import { useState, useMemo } from "react";
import { Grid3X3, X, ExternalLink, ChevronDown, ChevronUp, Loader2 } from "lucide-react";
import { Link } from "wouter";

/**
 * TechniqueHeatmapWidget — Aggregated MITRE ATT&CK technique usage heatmap.
 * Shows technique frequency across all threat actors grouped by tactic columns.
 * Click a cell to see which actors use that technique.
 */

interface TechniqueCell {
  id: string;
  name: string;
  count: number;
  actors: string[];
}

interface TacticColumn {
  tacticId: string;
  tacticKey: string;
  tacticName: string;
  order: number;
  techniques: TechniqueCell[];
  totalTechniques: number;
  totalUsage: number;
}

function getHeatColor(count: number, maxCount: number): string {
  if (maxCount === 0) return "bg-cyan-950/30";
  const ratio = count / maxCount;
  if (ratio >= 0.75) return "bg-red-500/80 text-white";
  if (ratio >= 0.5) return "bg-orange-500/60 text-white";
  if (ratio >= 0.25) return "bg-cyan-500/50 text-white";
  if (ratio >= 0.1) return "bg-cyan-700/40 text-cyan-100";
  return "bg-cyan-900/30 text-cyan-200";
}

function getHeatBorder(count: number, maxCount: number): string {
  if (maxCount === 0) return "border-cyan-900/20";
  const ratio = count / maxCount;
  if (ratio >= 0.75) return "border-red-500/50";
  if (ratio >= 0.5) return "border-orange-500/40";
  if (ratio >= 0.25) return "border-cyan-500/30";
  return "border-cyan-800/20";
}

export default function TechniqueHeatmapWidget() {
  const { data, isLoading, error } = trpc.threatIntel.techniqueHeatmap.useQuery(undefined, {
    staleTime: 300_000, // 5 min
    refetchOnWindowFocus: false,
  });

  const [selectedTechnique, setSelectedTechnique] = useState<TechniqueCell | null>(null);
  const [expandedTactics, setExpandedTactics] = useState<Set<string>>(new Set());
  const [showAll, setShowAll] = useState(false);

  // Limit techniques shown per tactic unless expanded
  const MAX_TECHNIQUES_PER_TACTIC = 8;

  const toggleTacticExpand = (tacticKey: string) => {
    setExpandedTactics(prev => {
      const next = new Set(prev);
      if (next.has(tacticKey)) next.delete(tacticKey);
      else next.add(tacticKey);
      return next;
    });
  };

  // Filter tactics that have at least one technique
  const activeTactics = useMemo(() => {
    if (!data) return [];
    return data.tactics.filter(t => t.totalTechniques > 0);
  }, [data]);

  if (isLoading) {
    return (
      <div className="space-y-3">
        <div className="flex items-center gap-2 mb-3">
          <Grid3X3 className="w-4 h-4 text-cyan-400" />
          <h3 className="font-display text-sm tracking-wider text-cyan-400">TECHNIQUE HEATMAP</h3>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7 gap-2">
          {Array.from({ length: 7 }).map((_, i) => (
            <div key={i} className="bg-card border border-border p-3 animate-pulse">
              <div className="h-3 bg-muted rounded w-20 mb-2" />
              <div className="space-y-1">
                {Array.from({ length: 4 }).map((_, j) => (
                  <div key={j} className="h-6 bg-muted/50 rounded" />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="bg-card border border-red-500/30 p-4 text-center">
        <p className="text-sm text-red-400">Failed to load technique heatmap</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Grid3X3 className="w-4 h-4 text-cyan-400" />
          <h3 className="font-display text-sm tracking-wider text-cyan-400">MITRE ATT&CK TECHNIQUE HEATMAP</h3>
        </div>
        <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
          <span>{data.totalTechniques} techniques</span>
          <span className="text-cyan-500/50">|</span>
          <span>{data.totalActorsWithTechniques}/{data.totalActors} actors with TTPs</span>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
        <span>Frequency:</span>
        <div className="flex items-center gap-1">
          <div className="w-4 h-3 bg-cyan-900/30 border border-cyan-800/20 rounded-sm" />
          <span>Low</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-4 h-3 bg-cyan-700/40 border border-cyan-800/20 rounded-sm" />
          <span>Med</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-4 h-3 bg-cyan-500/50 border border-cyan-500/30 rounded-sm" />
          <span>High</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-4 h-3 bg-orange-500/60 border border-orange-500/40 rounded-sm" />
          <span>Very High</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-4 h-3 bg-red-500/80 border border-red-500/50 rounded-sm" />
          <span>Critical</span>
        </div>
      </div>

      {/* Heatmap Grid */}
      <div className="overflow-x-auto">
        <div className="grid gap-2" style={{
          gridTemplateColumns: `repeat(${Math.min(activeTactics.length, showAll ? activeTactics.length : 7)}, minmax(140px, 1fr))`,
        }}>
          {(showAll ? activeTactics : activeTactics.slice(0, 7)).map((tactic) => {
            const isExpanded = expandedTactics.has(tactic.tacticKey);
            const visibleTechniques = isExpanded
              ? tactic.techniques
              : tactic.techniques.slice(0, MAX_TECHNIQUES_PER_TACTIC);
            const hasMore = tactic.techniques.length > MAX_TECHNIQUES_PER_TACTIC;

            return (
              <div key={tactic.tacticKey} className="bg-card/50 border border-border rounded-sm overflow-hidden">
                {/* Tactic Header */}
                <div className="bg-card border-b border-border px-2 py-1.5">
                  <div className="font-display text-[10px] tracking-wider text-cyan-400 truncate" title={tactic.tacticName}>
                    {tactic.tacticName.toUpperCase()}
                  </div>
                  <div className="text-[9px] text-muted-foreground">
                    {tactic.totalTechniques} techniques · {tactic.totalUsage} uses
                  </div>
                </div>

                {/* Technique Cells */}
                <div className="p-1 space-y-0.5">
                  {visibleTechniques.map((tech) => (
                    <button
                      key={tech.id}
                      onClick={() => setSelectedTechnique(
                        selectedTechnique?.id === tech.id ? null : tech
                      )}
                      className={`w-full text-left px-1.5 py-1 rounded-sm border transition-all text-[10px] leading-tight
                        ${getHeatColor(tech.count, data.maxCount)}
                        ${getHeatBorder(tech.count, data.maxCount)}
                        ${selectedTechnique?.id === tech.id ? 'ring-1 ring-cyan-400 ring-offset-1 ring-offset-background' : ''}
                        hover:brightness-110 cursor-pointer`}
                      title={`${tech.id}: ${tech.name} — ${tech.count} actor(s)`}
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span className="truncate font-mono">{tech.id}</span>
                        <span className="shrink-0 font-bold">{tech.count}</span>
                      </div>
                      <div className="truncate opacity-80 text-[9px]">{tech.name}</div>
                    </button>
                  ))}

                  {/* Expand/Collapse */}
                  {hasMore && (
                    <button
                      onClick={() => toggleTacticExpand(tactic.tacticKey)}
                      className="w-full text-center py-0.5 text-[9px] text-cyan-400 hover:text-cyan-300 transition-colors"
                    >
                      {isExpanded ? (
                        <span className="flex items-center justify-center gap-0.5">
                          <ChevronUp className="w-3 h-3" /> Show less
                        </span>
                      ) : (
                        <span className="flex items-center justify-center gap-0.5">
                          <ChevronDown className="w-3 h-3" /> +{tactic.techniques.length - MAX_TECHNIQUES_PER_TACTIC} more
                        </span>
                      )}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Show All / Show Less toggle */}
      {activeTactics.length > 7 && (
        <button
          onClick={() => setShowAll(!showAll)}
          className="text-[10px] text-cyan-400 hover:text-cyan-300 transition-colors"
        >
          {showAll ? `Show fewer tactics` : `Show all ${activeTactics.length} tactics`}
        </button>
      )}

      {/* Selected Technique Detail Panel */}
      {selectedTechnique && (
        <div className="bg-card border-2 border-cyan-500/30 p-3 rounded-sm animate-in fade-in slide-in-from-top-2 duration-200">
          <div className="flex items-center justify-between mb-2">
            <div>
              <span className="font-mono text-sm text-cyan-400">{selectedTechnique.id}</span>
              <span className="text-sm text-muted-foreground ml-2">— {selectedTechnique.name}</span>
            </div>
            <div className="flex items-center gap-2">
              <a
                href={`https://attack.mitre.org/techniques/${selectedTechnique.id.replace('.', '/')}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                <ExternalLink className="w-3 h-3" /> ATT&CK
              </a>
              <button onClick={() => setSelectedTechnique(null)} className="text-muted-foreground hover:text-foreground">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
          <div className="text-[10px] text-muted-foreground mb-2">
            Used by <span className="text-cyan-400 font-bold">{selectedTechnique.count}</span> threat actor(s)
          </div>
          <div className="flex flex-wrap gap-1">
            {selectedTechnique.actors.map((actor) => (
              <Link
                key={actor}
                href={`/threat-catalog/${encodeURIComponent(actor.toLowerCase().replace(/[^a-z0-9]/g, '-'))}`}
              >
                <span className="inline-block bg-cyan-950/50 border border-cyan-500/20 px-2 py-0.5 text-[10px] text-cyan-300 hover:bg-cyan-900/50 hover:border-cyan-500/40 transition-colors cursor-pointer rounded-sm">
                  {actor}
                </span>
              </Link>
            ))}
            {selectedTechnique.count > selectedTechnique.actors.length && (
              <span className="inline-block bg-muted/30 border border-border px-2 py-0.5 text-[10px] text-muted-foreground rounded-sm">
                +{selectedTechnique.count - selectedTechnique.actors.length} more
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
