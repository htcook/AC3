import { useState, useMemo } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Target,
  ZoomIn,
  ZoomOut,
  Filter,
  Download,
  Maximize2,
  X,
} from "lucide-react";

// ─── MITRE ATT&CK Enterprise Matrix Structure ───
const TACTICS = [
  { id: "reconnaissance", name: "Reconnaissance", shortName: "Recon", ta: "TA0043" },
  { id: "resource-development", name: "Resource Development", shortName: "Res Dev", ta: "TA0042" },
  { id: "initial-access", name: "Initial Access", shortName: "Init Access", ta: "TA0001" },
  { id: "execution", name: "Execution", shortName: "Execution", ta: "TA0002" },
  { id: "persistence", name: "Persistence", shortName: "Persist", ta: "TA0003" },
  { id: "privilege-escalation", name: "Privilege Escalation", shortName: "Priv Esc", ta: "TA0004" },
  { id: "defense-evasion", name: "Defense Evasion", shortName: "Def Evasion", ta: "TA0005" },
  { id: "credential-access", name: "Credential Access", shortName: "Cred Access", ta: "TA0006" },
  { id: "discovery", name: "Discovery", shortName: "Discovery", ta: "TA0007" },
  { id: "lateral-movement", name: "Lateral Movement", shortName: "Lat Move", ta: "TA0008" },
  { id: "collection", name: "Collection", shortName: "Collection", ta: "TA0009" },
  { id: "command-and-control", name: "Command and Control", shortName: "C2", ta: "TA0011" },
  { id: "exfiltration", name: "Exfiltration", shortName: "Exfil", ta: "TA0010" },
  { id: "impact", name: "Impact", shortName: "Impact", ta: "TA0040" },
];

// Color scale for technique scores (0-10)
function getScoreColor(score: number, isHighlighted: boolean): string {
  if (isHighlighted) return "bg-cyan-500/90 border-cyan-400 text-white";
  if (score >= 9) return "bg-red-600/90 border-red-500 text-white";
  if (score >= 7) return "bg-red-500/80 border-red-400 text-white";
  if (score >= 5) return "bg-orange-500/70 border-orange-400 text-white";
  if (score >= 3) return "bg-yellow-600/60 border-yellow-500 text-white";
  if (score >= 1) return "bg-blue-600/50 border-blue-500 text-white";
  return "bg-slate-600/40 border-slate-500 text-slate-200";
}

function getScoreGradient(score: number): string {
  if (score >= 9) return "#dc2626";
  if (score >= 7) return "#ef4444";
  if (score >= 5) return "#f97316";
  if (score >= 3) return "#eab308";
  if (score >= 1) return "#3b82f6";
  return "#64748b";
}

interface Technique {
  id: string;
  name: string;
  tactic: string;
  score?: number;
  description?: string;
}

interface AttackNavigatorProps {
  techniques: Technique[];
  actorName: string;
  onTechniqueClick?: (techniqueId: string) => void;
}

export default function AttackNavigator({
  techniques,
  actorName,
  onTechniqueClick,
}: AttackNavigatorProps) {
  const [zoom, setZoom] = useState(1);
  const [selectedTactic, setSelectedTactic] = useState<string>("all");
  const [hoveredTechnique, setHoveredTechnique] = useState<Technique | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [searchFilter, setSearchFilter] = useState("");

  // Group techniques by tactic
  const techniquesByTactic = useMemo(() => {
    const map: Record<string, Technique[]> = {};
    for (const t of techniques) {
      const tactic = t.tactic || "unknown";
      if (!map[tactic]) map[tactic] = [];
      map[tactic].push(t);
    }
    // Sort each tactic's techniques by score descending
    for (const key of Object.keys(map)) {
      map[key].sort((a, b) => (b.score || 0) - (a.score || 0));
    }
    return map;
  }, [techniques]);

  // Filter tactics
  const visibleTactics = useMemo(() => {
    if (selectedTactic === "all") return TACTICS;
    return TACTICS.filter((t) => t.id === selectedTactic);
  }, [selectedTactic]);

  // Filter techniques by search
  const filteredTechniquesByTactic = useMemo(() => {
    if (!searchFilter) return techniquesByTactic;
    const lower = searchFilter.toLowerCase();
    const filtered: Record<string, Technique[]> = {};
    for (const [tactic, techs] of Object.entries(techniquesByTactic)) {
      const matching = techs.filter(
        (t) =>
          t.id.toLowerCase().includes(lower) ||
          t.name.toLowerCase().includes(lower)
      );
      if (matching.length > 0) filtered[tactic] = matching;
    }
    return filtered;
  }, [techniquesByTactic, searchFilter]);

  // Max column height for layout
  const maxTechniquesInColumn = useMemo(() => {
    return Math.max(
      ...TACTICS.map((t) => filteredTechniquesByTactic[t.id]?.length || 0),
      1
    );
  }, [filteredTechniquesByTactic]);

  // Stats
  const totalTechniques = techniques.length;
  const coveredTactics = TACTICS.filter(
    (t) => (techniquesByTactic[t.id]?.length || 0) > 0
  ).length;
  const avgScore =
    techniques.length > 0
      ? (
          techniques.reduce((sum, t) => sum + (t.score || 0), 0) /
          techniques.length
        ).toFixed(1)
      : "0";
  const criticalCount = techniques.filter((t) => (t.score || 0) >= 7).length;

  const handleMouseEnter = (
    tech: Technique,
    e: React.MouseEvent<HTMLDivElement>
  ) => {
    const rect = e.currentTarget.getBoundingClientRect();
    setHoveredTechnique(tech);
    setTooltipPos({
      x: rect.left + rect.width / 2,
      y: rect.top - 10,
    });
  };

  const handleExportLayer = () => {
    const layer = {
      name: `${actorName} - ATT&CK Coverage`,
      versions: { attack: "14", navigator: "4.9.5", layer: "4.5" },
      domain: "enterprise-attack",
      description: `MITRE ATT&CK technique coverage for ${actorName}`,
      filters: { platforms: ["Windows", "Linux", "macOS", "Network", "Cloud"] },
      sorting: 3,
      layout: { layout: "side", aggregateFunction: "average", showID: true, showName: true, showAggregateScores: true, countUnscored: false, expandedSubtechniques: "annotated" },
      hideDisabled: false,
      techniques: techniques.map((t) => ({
        techniqueID: t.id,
        tactic: t.tactic?.replace(/-/g, "-"),
        color: getScoreGradient(t.score || 0),
        comment: t.description || "",
        enabled: true,
        metadata: [],
        links: [],
        showSubtechniques: false,
        score: t.score || 0,
      })),
      gradient: {
        colors: ["#3b82f6", "#eab308", "#f97316", "#dc2626"],
        minValue: 0,
        maxValue: 10,
      },
      legendItems: [
        { label: "Critical (9-10)", color: "#dc2626" },
        { label: "High (7-8)", color: "#ef4444" },
        { label: "Medium (5-6)", color: "#f97316" },
        { label: "Low (3-4)", color: "#eab308" },
        { label: "Minimal (1-2)", color: "#3b82f6" },
      ],
      metadata: [],
      links: [],
      showTacticRowBackground: true,
      tacticRowBackground: "#1e293b",
      selectTechniquesAcrossTactics: true,
      selectSubtechniquesWithParent: false,
      selectVisibleTechniques: false,
    };

    const blob = new Blob([JSON.stringify(layer, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${actorName.replace(/\s+/g, "_")}_attack_layer.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const containerClass = isFullscreen
    ? "fixed inset-0 z-50 bg-background p-4 overflow-auto"
    : "";

  return (
    <div className={containerClass}>
      <Card className="bg-card/50 border-border">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <CardTitle className="text-lg flex items-center gap-2">
              <Target className="w-5 h-5 text-red-400" />
              MITRE ATT&CK Navigator
            </CardTitle>
            <div className="flex items-center gap-2 flex-wrap">
              {/* Search */}
              <input
                type="text"
                placeholder="Search techniques..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="h-8 px-3 text-sm bg-muted/50 border border-border rounded-md w-40 focus:outline-none focus:ring-1 focus:ring-primary"
              />
              {/* Tactic filter */}
              <Select value={selectedTactic} onValueChange={setSelectedTactic}>
                <SelectTrigger className="h-8 w-40 text-xs">
                  <Filter className="w-3 h-3 mr-1" />
                  <SelectValue placeholder="All Tactics" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Tactics</SelectItem>
                  {TACTICS.map((t) => (
                    <SelectItem key={t.id} value={t.id}>
                      {t.name} ({techniquesByTactic[t.id]?.length || 0})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {/* Zoom */}
              <div className="flex items-center gap-1 border border-border rounded-md">
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  onClick={() => setZoom(Math.max(0.5, zoom - 0.1))}
                >
                  <ZoomOut className="w-3 h-3" />
                </Button>
                <span className="text-xs w-10 text-center">
                  {Math.round(zoom * 100)}%
                </span>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  onClick={() => setZoom(Math.min(2, zoom + 0.1))}
                >
                  <ZoomIn className="w-3 h-3" />
                </Button>
              </div>
              {/* Export */}
              <Button
                variant="outline"
                size="sm"
                className="h-8 text-xs"
                onClick={handleExportLayer}
              >
                <Download className="w-3 h-3 mr-1" /> Export Layer
              </Button>
              {/* Fullscreen */}
              <Button
                variant="outline"
                size="icon"
                className="h-8 w-8"
                onClick={() => setIsFullscreen(!isFullscreen)}
              >
                {isFullscreen ? (
                  <X className="w-3 h-3" />
                ) : (
                  <Maximize2 className="w-3 h-3" />
                )}
              </Button>
            </div>
          </div>

          {/* Stats bar */}
          <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
            <span>
              <strong className="text-foreground">{totalTechniques}</strong>{" "}
              techniques
            </span>
            <span>
              <strong className="text-foreground">{coveredTactics}</strong>/14
              tactics covered
            </span>
            <span>
              Avg score:{" "}
              <strong className="text-foreground">{avgScore}</strong>
            </span>
            <span>
              <strong className="text-red-400">{criticalCount}</strong> critical
            </span>
            {/* Legend */}
            <div className="flex items-center gap-2 ml-auto">
              <span className="text-[10px]">Score:</span>
              {[
                { label: "Critical", color: "bg-red-600" },
                { label: "High", color: "bg-red-500" },
                { label: "Medium", color: "bg-orange-500" },
                { label: "Low", color: "bg-yellow-600" },
                { label: "Minimal", color: "bg-blue-600" },
              ].map((item) => (
                <div key={item.label} className="flex items-center gap-1">
                  <div className={`w-2.5 h-2.5 rounded-sm ${item.color}`} />
                  <span className="text-[10px]">{item.label}</span>
                </div>
              ))}
            </div>
          </div>
        </CardHeader>

        <CardContent className="p-2">
          {techniques.length === 0 ? (
            <div className="text-center py-16 text-muted-foreground">
              <Target className="w-12 h-12 mx-auto mb-3 opacity-30" />
              <p className="text-sm">
                No technique data available. Click "Enrich with LLM" to
                populate ATT&CK techniques.
              </p>
            </div>
          ) : (
            <div
              className="overflow-x-auto"
              style={{ transform: `scale(${zoom})`, transformOrigin: "top left" }}
            >
              {/* Matrix Grid */}
              <div
                className="grid gap-[2px]"
                style={{
                  gridTemplateColumns: `repeat(${visibleTactics.length}, minmax(120px, 1fr))`,
                }}
              >
                {/* Tactic Headers */}
                {visibleTactics.map((tactic) => {
                  const count =
                    filteredTechniquesByTactic[tactic.id]?.length || 0;
                  const hasTechniques = count > 0;
                  return (
                    <div
                      key={tactic.id}
                      className={`text-center p-2 rounded-t-md border-b-2 ${
                        hasTechniques
                          ? "bg-slate-800 border-red-500/60"
                          : "bg-slate-900/50 border-slate-700/30"
                      }`}
                    >
                      <div
                        className={`text-[11px] font-bold leading-tight ${
                          hasTechniques
                            ? "text-slate-100"
                            : "text-slate-500"
                        }`}
                      >
                        {tactic.shortName}
                      </div>
                      <div className="text-[9px] text-slate-400 mt-0.5">
                        {tactic.ta}
                      </div>
                      {hasTechniques && (
                        <Badge
                          variant="secondary"
                          className="text-[9px] h-4 mt-1 bg-red-500/20 text-red-300"
                        >
                          {count}
                        </Badge>
                      )}
                    </div>
                  );
                })}

                {/* Technique Cells */}
                {visibleTactics.map((tactic) => {
                  const techs =
                    filteredTechniquesByTactic[tactic.id] || [];
                  return (
                    <div
                      key={`col-${tactic.id}`}
                      className="flex flex-col gap-[2px]"
                    >
                      {techs.map((tech) => {
                        const score = tech.score || 0;
                        const isHovered =
                          hoveredTechnique?.id === tech.id;
                        const isSearchMatch =
                          searchFilter &&
                          (tech.id
                            .toLowerCase()
                            .includes(searchFilter.toLowerCase()) ||
                            tech.name
                              .toLowerCase()
                              .includes(searchFilter.toLowerCase()));
                        return (
                          <div
                            key={tech.id}
                            className={`
                              relative px-1.5 py-1 rounded-sm border cursor-pointer
                              transition-all duration-150 group
                              ${getScoreColor(score, isSearchMatch || false)}
                              ${isHovered ? "ring-2 ring-white/60 scale-105 z-10" : ""}
                              hover:ring-1 hover:ring-white/40 hover:scale-[1.02]
                            `}
                            onMouseEnter={(e) => handleMouseEnter(tech, e)}
                            onMouseLeave={() => setHoveredTechnique(null)}
                            onClick={() => onTechniqueClick?.(tech.id)}
                          >
                            <div className="text-[10px] font-mono font-bold leading-tight truncate">
                              {tech.id}
                            </div>
                            <div className="text-[9px] leading-tight truncate opacity-80">
                              {tech.name}
                            </div>
                            {score > 0 && (
                              <div className="absolute top-0.5 right-0.5 text-[8px] font-bold opacity-70">
                                {score}
                              </div>
                            )}
                          </div>
                        );
                      })}
                      {/* Empty state for tactics with no techniques */}
                      {techs.length === 0 && (
                        <div className="px-1.5 py-3 rounded-sm border border-dashed border-slate-700/30 text-center">
                          <span className="text-[9px] text-slate-600">
                            No coverage
                          </span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Floating Tooltip */}
      {hoveredTechnique && (
        <div
          className="fixed z-[100] pointer-events-none"
          style={{
            left: `${tooltipPos.x}px`,
            top: `${tooltipPos.y}px`,
            transform: "translate(-50%, -100%)",
          }}
        >
          <div className="bg-slate-900 border border-slate-600 rounded-lg shadow-xl p-3 max-w-xs">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-mono font-bold text-cyan-400">
                {hoveredTechnique.id}
              </span>
              <Badge
                variant="outline"
                className="text-[9px] h-4"
                style={{
                  borderColor: getScoreGradient(hoveredTechnique.score || 0),
                  color: getScoreGradient(hoveredTechnique.score || 0),
                }}
              >
                Score: {hoveredTechnique.score || 0}
              </Badge>
            </div>
            <div className="text-sm font-semibold text-white mb-1">
              {hoveredTechnique.name}
            </div>
            <div className="text-[10px] text-slate-300 capitalize mb-1">
              Tactic: {hoveredTechnique.tactic?.replace(/-/g, " ")}
            </div>
            {hoveredTechnique.description && (
              <div className="text-[10px] text-slate-400 line-clamp-3">
                {hoveredTechnique.description}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tactic Coverage Bar (bottom summary) */}
      {techniques.length > 0 && (
        <div className="mt-3 px-2">
          <div className="text-[10px] text-muted-foreground mb-1">
            Tactic Coverage Distribution
          </div>
          <div className="flex gap-[2px] h-6 rounded-md overflow-hidden">
            {TACTICS.map((tactic) => {
              const count = techniquesByTactic[tactic.id]?.length || 0;
              const pct =
                totalTechniques > 0
                  ? (count / totalTechniques) * 100
                  : 0;
              if (pct === 0) return null;
              const maxScore = Math.max(
                ...(techniquesByTactic[tactic.id]?.map(
                  (t) => t.score || 0
                ) || [0])
              );
              return (
                <div
                  key={tactic.id}
                  className="relative group cursor-pointer transition-all hover:opacity-90"
                  style={{
                    width: `${Math.max(pct, 2)}%`,
                    backgroundColor: getScoreGradient(maxScore),
                    opacity: 0.8,
                  }}
                  title={`${tactic.name}: ${count} techniques (${pct.toFixed(1)}%)`}
                >
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-[8px] font-bold text-white/90 truncate px-0.5">
                      {count > 0 ? tactic.shortName : ""}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
