import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Grid3X3, Shield, AlertTriangle } from "lucide-react";

// Standard MITRE ATT&CK Enterprise tactic order
const TACTICS = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

const TACTIC_COLORS: Record<string, { bg: string; header: string }> = {
  "Reconnaissance":        { bg: "bg-slate-500/20",    header: "bg-slate-600" },
  "Resource Development":  { bg: "bg-gray-500/20",     header: "bg-gray-600" },
  "Initial Access":        { bg: "bg-red-500/20",      header: "bg-red-700" },
  "Execution":             { bg: "bg-orange-500/20",   header: "bg-orange-600" },
  "Persistence":           { bg: "bg-amber-500/20",    header: "bg-amber-700" },
  "Privilege Escalation":  { bg: "bg-yellow-500/20",   header: "bg-yellow-700" },
  "Defense Evasion":       { bg: "bg-lime-500/20",     header: "bg-lime-700" },
  "Credential Access":     { bg: "bg-emerald-500/20",  header: "bg-emerald-700" },
  "Discovery":             { bg: "bg-teal-500/20",     header: "bg-teal-600" },
  "Lateral Movement":      { bg: "bg-cyan-500/20",     header: "bg-cyan-700" },
  "Collection":            { bg: "bg-sky-500/20",      header: "bg-sky-600" },
  "Command and Control":   { bg: "bg-blue-500/20",     header: "bg-blue-700" },
  "Exfiltration":          { bg: "bg-indigo-500/20",   header: "bg-indigo-700" },
  "Impact":                { bg: "bg-purple-500/20",    header: "bg-purple-700" },
};

interface Technique {
  id: string;
  name: string;
  tactic: string;
}

interface MatrixItem {
  ksiId: string;
  ksiTitle: string;
  techniques: Technique[];
}

interface AttackMatrixGridProps {
  matrixData: MatrixItem[];
  onTechniqueClick?: (techniqueId: string) => void;
}

export default function AttackMatrixGrid({ matrixData, onTechniqueClick }: AttackMatrixGridProps) {
  const [hoveredTechnique, setHoveredTechnique] = useState<string | null>(null);

  // Build technique-to-KSI mapping and group by tactic
  const { tacticColumns, techniqueKsiMap, stats } = useMemo(() => {
    const techMap = new Map<string, { technique: Technique; ksiIds: string[]; ksiTitles: string[] }>();
    const columns: Record<string, { id: string; name: string; ksiCount: number }[]> = {};

    // Initialize columns
    for (const tactic of TACTICS) {
      columns[tactic] = [];
    }

    // Process all matrix items
    for (const item of matrixData) {
      for (const tech of item.techniques) {
        const key = tech.id;
        if (!techMap.has(key)) {
          techMap.set(key, { technique: tech, ksiIds: [], ksiTitles: [] });
        }
        const entry = techMap.get(key)!;
        if (!entry.ksiIds.includes(item.ksiId)) {
          entry.ksiIds.push(item.ksiId);
          entry.ksiTitles.push(item.ksiTitle);
        }
      }
    }

    // Populate columns
    for (const [, entry] of techMap) {
      const tactic = entry.technique.tactic;
      if (columns[tactic]) {
        columns[tactic].push({
          id: entry.technique.id,
          name: entry.technique.name,
          ksiCount: entry.ksiIds.length,
        });
      }
    }

    // Sort each column by technique ID
    for (const tactic of TACTICS) {
      columns[tactic].sort((a, b) => a.id.localeCompare(b.id));
    }

    const totalTechniques = techMap.size;
    const coveredTechniques = [...techMap.values()].filter(t => t.ksiIds.length > 0).length;
    const maxKsiPerTech = Math.max(0, ...[...techMap.values()].map(t => t.ksiIds.length));

    return {
      tacticColumns: columns,
      techniqueKsiMap: techMap,
      stats: { totalTechniques, coveredTechniques, maxKsiPerTech },
    };
  }, [matrixData]);

  const getIntensity = (ksiCount: number): string => {
    if (ksiCount === 0) return "bg-muted/30 border-muted";
    if (ksiCount === 1) return "bg-blue-500/30 border-blue-500/50";
    if (ksiCount <= 3) return "bg-blue-500/50 border-blue-500/70";
    if (ksiCount <= 5) return "bg-blue-500/70 border-blue-500";
    return "bg-blue-600 border-blue-400 text-white";
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Grid3X3 className="h-5 w-5" />
              MITRE ATT&CK Matrix Overlay
            </CardTitle>
            <CardDescription>
              Enterprise ATT&CK techniques mapped to KSI coverage. Brighter cells indicate more KSIs defending against that technique.
            </CardDescription>
          </div>
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <Shield className="h-3 w-3 text-emerald-500" />
              {stats.coveredTechniques} techniques covered
            </span>
            <span className="flex items-center gap-1">
              <AlertTriangle className="h-3 w-3 text-amber-500" />
              {stats.totalTechniques - stats.coveredTechniques} gaps
            </span>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <TooltipProvider>
          <div className="overflow-x-auto">
            <div className="flex gap-0.5" style={{ minWidth: "1200px" }}>
              {TACTICS.map((tactic) => {
                const colors = TACTIC_COLORS[tactic] || { bg: "bg-muted/20", header: "bg-muted" };
                const techniques = tacticColumns[tactic] || [];

                return (
                  <div key={tactic} className="flex-1 min-w-[80px]">
                    {/* Tactic header */}
                    <div className={`${colors.header} text-white text-[9px] font-medium px-1 py-1.5 rounded-t text-center leading-tight`}>
                      {tactic}
                    </div>

                    {/* Technique cells */}
                    <div className={`${colors.bg} rounded-b p-0.5 space-y-0.5`}>
                      {techniques.length > 0 ? (
                        techniques.map((tech) => {
                          const entry = techniqueKsiMap.get(tech.id);
                          const intensity = getIntensity(tech.ksiCount);
                          const isHovered = hoveredTechnique === tech.id;

                          return (
                            <Tooltip key={tech.id}>
                              <TooltipTrigger asChild>
                                <button
                                  className={`w-full text-left px-1 py-1 rounded text-[8px] leading-tight border transition-all ${intensity} ${
                                    isHovered ? "ring-1 ring-white scale-105" : ""
                                  }`}
                                  onMouseEnter={() => setHoveredTechnique(tech.id)}
                                  onMouseLeave={() => setHoveredTechnique(null)}
                                  onClick={() => onTechniqueClick?.(tech.id)}
                                >
                                  <div className="font-mono font-bold">{tech.id}</div>
                                  <div className="truncate opacity-80">{tech.name}</div>
                                </button>
                              </TooltipTrigger>
                              <TooltipContent side="right" className="max-w-xs">
                                <div className="space-y-1.5">
                                  <div className="font-medium text-xs">{tech.id}: {tech.name}</div>
                                  <div className="text-[10px] text-muted-foreground">Tactic: {tactic}</div>
                                  {entry && entry.ksiIds.length > 0 ? (
                                    <div>
                                      <div className="text-[10px] font-medium text-emerald-400 mb-0.5">
                                        Defended by {entry.ksiIds.length} KSI{entry.ksiIds.length > 1 ? "s" : ""}:
                                      </div>
                                      {entry.ksiIds.map((id, i) => (
                                        <div key={id} className="text-[10px]">
                                          <span className="font-mono">{id}</span>
                                          <span className="text-muted-foreground ml-1">{entry.ksiTitles[i]}</span>
                                        </div>
                                      ))}
                                    </div>
                                  ) : (
                                    <div className="text-[10px] text-amber-400">No KSI coverage</div>
                                  )}
                                </div>
                              </TooltipContent>
                            </Tooltip>
                          );
                        })
                      ) : (
                        <div className="text-[9px] text-muted-foreground text-center py-2 opacity-50">
                          No mapped techniques
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </TooltipProvider>

        {/* Legend */}
        <div className="flex items-center gap-3 mt-4 pt-3 border-t text-xs text-muted-foreground">
          <span>Coverage intensity:</span>
          <span className="flex items-center gap-1">
            <span className="w-4 h-3 rounded bg-muted/30 border border-muted inline-block" /> None
          </span>
          <span className="flex items-center gap-1">
            <span className="w-4 h-3 rounded bg-blue-500/30 border border-blue-500/50 inline-block" /> 1 KSI
          </span>
          <span className="flex items-center gap-1">
            <span className="w-4 h-3 rounded bg-blue-500/50 border border-blue-500/70 inline-block" /> 2-3 KSIs
          </span>
          <span className="flex items-center gap-1">
            <span className="w-4 h-3 rounded bg-blue-500/70 border border-blue-500 inline-block" /> 4-5 KSIs
          </span>
          <span className="flex items-center gap-1">
            <span className="w-4 h-3 rounded bg-blue-600 border border-blue-400 inline-block" /> 6+ KSIs
          </span>
        </div>
      </CardContent>
    </Card>
  );
}
