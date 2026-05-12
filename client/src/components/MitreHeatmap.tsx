import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Progress } from "@/components/ui/progress";

type Technique = {
  id: string;
  name: string;
  tacticId: string;
  c2: { total: number; succeeded: number; failed: number; successRate: number };
  edr: { total: number; detected: number; missed: number; partial: number; blocked: number; detectionRate: number };
  coverageScore: number | null;
  heatLevel: number;
};

type Tactic = {
  id: string;
  name: string;
  shortName: string;
};

type Props = {
  tactics: Tactic[];
  techniques: Technique[];
  coverage: { totalTechniques: number; testedTechniques: number; coveragePercent: number };
};

const HEAT_COLORS: Record<number, { bg: string; border: string; text: string; label: string }> = {
  0: { bg: "bg-zinc-800/50", border: "border-zinc-700", text: "text-zinc-500", label: "Untested" },
  1: { bg: "bg-emerald-900/60", border: "border-emerald-700", text: "text-emerald-300", label: "Fully Defended" },
  2: { bg: "bg-green-900/50", border: "border-green-700", text: "text-green-300", label: "Mostly Defended" },
  3: { bg: "bg-amber-900/50", border: "border-amber-600", text: "text-amber-300", label: "Mixed Results" },
  4: { bg: "bg-orange-900/50", border: "border-orange-600", text: "text-orange-300", label: "Mostly Missed" },
  5: { bg: "bg-red-900/60", border: "border-red-600", text: "text-red-300", label: "Fully Exposed" },
};

export function MitreHeatmap({ tactics, techniques, coverage }: Props) {
  const [selectedTechnique, setSelectedTechnique] = useState<Technique | null>(null);

  // Group techniques by tactic
  const tacticGroups = useMemo(() => {
    const groups: Record<string, Technique[]> = {};
    for (const tactic of tactics) {
      groups[tactic.id] = [];
    }
    for (const tech of techniques) {
      if (groups[tech.tacticId]) {
        groups[tech.tacticId].push(tech);
      }
    }
    // Sort each group by heat level (worst first)
    for (const key of Object.keys(groups)) {
      groups[key].sort((a, b) => b.heatLevel - a.heatLevel || a.id.localeCompare(b.id));
    }
    return groups;
  }, [tactics, techniques]);

  const maxTechniquesPerTactic = useMemo(() => {
    return Math.max(...Object.values(tacticGroups).map(g => g.length), 1);
  }, [tacticGroups]);

  return (
    <div className="space-y-6">
      {/* Coverage Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="pt-6">
            <div className="text-sm text-zinc-400">Total Techniques</div>
            <div className="text-3xl font-bold text-zinc-100">{coverage.totalTechniques}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="pt-6">
            <div className="text-sm text-zinc-400">Tested Techniques</div>
            <div className="text-3xl font-bold text-emerald-400">{coverage.testedTechniques}</div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="pt-6">
            <div className="text-sm text-zinc-400">Coverage</div>
            <div className="flex items-center gap-3">
              <div className="text-3xl font-bold text-zinc-100">{coverage.coveragePercent}%</div>
              <Progress value={coverage.coveragePercent} className="flex-1 h-2" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-3 text-xs">
        {Object.entries(HEAT_COLORS).map(([level, colors]) => (
          <div key={level} className="flex items-center gap-1.5">
            <div className={`w-3 h-3 rounded-sm ${colors.bg} ${colors.border} border`} />
            <span className="text-zinc-400">{colors.label}</span>
          </div>
        ))}
      </div>

      {/* Heatmap Grid */}
      <div className="overflow-x-auto">
        <div className="inline-flex gap-1 min-w-full">
          {tactics.map(tactic => {
            const techs = tacticGroups[tactic.id] || [];
            return (
              <div key={tactic.id} className="flex flex-col min-w-[110px] max-w-[140px]">
                {/* Tactic Header */}
                <div className="bg-zinc-800 border border-zinc-700 rounded-t-md px-2 py-2 text-center">
                  <div className="text-[10px] font-mono text-zinc-500">{tactic.id}</div>
                  <div className="text-xs font-semibold text-zinc-200 leading-tight">{tactic.shortName}</div>
                  <div className="text-[10px] text-zinc-500 mt-0.5">{techs.length} techniques</div>
                </div>
                {/* Technique Cells */}
                <div className="flex flex-col gap-0.5 mt-0.5">
                  <TooltipProvider delayDuration={200}>
                    {techs.map(tech => {
                      const colors = HEAT_COLORS[tech.heatLevel] || HEAT_COLORS[0];
                      return (
                        <Tooltip key={tech.id}>
                          <TooltipTrigger asChild>
                            <button
                              onClick={() => setSelectedTechnique(selectedTechnique?.id === tech.id ? null : tech)}
                              className={`${colors.bg} ${colors.border} border rounded-sm px-1.5 py-1 text-left hover:brightness-125 transition-all cursor-pointer ${selectedTechnique?.id === tech.id ? "ring-1 ring-white/40" : ""}`}
                            >
                              <div className={`text-[9px] font-mono ${colors.text} truncate`}>{tech.id}</div>
                              <div className="text-[9px] text-zinc-300 truncate leading-tight">{tech.name}</div>
                            </button>
                          </TooltipTrigger>
                          <TooltipContent side="right" className="max-w-xs bg-zinc-900 border-zinc-700">
                            <div className="space-y-1.5">
                              <div className="font-semibold text-sm">{tech.id}: {tech.name}</div>
                              <Badge variant="outline" className={`${colors.text} ${colors.border} text-[10px]`}>{colors.label}</Badge>
                              {tech.c2.total > 0 && (
                                <div className="text-xs">
                                  <span className="text-zinc-400">C2:</span>{" "}
                                  <span className="text-green-400">{tech.c2.succeeded} succeeded</span> /{" "}
                                  <span className="text-red-400">{tech.c2.failed} failed</span>{" "}
                                  <span className="text-zinc-500">({tech.c2.successRate}% success)</span>
                                </div>
                              )}
                              {tech.edr.total > 0 && (
                                <div className="text-xs">
                                  <span className="text-zinc-400">EDR:</span>{" "}
                                  <span className="text-emerald-400">{tech.edr.detected} detected</span> /{" "}
                                  <span className="text-red-400">{tech.edr.missed} missed</span> /{" "}
                                  <span className="text-blue-400">{tech.edr.blocked} blocked</span>{" "}
                                  <span className="text-zinc-500">({tech.edr.detectionRate}% detection)</span>
                                </div>
                              )}
                              {tech.c2.total === 0 && tech.edr.total === 0 && (
                                <div className="text-xs text-zinc-500">No test data available</div>
                              )}
                            </div>
                          </TooltipContent>
                        </Tooltip>
                      );
                    })}
                  </TooltipProvider>
                  {/* Fill empty space */}
                  {techs.length === 0 && (
                    <div className="bg-zinc-800/30 border border-dashed border-zinc-800 rounded-sm px-1.5 py-3 text-center">
                      <div className="text-[9px] text-zinc-600">No data</div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Selected Technique Detail */}
      {selectedTechnique && (
        <Card className="bg-zinc-900/50 border-zinc-700">
          <CardHeader className="pb-3">
            <CardTitle className="text-lg flex items-center gap-2">
              <span className="font-mono text-sm text-zinc-400">{selectedTechnique.id}</span>
              {selectedTechnique.name}
              <Badge variant="outline" className={`${HEAT_COLORS[selectedTechnique.heatLevel].text} ${HEAT_COLORS[selectedTechnique.heatLevel].border} text-xs`}>
                {HEAT_COLORS[selectedTechnique.heatLevel].label}
              </Badge>
            </CardTitle>
            <CardDescription>
              Tactic: {tactics.find(t => t.id === selectedTechnique.tacticId)?.name || selectedTechnique.tacticId}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* C2 Emulation Results */}
              <div className="space-y-2">
                <div className="text-sm font-medium text-zinc-300">C2 Emulation Results</div>
                {selectedTechnique.c2.total > 0 ? (
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-sm">
                      <span className="text-zinc-400">Total Executions</span>
                      <span className="text-zinc-200">{selectedTechnique.c2.total}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-green-400">Succeeded</span>
                      <span className="text-green-300">{selectedTechnique.c2.succeeded}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-red-400">Failed</span>
                      <span className="text-red-300">{selectedTechnique.c2.failed}</span>
                    </div>
                    <div className="flex justify-between text-sm font-medium">
                      <span className="text-zinc-300">Success Rate</span>
                      <span className={selectedTechnique.c2.successRate > 50 ? "text-amber-400" : "text-emerald-400"}>
                        {selectedTechnique.c2.successRate}%
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="text-sm text-zinc-500">No C2 emulation data</div>
                )}
              </div>
              {/* EDR Detection Results */}
              <div className="space-y-2">
                <div className="text-sm font-medium text-zinc-300">EDR Detection Results</div>
                {selectedTechnique.edr.total > 0 ? (
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-sm">
                      <span className="text-zinc-400">Total Tests</span>
                      <span className="text-zinc-200">{selectedTechnique.edr.total}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-emerald-400">Detected</span>
                      <span className="text-emerald-300">{selectedTechnique.edr.detected}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-blue-400">Blocked</span>
                      <span className="text-blue-300">{selectedTechnique.edr.blocked}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-amber-400">Partial</span>
                      <span className="text-amber-300">{selectedTechnique.edr.partial}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-red-400">Missed</span>
                      <span className="text-red-300">{selectedTechnique.edr.missed}</span>
                    </div>
                    <div className="flex justify-between text-sm font-medium">
                      <span className="text-zinc-300">Detection Rate</span>
                      <span className={selectedTechnique.edr.detectionRate > 70 ? "text-emerald-400" : "text-red-400"}>
                        {selectedTechnique.edr.detectionRate}%
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="text-sm text-zinc-500">No EDR test data</div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
