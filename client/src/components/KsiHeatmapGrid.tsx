import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { THEME_LABELS, KSI_TITLES, getThemeFromKsiId } from "@/lib/ksi-labels";
import { Grid3X3, ChevronDown, ChevronUp } from "lucide-react";
import { Button } from "@/components/ui/button";

interface KsiDefinition {
  ksiId: string;
  themeCode: string;
  themeName: string;
  title: string;
  validationType: string;
  frequency: string;
  coverageStatus: string;
  aceC3Module?: string;
}

interface ThemeStat {
  themeCode: string;
  themeName: string;
  total: number;
  direct: number;
  supporting: number;
  planned: number;
  coveragePercent: number;
}

interface KsiHeatmapGridProps {
  themeStats: ThemeStat[];
  definitions?: KsiDefinition[];
  onKsiClick?: (ksiId: string) => void;
}

const COVERAGE_COLORS: Record<string, { bg: string; border: string; text: string; label: string }> = {
  direct: { bg: "bg-emerald-500", border: "border-emerald-600", text: "text-white", label: "Direct" },
  supporting: { bg: "bg-amber-500", border: "border-amber-600", text: "text-white", label: "Supporting" },
  planned: { bg: "bg-slate-500/50", border: "border-slate-500", text: "text-slate-200", label: "Planned" },
  not_applicable: { bg: "bg-muted/30", border: "border-muted", text: "text-muted-foreground", label: "N/A" },
};

const VALIDATION_ICONS: Record<string, string> = {
  machine: "⚙",
  human: "👤",
  mixed: "⚡",
  tbd: "◌",
};

// Theme order for consistent display
const THEME_ORDER = ["AFR", "CMT", "CNA", "CED", "IAM", "INR", "MLA", "PIY", "RPL", "SVC", "SCR", "SDE", "PPM"];

export default function KsiHeatmapGrid({ themeStats, definitions = [], onKsiClick }: KsiHeatmapGridProps) {
  const [expanded, setExpanded] = useState(true);
  const [selectedTheme, setSelectedTheme] = useState<string | null>(null);

  // Group definitions by theme
  const defsByTheme = useMemo(() => {
    const map: Record<string, KsiDefinition[]> = {};
    for (const def of definitions) {
      const theme = def.themeCode || getThemeFromKsiId(def.ksiId);
      if (!map[theme]) map[theme] = [];
      map[theme].push(def);
    }
    return map;
  }, [definitions]);

  // Sort themes by THEME_ORDER
  const sortedThemes = useMemo(() => {
    return [...themeStats].sort((a, b) => {
      const ai = THEME_ORDER.indexOf(a.themeCode);
      const bi = THEME_ORDER.indexOf(b.themeCode);
      return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
    });
  }, [themeStats]);

  const selectedDefs = selectedTheme ? (defsByTheme[selectedTheme] || []) : [];

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Grid3X3 className="h-5 w-5" />
              KSI Coverage Heatmap
            </CardTitle>
            <CardDescription>
              Interactive grid showing coverage status for all 13 FedRAMP 20x security themes. Click a theme to drill into individual indicators.
            </CardDescription>
          </div>
          <Button variant="ghost" size="sm" onClick={() => setExpanded(!expanded)}>
            {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {expanded && (
          <>
            {/* Heatmap Grid */}
            <TooltipProvider>
              <div className="space-y-1.5">
                {sortedThemes.map((theme) => {
                  const themeDefs = defsByTheme[theme.themeCode] || [];
                  const isSelected = selectedTheme === theme.themeCode;

                  return (
                    <div key={theme.themeCode}>
                      <div
                        className={`flex items-center gap-3 p-2 rounded-md cursor-pointer transition-colors ${
                          isSelected ? "bg-accent" : "hover:bg-accent/50"
                        }`}
                        onClick={() => setSelectedTheme(isSelected ? null : theme.themeCode)}
                      >
                        {/* Theme label */}
                        <div className="w-40 flex-shrink-0">
                          <div className="text-xs font-medium truncate">{theme.themeName}</div>
                          <div className="text-[10px] text-muted-foreground">{theme.themeCode} · {theme.total} KSIs</div>
                        </div>

                        {/* KSI cells */}
                        <div className="flex gap-1 flex-wrap flex-1">
                          {themeDefs.length > 0 ? (
                            themeDefs.map((def) => {
                              const color = COVERAGE_COLORS[def.coverageStatus] || COVERAGE_COLORS.not_applicable;
                              const valIcon = VALIDATION_ICONS[def.validationType] || "◌";
                              const shortId = def.ksiId.split("-").pop() || def.ksiId;

                              return (
                                <Tooltip key={def.ksiId}>
                                  <TooltipTrigger asChild>
                                    <button
                                      className={`h-7 min-w-[2.5rem] px-1.5 rounded text-[10px] font-mono font-medium ${color.bg} ${color.text} border ${color.border} hover:opacity-80 transition-opacity flex items-center justify-center gap-0.5`}
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        onKsiClick?.(def.ksiId);
                                      }}
                                    >
                                      <span>{shortId}</span>
                                    </button>
                                  </TooltipTrigger>
                                  <TooltipContent side="top" className="max-w-xs">
                                    <div className="space-y-1">
                                      <div className="font-medium text-xs">{def.ksiId}</div>
                                      <div className="text-xs">{def.title}</div>
                                      <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                                        <span>{valIcon} {def.validationType}</span>
                                        <span>·</span>
                                        <span>{def.frequency}</span>
                                        <span>·</span>
                                        <Badge variant="outline" className="text-[10px] h-4 px-1">{def.coverageStatus}</Badge>
                                      </div>
                                      {def.aceC3Module && (
                                        <div className="text-[10px] text-blue-400">Module: {def.aceC3Module}</div>
                                      )}
                                    </div>
                                  </TooltipContent>
                                </Tooltip>
                              );
                            })
                          ) : (
                            // Fallback: show colored blocks based on stats
                            <>
                              {Array.from({ length: theme.direct }).map((_, i) => (
                                <div key={`d-${i}`} className="h-7 w-7 rounded bg-emerald-500 border border-emerald-600" />
                              ))}
                              {Array.from({ length: theme.supporting }).map((_, i) => (
                                <div key={`s-${i}`} className="h-7 w-7 rounded bg-amber-500 border border-amber-600" />
                              ))}
                              {Array.from({ length: theme.planned }).map((_, i) => (
                                <div key={`p-${i}`} className="h-7 w-7 rounded bg-slate-500/50 border border-slate-500" />
                              ))}
                            </>
                          )}
                        </div>

                        {/* Coverage badge */}
                        <div className="flex-shrink-0 w-14 text-right">
                          <Badge
                            variant={theme.coveragePercent >= 80 ? "default" : theme.coveragePercent >= 50 ? "secondary" : "destructive"}
                            className="text-[10px]"
                          >
                            {theme.coveragePercent}%
                          </Badge>
                        </div>
                      </div>

                      {/* Expanded detail for selected theme */}
                      {isSelected && selectedDefs.length > 0 && (
                        <div className="ml-44 mt-1 mb-2 p-3 bg-card border rounded-md">
                          <div className="text-xs font-medium mb-2 text-muted-foreground">
                            {theme.themeName} — {selectedDefs.length} Indicators
                          </div>
                          <div className="space-y-1.5">
                            {selectedDefs.map((def) => {
                              const color = COVERAGE_COLORS[def.coverageStatus] || COVERAGE_COLORS.not_applicable;
                              const valIcon = VALIDATION_ICONS[def.validationType] || "◌";

                              return (
                                <div
                                  key={def.ksiId}
                                  className="flex items-center gap-3 py-1.5 px-2 rounded hover:bg-accent/50 cursor-pointer text-xs"
                                  onClick={() => onKsiClick?.(def.ksiId)}
                                >
                                  <div className={`w-2 h-2 rounded-full ${color.bg}`} />
                                  <span className="font-mono text-muted-foreground w-24 flex-shrink-0">{def.ksiId}</span>
                                  <span className="flex-1">{def.title}</span>
                                  <span className="text-muted-foreground">{valIcon} {def.validationType}</span>
                                  <span className="text-muted-foreground">{def.frequency}</span>
                                  <Badge variant="outline" className="text-[10px] h-4 px-1">{def.coverageStatus}</Badge>
                                  {def.aceC3Module && (
                                    <span className="text-blue-400 text-[10px] max-w-32 truncate" title={def.aceC3Module}>
                                      {def.aceC3Module}
                                    </span>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </TooltipProvider>

            {/* Legend */}
            <div className="flex flex-wrap gap-4 mt-4 pt-3 border-t text-xs text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded bg-emerald-500 inline-block" /> Direct Coverage
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded bg-amber-500 inline-block" /> Supporting
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded bg-slate-500/50 inline-block" /> Planned
              </span>
              <span className="ml-auto flex items-center gap-3">
                <span>⚙ Machine</span>
                <span>👤 Human</span>
                <span>⚡ Mixed</span>
                <span>◌ TBD</span>
              </span>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
