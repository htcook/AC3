import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { THEME_LABELS, KSI_TITLES, getThemeFromKsiId } from "@/lib/ksi-labels";
import { getKsiEnriched, getThemeEnriched, getKsisByTheme, type EnrichedKSI } from "@/lib/ksi-enriched-data";
import { Grid3X3, ChevronDown, ChevronUp, ChevronRight, Shield, Cpu, FileCheck, Clock } from "lucide-react";
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
  "n/a": "◌",
};

const THEME_ORDER = ["AFR", "CMT", "CNA", "CED", "IAM", "INR", "MLA", "PIY", "RPL", "SVC", "SCR", "SDE", "PPM"];

export default function KsiHeatmapGrid({ themeStats, definitions = [], onKsiClick }: KsiHeatmapGridProps) {
  const [expanded, setExpanded] = useState(true);
  const [selectedTheme, setSelectedTheme] = useState<string | null>(null);
  const [expandedKsi, setExpandedKsi] = useState<string | null>(null);

  const defsByTheme = useMemo(() => {
    const map: Record<string, KsiDefinition[]> = {};
    for (const def of definitions) {
      const theme = def.themeCode || getThemeFromKsiId(def.ksiId);
      if (!map[theme]) map[theme] = [];
      map[theme].push(def);
    }
    return map;
  }, [definitions]);

  const sortedThemes = useMemo(() => {
    return [...themeStats].sort((a, b) => {
      const ai = THEME_ORDER.indexOf(a.themeCode);
      const bi = THEME_ORDER.indexOf(b.themeCode);
      return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
    });
  }, [themeStats]);

  const selectedDefs = selectedTheme ? (defsByTheme[selectedTheme] || []) : [];
  const themeEnriched = selectedTheme ? getThemeEnriched(selectedTheme) : null;

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
              Interactive grid showing coverage status for all 13 FedRAMP 20x security themes. Click a theme to see how Ace C3 addresses each indicator.
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
                        onClick={() => {
                          setSelectedTheme(isSelected ? null : theme.themeCode);
                          setExpandedKsi(null);
                        }}
                      >
                        <div className="w-40 flex-shrink-0">
                          <div className="text-xs font-medium truncate">{theme.themeName}</div>
                          <div className="text-[10px] text-muted-foreground">{theme.themeCode} · {theme.total} KSIs</div>
                        </div>

                        <div className="flex gap-1 flex-wrap flex-1">
                          {themeDefs.length > 0 ? (
                            themeDefs.map((def) => {
                              const enriched = getKsiEnriched(def.ksiId);
                              const color = COVERAGE_COLORS[def.coverageStatus] || COVERAGE_COLORS.not_applicable;
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
                                  <TooltipContent side="top" className="max-w-sm">
                                    <div className="space-y-1.5">
                                      <div className="font-medium text-xs">{def.ksiId}: {enriched?.name || def.title}</div>
                                      {enriched && (
                                        <p className="text-[11px] text-muted-foreground leading-relaxed">{enriched.requirement}</p>
                                      )}
                                      <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                                        <Badge variant="outline" className="text-[10px] h-4 px-1">{def.coverageStatus}</Badge>
                                        <span>{enriched?.validationMethod || def.validationType}</span>
                                        <span>·</span>
                                        <span>{enriched?.frequency || def.frequency}</span>
                                      </div>
                                      {enriched && enriched.aceModules.length > 0 && (
                                        <div className="text-[10px] text-blue-400">
                                          Modules: {enriched.aceModules.map(m => m.name).join(", ")}
                                        </div>
                                      )}
                                    </div>
                                  </TooltipContent>
                                </Tooltip>
                              );
                            })
                          ) : (
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

                        <div className="flex-shrink-0 w-14 text-right">
                          <Badge
                            variant={theme.coveragePercent >= 80 ? "default" : theme.coveragePercent >= 50 ? "secondary" : "destructive"}
                            className="text-[10px]"
                          >
                            {theme.coveragePercent}%
                          </Badge>
                        </div>
                      </div>

                      {/* Expanded theme detail with enriched KSI data */}
                      {isSelected && (
                        <div className="ml-4 md:ml-44 mt-1 mb-2 p-4 bg-card border rounded-md space-y-3">
                          {/* Theme narrative */}
                          {themeEnriched && (
                            <div className="pb-3 border-b">
                              <div className="text-xs font-semibold mb-1.5 flex items-center gap-1.5">
                                <Shield className="w-3.5 h-3.5 text-blue-400" />
                                How Ace C3 Addresses {theme.themeName}
                              </div>
                              <p className="text-xs text-muted-foreground leading-relaxed">{themeEnriched.aceC3Narrative}</p>
                            </div>
                          )}

                          <div className="text-xs font-medium text-muted-foreground">
                            {theme.themeName} — {selectedDefs.length} Indicators
                          </div>

                          <div className="space-y-1">
                            {selectedDefs.map((def) => {
                              const enriched = getKsiEnriched(def.ksiId);
                              const color = COVERAGE_COLORS[def.coverageStatus] || COVERAGE_COLORS.not_applicable;
                              const isKsiExpanded = expandedKsi === def.ksiId;

                              return (
                                <div key={def.ksiId}>
                                  <div
                                    className={`flex items-center gap-3 py-2 px-2 rounded cursor-pointer text-xs transition-colors ${
                                      isKsiExpanded ? "bg-accent" : "hover:bg-accent/50"
                                    }`}
                                    onClick={() => setExpandedKsi(isKsiExpanded ? null : def.ksiId)}
                                  >
                                    <ChevronRight className={`w-3 h-3 text-muted-foreground transition-transform flex-shrink-0 ${isKsiExpanded ? "rotate-90" : ""}`} />
                                    <div className={`w-2 h-2 rounded-full flex-shrink-0 ${color.bg}`} />
                                    <span className="font-mono text-muted-foreground w-24 flex-shrink-0">{def.ksiId}</span>
                                    <span className="flex-1 font-medium">{enriched?.name || def.title}</span>
                                    <Badge variant="outline" className="text-[10px] h-4 px-1">{def.coverageStatus}</Badge>
                                  </div>

                                  {/* Expanded KSI detail */}
                                  {isKsiExpanded && enriched && (
                                    <div className="ml-8 mr-2 mt-1 mb-2 p-3 bg-background/50 border rounded-md space-y-3 text-xs">
                                      {/* Requirement */}
                                      <div>
                                        <div className="font-semibold text-muted-foreground mb-1 flex items-center gap-1">
                                          <FileCheck className="w-3 h-3" /> What This KSI Requires
                                        </div>
                                        <p className="text-foreground leading-relaxed">{enriched.requirement}</p>
                                      </div>

                                      {/* How Ace C3 Delivers */}
                                      <div>
                                        <div className="font-semibold text-blue-400 mb-1 flex items-center gap-1">
                                          <Shield className="w-3 h-3" /> How Ace C3 {enriched.coverageLevel === "direct" ? "Meets" : enriched.coverageLevel === "supporting" ? "Supports" : "Plans to Address"} This
                                        </div>
                                        <p className="text-foreground leading-relaxed">{enriched.howAceC3Delivers}</p>
                                      </div>

                                      {/* Ace C3 Modules */}
                                      {enriched.aceModules.length > 0 && (
                                        <div>
                                          <div className="font-semibold text-muted-foreground mb-1.5 flex items-center gap-1">
                                            <Cpu className="w-3 h-3" /> Ace C3 Modules Involved
                                          </div>
                                          <div className="space-y-1.5">
                                            {enriched.aceModules.map((mod, i) => (
                                              <div key={i} className="flex gap-2 items-start">
                                                <Badge variant="outline" className="text-[10px] h-5 px-1.5 flex-shrink-0 font-mono">{mod.name}</Badge>
                                                <span className="text-muted-foreground">{mod.role}</span>
                                              </div>
                                            ))}
                                          </div>
                                        </div>
                                      )}

                                      {/* Evidence & Validation */}
                                      <div className="flex gap-6 pt-2 border-t">
                                        {enriched.evidenceTypes.length > 0 && (
                                          <div className="flex-1">
                                            <div className="font-semibold text-muted-foreground mb-1">Evidence Types</div>
                                            <div className="flex flex-wrap gap-1">
                                              {enriched.evidenceTypes.map((et, i) => (
                                                <Badge key={i} variant="outline" className="text-[10px] h-4 px-1">{et}</Badge>
                                              ))}
                                            </div>
                                          </div>
                                        )}
                                        <div className="flex-shrink-0 space-y-1">
                                          <div className="flex items-center gap-1.5">
                                            <Clock className="w-3 h-3 text-muted-foreground" />
                                            <span className="text-muted-foreground">Frequency:</span>
                                            <span className="font-medium">{enriched.frequency}</span>
                                          </div>
                                          <div className="flex items-center gap-1.5">
                                            <span className="text-muted-foreground">Validation:</span>
                                            <span className="font-medium">{enriched.validationMethod}</span>
                                          </div>
                                          {enriched.nistControls.length > 0 && (
                                            <div className="flex items-center gap-1.5">
                                              <span className="text-muted-foreground">NIST:</span>
                                              <span className="font-mono">{enriched.nistControls.join(", ")}</span>
                                            </div>
                                          )}
                                        </div>
                                      </div>

                                      {/* Link to detail page */}
                                      <div className="pt-1">
                                        <button
                                          className="text-blue-400 hover:text-blue-300 text-[11px] underline underline-offset-2"
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            onKsiClick?.(def.ksiId);
                                          }}
                                        >
                                          View full detail page →
                                        </button>
                                      </div>
                                    </div>
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
