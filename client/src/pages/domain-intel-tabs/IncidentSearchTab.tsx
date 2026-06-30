import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  AlertTriangle, Shield, Skull, Activity, Clock, ChevronDown, ChevronUp,
  Fingerprint, Target, Search, ExternalLink, ShieldAlert, Flame, Database,
  Globe, Info
} from "lucide-react";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";

interface IncidentMatch {
  source: "threat_catalog_event" | "threat_catalog_ioc" | "web_search";
  actorId?: string;
  actorName?: string;
  actorType?: string;
  eventType?: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  date?: string;
  victimName?: string;
  victimSector?: string;
  mitreTechniques?: string[];
  iocType?: string;
  iocValue?: string;
  confidence: "confirmed" | "probable" | "possible";
  relevanceScore: number;
}

interface IncidentSearchResult {
  domain: string;
  searchedAt: number;
  catalogMatches: IncidentMatch[];
  webSearchMatches: IncidentMatch[];
  totalMatches: number;
  hasActiveThreats: boolean;
  hasRansomwareEvent: boolean;
  hasRecentBreach: boolean;
  riskFloorContribution: number;
  summary: string;
  newActorsDiscovered: string[];
  newTTPsDiscovered: string[];
  newIOCsDiscovered: string[];
}

const severityConfig: Record<string, { color: string; bg: string; border: string; icon: React.ReactNode }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", icon: <Flame className="h-4 w-4 text-red-400" /> },
  high: { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", icon: <AlertTriangle className="h-4 w-4 text-orange-400" /> },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", icon: <ShieldAlert className="h-4 w-4 text-yellow-400" /> },
  low: { color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30", icon: <Shield className="h-4 w-4 text-blue-400" /> },
  info: { color: "text-slate-400", bg: "bg-slate-500/10", border: "border-slate-500/30", icon: <Info className="h-4 w-4 text-slate-400" /> },
};

const sourceConfig: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  threat_catalog_event: { label: "Threat Catalog", icon: <Database className="h-3 w-3" />, color: "text-purple-400 bg-purple-500/10 border-purple-500/30" },
  threat_catalog_ioc: { label: "IOC Match", icon: <Fingerprint className="h-3 w-3" />, color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/30" },
  web_search: { label: "OSINT", icon: <Globe className="h-3 w-3" />, color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30" },
};

const confidenceConfig: Record<string, { label: string; color: string }> = {
  confirmed: { label: "Confirmed", color: "text-red-400 bg-red-500/10 border-red-500/30" },
  probable: { label: "Probable", color: "text-orange-400 bg-orange-500/10 border-orange-500/30" },
  possible: { label: "Possible", color: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30" },
};

function IncidentCard({ incident, index }: { incident: IncidentMatch; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const sev = severityConfig[incident.severity] || severityConfig.info;
  const src = sourceConfig[incident.source] || sourceConfig.web_search;
  const conf = confidenceConfig[incident.confidence] || confidenceConfig.possible;

  return (
    <Collapsible open={expanded} onOpenChange={setExpanded}>
      <Card className={`${sev.border} ${sev.bg} transition-all hover:shadow-md`}>
        <CollapsibleTrigger asChild>
          <CardContent className="p-4 cursor-pointer">
            <div className="flex items-start gap-3">
              <div className="mt-0.5">{sev.icon}</div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1.5">
                  <Badge variant="outline" className={`text-[10px] font-mono ${src.color}`}>
                    {src.icon}
                    <span className="ml-1">{src.label}</span>
                  </Badge>
                  <Badge variant="outline" className={`text-[10px] font-mono uppercase ${sev.color} ${sev.bg} ${sev.border}`}>
                    {incident.severity}
                  </Badge>
                  <Badge variant="outline" className={`text-[10px] font-mono ${conf.color}`}>
                    {conf.label}
                  </Badge>
                  {incident.date && (
                    <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                      <Clock className="h-2.5 w-2.5" /> {incident.date}
                    </span>
                  )}
                </div>
                <h4 className="font-semibold text-sm leading-tight">{incident.title}</h4>
                {incident.actorName && (
                  <div className="flex items-center gap-1.5 mt-1.5">
                    <Skull className="h-3 w-3 text-amber-400" />
                    <span className="text-xs text-amber-400 font-medium">{incident.actorName}</span>
                    {incident.actorType && (
                      <Badge variant="outline" className="text-[9px] font-mono text-muted-foreground">
                        {incident.actorType}
                      </Badge>
                    )}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-2">
                <div className="text-right">
                  <div className="text-[10px] text-muted-foreground">Relevance</div>
                  <div className={`text-sm font-mono font-bold ${sev.color}`}>
                    {Math.round(incident.relevanceScore * 100)}%
                  </div>
                </div>
                {expanded ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
              </div>
            </div>
          </CardContent>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="px-4 pb-4 pt-0 border-t border-border/50 mt-0">
            <div className="pt-3 space-y-3">
              <div>
                <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Description</div>
                <p className="text-sm text-foreground/80 whitespace-pre-wrap leading-relaxed">{incident.description}</p>
              </div>
              {incident.mitreTechniques && incident.mitreTechniques.length > 0 && (
                <div>
                  <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">MITRE ATT&CK Techniques</div>
                  <div className="flex flex-wrap gap-1.5">
                    {incident.mitreTechniques.map((t, i) => (
                      <Badge key={i} variant="outline" className="text-[10px] font-mono text-purple-400 bg-purple-500/10 border-purple-500/30">
                        {t}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              {incident.victimName && (
                <div>
                  <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Victim</div>
                  <span className="text-sm">{incident.victimName}</span>
                  {incident.victimSector && <span className="text-xs text-muted-foreground ml-2">({incident.victimSector})</span>}
                </div>
              )}
              {incident.iocType && incident.iocValue && (
                <div>
                  <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">IOC</div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-[10px] font-mono">{incident.iocType}</Badge>
                    <code className="text-xs bg-muted/50 px-2 py-0.5 rounded font-mono">{incident.iocValue}</code>
                  </div>
                </div>
              )}
              {incident.eventType && (
                <div>
                  <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">Event Type</div>
                  <Badge variant="outline" className="text-[10px] font-mono capitalize">{incident.eventType.replace(/_/g, " ")}</Badge>
                </div>
              )}
            </div>
          </div>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}

export default function IncidentSearchTab({ incidentSearch }: { incidentSearch: IncidentSearchResult | null | undefined }) {
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [filterSource, setFilterSource] = useState<string>("all");

  if (!incidentSearch) {
    return (
      <Card className="border-border/50">
        <CardContent className="p-8 text-center">
          <Search className="h-12 w-12 text-muted-foreground mx-auto mb-4 opacity-50" />
          <h3 className="text-lg font-semibold mb-2">Incident Search Not Available</h3>
          <p className="text-sm text-muted-foreground max-w-md mx-auto">
            Incident intelligence enrichment was not run for this scan. Re-run the scan to include incident search results from the internal threat catalog and OSINT sources.
          </p>
        </CardContent>
      </Card>
    );
  }

  const allMatches = useMemo(() => {
    return [...incidentSearch.catalogMatches, ...incidentSearch.webSearchMatches]
      .sort((a, b) => {
        const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        const confOrder: Record<string, number> = { confirmed: 0, probable: 1, possible: 2 };
        const sevDiff = (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4);
        if (sevDiff !== 0) return sevDiff;
        return (confOrder[a.confidence] ?? 2) - (confOrder[b.confidence] ?? 2);
      });
  }, [incidentSearch]);

  const filtered = useMemo(() => {
    return allMatches.filter(m => {
      if (filterSeverity !== "all" && m.severity !== filterSeverity) return false;
      if (filterSource !== "all" && m.source !== filterSource) return false;
      return true;
    });
  }, [allMatches, filterSeverity, filterSource]);

  const sevCounts = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const m of allMatches) counts[m.severity] = (counts[m.severity] || 0) + 1;
    return counts;
  }, [allMatches]);

  const uniqueActors = useMemo(() => {
    return [...new Set(allMatches.map(m => m.actorName).filter(Boolean))];
  }, [allMatches]);

  const uniqueTTPs = useMemo(() => {
    return [...new Set(allMatches.flatMap(m => m.mitreTechniques || []))];
  }, [allMatches]);

  return (
    <div className="space-y-4">
      {/* Page Description */}
      <p className="text-sm text-muted-foreground">
        Incident intelligence from the internal threat catalog and open-source intelligence. This view shows known security incidents, ransomware events, data breaches, and threat actor activity targeting the scanned domain.
      </p>

      {/* Alert Banners */}
      {incidentSearch.hasRansomwareEvent && (
        <Card className="border-red-500/50 bg-red-500/10">
          <CardContent className="p-3 flex items-center gap-3">
            <Flame className="h-5 w-5 text-red-400 shrink-0" />
            <div>
              <span className="font-semibold text-red-400 text-sm">RANSOMWARE EVENT DETECTED</span>
              <p className="text-xs text-red-300/70 mt-0.5">One or more ransomware incidents have been identified targeting this organization.</p>
            </div>
          </CardContent>
        </Card>
      )}
      {incidentSearch.hasRecentBreach && (
        <Card className="border-orange-500/50 bg-orange-500/10">
          <CardContent className="p-3 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-orange-400 shrink-0" />
            <div>
              <span className="font-semibold text-orange-400 text-sm">RECENT BREACH IDENTIFIED</span>
              <p className="text-xs text-orange-300/70 mt-0.5">A data breach or data leak event from 2024 or later has been identified.</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="border-cyan-500/30 bg-cyan-500/5">
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold text-cyan-400">{incidentSearch.totalMatches}</p>
            <p className="text-xs text-muted-foreground mt-1">Total Incidents</p>
          </CardContent>
        </Card>
        <Card className="border-purple-500/30 bg-purple-500/5">
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold text-purple-400">{incidentSearch.catalogMatches.length}</p>
            <p className="text-xs text-muted-foreground mt-1">Catalog Matches</p>
          </CardContent>
        </Card>
        <Card className="border-emerald-500/30 bg-emerald-500/5">
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold text-emerald-400">{incidentSearch.webSearchMatches.length}</p>
            <p className="text-xs text-muted-foreground mt-1">OSINT Matches</p>
          </CardContent>
        </Card>
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardContent className="p-4 text-center">
            <p className="text-3xl font-bold text-amber-400">{uniqueActors.length}</p>
            <p className="text-xs text-muted-foreground mt-1">Threat Actors</p>
          </CardContent>
        </Card>
        <Card className={`${incidentSearch.riskFloorContribution > 0 ? 'border-red-500/30 bg-red-500/5' : 'border-border/50'}`}>
          <CardContent className="p-4 text-center">
            <p className={`text-3xl font-bold ${incidentSearch.riskFloorContribution > 0 ? 'text-red-400' : 'text-muted-foreground'}`}>
              +{incidentSearch.riskFloorContribution}
            </p>
            <p className="text-xs text-muted-foreground mt-1">Risk Floor Boost</p>
          </CardContent>
        </Card>
      </div>

      {/* Summary */}
      {incidentSearch.summary && (
        <Card className="border-border/50">
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <Activity className="h-4 w-4 text-cyan-400 mt-0.5 shrink-0" />
              <p className="text-sm text-foreground/80 leading-relaxed">{incidentSearch.summary}</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* New Discoveries */}
      {(incidentSearch.newActorsDiscovered.length > 0 || incidentSearch.newTTPsDiscovered.length > 0) && (
        <Card className="border-emerald-500/30 bg-emerald-500/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Target className="h-4 w-4 text-emerald-400" />
              New Intelligence Discovered
            </CardTitle>
            <CardDescription className="text-xs">
              New actors and techniques discovered from OSINT that have been ingested into the threat catalog.
            </CardDescription>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="flex flex-wrap gap-2">
              {incidentSearch.newActorsDiscovered.map((actor, i) => (
                <Badge key={`a-${i}`} variant="outline" className="text-[10px] font-mono text-amber-400 bg-amber-500/10 border-amber-500/30">
                  <Skull className="h-2.5 w-2.5 mr-1" /> {actor}
                </Badge>
              ))}
              {incidentSearch.newTTPsDiscovered.map((ttp, i) => (
                <Badge key={`t-${i}`} variant="outline" className="text-[10px] font-mono text-purple-400 bg-purple-500/10 border-purple-500/30">
                  {ttp}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filters */}
      {allMatches.length > 0 && (
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs text-muted-foreground font-semibold uppercase tracking-wider">Filter:</span>
          <div className="flex gap-1.5">
            {["all", "critical", "high", "medium", "low"].map(sev => (
              <Button
                key={sev}
                variant={filterSeverity === sev ? "default" : "outline"}
                size="sm"
                className="h-6 text-[10px] px-2"
                onClick={() => setFilterSeverity(sev)}
              >
                {sev === "all" ? "All" : `${sev.charAt(0).toUpperCase() + sev.slice(1)} (${sevCounts[sev] || 0})`}
              </Button>
            ))}
          </div>
          <div className="flex gap-1.5">
            {["all", "threat_catalog_event", "threat_catalog_ioc", "web_search"].map(src => (
              <Button
                key={src}
                variant={filterSource === src ? "default" : "outline"}
                size="sm"
                className="h-6 text-[10px] px-2"
                onClick={() => setFilterSource(src)}
              >
                {src === "all" ? "All Sources" : sourceConfig[src]?.label || src}
              </Button>
            ))}
          </div>
        </div>
      )}

      {/* Incident List */}
      {filtered.length > 0 ? (
        <div className="space-y-3">
          {filtered.map((incident, i) => (
            <IncidentCard key={i} incident={incident} index={i} />
          ))}
        </div>
      ) : allMatches.length > 0 ? (
        <Card className="border-border/50">
          <CardContent className="p-6 text-center">
            <p className="text-sm text-muted-foreground">No incidents match the current filters.</p>
          </CardContent>
        </Card>
      ) : (
        <Card className="border-emerald-500/30 bg-emerald-500/5">
          <CardContent className="p-6 text-center">
            <Shield className="h-8 w-8 text-emerald-400 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-emerald-400">No Known Incidents</h3>
            <p className="text-xs text-muted-foreground mt-1 max-w-md mx-auto">
              No security incidents, ransomware events, or threat actor activity was found targeting this domain in the internal threat catalog or public intelligence sources.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Threat Actor Summary Table */}
      {uniqueActors.length > 0 && (
        <Card className="border-amber-500/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Skull className="h-4 w-4 text-amber-400" />
              Threat Actors Identified ({uniqueActors.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/50">
                    <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Actor</th>
                    <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Type</th>
                    <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Incidents</th>
                    <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Max Severity</th>
                    <th className="text-left py-2 px-3 text-xs font-semibold text-muted-foreground">Techniques</th>
                  </tr>
                </thead>
                <tbody>
                  {uniqueActors.map((actor, i) => {
                    const actorMatches = allMatches.filter(m => m.actorName === actor);
                    const types = [...new Set(actorMatches.map(m => m.actorType).filter(Boolean))];
                    const techniques = [...new Set(actorMatches.flatMap(m => m.mitreTechniques || []))];
                    const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                    const maxSev = actorMatches.reduce((max, m) => (sevOrder[m.severity] ?? 4) < (sevOrder[max] ?? 4) ? m.severity : max, "info" as string);
                    const sevStyle = severityConfig[maxSev] || severityConfig.info;

                    return (
                      <tr key={i} className="border-b border-border/30 hover:bg-muted/20">
                        <td className="py-2 px-3 font-medium text-amber-400">{actor}</td>
                        <td className="py-2 px-3">
                          <Badge variant="outline" className="text-[10px] font-mono capitalize">{types.join(", ") || "unknown"}</Badge>
                        </td>
                        <td className="py-2 px-3 font-mono text-xs">{actorMatches.length}</td>
                        <td className="py-2 px-3">
                          <Badge variant="outline" className={`text-[10px] font-mono uppercase ${sevStyle.color} ${sevStyle.bg} ${sevStyle.border}`}>
                            {maxSev}
                          </Badge>
                        </td>
                        <td className="py-2 px-3">
                          <div className="flex flex-wrap gap-1">
                            {techniques.slice(0, 5).map((t, j) => (
                              <Badge key={j} variant="outline" className="text-[9px] font-mono text-purple-400 bg-purple-500/10 border-purple-500/30">{t}</Badge>
                            ))}
                            {techniques.length > 5 && <span className="text-[9px] text-muted-foreground">+{techniques.length - 5}</span>}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* MITRE Techniques Summary */}
      {uniqueTTPs.length > 0 && (
        <Card className="border-purple-500/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Fingerprint className="h-4 w-4 text-purple-400" />
              MITRE ATT&CK Techniques ({uniqueTTPs.length})
            </CardTitle>
            <CardDescription className="text-xs">
              Techniques observed across all identified incidents.
            </CardDescription>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="flex flex-wrap gap-1.5">
              {uniqueTTPs.sort().map((ttp, i) => (
                <Badge key={i} variant="outline" className="text-[10px] font-mono text-purple-400 bg-purple-500/10 border-purple-500/30">
                  {ttp}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Metadata */}
      <div className="text-[10px] text-muted-foreground text-right">
        Searched at {new Date(incidentSearch.searchedAt).toLocaleString()} — {incidentSearch.catalogMatches.length} catalog + {incidentSearch.webSearchMatches.length} OSINT sources
      </div>
    </div>
  );
}
