// @ts-nocheck
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  ArrowLeft, Shield, Target, AlertTriangle, Brain, Globe, Server,
  ChevronDown, ChevronUp, Crosshair, Zap, FileText, ExternalLink,
  Activity, Lock, Eye, Network, Loader2, BarChart3, Bug, Skull, Database, Cpu,
  TrendingUp, Fingerprint, Radar, Info, Search, Radio, Scan, Flag, Undo2, MessageSquare,
  Download, FlaskConical, Mail, ShieldAlert, ShieldCheck, ShieldX, CheckCircle2, XCircle, RefreshCw,
  Layers, Play, Pause, Settings2, GitBranch, Link2, Users, Hash, Clock, Unplug, Wifi,
  Workflow, Lightbulb, Route, Telescope, ShieldQuestion, ArrowRightLeft, KeyRound,
  Box, ClipboardCheck, PackageSearch, GitCompareArrows
} from "lucide-react";

export default function CveActorEnrichmentTab({ scanId }: { scanId: number }) {
  const { data, isLoading, error } = trpc.domainIntel.cveActorEnrichment.useQuery({ scanId });
  const [expandedCve, setExpandedCve] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [onlyActiveExploits, setOnlyActiveExploits] = useState(false);
  const [onlyKev, setOnlyKev] = useState(false);
  const [sortBy, setSortBy] = useState<"priority" | "cvss" | "actors" | "date">("date");

  const d = data as any;
  const allEnrichedCves = (d?.enrichedCves || []) as any[];
  const uniqueActors = (d?.uniqueActors || []) as string[];
  const actorTypeSummary = (d?.actorTypeSummary || []) as any[];
  const severityBreakdown = d?.severityBreakdown || {};
  const kevCount = d?.kevCount || 0;
  const activeExploitCount = d?.activeExploitCount || 0;

  // Apply filters — must be above early returns to satisfy Rules of Hooks
  const filteredCves = useMemo(() => {
    let cves = [...allEnrichedCves];
    if (severityFilter !== "all") {
      cves = cves.filter((c: any) => c.severity === severityFilter);
    }
    if (onlyActiveExploits) {
      cves = cves.filter((c: any) => c.activelyExploited);
    }
    if (onlyKev) {
      cves = cves.filter((c: any) => c.cisaKev);
    }
    // Sort
    cves.sort((a: any, b: any) => {
      if (sortBy === "date") {
        const dateA = a.publishedDate ? new Date(a.publishedDate).getTime() : 0;
        const dateB = b.publishedDate ? new Date(b.publishedDate).getTime() : 0;
        return dateB - dateA;
      }
      if (sortBy === "priority") return (b.priorityScore || 0) - (a.priorityScore || 0);
      if (sortBy === "cvss") return (b.cvssScore || 0) - (a.cvssScore || 0);
      return (b.actors?.length || 0) - (a.actors?.length || 0);
    });
    return cves;
  }, [allEnrichedCves, severityFilter, onlyActiveExploits, onlyKev, sortBy]);

  if (isLoading) return (
    <Card><CardContent className="flex items-center justify-center py-16">
      <Loader2 className="w-6 h-6 animate-spin text-cyan-400 mr-3" />
      <span className="text-muted-foreground">Correlating CVEs with threat actor intelligence...</span>
    </CardContent></Card>
  );

  if (error) return (
    <Card><CardContent className="py-8 text-center">
      <AlertTriangle className="w-8 h-8 text-amber-400 mx-auto mb-2" />
      <p className="text-sm text-muted-foreground">{error.message}</p>
    </CardContent></Card>
  );

  if (!data) return null;

  const threatLevelColor = (level: string) => {
    switch (level) {
      case "critical": return "text-red-400 bg-red-500/10 border-red-500/30";
      case "high": return "text-orange-400 bg-orange-500/10 border-orange-500/30";
      case "medium": return "text-amber-400 bg-amber-500/10 border-amber-500/30";
      default: return "text-blue-400 bg-blue-500/10 border-blue-500/30";
    }
  };

  const severityColor = (sev: string) => {
    switch (sev) {
      case "critical": return "text-red-400 border-red-500/40 bg-red-500/10";
      case "high": return "text-orange-400 border-orange-500/40 bg-orange-500/10";
      case "medium": return "text-amber-400 border-amber-500/40 bg-amber-500/10";
      case "low": return "text-blue-400 border-blue-500/40 bg-blue-500/10";
      default: return "text-muted-foreground border-border/50 bg-muted/30";
    }
  };

  const actorTypeIcon = (type: string) => {
    switch (type) {
      case "apt": return <Shield className="w-3.5 h-3.5 text-red-400" />;
      case "ransomware": return <Skull className="w-3.5 h-3.5 text-purple-400" />;
      case "cybercrime": return <Bug className="w-3.5 h-3.5 text-orange-400" />;
      case "hacktivist": return <Users className="w-3.5 h-3.5 text-cyan-400" />;
      default: return <Target className="w-3.5 h-3.5 text-muted-foreground" />;
    }
  };

  const priorityBar = (score: number) => {
    const color = score >= 80 ? "bg-red-500" : score >= 60 ? "bg-orange-500" : score >= 40 ? "bg-amber-500" : "bg-blue-500";
    return (
      <div className="flex items-center gap-2 min-w-[120px]">
        <div className="flex-1 h-1.5 bg-secondary/50 rounded-full overflow-hidden">
          <div className={`h-full rounded-full ${color}`} style={{ width: `${score}%` }} />
        </div>
        <span className="text-xs font-mono font-bold w-8 text-right">{score}</span>
      </div>
    );
  };

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Correlates discovered CVEs with known threat actor campaigns, APT groups, and ransomware operators.
        Use the severity filter to prioritize critical/high CVEs with active threat actor exploitation.
      </p>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <Card className={`${(d.totalCvesEnriched || 0) > 0 ? 'bg-red-500/10 border-red-500/30' : 'bg-muted/30 border-border/50'}`}>
          <CardContent className="p-3 text-center">
            <div className={`text-2xl font-bold ${(d.totalCvesEnriched || 0) > 0 ? 'text-red-400' : 'text-muted-foreground'}`}>{d.totalCvesEnriched || 0}</div>
            <div className="text-[11px] text-muted-foreground">CVEs Enriched</div>
          </CardContent>
        </Card>
        <Card className={`${(d.totalActorsLinked || 0) > 0 ? 'bg-purple-500/10 border-purple-500/30' : 'bg-muted/30 border-border/50'}`}>
          <CardContent className="p-3 text-center">
            <div className={`text-2xl font-bold ${(d.totalActorsLinked || 0) > 0 ? 'text-purple-400' : 'text-muted-foreground'}`}>{d.totalActorsLinked || 0}</div>
            <div className="text-[11px] text-muted-foreground">Threat Actors</div>
          </CardContent>
        </Card>
        <Card className={`${kevCount > 0 ? 'bg-red-500/10 border-red-500/30' : 'bg-muted/30 border-border/50'}`}>
          <CardContent className="p-3 text-center">
            <div className={`text-2xl font-bold ${kevCount > 0 ? 'text-red-400' : 'text-muted-foreground'}`}>{kevCount}</div>
            <div className="text-[11px] text-muted-foreground">CISA KEV</div>
          </CardContent>
        </Card>
        <Card className={`${activeExploitCount > 0 ? 'bg-orange-500/10 border-orange-500/30' : 'bg-muted/30 border-border/50'}`}>
          <CardContent className="p-3 text-center">
            <div className={`text-2xl font-bold ${activeExploitCount > 0 ? 'text-orange-400' : 'text-muted-foreground'}`}>{activeExploitCount}</div>
            <div className="text-[11px] text-muted-foreground">Active Exploits</div>
          </CardContent>
        </Card>
        {actorTypeSummary.slice(0, 2).map((at: any) => (
          <Card key={at.type} className="bg-muted/30 border-border/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-cyan-400">{at.count}</div>
              <div className="text-[11px] text-muted-foreground capitalize">{at.type}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Severity Filter Bar */}
      {allEnrichedCves.length > 0 && (
        <Card className="border-border/50">
          <CardContent className="py-3 px-4">
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-xs font-display tracking-wider text-muted-foreground">SEVERITY:</span>
              <div className="flex gap-1.5">
                {["all", "critical", "high", "medium", "low"].map((sev) => {
                  const count = sev === "all" ? allEnrichedCves.length : (severityBreakdown[sev] || 0);
                  const isActive = severityFilter === sev;
                  return (
                    <button
                      key={sev}
                      onClick={() => setSeverityFilter(sev)}
                      className={`px-2.5 py-1 rounded-md text-xs font-display tracking-wider transition-colors border ${
                        isActive
                          ? sev === "all" ? "bg-primary text-primary-foreground border-primary"
                            : severityColor(sev)
                          : "border-border/50 text-muted-foreground hover:bg-secondary/50"
                      }`}
                    >
                      {sev.toUpperCase()} ({count})
                    </button>
                  );
                })}
              </div>

              <div className="h-4 w-px bg-border/50 mx-1" />

              <button
                onClick={() => setOnlyActiveExploits(!onlyActiveExploits)}
                className={`px-2.5 py-1 rounded-md text-xs font-display tracking-wider transition-colors border ${
                  onlyActiveExploits ? "bg-orange-500/20 text-orange-400 border-orange-500/40" : "border-border/50 text-muted-foreground hover:bg-secondary/50"
                }`}
              >
                ACTIVE EXPLOITS
              </button>

              <button
                onClick={() => setOnlyKev(!onlyKev)}
                className={`px-2.5 py-1 rounded-md text-xs font-display tracking-wider transition-colors border ${
                  onlyKev ? "bg-red-500/20 text-red-400 border-red-500/40" : "border-border/50 text-muted-foreground hover:bg-secondary/50"
                }`}
              >
                CISA KEV ONLY
              </button>

              <div className="h-4 w-px bg-border/50 mx-1" />

              <span className="text-xs font-display tracking-wider text-muted-foreground">SORT:</span>
              <div className="flex gap-1.5">
                {(["date", "priority", "cvss", "actors"] as const).map((s) => (
                  <button
                    key={s}
                    onClick={() => setSortBy(s)}
                    className={`px-2.5 py-1 rounded-md text-xs font-display tracking-wider transition-colors border ${
                      sortBy === s ? "bg-primary text-primary-foreground border-primary" : "border-border/50 text-muted-foreground hover:bg-secondary/50"
                    }`}
                  >
                    {s.toUpperCase()}
                  </button>
                ))}
              </div>

              {(severityFilter !== "all" || onlyActiveExploits || onlyKev) && (
                <span className="text-xs text-muted-foreground ml-auto">
                  Showing {filteredCves.length} of {allEnrichedCves.length}
                </span>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Risk Elevation Banner */}
      {d.riskElevation && allEnrichedCves.length > 0 && (
        <Card className="bg-red-500/5 border-red-500/30">
          <CardContent className="flex items-start gap-3 py-4">
            <ShieldAlert className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
            <div>
              <div className="text-sm font-semibold text-red-400 mb-1">Threat Actor Risk Elevation</div>
              <p className="text-xs text-muted-foreground">{d.riskElevation}</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* No Enrichments */}
      {allEnrichedCves.length === 0 && (
        <Card className="bg-emerald-500/5 border-emerald-500/30">
          <CardContent className="flex items-center justify-center py-8">
            <ShieldCheck className="w-6 h-6 text-emerald-400 mr-3" />
            <span className="text-sm text-emerald-400">No discovered CVEs are linked to known threat actor campaigns.</span>
          </CardContent>
        </Card>
      )}

      {/* Filtered empty state */}
      {allEnrichedCves.length > 0 && filteredCves.length === 0 && (
        <Card className="bg-muted/20 border-border/50">
          <CardContent className="flex items-center justify-center py-8">
            <span className="text-sm text-muted-foreground">No CVEs match the current filter criteria. Try adjusting filters above.</span>
          </CardContent>
        </Card>
      )}

      {/* Enriched CVE Cards */}
      {filteredCves.map((cve: any) => (
        <Card key={cve.cveId} className={`border ${cve.severity === 'critical' ? 'border-red-500/40' : cve.severity === 'high' ? 'border-orange-500/40' : 'border-border/50'}`}>
          <CardHeader className="pb-2 cursor-pointer" onClick={() => setExpandedCve(expandedCve === cve.cveId ? null : cve.cveId)}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Badge className={severityColor(cve.severity || cve.threatLevel)}>{(cve.severity || cve.threatLevel || "unknown").toUpperCase()}</Badge>
                <span className="font-mono text-sm font-bold">{cve.cveId}</span>
                <span className="text-xs text-muted-foreground">({cve.technology})</span>
                {cve.cisaKev && (
                  <Badge className="bg-red-600/20 text-red-300 border-red-600/40 text-[10px] px-1.5 py-0">CISA KEV</Badge>
                )}
                {cve.activelyExploited && (
                  <Badge variant="destructive" className="text-[10px] px-1.5 py-0">ACTIVELY EXPLOITED</Badge>
                )}
              </div>
              <div className="flex items-center gap-3">
                {cve.priorityScore != null && priorityBar(cve.priorityScore)}
                <Badge variant="outline" className="text-[10px] text-cyan-400 border-cyan-500/40">CVSS {cve.cvssScore}</Badge>
                <Badge variant="outline" className="text-[10px]">{cve.actors?.length || 0} actor(s)</Badge>
                {expandedCve === cve.cveId ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </div>
            </div>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-[10px] text-muted-foreground">{cve.mitreTechnique}</span>
              <span className="text-[10px] text-muted-foreground">• Phase: {cve.attackPhase?.replace(/_/g, ' ')}</span>
              {cve.exploitAvailable && <span className="text-[10px] text-orange-400">• Public exploit available</span>}
            </div>
          </CardHeader>

          {expandedCve === cve.cveId && (
            <CardContent className="pt-0 space-y-3">
              {/* Threat Actor Cards */}
              {(cve.actors || []).map((actor: any, idx: number) => (
                <div key={idx} className="bg-muted/30 rounded-lg p-3 border border-border/50">
                  <div className="flex items-center gap-2 mb-2">
                    {actorTypeIcon(actor.type)}
                    <span className="font-semibold text-sm">{actor.name}</span>
                    <Badge variant="outline" className="text-[10px] capitalize">{actor.type}</Badge>
                    <Badge variant="outline" className="text-[10px]">{actor.origin}</Badge>
                    <Badge variant="outline" className="text-[10px]">{actor.sophistication}</Badge>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-muted-foreground">Campaign:</span>
                      <span className="ml-1">{actor.campaign}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Last Exploited:</span>
                      <span className="ml-1 font-mono">{actor.lastExploited}</span>
                    </div>
                    <div className="md:col-span-2">
                      <span className="text-muted-foreground">Exploit Context:</span>
                      <span className="ml-1">{actor.exploitContext}</span>
                    </div>
                  </div>
                </div>
              ))}
            </CardContent>
          )}
        </Card>
      ))}

      {/* Linked Actors Summary */}
      {uniqueActors.length > 0 && (
        <Card className="bg-muted/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Users className="w-4 h-4 text-purple-400" />
              All Linked Threat Actors ({uniqueActors.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {uniqueActors.map((actor: string) => (
                <Badge key={actor} variant="outline" className="text-xs">{actor}</Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Methodology */}
      <Card className="bg-muted/20">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Info className="w-4 h-4 text-muted-foreground" />
            Enrichment Methodology
          </CardTitle>
        </CardHeader>
        <CardContent className="text-xs text-muted-foreground space-y-1">
          <p>CVE-to-threat-actor enrichment correlates discovered vulnerabilities with known exploitation campaigns:</p>
          <ul className="list-disc list-inside space-y-0.5 ml-2">
            <li>Static mapping of CVEs to APT groups, ransomware operators, and cybercrime actors with documented exploitation</li>
            <li>Database correlation matching threat actor MITRE ATT&CK techniques against CVE attack surfaces</li>
            <li>Active exploitation timeline tracking to identify CVEs currently being weaponized</li>
            <li>CISA Known Exploited Vulnerabilities (KEV) catalog cross-reference for mandatory remediation tracking</li>
            <li>Priority scoring (0–100) combining CVSS severity, actor count, active exploitation, and KEV status</li>
            <li>Attack phase classification mapping each CVE to the kill chain stage where it is exploited</li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Takeover PoC Validation Tab
// ═══════════════════════════════════════════════════════════════════════════

