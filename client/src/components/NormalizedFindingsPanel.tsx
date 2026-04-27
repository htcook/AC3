/**
 * NormalizedFindingsPanel — Real-time normalization stats tab for EngagementOps.
 *
 * Calls vaBugBounty.normalizeEngagementFindings to pull live Nuclei/ZAP scan
 * results from the engagement ops state, run them through batchNormalize, and
 * display a unified view with dedup/corroboration breakdown and severity stats.
 */

import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Input } from "@/components/ui/input";
import {
  RefreshCw, Shield, AlertTriangle, Bug, Info, ChevronDown, ChevronRight,
  Search, Filter, ArrowUpDown, CheckCircle2, XCircle, Layers, Zap, Eye,
  BarChart3, Target, Fingerprint, Clock,
} from "lucide-react";

interface NormalizedFindingsPanelProps {
  engagementId: number;
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};
const CORROBORATION_COLORS: Record<string, string> = {
  confirmed: "bg-green-500/20 text-green-400 border-green-500/30",
  corroborated: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  single_source: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  unverified: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

type SortField = "severity" | "title" | "corroboration" | "sources";
type SortDir = "asc" | "desc";

export function NormalizedFindingsPanel({ engagementId }: NormalizedFindingsPanelProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  const [corroborationFilter, setCorroborationFilter] = useState<string | null>(null);
  const [sortField, setSortField] = useState<SortField>("severity");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());

  const normalizeMut = trpc.vaBugBounty.normalizeEngagementFindings.useMutation();

  const handleNormalize = () => {
    normalizeMut.mutate({ engagementId });
  };

  const findings = normalizeMut.data?.findings || [];
  const stats = normalizeMut.data?.stats;
  const totalAssets = normalizeMut.data?.totalAssetsAnalyzed || 0;
  const otherCount = normalizeMut.data?.otherScannerFindings || 0;

  // Filter and sort
  const filtered = useMemo(() => {
    let result = [...findings];
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter((f: any) =>
        f.title?.toLowerCase().includes(q) ||
        f.vulnClass?.toLowerCase().includes(q) ||
        f.cveIds?.some((c: string) => c.toLowerCase().includes(q)) ||
        f.affectedAsset?.hostname?.toLowerCase().includes(q)
      );
    }
    if (severityFilter) {
      result = result.filter((f: any) => f.severity === severityFilter);
    }
    if (corroborationFilter) {
      result = result.filter((f: any) => f.corroborationTier === corroborationFilter);
    }
    result.sort((a: any, b: any) => {
      let cmp = 0;
      switch (sortField) {
        case "severity":
          cmp = (SEVERITY_ORDER[a.severity as keyof typeof SEVERITY_ORDER] ?? 5) - (SEVERITY_ORDER[b.severity as keyof typeof SEVERITY_ORDER] ?? 5);
          break;
        case "title":
          cmp = (a.title || "").localeCompare(b.title || "");
          break;
        case "corroboration":
          cmp = (a.corroborationCount || 0) - (b.corroborationCount || 0);
          break;
        case "sources":
          cmp = (a.sources?.length || 0) - (b.sources?.length || 0);
          break;
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
    return result;
  }, [findings, searchQuery, severityFilter, corroborationFilter, sortField, sortDir]);

  const toggleExpanded = (id: string) => {
    setExpandedFindings(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSort = (field: SortField) => {
    if (sortField === field) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortField(field); setSortDir("asc"); }
  };

  // Severity distribution
  const severityDist = useMemo(() => {
    const dist: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((f: any) => { if (f.severity in dist) dist[f.severity]++; });
    return dist;
  }, [findings]);

  // Corroboration distribution
  const corrobDist = useMemo(() => {
    const dist: Record<string, number> = { confirmed: 0, corroborated: 0, single_source: 0, unverified: 0 };
    findings.forEach((f: any) => { if (f.corroborationTier in dist) dist[f.corroborationTier]++; });
    return dist;
  }, [findings]);

  return (
    <div className="space-y-4 py-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
            <Layers className="h-5 w-5 text-emerald-400" />
            Normalized Findings
          </h3>
          <p className="text-sm text-muted-foreground mt-0.5">
            Unified view of all scanner findings after normalization, deduplication, and corroboration analysis.
          </p>
        </div>
        <Button
          onClick={handleNormalize}
          disabled={normalizeMut.isPending}
          size="sm"
          className="gap-2"
        >
          <RefreshCw className={`h-4 w-4 ${normalizeMut.isPending ? "animate-spin" : ""}`} />
          {normalizeMut.isPending ? "Normalizing..." : findings.length > 0 ? "Refresh" : "Normalize Findings"}
        </Button>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          <StatMiniCard icon={<Target className="h-4 w-4 text-cyan-400" />} label="Assets Analyzed" value={totalAssets} />
          <StatMiniCard icon={<Bug className="h-4 w-4 text-yellow-400" />} label="Raw Findings" value={stats.totalRaw} />
          <StatMiniCard icon={<Layers className="h-4 w-4 text-emerald-400" />} label="Normalized" value={stats.totalNormalized} />
          <StatMiniCard icon={<Fingerprint className="h-4 w-4 text-purple-400" />} label="After Dedup" value={stats.totalDeduplicated} />
          <StatMiniCard
            icon={<BarChart3 className="h-4 w-4 text-blue-400" />}
            label="Dedup Rate"
            value={stats.totalRaw > 0 ? `${Math.round((1 - stats.totalDeduplicated / stats.totalRaw) * 100)}%` : "0%"}
          />
          <StatMiniCard icon={<Zap className="h-4 w-4 text-orange-400" />} label="Other Scanners" value={otherCount} />
        </div>
      )}

      {/* Scanner Breakdown */}
      {stats?.byScannerRaw && (
        <Card className="border-border/30 bg-card/50">
          <CardHeader className="py-2 px-4">
            <CardTitle className="text-sm font-medium text-muted-foreground">Scanner Breakdown</CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-3 pt-0">
            <div className="flex flex-wrap gap-3">
              {Object.entries(stats.byScannerRaw).map(([scanner, count]) => (
                <div key={scanner} className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-background/50 border border-border/30">
                  <span className="text-xs font-mono uppercase text-muted-foreground">{scanner}</span>
                  <span className="text-sm font-semibold text-foreground">{count as number}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Severity + Corroboration Distribution */}
      {findings.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {/* Severity Distribution */}
          <Card className="border-border/30 bg-card/50">
            <CardHeader className="py-2 px-4">
              <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                <AlertTriangle className="h-3.5 w-3.5" /> Severity Distribution
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-3 pt-0">
              <div className="space-y-1.5">
                {Object.entries(severityDist).map(([sev, count]) => {
                  const pct = findings.length > 0 ? (count / findings.length) * 100 : 0;
                  return (
                    <button
                      key={sev}
                      onClick={() => setSeverityFilter(severityFilter === sev ? null : sev)}
                      className={`w-full flex items-center gap-2 px-2 py-1 rounded text-xs transition-colors ${
                        severityFilter === sev ? "bg-accent/20 ring-1 ring-accent" : "hover:bg-accent/10"
                      }`}
                    >
                      <Badge variant="outline" className={`${SEVERITY_COLORS[sev]} text-[10px] w-16 justify-center`}>
                        {sev}
                      </Badge>
                      <div className="flex-1 h-1.5 bg-background/50 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${
                            sev === "critical" ? "bg-red-500" : sev === "high" ? "bg-orange-500" : sev === "medium" ? "bg-yellow-500" : sev === "low" ? "bg-blue-500" : "bg-gray-500"
                          }`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="text-foreground font-mono w-8 text-right">{count}</span>
                    </button>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Corroboration Distribution */}
          <Card className="border-border/30 bg-card/50">
            <CardHeader className="py-2 px-4">
              <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                <CheckCircle2 className="h-3.5 w-3.5" /> Corroboration Tiers
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-3 pt-0">
              <div className="space-y-1.5">
                {Object.entries(corrobDist).map(([tier, count]) => {
                  const pct = findings.length > 0 ? (count / findings.length) * 100 : 0;
                  return (
                    <button
                      key={tier}
                      onClick={() => setCorroborationFilter(corroborationFilter === tier ? null : tier)}
                      className={`w-full flex items-center gap-2 px-2 py-1 rounded text-xs transition-colors ${
                        corroborationFilter === tier ? "bg-accent/20 ring-1 ring-accent" : "hover:bg-accent/10"
                      }`}
                    >
                      <Badge variant="outline" className={`${CORROBORATION_COLORS[tier] || "bg-gray-500/20 text-gray-400"} text-[10px] w-24 justify-center`}>
                        {tier.replace(/_/g, " ")}
                      </Badge>
                      <div className="flex-1 h-1.5 bg-background/50 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${
                            tier === "confirmed" ? "bg-green-500" : tier === "corroborated" ? "bg-emerald-500" : tier === "single_source" ? "bg-yellow-500" : "bg-gray-500"
                          }`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="text-foreground font-mono w-8 text-right">{count}</span>
                    </button>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Search and Sort Controls */}
      {findings.length > 0 && (
        <div className="flex items-center gap-3">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              placeholder="Search findings, CVEs, hosts..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="pl-8 h-8 text-sm"
            />
          </div>
          <div className="flex items-center gap-1">
            {(["severity", "title", "corroboration", "sources"] as SortField[]).map(field => (
              <Button
                key={field}
                variant={sortField === field ? "secondary" : "ghost"}
                size="sm"
                className="h-7 text-xs gap-1"
                onClick={() => toggleSort(field)}
              >
                {field === "severity" ? "Sev" : field === "corroboration" ? "Corrob" : field === "sources" ? "Sources" : "Title"}
                {sortField === field && <ArrowUpDown className="h-3 w-3" />}
              </Button>
            ))}
          </div>
          {(severityFilter || corroborationFilter) && (
            <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => { setSeverityFilter(null); setCorroborationFilter(null); }}>
              <XCircle className="h-3 w-3 mr-1" /> Clear Filters
            </Button>
          )}
          <span className="text-xs text-muted-foreground ml-auto">{filtered.length} of {findings.length} findings</span>
        </div>
      )}

      {/* Findings List */}
      {findings.length > 0 ? (
        <ScrollArea className="h-[calc(100vh-520px)]">
          <div className="space-y-2">
            {filtered.map((f: any) => {
              const isExpanded = expandedFindings.has(f.findingId || f.fingerprint);
              return (
                <Card
                  key={f.findingId || f.fingerprint}
                  className="border-border/30 bg-card/50 hover:bg-card/70 transition-colors cursor-pointer"
                  onClick={() => toggleExpanded(f.findingId || f.fingerprint)}
                >
                  <CardContent className="p-3">
                    <div className="flex items-start gap-3">
                      {isExpanded ? <ChevronDown className="h-4 w-4 text-muted-foreground mt-0.5 flex-none" /> : <ChevronRight className="h-4 w-4 text-muted-foreground mt-0.5 flex-none" />}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge variant="outline" className={`${SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.info} text-[10px]`}>
                            {f.severity}
                          </Badge>
                          <Badge variant="outline" className={`${CORROBORATION_COLORS[f.corroborationTier] || CORROBORATION_COLORS.unverified} text-[10px]`}>
                            {(f.corroborationTier || "unverified").replace(/_/g, " ")}
                          </Badge>
                          <span className="text-sm font-medium text-foreground truncate">{f.title}</span>
                        </div>
                        <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                          {f.affectedAsset?.hostname && (
                            <span className="flex items-center gap-1">
                              <Target className="h-3 w-3" /> {f.affectedAsset.hostname}
                              {f.affectedAsset.port && `:${f.affectedAsset.port}`}
                            </span>
                          )}
                          {f.cveIds?.length > 0 && (
                            <span className="flex items-center gap-1 font-mono">
                              <Shield className="h-3 w-3" /> {f.cveIds.slice(0, 3).join(", ")}
                              {f.cveIds.length > 3 && ` +${f.cveIds.length - 3}`}
                            </span>
                          )}
                          {f.vulnClass && (
                            <span className="flex items-center gap-1">
                              <Bug className="h-3 w-3" /> {f.vulnClass}
                            </span>
                          )}
                          <span className="flex items-center gap-1">
                            <Eye className="h-3 w-3" /> {f.sources?.length || 1} source{(f.sources?.length || 1) !== 1 ? "s" : ""}
                          </span>
                        </div>

                        {/* Expanded Details */}
                        {isExpanded && (
                          <div className="mt-3 pt-3 border-t border-border/30 space-y-3">
                            {f.description && (
                              <div>
                                <span className="text-xs font-medium text-muted-foreground">Description</span>
                                <p className="text-sm text-foreground/80 mt-0.5">{f.description}</p>
                              </div>
                            )}
                            {f.cweIds?.length > 0 && (
                              <div>
                                <span className="text-xs font-medium text-muted-foreground">CWE</span>
                                <p className="text-sm font-mono text-foreground/80 mt-0.5">{f.cweIds.join(", ")}</p>
                              </div>
                            )}
                            {f.detectionMethod && (
                              <div>
                                <span className="text-xs font-medium text-muted-foreground">Detection Method</span>
                                <p className="text-sm text-foreground/80 mt-0.5">{f.detectionMethod.replace(/_/g, " ")}</p>
                              </div>
                            )}
                            {f.detectionConfidence != null && (
                              <div>
                                <span className="text-xs font-medium text-muted-foreground">Detection Confidence</span>
                                <p className="text-sm text-foreground/80 mt-0.5">{Math.round(f.detectionConfidence * 100)}%</p>
                              </div>
                            )}
                            {f.sources?.length > 0 && (
                              <div>
                                <span className="text-xs font-medium text-muted-foreground">Sources</span>
                                <div className="flex flex-wrap gap-1.5 mt-1">
                                  {f.sources.map((s: any, i: number) => (
                                    <Badge key={i} variant="outline" className="text-[10px] bg-background/50">
                                      {s.scanner} {s.scanTimestamp ? `(${new Date(s.scanTimestamp).toLocaleTimeString()})` : ""}
                                    </Badge>
                                  ))}
                                </div>
                              </div>
                            )}
                            {f.evidence?.length > 0 && (
                              <div>
                                <span className="text-xs font-medium text-muted-foreground">Evidence ({f.evidence.length})</span>
                                <div className="mt-1 space-y-1">
                                  {f.evidence.slice(0, 3).map((e: any, i: number) => (
                                    <div key={i} className="text-xs bg-background/50 rounded p-2 font-mono text-foreground/70 whitespace-pre-wrap break-all">
                                      {typeof e === "string" ? e : JSON.stringify(e, null, 2).slice(0, 500)}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                            {f.exploitability && (
                              <div>
                                <span className="text-xs font-medium text-muted-foreground">Exploitability</span>
                                <div className="flex flex-wrap gap-1.5 mt-1">
                                  {f.exploitability.isKev && <Badge variant="outline" className="text-[10px] bg-red-500/10 text-red-400 border-red-500/30">KEV</Badge>}
                                  {f.exploitability.hasPublicExploit && <Badge variant="outline" className="text-[10px] bg-orange-500/10 text-orange-400 border-orange-500/30">Public Exploit</Badge>}
                                  {f.exploitability.hasMetasploitModule && <Badge variant="outline" className="text-[10px] bg-purple-500/10 text-purple-400 border-purple-500/30">Metasploit</Badge>}
                                  {f.exploitability.hasNucleiTemplate && <Badge variant="outline" className="text-[10px] bg-cyan-500/10 text-cyan-400 border-cyan-500/30">Nuclei Template</Badge>}
                                  {f.exploitability.attackComplexity && <Badge variant="outline" className="text-[10px]">Complexity: {f.exploitability.attackComplexity}</Badge>}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </ScrollArea>
      ) : !normalizeMut.isPending && !normalizeMut.data ? (
        <Card className="border-border/30 bg-card/30">
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <div className="h-12 w-12 rounded-xl bg-emerald-500/10 flex items-center justify-center">
              <Layers className="h-6 w-6 text-emerald-400" />
            </div>
            <p className="text-sm text-muted-foreground text-center max-w-md">
              Click <strong>Normalize Findings</strong> to pull all Nuclei and ZAP scan results from this engagement,
              run them through the normalization pipeline, and view a unified, deduplicated breakdown.
            </p>
          </CardContent>
        </Card>
      ) : normalizeMut.data && findings.length === 0 ? (
        <Card className="border-border/30 bg-card/30">
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <CheckCircle2 className="h-8 w-8 text-emerald-400" />
            <p className="text-sm text-muted-foreground">No findings to normalize. The engagement may not have scan results yet.</p>
          </CardContent>
        </Card>
      ) : null}

      {normalizeMut.isError && (
        <Card className="border-red-500/30 bg-red-500/5">
          <CardContent className="py-3 px-4">
            <p className="text-sm text-red-400">{normalizeMut.error?.message || "Failed to normalize findings"}</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function StatMiniCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: string | number }) {
  return (
    <div className="flex items-center gap-2.5 px-3 py-2 rounded-lg border border-border/30 bg-card/50">
      {icon}
      <div>
        <div className="text-xs text-muted-foreground">{label}</div>
        <div className="text-sm font-semibold text-foreground">{value}</div>
      </div>
    </div>
  );
}

export default NormalizedFindingsPanel;
