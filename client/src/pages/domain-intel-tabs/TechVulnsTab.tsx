// @ts-nocheck
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
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

export default function TechVulnsTab({ scanId }: { scanId: number }) {
  const { data, isLoading, error } = trpc.domainIntel.techVulnerabilities.useQuery({ scanId });
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [searchTerm, setSearchTerm] = useState("");

  if (isLoading) return (
    <Card><CardContent className="flex items-center justify-center py-16">
      <Loader2 className="w-6 h-6 animate-spin text-cyan-400 mr-3" />
      <span className="text-muted-foreground">Cross-referencing technologies against CVE databases...</span>
    </CardContent></Card>
  );

  if (error) return (
    <Card><CardContent className="py-8 text-center">
      <AlertTriangle className="w-8 h-8 text-amber-400 mx-auto mb-2" />
      <p className="text-sm text-muted-foreground">{error.message}</p>
    </CardContent></Card>
  );

  if (!data) return null;

  const d = data as any;
  const techProfiles = (d.technologyProfiles || []) as any[];
  const vulnAssets = (d.vulnerableAssets || []) as any[];
  const summary = d.summary || {};

  const filteredProfiles = techProfiles.filter((tp: any) => {
    if (severityFilter !== "all" && tp.highestSeverity !== severityFilter) return false;
    if (searchTerm && !(tp.technology || '').toLowerCase().includes(searchTerm.toLowerCase()) &&
        !tp.cves?.some((c: any) => c.cveId?.toLowerCase().includes(searchTerm.toLowerCase()))) return false;
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Page Purpose */}
      <p className="text-sm text-muted-foreground">
        Cross-references all detected technologies and their versions against known CVE databases to identify outdated or vulnerable software across your attack surface.
      </p>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="bg-muted/30 border-border/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-cyan-400">{summary.totalTechnologies || 0}</div>
            <div className="text-[11px] text-muted-foreground">Technologies Detected</div>
          </CardContent>
        </Card>
        <Card className={`${(summary.vulnerableTechnologies || 0) > 0 ? 'bg-red-500/10 border-red-500/30' : 'bg-emerald-500/10 border-emerald-500/30'}`}>
          <CardContent className="p-3 text-center">
            <div className={`text-2xl font-bold ${(summary.vulnerableTechnologies || 0) > 0 ? 'text-red-400' : 'text-emerald-400'}`}>{summary.vulnerableTechnologies || 0}</div>
            <div className="text-[11px] text-muted-foreground">Vulnerable</div>
          </CardContent>
        </Card>
        <Card className={`${(summary.totalCves || 0) > 0 ? 'bg-orange-500/10 border-orange-500/30' : 'bg-muted/30 border-border/50'}`}>
          <CardContent className="p-3 text-center">
            <div className={`text-2xl font-bold ${(summary.totalCves || 0) > 0 ? 'text-orange-400' : 'text-muted-foreground'}`}>{summary.totalCves || 0}</div>
            <div className="text-[11px] text-muted-foreground">Total CVEs</div>
          </CardContent>
        </Card>
        <Card className={`${(summary.criticalCves || 0) > 0 ? 'bg-red-500/10 border-red-500/30' : 'bg-muted/30 border-border/50'}`}>
          <CardContent className="p-3 text-center">
            <div className={`text-2xl font-bold ${(summary.criticalCves || 0) > 0 ? 'text-red-400' : 'text-muted-foreground'}`}>{summary.criticalCves || 0}</div>
            <div className="text-[11px] text-muted-foreground">Critical CVEs</div>
          </CardContent>
        </Card>
        <Card className="bg-muted/30 border-border/50">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-amber-400">{summary.outdatedTechnologies || 0}</div>
            <div className="text-[11px] text-muted-foreground">Outdated Versions</div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search technologies or CVE IDs..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 text-sm bg-muted/30 border border-border/50 rounded-lg focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
          />
        </div>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-[140px]"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severity</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Technology Profiles */}
      {filteredProfiles.length === 0 ? (
        <Card className="bg-emerald-500/5 border-emerald-500/30">
          <CardContent className="flex items-center justify-center py-8">
            <ShieldCheck className="w-6 h-6 text-emerald-400 mr-3" />
            <span className="text-emerald-300">
              {searchTerm || severityFilter !== "all" ? "No technologies match the current filters." : "No known vulnerabilities detected in discovered technologies."}
            </span>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {filteredProfiles.map((tp: any, i: number) => (
            <Card key={i} className={`${
              tp.highestSeverity === 'critical' ? 'border-red-500/40' :
              tp.highestSeverity === 'high' ? 'border-orange-500/40' :
              tp.highestSeverity === 'medium' ? 'border-amber-500/40' :
              'border-border/50'
            }`}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <Cpu className="w-5 h-5 text-cyan-400" />
                    <div>
                      <span className="font-medium">{tp.technology}</span>
                      {tp.version && <span className="text-sm text-muted-foreground ml-2">v{tp.version}</span>}
                      {tp.latestVersion && tp.version !== tp.latestVersion && (
                        <Badge variant="outline" className="text-amber-400 border-amber-500/40 text-[10px] ml-2">
                          Latest: {tp.latestVersion}
                        </Badge>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {tp.isOutdated && <Badge variant="outline" className="text-amber-400 border-amber-500/40 text-[10px]">Outdated</Badge>}
                    {tp.isEol && <Badge variant="outline" className="text-red-400 border-red-500/40 text-[10px]">End of Life</Badge>}
                    <Badge variant="outline" className="text-muted-foreground text-[10px]">
                      {tp.affectedAssets?.length || 0} asset{(tp.affectedAssets?.length || 0) !== 1 ? 's' : ''}
                    </Badge>
                  </div>
                </div>

                {/* CVEs */}
                {tp.cves?.length > 0 && (
                  <div className="space-y-2 mt-2">
                    {tp.cves.map((cve: any, j: number) => (
                      <div key={j} className={`p-2 rounded-lg border ${
                        cve.severity === 'critical' ? 'bg-red-500/5 border-red-500/30' :
                        cve.severity === 'high' ? 'bg-orange-500/5 border-orange-500/30' :
                        cve.severity === 'medium' ? 'bg-amber-500/5 border-amber-500/30' :
                        'bg-muted/20 border-border/30'
                      }`}>
                        <div className="flex items-center gap-2 mb-1">
                          <a href={`https://nvd.nist.gov/vuln/detail/${cve.cveId}`} target="_blank" rel="noopener noreferrer"
                            className="font-mono text-xs text-cyan-400 hover:underline flex items-center gap-1">
                            {cve.cveId} <ExternalLink className="w-3 h-3" />
                          </a>
                          <Badge variant="outline" className={`text-[10px] ${
                            cve.severity === 'critical' ? 'text-red-400 border-red-500/40' :
                            cve.severity === 'high' ? 'text-orange-400 border-orange-500/40' :
                            cve.severity === 'medium' ? 'text-amber-400 border-amber-500/40' :
                            'text-muted-foreground'
                          }`}>{cve.severity}</Badge>
                          {cve.cvssScore && <span className="text-[10px] text-cyan-400">CVSS {cve.cvssScore}</span>}
                          {cve.exploitAvailable && <Badge variant="outline" className="text-red-400 border-red-500/40 text-[10px]">Exploit Available</Badge>}
                          {cve.kevListed && <Badge variant="outline" className="text-red-400 border-red-500/40 text-[10px]">KEV Listed</Badge>}
                          {cve.kevListed && cve.versionMatchConfirmed && <Badge variant="outline" className="text-emerald-400 border-emerald-500/40 text-[10px]">Confirmed Match</Badge>}
                          {cve.kevListed && !cve.versionMatchConfirmed && <Badge variant="outline" className="text-amber-400 border-amber-500/40 text-[10px]">Potential Match</Badge>}
                        </div>
                        <p className="text-xs text-muted-foreground">{cve.description}</p>
                        {cve.remediation && (
                          <div className="mt-1 p-1.5 rounded bg-blue-500/5 border border-blue-500/20">
                            <p className="text-[10px] text-blue-300"><strong>Remediation:</strong> {cve.remediation}</p>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* Affected Assets */}
                {tp.affectedAssets?.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    <span className="text-[10px] text-muted-foreground mr-1">Affected:</span>
                    {tp.affectedAssets.map((a: string, j: number) => (
                      <Badge key={j} variant="outline" className="text-[10px] font-mono">{a}</Badge>
                    ))}
                  </div>
                )}

                {/* Recommendations */}
                {tp.recommendation && (
                  <div className="mt-2 p-2 rounded bg-muted/20 border border-border/30">
                    <p className="text-xs text-muted-foreground"><strong>Recommendation:</strong> {tp.recommendation}</p>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Vulnerable Assets Summary */}
      {vulnAssets.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Server className="w-4 h-4 text-amber-400" />
              Vulnerable Assets ({vulnAssets.length})
            </CardTitle>
            <CardDescription>Assets with one or more vulnerable technologies detected.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-border/50 text-muted-foreground text-left">
                  <th className="pb-2 pr-4">Asset</th>
                  <th className="pb-2 pr-4">Vulnerable Tech</th>
                  <th className="pb-2 pr-4">CVEs</th>
                  <th className="pb-2">Highest Severity</th>
                </tr></thead>
                <tbody>
                  {vulnAssets.map((a: any, i: number) => (
                    <tr key={i} className="border-b border-border/20">
                      <td className="py-2 pr-4 font-mono text-xs text-cyan-400">{a.hostname}</td>
                      <td className="py-2 pr-4">
                        {a.vulnerableTech?.map((t: string, j: number) => (
                          <Badge key={j} variant="outline" className="text-[10px] mr-1 mb-1">{t}</Badge>
                        ))}
                      </td>
                      <td className="py-2 pr-4 text-xs">{a.totalCves || 0}</td>
                      <td className="py-2">
                        <Badge variant="outline" className={`text-[10px] ${
                          a.highestSeverity === 'critical' ? 'text-red-400 border-red-500/40' :
                          a.highestSeverity === 'high' ? 'text-orange-400 border-orange-500/40' :
                          a.highestSeverity === 'medium' ? 'text-amber-400 border-amber-500/40' :
                          'text-muted-foreground'
                        }`}>{a.highestSeverity}</Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════
// Takeover Tab — Subdomain Takeover Detection
// ═══════════════════════════════════════════════════════════════════════════

