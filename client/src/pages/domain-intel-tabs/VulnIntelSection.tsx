// @ts-nocheck
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
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
import { CorroborationTierBadge } from "@/components/CorroborationTierBadge";

type TierFilter = 'confirmed' | 'confirmed+probable' | 'all';

export default function VulnIntelSection({ scanId }: { scanId: number }) {
  const [expandedTech, setExpandedTech] = useState<string | null>(null);
  const [expandedCve, setExpandedCve] = useState<string | null>(null);
  const [tierFilter, setTierFilter] = useState<TierFilter>('confirmed');

  const { data, isLoading, error } = trpc.calderaProxy.matchTechVulns.useQuery(
    { scanId },
    { enabled: !!scanId }
  );

  // Compute filtered stats based on active tier filter
  const filteredStats = useMemo(() => {
    if (!data) return { vulns: 0, exploits: 0, kev: 0, zeroDay: 0, matches: [] };

    const allowedTiers = tierFilter === 'all'
      ? ['confirmed', 'probable', 'potential']
      : tierFilter === 'confirmed+probable'
        ? ['confirmed', 'probable']
        : ['confirmed'];

    const filteredMatches = data.matches.filter((m: any) => allowedTiers.includes(m.corroborationTier));

    // Recount stats from only the filtered matches
    let vulns = 0, exploits = 0, kev = 0, zeroDay = 0;
    for (const match of filteredMatches) {
      // Count vulns per tier within each tech match
      if (tierFilter === 'confirmed') {
        vulns += match.confirmedVulnCount || 0;
      } else if (tierFilter === 'confirmed+probable') {
        vulns += (match.confirmedVulnCount || 0) + (match.probableVulnCount || 0);
      } else {
        vulns += match.vulns?.length || 0;
      }
      exploits += match.exploitCount || 0;
      kev += match.kevCount || 0;
      zeroDay += match.vulns?.filter((v: any) => v.inTheWild).length || 0;
    }

    return { vulns, exploits, kev, zeroDay, matches: filteredMatches };
  }, [data, tierFilter]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-purple-400 mr-2" />
        <span className="text-muted-foreground">Matching discovered technologies against vulnerability feeds...</span>
      </div>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-8 text-center text-muted-foreground">
          <AlertTriangle className="h-8 w-8 mx-auto mb-2 text-destructive" />
          <p>Failed to load vulnerability intelligence. Feeds may still be loading.</p>
        </CardContent>
      </Card>
    );
  }

  if (!data || data.matches.length === 0) {
    return (
      <Card>
        <CardContent className="p-8 text-center text-muted-foreground">
          <Shield className="h-8 w-8 mx-auto mb-2 text-green-400" />
          <p className="font-semibold">No known vulnerabilities matched</p>
          <p className="text-xs mt-1">No discovered technologies matched against known exploited vulnerabilities (KEV), zero-day research, NVD, advisory feeds, or public exploit databases feeds.</p>
        </CardContent>
      </Card>
    );
  }

  const tierLabel = (tier: TierFilter) => {
    if (tier === 'confirmed') return 'Confirmed';
    if (tier === 'confirmed+probable') return 'Confirmed + Probable';
    return 'All Tiers';
  };

  const tierCount = (tier: TierFilter) => {
    if (tier === 'confirmed') return data.confirmedVulnCount || 0;
    if (tier === 'confirmed+probable') return (data.confirmedVulnCount || 0) + (data.probableVulnCount || 0);
    return data.totalVulns;
  };

  return (
    <TooltipProvider>
    <>
      {/* Tier Filter Toggle */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Showing:</span>
          {(['confirmed', 'confirmed+probable', 'all'] as TierFilter[]).map(tier => (
            <button
              key={tier}
              onClick={() => setTierFilter(tier)}
              className={`text-xs px-2 py-0.5 rounded border transition-all ${
                tierFilter === tier ? 'bg-accent text-accent-foreground border-accent' : 'border-border text-muted-foreground hover:border-accent/50'
              }`}
            >
              {tierLabel(tier)} ({tierCount(tier)})
            </button>
          ))}
        </div>
      </div>

      {/* Confidence Explanation Banner */}
      {tierFilter === 'confirmed' && filteredStats.vulns === 0 && data.totalVulns > 0 && (
        <Card className="border-blue-500/20 bg-blue-500/5 mb-3">
          <CardContent className="p-3">
            <div className="flex items-start gap-2">
              <Info className="h-4 w-4 text-blue-400 mt-0.5 shrink-0" />
              <div>
                <p className="text-xs text-blue-300 font-medium">No confirmed vulnerabilities found</p>
                <p className="text-[10px] text-muted-foreground mt-0.5">
                  {data.totalVulns} potential CVE associations were identified based on detected technologies, but none have been confirmed through version matching, KEV listing, or active exploitation evidence.
                  Use the "Confirmed + Probable" or "All Tiers" filters to review these associations.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Summary Stats — filtered by active tier */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="border-red-500/30 bg-red-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <Bug className="h-3.5 w-3.5 text-red-500" />
              <span className="text-[10px] text-muted-foreground">
                {tierFilter === 'confirmed' ? 'Confirmed' : tierFilter === 'confirmed+probable' ? 'Confirmed + Probable' : 'Total Vulns'}
              </span>
            </div>
            <div className="text-xl font-bold text-red-400 mt-0.5">{filteredStats.vulns}</div>
          </CardContent>
        </Card>
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <Crosshair className="h-3.5 w-3.5 text-amber-500" />
              <span className="text-[10px] text-muted-foreground">Exploits</span>
            </div>
            <div className="text-xl font-bold text-amber-400 mt-0.5">{filteredStats.exploits}</div>
          </CardContent>
        </Card>
        <Card className="border-orange-500/30 bg-orange-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5 text-orange-500" />
              <span className="text-[10px] text-muted-foreground">KEV</span>
            </div>
            <div className="text-xl font-bold text-orange-400 mt-0.5">{filteredStats.kev}</div>
          </CardContent>
        </Card>
        <Card className="border-purple-500/30 bg-purple-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <Zap className="h-3.5 w-3.5 text-purple-500" />
              <span className="text-[10px] text-muted-foreground">0-Day</span>
            </div>
            <div className="text-xl font-bold text-purple-400 mt-0.5">{filteredStats.zeroDay}</div>
          </CardContent>
        </Card>
        <Card className="border-blue-500/30 bg-blue-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <TrendingUp className="h-3.5 w-3.5 text-blue-500" />
              <span className="text-[10px] text-muted-foreground">Risk Boost</span>
            </div>
            <div className="text-xl font-bold text-blue-400 mt-0.5">+{data.overallRiskBoost}</div>
          </CardContent>
        </Card>
      </div>

      {/* Tier Breakdown Mini-Bar */}
      {data.totalVulns > 0 && (
        <div className="flex items-center gap-2 mt-1 mb-1">
          <span className="text-[10px] text-muted-foreground">Breakdown:</span>
          <div className="flex items-center gap-1.5">
            <span className="inline-flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-green-500" />
              <span className="text-[10px] text-green-400">{data.confirmedVulnCount || 0} confirmed</span>
            </span>
            <span className="text-[10px] text-muted-foreground">·</span>
            <span className="inline-flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-blue-500" />
              <span className="text-[10px] text-blue-400">{data.probableVulnCount || 0} probable</span>
            </span>
            <span className="text-[10px] text-muted-foreground">·</span>
            <span className="inline-flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-gray-500" />
              <span className="text-[10px] text-gray-400">{data.potentialVulnCount || 0} potential</span>
            </span>
          </div>
        </div>
      )}

      {/* Technology Matches — filtered by active tier */}
      <div className="space-y-2">
        {filteredStats.matches.length === 0 && (
          <Card>
            <CardContent className="p-6 text-center text-muted-foreground">
              <ShieldCheck className="h-6 w-6 mx-auto mb-2 text-green-400" />
              <p className="text-sm font-medium">No {tierLabel(tierFilter).toLowerCase()} vulnerabilities</p>
              <p className="text-[10px] mt-1">Try expanding the filter to see probable or potential matches.</p>
            </CardContent>
          </Card>
        )}
        {filteredStats.matches.map((match: any) => {
          const isExpanded = expandedTech === match.technology;
          const sevColors: Record<string, string> = {
            critical: "border-red-500/40 bg-red-500/5",
            high: "border-orange-500/40 bg-orange-500/5",
            medium: "border-yellow-500/40 bg-yellow-500/5",
            low: "border-blue-500/40 bg-blue-500/5",
            unknown: "border-border",
          };

          return (
            <Card
              key={match.technology}
              className={`transition-all ${sevColors[match.maxSeverity] || sevColors.unknown} ${isExpanded ? "ring-1 ring-accent/30" : ""}`}
            >
              <div
                className="p-3 cursor-pointer flex items-center gap-3"
                onClick={() => setExpandedTech(isExpanded ? null : match.technology)}
              >
                <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-muted/50 shrink-0">
                  <span className="text-sm font-bold">{match.riskScore}</span>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <Database className="h-3.5 w-3.5 text-accent" />
                    <span className="font-semibold text-sm">{match.technology}</span>
                    {match.corroborationTier && (
                      <CorroborationTierBadge
                        tier={match.corroborationTier}
                        size="xs"
                        showTooltip={true}
                        matchSpecificity={match._matchSpecificity}
                      />
                    )}
                  </div>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-[10px] text-muted-foreground">{match.vulns.length} CVEs</span>
                    {match.exploitCount > 0 && (
                      <Badge className="bg-amber-600/80 text-white text-[8px] h-4">{match.exploitCount} exploits</Badge>
                    )}
                    {match.kevCount > 0 && (
                      <Badge className="bg-red-600/80 text-white text-[8px] h-4">{match.kevCount} KEV</Badge>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <Badge className={`text-[9px] capitalize ${
                    match.maxSeverity === "critical" ? "bg-red-600/80 text-white" :
                    match.maxSeverity === "high" ? "bg-orange-600/80 text-white" :
                    match.maxSeverity === "medium" ? "bg-yellow-600/80 text-white" :
                    "bg-blue-600/80 text-white"
                  }`}>{match.maxSeverity}</Badge>
                  {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                </div>
              </div>

              {isExpanded && (
                <CardContent className="pt-0 pb-3 border-t border-border/50">
                  <div className="space-y-1.5 mt-3">
                    {match.vulns.map((vuln: any) => (
                      <div
                        key={vuln.cveId}
                        className={`p-2.5 rounded border border-border/50 cursor-pointer transition-all hover:border-accent/40 ${expandedCve === vuln.cveId ? "bg-muted/30" : ""}`}
                        onClick={() => setExpandedCve(expandedCve === vuln.cveId ? null : vuln.cveId)}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="font-mono text-xs font-bold text-accent">{vuln.cveId}</span>
                            <Badge className={`text-[8px] ${
                              vuln.severity === "critical" ? "bg-red-600/80 text-white" :
                              vuln.severity === "high" ? "bg-orange-600/80 text-white" :
                              vuln.severity === "medium" ? "bg-yellow-600/80 text-white" :
                              "bg-blue-600/80 text-white"
                            }`}>{vuln.severity?.toUpperCase()}</Badge>
                            {vuln.cvssScore && <Badge variant="outline" className="text-[8px] font-mono text-cyan-400 border-cyan-500/40">CVSS {vuln.cvssScore}</Badge>}
                            {vuln.kevListed && <Badge className="bg-red-600/80 text-white text-[8px]">KEV</Badge>}
                            {/* Per-CVE corroboration tier badge */}
                            {(() => {
                              const isProductSpecific = (vuln as any)._matchSpecificity === 'product';
                              const hasVersion = !!(match as any)._detectedVersion;
                              let cveTier: string;
                              if ((vuln.kevListed || vuln.inTheWild) && isProductSpecific) {
                                cveTier = 'confirmed';
                              } else if (isProductSpecific && (hasVersion || vuln.exploitAvailable)) {
                                cveTier = 'probable';
                              } else if (!isProductSpecific && hasVersion && vuln.exploitAvailable) {
                                cveTier = 'probable';
                              } else {
                                cveTier = 'potential';
                              }
                              return (
                                <CorroborationTierBadge
                                  tier={cveTier}
                                  size="xs"
                                  matchSpecificity={(vuln as any)._matchSpecificity}
                                />
                              );
                            })()}
                            {vuln.inTheWild && <Badge className="bg-purple-600/80 text-white text-[8px]">0-DAY</Badge>}
                            {vuln.exploitAvailable && !vuln.inTheWild && <Badge className="bg-amber-600/80 text-white text-[8px]">EXPLOIT</Badge>}
                            {vuln.ransomwareLinked && <Badge className="bg-pink-600/80 text-white text-[8px]">RANSOMWARE</Badge>}
                          </div>
                          <span className="text-[10px] text-muted-foreground">{vuln.datePublished?.slice(0, 10)}</span>
                        </div>
                        {expandedCve === vuln.cveId && (
                          <div className="mt-2 pt-2 border-t border-border/30">
                            <p className="text-xs text-muted-foreground">{vuln.description}</p>
                            <div className="flex gap-2 mt-2">
                              {vuln.sources?.map((s: string) => {
                                const labels: Record<string, string> = {
                                  cisa_kev: "KEV", project_zero: "zero-day research", nvd: "NVD", circl: "advisory feeds", exploit_db: "public exploit databases",
                                };
                                return <Badge key={s} variant="outline" className="text-[8px]">{labels[s] || s}</Badge>;
                              })}
                            </div>
                            <div className="flex gap-2 mt-2">
                              <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cveId}`} target="_blank" rel="noopener noreferrer" className="text-[10px] text-blue-400 hover:underline flex items-center gap-0.5" onClick={e => e.stopPropagation()}>
                                <ExternalLink className="h-2.5 w-2.5" /> NVD
                              </a>
                              {vuln.exploitDbId && (
                                <a href={`https://www.exploit-db.com/exploits/${vuln.exploitDbId}`} target="_blank" rel="noopener noreferrer" className="text-[10px] text-amber-400 hover:underline flex items-center gap-0.5" onClick={e => e.stopPropagation()}>
                                  <ExternalLink className="h-2.5 w-2.5" /> public exploit databases
                                </a>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </CardContent>
              )}
            </Card>
          );
        })}
      </div>
    </>
    </TooltipProvider>
  );
}


/** Validate Top 10 — quick-action banner for launching targeted validation from scan results */
