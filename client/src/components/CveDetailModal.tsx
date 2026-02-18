/**
 * CveDetailModal — Rich CVE detail view with exploit matching, IOCs, and intelligence.
 * Used from 0-day feed, ticker, and anywhere a CVE needs a detail view.
 */
import { trpc } from "@/lib/trpc";
import { safeUpper } from "@/lib/utils-safe";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  AlertTriangle, Shield, Crosshair, ExternalLink, Loader2,
  Flame, Bug, Zap, Terminal, Globe2, Clock, ChevronRight,
  Skull, Target, FileText,
} from "lucide-react";
import { Link } from "wouter";

interface CveDetailModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  cveId: string | null;
}

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: "text-red-500", bg: "bg-red-500/15", border: "border-red-500/40" },
  high: { color: "text-orange-500", bg: "bg-orange-500/15", border: "border-orange-500/40" },
  medium: { color: "text-yellow-500", bg: "bg-yellow-500/15", border: "border-yellow-500/40" },
  low: { color: "text-green-500", bg: "bg-green-500/15", border: "border-green-500/40" },
  unknown: { color: "text-muted-foreground", bg: "bg-muted/30", border: "border-border" },
};

function formatDate(d: string | null | undefined): string {
  if (!d) return "—";
  return new Date(d).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

export default function CveDetailModal({ open, onOpenChange, cveId }: CveDetailModalProps) {
  const { data, isLoading, error } = trpc.calderaProxy.getCveDetail.useQuery(
    { cveId: cveId! },
    { enabled: !!cveId && open, staleTime: 5 * 60 * 1000 }
  );

  const sev = SEVERITY_CONFIG[data?.severity || "unknown"] || SEVERITY_CONFIG.unknown;
  const exploitMatches = data?.exploitMatches;
  const associatedActors = data?.associatedActors || [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[90vh] p-0 bg-background border-border overflow-hidden">
        <DialogHeader className="px-6 pt-5 pb-3 border-b border-border bg-card">
          <div className="flex items-center gap-3">
            <div className={`p-2 border ${sev.border} ${sev.bg}`}>
              <Bug className={`w-5 h-5 ${sev.color}`} />
            </div>
            <div className="flex-1 min-w-0">
              <DialogTitle className={`text-lg font-mono tracking-wide ${sev.color}`}>
                {cveId || "Loading..."}
              </DialogTitle>
              <DialogDescription className="text-xs text-muted-foreground mt-1 flex items-center gap-2 flex-wrap">
                {data?.severity && (
                  <span className={`px-1.5 py-0.5 text-[9px] font-display tracking-wider border ${sev.border} ${sev.bg} ${sev.color}`}>
                    {safeUpper(data.severity)}
                  </span>
                )}
                {data?.cvssScore != null && (
                  <span className={`px-1.5 py-0.5 text-[9px] font-display tracking-wider border ${sev.border} ${sev.bg} ${sev.color}`}>
                    CVSS {data.cvssScore.toFixed(1)}
                  </span>
                )}
                {data?.inTheWild && (
                  <span className="px-1.5 py-0.5 text-[9px] font-display tracking-wider bg-red-500/20 text-red-400 border border-red-500/30 flex items-center gap-1">
                    <Flame className="w-2.5 h-2.5" /> IN THE WILD
                  </span>
                )}
                {data?.kevListed && (
                  <span className="px-1.5 py-0.5 text-[9px] font-display tracking-wider bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
                    CISA KEV
                  </span>
                )}
                {data?.ransomwareLinked && (
                  <span className="px-1.5 py-0.5 text-[9px] font-display tracking-wider bg-purple-500/20 text-purple-400 border border-purple-500/30">
                    RANSOMWARE
                  </span>
                )}
                {data?.exploitAvailable && (
                  <span className="px-1.5 py-0.5 text-[9px] font-display tracking-wider bg-orange-500/20 text-orange-400 border border-orange-500/30 flex items-center gap-1">
                    <Zap className="w-2.5 h-2.5" /> EXPLOIT AVAILABLE
                  </span>
                )}
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <ScrollArea className="max-h-[calc(90vh-100px)]">
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
              <span className="ml-3 text-sm text-muted-foreground">Loading CVE intelligence...</span>
            </div>
          ) : error ? (
            <div className="text-center py-16 text-red-400 text-sm">
              Failed to load CVE details: {error.message}
            </div>
          ) : !data ? (
            <div className="text-center py-16 text-muted-foreground text-sm">
              CVE not found in tracked feeds.
            </div>
          ) : (
            <Tabs defaultValue="overview" className="w-full">
              <TabsList className="w-full justify-start rounded-none border-b border-border bg-card px-6 h-auto py-0">
                <TabsTrigger value="overview" className="font-display tracking-wider text-[11px] rounded-none border-b-2 border-transparent data-[state=active]:border-primary py-2.5">
                  OVERVIEW
                </TabsTrigger>
                {exploitMatches && (
                  <TabsTrigger value="exploits" className="font-display tracking-wider text-[11px] rounded-none border-b-2 border-transparent data-[state=active]:border-orange-400 py-2.5">
                    EXPLOITS ({(exploitMatches.metasploitModules?.length || 0) + (exploitMatches.exploitDbEntries?.length || 0)})
                  </TabsTrigger>
                )}
                {associatedActors.length > 0 && (
                  <TabsTrigger value="actors" className="font-display tracking-wider text-[11px] rounded-none border-b-2 border-transparent data-[state=active]:border-red-400 py-2.5">
                    THREAT ACTORS ({associatedActors.length})
                  </TabsTrigger>
                )}
              </TabsList>

              {/* ── OVERVIEW TAB ── */}
              <TabsContent value="overview" className="px-6 py-4 space-y-5 mt-0">
                {/* Title & Vendor */}
                <div>
                  <h4 className="text-[10px] font-display tracking-widest text-muted-foreground mb-1">VULNERABILITY</h4>
                  <p className="text-sm font-medium">{data.title || data.cveId}</p>
                  <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                    {data.vendor && <span className="flex items-center gap-1"><Globe2 className="w-3 h-3" />{data.vendor}</span>}
                    {data.product && <span>· {data.product}</span>}
                    {data.datePublished && <span className="flex items-center gap-1"><Clock className="w-3 h-3 ml-2" />{formatDate(data.datePublished)}</span>}
                  </div>
                </div>

                {/* Description */}
                {data.description && (
                  <div>
                    <h4 className="text-[10px] font-display tracking-widest text-muted-foreground mb-2">DESCRIPTION</h4>
                    <p className="text-xs text-muted-foreground leading-relaxed">{data.description}</p>
                  </div>
                )}

                {/* CVSS Details */}
                <div className="bg-card border border-border p-4">
                  <h4 className="text-[10px] font-display tracking-widest text-muted-foreground mb-3">SCORING & CLASSIFICATION</h4>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                    <div className="text-center">
                      <div className={`text-2xl font-display ${sev.color}`}>
                        {data.cvssScore?.toFixed(1) || "—"}
                      </div>
                      <div className="text-[9px] tracking-wider text-muted-foreground">CVSS SCORE</div>
                    </div>
                    <div className="text-center">
                      <div className={`text-lg font-display ${sev.color}`}>
                        {safeUpper(data.severity)}
                      </div>
                      <div className="text-[9px] tracking-wider text-muted-foreground">SEVERITY</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-display text-muted-foreground">
                        {data.attackVector || "—"}
                      </div>
                      <div className="text-[9px] tracking-wider text-muted-foreground">ATTACK VECTOR</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-display text-muted-foreground">
                        {data.attackComplexity || "—"}
                      </div>
                      <div className="text-[9px] tracking-wider text-muted-foreground">COMPLEXITY</div>
                    </div>
                  </div>
                </div>

                {/* Status Indicators */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <div className={`p-3 border text-center ${data.inTheWild ? "border-red-500/30 bg-red-500/10" : "border-border bg-card"}`}>
                    <Flame className={`w-5 h-5 mx-auto mb-1 ${data.inTheWild ? "text-red-400" : "text-muted-foreground/30"}`} />
                    <div className={`text-[9px] tracking-wider ${data.inTheWild ? "text-red-400" : "text-muted-foreground/50"}`}>
                      {data.inTheWild ? "ACTIVELY EXPLOITED" : "NOT IN WILD"}
                    </div>
                  </div>
                  <div className={`p-3 border text-center ${data.kevListed ? "border-yellow-500/30 bg-yellow-500/10" : "border-border bg-card"}`}>
                    <Shield className={`w-5 h-5 mx-auto mb-1 ${data.kevListed ? "text-yellow-400" : "text-muted-foreground/30"}`} />
                    <div className={`text-[9px] tracking-wider ${data.kevListed ? "text-yellow-400" : "text-muted-foreground/50"}`}>
                      {data.kevListed ? "CISA KEV LISTED" : "NOT ON KEV"}
                    </div>
                  </div>
                  <div className={`p-3 border text-center ${data.exploitAvailable ? "border-orange-500/30 bg-orange-500/10" : "border-border bg-card"}`}>
                    <Zap className={`w-5 h-5 mx-auto mb-1 ${data.exploitAvailable ? "text-orange-400" : "text-muted-foreground/30"}`} />
                    <div className={`text-[9px] tracking-wider ${data.exploitAvailable ? "text-orange-400" : "text-muted-foreground/50"}`}>
                      {data.exploitAvailable ? "EXPLOIT PUBLIC" : "NO PUBLIC EXPLOIT"}
                    </div>
                  </div>
                  <div className={`p-3 border text-center ${data.ransomwareLinked ? "border-purple-500/30 bg-purple-500/10" : "border-border bg-card"}`}>
                    <Skull className={`w-5 h-5 mx-auto mb-1 ${data.ransomwareLinked ? "text-purple-400" : "text-muted-foreground/30"}`} />
                    <div className={`text-[9px] tracking-wider ${data.ransomwareLinked ? "text-purple-400" : "text-muted-foreground/50"}`}>
                      {data.ransomwareLinked ? "RANSOMWARE LINKED" : "NO RANSOMWARE"}
                    </div>
                  </div>
                </div>

                {/* Sources */}
                {data.sources && data.sources.length > 0 && (
                  <div>
                    <h4 className="text-[10px] font-display tracking-widest text-muted-foreground mb-2">INTELLIGENCE SOURCES</h4>
                    <div className="flex flex-wrap gap-1.5">
                      {data.sources.map((s: string) => (
                        <span key={s} className="text-[10px] font-display tracking-wider px-2 py-1 bg-muted border border-border">
                          {s.replace(/_/g, " ").toUpperCase()}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* MITRE Techniques */}
                {data.suggestedTechniques && data.suggestedTechniques.length > 0 && (
                  <div>
                    <h4 className="text-[10px] font-display tracking-widest text-muted-foreground mb-2 flex items-center gap-2">
                      <Crosshair className="w-3.5 h-3.5 text-primary" /> SUGGESTED MITRE TECHNIQUES
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                      {data.suggestedTechniques.map((t: string) => (
                        <a
                          key={t}
                          href={`https://attack.mitre.org/techniques/${t.replace(/\./g, "/")}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[10px] font-mono px-2 py-1 bg-primary/10 text-primary border border-primary/30 hover:bg-primary/20 transition-colors flex items-center gap-1"
                        >
                          {t} <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {/* Exploit Summary */}
                {exploitMatches && (
                  <div className="bg-orange-500/5 border border-orange-500/20 p-4">
                    <h4 className="text-[10px] font-display tracking-widest text-orange-400 mb-3 flex items-center gap-2">
                      <Terminal className="w-3.5 h-3.5" /> EXPLOIT ARSENAL SUMMARY
                    </h4>
                    <div className="grid grid-cols-3 gap-4 text-center">
                      <div>
                        <div className="text-lg font-display text-orange-400">{exploitMatches.metasploitModules?.length || 0}</div>
                        <div className="text-[9px] tracking-wider text-muted-foreground">METASPLOIT MODULES</div>
                      </div>
                      <div>
                        <div className="text-lg font-display text-amber-400">{exploitMatches.exploitDbEntries?.length || 0}</div>
                        <div className="text-[9px] tracking-wider text-muted-foreground">EXPLOITDB ENTRIES</div>
                      </div>
                      <div>
                        <div className={`text-lg font-display ${exploitMatches.isRemoteAccess ? "text-red-400" : "text-muted-foreground"}`}>
                          {exploitMatches.isRemoteAccess ? "YES" : "NO"}
                        </div>
                        <div className="text-[9px] tracking-wider text-muted-foreground">REMOTE ACCESS</div>
                      </div>
                    </div>
                    {exploitMatches.bestExploit && (
                      <div className="mt-3 border-t border-orange-500/20 pt-3">
                        <div className="text-[9px] tracking-wider text-orange-400 mb-1">BEST EXPLOIT</div>
                        <div className="text-xs font-mono text-foreground">{exploitMatches.bestExploit.name}</div>
                        <div className="text-[10px] text-muted-foreground mt-0.5">
                          {exploitMatches.bestExploit.source} · {exploitMatches.bestExploit.reliability} reliability · {exploitMatches.bestExploit.platform}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* External Links */}
                <div className="flex items-center gap-3 pt-2 border-t border-border">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${data.cveId}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] font-display tracking-wider text-primary hover:underline flex items-center gap-1"
                  >
                    NVD <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                  <a
                    href={`https://www.cvedetails.com/cve/${data.cveId}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] font-display tracking-wider text-primary hover:underline flex items-center gap-1"
                  >
                    CVE DETAILS <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                  {data.kevListed && (
                    <a
                      href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[10px] font-display tracking-wider text-yellow-400 hover:underline flex items-center gap-1"
                    >
                      CISA KEV <ExternalLink className="w-2.5 h-2.5" />
                    </a>
                  )}
                  {data.exploitDbId && (
                    <a
                      href={`https://www.exploit-db.com/exploits/${data.exploitDbId}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[10px] font-display tracking-wider text-orange-400 hover:underline flex items-center gap-1"
                    >
                      EXPLOIT-DB <ExternalLink className="w-2.5 h-2.5" />
                    </a>
                  )}
                  <Link
                    href={`/vuln-intel?search=${data.cveId}`}
                    className="text-[10px] font-display tracking-wider text-cyan-400 hover:underline flex items-center gap-1 ml-auto"
                    onClick={() => onOpenChange(false)}
                  >
                    FULL VULN INTEL <ChevronRight className="w-2.5 h-2.5" />
                  </Link>
                </div>
              </TabsContent>

              {/* ── EXPLOITS TAB ── */}
              {exploitMatches && (
                <TabsContent value="exploits" className="px-6 py-4 space-y-5 mt-0">
                  {/* Metasploit Modules */}
                  {exploitMatches.metasploitModules && exploitMatches.metasploitModules.length > 0 && (
                    <div>
                      <h4 className="text-[10px] font-display tracking-widest text-orange-400 mb-3 flex items-center gap-2">
                        <Terminal className="w-3.5 h-3.5" /> METASPLOIT MODULES
                      </h4>
                      <div className="space-y-2">
                        {exploitMatches.metasploitModules.map((mod: any, i: number) => (
                          <div key={i} className="bg-card border border-orange-500/20 p-3">
                            <div className="flex items-start justify-between">
                              <div className="flex-1 min-w-0">
                                <div className="text-xs font-mono text-orange-400 break-all">{mod.fullname || mod.name}</div>
                                <div className="text-[10px] text-muted-foreground mt-1 line-clamp-2">{mod.description}</div>
                              </div>
                              <span className={`text-[9px] px-1.5 py-0.5 border font-display tracking-wider shrink-0 ml-2 ${
                                mod.rank >= 500 ? "text-green-400 border-green-500/30 bg-green-500/10"
                                : mod.rank >= 300 ? "text-amber-400 border-amber-500/30 bg-amber-500/10"
                                : "text-muted-foreground border-border bg-muted/30"
                              }`}>
                                {safeUpper(mod.rankLabel || "UNKNOWN")}
                              </span>
                            </div>
                            <div className="flex items-center gap-2 mt-2 text-[9px] text-muted-foreground">
                              {mod.platform && <span>Platform: {mod.platform}</span>}
                              {mod.msfCommand && (
                                <code className="px-1.5 py-0.5 bg-muted border border-border font-mono text-foreground">
                                  {mod.msfCommand}
                                </code>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* ExploitDB Entries */}
                  {exploitMatches.exploitDbEntries && exploitMatches.exploitDbEntries.length > 0 && (
                    <div>
                      <h4 className="text-[10px] font-display tracking-widest text-amber-400 mb-3 flex items-center gap-2">
                        <FileText className="w-3.5 h-3.5" /> EXPLOIT-DB ENTRIES
                      </h4>
                      <div className="space-y-2">
                        {exploitMatches.exploitDbEntries.map((exp: any, i: number) => (
                          <div key={i} className="bg-card border border-amber-500/20 p-3">
                            <div className="flex items-start justify-between">
                              <div className="flex-1 min-w-0">
                                <div className="text-xs text-amber-400">{exp.description}</div>
                                <div className="flex items-center gap-2 mt-1 text-[9px] text-muted-foreground">
                                  {exp.author && <span>Author: {exp.author}</span>}
                                  {exp.platform && <span>· {exp.platform}</span>}
                                  {exp.type && <span>· {exp.type}</span>}
                                  {exp.datePublished && <span>· {formatDate(exp.datePublished)}</span>}
                                </div>
                              </div>
                              {exp.exploitDbUrl && (
                                <a
                                  href={exp.exploitDbUrl}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-[9px] text-amber-400 hover:underline flex items-center gap-1 shrink-0 ml-2"
                                >
                                  VIEW <ExternalLink className="w-2.5 h-2.5" />
                                </a>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Caldera Ability */}
                  {exploitMatches.calderaAbility && (
                    <div className="bg-primary/5 border border-primary/20 p-4">
                      <h4 className="text-[10px] font-display tracking-widest text-primary mb-2 flex items-center gap-2">
                        <Crosshair className="w-3.5 h-3.5" /> CALDERA ABILITY
                      </h4>
                      <div className="text-xs font-mono text-foreground">{exploitMatches.calderaAbility.name}</div>
                      <div className="text-[10px] text-muted-foreground mt-1">{exploitMatches.calderaAbility.description}</div>
                    </div>
                  )}
                </TabsContent>
              )}

              {/* ── THREAT ACTORS TAB ── */}
              {associatedActors.length > 0 && (
                <TabsContent value="actors" className="px-6 py-4 space-y-3 mt-0">
                  <h4 className="text-[10px] font-display tracking-widest text-muted-foreground flex items-center gap-2">
                    <Skull className="w-3.5 h-3.5 text-red-400" /> ASSOCIATED THREAT ACTORS
                  </h4>
                  <div className="space-y-2">
                    {associatedActors.map((actor: any) => (
                      <div key={actor.actorId} className="bg-card border border-red-500/20 p-3 flex items-center gap-3">
                        <Skull className="w-5 h-5 text-red-400 shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-display text-red-400">{actor.name}</div>
                          <div className="flex items-center gap-2 mt-0.5 text-[9px] text-muted-foreground">
                            {actor.type && <span>{actor.type.replace(/_/g, " ")}</span>}
                            {actor.origin && <span>· {actor.origin}</span>}
                            {actor.threatLevel && <span>· {actor.threatLevel} threat</span>}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </TabsContent>
              )}
            </Tabs>
          )}
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}
