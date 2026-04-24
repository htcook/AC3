// @ts-nocheck
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Server, Globe, Shield, AlertTriangle, ChevronDown, ChevronUp,
  Loader2, Database, Cpu, Network, Lock, Eye, Mail, Cloud, Layers,
  Activity, Info, ExternalLink, ShieldAlert, ShieldCheck, BarChart3,
  Fingerprint, Box, Wifi, Radio, Bug
} from "lucide-react";

const CATEGORY_META: Record<string, { label: string; icon: any; color: string }> = {
  dns: { label: "DNS", icon: Globe, color: "text-blue-400" },
  email: { label: "Email", icon: Mail, color: "text-cyan-400" },
  cdn_waf: { label: "CDN / WAF", icon: Shield, color: "text-green-400" },
  web_server: { label: "Web Server", icon: Server, color: "text-slate-400" },
  application_framework: { label: "App Framework", icon: Box, color: "text-violet-400" },
  cms: { label: "CMS", icon: Layers, color: "text-pink-400" },
  database: { label: "Database", icon: Database, color: "text-amber-400" },
  authentication: { label: "Authentication", icon: Lock, color: "text-yellow-400" },
  cloud_hosting: { label: "Cloud Hosting", icon: Cloud, color: "text-sky-400" },
  cloud_storage: { label: "Cloud Storage", icon: Database, color: "text-orange-400" },
  container_orchestration: { label: "Containers", icon: Cpu, color: "text-teal-400" },
  ci_cd: { label: "CI/CD", icon: Activity, color: "text-indigo-400" },
  monitoring: { label: "Monitoring", icon: Activity, color: "text-emerald-400" },
  analytics: { label: "Analytics", icon: BarChart3, color: "text-purple-400" },
  payment: { label: "Payment", icon: Fingerprint, color: "text-rose-400" },
  communication: { label: "Communication", icon: Radio, color: "text-lime-400" },
  security_tools: { label: "Security Tools", icon: ShieldCheck, color: "text-green-400" },
  certificate_authority: { label: "Certificate Authority", icon: Lock, color: "text-emerald-400" },
  api_gateway: { label: "API Gateway", icon: Network, color: "text-blue-400" },
  load_balancer: { label: "Load Balancer", icon: Wifi, color: "text-cyan-400" },
  vpn: { label: "VPN", icon: Lock, color: "text-amber-400" },
  other: { label: "Other", icon: Server, color: "text-slate-400" },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/20 border-red-500/40",
  high: "text-orange-400 bg-orange-500/20 border-orange-500/40",
  medium: "text-yellow-400 bg-yellow-500/20 border-yellow-500/40",
  low: "text-blue-400 bg-blue-500/20 border-blue-500/40",
};

const MATURITY_COLORS: Record<string, { color: string; bg: string }> = {
  advanced: { color: "text-emerald-400", bg: "bg-emerald-500/20" },
  moderate: { color: "text-blue-400", bg: "bg-blue-500/20" },
  basic: { color: "text-yellow-400", bg: "bg-yellow-500/20" },
  minimal: { color: "text-red-400", bg: "bg-red-500/20" },
};

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = pct >= 80 ? "bg-emerald-500" : pct >= 60 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 rounded-full bg-muted overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-muted-foreground">{pct}%</span>
    </div>
  );
}

export default function InfrastructureMapTab({ scanId }: { scanId: number }) {
  const { data: infraMap, isLoading, error } = trpc.calderaProxy.inferInfrastructure.useQuery(
    { scanId },
    { staleTime: 5 * 60 * 1000 }
  );
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());
  const [expandedRisks, setExpandedRisks] = useState(false);
  const [expandedVendors, setExpandedVendors] = useState(false);
  const [expandedLifecycle, setExpandedLifecycle] = useState(false);

  const toggleCategory = (cat: string) => {
    setExpandedCategories(prev => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  };

  // Group services by category
  const servicesByCategory = useMemo(() => {
    if (!infraMap) return new Map();
    const map = new Map<string, any[]>();
    for (const svc of infraMap.services) {
      if (!map.has(svc.category)) map.set(svc.category, []);
      map.get(svc.category)!.push(svc);
    }
    return map;
  }, [infraMap]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground mr-2" />
        <span className="text-muted-foreground">Inferring infrastructure from passive signals...</span>
      </div>
    );
  }

  if (error) {
    return (
      <Card className="border-red-500/30 bg-red-950/20">
        <CardContent className="p-6 text-center">
          <AlertTriangle className="h-6 w-6 text-red-400 mx-auto mb-2" />
          <p className="text-red-400">Failed to infer infrastructure: {error.message}</p>
        </CardContent>
      </Card>
    );
  }

  if (!infraMap || infraMap.services.length === 0) {
    return (
      <Card>
        <CardContent className="p-8 text-center text-muted-foreground">
          <Network className="h-8 w-8 mx-auto mb-3 opacity-50" />
          <p>No infrastructure signals detected from passive reconnaissance data.</p>
          <p className="text-xs mt-1">This may indicate limited DNS/header/technology fingerprinting data in the scan.</p>
        </CardContent>
      </Card>
    );
  }

  const summary = infraMap.summary;
  const maturityStyle = MATURITY_COLORS[summary.overallMaturity] || MATURITY_COLORS.minimal;

  return (
    <TooltipProvider>
      <div className="space-y-4">
        {/* ─── Summary Strip ─── */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-blue-400">{summary.totalServices}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Services</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-purple-400">{summary.totalVendors}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Vendors</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-cyan-400">{summary.thirdPartyManaged}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">3rd-Party</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-amber-400">{summary.externallyExposed}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Exposed</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className={`text-2xl font-bold ${summary.criticalRisks > 0 ? "text-red-400" : "text-emerald-400"}`}>
                {summary.criticalRisks + summary.highRisks}
              </div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Risks</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className={`text-lg font-bold capitalize ${maturityStyle.color}`}>{summary.overallMaturity}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Maturity</div>
            </CardContent>
          </Card>
        </div>

        {/* ─── Info Banner ─── */}
        <div className="flex items-start gap-2 p-3 rounded-lg bg-blue-950/30 border border-blue-500/20 text-xs text-blue-300">
          <Info className="h-3.5 w-3.5 mt-0.5 shrink-0" />
          <span>
            Infrastructure map inferred from passive reconnaissance signals including DNS, SPF, MX, HTTP headers, CNAME chains, Shodan, BuiltWith, certificate transparency, and JARM TLS fingerprinting. JARM fingerprints identify server TLS implementations to detect CDN, cloud hosting, and C2 frameworks.
          </span>
        </div>

        {/* ─── Service Categories ─── */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Network className="h-4 w-4 text-blue-400" />
              Detected Services ({infraMap.services.length})
            </CardTitle>
            <CardDescription>Backend services, platforms, and vendor dependencies inferred from passive signals</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {Array.from(servicesByCategory.entries()).map(([category, services]) => {
              const meta = CATEGORY_META[category] || CATEGORY_META.other;
              const Icon = meta.icon;
              const isExpanded = expandedCategories.has(category);
              return (
                <Collapsible key={category} open={isExpanded} onOpenChange={() => toggleCategory(category)}>
                  <CollapsibleTrigger className="flex items-center justify-between w-full p-2.5 rounded-lg hover:bg-muted/50 transition-colors">
                    <div className="flex items-center gap-2">
                      <Icon className={`h-4 w-4 ${meta.color}`} />
                      <span className="text-sm font-medium">{meta.label}</span>
                      <Badge variant="outline" className="text-[10px] px-1.5 py-0">{services.length}</Badge>
                    </div>
                    <div className="flex items-center gap-2">
                      {services.some((s: any) => s.exposedExternally) && (
                        <Tooltip>
                          <TooltipTrigger>
                            <Eye className="h-3 w-3 text-amber-400" />
                          </TooltipTrigger>
                          <TooltipContent>Externally exposed</TooltipContent>
                        </Tooltip>
                      )}
                      {isExpanded ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />}
                    </div>
                  </CollapsibleTrigger>
                  <CollapsibleContent>
                    <div className="ml-6 mt-1 space-y-2">
                      {services.map((svc: any) => (
                        <div key={svc.id} className="p-3 rounded-lg bg-muted/30 border border-border/50 space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium">{svc.name}</span>
                              {svc.provider && svc.provider !== svc.name && (
                                <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-muted-foreground">{svc.provider}</Badge>
                              )}
                              {svc.version && (
                                <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-blue-400 border-blue-500/30">v{svc.version}</Badge>
                              )}
                            </div>
                            <div className="flex items-center gap-2">
                              {svc.managedByThirdParty && (
                                <Tooltip>
                                  <TooltipTrigger>
                                    <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-cyan-400 border-cyan-500/30">Managed</Badge>
                                  </TooltipTrigger>
                                  <TooltipContent>Third-party managed service</TooltipContent>
                                </Tooltip>
                              )}
                              {svc.exposedExternally && (
                                <Tooltip>
                                  <TooltipTrigger>
                                    <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-amber-400 border-amber-500/30">External</Badge>
                                  </TooltipTrigger>
                                  <TooltipContent>Exposed to the internet</TooltipContent>
                                </Tooltip>
                              )}
                              <ConfidenceBar value={svc.confidence} />
                            </div>
                          </div>
                          {/* Evidence */}
                          {svc.evidence.length > 0 && (
                            <div className="text-xs text-muted-foreground space-y-0.5">
                              {svc.evidence.slice(0, 3).map((e: string, i: number) => (
                                <div key={i} className="flex items-start gap-1.5">
                                  <span className="text-muted-foreground/50 mt-0.5">-</span>
                                  <span className="break-all">{e}</span>
                                </div>
                              ))}
                              {svc.evidence.length > 3 && (
                                <span className="text-muted-foreground/50 text-[10px]">+{svc.evidence.length - 3} more evidence items</span>
                              )}
                            </div>
                          )}
                          {/* Ports */}
                          {svc.ports.length > 0 && (
                            <div className="flex items-center gap-1 flex-wrap">
                              <span className="text-[10px] text-muted-foreground">Ports:</span>
                              {svc.ports.map((p: number) => (
                                <Badge key={p} variant="outline" className="text-[10px] px-1 py-0 font-mono">{p}</Badge>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              );
            })}
          </CardContent>
        </Card>

        {/* ─── Supply Chain Risks ─── */}
        {infraMap.supplyChainRisks.length > 0 && (
          <Collapsible open={expandedRisks} onOpenChange={setExpandedRisks}>
            <Card className="border-red-500/20">
              <CardHeader className="pb-3">
                <CollapsibleTrigger className="flex items-center justify-between w-full">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-red-400" />
                    Supply Chain Risks ({infraMap.supplyChainRisks.length})
                  </CardTitle>
                  {expandedRisks ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                </CollapsibleTrigger>
                <CardDescription>Vendor concentration, missing defenses, and technology lifecycle risks</CardDescription>
              </CardHeader>
              <CollapsibleContent>
                <CardContent className="space-y-3 pt-0">
                  {infraMap.supplyChainRisks.map((risk: any, i: number) => {
                    const sevStyle = SEVERITY_COLORS[risk.severity] || SEVERITY_COLORS.medium;
                    return (
                      <div key={i} className={`p-3 rounded-lg border ${sevStyle} space-y-2`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Badge className={`text-[10px] uppercase ${sevStyle}`}>{risk.severity}</Badge>
                            <span className="text-xs font-medium capitalize">{risk.riskType.replace(/_/g, " ")}</span>
                          </div>
                        </div>
                        <p className="text-xs text-muted-foreground">{risk.description}</p>
                        <div className="flex items-start gap-1.5 text-xs">
                          <ShieldCheck className="h-3 w-3 text-emerald-400 mt-0.5 shrink-0" />
                          <span className="text-emerald-400/80">{risk.recommendation}</span>
                        </div>
                        {risk.affectedServices.length > 0 && (
                          <div className="flex items-center gap-1 flex-wrap">
                            <span className="text-[10px] text-muted-foreground">Affected:</span>
                            {risk.affectedServices.slice(0, 5).map((s: string, j: number) => (
                              <Badge key={j} variant="outline" className="text-[10px] px-1 py-0">{s}</Badge>
                            ))}
                            {risk.affectedServices.length > 5 && (
                              <span className="text-[10px] text-muted-foreground">+{risk.affectedServices.length - 5} more</span>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>
        )}

        {/* ─── Vendor Dependencies ─── */}
        {infraMap.vendorDependencies.length > 0 && (
          <Collapsible open={expandedVendors} onOpenChange={setExpandedVendors}>
            <Card>
              <CardHeader className="pb-3">
                <CollapsibleTrigger className="flex items-center justify-between w-full">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Layers className="h-4 w-4 text-purple-400" />
                    Vendor Dependencies ({infraMap.vendorDependencies.length})
                  </CardTitle>
                  {expandedVendors ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                </CollapsibleTrigger>
                <CardDescription>Third-party vendor concentration and single-point-of-failure analysis</CardDescription>
              </CardHeader>
              <CollapsibleContent>
                <CardContent className="pt-0">
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-border/50">
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Vendor</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">Services</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">Criticality</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">SPOF</th>
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Notes</th>
                        </tr>
                      </thead>
                      <tbody>
                        {infraMap.vendorDependencies.map((dep: any, i: number) => (
                          <tr key={i} className="border-b border-border/30 hover:bg-muted/30">
                            <td className="py-2 px-2 font-medium">{dep.vendor}</td>
                            <td className="py-2 px-2 text-center">{dep.serviceCount}</td>
                            <td className="py-2 px-2 text-center">
                              <Badge className={`text-[10px] ${SEVERITY_COLORS[dep.criticality] || ""}`}>{dep.criticality}</Badge>
                            </td>
                            <td className="py-2 px-2 text-center">
                              {dep.singlePointOfFailure ? (
                                <AlertTriangle className="h-3.5 w-3.5 text-red-400 mx-auto" />
                              ) : (
                                <span className="text-muted-foreground">-</span>
                              )}
                            </td>
                            <td className="py-2 px-2 text-muted-foreground">{dep.notes}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>
        )}

        {/* ─── Technology Lifecycle ─── */}
        {infraMap.techLifecycle.length > 0 && (
          <Collapsible open={expandedLifecycle} onOpenChange={setExpandedLifecycle}>
            <Card>
              <CardHeader className="pb-3">
                <CollapsibleTrigger className="flex items-center justify-between w-full">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Activity className="h-4 w-4 text-emerald-400" />
                    Technology Lifecycle ({infraMap.techLifecycle.length})
                  </CardTitle>
                  {expandedLifecycle ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                </CollapsibleTrigger>
                <CardDescription>Version currency and end-of-life status for detected technologies</CardDescription>
              </CardHeader>
              <CollapsibleContent>
                <CardContent className="pt-0">
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-border/50">
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Technology</th>
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Detected Version</th>
                          <th className="text-center py-2 px-2 text-muted-foreground font-medium">EOL Status</th>
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Signal</th>
                          <th className="text-left py-2 px-2 text-muted-foreground font-medium">Risk Note</th>
                        </tr>
                      </thead>
                      <tbody>
                        {infraMap.techLifecycle.map((tech: any, i: number) => {
                          const eolColors: Record<string, string> = {
                            current: "text-emerald-400 bg-emerald-500/20",
                            approaching_eol: "text-yellow-400 bg-yellow-500/20",
                            eol: "text-red-400 bg-red-500/20",
                            unknown: "text-slate-400 bg-slate-500/20",
                          };
                          return (
                            <tr key={i} className="border-b border-border/30 hover:bg-muted/30">
                              <td className="py-2 px-2 font-medium">{tech.technology}</td>
                              <td className="py-2 px-2 font-mono">{tech.detectedVersion || "-"}</td>
                              <td className="py-2 px-2 text-center">
                                <Badge className={`text-[10px] ${eolColors[tech.eolStatus] || eolColors.unknown}`}>
                                  {tech.eolStatus.replace(/_/g, " ").toUpperCase()}
                                </Badge>
                              </td>
                              <td className="py-2 px-2 text-muted-foreground">{tech.patchCadenceSignal}</td>
                              <td className="py-2 px-2 text-muted-foreground">{tech.riskNote}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </CollapsibleContent>
            </Card>
          </Collapsible>
        )}

        {/* ─── JARM TLS Fingerprint Analysis ─── */}
        {infraMap.jarmAnalysis && infraMap.jarmAnalysis.fingerprintsCollected > 0 && (
          <Card className={infraMap.jarmAnalysis.c2Detected ? "border-red-500/50 bg-red-950/10" : "bg-card/50"}>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Fingerprint className={`h-4 w-4 ${infraMap.jarmAnalysis.c2Detected ? "text-red-400" : "text-emerald-400"}`} />
                JARM TLS Fingerprint Analysis
                {infraMap.jarmAnalysis.c2Detected && (
                  <Badge className="bg-red-500/20 text-red-400 border-red-500/40 text-[10px] ml-1">
                    <Bug className="h-2.5 w-2.5 mr-0.5" /> C2 DETECTED
                  </Badge>
                )}
              </CardTitle>
              <CardDescription>
                {infraMap.jarmAnalysis.fingerprintsCollected} TLS fingerprint(s) collected,{" "}
                {infraMap.jarmAnalysis.matchesFound} matched to known infrastructure
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {/* Status badges */}
              <div className="flex flex-wrap gap-2">
                {infraMap.jarmAnalysis.cdnCorroborated && (
                  <Badge variant="outline" className="text-[10px] text-green-400 border-green-500/40 bg-green-500/10">
                    <ShieldCheck className="h-2.5 w-2.5 mr-1" /> CDN Corroborated
                  </Badge>
                )}
                {infraMap.jarmAnalysis.cloudCorroborated && (
                  <Badge variant="outline" className="text-[10px] text-sky-400 border-sky-500/40 bg-sky-500/10">
                    <Cloud className="h-2.5 w-2.5 mr-1" /> Cloud Hosting Corroborated
                  </Badge>
                )}
                {infraMap.jarmAnalysis.serverIdentified && (
                  <Badge variant="outline" className="text-[10px] text-slate-400 border-slate-500/40 bg-slate-500/10">
                    <Server className="h-2.5 w-2.5 mr-1" /> Server Software Identified
                  </Badge>
                )}
              </div>

              {/* Matches table */}
              {infraMap.jarmAnalysis.matches.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-border/50">
                        <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Hash (prefix)</th>
                        <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Matched Provider</th>
                        <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Type</th>
                        <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Source</th>
                        <th className="text-left py-1.5 px-2 text-muted-foreground font-medium">Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {infraMap.jarmAnalysis.matches.map((match: any, i: number) => (
                        <tr key={i} className={`border-b border-border/30 ${match.matchType === "c2" ? "bg-red-950/20" : ""}`}>
                          <td className="py-1.5 px-2 font-mono text-[10px] text-muted-foreground">
                            {match.hash.substring(0, 20)}…
                          </td>
                          <td className="py-1.5 px-2">
                            {match.matchedProvider ? (
                              <span className={match.matchType === "c2" ? "text-red-400 font-medium" : ""}>
                                {match.matchedProvider}
                              </span>
                            ) : (
                              <span className="text-muted-foreground italic">Unknown</span>
                            )}
                          </td>
                          <td className="py-1.5 px-2">
                            <Badge variant="outline" className={`text-[9px] px-1 py-0 ${
                              match.matchType === "c2" ? "text-red-400 border-red-500/40" :
                              match.matchType === "cdn" ? "text-green-400 border-green-500/40" :
                              match.matchType === "cloud" ? "text-sky-400 border-sky-500/40" :
                              match.matchType === "server" ? "text-slate-400 border-slate-500/40" :
                              "text-muted-foreground border-border"
                            }`}>
                              {match.matchType.toUpperCase()}
                            </Badge>
                          </td>
                          <td className="py-1.5 px-2 text-muted-foreground">{match.source}</td>
                          <td className="py-1.5 px-2"><ConfidenceBar value={match.confidence} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* JARM notes */}
              {infraMap.jarmAnalysis.notes.length > 0 && (
                <div className="space-y-1 pt-1">
                  {infraMap.jarmAnalysis.notes.map((note: string, i: number) => (
                    <div key={i} className={`text-xs flex items-start gap-1.5 ${
                      note.includes("CRITICAL") ? "text-red-400" :
                      note.includes("corroborates") ? "text-emerald-400" :
                      "text-muted-foreground"
                    }`}>
                      <span className="mt-0.5">•</span>
                      <span>{note}</span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* ─── Inference Notes ─── */}
        {infraMap.inferenceNotes.length > 0 && (
          <Card className="bg-card/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs flex items-center gap-2 text-muted-foreground">
                <Info className="h-3 w-3" />
                Inference Notes
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-0">
              <div className="space-y-1">
                {infraMap.inferenceNotes.map((note: string, i: number) => (
                  <div key={i} className="text-xs text-muted-foreground flex items-start gap-1.5">
                    <span className="text-muted-foreground/50 mt-0.5">-</span>
                    <span className={note.startsWith("WARNING") || note.startsWith("CRITICAL") ? (note.startsWith("CRITICAL") ? "text-red-400 font-medium" : "text-amber-400") : ""}>{note}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </TooltipProvider>
  );
}
